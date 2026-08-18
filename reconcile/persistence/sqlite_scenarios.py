"""SQLite scenario parent authority and durable v1 projection."""

from __future__ import annotations

import asyncio
import hashlib
import re
import sqlite3
from datetime import UTC, datetime
from itertools import pairwise
from pathlib import Path

from reconcile.contracts.codec import (
    ContractError,
    canonical_json_bytes,
    canonical_sha256,
    decode_contract,
)
from reconcile.contracts.comparison import (
    ComparisonRun,
    ComparisonStrategyKind,
    InvestigationComparisonRecord,
)
from reconcile.contracts.envelope import ExecutionEnvelope
from reconcile.contracts.operator import (
    AdvisoryTurnEventPayload,
    AdvisoryTurnStatus,
    EnvelopeSummaryEventPayload,
    ProbeRequestEventPayload,
    ScenarioLaunchRequest,
    ScenarioLifecycleEventPayload,
    ScenarioRunEvent,
    ScenarioRunEventType,
    ScenarioRunLifecycle,
    ScenarioRunMode,
    ScenarioRunResultKind,
    ScenarioRunSnapshot,
    TerminalStateEventPayload,
)
from reconcile.contracts.report import InvestigationReport, InvestigationStatus
from reconcile.contracts.scenario import ScenarioRunRequest, ScenarioRunResult
from reconcile.persistence.durable import LEASE_DURATION, CleanupStatus
from reconcile.persistence.scenarios import (
    SCENARIO_LEASE_VERSION,
    SCENARIO_WORK_ITEM_VERSION,
    CorruptScenarioState,
    CreateScenarioWorkResult,
    ScenarioInvestigationState,
    ScenarioLane,
    ScenarioLeaseToken,
    ScenarioLeaseUnavailable,
    ScenarioMutationState,
    ScenarioProjectionSnapshot,
    ScenarioStateConflict,
    ScenarioWorkConflict,
    ScenarioWorkItem,
    ScenarioWorkNotFound,
    StaleScenarioLease,
)
from reconcile.persistence.sqlite_runtime import SqliteDurableRuntimeStore, _blob

_DIGEST = re.compile(r"^[0-9a-f]{64}$")


def _aware_utc(value: datetime) -> datetime:
    if (
        not isinstance(value, datetime)
        or value.tzinfo is None
        or value.utcoffset() is None
    ):
        raise ValueError("scenario timestamps must be timezone-aware")
    return value.astimezone(UTC)


def _digest(value: str, label: str) -> str:
    if type(value) is not str or _DIGEST.fullmatch(value) is None:
        raise ValueError(f"{label} must be a SHA-256 digest")
    return value


class SqliteScenarioStore(SqliteDurableRuntimeStore):
    """Persist the parent state machine and exact non-authoritative projection."""

    def __init__(self, database_path: str | Path) -> None:
        super().__init__(database_path)

    @staticmethod
    def _scenario_decode[Model](
        payload: object,
        model_type: type[Model],
        investigation_id: str | None = None,
    ) -> Model:
        try:
            return decode_contract(_blob(payload), model_type)  # type: ignore[arg-type]
        except (ContractError, TypeError, ValueError) as error:
            raise CorruptScenarioState(investigation_id) from error

    @staticmethod
    def _decode_lane_result_payload(
        payload: object,
        investigation_id: str,
    ) -> tuple[ComparisonRun, bytes]:
        try:
            sealed = _blob(payload)
            result = ComparisonRun.model_validate_json(sealed)
        except (TypeError, ValueError) as error:
            raise CorruptScenarioState(investigation_id) from error
        if canonical_json_bytes(result) != sealed:
            raise CorruptScenarioState(investigation_id)
        return result, sealed

    def _lane_results_locked(
        self,
        connection: sqlite3.Connection,
        work: ScenarioWorkItem,
    ) -> dict[ScenarioLane, ComparisonRun]:
        investigation_id = work.scenario_request.investigation_id
        rows = connection.execute(
            """
            SELECT lane, sha256, payload
            FROM scenario_lane_results
            WHERE investigation_id = ?
            ORDER BY lane
            """,
            (investigation_id,),
        ).fetchall()
        lanes: dict[ScenarioLane, ComparisonRun] = {}
        for row in rows:
            try:
                lane = ScenarioLane(row["lane"])
            except (TypeError, ValueError) as error:
                raise CorruptScenarioState(investigation_id) from error
            result, payload = self._decode_lane_result_payload(
                row["payload"],
                investigation_id,
            )
            expected_strategy = (
                ComparisonStrategyKind.FIXED
                if lane is ScenarioLane.FIXED
                else ComparisonStrategyKind.ADAPTIVE
            )
            if (
                lane in lanes
                or row["sha256"] != hashlib.sha256(payload).hexdigest()
                or work.strategy is not ScenarioRunMode.COMPARE
                or work.envelope_sha256 is None
                or result.envelope_sha256 != work.envelope_sha256
                or result.scenario != work.scenario_request.scenario
                or result.strategy_kind is not expected_strategy
            ):
                raise CorruptScenarioState(investigation_id)
            lanes[lane] = result
        if work.strategy is not ScenarioRunMode.COMPARE:
            if lanes:
                raise CorruptScenarioState(investigation_id)
            return lanes
        if lanes and work.investigation_state is ScenarioInvestigationState.NOT_STARTED:
            raise CorruptScenarioState(investigation_id)
        if work.investigation_state is ScenarioInvestigationState.RECORDED:
            comparison = work.workflow_result
            if (
                type(comparison) is not InvestigationComparisonRecord
                or comparison.adaptive is None
                or set(lanes) != set(ScenarioLane)
                or lanes.get(ScenarioLane.FIXED) != comparison.baseline
                or lanes.get(ScenarioLane.ADAPTIVE) != comparison.adaptive
            ):
                raise CorruptScenarioState(investigation_id)
        return lanes

    def _work_locked(
        self,
        connection: sqlite3.Connection,
        investigation_id: str,
    ) -> ScenarioWorkItem:
        row = connection.execute(
            """
            SELECT launch_id, launch_sha256, payload
            FROM scenario_work_items
            WHERE investigation_id = ?
            """,
            (investigation_id,),
        ).fetchone()
        if row is None:
            raise ScenarioWorkNotFound(investigation_id)
        work = self._scenario_decode(
            row["payload"],
            ScenarioWorkItem,
            investigation_id,
        )
        if (
            row["launch_id"] != work.launch_request.launch_id
            or row["launch_sha256"] != work.launch_sha256
            or investigation_id != work.scenario_request.investigation_id
        ):
            raise CorruptScenarioState(investigation_id)
        self._lane_results_locked(connection, work)
        return work

    @staticmethod
    def _replace_work_locked(
        connection: sqlite3.Connection,
        work: ScenarioWorkItem,
    ) -> None:
        cursor = connection.execute(
            """
            UPDATE scenario_work_items
            SET launch_sha256 = ?, payload = ?
            WHERE investigation_id = ?
            """,
            (
                work.launch_sha256,
                canonical_json_bytes(work),
                work.scenario_request.investigation_id,
            ),
        )
        if cursor.rowcount != 1:
            raise ScenarioWorkNotFound(work.scenario_request.investigation_id)

    async def create_work(
        self,
        launch_request: ScenarioLaunchRequest,
        scenario_request: ScenarioRunRequest,
        *,
        strategy_sha256: str,
        semantic_config_sha256: str,
        runtime_provenance_sha256: str,
        workspace_id: str,
        invoked_at: datetime,
        snapshot: ScenarioRunSnapshot,
        accepted_event: ScenarioRunEvent,
        created_at: datetime,
    ) -> CreateScenarioWorkResult:
        return await asyncio.to_thread(
            self._create_work,
            launch_request,
            scenario_request,
            strategy_sha256,
            semantic_config_sha256,
            runtime_provenance_sha256,
            workspace_id,
            invoked_at,
            snapshot,
            accepted_event,
            created_at,
        )

    def _create_work(
        self,
        launch_request: ScenarioLaunchRequest,
        scenario_request: ScenarioRunRequest,
        strategy_sha256: str,
        semantic_config_sha256: str,
        runtime_provenance_sha256: str,
        workspace_id: str,
        invoked_at: datetime,
        snapshot: ScenarioRunSnapshot,
        accepted_event: ScenarioRunEvent,
        created_at: datetime,
    ) -> CreateScenarioWorkResult:
        if type(launch_request) is not ScenarioLaunchRequest:
            raise TypeError("scenario launch request must be exact")
        if type(scenario_request) is not ScenarioRunRequest:
            raise TypeError("scenario run request must be exact")
        if type(snapshot) is not ScenarioRunSnapshot:
            raise TypeError("scenario snapshot must be exact")
        if type(accepted_event) is not ScenarioRunEvent:
            raise TypeError("scenario event must be exact")
        created_at = _aware_utc(created_at)
        invoked_at = _aware_utc(invoked_at)
        investigation_id = scenario_request.investigation_id
        if (
            accepted_event.investigation_id != investigation_id
            or accepted_event.cursor != 1
            or accepted_event.type is not ScenarioRunEventType.LIFECYCLE
            or not isinstance(
                accepted_event.payload,
                ScenarioLifecycleEventPayload,
            )
            or accepted_event.payload.lifecycle is not ScenarioRunLifecycle.ACCEPTED
            or snapshot.lifecycle is not ScenarioRunLifecycle.ACCEPTED
            or snapshot.investigation_id != investigation_id
            or snapshot.event_cursor != 1
            or accepted_event.occurred_at != snapshot.accepted_at
            or created_at != snapshot.accepted_at
        ):
            raise ValueError("initial scenario projection is invalid")
        work = ScenarioWorkItem(
            schema_version=SCENARIO_WORK_ITEM_VERSION,
            launch_request=launch_request,
            launch_sha256=canonical_sha256(launch_request),
            scenario_request=scenario_request,
            scenario_request_sha256=canonical_sha256(scenario_request),
            strategy=launch_request.mode,
            strategy_sha256=_digest(strategy_sha256, "scenario strategy"),
            semantic_config_sha256=_digest(
                semantic_config_sha256,
                "scenario semantic configuration",
            ),
            runtime_provenance_sha256=_digest(
                runtime_provenance_sha256,
                "scenario runtime provenance",
            ),
            workspace_id=workspace_id,
            invoked_at=invoked_at,
            mutation_state=ScenarioMutationState.NOT_STARTED,
            investigation_state=ScenarioInvestigationState.NOT_STARTED,
            snapshot=snapshot,
            created_at=created_at,
            updated_at=created_at,
            revision=0,
        )
        try:
            with self._write() as connection:
                row = connection.execute(
                    """
                    SELECT investigation_id, launch_sha256, payload
                    FROM scenario_work_items
                    WHERE launch_id = ? OR investigation_id = ?
                    """,
                    (launch_request.launch_id, investigation_id),
                ).fetchone()
                if row is not None:
                    current = self._scenario_decode(
                        row["payload"],
                        ScenarioWorkItem,
                        row["investigation_id"],
                    )
                    if (
                        row["investigation_id"] != investigation_id
                        or row["launch_sha256"] != work.launch_sha256
                        or canonical_json_bytes(current.launch_request)
                        != canonical_json_bytes(work.launch_request)
                    ):
                        raise ScenarioWorkConflict(
                            launch_request.launch_id,
                            str(row["investigation_id"]),
                        )
                    return CreateScenarioWorkResult(work=current, created=False)
                connection.execute(
                    """
                    INSERT INTO scenario_work_items (
                        investigation_id, launch_id, launch_sha256, payload
                    ) VALUES (?, ?, ?, ?)
                    """,
                    (
                        investigation_id,
                        launch_request.launch_id,
                        work.launch_sha256,
                        canonical_json_bytes(work),
                    ),
                )
                connection.execute(
                    """
                    INSERT INTO scenario_events (
                        investigation_id, cursor, terminal, payload
                    ) VALUES (?, 1, 0, ?)
                    """,
                    (investigation_id, canonical_json_bytes(accepted_event)),
                )
                return CreateScenarioWorkResult(work=work, created=True)
        except (ScenarioWorkConflict, CorruptScenarioState):
            raise
        except sqlite3.DatabaseError as error:
            raise CorruptScenarioState(investigation_id) from error

    async def get_work(self, investigation_id: str) -> ScenarioWorkItem:
        return await asyncio.to_thread(self._get_work, investigation_id)

    def _get_work(self, investigation_id: str) -> ScenarioWorkItem:
        try:
            with self._connect() as connection:
                return self._work_locked(connection, investigation_id)
        except (ScenarioWorkNotFound, CorruptScenarioState):
            raise
        except sqlite3.DatabaseError as error:
            raise CorruptScenarioState(investigation_id) from error

    async def list_work(self) -> tuple[ScenarioWorkItem, ...]:
        return await asyncio.to_thread(self._list_work)

    def _list_work(self) -> tuple[ScenarioWorkItem, ...]:
        try:
            with self._connect() as connection:
                rows = connection.execute(
                    """
                    SELECT investigation_id, launch_id, launch_sha256, payload
                    FROM scenario_work_items
                    ORDER BY investigation_id
                    """
                ).fetchall()
                work = tuple(
                    self._scenario_decode(
                        row["payload"],
                        ScenarioWorkItem,
                        row["investigation_id"],
                    )
                    for row in rows
                )
                if any(
                    item.scenario_request.investigation_id != row["investigation_id"]
                    or item.launch_request.launch_id != row["launch_id"]
                    or item.launch_sha256 != row["launch_sha256"]
                    for row, item in zip(rows, work, strict=True)
                ):
                    raise CorruptScenarioState()
                for item in work:
                    self._lane_results_locked(connection, item)
                return work
        except CorruptScenarioState:
            raise
        except sqlite3.DatabaseError as error:
            raise CorruptScenarioState() from error

    def _lease_locked(
        self,
        connection: sqlite3.Connection,
        token: ScenarioLeaseToken,
        now: datetime,
    ) -> ScenarioLeaseToken:
        row = connection.execute(
            """
            SELECT investigation_id, fence, payload
            FROM scenario_leases
            WHERE investigation_id = ?
            """,
            (token.investigation_id,),
        ).fetchone()
        if row is None:
            raise StaleScenarioLease(token.investigation_id)
        _, current = self._validated_scenario_lease_row(
            row,
            token.investigation_id,
        )
        if current is None or current != token or current.expired(now):
            raise StaleScenarioLease(token.investigation_id)
        return current

    def _validated_scenario_lease_row(
        self,
        row: sqlite3.Row,
        investigation_id: str,
    ) -> tuple[int, ScenarioLeaseToken | None]:
        fence = row["fence"]
        if (
            row["investigation_id"] != investigation_id
            or type(fence) is not int
            or fence < 1
            or fence > 2**63 - 1
        ):
            raise CorruptScenarioState(investigation_id)
        if row["payload"] is None:
            return fence, None
        current = self._scenario_decode(
            row["payload"],
            ScenarioLeaseToken,
            investigation_id,
        )
        if current.investigation_id != investigation_id or current.fence != fence:
            raise CorruptScenarioState(investigation_id)
        return fence, current

    async def acquire_scenario_lease(
        self,
        investigation_id: str,
        owner_id: str,
        *,
        now: datetime,
    ) -> ScenarioLeaseToken:
        return await asyncio.to_thread(
            self._acquire_scenario_lease,
            investigation_id,
            owner_id,
            now,
        )

    def _acquire_scenario_lease(
        self,
        investigation_id: str,
        owner_id: str,
        now: datetime,
    ) -> ScenarioLeaseToken:
        now = _aware_utc(now)
        try:
            with self._write() as connection:
                self._work_locked(connection, investigation_id)
                row = connection.execute(
                    """
                    SELECT investigation_id, fence, payload FROM scenario_leases
                    WHERE investigation_id = ?
                    """,
                    (investigation_id,),
                ).fetchone()
                if row is None:
                    fence = 1
                    current = None
                else:
                    previous_fence, current = self._validated_scenario_lease_row(
                        row,
                        investigation_id,
                    )
                    fence = previous_fence + 1
                if current is not None:
                    if not current.expired(now):
                        raise ScenarioLeaseUnavailable(investigation_id)
                token = ScenarioLeaseToken(
                    schema_version=SCENARIO_LEASE_VERSION,
                    investigation_id=investigation_id,
                    owner_id=owner_id,
                    fence=fence,
                    acquired_at=now,
                    renewed_at=now,
                    expires_at=now + LEASE_DURATION,
                )
                connection.execute(
                    """
                    INSERT INTO scenario_leases (investigation_id, fence, payload)
                    VALUES (?, ?, ?)
                    ON CONFLICT(investigation_id) DO UPDATE SET
                        fence = excluded.fence,
                        payload = excluded.payload
                    """,
                    (investigation_id, fence, canonical_json_bytes(token)),
                )
                return token
        except (
            CorruptScenarioState,
            ScenarioLeaseUnavailable,
            ScenarioWorkNotFound,
        ):
            raise
        except sqlite3.DatabaseError as error:
            raise CorruptScenarioState(investigation_id) from error

    async def renew_scenario_lease(
        self,
        token: ScenarioLeaseToken,
        *,
        now: datetime,
    ) -> ScenarioLeaseToken:
        return await asyncio.to_thread(self._renew_scenario_lease, token, now)

    def _renew_scenario_lease(
        self,
        token: ScenarioLeaseToken,
        now: datetime,
    ) -> ScenarioLeaseToken:
        now = max(_aware_utc(now), token.renewed_at)
        try:
            with self._write() as connection:
                self._lease_locked(connection, token, now)
                renewed = token.model_copy(
                    update={"renewed_at": now, "expires_at": now + LEASE_DURATION}
                )
                connection.execute(
                    """
                    UPDATE scenario_leases SET payload = ?
                    WHERE investigation_id = ? AND fence = ?
                    """,
                    (
                        canonical_json_bytes(renewed),
                        token.investigation_id,
                        token.fence,
                    ),
                )
                return renewed
        except (CorruptScenarioState, StaleScenarioLease):
            raise
        except sqlite3.DatabaseError as error:
            raise CorruptScenarioState(token.investigation_id) from error

    async def release_scenario_lease(
        self,
        token: ScenarioLeaseToken,
        *,
        now: datetime,
    ) -> None:
        await asyncio.to_thread(self._release_scenario_lease, token, now)

    def _release_scenario_lease(
        self,
        token: ScenarioLeaseToken,
        now: datetime,
    ) -> None:
        now = max(_aware_utc(now), token.renewed_at)
        try:
            with self._write() as connection:
                self._lease_locked(connection, token, now)
                cursor = connection.execute(
                    """
                    UPDATE scenario_leases SET payload = NULL
                    WHERE investigation_id = ? AND fence = ?
                    """,
                    (token.investigation_id, token.fence),
                )
                if cursor.rowcount != 1:
                    raise StaleScenarioLease(token.investigation_id)
        except (CorruptScenarioState, StaleScenarioLease):
            raise
        except sqlite3.DatabaseError as error:
            raise CorruptScenarioState(token.investigation_id) from error

    def _transition_locked(
        self,
        connection: sqlite3.Connection,
        token: ScenarioLeaseToken,
        now: datetime,
        operation: str,
        updates: dict[str, object],
    ) -> ScenarioWorkItem:
        self._lease_locked(connection, token, now)
        current = self._work_locked(connection, token.investigation_id)
        replacement = current.model_copy(
            update={
                **updates,
                "updated_at": max(now, current.updated_at),
                "revision": current.revision + 1,
            }
        )
        try:
            replacement = decode_contract(
                canonical_json_bytes(replacement),
                ScenarioWorkItem,
            )
        except (ContractError, TypeError, ValueError) as error:
            raise ScenarioStateConflict(token.investigation_id, operation) from error
        self._replace_work_locked(connection, replacement)
        return replacement

    async def record_mutation_started(
        self,
        token: ScenarioLeaseToken,
        *,
        prepared_envelope: ExecutionEnvelope | None = None,
        prepared_envelope_sha256: str,
        cleanup_manifest_sha256: str,
        occurred_at: datetime,
    ) -> ScenarioWorkItem:
        return await asyncio.to_thread(
            self._record_mutation_started,
            token,
            prepared_envelope,
            prepared_envelope_sha256,
            cleanup_manifest_sha256,
            occurred_at,
        )

    def _record_mutation_started(
        self,
        token: ScenarioLeaseToken,
        prepared_envelope: ExecutionEnvelope | None,
        prepared_envelope_sha256: str,
        cleanup_manifest_sha256: str,
        occurred_at: datetime,
    ) -> ScenarioWorkItem:
        occurred_at = _aware_utc(occurred_at)
        with self._write() as connection:
            current = self._work_locked(connection, token.investigation_id)
            if current.mutation_state is not ScenarioMutationState.NOT_STARTED:
                raise ScenarioStateConflict(token.investigation_id, "start mutation")
            digest = _digest(prepared_envelope_sha256, "prepared envelope")
            if prepared_envelope is not None:
                if type(prepared_envelope) is not ExecutionEnvelope:
                    raise TypeError("prepared scenario envelope must be exact")
                request = current.scenario_request
                invocation = prepared_envelope.context.invocation
                if (
                    canonical_sha256(prepared_envelope) != digest
                    or prepared_envelope.investigation_id != request.investigation_id
                    or prepared_envelope.operation_id != request.operation_id
                    or invocation.invocation_id != request.invocation_id
                    or invocation.function_call_id != request.function_call_id
                ):
                    raise ScenarioStateConflict(
                        token.investigation_id,
                        "start mutation",
                    )
            return self._transition_locked(
                connection,
                token,
                occurred_at,
                "start mutation",
                {
                    "mutation_state": ScenarioMutationState.STARTED,
                    "prepared_envelope_sha256": digest,
                    "cleanup_manifest_sha256": _digest(
                        cleanup_manifest_sha256,
                        "cleanup manifest",
                    ),
                },
            )

    async def record_mutation_result(
        self,
        token: ScenarioLeaseToken,
        result: ScenarioRunResult,
        *,
        prepared_envelope_bytes: bytes,
        occurred_at: datetime,
    ) -> ScenarioWorkItem:
        return await asyncio.to_thread(
            self._record_mutation_result,
            token,
            result,
            prepared_envelope_bytes,
            occurred_at,
        )

    def _record_mutation_result(
        self,
        token: ScenarioLeaseToken,
        result: ScenarioRunResult,
        prepared_envelope_bytes: bytes,
        occurred_at: datetime,
    ) -> ScenarioWorkItem:
        occurred_at = _aware_utc(occurred_at)
        if type(result) is not ScenarioRunResult:
            raise TypeError("scenario mutation result must be exact")
        if type(prepared_envelope_bytes) is not bytes:
            raise TypeError("prepared scenario envelope must be exact bytes")
        with self._write() as connection:
            current = self._work_locked(connection, token.investigation_id)
            if current.mutation_state is not ScenarioMutationState.STARTED:
                raise ScenarioStateConflict(token.investigation_id, "record mutation")
            if (
                current.prepared_envelope_sha256
                != hashlib.sha256(prepared_envelope_bytes).hexdigest()
            ):
                raise ScenarioStateConflict(
                    token.investigation_id,
                    "record mutation envelope lineage",
                )
            try:
                prepared_envelope = decode_contract(
                    prepared_envelope_bytes,
                    ExecutionEnvelope,
                )
            except (ContractError, TypeError, ValueError) as error:
                raise ScenarioStateConflict(
                    token.investigation_id,
                    "record mutation envelope lineage",
                ) from error
            if canonical_json_bytes(prepared_envelope) != prepared_envelope_bytes:
                raise ScenarioStateConflict(
                    token.investigation_id,
                    "record mutation envelope lineage",
                )
            if result.execution_envelope is not None:
                derived_envelope = prepared_envelope.model_copy(
                    update={"ambiguity": result.execution_envelope.ambiguity}
                )
                if canonical_json_bytes(derived_envelope) != canonical_json_bytes(
                    result.execution_envelope
                ):
                    raise ScenarioStateConflict(
                        token.investigation_id,
                        "record mutation envelope lineage",
                    )
            envelope_sha256 = (
                None
                if result.execution_envelope is None
                else canonical_sha256(result.execution_envelope)
            )
            return self._transition_locked(
                connection,
                token,
                occurred_at,
                "record mutation",
                {
                    "mutation_state": ScenarioMutationState.RECORDED,
                    "scenario_result": result,
                    "envelope_sha256": envelope_sha256,
                },
            )

    async def mark_investigation_started(
        self,
        token: ScenarioLeaseToken,
        *,
        occurred_at: datetime,
    ) -> ScenarioWorkItem:
        return await asyncio.to_thread(
            self._mark_investigation_started,
            token,
            occurred_at,
        )

    def _mark_investigation_started(
        self,
        token: ScenarioLeaseToken,
        occurred_at: datetime,
    ) -> ScenarioWorkItem:
        occurred_at = _aware_utc(occurred_at)
        with self._write() as connection:
            current = self._work_locked(connection, token.investigation_id)
            if (
                current.mutation_state is not ScenarioMutationState.RECORDED
                or current.envelope_sha256 is None
                or current.investigation_state
                is not ScenarioInvestigationState.NOT_STARTED
            ):
                raise ScenarioStateConflict(
                    token.investigation_id,
                    "start investigation",
                )
            return self._transition_locked(
                connection,
                token,
                occurred_at,
                "start investigation",
                {"investigation_state": ScenarioInvestigationState.STARTED},
            )

    async def record_workflow_result(
        self,
        token: ScenarioLeaseToken,
        result: InvestigationReport | InvestigationComparisonRecord,
        *,
        occurred_at: datetime,
    ) -> ScenarioWorkItem:
        return await asyncio.to_thread(
            self._record_workflow_result,
            token,
            result,
            occurred_at,
        )

    def _record_workflow_result(
        self,
        token: ScenarioLeaseToken,
        result: InvestigationReport | InvestigationComparisonRecord,
        occurred_at: datetime,
    ) -> ScenarioWorkItem:
        occurred_at = _aware_utc(occurred_at)
        if type(result) not in {InvestigationReport, InvestigationComparisonRecord}:
            raise TypeError("scenario workflow result must be exact")
        with self._write() as connection:
            current = self._work_locked(connection, token.investigation_id)
            if current.investigation_state is not ScenarioInvestigationState.STARTED:
                raise ScenarioStateConflict(
                    token.investigation_id,
                    "record investigation",
                )
            accepted = False
            if type(result) is InvestigationReport:
                accepted = (
                    current.strategy is not ScenarioRunMode.COMPARE
                    and result.status is InvestigationStatus.COMPLETED
                    and result.investigation_id == token.investigation_id
                    and result.envelope_sha256 == current.envelope_sha256
                )
            elif current.strategy is ScenarioRunMode.COMPARE:
                lanes = self._lane_results_locked(connection, current)
                accepted = (
                    result.adaptive is not None
                    and result.scenario == current.scenario_request.scenario
                    and result.envelope_sha256 == current.envelope_sha256
                    and set(lanes) == set(ScenarioLane)
                    and lanes.get(ScenarioLane.FIXED) == result.baseline
                    and lanes.get(ScenarioLane.ADAPTIVE) == result.adaptive
                )
            if not accepted:
                raise ScenarioStateConflict(
                    token.investigation_id,
                    "record investigation",
                )
            return self._transition_locked(
                connection,
                token,
                occurred_at,
                "record investigation",
                {
                    "investigation_state": ScenarioInvestigationState.RECORDED,
                    "workflow_result": result,
                },
            )

    async def require_scenario_escalation(
        self,
        token: ScenarioLeaseToken,
        failure_code: str,
        *,
        occurred_at: datetime,
    ) -> ScenarioWorkItem:
        return await asyncio.to_thread(
            self._require_scenario_escalation,
            token,
            failure_code,
            occurred_at,
        )

    def _require_scenario_escalation(
        self,
        token: ScenarioLeaseToken,
        failure_code: str,
        occurred_at: datetime,
    ) -> ScenarioWorkItem:
        occurred_at = _aware_utc(occurred_at)
        with self._write() as connection:
            current = self._work_locked(connection, token.investigation_id)
            if current.investigation_state is ScenarioInvestigationState.RECORDED:
                raise ScenarioStateConflict(token.investigation_id, "escalate")
            return self._transition_locked(
                connection,
                token,
                occurred_at,
                "escalate",
                {
                    "investigation_state": (
                        ScenarioInvestigationState.ESCALATION_REQUIRED
                    ),
                    "recovery_failure_code": failure_code,
                },
            )

    async def record_scenario_cleanup(
        self,
        token: ScenarioLeaseToken,
        status: CleanupStatus,
        *,
        occurred_at: datetime,
        failure_code: str | None = None,
    ) -> ScenarioWorkItem:
        return await asyncio.to_thread(
            self._record_scenario_cleanup,
            token,
            status,
            occurred_at,
            failure_code,
        )

    def _record_scenario_cleanup(
        self,
        token: ScenarioLeaseToken,
        status: CleanupStatus,
        occurred_at: datetime,
        failure_code: str | None,
    ) -> ScenarioWorkItem:
        occurred_at = _aware_utc(occurred_at)
        if type(status) is not CleanupStatus:
            raise TypeError("scenario cleanup status must be exact")
        with self._write() as connection:
            current = self._work_locked(connection, token.investigation_id)
            allowed = {
                CleanupStatus.NOT_REQUESTED: {CleanupStatus.PENDING},
                CleanupStatus.PENDING: {CleanupStatus.SUCCEEDED, CleanupStatus.FAILED},
            }
            if (
                current.investigation_state is not ScenarioInvestigationState.RECORDED
                or status not in allowed.get(current.cleanup_status, set())
                or (status is CleanupStatus.FAILED) is not (failure_code is not None)
            ):
                raise ScenarioStateConflict(token.investigation_id, "record cleanup")
            return self._transition_locked(
                connection,
                token,
                occurred_at,
                "record cleanup",
                {
                    "cleanup_status": status,
                    "cleanup_failure_code": failure_code,
                },
            )

    async def append_projection(
        self,
        snapshot: ScenarioRunSnapshot,
        event: ScenarioRunEvent,
        *,
        terminal: bool,
    ) -> ScenarioWorkItem:
        return await asyncio.to_thread(
            self._append_projection,
            snapshot,
            event,
            terminal,
        )

    def _append_projection(
        self,
        snapshot: ScenarioRunSnapshot,
        event: ScenarioRunEvent,
        terminal: bool,
    ) -> ScenarioWorkItem:
        if (
            type(snapshot) is not ScenarioRunSnapshot
            or type(event) is not ScenarioRunEvent
        ):
            raise TypeError("scenario projection values must be exact")
        investigation_id = snapshot.investigation_id
        try:
            with self._write() as connection:
                current = self._work_locked(connection, investigation_id)
                expected_cursor = current.snapshot.event_cursor + 1
                current_terminal = connection.execute(
                    """
                    SELECT terminal FROM scenario_events
                    WHERE investigation_id = ? ORDER BY cursor DESC LIMIT 1
                    """,
                    (investigation_id,),
                ).fetchone()
                checks = (
                    (current_terminal is not None, "projection journal missing"),
                    (
                        current_terminal is not None
                        and not bool(current_terminal["terminal"]),
                        "projection journal terminal",
                    ),
                    (
                        event.investigation_id == investigation_id,
                        "projection identity",
                    ),
                    (event.cursor == expected_cursor, "projection event cursor"),
                    (
                        snapshot.event_cursor == expected_cursor,
                        "projection snapshot cursor",
                    ),
                    (
                        snapshot.launch_id == current.launch_request.launch_id,
                        "projection launch identity",
                    ),
                    (
                        snapshot.updated_at == event.occurred_at,
                        "projection timestamp",
                    ),
                    (
                        terminal is (event.type is ScenarioRunEventType.TERMINAL),
                        "projection terminal flag",
                    ),
                )
                failed = next(
                    (label for accepted, label in checks if not accepted), None
                )
                if failed is not None:
                    raise ScenarioStateConflict(investigation_id, failed)
                connection.execute(
                    """
                    INSERT INTO scenario_events (
                        investigation_id, cursor, terminal, payload
                    ) VALUES (?, ?, ?, ?)
                    """,
                    (
                        investigation_id,
                        event.cursor,
                        int(terminal),
                        canonical_json_bytes(event),
                    ),
                )
                replacement = current.model_copy(
                    update={
                        "snapshot": snapshot,
                        "updated_at": max(current.updated_at, snapshot.updated_at),
                        "revision": current.revision + 1,
                    }
                )
                replacement = decode_contract(
                    canonical_json_bytes(replacement),
                    ScenarioWorkItem,
                )
                self._replace_work_locked(connection, replacement)
                return replacement
        except (CorruptScenarioState, ScenarioStateConflict, ScenarioWorkNotFound):
            raise
        except (ContractError, sqlite3.DatabaseError, TypeError, ValueError) as error:
            raise CorruptScenarioState(investigation_id) from error

    async def snapshot_projection(
        self,
        investigation_id: str,
        *,
        after: int = 0,
    ) -> ScenarioProjectionSnapshot:
        return await asyncio.to_thread(
            self._snapshot_projection,
            investigation_id,
            after,
        )

    @staticmethod
    def _projection_semantics_valid(
        work: ScenarioWorkItem,
        events: tuple[ScenarioRunEvent, ...],
        *,
        terminal: bool,
    ) -> bool:
        snapshot = work.snapshot
        if not events:
            return False
        first = events[0]
        if (
            first.type is not ScenarioRunEventType.LIFECYCLE
            or not isinstance(first.payload, ScenarioLifecycleEventPayload)
            or first.payload.lifecycle is not ScenarioRunLifecycle.ACCEPTED
            or first.occurred_at != snapshot.accepted_at
            or snapshot.updated_at != events[-1].occurred_at
            or any(
                current.occurred_at < previous.occurred_at
                for previous, current in pairwise(events)
            )
        ):
            return False
        if len(events) > 1:
            running = events[1]
            if (
                running.type is not ScenarioRunEventType.LIFECYCLE
                or not isinstance(running.payload, ScenarioLifecycleEventPayload)
                or running.payload.lifecycle is not ScenarioRunLifecycle.RUNNING
            ):
                return False
        if any(event.type is ScenarioRunEventType.LIFECYCLE for event in events[2:]):
            return False
        envelope_events = tuple(
            event.payload.summary
            for event in events
            if isinstance(event.payload, EnvelopeSummaryEventPayload)
        )
        if len(envelope_events) > 1 or (
            snapshot.envelope_summary
            != (None if not envelope_events else envelope_events[0])
        ):
            return False
        if snapshot.envelope_summary is not None and (
            work.envelope_sha256 is None
            or snapshot.envelope_summary.envelope_sha256 != work.envelope_sha256
        ):
            return False
        request_sequence = 0
        advisory_turn_sequence = 0
        advisory_turn_open: AdvisoryTurnEventPayload | None = None
        for event in events:
            if isinstance(event.payload, ProbeRequestEventPayload):
                request_sequence += 1
                if event.payload.request.request_sequence != request_sequence:
                    return False
            elif isinstance(event.payload, AdvisoryTurnEventPayload):
                turn = event.payload.turn
                if turn.status is AdvisoryTurnStatus.STARTED:
                    if (
                        advisory_turn_open is not None
                        or turn.turn_sequence != advisory_turn_sequence + 1
                    ):
                        return False
                    advisory_turn_sequence = turn.turn_sequence
                    advisory_turn_open = event.payload
                elif (
                    advisory_turn_open is None
                    or turn.turn_sequence != advisory_turn_sequence
                    or turn.phase is not advisory_turn_open.turn.phase
                    or turn.input_sha256 != advisory_turn_open.turn.input_sha256
                ):
                    return False
                else:
                    advisory_turn_open = None
        if not terminal:
            expected = (
                ScenarioRunLifecycle.ACCEPTED
                if len(events) == 1
                else ScenarioRunLifecycle.RUNNING
            )
            return snapshot.lifecycle is expected
        if (
            not isinstance(events[-1].payload, TerminalStateEventPayload)
            or events[-1].type is not ScenarioRunEventType.TERMINAL
            or advisory_turn_open is not None
        ):
            return False
        summary = events[-1].payload.terminal
        if summary.lifecycle is not snapshot.lifecycle:
            return False
        if snapshot.lifecycle is ScenarioRunLifecycle.COMPLETED:
            if snapshot.report is not None:
                allowed = sum(gate.allowed for gate in snapshot.report.action_gate)
                return (
                    summary.result_kind is ScenarioRunResultKind.REPORT
                    and summary.classification is snapshot.report.classification
                    and summary.action_gate_allowed_count == allowed
                    and summary.action_gate_denied_count
                    == len(snapshot.report.action_gate) - allowed
                    and summary.missing_evidence_count
                    == len(snapshot.report.missing_evidence)
                    and summary.escalation_required
                    is (snapshot.report.classification.value != "COMMITTED")
                    and summary.failure_category is None
                    and summary.route_provenance == snapshot.report.route_provenance
                )
            return (
                snapshot.comparison is not None
                and summary.result_kind is ScenarioRunResultKind.COMPARISON
                and summary.classification is None
                and summary.action_gate_allowed_count == 0
                and summary.action_gate_denied_count == 0
                and summary.missing_evidence_count == 0
                and summary.escalation_required is None
                and summary.failure_category is None
            )
        if snapshot.lifecycle is ScenarioRunLifecycle.FAILED:
            return (
                summary.result_kind is ScenarioRunResultKind.NONE
                and summary.failure_category is snapshot.failure_category
            )
        return (
            snapshot.lifecycle is ScenarioRunLifecycle.CANCELLED
            and summary.result_kind is ScenarioRunResultKind.NONE
            and summary.failure_category is None
        )

    def _snapshot_projection(
        self,
        investigation_id: str,
        after: int,
    ) -> ScenarioProjectionSnapshot:
        try:
            with self._connect() as connection:
                connection.execute("BEGIN")
                work = self._work_locked(connection, investigation_id)
                if isinstance(after, bool) or not isinstance(after, int):
                    raise ValueError("scenario projection cursor must be an integer")
                rows = connection.execute(
                    """
                    SELECT cursor, terminal, payload FROM scenario_events
                    WHERE investigation_id = ? ORDER BY cursor
                    """,
                    (investigation_id,),
                ).fetchall()
                events = tuple(
                    self._scenario_decode(
                        row["payload"],
                        ScenarioRunEvent,
                        investigation_id,
                    )
                    for row in rows
                )
                if (
                    not 0 <= after <= len(events)
                    or len(events) != work.snapshot.event_cursor
                    or any(
                        event.cursor != index
                        or row["cursor"] != index
                        or event.investigation_id != investigation_id
                        or bool(row["terminal"])
                        is not (event.type is ScenarioRunEventType.TERMINAL)
                        or (row["terminal"] and index != len(events))
                        for index, (row, event) in enumerate(
                            zip(rows, events, strict=True),
                            1,
                        )
                    )
                    or not self._projection_semantics_valid(
                        work,
                        events,
                        terminal=bool(rows and rows[-1]["terminal"]),
                    )
                ):
                    raise CorruptScenarioState(investigation_id)
                return ScenarioProjectionSnapshot(
                    snapshot=work.snapshot,
                    events=events[after:],
                    cursor=len(events),
                    terminal=bool(rows[-1]["terminal"]),
                )
        except (CorruptScenarioState, ScenarioWorkNotFound, ValueError):
            raise
        except sqlite3.DatabaseError as error:
            raise CorruptScenarioState(investigation_id) from error

    async def record_lane_result(
        self,
        token: ScenarioLeaseToken,
        lane: ScenarioLane,
        result: ComparisonRun,
        *,
        occurred_at: datetime,
    ) -> None:
        await asyncio.to_thread(
            self._record_lane_result,
            token,
            lane,
            result,
            occurred_at,
        )

    def _record_lane_result(
        self,
        token: ScenarioLeaseToken,
        lane: ScenarioLane,
        result: ComparisonRun,
        occurred_at: datetime,
    ) -> None:
        if type(lane) is not ScenarioLane or type(result) is not ComparisonRun:
            raise TypeError("scenario lane result values must be exact")
        occurred_at = _aware_utc(occurred_at)
        investigation_id = token.investigation_id
        payload = canonical_json_bytes(result)
        sha256 = hashlib.sha256(payload).hexdigest()
        try:
            with self._write() as connection:
                self._lease_locked(connection, token, occurred_at)
                work = self._work_locked(connection, investigation_id)
                expected_strategy = (
                    ComparisonStrategyKind.FIXED
                    if lane is ScenarioLane.FIXED
                    else ComparisonStrategyKind.ADAPTIVE
                )
                if (
                    work.strategy is not ScenarioRunMode.COMPARE
                    or work.investigation_state
                    is not ScenarioInvestigationState.STARTED
                    or work.envelope_sha256 != result.envelope_sha256
                    or work.scenario_request.scenario != result.scenario
                    or result.strategy_kind is not expected_strategy
                ):
                    raise ScenarioStateConflict(
                        investigation_id,
                        "record lane result",
                    )
                row = connection.execute(
                    """
                    SELECT sha256, payload FROM scenario_lane_results
                    WHERE investigation_id = ? AND lane = ?
                    """,
                    (investigation_id, lane.value),
                ).fetchone()
                if row is not None:
                    if row["sha256"] != sha256 or _blob(row["payload"]) != payload:
                        raise ScenarioStateConflict(
                            investigation_id,
                            "record lane result",
                        )
                    return
                connection.execute(
                    """
                    INSERT INTO scenario_lane_results (
                        investigation_id, lane, sha256, payload
                    ) VALUES (?, ?, ?, ?)
                    """,
                    (investigation_id, lane.value, sha256, payload),
                )
        except (
            CorruptScenarioState,
            ScenarioStateConflict,
            ScenarioWorkNotFound,
            StaleScenarioLease,
        ):
            raise
        except sqlite3.DatabaseError as error:
            raise CorruptScenarioState(investigation_id) from error

    async def get_lane_result(
        self,
        investigation_id: str,
        lane: ScenarioLane,
    ) -> ComparisonRun | None:
        return await asyncio.to_thread(
            self._get_lane_result,
            investigation_id,
            lane,
        )

    def _get_lane_result(
        self,
        investigation_id: str,
        lane: ScenarioLane,
    ) -> ComparisonRun | None:
        try:
            with self._connect() as connection:
                self._work_locked(connection, investigation_id)
                row = connection.execute(
                    """
                    SELECT sha256, payload FROM scenario_lane_results
                    WHERE investigation_id = ? AND lane = ?
                    """,
                    (investigation_id, lane.value),
                ).fetchone()
                if row is None:
                    return None
                result, payload = self._decode_lane_result_payload(
                    row["payload"],
                    investigation_id,
                )
                if row["sha256"] != hashlib.sha256(payload).hexdigest():
                    raise CorruptScenarioState(investigation_id)
                return result
        except (CorruptScenarioState, ScenarioWorkNotFound):
            raise
        except sqlite3.DatabaseError as error:
            raise CorruptScenarioState(investigation_id) from error


__all__ = ["SqliteScenarioStore"]
