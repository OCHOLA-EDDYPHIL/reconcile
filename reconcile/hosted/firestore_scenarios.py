"""Request-scoped scenario authority persisted through bounded Firestore CAS."""

from __future__ import annotations

import asyncio
import hashlib
import re
from dataclasses import dataclass
from datetime import UTC, datetime
from itertools import pairwise
from typing import Literal, Protocol

from pydantic import Field, model_validator

from reconcile.contracts.base import Identifier, Sha256Digest, StrictModel
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
    MAX_SCENARIO_RUN_EVENTS,
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
from reconcile.hosted.firestore_cas import (
    FirestoreCasCollection,
    FirestoreCasConflict,
    FirestoreCasCorruptDocument,
    FirestoreCasDocument,
    FirestoreCasSnapshot,
    build_firestore_cas_document,
    new_firestore_cas_mutation_id,
)
from reconcile.hosted.provider import HostedCandidateIdentity
from reconcile.operator import sanitize_comparison, sanitize_report
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
    ScenarioPersistenceError,
    ScenarioProjectionSnapshot,
    ScenarioStateConflict,
    ScenarioWorkConflict,
    ScenarioWorkItem,
    ScenarioWorkNotFound,
    StaleScenarioLease,
)

FIRESTORE_SCENARIO_AGGREGATE_VERSION = "reconcile/firestore-scenario-aggregate/v1"
FIRESTORE_SCENARIO_INDEX_VERSION = "reconcile/firestore-scenario-index/v1"

_DIGEST = re.compile(r"^[0-9a-f]{64}$")


class FirestoreScenarioStoreError(ScenarioPersistenceError):
    """A sanitized hosted scenario persistence failure."""

    def __init__(self) -> None:
        super().__init__("hosted scenario persistence is unavailable")


class FirestoreScenarioEnumerationUnavailable(ScenarioPersistenceError):
    """Hosted request-scoped scenario authority cannot enumerate all work."""

    def __init__(self) -> None:
        super().__init__("hosted scenario work enumeration is unavailable")


@dataclass(frozen=True, slots=True)
class FirestoreScenarioOperationAuthority:
    """Read-only persisted authority for one hosted internal operation."""

    work: ScenarioWorkItem
    candidate: HostedCandidateIdentity
    prepared_envelope: ExecutionEnvelope | None
    lease_fence: int
    current_lease: ScenarioLeaseToken | None

    def __post_init__(self) -> None:
        if type(self.work) is not ScenarioWorkItem:
            raise TypeError("scenario operation work must be exact")
        if type(self.candidate) is not HostedCandidateIdentity:
            raise TypeError("scenario operation candidate must be exact")
        if self.prepared_envelope is not None and (
            type(self.prepared_envelope) is not ExecutionEnvelope
            or self.work.prepared_envelope_sha256
            != canonical_sha256(self.prepared_envelope)
        ):
            raise ValueError("scenario operation prepared envelope is invalid")
        if (self.work.prepared_envelope_sha256 is None) is not (
            self.prepared_envelope is None
        ):
            raise ValueError("scenario operation prepared envelope is incomplete")
        if type(self.lease_fence) is not int or not 0 <= self.lease_fence <= 2**63 - 1:
            raise ValueError("scenario operation lease fence is invalid")
        if self.current_lease is not None and (
            type(self.current_lease) is not ScenarioLeaseToken
            or self.current_lease.investigation_id
            != self.work.scenario_request.investigation_id
            or self.current_lease.fence != self.lease_fence
        ):
            raise ValueError("scenario operation lease is invalid")


class _FirestoreCasStorePort(Protocol):
    async def read(
        self,
        collection: FirestoreCasCollection,
        logical_id: str,
    ) -> FirestoreCasSnapshot | None: ...

    async def create_pair(
        self,
        first: FirestoreCasDocument,
        second: FirestoreCasDocument,
    ) -> tuple[FirestoreCasSnapshot, FirestoreCasSnapshot]: ...

    async def update(
        self,
        current: FirestoreCasSnapshot,
        replacement: FirestoreCasDocument,
    ) -> FirestoreCasSnapshot: ...


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


def _terminal_projection_matches_authority(
    snapshot: ScenarioRunSnapshot,
    work: ScenarioWorkItem,
) -> bool:
    if work.investigation_state is ScenarioInvestigationState.ESCALATION_REQUIRED:
        return snapshot.lifecycle is ScenarioRunLifecycle.FAILED
    if work.investigation_state is not ScenarioInvestigationState.RECORDED:
        return snapshot.lifecycle in {
            ScenarioRunLifecycle.FAILED,
            ScenarioRunLifecycle.CANCELLED,
        }
    if snapshot.lifecycle is not ScenarioRunLifecycle.COMPLETED:
        return False
    scenario_result = work.scenario_result
    workflow_result = work.workflow_result
    if (
        scenario_result is None
        or scenario_result.execution_envelope is None
        or workflow_result is None
        or snapshot.envelope_summary is None
        or snapshot.envelope_summary.envelope_sha256
        != canonical_sha256(scenario_result.execution_envelope)
    ):
        return False
    if type(workflow_result) is InvestigationReport:
        return (
            snapshot.report == sanitize_report(workflow_result)
            and snapshot.comparison is None
        )
    if type(workflow_result) is InvestigationComparisonRecord:
        return (
            snapshot.comparison == sanitize_comparison(workflow_result)
            and snapshot.report is None
        )
    return False


class _FirestoreScenarioIndex(StrictModel):
    schema_version: Literal["reconcile/firestore-scenario-index/v1"]
    launch_id: Identifier
    investigation_id: Identifier
    launch_sha256: Sha256Digest
    scenario_request_sha256: Sha256Digest
    strategy: ScenarioRunMode
    strategy_sha256: Sha256Digest
    semantic_config_sha256: Sha256Digest
    runtime_provenance_sha256: Sha256Digest
    workspace_id: Identifier
    candidate_id: Identifier
    candidate_sha256: Sha256Digest


class _FirestoreScenarioAggregate(StrictModel):
    schema_version: Literal["reconcile/firestore-scenario-aggregate/v1"]
    revision: int = Field(ge=0, le=2**63 - 1)
    launch_id: Identifier
    investigation_id: Identifier
    candidate: HostedCandidateIdentity
    work: ScenarioWorkItem
    prepared_envelope: ExecutionEnvelope | None = None
    lease_fence: int = Field(ge=0, le=2**63 - 1)
    current_lease: ScenarioLeaseToken | None = None
    events: tuple[ScenarioRunEvent, ...] = Field(
        min_length=1,
        max_length=MAX_SCENARIO_RUN_EVENTS,
    )
    fixed_lane_result: ComparisonRun | None = None
    fixed_lane_sha256: Sha256Digest | None = None
    adaptive_lane_result: ComparisonRun | None = None
    adaptive_lane_sha256: Sha256Digest | None = None

    @model_validator(mode="after")
    def validate_aggregate(self) -> _FirestoreScenarioAggregate:
        work = self.work
        if (
            self.launch_id != work.launch_request.launch_id
            or self.investigation_id != work.scenario_request.investigation_id
            or self.revision < work.revision
            or self.candidate.semantic_config_sha256 != work.semantic_config_sha256
        ):
            raise ValueError("scenario aggregate identity is invalid")
        if self.current_lease is not None and (
            self.current_lease.investigation_id != self.investigation_id
            or self.current_lease.fence != self.lease_fence
        ):
            raise ValueError("scenario aggregate lease is invalid")
        if self.current_lease is None and self.lease_fence < 0:
            raise ValueError("scenario aggregate lease fence is invalid")
        prepared = self.prepared_envelope
        prepared_required = work.mutation_state is not ScenarioMutationState.NOT_STARTED
        if prepared_required is not (prepared is not None):
            raise ValueError("scenario aggregate prepared envelope is incomplete")
        if prepared is not None:
            request = work.scenario_request
            invocation = prepared.context.invocation
            if (
                work.prepared_envelope_sha256 != canonical_sha256(prepared)
                or prepared.investigation_id != request.investigation_id
                or prepared.operation_id != request.operation_id
                or prepared.invoked_at != work.invoked_at
                or invocation.invocation_id != request.invocation_id
                or invocation.function_call_id != request.function_call_id
            ):
                raise ValueError("scenario aggregate prepared envelope is invalid")

        terminal = self.events[-1].type is ScenarioRunEventType.TERMINAL
        if (
            len(self.events) != work.snapshot.event_cursor
            or any(
                event.investigation_id != self.investigation_id
                or event.cursor != cursor
                or (
                    event.type is ScenarioRunEventType.TERMINAL
                    and cursor != len(self.events)
                )
                for cursor, event in enumerate(self.events, 1)
            )
            or not _projection_semantics_valid(
                work,
                self.events,
                terminal=terminal,
            )
            or (
                terminal
                and not _terminal_projection_matches_authority(work.snapshot, work)
            )
        ):
            raise ValueError("scenario aggregate projection is invalid")

        lane_values = (
            (
                ScenarioLane.FIXED,
                self.fixed_lane_result,
                self.fixed_lane_sha256,
                ComparisonStrategyKind.FIXED,
            ),
            (
                ScenarioLane.ADAPTIVE,
                self.adaptive_lane_result,
                self.adaptive_lane_sha256,
                ComparisonStrategyKind.ADAPTIVE,
            ),
        )
        lanes: dict[ScenarioLane, ComparisonRun] = {}
        for lane, result, digest, expected_strategy in lane_values:
            if (result is None) is not (digest is None):
                raise ValueError("scenario aggregate lane binding is incomplete")
            if result is not None:
                if (
                    digest != canonical_sha256(result)
                    or work.strategy is not ScenarioRunMode.COMPARE
                    or work.envelope_sha256 is None
                    or result.envelope_sha256 != work.envelope_sha256
                    or result.scenario != work.scenario_request.scenario
                    or result.strategy_kind is not expected_strategy
                ):
                    raise ValueError("scenario aggregate lane binding is invalid")
                lanes[lane] = result
        if work.strategy is not ScenarioRunMode.COMPARE and lanes:
            raise ValueError("non-comparison scenario has lane results")
        if lanes and work.investigation_state is ScenarioInvestigationState.NOT_STARTED:
            raise ValueError("scenario lanes precede investigation start")
        if work.investigation_state is ScenarioInvestigationState.RECORDED:
            workflow_result = work.workflow_result
            if work.strategy is ScenarioRunMode.COMPARE:
                if (
                    type(workflow_result) is not InvestigationComparisonRecord
                    or workflow_result.adaptive is None
                    or set(lanes) != set(ScenarioLane)
                    or lanes.get(ScenarioLane.FIXED) != workflow_result.baseline
                    or lanes.get(ScenarioLane.ADAPTIVE) != workflow_result.adaptive
                ):
                    raise ValueError("comparison result does not match its lanes")
            elif type(workflow_result) is not InvestigationReport:
                raise ValueError("fixed scenario result type is invalid")
        return self


class _CasRevisionConflict(RuntimeError):
    pass


def _sealed[Model: StrictModel](model: Model, model_type: type[Model]) -> Model:
    return decode_contract(canonical_json_bytes(model), model_type)


def _aggregate_document(
    aggregate: _FirestoreScenarioAggregate,
) -> FirestoreCasDocument:
    return build_firestore_cas_document(
        collection=FirestoreCasCollection.SCENARIO,
        logical_id=aggregate.launch_id,
        revision=aggregate.revision,
        mutation_id=new_firestore_cas_mutation_id(),
        canonical_payload=canonical_json_bytes(aggregate),
    )


def _index_document(index: _FirestoreScenarioIndex) -> FirestoreCasDocument:
    return build_firestore_cas_document(
        collection=FirestoreCasCollection.SCENARIO_INDEX,
        logical_id=index.investigation_id,
        revision=0,
        mutation_id=new_firestore_cas_mutation_id(),
        canonical_payload=canonical_json_bytes(index),
    )


def _decoded_aggregate(
    snapshot: FirestoreCasSnapshot,
) -> _FirestoreScenarioAggregate:
    investigation_id: str | None = None
    try:
        if (
            type(snapshot) is not FirestoreCasSnapshot
            or snapshot.collection is not FirestoreCasCollection.SCENARIO
            or snapshot.document.kind is not FirestoreCasCollection.SCENARIO
        ):
            raise ValueError
        aggregate = decode_contract(
            snapshot.document.payload_bytes,
            _FirestoreScenarioAggregate,
        )
        investigation_id = aggregate.investigation_id
        if (
            canonical_json_bytes(aggregate) != snapshot.document.payload_bytes
            or snapshot.document.logical_id != aggregate.launch_id
            or snapshot.document.revision != aggregate.revision
        ):
            raise ValueError
        return aggregate
    except CorruptScenarioState:
        raise
    except Exception:
        raise CorruptScenarioState(investigation_id) from None


def _decoded_index(snapshot: FirestoreCasSnapshot) -> _FirestoreScenarioIndex:
    investigation_id: str | None = None
    try:
        if (
            type(snapshot) is not FirestoreCasSnapshot
            or snapshot.collection is not FirestoreCasCollection.SCENARIO_INDEX
            or snapshot.document.kind is not FirestoreCasCollection.SCENARIO_INDEX
        ):
            raise ValueError
        index = decode_contract(
            snapshot.document.payload_bytes,
            _FirestoreScenarioIndex,
        )
        investigation_id = index.investigation_id
        if (
            canonical_json_bytes(index) != snapshot.document.payload_bytes
            or snapshot.document.logical_id != index.investigation_id
            or snapshot.document.revision != 0
        ):
            raise ValueError
        return index
    except CorruptScenarioState:
        raise
    except Exception:
        raise CorruptScenarioState(investigation_id) from None


def _validate_index_binding(
    index: _FirestoreScenarioIndex,
    aggregate: _FirestoreScenarioAggregate,
) -> None:
    work = aggregate.work
    if (
        index.launch_id != aggregate.launch_id
        or index.investigation_id != aggregate.investigation_id
        or index.launch_sha256 != work.launch_sha256
        or index.scenario_request_sha256 != work.scenario_request_sha256
        or index.strategy is not work.strategy
        or index.strategy_sha256 != work.strategy_sha256
        or index.semantic_config_sha256 != work.semantic_config_sha256
        or index.runtime_provenance_sha256 != work.runtime_provenance_sha256
        or index.workspace_id != work.workspace_id
        or index.candidate_id != aggregate.candidate.candidate_id
        or index.candidate_sha256 != aggregate.candidate.sha256
    ):
        raise CorruptScenarioState(index.investigation_id)


class FirestoreScenarioStore:
    """One-document request-scoped implementation of the scenario store."""

    def __init__(
        self,
        cas_store: _FirestoreCasStorePort,
        candidate: HostedCandidateIdentity,
    ) -> None:
        if any(
            not callable(getattr(cas_store, name, None))
            for name in ("create_pair", "read", "update")
        ):
            raise TypeError("hosted scenario store requires a CAS store")
        if type(candidate) is not HostedCandidateIdentity:
            raise TypeError("hosted scenario store requires an exact candidate")
        self._cas_store = cas_store
        self._candidate = candidate

    async def _read(
        self,
        collection: FirestoreCasCollection,
        logical_id: str,
        *,
        investigation_id: str | None,
    ) -> FirestoreCasSnapshot | None:
        try:
            return await self._cas_store.read(collection, logical_id)
        except asyncio.CancelledError:
            raise
        except FirestoreCasCorruptDocument:
            raise CorruptScenarioState(investigation_id) from None
        except Exception:
            raise FirestoreScenarioStoreError from None

    async def _load(
        self,
        investigation_id: str,
    ) -> tuple[
        FirestoreCasSnapshot,
        _FirestoreScenarioIndex,
        FirestoreCasSnapshot,
        _FirestoreScenarioAggregate,
    ]:
        index_snapshot = await self._read(
            FirestoreCasCollection.SCENARIO_INDEX,
            investigation_id,
            investigation_id=investigation_id,
        )
        if index_snapshot is None:
            raise ScenarioWorkNotFound(investigation_id)
        index = _decoded_index(index_snapshot)
        if index.investigation_id != investigation_id:
            raise CorruptScenarioState(investigation_id)
        aggregate_snapshot = await self._read(
            FirestoreCasCollection.SCENARIO,
            index.launch_id,
            investigation_id=investigation_id,
        )
        if aggregate_snapshot is None:
            raise CorruptScenarioState(investigation_id)
        aggregate = _decoded_aggregate(aggregate_snapshot)
        _validate_index_binding(index, aggregate)
        if aggregate.candidate != self._candidate:
            raise CorruptScenarioState(investigation_id)
        return index_snapshot, index, aggregate_snapshot, aggregate

    async def _write(
        self,
        current: FirestoreCasSnapshot,
        replacement: _FirestoreScenarioAggregate,
        *,
        operation: str,
    ) -> _FirestoreScenarioAggregate:
        try:
            document = _aggregate_document(replacement)
        except Exception:
            raise ScenarioStateConflict(
                replacement.investigation_id,
                operation,
            ) from None
        try:
            written = await self._cas_store.update(current, document)
        except asyncio.CancelledError:
            raise
        except FirestoreCasConflict:
            raise _CasRevisionConflict from None
        except FirestoreCasCorruptDocument:
            raise CorruptScenarioState(replacement.investigation_id) from None
        except Exception:
            raise FirestoreScenarioStoreError from None
        decoded = _decoded_aggregate(written)
        if written.document != document or decoded != replacement:
            raise CorruptScenarioState(replacement.investigation_id)
        return decoded

    @staticmethod
    def _next_aggregate(
        current: _FirestoreScenarioAggregate,
        **updates: object,
    ) -> _FirestoreScenarioAggregate:
        replacement = current.model_copy(
            update={"revision": current.revision + 1, **updates}
        )
        return _sealed(replacement, _FirestoreScenarioAggregate)

    @staticmethod
    def _next_work(
        current: ScenarioWorkItem,
        occurred_at: datetime,
        **updates: object,
    ) -> ScenarioWorkItem:
        replacement = current.model_copy(
            update={
                **updates,
                "updated_at": max(occurred_at, current.updated_at),
                "revision": current.revision + 1,
            }
        )
        return _sealed(replacement, ScenarioWorkItem)

    @staticmethod
    def _require_lease(
        aggregate: _FirestoreScenarioAggregate,
        token: ScenarioLeaseToken,
        now: datetime,
    ) -> None:
        current = aggregate.current_lease
        if (
            type(token) is not ScenarioLeaseToken
            or current is None
            or current != token
            or aggregate.lease_fence != token.fence
            or current.expired(now)
        ):
            raise StaleScenarioLease(token.investigation_id)

    def _create_values(
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
    ) -> tuple[_FirestoreScenarioIndex, _FirestoreScenarioAggregate]:
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
        candidate = self._candidate
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
            or candidate.semantic_config_sha256 != semantic_config_sha256
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
        index = _FirestoreScenarioIndex(
            schema_version=FIRESTORE_SCENARIO_INDEX_VERSION,
            launch_id=launch_request.launch_id,
            investigation_id=investigation_id,
            launch_sha256=work.launch_sha256,
            scenario_request_sha256=work.scenario_request_sha256,
            strategy=work.strategy,
            strategy_sha256=work.strategy_sha256,
            semantic_config_sha256=work.semantic_config_sha256,
            runtime_provenance_sha256=work.runtime_provenance_sha256,
            workspace_id=work.workspace_id,
            candidate_id=candidate.candidate_id,
            candidate_sha256=candidate.sha256,
        )
        aggregate = _FirestoreScenarioAggregate(
            schema_version=FIRESTORE_SCENARIO_AGGREGATE_VERSION,
            revision=0,
            launch_id=launch_request.launch_id,
            investigation_id=investigation_id,
            candidate=candidate,
            work=work,
            lease_fence=0,
            events=(accepted_event,),
        )
        return index, aggregate

    @staticmethod
    def _create_replay(
        expected_index: _FirestoreScenarioIndex,
        current_index: _FirestoreScenarioIndex,
        current_aggregate: _FirestoreScenarioAggregate,
    ) -> CreateScenarioWorkResult:
        if (
            current_index.launch_id != current_aggregate.launch_id
            or current_index.investigation_id != current_aggregate.investigation_id
        ):
            raise ScenarioWorkConflict(
                expected_index.launch_id,
                current_index.investigation_id,
            )
        _validate_index_binding(current_index, current_aggregate)
        if current_index != expected_index:
            raise ScenarioWorkConflict(
                expected_index.launch_id,
                current_index.investigation_id,
            )
        return CreateScenarioWorkResult(
            work=current_aggregate.work,
            created=False,
        )

    async def _resolve_create(
        self,
        expected_index: _FirestoreScenarioIndex,
    ) -> CreateScenarioWorkResult | None:
        aggregate_snapshot = await self._read(
            FirestoreCasCollection.SCENARIO,
            expected_index.launch_id,
            investigation_id=expected_index.investigation_id,
        )
        index_snapshot = await self._read(
            FirestoreCasCollection.SCENARIO_INDEX,
            expected_index.investigation_id,
            investigation_id=expected_index.investigation_id,
        )
        if aggregate_snapshot is None and index_snapshot is not None:
            aggregate_snapshot = await self._read(
                FirestoreCasCollection.SCENARIO,
                expected_index.launch_id,
                investigation_id=expected_index.investigation_id,
            )
        elif aggregate_snapshot is not None and index_snapshot is None:
            index_snapshot = await self._read(
                FirestoreCasCollection.SCENARIO_INDEX,
                expected_index.investigation_id,
                investigation_id=expected_index.investigation_id,
            )
        if aggregate_snapshot is None and index_snapshot is None:
            return None
        if aggregate_snapshot is None:
            assert index_snapshot is not None
            current_index = _decoded_index(index_snapshot)
            if current_index.launch_id != expected_index.launch_id:
                raise ScenarioWorkConflict(
                    expected_index.launch_id,
                    current_index.investigation_id,
                )
            raise CorruptScenarioState(expected_index.investigation_id)
        if index_snapshot is None:
            current_aggregate = _decoded_aggregate(aggregate_snapshot)
            if current_aggregate.investigation_id != expected_index.investigation_id:
                raise ScenarioWorkConflict(
                    expected_index.launch_id,
                    current_aggregate.investigation_id,
                )
            raise CorruptScenarioState(expected_index.investigation_id)
        current_aggregate = _decoded_aggregate(aggregate_snapshot)
        current_index = _decoded_index(index_snapshot)
        if (
            current_aggregate.launch_id != expected_index.launch_id
            or current_index.investigation_id != expected_index.investigation_id
        ):
            raise ScenarioWorkConflict(
                expected_index.launch_id,
                current_index.investigation_id,
            )
        return self._create_replay(
            expected_index,
            current_index,
            current_aggregate,
        )

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
        index, aggregate = self._create_values(
            launch_request,
            scenario_request,
            strategy_sha256=strategy_sha256,
            semantic_config_sha256=semantic_config_sha256,
            runtime_provenance_sha256=runtime_provenance_sha256,
            workspace_id=workspace_id,
            invoked_at=invoked_at,
            snapshot=snapshot,
            accepted_event=accepted_event,
            created_at=created_at,
        )
        existing = await self._resolve_create(index)
        if existing is not None:
            return existing
        try:
            aggregate_document = _aggregate_document(aggregate)
            index_document = _index_document(index)
        except Exception:
            raise CorruptScenarioState(index.investigation_id) from None
        try:
            aggregate_written, index_written = await self._cas_store.create_pair(
                aggregate_document,
                index_document,
            )
        except asyncio.CancelledError:
            raise
        except FirestoreCasConflict:
            resolved = await self._resolve_create(index)
            if resolved is None:
                raise FirestoreScenarioStoreError from None
            return resolved
        except FirestoreCasCorruptDocument:
            raise CorruptScenarioState(index.investigation_id) from None
        except Exception:
            raise FirestoreScenarioStoreError from None
        written_aggregate = _decoded_aggregate(aggregate_written)
        written_index = _decoded_index(index_written)
        if (
            aggregate_written.document != aggregate_document
            or index_written.document != index_document
            or written_aggregate != aggregate
            or written_index != index
        ):
            raise CorruptScenarioState(index.investigation_id)
        _validate_index_binding(written_index, written_aggregate)
        return CreateScenarioWorkResult(work=written_aggregate.work, created=True)

    async def get_work(self, investigation_id: str) -> ScenarioWorkItem:
        _, _, _, aggregate = await self._load(investigation_id)
        return aggregate.work

    async def operation_authority(
        self,
        investigation_id: str,
    ) -> FirestoreScenarioOperationAuthority:
        """Load one exact aggregate/index pair without changing durable state."""

        _, _, _, aggregate = await self._load(investigation_id)
        return FirestoreScenarioOperationAuthority(
            work=aggregate.work,
            candidate=aggregate.candidate,
            prepared_envelope=aggregate.prepared_envelope,
            lease_fence=aggregate.lease_fence,
            current_lease=aggregate.current_lease,
        )

    async def list_work(self) -> tuple[ScenarioWorkItem, ...]:
        raise FirestoreScenarioEnumerationUnavailable from None

    async def acquire_scenario_lease(
        self,
        investigation_id: str,
        owner_id: str,
        *,
        now: datetime,
    ) -> ScenarioLeaseToken:
        now = _aware_utc(now)
        _, _, snapshot, aggregate = await self._load(investigation_id)
        current = aggregate.current_lease
        if current is not None and not current.expired(now):
            raise ScenarioLeaseUnavailable(investigation_id)
        if aggregate.lease_fence >= 2**63 - 1:
            raise ScenarioLeaseUnavailable(investigation_id)
        token = ScenarioLeaseToken(
            schema_version=SCENARIO_LEASE_VERSION,
            investigation_id=investigation_id,
            owner_id=owner_id,
            fence=aggregate.lease_fence + 1,
            acquired_at=now,
            renewed_at=now,
            expires_at=now + LEASE_DURATION,
        )
        try:
            replacement = self._next_aggregate(
                aggregate,
                lease_fence=token.fence,
                current_lease=token,
            )
            await self._write(snapshot, replacement, operation="acquire lease")
        except _CasRevisionConflict:
            raise ScenarioLeaseUnavailable(investigation_id) from None
        return token

    async def renew_scenario_lease(
        self,
        token: ScenarioLeaseToken,
        *,
        now: datetime,
    ) -> ScenarioLeaseToken:
        if type(token) is not ScenarioLeaseToken:
            raise TypeError("scenario lease token must be exact")
        now = max(_aware_utc(now), token.renewed_at)
        _, _, snapshot, aggregate = await self._load(token.investigation_id)
        self._require_lease(aggregate, token, now)
        renewed = token.model_copy(
            update={"renewed_at": now, "expires_at": now + LEASE_DURATION}
        )
        renewed = _sealed(renewed, ScenarioLeaseToken)
        replacement = self._next_aggregate(
            aggregate,
            current_lease=renewed,
        )
        try:
            await self._write(snapshot, replacement, operation="renew lease")
        except _CasRevisionConflict:
            raise StaleScenarioLease(token.investigation_id) from None
        return renewed

    async def release_scenario_lease(
        self,
        token: ScenarioLeaseToken,
        *,
        now: datetime,
    ) -> None:
        if type(token) is not ScenarioLeaseToken:
            raise TypeError("scenario lease token must be exact")
        now = max(_aware_utc(now), token.renewed_at)
        _, _, snapshot, aggregate = await self._load(token.investigation_id)
        self._require_lease(aggregate, token, now)
        replacement = self._next_aggregate(aggregate, current_lease=None)
        try:
            await self._write(snapshot, replacement, operation="release lease")
        except _CasRevisionConflict:
            raise StaleScenarioLease(token.investigation_id) from None

    async def _transition_work(
        self,
        snapshot: FirestoreCasSnapshot,
        aggregate: _FirestoreScenarioAggregate,
        token: ScenarioLeaseToken,
        occurred_at: datetime,
        operation: str,
        **updates: object,
    ) -> ScenarioWorkItem:
        self._require_lease(aggregate, token, occurred_at)
        try:
            work = self._next_work(aggregate.work, occurred_at, **updates)
            replacement = self._next_aggregate(aggregate, work=work)
        except Exception:
            raise ScenarioStateConflict(token.investigation_id, operation) from None
        try:
            written = await self._write(
                snapshot,
                replacement,
                operation=operation,
            )
        except _CasRevisionConflict:
            _, _, _, current = await self._load(token.investigation_id)
            self._require_lease(current, token, occurred_at)
            raise ScenarioStateConflict(token.investigation_id, operation) from None
        return written.work

    async def record_mutation_started(
        self,
        token: ScenarioLeaseToken,
        *,
        prepared_envelope: ExecutionEnvelope | None = None,
        prepared_envelope_sha256: str,
        cleanup_manifest_sha256: str,
        occurred_at: datetime,
    ) -> ScenarioWorkItem:
        if type(token) is not ScenarioLeaseToken:
            raise TypeError("scenario lease token must be exact")
        if type(prepared_envelope) is not ExecutionEnvelope:
            raise TypeError("prepared scenario envelope must be exact")
        occurred_at = _aware_utc(occurred_at)
        _, _, snapshot, aggregate = await self._load(token.investigation_id)
        if aggregate.work.mutation_state is not ScenarioMutationState.NOT_STARTED:
            raise ScenarioStateConflict(token.investigation_id, "start mutation")
        digest = _digest(prepared_envelope_sha256, "prepared envelope")
        if digest != canonical_sha256(prepared_envelope):
            raise ScenarioStateConflict(
                token.investigation_id,
                "start mutation",
            )
        self._require_lease(aggregate, token, occurred_at)
        try:
            work = self._next_work(
                aggregate.work,
                occurred_at,
                mutation_state=ScenarioMutationState.STARTED,
                prepared_envelope_sha256=digest,
                cleanup_manifest_sha256=_digest(
                    cleanup_manifest_sha256,
                    "cleanup manifest",
                ),
            )
            replacement = self._next_aggregate(
                aggregate,
                work=work,
                prepared_envelope=prepared_envelope,
            )
        except Exception:
            raise ScenarioStateConflict(
                token.investigation_id,
                "start mutation",
            ) from None
        try:
            written = await self._write(
                snapshot,
                replacement,
                operation="start mutation",
            )
        except _CasRevisionConflict:
            _, _, _, current = await self._load(token.investigation_id)
            self._require_lease(current, token, occurred_at)
            raise ScenarioStateConflict(
                token.investigation_id,
                "start mutation",
            ) from None
        return written.work

    async def record_mutation_result(
        self,
        token: ScenarioLeaseToken,
        result: ScenarioRunResult,
        *,
        prepared_envelope_bytes: bytes,
        occurred_at: datetime,
    ) -> ScenarioWorkItem:
        if type(token) is not ScenarioLeaseToken:
            raise TypeError("scenario lease token must be exact")
        occurred_at = _aware_utc(occurred_at)
        if type(result) is not ScenarioRunResult:
            raise TypeError("scenario mutation result must be exact")
        if type(prepared_envelope_bytes) is not bytes:
            raise TypeError("prepared scenario envelope must be exact bytes")
        _, _, snapshot, aggregate = await self._load(token.investigation_id)
        current = aggregate.work
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
        except (ContractError, TypeError, ValueError):
            raise ScenarioStateConflict(
                token.investigation_id,
                "record mutation envelope lineage",
            ) from None
        if canonical_json_bytes(prepared_envelope) != prepared_envelope_bytes:
            raise ScenarioStateConflict(
                token.investigation_id,
                "record mutation envelope lineage",
            )
        if aggregate.prepared_envelope != prepared_envelope:
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
        return await self._transition_work(
            snapshot,
            aggregate,
            token,
            occurred_at,
            "record mutation",
            mutation_state=ScenarioMutationState.RECORDED,
            scenario_result=result,
            envelope_sha256=envelope_sha256,
        )

    async def mark_investigation_started(
        self,
        token: ScenarioLeaseToken,
        *,
        occurred_at: datetime,
    ) -> ScenarioWorkItem:
        if type(token) is not ScenarioLeaseToken:
            raise TypeError("scenario lease token must be exact")
        occurred_at = _aware_utc(occurred_at)
        _, _, snapshot, aggregate = await self._load(token.investigation_id)
        current = aggregate.work
        if (
            current.mutation_state is not ScenarioMutationState.RECORDED
            or current.envelope_sha256 is None
            or current.investigation_state is not ScenarioInvestigationState.NOT_STARTED
        ):
            raise ScenarioStateConflict(
                token.investigation_id,
                "start investigation",
            )
        return await self._transition_work(
            snapshot,
            aggregate,
            token,
            occurred_at,
            "start investigation",
            investigation_state=ScenarioInvestigationState.STARTED,
        )

    async def record_workflow_result(
        self,
        token: ScenarioLeaseToken,
        result: InvestigationReport | InvestigationComparisonRecord,
        *,
        occurred_at: datetime,
    ) -> ScenarioWorkItem:
        if type(token) is not ScenarioLeaseToken:
            raise TypeError("scenario lease token must be exact")
        occurred_at = _aware_utc(occurred_at)
        if type(result) not in {InvestigationReport, InvestigationComparisonRecord}:
            raise TypeError("scenario workflow result must be exact")
        _, _, snapshot, aggregate = await self._load(token.investigation_id)
        current = aggregate.work
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
            accepted = (
                result.adaptive is not None
                and result.scenario == current.scenario_request.scenario
                and result.envelope_sha256 == current.envelope_sha256
                and aggregate.fixed_lane_result == result.baseline
                and aggregate.adaptive_lane_result == result.adaptive
            )
        if not accepted:
            raise ScenarioStateConflict(
                token.investigation_id,
                "record investigation",
            )
        return await self._transition_work(
            snapshot,
            aggregate,
            token,
            occurred_at,
            "record investigation",
            investigation_state=ScenarioInvestigationState.RECORDED,
            workflow_result=result,
        )

    async def require_scenario_escalation(
        self,
        token: ScenarioLeaseToken,
        failure_code: str,
        *,
        occurred_at: datetime,
    ) -> ScenarioWorkItem:
        if type(token) is not ScenarioLeaseToken:
            raise TypeError("scenario lease token must be exact")
        occurred_at = _aware_utc(occurred_at)
        _, _, snapshot, aggregate = await self._load(token.investigation_id)
        if aggregate.work.investigation_state is ScenarioInvestigationState.RECORDED:
            raise ScenarioStateConflict(token.investigation_id, "escalate")
        return await self._transition_work(
            snapshot,
            aggregate,
            token,
            occurred_at,
            "escalate",
            investigation_state=ScenarioInvestigationState.ESCALATION_REQUIRED,
            recovery_failure_code=failure_code,
        )

    async def record_scenario_cleanup(
        self,
        token: ScenarioLeaseToken,
        status: CleanupStatus,
        *,
        occurred_at: datetime,
        failure_code: str | None = None,
    ) -> ScenarioWorkItem:
        if type(token) is not ScenarioLeaseToken:
            raise TypeError("scenario lease token must be exact")
        occurred_at = _aware_utc(occurred_at)
        if type(status) is not CleanupStatus:
            raise TypeError("scenario cleanup status must be exact")
        _, _, snapshot, aggregate = await self._load(token.investigation_id)
        current = aggregate.work
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
        return await self._transition_work(
            snapshot,
            aggregate,
            token,
            occurred_at,
            "record cleanup",
            cleanup_status=status,
            cleanup_failure_code=failure_code,
        )

    async def append_projection(
        self,
        snapshot: ScenarioRunSnapshot,
        event: ScenarioRunEvent,
        *,
        terminal: bool,
    ) -> ScenarioWorkItem:
        if (
            type(snapshot) is not ScenarioRunSnapshot
            or type(event) is not ScenarioRunEvent
        ):
            raise TypeError("scenario projection values must be exact")
        investigation_id = snapshot.investigation_id
        _, _, current_snapshot, aggregate = await self._load(investigation_id)
        current = aggregate.work
        expected_cursor = current.snapshot.event_cursor + 1
        current_terminal = aggregate.events[-1].type is ScenarioRunEventType.TERMINAL
        checks = (
            (not current_terminal, "projection journal terminal"),
            (event.investigation_id == investigation_id, "projection identity"),
            (event.cursor == expected_cursor, "projection event cursor"),
            (snapshot.event_cursor == expected_cursor, "projection snapshot cursor"),
            (
                snapshot.launch_id == current.launch_request.launch_id,
                "projection launch identity",
            ),
            (snapshot.updated_at == event.occurred_at, "projection timestamp"),
            (
                terminal is (event.type is ScenarioRunEventType.TERMINAL),
                "projection terminal flag",
            ),
            (
                not terminal
                or _terminal_projection_matches_authority(snapshot, current),
                "projection terminal authority",
            ),
        )
        failed = next((label for accepted, label in checks if not accepted), None)
        if failed is not None:
            raise ScenarioStateConflict(investigation_id, failed)
        try:
            work = self._next_work(
                current,
                max(current.updated_at, snapshot.updated_at),
                snapshot=snapshot,
            )
            replacement = self._next_aggregate(
                aggregate,
                work=work,
                events=(*aggregate.events, event),
            )
        except Exception:
            raise CorruptScenarioState(investigation_id) from None
        try:
            written = await self._write(
                current_snapshot,
                replacement,
                operation="append projection",
            )
        except _CasRevisionConflict:
            raise ScenarioStateConflict(
                investigation_id,
                "append projection",
            ) from None
        return written.work

    async def snapshot_projection(
        self,
        investigation_id: str,
        *,
        after: int = 0,
    ) -> ScenarioProjectionSnapshot:
        if isinstance(after, bool) or not isinstance(after, int):
            raise ValueError("scenario projection cursor must be an integer")
        _, _, _, aggregate = await self._load(investigation_id)
        events = aggregate.events
        if not 0 <= after <= len(events):
            raise ValueError("scenario projection cursor is outside the journal")
        terminal = events[-1].type is ScenarioRunEventType.TERMINAL
        return ScenarioProjectionSnapshot(
            snapshot=aggregate.work.snapshot,
            events=events[after:],
            cursor=len(events),
            terminal=terminal,
        )

    @staticmethod
    def _lane_value(
        aggregate: _FirestoreScenarioAggregate,
        lane: ScenarioLane,
    ) -> ComparisonRun | None:
        if lane is ScenarioLane.FIXED:
            return aggregate.fixed_lane_result
        return aggregate.adaptive_lane_result

    @staticmethod
    def _validate_lane_preconditions(
        aggregate: _FirestoreScenarioAggregate,
        lane: ScenarioLane,
        result: ComparisonRun,
    ) -> None:
        work = aggregate.work
        expected_strategy = (
            ComparisonStrategyKind.FIXED
            if lane is ScenarioLane.FIXED
            else ComparisonStrategyKind.ADAPTIVE
        )
        if (
            work.strategy is not ScenarioRunMode.COMPARE
            or work.investigation_state is not ScenarioInvestigationState.STARTED
            or work.envelope_sha256 != result.envelope_sha256
            or work.scenario_request.scenario != result.scenario
            or result.strategy_kind is not expected_strategy
        ):
            raise ScenarioStateConflict(
                aggregate.investigation_id,
                "record lane result",
            )

    async def record_lane_result(
        self,
        token: ScenarioLeaseToken,
        lane: ScenarioLane,
        result: ComparisonRun,
        *,
        occurred_at: datetime,
    ) -> None:
        if type(token) is not ScenarioLeaseToken:
            raise TypeError("scenario lease token must be exact")
        if type(lane) is not ScenarioLane or type(result) is not ComparisonRun:
            raise TypeError("scenario lane result values must be exact")
        occurred_at = _aware_utc(occurred_at)
        _, _, snapshot, aggregate = await self._load(token.investigation_id)
        self._require_lease(aggregate, token, occurred_at)
        self._validate_lane_preconditions(aggregate, lane, result)
        current = self._lane_value(aggregate, lane)
        if current is not None:
            if canonical_json_bytes(current) != canonical_json_bytes(result):
                raise ScenarioStateConflict(
                    token.investigation_id,
                    "record lane result",
                )
            return
        result_sha256 = canonical_sha256(result)
        updates: dict[str, object]
        if lane is ScenarioLane.FIXED:
            updates = {
                "fixed_lane_result": result,
                "fixed_lane_sha256": result_sha256,
            }
        else:
            updates = {
                "adaptive_lane_result": result,
                "adaptive_lane_sha256": result_sha256,
            }
        replacement = self._next_aggregate(aggregate, **updates)
        try:
            await self._write(snapshot, replacement, operation="record lane result")
        except _CasRevisionConflict:
            _, _, _, current_aggregate = await self._load(token.investigation_id)
            self._require_lease(current_aggregate, token, occurred_at)
            self._validate_lane_preconditions(current_aggregate, lane, result)
            current_result = self._lane_value(current_aggregate, lane)
            if current_result is not None and canonical_json_bytes(
                current_result
            ) == canonical_json_bytes(result):
                return
            raise ScenarioStateConflict(
                token.investigation_id,
                "record lane result",
            ) from None

    async def get_lane_result(
        self,
        investigation_id: str,
        lane: ScenarioLane,
    ) -> ComparisonRun | None:
        if type(lane) is not ScenarioLane:
            raise TypeError("scenario lane must be exact")
        _, _, _, aggregate = await self._load(investigation_id)
        return self._lane_value(aggregate, lane)


__all__ = [
    "FIRESTORE_SCENARIO_AGGREGATE_VERSION",
    "FIRESTORE_SCENARIO_INDEX_VERSION",
    "FirestoreScenarioEnumerationUnavailable",
    "FirestoreScenarioOperationAuthority",
    "FirestoreScenarioStore",
    "FirestoreScenarioStoreError",
]
