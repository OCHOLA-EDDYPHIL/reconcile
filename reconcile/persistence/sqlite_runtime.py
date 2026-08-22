"""SQLite implementation of the fenced durable runtime boundary."""

from __future__ import annotations

import asyncio
import os
import re
import sqlite3
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import UTC, datetime
from itertools import pairwise
from pathlib import Path

from reconcile.contracts.api import (
    MAX_INVESTIGATION_EVENTS,
    InvestigationEvent,
    InvestigationEventType,
    LifecycleEventPayload,
)
from reconcile.contracts.codec import (
    ContractError,
    canonical_json_bytes,
    canonical_sha256,
    decode_contract,
)
from reconcile.contracts.envelope import ExecutionEnvelope, ProbeRequest
from reconcile.contracts.recovery import ActionPermit, ActionPermitState
from reconcile.contracts.report import (
    InvestigationReport,
    InvestigationStatus,
    ProbeOutcome,
)
from reconcile.controller import (
    ControllerAuditRecord,
    ProbeObservation,
    probe_request_sha256,
)
from reconcile.persistence.durable import (
    COST_LEDGER_ENTRY_VERSION,
    COST_LEDGER_SNAPSHOT_VERSION,
    DURABLE_LEASE_VERSION,
    DURABLE_RUN_VERSION,
    LEASE_DURATION,
    LEASE_RENEWAL_INTERVAL,
    PROBE_CHECKPOINT_VERSION,
    BudgetExceeded,
    CleanupStatus,
    ControllerAuditConflict,
    CorruptDurableState,
    CostLedgerEntry,
    CostLedgerSnapshot,
    CreateDurableRunResult,
    DurableRunConflict,
    DurableRunNotFound,
    DurableRunRecord,
    DurableRunState,
    DurableStateConflict,
    LeaseRenewalTooEarly,
    LeaseToken,
    LeaseUnavailable,
    ProbeCheckpoint,
    ProbeCheckpointConflict,
    ProbeCheckpointState,
    ProbeReplaySafety,
    ProbeResumePlan,
    ProviderCallReceipt,
    RuntimeCostDelta,
    RuntimeLimits,
    RuntimeTelemetryRecord,
    StaleLease,
    UnsupportedDurableSchema,
    build_probe_resume_plan,
)
from reconcile.persistence.events import (
    DuplicateEvent,
    EventJournalSnapshot,
    InvalidCursor,
    JournalCapacityExceeded,
    OutOfOrderEvent,
    TerminalEventJournal,
)
from reconcile.persistence.permits import (
    PermitAuditEvent,
    PermitClaimDenied,
    PermitClaimRequest,
    PermitCompletionDenied,
    PermitCompletionRequest,
    PermitConflict,
    PermitCorruptState,
    PermitNotFound,
    PermitStoreError,
    evaluate_permit_claim,
    evaluate_permit_completion,
    issued_audit_event,
    validate_permit_audit_history,
)

_SQLITE_SCHEMA_VERSION = "5"
_SQLITE_PREVIOUS_SCHEMA_VERSION = "4"
_BUSY_TIMEOUT_MS = 5_000


def _aware_utc(value: datetime) -> datetime:
    if (
        not isinstance(value, datetime)
        or value.tzinfo is None
        or value.utcoffset() is None
    ):
        raise ValueError("durable runtime timestamps must be timezone-aware")
    return value.astimezone(UTC)


def _blob(value: object) -> bytes:
    if isinstance(value, bytes):
        return value
    if isinstance(value, str):
        return value.encode("utf-8")
    raise TypeError("stored durable payload is not text or bytes")


def _terminal_event(event: InvestigationEvent) -> bool:
    return (
        event.type is InvestigationEventType.LIFECYCLE
        and isinstance(event.payload, LifecycleEventPayload)
        and event.payload.status is InvestigationStatus.COMPLETED
    )


class SqliteDurableRuntimeStore:
    """Persist runtime authority in fenced, transactional SQLite records."""

    def __init__(self, database_path: str | Path) -> None:
        if not isinstance(database_path, (str, Path)):
            raise TypeError("SQLite runtime path must be a string or path")
        candidate = Path(database_path)
        if not candidate.name or not candidate.parent.exists():
            raise ValueError("SQLite runtime parent directory must exist")
        if candidate.exists() and not candidate.is_file():
            raise ValueError("SQLite runtime path must name a file")
        self._database_path = candidate
        self._initialize()
        os.chmod(self._database_path, 0o600)

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(
            self._database_path,
            timeout=_BUSY_TIMEOUT_MS / 1_000,
            isolation_level=None,
        )
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute(f"PRAGMA busy_timeout = {_BUSY_TIMEOUT_MS}")
        return connection

    @contextmanager
    def _write(self) -> Iterator[sqlite3.Connection]:
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            yield connection
            connection.commit()
        except BaseException:
            connection.rollback()
            raise
        finally:
            connection.close()

    def _initialize(self) -> None:
        try:
            with self._connect() as connection:
                connection.execute("PRAGMA journal_mode = WAL")
                connection.execute(
                    """
                    CREATE TABLE IF NOT EXISTS runtime_metadata (
                        metadata_key TEXT PRIMARY KEY,
                        metadata_value TEXT NOT NULL
                    )
                    """
                )
                schema = connection.execute(
                    """
                    SELECT metadata_value
                    FROM runtime_metadata
                    WHERE metadata_key = 'schema_version'
                    """
                ).fetchone()
                migrating_from_v4 = (
                    schema is not None
                    and schema["metadata_value"] == _SQLITE_PREVIOUS_SCHEMA_VERSION
                )
                if schema is None:
                    connection.execute(
                        """
                        INSERT INTO runtime_metadata (metadata_key, metadata_value)
                        VALUES ('schema_version', ?)
                        """,
                        (_SQLITE_SCHEMA_VERSION,),
                    )
                elif (
                    schema["metadata_value"] != _SQLITE_SCHEMA_VERSION
                    and not migrating_from_v4
                ):
                    raise UnsupportedDurableSchema

                connection.executescript(
                    """
                    CREATE TABLE IF NOT EXISTS durable_runs (
                        investigation_id TEXT PRIMARY KEY,
                        envelope_sha256 TEXT NOT NULL,
                        payload BLOB NOT NULL
                    );

                    CREATE TABLE IF NOT EXISTS runtime_provenance (
                        investigation_id TEXT PRIMARY KEY,
                        sha256 TEXT NOT NULL,
                        FOREIGN KEY (investigation_id)
                            REFERENCES durable_runs(investigation_id)
                            ON DELETE CASCADE
                    );

                    CREATE TABLE IF NOT EXISTS durable_leases (
                        investigation_id TEXT PRIMARY KEY,
                        fence INTEGER NOT NULL,
                        payload BLOB,
                        FOREIGN KEY (investigation_id)
                            REFERENCES durable_runs(investigation_id)
                            ON DELETE CASCADE
                    );

                    CREATE TABLE IF NOT EXISTS probe_checkpoints (
                        investigation_id TEXT NOT NULL,
                        checkpoint_id TEXT NOT NULL,
                        step_sequence INTEGER NOT NULL,
                        payload BLOB NOT NULL,
                        PRIMARY KEY (investigation_id, checkpoint_id),
                        UNIQUE (investigation_id, step_sequence),
                        FOREIGN KEY (investigation_id)
                            REFERENCES durable_runs(investigation_id)
                            ON DELETE CASCADE
                    );

                    CREATE TABLE IF NOT EXISTS controller_audits (
                        investigation_id TEXT NOT NULL,
                        sequence INTEGER NOT NULL,
                        payload BLOB NOT NULL,
                        PRIMARY KEY (investigation_id, sequence),
                        FOREIGN KEY (investigation_id)
                            REFERENCES durable_runs(investigation_id)
                            ON DELETE CASCADE
                    );

                    CREATE TABLE IF NOT EXISTS investigation_events (
                        investigation_id TEXT NOT NULL,
                        sequence INTEGER NOT NULL,
                        terminal INTEGER NOT NULL CHECK (terminal IN (0, 1)),
                        payload BLOB NOT NULL,
                        PRIMARY KEY (investigation_id, sequence),
                        FOREIGN KEY (investigation_id)
                            REFERENCES durable_runs(investigation_id)
                            ON DELETE CASCADE
                    );

                    CREATE TABLE IF NOT EXISTS runtime_telemetry (
                        investigation_id TEXT NOT NULL,
                        telemetry_id TEXT NOT NULL,
                        sequence INTEGER NOT NULL,
                        payload BLOB NOT NULL,
                        PRIMARY KEY (investigation_id, telemetry_id),
                        UNIQUE (investigation_id, sequence),
                        FOREIGN KEY (investigation_id)
                            REFERENCES durable_runs(investigation_id)
                            ON DELETE CASCADE
                    );

                    CREATE TABLE IF NOT EXISTS runtime_cost_entries (
                        investigation_id TEXT NOT NULL,
                        entry_id TEXT NOT NULL,
                        sequence INTEGER NOT NULL,
                        provider_calls INTEGER NOT NULL,
                        probe_count INTEGER NOT NULL,
                        evidence_bytes INTEGER NOT NULL,
                        controller_cost_units INTEGER NOT NULL,
                        estimated_cost_microunits INTEGER NOT NULL,
                        payload BLOB NOT NULL,
                        PRIMARY KEY (investigation_id, entry_id),
                        UNIQUE (investigation_id, sequence),
                        FOREIGN KEY (investigation_id)
                            REFERENCES durable_runs(investigation_id)
                            ON DELETE CASCADE
                    );

                    CREATE TABLE IF NOT EXISTS scenario_work_items (
                        investigation_id TEXT PRIMARY KEY,
                        launch_id TEXT NOT NULL UNIQUE,
                        launch_sha256 TEXT NOT NULL,
                        payload BLOB NOT NULL
                    );

                    CREATE TABLE IF NOT EXISTS scenario_leases (
                        investigation_id TEXT PRIMARY KEY,
                        fence INTEGER NOT NULL,
                        payload BLOB,
                        FOREIGN KEY (investigation_id)
                            REFERENCES scenario_work_items(investigation_id)
                            ON DELETE CASCADE
                    );

                    CREATE TABLE IF NOT EXISTS scenario_events (
                        investigation_id TEXT NOT NULL,
                        cursor INTEGER NOT NULL,
                        terminal INTEGER NOT NULL CHECK (terminal IN (0, 1)),
                        payload BLOB NOT NULL,
                        PRIMARY KEY (investigation_id, cursor),
                        FOREIGN KEY (investigation_id)
                            REFERENCES scenario_work_items(investigation_id)
                            ON DELETE CASCADE
                    );

                    CREATE TABLE IF NOT EXISTS scenario_lane_results (
                        investigation_id TEXT NOT NULL,
                        lane TEXT NOT NULL,
                        sha256 TEXT NOT NULL,
                        payload BLOB NOT NULL,
                        PRIMARY KEY (investigation_id, lane),
                        FOREIGN KEY (investigation_id)
                            REFERENCES scenario_work_items(investigation_id)
                            ON DELETE CASCADE
                    );

                    CREATE TABLE IF NOT EXISTS action_permits (
                        permit_id TEXT PRIMARY KEY,
                        certificate_id TEXT NOT NULL,
                        state TEXT NOT NULL,
                        revision INTEGER NOT NULL,
                        payload BLOB NOT NULL
                    );

                    CREATE TABLE IF NOT EXISTS action_permit_audits (
                        permit_id TEXT NOT NULL,
                        sequence INTEGER NOT NULL,
                        event_id TEXT NOT NULL,
                        payload BLOB NOT NULL,
                        PRIMARY KEY (permit_id, sequence),
                        UNIQUE (permit_id, event_id),
                        FOREIGN KEY (permit_id)
                            REFERENCES action_permits(permit_id)
                            ON DELETE CASCADE
                    );
                    """
                )
                if migrating_from_v4:
                    connection.execute(
                        """
                        UPDATE runtime_metadata
                        SET metadata_value = ?
                        WHERE metadata_key = 'schema_version'
                          AND metadata_value = ?
                        """,
                        (_SQLITE_SCHEMA_VERSION, _SQLITE_PREVIOUS_SCHEMA_VERSION),
                    )
        except UnsupportedDurableSchema:
            raise
        except sqlite3.DatabaseError as error:
            raise CorruptDurableState() from error

    @staticmethod
    def _decode[Model](
        payload: object,
        model_type: type[Model],
        investigation_id: str | None = None,
    ) -> Model:
        try:
            return decode_contract(_blob(payload), model_type)  # type: ignore[arg-type]
        except (ContractError, TypeError, ValueError) as error:
            raise CorruptDurableState(investigation_id) from error

    def _run_locked(
        self,
        connection: sqlite3.Connection,
        investigation_id: str,
    ) -> DurableRunRecord:
        row = connection.execute(
            """
            SELECT envelope_sha256, payload
            FROM durable_runs
            WHERE investigation_id = ?
            """,
            (investigation_id,),
        ).fetchone()
        if row is None:
            raise DurableRunNotFound(investigation_id)
        run = self._decode(row["payload"], DurableRunRecord, investigation_id)
        if row["envelope_sha256"] != run.envelope_sha256:
            raise CorruptDurableState(investigation_id)
        return run

    @staticmethod
    def _replace_run_locked(
        connection: sqlite3.Connection,
        run: DurableRunRecord,
    ) -> None:
        cursor = connection.execute(
            """
            UPDATE durable_runs
            SET envelope_sha256 = ?, payload = ?
            WHERE investigation_id = ?
            """,
            (
                run.envelope_sha256,
                canonical_json_bytes(run),
                run.investigation_id,
            ),
        )
        if cursor.rowcount != 1:
            raise DurableRunNotFound(run.investigation_id)

    def _validate_event_rows(
        self,
        rows: list[sqlite3.Row],
        investigation_id: str,
    ) -> tuple[InvestigationEvent, ...]:
        events = tuple(
            self._decode(row["payload"], InvestigationEvent, investigation_id)
            for row in rows
        )
        for expected, (row, event) in enumerate(zip(rows, events, strict=True), 1):
            if (
                row["sequence"] != expected
                or event.sequence != expected
                or event.investigation_id != investigation_id
                or bool(row["terminal"]) is not _terminal_event(event)
                or (row["terminal"] and expected != len(rows))
            ):
                raise CorruptDurableState(investigation_id)
        return events

    async def create_run(
        self,
        envelope: ExecutionEnvelope,
        *,
        created_at: datetime,
        limits: RuntimeLimits,
        runtime_provenance_sha256: str,
    ) -> CreateDurableRunResult:
        return await asyncio.to_thread(
            self._create_run,
            envelope,
            created_at,
            limits,
            runtime_provenance_sha256,
        )

    def _create_run(
        self,
        envelope: ExecutionEnvelope,
        created_at: datetime,
        limits: RuntimeLimits,
        runtime_provenance_sha256: str,
    ) -> CreateDurableRunResult:
        created_at = _aware_utc(created_at)
        if (
            not isinstance(runtime_provenance_sha256, str)
            or re.fullmatch(r"[0-9a-f]{64}", runtime_provenance_sha256) is None
        ):
            raise ValueError("runtime provenance must be a SHA-256 digest")
        record = DurableRunRecord(
            schema_version=DURABLE_RUN_VERSION,
            investigation_id=envelope.investigation_id,
            envelope=envelope,
            envelope_sha256=canonical_sha256(envelope),
            state=DurableRunState.CREATED,
            limits=limits,
            created_at=created_at,
            updated_at=created_at,
            revision=0,
        )
        payload = canonical_json_bytes(record)
        try:
            with self._write() as connection:
                row = connection.execute(
                    """
                    SELECT payload
                    FROM durable_runs
                    WHERE investigation_id = ?
                    """,
                    (record.investigation_id,),
                ).fetchone()
                if row is not None:
                    current = self._decode(
                        row["payload"],
                        DurableRunRecord,
                        record.investigation_id,
                    )
                    if canonical_json_bytes(current.envelope) != canonical_json_bytes(
                        record.envelope
                    ):
                        raise DurableRunConflict(record.investigation_id)
                    self._runtime_provenance_locked(
                        connection,
                        record.investigation_id,
                    )
                    return CreateDurableRunResult(run=current, created=False)
                connection.execute(
                    """
                    INSERT INTO durable_runs (
                        investigation_id,
                        envelope_sha256,
                        payload
                    ) VALUES (?, ?, ?)
                    """,
                    (record.investigation_id, record.envelope_sha256, payload),
                )
                connection.execute(
                    """
                    INSERT INTO runtime_provenance (investigation_id, sha256)
                    VALUES (?, ?)
                    """,
                    (record.investigation_id, runtime_provenance_sha256),
                )
                return CreateDurableRunResult(run=record, created=True)
        except DurableRuntimeExceptionTypes:
            raise
        except sqlite3.DatabaseError as error:
            raise CorruptDurableState(record.investigation_id) from error

    async def get_run(self, investigation_id: str) -> DurableRunRecord:
        return await asyncio.to_thread(self._get_run, investigation_id)

    def _get_run(self, investigation_id: str) -> DurableRunRecord:
        try:
            with self._connect() as connection:
                return self._run_locked(connection, investigation_id)
        except DurableRuntimeExceptionTypes:
            raise
        except sqlite3.DatabaseError as error:
            raise CorruptDurableState(investigation_id) from error

    async def list_runs(self) -> tuple[DurableRunRecord, ...]:
        return await asyncio.to_thread(self._list_runs)

    def _list_runs(self) -> tuple[DurableRunRecord, ...]:
        try:
            with self._connect() as connection:
                rows = connection.execute(
                    """
                    SELECT investigation_id, envelope_sha256, payload
                    FROM durable_runs
                    ORDER BY investigation_id
                    """
                ).fetchall()
                runs = tuple(
                    self._decode(
                        row["payload"],
                        DurableRunRecord,
                        row["investigation_id"],
                    )
                    for row in rows
                )
                if any(
                    row["investigation_id"] != run.investigation_id
                    or row["envelope_sha256"] != run.envelope_sha256
                    for row, run in zip(rows, runs, strict=True)
                ):
                    raise CorruptDurableState()
                return runs
        except DurableRuntimeExceptionTypes:
            raise
        except sqlite3.DatabaseError as error:
            raise CorruptDurableState() from error

    def _runtime_provenance_locked(
        self,
        connection: sqlite3.Connection,
        investigation_id: str,
    ) -> str:
        row = connection.execute(
            """
            SELECT sha256
            FROM runtime_provenance
            WHERE investigation_id = ?
            """,
            (investigation_id,),
        ).fetchone()
        if (
            row is None
            or not isinstance(row["sha256"], str)
            or re.fullmatch(r"[0-9a-f]{64}", row["sha256"]) is None
        ):
            raise CorruptDurableState(investigation_id)
        return row["sha256"]

    async def runtime_provenance_sha256(self, investigation_id: str) -> str:
        return await asyncio.to_thread(
            self._runtime_provenance_sha256,
            investigation_id,
        )

    def _runtime_provenance_sha256(self, investigation_id: str) -> str:
        try:
            with self._connect() as connection:
                self._run_locked(connection, investigation_id)
                return self._runtime_provenance_locked(
                    connection,
                    investigation_id,
                )
        except DurableRuntimeExceptionTypes:
            raise
        except sqlite3.DatabaseError as error:
            raise CorruptDurableState(investigation_id) from error

    def _current_lease_locked(
        self,
        connection: sqlite3.Connection,
        investigation_id: str,
    ) -> tuple[int, LeaseToken | None]:
        row = connection.execute(
            """
            SELECT fence, payload
            FROM durable_leases
            WHERE investigation_id = ?
            """,
            (investigation_id,),
        ).fetchone()
        if row is None:
            return 0, None
        if row["payload"] is None:
            return int(row["fence"]), None
        lease = self._decode(row["payload"], LeaseToken, investigation_id)
        if lease.fence != row["fence"]:
            raise CorruptDurableState(investigation_id)
        return int(row["fence"]), lease

    def _validate_lease_locked(
        self,
        connection: sqlite3.Connection,
        lease: LeaseToken,
        now: datetime,
    ) -> LeaseToken:
        now = _aware_utc(now)
        _, current = self._current_lease_locked(connection, lease.investigation_id)
        if (
            current is None
            or canonical_json_bytes(current) != canonical_json_bytes(lease)
            or now < current.renewed_at
            or current.expired(now)
        ):
            raise StaleLease(lease.investigation_id)
        return current

    async def acquire_lease(
        self,
        investigation_id: str,
        owner_id: str,
        *,
        now: datetime,
    ) -> LeaseToken:
        return await asyncio.to_thread(
            self._acquire_lease,
            investigation_id,
            owner_id,
            now,
        )

    def _acquire_lease(
        self,
        investigation_id: str,
        owner_id: str,
        now: datetime,
    ) -> LeaseToken:
        now = _aware_utc(now)
        try:
            with self._write() as connection:
                self._run_locked(connection, investigation_id)
                fence, current = self._current_lease_locked(
                    connection,
                    investigation_id,
                )
                if current is not None and not current.expired(now):
                    if current.owner_id == owner_id:
                        return current
                    raise LeaseUnavailable(investigation_id)
                lease = LeaseToken(
                    schema_version=DURABLE_LEASE_VERSION,
                    investigation_id=investigation_id,
                    owner_id=owner_id,
                    fence=fence + 1,
                    acquired_at=now,
                    renewed_at=now,
                    renew_after=now + LEASE_RENEWAL_INTERVAL,
                    expires_at=now + LEASE_DURATION,
                )
                connection.execute(
                    """
                    INSERT INTO durable_leases (investigation_id, fence, payload)
                    VALUES (?, ?, ?)
                    ON CONFLICT(investigation_id) DO UPDATE SET
                        fence = excluded.fence,
                        payload = excluded.payload
                    """,
                    (investigation_id, lease.fence, canonical_json_bytes(lease)),
                )
                return lease
        except DurableRuntimeExceptionTypes:
            raise
        except sqlite3.DatabaseError as error:
            raise CorruptDurableState(investigation_id) from error

    async def renew_lease(
        self,
        lease: LeaseToken,
        *,
        now: datetime,
    ) -> LeaseToken:
        return await asyncio.to_thread(self._renew_lease, lease, now)

    def _renew_lease(self, lease: LeaseToken, now: datetime) -> LeaseToken:
        now = _aware_utc(now)
        try:
            with self._write() as connection:
                current = self._validate_lease_locked(connection, lease, now)
                if now < current.renew_after:
                    raise LeaseRenewalTooEarly(lease.investigation_id)
                renewed = LeaseToken(
                    schema_version=DURABLE_LEASE_VERSION,
                    investigation_id=current.investigation_id,
                    owner_id=current.owner_id,
                    fence=current.fence,
                    acquired_at=current.acquired_at,
                    renewed_at=now,
                    renew_after=now + LEASE_RENEWAL_INTERVAL,
                    expires_at=now + LEASE_DURATION,
                )
                connection.execute(
                    """
                    UPDATE durable_leases
                    SET payload = ?
                    WHERE investigation_id = ? AND fence = ?
                    """,
                    (
                        canonical_json_bytes(renewed),
                        renewed.investigation_id,
                        renewed.fence,
                    ),
                )
                return renewed
        except DurableRuntimeExceptionTypes:
            raise
        except sqlite3.DatabaseError as error:
            raise CorruptDurableState(lease.investigation_id) from error

    async def validate_lease(
        self,
        lease: LeaseToken,
        *,
        now: datetime,
    ) -> None:
        await asyncio.to_thread(self._validate_lease, lease, now)

    def _validate_lease(self, lease: LeaseToken, now: datetime) -> None:
        now = _aware_utc(now)
        try:
            with self._connect() as connection:
                self._validate_lease_locked(connection, lease, now)
        except DurableRuntimeExceptionTypes:
            raise
        except sqlite3.DatabaseError as error:
            raise CorruptDurableState(lease.investigation_id) from error

    async def release_lease(
        self,
        lease: LeaseToken,
        *,
        now: datetime,
    ) -> None:
        await asyncio.to_thread(self._release_lease, lease, now)

    def _release_lease(self, lease: LeaseToken, now: datetime) -> None:
        try:
            with self._write() as connection:
                self._validate_lease_locked(connection, lease, now)
                connection.execute(
                    """
                    UPDATE durable_leases
                    SET payload = NULL
                    WHERE investigation_id = ? AND fence = ?
                    """,
                    (lease.investigation_id, lease.fence),
                )
        except DurableRuntimeExceptionTypes:
            raise
        except sqlite3.DatabaseError as error:
            raise CorruptDurableState(lease.investigation_id) from error

    async def mark_active(
        self,
        lease: LeaseToken,
        *,
        occurred_at: datetime,
    ) -> DurableRunRecord:
        return await asyncio.to_thread(self._mark_active, lease, occurred_at)

    def _mark_active(
        self,
        lease: LeaseToken,
        occurred_at: datetime,
    ) -> DurableRunRecord:
        occurred_at = _aware_utc(occurred_at)
        try:
            with self._write() as connection:
                self._validate_lease_locked(connection, lease, occurred_at)
                run = self._run_locked(connection, lease.investigation_id)
                if run.state is DurableRunState.ACTIVE:
                    return run
                if run.state is not DurableRunState.CREATED:
                    raise DurableStateConflict(run.investigation_id, "mark_active")
                active = DurableRunRecord.model_validate(
                    run.model_copy(
                        update={
                            "state": DurableRunState.ACTIVE,
                            "updated_at": max(run.updated_at, occurred_at),
                            "revision": run.revision + 1,
                        }
                    )
                )
                self._replace_run_locked(connection, active)
                return active
        except DurableRuntimeExceptionTypes:
            raise
        except sqlite3.DatabaseError as error:
            raise CorruptDurableState(lease.investigation_id) from error

    async def require_escalation(
        self,
        lease: LeaseToken,
        *,
        failure_code: str,
        occurred_at: datetime,
    ) -> DurableRunRecord:
        return await asyncio.to_thread(
            self._require_escalation,
            lease,
            failure_code,
            occurred_at,
        )

    def _require_escalation(
        self,
        lease: LeaseToken,
        failure_code: str,
        occurred_at: datetime,
    ) -> DurableRunRecord:
        occurred_at = _aware_utc(occurred_at)
        try:
            with self._write() as connection:
                self._validate_lease_locked(connection, lease, occurred_at)
                run = self._run_locked(connection, lease.investigation_id)
                if run.state is DurableRunState.ESCALATION_REQUIRED:
                    if run.recovery_failure_code == failure_code:
                        return run
                    raise DurableStateConflict(run.investigation_id, "escalate")
                if run.state is DurableRunState.TERMINAL:
                    raise DurableStateConflict(run.investigation_id, "escalate")
                escalated = DurableRunRecord.model_validate(
                    run.model_copy(
                        update={
                            "state": DurableRunState.ESCALATION_REQUIRED,
                            "recovery_failure_code": failure_code,
                            "updated_at": max(run.updated_at, occurred_at),
                            "revision": run.revision + 1,
                        }
                    )
                )
                self._replace_run_locked(connection, escalated)
                return escalated
        except DurableRuntimeExceptionTypes:
            raise
        except (TypeError, ValueError):
            raise
        except sqlite3.DatabaseError as error:
            raise CorruptDurableState(lease.investigation_id) from error

    async def start_probe(
        self,
        lease: LeaseToken,
        *,
        checkpoint_id: str,
        step_sequence: int,
        request: ProbeRequest,
        replay_safety: ProbeReplaySafety,
        started_at: datetime,
        now: datetime,
    ) -> ProbeCheckpoint:
        return await asyncio.to_thread(
            self._start_probe,
            lease,
            checkpoint_id,
            step_sequence,
            request,
            replay_safety,
            started_at,
            now,
        )

    def _start_probe(
        self,
        lease: LeaseToken,
        checkpoint_id: str,
        step_sequence: int,
        request: ProbeRequest,
        replay_safety: ProbeReplaySafety,
        started_at: datetime,
        now: datetime,
    ) -> ProbeCheckpoint:
        started_at = _aware_utc(started_at)
        now = _aware_utc(now)
        checkpoint = ProbeCheckpoint(
            schema_version=PROBE_CHECKPOINT_VERSION,
            investigation_id=lease.investigation_id,
            checkpoint_id=checkpoint_id,
            step_sequence=step_sequence,
            request=request,
            request_sha256=probe_request_sha256(request),
            replay_safety=replay_safety,
            state=ProbeCheckpointState.STARTED,
            started_at=started_at,
        )
        try:
            with self._write() as connection:
                self._validate_lease_locked(connection, lease, now)
                run = self._run_locked(connection, lease.investigation_id)
                row = connection.execute(
                    """
                    SELECT payload
                    FROM probe_checkpoints
                    WHERE investigation_id = ? AND checkpoint_id = ?
                    """,
                    (lease.investigation_id, checkpoint_id),
                ).fetchone()
                if row is not None:
                    current = self._decode(
                        row["payload"], ProbeCheckpoint, lease.investigation_id
                    )
                    if (
                        current.step_sequence == checkpoint.step_sequence
                        and current.request_sha256 == checkpoint.request_sha256
                        and current.replay_safety is checkpoint.replay_safety
                    ):
                        return current
                    raise ProbeCheckpointConflict(
                        lease.investigation_id,
                        checkpoint_id,
                    )
                if run.state is not DurableRunState.ACTIVE:
                    raise DurableStateConflict(run.investigation_id, "start_probe")
                if now >= run.limits.deadline_at:
                    raise BudgetExceeded(run.investigation_id, "deadline")
                previous_sequence = connection.execute(
                    """
                    SELECT COALESCE(MAX(step_sequence), 0) AS previous_sequence
                    FROM probe_checkpoints
                    WHERE investigation_id = ?
                    """,
                    (lease.investigation_id,),
                ).fetchone()["previous_sequence"]
                if (
                    step_sequence <= previous_sequence
                    or step_sequence > run.limits.max_probe_count
                ):
                    raise ProbeCheckpointConflict(
                        lease.investigation_id,
                        checkpoint_id,
                    )
                connection.execute(
                    """
                    INSERT INTO probe_checkpoints (
                        investigation_id,
                        checkpoint_id,
                        step_sequence,
                        payload
                    ) VALUES (?, ?, ?, ?)
                    """,
                    (
                        checkpoint.investigation_id,
                        checkpoint.checkpoint_id,
                        checkpoint.step_sequence,
                        canonical_json_bytes(checkpoint),
                    ),
                )
                return checkpoint
        except DurableRuntimeExceptionTypes:
            raise
        except sqlite3.IntegrityError as error:
            raise ProbeCheckpointConflict(
                lease.investigation_id,
                checkpoint_id,
            ) from error
        except sqlite3.DatabaseError as error:
            raise CorruptDurableState(lease.investigation_id) from error

    async def record_probe(
        self,
        lease: LeaseToken,
        checkpoint_id: str,
        *,
        audit: ControllerAuditRecord,
        observation: ProbeObservation | None,
        recorded_at: datetime,
    ) -> ProbeCheckpoint:
        return await asyncio.to_thread(
            self._record_probe,
            lease,
            checkpoint_id,
            audit,
            observation,
            recorded_at,
        )

    def _record_probe(
        self,
        lease: LeaseToken,
        checkpoint_id: str,
        audit: ControllerAuditRecord,
        observation: ProbeObservation | None,
        recorded_at: datetime,
    ) -> ProbeCheckpoint:
        recorded_at = _aware_utc(recorded_at)
        try:
            with self._write() as connection:
                self._validate_lease_locked(connection, lease, recorded_at)
                run = self._run_locked(connection, lease.investigation_id)
                row = connection.execute(
                    """
                    SELECT payload
                    FROM probe_checkpoints
                    WHERE investigation_id = ? AND checkpoint_id = ?
                    """,
                    (lease.investigation_id, checkpoint_id),
                ).fetchone()
                if row is None:
                    raise ProbeCheckpointConflict(
                        lease.investigation_id,
                        checkpoint_id,
                    )
                current = self._decode(
                    row["payload"], ProbeCheckpoint, lease.investigation_id
                )
                if current.replay_safety is not ProbeReplaySafety.SAFE_READ:
                    raise ProbeCheckpointConflict(
                        lease.investigation_id,
                        checkpoint_id,
                    )
                if current.state is ProbeCheckpointState.RECORDED:
                    if canonical_json_bytes(current.audit) == canonical_json_bytes(
                        audit
                    ) and (
                        (current.observation is None and observation is None)
                        or (
                            current.observation is not None
                            and observation is not None
                            and canonical_json_bytes(current.observation)
                            == canonical_json_bytes(observation)
                        )
                    ):
                        return current
                    raise ProbeCheckpointConflict(
                        lease.investigation_id,
                        checkpoint_id,
                    )
                if run.state is not DurableRunState.ACTIVE:
                    raise DurableStateConflict(run.investigation_id, "record_probe")
                if (
                    audit.outcome is ProbeOutcome.COMPLETED
                    and audit.completed_at >= run.limits.deadline_at
                ):
                    raise BudgetExceeded(run.investigation_id, "deadline")
                recorded = ProbeCheckpoint(
                    schema_version=PROBE_CHECKPOINT_VERSION,
                    investigation_id=current.investigation_id,
                    checkpoint_id=current.checkpoint_id,
                    step_sequence=current.step_sequence,
                    request=current.request,
                    request_sha256=current.request_sha256,
                    replay_safety=current.replay_safety,
                    state=ProbeCheckpointState.RECORDED,
                    started_at=current.started_at,
                    recorded_at=recorded_at,
                    audit=audit,
                    observation=observation,
                )
                connection.execute(
                    """
                    UPDATE probe_checkpoints
                    SET payload = ?
                    WHERE investigation_id = ? AND checkpoint_id = ?
                    """,
                    (
                        canonical_json_bytes(recorded),
                        lease.investigation_id,
                        checkpoint_id,
                    ),
                )
                return recorded
        except DurableRuntimeExceptionTypes:
            raise
        except sqlite3.DatabaseError as error:
            raise CorruptDurableState(lease.investigation_id) from error

    async def record_controller_audit(
        self,
        lease: LeaseToken,
        audit: ControllerAuditRecord,
        *,
        recorded_at: datetime,
    ) -> ControllerAuditRecord:
        return await asyncio.to_thread(
            self._record_controller_audit,
            lease,
            audit,
            recorded_at,
        )

    def _record_controller_audit(
        self,
        lease: LeaseToken,
        audit: ControllerAuditRecord,
        recorded_at: datetime,
    ) -> ControllerAuditRecord:
        if type(audit) is not ControllerAuditRecord:
            raise TypeError("controller audit must be exact")
        audit = ControllerAuditRecord.model_validate_json(canonical_json_bytes(audit))
        recorded_at = _aware_utc(recorded_at)
        try:
            with self._write() as connection:
                self._validate_lease_locked(connection, lease, recorded_at)
                run = self._run_locked(connection, lease.investigation_id)
                existing = connection.execute(
                    """
                    SELECT payload
                    FROM controller_audits
                    WHERE investigation_id = ? AND sequence = ?
                    """,
                    (lease.investigation_id, audit.sequence),
                ).fetchone()
                if existing is not None:
                    try:
                        current = ControllerAuditRecord.model_validate_json(
                            _blob(existing["payload"])
                        )
                    except (TypeError, ValueError) as error:
                        raise CorruptDurableState(lease.investigation_id) from error
                    if canonical_json_bytes(current) == canonical_json_bytes(audit):
                        return current
                    raise ControllerAuditConflict(
                        lease.investigation_id,
                        audit.sequence,
                    )
                if run.state is not DurableRunState.ACTIVE:
                    raise DurableStateConflict(
                        run.investigation_id,
                        "record_controller_audit",
                    )
                next_sequence = connection.execute(
                    """
                    SELECT COALESCE(MAX(sequence), 0) + 1 AS next_sequence
                    FROM controller_audits
                    WHERE investigation_id = ?
                    """,
                    (lease.investigation_id,),
                ).fetchone()["next_sequence"]
                budget = run.envelope.context.evidence_budget
                if (
                    audit.sequence != next_sequence
                    or audit.started_at < run.created_at
                    or recorded_at < audit.completed_at
                    or audit.target_sha256 != canonical_sha256(run.envelope.target)
                    or audit.probe_count_used > run.limits.max_probe_count
                    or audit.cost_units_used > run.limits.max_controller_cost_units
                    or audit.result_bytes_acquired > run.limits.max_evidence_bytes
                    or audit.session_elapsed_ms > budget.max_elapsed_ms
                ):
                    raise ControllerAuditConflict(
                        lease.investigation_id,
                        audit.sequence,
                    )
                connection.execute(
                    """
                    INSERT INTO controller_audits (
                        investigation_id,
                        sequence,
                        payload
                    ) VALUES (?, ?, ?)
                    """,
                    (
                        lease.investigation_id,
                        audit.sequence,
                        canonical_json_bytes(audit),
                    ),
                )
                return audit
        except DurableRuntimeExceptionTypes:
            raise
        except sqlite3.IntegrityError as error:
            raise ControllerAuditConflict(
                lease.investigation_id,
                audit.sequence,
            ) from error
        except sqlite3.DatabaseError as error:
            raise CorruptDurableState(lease.investigation_id) from error

    def _controller_audits_locked(
        self,
        connection: sqlite3.Connection,
        investigation_id: str,
    ) -> tuple[ControllerAuditRecord, ...]:
        run = self._run_locked(connection, investigation_id)
        rows = connection.execute(
            """
            SELECT sequence, payload
            FROM controller_audits
            WHERE investigation_id = ?
            ORDER BY sequence
            """,
            (investigation_id,),
        ).fetchall()
        try:
            audits = tuple(
                ControllerAuditRecord.model_validate_json(_blob(row["payload"]))
                for row in rows
            )
        except (TypeError, ValueError) as error:
            raise CorruptDurableState(investigation_id) from error
        budget = run.envelope.context.evidence_budget
        if any(
            row["sequence"] != expected
            or audit.sequence != expected
            or audit.target_sha256 != canonical_sha256(run.envelope.target)
            or audit.probe_count_used > run.limits.max_probe_count
            or audit.cost_units_used > run.limits.max_controller_cost_units
            or audit.result_bytes_acquired > run.limits.max_evidence_bytes
            or audit.session_elapsed_ms > budget.max_elapsed_ms
            for expected, (row, audit) in enumerate(
                zip(rows, audits, strict=True),
                1,
            )
        ):
            raise CorruptDurableState(investigation_id)
        return audits

    async def controller_audits(
        self,
        investigation_id: str,
    ) -> tuple[ControllerAuditRecord, ...]:
        return await asyncio.to_thread(self._controller_audits, investigation_id)

    def _controller_audits(
        self,
        investigation_id: str,
    ) -> tuple[ControllerAuditRecord, ...]:
        try:
            with self._connect() as connection:
                return self._controller_audits_locked(connection, investigation_id)
        except DurableRuntimeExceptionTypes:
            raise
        except sqlite3.DatabaseError as error:
            raise CorruptDurableState(investigation_id) from error

    async def resume_plan(
        self,
        investigation_id: str,
        *,
        now: datetime,
    ) -> ProbeResumePlan:
        return await asyncio.to_thread(self._resume_plan, investigation_id, now)

    def _resume_plan(
        self,
        investigation_id: str,
        now: datetime,
    ) -> ProbeResumePlan:
        now = _aware_utc(now)
        try:
            with self._connect() as connection:
                run = self._run_locked(connection, investigation_id)
                checkpoints = self._probe_checkpoints_locked(
                    connection,
                    investigation_id,
                )
                return build_probe_resume_plan(
                    investigation_id,
                    checkpoints,
                    repeat_safe_reads=(
                        run.state is DurableRunState.ACTIVE
                        and now < run.limits.deadline_at
                    ),
                )
        except DurableRuntimeExceptionTypes:
            raise
        except sqlite3.DatabaseError as error:
            raise CorruptDurableState(investigation_id) from error

    def _probe_checkpoints_locked(
        self,
        connection: sqlite3.Connection,
        investigation_id: str,
    ) -> tuple[ProbeCheckpoint, ...]:
        rows = connection.execute(
            """
            SELECT checkpoint_id, step_sequence, payload
            FROM probe_checkpoints
            WHERE investigation_id = ?
            ORDER BY step_sequence
            """,
            (investigation_id,),
        ).fetchall()
        checkpoints = tuple(
            self._decode(row["payload"], ProbeCheckpoint, investigation_id)
            for row in rows
        )
        if any(
            row["step_sequence"] != checkpoint.step_sequence
            or row["checkpoint_id"] != checkpoint.checkpoint_id
            or checkpoint.investigation_id != investigation_id
            for row, checkpoint in zip(rows, checkpoints, strict=True)
        ) or any(
            current.step_sequence <= previous.step_sequence
            for previous, current in pairwise(checkpoints)
        ):
            raise CorruptDurableState(investigation_id)
        return checkpoints

    async def probe_checkpoints(
        self,
        investigation_id: str,
    ) -> tuple[ProbeCheckpoint, ...]:
        return await asyncio.to_thread(self._probe_checkpoints, investigation_id)

    def _probe_checkpoints(
        self,
        investigation_id: str,
    ) -> tuple[ProbeCheckpoint, ...]:
        try:
            with self._connect() as connection:
                self._run_locked(connection, investigation_id)
                return self._probe_checkpoints_locked(connection, investigation_id)
        except DurableRuntimeExceptionTypes:
            raise
        except sqlite3.DatabaseError as error:
            raise CorruptDurableState(investigation_id) from error

    async def append_event(
        self,
        lease: LeaseToken,
        event: InvestigationEvent,
        *,
        now: datetime,
    ) -> InvestigationEvent:
        return await asyncio.to_thread(self._append_event, lease, event, now)

    def _append_event(
        self,
        lease: LeaseToken,
        event: InvestigationEvent,
        now: datetime,
    ) -> InvestigationEvent:
        now = _aware_utc(now)
        payload = canonical_json_bytes(event)
        validated = decode_contract(payload, InvestigationEvent)
        if validated.investigation_id != lease.investigation_id:
            raise DurableStateConflict(lease.investigation_id, "append_event")
        try:
            with self._write() as connection:
                self._validate_lease_locked(connection, lease, now)
                rows = connection.execute(
                    """
                    SELECT sequence, terminal, payload
                    FROM investigation_events
                    WHERE investigation_id = ?
                    ORDER BY sequence
                    """,
                    (lease.investigation_id,),
                ).fetchall()
                self._validate_event_rows(rows, lease.investigation_id)
                latest = len(rows)
                if validated.sequence <= latest:
                    existing = rows[validated.sequence - 1]
                    if _blob(existing["payload"]) == payload:
                        return self._decode(
                            existing["payload"],
                            InvestigationEvent,
                            lease.investigation_id,
                        )
                    raise DuplicateEvent(
                        lease.investigation_id,
                        latest + 1,
                        validated.sequence,
                    )
                if validated.sequence != latest + 1:
                    raise OutOfOrderEvent(
                        lease.investigation_id,
                        latest + 1,
                        validated.sequence,
                    )
                if latest >= MAX_INVESTIGATION_EVENTS:
                    raise JournalCapacityExceeded(lease.investigation_id)
                if rows and rows[-1]["terminal"]:
                    raise TerminalEventJournal(lease.investigation_id)
                connection.execute(
                    """
                    INSERT INTO investigation_events (
                        investigation_id,
                        sequence,
                        terminal,
                        payload
                    ) VALUES (?, ?, ?, ?)
                    """,
                    (
                        lease.investigation_id,
                        validated.sequence,
                        int(_terminal_event(validated)),
                        payload,
                    ),
                )
                return validated
        except DurableRuntimeExceptionTypes:
            raise
        except sqlite3.DatabaseError as error:
            raise CorruptDurableState(lease.investigation_id) from error

    async def snapshot_events(
        self,
        investigation_id: str,
        *,
        after: int = 0,
    ) -> EventJournalSnapshot:
        return await asyncio.to_thread(self._snapshot_events, investigation_id, after)

    def _snapshot_events(
        self,
        investigation_id: str,
        after: int,
    ) -> EventJournalSnapshot:
        try:
            with self._connect() as connection:
                self._run_locked(connection, investigation_id)
                rows = connection.execute(
                    """
                    SELECT sequence, terminal, payload
                    FROM investigation_events
                    WHERE investigation_id = ?
                    ORDER BY sequence
                    """,
                    (investigation_id,),
                ).fetchall()
                events = self._validate_event_rows(rows, investigation_id)
                latest = len(rows)
                if (
                    isinstance(after, bool)
                    or not isinstance(after, int)
                    or after < 0
                    or after > latest
                ):
                    raise InvalidCursor(investigation_id, after, latest)
                return EventJournalSnapshot(
                    events=events[after:],
                    cursor=latest,
                    terminal=bool(rows and rows[-1]["terminal"]),
                )
        except DurableRuntimeExceptionTypes:
            raise
        except sqlite3.DatabaseError as error:
            raise CorruptDurableState(investigation_id) from error

    async def establish_report(
        self,
        lease: LeaseToken,
        report: InvestigationReport,
        *,
        occurred_at: datetime,
    ) -> DurableRunRecord:
        return await asyncio.to_thread(
            self._establish_report,
            lease,
            report,
            occurred_at,
        )

    def _establish_report(
        self,
        lease: LeaseToken,
        report: InvestigationReport,
        occurred_at: datetime,
    ) -> DurableRunRecord:
        occurred_at = _aware_utc(occurred_at)
        try:
            with self._write() as connection:
                self._validate_lease_locked(connection, lease, occurred_at)
                run = self._run_locked(connection, lease.investigation_id)
                if run.established_report is not None:
                    if canonical_json_bytes(
                        run.established_report
                    ) == canonical_json_bytes(report):
                        return run
                    raise DurableStateConflict(run.investigation_id, "establish_report")
                if run.state is not DurableRunState.ACTIVE:
                    raise DurableStateConflict(run.investigation_id, "establish_report")
                terminal = DurableRunRecord.model_validate(
                    run.model_copy(
                        update={
                            "state": DurableRunState.TERMINAL,
                            "established_report": report,
                            "updated_at": max(
                                run.updated_at,
                                occurred_at,
                                report.updated_at,
                            ),
                            "revision": run.revision + 1,
                        }
                    )
                )
                self._replace_run_locked(connection, terminal)
                return terminal
        except DurableRuntimeExceptionTypes:
            raise
        except sqlite3.DatabaseError as error:
            raise CorruptDurableState(lease.investigation_id) from error

    async def record_cleanup(
        self,
        lease: LeaseToken,
        status: CleanupStatus,
        *,
        occurred_at: datetime,
        failure_code: str | None = None,
    ) -> DurableRunRecord:
        return await asyncio.to_thread(
            self._record_cleanup,
            lease,
            status,
            occurred_at,
            failure_code,
        )

    def _record_cleanup(
        self,
        lease: LeaseToken,
        status: CleanupStatus,
        occurred_at: datetime,
        failure_code: str | None,
    ) -> DurableRunRecord:
        occurred_at = _aware_utc(occurred_at)
        if status is CleanupStatus.NOT_REQUESTED:
            raise ValueError("cleanup recording requires an attempted status")
        try:
            with self._write() as connection:
                self._validate_lease_locked(connection, lease, occurred_at)
                run = self._run_locked(connection, lease.investigation_id)
                if run.cleanup_status in {
                    CleanupStatus.SUCCEEDED,
                    CleanupStatus.FAILED,
                }:
                    if (
                        run.cleanup_status is status
                        and run.cleanup_failure_code == failure_code
                    ):
                        return run
                    raise DurableStateConflict(run.investigation_id, "record_cleanup")
                if (
                    run.cleanup_status is CleanupStatus.PENDING
                    and status is CleanupStatus.PENDING
                ):
                    return run
                updated = DurableRunRecord.model_validate(
                    run.model_copy(
                        update={
                            "cleanup_status": status,
                            "cleanup_failure_code": failure_code,
                            "updated_at": max(run.updated_at, occurred_at),
                            "revision": run.revision + 1,
                        }
                    )
                )
                self._replace_run_locked(connection, updated)
                return updated
        except DurableRuntimeExceptionTypes:
            raise
        except sqlite3.DatabaseError as error:
            raise CorruptDurableState(lease.investigation_id) from error

    async def append_telemetry(
        self,
        lease: LeaseToken,
        record: RuntimeTelemetryRecord,
        *,
        now: datetime,
    ) -> RuntimeTelemetryRecord:
        return await asyncio.to_thread(self._append_telemetry, lease, record, now)

    def _append_telemetry(
        self,
        lease: LeaseToken,
        record: RuntimeTelemetryRecord,
        now: datetime,
    ) -> RuntimeTelemetryRecord:
        now = _aware_utc(now)
        payload = canonical_json_bytes(record)
        if record.investigation_id != lease.investigation_id:
            raise DurableStateConflict(lease.investigation_id, "append_telemetry")
        try:
            with self._write() as connection:
                self._validate_lease_locked(connection, lease, now)
                existing = connection.execute(
                    """
                    SELECT payload
                    FROM runtime_telemetry
                    WHERE investigation_id = ? AND telemetry_id = ?
                    """,
                    (record.investigation_id, record.telemetry_id),
                ).fetchone()
                if existing is not None:
                    if _blob(existing["payload"]) == payload:
                        return self._decode(
                            existing["payload"],
                            RuntimeTelemetryRecord,
                            record.investigation_id,
                        )
                    raise DurableStateConflict(
                        record.investigation_id,
                        "append_telemetry",
                    )
                next_sequence = connection.execute(
                    """
                    SELECT COALESCE(MAX(sequence), 0) + 1 AS next_sequence
                    FROM runtime_telemetry
                    WHERE investigation_id = ?
                    """,
                    (record.investigation_id,),
                ).fetchone()["next_sequence"]
                if record.sequence != next_sequence:
                    raise DurableStateConflict(
                        record.investigation_id,
                        "append_telemetry",
                    )
                connection.execute(
                    """
                    INSERT INTO runtime_telemetry (
                        investigation_id,
                        telemetry_id,
                        sequence,
                        payload
                    ) VALUES (?, ?, ?, ?)
                    """,
                    (
                        record.investigation_id,
                        record.telemetry_id,
                        record.sequence,
                        payload,
                    ),
                )
                return record
        except DurableRuntimeExceptionTypes:
            raise
        except sqlite3.DatabaseError as error:
            raise CorruptDurableState(record.investigation_id) from error

    async def telemetry_records(
        self,
        investigation_id: str,
    ) -> tuple[RuntimeTelemetryRecord, ...]:
        return await asyncio.to_thread(self._telemetry_records, investigation_id)

    def _telemetry_records(
        self,
        investigation_id: str,
    ) -> tuple[RuntimeTelemetryRecord, ...]:
        try:
            with self._connect() as connection:
                self._run_locked(connection, investigation_id)
                rows = connection.execute(
                    """
                    SELECT telemetry_id, sequence, payload
                    FROM runtime_telemetry
                    WHERE investigation_id = ?
                    ORDER BY sequence
                    """,
                    (investigation_id,),
                ).fetchall()
                records = tuple(
                    self._decode(
                        row["payload"],
                        RuntimeTelemetryRecord,
                        investigation_id,
                    )
                    for row in rows
                )
                if any(
                    row["sequence"] != expected
                    or record.sequence != expected
                    or row["telemetry_id"] != record.telemetry_id
                    or record.investigation_id != investigation_id
                    for expected, (row, record) in enumerate(
                        zip(rows, records, strict=True),
                        1,
                    )
                ):
                    raise CorruptDurableState(investigation_id)
                return records
        except DurableRuntimeExceptionTypes:
            raise
        except sqlite3.DatabaseError as error:
            raise CorruptDurableState(investigation_id) from error

    def _cost_snapshot_locked(
        self,
        connection: sqlite3.Connection,
        run: DurableRunRecord,
    ) -> CostLedgerSnapshot:
        rows = connection.execute(
            """
            SELECT entry_id,
                   sequence,
                   provider_calls,
                   probe_count,
                   evidence_bytes,
                   controller_cost_units,
                   estimated_cost_microunits,
                   payload
            FROM runtime_cost_entries
            WHERE investigation_id = ?
            ORDER BY sequence
            """,
            (run.investigation_id,),
        ).fetchall()
        totals = {
            "provider_calls": 0,
            "probe_count": 0,
            "evidence_bytes": 0,
            "controller_cost_units": 0,
            "estimated_cost_microunits": 0,
        }
        for expected_sequence, row in enumerate(rows, 1):
            entry = self._decode(
                row["payload"],
                CostLedgerEntry,
                run.investigation_id,
            )
            delta_columns = {
                "provider_calls": row["provider_calls"],
                "probe_count": row["probe_count"],
                "evidence_bytes": row["evidence_bytes"],
                "controller_cost_units": row["controller_cost_units"],
                "estimated_cost_microunits": row["estimated_cost_microunits"],
            }
            if (
                row["sequence"] != expected_sequence
                or entry.sequence != expected_sequence
                or row["entry_id"] != entry.entry_id
                or entry.investigation_id != run.investigation_id
                or any(
                    value != getattr(entry.delta, column)
                    for column, value in delta_columns.items()
                )
            ):
                raise CorruptDurableState(run.investigation_id)
            for column, value in delta_columns.items():
                totals[column] += value
        try:
            return CostLedgerSnapshot(
                schema_version=COST_LEDGER_SNAPSHOT_VERSION,
                investigation_id=run.investigation_id,
                entry_count=len(rows),
                provider_calls=totals["provider_calls"],
                probe_count=totals["probe_count"],
                evidence_bytes=totals["evidence_bytes"],
                controller_cost_units=totals["controller_cost_units"],
                estimated_cost_microunits=totals["estimated_cost_microunits"],
                limits=run.limits,
            )
        except (TypeError, ValueError) as error:
            raise CorruptDurableState(run.investigation_id) from error

    async def charge(
        self,
        lease: LeaseToken,
        *,
        entry_id: str,
        category: str,
        occurred_at: datetime,
        delta: RuntimeCostDelta,
    ) -> CostLedgerSnapshot:
        return await asyncio.to_thread(
            self._charge,
            lease,
            entry_id,
            category,
            occurred_at,
            delta,
            True,
        )

    async def reserve_provider_call(
        self,
        lease: LeaseToken,
        *,
        call_id: str,
        occurred_at: datetime,
        estimated_cost_microunits: int,
    ) -> CostLedgerSnapshot:
        return await asyncio.to_thread(
            self._charge,
            lease,
            f"provider-{call_id}",
            "advisory-provider-reservation",
            occurred_at,
            RuntimeCostDelta(
                provider_calls=1,
                estimated_cost_microunits=estimated_cost_microunits,
            ),
            False,
        )

    def _charge(
        self,
        lease: LeaseToken,
        entry_id: str,
        category: str,
        occurred_at: datetime,
        delta: RuntimeCostDelta,
        allow_replay: bool,
    ) -> CostLedgerSnapshot:
        occurred_at = _aware_utc(occurred_at)
        try:
            with self._write() as connection:
                self._validate_lease_locked(connection, lease, occurred_at)
                run = self._run_locked(connection, lease.investigation_id)
                existing = connection.execute(
                    """
                    SELECT payload
                    FROM runtime_cost_entries
                    WHERE investigation_id = ? AND entry_id = ?
                    """,
                    (run.investigation_id, entry_id),
                ).fetchone()
                snapshot = self._cost_snapshot_locked(connection, run)
                if existing is not None:
                    stored = self._decode(
                        existing["payload"],
                        CostLedgerEntry,
                        run.investigation_id,
                    )
                    if (
                        allow_replay
                        and stored.category == category
                        and stored.delta == delta
                    ):
                        return snapshot
                    operation = "charge" if allow_replay else "reserve_provider_call"
                    raise DurableStateConflict(run.investigation_id, operation)
                if occurred_at >= run.limits.deadline_at:
                    raise BudgetExceeded(run.investigation_id, "deadline")
                proposed = {
                    "provider_calls": snapshot.provider_calls + delta.provider_calls,
                    "probe_count": snapshot.probe_count + delta.probe_count,
                    "evidence_bytes": snapshot.evidence_bytes + delta.evidence_bytes,
                    "controller_cost_units": (
                        snapshot.controller_cost_units + delta.controller_cost_units
                    ),
                    "estimated_cost_microunits": (
                        snapshot.estimated_cost_microunits
                        + delta.estimated_cost_microunits
                    ),
                }
                limits = run.limits
                ceilings = {
                    "provider_calls": limits.max_provider_calls,
                    "probe_count": limits.max_probe_count,
                    "evidence_bytes": limits.max_evidence_bytes,
                    "controller_cost_units": limits.max_controller_cost_units,
                    "estimated_cost_microunits": (limits.max_estimated_cost_microunits),
                }
                for dimension, total in proposed.items():
                    if total > ceilings[dimension]:
                        raise BudgetExceeded(run.investigation_id, dimension)
                entry = CostLedgerEntry(
                    schema_version=COST_LEDGER_ENTRY_VERSION,
                    investigation_id=run.investigation_id,
                    entry_id=entry_id,
                    sequence=snapshot.entry_count + 1,
                    category=category,
                    occurred_at=occurred_at,
                    delta=delta,
                )
                connection.execute(
                    """
                    INSERT INTO runtime_cost_entries (
                        investigation_id,
                        entry_id,
                        sequence,
                        provider_calls,
                        probe_count,
                        evidence_bytes,
                        controller_cost_units,
                        estimated_cost_microunits,
                        payload
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        run.investigation_id,
                        entry.entry_id,
                        entry.sequence,
                        delta.provider_calls,
                        delta.probe_count,
                        delta.evidence_bytes,
                        delta.controller_cost_units,
                        delta.estimated_cost_microunits,
                        canonical_json_bytes(entry),
                    ),
                )
                return self._cost_snapshot_locked(connection, run)
        except DurableRuntimeExceptionTypes:
            raise
        except sqlite3.DatabaseError as error:
            raise CorruptDurableState(lease.investigation_id) from error

    async def cost_snapshot(self, investigation_id: str) -> CostLedgerSnapshot:
        return await asyncio.to_thread(self._cost_snapshot, investigation_id)

    async def provider_call_receipts(
        self,
        investigation_id: str,
    ) -> tuple[ProviderCallReceipt, ...]:
        return await asyncio.to_thread(
            self._provider_call_receipts,
            investigation_id,
        )

    def _provider_call_receipts(
        self,
        investigation_id: str,
    ) -> tuple[ProviderCallReceipt, ...]:
        try:
            with self._connect() as connection:
                run = self._run_locked(connection, investigation_id)
                self._cost_snapshot_locked(connection, run)
                rows = connection.execute(
                    """
                    SELECT payload
                    FROM runtime_cost_entries
                    WHERE investigation_id = ?
                    ORDER BY sequence
                    """,
                    (investigation_id,),
                ).fetchall()
                entries = tuple(
                    self._decode(
                        row["payload"],
                        CostLedgerEntry,
                        investigation_id,
                    )
                    for row in rows
                )
                receipts: list[ProviderCallReceipt] = []
                for entry in entries:
                    if entry.category != "advisory-provider-reservation":
                        continue
                    prefix = "provider-"
                    call_id = entry.entry_id.removeprefix(prefix)
                    if (
                        not entry.entry_id.startswith(prefix)
                        or not call_id
                        or entry.delta.provider_calls != 1
                        or entry.delta.probe_count != 0
                        or entry.delta.evidence_bytes != 0
                        or entry.delta.controller_cost_units != 0
                    ):
                        raise CorruptDurableState(investigation_id)
                    receipts.append(
                        ProviderCallReceipt(
                            order=len(receipts) + 1,
                            ledger_sequence=entry.sequence,
                            call_id=call_id,
                            estimated_cost_microunits=(
                                entry.delta.estimated_cost_microunits
                            ),
                        )
                    )
                return tuple(receipts)
        except DurableRuntimeExceptionTypes:
            raise
        except (TypeError, ValueError) as error:
            raise CorruptDurableState(investigation_id) from error
        except sqlite3.DatabaseError as error:
            raise CorruptDurableState(investigation_id) from error

    def _cost_snapshot(self, investigation_id: str) -> CostLedgerSnapshot:
        try:
            with self._connect() as connection:
                run = self._run_locked(connection, investigation_id)
                return self._cost_snapshot_locked(connection, run)
        except DurableRuntimeExceptionTypes:
            raise
        except sqlite3.DatabaseError as error:
            raise CorruptDurableState(investigation_id) from error

    @staticmethod
    def _decode_permit(payload: object, permit_id: str) -> ActionPermit:
        try:
            return decode_contract(_blob(payload), ActionPermit)
        except (ContractError, TypeError, ValueError) as error:
            raise PermitCorruptState(permit_id) from error

    @staticmethod
    def _decode_permit_audit(payload: object, permit_id: str) -> PermitAuditEvent:
        try:
            return decode_contract(_blob(payload), PermitAuditEvent)
        except (ContractError, TypeError, ValueError) as error:
            raise PermitCorruptState(permit_id) from error

    def _permit_locked(
        self,
        connection: sqlite3.Connection,
        permit_id: str,
    ) -> ActionPermit:
        row = connection.execute(
            """
            SELECT certificate_id, state, revision, payload
            FROM action_permits
            WHERE permit_id = ?
            """,
            (permit_id,),
        ).fetchone()
        if row is None:
            raise PermitNotFound(permit_id)
        permit = self._decode_permit(row["payload"], permit_id)
        if (
            permit.permit_id != permit_id
            or row["certificate_id"] != permit.certificate_id
            or row["state"] != permit.state.value
            or row["revision"] != permit.revision
        ):
            raise PermitCorruptState(permit_id)
        return permit

    def _permit_audits_locked(
        self,
        connection: sqlite3.Connection,
        permit: ActionPermit,
    ) -> tuple[PermitAuditEvent, ...]:
        rows = connection.execute(
            """
            SELECT sequence, event_id, payload
            FROM action_permit_audits
            WHERE permit_id = ?
            ORDER BY sequence
            """,
            (permit.permit_id,),
        ).fetchall()
        events = tuple(
            self._decode_permit_audit(row["payload"], permit.permit_id) for row in rows
        )
        if any(
            row["sequence"] != sequence
            or row["event_id"] != event.event_id
            or event.permit_id != permit.permit_id
            or event.sequence != sequence
            for sequence, (row, event) in enumerate(
                zip(rows, events, strict=True),
                1,
            )
        ):
            raise PermitCorruptState(permit.permit_id)
        try:
            validate_permit_audit_history(permit, events)
        except (TypeError, ValueError) as error:
            raise PermitCorruptState(permit.permit_id) from error
        return events

    @staticmethod
    def _replace_permit_locked(
        connection: sqlite3.Connection,
        current: ActionPermit,
        replacement: ActionPermit,
    ) -> None:
        cursor = connection.execute(
            """
            UPDATE action_permits
            SET state = ?, revision = ?, payload = ?
            WHERE permit_id = ? AND revision = ? AND payload = ?
            """,
            (
                replacement.state.value,
                replacement.revision,
                canonical_json_bytes(replacement),
                current.permit_id,
                current.revision,
                canonical_json_bytes(current),
            ),
        )
        if cursor.rowcount != 1:
            raise PermitConflict(current.permit_id)

    @staticmethod
    def _append_permit_audit_locked(
        connection: sqlite3.Connection,
        event: PermitAuditEvent,
    ) -> None:
        connection.execute(
            """
            INSERT INTO action_permit_audits (
                permit_id, sequence, event_id, payload
            ) VALUES (?, ?, ?, ?)
            """,
            (
                event.permit_id,
                event.sequence,
                event.event_id,
                canonical_json_bytes(event),
            ),
        )

    async def issue_permit(self, permit: ActionPermit) -> ActionPermit:
        return await asyncio.to_thread(self._issue_permit, permit)

    def _issue_permit(self, permit: ActionPermit) -> ActionPermit:
        if type(permit) is not ActionPermit or (
            permit.state is not ActionPermitState.ISSUED
        ):
            raise TypeError("an exact issued action permit is required")
        try:
            with self._write() as connection:
                row = connection.execute(
                    "SELECT payload FROM action_permits WHERE permit_id = ?",
                    (permit.permit_id,),
                ).fetchone()
                if row is not None:
                    current = self._permit_locked(connection, permit.permit_id)
                    if canonical_json_bytes(current) != canonical_json_bytes(permit):
                        raise PermitConflict(permit.permit_id)
                    self._permit_audits_locked(connection, current)
                    return current
                connection.execute(
                    """
                    INSERT INTO action_permits (
                        permit_id, certificate_id, state, revision, payload
                    ) VALUES (?, ?, ?, ?, ?)
                    """,
                    (
                        permit.permit_id,
                        permit.certificate_id,
                        permit.state.value,
                        permit.revision,
                        canonical_json_bytes(permit),
                    ),
                )
                self._append_permit_audit_locked(
                    connection,
                    issued_audit_event(permit),
                )
                return permit
        except PermitStoreError:
            raise
        except sqlite3.DatabaseError as error:
            raise PermitCorruptState(permit.permit_id) from error

    async def get_permit(self, permit_id: str) -> ActionPermit:
        return await asyncio.to_thread(self._get_permit, permit_id)

    def _get_permit(self, permit_id: str) -> ActionPermit:
        try:
            with self._connect() as connection:
                permit = self._permit_locked(connection, permit_id)
                self._permit_audits_locked(connection, permit)
                return permit
        except PermitStoreError:
            raise
        except sqlite3.DatabaseError as error:
            raise PermitCorruptState(permit_id) from error

    async def claim_permit(self, request: PermitClaimRequest) -> ActionPermit:
        return await asyncio.to_thread(self._claim_permit, request)

    def _claim_permit(self, request: PermitClaimRequest) -> ActionPermit:
        if type(request) is not PermitClaimRequest:
            raise TypeError("permit claim request must be exact")
        try:
            with self._write() as connection:
                current = self._permit_locked(connection, request.permit_id)
                audits = self._permit_audits_locked(connection, current)
                mutation = evaluate_permit_claim(
                    current,
                    request,
                    audit_sequence=len(audits) + 1,
                )
                if mutation.permit != current:
                    self._replace_permit_locked(
                        connection,
                        current,
                        mutation.permit,
                    )
                self._append_permit_audit_locked(connection, mutation.event)
        except PermitStoreError:
            raise
        except sqlite3.DatabaseError as error:
            raise PermitCorruptState(request.permit_id) from error
        if mutation.denial_reason is not None:
            raise PermitClaimDenied(request.permit_id, mutation.denial_reason)
        return mutation.permit

    async def complete_permit(
        self,
        request: PermitCompletionRequest,
    ) -> ActionPermit:
        return await asyncio.to_thread(self._complete_permit, request)

    def _complete_permit(self, request: PermitCompletionRequest) -> ActionPermit:
        if type(request) is not PermitCompletionRequest:
            raise TypeError("permit completion request must be exact")
        try:
            with self._write() as connection:
                current = self._permit_locked(connection, request.permit_id)
                audits = self._permit_audits_locked(connection, current)
                mutation = evaluate_permit_completion(
                    current,
                    request,
                    audit_sequence=len(audits) + 1,
                )
                if mutation.permit != current:
                    self._replace_permit_locked(
                        connection,
                        current,
                        mutation.permit,
                    )
                self._append_permit_audit_locked(connection, mutation.event)
        except PermitStoreError:
            raise
        except (TypeError, ValueError, sqlite3.DatabaseError) as error:
            raise PermitCorruptState(request.permit_id) from error
        if mutation.denial_reason is not None:
            raise PermitCompletionDenied(request.permit_id, mutation.denial_reason)
        return mutation.permit

    async def permit_audit_events(
        self,
        permit_id: str,
    ) -> tuple[PermitAuditEvent, ...]:
        return await asyncio.to_thread(self._permit_audit_events, permit_id)

    def _permit_audit_events(
        self,
        permit_id: str,
    ) -> tuple[PermitAuditEvent, ...]:
        try:
            with self._connect() as connection:
                permit = self._permit_locked(connection, permit_id)
                return self._permit_audits_locked(connection, permit)
        except PermitStoreError:
            raise
        except sqlite3.DatabaseError as error:
            raise PermitCorruptState(permit_id) from error


DurableRuntimeExceptionTypes = (
    BudgetExceeded,
    ControllerAuditConflict,
    CorruptDurableState,
    DurableRunConflict,
    DurableRunNotFound,
    DurableStateConflict,
    DuplicateEvent,
    InvalidCursor,
    JournalCapacityExceeded,
    LeaseRenewalTooEarly,
    LeaseUnavailable,
    OutOfOrderEvent,
    ProbeCheckpointConflict,
    StaleLease,
    TerminalEventJournal,
    UnsupportedDurableSchema,
)


__all__ = ["SqliteDurableRuntimeStore"]
