"""Single-aggregate durable runtime authority for hosted Firestore execution."""

from __future__ import annotations

import asyncio
import re
from datetime import UTC, datetime
from typing import Literal, Protocol, runtime_checkable

from pydantic import Field, model_validator

from reconcile.contracts.api import (
    MAX_INVESTIGATION_EVENTS,
    InvestigationEvent,
    InvestigationEventType,
    LifecycleEventPayload,
)
from reconcile.contracts.base import Sha256Digest, StrictModel
from reconcile.contracts.codec import (
    ContractError,
    canonical_json_bytes,
    canonical_sha256,
    decode_contract,
)
from reconcile.contracts.envelope import ExecutionEnvelope, ProbeRequest
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
from reconcile.hosted.firestore_cas import (
    FirestoreCasCollection,
    FirestoreCasConflict,
    FirestoreCasCorruptDocument,
    FirestoreCasDocument,
    FirestoreCasError,
    FirestoreCasOutcomeUnknown,
    FirestoreCasProviderUnavailable,
    FirestoreCasSnapshot,
    GoogleFirestoreCasStore,
    build_firestore_cas_document,
    new_firestore_cas_mutation_id,
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
    DurableRuntimeError,
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

FIRESTORE_DURABLE_RUNTIME_AGGREGATE_VERSION = (
    "reconcile/firestore-durable-runtime-aggregate/v1"
)

_DIGEST = re.compile(r"[0-9a-f]{64}")
_MAX_SIGNED_64 = 2**63 - 1


def _aware_utc(value: datetime) -> datetime:
    if (
        not isinstance(value, datetime)
        or value.tzinfo is None
        or value.utcoffset() is None
    ):
        raise ValueError("durable runtime timestamps must be timezone-aware")
    return value.astimezone(UTC)


def _terminal_event(event: InvestigationEvent) -> bool:
    return (
        event.type is InvestigationEventType.LIFECYCLE
        and isinstance(event.payload, LifecycleEventPayload)
        and event.payload.status is InvestigationStatus.COMPLETED
    )


class FirestoreDurableRuntimeAggregate(StrictModel):
    """Canonical state needed to resume one exact hosted investigation."""

    schema_version: Literal[FIRESTORE_DURABLE_RUNTIME_AGGREGATE_VERSION]
    run: DurableRunRecord
    runtime_provenance_sha256: Sha256Digest
    lease_fence: int = Field(ge=0, le=_MAX_SIGNED_64)
    current_lease: LeaseToken | None = None
    checkpoints: tuple[ProbeCheckpoint, ...] = ()
    controller_audits: tuple[ControllerAuditRecord, ...] = ()
    events: tuple[InvestigationEvent, ...] = ()
    telemetry: tuple[RuntimeTelemetryRecord, ...] = ()
    cost_entries: tuple[CostLedgerEntry, ...] = ()

    @model_validator(mode="after")
    def validate_aggregate(self) -> FirestoreDurableRuntimeAggregate:
        investigation_id = self.run.investigation_id
        if self.current_lease is not None and (
            self.current_lease.investigation_id != investigation_id
            or self.current_lease.fence != self.lease_fence
        ):
            raise ValueError("runtime lease does not match its aggregate")
        if self.current_lease is None and self.lease_fence < 0:
            raise ValueError("runtime lease fence is invalid")

        checkpoint_ids: set[str] = set()
        previous_sequence = 0
        for checkpoint in self.checkpoints:
            if (
                checkpoint.investigation_id != investigation_id
                or checkpoint.checkpoint_id in checkpoint_ids
                or checkpoint.step_sequence <= previous_sequence
                or checkpoint.step_sequence > self.run.limits.max_probe_count
            ):
                raise ValueError("runtime checkpoints are invalid")
            checkpoint_ids.add(checkpoint.checkpoint_id)
            previous_sequence = checkpoint.step_sequence

        budget = self.run.envelope.context.evidence_budget
        target_sha256 = canonical_sha256(self.run.envelope.target)
        for expected, audit in enumerate(self.controller_audits, 1):
            if (
                audit.sequence != expected
                or audit.started_at < self.run.created_at
                or audit.target_sha256 != target_sha256
                or audit.probe_count_used > self.run.limits.max_probe_count
                or audit.cost_units_used > self.run.limits.max_controller_cost_units
                or audit.result_bytes_acquired > self.run.limits.max_evidence_bytes
                or audit.session_elapsed_ms > budget.max_elapsed_ms
            ):
                raise ValueError("runtime controller audits are invalid")

        if len(self.events) > MAX_INVESTIGATION_EVENTS:
            raise ValueError("runtime event journal exceeds its bound")
        for expected, event in enumerate(self.events, 1):
            terminal = _terminal_event(event)
            if (
                event.investigation_id != investigation_id
                or event.sequence != expected
                or (terminal and expected != len(self.events))
            ):
                raise ValueError("runtime event journal is invalid")

        telemetry_ids: set[str] = set()
        for expected, record in enumerate(self.telemetry, 1):
            if (
                record.investigation_id != investigation_id
                or record.telemetry_id in telemetry_ids
                or record.sequence != expected
            ):
                raise ValueError("runtime telemetry journal is invalid")
            telemetry_ids.add(record.telemetry_id)

        entry_ids: set[str] = set()
        totals = {
            "provider_calls": 0,
            "probe_count": 0,
            "evidence_bytes": 0,
            "controller_cost_units": 0,
            "estimated_cost_microunits": 0,
        }
        for expected, entry in enumerate(self.cost_entries, 1):
            if (
                entry.investigation_id != investigation_id
                or entry.entry_id in entry_ids
                or entry.sequence != expected
            ):
                raise ValueError("runtime cost ledger is invalid")
            entry_ids.add(entry.entry_id)
            for dimension in totals:
                totals[dimension] += getattr(entry.delta, dimension)
        limits = self.run.limits
        ceilings = {
            "provider_calls": limits.max_provider_calls,
            "probe_count": limits.max_probe_count,
            "evidence_bytes": limits.max_evidence_bytes,
            "controller_cost_units": limits.max_controller_cost_units,
            "estimated_cost_microunits": limits.max_estimated_cost_microunits,
        }
        if any(totals[name] > ceilings[name] for name in totals):
            raise ValueError("runtime cost ledger exceeds its limits")
        return self


@runtime_checkable
class _FirestoreCasStore(Protocol):
    async def read(
        self,
        collection: FirestoreCasCollection,
        logical_id: str,
    ) -> FirestoreCasSnapshot | None: ...

    async def create(
        self,
        document: FirestoreCasDocument,
    ) -> FirestoreCasSnapshot: ...

    async def update(
        self,
        current: FirestoreCasSnapshot,
        replacement: FirestoreCasDocument,
    ) -> FirestoreCasSnapshot: ...


def _rebuild_aggregate(
    aggregate: FirestoreDurableRuntimeAggregate,
    **updates: object,
) -> FirestoreDurableRuntimeAggregate:
    candidate = aggregate.model_copy(update=updates)
    return decode_contract(
        canonical_json_bytes(candidate),
        FirestoreDurableRuntimeAggregate,
    )


def _rebuild_run(run: DurableRunRecord, **updates: object) -> DurableRunRecord:
    candidate = run.model_copy(update=updates)
    return decode_contract(canonical_json_bytes(candidate), DurableRunRecord)


class FirestoreDurableRuntimeStore:
    """DurableRuntimeStore backed by one revisioned aggregate per run."""

    def __init__(
        self,
        *,
        project_id: str,
        cas_store: _FirestoreCasStore | None = None,
    ) -> None:
        if cas_store is not None and not isinstance(cas_store, _FirestoreCasStore):
            raise TypeError("Firestore runtime CAS store is incomplete")
        self._cas: _FirestoreCasStore = cas_store or GoogleFirestoreCasStore(
            project_id=project_id
        )

    @staticmethod
    def _decode_snapshot(
        snapshot: FirestoreCasSnapshot,
        investigation_id: str,
    ) -> FirestoreDurableRuntimeAggregate:
        try:
            if (
                type(snapshot) is not FirestoreCasSnapshot
                or snapshot.collection is not FirestoreCasCollection.RUNTIME
                or snapshot.document.logical_id != investigation_id
            ):
                raise ValueError("runtime CAS snapshot identity is invalid")
            aggregate = decode_contract(
                snapshot.document.payload_bytes,
                FirestoreDurableRuntimeAggregate,
            )
            if (
                canonical_json_bytes(aggregate) != snapshot.document.payload_bytes
                or aggregate.run.investigation_id != investigation_id
                or aggregate.run.revision > snapshot.document.revision
            ):
                raise ValueError("runtime aggregate does not match its CAS wrapper")
            return aggregate
        except (ContractError, TypeError, ValueError):
            raise CorruptDurableState(investigation_id) from None

    @staticmethod
    def _unavailable(operation: str) -> DurableRuntimeError:
        return DurableRuntimeError(f"durable runtime {operation} is unavailable")

    async def _read_optional(
        self,
        investigation_id: str,
    ) -> tuple[FirestoreCasSnapshot, FirestoreDurableRuntimeAggregate] | None:
        try:
            snapshot = await self._cas.read(
                FirestoreCasCollection.RUNTIME,
                investigation_id,
            )
        except asyncio.CancelledError:
            raise
        except FirestoreCasCorruptDocument:
            raise CorruptDurableState(investigation_id) from None
        except FirestoreCasError:
            raise self._unavailable("read") from None
        if snapshot is None:
            return None
        return snapshot, self._decode_snapshot(snapshot, investigation_id)

    async def _read(
        self,
        investigation_id: str,
    ) -> tuple[FirestoreCasSnapshot, FirestoreDurableRuntimeAggregate]:
        current = await self._read_optional(investigation_id)
        if current is None:
            raise DurableRunNotFound(investigation_id)
        return current

    async def _create_aggregate(
        self,
        aggregate: FirestoreDurableRuntimeAggregate,
    ) -> FirestoreDurableRuntimeAggregate:
        investigation_id = aggregate.run.investigation_id
        document = build_firestore_cas_document(
            collection=FirestoreCasCollection.RUNTIME,
            logical_id=investigation_id,
            revision=0,
            mutation_id=new_firestore_cas_mutation_id(),
            canonical_payload=canonical_json_bytes(aggregate),
        )
        try:
            snapshot = await self._cas.create(document)
        except asyncio.CancelledError:
            raise
        except FirestoreCasConflict:
            raise DurableRunConflict(investigation_id) from None
        except FirestoreCasCorruptDocument:
            raise CorruptDurableState(investigation_id) from None
        except (FirestoreCasOutcomeUnknown, FirestoreCasProviderUnavailable):
            raise self._unavailable("create") from None
        if type(snapshot) is not FirestoreCasSnapshot or snapshot.document != document:
            raise CorruptDurableState(investigation_id)
        return self._decode_snapshot(snapshot, investigation_id)

    async def _update_aggregate(
        self,
        snapshot: FirestoreCasSnapshot,
        aggregate: FirestoreDurableRuntimeAggregate,
        *,
        operation: str,
        conflict: DurableRuntimeError,
    ) -> FirestoreDurableRuntimeAggregate:
        investigation_id = aggregate.run.investigation_id
        try:
            document = build_firestore_cas_document(
                collection=FirestoreCasCollection.RUNTIME,
                logical_id=investigation_id,
                revision=snapshot.document.revision + 1,
                mutation_id=new_firestore_cas_mutation_id(),
                canonical_payload=canonical_json_bytes(aggregate),
            )
        except (ContractError, TypeError, ValueError):
            raise DurableStateConflict(investigation_id, operation) from None
        try:
            updated = await self._cas.update(snapshot, document)
        except asyncio.CancelledError:
            raise
        except FirestoreCasConflict:
            raise conflict from None
        except FirestoreCasCorruptDocument:
            raise CorruptDurableState(investigation_id) from None
        except (FirestoreCasOutcomeUnknown, FirestoreCasProviderUnavailable):
            raise self._unavailable(operation) from None
        if type(updated) is not FirestoreCasSnapshot or updated.document != document:
            raise CorruptDurableState(investigation_id)
        return self._decode_snapshot(updated, investigation_id)

    @staticmethod
    def _validated_lease(
        aggregate: FirestoreDurableRuntimeAggregate,
        lease: LeaseToken,
        now: datetime,
    ) -> LeaseToken:
        now = _aware_utc(now)
        current = aggregate.current_lease
        if (
            current is None
            or canonical_json_bytes(current) != canonical_json_bytes(lease)
            or now < current.renewed_at
            or current.expired(now)
        ):
            raise StaleLease(lease.investigation_id)
        return current

    @staticmethod
    def _cost_snapshot(
        aggregate: FirestoreDurableRuntimeAggregate,
    ) -> CostLedgerSnapshot:
        totals = {
            "provider_calls": 0,
            "probe_count": 0,
            "evidence_bytes": 0,
            "controller_cost_units": 0,
            "estimated_cost_microunits": 0,
        }
        for entry in aggregate.cost_entries:
            for dimension in totals:
                totals[dimension] += getattr(entry.delta, dimension)
        try:
            return CostLedgerSnapshot(
                schema_version=COST_LEDGER_SNAPSHOT_VERSION,
                investigation_id=aggregate.run.investigation_id,
                entry_count=len(aggregate.cost_entries),
                limits=aggregate.run.limits,
                **totals,
            )
        except (TypeError, ValueError):
            raise CorruptDurableState(aggregate.run.investigation_id) from None

    async def create_run(
        self,
        envelope: ExecutionEnvelope,
        *,
        created_at: datetime,
        limits: RuntimeLimits,
        runtime_provenance_sha256: str,
    ) -> CreateDurableRunResult:
        created_at = _aware_utc(created_at)
        if (
            type(runtime_provenance_sha256) is not str
            or _DIGEST.fullmatch(runtime_provenance_sha256) is None
        ):
            raise ValueError("runtime provenance must be a SHA-256 digest")
        run = DurableRunRecord(
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
        current = await self._read_optional(run.investigation_id)
        if current is not None:
            aggregate = current[1]
            if canonical_json_bytes(aggregate.run.envelope) != canonical_json_bytes(
                run.envelope
            ):
                raise DurableRunConflict(run.investigation_id)
            return CreateDurableRunResult(run=aggregate.run, created=False)
        aggregate = FirestoreDurableRuntimeAggregate(
            schema_version=FIRESTORE_DURABLE_RUNTIME_AGGREGATE_VERSION,
            run=run,
            runtime_provenance_sha256=runtime_provenance_sha256,
            lease_fence=0,
        )
        try:
            created = await self._create_aggregate(aggregate)
        except DurableRunConflict:
            concurrent = await self._read_optional(run.investigation_id)
            if concurrent is None:
                raise DurableRunConflict(run.investigation_id) from None
            current_run = concurrent[1].run
            if canonical_json_bytes(current_run.envelope) != canonical_json_bytes(
                run.envelope
            ):
                raise DurableRunConflict(run.investigation_id) from None
            return CreateDurableRunResult(run=current_run, created=False)
        return CreateDurableRunResult(run=created.run, created=True)

    async def get_run(self, investigation_id: str) -> DurableRunRecord:
        return (await self._read(investigation_id))[1].run

    async def list_runs(self) -> tuple[DurableRunRecord, ...]:
        raise DurableRuntimeError("durable runtime enumeration is unavailable")

    async def runtime_provenance_sha256(self, investigation_id: str) -> str:
        return (await self._read(investigation_id))[1].runtime_provenance_sha256

    async def acquire_lease(
        self,
        investigation_id: str,
        owner_id: str,
        *,
        now: datetime,
    ) -> LeaseToken:
        now = _aware_utc(now)
        snapshot, aggregate = await self._read(investigation_id)
        current = aggregate.current_lease
        if current is not None and not current.expired(now):
            if current.owner_id == owner_id:
                return current
            raise LeaseUnavailable(investigation_id)
        lease = LeaseToken(
            schema_version=DURABLE_LEASE_VERSION,
            investigation_id=investigation_id,
            owner_id=owner_id,
            fence=aggregate.lease_fence + 1,
            acquired_at=now,
            renewed_at=now,
            renew_after=now + LEASE_RENEWAL_INTERVAL,
            expires_at=now + LEASE_DURATION,
        )
        replacement = _rebuild_aggregate(
            aggregate,
            lease_fence=lease.fence,
            current_lease=lease,
        )
        updated = await self._update_aggregate(
            snapshot,
            replacement,
            operation="acquire_lease",
            conflict=LeaseUnavailable(investigation_id),
        )
        if updated.current_lease is None:
            raise CorruptDurableState(investigation_id)
        return updated.current_lease

    async def renew_lease(
        self,
        lease: LeaseToken,
        *,
        now: datetime,
    ) -> LeaseToken:
        now = _aware_utc(now)
        snapshot, aggregate = await self._read(lease.investigation_id)
        current = self._validated_lease(aggregate, lease, now)
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
        replacement = _rebuild_aggregate(aggregate, current_lease=renewed)
        updated = await self._update_aggregate(
            snapshot,
            replacement,
            operation="renew_lease",
            conflict=StaleLease(lease.investigation_id),
        )
        if updated.current_lease is None:
            raise CorruptDurableState(lease.investigation_id)
        return updated.current_lease

    async def validate_lease(
        self,
        lease: LeaseToken,
        *,
        now: datetime,
    ) -> None:
        aggregate = (await self._read(lease.investigation_id))[1]
        self._validated_lease(aggregate, lease, now)

    async def release_lease(
        self,
        lease: LeaseToken,
        *,
        now: datetime,
    ) -> None:
        snapshot, aggregate = await self._read(lease.investigation_id)
        self._validated_lease(aggregate, lease, now)
        replacement = _rebuild_aggregate(aggregate, current_lease=None)
        await self._update_aggregate(
            snapshot,
            replacement,
            operation="release_lease",
            conflict=StaleLease(lease.investigation_id),
        )

    async def mark_active(
        self,
        lease: LeaseToken,
        *,
        occurred_at: datetime,
    ) -> DurableRunRecord:
        occurred_at = _aware_utc(occurred_at)
        snapshot, aggregate = await self._read(lease.investigation_id)
        self._validated_lease(aggregate, lease, occurred_at)
        run = aggregate.run
        if run.state is DurableRunState.ACTIVE:
            return run
        if run.state is not DurableRunState.CREATED:
            raise DurableStateConflict(run.investigation_id, "mark_active")
        active = _rebuild_run(
            run,
            state=DurableRunState.ACTIVE,
            updated_at=max(run.updated_at, occurred_at),
            revision=run.revision + 1,
        )
        replacement = _rebuild_aggregate(aggregate, run=active)
        return (
            await self._update_aggregate(
                snapshot,
                replacement,
                operation="mark_active",
                conflict=DurableStateConflict(run.investigation_id, "mark_active"),
            )
        ).run

    async def require_escalation(
        self,
        lease: LeaseToken,
        *,
        failure_code: str,
        occurred_at: datetime,
    ) -> DurableRunRecord:
        occurred_at = _aware_utc(occurred_at)
        snapshot, aggregate = await self._read(lease.investigation_id)
        self._validated_lease(aggregate, lease, occurred_at)
        run = aggregate.run
        if run.state is DurableRunState.ESCALATION_REQUIRED:
            if run.recovery_failure_code == failure_code:
                return run
            raise DurableStateConflict(run.investigation_id, "escalate")
        if run.state is DurableRunState.TERMINAL:
            raise DurableStateConflict(run.investigation_id, "escalate")
        escalated = _rebuild_run(
            run,
            state=DurableRunState.ESCALATION_REQUIRED,
            recovery_failure_code=failure_code,
            updated_at=max(run.updated_at, occurred_at),
            revision=run.revision + 1,
        )
        replacement = _rebuild_aggregate(aggregate, run=escalated)
        return (
            await self._update_aggregate(
                snapshot,
                replacement,
                operation="escalate",
                conflict=DurableStateConflict(run.investigation_id, "escalate"),
            )
        ).run

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
        snapshot, aggregate = await self._read(lease.investigation_id)
        self._validated_lease(aggregate, lease, now)
        for current in aggregate.checkpoints:
            if current.checkpoint_id == checkpoint_id:
                if (
                    current.step_sequence == checkpoint.step_sequence
                    and current.request_sha256 == checkpoint.request_sha256
                    and current.replay_safety is checkpoint.replay_safety
                ):
                    return current
                raise ProbeCheckpointConflict(lease.investigation_id, checkpoint_id)
            if current.step_sequence == step_sequence:
                raise ProbeCheckpointConflict(lease.investigation_id, checkpoint_id)
        run = aggregate.run
        if run.state is not DurableRunState.ACTIVE:
            raise DurableStateConflict(run.investigation_id, "start_probe")
        if now >= run.limits.deadline_at:
            raise BudgetExceeded(run.investigation_id, "deadline")
        previous_sequence = (
            aggregate.checkpoints[-1].step_sequence if aggregate.checkpoints else 0
        )
        if (
            step_sequence <= previous_sequence
            or step_sequence > run.limits.max_probe_count
        ):
            raise ProbeCheckpointConflict(lease.investigation_id, checkpoint_id)
        replacement = _rebuild_aggregate(
            aggregate,
            checkpoints=(*aggregate.checkpoints, checkpoint),
        )
        updated = await self._update_aggregate(
            snapshot,
            replacement,
            operation="start_probe",
            conflict=ProbeCheckpointConflict(lease.investigation_id, checkpoint_id),
        )
        return updated.checkpoints[-1]

    async def record_probe(
        self,
        lease: LeaseToken,
        checkpoint_id: str,
        *,
        audit: ControllerAuditRecord,
        observation: ProbeObservation | None,
        recorded_at: datetime,
    ) -> ProbeCheckpoint:
        recorded_at = _aware_utc(recorded_at)
        snapshot, aggregate = await self._read(lease.investigation_id)
        self._validated_lease(aggregate, lease, recorded_at)
        index = next(
            (
                index
                for index, checkpoint in enumerate(aggregate.checkpoints)
                if checkpoint.checkpoint_id == checkpoint_id
            ),
            None,
        )
        if index is None:
            raise ProbeCheckpointConflict(lease.investigation_id, checkpoint_id)
        current = aggregate.checkpoints[index]
        if current.replay_safety is not ProbeReplaySafety.SAFE_READ:
            raise ProbeCheckpointConflict(lease.investigation_id, checkpoint_id)
        if current.state is ProbeCheckpointState.RECORDED:
            if canonical_json_bytes(current.audit) == canonical_json_bytes(audit) and (
                (current.observation is None and observation is None)
                or (
                    current.observation is not None
                    and observation is not None
                    and canonical_json_bytes(current.observation)
                    == canonical_json_bytes(observation)
                )
            ):
                return current
            raise ProbeCheckpointConflict(lease.investigation_id, checkpoint_id)
        run = aggregate.run
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
        checkpoints = list(aggregate.checkpoints)
        checkpoints[index] = recorded
        replacement = _rebuild_aggregate(
            aggregate,
            checkpoints=tuple(checkpoints),
        )
        updated = await self._update_aggregate(
            snapshot,
            replacement,
            operation="record_probe",
            conflict=ProbeCheckpointConflict(lease.investigation_id, checkpoint_id),
        )
        return updated.checkpoints[index]

    async def record_controller_audit(
        self,
        lease: LeaseToken,
        audit: ControllerAuditRecord,
        *,
        recorded_at: datetime,
    ) -> ControllerAuditRecord:
        if type(audit) is not ControllerAuditRecord:
            raise TypeError("controller audit must be exact")
        audit = ControllerAuditRecord.model_validate_json(canonical_json_bytes(audit))
        recorded_at = _aware_utc(recorded_at)
        snapshot, aggregate = await self._read(lease.investigation_id)
        self._validated_lease(aggregate, lease, recorded_at)
        if audit.sequence <= len(aggregate.controller_audits):
            current = aggregate.controller_audits[audit.sequence - 1]
            if canonical_json_bytes(current) == canonical_json_bytes(audit):
                return current
            raise ControllerAuditConflict(lease.investigation_id, audit.sequence)
        run = aggregate.run
        budget = run.envelope.context.evidence_budget
        if (
            run.state is not DurableRunState.ACTIVE
            or audit.sequence != len(aggregate.controller_audits) + 1
            or audit.started_at < run.created_at
            or recorded_at < audit.completed_at
            or audit.target_sha256 != canonical_sha256(run.envelope.target)
            or audit.probe_count_used > run.limits.max_probe_count
            or audit.cost_units_used > run.limits.max_controller_cost_units
            or audit.result_bytes_acquired > run.limits.max_evidence_bytes
            or audit.session_elapsed_ms > budget.max_elapsed_ms
        ):
            if run.state is not DurableRunState.ACTIVE:
                raise DurableStateConflict(
                    run.investigation_id,
                    "record_controller_audit",
                )
            raise ControllerAuditConflict(lease.investigation_id, audit.sequence)
        replacement = _rebuild_aggregate(
            aggregate,
            controller_audits=(*aggregate.controller_audits, audit),
        )
        updated = await self._update_aggregate(
            snapshot,
            replacement,
            operation="record_controller_audit",
            conflict=ControllerAuditConflict(lease.investigation_id, audit.sequence),
        )
        return updated.controller_audits[-1]

    async def controller_audits(
        self,
        investigation_id: str,
    ) -> tuple[ControllerAuditRecord, ...]:
        return (await self._read(investigation_id))[1].controller_audits

    async def resume_plan(
        self,
        investigation_id: str,
        *,
        now: datetime,
    ) -> ProbeResumePlan:
        now = _aware_utc(now)
        aggregate = (await self._read(investigation_id))[1]
        return build_probe_resume_plan(
            investigation_id,
            aggregate.checkpoints,
            repeat_safe_reads=(
                aggregate.run.state is DurableRunState.ACTIVE
                and now < aggregate.run.limits.deadline_at
            ),
        )

    async def probe_checkpoints(
        self,
        investigation_id: str,
    ) -> tuple[ProbeCheckpoint, ...]:
        return (await self._read(investigation_id))[1].checkpoints

    async def append_event(
        self,
        lease: LeaseToken,
        event: InvestigationEvent,
        *,
        now: datetime,
    ) -> InvestigationEvent:
        now = _aware_utc(now)
        payload = canonical_json_bytes(event)
        validated = decode_contract(payload, InvestigationEvent)
        if validated.investigation_id != lease.investigation_id:
            raise DurableStateConflict(lease.investigation_id, "append_event")
        snapshot, aggregate = await self._read(lease.investigation_id)
        self._validated_lease(aggregate, lease, now)
        latest = len(aggregate.events)
        if validated.sequence <= latest:
            current = aggregate.events[validated.sequence - 1]
            if canonical_json_bytes(current) == payload:
                return current
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
        if aggregate.events and _terminal_event(aggregate.events[-1]):
            raise TerminalEventJournal(lease.investigation_id)
        replacement = _rebuild_aggregate(
            aggregate,
            events=(*aggregate.events, validated),
        )
        updated = await self._update_aggregate(
            snapshot,
            replacement,
            operation="append_event",
            conflict=DurableStateConflict(lease.investigation_id, "append_event"),
        )
        return updated.events[-1]

    async def snapshot_events(
        self,
        investigation_id: str,
        *,
        after: int = 0,
    ) -> EventJournalSnapshot:
        events = (await self._read(investigation_id))[1].events
        latest = len(events)
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
            terminal=bool(events and _terminal_event(events[-1])),
        )

    async def establish_report(
        self,
        lease: LeaseToken,
        report: InvestigationReport,
        *,
        occurred_at: datetime,
    ) -> DurableRunRecord:
        occurred_at = _aware_utc(occurred_at)
        snapshot, aggregate = await self._read(lease.investigation_id)
        self._validated_lease(aggregate, lease, occurred_at)
        run = aggregate.run
        if run.established_report is not None:
            if canonical_json_bytes(run.established_report) == canonical_json_bytes(
                report
            ):
                return run
            raise DurableStateConflict(run.investigation_id, "establish_report")
        if run.state is not DurableRunState.ACTIVE:
            raise DurableStateConflict(run.investigation_id, "establish_report")
        terminal = _rebuild_run(
            run,
            state=DurableRunState.TERMINAL,
            established_report=report,
            updated_at=max(run.updated_at, occurred_at, report.updated_at),
            revision=run.revision + 1,
        )
        replacement = _rebuild_aggregate(aggregate, run=terminal)
        return (
            await self._update_aggregate(
                snapshot,
                replacement,
                operation="establish_report",
                conflict=DurableStateConflict(
                    run.investigation_id,
                    "establish_report",
                ),
            )
        ).run

    async def record_cleanup(
        self,
        lease: LeaseToken,
        status: CleanupStatus,
        *,
        occurred_at: datetime,
        failure_code: str | None = None,
    ) -> DurableRunRecord:
        occurred_at = _aware_utc(occurred_at)
        if status is CleanupStatus.NOT_REQUESTED:
            raise ValueError("cleanup recording requires an attempted status")
        snapshot, aggregate = await self._read(lease.investigation_id)
        self._validated_lease(aggregate, lease, occurred_at)
        run = aggregate.run
        if run.cleanup_status in {CleanupStatus.SUCCEEDED, CleanupStatus.FAILED}:
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
        updated_run = _rebuild_run(
            run,
            cleanup_status=status,
            cleanup_failure_code=failure_code,
            updated_at=max(run.updated_at, occurred_at),
            revision=run.revision + 1,
        )
        replacement = _rebuild_aggregate(aggregate, run=updated_run)
        return (
            await self._update_aggregate(
                snapshot,
                replacement,
                operation="record_cleanup",
                conflict=DurableStateConflict(
                    run.investigation_id,
                    "record_cleanup",
                ),
            )
        ).run

    async def append_telemetry(
        self,
        lease: LeaseToken,
        record: RuntimeTelemetryRecord,
        *,
        now: datetime,
    ) -> RuntimeTelemetryRecord:
        now = _aware_utc(now)
        payload = canonical_json_bytes(record)
        if record.investigation_id != lease.investigation_id:
            raise DurableStateConflict(lease.investigation_id, "append_telemetry")
        snapshot, aggregate = await self._read(lease.investigation_id)
        self._validated_lease(aggregate, lease, now)
        for current in aggregate.telemetry:
            if current.telemetry_id != record.telemetry_id:
                continue
            if canonical_json_bytes(current) == payload:
                return current
            raise DurableStateConflict(record.investigation_id, "append_telemetry")
        if record.sequence != len(aggregate.telemetry) + 1:
            raise DurableStateConflict(record.investigation_id, "append_telemetry")
        replacement = _rebuild_aggregate(
            aggregate,
            telemetry=(*aggregate.telemetry, record),
        )
        updated = await self._update_aggregate(
            snapshot,
            replacement,
            operation="append_telemetry",
            conflict=DurableStateConflict(
                record.investigation_id,
                "append_telemetry",
            ),
        )
        return updated.telemetry[-1]

    async def telemetry_records(
        self,
        investigation_id: str,
    ) -> tuple[RuntimeTelemetryRecord, ...]:
        return (await self._read(investigation_id))[1].telemetry

    async def charge(
        self,
        lease: LeaseToken,
        *,
        entry_id: str,
        category: str,
        occurred_at: datetime,
        delta: RuntimeCostDelta,
    ) -> CostLedgerSnapshot:
        return await self._charge(
            lease,
            entry_id=entry_id,
            category=category,
            occurred_at=occurred_at,
            delta=delta,
            allow_replay=True,
        )

    async def reserve_provider_call(
        self,
        lease: LeaseToken,
        *,
        call_id: str,
        occurred_at: datetime,
        estimated_cost_microunits: int,
    ) -> CostLedgerSnapshot:
        return await self._charge(
            lease,
            entry_id=f"provider-{call_id}",
            category="advisory-provider-reservation",
            occurred_at=occurred_at,
            delta=RuntimeCostDelta(
                provider_calls=1,
                estimated_cost_microunits=estimated_cost_microunits,
            ),
            allow_replay=False,
        )

    async def _charge(
        self,
        lease: LeaseToken,
        *,
        entry_id: str,
        category: str,
        occurred_at: datetime,
        delta: RuntimeCostDelta,
        allow_replay: bool,
    ) -> CostLedgerSnapshot:
        occurred_at = _aware_utc(occurred_at)
        snapshot, aggregate = await self._read(lease.investigation_id)
        self._validated_lease(aggregate, lease, occurred_at)
        current_snapshot = self._cost_snapshot(aggregate)
        for entry in aggregate.cost_entries:
            if entry.entry_id != entry_id:
                continue
            if allow_replay and entry.category == category and entry.delta == delta:
                return current_snapshot
            operation = "charge" if allow_replay else "reserve_provider_call"
            raise DurableStateConflict(aggregate.run.investigation_id, operation)
        run = aggregate.run
        if occurred_at >= run.limits.deadline_at:
            raise BudgetExceeded(run.investigation_id, "deadline")
        proposed = {
            "provider_calls": current_snapshot.provider_calls + delta.provider_calls,
            "probe_count": current_snapshot.probe_count + delta.probe_count,
            "evidence_bytes": current_snapshot.evidence_bytes + delta.evidence_bytes,
            "controller_cost_units": (
                current_snapshot.controller_cost_units + delta.controller_cost_units
            ),
            "estimated_cost_microunits": (
                current_snapshot.estimated_cost_microunits
                + delta.estimated_cost_microunits
            ),
        }
        ceilings = {
            "provider_calls": run.limits.max_provider_calls,
            "probe_count": run.limits.max_probe_count,
            "evidence_bytes": run.limits.max_evidence_bytes,
            "controller_cost_units": run.limits.max_controller_cost_units,
            "estimated_cost_microunits": run.limits.max_estimated_cost_microunits,
        }
        for dimension, total in proposed.items():
            if total > ceilings[dimension]:
                raise BudgetExceeded(run.investigation_id, dimension)
        entry = CostLedgerEntry(
            schema_version=COST_LEDGER_ENTRY_VERSION,
            investigation_id=run.investigation_id,
            entry_id=entry_id,
            sequence=len(aggregate.cost_entries) + 1,
            category=category,
            occurred_at=occurred_at,
            delta=delta,
        )
        replacement = _rebuild_aggregate(
            aggregate,
            cost_entries=(*aggregate.cost_entries, entry),
        )
        operation = "charge" if allow_replay else "reserve_provider_call"
        updated = await self._update_aggregate(
            snapshot,
            replacement,
            operation=operation,
            conflict=DurableStateConflict(run.investigation_id, operation),
        )
        return self._cost_snapshot(updated)

    async def provider_call_receipts(
        self,
        investigation_id: str,
    ) -> tuple[ProviderCallReceipt, ...]:
        aggregate = (await self._read(investigation_id))[1]
        self._cost_snapshot(aggregate)
        receipts: list[ProviderCallReceipt] = []
        for entry in aggregate.cost_entries:
            if entry.category != "advisory-provider-reservation":
                continue
            call_id = entry.entry_id.removeprefix("provider-")
            if (
                not entry.entry_id.startswith("provider-")
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
                    estimated_cost_microunits=(entry.delta.estimated_cost_microunits),
                )
            )
        return tuple(receipts)

    async def cost_snapshot(self, investigation_id: str) -> CostLedgerSnapshot:
        return self._cost_snapshot((await self._read(investigation_id))[1])


__all__ = [
    "FIRESTORE_DURABLE_RUNTIME_AGGREGATE_VERSION",
    "FirestoreDurableRuntimeAggregate",
    "FirestoreDurableRuntimeStore",
]
