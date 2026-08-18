"""Hosted Firestore durable-runtime aggregate behavior."""

from __future__ import annotations

import asyncio
import json
from datetime import UTC, datetime, timedelta

import pytest

from reconcile.contracts.api import (
    INVESTIGATION_EVENT_VERSION,
    InvestigationEvent,
    InvestigationEventType,
    LifecycleEventPayload,
)
from reconcile.contracts.base import canonical_json_value_bytes
from reconcile.contracts.codec import canonical_json_bytes, canonical_sha256
from reconcile.contracts.common import Classification
from reconcile.contracts.envelope import ExecutionEnvelope
from reconcile.contracts.report import InvestigationStatus, ProbeOutcome
from reconcile.controller import (
    ControllerAuditRecord,
    ProbeObservation,
    ProbeStopReason,
    probe_request_sha256,
)
from reconcile.hosted.firestore_cas import (
    FirestoreCasCollection,
    FirestoreCasConflict,
    FirestoreCasDocument,
    FirestoreCasOutcomeUnknown,
    FirestoreCasProviderUnavailable,
    FirestoreCasSnapshot,
    build_firestore_cas_document,
    firestore_cas_document_key,
    new_firestore_cas_mutation_id,
)
from reconcile.hosted.firestore_runtime import (
    FirestoreDurableRuntimeAggregate,
    FirestoreDurableRuntimeStore,
)
from reconcile.persistence.durable import (
    RUNTIME_TELEMETRY_VERSION,
    BudgetExceeded,
    CleanupStatus,
    ControllerAuditConflict,
    CorruptDurableState,
    DurableRunConflict,
    DurableRunState,
    DurableRuntimeError,
    DurableStateConflict,
    LeaseRenewalTooEarly,
    LeaseUnavailable,
    ProbeCheckpointConflict,
    ProbeReplaySafety,
    ProbeResumeAction,
    RuntimeCostDelta,
    RuntimeTelemetryKind,
    RuntimeTelemetryRecord,
    StaleLease,
    runtime_limits_for,
)
from reconcile.persistence.events import DuplicateEvent, InvalidCursor
from tests.contract._factories import NOW, make_envelope, make_probe, make_report

pytestmark = pytest.mark.unit

_PROJECT = "test-project"
_PROVENANCE = "f" * 64


class _MemoryCas:
    def __init__(self, *, synchronize_creates: int = 0) -> None:
        self.documents: dict[str, FirestoreCasSnapshot] = {}
        self.read_calls: list[tuple[FirestoreCasCollection, str]] = []
        self.create_calls: list[FirestoreCasDocument] = []
        self.update_calls: list[tuple[FirestoreCasSnapshot, FirestoreCasDocument]] = []
        self.history: list[FirestoreCasDocument] = []
        self.read_failures: list[BaseException] = []
        self.create_failures: list[BaseException] = []
        self.update_failures: list[BaseException] = []
        self.clock = datetime(2026, 8, 18, 12, 0, tzinfo=UTC)
        self._create_target = synchronize_creates
        self._create_waiters = 0
        self._create_gate = asyncio.Event()

    def _snapshot(self, document: FirestoreCasDocument) -> FirestoreCasSnapshot:
        snapshot = FirestoreCasSnapshot(
            collection=document.kind,
            document_key=firestore_cas_document_key(
                document.kind,
                document.logical_id,
            ),
            document=document,
            update_time=self.clock,
        )
        self.clock += timedelta(microseconds=1)
        return snapshot

    async def read(
        self,
        collection: FirestoreCasCollection,
        logical_id: str,
    ) -> FirestoreCasSnapshot | None:
        self.read_calls.append((collection, logical_id))
        if self.read_failures:
            raise self.read_failures.pop(0)
        return self.documents.get(logical_id)

    async def create(
        self,
        document: FirestoreCasDocument,
    ) -> FirestoreCasSnapshot:
        self.create_calls.append(document)
        if self._create_target:
            self._create_waiters += 1
            if self._create_waiters == self._create_target:
                self._create_gate.set()
            await self._create_gate.wait()
        if self.create_failures:
            raise self.create_failures.pop(0)
        if document.logical_id in self.documents:
            raise FirestoreCasConflict
        snapshot = self._snapshot(document)
        self.documents[document.logical_id] = snapshot
        self.history.append(document)
        return snapshot

    async def update(
        self,
        current: FirestoreCasSnapshot,
        replacement: FirestoreCasDocument,
    ) -> FirestoreCasSnapshot:
        self.update_calls.append((current, replacement))
        if self.update_failures:
            raise self.update_failures.pop(0)
        stored = self.documents.get(replacement.logical_id)
        if (
            stored != current
            or replacement.revision != current.document.revision + 1
            or replacement.mutation_id == current.document.mutation_id
        ):
            raise FirestoreCasConflict
        snapshot = self._snapshot(replacement)
        self.documents[replacement.logical_id] = snapshot
        self.history.append(replacement)
        return snapshot

    def force(self, document: FirestoreCasDocument) -> None:
        self.documents[document.logical_id] = self._snapshot(document)


def _store(cas: _MemoryCas) -> FirestoreDurableRuntimeStore:
    return FirestoreDurableRuntimeStore(project_id=_PROJECT, cas_store=cas)


def _limits(envelope: ExecutionEnvelope):
    return runtime_limits_for(
        envelope,
        started_at=NOW,
        max_provider_calls=2,
        max_estimated_cost_microunits=100,
    )


async def _created(
    cas: _MemoryCas,
) -> tuple[FirestoreDurableRuntimeStore, ExecutionEnvelope]:
    store = _store(cas)
    envelope = make_envelope()
    await store.create_run(
        envelope,
        created_at=NOW,
        limits=_limits(envelope),
        runtime_provenance_sha256=_PROVENANCE,
    )
    return store, envelope


def _observation(at: datetime) -> ProbeObservation:
    return ProbeObservation(
        observed_at=at,
        payload={"generation": 7, "status": "present"},
    )


def _audit(
    sequence: int,
    *,
    observed_at: datetime,
) -> tuple[ControllerAuditRecord, ProbeObservation]:
    request = make_probe()
    observation = _observation(observed_at)
    payload = canonical_json_bytes(observation)
    return (
        ControllerAuditRecord(
            sequence=sequence,
            capability_name=request.capability_name,
            capability_version=request.capability_version,
            request_sha256=probe_request_sha256(request),
            target_sha256=canonical_sha256(make_envelope().target),
            outcome=ProbeOutcome.COMPLETED,
            stop_reason=ProbeStopReason.PROBE_COMPLETED,
            started_at=observed_at - timedelta(milliseconds=200),
            completed_at=observed_at,
            session_elapsed_ms=200,
            probe_count_used=sequence,
            cost_units_used=sequence,
            result_bytes_acquired=len(payload),
            result_sha256=canonical_sha256(observation),
            result_byte_count=len(payload),
        ),
        observation,
    )


def test_create_is_canonical_targeted_and_exactly_idempotent() -> None:
    async def scenario() -> None:
        cas = _MemoryCas()
        store, envelope = await _created(cas)
        replay = await _store(cas).create_run(
            envelope,
            created_at=NOW + timedelta(seconds=1),
            limits=_limits(envelope),
            runtime_provenance_sha256="e" * 64,
        )

        assert replay.created is False
        assert replay.run == await _store(cas).get_run(envelope.investigation_id)
        assert (
            await _store(cas).runtime_provenance_sha256(envelope.investigation_id)
        ) == _PROVENANCE
        assert len(cas.create_calls) == 1
        document = cas.history[0]
        aggregate = FirestoreDurableRuntimeAggregate.model_validate_json(
            document.payload_bytes
        )
        assert canonical_json_bytes(aggregate) == document.payload_bytes
        assert aggregate.run == replay.run

        conflict = ExecutionEnvelope.model_validate(
            envelope.model_copy(update={"operation_id": "operation-conflict"})
        )
        with pytest.raises(DurableRunConflict):
            await store.create_run(
                conflict,
                created_at=NOW,
                limits=_limits(conflict),
                runtime_provenance_sha256=_PROVENANCE,
            )
        reads_before = len(cas.read_calls)
        with pytest.raises(DurableRuntimeError, match="enumeration is unavailable"):
            await store.list_runs()
        assert len(cas.read_calls) == reads_before

    asyncio.run(scenario())


def test_concurrent_exact_create_has_one_create_and_one_replay() -> None:
    async def scenario() -> None:
        cas = _MemoryCas(synchronize_creates=2)
        envelope = make_envelope()

        results = await asyncio.gather(
            *(
                _store(cas).create_run(
                    envelope,
                    created_at=NOW,
                    limits=_limits(envelope),
                    runtime_provenance_sha256=_PROVENANCE,
                )
                for _ in range(2)
            )
        )

        assert sorted(result.created for result in results) == [False, True]
        assert results[0].run == results[1].run
        assert len(cas.create_calls) == 2
        assert len(cas.history) == 1

    asyncio.run(scenario())


def test_leases_retain_fences_and_each_mutation_is_one_fresh_cas_revision() -> None:
    async def scenario() -> None:
        cas = _MemoryCas()
        store, envelope = await _created(cas)
        first = await store.acquire_lease(
            envelope.investigation_id,
            "worker-a",
            now=NOW,
        )
        update_count = len(cas.update_calls)
        assert (
            await _store(cas).acquire_lease(
                envelope.investigation_id,
                "worker-a",
                now=NOW + timedelta(seconds=1),
            )
            == first
        )
        assert len(cas.update_calls) == update_count
        with pytest.raises(LeaseUnavailable):
            await store.acquire_lease(
                envelope.investigation_id,
                "worker-b",
                now=NOW + timedelta(seconds=2),
            )
        with pytest.raises(LeaseRenewalTooEarly):
            await store.renew_lease(first, now=NOW + timedelta(seconds=9))

        renewed = await store.renew_lease(first, now=NOW + timedelta(seconds=10))
        await _store(cas).validate_lease(renewed, now=NOW + timedelta(seconds=11))
        with pytest.raises(StaleLease):
            await store.validate_lease(first, now=NOW + timedelta(seconds=11))
        takeover = await _store(cas).acquire_lease(
            envelope.investigation_id,
            "worker-b",
            now=NOW + timedelta(seconds=40),
        )
        assert takeover.fence == first.fence + 1
        await store.release_lease(takeover, now=NOW + timedelta(seconds=41))
        next_owner = await store.acquire_lease(
            envelope.investigation_id,
            "worker-c",
            now=NOW + timedelta(seconds=42),
        )
        assert next_owner.fence == takeover.fence + 1

        revisions = tuple(document.revision for document in cas.history)
        mutation_ids = tuple(document.mutation_id for document in cas.history)
        assert revisions == tuple(range(len(revisions)))
        assert len(mutation_ids) == len(set(mutation_ids))

    asyncio.run(scenario())


def test_resume_reuses_recorded_reads_and_only_repeats_live_safe_reads() -> None:
    async def scenario() -> None:
        cas = _MemoryCas()
        store, envelope = await _created(cas)
        lease = await store.acquire_lease(
            envelope.investigation_id,
            "worker-a",
            now=NOW,
        )
        await store.mark_active(lease, occurred_at=NOW)
        request = make_probe()
        first = await store.start_probe(
            lease,
            checkpoint_id="probe-1",
            step_sequence=1,
            request=request,
            replay_safety=ProbeReplaySafety.SAFE_READ,
            started_at=NOW + timedelta(milliseconds=500),
            now=NOW + timedelta(milliseconds=500),
        )
        audit, observation = _audit(
            1,
            observed_at=NOW + timedelta(seconds=1),
        )
        recorded = await store.record_probe(
            lease,
            first.checkpoint_id,
            audit=audit,
            observation=observation,
            recorded_at=NOW + timedelta(milliseconds=1_100),
        )
        replay = await _store(cas).record_probe(
            lease,
            first.checkpoint_id,
            audit=audit,
            observation=observation,
            recorded_at=NOW + timedelta(milliseconds=1_200),
        )
        assert replay == recorded
        await store.start_probe(
            lease,
            checkpoint_id="probe-2",
            step_sequence=2,
            request=request,
            replay_safety=ProbeReplaySafety.SAFE_READ,
            started_at=NOW + timedelta(seconds=2),
            now=NOW + timedelta(seconds=2),
        )
        await store.start_probe(
            lease,
            checkpoint_id="probe-3",
            step_sequence=3,
            request=request,
            replay_safety=ProbeReplaySafety.UNKNOWN,
            started_at=NOW + timedelta(seconds=3),
            now=NOW + timedelta(seconds=3),
        )

        fresh = _store(cas)
        plan = await fresh.resume_plan(
            envelope.investigation_id,
            now=NOW + timedelta(milliseconds=3_100),
        )
        assert tuple(item.action for item in plan.decisions) == (
            ProbeResumeAction.REUSE_RECORDED,
            ProbeResumeAction.REPEAT_SAFE_READ,
            ProbeResumeAction.ESCALATE,
        )
        expired = await fresh.resume_plan(
            envelope.investigation_id,
            now=NOW + timedelta(seconds=5),
        )
        assert tuple(item.action for item in expired.decisions) == (
            ProbeResumeAction.REUSE_RECORDED,
            ProbeResumeAction.ESCALATE,
            ProbeResumeAction.ESCALATE,
        )
        checkpoints = await store.probe_checkpoints(envelope.investigation_id)
        assert await fresh.probe_checkpoints(envelope.investigation_id) == (
            recorded,
            *checkpoints[1:],
        )
        with pytest.raises(ProbeCheckpointConflict):
            await store.record_probe(
                lease,
                "probe-3",
                audit=audit,
                observation=observation,
                recorded_at=NOW + timedelta(seconds=3),
            )

        await store.release_lease(lease, now=NOW + timedelta(seconds=3))
        resumed = await store.acquire_lease(
            envelope.investigation_id,
            "worker-b",
            now=NOW + timedelta(milliseconds=3_100),
        )
        escalated = await store.require_escalation(
            resumed,
            failure_code="unsafe-unrecorded-probe",
            occurred_at=NOW + timedelta(seconds=4),
        )
        assert escalated.state is DurableRunState.ESCALATION_REQUIRED

    asyncio.run(scenario())


def test_audits_events_and_telemetry_survive_fresh_store_instances() -> None:
    async def scenario() -> None:
        cas = _MemoryCas()
        store, envelope = await _created(cas)
        lease = await store.acquire_lease(
            envelope.investigation_id,
            "worker-a",
            now=NOW,
        )
        await store.mark_active(lease, occurred_at=NOW)
        audit, _ = _audit(1, observed_at=NOW + timedelta(seconds=1))
        assert (
            await store.record_controller_audit(
                lease,
                audit,
                recorded_at=NOW + timedelta(milliseconds=1_100),
            )
            == audit
        )
        assert await _store(cas).controller_audits(envelope.investigation_id) == (
            audit,
        )
        with pytest.raises(ControllerAuditConflict):
            await store.record_controller_audit(
                lease,
                audit.model_copy(update={"session_elapsed_ms": 201}),
                recorded_at=NOW + timedelta(milliseconds=1_200),
            )

        event = InvestigationEvent(
            schema_version=INVESTIGATION_EVENT_VERSION,
            investigation_id=envelope.investigation_id,
            sequence=1,
            type=InvestigationEventType.LIFECYCLE,
            occurred_at=NOW,
            payload=LifecycleEventPayload(status=InvestigationStatus.CREATED),
        )
        assert await store.append_event(lease, event, now=NOW) == event
        assert await _store(cas).append_event(lease, event, now=NOW) == event
        snapshot = await _store(cas).snapshot_events(envelope.investigation_id)
        assert snapshot.events == (event,)
        assert snapshot.cursor == 1
        assert snapshot.terminal is False
        with pytest.raises(InvalidCursor):
            await store.snapshot_events(envelope.investigation_id, after=2)
        with pytest.raises(DuplicateEvent):
            await store.append_event(
                lease,
                event.model_copy(update={"occurred_at": NOW + timedelta(seconds=1)}),
                now=NOW + timedelta(seconds=1),
            )

        telemetry = RuntimeTelemetryRecord(
            schema_version=RUNTIME_TELEMETRY_VERSION,
            investigation_id=envelope.investigation_id,
            telemetry_id="telemetry-1",
            sequence=1,
            kind=RuntimeTelemetryKind.PROBE,
            occurred_at=NOW + timedelta(seconds=1),
            trace_id="trace-1",
            span_id="span-1",
            outcome="completed",
            probe_sequence=1,
            attributes={"capability": "gcs-object-readback"},
        )
        assert (
            await store.append_telemetry(
                lease,
                telemetry,
                now=NOW + timedelta(seconds=1),
            )
            == telemetry
        )
        assert await _store(cas).telemetry_records(envelope.investigation_id) == (
            telemetry,
        )

    asyncio.run(scenario())


def test_cost_provider_report_and_cleanup_authority_are_preserved() -> None:
    async def scenario() -> None:
        cas = _MemoryCas()
        store, envelope = await _created(cas)
        lease = await store.acquire_lease(
            envelope.investigation_id,
            "worker-a",
            now=NOW,
        )
        await store.mark_active(lease, occurred_at=NOW)
        delta = RuntimeCostDelta(
            probe_count=1,
            evidence_bytes=512,
            controller_cost_units=1,
        )
        first = await store.charge(
            lease,
            entry_id="charge-1",
            category="fixed-probe",
            occurred_at=NOW + timedelta(seconds=1),
            delta=delta,
        )
        replay = await _store(cas).charge(
            lease,
            entry_id="charge-1",
            category="fixed-probe",
            occurred_at=NOW + timedelta(seconds=2),
            delta=delta,
        )
        assert replay == first
        reserved = await store.reserve_provider_call(
            lease,
            call_id="turn-1",
            occurred_at=NOW + timedelta(seconds=2),
            estimated_cost_microunits=40,
        )
        assert reserved.provider_calls == 1
        with pytest.raises(DurableStateConflict):
            await _store(cas).reserve_provider_call(
                lease,
                call_id="turn-1",
                occurred_at=NOW + timedelta(seconds=3),
                estimated_cost_microunits=40,
            )
        receipts = await _store(cas).provider_call_receipts(envelope.investigation_id)
        assert tuple((item.order, item.call_id) for item in receipts) == (
            (1, "turn-1"),
        )
        assert (
            await _store(cas).cost_snapshot(envelope.investigation_id)
        ).entry_count == 2
        with pytest.raises(BudgetExceeded) as exhausted:
            await store.charge(
                lease,
                entry_id="charge-over",
                category="fixed-probe",
                occurred_at=NOW + timedelta(seconds=3),
                delta=RuntimeCostDelta(probe_count=3),
            )
        assert exhausted.value.dimension == "probe_count"
        with pytest.raises(BudgetExceeded) as deadline:
            await store.charge(
                lease,
                entry_id="charge-late",
                category="fixed-probe",
                occurred_at=NOW + timedelta(seconds=5),
                delta=RuntimeCostDelta(probe_count=1),
            )
        assert deadline.value.dimension == "deadline"

        report = make_report(Classification.COMMITTED)
        terminal = await store.establish_report(
            lease,
            report,
            occurred_at=NOW + timedelta(seconds=4),
        )
        assert terminal.classification is Classification.COMMITTED
        assert (
            await _store(cas).establish_report(
                lease,
                report,
                occurred_at=NOW + timedelta(seconds=5),
            )
            == terminal
        )
        await store.record_cleanup(
            lease,
            CleanupStatus.PENDING,
            occurred_at=NOW + timedelta(seconds=6),
        )
        failed = await store.record_cleanup(
            lease,
            CleanupStatus.FAILED,
            occurred_at=NOW + timedelta(seconds=7),
            failure_code="owned-resource-remains",
        )
        assert failed.classification is Classification.COMMITTED
        assert failed.cleanup_status is CleanupStatus.FAILED

    asyncio.run(scenario())


def test_cas_failures_are_sanitized_never_retried_and_cancellation_propagates() -> None:
    async def scenario() -> None:
        cas = _MemoryCas()
        store, envelope = await _created(cas)
        lease = await store.acquire_lease(
            envelope.investigation_id,
            "worker-a",
            now=NOW,
        )

        cas.update_failures.append(FirestoreCasConflict())
        before = len(cas.update_calls)
        with pytest.raises(DurableStateConflict):
            await store.mark_active(lease, occurred_at=NOW)
        assert len(cas.update_calls) == before + 1

        cas.update_failures.append(FirestoreCasOutcomeUnknown())
        before = len(cas.update_calls)
        with pytest.raises(DurableRuntimeError) as unavailable:
            await store.mark_active(lease, occurred_at=NOW)
        assert "provider" not in str(unavailable.value)
        assert len(cas.update_calls) == before + 1

        cas.read_failures.append(FirestoreCasProviderUnavailable())
        with pytest.raises(DurableRuntimeError) as read_unavailable:
            await store.get_run(envelope.investigation_id)
        assert "provider" not in str(read_unavailable.value)

        cas.read_failures.append(asyncio.CancelledError())
        with pytest.raises(asyncio.CancelledError):
            await store.get_run(envelope.investigation_id)

        current = cas.documents[envelope.investigation_id]
        payload = json.loads(current.document.canonical_payload)
        payload["unexpected"] = True
        corrupt = build_firestore_cas_document(
            collection=FirestoreCasCollection.RUNTIME,
            logical_id=envelope.investigation_id,
            revision=current.document.revision + 1,
            mutation_id=new_firestore_cas_mutation_id(),
            canonical_payload=canonical_json_value_bytes(payload),
        )
        cas.force(corrupt)
        with pytest.raises(CorruptDurableState):
            await _store(cas).get_run(envelope.investigation_id)

    asyncio.run(scenario())
