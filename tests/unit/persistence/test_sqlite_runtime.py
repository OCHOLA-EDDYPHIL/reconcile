from __future__ import annotations

import asyncio
import sqlite3
from datetime import timedelta
from pathlib import Path

import pytest
from pydantic import ValidationError

from reconcile.contracts.api import (
    INVESTIGATION_EVENT_VERSION,
    InvestigationEvent,
    InvestigationEventType,
    LifecycleEventPayload,
)
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
from reconcile.persistence.durable import (
    RUNTIME_TELEMETRY_VERSION,
    BudgetExceeded,
    CleanupStatus,
    CorruptDurableState,
    DurableRunConflict,
    DurableRunState,
    DurableStateConflict,
    LeaseRenewalTooEarly,
    LeaseUnavailable,
    ProbeReplaySafety,
    ProbeResumeAction,
    RuntimeCostDelta,
    RuntimeTelemetryKind,
    RuntimeTelemetryRecord,
    StaleLease,
    runtime_limits_for,
)
from reconcile.persistence.events import DuplicateEvent, InvalidCursor
from reconcile.persistence.sqlite_runtime import SqliteDurableRuntimeStore
from tests.contract._factories import NOW, make_envelope, make_probe, make_report


def _store(path: Path) -> SqliteDurableRuntimeStore:
    return SqliteDurableRuntimeStore(path / "runtime.sqlite3")


def _limits(envelope: ExecutionEnvelope):
    return runtime_limits_for(
        envelope,
        started_at=NOW,
        max_provider_calls=2,
        max_estimated_cost_microunits=100,
    )


async def _created_store(
    path: Path,
) -> tuple[SqliteDurableRuntimeStore, ExecutionEnvelope]:
    store = _store(path)
    envelope = make_envelope()
    await store.create_run(envelope, created_at=NOW, limits=_limits(envelope))
    return store, envelope


def _observation(at=NOW + timedelta(seconds=2)) -> ProbeObservation:
    return ProbeObservation(
        observed_at=at,
        payload={"generation": 7, "status": "present"},
    )


def _audit(
    sequence: int,
    *,
    observed_at=NOW + timedelta(seconds=2),
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


@pytest.mark.unit
def test_create_is_exactly_idempotent_and_conflicting_reuse_fails(
    tmp_path: Path,
) -> None:
    async def scenario() -> None:
        store = _store(tmp_path)
        envelope = make_envelope()
        limits = _limits(envelope)

        first = await store.create_run(
            envelope,
            created_at=NOW,
            limits=limits,
        )
        replay = await store.create_run(
            envelope,
            created_at=NOW + timedelta(seconds=1),
            limits=limits,
        )

        assert first.created is True
        assert replay.created is False
        assert canonical_json_bytes(first.run) == canonical_json_bytes(replay.run)

        conflict = ExecutionEnvelope.model_validate(
            envelope.model_copy(update={"operation_id": "operation-conflict"})
        )
        with pytest.raises(DurableRunConflict):
            await store.create_run(
                conflict,
                created_at=NOW,
                limits=_limits(conflict),
            )

    asyncio.run(scenario())


@pytest.mark.unit
def test_leases_are_thirty_second_fenced_tokens_renewed_every_ten_seconds(
    tmp_path: Path,
) -> None:
    async def scenario() -> None:
        store, envelope = await _created_store(tmp_path)
        first = await store.acquire_lease(
            envelope.investigation_id,
            "worker-a",
            now=NOW,
        )
        replay = await store.acquire_lease(
            envelope.investigation_id,
            "worker-a",
            now=NOW + timedelta(seconds=1),
        )
        assert replay == first
        assert first.renew_after == NOW + timedelta(seconds=10)
        assert first.expires_at == NOW + timedelta(seconds=30)

        with pytest.raises(LeaseUnavailable):
            await store.acquire_lease(
                envelope.investigation_id,
                "worker-b",
                now=NOW + timedelta(seconds=9),
            )
        with pytest.raises(LeaseRenewalTooEarly):
            await store.renew_lease(first, now=NOW + timedelta(seconds=9))

        renewed = await store.renew_lease(first, now=NOW + timedelta(seconds=10))
        assert renewed.fence == first.fence
        assert renewed.expires_at == NOW + timedelta(seconds=40)
        with pytest.raises(StaleLease):
            await store.mark_active(first, occurred_at=NOW + timedelta(seconds=11))

        takeover = await store.acquire_lease(
            envelope.investigation_id,
            "worker-b",
            now=NOW + timedelta(seconds=40),
        )
        assert takeover.fence == first.fence + 1
        with pytest.raises(StaleLease):
            await store.mark_active(
                renewed,
                occurred_at=NOW + timedelta(seconds=40),
            )

    asyncio.run(scenario())


@pytest.mark.unit
def test_resume_reuses_recorded_reads_and_repeats_only_unfinished_safe_reads(
    tmp_path: Path,
) -> None:
    async def scenario() -> None:
        store, envelope = await _created_store(tmp_path)
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
        )
        audit, observation = _audit(1, observed_at=NOW + timedelta(seconds=1))
        recorded = await store.record_probe(
            lease,
            first.checkpoint_id,
            audit=audit,
            observation=observation,
            recorded_at=NOW + timedelta(milliseconds=1_100),
        )
        assert recorded.observation == observation

        await store.start_probe(
            lease,
            checkpoint_id="probe-2",
            step_sequence=2,
            request=request,
            replay_safety=ProbeReplaySafety.SAFE_READ,
            started_at=NOW + timedelta(seconds=2),
        )
        await store.start_probe(
            lease,
            checkpoint_id="probe-3",
            step_sequence=3,
            request=request,
            replay_safety=ProbeReplaySafety.UNKNOWN,
            started_at=NOW + timedelta(seconds=3),
        )

        plan = await store.resume_plan(
            envelope.investigation_id,
            now=NOW + timedelta(milliseconds=3_100),
        )
        assert tuple(item.action for item in plan.decisions) == (
            ProbeResumeAction.REUSE_RECORDED,
            ProbeResumeAction.REPEAT_SAFE_READ,
            ProbeResumeAction.ESCALATE,
        )
        assert plan.requires_escalation is True

        await store.release_lease(lease, now=NOW + timedelta(seconds=3))
        resumed = await store.acquire_lease(
            envelope.investigation_id,
            "worker-b",
            now=NOW + timedelta(milliseconds=3_100),
        )
        assert resumed.fence == lease.fence + 1
        escalated = await store.require_escalation(
            resumed,
            failure_code="unsafe-unrecorded-probe",
            occurred_at=NOW + timedelta(seconds=4),
        )
        assert escalated.state is DurableRunState.ESCALATION_REQUIRED

    asyncio.run(scenario())


@pytest.mark.unit
def test_event_cursor_and_exact_append_survive_reopening(tmp_path: Path) -> None:
    async def scenario() -> None:
        store, envelope = await _created_store(tmp_path)
        lease = await store.acquire_lease(
            envelope.investigation_id,
            "worker-a",
            now=NOW,
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
        assert await store.append_event(lease, event, now=NOW) == event

        reopened = _store(tmp_path)
        snapshot = await reopened.snapshot_events(envelope.investigation_id)
        assert snapshot.events == (event,)
        assert snapshot.cursor == 1
        assert snapshot.terminal is False
        assert (
            await reopened.snapshot_events(envelope.investigation_id, after=1)
        ).events == ()
        with pytest.raises(InvalidCursor):
            await reopened.snapshot_events(envelope.investigation_id, after=2)

        divergent = event.model_copy(update={"occurred_at": NOW + timedelta(seconds=1)})
        with pytest.raises(DuplicateEvent):
            await reopened.append_event(
                lease, divergent, now=NOW + timedelta(seconds=1)
            )

    asyncio.run(scenario())


@pytest.mark.unit
def test_cost_ledger_is_atomic_idempotent_and_enforces_every_ceiling(
    tmp_path: Path,
) -> None:
    async def scenario() -> None:
        store, envelope = await _created_store(tmp_path)
        lease = await store.acquire_lease(
            envelope.investigation_id,
            "worker-a",
            now=NOW,
        )
        delta = RuntimeCostDelta(
            provider_calls=1,
            probe_count=1,
            evidence_bytes=512,
            controller_cost_units=1,
            estimated_cost_microunits=40,
        )
        first = await store.charge(
            lease,
            entry_id="charge-1",
            category="provider-probe",
            occurred_at=NOW + timedelta(seconds=1),
            delta=delta,
        )
        replay = await store.charge(
            lease,
            entry_id="charge-1",
            category="provider-probe",
            occurred_at=NOW + timedelta(seconds=1),
            delta=delta,
        )
        assert first == replay
        assert first.entry_count == 1

        with pytest.raises(BudgetExceeded) as exhausted:
            await store.charge(
                lease,
                entry_id="charge-2",
                category="provider-probe",
                occurred_at=NOW + timedelta(seconds=2),
                delta=RuntimeCostDelta(provider_calls=2),
            )
        assert exhausted.value.dimension == "provider_calls"
        assert (await store.cost_snapshot(envelope.investigation_id)).entry_count == 1

        with pytest.raises(BudgetExceeded) as deadline:
            await store.charge(
                lease,
                entry_id="charge-deadline",
                category="provider-probe",
                occurred_at=NOW + timedelta(seconds=5),
                delta=RuntimeCostDelta(probe_count=1),
            )
        assert deadline.value.dimension == "deadline"

    asyncio.run(scenario())


@pytest.mark.unit
def test_cost_ledger_rejects_columns_that_diverge_from_canonical_entry(
    tmp_path: Path,
) -> None:
    async def scenario() -> None:
        store, envelope = await _created_store(tmp_path)
        lease = await store.acquire_lease(
            envelope.investigation_id,
            "worker-a",
            now=NOW,
        )
        await store.charge(
            lease,
            entry_id="charge-1",
            category="provider",
            occurred_at=NOW + timedelta(seconds=1),
            delta=RuntimeCostDelta(provider_calls=1),
        )
        with sqlite3.connect(tmp_path / "runtime.sqlite3") as connection:
            connection.execute(
                """
                UPDATE runtime_cost_entries
                SET provider_calls = 2
                WHERE investigation_id = ? AND entry_id = ?
                """,
                (envelope.investigation_id, "charge-1"),
            )

        with pytest.raises(CorruptDurableState):
            await store.cost_snapshot(envelope.investigation_id)

    asyncio.run(scenario())


@pytest.mark.unit
def test_cleanup_failure_is_separate_from_established_classification(
    tmp_path: Path,
) -> None:
    async def scenario() -> None:
        store, envelope = await _created_store(tmp_path)
        lease = await store.acquire_lease(
            envelope.investigation_id,
            "worker-a",
            now=NOW,
        )
        await store.mark_active(lease, occurred_at=NOW)
        request = make_probe()
        checkpoint = await store.start_probe(
            lease,
            checkpoint_id="probe-before-terminal",
            step_sequence=1,
            request=request,
            replay_safety=ProbeReplaySafety.SAFE_READ,
            started_at=NOW + timedelta(seconds=4),
        )
        report = make_report(Classification.COMMITTED)
        terminal = await store.establish_report(
            lease,
            report,
            occurred_at=NOW + timedelta(seconds=5),
        )
        assert terminal.classification is Classification.COMMITTED

        replayed_checkpoint = await store.start_probe(
            lease,
            checkpoint_id="probe-before-terminal",
            step_sequence=1,
            request=request,
            replay_safety=ProbeReplaySafety.SAFE_READ,
            started_at=NOW + timedelta(seconds=6),
        )
        assert replayed_checkpoint == checkpoint

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
        assert failed.cleanup_status is CleanupStatus.FAILED
        assert failed.classification is Classification.COMMITTED
        assert failed.established_report == report
        with pytest.raises(DurableStateConflict):
            await store.record_cleanup(
                lease,
                CleanupStatus.SUCCEEDED,
                occurred_at=NOW + timedelta(seconds=8),
            )

    asyncio.run(scenario())


@pytest.mark.unit
def test_structured_telemetry_is_secret_free_ordered_and_durable(
    tmp_path: Path,
) -> None:
    async def scenario() -> None:
        store, envelope = await _created_store(tmp_path)
        lease = await store.acquire_lease(
            envelope.investigation_id,
            "worker-a",
            now=NOW,
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
        await store.append_telemetry(
            lease,
            telemetry,
            now=NOW + timedelta(seconds=1),
        )
        reopened = _store(tmp_path)
        assert await reopened.telemetry_records(envelope.investigation_id) == (
            telemetry,
        )

        with pytest.raises(ValidationError, match="secret-bearing"):
            RuntimeTelemetryRecord(
                schema_version=RUNTIME_TELEMETRY_VERSION,
                investigation_id=envelope.investigation_id,
                telemetry_id="telemetry-2",
                sequence=2,
                kind=RuntimeTelemetryKind.RUN,
                occurred_at=NOW + timedelta(seconds=2),
                trace_id="trace-1",
                span_id="span-2",
                outcome="active",
                attributes={"access_token": "not-allowed"},
            )

    asyncio.run(scenario())


@pytest.mark.unit
def test_corrupt_persisted_payload_fails_closed(tmp_path: Path) -> None:
    async def scenario() -> None:
        store, envelope = await _created_store(tmp_path)
        database = tmp_path / "runtime.sqlite3"
        with sqlite3.connect(database) as connection:
            connection.execute(
                """
                UPDATE durable_runs
                SET payload = ?
                WHERE investigation_id = ?
                """,
                (b"{}", envelope.investigation_id),
            )
        with pytest.raises(CorruptDurableState):
            await store.get_run(envelope.investigation_id)

    asyncio.run(scenario())
