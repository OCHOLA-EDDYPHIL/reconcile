from __future__ import annotations

import asyncio
from datetime import timedelta
from pathlib import Path

import pytest

from reconcile.contracts.api import (
    INVESTIGATION_EVENT_VERSION,
    InvestigationEvent,
    InvestigationEventType,
    LifecycleEventPayload,
)
from reconcile.contracts.codec import canonical_json_bytes, canonical_sha256
from reconcile.contracts.common import Classification
from reconcile.contracts.report import InvestigationStatus, ProbeOutcome
from reconcile.controller import (
    ControllerAuditRecord,
    ProbeObservation,
    ProbeStopReason,
    probe_request_sha256,
)
from reconcile.persistence.durable import (
    CleanupStatus,
    ProbeReplaySafety,
    ProbeResumeAction,
    RuntimeCostDelta,
    StaleLease,
    runtime_limits_for,
)
from reconcile.persistence.sqlite_runtime import SqliteDurableRuntimeStore
from tests.contract._factories import NOW, make_envelope, make_probe, make_report


def _recorded_read(sequence: int, completed_at):
    request = make_probe()
    observation = ProbeObservation(
        observed_at=completed_at,
        payload={"generation": sequence, "status": "present"},
    )
    encoded = canonical_json_bytes(observation)
    audit = ControllerAuditRecord(
        sequence=sequence,
        capability_name=request.capability_name,
        capability_version=request.capability_version,
        request_sha256=probe_request_sha256(request),
        target_sha256=canonical_sha256(make_envelope().target),
        outcome=ProbeOutcome.COMPLETED,
        stop_reason=ProbeStopReason.PROBE_COMPLETED,
        started_at=completed_at - timedelta(milliseconds=100),
        completed_at=completed_at,
        session_elapsed_ms=100,
        probe_count_used=sequence,
        cost_units_used=sequence,
        result_bytes_acquired=len(encoded),
        result_sha256=canonical_sha256(observation),
        result_byte_count=len(encoded),
    )
    return audit, observation


@pytest.mark.integration
def test_reopen_resumes_without_repeating_recorded_reads_and_preserves_result(
    tmp_path: Path,
) -> None:
    async def scenario() -> None:
        database = tmp_path / "runtime.sqlite3"
        envelope = make_envelope()
        limits = runtime_limits_for(
            envelope,
            started_at=NOW,
            max_provider_calls=2,
            max_estimated_cost_microunits=100,
        )
        first_process = SqliteDurableRuntimeStore(database)
        await first_process.create_run(
            envelope,
            created_at=NOW,
            limits=limits,
        )
        first_lease = await first_process.acquire_lease(
            envelope.investigation_id,
            "worker-first",
            now=NOW,
        )
        await first_process.mark_active(first_lease, occurred_at=NOW)
        await first_process.append_event(
            first_lease,
            InvestigationEvent(
                schema_version=INVESTIGATION_EVENT_VERSION,
                investigation_id=envelope.investigation_id,
                sequence=1,
                type=InvestigationEventType.LIFECYCLE,
                occurred_at=NOW,
                payload=LifecycleEventPayload(status=InvestigationStatus.CREATED),
            ),
            now=NOW,
        )

        request = make_probe()
        first_checkpoint = await first_process.start_probe(
            first_lease,
            checkpoint_id="read-1",
            step_sequence=1,
            request=request,
            replay_safety=ProbeReplaySafety.SAFE_READ,
            started_at=NOW + timedelta(milliseconds=500),
        )
        first_audit, first_observation = _recorded_read(
            1,
            NOW + timedelta(seconds=1),
        )
        await first_process.record_probe(
            first_lease,
            first_checkpoint.checkpoint_id,
            audit=first_audit,
            observation=first_observation,
            recorded_at=NOW + timedelta(milliseconds=1_100),
        )
        await first_process.charge(
            first_lease,
            entry_id="read-1-cost",
            category="probe-read",
            occurred_at=NOW + timedelta(milliseconds=1_200),
            delta=RuntimeCostDelta(
                probe_count=1,
                evidence_bytes=len(canonical_json_bytes(first_observation)),
                controller_cost_units=1,
            ),
        )
        await first_process.start_probe(
            first_lease,
            checkpoint_id="read-2",
            step_sequence=2,
            request=request,
            replay_safety=ProbeReplaySafety.SAFE_READ,
            started_at=NOW + timedelta(seconds=2),
        )
        await first_process.release_lease(
            first_lease,
            now=NOW + timedelta(milliseconds=2_100),
        )

        second_process = SqliteDurableRuntimeStore(database)
        second_lease = await second_process.acquire_lease(
            envelope.investigation_id,
            "worker-second",
            now=NOW + timedelta(milliseconds=2_200),
        )
        assert second_lease.fence == first_lease.fence + 1
        plan = await second_process.resume_plan(
            envelope.investigation_id,
            now=NOW + timedelta(milliseconds=2_200),
        )
        assert tuple(item.action for item in plan.decisions) == (
            ProbeResumeAction.REUSE_RECORDED,
            ProbeResumeAction.REPEAT_SAFE_READ,
        )
        with pytest.raises(StaleLease):
            await first_process.start_probe(
                first_lease,
                checkpoint_id="stale-read",
                step_sequence=3,
                request=request,
                replay_safety=ProbeReplaySafety.SAFE_READ,
                started_at=NOW + timedelta(milliseconds=2_300),
            )

        second_audit, second_observation = _recorded_read(
            2,
            NOW + timedelta(seconds=3),
        )
        await second_process.record_probe(
            second_lease,
            "read-2",
            audit=second_audit,
            observation=second_observation,
            recorded_at=NOW + timedelta(milliseconds=3_100),
        )
        await second_process.charge(
            second_lease,
            entry_id="read-2-cost",
            category="probe-read",
            occurred_at=NOW + timedelta(milliseconds=3_200),
            delta=RuntimeCostDelta(
                probe_count=1,
                evidence_bytes=len(canonical_json_bytes(second_observation)),
                controller_cost_units=1,
            ),
        )
        report = make_report(Classification.COMMITTED)
        await second_process.establish_report(
            second_lease,
            report,
            occurred_at=NOW + timedelta(seconds=5),
        )
        await second_process.record_cleanup(
            second_lease,
            CleanupStatus.FAILED,
            occurred_at=NOW + timedelta(seconds=6),
            failure_code="owned-resource-remains",
        )

        third_process = SqliteDurableRuntimeStore(database)
        final = await third_process.get_run(envelope.investigation_id)
        assert final.classification is Classification.COMMITTED
        assert final.established_report == report
        assert final.cleanup_status is CleanupStatus.FAILED
        assert tuple(
            item.action
            for item in (
                await third_process.resume_plan(
                    envelope.investigation_id,
                    now=NOW + timedelta(seconds=7),
                )
            ).decisions
        ) == (
            ProbeResumeAction.REUSE_RECORDED,
            ProbeResumeAction.REUSE_RECORDED,
        )
        assert (
            await third_process.cost_snapshot(envelope.investigation_id)
        ).entry_count == 2
        assert (
            await third_process.snapshot_events(envelope.investigation_id)
        ).cursor == 1

    asyncio.run(scenario())


@pytest.mark.integration
def test_expired_deadline_escalates_unrecorded_safe_read_after_crash(
    tmp_path: Path,
) -> None:
    async def scenario() -> None:
        database = tmp_path / "runtime.sqlite3"
        envelope = make_envelope()
        store = SqliteDurableRuntimeStore(database)
        await store.create_run(
            envelope,
            created_at=NOW,
            limits=runtime_limits_for(
                envelope,
                started_at=NOW,
                max_provider_calls=1,
                max_estimated_cost_microunits=50,
            ),
        )
        lease = await store.acquire_lease(
            envelope.investigation_id,
            "worker-crashed",
            now=NOW,
        )
        await store.mark_active(lease, occurred_at=NOW)
        await store.start_probe(
            lease,
            checkpoint_id="read-unrecorded",
            step_sequence=1,
            request=make_probe(),
            replay_safety=ProbeReplaySafety.SAFE_READ,
            started_at=NOW + timedelta(seconds=1),
        )

        restarted = SqliteDurableRuntimeStore(database)
        takeover = await restarted.acquire_lease(
            envelope.investigation_id,
            "worker-restarted",
            now=NOW + timedelta(seconds=30),
        )
        assert takeover.fence == lease.fence + 1
        plan = await restarted.resume_plan(
            envelope.investigation_id,
            now=NOW + timedelta(seconds=30),
        )
        assert plan.requires_escalation is True
        assert plan.decisions[0].action is ProbeResumeAction.ESCALATE

    asyncio.run(scenario())
