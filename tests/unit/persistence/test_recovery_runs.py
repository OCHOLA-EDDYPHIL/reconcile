"""Durable recovery-run aggregate and launch-authority guarantees."""

from __future__ import annotations

import asyncio
from datetime import timedelta

import pytest

from reconcile.contracts import (
    RecoveryDispatchOutcome,
    RecoveryLaunchPermitState,
    RecoveryNodeProgress,
    RecoveryNodeState,
    RecoveryRunEventPayload,
    RecoveryRunEventType,
    RecoveryRunLifecycle,
)
from reconcile.persistence import (
    InMemoryRecoveryRunStore,
    RecoveryLaunchClaimDenied,
    RecoveryRunConflict,
    SqliteRecoveryRunStore,
)
from tests.contract._factories import NOW, make_recovery_run_examples

pytestmark = pytest.mark.unit


def test_sqlite_recovery_run_replays_append_only_state_after_restart(tmp_path) -> None:
    request, _event, launch, _snapshot, _scope = make_recovery_run_examples()
    chain = make_recovery_run_examples()[3].chain
    database = tmp_path / "recovery.sqlite3"

    async def exercise() -> None:
        store = SqliteRecoveryRunStore(database)
        snapshot, created = await store.create(request, chain, created_at=NOW)
        assert created is True
        snapshot = await store.append(
            request.run_id,
            expected_revision=snapshot.revision,
            event_type=RecoveryRunEventType.LIFECYCLE,
            payload=RecoveryRunEventPayload(lifecycle=RecoveryRunLifecycle.RUNNING),
            occurred_at=NOW + timedelta(seconds=1),
        )
        snapshot = await store.append(
            request.run_id,
            expected_revision=snapshot.revision,
            event_type=RecoveryRunEventType.LAUNCH_PERMIT,
            payload=RecoveryRunEventPayload(launch_permit=launch),
            occurred_at=NOW + timedelta(seconds=2),
        )
        snapshot = await store.append(
            request.run_id,
            expected_revision=snapshot.revision,
            event_type=RecoveryRunEventType.NODE,
            payload=RecoveryRunEventPayload(
                node=RecoveryNodeProgress(
                    node_id=chain.nodes[0].node_id,
                    state=RecoveryNodeState.DISPATCH_PENDING,
                    attempt=1,
                )
            ),
            occurred_at=NOW + timedelta(seconds=3),
        )
        claimed = await store.claim_launch(
            request.run_id,
            launch_permit_id=launch.launch_permit_id,
            claim_id="claim-launch-7",
            action_request_sha256=launch.action_request_sha256,
            claimed_at=NOW + timedelta(seconds=4),
        )
        assert claimed.state is RecoveryLaunchPermitState.CLAIMED
        completed = await store.complete_launch(
            request.run_id,
            launch_permit_id=launch.launch_permit_id,
            claim_id="claim-launch-7",
            outcome=RecoveryDispatchOutcome.OUTCOME_UNKNOWN,
            completed_at=NOW + timedelta(seconds=5),
        )
        assert completed.state is RecoveryLaunchPermitState.COMPLETED

        reopened = SqliteRecoveryRunStore(database)
        restored = await reopened.get(request.run_id)
        events = await reopened.events(request.run_id)
        assert restored.launch_permit == completed
        assert restored.event_cursor == events.cursor == 7
        assert tuple(event.cursor for event in events.events) == tuple(range(1, 8))
        assert canonical_event_types(events.events) == (
            "LIFECYCLE",
            "CHAIN",
            "LIFECYCLE",
            "LAUNCH_PERMIT",
            "NODE",
            "LAUNCH_PERMIT",
            "LAUNCH_PERMIT",
        )

    asyncio.run(exercise())


def canonical_event_types(events) -> tuple[str, ...]:
    return tuple(event.type.value for event in events)


def test_launch_permit_has_one_atomic_winner_under_concurrency() -> None:
    request, _event, launch, snapshot, _scope = make_recovery_run_examples()

    async def exercise() -> None:
        store = InMemoryRecoveryRunStore()
        current, _created = await store.create(request, snapshot.chain, created_at=NOW)
        current = await store.append(
            request.run_id,
            expected_revision=current.revision,
            event_type=RecoveryRunEventType.LIFECYCLE,
            payload=RecoveryRunEventPayload(lifecycle=RecoveryRunLifecycle.RUNNING),
            occurred_at=NOW,
        )
        await store.append(
            request.run_id,
            expected_revision=current.revision,
            event_type=RecoveryRunEventType.LAUNCH_PERMIT,
            payload=RecoveryRunEventPayload(launch_permit=launch),
            occurred_at=NOW,
        )

        results = await asyncio.gather(
            *(
                store.claim_launch(
                    request.run_id,
                    launch_permit_id=launch.launch_permit_id,
                    claim_id=f"claim-{index}",
                    action_request_sha256=launch.action_request_sha256,
                    claimed_at=NOW + timedelta(seconds=1),
                )
                for index in range(32)
            ),
            return_exceptions=True,
        )
        winners = [item for item in results if not isinstance(item, BaseException)]
        denials = [
            item for item in results if isinstance(item, RecoveryLaunchClaimDenied)
        ]
        assert len(winners) == 1
        assert len(denials) == 31

    asyncio.run(exercise())


def test_recovery_node_state_cannot_skip_the_controller_transition() -> None:
    request, _event, _launch, snapshot, _scope = make_recovery_run_examples()

    async def exercise() -> None:
        store = InMemoryRecoveryRunStore()
        current, _created = await store.create(request, snapshot.chain, created_at=NOW)
        current = await store.append(
            request.run_id,
            expected_revision=current.revision,
            event_type=RecoveryRunEventType.LIFECYCLE,
            payload=RecoveryRunEventPayload(lifecycle=RecoveryRunLifecycle.RUNNING),
            occurred_at=NOW,
        )
        with pytest.raises(RecoveryRunConflict):
            await store.append(
                request.run_id,
                expected_revision=current.revision,
                event_type=RecoveryRunEventType.NODE,
                payload=RecoveryRunEventPayload(
                    node=RecoveryNodeProgress(
                        node_id=snapshot.chain.nodes[0].node_id,
                        state=RecoveryNodeState.COMPLETED,
                        attempt=1,
                    )
                ),
                occurred_at=NOW,
            )

    asyncio.run(exercise())
