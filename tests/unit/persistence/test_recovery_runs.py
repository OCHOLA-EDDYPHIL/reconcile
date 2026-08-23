"""Durable recovery-run aggregate and launch-authority guarantees."""

from __future__ import annotations

import asyncio
import json
import sqlite3
from datetime import timedelta

import pytest

from reconcile.contracts import (
    RecoveryDispatchOutcome,
    RecoveryDispatchReceipt,
    RecoveryLaunchPermitState,
    RecoveryNodeProgress,
    RecoveryNodeState,
    RecoveryRunEventPayload,
    RecoveryRunEventType,
    RecoveryRunFailureCategory,
    RecoveryRunLifecycle,
    canonical_json_bytes,
)
from reconcile.persistence import (
    InMemoryRecoveryRunStore,
    RecoveryLaunchClaimDenied,
    RecoveryRunConflict,
    RecoveryRunCorruptState,
    SqliteRecoveryRunStore,
)
from reconcile.persistence.recovery_runs import (
    RecoveryRunAggregate,
    _append_decoded_recovery_event,
    _canonical_verified_recovery_aggregate_bytes,
    append_recovery_event,
    create_recovery_run_aggregate,
)
from tests.contract._factories import (
    NOW,
    make_recovery_run_examples,
    make_recovery_scenario_examples,
)

pytestmark = pytest.mark.unit


def test_decoded_append_matches_full_history_validation() -> None:
    request, _event, _launch, snapshot, _scope = make_recovery_run_examples()
    aggregate = create_recovery_run_aggregate(
        request,
        snapshot.chain,
        created_at=NOW,
    )
    payload = RecoveryRunEventPayload(lifecycle=RecoveryRunLifecycle.RUNNING)

    expected = append_recovery_event(
        aggregate,
        event_type=RecoveryRunEventType.LIFECYCLE,
        payload=payload,
        occurred_at=NOW + timedelta(seconds=1, microseconds=123_456),
    )
    actual = _append_decoded_recovery_event(
        aggregate,
        event_type=RecoveryRunEventType.LIFECYCLE,
        payload=payload,
        occurred_at=NOW + timedelta(seconds=1, microseconds=123_456),
    )

    assert actual == expected
    assert (
        RecoveryRunAggregate.model_validate(actual.model_dump(mode="python"))
        == expected
    )
    assert _canonical_verified_recovery_aggregate_bytes(actual) == (
        canonical_json_bytes(expected)
    )


def test_sqlite_cache_revalidates_external_writes_tampering_and_restart(
    tmp_path,
    monkeypatch,
) -> None:
    request, _event, _launch, snapshot, _scope = make_recovery_run_examples()
    database = tmp_path / "tampered-prefix.sqlite3"
    decoded_payloads: list[bytes] = []
    decode = SqliteRecoveryRunStore._decode

    def counted_decode(payload: object, run_id: str):
        decoded_payloads.append(SqliteRecoveryRunStore._payload_bytes(payload, run_id))
        return decode(payload, run_id)

    monkeypatch.setattr(
        SqliteRecoveryRunStore,
        "_decode",
        staticmethod(counted_decode),
    )

    async def exercise() -> None:
        store = SqliteRecoveryRunStore(database)
        created, _ = await store.create(request, snapshot.chain, created_at=NOW)
        created.chain.nodes[0].semantic_action.semantic_arguments["release_id"] = (
            "caller-mutation"
        )
        cached = await store.get(request.run_id)
        assert cached == snapshot
        cached.chain.nodes[0].semantic_action.semantic_arguments["release_id"] = (
            "second-caller-mutation"
        )
        assert await store.get(request.run_id) == snapshot
        assert decoded_payloads == []

        reopened = SqliteRecoveryRunStore(database)
        assert await reopened.get(request.run_id) == snapshot
        assert len(decoded_payloads) == 1
        assert await reopened.get(request.run_id) == snapshot
        assert len(decoded_payloads) == 1

        updated = await reopened.append(
            request.run_id,
            expected_revision=snapshot.revision,
            event_type=RecoveryRunEventType.LIFECYCLE,
            payload=RecoveryRunEventPayload(lifecycle=RecoveryRunLifecycle.RUNNING),
            occurred_at=NOW + timedelta(seconds=1),
        )
        assert await store.get(request.run_id) == updated
        assert len(decoded_payloads) == 2
        assert await store.get(request.run_id) == updated
        assert len(decoded_payloads) == 2

        with sqlite3.connect(database) as connection:
            row = connection.execute(
                "SELECT payload FROM recovery_run_aggregates WHERE run_id = ?",
                (request.run_id,),
            ).fetchone()
            assert row is not None
            value = json.loads(row[0])
            value["events"] = value["events"][:-1]
            connection.execute(
                "UPDATE recovery_run_aggregates SET payload = ? WHERE run_id = ?",
                (
                    json.dumps(value, separators=(",", ":")).encode(),
                    request.run_id,
                ),
            )

        with pytest.raises(RecoveryRunCorruptState):
            await store.get(request.run_id)
        assert len(decoded_payloads) == 3

    asyncio.run(exercise())


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


def test_claimed_launch_permit_can_complete_after_terminal_cancellation(
    tmp_path,
) -> None:
    request, _event, launch, snapshot, _scope = make_recovery_run_examples()
    database = tmp_path / "late-launch-completion.sqlite3"

    async def exercise() -> None:
        store = SqliteRecoveryRunStore(database)
        current, _created = await store.create(
            request,
            snapshot.chain,
            created_at=NOW,
        )
        current = await store.append(
            request.run_id,
            expected_revision=current.revision,
            event_type=RecoveryRunEventType.LIFECYCLE,
            payload=RecoveryRunEventPayload(lifecycle=RecoveryRunLifecycle.RUNNING),
            occurred_at=NOW + timedelta(seconds=1),
        )
        current = await store.append(
            request.run_id,
            expected_revision=current.revision,
            event_type=RecoveryRunEventType.LAUNCH_PERMIT,
            payload=RecoveryRunEventPayload(launch_permit=launch),
            occurred_at=NOW + timedelta(seconds=2),
        )
        await store.claim_launch(
            request.run_id,
            launch_permit_id=launch.launch_permit_id,
            claim_id="claim-before-cancel-7",
            action_request_sha256=launch.action_request_sha256,
            claimed_at=NOW + timedelta(seconds=3),
        )
        current = await store.get(request.run_id)
        await store.append(
            request.run_id,
            expected_revision=current.revision,
            event_type=RecoveryRunEventType.LIFECYCLE,
            payload=RecoveryRunEventPayload(
                lifecycle=RecoveryRunLifecycle.CANCELLED,
                failure_category=RecoveryRunFailureCategory.CANCELLED,
            ),
            occurred_at=NOW + timedelta(seconds=4),
        )
        current = await store.get(request.run_id)
        with pytest.raises(RecoveryRunConflict):
            await store.append(
                request.run_id,
                expected_revision=current.revision,
                event_type=RecoveryRunEventType.LAUNCH_PERMIT,
                payload=RecoveryRunEventPayload(
                    launch_permit=launch.model_copy(
                        update={"launch_permit_id": "different-launch-7"}
                    )
                ),
                occurred_at=NOW + timedelta(seconds=5),
            )

        completed = await store.complete_launch(
            request.run_id,
            launch_permit_id=launch.launch_permit_id,
            claim_id="claim-before-cancel-7",
            outcome=RecoveryDispatchOutcome.SUCCEEDED,
            completed_at=NOW + timedelta(seconds=6),
        )
        reopened = SqliteRecoveryRunStore(database)
        final = await reopened.get(request.run_id)
        events = await reopened.events(request.run_id)

        assert completed.state is RecoveryLaunchPermitState.COMPLETED
        assert final.lifecycle is RecoveryRunLifecycle.CANCELLED
        assert final.launch_permit == completed
        assert tuple(event.type for event in events.events[-2:]) == (
            RecoveryRunEventType.LIFECYCLE,
            RecoveryRunEventType.LAUNCH_PERMIT,
        )
        assert tuple(event.cursor for event in events.events) == tuple(
            range(1, events.cursor + 1)
        )

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


@pytest.mark.parametrize("store_kind", ["memory", "sqlite"])
def test_dispatch_receipt_is_append_only_and_survives_restart(
    tmp_path,
    store_kind: str,
) -> None:
    request, _event, launch, snapshot, _scope = make_recovery_run_examples()
    example, _comparison = make_recovery_scenario_examples()
    database = tmp_path / "receipt.sqlite3"

    async def exercise() -> None:
        store = (
            InMemoryRecoveryRunStore()
            if store_kind == "memory"
            else SqliteRecoveryRunStore(database)
        )
        current, _created = await store.create(request, snapshot.chain, created_at=NOW)
        current = await store.append(
            request.run_id,
            expected_revision=current.revision,
            event_type=RecoveryRunEventType.LIFECYCLE,
            payload=RecoveryRunEventPayload(lifecycle=RecoveryRunLifecycle.RUNNING),
            occurred_at=NOW,
        )
        current = await store.append(
            request.run_id,
            expected_revision=current.revision,
            event_type=RecoveryRunEventType.LAUNCH_PERMIT,
            payload=RecoveryRunEventPayload(launch_permit=launch),
            occurred_at=NOW,
        )
        claimed = await store.claim_launch(
            request.run_id,
            launch_permit_id=launch.launch_permit_id,
            claim_id="claim-receipt-7",
            action_request_sha256=launch.action_request_sha256,
            claimed_at=NOW,
        )
        receipt = RecoveryDispatchReceipt.model_validate(
            example.model_copy(
                update={
                    "run_id": request.run_id,
                    "release_id": snapshot.chain.nodes[
                        0
                    ].semantic_action.semantic_arguments["release_id"],
                    "node_id": snapshot.chain.nodes[0].node_id,
                    "semantic_action_sha256": snapshot.chain.nodes[
                        0
                    ].semantic_action.semantic_action_sha256,
                    "action_request_sha256": launch.action_request_sha256,
                    "authority_id": launch.launch_permit_id,
                    "claim_id": claimed.claim_id,
                }
            )
        )
        current = await store.get(request.run_id)
        current = await store.append(
            request.run_id,
            expected_revision=current.revision,
            event_type=RecoveryRunEventType.DISPATCH_RECEIPT,
            payload=RecoveryRunEventPayload(dispatch_receipt=receipt),
            occurred_at=NOW,
        )
        assert current.dispatch_receipts == (receipt,)
        with pytest.raises(RecoveryRunConflict):
            await store.append(
                request.run_id,
                expected_revision=current.revision,
                event_type=RecoveryRunEventType.DISPATCH_RECEIPT,
                payload=RecoveryRunEventPayload(dispatch_receipt=receipt),
                occurred_at=NOW,
            )
        if store_kind == "sqlite":
            reopened = SqliteRecoveryRunStore(database)
            assert (await reopened.get(request.run_id)).dispatch_receipts == (receipt,)

    asyncio.run(exercise())


def test_dispatch_receipt_without_claimed_authority_is_rejected() -> None:
    request, _event, _launch, snapshot, _scope = make_recovery_run_examples()
    example, _comparison = make_recovery_scenario_examples()
    receipt = RecoveryDispatchReceipt.model_validate(
        example.model_copy(
            update={
                "run_id": request.run_id,
                "release_id": snapshot.chain.nodes[
                    0
                ].semantic_action.semantic_arguments["release_id"],
                "node_id": snapshot.chain.nodes[0].node_id,
                "semantic_action_sha256": snapshot.chain.nodes[
                    0
                ].semantic_action.semantic_action_sha256,
            }
        )
    )
    store = InMemoryRecoveryRunStore()

    async def exercise() -> None:
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
                event_type=RecoveryRunEventType.DISPATCH_RECEIPT,
                payload=RecoveryRunEventPayload(dispatch_receipt=receipt),
                occurred_at=NOW,
            )

    asyncio.run(exercise())
