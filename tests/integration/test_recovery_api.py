"""Public recovery-run HTTP and resumable SSE contracts."""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime, timedelta

import httpx
import pytest
from fastapi.testclient import TestClient

from reconcile.contracts import (
    MAX_RECOVERY_RUN_EVENTS,
    ActionPermitState,
    Classification,
    RecoveryNodeProgress,
    RecoveryNodeState,
    RecoveryRunEvent,
    RecoveryRunEventPayload,
    RecoveryRunEventType,
    RecoveryRunFailureCategory,
    RecoveryRunLifecycle,
    RecoveryRunRequest,
    RecoveryRunSnapshot,
    canonical_json_bytes,
    decode_contract,
)
from reconcile.interfaces.api import (
    _InternalApiFailure,
    _validated_recovery_event_snapshot,
    create_app,
)
from reconcile.interfaces.operator_api_client import OperatorApiClient
from reconcile.persistence import (
    RECOVERY_RUN_EVENT_SNAPSHOT_VERSION,
    InMemoryRecoveryRunStore,
    RecoveryRunEventSnapshot,
)
from reconcile.recovery_workflow import RecoveryRunLaunchResult
from tests.contract._factories import (
    make_recovery_examples,
    make_recovery_run_examples,
    make_report,
)

pytestmark = pytest.mark.integration


class _RecoveryService:
    def __init__(self) -> None:
        self.store = InMemoryRecoveryRunStore()
        self.closed = False

    async def launch(self, request: RecoveryRunRequest) -> RecoveryRunLaunchResult:
        chain = make_recovery_run_examples()[3].chain
        snapshot, created = await self.store.create(
            request,
            chain,
            created_at=datetime(2026, 8, 22, 12, 0, tzinfo=UTC),
        )
        if created:
            snapshot = await self.store.append(
                request.run_id,
                expected_revision=snapshot.revision,
                event_type=RecoveryRunEventType.LIFECYCLE,
                payload=RecoveryRunEventPayload(lifecycle=RecoveryRunLifecycle.RUNNING),
                occurred_at=snapshot.updated_at + timedelta(seconds=1),
            )
            snapshot = await self.store.append(
                request.run_id,
                expected_revision=snapshot.revision,
                event_type=RecoveryRunEventType.LIFECYCLE,
                payload=RecoveryRunEventPayload(
                    lifecycle=RecoveryRunLifecycle.FAILED,
                    failure_category=RecoveryRunFailureCategory.INTERNAL_FAILURE,
                ),
                occurred_at=snapshot.updated_at + timedelta(seconds=1),
            )
        return RecoveryRunLaunchResult(snapshot=snapshot, created=created)

    async def get(self, run_id: str) -> RecoveryRunSnapshot:
        return await self.store.get(run_id)

    async def snapshot(self, run_id: str, *, after: int = 0):
        return await self.store.events(run_id, after=after)

    async def wait_for_events(
        self,
        run_id: str,
        *,
        after: int = 0,
        cancellation_event: asyncio.Event | None = None,
    ):
        del cancellation_event
        return await self.snapshot(run_id, after=after)

    async def aclose(self) -> None:
        self.closed = True


class _TerminalAuditService:
    def __init__(
        self,
        snapshot: RecoveryRunSnapshot,
        events: RecoveryRunEventSnapshot,
    ) -> None:
        self._snapshot = snapshot
        self._events = events

    async def get(self, run_id: str) -> RecoveryRunSnapshot:
        assert run_id == self._snapshot.request.run_id
        return self._snapshot

    async def snapshot(self, run_id: str, *, after: int = 0):
        assert run_id == self._snapshot.request.run_id
        return self._events.model_copy(
            update={
                "events": tuple(
                    event for event in self._events.events if event.cursor > after
                )
            }
        )

    async def wait_for_events(
        self,
        run_id: str,
        *,
        after: int = 0,
        cancellation_event: asyncio.Event | None = None,
    ):
        del cancellation_event
        return await self.snapshot(run_id, after=after)

    async def aclose(self) -> None:
        return None


class _AdvancingTerminalAuditService(_TerminalAuditService):
    def __init__(
        self,
        snapshot: RecoveryRunSnapshot,
        events: RecoveryRunEventSnapshot,
    ) -> None:
        super().__init__(snapshot, events)
        self.after_calls: list[int] = []

    async def snapshot(self, run_id: str, *, after: int = 0):
        assert run_id == self._snapshot.request.run_id
        self.after_calls.append(after)
        if after == 0:
            return self._events.model_copy(
                update={"cursor": 2, "events": self._events.events[:2]}
            )
        return await super().snapshot(run_id, after=after)


def test_recovery_api_launch_get_and_resumable_sse() -> None:
    request = make_recovery_run_examples()[0]
    service = _RecoveryService()
    with TestClient(create_app(recovery_service=service, hosted=True)) as client:
        launched = client.post(
            "/api/v1/recovery-runs",
            content=canonical_json_bytes(request),
            headers={"Content-Type": "application/json"},
        )
        replayed = client.post(
            "/api/v1/recovery-runs",
            content=canonical_json_bytes(request),
            headers={"Content-Type": "application/json"},
        )
        fetched = client.get(f"/api/v1/recovery-runs/{request.run_id}")
        events = client.get(
            f"/api/v1/recovery-runs/{request.run_id}/events",
            headers={"Last-Event-ID": "2"},
        )

    assert launched.status_code == 202
    assert replayed.status_code == 200
    launched_snapshot = decode_contract(launched.content, RecoveryRunSnapshot)
    assert launched_snapshot.request == request
    assert decode_contract(fetched.content, RecoveryRunSnapshot) == launched_snapshot
    assert events.status_code == 200
    assert events.headers["content-type"].startswith("text/event-stream")
    assert events.text.count("\nid: ") == 1
    assert "id: 3\nevent: LIFECYCLE" in events.text
    assert "id: 4\nevent: LIFECYCLE" in events.text
    assert service.closed is True


def test_recovery_api_rejects_noncanonical_cursor_without_calling_service() -> None:
    request = make_recovery_run_examples()[0]
    service = _RecoveryService()
    asyncio.run(service.launch(request))
    response = TestClient(create_app(recovery_service=service, hosted=True)).get(
        f"/api/v1/recovery-runs/{request.run_id}/events?after=01"
    )

    assert response.status_code == 400
    assert response.json()["code"] == "invalid_contract"


def test_operator_client_validates_the_terminal_recovery_timeline() -> None:
    request = make_recovery_run_examples()[0]
    service = _RecoveryService()
    application = create_app(recovery_service=service, hosted=True)

    async def exercise() -> None:
        async with OperatorApiClient(
            transport=httpx.ASGITransport(app=application)
        ) as client:
            launched = await client.launch_recovery(request)
            timeline = [event async for event in client.recovery_events(request.run_id)]
            terminal = await client.get_recovery_snapshot(request.run_id)
            terminal_suffix = [
                event
                async for event in client.recovery_events(
                    request.run_id,
                    after=terminal.event_cursor,
                )
            ]
        assert launched.created is True
        assert tuple(event.cursor for event in timeline) == (1, 2, 3, 4)
        assert terminal.lifecycle is RecoveryRunLifecycle.FAILED
        assert terminal_suffix == []

    asyncio.run(exercise())


def test_terminal_recovery_suffix_accepts_late_permit_audit() -> None:
    request, accepted, _launch, snapshot, _scope = make_recovery_run_examples()
    _chain, _hypothesis, certificate, _witness, issued_permit = make_recovery_examples()
    permit = issued_permit.model_copy(
        update={
            "state": ActionPermitState.CLAIMED,
            "revision": 1,
            "claim_id": "claim-after-cancel-7",
            "claimed_at": issued_permit.issued_at + timedelta(microseconds=1),
        }
    )
    terminal = RecoveryRunEvent(
        schema_version=accepted.schema_version,
        run_id=request.run_id,
        cursor=2,
        type=RecoveryRunEventType.LIFECYCLE,
        occurred_at=accepted.occurred_at + timedelta(seconds=1),
        payload=RecoveryRunEventPayload(
            lifecycle=RecoveryRunLifecycle.CANCELLED,
            failure_category=RecoveryRunFailureCategory.CANCELLED,
        ),
    )
    audit = RecoveryRunEvent(
        schema_version=accepted.schema_version,
        run_id=request.run_id,
        cursor=3,
        type=RecoveryRunEventType.ACTION_PERMIT,
        occurred_at=accepted.occurred_at + timedelta(seconds=2),
        payload=RecoveryRunEventPayload(action_permit=permit),
    )
    full = RecoveryRunEventSnapshot(
        schema_version=RECOVERY_RUN_EVENT_SNAPSHOT_VERSION,
        run_id=request.run_id,
        cursor=3,
        terminal=True,
        events=(accepted, terminal, audit),
    )
    suffix = full.model_copy(update={"events": (audit,)})

    assert (
        _validated_recovery_event_snapshot(
            full,
            run_id=request.run_id,
            after=0,
        )
        == full
    )
    assert (
        _validated_recovery_event_snapshot(
            suffix,
            run_id=request.run_id,
            after=2,
        )
        == suffix
    )

    invalid = RecoveryRunEvent(
        schema_version=accepted.schema_version,
        run_id=request.run_id,
        cursor=3,
        type=RecoveryRunEventType.NODE,
        occurred_at=accepted.occurred_at + timedelta(seconds=2),
        payload=RecoveryRunEventPayload(
            node=RecoveryNodeProgress(
                node_id=snapshot.chain.nodes[0].node_id,
                state=RecoveryNodeState.RECONCILING,
                attempt=1,
            )
        ),
    )
    with pytest.raises(_InternalApiFailure):
        _validated_recovery_event_snapshot(
            full.model_copy(update={"events": (accepted, terminal, invalid)}),
            run_id=request.run_id,
            after=0,
        )
    with pytest.raises(_InternalApiFailure):
        _validated_recovery_event_snapshot(
            suffix.model_copy(update={"events": (invalid,)}),
            run_id=request.run_id,
            after=2,
        )

    final_snapshot = RecoveryRunSnapshot.model_validate(
        snapshot.model_copy(
            update={
                "lifecycle": RecoveryRunLifecycle.CANCELLED,
                "failure_category": RecoveryRunFailureCategory.CANCELLED,
                "event_cursor": 3,
                "revision": 2,
                "reports": (make_report(Classification.COMMITTED),),
                "certificates": (certificate,),
                "action_permits": (permit,),
                "updated_at": audit.occurred_at,
            }
        )
    )
    application = create_app(
        recovery_service=_TerminalAuditService(final_snapshot, full),
        hosted=True,
    )

    async def consume_without_reconnect() -> tuple[RecoveryRunEvent, ...]:
        async with OperatorApiClient(
            transport=httpx.ASGITransport(app=application)
        ) as client:
            events = [
                event
                async for event in client.recovery_events(
                    request.run_id,
                    max_reconnects=0,
                )
            ]
            return tuple(events)

    assert asyncio.run(consume_without_reconnect()) == full.events

    advancing_service = _AdvancingTerminalAuditService(final_snapshot, full)
    advancing_application = create_app(
        recovery_service=advancing_service,
        hosted=True,
    )

    async def consume_with_reconnect() -> tuple[RecoveryRunEvent, ...]:
        async with OperatorApiClient(
            transport=httpx.ASGITransport(app=advancing_application)
        ) as client:
            return tuple(
                [
                    event
                    async for event in client.recovery_events(
                        request.run_id,
                        max_reconnects=1,
                    )
                ]
            )

    assert asyncio.run(consume_with_reconnect()) == full.events
    assert advancing_service.after_calls == [0, 2]

    maximum_audit = audit.model_copy(update={"cursor": MAX_RECOVERY_RUN_EVENTS})
    maximum_events = full.model_copy(
        update={
            "cursor": MAX_RECOVERY_RUN_EVENTS,
            "events": (maximum_audit,),
        }
    )
    maximum_snapshot = final_snapshot.model_copy(
        update={
            "event_cursor": MAX_RECOVERY_RUN_EVENTS,
            "revision": MAX_RECOVERY_RUN_EVENTS - 1,
        }
    )
    maximum_application = create_app(
        recovery_service=_TerminalAuditService(maximum_snapshot, maximum_events),
        hosted=True,
    )

    async def consume_maximum_suffix() -> tuple[RecoveryRunEvent, ...]:
        async with OperatorApiClient(
            transport=httpx.ASGITransport(app=maximum_application)
        ) as client:
            return tuple(
                [
                    event
                    async for event in client.recovery_events(
                        request.run_id,
                        after=MAX_RECOVERY_RUN_EVENTS - 1,
                        max_reconnects=0,
                    )
                ]
            )

    assert asyncio.run(consume_maximum_suffix()) == (maximum_audit,)
