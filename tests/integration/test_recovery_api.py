"""Public recovery-run HTTP and resumable SSE contracts."""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime, timedelta

import httpx
import pytest
from fastapi.testclient import TestClient

from reconcile.contracts import (
    RecoveryRunEventPayload,
    RecoveryRunEventType,
    RecoveryRunFailureCategory,
    RecoveryRunLifecycle,
    RecoveryRunRequest,
    RecoveryRunSnapshot,
    canonical_json_bytes,
    decode_contract,
)
from reconcile.interfaces.api import create_app
from reconcile.interfaces.operator_api_client import OperatorApiClient
from reconcile.persistence import InMemoryRecoveryRunStore
from reconcile.recovery_workflow import RecoveryRunLaunchResult
from tests.contract._factories import make_recovery_run_examples

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
