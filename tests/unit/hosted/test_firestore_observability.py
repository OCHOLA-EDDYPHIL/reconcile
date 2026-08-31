"""Durable operational-event delivery claims use exact Firestore CAS state."""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime, timedelta

import pytest

from reconcile.contracts.codec import canonical_json_bytes
from reconcile.hosted.config import Component
from reconcile.hosted.firestore_cas import (
    FirestoreCasCollection,
    build_firestore_cas_document,
    new_firestore_cas_mutation_id,
)
from reconcile.hosted.firestore_observability import (
    OPERATIONAL_EVENT_DELIVERY_VERSION,
    FirestoreOperationalEventOutbox,
    OperationalEventDelivery,
    OperationalEventDeliveryState,
)
from reconcile.hosted.observability import (
    OperationalEvent,
    OperationalEventDeliveryError,
    OperationalSignal,
    emit_operational_event,
)
from tests.unit.hosted.test_firestore_cas import _Client, _store

pytestmark = pytest.mark.unit

_NOW = datetime(2026, 8, 31, 12, 0, tzinfo=UTC)


def _event(correlation_id: str = "run-123") -> OperationalEvent:
    return emit_operational_event(
        signal=OperationalSignal.FAILED_RUN,
        component=Component.API,
        correlation_id=correlation_id,
        occurred_at=_NOW,
        source_event_cursor=7,
        source_event_sha256="a" * 64,
        sink=lambda _event: None,
    )


async def _delivery(cas, event: OperationalEvent) -> OperationalEventDelivery:
    snapshot = await cas.read(FirestoreCasCollection.OPERATIONAL_EVENT, event.event_id)
    assert snapshot is not None
    return OperationalEventDelivery.model_validate_json(snapshot.document.payload_bytes)


def test_sink_failure_releases_claim_and_replay_delivers_once() -> None:
    async def exercise() -> None:
        client = _Client()
        cas, _factory = _store(client)
        outbox = FirestoreOperationalEventOutbox(cas, clock=lambda: _NOW)
        event = _event()
        attempts = 0

        def unavailable(_event: OperationalEvent) -> None:
            nonlocal attempts
            attempts += 1
            raise OSError("private sink failure")

        with pytest.raises(OperationalEventDeliveryError):
            await outbox.deliver(event, sink=unavailable)
        assert (await _delivery(cas, event)).state is (
            OperationalEventDeliveryState.AVAILABLE
        )

        delivered: list[OperationalEvent] = []
        assert await outbox.deliver(event, sink=delivered.append) is True
        assert await outbox.deliver(event, sink=delivered.append) is False
        assert attempts == 1
        assert delivered == [event]
        assert (await _delivery(cas, event)).state is (
            OperationalEventDeliveryState.DELIVERED
        )

    asyncio.run(exercise())


def test_expired_claim_replays_with_the_same_event_identity_and_timestamp() -> None:
    async def exercise() -> None:
        client = _Client()
        client.commit_before[2] = RuntimeError("private write failure")
        cas, _factory = _store(client)
        now = [_NOW]
        outbox = FirestoreOperationalEventOutbox(cas, clock=lambda: now[0])
        event = _event()
        attempts: list[tuple[str, datetime]] = []

        with pytest.raises(OperationalEventDeliveryError):
            await outbox.deliver(
                event,
                sink=lambda item: attempts.append((item.event_id, item.occurred_at)),
            )
        assert (await _delivery(cas, event)).state is (
            OperationalEventDeliveryState.CLAIMED
        )

        client.commit_before.clear()
        now[0] += timedelta(seconds=31)
        assert await outbox.deliver(
            event,
            sink=lambda item: attempts.append((item.event_id, item.occurred_at)),
        )
        assert attempts == [
            (event.event_id, _NOW),
            (event.event_id, _NOW),
        ]

    asyncio.run(exercise())


def test_concurrent_publishers_claim_once_and_emit_once() -> None:
    async def exercise() -> None:
        client = _Client()
        cas, _factory = _store(client)
        first = FirestoreOperationalEventOutbox(cas, clock=lambda: _NOW)
        second = FirestoreOperationalEventOutbox(cas, clock=lambda: _NOW)
        event = _event()
        emitted: list[str] = []

        results = await asyncio.gather(
            first.deliver(event, sink=lambda item: emitted.append(item.event_id)),
            second.deliver(event, sink=lambda item: emitted.append(item.event_id)),
            return_exceptions=True,
        )

        assert sum(result is True for result in results) == 1
        assert all(
            result in {False, True} or type(result) is OperationalEventDeliveryError
            for result in results
        )
        assert emitted == [event.event_id]
        assert await first.deliver(event, sink=lambda _item: pytest.fail()) is False

    asyncio.run(exercise())


def test_divergent_delivery_claim_fails_closed() -> None:
    async def exercise() -> None:
        client = _Client()
        cas, _factory = _store(client)
        expected = _event()
        divergent = OperationalEventDelivery(
            schema_version=OPERATIONAL_EVENT_DELIVERY_VERSION,
            event=_event("run-456"),
            state=OperationalEventDeliveryState.DELIVERED,
        )
        await cas.create(
            build_firestore_cas_document(
                collection=FirestoreCasCollection.OPERATIONAL_EVENT,
                logical_id=expected.event_id,
                revision=0,
                mutation_id=new_firestore_cas_mutation_id(),
                canonical_payload=canonical_json_bytes(divergent),
            )
        )

        with pytest.raises(OperationalEventDeliveryError):
            await FirestoreOperationalEventOutbox(cas).deliver(
                expected,
                sink=lambda _event: pytest.fail(),
            )

    asyncio.run(exercise())
