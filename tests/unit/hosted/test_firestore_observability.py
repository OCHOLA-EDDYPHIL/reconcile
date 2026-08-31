"""Durable operational-event delivery receipts use exact Firestore CAS state."""

from __future__ import annotations

import asyncio

import pytest

from reconcile.contracts.codec import canonical_json_bytes
from reconcile.hosted.config import Component
from reconcile.hosted.firestore_cas import (
    FirestoreCasCollection,
    build_firestore_cas_document,
    new_firestore_cas_mutation_id,
)
from reconcile.hosted.firestore_observability import FirestoreOperationalEventOutbox
from reconcile.hosted.observability import (
    OperationalEvent,
    OperationalEventDeliveryError,
    OperationalSignal,
    emit_operational_event,
)
from tests.unit.hosted.test_firestore_cas import _Client, _store

pytestmark = pytest.mark.unit


def _event(correlation_id: str = "run-123") -> OperationalEvent:
    return emit_operational_event(
        signal=OperationalSignal.FAILED_RUN,
        component=Component.API,
        correlation_id=correlation_id,
        source_event_cursor=7,
        source_event_sha256="a" * 64,
        sink=lambda _event: None,
    )


def test_sink_failure_leaves_no_receipt_and_replay_delivers_once() -> None:
    async def exercise() -> None:
        client = _Client()
        cas, _factory = _store(client)
        outbox = FirestoreOperationalEventOutbox(cas)
        event = _event()
        attempts = 0

        def unavailable(_event: OperationalEvent) -> None:
            nonlocal attempts
            attempts += 1
            raise OSError("private sink failure")

        with pytest.raises(OperationalEventDeliveryError):
            await outbox.deliver(event, sink=unavailable)
        assert client.documents == {}

        delivered: list[OperationalEvent] = []
        assert await outbox.deliver(event, sink=delivered.append) is True
        assert await outbox.deliver(event, sink=delivered.append) is False
        assert attempts == 1
        assert delivered == [event]

    asyncio.run(exercise())


def test_receipt_write_failure_replays_with_the_same_event_identity() -> None:
    async def exercise() -> None:
        client = _Client()
        client.commit_before[1] = RuntimeError("private write failure")
        cas, _factory = _store(client)
        outbox = FirestoreOperationalEventOutbox(cas)
        event = _event()
        attempts: list[str] = []

        with pytest.raises(OperationalEventDeliveryError):
            await outbox.deliver(
                event, sink=lambda item: attempts.append(item.event_id)
            )
        client.commit_before.clear()
        assert (
            await outbox.deliver(
                event,
                sink=lambda item: attempts.append(item.event_id),
            )
            is True
        )
        assert attempts == [event.event_id, event.event_id]

    asyncio.run(exercise())


def test_concurrent_publishers_share_one_stable_receipt_identity() -> None:
    async def exercise() -> None:
        client = _Client()
        cas, _factory = _store(client)
        first = FirestoreOperationalEventOutbox(cas)
        second = FirestoreOperationalEventOutbox(cas)
        event = _event()
        emitted: list[str] = []

        results = await asyncio.gather(
            first.deliver(event, sink=lambda item: emitted.append(item.event_id)),
            second.deliver(event, sink=lambda item: emitted.append(item.event_id)),
        )

        assert sorted(results) == [False, True]
        assert set(emitted) == {event.event_id}
        assert await first.deliver(event, sink=lambda _item: pytest.fail()) is False

    asyncio.run(exercise())


def test_divergent_receipt_fails_closed() -> None:
    async def exercise() -> None:
        client = _Client()
        cas, _factory = _store(client)
        expected = _event()
        divergent = _event("run-456")
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
