"""Durable delivery receipts for bounded hosted operational events."""

from __future__ import annotations

import asyncio
from typing import Protocol

from reconcile.contracts.codec import canonical_json_bytes, decode_contract
from reconcile.hosted.firestore_cas import (
    FirestoreCasCollection,
    FirestoreCasConflict,
    FirestoreCasDocument,
    FirestoreCasSnapshot,
    build_firestore_cas_document,
    new_firestore_cas_mutation_id,
)
from reconcile.hosted.observability import (
    OperationalEvent,
    OperationalEventDeliveryError,
    OperationalEventSink,
)


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


def _document(event: OperationalEvent) -> FirestoreCasDocument:
    return build_firestore_cas_document(
        collection=FirestoreCasCollection.OPERATIONAL_EVENT,
        logical_id=event.event_id,
        revision=0,
        mutation_id=new_firestore_cas_mutation_id(),
        canonical_payload=canonical_json_bytes(event),
    )


def _decode(snapshot: FirestoreCasSnapshot) -> OperationalEvent:
    try:
        event = decode_contract(snapshot.document.payload_bytes, OperationalEvent)
        if (
            snapshot.collection is not FirestoreCasCollection.OPERATIONAL_EVENT
            or snapshot.document.kind is not FirestoreCasCollection.OPERATIONAL_EVENT
            or snapshot.document.logical_id != event.event_id
            or snapshot.document.revision != 0
        ):
            raise ValueError
        return event
    except Exception as error:
        raise OperationalEventDeliveryError from error


class FirestoreOperationalEventOutbox:
    """Use an immutable CAS receipt to suppress delivered-event replays."""

    def __init__(self, cas_store: _FirestoreCasStore) -> None:
        if any(
            not callable(getattr(cas_store, name, None)) for name in ("create", "read")
        ):
            raise TypeError("Firestore operational outbox requires a CAS store")
        self._cas = cas_store

    async def _read(self, event_id: str) -> FirestoreCasSnapshot | None:
        try:
            return await self._cas.read(
                FirestoreCasCollection.OPERATIONAL_EVENT,
                event_id,
            )
        except asyncio.CancelledError:
            raise
        except Exception:
            raise OperationalEventDeliveryError from None

    async def deliver(
        self,
        event: OperationalEvent,
        *,
        sink: OperationalEventSink,
    ) -> bool:
        if type(event) is not OperationalEvent or not callable(sink):
            raise TypeError("operational event delivery inputs must be exact")
        existing = await self._read(event.event_id)
        if existing is not None:
            if _decode(existing) != event:
                raise OperationalEventDeliveryError
            return False

        try:
            sink(event)
        except Exception as error:
            raise OperationalEventDeliveryError from error

        document = _document(event)
        try:
            written = await self._cas.create(document)
        except asyncio.CancelledError:
            raise
        except FirestoreCasConflict:
            existing = await self._read(event.event_id)
            if existing is None or _decode(existing) != event:
                raise OperationalEventDeliveryError from None
            return False
        except Exception:
            raise OperationalEventDeliveryError from None
        if written.document != document or _decode(written) != event:
            raise OperationalEventDeliveryError
        return True


__all__ = ["FirestoreOperationalEventOutbox"]
