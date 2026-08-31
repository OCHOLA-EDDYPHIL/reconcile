"""Durable delivery claims for bounded hosted operational events."""

from __future__ import annotations

import asyncio
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from typing import Literal, Protocol

from pydantic import model_validator

from reconcile.contracts.base import AwareDatetime, Identifier, StrictModel
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

OPERATIONAL_EVENT_DELIVERY_VERSION = "reconcile/operational-event-delivery/v1"
_CLAIM_LEASE = timedelta(seconds=30)


class OperationalEventDeliveryState(StrEnum):
    AVAILABLE = "AVAILABLE"
    CLAIMED = "CLAIMED"
    DELIVERED = "DELIVERED"


class OperationalEventDelivery(StrictModel):
    """One immutable event plus its monotonic delivery state."""

    schema_version: Literal["reconcile/operational-event-delivery/v1"]
    event: OperationalEvent
    state: OperationalEventDeliveryState
    claim_id: Identifier | None = None
    claim_expires_at: AwareDatetime | None = None

    @model_validator(mode="after")
    def _validate_claim(self) -> OperationalEventDelivery:
        claimed = self.state is OperationalEventDeliveryState.CLAIMED
        if claimed != (self.claim_id is not None and self.claim_expires_at is not None):
            raise ValueError("operational event delivery claim is invalid")
        return self


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

    async def update(
        self,
        current: FirestoreCasSnapshot,
        replacement: FirestoreCasDocument,
    ) -> FirestoreCasSnapshot: ...


def _utc(value: datetime) -> datetime:
    if not isinstance(value, datetime) or value.tzinfo is None:
        raise ValueError("operational delivery clock must be timezone-aware")
    if value.utcoffset() is None:
        raise ValueError("operational delivery clock must be timezone-aware")
    return value.astimezone(UTC)


def _document(
    delivery: OperationalEventDelivery,
    *,
    revision: int,
) -> FirestoreCasDocument:
    return build_firestore_cas_document(
        collection=FirestoreCasCollection.OPERATIONAL_EVENT,
        logical_id=delivery.event.event_id,
        revision=revision,
        mutation_id=new_firestore_cas_mutation_id(),
        canonical_payload=canonical_json_bytes(delivery),
    )


def _decode(snapshot: FirestoreCasSnapshot) -> OperationalEventDelivery:
    try:
        delivery = decode_contract(
            snapshot.document.payload_bytes,
            OperationalEventDelivery,
        )
        if (
            snapshot.collection is not FirestoreCasCollection.OPERATIONAL_EVENT
            or snapshot.document.kind is not FirestoreCasCollection.OPERATIONAL_EVENT
            or snapshot.document.logical_id != delivery.event.event_id
        ):
            raise ValueError
        return delivery
    except Exception as error:
        raise OperationalEventDeliveryError from error


def _claimed(event: OperationalEvent, *, now: datetime) -> OperationalEventDelivery:
    return OperationalEventDelivery(
        schema_version=OPERATIONAL_EVENT_DELIVERY_VERSION,
        event=event,
        state=OperationalEventDeliveryState.CLAIMED,
        claim_id=new_firestore_cas_mutation_id(),
        claim_expires_at=now + _CLAIM_LEASE,
    )


def _settled(
    event: OperationalEvent,
    state: Literal[
        OperationalEventDeliveryState.AVAILABLE,
        OperationalEventDeliveryState.DELIVERED,
    ],
) -> OperationalEventDelivery:
    return OperationalEventDelivery(
        schema_version=OPERATIONAL_EVENT_DELIVERY_VERSION,
        event=event,
        state=state,
    )


class FirestoreOperationalEventOutbox:
    """Claim one event before emission and durably suppress delivered replays."""

    def __init__(
        self,
        cas_store: _FirestoreCasStore,
        *,
        clock: Callable[[], datetime] = lambda: datetime.now(UTC),
    ) -> None:
        if any(
            not callable(getattr(cas_store, name, None))
            for name in ("create", "read", "update")
        ):
            raise TypeError("Firestore operational outbox requires a CAS store")
        if not callable(clock):
            raise TypeError("Firestore operational outbox requires a clock")
        self._cas = cas_store
        self._clock = clock

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

    async def _claim(self, event: OperationalEvent) -> FirestoreCasSnapshot | None:
        for _attempt in range(2):
            now = _utc(self._clock())
            current = await self._read(event.event_id)
            if current is None:
                document = _document(_claimed(event, now=now), revision=0)
                try:
                    return await self._cas.create(document)
                except asyncio.CancelledError:
                    raise
                except FirestoreCasConflict:
                    continue
                except Exception:
                    raise OperationalEventDeliveryError from None

            delivery = _decode(current)
            if delivery.event != event:
                raise OperationalEventDeliveryError
            if delivery.state is OperationalEventDeliveryState.DELIVERED:
                return None
            if (
                delivery.state is OperationalEventDeliveryState.CLAIMED
                and delivery.claim_expires_at is not None
                and delivery.claim_expires_at > now
            ):
                raise OperationalEventDeliveryError
            replacement = _document(
                _claimed(event, now=now),
                revision=current.document.revision + 1,
            )
            try:
                return await self._cas.update(current, replacement)
            except asyncio.CancelledError:
                raise
            except FirestoreCasConflict:
                continue
            except Exception:
                raise OperationalEventDeliveryError from None
        raise OperationalEventDeliveryError

    async def _settle(
        self,
        claim: FirestoreCasSnapshot,
        event: OperationalEvent,
        state: Literal[
            OperationalEventDeliveryState.AVAILABLE,
            OperationalEventDeliveryState.DELIVERED,
        ],
    ) -> None:
        replacement = _document(
            _settled(event, state),
            revision=claim.document.revision + 1,
        )
        try:
            written = await self._cas.update(claim, replacement)
        except asyncio.CancelledError:
            raise
        except Exception:
            raise OperationalEventDeliveryError from None
        if written.document != replacement or _decode(written) != _settled(
            event, state
        ):
            raise OperationalEventDeliveryError

    async def deliver(
        self,
        event: OperationalEvent,
        *,
        sink: OperationalEventSink,
    ) -> bool:
        if type(event) is not OperationalEvent or not callable(sink):
            raise TypeError("operational event delivery inputs must be exact")
        claim = await self._claim(event)
        if claim is None:
            return False
        try:
            sink(event)
        except Exception:
            await self._settle(
                claim,
                event,
                OperationalEventDeliveryState.AVAILABLE,
            )
            raise OperationalEventDeliveryError from None
        await self._settle(
            claim,
            event,
            OperationalEventDeliveryState.DELIVERED,
        )
        return True


__all__ = [
    "OPERATIONAL_EVENT_DELIVERY_VERSION",
    "FirestoreOperationalEventOutbox",
    "OperationalEventDelivery",
    "OperationalEventDeliveryState",
]
