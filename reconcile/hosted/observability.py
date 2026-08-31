"""Bounded secret-free operational signals for hosted deployments."""

from __future__ import annotations

import asyncio
import hashlib
import sys
from collections.abc import Callable
from enum import StrEnum
from typing import Literal, Protocol, TextIO, runtime_checkable

from pydantic import Field, model_validator

from reconcile.contracts.base import (
    Identifier,
    Sha256Digest,
    StrictModel,
    canonical_json_value_bytes,
)
from reconcile.hosted.config import Component

OPERATIONAL_EVENT_VERSION = "reconcile/operational-event/v1"


class OperationalSignal(StrEnum):
    FAILED_RUN = "failed-run"
    UNRESOLVED_AMBIGUITY = "unresolved-ambiguity"
    PROVIDER_UNAVAILABLE = "provider-unavailable"
    PERMIT_DENIAL = "permit-denial"
    REPLAY_DENIAL = "replay-denial"
    WORKER_FAILURE = "worker-failure"


class OperationalEvent(StrictModel):
    """A fixed-field event safe for direct Cloud Logging JSON ingestion."""

    schema_version: Literal["reconcile/operational-event/v1"]
    event: Literal["operational-signal"]
    severity: Literal["WARNING", "ERROR"]
    signal: OperationalSignal
    component: Component
    correlation_id: Identifier
    event_id: Identifier
    source_event_cursor: int | None = Field(default=None, ge=1, le=2**63 - 1)
    source_event_sha256: Sha256Digest | None = None

    @model_validator(mode="after")
    def _validate_severity(self) -> OperationalEvent:
        expected = (
            "ERROR"
            if self.signal
            in {OperationalSignal.FAILED_RUN, OperationalSignal.WORKER_FAILURE}
            else "WARNING"
        )
        if self.severity != expected:
            raise ValueError("operational signal severity is not canonical")
        if (self.source_event_cursor is None) != (self.source_event_sha256 is None):
            raise ValueError("operational event source identity is incomplete")
        if self.event_id != operational_event_id(
            signal=self.signal,
            component=self.component,
            correlation_id=self.correlation_id,
            source_event_cursor=self.source_event_cursor,
            source_event_sha256=self.source_event_sha256,
        ):
            raise ValueError("operational event identity is not canonical")
        return self


class OperationalEventSink(Protocol):
    def __call__(self, event: OperationalEvent) -> None: ...


class OperationalEventDeliveryError(RuntimeError):
    """A bounded operational event is not durably delivered yet."""


@runtime_checkable
class OperationalEventOutbox(Protocol):
    async def deliver(
        self,
        event: OperationalEvent,
        *,
        sink: OperationalEventSink,
    ) -> bool: ...


class OperationalSignalPublisher(Protocol):
    async def __call__(
        self,
        signal: str,
        correlation_id: str,
        *,
        source_event_cursor: int | None = None,
        source_event_sha256: str | None = None,
    ) -> None: ...


def operational_event_id(
    *,
    signal: OperationalSignal,
    component: Component,
    correlation_id: str,
    source_event_cursor: int | None = None,
    source_event_sha256: str | None = None,
) -> str:
    """Derive one stable identity for idempotent delivery and log ingestion."""

    if (
        type(signal) is not OperationalSignal
        or type(component) is not Component
        or type(correlation_id) is not str
        or not correlation_id
    ):
        raise TypeError("operational event identity must be exact")
    payload = canonical_json_value_bytes(
        {
            "component": component.value,
            "correlation_id": correlation_id,
            "signal": signal.value,
            "source_event_cursor": source_event_cursor,
            "source_event_sha256": source_event_sha256,
        }
    )
    return f"event-{hashlib.sha256(payload).hexdigest()}"


def _stderr_sink(event: OperationalEvent, *, stream: TextIO | None = None) -> None:
    destination = sys.stderr if stream is None else stream
    payload = event.model_dump(mode="json")
    payload["logging.googleapis.com/insertId"] = event.event_id
    destination.write(canonical_json_value_bytes(payload).decode("utf-8"))
    destination.write("\n")
    destination.flush()


def emit_operational_event(
    *,
    signal: OperationalSignal,
    component: Component,
    correlation_id: str,
    source_event_cursor: int | None = None,
    source_event_sha256: str | None = None,
    sink: OperationalEventSink | None = None,
) -> OperationalEvent:
    """Validate and emit one bounded event without accepting exception details."""

    if type(signal) is not OperationalSignal or type(component) is not Component:
        raise TypeError("operational event identity must be exact")
    severity: Literal["WARNING", "ERROR"] = (
        "ERROR"
        if signal in {OperationalSignal.FAILED_RUN, OperationalSignal.WORKER_FAILURE}
        else "WARNING"
    )
    event = OperationalEvent(
        schema_version=OPERATIONAL_EVENT_VERSION,
        event="operational-signal",
        severity=severity,
        signal=signal,
        component=component,
        correlation_id=correlation_id,
        event_id=operational_event_id(
            signal=signal,
            component=component,
            correlation_id=correlation_id,
            source_event_cursor=source_event_cursor,
            source_event_sha256=source_event_sha256,
        ),
        source_event_cursor=source_event_cursor,
        source_event_sha256=source_event_sha256,
    )
    (sink or _stderr_sink)(event)
    return event


def component_observer(
    component: Component,
    *,
    sink: OperationalEventSink | None = None,
) -> Callable[[str, str], None]:
    """Adapt fixed internal signal names to one component-bound event sink."""

    if type(component) is not Component:
        raise TypeError("operational observer component must be exact")

    def observe(signal: str, correlation_id: str) -> None:
        emit_operational_event(
            signal=OperationalSignal(signal),
            component=component,
            correlation_id=correlation_id,
            sink=sink,
        )

    return observe


class InMemoryOperationalEventOutbox:
    """Provide deterministic delivery semantics without external persistence."""

    def __init__(self) -> None:
        self._delivered: dict[str, OperationalEvent] = {}
        self._lock = asyncio.Lock()

    async def deliver(
        self,
        event: OperationalEvent,
        *,
        sink: OperationalEventSink,
    ) -> bool:
        if type(event) is not OperationalEvent or not callable(sink):
            raise TypeError("operational event delivery inputs must be exact")
        async with self._lock:
            delivered = self._delivered.get(event.event_id)
            if delivered is not None:
                if delivered != event:
                    raise OperationalEventDeliveryError
                return False
            try:
                sink(event)
            except Exception as error:
                raise OperationalEventDeliveryError from error
            self._delivered[event.event_id] = event
            return True


def component_publisher(
    component: Component,
    outbox: OperationalEventOutbox,
    *,
    sink: OperationalEventSink | None = None,
) -> OperationalSignalPublisher:
    """Bind one component to durable, replay-safe operational delivery."""

    if type(component) is not Component or not isinstance(
        outbox, OperationalEventOutbox
    ):
        raise TypeError("operational publisher inputs must be exact")
    destination = sink or _stderr_sink

    async def publish(
        signal: str,
        correlation_id: str,
        *,
        source_event_cursor: int | None = None,
        source_event_sha256: str | None = None,
    ) -> None:
        event = OperationalEvent(
            schema_version=OPERATIONAL_EVENT_VERSION,
            event="operational-signal",
            severity=(
                "ERROR"
                if OperationalSignal(signal)
                in {OperationalSignal.FAILED_RUN, OperationalSignal.WORKER_FAILURE}
                else "WARNING"
            ),
            signal=OperationalSignal(signal),
            component=component,
            correlation_id=correlation_id,
            source_event_cursor=source_event_cursor,
            source_event_sha256=source_event_sha256,
            event_id=operational_event_id(
                signal=OperationalSignal(signal),
                component=component,
                correlation_id=correlation_id,
                source_event_cursor=source_event_cursor,
                source_event_sha256=source_event_sha256,
            ),
        )
        for attempt in range(2):
            try:
                await outbox.deliver(event, sink=destination)
                return
            except asyncio.CancelledError:
                raise
            except OperationalEventDeliveryError:
                if attempt == 1:
                    raise

    return publish


__all__ = [
    "OPERATIONAL_EVENT_VERSION",
    "InMemoryOperationalEventOutbox",
    "OperationalEvent",
    "OperationalEventDeliveryError",
    "OperationalEventOutbox",
    "OperationalEventSink",
    "OperationalSignal",
    "OperationalSignalPublisher",
    "component_observer",
    "component_publisher",
    "emit_operational_event",
    "operational_event_id",
]
