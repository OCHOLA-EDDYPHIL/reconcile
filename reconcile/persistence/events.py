"""Append-only in-memory investigation event journal."""

from __future__ import annotations

import asyncio
from contextlib import suppress
from dataclasses import dataclass, field

from reconcile.contracts.api import (
    MAX_INVESTIGATION_EVENTS,
    InvestigationEvent,
    InvestigationEventType,
    LifecycleEventPayload,
)
from reconcile.contracts.codec import canonical_json_bytes, decode_contract
from reconcile.contracts.report import InvestigationStatus


class EventJournalError(Exception):
    """Base class for deterministic event-journal failures."""


class JournalAlreadyRegistered(EventJournalError):
    """An event journal already exists for the investigation."""

    def __init__(self, investigation_id: str) -> None:
        self.investigation_id = investigation_id
        super().__init__(f"event journal already exists: {investigation_id}")


class JournalNotFound(EventJournalError):
    """No event journal exists for the investigation."""

    def __init__(self, investigation_id: str) -> None:
        self.investigation_id = investigation_id
        super().__init__(f"event journal does not exist: {investigation_id}")


class EventSequenceConflict(EventJournalError):
    """Base class for a non-contiguous event append."""

    def __init__(
        self,
        investigation_id: str,
        expected_sequence: int,
        actual_sequence: int,
        message: str,
    ) -> None:
        self.investigation_id = investigation_id
        self.expected_sequence = expected_sequence
        self.actual_sequence = actual_sequence
        super().__init__(message)


class DuplicateEvent(EventSequenceConflict):
    """An event sequence has already been accepted by the journal."""

    def __init__(
        self,
        investigation_id: str,
        expected_sequence: int,
        actual_sequence: int,
    ) -> None:
        self.sequence = actual_sequence
        super().__init__(
            investigation_id,
            expected_sequence,
            actual_sequence,
            f"event sequence {actual_sequence} already exists for {investigation_id}",
        )


class OutOfOrderEvent(EventSequenceConflict):
    """An append skipped the journal's next required sequence."""

    def __init__(
        self,
        investigation_id: str,
        expected_sequence: int,
        actual_sequence: int,
    ) -> None:
        super().__init__(
            investigation_id,
            expected_sequence,
            actual_sequence,
            "out-of-order event for "
            f"{investigation_id}: expected {expected_sequence}, "
            f"received {actual_sequence}",
        )


class TerminalEventJournal(EventJournalError):
    """A terminal journal cannot accept another event."""

    def __init__(self, investigation_id: str) -> None:
        self.investigation_id = investigation_id
        super().__init__(f"event journal is terminal: {investigation_id}")


class JournalCapacityExceeded(EventJournalError):
    """The public event-contract bound has been reached."""

    def __init__(self, investigation_id: str) -> None:
        self.investigation_id = investigation_id
        self.limit = MAX_INVESTIGATION_EVENTS
        super().__init__(
            f"event journal reached its {self.limit}-event limit: {investigation_id}"
        )


class InvalidCursor(EventJournalError):
    """An exclusive cursor is outside the retained journal range."""

    def __init__(self, investigation_id: str, cursor: object, latest: int) -> None:
        self.investigation_id = investigation_id
        self.cursor = cursor
        self.latest = latest
        super().__init__(
            f"event cursor is outside the journal range for {investigation_id}"
        )


@dataclass(frozen=True, slots=True)
class EventJournalSnapshot:
    """An atomic suffix view strictly after an exclusive sequence cursor."""

    events: tuple[InvestigationEvent, ...]
    cursor: int
    terminal: bool


@dataclass(frozen=True, slots=True)
class _EncodedSnapshot:
    events: tuple[bytes, ...]
    cursor: int
    terminal: bool


@dataclass(slots=True)
class _JournalState:
    condition: asyncio.Condition = field(default_factory=asyncio.Condition)
    events: list[bytes] = field(default_factory=list)
    generation: int = 0
    terminal: bool = False


def _validated_event(event: InvestigationEvent) -> tuple[InvestigationEvent, bytes]:
    payload = canonical_json_bytes(event)
    return decode_contract(payload, InvestigationEvent), payload


def _is_terminal(event: InvestigationEvent) -> bool:
    return (
        event.type is InvestigationEventType.LIFECYCLE
        and isinstance(event.payload, LifecycleEventPayload)
        and event.payload.status is InvestigationStatus.COMPLETED
    )


def _validate_cursor(
    investigation_id: str,
    after: object,
    latest: int,
) -> int:
    if (
        isinstance(after, bool)
        or not isinstance(after, int)
        or after < 0
        or after > latest
    ):
        raise InvalidCursor(investigation_id, after, latest)
    return after


def _encoded_snapshot_locked(
    investigation_id: str,
    state: _JournalState,
    after: object,
) -> _EncodedSnapshot:
    latest = len(state.events)
    cursor = _validate_cursor(investigation_id, after, latest)
    return _EncodedSnapshot(
        events=tuple(state.events[cursor:]),
        cursor=latest,
        terminal=state.terminal,
    )


def _decode_snapshot(snapshot: _EncodedSnapshot) -> EventJournalSnapshot:
    return EventJournalSnapshot(
        events=tuple(
            decode_contract(payload, InvestigationEvent) for payload in snapshot.events
        ),
        cursor=snapshot.cursor,
        terminal=snapshot.terminal,
    )


async def _wait_for_generation_or_cancellation(
    state: _JournalState,
    generation: int,
    cancellation_event: asyncio.Event,
) -> None:
    notified = asyncio.create_task(
        state.condition.wait_for(lambda: state.generation != generation)
    )
    cancelled = asyncio.create_task(cancellation_event.wait())
    tasks = (notified, cancelled)
    try:
        done, _ = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
        if cancelled in done and cancellation_event.is_set():
            raise asyncio.CancelledError
        await notified
    finally:
        for task in tasks:
            if not task.done():
                task.cancel()
        for task in tasks:
            with suppress(asyncio.CancelledError):
                await task


class InMemoryInvestigationEventJournal:
    """Retain canonical event bytes and wake resumable readers without loss."""

    def __init__(self) -> None:
        self._journals: dict[str, _JournalState] = {}
        self._registry_lock = asyncio.Lock()

    async def register(self, investigation_id: str) -> None:
        """Atomically register one initially empty investigation journal."""

        async with self._registry_lock:
            if investigation_id in self._journals:
                raise JournalAlreadyRegistered(investigation_id)
            self._journals[investigation_id] = _JournalState()

    async def _get_state(self, investigation_id: str) -> _JournalState:
        async with self._registry_lock:
            state = self._journals.get(investigation_id)
            if state is None:
                raise JournalNotFound(investigation_id)
            return state

    async def append(self, event: InvestigationEvent) -> InvestigationEvent:
        """Append exactly the next event and return an isolated validated copy."""

        validated, payload = _validated_event(event)
        state = await self._get_state(validated.investigation_id)
        async with state.condition:
            if len(state.events) >= MAX_INVESTIGATION_EVENTS:
                raise JournalCapacityExceeded(validated.investigation_id)

            expected_sequence = len(state.events) + 1
            if validated.sequence < expected_sequence:
                raise DuplicateEvent(
                    validated.investigation_id,
                    expected_sequence,
                    validated.sequence,
                )
            if validated.sequence > expected_sequence:
                raise OutOfOrderEvent(
                    validated.investigation_id,
                    expected_sequence,
                    validated.sequence,
                )
            if state.terminal:
                raise TerminalEventJournal(validated.investigation_id)

            state.events.append(payload)
            state.generation += 1
            state.terminal = _is_terminal(validated)
            state.condition.notify_all()

        return decode_contract(payload, InvestigationEvent)

    async def snapshot(
        self,
        investigation_id: str,
        after: int = 0,
    ) -> EventJournalSnapshot:
        """Return the atomic suffix strictly after ``after`` and latest cursor."""

        state = await self._get_state(investigation_id)
        async with state.condition:
            encoded = _encoded_snapshot_locked(investigation_id, state, after)
        return _decode_snapshot(encoded)

    async def wait_for_events(
        self,
        investigation_id: str,
        after: int = 0,
        *,
        cancellation_event: asyncio.Event | None = None,
    ) -> EventJournalSnapshot:
        """Wait for a suffix or terminal state without a snapshot/wait race."""

        state = await self._get_state(investigation_id)
        async with state.condition:
            while True:
                encoded = _encoded_snapshot_locked(
                    investigation_id,
                    state,
                    after,
                )
                if encoded.events or encoded.terminal:
                    break
                if cancellation_event is not None and cancellation_event.is_set():
                    raise asyncio.CancelledError

                generation = state.generation
                if cancellation_event is None:
                    await state.condition.wait_for(
                        lambda generation=generation: state.generation != generation
                    )
                else:
                    await _wait_for_generation_or_cancellation(
                        state,
                        generation,
                        cancellation_event,
                    )

        return _decode_snapshot(encoded)
