from __future__ import annotations

import asyncio
from datetime import UTC, datetime, timedelta

import pytest

from reconcile.contracts.api import (
    INVESTIGATION_EVENT_VERSION,
    MAX_INVESTIGATION_EVENTS,
    InvestigationEvent,
    InvestigationEventType,
    LifecycleEventPayload,
)
from reconcile.contracts.codec import canonical_json_bytes
from reconcile.contracts.report import InvestigationStatus
from reconcile.persistence.events import (
    DuplicateEvent,
    InMemoryInvestigationEventJournal,
    InvalidCursor,
    JournalAlreadyRegistered,
    JournalCapacityExceeded,
    JournalNotFound,
    OutOfOrderEvent,
    TerminalEventJournal,
)

FIXED_TIME = datetime(2026, 8, 13, 12, 0, tzinfo=UTC)


def _event(
    sequence: int,
    *,
    investigation_id: str = "investigation-1",
    status: InvestigationStatus = InvestigationStatus.CREATED,
) -> InvestigationEvent:
    return InvestigationEvent(
        schema_version=INVESTIGATION_EVENT_VERSION,
        investigation_id=investigation_id,
        sequence=sequence,
        type=InvestigationEventType.LIFECYCLE,
        occurred_at=FIXED_TIME + timedelta(microseconds=sequence),
        payload=LifecycleEventPayload(status=status),
    )


@pytest.mark.unit
def test_registration_is_explicit_and_missing_journals_are_distinct() -> None:
    async def scenario() -> None:
        journal = InMemoryInvestigationEventJournal()

        with pytest.raises(JournalNotFound):
            await journal.snapshot("investigation-1")
        with pytest.raises(JournalNotFound):
            await journal.append(_event(1))

        await journal.register("investigation-1")
        snapshot = await journal.snapshot("investigation-1")
        assert snapshot.events == ()
        assert snapshot.cursor == 0
        assert snapshot.terminal is False

        with pytest.raises(JournalAlreadyRegistered):
            await journal.register("investigation-1")

    asyncio.run(scenario())


@pytest.mark.unit
def test_append_retains_canonical_isolated_events_and_exclusive_suffixes() -> None:
    async def scenario() -> None:
        journal = InMemoryInvestigationEventJournal()
        await journal.register("investigation-1")
        first = _event(1)
        second = _event(
            2,
            status=InvestigationStatus.INVESTIGATING,
        )

        appended = await journal.append(first)
        await journal.append(second)
        full = await journal.snapshot("investigation-1")
        suffix = await journal.snapshot("investigation-1", after=1)
        current = await journal.snapshot("investigation-1", after=2)

        assert appended is not first
        assert canonical_json_bytes(appended) == canonical_json_bytes(first)
        assert [event.sequence for event in full.events] == [1, 2]
        assert full.events[0] is not appended
        assert full.cursor == 2
        assert full.terminal is False
        assert [event.sequence for event in suffix.events] == [2]
        assert suffix.cursor == 2
        assert current.events == ()
        assert current.cursor == 2

    asyncio.run(scenario())


@pytest.mark.unit
def test_duplicate_and_out_of_order_appends_preserve_contiguity() -> None:
    async def scenario() -> None:
        journal = InMemoryInvestigationEventJournal()
        await journal.register("investigation-1")

        with pytest.raises(OutOfOrderEvent) as skipped:
            await journal.append(_event(2))
        assert skipped.value.expected_sequence == 1
        assert skipped.value.actual_sequence == 2

        await journal.append(_event(1))
        with pytest.raises(DuplicateEvent) as duplicate:
            await journal.append(_event(1))
        assert duplicate.value.sequence == 1

        snapshot = await journal.snapshot("investigation-1")
        assert [event.sequence for event in snapshot.events] == [1]

    asyncio.run(scenario())


@pytest.mark.unit
def test_concurrent_same_sequence_append_has_one_winner() -> None:
    async def scenario() -> None:
        journal = InMemoryInvestigationEventJournal()
        await journal.register("investigation-1")

        results = await asyncio.gather(
            journal.append(_event(1)),
            journal.append(_event(1)),
            return_exceptions=True,
        )
        assert sum(isinstance(result, InvestigationEvent) for result in results) == 1
        assert sum(isinstance(result, DuplicateEvent) for result in results) == 1

        await journal.append(
            _event(
                2,
                status=InvestigationStatus.INVESTIGATING,
            )
        )
        snapshot = await journal.snapshot("investigation-1")
        assert [event.sequence for event in snapshot.events] == [1, 2]

    asyncio.run(scenario())


@pytest.mark.unit
@pytest.mark.parametrize("cursor", [-1, 1, True, "0"])
def test_snapshot_rejects_cursors_outside_the_current_journal(cursor: object) -> None:
    async def scenario() -> None:
        journal = InMemoryInvestigationEventJournal()
        await journal.register("investigation-1")

        with pytest.raises(InvalidCursor) as invalid:
            await journal.snapshot("investigation-1", after=cursor)  # type: ignore[arg-type]
        assert invalid.value.cursor == cursor
        assert invalid.value.latest == 0

    asyncio.run(scenario())


@pytest.mark.unit
def test_wait_observes_append_without_a_snapshot_notification_gap() -> None:
    async def scenario() -> None:
        journal = InMemoryInvestigationEventJournal()
        await journal.register("investigation-1")

        waiting = asyncio.create_task(journal.wait_for_events("investigation-1"))
        await asyncio.sleep(0)
        await journal.append(_event(1))
        snapshot = await asyncio.wait_for(waiting, timeout=1)

        assert [event.sequence for event in snapshot.events] == [1]
        assert snapshot.cursor == 1

    asyncio.run(scenario())


@pytest.mark.unit
def test_slow_consumer_can_resume_without_dropped_events() -> None:
    async def scenario() -> None:
        journal = InMemoryInvestigationEventJournal()
        await journal.register("investigation-1")
        for sequence in range(1, 7):
            await journal.append(_event(sequence))

        first_page = await journal.snapshot("investigation-1", after=0)
        resumed = await journal.snapshot("investigation-1", after=2)

        assert [event.sequence for event in first_page.events] == list(range(1, 7))
        assert [event.sequence for event in resumed.events] == list(range(3, 7))
        assert resumed.cursor == 6

    asyncio.run(scenario())


@pytest.mark.unit
def test_cancelled_waiter_does_not_consume_a_later_event() -> None:
    async def scenario() -> None:
        journal = InMemoryInvestigationEventJournal()
        await journal.register("investigation-1")
        waiting = asyncio.create_task(journal.wait_for_events("investigation-1"))
        await asyncio.sleep(0)

        waiting.cancel()
        with pytest.raises(asyncio.CancelledError):
            await waiting

        await journal.append(_event(1))
        resumed = await journal.snapshot("investigation-1", after=0)
        assert [event.sequence for event in resumed.events] == [1]

    asyncio.run(scenario())


@pytest.mark.unit
def test_explicit_wait_cancellation_preserves_accepted_events() -> None:
    async def scenario() -> None:
        journal = InMemoryInvestigationEventJournal()
        await journal.register("investigation-1")
        cancellation = asyncio.Event()
        waiting = asyncio.create_task(
            journal.wait_for_events(
                "investigation-1",
                cancellation_event=cancellation,
            )
        )
        await asyncio.sleep(0)

        cancellation.set()
        with pytest.raises(asyncio.CancelledError):
            await asyncio.wait_for(waiting, timeout=1)

        await journal.append(_event(1))
        resumed = await journal.snapshot("investigation-1", after=0)
        assert [event.sequence for event in resumed.events] == [1]

    asyncio.run(scenario())


@pytest.mark.unit
def test_completed_lifecycle_terminalizes_replay_and_waiting() -> None:
    async def scenario() -> None:
        journal = InMemoryInvestigationEventJournal()
        await journal.register("investigation-1")
        await journal.append(_event(1))
        await journal.append(
            _event(
                2,
                status=InvestigationStatus.INVESTIGATING,
            )
        )
        await journal.append(
            _event(
                3,
                status=InvestigationStatus.COMPLETED,
            )
        )

        replay = await journal.snapshot("investigation-1", after=3)
        waited = await journal.wait_for_events("investigation-1", after=3)
        assert replay.events == waited.events == ()
        assert replay.cursor == waited.cursor == 3
        assert replay.terminal is waited.terminal is True

        with pytest.raises(TerminalEventJournal):
            await journal.append(_event(4))

    asyncio.run(scenario())


@pytest.mark.unit
def test_journal_count_is_bounded_by_the_public_event_contract() -> None:
    async def scenario() -> None:
        journal = InMemoryInvestigationEventJournal()
        await journal.register("investigation-1")
        for sequence in range(1, MAX_INVESTIGATION_EVENTS + 1):
            await journal.append(_event(sequence))

        snapshot = await journal.snapshot("investigation-1")
        assert snapshot.cursor == MAX_INVESTIGATION_EVENTS
        assert len(snapshot.events) == MAX_INVESTIGATION_EVENTS
        with pytest.raises(JournalCapacityExceeded) as exhausted:
            await journal.append(_event(MAX_INVESTIGATION_EVENTS))
        assert exhausted.value.limit == MAX_INVESTIGATION_EVENTS

    asyncio.run(scenario())
