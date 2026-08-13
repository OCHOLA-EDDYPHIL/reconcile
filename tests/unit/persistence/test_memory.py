from __future__ import annotations

import asyncio
from datetime import timedelta

import pytest

from reconcile.contracts.codec import canonical_json_bytes
from reconcile.persistence.memory import InMemoryInvestigationRepository
from reconcile.persistence.repository import (
    DuplicateInvestigationId,
    InvestigationNotFound,
    RevisionConflict,
)
from tests.unit.persistence._support import (
    FIXED_TIME,
    make_record,
    next_report,
)


@pytest.mark.unit
def test_create_is_idempotent_for_the_exact_envelope() -> None:
    async def scenario() -> None:
        repository = InMemoryInvestigationRepository()
        original = make_record()
        replay = make_record(created_at=FIXED_TIME + timedelta(seconds=30))

        first = await repository.create(original)
        second = await repository.create(replay)

        assert first.created is True
        assert second.created is False
        assert canonical_json_bytes(second.record) == canonical_json_bytes(first.record)

    asyncio.run(scenario())


@pytest.mark.unit
def test_duplicate_identifier_conflict_preserves_the_original() -> None:
    async def scenario() -> None:
        repository = InMemoryInvestigationRepository()
        original = make_record()
        await repository.create(original)

        with pytest.raises(DuplicateInvestigationId):
            await repository.create(make_record(operation_id="operation-2"))

        stored = await repository.get(original.investigation_id)
        assert canonical_json_bytes(stored) == canonical_json_bytes(original)

    asyncio.run(scenario())


@pytest.mark.unit
def test_records_are_isolated_from_nested_mutation() -> None:
    async def scenario() -> None:
        repository = InMemoryInvestigationRepository()
        original = make_record()
        created = await repository.create(original)

        original.envelope.target.scope["project_id"] = "changed-before-read"
        created.record.envelope.target.scope["project_id"] = "changed-result"
        first_read = await repository.get(original.investigation_id)
        assert first_read.envelope.target.scope["project_id"] == "project-1"

        first_read.envelope.target.scope["project_id"] = "changed-read"
        second_read = await repository.get(original.investigation_id)
        assert second_read.envelope.target.scope["project_id"] == "project-1"

    asyncio.run(scenario())


@pytest.mark.unit
def test_compare_and_swap_advances_once_and_rejects_stale_revision() -> None:
    async def scenario() -> None:
        repository = InMemoryInvestigationRepository()
        record = make_record()
        await repository.create(record)

        replacement = await repository.replace_report(
            record.investigation_id,
            0,
            next_report(record),
        )
        assert replacement.revision == 1

        with pytest.raises(RevisionConflict) as conflict:
            await repository.replace_report(
                record.investigation_id,
                0,
                next_report(record, seconds_later=2),
            )
        assert conflict.value.actual_revision == 1

    asyncio.run(scenario())


@pytest.mark.unit
def test_replace_requires_the_next_revision_and_existing_record() -> None:
    async def scenario() -> None:
        repository = InMemoryInvestigationRepository()
        record = make_record()

        with pytest.raises(InvestigationNotFound):
            await repository.get(record.investigation_id)
        with pytest.raises(InvestigationNotFound):
            await repository.replace_report(
                record.investigation_id,
                0,
                next_report(record),
            )

        await repository.create(record)
        invalid_revision = next_report(record).model_copy(update={"revision": 2})
        with pytest.raises(ValueError, match="advance by one"):
            await repository.replace_report(
                record.investigation_id,
                0,
                invalid_revision,
            )

    asyncio.run(scenario())


@pytest.mark.unit
def test_concurrent_exact_creates_have_one_creator() -> None:
    async def scenario() -> None:
        repository = InMemoryInvestigationRepository()
        record = make_record()
        results = await asyncio.gather(
            repository.create(record),
            repository.create(record),
        )
        assert sorted(result.created for result in results) == [False, True]

    asyncio.run(scenario())


@pytest.mark.unit
def test_concurrent_report_replacements_have_one_winner() -> None:
    async def scenario() -> None:
        repository = InMemoryInvestigationRepository()
        record = make_record()
        await repository.create(record)

        results = await asyncio.gather(
            repository.replace_report(
                record.investigation_id,
                0,
                next_report(record, seconds_later=1),
            ),
            repository.replace_report(
                record.investigation_id,
                0,
                next_report(record, seconds_later=2),
            ),
            return_exceptions=True,
        )
        assert sum(not isinstance(result, Exception) for result in results) == 1
        assert sum(isinstance(result, RevisionConflict) for result in results) == 1

    asyncio.run(scenario())
