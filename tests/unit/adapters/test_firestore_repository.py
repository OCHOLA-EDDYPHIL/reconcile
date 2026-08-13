from __future__ import annotations

import asyncio
from copy import deepcopy
from hashlib import sha256

import pytest
from pydantic import JsonValue, ValidationError

from reconcile.adapters.firestore_repository import (
    FIRESTORE_DOCUMENT_VERSION,
    FirestoreInvestigationRepository,
    firestore_document_key,
)
from reconcile.persistence.repository import (
    CorruptStoredRecord,
    DuplicateInvestigationId,
    RevisionConflict,
    WriteOutcomeUnknown,
)
from tests.unit.persistence._support import make_record, next_report


def _assert_json_value(value: JsonValue) -> None:
    if value is None or type(value) in {bool, int, float, str}:
        return
    if isinstance(value, list):
        for item in value:
            _assert_json_value(item)
        return
    if isinstance(value, dict):
        assert all(isinstance(key, str) for key in value)
        for item in value.values():
            _assert_json_value(item)
        return
    raise AssertionError(f"non-JSON provider value: {type(value)!r}")


class FakeFirestoreDocumentPort:
    def __init__(self) -> None:
        self.documents: dict[str, dict[str, JsonValue]] = {}
        self.create_outcome = "normal"
        self.replace_outcome = "normal"
        self.written_keys: list[str] = []

    async def read(self, document_key: str) -> dict[str, JsonValue] | None:
        document = self.documents.get(document_key)
        return deepcopy(document) if document is not None else None

    async def create_if_absent(
        self,
        document_key: str,
        document: dict[str, JsonValue],
    ) -> bool:
        _assert_json_value(document)
        self.written_keys.append(document_key)
        if self.create_outcome == "unknown-before":
            raise WriteOutcomeUnknown("create", "provider")
        if document_key in self.documents:
            return False
        self.documents[document_key] = deepcopy(document)
        if self.create_outcome == "unknown-after":
            raise WriteOutcomeUnknown("create", "provider")
        return True

    async def compare_and_swap(
        self,
        document_key: str,
        expected_revision: int,
        document: dict[str, JsonValue],
    ) -> bool:
        _assert_json_value(document)
        self.written_keys.append(document_key)
        current = self.documents.get(document_key)
        if self.replace_outcome == "unknown-absent":
            self.documents.pop(document_key, None)
            raise WriteOutcomeUnknown("replace_report", "provider")
        if self.replace_outcome == "unknown-before":
            raise WriteOutcomeUnknown("replace_report", "provider")
        if current is None or current["revision"] != expected_revision:
            return False
        self.documents[document_key] = deepcopy(document)
        if self.replace_outcome == "unknown-after":
            raise WriteOutcomeUnknown("replace_report", "provider")
        return True


@pytest.mark.unit
def test_create_uses_hashed_key_and_json_primitive_document() -> None:
    async def scenario() -> None:
        port = FakeFirestoreDocumentPort()
        repository = FirestoreInvestigationRepository(port)
        record = make_record()

        result = await repository.create(record)
        key = sha256(record.investigation_id.encode("utf-8")).hexdigest()

        assert result.created is True
        assert port.written_keys == [key]
        assert firestore_document_key(record.investigation_id) == key
        assert port.documents[key]["schema_version"] == FIRESTORE_DOCUMENT_VERSION

        replay = await repository.create(record)
        assert replay.created is False
        assert replay.record == result.record

    asyncio.run(scenario())


@pytest.mark.unit
def test_ambiguous_create_is_resolved_only_by_exact_readback() -> None:
    async def scenario() -> None:
        committed_port = FakeFirestoreDocumentPort()
        committed_port.create_outcome = "unknown-after"
        committed_repository = FirestoreInvestigationRepository(committed_port)
        committed = await committed_repository.create(make_record())
        assert committed.created is False

        absent_port = FakeFirestoreDocumentPort()
        absent_port.create_outcome = "unknown-before"
        absent_repository = FirestoreInvestigationRepository(absent_port)
        with pytest.raises(WriteOutcomeUnknown):
            await absent_repository.create(make_record())

    asyncio.run(scenario())


@pytest.mark.unit
def test_conflicting_identifier_is_rejected_without_overwrite() -> None:
    async def scenario() -> None:
        port = FakeFirestoreDocumentPort()
        repository = FirestoreInvestigationRepository(port)
        original = make_record()
        await repository.create(original)
        key = firestore_document_key(original.investigation_id)
        before = deepcopy(port.documents[key])

        with pytest.raises(DuplicateInvestigationId):
            await repository.create(make_record(operation_id="operation-2"))
        assert port.documents[key] == before

    asyncio.run(scenario())


@pytest.mark.unit
def test_ambiguous_compare_and_swap_uses_exact_readback() -> None:
    async def scenario() -> None:
        committed_port = FakeFirestoreDocumentPort()
        committed_repository = FirestoreInvestigationRepository(committed_port)
        record = make_record()
        await committed_repository.create(record)
        committed_port.replace_outcome = "unknown-after"

        replacement = await committed_repository.replace_report(
            record.investigation_id,
            0,
            next_report(record),
        )
        assert replacement.revision == 1

        unchanged_port = FakeFirestoreDocumentPort()
        unchanged_repository = FirestoreInvestigationRepository(unchanged_port)
        await unchanged_repository.create(record)
        unchanged_port.replace_outcome = "unknown-before"
        with pytest.raises(WriteOutcomeUnknown):
            await unchanged_repository.replace_report(
                record.investigation_id,
                0,
                next_report(record),
            )

        absent_port = FakeFirestoreDocumentPort()
        absent_repository = FirestoreInvestigationRepository(absent_port)
        await absent_repository.create(record)
        absent_port.replace_outcome = "unknown-absent"
        with pytest.raises(WriteOutcomeUnknown):
            await absent_repository.replace_report(
                record.investigation_id,
                0,
                next_report(record),
            )

    asyncio.run(scenario())


@pytest.mark.unit
def test_concurrent_compare_and_swap_has_one_winner() -> None:
    async def scenario() -> None:
        port = FakeFirestoreDocumentPort()
        repository = FirestoreInvestigationRepository(port)
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


@pytest.mark.unit
def test_invalid_or_noncanonical_provider_document_is_corrupt() -> None:
    async def scenario() -> None:
        port = FakeFirestoreDocumentPort()
        repository = FirestoreInvestigationRepository(port)
        record = make_record()
        await repository.create(record)
        key = firestore_document_key(record.investigation_id)
        original_document = deepcopy(port.documents[key])

        port.documents[key]["schema_version"] = "reconcile/unknown/v1"
        with pytest.raises(CorruptStoredRecord):
            await repository.get(record.investigation_id)

        port.documents[key] = original_document
        canonical_record = port.documents[key]["canonical_record"]
        assert isinstance(canonical_record, str)
        noncanonical_record = f"{canonical_record}\n"
        port.documents[key]["canonical_record"] = noncanonical_record
        port.documents[key]["record_sha256"] = sha256(
            noncanonical_record.encode("utf-8")
        ).hexdigest()
        with pytest.raises(CorruptStoredRecord):
            await repository.get(record.investigation_id)

    asyncio.run(scenario())


@pytest.mark.unit
def test_outgoing_document_limit_is_measured_in_utf8_bytes() -> None:
    async def scenario() -> None:
        port = FakeFirestoreDocumentPort()
        repository = FirestoreInvestigationRepository(port)
        record = make_record()
        large_report = record.report.model_copy(
            update={"limitations": ("😀" * 4096,) * 64}
        )
        large_record = type(record)(
            schema_version=record.schema_version,
            investigation_id=record.investigation_id,
            envelope=record.envelope,
            envelope_sha256=record.envelope_sha256,
            report=large_report,
            revision=record.revision,
        )

        with pytest.raises(ValidationError, match="Firestore byte ceiling"):
            await repository.create(large_record)

        assert port.documents == {}

    asyncio.run(scenario())
