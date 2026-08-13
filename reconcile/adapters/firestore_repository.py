"""Provider-neutral Firestore document adapter for investigation records."""

from __future__ import annotations

from hashlib import sha256
from typing import Literal, Protocol

from pydantic import Field, JsonValue, ValidationError, field_validator

from reconcile.contracts.base import Identifier, Sha256Digest, StrictModel
from reconcile.contracts.codec import canonical_json_bytes, decode_contract
from reconcile.contracts.report import InvestigationReport
from reconcile.persistence.models import (
    INVESTIGATION_RECORD_VERSION,
    InvestigationRecord,
)
from reconcile.persistence.repository import (
    CorruptStoredRecord,
    CreateResult,
    DuplicateInvestigationId,
    InvestigationNotFound,
    RevisionConflict,
    WriteOutcomeUnknown,
)

FIRESTORE_DOCUMENT_VERSION = "reconcile/firestore-investigation-document/v1"
FIRESTORE_CANONICAL_RECORD_BYTE_CEILING = 1_000_000


class FirestoreDocumentPort(Protocol):
    """Atomic, strongly consistent operations supplied by provider integration code."""

    async def read(self, document_key: str) -> dict[str, JsonValue] | None:
        """Strongly read one document after writes completed before this call."""

    async def create_if_absent(
        self,
        document_key: str,
        document: dict[str, JsonValue],
    ) -> bool:
        """Create atomically; false proves it already existed, unknown raises."""

    async def compare_and_swap(
        self,
        document_key: str,
        expected_revision: int,
        document: dict[str, JsonValue],
    ) -> bool:
        """Replace atomically; false proves a revision mismatch, unknown raises."""


class _FirestoreStoredDocument(StrictModel):
    schema_version: Literal[FIRESTORE_DOCUMENT_VERSION]
    investigation_id: Identifier
    revision: int = Field(ge=0, le=2**63 - 1)
    canonical_record: str = Field(min_length=1, max_length=1_000_000)
    record_sha256: Sha256Digest
    envelope_sha256: Sha256Digest

    @field_validator("canonical_record")
    @classmethod
    def validate_record_size(cls, value: str) -> str:
        if len(value.encode("utf-8")) > FIRESTORE_CANONICAL_RECORD_BYTE_CEILING:
            raise ValueError("canonical record exceeds the Firestore byte ceiling")
        return value


def firestore_document_key(investigation_id: str) -> str:
    """Derive a fixed-size document key from an investigation identifier."""

    return sha256(investigation_id.encode("utf-8")).hexdigest()


def _canonical_record(record: InvestigationRecord) -> tuple[InvestigationRecord, bytes]:
    payload = canonical_json_bytes(record)
    return decode_contract(payload, InvestigationRecord), payload


def _same_envelope(left: InvestigationRecord, right: InvestigationRecord) -> bool:
    return canonical_json_bytes(left.envelope) == canonical_json_bytes(right.envelope)


def _document_for(
    record: InvestigationRecord,
) -> tuple[InvestigationRecord, bytes, dict[str, JsonValue]]:
    validated, payload = _canonical_record(record)
    stored = _FirestoreStoredDocument(
        schema_version=FIRESTORE_DOCUMENT_VERSION,
        investigation_id=validated.investigation_id,
        revision=validated.revision,
        canonical_record=payload.decode("utf-8"),
        record_sha256=sha256(payload).hexdigest(),
        envelope_sha256=validated.envelope_sha256,
    )
    document: dict[str, JsonValue] = stored.model_dump(mode="json")
    return validated, payload, document


def _record_from_document(
    investigation_id: str,
    document: dict[str, JsonValue],
) -> tuple[InvestigationRecord, bytes]:
    try:
        stored = _FirestoreStoredDocument.model_validate(document)
        if stored.investigation_id != investigation_id:
            raise ValueError("stored investigation identifier does not match the key")
        payload = stored.canonical_record.encode("utf-8")
        if sha256(payload).hexdigest() != stored.record_sha256:
            raise ValueError("stored record digest does not match its payload")
        record = decode_contract(payload, InvestigationRecord)
        canonical_payload = canonical_json_bytes(record)
        if canonical_payload != payload:
            raise ValueError("stored record is not in canonical form")
        if record.investigation_id != investigation_id:
            raise ValueError("nested investigation identifier does not match")
        if record.revision != stored.revision:
            raise ValueError("stored and nested revisions do not match")
        if record.envelope_sha256 != stored.envelope_sha256:
            raise ValueError("stored and nested envelope digests do not match")
    except (TypeError, ValueError, ValidationError) as exc:
        raise CorruptStoredRecord(investigation_id) from exc
    return record, payload


class FirestoreInvestigationRepository:
    """Investigation repository built on an injected atomic document boundary."""

    def __init__(self, port: FirestoreDocumentPort) -> None:
        self._port = port

    async def _read_optional(
        self,
        investigation_id: str,
    ) -> tuple[InvestigationRecord, bytes] | None:
        document = await self._port.read(firestore_document_key(investigation_id))
        if document is None:
            return None
        return _record_from_document(investigation_id, document)

    async def create(self, record: InvestigationRecord) -> CreateResult:
        attempted, attempted_payload, document = _document_for(record)
        key = firestore_document_key(attempted.investigation_id)
        try:
            created = await self._port.create_if_absent(key, document)
        except WriteOutcomeUnknown:
            return await self._resolve_create(attempted, attempted_payload)
        if type(created) is not bool:
            raise CorruptStoredRecord(attempted.investigation_id)
        if created:
            return CreateResult(record=attempted, created=True)
        return await self._resolve_create(attempted, attempted_payload)

    async def _resolve_create(
        self,
        attempted: InvestigationRecord,
        attempted_payload: bytes,
    ) -> CreateResult:
        current_result = await self._read_optional(attempted.investigation_id)
        if current_result is None:
            raise WriteOutcomeUnknown("create", attempted.investigation_id)
        current, current_payload = current_result
        if current_payload == attempted_payload:
            return CreateResult(record=current, created=False)
        if _same_envelope(current, attempted):
            return CreateResult(record=current, created=False)
        raise DuplicateInvestigationId(attempted.investigation_id)

    async def get(self, investigation_id: str) -> InvestigationRecord:
        current = await self._read_optional(investigation_id)
        if current is None:
            raise InvestigationNotFound(investigation_id)
        return current[0]

    async def replace_report(
        self,
        investigation_id: str,
        expected_revision: int,
        report: InvestigationReport,
    ) -> InvestigationRecord:
        current = await self.get(investigation_id)
        if current.revision != expected_revision:
            raise RevisionConflict(
                investigation_id,
                expected_revision,
                current.revision,
            )
        if report.revision != expected_revision + 1:
            raise ValueError("replacement report revision must advance by one")

        attempted, attempted_payload, document = _document_for(
            InvestigationRecord(
                schema_version=INVESTIGATION_RECORD_VERSION,
                investigation_id=investigation_id,
                envelope=current.envelope,
                envelope_sha256=current.envelope_sha256,
                report=report,
                revision=report.revision,
            )
        )
        key = firestore_document_key(investigation_id)
        try:
            replaced = await self._port.compare_and_swap(
                key,
                expected_revision,
                document,
            )
        except WriteOutcomeUnknown:
            return await self._resolve_replace(
                investigation_id,
                expected_revision,
                attempted_payload,
            )
        if type(replaced) is not bool:
            raise CorruptStoredRecord(investigation_id)
        if replaced:
            return attempted
        return await self._resolve_replace(
            investigation_id,
            expected_revision,
            attempted_payload,
        )

    async def _resolve_replace(
        self,
        investigation_id: str,
        expected_revision: int,
        attempted_payload: bytes,
    ) -> InvestigationRecord:
        current_result = await self._read_optional(investigation_id)
        if current_result is None:
            raise WriteOutcomeUnknown("replace_report", investigation_id)
        current, current_payload = current_result
        if current_payload == attempted_payload:
            return current
        if current.revision == expected_revision:
            raise WriteOutcomeUnknown("replace_report", investigation_id)
        raise RevisionConflict(
            investigation_id,
            expected_revision,
            current.revision,
        )


__all__ = [
    "FIRESTORE_CANONICAL_RECORD_BYTE_CEILING",
    "FIRESTORE_DOCUMENT_VERSION",
    "FirestoreDocumentPort",
    "FirestoreInvestigationRepository",
    "firestore_document_key",
]
