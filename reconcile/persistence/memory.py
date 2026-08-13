"""Deterministic in-memory investigation repository."""

from __future__ import annotations

import asyncio

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
)


def _validated_record(record: InvestigationRecord) -> tuple[InvestigationRecord, bytes]:
    payload = canonical_json_bytes(record)
    return decode_contract(payload, InvestigationRecord), payload


def _same_envelope(left: InvestigationRecord, right: InvestigationRecord) -> bool:
    return canonical_json_bytes(left.envelope) == canonical_json_bytes(right.envelope)


def _decode_stored(investigation_id: str, payload: bytes) -> InvestigationRecord:
    try:
        return decode_contract(payload, InvestigationRecord)
    except (TypeError, ValueError) as exc:
        raise CorruptStoredRecord(investigation_id) from exc


class InMemoryInvestigationRepository:
    """Serialize all mutations and retain canonical bytes instead of live models."""

    def __init__(self) -> None:
        self._records: dict[str, bytes] = {}
        self._lock = asyncio.Lock()

    async def create(self, record: InvestigationRecord) -> CreateResult:
        attempted, attempted_payload = _validated_record(record)
        async with self._lock:
            current_payload = self._records.get(attempted.investigation_id)
            if current_payload is None:
                self._records[attempted.investigation_id] = attempted_payload
                return CreateResult(
                    record=decode_contract(attempted_payload, InvestigationRecord),
                    created=True,
                )

            current = _decode_stored(attempted.investigation_id, current_payload)
            if not _same_envelope(current, attempted):
                raise DuplicateInvestigationId(attempted.investigation_id)
            return CreateResult(record=current, created=False)

    async def get(self, investigation_id: str) -> InvestigationRecord:
        async with self._lock:
            payload = self._records.get(investigation_id)
            if payload is None:
                raise InvestigationNotFound(investigation_id)
            return _decode_stored(investigation_id, payload)

    async def replace_report(
        self,
        investigation_id: str,
        expected_revision: int,
        report: InvestigationReport,
    ) -> InvestigationRecord:
        async with self._lock:
            current_payload = self._records.get(investigation_id)
            if current_payload is None:
                raise InvestigationNotFound(investigation_id)
            current = _decode_stored(investigation_id, current_payload)
            if current.revision != expected_revision:
                raise RevisionConflict(
                    investigation_id,
                    expected_revision,
                    current.revision,
                )
            if report.revision != expected_revision + 1:
                raise ValueError("replacement report revision must advance by one")

            replacement, replacement_payload = _validated_record(
                InvestigationRecord(
                    schema_version=INVESTIGATION_RECORD_VERSION,
                    investigation_id=investigation_id,
                    envelope=current.envelope,
                    envelope_sha256=current.envelope_sha256,
                    report=report,
                    revision=report.revision,
                )
            )
            self._records[investigation_id] = replacement_payload
            return replacement
