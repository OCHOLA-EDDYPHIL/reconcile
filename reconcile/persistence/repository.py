"""Provider-neutral asynchronous investigation repository boundary."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol

from reconcile.contracts.report import InvestigationReport
from reconcile.persistence.models import InvestigationRecord


class RepositoryError(Exception):
    """Base class for deterministic persistence-boundary failures."""


class DuplicateInvestigationId(RepositoryError):
    """An identifier is already bound to a different execution envelope."""

    def __init__(self, investigation_id: str) -> None:
        self.investigation_id = investigation_id
        super().__init__(
            f"investigation identifier is already in use: {investigation_id}"
        )


class InvestigationNotFound(RepositoryError):
    """No persisted investigation has the requested identifier."""

    def __init__(self, investigation_id: str) -> None:
        self.investigation_id = investigation_id
        super().__init__(f"investigation does not exist: {investigation_id}")


class RevisionConflict(RepositoryError):
    """A report replacement did not match the current persisted revision."""

    def __init__(
        self,
        investigation_id: str,
        expected_revision: int,
        actual_revision: int,
    ) -> None:
        self.investigation_id = investigation_id
        self.expected_revision = expected_revision
        self.actual_revision = actual_revision
        super().__init__(
            "revision conflict for "
            f"{investigation_id}: expected {expected_revision}, "
            f"found {actual_revision}"
        )


class CorruptStoredRecord(RepositoryError):
    """A provider returned a record that fails the repository contract."""

    def __init__(self, investigation_id: str) -> None:
        self.investigation_id = investigation_id
        super().__init__(f"stored investigation record is invalid: {investigation_id}")


class WriteOutcomeUnknown(RepositoryError):
    """A storage write response was lost and readback cannot prove its outcome."""

    def __init__(self, operation: str, investigation_id: str) -> None:
        self.operation = operation
        self.investigation_id = investigation_id
        super().__init__(
            f"{operation} outcome is unknown for investigation {investigation_id}"
        )


@dataclass(frozen=True, slots=True)
class CreateResult:
    record: InvestigationRecord
    created: bool


class InvestigationRepository(Protocol):
    async def create(self, record: InvestigationRecord) -> CreateResult:
        """Create a record or return the current record for an envelope replay."""

    async def get(self, investigation_id: str) -> InvestigationRecord:
        """Return an isolated validated copy of the current record."""

    async def replace_report(
        self,
        investigation_id: str,
        expected_revision: int,
        report: InvestigationReport,
    ) -> InvestigationRecord:
        """Replace the report when the current revision matches."""
