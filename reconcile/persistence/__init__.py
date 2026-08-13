"""Persistence contracts and deterministic repository implementations."""

from reconcile.persistence.memory import InMemoryInvestigationRepository
from reconcile.persistence.models import (
    INVESTIGATION_RECORD_VERSION,
    InvestigationRecord,
    new_investigation_record,
)
from reconcile.persistence.repository import (
    CorruptStoredRecord,
    CreateResult,
    DuplicateInvestigationId,
    InvestigationNotFound,
    InvestigationRepository,
    RepositoryError,
    RevisionConflict,
    WriteOutcomeUnknown,
)

__all__ = [
    "INVESTIGATION_RECORD_VERSION",
    "CorruptStoredRecord",
    "CreateResult",
    "DuplicateInvestigationId",
    "InMemoryInvestigationRepository",
    "InvestigationNotFound",
    "InvestigationRecord",
    "InvestigationRepository",
    "RepositoryError",
    "RevisionConflict",
    "WriteOutcomeUnknown",
    "new_investigation_record",
]
