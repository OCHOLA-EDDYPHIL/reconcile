"""Persistence contracts and deterministic repository implementations."""

from reconcile.persistence.events import (
    DuplicateEvent,
    EventJournalError,
    EventJournalSnapshot,
    EventSequenceConflict,
    InMemoryInvestigationEventJournal,
    InvalidCursor,
    JournalAlreadyRegistered,
    JournalCapacityExceeded,
    JournalNotFound,
    OutOfOrderEvent,
    TerminalEventJournal,
)
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
    "DuplicateEvent",
    "DuplicateInvestigationId",
    "EventJournalError",
    "EventJournalSnapshot",
    "EventSequenceConflict",
    "InMemoryInvestigationEventJournal",
    "InMemoryInvestigationRepository",
    "InvalidCursor",
    "InvestigationNotFound",
    "InvestigationRecord",
    "InvestigationRepository",
    "JournalAlreadyRegistered",
    "JournalCapacityExceeded",
    "JournalNotFound",
    "OutOfOrderEvent",
    "RepositoryError",
    "RevisionConflict",
    "TerminalEventJournal",
    "WriteOutcomeUnknown",
    "new_investigation_record",
]
