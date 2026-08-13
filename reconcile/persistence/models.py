"""Internal versioned records stored by investigation repositories."""

from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import Field, model_validator

from reconcile.contracts.base import Identifier, Sha256Digest, StrictModel
from reconcile.contracts.codec import canonical_sha256
from reconcile.contracts.envelope import ExecutionEnvelope
from reconcile.contracts.report import (
    INVESTIGATION_REPORT_VERSION,
    InvestigationReport,
    InvestigationStatus,
)

INVESTIGATION_RECORD_VERSION = "reconcile/investigation-record/v1"


class InvestigationRecord(StrictModel):
    """One envelope and the current revision of its investigation report."""

    schema_version: Literal[INVESTIGATION_RECORD_VERSION]
    investigation_id: Identifier
    envelope: ExecutionEnvelope
    envelope_sha256: Sha256Digest
    report: InvestigationReport
    revision: int = Field(ge=0, le=2**63 - 1)

    @model_validator(mode="after")
    def validate_references(self) -> InvestigationRecord:
        if self.investigation_id != self.envelope.investigation_id:
            raise ValueError("record and envelope investigation identifiers must match")
        if self.investigation_id != self.report.investigation_id:
            raise ValueError("record and report investigation identifiers must match")
        if self.envelope_sha256 != canonical_sha256(self.envelope):
            raise ValueError("record envelope digest does not match the envelope")
        if self.report.envelope_sha256 != self.envelope_sha256:
            raise ValueError("report envelope digest does not match the record")
        if self.revision != self.report.revision:
            raise ValueError("record and report revisions must match")
        return self


def new_investigation_record(
    envelope: ExecutionEnvelope,
    *,
    created_at: datetime,
) -> InvestigationRecord:
    """Create the initial persisted record for an execution envelope."""

    envelope_sha256 = canonical_sha256(envelope)
    report = InvestigationReport(
        schema_version=INVESTIGATION_REPORT_VERSION,
        investigation_id=envelope.investigation_id,
        envelope_sha256=envelope_sha256,
        status=InvestigationStatus.CREATED,
        created_at=created_at,
        updated_at=created_at,
        revision=0,
    )
    return InvestigationRecord(
        schema_version=INVESTIGATION_RECORD_VERSION,
        investigation_id=envelope.investigation_id,
        envelope=envelope,
        envelope_sha256=envelope_sha256,
        report=report,
        revision=0,
    )
