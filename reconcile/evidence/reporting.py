"""Stable report assembly from sealed deterministic evidence output."""

from __future__ import annotations

from collections import defaultdict
from datetime import datetime

from reconcile.contracts import (
    INVESTIGATION_REPORT_VERSION,
    AdvisoryExplanation,
    EvidenceDisposition,
    ExecutionEnvelope,
    InvestigationReport,
    InvestigationStatus,
    ProbeAuditRecord,
    canonical_json_bytes,
    canonical_sha256,
    decode_contract,
)
from reconcile.controller import ControllerAuditRecord
from reconcile.evidence.classification import CoreEvaluation


def build_report(
    envelope: ExecutionEnvelope,
    audit_trail: tuple[ControllerAuditRecord, ...],
    evaluation: CoreEvaluation,
    *,
    created_at: datetime,
    updated_at: datetime,
    revision: int,
    advisory_explanation: AdvisoryExplanation | None = None,
) -> InvestigationReport:
    """Build a completed report without accepting model-authored authority fields."""

    envelope = decode_contract(canonical_json_bytes(envelope), ExecutionEnvelope)
    if type(evaluation) is not CoreEvaluation or not evaluation.is_engine_output():
        raise TypeError("report assembly accepts only sealed core evaluations")
    envelope_sha256 = canonical_sha256(envelope)
    if evaluation.envelope_sha256 != envelope_sha256:
        raise ValueError("core evaluation belongs to a different envelope")
    if any(type(record) is not ControllerAuditRecord for record in audit_trail):
        raise TypeError("report audit accepts only controller audit records")
    audit_trail = tuple(sorted(audit_trail, key=lambda record: record.sequence))
    if [record.sequence for record in audit_trail] != list(
        range(1, len(audit_trail) + 1)
    ):
        raise ValueError("controller audit sequence must be contiguous")
    audit_by_sequence = {record.sequence: record for record in audit_trail}
    attempt_sequences = [attempt.probe_sequence for attempt in evaluation.attempts]
    if attempt_sequences != [record.sequence for record in audit_trail]:
        raise ValueError("every controller audit record requires one evidence attempt")
    evidence_ids_by_sequence: dict[int, list[str]] = defaultdict(list)
    for attempt in evaluation.attempts:
        if attempt.probe_sequence not in audit_by_sequence:
            raise ValueError("evidence attempt has no controller audit record")
        if (
            canonical_sha256(audit_by_sequence[attempt.probe_sequence])
            != attempt.controller_audit_sha256
        ):
            raise ValueError("evidence attempt audit does not match the controller")
        evidence_ids_by_sequence[attempt.probe_sequence].append(
            attempt.decision.evidence_id
        )

    report_audit = tuple(
        ProbeAuditRecord(
            probe_sequence=record.sequence,
            capability_name=record.capability_name,
            capability_version=record.capability_version,
            request_sha256=record.request_sha256,
            target_sha256=record.target_sha256,
            outcome=record.outcome,
            started_at=record.started_at,
            completed_at=record.completed_at,
            session_elapsed_ms=record.session_elapsed_ms,
            probe_count_used=record.probe_count_used,
            cost_units_used=record.cost_units_used,
            result_bytes_acquired=record.result_bytes_acquired,
            result_sha256=record.result_sha256,
            result_byte_count=record.result_byte_count,
            evidence_ids=tuple(sorted(evidence_ids_by_sequence[record.sequence])),
            stop_reason=record.stop_reason.value,
        )
        for record in audit_trail
    )

    if advisory_explanation is not None:
        advisory_explanation = AdvisoryExplanation.model_validate(advisory_explanation)
        explainable = {
            decision.evidence_id
            for decision in evaluation.decisions
            if decision.disposition
            in {EvidenceDisposition.ADMITTED, EvidenceDisposition.WEAK}
        }
        if not set(advisory_explanation.cited_evidence_ids) <= explainable:
            advisory_explanation = None

    limitations = ("No mutation was retried or compensated.",)
    return InvestigationReport(
        schema_version=INVESTIGATION_REPORT_VERSION,
        investigation_id=envelope.investigation_id,
        envelope_sha256=envelope_sha256,
        status=InvestigationStatus.COMPLETED,
        probe_audit=report_audit,
        evidence=evaluation.evidence,
        evidence_decisions=evaluation.decisions,
        proof=evaluation.proof,
        classification=evaluation.classification,
        action_gate=evaluation.action_gates,
        missing_evidence=evaluation.missing_evidence,
        limitations=limitations,
        advisory_explanation=advisory_explanation,
        created_at=created_at,
        updated_at=updated_at,
        revision=revision,
    )


__all__ = ["build_report"]
