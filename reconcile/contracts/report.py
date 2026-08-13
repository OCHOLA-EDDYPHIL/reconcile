"""Investigation report and action-gate contracts."""

from __future__ import annotations

from enum import StrEnum
from typing import Literal

from pydantic import Field, model_validator

from reconcile.contracts.base import (
    AwareDatetime,
    Identifier,
    NonEmptyText,
    Sha256Digest,
    StrictModel,
)
from reconcile.contracts.common import Classification
from reconcile.contracts.envelope import ProbeRequest
from reconcile.contracts.evidence import (
    EffectAssertionState,
    EvidenceAuthority,
    EvidenceDecision,
    EvidenceDisposition,
    NormalizedEvidence,
    OperationStatus,
)

ACTION_GATE_RESULT_VERSION = "reconcile/action-gate-result/v1"
INVESTIGATION_REPORT_VERSION = "reconcile/investigation-report/v1"


class RequestedAction(StrEnum):
    CONTINUE = "CONTINUE"
    RETRY = "RETRY"
    COMPENSATE = "COMPENSATE"
    ESCALATE = "ESCALATE"
    OBSERVE = "OBSERVE"


class ActionGateReason(StrEnum):
    ALL_EFFECTS_ESTABLISHED = "all_effects_established"
    DUPLICATE_EFFECT_RISK = "duplicate_effect_risk"
    COMPENSATION_OUT_OF_SCOPE_V1 = "compensation_out_of_scope_v1"
    EXPLICIT_RETRY_POLICY_REQUIRED = "explicit_retry_policy_required"
    OPERATOR_REVIEW_AVAILABLE = "operator_review_available"
    INCOMPLETE_EFFECT_SET = "incomplete_effect_set"
    OPERATOR_INTERVENTION_REQUIRED = "operator_intervention_required"
    OPERATION_ACTIVE = "operation_active"
    READ_ONLY_FOLLOW_UP = "read_only_follow_up"
    INSUFFICIENT_AUTHORITATIVE_EVIDENCE = "insufficient_authoritative_evidence"
    AMBIGUOUS_DUPLICATE_RISK = "ambiguous_duplicate_risk"


class ActionGateResult(StrictModel):
    schema_version: Literal[ACTION_GATE_RESULT_VERSION]
    requested_action: RequestedAction
    allowed: bool
    reason: ActionGateReason
    classification: Classification
    classification_policy_version: Identifier
    action_policy_version: Identifier
    escalation_required: bool

    @model_validator(mode="after")
    def validate_v1_safety(self) -> ActionGateResult:
        escalation_required = self.classification in {
            Classification.NOT_COMMITTED,
            Classification.PARTIAL,
            Classification.UNKNOWN,
        }
        if self.escalation_required is not escalation_required:
            raise ValueError("escalation requirement does not match classification")
        if (
            self.requested_action
            in {
                RequestedAction.RETRY,
                RequestedAction.COMPENSATE,
            }
            and self.allowed
        ):
            raise ValueError("retry and compensation are not executable in v1")
        if self.requested_action is RequestedAction.CONTINUE and self.allowed != (
            self.classification is Classification.COMMITTED
        ):
            raise ValueError("continuation is allowed exactly when committed")
        if (
            self.classification
            in {Classification.PARTIAL, Classification.PENDING, Classification.UNKNOWN}
            and self.requested_action
            in {
                RequestedAction.CONTINUE,
                RequestedAction.RETRY,
                RequestedAction.COMPENSATE,
            }
            and self.allowed
        ):
            raise ValueError("indeterminate classifications block mutation")
        if self.requested_action is RequestedAction.COMPENSATE:
            if self.reason is not ActionGateReason.COMPENSATION_OUT_OF_SCOPE_V1:
                raise ValueError("compensation requires the frozen v1 denial reason")
        elif self.requested_action is RequestedAction.RETRY:
            retry_reasons = {
                Classification.COMMITTED: ActionGateReason.DUPLICATE_EFFECT_RISK,
                Classification.NOT_COMMITTED: (
                    ActionGateReason.EXPLICIT_RETRY_POLICY_REQUIRED
                ),
                Classification.PARTIAL: ActionGateReason.DUPLICATE_EFFECT_RISK,
                Classification.PENDING: ActionGateReason.OPERATION_ACTIVE,
                Classification.UNKNOWN: ActionGateReason.AMBIGUOUS_DUPLICATE_RISK,
            }
            if self.reason is not retry_reasons[self.classification]:
                raise ValueError("retry reason does not match classification")
        elif self.requested_action is RequestedAction.CONTINUE:
            continue_reasons = {
                Classification.COMMITTED: ActionGateReason.ALL_EFFECTS_ESTABLISHED,
                Classification.PARTIAL: ActionGateReason.INCOMPLETE_EFFECT_SET,
                Classification.PENDING: ActionGateReason.OPERATION_ACTIVE,
                Classification.UNKNOWN: (
                    ActionGateReason.INSUFFICIENT_AUTHORITATIVE_EVIDENCE
                ),
            }
            expected = continue_reasons.get(self.classification)
            if expected is None or self.reason is not expected:
                raise ValueError("continuation reason does not match classification")
        elif self.requested_action is RequestedAction.OBSERVE:
            if (
                not self.allowed
                or self.reason is not ActionGateReason.READ_ONLY_FOLLOW_UP
            ):
                raise ValueError("observation must remain available and read-only")
        elif self.requested_action is RequestedAction.ESCALATE:
            escalation_reasons = {
                Classification.NOT_COMMITTED: ActionGateReason.OPERATOR_REVIEW_AVAILABLE,
                Classification.PARTIAL: ActionGateReason.OPERATOR_INTERVENTION_REQUIRED,
                Classification.PENDING: ActionGateReason.OPERATOR_INTERVENTION_REQUIRED,
                Classification.UNKNOWN: ActionGateReason.OPERATOR_INTERVENTION_REQUIRED,
            }
            expected = escalation_reasons.get(self.classification)
            if not self.allowed or expected is None or self.reason is not expected:
                raise ValueError("operator escalation must remain available")
        return self


class InvestigationStatus(StrEnum):
    CREATED = "CREATED"
    INVESTIGATING = "INVESTIGATING"
    COMPLETED = "COMPLETED"


class ProbeOutcome(StrEnum):
    COMPLETED = "COMPLETED"
    REJECTED = "REJECTED"
    TIMED_OUT = "TIMED_OUT"
    UNAVAILABLE = "UNAVAILABLE"
    CANCELLED = "CANCELLED"
    MALFORMED = "MALFORMED"
    BUDGET_EXHAUSTED = "BUDGET_EXHAUSTED"


class ProbeAuditRecord(StrictModel):
    probe_sequence: int = Field(ge=1, le=2**63 - 1)
    request: ProbeRequest
    outcome: ProbeOutcome
    started_at: AwareDatetime
    completed_at: AwareDatetime
    evidence_ids: tuple[Identifier, ...] = Field(default_factory=tuple, max_length=64)
    stop_reason: Identifier | None = None

    @model_validator(mode="after")
    def validate_record(self) -> ProbeAuditRecord:
        if self.completed_at < self.started_at:
            raise ValueError("probe completion cannot precede its start")
        if len(self.evidence_ids) != len(set(self.evidence_ids)):
            raise ValueError("probe evidence identifiers must be unique")
        return self


class EffectFinding(StrictModel):
    effect_id: Identifier
    commit_scope: Identifier
    state: EffectAssertionState
    evidence_ids: tuple[Identifier, ...] = Field(default_factory=tuple, max_length=64)

    @model_validator(mode="after")
    def validate_evidence_identity(self) -> EffectFinding:
        if len(self.evidence_ids) != len(set(self.evidence_ids)):
            raise ValueError("effect finding evidence identifiers must be unique")
        return self


class DeterministicProof(StrictModel):
    effect_findings: tuple[EffectFinding, ...] = Field(min_length=1, max_length=64)
    operation_status: OperationStatus | None = None
    conflicting_authority: bool = False
    admitted_evidence_ids: tuple[Identifier, ...] = Field(
        default_factory=tuple,
        max_length=128,
    )

    @model_validator(mode="after")
    def validate_findings(self) -> DeterministicProof:
        effect_ids = [finding.effect_id for finding in self.effect_findings]
        if len(effect_ids) != len(set(effect_ids)):
            raise ValueError("proof effect identifiers must be unique")
        if len(self.admitted_evidence_ids) != len(set(self.admitted_evidence_ids)):
            raise ValueError("admitted evidence identifiers must be unique")
        return self


class MissingEvidence(StrictModel):
    effect_ids: tuple[Identifier, ...] = Field(default_factory=tuple, max_length=64)
    reason: Identifier

    @model_validator(mode="after")
    def validate_effect_identity(self) -> MissingEvidence:
        if len(self.effect_ids) != len(set(self.effect_ids)):
            raise ValueError("missing effect identifiers must be unique")
        return self


class AdvisoryExplanation(StrictModel):
    text: NonEmptyText
    cited_evidence_ids: tuple[Identifier, ...] = Field(
        default_factory=tuple,
        max_length=128,
    )

    @model_validator(mode="after")
    def validate_citation_identity(self) -> AdvisoryExplanation:
        if len(self.cited_evidence_ids) != len(set(self.cited_evidence_ids)):
            raise ValueError("advisory evidence citations must be unique")
        return self


class InvestigationReport(StrictModel):
    schema_version: Literal[INVESTIGATION_REPORT_VERSION]
    investigation_id: Identifier
    envelope_sha256: Sha256Digest
    status: InvestigationStatus
    probe_audit: tuple[ProbeAuditRecord, ...] = Field(default_factory=tuple)
    evidence: tuple[NormalizedEvidence, ...] = Field(default_factory=tuple)
    evidence_decisions: tuple[EvidenceDecision, ...] = Field(default_factory=tuple)
    proof: DeterministicProof | None = None
    classification: Classification | None = None
    action_gate: tuple[ActionGateResult, ...] = Field(default_factory=tuple)
    missing_evidence: tuple[MissingEvidence, ...] = Field(default_factory=tuple)
    limitations: tuple[NonEmptyText, ...] = Field(default_factory=tuple)
    advisory_explanation: AdvisoryExplanation | None = None
    created_at: AwareDatetime
    updated_at: AwareDatetime
    revision: int = Field(ge=0, le=2**63 - 1)

    @model_validator(mode="after")
    def validate_references(self) -> InvestigationReport:
        if self.updated_at < self.created_at:
            raise ValueError("report update cannot precede creation")
        if self.status is InvestigationStatus.COMPLETED and (
            self.proof is None or self.classification is None or not self.action_gate
        ):
            raise ValueError(
                "completed reports require proof, classification, and action gates"
            )
        if self.classification is None and self.action_gate:
            raise ValueError("action gates require a classification")

        sequences = [record.probe_sequence for record in self.probe_audit]
        if sequences != list(range(1, len(sequences) + 1)):
            raise ValueError("probe audit sequence must be contiguous and ordered")

        evidence_ids = [item.evidence_id for item in self.evidence]
        if len(evidence_ids) != len(set(evidence_ids)):
            raise ValueError("evidence identifiers must be unique")
        decision_ids = [item.evidence_id for item in self.evidence_decisions]
        if len(decision_ids) != len(set(decision_ids)):
            raise ValueError("evidence decision identifiers must be unique")
        decision_by_id = {item.evidence_id: item for item in self.evidence_decisions}
        if not set(evidence_ids) <= set(decision_ids):
            raise ValueError("every normalized evidence item requires one decision")
        if any(
            decision.disposition is not EvidenceDisposition.REJECTED
            for evidence_id, decision in decision_by_id.items()
            if evidence_id not in set(evidence_ids)
        ):
            raise ValueError("only rejected attempts may omit normalized evidence")

        for record in self.probe_audit:
            if not set(record.evidence_ids) <= set(decision_ids):
                raise ValueError("probe audit references an unknown evidence decision")

        admitted = {
            decision.evidence_id
            for decision in self.evidence_decisions
            if decision.disposition is EvidenceDisposition.ADMITTED
        }
        weak = {
            decision.evidence_id
            for decision in self.evidence_decisions
            if decision.disposition is EvidenceDisposition.WEAK
        }
        evidence_by_id = {item.evidence_id: item for item in self.evidence}
        if any(
            evidence_by_id[evidence_id].authority is not EvidenceAuthority.TARGET_STATE
            for evidence_id in admitted
        ):
            raise ValueError("only target-state evidence can be admitted")
        if self.proof is not None:
            if not set(self.proof.admitted_evidence_ids) <= admitted:
                raise ValueError("proof references evidence that was not admitted")
            for finding in self.proof.effect_findings:
                if not set(finding.evidence_ids) <= admitted:
                    raise ValueError("effect finding references evidence not admitted")
        if (
            self.advisory_explanation is not None
            and not set(self.advisory_explanation.cited_evidence_ids) <= admitted | weak
        ):
            raise ValueError("advisory explanation must cite admitted or weak evidence")

        actions = [gate.requested_action for gate in self.action_gate]
        if len(actions) != len(set(actions)):
            raise ValueError("action gate requests must be unique")
        if self.classification is not None and any(
            gate.classification is not self.classification for gate in self.action_gate
        ):
            raise ValueError("action gate classification must match the report")
        return self
