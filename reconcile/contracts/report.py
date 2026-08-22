"""Investigation report and action-gate contracts."""

from __future__ import annotations

from enum import StrEnum
from typing import Annotated, Literal

from pydantic import Field, model_validator

from reconcile.contracts.base import (
    AwareDatetime,
    Identifier,
    SanitizedText,
    Sha256Digest,
    StrictModel,
)
from reconcile.contracts.codec import canonical_sha256
from reconcile.contracts.common import Classification
from reconcile.contracts.evidence import (
    EffectAssertionState,
    EvidenceAuthority,
    EvidenceDecision,
    EvidenceDisposition,
    EvidenceReason,
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
    OPERATION_NOT_COMMITTED = "operation_not_committed"
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
        escalation_required = self.classification is not Classification.COMMITTED
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
                Classification.NOT_COMMITTED: (
                    ActionGateReason.OPERATION_NOT_COMMITTED
                ),
                Classification.PARTIAL: ActionGateReason.INCOMPLETE_EFFECT_SET,
                Classification.PENDING: ActionGateReason.OPERATION_ACTIVE,
                Classification.UNKNOWN: (
                    ActionGateReason.INSUFFICIENT_AUTHORITATIVE_EVIDENCE
                ),
            }
            if self.reason is not continue_reasons[self.classification]:
                raise ValueError("continuation reason does not match classification")
        elif self.requested_action is RequestedAction.OBSERVE:
            if (
                not self.allowed
                or self.reason is not ActionGateReason.READ_ONLY_FOLLOW_UP
            ):
                raise ValueError("observation must remain available and read-only")
        elif self.requested_action is RequestedAction.ESCALATE:
            escalation_outcomes = {
                Classification.COMMITTED: (
                    False,
                    ActionGateReason.ALL_EFFECTS_ESTABLISHED,
                ),
                Classification.NOT_COMMITTED: (
                    True,
                    ActionGateReason.OPERATOR_REVIEW_AVAILABLE,
                ),
                Classification.PARTIAL: (
                    True,
                    ActionGateReason.OPERATOR_INTERVENTION_REQUIRED,
                ),
                Classification.PENDING: (
                    True,
                    ActionGateReason.OPERATOR_INTERVENTION_REQUIRED,
                ),
                Classification.UNKNOWN: (
                    True,
                    ActionGateReason.OPERATOR_INTERVENTION_REQUIRED,
                ),
            }
            allowed, reason = escalation_outcomes[self.classification]
            if self.allowed is not allowed or self.reason is not reason:
                raise ValueError("operator escalation outcome does not match state")
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
    capability_name: Identifier | None = None
    capability_version: Identifier | None = None
    request_sha256: Sha256Digest | None = None
    target_sha256: Sha256Digest
    outcome: ProbeOutcome
    stop_reason: Identifier
    started_at: AwareDatetime
    completed_at: AwareDatetime
    session_elapsed_ms: int = Field(ge=0, le=2**63 - 1)
    probe_count_used: int = Field(ge=0, le=2**63 - 1)
    cost_units_used: int = Field(ge=0, le=2**63 - 1)
    result_bytes_acquired: int = Field(ge=0, le=2**63 - 1)
    result_sha256: Sha256Digest | None = None
    result_byte_count: int | None = Field(default=None, ge=0, le=2**63 - 1)
    evidence_ids: tuple[Identifier, ...] = Field(min_length=1, max_length=1)

    @model_validator(mode="after")
    def validate_record(self) -> ProbeAuditRecord:
        if self.completed_at < self.started_at:
            raise ValueError("probe completion cannot precede its start")
        if (self.capability_name is None) is not (self.capability_version is None):
            raise ValueError("probe capability identity must be complete")
        if self.outcome is ProbeOutcome.COMPLETED:
            if (
                self.capability_name is None
                or self.request_sha256 is None
                or self.result_sha256 is None
                or self.result_byte_count is None
            ):
                raise ValueError(
                    "completed probes require request, capability, and result identity"
                )
        elif self.result_sha256 is not None:
            raise ValueError("rejected probe output cannot become an evidence digest")
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
        max_length=64,
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
    text: SanitizedText
    cited_evidence_ids: tuple[Identifier, ...] = Field(
        min_length=1,
        max_length=64,
    )

    @model_validator(mode="after")
    def validate_citation_identity(self) -> AdvisoryExplanation:
        if len(self.cited_evidence_ids) != len(set(self.cited_evidence_ids)):
            raise ValueError("advisory evidence citations must be unique")
        return self


ActionGateCollection = (
    Annotated[tuple[ActionGateResult, ...], Field(max_length=0)]
    | Annotated[
        tuple[ActionGateResult, ...],
        Field(min_length=len(RequestedAction), max_length=len(RequestedAction)),
    ]
)


class InvestigationReport(StrictModel):
    schema_version: Literal[INVESTIGATION_REPORT_VERSION]
    investigation_id: Identifier
    envelope_sha256: Sha256Digest
    status: InvestigationStatus
    probe_audit: tuple[ProbeAuditRecord, ...] = Field(
        default_factory=tuple,
        max_length=64,
    )
    evidence: tuple[NormalizedEvidence, ...] = Field(
        default_factory=tuple,
        max_length=64,
    )
    evidence_decisions: tuple[EvidenceDecision, ...] = Field(
        default_factory=tuple,
        max_length=64,
    )
    proof: DeterministicProof | None = None
    classification: Classification | None = None
    action_gate: ActionGateCollection = Field(default_factory=tuple)
    missing_evidence: tuple[MissingEvidence, ...] = Field(
        default_factory=tuple,
        max_length=64,
    )
    limitations: tuple[SanitizedText, ...] = Field(
        default_factory=tuple,
        max_length=64,
    )
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

        audit_by_evidence_id: dict[str, ProbeAuditRecord] = {}
        for record in self.probe_audit:
            if not set(record.evidence_ids) <= set(decision_ids):
                raise ValueError("probe audit references an unknown evidence decision")
            for evidence_id in record.evidence_ids:
                if evidence_id in audit_by_evidence_id:
                    raise ValueError(
                        "evidence decisions require one probe audit source"
                    )
                audit_by_evidence_id[evidence_id] = record
        if set(decision_ids) != set(audit_by_evidence_id):
            raise ValueError("every evidence decision requires one probe audit source")

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
        for evidence_id, evidence in evidence_by_id.items():
            audit = audit_by_evidence_id[evidence_id]
            if audit.outcome is not ProbeOutcome.COMPLETED:
                raise ValueError("normalized evidence requires a completed probe")
            if (
                audit.capability_name != evidence.capability_name
                or audit.capability_version != evidence.capability_version
            ):
                raise ValueError("evidence capability does not match its probe audit")
            if (
                decision_by_id[evidence_id].disposition
                is not EvidenceDisposition.REJECTED
                and audit.target_sha256 != canonical_sha256(evidence.target)
            ):
                raise ValueError("evidence target does not match its probe audit")
            if (
                audit.result_sha256 != evidence.raw_observation.sha256
                or audit.result_byte_count != evidence.raw_observation.byte_count
            ):
                raise ValueError("raw observation does not match its probe result")
            if audit.completed_at != evidence.provenance.retrieved_at:
                raise ValueError(
                    "evidence retrieval time does not match probe completion"
                )
            if (
                decision_by_id[evidence_id].disposition
                is not EvidenceDisposition.REJECTED
                and not evidence.freshness.valid_from
                <= evidence.provenance.retrieved_at
                <= evidence.freshness.valid_until
            ):
                raise ValueError("retained evidence is outside its freshness window")

        if any(
            evidence_by_id[evidence_id].authority is not EvidenceAuthority.TARGET_STATE
            for evidence_id in admitted
        ):
            raise ValueError("only target-state evidence can be admitted")
        if any(
            evidence_by_id[evidence_id].authority is EvidenceAuthority.TARGET_STATE
            for evidence_id in weak
        ):
            raise ValueError("target-state evidence cannot be retained as weak")

        for evidence_id, decision in decision_by_id.items():
            evidence = evidence_by_id.get(evidence_id)
            if evidence is None or decision.disposition is EvidenceDisposition.REJECTED:
                continue
            if decision.disposition is EvidenceDisposition.WEAK:
                expected_weak_reason = {
                    EvidenceAuthority.SUPPLEMENTARY: (
                        EvidenceReason.NON_AUTHORITATIVE_LOG_ONLY
                    ),
                    EvidenceAuthority.WEAK: EvidenceReason.NOT_FOUND_ABSENCE_ONLY,
                }.get(evidence.authority)
                if decision.reason is not expected_weak_reason:
                    raise ValueError(
                        "weak evidence reason does not match its authority"
                    )
                continue
            if evidence.operation_status in {
                OperationStatus.ACTIVE,
                OperationStatus.UNRESOLVED,
            }:
                expected_reason = EvidenceReason.AUTHORITATIVE_ACTIVE_STATUS
            elif evidence.operation_status is OperationStatus.TERMINAL_NOT_COMMITTED:
                expected_reason = EvidenceReason.AUTHORITATIVE_AFFIRMATIVE_NON_EXECUTION
            else:
                expected_reason = EvidenceReason.AUTHORITATIVE_EXACT_CORRELATION
            if decision.reason is not expected_reason:
                raise ValueError(
                    "admitted evidence reason does not match its semantics"
                )

        admitted_evidence = [evidence_by_id[evidence_id] for evidence_id in admitted]
        if admitted_evidence:
            target_sha256 = canonical_sha256(admitted_evidence[0].target)
            if any(
                canonical_sha256(item.target) != target_sha256
                for item in admitted_evidence[1:]
            ):
                raise ValueError("admitted evidence targets must match")
            first = admitted_evidence[0]
            if any(
                item.authority_policy_version != first.authority_policy_version
                for item in admitted_evidence[1:]
            ):
                raise ValueError("admitted evidence authority policies must match")

        if self.proof is not None:
            if set(self.proof.admitted_evidence_ids) != admitted:
                raise ValueError("proof must include every admitted evidence item")
            finding_ids = {finding.effect_id for finding in self.proof.effect_findings}
            assertions_by_effect: dict[
                str,
                list[tuple[EffectAssertionState, str]],
            ] = {}
            statuses: set[OperationStatus] = set()
            for evidence_id in self.proof.admitted_evidence_ids:
                evidence = evidence_by_id[evidence_id]
                if evidence.operation_status is not None:
                    statuses.add(evidence.operation_status)
                for assertion in evidence.effect_assertions:
                    if assertion.effect_id not in finding_ids:
                        raise ValueError(
                            "admitted assertion is absent from deterministic proof"
                        )
                    assertions_by_effect.setdefault(assertion.effect_id, []).append(
                        (assertion.state, evidence_id)
                    )

            aggregate_conflict = False
            for finding in self.proof.effect_findings:
                if not set(finding.evidence_ids) <= set(
                    self.proof.admitted_evidence_ids
                ):
                    raise ValueError("effect finding references evidence not admitted")
                if (
                    finding.state is not EffectAssertionState.UNVERIFIED
                    and not finding.evidence_ids
                ):
                    raise ValueError("definitive effect findings require evidence")
                values = assertions_by_effect.get(finding.effect_id, [])
                definitive_states = {
                    state
                    for state, _ in values
                    if state is not EffectAssertionState.UNVERIFIED
                }
                contradictory = {
                    EffectAssertionState.ESTABLISHED,
                    EffectAssertionState.NOT_ESTABLISHED,
                }
                if contradictory <= definitive_states:
                    aggregate_conflict = True
                    expected_state = EffectAssertionState.UNVERIFIED
                elif EffectAssertionState.ESTABLISHED in definitive_states:
                    expected_state = EffectAssertionState.ESTABLISHED
                elif EffectAssertionState.NOT_ESTABLISHED in definitive_states:
                    expected_state = EffectAssertionState.NOT_ESTABLISHED
                else:
                    expected_state = EffectAssertionState.UNVERIFIED
                if finding.state is not expected_state:
                    raise ValueError(
                        "effect finding does not match aggregate admitted evidence"
                    )
                expected_citations = tuple(
                    sorted(
                        evidence_id
                        for state, evidence_id in values
                        if state is not EffectAssertionState.UNVERIFIED
                    )
                )
                if finding.evidence_ids != expected_citations:
                    raise ValueError(
                        "effect finding must cite every definitive assertion"
                    )

                cited_states = []
                for evidence_id in finding.evidence_ids:
                    assertions = {
                        assertion.effect_id: assertion.state
                        for assertion in evidence_by_id[evidence_id].effect_assertions
                    }
                    cited_state = assertions.get(finding.effect_id)
                    if cited_state is None:
                        raise ValueError(
                            "effect finding is not supported by its cited evidence"
                        )
                    cited_states.append(cited_state)
                if (
                    finding.state is EffectAssertionState.UNVERIFIED
                    and finding.evidence_ids
                ):
                    if not self.proof.conflicting_authority or not contradictory <= set(
                        cited_states
                    ):
                        raise ValueError(
                            "unverified finding citations require conflicting authority"
                        )
                elif any(state is not finding.state for state in cited_states):
                    raise ValueError(
                        "effect finding is not supported by its cited evidence"
                    )

            terminal_not_committed = OperationStatus.TERMINAL_NOT_COMMITTED in statuses
            terminal_committed = OperationStatus.TERMINAL_COMMITTED in statuses
            active = bool(
                statuses & {OperationStatus.ACTIVE, OperationStatus.UNRESOLVED}
            )
            all_established = all(
                finding.state is EffectAssertionState.ESTABLISHED
                for finding in self.proof.effect_findings
            )
            if (
                (terminal_committed and terminal_not_committed)
                or (terminal_not_committed and active)
                or (
                    terminal_not_committed
                    and any(
                        finding.state is EffectAssertionState.ESTABLISHED
                        for finding in self.proof.effect_findings
                    )
                )
                or (terminal_committed and active and not all_established)
            ):
                aggregate_conflict = True

            if aggregate_conflict != self.proof.conflicting_authority:
                raise ValueError(
                    "conflict flag does not match aggregate admitted evidence"
                )
            if aggregate_conflict:
                expected_status = None
            elif terminal_committed:
                expected_status = OperationStatus.TERMINAL_COMMITTED
            elif OperationStatus.UNRESOLVED in statuses:
                expected_status = OperationStatus.UNRESOLVED
            elif OperationStatus.ACTIVE in statuses:
                expected_status = OperationStatus.ACTIVE
            elif terminal_not_committed:
                expected_status = OperationStatus.TERMINAL_NOT_COMMITTED
            else:
                expected_status = None
            if self.proof.operation_status is not expected_status:
                raise ValueError(
                    "operation status does not match aggregate admitted evidence"
                )
        if (
            self.advisory_explanation is not None
            and not set(self.advisory_explanation.cited_evidence_ids) <= admitted | weak
        ):
            raise ValueError("advisory explanation must cite admitted or weak evidence")

        actions = [gate.requested_action for gate in self.action_gate]
        if len(actions) != len(set(actions)):
            raise ValueError("action gate requests must be unique")
        if actions and actions != list(RequestedAction):
            raise ValueError("action gates must cover every v1 requested action")
        if self.classification is not None and any(
            gate.classification is not self.classification for gate in self.action_gate
        ):
            raise ValueError("action gate classification must match the report")
        if self.action_gate:
            first_gate = self.action_gate[0]
            if any(
                gate.classification_policy_version
                != first_gate.classification_policy_version
                or gate.action_policy_version != first_gate.action_policy_version
                for gate in self.action_gate[1:]
            ):
                raise ValueError("action gates must use one policy version pair")

        if self.classification is not None and self.proof is not None:
            states = [finding.state for finding in self.proof.effect_findings]
            established = [
                finding
                for finding in self.proof.effect_findings
                if finding.state is EffectAssertionState.ESTABLISHED
            ]
            if (
                self.proof.conflicting_authority
                and self.classification is not Classification.UNKNOWN
            ):
                raise ValueError("conflicting authority requires UNKNOWN")
            if self.classification is Classification.COMMITTED and (
                self.proof.conflicting_authority
                or any(
                    state is not EffectAssertionState.ESTABLISHED for state in states
                )
            ):
                raise ValueError("COMMITTED requires every effect to be established")
            if self.classification is Classification.NOT_COMMITTED and (
                self.proof.conflicting_authority
                or self.proof.operation_status
                is not OperationStatus.TERMINAL_NOT_COMMITTED
                or established
            ):
                raise ValueError(
                    "NOT_COMMITTED requires affirmative terminal non-execution"
                )
            if self.classification is Classification.PARTIAL:
                if (
                    self.proof.conflicting_authority
                    or not established
                    or len(established) == len(states)
                    or EffectAssertionState.UNVERIFIED in states
                    or self.proof.operation_status is OperationStatus.ACTIVE
                ):
                    raise ValueError(
                        "PARTIAL requires a terminal strict subset of effects"
                    )
                scope_states: dict[str, set[bool]] = {}
                for finding in self.proof.effect_findings:
                    scope_states.setdefault(finding.commit_scope, set()).add(
                        finding.state is EffectAssertionState.ESTABLISHED
                    )
                if any(len(values) != 1 for values in scope_states.values()):
                    raise ValueError(
                        "PARTIAL cannot split effects in one atomic commit scope"
                    )
            if self.classification is Classification.PENDING and (
                self.proof.conflicting_authority
                or self.proof.operation_status
                not in {OperationStatus.ACTIVE, OperationStatus.UNRESOLVED}
                or len(established) == len(states)
            ):
                raise ValueError(
                    "PENDING requires an unresolved operation without complete proof"
                )

            established_ids = {
                finding.effect_id
                for finding in self.proof.effect_findings
                if finding.state is EffectAssertionState.ESTABLISHED
            }
            not_established_ids = {
                finding.effect_id
                for finding in self.proof.effect_findings
                if finding.state is EffectAssertionState.NOT_ESTABLISHED
            }
            effects_by_scope: dict[str, set[str]] = {}
            for finding in self.proof.effect_findings:
                effects_by_scope.setdefault(finding.commit_scope, set()).add(
                    finding.effect_id
                )
            fully_established_scopes = {
                scope
                for scope, effect_ids in effects_by_scope.items()
                if effect_ids <= established_ids
            }
            fully_not_established_scopes = {
                scope
                for scope, effect_ids in effects_by_scope.items()
                if effect_ids <= not_established_ids
            }
            all_established = len(established_ids) == len(self.proof.effect_findings)
            operation_active = self.proof.operation_status is OperationStatus.ACTIVE
            operation_failed = self.proof.operation_status is OperationStatus.UNRESOLVED
            terminal_not_committed = (
                self.proof.operation_status is OperationStatus.TERMINAL_NOT_COMMITTED
            )
            partial = (
                len(effects_by_scope) >= 2
                and 0 < len(fully_established_scopes) < len(effects_by_scope)
                and fully_established_scopes | fully_not_established_scopes
                == set(effects_by_scope)
            )
            if self.proof.conflicting_authority:
                expected_classification = Classification.UNKNOWN
            elif all_established:
                expected_classification = Classification.COMMITTED
            elif operation_active:
                expected_classification = Classification.PENDING
            elif partial:
                expected_classification = Classification.PARTIAL
            elif operation_failed:
                expected_classification = Classification.PENDING
            elif terminal_not_committed and not established:
                expected_classification = Classification.NOT_COMMITTED
            else:
                expected_classification = Classification.UNKNOWN
            if self.classification is not expected_classification:
                raise ValueError(
                    "classification does not match deterministic proof precedence"
                )

            unresolved = tuple(
                finding.effect_id
                for finding in self.proof.effect_findings
                if finding.state is not EffectAssertionState.ESTABLISHED
            )
            definitive = self.classification in {
                Classification.COMMITTED,
                Classification.NOT_COMMITTED,
            }
            if definitive and self.missing_evidence:
                raise ValueError(
                    "definitive classifications cannot list missing evidence"
                )
            if not definitive:
                if len(self.missing_evidence) != 1:
                    raise ValueError(
                        "non-definitive classifications require missing evidence"
                    )
                missing = self.missing_evidence[0]
                if missing.effect_ids != unresolved:
                    raise ValueError(
                        "missing evidence must list every unresolved effect"
                    )
                expected_missing_reason = {
                    Classification.PARTIAL: "authoritative-effect-proof-required",
                    Classification.PENDING: "authoritative-terminal-proof-required",
                }.get(self.classification)
                if self.proof.conflicting_authority:
                    expected_missing_reason = EvidenceReason.CONFLICTING_AUTHORITY.value
                elif self.classification is Classification.UNKNOWN:
                    reported_reasons = sorted(
                        decision.reason.value
                        for decision in self.evidence_decisions
                        if decision.disposition is not EvidenceDisposition.ADMITTED
                    )
                    expected_missing_reason = (
                        reported_reasons[0]
                        if reported_reasons
                        else "authoritative-effect-proof-required"
                    )
                if (
                    expected_missing_reason is not None
                    and missing.reason != expected_missing_reason
                ):
                    raise ValueError(
                        "missing evidence reason does not match classification"
                    )
        return self
