"""Strict sanitized contracts for the operator scenario surface."""

from __future__ import annotations

from enum import StrEnum
from typing import Literal

from pydantic import ConfigDict, Field, model_validator

from reconcile.contracts.base import (
    AwareDatetime,
    Identifier,
    Sha256Digest,
    StrictModel,
)
from reconcile.contracts.common import (
    AmbiguityKind,
    CapabilityRef,
    Classification,
    EvidenceBudget,
)
from reconcile.contracts.comparison import (
    ComparisonModelUsage,
    ComparisonModelUsageStatus,
    ComparisonStrategyKind,
    ExplanationCompleteness,
)
from reconcile.contracts.evidence import (
    EffectAssertion,
    EffectAssertionState,
    EvidenceAuthority,
    EvidenceDecision,
    EvidenceDisposition,
    EvidenceReason,
    OperationStatus,
)
from reconcile.contracts.planning import AdaptivePlannerPhase
from reconcile.contracts.report import (
    ActionGateResult,
    InvestigationStatus,
    ProbeOutcome,
    RequestedAction,
)

EXECUTION_ENVELOPE_SUMMARY_VERSION = "reconcile/execution-envelope-summary/v1"
SCENARIO_LAUNCH_REQUEST_VERSION = "reconcile/scenario-launch-request/v1"
SCENARIO_RUN_SNAPSHOT_VERSION = "reconcile/scenario-run-snapshot/v2"
SCENARIO_RUN_EVENT_VERSION = "reconcile/scenario-run-event/v2"
BOUNDED_HYBRID_ROUTE_POLICY_VERSION = "1.0.0"

MAX_SCENARIO_RUN_EVENTS = 1024

_MAX_SIGNED_64 = 2**63 - 1
_MAX_ADVISORY_TURNS = 65
_MAX_PROPOSAL_EVENTS = 64 + _MAX_ADVISORY_TURNS * 8


class EnvelopeEffectSummary(StrictModel):
    """Opaque expected-effect identity without predicates or descriptions."""

    effect_id: Identifier
    commit_scope: Identifier


class ExecutionEnvelopeSummary(StrictModel):
    """Operator-safe projection of an execution envelope."""

    schema_version: Literal[EXECUTION_ENVELOPE_SUMMARY_VERSION]
    investigation_id: Identifier
    envelope_sha256: Sha256Digest
    target_kind: Identifier
    invoked_at: AwareDatetime
    ambiguity_kind: AmbiguityKind
    ambiguity_observed_at: AwareDatetime
    expected_effects: tuple[EnvelopeEffectSummary, ...] = Field(
        min_length=1,
        max_length=64,
    )
    enabled_capabilities: tuple[CapabilityRef, ...] = Field(
        min_length=1,
        max_length=64,
    )
    evidence_budget: EvidenceBudget

    @model_validator(mode="after")
    def validate_summary(self) -> ExecutionEnvelopeSummary:
        if self.ambiguity_observed_at < self.invoked_at:
            raise ValueError("ambiguity cannot precede the invocation")
        effect_ids = tuple(item.effect_id for item in self.expected_effects)
        if len(effect_ids) != len(set(effect_ids)):
            raise ValueError("summary effect identifiers must be unique")
        capabilities = tuple(
            (item.name, item.version) for item in self.enabled_capabilities
        )
        if len(capabilities) != len(set(capabilities)):
            raise ValueError("summary capability identities must be unique")
        return self


class ScenarioLaunchName(StrEnum):
    STORAGE = "storage"
    FIRESTORE_BUSINESS = "firestore-business"
    SANDBOX_ORDER = "sandbox-order"


class ScenarioRunMode(StrEnum):
    FIXED = "fixed"
    ADAPTIVE = "adaptive"
    COMPARE = "compare"


class ScenarioHybridRoute(StrEnum):
    """Deterministic G4R route selected from a trusted scenario profile."""

    FIXED_AUTHORITATIVE = "FIXED_AUTHORITATIVE"
    PLANNER_HETEROGENEOUS = "PLANNER_HETEROGENEOUS"


class ScenarioHybridOutcome(StrEnum):
    """Sanitized terminal disposition of one bounded hybrid route."""

    FIXED_AUTHORITATIVE = "FIXED_AUTHORITATIVE"
    PLANNER_EVIDENCE = "PLANNER_EVIDENCE"
    FIXED_FALLBACK = "FIXED_FALLBACK"
    EXPLICIT_UNKNOWN = "EXPLICIT_UNKNOWN"


class ScenarioRouteProvenance(StrictModel):
    """Public route and provider-failure facts without provider detail."""

    policy_version: Literal[BOUNDED_HYBRID_ROUTE_POLICY_VERSION]
    route: ScenarioHybridRoute
    outcome: ScenarioHybridOutcome
    planner_invoked: bool
    fixed_connector_invoked: bool
    provider_failure: bool
    provider_cleanup_failure: bool

    @model_validator(mode="after")
    def validate_route(self) -> ScenarioRouteProvenance:
        if self.route is ScenarioHybridRoute.FIXED_AUTHORITATIVE:
            valid = (
                self.outcome is ScenarioHybridOutcome.FIXED_AUTHORITATIVE
                and not self.planner_invoked
                and self.fixed_connector_invoked
                and not self.provider_failure
                and not self.provider_cleanup_failure
            )
        elif self.outcome is ScenarioHybridOutcome.PLANNER_EVIDENCE:
            valid = (
                self.planner_invoked
                and not self.fixed_connector_invoked
                and not self.provider_failure
            )
        elif self.outcome is ScenarioHybridOutcome.FIXED_FALLBACK:
            valid = self.fixed_connector_invoked and self.provider_failure
        else:
            valid = (
                self.outcome is ScenarioHybridOutcome.EXPLICIT_UNKNOWN
                and not self.fixed_connector_invoked
                and self.planner_invoked is self.provider_failure
            )
        if not valid:
            raise ValueError("hybrid route provenance is inconsistent")
        return self


class ScenarioRunLifecycle(StrEnum):
    ACCEPTED = "ACCEPTED"
    RUNNING = "RUNNING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    CANCELLED = "CANCELLED"


class ScenarioRunFailureCategory(StrEnum):
    INVALID_CONFIGURATION = "invalid_configuration"
    SCENARIO_EXECUTION_FAILED = "scenario_execution_failed"
    MODEL_UNAVAILABLE = "model_unavailable"
    CLEANUP_FAILED = "cleanup_failed"
    COMPARISON_UNREPRESENTABLE = "comparison_unrepresentable"
    EVENT_JOURNAL_FAILED = "event_journal_failed"
    INTERNAL_FAILURE = "internal_failure"


class ScenarioRunResultKind(StrEnum):
    NONE = "NONE"
    REPORT = "REPORT"
    COMPARISON = "COMPARISON"


class ScenarioLaunchRequest(StrictModel):
    """Idempotent request for one server-owned canonical scenario run."""

    schema_version: Literal[SCENARIO_LAUNCH_REQUEST_VERSION]
    launch_id: Identifier
    scenario: ScenarioLaunchName
    mode: ScenarioRunMode = ScenarioRunMode.FIXED


class SanitizedProbeAuditRecord(StrictModel):
    probe_sequence: int = Field(ge=1, le=64)
    capability_name: Identifier | None
    capability_version: Identifier | None
    request_sha256: Sha256Digest | None
    outcome: ProbeOutcome
    stop_reason: Identifier
    started_at: AwareDatetime
    completed_at: AwareDatetime
    session_elapsed_ms: int = Field(ge=0, le=_MAX_SIGNED_64)
    probe_count_used: int = Field(ge=0, le=64)
    cost_units_used: int = Field(ge=0, le=_MAX_SIGNED_64)
    result_bytes_acquired: int = Field(ge=0, le=_MAX_SIGNED_64)
    result_sha256: Sha256Digest | None
    result_byte_count: int | None = Field(default=None, ge=0, le=_MAX_SIGNED_64)
    evidence_ids: tuple[Identifier, ...] = Field(min_length=1, max_length=1)

    @model_validator(mode="after")
    def validate_audit(self) -> SanitizedProbeAuditRecord:
        if self.completed_at < self.started_at:
            raise ValueError("probe completion cannot precede its start")
        if (self.capability_name is None) is not (self.capability_version is None):
            raise ValueError("probe audit capability identity must be complete")
        if self.outcome is ProbeOutcome.COMPLETED:
            if (
                self.capability_name is None
                or self.request_sha256 is None
                or self.result_sha256 is None
                or self.result_byte_count is None
            ):
                raise ValueError("completed probe audits require bounded identity")
        elif self.result_sha256 is not None or self.result_byte_count is not None:
            raise ValueError("noncompleted probes cannot expose result identity")
        if self.result_bytes_acquired < (self.result_byte_count or 0):
            raise ValueError("probe result bytes cannot exceed acquired bytes")
        return self


_ADMITTED_EVIDENCE_REASONS = frozenset(
    {
        EvidenceReason.AUTHORITATIVE_ACTIVE_STATUS,
        EvidenceReason.AUTHORITATIVE_AFFIRMATIVE_NON_EXECUTION,
        EvidenceReason.AUTHORITATIVE_EXACT_CORRELATION,
    }
)
_WEAK_EVIDENCE_REASONS = frozenset(
    {
        EvidenceReason.NON_AUTHORITATIVE_LOG_ONLY,
        EvidenceReason.NOT_FOUND_ABSENCE_ONLY,
    }
)


class SanitizedEvidenceSummary(StrictModel):
    evidence_id: Identifier
    capability_name: Identifier | None
    capability_version: Identifier | None
    disposition: EvidenceDisposition
    reason: EvidenceReason
    authority: EvidenceAuthority | None
    effect_assertions: tuple[EffectAssertion, ...] = Field(max_length=64)
    operation_status: OperationStatus | None

    @model_validator(mode="after")
    def validate_evidence(self) -> SanitizedEvidenceSummary:
        if (self.capability_name is None) is not (self.capability_version is None):
            raise ValueError("evidence capability identity must be complete")
        effect_ids = tuple(item.effect_id for item in self.effect_assertions)
        if len(effect_ids) != len(set(effect_ids)):
            raise ValueError("evidence effect identifiers must be unique")
        if self.disposition is EvidenceDisposition.ADMITTED:
            valid = (
                self.capability_name is not None
                and self.reason in _ADMITTED_EVIDENCE_REASONS
                and self.authority is EvidenceAuthority.TARGET_STATE
                and (bool(self.effect_assertions) or self.operation_status is not None)
            )
        elif self.disposition is EvidenceDisposition.WEAK:
            valid = (
                self.capability_name is not None
                and self.reason in _WEAK_EVIDENCE_REASONS
                and self.authority
                in {EvidenceAuthority.SUPPLEMENTARY, EvidenceAuthority.WEAK}
                and self.operation_status is None
                and all(
                    assertion.state is EffectAssertionState.UNVERIFIED
                    for assertion in self.effect_assertions
                )
            )
        else:
            valid = (
                self.reason not in _ADMITTED_EVIDENCE_REASONS
                and self.reason not in _WEAK_EVIDENCE_REASONS
                and self.authority is None
                and not self.effect_assertions
                and self.operation_status is None
            )
        if not valid:
            raise ValueError("evidence summary fields do not match disposition")
        return self


class SanitizedEffectFinding(StrictModel):
    effect_id: Identifier
    commit_scope: Identifier
    state: EffectAssertionState
    evidence_ids: tuple[Identifier, ...] = Field(max_length=64)

    @model_validator(mode="after")
    def validate_finding(self) -> SanitizedEffectFinding:
        if len(self.evidence_ids) != len(set(self.evidence_ids)):
            raise ValueError("effect finding evidence identifiers must be unique")
        if self.state is not EffectAssertionState.UNVERIFIED and not self.evidence_ids:
            raise ValueError("definitive effect findings require evidence")
        return self


class SanitizedDeterministicProof(StrictModel):
    effect_findings: tuple[SanitizedEffectFinding, ...] = Field(
        min_length=1,
        max_length=64,
    )
    operation_status: OperationStatus | None
    conflicting_authority: bool
    admitted_evidence_ids: tuple[Identifier, ...] = Field(max_length=64)

    @model_validator(mode="after")
    def validate_proof(self) -> SanitizedDeterministicProof:
        effect_ids = tuple(item.effect_id for item in self.effect_findings)
        if len(effect_ids) != len(set(effect_ids)):
            raise ValueError("proof effect identifiers must be unique")
        if len(self.admitted_evidence_ids) != len(set(self.admitted_evidence_ids)):
            raise ValueError("proof evidence identifiers must be unique")
        admitted = set(self.admitted_evidence_ids)
        if any(
            not set(finding.evidence_ids) <= admitted
            for finding in self.effect_findings
        ):
            raise ValueError("effect findings must cite admitted evidence")
        return self


class SanitizedMissingEvidence(StrictModel):
    effect_ids: tuple[Identifier, ...] = Field(max_length=64)
    reason: Identifier

    @model_validator(mode="after")
    def validate_missing(self) -> SanitizedMissingEvidence:
        if len(self.effect_ids) != len(set(self.effect_ids)):
            raise ValueError("missing effect identifiers must be unique")
        return self


class SanitizedInvestigationReport(StrictModel):
    investigation_id: Identifier
    envelope_sha256: Sha256Digest
    status: InvestigationStatus
    probe_audit: tuple[SanitizedProbeAuditRecord, ...] = Field(max_length=64)
    evidence: tuple[SanitizedEvidenceSummary, ...] = Field(max_length=64)
    proof: SanitizedDeterministicProof | None
    classification: Classification | None
    action_gate: tuple[ActionGateResult, ...] = Field(max_length=len(RequestedAction))
    missing_evidence: tuple[SanitizedMissingEvidence, ...] = Field(max_length=64)
    advisory_cited_evidence_ids: tuple[Identifier, ...] = Field(max_length=64)
    route_provenance: ScenarioRouteProvenance | None = None
    created_at: AwareDatetime
    updated_at: AwareDatetime
    revision: int = Field(ge=0, le=_MAX_SIGNED_64)

    @model_validator(mode="after")
    def validate_report(self) -> SanitizedInvestigationReport:
        if self.updated_at < self.created_at:
            raise ValueError("report update cannot precede creation")
        sequences = tuple(item.probe_sequence for item in self.probe_audit)
        if sequences != tuple(range(1, len(sequences) + 1)):
            raise ValueError("probe audit must be contiguous and ordered")
        evidence_ids = tuple(item.evidence_id for item in self.evidence)
        if len(evidence_ids) != len(set(evidence_ids)):
            raise ValueError("evidence identifiers must be unique")
        audit_evidence_ids = tuple(
            evidence_id
            for audit in self.probe_audit
            for evidence_id in audit.evidence_ids
        )
        if len(audit_evidence_ids) != len(set(audit_evidence_ids)):
            raise ValueError("evidence requires one probe audit source")
        if set(evidence_ids) != set(audit_evidence_ids):
            raise ValueError("evidence summaries must match probe audit attempts")
        audit_by_evidence_id = {
            audit.evidence_ids[0]: audit for audit in self.probe_audit
        }
        evidence_by_id = {item.evidence_id: item for item in self.evidence}
        for item in self.evidence:
            audit = audit_by_evidence_id[item.evidence_id]
            if item.capability_name is not None and (
                item.capability_name != audit.capability_name
                or item.capability_version != audit.capability_version
            ):
                raise ValueError("evidence capability does not match its probe audit")
            if (
                item.disposition is not EvidenceDisposition.REJECTED
                and audit.outcome is not ProbeOutcome.COMPLETED
            ):
                raise ValueError("retained evidence requires a completed probe")
            if item.disposition is EvidenceDisposition.ADMITTED:
                if item.operation_status in {
                    OperationStatus.ACTIVE,
                    OperationStatus.UNRESOLVED,
                }:
                    expected_reason = EvidenceReason.AUTHORITATIVE_ACTIVE_STATUS
                elif item.operation_status is OperationStatus.TERMINAL_NOT_COMMITTED:
                    expected_reason = (
                        EvidenceReason.AUTHORITATIVE_AFFIRMATIVE_NON_EXECUTION
                    )
                else:
                    expected_reason = EvidenceReason.AUTHORITATIVE_EXACT_CORRELATION
                if item.reason is not expected_reason:
                    raise ValueError(
                        "admitted evidence reason does not match its semantics"
                    )
            elif item.disposition is EvidenceDisposition.WEAK:
                expected_reason = {
                    EvidenceAuthority.SUPPLEMENTARY: (
                        EvidenceReason.NON_AUTHORITATIVE_LOG_ONLY
                    ),
                    EvidenceAuthority.WEAK: EvidenceReason.NOT_FOUND_ABSENCE_ONLY,
                }[item.authority]
                if item.reason is not expected_reason:
                    raise ValueError(
                        "weak evidence reason does not match its authority"
                    )
        admitted = {
            item.evidence_id
            for item in self.evidence
            if item.disposition is EvidenceDisposition.ADMITTED
        }
        if self.proof is not None and set(self.proof.admitted_evidence_ids) != admitted:
            raise ValueError("proof must include every admitted evidence item")
        retained = {
            item.evidence_id
            for item in self.evidence
            if item.disposition is not EvidenceDisposition.REJECTED
        }
        if (
            len(self.advisory_cited_evidence_ids)
            != len(set(self.advisory_cited_evidence_ids))
            or not set(self.advisory_cited_evidence_ids) <= retained
        ):
            raise ValueError("advisory citations must reference retained evidence")

        if self.proof is not None:
            finding_ids = {finding.effect_id for finding in self.proof.effect_findings}
            assertions_by_effect: dict[
                str,
                list[tuple[EffectAssertionState, str]],
            ] = {}
            statuses: set[OperationStatus] = set()
            for evidence_id in self.proof.admitted_evidence_ids:
                item = evidence_by_id[evidence_id]
                if item.operation_status is not None:
                    statuses.add(item.operation_status)
                for assertion in item.effect_assertions:
                    if assertion.effect_id not in finding_ids:
                        raise ValueError(
                            "admitted assertion is absent from deterministic proof"
                        )
                    assertions_by_effect.setdefault(assertion.effect_id, []).append(
                        (assertion.state, evidence_id)
                    )

            aggregate_conflict = False
            for finding in self.proof.effect_findings:
                assertions = assertions_by_effect.get(finding.effect_id, [])
                definitive_states = {
                    state
                    for state, _ in assertions
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
                expected_citations = tuple(
                    sorted(
                        evidence_id
                        for state, evidence_id in assertions
                        if state is not EffectAssertionState.UNVERIFIED
                    )
                )
                if (
                    finding.state is not expected_state
                    or finding.evidence_ids != expected_citations
                ):
                    raise ValueError("effect finding does not match admitted evidence")

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
            if aggregate_conflict is not self.proof.conflicting_authority:
                raise ValueError("conflict flag does not match admitted evidence")
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
                raise ValueError("operation status does not match admitted evidence")

        if self.status is InvestigationStatus.COMPLETED:
            if (
                self.proof is None
                or self.classification is None
                or len(self.action_gate) != len(RequestedAction)
            ):
                raise ValueError("completed reports require deterministic output")
            actions = tuple(item.requested_action for item in self.action_gate)
            if set(actions) != set(RequestedAction) or len(actions) != len(
                set(actions)
            ):
                raise ValueError("action gates must cover every requested action")
            if any(
                gate.classification is not self.classification
                for gate in self.action_gate
            ):
                raise ValueError("action gates must match report classification")
            if tuple(gate.requested_action for gate in self.action_gate) != tuple(
                RequestedAction
            ):
                raise ValueError("action gates must use the canonical order")
            first_gate = self.action_gate[0]
            if any(
                gate.classification_policy_version
                != first_gate.classification_policy_version
                or gate.action_policy_version != first_gate.action_policy_version
                for gate in self.action_gate[1:]
            ):
                raise ValueError("action gates must use one policy version pair")

            states = tuple(finding.state for finding in self.proof.effect_findings)
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
            all_established = len(established_ids) == len(states)
            operation_active = self.proof.operation_status is OperationStatus.ACTIVE
            operation_failed = self.proof.operation_status is OperationStatus.UNRESOLVED
            terminal_not_committed = self.proof.operation_status is (
                OperationStatus.TERMINAL_NOT_COMMITTED
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
            elif terminal_not_committed and not established_ids:
                expected_classification = Classification.NOT_COMMITTED
            else:
                expected_classification = Classification.UNKNOWN
            if self.classification is not expected_classification:
                raise ValueError("classification does not match deterministic proof")

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
                    Classification.PARTIAL: ("authoritative-effect-proof-required"),
                    Classification.PENDING: ("authoritative-terminal-proof-required"),
                }.get(self.classification)
                if self.proof.conflicting_authority:
                    expected_missing_reason = EvidenceReason.CONFLICTING_AUTHORITY.value
                elif self.classification is Classification.UNKNOWN:
                    reported_reasons = sorted(
                        item.reason.value
                        for item in self.evidence
                        if item.disposition is not EvidenceDisposition.ADMITTED
                    )
                    expected_missing_reason = (
                        reported_reasons[0]
                        if reported_reasons
                        else "authoritative-effect-proof-required"
                    )
                if missing.reason != expected_missing_reason:
                    raise ValueError(
                        "missing evidence reason does not match classification"
                    )
        elif (
            self.proof is not None
            or self.classification is not None
            or self.action_gate
        ):
            raise ValueError("active reports cannot contain terminal decisions")
        return self


class SanitizedComparisonRun(StrictModel):
    strategy_kind: ComparisonStrategyKind
    strategy_version: Identifier
    plan_sha256: Sha256Digest
    report_sha256: Sha256Digest
    classification: Classification
    planned_probe_count: int = Field(ge=0, le=_MAX_SIGNED_64)
    executed_probe_count: int = Field(ge=0, le=_MAX_SIGNED_64)
    controller_cost_units_used: int = Field(ge=0, le=_MAX_SIGNED_64)
    controller_result_bytes_acquired: int = Field(ge=0, le=_MAX_SIGNED_64)
    total_elapsed_ms: int = Field(ge=0, le=_MAX_SIGNED_64)
    time_to_sufficient_evidence_ms: int | None = Field(
        default=None,
        ge=0,
        le=_MAX_SIGNED_64,
    )
    stop_reason: Identifier
    unsupported_probe_count: int = Field(ge=0, le=_MAX_SIGNED_64)
    unnecessary_probe_count: int = Field(ge=0, le=_MAX_SIGNED_64)
    duplicate_probe_count: int = Field(ge=0, le=_MAX_SIGNED_64)
    explanation_completeness: ExplanationCompleteness
    model_usage: ComparisonModelUsage

    @model_validator(mode="after")
    def validate_run(self) -> SanitizedComparisonRun:
        if self.executed_probe_count > self.planned_probe_count:
            raise ValueError("executed probes cannot exceed the recorded plan")
        if any(
            value > self.executed_probe_count
            for value in (
                self.unsupported_probe_count,
                self.unnecessary_probe_count,
                self.duplicate_probe_count,
            )
        ):
            raise ValueError("probe findings cannot exceed executed probes")
        if (
            self.time_to_sufficient_evidence_ms is not None
            and self.time_to_sufficient_evidence_ms > self.total_elapsed_ms
        ):
            raise ValueError("sufficient-evidence time cannot exceed total elapsed")
        if self.executed_probe_count == 0 and (
            self.controller_cost_units_used != 0
            or self.controller_result_bytes_acquired != 0
            or self.unnecessary_probe_count != 0
            or self.time_to_sufficient_evidence_ms is not None
        ):
            raise ValueError("an unexecuted plan cannot contain execution metrics")
        fixed = self.strategy_kind is ComparisonStrategyKind.FIXED
        model_not_applicable = (
            self.model_usage.status is ComparisonModelUsageStatus.NOT_APPLICABLE
        )
        if fixed is not model_not_applicable:
            raise ValueError("strategy kind and model usage are inconsistent")
        return self


class SanitizedInvestigationComparison(StrictModel):
    comparison_id: Identifier
    envelope_sha256: Sha256Digest
    baseline: SanitizedComparisonRun
    adaptive: SanitizedComparisonRun | None

    @model_validator(mode="after")
    def validate_comparison(self) -> SanitizedInvestigationComparison:
        if self.baseline.strategy_kind is not ComparisonStrategyKind.FIXED:
            raise ValueError("the baseline must use the fixed strategy")
        if self.adaptive is not None and (
            self.adaptive.strategy_kind is not ComparisonStrategyKind.ADAPTIVE
        ):
            raise ValueError("the adaptive lane must use the adaptive strategy")
        return self


class ScenarioRunSnapshot(StrictModel):
    """Atomic operator projection of one scenario run."""

    schema_version: Literal[SCENARIO_RUN_SNAPSHOT_VERSION]
    launch_id: Identifier
    investigation_id: Identifier
    scenario: ScenarioLaunchName
    mode: ScenarioRunMode
    lifecycle: ScenarioRunLifecycle
    event_cursor: int = Field(ge=0, le=MAX_SCENARIO_RUN_EVENTS)
    envelope_summary: ExecutionEnvelopeSummary | None
    report: SanitizedInvestigationReport | None
    comparison: SanitizedInvestigationComparison | None
    failure_category: ScenarioRunFailureCategory | None
    accepted_at: AwareDatetime
    updated_at: AwareDatetime

    @model_validator(mode="after")
    def validate_snapshot(self) -> ScenarioRunSnapshot:
        if self.updated_at < self.accepted_at:
            raise ValueError("snapshot update cannot precede acceptance")
        if (
            self.envelope_summary is not None
            and self.envelope_summary.investigation_id != self.investigation_id
        ):
            raise ValueError("envelope summary investigation does not match snapshot")
        if self.report is not None:
            if self.report.investigation_id != self.investigation_id:
                raise ValueError("report investigation does not match snapshot")
            if (
                self.envelope_summary is not None
                and self.report.envelope_sha256 != self.envelope_summary.envelope_sha256
            ):
                raise ValueError("report envelope does not match snapshot summary")
        if self.comparison is not None:
            if (
                self.envelope_summary is not None
                and self.comparison.envelope_sha256
                != self.envelope_summary.envelope_sha256
            ):
                raise ValueError("comparison envelope does not match snapshot summary")

        if self.mode is ScenarioRunMode.COMPARE:
            if self.report is not None:
                raise ValueError("comparison snapshots cannot contain a report result")
        elif self.comparison is not None:
            raise ValueError("non-comparison snapshots cannot contain a comparison")

        if self.lifecycle is ScenarioRunLifecycle.ACCEPTED:
            if any(
                value is not None
                for value in (
                    self.envelope_summary,
                    self.report,
                    self.comparison,
                    self.failure_category,
                )
            ):
                raise ValueError("accepted snapshots cannot contain execution output")
        elif self.lifecycle is ScenarioRunLifecycle.RUNNING:
            if self.failure_category is not None or self.comparison is not None:
                raise ValueError("running snapshots cannot contain terminal output")
            if (
                self.report is not None
                and self.report.status is InvestigationStatus.COMPLETED
            ):
                raise ValueError("running snapshots cannot contain a completed report")
        elif self.lifecycle is ScenarioRunLifecycle.COMPLETED:
            if self.envelope_summary is None or self.failure_category is not None:
                raise ValueError(
                    "completed snapshots require an envelope and no failure"
                )
            if self.mode is ScenarioRunMode.COMPARE:
                if self.comparison is None or self.comparison.adaptive is None:
                    raise ValueError(
                        "completed comparison snapshots require both lanes"
                    )
            elif self.report is None or self.report.status is not (
                InvestigationStatus.COMPLETED
            ):
                raise ValueError("completed scenario snapshots require a final report")
        elif self.lifecycle is ScenarioRunLifecycle.FAILED:
            if (
                self.failure_category is None
                or self.report is not None
                or self.comparison is not None
            ):
                raise ValueError("failed snapshots require only a failure category")
        elif (
            self.failure_category is not None
            or self.report is not None
            or self.comparison is not None
        ):
            raise ValueError("cancelled snapshots cannot contain terminal output")
        return self


class AdvisoryTurnStatus(StrEnum):
    STARTED = "STARTED"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    CANCELLED = "CANCELLED"


class AdvisoryTurnFailureCategory(StrEnum):
    UNAVAILABLE = "unavailable"
    TIMEOUT = "timeout"
    SCHEMA_INVALID = "schema_invalid"


class AdvisoryTurnSummary(StrictModel):
    turn_sequence: int = Field(ge=1, le=_MAX_ADVISORY_TURNS)
    phase: AdaptivePlannerPhase
    status: AdvisoryTurnStatus
    input_sha256: Sha256Digest
    output_sha256: Sha256Digest | None
    proposal_count: int = Field(ge=0, le=8)
    selected_proposal_count: int = Field(ge=0, le=1)
    failure_category: AdvisoryTurnFailureCategory | None

    @model_validator(mode="after")
    def validate_turn(self) -> AdvisoryTurnSummary:
        if self.selected_proposal_count > self.proposal_count:
            raise ValueError("selected advisory proposals cannot exceed proposals")
        if self.status is AdvisoryTurnStatus.STARTED:
            valid = (
                self.output_sha256 is None
                and self.proposal_count == 0
                and self.selected_proposal_count == 0
                and self.failure_category is None
            )
        elif self.status is AdvisoryTurnStatus.COMPLETED:
            valid = self.output_sha256 is not None and self.failure_category is None
        elif self.status is AdvisoryTurnStatus.FAILED:
            valid = (
                self.proposal_count == 0
                and self.selected_proposal_count == 0
                and self.failure_category is not None
            )
        else:
            valid = (
                self.output_sha256 is None
                and self.proposal_count == 0
                and self.selected_proposal_count == 0
                and self.failure_category is None
            )
        if not valid:
            raise ValueError("advisory turn fields do not match its status")
        return self


class ProbeRequestDisposition(StrEnum):
    SELECTED = "selected"
    DEFERRED = "deferred"
    DUPLICATE = "duplicate"
    UNSUPPORTED_CAPABILITY = "unsupported_capability"
    INVALID_EFFECT_REFERENCE = "invalid_effect_reference"
    INVALID_ARGUMENTS = "invalid_arguments"
    UNAVAILABLE = "unavailable"
    BUDGET_EXCEEDED = "budget_exceeded"
    IGNORED_EXPLANATION_PHASE = "ignored_explanation_phase"


class SanitizedProbeRequest(StrictModel):
    request_sequence: int = Field(ge=1, le=_MAX_PROPOSAL_EVENTS)
    advisory_turn_sequence: int | None = Field(
        default=None,
        ge=1,
        le=_MAX_ADVISORY_TURNS,
    )
    proposal_sequence: int | None = Field(default=None, ge=1, le=8)
    capability_name: Identifier
    capability_version: Identifier
    request_sha256: Sha256Digest
    relevant_effect_ids: tuple[Identifier, ...] = Field(
        min_length=1,
        max_length=64,
    )
    disposition: ProbeRequestDisposition

    @model_validator(mode="after")
    def validate_request(self) -> SanitizedProbeRequest:
        if len(self.relevant_effect_ids) != len(set(self.relevant_effect_ids)):
            raise ValueError("probe request effect identifiers must be unique")
        if (self.advisory_turn_sequence is None) is not (
            self.proposal_sequence is None
        ):
            raise ValueError("adaptive proposal identity must be complete")
        if (
            self.disposition is not ProbeRequestDisposition.SELECTED
            and self.advisory_turn_sequence is None
        ):
            raise ValueError("rejected proposals require an advisory turn")
        return self


class SanitizedProbeResult(StrictModel):
    probe_sequence: int = Field(ge=1, le=64)
    capability_name: Identifier | None
    capability_version: Identifier | None
    request_sha256: Sha256Digest | None
    outcome: ProbeOutcome
    stop_reason: Identifier
    result_sha256: Sha256Digest | None
    result_byte_count: int | None = Field(default=None, ge=0, le=_MAX_SIGNED_64)
    evidence_ids: tuple[Identifier, ...] = Field(min_length=1, max_length=1)

    @model_validator(mode="after")
    def validate_result(self) -> SanitizedProbeResult:
        if (self.capability_name is None) is not (self.capability_version is None):
            raise ValueError("probe result capability identity must be complete")
        if self.outcome is ProbeOutcome.COMPLETED:
            if (
                self.capability_name is None
                or self.request_sha256 is None
                or self.result_sha256 is None
                or self.result_byte_count is None
            ):
                raise ValueError("completed probe results require bounded identity")
        elif self.result_sha256 is not None or self.result_byte_count is not None:
            raise ValueError("noncompleted probes cannot expose result identity")
        return self


class TerminalStateSummary(StrictModel):
    lifecycle: Literal[
        ScenarioRunLifecycle.COMPLETED,
        ScenarioRunLifecycle.FAILED,
        ScenarioRunLifecycle.CANCELLED,
    ]
    result_kind: ScenarioRunResultKind
    classification: Classification | None
    action_gate_allowed_count: int = Field(
        ge=0,
        le=len(RequestedAction),
    )
    action_gate_denied_count: int = Field(
        ge=0,
        le=len(RequestedAction),
    )
    missing_evidence_count: int = Field(ge=0, le=64)
    escalation_required: bool | None
    failure_category: ScenarioRunFailureCategory | None
    route_provenance: ScenarioRouteProvenance | None = None

    @model_validator(mode="after")
    def validate_terminal_state(self) -> TerminalStateSummary:
        action_count = self.action_gate_allowed_count + self.action_gate_denied_count
        if self.lifecycle is ScenarioRunLifecycle.COMPLETED:
            if self.failure_category is not None:
                raise ValueError("completed terminal states cannot contain failures")
            if self.result_kind is ScenarioRunResultKind.REPORT:
                if (
                    self.classification is None
                    or action_count != len(RequestedAction)
                    or self.escalation_required
                    is not (self.classification is not Classification.COMMITTED)
                ):
                    raise ValueError("report terminal state is incomplete")
            elif self.result_kind is ScenarioRunResultKind.COMPARISON:
                if (
                    self.classification is not None
                    or action_count != 0
                    or self.missing_evidence_count != 0
                    or self.escalation_required is not None
                    or self.route_provenance is not None
                ):
                    raise ValueError("comparison terminal state must remain neutral")
            else:
                raise ValueError("completed terminal states require a result")
        elif self.lifecycle is ScenarioRunLifecycle.FAILED:
            if (
                self.result_kind is not ScenarioRunResultKind.NONE
                or self.classification is not None
                or action_count != 0
                or self.missing_evidence_count != 0
                or self.escalation_required is not None
                or self.failure_category is None
                or self.route_provenance is not None
            ):
                raise ValueError("failed terminal state is inconsistent")
        elif (
            self.result_kind is not ScenarioRunResultKind.NONE
            or self.classification is not None
            or action_count != 0
            or self.missing_evidence_count != 0
            or self.escalation_required is not None
            or self.failure_category is not None
            or self.route_provenance is not None
        ):
            raise ValueError("cancelled terminal state is inconsistent")
        return self


class ScenarioRunEventType(StrEnum):
    LIFECYCLE = "LIFECYCLE"
    ENVELOPE_SUMMARY = "ENVELOPE_SUMMARY"
    ADVISORY_TURN = "ADVISORY_TURN"
    PROBE_REQUEST = "PROBE_REQUEST"
    PROBE_RESULT = "PROBE_RESULT"
    EVIDENCE_DECISION = "EVIDENCE_DECISION"
    TERMINAL = "TERMINAL"


class ScenarioLifecycleEventPayload(StrictModel):
    lifecycle: Literal[
        ScenarioRunLifecycle.ACCEPTED,
        ScenarioRunLifecycle.RUNNING,
    ]


class EnvelopeSummaryEventPayload(StrictModel):
    summary: ExecutionEnvelopeSummary


class AdvisoryTurnEventPayload(StrictModel):
    turn: AdvisoryTurnSummary


class ProbeRequestEventPayload(StrictModel):
    strategy: ComparisonStrategyKind
    request: SanitizedProbeRequest


class ProbeResultEventPayload(StrictModel):
    strategy: ComparisonStrategyKind
    probe: SanitizedProbeResult


class OperatorEvidenceDecisionEventPayload(StrictModel):
    strategy: ComparisonStrategyKind
    decision: EvidenceDecision


class TerminalStateEventPayload(StrictModel):
    terminal: TerminalStateSummary


type ScenarioRunEventPayload = (
    ScenarioLifecycleEventPayload
    | EnvelopeSummaryEventPayload
    | AdvisoryTurnEventPayload
    | ProbeRequestEventPayload
    | ProbeResultEventPayload
    | OperatorEvidenceDecisionEventPayload
    | TerminalStateEventPayload
)


_EVENT_PAYLOAD_TYPES = {
    ScenarioRunEventType.LIFECYCLE: ScenarioLifecycleEventPayload,
    ScenarioRunEventType.ENVELOPE_SUMMARY: EnvelopeSummaryEventPayload,
    ScenarioRunEventType.ADVISORY_TURN: AdvisoryTurnEventPayload,
    ScenarioRunEventType.PROBE_REQUEST: ProbeRequestEventPayload,
    ScenarioRunEventType.PROBE_RESULT: ProbeResultEventPayload,
    ScenarioRunEventType.EVIDENCE_DECISION: OperatorEvidenceDecisionEventPayload,
    ScenarioRunEventType.TERMINAL: TerminalStateEventPayload,
}


class ScenarioRunEvent(StrictModel):
    model_config = ConfigDict(
        json_schema_extra={
            "allOf": [
                {
                    "if": {
                        "properties": {"type": {"const": event_type.value}},
                        "required": ["type"],
                    },
                    "then": {"properties": {"payload": {"required": [field]}}},
                }
                for event_type, field in (
                    (ScenarioRunEventType.LIFECYCLE, "lifecycle"),
                    (ScenarioRunEventType.ENVELOPE_SUMMARY, "summary"),
                    (ScenarioRunEventType.ADVISORY_TURN, "turn"),
                    (ScenarioRunEventType.PROBE_REQUEST, "request"),
                    (ScenarioRunEventType.PROBE_RESULT, "probe"),
                    (ScenarioRunEventType.EVIDENCE_DECISION, "decision"),
                    (ScenarioRunEventType.TERMINAL, "terminal"),
                )
            ]
        }
    )

    schema_version: Literal[SCENARIO_RUN_EVENT_VERSION]
    investigation_id: Identifier
    cursor: int = Field(ge=1, le=MAX_SCENARIO_RUN_EVENTS)
    type: ScenarioRunEventType
    occurred_at: AwareDatetime
    payload: ScenarioRunEventPayload

    @model_validator(mode="after")
    def validate_event(self) -> ScenarioRunEvent:
        expected_payload = _EVENT_PAYLOAD_TYPES[self.type]
        if not isinstance(self.payload, expected_payload):
            raise ValueError("scenario event type does not match its payload")
        if (
            isinstance(self.payload, EnvelopeSummaryEventPayload)
            and self.payload.summary.investigation_id != self.investigation_id
        ):
            raise ValueError("event envelope investigation does not match")
        return self


__all__ = [
    "BOUNDED_HYBRID_ROUTE_POLICY_VERSION",
    "EXECUTION_ENVELOPE_SUMMARY_VERSION",
    "MAX_SCENARIO_RUN_EVENTS",
    "SCENARIO_LAUNCH_REQUEST_VERSION",
    "SCENARIO_RUN_EVENT_VERSION",
    "SCENARIO_RUN_SNAPSHOT_VERSION",
    "AdvisoryTurnEventPayload",
    "AdvisoryTurnFailureCategory",
    "AdvisoryTurnStatus",
    "AdvisoryTurnSummary",
    "EnvelopeEffectSummary",
    "EnvelopeSummaryEventPayload",
    "ExecutionEnvelopeSummary",
    "OperatorEvidenceDecisionEventPayload",
    "ProbeRequestDisposition",
    "ProbeRequestEventPayload",
    "ProbeResultEventPayload",
    "SanitizedComparisonRun",
    "SanitizedDeterministicProof",
    "SanitizedEffectFinding",
    "SanitizedEvidenceSummary",
    "SanitizedInvestigationComparison",
    "SanitizedInvestigationReport",
    "SanitizedMissingEvidence",
    "SanitizedProbeAuditRecord",
    "SanitizedProbeRequest",
    "SanitizedProbeResult",
    "ScenarioHybridOutcome",
    "ScenarioHybridRoute",
    "ScenarioLaunchName",
    "ScenarioLaunchRequest",
    "ScenarioLifecycleEventPayload",
    "ScenarioRouteProvenance",
    "ScenarioRunEvent",
    "ScenarioRunEventPayload",
    "ScenarioRunEventType",
    "ScenarioRunFailureCategory",
    "ScenarioRunLifecycle",
    "ScenarioRunMode",
    "ScenarioRunResultKind",
    "ScenarioRunSnapshot",
    "TerminalStateEventPayload",
    "TerminalStateSummary",
]
