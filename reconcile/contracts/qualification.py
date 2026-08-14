"""Versioned contracts for preregistered adaptive qualification."""

from __future__ import annotations

from enum import StrEnum
from typing import Literal

from pydantic import Field, model_validator

from reconcile.contracts.base import (
    AwareDatetime,
    Identifier,
    Sha256Digest,
    StrictModel,
)
from reconcile.contracts.common import EvidenceBudget
from reconcile.contracts.comparison import (
    ComparisonStrategyKind,
    InvestigationComparisonRecord,
    PreregisteredExpectedClassification,
)
from reconcile.contracts.scenario import ScenarioRef

QUALIFICATION_SUITE_MANIFEST_VERSION = "reconcile/qualification-suite-manifest/v1"
QUALIFICATION_CASE_RESULT_VERSION = "reconcile/qualification-case-result/v1"
QUALIFICATION_RESULT_SET_VERSION = "reconcile/qualification-result-set/v1"
QUALIFICATION_SUMMARY_VERSION = "reconcile/qualification-summary/v1"
QUALIFICATION_DISPOSITION_VERSION = "reconcile/qualification-disposition/v1"

MAX_QUALIFICATION_CASES = 64
MAX_QUALIFICATION_REPETITIONS = 16
MAX_QUALIFICATION_RESULTS = MAX_QUALIFICATION_CASES * MAX_QUALIFICATION_REPETITIONS
_MAX_SIGNED_64 = 2**63 - 1


class QualificationMetric(StrEnum):
    SAFETY_PARITY = "safety_parity"
    DETERMINISTIC_CLASSIFICATION_PARITY = "deterministic_classification_parity"
    CLASSIFICATION_COVERAGE = "classification_coverage"
    EXECUTED_PROBE_COUNT = "executed_probe_count"
    TIME_TO_SUFFICIENT_EVIDENCE = "time_to_sufficient_evidence"
    UNSUPPORTED_PROBE_COUNT = "unsupported_probe_count"
    UNNECESSARY_PROBE_COUNT = "unnecessary_probe_count"
    EXPLANATION_COMPLETENESS = "explanation_completeness"
    UNKNOWN_OUTCOME_COUNT = "unknown_outcome_count"
    MODEL_COST = "model_cost"


class QualificationCaseRole(StrEnum):
    MEASUREMENT = "MEASUREMENT"
    FAIL_CLOSED_CONTROL = "FAIL_CLOSED_CONTROL"


class QualificationEvidenceProfile(StrEnum):
    AUTHORITATIVE_SINGLE_LOOKUP = "authoritative_single_lookup"
    HETEROGENEOUS_CONDITIONAL = "heterogeneous_conditional"
    REDUNDANT_CAPABILITIES = "redundant_capabilities"
    WEAK_ONLY = "weak_only"
    PROVIDER_FAILURE = "provider_failure"
    EQUAL_OUTCOME = "equal_outcome"


class QualificationOpportunity(StrEnum):
    FIXED_EFFICIENCY = "fixed_efficiency"
    ADAPTIVE_EFFICIENCY = "adaptive_efficiency"
    NEUTRAL = "neutral"
    FAIL_CLOSED = "fail_closed"


class QualificationLaneOrder(StrEnum):
    FIXED_FIRST = "FIXED_FIRST"
    ADAPTIVE_FIRST = "ADAPTIVE_FIRST"


class QualificationCaseResultStatus(StrEnum):
    COMPLETED = "COMPLETED"
    CONTROL_PASSED = "CONTROL_PASSED"
    CONTROL_FAILED = "CONTROL_FAILED"
    FAILED = "FAILED"
    INVALID = "INVALID"


class QualificationDispositionKind(StrEnum):
    ADAPTIVE_VALUE_DEMONSTRATED = "ADAPTIVE_VALUE_DEMONSTRATED"
    NO_MEASURABLE_VALUE = "NO_MEASURABLE_VALUE"
    UNSAFE = "UNSAFE"
    INCONCLUSIVE = "INCONCLUSIVE"
    INVALID_RUN = "INVALID_RUN"


class QualificationDispositionReason(StrEnum):
    ADAPTIVE_BENEFIT_THRESHOLD_MET = "adaptive_benefit_threshold_met"
    ADAPTIVE_BENEFIT_THRESHOLD_NOT_MET = "adaptive_benefit_threshold_not_met"
    SAFETY_PARITY_FAILED = "safety_parity_failed"
    CLASSIFICATION_PARITY_FAILED = "classification_parity_failed"
    PREREGISTERED_EXPECTATION_MISMATCH = "preregistered_expectation_mismatch"
    FAIL_CLOSED_CONTROL_FAILED = "fail_closed_control_failed"
    RESULT_SET_INCOMPLETE = "result_set_incomplete"
    FAILED_RESULT_PRESENT = "failed_result_present"
    INTEGRITY_INVALID = "integrity_invalid"
    INSUFFICIENT_VALID_RESULTS = "insufficient_valid_results"
    COST_LIMIT_EXCEEDED = "cost_limit_exceeded"


class QualificationProviderSettings(StrictModel):
    provider_name: Identifier
    model_name: Identifier
    model_revision: Identifier
    location: Identifier
    prompt_version: Identifier
    adk_version: Identifier
    genai_version: Identifier
    timeout_ms: int = Field(ge=1, le=300_000)
    max_output_tokens: int = Field(ge=1, le=65_536)
    temperature_milli: int = Field(ge=0, le=2_000)
    billing_currency: Literal["USD"]
    input_cost_nano_units_per_token: int = Field(ge=0, le=_MAX_SIGNED_64)
    output_cost_nano_units_per_token: int = Field(ge=0, le=_MAX_SIGNED_64)

    @model_validator(mode="after")
    def validate_deterministic_settings(self) -> QualificationProviderSettings:
        if self.temperature_milli != 0:
            raise ValueError("qualification temperature must remain zero")
        return self


class QualificationThresholds(StrictModel):
    minimum_valid_measurement_results: int = Field(
        ge=1,
        le=MAX_QUALIFICATION_RESULTS,
    )
    minimum_suite_median_probe_reduction: int = Field(ge=1, le=_MAX_SIGNED_64)
    minimum_suite_median_time_reduction_basis_points: int = Field(
        ge=1,
        le=10_000,
    )
    minimum_suite_median_sufficient_time_reduction_ms: int = Field(
        ge=1,
        le=_MAX_SIGNED_64,
    )
    fallback_heterogeneous_case_id: Identifier
    minimum_fallback_case_successful_repetitions: int = Field(
        ge=1,
        le=MAX_QUALIFICATION_REPETITIONS,
    )
    explanation_completeness_can_demonstrate_value: Literal[False]


class QualificationStopConditions(StrictModel):
    stop_on_safety_failure: Literal[True]
    stop_on_source_mismatch: Literal[True]
    stop_on_manifest_mismatch: Literal[True]
    maximum_failed_results: int = Field(ge=0, le=MAX_QUALIFICATION_RESULTS)
    maximum_total_model_calls: int = Field(ge=1, le=_MAX_SIGNED_64)
    maximum_total_input_tokens: int = Field(ge=1, le=_MAX_SIGNED_64)
    maximum_total_output_tokens: int = Field(ge=1, le=_MAX_SIGNED_64)
    maximum_total_model_cost_nano_units: int = Field(ge=1, le=_MAX_SIGNED_64)


class QualificationCaseDefinition(StrictModel):
    case_id: Identifier
    scenario: ScenarioRef
    fixture_id: Identifier
    seed: int = Field(ge=0, le=_MAX_SIGNED_64)
    role: QualificationCaseRole
    evidence_profile: QualificationEvidenceProfile
    opportunity: QualificationOpportunity
    expectation: PreregisteredExpectedClassification | None
    evidence_budget: EvidenceBudget

    @model_validator(mode="after")
    def validate_case_role(self) -> QualificationCaseDefinition:
        if self.role is QualificationCaseRole.MEASUREMENT:
            if self.expectation is None:
                raise ValueError("measurement cases require a frozen expectation")
            if self.evidence_profile is QualificationEvidenceProfile.PROVIDER_FAILURE:
                raise ValueError("provider failure is reserved for the control case")
            if self.opportunity is QualificationOpportunity.FAIL_CLOSED:
                raise ValueError("measurement cases cannot be fail-closed controls")
        elif (
            self.expectation is not None
            or self.evidence_profile
            is not QualificationEvidenceProfile.PROVIDER_FAILURE
            or self.opportunity is not QualificationOpportunity.FAIL_CLOSED
        ):
            raise ValueError("fail-closed control fields are inconsistent")
        return self


class QualificationSuiteManifest(StrictModel):
    schema_version: Literal[QUALIFICATION_SUITE_MANIFEST_VERSION]
    suite_id: Identifier
    source_revision: Sha256Digest
    registered_at: AwareDatetime
    provider: QualificationProviderSettings
    controller_version: Identifier
    fixed_strategy_version: Identifier
    adaptive_strategy_version: Identifier
    authority_policy_version: Identifier
    classification_policy_version: Identifier
    action_policy_version: Identifier
    metrics: tuple[QualificationMetric, ...] = Field(
        min_length=len(QualificationMetric),
        max_length=len(QualificationMetric),
    )
    thresholds: QualificationThresholds
    stop_conditions: QualificationStopConditions
    repetition_count: int = Field(ge=1, le=MAX_QUALIFICATION_REPETITIONS)
    lane_orders: tuple[QualificationLaneOrder, ...] = Field(
        min_length=1,
        max_length=MAX_QUALIFICATION_REPETITIONS,
    )
    cases: tuple[QualificationCaseDefinition, ...] = Field(
        min_length=8,
        max_length=8,
    )

    @model_validator(mode="after")
    def validate_manifest(self) -> QualificationSuiteManifest:
        if self.metrics != tuple(QualificationMetric):
            raise ValueError("qualification metrics must use the complete frozen order")
        if len(self.lane_orders) != self.repetition_count:
            raise ValueError("lane order schedule must cover every repetition")
        if self.repetition_count > 1 and set(self.lane_orders) != set(
            QualificationLaneOrder
        ):
            raise ValueError("repeated qualification must exercise both lane orders")

        case_ids = tuple(item.case_id for item in self.cases)
        if case_ids != tuple(sorted(case_ids)) or len(case_ids) != len(set(case_ids)):
            raise ValueError("qualification cases must be uniquely ordered")
        fixtures = tuple((item.scenario.name, item.fixture_id) for item in self.cases)
        if len(fixtures) != len(set(fixtures)):
            raise ValueError("qualification fixture identities must be unique")
        seeds = tuple((item.scenario.name, item.seed) for item in self.cases)
        if len(seeds) != len(set(seeds)):
            raise ValueError("qualification scenario seeds must be unique")

        controls = tuple(
            item
            for item in self.cases
            if item.role is QualificationCaseRole.FAIL_CLOSED_CONTROL
        )
        if len(controls) != 1:
            raise ValueError("qualification requires one provider failure control")
        required_profiles = set(QualificationEvidenceProfile)
        if {item.evidence_profile for item in self.cases} != required_profiles:
            raise ValueError("qualification cases do not cover every evidence profile")
        required_scenarios = {
            "storage-object",
            "firestore-business-operation",
            "sandbox-order-unknown",
        }
        if not required_scenarios <= {item.scenario.name for item in self.cases}:
            raise ValueError("qualification cases omit a canonical scenario")
        opportunities = {item.opportunity for item in self.cases}
        if (
            not {
                QualificationOpportunity.FIXED_EFFICIENCY,
                QualificationOpportunity.ADAPTIVE_EFFICIENCY,
                QualificationOpportunity.NEUTRAL,
                QualificationOpportunity.FAIL_CLOSED,
            }
            <= opportunities
        ):
            raise ValueError("qualification cases omit a required opportunity")

        measurement_count = (
            sum(item.role is QualificationCaseRole.MEASUREMENT for item in self.cases)
            * self.repetition_count
        )
        if self.thresholds.minimum_valid_measurement_results > measurement_count:
            raise ValueError("valid result threshold exceeds measurement schedule")
        fallback = tuple(
            item
            for item in self.cases
            if item.case_id == self.thresholds.fallback_heterogeneous_case_id
        )
        if (
            len(fallback) != 1
            or fallback[0].role is not QualificationCaseRole.MEASUREMENT
            or fallback[0].evidence_profile
            is not QualificationEvidenceProfile.HETEROGENEOUS_CONDITIONAL
        ):
            raise ValueError("fallback threshold must bind one heterogeneous case")
        if (
            self.thresholds.minimum_fallback_case_successful_repetitions
            > self.repetition_count
        ):
            raise ValueError("fallback threshold exceeds the repetition schedule")
        return self


class QualificationArtifactIdentity(StrictModel):
    artifact_id: Identifier
    sha256: Sha256Digest
    byte_count: int = Field(ge=0, le=_MAX_SIGNED_64)


class QualificationLaneArtifacts(StrictModel):
    strategy_kind: ComparisonStrategyKind
    raw_observations: QualificationArtifactIdentity
    normalized_run: QualificationArtifactIdentity | None
    failure_record: QualificationArtifactIdentity | None

    @model_validator(mode="after")
    def validate_artifacts(self) -> QualificationLaneArtifacts:
        if (self.normalized_run is None) is (self.failure_record is None):
            raise ValueError(
                "lane artifacts require one normalized run or failure record"
            )
        return self


class QualificationValidity(StrictModel):
    manifest_binding_valid: bool
    source_binding_valid: bool
    provider_settings_match: bool
    fixture_binding_valid: bool
    scenario_binding_valid: bool
    envelope_binding_valid: bool
    artifact_binding_valid: bool
    model_cost_measured: bool
    within_preregistered_budget: bool
    strategy_versions_match: bool
    policy_versions_match: bool
    classifications_match: bool
    fixed_matches_expectation: bool
    adaptive_matches_expectation: bool
    action_gates_match: bool
    model_has_no_classification_or_action_authority: bool
    probes_allowlisted_and_read_only: bool
    integrity_valid: bool
    safety_valid: bool
    eligible_for_value_evidence: bool

    @model_validator(mode="after")
    def validate_derived_validity(self) -> QualificationValidity:
        integrity = all(
            (
                self.manifest_binding_valid,
                self.source_binding_valid,
                self.provider_settings_match,
                self.fixture_binding_valid,
                self.scenario_binding_valid,
                self.envelope_binding_valid,
                self.artifact_binding_valid,
                self.model_cost_measured,
                self.within_preregistered_budget,
                self.strategy_versions_match,
                self.policy_versions_match,
            )
        )
        safety = all(
            (
                self.classifications_match,
                self.action_gates_match,
                self.model_has_no_classification_or_action_authority,
                self.probes_allowlisted_and_read_only,
            )
        )
        eligible = all(
            (
                integrity,
                safety,
                self.fixed_matches_expectation,
                self.adaptive_matches_expectation,
            )
        )
        if (
            self.integrity_valid is not integrity
            or self.safety_valid is not safety
            or self.eligible_for_value_evidence is not eligible
        ):
            raise ValueError("qualification validity flags must be derived")
        return self


class QualificationControlOutcome(StrictModel):
    provider_failure_observed: bool
    classification_emitted: bool
    consequential_action_allowed: bool
    model_mutation_attempted: bool
    failure_artifact_retained: bool
    passed: bool

    @model_validator(mode="after")
    def validate_control(self) -> QualificationControlOutcome:
        passed = (
            self.provider_failure_observed
            and not self.classification_emitted
            and not self.consequential_action_allowed
            and not self.model_mutation_attempted
            and self.failure_artifact_retained
        )
        if self.passed is not passed:
            raise ValueError("fail-closed control outcome must be derived")
        return self


class QualificationCaseResult(StrictModel):
    schema_version: Literal[QUALIFICATION_CASE_RESULT_VERSION]
    execution_id: Identifier
    suite_id: Identifier
    manifest_sha256: Sha256Digest
    source_revision: Sha256Digest
    case_id: Identifier
    repetition: int = Field(ge=1, le=MAX_QUALIFICATION_REPETITIONS)
    lane_order: QualificationLaneOrder
    status: QualificationCaseResultStatus
    comparison: InvestigationComparisonRecord | None
    validity: QualificationValidity | None
    control_outcome: QualificationControlOutcome | None
    artifacts: tuple[QualificationLaneArtifacts, ...] = Field(max_length=2)
    failure_category: Identifier | None

    @model_validator(mode="after")
    def validate_result_shape(self) -> QualificationCaseResult:
        strategies = tuple(item.strategy_kind for item in self.artifacts)
        if len(strategies) != len(set(strategies)):
            raise ValueError("qualification lane artifacts must be unique")

        if self.status is QualificationCaseResultStatus.COMPLETED:
            if (
                self.comparison is None
                or self.comparison.adaptive is None
                or self.validity is None
                or self.control_outcome is not None
                or self.failure_category is not None
                or set(strategies) != set(ComparisonStrategyKind)
                or any(item.normalized_run is None for item in self.artifacts)
            ):
                raise ValueError("completed measurement result is incomplete")
            if self.comparison.case_id != self.case_id:
                raise ValueError("comparison case identity does not match result")
        elif self.status in {
            QualificationCaseResultStatus.CONTROL_PASSED,
            QualificationCaseResultStatus.CONTROL_FAILED,
        }:
            expected_pass = self.status is QualificationCaseResultStatus.CONTROL_PASSED
            if (
                self.comparison is not None
                or self.validity is not None
                or self.control_outcome is None
                or self.control_outcome.passed is not expected_pass
                or set(strategies) != {ComparisonStrategyKind.ADAPTIVE}
                or self.artifacts[0].failure_record is None
                or (expected_pass and self.failure_category is not None)
                or (not expected_pass and self.failure_category is None)
            ):
                raise ValueError("fail-closed control result is inconsistent")
        elif (
            self.failure_category is None
            or self.validity is not None
            or self.control_outcome is not None
        ):
            raise ValueError("failed and invalid results require only failure evidence")
        return self


class QualificationResultSet(StrictModel):
    schema_version: Literal[QUALIFICATION_RESULT_SET_VERSION]
    suite_id: Identifier
    manifest_sha256: Sha256Digest
    source_revision: Sha256Digest
    results: tuple[QualificationCaseResult, ...] = Field(
        min_length=1,
        max_length=MAX_QUALIFICATION_RESULTS,
    )

    @model_validator(mode="after")
    def validate_result_set(self) -> QualificationResultSet:
        identities = tuple((item.case_id, item.repetition) for item in self.results)
        if identities != tuple(sorted(identities)) or len(identities) != len(
            set(identities)
        ):
            raise ValueError("qualification results must be uniquely ordered")
        execution_ids = tuple(item.execution_id for item in self.results)
        if len(execution_ids) != len(set(execution_ids)):
            raise ValueError("qualification execution identities must be unique")
        if any(
            item.suite_id != self.suite_id
            or item.manifest_sha256 != self.manifest_sha256
            or item.source_revision != self.source_revision
            for item in self.results
        ):
            raise ValueError("qualification result binding does not match result set")
        return self


class QualificationLaneMetrics(StrictModel):
    strategy_kind: ComparisonStrategyKind
    run_count: int = Field(ge=0, le=MAX_QUALIFICATION_RESULTS)
    classification_coverage_count: int = Field(
        ge=0,
        le=MAX_QUALIFICATION_RESULTS,
    )
    unknown_outcome_count: int = Field(ge=0, le=MAX_QUALIFICATION_RESULTS)
    planned_probe_count: int = Field(ge=0, le=_MAX_SIGNED_64)
    executed_probe_count: int = Field(ge=0, le=_MAX_SIGNED_64)
    sufficient_time_observation_count: int = Field(
        ge=0,
        le=MAX_QUALIFICATION_RESULTS,
    )
    total_time_to_sufficient_evidence_ms: int = Field(ge=0, le=_MAX_SIGNED_64)
    unsupported_probe_count: int = Field(ge=0, le=_MAX_SIGNED_64)
    unnecessary_probe_count: int = Field(ge=0, le=_MAX_SIGNED_64)
    duplicate_probe_count: int = Field(ge=0, le=_MAX_SIGNED_64)
    complete_explanation_count: int = Field(
        ge=0,
        le=MAX_QUALIFICATION_RESULTS,
    )
    controller_cost_units: int = Field(ge=0, le=_MAX_SIGNED_64)
    controller_result_bytes: int = Field(ge=0, le=_MAX_SIGNED_64)
    total_elapsed_ms: int = Field(ge=0, le=_MAX_SIGNED_64)
    measured_model_usage_count: int = Field(
        ge=0,
        le=MAX_QUALIFICATION_RESULTS,
    )
    unavailable_model_usage_count: int = Field(
        ge=0,
        le=MAX_QUALIFICATION_RESULTS,
    )
    model_call_count: int = Field(ge=0, le=_MAX_SIGNED_64)
    input_token_count: int = Field(ge=0, le=_MAX_SIGNED_64)
    output_token_count: int = Field(ge=0, le=_MAX_SIGNED_64)
    total_token_count: int = Field(ge=0, le=_MAX_SIGNED_64)
    model_cost_nano_units: int = Field(ge=0, le=_MAX_SIGNED_64)

    @model_validator(mode="after")
    def validate_metrics(self) -> QualificationLaneMetrics:
        bounded_counts = (
            self.classification_coverage_count,
            self.unknown_outcome_count,
            self.sufficient_time_observation_count,
            self.complete_explanation_count,
            self.measured_model_usage_count,
            self.unavailable_model_usage_count,
        )
        if any(value > self.run_count for value in bounded_counts):
            raise ValueError("qualification metric count exceeds lane run count")
        if self.total_token_count != self.input_token_count + self.output_token_count:
            raise ValueError("qualification token totals must be additive")
        if self.strategy_kind is ComparisonStrategyKind.FIXED and any(
            (
                self.measured_model_usage_count,
                self.unavailable_model_usage_count,
                self.model_call_count,
                self.input_token_count,
                self.output_token_count,
                self.total_token_count,
                self.model_cost_nano_units,
            )
        ):
            raise ValueError("fixed qualification metrics cannot contain model usage")
        return self


class QualificationSummary(StrictModel):
    schema_version: Literal[QUALIFICATION_SUMMARY_VERSION]
    suite_id: Identifier
    manifest_sha256: Sha256Digest
    result_set_sha256: Sha256Digest
    source_revision: Sha256Digest
    evaluated_at: AwareDatetime
    expected_result_count: int = Field(ge=1, le=MAX_QUALIFICATION_RESULTS)
    observed_result_count: int = Field(ge=0, le=MAX_QUALIFICATION_RESULTS)
    completed_measurement_count: int = Field(ge=0, le=MAX_QUALIFICATION_RESULTS)
    eligible_measurement_count: int = Field(ge=0, le=MAX_QUALIFICATION_RESULTS)
    expected_control_count: int = Field(ge=1, le=MAX_QUALIFICATION_RESULTS)
    passed_control_count: int = Field(ge=0, le=MAX_QUALIFICATION_RESULTS)
    failed_result_count: int = Field(ge=0, le=MAX_QUALIFICATION_RESULTS)
    integrity_invalid_count: int = Field(ge=0, le=MAX_QUALIFICATION_RESULTS)
    safety_failure_count: int = Field(ge=0, le=MAX_QUALIFICATION_RESULTS)
    classification_parity_failure_count: int = Field(
        ge=0,
        le=MAX_QUALIFICATION_RESULTS,
    )
    expectation_mismatch_count: int = Field(ge=0, le=MAX_QUALIFICATION_RESULTS)
    control_failure_count: int = Field(ge=0, le=MAX_QUALIFICATION_RESULTS)
    adaptive_benefit_result_count: int = Field(
        ge=0,
        le=MAX_QUALIFICATION_RESULTS,
    )
    fixed_efficiency_result_count: int = Field(
        ge=0,
        le=MAX_QUALIFICATION_RESULTS,
    )
    equal_efficiency_result_count: int = Field(
        ge=0,
        le=MAX_QUALIFICATION_RESULTS,
    )
    mixed_efficiency_result_count: int = Field(
        ge=0,
        le=MAX_QUALIFICATION_RESULTS,
    )
    suite_median_probe_reduction: int = Field(
        ge=-_MAX_SIGNED_64,
        le=_MAX_SIGNED_64,
    )
    suite_median_time_reduction_basis_points: int | None = Field(
        default=None,
        ge=-_MAX_SIGNED_64,
        le=_MAX_SIGNED_64,
    )
    suite_median_sufficient_time_reduction_ms: int | None = Field(
        default=None,
        ge=-_MAX_SIGNED_64,
        le=_MAX_SIGNED_64,
    )
    fallback_heterogeneous_success_count: int = Field(
        ge=0,
        le=MAX_QUALIFICATION_REPETITIONS,
    )
    fixed_metrics: QualificationLaneMetrics
    adaptive_metrics: QualificationLaneMetrics
    complete_result_set: bool
    cost_limit_exceeded: bool
    valid_for_value_evidence: bool

    @model_validator(mode="after")
    def validate_summary(self) -> QualificationSummary:
        if self.fixed_metrics.strategy_kind is not ComparisonStrategyKind.FIXED:
            raise ValueError("fixed summary metrics use the wrong lane")
        if self.adaptive_metrics.strategy_kind is not ComparisonStrategyKind.ADAPTIVE:
            raise ValueError("adaptive summary metrics use the wrong lane")
        if self.fixed_metrics.run_count != self.completed_measurement_count or (
            self.adaptive_metrics.run_count != self.completed_measurement_count
        ):
            raise ValueError("summary lane counts do not match completed measurements")
        if self.eligible_measurement_count > self.completed_measurement_count:
            raise ValueError("eligible measurements exceed completed measurements")
        efficiency_partition = (
            self.adaptive_benefit_result_count
            + self.fixed_efficiency_result_count
            + self.equal_efficiency_result_count
            + self.mixed_efficiency_result_count
        )
        if efficiency_partition != self.eligible_measurement_count:
            raise ValueError("efficiency result counts must partition eligible results")
        if self.passed_control_count + self.control_failure_count > (
            self.expected_control_count
        ):
            raise ValueError("control counts exceed the preregistered schedule")
        complete = self.observed_result_count == self.expected_result_count
        valid = all(
            (
                complete,
                self.failed_result_count == 0,
                self.integrity_invalid_count == 0,
                self.safety_failure_count == 0,
                self.expectation_mismatch_count == 0,
                self.control_failure_count == 0,
                self.passed_control_count == self.expected_control_count,
                not self.cost_limit_exceeded,
            )
        )
        if (
            self.complete_result_set is not complete
            or self.valid_for_value_evidence is not valid
        ):
            raise ValueError("qualification summary validity flags must be derived")
        return self


class QualificationDisposition(StrictModel):
    schema_version: Literal[QUALIFICATION_DISPOSITION_VERSION]
    suite_id: Identifier
    manifest_sha256: Sha256Digest
    result_set_sha256: Sha256Digest
    summary_sha256: Sha256Digest
    source_revision: Sha256Digest
    decided_at: AwareDatetime
    disposition: QualificationDispositionKind
    reasons: tuple[QualificationDispositionReason, ...] = Field(
        min_length=1,
        max_length=len(QualificationDispositionReason),
    )

    @model_validator(mode="after")
    def validate_reasons(self) -> QualificationDisposition:
        if self.reasons != tuple(sorted(self.reasons, key=lambda item: item.value)) or (
            len(self.reasons) != len(set(self.reasons))
        ):
            raise ValueError(
                "qualification disposition reasons must be unique and sorted"
            )
        allowed = {
            QualificationDispositionKind.ADAPTIVE_VALUE_DEMONSTRATED: {
                QualificationDispositionReason.ADAPTIVE_BENEFIT_THRESHOLD_MET,
            },
            QualificationDispositionKind.NO_MEASURABLE_VALUE: {
                QualificationDispositionReason.ADAPTIVE_BENEFIT_THRESHOLD_NOT_MET,
            },
            QualificationDispositionKind.UNSAFE: {
                QualificationDispositionReason.SAFETY_PARITY_FAILED,
                QualificationDispositionReason.CLASSIFICATION_PARITY_FAILED,
                QualificationDispositionReason.PREREGISTERED_EXPECTATION_MISMATCH,
                QualificationDispositionReason.FAIL_CLOSED_CONTROL_FAILED,
            },
            QualificationDispositionKind.INCONCLUSIVE: {
                QualificationDispositionReason.RESULT_SET_INCOMPLETE,
                QualificationDispositionReason.INSUFFICIENT_VALID_RESULTS,
                QualificationDispositionReason.FAIL_CLOSED_CONTROL_FAILED,
            },
            QualificationDispositionKind.INVALID_RUN: {
                QualificationDispositionReason.FAILED_RESULT_PRESENT,
                QualificationDispositionReason.INTEGRITY_INVALID,
                QualificationDispositionReason.COST_LIMIT_EXCEEDED,
            },
        }[self.disposition]
        if not set(self.reasons) <= allowed or not set(self.reasons) & allowed:
            raise ValueError("qualification reasons do not match the disposition")
        return self


__all__ = [
    "MAX_QUALIFICATION_CASES",
    "MAX_QUALIFICATION_REPETITIONS",
    "MAX_QUALIFICATION_RESULTS",
    "QUALIFICATION_CASE_RESULT_VERSION",
    "QUALIFICATION_DISPOSITION_VERSION",
    "QUALIFICATION_RESULT_SET_VERSION",
    "QUALIFICATION_SUITE_MANIFEST_VERSION",
    "QUALIFICATION_SUMMARY_VERSION",
    "QualificationArtifactIdentity",
    "QualificationCaseDefinition",
    "QualificationCaseResult",
    "QualificationCaseResultStatus",
    "QualificationCaseRole",
    "QualificationControlOutcome",
    "QualificationDisposition",
    "QualificationDispositionKind",
    "QualificationDispositionReason",
    "QualificationEvidenceProfile",
    "QualificationLaneArtifacts",
    "QualificationLaneMetrics",
    "QualificationLaneOrder",
    "QualificationMetric",
    "QualificationOpportunity",
    "QualificationProviderSettings",
    "QualificationResultSet",
    "QualificationStopConditions",
    "QualificationSuiteManifest",
    "QualificationSummary",
    "QualificationThresholds",
    "QualificationValidity",
]
