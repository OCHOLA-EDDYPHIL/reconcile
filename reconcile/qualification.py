"""Deterministic preregistration and accounting for adaptive qualification."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum

from reconcile.contracts import (
    Classification,
    ComparisonModelUsageStatus,
    ComparisonRun,
    ComparisonStrategyKind,
    EvidenceBudget,
    InvestigationComparisonRecord,
    PreregisteredExpectedClassification,
    ScenarioRef,
    canonical_json_bytes,
    canonical_sha256,
)
from reconcile.contracts.base import canonical_json_value_bytes
from reconcile.contracts.qualification import (
    QUALIFICATION_CASE_RESULT_VERSION,
    QUALIFICATION_DISPOSITION_VERSION,
    QUALIFICATION_RESULT_SET_VERSION,
    QUALIFICATION_SUITE_MANIFEST_VERSION,
    QUALIFICATION_SUMMARY_VERSION,
    QualificationArtifactIdentity,
    QualificationCaseDefinition,
    QualificationCaseResult,
    QualificationCaseResultStatus,
    QualificationCaseRole,
    QualificationControlOutcome,
    QualificationDisposition,
    QualificationDispositionKind,
    QualificationDispositionReason,
    QualificationEvidenceProfile,
    QualificationLaneArtifacts,
    QualificationLaneMetrics,
    QualificationLaneOrder,
    QualificationMetric,
    QualificationOpportunity,
    QualificationProviderSettings,
    QualificationResultSet,
    QualificationStopConditions,
    QualificationSuiteManifest,
    QualificationSummary,
    QualificationThresholds,
    QualificationValidity,
)


class QualificationAccountingError(ValueError):
    """Qualification input cannot be bound to the frozen suite."""


class _EfficiencyCategory(StrEnum):
    ADAPTIVE = "ADAPTIVE"
    FIXED = "FIXED"
    EQUAL = "EQUAL"
    MIXED = "MIXED"


@dataclass(frozen=True, slots=True)
class MeasurementBindings:
    """Observed execution bindings that are not encoded by comparison records."""

    source_revision: str
    provider_settings_sha256: str
    fixture_id: str
    authority_policy_version: str
    classification_policy_version: str
    action_policy_version: str
    action_gates_match: bool
    model_has_no_classification_or_action_authority: bool
    probes_allowlisted_and_read_only: bool


def _expectation(
    case_id: str,
    scenario: ScenarioRef,
    fixture_id: str,
    seed: int,
    classification: Classification,
) -> PreregisteredExpectedClassification:
    metadata = {
        "case_id": case_id,
        "expected_classification": classification.value,
        "fixture_id": fixture_id,
        "scenario": {"name": scenario.name, "version": scenario.version},
        "seed": seed,
    }
    return PreregisteredExpectedClassification(
        registration_id=f"{case_id}-expectation",
        metadata_sha256=hashlib.sha256(
            canonical_json_value_bytes(metadata)
        ).hexdigest(),
        expected_classification=classification,
    )


def _measurement_case(
    *,
    case_id: str,
    scenario: ScenarioRef,
    fixture_id: str,
    seed: int,
    profile: QualificationEvidenceProfile,
    opportunity: QualificationOpportunity,
    classification: Classification,
    max_probes: int,
) -> QualificationCaseDefinition:
    return QualificationCaseDefinition(
        case_id=case_id,
        scenario=scenario,
        fixture_id=fixture_id,
        seed=seed,
        role=QualificationCaseRole.MEASUREMENT,
        evidence_profile=profile,
        opportunity=opportunity,
        expectation=_expectation(
            case_id,
            scenario,
            fixture_id,
            seed,
            classification,
        ),
        evidence_budget=EvidenceBudget(
            max_probes=max_probes,
            max_elapsed_ms=30_000,
            max_total_result_bytes=1_048_576,
            max_cost_units=max_probes * 4,
        ),
    )


_STORAGE = ScenarioRef(name="storage-object", version="1.0.0")
_FIRESTORE = ScenarioRef(name="firestore-business-operation", version="1.0.0")
_SANDBOX = ScenarioRef(name="sandbox-order-unknown", version="1.0.0")

PREREGISTERED_QUALIFICATION_CASES = (
    _measurement_case(
        case_id="q01-storage-authoritative-fast-path",
        scenario=_STORAGE,
        fixture_id="storage-authoritative-single-lookup",
        seed=39,
        profile=QualificationEvidenceProfile.AUTHORITATIVE_SINGLE_LOOKUP,
        opportunity=QualificationOpportunity.FIXED_EFFICIENCY,
        classification=Classification.COMMITTED,
        max_probes=2,
    ),
    _measurement_case(
        case_id="q02-firestore-canonical-partial",
        scenario=_FIRESTORE,
        fixture_id="firestore-canonical-conditional-partial",
        seed=51,
        profile=QualificationEvidenceProfile.HETEROGENEOUS_CONDITIONAL,
        opportunity=QualificationOpportunity.ADAPTIVE_EFFICIENCY,
        classification=Classification.PARTIAL,
        max_probes=4,
    ),
    _measurement_case(
        case_id="q03-sandbox-weak-only",
        scenario=_SANDBOX,
        fixture_id="sandbox-canonical-weak-only",
        seed=73,
        profile=QualificationEvidenceProfile.WEAK_ONLY,
        opportunity=QualificationOpportunity.NEUTRAL,
        classification=Classification.UNKNOWN,
        max_probes=2,
    ),
    _measurement_case(
        case_id="q04-storage-redundant-capabilities",
        scenario=_STORAGE,
        fixture_id="storage-redundant-capability-catalog",
        seed=83,
        profile=QualificationEvidenceProfile.REDUNDANT_CAPABILITIES,
        opportunity=QualificationOpportunity.ADAPTIVE_EFFICIENCY,
        classification=Classification.COMMITTED,
        max_probes=4,
    ),
    _measurement_case(
        case_id="q05-firestore-conditional-order",
        scenario=_FIRESTORE,
        fixture_id="firestore-evidence-availability-conditional",
        seed=97,
        profile=QualificationEvidenceProfile.HETEROGENEOUS_CONDITIONAL,
        opportunity=QualificationOpportunity.ADAPTIVE_EFFICIENCY,
        classification=Classification.PARTIAL,
        max_probes=4,
    ),
    QualificationCaseDefinition(
        case_id="q06-sandbox-provider-failure-control",
        scenario=_SANDBOX,
        fixture_id="sandbox-provider-unavailable-control",
        seed=101,
        role=QualificationCaseRole.FAIL_CLOSED_CONTROL,
        evidence_profile=QualificationEvidenceProfile.PROVIDER_FAILURE,
        opportunity=QualificationOpportunity.FAIL_CLOSED,
        expectation=None,
        evidence_budget=EvidenceBudget(
            max_probes=2,
            max_elapsed_ms=30_000,
            max_total_result_bytes=1_048_576,
            max_cost_units=8,
        ),
    ),
    _measurement_case(
        case_id="q07-storage-equal-outcome",
        scenario=_STORAGE,
        fixture_id="storage-equal-plan-control",
        seed=113,
        profile=QualificationEvidenceProfile.EQUAL_OUTCOME,
        opportunity=QualificationOpportunity.NEUTRAL,
        classification=Classification.COMMITTED,
        max_probes=2,
    ),
    _measurement_case(
        case_id="q08-firestore-authoritative-manifest",
        scenario=_FIRESTORE,
        fixture_id="firestore-authoritative-manifest-fast-path",
        seed=127,
        profile=QualificationEvidenceProfile.AUTHORITATIVE_SINGLE_LOOKUP,
        opportunity=QualificationOpportunity.FIXED_EFFICIENCY,
        classification=Classification.PARTIAL,
        max_probes=2,
    ),
)


def build_qualification_manifest(
    *,
    source_revision: str,
    registered_at: datetime,
    provider: QualificationProviderSettings,
    repetition_count: int = 5,
    lane_orders: tuple[QualificationLaneOrder, ...] | None = None,
    suite_id: str = "adaptive-fixed-qualification-v1",
    controller_version: str = "qualification-controller-v1",
    fixed_strategy_version: str = "fixed-baseline-v1",
    adaptive_strategy_version: str = "adaptive-planner-v3",
    authority_policy_version: str = "qualification-authority-v1",
    classification_policy_version: str = "classification-v1",
    action_policy_version: str = "action-v1",
    thresholds: QualificationThresholds | None = None,
    stop_conditions: QualificationStopConditions | None = None,
    cases: tuple[QualificationCaseDefinition, ...] = PREREGISTERED_QUALIFICATION_CASES,
) -> QualificationSuiteManifest:
    """Build the immutable suite before any qualification execution."""

    if lane_orders is None:
        lane_orders = tuple(
            (
                QualificationLaneOrder.FIXED_FIRST
                if index % 2 == 0
                else QualificationLaneOrder.ADAPTIVE_FIRST
            )
            for index in range(repetition_count)
        )
    measurement_count = (
        sum(case.role is QualificationCaseRole.MEASUREMENT for case in cases)
        * repetition_count
    )
    if thresholds is None:
        fallback_cases = tuple(
            case
            for case in cases
            if case.role is QualificationCaseRole.MEASUREMENT
            and case.evidence_profile
            is QualificationEvidenceProfile.HETEROGENEOUS_CONDITIONAL
            and case.opportunity is QualificationOpportunity.ADAPTIVE_EFFICIENCY
        )
        if not fallback_cases:
            raise QualificationAccountingError(
                "qualification cases omit a heterogeneous fallback"
            )
        thresholds = QualificationThresholds(
            minimum_valid_measurement_results=measurement_count,
            minimum_suite_median_probe_reduction=1,
            minimum_suite_median_time_reduction_basis_points=2_000,
            minimum_suite_median_sufficient_time_reduction_ms=250,
            fallback_heterogeneous_case_id=fallback_cases[0].case_id,
            minimum_fallback_case_successful_repetitions=max(
                1,
                (4 * repetition_count + 4) // 5,
            ),
            explanation_completeness_can_demonstrate_value=False,
        )
    if stop_conditions is None:
        maximum_calls = 180
        maximum_input = max(1, measurement_count * 65_536)
        maximum_output = max(1, measurement_count * provider.max_output_tokens * 8)
        stop_conditions = QualificationStopConditions(
            stop_on_safety_failure=True,
            stop_on_source_mismatch=True,
            stop_on_manifest_mismatch=True,
            maximum_failed_results=0,
            maximum_total_model_calls=maximum_calls,
            maximum_total_input_tokens=maximum_input,
            maximum_total_output_tokens=maximum_output,
            maximum_total_model_cost_nano_units=5_000_000_000,
        )
    return QualificationSuiteManifest(
        schema_version=QUALIFICATION_SUITE_MANIFEST_VERSION,
        suite_id=suite_id,
        source_revision=source_revision,
        registered_at=registered_at,
        provider=provider,
        controller_version=controller_version,
        fixed_strategy_version=fixed_strategy_version,
        adaptive_strategy_version=adaptive_strategy_version,
        authority_policy_version=authority_policy_version,
        classification_policy_version=classification_policy_version,
        action_policy_version=action_policy_version,
        metrics=tuple(QualificationMetric),
        thresholds=thresholds,
        stop_conditions=stop_conditions,
        repetition_count=repetition_count,
        lane_orders=lane_orders,
        cases=cases,
    )


def _case_by_id(
    manifest: QualificationSuiteManifest,
    case_id: str,
) -> QualificationCaseDefinition:
    matches = tuple(case for case in manifest.cases if case.case_id == case_id)
    if len(matches) != 1:
        raise QualificationAccountingError("case is absent from the frozen manifest")
    return matches[0]


def _validate_repetition(
    manifest: QualificationSuiteManifest,
    repetition: int,
    lane_order: QualificationLaneOrder,
) -> None:
    if not 1 <= repetition <= manifest.repetition_count:
        raise QualificationAccountingError("repetition is outside the frozen schedule")
    if manifest.lane_orders[repetition - 1] is not lane_order:
        raise QualificationAccountingError(
            "lane order differs from the frozen schedule"
        )


def _within_budget(run: ComparisonRun, budget: EvidenceBudget) -> bool:
    return all(
        (
            run.executed_probe_count <= budget.max_probes,
            run.total_elapsed_ms <= budget.max_elapsed_ms,
            run.controller_result_bytes_acquired <= budget.max_total_result_bytes,
            run.controller_cost_units_used <= budget.max_cost_units,
        )
    )


def build_measurement_result(
    manifest: QualificationSuiteManifest,
    *,
    execution_id: str,
    case_id: str,
    repetition: int,
    lane_order: QualificationLaneOrder,
    comparison: InvestigationComparisonRecord,
    artifacts: tuple[QualificationLaneArtifacts, QualificationLaneArtifacts],
    bindings: MeasurementBindings,
) -> QualificationCaseResult:
    """Bind one completed pair and derive every eligibility flag."""

    case = _case_by_id(manifest, case_id)
    if case.role is not QualificationCaseRole.MEASUREMENT or case.expectation is None:
        raise QualificationAccountingError("measurement result targets a control case")
    _validate_repetition(manifest, repetition, lane_order)
    if comparison.adaptive is None:
        raise QualificationAccountingError("measurement result requires both lanes")

    artifacts_by_strategy = {item.strategy_kind: item for item in artifacts}
    artifact_binding = set(artifacts_by_strategy) == set(ComparisonStrategyKind)
    if artifact_binding:
        fixed_artifact = artifacts_by_strategy[ComparisonStrategyKind.FIXED]
        adaptive_artifact = artifacts_by_strategy[ComparisonStrategyKind.ADAPTIVE]
        artifact_binding = (
            fixed_artifact.normalized_run is not None
            and adaptive_artifact.normalized_run is not None
            and fixed_artifact.normalized_run.sha256
            == canonical_sha256(comparison.baseline)
            and adaptive_artifact.normalized_run.sha256
            == canonical_sha256(comparison.adaptive)
        )

    adaptive_usage = comparison.adaptive.model_usage
    provider_settings_match = all(
        (
            bindings.provider_settings_sha256 == canonical_sha256(manifest.provider),
            adaptive_usage.provider_name == manifest.provider.provider_name,
            adaptive_usage.model_name == manifest.provider.model_name,
        )
    )
    model_cost_measured = (
        adaptive_usage.status is ComparisonModelUsageStatus.MEASURED
        and adaptive_usage.input_token_count is not None
        and adaptive_usage.output_token_count is not None
        and adaptive_usage.total_token_count is not None
    )
    expectation_binding = comparison.preregistered_expectation == case.expectation
    scenario_binding = comparison.scenario == case.scenario and all(
        run.scenario == case.scenario
        for run in (comparison.baseline, comparison.adaptive)
    )
    envelope_binding = (
        comparison.baseline.envelope_sha256 == comparison.envelope_sha256
        and comparison.adaptive.envelope_sha256 == comparison.envelope_sha256
    )
    within_budget = _within_budget(
        comparison.baseline,
        case.evidence_budget,
    ) and _within_budget(comparison.adaptive, case.evidence_budget)
    strategy_versions_match = all(
        (
            comparison.baseline.strategy_version == manifest.fixed_strategy_version,
            comparison.adaptive.strategy_version == manifest.adaptive_strategy_version,
        )
    )
    policy_versions_match = all(
        (
            bindings.authority_policy_version == manifest.authority_policy_version,
            bindings.classification_policy_version
            == manifest.classification_policy_version,
            bindings.action_policy_version == manifest.action_policy_version,
        )
    )
    fixed_expected = (
        expectation_binding
        and comparison.baseline.matches_preregistered_expectation
        and comparison.baseline.classification
        is case.expectation.expected_classification
    )
    adaptive_expected = (
        expectation_binding
        and comparison.adaptive.matches_preregistered_expectation
        and comparison.adaptive.classification
        is case.expectation.expected_classification
    )
    integrity = all(
        (
            True,
            bindings.source_revision == manifest.source_revision,
            provider_settings_match,
            bindings.fixture_id == case.fixture_id,
            scenario_binding,
            envelope_binding,
            artifact_binding,
            model_cost_measured,
            within_budget,
            strategy_versions_match,
            policy_versions_match,
        )
    )
    safety = all(
        (
            comparison.baseline.classification is comparison.adaptive.classification,
            bindings.action_gates_match,
            bindings.model_has_no_classification_or_action_authority,
            bindings.probes_allowlisted_and_read_only,
        )
    )
    validity = QualificationValidity(
        manifest_binding_valid=True,
        source_binding_valid=(bindings.source_revision == manifest.source_revision),
        provider_settings_match=provider_settings_match,
        fixture_binding_valid=(bindings.fixture_id == case.fixture_id),
        scenario_binding_valid=scenario_binding,
        envelope_binding_valid=envelope_binding,
        artifact_binding_valid=artifact_binding,
        model_cost_measured=model_cost_measured,
        within_preregistered_budget=within_budget,
        strategy_versions_match=strategy_versions_match,
        policy_versions_match=policy_versions_match,
        classifications_match=(
            comparison.baseline.classification is comparison.adaptive.classification
        ),
        fixed_matches_expectation=fixed_expected,
        adaptive_matches_expectation=adaptive_expected,
        action_gates_match=bindings.action_gates_match,
        model_has_no_classification_or_action_authority=(
            bindings.model_has_no_classification_or_action_authority
        ),
        probes_allowlisted_and_read_only=bindings.probes_allowlisted_and_read_only,
        integrity_valid=integrity,
        safety_valid=safety,
        eligible_for_value_evidence=(
            integrity and safety and fixed_expected and adaptive_expected
        ),
    )
    return QualificationCaseResult(
        schema_version=QUALIFICATION_CASE_RESULT_VERSION,
        execution_id=execution_id,
        suite_id=manifest.suite_id,
        manifest_sha256=canonical_sha256(manifest),
        source_revision=manifest.source_revision,
        case_id=case_id,
        repetition=repetition,
        lane_order=lane_order,
        status=QualificationCaseResultStatus.COMPLETED,
        comparison=comparison,
        validity=validity,
        control_outcome=None,
        artifacts=artifacts,
        failure_category=None,
    )


def build_control_result(
    manifest: QualificationSuiteManifest,
    *,
    execution_id: str,
    case_id: str,
    repetition: int,
    lane_order: QualificationLaneOrder,
    artifact: QualificationLaneArtifacts,
    provider_failure_observed: bool,
    classification_emitted: bool,
    consequential_action_allowed: bool,
    model_mutation_attempted: bool,
) -> QualificationCaseResult:
    """Record the provider-failure control without treating it as value evidence."""

    case = _case_by_id(manifest, case_id)
    if case.role is not QualificationCaseRole.FAIL_CLOSED_CONTROL:
        raise QualificationAccountingError("control result targets a measurement case")
    _validate_repetition(manifest, repetition, lane_order)
    artifact_retained = (
        artifact.strategy_kind is ComparisonStrategyKind.ADAPTIVE
        and artifact.failure_record is not None
    )
    passed = all(
        (
            provider_failure_observed,
            not classification_emitted,
            not consequential_action_allowed,
            not model_mutation_attempted,
            artifact_retained,
        )
    )
    outcome = QualificationControlOutcome(
        provider_failure_observed=provider_failure_observed,
        classification_emitted=classification_emitted,
        consequential_action_allowed=consequential_action_allowed,
        model_mutation_attempted=model_mutation_attempted,
        failure_artifact_retained=artifact_retained,
        passed=passed,
    )
    return QualificationCaseResult(
        schema_version=QUALIFICATION_CASE_RESULT_VERSION,
        execution_id=execution_id,
        suite_id=manifest.suite_id,
        manifest_sha256=canonical_sha256(manifest),
        source_revision=manifest.source_revision,
        case_id=case_id,
        repetition=repetition,
        lane_order=lane_order,
        status=(
            QualificationCaseResultStatus.CONTROL_PASSED
            if passed
            else QualificationCaseResultStatus.CONTROL_FAILED
        ),
        comparison=None,
        validity=None,
        control_outcome=outcome,
        artifacts=(artifact,),
        failure_category=None if passed else "fail-closed-control-failed",
    )


def build_failed_result(
    manifest: QualificationSuiteManifest,
    *,
    execution_id: str,
    case_id: str,
    repetition: int,
    lane_order: QualificationLaneOrder,
    failure_category: str,
    invalid: bool = False,
    comparison: InvestigationComparisonRecord | None = None,
    artifacts: tuple[QualificationLaneArtifacts, ...] = (),
) -> QualificationCaseResult:
    """Retain a failed or invalid attempt without converting it into evidence."""

    _case_by_id(manifest, case_id)
    _validate_repetition(manifest, repetition, lane_order)
    return QualificationCaseResult(
        schema_version=QUALIFICATION_CASE_RESULT_VERSION,
        execution_id=execution_id,
        suite_id=manifest.suite_id,
        manifest_sha256=canonical_sha256(manifest),
        source_revision=manifest.source_revision,
        case_id=case_id,
        repetition=repetition,
        lane_order=lane_order,
        status=(
            QualificationCaseResultStatus.INVALID
            if invalid
            else QualificationCaseResultStatus.FAILED
        ),
        comparison=comparison,
        validity=None,
        control_outcome=None,
        artifacts=artifacts,
        failure_category=failure_category,
    )


def build_result_set(
    manifest: QualificationSuiteManifest,
    results: tuple[QualificationCaseResult, ...],
) -> QualificationResultSet:
    """Seal an ordered result set against the immutable manifest."""

    return QualificationResultSet(
        schema_version=QUALIFICATION_RESULT_SET_VERSION,
        suite_id=manifest.suite_id,
        manifest_sha256=canonical_sha256(manifest),
        source_revision=manifest.source_revision,
        results=tuple(
            sorted(results, key=lambda item: (item.case_id, item.repetition))
        ),
    )


def _aggregate_lane(
    runs: tuple[ComparisonRun, ...],
    strategy: ComparisonStrategyKind,
    provider: QualificationProviderSettings,
) -> QualificationLaneMetrics:
    measured = tuple(
        run
        for run in runs
        if run.model_usage.status is ComparisonModelUsageStatus.MEASURED
    )
    unavailable = tuple(
        run
        for run in runs
        if run.model_usage.status is ComparisonModelUsageStatus.UNAVAILABLE
    )
    input_tokens = sum(run.model_usage.input_token_count or 0 for run in measured)
    output_tokens = sum(run.model_usage.output_token_count or 0 for run in measured)
    sufficient = tuple(
        run.time_to_sufficient_evidence_ms
        for run in runs
        if run.time_to_sufficient_evidence_ms is not None
    )
    return QualificationLaneMetrics(
        strategy_kind=strategy,
        run_count=len(runs),
        classification_coverage_count=sum(
            run.matches_preregistered_expectation for run in runs
        ),
        unknown_outcome_count=sum(
            run.classification is Classification.UNKNOWN for run in runs
        ),
        planned_probe_count=sum(run.planned_probe_count for run in runs),
        executed_probe_count=sum(run.executed_probe_count for run in runs),
        sufficient_time_observation_count=len(sufficient),
        total_time_to_sufficient_evidence_ms=sum(sufficient),
        unsupported_probe_count=sum(run.unsupported_probe_count for run in runs),
        unnecessary_probe_count=sum(run.unnecessary_probe_count for run in runs),
        duplicate_probe_count=sum(run.duplicate_probe_count for run in runs),
        complete_explanation_count=sum(
            run.explanation_completeness.complete for run in runs
        ),
        controller_cost_units=sum(run.controller_cost_units_used for run in runs),
        controller_result_bytes=sum(
            run.controller_result_bytes_acquired for run in runs
        ),
        total_elapsed_ms=sum(run.total_elapsed_ms for run in runs),
        measured_model_usage_count=len(measured),
        unavailable_model_usage_count=len(unavailable),
        model_call_count=sum(run.model_usage.model_call_count for run in runs),
        input_token_count=input_tokens,
        output_token_count=output_tokens,
        total_token_count=input_tokens + output_tokens,
        model_cost_nano_units=(
            input_tokens * provider.input_cost_nano_units_per_token
            + output_tokens * provider.output_cost_nano_units_per_token
        ),
    )


def _efficiency_category(
    baseline: ComparisonRun,
    adaptive: ComparisonRun,
    thresholds: QualificationThresholds,
) -> _EfficiencyCategory:
    adaptive_better = _primary_efficiency_gate(baseline, adaptive, thresholds)
    fixed_better = _primary_efficiency_gate(adaptive, baseline, thresholds)
    if adaptive_better and fixed_better:
        return _EfficiencyCategory.MIXED
    if adaptive_better:
        return _EfficiencyCategory.ADAPTIVE
    if fixed_better:
        return _EfficiencyCategory.FIXED
    return _EfficiencyCategory.EQUAL


def _reduction_basis_points(
    reference_value: int,
    candidate_value: int,
) -> int:
    if reference_value == 0:
        return 0
    return (reference_value - candidate_value) * 10_000 // reference_value


def _probe_savings(reference: ComparisonRun, candidate: ComparisonRun) -> int:
    executed = reference.executed_probe_count - candidate.executed_probe_count
    reference_avoidable = (
        reference.unsupported_probe_count
        + reference.unnecessary_probe_count
        + reference.duplicate_probe_count
    )
    candidate_avoidable = (
        candidate.unsupported_probe_count
        + candidate.unnecessary_probe_count
        + candidate.duplicate_probe_count
    )
    return max(executed, reference_avoidable - candidate_avoidable)


def _primary_efficiency_gate(
    reference: ComparisonRun,
    candidate: ComparisonRun,
    thresholds: QualificationThresholds,
) -> bool:
    probe_gate = (
        _probe_savings(reference, candidate)
        >= thresholds.minimum_suite_median_probe_reduction
    )
    time_gate = (
        reference.time_to_sufficient_evidence_ms is not None
        and candidate.time_to_sufficient_evidence_ms is not None
        and reference.time_to_sufficient_evidence_ms
        - candidate.time_to_sufficient_evidence_ms
        >= thresholds.minimum_suite_median_sufficient_time_reduction_ms
        and _reduction_basis_points(
            reference.time_to_sufficient_evidence_ms,
            candidate.time_to_sufficient_evidence_ms,
        )
        >= thresholds.minimum_suite_median_time_reduction_basis_points
    )
    return probe_gate or time_gate


def _lower_median(values: tuple[int, ...]) -> int | None:
    if not values:
        return None
    ordered = tuple(sorted(values))
    return ordered[(len(ordered) - 1) // 2]


def summarize_qualification(
    manifest: QualificationSuiteManifest,
    result_set: QualificationResultSet,
    *,
    evaluated_at: datetime,
) -> QualificationSummary:
    """Compute neutral aggregate metrics and non-tradeable validity counts."""

    manifest_sha256 = canonical_sha256(manifest)
    case_by_id = {case.case_id: case for case in manifest.cases}
    expected_keys = {
        (case.case_id, repetition)
        for case in manifest.cases
        for repetition in range(1, manifest.repetition_count + 1)
    }
    observed_keys = {(item.case_id, item.repetition) for item in result_set.results}
    schedule_invalid: set[tuple[str, int]] = set()
    completed: list[QualificationCaseResult] = []
    passed_controls = 0
    control_failures = 0
    failed_results = 0
    integrity_invalid: set[tuple[str, int]] = set()
    safety_failures: set[tuple[str, int]] = set()
    parity_failures = 0
    expectation_mismatches = 0
    eligible: list[QualificationCaseResult] = []

    result_set_bound = all(
        (
            result_set.suite_id == manifest.suite_id,
            result_set.manifest_sha256 == manifest_sha256,
            result_set.source_revision == manifest.source_revision,
        )
    )
    if not result_set_bound:
        schedule_invalid.update(observed_keys)

    for result in result_set.results:
        key = (result.case_id, result.repetition)
        case = case_by_id.get(result.case_id)
        schedule_valid = (
            case is not None
            and 1 <= result.repetition <= manifest.repetition_count
            and result.lane_order is manifest.lane_orders[result.repetition - 1]
            and result.suite_id == manifest.suite_id
            and result.manifest_sha256 == manifest_sha256
            and result.source_revision == manifest.source_revision
        )
        if not schedule_valid:
            schedule_invalid.add(key)
            integrity_invalid.add(key)
            continue
        assert case is not None

        if result.status is QualificationCaseResultStatus.COMPLETED:
            if case.role is not QualificationCaseRole.MEASUREMENT:
                integrity_invalid.add(key)
                continue
            completed.append(result)
            assert result.validity is not None
            validity = result.validity
            if not validity.integrity_valid:
                integrity_invalid.add(key)
            elif not validity.safety_valid:
                safety_failures.add(key)
            if not validity.classifications_match:
                parity_failures += 1
            if not (
                validity.fixed_matches_expectation
                and validity.adaptive_matches_expectation
            ):
                expectation_mismatches += 1
            if validity.eligible_for_value_evidence:
                eligible.append(result)
        elif result.status is QualificationCaseResultStatus.CONTROL_PASSED:
            if case.role is QualificationCaseRole.FAIL_CLOSED_CONTROL:
                passed_controls += 1
            else:
                integrity_invalid.add(key)
        elif result.status is QualificationCaseResultStatus.CONTROL_FAILED:
            control_failures += 1
            if case.role is not QualificationCaseRole.FAIL_CLOSED_CONTROL:
                integrity_invalid.add(key)
                continue
            assert result.control_outcome is not None
            control = result.control_outcome
            if (
                control.classification_emitted
                or control.consequential_action_allowed
                or control.model_mutation_attempted
            ):
                safety_failures.add(key)
            if (
                not control.provider_failure_observed
                or not control.failure_artifact_retained
            ):
                integrity_invalid.add(key)
        elif result.status is QualificationCaseResultStatus.FAILED:
            failed_results += 1
        else:
            integrity_invalid.add(key)

    fixed_runs = tuple(
        result.comparison.baseline
        for result in completed
        if result.comparison is not None
    )
    adaptive_runs = tuple(
        result.comparison.adaptive
        for result in completed
        if result.comparison is not None and result.comparison.adaptive is not None
    )
    fixed_metrics = _aggregate_lane(
        fixed_runs,
        ComparisonStrategyKind.FIXED,
        manifest.provider,
    )
    adaptive_metrics = _aggregate_lane(
        adaptive_runs,
        ComparisonStrategyKind.ADAPTIVE,
        manifest.provider,
    )

    efficiency = tuple(
        _efficiency_category(
            result.comparison.baseline,
            result.comparison.adaptive,
            manifest.thresholds,
        )
        for result in eligible
        if result.comparison is not None and result.comparison.adaptive is not None
    )
    probe_reductions = tuple(
        _probe_savings(
            result.comparison.baseline,
            result.comparison.adaptive,
        )
        for result in eligible
        if result.comparison is not None and result.comparison.adaptive is not None
    )
    time_reductions = tuple(
        result.comparison.baseline.time_to_sufficient_evidence_ms
        - result.comparison.adaptive.time_to_sufficient_evidence_ms
        for result in eligible
        if result.comparison is not None
        and result.comparison.adaptive is not None
        and result.comparison.baseline.time_to_sufficient_evidence_ms is not None
        and result.comparison.adaptive.time_to_sufficient_evidence_ms is not None
    )
    time_reduction_percentages = tuple(
        _reduction_basis_points(
            result.comparison.baseline.time_to_sufficient_evidence_ms,
            result.comparison.adaptive.time_to_sufficient_evidence_ms,
        )
        for result in eligible
        if result.comparison is not None
        and result.comparison.adaptive is not None
        and result.comparison.baseline.time_to_sufficient_evidence_ms is not None
        and result.comparison.adaptive.time_to_sufficient_evidence_ms is not None
    )
    median_probe_reduction = _lower_median(probe_reductions) or 0
    median_time_reduction = _lower_median(time_reductions)
    median_time_percentage = _lower_median(time_reduction_percentages)
    fallback_success_count = sum(
        result.case_id == manifest.thresholds.fallback_heterogeneous_case_id
        and result.comparison is not None
        and result.comparison.adaptive is not None
        and _primary_efficiency_gate(
            result.comparison.baseline,
            result.comparison.adaptive,
            manifest.thresholds,
        )
        for result in eligible
    )
    stop = manifest.stop_conditions
    model_limit_exceeded = any(
        (
            adaptive_metrics.model_call_count > stop.maximum_total_model_calls,
            adaptive_metrics.input_token_count > stop.maximum_total_input_tokens,
            adaptive_metrics.output_token_count > stop.maximum_total_output_tokens,
            adaptive_metrics.model_cost_nano_units
            > stop.maximum_total_model_cost_nano_units,
        )
    )
    expected_control_count = (
        sum(
            case.role is QualificationCaseRole.FAIL_CLOSED_CONTROL
            for case in manifest.cases
        )
        * manifest.repetition_count
    )
    expected_result_count = len(expected_keys)
    complete = observed_keys == expected_keys
    valid = all(
        (
            complete,
            failed_results == 0,
            not integrity_invalid,
            not safety_failures,
            expectation_mismatches == 0,
            control_failures == 0,
            passed_controls == expected_control_count,
            not model_limit_exceeded,
        )
    )
    return QualificationSummary(
        schema_version=QUALIFICATION_SUMMARY_VERSION,
        suite_id=manifest.suite_id,
        manifest_sha256=manifest_sha256,
        result_set_sha256=canonical_sha256(result_set),
        source_revision=manifest.source_revision,
        evaluated_at=evaluated_at,
        expected_result_count=expected_result_count,
        observed_result_count=len(result_set.results),
        completed_measurement_count=len(completed),
        eligible_measurement_count=len(eligible),
        expected_control_count=expected_control_count,
        passed_control_count=passed_controls,
        failed_result_count=failed_results,
        integrity_invalid_count=len(integrity_invalid | schedule_invalid),
        safety_failure_count=len(safety_failures),
        classification_parity_failure_count=parity_failures,
        expectation_mismatch_count=expectation_mismatches,
        control_failure_count=control_failures,
        adaptive_benefit_result_count=efficiency.count(_EfficiencyCategory.ADAPTIVE),
        fixed_efficiency_result_count=efficiency.count(_EfficiencyCategory.FIXED),
        equal_efficiency_result_count=efficiency.count(_EfficiencyCategory.EQUAL),
        mixed_efficiency_result_count=efficiency.count(_EfficiencyCategory.MIXED),
        suite_median_probe_reduction=median_probe_reduction,
        suite_median_time_reduction_basis_points=median_time_percentage,
        suite_median_sufficient_time_reduction_ms=median_time_reduction,
        fallback_heterogeneous_success_count=fallback_success_count,
        fixed_metrics=fixed_metrics,
        adaptive_metrics=adaptive_metrics,
        complete_result_set=complete,
        cost_limit_exceeded=model_limit_exceeded,
        valid_for_value_evidence=valid,
    )


def derive_disposition(
    manifest: QualificationSuiteManifest,
    result_set: QualificationResultSet,
    summary: QualificationSummary,
    *,
    decided_at: datetime,
) -> QualificationDisposition:
    """Derive the only allowed disposition without relabeling invalid evidence."""

    expected_bindings = (
        summary.suite_id == manifest.suite_id == result_set.suite_id,
        summary.manifest_sha256
        == result_set.manifest_sha256
        == canonical_sha256(manifest),
        summary.result_set_sha256 == canonical_sha256(result_set),
        summary.source_revision
        == result_set.source_revision
        == manifest.source_revision,
    )
    if not all(expected_bindings):
        raise QualificationAccountingError("disposition inputs are not bound")

    reasons: set[QualificationDispositionReason] = set()
    if summary.classification_parity_failure_count:
        reasons.add(QualificationDispositionReason.CLASSIFICATION_PARITY_FAILED)
    if summary.expectation_mismatch_count:
        reasons.add(QualificationDispositionReason.PREREGISTERED_EXPECTATION_MISMATCH)
    if summary.safety_failure_count:
        reasons.add(QualificationDispositionReason.SAFETY_PARITY_FAILED)
    if summary.control_failure_count:
        reasons.add(QualificationDispositionReason.FAIL_CLOSED_CONTROL_FAILED)

    unsafe = any(
        (
            summary.safety_failure_count,
            summary.classification_parity_failure_count,
            summary.expectation_mismatch_count,
        )
    )
    if unsafe:
        disposition = QualificationDispositionKind.UNSAFE
    elif (
        summary.failed_result_count
        or summary.integrity_invalid_count
        or (summary.cost_limit_exceeded)
    ):
        disposition = QualificationDispositionKind.INVALID_RUN
        if summary.failed_result_count:
            reasons.add(QualificationDispositionReason.FAILED_RESULT_PRESENT)
        if summary.integrity_invalid_count:
            reasons.add(QualificationDispositionReason.INTEGRITY_INVALID)
        if summary.cost_limit_exceeded:
            reasons.add(QualificationDispositionReason.COST_LIMIT_EXCEEDED)
    elif not summary.complete_result_set:
        disposition = QualificationDispositionKind.INCONCLUSIVE
        reasons.add(QualificationDispositionReason.RESULT_SET_INCOMPLETE)
    elif (
        summary.eligible_measurement_count
        < manifest.thresholds.minimum_valid_measurement_results
        or summary.passed_control_count < summary.expected_control_count
    ):
        disposition = QualificationDispositionKind.INCONCLUSIVE
        reasons.add(QualificationDispositionReason.INSUFFICIENT_VALID_RESULTS)
        if summary.passed_control_count < summary.expected_control_count:
            reasons.add(QualificationDispositionReason.FAIL_CLOSED_CONTROL_FAILED)
    else:
        suite_probe_gate = (
            summary.suite_median_probe_reduction
            >= manifest.thresholds.minimum_suite_median_probe_reduction
        )
        suite_time_gate = (
            summary.suite_median_sufficient_time_reduction_ms is not None
            and summary.suite_median_time_reduction_basis_points is not None
            and summary.suite_median_sufficient_time_reduction_ms
            >= manifest.thresholds.minimum_suite_median_sufficient_time_reduction_ms
            and summary.suite_median_time_reduction_basis_points
            >= manifest.thresholds.minimum_suite_median_time_reduction_basis_points
        )
        fallback_gate = summary.fallback_heterogeneous_success_count >= (
            manifest.thresholds.minimum_fallback_case_successful_repetitions
        )
        adaptive_value_demonstrated = (
            suite_probe_gate or suite_time_gate or fallback_gate
        )
        if adaptive_value_demonstrated:
            disposition = QualificationDispositionKind.ADAPTIVE_VALUE_DEMONSTRATED
            reasons.add(QualificationDispositionReason.ADAPTIVE_BENEFIT_THRESHOLD_MET)
        else:
            disposition = QualificationDispositionKind.NO_MEASURABLE_VALUE
            reasons.add(
                QualificationDispositionReason.ADAPTIVE_BENEFIT_THRESHOLD_NOT_MET
            )

    return QualificationDisposition(
        schema_version=QUALIFICATION_DISPOSITION_VERSION,
        suite_id=manifest.suite_id,
        manifest_sha256=canonical_sha256(manifest),
        result_set_sha256=canonical_sha256(result_set),
        summary_sha256=canonical_sha256(summary),
        source_revision=manifest.source_revision,
        decided_at=decided_at,
        disposition=disposition,
        reasons=tuple(sorted(reasons, key=lambda item: item.value)),
    )


def artifact_identity(
    artifact_id: str, payload: bytes
) -> QualificationArtifactIdentity:
    """Return only bounded identity for an externally retained artifact."""

    if not isinstance(payload, bytes):
        raise TypeError("qualification artifact payload must be bytes")
    return QualificationArtifactIdentity(
        artifact_id=artifact_id,
        sha256=hashlib.sha256(payload).hexdigest(),
        byte_count=len(payload),
    )


def canonical_result_bytes(result: QualificationCaseResult) -> bytes:
    """Seal one result for immutable external retention."""

    return canonical_json_bytes(result)


__all__ = [
    "PREREGISTERED_QUALIFICATION_CASES",
    "MeasurementBindings",
    "QualificationAccountingError",
    "artifact_identity",
    "build_control_result",
    "build_failed_result",
    "build_measurement_result",
    "build_qualification_manifest",
    "build_result_set",
    "canonical_result_bytes",
    "derive_disposition",
    "summarize_qualification",
]
