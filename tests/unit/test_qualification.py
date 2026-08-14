"""Deterministic adaptive qualification accounting."""

from __future__ import annotations

import hashlib
from dataclasses import replace
from datetime import UTC, datetime

import pytest

from reconcile.contracts import (
    Classification,
    ComparisonModelUsage,
    ComparisonModelUsageStatus,
    ComparisonRun,
    ComparisonStrategyKind,
    ExplanationCompleteness,
    InvestigationComparisonRecord,
    canonical_json_bytes,
    canonical_sha256,
)
from reconcile.contracts.base import canonical_json_value_bytes
from reconcile.contracts.comparison import INVESTIGATION_COMPARISON_RECORD_VERSION
from reconcile.contracts.qualification import (
    QualificationCaseDefinition,
    QualificationCaseRole,
    QualificationDispositionKind,
    QualificationLaneArtifacts,
    QualificationLaneOrder,
    QualificationProviderSettings,
    QualificationSuiteManifest,
)
from reconcile.qualification import (
    MeasurementBindings,
    QualificationAccountingError,
    artifact_identity,
    build_control_result,
    build_failed_result,
    build_measurement_result,
    build_qualification_manifest,
    build_result_set,
    derive_disposition,
    summarize_qualification,
)

pytestmark = pytest.mark.unit

NOW = datetime(2026, 8, 14, 12, 0, tzinfo=UTC)
SOURCE_REVISION = "1" * 64


def _provider() -> QualificationProviderSettings:
    return QualificationProviderSettings(
        provider_name="google",
        model_name="gemini-2.5-flash",
        model_revision="2026-06-17",
        location="global",
        prompt_version="adaptive-qualification-v1",
        adk_version="2.6.3",
        genai_version="2.18.0",
        timeout_ms=30_000,
        max_output_tokens=2_048,
        temperature_milli=0,
        billing_currency="USD",
        input_cost_nano_units_per_token=100,
        output_cost_nano_units_per_token=400,
    )


def _manifest() -> QualificationSuiteManifest:
    return build_qualification_manifest(
        source_revision=SOURCE_REVISION,
        registered_at=NOW,
        provider=_provider(),
        repetition_count=1,
    )


def _measurement_case(
    manifest: QualificationSuiteManifest,
    case_id: str = "q01-storage-authoritative-fast-path",
) -> QualificationCaseDefinition:
    return next(case for case in manifest.cases if case.case_id == case_id)


def _comparison(
    manifest: QualificationSuiteManifest,
    case: QualificationCaseDefinition,
    *,
    fixed_probes: int = 1,
    adaptive_probes: int = 1,
    fixed_time_ms: int = 10,
    adaptive_time_ms: int = 10,
    adaptive_classification: Classification | None = None,
) -> InvestigationComparisonRecord:
    assert case.expectation is not None
    expected = case.expectation.expected_classification
    adaptive_classification = adaptive_classification or expected
    explanation = ExplanationCompleteness(
        required_evidence_citation_count=1,
        valid_evidence_citation_count=1,
        missing_evidence_citation_count=0,
        complete=True,
    )
    envelope_sha256 = hashlib.sha256(
        canonical_json_value_bytes(
            {"case_id": case.case_id, "fixture_id": case.fixture_id}
        )
    ).hexdigest()
    baseline = ComparisonRun(
        scenario=case.scenario,
        envelope_sha256=envelope_sha256,
        strategy_kind=ComparisonStrategyKind.FIXED,
        strategy_version=manifest.fixed_strategy_version,
        plan_sha256="a" * 64,
        report_sha256="b" * 64,
        classification=expected,
        matches_preregistered_expectation=True,
        planned_probe_count=fixed_probes,
        executed_probe_count=fixed_probes,
        controller_cost_units_used=fixed_probes,
        controller_result_bytes_acquired=512,
        total_elapsed_ms=fixed_time_ms,
        time_to_sufficient_evidence_ms=fixed_time_ms,
        stop_reason="sufficient-evidence",
        unsupported_probe_count=0,
        unnecessary_probe_count=0,
        duplicate_probe_count=0,
        explanation_completeness=explanation,
        model_usage=ComparisonModelUsage(
            status=ComparisonModelUsageStatus.NOT_APPLICABLE,
            model_call_count=0,
            input_token_count=0,
            output_token_count=0,
            total_token_count=0,
        ),
    )
    adaptive = ComparisonRun(
        scenario=case.scenario,
        envelope_sha256=envelope_sha256,
        strategy_kind=ComparisonStrategyKind.ADAPTIVE,
        strategy_version=manifest.adaptive_strategy_version,
        plan_sha256="c" * 64,
        report_sha256="d" * 64,
        classification=adaptive_classification,
        matches_preregistered_expectation=adaptive_classification is expected,
        planned_probe_count=adaptive_probes,
        executed_probe_count=adaptive_probes,
        controller_cost_units_used=adaptive_probes,
        controller_result_bytes_acquired=512,
        total_elapsed_ms=adaptive_time_ms,
        time_to_sufficient_evidence_ms=adaptive_time_ms,
        stop_reason="sufficient-evidence",
        unsupported_probe_count=0,
        unnecessary_probe_count=0,
        duplicate_probe_count=0,
        explanation_completeness=explanation,
        model_usage=ComparisonModelUsage(
            status=ComparisonModelUsageStatus.MEASURED,
            provider_name=manifest.provider.provider_name,
            model_name=manifest.provider.model_name,
            model_call_count=1,
            input_token_count=100,
            output_token_count=20,
            total_token_count=120,
        ),
    )
    return InvestigationComparisonRecord(
        schema_version=INVESTIGATION_COMPARISON_RECORD_VERSION,
        comparison_id=f"comparison-{case.case_id}",
        case_id=case.case_id,
        scenario=case.scenario,
        envelope_sha256=envelope_sha256,
        preregistered_expectation=case.expectation,
        baseline=baseline,
        adaptive=adaptive,
    )


def _artifacts(
    case: QualificationCaseDefinition,
    comparison: InvestigationComparisonRecord,
) -> tuple[QualificationLaneArtifacts, QualificationLaneArtifacts]:
    assert comparison.adaptive is not None
    return tuple(  # type: ignore[return-value]
        QualificationLaneArtifacts(
            strategy_kind=strategy,
            raw_observations=artifact_identity(
                f"{case.case_id}-{strategy.value.lower()}-raw",
                b"externally-retained-observation",
            ),
            normalized_run=artifact_identity(
                f"{case.case_id}-{strategy.value.lower()}-run",
                canonical_json_bytes(run),
            ),
            failure_record=None,
        )
        for strategy, run in (
            (ComparisonStrategyKind.FIXED, comparison.baseline),
            (ComparisonStrategyKind.ADAPTIVE, comparison.adaptive),
        )
    )


def _bindings(
    manifest: QualificationSuiteManifest,
    case: QualificationCaseDefinition,
) -> MeasurementBindings:
    return MeasurementBindings(
        source_revision=manifest.source_revision,
        provider_settings_sha256=canonical_sha256(manifest.provider),
        fixture_id=case.fixture_id,
        authority_policy_version=manifest.authority_policy_version,
        classification_policy_version=manifest.classification_policy_version,
        action_policy_version=manifest.action_policy_version,
        action_gates_match=True,
        model_has_no_classification_or_action_authority=True,
        probes_allowlisted_and_read_only=True,
    )


def _measurement_result(
    manifest: QualificationSuiteManifest,
    case: QualificationCaseDefinition,
    *,
    adaptive_better: bool = False,
    bindings: MeasurementBindings | None = None,
    repetition: int = 1,
    lane_order: QualificationLaneOrder = QualificationLaneOrder.FIXED_FIRST,
):
    comparison = _comparison(
        manifest,
        case,
        fixed_probes=2 if adaptive_better else 1,
        adaptive_probes=1,
        fixed_time_ms=400 if adaptive_better else 100,
        adaptive_time_ms=100,
    )
    return build_measurement_result(
        manifest,
        execution_id=f"execution-{case.case_id}-{repetition}",
        case_id=case.case_id,
        repetition=repetition,
        lane_order=lane_order,
        comparison=comparison,
        artifacts=_artifacts(case, comparison),
        bindings=bindings or _bindings(manifest, case),
    )


def _full_results(
    manifest: QualificationSuiteManifest,
    *,
    adaptive_benefit: bool = False,
    unsafe: bool = False,
):
    results = []
    benefit_recorded = False
    for case in manifest.cases:
        if case.role is QualificationCaseRole.FAIL_CLOSED_CONTROL:
            artifact = QualificationLaneArtifacts(
                strategy_kind=ComparisonStrategyKind.ADAPTIVE,
                raw_observations=artifact_identity(
                    "control-raw", b"provider-unavailable"
                ),
                normalized_run=None,
                failure_record=artifact_identity(
                    "control-failure", b"provider-unavailable-normalized"
                ),
            )
            results.append(
                build_control_result(
                    manifest,
                    execution_id=f"execution-{case.case_id}",
                    case_id=case.case_id,
                    repetition=1,
                    lane_order=QualificationLaneOrder.FIXED_FIRST,
                    artifact=artifact,
                    provider_failure_observed=True,
                    classification_emitted=False,
                    consequential_action_allowed=False,
                    model_mutation_attempted=False,
                )
            )
            continue
        bindings = _bindings(manifest, case)
        if unsafe and not benefit_recorded:
            bindings = replace(bindings, action_gates_match=False)
            benefit_recorded = True
        use_benefit = (
            adaptive_benefit
            and case.case_id == manifest.thresholds.fallback_heterogeneous_case_id
        )
        results.append(
            _measurement_result(
                manifest,
                case,
                adaptive_better=use_benefit,
                bindings=bindings,
            )
        )
        benefit_recorded = benefit_recorded or use_benefit
    return tuple(results)


def _five_repeat_results(
    manifest: QualificationSuiteManifest,
    *,
    fallback_successes: int,
):
    results = []
    fallback_id = manifest.thresholds.fallback_heterogeneous_case_id
    for repetition, lane_order in enumerate(manifest.lane_orders, start=1):
        for case in manifest.cases:
            if case.role is QualificationCaseRole.FAIL_CLOSED_CONTROL:
                artifact = QualificationLaneArtifacts(
                    strategy_kind=ComparisonStrategyKind.ADAPTIVE,
                    raw_observations=artifact_identity(
                        f"control-raw-{repetition}", b"provider-unavailable"
                    ),
                    normalized_run=None,
                    failure_record=artifact_identity(
                        f"control-failure-{repetition}",
                        b"provider-unavailable-normalized",
                    ),
                )
                results.append(
                    build_control_result(
                        manifest,
                        execution_id=f"execution-{case.case_id}-{repetition}",
                        case_id=case.case_id,
                        repetition=repetition,
                        lane_order=lane_order,
                        artifact=artifact,
                        provider_failure_observed=True,
                        classification_emitted=False,
                        consequential_action_allowed=False,
                        model_mutation_attempted=False,
                    )
                )
                continue
            results.append(
                _measurement_result(
                    manifest,
                    case,
                    adaptive_better=(
                        case.case_id == fallback_id and repetition <= fallback_successes
                    ),
                    repetition=repetition,
                    lane_order=lane_order,
                )
            )
    return tuple(results)


def test_measurement_result_derives_binding_and_exact_model_cost() -> None:
    manifest = _manifest()
    case = _measurement_case(manifest)
    result = _measurement_result(manifest, case, adaptive_better=True)
    assert result.validity is not None
    assert result.validity.eligible_for_value_evidence

    result_set = build_result_set(manifest, (result,))
    summary = summarize_qualification(manifest, result_set, evaluated_at=NOW)
    assert summary.adaptive_metrics.input_token_count == 100
    assert summary.adaptive_metrics.output_token_count == 20
    assert summary.adaptive_metrics.model_cost_nano_units == 18_000
    assert summary.adaptive_benefit_result_count == 1


@pytest.mark.parametrize(
    "binding_change",
    (
        {"source_revision": "2" * 64},
        {"provider_settings_sha256": "2" * 64},
        {"fixture_id": "wrong-fixture"},
        {"classification_policy_version": "wrong-policy"},
    ),
)
def test_integrity_mismatches_are_never_value_evidence(
    binding_change: dict[str, object],
) -> None:
    manifest = _manifest()
    case = _measurement_case(manifest)
    bindings = replace(_bindings(manifest, case), **binding_change)
    result = _measurement_result(manifest, case, bindings=bindings)

    assert result.validity is not None
    assert not result.validity.integrity_valid
    assert not result.validity.eligible_for_value_evidence
    assert result.source_revision == manifest.source_revision


def test_lane_order_must_match_preregistered_schedule() -> None:
    manifest = _manifest()
    case = _measurement_case(manifest)
    comparison = _comparison(manifest, case)
    with pytest.raises(QualificationAccountingError, match="lane order"):
        build_measurement_result(
            manifest,
            execution_id="wrong-order",
            case_id=case.case_id,
            repetition=1,
            lane_order=QualificationLaneOrder.ADAPTIVE_FIRST,
            comparison=comparison,
            artifacts=_artifacts(case, comparison),
            bindings=_bindings(manifest, case),
        )


@pytest.mark.parametrize(
    ("adaptive_benefit", "expected"),
    (
        (True, QualificationDispositionKind.ADAPTIVE_VALUE_DEMONSTRATED),
        (False, QualificationDispositionKind.NO_MEASURABLE_VALUE),
    ),
)
def test_complete_valid_suite_has_only_preregistered_value_dispositions(
    adaptive_benefit: bool,
    expected: QualificationDispositionKind,
) -> None:
    manifest = _manifest()
    result_set = build_result_set(
        manifest,
        _full_results(manifest, adaptive_benefit=adaptive_benefit),
    )
    summary = summarize_qualification(manifest, result_set, evaluated_at=NOW)
    disposition = derive_disposition(
        manifest,
        result_set,
        summary,
        decided_at=NOW,
    )

    assert summary.complete_result_set
    assert summary.valid_for_value_evidence
    assert disposition.disposition is expected


@pytest.mark.parametrize(
    ("fallback_successes", "expected"),
    (
        (4, QualificationDispositionKind.ADAPTIVE_VALUE_DEMONSTRATED),
        (3, QualificationDispositionKind.NO_MEASURABLE_VALUE),
    ),
)
def test_five_repeat_heterogeneous_fallback_requires_four_repeatable_wins(
    fallback_successes: int,
    expected: QualificationDispositionKind,
) -> None:
    manifest = build_qualification_manifest(
        source_revision=SOURCE_REVISION,
        registered_at=NOW,
        provider=_provider(),
    )
    result_set = build_result_set(
        manifest,
        _five_repeat_results(
            manifest,
            fallback_successes=fallback_successes,
        ),
    )
    summary = summarize_qualification(manifest, result_set, evaluated_at=NOW)
    disposition = derive_disposition(
        manifest,
        result_set,
        summary,
        decided_at=NOW,
    )

    assert summary.observed_result_count == 40
    assert summary.fallback_heterogeneous_success_count == fallback_successes
    assert summary.suite_median_probe_reduction == 0
    assert disposition.disposition is expected


def test_safety_failure_dominates_efficiency_and_returns_unsafe() -> None:
    manifest = _manifest()
    result_set = build_result_set(manifest, _full_results(manifest, unsafe=True))
    summary = summarize_qualification(manifest, result_set, evaluated_at=NOW)
    disposition = derive_disposition(manifest, result_set, summary, decided_at=NOW)

    assert summary.safety_failure_count == 1
    assert disposition.disposition is QualificationDispositionKind.UNSAFE


def test_failed_result_cannot_be_relabelled_as_success() -> None:
    manifest = _manifest()
    results = list(_full_results(manifest, adaptive_benefit=True))
    case = _measurement_case(manifest)
    results[0] = build_failed_result(
        manifest,
        execution_id="failed-execution",
        case_id=case.case_id,
        repetition=1,
        lane_order=QualificationLaneOrder.FIXED_FIRST,
        failure_category="provider-timeout",
    )
    result_set = build_result_set(manifest, tuple(results))
    summary = summarize_qualification(manifest, result_set, evaluated_at=NOW)
    disposition = derive_disposition(manifest, result_set, summary, decided_at=NOW)

    assert summary.failed_result_count == 1
    assert disposition.disposition is QualificationDispositionKind.INVALID_RUN


def test_incomplete_result_set_is_inconclusive_and_artifact_payload_is_absent() -> None:
    manifest = _manifest()
    result = _measurement_result(manifest, _measurement_case(manifest))
    result_set = build_result_set(manifest, (result,))
    summary = summarize_qualification(manifest, result_set, evaluated_at=NOW)
    disposition = derive_disposition(manifest, result_set, summary, decided_at=NOW)
    serialized = canonical_json_bytes(result)

    assert disposition.disposition is QualificationDispositionKind.INCONCLUSIVE
    assert b"externally-retained-observation" not in serialized
    assert b'"sha256"' in serialized
