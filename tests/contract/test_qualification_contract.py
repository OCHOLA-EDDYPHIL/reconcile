"""Qualification preregistration and evidence-boundary contracts."""

from __future__ import annotations

import json
from datetime import UTC, datetime

import pytest
from pydantic import ValidationError

from reconcile.contracts import canonical_json_bytes, canonical_sha256, decode_contract
from reconcile.contracts.qualification import (
    QUALIFICATION_SUITE_MANIFEST_VERSION,
    QualificationArtifactIdentity,
    QualificationControlOutcome,
    QualificationDisposition,
    QualificationDispositionKind,
    QualificationDispositionReason,
    QualificationEvidenceProfile,
    QualificationLaneArtifacts,
    QualificationLaneOrder,
    QualificationMetric,
    QualificationOpportunity,
    QualificationProviderSettings,
    QualificationSuiteManifest,
    QualificationValidity,
)
from reconcile.qualification import build_qualification_manifest

pytestmark = pytest.mark.contract

SOURCE_REVISION = "1" * 64
NOW = datetime(2026, 8, 14, 12, 0, tzinfo=UTC)


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
    )


def test_manifest_freezes_complete_eight_case_preregistration() -> None:
    manifest = _manifest()

    assert manifest.schema_version == QUALIFICATION_SUITE_MANIFEST_VERSION
    assert len(manifest.cases) == 8
    assert manifest.metrics == tuple(QualificationMetric)
    assert manifest.lane_orders == (
        QualificationLaneOrder.FIXED_FIRST,
        QualificationLaneOrder.ADAPTIVE_FIRST,
        QualificationLaneOrder.FIXED_FIRST,
        QualificationLaneOrder.ADAPTIVE_FIRST,
        QualificationLaneOrder.FIXED_FIRST,
    )
    assert manifest.repetition_count == 5
    assert manifest.thresholds.minimum_suite_median_probe_reduction == 1
    assert (
        manifest.thresholds.minimum_suite_median_time_reduction_basis_points == 2_000
    )
    assert manifest.thresholds.minimum_suite_median_sufficient_time_reduction_ms == 250
    assert manifest.thresholds.minimum_fallback_case_successful_repetitions == 4
    assert not manifest.thresholds.explanation_completeness_can_demonstrate_value
    assert manifest.stop_conditions.maximum_total_model_calls == 180
    assert manifest.stop_conditions.maximum_total_model_cost_nano_units == 5_000_000_000
    assert {case.evidence_profile for case in manifest.cases} == set(
        QualificationEvidenceProfile
    )
    assert {case.opportunity for case in manifest.cases} == set(
        QualificationOpportunity
    )
    assert {case.scenario.name for case in manifest.cases} == {
        "storage-object",
        "firestore-business-operation",
        "sandbox-order-unknown",
    }
    controls = tuple(case for case in manifest.cases if case.expectation is None)
    assert len(controls) == 1
    assert controls[0].evidence_profile is QualificationEvidenceProfile.PROVIDER_FAILURE
    assert decode_contract(canonical_json_bytes(manifest), QualificationSuiteManifest) == manifest
    assert canonical_sha256(manifest) == canonical_sha256(_manifest())

    with pytest.raises(ValidationError):
        manifest.suite_id = "changed"  # type: ignore[misc]


@pytest.mark.parametrize(
    ("field", "value"),
    (
        ("metrics", [metric.value for metric in tuple(QualificationMetric)[:-1]]),
        ("lane_orders", ["FIXED_FIRST", "FIXED_FIRST"]),
        ("cases", None),
    ),
)
def test_manifest_rejects_post_hoc_suite_changes(field: str, value: object) -> None:
    payload = json.loads(canonical_json_bytes(_manifest()))
    if field == "cases":
        payload[field] = payload[field][:-1]
    else:
        payload[field] = value

    with pytest.raises(ValidationError):
        QualificationSuiteManifest.model_validate_json(json.dumps(payload))


def test_provider_settings_are_deterministic_and_secret_free() -> None:
    payload = json.loads(canonical_json_bytes(_provider()))
    payload["temperature_milli"] = 1
    with pytest.raises(ValidationError, match="temperature"):
        QualificationProviderSettings.model_validate_json(json.dumps(payload))

    assert set(QualificationProviderSettings.model_fields).isdisjoint(
        {"project_id", "credentials", "api_key", "access_token"}
    )


def test_validity_flags_cannot_relabel_invalid_evidence() -> None:
    fields = {
        name: True
        for name in QualificationValidity.model_fields
        if name not in {"integrity_valid", "safety_valid", "eligible_for_value_evidence"}
    }
    fields["source_binding_valid"] = False
    fields.update(
        integrity_valid=True,
        safety_valid=True,
        eligible_for_value_evidence=True,
    )

    with pytest.raises(ValidationError, match="must be derived"):
        QualificationValidity(**fields)


def test_control_pass_is_derived_and_artifacts_are_identity_only() -> None:
    with pytest.raises(ValidationError, match="must be derived"):
        QualificationControlOutcome(
            provider_failure_observed=True,
            classification_emitted=True,
            consequential_action_allowed=False,
            model_mutation_attempted=False,
            failure_artifact_retained=True,
            passed=True,
        )

    assert set(QualificationArtifactIdentity.model_fields) == {
        "artifact_id",
        "sha256",
        "byte_count",
    }
    assert set(QualificationLaneArtifacts.model_fields) == {
        "strategy_kind",
        "raw_observations",
        "normalized_run",
        "failure_record",
    }


def test_disposition_reason_cannot_contradict_disposition() -> None:
    with pytest.raises(ValidationError, match="do not match"):
        QualificationDisposition(
            schema_version="reconcile/qualification-disposition/v1",
            suite_id="suite",
            manifest_sha256="1" * 64,
            result_set_sha256="2" * 64,
            summary_sha256="3" * 64,
            source_revision="4" * 64,
            decided_at=NOW,
            disposition=QualificationDispositionKind.ADAPTIVE_VALUE_DEMONSTRATED,
            reasons=(QualificationDispositionReason.INTEGRITY_INVALID,),
        )
