"""Neutral comparison-record invariants and execution-data boundaries."""

from __future__ import annotations

import json

import pytest
from pydantic import ValidationError

from reconcile.contracts import (
    INVESTIGATION_COMPARISON_RECORD_VERSION,
    ComparisonModelUsage,
    ComparisonModelUsageStatus,
    ComparisonRun,
    ComparisonStrategyKind,
    ExplanationCompleteness,
    InvestigationComparisonRecord,
    PreregisteredExpectedClassification,
    canonical_json_bytes,
    decode_contract,
)
from tests.contract._factories import make_comparison_record

pytestmark = pytest.mark.contract


def _payload(*, include_adaptive: bool = False) -> dict[str, object]:
    return json.loads(
        canonical_json_bytes(make_comparison_record(include_adaptive=include_adaptive))
    )


def test_baseline_is_required_before_an_explicitly_nullable_adaptive_run() -> None:
    record = make_comparison_record()

    assert record.schema_version == INVESTIGATION_COMPARISON_RECORD_VERSION
    assert record.baseline.strategy_kind is ComparisonStrategyKind.FIXED
    assert record.adaptive is None
    assert record.baseline.model_usage == ComparisonModelUsage(
        status=ComparisonModelUsageStatus.NOT_APPLICABLE,
        model_call_count=0,
        input_token_count=0,
        output_token_count=0,
        total_token_count=0,
    )
    fields = tuple(InvestigationComparisonRecord.model_fields)
    assert fields.index("baseline") < fields.index("adaptive")
    assert InvestigationComparisonRecord.model_fields["baseline"].is_required()
    assert InvestigationComparisonRecord.model_fields["adaptive"].is_required()
    assert (
        decode_contract(canonical_json_bytes(record), InvestigationComparisonRecord)
        == record
    )


def test_measured_and_unavailable_adaptive_model_usage_are_distinct() -> None:
    measured = make_comparison_record(include_adaptive=True)
    assert measured.adaptive is not None
    assert measured.adaptive.strategy_kind is ComparisonStrategyKind.ADAPTIVE
    assert measured.adaptive.model_usage.status is ComparisonModelUsageStatus.MEASURED
    assert measured.adaptive.model_usage.total_token_count == 120

    payload = _payload(include_adaptive=True)
    usage = payload["adaptive"]["model_usage"]  # type: ignore[index]
    usage.update(  # type: ignore[union-attr]
        {
            "status": "UNAVAILABLE",
            "input_token_count": None,
            "output_token_count": None,
            "total_token_count": None,
        }
    )
    unavailable = InvestigationComparisonRecord.model_validate_json(json.dumps(payload))

    assert unavailable.adaptive is not None
    assert (
        unavailable.adaptive.model_usage.status
        is ComparisonModelUsageStatus.UNAVAILABLE
    )
    assert unavailable.adaptive.model_usage.input_token_count is None


@pytest.mark.parametrize(
    "values",
    (
        {
            "status": "NOT_APPLICABLE",
            "provider_name": "google",
            "model_name": "gemini-2.5-flash",
            "model_call_count": 0,
            "input_token_count": 0,
            "output_token_count": 0,
            "total_token_count": 0,
        },
        {
            "status": "NOT_APPLICABLE",
            "provider_name": None,
            "model_name": None,
            "model_call_count": 0,
            "input_token_count": None,
            "output_token_count": None,
            "total_token_count": None,
        },
        {
            "status": "MEASURED",
            "provider_name": "google",
            "model_name": "gemini-2.5-flash",
            "model_call_count": 1,
            "input_token_count": 100,
            "output_token_count": 20,
            "total_token_count": 119,
        },
        {
            "status": "MEASURED",
            "provider_name": "google",
            "model_name": None,
            "model_call_count": 1,
            "input_token_count": 100,
            "output_token_count": 20,
            "total_token_count": 120,
        },
        {
            "status": "UNAVAILABLE",
            "provider_name": "google",
            "model_name": "gemini-2.5-flash",
            "model_call_count": 1,
            "input_token_count": 0,
            "output_token_count": 0,
            "total_token_count": 0,
        },
        {
            "status": "UNAVAILABLE",
            "provider_name": "google",
            "model_name": "gemini-2.5-flash",
            "model_call_count": 0,
            "input_token_count": None,
            "output_token_count": None,
            "total_token_count": None,
        },
    ),
)
def test_model_usage_statuses_reject_fabricated_or_incomplete_counts(
    values: dict[str, object],
) -> None:
    with pytest.raises(ValidationError):
        ComparisonModelUsage.model_validate_json(json.dumps(values))


def test_strategy_kind_determines_whether_model_usage_is_applicable() -> None:
    payload = _payload()
    payload["baseline"]["strategy_kind"] = "ADAPTIVE"  # type: ignore[index]

    with pytest.raises(ValidationError, match="strategy kind"):
        InvestigationComparisonRecord.model_validate_json(json.dumps(payload))

    payload = _payload(include_adaptive=True)
    usage = payload["adaptive"]["model_usage"]  # type: ignore[index]
    usage.update(  # type: ignore[union-attr]
        {
            "status": "NOT_APPLICABLE",
            "provider_name": None,
            "model_name": None,
            "model_call_count": 0,
            "input_token_count": 0,
            "output_token_count": 0,
            "total_token_count": 0,
        }
    )

    with pytest.raises(ValidationError, match="strategy kind"):
        InvestigationComparisonRecord.model_validate_json(json.dumps(payload))


@pytest.mark.parametrize(
    ("run_name", "field", "value"),
    (
        ("baseline", "scenario", {"name": "other", "version": "1.0.0"}),
        ("baseline", "envelope_sha256", "0" * 64),
        ("baseline", "matches_preregistered_expectation", False),
        ("adaptive", "scenario", {"name": "other", "version": "1.0.0"}),
        ("adaptive", "envelope_sha256", "0" * 64),
        ("adaptive", "matches_preregistered_expectation", False),
    ),
)
def test_runs_must_share_scenario_envelope_and_preregistered_expectation(
    run_name: str,
    field: str,
    value: object,
) -> None:
    payload = _payload(include_adaptive=True)
    payload[run_name][field] = value  # type: ignore[index]

    with pytest.raises(ValidationError):
        InvestigationComparisonRecord.model_validate_json(json.dumps(payload))


def test_preregistered_expectation_is_structurally_outside_run_data() -> None:
    assert set(PreregisteredExpectedClassification.model_fields) == {
        "registration_id",
        "metadata_sha256",
        "expected_classification",
    }
    assert "expected_classification" not in ComparisonRun.model_fields
    assert "preregistered_expectation" not in ComparisonRun.model_fields

    payload = _payload()
    payload["baseline"]["expected_classification"] = "COMMITTED"  # type: ignore[index]
    with pytest.raises(ValidationError):
        InvestigationComparisonRecord.model_validate_json(json.dumps(payload))


@pytest.mark.parametrize(
    "field",
    (
        "planned_probe_count",
        "executed_probe_count",
        "controller_cost_units_used",
        "controller_result_bytes_acquired",
        "total_elapsed_ms",
        "unsupported_probe_count",
        "unnecessary_probe_count",
        "duplicate_probe_count",
    ),
)
def test_run_counters_are_nonnegative(field: str) -> None:
    payload = _payload()
    payload["baseline"][field] = -1  # type: ignore[index]

    with pytest.raises(ValidationError):
        InvestigationComparisonRecord.model_validate_json(json.dumps(payload))


def test_probe_and_elapsed_metrics_are_internally_bounded() -> None:
    payload = _payload()
    payload["baseline"]["executed_probe_count"] = 2  # type: ignore[index]
    with pytest.raises(ValidationError, match="executed probes"):
        InvestigationComparisonRecord.model_validate_json(json.dumps(payload))

    payload = _payload()
    payload["baseline"]["time_to_sufficient_evidence_ms"] = 21  # type: ignore[index]
    with pytest.raises(ValidationError, match="total elapsed"):
        InvestigationComparisonRecord.model_validate_json(json.dumps(payload))

    payload = _payload()
    payload["baseline"]["unsupported_probe_count"] = 2  # type: ignore[index]
    with pytest.raises(ValidationError, match="executed probes"):
        InvestigationComparisonRecord.model_validate_json(json.dumps(payload))

    payload = _payload()
    payload["baseline"]["unnecessary_probe_count"] = 2  # type: ignore[index]
    with pytest.raises(ValidationError, match="executed probes"):
        InvestigationComparisonRecord.model_validate_json(json.dumps(payload))

    payload = _payload()
    baseline = payload["baseline"]  # type: ignore[assignment]
    baseline.update(  # type: ignore[union-attr]
        {
            "planned_probe_count": 0,
            "executed_probe_count": 0,
            "controller_cost_units_used": 0,
            "controller_result_bytes_acquired": 0,
            "time_to_sufficient_evidence_ms": None,
            "duplicate_probe_count": 1,
        }
    )
    with pytest.raises(ValidationError, match="executed probes"):
        InvestigationComparisonRecord.model_validate_json(json.dumps(payload))


@pytest.mark.parametrize(
    ("required", "valid", "missing", "complete"),
    ((2, 1, 0, False), (2, 1, 1, True)),
)
def test_explanation_completeness_is_an_objective_partition(
    required: int,
    valid: int,
    missing: int,
    complete: bool,
) -> None:
    with pytest.raises(ValidationError):
        ExplanationCompleteness(
            required_evidence_citation_count=required,
            valid_evidence_citation_count=valid,
            missing_evidence_citation_count=missing,
            complete=complete,
        )


@pytest.mark.parametrize(
    ("location", "field", "value"),
    (
        ("record", "winner", "baseline"),
        ("record", "improvement", True),
        ("record", "superiority", "adaptive"),
        ("baseline", "dollar_cost", 0.01),
        ("model_usage", "cost_usd", 0.01),
    ),
)
def test_claim_and_monetary_fields_are_not_part_of_the_contract(
    location: str,
    field: str,
    value: object,
) -> None:
    payload = _payload()
    if location == "record":
        payload[field] = value
    elif location == "baseline":
        payload["baseline"][field] = value  # type: ignore[index]
    else:
        payload["baseline"]["model_usage"][field] = value  # type: ignore[index]

    with pytest.raises(ValidationError):
        InvestigationComparisonRecord.model_validate_json(json.dumps(payload))

    schema_text = json.dumps(
        InvestigationComparisonRecord.model_json_schema(),
        sort_keys=True,
    ).lower()
    for forbidden in ("winner", "improvement", "superiority", "dollar", "usd"):
        assert forbidden not in schema_text


def test_stop_reason_is_required_and_nonempty() -> None:
    payload = _payload()
    payload["baseline"].pop("stop_reason")  # type: ignore[union-attr]
    with pytest.raises(ValidationError):
        InvestigationComparisonRecord.model_validate_json(json.dumps(payload))

    payload = _payload()
    payload["baseline"]["stop_reason"] = ""  # type: ignore[index]
    with pytest.raises(ValidationError):
        InvestigationComparisonRecord.model_validate_json(json.dumps(payload))
