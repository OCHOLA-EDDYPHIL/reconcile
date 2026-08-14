"""Strict advisory-planning payload boundaries."""

from __future__ import annotations

import json
from datetime import timedelta

import pytest
from pydantic import ValidationError

from reconcile.contracts import (
    ADAPTIVE_PLANNER_INPUT_VERSION,
    ADAPTIVE_PLANNER_OUTPUT_VERSION,
    AdaptivePlannerInput,
    AdaptivePlannerOutput,
    ContractError,
    PlannerCitationRefs,
    canonical_json_bytes,
    decode_contract,
)
from tests.contract._factories import NOW, make_planner_input, make_planner_output

pytestmark = pytest.mark.contract


def _payload(value: object) -> dict[str, object]:
    return json.loads(canonical_json_bytes(value))


def _property_names(schema: object) -> set[str]:
    if isinstance(schema, dict):
        result = set(schema.get("properties", {}))
        for value in schema.values():
            result.update(_property_names(value))
        return result
    if isinstance(schema, list):
        result: set[str] = set()
        for value in schema:
            result.update(_property_names(value))
        return result
    return set()


def test_planner_input_is_versioned_strict_bounded_public_state() -> None:
    planner_input = make_planner_input()

    assert planner_input.schema_version == ADAPTIVE_PLANNER_INPUT_VERSION
    assert planner_input.capabilities[0].read_only is True
    assert set(AdaptivePlannerInput.model_fields) == {
        "schema_version",
        "phase",
        "envelope",
        "capabilities",
        "admitted_evidence",
        "weak_evidence",
        "rejected_evidence",
        "missing_evidence",
        "prior_executable_request_hashes",
        "remaining_budget",
        "versions",
    }
    assert (
        decode_contract(canonical_json_bytes(planner_input), AdaptivePlannerInput)
        == planner_input
    )


def test_planner_output_is_versioned_strict_advice_only() -> None:
    planner_output = make_planner_output()

    assert planner_output.schema_version == ADAPTIVE_PLANNER_OUTPUT_VERSION
    assert set(AdaptivePlannerOutput.model_fields) == {
        "schema_version",
        "probe_proposals",
        "acquisition_advice",
        "stop_advice",
        "missing_evidence_notes",
        "explanation",
    }
    assert (
        decode_contract(canonical_json_bytes(planner_output), AdaptivePlannerOutput)
        == planner_output
    )


@pytest.mark.parametrize(
    "field",
    (
        "hidden_truth",
        "handler",
        "raw_observation",
        "credentials",
        "secret",
        "preregistered_expectation",
        "classification",
        "action_gate",
        "cleanup_owner",
        "cleanup",
        "cleanup_outcome",
        "private_state",
        "private_path",
        "expected_outcome",
    ),
)
def test_planner_input_rejects_forbidden_state(field: str) -> None:
    payload = _payload(make_planner_input())
    payload[field] = "forbidden"

    with pytest.raises(ValidationError):
        AdaptivePlannerInput.model_validate_json(json.dumps(payload))


@pytest.mark.parametrize(
    "field",
    (
        "classification",
        "authoritative_classification",
        "retry",
        "compensation",
        "action_gate",
        "authorization",
        "cleanup",
        "cleanup_outcome",
        "expected_outcome",
        "credentials",
        "secret",
        "raw_response",
        "private_reasoning",
        "chain_of_thought",
    ),
)
def test_planner_output_rejects_authority_secrets_and_private_reasoning(
    field: str,
) -> None:
    payload = _payload(make_planner_output())
    payload[field] = "forbidden"

    with pytest.raises(ValidationError):
        AdaptivePlannerOutput.model_validate_json(json.dumps(payload))


def test_public_schemas_have_no_forbidden_authority_or_private_properties() -> None:
    input_properties = _property_names(AdaptivePlannerInput.model_json_schema())
    output_properties = _property_names(AdaptivePlannerOutput.model_json_schema())

    assert {
        "hidden_truth",
        "handler",
        "raw_observation",
        "credentials",
        "preregistered_expectation",
        "action_gate",
        "cleanup_owner",
        "cleanup",
        "cleanup_outcome",
        "private_state",
        "private_path",
        "expected_outcome",
    }.isdisjoint(input_properties)
    assert {
        "classification",
        "authoritative_classification",
        "retry",
        "compensation",
        "action_gate",
        "authorization",
        "cleanup",
        "cleanup_outcome",
        "expected_outcome",
        "credentials",
        "raw_response",
        "private_reasoning",
        "chain_of_thought",
    }.isdisjoint(output_properties)


@pytest.mark.parametrize(
    ("model", "value", "version"),
    (
        (
            AdaptivePlannerInput,
            make_planner_input,
            "reconcile/adaptive-planner-input/v2",
        ),
        (
            AdaptivePlannerOutput,
            make_planner_output,
            "reconcile/adaptive-planner-output/v2",
        ),
    ),
)
def test_planner_contracts_reject_unsupported_versions(
    model: type[AdaptivePlannerInput] | type[AdaptivePlannerOutput],
    value: object,
    version: str,
) -> None:
    payload = _payload(value())  # type: ignore[operator]
    payload["schema_version"] = version

    with pytest.raises(ContractError) as captured:
        decode_contract(json.dumps(payload), model)

    assert captured.value.code == "unsupported_contract_version"


def test_capability_catalog_must_exactly_match_enabled_read_only_capabilities() -> None:
    payload = _payload(make_planner_input())
    payload["capabilities"][0]["read_only"] = False  # type: ignore[index]
    with pytest.raises(ValidationError):
        AdaptivePlannerInput.model_validate_json(json.dumps(payload))

    payload = _payload(make_planner_input())
    payload["capabilities"][0]["name"] = "not-enabled"  # type: ignore[index]
    with pytest.raises(ValidationError, match="enabled catalog"):
        AdaptivePlannerInput.model_validate_json(json.dumps(payload))

    payload = _payload(make_planner_input())
    payload["capabilities"].append(payload["capabilities"][0])  # type: ignore[union-attr,index]
    with pytest.raises(ValidationError, match="identities"):
        AdaptivePlannerInput.model_validate_json(json.dumps(payload))


@pytest.mark.parametrize(
    ("property_name", "property_schema"),
    (
        ("api_key", {"type": "string"}),
        ("private_path", {"type": "string"}),
        ("lookup", {"$ref": "#/$defs/lookup"}),
    ),
)
def test_capability_catalog_rejects_sensitive_coordinates_and_indirection(
    property_name: str,
    property_schema: dict[str, object],
) -> None:
    payload = _payload(make_planner_input())
    schema = payload["capabilities"][0]["argument_schema"]  # type: ignore[index]
    schema["properties"] = {property_name: property_schema}  # type: ignore[index]

    with pytest.raises(ValidationError):
        AdaptivePlannerInput.model_validate_json(json.dumps(payload))


@pytest.mark.parametrize(
    ("collection", "reason"),
    (
        ("admitted_evidence", "non_authoritative_log_only"),
        ("weak_evidence", "authoritative_exact_correlation"),
        ("rejected_evidence", "not_found_absence_only"),
    ),
)
def test_evidence_summary_reason_categories_are_fixed(
    collection: str,
    reason: str,
) -> None:
    payload = _payload(make_planner_input())
    payload[collection][0]["reason"] = reason  # type: ignore[index]

    with pytest.raises(ValidationError):
        AdaptivePlannerInput.model_validate_json(json.dumps(payload))


def test_evidence_summaries_require_unique_known_ids_effects_and_capabilities() -> None:
    payload = _payload(make_planner_input())
    payload["weak_evidence"][0]["evidence_id"] = payload["admitted_evidence"][0][  # type: ignore[index]
        "evidence_id"
    ]
    with pytest.raises(ValidationError, match="evidence identifiers"):
        AdaptivePlannerInput.model_validate_json(json.dumps(payload))

    payload = _payload(make_planner_input())
    payload["missing_evidence"][0]["effect_id"] = "unexpected-effect"  # type: ignore[index]
    with pytest.raises(ValidationError, match="unexpected effect"):
        AdaptivePlannerInput.model_validate_json(json.dumps(payload))

    payload = _payload(make_planner_input())
    payload["weak_evidence"][0]["capability_name"] = "not-enabled"  # type: ignore[index]
    with pytest.raises(ValidationError, match="unknown capability"):
        AdaptivePlannerInput.model_validate_json(json.dumps(payload))


@pytest.mark.parametrize(
    ("field", "value"),
    (
        ("probes", 4),
        ("elapsed_ms", 5_001),
        ("result_bytes", 65_537),
        ("cost_units", 4),
    ),
)
def test_remaining_budget_cannot_exceed_the_sealed_envelope(
    field: str,
    value: int,
) -> None:
    payload = _payload(make_planner_input())
    payload["remaining_budget"][field] = value  # type: ignore[index]

    with pytest.raises(ValidationError, match="exceeds"):
        AdaptivePlannerInput.model_validate_json(json.dumps(payload))


def test_deadline_and_policy_versions_are_bound_to_the_envelope() -> None:
    payload = _payload(make_planner_input())
    payload["remaining_budget"]["deadline_at"] = (  # type: ignore[index]
        NOW - timedelta(seconds=1)
    ).isoformat()
    with pytest.raises(ValidationError, match="deadline"):
        AdaptivePlannerInput.model_validate_json(json.dumps(payload))

    payload = _payload(make_planner_input())
    payload["versions"]["authority_policy_version"] = "other-policy"  # type: ignore[index]
    with pytest.raises(ValidationError, match="policy versions"):
        AdaptivePlannerInput.model_validate_json(json.dumps(payload))


@pytest.mark.parametrize(
    ("collection", "count"),
    (
        ("capabilities", 65),
        ("admitted_evidence", 65),
        ("weak_evidence", 65),
        ("rejected_evidence", 65),
        ("missing_evidence", 65),
        ("prior_executable_request_hashes", 65),
    ),
)
def test_planner_input_collections_are_bounded(collection: str, count: int) -> None:
    payload = _payload(make_planner_input())
    exemplar = payload[collection][0]  # type: ignore[index]
    payload[collection] = [exemplar for _ in range(count)]

    with pytest.raises(ValidationError):
        AdaptivePlannerInput.model_validate_json(json.dumps(payload))


def test_planner_output_proposals_and_notes_are_bounded_and_fully_typed() -> None:
    payload = _payload(make_planner_output())
    payload["probe_proposals"] = [payload["probe_proposals"][0] for _ in range(9)]  # type: ignore[index]
    with pytest.raises(ValidationError):
        AdaptivePlannerOutput.model_validate_json(json.dumps(payload))

    payload = _payload(make_planner_output())
    payload["missing_evidence_notes"] = [
        payload["missing_evidence_notes"][0]
        for _ in range(65)  # type: ignore[index]
    ]
    with pytest.raises(ValidationError):
        AdaptivePlannerOutput.model_validate_json(json.dumps(payload))

    payload = _payload(make_planner_output())
    payload["probe_proposals"][0]["classification"] = "COMMITTED"  # type: ignore[index]
    with pytest.raises(ValidationError):
        AdaptivePlannerOutput.model_validate_json(json.dumps(payload))


def test_citation_namespaces_are_separate_unique_and_nonempty() -> None:
    citations = make_planner_output().explanation.citations

    assert set(PlannerCitationRefs.model_fields) == {
        "admitted_evidence_ids",
        "weak_evidence_ids",
        "rejected_evidence_ids",
        "missing_effect_ids",
    }
    assert citations.admitted_evidence_ids == ("evidence-admitted-7",)
    assert citations.missing_effect_ids == ("audit-record",)

    payload = _payload(citations)
    payload["weak_evidence_ids"] = ["evidence-admitted-7"]
    with pytest.raises(ValidationError, match="cross-category"):
        PlannerCitationRefs.model_validate_json(json.dumps(payload))

    payload = _payload(citations)
    payload["admitted_evidence_ids"] = []
    payload["weak_evidence_ids"] = []
    payload["rejected_evidence_ids"] = []
    payload["missing_effect_ids"] = []
    with pytest.raises(ValidationError, match="at least one citation"):
        PlannerCitationRefs.model_validate_json(json.dumps(payload))


@pytest.mark.parametrize(
    ("citation_field", "section_field"),
    (
        ("admitted_evidence_ids", "admitted_evidence"),
        ("weak_evidence_ids", "weak_evidence"),
        ("rejected_evidence_ids", "rejected_evidence"),
        ("missing_effect_ids", "missing_evidence"),
    ),
)
def test_each_cited_category_requires_a_separate_explanation_section(
    citation_field: str,
    section_field: str,
) -> None:
    payload = _payload(make_planner_output())
    assert payload["explanation"]["citations"][citation_field]  # type: ignore[index]
    payload["explanation"][section_field] = None  # type: ignore[index]

    with pytest.raises(ValidationError, match="each cited category"):
        AdaptivePlannerOutput.model_validate_json(json.dumps(payload))


@pytest.mark.parametrize(
    ("citation_field", "section_field"),
    (
        ("admitted_evidence_ids", "admitted_evidence"),
        ("weak_evidence_ids", "weak_evidence"),
        ("rejected_evidence_ids", "rejected_evidence"),
        ("missing_effect_ids", "missing_evidence"),
    ),
)
def test_each_explanation_section_requires_matching_category_citations(
    citation_field: str,
    section_field: str,
) -> None:
    payload = _payload(make_planner_output())
    assert payload["explanation"][section_field] is not None  # type: ignore[index]
    payload["explanation"]["citations"][citation_field] = []  # type: ignore[index]

    with pytest.raises(ValidationError, match="section requires citations"):
        AdaptivePlannerOutput.model_validate_json(json.dumps(payload))


def test_duplicate_missing_note_effects_and_oversized_advice_fail() -> None:
    payload = _payload(make_planner_output())
    payload["missing_evidence_notes"][0]["effect_ids"] = [  # type: ignore[index]
        "audit-record",
        "audit-record",
    ]
    with pytest.raises(ValidationError, match="effect identifiers"):
        AdaptivePlannerOutput.model_validate_json(json.dumps(payload))

    payload = _payload(make_planner_output())
    payload["acquisition_advice"]["summary"] = "x" * 513  # type: ignore[index]
    with pytest.raises(ValidationError):
        AdaptivePlannerOutput.model_validate_json(json.dumps(payload))
