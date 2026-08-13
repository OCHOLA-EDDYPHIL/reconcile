"""Frozen API error and ordered investigation-event contracts."""

from __future__ import annotations

import json

import pytest
from jsonschema import Draft202012Validator
from pydantic import BaseModel, ValidationError

from reconcile.contracts import (
    ERROR_VERSION,
    MAX_INVESTIGATION_EVENTS,
    ApiError,
    ApiErrorCode,
    Classification,
    ContractError,
    ExecutionEnvelope,
    InvestigationEvent,
    InvestigationEventType,
    InvestigationStatus,
    RequestedAction,
    canonical_json_bytes,
    decode_contract,
)
from scripts.generate_contract_schemas import PUBLIC_SCHEMAS, generated_artifacts
from tests.contract._factories import (
    make_api_error,
    make_envelope,
    make_investigation_event,
)

pytestmark = pytest.mark.contract


def _payload(model: BaseModel) -> dict[str, object]:
    return json.loads(canonical_json_bytes(model))


@pytest.mark.parametrize(
    ("contract", "model_type"),
    (
        (make_api_error(), ApiError),
        (make_investigation_event(), InvestigationEvent),
        (make_envelope(), ExecutionEnvelope),
    ),
)
def test_frozen_api_contracts_have_canonical_round_trips(
    contract: BaseModel,
    model_type: type[BaseModel],
) -> None:
    encoded = canonical_json_bytes(contract)

    parsed = decode_contract(encoded, model_type)

    assert parsed == contract
    assert canonical_json_bytes(parsed) == encoded


def test_public_schema_set_contains_only_the_frozen_http_models() -> None:
    assert "error" in PUBLIC_SCHEMAS
    assert "investigation-event" in PUBLIC_SCHEMAS
    assert "investigation-create-request" not in PUBLIC_SCHEMAS
    assert "investigation-view" not in PUBLIC_SCHEMAS
    assert "api-error" not in PUBLIC_SCHEMAS


@pytest.mark.parametrize("event_type", tuple(InvestigationEventType))
def test_every_event_type_has_a_canonical_round_trip(
    event_type: InvestigationEventType,
) -> None:
    event = make_investigation_event(event_type)
    encoded = canonical_json_bytes(event)

    assert decode_contract(encoded, InvestigationEvent) == event
    assert canonical_json_bytes(decode_contract(encoded, InvestigationEvent)) == encoded


@pytest.mark.parametrize(
    ("contract", "model_type"),
    (
        (make_api_error(), ApiError),
        (make_investigation_event(), InvestigationEvent),
    ),
)
def test_unsupported_versions_are_distinct_from_invalid_contracts(
    contract: BaseModel,
    model_type: type[BaseModel],
) -> None:
    payload = _payload(contract)
    payload["schema_version"] = "reconcile/unsupported/v2"

    with pytest.raises(ContractError) as captured:
        decode_contract(json.dumps(payload), model_type)

    assert captured.value.code == "unsupported_contract_version"


def test_event_wire_has_exactly_the_frozen_top_level_fields() -> None:
    payload = _payload(make_investigation_event())

    assert set(payload) == {
        "schema_version",
        "investigation_id",
        "sequence",
        "type",
        "occurred_at",
        "payload",
    }
    assert "kind" not in payload
    assert "cursor" not in payload
    assert "report_revision" not in payload


@pytest.mark.parametrize(
    ("event_type", "payload_type"),
    tuple(
        (event_type, payload_type)
        for event_type in InvestigationEventType
        for payload_type in InvestigationEventType
        if event_type is not payload_type
    ),
)
def test_event_type_must_exactly_match_its_payload(
    event_type: InvestigationEventType,
    payload_type: InvestigationEventType,
) -> None:
    payload = _payload(make_investigation_event(payload_type))
    payload["type"] = event_type.value

    with pytest.raises(ValidationError, match="type does not match"):
        InvestigationEvent.model_validate_json(json.dumps(payload))


@pytest.mark.parametrize(
    ("event_type", "payload_type"),
    tuple(
        (event_type, payload_type)
        for event_type in InvestigationEventType
        for payload_type in InvestigationEventType
        if event_type is not payload_type
    ),
)
def test_public_schema_rejects_every_event_type_payload_mismatch(
    event_type: InvestigationEventType,
    payload_type: InvestigationEventType,
) -> None:
    artifacts = generated_artifacts()
    event_path = next(
        path for path in artifacts if path.name == "investigation-event.schema.json"
    )
    validator = Draft202012Validator(json.loads(artifacts[event_path]))
    payload = _payload(make_investigation_event(payload_type))
    payload["type"] = event_type.value

    assert list(validator.iter_errors(payload))


@pytest.mark.parametrize("sequence", (0, MAX_INVESTIGATION_EVENTS + 1))
def test_event_sequence_is_positive_and_bounded(sequence: int) -> None:
    payload = _payload(make_investigation_event())
    payload["sequence"] = sequence

    with pytest.raises(ValidationError):
        InvestigationEvent.model_validate_json(json.dumps(payload))


def test_event_capacity_covers_the_bounded_report_projection() -> None:
    assert MAX_INVESTIGATION_EVENTS == 3 + 64 + 64 + 1 + len(RequestedAction)


def test_lifecycle_has_exactly_the_public_report_states() -> None:
    assert tuple(InvestigationStatus) == (
        InvestigationStatus.CREATED,
        InvestigationStatus.INVESTIGATING,
        InvestigationStatus.COMPLETED,
    )


@pytest.mark.parametrize(
    "field",
    ("classification", "evidence", "action_gate", "retry_allowed", "kind"),
)
def test_event_rejects_top_level_controller_authority_and_draft_fields(
    field: str,
) -> None:
    payload = _payload(make_investigation_event())
    payload[field] = "fabricated"

    with pytest.raises(ValidationError):
        InvestigationEvent.model_validate_json(json.dumps(payload))


def test_classification_payload_cannot_fabricate_action_authority() -> None:
    payload = _payload(make_investigation_event(InvestigationEventType.CLASSIFICATION))
    event_payload = payload["payload"]
    assert isinstance(event_payload, dict)
    event_payload["allowed"] = True

    with pytest.raises(ValidationError):
        InvestigationEvent.model_validate_json(json.dumps(payload))


def test_embedded_action_gate_invariants_remain_authoritative() -> None:
    payload = _payload(make_investigation_event(InvestigationEventType.ACTION_GATE))
    event_payload = payload["payload"]
    assert isinstance(event_payload, dict)
    action_gate = event_payload["action_gate"]
    assert isinstance(action_gate, dict)
    action_gate.update(
        {
            "requested_action": "RETRY",
            "allowed": True,
            "reason": "duplicate_effect_risk",
        }
    )

    with pytest.raises(ValidationError, match="not executable"):
        InvestigationEvent.model_validate_json(json.dumps(payload))


def test_embedded_evidence_decision_invariants_remain_authoritative() -> None:
    payload = _payload(
        make_investigation_event(InvestigationEventType.EVIDENCE_DECISION)
    )
    event_payload = payload["payload"]
    assert isinstance(event_payload, dict)
    decision = event_payload["decision"]
    assert isinstance(decision, dict)
    decision["reason"] = "probe_timeout"

    with pytest.raises(ValidationError, match="incompatible with disposition"):
        InvestigationEvent.model_validate_json(json.dumps(payload))


def test_error_contract_has_the_frozen_version_fields_and_codes() -> None:
    assert ERROR_VERSION == "reconcile/error/v1"
    assert tuple(code.value for code in ApiErrorCode) == (
        "invalid_contract",
        "unsupported_contract_version",
        "investigation_not_found",
        "duplicate_investigation_id",
        "dependency_unavailable",
        "internal_failure",
    )
    assert set(_payload(make_api_error())) == {
        "schema_version",
        "code",
        "message",
        "details",
    }


@pytest.mark.parametrize("code", tuple(ApiErrorCode))
def test_every_error_code_has_a_canonical_round_trip(code: ApiErrorCode) -> None:
    error = make_api_error(code)

    assert decode_contract(canonical_json_bytes(error), ApiError) == error


@pytest.mark.parametrize(
    "field",
    ("investigation_id", "traceback", "exception", "stack"),
)
def test_error_rejects_superseded_or_internal_top_level_fields(field: str) -> None:
    payload = _payload(make_api_error(ApiErrorCode.INTERNAL_FAILURE))
    payload[field] = "private runtime material"

    with pytest.raises(ValidationError):
        ApiError.model_validate_json(json.dumps(payload))


@pytest.mark.parametrize("sensitive_key", ("access_token", "password", "api_key"))
def test_error_details_reject_credential_shaped_fields(sensitive_key: str) -> None:
    payload = _payload(make_api_error())
    payload["details"] = {sensitive_key: "private"}

    with pytest.raises(ValidationError, match="secret-bearing"):
        ApiError.model_validate_json(json.dumps(payload))


@pytest.mark.parametrize(
    "details",
    (
        {"traceback": "private"},
        {"nested": {"stackTrace": "private"}},
        {"exception": "private"},
    ),
)
def test_error_details_reject_internal_failure_material(
    details: dict[str, object],
) -> None:
    payload = _payload(make_api_error())
    payload["details"] = details

    with pytest.raises(ValidationError, match="internal failure material"):
        ApiError.model_validate_json(json.dumps(payload))


@pytest.mark.parametrize(
    "classification",
    (Classification.UNKNOWN, Classification.PENDING),
)
def test_indeterminate_classifications_remain_ordinary_event_data(
    classification: Classification,
) -> None:
    event = make_investigation_event(InvestigationEventType.CLASSIFICATION)
    payload = _payload(event)
    event_payload = payload["payload"]
    assert isinstance(event_payload, dict)
    event_payload["classification"] = classification.value

    parsed = InvestigationEvent.model_validate_json(json.dumps(payload))

    assert parsed.payload.classification is classification  # type: ignore[union-attr]


def test_independent_schema_clients_validate_every_event_payload() -> None:
    artifacts = generated_artifacts()
    event_path = next(
        path for path in artifacts if path.name == "investigation-event.schema.json"
    )
    validator = Draft202012Validator(json.loads(artifacts[event_path]))

    for event_type in InvestigationEventType:
        validator.validate(_payload(make_investigation_event(event_type)))
