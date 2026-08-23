"""Canonical wire-codec behavior."""

from __future__ import annotations

import json

import pytest
from pydantic import BaseModel, ValidationError

from reconcile.contracts import (
    EXECUTION_ENVELOPE_VERSION,
    RECOVERY_ACTION_SCOPE_VERSION,
    Classification,
    ContractError,
    ExecutionEnvelope,
    RecoveryActionScope,
    canonical_json_bytes,
    decode_contract,
)
from tests.contract._factories import make_envelope, make_report, public_examples

pytestmark = pytest.mark.unit


@pytest.mark.parametrize("model", public_examples())
def test_every_public_payload_round_trips_canonically(model: BaseModel) -> None:
    encoded = canonical_json_bytes(model)

    decoded = decode_contract(encoded, type(model))

    assert decoded == model
    assert canonical_json_bytes(decoded) == encoded
    assert b"\n" not in encoded
    schema_version = json.loads(encoded)["schema_version"]
    if type(model) is RecoveryActionScope:
        assert schema_version == RECOVERY_ACTION_SCOPE_VERSION
    else:
        assert schema_version.endswith("/v1")


@pytest.mark.parametrize("classification", tuple(Classification))
def test_all_five_state_report_examples_round_trip(
    classification: Classification,
) -> None:
    report = make_report(classification)

    assert (
        decode_contract(
            canonical_json_bytes(report),
            type(report),
        )
        == report
    )


def test_canonical_json_sorts_keys_and_normalizes_timestamps_to_utc() -> None:
    original = canonical_json_bytes(make_envelope())
    payload = json.loads(original)
    payload["invoked_at"] = "2026-08-13T14:00:00+02:00"
    encoded = json.dumps(payload, ensure_ascii=False)

    decoded = decode_contract(encoded, ExecutionEnvelope)
    canonical = canonical_json_bytes(decoded)

    assert canonical == original
    assert b'"invoked_at":"2026-08-13T12:00:00Z"' in canonical
    assert canonical.startswith(b'{"ambiguity":')


@pytest.mark.parametrize(
    ("payload", "code"),
    (
        ('{"investigation_id":"i"}', "invalid_contract"),
        (
            '{"schema_version":"reconcile/execution-envelope/v2"}',
            "unsupported_contract_version",
        ),
        (
            '{"schema_version":"reconcile/execution-envelope/v1",'
            '"investigation_id":"one","investigation_id":"two"}',
            "invalid_contract",
        ),
        (
            '{"schema_version":"reconcile/execution-envelope/v1","number":NaN}',
            "invalid_contract",
        ),
        ("[]", "invalid_contract"),
        ("{", "invalid_contract"),
    ),
)
def test_invalid_wire_payloads_fail_with_stable_codes(payload: str, code: str) -> None:
    with pytest.raises(ContractError) as raised:
        decode_contract(payload, ExecutionEnvelope)

    assert raised.value.code == code


def test_unknown_version_wins_before_field_validation() -> None:
    payload = {
        "schema_version": "reconcile/execution-envelope/v999",
        "unexpected": "field",
    }

    with pytest.raises(ContractError) as raised:
        decode_contract(json.dumps(payload), ExecutionEnvelope)

    assert raised.value.code == "unsupported_contract_version"


def test_nested_unknown_version_is_explicitly_unsupported() -> None:
    payload = json.loads(canonical_json_bytes(make_envelope()))
    payload["expected_effects"][0]["schema_version"] = "reconcile/expected-effect/v2"

    with pytest.raises(ContractError) as raised:
        decode_contract(json.dumps(payload), ExecutionEnvelope)

    assert raised.value.code == "unsupported_contract_version"


@pytest.mark.parametrize("malformed", (1, None, True, [], {}))
def test_nested_non_string_versions_are_invalid(malformed: object) -> None:
    payload = json.loads(canonical_json_bytes(make_envelope()))
    payload["expected_effects"][0]["schema_version"] = malformed

    with pytest.raises(ContractError) as raised:
        decode_contract(json.dumps(payload), ExecutionEnvelope)

    assert raised.value.code == "invalid_contract"


def test_excessively_nested_json_is_a_stable_invalid_contract() -> None:
    payload = "[" * 10_000 + "]" * 10_000

    with pytest.raises(ContractError) as raised:
        decode_contract(payload, ExecutionEnvelope)

    assert raised.value.code == "invalid_contract"


def test_extra_fields_and_naive_timestamps_are_invalid_contracts() -> None:
    for field, value in (
        ("unexpected", True),
        ("invoked_at", "2026-08-13T12:00:00"),
    ):
        payload = json.loads(canonical_json_bytes(make_envelope()))
        payload[field] = value

        with pytest.raises(ContractError) as raised:
            decode_contract(json.dumps(payload), ExecutionEnvelope)

        assert raised.value.code == "invalid_contract"


def test_non_unicode_scalar_text_is_rejected_before_persistence() -> None:
    payload = json.loads(canonical_json_bytes(make_envelope()))
    payload["ambiguity"]["detail"] = "invalid-\ud800"

    with pytest.raises(ContractError) as raised:
        decode_contract(json.dumps(payload), ExecutionEnvelope)

    assert raised.value.code == "invalid_contract"


def test_non_unicode_scalar_version_is_malformed_not_unsupported() -> None:
    with pytest.raises(ContractError) as raised:
        decode_contract('{"schema_version":"\\ud800"}', ExecutionEnvelope)

    assert raised.value.code == "invalid_contract"


def test_public_models_require_explicit_versions_even_for_direct_validation() -> None:
    payload = json.loads(canonical_json_bytes(make_envelope()))
    payload.pop("schema_version")

    with pytest.raises(ValidationError):
        ExecutionEnvelope.model_validate_json(json.dumps(payload))

    assert EXECUTION_ENVELOPE_VERSION.endswith("/v1")
