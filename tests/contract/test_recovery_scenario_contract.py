"""Contract invariants for judge-facing release-policy comparisons."""

from __future__ import annotations

import json

import pytest
from pydantic import ValidationError

from reconcile.contracts import (
    RecoveryPolicyComparison,
    RecoveryPolicyResult,
    canonical_json_bytes,
    decode_contract,
)
from tests.contract._factories import make_recovery_scenario_examples

pytestmark = pytest.mark.contract


def _payload(model: object) -> dict[str, object]:
    return json.loads(canonical_json_bytes(model))  # type: ignore[arg-type]


def test_recovery_scenario_contracts_round_trip_canonically() -> None:
    for model in make_recovery_scenario_examples():
        decoded = decode_contract(canonical_json_bytes(model), type(model))
        assert decoded == model
        assert canonical_json_bytes(decoded) == canonical_json_bytes(model)


def test_policy_result_rejects_receipt_from_another_run() -> None:
    receipt, comparison = make_recovery_scenario_examples()
    payload = _payload(comparison.lanes[-2])
    payload["dispatch_receipts"] = [_payload(receipt)]

    with pytest.raises(ValidationError, match="run or release identity"):
        RecoveryPolicyResult.model_validate_json(json.dumps(payload))


def test_suppressed_proof_lane_requires_one_issued_and_consumed_retry() -> None:
    receipt, comparison = make_recovery_scenario_examples()
    payload = _payload(comparison.lanes[-1])
    payload["fault"] = "suppress-before-dispatch"
    payload["dispatch_receipts"] = [_payload(receipt)]
    payload["counters"].update(
        {
            "retry_permits_issued": 1,
            "retry_permits_consumed": 1,
            "action_permits_consumed": 3,
        }
    )

    result = RecoveryPolicyResult.model_validate_json(json.dumps(payload))
    assert result.counters.retry_permits_consumed == 1

    payload["dispatch_receipts"] = []
    with pytest.raises(ValidationError, match="suppression receipt"):
        RecoveryPolicyResult.model_validate_json(json.dumps(payload))


def test_proof_lane_requires_a_certificate_or_ambiguity_witness() -> None:
    _receipt, comparison = make_recovery_scenario_examples()
    payload = _payload(comparison.lanes[-2])
    payload["certificate_sha256s"] = []

    with pytest.raises(ValidationError, match="certificate or ambiguity witness"):
        RecoveryPolicyResult.model_validate_json(json.dumps(payload))


@pytest.mark.parametrize("changed", ["run", "fault", "binding", "release"])
def test_comparison_rejects_non_equivalent_policy_lanes(changed: str) -> None:
    _receipt, comparison = make_recovery_scenario_examples()
    payload = _payload(comparison)
    lanes = payload["lanes"]
    assert isinstance(lanes, list)

    if changed == "run":
        lanes[1]["run_id"] = lanes[0]["run_id"]
    elif changed == "fault":
        lanes[1]["fault"] = "suppress-before-dispatch"
    elif changed == "binding":
        lanes[1]["target_sha256"] = "f" * 64
    else:
        lanes[1]["firestore"]["release_id"] = "release-8"

    with pytest.raises(ValidationError):
        RecoveryPolicyComparison.model_validate_json(json.dumps(payload))
