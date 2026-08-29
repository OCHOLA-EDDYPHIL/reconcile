"""Contract invariants for proof-scoped recovery authority."""

from __future__ import annotations

import json
from copy import deepcopy

import pytest
from pydantic import ValidationError

from reconcile.contracts import (
    RECOVERY_RUN_REQUEST_VERSION,
    ActionPermit,
    AmbiguityWitness,
    Classification,
    GeminiHypothesis,
    RecoveryChain,
    RecoveryRunFault,
    RecoveryRunPolicy,
    RecoveryRunRequest,
    SemanticActionIdentity,
    canonical_json_bytes,
    decode_contract,
    semantic_action_sha256,
)
from tests.contract._factories import make_recovery_examples

pytestmark = pytest.mark.contract


def _payload(model: object) -> dict[str, object]:
    return json.loads(canonical_json_bytes(model))  # type: ignore[arg-type]


def test_partial_read_acceptance_fault_is_fixed_and_run_id_scoped() -> None:
    request = RecoveryRunRequest(
        schema_version=RECOVERY_RUN_REQUEST_VERSION,
        run_id=f"p5w-fixed-{'a' * 32}",
        scenario="cloud-run-rollout",
        policy=RecoveryRunPolicy.FIXED,
        fault=(RecoveryRunFault.ACCEPTANCE_DROP_AFTER_ACCEPT_PARTIAL_READ_OUTAGE),
    )

    assert request.fault.value == ("acceptance-drop-after-accept-partial-read-outage")
    for update in (
        {"policy": RecoveryRunPolicy.ADAPTIVE},
        {"run_id": f"p5r-fixed-{'a' * 32}"},
        {"run_id": f"p5w-fixed-{'A' * 32}"},
    ):
        with pytest.raises(ValidationError, match="partial-read acceptance fault"):
            RecoveryRunRequest.model_validate(
                request.model_dump(mode="python") | update
            )


def test_recovery_contracts_round_trip_canonically() -> None:
    for model in make_recovery_examples():
        decoded = decode_contract(canonical_json_bytes(model), type(model))
        assert decoded == model
        assert canonical_json_bytes(decoded) == canonical_json_bytes(model)


@pytest.mark.parametrize("failure", ("cycle", "missing", "profile", "semantic"))
def test_recovery_chain_rejects_invalid_graphs(failure: str) -> None:
    chain = make_recovery_examples()[0]
    payload = _payload(chain)
    nodes = payload["nodes"]
    assert isinstance(nodes, list)

    if failure == "cycle":
        nodes[0]["depends_on"] = [nodes[1]["node_id"]]
    elif failure == "missing":
        nodes[1]["depends_on"] = ["missing-node"]
    elif failure == "profile":
        nodes[1]["chain_profile_version"] = "different-profile"
    else:
        nodes[1]["semantic_action"] = nodes[0]["semantic_action"]

    with pytest.raises(ValidationError):
        RecoveryChain.model_validate_json(json.dumps(payload))


def test_semantic_identity_ignores_dispatch_ids_but_binds_meaning() -> None:
    action = make_recovery_examples()[0].nodes[0].semantic_action
    unchanged = semantic_action_sha256(
        key_version=action.key_version,
        tool_name=action.tool_name,
        tool_version=action.tool_version,
        semantic_arguments=action.semantic_arguments,
        target=action.target,
        expected_effect_sha256s=action.expected_effect_sha256s,
        action_profile_version=action.action_profile_version,
    )
    assert unchanged == action.semantic_action_sha256

    changed_arguments = dict(action.semantic_arguments)
    changed_arguments["release_id"] = "r-8"
    changed = semantic_action_sha256(
        key_version=action.key_version,
        tool_name=action.tool_name,
        tool_version=action.tool_version,
        semantic_arguments=changed_arguments,
        target=action.target,
        expected_effect_sha256s=action.expected_effect_sha256s,
        action_profile_version=action.action_profile_version,
    )
    assert changed != unchanged

    changed_target = action.target.model_copy(
        update={"resource": {"object_name": "receipts/order-8.json"}}
    )
    target_changed = semantic_action_sha256(
        key_version=action.key_version,
        tool_name=action.tool_name,
        tool_version=action.tool_version,
        semantic_arguments=action.semantic_arguments,
        target=changed_target,
        expected_effect_sha256s=action.expected_effect_sha256s,
        action_profile_version=action.action_profile_version,
    )
    assert target_changed != unchanged

    payload = _payload(action)
    payload["semantic_arguments"] = changed_arguments
    with pytest.raises(ValidationError, match="semantic action digest"):
        SemanticActionIdentity.model_validate_json(json.dumps(payload))

    secret = _payload(action)
    secret_arguments = deepcopy(secret["semantic_arguments"])
    secret_arguments["access_token"] = "visible-secret"
    secret["semantic_arguments"] = secret_arguments
    with pytest.raises(ValidationError, match="secret-bearing"):
        SemanticActionIdentity.model_validate_json(json.dumps(secret))


def test_gemini_hypothesis_is_advisory_and_citations_are_closed() -> None:
    hypothesis = make_recovery_examples()[1]
    payload = _payload(hypothesis)
    payload["permit_id"] = "model-forged-permit"

    with pytest.raises(ValidationError):
        GeminiHypothesis.model_validate_json(json.dumps(payload))

    payload = _payload(hypothesis)
    payload["effect_hypotheses"][0]["cited_evidence_ids"] = ["unknown-evidence"]
    with pytest.raises(ValidationError, match="undeclared evidence"):
        GeminiHypothesis.model_validate_json(json.dumps(payload))


def test_certificate_rejects_unknown_or_mismatched_authority() -> None:
    certificate = make_recovery_examples()[2]

    unknown = _payload(certificate)
    unknown["classification"] = Classification.UNKNOWN
    unknown["transition"] = None
    with pytest.raises(ValidationError, match="ambiguity witness"):
        type(certificate).model_validate_json(json.dumps(unknown))

    wrong_target = _payload(certificate)
    wrong_target["target_sha256"] = "0" * 64
    with pytest.raises(ValidationError, match="target digest"):
        type(certificate).model_validate_json(json.dumps(wrong_target))

    overlong = _payload(certificate)
    overlong["expires_at"] = "2026-08-13T12:01:00Z"
    with pytest.raises(ValidationError, match="supporting evidence"):
        type(certificate).model_validate_json(json.dumps(overlong))


def test_ambiguity_witness_requires_distinct_compatible_histories() -> None:
    witness = make_recovery_examples()[3]
    payload = _payload(witness)
    payload["possible_histories"][1]["classification"] = payload["possible_histories"][
        0
    ]["classification"]
    payload["possible_histories"][1]["effect_states"] = payload["possible_histories"][
        0
    ]["effect_states"]

    with pytest.raises(ValidationError, match="history outcomes"):
        AmbiguityWitness.model_validate_json(json.dumps(payload))

    unknown_history = _payload(witness)
    unknown_history["discriminating_observations"][0]["distinguishes_history_ids"][
        1
    ] = "unknown-history"
    with pytest.raises(ValidationError, match="unknown history"):
        AmbiguityWitness.model_validate_json(json.dumps(unknown_history))


def test_action_permit_enforces_one_use_lifecycle() -> None:
    permit = make_recovery_examples()[4]
    payload = _payload(permit)
    payload["max_uses"] = 2
    with pytest.raises(ValidationError):
        ActionPermit.model_validate_json(json.dumps(payload))

    claimed_without_identity = _payload(permit)
    claimed_without_identity["state"] = "CLAIMED"
    claimed_without_identity["revision"] = 1
    with pytest.raises(ValidationError, match="lifecycle state"):
        ActionPermit.model_validate_json(json.dumps(claimed_without_identity))

    retry_to_successor = _payload(permit)
    retry_to_successor["action"] = "RETRY"
    with pytest.raises(ValidationError, match="source node"):
        ActionPermit.model_validate_json(json.dumps(retry_to_successor))
