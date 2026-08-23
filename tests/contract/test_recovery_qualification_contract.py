"""Public recovery qualification v1 contract guarantees."""

from __future__ import annotations

import json

import pytest
from jsonschema import Draft202012Validator
from pydantic import ValidationError

from reconcile.contracts import (
    GeminiHypothesis,
    RecoveryHypothesisDisposition,
    canonical_json_bytes,
    canonical_sha256,
)
from scripts.generate_contract_schemas import PUBLIC_SCHEMAS, generated_artifacts
from tests.contract._factories import make_recovery_qualification_examples

pytestmark = pytest.mark.contract


def test_recovery_qualification_examples_are_strict_canonical_v1_records() -> None:
    examples = make_recovery_qualification_examples()

    assert len(examples) == 7
    assert all(
        example.schema_version.startswith("reconcile/recovery-qualification-")
        and example.schema_version.endswith("/v1")
        for example in examples
    )
    assert all(canonical_json_bytes(example) for example in examples)


def test_recovery_qualification_schemas_are_exact_and_validate_examples() -> None:
    examples = {type(item): item for item in make_recovery_qualification_examples()}
    artifacts = generated_artifacts()
    selected = {
        name: model
        for name, model in PUBLIC_SCHEMAS.items()
        if name.startswith("recovery-qualification-")
    }

    assert len(selected) == 7
    for name, model in selected.items():
        path = next(item for item in artifacts if item.stem == f"{name}.schema")
        expected = artifacts[path]
        assert path.read_text(encoding="utf-8") == expected
        schema = json.loads(expected)
        Draft202012Validator(schema).validate(
            json.loads(canonical_json_bytes(examples[model]))
        )


def test_manifest_rejects_seed_or_matrix_drift() -> None:
    manifest = make_recovery_qualification_examples()[0]
    payload = manifest.model_dump(mode="python")
    payload["seeds"] = (1, *manifest.seeds[1:])

    with pytest.raises(ValidationError, match="seeds changed"):
        type(manifest).model_validate(payload)


def test_results_reject_false_permit_accounting_drift() -> None:
    results = make_recovery_qualification_examples()[2]
    payload = results.model_dump(mode="python")
    payload["false_permit_count"] = 1

    with pytest.raises(ValidationError, match="aggregate counts"):
        type(results).model_validate(payload)


def test_results_reject_an_unsupported_wrong_hypothesis_probe() -> None:
    results = make_recovery_qualification_examples()[2]
    payload = results.model_dump(mode="python")
    replay = payload["case_proofs"][0]["wrong_hypothesis_replays"][0]
    replay["disposition"] = RecoveryHypothesisDisposition.UNSUPPORTED_PROBE

    with pytest.raises(ValidationError, match="supported probe path"):
        type(results).model_validate(payload)


def test_results_require_the_declared_factual_hypothesis_error() -> None:
    results = make_recovery_qualification_examples()[2]
    payload = results.model_dump(mode="python")
    replay = payload["case_proofs"][0]["wrong_hypothesis_replays"][0]
    replay["persisted_hypothesis"]["proposed_classification"] = replay[
        "expected_hypothesis"
    ]["proposed_classification"]
    digest = canonical_sha256(
        GeminiHypothesis.model_validate(replay["persisted_hypothesis"])
    )
    replay["persisted_hypothesis_sha256"] = digest
    replay["agent_output_sha256"] = digest

    with pytest.raises(ValidationError, match="exactly its declared fact"):
        type(results).model_validate(payload)


def test_wrong_hypothesis_oracle_is_derived_from_its_retained_report() -> None:
    results = make_recovery_qualification_examples()[2]
    payload = results.model_dump(mode="python")
    replay = payload["case_proofs"][0]["wrong_hypothesis_replays"][0]
    replay["expected_hypothesis"]["proposed_classification"] = replay[
        "persisted_hypothesis"
    ]["proposed_classification"]
    replay["expected_hypothesis_sha256"] = canonical_sha256(
        GeminiHypothesis.model_validate(replay["expected_hypothesis"])
    )

    with pytest.raises(ValidationError, match="reproduce its report facts"):
        type(results).model_validate(payload)


def test_wrong_hypothesis_rejects_a_false_generation_source() -> None:
    results = make_recovery_qualification_examples()[2]
    payload = results.model_dump(mode="python")
    replay = payload["case_proofs"][0]["wrong_hypothesis_replays"][0]
    replay["generation_source"] = "gemini"

    with pytest.raises(ValidationError, match="scripted-adversarial"):
        type(results).model_validate(payload)


def test_wrong_hypothesis_rejects_a_stale_persisted_digest() -> None:
    results = make_recovery_qualification_examples()[2]
    payload = results.model_dump(mode="python")
    replay = payload["case_proofs"][0]["wrong_hypothesis_replays"][0]
    replay["persisted_hypothesis_sha256"] = "0" * 64

    with pytest.raises(ValidationError, match="persisted wrong-hypothesis identity"):
        type(results).model_validate(payload)


def test_wrong_hypothesis_rejects_an_unpersisted_agent_output() -> None:
    results = make_recovery_qualification_examples()[2]
    payload = results.model_dump(mode="python")
    replay = payload["case_proofs"][0]["wrong_hypothesis_replays"][0]
    replay["agent_output_sha256"] = "0" * 64

    with pytest.raises(ValidationError, match="persisted byte-for-byte"):
        type(results).model_validate(payload)


def test_scripted_claim_record_withholds_adaptive_efficiency_wording() -> None:
    claims = make_recovery_qualification_examples()[5]

    assert claims.safety_claim_authorized is True
    assert claims.adaptive_efficiency_claim_authorized is False
    assert claims.authorized_claims == (
        "proof-to-permit safety on the frozen recovery matrix",
    )
    assert claims.withheld_claims == (
        "adaptive investigation reduced median probe count by at least 25 percent",
    )
