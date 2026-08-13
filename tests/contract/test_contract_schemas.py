"""Checked-in public schema artifact guarantees."""

from __future__ import annotations

import json

import pytest
from jsonschema import Draft202012Validator

from reconcile.contracts import canonical_json_bytes
from scripts.generate_contract_schemas import PUBLIC_SCHEMAS, generated_artifacts
from tests.contract._factories import public_examples

pytestmark = pytest.mark.contract


def test_checked_in_schema_artifacts_are_exactly_regenerable() -> None:
    for path, expected in generated_artifacts().items():
        assert path.read_text(encoding="utf-8") == expected


def test_every_public_schema_requires_exact_version_and_rejects_unknown_fields() -> (
    None
):
    for name in PUBLIC_SCHEMAS:
        path = generated_artifacts().keys()
        artifact_path = next(item for item in path if item.stem == f"{name}.schema")
        schema = json.loads(artifact_path.read_text(encoding="utf-8"))

        assert schema["additionalProperties"] is False
        assert "schema_version" in schema["required"]
        assert schema["properties"]["schema_version"]["const"].endswith("/v1")


def test_canonical_examples_validate_against_public_schema_artifacts() -> None:
    examples = {type(example): example for example in public_examples()}
    artifacts = generated_artifacts()
    for name, model in PUBLIC_SCHEMAS.items():
        path = next(item for item in artifacts if item.stem == f"{name}.schema")
        schema = json.loads(path.read_text(encoding="utf-8"))
        Draft202012Validator(schema).validate(
            json.loads(canonical_json_bytes(examples[model]))
        )


def test_argument_key_count_matches_runtime_contract() -> None:
    artifact = generated_artifacts()[
        next(
            path
            for path in generated_artifacts()
            if path.name == "probe-request.schema.json"
        )
    ]
    schema = json.loads(artifact)
    payload = json.loads(canonical_json_bytes(public_examples()[3]))
    payload["arguments"] = {f"field_{index}": index for index in range(65)}

    errors = list(Draft202012Validator(schema).iter_errors(payload))

    assert any(error.validator == "maxProperties" for error in errors)
