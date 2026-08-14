"""Execution, effect, capability, and probe contracts."""

from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from typing import Literal

from jsonschema import Draft202012Validator
from jsonschema.exceptions import SchemaError
from pydantic import Field, JsonValue, model_validator

from reconcile.contracts.base import (
    ArgumentsObject,
    AwareDatetime,
    Identifier,
    JsonObject,
    NonEmptySmallJsonObject,
    NonEmptyText,
    SanitizedText,
    StrictModel,
    canonical_json_value_bytes,
    reject_sensitive_keys,
    reject_sensitive_values,
)
from reconcile.contracts.common import (
    AmbiguousExecution,
    EnvelopeContext,
    TargetBinding,
    TargetConstraint,
)

EXPECTED_EFFECT_VERSION = "reconcile/expected-effect/v1"
EXECUTION_ENVELOPE_VERSION = "reconcile/execution-envelope/v1"
OBSERVATION_CAPABILITY_VERSION = "reconcile/observation-capability/v1"
PROBE_REQUEST_VERSION = "reconcile/probe-request/v1"

_TARGET_COORDINATE_TOKENS = frozenset(
    {
        "address",
        "bucket",
        "credential",
        "credentials",
        "database",
        "document",
        "domain",
        "endpoint",
        "headers",
        "header",
        "host",
        "hostname",
        "method",
        "object",
        "path",
        "port",
        "project",
        "resource",
        "scope",
        "target",
        "token",
        "uri",
        "url",
    }
)


def _iter_object_keys(value: JsonValue) -> Sequence[str]:
    keys: list[str] = []
    if isinstance(value, Mapping):
        for key, item in value.items():
            words = re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", key).lower()
            keys.extend(part for part in re.split(r"[^a-z0-9]+", words) if part)
            keys.extend(_iter_object_keys(item))
    elif isinstance(value, list):
        for item in value:
            keys.extend(_iter_object_keys(item))
    return keys


def _reject_target_coordinates(value: JsonObject) -> None:
    forbidden = _TARGET_COORDINATE_TOKENS.intersection(_iter_object_keys(value))
    if forbidden:
        names = ", ".join(sorted(forbidden))
        raise ValueError(f"target coordinates are controller-owned: {names}")


def _reject_schema_indirection(value: JsonValue, *, root: bool = True) -> None:
    if isinstance(value, Mapping):
        for key, item in value.items():
            if key.startswith("$") and (key != "$schema" or not root):
                raise ValueError("capability argument schemas cannot use indirection")
            _reject_schema_indirection(item, root=False)
    elif isinstance(value, list):
        for item in value:
            _reject_schema_indirection(item, root=False)


class ExpectedEffect(StrictModel):
    schema_version: Literal[EXPECTED_EFFECT_VERSION]
    effect_id: Identifier
    commit_scope: Identifier
    predicate: NonEmptySmallJsonObject
    description: NonEmptyText

    @model_validator(mode="after")
    def validate_no_credentials(self) -> ExpectedEffect:
        reject_sensitive_keys(self.predicate)
        reject_sensitive_values(self.predicate)
        reject_sensitive_values(self.description)
        return self


class ExecutionEnvelope(StrictModel):
    schema_version: Literal[EXECUTION_ENVELOPE_VERSION]
    investigation_id: Identifier
    operation_id: Identifier
    target: TargetBinding
    invoked_at: AwareDatetime
    ambiguity: AmbiguousExecution
    expected_effects: tuple[ExpectedEffect, ...] = Field(min_length=1, max_length=64)
    context: EnvelopeContext

    @model_validator(mode="after")
    def validate_effect_identity(self) -> ExecutionEnvelope:
        effect_ids = [effect.effect_id for effect in self.expected_effects]
        if len(effect_ids) != len(set(effect_ids)):
            raise ValueError("expected effect identifiers must be unique")
        return self


class ObservationCapability(StrictModel):
    schema_version: Literal[OBSERVATION_CAPABILITY_VERSION]
    name: Identifier
    version: Identifier
    read_only: Literal[True]
    argument_schema: JsonObject
    allowed_targets: tuple[TargetConstraint, ...] = Field(min_length=1, max_length=32)
    timeout_ms: int = Field(ge=1, le=2**63 - 1)
    result_byte_ceiling: int = Field(ge=1, le=2**63 - 1)
    cost_units: int = Field(ge=1, le=2**63 - 1)

    @model_validator(mode="after")
    def validate_descriptor(self) -> ObservationCapability:
        if self.argument_schema.get("type") != "object":
            raise ValueError("capability argument schema must describe an object")
        if self.argument_schema.get("additionalProperties") is not False:
            raise ValueError("capability argument schema must reject extra properties")
        if (
            self.argument_schema.get("$schema")
            != Draft202012Validator.META_SCHEMA["$id"]
        ):
            raise ValueError(
                "capability argument schema must declare JSON Schema 2020-12"
            )
        try:
            Draft202012Validator.check_schema(self.argument_schema)
        except SchemaError as error:
            raise ValueError("capability argument schema is invalid") from error
        _reject_schema_indirection(self.argument_schema)
        reject_sensitive_keys(self.argument_schema)
        _reject_target_coordinates(self.argument_schema)
        target_keys = [
            (target.target_kind, canonical_json_value_bytes(target.scope))
            for target in self.allowed_targets
        ]
        if len(target_keys) != len(set(target_keys)):
            raise ValueError("allowed target constraints must be unique")
        return self


class ProbeRequest(StrictModel):
    schema_version: Literal[PROBE_REQUEST_VERSION]
    capability_name: Identifier
    capability_version: Identifier
    relevant_effect_ids: tuple[Identifier, ...] = Field(min_length=1, max_length=64)
    arguments: ArgumentsObject = Field(default_factory=dict)
    rationale: SanitizedText

    @model_validator(mode="after")
    def validate_request(self) -> ProbeRequest:
        if len(self.relevant_effect_ids) != len(set(self.relevant_effect_ids)):
            raise ValueError("relevant effect identifiers must be unique")
        reject_sensitive_keys(self.arguments)
        reject_sensitive_values(self.arguments)
        _reject_target_coordinates(self.arguments)
        return self
