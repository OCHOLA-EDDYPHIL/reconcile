"""Immutable allowlist registrations for provider-neutral observation probes."""

from __future__ import annotations

import inspect
from collections.abc import Mapping
from dataclasses import dataclass, field
from enum import StrEnum
from threading import RLock
from types import MappingProxyType
from typing import Protocol

from pydantic import Field, JsonValue, model_validator

from reconcile.contracts import (
    ObservationCapability,
    TargetBinding,
    canonical_json_bytes,
    decode_contract,
)
from reconcile.contracts.base import (
    ArgumentsObject,
    AwareDatetime,
    Identifier,
    JsonObject,
    StrictModel,
    reject_sensitive_keys,
)

_MAX_SIGNED_64 = 2**63 - 1
_ROOT_SCHEMA_KEYS = frozenset(
    {"$schema", "additionalProperties", "properties", "required", "type"}
)
_SCALAR_SCHEMA_KEYS = {
    "boolean": frozenset({"type"}),
    "integer": frozenset({"maximum", "minimum", "type"}),
    "null": frozenset({"type"}),
    "number": frozenset({"maximum", "minimum", "type"}),
    "string": frozenset({"maxLength", "minLength", "type"}),
}
_ARRAY_SCHEMA_KEYS = frozenset({"items", "maxItems", "minItems", "type", "uniqueItems"})


class CapabilitySemantics(StrEnum):
    READ_ONLY = "READ_ONLY"
    MUTATING = "MUTATING"
    AMBIGUOUS = "AMBIGUOUS"


class BoundProbe(StrictModel):
    investigation_id: Identifier
    operation_id: Identifier
    capability_name: Identifier
    capability_version: Identifier
    target: TargetBinding
    relevant_effect_ids: tuple[Identifier, ...] = Field(min_length=1, max_length=64)
    arguments: ArgumentsObject = Field(default_factory=dict)
    timeout_ms: int = Field(ge=1, le=_MAX_SIGNED_64)
    result_byte_ceiling: int = Field(ge=1, le=_MAX_SIGNED_64)

    @model_validator(mode="after")
    def validate_probe(self) -> BoundProbe:
        if len(self.relevant_effect_ids) != len(set(self.relevant_effect_ids)):
            raise ValueError("relevant effect identifiers must be unique")
        reject_sensitive_keys(self.arguments)
        return self


class ProbeObservation(StrictModel):
    observed_at: AwareDatetime
    payload: JsonObject

    @model_validator(mode="after")
    def validate_secret_free_payload(self) -> ProbeObservation:
        reject_sensitive_keys(self.payload)
        return self


class ObservationHandler(Protocol):
    async def __call__(self, probe: BoundProbe) -> ProbeObservation: ...


class CapabilityUnavailable(RuntimeError):
    code = "capability_unavailable"

    def __init__(self) -> None:
        super().__init__("capability is unavailable")


class DuplicateCapabilityRegistration(ValueError):
    def __init__(self) -> None:
        super().__init__("capability identity is already registered")


class RegistryFrozen(RuntimeError):
    def __init__(self) -> None:
        super().__init__("capability registry is frozen")


def _validate_nonnegative_bound(
    schema: Mapping[str, JsonValue],
    key: str,
    *,
    ceiling: int,
    required: bool,
) -> int:
    value = schema.get(key)
    if value is None and not required:
        return 0
    if type(value) is not int or value < 0 or value > ceiling:
        raise ValueError("capability argument schema is outside the closed profile")
    return value


def _validate_numeric_leaf(schema: Mapping[str, JsonValue], schema_type: str) -> None:
    minimum = schema.get("minimum")
    maximum = schema.get("maximum")
    allowed_type = int if schema_type == "integer" else (int, float)
    if (
        isinstance(minimum, bool)
        or isinstance(maximum, bool)
        or not isinstance(minimum, allowed_type)
        or not isinstance(maximum, allowed_type)
        or minimum > maximum
    ):
        raise ValueError("capability argument schema is outside the closed profile")


def _validate_scalar_schema(
    schema: JsonValue,
    *,
    argument_byte_ceiling: int,
) -> None:
    if not isinstance(schema, dict):
        raise ValueError("capability argument schema is outside the closed profile")
    schema_type = schema.get("type")
    if not isinstance(schema_type, str) or schema_type not in _SCALAR_SCHEMA_KEYS:
        raise ValueError("capability argument schema is outside the closed profile")
    if set(schema) - _SCALAR_SCHEMA_KEYS[schema_type]:
        raise ValueError("capability argument schema is outside the closed profile")
    if schema_type == "string":
        minimum = _validate_nonnegative_bound(
            schema,
            "minLength",
            ceiling=argument_byte_ceiling,
            required=False,
        )
        maximum = _validate_nonnegative_bound(
            schema,
            "maxLength",
            ceiling=argument_byte_ceiling,
            required=True,
        )
        if minimum > maximum:
            raise ValueError("capability argument schema is outside the closed profile")
    elif schema_type in {"integer", "number"}:
        _validate_numeric_leaf(schema, schema_type)


def _validate_property_schema(
    schema: JsonValue,
    *,
    argument_byte_ceiling: int,
) -> None:
    if not isinstance(schema, dict):
        raise ValueError("capability argument schema is outside the closed profile")
    if schema.get("type") != "array":
        _validate_scalar_schema(
            schema,
            argument_byte_ceiling=argument_byte_ceiling,
        )
        return
    if set(schema) - _ARRAY_SCHEMA_KEYS:
        raise ValueError("capability argument schema is outside the closed profile")
    minimum = _validate_nonnegative_bound(
        schema,
        "minItems",
        ceiling=argument_byte_ceiling,
        required=False,
    )
    maximum = _validate_nonnegative_bound(
        schema,
        "maxItems",
        ceiling=argument_byte_ceiling,
        required=True,
    )
    if minimum > maximum or type(schema.get("uniqueItems", False)) is not bool:
        raise ValueError("capability argument schema is outside the closed profile")
    _validate_scalar_schema(
        schema.get("items"),
        argument_byte_ceiling=argument_byte_ceiling,
    )


def _validate_closed_argument_schema(
    capability: ObservationCapability,
    *,
    argument_byte_ceiling: int,
) -> None:
    schema = capability.argument_schema
    if set(schema) != _ROOT_SCHEMA_KEYS:
        raise ValueError("capability argument schema is outside the closed profile")
    properties = schema.get("properties")
    required = schema.get("required")
    if (
        schema.get("type") != "object"
        or schema.get("additionalProperties") is not False
        or not isinstance(properties, dict)
        or len(properties) > 64
        or not isinstance(required, list)
        or any(not isinstance(name, str) for name in required)
        or len(required) != len(set(required))
        or not set(required).issubset(properties)
    ):
        raise ValueError("capability argument schema is outside the closed profile")
    for property_schema in properties.values():
        _validate_property_schema(
            property_schema,
            argument_byte_ceiling=argument_byte_ceiling,
        )


def _is_async_callable(handler: object) -> bool:
    if not callable(handler):
        return False
    if inspect.iscoroutinefunction(handler):
        return True
    call = type(handler).__call__
    return inspect.iscoroutinefunction(call)


@dataclass(frozen=True, slots=True, init=False)
class CapabilityRegistration:
    _capability_bytes: bytes = field(repr=False)
    semantics: CapabilitySemantics
    enabled: bool
    argument_byte_ceiling: int
    max_invocations: int
    handler: ObservationHandler | None = field(default=None, repr=False, compare=False)

    def __init__(
        self,
        capability: ObservationCapability,
        semantics: CapabilitySemantics,
        enabled: bool,
        argument_byte_ceiling: int,
        max_invocations: int,
        handler: ObservationHandler | None = None,
    ) -> None:
        if type(capability) is not ObservationCapability:
            raise TypeError("capability must be an observation capability")
        if not isinstance(semantics, CapabilitySemantics):
            raise TypeError("capability semantics must be explicitly verified")
        if type(enabled) is not bool:
            raise TypeError("capability enabled state must be boolean")
        for value, label in (
            (argument_byte_ceiling, "argument byte ceiling"),
            (max_invocations, "maximum invocation count"),
        ):
            if type(value) is not int or not 1 <= value <= _MAX_SIGNED_64:
                raise ValueError(f"{label} must be a positive signed 64-bit integer")

        executable = enabled and semantics is CapabilitySemantics.READ_ONLY
        if executable and handler is None:
            raise ValueError("enabled read-only capability requires an async handler")
        if not executable and handler is not None:
            raise ValueError("non-executable capability cannot store a handler")
        if handler is not None and not _is_async_callable(handler):
            raise TypeError("observation handler must be async")

        _validate_closed_argument_schema(
            capability,
            argument_byte_ceiling=argument_byte_ceiling,
        )
        object.__setattr__(self, "_capability_bytes", canonical_json_bytes(capability))
        object.__setattr__(self, "semantics", semantics)
        object.__setattr__(self, "enabled", enabled)
        object.__setattr__(self, "argument_byte_ceiling", argument_byte_ceiling)
        object.__setattr__(self, "max_invocations", max_invocations)
        object.__setattr__(self, "handler", handler)

    @property
    def capability(self) -> ObservationCapability:
        return decode_contract(self._capability_bytes, ObservationCapability)

    @property
    def identity(self) -> tuple[str, str]:
        capability = self.capability
        return capability.name, capability.version

    def isolated_copy(self) -> CapabilityRegistration:
        return CapabilityRegistration(
            capability=self.capability,
            semantics=self.semantics,
            enabled=self.enabled,
            argument_byte_ceiling=self.argument_byte_ceiling,
            max_invocations=self.max_invocations,
            handler=self.handler,
        )


class CapabilityRegistry:
    def __init__(self) -> None:
        self._lock = RLock()
        self._registrations: dict[tuple[str, str], CapabilityRegistration] = {}
        self._snapshot: Mapping[tuple[str, str], CapabilityRegistration] | None = None

    @property
    def is_frozen(self) -> bool:
        with self._lock:
            return self._snapshot is not None

    def register(self, registration: CapabilityRegistration) -> None:
        if type(registration) is not CapabilityRegistration:
            raise TypeError("registration must be a capability registration")
        with self._lock:
            if self._snapshot is not None:
                raise RegistryFrozen
            key = registration.identity
            if key in self._registrations:
                raise DuplicateCapabilityRegistration
            self._registrations[key] = registration.isolated_copy()

    def freeze(self) -> tuple[CapabilityRegistration, ...]:
        with self._lock:
            if self._snapshot is None:
                self._snapshot = MappingProxyType(dict(self._registrations))
            return tuple(
                self._snapshot[key].isolated_copy() for key in sorted(self._snapshot)
            )

    def resolve(self, name: str, version: str) -> CapabilityRegistration | None:
        if type(name) is not str or type(version) is not str:
            return None
        with self._lock:
            if self._snapshot is None:
                self._snapshot = MappingProxyType(dict(self._registrations))
            registration = self._snapshot.get((name, version))
            return registration.isolated_copy() if registration is not None else None
