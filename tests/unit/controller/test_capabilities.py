from __future__ import annotations

import ast
from copy import deepcopy
from dataclasses import FrozenInstanceError
from datetime import UTC, datetime
from pathlib import Path

import pytest
from pydantic import ValidationError

import reconcile.controller.capabilities as capabilities_module
from reconcile.contracts import ObservationCapability
from reconcile.controller.capabilities import (
    BoundProbe,
    CapabilityRegistration,
    CapabilityRegistry,
    CapabilitySemantics,
    CapabilityUnavailable,
    DuplicateCapabilityRegistration,
    ProbeObservation,
    RegistryFrozen,
)
from tests.contract._factories import make_capability, make_target

pytestmark = pytest.mark.unit

NOW = datetime(2026, 8, 13, 12, 0, tzinfo=UTC)


async def _observe(probe: BoundProbe) -> ProbeObservation:
    return ProbeObservation(
        observed_at=NOW,
        payload={"operation_id": probe.operation_id, "exists": True},
    )


def _closed_capability(
    *,
    name: str = "gcs-object-readback",
    version: str = "1.0.0",
    argument_schema: dict[str, object] | None = None,
) -> ObservationCapability:
    base = make_capability()
    schema = deepcopy(base.argument_schema)
    schema["properties"]["order_id"]["maxLength"] = 128  # type: ignore[index]
    if argument_schema is not None:
        schema = argument_schema
    return ObservationCapability(
        schema_version=base.schema_version,
        name=name,
        version=version,
        read_only=True,
        argument_schema=schema,
        allowed_targets=base.allowed_targets,
        timeout_ms=base.timeout_ms,
        result_byte_ceiling=base.result_byte_ceiling,
        cost_units=base.cost_units,
    )


def _registration(
    *,
    capability: ObservationCapability | None = None,
    semantics: CapabilitySemantics = CapabilitySemantics.READ_ONLY,
    enabled: bool = True,
    argument_byte_ceiling: int = 1_024,
    max_invocations: int = 3,
    handler: object = _observe,
) -> CapabilityRegistration:
    return CapabilityRegistration(
        capability=capability or _closed_capability(),
        semantics=semantics,
        enabled=enabled,
        argument_byte_ceiling=argument_byte_ceiling,
        max_invocations=max_invocations,
        handler=handler,  # type: ignore[arg-type]
    )


def test_registry_resolves_only_the_exact_stable_identity() -> None:
    registry = CapabilityRegistry()
    registry.register(_registration())
    registry.register(_registration(capability=_closed_capability(version="1.0.1")))

    resolved = registry.resolve("gcs-object-readback", "1.0.0")

    assert resolved is not None
    assert resolved.identity == ("gcs-object-readback", "1.0.0")
    assert registry.resolve("GCS-object-readback", "1.0.0") is None
    assert registry.resolve("gcs-object-readback", "1.0") is None
    assert registry.resolve("gcs-object-readback ", "1.0.0") is None
    assert registry.resolve(1, "1.0.0") is None  # type: ignore[arg-type]


def test_duplicate_identity_fails_without_replacing_the_original() -> None:
    registry = CapabilityRegistry()
    original = _registration(max_invocations=2)
    registry.register(original)

    with pytest.raises(
        DuplicateCapabilityRegistration,
        match="capability identity is already registered",
    ):
        registry.register(_registration(max_invocations=8))

    resolved = registry.resolve(*original.identity)
    assert resolved is not None
    assert resolved.max_invocations == 2


def test_freeze_returns_sorted_snapshot_and_rejects_later_registration() -> None:
    registry = CapabilityRegistry()
    registry.register(_registration(capability=_closed_capability(name="second-read")))
    registry.register(_registration(capability=_closed_capability(name="first-read")))

    snapshot = registry.freeze()

    assert registry.is_frozen is True
    assert [registration.identity for registration in snapshot] == [
        ("first-read", "1.0.0"),
        ("second-read", "1.0.0"),
    ]
    assert registry.freeze() == snapshot
    with pytest.raises(RegistryFrozen, match="capability registry is frozen"):
        registry.register(
            _registration(capability=_closed_capability(name="third-read"))
        )


def test_first_resolution_atomically_freezes_the_registry() -> None:
    registry = CapabilityRegistry()
    registry.register(_registration())

    assert registry.resolve("gcs-object-readback", "1.0.0") is not None

    with pytest.raises(RegistryFrozen):
        registry.register(
            _registration(capability=_closed_capability(name="another-read"))
        )


@pytest.mark.parametrize(
    "semantics",
    (CapabilitySemantics.MUTATING, CapabilitySemantics.AMBIGUOUS),
)
def test_unsafe_semantics_are_quarantined_without_handlers(
    semantics: CapabilitySemantics,
) -> None:
    registration = _registration(
        semantics=semantics,
        enabled=True,
        handler=None,
    )
    assert registration.handler is None

    with pytest.raises(ValueError, match="cannot store a handler"):
        _registration(semantics=semantics)


def test_disabled_and_read_only_handler_rules_are_fail_closed() -> None:
    disabled = _registration(enabled=False, handler=None)
    assert disabled.handler is None

    with pytest.raises(ValueError, match="cannot store a handler"):
        _registration(enabled=False)
    with pytest.raises(ValueError, match="requires an async handler"):
        _registration(handler=None)
    with pytest.raises(TypeError, match="must be async"):
        _registration(handler=lambda _: None)


def test_registration_and_resolution_isolate_nested_descriptor_values() -> None:
    capability = _closed_capability()
    registration = _registration(capability=capability)
    capability.argument_schema["properties"]["order_id"]["maxLength"] = 1  # type: ignore[index]
    capability.allowed_targets[0].scope["project_id"] = "changed-project"

    registry = CapabilityRegistry()
    registry.register(registration)
    first = registry.resolve(*registration.identity)
    assert first is not None
    first_descriptor = first.capability
    first_descriptor.argument_schema["properties"]["order_id"][  # type: ignore[index]
        "maxLength"
    ] = 2
    first_descriptor.allowed_targets[0].scope["project_id"] = "other-project"

    second = registry.resolve(*registration.identity)
    assert second is not None
    assert (
        second.capability.argument_schema["properties"]["order_id"][  # type: ignore[index]
            "maxLength"
        ]
        == 128
    )
    assert second.capability.allowed_targets[0].scope["project_id"] == "demo-project"


def test_registration_is_frozen_and_limits_are_positive_signed_64_bit() -> None:
    registration = _registration()
    with pytest.raises(FrozenInstanceError):
        registration.enabled = False  # type: ignore[misc]

    for field_name in ("argument_byte_ceiling", "max_invocations"):
        for invalid in (False, 0, -1, 2**63):
            options = {field_name: invalid}
            with pytest.raises(ValueError, match="positive signed 64-bit"):
                _registration(**options)  # type: ignore[arg-type]

    with pytest.raises(TypeError, match="explicitly verified"):
        _registration(semantics="READ_ONLY")  # type: ignore[arg-type]
    with pytest.raises(TypeError, match="enabled state"):
        _registration(enabled=1)  # type: ignore[arg-type]


def test_registration_revalidates_forged_or_mutated_public_descriptors() -> None:
    valid = _closed_capability()
    payload = valid.model_dump(mode="python")
    payload["read_only"] = False
    forged = ObservationCapability.model_construct(**payload)

    with pytest.raises(ValueError):
        _registration(capability=forged)

    valid.allowed_targets[0].scope["access_token"] = "must-not-survive"
    with pytest.raises(ValueError):
        _registration(capability=valid)


@pytest.mark.parametrize(
    "mutate",
    (
        lambda schema: schema["properties"]["order_id"].update(default="order-7"),
        lambda schema: schema.update(patternProperties={"^x": {"type": "string"}}),
        lambda schema: schema["properties"]["order_id"].update(
            oneOf=[{"type": "string"}, {"type": "null"}]
        ),
        lambda schema: schema["properties"].update(
            nested={
                "type": "object",
                "properties": {},
                "required": [],
                "additionalProperties": False,
            }
        ),
        lambda schema: schema["properties"]["order_id"].pop("maxLength"),
    ),
)
def test_registration_rejects_schemas_outside_the_closed_profile(
    mutate: object,
) -> None:
    schema = deepcopy(_closed_capability().argument_schema)
    mutate(schema)  # type: ignore[operator]
    capability = _closed_capability(argument_schema=schema)

    with pytest.raises(ValueError, match="outside the closed profile"):
        _registration(capability=capability)


@pytest.mark.parametrize("unsafe_name", ("host", "x_api_key"))
def test_transport_and_credential_aliases_cannot_enter_capability_schemas(
    unsafe_name: str,
) -> None:
    schema = {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "type": "object",
        "properties": {
            unsafe_name: {"type": "string", "minLength": 1, "maxLength": 128}
        },
        "required": [unsafe_name],
        "additionalProperties": False,
    }

    with pytest.raises(ValidationError):
        _closed_capability(argument_schema=schema)


def test_closed_profile_accepts_bounded_scalar_and_array_leaves() -> None:
    schema = {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "type": "object",
        "properties": {
            "label": {"type": "string", "minLength": 1, "maxLength": 32},
            "attempt": {"type": "integer", "minimum": 0, "maximum": 10},
            "ratio": {"type": "number", "minimum": 0.0, "maximum": 1.0},
            "active": {"type": "boolean"},
            "marker": {"type": "null"},
            "tags": {
                "type": "array",
                "items": {"type": "string", "maxLength": 16},
                "minItems": 0,
                "maxItems": 4,
                "uniqueItems": True,
            },
        },
        "required": ["label"],
        "additionalProperties": False,
    }

    registration = _registration(
        capability=_closed_capability(argument_schema=schema),
    )

    assert registration.capability.argument_schema == schema


def test_required_fields_must_be_unique_declared_properties() -> None:
    schema = deepcopy(_closed_capability().argument_schema)
    schema["required"] = ["undeclared"]
    capability = _closed_capability(argument_schema=schema)

    with pytest.raises(ValueError, match="outside the closed profile"):
        _registration(capability=capability)

    schema["required"] = ["order_id", "order_id"]
    with pytest.raises(ValidationError, match="argument schema is invalid"):
        _closed_capability(argument_schema=schema)


def test_bound_probe_and_observation_are_strict_secret_free_models() -> None:
    probe = BoundProbe(
        investigation_id="investigation-7",
        operation_id="operation-7",
        capability_name="gcs-object-readback",
        capability_version="1.0.0",
        target=make_target(),
        relevant_effect_ids=("business-record",),
        arguments={"order_id": "order-7"},
        timeout_ms=2_000,
        result_byte_ceiling=65_536,
    )

    assert probe.target.resource["object_name"] == "receipts/order-7.json"
    assert ProbeObservation(observed_at=NOW, payload={"exists": True}).payload == {
        "exists": True
    }

    duplicate_effects = probe.model_dump(mode="python")
    duplicate_effects["relevant_effect_ids"] = (
        "business-record",
        "business-record",
    )
    with pytest.raises(ValidationError, match="unique"):
        BoundProbe(**duplicate_effects)
    with pytest.raises(ValidationError, match="secret-bearing"):
        ProbeObservation(
            observed_at=NOW,
            payload={"result": {"access_token": "not-stored"}},
        )
    with pytest.raises(ValidationError, match="secret-bearing"):
        ProbeObservation(
            observed_at=NOW,
            payload={"provider_detail": "Bearer private-marker-value"},
        )
    with pytest.raises(ValidationError, match="secret-bearing"):
        BoundProbe(
            investigation_id="investigation-7",
            operation_id="operation-7",
            capability_name="gcs-object-readback",
            capability_version="1.0.0",
            target=make_target(),
            relevant_effect_ids=("business-record",),
            arguments={"provider_detail": "Bearer private-marker-value"},
            timeout_ms=2_000,
            result_byte_ceiling=65_536,
        )


@pytest.mark.parametrize("sensitive_key", ("apikey", "accesskey", "privatekey"))
def test_separator_free_credential_aliases_are_rejected(
    sensitive_key: str,
) -> None:
    with pytest.raises(ValidationError, match="secret-bearing"):
        ProbeObservation(
            observed_at=NOW,
            payload={sensitive_key: "not-stored"},
        )


def test_unavailable_exception_exposes_only_a_stable_sanitized_code() -> None:
    error = CapabilityUnavailable()

    assert error.code == "capability_unavailable"
    assert str(error) == "capability is unavailable"


def test_module_has_no_provider_or_application_framework_imports() -> None:
    source = Path(capabilities_module.__file__).read_text(encoding="utf-8")
    tree = ast.parse(source)
    imported_roots: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported_roots.update(
                alias.name.split(".", maxsplit=1)[0] for alias in node.names
            )
        elif isinstance(node, ast.ImportFrom) and node.module is not None:
            imported_roots.add(node.module.split(".", maxsplit=1)[0])

    assert imported_roots.isdisjoint(
        {"fastapi", "google", "googleapiclient", "starlette", "textual", "typer"}
    )
