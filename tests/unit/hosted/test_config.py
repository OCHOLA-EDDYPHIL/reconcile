"""Focused tests for the closed hosted configuration boundary."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping

import pytest

from reconcile.hosted.config import Component, HostedConfigError, load_config

pytestmark = pytest.mark.unit

_PROJECT = "reconcile-dev-260813-14fa6d"
_API_CALLER = f"rec-p5-apply@{_PROJECT}.iam.gserviceaccount.com"
_INTERNAL_CALLER = f"rec-p5-api@{_PROJECT}.iam.gserviceaccount.com"
_SANDBOX_READ_CALLER = f"rec-p5-controller@{_PROJECT}.iam.gserviceaccount.com"
_SANDBOX_MUTATION_CALLER = f"rec-p5-fault@{_PROJECT}.iam.gserviceaccount.com"
_PROMPT_SHA256 = "a18ac5bbd22570562acc6dfbc49437a82f0db6a265a4de737c1371b6ef2ca2d3"


def _canary_baseline() -> str:
    identity = {
        "image_digest": f"sha256:{'b' * 64}",
        "infrastructure_revision": "c" * 64,
        "project_id": _PROJECT,
        "region": "us-central1",
        "request_timeout_seconds": 60,
        "semantic_config_sha256": "d" * 64,
        "service_account_email": (f"rec-p5-canary@{_PROJECT}.iam.gserviceaccount.com"),
        "source_revision": "a" * 40,
    }
    encoded = json.dumps(identity, separators=(",", ":"), sort_keys=True).encode()
    return f"reconcile-p5-canary-b-{hashlib.sha256(encoded).hexdigest()[:16]}"


def _audience(component: Component) -> str:
    return f"https://reconcile.invalid/phase5/{_PROJECT}/{component.value}"


def _common(component: Component) -> dict[str, str]:
    return {
        "RECONCILE_COMPONENT": component.value,
        "PORT": "8080",
        "GOOGLE_CLOUD_PROJECT": _PROJECT,
        "RECONCILE_AUTH_AUDIENCE": _audience(component),
        "RECONCILE_SOURCE_REVISION": "a" * 40,
        "RECONCILE_IMAGE_DIGEST": f"sha256:{'b' * 64}",
        "RECONCILE_INFRA_REVISION": "c" * 64,
        "RECONCILE_SEMANTIC_CONFIG_SHA256": "d" * 64,
    }


def _environment(component: Component) -> dict[str, str]:
    environment = _common(component)
    if component is Component.API:
        environment.update(
            {
                "RECONCILE_ALLOWED_CALLER_EMAILS": _API_CALLER,
                "RECONCILE_RUNTIME_DATABASE": "reconcile-p5-runtime",
                "RECONCILE_TARGET_BUCKET": f"{_PROJECT}-p5-target",
                "RECONCILE_CONTROLLER_URL": "https://controller.example.run.app",
                "RECONCILE_CONTROLLER_AUDIENCE": _audience(Component.CONTROLLER),
                "RECONCILE_FAULT_PROXY_URL": ("https://fault-proxy.example.run.app"),
                "RECONCILE_FAULT_PROXY_AUDIENCE": _audience(Component.FAULT_PROXY),
            }
        )
    elif component is Component.CONTROLLER:
        environment.update(
            {
                "RECONCILE_ALLOWED_CALLER_EMAILS": _INTERNAL_CALLER,
                "RECONCILE_RUNTIME_DATABASE": "reconcile-p5-runtime",
                "RECONCILE_TARGET_DATABASE": "reconcile-p5-target",
                "RECONCILE_TARGET_BUCKET": f"{_PROJECT}-p5-target",
                "RECONCILE_SANDBOX_URL": "https://sandbox.example.run.app",
                "RECONCILE_SANDBOX_AUDIENCE": _audience(Component.SANDBOX),
                "RECONCILE_VERTEX_LOCATION": "us",
                "RECONCILE_VERTEX_MODEL": "gemini-3.5-flash",
                "RECONCILE_VERTEX_PROMPT_VERSION": "adaptive-planner-v3",
                "RECONCILE_VERTEX_PROMPT_SHA256": _PROMPT_SHA256,
                "RECONCILE_VERTEX_MAX_COUNT_TOKENS_ATTEMPTS": "1",
                "RECONCILE_VERTEX_MAX_GENERATION_ATTEMPTS": "1",
                "RECONCILE_VERTEX_MAX_INPUT_TOKENS": "12000",
                "RECONCILE_VERTEX_MAX_OUTPUT_TOKENS": "1024",
                "RECONCILE_VERTEX_THINKING_LEVEL": "MINIMAL",
            }
        )
    elif component is Component.FAULT_PROXY:
        environment.update(
            {
                "RECONCILE_ALLOWED_CALLER_EMAILS": _INTERNAL_CALLER,
                "RECONCILE_RUNTIME_DATABASE": "reconcile-p5-runtime",
                "RECONCILE_TARGET_DATABASE": "reconcile-p5-target",
                "RECONCILE_TARGET_BUCKET": f"{_PROJECT}-p5-target",
                "RECONCILE_SANDBOX_URL": "https://sandbox.example.run.app",
                "RECONCILE_SANDBOX_AUDIENCE": _audience(Component.SANDBOX),
                "RECONCILE_CANARY_LOCATION": "us-central1",
                "RECONCILE_CANARY_SERVICE": "reconcile-p5-canary",
                "RECONCILE_CANARY_BASELINE_REVISION": (_canary_baseline()),
                "RECONCILE_CANARY_AUDIENCE": (
                    f"https://reconcile.invalid/phase5/{_PROJECT}/canary"
                ),
            }
        )
    else:
        environment.update(
            {
                "RECONCILE_RUNTIME_DATABASE": "reconcile-p5-runtime",
                "RECONCILE_TARGET_DATABASE": "reconcile-p5-sandbox",
                "RECONCILE_SANDBOX_READ_CALLER_EMAIL": _SANDBOX_READ_CALLER,
                "RECONCILE_SANDBOX_MUTATION_CALLER_EMAIL": (_SANDBOX_MUTATION_CALLER),
            }
        )
    return environment


def test_component_values_are_exact() -> None:
    assert tuple(Component) == (
        Component.API,
        Component.CONTROLLER,
        Component.FAULT_PROXY,
        Component.SANDBOX,
    )
    assert tuple(item.value for item in Component) == (
        "api",
        "controller",
        "fault-proxy",
        "sandbox",
    )


@pytest.mark.parametrize("component", tuple(Component))
def test_every_component_loads_only_its_exact_fields(component: Component) -> None:
    config = load_config(_environment(component))

    assert config.component is component
    assert config.port == 8080
    assert config.project_id == _PROJECT
    assert config.auth_audience == _audience(component)
    assert config.source_revision == "a" * 40
    assert config.image_digest == f"sha256:{'b' * 64}"
    assert config.infra_revision == "c" * 64
    assert config.semantic_config_sha256 == "d" * 64

    if component is Component.API:
        assert config.allowed_caller_emails == (_API_CALLER,)
        assert config.runtime_database == "reconcile-p5-runtime"
        assert config.target_bucket == f"{_PROJECT}-p5-target"
        assert config.controller_url == "https://controller.example.run.app"
        assert config.controller_audience == _audience(Component.CONTROLLER)
        assert config.fault_proxy_url == "https://fault-proxy.example.run.app"
        assert config.target_database is None
    elif component is Component.CONTROLLER:
        assert config.allowed_caller_emails == (_INTERNAL_CALLER,)
        assert config.sandbox_url == "https://sandbox.example.run.app"
        assert config.vertex_prompt_version == "adaptive-planner-v3"
        assert config.vertex_prompt_sha256 == _PROMPT_SHA256
        assert config.vertex_max_count_tokens_attempts == 1
        assert config.vertex_max_generation_attempts == 1
        assert config.vertex_thinking_level == "MINIMAL"
        assert config.controller_url is None
    elif component is Component.FAULT_PROXY:
        assert config.allowed_caller_emails == (_INTERNAL_CALLER,)
        assert config.target_bucket == f"{_PROJECT}-p5-target"
        assert config.runtime_database == "reconcile-p5-runtime"
        assert config.canary_location == "us-central1"
        assert config.canary_service == "reconcile-p5-canary"
        assert config.canary_baseline_revision == _canary_baseline()
        assert config.canary_audience == (
            f"https://reconcile.invalid/phase5/{_PROJECT}/canary"
        )
    else:
        assert config.allowed_caller_emails == (
            _SANDBOX_READ_CALLER,
            _SANDBOX_MUTATION_CALLER,
        )
        assert config.sandbox_read_caller_email == _SANDBOX_READ_CALLER
        assert config.sandbox_mutation_caller_email == _SANDBOX_MUTATION_CALLER
        assert config.runtime_database == "reconcile-p5-runtime"
        assert config.target_database == "reconcile-p5-sandbox"
        assert config.target_bucket is None


@pytest.mark.parametrize("component", tuple(Component))
def test_every_declared_field_is_required_for_its_component(
    component: Component,
) -> None:
    environment = _environment(component)

    for name in tuple(environment):
        incomplete = environment.copy()
        incomplete.pop(name)
        with pytest.raises(HostedConfigError):
            load_config(incomplete)


@pytest.mark.parametrize(
    ("component", "irrelevant_name", "irrelevant_value"),
    (
        (Component.API, "RECONCILE_SANDBOX_URL", "https://sandbox.example.run.app"),
        (
            Component.CONTROLLER,
            "RECONCILE_CONTROLLER_URL",
            "https://controller.example.run.app",
        ),
        (
            Component.FAULT_PROXY,
            "RECONCILE_CONTROLLER_URL",
            "https://controller.example.run.app",
        ),
        (Component.SANDBOX, "RECONCILE_ALLOWED_CALLER_EMAILS", _INTERNAL_CALLER),
    ),
)
def test_component_rejects_known_but_irrelevant_fields(
    component: Component,
    irrelevant_name: str,
    irrelevant_value: str,
) -> None:
    environment = _environment(component)
    environment[irrelevant_name] = irrelevant_value

    with pytest.raises(HostedConfigError, match="selected component"):
        load_config(environment)


@pytest.mark.parametrize("port", ("", "0", "65536", "08080", "+8080", "8080 "))
def test_port_is_canonical_and_bounded(port: str) -> None:
    environment = _environment(Component.API)
    environment["PORT"] = port

    with pytest.raises(HostedConfigError, match="is invalid"):
        load_config(environment)


@pytest.mark.parametrize(
    ("name", "value"),
    (
        ("GOOGLE_CLOUD_PROJECT", "another-project"),
        ("RECONCILE_ALLOWED_CALLER_EMAILS", "other@example.com"),
        ("RECONCILE_RUNTIME_DATABASE", "other-runtime"),
        ("RECONCILE_TARGET_DATABASE", "other-target"),
        ("RECONCILE_TARGET_BUCKET", "other-target-bucket"),
        ("RECONCILE_VERTEX_LOCATION", "us-central1"),
        ("RECONCILE_VERTEX_MODEL", "another-model"),
        ("RECONCILE_VERTEX_PROMPT_VERSION", "adaptive-planner-v4"),
        ("RECONCILE_VERTEX_PROMPT_SHA256", "0" * 64),
        ("RECONCILE_VERTEX_MAX_COUNT_TOKENS_ATTEMPTS", "2"),
        ("RECONCILE_VERTEX_MAX_GENERATION_ATTEMPTS", "2"),
        ("RECONCILE_VERTEX_MAX_INPUT_TOKENS", "12001"),
        ("RECONCILE_VERTEX_MAX_OUTPUT_TOKENS", "1025"),
        ("RECONCILE_VERTEX_THINKING_LEVEL", "LOW"),
    ),
)
def test_controller_rejects_values_outside_the_frozen_boundary(
    name: str,
    value: str,
) -> None:
    environment = _environment(Component.CONTROLLER)
    environment[name] = value

    with pytest.raises(HostedConfigError, match="is invalid"):
        load_config(environment)


@pytest.mark.parametrize(
    ("component", "database"),
    (
        (Component.CONTROLLER, "reconcile-p5-sandbox"),
        (Component.FAULT_PROXY, "reconcile-p5-sandbox"),
        (Component.SANDBOX, "reconcile-p5-target"),
    ),
)
def test_component_database_boundaries_cannot_be_crossed(
    component: Component,
    database: str,
) -> None:
    environment = _environment(component)
    environment["RECONCILE_TARGET_DATABASE"] = database

    with pytest.raises(HostedConfigError, match="is invalid"):
        load_config(environment)


@pytest.mark.parametrize(
    "value",
    (
        "http://api.example.run.app",
        "https://user@api.example.run.app",
        "https://api.example.run.app/path",
        "https://api.example.run.app?token=value",
        "https://api.example.run.app:443",
        "https://api.example.run.app/",
        "https://reconcile.invalid/phase5/reconcile-dev-260813-14fa6d/api/",
    ),
)
def test_stable_audience_is_the_exact_frozen_value(value: str) -> None:
    environment = _environment(Component.API)
    environment["RECONCILE_AUTH_AUDIENCE"] = value

    with pytest.raises(HostedConfigError, match="is invalid"):
        load_config(environment)


@pytest.mark.parametrize(
    "value",
    (
        "http://controller.example.run.app",
        "https://user@controller.example.run.app",
        "https://controller.example.run.app/path",
        "https://controller.example.run.app?value=1",
        "https://controller.example.run.app:443",
        "https://CONTROLLER.example.run.app",
        "https://controller.example.run.app/",
    ),
)
def test_destination_url_is_a_canonical_https_origin(value: str) -> None:
    environment = _environment(Component.API)
    environment["RECONCILE_CONTROLLER_URL"] = value

    with pytest.raises(HostedConfigError, match="is invalid"):
        load_config(environment)


@pytest.mark.parametrize(
    ("name", "value"),
    (
        ("RECONCILE_SANDBOX_READ_CALLER_EMAIL", _SANDBOX_MUTATION_CALLER),
        ("RECONCILE_SANDBOX_MUTATION_CALLER_EMAIL", _SANDBOX_READ_CALLER),
        ("RECONCILE_SANDBOX_READ_CALLER_EMAIL", _SANDBOX_READ_CALLER.upper()),
    ),
)
def test_sandbox_route_callers_are_exact_and_distinct(name: str, value: str) -> None:
    environment = _environment(Component.SANDBOX)
    environment[name] = value

    with pytest.raises(HostedConfigError, match="is invalid"):
        load_config(environment)


@pytest.mark.parametrize(
    ("name", "value"),
    (
        ("RECONCILE_SOURCE_REVISION", "a" * 39),
        ("RECONCILE_IMAGE_DIGEST", "b" * 64),
        ("RECONCILE_INFRA_REVISION", "C" * 64),
        ("RECONCILE_SEMANTIC_CONFIG_SHA256", "d" * 63),
    ),
)
def test_candidate_identity_is_complete_and_canonical(name: str, value: str) -> None:
    environment = _environment(Component.FAULT_PROXY)
    environment[name] = value

    with pytest.raises(HostedConfigError, match="is invalid"):
        load_config(environment)


def test_unknown_application_environment_and_values_are_not_disclosed() -> None:
    marker = "Bearer private-marker-123456"
    environment = _environment(Component.API)
    environment["RECONCILE_PRIVATE_TOKEN"] = marker

    with pytest.raises(HostedConfigError) as captured:
        load_config(environment)

    assert captured.value.code == "contains unsupported variables"
    assert marker not in str(captured.value)
    assert marker not in repr(captured.value)


def test_invalid_selected_value_is_not_disclosed() -> None:
    marker = "Bearer private-marker-123456"
    environment = _environment(Component.API)
    environment["RECONCILE_COMPONENT"] = marker

    with pytest.raises(HostedConfigError) as captured:
        load_config(environment)

    current: BaseException | None = captured.value
    while current is not None:
        assert marker not in str(current)
        assert marker not in repr(current)
        current = current.__cause__ or current.__context__


def test_ambient_non_application_variables_are_outside_the_config_namespace() -> None:
    environment: Mapping[str, str] = {
        **_environment(Component.API),
        "PATH": "/not/part/of/hosted/config",
        "K_SERVICE": "platform-owned",
    }

    assert load_config(environment).component is Component.API
