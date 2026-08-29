"""Strict environment configuration for hosted RECONCILE components."""

from __future__ import annotations

import hashlib
import json
import os
import re
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from urllib.parse import urlsplit


class Component(StrEnum):
    API = "api"
    CONTROLLER = "controller"
    FAULT_PROXY = "fault-proxy"
    SANDBOX = "sandbox"


class HostedConfigError(ValueError):
    """A configuration failure that never includes environment values."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(f"hosted configuration {code}")


@dataclass(frozen=True, slots=True)
class HostedConfig:
    component: Component
    port: int
    project_id: str
    auth_audience: str
    allowed_caller_emails: tuple[str, ...]
    source_revision: str
    image_digest: str
    infra_revision: str
    semantic_config_sha256: str
    runtime_database: str | None = None
    target_database: str | None = None
    target_bucket: str | None = None
    controller_url: str | None = None
    controller_audience: str | None = None
    fault_proxy_url: str | None = None
    fault_proxy_audience: str | None = None
    sandbox_url: str | None = None
    sandbox_audience: str | None = None
    sandbox_read_caller_email: str | None = None
    sandbox_mutation_caller_email: str | None = None
    canary_location: str | None = None
    canary_service: str | None = None
    canary_baseline_revision: str | None = None
    canary_audience: str | None = None
    recovery_release_id: str | None = None
    recovery_payload_sha256: str | None = None
    recovery_definition_created_at: datetime | None = None
    recovery_execution_timeout_seconds: int | None = None
    recovery_action_caller_email: str | None = None
    vertex_location: str | None = None
    vertex_model: str | None = None
    vertex_prompt_version: str | None = None
    vertex_prompt_sha256: str | None = None
    vertex_max_count_tokens_attempts: int | None = None
    vertex_max_generation_attempts: int | None = None
    vertex_max_input_tokens: int | None = None
    vertex_max_output_tokens: int | None = None
    vertex_thinking_level: str | None = None


_COMPONENT = "RECONCILE_COMPONENT"
_PORT = "PORT"
_PROJECT_ID = "GOOGLE_CLOUD_PROJECT"
_AUTH_AUDIENCE = "RECONCILE_AUTH_AUDIENCE"
_ALLOWED_CALLERS = "RECONCILE_ALLOWED_CALLER_EMAILS"
_SOURCE_REVISION = "RECONCILE_SOURCE_REVISION"
_IMAGE_DIGEST = "RECONCILE_IMAGE_DIGEST"
_INFRA_REVISION = "RECONCILE_INFRA_REVISION"
_SEMANTIC_CONFIG_SHA256 = "RECONCILE_SEMANTIC_CONFIG_SHA256"
_RUNTIME_DATABASE = "RECONCILE_RUNTIME_DATABASE"
_TARGET_DATABASE = "RECONCILE_TARGET_DATABASE"
_TARGET_BUCKET = "RECONCILE_TARGET_BUCKET"
_CONTROLLER_URL = "RECONCILE_CONTROLLER_URL"
_CONTROLLER_AUDIENCE = "RECONCILE_CONTROLLER_AUDIENCE"
_FAULT_PROXY_URL = "RECONCILE_FAULT_PROXY_URL"
_FAULT_PROXY_AUDIENCE = "RECONCILE_FAULT_PROXY_AUDIENCE"
_SANDBOX_URL = "RECONCILE_SANDBOX_URL"
_SANDBOX_AUDIENCE = "RECONCILE_SANDBOX_AUDIENCE"
_SANDBOX_READ_CALLER = "RECONCILE_SANDBOX_READ_CALLER_EMAIL"
_SANDBOX_MUTATION_CALLER = "RECONCILE_SANDBOX_MUTATION_CALLER_EMAIL"
_CANARY_LOCATION = "RECONCILE_CANARY_LOCATION"
_CANARY_SERVICE = "RECONCILE_CANARY_SERVICE"
_CANARY_BASELINE_REVISION = "RECONCILE_CANARY_BASELINE_REVISION"
_CANARY_AUDIENCE = "RECONCILE_CANARY_AUDIENCE"
_RECOVERY_RELEASE_ID = "RECONCILE_RECOVERY_RELEASE_ID"
_RECOVERY_PAYLOAD_SHA256 = "RECONCILE_RECOVERY_PAYLOAD_SHA256"
_RECOVERY_DEFINITION_CREATED_AT = "RECONCILE_RECOVERY_DEFINITION_CREATED_AT"
_RECOVERY_EXECUTION_TIMEOUT_SECONDS = "RECONCILE_RECOVERY_EXECUTION_TIMEOUT_SECONDS"
_RECOVERY_ACTION_CALLER = "RECONCILE_RECOVERY_ACTION_CALLER_EMAIL"
_VERTEX_LOCATION = "RECONCILE_VERTEX_LOCATION"
_VERTEX_MODEL = "RECONCILE_VERTEX_MODEL"
_VERTEX_PROMPT_VERSION = "RECONCILE_VERTEX_PROMPT_VERSION"
_VERTEX_PROMPT_SHA256 = "RECONCILE_VERTEX_PROMPT_SHA256"
_VERTEX_MAX_COUNT_TOKENS_ATTEMPTS = "RECONCILE_VERTEX_MAX_COUNT_TOKENS_ATTEMPTS"
_VERTEX_MAX_GENERATION_ATTEMPTS = "RECONCILE_VERTEX_MAX_GENERATION_ATTEMPTS"
_VERTEX_MAX_INPUT_TOKENS = "RECONCILE_VERTEX_MAX_INPUT_TOKENS"
_VERTEX_MAX_OUTPUT_TOKENS = "RECONCILE_VERTEX_MAX_OUTPUT_TOKENS"
_VERTEX_THINKING_LEVEL = "RECONCILE_VERTEX_THINKING_LEVEL"

_COMMON_NAMES = frozenset(
    {
        _COMPONENT,
        _PORT,
        _PROJECT_ID,
        _AUTH_AUDIENCE,
        _SOURCE_REVISION,
        _IMAGE_DIGEST,
        _INFRA_REVISION,
        _SEMANTIC_CONFIG_SHA256,
    }
)
_COMPONENT_NAMES = {
    Component.API: frozenset(
        {
            _ALLOWED_CALLERS,
            _RUNTIME_DATABASE,
            _TARGET_BUCKET,
            _CONTROLLER_URL,
            _CONTROLLER_AUDIENCE,
            _FAULT_PROXY_URL,
            _FAULT_PROXY_AUDIENCE,
        }
    ),
    Component.CONTROLLER: frozenset(
        {
            _ALLOWED_CALLERS,
            _RUNTIME_DATABASE,
            _TARGET_DATABASE,
            _TARGET_BUCKET,
            _FAULT_PROXY_URL,
            _FAULT_PROXY_AUDIENCE,
            _SANDBOX_URL,
            _SANDBOX_AUDIENCE,
            _CANARY_LOCATION,
            _CANARY_SERVICE,
            _CANARY_BASELINE_REVISION,
            _CANARY_AUDIENCE,
            _RECOVERY_RELEASE_ID,
            _RECOVERY_PAYLOAD_SHA256,
            _RECOVERY_DEFINITION_CREATED_AT,
            _RECOVERY_EXECUTION_TIMEOUT_SECONDS,
            _VERTEX_LOCATION,
            _VERTEX_MODEL,
            _VERTEX_PROMPT_VERSION,
            _VERTEX_PROMPT_SHA256,
            _VERTEX_MAX_COUNT_TOKENS_ATTEMPTS,
            _VERTEX_MAX_GENERATION_ATTEMPTS,
            _VERTEX_MAX_INPUT_TOKENS,
            _VERTEX_MAX_OUTPUT_TOKENS,
            _VERTEX_THINKING_LEVEL,
        }
    ),
    Component.FAULT_PROXY: frozenset(
        {
            _ALLOWED_CALLERS,
            _RUNTIME_DATABASE,
            _TARGET_DATABASE,
            _TARGET_BUCKET,
            _SANDBOX_URL,
            _SANDBOX_AUDIENCE,
            _CANARY_LOCATION,
            _CANARY_SERVICE,
            _CANARY_BASELINE_REVISION,
            _CANARY_AUDIENCE,
            _RECOVERY_ACTION_CALLER,
        }
    ),
    Component.SANDBOX: frozenset(
        {
            _RUNTIME_DATABASE,
            _TARGET_DATABASE,
            _SANDBOX_READ_CALLER,
            _SANDBOX_MUTATION_CALLER,
        }
    ),
}
SUPPORTED_ENVIRONMENT_VARIABLES = frozenset().union(
    _COMMON_NAMES,
    *_COMPONENT_NAMES.values(),
)

_EMAIL_PATTERN = re.compile(
    r"[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]{1,64}"
    r"@[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?"
    r"(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)+"
)
_HOST_PATTERN = re.compile(
    r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?"
    r"(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+"
)
_SOURCE_REVISION_PATTERN = re.compile(r"[0-9a-f]{40}")
_IMAGE_DIGEST_PATTERN = re.compile(r"sha256:[0-9a-f]{64}")
_SHA256_PATTERN = re.compile(r"[0-9a-f]{64}")
_UTC_TIMESTAMP_PATTERN = re.compile(
    r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}"
    r"(?:\.[0-9]{6})?Z"
)
_APPROVED_PROJECT_ID = "example-project-id"
_APPROVED_RUNTIME_DATABASE = "reconcile-p5-runtime"
_APPROVED_SANDBOX_DATABASE = "reconcile-p5-sandbox"
_APPROVED_TARGET_DATABASE = "reconcile-p5-target"
_APPROVED_TARGET_BUCKET = "example-project-id-p5-target"
_APPROVED_VERTEX_PROMPT_VERSION = "adaptive-planner-v3"
_APPROVED_VERTEX_PROMPT_SHA256 = (
    "a18ac5bbd22570562acc6dfbc49437a82f0db6a265a4de737c1371b6ef2ca2d3"
)
_APPROVED_AUDIENCES = {
    component: (
        f"https://reconcile.invalid/phase5/{_APPROVED_PROJECT_ID}/{component.value}"
    )
    for component in Component
}
_APPROVED_CALLERS = {
    Component.API: ("rec-p5-apply@example-project-id.iam.gserviceaccount.com"),
    Component.CONTROLLER: ("rec-p5-api@example-project-id.iam.gserviceaccount.com"),
    Component.FAULT_PROXY: ("rec-p5-api@example-project-id.iam.gserviceaccount.com"),
}
_APPROVED_SANDBOX_READ_CALLER = (
    "rec-p5-controller@example-project-id.iam.gserviceaccount.com"
)
_APPROVED_SANDBOX_MUTATION_CALLER = (
    "rec-p5-fault@example-project-id.iam.gserviceaccount.com"
)
_APPROVED_CANARY_AUDIENCE = (
    f"https://reconcile.invalid/phase5/{_APPROVED_PROJECT_ID}/canary"
)
_APPROVED_CANARY_SERVICE_ACCOUNT = (
    "rec-p5-canary@example-project-id.iam.gserviceaccount.com"
)


def _expected_canary_baseline_revision(
    *,
    project_id: str,
    image_digest: str,
    infrastructure_revision: str,
    semantic_config_sha256: str,
    source_revision: str,
) -> str:
    identity = {
        "image_digest": image_digest,
        "infrastructure_revision": infrastructure_revision,
        "project_id": project_id,
        "region": "us-central1",
        "request_timeout_seconds": 60,
        "semantic_config_sha256": semantic_config_sha256,
        "service_account_email": _APPROVED_CANARY_SERVICE_ACCOUNT,
        "source_revision": source_revision,
    }
    encoded = json.dumps(
        identity,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    return f"reconcile-p5-canary-b-{hashlib.sha256(encoded).hexdigest()[:16]}"


def _expected_recovery_payload_sha256(
    *,
    project_id: str,
    image_digest: str,
    infrastructure_revision: str,
    semantic_config_sha256: str,
    source_revision: str,
) -> str:
    identity = {
        "configured_model": "gemini-3.5-flash",
        "image_digest": image_digest,
        "infrastructure_revision": infrastructure_revision,
        "maximum_count_tokens_attempts": 1,
        "maximum_generation_attempts": 1,
        "maximum_input_tokens": 12_000,
        "maximum_output_tokens": 4_096,
        "project_id": project_id,
        "prompt_sha256": _APPROVED_VERTEX_PROMPT_SHA256,
        "prompt_version": _APPROVED_VERTEX_PROMPT_VERSION,
        "schema_version": "reconcile/hosted-candidate-identity/v1",
        "semantic_config_sha256": semantic_config_sha256,
        "source_revision": source_revision,
        "thinking_level": "MINIMAL",
        "vertex_location": "us",
    }
    encoded = json.dumps(
        identity,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _managed_environment(source: Mapping[str, str]) -> dict[str, str]:
    managed: dict[str, str] = {}
    try:
        for name, value in source.items():
            if not isinstance(name, str) or not isinstance(value, str):
                raise HostedConfigError("is invalid")
            if name in {_PORT, _PROJECT_ID} or name.startswith("RECONCILE_"):
                managed[name] = value
    except HostedConfigError:
        raise
    except Exception as error:
        raise HostedConfigError("could not be read") from error
    return managed


def _required(environment: Mapping[str, str], name: str) -> str:
    value = environment.get(name)
    if value is None:
        raise HostedConfigError("is incomplete")
    if not value or len(value) > 2048 or value != value.strip():
        raise HostedConfigError("is invalid")
    return value


def _integer(
    environment: Mapping[str, str],
    name: str,
    *,
    minimum: int,
    maximum: int,
) -> int:
    value = _required(environment, name)
    if not value.isascii() or not value.isdecimal() or value.startswith("0"):
        raise HostedConfigError("is invalid")
    parsed = int(value)
    if not minimum <= parsed <= maximum:
        raise HostedConfigError("is invalid")
    return parsed


def _pattern(
    environment: Mapping[str, str],
    name: str,
    pattern: re.Pattern[str],
) -> str:
    value = _required(environment, name)
    if pattern.fullmatch(value) is None:
        raise HostedConfigError("is invalid")
    return value


def _email(environment: Mapping[str, str], name: str) -> str:
    value = _pattern(environment, name, _EMAIL_PATTERN)
    if len(value) > 254 or value != value.lower():
        raise HostedConfigError("is invalid")
    return value


def _single_allowed_caller(
    environment: Mapping[str, str],
    component: Component,
) -> tuple[str, ...]:
    value = _required(environment, _ALLOWED_CALLERS)
    if "," in value or _EMAIL_PATTERN.fullmatch(value) is None or len(value) > 254:
        raise HostedConfigError("is invalid")
    if value != _APPROVED_CALLERS[component]:
        raise HostedConfigError("is invalid")
    return (value,)


def _exact(environment: Mapping[str, str], name: str, expected: str) -> str:
    value = _required(environment, name)
    if value != expected:
        raise HostedConfigError("is invalid")
    return value


def _audience(
    environment: Mapping[str, str],
    name: str,
    component: Component,
) -> str:
    return _exact(environment, name, _APPROVED_AUDIENCES[component])


def _https_origin(environment: Mapping[str, str], name: str) -> str:
    value = _required(environment, name)
    try:
        parsed = urlsplit(value)
        port = parsed.port
    except ValueError as error:
        raise HostedConfigError("is invalid") from error
    if (
        parsed.scheme != "https"
        or parsed.username is not None
        or parsed.password is not None
        or parsed.hostname is None
        or parsed.hostname != parsed.hostname.lower()
        or _HOST_PATTERN.fullmatch(parsed.hostname) is None
        or port is not None
        or parsed.path
        or parsed.query
        or parsed.fragment
        or value != f"https://{parsed.hostname}"
    ):
        raise HostedConfigError("is invalid")
    return value


def _utc_timestamp(environment: Mapping[str, str], name: str) -> datetime:
    value = _pattern(environment, name, _UTC_TIMESTAMP_PATTERN)
    try:
        parsed = datetime.fromisoformat(f"{value[:-1]}+00:00").astimezone(UTC)
    except ValueError as error:
        raise HostedConfigError("is invalid") from error
    timespec = "microseconds" if parsed.microsecond else "seconds"
    canonical = parsed.isoformat(timespec=timespec).replace("+00:00", "Z")
    if value != canonical:
        raise HostedConfigError("is invalid")
    return parsed


def _load_config(environment: Mapping[str, str]) -> HostedConfig:
    managed = _managed_environment(environment)
    try:
        component = Component(_required(managed, _COMPONENT))
    except ValueError as error:
        raise HostedConfigError("is invalid") from error

    expected_names = _COMMON_NAMES | _COMPONENT_NAMES[component]
    if set(managed) != expected_names:
        if set(managed) - SUPPORTED_ENVIRONMENT_VARIABLES:
            raise HostedConfigError("contains unsupported variables")
        raise HostedConfigError("does not match the selected component")

    if component is Component.SANDBOX:
        sandbox_read_caller = _email(managed, _SANDBOX_READ_CALLER)
        sandbox_mutation_caller = _email(managed, _SANDBOX_MUTATION_CALLER)
        if sandbox_read_caller == sandbox_mutation_caller:
            raise HostedConfigError("is invalid")
        if (
            sandbox_read_caller != _APPROVED_SANDBOX_READ_CALLER
            or sandbox_mutation_caller != _APPROVED_SANDBOX_MUTATION_CALLER
        ):
            raise HostedConfigError("is invalid")
        allowed_callers = (sandbox_read_caller, sandbox_mutation_caller)
    else:
        sandbox_read_caller = None
        sandbox_mutation_caller = None
        allowed_callers = _single_allowed_caller(managed, component)

    common: dict[str, object] = {
        "component": component,
        "port": _integer(managed, _PORT, minimum=1, maximum=65535),
        "project_id": _exact(managed, _PROJECT_ID, _APPROVED_PROJECT_ID),
        "auth_audience": _audience(managed, _AUTH_AUDIENCE, component),
        "allowed_caller_emails": allowed_callers,
        "source_revision": _pattern(
            managed, _SOURCE_REVISION, _SOURCE_REVISION_PATTERN
        ),
        "image_digest": _pattern(managed, _IMAGE_DIGEST, _IMAGE_DIGEST_PATTERN),
        "infra_revision": _pattern(managed, _INFRA_REVISION, _SHA256_PATTERN),
        "semantic_config_sha256": _pattern(
            managed, _SEMANTIC_CONFIG_SHA256, _SHA256_PATTERN
        ),
    }
    specific: dict[str, object]
    if component is Component.API:
        specific = {
            "runtime_database": _exact(
                managed, _RUNTIME_DATABASE, _APPROVED_RUNTIME_DATABASE
            ),
            "target_bucket": _exact(managed, _TARGET_BUCKET, _APPROVED_TARGET_BUCKET),
            "controller_url": _https_origin(managed, _CONTROLLER_URL),
            "controller_audience": _audience(
                managed, _CONTROLLER_AUDIENCE, Component.CONTROLLER
            ),
            "fault_proxy_url": _https_origin(managed, _FAULT_PROXY_URL),
            "fault_proxy_audience": _audience(
                managed, _FAULT_PROXY_AUDIENCE, Component.FAULT_PROXY
            ),
        }
    elif component is Component.CONTROLLER:
        expected_baseline = _expected_canary_baseline_revision(
            project_id=str(common["project_id"]),
            image_digest=str(common["image_digest"]),
            infrastructure_revision=str(common["infra_revision"]),
            semantic_config_sha256=str(common["semantic_config_sha256"]),
            source_revision=str(common["source_revision"]),
        )
        expected_release_id = f"p5-release-{str(common['source_revision'])[:24]}"
        expected_payload_sha256 = _expected_recovery_payload_sha256(
            project_id=str(common["project_id"]),
            image_digest=str(common["image_digest"]),
            infrastructure_revision=str(common["infra_revision"]),
            semantic_config_sha256=str(common["semantic_config_sha256"]),
            source_revision=str(common["source_revision"]),
        )
        specific = {
            "runtime_database": _exact(
                managed, _RUNTIME_DATABASE, _APPROVED_RUNTIME_DATABASE
            ),
            "target_database": _exact(
                managed, _TARGET_DATABASE, _APPROVED_TARGET_DATABASE
            ),
            "target_bucket": _exact(managed, _TARGET_BUCKET, _APPROVED_TARGET_BUCKET),
            "fault_proxy_url": _https_origin(managed, _FAULT_PROXY_URL),
            "fault_proxy_audience": _audience(
                managed, _FAULT_PROXY_AUDIENCE, Component.FAULT_PROXY
            ),
            "sandbox_url": _https_origin(managed, _SANDBOX_URL),
            "sandbox_audience": _audience(
                managed, _SANDBOX_AUDIENCE, Component.SANDBOX
            ),
            "canary_location": _exact(managed, _CANARY_LOCATION, "us-central1"),
            "canary_service": _exact(
                managed,
                _CANARY_SERVICE,
                "reconcile-p5-canary",
            ),
            "canary_baseline_revision": _exact(
                managed,
                _CANARY_BASELINE_REVISION,
                expected_baseline,
            ),
            "canary_audience": _exact(
                managed,
                _CANARY_AUDIENCE,
                _APPROVED_CANARY_AUDIENCE,
            ),
            "recovery_release_id": _exact(
                managed,
                _RECOVERY_RELEASE_ID,
                expected_release_id,
            ),
            "recovery_payload_sha256": _exact(
                managed,
                _RECOVERY_PAYLOAD_SHA256,
                expected_payload_sha256,
            ),
            "recovery_definition_created_at": _utc_timestamp(
                managed,
                _RECOVERY_DEFINITION_CREATED_AT,
            ),
            "recovery_execution_timeout_seconds": _integer(
                managed,
                _RECOVERY_EXECUTION_TIMEOUT_SECONDS,
                minimum=240,
                maximum=240,
            ),
            "vertex_location": _exact(managed, _VERTEX_LOCATION, "us"),
            "vertex_model": _exact(managed, _VERTEX_MODEL, "gemini-3.5-flash"),
            "vertex_prompt_version": _exact(
                managed,
                _VERTEX_PROMPT_VERSION,
                _APPROVED_VERTEX_PROMPT_VERSION,
            ),
            "vertex_prompt_sha256": _exact(
                managed,
                _VERTEX_PROMPT_SHA256,
                _APPROVED_VERTEX_PROMPT_SHA256,
            ),
            "vertex_max_count_tokens_attempts": _integer(
                managed,
                _VERTEX_MAX_COUNT_TOKENS_ATTEMPTS,
                minimum=1,
                maximum=1,
            ),
            "vertex_max_generation_attempts": _integer(
                managed,
                _VERTEX_MAX_GENERATION_ATTEMPTS,
                minimum=1,
                maximum=1,
            ),
            "vertex_max_input_tokens": _integer(
                managed,
                _VERTEX_MAX_INPUT_TOKENS,
                minimum=12_000,
                maximum=12_000,
            ),
            "vertex_max_output_tokens": _integer(
                managed,
                _VERTEX_MAX_OUTPUT_TOKENS,
                minimum=4_096,
                maximum=4_096,
            ),
            "vertex_thinking_level": _exact(managed, _VERTEX_THINKING_LEVEL, "MINIMAL"),
        }
    elif component is Component.FAULT_PROXY:
        expected_baseline = _expected_canary_baseline_revision(
            project_id=str(common["project_id"]),
            image_digest=str(common["image_digest"]),
            infrastructure_revision=str(common["infra_revision"]),
            semantic_config_sha256=str(common["semantic_config_sha256"]),
            source_revision=str(common["source_revision"]),
        )
        specific = {
            "runtime_database": _exact(
                managed, _RUNTIME_DATABASE, _APPROVED_RUNTIME_DATABASE
            ),
            "target_database": _exact(
                managed, _TARGET_DATABASE, _APPROVED_TARGET_DATABASE
            ),
            "target_bucket": _exact(managed, _TARGET_BUCKET, _APPROVED_TARGET_BUCKET),
            "sandbox_url": _https_origin(managed, _SANDBOX_URL),
            "sandbox_audience": _audience(
                managed, _SANDBOX_AUDIENCE, Component.SANDBOX
            ),
            "canary_location": _exact(managed, _CANARY_LOCATION, "us-central1"),
            "canary_service": _exact(managed, _CANARY_SERVICE, "reconcile-p5-canary"),
            "canary_baseline_revision": _exact(
                managed,
                _CANARY_BASELINE_REVISION,
                expected_baseline,
            ),
            "canary_audience": _exact(
                managed,
                _CANARY_AUDIENCE,
                _APPROVED_CANARY_AUDIENCE,
            ),
            "recovery_action_caller_email": _exact(
                managed,
                _RECOVERY_ACTION_CALLER,
                _APPROVED_SANDBOX_READ_CALLER,
            ),
        }
    else:
        specific = {
            "runtime_database": _exact(
                managed, _RUNTIME_DATABASE, _APPROVED_RUNTIME_DATABASE
            ),
            "target_database": _exact(
                managed, _TARGET_DATABASE, _APPROVED_SANDBOX_DATABASE
            ),
            "sandbox_read_caller_email": sandbox_read_caller,
            "sandbox_mutation_caller_email": sandbox_mutation_caller,
        }
    return HostedConfig(**common, **specific)  # type: ignore[arg-type]


def load_config(environ: Mapping[str, str] | None = None) -> HostedConfig:
    """Load one exact component configuration without echoing invalid values."""

    source = os.environ if environ is None else environ
    failure: HostedConfigError
    try:
        return _load_config(source)
    except HostedConfigError as error:
        failure = HostedConfigError(error.code)
    except Exception:
        failure = HostedConfigError("is invalid")
    raise failure from None


__all__ = [
    "SUPPORTED_ENVIRONMENT_VARIABLES",
    "Component",
    "HostedConfig",
    "HostedConfigError",
    "load_config",
]
