"""Sealed semantic-action profiles for proof-scoped recovery."""

from __future__ import annotations

import hashlib
import re
from datetime import datetime
from enum import StrEnum
from itertools import combinations, pairwise
from types import MappingProxyType
from typing import Literal

from pydantic import Field, ValidationError, model_validator

from reconcile.contracts.base import (
    ArgumentsObject,
    Identifier,
    NonEmptyText,
    Sha256Digest,
    StrictModel,
    canonical_json_value_bytes,
)
from reconcile.contracts.codec import canonical_sha256
from reconcile.contracts.common import Classification, TargetBinding
from reconcile.contracts.envelope import ExpectedEffect
from reconcile.contracts.evidence import (
    EffectAssertionState,
    EvidenceAuthority,
    NormalizedEvidence,
    OperationStatus,
)
from reconcile.contracts.recovery import SemanticActionIdentity

RECOVERY_ACTION_PROFILE_VERSION = "reconcile/recovery-action-profile/v1"

STAGE_CLOUD_RUN_REVISION_PROFILE_VERSION = "stage-cloud-run-revision-profile-v1"
PROMOTE_CLOUD_RUN_TRAFFIC_PROFILE_VERSION = "promote-cloud-run-traffic-profile-v1"
CREATE_FIRESTORE_RELEASE_RECORD_PROFILE_VERSION = (
    "create-firestore-release-record-profile-v1"
)

CLOUD_RUN_SERVICE_TARGET_KIND = "google.cloud_run.service"
FIRESTORE_DOCUMENT_TARGET_KIND = "google.firestore.document"
RECOVERY_TOOL_VERSION = "1.0.0"
RECOVERY_CAPABILITY_VERSION = "1.0.0"

CLOUD_RUN_PROVIDER_SOURCE = "google-cloud-run-v2"
CLOUD_RUN_PROVIDER_ADAPTER_VERSION = "reconcile-cloud-run-v2-v1"
CLOUD_RUN_HEALTH_SOURCE = "cloud-run-revision-health"
CLOUD_RUN_HEALTH_ADAPTER_VERSION = "reconcile-cloud-run-health-v1"
FIRESTORE_PROVIDER_SOURCE = "google-firestore-v1"
FIRESTORE_PROVIDER_ADAPTER_VERSION = "reconcile-firestore-v1"
DISPATCH_RECEIPT_SOURCE = "reconcile-dispatcher"
DISPATCH_RECEIPT_ADAPTER_VERSION = "reconcile-dispatch-receipt-v1"

CLOUD_RUN_SERVICE_OBSERVATION_VERSION = "cloud-run-service-observation-v1"
CLOUD_RUN_REVISION_OBSERVATION_VERSION = "cloud-run-revision-observation-v1"
CLOUD_RUN_OPERATION_OBSERVATION_VERSION = "cloud-run-operation-observation-v1"
CLOUD_RUN_HEALTH_OBSERVATION_VERSION = "cloud-run-health-observation-v1"
FIRESTORE_DOCUMENT_OBSERVATION_VERSION = "firestore-document-observation-v1"
DISPATCH_RECEIPT_OBSERVATION_VERSION = "dispatch-receipt-observation-v1"

STAGE_REVISION_EFFECT_SCOPE = "cloud-run-revision-created"
STAGE_READINESS_EFFECT_SCOPE = "cloud-run-revision-ready"
STAGE_TRAFFIC_EFFECT_SCOPE = "cloud-run-revision-zero-traffic"
PROMOTION_TRAFFIC_EFFECT_SCOPE = "cloud-run-traffic-promoted"
FIRESTORE_RECORD_EFFECT_SCOPE = "firestore-release-record-created"

_SHA256 = re.compile(r"[0-9a-f]{64}")
_IMAGE_DIGEST = re.compile(r"sha256:[0-9a-f]{64}")
_IDENTIFIER = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}")
_CLOUD_RUN_REVISION = re.compile(r"[a-z][a-z0-9-]{0,62}")
_RESOURCE_COMPONENT = re.compile(r"[^/\s]{1,128}")
_POSITIVE_GENERATION = re.compile(r"[1-9][0-9]{0,18}")
_NONNEGATIVE_GENERATION = re.compile(r"0|[1-9][0-9]{0,18}")


class RecoveryRuleViolation(ValueError):
    """A semantic action or its proof input does not match a sealed profile."""


class RecoveryPreconditionKind(StrEnum):
    NONE = "NONE"
    CLOUD_RUN_SERVICE_ETAG = "CLOUD_RUN_SERVICE_ETAG"
    FIRESTORE_MUST_NOT_EXIST = "FIRESTORE_MUST_NOT_EXIST"


class _CloudRunServiceObservation(StrictModel):
    observation_schema: Literal[CLOUD_RUN_SERVICE_OBSERVATION_VERSION]
    release_id: Identifier
    revision: Identifier
    service_etag: NonEmptyText
    generation: NonEmptyText
    observed_generation: NonEmptyText
    reconciling: Literal["true", "false"]
    terminal_condition: Literal["SUCCEEDED", "FAILED", "NONE"]
    revision_traffic_percent: NonEmptyText

    @model_validator(mode="after")
    def validate_provider_state(self) -> _CloudRunServiceObservation:
        generation = _generation(self.generation, observed=False)
        observed = _generation(self.observed_generation, observed=True)
        if observed > generation:
            raise ValueError("observed generation cannot exceed service generation")
        if self.reconciling == "false":
            if observed != generation or self.terminal_condition == "NONE":
                raise ValueError("settled service state must be terminal and observed")
        elif self.terminal_condition != "NONE":
            raise ValueError("reconciling service state cannot be terminal")
        _traffic_percent(self.revision_traffic_percent)
        _provider_value(self.service_etag, label="service_etag")
        _revision(self.revision)
        return self


class _CloudRunRevisionObservation(StrictModel):
    observation_schema: Literal[CLOUD_RUN_REVISION_OBSERVATION_VERSION]
    release_id: Identifier
    release_label: Identifier
    revision: Identifier
    image_digest: NonEmptyText
    configuration_sha256: Sha256Digest
    generation: NonEmptyText
    observed_generation: NonEmptyText
    reconciling: Literal["true", "false"]
    terminal_condition: Literal["SUCCEEDED", "FAILED", "NONE"]
    readiness: Literal["READY", "NOT_READY", "UNKNOWN"]

    @model_validator(mode="after")
    def validate_provider_state(self) -> _CloudRunRevisionObservation:
        generation = _generation(self.generation, observed=False)
        observed = _generation(self.observed_generation, observed=True)
        if observed > generation:
            raise ValueError("observed generation cannot exceed revision generation")
        if self.reconciling == "false":
            if observed != generation or self.terminal_condition == "NONE":
                raise ValueError("settled revision state must be terminal and observed")
        elif self.terminal_condition != "NONE":
            raise ValueError("reconciling revision state cannot be terminal")
        if self.terminal_condition == "SUCCEEDED" and self.readiness != "READY":
            raise ValueError("successful revision must be ready")
        if self.terminal_condition == "FAILED" and self.readiness == "READY":
            raise ValueError("failed revision cannot be ready")
        if _IMAGE_DIGEST.fullmatch(self.image_digest) is None:
            raise ValueError("revision image digest is malformed")
        _revision(self.revision)
        return self


class _CloudRunOperationObservation(StrictModel):
    observation_schema: Literal[CLOUD_RUN_OPERATION_OBSERVATION_VERSION]
    release_id: Identifier
    revision: Identifier
    operation_name: NonEmptyText
    operation_state: Literal["RUNNING", "SUCCEEDED", "FAILED"]

    @model_validator(mode="after")
    def validate_provider_state(self) -> _CloudRunOperationObservation:
        _provider_value(self.operation_name, label="operation_name")
        _revision(self.revision)
        return self


class _CloudRunHealthObservation(StrictModel):
    observation_schema: Literal[CLOUD_RUN_HEALTH_OBSERVATION_VERSION]
    release_id: Identifier
    revision: Identifier
    health_status: Literal["READY", "UNHEALTHY"]

    @model_validator(mode="after")
    def validate_provider_state(self) -> _CloudRunHealthObservation:
        _revision(self.revision)
        return self


class _FirestoreDocumentObservation(StrictModel):
    observation_schema: Literal[FIRESTORE_DOCUMENT_OBSERVATION_VERSION]
    release_id: Identifier
    cloud_run_revision: Identifier | None = None
    payload_sha256: Sha256Digest
    semantic_action_sha256: Sha256Digest | None = None
    exists: Literal["true", "false"]

    @model_validator(mode="after")
    def validate_release_binding(self) -> _FirestoreDocumentObservation:
        if (self.cloud_run_revision is None) is not (
            self.semantic_action_sha256 is None
        ):
            raise ValueError("Firestore release binding must be complete")
        return self


class _DispatchReceiptObservation(StrictModel):
    observation_schema: Literal[DISPATCH_RECEIPT_OBSERVATION_VERSION]
    release_id: Identifier
    semantic_action_sha256: Sha256Digest
    receipt_id: Identifier
    provider_contact: Literal["false"]
    outcome: Literal[
        "SUPPRESSED_BEFORE_DISPATCH",
        "AUTHORITATIVE_REJECTION_BEFORE_PROVIDER_CONTACT",
    ]


class RecoveryCapability(StrictModel):
    name: Identifier
    version: Identifier

    @property
    def key(self) -> tuple[str, str]:
        return self.name, self.version


class RecoveryActionProfile(StrictModel):
    """One immutable member of the supported recovery-action inventory."""

    schema_version: Literal[RECOVERY_ACTION_PROFILE_VERSION]
    profile_version: Identifier
    tool_name: Identifier
    tool_version: Identifier
    target_kind: Identifier
    target_scope_fields: tuple[Identifier, ...] = Field(min_length=1, max_length=8)
    target_resource_fields: tuple[Identifier, ...] = Field(
        min_length=1,
        max_length=8,
    )
    semantic_argument_fields: tuple[Identifier, ...] = Field(
        min_length=1,
        max_length=8,
    )
    retry_allowed: bool
    evidence_capabilities: tuple[RecoveryCapability, ...] = Field(
        min_length=1,
        max_length=8,
    )
    discriminating_probe: RecoveryCapability
    precondition_kind: RecoveryPreconditionKind

    @model_validator(mode="after")
    def validate_inventory_entry(self) -> RecoveryActionProfile:
        for fields in (
            self.target_scope_fields,
            self.target_resource_fields,
            self.semantic_argument_fields,
        ):
            if len(fields) != len(set(fields)):
                raise ValueError("profile field names must be unique")
        capability_keys = tuple(item.key for item in self.evidence_capabilities)
        if len(capability_keys) != len(set(capability_keys)):
            raise ValueError("profile evidence capabilities must be unique")
        if self.discriminating_probe.key not in capability_keys:
            raise ValueError(
                "the discriminating probe must be an allowed evidence capability"
            )
        return self


_SERVICE_GET = RecoveryCapability(
    name="cloud-run-service-get",
    version=RECOVERY_CAPABILITY_VERSION,
)
_REVISION_GET = RecoveryCapability(
    name="cloud-run-revision-get",
    version=RECOVERY_CAPABILITY_VERSION,
)
_OPERATION_GET = RecoveryCapability(
    name="cloud-run-operation-get",
    version=RECOVERY_CAPABILITY_VERSION,
)
_REVISION_HEALTH = RecoveryCapability(
    name="cloud-run-revision-health",
    version=RECOVERY_CAPABILITY_VERSION,
)
_FIRESTORE_GET = RecoveryCapability(
    name="firestore-release-record-get",
    version=RECOVERY_CAPABILITY_VERSION,
)
_DISPATCH_RECEIPT_GET = RecoveryCapability(
    name="reconcile-dispatch-receipt-get",
    version=RECOVERY_CAPABILITY_VERSION,
)
_CLOUD_RUN_CAPABILITIES = (
    _SERVICE_GET,
    _REVISION_GET,
    _OPERATION_GET,
    _REVISION_HEALTH,
)

STAGE_CLOUD_RUN_REVISION_PROFILE = RecoveryActionProfile(
    schema_version=RECOVERY_ACTION_PROFILE_VERSION,
    profile_version=STAGE_CLOUD_RUN_REVISION_PROFILE_VERSION,
    tool_name="stage-cloud-run-revision",
    tool_version=RECOVERY_TOOL_VERSION,
    target_kind=CLOUD_RUN_SERVICE_TARGET_KIND,
    target_scope_fields=("project", "location"),
    target_resource_fields=("service",),
    semantic_argument_fields=(
        "release_id",
        "image_digest",
        "configuration_sha256",
    ),
    retry_allowed=False,
    evidence_capabilities=_CLOUD_RUN_CAPABILITIES,
    discriminating_probe=_REVISION_GET,
    precondition_kind=RecoveryPreconditionKind.NONE,
)

PROMOTE_CLOUD_RUN_TRAFFIC_PROFILE = RecoveryActionProfile(
    schema_version=RECOVERY_ACTION_PROFILE_VERSION,
    profile_version=PROMOTE_CLOUD_RUN_TRAFFIC_PROFILE_VERSION,
    tool_name="promote-cloud-run-traffic",
    tool_version=RECOVERY_TOOL_VERSION,
    target_kind=CLOUD_RUN_SERVICE_TARGET_KIND,
    target_scope_fields=("project", "location"),
    target_resource_fields=("service",),
    semantic_argument_fields=("release_id", "revision", "percent"),
    retry_allowed=False,
    evidence_capabilities=_CLOUD_RUN_CAPABILITIES,
    discriminating_probe=_SERVICE_GET,
    precondition_kind=RecoveryPreconditionKind.CLOUD_RUN_SERVICE_ETAG,
)

CREATE_FIRESTORE_RELEASE_RECORD_PROFILE = RecoveryActionProfile(
    schema_version=RECOVERY_ACTION_PROFILE_VERSION,
    profile_version=CREATE_FIRESTORE_RELEASE_RECORD_PROFILE_VERSION,
    tool_name="create-firestore-release-record",
    tool_version=RECOVERY_TOOL_VERSION,
    target_kind=FIRESTORE_DOCUMENT_TARGET_KIND,
    target_scope_fields=("project", "database"),
    target_resource_fields=("document",),
    semantic_argument_fields=("release_id", "payload_sha256"),
    retry_allowed=True,
    evidence_capabilities=(_FIRESTORE_GET, _DISPATCH_RECEIPT_GET),
    discriminating_probe=_FIRESTORE_GET,
    precondition_kind=RecoveryPreconditionKind.FIRESTORE_MUST_NOT_EXIST,
)

RECOVERY_ACTION_PROFILES = (
    STAGE_CLOUD_RUN_REVISION_PROFILE,
    PROMOTE_CLOUD_RUN_TRAFFIC_PROFILE,
    CREATE_FIRESTORE_RELEASE_RECORD_PROFILE,
)

_PROFILES_BY_VERSION = MappingProxyType(
    {profile.profile_version: profile for profile in RECOVERY_ACTION_PROFILES}
)

_TRUSTED_PROVENANCE = MappingProxyType(
    {
        _SERVICE_GET.key: (
            CLOUD_RUN_PROVIDER_SOURCE,
            CLOUD_RUN_PROVIDER_ADAPTER_VERSION,
        ),
        _REVISION_GET.key: (
            CLOUD_RUN_PROVIDER_SOURCE,
            CLOUD_RUN_PROVIDER_ADAPTER_VERSION,
        ),
        _OPERATION_GET.key: (
            CLOUD_RUN_PROVIDER_SOURCE,
            CLOUD_RUN_PROVIDER_ADAPTER_VERSION,
        ),
        _REVISION_HEALTH.key: (
            CLOUD_RUN_HEALTH_SOURCE,
            CLOUD_RUN_HEALTH_ADAPTER_VERSION,
        ),
        _FIRESTORE_GET.key: (
            FIRESTORE_PROVIDER_SOURCE,
            FIRESTORE_PROVIDER_ADAPTER_VERSION,
        ),
        _DISPATCH_RECEIPT_GET.key: (
            DISPATCH_RECEIPT_SOURCE,
            DISPATCH_RECEIPT_ADAPTER_VERSION,
        ),
    }
)

_OBSERVATION_MODELS = MappingProxyType(
    {
        _SERVICE_GET.key: _CloudRunServiceObservation,
        _REVISION_GET.key: _CloudRunRevisionObservation,
        _OPERATION_GET.key: _CloudRunOperationObservation,
        _REVISION_HEALTH.key: _CloudRunHealthObservation,
        _FIRESTORE_GET.key: _FirestoreDocumentObservation,
        _DISPATCH_RECEIPT_GET.key: _DispatchReceiptObservation,
    }
)


def _generation(value: str, *, observed: bool) -> int:
    pattern = _NONNEGATIVE_GENERATION if observed else _POSITIVE_GENERATION
    if pattern.fullmatch(value) is None:
        raise ValueError("provider generation is not canonical decimal text")
    return int(value)


def _traffic_percent(value: str) -> int:
    if _NONNEGATIVE_GENERATION.fullmatch(value) is None:
        raise ValueError("traffic percent is not canonical decimal text")
    result = int(value)
    if result > 100:
        raise ValueError("traffic percent is outside the closed range 0..100")
    return result


def _provider_value(value: str, *, label: str) -> str:
    if not 1 <= len(value) <= 512 or any(character.isspace() for character in value):
        raise ValueError(f"{label} is not a bounded opaque provider value")
    return value


def _revision(value: str) -> str:
    if _CLOUD_RUN_REVISION.fullmatch(value) is None:
        raise ValueError("revision is not a canonical Cloud Run revision name")
    return value


def _target_text(action: SemanticActionIdentity, section: str, name: str) -> str:
    values = action.target.scope if section == "scope" else action.target.resource
    value = values[name]
    if type(value) is not str or _RESOURCE_COMPONENT.fullmatch(value) is None:
        raise RecoveryRuleViolation(
            f"action target {section} field {name} is not a resource component"
        )
    return value


def _require_exact_fields(
    value: dict[str, object],
    expected: tuple[str, ...],
    *,
    label: str,
) -> None:
    if set(value) != set(expected):
        raise RecoveryRuleViolation(f"{label} fields do not match the profile")


def _require_text(value: object, *, label: str, pattern: re.Pattern[str]) -> str:
    if type(value) is not str or pattern.fullmatch(value) is None:
        raise RecoveryRuleViolation(f"{label} does not match the profile")
    return value


def deterministic_stage_revision(*, service: str, release_id: str) -> str:
    """Return the exact Cloud Run revision named by a staged release action."""

    _require_text(service, label="service", pattern=_CLOUD_RUN_REVISION)
    _require_text(release_id, label="release_id", pattern=_IDENTIFIER)
    operation_suffix = hashlib.sha256(f"{release_id}\0stage".encode()).hexdigest()[:24]
    operation_id = f"release-stage-{operation_suffix}"
    revision_suffix = hashlib.sha256(operation_id.encode("utf-8")).hexdigest()[:16]
    revision = f"{service}-r-{revision_suffix}"
    _require_text(revision, label="revision", pattern=_CLOUD_RUN_REVISION)
    return revision


def _validate_target(
    profile: RecoveryActionProfile,
    action: SemanticActionIdentity,
) -> None:
    target = action.target
    if target.target_kind != profile.target_kind:
        raise RecoveryRuleViolation("action target kind does not match the profile")
    _require_exact_fields(
        target.scope,
        profile.target_scope_fields,
        label="action target scope",
    )
    _require_exact_fields(
        target.resource,
        profile.target_resource_fields,
        label="action target resource",
    )
    for field, value in (*target.scope.items(), *target.resource.items()):
        if type(value) is not str or not value:
            raise RecoveryRuleViolation(
                f"action target field {field} must be nonempty text"
            )


def _validate_arguments(
    profile: RecoveryActionProfile,
    action: SemanticActionIdentity,
) -> None:
    arguments = action.semantic_arguments
    _require_exact_fields(
        arguments,
        profile.semantic_argument_fields,
        label="semantic argument",
    )
    _require_text(
        arguments["release_id"],
        label="release_id",
        pattern=_IDENTIFIER,
    )
    if profile is STAGE_CLOUD_RUN_REVISION_PROFILE:
        _require_text(
            arguments["image_digest"],
            label="image_digest",
            pattern=_IMAGE_DIGEST,
        )
        _require_text(
            arguments["configuration_sha256"],
            label="configuration_sha256",
            pattern=_SHA256,
        )
    elif profile is PROMOTE_CLOUD_RUN_TRAFFIC_PROFILE:
        _require_text(
            arguments["revision"],
            label="revision",
            pattern=_CLOUD_RUN_REVISION,
        )
        if type(arguments["percent"]) is not int or arguments["percent"] != 100:
            raise RecoveryRuleViolation("percent must be the integer 100")
    elif profile is CREATE_FIRESTORE_RELEASE_RECORD_PROFILE:
        _require_text(
            arguments["payload_sha256"],
            label="payload_sha256",
            pattern=_SHA256,
        )
    else:  # pragma: no cover - the sealed inventory is exhaustive
        raise RecoveryRuleViolation("action profile is not sealed")


def validate_recovery_action(
    profile: RecoveryActionProfile,
    action: SemanticActionIdentity,
) -> None:
    """Require an action to match one profile without coercion or fallback."""

    if type(profile) is not RecoveryActionProfile:
        raise TypeError("recovery profile must be exact")
    if type(action) is not SemanticActionIdentity:
        raise TypeError("semantic action must be exact")
    if _PROFILES_BY_VERSION.get(profile.profile_version) is not profile:
        raise RecoveryRuleViolation("action profile is not in the sealed inventory")
    if (
        action.action_profile_version != profile.profile_version
        or action.tool_name != profile.tool_name
        or action.tool_version != profile.tool_version
    ):
        raise RecoveryRuleViolation(
            "semantic action identity does not match the profile"
        )
    _validate_target(profile, action)
    _validate_arguments(profile, action)


def resolve_recovery_action_profile(
    action: SemanticActionIdentity,
) -> RecoveryActionProfile:
    """Resolve and validate the one sealed profile named by an action."""

    if type(action) is not SemanticActionIdentity:
        raise TypeError("semantic action must be exact")
    profile = _PROFILES_BY_VERSION.get(action.action_profile_version)
    if profile is None:
        raise RecoveryRuleViolation("semantic action names an unsupported profile")
    validate_recovery_action(profile, action)
    return profile


def validate_recovery_dispatch(
    action: SemanticActionIdentity,
    *,
    tool_name: str,
    tool_version: str,
    arguments: ArgumentsObject,
    target: TargetBinding,
    precondition: dict[str, object],
) -> RecoveryActionProfile:
    """Validate an outbound call against one sealed semantic action profile."""

    profile = resolve_recovery_action_profile(action)
    if type(target) is not TargetBinding:
        raise TypeError("dispatch target must be exact")
    if type(arguments) is not dict or type(precondition) is not dict:
        raise TypeError("dispatch arguments and precondition must be exact objects")
    if (
        tool_name != action.tool_name
        or tool_version != action.tool_version
        or arguments != action.semantic_arguments
        or target != action.target
    ):
        raise RecoveryRuleViolation(
            "dispatch identity does not match the sealed semantic action"
        )

    if profile.precondition_kind is RecoveryPreconditionKind.NONE:
        valid_precondition = set(precondition) == {"none"} and (
            precondition["none"] is True
        )
    elif profile.precondition_kind is RecoveryPreconditionKind.CLOUD_RUN_SERVICE_ETAG:
        etag = precondition.get("service_etag")
        valid_precondition = set(precondition) == {"service_etag"} and type(etag) is str
        if valid_precondition:
            try:
                _provider_value(etag, label="service_etag")
            except ValueError:
                valid_precondition = False
    elif profile.precondition_kind is RecoveryPreconditionKind.FIRESTORE_MUST_NOT_EXIST:
        valid_precondition = set(precondition) == {"exists"} and (
            precondition["exists"] is False
        )
    else:  # pragma: no cover - the sealed inventory is exhaustive
        valid_precondition = False
    if not valid_precondition:
        raise RecoveryRuleViolation(
            "dispatch precondition does not match the sealed action profile"
        )
    return profile


ProviderObservation = (
    _CloudRunServiceObservation
    | _CloudRunRevisionObservation
    | _CloudRunOperationObservation
    | _CloudRunHealthObservation
    | _FirestoreDocumentObservation
    | _DispatchReceiptObservation
)


def _provider_observation(evidence: NormalizedEvidence) -> ProviderObservation:
    key = (evidence.capability_name, evidence.capability_version)
    provenance = _TRUSTED_PROVENANCE.get(key)
    model = _OBSERVATION_MODELS.get(key)
    if provenance is None or model is None:
        raise RecoveryRuleViolation("evidence capability has no sealed provider rule")
    if (
        evidence.provenance.source,
        evidence.provenance.adapter_version,
    ) != provenance:
        raise RecoveryRuleViolation(
            "evidence provenance does not name the trusted provider adapter"
        )
    try:
        return model.model_validate(evidence.correlation)
    except ValidationError as error:
        raise RecoveryRuleViolation(
            "evidence correlation is not a typed provider observation"
        ) from error


def _cloud_run_record(
    action: SemanticActionIdentity,
    observation: ProviderObservation,
) -> str:
    project = _target_text(action, "scope", "project")
    location = _target_text(action, "scope", "location")
    service = _target_text(action, "resource", "service")
    service_record = f"projects/{project}/locations/{location}/services/{service}"
    if type(observation) is _CloudRunServiceObservation:
        return service_record
    if type(observation) in {
        _CloudRunRevisionObservation,
        _CloudRunHealthObservation,
    }:
        record = f"{service_record}/revisions/{observation.revision}"
        return (
            f"{record}/health"
            if type(observation) is _CloudRunHealthObservation
            else record
        )
    if type(observation) is _CloudRunOperationObservation:
        operation_prefix = f"projects/{project}/locations/{location}/operations/"
        operation_id = observation.operation_name.removeprefix(operation_prefix)
        if (
            operation_id == observation.operation_name
            or _RESOURCE_COMPONENT.fullmatch(operation_id) is None
        ):
            raise RecoveryRuleViolation(
                "Cloud Run operation is outside the exact action project and location"
            )
        return observation.operation_name
    raise RecoveryRuleViolation("Cloud Run evidence has the wrong observation type")


def _firestore_record(action: SemanticActionIdentity) -> str:
    project = _target_text(action, "scope", "project")
    database = _target_text(action, "scope", "database")
    document = action.target.resource["document"]
    if (
        type(document) is not str
        or not 1 <= len(document) <= 512
        or document.startswith("/")
        or document.endswith("/")
        or "//" in document
        or any(character.isspace() for character in document)
    ):
        raise RecoveryRuleViolation(
            "action target document is not a canonical relative document path"
        )
    return f"projects/{project}/databases/{database}/documents/{document}"


def _validate_evidence_status(
    evidence: NormalizedEvidence,
    observation: ProviderObservation,
) -> None:
    assertions = tuple(item.state for item in evidence.effect_assertions)
    if type(observation) is _CloudRunOperationObservation:
        expected = {
            "RUNNING": OperationStatus.ACTIVE,
            "SUCCEEDED": OperationStatus.TERMINAL_COMMITTED,
            # A failed Cloud Run operation does not prove that no provider-side
            # effect occurred before failure.
            "FAILED": OperationStatus.UNRESOLVED,
        }[observation.operation_state]
        if evidence.operation_status is not expected:
            raise RecoveryRuleViolation(
                "Cloud Run operation evidence has inconsistent proof semantics"
            )
        if observation.operation_state == "SUCCEEDED":
            if (
                EffectAssertionState.ESTABLISHED not in assertions
                or EffectAssertionState.NOT_ESTABLISHED in assertions
            ):
                raise RecoveryRuleViolation(
                    "successful Cloud Run operation evidence must establish an effect"
                )
        elif any(state is not EffectAssertionState.UNVERIFIED for state in assertions):
            raise RecoveryRuleViolation(
                "non-successful Cloud Run operation evidence cannot establish effects"
            )
        return
    if type(observation) is _DispatchReceiptObservation:
        if (
            evidence.operation_status is not OperationStatus.TERMINAL_NOT_COMMITTED
            or not assertions
            or any(
                state is not EffectAssertionState.NOT_ESTABLISHED
                for state in assertions
            )
        ):
            raise RecoveryRuleViolation(
                "dispatch receipt must positively prove pre-provider non-execution"
            )
        return
    if (
        type(observation)
        in {
            _CloudRunServiceObservation,
            _CloudRunRevisionObservation,
        }
        and observation.reconciling == "true"
    ):
        if evidence.operation_status not in {None, OperationStatus.ACTIVE} or any(
            state is EffectAssertionState.NOT_ESTABLISHED for state in assertions
        ):
            raise RecoveryRuleViolation(
                "reconciling Cloud Run state must remain authoritative pending"
            )
    elif evidence.operation_status is not None:
        raise RecoveryRuleViolation(
            "settled provider state reads cannot assert an operation outcome"
        )
    if (
        type(observation) is _FirestoreDocumentObservation
        and observation.exists == "false"
        and any(state is not EffectAssertionState.UNVERIFIED for state in assertions)
    ):
        raise RecoveryRuleViolation(
            "a missing Firestore document is absence-only evidence"
        )


def _validate_observation_binding(
    profile: RecoveryActionProfile,
    action: SemanticActionIdentity,
    evidence: NormalizedEvidence,
    observation: ProviderObservation,
    *,
    require_expected_stage_revision: bool,
) -> None:
    release_id = action.semantic_arguments["release_id"]
    if observation.release_id != release_id:
        raise RecoveryRuleViolation(
            "provider observation release does not match the semantic action"
        )
    if (
        require_expected_stage_revision
        and profile is STAGE_CLOUD_RUN_REVISION_PROFILE
        and isinstance(
            observation,
            (
                _CloudRunServiceObservation,
                _CloudRunRevisionObservation,
                _CloudRunOperationObservation,
                _CloudRunHealthObservation,
            ),
        )
        and observation.revision
        != deterministic_stage_revision(
            service=str(action.target.resource["service"]),
            release_id=str(release_id),
        )
    ):
        raise RecoveryRuleViolation(
            "Cloud Run observation names a different staged revision"
        )
    if type(observation) is _CloudRunRevisionObservation:
        if observation.release_label != release_id:
            raise RecoveryRuleViolation(
                "Cloud Run revision does not carry the exact release label"
            )
        if profile is STAGE_CLOUD_RUN_REVISION_PROFILE and (
            observation.image_digest != action.semantic_arguments["image_digest"]
            or observation.configuration_sha256
            != action.semantic_arguments["configuration_sha256"]
        ):
            raise RecoveryRuleViolation(
                "Cloud Run revision identity differs from the staged action"
            )
    elif type(observation) is _CloudRunServiceObservation:
        if (
            profile is PROMOTE_CLOUD_RUN_TRAFFIC_PROFILE
            and observation.revision != action.semantic_arguments["revision"]
        ):
            raise RecoveryRuleViolation(
                "Cloud Run service traffic names another revision"
            )
    elif type(observation) is _CloudRunOperationObservation:
        if (
            profile is PROMOTE_CLOUD_RUN_TRAFFIC_PROFILE
            and observation.revision != action.semantic_arguments["revision"]
        ):
            raise RecoveryRuleViolation("Cloud Run operation names another revision")
    elif type(observation) is _CloudRunHealthObservation:
        if (
            profile is PROMOTE_CLOUD_RUN_TRAFFIC_PROFILE
            and observation.revision != action.semantic_arguments["revision"]
        ):
            raise RecoveryRuleViolation("Cloud Run health names another revision")
    elif type(observation) is _FirestoreDocumentObservation:
        if observation.payload_sha256 != action.semantic_arguments[
            "payload_sha256"
        ] or (
            observation.semantic_action_sha256 is not None
            and observation.semantic_action_sha256 != action.semantic_action_sha256
        ):
            raise RecoveryRuleViolation(
                "Firestore record identity differs from the semantic action"
            )
    elif type(observation) is _DispatchReceiptObservation:
        if observation.semantic_action_sha256 != action.semantic_action_sha256:
            raise RecoveryRuleViolation(
                "dispatch receipt belongs to another semantic action"
            )
    else:  # pragma: no cover - ProviderObservation is exhaustive
        raise RecoveryRuleViolation("provider observation type is unsupported")

    if profile.target_kind == CLOUD_RUN_SERVICE_TARGET_KIND:
        expected_record = _cloud_run_record(action, observation)
    elif type(observation) is _FirestoreDocumentObservation:
        expected_record = _firestore_record(action)
    elif type(observation) is _DispatchReceiptObservation:
        expected_record = f"dispatch-receipts/{observation.receipt_id}"
    else:  # pragma: no cover - the sealed profile inventory is exhaustive
        raise RecoveryRuleViolation("provider observation target is unsupported")
    if evidence.provenance.source_record != expected_record:
        raise RecoveryRuleViolation(
            "provider source record does not match the exact action target"
        )


def _validated_recovery_observations(
    profile: RecoveryActionProfile,
    action: SemanticActionIdentity,
    evidence: tuple[NormalizedEvidence, ...],
    *,
    require_expected_stage_revision: bool,
) -> tuple[ProviderObservation, ...]:
    """Return typed provider observations after action and target validation."""

    validate_recovery_action(profile, action)
    if type(evidence) is not tuple or any(
        type(item) is not NormalizedEvidence for item in evidence
    ):
        raise TypeError("recovery evidence must be an exact tuple of evidence")
    if not evidence:
        raise RecoveryRuleViolation("recovery proof requires provider evidence")
    allowed = {item.key for item in profile.evidence_capabilities}
    observations: list[ProviderObservation] = []
    for item in evidence:
        if (item.capability_name, item.capability_version) not in allowed:
            raise RecoveryRuleViolation(
                "supporting evidence capability does not match the profile"
            )
        if item.target != action.target:
            raise RecoveryRuleViolation(
                "supporting evidence target does not match the semantic action"
            )
        if item.authority is not EvidenceAuthority.TARGET_STATE:
            raise RecoveryRuleViolation(
                "supporting evidence is not authoritative target state"
            )
        observation = _provider_observation(item)
        _validate_evidence_status(item, observation)
        _validate_observation_binding(
            profile,
            action,
            item,
            observation,
            require_expected_stage_revision=require_expected_stage_revision,
        )
        observations.append(observation)
    return tuple(observations)


def validate_recovery_evidence(
    profile: RecoveryActionProfile,
    action: SemanticActionIdentity,
    evidence: tuple[NormalizedEvidence, ...],
) -> None:
    """Require typed trusted-provider evidence bound to one exact action."""

    _validated_recovery_observations(
        profile,
        action,
        evidence,
        require_expected_stage_revision=True,
    )


def _require_consistent_observations(
    evidence: tuple[NormalizedEvidence, ...],
    observations: tuple[ProviderObservation, ...],
) -> None:
    """Reject divergent snapshots while allowing monotonic operation polling."""

    snapshots: dict[
        tuple[str, str, str],
        list[tuple[NormalizedEvidence, ProviderObservation]],
    ] = {}
    for item, observation in zip(evidence, observations, strict=True):
        resource_key = (
            item.capability_name,
            item.capability_version,
            item.provenance.source_record,
        )
        snapshots.setdefault(resource_key, []).append((item, observation))

    for resource_snapshots in snapshots.values():
        first = resource_snapshots[0][1]
        if type(first) is not _CloudRunOperationObservation:
            if any(observation != first for _, observation in resource_snapshots[1:]):
                raise RecoveryRuleViolation(
                    "provider evidence contains inconsistent snapshots of one resource"
                )
            continue

        operations = tuple(
            (item, observation)
            for item, observation in resource_snapshots
            if type(observation) is _CloudRunOperationObservation
        )
        if len(operations) != len(resource_snapshots):
            raise RecoveryRuleViolation(
                "provider evidence contains inconsistent snapshots of one resource"
            )
        identities = {
            (
                observation.observation_schema,
                observation.release_id,
                observation.revision,
                observation.operation_name,
            )
            for _, observation in operations
        }
        if len(identities) != 1:
            raise RecoveryRuleViolation(
                "provider evidence contains inconsistent operation identity"
            )

        by_observed_at: dict[datetime, set[str]] = {}
        for item, observation in operations:
            by_observed_at.setdefault(item.observed_at, set()).add(
                observation.operation_state
            )
        if any(len(states) != 1 for states in by_observed_at.values()):
            raise RecoveryRuleViolation(
                "provider operation diverges at one observation time"
            )

        ordered_states = tuple(
            observation.operation_state
            for _, observation in sorted(
                operations,
                key=lambda pair: (
                    pair[0].observed_at,
                    pair[0].provenance.retrieved_at,
                    pair[0].evidence_id,
                ),
            )
        )
        for previous, current in pairwise(ordered_states):
            if previous == current:
                continue
            if previous == "RUNNING" and current in {"SUCCEEDED", "FAILED"}:
                continue
            raise RecoveryRuleViolation(
                "provider operation snapshots regress or disagree after termination"
            )


def _require_stage_revision_coherence(
    observations: tuple[ProviderObservation, ...],
) -> None:
    revisions = {
        item.revision
        for item in observations
        if type(item)
        in {
            _CloudRunServiceObservation,
            _CloudRunRevisionObservation,
            _CloudRunOperationObservation,
            _CloudRunHealthObservation,
        }
    }
    if len(revisions) > 1:
        raise RecoveryRuleViolation(
            "staging observations do not identify one exact revision"
        )


def recovery_provider_conflict_pairs(
    profile: RecoveryActionProfile,
    action: SemanticActionIdentity,
    evidence: tuple[NormalizedEvidence, ...],
) -> tuple[tuple[str, str], ...]:
    """Return every deterministic two-observation provider contradiction.

    Each observation must first be structurally admissible and bound to the
    sealed provider target. Pairwise evaluation then exposes conflicts that the
    generic effect classifier cannot see, such as divergent ETags, divergent
    staged revisions, or an LRO state regression. Proof authority separately
    requires every staging observation to name the intended revision.
    """

    observations = _validated_recovery_observations(
        profile,
        action,
        evidence,
        require_expected_stage_revision=False,
    )
    conflicts: set[tuple[str, str]] = set()
    for left_index, right_index in combinations(range(len(evidence)), 2):
        pair_evidence = (evidence[left_index], evidence[right_index])
        pair_observations = (
            observations[left_index],
            observations[right_index],
        )
        try:
            _require_consistent_observations(pair_evidence, pair_observations)
            if profile is STAGE_CLOUD_RUN_REVISION_PROFILE:
                _require_stage_revision_coherence(pair_observations)
        except RecoveryRuleViolation:
            conflicts.add(
                tuple(
                    sorted(
                        (
                            evidence[left_index].evidence_id,
                            evidence[right_index].evidence_id,
                        )
                    )
                )
            )
    return tuple(sorted(conflicts))


def _expected_effects_by_scope(
    profile: RecoveryActionProfile,
    action: SemanticActionIdentity,
    expected_effects: tuple[ExpectedEffect, ...],
) -> dict[str, ExpectedEffect]:
    if type(expected_effects) is not tuple or any(
        type(item) is not ExpectedEffect for item in expected_effects
    ):
        raise TypeError("expected effects must be an exact tuple of effects")
    if tuple(canonical_sha256(item) for item in expected_effects) != (
        action.expected_effect_sha256s
    ):
        raise RecoveryRuleViolation(
            "expected effects do not match the semantic action identity"
        )
    effects = {item.commit_scope: item for item in expected_effects}
    if len(effects) != len(expected_effects):
        raise RecoveryRuleViolation("recovery effect scopes must be unique")

    arguments = action.semantic_arguments
    release_id = arguments["release_id"]
    if profile is STAGE_CLOUD_RUN_REVISION_PROFILE:
        revision = deterministic_stage_revision(
            service=str(action.target.resource["service"]),
            release_id=str(release_id),
        )
        predicates: dict[str, dict[str, object]] = {
            STAGE_REVISION_EFFECT_SCOPE: {
                "release_id": release_id,
                "image_digest": arguments["image_digest"],
                "configuration_sha256": arguments["configuration_sha256"],
                "revision": revision,
            },
            STAGE_READINESS_EFFECT_SCOPE: {
                "release_id": release_id,
                "ready": True,
                "revision": revision,
            },
            STAGE_TRAFFIC_EFFECT_SCOPE: {
                "release_id": release_id,
                "traffic_percent": 0,
                "revision": revision,
            },
        }
    elif profile is PROMOTE_CLOUD_RUN_TRAFFIC_PROFILE:
        predicates = {
            PROMOTION_TRAFFIC_EFFECT_SCOPE: {
                "release_id": release_id,
                "revision": arguments["revision"],
                "percent": 100,
            }
        }
    elif profile is CREATE_FIRESTORE_RELEASE_RECORD_PROFILE:
        base_predicate: dict[str, object] = {
            "release_id": release_id,
            "payload_sha256": arguments["payload_sha256"],
        }
        record_effect = effects.get(FIRESTORE_RECORD_EFFECT_SCOPE)
        record_predicate = (
            {} if record_effect is None else dict(record_effect.predicate)
        )
        if record_predicate != base_predicate:
            enhanced_fields = {*base_predicate, "cloud_run_revision"}
            if set(record_predicate) != enhanced_fields or any(
                record_predicate[field] != value
                for field, value in base_predicate.items()
            ):
                raise RecoveryRuleViolation(
                    "expected-effect predicates do not match the sealed action profile"
                )
            _require_text(
                record_predicate["cloud_run_revision"],
                label="cloud_run_revision",
                pattern=_CLOUD_RUN_REVISION,
            )
        predicates = {FIRESTORE_RECORD_EFFECT_SCOPE: record_predicate}
    else:  # pragma: no cover - the sealed inventory is exhaustive
        raise RecoveryRuleViolation("recovery effect profile is unsupported")

    if set(effects) != set(predicates) or any(
        effects[scope].predicate != predicate for scope, predicate in predicates.items()
    ):
        raise RecoveryRuleViolation(
            "expected-effect predicates do not match the sealed action profile"
        )
    return effects


def _assertion_states(
    effects: dict[str, ExpectedEffect],
    evidence: tuple[NormalizedEvidence, ...],
) -> dict[str, set[EffectAssertionState]]:
    scope_by_effect = {effect.effect_id: scope for scope, effect in effects.items()}
    states = {effect_id: set() for effect_id in scope_by_effect}
    for item in evidence:
        observation = _provider_observation(item)
        allowed_scopes: set[str]
        if type(observation) is _CloudRunServiceObservation:
            allowed_scopes = {
                STAGE_TRAFFIC_EFFECT_SCOPE,
                PROMOTION_TRAFFIC_EFFECT_SCOPE,
            }
        elif type(observation) is _CloudRunRevisionObservation:
            allowed_scopes = {
                STAGE_REVISION_EFFECT_SCOPE,
                STAGE_READINESS_EFFECT_SCOPE,
            }
        elif type(observation) is _CloudRunHealthObservation:
            allowed_scopes = {STAGE_READINESS_EFFECT_SCOPE}
        elif type(observation) is _CloudRunOperationObservation:
            allowed_scopes = {
                STAGE_REVISION_EFFECT_SCOPE,
                PROMOTION_TRAFFIC_EFFECT_SCOPE,
            }
        elif type(observation) in {
            _FirestoreDocumentObservation,
            _DispatchReceiptObservation,
        }:
            allowed_scopes = {FIRESTORE_RECORD_EFFECT_SCOPE}
        else:
            allowed_scopes = set()
        for assertion in item.effect_assertions:
            scope = scope_by_effect.get(assertion.effect_id)
            if scope is None:
                raise RecoveryRuleViolation(
                    "provider evidence asserts an undeclared expected effect"
                )
            if (
                assertion.state is not EffectAssertionState.UNVERIFIED
                and scope not in allowed_scopes
            ):
                raise RecoveryRuleViolation(
                    "provider capability asserted an effect outside its authority"
                )
            expected_state = _provider_effect_state(observation, scope)
            if (
                assertion.state is not EffectAssertionState.UNVERIFIED
                and assertion.state is not expected_state
            ):
                raise RecoveryRuleViolation(
                    "provider effect assertion contradicts its typed observation"
                )
            states[assertion.effect_id].add(assertion.state)
    return states


def _provider_effect_state(
    observation: ProviderObservation,
    scope: str,
) -> EffectAssertionState:
    if type(observation) is _CloudRunServiceObservation:
        settled = (
            observation.reconciling == "false"
            and observation.terminal_condition == "SUCCEEDED"
        )
        if not settled:
            return EffectAssertionState.UNVERIFIED
        if scope == STAGE_TRAFFIC_EFFECT_SCOPE:
            satisfied = observation.revision_traffic_percent == "0"
        elif scope == PROMOTION_TRAFFIC_EFFECT_SCOPE:
            satisfied = observation.revision_traffic_percent == "100"
        else:
            return EffectAssertionState.UNVERIFIED
        return (
            EffectAssertionState.ESTABLISHED
            if satisfied
            else EffectAssertionState.NOT_ESTABLISHED
        )
    if type(observation) is _CloudRunRevisionObservation:
        if scope == STAGE_REVISION_EFFECT_SCOPE:
            return EffectAssertionState.ESTABLISHED
        if scope == STAGE_READINESS_EFFECT_SCOPE:
            if (
                observation.reconciling == "false"
                and observation.terminal_condition == "SUCCEEDED"
                and observation.readiness == "READY"
            ):
                return EffectAssertionState.ESTABLISHED
            if observation.reconciling == "false":
                return EffectAssertionState.NOT_ESTABLISHED
        return EffectAssertionState.UNVERIFIED
    if type(observation) is _CloudRunHealthObservation:
        return (
            EffectAssertionState.ESTABLISHED
            if observation.health_status == "READY"
            else EffectAssertionState.NOT_ESTABLISHED
        )
    if type(observation) is _CloudRunOperationObservation:
        if observation.operation_state == "SUCCEEDED" and scope in {
            STAGE_REVISION_EFFECT_SCOPE,
            PROMOTION_TRAFFIC_EFFECT_SCOPE,
        }:
            return EffectAssertionState.ESTABLISHED
        return EffectAssertionState.UNVERIFIED
    if type(observation) is _FirestoreDocumentObservation:
        return (
            EffectAssertionState.ESTABLISHED
            if observation.exists == "true"
            else EffectAssertionState.UNVERIFIED
        )
    if type(observation) is _DispatchReceiptObservation:
        return EffectAssertionState.NOT_ESTABLISHED
    return EffectAssertionState.UNVERIFIED


def _require_stage_commit(
    observations: tuple[ProviderObservation, ...],
) -> None:
    services = tuple(
        item for item in observations if type(item) is _CloudRunServiceObservation
    )
    revisions = tuple(
        item for item in observations if type(item) is _CloudRunRevisionObservation
    )
    health = tuple(
        item for item in observations if type(item) is _CloudRunHealthObservation
    )
    if not services or not revisions or not health:
        raise RecoveryRuleViolation(
            "committed staging requires service, revision, and health observations"
        )
    if any(
        item.reconciling != "false"
        or item.terminal_condition != "SUCCEEDED"
        or item.revision_traffic_percent != "0"
        for item in services
    ):
        raise RecoveryRuleViolation(
            "staged revision requires settled service state and zero traffic"
        )
    if any(
        item.reconciling != "false"
        or item.terminal_condition != "SUCCEEDED"
        or item.readiness != "READY"
        for item in revisions
    ):
        raise RecoveryRuleViolation(
            "staged revision is not terminally reconciled and ready"
        )
    if any(item.health_status != "READY" for item in health):
        raise RecoveryRuleViolation(
            "staged revision lacks a successful exact-revision health result"
        )
    _require_stage_revision_coherence(observations)
    if len({item.service_etag for item in services}) != 1:
        raise RecoveryRuleViolation(
            "staging observations do not carry one consistent service ETag"
        )


def _require_promotion_commit(
    action: SemanticActionIdentity,
    observations: tuple[ProviderObservation, ...],
) -> None:
    services = tuple(
        item for item in observations if type(item) is _CloudRunServiceObservation
    )
    if not services or any(
        item.revision != action.semantic_arguments["revision"]
        or item.revision_traffic_percent != "100"
        or item.reconciling != "false"
        or item.terminal_condition != "SUCCEEDED"
        for item in services
    ):
        raise RecoveryRuleViolation(
            "promotion requires settled 100-percent traffic to the exact revision"
        )
    if len({item.service_etag for item in services}) != 1:
        raise RecoveryRuleViolation(
            "promotion observations do not carry one consistent service ETag"
        )


def _require_firestore_commit(
    action: SemanticActionIdentity,
    effects: dict[str, ExpectedEffect],
    observations: tuple[ProviderObservation, ...],
) -> None:
    documents = tuple(
        item for item in observations if type(item) is _FirestoreDocumentObservation
    )
    if not documents or any(item.exists != "true" for item in documents):
        raise RecoveryRuleViolation(
            "Firestore commit requires the exact release record to exist"
        )
    expected_revision = effects[FIRESTORE_RECORD_EFFECT_SCOPE].predicate.get(
        "cloud_run_revision"
    )
    if expected_revision is not None and any(
        item.cloud_run_revision != expected_revision
        or item.semantic_action_sha256 != action.semantic_action_sha256
        for item in documents
    ):
        raise RecoveryRuleViolation(
            "Firestore commit is not bound to the intended Cloud Run revision"
        )


def validate_recovery_proof(
    profile: RecoveryActionProfile,
    action: SemanticActionIdentity,
    expected_effects: tuple[ExpectedEffect, ...],
    classification: Classification,
    evidence: tuple[NormalizedEvidence, ...],
) -> None:
    """Validate the provider-specific proof behind one classifier result.

    Freshness remains the verifier's responsibility because it depends on the
    certificate issuance time. This function owns action, observation, and
    expected-effect semantics only.
    """

    if type(classification) is not Classification:
        raise TypeError("classification must be exact")
    validate_recovery_evidence(profile, action, evidence)
    effects = _expected_effects_by_scope(profile, action, expected_effects)
    observations = tuple(_provider_observation(item) for item in evidence)
    if classification is not Classification.UNKNOWN:
        _require_consistent_observations(evidence, observations)
        if profile is STAGE_CLOUD_RUN_REVISION_PROFILE:
            _require_stage_revision_coherence(observations)
    states = _assertion_states(effects, evidence)
    definitive = {
        effect_id: values - {EffectAssertionState.UNVERIFIED}
        for effect_id, values in states.items()
    }
    if any(len(values) > 1 for values in definitive.values()):
        raise RecoveryRuleViolation("provider evidence contains conflicting effects")
    established = {
        effect_id
        for effect_id, values in definitive.items()
        if values == {EffectAssertionState.ESTABLISHED}
    }
    not_established = {
        effect_id
        for effect_id, values in definitive.items()
        if values == {EffectAssertionState.NOT_ESTABLISHED}
    }
    effect_ids = set(states)
    if classification is Classification.UNKNOWN:
        return
    if classification is Classification.COMMITTED:
        if established != effect_ids or not_established:
            raise RecoveryRuleViolation(
                "committed proof does not establish every declared effect"
            )
        if profile is STAGE_CLOUD_RUN_REVISION_PROFILE:
            _require_stage_commit(observations)
        elif profile is PROMOTE_CLOUD_RUN_TRAFFIC_PROFILE:
            _require_promotion_commit(action, observations)
        else:
            _require_firestore_commit(action, effects, observations)
        return
    if classification is Classification.NOT_COMMITTED:
        receipts = tuple(
            item for item in observations if type(item) is _DispatchReceiptObservation
        )
        if (
            profile is not CREATE_FIRESTORE_RELEASE_RECORD_PROFILE
            or not receipts
            or not_established != effect_ids
            or established
            or any(
                type(item) is not _DispatchReceiptObservation for item in observations
            )
        ):
            raise RecoveryRuleViolation(
                "not-committed proof requires only a positive pre-provider receipt"
            )
        return
    if classification is Classification.PENDING:
        if not any(
            (
                type(item) is _CloudRunOperationObservation
                and item.operation_state in {"RUNNING", "FAILED"}
            )
            or (
                type(item)
                in {_CloudRunServiceObservation, _CloudRunRevisionObservation}
                and item.reconciling == "true"
            )
            for item in observations
        ):
            raise RecoveryRuleViolation(
                "pending proof requires typed unresolved Cloud Run state"
            )
        return
    if classification is Classification.PARTIAL:
        if (
            profile is not STAGE_CLOUD_RUN_REVISION_PROFILE
            or not established
            or not not_established
            or established | not_established != effect_ids
        ):
            raise RecoveryRuleViolation(
                "partial proof requires explicit mixed Cloud Run stage effects"
            )
        revision_effect_id = effects[STAGE_REVISION_EFFECT_SCOPE].effect_id
        if revision_effect_id in established and not any(
            type(item) is _CloudRunRevisionObservation for item in observations
        ):
            raise RecoveryRuleViolation(
                "partial staged revision creation requires an exact revision read"
            )
        return
    raise RecoveryRuleViolation("classification is outside the sealed inventory")


def recovery_precondition_sha256(
    profile: RecoveryActionProfile,
    evidence: tuple[NormalizedEvidence, ...],
    *,
    retry: bool = False,
) -> str:
    """Hash the exact dispatch precondition selected by a sealed profile."""

    if type(profile) is not RecoveryActionProfile:
        raise TypeError("recovery profile must be exact")
    if _PROFILES_BY_VERSION.get(profile.profile_version) is not profile:
        raise RecoveryRuleViolation("action profile is not in the sealed inventory")
    if type(evidence) is not tuple or any(
        type(item) is not NormalizedEvidence for item in evidence
    ):
        raise TypeError("recovery evidence must be an exact tuple of evidence")
    for item in evidence:
        _provider_observation(item)

    if profile.precondition_kind is RecoveryPreconditionKind.NONE:
        precondition: dict[str, object] = {"none": True}
    elif profile.precondition_kind is RecoveryPreconditionKind.FIRESTORE_MUST_NOT_EXIST:
        if retry and (
            not evidence
            or any(
                (item.capability_name, item.capability_version)
                != _DISPATCH_RECEIPT_GET.key
                or item.operation_status is not OperationStatus.TERMINAL_NOT_COMMITTED
                for item in evidence
            )
        ):
            raise RecoveryRuleViolation(
                "Firestore retry precondition requires a positive dispatch receipt"
            )
        precondition = {"exists": False}
    elif profile.precondition_kind is RecoveryPreconditionKind.CLOUD_RUN_SERVICE_ETAG:
        service_observations = tuple(
            item
            for item in evidence
            if (item.capability_name, item.capability_version) == _SERVICE_GET.key
        )
        if not service_observations or any(
            "service_etag" not in item.correlation for item in service_observations
        ):
            raise RecoveryRuleViolation(
                "promotion requires a service_etag from service evidence"
            )
        etags = {item.correlation["service_etag"] for item in service_observations}
        if len(etags) != 1:
            raise RecoveryRuleViolation(
                "promotion requires one consistent service_etag"
            )
        precondition = {"service_etag": next(iter(etags))}
    else:  # pragma: no cover - the sealed inventory is exhaustive
        raise RecoveryRuleViolation("profile precondition is unsupported")

    return hashlib.sha256(canonical_json_value_bytes(precondition)).hexdigest()


__all__ = [
    "CLOUD_RUN_HEALTH_ADAPTER_VERSION",
    "CLOUD_RUN_HEALTH_OBSERVATION_VERSION",
    "CLOUD_RUN_HEALTH_SOURCE",
    "CLOUD_RUN_OPERATION_OBSERVATION_VERSION",
    "CLOUD_RUN_PROVIDER_ADAPTER_VERSION",
    "CLOUD_RUN_PROVIDER_SOURCE",
    "CLOUD_RUN_REVISION_OBSERVATION_VERSION",
    "CLOUD_RUN_SERVICE_OBSERVATION_VERSION",
    "CLOUD_RUN_SERVICE_TARGET_KIND",
    "CREATE_FIRESTORE_RELEASE_RECORD_PROFILE",
    "CREATE_FIRESTORE_RELEASE_RECORD_PROFILE_VERSION",
    "DISPATCH_RECEIPT_ADAPTER_VERSION",
    "DISPATCH_RECEIPT_OBSERVATION_VERSION",
    "DISPATCH_RECEIPT_SOURCE",
    "FIRESTORE_DOCUMENT_OBSERVATION_VERSION",
    "FIRESTORE_DOCUMENT_TARGET_KIND",
    "FIRESTORE_PROVIDER_ADAPTER_VERSION",
    "FIRESTORE_PROVIDER_SOURCE",
    "FIRESTORE_RECORD_EFFECT_SCOPE",
    "PROMOTE_CLOUD_RUN_TRAFFIC_PROFILE",
    "PROMOTE_CLOUD_RUN_TRAFFIC_PROFILE_VERSION",
    "PROMOTION_TRAFFIC_EFFECT_SCOPE",
    "RECOVERY_ACTION_PROFILES",
    "RECOVERY_ACTION_PROFILE_VERSION",
    "RECOVERY_CAPABILITY_VERSION",
    "RECOVERY_TOOL_VERSION",
    "STAGE_CLOUD_RUN_REVISION_PROFILE",
    "STAGE_CLOUD_RUN_REVISION_PROFILE_VERSION",
    "STAGE_READINESS_EFFECT_SCOPE",
    "STAGE_REVISION_EFFECT_SCOPE",
    "STAGE_TRAFFIC_EFFECT_SCOPE",
    "RecoveryActionProfile",
    "RecoveryCapability",
    "RecoveryPreconditionKind",
    "RecoveryRuleViolation",
    "deterministic_stage_revision",
    "recovery_precondition_sha256",
    "recovery_provider_conflict_pairs",
    "resolve_recovery_action_profile",
    "validate_recovery_action",
    "validate_recovery_dispatch",
    "validate_recovery_evidence",
    "validate_recovery_proof",
]
