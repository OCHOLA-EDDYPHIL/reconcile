"""Storage metadata readback and deterministic evidence rules."""

from __future__ import annotations

import asyncio
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta

from pydantic import Field, model_validator

from reconcile.contracts import (
    OBSERVATION_CAPABILITY_VERSION,
    EffectAssertion,
    EffectAssertionState,
    EvidenceReason,
    ExecutionEnvelope,
    ObservationCapability,
    OperationStatus,
    TargetBinding,
    TargetConstraint,
    canonical_json_bytes,
)
from reconcile.contracts.base import (
    AwareDatetime,
    Identifier,
    NonEmptyText,
    Sha256Digest,
    StrictModel,
    canonical_json_value_bytes,
    reject_sensitive_keys,
)
from reconcile.controller import (
    BoundProbe,
    CapabilityRegistration,
    CapabilitySemantics,
    CapabilityUnavailable,
    ProbeObservation,
)
from reconcile.evidence import (
    RuleInput,
    RuleObservation,
    RuleRejected,
    RuleRequest,
    RuleVerdict,
    TargetRuleDescriptor,
    TargetRuleRegistration,
)
from reconcile.scenarios.local_storage import (
    LocalStorageReadTarget,
    StorageGenerationReceipt,
    StorageObjectMetadata,
    StorageReadback,
    StorageReadPort,
    correlation_sha256,
)

STORAGE_TARGET_KIND = "storage.object"
STORAGE_CAPABILITY_NAME = "storage-object-metadata-readback"
STORAGE_CAPABILITY_VERSION = "1.0.0"
STORAGE_CLASSIFICATION_POLICY_VERSION = "classification-v1"


@dataclass(frozen=True, slots=True)
class StorageAdapterProfile:
    """One sealed target identity for the shared deterministic Storage rule."""

    environment: str
    authority_policy_version: str
    source: str
    adapter_version: str
    timeout_ms: int


LOCAL_STORAGE_PROFILE = StorageAdapterProfile(
    environment="local-sqlite",
    authority_policy_version="authority-local-storage-v1",
    source="local-storage-sqlite",
    adapter_version="1.0.0",
    timeout_ms=2_000,
)
CLOUD_STORAGE_PROFILE = StorageAdapterProfile(
    environment="google-cloud-storage",
    authority_policy_version="authority-cloud-storage-v1",
    source="google-cloud-storage-json-v1",
    adapter_version="1.0.0",
    timeout_ms=5_000,
)

STORAGE_ENVIRONMENT = LOCAL_STORAGE_PROFILE.environment
STORAGE_AUTHORITY_POLICY_VERSION = LOCAL_STORAGE_PROFILE.authority_policy_version
STORAGE_ADAPTER_VERSION = LOCAL_STORAGE_PROFILE.adapter_version
STORAGE_SOURCE = LOCAL_STORAGE_PROFILE.source
CLOUD_STORAGE_ENVIRONMENT = CLOUD_STORAGE_PROFILE.environment
CLOUD_STORAGE_AUTHORITY_POLICY_VERSION = CLOUD_STORAGE_PROFILE.authority_policy_version
CLOUD_STORAGE_ADAPTER_VERSION = CLOUD_STORAGE_PROFILE.adapter_version
CLOUD_STORAGE_SOURCE = CLOUD_STORAGE_PROFILE.source

_ARGUMENT_BYTE_CEILING = 2
_RESULT_BYTE_CEILING = 16_384
_PREDICATE_KEYS = frozenset({"content_sha256", "size_bytes", "correlation"})
_TARGET_SCOPE_KEYS = frozenset({"bucket_name", "environment"})
_TARGET_RESOURCE_KEYS = frozenset({"object_name"})


class _StorageObjectPayload(StrictModel):
    bucket_name: NonEmptyText
    object_name: NonEmptyText
    generation: int = Field(ge=1, le=2**63 - 1)
    content_sha256: Sha256Digest
    size_bytes: int = Field(ge=0, le=2**63 - 1)
    correlation: dict[Identifier, NonEmptyText] = Field(max_length=32)
    observed_at: AwareDatetime

    @model_validator(mode="after")
    def validate_correlation(self) -> _StorageObjectPayload:
        reject_sensitive_keys(self.correlation)
        return self


class _StorageReceiptPayload(StrictModel):
    operation_id: NonEmptyText
    bucket_name: NonEmptyText
    object_name: NonEmptyText
    generation: int = Field(ge=1, le=2**63 - 1)
    content_sha256: Sha256Digest
    size_bytes: int = Field(ge=0, le=2**63 - 1)
    correlation_sha256: Sha256Digest
    observed_at: AwareDatetime


class _StorageReadbackPayload(StrictModel):
    object_metadata: _StorageObjectPayload | None
    receipt: _StorageReceiptPayload | None


def _bounded_coordinate(value: object, label: str) -> str:
    if type(value) is not str or not 1 <= len(value) <= 1_024:
        raise ValueError(f"{label} must be a bounded nonempty string")
    try:
        value.encode("utf-8")
    except UnicodeEncodeError as error:
        raise ValueError(f"{label} must contain Unicode scalar values") from error
    return value


def _require_profile(profile: StorageAdapterProfile) -> StorageAdapterProfile:
    if profile is not LOCAL_STORAGE_PROFILE and profile is not CLOUD_STORAGE_PROFILE:
        raise TypeError("storage adapter profile is not supported")
    return profile


def build_storage_target(
    *,
    bucket_name: str,
    object_name: str,
    profile: StorageAdapterProfile = LOCAL_STORAGE_PROFILE,
) -> TargetBinding:
    """Build one exact target under a sealed Storage adapter profile."""

    profile = _require_profile(profile)
    return TargetBinding(
        target_kind=STORAGE_TARGET_KIND,
        scope={
            "bucket_name": _bounded_coordinate(bucket_name, "bucket name"),
            "environment": profile.environment,
        },
        resource={
            "object_name": _bounded_coordinate(object_name, "object name"),
        },
    )


def _target_coordinates(
    target: TargetBinding,
    profile: StorageAdapterProfile,
) -> tuple[str, str]:
    profile = _require_profile(profile)
    if target.target_kind != STORAGE_TARGET_KIND:
        raise ValueError("storage target kind is not supported")
    if set(target.scope) != _TARGET_SCOPE_KEYS:
        raise ValueError("storage target scope is not exact")
    if target.scope.get("environment") != profile.environment:
        raise ValueError("storage target does not match its adapter profile")
    bucket_name = _bounded_coordinate(target.scope.get("bucket_name"), "bucket name")
    if set(target.resource) != _TARGET_RESOURCE_KEYS:
        raise ValueError("storage target resource is not exact")
    object_name = _bounded_coordinate(
        target.resource.get("object_name"),
        "object name",
    )
    return bucket_name, object_name


def build_storage_capability(
    target: TargetBinding,
    *,
    profile: StorageAdapterProfile = LOCAL_STORAGE_PROFILE,
) -> ObservationCapability:
    """Build one empty-argument read capability bound to an exact target scope."""

    profile = _require_profile(profile)
    _target_coordinates(target, profile)
    return ObservationCapability(
        schema_version=OBSERVATION_CAPABILITY_VERSION,
        name=STORAGE_CAPABILITY_NAME,
        version=STORAGE_CAPABILITY_VERSION,
        read_only=True,
        argument_schema={
            "$schema": "https://json-schema.org/draft/2020-12/schema",
            "type": "object",
            "properties": {},
            "required": [],
            "additionalProperties": False,
        },
        allowed_targets=(
            TargetConstraint(
                target_kind=target.target_kind,
                scope=dict(target.scope),
            ),
        ),
        timeout_ms=profile.timeout_ms,
        result_byte_ceiling=_RESULT_BYTE_CEILING,
        cost_units=1,
    )


def _metadata_payload(metadata: StorageObjectMetadata) -> dict[str, object]:
    return {
        "bucket_name": metadata.bucket,
        "object_name": metadata.name,
        "generation": metadata.generation,
        "content_sha256": metadata.content_sha256,
        "size_bytes": metadata.size,
        "correlation": metadata.correlation,
        "observed_at": metadata.observed_at.isoformat(),
    }


def _receipt_payload(receipt: StorageGenerationReceipt) -> dict[str, object]:
    return {
        "operation_id": receipt.operation_id,
        "bucket_name": receipt.bucket,
        "object_name": receipt.name,
        "generation": receipt.generation,
        "content_sha256": receipt.content_sha256,
        "size_bytes": receipt.size,
        "correlation_sha256": receipt.correlation_sha256,
        "observed_at": receipt.observed_at.isoformat(),
    }


def _readback_payload(readback: StorageReadback) -> dict[str, object]:
    return {
        "object_metadata": (
            None
            if readback.object_metadata is None
            else _metadata_payload(readback.object_metadata)
        ),
        "receipt": (
            None if readback.receipt is None else _receipt_payload(readback.receipt)
        ),
    }


@dataclass(frozen=True, slots=True)
class _StorageReadHandler:
    read_target: StorageReadPort = field(repr=False, compare=False)
    profile: StorageAdapterProfile
    target_bytes: bytes = field(repr=False)
    clock: Callable[[], datetime] = field(repr=False, compare=False)

    async def __call__(self, probe: BoundProbe) -> ProbeObservation:
        target = TargetBinding.model_validate_json(self.target_bytes)
        if (
            probe.capability_name != STORAGE_CAPABILITY_NAME
            or probe.capability_version != STORAGE_CAPABILITY_VERSION
            or canonical_json_bytes(probe.target) != self.target_bytes
            or probe.arguments != {}
        ):
            raise CapabilityUnavailable
        bucket_name, object_name = _target_coordinates(target, self.profile)
        readback = await asyncio.to_thread(
            self.read_target.read,
            bucket=bucket_name,
            name=object_name,
            operation_id=probe.operation_id,
        )
        if type(readback) is not StorageReadback:
            raise CapabilityUnavailable
        observed_at = self.clock()
        if observed_at.tzinfo is None or observed_at.utcoffset() is None:
            raise CapabilityUnavailable
        return ProbeObservation(
            observed_at=observed_at.astimezone(UTC),
            payload=_readback_payload(readback),
        )


def build_storage_capability_registration(
    *,
    read_target: StorageReadPort,
    target: TargetBinding,
    clock: Callable[[], datetime] | None = None,
    profile: StorageAdapterProfile = LOCAL_STORAGE_PROFILE,
) -> CapabilityRegistration:
    """Register one trusted exact metadata read as an enabled read-only probe."""

    profile = _require_profile(profile)
    if profile is LOCAL_STORAGE_PROFILE:
        trusted = type(read_target) is LocalStorageReadTarget
    else:
        from reconcile.hosted.storage import CloudStorageReadTarget

        trusted = type(read_target) is CloudStorageReadTarget
    if not trusted:
        raise TypeError("storage capability requires the sealed read target")
    handler = _StorageReadHandler(
        read_target=read_target,
        profile=profile,
        target_bytes=canonical_json_bytes(target),
        clock=clock or (lambda: datetime.now(UTC)),
    )
    return CapabilityRegistration(
        capability=build_storage_capability(target, profile=profile),
        semantics=CapabilitySemantics.READ_ONLY,
        enabled=True,
        argument_byte_ceiling=_ARGUMENT_BYTE_CEILING,
        max_invocations=1,
        handler=handler,
    )


def _parse_observation(
    rule_input: RuleInput,
) -> tuple[
    ProbeObservation,
    _StorageReadbackPayload,
]:
    try:
        observation = ProbeObservation.model_validate_json(rule_input.observation)
        payload = _StorageReadbackPayload.model_validate_json(
            canonical_json_value_bytes(observation.payload)
        )
    except (TypeError, ValueError) as error:
        raise RuleRejected(EvidenceReason.MALFORMED_OBSERVATION) from error
    return observation, payload


def _expected_values(
    envelope: ExecutionEnvelope,
    request: RuleRequest,
) -> tuple[str, int, dict[str, str], tuple[EffectAssertion, ...]]:
    effects = {effect.effect_id: effect for effect in envelope.expected_effects}
    assertions: list[EffectAssertion] = []
    expected_values: tuple[str, int, dict[str, str]] | None = None
    for effect_id in request.relevant_effect_ids:
        effect = effects.get(effect_id)
        if effect is None or set(effect.predicate) != _PREDICATE_KEYS:
            raise RuleRejected(EvidenceReason.EXPECTED_EFFECT_MISMATCH)
        content_sha256 = effect.predicate.get("content_sha256")
        size_bytes = effect.predicate.get("size_bytes")
        correlation = effect.predicate.get("correlation")
        if (
            type(content_sha256) is not str
            or len(content_sha256) != 64
            or any(character not in "0123456789abcdef" for character in content_sha256)
            or type(size_bytes) is not int
            or size_bytes < 0
            or not isinstance(correlation, dict)
            or any(
                type(key) is not str or type(value) is not str
                for key, value in correlation.items()
            )
        ):
            raise RuleRejected(EvidenceReason.EXPECTED_EFFECT_MISMATCH)
        values = (content_sha256, size_bytes, dict(correlation))
        if expected_values is not None and values != expected_values:
            raise RuleRejected(EvidenceReason.EXPECTED_EFFECT_MISMATCH)
        expected_values = values
        assertions.append(
            EffectAssertion(
                effect_id=effect_id,
                state=EffectAssertionState.ESTABLISHED,
            )
        )
    if expected_values is None:
        raise RuleRejected(EvidenceReason.EXPECTED_EFFECT_MISMATCH)
    return (*expected_values, tuple(assertions))


def _fresh_timestamp(
    *,
    observed_at: datetime,
    read_at: datetime,
    retrieved_at: datetime,
    envelope: ExecutionEnvelope,
) -> bool:
    try:
        skew = timedelta(seconds=envelope.context.freshness.clock_skew_seconds)
        horizon = timedelta(seconds=envelope.context.freshness.max_age_seconds) + skew
        return not (
            observed_at > read_at + skew
            or read_at > retrieved_at + skew
            or observed_at > retrieved_at + skew
            or envelope.invoked_at - observed_at > skew
            or retrieved_at - observed_at > horizon
            or retrieved_at - read_at > horizon
        )
    except (OverflowError, ValueError):
        return False


def _weak_observation(
    *,
    envelope: ExecutionEnvelope,
    request: RuleRequest,
    observed_at: datetime,
    metadata: _StorageObjectPayload | None,
) -> RuleObservation:
    return RuleObservation(
        target=envelope.target,
        source_record="storage-readback-incomplete",
        observed_at=observed_at,
        correlation={} if metadata is None else metadata.correlation,
        effect_assertions=tuple(
            EffectAssertion(
                effect_id=effect_id,
                state=EffectAssertionState.UNVERIFIED,
            )
            for effect_id in request.relevant_effect_ids
        ),
        verdict=RuleVerdict.ABSENCE_ONLY,
    )


@dataclass(frozen=True, slots=True)
class StorageReadbackNormalizer:
    """Admit only a fresh exact object generation bound by its receipt."""

    profile: StorageAdapterProfile = LOCAL_STORAGE_PROFILE

    def __post_init__(self) -> None:
        _require_profile(self.profile)

    def __call__(self, rule_input: RuleInput) -> RuleObservation:
        if type(rule_input) is not RuleInput:
            raise RuleRejected(EvidenceReason.MALFORMED_OBSERVATION)
        envelope = rule_input.envelope
        request = rule_input.request
        if (
            request.capability_name != STORAGE_CAPABILITY_NAME
            or request.capability_version != STORAGE_CAPABILITY_VERSION
            or request.arguments != {}
        ):
            raise RuleRejected(EvidenceReason.MALFORMED_OBSERVATION)
        try:
            bucket_name, object_name = _target_coordinates(
                envelope.target,
                self.profile,
            )
        except (TypeError, ValueError) as error:
            raise RuleRejected(EvidenceReason.UNVERIFIABLE_AUTHORITY) from error

        observation, readback = _parse_observation(rule_input)
        if not _fresh_timestamp(
            observed_at=observation.observed_at,
            read_at=observation.observed_at,
            retrieved_at=rule_input.retrieved_at,
            envelope=envelope,
        ):
            raise RuleRejected(EvidenceReason.UNVERIFIABLE_AUTHORITY)

        metadata = readback.object_metadata
        receipt = readback.receipt
        if metadata is None or receipt is None:
            return _weak_observation(
                envelope=envelope,
                request=request,
                observed_at=observation.observed_at,
                metadata=metadata,
            )

        exact_target = (
            metadata.bucket_name == bucket_name
            and metadata.object_name == object_name
            and receipt.bucket_name == bucket_name
            and receipt.object_name == object_name
        )
        exact_receipt = (
            receipt.operation_id == envelope.operation_id
            and receipt.generation == metadata.generation
            and receipt.content_sha256 == metadata.content_sha256
            and receipt.size_bytes == metadata.size_bytes
            and receipt.correlation_sha256 == correlation_sha256(metadata.correlation)
        )
        if not exact_target or not exact_receipt:
            raise RuleRejected(EvidenceReason.UNVERIFIABLE_AUTHORITY)

        content_sha256, size_bytes, correlation, assertions = _expected_values(
            envelope,
            request,
        )
        if (
            metadata.content_sha256 != content_sha256
            or metadata.size_bytes != size_bytes
            or metadata.correlation != correlation
            or envelope.context.correlation_fields != correlation
        ):
            raise RuleRejected(EvidenceReason.EXPECTED_EFFECT_MISMATCH)
        if not all(
            _fresh_timestamp(
                observed_at=timestamp,
                read_at=observation.observed_at,
                retrieved_at=rule_input.retrieved_at,
                envelope=envelope,
            )
            for timestamp in (metadata.observed_at, receipt.observed_at)
        ):
            raise RuleRejected(EvidenceReason.UNVERIFIABLE_AUTHORITY)

        return RuleObservation(
            target=envelope.target,
            source_record=f"object-generation-{metadata.generation}",
            observed_at=observation.observed_at,
            operation_id=envelope.operation_id,
            correlation=metadata.correlation,
            effect_assertions=assertions,
            operation_status=OperationStatus.TERMINAL_COMMITTED,
            verdict=RuleVerdict.AUTHORITATIVE_EFFECTS,
        )


def build_storage_rule_descriptor(
    *,
    profile: StorageAdapterProfile = LOCAL_STORAGE_PROFILE,
) -> TargetRuleDescriptor:
    """Build the exact deterministic rule identity for one Storage profile."""

    profile = _require_profile(profile)
    return TargetRuleDescriptor(
        target_kind=STORAGE_TARGET_KIND,
        capability_name=STORAGE_CAPABILITY_NAME,
        capability_version=STORAGE_CAPABILITY_VERSION,
        authority_policy_version=profile.authority_policy_version,
        classification_policy_version=STORAGE_CLASSIFICATION_POLICY_VERSION,
        source=profile.source,
        adapter_version=profile.adapter_version,
    )


def build_storage_rule_registration(
    *,
    profile: StorageAdapterProfile = LOCAL_STORAGE_PROFILE,
) -> TargetRuleRegistration:
    """Register the Storage normalizer under one sealed target identity."""

    profile = _require_profile(profile)
    return TargetRuleRegistration(
        descriptor=build_storage_rule_descriptor(profile=profile),
        normalizer=StorageReadbackNormalizer(profile=profile),
    )


__all__ = [
    "CLOUD_STORAGE_ADAPTER_VERSION",
    "CLOUD_STORAGE_AUTHORITY_POLICY_VERSION",
    "CLOUD_STORAGE_ENVIRONMENT",
    "CLOUD_STORAGE_PROFILE",
    "CLOUD_STORAGE_SOURCE",
    "LOCAL_STORAGE_PROFILE",
    "STORAGE_ADAPTER_VERSION",
    "STORAGE_AUTHORITY_POLICY_VERSION",
    "STORAGE_CAPABILITY_NAME",
    "STORAGE_CAPABILITY_VERSION",
    "STORAGE_CLASSIFICATION_POLICY_VERSION",
    "STORAGE_ENVIRONMENT",
    "STORAGE_SOURCE",
    "STORAGE_TARGET_KIND",
    "StorageAdapterProfile",
    "StorageReadbackNormalizer",
    "build_storage_capability",
    "build_storage_capability_registration",
    "build_storage_rule_descriptor",
    "build_storage_rule_registration",
    "build_storage_target",
]
