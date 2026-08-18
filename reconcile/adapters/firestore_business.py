"""Composite local business-document readback and deterministic evidence rules."""

from __future__ import annotations

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
from reconcile.scenarios.local_firestore import (
    BusinessDocument,
    BusinessDocumentCoordinate,
    BusinessOperationManifest,
    BusinessOperationReadback,
    BusinessOperationStatus,
    FirestoreBusinessReadPort,
    LocalFirestoreReadTarget,
    expected_effect_declarations_sha256,
)

FIRESTORE_BUSINESS_TARGET_KIND = "business.documents"
FIRESTORE_BUSINESS_ENVIRONMENT = "local-sqlite"
FIRESTORE_BUSINESS_CAPABILITY_NAME = "business-operation-composite-readback"
FIRESTORE_BUSINESS_CAPABILITY_VERSION = "1.0.0"
FIRESTORE_BUSINESS_AUTHORITY_POLICY_VERSION = "authority-local-business-documents-v1"
FIRESTORE_BUSINESS_CLASSIFICATION_POLICY_VERSION = "classification-v1"
FIRESTORE_BUSINESS_ADAPTER_VERSION = "1.0.0"
FIRESTORE_BUSINESS_SOURCE = "local-business-documents-sqlite"
FIRESTORE_BUSINESS_CLOUD_ENVIRONMENT = "google-cloud-firestore"
FIRESTORE_BUSINESS_CLOUD_AUTHORITY_POLICY_VERSION = (
    "authority-cloud-firestore-business-documents-v1"
)
FIRESTORE_BUSINESS_CLOUD_ADAPTER_VERSION = "1.0.0"
FIRESTORE_BUSINESS_CLOUD_SOURCE = "google-cloud-firestore-v1"

_ARGUMENT_BYTE_CEILING = 2
_RESULT_BYTE_CEILING = 32_768
_TIMEOUT_MS = 2_000
_EFFECT_COUNT = 3
_PREDICATE_KEYS = frozenset(
    {"collection_name", "document_id", "content_sha256", "correlation"}
)
_TARGET_SCOPE_KEYS = frozenset({"environment", "namespace_id"})
_TARGET_RESOURCE_KEYS = frozenset(
    {"manifest_collection", "manifest_document_id", "effect_documents"}
)
_COORDINATE_KEYS = frozenset({"effect_id", "collection_name", "document_id"})


@dataclass(frozen=True, slots=True)
class FirestoreBusinessTargetProfile:
    """Trusted target and rule identity for one deterministic read provider."""

    environment: str
    authority_policy_version: str
    source: str
    adapter_version: str
    timeout_ms: int


FIRESTORE_BUSINESS_LOCAL_PROFILE = FirestoreBusinessTargetProfile(
    environment=FIRESTORE_BUSINESS_ENVIRONMENT,
    authority_policy_version=FIRESTORE_BUSINESS_AUTHORITY_POLICY_VERSION,
    source=FIRESTORE_BUSINESS_SOURCE,
    adapter_version=FIRESTORE_BUSINESS_ADAPTER_VERSION,
    timeout_ms=_TIMEOUT_MS,
)
FIRESTORE_BUSINESS_CLOUD_PROFILE = FirestoreBusinessTargetProfile(
    environment=FIRESTORE_BUSINESS_CLOUD_ENVIRONMENT,
    authority_policy_version=FIRESTORE_BUSINESS_CLOUD_AUTHORITY_POLICY_VERSION,
    source=FIRESTORE_BUSINESS_CLOUD_SOURCE,
    adapter_version=FIRESTORE_BUSINESS_CLOUD_ADAPTER_VERSION,
    timeout_ms=5_000,
)
_TRUSTED_PROFILES = (
    FIRESTORE_BUSINESS_LOCAL_PROFILE,
    FIRESTORE_BUSINESS_CLOUD_PROFILE,
)


def _trusted_profile(
    profile: FirestoreBusinessTargetProfile,
) -> FirestoreBusinessTargetProfile:
    if not any(profile is candidate for candidate in _TRUSTED_PROFILES):
        raise TypeError("business target profile is not trusted")
    return profile


def _target_profile(target: TargetBinding) -> FirestoreBusinessTargetProfile:
    environment = target.scope.get("environment")
    for profile in _TRUSTED_PROFILES:
        if environment == profile.environment:
            return profile
    raise ValueError("business-document target environment is not supported")


class _BusinessDocumentPayload(StrictModel):
    effect_id: Identifier
    collection_name: NonEmptyText
    document_id: NonEmptyText
    operation_id: Identifier
    revision: int = Field(ge=1, le=2**63 - 1)
    content_sha256: Sha256Digest
    correlation: dict[Identifier, NonEmptyText] = Field(max_length=32)
    observed_at: AwareDatetime

    @model_validator(mode="after")
    def validate_correlation(self) -> _BusinessDocumentPayload:
        reject_sensitive_keys(self.correlation)
        return self


class _BusinessManifestPayload(StrictModel):
    namespace_id: NonEmptyText
    operation_id: Identifier
    manifest_collection: NonEmptyText
    manifest_document_id: NonEmptyText
    status: BusinessOperationStatus
    revision: int = Field(ge=1, le=2**63 - 1)
    expected_effect_ids: tuple[Identifier, ...] = Field(
        min_length=1,
        max_length=64,
    )
    expected_effects_sha256: Sha256Digest
    established_effect_ids: tuple[Identifier, ...] = Field(max_length=64)
    not_established_effect_ids: tuple[Identifier, ...] = Field(max_length=64)
    effect_revisions: dict[Identifier, int] = Field(max_length=64)
    correlation: dict[Identifier, NonEmptyText] = Field(max_length=32)
    observed_at: AwareDatetime

    @model_validator(mode="after")
    def validate_manifest_shape(self) -> _BusinessManifestPayload:
        for values in (
            self.expected_effect_ids,
            self.established_effect_ids,
            self.not_established_effect_ids,
        ):
            if len(values) != len(set(values)):
                raise ValueError("manifest effect identifiers must be unique")
        if any(
            type(value) is not int or value < 1
            for value in self.effect_revisions.values()
        ):
            raise ValueError("manifest effect revisions must be positive integers")
        reject_sensitive_keys(self.correlation)
        return self


class _BusinessReadbackPayload(StrictModel):
    manifest: _BusinessManifestPayload | None
    documents: tuple[_BusinessDocumentPayload, ...] = Field(max_length=64)


@dataclass(frozen=True, slots=True)
class _ExpectedBusinessEffect:
    effect_id: str
    collection_name: str
    document_id: str
    content_sha256: str
    correlation: dict[str, str]


def _bounded_coordinate(value: object, label: str) -> str:
    if type(value) is not str or not 1 <= len(value) <= 1_024:
        raise ValueError(f"{label} must be a bounded nonempty string")
    try:
        value.encode("utf-8")
    except UnicodeEncodeError as error:
        raise ValueError(f"{label} must contain Unicode scalar values") from error
    return value


def _validate_coordinates(
    document_coordinates: tuple[BusinessDocumentCoordinate, ...],
) -> tuple[BusinessDocumentCoordinate, ...]:
    if (
        type(document_coordinates) is not tuple
        or len(document_coordinates) != _EFFECT_COUNT
    ):
        raise ValueError("business target requires exactly three document coordinates")
    if any(
        type(item) is not BusinessDocumentCoordinate for item in document_coordinates
    ):
        raise TypeError("business document coordinates must use the exact target type")
    effect_ids = [item.effect_id for item in document_coordinates]
    coordinates = [
        (item.collection_name, item.document_id) for item in document_coordinates
    ]
    if len(effect_ids) != len(set(effect_ids)):
        raise ValueError("business document effect identifiers must be unique")
    if len(coordinates) != len(set(coordinates)):
        raise ValueError("business document coordinates must be unique")
    return document_coordinates


def build_firestore_business_target(
    *,
    namespace_id: str,
    manifest_collection: str,
    manifest_document_id: str,
    document_coordinates: tuple[BusinessDocumentCoordinate, ...],
    profile: FirestoreBusinessTargetProfile = FIRESTORE_BUSINESS_LOCAL_PROFILE,
) -> TargetBinding:
    """Build one exact trusted business-document target."""

    profile = _trusted_profile(profile)
    coordinates = _validate_coordinates(document_coordinates)
    return TargetBinding(
        target_kind=FIRESTORE_BUSINESS_TARGET_KIND,
        scope={
            "environment": profile.environment,
            "namespace_id": _bounded_coordinate(namespace_id, "namespace identifier"),
        },
        resource={
            "manifest_collection": _bounded_coordinate(
                manifest_collection,
                "manifest collection",
            ),
            "manifest_document_id": _bounded_coordinate(
                manifest_document_id,
                "manifest document identifier",
            ),
            "effect_documents": [
                {
                    "effect_id": item.effect_id,
                    "collection_name": item.collection_name,
                    "document_id": item.document_id,
                }
                for item in coordinates
            ],
        },
    )


def _target_coordinates(
    target: TargetBinding,
    profile: FirestoreBusinessTargetProfile | None = None,
) -> tuple[
    str,
    str,
    str,
    tuple[BusinessDocumentCoordinate, ...],
]:
    profile = _target_profile(target) if profile is None else _trusted_profile(profile)
    if target.target_kind != FIRESTORE_BUSINESS_TARGET_KIND:
        raise ValueError("business-document target kind is not supported")
    if set(target.scope) != _TARGET_SCOPE_KEYS:
        raise ValueError("business-document target scope is not exact")
    if target.scope.get("environment") != profile.environment:
        raise ValueError("business-document target profile does not match")
    namespace_id = _bounded_coordinate(
        target.scope.get("namespace_id"),
        "namespace identifier",
    )
    if set(target.resource) != _TARGET_RESOURCE_KEYS:
        raise ValueError("business-document target resource is not exact")
    manifest_collection = _bounded_coordinate(
        target.resource.get("manifest_collection"),
        "manifest collection",
    )
    manifest_document_id = _bounded_coordinate(
        target.resource.get("manifest_document_id"),
        "manifest document identifier",
    )
    raw_coordinates = target.resource.get("effect_documents")
    if not isinstance(raw_coordinates, list):
        raise ValueError("business-document target coordinates are malformed")
    coordinates: list[BusinessDocumentCoordinate] = []
    try:
        for item in raw_coordinates:
            if not isinstance(item, dict) or set(item) != _COORDINATE_KEYS:
                raise ValueError("business-document target coordinate is not exact")
            coordinates.append(
                BusinessDocumentCoordinate(
                    effect_id=_bounded_coordinate(
                        item.get("effect_id"), "effect identifier"
                    ),
                    collection_name=_bounded_coordinate(
                        item.get("collection_name"),
                        "collection name",
                    ),
                    document_id=_bounded_coordinate(
                        item.get("document_id"),
                        "document identifier",
                    ),
                )
            )
    except (TypeError, ValueError) as error:
        raise ValueError(
            "business-document target coordinates are malformed"
        ) from error
    return (
        namespace_id,
        manifest_collection,
        manifest_document_id,
        _validate_coordinates(tuple(coordinates)),
    )


def build_firestore_business_capability(
    target: TargetBinding,
) -> ObservationCapability:
    """Build one empty-argument composite read bound to one exact operation."""

    profile = _target_profile(target)
    _target_coordinates(target, profile)
    return ObservationCapability(
        schema_version=OBSERVATION_CAPABILITY_VERSION,
        name=FIRESTORE_BUSINESS_CAPABILITY_NAME,
        version=FIRESTORE_BUSINESS_CAPABILITY_VERSION,
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


def _document_payload(document: BusinessDocument) -> dict[str, object]:
    return {
        "effect_id": document.effect_id,
        "collection_name": document.collection_name,
        "document_id": document.document_id,
        "operation_id": document.operation_id,
        "revision": document.revision,
        "content_sha256": document.content_sha256,
        "correlation": document.correlation,
        "observed_at": document.observed_at.isoformat(),
    }


def _manifest_payload(manifest: BusinessOperationManifest) -> dict[str, object]:
    return {
        "namespace_id": manifest.namespace_id,
        "operation_id": manifest.operation_id,
        "manifest_collection": manifest.manifest_collection,
        "manifest_document_id": manifest.manifest_document_id,
        "status": manifest.status.value,
        "revision": manifest.revision,
        "expected_effect_ids": list(manifest.expected_effect_ids),
        "expected_effects_sha256": manifest.expected_effects_sha256,
        "established_effect_ids": list(manifest.established_effect_ids),
        "not_established_effect_ids": list(manifest.not_established_effect_ids),
        "effect_revisions": manifest.effect_revisions,
        "correlation": manifest.correlation,
        "observed_at": manifest.observed_at.isoformat(),
    }


def _readback_payload(readback: BusinessOperationReadback) -> dict[str, object]:
    return {
        "manifest": (
            None if readback.manifest is None else _manifest_payload(readback.manifest)
        ),
        "documents": [_document_payload(item) for item in readback.documents],
    }


@dataclass(frozen=True, slots=True)
class _FirestoreBusinessReadHandler:
    read_target: FirestoreBusinessReadPort = field(repr=False, compare=False)
    profile: FirestoreBusinessTargetProfile = field(repr=False)
    target_bytes: bytes = field(repr=False)
    clock: Callable[[], datetime] = field(repr=False, compare=False)

    async def __call__(self, probe: BoundProbe) -> ProbeObservation:
        target = TargetBinding.model_validate_json(self.target_bytes)
        (
            namespace_id,
            manifest_collection,
            manifest_document_id,
            document_coordinates,
        ) = _target_coordinates(target, self.profile)
        if (
            probe.capability_name != FIRESTORE_BUSINESS_CAPABILITY_NAME
            or probe.capability_version != FIRESTORE_BUSINESS_CAPABILITY_VERSION
            or canonical_json_bytes(probe.target) != self.target_bytes
            or probe.arguments != {}
            or tuple(probe.relevant_effect_ids)
            != tuple(item.effect_id for item in document_coordinates)
        ):
            raise CapabilityUnavailable
        readback = await self.read_target.read_business_operation(
            namespace_id=namespace_id,
            operation_id=probe.operation_id,
            manifest_collection=manifest_collection,
            manifest_document_id=manifest_document_id,
            document_coordinates=document_coordinates,
        )
        if type(readback) is not BusinessOperationReadback:
            raise CapabilityUnavailable
        observed_at = self.clock()
        if observed_at.tzinfo is None or observed_at.utcoffset() is None:
            raise CapabilityUnavailable
        return ProbeObservation(
            observed_at=observed_at.astimezone(UTC),
            payload=_readback_payload(readback),
        )


def build_firestore_business_capability_registration(
    *,
    read_target: FirestoreBusinessReadPort,
    target: TargetBinding,
    clock: Callable[[], datetime] | None = None,
    profile: FirestoreBusinessTargetProfile = FIRESTORE_BUSINESS_LOCAL_PROFILE,
) -> CapabilityRegistration:
    """Register an exact trusted composite read as a read-only probe."""

    profile = _trusted_profile(profile)
    if profile is FIRESTORE_BUSINESS_LOCAL_PROFILE:
        trusted = type(read_target) is LocalFirestoreReadTarget
    else:
        from reconcile.hosted.firestore_business import (
            GoogleFirestoreBusinessReadTarget,
        )

        trusted = type(read_target) is GoogleFirestoreBusinessReadTarget
    if not trusted:
        raise TypeError("business capability requires the sealed read target")
    _target_coordinates(target, profile)
    handler = _FirestoreBusinessReadHandler(
        read_target=read_target,
        profile=profile,
        target_bytes=canonical_json_bytes(target),
        clock=clock or (lambda: datetime.now(UTC)),
    )
    return CapabilityRegistration(
        capability=build_firestore_business_capability(target),
        semantics=CapabilitySemantics.READ_ONLY,
        enabled=True,
        argument_byte_ceiling=_ARGUMENT_BYTE_CEILING,
        max_invocations=1,
        handler=handler,
    )


def _parse_observation(
    rule_input: RuleInput,
) -> tuple[ProbeObservation, _BusinessReadbackPayload]:
    try:
        observation = ProbeObservation.model_validate_json(rule_input.observation)
        payload = _BusinessReadbackPayload.model_validate_json(
            canonical_json_value_bytes(observation.payload)
        )
    except (TypeError, ValueError) as error:
        raise RuleRejected(EvidenceReason.MALFORMED_OBSERVATION) from error
    return observation, payload


def _expected_effects(
    envelope: ExecutionEnvelope,
    request: RuleRequest,
    coordinates: tuple[BusinessDocumentCoordinate, ...],
) -> tuple[_ExpectedBusinessEffect, ...]:
    expected_effects = tuple(envelope.expected_effects)
    effect_ids = tuple(effect.effect_id for effect in expected_effects)
    coordinate_by_effect = {item.effect_id: item for item in coordinates}
    if (
        len(expected_effects) != _EFFECT_COUNT
        or len({effect.commit_scope for effect in expected_effects}) != _EFFECT_COUNT
        or tuple(request.relevant_effect_ids) != effect_ids
        or set(effect_ids) != set(coordinate_by_effect)
    ):
        raise RuleRejected(EvidenceReason.EXPECTED_EFFECT_MISMATCH)

    expected: list[_ExpectedBusinessEffect] = []
    envelope_correlation = dict(envelope.context.correlation_fields)
    for effect in expected_effects:
        if set(effect.predicate) != _PREDICATE_KEYS:
            raise RuleRejected(EvidenceReason.EXPECTED_EFFECT_MISMATCH)
        collection_name = effect.predicate.get("collection_name")
        document_id = effect.predicate.get("document_id")
        content_sha256 = effect.predicate.get("content_sha256")
        correlation = effect.predicate.get("correlation")
        if (
            type(collection_name) is not str
            or not collection_name
            or type(document_id) is not str
            or not document_id
            or type(content_sha256) is not str
            or len(content_sha256) != 64
            or any(character not in "0123456789abcdef" for character in content_sha256)
            or not isinstance(correlation, dict)
            or any(
                type(key) is not str or type(value) is not str
                for key, value in correlation.items()
            )
            or correlation != envelope_correlation
        ):
            raise RuleRejected(EvidenceReason.EXPECTED_EFFECT_MISMATCH)
        coordinate = coordinate_by_effect[effect.effect_id]
        if (
            coordinate.collection_name != collection_name
            or coordinate.document_id != document_id
        ):
            raise RuleRejected(EvidenceReason.EXPECTED_EFFECT_MISMATCH)
        expected.append(
            _ExpectedBusinessEffect(
                effect_id=effect.effect_id,
                collection_name=collection_name,
                document_id=document_id,
                content_sha256=content_sha256,
                correlation=dict(correlation),
            )
        )
    return tuple(expected)


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
) -> RuleObservation:
    return RuleObservation(
        target=envelope.target,
        source_record="business-operation-readback-missing",
        observed_at=observed_at,
        effect_assertions=tuple(
            EffectAssertion(
                effect_id=effect_id,
                state=EffectAssertionState.UNVERIFIED,
            )
            for effect_id in request.relevant_effect_ids
        ),
        verdict=RuleVerdict.ABSENCE_ONLY,
    )


def _validate_manifest(
    *,
    manifest: _BusinessManifestPayload,
    envelope: ExecutionEnvelope,
    expected: tuple[_ExpectedBusinessEffect, ...],
    namespace_id: str,
    manifest_collection: str,
    manifest_document_id: str,
    read_at: datetime,
    retrieved_at: datetime,
) -> tuple[set[str], set[str], dict[str, int]]:
    expected_ids = tuple(item.effect_id for item in expected)
    declarations = tuple(
        (
            item.effect_id,
            item.collection_name,
            item.document_id,
            item.content_sha256,
        )
        for item in expected
    )
    if (
        manifest.namespace_id != namespace_id
        or manifest.operation_id != envelope.operation_id
        or manifest.manifest_collection != manifest_collection
        or manifest.manifest_document_id != manifest_document_id
    ):
        raise RuleRejected(EvidenceReason.UNVERIFIABLE_AUTHORITY)
    if (
        manifest.expected_effect_ids != expected_ids
        or manifest.expected_effects_sha256
        != expected_effect_declarations_sha256(declarations)
        or manifest.correlation != envelope.context.correlation_fields
    ):
        raise RuleRejected(EvidenceReason.EXPECTED_EFFECT_MISMATCH)
    if not _fresh_timestamp(
        observed_at=manifest.observed_at,
        read_at=read_at,
        retrieved_at=retrieved_at,
        envelope=envelope,
    ):
        raise RuleRejected(EvidenceReason.UNVERIFIABLE_AUTHORITY)

    expected_set = set(expected_ids)
    established = set(manifest.established_effect_ids)
    not_established = set(manifest.not_established_effect_ids)
    effect_revisions = dict(manifest.effect_revisions)
    if (
        not established <= expected_set
        or not not_established <= expected_set
        or established & not_established
        or set(effect_revisions) != established
        or len(set(effect_revisions.values())) != len(effect_revisions)
        or any(value > manifest.revision for value in effect_revisions.values())
        or (effect_revisions and max(effect_revisions.values()) != manifest.revision)
    ):
        raise RuleRejected(EvidenceReason.UNVERIFIABLE_AUTHORITY)

    if manifest.status is BusinessOperationStatus.ACTIVE:
        valid = not not_established and established != expected_set
    elif manifest.status is BusinessOperationStatus.TERMINAL_COMMITTED:
        valid = bool(established) and established | not_established == expected_set
    elif manifest.status is BusinessOperationStatus.TERMINAL_NOT_COMMITTED:
        valid = not established and not_established == expected_set
    else:
        valid = False
    if not valid:
        raise RuleRejected(EvidenceReason.UNVERIFIABLE_AUTHORITY)
    return established, not_established, effect_revisions


def _validate_documents(
    *,
    documents: tuple[_BusinessDocumentPayload, ...],
    manifest: _BusinessManifestPayload,
    envelope: ExecutionEnvelope,
    expected: tuple[_ExpectedBusinessEffect, ...],
    established: set[str],
    effect_revisions: dict[str, int],
    read_at: datetime,
    retrieved_at: datetime,
) -> None:
    document_effect_ids = [item.effect_id for item in documents]
    document_coordinates = [
        (item.collection_name, item.document_id) for item in documents
    ]
    if len(document_effect_ids) != len(set(document_effect_ids)) or len(
        document_coordinates
    ) != len(set(document_coordinates)):
        raise RuleRejected(EvidenceReason.DUPLICATE_CANDIDATES)
    if set(document_effect_ids) != established:
        raise RuleRejected(EvidenceReason.UNVERIFIABLE_AUTHORITY)

    expected_by_id = {item.effect_id: item for item in expected}
    try:
        skew = timedelta(seconds=envelope.context.freshness.clock_skew_seconds)
    except (OverflowError, ValueError) as error:
        raise RuleRejected(EvidenceReason.UNVERIFIABLE_AUTHORITY) from error
    for document in documents:
        expected_document = expected_by_id.get(document.effect_id)
        if expected_document is None:
            raise RuleRejected(EvidenceReason.UNVERIFIABLE_AUTHORITY)
        if (
            document.collection_name != expected_document.collection_name
            or document.document_id != expected_document.document_id
            or document.operation_id != envelope.operation_id
            or document.content_sha256 != expected_document.content_sha256
            or document.correlation != expected_document.correlation
            or document.revision != effect_revisions.get(document.effect_id)
            or document.observed_at > manifest.observed_at + skew
        ):
            raise RuleRejected(EvidenceReason.UNVERIFIABLE_AUTHORITY)
        if not _fresh_timestamp(
            observed_at=document.observed_at,
            read_at=read_at,
            retrieved_at=retrieved_at,
            envelope=envelope,
        ):
            raise RuleRejected(EvidenceReason.UNVERIFIABLE_AUTHORITY)


@dataclass(frozen=True, slots=True)
class FirestoreBusinessReadbackNormalizer:
    """Admit only a coherent manifest and all corresponding exact documents."""

    profile: FirestoreBusinessTargetProfile = FIRESTORE_BUSINESS_LOCAL_PROFILE

    def __post_init__(self) -> None:
        _trusted_profile(self.profile)

    def __call__(self, rule_input: RuleInput) -> RuleObservation:
        if type(rule_input) is not RuleInput:
            raise RuleRejected(EvidenceReason.MALFORMED_OBSERVATION)
        envelope = rule_input.envelope
        request = rule_input.request
        if (
            request.capability_name != FIRESTORE_BUSINESS_CAPABILITY_NAME
            or request.capability_version != FIRESTORE_BUSINESS_CAPABILITY_VERSION
            or request.arguments != {}
        ):
            raise RuleRejected(EvidenceReason.MALFORMED_OBSERVATION)
        try:
            (
                namespace_id,
                manifest_collection,
                manifest_document_id,
                document_coordinates,
            ) = _target_coordinates(envelope.target, self.profile)
        except (TypeError, ValueError) as error:
            raise RuleRejected(EvidenceReason.UNVERIFIABLE_AUTHORITY) from error
        expected = _expected_effects(envelope, request, document_coordinates)
        observation, readback = _parse_observation(rule_input)
        if not _fresh_timestamp(
            observed_at=observation.observed_at,
            read_at=observation.observed_at,
            retrieved_at=rule_input.retrieved_at,
            envelope=envelope,
        ):
            raise RuleRejected(EvidenceReason.UNVERIFIABLE_AUTHORITY)

        manifest = readback.manifest
        if manifest is None:
            if readback.documents:
                raise RuleRejected(EvidenceReason.UNVERIFIABLE_AUTHORITY)
            return _weak_observation(
                envelope=envelope,
                request=request,
                observed_at=observation.observed_at,
            )

        established, not_established, effect_revisions = _validate_manifest(
            manifest=manifest,
            envelope=envelope,
            expected=expected,
            namespace_id=namespace_id,
            manifest_collection=manifest_collection,
            manifest_document_id=manifest_document_id,
            read_at=observation.observed_at,
            retrieved_at=rule_input.retrieved_at,
        )
        _validate_documents(
            documents=readback.documents,
            manifest=manifest,
            envelope=envelope,
            expected=expected,
            established=established,
            effect_revisions=effect_revisions,
            read_at=observation.observed_at,
            retrieved_at=rule_input.retrieved_at,
        )

        if manifest.status is BusinessOperationStatus.ACTIVE:
            verdict = RuleVerdict.AUTHORITATIVE_PENDING
            operation_status = OperationStatus.ACTIVE
        elif manifest.status is BusinessOperationStatus.TERMINAL_NOT_COMMITTED:
            verdict = RuleVerdict.AUTHORITATIVE_NON_EXECUTION
            operation_status = OperationStatus.TERMINAL_NOT_COMMITTED
        else:
            verdict = RuleVerdict.AUTHORITATIVE_EFFECTS
            operation_status = OperationStatus.TERMINAL_COMMITTED

        assertions = tuple(
            EffectAssertion(
                effect_id=item.effect_id,
                state=(
                    EffectAssertionState.ESTABLISHED
                    if item.effect_id in established
                    else (
                        EffectAssertionState.NOT_ESTABLISHED
                        if item.effect_id in not_established
                        else EffectAssertionState.UNVERIFIED
                    )
                ),
            )
            for item in expected
        )
        return RuleObservation(
            target=envelope.target,
            source_record=f"business-operation-manifest-{manifest.revision}",
            observed_at=observation.observed_at,
            operation_id=envelope.operation_id,
            correlation=manifest.correlation,
            effect_assertions=assertions,
            operation_status=operation_status,
            verdict=verdict,
        )


def build_firestore_business_rule_descriptor(
    profile: FirestoreBusinessTargetProfile = FIRESTORE_BUSINESS_LOCAL_PROFILE,
) -> TargetRuleDescriptor:
    """Build the deterministic rule identity for one trusted provider."""

    profile = _trusted_profile(profile)
    return TargetRuleDescriptor(
        target_kind=FIRESTORE_BUSINESS_TARGET_KIND,
        capability_name=FIRESTORE_BUSINESS_CAPABILITY_NAME,
        capability_version=FIRESTORE_BUSINESS_CAPABILITY_VERSION,
        authority_policy_version=profile.authority_policy_version,
        classification_policy_version=FIRESTORE_BUSINESS_CLASSIFICATION_POLICY_VERSION,
        source=profile.source,
        adapter_version=profile.adapter_version,
    )


def build_firestore_business_rule_registration(
    profile: FirestoreBusinessTargetProfile = FIRESTORE_BUSINESS_LOCAL_PROFILE,
) -> TargetRuleRegistration:
    """Register the composite normalizer under its sealed rule identity."""

    return TargetRuleRegistration(
        descriptor=build_firestore_business_rule_descriptor(profile),
        normalizer=FirestoreBusinessReadbackNormalizer(profile=profile),
    )


__all__ = [
    "FIRESTORE_BUSINESS_ADAPTER_VERSION",
    "FIRESTORE_BUSINESS_AUTHORITY_POLICY_VERSION",
    "FIRESTORE_BUSINESS_CAPABILITY_NAME",
    "FIRESTORE_BUSINESS_CAPABILITY_VERSION",
    "FIRESTORE_BUSINESS_CLASSIFICATION_POLICY_VERSION",
    "FIRESTORE_BUSINESS_CLOUD_ADAPTER_VERSION",
    "FIRESTORE_BUSINESS_CLOUD_AUTHORITY_POLICY_VERSION",
    "FIRESTORE_BUSINESS_CLOUD_ENVIRONMENT",
    "FIRESTORE_BUSINESS_CLOUD_PROFILE",
    "FIRESTORE_BUSINESS_CLOUD_SOURCE",
    "FIRESTORE_BUSINESS_ENVIRONMENT",
    "FIRESTORE_BUSINESS_LOCAL_PROFILE",
    "FIRESTORE_BUSINESS_SOURCE",
    "FIRESTORE_BUSINESS_TARGET_KIND",
    "FirestoreBusinessReadbackNormalizer",
    "FirestoreBusinessTargetProfile",
    "build_firestore_business_capability",
    "build_firestore_business_capability_registration",
    "build_firestore_business_rule_descriptor",
    "build_firestore_business_rule_registration",
    "build_firestore_business_target",
]
