"""Cloud Run canary probes and deterministic recovery evidence normalization."""

from __future__ import annotations

import asyncio
import re
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Literal

from pydantic import model_validator

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
    Identifier,
    NonEmptyText,
    Sha256Digest,
    StrictModel,
    canonical_json_value_bytes,
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
    RuleVerdict,
    TargetRuleDescriptor,
    TargetRuleRegistration,
)
from reconcile.evidence.recovery_rules import (
    CLOUD_RUN_HEALTH_ADAPTER_VERSION,
    CLOUD_RUN_HEALTH_OBSERVATION_VERSION,
    CLOUD_RUN_HEALTH_SOURCE,
    CLOUD_RUN_OPERATION_OBSERVATION_VERSION,
    CLOUD_RUN_PROVIDER_ADAPTER_VERSION,
    CLOUD_RUN_PROVIDER_SOURCE,
    CLOUD_RUN_REVISION_OBSERVATION_VERSION,
    CLOUD_RUN_SERVICE_OBSERVATION_VERSION,
    CLOUD_RUN_SERVICE_TARGET_KIND,
    PROMOTION_TRAFFIC_EFFECT_SCOPE,
    RECOVERY_CAPABILITY_VERSION,
    STAGE_READINESS_EFFECT_SCOPE,
    STAGE_REVISION_EFFECT_SCOPE,
    STAGE_TRAFFIC_EFFECT_SCOPE,
)
from reconcile.hosted.cloud_run_canary import (
    CloudRunCanaryAction,
    CloudRunCanaryError,
    CloudRunCanaryReader,
    CloudRunHealthSnapshot,
    CloudRunOperationSnapshot,
    CloudRunRevisionAmbiguous,
    CloudRunRevisionSnapshot,
    CloudRunServiceSnapshot,
)

CLOUD_RUN_SERVICE_CAPABILITY = "cloud-run-service-get"
CLOUD_RUN_REVISION_CAPABILITY = "cloud-run-revision-get"
CLOUD_RUN_OPERATION_CAPABILITY = "cloud-run-operation-get"
CLOUD_RUN_HEALTH_CAPABILITY = "cloud-run-revision-health"
CLOUD_RUN_AUTHORITY_POLICY_VERSION = "recovery-authority-v1"
CLOUD_RUN_CLASSIFICATION_POLICY_VERSION = "recovery-classification-v1"

_CAPABILITIES = frozenset(
    {
        CLOUD_RUN_SERVICE_CAPABILITY,
        CLOUD_RUN_REVISION_CAPABILITY,
        CLOUD_RUN_OPERATION_CAPABILITY,
        CLOUD_RUN_HEALTH_CAPABILITY,
    }
)
_TARGET_SCOPE_KEYS = frozenset({"project", "location"})
_TARGET_RESOURCE_KEYS = frozenset({"service"})
_ARGUMENT_BYTE_CEILING = 2
_RESULT_BYTE_CEILING = 8_192
_TIMEOUT_MS = 5_000
_REVISION_NAME = re.compile(r"[a-z][a-z0-9-]{0,62}")
_RELEASE_ID = re.compile(r"[a-z][a-z0-9_-]{0,62}")
_IMAGE_DIGEST = re.compile(r"sha256:[0-9a-f]{64}")
_SHA256 = re.compile(r"[0-9a-f]{64}")
_POSITIVE_DECIMAL = re.compile(r"[1-9][0-9]{0,18}")
_NONNEGATIVE_DECIMAL = re.compile(r"0|[1-9][0-9]{0,18}")


def _provider_revision(value: str) -> str:
    if _REVISION_NAME.fullmatch(value) is None:
        raise ValueError("Cloud Run revision name is not canonical")
    return value


def _generation(value: str, *, observed: bool) -> int:
    pattern = _NONNEGATIVE_DECIMAL if observed else _POSITIVE_DECIMAL
    if pattern.fullmatch(value) is None:
        raise ValueError("Cloud Run generation is not canonical")
    return int(value)


def _opaque(value: str) -> str:
    if not 1 <= len(value) <= 512 or any(character.isspace() for character in value):
        raise ValueError("Cloud Run provider value is not bounded")
    return value


class _ObservationPayload(StrictModel):
    observation: dict[str, object] | None


class _ServiceObservation(StrictModel):
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
    def validate_provider_state(self) -> _ServiceObservation:
        generation = _generation(self.generation, observed=False)
        observed = _generation(self.observed_generation, observed=True)
        if observed > generation:
            raise ValueError("service observed generation exceeds generation")
        if self.reconciling == "false":
            if observed != generation or self.terminal_condition == "NONE":
                raise ValueError("settled service state is incomplete")
        elif self.terminal_condition != "NONE":
            raise ValueError("reconciling service state is terminal")
        if (
            _NONNEGATIVE_DECIMAL.fullmatch(self.revision_traffic_percent) is None
            or int(self.revision_traffic_percent) > 100
        ):
            raise ValueError("traffic percentage is outside 0..100")
        _provider_revision(self.revision)
        _opaque(self.service_etag)
        return self


class _RevisionObservation(StrictModel):
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
    def validate_provider_state(self) -> _RevisionObservation:
        generation = _generation(self.generation, observed=False)
        observed = _generation(self.observed_generation, observed=True)
        if observed > generation:
            raise ValueError("revision observed generation exceeds generation")
        if self.reconciling == "false":
            if observed != generation or self.terminal_condition == "NONE":
                raise ValueError("settled revision state is incomplete")
        elif self.terminal_condition != "NONE":
            raise ValueError("reconciling revision state is terminal")
        if self.terminal_condition == "SUCCEEDED" and self.readiness != "READY":
            raise ValueError("successful revision is not ready")
        if self.terminal_condition == "FAILED" and self.readiness == "READY":
            raise ValueError("failed revision is ready")
        _provider_revision(self.revision)
        if _IMAGE_DIGEST.fullmatch(self.image_digest) is None:
            raise ValueError("revision image is not digest-pinned")
        return self


class _OperationObservation(StrictModel):
    observation_schema: Literal[CLOUD_RUN_OPERATION_OBSERVATION_VERSION]
    release_id: Identifier
    revision: Identifier
    operation_name: NonEmptyText
    operation_state: Literal["RUNNING", "SUCCEEDED", "FAILED"]

    @model_validator(mode="after")
    def validate_provider_state(self) -> _OperationObservation:
        _provider_revision(self.revision)
        _opaque(self.operation_name)
        return self


class _HealthObservation(StrictModel):
    observation_schema: Literal[CLOUD_RUN_HEALTH_OBSERVATION_VERSION]
    release_id: Identifier
    revision: Identifier
    health_status: Literal["READY", "UNHEALTHY"]

    @model_validator(mode="after")
    def validate_provider_state(self) -> _HealthObservation:
        _provider_revision(self.revision)
        return self


type _TypedObservation = (
    _ServiceObservation
    | _RevisionObservation
    | _OperationObservation
    | _HealthObservation
)


@dataclass(frozen=True, slots=True)
class CloudRunProbeBinding:
    """Controller-owned action identity excluded from model-generated arguments."""

    release_id: str
    revision: str | None = None
    image_digest: str | None = None
    configuration_sha256: str | None = None
    operation_name: str | None = None
    operation_revision: str | None = None

    def __post_init__(self) -> None:
        stage = self.revision is None
        if (
            type(self.release_id) is not str
            or _RELEASE_ID.fullmatch(self.release_id) is None
            or (
                stage
                and (self.image_digest is None or self.configuration_sha256 is None)
            )
            or (
                not stage
                and (
                    self.image_digest is not None
                    or self.configuration_sha256 is not None
                )
            )
            or (
                self.operation_name is not None
                and (
                    type(self.operation_name) is not str
                    or not self.operation_name
                    or len(self.operation_name) > 512
                    or any(character.isspace() for character in self.operation_name)
                )
            )
            or (
                stage
                and self.operation_name is not None
                and self.operation_revision is None
            )
            or (self.operation_name is None and self.operation_revision is not None)
            or (not stage and self.operation_revision is not None)
            or (
                self.revision is not None
                and _REVISION_NAME.fullmatch(self.revision) is None
            )
            or (
                self.operation_revision is not None
                and _REVISION_NAME.fullmatch(self.operation_revision) is None
            )
            or (
                self.image_digest is not None
                and _IMAGE_DIGEST.fullmatch(self.image_digest) is None
            )
            or (
                self.configuration_sha256 is not None
                and _SHA256.fullmatch(self.configuration_sha256) is None
            )
        ):
            raise ValueError("Cloud Run probe binding is incomplete or mixed")

    @classmethod
    def for_stage(
        cls,
        *,
        release_id: str,
        image_digest: str,
        configuration_sha256: str,
        operation_name: str | None = None,
        operation_revision: str | None = None,
    ) -> CloudRunProbeBinding:
        return cls(
            release_id=release_id,
            image_digest=image_digest,
            configuration_sha256=configuration_sha256,
            operation_name=operation_name,
            operation_revision=operation_revision,
        )

    @classmethod
    def for_promotion(
        cls,
        *,
        release_id: str,
        revision: str,
        operation_name: str | None = None,
    ) -> CloudRunProbeBinding:
        return cls(
            release_id=release_id,
            revision=revision,
            operation_name=operation_name,
        )

    @property
    def is_stage(self) -> bool:
        return self.revision is None


def _bounded_coordinate(value: object, label: str) -> str:
    if type(value) is not str or not 1 <= len(value) <= 128:
        raise ValueError(f"{label} must be bounded nonempty text")
    if any(character.isspace() or character == "/" for character in value):
        raise ValueError(f"{label} is not one resource component")
    return value


def build_cloud_run_target(
    *, project: str, location: str, service: str
) -> TargetBinding:
    return TargetBinding(
        target_kind=CLOUD_RUN_SERVICE_TARGET_KIND,
        scope={
            "project": _bounded_coordinate(project, "project"),
            "location": _bounded_coordinate(location, "location"),
        },
        resource={"service": _bounded_coordinate(service, "service")},
    )


def _target_coordinates(target: TargetBinding) -> tuple[str, str, str]:
    if (
        target.target_kind != CLOUD_RUN_SERVICE_TARGET_KIND
        or set(target.scope) != _TARGET_SCOPE_KEYS
        or set(target.resource) != _TARGET_RESOURCE_KEYS
    ):
        raise ValueError("Cloud Run target does not match the sealed profile")
    return (
        _bounded_coordinate(target.scope.get("project"), "project"),
        _bounded_coordinate(target.scope.get("location"), "location"),
        _bounded_coordinate(target.resource.get("service"), "service"),
    )


def build_cloud_run_capability(
    *, capability_name: str, target: TargetBinding
) -> ObservationCapability:
    if capability_name not in _CAPABILITIES:
        raise ValueError("Cloud Run capability is outside the sealed inventory")
    _target_coordinates(target)
    return ObservationCapability(
        schema_version=OBSERVATION_CAPABILITY_VERSION,
        name=capability_name,
        version=RECOVERY_CAPABILITY_VERSION,
        read_only=True,
        argument_schema={
            "$schema": "https://json-schema.org/draft/2020-12/schema",
            "type": "object",
            "properties": {},
            "required": [],
            "additionalProperties": False,
        },
        allowed_targets=(
            TargetConstraint(target_kind=target.target_kind, scope=dict(target.scope)),
        ),
        timeout_ms=_TIMEOUT_MS,
        result_byte_ceiling=_RESULT_BYTE_CEILING,
        cost_units=1,
    )


def _snapshot_payload(snapshot: object) -> dict[str, object]:
    values = asdict(snapshot)
    values.pop("observed_at", None)
    if type(snapshot) is CloudRunServiceSnapshot:
        values.update(
            {
                "observation_schema": CLOUD_RUN_SERVICE_OBSERVATION_VERSION,
                "generation": str(snapshot.generation),
                "observed_generation": str(snapshot.observed_generation),
                "reconciling": str(snapshot.reconciling).lower(),
                "revision_traffic_percent": str(snapshot.revision_traffic_percent),
            }
        )
    elif type(snapshot) is CloudRunRevisionSnapshot:
        values.update(
            {
                "observation_schema": CLOUD_RUN_REVISION_OBSERVATION_VERSION,
                "generation": str(snapshot.generation),
                "observed_generation": str(snapshot.observed_generation),
                "reconciling": str(snapshot.reconciling).lower(),
            }
        )
    elif type(snapshot) is CloudRunOperationSnapshot:
        values["observation_schema"] = CLOUD_RUN_OPERATION_OBSERVATION_VERSION
    elif type(snapshot) is CloudRunHealthSnapshot:
        values["observation_schema"] = CLOUD_RUN_HEALTH_OBSERVATION_VERSION
    else:
        raise TypeError("Cloud Run snapshot type is unsupported")
    return values


@dataclass(frozen=True, slots=True)
class _CloudRunReadHandler:
    reader: CloudRunCanaryReader = field(repr=False, compare=False)
    binding: CloudRunProbeBinding
    capability_name: str
    target_bytes: bytes = field(repr=False)
    clock: object = field(repr=False, compare=False)

    def _revision(self) -> str | None:
        if self.binding.revision is not None:
            return self.binding.revision
        try:
            return self.reader.discover_revision(
                release_id=self.binding.release_id,
                image_digest=self.binding.image_digest or "",
                configuration_sha256=self.binding.configuration_sha256 or "",
            )
        except CloudRunRevisionAmbiguous:
            raise CapabilityUnavailable from None

    def _read(self) -> object | None:
        if self.capability_name == CLOUD_RUN_OPERATION_CAPABILITY:
            if self.binding.operation_name is None:
                return None
            revision = self.binding.revision or self.binding.operation_revision
            if revision is None:  # guarded by CloudRunProbeBinding
                raise CapabilityUnavailable
            return self.reader.read_operation(
                action=(
                    CloudRunCanaryAction.STAGE
                    if self.binding.is_stage
                    else CloudRunCanaryAction.PROMOTE
                ),
                release_id=self.binding.release_id,
                revision=revision,
                operation_name=self.binding.operation_name,
                image_digest=self.binding.image_digest,
                configuration_sha256=self.binding.configuration_sha256,
            )
        revision = self._revision()
        if revision is None:
            return None
        values = {"release_id": self.binding.release_id, "revision": revision}
        if self.capability_name == CLOUD_RUN_SERVICE_CAPABILITY:
            return self.reader.read_service(**values)
        if self.capability_name == CLOUD_RUN_REVISION_CAPABILITY:
            return self.reader.read_revision(**values)
        if self.capability_name == CLOUD_RUN_HEALTH_CAPABILITY:
            return self.reader.read_health(**values)
        raise CapabilityUnavailable

    async def __call__(self, probe: BoundProbe) -> ProbeObservation:
        if (
            probe.capability_name != self.capability_name
            or probe.capability_version != RECOVERY_CAPABILITY_VERSION
            or canonical_json_bytes(probe.target) != self.target_bytes
            or probe.arguments != {}
        ):
            raise CapabilityUnavailable
        try:
            snapshot = await asyncio.to_thread(self._read)
        except (CloudRunCanaryError, ValueError, TypeError):
            raise CapabilityUnavailable from None
        if snapshot is None:
            observed_at = self.clock()
            if not isinstance(observed_at, datetime) or observed_at.tzinfo is None:
                raise CapabilityUnavailable
            payload: dict[str, object] = {"observation": None}
            observed = observed_at.astimezone(UTC)
        else:
            observed = snapshot.observed_at
            payload = {"observation": _snapshot_payload(snapshot)}
        return ProbeObservation(observed_at=observed, payload=payload)


def build_cloud_run_capability_registration(
    *,
    reader: CloudRunCanaryReader,
    binding: CloudRunProbeBinding,
    capability_name: str,
    target: TargetBinding,
    clock: object | None = None,
) -> CapabilityRegistration:
    if type(reader) is not CloudRunCanaryReader:
        raise TypeError("Cloud Run capability requires the sealed reader")
    if type(binding) is not CloudRunProbeBinding:
        raise TypeError("Cloud Run capability requires an exact action binding")
    if clock is not None and not callable(clock):
        raise TypeError("Cloud Run capability clock must be callable")
    project, location, service = _target_coordinates(target)
    if (
        reader.target.project,
        reader.target.location,
        reader.target.service,
    ) != (project, location, service):
        raise ValueError("Cloud Run reader and capability target differ")
    handler = _CloudRunReadHandler(
        reader=reader,
        binding=binding,
        capability_name=capability_name,
        target_bytes=canonical_json_bytes(target),
        clock=clock or (lambda: datetime.now(UTC)),
    )
    return CapabilityRegistration(
        capability=build_cloud_run_capability(
            capability_name=capability_name,
            target=target,
        ),
        semantics=CapabilitySemantics.READ_ONLY,
        enabled=True,
        argument_byte_ceiling=_ARGUMENT_BYTE_CEILING,
        max_invocations=(4 if capability_name == CLOUD_RUN_OPERATION_CAPABILITY else 2),
        handler=handler,
    )


def _parse_observation(
    rule_input: RuleInput, capability_name: str
) -> tuple[ProbeObservation, _TypedObservation | None]:
    models = {
        CLOUD_RUN_SERVICE_CAPABILITY: _ServiceObservation,
        CLOUD_RUN_REVISION_CAPABILITY: _RevisionObservation,
        CLOUD_RUN_OPERATION_CAPABILITY: _OperationObservation,
        CLOUD_RUN_HEALTH_CAPABILITY: _HealthObservation,
    }
    try:
        observation = ProbeObservation.model_validate_json(rule_input.observation)
        wrapper = _ObservationPayload.model_validate_json(
            canonical_json_value_bytes(observation.payload)
        )
        typed = (
            None
            if wrapper.observation is None
            else models[capability_name].model_validate(wrapper.observation)
        )
    except (KeyError, TypeError, ValueError) as error:
        raise RuleRejected(EvidenceReason.MALFORMED_OBSERVATION) from error
    return observation, typed


def _fresh(
    observation: ProbeObservation,
    rule_input: RuleInput,
) -> bool:
    envelope = rule_input.envelope
    try:
        skew = timedelta(seconds=envelope.context.freshness.clock_skew_seconds)
        horizon = timedelta(seconds=envelope.context.freshness.max_age_seconds) + skew
        return not (
            observation.observed_at > rule_input.retrieved_at + skew
            or envelope.invoked_at - observation.observed_at > skew
            or rule_input.retrieved_at - observation.observed_at > horizon
        )
    except (OverflowError, ValueError):
        return False


def _effect_predicates(
    envelope: ExecutionEnvelope,
    relevant_effect_ids: tuple[str, ...],
) -> dict[str, tuple[str, dict[str, object]]]:
    effects = {effect.effect_id: effect for effect in envelope.expected_effects}
    result: dict[str, tuple[str, dict[str, object]]] = {}
    for effect_id in relevant_effect_ids:
        effect = effects.get(effect_id)
        if effect is None:
            raise RuleRejected(EvidenceReason.EXPECTED_EFFECT_MISMATCH)
        result[effect_id] = (effect.commit_scope, dict(effect.predicate))
    return result


def _validate_expected_effects(
    binding: CloudRunProbeBinding,
    effects: dict[str, tuple[str, dict[str, object]]],
) -> None:
    expected: dict[str, dict[str, object]]
    if binding.is_stage:
        expected = {
            STAGE_REVISION_EFFECT_SCOPE: {
                "release_id": binding.release_id,
                "image_digest": binding.image_digest,
                "configuration_sha256": binding.configuration_sha256,
            },
            STAGE_READINESS_EFFECT_SCOPE: {
                "release_id": binding.release_id,
                "ready": True,
            },
            STAGE_TRAFFIC_EFFECT_SCOPE: {
                "release_id": binding.release_id,
                "traffic_percent": 0,
            },
        }
    else:
        expected = {
            PROMOTION_TRAFFIC_EFFECT_SCOPE: {
                "release_id": binding.release_id,
                "revision": binding.revision,
                "percent": 100,
            }
        }
    if any(expected.get(scope) != predicate for scope, predicate in effects.values()):
        raise RuleRejected(EvidenceReason.EXPECTED_EFFECT_MISMATCH)


def _states(
    capability_name: str,
    observation: _TypedObservation,
    effects: dict[str, tuple[str, dict[str, object]]],
) -> dict[str, EffectAssertionState]:
    result = {key: EffectAssertionState.UNVERIFIED for key in effects}
    for effect_id, (scope, _) in effects.items():
        if type(observation) is _ServiceObservation:
            settled = (
                observation.reconciling == "false"
                and observation.terminal_condition == "SUCCEEDED"
            )
            expected_percent = "0" if scope == STAGE_TRAFFIC_EFFECT_SCOPE else "100"
            if settled and scope in {
                STAGE_TRAFFIC_EFFECT_SCOPE,
                PROMOTION_TRAFFIC_EFFECT_SCOPE,
            }:
                result[effect_id] = (
                    EffectAssertionState.ESTABLISHED
                    if observation.revision_traffic_percent == expected_percent
                    else EffectAssertionState.NOT_ESTABLISHED
                )
        elif type(observation) is _RevisionObservation:
            if scope == STAGE_REVISION_EFFECT_SCOPE:
                result[effect_id] = EffectAssertionState.ESTABLISHED
            elif scope == STAGE_READINESS_EFFECT_SCOPE:
                if (
                    observation.reconciling == "false"
                    and observation.terminal_condition == "SUCCEEDED"
                    and observation.readiness == "READY"
                ):
                    result[effect_id] = EffectAssertionState.ESTABLISHED
                elif observation.reconciling == "false":
                    result[effect_id] = EffectAssertionState.NOT_ESTABLISHED
        elif type(observation) is _OperationObservation:
            allowed_scope = (
                STAGE_REVISION_EFFECT_SCOPE
                if capability_name == CLOUD_RUN_OPERATION_CAPABILITY
                and scope == STAGE_REVISION_EFFECT_SCOPE
                else PROMOTION_TRAFFIC_EFFECT_SCOPE
                if scope == PROMOTION_TRAFFIC_EFFECT_SCOPE
                else None
            )
            if allowed_scope is not None and observation.operation_state == "SUCCEEDED":
                result[effect_id] = EffectAssertionState.ESTABLISHED
        elif (
            type(observation) is _HealthObservation
            and scope == STAGE_READINESS_EFFECT_SCOPE
            and observation.health_status == "READY"
        ):
            result[effect_id] = EffectAssertionState.ESTABLISHED
    return result


def _source_record(
    target: TargetBinding,
    capability_name: str,
    observation: _TypedObservation | None,
) -> str:
    project, location, service = _target_coordinates(target)
    base = f"projects/{project}/locations/{location}/services/{service}"
    if type(observation) is _ServiceObservation:
        return base
    if type(observation) is _OperationObservation:
        return observation.operation_name
    if type(observation) in {_RevisionObservation, _HealthObservation}:
        record = f"{base}/revisions/{observation.revision}"
        return f"{record}/health" if type(observation) is _HealthObservation else record
    if capability_name == CLOUD_RUN_OPERATION_CAPABILITY:
        return f"projects/{project}/locations/{location}/operations"
    return (
        f"{base}/revisions" if capability_name != CLOUD_RUN_SERVICE_CAPABILITY else base
    )


@dataclass(frozen=True, slots=True)
class CloudRunObservationNormalizer:
    capability_name: str
    binding: CloudRunProbeBinding

    def __post_init__(self) -> None:
        if self.capability_name not in _CAPABILITIES:
            raise ValueError("Cloud Run normalizer capability is unsupported")
        if type(self.binding) is not CloudRunProbeBinding:
            raise TypeError("Cloud Run normalizer binding must be exact")

    def __call__(self, rule_input: RuleInput) -> RuleObservation:
        if type(rule_input) is not RuleInput:
            raise RuleRejected(EvidenceReason.MALFORMED_OBSERVATION)
        request = rule_input.request
        envelope = rule_input.envelope
        if (
            request.capability_name != self.capability_name
            or request.capability_version != RECOVERY_CAPABILITY_VERSION
            or request.arguments != {}
        ):
            raise RuleRejected(EvidenceReason.MALFORMED_OBSERVATION)
        try:
            project, location, _ = _target_coordinates(envelope.target)
        except (TypeError, ValueError) as error:
            raise RuleRejected(EvidenceReason.UNVERIFIABLE_AUTHORITY) from error
        if self.binding.operation_name is not None:
            prefix = f"projects/{project}/locations/{location}/operations/"
            suffix = self.binding.operation_name.removeprefix(prefix)
            if suffix == self.binding.operation_name or not suffix or "/" in suffix:
                raise RuleRejected(EvidenceReason.UNVERIFIABLE_AUTHORITY)
        effects = _effect_predicates(envelope, request.relevant_effect_ids)
        _validate_expected_effects(self.binding, effects)
        raw, observation = _parse_observation(rule_input, self.capability_name)
        if not _fresh(raw, rule_input):
            raise RuleRejected(EvidenceReason.UNVERIFIABLE_AUTHORITY)
        if observation is None:
            assertions = tuple(
                EffectAssertion(
                    effect_id=effect_id,
                    state=EffectAssertionState.UNVERIFIED,
                )
                for effect_id in effects
            )
            return RuleObservation(
                target=envelope.target,
                source_record=_source_record(
                    envelope.target, self.capability_name, None
                ),
                observed_at=raw.observed_at,
                correlation={},
                effect_assertions=assertions,
                verdict=RuleVerdict.ABSENCE_ONLY,
            )

        correlation = observation.model_dump(mode="json")
        if observation.release_id != self.binding.release_id:
            raise RuleRejected(EvidenceReason.EXPECTED_EFFECT_MISMATCH)
        revision = getattr(observation, "revision", None)
        if self.binding.revision is not None and revision != self.binding.revision:
            raise RuleRejected(EvidenceReason.EXPECTED_EFFECT_MISMATCH)
        if type(observation) is _RevisionObservation and self.binding.is_stage:
            if (
                observation.release_label != self.binding.release_id
                or observation.image_digest != self.binding.image_digest
                or observation.configuration_sha256 != self.binding.configuration_sha256
            ):
                raise RuleRejected(EvidenceReason.EXPECTED_EFFECT_MISMATCH)
        if type(observation) is _OperationObservation:
            if (
                self.binding.operation_name is None
                or observation.operation_name != self.binding.operation_name
                or observation.revision
                != (self.binding.revision or self.binding.operation_revision)
            ):
                raise RuleRejected(EvidenceReason.EXPECTED_EFFECT_MISMATCH)

        states = _states(self.capability_name, observation, effects)
        definitive = set(states.values()) - {EffectAssertionState.UNVERIFIED}
        operation_status = None
        if type(observation) is _OperationObservation:
            operation_status = {
                "RUNNING": OperationStatus.ACTIVE,
                "SUCCEEDED": OperationStatus.TERMINAL_COMMITTED,
                "FAILED": OperationStatus.UNRESOLVED,
            }[observation.operation_state]
            if observation.operation_state != "SUCCEEDED":
                verdict = RuleVerdict.AUTHORITATIVE_PENDING
            elif EffectAssertionState.ESTABLISHED in definitive:
                verdict = RuleVerdict.AUTHORITATIVE_EFFECTS
            else:
                operation_status = None
                verdict = RuleVerdict.ABSENCE_ONLY
        elif EffectAssertionState.ESTABLISHED in definitive:
            verdict = RuleVerdict.AUTHORITATIVE_EFFECTS
        else:
            # RuleObservation deliberately has no target-state verdict for a lone
            # negative assertion.  Preserve safety by weakening it to unverified;
            # collective recovery rules still prevent a commit classification.
            states = {key: EffectAssertionState.UNVERIFIED for key in states}
            verdict = RuleVerdict.ABSENCE_ONLY
        assertions = tuple(
            EffectAssertion(effect_id=effect_id, state=states[effect_id])
            for effect_id in effects
        )
        return RuleObservation(
            target=envelope.target,
            source_record=_source_record(
                envelope.target, self.capability_name, observation
            ),
            observed_at=raw.observed_at,
            operation_id=(
                envelope.operation_id
                if verdict
                in {
                    RuleVerdict.AUTHORITATIVE_EFFECTS,
                    RuleVerdict.AUTHORITATIVE_PENDING,
                }
                else None
            ),
            correlation=correlation,
            effect_assertions=assertions,
            operation_status=operation_status,
            verdict=verdict,
        )


def build_cloud_run_rule_descriptor(*, capability_name: str) -> TargetRuleDescriptor:
    if capability_name not in _CAPABILITIES:
        raise ValueError("Cloud Run capability is outside the sealed inventory")
    health = capability_name == CLOUD_RUN_HEALTH_CAPABILITY
    return TargetRuleDescriptor(
        target_kind=CLOUD_RUN_SERVICE_TARGET_KIND,
        capability_name=capability_name,
        capability_version=RECOVERY_CAPABILITY_VERSION,
        authority_policy_version=CLOUD_RUN_AUTHORITY_POLICY_VERSION,
        classification_policy_version=CLOUD_RUN_CLASSIFICATION_POLICY_VERSION,
        source=CLOUD_RUN_HEALTH_SOURCE if health else CLOUD_RUN_PROVIDER_SOURCE,
        adapter_version=(
            CLOUD_RUN_HEALTH_ADAPTER_VERSION
            if health
            else CLOUD_RUN_PROVIDER_ADAPTER_VERSION
        ),
    )


def build_cloud_run_rule_registration(
    *, capability_name: str, binding: CloudRunProbeBinding
) -> TargetRuleRegistration:
    return TargetRuleRegistration(
        descriptor=build_cloud_run_rule_descriptor(capability_name=capability_name),
        normalizer=CloudRunObservationNormalizer(
            capability_name=capability_name,
            binding=binding,
        ),
    )


__all__ = [
    "CLOUD_RUN_AUTHORITY_POLICY_VERSION",
    "CLOUD_RUN_CLASSIFICATION_POLICY_VERSION",
    "CLOUD_RUN_HEALTH_CAPABILITY",
    "CLOUD_RUN_OPERATION_CAPABILITY",
    "CLOUD_RUN_REVISION_CAPABILITY",
    "CLOUD_RUN_SERVICE_CAPABILITY",
    "CloudRunObservationNormalizer",
    "CloudRunProbeBinding",
    "build_cloud_run_capability",
    "build_cloud_run_capability_registration",
    "build_cloud_run_rule_descriptor",
    "build_cloud_run_rule_registration",
    "build_cloud_run_target",
]
