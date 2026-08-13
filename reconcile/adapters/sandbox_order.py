"""Deliberately weak local sandbox-order observations and evidence rules."""

from __future__ import annotations

import asyncio
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Literal

from reconcile.contracts import (
    OBSERVATION_CAPABILITY_VERSION,
    EffectAssertion,
    EffectAssertionState,
    EvidenceReason,
    ExecutionEnvelope,
    ObservationCapability,
    TargetBinding,
    TargetConstraint,
    canonical_json_bytes,
)
from reconcile.contracts.base import (
    AwareDatetime,
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
    RuleRequest,
    RuleVerdict,
    TargetRuleDescriptor,
    TargetRuleRegistration,
)
from reconcile.scenarios.local_order import (
    LocalOrderReadTarget,
    WeakIngressObservation,
    WeakOrderAggregateObservation,
    WeakOrderCountBand,
)

SANDBOX_ORDER_TARGET_KIND = "sandbox.order"
SANDBOX_ORDER_ENVIRONMENT = "local-sandbox-sqlite"
SANDBOX_ORDER_INGRESS_CAPABILITY_NAME = "sandbox-order-ingress-observation"
SANDBOX_ORDER_AGGREGATE_CAPABILITY_NAME = "sandbox-order-aggregate-observation"
SANDBOX_ORDER_CAPABILITY_VERSION = "1.0.0"
SANDBOX_ORDER_AUTHORITY_POLICY_VERSION = "authority-local-sandbox-order-weak-v1"
SANDBOX_ORDER_CLASSIFICATION_POLICY_VERSION = "classification-v1"
SANDBOX_ORDER_ADAPTER_VERSION = "1.0.0"
SANDBOX_ORDER_INGRESS_SOURCE = "local-sandbox-order-weak-ingress"
SANDBOX_ORDER_AGGREGATE_SOURCE = "local-sandbox-order-weak-aggregate"

_ARGUMENT_BYTE_CEILING = 2
_RESULT_BYTE_CEILING = 4_096
_TIMEOUT_MS = 2_000
_OBSERVATION_SET = "weak-order-observations"
_TARGET_SCOPE_KEYS = frozenset({"environment", "sandbox_id"})
_TARGET_RESOURCE_KEYS = frozenset({"observation_set"})


class _IngressObservationPayload(StrictModel):
    event_kind: Literal["REQUEST_SEEN"]
    observed_at: AwareDatetime


class _IngressReadPayload(StrictModel):
    ingress: _IngressObservationPayload | None


class _AggregateObservationPayload(StrictModel):
    count_band: WeakOrderCountBand
    observed_at: AwareDatetime


class _AggregateReadPayload(StrictModel):
    aggregate: _AggregateObservationPayload | None


def _bounded_coordinate(value: object, label: str) -> str:
    if type(value) is not str or not 1 <= len(value) <= 1_024:
        raise ValueError(f"{label} must be a bounded nonempty string")
    try:
        value.encode("utf-8")
    except UnicodeEncodeError as error:
        raise ValueError(f"{label} must contain Unicode scalar values") from error
    return value


def build_sandbox_order_target(*, sandbox_id: str) -> TargetBinding:
    """Build the exact local weak-observation target for one sandbox."""

    return TargetBinding(
        target_kind=SANDBOX_ORDER_TARGET_KIND,
        scope={
            "environment": SANDBOX_ORDER_ENVIRONMENT,
            "sandbox_id": _bounded_coordinate(sandbox_id, "sandbox identifier"),
        },
        resource={"observation_set": _OBSERVATION_SET},
    )


def _target_coordinates(target: TargetBinding) -> str:
    if target.target_kind != SANDBOX_ORDER_TARGET_KIND:
        raise ValueError("sandbox-order target kind is not supported")
    if set(target.scope) != _TARGET_SCOPE_KEYS:
        raise ValueError("sandbox-order target scope is not exact")
    if target.scope.get("environment") != SANDBOX_ORDER_ENVIRONMENT:
        raise ValueError("sandbox-order target is not the local sandbox")
    sandbox_id = _bounded_coordinate(
        target.scope.get("sandbox_id"),
        "sandbox identifier",
    )
    if (
        set(target.resource) != _TARGET_RESOURCE_KEYS
        or target.resource.get("observation_set") != _OBSERVATION_SET
    ):
        raise ValueError("sandbox-order target resource is not exact")
    return sandbox_id


def _empty_argument_capability(
    *,
    target: TargetBinding,
    name: str,
) -> ObservationCapability:
    _target_coordinates(target)
    return ObservationCapability(
        schema_version=OBSERVATION_CAPABILITY_VERSION,
        name=name,
        version=SANDBOX_ORDER_CAPABILITY_VERSION,
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
        timeout_ms=_TIMEOUT_MS,
        result_byte_ceiling=_RESULT_BYTE_CEILING,
        cost_units=1,
    )


def build_sandbox_order_ingress_capability(
    target: TargetBinding,
) -> ObservationCapability:
    """Build the allowlisted generic-ingress read for one local sandbox."""

    return _empty_argument_capability(
        target=target,
        name=SANDBOX_ORDER_INGRESS_CAPABILITY_NAME,
    )


def build_sandbox_order_aggregate_capability(
    target: TargetBinding,
) -> ObservationCapability:
    """Build the allowlisted coarse-count read for one local sandbox."""

    return _empty_argument_capability(
        target=target,
        name=SANDBOX_ORDER_AGGREGATE_CAPABILITY_NAME,
    )


def _ingress_payload(
    ingress: WeakIngressObservation | None,
) -> dict[str, object]:
    return {
        "ingress": (
            None
            if ingress is None
            else {
                "event_kind": ingress.event_kind,
                "observed_at": ingress.observed_at.isoformat(),
            }
        )
    }


def _aggregate_payload(
    aggregate: WeakOrderAggregateObservation | None,
) -> dict[str, object]:
    return {
        "aggregate": (
            None
            if aggregate is None
            else {
                "count_band": aggregate.count_band.value,
                "observed_at": aggregate.observed_at.isoformat(),
            }
        )
    }


def _probe_is_exact(
    probe: BoundProbe,
    *,
    capability_name: str,
    target_bytes: bytes,
) -> bool:
    return (
        probe.capability_name == capability_name
        and probe.capability_version == SANDBOX_ORDER_CAPABILITY_VERSION
        and canonical_json_bytes(probe.target) == target_bytes
        and probe.arguments == {}
    )


def _read_at(clock: Callable[[], datetime]) -> datetime:
    value = clock()
    if not isinstance(value, datetime) or value.tzinfo is None:
        raise CapabilityUnavailable
    if value.utcoffset() is None:
        raise CapabilityUnavailable
    return value.astimezone(UTC)


@dataclass(frozen=True, slots=True)
class _SandboxOrderIngressReadHandler:
    read_target: LocalOrderReadTarget = field(repr=False, compare=False)
    target_bytes: bytes = field(repr=False)
    clock: Callable[[], datetime] = field(repr=False, compare=False)

    async def __call__(self, probe: BoundProbe) -> ProbeObservation:
        if not _probe_is_exact(
            probe,
            capability_name=SANDBOX_ORDER_INGRESS_CAPABILITY_NAME,
            target_bytes=self.target_bytes,
        ):
            raise CapabilityUnavailable
        try:
            ingress = await asyncio.to_thread(self.read_target.read_ingress)
        except Exception as error:
            raise CapabilityUnavailable from error
        if ingress is not None and type(ingress) is not WeakIngressObservation:
            raise CapabilityUnavailable
        return ProbeObservation(
            observed_at=_read_at(self.clock),
            payload=_ingress_payload(ingress),
        )


@dataclass(frozen=True, slots=True)
class _SandboxOrderAggregateReadHandler:
    read_target: LocalOrderReadTarget = field(repr=False, compare=False)
    target_bytes: bytes = field(repr=False)
    clock: Callable[[], datetime] = field(repr=False, compare=False)

    async def __call__(self, probe: BoundProbe) -> ProbeObservation:
        if not _probe_is_exact(
            probe,
            capability_name=SANDBOX_ORDER_AGGREGATE_CAPABILITY_NAME,
            target_bytes=self.target_bytes,
        ):
            raise CapabilityUnavailable
        try:
            aggregate = await asyncio.to_thread(self.read_target.read_aggregate)
        except Exception as error:
            raise CapabilityUnavailable from error
        if (
            aggregate is not None
            and type(aggregate) is not WeakOrderAggregateObservation
        ):
            raise CapabilityUnavailable
        return ProbeObservation(
            observed_at=_read_at(self.clock),
            payload=_aggregate_payload(aggregate),
        )


def _capability_registration(
    *,
    read_target: LocalOrderReadTarget,
    target: TargetBinding,
    capability: ObservationCapability,
    handler: _SandboxOrderIngressReadHandler | _SandboxOrderAggregateReadHandler,
) -> CapabilityRegistration:
    if type(read_target) is not LocalOrderReadTarget:
        raise TypeError("sandbox-order capability requires the restricted read target")
    return CapabilityRegistration(
        capability=capability,
        semantics=CapabilitySemantics.READ_ONLY,
        enabled=True,
        argument_byte_ceiling=_ARGUMENT_BYTE_CEILING,
        max_invocations=1,
        handler=handler,
    )


def build_sandbox_order_ingress_capability_registration(
    *,
    read_target: LocalOrderReadTarget,
    target: TargetBinding,
    clock: Callable[[], datetime] | None = None,
) -> CapabilityRegistration:
    """Register the generic ingress read without private order access."""

    if type(read_target) is not LocalOrderReadTarget:
        raise TypeError("sandbox-order capability requires the restricted read target")
    return _capability_registration(
        read_target=read_target,
        target=target,
        capability=build_sandbox_order_ingress_capability(target),
        handler=_SandboxOrderIngressReadHandler(
            read_target=read_target,
            target_bytes=canonical_json_bytes(target),
            clock=clock or (lambda: datetime.now(UTC)),
        ),
    )


def build_sandbox_order_aggregate_capability_registration(
    *,
    read_target: LocalOrderReadTarget,
    target: TargetBinding,
    clock: Callable[[], datetime] | None = None,
) -> CapabilityRegistration:
    """Register the coarse aggregate read without private order access."""

    if type(read_target) is not LocalOrderReadTarget:
        raise TypeError("sandbox-order capability requires the restricted read target")
    return _capability_registration(
        read_target=read_target,
        target=target,
        capability=build_sandbox_order_aggregate_capability(target),
        handler=_SandboxOrderAggregateReadHandler(
            read_target=read_target,
            target_bytes=canonical_json_bytes(target),
            clock=clock or (lambda: datetime.now(UTC)),
        ),
    )


def _parse_ingress_observation(
    rule_input: RuleInput,
) -> tuple[ProbeObservation, _IngressReadPayload]:
    try:
        observation = ProbeObservation.model_validate_json(rule_input.observation)
        payload = _IngressReadPayload.model_validate_json(
            canonical_json_value_bytes(observation.payload)
        )
    except (TypeError, ValueError) as error:
        raise RuleRejected(EvidenceReason.MALFORMED_OBSERVATION) from error
    return observation, payload


def _parse_aggregate_observation(
    rule_input: RuleInput,
) -> tuple[ProbeObservation, _AggregateReadPayload]:
    try:
        observation = ProbeObservation.model_validate_json(rule_input.observation)
        payload = _AggregateReadPayload.model_validate_json(
            canonical_json_value_bytes(observation.payload)
        )
    except (TypeError, ValueError) as error:
        raise RuleRejected(EvidenceReason.MALFORMED_OBSERVATION) from error
    return observation, payload


def _validate_request(
    *,
    envelope: ExecutionEnvelope,
    request: RuleRequest,
    capability_name: str,
) -> None:
    if (
        request.capability_name != capability_name
        or request.capability_version != SANDBOX_ORDER_CAPABILITY_VERSION
        or request.arguments != {}
    ):
        raise RuleRejected(EvidenceReason.MALFORMED_OBSERVATION)
    try:
        _target_coordinates(envelope.target)
    except (TypeError, ValueError) as error:
        raise RuleRejected(EvidenceReason.UNVERIFIABLE_AUTHORITY) from error
    expected_effect_ids = tuple(
        effect.effect_id for effect in envelope.expected_effects
    )
    if tuple(request.relevant_effect_ids) != expected_effect_ids:
        raise RuleRejected(EvidenceReason.EXPECTED_EFFECT_MISMATCH)
    if envelope.context.correlation_fields:
        raise RuleRejected(EvidenceReason.UNVERIFIABLE_AUTHORITY)


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
    source_record: str,
    verdict: RuleVerdict,
) -> RuleObservation:
    return RuleObservation(
        target=envelope.target,
        source_record=source_record,
        observed_at=observed_at,
        correlation={},
        effect_assertions=tuple(
            EffectAssertion(
                effect_id=effect_id,
                state=EffectAssertionState.UNVERIFIED,
            )
            for effect_id in request.relevant_effect_ids
        ),
        verdict=verdict,
    )


class SandboxOrderIngressNormalizer:
    """Normalize a generic ingress log without assigning target authority."""

    def __call__(self, rule_input: RuleInput) -> RuleObservation:
        if type(rule_input) is not RuleInput:
            raise RuleRejected(EvidenceReason.MALFORMED_OBSERVATION)
        envelope = rule_input.envelope
        request = rule_input.request
        _validate_request(
            envelope=envelope,
            request=request,
            capability_name=SANDBOX_ORDER_INGRESS_CAPABILITY_NAME,
        )
        observation, payload = _parse_ingress_observation(rule_input)
        ingress = payload.ingress
        observed_at = (
            observation.observed_at if ingress is None else ingress.observed_at
        )
        if not _fresh_timestamp(
            observed_at=observed_at,
            read_at=observation.observed_at,
            retrieved_at=rule_input.retrieved_at,
            envelope=envelope,
        ):
            raise RuleRejected(EvidenceReason.UNVERIFIABLE_AUTHORITY)
        return _weak_observation(
            envelope=envelope,
            request=request,
            observed_at=observed_at,
            source_record=(
                "weak-ingress-missing"
                if ingress is None
                else "weak-ingress-request-seen"
            ),
            verdict=(
                RuleVerdict.ABSENCE_ONLY
                if ingress is None
                else RuleVerdict.SUPPLEMENTARY
            ),
        )


class SandboxOrderAggregateNormalizer:
    """Normalize a coarse order count without assigning target authority."""

    def __call__(self, rule_input: RuleInput) -> RuleObservation:
        if type(rule_input) is not RuleInput:
            raise RuleRejected(EvidenceReason.MALFORMED_OBSERVATION)
        envelope = rule_input.envelope
        request = rule_input.request
        _validate_request(
            envelope=envelope,
            request=request,
            capability_name=SANDBOX_ORDER_AGGREGATE_CAPABILITY_NAME,
        )
        observation, payload = _parse_aggregate_observation(rule_input)
        aggregate = payload.aggregate
        observed_at = (
            observation.observed_at if aggregate is None else aggregate.observed_at
        )
        if not _fresh_timestamp(
            observed_at=observed_at,
            read_at=observation.observed_at,
            retrieved_at=rule_input.retrieved_at,
            envelope=envelope,
        ):
            raise RuleRejected(EvidenceReason.UNVERIFIABLE_AUTHORITY)
        return _weak_observation(
            envelope=envelope,
            request=request,
            observed_at=observed_at,
            source_record=(
                "weak-order-aggregate-missing"
                if aggregate is None
                else f"weak-order-count-{aggregate.count_band.value.lower()}"
            ),
            verdict=(
                RuleVerdict.ABSENCE_ONLY
                if aggregate is None
                else RuleVerdict.SUPPLEMENTARY
            ),
        )


def _rule_descriptor(*, capability_name: str, source: str) -> TargetRuleDescriptor:
    return TargetRuleDescriptor(
        target_kind=SANDBOX_ORDER_TARGET_KIND,
        capability_name=capability_name,
        capability_version=SANDBOX_ORDER_CAPABILITY_VERSION,
        authority_policy_version=SANDBOX_ORDER_AUTHORITY_POLICY_VERSION,
        classification_policy_version=SANDBOX_ORDER_CLASSIFICATION_POLICY_VERSION,
        source=source,
        adapter_version=SANDBOX_ORDER_ADAPTER_VERSION,
    )


def build_sandbox_order_ingress_rule_descriptor() -> TargetRuleDescriptor:
    """Build the deterministic generic-ingress rule identity."""

    return _rule_descriptor(
        capability_name=SANDBOX_ORDER_INGRESS_CAPABILITY_NAME,
        source=SANDBOX_ORDER_INGRESS_SOURCE,
    )


def build_sandbox_order_aggregate_rule_descriptor() -> TargetRuleDescriptor:
    """Build the deterministic coarse-aggregate rule identity."""

    return _rule_descriptor(
        capability_name=SANDBOX_ORDER_AGGREGATE_CAPABILITY_NAME,
        source=SANDBOX_ORDER_AGGREGATE_SOURCE,
    )


def build_sandbox_order_ingress_rule_registration() -> TargetRuleRegistration:
    """Register the weak ingress normalizer under its sealed identity."""

    return TargetRuleRegistration(
        descriptor=build_sandbox_order_ingress_rule_descriptor(),
        normalizer=SandboxOrderIngressNormalizer(),
    )


def build_sandbox_order_aggregate_rule_registration() -> TargetRuleRegistration:
    """Register the weak aggregate normalizer under its sealed identity."""

    return TargetRuleRegistration(
        descriptor=build_sandbox_order_aggregate_rule_descriptor(),
        normalizer=SandboxOrderAggregateNormalizer(),
    )


__all__ = [
    "SANDBOX_ORDER_ADAPTER_VERSION",
    "SANDBOX_ORDER_AGGREGATE_CAPABILITY_NAME",
    "SANDBOX_ORDER_AGGREGATE_SOURCE",
    "SANDBOX_ORDER_AUTHORITY_POLICY_VERSION",
    "SANDBOX_ORDER_CAPABILITY_VERSION",
    "SANDBOX_ORDER_CLASSIFICATION_POLICY_VERSION",
    "SANDBOX_ORDER_ENVIRONMENT",
    "SANDBOX_ORDER_INGRESS_CAPABILITY_NAME",
    "SANDBOX_ORDER_INGRESS_SOURCE",
    "SANDBOX_ORDER_TARGET_KIND",
    "SandboxOrderAggregateNormalizer",
    "SandboxOrderIngressNormalizer",
    "build_sandbox_order_aggregate_capability",
    "build_sandbox_order_aggregate_capability_registration",
    "build_sandbox_order_aggregate_rule_descriptor",
    "build_sandbox_order_aggregate_rule_registration",
    "build_sandbox_order_ingress_capability",
    "build_sandbox_order_ingress_capability_registration",
    "build_sandbox_order_ingress_rule_descriptor",
    "build_sandbox_order_ingress_rule_registration",
    "build_sandbox_order_target",
]
