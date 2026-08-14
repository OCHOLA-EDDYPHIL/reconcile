"""Sealed target-rule registrations for deterministic evidence normalization."""

from __future__ import annotations

import inspect
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum
from threading import RLock
from types import MappingProxyType
from typing import Protocol

from pydantic import Field, model_validator

from reconcile.contracts import (
    ExecutionEnvelope,
    ProbeRequest,
    TargetBinding,
    canonical_json_bytes,
    decode_contract,
)
from reconcile.contracts.base import (
    ArgumentsObject,
    AwareDatetime,
    Identifier,
    NonEmptyText,
    StrictModel,
    reject_sensitive_keys,
    reject_sensitive_values,
)
from reconcile.contracts.evidence import (
    EffectAssertion,
    EffectAssertionState,
    EvidenceReason,
    OperationStatus,
)


class RuleVerdict(StrEnum):
    AUTHORITATIVE_EFFECTS = "AUTHORITATIVE_EFFECTS"
    AUTHORITATIVE_NON_EXECUTION = "AUTHORITATIVE_NON_EXECUTION"
    AUTHORITATIVE_PENDING = "AUTHORITATIVE_PENDING"
    SUPPLEMENTARY = "SUPPLEMENTARY"
    ABSENCE_ONLY = "ABSENCE_ONLY"


class TargetRuleDescriptor(StrictModel):
    target_kind: Identifier
    capability_name: Identifier
    capability_version: Identifier
    authority_policy_version: Identifier
    classification_policy_version: Identifier
    source: Identifier
    adapter_version: Identifier

    @property
    def key(self) -> tuple[str, str, str, str, str]:
        return (
            self.target_kind,
            self.capability_name,
            self.capability_version,
            self.authority_policy_version,
            self.classification_policy_version,
        )


class RuleObservation(StrictModel):
    target: TargetBinding
    source_record: NonEmptyText
    observed_at: AwareDatetime
    operation_id: Identifier | None = None
    correlation: dict[Identifier, NonEmptyText] = Field(
        default_factory=dict,
        max_length=32,
    )
    effect_assertions: tuple[EffectAssertion, ...] = Field(
        default_factory=tuple,
        max_length=64,
    )
    operation_status: OperationStatus | None = None
    verdict: RuleVerdict

    @model_validator(mode="after")
    def validate_verdict(self) -> RuleObservation:
        reject_sensitive_keys(self.correlation)
        reject_sensitive_values(self.correlation)
        reject_sensitive_values(self.source_record)
        effect_ids = [item.effect_id for item in self.effect_assertions]
        if len(effect_ids) != len(set(effect_ids)):
            raise ValueError("rule effect assertions must be unique")
        states = {item.state for item in self.effect_assertions}
        if self.verdict is RuleVerdict.AUTHORITATIVE_EFFECTS:
            if (
                EffectAssertionState.ESTABLISHED not in states
                or self.operation_status
                not in {None, OperationStatus.TERMINAL_COMMITTED}
            ):
                raise ValueError("authoritative effect verdict is inconsistent")
        elif self.verdict is RuleVerdict.AUTHORITATIVE_NON_EXECUTION:
            if (
                self.operation_status is not OperationStatus.TERMINAL_NOT_COMMITTED
                or EffectAssertionState.ESTABLISHED in states
            ):
                raise ValueError("non-execution verdict requires terminal authority")
        elif self.verdict is RuleVerdict.AUTHORITATIVE_PENDING:
            if (
                self.operation_status
                not in {
                    OperationStatus.ACTIVE,
                    OperationStatus.UNRESOLVED,
                }
                or EffectAssertionState.NOT_ESTABLISHED in states
            ):
                raise ValueError("pending verdict requires an active target status")
        elif self.operation_status is not None or states - {
            EffectAssertionState.UNVERIFIED
        }:
            raise ValueError("weak rule verdict cannot assert target state")
        return self


class RuleRequest(StrictModel):
    """Rationale-free executable probe input visible to target rules."""

    capability_name: Identifier
    capability_version: Identifier
    relevant_effect_ids: tuple[Identifier, ...] = Field(min_length=1, max_length=64)
    arguments: ArgumentsObject = Field(default_factory=dict)

    @model_validator(mode="after")
    def validate_effect_identity(self) -> RuleRequest:
        if len(self.relevant_effect_ids) != len(set(self.relevant_effect_ids)):
            raise ValueError("relevant effect identifiers must be unique")
        reject_sensitive_keys(self.arguments)
        return self


@dataclass(frozen=True, slots=True, init=False)
class RuleInput:
    _envelope_bytes: bytes = field(repr=False)
    _request_bytes: bytes = field(repr=False)
    observation: bytes = field(repr=False)
    retrieved_at: datetime

    def __init__(
        self,
        *,
        envelope: ExecutionEnvelope,
        request: ProbeRequest,
        observation: bytes,
        retrieved_at: datetime,
    ) -> None:
        if type(observation) is not bytes:
            raise TypeError("rule observation must be immutable bytes")
        if retrieved_at.tzinfo is None or retrieved_at.utcoffset() is None:
            raise ValueError("rule retrieval time must include a UTC offset")
        deterministic_request = RuleRequest(
            capability_name=request.capability_name,
            capability_version=request.capability_version,
            relevant_effect_ids=request.relevant_effect_ids,
            arguments=request.arguments,
        )
        object.__setattr__(self, "_envelope_bytes", canonical_json_bytes(envelope))
        object.__setattr__(
            self,
            "_request_bytes",
            canonical_json_bytes(deterministic_request),
        )
        object.__setattr__(self, "observation", observation)
        object.__setattr__(self, "retrieved_at", retrieved_at.astimezone(UTC))

    @property
    def envelope(self) -> ExecutionEnvelope:
        return decode_contract(self._envelope_bytes, ExecutionEnvelope)

    @property
    def request(self) -> RuleRequest:
        return RuleRequest.model_validate_json(self._request_bytes)


class TargetNormalizer(Protocol):
    def __call__(self, rule_input: RuleInput) -> RuleObservation: ...


class RuleRejected(ValueError):
    _ALLOWED_REASONS = frozenset(
        {
            EvidenceReason.DUPLICATE_CANDIDATES,
            EvidenceReason.EXPECTED_EFFECT_MISMATCH,
            EvidenceReason.MALFORMED_OBSERVATION,
            EvidenceReason.UNVERIFIABLE_AUTHORITY,
        }
    )

    def __init__(self, reason: EvidenceReason) -> None:
        if reason not in self._ALLOWED_REASONS:
            raise ValueError("rule rejection reason is not permitted")
        self.reason = reason
        super().__init__(reason.value)


class DuplicateTargetRule(ValueError):
    pass


class TargetRuleRegistryFrozen(RuntimeError):
    pass


@dataclass(frozen=True, slots=True, init=False)
class TargetRuleRegistration:
    _descriptor_bytes: bytes = field(repr=False)
    normalizer: TargetNormalizer = field(repr=False, compare=False)

    def __init__(
        self,
        *,
        descriptor: TargetRuleDescriptor,
        normalizer: TargetNormalizer,
    ) -> None:
        if type(descriptor) is not TargetRuleDescriptor:
            raise TypeError("target rule descriptor must be exact")
        if not callable(normalizer) or inspect.iscoroutinefunction(normalizer):
            raise TypeError("target rule normalizer must be synchronous")
        call = type(normalizer).__call__
        if inspect.iscoroutinefunction(call):
            raise TypeError("target rule normalizer must be synchronous")
        object.__setattr__(
            self,
            "_descriptor_bytes",
            descriptor.model_dump_json().encode("utf-8"),
        )
        object.__setattr__(self, "normalizer", normalizer)

    @property
    def descriptor(self) -> TargetRuleDescriptor:
        return TargetRuleDescriptor.model_validate_json(self._descriptor_bytes)

    @property
    def key(self) -> tuple[str, str, str, str, str]:
        return self.descriptor.key

    def isolated_copy(self) -> TargetRuleRegistration:
        return TargetRuleRegistration(
            descriptor=self.descriptor,
            normalizer=self.normalizer,
        )


class TargetRuleRegistry:
    def __init__(self) -> None:
        self._lock = RLock()
        self._registrations: dict[
            tuple[str, str, str, str, str], TargetRuleRegistration
        ] = {}
        self._snapshot: (
            MappingProxyType[tuple[str, str, str, str, str], TargetRuleRegistration]
            | None
        ) = None

    @property
    def is_frozen(self) -> bool:
        with self._lock:
            return self._snapshot is not None

    def register(self, registration: TargetRuleRegistration) -> None:
        if type(registration) is not TargetRuleRegistration:
            raise TypeError("registration must be a target rule registration")
        with self._lock:
            if self._snapshot is not None:
                raise TargetRuleRegistryFrozen("target rule registry is frozen")
            if registration.key in self._registrations:
                raise DuplicateTargetRule("target rule identity is already registered")
            self._registrations[registration.key] = registration.isolated_copy()

    def freeze(self) -> tuple[TargetRuleRegistration, ...]:
        with self._lock:
            if self._snapshot is None:
                self._snapshot = MappingProxyType(dict(self._registrations))
            return tuple(
                self._snapshot[key].isolated_copy() for key in sorted(self._snapshot)
            )

    def resolve(
        self,
        key: tuple[str, str, str, str, str],
    ) -> TargetRuleRegistration | None:
        if (
            type(key) is not tuple
            or len(key) != 5
            or any(type(item) is not str for item in key)
        ):
            return None
        with self._lock:
            if self._snapshot is None:
                self._snapshot = MappingProxyType(dict(self._registrations))
            registration = self._snapshot.get(key)
            return registration.isolated_copy() if registration is not None else None


__all__ = [
    "DuplicateTargetRule",
    "RuleInput",
    "RuleObservation",
    "RuleRejected",
    "RuleRequest",
    "RuleVerdict",
    "TargetNormalizer",
    "TargetRuleDescriptor",
    "TargetRuleRegistration",
    "TargetRuleRegistry",
    "TargetRuleRegistryFrozen",
]
