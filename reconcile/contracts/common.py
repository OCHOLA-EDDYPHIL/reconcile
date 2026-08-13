"""Nested contract values shared across public payloads."""

from __future__ import annotations

import hashlib
from enum import StrEnum

from pydantic import Field, model_validator

from reconcile.contracts.base import (
    ArgumentsObject,
    AwareDatetime,
    Identifier,
    NonEmptySmallJsonObject,
    NonEmptyText,
    Sha256Digest,
    ShortText,
    StrictModel,
    canonical_json_value_bytes,
    reject_sensitive_keys,
)


class Classification(StrEnum):
    COMMITTED = "COMMITTED"
    NOT_COMMITTED = "NOT_COMMITTED"
    PARTIAL = "PARTIAL"
    PENDING = "PENDING"
    UNKNOWN = "UNKNOWN"


class AmbiguityKind(StrEnum):
    TIMEOUT = "TIMEOUT"
    CONNECTION_RESET = "CONNECTION_RESET"
    PROCESS_INTERRUPTED = "PROCESS_INTERRUPTED"
    MISSING_TOOL_RESULT = "MISSING_TOOL_RESULT"
    PROVIDER_UNAVAILABLE = "PROVIDER_UNAVAILABLE"
    OTHER = "OTHER"


class AmbiguousExecution(StrictModel):
    kind: AmbiguityKind
    observed_at: AwareDatetime
    detail: ShortText | None = None


class CapabilityRef(StrictModel):
    name: Identifier
    version: Identifier


class TargetBinding(StrictModel):
    target_kind: Identifier
    scope: NonEmptySmallJsonObject
    resource: NonEmptySmallJsonObject

    @model_validator(mode="after")
    def validate_no_credentials(self) -> TargetBinding:
        reject_sensitive_keys(self.scope)
        reject_sensitive_keys(self.resource)
        return self


class TargetConstraint(StrictModel):
    """An exact provider-neutral target scope admitted by a capability."""

    target_kind: Identifier
    scope: NonEmptySmallJsonObject

    @model_validator(mode="after")
    def validate_no_credentials(self) -> TargetConstraint:
        reject_sensitive_keys(self.scope)
        return self


class OriginalInvocation(StrictModel):
    """Caller-redacted invocation identity and canonical public arguments."""

    invocation_id: Identifier
    function_call_id: Identifier | None = None
    tool_name: Identifier
    tool_version: Identifier
    arguments: ArgumentsObject = Field(default_factory=dict)
    arguments_sha256: Sha256Digest

    @model_validator(mode="after")
    def validate_arguments_digest(self) -> OriginalInvocation:
        reject_sensitive_keys(self.arguments)
        digest = hashlib.sha256(canonical_json_value_bytes(self.arguments)).hexdigest()
        if digest != self.arguments_sha256:
            raise ValueError("invocation argument digest does not match arguments")
        return self


class EvidenceBudget(StrictModel):
    max_probes: int = Field(ge=1, le=64)
    max_elapsed_ms: int = Field(ge=1, le=2**63 - 1)
    max_total_result_bytes: int = Field(ge=1, le=2**63 - 1)
    max_cost_units: int = Field(ge=1, le=2**63 - 1)


class FreshnessPolicy(StrictModel):
    max_age_seconds: int = Field(ge=1, le=2**63 - 1)
    clock_skew_seconds: int = Field(ge=0, le=2**63 - 1)


class PolicyReferences(StrictModel):
    authority: Identifier
    classification: Identifier
    action: Identifier


class EnvelopeContext(StrictModel):
    invocation: OriginalInvocation
    enabled_capabilities: tuple[CapabilityRef, ...] = Field(min_length=1, max_length=64)
    correlation_fields: dict[Identifier, NonEmptyText] = Field(
        default_factory=dict,
        max_length=32,
    )
    evidence_budget: EvidenceBudget
    freshness: FreshnessPolicy
    policies: PolicyReferences

    @model_validator(mode="after")
    def validate_capability_identity(self) -> EnvelopeContext:
        identities = [(item.name, item.version) for item in self.enabled_capabilities]
        if len(identities) != len(set(identities)):
            raise ValueError("enabled capability identities must be unique")
        reject_sensitive_keys(self.correlation_fields)
        return self


class RawObservationReference(StrictModel):
    sha256: Sha256Digest
    reference: Identifier
    byte_count: int = Field(ge=0, le=2**63 - 1)


class EvidenceProvenance(StrictModel):
    source: Identifier
    source_record: NonEmptyText
    adapter_version: Identifier
    retrieved_at: AwareDatetime


class FreshnessWindow(StrictModel):
    valid_from: AwareDatetime
    valid_until: AwareDatetime

    @model_validator(mode="after")
    def validate_order(self) -> FreshnessWindow:
        if self.valid_until < self.valid_from:
            raise ValueError("freshness window must be ordered")
        return self
