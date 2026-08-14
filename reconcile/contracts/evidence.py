"""Normalized evidence and deterministic admission-decision contracts."""

from __future__ import annotations

from enum import StrEnum
from typing import Literal

from pydantic import Field, model_validator

from reconcile.contracts.base import (
    AwareDatetime,
    Identifier,
    NonEmptyText,
    StrictModel,
    reject_sensitive_keys,
    reject_sensitive_values,
)
from reconcile.contracts.common import (
    EvidenceProvenance,
    FreshnessWindow,
    RawObservationReference,
    TargetBinding,
)

NORMALIZED_EVIDENCE_VERSION = "reconcile/normalized-evidence/v1"
EVIDENCE_DECISION_VERSION = "reconcile/evidence-decision/v1"


class EvidenceAuthority(StrEnum):
    TARGET_STATE = "TARGET_STATE"
    SUPPLEMENTARY = "SUPPLEMENTARY"
    WEAK = "WEAK"


class EffectAssertionState(StrEnum):
    ESTABLISHED = "ESTABLISHED"
    NOT_ESTABLISHED = "NOT_ESTABLISHED"
    UNVERIFIED = "UNVERIFIED"


class OperationStatus(StrEnum):
    ACTIVE = "ACTIVE"
    UNRESOLVED = "UNRESOLVED"
    TERMINAL_COMMITTED = "TERMINAL_COMMITTED"
    TERMINAL_NOT_COMMITTED = "TERMINAL_NOT_COMMITTED"


class EffectAssertion(StrictModel):
    effect_id: Identifier
    state: EffectAssertionState


class NormalizedEvidence(StrictModel):
    schema_version: Literal[NORMALIZED_EVIDENCE_VERSION]
    evidence_id: Identifier
    capability_name: Identifier
    capability_version: Identifier
    target: TargetBinding
    provenance: EvidenceProvenance
    observed_at: AwareDatetime
    freshness: FreshnessWindow
    correlation: dict[Identifier, NonEmptyText] = Field(
        default_factory=dict,
        max_length=32,
    )
    authority: EvidenceAuthority
    authority_policy_version: Identifier
    effect_assertions: tuple[EffectAssertion, ...] = Field(
        default_factory=tuple,
        max_length=64,
    )
    operation_status: OperationStatus | None = None
    raw_observation: RawObservationReference

    @model_validator(mode="after")
    def validate_evidence_semantics(self) -> NormalizedEvidence:
        effect_ids = [assertion.effect_id for assertion in self.effect_assertions]
        if len(effect_ids) != len(set(effect_ids)):
            raise ValueError("effect assertions must have unique identifiers")
        reject_sensitive_keys(self.correlation)
        reject_sensitive_values(self.correlation)
        reject_sensitive_values(self.provenance.source_record)
        if (
            not self.freshness.valid_from
            <= self.observed_at
            <= self.freshness.valid_until
        ):
            raise ValueError("observation must fall inside its freshness window")
        authoritative = self.authority is EvidenceAuthority.TARGET_STATE
        if not authoritative:
            if self.operation_status is not None:
                raise ValueError(
                    "non-target evidence cannot assert authoritative operation status"
                )
            if any(
                assertion.state is not EffectAssertionState.UNVERIFIED
                for assertion in self.effect_assertions
            ):
                raise ValueError(
                    "non-target evidence cannot establish expected effects"
                )

        if self.operation_status is OperationStatus.TERMINAL_NOT_COMMITTED and any(
            assertion.state is EffectAssertionState.ESTABLISHED
            for assertion in self.effect_assertions
        ):
            raise ValueError(
                "terminal non-execution cannot coexist with an established effect"
            )
        return self


class EvidenceDisposition(StrEnum):
    ADMITTED = "ADMITTED"
    WEAK = "WEAK"
    REJECTED = "REJECTED"


class EvidenceReason(StrEnum):
    AUTHORITATIVE_EXACT_CORRELATION = "authoritative_exact_correlation"
    AUTHORITATIVE_AFFIRMATIVE_NON_EXECUTION = "authoritative_affirmative_non_execution"
    AUTHORITATIVE_ACTIVE_STATUS = "authoritative_active_status"
    NON_AUTHORITATIVE_LOG_ONLY = "non_authoritative_log_only"
    NOT_FOUND_ABSENCE_ONLY = "not_found_absence_only"
    STALE_OBSERVATION = "stale_observation"
    CORRELATION_MISMATCH = "correlation_mismatch"
    SCOPE_MISMATCH = "scope_mismatch"
    UNSUPPORTED_CAPABILITY = "unsupported_capability"
    MALFORMED_OBSERVATION = "malformed_observation"
    UNVERIFIABLE_AUTHORITY = "unverifiable_authority"
    CONFLICTING_AUTHORITY = "conflicting_authority"
    BUDGET_EXHAUSTED = "budget_exhausted"
    PROBE_TIMEOUT = "probe_timeout"
    RESULT_TOO_LARGE = "result_too_large"
    DUPLICATE_CANDIDATES = "duplicate_candidates"
    CLOCK_AMBIGUITY = "clock_ambiguity"
    EXPECTED_EFFECT_MISMATCH = "expected_effect_mismatch"


_ADMITTED_REASONS = {
    EvidenceReason.AUTHORITATIVE_ACTIVE_STATUS,
    EvidenceReason.AUTHORITATIVE_AFFIRMATIVE_NON_EXECUTION,
    EvidenceReason.AUTHORITATIVE_EXACT_CORRELATION,
}
_WEAK_REASONS = {
    EvidenceReason.NON_AUTHORITATIVE_LOG_ONLY,
    EvidenceReason.NOT_FOUND_ABSENCE_ONLY,
}


class EvidenceDecision(StrictModel):
    schema_version: Literal[EVIDENCE_DECISION_VERSION]
    evidence_id: Identifier
    disposition: EvidenceDisposition
    reason: EvidenceReason

    @model_validator(mode="after")
    def validate_reason_compatibility(self) -> EvidenceDecision:
        if self.disposition is EvidenceDisposition.ADMITTED:
            valid = self.reason in _ADMITTED_REASONS
        elif self.disposition is EvidenceDisposition.WEAK:
            valid = self.reason in _WEAK_REASONS
        else:
            valid = self.reason not in _ADMITTED_REASONS | _WEAK_REASONS
        if not valid:
            raise ValueError("evidence reason is incompatible with disposition")
        return self
