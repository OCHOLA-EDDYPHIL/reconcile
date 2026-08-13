"""Strict public payloads for bounded advisory evidence planning."""

from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from enum import StrEnum
from typing import Literal

from jsonschema import Draft202012Validator
from jsonschema.exceptions import SchemaError
from pydantic import Field, JsonValue, model_validator

from reconcile.contracts.base import (
    AwareDatetime,
    Identifier,
    JsonObject,
    Sha256Digest,
    ShortText,
    StrictModel,
    reject_sensitive_keys,
)
from reconcile.contracts.envelope import ExecutionEnvelope, ProbeRequest
from reconcile.contracts.evidence import (
    EffectAssertion,
    EvidenceReason,
    OperationStatus,
)

ADAPTIVE_PLANNER_INPUT_VERSION = "reconcile/adaptive-planner-input/v1"
ADAPTIVE_PLANNER_OUTPUT_VERSION = "reconcile/adaptive-planner-output/v1"

_MAX_SIGNED_64 = 2**63 - 1
_TARGET_COORDINATE_TOKENS = frozenset(
    {
        "address",
        "bucket",
        "database",
        "document",
        "domain",
        "endpoint",
        "host",
        "hostname",
        "method",
        "object",
        "path",
        "port",
        "project",
        "resource",
        "scope",
        "target",
        "uri",
        "url",
    }
)
_ADMITTED_REASONS = frozenset(
    {
        EvidenceReason.AUTHORITATIVE_ACTIVE_STATUS,
        EvidenceReason.AUTHORITATIVE_AFFIRMATIVE_NON_EXECUTION,
        EvidenceReason.AUTHORITATIVE_EXACT_CORRELATION,
    }
)
_WEAK_REASONS = frozenset(
    {
        EvidenceReason.NON_AUTHORITATIVE_LOG_ONLY,
        EvidenceReason.NOT_FOUND_ABSENCE_ONLY,
    }
)


def _iter_object_keys(value: JsonValue) -> Sequence[str]:
    keys: list[str] = []
    if isinstance(value, Mapping):
        for key, item in value.items():
            words = re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", key).lower()
            keys.extend(part for part in re.split(r"[^a-z0-9]+", words) if part)
            keys.extend(_iter_object_keys(item))
    elif isinstance(value, list):
        for item in value:
            keys.extend(_iter_object_keys(item))
    return keys


def _validate_argument_schema(value: JsonObject) -> None:
    if value.get("type") != "object":
        raise ValueError("planner capability schemas must describe an object")
    if value.get("additionalProperties") is not False:
        raise ValueError("planner capability schemas must reject extra properties")
    if value.get("$schema") != Draft202012Validator.META_SCHEMA["$id"]:
        raise ValueError("planner capability schemas must declare JSON Schema 2020-12")
    try:
        Draft202012Validator.check_schema(value)
    except SchemaError as error:
        raise ValueError("planner capability schema is invalid") from error

    def reject_indirection(item: JsonValue, *, root: bool = True) -> None:
        if isinstance(item, Mapping):
            for key, nested in item.items():
                if key.startswith("$") and (key != "$schema" or not root):
                    raise ValueError(
                        "planner capability schemas cannot use indirection"
                    )
                reject_indirection(nested, root=False)
        elif isinstance(item, list):
            for nested in item:
                reject_indirection(nested, root=False)

    reject_indirection(value)
    reject_sensitive_keys(value)
    coordinates = _TARGET_COORDINATE_TOKENS.intersection(_iter_object_keys(value))
    if coordinates:
        names = ", ".join(sorted(coordinates))
        raise ValueError(f"target coordinates are controller-owned: {names}")


def _require_unique(values: tuple[str, ...], label: str) -> None:
    if len(values) != len(set(values)):
        raise ValueError(f"{label} must be unique")


class AdaptivePlannerPhase(StrEnum):
    ACQUIRE_EVIDENCE = "ACQUIRE_EVIDENCE"
    EXPLAIN_EVIDENCE = "EXPLAIN_EVIDENCE"


class PlannerCapability(StrictModel):
    name: Identifier
    version: Identifier
    description: ShortText
    read_only: Literal[True]
    argument_schema: JsonObject
    cost_units: int = Field(ge=1, le=_MAX_SIGNED_64)
    remaining_invocations: int = Field(ge=0, le=64)

    @model_validator(mode="after")
    def validate_capability(self) -> PlannerCapability:
        _validate_argument_schema(self.argument_schema)
        return self


class PlannerAdmittedEvidence(StrictModel):
    evidence_id: Identifier
    capability_name: Identifier
    capability_version: Identifier
    reason: EvidenceReason
    effect_assertions: tuple[EffectAssertion, ...] = Field(max_length=64)
    operation_status: OperationStatus | None

    @model_validator(mode="after")
    def validate_summary(self) -> PlannerAdmittedEvidence:
        if self.reason not in _ADMITTED_REASONS:
            raise ValueError("admitted evidence requires an admitted reason")
        effect_ids = tuple(item.effect_id for item in self.effect_assertions)
        _require_unique(effect_ids, "admitted effect identifiers")
        if not self.effect_assertions and self.operation_status is None:
            raise ValueError("admitted evidence must summarize a status or effect")
        return self


class PlannerWeakEvidence(StrictModel):
    evidence_id: Identifier
    capability_name: Identifier
    capability_version: Identifier
    reason: EvidenceReason
    relevant_effect_ids: tuple[Identifier, ...] = Field(min_length=1, max_length=64)

    @model_validator(mode="after")
    def validate_summary(self) -> PlannerWeakEvidence:
        if self.reason not in _WEAK_REASONS:
            raise ValueError("weak evidence requires a weak reason")
        _require_unique(self.relevant_effect_ids, "weak evidence effect identifiers")
        return self


class PlannerRejectedEvidence(StrictModel):
    evidence_id: Identifier
    capability_name: Identifier | None
    capability_version: Identifier | None
    reason: EvidenceReason
    relevant_effect_ids: tuple[Identifier, ...] = Field(min_length=1, max_length=64)

    @model_validator(mode="after")
    def validate_summary(self) -> PlannerRejectedEvidence:
        if (self.capability_name is None) is not (self.capability_version is None):
            raise ValueError("rejected capability identity must be complete")
        if self.reason in _ADMITTED_REASONS | _WEAK_REASONS:
            raise ValueError("rejected evidence requires a rejection reason")
        _require_unique(
            self.relevant_effect_ids,
            "rejected evidence effect identifiers",
        )
        return self


class PlannerMissingEvidence(StrictModel):
    effect_id: Identifier
    reason: Identifier


class PlannerRemainingBudget(StrictModel):
    probes: int = Field(ge=0, le=64)
    elapsed_ms: int = Field(ge=0, le=_MAX_SIGNED_64)
    result_bytes: int = Field(ge=0, le=_MAX_SIGNED_64)
    cost_units: int = Field(ge=0, le=_MAX_SIGNED_64)
    deadline_at: AwareDatetime


class PlannerVersionMetadata(StrictModel):
    provider_name: Identifier
    model_name: Identifier
    adk_version: Identifier
    genai_version: Identifier
    prompt_version: Identifier
    capability_catalog_version: Identifier
    authority_policy_version: Identifier
    classification_policy_version: Identifier
    action_policy_version: Identifier
    input_schema_version: Literal[ADAPTIVE_PLANNER_INPUT_VERSION]
    output_schema_version: Literal[ADAPTIVE_PLANNER_OUTPUT_VERSION]


class AdaptivePlannerInput(StrictModel):
    schema_version: Literal[ADAPTIVE_PLANNER_INPUT_VERSION]
    phase: AdaptivePlannerPhase
    envelope: ExecutionEnvelope
    capabilities: tuple[PlannerCapability, ...] = Field(min_length=1, max_length=64)
    admitted_evidence: tuple[PlannerAdmittedEvidence, ...] = Field(max_length=64)
    weak_evidence: tuple[PlannerWeakEvidence, ...] = Field(max_length=64)
    rejected_evidence: tuple[PlannerRejectedEvidence, ...] = Field(max_length=64)
    missing_evidence: tuple[PlannerMissingEvidence, ...] = Field(max_length=64)
    prior_executable_request_hashes: tuple[Sha256Digest, ...] = Field(max_length=64)
    remaining_budget: PlannerRemainingBudget
    versions: PlannerVersionMetadata

    @model_validator(mode="after")
    def validate_input(self) -> AdaptivePlannerInput:
        catalog = tuple((item.name, item.version) for item in self.capabilities)
        _require_unique(catalog, "planner capability identities")  # type: ignore[arg-type]
        enabled = {
            (item.name, item.version)
            for item in self.envelope.context.enabled_capabilities
        }
        if set(catalog) != enabled:
            raise ValueError("planner capabilities must match the enabled catalog")

        evidence_ids = tuple(
            item.evidence_id
            for collection in (
                self.admitted_evidence,
                self.weak_evidence,
                self.rejected_evidence,
            )
            for item in collection
        )
        _require_unique(evidence_ids, "planner evidence identifiers")
        _require_unique(
            self.prior_executable_request_hashes,
            "prior executable request hashes",
        )
        missing_effect_ids = tuple(item.effect_id for item in self.missing_evidence)
        _require_unique(missing_effect_ids, "missing effect identifiers")

        expected_effect_ids = {
            item.effect_id for item in self.envelope.expected_effects
        }
        referenced_effect_ids = set(missing_effect_ids)
        for item in self.admitted_evidence:
            referenced_effect_ids.update(
                assertion.effect_id for assertion in item.effect_assertions
            )
        for collection in (self.weak_evidence, self.rejected_evidence):
            for item in collection:
                referenced_effect_ids.update(item.relevant_effect_ids)
        if not referenced_effect_ids <= expected_effect_ids:
            raise ValueError("planner summaries reference an unexpected effect")

        catalog_set = set(catalog)
        for collection in (self.admitted_evidence, self.weak_evidence):
            if any(
                (item.capability_name, item.capability_version) not in catalog_set
                for item in collection
            ):
                raise ValueError("planner evidence references an unknown capability")
        if any(
            item.capability_name is not None
            and (item.capability_name, item.capability_version) not in catalog_set
            for item in self.rejected_evidence
        ):
            raise ValueError("rejected evidence references an unknown capability")

        maximum = self.envelope.context.evidence_budget
        remaining = self.remaining_budget
        if (
            remaining.probes > maximum.max_probes
            or remaining.elapsed_ms > maximum.max_elapsed_ms
            or remaining.result_bytes > maximum.max_total_result_bytes
            or remaining.cost_units > maximum.max_cost_units
        ):
            raise ValueError("remaining planner budget exceeds the execution envelope")
        if remaining.deadline_at < self.envelope.invoked_at:
            raise ValueError("planner deadline cannot precede invocation")

        policies = self.envelope.context.policies
        versions = self.versions
        if (
            versions.authority_policy_version != policies.authority
            or versions.classification_policy_version != policies.classification
            or versions.action_policy_version != policies.action
        ):
            raise ValueError("planner policy versions must match the envelope")
        return self


class PlannerAcquisitionAdvice(StrictModel):
    summary: ShortText


class PlannerStopAdvice(StrictModel):
    recommend_stop: bool
    reason: ShortText


class PlannerMissingEvidenceNote(StrictModel):
    effect_ids: tuple[Identifier, ...] = Field(min_length=1, max_length=64)
    note: ShortText

    @model_validator(mode="after")
    def validate_effects(self) -> PlannerMissingEvidenceNote:
        _require_unique(self.effect_ids, "missing-note effect identifiers")
        return self


class PlannerCitationRefs(StrictModel):
    admitted_evidence_ids: tuple[Identifier, ...] = Field(max_length=64)
    weak_evidence_ids: tuple[Identifier, ...] = Field(max_length=64)
    rejected_evidence_ids: tuple[Identifier, ...] = Field(max_length=64)
    missing_effect_ids: tuple[Identifier, ...] = Field(max_length=64)

    @model_validator(mode="after")
    def validate_references(self) -> PlannerCitationRefs:
        for label, values in (
            ("admitted citation identifiers", self.admitted_evidence_ids),
            ("weak citation identifiers", self.weak_evidence_ids),
            ("rejected citation identifiers", self.rejected_evidence_ids),
            ("missing citation identifiers", self.missing_effect_ids),
        ):
            _require_unique(values, label)
        evidence_ids = (
            *self.admitted_evidence_ids,
            *self.weak_evidence_ids,
            *self.rejected_evidence_ids,
        )
        _require_unique(evidence_ids, "cross-category evidence citation identifiers")
        if not evidence_ids and not self.missing_effect_ids:
            raise ValueError("planner explanations require at least one citation")
        return self


class PlannerExplanation(StrictModel):
    summary: ShortText
    admitted_evidence: ShortText | None
    weak_evidence: ShortText | None
    rejected_evidence: ShortText | None
    missing_evidence: ShortText | None
    citations: PlannerCitationRefs

    @model_validator(mode="after")
    def validate_sections(self) -> PlannerExplanation:
        sections = (
            (self.citations.admitted_evidence_ids, self.admitted_evidence),
            (self.citations.weak_evidence_ids, self.weak_evidence),
            (self.citations.rejected_evidence_ids, self.rejected_evidence),
            (self.citations.missing_effect_ids, self.missing_evidence),
        )
        if any(references and text is None for references, text in sections):
            raise ValueError("each cited category requires its explanation section")
        if any(not references and text is not None for references, text in sections):
            raise ValueError(
                "each explanation section requires citations in its category"
            )
        return self


class AdaptivePlannerOutput(StrictModel):
    schema_version: Literal[ADAPTIVE_PLANNER_OUTPUT_VERSION]
    probe_proposals: tuple[ProbeRequest, ...] = Field(max_length=8)
    acquisition_advice: PlannerAcquisitionAdvice
    stop_advice: PlannerStopAdvice
    missing_evidence_notes: tuple[PlannerMissingEvidenceNote, ...] = Field(
        max_length=64,
    )
    explanation: PlannerExplanation


__all__ = [
    "ADAPTIVE_PLANNER_INPUT_VERSION",
    "ADAPTIVE_PLANNER_OUTPUT_VERSION",
    "AdaptivePlannerInput",
    "AdaptivePlannerOutput",
    "AdaptivePlannerPhase",
    "PlannerAcquisitionAdvice",
    "PlannerAdmittedEvidence",
    "PlannerCapability",
    "PlannerCitationRefs",
    "PlannerExplanation",
    "PlannerMissingEvidence",
    "PlannerMissingEvidenceNote",
    "PlannerRejectedEvidence",
    "PlannerRemainingBudget",
    "PlannerStopAdvice",
    "PlannerVersionMetadata",
    "PlannerWeakEvidence",
]
