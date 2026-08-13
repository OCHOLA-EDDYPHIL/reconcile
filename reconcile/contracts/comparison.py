"""Neutral versioned records for fixed and adaptive investigation runs."""

from __future__ import annotations

from enum import StrEnum
from typing import Literal

from pydantic import Field, model_validator

from reconcile.contracts.base import Identifier, Sha256Digest, StrictModel
from reconcile.contracts.common import Classification
from reconcile.contracts.scenario import ScenarioRef

INVESTIGATION_COMPARISON_RECORD_VERSION = "reconcile/investigation-comparison-record/v1"

_MAX_SIGNED_64 = 2**63 - 1


class ComparisonStrategyKind(StrEnum):
    FIXED = "FIXED"
    ADAPTIVE = "ADAPTIVE"


class ComparisonModelUsageStatus(StrEnum):
    NOT_APPLICABLE = "NOT_APPLICABLE"
    MEASURED = "MEASURED"
    UNAVAILABLE = "UNAVAILABLE"


class ComparisonModelUsage(StrictModel):
    status: ComparisonModelUsageStatus
    provider_name: Identifier | None = None
    model_name: Identifier | None = None
    model_call_count: int = Field(ge=0, le=_MAX_SIGNED_64)
    input_token_count: int | None = Field(default=None, ge=0, le=_MAX_SIGNED_64)
    output_token_count: int | None = Field(default=None, ge=0, le=_MAX_SIGNED_64)
    total_token_count: int | None = Field(default=None, ge=0, le=_MAX_SIGNED_64)

    @model_validator(mode="after")
    def validate_usage(self) -> ComparisonModelUsage:
        identity_complete = (self.provider_name is None) is (self.model_name is None)
        if not identity_complete:
            raise ValueError("model provider and model identity must be complete")

        token_counts = (
            self.input_token_count,
            self.output_token_count,
            self.total_token_count,
        )
        if self.status is ComparisonModelUsageStatus.NOT_APPLICABLE:
            valid = (
                self.provider_name is None
                and self.model_call_count == 0
                and token_counts == (0, 0, 0)
            )
        elif self.status is ComparisonModelUsageStatus.MEASURED:
            valid = (
                self.provider_name is not None
                and self.model_call_count > 0
                and all(value is not None for value in token_counts)
                and self.total_token_count
                == self.input_token_count + self.output_token_count  # type: ignore[operator]
            )
        else:
            valid = (
                self.provider_name is not None
                and self.model_call_count > 0
                and token_counts == (None, None, None)
            )
        if not valid:
            raise ValueError("model usage fields do not match their status")
        return self


class ExplanationCompleteness(StrictModel):
    required_evidence_citation_count: int = Field(ge=0, le=_MAX_SIGNED_64)
    valid_evidence_citation_count: int = Field(ge=0, le=_MAX_SIGNED_64)
    missing_evidence_citation_count: int = Field(ge=0, le=_MAX_SIGNED_64)
    complete: bool

    @model_validator(mode="after")
    def validate_completeness(self) -> ExplanationCompleteness:
        if self.required_evidence_citation_count != (
            self.valid_evidence_citation_count + self.missing_evidence_citation_count
        ):
            raise ValueError("explanation citation counts must form a partition")
        if self.complete is not (self.missing_evidence_citation_count == 0):
            raise ValueError("explanation completeness must match missing citations")
        return self


class PreregisteredExpectedClassification(StrictModel):
    registration_id: Identifier
    metadata_sha256: Sha256Digest
    expected_classification: Classification


class ComparisonRun(StrictModel):
    scenario: ScenarioRef
    envelope_sha256: Sha256Digest
    strategy_kind: ComparisonStrategyKind
    strategy_version: Identifier
    plan_sha256: Sha256Digest
    report_sha256: Sha256Digest
    classification: Classification
    matches_preregistered_expectation: bool
    planned_probe_count: int = Field(ge=0, le=_MAX_SIGNED_64)
    executed_probe_count: int = Field(ge=0, le=_MAX_SIGNED_64)
    controller_cost_units_used: int = Field(ge=0, le=_MAX_SIGNED_64)
    controller_result_bytes_acquired: int = Field(ge=0, le=_MAX_SIGNED_64)
    total_elapsed_ms: int = Field(ge=0, le=_MAX_SIGNED_64)
    time_to_sufficient_evidence_ms: int | None = Field(
        default=None,
        ge=0,
        le=_MAX_SIGNED_64,
    )
    stop_reason: Identifier
    unsupported_probe_count: int = Field(ge=0, le=_MAX_SIGNED_64)
    unnecessary_probe_count: int = Field(ge=0, le=_MAX_SIGNED_64)
    duplicate_probe_count: int = Field(ge=0, le=_MAX_SIGNED_64)
    explanation_completeness: ExplanationCompleteness
    model_usage: ComparisonModelUsage

    @model_validator(mode="after")
    def validate_run(self) -> ComparisonRun:
        if self.executed_probe_count > self.planned_probe_count:
            raise ValueError("executed probes cannot exceed the recorded plan")
        if any(
            value > self.executed_probe_count
            for value in (
                self.unsupported_probe_count,
                self.unnecessary_probe_count,
                self.duplicate_probe_count,
            )
        ):
            raise ValueError("probe findings cannot exceed executed probes")
        if (
            self.time_to_sufficient_evidence_ms is not None
            and self.time_to_sufficient_evidence_ms > self.total_elapsed_ms
        ):
            raise ValueError("time to sufficient evidence cannot exceed total elapsed")
        if self.executed_probe_count == 0 and (
            self.controller_cost_units_used != 0
            or self.controller_result_bytes_acquired != 0
            or self.unnecessary_probe_count != 0
            or self.time_to_sufficient_evidence_ms is not None
        ):
            raise ValueError("an unexecuted plan cannot contain execution metrics")

        fixed = self.strategy_kind is ComparisonStrategyKind.FIXED
        not_applicable = (
            self.model_usage.status is ComparisonModelUsageStatus.NOT_APPLICABLE
        )
        if fixed is not not_applicable:
            raise ValueError("strategy kind and model usage status are inconsistent")
        return self


class InvestigationComparisonRecord(StrictModel):
    schema_version: Literal[INVESTIGATION_COMPARISON_RECORD_VERSION]
    comparison_id: Identifier
    case_id: Identifier
    scenario: ScenarioRef
    envelope_sha256: Sha256Digest
    preregistered_expectation: PreregisteredExpectedClassification
    baseline: ComparisonRun
    adaptive: ComparisonRun | None

    @model_validator(mode="after")
    def validate_record(self) -> InvestigationComparisonRecord:
        if self.baseline.strategy_kind is not ComparisonStrategyKind.FIXED:
            raise ValueError("the baseline run must use the fixed strategy")
        runs = (
            (self.baseline,)
            if self.adaptive is None
            else (self.baseline, self.adaptive)
        )
        if self.adaptive is not None and (
            self.adaptive.strategy_kind is not ComparisonStrategyKind.ADAPTIVE
        ):
            raise ValueError("the adaptive run must use the adaptive strategy")
        for run in runs:
            if run.scenario != self.scenario:
                raise ValueError("comparison runs must use the common scenario")
            if run.envelope_sha256 != self.envelope_sha256:
                raise ValueError("comparison runs must use the common envelope")
            expected_match = (
                run.classification
                is self.preregistered_expectation.expected_classification
            )
            if run.matches_preregistered_expectation is not expected_match:
                raise ValueError(
                    "expectation match must derive from preregistered classification"
                )
        return self


__all__ = [
    "INVESTIGATION_COMPARISON_RECORD_VERSION",
    "ComparisonModelUsage",
    "ComparisonModelUsageStatus",
    "ComparisonRun",
    "ComparisonStrategyKind",
    "ExplanationCompleteness",
    "InvestigationComparisonRecord",
    "PreregisteredExpectedClassification",
]
