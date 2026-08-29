"""Single-use v3 execution protocol around frozen public v1 qualification models."""

from __future__ import annotations

import asyncio
import hashlib
import inspect
import json
import os
import re
import secrets
import stat
import subprocess
import weakref
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from pathlib import Path
from typing import Literal

from pydantic import Field, model_validator

from reconcile.adaptive import (
    AdaptiveInvestigationResult,
    AdaptiveStopReason,
    AdvisoryPlanner,
    AdvisoryPlannerMetadata,
    AdvisoryPlannerTurn,
    PlannerFailureKind,
    ProposalDisposition,
    execute_adaptive_investigation,
)
from reconcile.adk_planner import (
    AdkGeminiPlanner,
    QualificationDispatchContext,
    QualificationDispatchHook,
    VertexAdcPlannerConfig,
)
from reconcile.baseline import FixedBaselineResult, execute_fixed_plan
from reconcile.contracts import (
    ADAPTIVE_PLANNER_INPUT_VERSION,
    ADAPTIVE_PLANNER_OUTPUT_VERSION,
    INVESTIGATION_COMPARISON_RECORD_VERSION,
    ActionGateResult,
    AdaptivePlannerInput,
    AdaptivePlannerOutput,
    AdaptivePlannerPhase,
    AmbiguityKind,
    ComparisonModelUsage,
    ComparisonModelUsageStatus,
    ComparisonRun,
    ComparisonStrategyKind,
    ExecutionEnvelope,
    ExplanationCompleteness,
    InvestigationComparisonRecord,
    canonical_json_bytes,
    canonical_sha256,
    decode_contract,
)
from reconcile.contracts.base import (
    AwareDatetime,
    Identifier,
    Sha256Digest,
    StrictModel,
    canonical_json_value_bytes,
    reject_sensitive_values,
)
from reconcile.contracts.qualification import (
    QualificationArtifactIdentity,
    QualificationCaseDefinition,
    QualificationCaseResult,
    QualificationCaseResultStatus,
    QualificationCaseRole,
    QualificationDisposition,
    QualificationLaneArtifacts,
    QualificationLaneOrder,
    QualificationProviderSettings,
    QualificationResultSet,
    QualificationStopConditions,
    QualificationSuiteManifest,
    QualificationSummary,
)
from reconcile.controller import ProbeObservation
from reconcile.qualification import (
    PREREGISTERED_QUALIFICATION_CASES,
    MeasurementBindings,
    artifact_identity,
    build_control_result,
    build_failed_result,
    build_measurement_result,
    build_qualification_manifest,
    build_result_set,
    derive_disposition,
    summarize_qualification,
)
from reconcile.qualification_fixtures import (
    PreparedQualificationFixture,
    QualificationFixtureRegistry,
    QualificationProtocolStage,
    QualificationRawObservation,
    _FinalFixtureSession,
    _issue_final_fixture_access,
    qualification_cases_for_stage,
)
from reconcile.qualification_v2_custody import (
    QualificationConsumedV2Custody,
    QualificationV2CustodySource,
    QualificationV2UsageTotals,
    canonical_consumed_v2_custody,
    load_consumed_v2_custody,
)
from reconcile.security import is_sensitive_key

_ARTIFACT_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_GIT_COMMIT_SHA1 = re.compile(r"^[0-9a-f]{40}$")
_MAX_SIGNED_64 = 2**63 - 1
_FROZEN_PROVIDER_PROJECT = "example-project-id"
_FROZEN_PROVIDER_NAME = "google-vertex-ai"
_FROZEN_MODEL_NAME = "gemini-3.5-flash"
_FROZEN_MODEL_REVISION = "UNKNOWN"
_FROZEN_PROVIDER_LOCATION = "global"
_FROZEN_PROMPT_VERSION = "adaptive-planner-v3"
_FROZEN_PROMPT_SHA256 = (
    "a18ac5bbd22570562acc6dfbc49437a82f0db6a265a4de737c1371b6ef2ca2d3"
)
_FROZEN_ADK_VERSION = "2.6.3"
_FROZEN_GENAI_VERSION = "2.18.0"
_FROZEN_TIMEOUT_MS = 30_000
_FROZEN_MAX_OUTPUT_TOKENS = 1_024
_FROZEN_INPUT_COST_NANO_UNITS = 1_500
_FROZEN_OUTPUT_COST_NANO_UNITS = 9_000
_FROZEN_CONTEXT_WINDOW_TOKENS = 1_048_576
_FROZEN_MAX_INPUT_TOKENS_PER_CALL = 12_000
_FROZEN_MAX_NEW_MODEL_CALLS = 176
_FROZEN_MAX_COUNT_TOKEN_CALLS = 177
_FROZEN_MAX_TOTAL_PROVIDER_REQUESTS = 357
_FROZEN_MAX_CURRENT_OPERATION_RECORDS = 352
_CONCRETE_MODEL_REVISION = re.compile(rf"^{re.escape(_FROZEN_MODEL_NAME)}-[0-9]{{3}}$")
_FROZEN_MAX_TOTAL_INPUT_TOKENS = 2_143_945
_FROZEN_MAX_TOTAL_OUTPUT_TOKENS = 182_373
_HISTORICAL_RECONSTRUCTION_OVERHEAD = 8_192
_HISTORICAL_GIT_COMMIT = "b6f17aa197b82740d04e9c54ee6baf6a12b7ade6"
_HISTORICAL_SOURCE_REVISION = (
    "db97e18893f3cd6088cffe3901f05cb630480c7a32b3f09ddd72c030b138b334"
)
_FROZEN_LANE_ORDERS = (
    QualificationLaneOrder.FIXED_FIRST,
    QualificationLaneOrder.ADAPTIVE_FIRST,
    QualificationLaneOrder.FIXED_FIRST,
    QualificationLaneOrder.ADAPTIVE_FIRST,
    QualificationLaneOrder.FIXED_FIRST,
)
_CONSEQUENTIAL_ACTIONS = frozenset({"CONTINUE", "RETRY", "COMPENSATE"})
_AUTHORIZED_LIVE_PLANNERS: weakref.WeakKeyDictionary[
    AdkGeminiPlanner, QualificationRuntimeIdentity
] = weakref.WeakKeyDictionary()


def _reject_artifact_secret_keys(value: object) -> None:
    if isinstance(value, dict):
        for key, item in value.items():
            metric_key = key.endswith(("_tokens", "_token_count", "_per_token"))
            if is_sensitive_key(key) and not metric_key:
                raise ValueError("secret-bearing fields are not allowed")
            _reject_artifact_secret_keys(item)
    elif isinstance(value, list):
        for item in value:
            _reject_artifact_secret_keys(item)


QUALIFICATION_EXECUTION_START_VERSION = "reconcile/qualification-execution-start/v3"
QUALIFICATION_RUNTIME_IDENTITY_VERSION = "reconcile/qualification-runtime-identity/v3"
QUALIFICATION_MODEL_BINDING_VERSION = "reconcile/qualification-model-binding/v3"
QUALIFICATION_OBSERVATION_BUNDLE_VERSION = (
    "reconcile/qualification-observation-bundle/v3"
)
QUALIFICATION_NORMALIZED_RUN_VERSION = "reconcile/qualification-normalized-run/v3"
QUALIFICATION_LANE_RECEIPT_VERSION = "reconcile/qualification-lane-receipt/v3"
QUALIFICATION_FAILURE_RECORD_VERSION = "reconcile/qualification-failure-record/v3"
QUALIFICATION_PARTIAL_PUBLICATION_VERSION = (
    "reconcile/qualification-partial-publication/v3"
)
QUALIFICATION_ATTEMPT_START_VERSION = "reconcile/qualification-attempt-start/v3"
QUALIFICATION_ATTEMPT_VERSION = "reconcile/qualification-attempt/v3"
QUALIFICATION_ATTEMPT_LEDGER_VERSION = "reconcile/qualification-attempt-ledger/v3"
QUALIFICATION_PRIOR_ATTEMPT_LEDGER_VERSION = (
    "reconcile/qualification-prior-attempt-ledger/v2"
)
QUALIFICATION_HISTORICAL_ATTEMPT_LEDGER_VERSION = (
    QUALIFICATION_PRIOR_ATTEMPT_LEDGER_VERSION
)
QUALIFICATION_COMBINED_PRIOR_ATTEMPT_LEDGER_VERSION = (
    "reconcile/qualification-combined-prior-attempt-ledger/v3"
)
QUALIFICATION_CASE_EXECUTION_VERSION = "reconcile/qualification-case-execution/v3"
QUALIFICATION_PROTOCOL_SUMMARY_VERSION = "reconcile/qualification-protocol-summary/v3"
QUALIFICATION_EXECUTION_COMPLETION_VERSION = (
    "reconcile/qualification-execution-completion/v3"
)


class QualificationProtocolError(RuntimeError):
    """Qualification execution cannot continue without weakening its protocol."""


class QualificationExecutionConsumed(QualificationProtocolError):
    pass


class QualificationBudgetExceeded(QualificationProtocolError):
    pass


class QualificationProviderDrift(QualificationProtocolError):
    pass


class _ArtifactLinkOutcomeAmbiguous(OSError):
    """The link call failed without proving whether the immutable link exists."""


class QualificationAttemptOutcome(StrEnum):
    MEASURED = "MEASURED"
    TOKEN_COUNTED = "TOKEN_COUNTED"
    PROVIDER_FAILURE = "PROVIDER_FAILURE"
    CONTROL_FAILURE = "CONTROL_FAILURE"
    RAISED = "RAISED"
    USAGE_UNAVAILABLE = "USAGE_UNAVAILABLE"
    PROVIDER_DRIFT = "PROVIDER_DRIFT"
    RESERVATION_EXCEEDED = "RESERVATION_EXCEEDED"


class QualificationAccountingBasis(StrEnum):
    MEASURED = "MEASURED"
    NON_BILLABLE = "NON_BILLABLE"
    RESERVED = "RESERVED"


class QualificationBoundStatus(StrEnum):
    WITHIN = "WITHIN"
    EXCEEDED = "EXCEEDED"
    UNKNOWN = "UNKNOWN"
    NOT_APPLICABLE = "NOT_APPLICABLE"


class QualificationExecutionBasis(StrEnum):
    LIVE_PROVIDER = "LIVE_PROVIDER"
    DETERMINISTIC_TEST = "DETERMINISTIC_TEST"


class QualificationProviderOperation(StrEnum):
    COUNT_TOKENS = "COUNT_TOKENS"
    GENERATE = "GENERATE"


class QualificationHistoricalUsageBasis(StrEnum):
    MEASURED_PROVIDER_USAGE = "MEASURED_PROVIDER_USAGE"
    RECONSTRUCTED_REQUEST_BYTES_PLUS_8192 = "RECONSTRUCTED_REQUEST_BYTES_PLUS_8192"


class QualificationRuntimeIdentity(StrictModel):
    schema_version: Literal[QUALIFICATION_RUNTIME_IDENTITY_VERSION]
    provider_project: Identifier
    provider_name: Identifier
    configured_model: Identifier
    model_revision: Identifier
    location: Identifier
    timeout_ms: int = Field(ge=1, le=300_000)
    max_output_tokens: int = Field(ge=1, le=65_536)
    temperature_milli: int = Field(ge=0, le=2_000)
    context_window_tokens: int = Field(ge=1, le=_MAX_SIGNED_64)
    maximum_input_tokens_per_call: int = Field(ge=1, le=_MAX_SIGNED_64)
    prompt_version: Identifier
    prompt_sha256: Sha256Digest
    input_schema_version: str = Field(min_length=1, max_length=128)
    output_schema_version: str = Field(min_length=1, max_length=128)
    adk_version: Identifier
    genai_version: Identifier
    billing_currency: Literal["USD"]
    input_cost_nano_units_per_token: int = Field(ge=0, le=_MAX_SIGNED_64)
    output_cost_nano_units_per_token: int = Field(ge=0, le=_MAX_SIGNED_64)

    @model_validator(mode="after")
    def validate_bounds(self) -> QualificationRuntimeIdentity:
        if (
            self.maximum_input_tokens_per_call + self.max_output_tokens
            > self.context_window_tokens
        ):
            raise ValueError("runtime request bounds exceed the context window")
        return self


class QualificationModelBinding(StrictModel):
    schema_version: Literal[QUALIFICATION_MODEL_BINDING_VERSION]
    suite_id: Identifier
    runtime_identity_sha256: Sha256Digest
    configured_model: Identifier
    reported_model_revision: Identifier
    reported_model_raw_sha256: Sha256Digest
    preflight_generation_attempt_id: Identifier
    preflight_input_sha256: Sha256Digest
    bound_at: AwareDatetime

    @model_validator(mode="after")
    def validate_revision(self) -> QualificationModelBinding:
        if (
            self.configured_model != _FROZEN_MODEL_NAME
            or _CONCRETE_MODEL_REVISION.fullmatch(self.reported_model_revision) is None
        ):
            raise ValueError("provider model binding requires a concrete revision")
        return self


def frozen_qualification_provider_settings() -> QualificationProviderSettings:
    return QualificationProviderSettings(
        provider_name=_FROZEN_PROVIDER_NAME,
        model_name=_FROZEN_MODEL_NAME,
        model_revision=_FROZEN_MODEL_REVISION,
        location=_FROZEN_PROVIDER_LOCATION,
        prompt_version=_FROZEN_PROMPT_VERSION,
        adk_version=_FROZEN_ADK_VERSION,
        genai_version=_FROZEN_GENAI_VERSION,
        timeout_ms=_FROZEN_TIMEOUT_MS,
        max_output_tokens=_FROZEN_MAX_OUTPUT_TOKENS,
        temperature_milli=0,
        billing_currency="USD",
        input_cost_nano_units_per_token=_FROZEN_INPUT_COST_NANO_UNITS,
        output_cost_nano_units_per_token=_FROZEN_OUTPUT_COST_NANO_UNITS,
    )


def frozen_qualification_runtime_identity() -> QualificationRuntimeIdentity:
    return QualificationRuntimeIdentity(
        schema_version=QUALIFICATION_RUNTIME_IDENTITY_VERSION,
        provider_project=_FROZEN_PROVIDER_PROJECT,
        provider_name=_FROZEN_PROVIDER_NAME,
        configured_model=_FROZEN_MODEL_NAME,
        model_revision=_FROZEN_MODEL_REVISION,
        location=_FROZEN_PROVIDER_LOCATION,
        timeout_ms=_FROZEN_TIMEOUT_MS,
        max_output_tokens=_FROZEN_MAX_OUTPUT_TOKENS,
        temperature_milli=0,
        context_window_tokens=_FROZEN_CONTEXT_WINDOW_TOKENS,
        maximum_input_tokens_per_call=_FROZEN_MAX_INPUT_TOKENS_PER_CALL,
        prompt_version=_FROZEN_PROMPT_VERSION,
        prompt_sha256=_FROZEN_PROMPT_SHA256,
        input_schema_version=ADAPTIVE_PLANNER_INPUT_VERSION,
        output_schema_version=ADAPTIVE_PLANNER_OUTPUT_VERSION,
        adk_version=_FROZEN_ADK_VERSION,
        genai_version=_FROZEN_GENAI_VERSION,
        billing_currency="USD",
        input_cost_nano_units_per_token=_FROZEN_INPUT_COST_NANO_UNITS,
        output_cost_nano_units_per_token=_FROZEN_OUTPUT_COST_NANO_UNITS,
    )


class QualificationExecutionStart(StrictModel):
    schema_version: Literal[QUALIFICATION_EXECUTION_START_VERSION]
    stage: QualificationProtocolStage
    suite_id: Identifier
    manifest_sha256: Sha256Digest
    source_revision: Sha256Digest
    git_commit: str = Field(pattern=r"^[0-9a-f]{40}$")
    provider_settings_sha256: Sha256Digest
    planner_configuration_sha256: Sha256Digest
    runtime_identity: QualificationArtifactIdentity
    model_binding: QualificationArtifactIdentity
    execution_basis: QualificationExecutionBasis
    prior_stage_completion_sha256: Sha256Digest | None
    prior_attempt_ledger_sha256: Sha256Digest | None
    historical_attempt_ledger_sha256: Sha256Digest
    consumed_v2_custody_sha256: Sha256Digest
    started_at: AwareDatetime

    @model_validator(mode="after")
    def validate_source(self) -> QualificationExecutionStart:
        if self.source_revision != source_revision_for_git_commit(self.git_commit):
            raise ValueError("execution source digest must bind the Git commit")
        if self.runtime_identity.sha256 != self.planner_configuration_sha256:
            raise ValueError("execution start must bind its runtime identity")
        return self


class QualificationObservationRecord(StrictModel):
    sequence: int = Field(ge=1, le=64)
    capability_name: Identifier
    observation_sha256: Sha256Digest
    observation: ProbeObservation


class QualificationObservationBundle(StrictModel):
    schema_version: Literal[QUALIFICATION_OBSERVATION_BUNDLE_VERSION]
    execution_id: Identifier
    case_id: Identifier
    repetition: int = Field(ge=1, le=16)
    execution_sequence: int = Field(ge=1, le=2)
    strategy_kind: ComparisonStrategyKind
    runtime_identity_sha256: Sha256Digest
    envelope_sha256: Sha256Digest
    semantic_state_sha256: Sha256Digest
    catalog_sha256: Sha256Digest
    rules_sha256: Sha256Digest
    observations: tuple[QualificationObservationRecord, ...] = Field(max_length=64)

    @model_validator(mode="after")
    def validate_sequence(self) -> QualificationObservationBundle:
        if tuple(item.sequence for item in self.observations) != tuple(
            range(1, len(self.observations) + 1)
        ):
            raise ValueError("qualification observations must be contiguous")
        if any(
            item.observation_sha256 != canonical_sha256(item.observation)
            for item in self.observations
        ):
            raise ValueError("qualification observation digest changed")
        return self


class QualificationProposalFacts(StrictModel):
    acquisition_proposal_count: int = Field(ge=0, le=_MAX_SIGNED_64)
    selected_proposal_count: int = Field(ge=0, le=_MAX_SIGNED_64)
    deferred_proposal_count: int = Field(ge=0, le=_MAX_SIGNED_64)
    unsupported_proposal_count: int = Field(ge=0, le=_MAX_SIGNED_64)
    invalid_proposal_count: int = Field(ge=0, le=_MAX_SIGNED_64)
    duplicate_proposal_count: int = Field(ge=0, le=_MAX_SIGNED_64)
    unavailable_proposal_count: int = Field(ge=0, le=_MAX_SIGNED_64)
    budget_exceeded_proposal_count: int = Field(ge=0, le=_MAX_SIGNED_64)
    ignored_explanation_proposal_count: int = Field(ge=0, le=_MAX_SIGNED_64)

    @model_validator(mode="after")
    def validate_partition(self) -> QualificationProposalFacts:
        acquisition_partition = sum(
            (
                self.selected_proposal_count,
                self.deferred_proposal_count,
                self.unsupported_proposal_count,
                self.invalid_proposal_count,
                self.duplicate_proposal_count,
                self.unavailable_proposal_count,
                self.budget_exceeded_proposal_count,
            )
        )
        if acquisition_partition != self.acquisition_proposal_count:
            raise ValueError(
                "acquisition proposal dispositions must partition proposals"
            )
        return self


def _zero_proposal_facts() -> QualificationProposalFacts:
    return QualificationProposalFacts(
        acquisition_proposal_count=0,
        selected_proposal_count=0,
        deferred_proposal_count=0,
        unsupported_proposal_count=0,
        invalid_proposal_count=0,
        duplicate_proposal_count=0,
        unavailable_proposal_count=0,
        budget_exceeded_proposal_count=0,
        ignored_explanation_proposal_count=0,
    )


class QualificationNormalizedRun(StrictModel):
    schema_version: Literal[QUALIFICATION_NORMALIZED_RUN_VERSION]
    runtime_identity_sha256: Sha256Digest
    run: ComparisonRun
    proposal_facts: QualificationProposalFacts
    unavailable_probe_count: int = Field(ge=0, le=_MAX_SIGNED_64)

    @model_validator(mode="after")
    def validate_domains(self) -> QualificationNormalizedRun:
        if self.run.strategy_kind is ComparisonStrategyKind.FIXED:
            if self.proposal_facts != _zero_proposal_facts():
                raise ValueError("fixed qualification runs cannot contain proposals")
        elif (
            self.run.planned_probe_count != self.proposal_facts.selected_proposal_count
        ):
            raise ValueError("adaptive planned probes must be selected proposals")
        if self.unavailable_probe_count > self.run.executed_probe_count:
            raise ValueError("unavailable probes cannot exceed execution attempts")
        return self


class QualificationLaneReceipt(StrictModel):
    schema_version: Literal[QUALIFICATION_LANE_RECEIPT_VERSION]
    suite_id: Identifier
    manifest_sha256: Sha256Digest
    execution_id: Identifier
    case_id: Identifier
    repetition: int = Field(ge=1, le=16)
    lane_order: QualificationLaneOrder
    execution_sequence: int = Field(ge=1, le=2)
    strategy_kind: ComparisonStrategyKind
    runtime_identity_sha256: Sha256Digest
    envelope_sha256: Sha256Digest
    target_sha256: Sha256Digest
    semantic_state_before_sha256: Sha256Digest
    semantic_state_after_sha256: Sha256Digest
    catalog_sha256: Sha256Digest
    rules_sha256: Sha256Digest
    policies_sha256: Sha256Digest
    report_sha256: Sha256Digest | None
    action_gates_sha256: Sha256Digest | None
    raw_observations: QualificationArtifactIdentity
    normalized_run: QualificationArtifactIdentity | None
    protocol_run: QualificationArtifactIdentity | None
    failure_record: QualificationArtifactIdentity | None

    @model_validator(mode="after")
    def validate_receipt(self) -> QualificationLaneReceipt:
        successful = (
            self.normalized_run is not None
            and self.protocol_run is not None
            and self.failure_record is None
            and self.report_sha256 is not None
            and self.action_gates_sha256 is not None
        )
        failed = (
            self.normalized_run is None
            and self.protocol_run is None
            and self.failure_record is not None
            and (self.report_sha256 is None) is (self.action_gates_sha256 is None)
        )
        if not (successful or failed):
            raise ValueError("lane receipt requires one normalized run or failure")
        if successful and (
            self.semantic_state_before_sha256 != self.semantic_state_after_sha256
        ):
            raise ValueError("successful qualification lane changed target state")
        return self


class QualificationFailureRecord(StrictModel):
    schema_version: Literal[QUALIFICATION_FAILURE_RECORD_VERSION]
    execution_id: Identifier
    category: Identifier
    strategy_kind: ComparisonStrategyKind | None
    runtime_identity_sha256: Sha256Digest
    failure_kind: Identifier
    occurred_at: AwareDatetime
    retained_report_sha256: Sha256Digest | None = None
    retained_stop_reason: Identifier | None = None
    control_action_gates: tuple[ActionGateResult, ...] | None = None
    partial_publication: QualificationArtifactIdentity | None = None

    @model_validator(mode="after")
    def validate_failure_scope(self) -> QualificationFailureRecord:
        if self.partial_publication is not None and self.strategy_kind is not None:
            raise ValueError(
                "partial publication custody belongs only to the case failure root"
            )
        if (self.retained_report_sha256 is None) is not (
            self.retained_stop_reason is None
        ):
            raise ValueError("retained report and stop reason must be paired")
        control = self.failure_kind == "provider-unavailable-control"
        if (self.control_action_gates is not None) is not control or (
            control and (self.retained_report_sha256 is None)
        ):
            raise ValueError("control failure must retain its exact action gates")
        return self


class QualificationPartialPublication(StrictModel):
    schema_version: Literal[QUALIFICATION_PARTIAL_PUBLICATION_VERSION]
    execution_id: Identifier
    case_id: Identifier
    repetition: int = Field(ge=1, le=16)
    strategy_kind: ComparisonStrategyKind
    runtime_identity_sha256: Sha256Digest
    raw_observations: QualificationArtifactIdentity
    normalized_run: QualificationArtifactIdentity | None = None
    protocol_run: QualificationArtifactIdentity | None = None
    failure_record: QualificationArtifactIdentity | None = None

    @model_validator(mode="after")
    def validate_prefix(self) -> QualificationPartialPublication:
        if self.protocol_run is not None and self.normalized_run is None:
            raise ValueError("partial protocol run requires its normalized run")
        if self.failure_record is not None and (
            self.normalized_run is not None or self.protocol_run is not None
        ):
            raise ValueError(
                "partial failed lane cannot also claim successful run artifacts"
            )
        identities = tuple(
            item.artifact_id
            for item in (
                self.raw_observations,
                self.normalized_run,
                self.protocol_run,
                self.failure_record,
            )
            if item is not None
        )
        if len(identities) != len(set(identities)):
            raise ValueError("partial publication artifacts must be unique")
        return self


class QualificationProviderAttemptStart(StrictModel):
    schema_version: Literal[QUALIFICATION_ATTEMPT_START_VERSION]
    attempt_id: Identifier
    sequence: int = Field(ge=1, le=_FROZEN_MAX_CURRENT_OPERATION_RECORDS)
    dispatch_id: Identifier
    execution_id: Identifier
    case_id: Identifier
    repetition: int = Field(ge=1, le=16)
    planner_phase: AdaptivePlannerPhase
    operation: QualificationProviderOperation
    execution_basis: QualificationExecutionBasis
    planner_configuration_sha256: Sha256Digest
    input_sha256: Sha256Digest
    request_byte_count: int = Field(ge=1, le=_FROZEN_MAX_INPUT_TOKENS_PER_CALL)
    sealed_generation_request_sha256: Sha256Digest | None = None
    provider_request_sha256: Sha256Digest | None = None
    paired_count_attempt_id: Identifier | None = None
    reserved_provider_request_count: Literal[0, 1]
    reserved_input_tokens: int = Field(ge=0, le=_MAX_SIGNED_64)
    reserved_output_tokens: int = Field(ge=0, le=_MAX_SIGNED_64)
    reserved_cost_nano_units: int = Field(ge=0, le=_MAX_SIGNED_64)
    started_at: AwareDatetime

    @model_validator(mode="after")
    def validate_reservation(self) -> QualificationProviderAttemptStart:
        if self.operation is QualificationProviderOperation.COUNT_TOKENS:
            if (
                self.sealed_generation_request_sha256 is None
                or self.provider_request_sha256 is None
                or self.paired_count_attempt_id is not None
                or self.reserved_provider_request_count != 1
                or any(
                    (
                        self.reserved_input_tokens,
                        self.reserved_output_tokens,
                        self.reserved_cost_nano_units,
                    )
                )
            ):
                raise ValueError("token-count start must reserve only its request")
            return self
        if self.provider_request_sha256 is not None:
            raise ValueError("generation start cannot contain a count request digest")
        if self.reserved_provider_request_count == 0:
            if (
                self.paired_count_attempt_id is not None
                or self.sealed_generation_request_sha256 is not None
            ):
                raise ValueError("control generation cannot claim a count pair")
        elif (
            self.paired_count_attempt_id is None
            or self.sealed_generation_request_sha256 is None
        ):
            raise ValueError("provider generation requires a count pair")
        expected_cost = (
            self.reserved_input_tokens * _FROZEN_INPUT_COST_NANO_UNITS
            + self.reserved_output_tokens * _FROZEN_OUTPUT_COST_NANO_UNITS
        )
        if (
            self.reserved_input_tokens != _FROZEN_MAX_INPUT_TOKENS_PER_CALL
            or self.reserved_output_tokens != _FROZEN_MAX_OUTPUT_TOKENS
            or self.reserved_cost_nano_units != expected_cost
        ):
            raise ValueError("generation start must reserve the frozen full call")
        return self


class QualificationProviderAttempt(StrictModel):
    schema_version: Literal[QUALIFICATION_ATTEMPT_VERSION]
    attempt_id: Identifier
    sequence: int = Field(ge=1, le=_FROZEN_MAX_CURRENT_OPERATION_RECORDS)
    dispatch_id: Identifier
    execution_id: Identifier
    case_id: Identifier
    repetition: int = Field(ge=1, le=16)
    planner_phase: AdaptivePlannerPhase
    operation: QualificationProviderOperation
    execution_basis: QualificationExecutionBasis
    planner_configuration_sha256: Sha256Digest
    input_sha256: Sha256Digest
    request_byte_count: int = Field(ge=1, le=_FROZEN_MAX_INPUT_TOKENS_PER_CALL)
    sealed_generation_request_sha256: Sha256Digest | None = None
    provider_request_sha256: Sha256Digest | None = None
    paired_count_attempt_id: Identifier | None = None
    reserved_provider_request_count: Literal[0, 1]
    output_sha256: Sha256Digest | None = None
    outcome: QualificationAttemptOutcome
    accounting_basis: QualificationAccountingBasis
    failure_category: Identifier | None = None
    provider_failure_kind: Identifier | None = None
    input_bound_status: QualificationBoundStatus
    output_bound_status: QualificationBoundStatus
    provider_name: Identifier
    configured_model: Identifier
    reported_model: Identifier | None = None
    reported_model_raw_sha256: Sha256Digest | None = None
    counted_input_tokens: int | None = Field(default=None, ge=1, le=_MAX_SIGNED_64)
    reserved_input_tokens: int = Field(ge=0, le=_MAX_SIGNED_64)
    reserved_output_tokens: int = Field(ge=0, le=_MAX_SIGNED_64)
    reserved_cost_nano_units: int = Field(ge=0, le=_MAX_SIGNED_64)
    accounted_input_tokens: int = Field(ge=0, le=_MAX_SIGNED_64)
    accounted_output_tokens: int = Field(ge=0, le=_MAX_SIGNED_64)
    accounted_cost_nano_units: int = Field(ge=0, le=_MAX_SIGNED_64)
    measured_input_tokens: int | None = Field(default=None, ge=0, le=_MAX_SIGNED_64)
    measured_output_tokens: int | None = Field(default=None, ge=0, le=_MAX_SIGNED_64)
    usage_measured: bool
    completed_at: AwareDatetime

    @model_validator(mode="after")
    def validate_attempt(self) -> QualificationProviderAttempt:
        if self.operation is QualificationProviderOperation.COUNT_TOKENS:
            if (
                self.outcome
                not in {
                    QualificationAttemptOutcome.TOKEN_COUNTED,
                    QualificationAttemptOutcome.PROVIDER_FAILURE,
                }
                or self.accounting_basis
                is not QualificationAccountingBasis.NON_BILLABLE
                or self.usage_measured
                or self.reported_model is not None
                or self.reported_model_raw_sha256 is not None
                or self.sealed_generation_request_sha256 is None
                or self.provider_request_sha256 is None
                or self.paired_count_attempt_id is not None
                or self.reserved_provider_request_count != 1
                or self.accounted_input_tokens != 0
                or self.accounted_output_tokens != 0
                or self.accounted_cost_nano_units != 0
                or self.measured_input_tokens is not None
                or self.measured_output_tokens is not None
                or self.reserved_input_tokens != 0
                or self.reserved_output_tokens != 0
                or self.reserved_cost_nano_units != 0
                or self.input_bound_status
                is not QualificationBoundStatus.NOT_APPLICABLE
                or self.output_bound_status
                is not QualificationBoundStatus.NOT_APPLICABLE
            ):
                raise ValueError("token-count attempts are non-generative accounting")
            counted = self.outcome is QualificationAttemptOutcome.TOKEN_COUNTED
            if (
                counted
                and (
                    self.counted_input_tokens is None
                    or self.counted_input_tokens > _FROZEN_MAX_INPUT_TOKENS_PER_CALL
                    or self.failure_category is not None
                    or self.provider_failure_kind is not None
                )
            ) or (
                not counted
                and (
                    self.counted_input_tokens is not None
                    or self.failure_category is None
                    or self.provider_failure_kind != self.failure_category
                )
            ):
                raise ValueError("token-count outcome and response are inconsistent")
            provider_identity_matches = (
                self.provider_name == _FROZEN_PROVIDER_NAME
                and self.configured_model == _FROZEN_MODEL_NAME
            )
            if not provider_identity_matches and not (
                self.outcome is QualificationAttemptOutcome.PROVIDER_FAILURE
                and self.failure_category == "provider-drift"
            ):
                raise ValueError(
                    "successful token count must bind the frozen provider identity"
                )
            return self
        if self.accounting_basis is QualificationAccountingBasis.NON_BILLABLE:
            raise ValueError("generation attempts require billable accounting")
        if self.provider_request_sha256 is not None:
            raise ValueError("generation attempts cannot use token-count requests")
        if self.counted_input_tokens is not None:
            raise ValueError("generation attempts cannot claim a token count response")
        if self.outcome is QualificationAttemptOutcome.TOKEN_COUNTED:
            raise ValueError("generation attempts cannot be token-count outcomes")
        if self.usage_measured is not (
            self.measured_input_tokens is not None
            and self.measured_output_tokens is not None
        ):
            raise ValueError("generation measured usage fields must be paired")
        if self.outcome is not QualificationAttemptOutcome.PROVIDER_DRIFT and (
            self.provider_name != _FROZEN_PROVIDER_NAME
            or self.configured_model != _FROZEN_MODEL_NAME
        ):
            raise ValueError(
                "generation attempt must bind the frozen provider identity"
            )
        if (self.reported_model is None) is not (
            self.reported_model_raw_sha256 is None
        ):
            raise ValueError("reported model revision and raw digest must be paired")
        if self.reserved_provider_request_count == 0:
            if (
                self.outcome is not QualificationAttemptOutcome.CONTROL_FAILURE
                or self.paired_count_attempt_id is not None
                or self.sealed_generation_request_sha256 is not None
            ):
                raise ValueError("only control attempts omit an external request")
        elif (
            self.outcome is QualificationAttemptOutcome.CONTROL_FAILURE
            or self.paired_count_attempt_id is None
            or self.sealed_generation_request_sha256 is None
        ):
            raise ValueError("generation requests require their token-count pair")
        expected_reservation_cost = (
            self.reserved_input_tokens * _FROZEN_INPUT_COST_NANO_UNITS
            + self.reserved_output_tokens * _FROZEN_OUTPUT_COST_NANO_UNITS
        )
        if (
            self.reserved_input_tokens != _FROZEN_MAX_INPUT_TOKENS_PER_CALL
            or self.reserved_output_tokens != _FROZEN_MAX_OUTPUT_TOKENS
            or self.reserved_cost_nano_units != expected_reservation_cost
        ):
            raise ValueError("generation attempt must retain the frozen full call")
        expected_input_status = (
            QualificationBoundStatus.NOT_APPLICABLE
            if self.reserved_provider_request_count == 0
            else (
                QualificationBoundStatus.UNKNOWN
                if self.measured_input_tokens is None
                else (
                    QualificationBoundStatus.EXCEEDED
                    if self.measured_input_tokens > self.reserved_input_tokens
                    else QualificationBoundStatus.WITHIN
                )
            )
        )
        expected_output_status = (
            QualificationBoundStatus.NOT_APPLICABLE
            if self.reserved_provider_request_count == 0
            else (
                QualificationBoundStatus.UNKNOWN
                if self.measured_output_tokens is None
                else (
                    QualificationBoundStatus.EXCEEDED
                    if self.measured_output_tokens > self.reserved_output_tokens
                    else QualificationBoundStatus.WITHIN
                )
            )
        )
        if (
            self.input_bound_status is not expected_input_status
            or self.output_bound_status is not expected_output_status
        ):
            raise ValueError("generation bound status must derive per measured axis")
        provider_failure = self.outcome in {
            QualificationAttemptOutcome.PROVIDER_FAILURE,
            QualificationAttemptOutcome.PROVIDER_DRIFT,
            QualificationAttemptOutcome.RAISED,
        }
        if provider_failure is not (self.provider_failure_kind is not None) or (
            provider_failure and self.provider_failure_kind != self.failure_category
        ):
            raise ValueError("provider failure must remain an orthogonal exact fact")
        if (
            self.outcome is not QualificationAttemptOutcome.MEASURED
            and self.accounting_basis is not QualificationAccountingBasis.RESERVED
        ):
            raise ValueError("non-success generation accounting must be conservative")
        if self.outcome is QualificationAttemptOutcome.MEASURED:
            if (
                not self.usage_measured
                or self.accounting_basis is not QualificationAccountingBasis.MEASURED
                or self.failure_category is not None
                or self.provider_failure_kind is not None
                or self.input_bound_status is not QualificationBoundStatus.WITHIN
                or self.output_bound_status is not QualificationBoundStatus.WITHIN
                or self.measured_input_tokens != self.accounted_input_tokens
                or self.measured_output_tokens != self.accounted_output_tokens
            ):
                raise ValueError("measured attempts require measured accounting")
        elif self.outcome is QualificationAttemptOutcome.CONTROL_FAILURE:
            if (
                self.usage_measured
                or self.accounting_basis is not QualificationAccountingBasis.RESERVED
                or self.failure_category != "control-unavailable"
                or self.provider_failure_kind is not None
            ):
                raise ValueError("control failures require reserved accounting")
        elif self.outcome is QualificationAttemptOutcome.RESERVATION_EXCEEDED:
            if (
                not self.usage_measured
                or self.accounting_basis is not QualificationAccountingBasis.RESERVED
                or self.failure_category != "reservation-exceeded"
                or self.provider_failure_kind is not None
                or QualificationBoundStatus.EXCEEDED
                not in {self.input_bound_status, self.output_bound_status}
            ):
                raise ValueError("reservation overrun must retain measured bounds")
        elif self.failure_category is None:
            raise ValueError("failed attempts require a sanitized failure category")
        if self.accounting_basis is QualificationAccountingBasis.RESERVED and (
            self.accounted_input_tokens < self.reserved_input_tokens
            or self.accounted_output_tokens < self.reserved_output_tokens
            or self.accounted_cost_nano_units < self.reserved_cost_nano_units
        ):
            raise ValueError("reserved accounting cannot undercharge a reservation")
        expected_accounted_cost = (
            self.accounted_input_tokens * _FROZEN_INPUT_COST_NANO_UNITS
            + self.accounted_output_tokens * _FROZEN_OUTPUT_COST_NANO_UNITS
        )
        if self.accounted_cost_nano_units != expected_accounted_cost:
            raise ValueError("generation accounted cost must derive from usage")
        return self


class QualificationModelUsageTotals(StrictModel):
    model_call_count: int = Field(ge=0, le=_MAX_SIGNED_64)
    count_tokens_call_count: int = Field(ge=0, le=_MAX_SIGNED_64)
    provider_request_count: int = Field(ge=0, le=_MAX_SIGNED_64)
    input_token_count: int = Field(ge=0, le=_MAX_SIGNED_64)
    output_token_count: int = Field(ge=0, le=_MAX_SIGNED_64)
    total_token_count: int = Field(ge=0, le=_MAX_SIGNED_64)
    model_cost_nano_units: int = Field(ge=0, le=_MAX_SIGNED_64)
    reserved_usage_count: int = Field(ge=0, le=_MAX_SIGNED_64)
    unexpected_missing_usage_count: int = Field(ge=0, le=_MAX_SIGNED_64)

    @model_validator(mode="after")
    def validate_totals(self) -> QualificationModelUsageTotals:
        if self.total_token_count != self.input_token_count + self.output_token_count:
            raise ValueError("model token totals must be additive")
        if (
            self.reserved_usage_count > self.model_call_count
            or self.unexpected_missing_usage_count > self.reserved_usage_count
            or self.provider_request_count
            > self.model_call_count + self.count_tokens_call_count
            or self.count_tokens_call_count > self.provider_request_count
        ):
            raise ValueError("model usage accounting counts exceed attempted calls")
        return self


class QualificationPriorModelUsageTotals(StrictModel):
    """Frozen usage shape retained by the historical custody artifact."""

    model_call_count: int = Field(ge=0, le=_MAX_SIGNED_64)
    input_token_count: int = Field(ge=0, le=_MAX_SIGNED_64)
    output_token_count: int = Field(ge=0, le=_MAX_SIGNED_64)
    total_token_count: int = Field(ge=0, le=_MAX_SIGNED_64)
    model_cost_nano_units: int = Field(ge=0, le=_MAX_SIGNED_64)
    reserved_usage_count: int = Field(ge=0, le=_MAX_SIGNED_64)
    unexpected_missing_usage_count: int = Field(ge=0, le=_MAX_SIGNED_64)

    @model_validator(mode="after")
    def validate_totals(self) -> QualificationPriorModelUsageTotals:
        if self.total_token_count != self.input_token_count + self.output_token_count:
            raise ValueError("historical model token totals must be additive")
        if (
            self.reserved_usage_count > self.model_call_count
            or self.unexpected_missing_usage_count > self.reserved_usage_count
        ):
            raise ValueError("historical usage counts exceed attempted calls")
        return self


def _project_prior_usage(
    usage: QualificationPriorModelUsageTotals,
) -> QualificationModelUsageTotals:
    """Project frozen historical totals into the current provider accounting."""

    return QualificationModelUsageTotals(
        model_call_count=usage.model_call_count,
        count_tokens_call_count=0,
        provider_request_count=usage.model_call_count,
        input_token_count=usage.input_token_count,
        output_token_count=usage.output_token_count,
        total_token_count=usage.total_token_count,
        model_cost_nano_units=usage.model_cost_nano_units,
        reserved_usage_count=usage.reserved_usage_count,
        unexpected_missing_usage_count=usage.unexpected_missing_usage_count,
    )


def _empty_usage() -> QualificationModelUsageTotals:
    return QualificationModelUsageTotals(
        model_call_count=0,
        count_tokens_call_count=0,
        provider_request_count=0,
        input_token_count=0,
        output_token_count=0,
        total_token_count=0,
        model_cost_nano_units=0,
        reserved_usage_count=0,
        unexpected_missing_usage_count=0,
    )


def _add_usage(
    left: QualificationModelUsageTotals,
    right: QualificationModelUsageTotals,
) -> QualificationModelUsageTotals:
    return QualificationModelUsageTotals(
        model_call_count=left.model_call_count + right.model_call_count,
        count_tokens_call_count=(
            left.count_tokens_call_count + right.count_tokens_call_count
        ),
        provider_request_count=(
            left.provider_request_count + right.provider_request_count
        ),
        input_token_count=left.input_token_count + right.input_token_count,
        output_token_count=left.output_token_count + right.output_token_count,
        total_token_count=left.total_token_count + right.total_token_count,
        model_cost_nano_units=(
            left.model_cost_nano_units + right.model_cost_nano_units
        ),
        reserved_usage_count=left.reserved_usage_count + right.reserved_usage_count,
        unexpected_missing_usage_count=(
            left.unexpected_missing_usage_count + right.unexpected_missing_usage_count
        ),
    )


def _attempt_totals(
    attempts: tuple[QualificationProviderAttempt, ...],
) -> QualificationModelUsageTotals:
    generations = tuple(
        item
        for item in attempts
        if item.operation is QualificationProviderOperation.GENERATE
    )
    counts = tuple(
        item
        for item in attempts
        if item.operation is QualificationProviderOperation.COUNT_TOKENS
    )
    reserved = sum(
        item.accounting_basis is QualificationAccountingBasis.RESERVED
        for item in generations
    )
    unexpected = sum(
        item.reserved_provider_request_count == 1 and not item.usage_measured
        for item in generations
    )
    inputs = sum(item.accounted_input_tokens for item in generations)
    outputs = sum(item.accounted_output_tokens for item in generations)
    return QualificationModelUsageTotals(
        model_call_count=len(generations),
        count_tokens_call_count=len(counts),
        provider_request_count=sum(
            item.reserved_provider_request_count for item in attempts
        ),
        input_token_count=inputs,
        output_token_count=outputs,
        total_token_count=inputs + outputs,
        model_cost_nano_units=sum(
            item.accounted_cost_nano_units for item in generations
        ),
        reserved_usage_count=reserved,
        unexpected_missing_usage_count=unexpected,
    )


def _validate_retained_adaptive_usage(
    usage: ComparisonModelUsage,
    generations: tuple[QualificationProviderAttempt, ...],
    token_counts: tuple[QualificationProviderAttempt, ...],
    runtime_identity: QualificationRuntimeIdentity,
    model_binding: QualificationModelBinding,
) -> None:
    dispatched_generations = tuple(
        item for item in generations if item.reserved_provider_request_count == 1
    )
    measured = usage.status is ComparisonModelUsageStatus.MEASURED
    all_attempt_usage_measured = bool(generations) and all(
        item.usage_measured for item in generations
    )
    if (
        usage.provider_name != runtime_identity.provider_name
        or usage.model_name != model_binding.configured_model
        or len(generations) != usage.model_call_count
        or len(token_counts) != len(dispatched_generations)
        or any(
            item.outcome is not QualificationAttemptOutcome.TOKEN_COUNTED
            for item in token_counts
        )
        or measured is not all_attempt_usage_measured
        or (
            measured
            and (
                usage.input_token_count
                != sum(item.measured_input_tokens or 0 for item in generations)
                or usage.output_token_count
                != sum(item.measured_output_tokens or 0 for item in generations)
            )
        )
    ):
        raise QualificationProtocolError("qualification adaptive model usage changed")


class QualificationAttemptLedger(StrictModel):
    schema_version: Literal[QUALIFICATION_ATTEMPT_LEDGER_VERSION]
    suite_id: Identifier
    manifest_sha256: Sha256Digest
    source_revision: Sha256Digest
    execution_basis: QualificationExecutionBasis
    planner_configuration_sha256: Sha256Digest
    attempts: tuple[QualificationProviderAttempt, ...] = Field(
        max_length=_FROZEN_MAX_CURRENT_OPERATION_RECORDS
    )
    attempt_starts: tuple[QualificationArtifactIdentity, ...] = Field(
        max_length=_FROZEN_MAX_CURRENT_OPERATION_RECORDS
    )
    attempt_finishes: tuple[QualificationArtifactIdentity, ...] = Field(
        max_length=_FROZEN_MAX_CURRENT_OPERATION_RECORDS
    )
    totals: QualificationModelUsageTotals

    @model_validator(mode="after")
    def validate_ledger(self) -> QualificationAttemptLedger:
        if tuple(item.sequence for item in self.attempts) != tuple(
            range(1, len(self.attempts) + 1)
        ):
            raise ValueError("qualification attempts must be contiguous")
        if self.totals != _attempt_totals(self.attempts):
            raise ValueError("qualification attempt totals must be derived")
        if not (
            len(self.attempt_starts) == len(self.attempts) == len(self.attempt_finishes)
        ):
            raise ValueError("qualification attempt artifacts must be complete")
        if any(
            item.execution_basis is not self.execution_basis
            or item.planner_configuration_sha256 != self.planner_configuration_sha256
            for item in self.attempts
        ):
            raise ValueError("qualification attempt identity changed within a stage")
        expected_ids = tuple(
            (
                f"attempt-{item.sequence:03d}-"
                f"{item.operation.value.lower().replace('_', '-')}"
            )
            for item in self.attempts
        )
        if tuple(item.attempt_id for item in self.attempts) != expected_ids:
            raise ValueError("qualification attempt identifiers are not canonical")
        if tuple(item.artifact_id for item in self.attempt_starts) != tuple(
            f"{attempt_id}-start" for attempt_id in expected_ids
        ) or tuple(item.artifact_id for item in self.attempt_finishes) != tuple(
            f"{attempt_id}-finish" for attempt_id in expected_ids
        ):
            raise ValueError("qualification attempt artifact identifiers changed")
        all_artifact_ids = tuple(
            item.artifact_id for item in (*self.attempt_starts, *self.attempt_finishes)
        )
        if len(all_artifact_ids) != len(set(all_artifact_ids)):
            raise ValueError("qualification attempt artifacts must be unique")
        preflight = tuple(
            item
            for item in self.attempts
            if item.execution_id == "provider-model-revision-preflight"
        )
        if self.attempts and (
            len(preflight) != 2
            or self.attempts[:2] != preflight
            or tuple(item.operation for item in preflight)
            != (
                QualificationProviderOperation.COUNT_TOKENS,
                QualificationProviderOperation.GENERATE,
            )
            or preflight[0].outcome is not QualificationAttemptOutcome.TOKEN_COUNTED
            or preflight[1].outcome is not QualificationAttemptOutcome.MEASURED
            or any(
                item.case_id != "provider-model-revision-preflight"
                or item.repetition != 1
                or item.planner_phase is not AdaptivePlannerPhase.ACQUIRE_EVIDENCE
                for item in preflight
            )
        ):
            raise ValueError("qualification preflight attempt pair is invalid")
        paired_dispatches: set[str] = set()
        for index, attempt in enumerate(self.attempts):
            if attempt.operation is QualificationProviderOperation.COUNT_TOKENS:
                expected_dispatch = (
                    f"dispatch-{attempt.sequence:03d}-{attempt.input_sha256[:16]}"
                )
                if attempt.dispatch_id != expected_dispatch:
                    raise ValueError("token-count dispatch identifier changed")
                if attempt.outcome is QualificationAttemptOutcome.TOKEN_COUNTED:
                    if index + 1 >= len(self.attempts):
                        raise ValueError("successful token count is orphaned")
                    generation = self.attempts[index + 1]
                    shared_fields = (
                        "dispatch_id",
                        "execution_id",
                        "case_id",
                        "repetition",
                        "planner_phase",
                        "execution_basis",
                        "planner_configuration_sha256",
                        "input_sha256",
                        "request_byte_count",
                        "sealed_generation_request_sha256",
                    )
                    if (
                        generation.operation
                        is not QualificationProviderOperation.GENERATE
                        or generation.paired_count_attempt_id != attempt.attempt_id
                        or any(
                            getattr(generation, field_name)
                            != getattr(attempt, field_name)
                            for field_name in shared_fields
                        )
                        or attempt.dispatch_id in paired_dispatches
                    ):
                        raise ValueError("token count and generation are not paired")
                    paired_dispatches.add(attempt.dispatch_id)
                continue
            if attempt.reserved_provider_request_count == 0:
                expected_control = (
                    f"control-{attempt.sequence:03d}-{attempt.input_sha256[:16]}"
                )
                if attempt.dispatch_id != expected_control:
                    raise ValueError("control dispatch identifier changed")
                continue
            if (
                index == 0
                or self.attempts[index - 1].attempt_id
                != attempt.paired_count_attempt_id
                or attempt.dispatch_id not in paired_dispatches
            ):
                raise ValueError("generation has no immediately preceding token count")
        return self


class QualificationPriorProviderAttempt(StrictModel):
    attempt_id: Identifier
    source_revision: Sha256Digest
    git_commit: str = Field(pattern=r"^[0-9a-f]{40}$")
    execution_basis: Literal[QualificationExecutionBasis.LIVE_PROVIDER]
    qualification_evidence_qualifying: Literal[False]
    started_at: AwareDatetime
    completed_at: AwareDatetime
    provider_name: Identifier
    configured_model: Identifier
    reported_model: Identifier | None = None
    location: Identifier
    timeout_ms: int = Field(ge=1, le=300_000)
    max_output_tokens: int = Field(ge=1, le=65_536)
    outcome: QualificationAttemptOutcome
    accounting_basis: QualificationAccountingBasis
    failure_category: Identifier | None = None
    historical_usage_basis: QualificationHistoricalUsageBasis
    reconstructed_request_byte_count: int | None = Field(
        default=None, ge=1, le=_MAX_SIGNED_64
    )
    accounted_input_tokens: int = Field(ge=0, le=_MAX_SIGNED_64)
    accounted_output_tokens: int = Field(ge=0, le=_MAX_SIGNED_64)
    input_cost_nano_units_per_token: int = Field(ge=0, le=_MAX_SIGNED_64)
    output_cost_nano_units_per_token: int = Field(ge=0, le=_MAX_SIGNED_64)
    accounted_cost_nano_units: int = Field(ge=0, le=_MAX_SIGNED_64)
    usage_measured: bool

    @model_validator(mode="after")
    def validate_cost(self) -> QualificationPriorProviderAttempt:
        expected = (
            self.accounted_input_tokens * self.input_cost_nano_units_per_token
            + self.accounted_output_tokens * self.output_cost_nano_units_per_token
        )
        if self.accounted_cost_nano_units != expected:
            raise ValueError("prior attempt cost must derive from accounted tokens")
        if self.usage_measured is (
            self.accounting_basis is QualificationAccountingBasis.RESERVED
        ):
            raise ValueError("prior attempt accounting basis contradicts usage")
        if self.accounting_basis is QualificationAccountingBasis.RESERVED:
            if (
                self.historical_usage_basis
                is not QualificationHistoricalUsageBasis.RECONSTRUCTED_REQUEST_BYTES_PLUS_8192
                or self.reconstructed_request_byte_count is None
                or self.accounted_input_tokens
                != self.reconstructed_request_byte_count
                + _HISTORICAL_RECONSTRUCTION_OVERHEAD
                or self.accounted_output_tokens != self.max_output_tokens
            ):
                raise ValueError(
                    "historical missing usage requires the captured request reservation"
                )
        elif (
            self.historical_usage_basis
            is not QualificationHistoricalUsageBasis.MEASURED_PROVIDER_USAGE
            or self.reconstructed_request_byte_count is not None
        ):
            raise ValueError("measured historical usage cannot claim a reservation")
        if self.source_revision != source_revision_for_git_commit(self.git_commit):
            raise ValueError(
                "historical attempt source digest must bind its Git commit"
            )
        if self.started_at >= self.completed_at:
            raise ValueError("historical attempt timestamps must be ordered")
        if self.outcome is QualificationAttemptOutcome.PROVIDER_FAILURE:
            if self.failure_category != PlannerFailureKind.UNAVAILABLE.value:
                raise ValueError("historical provider failure must retain its category")
        elif self.failure_category is not None:
            raise ValueError("successful historical attempts cannot claim a failure")
        return self


def _prior_totals(
    attempts: tuple[QualificationPriorProviderAttempt, ...],
) -> QualificationPriorModelUsageTotals:
    inputs = sum(item.accounted_input_tokens for item in attempts)
    outputs = sum(item.accounted_output_tokens for item in attempts)
    return QualificationPriorModelUsageTotals(
        model_call_count=len(attempts),
        input_token_count=inputs,
        output_token_count=outputs,
        total_token_count=inputs + outputs,
        model_cost_nano_units=sum(item.accounted_cost_nano_units for item in attempts),
        reserved_usage_count=sum(
            item.accounting_basis is QualificationAccountingBasis.RESERVED
            for item in attempts
        ),
        unexpected_missing_usage_count=0,
    )


class QualificationPriorAttemptLedger(StrictModel):
    """Byte-compatible decoder for the immutable historical v2 ledger."""

    schema_version: Literal[QUALIFICATION_PRIOR_ATTEMPT_LEDGER_VERSION]
    attempts: tuple[QualificationPriorProviderAttempt, ...] = Field(max_length=180)
    totals: QualificationPriorModelUsageTotals

    @model_validator(mode="after")
    def validate_ledger(self) -> QualificationPriorAttemptLedger:
        ids = tuple(item.attempt_id for item in self.attempts)
        if len(ids) != len(set(ids)):
            raise ValueError("prior qualification attempts must be unique")
        if self.totals != _prior_totals(self.attempts):
            raise ValueError("prior attempt totals must be derived")
        return self


QualificationHistoricalAttemptLedger = QualificationPriorAttemptLedger


def canonical_historical_attempt_ledger() -> QualificationPriorAttemptLedger:
    attempts = (
        QualificationPriorProviderAttempt(
            attempt_id="call_StJWb2dkWSLLVpHNOEaXeywn",
            source_revision=_HISTORICAL_SOURCE_REVISION,
            git_commit=_HISTORICAL_GIT_COMMIT,
            execution_basis=QualificationExecutionBasis.LIVE_PROVIDER,
            qualification_evidence_qualifying=False,
            started_at=datetime(2026, 8, 14, 11, 24, 10, 867_000, tzinfo=UTC),
            completed_at=datetime(2026, 8, 14, 11, 24, 20, 145_000, tzinfo=UTC),
            provider_name=_FROZEN_PROVIDER_NAME,
            configured_model=_FROZEN_MODEL_NAME,
            reported_model=None,
            location=_FROZEN_PROVIDER_LOCATION,
            timeout_ms=4_250,
            max_output_tokens=1_024,
            outcome=QualificationAttemptOutcome.PROVIDER_FAILURE,
            accounting_basis=QualificationAccountingBasis.RESERVED,
            failure_category=PlannerFailureKind.UNAVAILABLE.value,
            historical_usage_basis=(
                QualificationHistoricalUsageBasis.RECONSTRUCTED_REQUEST_BYTES_PLUS_8192
            ),
            reconstructed_request_byte_count=3_525,
            accounted_input_tokens=11_717,
            accounted_output_tokens=1_024,
            input_cost_nano_units_per_token=_FROZEN_INPUT_COST_NANO_UNITS,
            output_cost_nano_units_per_token=_FROZEN_OUTPUT_COST_NANO_UNITS,
            accounted_cost_nano_units=26_791_500,
            usage_measured=False,
        ),
        QualificationPriorProviderAttempt(
            attempt_id="call_0q88mBIC82Av6mw2a8PlMEIb",
            source_revision=_HISTORICAL_SOURCE_REVISION,
            git_commit=_HISTORICAL_GIT_COMMIT,
            execution_basis=QualificationExecutionBasis.LIVE_PROVIDER,
            qualification_evidence_qualifying=False,
            started_at=datetime(2026, 8, 14, 11, 24, 40, 634_000, tzinfo=UTC),
            completed_at=datetime(2026, 8, 14, 11, 24, 43, 272_000, tzinfo=UTC),
            provider_name=_FROZEN_PROVIDER_NAME,
            configured_model=_FROZEN_MODEL_NAME,
            reported_model=None,
            location=_FROZEN_PROVIDER_LOCATION,
            timeout_ms=30_000,
            max_output_tokens=16,
            outcome=QualificationAttemptOutcome.USAGE_UNAVAILABLE,
            accounting_basis=QualificationAccountingBasis.RESERVED,
            historical_usage_basis=(
                QualificationHistoricalUsageBasis.RECONSTRUCTED_REQUEST_BYTES_PLUS_8192
            ),
            reconstructed_request_byte_count=30,
            accounted_input_tokens=8_222,
            accounted_output_tokens=16,
            input_cost_nano_units_per_token=_FROZEN_INPUT_COST_NANO_UNITS,
            output_cost_nano_units_per_token=_FROZEN_OUTPUT_COST_NANO_UNITS,
            accounted_cost_nano_units=12_477_000,
            usage_measured=False,
        ),
        QualificationPriorProviderAttempt(
            attempt_id="call_dlT8NpkWkVNx8XJDgrlyHGAo",
            source_revision=_HISTORICAL_SOURCE_REVISION,
            git_commit=_HISTORICAL_GIT_COMMIT,
            execution_basis=QualificationExecutionBasis.LIVE_PROVIDER,
            qualification_evidence_qualifying=False,
            started_at=datetime(2026, 8, 14, 11, 25, 53, 61_000, tzinfo=UTC),
            completed_at=datetime(2026, 8, 14, 11, 25, 56, 410_000, tzinfo=UTC),
            provider_name=_FROZEN_PROVIDER_NAME,
            configured_model=_FROZEN_MODEL_NAME,
            reported_model=None,
            location=_FROZEN_PROVIDER_LOCATION,
            timeout_ms=30_000,
            max_output_tokens=128,
            outcome=QualificationAttemptOutcome.MEASURED,
            accounting_basis=QualificationAccountingBasis.MEASURED,
            historical_usage_basis=(
                QualificationHistoricalUsageBasis.MEASURED_PROVIDER_USAGE
            ),
            reconstructed_request_byte_count=None,
            accounted_input_tokens=6,
            accounted_output_tokens=85,
            input_cost_nano_units_per_token=_FROZEN_INPUT_COST_NANO_UNITS,
            output_cost_nano_units_per_token=_FROZEN_OUTPUT_COST_NANO_UNITS,
            accounted_cost_nano_units=774_000,
            usage_measured=True,
        ),
    )
    return QualificationPriorAttemptLedger(
        schema_version=QUALIFICATION_PRIOR_ATTEMPT_LEDGER_VERSION,
        attempts=attempts,
        totals=_prior_totals(attempts),
    )


def _project_v2_usage(
    usage: QualificationV2UsageTotals,
) -> QualificationModelUsageTotals:
    return QualificationModelUsageTotals(
        model_call_count=usage.model_call_count,
        count_tokens_call_count=usage.count_tokens_call_count,
        provider_request_count=usage.provider_request_count,
        input_token_count=usage.input_token_count,
        output_token_count=usage.output_token_count,
        total_token_count=usage.total_token_count,
        model_cost_nano_units=usage.model_cost_nano_units,
        reserved_usage_count=usage.reserved_usage_count,
        unexpected_missing_usage_count=usage.unexpected_missing_usage_count,
    )


class QualificationCombinedPriorAttemptLedger(StrictModel):
    schema_version: Literal[QUALIFICATION_COMBINED_PRIOR_ATTEMPT_LEDGER_VERSION]
    historical_attempt_ledger: QualificationPriorAttemptLedger
    historical_attempt_ledger_sha256: Sha256Digest
    consumed_v2_custody_sha256: Sha256Digest
    historical_usage: QualificationModelUsageTotals
    consumed_v2_usage: QualificationModelUsageTotals
    totals: QualificationModelUsageTotals

    @model_validator(mode="after")
    def validate_ledger(self) -> QualificationCombinedPriorAttemptLedger:
        if (
            self.historical_attempt_ledger_sha256
            != canonical_sha256(self.historical_attempt_ledger)
            or self.historical_usage
            != _project_prior_usage(self.historical_attempt_ledger.totals)
            or self.totals != _add_usage(self.historical_usage, self.consumed_v2_usage)
        ):
            raise ValueError("combined prior-attempt custody must be derived")
        return self


def canonical_prior_attempt_ledger(
    custody: QualificationConsumedV2Custody | None = None,
) -> QualificationCombinedPriorAttemptLedger:
    consumed = canonical_consumed_v2_custody() if custody is None else custody
    historical = canonical_historical_attempt_ledger()
    return QualificationCombinedPriorAttemptLedger(
        schema_version=QUALIFICATION_COMBINED_PRIOR_ATTEMPT_LEDGER_VERSION,
        historical_attempt_ledger=historical,
        historical_attempt_ledger_sha256=canonical_sha256(historical),
        consumed_v2_custody_sha256=canonical_sha256(consumed),
        historical_usage=_project_v2_usage(consumed.historical_totals),
        consumed_v2_usage=_project_v2_usage(consumed.consumed_v2_totals),
        totals=_project_v2_usage(consumed.combined_totals),
    )


class QualificationCaseExecutionRecord(StrictModel):
    schema_version: Literal[QUALIFICATION_CASE_EXECUTION_VERSION]
    execution_id: Identifier
    case_id: Identifier
    repetition: int = Field(ge=1, le=16)
    lane_order: QualificationLaneOrder
    status: QualificationCaseResultStatus
    runtime_identity_sha256: Sha256Digest
    result: QualificationArtifactIdentity
    lane_receipts: tuple[QualificationArtifactIdentity, ...] = Field(max_length=2)
    failure_record: QualificationArtifactIdentity | None = None

    @model_validator(mode="after")
    def validate_failure_graph(self) -> QualificationCaseExecutionRecord:
        failed = self.status in {
            QualificationCaseResultStatus.FAILED,
            QualificationCaseResultStatus.INVALID,
            QualificationCaseResultStatus.CONTROL_FAILED,
        }
        if (self.failure_record is not None) is not failed:
            raise ValueError("case failure roots must match the result status")
        return self


class QualificationProtocolLaneMetrics(StrictModel):
    strategy_kind: ComparisonStrategyKind
    run_count: int = Field(ge=0, le=128)
    acquisition_proposal_count: int = Field(ge=0, le=_MAX_SIGNED_64)
    selected_proposal_count: int = Field(ge=0, le=_MAX_SIGNED_64)
    deferred_proposal_count: int = Field(ge=0, le=_MAX_SIGNED_64)
    unsupported_proposal_count: int = Field(ge=0, le=_MAX_SIGNED_64)
    invalid_proposal_count: int = Field(ge=0, le=_MAX_SIGNED_64)
    duplicate_proposal_count: int = Field(ge=0, le=_MAX_SIGNED_64)
    unavailable_proposal_count: int = Field(ge=0, le=_MAX_SIGNED_64)
    budget_exceeded_proposal_count: int = Field(ge=0, le=_MAX_SIGNED_64)
    ignored_explanation_proposal_count: int = Field(ge=0, le=_MAX_SIGNED_64)
    planned_probe_count: int = Field(ge=0, le=_MAX_SIGNED_64)
    executed_probe_count: int = Field(ge=0, le=_MAX_SIGNED_64)
    unsupported_probe_count: int = Field(ge=0, le=_MAX_SIGNED_64)
    unavailable_probe_count: int = Field(ge=0, le=_MAX_SIGNED_64)
    unnecessary_probe_count: int = Field(ge=0, le=_MAX_SIGNED_64)
    duplicate_probe_count: int = Field(ge=0, le=_MAX_SIGNED_64)
    total_elapsed_ms: int = Field(ge=0, le=_MAX_SIGNED_64)
    model_call_count: int = Field(ge=0, le=_MAX_SIGNED_64)
    input_token_count: int = Field(ge=0, le=_MAX_SIGNED_64)
    output_token_count: int = Field(ge=0, le=_MAX_SIGNED_64)
    total_token_count: int = Field(ge=0, le=_MAX_SIGNED_64)
    model_cost_nano_units: int = Field(ge=0, le=_MAX_SIGNED_64)

    @model_validator(mode="after")
    def validate_metrics(self) -> QualificationProtocolLaneMetrics:
        if self.total_token_count != self.input_token_count + self.output_token_count:
            raise ValueError("protocol lane token totals must be additive")
        proposal_partition = sum(
            (
                self.selected_proposal_count,
                self.deferred_proposal_count,
                self.unsupported_proposal_count,
                self.invalid_proposal_count,
                self.duplicate_proposal_count,
                self.unavailable_proposal_count,
                self.budget_exceeded_proposal_count,
            )
        )
        if proposal_partition != self.acquisition_proposal_count:
            raise ValueError("protocol lane proposal metrics must partition proposals")
        if self.strategy_kind is ComparisonStrategyKind.FIXED and any(
            (
                self.acquisition_proposal_count,
                self.ignored_explanation_proposal_count,
                self.model_call_count,
                self.input_token_count,
                self.output_token_count,
                self.model_cost_nano_units,
            )
        ):
            raise ValueError("fixed protocol metrics cannot contain model facts")
        return self


class QualificationProtocolSummary(StrictModel):
    schema_version: Literal[QUALIFICATION_PROTOCOL_SUMMARY_VERSION]
    suite_id: Identifier
    manifest_sha256: Sha256Digest
    result_set_sha256: Sha256Digest
    qualification_summary: QualificationArtifactIdentity
    attempt_ledger_sha256: Sha256Digest
    model_binding_sha256: Sha256Digest
    prior_attempt_ledger_sha256: Sha256Digest | None
    historical_attempt_ledger_sha256: Sha256Digest
    consumed_v2_custody_sha256: Sha256Digest
    prior_stage_completion_sha256: Sha256Digest | None
    execution_basis: QualificationExecutionBasis
    planner_configuration_sha256: Sha256Digest
    case_executions: tuple[QualificationArtifactIdentity, ...] = Field(max_length=128)
    fixed_metrics: QualificationProtocolLaneMetrics
    adaptive_metrics: QualificationProtocolLaneMetrics
    qualification_attempt_usage: QualificationModelUsageTotals
    historical_attempt_usage: QualificationModelUsageTotals
    consumed_v2_attempt_usage: QualificationModelUsageTotals
    prior_attempt_usage: QualificationModelUsageTotals
    ceiling_usage: QualificationModelUsageTotals
    maximum_total_model_calls: int = Field(ge=1, le=_MAX_SIGNED_64)
    maximum_total_count_tokens_calls: int = Field(ge=1, le=_MAX_SIGNED_64)
    maximum_total_provider_requests: int = Field(ge=1, le=_MAX_SIGNED_64)
    maximum_total_input_tokens: int = Field(ge=1, le=_MAX_SIGNED_64)
    maximum_total_output_tokens: int = Field(ge=1, le=_MAX_SIGNED_64)
    maximum_total_model_cost_nano_units: int = Field(ge=1, le=_MAX_SIGNED_64)
    usage_incomplete: bool
    provider_limit_exceeded: bool
    qualification_valid_for_value_evidence: bool
    protocol_valid: bool
    provider_evidence_qualifying: bool
    successful: bool

    @model_validator(mode="after")
    def validate_summary(self) -> QualificationProtocolSummary:
        if self.fixed_metrics.strategy_kind is not ComparisonStrategyKind.FIXED:
            raise ValueError("protocol fixed metrics use the wrong strategy")
        if self.adaptive_metrics.strategy_kind is not ComparisonStrategyKind.ADAPTIVE:
            raise ValueError("protocol adaptive metrics use the wrong strategy")
        custody = canonical_consumed_v2_custody()
        historical = canonical_historical_attempt_ledger()
        if (
            self.historical_attempt_ledger_sha256 != canonical_sha256(historical)
            or self.consumed_v2_custody_sha256 != canonical_sha256(custody)
            or self.historical_attempt_usage
            != _project_v2_usage(custody.historical_totals)
            or self.consumed_v2_attempt_usage
            != _project_v2_usage(custody.consumed_v2_totals)
        ):
            raise ValueError("protocol legacy custody totals changed")
        expected_ceiling = _add_usage(
            self.qualification_attempt_usage, self.prior_attempt_usage
        )
        if self.ceiling_usage != expected_ceiling:
            raise ValueError("protocol ceiling usage must include prior attempts")
        incomplete = self.qualification_attempt_usage.unexpected_missing_usage_count > 0
        exceeded = any(
            (
                self.ceiling_usage.model_call_count > self.maximum_total_model_calls,
                self.ceiling_usage.count_tokens_call_count
                > self.maximum_total_count_tokens_calls,
                self.ceiling_usage.provider_request_count
                > self.maximum_total_provider_requests,
                self.ceiling_usage.input_token_count > self.maximum_total_input_tokens,
                self.ceiling_usage.output_token_count
                > self.maximum_total_output_tokens,
                self.ceiling_usage.model_cost_nano_units
                > self.maximum_total_model_cost_nano_units,
            )
        )
        if self.usage_incomplete is not incomplete:
            raise ValueError("protocol usage completeness must be derived")
        if self.provider_limit_exceeded is not exceeded:
            raise ValueError("protocol provider ceiling state must be derived")
        protocol_valid = all(
            (
                self.qualification_valid_for_value_evidence,
                not self.usage_incomplete,
                not self.provider_limit_exceeded,
            )
        )
        qualifying = self.execution_basis is QualificationExecutionBasis.LIVE_PROVIDER
        if self.protocol_valid is not protocol_valid:
            raise ValueError("protocol validity must be derived")
        if self.provider_evidence_qualifying is not qualifying:
            raise ValueError("provider evidence eligibility must be derived")
        if self.successful is not (protocol_valid and qualifying):
            raise ValueError("protocol success must be derived")
        return self


class QualificationExecutionCompletion(StrictModel):
    schema_version: Literal[QUALIFICATION_EXECUTION_COMPLETION_VERSION]
    stage: QualificationProtocolStage
    suite_id: Identifier
    manifest_sha256: Sha256Digest
    source_revision: Sha256Digest
    git_commit: str = Field(pattern=r"^[0-9a-f]{40}$")
    provider_settings_sha256: Sha256Digest
    planner_configuration_sha256: Sha256Digest
    runtime_identity: QualificationArtifactIdentity
    model_binding: QualificationArtifactIdentity
    execution_basis: QualificationExecutionBasis
    prior_stage_completion_sha256: Sha256Digest | None
    historical_attempt_ledger_sha256: Sha256Digest
    consumed_v2_custody_sha256: Sha256Digest
    completed_at: AwareDatetime
    protocol_valid: bool
    provider_evidence_qualifying: bool
    successful: bool
    manifest: QualificationArtifactIdentity
    execution_start: QualificationArtifactIdentity
    result_set: QualificationArtifactIdentity
    attempt_ledger: QualificationArtifactIdentity
    prior_attempt_ledger: QualificationArtifactIdentity | None
    consumed_v2_custody: QualificationArtifactIdentity | None
    qualification_summary: QualificationArtifactIdentity
    protocol_summary: QualificationArtifactIdentity
    disposition: QualificationArtifactIdentity
    case_executions: tuple[QualificationArtifactIdentity, ...] = Field(max_length=128)
    retained_artifacts: tuple[QualificationArtifactIdentity, ...] = Field(
        max_length=2_048
    )

    @model_validator(mode="after")
    def validate_graph_roots(self) -> QualificationExecutionCompletion:
        roots = (
            self.manifest,
            self.runtime_identity,
            self.model_binding,
            self.execution_start,
            self.result_set,
            self.attempt_ledger,
            self.qualification_summary,
            self.protocol_summary,
            self.disposition,
            *self.case_executions,
            *(
                ()
                if self.prior_attempt_ledger is None
                else (self.prior_attempt_ledger,)
            ),
            *(() if self.consumed_v2_custody is None else (self.consumed_v2_custody,)),
        )
        retained = {(item.artifact_id, item.sha256) for item in self.retained_artifacts}
        if any((item.artifact_id, item.sha256) not in retained for item in roots):
            raise ValueError("completion roots must be retained artifacts")
        identities = tuple(item.artifact_id for item in self.retained_artifacts)
        if len(identities) != len(set(identities)):
            raise ValueError("completion retained artifacts must be unique")
        qualifying = self.execution_basis is QualificationExecutionBasis.LIVE_PROVIDER
        if (
            self.source_revision != source_revision_for_git_commit(self.git_commit)
            or self.runtime_identity.sha256 != self.planner_configuration_sha256
            or self.provider_evidence_qualifying is not qualifying
            or self.successful is not (self.protocol_valid and qualifying)
        ):
            raise ValueError("completion outcome or source identity is inconsistent")
        return self


class QualificationSourceState(StrictModel):
    source_revision: Sha256Digest
    git_commit: str = Field(pattern=r"^[0-9a-f]{40}$")
    clean: bool


class QualificationProtocolOutcome(StrictModel):
    stage: QualificationProtocolStage
    result_set: QualificationResultSet
    attempt_ledger: QualificationAttemptLedger
    qualification_summary: QualificationSummary
    protocol_summary: QualificationProtocolSummary
    disposition: QualificationDisposition
    completion: QualificationExecutionCompletion


def source_revision_for_git_commit(git_commit: str) -> str:
    """Bind the public SHA-256 source field to one exact Git commit identity."""

    if type(git_commit) is not str or _GIT_COMMIT_SHA1.fullmatch(git_commit) is None:
        raise ValueError("Git commit identity must be an exact lowercase SHA-1")
    return hashlib.sha256(git_commit.encode("ascii")).hexdigest()


def repository_source_state(repository: str | Path) -> QualificationSourceState:
    path = Path(repository).resolve()
    revision = subprocess.run(
        ("git", "rev-parse", "HEAD"),
        cwd=path,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    status = subprocess.run(
        ("git", "status", "--porcelain"),
        cwd=path,
        check=True,
        capture_output=True,
        text=True,
    ).stdout
    return QualificationSourceState(
        source_revision=source_revision_for_git_commit(revision),
        git_commit=revision,
        clean=not status,
    )


class QualificationArtifactStore:
    """Atomically publish canonical immutable artifacts beneath a consumed stage."""

    def __init__(
        self,
        root: str | Path,
        *,
        v2_custody_source: QualificationV2CustodySource | None = None,
        repository: str | Path | None = None,
    ) -> None:
        candidate = Path(root).absolute()
        if candidate.name != "qualification-protocol-v3":
            raise QualificationProtocolError(
                "artifact root must use the qualification-protocol-v3 namespace"
            )
        for path in (candidate, *candidate.parents):
            try:
                path_stat = path.lstat()
            except FileNotFoundError:
                continue
            if stat.S_ISLNK(path_stat.st_mode):
                raise QualificationProtocolError(
                    "artifact path cannot traverse a symlink"
                )
        candidate = candidate.resolve(strict=False)
        if repository is not None:
            repository_path = Path(repository).resolve(strict=True)
            if candidate == repository_path or candidate.is_relative_to(
                repository_path
            ):
                raise QualificationProtocolError(
                    "qualification artifacts must remain outside the source repository"
                )
        if v2_custody_source is not None:
            try:
                load_consumed_v2_custody(v2_custody_source)
            except Exception as error:
                raise QualificationProtocolError(
                    "consumed-v2 custody source is unsafe"
                ) from error
            source_paths = (
                v2_custody_source.stage_directory.resolve(strict=True),
                v2_custody_source.launcher_file.resolve(strict=True),
            )
            if any(
                candidate == source_path
                or candidate.is_relative_to(source_path)
                or source_path.is_relative_to(candidate)
                for source_path in source_paths
            ):
                raise QualificationProtocolError(
                    "v3 artifact and consumed-v2 custody paths must not overlap"
                )
        self.root = candidate
        self.v2_custody_source = v2_custody_source
        self.root.mkdir(mode=0o700, parents=True, exist_ok=True)
        os.chmod(self.root, 0o700)
        self._stage_path: Path | None = None
        self._stage_fd: int | None = None
        self._final_registry_created = False
        self._poisoned = False

    def begin(self, stage: QualificationProtocolStage) -> None:
        path = self.root / stage.value
        try:
            os.mkdir(path, 0o700)
        except FileExistsError as error:
            raise QualificationExecutionConsumed(
                "qualification stage has already been consumed"
            ) from error
        self._stage_path = path
        self._stage_fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        self._fsync_directory(self.root)

    @staticmethod
    def _fsync_directory(path: Path) -> None:
        descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)

    @property
    def stage_path(self) -> Path:
        if self._stage_path is None:
            raise QualificationProtocolError("artifact stage has not started")
        return self._stage_path

    @property
    def stage_fd(self) -> int:
        if self._stage_fd is None:
            raise QualificationProtocolError("artifact stage has not started")
        return self._stage_fd

    @staticmethod
    def _validate_canonical_json(payload: bytes) -> None:
        if type(payload) is not bytes:
            raise TypeError("qualification artifact payload must be bytes")
        try:
            parsed = json.loads(payload)
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise ValueError("qualification artifacts must contain JSON") from error
        if canonical_json_value_bytes(parsed) != payload:
            raise ValueError("qualification artifacts must use canonical JSON")
        _reject_artifact_secret_keys(parsed)
        reject_sensitive_values(parsed)

    def publish_bytes(
        self,
        artifact_id: str,
        payload: bytes,
    ) -> QualificationArtifactIdentity:
        if self._poisoned:
            raise QualificationProtocolError(
                "qualification artifact store has an unresolved publication"
            )
        if _ARTIFACT_ID.fullmatch(artifact_id) is None:
            raise ValueError("qualification artifact identity is invalid")
        self._validate_canonical_json(payload)
        final_name = f"{artifact_id}.json"
        temporary_name = f".{artifact_id}.{secrets.token_hex(12)}.tmp"
        descriptor = os.open(
            temporary_name,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
            0o600,
            dir_fd=self.stage_fd,
        )
        linked = False
        temporary_exists = True
        try:
            view = memoryview(payload)
            while view:
                written = os.write(descriptor, view)
                view = view[written:]
            os.fsync(descriptor)
            os.fchmod(descriptor, 0o400)
            try:
                os.link(
                    temporary_name,
                    final_name,
                    src_dir_fd=self.stage_fd,
                    dst_dir_fd=self.stage_fd,
                    follow_symlinks=False,
                )
            except FileExistsError as error:
                raise QualificationExecutionConsumed(
                    "qualification artifact cannot be overwritten"
                ) from error
            except OSError as error:
                raise _ArtifactLinkOutcomeAmbiguous(
                    "qualification artifact link outcome is ambiguous"
                ) from error
            linked = True
            os.fsync(self.stage_fd)
            os.unlink(temporary_name, dir_fd=self.stage_fd)
            temporary_exists = False
            os.fsync(self.stage_fd)
        except BaseException:
            if linked:
                self._poisoned = True
                self._invalidate_linked_artifact(descriptor, final_name)
            if temporary_exists:
                try:
                    os.unlink(temporary_name, dir_fd=self.stage_fd)
                    temporary_exists = False
                except FileNotFoundError:
                    temporary_exists = False
                except OSError:
                    self._poisoned = True
            raise
        finally:
            os.close(descriptor)
        return artifact_identity(artifact_id, payload)

    def _invalidate_linked_artifact(self, descriptor: int, final_name: str) -> None:
        """Make a failed post-link publication unreadable across fresh readers."""

        try:
            os.fchmod(descriptor, 0)
            os.fsync(descriptor)
        except OSError:
            pass
        try:
            os.unlink(final_name, dir_fd=self.stage_fd)
        except OSError:
            pass
        try:
            os.fsync(self.stage_fd)
        except OSError:
            pass

    def publish(
        self,
        artifact_id: str,
        model: StrictModel,
    ) -> QualificationArtifactIdentity:
        payload = canonical_json_bytes(model)
        try:
            return self.publish_bytes(artifact_id, payload)
        except _ArtifactLinkOutcomeAmbiguous:
            committed = self.resolve_committed(artifact_id, model)
            if committed is None:
                self._poisoned = True
                raise
            return committed

    def resolve_committed(
        self,
        artifact_id: str,
        model: StrictModel,
    ) -> QualificationArtifactIdentity | None:
        """Resolve an exact immutable link after an ambiguous publication error."""

        if self._poisoned:
            raise QualificationProtocolError(
                "qualification artifact store has an unresolved publication"
            )
        payload = canonical_json_bytes(model)
        descriptor = -1
        try:
            descriptor = os.open(
                f"{artifact_id}.json",
                os.O_RDONLY | os.O_NOFOLLOW,
                dir_fd=self.stage_fd,
            )
            metadata = os.fstat(descriptor)
            if (
                not stat.S_ISREG(metadata.st_mode)
                or stat.S_IMODE(metadata.st_mode) != 0o400
            ):
                self._poisoned = True
                return None
            chunks: list[bytes] = []
            while chunk := os.read(descriptor, 64 * 1024):
                chunks.append(chunk)
            if b"".join(chunks) != payload:
                self._poisoned = True
                return None
            if any(
                name.startswith(".") and name.endswith(".tmp")
                for name in os.listdir(self.stage_fd)
            ):
                self._poisoned = True
                return None
            os.fsync(self.stage_fd)
        except OSError:
            if descriptor >= 0:
                self._poisoned = True
            return None
        finally:
            if descriptor >= 0:
                os.close(descriptor)
        return artifact_identity(artifact_id, payload)

    def runtime_path(self, stage: QualificationProtocolStage) -> Path:
        path = self.root / f".runtime-{stage.value}"
        try:
            os.mkdir(path, 0o700)
        except FileExistsError as error:
            raise QualificationExecutionConsumed(
                "qualification runtime has already been consumed"
            ) from error
        self._fsync_directory(self.root)
        return path

    def _read_identity(
        self,
        stage: QualificationProtocolStage,
        identity: QualificationArtifactIdentity,
    ) -> bytes:
        payload, mode = self._read_stage_file(stage, f"{identity.artifact_id}.json")
        self._validate_canonical_json(payload)
        if (
            mode != 0o400
            or len(payload) != identity.byte_count
            or hashlib.sha256(payload).hexdigest() != identity.sha256
        ):
            raise QualificationProtocolError(
                "qualification artifact identity or custody changed"
            )
        return payload

    def _read_stage_file(
        self, stage: QualificationProtocolStage, name: str
    ) -> tuple[bytes, int]:
        stage_descriptor = -1
        descriptor = -1
        try:
            stage_descriptor = os.open(
                self.root / stage.value,
                os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
            )
            descriptor = os.open(
                name,
                os.O_RDONLY | os.O_NOFOLLOW,
                dir_fd=stage_descriptor,
            )
            file_stat = os.fstat(descriptor)
            if not stat.S_ISREG(file_stat.st_mode):
                raise QualificationProtocolError(
                    "qualification artifact is not a regular file"
                )
            chunks: list[bytes] = []
            while chunk := os.read(descriptor, 64 * 1024):
                chunks.append(chunk)
            return b"".join(chunks), stat.S_IMODE(file_stat.st_mode)
        except QualificationProtocolError:
            raise
        except OSError as error:
            raise QualificationProtocolError(
                "required qualification artifact is missing or unsafe"
            ) from error
        finally:
            if descriptor >= 0:
                os.close(descriptor)
            if stage_descriptor >= 0:
                os.close(stage_descriptor)

    def read_completion(
        self,
        stage: QualificationProtocolStage,
    ) -> QualificationExecutionCompletion:
        payload, completion_mode = self._read_stage_file(
            stage, "execution-completion.json"
        )
        self._validate_canonical_json(payload)
        if completion_mode != 0o400:
            raise QualificationProtocolError("qualification completion custody changed")
        completion = decode_contract(payload, QualificationExecutionCompletion)
        if completion.stage is not stage:
            raise QualificationProtocolError("qualification completion stage changed")
        if completion.execution_basis is QualificationExecutionBasis.LIVE_PROVIDER:
            if self.v2_custody_source is None:
                raise QualificationProtocolError(
                    "live completion read requires consumed-v2 custody source"
                )
            try:
                consumed_v2_custody = load_consumed_v2_custody(self.v2_custody_source)
            except Exception as error:
                raise QualificationProtocolError(
                    "consumed-v2 custody revalidation failed"
                ) from error
        else:
            consumed_v2_custody = canonical_consumed_v2_custody()
        if completion.consumed_v2_custody_sha256 != canonical_sha256(
            consumed_v2_custody
        ):
            raise QualificationProtocolError(
                "qualification consumed-v2 custody identity changed"
            )
        reachable: set[tuple[str, str]] = set()

        def mark(identity: QualificationArtifactIdentity | None) -> None:
            if identity is not None:
                reachable.add((identity.artifact_id, identity.sha256))

        for root in (
            completion.manifest,
            completion.runtime_identity,
            completion.model_binding,
            completion.execution_start,
            completion.result_set,
            completion.attempt_ledger,
            completion.prior_attempt_ledger,
            completion.consumed_v2_custody,
            completion.qualification_summary,
            completion.protocol_summary,
            completion.disposition,
            *completion.case_executions,
        ):
            mark(root)
        for identity in completion.retained_artifacts:
            self._read_identity(stage, identity)
        manifest = decode_contract(
            self._read_identity(stage, completion.manifest),
            QualificationSuiteManifest,
        )
        runtime_identity = decode_contract(
            self._read_identity(stage, completion.runtime_identity),
            QualificationRuntimeIdentity,
        )
        model_binding = decode_contract(
            self._read_identity(stage, completion.model_binding),
            QualificationModelBinding,
        )
        validate_protocol_manifest(stage, manifest)
        if (
            completion.manifest.artifact_id != "manifest"
            or completion.runtime_identity.artifact_id != "runtime-identity"
            or completion.model_binding.artifact_id != "provider-model-binding"
            or completion.execution_start.artifact_id != "execution-start"
            or completion.result_set.artifact_id != "result-set"
            or completion.attempt_ledger.artifact_id != "attempt-ledger"
            or completion.qualification_summary.artifact_id
            != "qualification-summary-v1"
            or completion.protocol_summary.artifact_id != "summary"
            or completion.disposition.artifact_id != "disposition"
            or (
                completion.prior_attempt_ledger is not None
                and completion.prior_attempt_ledger.artifact_id
                != "prior-attempt-ledger"
            )
            or (
                completion.consumed_v2_custody is not None
                and completion.consumed_v2_custody.artifact_id != "consumed-v2-custody"
            )
            or completion.manifest.sha256 != completion.manifest_sha256
            or completion.suite_id != manifest.suite_id
            or completion.source_revision != manifest.source_revision
            or completion.source_revision
            != source_revision_for_git_commit(completion.git_commit)
            or completion.provider_settings_sha256
            != canonical_sha256(manifest.provider)
            or runtime_identity != frozen_qualification_runtime_identity()
            or completion.runtime_identity.sha256
            != completion.planner_configuration_sha256
            or model_binding.suite_id != completion.suite_id
            or model_binding.runtime_identity_sha256
            != completion.planner_configuration_sha256
            or model_binding.configured_model != runtime_identity.configured_model
            or completion.historical_attempt_ledger_sha256
            != canonical_sha256(canonical_historical_attempt_ledger())
            or completion.consumed_v2_custody_sha256
            != canonical_sha256(consumed_v2_custody)
        ):
            raise QualificationProtocolError(
                "qualification completion provenance is inconsistent"
            )
        start = decode_contract(
            self._read_identity(stage, completion.execution_start),
            QualificationExecutionStart,
        )
        if (
            start.stage is not stage
            or start.suite_id != completion.suite_id
            or start.manifest_sha256 != completion.manifest_sha256
            or start.source_revision != completion.source_revision
            or start.git_commit != completion.git_commit
            or start.provider_settings_sha256 != completion.provider_settings_sha256
            or start.planner_configuration_sha256
            != completion.planner_configuration_sha256
            or start.runtime_identity != completion.runtime_identity
            or start.model_binding != completion.model_binding
            or start.execution_basis is not completion.execution_basis
            or start.prior_stage_completion_sha256
            != completion.prior_stage_completion_sha256
            or start.prior_attempt_ledger_sha256
            != (
                None
                if completion.prior_attempt_ledger is None
                else completion.prior_attempt_ledger.sha256
            )
            or start.historical_attempt_ledger_sha256
            != completion.historical_attempt_ledger_sha256
            or start.consumed_v2_custody_sha256 != completion.consumed_v2_custody_sha256
        ):
            raise QualificationProtocolError(
                "qualification execution start is inconsistent"
            )
        result_set = decode_contract(
            self._read_identity(stage, completion.result_set), QualificationResultSet
        )
        attempt_ledger = decode_contract(
            self._read_identity(stage, completion.attempt_ledger),
            QualificationAttemptLedger,
        )
        qualification_summary = decode_contract(
            self._read_identity(stage, completion.qualification_summary),
            QualificationSummary,
        )
        protocol_summary = decode_contract(
            self._read_identity(stage, completion.protocol_summary),
            QualificationProtocolSummary,
        )
        disposition = decode_contract(
            self._read_identity(stage, completion.disposition),
            QualificationDisposition,
        )
        if (
            result_set.suite_id != completion.suite_id
            or result_set.manifest_sha256 != completion.manifest_sha256
            or result_set.source_revision != completion.source_revision
            or attempt_ledger.suite_id != completion.suite_id
            or attempt_ledger.manifest_sha256 != completion.manifest_sha256
            or attempt_ledger.source_revision != completion.source_revision
            or attempt_ledger.execution_basis is not completion.execution_basis
            or attempt_ledger.planner_configuration_sha256
            != completion.planner_configuration_sha256
            or qualification_summary.suite_id != completion.suite_id
            or qualification_summary.manifest_sha256 != completion.manifest_sha256
            or qualification_summary.result_set_sha256 != completion.result_set.sha256
            or qualification_summary.source_revision != completion.source_revision
            or disposition.suite_id != completion.suite_id
            or disposition.manifest_sha256 != completion.manifest_sha256
            or disposition.result_set_sha256 != completion.result_set.sha256
            or disposition.summary_sha256 != completion.qualification_summary.sha256
            or disposition.source_revision != completion.source_revision
            or protocol_summary.suite_id != completion.suite_id
            or protocol_summary.manifest_sha256 != completion.manifest_sha256
            or protocol_summary.result_set_sha256 != completion.result_set.sha256
            or protocol_summary.attempt_ledger_sha256
            != completion.attempt_ledger.sha256
            or protocol_summary.model_binding_sha256 != completion.model_binding.sha256
            or protocol_summary.qualification_summary.sha256
            != completion.qualification_summary.sha256
            or protocol_summary.case_executions != completion.case_executions
            or protocol_summary.prior_stage_completion_sha256
            != completion.prior_stage_completion_sha256
            or protocol_summary.historical_attempt_ledger_sha256
            != completion.historical_attempt_ledger_sha256
            or protocol_summary.consumed_v2_custody_sha256
            != completion.consumed_v2_custody_sha256
            or protocol_summary.execution_basis is not completion.execution_basis
            or protocol_summary.planner_configuration_sha256
            != completion.planner_configuration_sha256
            or protocol_summary.protocol_valid is not completion.protocol_valid
            or protocol_summary.provider_evidence_qualifying
            is not completion.provider_evidence_qualifying
            or protocol_summary.successful is not completion.successful
        ):
            raise QualificationProtocolError(
                "qualification completion graph is inconsistent"
            )
        prior = completion.prior_attempt_ledger
        consumed_v2_identity = completion.consumed_v2_custody
        if protocol_summary.prior_attempt_ledger_sha256 != (
            None if prior is None else prior.sha256
        ):
            raise QualificationProtocolError(
                "qualification prior-attempt graph is inconsistent"
            )
        if prior is not None and consumed_v2_identity is not None:
            prior_ledger = decode_contract(
                self._read_identity(stage, prior),
                QualificationCombinedPriorAttemptLedger,
            )
            retained_consumed_v2 = decode_contract(
                self._read_identity(stage, consumed_v2_identity),
                QualificationConsumedV2Custody,
            )
            if (
                stage is not QualificationProtocolStage.DEVELOPMENT_1
                or retained_consumed_v2 != consumed_v2_custody
                or prior_ledger != canonical_prior_attempt_ledger(consumed_v2_custody)
                or prior_ledger.totals != protocol_summary.prior_attempt_usage
            ):
                raise QualificationProtocolError(
                    "qualification imported attempts are inconsistent"
                )
        elif stage is QualificationProtocolStage.DEVELOPMENT_1:
            raise QualificationProtocolError(
                "development omitted canonical legacy custody"
            )
        elif prior is not None or consumed_v2_identity is not None:
            raise QualificationProtocolError(
                "later qualification stage reimported legacy custody"
            )
        preflight_generations = tuple(
            item
            for item in attempt_ledger.attempts
            if item.execution_id == "provider-model-revision-preflight"
            and item.operation is QualificationProviderOperation.GENERATE
        )
        if (
            len(preflight_generations) != 1
            or preflight_generations[0].attempt_id
            != model_binding.preflight_generation_attempt_id
            or preflight_generations[0].input_sha256
            != model_binding.preflight_input_sha256
            or preflight_generations[0].reported_model
            != model_binding.reported_model_revision
            or preflight_generations[0].reported_model_raw_sha256
            != model_binding.reported_model_raw_sha256
            or not (
                preflight_generations[0].completed_at
                <= model_binding.bound_at
                <= start.started_at
                <= completion.completed_at
            )
            or any(
                item.reported_model != model_binding.reported_model_revision
                for item in attempt_ledger.attempts
                if item.operation is QualificationProviderOperation.GENERATE
                and item.outcome is QualificationAttemptOutcome.MEASURED
            )
        ):
            raise QualificationProtocolError(
                "qualification provider model revision binding is inconsistent"
            )
        attempt_start_times: list[datetime] = []
        attempt_finish_times: list[datetime] = []
        for start_identity, finish_identity, attempt in zip(
            attempt_ledger.attempt_starts,
            attempt_ledger.attempt_finishes,
            attempt_ledger.attempts,
            strict=True,
        ):
            mark(start_identity)
            mark(finish_identity)
            attempt_start = decode_contract(
                self._read_identity(stage, start_identity),
                QualificationProviderAttemptStart,
            )
            attempt_finish = decode_contract(
                self._read_identity(stage, finish_identity),
                QualificationProviderAttempt,
            )
            attempt_start_times.append(attempt_start.started_at)
            attempt_finish_times.append(attempt_finish.completed_at)
            shared_fields = (
                "attempt_id",
                "sequence",
                "dispatch_id",
                "execution_id",
                "case_id",
                "repetition",
                "planner_phase",
                "operation",
                "execution_basis",
                "planner_configuration_sha256",
                "input_sha256",
                "request_byte_count",
                "sealed_generation_request_sha256",
                "provider_request_sha256",
                "paired_count_attempt_id",
                "reserved_provider_request_count",
                "reserved_input_tokens",
                "reserved_output_tokens",
                "reserved_cost_nano_units",
            )
            if (
                attempt_finish != attempt
                or any(
                    getattr(attempt_start, field_name) != getattr(attempt, field_name)
                    for field_name in shared_fields
                )
                or attempt_start.started_at > attempt.completed_at
            ):
                raise QualificationProtocolError(
                    "qualification attempt artifact binding is inconsistent"
                )
        result_records = {
            (item.case_id, item.repetition): item for item in result_set.results
        }
        case_by_id = {item.case_id: item for item in manifest.cases}
        scheduled_keys = tuple(
            (case.case_id, repetition)
            for repetition in range(1, manifest.repetition_count + 1)
            for case in manifest.cases
        )
        decoded_case_results: list[QualificationCaseResult] = []
        decoded_normalized_runs: list[QualificationNormalizedRun] = []
        adaptive_runs_by_execution: dict[str, ComparisonRun] = {}
        adaptive_failed_executions: set[str] = set()
        observed_execution_ids: list[str] = []
        observed_case_keys: list[tuple[str, int]] = []
        observed_failure_times: list[datetime] = []
        for case_identity in completion.case_executions:
            case_record = decode_contract(
                self._read_identity(stage, case_identity),
                QualificationCaseExecutionRecord,
            )
            result = decode_contract(
                self._read_identity(stage, case_record.result),
                QualificationCaseResult,
            )
            decoded_case_results.append(result)
            observed_execution_ids.append(case_record.execution_id)
            observed_case_keys.append((case_record.case_id, case_record.repetition))
            mark(case_record.result)
            mark(case_record.failure_record)
            for receipt_identity in case_record.lane_receipts:
                mark(receipt_identity)
            if (
                result_records.get((case_record.case_id, case_record.repetition))
                != result
                or case_identity.artifact_id
                != f"{case_record.execution_id}-case-execution"
                or case_record.result.artifact_id
                != f"{case_record.execution_id}-result"
                or case_record.execution_id != result.execution_id
                or case_record.execution_id
                != f"execution-{case_record.case_id}-r{case_record.repetition}"
                or case_record.lane_order is not result.lane_order
                or case_record.status is not result.status
                or case_record.case_id not in case_by_id
                or case_record.runtime_identity_sha256
                != completion.planner_configuration_sha256
            ):
                raise QualificationProtocolError(
                    "qualification case execution graph is inconsistent"
                )
            receipts = tuple(
                decode_contract(
                    self._read_identity(stage, receipt), QualificationLaneReceipt
                )
                for receipt in case_record.lane_receipts
            )
            if (
                tuple(identity.artifact_id for identity in case_record.lane_receipts)
                != tuple(
                    f"{case_record.execution_id}-lane-{sequence}-receipt"
                    for sequence in range(1, len(receipts) + 1)
                )
                or tuple(item.execution_sequence for item in receipts)
                != tuple(range(1, len(receipts) + 1))
                or any(
                    item.suite_id != completion.suite_id
                    or item.manifest_sha256 != completion.manifest_sha256
                    or item.execution_id != case_record.execution_id
                    or item.case_id != case_record.case_id
                    or item.repetition != case_record.repetition
                    or item.lane_order is not case_record.lane_order
                    or item.runtime_identity_sha256
                    != completion.planner_configuration_sha256
                    or item.policies_sha256 != _frozen_policies_sha256(manifest)
                    for item in receipts
                )
            ):
                raise QualificationProtocolError(
                    "qualification lane receipt graph is inconsistent"
                )
            complete_order = _ordered_strategies(result.lane_order)
            expected_strategies = (
                (ComparisonStrategyKind.ADAPTIVE,)
                if result.control_outcome is not None
                else complete_order
            )
            observed_strategies = tuple(item.strategy_kind for item in receipts)
            if (
                (
                    result.comparison is not None
                    and observed_strategies != expected_strategies
                )
                or (
                    result.comparison is None
                    and result.control_outcome is None
                    and observed_strategies != complete_order[: len(receipts)]
                )
                or (
                    result.control_outcome is not None
                    and observed_strategies != expected_strategies
                )
            ):
                raise QualificationProtocolError("qualification lane order changed")
            if len(receipts) == 2 and any(
                getattr(receipts[0], field_name) != getattr(receipts[1], field_name)
                for field_name in (
                    "envelope_sha256",
                    "target_sha256",
                    "semantic_state_before_sha256",
                    "semantic_state_after_sha256",
                    "catalog_sha256",
                    "rules_sha256",
                    "policies_sha256",
                )
            ):
                raise QualificationProtocolError(
                    "qualification lane sealed inputs changed"
                )
            artifact_by_strategy = {
                item.strategy_kind: item for item in result.artifacts
            }
            runs_by_strategy: dict[ComparisonStrategyKind, ComparisonRun] = {}
            failures_by_strategy: dict[
                ComparisonStrategyKind, QualificationFailureRecord
            ] = {}
            if len(artifact_by_strategy) != len(receipts):
                raise QualificationProtocolError(
                    "qualification result artifacts do not match lane receipts"
                )
            for receipt in receipts:
                mark(receipt.raw_observations)
                mark(receipt.normalized_run)
                mark(receipt.protocol_run)
                mark(receipt.failure_record)
                lane_artifact = artifact_by_strategy.get(receipt.strategy_kind)
                if (
                    lane_artifact is None
                    or lane_artifact.raw_observations != receipt.raw_observations
                    or lane_artifact.normalized_run != receipt.normalized_run
                    or lane_artifact.failure_record != receipt.failure_record
                ):
                    raise QualificationProtocolError(
                        "qualification lane artifact binding is inconsistent"
                    )
                strategy_name = receipt.strategy_kind.value.lower()
                if (
                    receipt.raw_observations.artifact_id
                    != f"{receipt.execution_id}-{strategy_name}-observations"
                    or (
                        receipt.normalized_run is not None
                        and receipt.normalized_run.artifact_id
                        != f"{receipt.execution_id}-{strategy_name}-run"
                    )
                    or (
                        receipt.protocol_run is not None
                        and receipt.protocol_run.artifact_id
                        != f"{receipt.execution_id}-{strategy_name}-protocol-run"
                    )
                    or (
                        receipt.failure_record is not None
                        and receipt.failure_record.artifact_id
                        != f"{receipt.execution_id}-{strategy_name}-failure"
                    )
                ):
                    raise QualificationProtocolError(
                        "qualification lane artifact identifiers changed"
                    )
                bundle = decode_contract(
                    self._read_identity(stage, receipt.raw_observations),
                    QualificationObservationBundle,
                )
                if (
                    bundle.execution_id != receipt.execution_id
                    or bundle.case_id != receipt.case_id
                    or bundle.repetition != receipt.repetition
                    or bundle.execution_sequence != receipt.execution_sequence
                    or bundle.strategy_kind is not receipt.strategy_kind
                    or bundle.runtime_identity_sha256
                    != completion.planner_configuration_sha256
                    or bundle.envelope_sha256 != receipt.envelope_sha256
                    or bundle.semantic_state_sha256
                    != receipt.semantic_state_before_sha256
                    or bundle.catalog_sha256 != receipt.catalog_sha256
                    or bundle.rules_sha256 != receipt.rules_sha256
                ):
                    raise QualificationProtocolError(
                        "qualification observation binding is inconsistent"
                    )
                if receipt.normalized_run is not None:
                    run = ComparisonRun.model_validate_json(
                        self._read_identity(stage, receipt.normalized_run)
                    )
                    runs_by_strategy[receipt.strategy_kind] = run
                    wrapper = decode_contract(
                        self._read_identity(stage, receipt.protocol_run),
                        QualificationNormalizedRun,
                    )
                    decoded_normalized_runs.append(wrapper)
                    if receipt.strategy_kind is ComparisonStrategyKind.ADAPTIVE:
                        if receipt.execution_id in adaptive_runs_by_execution:
                            raise QualificationProtocolError(
                                "qualification execution has duplicate adaptive runs"
                            )
                        adaptive_runs_by_execution[receipt.execution_id] = run
                    if wrapper.run != run:
                        raise QualificationProtocolError(
                            "qualification protocol run binding is inconsistent"
                        )
                    if (
                        wrapper.runtime_identity_sha256
                        != completion.planner_configuration_sha256
                        or run.strategy_kind is not receipt.strategy_kind
                        or run.envelope_sha256 != receipt.envelope_sha256
                        or run.scenario != case_by_id[receipt.case_id].scenario
                    ):
                        raise QualificationProtocolError(
                            "qualification runtime run binding is inconsistent"
                        )
                    comparison = result.comparison
                    expected_run = (
                        None
                        if comparison is None
                        else (
                            comparison.baseline
                            if receipt.strategy_kind is ComparisonStrategyKind.FIXED
                            else comparison.adaptive
                        )
                    )
                    if (
                        run.report_sha256 != receipt.report_sha256
                        or (expected_run is not None and run != expected_run)
                        or (
                            expected_run is None
                            and result.status is QualificationCaseResultStatus.COMPLETED
                        )
                    ):
                        raise QualificationProtocolError(
                            "qualification comparison run binding is inconsistent"
                        )
                else:
                    failure = decode_contract(
                        self._read_identity(stage, receipt.failure_record),
                        QualificationFailureRecord,
                    )
                    observed_failure_times.append(failure.occurred_at)
                    failures_by_strategy[receipt.strategy_kind] = failure
                    if receipt.strategy_kind is ComparisonStrategyKind.ADAPTIVE:
                        adaptive_failed_executions.add(receipt.execution_id)
                    if (
                        failure.execution_id != receipt.execution_id
                        or failure.strategy_kind is not receipt.strategy_kind
                        or failure.runtime_identity_sha256
                        != completion.planner_configuration_sha256
                        or failure.partial_publication is not None
                    ):
                        raise QualificationProtocolError(
                            "qualification lane failure binding is inconsistent"
                        )
            case_definition = case_by_id[case_record.case_id]
            receipts_by_strategy = {item.strategy_kind: item for item in receipts}
            if case_definition.role is QualificationCaseRole.MEASUREMENT:
                if result.status is QualificationCaseResultStatus.COMPLETED:
                    if (
                        tuple(item.strategy_kind for item in result.artifacts)
                        != (
                            ComparisonStrategyKind.FIXED,
                            ComparisonStrategyKind.ADAPTIVE,
                        )
                        or set(runs_by_strategy) != set(ComparisonStrategyKind)
                        or set(receipts_by_strategy) != set(ComparisonStrategyKind)
                    ):
                        raise QualificationProtocolError(
                            "qualification measurement lanes are incomplete"
                        )
                    fixed_receipt = receipts_by_strategy[ComparisonStrategyKind.FIXED]
                    adaptive_receipt = receipts_by_strategy[
                        ComparisonStrategyKind.ADAPTIVE
                    ]
                    if (
                        fixed_receipt.action_gates_sha256 is None
                        or adaptive_receipt.action_gates_sha256 is None
                    ):
                        raise QualificationProtocolError(
                            "qualification measurement action gates are missing"
                        )
                    expected_comparison = InvestigationComparisonRecord(
                        schema_version=INVESTIGATION_COMPARISON_RECORD_VERSION,
                        comparison_id=(
                            f"comparison-{case_record.case_id}-"
                            f"r{case_record.repetition}"
                        ),
                        case_id=case_record.case_id,
                        scenario=case_definition.scenario,
                        envelope_sha256=fixed_receipt.envelope_sha256,
                        preregistered_expectation=case_definition.expectation,
                        baseline=runs_by_strategy[ComparisonStrategyKind.FIXED],
                        adaptive=runs_by_strategy[ComparisonStrategyKind.ADAPTIVE],
                    )
                    expected_result = build_measurement_result(
                        manifest,
                        execution_id=case_record.execution_id,
                        case_id=case_record.case_id,
                        repetition=case_record.repetition,
                        lane_order=case_record.lane_order,
                        comparison=expected_comparison,
                        artifacts=result.artifacts,
                        bindings=MeasurementBindings(
                            source_revision=manifest.source_revision,
                            provider_settings_sha256=canonical_sha256(
                                manifest.provider
                            ),
                            fixture_id=case_definition.fixture_id,
                            authority_policy_version=(
                                manifest.authority_policy_version
                            ),
                            classification_policy_version=(
                                manifest.classification_policy_version
                            ),
                            action_policy_version=manifest.action_policy_version,
                            action_gates_match=(
                                fixed_receipt.action_gates_sha256
                                == adaptive_receipt.action_gates_sha256
                            ),
                            model_has_no_classification_or_action_authority=(
                                _model_has_no_authority()
                            ),
                            probes_allowlisted_and_read_only=True,
                        ),
                    )
                    if result != expected_result:
                        raise QualificationProtocolError(
                            "qualification measurement validity was not recomputed"
                        )
                elif result.comparison is not None or result.validity is not None:
                    raise QualificationProtocolError(
                        "failed qualification measurement was relabeled"
                    )
            elif result.status in {
                QualificationCaseResultStatus.CONTROL_PASSED,
                QualificationCaseResultStatus.CONTROL_FAILED,
            }:
                control_failure = failures_by_strategy.get(
                    ComparisonStrategyKind.ADAPTIVE
                )
                control_receipt = receipts_by_strategy.get(
                    ComparisonStrategyKind.ADAPTIVE
                )
                if (
                    len(receipts) != 1
                    or control_failure is None
                    or control_receipt is None
                    or control_failure.control_action_gates is None
                    or control_failure.retained_report_sha256
                    != control_receipt.report_sha256
                    or hashlib.sha256(
                        canonical_json_value_bytes(
                            [
                                item.model_dump(mode="json")
                                for item in control_failure.control_action_gates
                            ]
                        )
                    ).hexdigest()
                    != control_receipt.action_gates_sha256
                ):
                    raise QualificationProtocolError(
                        "qualification fail-closed control evidence changed"
                    )
                expected_control_result = build_control_result(
                    manifest,
                    execution_id=case_record.execution_id,
                    case_id=case_record.case_id,
                    repetition=case_record.repetition,
                    lane_order=case_record.lane_order,
                    artifact=result.artifacts[0],
                    provider_failure_observed=(
                        control_failure.retained_stop_reason
                        == AdaptiveStopReason.PLANNER_UNAVAILABLE.value
                    ),
                    classification_emitted=False,
                    consequential_action_allowed=any(
                        item.requested_action.value in _CONSEQUENTIAL_ACTIONS
                        and item.allowed
                        for item in control_failure.control_action_gates
                    ),
                    model_mutation_attempted=not _model_has_no_authority(),
                )
                if result != expected_control_result:
                    raise QualificationProtocolError(
                        "qualification control outcome was not recomputed"
                    )
            elif (
                result.control_outcome is not None
                or result.comparison is not None
                or result.validity is not None
            ):
                raise QualificationProtocolError(
                    "failed qualification control was relabeled"
                )
            if case_record.failure_record is not None:
                case_failure = decode_contract(
                    self._read_identity(stage, case_record.failure_record),
                    QualificationFailureRecord,
                )
                observed_failure_times.append(case_failure.occurred_at)
                if (
                    case_failure.execution_id != case_record.execution_id
                    or case_failure.strategy_kind is not None
                    or case_failure.runtime_identity_sha256
                    != completion.planner_configuration_sha256
                    or case_record.failure_record.artifact_id
                    != f"{case_record.execution_id}-case-failure"
                ):
                    raise QualificationProtocolError(
                        "qualification case failure binding is inconsistent"
                    )
                partial_identity = case_failure.partial_publication
                mark(partial_identity)
                if partial_identity is not None:
                    partial = decode_contract(
                        self._read_identity(stage, partial_identity),
                        QualificationPartialPublication,
                    )
                    mark(partial.raw_observations)
                    mark(partial.normalized_run)
                    mark(partial.protocol_run)
                    mark(partial.failure_record)
                    partial_bundle = decode_contract(
                        self._read_identity(stage, partial.raw_observations),
                        QualificationObservationBundle,
                    )
                    pending_strategies = (
                        (ComparisonStrategyKind.ADAPTIVE,)
                        if case_by_id[case_record.case_id].role
                        is QualificationCaseRole.FAIL_CLOSED_CONTROL
                        else complete_order
                    )
                    if len(receipts) >= len(pending_strategies):
                        raise QualificationProtocolError(
                            "qualification partial publication has no pending lane"
                        )
                    partial_strategy_name = partial.strategy_kind.value.lower()
                    expected_partial_sequence = len(receipts) + 1
                    expected_partial_strategy = pending_strategies[len(receipts)]
                    if expected_partial_strategy is ComparisonStrategyKind.ADAPTIVE:
                        adaptive_failed_executions.add(case_record.execution_id)
                    if (
                        partial_identity.artifact_id
                        != f"{case_record.execution_id}-partial-publication"
                        or partial.execution_id != case_record.execution_id
                        or partial.case_id != case_record.case_id
                        or partial.repetition != case_record.repetition
                        or partial.strategy_kind is not expected_partial_strategy
                        or partial.runtime_identity_sha256
                        != completion.planner_configuration_sha256
                        or partial.raw_observations.artifact_id
                        != (
                            f"{case_record.execution_id}-{partial_strategy_name}"
                            "-observations"
                        )
                        or (
                            partial.normalized_run is not None
                            and partial.normalized_run.artifact_id
                            != (
                                f"{case_record.execution_id}-{partial_strategy_name}"
                                "-run"
                            )
                        )
                        or (
                            partial.protocol_run is not None
                            and partial.protocol_run.artifact_id
                            != (
                                f"{case_record.execution_id}-{partial_strategy_name}"
                                "-protocol-run"
                            )
                        )
                        or (
                            partial.failure_record is not None
                            and partial.failure_record.artifact_id
                            != (
                                f"{case_record.execution_id}-{partial_strategy_name}"
                                "-failure"
                            )
                        )
                        or partial_bundle.execution_id != partial.execution_id
                        or partial_bundle.case_id != partial.case_id
                        or partial_bundle.repetition != partial.repetition
                        or partial_bundle.execution_sequence
                        != expected_partial_sequence
                        or partial_bundle.strategy_kind is not partial.strategy_kind
                        or partial_bundle.runtime_identity_sha256
                        != completion.planner_configuration_sha256
                    ):
                        raise QualificationProtocolError(
                            "qualification partial publication binding is inconsistent"
                        )
                    if partial.normalized_run is not None:
                        partial_run = ComparisonRun.model_validate_json(
                            self._read_identity(stage, partial.normalized_run)
                        )
                        if (
                            partial_run.strategy_kind is not partial.strategy_kind
                            or partial_run.envelope_sha256
                            != partial_bundle.envelope_sha256
                            or partial_run.scenario
                            != case_by_id[partial.case_id].scenario
                        ):
                            raise QualificationProtocolError(
                                "qualification partial normalized run changed"
                            )
                        if partial.strategy_kind is ComparisonStrategyKind.ADAPTIVE:
                            if partial.execution_id in adaptive_runs_by_execution:
                                raise QualificationProtocolError(
                                    "qualification execution has duplicate adaptive runs"
                                )
                            adaptive_runs_by_execution[partial.execution_id] = (
                                partial_run
                            )
                        if partial.protocol_run is not None:
                            partial_wrapper = decode_contract(
                                self._read_identity(stage, partial.protocol_run),
                                QualificationNormalizedRun,
                            )
                            if (
                                partial_wrapper.run != partial_run
                                or partial_wrapper.runtime_identity_sha256
                                != completion.planner_configuration_sha256
                            ):
                                raise QualificationProtocolError(
                                    "qualification partial run binding is inconsistent"
                                )
                    if partial.failure_record is not None:
                        partial_failure = decode_contract(
                            self._read_identity(stage, partial.failure_record),
                            QualificationFailureRecord,
                        )
                        observed_failure_times.append(partial_failure.occurred_at)
                        if (
                            partial_failure.execution_id != partial.execution_id
                            or partial_failure.strategy_kind
                            is not partial.strategy_kind
                            or partial_failure.runtime_identity_sha256
                            != completion.planner_configuration_sha256
                            or partial_failure.partial_publication is not None
                        ):
                            raise QualificationProtocolError(
                                "qualification partial failure binding is inconsistent"
                            )
                    if receipts and any(
                        getattr(receipts[0], field_name)
                        != getattr(partial_bundle, bundle_field_name)
                        for field_name, bundle_field_name in (
                            ("envelope_sha256", "envelope_sha256"),
                            (
                                "semantic_state_before_sha256",
                                "semantic_state_sha256",
                            ),
                            ("catalog_sha256", "catalog_sha256"),
                            ("rules_sha256", "rules_sha256"),
                        )
                    ):
                        raise QualificationProtocolError(
                            "qualification partial lane sealed inputs changed"
                        )
        if len(result_records) != len(completion.case_executions):
            raise QualificationProtocolError(
                "qualification case execution graph is incomplete"
            )
        if tuple(observed_case_keys) != scheduled_keys[: len(observed_case_keys)]:
            raise QualificationProtocolError(
                "qualification case executions changed preregistered order"
            )

        def stops_stage(result: QualificationCaseResult) -> bool:
            return result.status not in {
                QualificationCaseResultStatus.COMPLETED,
                QualificationCaseResultStatus.CONTROL_PASSED,
            } or (
                result.validity is not None
                and (
                    not result.validity.integrity_valid
                    or not result.validity.safety_valid
                )
            )

        if any(stops_stage(item) for item in decoded_case_results[:-1]) or (
            len(decoded_case_results) < len(scheduled_keys)
            and (not decoded_case_results or not stops_stage(decoded_case_results[-1]))
        ):
            raise QualificationProtocolError(
                "qualification stage termination does not match case outcomes"
            )
        expected_result_set = build_result_set(manifest, tuple(decoded_case_results))
        expected_qualification_summary = summarize_qualification(
            manifest,
            expected_result_set,
            evaluated_at=qualification_summary.evaluated_at,
        )
        expected_disposition = derive_disposition(
            manifest,
            expected_result_set,
            expected_qualification_summary,
            decided_at=disposition.decided_at,
        )
        if (
            expected_result_set != result_set
            or expected_qualification_summary != qualification_summary
            or expected_disposition != disposition
        ):
            raise QualificationProtocolError(
                "qualification derived evidence was not recomputed faithfully"
            )

        predecessor_stage = {
            QualificationProtocolStage.DEVELOPMENT_1: None,
            QualificationProtocolStage.DEVELOPMENT_2: (
                QualificationProtocolStage.DEVELOPMENT_1
            ),
            QualificationProtocolStage.FINAL_HOLDOUT: (
                QualificationProtocolStage.DEVELOPMENT_2
            ),
        }[stage]
        predecessor_identity: QualificationArtifactIdentity | None = None
        if predecessor_stage is None:
            expected_prior_usage = canonical_prior_attempt_ledger(
                consumed_v2_custody
            ).totals
            if (
                prior is None
                or consumed_v2_identity is None
                or completion.prior_stage_completion_sha256 is not None
            ):
                raise QualificationProtocolError(
                    "development one legacy custody is incomplete"
                )
        else:
            if prior is not None or consumed_v2_identity is not None:
                raise QualificationProtocolError(
                    "later qualification stages cannot reimport legacy calls"
                )
            predecessor_completion = self.read_completion(predecessor_stage)
            predecessor_identity = self.completion_identity(predecessor_stage)
            predecessor_protocol_summary = decode_contract(
                self._read_identity(
                    predecessor_stage, predecessor_completion.protocol_summary
                ),
                QualificationProtocolSummary,
            )
            predecessor_binding = decode_contract(
                self._read_identity(
                    predecessor_stage, predecessor_completion.model_binding
                ),
                QualificationModelBinding,
            )
            expected_prior_usage = predecessor_protocol_summary.ceiling_usage
            if (
                completion.prior_stage_completion_sha256 != predecessor_identity.sha256
                or model_binding.reported_model_revision
                != predecessor_binding.reported_model_revision
            ):
                raise QualificationProtocolError(
                    "qualification predecessor custody changed"
                )
        expected_protocol_summary = _build_protocol_summary(
            manifest=manifest,
            result_set=expected_result_set,
            qualification_summary=expected_qualification_summary,
            qualification_summary_identity=completion.qualification_summary,
            ledger=attempt_ledger,
            ledger_identity=completion.attempt_ledger,
            model_binding_identity=completion.model_binding,
            prior_identity=prior,
            historical_attempt_ledger_sha256=(
                completion.historical_attempt_ledger_sha256
            ),
            consumed_v2_custody_sha256=(completion.consumed_v2_custody_sha256),
            prior_stage_identity=predecessor_identity,
            execution_basis=completion.execution_basis,
            planner_configuration_sha256=(completion.planner_configuration_sha256),
            case_execution_identities=completion.case_executions,
            normalized_runs=tuple(decoded_normalized_runs),
            prior_usage=expected_prior_usage,
        )
        if expected_protocol_summary != protocol_summary:
            raise QualificationProtocolError(
                "qualification protocol summary was not recomputed faithfully"
            )

        results_by_execution = {
            item.execution_id: item for item in decoded_case_results
        }
        for attempt in attempt_ledger.attempts:
            if attempt.execution_id == "provider-model-revision-preflight":
                continue
            result = results_by_execution.get(attempt.execution_id)
            if (
                result is None
                or attempt.case_id != result.case_id
                or attempt.repetition != result.repetition
            ):
                raise QualificationProtocolError(
                    "qualification provider attempt has no case outcome"
                )
            if attempt.outcome is QualificationAttemptOutcome.CONTROL_FAILURE:
                if result.status not in {
                    QualificationCaseResultStatus.CONTROL_PASSED,
                    QualificationCaseResultStatus.CONTROL_FAILED,
                    QualificationCaseResultStatus.FAILED,
                    QualificationCaseResultStatus.INVALID,
                }:
                    raise QualificationProtocolError(
                        "qualification control attempt was relabeled"
                    )
            elif attempt.outcome not in {
                QualificationAttemptOutcome.TOKEN_COUNTED,
                QualificationAttemptOutcome.MEASURED,
            } and result.status not in {
                QualificationCaseResultStatus.FAILED,
                QualificationCaseResultStatus.INVALID,
            }:
                raise QualificationProtocolError(
                    "qualification failed provider attempt was relabeled"
                )

        attempts_by_execution: dict[str, list[QualificationProviderAttempt]] = {}
        for attempt in attempt_ledger.attempts[2:]:
            attempts_by_execution.setdefault(attempt.execution_id, []).append(attempt)
        for result in decoded_case_results:
            execution_attempts = attempts_by_execution.get(result.execution_id, [])
            generations = tuple(
                item
                for item in execution_attempts
                if item.operation is QualificationProviderOperation.GENERATE
            )
            token_counts = tuple(
                item
                for item in execution_attempts
                if item.operation is QualificationProviderOperation.COUNT_TOKENS
            )
            case_definition = case_by_id[result.case_id]
            if case_definition.role is QualificationCaseRole.FAIL_CLOSED_CONTROL:
                if (
                    token_counts
                    or len(generations) > 1
                    or any(
                        item.outcome is not QualificationAttemptOutcome.CONTROL_FAILURE
                        for item in generations
                    )
                    or (
                        result.status
                        in {
                            QualificationCaseResultStatus.CONTROL_PASSED,
                            QualificationCaseResultStatus.CONTROL_FAILED,
                        }
                        and len(generations) != 1
                    )
                ):
                    raise QualificationProtocolError(
                        "qualification control provider accounting changed"
                    )
                continue
            adaptive_run = adaptive_runs_by_execution.get(result.execution_id)
            if adaptive_run is None:
                if (
                    any(
                        item.outcome is QualificationAttemptOutcome.MEASURED
                        for item in generations
                    )
                    and result.execution_id not in adaptive_failed_executions
                ):
                    raise QualificationProtocolError(
                        "qualification measured generation has no adaptive lane"
                    )
                continue
            _validate_retained_adaptive_usage(
                adaptive_run.model_usage,
                generations,
                token_counts,
                runtime_identity,
                model_binding,
            )

        if (
            not (
                model_binding.bound_at
                <= start.started_at
                <= qualification_summary.evaluated_at
                <= disposition.decided_at
                <= completion.completed_at
            )
            or any(
                started_at > completed_at
                for started_at, completed_at in zip(
                    attempt_start_times, attempt_finish_times, strict=True
                )
            )
            or any(
                completed_at > next_started_at
                for completed_at, next_started_at in zip(
                    attempt_finish_times,
                    attempt_start_times[1:],
                    strict=False,
                )
            )
            or any(
                not start.started_at <= item <= qualification_summary.evaluated_at
                for item in observed_failure_times
            )
            or any(
                (
                    completed_at > model_binding.bound_at
                    if attempt.execution_id == "provider-model-revision-preflight"
                    else started_at < start.started_at
                    or completed_at > qualification_summary.evaluated_at
                )
                for attempt, started_at, completed_at in zip(
                    attempt_ledger.attempts,
                    attempt_start_times,
                    attempt_finish_times,
                    strict=True,
                )
            )
        ):
            raise QualificationProtocolError(
                "qualification artifact chronology is inconsistent"
            )
        retained = {
            (identity.artifact_id, identity.sha256)
            for identity in completion.retained_artifacts
        }
        if retained != reachable:
            raise QualificationProtocolError(
                "qualification retained artifacts are not exactly reachable"
            )
        stage_path = self.root / stage.value
        expected_names = {
            *(f"{item.artifact_id}.json" for item in completion.retained_artifacts),
            "execution-completion.json",
        }
        try:
            stage_stat = stage_path.stat(follow_symlinks=False)
            entries = tuple(os.scandir(stage_path))
            observed_names = {item.name for item in entries}
            invalid_entry = any(
                not item.is_file(follow_symlinks=False)
                or stat.S_IMODE(item.stat(follow_symlinks=False).st_mode) != 0o400
                for item in entries
            )
        except OSError as error:
            raise QualificationProtocolError(
                "qualification stage custody cannot be enumerated"
            ) from error
        if (
            not stat.S_ISDIR(stage_stat.st_mode)
            or stat.S_IMODE(stage_stat.st_mode) != 0o700
            or observed_names != expected_names
            or invalid_entry
        ):
            raise QualificationProtocolError(
                "qualification stage contains missing, extra, or mutable artifacts"
            )
        return completion

    def completion_identity(
        self, stage: QualificationProtocolStage
    ) -> QualificationArtifactIdentity:
        self.read_completion(stage)
        payload, _ = self._read_stage_file(stage, "execution-completion.json")
        return artifact_identity("execution-completion", payload)

    def read_protocol_summary(
        self, stage: QualificationProtocolStage
    ) -> QualificationProtocolSummary:
        completion = self.read_completion(stage)
        return decode_contract(
            self._read_identity(stage, completion.protocol_summary),
            QualificationProtocolSummary,
        )

    def create_fixture_registry(
        self,
        stage: QualificationProtocolStage,
        manifest: QualificationSuiteManifest,
        start_identity: QualificationArtifactIdentity,
        *,
        workspace: Path,
        real_monotonic: bool,
    ) -> QualificationFixtureRegistry:
        if stage is not QualificationProtocolStage.FINAL_HOLDOUT:
            return QualificationFixtureRegistry(
                stage,
                manifest.cases,
                workspace=workspace,
                real_monotonic=real_monotonic,
            )
        if self._final_registry_created:
            raise QualificationExecutionConsumed(
                "final fixture registry authorization is single-use"
            )
        if (
            self.stage_path
            != self.root / QualificationProtocolStage.FINAL_HOLDOUT.value
        ):
            raise QualificationProtocolError(
                "final fixture access requires this store's consumed final stage"
            )
        start = decode_contract(
            self._read_identity(
                QualificationProtocolStage.FINAL_HOLDOUT, start_identity
            ),
            QualificationExecutionStart,
        )
        manifest_identity = artifact_identity(
            "manifest", canonical_json_bytes(manifest)
        )
        self._read_identity(QualificationProtocolStage.FINAL_HOLDOUT, manifest_identity)
        first = self.read_completion(QualificationProtocolStage.DEVELOPMENT_1)
        second = self.read_completion(QualificationProtocolStage.DEVELOPMENT_2)
        first_identity = self.completion_identity(
            QualificationProtocolStage.DEVELOPMENT_1
        )
        second_identity = self.completion_identity(
            QualificationProtocolStage.DEVELOPMENT_2
        )
        first_binding = decode_contract(
            self._read_identity(
                QualificationProtocolStage.DEVELOPMENT_1, first.model_binding
            ),
            QualificationModelBinding,
        )
        second_binding = decode_contract(
            self._read_identity(
                QualificationProtocolStage.DEVELOPMENT_2, second.model_binding
            ),
            QualificationModelBinding,
        )
        start_binding = decode_contract(
            self._read_identity(
                QualificationProtocolStage.FINAL_HOLDOUT, start.model_binding
            ),
            QualificationModelBinding,
        )
        if (
            start.stage is not QualificationProtocolStage.FINAL_HOLDOUT
            or start.execution_basis is not QualificationExecutionBasis.LIVE_PROVIDER
            or start.manifest_sha256 != manifest_identity.sha256
            or start.suite_id != manifest.suite_id
            or start.source_revision != manifest.source_revision
            or start.provider_settings_sha256 != canonical_sha256(manifest.provider)
            or not first.successful
            or not second.successful
            or second.prior_stage_completion_sha256 != first_identity.sha256
            or start.prior_stage_completion_sha256 != second_identity.sha256
            or first.planner_configuration_sha256 != start.planner_configuration_sha256
            or second.planner_configuration_sha256 != start.planner_configuration_sha256
            or first.source_revision != start.source_revision
            or second.source_revision != start.source_revision
            or first.historical_attempt_ledger_sha256
            != start.historical_attempt_ledger_sha256
            or second.historical_attempt_ledger_sha256
            != start.historical_attempt_ledger_sha256
            or first.consumed_v2_custody_sha256 != start.consumed_v2_custody_sha256
            or second.consumed_v2_custody_sha256 != start.consumed_v2_custody_sha256
            or first_binding.reported_model_revision
            != start_binding.reported_model_revision
            or second_binding.reported_model_revision
            != start_binding.reported_model_revision
        ):
            raise QualificationProtocolError(
                "final fixture prerequisites are not bound to the validated start"
            )
        schedule = tuple(
            (case.case_id, repetition)
            for repetition in range(1, manifest.repetition_count + 1)
            for case in manifest.cases
        )
        access = _issue_final_fixture_access(
            self.stage_path,
            start_identity,
            self.root,
            manifest_identity=manifest_identity,
            final_runtime_identity=start.runtime_identity,
            final_model_binding_identity=start.model_binding,
            prerequisite_completion_identities=(
                first_identity,
                second_identity,
            ),
            prerequisite_model_binding_identities=(
                first.model_binding,
                second.model_binding,
            ),
            prerequisite_retained_artifacts=(
                first.retained_artifacts,
                second.retained_artifacts,
            ),
            source_revision=start.source_revision,
            runtime_identity_sha256=start.planner_configuration_sha256,
            concrete_model_revision=start_binding.reported_model_revision,
            historical_attempt_ledger_sha256=(start.historical_attempt_ledger_sha256),
            consumed_v2_custody_sha256=start.consumed_v2_custody_sha256,
            schedule=schedule,
        )
        self._final_registry_created = True
        return QualificationFixtureRegistry._from_store(
            manifest.cases,
            workspace=workspace,
            session=_FinalFixtureSession(access),
            real_monotonic=real_monotonic,
        )


def build_protocol_manifest(
    stage: QualificationProtocolStage,
    *,
    source_revision: str,
    registered_at: datetime,
    provider: QualificationProviderSettings,
) -> QualificationSuiteManifest:
    if provider != frozen_qualification_provider_settings():
        raise QualificationProviderDrift(
            "qualification manifest provider settings are not frozen"
        )
    cases = qualification_cases_for_stage(stage, PREREGISTERED_QUALIFICATION_CASES)
    suite_id = {
        QualificationProtocolStage.DEVELOPMENT_1: "adaptive-development-one-v3",
        QualificationProtocolStage.DEVELOPMENT_2: "adaptive-development-two-v3",
        QualificationProtocolStage.FINAL_HOLDOUT: "adaptive-fixed-qualification-v3",
    }[stage]
    repetition_count = 5 if stage is QualificationProtocolStage.FINAL_HOLDOUT else 1
    lane_orders = {
        QualificationProtocolStage.DEVELOPMENT_1: (QualificationLaneOrder.FIXED_FIRST,),
        QualificationProtocolStage.DEVELOPMENT_2: (
            QualificationLaneOrder.ADAPTIVE_FIRST,
        ),
        QualificationProtocolStage.FINAL_HOLDOUT: _FROZEN_LANE_ORDERS,
    }[stage]
    return build_qualification_manifest(
        source_revision=source_revision,
        registered_at=registered_at,
        provider=provider,
        repetition_count=repetition_count,
        lane_orders=lane_orders,
        suite_id=suite_id,
        controller_version="qualification-controller-v3",
        fixed_strategy_version="qualification-fixed-plan:1.0.0",
        adaptive_strategy_version="qualification-adaptive-policy:1.0.0",
        stop_conditions=QualificationStopConditions(
            stop_on_safety_failure=True,
            stop_on_source_mismatch=True,
            stop_on_manifest_mismatch=True,
            maximum_failed_results=0,
            maximum_total_model_calls=180,
            maximum_total_input_tokens=_FROZEN_MAX_TOTAL_INPUT_TOKENS,
            maximum_total_output_tokens=_FROZEN_MAX_TOTAL_OUTPUT_TOKENS,
            maximum_total_model_cost_nano_units=5_000_000_000,
        ),
        cases=cases,
    )


def validate_protocol_manifest(
    stage: QualificationProtocolStage,
    manifest: QualificationSuiteManifest,
) -> None:
    expected = build_protocol_manifest(
        stage,
        source_revision=manifest.source_revision,
        registered_at=manifest.registered_at,
        provider=manifest.provider,
    )
    if manifest != expected:
        raise QualificationProtocolError("qualification protocol is not frozen")


def build_vertex_qualification_planner(
    provider: QualificationProviderSettings,
    config: VertexAdcPlannerConfig,
) -> AdkGeminiPlanner:
    """Build the no-retry Vertex planner only when runtime settings match manifest."""

    if type(config) is not VertexAdcPlannerConfig:
        raise TypeError("qualification Vertex configuration must be exact")
    if provider != frozen_qualification_provider_settings() or (
        config.project != _FROZEN_PROVIDER_PROJECT
        or config.location != provider.location
        or config.model != provider.model_name
        or int(config.timeout_seconds * 1_000) != provider.timeout_ms
        or config.max_output_tokens != provider.max_output_tokens
        or config.prompt_version != provider.prompt_version
        or provider.timeout_ms != 30_000
        or provider.temperature_milli != 0
    ):
        raise QualificationProviderDrift(
            "Vertex runtime settings do not match the qualification manifest"
        )
    planner = AdkGeminiPlanner.from_vertex_adc_qualification(config)
    metadata = planner.metadata
    if (
        metadata.provider_name != provider.provider_name
        or metadata.configured_model != provider.model_name
        or metadata.adk_version != provider.adk_version
        or metadata.genai_version != provider.genai_version
        or metadata.prompt_version != provider.prompt_version
        or metadata.prompt_sha256 != _FROZEN_PROMPT_SHA256
        or metadata.input_schema_version != ADAPTIVE_PLANNER_INPUT_VERSION
        or metadata.output_schema_version != ADAPTIVE_PLANNER_OUTPUT_VERSION
    ):
        raise QualificationProviderDrift(
            "Vertex adapter identity does not match the qualification manifest"
        )
    _AUTHORIZED_LIVE_PLANNERS[planner] = frozen_qualification_runtime_identity()
    return planner


def qualification_runtime_identity(
    planner: AdkGeminiPlanner,
) -> QualificationRuntimeIdentity:
    if type(planner) is not AdkGeminiPlanner:
        raise TypeError("qualification runtime identity requires the exact planner")
    identity = _AUTHORIZED_LIVE_PLANNERS.get(planner)
    if identity is None:
        raise QualificationProviderDrift(
            "planner was not created by the sealed qualification factory"
        )
    try:
        planner.validate_qualification_runtime_configuration()
    except RuntimeError as error:
        raise QualificationProviderDrift(
            "sealed qualification planner configuration drifted"
        ) from error
    return identity


def _planner_metadata_sha256(metadata: AdvisoryPlannerMetadata) -> str:
    return hashlib.sha256(
        canonical_json_value_bytes(
            {
                "adk_version": metadata.adk_version,
                "configured_model": metadata.configured_model,
                "genai_version": metadata.genai_version,
                "input_schema_version": metadata.input_schema_version,
                "output_schema_version": metadata.output_schema_version,
                "prompt_sha256": metadata.prompt_sha256,
                "prompt_version": metadata.prompt_version,
                "provider_name": metadata.provider_name,
            }
        )
    ).hexdigest()


def _model_revision_preflight_input(
    metadata: AdvisoryPlannerMetadata,
    invoked_at: datetime,
) -> AdaptivePlannerInput:
    return AdaptivePlannerInput.model_validate(
        {
            "schema_version": ADAPTIVE_PLANNER_INPUT_VERSION,
            "phase": AdaptivePlannerPhase.ACQUIRE_EVIDENCE,
            "envelope": {
                "schema_version": "reconcile/execution-envelope/v1",
                "investigation_id": "qualification-model-revision-preflight",
                "operation_id": "qualification-model-revision-preflight",
                "target": {
                    "target_kind": "qualification.model",
                    "scope": {"provider": _FROZEN_PROVIDER_NAME},
                    "resource": {"model": _FROZEN_MODEL_NAME},
                },
                "invoked_at": invoked_at,
                "ambiguity": {
                    "kind": AmbiguityKind.MISSING_TOOL_RESULT,
                    "observed_at": invoked_at,
                    "detail": "Provider revision identity is not yet bound.",
                },
                "expected_effects": (
                    {
                        "schema_version": "reconcile/expected-effect/v1",
                        "effect_id": "provider-revision-bound",
                        "commit_scope": "qualification",
                        "predicate": {"equals": True, "field": "reported"},
                        "description": "The provider reports one concrete model revision.",
                    },
                ),
                "context": {
                    "invocation": {
                        "invocation_id": "qualification-model-preflight",
                        "function_call_id": "qualification-model-preflight",
                        "tool_name": "qualification-model-preflight",
                        "tool_version": "1.0.0",
                        "arguments": {},
                        "arguments_sha256": hashlib.sha256(b"{}").hexdigest(),
                    },
                    "enabled_capabilities": (
                        {"name": "qualification-readback", "version": "1.0.0"},
                    ),
                    "correlation_fields": {"model": _FROZEN_MODEL_NAME},
                    "evidence_budget": {
                        "max_probes": 1,
                        "max_elapsed_ms": 1_000,
                        "max_total_result_bytes": 1_024,
                        "max_cost_units": 1,
                    },
                    "freshness": {"max_age_seconds": 60, "clock_skew_seconds": 5},
                    "policies": {
                        "authority": "qualification-authority-v1",
                        "classification": "qualification-classification-v1",
                        "action": "qualification-action-v1",
                    },
                },
            },
            "capabilities": (
                {
                    "name": "qualification-readback",
                    "version": "1.0.0",
                    "description": "Read only preflight capability descriptor.",
                    "read_only": True,
                    "argument_schema": {
                        "$schema": "https://json-schema.org/draft/2020-12/schema",
                        "type": "object",
                        "properties": {},
                        "additionalProperties": False,
                    },
                    "cost_units": 1,
                    "remaining_invocations": 1,
                },
            ),
            "admitted_evidence": (),
            "weak_evidence": (),
            "rejected_evidence": (),
            "missing_evidence": (
                {
                    "effect_id": "provider-revision-bound",
                    "reason": "provider_revision_not_reported",
                },
            ),
            "prior_executable_request_hashes": (),
            "remaining_budget": {
                "probes": 1,
                "elapsed_ms": 0,
                "result_bytes": 1_024,
                "cost_units": 1,
                "deadline_at": invoked_at + timedelta(seconds=1),
            },
            "versions": {
                "provider_name": metadata.provider_name,
                "model_name": metadata.configured_model,
                "adk_version": metadata.adk_version,
                "genai_version": metadata.genai_version,
                "prompt_version": metadata.prompt_version,
                "capability_catalog_version": "capability-catalog-v1",
                "authority_policy_version": "qualification-authority-v1",
                "classification_policy_version": "qualification-classification-v1",
                "action_policy_version": "qualification-action-v1",
                "input_schema_version": ADAPTIVE_PLANNER_INPUT_VERSION,
                "output_schema_version": ADAPTIVE_PLANNER_OUTPUT_VERSION,
            },
        }
    )


def _metadata_matches_runtime(
    metadata: AdvisoryPlannerMetadata,
    runtime: QualificationRuntimeIdentity,
) -> bool:
    return all(
        (
            metadata.provider_name == runtime.provider_name,
            metadata.configured_model == runtime.configured_model,
            metadata.adk_version == runtime.adk_version,
            metadata.genai_version == runtime.genai_version,
            metadata.prompt_version == runtime.prompt_version,
            metadata.prompt_sha256 == runtime.prompt_sha256,
            metadata.input_schema_version == runtime.input_schema_version,
            metadata.output_schema_version == runtime.output_schema_version,
        )
    )


def _attempt_cost(
    provider: QualificationProviderSettings,
    input_tokens: int,
    output_tokens: int,
) -> int:
    return (
        input_tokens * provider.input_cost_nano_units_per_token
        + output_tokens * provider.output_cost_nano_units_per_token
    )


@dataclass(frozen=True, slots=True)
class _ProviderReservation:
    model_calls: int
    count_tokens_calls: int
    provider_requests: int
    input_tokens: int
    output_tokens: int
    cost_nano_units: int


def _provider_reservation(
    runtime: QualificationRuntimeIdentity,
    complete_input_token_bound: int,
    *,
    output_tokens: int | None = None,
    model_calls: Literal[0, 1] = 1,
    count_tokens_calls: Literal[0, 1] = 0,
    provider_requests: Literal[0, 1, 2] = 1,
) -> _ProviderReservation:
    if type(complete_input_token_bound) is not int or complete_input_token_bound < 0:
        raise TypeError("qualification input token bound must be nonnegative")
    if complete_input_token_bound > runtime.maximum_input_tokens_per_call:
        raise QualificationBudgetExceeded(
            "qualification input exceeds the sealed provider request bound"
        )
    reserved_output = (
        runtime.max_output_tokens if output_tokens is None else output_tokens
    )
    if type(reserved_output) is not int or not 0 <= reserved_output <= (
        runtime.max_output_tokens
    ):
        raise TypeError("qualification output reservation must be bounded")
    return _ProviderReservation(
        model_calls=model_calls,
        count_tokens_calls=count_tokens_calls,
        provider_requests=provider_requests,
        input_tokens=complete_input_token_bound,
        output_tokens=reserved_output,
        cost_nano_units=(
            complete_input_token_bound * runtime.input_cost_nano_units_per_token
            + reserved_output * runtime.output_cost_nano_units_per_token
        ),
    )


def _reservation_exceeds_ceiling(
    manifest: QualificationSuiteManifest,
    current: QualificationModelUsageTotals,
    reservation: _ProviderReservation,
) -> bool:
    stop = manifest.stop_conditions
    return any(
        (
            current.model_call_count + reservation.model_calls
            > stop.maximum_total_model_calls,
            current.count_tokens_call_count + reservation.count_tokens_calls
            > _FROZEN_MAX_COUNT_TOKEN_CALLS,
            current.provider_request_count + reservation.provider_requests
            > _FROZEN_MAX_TOTAL_PROVIDER_REQUESTS,
            current.input_token_count + reservation.input_tokens
            > stop.maximum_total_input_tokens,
            current.output_token_count + reservation.output_tokens
            > stop.maximum_total_output_tokens,
            current.model_cost_nano_units + reservation.cost_nano_units
            > stop.maximum_total_model_cost_nano_units,
        )
    )


class _AttemptMeter:
    def __init__(
        self,
        manifest: QualificationSuiteManifest,
        store: QualificationArtifactStore,
        retained: list[QualificationArtifactIdentity],
        *,
        prior_usage: QualificationModelUsageTotals,
        execution_basis: QualificationExecutionBasis,
        runtime_identity: QualificationRuntimeIdentity,
        source_guard: Callable[[], None],
    ) -> None:
        self.manifest = manifest
        self.store = store
        self.retained = retained
        self.prior_usage = prior_usage
        self.execution_basis = execution_basis
        self.runtime_identity = runtime_identity
        self.planner_configuration_sha256 = canonical_sha256(runtime_identity)
        self.source_guard = source_guard
        self.attempts: list[QualificationProviderAttempt] = []
        self.attempt_starts: list[QualificationArtifactIdentity] = []
        self.attempt_finishes: list[QualificationArtifactIdentity] = []
        self.invalid_executions: dict[str, str] = {}
        self.model_binding: QualificationModelBinding | None = None

    def _totals(self) -> QualificationModelUsageTotals:
        return _attempt_totals(tuple(self.attempts))

    def bind_model_revision(self, binding: QualificationModelBinding) -> None:
        if self.model_binding is not None:
            raise QualificationProviderDrift("provider model revision is write-once")
        if (
            binding.runtime_identity_sha256 != self.planner_configuration_sha256
            or binding.configured_model != self.runtime_identity.configured_model
        ):
            raise QualificationProviderDrift("provider model revision binding drifted")
        self.model_binding = binding

    def _reserve(
        self,
        *,
        operation: QualificationProviderOperation,
        execution_id: str,
        case_id: str,
        repetition: int,
        planner_phase: AdaptivePlannerPhase,
        input_sha256: str,
        request_byte_count: int,
        dispatch_id: str,
        sealed_generation_request_sha256: str | None,
        provider_request_sha256: str | None,
        paired_count_attempt_id: str | None,
        reserved_provider_request_count: Literal[0, 1],
        input_tokens: int,
        output_tokens: int,
        model_calls: Literal[0, 1],
        count_tokens_calls: Literal[0, 1],
    ) -> QualificationProviderAttemptStart:
        self.source_guard()
        current = _add_usage(self.prior_usage, self._totals())
        sequence = len(self.attempts) + 1
        try:
            reservation = _provider_reservation(
                self.runtime_identity,
                input_tokens,
                output_tokens=output_tokens,
                model_calls=model_calls,
                count_tokens_calls=count_tokens_calls,
                provider_requests=reserved_provider_request_count,
            )
        except (QualificationBudgetExceeded, TypeError, ValueError) as error:
            self.invalid_executions[execution_id] = "provider-input-bound-exceeded"
            raise QualificationBudgetExceeded(
                "qualification input exceeds the sealed provider request bound"
            ) from error
        if _reservation_exceeds_ceiling(self.manifest, current, reservation):
            self.invalid_executions[execution_id] = "provider-ceiling-reached"
            raise QualificationBudgetExceeded(
                "qualification provider ceiling would be exceeded"
            )
        attempt = QualificationProviderAttemptStart(
            schema_version=QUALIFICATION_ATTEMPT_START_VERSION,
            attempt_id=(
                f"attempt-{sequence:03d}-{operation.value.lower().replace('_', '-')}"
            ),
            sequence=sequence,
            dispatch_id=dispatch_id,
            execution_id=execution_id,
            case_id=case_id,
            repetition=repetition,
            planner_phase=planner_phase,
            operation=operation,
            execution_basis=self.execution_basis,
            planner_configuration_sha256=self.planner_configuration_sha256,
            input_sha256=input_sha256,
            request_byte_count=request_byte_count,
            sealed_generation_request_sha256=sealed_generation_request_sha256,
            provider_request_sha256=provider_request_sha256,
            paired_count_attempt_id=paired_count_attempt_id,
            reserved_provider_request_count=reserved_provider_request_count,
            reserved_input_tokens=reservation.input_tokens,
            reserved_output_tokens=reservation.output_tokens,
            reserved_cost_nano_units=reservation.cost_nano_units,
            started_at=datetime.now(UTC),
        )
        identity = self.store.publish(f"{attempt.attempt_id}-start", attempt)
        self.retained.append(identity)
        self.attempt_starts.append(identity)
        return attempt

    def reserve_count_tokens(
        self,
        *,
        execution_id: str,
        case_id: str,
        repetition: int,
        planner_phase: AdaptivePlannerPhase,
        input_sha256: str,
        request_byte_count: int,
        sealed_generation_request_sha256: str,
        provider_request_sha256: str,
    ) -> QualificationProviderAttemptStart:
        if (
            not 1
            <= request_byte_count
            <= self.runtime_identity.maximum_input_tokens_per_call
        ):
            raise QualificationBudgetExceeded(
                "assembled qualification request exceeds its local size guard"
            )
        current = _add_usage(self.prior_usage, self._totals())
        paired_worst_case = _provider_reservation(
            self.runtime_identity,
            self.runtime_identity.maximum_input_tokens_per_call,
            model_calls=1,
            count_tokens_calls=1,
            provider_requests=2,
        )
        if _reservation_exceeds_ceiling(self.manifest, current, paired_worst_case):
            self.invalid_executions[execution_id] = "provider-ceiling-reached"
            raise QualificationBudgetExceeded(
                "qualification provider ceiling cannot admit a paired dispatch"
            )
        sequence = len(self.attempts) + 1
        return self._reserve(
            operation=QualificationProviderOperation.COUNT_TOKENS,
            execution_id=execution_id,
            case_id=case_id,
            repetition=repetition,
            planner_phase=planner_phase,
            input_sha256=input_sha256,
            request_byte_count=request_byte_count,
            dispatch_id=f"dispatch-{sequence:03d}-{input_sha256[:16]}",
            sealed_generation_request_sha256=(sealed_generation_request_sha256),
            provider_request_sha256=provider_request_sha256,
            paired_count_attempt_id=None,
            reserved_provider_request_count=1,
            input_tokens=0,
            output_tokens=0,
            model_calls=0,
            count_tokens_calls=1,
        )

    def reserve_generation(
        self,
        *,
        count_attempt: QualificationProviderAttempt,
    ) -> QualificationProviderAttemptStart:
        counted_input_tokens = count_attempt.counted_input_tokens
        if type(counted_input_tokens) is not int or counted_input_tokens < 1:
            raise QualificationBudgetExceeded("provider token count is invalid")
        if (
            count_attempt.operation is not QualificationProviderOperation.COUNT_TOKENS
            or count_attempt.outcome is not QualificationAttemptOutcome.TOKEN_COUNTED
            or count_attempt.sealed_generation_request_sha256 is None
        ):
            raise QualificationProtocolError(
                "generation reservation requires one successful token count"
            )
        return self._reserve(
            operation=QualificationProviderOperation.GENERATE,
            execution_id=count_attempt.execution_id,
            case_id=count_attempt.case_id,
            repetition=count_attempt.repetition,
            planner_phase=count_attempt.planner_phase,
            input_sha256=count_attempt.input_sha256,
            request_byte_count=count_attempt.request_byte_count,
            dispatch_id=count_attempt.dispatch_id,
            sealed_generation_request_sha256=(
                count_attempt.sealed_generation_request_sha256
            ),
            provider_request_sha256=None,
            paired_count_attempt_id=count_attempt.attempt_id,
            reserved_provider_request_count=1,
            input_tokens=self.runtime_identity.maximum_input_tokens_per_call,
            output_tokens=self.runtime_identity.max_output_tokens,
            model_calls=1,
            count_tokens_calls=0,
        )

    def reserve_control_generation(
        self,
        *,
        execution_id: str,
        case_id: str,
        repetition: int,
        planner_phase: AdaptivePlannerPhase,
        input_sha256: str,
        request_byte_count: int,
    ) -> QualificationProviderAttemptStart:
        sequence = len(self.attempts) + 1
        return self._reserve(
            operation=QualificationProviderOperation.GENERATE,
            execution_id=execution_id,
            case_id=case_id,
            repetition=repetition,
            planner_phase=planner_phase,
            input_sha256=input_sha256,
            request_byte_count=request_byte_count,
            dispatch_id=f"control-{sequence:03d}-{input_sha256[:16]}",
            sealed_generation_request_sha256=None,
            provider_request_sha256=None,
            paired_count_attempt_id=None,
            reserved_provider_request_count=0,
            input_tokens=self.runtime_identity.maximum_input_tokens_per_call,
            output_tokens=self.runtime_identity.max_output_tokens,
            model_calls=1,
            count_tokens_calls=0,
        )

    def _publish_attempt(self, record: QualificationProviderAttempt) -> None:
        self.attempts.append(record)
        identity = self.store.publish(f"{record.attempt_id}-finish", record)
        self.retained.append(identity)
        self.attempt_finishes.append(identity)

    def complete_count_tokens(
        self,
        start: QualificationProviderAttemptStart,
        metadata: AdvisoryPlannerMetadata,
        *,
        counted_input_tokens: int | None,
        failure_category: str | None = None,
    ) -> QualificationProviderAttempt:
        if start.operation is not QualificationProviderOperation.COUNT_TOKENS:
            raise QualificationProtocolError(
                "token count completed the wrong operation"
            )
        valid_metadata = _metadata_matches_runtime(metadata, self.runtime_identity)
        counted = (
            counted_input_tokens
            if type(counted_input_tokens) is int
            and 1
            <= counted_input_tokens
            <= self.runtime_identity.maximum_input_tokens_per_call
            else None
        )
        if not valid_metadata:
            counted = None
            failure_category = "provider-drift"
        elif counted is None:
            failure_category = failure_category or "token-count-unavailable"
        outcome = (
            QualificationAttemptOutcome.TOKEN_COUNTED
            if counted is not None
            else QualificationAttemptOutcome.PROVIDER_FAILURE
        )
        record = QualificationProviderAttempt(
            schema_version=QUALIFICATION_ATTEMPT_VERSION,
            attempt_id=start.attempt_id,
            sequence=start.sequence,
            dispatch_id=start.dispatch_id,
            execution_id=start.execution_id,
            case_id=start.case_id,
            repetition=start.repetition,
            planner_phase=start.planner_phase,
            operation=start.operation,
            execution_basis=start.execution_basis,
            planner_configuration_sha256=start.planner_configuration_sha256,
            input_sha256=start.input_sha256,
            request_byte_count=start.request_byte_count,
            sealed_generation_request_sha256=(start.sealed_generation_request_sha256),
            provider_request_sha256=start.provider_request_sha256,
            paired_count_attempt_id=start.paired_count_attempt_id,
            reserved_provider_request_count=(start.reserved_provider_request_count),
            outcome=outcome,
            accounting_basis=QualificationAccountingBasis.NON_BILLABLE,
            failure_category=None if counted is not None else failure_category,
            provider_failure_kind=(None if counted is not None else failure_category),
            input_bound_status=QualificationBoundStatus.NOT_APPLICABLE,
            output_bound_status=QualificationBoundStatus.NOT_APPLICABLE,
            provider_name=metadata.provider_name,
            configured_model=metadata.configured_model,
            reported_model=None,
            counted_input_tokens=counted,
            reserved_input_tokens=0,
            reserved_output_tokens=0,
            reserved_cost_nano_units=0,
            accounted_input_tokens=0,
            accounted_output_tokens=0,
            accounted_cost_nano_units=0,
            usage_measured=False,
            completed_at=datetime.now(UTC),
        )
        self._publish_attempt(record)
        if counted is None:
            self.invalid_executions[start.execution_id] = (
                failure_category or "token-count-unavailable"
            )
        return record

    def complete_generation(
        self,
        start: QualificationProviderAttemptStart,
        metadata: AdvisoryPlannerMetadata,
        *,
        turn: AdvisoryPlannerTurn | None,
        raised: bool = False,
        control: bool = False,
        preflight: bool = False,
    ) -> QualificationProviderAttempt:
        if start.operation is not QualificationProviderOperation.GENERATE:
            raise QualificationProtocolError("generation completed the wrong operation")
        provider = self.manifest.provider
        usage = None if turn is None else turn.usage
        failure = None if turn is None else turn.failure
        output_sha256 = None if turn is None else turn.output_sha256
        reported_model = None if turn is None else turn.metadata.reported_model
        reported_model_raw_sha256 = (
            None if turn is None else turn.metadata.reported_model_raw_sha256
        )
        provider_drift = not _metadata_matches_runtime(
            metadata, self.runtime_identity
        ) or (
            turn is not None
            and not _metadata_matches_runtime(turn.metadata, self.runtime_identity)
        )
        if turn is not None and turn.failure is None:
            if preflight:
                try:
                    QualificationModelBinding(
                        schema_version=QUALIFICATION_MODEL_BINDING_VERSION,
                        suite_id=self.manifest.suite_id,
                        runtime_identity_sha256=self.planner_configuration_sha256,
                        configured_model=self.runtime_identity.configured_model,
                        reported_model_revision=turn.metadata.reported_model,
                        reported_model_raw_sha256=(
                            turn.metadata.reported_model_raw_sha256
                        ),
                        preflight_generation_attempt_id=start.attempt_id,
                        preflight_input_sha256=start.input_sha256,
                        bound_at=datetime.now(UTC),
                    )
                except (TypeError, ValueError):
                    provider_drift = True
            else:
                provider_drift = (
                    provider_drift
                    or self.model_binding is None
                    or turn.metadata.reported_model
                    != self.model_binding.reported_model_revision
                )
        usage_measured = usage is not None and not control
        measured_input_tokens = None if not usage_measured else usage.prompt_tokens
        measured_output_tokens = None if not usage_measured else usage.output_tokens
        if control:
            input_bound_status = QualificationBoundStatus.NOT_APPLICABLE
            output_bound_status = QualificationBoundStatus.NOT_APPLICABLE
        else:
            input_bound_status = (
                QualificationBoundStatus.UNKNOWN
                if measured_input_tokens is None
                else (
                    QualificationBoundStatus.EXCEEDED
                    if measured_input_tokens > start.reserved_input_tokens
                    else QualificationBoundStatus.WITHIN
                )
            )
            output_bound_status = (
                QualificationBoundStatus.UNKNOWN
                if measured_output_tokens is None
                else (
                    QualificationBoundStatus.EXCEEDED
                    if measured_output_tokens > start.reserved_output_tokens
                    else QualificationBoundStatus.WITHIN
                )
            )
        provider_failure_kind: str | None = None
        if control:
            outcome = QualificationAttemptOutcome.CONTROL_FAILURE
            failure_category = "control-unavailable"
        elif raised:
            outcome = QualificationAttemptOutcome.RAISED
            failure_category = "provider-raised"
            provider_failure_kind = failure_category
        elif provider_drift:
            outcome = QualificationAttemptOutcome.PROVIDER_DRIFT
            failure_category = "provider-drift"
            provider_failure_kind = failure_category
        elif failure is not None:
            outcome = QualificationAttemptOutcome.PROVIDER_FAILURE
            failure_category = failure.value
            provider_failure_kind = failure_category
        elif usage is None:
            outcome = QualificationAttemptOutcome.USAGE_UNAVAILABLE
            failure_category = "usage-unavailable"
        elif QualificationBoundStatus.EXCEEDED in {
            input_bound_status,
            output_bound_status,
        }:
            outcome = QualificationAttemptOutcome.RESERVATION_EXCEEDED
            failure_category = "reservation-exceeded"
        else:
            outcome = QualificationAttemptOutcome.MEASURED
            failure_category = None
        basis = (
            QualificationAccountingBasis.MEASURED
            if outcome is QualificationAttemptOutcome.MEASURED
            else QualificationAccountingBasis.RESERVED
        )
        if basis is QualificationAccountingBasis.MEASURED:
            assert measured_input_tokens is not None
            assert measured_output_tokens is not None
            input_tokens = measured_input_tokens
            output_tokens = measured_output_tokens
        else:
            input_tokens = max(
                start.reserved_input_tokens,
                0 if measured_input_tokens is None else measured_input_tokens,
            )
            output_tokens = max(
                start.reserved_output_tokens,
                0 if measured_output_tokens is None else measured_output_tokens,
            )
        cost = _attempt_cost(provider, input_tokens, output_tokens)
        record = QualificationProviderAttempt(
            schema_version=QUALIFICATION_ATTEMPT_VERSION,
            attempt_id=start.attempt_id,
            sequence=start.sequence,
            dispatch_id=start.dispatch_id,
            execution_id=start.execution_id,
            case_id=start.case_id,
            repetition=start.repetition,
            planner_phase=start.planner_phase,
            operation=start.operation,
            execution_basis=start.execution_basis,
            planner_configuration_sha256=start.planner_configuration_sha256,
            input_sha256=start.input_sha256,
            request_byte_count=start.request_byte_count,
            sealed_generation_request_sha256=(start.sealed_generation_request_sha256),
            provider_request_sha256=start.provider_request_sha256,
            paired_count_attempt_id=start.paired_count_attempt_id,
            reserved_provider_request_count=(start.reserved_provider_request_count),
            output_sha256=output_sha256,
            outcome=outcome,
            accounting_basis=basis,
            failure_category=failure_category,
            provider_failure_kind=provider_failure_kind,
            input_bound_status=input_bound_status,
            output_bound_status=output_bound_status,
            provider_name=metadata.provider_name,
            configured_model=metadata.configured_model,
            reported_model=reported_model,
            reported_model_raw_sha256=reported_model_raw_sha256,
            counted_input_tokens=None,
            reserved_input_tokens=start.reserved_input_tokens,
            reserved_output_tokens=start.reserved_output_tokens,
            reserved_cost_nano_units=start.reserved_cost_nano_units,
            accounted_input_tokens=input_tokens,
            accounted_output_tokens=output_tokens,
            accounted_cost_nano_units=cost,
            measured_input_tokens=measured_input_tokens,
            measured_output_tokens=measured_output_tokens,
            usage_measured=usage_measured,
            completed_at=datetime.now(UTC),
        )
        self._publish_attempt(record)
        if outcome not in {
            QualificationAttemptOutcome.MEASURED,
            QualificationAttemptOutcome.CONTROL_FAILURE,
        }:
            self.invalid_executions[start.execution_id] = (
                failure_category or "provider-attempt-invalid"
            )
        return record

    def ledger(self) -> QualificationAttemptLedger:
        attempts = tuple(self.attempts)
        return QualificationAttemptLedger(
            schema_version=QUALIFICATION_ATTEMPT_LEDGER_VERSION,
            suite_id=self.manifest.suite_id,
            manifest_sha256=canonical_sha256(self.manifest),
            source_revision=self.manifest.source_revision,
            execution_basis=self.execution_basis,
            planner_configuration_sha256=self.planner_configuration_sha256,
            attempts=attempts,
            attempt_starts=tuple(self.attempt_starts),
            attempt_finishes=tuple(self.attempt_finishes),
            totals=_attempt_totals(attempts),
        )


class _MeteredPlanner:
    def __init__(
        self,
        planner: AdvisoryPlanner,
        meter: _AttemptMeter,
        *,
        execution_id: str,
        case_id: str,
        repetition: int,
        control_failure: bool,
        preflight: bool = False,
    ) -> None:
        self._planner = planner
        self._meter = meter
        self._execution_id = execution_id
        self._case_id = case_id
        self._repetition = repetition
        self._control_failure = control_failure
        self._preflight = preflight

    @property
    def metadata(self) -> AdvisoryPlannerMetadata:
        return self._planner.metadata

    async def plan(self, planner_input: AdaptivePlannerInput) -> AdvisoryPlannerTurn:
        input_bytes = canonical_json_bytes(planner_input)
        input_sha256 = hashlib.sha256(input_bytes).hexdigest()
        if self._control_failure:
            start = self._meter.reserve_control_generation(
                execution_id=self._execution_id,
                case_id=self._case_id,
                repetition=self._repetition,
                planner_phase=planner_input.phase,
                input_sha256=input_sha256,
                request_byte_count=len(input_bytes),
            )
            turn = AdvisoryPlannerTurn(
                output=None,
                failure=PlannerFailureKind.UNAVAILABLE,
                metadata=self.metadata,
                input_sha256=start.input_sha256,
                output_sha256=None,
                usage=None,
            )
            self._meter.complete_generation(
                start, self.metadata, turn=turn, control=True
            )
            return turn
        count_start: QualificationProviderAttemptStart | None = None
        count_finish: QualificationProviderAttempt | None = None
        generation_start: QualificationProviderAttemptStart | None = None
        paired_budget_refused = False
        dispatch_hook: QualificationDispatchHook | None = None
        dispatch_consumed: bool | None = None

        def persist_undispatched_generation() -> None:
            start = self._meter.reserve_control_generation(
                execution_id=self._execution_id,
                case_id=self._case_id,
                repetition=self._repetition,
                planner_phase=planner_input.phase,
                input_sha256=input_sha256,
                request_byte_count=len(input_bytes),
            )
            unavailable = AdvisoryPlannerTurn(
                output=None,
                failure=PlannerFailureKind.UNAVAILABLE,
                metadata=self.metadata,
                input_sha256=start.input_sha256,
                output_sha256=None,
                usage=None,
            )
            self._meter.complete_generation(
                start,
                self.metadata,
                turn=unavailable,
                control=True,
                preflight=self._preflight,
            )
            self._meter.invalid_executions[self._execution_id] = (
                "provider-generation-undispatched"
            )

        if type(self._planner) is AdkGeminiPlanner:
            live_planner = self._planner

            async def precharge(
                context: QualificationDispatchContext,
            ):
                nonlocal count_start
                nonlocal count_finish
                nonlocal generation_start
                nonlocal paired_budget_refused
                if count_start is not None or generation_start is not None:
                    raise QualificationProtocolError(
                        "qualification planner dispatched more than once"
                    )
                try:
                    count_start = self._meter.reserve_count_tokens(
                        execution_id=self._execution_id,
                        case_id=self._case_id,
                        repetition=self._repetition,
                        planner_phase=planner_input.phase,
                        input_sha256=input_sha256,
                        request_byte_count=context.request_byte_count,
                        sealed_generation_request_sha256=(
                            context.sealed_generation_request_sha256
                        ),
                        provider_request_sha256=(context.provider_request_sha256),
                    )
                except QualificationBudgetExceeded:
                    paired_budget_refused = True
                    raise
                try:
                    counted_input_tokens = await context.count_tokens()
                except BaseException:
                    count_finish = self._meter.complete_count_tokens(
                        count_start,
                        self.metadata,
                        counted_input_tokens=None,
                        failure_category="token-count-unavailable",
                    )
                    raise
                count_finish = self._meter.complete_count_tokens(
                    count_start,
                    self.metadata,
                    counted_input_tokens=counted_input_tokens,
                )
                if (
                    count_finish.outcome
                    is not QualificationAttemptOutcome.TOKEN_COUNTED
                ):
                    raise QualificationProtocolError(
                        "qualification token count did not authorize generation"
                    )
                generation_start = self._meter.reserve_generation(
                    count_attempt=count_finish,
                )
                return await context.generate_content()

            dispatch_hook = precharge
            live_planner.bind_qualification_dispatch_hook(dispatch_hook)
        else:
            request_byte_count = len(input_bytes)
            count_start = self._meter.reserve_count_tokens(
                execution_id=self._execution_id,
                case_id=self._case_id,
                repetition=self._repetition,
                planner_phase=planner_input.phase,
                input_sha256=input_sha256,
                request_byte_count=request_byte_count,
                sealed_generation_request_sha256=input_sha256,
                provider_request_sha256=hashlib.sha256(
                    b"count-tokens:" + input_bytes
                ).hexdigest(),
            )
            counted_input_tokens = request_byte_count
            count_finish = self._meter.complete_count_tokens(
                count_start,
                self.metadata,
                counted_input_tokens=counted_input_tokens,
            )
            generation_start = self._meter.reserve_generation(
                count_attempt=count_finish,
            )
        try:
            try:
                turn = await self._planner.plan(planner_input)
            except BaseException:
                if generation_start is not None:
                    self._meter.complete_generation(
                        generation_start,
                        self.metadata,
                        turn=None,
                        raised=True,
                        preflight=self._preflight,
                    )
                elif count_start is None and not paired_budget_refused:
                    persist_undispatched_generation()
                raise
            try:
                self._meter.source_guard()
            except BaseException:
                if generation_start is not None:
                    self._meter.complete_generation(
                        generation_start,
                        self.metadata,
                        turn=turn,
                        preflight=self._preflight,
                    )
                elif count_start is None and not paired_budget_refused:
                    persist_undispatched_generation()
                raise
        finally:
            if dispatch_hook is not None:
                dispatch_consumed = live_planner.clear_qualification_dispatch_hook(
                    dispatch_hook
                )
        if type(self._planner) is AdkGeminiPlanner:
            if count_start is not None and dispatch_consumed is not True:
                raise QualificationProtocolError(
                    "qualification count escaped its public dispatch"
                )
            if count_start is None and not paired_budget_refused:
                persist_undispatched_generation()
            elif (count_finish is None and not paired_budget_refused) or (
                count_finish is not None
                and count_finish.outcome is QualificationAttemptOutcome.TOKEN_COUNTED
                and generation_start is None
            ):
                raise QualificationProtocolError(
                    "qualification dispatch accounting is incomplete"
                )
        if generation_start is None:
            return turn
        record = self._meter.complete_generation(
            generation_start,
            self.metadata,
            turn=turn,
            preflight=self._preflight,
        )
        if record.outcome in {
            QualificationAttemptOutcome.PROVIDER_DRIFT,
            QualificationAttemptOutcome.RESERVATION_EXCEEDED,
        }:
            return AdvisoryPlannerTurn(
                output=None,
                failure=PlannerFailureKind.SCHEMA_INVALID,
                metadata=self.metadata,
                input_sha256=generation_start.input_sha256,
                output_sha256=None,
                usage=turn.usage,
            )
        return turn


def _proposal_facts(result: AdaptiveInvestigationResult) -> QualificationProposalFacts:
    acquisition = tuple(
        proposal
        for turn in result.turns
        if turn.phase is AdaptivePlannerPhase.ACQUIRE_EVIDENCE
        for proposal in turn.proposals
    )
    explanation = tuple(
        proposal
        for turn in result.turns
        if turn.phase is AdaptivePlannerPhase.EXPLAIN_EVIDENCE
        for proposal in turn.proposals
    )
    count = lambda disposition: sum(  # noqa: E731
        item.disposition is disposition for item in acquisition
    )
    return QualificationProposalFacts(
        acquisition_proposal_count=len(acquisition),
        selected_proposal_count=count(ProposalDisposition.SELECTED),
        deferred_proposal_count=count(ProposalDisposition.DEFERRED),
        unsupported_proposal_count=count(ProposalDisposition.UNSUPPORTED_CAPABILITY),
        invalid_proposal_count=sum(
            item.disposition
            in {
                ProposalDisposition.INVALID_ARGUMENTS,
                ProposalDisposition.INVALID_EFFECT_REFERENCE,
            }
            for item in acquisition
        ),
        duplicate_proposal_count=count(ProposalDisposition.DUPLICATE),
        unavailable_proposal_count=count(ProposalDisposition.UNAVAILABLE),
        budget_exceeded_proposal_count=count(ProposalDisposition.BUDGET_EXCEEDED),
        ignored_explanation_proposal_count=sum(
            item.disposition is ProposalDisposition.IGNORED_EXPLANATION_PHASE
            for item in explanation
        ),
    )


def _explanation_completeness(
    result: FixedBaselineResult | AdaptiveInvestigationResult,
) -> ExplanationCompleteness:
    explanation = result.report.advisory_explanation
    if explanation is None:
        return ExplanationCompleteness(
            required_evidence_citation_count=0,
            valid_evidence_citation_count=0,
            missing_evidence_citation_count=0,
            complete=True,
        )
    citations = explanation.cited_evidence_ids
    retained = {item.evidence_id for item in result.report.evidence}
    valid = sum(item in retained for item in citations)
    return ExplanationCompleteness(
        required_evidence_citation_count=len(citations),
        valid_evidence_citation_count=valid,
        missing_evidence_citation_count=len(citations) - valid,
        complete=valid == len(citations),
    )


def _fixed_normalized_run(
    manifest: QualificationSuiteManifest,
    case: QualificationCaseDefinition,
    envelope_sha256: str,
    result: FixedBaselineResult,
    runtime_identity_sha256: str,
) -> QualificationNormalizedRun:
    assert case.expectation is not None
    strategy_version = f"{result.plan_name}:{result.plan_version}"
    if strategy_version != manifest.fixed_strategy_version:
        raise QualificationProtocolError("fixed strategy version drifted")
    run = ComparisonRun(
        scenario=case.scenario,
        envelope_sha256=envelope_sha256,
        strategy_kind=ComparisonStrategyKind.FIXED,
        strategy_version=strategy_version,
        plan_sha256=result.plan_sha256,
        report_sha256=canonical_sha256(result.report),
        classification=result.classification,
        matches_preregistered_expectation=(
            result.classification is case.expectation.expected_classification
        ),
        planned_probe_count=result.planned_probe_count,
        executed_probe_count=result.attempted_probe_count,
        controller_cost_units_used=result.cost_units_used,
        controller_result_bytes_acquired=result.result_bytes_acquired,
        total_elapsed_ms=result.total_elapsed_ms,
        time_to_sufficient_evidence_ms=result.time_to_sufficient_evidence_ms,
        stop_reason=result.stop_reason.value,
        unsupported_probe_count=result.unsupported_probe_count,
        unnecessary_probe_count=result.redundant_probe_count,
        duplicate_probe_count=result.duplicate_probe_count,
        explanation_completeness=_explanation_completeness(result),
        model_usage=ComparisonModelUsage(
            status=ComparisonModelUsageStatus.NOT_APPLICABLE,
            model_call_count=0,
            input_token_count=0,
            output_token_count=0,
            total_token_count=0,
        ),
    )
    return QualificationNormalizedRun(
        schema_version=QUALIFICATION_NORMALIZED_RUN_VERSION,
        runtime_identity_sha256=runtime_identity_sha256,
        run=run,
        proposal_facts=_zero_proposal_facts(),
        unavailable_probe_count=result.unavailable_probe_count,
    )


def _adaptive_normalized_run(
    manifest: QualificationSuiteManifest,
    case: QualificationCaseDefinition,
    envelope_sha256: str,
    result: AdaptiveInvestigationResult,
    runtime_identity_sha256: str,
) -> QualificationNormalizedRun:
    assert case.expectation is not None
    strategy_version = f"{result.policy_name}:{result.policy_version}"
    if strategy_version != manifest.adaptive_strategy_version:
        raise QualificationProtocolError("adaptive strategy version drifted")
    facts = _proposal_facts(result)
    counts = (
        result.model_prompt_tokens,
        result.model_output_tokens,
        result.model_total_tokens,
    )
    measured = all(value is not None for value in counts)
    run = ComparisonRun(
        scenario=case.scenario,
        envelope_sha256=envelope_sha256,
        strategy_kind=ComparisonStrategyKind.ADAPTIVE,
        strategy_version=strategy_version,
        plan_sha256=result.policy_sha256,
        report_sha256=canonical_sha256(result.report),
        classification=result.classification,
        matches_preregistered_expectation=(
            result.classification is case.expectation.expected_classification
        ),
        planned_probe_count=facts.selected_proposal_count,
        executed_probe_count=result.attempted_probe_count,
        controller_cost_units_used=result.cost_units_used,
        controller_result_bytes_acquired=result.result_bytes_acquired,
        total_elapsed_ms=result.total_elapsed_ms,
        time_to_sufficient_evidence_ms=result.time_to_sufficient_evidence_ms,
        stop_reason=result.stop_reason.value,
        unsupported_probe_count=0,
        unnecessary_probe_count=result.redundant_probe_count,
        duplicate_probe_count=0,
        explanation_completeness=_explanation_completeness(result),
        model_usage=ComparisonModelUsage(
            status=(
                ComparisonModelUsageStatus.MEASURED
                if measured
                else ComparisonModelUsageStatus.UNAVAILABLE
            ),
            provider_name=result.provider_name,
            model_name=result.configured_model,
            model_call_count=result.model_invocation_count,
            input_token_count=result.model_prompt_tokens,
            output_token_count=result.model_output_tokens,
            total_token_count=result.model_total_tokens,
        ),
    )
    return QualificationNormalizedRun(
        schema_version=QUALIFICATION_NORMALIZED_RUN_VERSION,
        runtime_identity_sha256=runtime_identity_sha256,
        run=run,
        proposal_facts=facts,
        unavailable_probe_count=result.unavailable_probe_count,
    )


def _action_gates_sha256(
    result: FixedBaselineResult | AdaptiveInvestigationResult,
) -> str:
    return hashlib.sha256(
        canonical_json_value_bytes(
            [item.model_dump(mode="json") for item in result.report.action_gate]
        )
    ).hexdigest()


def _policies_sha256(
    manifest: QualificationSuiteManifest,
    fixture: PreparedQualificationFixture,
) -> str:
    observed = {
        "action": fixture.envelope.context.policies.action,
        "adaptive_strategy": manifest.adaptive_strategy_version,
        "authority": fixture.envelope.context.policies.authority,
        "classification": fixture.envelope.context.policies.classification,
        "fixed_strategy": manifest.fixed_strategy_version,
    }
    expected = {
        "action": manifest.action_policy_version,
        "adaptive_strategy": manifest.adaptive_strategy_version,
        "authority": manifest.authority_policy_version,
        "classification": manifest.classification_policy_version,
        "fixed_strategy": manifest.fixed_strategy_version,
    }
    if observed != expected:
        raise QualificationProtocolError(
            "qualification fixture policy bindings changed"
        )
    return hashlib.sha256(canonical_json_value_bytes(expected)).hexdigest()


def _frozen_policies_sha256(manifest: QualificationSuiteManifest) -> str:
    return hashlib.sha256(
        canonical_json_value_bytes(
            {
                "action": manifest.action_policy_version,
                "adaptive_strategy": manifest.adaptive_strategy_version,
                "authority": manifest.authority_policy_version,
                "classification": manifest.classification_policy_version,
                "fixed_strategy": manifest.fixed_strategy_version,
            }
        )
    ).hexdigest()


def _capabilities_are_read_only(fixture: PreparedQualificationFixture) -> bool:
    return all(
        item.enabled
        and item.semantics.value == "READ_ONLY"
        and item.handler is not None
        for item in fixture.capabilities.freeze()
    )


def _model_has_no_authority() -> bool:
    forbidden = {"classification", "action", "action_gate", "allowed"}
    return set(AdaptivePlannerOutput.model_fields).isdisjoint(forbidden)


def _observation_bundle(
    *,
    execution_id: str,
    case_id: str,
    repetition: int,
    sequence: int,
    strategy: ComparisonStrategyKind,
    fixture: PreparedQualificationFixture,
    state_sha256: str,
    observations: tuple[QualificationRawObservation, ...],
    runtime_identity_sha256: str,
) -> QualificationObservationBundle:
    return QualificationObservationBundle(
        schema_version=QUALIFICATION_OBSERVATION_BUNDLE_VERSION,
        execution_id=execution_id,
        case_id=case_id,
        repetition=repetition,
        execution_sequence=sequence,
        strategy_kind=strategy,
        runtime_identity_sha256=runtime_identity_sha256,
        envelope_sha256=canonical_sha256(fixture.envelope),
        semantic_state_sha256=state_sha256,
        catalog_sha256=fixture.catalog_sha256,
        rules_sha256=fixture.rules_sha256,
        observations=tuple(
            QualificationObservationRecord(
                sequence=item.sequence,
                capability_name=item.capability_name,
                observation_sha256=hashlib.sha256(item.canonical_json).hexdigest(),
                observation=ProbeObservation.model_validate_json(item.canonical_json),
            )
            for item in observations
        ),
    )


@dataclass(frozen=True, slots=True)
class _CompletedLane:
    normalized: QualificationNormalizedRun
    result: FixedBaselineResult | AdaptiveInvestigationResult
    artifacts: QualificationLaneArtifacts
    receipt_identity: QualificationArtifactIdentity


class _LaneExecutionFailed(QualificationProtocolError):
    def __init__(
        self,
        artifacts: QualificationLaneArtifacts,
        receipt_identity: QualificationArtifactIdentity,
        normalized_runs: tuple[QualificationNormalizedRun, ...] = (),
    ) -> None:
        super().__init__("qualification lane failed and was retained")
        self.artifacts = artifacts
        self.receipt_identity = receipt_identity
        self.normalized_runs = normalized_runs


class _LanePublicationInterrupted(QualificationProtocolError):
    def __init__(self, partial: QualificationPartialPublication) -> None:
        super().__init__("qualification lane publication was interrupted")
        self.partial = partial


async def _execute_lane(
    *,
    sequence: int,
    strategy: ComparisonStrategyKind,
    manifest: QualificationSuiteManifest,
    case: QualificationCaseDefinition,
    repetition: int,
    fixture: PreparedQualificationFixture,
    planner: _MeteredPlanner,
    execution_id: str,
    store: QualificationArtifactStore,
    retained: list[QualificationArtifactIdentity],
    runtime_identity_sha256: str,
) -> _CompletedLane:
    state_before = await fixture.semantic_state_sha256()
    envelope_bytes = canonical_json_bytes(fixture.envelope)
    fixture.begin_lane(strategy.value)
    failure: BaseException | None = None
    result: FixedBaselineResult | AdaptiveInvestigationResult | None = None
    try:
        if strategy is ComparisonStrategyKind.FIXED:
            result = await execute_fixed_plan(
                decode_contract(envelope_bytes, ExecutionEnvelope),
                fixture.capabilities,
                fixture.rules,
                fixture.fixed_plan,
                clock=fixture.new_controller_clock(),
            )
        else:
            result = await execute_adaptive_investigation(
                decode_contract(envelope_bytes, ExecutionEnvelope),
                fixture.capabilities,
                fixture.rules,
                planner,
                fixture.adaptive_policy,
                clock=fixture.new_controller_clock(),
            )
    except BaseException as error:
        failure = error
    finally:
        observations = fixture.end_lane(strategy.value)
    state_after = await fixture.semantic_state_sha256()
    if failure is None and canonical_json_bytes(fixture.envelope) != envelope_bytes:
        failure = QualificationProtocolError(
            "qualification envelope changed during a lane"
        )
    if failure is None and state_before != state_after:
        failure = QualificationProtocolError(
            "qualification target changed during a lane"
        )
    envelope_sha256 = hashlib.sha256(envelope_bytes).hexdigest()
    if failure is not None:
        bundle = _observation_bundle(
            execution_id=execution_id,
            case_id=case.case_id,
            repetition=repetition,
            sequence=sequence,
            strategy=strategy,
            fixture=fixture,
            state_sha256=state_before,
            observations=observations,
            runtime_identity_sha256=runtime_identity_sha256,
        )
        raw_identity: QualificationArtifactIdentity | None = None
        failure_identity: QualificationArtifactIdentity | None = None
        receipt_identity: QualificationArtifactIdentity | None = None
        failure_record: QualificationFailureRecord | None = None
        receipt: QualificationLaneReceipt | None = None
        try:
            raw_identity = store.publish(
                f"{execution_id}-{strategy.value.lower()}-observations", bundle
            )
            retained.append(raw_identity)
            failure_record = QualificationFailureRecord(
                schema_version=QUALIFICATION_FAILURE_RECORD_VERSION,
                execution_id=execution_id,
                category="qualification-lane-failed",
                strategy_kind=strategy,
                runtime_identity_sha256=runtime_identity_sha256,
                failure_kind=(
                    "provider-budget-precharge"
                    if isinstance(failure, QualificationBudgetExceeded)
                    else "protocol-violation"
                    if isinstance(failure, QualificationProtocolError)
                    else "lane-execution-error"
                ),
                occurred_at=datetime.now(UTC),
            )
            failure_identity = store.publish(
                f"{execution_id}-{strategy.value.lower()}-failure",
                failure_record,
            )
            retained.append(failure_identity)
            receipt = QualificationLaneReceipt(
                schema_version=QUALIFICATION_LANE_RECEIPT_VERSION,
                suite_id=manifest.suite_id,
                manifest_sha256=canonical_sha256(manifest),
                execution_id=execution_id,
                case_id=case.case_id,
                repetition=repetition,
                lane_order=manifest.lane_orders[repetition - 1],
                execution_sequence=sequence,
                strategy_kind=strategy,
                runtime_identity_sha256=runtime_identity_sha256,
                envelope_sha256=envelope_sha256,
                target_sha256=canonical_sha256(fixture.envelope.target),
                semantic_state_before_sha256=state_before,
                semantic_state_after_sha256=state_after,
                catalog_sha256=fixture.catalog_sha256,
                rules_sha256=fixture.rules_sha256,
                policies_sha256=_policies_sha256(manifest, fixture),
                report_sha256=None,
                action_gates_sha256=None,
                raw_observations=raw_identity,
                normalized_run=None,
                protocol_run=None,
                failure_record=failure_identity,
            )
            receipt_identity = store.publish(
                f"{execution_id}-lane-{sequence}-receipt", receipt
            )
            retained.append(receipt_identity)
        except Exception as publication_error:
            raw_identity = raw_identity or store.resolve_committed(
                f"{execution_id}-{strategy.value.lower()}-observations", bundle
            )
            if raw_identity is None:
                raise
            if raw_identity not in retained:
                retained.append(raw_identity)
            if failure_record is not None:
                failure_identity = failure_identity or store.resolve_committed(
                    f"{execution_id}-{strategy.value.lower()}-failure",
                    failure_record,
                )
            if failure_identity is not None and failure_identity not in retained:
                retained.append(failure_identity)
            if receipt is not None:
                receipt_identity = receipt_identity or store.resolve_committed(
                    f"{execution_id}-lane-{sequence}-receipt", receipt
                )
            if receipt_identity is not None:
                if receipt_identity not in retained:
                    retained.append(receipt_identity)
            else:
                raise _LanePublicationInterrupted(
                    QualificationPartialPublication(
                        schema_version=QUALIFICATION_PARTIAL_PUBLICATION_VERSION,
                        execution_id=execution_id,
                        case_id=case.case_id,
                        repetition=repetition,
                        strategy_kind=strategy,
                        runtime_identity_sha256=runtime_identity_sha256,
                        raw_observations=raw_identity,
                        failure_record=failure_identity,
                    )
                ) from publication_error
        assert failure_identity is not None
        assert receipt_identity is not None
        if isinstance(failure, asyncio.CancelledError):
            raise failure
        raise _LaneExecutionFailed(
            QualificationLaneArtifacts(
                strategy_kind=strategy,
                raw_observations=raw_identity,
                normalized_run=None,
                failure_record=failure_identity,
            ),
            receipt_identity,
        ) from failure
    assert result is not None
    normalized = (
        _fixed_normalized_run(
            manifest, case, envelope_sha256, result, runtime_identity_sha256
        )
        if type(result) is FixedBaselineResult
        else _adaptive_normalized_run(
            manifest, case, envelope_sha256, result, runtime_identity_sha256
        )
    )
    bundle = _observation_bundle(
        execution_id=execution_id,
        case_id=case.case_id,
        repetition=repetition,
        sequence=sequence,
        strategy=strategy,
        fixture=fixture,
        state_sha256=state_before,
        observations=observations,
        runtime_identity_sha256=runtime_identity_sha256,
    )
    raw_identity: QualificationArtifactIdentity | None = None
    normalized_identity: QualificationArtifactIdentity | None = None
    protocol_identity: QualificationArtifactIdentity | None = None
    receipt_identity: QualificationArtifactIdentity | None = None
    receipt: QualificationLaneReceipt | None = None
    try:
        raw_identity = store.publish(
            f"{execution_id}-{strategy.value.lower()}-observations", bundle
        )
        retained.append(raw_identity)
        normalized_identity = store.publish(
            f"{execution_id}-{strategy.value.lower()}-run", normalized.run
        )
        retained.append(normalized_identity)
        protocol_identity = store.publish(
            f"{execution_id}-{strategy.value.lower()}-protocol-run", normalized
        )
        retained.append(protocol_identity)
        receipt = QualificationLaneReceipt(
            schema_version=QUALIFICATION_LANE_RECEIPT_VERSION,
            suite_id=manifest.suite_id,
            manifest_sha256=canonical_sha256(manifest),
            execution_id=execution_id,
            case_id=case.case_id,
            repetition=repetition,
            lane_order=manifest.lane_orders[repetition - 1],
            execution_sequence=sequence,
            strategy_kind=strategy,
            runtime_identity_sha256=runtime_identity_sha256,
            envelope_sha256=envelope_sha256,
            target_sha256=canonical_sha256(fixture.envelope.target),
            semantic_state_before_sha256=state_before,
            semantic_state_after_sha256=state_after,
            catalog_sha256=fixture.catalog_sha256,
            rules_sha256=fixture.rules_sha256,
            policies_sha256=_policies_sha256(manifest, fixture),
            report_sha256=canonical_sha256(result.report),
            action_gates_sha256=_action_gates_sha256(result),
            raw_observations=raw_identity,
            normalized_run=normalized_identity,
            protocol_run=protocol_identity,
            failure_record=None,
        )
        receipt_identity = store.publish(
            f"{execution_id}-lane-{sequence}-receipt", receipt
        )
        retained.append(receipt_identity)
    except Exception as error:
        raw_identity = raw_identity or store.resolve_committed(
            f"{execution_id}-{strategy.value.lower()}-observations", bundle
        )
        if raw_identity is None:
            raise
        if raw_identity not in retained:
            retained.append(raw_identity)
        normalized_identity = normalized_identity or store.resolve_committed(
            f"{execution_id}-{strategy.value.lower()}-run", normalized.run
        )
        if normalized_identity is not None and normalized_identity not in retained:
            retained.append(normalized_identity)
        protocol_identity = protocol_identity or store.resolve_committed(
            f"{execution_id}-{strategy.value.lower()}-protocol-run", normalized
        )
        if protocol_identity is not None and protocol_identity not in retained:
            retained.append(protocol_identity)
        if receipt is not None:
            receipt_identity = receipt_identity or store.resolve_committed(
                f"{execution_id}-lane-{sequence}-receipt", receipt
            )
        if receipt_identity is not None:
            if receipt_identity not in retained:
                retained.append(receipt_identity)
        else:
            raise _LanePublicationInterrupted(
                QualificationPartialPublication(
                    schema_version=QUALIFICATION_PARTIAL_PUBLICATION_VERSION,
                    execution_id=execution_id,
                    case_id=case.case_id,
                    repetition=repetition,
                    strategy_kind=strategy,
                    runtime_identity_sha256=runtime_identity_sha256,
                    raw_observations=raw_identity,
                    normalized_run=normalized_identity,
                    protocol_run=protocol_identity,
                )
            ) from error
    assert normalized_identity is not None
    assert protocol_identity is not None
    assert receipt_identity is not None
    return _CompletedLane(
        normalized=normalized,
        result=result,
        artifacts=QualificationLaneArtifacts(
            strategy_kind=strategy,
            raw_observations=raw_identity,
            normalized_run=normalized_identity,
            failure_record=None,
        ),
        receipt_identity=receipt_identity,
    )


def _ordered_strategies(
    order: QualificationLaneOrder,
) -> tuple[ComparisonStrategyKind, ComparisonStrategyKind]:
    return (
        (ComparisonStrategyKind.FIXED, ComparisonStrategyKind.ADAPTIVE)
        if order is QualificationLaneOrder.FIXED_FIRST
        else (ComparisonStrategyKind.ADAPTIVE, ComparisonStrategyKind.FIXED)
    )


@dataclass(frozen=True, slots=True)
class _CaseExecution:
    result: QualificationCaseResult
    normalized_runs: tuple[QualificationNormalizedRun, ...]
    lane_receipts: tuple[QualificationArtifactIdentity, ...]
    partial_publication: QualificationPartialPublication | None = None


async def _measurement_result(
    manifest: QualificationSuiteManifest,
    case: QualificationCaseDefinition,
    repetition: int,
    fixture: PreparedQualificationFixture,
    planner: AdvisoryPlanner,
    meter: _AttemptMeter,
    store: QualificationArtifactStore,
    retained: list[QualificationArtifactIdentity],
    runtime_identity_sha256: str,
) -> _CaseExecution:
    order = manifest.lane_orders[repetition - 1]
    execution_id = f"execution-{case.case_id}-r{repetition}"
    metered = _MeteredPlanner(
        planner,
        meter,
        execution_id=execution_id,
        case_id=case.case_id,
        repetition=repetition,
        control_failure=False,
    )
    ordered = []
    completed: dict[ComparisonStrategyKind, _CompletedLane] = {}
    for sequence, strategy in enumerate(_ordered_strategies(order), start=1):
        try:
            lane = await _execute_lane(
                sequence=sequence,
                strategy=strategy,
                manifest=manifest,
                case=case,
                repetition=repetition,
                fixture=fixture,
                planner=metered,
                execution_id=execution_id,
                store=store,
                retained=retained,
                runtime_identity_sha256=runtime_identity_sha256,
            )
        except _LaneExecutionFailed as failure:
            artifacts = (*(item.artifacts for item in ordered), failure.artifacts)
            return _CaseExecution(
                result=build_failed_result(
                    manifest,
                    execution_id=execution_id,
                    case_id=case.case_id,
                    repetition=repetition,
                    lane_order=order,
                    failure_category="qualification-lane-failed",
                    invalid=True,
                    artifacts=artifacts,
                ),
                normalized_runs=tuple(item.normalized for item in ordered),
                lane_receipts=(
                    *(item.receipt_identity for item in ordered),
                    failure.receipt_identity,
                ),
            )
        except _LanePublicationInterrupted as failure:
            return _CaseExecution(
                result=build_failed_result(
                    manifest,
                    execution_id=execution_id,
                    case_id=case.case_id,
                    repetition=repetition,
                    lane_order=order,
                    failure_category="qualification-publication-interrupted",
                    invalid=True,
                    artifacts=tuple(item.artifacts for item in ordered),
                ),
                normalized_runs=tuple(item.normalized for item in ordered),
                lane_receipts=tuple(item.receipt_identity for item in ordered),
                partial_publication=failure.partial,
            )
        ordered.append(lane)
        completed[strategy] = lane
    fixed = completed[ComparisonStrategyKind.FIXED]
    adaptive = completed[ComparisonStrategyKind.ADAPTIVE]
    comparison = InvestigationComparisonRecord(
        schema_version=INVESTIGATION_COMPARISON_RECORD_VERSION,
        comparison_id=f"comparison-{case.case_id}-r{repetition}",
        case_id=case.case_id,
        scenario=case.scenario,
        envelope_sha256=canonical_sha256(fixture.envelope),
        preregistered_expectation=case.expectation,
        baseline=fixed.normalized.run,
        adaptive=adaptive.normalized.run,
    )
    fixed_result = fixed.result
    adaptive_result = adaptive.result
    assert type(fixed_result) is FixedBaselineResult
    assert type(adaptive_result) is AdaptiveInvestigationResult
    action_match = canonical_json_value_bytes(
        [item.model_dump(mode="json") for item in fixed_result.report.action_gate]
    ) == canonical_json_value_bytes(
        [item.model_dump(mode="json") for item in adaptive_result.report.action_gate]
    )
    bindings = MeasurementBindings(
        source_revision=manifest.source_revision,
        provider_settings_sha256=canonical_sha256(manifest.provider),
        fixture_id=case.fixture_id,
        authority_policy_version=adaptive_result.authority_policy_version,
        classification_policy_version=adaptive_result.classification_policy_version,
        action_policy_version=adaptive_result.action_policy_version,
        action_gates_match=action_match,
        model_has_no_classification_or_action_authority=_model_has_no_authority(),
        probes_allowlisted_and_read_only=_capabilities_are_read_only(fixture),
    )
    artifacts = (fixed.artifacts, adaptive.artifacts)
    invalid = meter.invalid_executions.get(execution_id)
    if invalid is not None:
        result = build_failed_result(
            manifest,
            execution_id=execution_id,
            case_id=case.case_id,
            repetition=repetition,
            lane_order=order,
            failure_category=invalid,
            invalid=True,
            artifacts=artifacts,
        )
    else:
        result = build_measurement_result(
            manifest,
            execution_id=execution_id,
            case_id=case.case_id,
            repetition=repetition,
            lane_order=order,
            comparison=comparison,
            artifacts=artifacts,
            bindings=bindings,
        )
    return _CaseExecution(
        result=result,
        normalized_runs=tuple(item.normalized for item in ordered),
        lane_receipts=tuple(item.receipt_identity for item in ordered),
    )


async def _control_result(
    manifest: QualificationSuiteManifest,
    case: QualificationCaseDefinition,
    repetition: int,
    fixture: PreparedQualificationFixture,
    planner: AdvisoryPlanner,
    meter: _AttemptMeter,
    store: QualificationArtifactStore,
    retained: list[QualificationArtifactIdentity],
    runtime_identity_sha256: str,
) -> _CaseExecution:
    order = manifest.lane_orders[repetition - 1]
    execution_id = f"execution-{case.case_id}-r{repetition}"
    metered = _MeteredPlanner(
        planner,
        meter,
        execution_id=execution_id,
        case_id=case.case_id,
        repetition=repetition,
        control_failure=True,
    )
    state_before = await fixture.semantic_state_sha256()
    envelope_bytes = canonical_json_bytes(fixture.envelope)
    fixture.begin_lane(ComparisonStrategyKind.ADAPTIVE.value)
    try:
        result = await execute_adaptive_investigation(
            decode_contract(envelope_bytes, ExecutionEnvelope),
            fixture.capabilities,
            fixture.rules,
            metered,
            fixture.adaptive_policy,
            clock=fixture.new_controller_clock(),
        )
    finally:
        observations = fixture.end_lane(ComparisonStrategyKind.ADAPTIVE.value)
    state_after = await fixture.semantic_state_sha256()
    if (
        state_before != state_after
        or canonical_json_bytes(fixture.envelope) != envelope_bytes
    ):
        raise QualificationProtocolError("qualification control changed sealed state")
    bundle = _observation_bundle(
        execution_id=execution_id,
        case_id=case.case_id,
        repetition=repetition,
        sequence=1,
        strategy=ComparisonStrategyKind.ADAPTIVE,
        fixture=fixture,
        state_sha256=state_before,
        observations=observations,
        runtime_identity_sha256=runtime_identity_sha256,
    )
    raw_identity: QualificationArtifactIdentity | None = None
    failure_identity: QualificationArtifactIdentity | None = None
    receipt_identity: QualificationArtifactIdentity | None = None
    failure: QualificationFailureRecord | None = None
    receipt: QualificationLaneReceipt | None = None
    try:
        raw_identity = store.publish(f"{execution_id}-adaptive-observations", bundle)
        retained.append(raw_identity)
        failure = QualificationFailureRecord(
            schema_version=QUALIFICATION_FAILURE_RECORD_VERSION,
            execution_id=execution_id,
            category="injected-provider-unavailable",
            strategy_kind=ComparisonStrategyKind.ADAPTIVE,
            runtime_identity_sha256=runtime_identity_sha256,
            failure_kind="provider-unavailable-control",
            occurred_at=datetime.now(UTC),
            retained_report_sha256=canonical_sha256(result.report),
            retained_stop_reason=result.stop_reason.value,
            control_action_gates=result.report.action_gate,
        )
        failure_identity = store.publish(f"{execution_id}-adaptive-failure", failure)
        retained.append(failure_identity)
        receipt = QualificationLaneReceipt(
            schema_version=QUALIFICATION_LANE_RECEIPT_VERSION,
            suite_id=manifest.suite_id,
            manifest_sha256=canonical_sha256(manifest),
            execution_id=execution_id,
            case_id=case.case_id,
            repetition=repetition,
            lane_order=order,
            execution_sequence=1,
            strategy_kind=ComparisonStrategyKind.ADAPTIVE,
            runtime_identity_sha256=runtime_identity_sha256,
            envelope_sha256=canonical_sha256(fixture.envelope),
            target_sha256=canonical_sha256(fixture.envelope.target),
            semantic_state_before_sha256=state_before,
            semantic_state_after_sha256=state_after,
            catalog_sha256=fixture.catalog_sha256,
            rules_sha256=fixture.rules_sha256,
            policies_sha256=_policies_sha256(manifest, fixture),
            report_sha256=canonical_sha256(result.report),
            action_gates_sha256=_action_gates_sha256(result),
            raw_observations=raw_identity,
            normalized_run=None,
            protocol_run=None,
            failure_record=failure_identity,
        )
        receipt_identity = store.publish(f"{execution_id}-lane-1-receipt", receipt)
        retained.append(receipt_identity)
    except Exception as publication_error:
        raw_identity = raw_identity or store.resolve_committed(
            f"{execution_id}-adaptive-observations", bundle
        )
        if raw_identity is None:
            raise
        if raw_identity not in retained:
            retained.append(raw_identity)
        if failure is not None:
            failure_identity = failure_identity or store.resolve_committed(
                f"{execution_id}-adaptive-failure", failure
            )
        if failure_identity is not None and failure_identity not in retained:
            retained.append(failure_identity)
        if receipt is not None:
            receipt_identity = receipt_identity or store.resolve_committed(
                f"{execution_id}-lane-1-receipt", receipt
            )
        if receipt_identity is not None:
            if receipt_identity not in retained:
                retained.append(receipt_identity)
        else:
            raise _LanePublicationInterrupted(
                QualificationPartialPublication(
                    schema_version=QUALIFICATION_PARTIAL_PUBLICATION_VERSION,
                    execution_id=execution_id,
                    case_id=case.case_id,
                    repetition=repetition,
                    strategy_kind=ComparisonStrategyKind.ADAPTIVE,
                    runtime_identity_sha256=runtime_identity_sha256,
                    raw_observations=raw_identity,
                    failure_record=failure_identity,
                )
            ) from publication_error
    assert failure_identity is not None
    assert receipt_identity is not None
    consequential_allowed = any(
        item.requested_action.value in _CONSEQUENTIAL_ACTIONS and item.allowed
        for item in result.report.action_gate
    )
    provider_failure = result.stop_reason is AdaptiveStopReason.PLANNER_UNAVAILABLE
    classification_published = False
    control = build_control_result(
        manifest,
        execution_id=execution_id,
        case_id=case.case_id,
        repetition=repetition,
        lane_order=order,
        artifact=QualificationLaneArtifacts(
            strategy_kind=ComparisonStrategyKind.ADAPTIVE,
            raw_observations=raw_identity,
            normalized_run=None,
            failure_record=failure_identity,
        ),
        provider_failure_observed=provider_failure,
        classification_emitted=classification_published,
        consequential_action_allowed=consequential_allowed,
        model_mutation_attempted=not _model_has_no_authority(),
    )
    return _CaseExecution(
        result=control,
        normalized_runs=(),
        lane_receipts=(receipt_identity,),
    )


def _aggregate_protocol_lane(
    normalized_runs: tuple[QualificationNormalizedRun, ...],
    strategy: ComparisonStrategyKind,
    provider: QualificationProviderSettings,
) -> QualificationProtocolLaneMetrics:
    selected = tuple(
        item for item in normalized_runs if item.run.strategy_kind is strategy
    )
    facts = tuple(item.proposal_facts for item in selected)
    measured = tuple(
        item.run
        for item in selected
        if item.run.model_usage.status is ComparisonModelUsageStatus.MEASURED
    )
    inputs = sum(item.model_usage.input_token_count or 0 for item in measured)
    outputs = sum(item.model_usage.output_token_count or 0 for item in measured)
    return QualificationProtocolLaneMetrics(
        strategy_kind=strategy,
        run_count=len(selected),
        acquisition_proposal_count=sum(
            item.acquisition_proposal_count for item in facts
        ),
        selected_proposal_count=sum(item.selected_proposal_count for item in facts),
        deferred_proposal_count=sum(item.deferred_proposal_count for item in facts),
        unsupported_proposal_count=sum(
            item.unsupported_proposal_count for item in facts
        ),
        invalid_proposal_count=sum(item.invalid_proposal_count for item in facts),
        duplicate_proposal_count=sum(item.duplicate_proposal_count for item in facts),
        unavailable_proposal_count=sum(
            item.unavailable_proposal_count for item in facts
        ),
        budget_exceeded_proposal_count=sum(
            item.budget_exceeded_proposal_count for item in facts
        ),
        ignored_explanation_proposal_count=sum(
            item.ignored_explanation_proposal_count for item in facts
        ),
        planned_probe_count=sum(item.run.planned_probe_count for item in selected),
        executed_probe_count=sum(item.run.executed_probe_count for item in selected),
        unsupported_probe_count=sum(
            item.run.unsupported_probe_count for item in selected
        ),
        unavailable_probe_count=sum(item.unavailable_probe_count for item in selected),
        unnecessary_probe_count=sum(
            item.run.unnecessary_probe_count for item in selected
        ),
        duplicate_probe_count=sum(item.run.duplicate_probe_count for item in selected),
        total_elapsed_ms=sum(item.run.total_elapsed_ms for item in selected),
        model_call_count=sum(item.model_usage.model_call_count for item in measured),
        input_token_count=inputs,
        output_token_count=outputs,
        total_token_count=inputs + outputs,
        model_cost_nano_units=_attempt_cost(provider, inputs, outputs),
    )


def _provider_limit_exceeded(
    manifest: QualificationSuiteManifest,
    usage: QualificationModelUsageTotals,
) -> bool:
    stop = manifest.stop_conditions
    return any(
        (
            usage.model_call_count > stop.maximum_total_model_calls,
            usage.count_tokens_call_count > _FROZEN_MAX_COUNT_TOKEN_CALLS,
            usage.provider_request_count > _FROZEN_MAX_TOTAL_PROVIDER_REQUESTS,
            usage.input_token_count > stop.maximum_total_input_tokens,
            usage.output_token_count > stop.maximum_total_output_tokens,
            usage.model_cost_nano_units > stop.maximum_total_model_cost_nano_units,
        )
    )


def _build_protocol_summary(
    *,
    manifest: QualificationSuiteManifest,
    result_set: QualificationResultSet,
    qualification_summary: QualificationSummary,
    qualification_summary_identity: QualificationArtifactIdentity,
    ledger: QualificationAttemptLedger,
    ledger_identity: QualificationArtifactIdentity,
    model_binding_identity: QualificationArtifactIdentity,
    prior_identity: QualificationArtifactIdentity | None,
    historical_attempt_ledger_sha256: str,
    consumed_v2_custody_sha256: str,
    prior_stage_identity: QualificationArtifactIdentity | None,
    execution_basis: QualificationExecutionBasis,
    planner_configuration_sha256: str,
    case_execution_identities: tuple[QualificationArtifactIdentity, ...],
    normalized_runs: tuple[QualificationNormalizedRun, ...],
    prior_usage: QualificationModelUsageTotals,
) -> QualificationProtocolSummary:
    fixed_metrics = _aggregate_protocol_lane(
        normalized_runs, ComparisonStrategyKind.FIXED, manifest.provider
    )
    adaptive_metrics = _aggregate_protocol_lane(
        normalized_runs, ComparisonStrategyKind.ADAPTIVE, manifest.provider
    )
    ceiling_usage = _add_usage(ledger.totals, prior_usage)
    usage_incomplete = ledger.totals.unexpected_missing_usage_count > 0
    provider_limit_exceeded = _provider_limit_exceeded(manifest, ceiling_usage)
    protocol_valid = all(
        (
            qualification_summary.valid_for_value_evidence,
            not usage_incomplete,
            not provider_limit_exceeded,
        )
    )
    provider_evidence_qualifying = (
        execution_basis is QualificationExecutionBasis.LIVE_PROVIDER
    )
    consumed_v2_custody = canonical_consumed_v2_custody()
    return QualificationProtocolSummary(
        schema_version=QUALIFICATION_PROTOCOL_SUMMARY_VERSION,
        suite_id=manifest.suite_id,
        manifest_sha256=canonical_sha256(manifest),
        result_set_sha256=canonical_sha256(result_set),
        qualification_summary=qualification_summary_identity,
        attempt_ledger_sha256=ledger_identity.sha256,
        model_binding_sha256=model_binding_identity.sha256,
        prior_attempt_ledger_sha256=(
            None if prior_identity is None else prior_identity.sha256
        ),
        historical_attempt_ledger_sha256=historical_attempt_ledger_sha256,
        consumed_v2_custody_sha256=consumed_v2_custody_sha256,
        prior_stage_completion_sha256=(
            None if prior_stage_identity is None else prior_stage_identity.sha256
        ),
        execution_basis=execution_basis,
        planner_configuration_sha256=planner_configuration_sha256,
        case_executions=case_execution_identities,
        fixed_metrics=fixed_metrics,
        adaptive_metrics=adaptive_metrics,
        qualification_attempt_usage=ledger.totals,
        historical_attempt_usage=_project_v2_usage(
            consumed_v2_custody.historical_totals
        ),
        consumed_v2_attempt_usage=_project_v2_usage(
            consumed_v2_custody.consumed_v2_totals
        ),
        prior_attempt_usage=prior_usage,
        ceiling_usage=ceiling_usage,
        maximum_total_model_calls=(manifest.stop_conditions.maximum_total_model_calls),
        maximum_total_count_tokens_calls=_FROZEN_MAX_COUNT_TOKEN_CALLS,
        maximum_total_provider_requests=_FROZEN_MAX_TOTAL_PROVIDER_REQUESTS,
        maximum_total_input_tokens=(
            manifest.stop_conditions.maximum_total_input_tokens
        ),
        maximum_total_output_tokens=(
            manifest.stop_conditions.maximum_total_output_tokens
        ),
        maximum_total_model_cost_nano_units=(
            manifest.stop_conditions.maximum_total_model_cost_nano_units
        ),
        usage_incomplete=usage_incomplete,
        provider_limit_exceeded=provider_limit_exceeded,
        qualification_valid_for_value_evidence=(
            qualification_summary.valid_for_value_evidence
        ),
        protocol_valid=protocol_valid,
        provider_evidence_qualifying=provider_evidence_qualifying,
        successful=protocol_valid and provider_evidence_qualifying,
    )


class QualificationProtocolRunner:
    def __init__(
        self,
        artifact_root: str | Path,
        *,
        repository: str | Path,
        v2_custody_source: QualificationV2CustodySource | None = None,
    ) -> None:
        self.repository = Path(repository).resolve()
        artifact_path = Path(artifact_root).absolute()
        if artifact_path == self.repository or artifact_path.is_relative_to(
            self.repository
        ):
            raise QualificationProtocolError(
                "qualification artifacts must remain outside the source repository"
            )
        self.v2_custody_source = v2_custody_source
        self.store = QualificationArtifactStore(
            artifact_path,
            v2_custody_source=v2_custody_source,
            repository=self.repository,
        )

    def _resolve_consumed_v2_custody(
        self,
        execution_basis: QualificationExecutionBasis,
    ) -> QualificationConsumedV2Custody:
        if execution_basis is QualificationExecutionBasis.DETERMINISTIC_TEST:
            return canonical_consumed_v2_custody()
        if self.v2_custody_source is None:
            raise QualificationProtocolError(
                "live qualification requires the consumed-v2 custody source"
            )
        try:
            return load_consumed_v2_custody(self.v2_custody_source)
        except Exception as error:
            raise QualificationProtocolError(
                "consumed-v2 custody validation failed"
            ) from error

    def _assert_consumed_v2_custody(
        self,
        execution_basis: QualificationExecutionBasis,
        expected: QualificationConsumedV2Custody,
    ) -> None:
        if (
            execution_basis is QualificationExecutionBasis.LIVE_PROVIDER
            and self._resolve_consumed_v2_custody(execution_basis) != expected
        ):
            raise QualificationProtocolError("consumed-v2 custody changed")

    def _assert_source(
        self, manifest: QualificationSuiteManifest
    ) -> QualificationSourceState:
        state = repository_source_state(self.repository)
        if not state.clean:
            raise QualificationProtocolError("qualification source is not clean")
        if state.source_revision != manifest.source_revision:
            raise QualificationProtocolError("qualification source revision drifted")
        return state

    @staticmethod
    def _validate_planner(
        manifest: QualificationSuiteManifest,
        planner: AdvisoryPlanner,
        execution_basis: QualificationExecutionBasis,
    ) -> QualificationRuntimeIdentity:
        metadata = planner.metadata
        runtime = frozen_qualification_runtime_identity()
        if manifest.provider != frozen_qualification_provider_settings() or not (
            _metadata_matches_runtime(metadata, runtime)
            and metadata.reported_model is None
        ):
            raise QualificationProviderDrift(
                "planner identity does not match the qualification manifest"
            )
        if (
            execution_basis is QualificationExecutionBasis.DETERMINISTIC_TEST
            and isinstance(planner, AdkGeminiPlanner)
        ):
            raise QualificationProviderDrift(
                "deterministic qualification cannot use the live provider planner"
            )
        if execution_basis is QualificationExecutionBasis.LIVE_PROVIDER:
            registered = (
                qualification_runtime_identity(planner)
                if type(planner) is AdkGeminiPlanner
                else None
            )
            if registered != runtime:
                raise QualificationProviderDrift(
                    "live qualification requires the sealed Vertex planner factory"
                )
        return runtime

    def _validate_prerequisites(
        self,
        stage: QualificationProtocolStage,
        manifest: QualificationSuiteManifest,
        execution_basis: QualificationExecutionBasis,
        planner_configuration_sha256: str,
        consumed_v2_custody: QualificationConsumedV2Custody,
    ) -> tuple[
        QualificationSourceState,
        QualificationArtifactIdentity | None,
        QualificationModelUsageTotals,
        str,
        str,
        str | None,
    ]:
        state = self._assert_source(manifest)
        if (
            stage is QualificationProtocolStage.FINAL_HOLDOUT
            and execution_basis is not QualificationExecutionBasis.LIVE_PROVIDER
        ):
            raise QualificationProtocolError(
                "the final holdout requires live provider execution"
            )
        required = {
            QualificationProtocolStage.DEVELOPMENT_1: (),
            QualificationProtocolStage.DEVELOPMENT_2: (
                QualificationProtocolStage.DEVELOPMENT_1,
            ),
            QualificationProtocolStage.FINAL_HOLDOUT: (
                QualificationProtocolStage.DEVELOPMENT_1,
                QualificationProtocolStage.DEVELOPMENT_2,
            ),
        }[stage]
        completions = tuple(self.store.read_completion(item) for item in required)
        identities = tuple(self.store.completion_identity(item) for item in required)
        summaries = tuple(self.store.read_protocol_summary(item) for item in required)
        bindings = tuple(
            decode_contract(
                self.store._read_identity(stage_name, completion.model_binding),
                QualificationModelBinding,
            )
            for stage_name, completion in zip(required, completions, strict=True)
        )
        if execution_basis is QualificationExecutionBasis.LIVE_PROVIDER:
            prerequisites_valid = all(item.successful for item in completions)
        else:
            prerequisites_valid = all(
                item.protocol_valid
                and item.execution_basis
                is QualificationExecutionBasis.DETERMINISTIC_TEST
                for item in completions
            )
        if not prerequisites_valid:
            raise QualificationProtocolError(
                "prior qualification development stage did not pass"
            )
        provider_sha256 = canonical_sha256(manifest.provider)
        if any(
            item.source_revision != manifest.source_revision
            or item.git_commit != state.git_commit
            or item.provider_settings_sha256 != provider_sha256
            or item.planner_configuration_sha256 != planner_configuration_sha256
            for item in completions
        ):
            raise QualificationProtocolError(
                "qualification candidate or provider settings changed"
            )
        historical_sha256 = canonical_sha256(canonical_historical_attempt_ledger())
        consumed_v2_sha256 = canonical_sha256(consumed_v2_custody)
        if (
            any(
                item.historical_attempt_ledger_sha256 != historical_sha256
                for item in completions
            )
            or any(
                item.consumed_v2_custody_sha256 != consumed_v2_sha256
                for item in completions
            )
            or any(
                binding.runtime_identity_sha256 != planner_configuration_sha256
                or binding.reported_model_revision
                != bindings[0].reported_model_revision
                for binding in bindings
            )
        ):
            raise QualificationProtocolError(
                "qualification historical or model-revision custody changed"
            )
        for index in range(1, len(completions)):
            if (
                completions[index].prior_stage_completion_sha256
                != identities[index - 1].sha256
            ):
                raise QualificationProtocolError(
                    "qualification predecessor chain changed"
                )
        return (
            state,
            None if not identities else identities[-1],
            _empty_usage() if not summaries else summaries[-1].ceiling_usage,
            historical_sha256,
            consumed_v2_sha256,
            None if not bindings else bindings[-1].reported_model_revision,
        )

    @staticmethod
    def _prior_attempts(
        stage: QualificationProtocolStage,
        manifest: QualificationSuiteManifest,
        consumed_v2_custody: QualificationConsumedV2Custody,
    ) -> tuple[
        QualificationCombinedPriorAttemptLedger | None,
        QualificationModelUsageTotals,
    ]:
        if stage is not QualificationProtocolStage.DEVELOPMENT_1:
            return None, _empty_usage()
        prior = canonical_prior_attempt_ledger(consumed_v2_custody)
        if _provider_limit_exceeded(manifest, prior.totals):
            raise QualificationBudgetExceeded(
                "prior development calls already exceed provider ceilings"
            )
        return prior, prior.totals

    async def run(
        self,
        stage: QualificationProtocolStage,
        manifest: QualificationSuiteManifest,
        planner: AdvisoryPlanner,
        *,
        execution_basis: QualificationExecutionBasis = (
            QualificationExecutionBasis.LIVE_PROVIDER
        ),
    ) -> QualificationProtocolOutcome:
        if type(execution_basis) is not QualificationExecutionBasis:
            raise TypeError("qualification execution basis must be exact")
        consumed_v2_custody = self._resolve_consumed_v2_custody(execution_basis)
        validate_protocol_manifest(stage, manifest)
        runtime_identity = self._validate_planner(manifest, planner, execution_basis)
        planner_configuration_sha256 = canonical_sha256(runtime_identity)
        (
            source,
            prior_stage_identity,
            carried_usage,
            historical_attempt_ledger_sha256,
            consumed_v2_custody_sha256,
            required_model_revision,
        ) = self._validate_prerequisites(
            stage,
            manifest,
            execution_basis,
            planner_configuration_sha256,
            consumed_v2_custody,
        )
        prior_attempts, imported_usage = self._prior_attempts(
            stage, manifest, consumed_v2_custody
        )
        prior_usage = _add_usage(carried_usage, imported_usage)
        self.store.begin(stage)
        retained: list[QualificationArtifactIdentity] = []
        manifest_identity = self.store.publish("manifest", manifest)
        retained.append(manifest_identity)
        runtime_identity_artifact = self.store.publish(
            "runtime-identity", runtime_identity
        )
        retained.append(runtime_identity_artifact)
        prior_identity = None
        consumed_v2_identity = None
        if prior_attempts is not None:
            consumed_v2_identity = self.store.publish(
                "consumed-v2-custody", consumed_v2_custody
            )
            retained.append(consumed_v2_identity)
            prior_identity = self.store.publish("prior-attempt-ledger", prior_attempts)
            retained.append(prior_identity)
        meter = _AttemptMeter(
            manifest,
            self.store,
            retained,
            prior_usage=prior_usage,
            execution_basis=execution_basis,
            runtime_identity=runtime_identity,
            source_guard=lambda: (
                self._assert_source(manifest),
                self._assert_consumed_v2_custody(execution_basis, consumed_v2_custody),
            ),
        )
        preflight_input = _model_revision_preflight_input(
            planner.metadata, datetime.now(UTC)
        )
        preflight_planner = _MeteredPlanner(
            planner,
            meter,
            execution_id="provider-model-revision-preflight",
            case_id="provider-model-revision-preflight",
            repetition=1,
            control_failure=False,
            preflight=True,
        )
        preflight_turn = await preflight_planner.plan(preflight_input)
        preflight_attempts = tuple(
            item
            for item in meter.attempts
            if item.execution_id == "provider-model-revision-preflight"
            and item.operation is QualificationProviderOperation.GENERATE
        )
        if (
            len(preflight_attempts) != 1
            or preflight_turn.failure is not None
            or preflight_attempts[0].outcome is not QualificationAttemptOutcome.MEASURED
            or preflight_turn.metadata.reported_model is None
        ):
            raise QualificationProviderDrift(
                "provider model-revision preflight did not bind a concrete version"
            )
        model_binding = QualificationModelBinding(
            schema_version=QUALIFICATION_MODEL_BINDING_VERSION,
            suite_id=manifest.suite_id,
            runtime_identity_sha256=planner_configuration_sha256,
            configured_model=runtime_identity.configured_model,
            reported_model_revision=preflight_turn.metadata.reported_model,
            reported_model_raw_sha256=(
                preflight_turn.metadata.reported_model_raw_sha256
            ),
            preflight_generation_attempt_id=preflight_attempts[0].attempt_id,
            preflight_input_sha256=preflight_attempts[0].input_sha256,
            bound_at=datetime.now(UTC),
        )
        if (
            required_model_revision is not None
            and model_binding.reported_model_revision != required_model_revision
        ):
            raise QualificationProviderDrift(
                "provider model revision changed between qualification stages"
            )
        model_binding_identity = self.store.publish(
            "provider-model-binding", model_binding
        )
        retained.append(model_binding_identity)
        meter.bind_model_revision(model_binding)
        start = QualificationExecutionStart(
            schema_version=QUALIFICATION_EXECUTION_START_VERSION,
            stage=stage,
            suite_id=manifest.suite_id,
            manifest_sha256=manifest_identity.sha256,
            source_revision=manifest.source_revision,
            git_commit=source.git_commit,
            provider_settings_sha256=canonical_sha256(manifest.provider),
            planner_configuration_sha256=planner_configuration_sha256,
            runtime_identity=runtime_identity_artifact,
            model_binding=model_binding_identity,
            execution_basis=execution_basis,
            prior_stage_completion_sha256=(
                None if prior_stage_identity is None else prior_stage_identity.sha256
            ),
            prior_attempt_ledger_sha256=(
                None if prior_identity is None else prior_identity.sha256
            ),
            historical_attempt_ledger_sha256=historical_attempt_ledger_sha256,
            consumed_v2_custody_sha256=consumed_v2_custody_sha256,
            started_at=datetime.now(UTC),
        )
        start_identity = self.store.publish("execution-start", start)
        retained.append(start_identity)
        registry = self.store.create_fixture_registry(
            stage,
            manifest,
            start_identity,
            workspace=self.store.runtime_path(stage),
            real_monotonic=(
                execution_basis is QualificationExecutionBasis.LIVE_PROVIDER
            ),
        )
        results: list[QualificationCaseResult] = []
        normalized_runs: list[QualificationNormalizedRun] = []
        case_execution_identities: list[QualificationArtifactIdentity] = []
        stop = False
        try:
            if registry.fixture_ids != tuple(
                sorted(case.fixture_id for case in manifest.cases)
            ):
                raise QualificationProtocolError(
                    "qualification fixture registry is incomplete"
                )
            for repetition in range(1, manifest.repetition_count + 1):
                for case in manifest.cases:
                    fixture: PreparedQualificationFixture | None = None
                    execution: _CaseExecution | None = None
                    cleanup_failed = False
                    try:
                        self._assert_source(manifest)
                        self._assert_consumed_v2_custody(
                            execution_basis, consumed_v2_custody
                        )
                        fixture = registry.prepare(manifest, case, repetition)
                        if case.role is QualificationCaseRole.FAIL_CLOSED_CONTROL:
                            execution = await _control_result(
                                manifest,
                                case,
                                repetition,
                                fixture,
                                planner,
                                meter,
                                self.store,
                                retained,
                                planner_configuration_sha256,
                            )
                        else:
                            execution = await _measurement_result(
                                manifest,
                                case,
                                repetition,
                                fixture,
                                planner,
                                meter,
                                self.store,
                                retained,
                                planner_configuration_sha256,
                            )
                    except asyncio.CancelledError:
                        raise
                    except _LanePublicationInterrupted as failure:
                        execution = _CaseExecution(
                            result=build_failed_result(
                                manifest,
                                execution_id=(
                                    f"execution-{case.case_id}-r{repetition}"
                                ),
                                case_id=case.case_id,
                                repetition=repetition,
                                lane_order=manifest.lane_orders[repetition - 1],
                                failure_category=(
                                    "qualification-publication-interrupted"
                                ),
                                invalid=True,
                            ),
                            normalized_runs=(),
                            lane_receipts=(),
                            partial_publication=failure.partial,
                        )
                        stop = True
                    except Exception:
                        execution = _CaseExecution(
                            result=build_failed_result(
                                manifest,
                                execution_id=(
                                    f"execution-{case.case_id}-r{repetition}"
                                ),
                                case_id=case.case_id,
                                repetition=repetition,
                                lane_order=manifest.lane_orders[repetition - 1],
                                failure_category="qualification-execution-failed",
                                invalid=True,
                            ),
                            normalized_runs=(),
                            lane_receipts=(),
                        )
                        stop = True
                    finally:
                        if fixture is not None:
                            try:
                                fixture.cleanup()
                            except Exception:
                                cleanup_failed = True
                    assert execution is not None
                    if cleanup_failed:
                        execution = _CaseExecution(
                            result=build_failed_result(
                                manifest,
                                execution_id=execution.result.execution_id,
                                case_id=case.case_id,
                                repetition=repetition,
                                lane_order=manifest.lane_orders[repetition - 1],
                                failure_category="qualification-cleanup-failed",
                                invalid=True,
                                artifacts=execution.result.artifacts,
                            ),
                            normalized_runs=execution.normalized_runs,
                            lane_receipts=execution.lane_receipts,
                            partial_publication=execution.partial_publication,
                        )
                        stop = True
                    result = execution.result
                    results.append(result)
                    normalized_runs.extend(execution.normalized_runs)
                    result_identity = self.store.publish(
                        f"{result.execution_id}-result", result
                    )
                    retained.append(result_identity)
                    case_failure_identity = None
                    partial_publication_identity = None
                    if execution.partial_publication is not None:
                        partial_publication_identity = self.store.publish(
                            f"{result.execution_id}-partial-publication",
                            execution.partial_publication,
                        )
                        retained.append(partial_publication_identity)
                    if result.status in {
                        QualificationCaseResultStatus.FAILED,
                        QualificationCaseResultStatus.INVALID,
                        QualificationCaseResultStatus.CONTROL_FAILED,
                    }:
                        case_failure = QualificationFailureRecord(
                            schema_version=QUALIFICATION_FAILURE_RECORD_VERSION,
                            execution_id=result.execution_id,
                            category=result.failure_category
                            or "qualification-case-failed",
                            strategy_kind=None,
                            runtime_identity_sha256=planner_configuration_sha256,
                            failure_kind=(
                                "cleanup-failure"
                                if cleanup_failed
                                else "case-execution-failure"
                            ),
                            occurred_at=datetime.now(UTC),
                            partial_publication=partial_publication_identity,
                        )
                        case_failure_identity = self.store.publish(
                            f"{result.execution_id}-case-failure", case_failure
                        )
                        retained.append(case_failure_identity)
                    case_record = QualificationCaseExecutionRecord(
                        schema_version=QUALIFICATION_CASE_EXECUTION_VERSION,
                        execution_id=result.execution_id,
                        case_id=result.case_id,
                        repetition=result.repetition,
                        lane_order=result.lane_order,
                        status=result.status,
                        runtime_identity_sha256=planner_configuration_sha256,
                        result=result_identity,
                        lane_receipts=execution.lane_receipts,
                        failure_record=case_failure_identity,
                    )
                    case_identity = self.store.publish(
                        f"{result.execution_id}-case-execution", case_record
                    )
                    retained.append(case_identity)
                    case_execution_identities.append(case_identity)
                    if result.validity is not None and (
                        not result.validity.integrity_valid
                        or not result.validity.safety_valid
                    ):
                        stop = True
                    if result.status not in {
                        QualificationCaseResultStatus.COMPLETED,
                        QualificationCaseResultStatus.CONTROL_PASSED,
                    }:
                        stop = True
                    if stop:
                        break
                if stop:
                    break
        finally:
            registry.cleanup_workspace()
        self._assert_source(manifest)
        self._assert_consumed_v2_custody(execution_basis, consumed_v2_custody)
        result_set = build_result_set(manifest, tuple(results))
        result_set_identity = self.store.publish("result-set", result_set)
        retained.append(result_set_identity)
        ledger = meter.ledger()
        ledger_identity = self.store.publish("attempt-ledger", ledger)
        retained.append(ledger_identity)
        qualification_summary = summarize_qualification(
            manifest,
            result_set,
            evaluated_at=datetime.now(UTC),
        )
        qualification_summary_identity = self.store.publish(
            "qualification-summary-v1", qualification_summary
        )
        retained.append(qualification_summary_identity)
        protocol_summary = _build_protocol_summary(
            manifest=manifest,
            result_set=result_set,
            qualification_summary=qualification_summary,
            qualification_summary_identity=qualification_summary_identity,
            ledger=ledger,
            ledger_identity=ledger_identity,
            model_binding_identity=model_binding_identity,
            prior_identity=prior_identity,
            historical_attempt_ledger_sha256=(historical_attempt_ledger_sha256),
            consumed_v2_custody_sha256=consumed_v2_custody_sha256,
            prior_stage_identity=prior_stage_identity,
            execution_basis=execution_basis,
            planner_configuration_sha256=planner_configuration_sha256,
            case_execution_identities=tuple(case_execution_identities),
            normalized_runs=tuple(normalized_runs),
            prior_usage=prior_usage,
        )
        protocol_valid = protocol_summary.protocol_valid
        provider_evidence_qualifying = protocol_summary.provider_evidence_qualifying
        successful = protocol_summary.successful
        protocol_summary_identity = self.store.publish("summary", protocol_summary)
        retained.append(protocol_summary_identity)
        disposition = derive_disposition(
            manifest,
            result_set,
            qualification_summary,
            decided_at=datetime.now(UTC),
        )
        disposition_identity = self.store.publish("disposition", disposition)
        retained.append(disposition_identity)
        completed_source = self._assert_source(manifest)
        self._assert_consumed_v2_custody(execution_basis, consumed_v2_custody)
        completion = QualificationExecutionCompletion(
            schema_version=QUALIFICATION_EXECUTION_COMPLETION_VERSION,
            stage=stage,
            suite_id=manifest.suite_id,
            manifest_sha256=canonical_sha256(manifest),
            source_revision=manifest.source_revision,
            git_commit=completed_source.git_commit,
            provider_settings_sha256=canonical_sha256(manifest.provider),
            planner_configuration_sha256=planner_configuration_sha256,
            runtime_identity=runtime_identity_artifact,
            model_binding=model_binding_identity,
            execution_basis=execution_basis,
            prior_stage_completion_sha256=(
                None if prior_stage_identity is None else prior_stage_identity.sha256
            ),
            historical_attempt_ledger_sha256=(historical_attempt_ledger_sha256),
            consumed_v2_custody_sha256=consumed_v2_custody_sha256,
            completed_at=datetime.now(UTC),
            protocol_valid=protocol_valid,
            provider_evidence_qualifying=provider_evidence_qualifying,
            successful=successful,
            manifest=manifest_identity,
            execution_start=start_identity,
            result_set=result_set_identity,
            attempt_ledger=ledger_identity,
            prior_attempt_ledger=prior_identity,
            consumed_v2_custody=consumed_v2_identity,
            qualification_summary=qualification_summary_identity,
            protocol_summary=protocol_summary_identity,
            disposition=disposition_identity,
            case_executions=tuple(case_execution_identities),
            retained_artifacts=tuple(retained),
        )
        completion_identity = self.store.publish("execution-completion", completion)
        if (
            completion_identity
            != artifact_identity(
                "execution-completion", canonical_json_bytes(completion)
            )
            or self.store.read_completion(stage) != completion
        ):
            raise QualificationProtocolError(
                "qualification completion failed its final custody readback"
            )
        return QualificationProtocolOutcome(
            stage=stage,
            result_set=result_set,
            attempt_ledger=ledger,
            qualification_summary=qualification_summary,
            protocol_summary=protocol_summary,
            disposition=disposition,
            completion=completion,
        )


async def close_qualification_planner(planner: AdvisoryPlanner) -> None:
    closer = getattr(planner, "aclose", None)
    if not callable(closer):
        return
    result = closer()
    if inspect.isawaitable(result):
        await result


__all__ = [
    "QUALIFICATION_COMBINED_PRIOR_ATTEMPT_LEDGER_VERSION",
    "QUALIFICATION_PRIOR_ATTEMPT_LEDGER_VERSION",
    "QUALIFICATION_RUNTIME_IDENTITY_VERSION",
    "QualificationAccountingBasis",
    "QualificationArtifactStore",
    "QualificationAttemptLedger",
    "QualificationAttemptOutcome",
    "QualificationBoundStatus",
    "QualificationBudgetExceeded",
    "QualificationCombinedPriorAttemptLedger",
    "QualificationConsumedV2Custody",
    "QualificationExecutionBasis",
    "QualificationExecutionCompletion",
    "QualificationExecutionConsumed",
    "QualificationHistoricalAttemptLedger",
    "QualificationHistoricalUsageBasis",
    "QualificationModelUsageTotals",
    "QualificationObservationBundle",
    "QualificationPriorAttemptLedger",
    "QualificationPriorProviderAttempt",
    "QualificationProtocolError",
    "QualificationProtocolOutcome",
    "QualificationProtocolRunner",
    "QualificationProtocolSummary",
    "QualificationProviderAttempt",
    "QualificationProviderDrift",
    "QualificationRuntimeIdentity",
    "QualificationSourceState",
    "QualificationV2CustodySource",
    "build_protocol_manifest",
    "build_vertex_qualification_planner",
    "canonical_consumed_v2_custody",
    "canonical_historical_attempt_ledger",
    "canonical_prior_attempt_ledger",
    "close_qualification_planner",
    "frozen_qualification_provider_settings",
    "frozen_qualification_runtime_identity",
    "qualification_runtime_identity",
    "repository_source_state",
    "source_revision_for_git_commit",
    "validate_protocol_manifest",
]
