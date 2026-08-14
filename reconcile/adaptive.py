"""Bounded advisory planning around deterministic probe and evidence policy."""

from __future__ import annotations

import asyncio
import hashlib
import json
import re
import time
from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from typing import Protocol

from jsonschema import Draft202012Validator, validators

from reconcile.contracts import (
    ActionGateResult,
    AdvisoryExplanation,
    CapabilityRef,
    Classification,
    ComparisonStrategyKind,
    EvidenceDisposition,
    EvidenceReason,
    ExecutionEnvelope,
    InvestigationReport,
    MissingEvidence,
    ProbeOutcome,
    ProbeRequest,
    RequestedAction,
    canonical_json_bytes,
    decode_contract,
)
from reconcile.contracts.base import canonical_json_value_bytes
from reconcile.contracts.planning import (
    ADAPTIVE_PLANNER_INPUT_VERSION,
    ADAPTIVE_PLANNER_OUTPUT_VERSION,
    AdaptivePlannerInput,
    AdaptivePlannerOutput,
    AdaptivePlannerPhase,
    PlannerAdmittedEvidence,
    PlannerCapability,
    PlannerMissingEvidence,
    PlannerRejectedEvidence,
    PlannerRemainingBudget,
    PlannerVersionMetadata,
    PlannerWeakEvidence,
)
from reconcile.controller import (
    CapabilityRegistration,
    CapabilityRegistry,
    CapabilitySemantics,
    ControllerClock,
    ProbeController,
    ProbeStopReason,
    probe_request_sha256,
)
from reconcile.evidence import (
    CoreEvaluation,
    EvidenceEngine,
    ProbeRun,
    TargetRuleRegistry,
)
from reconcile.progress import (
    AdvisoryProgress,
    AdvisoryProgressStage,
    AdvisoryProposalProgress,
    EvidenceProgress,
    ProbeProgress,
    ProbeProgressStage,
    ProgressEmitter,
    ProgressPlannerFailure,
    ProgressProposalDisposition,
    StrategyProgress,
    StrategyProgressStage,
)
from reconcile.security import contains_sensitive_material

_IDENTIFIER_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]*$")
_SHA256_PATTERN = re.compile(r"^[0-9a-f]{64}$")
_MAX_TURNS = 64
_NON_PROGRESS_LIMIT = 2
_CAPABILITY_CATALOG_VERSION = "adaptive-catalog-v1"


def _progress_occurred_at() -> datetime:
    """Timestamp observation without touching the authoritative execution clock."""

    return datetime.now(UTC)


def _validate_identifier(value: str, label: str) -> None:
    if (
        type(value) is not str
        or not 1 <= len(value) <= 128
        or _IDENTIFIER_PATTERN.fullmatch(value) is None
        or contains_sensitive_material(value)
    ):
        raise ValueError(f"{label} must be a bounded identifier")


def _validate_sha256(value: str, label: str) -> None:
    if type(value) is not str or _SHA256_PATTERN.fullmatch(value) is None:
        raise ValueError(f"{label} must be a SHA-256 digest")


class PlannerFailureKind(StrEnum):
    """Sanitized provider failures that deterministic policy may observe."""

    UNAVAILABLE = "unavailable"
    TIMEOUT = "timeout"
    SCHEMA_INVALID = "schema_invalid"


@dataclass(frozen=True, slots=True)
class AdvisoryPlannerMetadata:
    """Public planner configuration and response-version metadata."""

    provider_name: str
    configured_model: str
    reported_model: str | None
    adk_version: str
    genai_version: str
    prompt_version: str
    prompt_sha256: str
    input_schema_version: str
    output_schema_version: str

    def __post_init__(self) -> None:
        for value, label in (
            (self.provider_name, "planner provider"),
            (self.configured_model, "configured planner model"),
            (self.adk_version, "ADK version"),
            (self.genai_version, "GenAI version"),
            (self.prompt_version, "planner prompt version"),
        ):
            _validate_identifier(value, label)
        if self.reported_model is not None:
            _validate_identifier(self.reported_model, "reported planner model")
        _validate_sha256(self.prompt_sha256, "planner prompt digest")
        if self.input_schema_version != ADAPTIVE_PLANNER_INPUT_VERSION:
            raise ValueError("planner input schema version is unsupported")
        if self.output_schema_version != ADAPTIVE_PLANNER_OUTPUT_VERSION:
            raise ValueError("planner output schema version is unsupported")


@dataclass(frozen=True, slots=True)
class AdvisoryPlannerUsage:
    """Measured token usage for exactly one planner call."""

    prompt_tokens: int
    output_tokens: int
    total_tokens: int

    def __post_init__(self) -> None:
        values = (self.prompt_tokens, self.output_tokens, self.total_tokens)
        if any(type(value) is not int or not 0 <= value < 2**63 for value in values):
            raise ValueError("planner token counts must be nonnegative integers")
        if self.total_tokens != self.prompt_tokens + self.output_tokens:
            raise ValueError(
                "planner total tokens must equal prompt plus output tokens"
            )


@dataclass(frozen=True, slots=True, init=False)
class AdvisoryPlannerTurn:
    """One validated planner result without raw provider text or error detail."""

    _output_bytes: bytes | None = field(repr=False)
    failure: PlannerFailureKind | None
    metadata: AdvisoryPlannerMetadata
    input_sha256: str
    output_sha256: str | None
    usage: AdvisoryPlannerUsage | None

    def __init__(
        self,
        *,
        output: AdaptivePlannerOutput | None,
        failure: PlannerFailureKind | None,
        metadata: AdvisoryPlannerMetadata,
        input_sha256: str,
        output_sha256: str | None,
        usage: AdvisoryPlannerUsage | None,
    ) -> None:
        if output is not None and type(output) is not AdaptivePlannerOutput:
            raise TypeError("planner output must be an exact adaptive planner output")
        if failure is not None and type(failure) is not PlannerFailureKind:
            raise TypeError("planner failure must be an exact sanitized failure")
        if type(metadata) is not AdvisoryPlannerMetadata:
            raise TypeError("planner turn metadata must be exact")
        if usage is not None and type(usage) is not AdvisoryPlannerUsage:
            raise TypeError("planner usage must be exact")
        _validate_sha256(input_sha256, "planner input digest")
        if output_sha256 is not None:
            _validate_sha256(output_sha256, "planner output digest")

        successful = output is not None
        if successful != (failure is None):
            raise ValueError("planner turn must contain exactly one output or failure")
        if successful and usage is None:
            raise ValueError("successful planner turns require measured usage")
        output_bytes = canonical_json_bytes(output) if output is not None else None
        if output_bytes is not None:
            expected_sha256 = hashlib.sha256(output_bytes).hexdigest()
            if output_sha256 != expected_sha256:
                raise ValueError("planner output digest does not match output")

        object.__setattr__(self, "_output_bytes", output_bytes)
        object.__setattr__(self, "failure", failure)
        object.__setattr__(self, "metadata", metadata)
        object.__setattr__(self, "input_sha256", input_sha256)
        object.__setattr__(self, "output_sha256", output_sha256)
        object.__setattr__(self, "usage", usage)

    @property
    def output(self) -> AdaptivePlannerOutput | None:
        """Return an isolated copy of the strict planner output."""

        if self._output_bytes is None:
            return None
        return decode_contract(self._output_bytes, AdaptivePlannerOutput)


class AdvisoryPlanner(Protocol):
    """Strict asynchronous boundary implemented by advisory providers."""

    @property
    def metadata(self) -> AdvisoryPlannerMetadata:
        """Return immutable metadata needed to build the typed planner input."""

    async def plan(self, planner_input: AdaptivePlannerInput) -> AdvisoryPlannerTurn:
        """Perform exactly one provider call without retries or schema repair."""


class AdaptiveStopReason(StrEnum):
    """Deterministic reason that adaptive evidence acquisition ended."""

    SUFFICIENT_EVIDENCE = "sufficient_evidence"
    NO_VALID_PROPOSAL = "no_valid_proposal"
    MAX_TURNS = "max_turns"
    BUDGET_EXHAUSTED = "budget_exhausted"
    DEADLINE_EXHAUSTED = "deadline_exhausted"
    CANCELLED = "cancelled"
    REQUIRED_CAPABILITY_UNAVAILABLE = "required_capability_unavailable"
    REQUIRED_PROBE_FAILED = "required_probe_failed"
    NON_PROGRESS = "non_progress"
    PLANNER_UNAVAILABLE = "planner_unavailable"
    PLANNER_TIMEOUT = "planner_timeout"
    PLANNER_SCHEMA_INVALID = "planner_schema_invalid"
    CAPABILITY_CATALOG_UNSAFE = "capability_catalog_unsafe"


class ProposalDisposition(StrEnum):
    """Sanitized deterministic disposition of one advisory proposal."""

    SELECTED = "selected"
    DEFERRED = "deferred"
    DUPLICATE = "duplicate"
    UNSUPPORTED_CAPABILITY = "unsupported_capability"
    INVALID_EFFECT_REFERENCE = "invalid_effect_reference"
    INVALID_ARGUMENTS = "invalid_arguments"
    UNAVAILABLE = "unavailable"
    BUDGET_EXCEEDED = "budget_exceeded"
    IGNORED_EXPLANATION_PHASE = "ignored_explanation_phase"


@dataclass(frozen=True, slots=True, init=False)
class AdaptiveInvestigationPolicy:
    """Versioned deterministic stop and planner-call bounds."""

    name: str
    version: str
    sufficient_classifications: tuple[Classification, ...]
    required_capabilities: tuple[CapabilityRef, ...]
    max_turns: int
    planner_timeout_ms: int
    include_explanation: bool
    sha256: str

    def __init__(
        self,
        *,
        name: str,
        version: str,
        sufficient_classifications: tuple[Classification, ...],
        required_capabilities: tuple[CapabilityRef, ...] = (),
        max_turns: int = 8,
        planner_timeout_ms: int = 30_000,
        include_explanation: bool = False,
    ) -> None:
        _validate_identifier(name, "adaptive policy name")
        _validate_identifier(version, "adaptive policy version")
        if type(sufficient_classifications) is not tuple:
            raise TypeError("sufficient classifications must be an immutable tuple")
        if any(
            type(classification) is not Classification
            for classification in sufficient_classifications
        ):
            raise TypeError("sufficient classifications must be exact")
        if Classification.UNKNOWN in sufficient_classifications:
            raise ValueError("UNKNOWN cannot be declared sufficient evidence")
        if len(sufficient_classifications) != len(set(sufficient_classifications)):
            raise ValueError("sufficient classifications must be unique")
        classifications = tuple(
            sorted(sufficient_classifications, key=lambda item: item.value)
        )

        if type(required_capabilities) is not tuple:
            raise TypeError("required capabilities must be an immutable tuple")
        if any(type(item) is not CapabilityRef for item in required_capabilities):
            raise TypeError("required capabilities must be exact capability references")
        required_payloads = tuple(
            sorted(
                (canonical_json_bytes(item) for item in required_capabilities),
            )
        )
        required = tuple(
            CapabilityRef.model_validate_json(payload) for payload in required_payloads
        )
        required_identities = tuple((item.name, item.version) for item in required)
        if len(required_identities) != len(set(required_identities)):
            raise ValueError("required capability identities must be unique")
        if type(max_turns) is not int or not 1 <= max_turns <= _MAX_TURNS:
            raise ValueError("adaptive policy requires one to 64 acquisition turns")
        if type(planner_timeout_ms) is not int or not 1 <= planner_timeout_ms < 2**63:
            raise ValueError("planner timeout must be a positive signed 64-bit integer")
        if type(include_explanation) is not bool:
            raise TypeError("explanation selection must be a boolean")

        material = {
            "include_explanation": include_explanation,
            "max_turns": max_turns,
            "name": name,
            "planner_timeout_ms": planner_timeout_ms,
            "required_capabilities": [
                json.loads(payload) for payload in required_payloads
            ],
            "sufficient_classifications": [
                classification.value for classification in classifications
            ],
            "version": version,
        }
        digest = hashlib.sha256(canonical_json_value_bytes(material)).hexdigest()
        object.__setattr__(self, "name", name)
        object.__setattr__(self, "version", version)
        object.__setattr__(self, "sufficient_classifications", classifications)
        object.__setattr__(self, "required_capabilities", required)
        object.__setattr__(self, "max_turns", max_turns)
        object.__setattr__(self, "planner_timeout_ms", planner_timeout_ms)
        object.__setattr__(self, "include_explanation", include_explanation)
        object.__setattr__(self, "sha256", digest)


@dataclass(frozen=True, slots=True)
class ProposalRecord:
    """Non-sensitive identity and disposition for one model proposal."""

    proposal_sequence: int
    capability_name: str
    capability_version: str
    request_sha256: str
    disposition: ProposalDisposition

    def __post_init__(self) -> None:
        if (
            type(self.proposal_sequence) is not int
            or not 1 <= self.proposal_sequence <= 8
        ):
            raise ValueError("proposal sequence must be between one and eight")
        _validate_identifier(self.capability_name, "proposal capability name")
        _validate_identifier(self.capability_version, "proposal capability version")
        _validate_sha256(self.request_sha256, "proposal request digest")
        if type(self.disposition) is not ProposalDisposition:
            raise TypeError("proposal disposition must be exact")


@dataclass(frozen=True, slots=True)
class AdaptiveTurnRecord:
    """Immutable planner transcript metadata without prompts or response text."""

    turn_sequence: int
    phase: AdaptivePlannerPhase
    input_sha256: str
    output_sha256: str | None
    failure: PlannerFailureKind | None
    cancelled: bool
    metadata: AdvisoryPlannerMetadata
    usage: AdvisoryPlannerUsage | None
    proposals: tuple[ProposalRecord, ...]
    selected_request_sha256: str | None
    planner_recommended_stop: bool | None

    def __post_init__(self) -> None:
        if type(self.turn_sequence) is not int or self.turn_sequence < 1:
            raise ValueError("adaptive turn sequence must be positive")
        if type(self.phase) is not AdaptivePlannerPhase:
            raise TypeError("adaptive turn phase must be exact")
        _validate_sha256(self.input_sha256, "adaptive turn input digest")
        if self.output_sha256 is not None:
            _validate_sha256(self.output_sha256, "adaptive turn output digest")
        if self.failure is not None and type(self.failure) is not PlannerFailureKind:
            raise TypeError("adaptive turn failure must be exact")
        if type(self.cancelled) is not bool:
            raise TypeError("adaptive turn cancellation marker must be a boolean")
        if type(self.metadata) is not AdvisoryPlannerMetadata:
            raise TypeError("adaptive turn metadata must be exact")
        if self.usage is not None and type(self.usage) is not AdvisoryPlannerUsage:
            raise TypeError("adaptive turn usage must be exact")
        if type(self.proposals) is not tuple or any(
            type(item) is not ProposalRecord for item in self.proposals
        ):
            raise TypeError("adaptive proposals must be an immutable exact tuple")
        sequences = tuple(item.proposal_sequence for item in self.proposals)
        if sequences != tuple(range(1, len(sequences) + 1)):
            raise ValueError("proposal records must be contiguous and ordered")
        if self.selected_request_sha256 is not None:
            _validate_sha256(
                self.selected_request_sha256,
                "selected proposal digest",
            )
            selected = tuple(
                item
                for item in self.proposals
                if item.disposition is ProposalDisposition.SELECTED
            )
            if len(selected) != 1 or selected[0].request_sha256 != (
                self.selected_request_sha256
            ):
                raise ValueError("selected proposal metadata is inconsistent")
        elif any(
            item.disposition is ProposalDisposition.SELECTED for item in self.proposals
        ):
            raise ValueError("selected proposal requires a selected digest")
        if (
            self.planner_recommended_stop is not None
            and type(self.planner_recommended_stop) is not bool
        ):
            raise TypeError("planner stop advice marker must be a boolean")
        if self.cancelled and (
            self.output_sha256 is not None
            or self.failure is not None
            or self.usage is not None
            or self.proposals
            or self.planner_recommended_stop is not None
        ):
            raise ValueError("cancelled planner turns cannot contain provider output")
        if (
            not self.cancelled
            and self.failure is None
            and (
                self.output_sha256 is None
                or self.usage is None
                or self.planner_recommended_stop is None
            )
        ):
            raise ValueError("successful planner metadata must be complete")
        if self.failure is not None and (
            self.proposals
            or self.selected_request_sha256 is not None
            or self.planner_recommended_stop is not None
        ):
            raise ValueError("failed planner turns cannot contain proposals or advice")
        ignored = ProposalDisposition.IGNORED_EXPLANATION_PHASE
        if self.phase is AdaptivePlannerPhase.EXPLAIN_EVIDENCE:
            if any(item.disposition is not ignored for item in self.proposals):
                raise ValueError("explanation turns cannot select probe proposals")
        elif any(item.disposition is ignored for item in self.proposals):
            raise ValueError("acquisition turns cannot use explanation dispositions")


_ADAPTIVE_RESULT_SEAL = object()


@dataclass(frozen=True, slots=True, init=False)
class AdaptiveInvestigationResult:
    """An ordinary deterministic report plus sanitized adaptive measurements."""

    _report_bytes: bytes = field(repr=False)
    policy_name: str
    policy_version: str
    policy_sha256: str
    capability_catalog_version: str
    capability_catalog_sha256: str
    stop_reason: AdaptiveStopReason
    acquisition_turn_count: int
    model_invocation_count: int
    proposal_count: int
    attempted_probe_count: int
    probe_count_used: int
    cost_units_used: int
    result_bytes_acquired: int
    total_elapsed_ms: int
    sufficient_probe_sequence: int | None
    time_to_sufficient_evidence_ms: int | None
    unsupported_proposal_count: int
    invalid_proposal_count: int
    duplicate_proposal_count: int
    unavailable_probe_count: int
    redundant_probe_count: int
    provider_name: str
    configured_model: str
    reported_models: tuple[str, ...]
    adk_version: str
    genai_version: str
    prompt_version: str
    prompt_sha256: str
    input_schema_version: str
    output_schema_version: str
    authority_policy_version: str
    classification_policy_version: str
    action_policy_version: str
    model_prompt_tokens: int | None
    model_output_tokens: int | None
    model_total_tokens: int | None
    explanation_valid: bool | None
    transcript_sha256: str
    turns: tuple[AdaptiveTurnRecord, ...]

    def __init__(
        self,
        *,
        report: InvestigationReport,
        policy: AdaptiveInvestigationPolicy,
        capability_catalog_sha256: str,
        stop_reason: AdaptiveStopReason,
        acquisition_turn_count: int,
        model_invocation_count: int,
        proposal_count: int,
        attempted_probe_count: int,
        probe_count_used: int,
        cost_units_used: int,
        result_bytes_acquired: int,
        total_elapsed_ms: int,
        sufficient_probe_sequence: int | None,
        time_to_sufficient_evidence_ms: int | None,
        unsupported_proposal_count: int,
        invalid_proposal_count: int,
        duplicate_proposal_count: int,
        unavailable_probe_count: int,
        redundant_probe_count: int,
        planner_metadata: AdvisoryPlannerMetadata,
        policies: tuple[str, str, str],
        model_prompt_tokens: int | None,
        model_output_tokens: int | None,
        model_total_tokens: int | None,
        explanation_valid: bool | None,
        turns: tuple[AdaptiveTurnRecord, ...],
        transcript_sha256: str,
        _seal: object,
    ) -> None:
        if _seal is not _ADAPTIVE_RESULT_SEAL:
            raise TypeError("adaptive results are created only by the executor")
        if type(report) is not InvestigationReport:
            raise TypeError("adaptive result requires an exact report")
        if type(policy) is not AdaptiveInvestigationPolicy:
            raise TypeError("adaptive result requires an exact policy")
        if type(stop_reason) is not AdaptiveStopReason:
            raise TypeError("adaptive stop reason must be exact")
        if type(planner_metadata) is not AdvisoryPlannerMetadata:
            raise TypeError("adaptive result planner metadata must be exact")
        _validate_sha256(capability_catalog_sha256, "capability catalog digest")
        _validate_sha256(transcript_sha256, "adaptive transcript digest")
        counts = (
            acquisition_turn_count,
            model_invocation_count,
            proposal_count,
            attempted_probe_count,
            probe_count_used,
            cost_units_used,
            result_bytes_acquired,
            total_elapsed_ms,
            unsupported_proposal_count,
            invalid_proposal_count,
            duplicate_proposal_count,
            unavailable_probe_count,
            redundant_probe_count,
        )
        if any(type(value) is not int or value < 0 for value in counts):
            raise ValueError("adaptive measurements must be nonnegative integers")
        if type(turns) is not tuple or any(
            type(item) is not AdaptiveTurnRecord for item in turns
        ):
            raise TypeError("adaptive turns must be an immutable exact tuple")
        if model_invocation_count != len(turns):
            raise ValueError("planner invocation count must match transcript turns")
        if acquisition_turn_count != sum(
            item.phase is AdaptivePlannerPhase.ACQUIRE_EVIDENCE for item in turns
        ):
            raise ValueError("acquisition turn count must match the transcript")
        if proposal_count != sum(len(item.proposals) for item in turns):
            raise ValueError("proposal count must match the transcript")
        if attempted_probe_count < probe_count_used:
            raise ValueError("controller probe use cannot exceed adaptive attempts")
        if any(
            value > proposal_count
            for value in (
                unsupported_proposal_count,
                invalid_proposal_count,
                duplicate_proposal_count,
            )
        ):
            raise ValueError("proposal findings cannot exceed proposal count")
        if any(
            value > attempted_probe_count
            for value in (unavailable_probe_count, redundant_probe_count)
        ):
            raise ValueError("probe findings cannot exceed adaptive attempts")
        if transcript_sha256 != _transcript_sha256(turns):
            raise ValueError("adaptive transcript digest does not match turns")
        if sufficient_probe_sequence is not None and not (
            1 <= sufficient_probe_sequence <= attempted_probe_count
        ):
            raise ValueError("sufficient probe sequence is outside adaptive attempts")
        sufficient = stop_reason is AdaptiveStopReason.SUFFICIENT_EVIDENCE
        if sufficient != (sufficient_probe_sequence is not None):
            raise ValueError("sufficiency reason and probe sequence must agree")
        if sufficient != (time_to_sufficient_evidence_ms is not None):
            raise ValueError("sufficiency reason and timing must agree")
        if (
            time_to_sufficient_evidence_ms is not None
            and time_to_sufficient_evidence_ms > total_elapsed_ms
        ):
            raise ValueError("sufficiency time cannot exceed total elapsed time")
        token_counts = (
            model_prompt_tokens,
            model_output_tokens,
            model_total_tokens,
        )
        if any(value is None for value in token_counts):
            if token_counts != (None, None, None):
                raise ValueError("adaptive token counts must be wholly measured")
        elif (
            any(type(value) is not int or value < 0 for value in token_counts)
            or model_total_tokens != model_prompt_tokens + model_output_tokens
        ):
            raise ValueError("adaptive token counts are inconsistent")
        if explanation_valid is not None and type(explanation_valid) is not bool:
            raise TypeError("explanation validity must be a boolean when present")
        if type(policies) is not tuple or len(policies) != 3:
            raise TypeError("adaptive result requires three policy versions")
        for value, label in zip(
            policies,
            ("authority", "classification", "action"),
            strict=True,
        ):
            _validate_identifier(value, f"{label} policy version")
        report_payload = canonical_json_bytes(report)
        validated_report = decode_contract(report_payload, InvestigationReport)
        if validated_report.classification is None:
            raise ValueError("a completed adaptive report requires a classification")

        reported_models = tuple(
            sorted(
                {
                    turn.metadata.reported_model
                    for turn in turns
                    if turn.metadata.reported_model is not None
                }
            )
        )
        object.__setattr__(self, "_report_bytes", report_payload)
        object.__setattr__(self, "policy_name", policy.name)
        object.__setattr__(self, "policy_version", policy.version)
        object.__setattr__(self, "policy_sha256", policy.sha256)
        object.__setattr__(
            self,
            "capability_catalog_version",
            _CAPABILITY_CATALOG_VERSION,
        )
        object.__setattr__(
            self,
            "capability_catalog_sha256",
            capability_catalog_sha256,
        )
        object.__setattr__(self, "stop_reason", stop_reason)
        for name, value in (
            ("acquisition_turn_count", acquisition_turn_count),
            ("model_invocation_count", model_invocation_count),
            ("proposal_count", proposal_count),
            ("attempted_probe_count", attempted_probe_count),
            ("probe_count_used", probe_count_used),
            ("cost_units_used", cost_units_used),
            ("result_bytes_acquired", result_bytes_acquired),
            ("total_elapsed_ms", total_elapsed_ms),
            ("unsupported_proposal_count", unsupported_proposal_count),
            ("invalid_proposal_count", invalid_proposal_count),
            ("duplicate_proposal_count", duplicate_proposal_count),
            ("unavailable_probe_count", unavailable_probe_count),
            ("redundant_probe_count", redundant_probe_count),
        ):
            object.__setattr__(self, name, value)
        object.__setattr__(self, "sufficient_probe_sequence", sufficient_probe_sequence)
        object.__setattr__(
            self,
            "time_to_sufficient_evidence_ms",
            time_to_sufficient_evidence_ms,
        )
        object.__setattr__(self, "provider_name", planner_metadata.provider_name)
        object.__setattr__(self, "configured_model", planner_metadata.configured_model)
        object.__setattr__(self, "reported_models", reported_models)
        object.__setattr__(self, "adk_version", planner_metadata.adk_version)
        object.__setattr__(self, "genai_version", planner_metadata.genai_version)
        object.__setattr__(self, "prompt_version", planner_metadata.prompt_version)
        object.__setattr__(self, "prompt_sha256", planner_metadata.prompt_sha256)
        object.__setattr__(
            self,
            "input_schema_version",
            planner_metadata.input_schema_version,
        )
        object.__setattr__(
            self,
            "output_schema_version",
            planner_metadata.output_schema_version,
        )
        object.__setattr__(self, "authority_policy_version", policies[0])
        object.__setattr__(self, "classification_policy_version", policies[1])
        object.__setattr__(self, "action_policy_version", policies[2])
        object.__setattr__(self, "model_prompt_tokens", model_prompt_tokens)
        object.__setattr__(self, "model_output_tokens", model_output_tokens)
        object.__setattr__(self, "model_total_tokens", model_total_tokens)
        object.__setattr__(self, "explanation_valid", explanation_valid)
        object.__setattr__(self, "transcript_sha256", transcript_sha256)
        object.__setattr__(self, "turns", tuple(turns))

    @property
    def report(self) -> InvestigationReport:
        """Return an isolated copy of the deterministic investigation report."""

        return decode_contract(self._report_bytes, InvestigationReport)

    @property
    def classification(self) -> Classification:
        classification = self.report.classification
        if classification is None:
            raise RuntimeError("a completed adaptive report lost its classification")
        return classification


class _SystemClock:
    def monotonic(self) -> float:
        return time.monotonic()

    def now(self) -> datetime:
        return datetime.now(UTC)


@dataclass(frozen=True, slots=True)
class _CatalogEntry:
    registration: CapabilityRegistration
    descriptor: PlannerCapability


@dataclass(frozen=True, slots=True)
class _ProposalSelection:
    request: ProbeRequest | None
    records: tuple[ProposalRecord, ...]


@dataclass(frozen=True, slots=True)
class _PlannerCall:
    turn: AdvisoryPlannerTurn | None
    failure: PlannerFailureKind | None
    cancelled: bool


_UNSUPPORTED_REASONS = frozenset(
    {
        ProbeStopReason.INVALID_REQUEST,
        ProbeStopReason.UNKNOWN_CAPABILITY,
        ProbeStopReason.CAPABILITY_DISABLED,
        ProbeStopReason.CAPABILITY_NOT_ENABLED,
        ProbeStopReason.CAPABILITY_MUTATING,
        ProbeStopReason.CAPABILITY_SEMANTICS_AMBIGUOUS,
        ProbeStopReason.TARGET_KIND_MISMATCH,
        ProbeStopReason.TARGET_SCOPE_MISMATCH,
        ProbeStopReason.INVALID_EFFECT_REFERENCE,
        ProbeStopReason.INVALID_ARGUMENTS,
        ProbeStopReason.ARGUMENTS_TOO_LARGE,
        ProbeStopReason.TARGET_PARAMETER_INJECTION,
        ProbeStopReason.CORRELATION_MISMATCH,
    }
)
_BUDGET_REASONS = frozenset(
    {
        ProbeStopReason.PROBE_COUNT_EXHAUSTED,
        ProbeStopReason.CAPABILITY_PROBE_LIMIT_EXHAUSTED,
        ProbeStopReason.COST_BUDGET_EXHAUSTED,
        ProbeStopReason.TOTAL_RESULT_BYTES_EXHAUSTED,
        ProbeStopReason.RESULT_TOO_LARGE,
    }
)
_DEADLINE_REASONS = frozenset(
    {
        ProbeStopReason.ELAPSED_BUDGET_EXHAUSTED,
        ProbeStopReason.PROBE_TIMEOUT,
    }
)
_TARGET_VALUE_PREFIXES = (
    "buckets/",
    "databases/",
    "documents/",
    "gs://",
    "http://",
    "https://",
    "projects/",
)
_URI_SCHEME = re.compile(r"^[a-z][a-z0-9+.-]*://", re.IGNORECASE)


def _is_strict_integer(_checker: object, instance: object) -> bool:
    return type(instance) is int


def _is_strict_number(_checker: object, instance: object) -> bool:
    return type(instance) in {int, float}


_STRICT_TYPE_CHECKER = Draft202012Validator.TYPE_CHECKER.redefine_many(
    {
        "integer": _is_strict_integer,
        "number": _is_strict_number,
    }
)
_StrictDraft202012Validator = validators.extend(
    Draft202012Validator,
    type_checker=_STRICT_TYPE_CHECKER,
)


def _contains_target_coordinate_value(value: object) -> bool:
    if isinstance(value, str):
        lowered = value.strip().lower()
        return lowered.startswith(_TARGET_VALUE_PREFIXES) or bool(
            _URI_SCHEME.match(lowered)
        )
    if isinstance(value, list):
        return any(_contains_target_coordinate_value(item) for item in value)
    if isinstance(value, dict):
        return any(_contains_target_coordinate_value(item) for item in value.values())
    return False


def _progress_sha256(evaluation: CoreEvaluation) -> str:
    proof = evaluation.proof
    material = {
        "classification": evaluation.classification.value,
        "conflicting_authority": proof.conflicting_authority,
        "effects": [
            {
                "commit_scope": finding.commit_scope,
                "effect_id": finding.effect_id,
                "state": finding.state.value,
            }
            for finding in proof.effect_findings
        ],
        "operation_status": (
            None if proof.operation_status is None else proof.operation_status.value
        ),
    }
    return hashlib.sha256(canonical_json_value_bytes(material)).hexdigest()


def _progress_state(
    classification: Classification | None,
    action_gates: tuple[ActionGateResult, ...],
    missing_evidence: tuple[MissingEvidence, ...],
) -> tuple[Classification, bool, bool, tuple[str, ...]]:
    if classification is None:
        raise RuntimeError("progress requires a deterministic classification")
    continuation = next(
        (
            gate
            for gate in action_gates
            if gate.requested_action is RequestedAction.CONTINUE
        ),
        None,
    )
    if continuation is None:
        raise RuntimeError("progress requires a deterministic continuation gate")
    missing_effect_ids = tuple(
        sorted(
            {effect_id for item in missing_evidence for effect_id in item.effect_ids}
        )
    )
    return (
        classification,
        continuation.allowed,
        continuation.escalation_required,
        missing_effect_ids,
    )


def _catalog(
    envelope: ExecutionEnvelope,
    registry: CapabilityRegistry,
) -> tuple[dict[tuple[str, str], _CatalogEntry], bool, str]:
    registrations = {item.identity: item for item in registry.freeze()}
    enabled = {
        (reference.name, reference.version)
        for reference in envelope.context.enabled_capabilities
    }
    target_scope = canonical_json_value_bytes(envelope.target.scope)
    entries: dict[tuple[str, str], _CatalogEntry] = {}
    for identity in sorted(enabled):
        registration = registrations.get(identity)
        if (
            registration is None
            or not registration.enabled
            or registration.semantics is not CapabilitySemantics.READ_ONLY
            or registration.handler is None
        ):
            continue
        capability = registration.capability
        target_allowed = any(
            constraint.target_kind == envelope.target.target_kind
            and canonical_json_value_bytes(constraint.scope) == target_scope
            for constraint in capability.allowed_targets
        )
        if not target_allowed:
            continue
        descriptor = PlannerCapability(
            name=capability.name,
            version=capability.version,
            description=f"Read-only observation capability {capability.name}.",
            read_only=True,
            argument_schema=capability.argument_schema,
            cost_units=capability.cost_units,
            remaining_invocations=min(
                registration.max_invocations,
                envelope.context.evidence_budget.max_probes,
            ),
        )
        entries[identity] = _CatalogEntry(
            registration=registration,
            descriptor=descriptor,
        )
    material = [
        json.loads(canonical_json_bytes(entries[key].descriptor))
        for key in sorted(entries)
    ]
    digest = hashlib.sha256(canonical_json_value_bytes(material)).hexdigest()
    return entries, set(entries) == enabled, digest


def _remaining_budget(
    envelope: ExecutionEnvelope,
    controller: ProbeController,
    clock: ControllerClock,
    started_monotonic: float,
) -> PlannerRemainingBudget:
    maximum = envelope.context.evidence_budget
    audit = controller.audit_trail
    final = audit[-1] if audit else None
    probes_used = final.probe_count_used if final is not None else 0
    cost_used = final.cost_units_used if final is not None else 0
    result_bytes = final.result_bytes_acquired if final is not None else 0
    elapsed_ms = min(
        max(0, int((clock.monotonic() - started_monotonic) * 1_000)),
        2**63 - 1,
    )
    remaining_elapsed = max(0, maximum.max_elapsed_ms - elapsed_ms)
    deadline_at = clock.now() + timedelta(milliseconds=remaining_elapsed)
    deadline_at = max(deadline_at, envelope.invoked_at)
    return PlannerRemainingBudget(
        probes=max(0, maximum.max_probes - probes_used),
        elapsed_ms=remaining_elapsed,
        result_bytes=max(0, maximum.max_total_result_bytes - result_bytes),
        cost_units=max(0, maximum.max_cost_units - cost_used),
        deadline_at=deadline_at,
    )


def _turn_capabilities(
    catalog: Mapping[tuple[str, str], _CatalogEntry],
    selected_counts: Mapping[tuple[str, str], int],
) -> tuple[PlannerCapability, ...]:
    descriptors: list[PlannerCapability] = []
    for identity in sorted(catalog):
        entry = catalog[identity]
        descriptor = entry.descriptor
        descriptors.append(
            PlannerCapability(
                name=descriptor.name,
                version=descriptor.version,
                description=descriptor.description,
                read_only=True,
                argument_schema=descriptor.argument_schema,
                cost_units=descriptor.cost_units,
                remaining_invocations=max(
                    0,
                    descriptor.remaining_invocations - selected_counts.get(identity, 0),
                ),
            )
        )
    return tuple(descriptors)


def _evidence_summaries(
    evaluation: CoreEvaluation,
    request_by_sequence: Mapping[int, ProbeRequest],
    catalog: Mapping[tuple[str, str], _CatalogEntry],
    expected_effect_ids: tuple[str, ...],
) -> tuple[
    tuple[PlannerAdmittedEvidence, ...],
    tuple[PlannerWeakEvidence, ...],
    tuple[PlannerRejectedEvidence, ...],
    tuple[PlannerMissingEvidence, ...],
]:
    admitted: list[PlannerAdmittedEvidence] = []
    weak: list[PlannerWeakEvidence] = []
    rejected: list[PlannerRejectedEvidence] = []
    for attempt in evaluation.attempts:
        decision = attempt.decision
        evidence = attempt.evidence
        request = request_by_sequence.get(attempt.probe_sequence)
        if decision.disposition is EvidenceDisposition.ADMITTED:
            if evidence is None:
                raise RuntimeError("admitted evidence lost its normalized summary")
            admitted.append(
                PlannerAdmittedEvidence(
                    evidence_id=decision.evidence_id,
                    capability_name=evidence.capability_name,
                    capability_version=evidence.capability_version,
                    reason=decision.reason,
                    effect_assertions=evidence.effect_assertions,
                    operation_status=evidence.operation_status,
                )
            )
            continue
        if decision.disposition is EvidenceDisposition.WEAK:
            if evidence is None:
                raise RuntimeError("weak evidence lost its normalized summary")
            relevant_effect_ids = tuple(
                assertion.effect_id for assertion in evidence.effect_assertions
            )
            if not relevant_effect_ids and request is not None:
                relevant_effect_ids = request.relevant_effect_ids
            weak.append(
                PlannerWeakEvidence(
                    evidence_id=decision.evidence_id,
                    capability_name=evidence.capability_name,
                    capability_version=evidence.capability_version,
                    reason=decision.reason,
                    relevant_effect_ids=relevant_effect_ids,
                )
            )
            continue

        capability_name: str | None = None
        capability_version: str | None = None
        if (
            request is not None
            and (
                request.capability_name,
                request.capability_version,
            )
            in catalog
        ):
            capability_name = request.capability_name
            capability_version = request.capability_version
        relevant_effect_ids = (
            request.relevant_effect_ids if request is not None else expected_effect_ids
        )
        rejected.append(
            PlannerRejectedEvidence(
                evidence_id=decision.evidence_id,
                capability_name=capability_name,
                capability_version=capability_version,
                reason=decision.reason,
                relevant_effect_ids=relevant_effect_ids,
            )
        )

    missing_by_effect: dict[str, str] = {}
    for item in evaluation.missing_evidence:
        for effect_id in item.effect_ids:
            current = missing_by_effect.get(effect_id)
            if current is None or item.reason < current:
                missing_by_effect[effect_id] = item.reason
    missing = tuple(
        PlannerMissingEvidence(effect_id=effect_id, reason=missing_by_effect[effect_id])
        for effect_id in sorted(missing_by_effect)
    )
    return (
        tuple(sorted(admitted, key=lambda item: item.evidence_id)),
        tuple(sorted(weak, key=lambda item: item.evidence_id)),
        tuple(sorted(rejected, key=lambda item: item.evidence_id)),
        missing,
    )


def _planner_input(
    *,
    phase: AdaptivePlannerPhase,
    envelope: ExecutionEnvelope,
    catalog: Mapping[tuple[str, str], _CatalogEntry],
    selected_counts: Mapping[tuple[str, str], int],
    evaluation: CoreEvaluation,
    request_by_sequence: Mapping[int, ProbeRequest],
    prior_request_hashes: tuple[str, ...],
    remaining_budget: PlannerRemainingBudget,
    metadata: AdvisoryPlannerMetadata,
) -> AdaptivePlannerInput:
    expected_effect_ids = tuple(
        sorted(effect.effect_id for effect in envelope.expected_effects)
    )
    admitted, weak, rejected, missing = _evidence_summaries(
        evaluation,
        request_by_sequence,
        catalog,
        expected_effect_ids,
    )
    policies = envelope.context.policies
    return AdaptivePlannerInput(
        schema_version=ADAPTIVE_PLANNER_INPUT_VERSION,
        phase=phase,
        envelope=envelope,
        capabilities=_turn_capabilities(catalog, selected_counts),
        admitted_evidence=admitted,
        weak_evidence=weak,
        rejected_evidence=rejected,
        missing_evidence=missing,
        prior_executable_request_hashes=prior_request_hashes,
        remaining_budget=remaining_budget,
        versions=PlannerVersionMetadata(
            provider_name=metadata.provider_name,
            model_name=metadata.configured_model,
            adk_version=metadata.adk_version,
            genai_version=metadata.genai_version,
            prompt_version=metadata.prompt_version,
            capability_catalog_version=_CAPABILITY_CATALOG_VERSION,
            authority_policy_version=policies.authority,
            classification_policy_version=policies.classification,
            action_policy_version=policies.action,
            input_schema_version=ADAPTIVE_PLANNER_INPUT_VERSION,
            output_schema_version=ADAPTIVE_PLANNER_OUTPUT_VERSION,
        ),
    )


def _proposal_disposition(
    request: ProbeRequest,
    *,
    catalog: Mapping[tuple[str, str], _CatalogEntry],
    remaining: PlannerRemainingBudget,
    selected_counts: Mapping[tuple[str, str], int],
    expected_effect_ids: frozenset[str],
    correlation_fields: Mapping[str, str],
) -> ProposalDisposition | None:
    identity = (request.capability_name, request.capability_version)
    entry = catalog.get(identity)
    if entry is None:
        return ProposalDisposition.UNSUPPORTED_CAPABILITY
    if not set(request.relevant_effect_ids) <= expected_effect_ids:
        return ProposalDisposition.INVALID_EFFECT_REFERENCE
    descriptor = entry.descriptor
    if (
        selected_counts.get(identity, 0) >= descriptor.remaining_invocations
        or remaining.probes == 0
    ):
        return ProposalDisposition.UNAVAILABLE
    if descriptor.cost_units > remaining.cost_units or remaining.result_bytes == 0:
        return ProposalDisposition.BUDGET_EXCEEDED
    try:
        arguments_payload = canonical_json_value_bytes(request.arguments)
    except (TypeError, ValueError):
        return ProposalDisposition.INVALID_ARGUMENTS
    if len(arguments_payload) > entry.registration.argument_byte_ceiling:
        return ProposalDisposition.INVALID_ARGUMENTS
    validator = _StrictDraft202012Validator(descriptor.argument_schema)
    if not validator.is_valid(request.arguments):
        return ProposalDisposition.INVALID_ARGUMENTS
    if _contains_target_coordinate_value(request.arguments):
        return ProposalDisposition.INVALID_ARGUMENTS
    for key, expected in correlation_fields.items():
        if key in request.arguments and canonical_json_value_bytes(
            request.arguments[key]
        ) != canonical_json_value_bytes(expected):
            return ProposalDisposition.INVALID_ARGUMENTS
    return None


def _select_proposal(
    proposals: tuple[ProbeRequest, ...],
    *,
    catalog: Mapping[tuple[str, str], _CatalogEntry],
    remaining: PlannerRemainingBudget,
    selected_counts: Mapping[tuple[str, str], int],
    expected_effect_ids: frozenset[str],
    correlation_fields: Mapping[str, str],
    prior_request_hashes: frozenset[str],
) -> _ProposalSelection:
    if not proposals:
        return _ProposalSelection(request=None, records=())

    request_hashes = tuple(probe_request_sha256(request) for request in proposals)
    representatives: dict[str, int] = {}
    for index, (request, request_sha256) in enumerate(
        zip(proposals, request_hashes, strict=True)
    ):
        if request_sha256 in prior_request_hashes:
            continue
        current = representatives.get(request_sha256)
        if current is None or canonical_json_bytes(request) < canonical_json_bytes(
            proposals[current]
        ):
            representatives[request_sha256] = index

    dispositions: list[ProposalDisposition | None] = [None] * len(proposals)
    valid: list[tuple[int, str, int, str, str]] = []
    for index, request in enumerate(proposals):
        request_sha256 = request_hashes[index]
        if (
            request_sha256 in prior_request_hashes
            or representatives.get(request_sha256) != index
        ):
            dispositions[index] = ProposalDisposition.DUPLICATE
            continue
        disposition = _proposal_disposition(
            request,
            catalog=catalog,
            remaining=remaining,
            selected_counts=selected_counts,
            expected_effect_ids=expected_effect_ids,
            correlation_fields=correlation_fields,
        )
        if disposition is not None:
            dispositions[index] = disposition
            continue
        entry = catalog[(request.capability_name, request.capability_version)]
        valid.append(
            (
                entry.descriptor.cost_units,
                request.capability_name,
                request.capability_version,
                request_sha256,
                index,
            )
        )

    selected_index: int | None = None
    if valid:
        selected_index = min(valid)[-1]
    records: list[ProposalRecord] = []
    for index, request in enumerate(proposals):
        disposition = dispositions[index]
        if disposition is None:
            disposition = (
                ProposalDisposition.SELECTED
                if index == selected_index
                else ProposalDisposition.DEFERRED
            )
        records.append(
            ProposalRecord(
                proposal_sequence=index + 1,
                capability_name=request.capability_name,
                capability_version=request.capability_version,
                request_sha256=request_hashes[index],
                disposition=disposition,
            )
        )
    selected_request = proposals[selected_index] if selected_index is not None else None
    return _ProposalSelection(request=selected_request, records=tuple(records))


def _metadata_matches(
    configured: AdvisoryPlannerMetadata,
    returned: AdvisoryPlannerMetadata,
) -> bool:
    return (
        configured.provider_name == returned.provider_name
        and configured.configured_model == returned.configured_model
        and configured.adk_version == returned.adk_version
        and configured.genai_version == returned.genai_version
        and configured.prompt_version == returned.prompt_version
        and configured.prompt_sha256 == returned.prompt_sha256
        and configured.input_schema_version == returned.input_schema_version
        and configured.output_schema_version == returned.output_schema_version
    )


async def _call_planner(
    planner: AdvisoryPlanner,
    planner_input: AdaptivePlannerInput,
    *,
    timeout_ms: int,
    cancellation_event: asyncio.Event | None,
) -> _PlannerCall:
    task = asyncio.create_task(planner.plan(planner_input))
    cancellation_task = (
        asyncio.create_task(cancellation_event.wait())
        if cancellation_event is not None
        else None
    )
    waiters: set[asyncio.Task[object]] = {task}  # type: ignore[arg-type]
    if cancellation_task is not None:
        waiters.add(cancellation_task)  # type: ignore[arg-type]
    try:
        done, _ = await asyncio.wait(
            waiters,
            timeout=timeout_ms / 1_000,
            return_when=asyncio.FIRST_COMPLETED,
        )
        if (
            cancellation_task is not None
            and cancellation_task in done
            and cancellation_event is not None
            and cancellation_event.is_set()
        ):
            task.cancel()
            await asyncio.gather(task, return_exceptions=True)
            return _PlannerCall(turn=None, failure=None, cancelled=True)
        if task not in done:
            task.cancel()
            await asyncio.gather(task, return_exceptions=True)
            return _PlannerCall(
                turn=None,
                failure=PlannerFailureKind.TIMEOUT,
                cancelled=False,
            )
        try:
            result = await task
        except TimeoutError:
            return _PlannerCall(
                turn=None,
                failure=PlannerFailureKind.TIMEOUT,
                cancelled=False,
            )
        except asyncio.CancelledError:
            raise
        except Exception:
            return _PlannerCall(
                turn=None,
                failure=PlannerFailureKind.UNAVAILABLE,
                cancelled=False,
            )
        if type(result) is not AdvisoryPlannerTurn:
            return _PlannerCall(
                turn=None,
                failure=PlannerFailureKind.SCHEMA_INVALID,
                cancelled=False,
            )
        return _PlannerCall(turn=result, failure=None, cancelled=False)
    except asyncio.CancelledError:
        task.cancel()
        if cancellation_task is not None:
            cancellation_task.cancel()
        await asyncio.gather(
            task,
            *(() if cancellation_task is None else (cancellation_task,)),
            return_exceptions=True,
        )
        raise
    finally:
        if cancellation_task is not None and not cancellation_task.done():
            cancellation_task.cancel()
            await asyncio.gather(cancellation_task, return_exceptions=True)


async def _execute_with_cancellation(
    controller: ProbeController,
    request: ProbeRequest,
    cancellation_event: asyncio.Event | None,
):
    if cancellation_event is None:
        return await controller.execute(request)
    if cancellation_event.is_set():
        controller.cancel()
        return await controller.execute(request)

    execution_task = asyncio.create_task(controller.execute(request))
    cancellation_task = asyncio.create_task(cancellation_event.wait())
    try:
        done, _ = await asyncio.wait(
            {execution_task, cancellation_task},
            return_when=asyncio.FIRST_COMPLETED,
        )
        if cancellation_task in done and cancellation_event.is_set():
            controller.cancel()
        return await execution_task
    finally:
        if not cancellation_task.done():
            cancellation_task.cancel()
        if not execution_task.done():
            execution_task.cancel()
        await asyncio.gather(
            execution_task,
            cancellation_task,
            return_exceptions=True,
        )


def _turn_material(turn: AdaptiveTurnRecord) -> dict[str, object]:
    metadata = turn.metadata
    usage = turn.usage
    return {
        "cancelled": turn.cancelled,
        "failure": None if turn.failure is None else turn.failure.value,
        "input_sha256": turn.input_sha256,
        "metadata": {
            "adk_version": metadata.adk_version,
            "configured_model": metadata.configured_model,
            "genai_version": metadata.genai_version,
            "input_schema_version": metadata.input_schema_version,
            "output_schema_version": metadata.output_schema_version,
            "prompt_sha256": metadata.prompt_sha256,
            "prompt_version": metadata.prompt_version,
            "provider_name": metadata.provider_name,
            "reported_model": metadata.reported_model,
        },
        "output_sha256": turn.output_sha256,
        "phase": turn.phase.value,
        "planner_recommended_stop": turn.planner_recommended_stop,
        "proposals": [
            {
                "capability_name": proposal.capability_name,
                "capability_version": proposal.capability_version,
                "disposition": proposal.disposition.value,
                "proposal_sequence": proposal.proposal_sequence,
                "request_sha256": proposal.request_sha256,
            }
            for proposal in turn.proposals
        ],
        "selected_request_sha256": turn.selected_request_sha256,
        "turn_sequence": turn.turn_sequence,
        "usage": (
            None
            if usage is None
            else {
                "output_tokens": usage.output_tokens,
                "prompt_tokens": usage.prompt_tokens,
                "total_tokens": usage.total_tokens,
            }
        ),
    }


def _transcript_sha256(turns: tuple[AdaptiveTurnRecord, ...]) -> str:
    return hashlib.sha256(
        canonical_json_value_bytes([_turn_material(turn) for turn in turns])
    ).hexdigest()


def _advisory_explanation(
    output: AdaptivePlannerOutput,
    planner_input: AdaptivePlannerInput,
) -> tuple[AdvisoryExplanation | None, bool]:
    explanation = output.explanation
    citations = explanation.citations
    admitted = {item.evidence_id for item in planner_input.admitted_evidence}
    weak = {item.evidence_id for item in planner_input.weak_evidence}
    rejected = {item.evidence_id for item in planner_input.rejected_evidence}
    missing = {item.effect_id for item in planner_input.missing_evidence}
    valid = (
        set(citations.admitted_evidence_ids) <= admitted
        and set(citations.weak_evidence_ids) <= weak
        and set(citations.rejected_evidence_ids) <= rejected
        and set(citations.missing_effect_ids) <= missing
        and bool(citations.admitted_evidence_ids)
        is (explanation.admitted_evidence is not None)
        and bool(citations.weak_evidence_ids) is (explanation.weak_evidence is not None)
        and bool(citations.rejected_evidence_ids)
        is (explanation.rejected_evidence is not None)
        and bool(citations.missing_effect_ids)
        is (explanation.missing_evidence is not None)
    )
    retained_citations = (
        *citations.admitted_evidence_ids,
        *citations.weak_evidence_ids,
    )
    if not valid or not retained_citations:
        return None, False
    sections = [explanation.summary]
    for label, text in (
        ("Admitted evidence", explanation.admitted_evidence),
        ("Weak evidence", explanation.weak_evidence),
        ("Rejected evidence", explanation.rejected_evidence),
        ("Missing evidence", explanation.missing_evidence),
    ):
        if text is not None:
            sections.append(f"{label}: {text}")
    return (
        AdvisoryExplanation(
            text="\n".join(sections),
            cited_evidence_ids=tuple(retained_citations),
        ),
        True,
    )


def _failure_stop_reason(failure: PlannerFailureKind) -> AdaptiveStopReason:
    return {
        PlannerFailureKind.UNAVAILABLE: AdaptiveStopReason.PLANNER_UNAVAILABLE,
        PlannerFailureKind.TIMEOUT: AdaptiveStopReason.PLANNER_TIMEOUT,
        PlannerFailureKind.SCHEMA_INVALID: AdaptiveStopReason.PLANNER_SCHEMA_INVALID,
    }[failure]


def _failure_turn_record(
    *,
    sequence: int,
    phase: AdaptivePlannerPhase,
    input_sha256: str,
    metadata: AdvisoryPlannerMetadata,
    failure: PlannerFailureKind | None,
    cancelled: bool,
    output_sha256: str | None = None,
    usage: AdvisoryPlannerUsage | None = None,
) -> AdaptiveTurnRecord:
    return AdaptiveTurnRecord(
        turn_sequence=sequence,
        phase=phase,
        input_sha256=input_sha256,
        output_sha256=output_sha256,
        failure=failure,
        cancelled=cancelled,
        metadata=metadata,
        usage=usage,
        proposals=(),
        selected_request_sha256=None,
        planner_recommended_stop=None,
    )


def _validated_turn(
    call: _PlannerCall,
    *,
    configured_metadata: AdvisoryPlannerMetadata,
    input_sha256: str,
) -> tuple[AdvisoryPlannerTurn | None, PlannerFailureKind | None, bool]:
    if call.cancelled:
        return None, None, True
    if call.failure is not None:
        return None, call.failure, False
    turn = call.turn
    if (
        turn is None
        or turn.input_sha256 != input_sha256
        or not _metadata_matches(configured_metadata, turn.metadata)
    ):
        return None, PlannerFailureKind.SCHEMA_INVALID, False
    return turn, turn.failure, False


def _emit_advisory_requested(
    progress_emitter: ProgressEmitter | None,
    *,
    occurred_at: datetime,
    investigation_id: str,
    phase: AdaptivePlannerPhase,
    turn_sequence: int,
    input_sha256: str,
) -> None:
    if progress_emitter is None:
        return
    progress_emitter(
        AdvisoryProgress(
            occurred_at=occurred_at,
            investigation_id=investigation_id,
            strategy=ComparisonStrategyKind.ADAPTIVE,
            stage=AdvisoryProgressStage.REQUESTED,
            phase=phase,
            turn_sequence=turn_sequence,
            input_sha256=input_sha256,
        )
    )


def _emit_advisory_completed(
    progress_emitter: ProgressEmitter | None,
    *,
    occurred_at: datetime,
    investigation_id: str,
    turn: AdaptiveTurnRecord,
    proposal_requests: tuple[ProbeRequest, ...] = (),
) -> None:
    if progress_emitter is None:
        return
    if len(proposal_requests) != len(turn.proposals):
        raise RuntimeError("advisory progress lost its sanitized proposals")
    proposals = tuple(
        AdvisoryProposalProgress(
            proposal_sequence=record.proposal_sequence,
            capability_name=record.capability_name,
            capability_version=record.capability_version,
            request_sha256=record.request_sha256,
            relevant_effect_ids=request.relevant_effect_ids,
            disposition=ProgressProposalDisposition(record.disposition.value),
        )
        for record, request in zip(turn.proposals, proposal_requests, strict=True)
    )
    progress_emitter(
        AdvisoryProgress(
            occurred_at=occurred_at,
            investigation_id=investigation_id,
            strategy=ComparisonStrategyKind.ADAPTIVE,
            stage=AdvisoryProgressStage.COMPLETED,
            phase=turn.phase,
            turn_sequence=turn.turn_sequence,
            input_sha256=turn.input_sha256,
            output_sha256=turn.output_sha256,
            failure=(
                None
                if turn.failure is None
                else ProgressPlannerFailure(turn.failure.value)
            ),
            cancelled=turn.cancelled,
            proposals=proposals,
            selected_request_sha256=turn.selected_request_sha256,
            planner_recommended_stop=turn.planner_recommended_stop,
        )
    )


async def execute_adaptive_investigation(
    envelope: ExecutionEnvelope,
    capabilities: CapabilityRegistry,
    rules: TargetRuleRegistry,
    planner: AdvisoryPlanner,
    policy: AdaptiveInvestigationPolicy,
    *,
    clock: ControllerClock | None = None,
    revision: int = 1,
    cancellation_event: asyncio.Event | None = None,
    additional_limitations: tuple[str, ...] = (),
    progress_emitter: ProgressEmitter | None = None,
) -> AdaptiveInvestigationResult:
    """Run bounded advisory acquisition through deterministic safety boundaries."""

    if type(envelope) is not ExecutionEnvelope:
        raise TypeError("adaptive execution requires an exact execution envelope")
    if type(capabilities) is not CapabilityRegistry:
        raise TypeError("adaptive execution requires an exact capability registry")
    if type(rules) is not TargetRuleRegistry:
        raise TypeError("adaptive execution requires an exact target-rule registry")
    if type(policy) is not AdaptiveInvestigationPolicy:
        raise TypeError("adaptive execution requires an exact adaptive policy")
    try:
        configured_metadata = planner.metadata
        plan_method = planner.plan
    except Exception:
        raise TypeError(
            "adaptive planner does not satisfy the strict protocol"
        ) from None
    if type(configured_metadata) is not AdvisoryPlannerMetadata or not callable(
        plan_method
    ):
        raise TypeError("adaptive planner does not satisfy the strict protocol")
    if type(revision) is not int or revision < 0:
        raise ValueError("report revision must be a nonnegative integer")
    if cancellation_event is not None and type(cancellation_event) is not asyncio.Event:
        raise TypeError("cancellation event must be an exact asyncio event")
    if progress_emitter is not None and not callable(progress_emitter):
        raise TypeError("progress emitter must be callable")
    if type(additional_limitations) is not tuple or len(additional_limitations) > 63:
        raise ValueError("additional limitations must be a bounded immutable tuple")
    for limitation in additional_limitations:
        if type(limitation) is not str or not 1 <= len(limitation) <= 4_096:
            raise ValueError("each additional limitation must be bounded and nonempty")
        try:
            limitation.encode("utf-8")
        except UnicodeEncodeError as error:
            raise ValueError(
                "additional limitations must contain Unicode scalar values"
            ) from error

    sealed_envelope = decode_contract(canonical_json_bytes(envelope), ExecutionEnvelope)
    selected_clock = clock or _SystemClock()
    started_monotonic = selected_clock.monotonic()
    catalog, catalog_safe, catalog_sha256 = _catalog(
        sealed_envelope,
        capabilities,
    )
    controller = ProbeController(
        sealed_envelope,
        capabilities,
        clock=selected_clock,
    )
    engine = EvidenceEngine(sealed_envelope, rules)
    evaluation = engine.evaluate(())
    expected_effect_ids = frozenset(
        effect.effect_id for effect in sealed_envelope.expected_effects
    )
    required_identities = {
        (item.name, item.version) for item in policy.required_capabilities
    }

    stop_reason: AdaptiveStopReason | None = None
    sufficient_sequence: int | None = None
    sufficient_elapsed_ms: int | None = None
    turns: list[AdaptiveTurnRecord] = []
    request_by_sequence: dict[int, ProbeRequest] = {}
    prior_request_hashes: list[str] = []
    selected_counts: dict[tuple[str, str], int] = {}
    processed_sequences: set[int] = set()
    unavailable_sequences: set[int] = set()
    redundant_sequences: set[int] = set()
    unchanged_progress_count = 0
    explanation: AdvisoryExplanation | None = None
    explanation_valid: bool | None = None
    planner_failed = False
    if progress_emitter is not None:
        progress_emitter(
            StrategyProgress(
                occurred_at=_progress_occurred_at(),
                investigation_id=sealed_envelope.investigation_id,
                strategy=ComparisonStrategyKind.ADAPTIVE,
                stage=StrategyProgressStage.STARTED,
            )
        )

    if cancellation_event is not None and cancellation_event.is_set():
        controller.cancel()
        stop_reason = AdaptiveStopReason.CANCELLED
    elif not required_identities <= set(catalog):
        stop_reason = AdaptiveStopReason.REQUIRED_CAPABILITY_UNAVAILABLE
    elif not catalog_safe:
        stop_reason = AdaptiveStopReason.CAPABILITY_CATALOG_UNSAFE

    for _ in range(policy.max_turns):
        if stop_reason is not None:
            break
        if evaluation.classification in policy.sufficient_classifications:
            stop_reason = AdaptiveStopReason.SUFFICIENT_EVIDENCE
            break
        if cancellation_event is not None and cancellation_event.is_set():
            controller.cancel()
            stop_reason = AdaptiveStopReason.CANCELLED
            break
        remaining = _remaining_budget(
            sealed_envelope,
            controller,
            selected_clock,
            started_monotonic,
        )
        if remaining.elapsed_ms == 0:
            stop_reason = AdaptiveStopReason.DEADLINE_EXHAUSTED
            break
        if (
            remaining.probes == 0
            or remaining.cost_units == 0
            or remaining.result_bytes == 0
        ):
            stop_reason = AdaptiveStopReason.BUDGET_EXHAUSTED
            break
        if any(
            selected_counts.get(identity, 0)
            >= catalog[identity].descriptor.remaining_invocations
            for identity in required_identities
        ):
            stop_reason = AdaptiveStopReason.REQUIRED_CAPABILITY_UNAVAILABLE
            break

        try:
            planner_input = _planner_input(
                phase=AdaptivePlannerPhase.ACQUIRE_EVIDENCE,
                envelope=sealed_envelope,
                catalog=catalog,
                selected_counts=selected_counts,
                evaluation=evaluation,
                request_by_sequence=request_by_sequence,
                prior_request_hashes=tuple(prior_request_hashes),
                remaining_budget=remaining,
                metadata=configured_metadata,
            )
        except (TypeError, ValueError):
            stop_reason = AdaptiveStopReason.PLANNER_SCHEMA_INVALID
            planner_failed = True
            break
        input_sha256 = hashlib.sha256(canonical_json_bytes(planner_input)).hexdigest()
        sequence = len(turns) + 1
        _emit_advisory_requested(
            progress_emitter,
            occurred_at=_progress_occurred_at(),
            investigation_id=sealed_envelope.investigation_id,
            phase=AdaptivePlannerPhase.ACQUIRE_EVIDENCE,
            turn_sequence=sequence,
            input_sha256=input_sha256,
        )
        call = await _call_planner(
            planner,
            planner_input,
            timeout_ms=min(policy.planner_timeout_ms, remaining.elapsed_ms),
            cancellation_event=cancellation_event,
        )
        turn, failure, cancelled = _validated_turn(
            call,
            configured_metadata=configured_metadata,
            input_sha256=input_sha256,
        )
        if cancelled:
            controller.cancel()
            record = _failure_turn_record(
                sequence=sequence,
                phase=AdaptivePlannerPhase.ACQUIRE_EVIDENCE,
                input_sha256=input_sha256,
                metadata=configured_metadata,
                failure=None,
                cancelled=True,
            )
            turns.append(record)
            _emit_advisory_completed(
                progress_emitter,
                occurred_at=_progress_occurred_at(),
                investigation_id=sealed_envelope.investigation_id,
                turn=record,
            )
            stop_reason = AdaptiveStopReason.CANCELLED
            break
        if failure is not None:
            returned = call.turn
            metadata = (
                returned.metadata
                if returned is not None
                and _metadata_matches(configured_metadata, returned.metadata)
                else configured_metadata
            )
            record = _failure_turn_record(
                sequence=sequence,
                phase=AdaptivePlannerPhase.ACQUIRE_EVIDENCE,
                input_sha256=input_sha256,
                metadata=metadata,
                failure=failure,
                cancelled=False,
                output_sha256=(
                    returned.output_sha256 if returned is not None else None
                ),
                usage=returned.usage if returned is not None else None,
            )
            turns.append(record)
            _emit_advisory_completed(
                progress_emitter,
                occurred_at=_progress_occurred_at(),
                investigation_id=sealed_envelope.investigation_id,
                turn=record,
            )
            stop_reason = _failure_stop_reason(failure)
            planner_failed = True
            break
        if turn is None or turn.output is None:
            raise RuntimeError("validated planner success lost its output")
        output = turn.output
        selection = _select_proposal(
            output.probe_proposals,
            catalog=catalog,
            remaining=remaining,
            selected_counts=selected_counts,
            expected_effect_ids=expected_effect_ids,
            correlation_fields=sealed_envelope.context.correlation_fields,
            prior_request_hashes=frozenset(prior_request_hashes),
        )
        selected_request_sha256 = (
            None
            if selection.request is None
            else probe_request_sha256(selection.request)
        )
        record = AdaptiveTurnRecord(
            turn_sequence=sequence,
            phase=AdaptivePlannerPhase.ACQUIRE_EVIDENCE,
            input_sha256=input_sha256,
            output_sha256=turn.output_sha256,
            failure=None,
            cancelled=False,
            metadata=turn.metadata,
            usage=turn.usage,
            proposals=selection.records,
            selected_request_sha256=selected_request_sha256,
            planner_recommended_stop=output.stop_advice.recommend_stop,
        )
        turns.append(record)
        _emit_advisory_completed(
            progress_emitter,
            occurred_at=_progress_occurred_at(),
            investigation_id=sealed_envelope.investigation_id,
            turn=record,
            proposal_requests=output.probe_proposals,
        )
        if selection.request is None:
            stop_reason = (
                AdaptiveStopReason.NON_PROGRESS
                if selection.records
                and all(
                    item.disposition is ProposalDisposition.DUPLICATE
                    for item in selection.records
                )
                else AdaptiveStopReason.NO_VALID_PROPOSAL
            )
            break

        request = selection.request
        request_sha256 = probe_request_sha256(request)
        attempt_sequence = len(prior_request_hashes) + 1
        identity = (request.capability_name, request.capability_version)
        prior_request_hashes.append(request_sha256)
        selected_counts[identity] = selected_counts.get(identity, 0) + 1
        previous_progress = _progress_sha256(evaluation)
        if progress_emitter is not None:
            progress_emitter(
                ProbeProgress(
                    occurred_at=_progress_occurred_at(),
                    investigation_id=sealed_envelope.investigation_id,
                    strategy=ComparisonStrategyKind.ADAPTIVE,
                    stage=ProbeProgressStage.REQUESTED,
                    attempt_sequence=attempt_sequence,
                    capability_name=request.capability_name,
                    capability_version=request.capability_version,
                    request_sha256=request_sha256,
                    relevant_effect_ids=request.relevant_effect_ids,
                )
            )
        execution = await _execute_with_cancellation(
            controller,
            request,
            cancellation_event,
        )
        audit = execution.audit
        reused_sequence = audit.sequence in processed_sequences
        if reused_sequence:
            if progress_emitter is not None:
                previous_attempt = next(
                    (
                        item
                        for item in engine.attempts
                        if item.probe_sequence == audit.sequence
                    ),
                    None,
                )
                if previous_attempt is None:
                    raise RuntimeError("reused controller progress lost its evidence")
                progress_emitter(
                    ProbeProgress(
                        occurred_at=_progress_occurred_at(),
                        investigation_id=sealed_envelope.investigation_id,
                        strategy=ComparisonStrategyKind.ADAPTIVE,
                        stage=ProbeProgressStage.COMPLETED,
                        attempt_sequence=attempt_sequence,
                        capability_name=audit.capability_name,
                        capability_version=audit.capability_version,
                        request_sha256=audit.request_sha256,
                        relevant_effect_ids=request.relevant_effect_ids,
                        controller_sequence=audit.sequence,
                        controller_sequence_reused=True,
                        outcome=audit.outcome,
                        controller_stop_reason=audit.stop_reason,
                        session_elapsed_ms=audit.session_elapsed_ms,
                        probe_count_used=audit.probe_count_used,
                        cost_units_used=audit.cost_units_used,
                        result_bytes_acquired=audit.result_bytes_acquired,
                        result_sha256=audit.result_sha256,
                        result_byte_count=(
                            audit.result_byte_count
                            if audit.outcome is ProbeOutcome.COMPLETED
                            else None
                        ),
                        evidence_ids=(previous_attempt.decision.evidence_id,),
                    )
                )
            redundant_sequences.add(audit.sequence)
            stop_reason = AdaptiveStopReason.NON_PROGRESS
            break
        processed_sequences.add(audit.sequence)
        request_by_sequence[audit.sequence] = request
        engine.process(ProbeRun(request=request, execution=execution))
        evaluation = engine.evaluate(controller.audit_trail)
        decision = evaluation.attempts[-1].decision
        if progress_emitter is not None:
            progress_emitter(
                ProbeProgress(
                    occurred_at=_progress_occurred_at(),
                    investigation_id=sealed_envelope.investigation_id,
                    strategy=ComparisonStrategyKind.ADAPTIVE,
                    stage=ProbeProgressStage.COMPLETED,
                    attempt_sequence=attempt_sequence,
                    capability_name=audit.capability_name,
                    capability_version=audit.capability_version,
                    request_sha256=audit.request_sha256,
                    relevant_effect_ids=request.relevant_effect_ids,
                    controller_sequence=audit.sequence,
                    controller_sequence_reused=False,
                    outcome=audit.outcome,
                    controller_stop_reason=audit.stop_reason,
                    session_elapsed_ms=audit.session_elapsed_ms,
                    probe_count_used=audit.probe_count_used,
                    cost_units_used=audit.cost_units_used,
                    result_bytes_acquired=audit.result_bytes_acquired,
                    result_sha256=audit.result_sha256,
                    result_byte_count=(
                        audit.result_byte_count
                        if audit.outcome is ProbeOutcome.COMPLETED
                        else None
                    ),
                    evidence_ids=(decision.evidence_id,),
                )
            )
            (
                classification,
                continue_allowed,
                escalation_required,
                missing_effect_ids,
            ) = _progress_state(
                evaluation.classification,
                evaluation.action_gates,
                evaluation.missing_evidence,
            )
            progress_emitter(
                EvidenceProgress(
                    occurred_at=_progress_occurred_at(),
                    investigation_id=sealed_envelope.investigation_id,
                    strategy=ComparisonStrategyKind.ADAPTIVE,
                    attempt_sequence=attempt_sequence,
                    controller_sequence=audit.sequence,
                    evidence_id=decision.evidence_id,
                    disposition=decision.disposition,
                    reason=decision.reason,
                    classification=classification,
                    continue_allowed=continue_allowed,
                    escalation_required=escalation_required,
                    missing_effect_ids=missing_effect_ids,
                )
            )
        if audit.stop_reason is ProbeStopReason.CAPABILITY_UNAVAILABLE:
            unavailable_sequences.add(audit.sequence)
        if decision.reason is EvidenceReason.DUPLICATE_CANDIDATES:
            redundant_sequences.add(audit.sequence)

        progress = _progress_sha256(evaluation)
        if progress == previous_progress:
            unchanged_progress_count += 1
        else:
            unchanged_progress_count = 0

        if evaluation.classification in policy.sufficient_classifications:
            stop_reason = AdaptiveStopReason.SUFFICIENT_EVIDENCE
            sufficient_sequence = audit.sequence
            sufficient_elapsed_ms = audit.session_elapsed_ms
            break
        if (
            identity in required_identities
            and audit.stop_reason is ProbeStopReason.CAPABILITY_UNAVAILABLE
        ):
            stop_reason = AdaptiveStopReason.REQUIRED_CAPABILITY_UNAVAILABLE
            break
        if identity in required_identities and (
            audit.stop_reason in _UNSUPPORTED_REASONS
            or audit.outcome in {ProbeOutcome.REJECTED, ProbeOutcome.MALFORMED}
            or decision.reason is EvidenceReason.UNSUPPORTED_CAPABILITY
            or (
                audit.outcome is ProbeOutcome.COMPLETED
                and decision.disposition is EvidenceDisposition.REJECTED
            )
        ):
            stop_reason = AdaptiveStopReason.REQUIRED_PROBE_FAILED
            break
        if audit.stop_reason in _BUDGET_REASONS:
            stop_reason = AdaptiveStopReason.BUDGET_EXHAUSTED
            break
        if audit.stop_reason in _DEADLINE_REASONS:
            stop_reason = AdaptiveStopReason.DEADLINE_EXHAUSTED
            break
        if audit.stop_reason is ProbeStopReason.PROBE_CANCELLED:
            stop_reason = AdaptiveStopReason.CANCELLED
            break
        if audit.stop_reason in _UNSUPPORTED_REASONS:
            stop_reason = AdaptiveStopReason.NO_VALID_PROPOSAL
            break
        if unchanged_progress_count >= _NON_PROGRESS_LIMIT:
            redundant_sequences.add(audit.sequence)
            stop_reason = AdaptiveStopReason.NON_PROGRESS
            break

    if stop_reason is None:
        stop_reason = AdaptiveStopReason.MAX_TURNS

    if (
        policy.include_explanation
        and catalog_safe
        and not planner_failed
        and stop_reason is not AdaptiveStopReason.CANCELLED
        and (cancellation_event is None or not cancellation_event.is_set())
    ):
        remaining = _remaining_budget(
            sealed_envelope,
            controller,
            selected_clock,
            started_monotonic,
        )
        if remaining.elapsed_ms > 0:
            try:
                explanation_input = _planner_input(
                    phase=AdaptivePlannerPhase.EXPLAIN_EVIDENCE,
                    envelope=sealed_envelope,
                    catalog=catalog,
                    selected_counts=selected_counts,
                    evaluation=evaluation,
                    request_by_sequence=request_by_sequence,
                    prior_request_hashes=tuple(prior_request_hashes),
                    remaining_budget=remaining,
                    metadata=configured_metadata,
                )
            except (TypeError, ValueError):
                explanation_valid = False
            else:
                input_sha256 = hashlib.sha256(
                    canonical_json_bytes(explanation_input)
                ).hexdigest()
                sequence = len(turns) + 1
                _emit_advisory_requested(
                    progress_emitter,
                    occurred_at=_progress_occurred_at(),
                    investigation_id=sealed_envelope.investigation_id,
                    phase=AdaptivePlannerPhase.EXPLAIN_EVIDENCE,
                    turn_sequence=sequence,
                    input_sha256=input_sha256,
                )
                call = await _call_planner(
                    planner,
                    explanation_input,
                    timeout_ms=min(policy.planner_timeout_ms, remaining.elapsed_ms),
                    cancellation_event=cancellation_event,
                )
                turn, failure, cancelled = _validated_turn(
                    call,
                    configured_metadata=configured_metadata,
                    input_sha256=input_sha256,
                )
                if cancelled:
                    record = _failure_turn_record(
                        sequence=sequence,
                        phase=AdaptivePlannerPhase.EXPLAIN_EVIDENCE,
                        input_sha256=input_sha256,
                        metadata=configured_metadata,
                        failure=None,
                        cancelled=True,
                    )
                    turns.append(record)
                    _emit_advisory_completed(
                        progress_emitter,
                        occurred_at=_progress_occurred_at(),
                        investigation_id=sealed_envelope.investigation_id,
                        turn=record,
                    )
                    explanation_valid = False
                elif failure is not None:
                    returned = call.turn
                    metadata = (
                        returned.metadata
                        if returned is not None
                        and _metadata_matches(configured_metadata, returned.metadata)
                        else configured_metadata
                    )
                    record = _failure_turn_record(
                        sequence=sequence,
                        phase=AdaptivePlannerPhase.EXPLAIN_EVIDENCE,
                        input_sha256=input_sha256,
                        metadata=metadata,
                        failure=failure,
                        cancelled=False,
                        output_sha256=(
                            returned.output_sha256 if returned is not None else None
                        ),
                        usage=returned.usage if returned is not None else None,
                    )
                    turns.append(record)
                    _emit_advisory_completed(
                        progress_emitter,
                        occurred_at=_progress_occurred_at(),
                        investigation_id=sealed_envelope.investigation_id,
                        turn=record,
                    )
                    explanation_valid = False
                else:
                    if turn is None or turn.output is None:
                        raise RuntimeError("validated explanation lost its output")
                    output = turn.output
                    ignored = tuple(
                        ProposalRecord(
                            proposal_sequence=index,
                            capability_name=request.capability_name,
                            capability_version=request.capability_version,
                            request_sha256=probe_request_sha256(request),
                            disposition=(ProposalDisposition.IGNORED_EXPLANATION_PHASE),
                        )
                        for index, request in enumerate(
                            output.probe_proposals,
                            start=1,
                        )
                    )
                    record = AdaptiveTurnRecord(
                        turn_sequence=sequence,
                        phase=AdaptivePlannerPhase.EXPLAIN_EVIDENCE,
                        input_sha256=input_sha256,
                        output_sha256=turn.output_sha256,
                        failure=None,
                        cancelled=False,
                        metadata=turn.metadata,
                        usage=turn.usage,
                        proposals=ignored,
                        selected_request_sha256=None,
                        planner_recommended_stop=(output.stop_advice.recommend_stop),
                    )
                    turns.append(record)
                    _emit_advisory_completed(
                        progress_emitter,
                        occurred_at=_progress_occurred_at(),
                        investigation_id=sealed_envelope.investigation_id,
                        turn=record,
                        proposal_requests=output.probe_proposals,
                    )
                    explanation, explanation_valid = _advisory_explanation(
                        output,
                        explanation_input,
                    )

    audit_trail = controller.audit_trail
    updated_at = max(selected_clock.now(), sealed_envelope.ambiguity.observed_at)
    report = engine.report(
        audit_trail,
        created_at=sealed_envelope.ambiguity.observed_at,
        updated_at=updated_at,
        revision=revision,
        advisory_explanation=explanation,
    )
    if additional_limitations:
        payload = report.model_dump(mode="python")
        payload["limitations"] = (*report.limitations, *additional_limitations)
        report = InvestigationReport.model_validate(payload)

    final_audit = audit_trail[-1] if audit_trail else None
    total_elapsed_ms = min(
        max(0, int((selected_clock.monotonic() - started_monotonic) * 1_000)),
        2**63 - 1,
    )
    if final_audit is not None:
        total_elapsed_ms = max(total_elapsed_ms, final_audit.session_elapsed_ms)
    turn_tuple = tuple(turns)
    usages = tuple(turn.usage for turn in turn_tuple)
    if not usages:
        prompt_tokens: int | None = 0
        output_tokens: int | None = 0
        total_tokens: int | None = 0
    elif all(usage is not None for usage in usages):
        prompt_tokens = sum(
            usage.prompt_tokens for usage in usages if usage is not None
        )
        output_tokens = sum(
            usage.output_tokens for usage in usages if usage is not None
        )
        total_tokens = prompt_tokens + output_tokens
    else:
        prompt_tokens = None
        output_tokens = None
        total_tokens = None

    proposal_records = tuple(
        proposal for turn in turn_tuple for proposal in turn.proposals
    )
    unsupported_proposal_count = sum(
        item.disposition is ProposalDisposition.UNSUPPORTED_CAPABILITY
        for item in proposal_records
    )
    invalid_proposal_count = sum(
        item.disposition
        in {
            ProposalDisposition.INVALID_ARGUMENTS,
            ProposalDisposition.INVALID_EFFECT_REFERENCE,
        }
        for item in proposal_records
    )
    duplicate_proposal_count = sum(
        item.disposition is ProposalDisposition.DUPLICATE for item in proposal_records
    )
    policies = sealed_envelope.context.policies
    result = AdaptiveInvestigationResult(
        report=report,
        policy=policy,
        capability_catalog_sha256=catalog_sha256,
        stop_reason=stop_reason,
        acquisition_turn_count=sum(
            turn.phase is AdaptivePlannerPhase.ACQUIRE_EVIDENCE for turn in turn_tuple
        ),
        model_invocation_count=len(turn_tuple),
        proposal_count=len(proposal_records),
        attempted_probe_count=len(audit_trail),
        probe_count_used=(final_audit.probe_count_used if final_audit else 0),
        cost_units_used=(final_audit.cost_units_used if final_audit else 0),
        result_bytes_acquired=(final_audit.result_bytes_acquired if final_audit else 0),
        total_elapsed_ms=total_elapsed_ms,
        sufficient_probe_sequence=sufficient_sequence,
        time_to_sufficient_evidence_ms=sufficient_elapsed_ms,
        unsupported_proposal_count=unsupported_proposal_count,
        invalid_proposal_count=invalid_proposal_count,
        duplicate_proposal_count=duplicate_proposal_count,
        unavailable_probe_count=len(unavailable_sequences),
        redundant_probe_count=len(redundant_sequences),
        planner_metadata=configured_metadata,
        policies=(policies.authority, policies.classification, policies.action),
        model_prompt_tokens=prompt_tokens,
        model_output_tokens=output_tokens,
        model_total_tokens=total_tokens,
        explanation_valid=explanation_valid,
        turns=turn_tuple,
        transcript_sha256=_transcript_sha256(turn_tuple),
        _seal=_ADAPTIVE_RESULT_SEAL,
    )
    if progress_emitter is not None:
        (
            classification,
            continue_allowed,
            escalation_required,
            missing_effect_ids,
        ) = _progress_state(
            report.classification,
            report.action_gate,
            report.missing_evidence,
        )
        progress_emitter(
            StrategyProgress(
                occurred_at=_progress_occurred_at(),
                investigation_id=sealed_envelope.investigation_id,
                strategy=ComparisonStrategyKind.ADAPTIVE,
                stage=StrategyProgressStage.COMPLETED,
                stop_reason=stop_reason.value,
                classification=classification,
                continue_allowed=continue_allowed,
                escalation_required=escalation_required,
                missing_effect_ids=missing_effect_ids,
            )
        )
    return result


def run_adaptive_investigation(
    envelope: ExecutionEnvelope,
    capabilities: CapabilityRegistry,
    rules: TargetRuleRegistry,
    planner: AdvisoryPlanner,
    policy: AdaptiveInvestigationPolicy,
    *,
    clock: ControllerClock | None = None,
    revision: int = 1,
    cancellation_event: asyncio.Event | None = None,
    additional_limitations: tuple[str, ...] = (),
) -> AdaptiveInvestigationResult:
    """Synchronously run adaptive investigation outside an active event loop."""

    try:
        asyncio.get_running_loop()
    except RuntimeError:
        pass
    else:
        raise RuntimeError(
            "run_adaptive_investigation cannot run inside an active event loop"
        )
    return asyncio.run(
        execute_adaptive_investigation(
            envelope,
            capabilities,
            rules,
            planner,
            policy,
            clock=clock,
            revision=revision,
            cancellation_event=cancellation_event,
            additional_limitations=additional_limitations,
        )
    )


__all__ = [
    "AdaptiveInvestigationPolicy",
    "AdaptiveInvestigationResult",
    "AdaptiveStopReason",
    "AdaptiveTurnRecord",
    "AdvisoryPlanner",
    "AdvisoryPlannerMetadata",
    "AdvisoryPlannerTurn",
    "AdvisoryPlannerUsage",
    "PlannerFailureKind",
    "ProposalDisposition",
    "ProposalRecord",
    "execute_adaptive_investigation",
    "run_adaptive_investigation",
]
