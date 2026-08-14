"""Sanitized, non-authoritative progress delivery for investigations."""

from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable
from enum import StrEnum
from typing import Literal

from pydantic import Field, model_validator

from reconcile.contracts.base import (
    AwareDatetime,
    Identifier,
    Sha256Digest,
    StrictModel,
)
from reconcile.contracts.common import Classification
from reconcile.contracts.comparison import ComparisonStrategyKind
from reconcile.contracts.evidence import EvidenceDisposition, EvidenceReason
from reconcile.contracts.operator import ExecutionEnvelopeSummary
from reconcile.contracts.planning import AdaptivePlannerPhase
from reconcile.contracts.report import ProbeOutcome
from reconcile.controller import ProbeStopReason

_MAX_FIXED_PROGRESS_EVENTS = 2 + (3 * 64)
_MAX_ADAPTIVE_PROGRESS_EVENTS = 2 + (5 * 64) + 2
_MAX_COMPARE_PROGRESS_EVENTS = (
    _MAX_FIXED_PROGRESS_EVENTS + _MAX_ADAPTIVE_PROGRESS_EVENTS
)
_MAX_WORKFLOW_PROGRESS_EVENTS = _MAX_COMPARE_PROGRESS_EVENTS + 1
_PROGRESS_QUEUE_CAPACITY = _MAX_WORKFLOW_PROGRESS_EVENTS + 1
_DEFAULT_FLUSH_TIMEOUT_SECONDS = 5.0
_CLOSE_SENTINEL = object()


class StrategyProgressStage(StrEnum):
    """Lifecycle stage for one deterministic investigation strategy."""

    STARTED = "STARTED"
    COMPLETED = "COMPLETED"


class AdvisoryProgressStage(StrEnum):
    """Lifecycle stage for one bounded advisory turn."""

    REQUESTED = "REQUESTED"
    COMPLETED = "COMPLETED"


class ProbeProgressStage(StrEnum):
    """Lifecycle stage for one controller-bound probe attempt."""

    REQUESTED = "REQUESTED"
    COMPLETED = "COMPLETED"


class ProgressPlannerFailure(StrEnum):
    """Sanitized advisory failure visible to a progress consumer."""

    UNAVAILABLE = "unavailable"
    TIMEOUT = "timeout"
    SCHEMA_INVALID = "schema_invalid"


class ProgressProposalDisposition(StrEnum):
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


class AdvisoryProposalProgress(StrictModel):
    """One sanitized advisory proposal without arguments or rationale."""

    proposal_sequence: int = Field(ge=1, le=8)
    capability_name: Identifier
    capability_version: Identifier
    request_sha256: Sha256Digest
    relevant_effect_ids: tuple[Identifier, ...] = Field(
        min_length=1,
        max_length=64,
    )
    disposition: ProgressProposalDisposition

    @model_validator(mode="after")
    def validate_effect_ids(self) -> AdvisoryProposalProgress:
        if len(self.relevant_effect_ids) != len(set(self.relevant_effect_ids)):
            raise ValueError("relevant effect identities must be unique")
        return self


class EnvelopeProgress(StrictModel):
    """One already-sanitized execution-envelope summary."""

    occurred_at: AwareDatetime
    investigation_id: Identifier
    summary: ExecutionEnvelopeSummary

    @model_validator(mode="after")
    def validate_investigation(self) -> EnvelopeProgress:
        if self.summary.investigation_id != self.investigation_id:
            raise ValueError("envelope progress investigation must match its summary")
        return self


class StrategyProgress(StrictModel):
    """Sanitized start or terminal state for one strategy lane."""

    occurred_at: AwareDatetime
    investigation_id: Identifier
    strategy: ComparisonStrategyKind
    stage: StrategyProgressStage
    stop_reason: Identifier | None = None
    classification: Classification | None = None
    continue_allowed: bool | None = None
    escalation_required: bool | None = None
    missing_effect_ids: tuple[Identifier, ...] = Field(
        default_factory=tuple,
        max_length=64,
    )

    @model_validator(mode="after")
    def validate_stage(self) -> StrategyProgress:
        completed = self.stage is StrategyProgressStage.COMPLETED
        terminal_values = (
            self.stop_reason,
            self.classification,
            self.continue_allowed,
            self.escalation_required,
        )
        if completed != all(value is not None for value in terminal_values):
            raise ValueError("completed strategy progress requires terminal state")
        if not completed and self.missing_effect_ids:
            raise ValueError("started strategy progress cannot contain missing effects")
        if len(self.missing_effect_ids) != len(set(self.missing_effect_ids)):
            raise ValueError("missing effect identities must be unique")
        return self


class AdvisoryProgress(StrictModel):
    """Sanitized request or result metadata for one advisory turn."""

    occurred_at: AwareDatetime
    investigation_id: Identifier
    strategy: Literal[ComparisonStrategyKind.ADAPTIVE]
    stage: AdvisoryProgressStage
    phase: AdaptivePlannerPhase
    turn_sequence: int = Field(ge=1, le=65)
    input_sha256: Sha256Digest
    output_sha256: Sha256Digest | None = None
    failure: ProgressPlannerFailure | None = None
    cancelled: bool = False
    proposals: tuple[AdvisoryProposalProgress, ...] = Field(
        default_factory=tuple,
        max_length=8,
    )
    selected_request_sha256: Sha256Digest | None = None
    planner_recommended_stop: bool | None = None

    @model_validator(mode="after")
    def validate_stage(self) -> AdvisoryProgress:
        if self.stage is AdvisoryProgressStage.REQUESTED:
            if (
                self.output_sha256 is not None
                or self.failure is not None
                or self.cancelled
                or self.proposals
                or self.selected_request_sha256 is not None
                or self.planner_recommended_stop is not None
            ):
                raise ValueError("requested advisory progress cannot contain a result")
            return self

        if self.cancelled:
            if (
                self.output_sha256 is not None
                or self.failure is not None
                or self.proposals
                or self.selected_request_sha256 is not None
                or self.planner_recommended_stop is not None
            ):
                raise ValueError("cancelled advisory progress cannot contain output")
            return self

        if self.failure is not None:
            if (
                self.proposals
                or self.selected_request_sha256 is not None
                or self.planner_recommended_stop is not None
            ):
                raise ValueError("failed advisory progress cannot contain advice")
            return self

        if self.output_sha256 is None or self.planner_recommended_stop is None:
            raise ValueError("successful advisory progress requires validated output")
        selected = sum(
            proposal.disposition is ProgressProposalDisposition.SELECTED
            for proposal in self.proposals
        )
        sequences = tuple(proposal.proposal_sequence for proposal in self.proposals)
        if sequences != tuple(range(1, len(self.proposals) + 1)):
            raise ValueError("advisory proposal progress must be ordered")
        if (self.selected_request_sha256 is not None) != (selected == 1):
            raise ValueError("selected advisory progress is inconsistent")
        if selected == 1 and self.selected_request_sha256 != next(
            proposal.request_sha256
            for proposal in self.proposals
            if proposal.disposition is ProgressProposalDisposition.SELECTED
        ):
            raise ValueError("selected advisory progress digest is inconsistent")
        return self


class ProbeProgress(StrictModel):
    """Sanitized request or controller result for one probe attempt."""

    occurred_at: AwareDatetime
    investigation_id: Identifier
    strategy: ComparisonStrategyKind
    stage: ProbeProgressStage
    attempt_sequence: int = Field(ge=1, le=64)
    capability_name: Identifier | None
    capability_version: Identifier | None
    request_sha256: Sha256Digest | None
    relevant_effect_ids: tuple[Identifier, ...] = Field(min_length=1, max_length=64)
    controller_sequence: int | None = Field(default=None, ge=1, le=2**63 - 1)
    controller_sequence_reused: bool | None = None
    outcome: ProbeOutcome | None = None
    controller_stop_reason: ProbeStopReason | None = None
    session_elapsed_ms: int | None = Field(default=None, ge=0, le=2**63 - 1)
    probe_count_used: int | None = Field(default=None, ge=0, le=2**63 - 1)
    cost_units_used: int | None = Field(default=None, ge=0, le=2**63 - 1)
    result_bytes_acquired: int | None = Field(default=None, ge=0, le=2**63 - 1)
    result_sha256: Sha256Digest | None = None
    result_byte_count: int | None = Field(default=None, ge=0, le=2**63 - 1)
    evidence_ids: tuple[Identifier, ...] = Field(default_factory=tuple, max_length=1)

    @model_validator(mode="after")
    def validate_stage(self) -> ProbeProgress:
        if (self.capability_name is None) is not (self.capability_version is None):
            raise ValueError("probe capability identity must be complete")
        if len(self.relevant_effect_ids) != len(set(self.relevant_effect_ids)):
            raise ValueError("relevant effect identities must be unique")
        result_values = (
            self.controller_sequence,
            self.controller_sequence_reused,
            self.outcome,
            self.controller_stop_reason,
            self.session_elapsed_ms,
            self.probe_count_used,
            self.cost_units_used,
            self.result_bytes_acquired,
        )
        completed = self.stage is ProbeProgressStage.COMPLETED
        if completed != all(value is not None for value in result_values):
            raise ValueError("completed probe progress requires a controller result")
        if not completed and (
            self.capability_name is None
            or self.request_sha256 is None
            or not self.relevant_effect_ids
        ):
            raise ValueError("requested probe progress requires sanitized request data")
        if completed != (len(self.evidence_ids) == 1):
            raise ValueError("completed probe progress requires one evidence identity")
        if not completed and (
            self.result_sha256 is not None or self.result_byte_count is not None
        ):
            raise ValueError("requested probe progress cannot contain result identity")
        if completed and self.outcome is ProbeOutcome.COMPLETED:
            if (
                self.capability_name is None
                or self.request_sha256 is None
                or self.result_sha256 is None
                or self.result_byte_count is None
            ):
                raise ValueError("completed outcomes require bounded result identity")
        elif completed and (
            self.result_sha256 is not None or self.result_byte_count is not None
        ):
            raise ValueError("noncompleted outcomes cannot contain result identity")
        return self


class EvidenceProgress(StrictModel):
    """Sanitized deterministic evidence and classification progress."""

    occurred_at: AwareDatetime
    investigation_id: Identifier
    strategy: ComparisonStrategyKind
    attempt_sequence: int = Field(ge=1, le=64)
    controller_sequence: int = Field(ge=1, le=2**63 - 1)
    evidence_id: Identifier
    disposition: EvidenceDisposition
    reason: EvidenceReason
    classification: Classification
    continue_allowed: bool
    escalation_required: bool
    missing_effect_ids: tuple[Identifier, ...] = Field(
        default_factory=tuple,
        max_length=64,
    )

    @model_validator(mode="after")
    def validate_missing_effects(self) -> EvidenceProgress:
        if len(self.missing_effect_ids) != len(set(self.missing_effect_ids)):
            raise ValueError("missing effect identities must be unique")
        return self


type InvestigationProgress = (
    EnvelopeProgress
    | StrategyProgress
    | AdvisoryProgress
    | ProbeProgress
    | EvidenceProgress
)
type ProgressCallback = Callable[[InvestigationProgress], Awaitable[None]]
type ProgressEmitter = Callable[[InvestigationProgress], None]


class ProgressDeliveryError(RuntimeError):
    """A progress consumer failed after deterministic execution completed."""

    def __init__(self) -> None:
        super().__init__("investigation progress delivery failed")


_PROGRESS_TYPES = (
    EnvelopeProgress,
    StrategyProgress,
    AdvisoryProgress,
    ProbeProgress,
    EvidenceProgress,
)


class ProgressDispatcher:
    """Buffer ordered progress without feeding consumer behavior into policy."""

    def __init__(
        self,
        callback: ProgressCallback,
        *,
        flush_timeout_seconds: float = _DEFAULT_FLUSH_TIMEOUT_SECONDS,
    ) -> None:
        if not callable(callback):
            raise TypeError("progress callback must be callable")
        if (
            type(flush_timeout_seconds) not in {int, float}
            or not 0 < flush_timeout_seconds <= 60
        ):
            raise ValueError("progress flush timeout must be positive and bounded")
        self._callback = callback
        self._flush_timeout_seconds = float(flush_timeout_seconds)
        self._queue: asyncio.Queue[InvestigationProgress | object] = asyncio.Queue(
            maxsize=_PROGRESS_QUEUE_CAPACITY
        )
        self._failed = False
        self._closed = False
        self._finished = False
        self._aborting = False
        self._worker = asyncio.create_task(
            self._drain(),
            name="reconcile-progress-dispatch",
        )

    def emit(self, event: InvestigationProgress) -> None:
        """Queue exact sanitized progress without raising into execution policy."""

        if self._closed or type(event) not in _PROGRESS_TYPES:
            self._failed = True
            return
        try:
            self._queue.put_nowait(event)
        except asyncio.QueueFull:
            self._failed = True

    async def _drain(self) -> None:
        while True:
            item = await self._queue.get()
            try:
                if item is _CLOSE_SENTINEL:
                    return
                if self._failed:
                    continue
                try:
                    result = await self._callback(item)  # type: ignore[arg-type]
                except asyncio.CancelledError:
                    if self._aborting:
                        raise
                    self._failed = True
                except BaseException:
                    self._failed = True
                else:
                    if result is not None:
                        self._failed = True
            finally:
                self._queue.task_done()

    async def _cancel_worker(self) -> None:
        self._aborting = True
        if not self._worker.done():
            self._worker.cancel()
        await asyncio.gather(self._worker, return_exceptions=True)
        while True:
            try:
                self._queue.get_nowait()
            except asyncio.QueueEmpty:
                break
            else:
                self._queue.task_done()

    async def finish(self) -> None:
        """Flush accepted progress and surface only a sanitized terminal failure."""

        if self._finished:
            if self._failed:
                raise ProgressDeliveryError from None
            return
        self._closed = True
        try:
            self._queue.put_nowait(_CLOSE_SENTINEL)
        except asyncio.QueueFull:
            self._failed = True
            await self._cancel_worker()
        else:
            try:
                await asyncio.wait_for(
                    asyncio.shield(self._worker),
                    timeout=self._flush_timeout_seconds,
                )
            except TimeoutError:
                self._failed = True
                await self._cancel_worker()
            except asyncio.CancelledError:
                await self._cancel_worker()
                self._finished = True
                raise
            else:
                if self._worker.cancelled() or self._worker.exception() is not None:
                    self._failed = True
        self._finished = True
        if self._failed:
            raise ProgressDeliveryError from None

    async def abort(self) -> None:
        """Cancel and join delivery without masking an execution exception."""

        self._closed = True
        self._finished = True
        await self._cancel_worker()


__all__ = [
    "AdvisoryProgress",
    "AdvisoryProgressStage",
    "AdvisoryProposalProgress",
    "EnvelopeProgress",
    "EvidenceProgress",
    "InvestigationProgress",
    "ProbeProgress",
    "ProbeProgressStage",
    "ProgressCallback",
    "ProgressDeliveryError",
    "ProgressDispatcher",
    "ProgressEmitter",
    "ProgressPlannerFailure",
    "ProgressProposalDisposition",
    "StrategyProgress",
    "StrategyProgressStage",
]
