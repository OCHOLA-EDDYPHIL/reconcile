"""Fixed probe plans executed through the deterministic investigation path."""

from __future__ import annotations

import asyncio
import hashlib
import json
import re
import time
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum

from reconcile.contracts import (
    ActionGateResult,
    Classification,
    ComparisonStrategyKind,
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
from reconcile.controller import (
    CapabilityRegistry,
    ControllerClock,
    ProbeController,
    ProbeDurabilityObserver,
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
    EvidenceProgress,
    ProbeProgress,
    ProbeProgressStage,
    ProgressEmitter,
    StrategyProgress,
    StrategyProgressStage,
)
from reconcile.security import contains_sensitive_material

_MAX_PLAN_STEPS = 64
_IDENTIFIER_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]*$")


def _progress_occurred_at() -> datetime:
    """Timestamp observation without touching the authoritative execution clock."""

    return datetime.now(UTC)


class FixedBaselineStopReason(StrEnum):
    """Why a finite fixed plan stopped issuing read-only probes."""

    SUFFICIENT_EVIDENCE = "sufficient_evidence"
    PLAN_EXHAUSTED = "plan_exhausted"
    BUDGET_EXHAUSTED = "budget_exhausted"
    DEADLINE_EXHAUSTED = "deadline_exhausted"
    CANCELLED = "cancelled"
    REQUIRED_CAPABILITY_UNAVAILABLE = "required_capability_unavailable"
    REQUIRED_PROBE_FAILED = "required_probe_failed"
    NON_PROGRESS = "non_progress"


@dataclass(frozen=True, slots=True, init=False)
class FixedProbeStep:
    """One immutable controller-bound request in a predetermined plan."""

    _request_bytes: bytes = field(repr=False)
    required: bool

    def __init__(self, *, request: ProbeRequest, required: bool = True) -> None:
        if type(request) is not ProbeRequest:
            raise TypeError("a fixed probe step requires an exact probe request")
        if type(required) is not bool:
            raise TypeError("a fixed probe required flag must be a boolean")
        payload = canonical_json_bytes(request)
        decode_contract(payload, ProbeRequest)
        object.__setattr__(self, "_request_bytes", payload)
        object.__setattr__(self, "required", required)

    @property
    def request(self) -> ProbeRequest:
        """Return an isolated copy of the sealed probe request."""

        return decode_contract(self._request_bytes, ProbeRequest)


@dataclass(frozen=True, slots=True, init=False)
class FixedProbePlan:
    """A versioned ordered plan and its explicit evidence stop policy."""

    name: str
    version: str
    steps: tuple[FixedProbeStep, ...]
    sufficient_classifications: tuple[Classification, ...]
    sha256: str

    def __init__(
        self,
        *,
        name: str,
        version: str,
        steps: tuple[FixedProbeStep, ...],
        sufficient_classifications: tuple[Classification, ...] = (),
    ) -> None:
        _validate_identifier(name, "fixed plan name")
        _validate_identifier(version, "fixed plan version")
        if type(steps) is not tuple or not 1 <= len(steps) <= _MAX_PLAN_STEPS:
            raise ValueError("a fixed plan requires one to 64 ordered steps")
        if any(type(step) is not FixedProbeStep for step in steps):
            raise TypeError("fixed plan steps must be exact fixed probe steps")
        if type(sufficient_classifications) is not tuple:
            raise TypeError("sufficient classifications must be an immutable tuple")
        if any(
            type(classification) is not Classification
            for classification in sufficient_classifications
        ):
            raise TypeError("sufficient classifications must be exact classifications")
        if Classification.UNKNOWN in sufficient_classifications:
            raise ValueError("UNKNOWN cannot be declared sufficient evidence")
        if len(sufficient_classifications) != len(set(sufficient_classifications)):
            raise ValueError("sufficient classifications must be unique")
        classifications = tuple(
            sorted(sufficient_classifications, key=lambda item: item.value)
        )
        material = {
            "name": name,
            "steps": [
                {
                    "request": json.loads(step._request_bytes),
                    "required": step.required,
                }
                for step in steps
            ],
            "sufficient_classifications": [
                classification.value for classification in classifications
            ],
            "version": version,
        }
        digest = hashlib.sha256(canonical_json_value_bytes(material)).hexdigest()
        object.__setattr__(self, "name", name)
        object.__setattr__(self, "version", version)
        object.__setattr__(self, "steps", tuple(steps))
        object.__setattr__(self, "sufficient_classifications", classifications)
        object.__setattr__(self, "sha256", digest)


_BASELINE_RESULT_SEAL = object()


@dataclass(frozen=True, slots=True, init=False)
class FixedBaselineResult:
    """An ordinary report plus neutral fixed-plan execution measurements."""

    _report_bytes: bytes = field(repr=False)
    plan_name: str
    plan_version: str
    plan_sha256: str
    stop_reason: FixedBaselineStopReason
    planned_probe_count: int
    attempted_probe_count: int
    probe_count_used: int
    cost_units_used: int
    result_bytes_acquired: int
    total_elapsed_ms: int
    sufficient_probe_sequence: int | None
    time_to_sufficient_evidence_ms: int | None
    unsupported_probe_count: int
    unavailable_probe_count: int
    redundant_probe_count: int
    duplicate_probe_count: int
    model_invocation_count: int

    def __init__(
        self,
        *,
        report: InvestigationReport,
        plan: FixedProbePlan,
        stop_reason: FixedBaselineStopReason,
        attempted_probe_count: int,
        probe_count_used: int,
        cost_units_used: int,
        result_bytes_acquired: int,
        total_elapsed_ms: int,
        sufficient_probe_sequence: int | None,
        time_to_sufficient_evidence_ms: int | None,
        unsupported_probe_count: int,
        unavailable_probe_count: int,
        redundant_probe_count: int,
        duplicate_probe_count: int,
        _seal: object,
    ) -> None:
        if _seal is not _BASELINE_RESULT_SEAL:
            raise TypeError("fixed baseline results are created only by the executor")
        if type(report) is not InvestigationReport:
            raise TypeError("a fixed baseline result requires an exact report")
        if type(plan) is not FixedProbePlan:
            raise TypeError("a fixed baseline result requires an exact plan")
        if type(stop_reason) is not FixedBaselineStopReason:
            raise TypeError("a fixed baseline result requires an exact stop reason")
        counts = (
            attempted_probe_count,
            probe_count_used,
            cost_units_used,
            result_bytes_acquired,
            total_elapsed_ms,
            unsupported_probe_count,
            unavailable_probe_count,
            redundant_probe_count,
            duplicate_probe_count,
        )
        if any(type(value) is not int or value < 0 for value in counts):
            raise ValueError("fixed baseline measurements must be nonnegative integers")
        if attempted_probe_count > len(plan.steps):
            raise ValueError("attempted probes cannot exceed fixed plan steps")
        if any(
            value > attempted_probe_count
            for value in (
                unsupported_probe_count,
                unavailable_probe_count,
                redundant_probe_count,
                duplicate_probe_count,
            )
        ):
            raise ValueError("probe disposition counts cannot exceed attempts")
        sufficient = stop_reason is FixedBaselineStopReason.SUFFICIENT_EVIDENCE
        if sufficient != (sufficient_probe_sequence is not None):
            raise ValueError("sufficient stop reason and sequence must agree")
        if sufficient != (time_to_sufficient_evidence_ms is not None):
            raise ValueError("sufficient stop reason and timing must agree")
        if sufficient_probe_sequence is not None and not (
            1 <= sufficient_probe_sequence <= attempted_probe_count
        ):
            raise ValueError("sufficient probe sequence is outside attempted probes")
        if (
            time_to_sufficient_evidence_ms is not None
            and time_to_sufficient_evidence_ms > total_elapsed_ms
        ):
            raise ValueError("sufficiency time cannot exceed total elapsed time")
        report_payload = canonical_json_bytes(report)
        validated_report = decode_contract(report_payload, InvestigationReport)
        if validated_report.classification is None:
            raise ValueError("a fixed baseline report requires a classification")
        object.__setattr__(self, "_report_bytes", report_payload)
        object.__setattr__(self, "plan_name", plan.name)
        object.__setattr__(self, "plan_version", plan.version)
        object.__setattr__(self, "plan_sha256", plan.sha256)
        object.__setattr__(self, "stop_reason", stop_reason)
        object.__setattr__(self, "planned_probe_count", len(plan.steps))
        object.__setattr__(self, "attempted_probe_count", attempted_probe_count)
        object.__setattr__(self, "probe_count_used", probe_count_used)
        object.__setattr__(self, "cost_units_used", cost_units_used)
        object.__setattr__(self, "result_bytes_acquired", result_bytes_acquired)
        object.__setattr__(self, "total_elapsed_ms", total_elapsed_ms)
        object.__setattr__(
            self,
            "sufficient_probe_sequence",
            sufficient_probe_sequence,
        )
        object.__setattr__(
            self,
            "time_to_sufficient_evidence_ms",
            time_to_sufficient_evidence_ms,
        )
        object.__setattr__(
            self,
            "unsupported_probe_count",
            unsupported_probe_count,
        )
        object.__setattr__(
            self,
            "unavailable_probe_count",
            unavailable_probe_count,
        )
        object.__setattr__(self, "redundant_probe_count", redundant_probe_count)
        object.__setattr__(self, "duplicate_probe_count", duplicate_probe_count)
        object.__setattr__(self, "model_invocation_count", 0)

    @property
    def report(self) -> InvestigationReport:
        """Return an isolated copy of the deterministic investigation report."""

        return decode_contract(self._report_bytes, InvestigationReport)

    @property
    def classification(self) -> Classification:
        classification = self.report.classification
        if classification is None:
            raise RuntimeError("a completed baseline report lost its classification")
        return classification


class _SystemClock:
    def monotonic(self) -> float:
        return time.monotonic()

    def now(self) -> datetime:
        return datetime.now(UTC)


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


def _validate_identifier(value: str, label: str) -> None:
    if (
        type(value) is not str
        or not 1 <= len(value) <= 128
        or _IDENTIFIER_PATTERN.fullmatch(value) is None
        or contains_sensitive_material(value)
    ):
        raise ValueError(f"{label} must be a bounded identifier")


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


async def execute_fixed_plan(
    envelope: ExecutionEnvelope,
    capabilities: CapabilityRegistry,
    rules: TargetRuleRegistry,
    plan: FixedProbePlan,
    *,
    clock: ControllerClock | None = None,
    revision: int = 1,
    cancellation_event: asyncio.Event | None = None,
    additional_limitations: tuple[str, ...] = (),
    progress_emitter: ProgressEmitter | None = None,
    durability_observer: ProbeDurabilityObserver | None = None,
    elapsed_offset_ms: int = 0,
) -> FixedBaselineResult:
    """Execute one finite plan without bypassing controller or evidence policy."""

    if type(envelope) is not ExecutionEnvelope:
        raise TypeError("fixed execution requires an exact execution envelope")
    if type(capabilities) is not CapabilityRegistry:
        raise TypeError("fixed execution requires an exact capability registry")
    if type(rules) is not TargetRuleRegistry:
        raise TypeError("fixed execution requires an exact target-rule registry")
    if type(plan) is not FixedProbePlan:
        raise TypeError("fixed execution requires an exact fixed probe plan")
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
    controller = ProbeController(
        sealed_envelope,
        capabilities,
        clock=selected_clock,
        durability_observer=durability_observer,
        elapsed_offset_ms=elapsed_offset_ms,
    )
    engine = EvidenceEngine(sealed_envelope, rules)
    stop_reason: FixedBaselineStopReason | None = None
    sufficient_sequence: int | None = None
    sufficient_elapsed_ms: int | None = None
    processed_sequences: set[int] = set()
    request_progress: dict[str, str] = {}
    unsupported_sequences: set[int] = set()
    unavailable_sequences: set[int] = set()
    redundant_sequences: set[int] = set()
    duplicate_sequences: set[int] = set()
    if progress_emitter is not None:
        progress_emitter(
            StrategyProgress(
                occurred_at=_progress_occurred_at(),
                investigation_id=sealed_envelope.investigation_id,
                strategy=ComparisonStrategyKind.FIXED,
                stage=StrategyProgressStage.STARTED,
            )
        )

    for attempt_sequence, step in enumerate(plan.steps, start=1):
        request = step.request
        request_identity = probe_request_sha256(request)
        repeated_request = request_identity in request_progress
        if progress_emitter is not None:
            progress_emitter(
                ProbeProgress(
                    occurred_at=_progress_occurred_at(),
                    investigation_id=sealed_envelope.investigation_id,
                    strategy=ComparisonStrategyKind.FIXED,
                    stage=ProbeProgressStage.REQUESTED,
                    attempt_sequence=attempt_sequence,
                    capability_name=request.capability_name,
                    capability_version=request.capability_version,
                    request_sha256=request_identity,
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
                        strategy=ComparisonStrategyKind.FIXED,
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
            if repeated_request:
                redundant_sequences.add(audit.sequence)
                duplicate_sequences.add(audit.sequence)
            stop_reason = FixedBaselineStopReason.NON_PROGRESS
            break
        processed_sequences.add(audit.sequence)
        engine.process(ProbeRun(request=request, execution=execution))
        evaluation = engine.evaluate(controller.audit_trail)
        decision = evaluation.attempts[-1].decision
        if progress_emitter is not None:
            progress_emitter(
                ProbeProgress(
                    occurred_at=_progress_occurred_at(),
                    investigation_id=sealed_envelope.investigation_id,
                    strategy=ComparisonStrategyKind.FIXED,
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
                    strategy=ComparisonStrategyKind.FIXED,
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

        if (
            audit.stop_reason in _UNSUPPORTED_REASONS
            or decision.reason is EvidenceReason.UNSUPPORTED_CAPABILITY
        ):
            unsupported_sequences.add(audit.sequence)
        if audit.stop_reason is ProbeStopReason.CAPABILITY_UNAVAILABLE:
            unavailable_sequences.add(audit.sequence)
        if decision.reason is EvidenceReason.DUPLICATE_CANDIDATES:
            redundant_sequences.add(audit.sequence)
        if repeated_request:
            duplicate_sequences.add(audit.sequence)

        progress = _progress_sha256(evaluation)
        previous_progress = request_progress.get(request_identity)
        request_progress[request_identity] = progress
        if repeated_request and previous_progress == progress:
            redundant_sequences.add(audit.sequence)

        if evaluation.classification in plan.sufficient_classifications:
            stop_reason = FixedBaselineStopReason.SUFFICIENT_EVIDENCE
            sufficient_sequence = audit.sequence
            sufficient_elapsed_ms = audit.session_elapsed_ms
            break
        if (
            step.required
            and audit.stop_reason is ProbeStopReason.CAPABILITY_UNAVAILABLE
        ):
            stop_reason = FixedBaselineStopReason.REQUIRED_CAPABILITY_UNAVAILABLE
            break
        if step.required and (
            audit.stop_reason in _UNSUPPORTED_REASONS
            or audit.outcome in {ProbeOutcome.REJECTED, ProbeOutcome.MALFORMED}
            or decision.reason is EvidenceReason.UNSUPPORTED_CAPABILITY
        ):
            stop_reason = FixedBaselineStopReason.REQUIRED_PROBE_FAILED
            break
        if audit.stop_reason in _BUDGET_REASONS:
            stop_reason = FixedBaselineStopReason.BUDGET_EXHAUSTED
            break
        if audit.stop_reason in _DEADLINE_REASONS:
            stop_reason = FixedBaselineStopReason.DEADLINE_EXHAUSTED
            break
        if audit.stop_reason is ProbeStopReason.PROBE_CANCELLED:
            stop_reason = FixedBaselineStopReason.CANCELLED
            break
        if repeated_request and previous_progress == progress:
            stop_reason = FixedBaselineStopReason.NON_PROGRESS
            break

    if stop_reason is None:
        stop_reason = FixedBaselineStopReason.PLAN_EXHAUSTED

    audit_trail = controller.audit_trail
    if not audit_trail:
        raise RuntimeError("a nonempty fixed plan produced no controller audit")
    report = engine.report(
        audit_trail,
        created_at=sealed_envelope.ambiguity.observed_at,
        updated_at=selected_clock.now(),
        revision=revision,
    )
    if additional_limitations:
        payload = report.model_dump(mode="python")
        payload["limitations"] = (*report.limitations, *additional_limitations)
        report = InvestigationReport.model_validate(payload)
    final_audit = audit_trail[-1]
    result = FixedBaselineResult(
        report=report,
        plan=plan,
        stop_reason=stop_reason,
        attempted_probe_count=len(audit_trail),
        probe_count_used=final_audit.probe_count_used,
        cost_units_used=final_audit.cost_units_used,
        result_bytes_acquired=final_audit.result_bytes_acquired,
        total_elapsed_ms=final_audit.session_elapsed_ms,
        sufficient_probe_sequence=sufficient_sequence,
        time_to_sufficient_evidence_ms=sufficient_elapsed_ms,
        unsupported_probe_count=len(unsupported_sequences),
        unavailable_probe_count=len(unavailable_sequences),
        redundant_probe_count=len(redundant_sequences),
        duplicate_probe_count=len(duplicate_sequences),
        _seal=_BASELINE_RESULT_SEAL,
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
                strategy=ComparisonStrategyKind.FIXED,
                stage=StrategyProgressStage.COMPLETED,
                stop_reason=stop_reason.value,
                classification=classification,
                continue_allowed=continue_allowed,
                escalation_required=escalation_required,
                missing_effect_ids=missing_effect_ids,
            )
        )
    return result


def run_fixed_plan(
    envelope: ExecutionEnvelope,
    capabilities: CapabilityRegistry,
    rules: TargetRuleRegistry,
    plan: FixedProbePlan,
    *,
    clock: ControllerClock | None = None,
    revision: int = 1,
    cancellation_event: asyncio.Event | None = None,
    additional_limitations: tuple[str, ...] = (),
) -> FixedBaselineResult:
    """Synchronously execute one finite fixed plan outside an event loop."""

    try:
        asyncio.get_running_loop()
    except RuntimeError:
        pass
    else:
        raise RuntimeError("run_fixed_plan cannot run inside an active event loop")
    return asyncio.run(
        execute_fixed_plan(
            envelope,
            capabilities,
            rules,
            plan,
            clock=clock,
            revision=revision,
            cancellation_event=cancellation_event,
            additional_limitations=additional_limitations,
        )
    )


__all__ = [
    "FixedBaselineResult",
    "FixedBaselineStopReason",
    "FixedProbePlan",
    "FixedProbeStep",
    "execute_fixed_plan",
    "run_fixed_plan",
]
