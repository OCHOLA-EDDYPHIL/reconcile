"""Single-process operator service for canonical scenario investigations."""

from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable
from contextlib import suppress
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from functools import partial
from typing import Protocol

from reconcile.adk_planner import VertexAdcPlannerConfig
from reconcile.contracts.codec import canonical_json_bytes, decode_contract
from reconcile.contracts.comparison import (
    ComparisonRun,
    ComparisonStrategyKind,
    InvestigationComparisonRecord,
)
from reconcile.contracts.evidence import EVIDENCE_DECISION_VERSION, EvidenceDecision
from reconcile.contracts.operational import ScenarioOperationalStatus
from reconcile.contracts.operator import (
    MAX_SCENARIO_RUN_EVENTS,
    SCENARIO_RUN_EVENT_VERSION,
    SCENARIO_RUN_SNAPSHOT_VERSION,
    AdvisoryTurnEventPayload,
    AdvisoryTurnFailureCategory,
    AdvisoryTurnStatus,
    AdvisoryTurnSummary,
    EnvelopeSummaryEventPayload,
    ExecutionEnvelopeSummary,
    OperatorEvidenceDecisionEventPayload,
    ProbeRequestDisposition,
    ProbeRequestEventPayload,
    ProbeResultEventPayload,
    SanitizedComparisonRun,
    SanitizedDeterministicProof,
    SanitizedEffectFinding,
    SanitizedEvidenceSummary,
    SanitizedInvestigationComparison,
    SanitizedInvestigationReport,
    SanitizedMissingEvidence,
    SanitizedProbeAuditRecord,
    SanitizedProbeRequest,
    SanitizedProbeResult,
    ScenarioLaunchName,
    ScenarioLaunchRequest,
    ScenarioLifecycleEventPayload,
    ScenarioRunEvent,
    ScenarioRunEventPayload,
    ScenarioRunEventType,
    ScenarioRunFailureCategory,
    ScenarioRunLifecycle,
    ScenarioRunMode,
    ScenarioRunResultKind,
    ScenarioRunSnapshot,
    TerminalStateEventPayload,
    TerminalStateSummary,
)
from reconcile.contracts.report import (
    InvestigationReport,
    InvestigationStatus,
    ProbeOutcome,
)
from reconcile.persistence import (
    CreateScenarioWorkResult,
    ScenarioInvestigationState,
    ScenarioStore,
    ScenarioWorkConflict,
    ScenarioWorkItem,
    ScenarioWorkNotFound,
)
from reconcile.progress import (
    AdvisoryProgress,
    AdvisoryProgressStage,
    EnvelopeProgress,
    EvidenceProgress,
    InvestigationProgress,
    ProbeProgress,
    ProbeProgressStage,
    ProgressCallback,
    ProgressDeliveryError,
    StrategyProgress,
)
from reconcile.scenarios.service import (
    ScenarioMode,
    ScenarioName,
    ScenarioWorkflowError,
    ScenarioWorkflowErrorCategory,
    ScenarioWorkflowResult,
    _envelope_summary,
    bounded_hybrid_route_provenance,
    run_one,
    scenario_investigation_id,
)

MAX_ACTIVE_SCENARIO_RUNS = 4
MAX_RETAINED_SCENARIO_RUNS = 64
_REQUEST_TERMINALIZATION_GRACE = timedelta(seconds=4)


class OperatorServiceError(Exception):
    """Base class for deterministic operator-service boundary failures."""


class OperatorServiceClosed(OperatorServiceError):
    """New scenario launches are not accepted after service shutdown."""


class OperatorServiceUnavailable(OperatorServiceError):
    """An owned run exited before it durably terminalized."""

    def __init__(self, investigation_id: str) -> None:
        self.investigation_id = investigation_id
        super().__init__(
            f"operator scenario service is unavailable: {investigation_id}"
        )


class OperatorCapacityExceeded(OperatorServiceError):
    """The bounded single-process operator registry cannot admit a new run."""

    def __init__(self) -> None:
        super().__init__("operator scenario capacity is exhausted")


class ScenarioLaunchConflict(OperatorServiceError):
    """A launch identity is already bound to different canonical input."""

    def __init__(self, launch_id: str, investigation_id: str) -> None:
        self.launch_id = launch_id
        self.investigation_id = investigation_id
        super().__init__(f"scenario launch identity is already in use: {launch_id}")


class ScenarioRunNotFound(OperatorServiceError):
    """No process-lifetime scenario run has the requested identity."""

    def __init__(self, investigation_id: str) -> None:
        self.investigation_id = investigation_id
        super().__init__(f"scenario run does not exist: {investigation_id}")


class ScenarioEnvelopeUnavailable(OperatorServiceError):
    """The run has not produced a sanitized envelope summary."""

    def __init__(self, investigation_id: str) -> None:
        self.investigation_id = investigation_id
        super().__init__(f"scenario envelope is unavailable: {investigation_id}")


class InvalidScenarioEventCursor(OperatorServiceError):
    """An exclusive event cursor is outside the retained journal."""

    def __init__(self, investigation_id: str, cursor: object, latest: int) -> None:
        self.investigation_id = investigation_id
        self.cursor = cursor
        self.latest = latest
        super().__init__(f"scenario event cursor is invalid: {investigation_id}")


class ScenarioEventJournalFull(OperatorServiceError):
    """The bounded journal reserved its final entry for terminal state."""

    def __init__(self, investigation_id: str) -> None:
        self.investigation_id = investigation_id
        self.limit = MAX_SCENARIO_RUN_EVENTS
        super().__init__(f"scenario event journal is full: {investigation_id}")


class ScenarioEventJournalTerminal(OperatorServiceError):
    """A terminal journal cannot accept another transition."""

    def __init__(self, investigation_id: str) -> None:
        self.investigation_id = investigation_id
        super().__init__(f"scenario event journal is terminal: {investigation_id}")


class ScenarioWorkflowRunner(Protocol):
    """Server-owned scenario runner with non-authoritative progress delivery."""

    def __call__(
        self,
        scenario: ScenarioName,
        mode: ScenarioMode,
        *,
        vertex_config: VertexAdcPlannerConfig | None,
        run_id: str,
        progress_callback: ProgressCallback | None,
        cancellation_event: asyncio.Event | None,
    ) -> Awaitable[ScenarioWorkflowResult]: ...


class DurableScenarioCoordinator(Protocol):
    @property
    def provider_available(self) -> bool: ...

    async def bind_launch(
        self,
        launch: ScenarioLaunchRequest,
        *,
        snapshot: ScenarioRunSnapshot,
        accepted_event: ScenarioRunEvent,
    ) -> CreateScenarioWorkResult: ...

    async def audit_terminal_projection(self, investigation_id: str) -> None: ...

    async def get_operational_status(
        self,
        investigation_id: str,
    ) -> ScenarioOperationalStatus: ...


@dataclass(frozen=True, slots=True)
class LaunchScenarioResult:
    """Current snapshot plus whether this call first bound the launch ID."""

    snapshot: ScenarioRunSnapshot
    created: bool


@dataclass(frozen=True, slots=True)
class ScenarioRunEventSnapshot:
    """Atomic event suffix strictly after an exclusive cursor."""

    events: tuple[ScenarioRunEvent, ...]
    cursor: int
    terminal: bool


@dataclass(slots=True)
class _RunState:
    launch_bytes: bytes
    condition: asyncio.Condition
    snapshot_bytes: bytes
    events: list[bytes]
    cancellation_event: asyncio.Event
    generation: int = 0
    terminal: bool = False
    task: asyncio.Task[None] | None = None
    request_sequence: int = 0
    advisory_turn_sequence: int = 0
    advisory_turn_open: AdvisoryTurnSummary | None = None
    task_exit: Exception | None = None
    task_exit_notifier: asyncio.Task[None] | None = None


def _sealed[Model](value: Model, model_type: type[Model]) -> tuple[Model, bytes]:
    payload = canonical_json_bytes(value)  # type: ignore[arg-type]
    return decode_contract(payload, model_type), payload


def _scenario_name(value: ScenarioLaunchName) -> ScenarioName:
    return ScenarioName(value.value)


def _scenario_mode(value: ScenarioRunMode) -> ScenarioMode:
    return ScenarioMode(value.value)


def _sanitize_probe_audit(
    report: InvestigationReport,
) -> tuple[SanitizedProbeAuditRecord, ...]:
    return tuple(
        SanitizedProbeAuditRecord(
            probe_sequence=item.probe_sequence,
            capability_name=item.capability_name,
            capability_version=item.capability_version,
            request_sha256=item.request_sha256,
            outcome=item.outcome,
            stop_reason=item.stop_reason,
            started_at=item.started_at,
            completed_at=item.completed_at,
            session_elapsed_ms=item.session_elapsed_ms,
            probe_count_used=item.probe_count_used,
            cost_units_used=item.cost_units_used,
            result_bytes_acquired=item.result_bytes_acquired,
            result_sha256=item.result_sha256,
            result_byte_count=(
                item.result_byte_count
                if item.outcome is ProbeOutcome.COMPLETED
                else None
            ),
            evidence_ids=item.evidence_ids,
        )
        for item in report.probe_audit
    )


def _sanitize_evidence(
    report: InvestigationReport,
) -> tuple[SanitizedEvidenceSummary, ...]:
    retained = {item.evidence_id: item for item in report.evidence}
    audits = {
        evidence_id: audit
        for audit in report.probe_audit
        for evidence_id in audit.evidence_ids
    }
    summaries: list[SanitizedEvidenceSummary] = []
    for decision in report.evidence_decisions:
        evidence = retained.get(decision.evidence_id)
        audit = audits[decision.evidence_id]
        rejected = decision.disposition.value == "REJECTED"
        summaries.append(
            SanitizedEvidenceSummary(
                evidence_id=decision.evidence_id,
                capability_name=(
                    audit.capability_name
                    if evidence is None
                    else evidence.capability_name
                ),
                capability_version=(
                    audit.capability_version
                    if evidence is None
                    else evidence.capability_version
                ),
                disposition=decision.disposition,
                reason=decision.reason,
                authority=None if rejected or evidence is None else evidence.authority,
                effect_assertions=(
                    () if rejected or evidence is None else evidence.effect_assertions
                ),
                operation_status=(
                    None if rejected or evidence is None else evidence.operation_status
                ),
            )
        )
    return tuple(summaries)


def sanitize_report(report: InvestigationReport) -> SanitizedInvestigationReport:
    """Project a report without target coordinates, observations, or prose."""

    if type(report) is not InvestigationReport:
        raise TypeError("operator report projection requires an exact report")
    report = decode_contract(canonical_json_bytes(report), InvestigationReport)
    proof = report.proof
    sanitized_proof = (
        None
        if proof is None
        else SanitizedDeterministicProof(
            effect_findings=tuple(
                SanitizedEffectFinding(
                    effect_id=item.effect_id,
                    commit_scope=item.commit_scope,
                    state=item.state,
                    evidence_ids=item.evidence_ids,
                )
                for item in proof.effect_findings
            ),
            operation_status=proof.operation_status,
            conflicting_authority=proof.conflicting_authority,
            admitted_evidence_ids=proof.admitted_evidence_ids,
        )
    )
    projected = SanitizedInvestigationReport(
        investigation_id=report.investigation_id,
        envelope_sha256=report.envelope_sha256,
        status=report.status,
        probe_audit=_sanitize_probe_audit(report),
        evidence=_sanitize_evidence(report),
        proof=sanitized_proof,
        classification=report.classification,
        action_gate=report.action_gate,
        missing_evidence=tuple(
            SanitizedMissingEvidence(
                effect_ids=item.effect_ids,
                reason=item.reason,
            )
            for item in report.missing_evidence
        ),
        advisory_cited_evidence_ids=(
            ()
            if report.advisory_explanation is None
            else report.advisory_explanation.cited_evidence_ids
        ),
        route_provenance=bounded_hybrid_route_provenance(report),
        created_at=report.created_at,
        updated_at=report.updated_at,
        revision=report.revision,
    )
    return SanitizedInvestigationReport.model_validate_json(
        canonical_json_bytes(projected)
    )


def _sanitize_comparison_run(run: ComparisonRun) -> SanitizedComparisonRun:
    return SanitizedComparisonRun(
        strategy_kind=run.strategy_kind,
        strategy_version=run.strategy_version,
        plan_sha256=run.plan_sha256,
        report_sha256=run.report_sha256,
        classification=run.classification,
        planned_probe_count=run.planned_probe_count,
        executed_probe_count=run.executed_probe_count,
        controller_cost_units_used=run.controller_cost_units_used,
        controller_result_bytes_acquired=run.controller_result_bytes_acquired,
        total_elapsed_ms=run.total_elapsed_ms,
        time_to_sufficient_evidence_ms=run.time_to_sufficient_evidence_ms,
        stop_reason=run.stop_reason,
        unsupported_probe_count=run.unsupported_probe_count,
        unnecessary_probe_count=run.unnecessary_probe_count,
        duplicate_probe_count=run.duplicate_probe_count,
        explanation_completeness=run.explanation_completeness,
        model_usage=run.model_usage,
    )


def sanitize_comparison(
    comparison: InvestigationComparisonRecord,
) -> SanitizedInvestigationComparison:
    """Project neutral comparison measurements without expectation metadata."""

    if type(comparison) is not InvestigationComparisonRecord:
        raise TypeError("operator comparison projection requires an exact record")
    comparison = decode_contract(
        canonical_json_bytes(comparison),
        InvestigationComparisonRecord,
    )
    projected = SanitizedInvestigationComparison(
        comparison_id=comparison.comparison_id,
        envelope_sha256=comparison.envelope_sha256,
        baseline=_sanitize_comparison_run(comparison.baseline),
        adaptive=(
            None
            if comparison.adaptive is None
            else _sanitize_comparison_run(comparison.adaptive)
        ),
    )
    return SanitizedInvestigationComparison.model_validate_json(
        canonical_json_bytes(projected)
    )


class OperatorApplicationService:
    """Own scenario launch idempotency, tasks, snapshots, and event journals."""

    def __init__(
        self,
        *,
        runner: ScenarioWorkflowRunner = run_one,
        vertex_config: VertexAdcPlannerConfig | None = None,
        clock: Callable[[], datetime] | None = None,
        projection_store: ScenarioStore | None = None,
    ) -> None:
        if not callable(runner):
            raise TypeError("operator scenario runner must be callable")
        if vertex_config is not None:
            if type(vertex_config) is not VertexAdcPlannerConfig:
                raise TypeError("operator Vertex configuration must be exact")
            if vertex_config.credentials is not None:
                raise ValueError("operator Vertex configuration requires ambient ADC")
        self._runner = runner
        self._vertex_config = vertex_config
        self._clock = clock or (lambda: datetime.now(UTC))
        self._projection_store = projection_store
        coordinator = getattr(runner, "bind_launch", None)
        if projection_store is not None and not callable(coordinator):
            raise TypeError("durable operator runner must bind scenario launches")
        if projection_store is None and callable(coordinator):
            raise ValueError("durable operator runner requires a projection store")
        self._coordinator: DurableScenarioCoordinator | None = (
            None if projection_store is None else runner  # type: ignore[assignment]
        )
        self._registry_lock = asyncio.Lock()
        self._by_launch_id: dict[str, _RunState] = {}
        self._by_investigation_id: dict[str, _RunState] = {}
        self._closed = False
        self._close_task: asyncio.Task[None] | None = None

    @staticmethod
    def _terminal_projection_matches_authority(
        snapshot: ScenarioRunSnapshot,
        work: ScenarioWorkItem,
    ) -> bool:
        scenario_result = work.scenario_result
        workflow_result = work.workflow_result
        if (
            scenario_result is None
            or scenario_result.execution_envelope is None
            or workflow_result is None
            or snapshot.envelope_summary
            != _envelope_summary(scenario_result.execution_envelope)
        ):
            return False
        if type(workflow_result) is InvestigationReport:
            return (
                snapshot.report == sanitize_report(workflow_result)
                and snapshot.comparison is None
            )
        if type(workflow_result) is InvestigationComparisonRecord:
            return (
                snapshot.comparison == sanitize_comparison(workflow_result)
                and snapshot.report is None
            )
        return False

    @staticmethod
    def _journal_counters(
        events: tuple[ScenarioRunEvent, ...],
    ) -> tuple[int, int, AdvisoryTurnSummary | None]:
        request_sequence = 0
        advisory_turn_sequence = 0
        advisory_turn_open: AdvisoryTurnSummary | None = None
        for event in events:
            if isinstance(event.payload, ProbeRequestEventPayload):
                request_sequence += 1
                if event.payload.request.request_sequence != request_sequence:
                    raise RuntimeError("scenario request journal sequence is invalid")
            elif isinstance(event.payload, AdvisoryTurnEventPayload):
                turn = event.payload.turn
                if turn.status is AdvisoryTurnStatus.STARTED:
                    if (
                        advisory_turn_open is not None
                        or turn.turn_sequence != advisory_turn_sequence + 1
                    ):
                        raise RuntimeError(
                            "scenario advisory journal sequence is invalid"
                        )
                    advisory_turn_sequence = turn.turn_sequence
                    advisory_turn_open = turn
                elif (
                    advisory_turn_open is None
                    or turn.turn_sequence != advisory_turn_sequence
                    or turn.phase is not advisory_turn_open.phase
                    or turn.input_sha256 != advisory_turn_open.input_sha256
                ):
                    raise RuntimeError("scenario advisory journal sequence is invalid")
                else:
                    advisory_turn_open = None
        return (
            request_sequence,
            advisory_turn_sequence,
            advisory_turn_open,
        )

    async def start(self) -> None:
        """Reconnect durable snapshots and resume every nonterminal work item."""

        if self._projection_store is None:
            return
        work_items = await self._projection_store.list_work()
        async with self._registry_lock:
            if self._closed:
                raise OperatorServiceClosed
            for work in work_items:
                launch_id = work.launch_request.launch_id
                investigation_id = work.scenario_request.investigation_id
                if (
                    launch_id in self._by_launch_id
                    or investigation_id in self._by_investigation_id
                ):
                    raise RuntimeError("durable operator registry contains a collision")
                projection = await self._projection_store.snapshot_projection(
                    investigation_id
                )
                if projection.snapshot.envelope_summary is not None and (
                    work.scenario_result is None
                    or work.scenario_result.execution_envelope is None
                    or projection.snapshot.envelope_summary
                    != _envelope_summary(work.scenario_result.execution_envelope)
                ):
                    raise RuntimeError(
                        "scenario envelope projection contradicts private authority"
                    )
                (
                    request_sequence,
                    advisory_turn_sequence,
                    advisory_turn_open,
                ) = self._journal_counters(projection.events)
                if projection.terminal and advisory_turn_open is not None:
                    raise RuntimeError(
                        "terminal scenario has an unfinished advisory turn"
                    )
                state = _RunState(
                    launch_bytes=canonical_json_bytes(work.launch_request),
                    condition=asyncio.Condition(),
                    snapshot_bytes=canonical_json_bytes(projection.snapshot),
                    events=[canonical_json_bytes(event) for event in projection.events],
                    cancellation_event=asyncio.Event(),
                    generation=projection.cursor,
                    terminal=projection.terminal,
                    request_sequence=request_sequence,
                    advisory_turn_sequence=advisory_turn_sequence,
                    advisory_turn_open=advisory_turn_open,
                )
                self._by_launch_id[launch_id] = state
                self._by_investigation_id[investigation_id] = state
                if state.terminal:
                    await self._coordinator.audit_terminal_projection(investigation_id)  # type: ignore[union-attr]
                    audited = await self._projection_store.get_work(investigation_id)
                    if (
                        audited.investigation_state
                        is ScenarioInvestigationState.RECORDED
                        and projection.snapshot.lifecycle
                        is not ScenarioRunLifecycle.COMPLETED
                    ) or (
                        audited.investigation_state
                        is ScenarioInvestigationState.ESCALATION_REQUIRED
                        and projection.snapshot.lifecycle
                        is not ScenarioRunLifecycle.FAILED
                    ):
                        raise RuntimeError(
                            "terminal scenario projection contradicts private authority"
                        )
                    if (
                        audited.investigation_state
                        is ScenarioInvestigationState.RECORDED
                        and not self._terminal_projection_matches_authority(
                            projection.snapshot,
                            audited,
                        )
                    ):
                        raise RuntimeError(
                            "terminal scenario projection contradicts private result"
                        )
                else:
                    self._start_task(
                        state,
                        work.launch_request,
                        _scenario_name(work.launch_request.scenario),
                        _scenario_mode(work.launch_request.mode),
                    )

    async def __aenter__(self) -> OperatorApplicationService:
        if self._closed:
            raise OperatorServiceClosed
        return self

    async def __aexit__(self, *exc_info: object) -> None:
        await self.aclose()

    def _now(self, *, not_before: datetime | None = None) -> datetime:
        value = self._clock()
        if not isinstance(value, datetime):
            raise TypeError("operator clock must return a datetime")
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("operator clock must return an aware datetime")
        value = value.astimezone(UTC)
        if not_before is not None:
            value = max(value, not_before.astimezone(UTC))
        return value

    @staticmethod
    def _progress_time(value: datetime, *, not_before: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("progress timestamp must be aware")
        return max(value.astimezone(UTC), not_before.astimezone(UTC))

    async def launch(self, request: ScenarioLaunchRequest) -> LaunchScenarioResult:
        """Bind once, replay exact requests, and start one owned task."""

        if type(request) is not ScenarioLaunchRequest:
            raise TypeError("scenario launch requires an exact request")
        request, request_bytes = _sealed(request, ScenarioLaunchRequest)
        scenario = _scenario_name(request.scenario)
        mode = _scenario_mode(request.mode)
        investigation_id = scenario_investigation_id(scenario, request.launch_id)

        existing: _RunState | None = None
        async with self._registry_lock:
            if self._closed:
                raise OperatorServiceClosed
            existing = self._by_launch_id.get(request.launch_id)
            if existing is not None:
                if existing.launch_bytes != request_bytes:
                    snapshot = decode_contract(
                        existing.snapshot_bytes,
                        ScenarioRunSnapshot,
                    )
                    raise ScenarioLaunchConflict(
                        request.launch_id,
                        snapshot.investigation_id,
                    )
            else:
                collision = self._by_investigation_id.get(investigation_id)
                if collision is not None:
                    raise ScenarioLaunchConflict(request.launch_id, investigation_id)
                active_count = sum(
                    state.task is not None and not state.task.done()
                    for state in self._by_launch_id.values()
                )
                if (
                    active_count >= MAX_ACTIVE_SCENARIO_RUNS
                    or len(self._by_launch_id) >= MAX_RETAINED_SCENARIO_RUNS
                ):
                    raise OperatorCapacityExceeded
                accepted_at = self._now()
                event = ScenarioRunEvent(
                    schema_version=SCENARIO_RUN_EVENT_VERSION,
                    investigation_id=investigation_id,
                    cursor=1,
                    type=ScenarioRunEventType.LIFECYCLE,
                    occurred_at=accepted_at,
                    payload=ScenarioLifecycleEventPayload(
                        lifecycle=ScenarioRunLifecycle.ACCEPTED
                    ),
                )
                snapshot = ScenarioRunSnapshot(
                    schema_version=SCENARIO_RUN_SNAPSHOT_VERSION,
                    launch_id=request.launch_id,
                    investigation_id=investigation_id,
                    scenario=request.scenario,
                    mode=request.mode,
                    lifecycle=ScenarioRunLifecycle.ACCEPTED,
                    event_cursor=1,
                    envelope_summary=None,
                    report=None,
                    comparison=None,
                    failure_category=None,
                    accepted_at=accepted_at,
                    updated_at=accepted_at,
                )
                snapshot, snapshot_bytes = _sealed(snapshot, ScenarioRunSnapshot)
                _, event_bytes = _sealed(event, ScenarioRunEvent)
                state = _RunState(
                    launch_bytes=request_bytes,
                    condition=asyncio.Condition(),
                    snapshot_bytes=snapshot_bytes,
                    events=[event_bytes],
                    cancellation_event=asyncio.Event(),
                    generation=1,
                )
                if self._coordinator is not None:
                    try:
                        bound = await self._coordinator.bind_launch(
                            request,
                            snapshot=snapshot,
                            accepted_event=event,
                        )
                    except ScenarioWorkConflict as error:
                        raise ScenarioLaunchConflict(
                            error.launch_id,
                            error.investigation_id,
                        ) from error
                    if not bound.created:
                        projection = await self._projection_store.snapshot_projection(
                            investigation_id
                        )  # type: ignore[union-attr]
                        snapshot = projection.snapshot
                        state.snapshot_bytes = canonical_json_bytes(snapshot)
                        state.events = [
                            canonical_json_bytes(item) for item in projection.events
                        ]
                        state.generation = projection.cursor
                        state.terminal = projection.terminal
                self._by_launch_id[request.launch_id] = state
                self._by_investigation_id[investigation_id] = state
                if not state.terminal:
                    self._start_task(state, request, scenario, mode)
                return LaunchScenarioResult(
                    snapshot=snapshot,
                    created=(bound.created if self._coordinator is not None else True),
                )

        if existing is None:  # pragma: no cover - protected by the registry lock.
            raise RuntimeError("operator launch registry lost its state")
        if not existing.terminal and (existing.task is None or existing.task.done()):
            self._start_task(existing, request, scenario, mode)
        return LaunchScenarioResult(
            snapshot=await self._current_snapshot(existing),
            created=False,
        )

    async def launch_and_wait(
        self,
        request: ScenarioLaunchRequest,
    ) -> ScenarioRunSnapshot:
        """Launch or replay one scenario and join its exact terminal projection."""

        return (await self.launch_and_wait_result(request)).snapshot

    async def launch_and_wait_result(
        self,
        request: ScenarioLaunchRequest,
    ) -> LaunchScenarioResult:
        """Join one owned request and retain whether it first bound the launch."""

        if type(request) is not ScenarioLaunchRequest:
            raise TypeError("scenario launch requires an exact request")
        sealed_request, _ = _sealed(request, ScenarioLaunchRequest)
        investigation_id = scenario_investigation_id(
            _scenario_name(sealed_request.scenario),
            sealed_request.launch_id,
        )
        state: _RunState | None = None
        task: asyncio.Task[None] | None = None
        try:
            launched = await self.launch(sealed_request)
            state = await self._lookup(investigation_id)
            task = state.task
            if task is not None:
                await self._await_request_task(state, task)
            await self._settle_request_state(state, task, cancel=False)
            snapshot = await self._terminal_request_snapshot(state, investigation_id)
            return LaunchScenarioResult(snapshot=snapshot, created=launched.created)
        except asyncio.CancelledError:
            if state is not None:
                await self._settle_request_state(state, task, cancel=True)
            raise
        except (
            OperatorCapacityExceeded,
            OperatorServiceClosed,
            ScenarioLaunchConflict,
        ):
            if state is not None:
                await self._settle_request_state(state, task, cancel=True)
            raise
        except OperatorServiceUnavailable:
            if state is not None:
                await self._settle_request_state(state, task, cancel=True)
            raise OperatorServiceUnavailable(investigation_id) from None
        except Exception:
            if state is not None:
                await self._settle_request_state(state, task, cancel=True)
            raise OperatorServiceUnavailable(investigation_id) from None

    async def _await_request_task(
        self,
        state: _RunState,
        task: asyncio.Task[None],
    ) -> None:
        deadline_at: datetime | None = None
        while not task.done():
            async with state.condition:
                snapshot = decode_contract(
                    state.snapshot_bytes,
                    ScenarioRunSnapshot,
                )
                generation = state.generation
                if snapshot.envelope_summary is not None and deadline_at is None:
                    envelope_event: ScenarioRunEvent | None = None
                    for payload in state.events:
                        event = decode_contract(payload, ScenarioRunEvent)
                        if event.type is ScenarioRunEventType.ENVELOPE_SUMMARY:
                            if envelope_event is not None:
                                raise RuntimeError("duplicate envelope summary event")
                            envelope_event = event
                    if envelope_event is None or not isinstance(
                        envelope_event.payload,
                        EnvelopeSummaryEventPayload,
                    ):
                        raise RuntimeError("envelope summary event is unavailable")
                    lane_ceiling = 1 if snapshot.mode is ScenarioRunMode.FIXED else 2
                    deadline_at = (
                        envelope_event.occurred_at
                        + timedelta(
                            milliseconds=(
                                snapshot.envelope_summary.evidence_budget.max_elapsed_ms
                                * lane_ceiling
                            )
                        )
                        + _REQUEST_TERMINALIZATION_GRACE
                    )
            timeout: float | None = None
            if deadline_at is not None:
                timeout = (deadline_at - self._now()).total_seconds()
                if timeout <= 0:
                    raise TimeoutError

            change_task = asyncio.create_task(
                self._wait_for_change(state, generation, None)
            )
            try:
                done, _ = await asyncio.wait(
                    {task, change_task},
                    timeout=timeout,
                    return_when=asyncio.FIRST_COMPLETED,
                )
                if not done:
                    raise TimeoutError
            finally:
                if not change_task.done():
                    change_task.cancel()
                await asyncio.gather(change_task, return_exceptions=True)
        if task.cancelled():
            raise RuntimeError("operator request task was cancelled")
        failure = task.exception()
        if failure is not None:
            raise failure

    @staticmethod
    async def _join_request_tasks(
        tasks: tuple[asyncio.Task[None], ...],
    ) -> None:
        for task in tasks:
            while not task.done():
                try:
                    await asyncio.shield(task)
                except asyncio.CancelledError:
                    if task.done():
                        break
                    continue
                except Exception:
                    break
            if task.done():
                with suppress(asyncio.CancelledError):
                    task.exception()

    async def _settle_request_state(
        self,
        state: _RunState,
        task: asyncio.Task[None] | None,
        *,
        cancel: bool,
    ) -> None:
        current = state.task
        candidates = tuple(
            dict.fromkeys(item for item in (task, current) if item is not None)
        )
        if any(not item.done() for item in candidates):
            cancel = True
        if cancel:
            state.cancellation_event.set()
            for item in candidates:
                if not item.done():
                    item.cancel()
        if current in candidates:
            state.task = None
        notifier = state.task_exit_notifier
        state.task_exit_notifier = None
        await self._join_request_tasks(candidates)
        if notifier is not None:
            await self._join_request_tasks((notifier,))
        trailing = state.task_exit_notifier
        state.task_exit_notifier = None
        if trailing is not None:
            await self._join_request_tasks((trailing,))

    async def _terminal_request_snapshot(
        self,
        state: _RunState,
        investigation_id: str,
    ) -> ScenarioRunSnapshot:
        await self._refresh_durable_state(state, investigation_id)
        async with state.condition:
            terminal = state.terminal
            snapshot = decode_contract(
                state.snapshot_bytes,
                ScenarioRunSnapshot,
            )
        if not terminal or snapshot.lifecycle not in {
            ScenarioRunLifecycle.COMPLETED,
            ScenarioRunLifecycle.FAILED,
            ScenarioRunLifecycle.CANCELLED,
        }:
            raise OperatorServiceUnavailable(investigation_id)
        if self._coordinator is not None:
            await self._coordinator.audit_terminal_projection(investigation_id)
            work = await self._projection_store.get_work(investigation_id)  # type: ignore[union-attr]
            if (
                work.investigation_state is ScenarioInvestigationState.RECORDED
                and not self._terminal_projection_matches_authority(snapshot, work)
            ) or (
                work.investigation_state
                is ScenarioInvestigationState.ESCALATION_REQUIRED
                and snapshot.lifecycle is not ScenarioRunLifecycle.FAILED
            ):
                raise OperatorServiceUnavailable(investigation_id)
        return decode_contract(canonical_json_bytes(snapshot), ScenarioRunSnapshot)

    def _start_task(
        self,
        state: _RunState,
        request: ScenarioLaunchRequest,
        scenario: ScenarioName,
        mode: ScenarioMode,
    ) -> None:
        if state.task is not None and not state.task.done():
            return
        state.task_exit = None
        task = asyncio.create_task(
            self._execute(state, request, scenario, mode),
            name=f"reconcile-scenario-{scenario_investigation_id(scenario, request.launch_id)}",
        )
        state.task = task
        task.add_done_callback(partial(self._task_done, state))

    def _task_done(self, state: _RunState, task: asyncio.Task[None]) -> None:
        if state.task is not task:
            return
        state.task = None
        if task.cancelled():
            failure = RuntimeError(
                "operator task was cancelled before durable terminal state"
            )
        else:
            failure = task.exception() or RuntimeError(
                "operator task exited before durable terminal state"
            )
        if not self._closed and not state.terminal:
            state.task_exit = failure
            state.task_exit_notifier = asyncio.create_task(
                self._notify_task_exit(state)
            )

    @staticmethod
    async def _notify_task_exit(state: _RunState) -> None:
        async with state.condition:
            state.generation += 1
            state.condition.notify_all()

    @staticmethod
    def _raise_if_task_exited(
        state: _RunState,
        investigation_id: str,
    ) -> None:
        if not state.terminal and state.task_exit is not None:
            raise OperatorServiceUnavailable(investigation_id) from state.task_exit

    async def _lookup(self, investigation_id: str) -> _RunState:
        async with self._registry_lock:
            state = self._by_investigation_id.get(investigation_id)
        if state is not None:
            return state
        store = self._projection_store
        if store is None:
            raise ScenarioRunNotFound(investigation_id)
        try:
            work = await store.get_work(investigation_id)
            projection = await store.snapshot_projection(investigation_id)
            launch = work.launch_request
            snapshot = projection.snapshot
            if (
                work.scenario_request.investigation_id != investigation_id
                or snapshot.investigation_id != investigation_id
                or snapshot.launch_id != launch.launch_id
                or snapshot.scenario is not launch.scenario
                or snapshot.mode is not launch.mode
                or projection.cursor != len(projection.events)
                or snapshot.event_cursor != projection.cursor
            ):
                raise ValueError("durable operator projection identity changed")
            hydrated = _RunState(
                launch_bytes=canonical_json_bytes(launch),
                condition=asyncio.Condition(),
                snapshot_bytes=canonical_json_bytes(snapshot),
                events=[canonical_json_bytes(event) for event in projection.events],
                cancellation_event=asyncio.Event(),
                generation=projection.cursor,
                terminal=projection.terminal,
            )
        except asyncio.CancelledError:
            raise
        except ScenarioWorkNotFound:
            raise ScenarioRunNotFound(investigation_id) from None
        except Exception as error:
            raise OperatorServiceUnavailable(investigation_id) from error
        async with self._registry_lock:
            if self._closed:
                raise OperatorServiceClosed
            state = self._by_investigation_id.get(investigation_id)
            if state is not None:
                return state
            collision = self._by_launch_id.get(launch.launch_id)
            if collision is not None:
                raise OperatorServiceUnavailable(investigation_id)
            if len(self._by_launch_id) >= MAX_RETAINED_SCENARIO_RUNS:
                raise OperatorCapacityExceeded
            self._by_launch_id[launch.launch_id] = hydrated
            self._by_investigation_id[investigation_id] = hydrated
            return hydrated

    @staticmethod
    async def _current_snapshot(state: _RunState) -> ScenarioRunSnapshot:
        async with state.condition:
            payload = state.snapshot_bytes
        return decode_contract(payload, ScenarioRunSnapshot)

    async def _refresh_durable_state(
        self,
        state: _RunState,
        investigation_id: str,
    ) -> None:
        if self._projection_store is None:
            return
        projection = await self._projection_store.snapshot_projection(investigation_id)
        async with state.condition:
            snapshot_bytes = canonical_json_bytes(projection.snapshot)
            event_bytes = [canonical_json_bytes(event) for event in projection.events]
            if projection.cursor < len(state.events):
                return
            if projection.cursor == len(state.events) and state.events != event_bytes:
                raise RuntimeError("durable operator projection diverged")
            changed = (
                state.snapshot_bytes != snapshot_bytes
                or state.terminal != projection.terminal
            )
            state.snapshot_bytes = snapshot_bytes
            state.events = event_bytes
            state.terminal = projection.terminal
            if changed:
                state.generation += 1
                state.condition.notify_all()

    async def get(self, investigation_id: str) -> ScenarioRunSnapshot:
        """Return one isolated snapshot coherent with its event cursor."""

        state = await self._lookup(investigation_id)
        await self._refresh_durable_state(state, investigation_id)
        self._raise_if_task_exited(state, investigation_id)
        return await self._current_snapshot(state)

    async def get_operational_status(
        self,
        investigation_id: str,
    ) -> ScenarioOperationalStatus:
        """Return read-only durable state coherent with the v1 run identity."""

        state = await self._lookup(investigation_id)
        if self._coordinator is None:
            raise OperatorServiceUnavailable(investigation_id)
        try:
            await self._refresh_durable_state(state, investigation_id)
            snapshot = await self._current_snapshot(state)
            status = await self._coordinator.get_operational_status(investigation_id)
            if type(status) is not ScenarioOperationalStatus:
                raise TypeError("operational status must use the exact contract")
            status = decode_contract(
                canonical_json_bytes(status),
                ScenarioOperationalStatus,
            )
            if (
                status.launch_id != snapshot.launch_id
                or status.investigation_id != snapshot.investigation_id
                or status.scenario is not snapshot.scenario
                or status.mode is not snapshot.mode
                or status.updated_at < snapshot.updated_at
            ):
                raise ValueError("operational status contradicts the v1 identity")
            return status
        except asyncio.CancelledError:
            raise
        except Exception as error:
            raise OperatorServiceUnavailable(investigation_id) from error

    async def get_envelope_summary(
        self,
        investigation_id: str,
    ) -> ExecutionEnvelopeSummary:
        """Return the sanitized envelope once it has been journaled."""

        snapshot = await self.get(investigation_id)
        if snapshot.envelope_summary is None:
            raise ScenarioEnvelopeUnavailable(investigation_id)
        return decode_contract(
            canonical_json_bytes(snapshot.envelope_summary),
            ExecutionEnvelopeSummary,
        )

    @staticmethod
    def _validated_cursor(
        investigation_id: str,
        after: object,
        latest: int,
    ) -> int:
        if (
            isinstance(after, bool)
            or not isinstance(after, int)
            or after < 0
            or after > latest
        ):
            raise InvalidScenarioEventCursor(investigation_id, after, latest)
        return after

    @classmethod
    def _event_snapshot_locked(
        cls,
        state: _RunState,
        investigation_id: str,
        after: object,
    ) -> ScenarioRunEventSnapshot:
        latest = len(state.events)
        cursor = cls._validated_cursor(investigation_id, after, latest)
        events = tuple(
            decode_contract(payload, ScenarioRunEvent)
            for payload in state.events[cursor:]
        )
        return ScenarioRunEventSnapshot(
            events=events,
            cursor=latest,
            terminal=state.terminal,
        )

    async def snapshot(
        self,
        investigation_id: str,
        *,
        after: int = 0,
    ) -> ScenarioRunEventSnapshot:
        """Return accepted events strictly after an exclusive cursor."""

        state = await self._lookup(investigation_id)
        await self._refresh_durable_state(state, investigation_id)
        async with state.condition:
            snapshot = self._event_snapshot_locked(state, investigation_id, after)
            if not snapshot.events and not snapshot.terminal:
                self._raise_if_task_exited(state, investigation_id)
            return snapshot

    @staticmethod
    async def _wait_for_change(
        state: _RunState,
        generation: int,
        cancellation_event: asyncio.Event | None,
    ) -> None:
        async def changed() -> None:
            async with state.condition:
                await state.condition.wait_for(lambda: state.generation != generation)

        change_task = asyncio.create_task(changed())
        cancellation_task = (
            None
            if cancellation_event is None
            else asyncio.create_task(cancellation_event.wait())
        )
        tasks = (
            {change_task}
            if cancellation_task is None
            else {change_task, cancellation_task}
        )
        try:
            done, _ = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
            if (
                cancellation_task is not None
                and cancellation_task in done
                and cancellation_event is not None
                and cancellation_event.is_set()
            ):
                raise asyncio.CancelledError
            await change_task
        finally:
            for task in tasks:
                if not task.done():
                    task.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)

    async def wait_for_events(
        self,
        investigation_id: str,
        *,
        after: int = 0,
        cancellation_event: asyncio.Event | None = None,
    ) -> ScenarioRunEventSnapshot:
        """Wait without a snapshot race for a suffix or terminal state."""

        if cancellation_event is not None and type(cancellation_event) is not (
            asyncio.Event
        ):
            raise TypeError("scenario event cancellation must be an asyncio event")
        state = await self._lookup(investigation_id)
        while True:
            await self._refresh_durable_state(state, investigation_id)
            async with state.condition:
                snapshot = self._event_snapshot_locked(
                    state,
                    investigation_id,
                    after,
                )
                if snapshot.events or snapshot.terminal:
                    return snapshot
                self._raise_if_task_exited(state, investigation_id)
                if cancellation_event is not None and cancellation_event.is_set():
                    raise asyncio.CancelledError
                generation = state.generation
            if self._projection_store is None:
                await self._wait_for_change(state, generation, cancellation_event)
            else:
                try:
                    await asyncio.wait_for(
                        asyncio.sleep(0.05),
                        timeout=0.1,
                    )
                except TimeoutError:  # pragma: no cover - defensive timeout.
                    pass

    async def _append_transition(
        self,
        state: _RunState,
        *,
        event_type: ScenarioRunEventType,
        payload: ScenarioRunEventPayload,
        occurred_at: datetime,
        updates: dict[str, object] | None = None,
        terminal: bool = False,
    ) -> ScenarioRunSnapshot:
        async with state.condition:
            current = decode_contract(state.snapshot_bytes, ScenarioRunSnapshot)
            if state.terminal:
                raise ScenarioEventJournalTerminal(current.investigation_id)
            capacity = (
                MAX_SCENARIO_RUN_EVENTS if terminal else (MAX_SCENARIO_RUN_EVENTS - 1)
            )
            if len(state.events) >= capacity:
                raise ScenarioEventJournalFull(current.investigation_id)
            occurred_at = self._progress_time(
                occurred_at,
                not_before=current.updated_at,
            )
            cursor = len(state.events) + 1
            event = ScenarioRunEvent(
                schema_version=SCENARIO_RUN_EVENT_VERSION,
                investigation_id=current.investigation_id,
                cursor=cursor,
                type=event_type,
                occurred_at=occurred_at,
                payload=payload,
            )
            replacement_values = dict(updates or {})
            replacement_values.update(
                {"event_cursor": cursor, "updated_at": occurred_at}
            )
            replacement = current.model_copy(update=replacement_values)
            replacement, snapshot_bytes = _sealed(
                replacement,
                ScenarioRunSnapshot,
            )
            _, event_bytes = _sealed(event, ScenarioRunEvent)
            if self._projection_store is not None:
                await self._projection_store.append_projection(
                    replacement,
                    event,
                    terminal=terminal,
                )
            state.snapshot_bytes = snapshot_bytes
            state.events.append(event_bytes)
            state.generation += 1
            state.terminal = terminal
            state.condition.notify_all()
            return replacement

    async def _mark_running(self, state: _RunState) -> None:
        current = await self._current_snapshot(state)
        await self._append_transition(
            state,
            event_type=ScenarioRunEventType.LIFECYCLE,
            payload=ScenarioLifecycleEventPayload(
                lifecycle=ScenarioRunLifecycle.RUNNING
            ),
            occurred_at=self._now(not_before=current.updated_at),
            updates={"lifecycle": ScenarioRunLifecycle.RUNNING},
        )

    async def _project_progress(
        self,
        state: _RunState,
        progress: InvestigationProgress,
    ) -> None:
        if (
            progress.investigation_id
            != (await self._current_snapshot(state)).investigation_id
        ):
            raise ValueError("progress belongs to another investigation")
        if type(progress) is EnvelopeProgress:
            current = await self._current_snapshot(state)
            if current.envelope_summary is not None:
                if current.envelope_summary == progress.summary:
                    return
                raise ValueError("scenario emitted divergent envelope summaries")
            await self._append_transition(
                state,
                event_type=ScenarioRunEventType.ENVELOPE_SUMMARY,
                payload=EnvelopeSummaryEventPayload(summary=progress.summary),
                occurred_at=progress.occurred_at,
                updates={"envelope_summary": progress.summary},
            )
            return
        if type(progress) is StrategyProgress:
            return
        if type(progress) is AdvisoryProgress:
            await self._project_advisory_progress(state, progress)
            return
        if type(progress) is ProbeProgress:
            await self._project_probe_progress(state, progress)
            return
        if type(progress) is EvidenceProgress:
            await self._append_transition(
                state,
                event_type=ScenarioRunEventType.EVIDENCE_DECISION,
                payload=OperatorEvidenceDecisionEventPayload(
                    strategy=progress.strategy,
                    decision=EvidenceDecision(
                        schema_version=EVIDENCE_DECISION_VERSION,
                        evidence_id=progress.evidence_id,
                        disposition=progress.disposition,
                        reason=progress.reason,
                    ),
                ),
                occurred_at=progress.occurred_at,
            )
            return
        raise TypeError("operator received an unknown progress record")

    async def _next_request_sequence(self, state: _RunState) -> int:
        return state.request_sequence + 1

    async def _project_advisory_progress(
        self,
        state: _RunState,
        progress: AdvisoryProgress,
    ) -> None:
        if progress.stage is AdvisoryProgressStage.REQUESTED:
            status = AdvisoryTurnStatus.STARTED
        elif progress.cancelled:
            status = AdvisoryTurnStatus.CANCELLED
        elif progress.failure is not None:
            status = AdvisoryTurnStatus.FAILED
        else:
            status = AdvisoryTurnStatus.COMPLETED
        failure = (
            None
            if progress.failure is None
            else AdvisoryTurnFailureCategory(progress.failure.value)
        )
        turn = AdvisoryTurnSummary(
            turn_sequence=progress.turn_sequence,
            phase=progress.phase,
            status=status,
            input_sha256=progress.input_sha256,
            output_sha256=progress.output_sha256,
            proposal_count=len(progress.proposals),
            selected_proposal_count=sum(
                proposal.disposition.value == "selected"
                for proposal in progress.proposals
            ),
            failure_category=failure,
        )
        if status is AdvisoryTurnStatus.STARTED:
            if (
                state.advisory_turn_open is not None
                or turn.turn_sequence != state.advisory_turn_sequence + 1
            ):
                raise ValueError("scenario advisory progress sequence is invalid")
        elif (
            state.advisory_turn_open is None
            or turn.turn_sequence != state.advisory_turn_sequence
            or turn.phase is not state.advisory_turn_open.phase
            or turn.input_sha256 != state.advisory_turn_open.input_sha256
        ):
            raise ValueError("scenario advisory progress sequence is invalid")
        await self._append_transition(
            state,
            event_type=ScenarioRunEventType.ADVISORY_TURN,
            payload=AdvisoryTurnEventPayload(turn=turn),
            occurred_at=progress.occurred_at,
        )
        if status is AdvisoryTurnStatus.STARTED:
            state.advisory_turn_sequence = turn.turn_sequence
            state.advisory_turn_open = turn
            return
        state.advisory_turn_open = None
        for proposal in progress.proposals:
            request_sequence = await self._next_request_sequence(state)
            await self._append_transition(
                state,
                event_type=ScenarioRunEventType.PROBE_REQUEST,
                payload=ProbeRequestEventPayload(
                    strategy=ComparisonStrategyKind.ADAPTIVE,
                    request=SanitizedProbeRequest(
                        request_sequence=request_sequence,
                        advisory_turn_sequence=progress.turn_sequence,
                        proposal_sequence=proposal.proposal_sequence,
                        capability_name=proposal.capability_name,
                        capability_version=proposal.capability_version,
                        request_sha256=proposal.request_sha256,
                        relevant_effect_ids=proposal.relevant_effect_ids,
                        disposition=ProbeRequestDisposition(proposal.disposition.value),
                    ),
                ),
                occurred_at=progress.occurred_at,
            )
            state.request_sequence = request_sequence

    async def _project_probe_progress(
        self,
        state: _RunState,
        progress: ProbeProgress,
    ) -> None:
        if progress.stage is ProbeProgressStage.REQUESTED:
            if progress.strategy is ComparisonStrategyKind.ADAPTIVE:
                return
            request_sequence = await self._next_request_sequence(state)
            await self._append_transition(
                state,
                event_type=ScenarioRunEventType.PROBE_REQUEST,
                payload=ProbeRequestEventPayload(
                    strategy=progress.strategy,
                    request=SanitizedProbeRequest(
                        request_sequence=request_sequence,
                        advisory_turn_sequence=None,
                        proposal_sequence=None,
                        capability_name=progress.capability_name,
                        capability_version=progress.capability_version,
                        request_sha256=progress.request_sha256,
                        relevant_effect_ids=progress.relevant_effect_ids,
                        disposition=ProbeRequestDisposition.SELECTED,
                    ),
                ),
                occurred_at=progress.occurred_at,
            )
            state.request_sequence = request_sequence
            return
        if progress.controller_sequence_reused:
            return
        await self._append_transition(
            state,
            event_type=ScenarioRunEventType.PROBE_RESULT,
            payload=ProbeResultEventPayload(
                strategy=progress.strategy,
                probe=SanitizedProbeResult(
                    probe_sequence=progress.controller_sequence,
                    capability_name=progress.capability_name,
                    capability_version=progress.capability_version,
                    request_sha256=progress.request_sha256,
                    outcome=progress.outcome,
                    stop_reason=progress.controller_stop_reason.value,
                    result_sha256=progress.result_sha256,
                    result_byte_count=progress.result_byte_count,
                    evidence_ids=progress.evidence_ids,
                ),
            ),
            occurred_at=progress.occurred_at,
        )

    async def _execute(
        self,
        state: _RunState,
        request: ScenarioLaunchRequest,
        scenario: ScenarioName,
        mode: ScenarioMode,
    ) -> None:
        try:
            current = await self._current_snapshot(state)
            if current.lifecycle is ScenarioRunLifecycle.ACCEPTED:
                await self._mark_running(state)
            elif current.lifecycle is not ScenarioRunLifecycle.RUNNING:
                return
            if (
                mode is ScenarioMode.COMPARE
                and self._vertex_config is None
                and (
                    self._coordinator is None
                    or not self._coordinator.provider_available
                )
            ):
                await self._terminal_failure(
                    state,
                    ScenarioRunFailureCategory.MODEL_UNAVAILABLE,
                )
                return
            result = await self._runner(
                scenario,
                mode,
                vertex_config=(
                    None if mode is ScenarioMode.FIXED else self._vertex_config
                ),
                run_id=request.launch_id,
                progress_callback=partial(self._project_progress, state),
                cancellation_event=state.cancellation_event,
            )
            if state.cancellation_event.is_set():
                await self._terminal_cancelled(state)
                return
            await self._terminal_completed(state, result)
        except asyncio.CancelledError:
            if self._projection_store is None:
                await asyncio.shield(self._terminal_cancelled(state))
            raise
        except ProgressDeliveryError:
            await self._terminal_failure(
                state,
                ScenarioRunFailureCategory.EVENT_JOURNAL_FAILED,
            )
        except ScenarioWorkflowError as error:
            await self._terminal_failure(state, self._failure_category(error))
        except Exception:
            await self._terminal_failure(
                state,
                ScenarioRunFailureCategory.INTERNAL_FAILURE,
            )

    @staticmethod
    def _failure_category(
        error: ScenarioWorkflowError,
    ) -> ScenarioRunFailureCategory:
        return {
            ScenarioWorkflowErrorCategory.INVALID_CONFIGURATION: (
                ScenarioRunFailureCategory.INVALID_CONFIGURATION
            ),
            ScenarioWorkflowErrorCategory.SCENARIO_EXECUTION_FAILED: (
                ScenarioRunFailureCategory.SCENARIO_EXECUTION_FAILED
            ),
            ScenarioWorkflowErrorCategory.PROVIDER_FAILED: (
                ScenarioRunFailureCategory.MODEL_UNAVAILABLE
            ),
            ScenarioWorkflowErrorCategory.CLEANUP_FAILED: (
                ScenarioRunFailureCategory.CLEANUP_FAILED
            ),
            ScenarioWorkflowErrorCategory.COMPARISON_UNREPRESENTABLE: (
                ScenarioRunFailureCategory.COMPARISON_UNREPRESENTABLE
            ),
        }[error.category]

    async def _terminal_completed(
        self,
        state: _RunState,
        result: ScenarioWorkflowResult,
    ) -> None:
        current = await self._current_snapshot(state)
        if state.advisory_turn_open is not None:
            raise ValueError("completed scenario has an unfinished advisory turn")
        if current.envelope_summary is None:
            raise ValueError("completed scenario omitted its envelope summary")
        if type(result) is InvestigationReport:
            if current.mode is ScenarioRunMode.COMPARE:
                raise TypeError("comparison mode returned a report")
            report = sanitize_report(result)
            if (
                report.status is not InvestigationStatus.COMPLETED
                or report.investigation_id != current.investigation_id
                or report.envelope_sha256 != current.envelope_summary.envelope_sha256
                or report.classification is None
            ):
                raise ValueError("scenario report does not match its launch")
            allowed = sum(gate.allowed for gate in report.action_gate)
            terminal = TerminalStateSummary(
                lifecycle=ScenarioRunLifecycle.COMPLETED,
                result_kind=ScenarioRunResultKind.REPORT,
                classification=report.classification,
                action_gate_allowed_count=allowed,
                action_gate_denied_count=len(report.action_gate) - allowed,
                missing_evidence_count=len(report.missing_evidence),
                escalation_required=(report.classification.value != "COMMITTED"),
                failure_category=None,
                route_provenance=report.route_provenance,
            )
            updates: dict[str, object] = {
                "lifecycle": ScenarioRunLifecycle.COMPLETED,
                "report": report,
                "comparison": None,
                "failure_category": None,
            }
        elif type(result) is InvestigationComparisonRecord:
            if current.mode is not ScenarioRunMode.COMPARE:
                raise TypeError("non-comparison mode returned a comparison")
            comparison = sanitize_comparison(result)
            if (
                comparison.adaptive is None
                or comparison.envelope_sha256
                != current.envelope_summary.envelope_sha256
            ):
                await self._terminal_failure(
                    state,
                    ScenarioRunFailureCategory.COMPARISON_UNREPRESENTABLE,
                )
                return
            terminal = TerminalStateSummary(
                lifecycle=ScenarioRunLifecycle.COMPLETED,
                result_kind=ScenarioRunResultKind.COMPARISON,
                classification=None,
                action_gate_allowed_count=0,
                action_gate_denied_count=0,
                missing_evidence_count=0,
                escalation_required=None,
                failure_category=None,
            )
            updates = {
                "lifecycle": ScenarioRunLifecycle.COMPLETED,
                "report": None,
                "comparison": comparison,
                "failure_category": None,
            }
        else:
            raise TypeError("scenario runner returned an unsupported result")
        await self._append_transition(
            state,
            event_type=ScenarioRunEventType.TERMINAL,
            payload=TerminalStateEventPayload(terminal=terminal),
            occurred_at=self._now(not_before=current.updated_at),
            updates=updates,
            terminal=True,
        )

    async def _terminal_failure(
        self,
        state: _RunState,
        category: ScenarioRunFailureCategory,
    ) -> None:
        current = await self._current_snapshot(state)
        if current.lifecycle in {
            ScenarioRunLifecycle.COMPLETED,
            ScenarioRunLifecycle.FAILED,
            ScenarioRunLifecycle.CANCELLED,
        }:
            return
        await self._close_open_advisory(
            state,
            status=AdvisoryTurnStatus.FAILED,
        )
        current = await self._current_snapshot(state)
        await self._append_transition(
            state,
            event_type=ScenarioRunEventType.TERMINAL,
            payload=TerminalStateEventPayload(
                terminal=TerminalStateSummary(
                    lifecycle=ScenarioRunLifecycle.FAILED,
                    result_kind=ScenarioRunResultKind.NONE,
                    classification=None,
                    action_gate_allowed_count=0,
                    action_gate_denied_count=0,
                    missing_evidence_count=0,
                    escalation_required=None,
                    failure_category=category,
                )
            ),
            occurred_at=self._now(not_before=current.updated_at),
            updates={
                "lifecycle": ScenarioRunLifecycle.FAILED,
                "report": None,
                "comparison": None,
                "failure_category": category,
            },
            terminal=True,
        )

    async def _terminal_cancelled(self, state: _RunState) -> None:
        current = await self._current_snapshot(state)
        if current.lifecycle in {
            ScenarioRunLifecycle.COMPLETED,
            ScenarioRunLifecycle.FAILED,
            ScenarioRunLifecycle.CANCELLED,
        }:
            return
        await self._close_open_advisory(
            state,
            status=AdvisoryTurnStatus.CANCELLED,
        )
        current = await self._current_snapshot(state)
        await self._append_transition(
            state,
            event_type=ScenarioRunEventType.TERMINAL,
            payload=TerminalStateEventPayload(
                terminal=TerminalStateSummary(
                    lifecycle=ScenarioRunLifecycle.CANCELLED,
                    result_kind=ScenarioRunResultKind.NONE,
                    classification=None,
                    action_gate_allowed_count=0,
                    action_gate_denied_count=0,
                    missing_evidence_count=0,
                    escalation_required=None,
                    failure_category=None,
                )
            ),
            occurred_at=self._now(not_before=current.updated_at),
            updates={
                "lifecycle": ScenarioRunLifecycle.CANCELLED,
                "report": None,
                "comparison": None,
                "failure_category": None,
            },
            terminal=True,
        )

    async def _close_open_advisory(
        self,
        state: _RunState,
        *,
        status: AdvisoryTurnStatus,
    ) -> None:
        opened = state.advisory_turn_open
        if opened is None:
            return
        if status not in {
            AdvisoryTurnStatus.FAILED,
            AdvisoryTurnStatus.CANCELLED,
        }:
            raise ValueError("open advisory requires a failure or cancellation")
        current = await self._current_snapshot(state)
        turn = AdvisoryTurnSummary(
            turn_sequence=opened.turn_sequence,
            phase=opened.phase,
            status=status,
            input_sha256=opened.input_sha256,
            output_sha256=None,
            proposal_count=0,
            selected_proposal_count=0,
            failure_category=(
                AdvisoryTurnFailureCategory.UNAVAILABLE
                if status is AdvisoryTurnStatus.FAILED
                else None
            ),
        )
        await self._append_transition(
            state,
            event_type=ScenarioRunEventType.ADVISORY_TURN,
            payload=AdvisoryTurnEventPayload(turn=turn),
            occurred_at=self._now(not_before=current.updated_at),
        )
        state.advisory_turn_open = None

    async def _finish_close(
        self,
        active: tuple[tuple[_RunState, asyncio.Task[None]], ...],
    ) -> None:
        if not active:
            return
        await asyncio.gather(
            *(task for _, task in active),
            return_exceptions=True,
        )
        if self._projection_store is None:
            for state, _ in active:
                await self._terminal_cancelled(state)

    @staticmethod
    async def _join_close_task(task: asyncio.Task[None]) -> None:
        try:
            await asyncio.shield(task)
        except asyncio.CancelledError:
            while not task.done():
                try:
                    await asyncio.shield(task)
                except asyncio.CancelledError:
                    continue
                except BaseException:
                    break
            with suppress(asyncio.CancelledError):
                task.exception()
            raise

    async def aclose(self) -> None:
        """Cancel and join every owned run; no task survives service shutdown."""

        async with self._registry_lock:
            if self._close_task is None:
                self._closed = True
                active = tuple(
                    (state, state.task)
                    for state in self._by_launch_id.values()
                    if state.task is not None and not state.task.done()
                )
                for state, task in active:
                    state.cancellation_event.set()
                    task.cancel()
                self._close_task = asyncio.create_task(
                    self._finish_close(active),
                    name="reconcile-operator-shutdown",
                )
            close_task = self._close_task
        await self._join_close_task(close_task)


__all__ = [
    "MAX_ACTIVE_SCENARIO_RUNS",
    "MAX_RETAINED_SCENARIO_RUNS",
    "InvalidScenarioEventCursor",
    "LaunchScenarioResult",
    "OperatorApplicationService",
    "OperatorCapacityExceeded",
    "OperatorServiceClosed",
    "OperatorServiceError",
    "OperatorServiceUnavailable",
    "ScenarioEnvelopeUnavailable",
    "ScenarioEventJournalFull",
    "ScenarioEventJournalTerminal",
    "ScenarioLaunchConflict",
    "ScenarioRunEventSnapshot",
    "ScenarioRunNotFound",
    "ScenarioWorkflowRunner",
    "sanitize_comparison",
    "sanitize_report",
]
