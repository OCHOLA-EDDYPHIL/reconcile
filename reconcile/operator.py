"""Single-process operator service for canonical scenario investigations."""

from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable
from contextlib import suppress
from dataclasses import dataclass
from datetime import UTC, datetime
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
    run_one,
    scenario_investigation_id,
)

MAX_ACTIVE_SCENARIO_RUNS = 4
MAX_RETAINED_SCENARIO_RUNS = 64


class OperatorServiceError(Exception):
    """Base class for deterministic operator-service boundary failures."""


class OperatorServiceClosed(OperatorServiceError):
    """New scenario launches are not accepted after service shutdown."""


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
        self._registry_lock = asyncio.Lock()
        self._by_launch_id: dict[str, _RunState] = {}
        self._by_investigation_id: dict[str, _RunState] = {}
        self._closed = False
        self._close_task: asyncio.Task[None] | None = None

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
                self._by_launch_id[request.launch_id] = state
                self._by_investigation_id[investigation_id] = state
                task = asyncio.create_task(
                    self._execute(state, request, scenario, mode),
                    name=f"reconcile-scenario-{investigation_id}",
                )
                state.task = task
                task.add_done_callback(partial(self._task_done, state))
                return LaunchScenarioResult(snapshot=snapshot, created=True)

        if existing is None:  # pragma: no cover - protected by the registry lock.
            raise RuntimeError("operator launch registry lost its state")
        return LaunchScenarioResult(
            snapshot=await self._current_snapshot(existing),
            created=False,
        )

    def _task_done(self, state: _RunState, task: asyncio.Task[None]) -> None:
        if state.task is task:
            state.task = None
        with suppress(asyncio.CancelledError):
            task.exception()

    async def _lookup(self, investigation_id: str) -> _RunState:
        async with self._registry_lock:
            state = self._by_investigation_id.get(investigation_id)
        if state is None:
            raise ScenarioRunNotFound(investigation_id)
        return state

    @staticmethod
    async def _current_snapshot(state: _RunState) -> ScenarioRunSnapshot:
        async with state.condition:
            payload = state.snapshot_bytes
        return decode_contract(payload, ScenarioRunSnapshot)

    async def get(self, investigation_id: str) -> ScenarioRunSnapshot:
        """Return one isolated snapshot coherent with its event cursor."""

        return await self._current_snapshot(await self._lookup(investigation_id))

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
        async with state.condition:
            return self._event_snapshot_locked(state, investigation_id, after)

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
            async with state.condition:
                snapshot = self._event_snapshot_locked(
                    state,
                    investigation_id,
                    after,
                )
                if snapshot.events or snapshot.terminal:
                    return snapshot
                if cancellation_event is not None and cancellation_event.is_set():
                    raise asyncio.CancelledError
                generation = state.generation
            await self._wait_for_change(state, generation, cancellation_event)

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
        next_sequence = state.request_sequence + 1
        state.request_sequence = next_sequence
        return next_sequence

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
        await self._append_transition(
            state,
            event_type=ScenarioRunEventType.ADVISORY_TURN,
            payload=AdvisoryTurnEventPayload(
                turn=AdvisoryTurnSummary(
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
            ),
            occurred_at=progress.occurred_at,
        )
        if progress.stage is AdvisoryProgressStage.REQUESTED:
            return
        for proposal in progress.proposals:
            await self._append_transition(
                state,
                event_type=ScenarioRunEventType.PROBE_REQUEST,
                payload=ProbeRequestEventPayload(
                    strategy=ComparisonStrategyKind.ADAPTIVE,
                    request=SanitizedProbeRequest(
                        request_sequence=await self._next_request_sequence(state),
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

    async def _project_probe_progress(
        self,
        state: _RunState,
        progress: ProbeProgress,
    ) -> None:
        if progress.stage is ProbeProgressStage.REQUESTED:
            if progress.strategy is ComparisonStrategyKind.ADAPTIVE:
                return
            await self._append_transition(
                state,
                event_type=ScenarioRunEventType.PROBE_REQUEST,
                payload=ProbeRequestEventPayload(
                    strategy=progress.strategy,
                    request=SanitizedProbeRequest(
                        request_sequence=await self._next_request_sequence(state),
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
            await self._mark_running(state)
            if mode is not ScenarioMode.FIXED and self._vertex_config is None:
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
