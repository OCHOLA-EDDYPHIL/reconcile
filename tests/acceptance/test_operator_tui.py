"""Headless operator journeys across the API-only terminal boundary."""

from __future__ import annotations

import asyncio
from collections import deque
from collections.abc import AsyncIterator
from dataclasses import dataclass, field
from datetime import timedelta

import pytest
from textual.containers import VerticalScroll
from textual.widgets import Button, Input, Select, Static, TabbedContent

from reconcile.contracts import (
    BOUNDED_HYBRID_ROUTE_POLICY_VERSION,
    EVIDENCE_DECISION_VERSION,
    EXECUTION_ENVELOPE_SUMMARY_VERSION,
    SCENARIO_OPERATIONAL_STATUS_VERSION,
    SCENARIO_RUN_EVENT_VERSION,
    SCENARIO_RUN_SNAPSHOT_VERSION,
    AdaptivePlannerPhase,
    AdvisoryTurnEventPayload,
    AdvisoryTurnStatus,
    AdvisoryTurnSummary,
    Classification,
    ComparisonRun,
    ComparisonStrategyKind,
    EnvelopeEffectSummary,
    EnvelopeSummaryEventPayload,
    EvidenceDecision,
    EvidenceDisposition,
    EvidenceReason,
    ExecutionEnvelope,
    ExecutionEnvelopeSummary,
    InvestigationReport,
    OperatorEvidenceDecisionEventPayload,
    ProbeOutcome,
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
    ScenarioHybridOutcome,
    ScenarioHybridRoute,
    ScenarioLaunchName,
    ScenarioLaunchRequest,
    ScenarioLifecycleEventPayload,
    ScenarioOperationalCleanupState,
    ScenarioOperationalInvestigationState,
    ScenarioOperationalMutationState,
    ScenarioOperationalRecoveryState,
    ScenarioOperationalStatus,
    ScenarioRouteProvenance,
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
    canonical_sha256,
)
from reconcile.interfaces.api_client import (
    InvestigationNotFoundError,
    RemoteProtocolError,
    ServiceUnavailableError,
    TransportError,
)
from reconcile.interfaces.operator_api_client import StreamInterruptedError
from reconcile.interfaces.tui import ReconcileApp
from reconcile.interfaces.tui_state import ConnectionPhase
from tests.contract._factories import (
    NOW,
    make_comparison_record,
    make_envelope,
    make_report,
)

pytestmark = pytest.mark.acceptance


@dataclass(frozen=True, slots=True)
class _LaunchResult:
    created: bool
    snapshot: ScenarioRunSnapshot


@dataclass(slots=True)
class _StreamPlan:
    events: tuple[ScenarioRunEvent, ...]
    pause_after: int | None = None
    error: Exception | None = None
    paused: asyncio.Event = field(default_factory=asyncio.Event)
    release: asyncio.Event = field(default_factory=asyncio.Event)
    cancelled: bool = False


@dataclass(slots=True)
class _LaunchGate:
    started: asyncio.Event = field(default_factory=asyncio.Event)
    release: asyncio.Event = field(default_factory=asyncio.Event)
    cancelled: bool = False


class _ScriptedClient:
    def __init__(
        self,
        *,
        launch: ScenarioRunSnapshot | Exception | None = None,
        snapshots: tuple[ScenarioRunSnapshot | Exception, ...] = (),
        statuses: tuple[ScenarioOperationalStatus | Exception, ...] = (),
        streams: tuple[_StreamPlan, ...] = (),
        created: bool = True,
        launch_gate: _LaunchGate | None = None,
    ) -> None:
        self._launch = launch
        self._snapshots = deque(snapshots)
        self._statuses = deque(statuses)
        self._streams = deque(streams)
        self._created = created
        self._launch_gate = launch_gate
        self.calls: list[tuple[object, ...]] = []
        self.close_count = 0

    async def launch(self, request: ScenarioLaunchRequest) -> _LaunchResult:
        self.calls.append(("launch", request))
        if self._launch_gate is not None:
            self._launch_gate.started.set()
            try:
                await self._launch_gate.release.wait()
            except asyncio.CancelledError:
                self._launch_gate.cancelled = True
                raise
        if isinstance(self._launch, Exception):
            raise self._launch
        if self._launch is None:
            raise AssertionError("unexpected launch")
        return _LaunchResult(created=self._created, snapshot=self._launch)

    async def get_snapshot(self, investigation_id: str) -> ScenarioRunSnapshot:
        self.calls.append(("get_snapshot", investigation_id))
        if not self._snapshots:
            raise AssertionError("unexpected snapshot read")
        result = self._snapshots.popleft()
        if isinstance(result, Exception):
            raise result
        return result

    async def get_operational_status(
        self,
        investigation_id: str,
    ) -> ScenarioOperationalStatus:
        self.calls.append(("get_operational_status", investigation_id))
        if not self._statuses:
            raise ServiceUnavailableError()
        result = self._statuses.popleft()
        if isinstance(result, Exception):
            raise result
        return result

    def events(
        self,
        investigation_id: str,
        *,
        after: int = 0,
        max_reconnects: int = 3,
    ) -> AsyncIterator[ScenarioRunEvent]:
        self.calls.append(("events", investigation_id, after, max_reconnects))
        if not self._streams:
            raise AssertionError("unexpected event stream")
        plan = self._streams.popleft()

        async def iterate() -> AsyncIterator[ScenarioRunEvent]:
            try:
                for index, event in enumerate(plan.events, start=1):
                    yield event
                    if plan.pause_after == index:
                        plan.paused.set()
                        await plan.release.wait()
                if plan.error is not None:
                    raise plan.error
            except asyncio.CancelledError:
                plan.cancelled = True
                raise

        return iterate()

    async def aclose(self) -> None:
        self.calls.append(("close",))
        self.close_count += 1


class _ClipboardApp(ReconcileApp):
    def __init__(self, *, client: _ScriptedClient) -> None:
        super().__init__(client=client)
        self.copied: list[str] = []

    def copy_to_clipboard(self, text: str) -> None:
        self.copied.append(text)


def _envelope(investigation_id: str) -> ExecutionEnvelope:
    payload = make_envelope().model_dump(mode="python")
    payload["investigation_id"] = investigation_id
    return ExecutionEnvelope.model_validate(payload)


def _summary(investigation_id: str) -> ExecutionEnvelopeSummary:
    envelope = _envelope(investigation_id)
    return ExecutionEnvelopeSummary(
        schema_version=EXECUTION_ENVELOPE_SUMMARY_VERSION,
        investigation_id=investigation_id,
        envelope_sha256=canonical_sha256(envelope),
        target_kind=envelope.target.target_kind,
        invoked_at=envelope.invoked_at,
        ambiguity_kind=envelope.ambiguity.kind,
        ambiguity_observed_at=envelope.ambiguity.observed_at,
        expected_effects=tuple(
            EnvelopeEffectSummary(
                effect_id=item.effect_id,
                commit_scope=item.commit_scope,
            )
            for item in envelope.expected_effects
        ),
        enabled_capabilities=envelope.context.enabled_capabilities,
        evidence_budget=envelope.context.evidence_budget,
    )


def _sanitized_report(
    classification: Classification,
    investigation_id: str,
    *,
    route_provenance: ScenarioRouteProvenance | None = None,
) -> SanitizedInvestigationReport:
    payload = make_report(classification).model_dump(mode="python")
    payload["investigation_id"] = investigation_id
    payload["envelope_sha256"] = _summary(investigation_id).envelope_sha256
    report = InvestigationReport.model_validate(payload)
    decisions = {item.evidence_id: item for item in report.evidence_decisions}
    proof = report.proof
    return SanitizedInvestigationReport(
        investigation_id=report.investigation_id,
        envelope_sha256=report.envelope_sha256,
        status=report.status,
        probe_audit=tuple(
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
                result_byte_count=item.result_byte_count,
                evidence_ids=item.evidence_ids,
            )
            for item in report.probe_audit
        ),
        evidence=tuple(
            SanitizedEvidenceSummary(
                evidence_id=item.evidence_id,
                capability_name=item.capability_name,
                capability_version=item.capability_version,
                disposition=decisions[item.evidence_id].disposition,
                reason=decisions[item.evidence_id].reason,
                authority=item.authority,
                effect_assertions=item.effect_assertions,
                operation_status=item.operation_status,
            )
            for item in report.evidence
        ),
        proof=(
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
        ),
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
        route_provenance=route_provenance,
        created_at=report.created_at,
        updated_at=report.updated_at,
        revision=report.revision,
    )


def _sanitized_comparison_run(run: ComparisonRun) -> SanitizedComparisonRun:
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


def _active_snapshot(
    *,
    scenario: ScenarioLaunchName,
    mode: ScenarioRunMode,
    launch_id: str,
    investigation_id: str,
    event_cursor: int,
    include_summary: bool = True,
) -> ScenarioRunSnapshot:
    return ScenarioRunSnapshot(
        schema_version=SCENARIO_RUN_SNAPSHOT_VERSION,
        launch_id=launch_id,
        investigation_id=investigation_id,
        scenario=scenario,
        mode=mode,
        lifecycle=ScenarioRunLifecycle.RUNNING,
        event_cursor=event_cursor,
        envelope_summary=_summary(investigation_id) if include_summary else None,
        report=None,
        comparison=None,
        failure_category=None,
        accepted_at=NOW,
        updated_at=NOW + timedelta(seconds=1),
    )


def _completed_report_snapshot(
    *,
    classification: Classification,
    scenario: ScenarioLaunchName,
    launch_id: str,
    investigation_id: str,
    event_cursor: int = 3,
    mode: ScenarioRunMode = ScenarioRunMode.FIXED,
    route_provenance: ScenarioRouteProvenance | None = None,
) -> ScenarioRunSnapshot:
    return ScenarioRunSnapshot(
        schema_version=SCENARIO_RUN_SNAPSHOT_VERSION,
        launch_id=launch_id,
        investigation_id=investigation_id,
        scenario=scenario,
        mode=mode,
        lifecycle=ScenarioRunLifecycle.COMPLETED,
        event_cursor=event_cursor,
        envelope_summary=_summary(investigation_id),
        report=_sanitized_report(
            classification,
            investigation_id,
            route_provenance=route_provenance,
        ),
        comparison=None,
        failure_category=None,
        accepted_at=NOW,
        updated_at=NOW + timedelta(seconds=6),
    )


def _completed_comparison_snapshot(
    *,
    launch_id: str,
    investigation_id: str,
    event_cursor: int = 3,
) -> ScenarioRunSnapshot:
    source = make_comparison_record(include_adaptive=True)
    assert source.adaptive is not None
    comparison = SanitizedInvestigationComparison(
        comparison_id=source.comparison_id,
        envelope_sha256=source.envelope_sha256,
        baseline=_sanitized_comparison_run(source.baseline),
        adaptive=_sanitized_comparison_run(source.adaptive),
    )
    summary = _summary(investigation_id).model_copy(
        update={"envelope_sha256": comparison.envelope_sha256}
    )
    return ScenarioRunSnapshot(
        schema_version=SCENARIO_RUN_SNAPSHOT_VERSION,
        launch_id=launch_id,
        investigation_id=investigation_id,
        scenario=ScenarioLaunchName.STORAGE,
        mode=ScenarioRunMode.COMPARE,
        lifecycle=ScenarioRunLifecycle.COMPLETED,
        event_cursor=event_cursor,
        envelope_summary=summary,
        report=None,
        comparison=comparison,
        failure_category=None,
        accepted_at=NOW,
        updated_at=NOW + timedelta(seconds=6),
    )


def _failed_snapshot(
    *,
    launch_id: str,
    investigation_id: str,
    event_cursor: int = 3,
) -> ScenarioRunSnapshot:
    return ScenarioRunSnapshot(
        schema_version=SCENARIO_RUN_SNAPSHOT_VERSION,
        launch_id=launch_id,
        investigation_id=investigation_id,
        scenario=ScenarioLaunchName.STORAGE,
        mode=ScenarioRunMode.ADAPTIVE,
        lifecycle=ScenarioRunLifecycle.FAILED,
        event_cursor=event_cursor,
        envelope_summary=None,
        report=None,
        comparison=None,
        failure_category=ScenarioRunFailureCategory.MODEL_UNAVAILABLE,
        accepted_at=NOW,
        updated_at=NOW + timedelta(seconds=2),
    )


def _operational_status(
    snapshot: ScenarioRunSnapshot,
    *,
    revision: int,
    investigation_state: ScenarioOperationalInvestigationState = (
        ScenarioOperationalInvestigationState.STARTED
    ),
    cleanup_state: ScenarioOperationalCleanupState = (
        ScenarioOperationalCleanupState.NOT_REQUESTED
    ),
    recovery_state: ScenarioOperationalRecoveryState = (
        ScenarioOperationalRecoveryState.NOT_ESCALATED
    ),
) -> ScenarioOperationalStatus:
    return ScenarioOperationalStatus(
        schema_version=SCENARIO_OPERATIONAL_STATUS_VERSION,
        launch_id=snapshot.launch_id,
        investigation_id=snapshot.investigation_id,
        scenario=snapshot.scenario,
        mode=snapshot.mode,
        revision=revision,
        mutation_state=ScenarioOperationalMutationState.RECORDED,
        investigation_state=investigation_state,
        cleanup_state=cleanup_state,
        recovery_state=recovery_state,
        updated_at=NOW + timedelta(seconds=revision),
    )


def _event(
    cursor: int,
    event_type: ScenarioRunEventType,
    payload: ScenarioRunEventPayload,
    investigation_id: str,
) -> ScenarioRunEvent:
    return ScenarioRunEvent(
        schema_version=SCENARIO_RUN_EVENT_VERSION,
        investigation_id=investigation_id,
        cursor=cursor,
        type=event_type,
        occurred_at=NOW + timedelta(milliseconds=cursor),
        payload=payload,
    )


def _lifecycle_events(investigation_id: str) -> tuple[ScenarioRunEvent, ...]:
    return (
        _event(
            1,
            ScenarioRunEventType.LIFECYCLE,
            ScenarioLifecycleEventPayload(lifecycle=ScenarioRunLifecycle.ACCEPTED),
            investigation_id,
        ),
        _event(
            2,
            ScenarioRunEventType.LIFECYCLE,
            ScenarioLifecycleEventPayload(lifecycle=ScenarioRunLifecycle.RUNNING),
            investigation_id,
        ),
    )


def _report_terminal_event(snapshot: ScenarioRunSnapshot) -> ScenarioRunEvent:
    report = snapshot.report
    assert report is not None
    assert report.classification is not None
    allowed = sum(item.allowed for item in report.action_gate)
    return _event(
        snapshot.event_cursor,
        ScenarioRunEventType.TERMINAL,
        TerminalStateEventPayload(
            terminal=TerminalStateSummary(
                lifecycle=ScenarioRunLifecycle.COMPLETED,
                result_kind=ScenarioRunResultKind.REPORT,
                classification=report.classification,
                action_gate_allowed_count=allowed,
                action_gate_denied_count=len(report.action_gate) - allowed,
                missing_evidence_count=len(report.missing_evidence),
                escalation_required=(
                    report.classification is not Classification.COMMITTED
                ),
                failure_category=None,
            )
        ),
        snapshot.investigation_id,
    )


def _comparison_terminal_event(snapshot: ScenarioRunSnapshot) -> ScenarioRunEvent:
    return _event(
        snapshot.event_cursor,
        ScenarioRunEventType.TERMINAL,
        TerminalStateEventPayload(
            terminal=TerminalStateSummary(
                lifecycle=ScenarioRunLifecycle.COMPLETED,
                result_kind=ScenarioRunResultKind.COMPARISON,
                classification=None,
                action_gate_allowed_count=0,
                action_gate_denied_count=0,
                missing_evidence_count=0,
                escalation_required=None,
                failure_category=None,
            )
        ),
        snapshot.investigation_id,
    )


def _failure_terminal_event(snapshot: ScenarioRunSnapshot) -> ScenarioRunEvent:
    return _event(
        snapshot.event_cursor,
        ScenarioRunEventType.TERMINAL,
        TerminalStateEventPayload(
            terminal=TerminalStateSummary(
                lifecycle=ScenarioRunLifecycle.FAILED,
                result_kind=ScenarioRunResultKind.NONE,
                classification=None,
                action_gate_allowed_count=0,
                action_gate_denied_count=0,
                missing_evidence_count=0,
                escalation_required=None,
                failure_category=ScenarioRunFailureCategory.MODEL_UNAVAILABLE,
            )
        ),
        snapshot.investigation_id,
    )


def _rich_active_journal(
    investigation_id: str,
) -> tuple[ScenarioRunEvent, ...]:
    summary = _summary(investigation_id)
    request_sha256 = "a" * 64
    common_request = {
        "advisory_turn_sequence": 1,
        "capability_name": "gcs-object-readback",
        "capability_version": "1.0.0",
        "request_sha256": request_sha256,
        "relevant_effect_ids": ("business-record",),
    }
    return (
        *_lifecycle_events(investigation_id),
        _event(
            3,
            ScenarioRunEventType.ENVELOPE_SUMMARY,
            EnvelopeSummaryEventPayload(summary=summary),
            investigation_id,
        ),
        _event(
            4,
            ScenarioRunEventType.ADVISORY_TURN,
            AdvisoryTurnEventPayload(
                turn=AdvisoryTurnSummary(
                    turn_sequence=1,
                    phase=AdaptivePlannerPhase.ACQUIRE_EVIDENCE,
                    status=AdvisoryTurnStatus.COMPLETED,
                    input_sha256="b" * 64,
                    output_sha256="c" * 64,
                    proposal_count=2,
                    selected_proposal_count=1,
                    failure_category=None,
                )
            ),
            investigation_id,
        ),
        _event(
            5,
            ScenarioRunEventType.PROBE_REQUEST,
            ProbeRequestEventPayload(
                strategy=ComparisonStrategyKind.ADAPTIVE,
                request=SanitizedProbeRequest(
                    request_sequence=1,
                    proposal_sequence=1,
                    disposition=ProbeRequestDisposition.SELECTED,
                    **common_request,
                ),
            ),
            investigation_id,
        ),
        _event(
            6,
            ScenarioRunEventType.PROBE_REQUEST,
            ProbeRequestEventPayload(
                strategy=ComparisonStrategyKind.ADAPTIVE,
                request=SanitizedProbeRequest(
                    request_sequence=2,
                    proposal_sequence=2,
                    disposition=ProbeRequestDisposition.UNSUPPORTED_CAPABILITY,
                    **common_request,
                ),
            ),
            investigation_id,
        ),
        _event(
            7,
            ScenarioRunEventType.PROBE_RESULT,
            ProbeResultEventPayload(
                strategy=ComparisonStrategyKind.ADAPTIVE,
                probe=SanitizedProbeResult(
                    probe_sequence=1,
                    capability_name="gcs-object-readback",
                    capability_version="1.0.0",
                    request_sha256=request_sha256,
                    outcome=ProbeOutcome.COMPLETED,
                    stop_reason="probe_completed",
                    result_sha256="d" * 64,
                    result_byte_count=2,
                    evidence_ids=("evidence-admitted",),
                ),
            ),
            investigation_id,
        ),
        *(
            _event(
                cursor,
                ScenarioRunEventType.EVIDENCE_DECISION,
                OperatorEvidenceDecisionEventPayload(
                    strategy=ComparisonStrategyKind.ADAPTIVE,
                    decision=EvidenceDecision(
                        schema_version=EVIDENCE_DECISION_VERSION,
                        evidence_id=evidence_id,
                        disposition=disposition,
                        reason=reason,
                    ),
                ),
                investigation_id,
            )
            for cursor, evidence_id, disposition, reason in (
                (
                    8,
                    "evidence-admitted",
                    EvidenceDisposition.ADMITTED,
                    EvidenceReason.AUTHORITATIVE_EXACT_CORRELATION,
                ),
                (
                    9,
                    "evidence-weak",
                    EvidenceDisposition.WEAK,
                    EvidenceReason.NON_AUTHORITATIVE_LOG_ONLY,
                ),
                (
                    10,
                    "evidence-rejected",
                    EvidenceDisposition.REJECTED,
                    EvidenceReason.STALE_OBSERVATION,
                ),
            )
        ),
    )


def _text(app: ReconcileApp, selector: str) -> str:
    return str(app.query_one(selector, Static).content)


@pytest.mark.parametrize(
    ("scenario", "classification", "continue_state", "missing_state"),
    (
        (
            ScenarioLaunchName.STORAGE,
            Classification.COMMITTED,
            "ALLOWED",
            "NONE",
        ),
        (
            ScenarioLaunchName.FIRESTORE_BUSINESS,
            Classification.PARTIAL,
            "DENIED",
            "effects=",
        ),
        (
            ScenarioLaunchName.SANDBOX_ORDER,
            Classification.UNKNOWN,
            "DENIED",
            "effects=",
        ),
    ),
)
def test_keyboard_launch_keeps_active_and_terminal_fixed_states_explicit(
    scenario: ScenarioLaunchName,
    classification: Classification,
    continue_state: str,
    missing_state: str,
) -> None:
    async def journey() -> None:
        launch_id = f"launch-{scenario.value}"
        investigation_id = f"investigation-{scenario.value}"
        active = _active_snapshot(
            scenario=scenario,
            mode=ScenarioRunMode.FIXED,
            launch_id=launch_id,
            investigation_id=investigation_id,
            event_cursor=2,
        )
        terminal = _completed_report_snapshot(
            classification=classification,
            scenario=scenario,
            launch_id=launch_id,
            investigation_id=investigation_id,
        )
        stream = _StreamPlan(
            events=(
                *_lifecycle_events(investigation_id),
                _report_terminal_event(terminal),
            ),
            pause_after=2,
        )
        client = _ScriptedClient(
            launch=active,
            snapshots=(terminal,),
            streams=(stream,),
        )
        app = ReconcileApp(client=client)

        async with app.run_test(size=(100, 40)) as pilot:
            assert app.focused is app.query_one("#scenario-select", Select)
            assert not app.screen.has_class("narrow")
            app.query_one("#scenario-select", Select).value = scenario
            app.query_one("#mode-select", Select).value = ScenarioRunMode.FIXED
            app.query_one("#launch-id", Input).value = launch_id

            await pilot.press("f5")
            await asyncio.wait_for(stream.paused.wait(), timeout=1)
            assert app.operator_view_state.last_cursor == 2
            assert "DETERMINISTIC DECISION: PENDING" in _text(
                app, "#deterministic-panel"
            )

            stream.release.set()
            await app.workers.wait_for_complete()
            await pilot.pause()

            plain = "\n".join(
                _text(app, selector)
                for selector in (
                    "#identity-strip",
                    "#outcome-panel",
                    "#deterministic-panel",
                    "#actions-panel",
                    "#missing-panel",
                )
            )
            assert f"DETERMINISTIC CLASSIFICATION: {classification.value}" in plain
            assert "ACTION PERMISSION: ALLOWED=" in _text(app, "#outcome-panel")
            assert "MISSING EVIDENCE:" in _text(app, "#outcome-panel")
            assert f"ACTION CONTINUE: {continue_state}" in plain
            assert f"MISSING EVIDENCE: {missing_state}" in plain
            assert "API CONNECTION: LIVE" in plain
            assert "\x1b" not in plain
            assert app.operator_view_state.timeline_complete

            launch_call = next(call for call in client.calls if call[0] == "launch")
            request = launch_call[1]
            assert isinstance(request, ScenarioLaunchRequest)
            assert request.scenario is scenario
            assert request.mode is ScenarioRunMode.FIXED

        assert client.close_count == 1

    asyncio.run(journey())


def test_operations_panel_keeps_cleanup_failure_separate_from_v1_decision() -> None:
    async def journey() -> None:
        launch_id = "launch-cleanup-failed"
        investigation_id = "investigation-cleanup-failed"
        active = _active_snapshot(
            scenario=ScenarioLaunchName.STORAGE,
            mode=ScenarioRunMode.FIXED,
            launch_id=launch_id,
            investigation_id=investigation_id,
            event_cursor=2,
        )
        terminal = _completed_report_snapshot(
            classification=Classification.COMMITTED,
            scenario=ScenarioLaunchName.STORAGE,
            launch_id=launch_id,
            investigation_id=investigation_id,
        )
        initial_status = _operational_status(active, revision=3)
        cleanup_failed = _operational_status(
            terminal,
            revision=8,
            investigation_state=ScenarioOperationalInvestigationState.RECORDED,
            cleanup_state=ScenarioOperationalCleanupState.FAILED,
        )
        client = _ScriptedClient(
            launch=active,
            snapshots=(terminal,),
            statuses=(initial_status, cleanup_failed),
            streams=(
                _StreamPlan(
                    events=(
                        *_lifecycle_events(investigation_id),
                        _report_terminal_event(terminal),
                    )
                ),
            ),
        )
        app = ReconcileApp(client=client)

        async with app.run_test(size=(100, 40)) as pilot:
            app.query_one("#launch-id", Input).value = launch_id
            await pilot.press("f5")
            await app.workers.wait_for_complete()
            await pilot.pause()

            operations = _text(app, "#operations-panel")
            assert "OPERATIONAL STATUS: AVAILABLE" in operations
            assert "MUTATION: RECORDED" in operations
            assert "INVESTIGATION: RECORDED" in operations
            assert "CLEANUP: FAILED" in operations
            assert "HUMAN ESCALATION: NOT_ESCALATED" in operations
            assert "DETERMINISTIC CLASSIFICATION: COMMITTED" in _text(
                app, "#deterministic-panel"
            )
            assert "ACTION CONTINUE: ALLOWED" in _text(app, "#actions-panel")
            assert [
                call[1] for call in client.calls if call[0] == "get_operational_status"
            ] == [investigation_id, investigation_id]

        assert client.close_count == 1

    asyncio.run(journey())


def test_operations_panel_exposes_required_human_escalation() -> None:
    async def journey() -> None:
        launch_id = "launch-human-escalation"
        investigation_id = "investigation-human-escalation"
        active = _active_snapshot(
            scenario=ScenarioLaunchName.STORAGE,
            mode=ScenarioRunMode.ADAPTIVE,
            launch_id=launch_id,
            investigation_id=investigation_id,
            event_cursor=2,
            include_summary=False,
        )
        failed = _failed_snapshot(
            launch_id=launch_id,
            investigation_id=investigation_id,
        )
        escalated = _operational_status(
            failed,
            revision=6,
            investigation_state=(
                ScenarioOperationalInvestigationState.ESCALATION_REQUIRED
            ),
            recovery_state=(ScenarioOperationalRecoveryState.HUMAN_ESCALATION_REQUIRED),
        )
        client = _ScriptedClient(
            launch=active,
            snapshots=(failed,),
            statuses=(_operational_status(active, revision=2), escalated),
            streams=(
                _StreamPlan(
                    events=(
                        *_lifecycle_events(investigation_id),
                        _failure_terminal_event(failed),
                    )
                ),
            ),
        )
        app = ReconcileApp(client=client)

        async with app.run_test(size=(100, 40)) as pilot:
            app.query_one("#mode-select", Select).value = ScenarioRunMode.ADAPTIVE
            app.query_one("#launch-id", Input).value = launch_id
            await pilot.press("f5")
            await app.workers.wait_for_complete()
            await pilot.pause()

            operations = _text(app, "#operations-panel")
            assert "INVESTIGATION: ESCALATION_REQUIRED" in operations
            assert "CLEANUP: NOT_REQUESTED" in operations
            assert "HUMAN ESCALATION: HUMAN_ESCALATION_REQUIRED" in operations
            assert "RUN FAILED" in _text(app, "#deterministic-panel")

        assert client.close_count == 1

    asyncio.run(journey())


@pytest.mark.parametrize(
    ("status_error", "marker"),
    (
        (RemoteProtocolError(), "OPERATIONAL STATUS: INVALID"),
        (ServiceUnavailableError(), "OPERATIONAL STATUS: UNAVAILABLE"),
    ),
)
def test_bad_terminal_status_retains_authoritative_v1_and_last_good_operations(
    status_error: Exception,
    marker: str,
) -> None:
    async def journey() -> None:
        launch_id = f"launch-status-{marker.rsplit(': ', 1)[-1].lower()}"
        investigation_id = f"investigation-status-{marker.rsplit(': ', 1)[-1].lower()}"
        active = _active_snapshot(
            scenario=ScenarioLaunchName.STORAGE,
            mode=ScenarioRunMode.FIXED,
            launch_id=launch_id,
            investigation_id=investigation_id,
            event_cursor=2,
        )
        terminal = _completed_report_snapshot(
            classification=Classification.COMMITTED,
            scenario=ScenarioLaunchName.STORAGE,
            launch_id=launch_id,
            investigation_id=investigation_id,
        )
        initial_status = _operational_status(active, revision=2)
        client = _ScriptedClient(
            launch=active,
            snapshots=(terminal,),
            statuses=(initial_status, status_error),
            streams=(
                _StreamPlan(
                    events=(
                        *_lifecycle_events(investigation_id),
                        _report_terminal_event(terminal),
                    )
                ),
            ),
        )
        app = ReconcileApp(client=client)

        async with app.run_test(size=(100, 40)) as pilot:
            app.query_one("#launch-id", Input).value = launch_id
            await pilot.press("f5")
            await app.workers.wait_for_complete()
            await pilot.pause()

            assert app.operator_view_state.snapshot == terminal
            assert app.operator_view_state.timeline_complete
            assert app.operator_view_state.operational_status == initial_status
            assert "DETERMINISTIC CLASSIFICATION: COMMITTED" in _text(
                app, "#deterministic-panel"
            )
            assert "CURSOR 3 TERMINAL" in _text(app, "#timeline-panel")
            operations = _text(app, "#operations-panel")
            assert marker in operations
            assert "V1 STATE RETAINED" in operations
            assert "OPERATIONS REVISION: 2" in operations
            assert app.operator_view_state.connection_phase is ConnectionPhase.LIVE
            assert "Terminal snapshot confirmed" in _text(app, "#operator-message")

        assert client.close_count == 1

    asyncio.run(journey())


def test_authoritative_outcome_is_visible_at_supported_small_sizes() -> None:
    async def journey() -> None:
        launch_id = "launch-small-terminal"
        investigation_id = "investigation-small-terminal"
        active = _active_snapshot(
            scenario=ScenarioLaunchName.STORAGE,
            mode=ScenarioRunMode.FIXED,
            launch_id=launch_id,
            investigation_id=investigation_id,
            event_cursor=2,
        )
        terminal = _completed_report_snapshot(
            classification=Classification.COMMITTED,
            scenario=ScenarioLaunchName.STORAGE,
            launch_id=launch_id,
            investigation_id=investigation_id,
        )
        client = _ScriptedClient(
            launch=active,
            snapshots=(terminal,),
            streams=(
                _StreamPlan(
                    events=(
                        *_lifecycle_events(investigation_id),
                        _report_terminal_event(terminal),
                    )
                ),
            ),
        )
        app = ReconcileApp(client=client)

        async with app.run_test(size=(100, 40)) as pilot:
            app.query_one("#launch-id", Input).value = launch_id
            await pilot.press("f5")
            await app.workers.wait_for_complete()

            outcome = app.query_one("#outcome-panel", Static)
            scroll = app.query_one("#summary-tab").query_one(VerticalScroll)
            for width, height in ((80, 24), (50, 20)):
                await pilot.resize_terminal(width, height)
                await pilot.pause()

                assert app.screen.has_class("narrow")
                assert scroll.region.height > 0
                assert outcome.is_on_screen
                assert outcome.region.intersection(scroll.region) == outcome.region
                assert (
                    outcome.content_region.intersection(scroll.region)
                    == outcome.content_region
                )
                plain = _text(app, "#outcome-panel")
                assert "DETERMINISTIC CLASSIFICATION: COMMITTED" in plain
                assert "ACTION PERMISSION: ALLOWED=" in plain
                assert "MISSING EVIDENCE:" in plain

        assert client.close_count == 1

    asyncio.run(journey())


def test_keyboard_attach_and_copy_preserve_a_maximum_length_identifier() -> None:
    async def journey() -> None:
        investigation_id = "investigation-" + "x" * (128 - len("investigation-"))
        terminal = _completed_report_snapshot(
            classification=Classification.COMMITTED,
            scenario=ScenarioLaunchName.STORAGE,
            launch_id="launch-long-identifier",
            investigation_id=investigation_id,
        )
        stream = _StreamPlan(
            events=(
                *_lifecycle_events(investigation_id),
                _report_terminal_event(terminal),
            )
        )
        client = _ScriptedClient(
            snapshots=(terminal, terminal),
            streams=(stream,),
        )
        app = _ClipboardApp(client=client)

        async with app.run_test(size=(100, 40)) as pilot:
            await pilot.press("tab", "tab", "tab", "tab")
            identifier_input = app.query_one("#investigation-id", Input)
            assert app.focused is identifier_input
            await pilot.press(*tuple(investigation_id))
            assert identifier_input.value == investigation_id

            await pilot.press("f6")
            await app.workers.wait_for_complete()
            await pilot.pause()
            assert investigation_id in _text(app, "#identity-strip")

            await pilot.press("tab")
            assert app.focused is app.query_one("#attach-button", Button)
            await pilot.press("c")
            await pilot.pause()
            assert app.copied == [investigation_id]
            assert "copied exactly" in _text(app, "#operator-message")

        assert client.close_count == 1

    asyncio.run(journey())


def test_busy_second_command_cannot_cancel_or_mutate_inflight_launch() -> None:
    async def journey() -> None:
        launch_id = "launch-queued-command"
        investigation_id = "investigation-queued-command"
        active = _active_snapshot(
            scenario=ScenarioLaunchName.STORAGE,
            mode=ScenarioRunMode.FIXED,
            launch_id=launch_id,
            investigation_id=investigation_id,
            event_cursor=2,
        )
        terminal = _completed_report_snapshot(
            classification=Classification.COMMITTED,
            scenario=ScenarioLaunchName.STORAGE,
            launch_id=launch_id,
            investigation_id=investigation_id,
        )
        gate = _LaunchGate()
        first_stream = _StreamPlan(
            events=(
                *_lifecycle_events(investigation_id),
                _report_terminal_event(terminal),
            )
        )
        client = _ScriptedClient(
            launch=active,
            snapshots=(terminal,),
            streams=(first_stream,),
            launch_gate=gate,
        )
        app = ReconcileApp(client=client)

        async with app.run_test(size=(100, 40)) as pilot:
            app.query_one("#launch-id", Input).value = launch_id
            await pilot.press("f5")
            await asyncio.wait_for(gate.started.wait(), timeout=1)

            app.query_one("#launch-id", Input).value = "launch-must-not-replace-active"
            app.query_one(
                "#investigation-id", Input
            ).value = "investigation-must-not-submit"
            await pilot.press("f6")
            await pilot.pause()

            assert not gate.cancelled
            assert [call[0] for call in client.calls] == ["launch"]
            assert "[BUSY]" in _text(app, "#operator-message")
            assert "no request was cancelled or submitted" in _text(
                app, "#operator-message"
            )
            launch_call = client.calls[0]
            request = launch_call[1]
            assert isinstance(request, ScenarioLaunchRequest)
            assert request.launch_id == launch_id

            gate.release.set()
            await app.workers.wait_for_complete()
            await pilot.pause()

            assert not gate.cancelled
            event_calls = [call for call in client.calls if call[0] == "events"]
            assert len(event_calls) == 1
            assert all(call[1] == investigation_id for call in event_calls)
            snapshot_calls = [
                call for call in client.calls if call[0] == "get_snapshot"
            ]
            assert [call[1] for call in snapshot_calls] == [investigation_id]
            assert not first_stream.cancelled
            assert app.operator_view_state.snapshot == terminal
            assert app.operator_view_state.timeline_complete

        assert client.close_count == 1

    asyncio.run(journey())


def test_explicit_keyboard_reconnect_resumes_after_the_confirmed_cursor() -> None:
    async def journey() -> None:
        launch_id = "launch-reconnect"
        investigation_id = "investigation-reconnect"
        active = _active_snapshot(
            scenario=ScenarioLaunchName.STORAGE,
            mode=ScenarioRunMode.FIXED,
            launch_id=launch_id,
            investigation_id=investigation_id,
            event_cursor=2,
        )
        terminal = _completed_report_snapshot(
            classification=Classification.COMMITTED,
            scenario=ScenarioLaunchName.STORAGE,
            launch_id=launch_id,
            investigation_id=investigation_id,
        )
        first = _StreamPlan(
            events=_lifecycle_events(investigation_id),
            error=StreamInterruptedError(2),
        )
        second = _StreamPlan(events=(_report_terminal_event(terminal),))
        client = _ScriptedClient(
            launch=active,
            snapshots=(terminal, terminal),
            streams=(first, second),
        )
        app = ReconcileApp(client=client)

        async with app.run_test(size=(100, 40)) as pilot:
            app.query_one("#launch-id", Input).value = launch_id
            await pilot.press("f5")
            await app.workers.wait_for_complete()
            await pilot.pause()

            assert app.operator_view_state.connection_phase is (
                ConnectionPhase.DISCONNECTED
            )
            assert app.operator_view_state.last_cursor == 2
            assert "press R to reconnect" in _text(app, "#operator-message")

            await pilot.press("tab", "tab", "tab")
            assert app.focused is app.query_one("#launch-button", Button)
            await pilot.press("r")
            await app.workers.wait_for_complete()
            await pilot.pause()

            event_calls = [call for call in client.calls if call[0] == "events"]
            assert [call[2] for call in event_calls] == [0, 2]
            assert all(call[3] == 0 for call in event_calls)
            status_calls = [
                call for call in client.calls if call[0] == "get_operational_status"
            ]
            assert [call[1] for call in status_calls] == [
                investigation_id,
                investigation_id,
                investigation_id,
            ]
            assert app.operator_view_state.last_cursor == 3
            assert app.operator_view_state.timeline_complete
            assert "CURSOR 1 LIFECYCLE: ACCEPTED" in _text(app, "#timeline-panel")
            assert "CURSOR 3 TERMINAL" in _text(app, "#timeline-panel")
            assert "Terminal snapshot confirmed" in _text(app, "#operator-message")

        assert client.close_count == 1

    asyncio.run(journey())


def test_fixed_fallback_route_provenance_is_visible_without_provider_detail() -> None:
    async def journey() -> None:
        launch_id = "launch-hybrid-fixed-fallback"
        investigation_id = "investigation-hybrid-fixed-fallback"
        provenance = ScenarioRouteProvenance(
            policy_version=BOUNDED_HYBRID_ROUTE_POLICY_VERSION,
            route=ScenarioHybridRoute.PLANNER_HETEROGENEOUS,
            outcome=ScenarioHybridOutcome.FIXED_FALLBACK,
            planner_invoked=True,
            fixed_connector_invoked=True,
            provider_failure=True,
            provider_cleanup_failure=False,
        )
        active = _active_snapshot(
            scenario=ScenarioLaunchName.SANDBOX_ORDER,
            mode=ScenarioRunMode.ADAPTIVE,
            launch_id=launch_id,
            investigation_id=investigation_id,
            event_cursor=2,
        )
        terminal = _completed_report_snapshot(
            classification=Classification.UNKNOWN,
            scenario=ScenarioLaunchName.SANDBOX_ORDER,
            launch_id=launch_id,
            investigation_id=investigation_id,
            mode=ScenarioRunMode.ADAPTIVE,
            route_provenance=provenance,
        )
        client = _ScriptedClient(
            launch=active,
            snapshots=(terminal,),
            streams=(
                _StreamPlan(
                    events=(
                        *_lifecycle_events(investigation_id),
                        _report_terminal_event(terminal),
                    )
                ),
            ),
        )
        app = ReconcileApp(client=client)

        async with app.run_test(size=(120, 40)) as pilot:
            app.query_one(
                "#scenario-select", Select
            ).value = ScenarioLaunchName.SANDBOX_ORDER
            app.query_one("#mode-select", Select).value = ScenarioRunMode.ADAPTIVE
            app.query_one("#launch-id", Input).value = launch_id
            await pilot.press("f5")
            await app.workers.wait_for_complete()
            await pilot.pause()

            rendered = _text(app, "#deterministic-panel")
            assert (
                "HYBRID ROUTE: policy=1.0.0 route=PLANNER_HETEROGENEOUS "
                "outcome=FIXED_FALLBACK planner_invoked=TRUE "
                "fixed_connector_invoked=TRUE provider_failure=TRUE "
                "provider_cleanup_failure=FALSE"
            ) in rendered
            assert "DETERMINISTIC CLASSIFICATION: UNKNOWN" in rendered
            snapshot = app.operator_view_state.snapshot
            assert snapshot is not None
            assert snapshot.report is not None
            assert snapshot.report.route_provenance == provenance
            assert "private provider" not in rendered.lower()

        assert client.close_count == 1

    asyncio.run(journey())


def test_provider_failure_remains_distinct_from_terminal_unknown() -> None:
    async def journey() -> None:
        launch_id = "launch-provider-unavailable"
        investigation_id = "investigation-provider-unavailable"
        active = _active_snapshot(
            scenario=ScenarioLaunchName.STORAGE,
            mode=ScenarioRunMode.ADAPTIVE,
            launch_id=launch_id,
            investigation_id=investigation_id,
            event_cursor=2,
            include_summary=False,
        )
        failed = _failed_snapshot(
            launch_id=launch_id,
            investigation_id=investigation_id,
        )
        stream = _StreamPlan(
            events=(
                *_lifecycle_events(investigation_id),
                _failure_terminal_event(failed),
            )
        )
        client = _ScriptedClient(
            launch=active,
            snapshots=(failed,),
            streams=(stream,),
        )
        app = ReconcileApp(client=client)

        async with app.run_test(size=(100, 40)) as pilot:
            app.query_one("#mode-select", Select).value = ScenarioRunMode.ADAPTIVE
            app.query_one("#launch-id", Input).value = launch_id
            await pilot.press("f5")
            await app.workers.wait_for_complete()
            await pilot.pause()

            plain = "\n".join(
                _text(app, selector)
                for selector in (
                    "#advisory-panel",
                    "#deterministic-panel",
                    "#actions-panel",
                )
            )
            assert "MODEL_UNAVAILABLE" in plain
            assert "RUN FAILED" in plain
            assert "UNKNOWN" not in plain
            assert "\x1b" not in plain

        assert client.close_count == 1

    asyncio.run(journey())


@pytest.mark.parametrize(
    ("operation", "error", "marker"),
    (
        ("attach", InvestigationNotFoundError(), "[NOT FOUND]"),
        ("launch", ServiceUnavailableError(), "[SERVICE UNAVAILABLE]"),
    ),
)
def test_failed_new_request_clears_a_prior_deterministic_result(
    operation: str,
    error: Exception,
    marker: str,
) -> None:
    async def journey() -> None:
        prior_id = "investigation-prior-committed"
        prior = _completed_report_snapshot(
            classification=Classification.COMMITTED,
            scenario=ScenarioLaunchName.STORAGE,
            launch_id="launch-prior-committed",
            investigation_id=prior_id,
        )
        snapshots: tuple[ScenarioRunSnapshot | Exception, ...] = (
            (prior, prior, error) if operation == "attach" else (prior, prior)
        )
        client = _ScriptedClient(
            launch=error if operation == "launch" else None,
            snapshots=snapshots,
            streams=(
                _StreamPlan(
                    events=(
                        *_lifecycle_events(prior_id),
                        _report_terminal_event(prior),
                    )
                ),
            ),
        )
        app = ReconcileApp(client=client)

        async with app.run_test(size=(100, 40)) as pilot:
            app.query_one("#investigation-id", Input).value = prior_id
            await pilot.press("f6")
            await app.workers.wait_for_complete()
            assert "DETERMINISTIC CLASSIFICATION: COMMITTED" in _text(
                app, "#deterministic-panel"
            )

            if operation == "attach":
                app.query_one(
                    "#investigation-id", Input
                ).value = "investigation-new-missing"
                await pilot.press("f6")
            else:
                app.query_one("#launch-id", Input).value = "launch-new-refused"
                await pilot.press("f5")
            await app.workers.wait_for_complete()
            await pilot.pause()

            assert marker in _text(app, "#operator-message")
            assert app.operator_view_state.snapshot is None
            assert "DETERMINISTIC DECISION: NO RUN" in _text(
                app, "#deterministic-panel"
            )
            assert "COMMITTED" not in _text(app, "#deterministic-panel")
            assert "ACTION PERMISSION: NO RUN" in _text(app, "#actions-panel")

        assert client.close_count == 1

    asyncio.run(journey())


def test_clean_nonterminal_stream_return_cannot_claim_terminal_confirmation() -> None:
    async def journey() -> None:
        launch_id = "launch-active-clean-return"
        investigation_id = "investigation-active-clean-return"
        active = _active_snapshot(
            scenario=ScenarioLaunchName.STORAGE,
            mode=ScenarioRunMode.FIXED,
            launch_id=launch_id,
            investigation_id=investigation_id,
            event_cursor=2,
        )
        client = _ScriptedClient(
            launch=active,
            snapshots=(active,),
            streams=(_StreamPlan(events=_lifecycle_events(investigation_id)),),
        )
        app = ReconcileApp(client=client)

        async with app.run_test(size=(100, 40)) as pilot:
            app.query_one("#launch-id", Input).value = launch_id
            await pilot.press("f5")
            await app.workers.wait_for_complete()
            await pilot.pause()

            assert app.operator_view_state.snapshot is not None
            assert app.operator_view_state.snapshot.lifecycle is (
                ScenarioRunLifecycle.RUNNING
            )
            assert "decision remains pending" in _text(app, "#operator-message")
            assert "Terminal snapshot confirmed" not in _text(app, "#operator-message")
            assert "DETERMINISTIC DECISION: PENDING" in _text(
                app, "#deterministic-panel"
            )

        assert client.close_count == 1

    asyncio.run(journey())


@pytest.mark.parametrize(
    ("error", "marker", "phase"),
    (
        (
            InvestigationNotFoundError(),
            "[NOT FOUND]",
            ConnectionPhase.REFUSED,
        ),
        (
            ServiceUnavailableError(),
            "[SERVICE UNAVAILABLE]",
            ConnectionPhase.REFUSED,
        ),
        (
            TransportError(),
            "[API UNREACHABLE]",
            ConnectionPhase.DISCONNECTED,
        ),
    ),
)
def test_attach_failures_are_explicit_and_recoverable(
    error: Exception,
    marker: str,
    phase: ConnectionPhase,
) -> None:
    async def journey() -> None:
        client = _ScriptedClient(snapshots=(error,))
        app = ReconcileApp(client=client)

        async with app.run_test(size=(100, 40)) as pilot:
            app.query_one("#investigation-id", Input).value = "investigation-refused"
            await pilot.press("f6")
            await app.workers.wait_for_complete()
            await pilot.pause()

            assert marker in _text(app, "#operator-message")
            assert app.operator_view_state.connection_phase is phase
            assert app.operator_view_state.snapshot is None
            assert not any(call[0] == "events" for call in client.calls)

        assert client.close_count == 1

    asyncio.run(journey())


def test_neutral_comparison_stays_legible_after_narrow_resize() -> None:
    async def journey() -> None:
        launch_id = "launch-comparison"
        investigation_id = "investigation-comparison"
        terminal = _completed_comparison_snapshot(
            launch_id=launch_id,
            investigation_id=investigation_id,
        )
        active = _active_snapshot(
            scenario=ScenarioLaunchName.STORAGE,
            mode=ScenarioRunMode.COMPARE,
            launch_id=launch_id,
            investigation_id=investigation_id,
            event_cursor=2,
        ).model_copy(update={"envelope_summary": terminal.envelope_summary})
        stream = _StreamPlan(
            events=(
                *_lifecycle_events(investigation_id),
                _comparison_terminal_event(terminal),
            )
        )
        client = _ScriptedClient(
            launch=active,
            snapshots=(terminal,),
            streams=(stream,),
        )
        app = ReconcileApp(client=client)

        async with app.run_test(size=(100, 40)) as pilot:
            app.query_one("#mode-select", Select).value = ScenarioRunMode.COMPARE
            app.query_one("#launch-id", Input).value = launch_id
            await pilot.press("f5")
            await app.workers.wait_for_complete()
            await pilot.pause()

            app.query_one("#workspace", TabbedContent).active = "comparison-tab"
            plain = "\n".join(
                _text(app, selector)
                for selector in (
                    "#comparison-panel",
                    "#deterministic-panel",
                    "#actions-panel",
                )
            )
            assert "COMPARISON: NEUTRAL FIXED AND ADAPTIVE LANES" in plain
            assert "COMPARISON CLASSIFICATIONS: FIXED=" in plain
            assert "ADAPTIVE=" in plain
            assert "COMPARISON LANE: FIXED" in plain
            assert "COMPARISON LANE: ADAPTIVE" in plain
            assert "NO OVERALL CLASSIFICATION" in plain
            for disallowed in ("winner", "better", "best", "superior", "recommended"):
                assert disallowed not in plain.lower()

            assert not app.screen.has_class("narrow")
            await pilot.resize_terminal(60, 24)
            assert app.screen.has_class("narrow")
            assert "COMPARISON LANE: FIXED" in _text(app, "#comparison-panel")
            assert "COMPARISON LANE: ADAPTIVE" in _text(app, "#comparison-panel")
            scroll = app.query_one("#comparison-tab").query_one(VerticalScroll)
            assert scroll.region.height > 0
            assert scroll.max_scroll_y > 0
            scroll.scroll_end(animate=False)
            await pilot.pause()
            assert scroll.scroll_y == scroll.max_scroll_y

        assert client.close_count == 1

    asyncio.run(journey())


def test_unmount_cancels_only_the_local_stream_and_closes_the_client() -> None:
    async def journey() -> None:
        launch_id = "launch-active-timeline"
        investigation_id = "investigation-active-timeline"
        journal = _rich_active_journal(investigation_id)
        active = _active_snapshot(
            scenario=ScenarioLaunchName.STORAGE,
            mode=ScenarioRunMode.ADAPTIVE,
            launch_id=launch_id,
            investigation_id=investigation_id,
            event_cursor=len(journal),
        )
        stream = _StreamPlan(events=journal, pause_after=len(journal))
        client = _ScriptedClient(launch=active, streams=(stream,))
        app = ReconcileApp(client=client)

        async with app.run_test(size=(100, 40)) as pilot:
            app.query_one("#mode-select", Select).value = ScenarioRunMode.ADAPTIVE
            app.query_one("#launch-id", Input).value = launch_id
            await pilot.press("f5")
            await asyncio.wait_for(stream.paused.wait(), timeout=1)
            await pilot.pause()

            plain = _text(app, "#timeline-panel")
            for marker in (
                "ADVISORY TURN",
                "PROBE REQUEST SELECTED",
                "PROBE REQUEST DENIED",
                "UNSUPPORTED_CAPABILITY",
                "PROBE RESULT",
                "EVIDENCE ADMITTED",
                "EVIDENCE WEAK",
                "EVIDENCE REJECTED",
            ):
                assert marker in plain
            assert "\x1b" not in plain
            assert app.operator_view_state.timeline_complete

        assert stream.cancelled
        assert client.close_count == 1
        assert {call[0] for call in client.calls} == {
            "launch",
            "get_operational_status",
            "events",
            "close",
        }

    asyncio.run(journey())
