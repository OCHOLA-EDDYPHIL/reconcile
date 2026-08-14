"""Process-lifetime scenario operator service behavior."""

from __future__ import annotations

import asyncio
from collections.abc import Callable
from datetime import datetime, timedelta

import pytest

from reconcile.adk_planner import VertexAdcPlannerConfig
from reconcile.contracts import (
    EXECUTION_ENVELOPE_SUMMARY_VERSION,
    MAX_SCENARIO_RUN_EVENTS,
    SCENARIO_LAUNCH_REQUEST_VERSION,
    AdaptivePlannerPhase,
    Classification,
    ComparisonStrategyKind,
    EnvelopeEffectSummary,
    EvidenceDisposition,
    EvidenceReason,
    ExecutionEnvelope,
    ExecutionEnvelopeSummary,
    InvestigationComparisonRecord,
    InvestigationReport,
    ProbeOutcome,
    ProbeRequestEventPayload,
    ProbeResultEventPayload,
    ScenarioLaunchName,
    ScenarioLaunchRequest,
    ScenarioRunEventType,
    ScenarioRunFailureCategory,
    ScenarioRunLifecycle,
    ScenarioRunMode,
    canonical_json_bytes,
    canonical_sha256,
)
from reconcile.controller import ProbeStopReason
from reconcile.operator import (
    MAX_ACTIVE_SCENARIO_RUNS,
    InvalidScenarioEventCursor,
    OperatorApplicationService,
    OperatorCapacityExceeded,
    OperatorServiceClosed,
    ScenarioEnvelopeUnavailable,
    ScenarioEventJournalFull,
    ScenarioLaunchConflict,
    sanitize_report,
)
from reconcile.progress import (
    AdvisoryProgress,
    AdvisoryProgressStage,
    AdvisoryProposalProgress,
    EnvelopeProgress,
    EvidenceProgress,
    ProbeProgress,
    ProbeProgressStage,
    ProgressCallback,
    ProgressDeliveryError,
    ProgressProposalDisposition,
)
from reconcile.scenarios.service import (
    ScenarioMode,
    ScenarioName,
    ScenarioWorkflowError,
    ScenarioWorkflowErrorCategory,
    ScenarioWorkflowResult,
    scenario_investigation_id,
)
from tests.contract._factories import (
    NOW,
    make_comparison_record,
    make_envelope,
    make_report,
)

pytestmark = pytest.mark.unit


class _TickClock:
    def __init__(self) -> None:
        self._value = NOW + timedelta(hours=1)

    def __call__(self) -> datetime:
        value = self._value
        self._value += timedelta(milliseconds=1)
        return value


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


def _report(
    investigation_id: str,
    classification: Classification = Classification.COMMITTED,
) -> InvestigationReport:
    payload = make_report(classification).model_dump(mode="python")
    payload["investigation_id"] = investigation_id
    payload["envelope_sha256"] = _summary(investigation_id).envelope_sha256
    return InvestigationReport.model_validate(payload)


def _comparison(
    investigation_id: str,
    *,
    include_adaptive: bool,
) -> InvestigationComparisonRecord:
    payload = make_comparison_record(include_adaptive=include_adaptive).model_dump(
        mode="python"
    )
    envelope_sha256 = _summary(investigation_id).envelope_sha256
    payload["envelope_sha256"] = envelope_sha256
    payload["baseline"]["envelope_sha256"] = envelope_sha256
    if payload["adaptive"] is not None:
        payload["adaptive"]["envelope_sha256"] = envelope_sha256
    return InvestigationComparisonRecord.model_validate(payload)


class _Runner:
    def __init__(
        self,
        result: Callable[[str], ScenarioWorkflowResult] | None = None,
        *,
        error: Exception | None = None,
        hold: bool = False,
    ) -> None:
        self._result = result or _report
        self._error = error
        self._hold = hold
        self.started = asyncio.Event()
        self.release = asyncio.Event()
        self.calls: list[
            tuple[ScenarioName, ScenarioMode, VertexAdcPlannerConfig | None, str]
        ] = []
        self.cleanup_reached = False
        self.cancel_was_signalled = False

    async def __call__(
        self,
        scenario: ScenarioName,
        mode: ScenarioMode,
        *,
        vertex_config: VertexAdcPlannerConfig | None,
        run_id: str,
        progress_callback: ProgressCallback | None,
        cancellation_event: asyncio.Event | None,
    ) -> ScenarioWorkflowResult:
        self.calls.append((scenario, mode, vertex_config, run_id))
        self.started.set()
        try:
            if self._hold:
                await self.release.wait()
            if self._error is not None:
                raise self._error
            investigation_id = scenario_investigation_id(scenario, run_id)
            if progress_callback is not None:
                await progress_callback(
                    EnvelopeProgress(
                        occurred_at=NOW + timedelta(seconds=3),
                        investigation_id=investigation_id,
                        summary=_summary(investigation_id),
                    )
                )
            return self._result(investigation_id)
        finally:
            self.cleanup_reached = True
            self.cancel_was_signalled = bool(
                cancellation_event is not None and cancellation_event.is_set()
            )


class _ProgressRunner:
    async def __call__(
        self,
        scenario: ScenarioName,
        mode: ScenarioMode,
        *,
        vertex_config: VertexAdcPlannerConfig | None,
        run_id: str,
        progress_callback: ProgressCallback | None,
        cancellation_event: asyncio.Event | None,
    ) -> ScenarioWorkflowResult:
        del vertex_config, cancellation_event
        assert mode is ScenarioMode.ADAPTIVE
        assert progress_callback is not None
        investigation_id = scenario_investigation_id(scenario, run_id)
        request_sha256 = "c" * 64
        common_probe = {
            "investigation_id": investigation_id,
            "strategy": ComparisonStrategyKind.ADAPTIVE,
            "attempt_sequence": 1,
            "capability_name": "gcs-object-readback",
            "capability_version": "1.0.0",
            "request_sha256": request_sha256,
            "relevant_effect_ids": ("business-record",),
        }
        await progress_callback(
            EnvelopeProgress(
                occurred_at=NOW + timedelta(seconds=3),
                investigation_id=investigation_id,
                summary=_summary(investigation_id),
            )
        )
        await progress_callback(
            AdvisoryProgress(
                occurred_at=NOW + timedelta(seconds=4),
                investigation_id=investigation_id,
                strategy=ComparisonStrategyKind.ADAPTIVE,
                stage=AdvisoryProgressStage.REQUESTED,
                phase=AdaptivePlannerPhase.ACQUIRE_EVIDENCE,
                turn_sequence=1,
                input_sha256="a" * 64,
            )
        )
        await progress_callback(
            AdvisoryProgress(
                occurred_at=NOW + timedelta(seconds=5),
                investigation_id=investigation_id,
                strategy=ComparisonStrategyKind.ADAPTIVE,
                stage=AdvisoryProgressStage.COMPLETED,
                phase=AdaptivePlannerPhase.ACQUIRE_EVIDENCE,
                turn_sequence=1,
                input_sha256="a" * 64,
                output_sha256="b" * 64,
                proposals=(
                    AdvisoryProposalProgress(
                        proposal_sequence=1,
                        capability_name="gcs-object-readback",
                        capability_version="1.0.0",
                        request_sha256=request_sha256,
                        relevant_effect_ids=("business-record",),
                        disposition=ProgressProposalDisposition.SELECTED,
                    ),
                ),
                selected_request_sha256=request_sha256,
                planner_recommended_stop=False,
            )
        )
        await progress_callback(
            ProbeProgress(
                occurred_at=NOW + timedelta(seconds=6),
                stage=ProbeProgressStage.REQUESTED,
                **common_probe,
            )
        )
        completed_probe = ProbeProgress(
            occurred_at=NOW + timedelta(seconds=7),
            stage=ProbeProgressStage.COMPLETED,
            controller_sequence=1,
            controller_sequence_reused=False,
            outcome=ProbeOutcome.COMPLETED,
            controller_stop_reason=ProbeStopReason.PROBE_COMPLETED,
            session_elapsed_ms=12,
            probe_count_used=1,
            cost_units_used=1,
            result_bytes_acquired=2,
            result_sha256="d" * 64,
            result_byte_count=2,
            evidence_ids=("evidence-7",),
            **common_probe,
        )
        await progress_callback(completed_probe)
        await progress_callback(
            completed_probe.model_copy(
                update={
                    "occurred_at": NOW + timedelta(seconds=8),
                    "controller_sequence_reused": True,
                }
            )
        )
        await progress_callback(
            EvidenceProgress(
                occurred_at=NOW + timedelta(seconds=9),
                investigation_id=investigation_id,
                strategy=ComparisonStrategyKind.ADAPTIVE,
                attempt_sequence=1,
                controller_sequence=1,
                evidence_id="evidence-7",
                disposition=EvidenceDisposition.ADMITTED,
                reason=EvidenceReason.AUTHORITATIVE_EXACT_CORRELATION,
                classification=Classification.COMMITTED,
                continue_allowed=False,
                escalation_required=False,
            )
        )
        return _report(investigation_id)


def _launch(
    *,
    launch_id: str = "operator-run-7",
    scenario: ScenarioLaunchName = ScenarioLaunchName.STORAGE,
    mode: ScenarioRunMode = ScenarioRunMode.FIXED,
) -> ScenarioLaunchRequest:
    return ScenarioLaunchRequest(
        schema_version=SCENARIO_LAUNCH_REQUEST_VERSION,
        launch_id=launch_id,
        scenario=scenario,
        mode=mode,
    )


def _vertex_config() -> VertexAdcPlannerConfig:
    return VertexAdcPlannerConfig(
        project="demo-project",
        location="global",
        model="gemini-2.5-flash-lite",
        timeout_seconds=1,
        max_output_tokens=128,
    )


async def _terminal_snapshot(
    service: OperatorApplicationService,
    investigation_id: str,
):
    cursor = 0
    while True:
        suffix = await service.wait_for_events(investigation_id, after=cursor)
        cursor = suffix.cursor
        if suffix.terminal:
            return await service.get(investigation_id)


def test_launch_is_exactly_idempotent_and_conflicting_reuse_is_rejected() -> None:
    async def check() -> None:
        runner = _Runner(hold=True)
        service = OperatorApplicationService(runner=runner, clock=_TickClock())
        request = _launch()

        first = await service.launch(request)
        await runner.started.wait()
        replay = await service.launch(request)

        assert first.created is True
        assert first.snapshot.lifecycle is ScenarioRunLifecycle.ACCEPTED
        assert first.snapshot.event_cursor == 1
        assert replay.created is False
        assert len(runner.calls) == 1
        with pytest.raises(ScenarioLaunchConflict):
            await service.launch(
                _launch(scenario=ScenarioLaunchName.FIRESTORE_BUSINESS)
            )

        runner.release.set()
        terminal = await _terminal_snapshot(
            service,
            first.snapshot.investigation_id,
        )
        assert terminal.lifecycle is ScenarioRunLifecycle.COMPLETED
        await service.aclose()

    asyncio.run(check())


def test_concurrent_identical_launches_create_exactly_one_run() -> None:
    async def check() -> None:
        runner = _Runner(hold=True)
        service = OperatorApplicationService(runner=runner, clock=_TickClock())
        request = _launch()

        results = await asyncio.gather(*(service.launch(request) for _ in range(100)))
        await runner.started.wait()

        assert sum(result.created for result in results) == 1
        assert len(runner.calls) == 1
        assert {result.snapshot.investigation_id for result in results} == {
            scenario_investigation_id(ScenarioName.STORAGE, request.launch_id)
        }

        runner.release.set()
        terminal = await _terminal_snapshot(
            service,
            results[0].snapshot.investigation_id,
        )
        assert terminal.lifecycle is ScenarioRunLifecycle.COMPLETED
        await service.aclose()

    asyncio.run(check())


def test_unique_launch_admission_is_bounded_but_exact_replay_remains_available() -> (
    None
):
    async def check() -> None:
        runner = _Runner(hold=True)
        service = OperatorApplicationService(runner=runner, clock=_TickClock())
        requests = tuple(
            _launch(launch_id=f"bounded-run-{index}")
            for index in range(MAX_ACTIVE_SCENARIO_RUNS)
        )
        launched = [await service.launch(request) for request in requests]

        with pytest.raises(OperatorCapacityExceeded):
            await service.launch(_launch(launch_id="bounded-run-overflow"))
        replay = await service.launch(requests[0])
        assert replay.created is False

        runner.release.set()
        await asyncio.gather(
            *(
                _terminal_snapshot(service, item.snapshot.investigation_id)
                for item in launched
            )
        )
        await asyncio.sleep(0)
        admitted = await service.launch(_launch(launch_id="bounded-run-after"))
        assert admitted.created is True
        await _terminal_snapshot(service, admitted.snapshot.investigation_id)
        await service.aclose()

    asyncio.run(check())


def test_retained_run_admission_is_bounded(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def check() -> None:
        monkeypatch.setattr("reconcile.operator.MAX_RETAINED_SCENARIO_RUNS", 2)
        runner = _Runner()
        service = OperatorApplicationService(runner=runner, clock=_TickClock())
        for index in range(2):
            launched = await service.launch(_launch(launch_id=f"retained-{index}"))
            await _terminal_snapshot(service, launched.snapshot.investigation_id)

        with pytest.raises(OperatorCapacityExceeded):
            await service.launch(_launch(launch_id="retained-overflow"))
        replay = await service.launch(_launch(launch_id="retained-0"))
        assert replay.created is False
        await service.aclose()

    asyncio.run(check())


def test_fixed_completion_is_sanitized_atomic_and_resumable() -> None:
    async def check() -> None:
        runner = _Runner()
        service = OperatorApplicationService(runner=runner, clock=_TickClock())
        launched = await service.launch(_launch())
        investigation_id = launched.snapshot.investigation_id

        terminal = await _terminal_snapshot(service, investigation_id)
        journal = await service.snapshot(investigation_id)
        replay = await service.snapshot(investigation_id, after=1)

        assert terminal.lifecycle is ScenarioRunLifecycle.COMPLETED
        assert terminal.report is not None
        assert terminal.report.classification is Classification.COMMITTED
        assert terminal.event_cursor == journal.cursor == len(journal.events)
        assert tuple(item.cursor for item in journal.events) == tuple(
            range(1, journal.cursor + 1)
        )
        assert tuple(item.cursor for item in replay.events) == tuple(
            range(2, journal.cursor + 1)
        )
        assert replay.terminal is True
        assert await service.get_envelope_summary(investigation_id) == (
            terminal.envelope_summary
        )
        assert runner.calls == [
            (ScenarioName.STORAGE, ScenarioMode.FIXED, None, "operator-run-7")
        ]

        encoded = canonical_json_bytes(terminal).decode()
        for private_value in (
            "demo-project",
            "demo-bucket",
            "receipts/order-7.json",
            "The mutation result was not delivered",
            "generation-1700000000000000",
        ):
            assert private_value not in encoded
        await service.aclose()

    asyncio.run(check())


def test_adaptive_progress_is_projected_once_with_strategy_identity() -> None:
    async def check() -> None:
        service = OperatorApplicationService(
            runner=_ProgressRunner(),
            vertex_config=_vertex_config(),
            clock=_TickClock(),
        )
        launched = await service.launch(_launch(mode=ScenarioRunMode.ADAPTIVE))

        terminal = await _terminal_snapshot(
            service,
            launched.snapshot.investigation_id,
        )
        journal = await service.snapshot(terminal.investigation_id)

        assert terminal.lifecycle is ScenarioRunLifecycle.COMPLETED
        assert tuple(event.type for event in journal.events) == (
            ScenarioRunEventType.LIFECYCLE,
            ScenarioRunEventType.LIFECYCLE,
            ScenarioRunEventType.ENVELOPE_SUMMARY,
            ScenarioRunEventType.ADVISORY_TURN,
            ScenarioRunEventType.ADVISORY_TURN,
            ScenarioRunEventType.PROBE_REQUEST,
            ScenarioRunEventType.PROBE_RESULT,
            ScenarioRunEventType.EVIDENCE_DECISION,
            ScenarioRunEventType.TERMINAL,
        )
        request_event = journal.events[5]
        result_event = journal.events[6]
        assert isinstance(request_event.payload, ProbeRequestEventPayload)
        assert request_event.payload.strategy is ComparisonStrategyKind.ADAPTIVE
        assert request_event.payload.request.advisory_turn_sequence == 1
        assert request_event.payload.request.request_sequence == 1
        assert isinstance(result_event.payload, ProbeResultEventPayload)
        assert result_event.payload.strategy is ComparisonStrategyKind.ADAPTIVE
        assert result_event.payload.probe.probe_sequence == 1
        await service.aclose()

    asyncio.run(check())


def test_adaptive_without_server_configuration_fails_without_running() -> None:
    async def check() -> None:
        runner = _Runner()
        service = OperatorApplicationService(runner=runner, clock=_TickClock())
        launched = await service.launch(_launch(mode=ScenarioRunMode.ADAPTIVE))

        terminal = await _terminal_snapshot(
            service,
            launched.snapshot.investigation_id,
        )

        assert terminal.lifecycle is ScenarioRunLifecycle.FAILED
        assert terminal.failure_category is (
            ScenarioRunFailureCategory.MODEL_UNAVAILABLE
        )
        assert terminal.report is None
        assert terminal.comparison is None
        assert runner.calls == []
        with pytest.raises(ScenarioEnvelopeUnavailable):
            await service.get_envelope_summary(terminal.investigation_id)
        await service.aclose()

    asyncio.run(check())


def test_event_journal_reserves_its_final_slot_for_failure() -> None:
    async def overflowing_runner(
        scenario: ScenarioName,
        mode: ScenarioMode,
        *,
        vertex_config: VertexAdcPlannerConfig | None,
        run_id: str,
        progress_callback: ProgressCallback | None,
        cancellation_event: asyncio.Event | None,
    ) -> ScenarioWorkflowResult:
        del mode, vertex_config, cancellation_event
        assert progress_callback is not None
        investigation_id = scenario_investigation_id(scenario, run_id)
        for sequence in range(1, MAX_SCENARIO_RUN_EVENTS + 1):
            try:
                await progress_callback(
                    EvidenceProgress(
                        occurred_at=NOW + timedelta(milliseconds=sequence),
                        investigation_id=investigation_id,
                        strategy=ComparisonStrategyKind.FIXED,
                        attempt_sequence=((sequence - 1) % 64) + 1,
                        controller_sequence=sequence,
                        evidence_id=f"evidence-{sequence}",
                        disposition=EvidenceDisposition.REJECTED,
                        reason=EvidenceReason.BUDGET_EXHAUSTED,
                        classification=Classification.UNKNOWN,
                        continue_allowed=False,
                        escalation_required=True,
                    )
                )
            except ScenarioEventJournalFull as error:
                raise ProgressDeliveryError from error
        raise AssertionError("bounded journal did not reject excess progress")

    async def check() -> None:
        service = OperatorApplicationService(
            runner=overflowing_runner,
            clock=_TickClock(),
        )
        launched = await service.launch(_launch())

        terminal = await _terminal_snapshot(
            service,
            launched.snapshot.investigation_id,
        )
        journal = await service.snapshot(terminal.investigation_id)

        assert terminal.lifecycle is ScenarioRunLifecycle.FAILED
        assert terminal.failure_category is (
            ScenarioRunFailureCategory.EVENT_JOURNAL_FAILED
        )
        assert terminal.event_cursor == MAX_SCENARIO_RUN_EVENTS
        assert journal.cursor == len(journal.events) == MAX_SCENARIO_RUN_EVENTS
        assert journal.events[-1].type is ScenarioRunEventType.TERMINAL
        await service.aclose()

    asyncio.run(check())


def test_provider_failure_is_sanitized_and_never_returns_a_result() -> None:
    async def check() -> None:
        runner = _Runner(
            error=ScenarioWorkflowError(
                ScenarioWorkflowErrorCategory.PROVIDER_FAILED,
                scenario=ScenarioName.STORAGE,
            )
        )
        service = OperatorApplicationService(
            runner=runner,
            vertex_config=_vertex_config(),
            clock=_TickClock(),
        )
        launched = await service.launch(_launch(mode=ScenarioRunMode.ADAPTIVE))

        terminal = await _terminal_snapshot(
            service,
            launched.snapshot.investigation_id,
        )

        assert terminal.lifecycle is ScenarioRunLifecycle.FAILED
        assert terminal.failure_category is (
            ScenarioRunFailureCategory.MODEL_UNAVAILABLE
        )
        assert terminal.report is None
        assert terminal.comparison is None
        assert len(runner.calls) == 1
        assert runner.calls[0][2] == _vertex_config()
        await service.aclose()

    asyncio.run(check())


def test_partial_comparison_fails_without_publishing_a_baseline_lane() -> None:
    async def check() -> None:
        runner = _Runner(
            lambda investigation_id: _comparison(
                investigation_id,
                include_adaptive=False,
            )
        )
        service = OperatorApplicationService(
            runner=runner,
            vertex_config=_vertex_config(),
            clock=_TickClock(),
        )
        launched = await service.launch(_launch(mode=ScenarioRunMode.COMPARE))

        terminal = await _terminal_snapshot(
            service,
            launched.snapshot.investigation_id,
        )

        assert terminal.lifecycle is ScenarioRunLifecycle.FAILED
        assert terminal.failure_category is (
            ScenarioRunFailureCategory.COMPARISON_UNREPRESENTABLE
        )
        assert terminal.comparison is None
        assert terminal.report is None
        await service.aclose()

    asyncio.run(check())


def test_complete_comparison_remains_neutral() -> None:
    async def check() -> None:
        runner = _Runner(
            lambda investigation_id: _comparison(
                investigation_id,
                include_adaptive=True,
            )
        )
        service = OperatorApplicationService(
            runner=runner,
            vertex_config=_vertex_config(),
            clock=_TickClock(),
        )
        launched = await service.launch(_launch(mode=ScenarioRunMode.COMPARE))

        terminal = await _terminal_snapshot(
            service,
            launched.snapshot.investigation_id,
        )

        assert terminal.lifecycle is ScenarioRunLifecycle.COMPLETED
        assert terminal.comparison is not None
        assert terminal.comparison.adaptive is not None
        assert terminal.report is None
        final_event = (await service.snapshot(terminal.investigation_id)).events[-1]
        payload = final_event.payload
        assert payload.terminal.classification is None  # type: ignore[union-attr]
        assert "winner" not in canonical_json_bytes(terminal).decode()
        await service.aclose()

    asyncio.run(check())


def test_waiter_cancellation_does_not_cancel_the_scenario() -> None:
    async def check() -> None:
        runner = _Runner(hold=True)
        service = OperatorApplicationService(runner=runner, clock=_TickClock())
        launched = await service.launch(_launch())
        await runner.started.wait()
        current = await service.snapshot(launched.snapshot.investigation_id)
        disconnected = asyncio.Event()
        waiter = asyncio.create_task(
            service.wait_for_events(
                launched.snapshot.investigation_id,
                after=current.cursor,
                cancellation_event=disconnected,
            )
        )

        disconnected.set()
        with pytest.raises(asyncio.CancelledError):
            await waiter
        assert (await service.get(launched.snapshot.investigation_id)).lifecycle is (
            ScenarioRunLifecycle.RUNNING
        )

        runner.release.set()
        terminal = await _terminal_snapshot(
            service,
            launched.snapshot.investigation_id,
        )
        assert terminal.lifecycle is ScenarioRunLifecycle.COMPLETED
        await service.aclose()

    asyncio.run(check())


def test_close_cancels_and_joins_the_owned_run_after_cleanup() -> None:
    async def check() -> None:
        runner = _Runner(hold=True)
        service = OperatorApplicationService(runner=runner, clock=_TickClock())
        launched = await service.launch(_launch())
        await runner.started.wait()

        await service.aclose()

        terminal = await service.get(launched.snapshot.investigation_id)
        assert terminal.lifecycle is ScenarioRunLifecycle.CANCELLED
        assert runner.cleanup_reached is True
        assert runner.cancel_was_signalled is True
        with pytest.raises(OperatorServiceClosed):
            await service.launch(_launch(launch_id="operator-run-8"))

    asyncio.run(check())


def test_concurrent_close_callers_share_the_owned_run_join() -> None:
    async def check() -> None:
        runner_started = asyncio.Event()
        runner_release = asyncio.Event()

        async def cancellation_resistant_runner(
            scenario: ScenarioName,
            mode: ScenarioMode,
            *,
            vertex_config: VertexAdcPlannerConfig | None,
            run_id: str,
            progress_callback: ProgressCallback | None,
            cancellation_event: asyncio.Event | None,
        ) -> ScenarioWorkflowResult:
            del (
                scenario,
                mode,
                vertex_config,
                run_id,
                progress_callback,
                cancellation_event,
            )
            runner_started.set()
            try:
                await runner_release.wait()
            except asyncio.CancelledError:
                await runner_release.wait()
                raise
            raise AssertionError("runner completed without cancellation")

        service = OperatorApplicationService(
            runner=cancellation_resistant_runner,
            clock=_TickClock(),
        )
        launched = await service.launch(_launch())
        await runner_started.wait()

        first_close = asyncio.create_task(service.aclose())
        await asyncio.sleep(0)
        second_close = asyncio.create_task(service.aclose())
        await asyncio.sleep(0)

        assert not first_close.done()
        assert not second_close.done()
        assert (
            await service.get(launched.snapshot.investigation_id)
        ).lifecycle is ScenarioRunLifecycle.RUNNING

        runner_release.set()
        await asyncio.gather(first_close, second_close)

        terminal = await service.get(launched.snapshot.investigation_id)
        journal = await service.snapshot(terminal.investigation_id)
        assert terminal.lifecycle is ScenarioRunLifecycle.CANCELLED
        assert (
            sum(event.type is ScenarioRunEventType.TERMINAL for event in journal.events)
            == 1
        )

    asyncio.run(check())


def test_immediate_close_terminalizes_a_task_cancelled_before_start() -> None:
    async def check() -> None:
        runner = _Runner(hold=True)
        service = OperatorApplicationService(runner=runner, clock=_TickClock())
        launched = await service.launch(_launch())

        await service.aclose()

        terminal = await service.get(launched.snapshot.investigation_id)
        journal = await service.snapshot(terminal.investigation_id)
        assert runner.calls == []
        assert terminal.lifecycle is ScenarioRunLifecycle.CANCELLED
        assert terminal.event_cursor == 2
        assert journal.terminal is True
        assert journal.cursor == len(journal.events) == 2
        assert journal.events[-1].type is ScenarioRunEventType.TERMINAL

    asyncio.run(check())


def test_oversize_probe_projection_hides_rejected_result_identity() -> None:
    payload = make_report(Classification.UNKNOWN).model_dump(mode="python")
    audit = payload["probe_audit"][0]
    audit.update(
        {
            "outcome": ProbeOutcome.BUDGET_EXHAUSTED,
            "stop_reason": ProbeStopReason.RESULT_TOO_LARGE,
            "result_sha256": None,
            "result_byte_count": 89,
            "result_bytes_acquired": 89,
        }
    )
    payload["evidence"] = ()
    payload["evidence_decisions"][0].update(
        {
            "disposition": EvidenceDisposition.REJECTED,
            "reason": EvidenceReason.RESULT_TOO_LARGE,
        }
    )
    payload["missing_evidence"][0]["reason"] = EvidenceReason.RESULT_TOO_LARGE
    payload["advisory_explanation"] = None
    report = InvestigationReport.model_validate(payload)

    projected = sanitize_report(report)

    assert projected.classification is Classification.UNKNOWN
    assert projected.probe_audit[0].outcome is ProbeOutcome.BUDGET_EXHAUSTED
    assert projected.probe_audit[0].result_bytes_acquired == 89
    assert projected.probe_audit[0].result_sha256 is None
    assert projected.probe_audit[0].result_byte_count is None


def test_invalid_event_cursors_are_rejected() -> None:
    async def check() -> None:
        runner = _Runner(hold=True)
        service = OperatorApplicationService(runner=runner, clock=_TickClock())
        launched = await service.launch(_launch())
        await runner.started.wait()

        with pytest.raises(InvalidScenarioEventCursor):
            await service.snapshot(launched.snapshot.investigation_id, after=-1)
        with pytest.raises(InvalidScenarioEventCursor):
            await service.snapshot(launched.snapshot.investigation_id, after=True)
        with pytest.raises(InvalidScenarioEventCursor):
            await service.snapshot(launched.snapshot.investigation_id, after=999)

        runner.release.set()
        await _terminal_snapshot(service, launched.snapshot.investigation_id)
        await service.aclose()

    asyncio.run(check())
