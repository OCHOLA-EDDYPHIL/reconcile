from __future__ import annotations

import asyncio
import hashlib
import os
import sqlite3
import time
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

import reconcile.adaptive as adaptive_module
import reconcile.durable_scenarios as durable_scenarios_module
from reconcile.adaptive import AdvisoryPlannerTurn, PlannerFailureKind
from reconcile.contracts import (
    SCENARIO_LAUNCH_REQUEST_VERSION,
    SCENARIO_RUN_EVENT_VERSION,
    SCENARIO_RUN_SNAPSHOT_VERSION,
    AdaptivePlannerInput,
    AdaptivePlannerPhase,
    AdvisoryTurnEventPayload,
    AdvisoryTurnFailureCategory,
    AdvisoryTurnStatus,
    AdvisoryTurnSummary,
    Classification,
    ComparisonStrategyKind,
    EnvelopeSummaryEventPayload,
    InvestigationReport,
    InvestigationStatus,
    ProbeRequestEventPayload,
    ScenarioHybridOutcome,
    ScenarioHybridRoute,
    ScenarioLaunchName,
    ScenarioLaunchRequest,
    ScenarioLifecycleEventPayload,
    ScenarioOperationalCleanupState,
    ScenarioOperationalInvestigationState,
    ScenarioOperationalMutationState,
    ScenarioOperationalRecoveryState,
    ScenarioRunEvent,
    ScenarioRunEventType,
    ScenarioRunFailureCategory,
    ScenarioRunLifecycle,
    ScenarioRunMode,
    ScenarioRunResultKind,
    ScenarioRunSnapshot,
    TerminalStateEventPayload,
    TerminalStateSummary,
    canonical_json_bytes,
    decode_contract,
)
from reconcile.durable_application import (
    DurableExecutionContext,
    DurableInvestigationApplicationService,
    DurableServiceUnavailable,
)
from reconcile.durable_scenarios import DurableScenarioWorkflow
from reconcile.interfaces.api import create_app
from reconcile.operator import (
    OperatorApplicationService,
    OperatorServiceUnavailable,
    sanitize_report,
)
from reconcile.persistence import (
    CleanupStatus,
    CorruptScenarioState,
    RuntimeTelemetryKind,
    ScenarioInvestigationState,
    ScenarioLane,
    ScenarioLeaseUnavailable,
    ScenarioMutationState,
    ScenarioStateConflict,
    SqliteDurableRuntimeStore,
    SqliteScenarioStore,
    StaleScenarioLease,
    runtime_limits_for,
)
from reconcile.progress import ProbeProgress, ProbeProgressStage
from reconcile.scenarios.firestore_business import (
    FIRESTORE_BUSINESS_FIXED_PROBE_PLAN,
    FIRESTORE_BUSINESS_SCENARIO,
)
from reconcile.scenarios.runner import ScenarioRunner
from reconcile.scenarios.sandbox_order import SANDBOX_ORDER_FIXED_PROBE_PLAN
from reconcile.scenarios.service import (
    BOUNDED_HYBRID_ADVISORY_PROVENANCE,
    BOUNDED_HYBRID_EXPLICIT_UNKNOWN_PROVENANCE,
    BOUNDED_HYBRID_FIXED_PROVENANCE,
    BOUNDED_HYBRID_PROVIDER_CLEANUP_PROVENANCE,
    ScenarioMode,
    ScenarioName,
    ScenarioWorkflowError,
    ScenarioWorkflowErrorCategory,
    _definition,
    _envelope_summary,
    _seed_sandbox_fixture,
    bounded_hybrid_route_provenance,
    is_bounded_hybrid_explicit_unknown,
    is_bounded_hybrid_fixed_fallback,
)
from reconcile.scenarios.storage import STORAGE_FIXED_PROBE_PLAN
from tests.contract._factories import make_comparison_record, make_envelope, make_report
from tests.integration.test_adaptive_scenarios import _ScriptedPlanner

pytestmark = pytest.mark.integration

_SCENARIO_PROPOSALS = (
    (
        ScenarioLaunchName.STORAGE,
        tuple(step.request for step in STORAGE_FIXED_PROBE_PLAN.steps),
    ),
    (
        ScenarioLaunchName.FIRESTORE_BUSINESS,
        tuple(step.request for step in FIRESTORE_BUSINESS_FIXED_PROBE_PLAN.steps),
    ),
    (
        ScenarioLaunchName.SANDBOX_ORDER,
        tuple(step.request for step in SANDBOX_ORDER_FIXED_PROBE_PLAN.steps),
    ),
)


async def _bind(
    workflow: DurableScenarioWorkflow,
    *,
    launch_id: str,
    scenario: ScenarioLaunchName = ScenarioLaunchName.STORAGE,
    mode: ScenarioRunMode = ScenarioRunMode.FIXED,
):
    launch = ScenarioLaunchRequest(
        schema_version=SCENARIO_LAUNCH_REQUEST_VERSION,
        launch_id=launch_id,
        scenario=scenario,
        mode=mode,
    )
    accepted_at = datetime.now(UTC)
    scenario_name = ScenarioName(scenario.value)
    from reconcile.scenarios.service import scenario_investigation_id

    investigation_id = scenario_investigation_id(scenario_name, launch_id)
    event = ScenarioRunEvent(
        schema_version=SCENARIO_RUN_EVENT_VERSION,
        investigation_id=investigation_id,
        cursor=1,
        type=ScenarioRunEventType.LIFECYCLE,
        occurred_at=accepted_at,
        payload=ScenarioLifecycleEventPayload(lifecycle=ScenarioRunLifecycle.ACCEPTED),
    )
    snapshot = ScenarioRunSnapshot(
        schema_version=SCENARIO_RUN_SNAPSHOT_VERSION,
        launch_id=launch_id,
        investigation_id=investigation_id,
        scenario=scenario,
        mode=mode,
        lifecycle=ScenarioRunLifecycle.ACCEPTED,
        event_cursor=1,
        envelope_summary=None,
        report=None,
        comparison=None,
        failure_category=None,
        accepted_at=accepted_at,
        updated_at=accepted_at,
    )
    return await workflow.bind_launch(
        launch,
        snapshot=snapshot,
        accepted_event=event,
    )


async def _terminal(service: OperatorApplicationService, investigation_id: str):
    async with asyncio.timeout(20):
        while True:
            snapshot = await service.get(investigation_id)
            if snapshot.lifecycle in {
                ScenarioRunLifecycle.COMPLETED,
                ScenarioRunLifecycle.FAILED,
                ScenarioRunLifecycle.CANCELLED,
            }:
                return snapshot
            await asyncio.sleep(0.02)


async def _record_mutation_and_start_investigation(
    store: SqliteScenarioStore,
    workspace_root: Path,
    bound,
    *,
    start_investigation: bool = True,
) -> None:
    work = bound.work
    workspace = workspace_root / work.workspace_id
    scenario = ScenarioName(work.launch_request.scenario.value)
    definition = _definition(
        scenario,
        workspace,
        invoked_at=work.invoked_at,
        seed_sandbox=False,
    )
    runner = ScenarioRunner()
    prepared = runner.prepare(work.scenario_request, definition)
    token = await store.acquire_scenario_lease(
        work.scenario_request.investigation_id,
        "boundary-owner",
        now=datetime.now(UTC),
    )
    await store.record_mutation_started(
        token,
        prepared_envelope_sha256=hashlib.sha256(
            prepared.execution_envelope_bytes
        ).hexdigest(),
        cleanup_manifest_sha256=prepared.cleanup_manifest_sha256,
        occurred_at=datetime.now(UTC),
    )
    if scenario is ScenarioName.SANDBOX_ORDER:
        _seed_sandbox_fixture(workspace)
    result = await asyncio.to_thread(
        runner.run_prepared,
        work.scenario_request,
        definition,
        prepared,
    )
    await store.record_mutation_result(
        token,
        result,
        prepared_envelope_bytes=prepared.execution_envelope_bytes,
        occurred_at=datetime.now(UTC),
    )
    if start_investigation:
        await store.mark_investigation_started(token, occurred_at=datetime.now(UTC))
    await store.release_scenario_lease(token, now=datetime.now(UTC))


def _report_for_work(work, *, status=InvestigationStatus.COMPLETED):
    return make_report(Classification.COMMITTED).model_copy(
        update={
            "investigation_id": work.scenario_request.investigation_id,
            "envelope_sha256": work.envelope_sha256,
            "status": status,
        }
    )


def _comparison_for_work(work, *, scenario=None):
    template = make_comparison_record(include_adaptive=True)
    assert template.adaptive is not None
    scenario = work.scenario_request.scenario if scenario is None else scenario
    baseline = template.baseline.model_copy(
        update={
            "scenario": scenario,
            "envelope_sha256": work.envelope_sha256,
        }
    )
    adaptive = template.adaptive.model_copy(
        update={
            "scenario": scenario,
            "envelope_sha256": work.envelope_sha256,
        }
    )
    return template.model_copy(
        update={
            "scenario": scenario,
            "envelope_sha256": work.envelope_sha256,
            "baseline": baseline,
            "adaptive": adaptive,
        }
    )


async def _ready_parent_for_workflow_result(
    tmp_path: Path,
    *,
    launch_id: str,
    mode: ScenarioRunMode,
):
    os.chmod(tmp_path, 0o700)
    workspace_root = tmp_path / "workspaces"
    workspace_root.mkdir(mode=0o700)
    store = SqliteScenarioStore(tmp_path / "parent.sqlite3")
    workflow = DurableScenarioWorkflow(
        store,
        workspace_root,
        semantic_config_sha256="0" * 64,
    )
    bound = await _bind(workflow, launch_id=launch_id, mode=mode)
    await _record_mutation_and_start_investigation(store, workspace_root, bound)
    work = await store.get_work(bound.work.scenario_request.investigation_id)
    token = await store.acquire_scenario_lease(
        work.scenario_request.investigation_id,
        "workflow-result-owner",
        now=datetime.now(UTC),
    )
    return store, work, token


async def _append_completed_report_projection(
    store: SqliteScenarioStore,
    work,
) -> None:
    assert work.scenario_result is not None
    assert work.scenario_result.execution_envelope is not None
    assert work.workflow_result is not None
    report = sanitize_report(work.workflow_result)
    assert report.classification is not None
    snapshot = work.snapshot
    if snapshot.lifecycle is ScenarioRunLifecycle.ACCEPTED:
        running_at = datetime.now(UTC)
        running_event = ScenarioRunEvent(
            schema_version=SCENARIO_RUN_EVENT_VERSION,
            investigation_id=work.scenario_request.investigation_id,
            cursor=snapshot.event_cursor + 1,
            type=ScenarioRunEventType.LIFECYCLE,
            occurred_at=running_at,
            payload=ScenarioLifecycleEventPayload(
                lifecycle=ScenarioRunLifecycle.RUNNING
            ),
        )
        snapshot = snapshot.model_copy(
            update={
                "lifecycle": ScenarioRunLifecycle.RUNNING,
                "event_cursor": running_event.cursor,
                "updated_at": running_at,
            }
        )
        updated = await store.append_projection(
            snapshot,
            running_event,
            terminal=False,
        )
        snapshot = updated.snapshot
    if snapshot.envelope_summary is None:
        summary_at = datetime.now(UTC)
        summary = _envelope_summary(work.scenario_result.execution_envelope)
        summary_event = ScenarioRunEvent(
            schema_version=SCENARIO_RUN_EVENT_VERSION,
            investigation_id=work.scenario_request.investigation_id,
            cursor=snapshot.event_cursor + 1,
            type=ScenarioRunEventType.ENVELOPE_SUMMARY,
            occurred_at=summary_at,
            payload=EnvelopeSummaryEventPayload(summary=summary),
        )
        snapshot = snapshot.model_copy(
            update={
                "event_cursor": summary_event.cursor,
                "envelope_summary": summary,
                "updated_at": summary_at,
            }
        )
        updated = await store.append_projection(
            snapshot,
            summary_event,
            terminal=False,
        )
        snapshot = updated.snapshot
    occurred_at = datetime.now(UTC)
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
    event = ScenarioRunEvent(
        schema_version=SCENARIO_RUN_EVENT_VERSION,
        investigation_id=work.scenario_request.investigation_id,
        cursor=snapshot.event_cursor + 1,
        type=ScenarioRunEventType.TERMINAL,
        occurred_at=occurred_at,
        payload=TerminalStateEventPayload(terminal=terminal),
    )
    snapshot = snapshot.model_copy(
        update={
            "lifecycle": ScenarioRunLifecycle.COMPLETED,
            "event_cursor": event.cursor,
            "envelope_summary": snapshot.envelope_summary,
            "report": report,
            "comparison": None,
            "failure_category": None,
            "updated_at": occurred_at,
        }
    )
    await store.append_projection(snapshot, event, terminal=True)


@pytest.mark.parametrize(
    "scenario",
    (
        ScenarioLaunchName.STORAGE,
        ScenarioLaunchName.FIRESTORE_BUSINESS,
        ScenarioLaunchName.SANDBOX_ORDER,
    ),
)
def test_real_fixed_operator_scenarios_use_durable_parent_and_lane(
    tmp_path: Path,
    scenario: ScenarioLaunchName,
) -> None:
    async def exercise() -> None:
        os.chmod(tmp_path, 0o700)
        workspace_root = tmp_path / "workspaces"
        workspace_root.mkdir(mode=0o700)
        store = SqliteScenarioStore(tmp_path / "parent.sqlite3")
        workflow = DurableScenarioWorkflow(
            store,
            workspace_root,
            semantic_config_sha256="a" * 64,
        )
        service = OperatorApplicationService(
            runner=workflow,
            projection_store=store,
        )
        await service.start()
        launch = ScenarioLaunchRequest(
            schema_version=SCENARIO_LAUNCH_REQUEST_VERSION,
            launch_id=f"durable-{scenario.value}",
            scenario=scenario,
            mode=ScenarioRunMode.FIXED,
        )
        created = await service.launch(launch)
        terminal = await _terminal(service, created.snapshot.investigation_id)
        work = await store.get_work(created.snapshot.investigation_id)
        status = await service.get_operational_status(created.snapshot.investigation_id)
        await service.aclose()

        assert terminal.lifecycle is ScenarioRunLifecycle.COMPLETED
        assert work.workflow_result is not None
        assert terminal.report is not None
        assert work.mutation_state is ScenarioMutationState.RECORDED
        assert work.investigation_state is ScenarioInvestigationState.RECORDED
        assert work.cleanup_status is CleanupStatus.SUCCEEDED
        assert status.revision == work.revision
        assert status.mutation_state is ScenarioOperationalMutationState.RECORDED
        assert (
            status.investigation_state is ScenarioOperationalInvestigationState.RECORDED
        )
        assert status.cleanup_state is ScenarioOperationalCleanupState.SUCCEEDED
        assert status.recovery_state is ScenarioOperationalRecoveryState.NOT_ESCALATED
        lane = workspace_root / work.workspace_id / "runtime-fixed.sqlite3"
        assert lane.is_file()

    asyncio.run(exercise())


def test_parent_waits_for_child_terminal_telemetry_before_cleanup_and_close(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def exercise() -> None:
        os.chmod(tmp_path, 0o700)
        workspace_root = tmp_path / "workspaces"
        workspace_root.mkdir(mode=0o700)
        store = SqliteScenarioStore(tmp_path / "parent.sqlite3")
        workflow = DurableScenarioWorkflow(
            store,
            workspace_root,
            semantic_config_sha256="7" * 64,
        )
        bound = await _bind(workflow, launch_id="delayed-child-terminal")
        investigation_id = bound.work.scenario_request.investigation_id
        telemetry_entered = asyncio.Event()
        release_telemetry = asyncio.Event()
        close_observations: list[tuple[bool, frozenset[RuntimeTelemetryKind]]] = []
        original_emit = DurableExecutionContext.emit_report_telemetry
        original_close = DurableInvestigationApplicationService.aclose

        async def delayed_emit(context, report):
            telemetry_entered.set()
            await release_telemetry.wait()
            await original_emit(context, report)

        async def observed_close(service):
            journal = await service._store.snapshot_events(investigation_id)
            telemetry = await service._store.telemetry_records(investigation_id)
            close_observations.append(
                (journal.terminal, frozenset(record.kind for record in telemetry))
            )
            await original_close(service)

        monkeypatch.setattr(
            DurableExecutionContext,
            "emit_report_telemetry",
            delayed_emit,
        )
        monkeypatch.setattr(
            DurableInvestigationApplicationService,
            "aclose",
            observed_close,
        )
        task = asyncio.create_task(
            workflow(
                ScenarioName.STORAGE,
                ScenarioMode.FIXED,
                vertex_config=None,
                run_id="delayed-child-terminal",
                progress_callback=None,
                cancellation_event=None,
            )
        )
        await asyncio.wait_for(telemetry_entered.wait(), timeout=20)
        pending = await store.get_work(investigation_id)
        lane_store = SqliteDurableRuntimeStore(
            workspace_root / pending.workspace_id / "runtime-fixed.sqlite3"
        )
        journal = await lane_store.snapshot_events(investigation_id)
        telemetry = await lane_store.telemetry_records(investigation_id)
        try:
            assert pending.workflow_result is None
            assert pending.cleanup_status is CleanupStatus.NOT_REQUESTED
            assert not journal.terminal
            assert close_observations == []
            assert RuntimeTelemetryKind.CLASSIFIER not in {
                record.kind for record in telemetry
            }
            assert RuntimeTelemetryKind.ACTION_GATE not in {
                record.kind for record in telemetry
            }
        finally:
            release_telemetry.set()

        await asyncio.wait_for(task, timeout=20)
        complete = await store.get_work(investigation_id)
        final_journal = await lane_store.snapshot_events(investigation_id)
        final_telemetry = await lane_store.telemetry_records(investigation_id)

        assert len(close_observations) == 1
        assert close_observations[0][0]
        assert RuntimeTelemetryKind.CLASSIFIER in close_observations[0][1]
        assert RuntimeTelemetryKind.ACTION_GATE in close_observations[0][1]
        assert final_journal.terminal
        assert complete.cleanup_status is CleanupStatus.SUCCEEDED
        assert RuntimeTelemetryKind.CLASSIFIER in {
            record.kind for record in final_telemetry
        }
        assert RuntimeTelemetryKind.ACTION_GATE in {
            record.kind for record in final_telemetry
        }

    asyncio.run(exercise())


def test_child_terminal_projection_failure_fails_closed_without_parent_cleanup(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def exercise() -> None:
        os.chmod(tmp_path, 0o700)
        workspace_root = tmp_path / "workspaces"
        workspace_root.mkdir(mode=0o700)
        store = SqliteScenarioStore(tmp_path / "parent.sqlite3")
        workflow = DurableScenarioWorkflow(
            store,
            workspace_root,
            semantic_config_sha256="6" * 64,
        )
        bound = await _bind(workflow, launch_id="child-projection-failure")
        investigation_id = bound.work.scenario_request.investigation_id
        projection_attempted = asyncio.Event()

        async def fail_projection(service, run, authority):
            del service, run, authority
            projection_attempted.set()
            raise RuntimeError("injected child projection failure")

        monkeypatch.setattr(
            DurableInvestigationApplicationService,
            "_project_terminal",
            fail_projection,
        )
        with pytest.raises(DurableServiceUnavailable):
            async with asyncio.timeout(20):
                await workflow(
                    ScenarioName.STORAGE,
                    ScenarioMode.FIXED,
                    vertex_config=None,
                    run_id="child-projection-failure",
                    progress_callback=None,
                    cancellation_event=None,
                )
        failed = await store.get_work(investigation_id)
        lane_store = SqliteDurableRuntimeStore(
            workspace_root / failed.workspace_id / "runtime-fixed.sqlite3"
        )
        journal = await lane_store.snapshot_events(investigation_id)

        assert projection_attempted.is_set()
        assert not journal.terminal
        assert failed.investigation_state is ScenarioInvestigationState.STARTED
        assert failed.workflow_result is None
        assert failed.cleanup_status is CleanupStatus.NOT_REQUESTED

    asyncio.run(exercise())


def test_child_record_probe_exit_surfaces_without_parent_cleanup(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def exercise() -> None:
        os.chmod(tmp_path, 0o700)
        workspace_root = tmp_path / "workspaces"
        workspace_root.mkdir(mode=0o700)
        store = SqliteScenarioStore(tmp_path / "parent.sqlite3")
        workflow = DurableScenarioWorkflow(
            store,
            workspace_root,
            semantic_config_sha256="4" * 64,
        )
        bound = await _bind(workflow, launch_id="child-record-probe-exit")
        investigation_id = bound.work.scenario_request.investigation_id
        original_record_probe = SqliteDurableRuntimeStore.record_probe
        failed_once = False

        async def fail_record_probe_once(lane_store, *args, **kwargs):
            nonlocal failed_once
            if not failed_once:
                failed_once = True
                raise RuntimeError("injected record-probe loss")
            return await original_record_probe(lane_store, *args, **kwargs)

        monkeypatch.setattr(
            SqliteDurableRuntimeStore,
            "record_probe",
            fail_record_probe_once,
        )
        with pytest.raises(DurableServiceUnavailable):
            async with asyncio.timeout(20):
                await workflow(
                    ScenarioName.STORAGE,
                    ScenarioMode.FIXED,
                    vertex_config=None,
                    run_id="child-record-probe-exit",
                    progress_callback=None,
                    cancellation_event=None,
                )
        failed = await store.get_work(investigation_id)

        assert failed_once
        assert failed.investigation_state is ScenarioInvestigationState.STARTED
        assert failed.workflow_result is None
        assert failed.cleanup_status is CleanupStatus.NOT_REQUESTED

    asyncio.run(exercise())


def test_spontaneously_cancelled_child_surfaces_without_parent_cleanup(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def exercise() -> None:
        os.chmod(tmp_path, 0o700)
        workspace_root = tmp_path / "workspaces"
        workspace_root.mkdir(mode=0o700)
        store = SqliteScenarioStore(tmp_path / "parent.sqlite3")
        workflow = DurableScenarioWorkflow(
            store,
            workspace_root,
            semantic_config_sha256="5" * 64,
        )
        bound = await _bind(workflow, launch_id="spontaneous-child-cancel")
        investigation_id = bound.work.scenario_request.investigation_id
        cancelled = asyncio.Event()

        async def cancel_fixed_investigation(*args, **kwargs):
            del args, kwargs
            cancelled.set()
            raise asyncio.CancelledError

        monkeypatch.setattr(
            durable_scenarios_module,
            "_fixed_investigation",
            cancel_fixed_investigation,
        )
        with pytest.raises(DurableServiceUnavailable):
            async with asyncio.timeout(20):
                await workflow(
                    ScenarioName.STORAGE,
                    ScenarioMode.FIXED,
                    vertex_config=None,
                    run_id="spontaneous-child-cancel",
                    progress_callback=None,
                    cancellation_event=None,
                )
        failed = await store.get_work(investigation_id)

        assert cancelled.is_set()
        assert failed.investigation_state is ScenarioInvestigationState.STARTED
        assert failed.workflow_result is None
        assert failed.cleanup_status is CleanupStatus.NOT_REQUESTED

    asyncio.run(exercise())


def test_real_adaptive_scenario_precharges_every_planner_turn(
    tmp_path: Path,
) -> None:
    async def exercise() -> None:
        scenario = ScenarioLaunchName.SANDBOX_ORDER
        proposals = tuple(step.request for step in SANDBOX_ORDER_FIXED_PROBE_PLAN.steps)
        os.chmod(tmp_path, 0o700)
        workspace_root = tmp_path / "workspaces"
        workspace_root.mkdir(mode=0o700)
        store = SqliteScenarioStore(tmp_path / "parent.sqlite3")
        planners: list[_ScriptedPlanner] = []

        def planner_factory(_scenario):
            planner = _ScriptedPlanner(proposals)
            planners.append(planner)
            return planner

        workflow = DurableScenarioWorkflow(
            store,
            workspace_root,
            semantic_config_sha256="b" * 64,
            planner_factory=planner_factory,
        )
        service = OperatorApplicationService(
            runner=workflow,
            projection_store=store,
        )
        await service.start()
        launch = ScenarioLaunchRequest(
            schema_version=SCENARIO_LAUNCH_REQUEST_VERSION,
            launch_id=f"durable-adaptive-{scenario.value}",
            scenario=scenario,
            mode=ScenarioRunMode.ADAPTIVE,
        )
        created = await service.launch(launch)
        terminal = await _terminal(service, created.snapshot.investigation_id)
        journal = await service.snapshot(created.snapshot.investigation_id)
        work = await store.get_work(created.snapshot.investigation_id)
        await service.aclose()

        assert terminal.lifecycle is ScenarioRunLifecycle.COMPLETED
        assert work.workflow_result is not None
        assert BOUNDED_HYBRID_ADVISORY_PROVENANCE in work.workflow_result.limitations
        assert terminal.report is not None
        assert terminal.report.route_provenance is not None
        assert terminal.report.route_provenance.route is (
            ScenarioHybridRoute.PLANNER_HETEROGENEOUS
        )
        assert terminal.report.route_provenance.outcome is (
            ScenarioHybridOutcome.PLANNER_EVIDENCE
        )
        lane_path = workspace_root / work.workspace_id / "runtime-adaptive.sqlite3"
        lane_store = SqliteDurableRuntimeStore(lane_path)
        receipts = await lane_store.provider_call_receipts(
            created.snapshot.investigation_id
        )
        assert receipts
        started_turns = sum(
            isinstance(event.payload, AdvisoryTurnEventPayload)
            and event.payload.turn.status is AdvisoryTurnStatus.STARTED
            for event in journal.events
        )
        assert len(planners) == 1
        assert len(receipts) == len(planners[0].inputs) == started_turns
        assert tuple(receipt.order for receipt in receipts) == tuple(
            range(1, len(receipts) + 1)
        )
        assert len({receipt.call_id for receipt in receipts}) == len(receipts)
        assert all(receipt.call_id.startswith("planner-") for receipt in receipts)

    asyncio.run(exercise())


@pytest.mark.parametrize(
    "scenario",
    (ScenarioLaunchName.STORAGE, ScenarioLaunchName.FIRESTORE_BUSINESS),
)
def test_adaptive_authoritative_routes_never_construct_a_planner(
    tmp_path: Path,
    scenario: ScenarioLaunchName,
) -> None:
    async def exercise() -> None:
        os.chmod(tmp_path, 0o700)
        workspace_root = tmp_path / "workspaces"
        workspace_root.mkdir(mode=0o700)
        store = SqliteScenarioStore(tmp_path / "parent.sqlite3")
        planner_factories = 0

        def planner_factory(_scenario):
            nonlocal planner_factories
            planner_factories += 1
            raise AssertionError("authoritative routes cannot construct a planner")

        workflow = DurableScenarioWorkflow(
            store,
            workspace_root,
            semantic_config_sha256="a" * 64,
            planner_factory=planner_factory,
        )
        service = OperatorApplicationService(runner=workflow, projection_store=store)
        await service.start()
        launch = ScenarioLaunchRequest(
            schema_version=SCENARIO_LAUNCH_REQUEST_VERSION,
            launch_id=f"durable-authoritative-{scenario.value}",
            scenario=scenario,
            mode=ScenarioRunMode.ADAPTIVE,
        )
        created = await service.launch(launch)
        terminal = await _terminal(service, created.snapshot.investigation_id)
        work = await store.get_work(created.snapshot.investigation_id)
        await service.aclose()

        lane_root = workspace_root / work.workspace_id
        assert terminal.lifecycle is ScenarioRunLifecycle.COMPLETED
        assert planner_factories == 0
        assert work.workflow_result is not None
        assert BOUNDED_HYBRID_FIXED_PROVENANCE in work.workflow_result.limitations
        assert terminal.report is not None
        assert terminal.report.route_provenance is not None
        assert terminal.report.route_provenance.route is (
            ScenarioHybridRoute.FIXED_AUTHORITATIVE
        )
        assert (lane_root / "runtime-fixed.sqlite3").is_file()
        assert not (lane_root / "runtime-adaptive.sqlite3").exists()

    asyncio.run(exercise())


@pytest.mark.parametrize(
    "failure_kind",
    ("missing", "factory", "protocol", "dispatch"),
)
def test_sandbox_adaptive_provider_failure_uses_separate_fixed_fallback_lane(
    tmp_path: Path,
    failure_kind: str,
) -> None:
    async def exercise() -> None:
        os.chmod(tmp_path, 0o700)
        workspace_root = tmp_path / "workspaces"
        workspace_root.mkdir(mode=0o700)
        store = SqliteScenarioStore(tmp_path / "parent.sqlite3")
        planner_factory = None
        invalid_planners = []
        if failure_kind == "factory":

            def planner_factory(_scenario):
                raise RuntimeError("private provider construction detail")

        elif failure_kind == "protocol":

            class InvalidPlanner:
                closed = False

                @property
                def metadata(self):
                    return object()

                async def plan(self, planner_input):
                    del planner_input
                    raise AssertionError("invalid planner cannot be invoked")

                async def aclose(self):
                    self.closed = True

            def invalid_factory(_scenario):
                planner = InvalidPlanner()
                invalid_planners.append(planner)
                return planner

            planner_factory = invalid_factory

        elif failure_kind == "dispatch":

            class UnavailablePlanner(_ScriptedPlanner):
                async def plan(self, planner_input):
                    del planner_input
                    raise RuntimeError("private provider dispatch detail")

            def unavailable_factory(_scenario):
                return UnavailablePlanner(())

            planner_factory = unavailable_factory

        workflow = DurableScenarioWorkflow(
            store,
            workspace_root,
            semantic_config_sha256="f" * 64,
            planner_factory=planner_factory,
        )
        service = OperatorApplicationService(runner=workflow, projection_store=store)
        await service.start()
        launch = ScenarioLaunchRequest(
            schema_version=SCENARIO_LAUNCH_REQUEST_VERSION,
            launch_id=f"durable-fallback-{failure_kind}",
            scenario=ScenarioLaunchName.SANDBOX_ORDER,
            mode=ScenarioRunMode.ADAPTIVE,
        )
        created = await service.launch(launch)
        terminal = await _terminal(service, created.snapshot.investigation_id)
        journal = await service.snapshot(created.snapshot.investigation_id)
        work = await store.get_work(created.snapshot.investigation_id)
        await service.aclose()

        assert terminal.lifecycle is ScenarioRunLifecycle.COMPLETED
        assert terminal.report is not None
        assert terminal.report.classification is Classification.UNKNOWN
        assert terminal.report.route_provenance is not None
        assert terminal.report.route_provenance.outcome is (
            ScenarioHybridOutcome.FIXED_FALLBACK
        )
        assert terminal.report.route_provenance.planner_invoked is (
            failure_kind == "dispatch"
        )
        assert work.workflow_result is not None
        assert is_bounded_hybrid_fixed_fallback(work.workflow_result)
        lane_root = workspace_root / work.workspace_id
        assert (lane_root / "runtime-fixed.sqlite3").is_file()
        if failure_kind in {"missing", "factory", "protocol"}:
            assert not (lane_root / "runtime-adaptive.sqlite3").exists()
        else:
            assert (lane_root / "runtime-adaptive.sqlite3").is_file()
        fixed_requests = tuple(
            event
            for event in journal.events
            if isinstance(event.payload, ProbeRequestEventPayload)
            and event.payload.strategy is ComparisonStrategyKind.FIXED
        )
        assert len(fixed_requests) == len(SANDBOX_ORDER_FIXED_PROBE_PLAN.steps)
        advisory_failures = tuple(
            event
            for event in journal.events
            if isinstance(event.payload, AdvisoryTurnEventPayload)
            and event.payload.turn.status is AdvisoryTurnStatus.FAILED
        )
        assert bool(advisory_failures) is (failure_kind == "dispatch")
        if failure_kind == "protocol":
            assert len(invalid_planners) == 1
            assert invalid_planners[0].closed

    asyncio.run(exercise())


def test_durable_explanation_failure_preserves_advisory_result(
    tmp_path: Path,
) -> None:
    async def exercise() -> None:
        os.chmod(tmp_path, 0o700)
        workspace_root = tmp_path / "workspaces"
        workspace_root.mkdir(mode=0o700)
        store = SqliteScenarioStore(tmp_path / "parent.sqlite3")

        class ExplanationFailurePlanner(_ScriptedPlanner):
            async def plan(
                self,
                planner_input: AdaptivePlannerInput,
            ) -> AdvisoryPlannerTurn:
                if planner_input.phase is not AdaptivePlannerPhase.EXPLAIN_EVIDENCE:
                    return await super().plan(planner_input)
                payload = canonical_json_bytes(planner_input)
                self.inputs.append(planner_input)
                self.input_bytes.append(payload)
                return AdvisoryPlannerTurn(
                    output=None,
                    failure=PlannerFailureKind.UNAVAILABLE,
                    metadata=self.metadata,
                    input_sha256=hashlib.sha256(payload).hexdigest(),
                    output_sha256=None,
                    usage=None,
                )

        workflow = DurableScenarioWorkflow(
            store,
            workspace_root,
            semantic_config_sha256="e" * 64,
            planner_factory=lambda _scenario: ExplanationFailurePlanner(
                tuple(step.request for step in SANDBOX_ORDER_FIXED_PROBE_PLAN.steps)
            ),
        )
        service = OperatorApplicationService(runner=workflow, projection_store=store)
        await service.start()
        launch = ScenarioLaunchRequest(
            schema_version=SCENARIO_LAUNCH_REQUEST_VERSION,
            launch_id="durable-explanation-provider-failure",
            scenario=ScenarioLaunchName.SANDBOX_ORDER,
            mode=ScenarioRunMode.ADAPTIVE,
        )
        created = await service.launch(launch)
        terminal = await _terminal(service, created.snapshot.investigation_id)
        journal = await service.snapshot(created.snapshot.investigation_id)
        work = await store.get_work(created.snapshot.investigation_id)
        await service.aclose()

        assert terminal.lifecycle is ScenarioRunLifecycle.COMPLETED
        assert terminal.report is not None
        assert terminal.report.classification is Classification.UNKNOWN
        assert terminal.report.route_provenance is not None
        assert terminal.report.route_provenance.outcome is (
            ScenarioHybridOutcome.PLANNER_EVIDENCE
        )
        assert not terminal.report.route_provenance.provider_failure
        assert work.workflow_result is not None
        assert not is_bounded_hybrid_fixed_fallback(work.workflow_result)
        assert not is_bounded_hybrid_explicit_unknown(work.workflow_result)
        failed_turns = tuple(
            event.payload.turn
            for event in journal.events
            if isinstance(event.payload, AdvisoryTurnEventPayload)
            and event.payload.turn.status is AdvisoryTurnStatus.FAILED
        )
        assert len(failed_turns) == 1
        assert failed_turns[0].phase is AdaptivePlannerPhase.EXPLAIN_EVIDENCE
        assert failed_turns[0].failure_category is (
            AdvisoryTurnFailureCategory.UNAVAILABLE
        )
        lane_root = workspace_root / work.workspace_id
        assert (lane_root / "runtime-adaptive.sqlite3").is_file()
        assert not (lane_root / "runtime-fixed.sqlite3").exists()

    asyncio.run(exercise())


def test_late_durable_provider_failure_stops_unknown_without_budget_reset(
    tmp_path: Path,
) -> None:
    async def exercise() -> None:
        os.chmod(tmp_path, 0o700)
        workspace_root = tmp_path / "workspaces"
        workspace_root.mkdir(mode=0o700)
        store = SqliteScenarioStore(tmp_path / "parent.sqlite3")
        first_request = SANDBOX_ORDER_FIXED_PROBE_PLAN.steps[0].request
        planners: list[_ScriptedPlanner] = []

        class LateFailurePlanner(_ScriptedPlanner):
            async def plan(
                self,
                planner_input: AdaptivePlannerInput,
            ) -> AdvisoryPlannerTurn:
                if not self.inputs:
                    return await super().plan(planner_input)
                payload = canonical_json_bytes(planner_input)
                self.inputs.append(planner_input)
                self.input_bytes.append(payload)
                return AdvisoryPlannerTurn(
                    output=None,
                    failure=PlannerFailureKind.UNAVAILABLE,
                    metadata=self.metadata,
                    input_sha256=hashlib.sha256(payload).hexdigest(),
                    output_sha256=None,
                    usage=None,
                )

        def planner_factory(_scenario):
            planner = LateFailurePlanner((first_request,))
            planners.append(planner)
            return planner

        workflow = DurableScenarioWorkflow(
            store,
            workspace_root,
            semantic_config_sha256="1" * 64,
            planner_factory=planner_factory,
        )
        service = OperatorApplicationService(runner=workflow, projection_store=store)
        await service.start()
        launch = ScenarioLaunchRequest(
            schema_version=SCENARIO_LAUNCH_REQUEST_VERSION,
            launch_id="durable-late-provider-failure",
            scenario=ScenarioLaunchName.SANDBOX_ORDER,
            mode=ScenarioRunMode.ADAPTIVE,
        )
        created = await service.launch(launch)
        terminal = await _terminal(service, created.snapshot.investigation_id)
        journal = await service.snapshot(created.snapshot.investigation_id)
        work = await store.get_work(created.snapshot.investigation_id)
        await service.aclose()

        assert terminal.lifecycle is ScenarioRunLifecycle.COMPLETED
        assert terminal.report is not None
        assert terminal.report.classification is Classification.UNKNOWN
        assert terminal.report.route_provenance is not None
        assert terminal.report.route_provenance.outcome is (
            ScenarioHybridOutcome.EXPLICIT_UNKNOWN
        )
        assert work.workflow_result is not None
        assert is_bounded_hybrid_explicit_unknown(work.workflow_result)
        assert BOUNDED_HYBRID_EXPLICIT_UNKNOWN_PROVENANCE in (
            work.workflow_result.limitations
        )
        lane_root = workspace_root / work.workspace_id
        adaptive_path = lane_root / "runtime-adaptive.sqlite3"
        assert adaptive_path.is_file()
        assert not (lane_root / "runtime-fixed.sqlite3").exists()
        lane_store = SqliteDurableRuntimeStore(adaptive_path)
        checkpoints = await lane_store.probe_checkpoints(
            created.snapshot.investigation_id
        )
        receipts = await lane_store.provider_call_receipts(
            created.snapshot.investigation_id
        )
        assert len(planners) == 1
        assert len(planners[0].inputs) == len(receipts) == 2
        assert len(checkpoints) == 1
        assert work.scenario_result is not None
        assert work.scenario_result.execution_envelope is not None
        assert len(checkpoints) <= (
            work.scenario_result.execution_envelope.context.evidence_budget.max_probes
        )
        fixed_requests = tuple(
            event
            for event in journal.events
            if isinstance(event.payload, ProbeRequestEventPayload)
            and event.payload.strategy is ComparisonStrategyKind.FIXED
        )
        assert fixed_requests == ()

    asyncio.run(exercise())


def test_late_trusted_input_failure_escalates_without_fixed_fallback(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def exercise() -> None:
        os.chmod(tmp_path, 0o700)
        workspace_root = tmp_path / "workspaces"
        workspace_root.mkdir(mode=0o700)
        store = SqliteScenarioStore(tmp_path / "parent.sqlite3")
        first_request = SANDBOX_ORDER_FIXED_PROBE_PLAN.steps[0].request
        original_input = adaptive_module._planner_input
        input_calls = 0

        def fail_second_input(*args, **kwargs):
            nonlocal input_calls
            input_calls += 1
            if input_calls == 2:
                raise ValueError("private trusted input construction detail")
            return original_input(*args, **kwargs)

        monkeypatch.setattr(adaptive_module, "_planner_input", fail_second_input)
        workflow = DurableScenarioWorkflow(
            store,
            workspace_root,
            semantic_config_sha256="6" * 64,
            planner_factory=lambda _scenario: _ScriptedPlanner((first_request,)),
        )
        service = OperatorApplicationService(runner=workflow, projection_store=store)
        await service.start()
        launch = ScenarioLaunchRequest(
            schema_version=SCENARIO_LAUNCH_REQUEST_VERSION,
            launch_id="late-trusted-input-failure",
            scenario=ScenarioLaunchName.SANDBOX_ORDER,
            mode=ScenarioRunMode.ADAPTIVE,
        )
        created = await service.launch(launch)
        terminal = await _terminal(service, created.snapshot.investigation_id)
        work = await store.get_work(created.snapshot.investigation_id)
        await service.aclose()

        assert terminal.lifecycle is ScenarioRunLifecycle.FAILED
        assert terminal.failure_category is (
            ScenarioRunFailureCategory.SCENARIO_EXECUTION_FAILED
        )
        assert work.workflow_result is None
        assert (
            work.investigation_state is ScenarioInvestigationState.ESCALATION_REQUIRED
        )
        lane_root = workspace_root / work.workspace_id
        adaptive_path = lane_root / "runtime-adaptive.sqlite3"
        assert adaptive_path.is_file()
        assert not (lane_root / "runtime-fixed.sqlite3").exists()
        lane_store = SqliteDurableRuntimeStore(adaptive_path)
        assert (
            len(
                await lane_store.provider_call_receipts(
                    created.snapshot.investigation_id
                )
            )
            == 1
        )
        assert (
            len(await lane_store.probe_checkpoints(created.snapshot.investigation_id))
            == 1
        )

    asyncio.run(exercise())


@pytest.mark.parametrize("failure_surface", ("call", "attribute"))
def test_durable_provider_cleanup_failure_preserves_established_result(
    tmp_path: Path,
    failure_surface: str,
) -> None:
    async def exercise() -> None:
        os.chmod(tmp_path, 0o700)
        workspace_root = tmp_path / "workspaces"
        workspace_root.mkdir(mode=0o700)
        store = SqliteScenarioStore(tmp_path / "parent.sqlite3")

        class CleanupFailurePlanner(_ScriptedPlanner):
            async def aclose(self) -> None:
                raise RuntimeError("private provider cleanup detail")

        class CleanupAttributeFailurePlanner(_ScriptedPlanner):
            @property
            def aclose(self):
                raise RuntimeError("private provider cleanup descriptor detail")

        planner_type = (
            CleanupFailurePlanner
            if failure_surface == "call"
            else CleanupAttributeFailurePlanner
        )

        workflow = DurableScenarioWorkflow(
            store,
            workspace_root,
            semantic_config_sha256="2" * 64,
            planner_factory=lambda _scenario: planner_type(
                tuple(step.request for step in SANDBOX_ORDER_FIXED_PROBE_PLAN.steps)
            ),
        )
        service = OperatorApplicationService(runner=workflow, projection_store=store)
        await service.start()
        launch = ScenarioLaunchRequest(
            schema_version=SCENARIO_LAUNCH_REQUEST_VERSION,
            launch_id=f"durable-provider-cleanup-failure-{failure_surface}",
            scenario=ScenarioLaunchName.SANDBOX_ORDER,
            mode=ScenarioRunMode.ADAPTIVE,
        )
        created = await service.launch(launch)
        terminal = await _terminal(service, created.snapshot.investigation_id)
        work = await store.get_work(created.snapshot.investigation_id)
        await service.aclose()

        assert terminal.lifecycle is ScenarioRunLifecycle.COMPLETED
        assert terminal.report is not None
        assert terminal.report.route_provenance is not None
        assert terminal.report.route_provenance.outcome is (
            ScenarioHybridOutcome.PLANNER_EVIDENCE
        )
        assert terminal.report.route_provenance.provider_cleanup_failure
        assert work.workflow_result is not None
        assert BOUNDED_HYBRID_PROVIDER_CLEANUP_PROVENANCE in (
            work.workflow_result.limitations
        )
        lane_root = workspace_root / work.workspace_id
        assert (lane_root / "runtime-adaptive.sqlite3").is_file()
        assert not (lane_root / "runtime-fixed.sqlite3").exists()

    asyncio.run(exercise())


@pytest.mark.parametrize(("scenario", "proposals"), _SCENARIO_PROPOSALS)
def test_real_comparison_uses_separate_stable_durable_lanes(
    tmp_path: Path,
    scenario: ScenarioLaunchName,
    proposals,
) -> None:
    async def exercise() -> None:
        os.chmod(tmp_path, 0o700)
        workspace_root = tmp_path / "workspaces"
        workspace_root.mkdir(mode=0o700)
        store = SqliteScenarioStore(tmp_path / "parent.sqlite3")
        planners: list[_ScriptedPlanner] = []

        def planner_factory(_scenario):
            planner = _ScriptedPlanner(proposals)
            planners.append(planner)
            return planner

        workflow = DurableScenarioWorkflow(
            store,
            workspace_root,
            semantic_config_sha256="c" * 64,
            planner_factory=planner_factory,
        )
        service = OperatorApplicationService(
            runner=workflow,
            projection_store=store,
        )
        await service.start()
        launch = ScenarioLaunchRequest(
            schema_version=SCENARIO_LAUNCH_REQUEST_VERSION,
            launch_id=f"durable-compare-{scenario.value}",
            scenario=scenario,
            mode=ScenarioRunMode.COMPARE,
        )
        created = await service.launch(launch)
        terminal = await _terminal(service, created.snapshot.investigation_id)
        journal = await service.snapshot(created.snapshot.investigation_id)
        work = await store.get_work(created.snapshot.investigation_id)
        await service.aclose()

        assert terminal.lifecycle is ScenarioRunLifecycle.COMPLETED
        assert terminal.comparison is not None
        lane_root = workspace_root / work.workspace_id
        assert (lane_root / "runtime-fixed.sqlite3").is_file()
        adaptive_path = lane_root / "runtime-adaptive.sqlite3"
        assert adaptive_path.is_file()
        receipts = await SqliteDurableRuntimeStore(
            adaptive_path
        ).provider_call_receipts(created.snapshot.investigation_id)
        started_turns = sum(
            isinstance(event.payload, AdvisoryTurnEventPayload)
            and event.payload.turn.status is AdvisoryTurnStatus.STARTED
            for event in journal.events
        )
        assert len(planners) == 1
        assert len(receipts) == len(planners[0].inputs) == started_turns

    asyncio.run(exercise())


def test_started_mutation_without_result_escalates_and_is_never_repeated(
    tmp_path: Path,
) -> None:
    async def exercise() -> None:
        os.chmod(tmp_path, 0o700)
        workspace_root = tmp_path / "workspaces"
        workspace_root.mkdir(mode=0o700)
        store = SqliteScenarioStore(tmp_path / "parent.sqlite3")
        workflow = DurableScenarioWorkflow(
            store,
            workspace_root,
            semantic_config_sha256="d" * 64,
        )
        bound = await _bind(workflow, launch_id="mutation-unknown")
        investigation_id = bound.work.scenario_request.investigation_id
        token = await store.acquire_scenario_lease(
            investigation_id,
            "test-owner",
            now=datetime.now(UTC),
        )
        await store.record_mutation_started(
            token,
            prepared_envelope_sha256="1" * 64,
            cleanup_manifest_sha256="2" * 64,
            occurred_at=datetime.now(UTC),
        )
        await store.release_scenario_lease(token, now=datetime.now(UTC))

        service = OperatorApplicationService(
            runner=workflow,
            projection_store=store,
        )
        await service.start()
        terminal = await _terminal(service, investigation_id)
        recovered = await store.get_work(investigation_id)
        status = await service.get_operational_status(investigation_id)
        await service.aclose()

        assert terminal.lifecycle is ScenarioRunLifecycle.FAILED
        assert recovered.mutation_state is ScenarioMutationState.STARTED
        assert recovered.scenario_result is None
        assert (
            recovered.investigation_state
            is ScenarioInvestigationState.ESCALATION_REQUIRED
        )
        assert recovered.recovery_failure_code == "mutation-outcome-unknown"
        assert status.mutation_state is ScenarioOperationalMutationState.STARTED
        assert (
            status.investigation_state
            is ScenarioOperationalInvestigationState.ESCALATION_REQUIRED
        )
        assert (
            status.recovery_state
            is ScenarioOperationalRecoveryState.HUMAN_ESCALATION_REQUIRED
        )
        assert not (
            workspace_root / recovered.workspace_id / "storage.sqlite3"
        ).exists()

    asyncio.run(exercise())


def test_terminal_v1_failure_cannot_hide_started_mutation_unknown(
    tmp_path: Path,
) -> None:
    async def exercise() -> None:
        os.chmod(tmp_path, 0o700)
        workspace_root = tmp_path / "workspaces"
        workspace_root.mkdir(mode=0o700)
        store = SqliteScenarioStore(tmp_path / "parent.sqlite3")
        workflow = DurableScenarioWorkflow(
            store,
            workspace_root,
            semantic_config_sha256="5" * 64,
        )
        bound = await _bind(workflow, launch_id="terminal-hides-unknown")
        investigation_id = bound.work.scenario_request.investigation_id
        token = await store.acquire_scenario_lease(
            investigation_id,
            "test-owner",
            now=datetime.now(UTC),
        )
        await store.record_mutation_started(
            token,
            prepared_envelope_sha256="6" * 64,
            cleanup_manifest_sha256="7" * 64,
            occurred_at=datetime.now(UTC),
        )
        await store.release_scenario_lease(token, now=datetime.now(UTC))

        running_at = datetime.now(UTC)
        running_event = ScenarioRunEvent(
            schema_version=SCENARIO_RUN_EVENT_VERSION,
            investigation_id=investigation_id,
            cursor=2,
            type=ScenarioRunEventType.LIFECYCLE,
            occurred_at=running_at,
            payload=ScenarioLifecycleEventPayload(
                lifecycle=ScenarioRunLifecycle.RUNNING
            ),
        )
        running_snapshot = bound.work.snapshot.model_copy(
            update={
                "lifecycle": ScenarioRunLifecycle.RUNNING,
                "event_cursor": 2,
                "updated_at": running_at,
            }
        )
        await store.append_projection(
            running_snapshot,
            running_event,
            terminal=False,
        )
        occurred_at = datetime.now(UTC)
        terminal_summary = TerminalStateSummary(
            lifecycle=ScenarioRunLifecycle.FAILED,
            result_kind=ScenarioRunResultKind.NONE,
            classification=None,
            action_gate_allowed_count=0,
            action_gate_denied_count=0,
            missing_evidence_count=0,
            escalation_required=None,
            failure_category=ScenarioRunFailureCategory.INTERNAL_FAILURE,
        )
        event = ScenarioRunEvent(
            schema_version=SCENARIO_RUN_EVENT_VERSION,
            investigation_id=investigation_id,
            cursor=3,
            type=ScenarioRunEventType.TERMINAL,
            occurred_at=occurred_at,
            payload=TerminalStateEventPayload(terminal=terminal_summary),
        )
        snapshot = running_snapshot.model_copy(
            update={
                "lifecycle": ScenarioRunLifecycle.FAILED,
                "event_cursor": 3,
                "failure_category": ScenarioRunFailureCategory.INTERNAL_FAILURE,
                "updated_at": occurred_at,
            }
        )
        await store.append_projection(snapshot, event, terminal=True)

        service = OperatorApplicationService(
            runner=workflow,
            projection_store=store,
        )
        await service.start()
        audited = await store.get_work(investigation_id)
        await service.aclose()

        assert audited.mutation_state is ScenarioMutationState.STARTED
        assert audited.scenario_result is None
        assert (
            audited.investigation_state
            is ScenarioInvestigationState.ESCALATION_REQUIRED
        )
        assert audited.recovery_failure_code == "mutation-outcome-unknown"

    asyncio.run(exercise())


def test_startup_rejects_semantically_forged_initial_projection_event(
    tmp_path: Path,
) -> None:
    async def exercise() -> None:
        os.chmod(tmp_path, 0o700)
        workspace_root = tmp_path / "workspaces"
        workspace_root.mkdir(mode=0o700)
        database = tmp_path / "parent.sqlite3"
        store = SqliteScenarioStore(database)
        workflow = DurableScenarioWorkflow(
            store,
            workspace_root,
            semantic_config_sha256="c" * 64,
        )
        bound = await _bind(workflow, launch_id="forged-initial-event")
        investigation_id = bound.work.scenario_request.investigation_id
        projection = await store.snapshot_projection(investigation_id)
        forged = projection.events[0].model_copy(
            update={
                "payload": ScenarioLifecycleEventPayload(
                    lifecycle=ScenarioRunLifecycle.RUNNING
                )
            }
        )
        with sqlite3.connect(database) as connection:
            connection.execute(
                "UPDATE scenario_events SET payload = ? "
                "WHERE investigation_id = ? AND cursor = 1",
                (canonical_json_bytes(forged), investigation_id),
            )

        service = OperatorApplicationService(
            runner=workflow,
            projection_store=store,
        )
        with pytest.raises(CorruptScenarioState):
            await service.start()
        await service.aclose()

    asyncio.run(exercise())


def test_startup_rejects_same_digest_forged_running_envelope_summary(
    tmp_path: Path,
) -> None:
    async def exercise() -> None:
        os.chmod(tmp_path, 0o700)
        workspace_root = tmp_path / "workspaces"
        workspace_root.mkdir(mode=0o700)
        store = SqliteScenarioStore(tmp_path / "parent.sqlite3")
        workflow = DurableScenarioWorkflow(
            store,
            workspace_root,
            semantic_config_sha256="f" * 64,
        )
        bound = await _bind(workflow, launch_id="forged-running-summary")
        await _record_mutation_and_start_investigation(
            store,
            workspace_root,
            bound,
        )
        investigation_id = bound.work.scenario_request.investigation_id
        work = await store.get_work(investigation_id)
        assert work.scenario_result is not None
        assert work.scenario_result.execution_envelope is not None
        running_at = datetime.now(UTC)
        running_event = ScenarioRunEvent(
            schema_version=SCENARIO_RUN_EVENT_VERSION,
            investigation_id=investigation_id,
            cursor=2,
            type=ScenarioRunEventType.LIFECYCLE,
            occurred_at=running_at,
            payload=ScenarioLifecycleEventPayload(
                lifecycle=ScenarioRunLifecycle.RUNNING
            ),
        )
        running_snapshot = work.snapshot.model_copy(
            update={
                "lifecycle": ScenarioRunLifecycle.RUNNING,
                "event_cursor": 2,
                "updated_at": running_at,
            }
        )
        await store.append_projection(
            running_snapshot,
            running_event,
            terminal=False,
        )
        summary_at = datetime.now(UTC)
        expected = _envelope_summary(work.scenario_result.execution_envelope)
        forged = expected.model_copy(update={"target_kind": "forged-target"})
        assert forged.envelope_sha256 == expected.envelope_sha256
        summary_event = ScenarioRunEvent(
            schema_version=SCENARIO_RUN_EVENT_VERSION,
            investigation_id=investigation_id,
            cursor=3,
            type=ScenarioRunEventType.ENVELOPE_SUMMARY,
            occurred_at=summary_at,
            payload=EnvelopeSummaryEventPayload(summary=forged),
        )
        summary_snapshot = running_snapshot.model_copy(
            update={
                "event_cursor": 3,
                "envelope_summary": forged,
                "updated_at": summary_at,
            }
        )
        await store.append_projection(
            summary_snapshot,
            summary_event,
            terminal=False,
        )
        assert not (
            workspace_root / work.workspace_id / "runtime-fixed.sqlite3"
        ).exists()

        service = OperatorApplicationService(
            runner=workflow,
            projection_store=store,
        )
        with pytest.raises(RuntimeError, match="envelope projection"):
            await service.start()
        await service.aclose()

        assert not (
            workspace_root / work.workspace_id / "runtime-fixed.sqlite3"
        ).exists()

    asyncio.run(exercise())


def test_adaptive_restart_balances_precharged_open_advisory_before_escalation(
    tmp_path: Path,
) -> None:
    async def exercise() -> None:
        os.chmod(tmp_path, 0o700)
        workspace_root = tmp_path / "workspaces"
        workspace_root.mkdir(mode=0o700)
        database = tmp_path / "parent.sqlite3"
        provider_entered = asyncio.Event()
        provider_dispatches = 0

        class BlockingPlanner(_ScriptedPlanner):
            async def plan(self, planner_input):
                del planner_input
                nonlocal provider_dispatches
                provider_dispatches += 1
                provider_entered.set()
                await asyncio.Future()

        first_store = SqliteScenarioStore(database)
        first_workflow = DurableScenarioWorkflow(
            first_store,
            workspace_root,
            semantic_config_sha256="9" * 64,
            planner_factory=lambda _scenario: BlockingPlanner(()),
        )
        first = OperatorApplicationService(
            runner=first_workflow,
            projection_store=first_store,
        )
        await first.start()
        launch = ScenarioLaunchRequest(
            schema_version=SCENARIO_LAUNCH_REQUEST_VERSION,
            launch_id="adaptive-precharge-restart",
            scenario=ScenarioLaunchName.SANDBOX_ORDER,
            mode=ScenarioRunMode.ADAPTIVE,
        )
        created = await first.launch(launch)
        investigation_id = created.snapshot.investigation_id
        await asyncio.wait_for(provider_entered.wait(), timeout=20)

        async with asyncio.timeout(20):
            while True:
                first_projection = await first.snapshot(investigation_id)
                started = tuple(
                    event.payload.turn
                    for event in first_projection.events
                    if isinstance(event.payload, AdvisoryTurnEventPayload)
                    and event.payload.turn.status is AdvisoryTurnStatus.STARTED
                )
                if started:
                    break
                await asyncio.sleep(0.02)

        first_work = await first_store.get_work(investigation_id)
        lane_path = (
            workspace_root / first_work.workspace_id / "runtime-adaptive.sqlite3"
        )
        lane_store = SqliteDurableRuntimeStore(lane_path)
        receipts = await lane_store.provider_call_receipts(investigation_id)
        assert len(receipts) == provider_dispatches == 1
        await first.aclose()

        second_store = SqliteScenarioStore(database)
        second_workflow = DurableScenarioWorkflow(
            second_store,
            workspace_root,
            semantic_config_sha256="9" * 64,
            planner_factory=lambda _scenario: BlockingPlanner(()),
        )
        second = OperatorApplicationService(
            runner=second_workflow,
            projection_store=second_store,
        )
        await second.start()
        terminal = await _terminal(second, investigation_id)
        projection = await second_store.snapshot_projection(investigation_id)
        recovered = await second_store.get_work(investigation_id)
        await second.aclose()

        advisory = tuple(
            event.payload.turn
            for event in projection.events
            if isinstance(event.payload, AdvisoryTurnEventPayload)
        )
        assert terminal.lifecycle is ScenarioRunLifecycle.FAILED
        assert projection.terminal
        assert tuple(turn.status for turn in advisory) == (
            AdvisoryTurnStatus.STARTED,
            AdvisoryTurnStatus.FAILED,
        )
        assert advisory[1].turn_sequence == advisory[0].turn_sequence
        assert advisory[1].phase is advisory[0].phase
        assert advisory[1].input_sha256 == advisory[0].input_sha256
        assert advisory[1].failure_category is AdvisoryTurnFailureCategory.UNAVAILABLE
        assert provider_dispatches == 1
        assert (
            recovered.investigation_state
            is ScenarioInvestigationState.ESCALATION_REQUIRED
        )
        assert recovered.recovery_failure_code == ("durable-lane-escalation-required")
        assert recovered.cleanup_status is CleanupStatus.NOT_REQUESTED
        assert recovered.workflow_result is None

    asyncio.run(exercise())


def test_parent_terminal_projection_failure_surfaces_nonterminal_task_exit(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def exercise() -> None:
        os.chmod(tmp_path, 0o700)
        workspace_root = tmp_path / "workspaces"
        workspace_root.mkdir(mode=0o700)
        store = SqliteScenarioStore(tmp_path / "parent.sqlite3")
        workflow = DurableScenarioWorkflow(
            store,
            workspace_root,
            semantic_config_sha256="e" * 64,
        )

        async def fail_owned(*args, **kwargs):
            del args, kwargs
            raise ScenarioWorkflowError(
                ScenarioWorkflowErrorCategory.SCENARIO_EXECUTION_FAILED,
                scenario=ScenarioName.STORAGE,
            )

        monkeypatch.setattr(workflow, "_run_owned", fail_owned)
        append_projection = store.append_projection

        async def fail_terminal_projection(snapshot, event, *, terminal):
            if terminal:
                raise RuntimeError("injected terminal projection failure")
            return await append_projection(snapshot, event, terminal=terminal)

        monkeypatch.setattr(store, "append_projection", fail_terminal_projection)
        service = OperatorApplicationService(
            runner=workflow,
            projection_store=store,
        )
        await service.start()
        created = await service.launch(
            ScenarioLaunchRequest(
                schema_version=SCENARIO_LAUNCH_REQUEST_VERSION,
                launch_id="parent-terminal-append-failure",
                scenario=ScenarioLaunchName.STORAGE,
                mode=ScenarioRunMode.FIXED,
            )
        )
        investigation_id = created.snapshot.investigation_id

        async with asyncio.timeout(5):
            while (await store.snapshot_projection(investigation_id)).cursor < 2:
                await asyncio.sleep(0.02)
        with pytest.raises(OperatorServiceUnavailable):
            async with asyncio.timeout(5):
                await service.wait_for_events(investigation_id, after=2)
        with pytest.raises(OperatorServiceUnavailable):
            await service.get(investigation_id)
        projection = await store.snapshot_projection(investigation_id)
        work = await store.get_work(investigation_id)
        await service.aclose()

        assert projection.cursor == 2
        assert not projection.terminal
        assert projection.snapshot.lifecycle is ScenarioRunLifecycle.RUNNING
        assert work.workflow_result is None
        assert work.cleanup_status is CleanupStatus.NOT_REQUESTED

    asyncio.run(exercise())


def test_spontaneously_cancelled_parent_surfaces_nonterminal_task_exit(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def exercise() -> None:
        os.chmod(tmp_path, 0o700)
        workspace_root = tmp_path / "workspaces"
        workspace_root.mkdir(mode=0o700)
        store = SqliteScenarioStore(tmp_path / "parent.sqlite3")
        workflow = DurableScenarioWorkflow(
            store,
            workspace_root,
            semantic_config_sha256="f" * 64,
        )

        async def cancel_owned(*args, **kwargs):
            del args, kwargs
            raise asyncio.CancelledError

        monkeypatch.setattr(workflow, "_run_owned", cancel_owned)
        service = OperatorApplicationService(
            runner=workflow,
            projection_store=store,
        )
        await service.start()
        created = await service.launch(
            ScenarioLaunchRequest(
                schema_version=SCENARIO_LAUNCH_REQUEST_VERSION,
                launch_id="spontaneous-parent-cancel",
                scenario=ScenarioLaunchName.STORAGE,
                mode=ScenarioRunMode.FIXED,
            )
        )
        investigation_id = created.snapshot.investigation_id

        async with asyncio.timeout(5):
            while (await store.snapshot_projection(investigation_id)).cursor < 2:
                await asyncio.sleep(0.02)
        with pytest.raises(OperatorServiceUnavailable):
            async with asyncio.timeout(5):
                await service.wait_for_events(investigation_id, after=2)
        projection = await store.snapshot_projection(investigation_id)
        work = await store.get_work(investigation_id)
        await service.aclose()

        assert projection.cursor == 2
        assert not projection.terminal
        assert projection.snapshot.lifecycle is ScenarioRunLifecycle.RUNNING
        assert work.workflow_result is None
        assert work.cleanup_status is CleanupStatus.NOT_REQUESTED

    asyncio.run(exercise())


def test_operator_restart_continues_public_probe_request_sequence(
    tmp_path: Path,
) -> None:
    class ProgressOnlyRunner:
        def __init__(self, coordinator, investigation_id: str, emitted: asyncio.Event):
            self._coordinator = coordinator
            self._investigation_id = investigation_id
            self._emitted = emitted

        @property
        def provider_available(self) -> bool:
            return False

        async def bind_launch(self, launch, *, snapshot, accepted_event):
            return await self._coordinator.bind_launch(
                launch,
                snapshot=snapshot,
                accepted_event=accepted_event,
            )

        async def audit_terminal_projection(self, investigation_id):
            await self._coordinator.audit_terminal_projection(investigation_id)

        async def __call__(
            self,
            scenario,
            mode,
            *,
            vertex_config,
            run_id,
            progress_callback,
            cancellation_event,
        ):
            del scenario, mode, vertex_config, run_id, cancellation_event
            assert progress_callback is not None
            await progress_callback(
                ProbeProgress(
                    occurred_at=datetime.now(UTC),
                    investigation_id=self._investigation_id,
                    strategy=ComparisonStrategyKind.FIXED,
                    stage=ProbeProgressStage.REQUESTED,
                    attempt_sequence=1,
                    capability_name="restart-read",
                    capability_version="1.0.0",
                    request_sha256="a" * 64,
                    relevant_effect_ids=("restart-effect",),
                )
            )
            self._emitted.set()
            await asyncio.Future()

    async def exercise() -> None:
        os.chmod(tmp_path, 0o700)
        workspace_root = tmp_path / "workspaces"
        workspace_root.mkdir(mode=0o700)
        database = tmp_path / "parent.sqlite3"
        store = SqliteScenarioStore(database)
        coordinator = DurableScenarioWorkflow(
            store,
            workspace_root,
            semantic_config_sha256="1" * 64,
        )
        launch = ScenarioLaunchRequest(
            schema_version=SCENARIO_LAUNCH_REQUEST_VERSION,
            launch_id="request-sequence-restart",
            scenario=ScenarioLaunchName.STORAGE,
            mode=ScenarioRunMode.FIXED,
        )
        from reconcile.scenarios.service import scenario_investigation_id

        investigation_id = scenario_investigation_id(
            ScenarioName.STORAGE,
            launch.launch_id,
        )
        first_emitted = asyncio.Event()
        first = OperatorApplicationService(
            runner=ProgressOnlyRunner(
                coordinator,
                investigation_id,
                first_emitted,
            ),
            projection_store=store,
        )
        await first.start()
        await first.launch(launch)
        await asyncio.wait_for(first_emitted.wait(), timeout=5)
        await first.aclose()

        second_emitted = asyncio.Event()
        second = OperatorApplicationService(
            runner=ProgressOnlyRunner(
                coordinator,
                investigation_id,
                second_emitted,
            ),
            projection_store=store,
        )
        await second.start()
        await asyncio.wait_for(second_emitted.wait(), timeout=5)
        projection = await store.snapshot_projection(investigation_id)
        request_events = tuple(
            event
            for event in projection.events
            if isinstance(event.payload, ProbeRequestEventPayload)
        )
        await second.aclose()

        sequences = tuple(
            event.payload.request.request_sequence for event in request_events
        )
        assert sequences == (1, 2)

        duplicate = request_events[-1].model_copy(
            update={
                "payload": request_events[-1].payload.model_copy(
                    update={
                        "request": request_events[-1].payload.request.model_copy(
                            update={"request_sequence": 1}
                        )
                    }
                )
            }
        )
        with sqlite3.connect(database) as connection:
            connection.execute(
                "UPDATE scenario_events SET payload = ? "
                "WHERE investigation_id = ? AND cursor = ?",
                (
                    canonical_json_bytes(duplicate),
                    investigation_id,
                    duplicate.cursor,
                ),
            )
        with pytest.raises(CorruptScenarioState):
            await store.snapshot_projection(investigation_id)

    asyncio.run(exercise())


def test_projection_rejects_noncontiguous_advisory_turn_sequence(
    tmp_path: Path,
) -> None:
    async def exercise() -> None:
        os.chmod(tmp_path, 0o700)
        workspace_root = tmp_path / "workspaces"
        workspace_root.mkdir(mode=0o700)
        store = SqliteScenarioStore(tmp_path / "parent.sqlite3")
        workflow = DurableScenarioWorkflow(
            store,
            workspace_root,
            semantic_config_sha256="2" * 64,
            planner_factory=lambda _scenario: _ScriptedPlanner(()),
        )
        bound = await _bind(
            workflow,
            launch_id="noncontiguous-advisory",
            mode=ScenarioRunMode.ADAPTIVE,
        )
        investigation_id = bound.work.scenario_request.investigation_id
        running_at = datetime.now(UTC)
        running_event = ScenarioRunEvent(
            schema_version=SCENARIO_RUN_EVENT_VERSION,
            investigation_id=investigation_id,
            cursor=2,
            type=ScenarioRunEventType.LIFECYCLE,
            occurred_at=running_at,
            payload=ScenarioLifecycleEventPayload(
                lifecycle=ScenarioRunLifecycle.RUNNING
            ),
        )
        running_snapshot = bound.work.snapshot.model_copy(
            update={
                "lifecycle": ScenarioRunLifecycle.RUNNING,
                "event_cursor": 2,
                "updated_at": running_at,
            }
        )
        await store.append_projection(
            running_snapshot,
            running_event,
            terminal=False,
        )
        advisory_at = datetime.now(UTC)
        advisory_event = ScenarioRunEvent(
            schema_version=SCENARIO_RUN_EVENT_VERSION,
            investigation_id=investigation_id,
            cursor=3,
            type=ScenarioRunEventType.ADVISORY_TURN,
            occurred_at=advisory_at,
            payload=AdvisoryTurnEventPayload(
                turn=AdvisoryTurnSummary(
                    turn_sequence=2,
                    phase=AdaptivePlannerPhase.ACQUIRE_EVIDENCE,
                    status=AdvisoryTurnStatus.STARTED,
                    input_sha256="b" * 64,
                    output_sha256=None,
                    proposal_count=0,
                    selected_proposal_count=0,
                    failure_category=None,
                )
            ),
        )
        advisory_snapshot = running_snapshot.model_copy(
            update={
                "event_cursor": 3,
                "updated_at": advisory_at,
            }
        )
        await store.append_projection(
            advisory_snapshot,
            advisory_event,
            terminal=False,
        )

        with pytest.raises(CorruptScenarioState):
            await store.snapshot_projection(investigation_id)

    asyncio.run(exercise())


def test_startup_rejects_terminal_summary_that_contradicts_snapshot(
    tmp_path: Path,
) -> None:
    async def exercise() -> None:
        os.chmod(tmp_path, 0o700)
        workspace_root = tmp_path / "workspaces"
        workspace_root.mkdir(mode=0o700)
        database = tmp_path / "parent.sqlite3"
        store = SqliteScenarioStore(database)
        workflow = DurableScenarioWorkflow(
            store,
            workspace_root,
            semantic_config_sha256="d" * 64,
        )
        bound = await _bind(workflow, launch_id="forged-terminal-summary")
        investigation_id = bound.work.scenario_request.investigation_id
        await workflow(
            ScenarioName.STORAGE,
            ScenarioMode.FIXED,
            vertex_config=None,
            run_id="forged-terminal-summary",
            progress_callback=None,
            cancellation_event=None,
        )
        recorded = await store.get_work(investigation_id)
        await _append_completed_report_projection(store, recorded)
        projection = await store.snapshot_projection(investigation_id)
        terminal_event = projection.events[-1]
        assert isinstance(terminal_event.payload, TerminalStateEventPayload)
        summary = terminal_event.payload.terminal
        forged_summary = summary.model_copy(
            update={"missing_evidence_count": (summary.missing_evidence_count + 1) % 65}
        )
        forged_event = terminal_event.model_copy(
            update={"payload": TerminalStateEventPayload(terminal=forged_summary)}
        )
        with sqlite3.connect(database) as connection:
            connection.execute(
                "UPDATE scenario_events SET payload = ? "
                "WHERE investigation_id = ? AND cursor = ?",
                (
                    canonical_json_bytes(forged_event),
                    investigation_id,
                    forged_event.cursor,
                ),
            )

        service = OperatorApplicationService(
            runner=workflow,
            projection_store=store,
        )
        with pytest.raises(CorruptScenarioState):
            await service.start()
        await service.aclose()

    asyncio.run(exercise())


def test_startup_rejects_coherent_terminal_projection_that_forges_private_result(
    tmp_path: Path,
) -> None:
    async def exercise() -> None:
        os.chmod(tmp_path, 0o700)
        workspace_root = tmp_path / "workspaces"
        workspace_root.mkdir(mode=0o700)
        database = tmp_path / "parent.sqlite3"
        store = SqliteScenarioStore(database)
        workflow = DurableScenarioWorkflow(
            store,
            workspace_root,
            semantic_config_sha256="e" * 64,
        )
        bound = await _bind(workflow, launch_id="forged-private-result")
        investigation_id = bound.work.scenario_request.investigation_id
        await workflow(
            ScenarioName.STORAGE,
            ScenarioMode.FIXED,
            vertex_config=None,
            run_id="forged-private-result",
            progress_callback=None,
            cancellation_event=None,
        )
        recorded = await store.get_work(investigation_id)
        await _append_completed_report_projection(store, recorded)
        terminal = await store.get_work(investigation_id)
        report = terminal.snapshot.report
        assert report is not None
        assert report.probe_audit
        forged_audit = report.probe_audit[0].model_copy(
            update={"stop_reason": "forged-stop"}
        )
        forged_report = report.model_copy(
            update={"probe_audit": (forged_audit, *report.probe_audit[1:])}
        )
        forged_snapshot = terminal.snapshot.model_copy(update={"report": forged_report})
        forged_work = terminal.model_copy(update={"snapshot": forged_snapshot})
        with sqlite3.connect(database) as connection:
            connection.execute(
                "UPDATE scenario_work_items SET payload = ? WHERE investigation_id = ?",
                (canonical_json_bytes(forged_work), investigation_id),
            )
        coherent = await store.snapshot_projection(investigation_id)
        assert coherent.terminal

        service = OperatorApplicationService(
            runner=workflow,
            projection_store=store,
        )
        with pytest.raises(RuntimeError, match="private result"):
            await service.start()
        await service.aclose()

    asyncio.run(exercise())


def test_startup_repairs_terminal_projection_from_authoritative_result(
    tmp_path: Path,
) -> None:
    async def exercise() -> None:
        os.chmod(tmp_path, 0o700)
        workspace_root = tmp_path / "workspaces"
        workspace_root.mkdir(mode=0o700)
        store = SqliteScenarioStore(tmp_path / "parent.sqlite3")
        workflow = DurableScenarioWorkflow(
            store,
            workspace_root,
            semantic_config_sha256="e" * 64,
        )
        bound = await _bind(workflow, launch_id="repair-projection")
        investigation_id = bound.work.scenario_request.investigation_id
        result = await workflow(
            ScenarioName.STORAGE,
            ScenarioMode.FIXED,
            vertex_config=None,
            run_id="repair-projection",
            progress_callback=None,
            cancellation_event=None,
        )
        before = await store.get_work(investigation_id)
        assert before.workflow_result == result
        assert before.snapshot.lifecycle is ScenarioRunLifecycle.ACCEPTED

        service = OperatorApplicationService(
            runner=workflow,
            projection_store=store,
        )
        await service.start()
        terminal = await _terminal(service, investigation_id)
        journal = await service.snapshot(investigation_id)
        await service.aclose()

        assert terminal.lifecycle is ScenarioRunLifecycle.COMPLETED
        assert terminal.report is not None
        assert journal.terminal
        assert journal.events[-1].type is ScenarioRunEventType.TERMINAL

    asyncio.run(exercise())


def test_pending_cleanup_recovers_as_unknown_without_redispatch(tmp_path: Path) -> None:
    class InjectAfterPendingStore(SqliteScenarioStore):
        injected = False

        async def record_scenario_cleanup(self, token, status, **kwargs):
            work = await super().record_scenario_cleanup(token, status, **kwargs)
            if status is CleanupStatus.PENDING and not self.injected:
                self.injected = True
                raise RuntimeError("simulated process loss after PENDING")
            return work

    async def exercise() -> None:
        os.chmod(tmp_path, 0o700)
        workspace_root = tmp_path / "workspaces"
        workspace_root.mkdir(mode=0o700)
        database = tmp_path / "parent.sqlite3"
        crashing_store = InjectAfterPendingStore(database)
        crashing_workflow = DurableScenarioWorkflow(
            crashing_store,
            workspace_root,
            semantic_config_sha256="f" * 64,
        )
        bound = await _bind(crashing_workflow, launch_id="cleanup-unknown")
        investigation_id = bound.work.scenario_request.investigation_id
        with pytest.raises(RuntimeError, match="simulated process loss"):
            await crashing_workflow(
                ScenarioName.STORAGE,
                ScenarioMode.FIXED,
                vertex_config=None,
                run_id="cleanup-unknown",
                progress_callback=None,
                cancellation_event=None,
            )
        pending = await crashing_store.get_work(investigation_id)
        assert pending.cleanup_status is CleanupStatus.PENDING
        assert pending.workflow_result is not None

        store = SqliteScenarioStore(database)
        workflow = DurableScenarioWorkflow(
            store,
            workspace_root,
            semantic_config_sha256="f" * 64,
        )
        service = OperatorApplicationService(
            runner=workflow,
            projection_store=store,
        )
        await service.start()
        terminal = await _terminal(service, investigation_id)
        recovered = await store.get_work(investigation_id)
        status = await service.get_operational_status(investigation_id)
        await service.aclose()

        assert terminal.lifecycle is ScenarioRunLifecycle.COMPLETED
        assert recovered.cleanup_status is CleanupStatus.FAILED
        assert recovered.cleanup_failure_code == "cleanup-outcome-unknown"
        assert recovered.workflow_result == pending.workflow_result
        assert status.cleanup_state is ScenarioOperationalCleanupState.FAILED
        assert status.recovery_state is ScenarioOperationalRecoveryState.NOT_ESCALATED

    asyncio.run(exercise())


def test_terminal_projection_runs_one_not_requested_cleanup_attempt(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class StopBeforePendingStore(SqliteScenarioStore):
        stopped = False

        async def record_scenario_cleanup(self, token, status, **kwargs):
            if status is CleanupStatus.PENDING and not self.stopped:
                self.stopped = True
                raise RuntimeError("simulated process loss before PENDING")
            return await super().record_scenario_cleanup(token, status, **kwargs)

    async def exercise() -> None:
        os.chmod(tmp_path, 0o700)
        workspace_root = tmp_path / "workspaces"
        workspace_root.mkdir(mode=0o700)
        database = tmp_path / "parent.sqlite3"
        crashing_store = StopBeforePendingStore(database)
        crashing_workflow = DurableScenarioWorkflow(
            crashing_store,
            workspace_root,
            semantic_config_sha256="0" * 64,
        )
        bound = await _bind(crashing_workflow, launch_id="cleanup-not-requested")
        investigation_id = bound.work.scenario_request.investigation_id
        with pytest.raises(RuntimeError, match="process loss before PENDING"):
            await crashing_workflow(
                ScenarioName.STORAGE,
                ScenarioMode.FIXED,
                vertex_config=None,
                run_id="cleanup-not-requested",
                progress_callback=None,
                cancellation_event=None,
            )
        recorded = await crashing_store.get_work(investigation_id)
        assert recorded.investigation_state is ScenarioInvestigationState.RECORDED
        assert recorded.cleanup_status is CleanupStatus.NOT_REQUESTED
        await _append_completed_report_projection(crashing_store, recorded)

        cleanup_calls = 0
        original_cleanup = ScenarioRunner.cleanup

        def counted_cleanup(self, request, definition):
            nonlocal cleanup_calls
            cleanup_calls += 1
            return original_cleanup(self, request, definition)

        monkeypatch.setattr(ScenarioRunner, "cleanup", counted_cleanup)
        store = SqliteScenarioStore(database)
        workflow = DurableScenarioWorkflow(
            store,
            workspace_root,
            semantic_config_sha256="0" * 64,
        )
        service = OperatorApplicationService(
            runner=workflow,
            projection_store=store,
        )
        await service.start()
        recovered = await store.get_work(investigation_id)
        await service.aclose()

        assert cleanup_calls == 1
        assert recovered.cleanup_status is CleanupStatus.SUCCEEDED
        assert recovered.cleanup_failure_code is None

    asyncio.run(exercise())


@pytest.mark.parametrize(
    "drift",
    ("dependency", "missing", "mode", "owner", "identity"),
)
def test_terminal_projection_drift_fails_closed_without_cleanup(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    drift: str,
) -> None:
    class StopBeforePendingStore(SqliteScenarioStore):
        stopped = False

        async def record_scenario_cleanup(self, token, status, **kwargs):
            if status is CleanupStatus.PENDING and not self.stopped:
                self.stopped = True
                raise RuntimeError("simulated process loss before PENDING")
            return await super().record_scenario_cleanup(token, status, **kwargs)

    async def exercise() -> None:
        os.chmod(tmp_path, 0o700)
        workspace_root = tmp_path / "workspaces"
        workspace_root.mkdir(mode=0o700)
        database = tmp_path / "parent.sqlite3"
        crashing_store = StopBeforePendingStore(database)
        crashing_workflow = DurableScenarioWorkflow(
            crashing_store,
            workspace_root,
            semantic_config_sha256="1" * 64,
        )
        bound = await _bind(
            crashing_workflow,
            launch_id=f"terminal-{drift}-drift",
        )
        investigation_id = bound.work.scenario_request.investigation_id
        with pytest.raises(RuntimeError, match="process loss before PENDING"):
            await crashing_workflow(
                ScenarioName.STORAGE,
                ScenarioMode.FIXED,
                vertex_config=None,
                run_id=f"terminal-{drift}-drift",
                progress_callback=None,
                cancellation_event=None,
            )
        recorded = await crashing_store.get_work(investigation_id)
        await _append_completed_report_projection(crashing_store, recorded)
        recorded = await crashing_store.get_work(investigation_id)
        workspace = workspace_root / recorded.workspace_id
        if drift == "missing":
            workspace.rename(workspace.with_name(f"{workspace.name}.moved"))
        elif drift == "mode":
            os.chmod(workspace, 0o750)
        elif drift == "owner":
            original_stat = Path.stat
            workspace_metadata = original_stat(workspace)

            def drifted_stat(path, *args, **kwargs):
                metadata = original_stat(path, *args, **kwargs)
                if path == workspace:
                    values = list(workspace_metadata)
                    values[4] = os.geteuid() + 1
                    return os.stat_result(values)
                return metadata

            monkeypatch.setattr(Path, "stat", drifted_stat)
        elif drift == "identity":
            wrong_id = f"scenario-workspace-{'f' * 32}"
            (workspace_root / wrong_id).mkdir(mode=0o700)
            corrupted = recorded.model_copy(update={"workspace_id": wrong_id})
            with sqlite3.connect(database) as connection:
                connection.execute(
                    "UPDATE scenario_work_items SET payload = ? "
                    "WHERE investigation_id = ?",
                    (canonical_json_bytes(corrupted), investigation_id),
                )

        cleanup_calls = 0
        mutation_dispatches = 0

        def forbidden_cleanup(self, request, definition):
            nonlocal cleanup_calls
            cleanup_calls += 1
            raise AssertionError("cleanup must not run after authority drift")

        def forbidden_mutation(self, request, definition, prepared):
            nonlocal mutation_dispatches
            mutation_dispatches += 1
            raise AssertionError("mutation must not run after authority drift")

        monkeypatch.setattr(ScenarioRunner, "cleanup", forbidden_cleanup)
        monkeypatch.setattr(ScenarioRunner, "run_prepared", forbidden_mutation)
        store = SqliteScenarioStore(database)
        workflow = DurableScenarioWorkflow(
            store,
            workspace_root,
            semantic_config_sha256=("2" * 64 if drift == "dependency" else "1" * 64),
        )
        service = OperatorApplicationService(
            runner=workflow,
            projection_store=store,
        )
        with pytest.raises(ScenarioWorkflowError):
            await service.start()
        recovered = await store.get_work(investigation_id)
        await service.aclose()

        assert cleanup_calls == 0
        assert mutation_dispatches == 0
        assert recovered.cleanup_status is CleanupStatus.NOT_REQUESTED

    asyncio.run(exercise())


def test_bind_launch_rejects_workspace_symlink_without_following_it(
    tmp_path: Path,
) -> None:
    async def exercise() -> None:
        os.chmod(tmp_path, 0o700)
        workspace_root = tmp_path / "workspaces"
        workspace_root.mkdir(mode=0o700)
        store = SqliteScenarioStore(tmp_path / "parent.sqlite3")
        workflow = DurableScenarioWorkflow(
            store,
            workspace_root,
            semantic_config_sha256="a" * 64,
        )
        launch_id = "workspace-symlink"
        from reconcile.scenarios.service import scenario_investigation_id

        investigation_id = scenario_investigation_id(
            ScenarioName.STORAGE,
            launch_id,
        )
        workspace_id = (
            "scenario-workspace-"
            f"{hashlib.sha256(investigation_id.encode()).hexdigest()[:32]}"
        )
        target = workspace_root / "symlink-target"
        target.mkdir(mode=0o755)
        target_mode = target.stat().st_mode & 0o777
        (workspace_root / workspace_id).symlink_to(target, target_is_directory=True)

        with pytest.raises(ValueError, match="not canonical"):
            await _bind(workflow, launch_id=launch_id)

        assert target.stat().st_mode & 0o777 == target_mode
        assert await store.list_work() == ()

    asyncio.run(exercise())


def test_recorded_mutation_envelope_must_derive_from_prepared_authority(
    tmp_path: Path,
) -> None:
    async def exercise() -> None:
        os.chmod(tmp_path, 0o700)
        workspace_root = tmp_path / "workspaces"
        workspace_root.mkdir(mode=0o700)
        store = SqliteScenarioStore(tmp_path / "parent.sqlite3")
        workflow = DurableScenarioWorkflow(
            store,
            workspace_root,
            semantic_config_sha256="b" * 64,
        )
        bound = await _bind(workflow, launch_id="envelope-lineage")
        work = bound.work
        workspace = workspace_root / work.workspace_id
        definition = _definition(
            ScenarioName.STORAGE,
            workspace,
            invoked_at=work.invoked_at,
            seed_sandbox=False,
        )
        runner = ScenarioRunner()
        prepared = runner.prepare(work.scenario_request, definition)
        token = await store.acquire_scenario_lease(
            work.scenario_request.investigation_id,
            "lineage-owner",
            now=datetime.now(UTC),
        )
        await store.record_mutation_started(
            token,
            prepared_envelope_sha256=hashlib.sha256(
                prepared.execution_envelope_bytes
            ).hexdigest(),
            cleanup_manifest_sha256=prepared.cleanup_manifest_sha256,
            occurred_at=datetime.now(UTC),
        )
        result = await asyncio.to_thread(
            runner.run_prepared,
            work.scenario_request,
            definition,
            prepared,
        )
        assert result.execution_envelope is not None
        envelope = result.execution_envelope
        first_effect = envelope.expected_effects[0].model_copy(
            update={"description": "tampered immutable effect authority"}
        )
        tampered_envelope = envelope.model_copy(
            update={"expected_effects": (first_effect, *envelope.expected_effects[1:])}
        )
        tampered_result = result.model_copy(
            update={"execution_envelope": tampered_envelope}
        )

        with pytest.raises(ScenarioStateConflict) as raised:
            await store.record_mutation_result(
                token,
                tampered_result,
                prepared_envelope_bytes=prepared.execution_envelope_bytes,
                occurred_at=datetime.now(UTC),
            )
        assert raised.value.operation == "record mutation envelope lineage"

        recorded = await store.record_mutation_result(
            token,
            result,
            prepared_envelope_bytes=prepared.execution_envelope_bytes,
            occurred_at=datetime.now(UTC),
        )
        assert recorded.mutation_state is ScenarioMutationState.RECORDED

    asyncio.run(exercise())


@pytest.mark.parametrize(
    "scenario",
    (
        ScenarioLaunchName.STORAGE,
        ScenarioLaunchName.FIRESTORE_BUSINESS,
        ScenarioLaunchName.SANDBOX_ORDER,
    ),
)
def test_fixed_recovery_may_start_missing_safe_read_lane(
    tmp_path: Path,
    scenario: ScenarioLaunchName,
) -> None:
    async def exercise() -> None:
        os.chmod(tmp_path, 0o700)
        workspace_root = tmp_path / "workspaces"
        workspace_root.mkdir(mode=0o700)
        store = SqliteScenarioStore(tmp_path / "parent.sqlite3")
        workflow = DurableScenarioWorkflow(
            store,
            workspace_root,
            semantic_config_sha256="3" * 64,
        )
        bound = await _bind(
            workflow,
            launch_id=f"fixed-boundary-{scenario.value}",
            scenario=scenario,
        )
        await _record_mutation_and_start_investigation(
            store,
            workspace_root,
            bound,
        )
        investigation_id = bound.work.scenario_request.investigation_id
        lane_path = workspace_root / bound.work.workspace_id / "runtime-fixed.sqlite3"
        assert not lane_path.exists()

        service = OperatorApplicationService(
            runner=workflow,
            projection_store=store,
        )
        await service.start()
        terminal = await _terminal(service, investigation_id)
        recovered = await store.get_work(investigation_id)
        await service.aclose()

        assert terminal.lifecycle is ScenarioRunLifecycle.COMPLETED
        assert recovered.investigation_state is ScenarioInvestigationState.RECORDED
        assert lane_path.is_file()

    asyncio.run(exercise())


def test_providerless_sandbox_recovery_without_route_lane_fails_closed(
    tmp_path: Path,
) -> None:
    async def exercise() -> None:
        os.chmod(tmp_path, 0o700)
        workspace_root = tmp_path / "workspaces"
        workspace_root.mkdir(mode=0o700)
        store = SqliteScenarioStore(tmp_path / "parent.sqlite3")
        workflow = DurableScenarioWorkflow(
            store,
            workspace_root,
            semantic_config_sha256="3" * 64,
        )
        bound = await _bind(
            workflow,
            launch_id="providerless-recovery-without-route-lane",
            scenario=ScenarioLaunchName.SANDBOX_ORDER,
            mode=ScenarioRunMode.ADAPTIVE,
        )
        await _record_mutation_and_start_investigation(
            store,
            workspace_root,
            bound,
        )
        investigation_id = bound.work.scenario_request.investigation_id
        before = await store.get_work(investigation_id)
        assert before.scenario_result is not None
        scenario_result_bytes = canonical_json_bytes(before.scenario_result)

        service = OperatorApplicationService(runner=workflow, projection_store=store)
        await service.start()
        terminal = await _terminal(service, investigation_id)
        recovered = await store.get_work(investigation_id)
        await service.aclose()

        assert terminal.lifecycle is ScenarioRunLifecycle.FAILED
        assert terminal.failure_category is (
            ScenarioRunFailureCategory.SCENARIO_EXECUTION_FAILED
        )
        assert recovered.scenario_result is not None
        assert canonical_json_bytes(recovered.scenario_result) == scenario_result_bytes
        assert recovered.workflow_result is None
        assert (
            recovered.investigation_state
            is ScenarioInvestigationState.ESCALATION_REQUIRED
        )
        assert recovered.recovery_failure_code == "durable-lane-escalation-required"
        lane_root = workspace_root / recovered.workspace_id
        assert not (lane_root / "runtime-fixed.sqlite3").exists()
        assert not (lane_root / "runtime-adaptive.sqlite3").exists()

    asyncio.run(exercise())


def test_construction_fallback_recovery_resumes_existing_fixed_lane(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def exercise() -> None:
        os.chmod(tmp_path, 0o700)
        workspace_root = tmp_path / "workspaces"
        workspace_root.mkdir(mode=0o700)
        store = SqliteScenarioStore(tmp_path / "parent.sqlite3")

        def unavailable_factory(_scenario):
            raise RuntimeError("private provider construction detail")

        first_workflow = DurableScenarioWorkflow(
            store,
            workspace_root,
            semantic_config_sha256="3" * 64,
            planner_factory=unavailable_factory,
        )
        bound = await _bind(
            first_workflow,
            launch_id="construction-fixed-fallback-recovery",
            scenario=ScenarioLaunchName.SANDBOX_ORDER,
            mode=ScenarioRunMode.ADAPTIVE,
        )
        original_record = store.record_workflow_result

        async def interrupt_parent_record(*args, **kwargs):
            del args, kwargs
            raise RuntimeError("injected parent record interruption")

        monkeypatch.setattr(store, "record_workflow_result", interrupt_parent_record)
        with pytest.raises(RuntimeError, match="parent record interruption"):
            await first_workflow(
                ScenarioName.SANDBOX_ORDER,
                ScenarioMode.ADAPTIVE,
                vertex_config=None,
                run_id="construction-fixed-fallback-recovery",
                progress_callback=None,
                cancellation_event=None,
            )
        monkeypatch.setattr(store, "record_workflow_result", original_record)

        interrupted = await store.get_work(bound.work.scenario_request.investigation_id)
        lane_root = workspace_root / interrupted.workspace_id
        assert interrupted.workflow_result is None
        assert (lane_root / "runtime-fixed.sqlite3").is_file()
        assert not (lane_root / "runtime-adaptive.sqlite3").exists()

        planner_constructions = 0

        def unexpected_factory(_scenario):
            nonlocal planner_constructions
            planner_constructions += 1
            raise AssertionError("fixed fallback recovery cannot construct a planner")

        second_workflow = DurableScenarioWorkflow(
            store,
            workspace_root,
            semantic_config_sha256="3" * 64,
            planner_factory=unexpected_factory,
        )
        report = await second_workflow(
            ScenarioName.SANDBOX_ORDER,
            ScenarioMode.ADAPTIVE,
            vertex_config=None,
            run_id="construction-fixed-fallback-recovery",
            progress_callback=None,
            cancellation_event=None,
        )
        recovered = await store.get_work(bound.work.scenario_request.investigation_id)

        assert type(report) is InvestigationReport
        provenance = bounded_hybrid_route_provenance(report)
        assert provenance is not None
        assert provenance.outcome is ScenarioHybridOutcome.FIXED_FALLBACK
        assert not provenance.planner_invoked
        assert planner_constructions == 0
        assert recovered.workflow_result == report
        assert recovered.cleanup_status is CleanupStatus.SUCCEEDED

    asyncio.run(exercise())


def test_missing_adaptive_ledger_cannot_be_relabelled_as_predispatch_fallback(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def exercise() -> None:
        os.chmod(tmp_path, 0o700)
        workspace_root = tmp_path / "workspaces"
        workspace_root.mkdir(mode=0o700)
        store = SqliteScenarioStore(tmp_path / "parent.sqlite3")

        class UnavailablePlanner(_ScriptedPlanner):
            async def plan(self, planner_input):
                del planner_input
                raise RuntimeError("private provider dispatch detail")

        def planner_factory(_scenario):
            return UnavailablePlanner(())

        first_workflow = DurableScenarioWorkflow(
            store,
            workspace_root,
            semantic_config_sha256="4" * 64,
            planner_factory=planner_factory,
        )
        bound = await _bind(
            first_workflow,
            launch_id="missing-adaptive-ledger",
            scenario=ScenarioLaunchName.SANDBOX_ORDER,
            mode=ScenarioRunMode.ADAPTIVE,
        )
        original_record = store.record_workflow_result

        async def interrupt_parent_record(*args, **kwargs):
            del args, kwargs
            raise RuntimeError("injected parent record interruption")

        monkeypatch.setattr(store, "record_workflow_result", interrupt_parent_record)
        with pytest.raises(RuntimeError, match="parent record interruption"):
            await first_workflow(
                ScenarioName.SANDBOX_ORDER,
                ScenarioMode.ADAPTIVE,
                vertex_config=None,
                run_id="missing-adaptive-ledger",
                progress_callback=None,
                cancellation_event=None,
            )
        monkeypatch.setattr(store, "record_workflow_result", original_record)

        interrupted = await store.get_work(bound.work.scenario_request.investigation_id)
        lane_root = workspace_root / interrupted.workspace_id
        fixed_path = lane_root / "runtime-fixed.sqlite3"
        adaptive_path = lane_root / "runtime-adaptive.sqlite3"
        assert fixed_path.is_file()
        assert adaptive_path.is_file()
        adaptive_path.unlink()

        second_workflow = DurableScenarioWorkflow(
            store,
            workspace_root,
            semantic_config_sha256="4" * 64,
            planner_factory=planner_factory,
        )
        with pytest.raises(ScenarioWorkflowError) as captured:
            await second_workflow(
                ScenarioName.SANDBOX_ORDER,
                ScenarioMode.ADAPTIVE,
                vertex_config=None,
                run_id="missing-adaptive-ledger",
                progress_callback=None,
                cancellation_event=None,
            )
        recovered = await store.get_work(bound.work.scenario_request.investigation_id)

        assert captured.value.category is (
            ScenarioWorkflowErrorCategory.SCENARIO_EXECUTION_FAILED
        )
        assert recovered.workflow_result is None
        assert (
            recovered.investigation_state
            is ScenarioInvestigationState.ESCALATION_REQUIRED
        )
        assert recovered.recovery_failure_code == "durable-lane-escalation-required"

    asyncio.run(exercise())


def test_hybrid_durable_lanes_share_one_elapsed_budget_origin(tmp_path: Path) -> None:
    async def exercise() -> None:
        os.chmod(tmp_path, 0o700)
        workspace_root = tmp_path / "workspaces"
        workspace_root.mkdir(mode=0o700)
        store = SqliteScenarioStore(tmp_path / "parent.sqlite3")

        class SlowUnavailablePlanner(_ScriptedPlanner):
            async def plan(self, planner_input):
                del planner_input
                await asyncio.sleep(0.05)
                raise RuntimeError("private provider dispatch detail")

        workflow = DurableScenarioWorkflow(
            store,
            workspace_root,
            semantic_config_sha256="5" * 64,
            planner_factory=lambda _scenario: SlowUnavailablePlanner(()),
        )
        service = OperatorApplicationService(runner=workflow, projection_store=store)
        await service.start()
        launch = ScenarioLaunchRequest(
            schema_version=SCENARIO_LAUNCH_REQUEST_VERSION,
            launch_id="hybrid-shared-elapsed-budget",
            scenario=ScenarioLaunchName.SANDBOX_ORDER,
            mode=ScenarioRunMode.ADAPTIVE,
        )
        created = await service.launch(launch)
        terminal = await _terminal(service, created.snapshot.investigation_id)
        work = await store.get_work(created.snapshot.investigation_id)
        await service.aclose()

        assert terminal.report is not None
        assert terminal.report.route_provenance is not None
        assert terminal.report.route_provenance.outcome is (
            ScenarioHybridOutcome.FIXED_FALLBACK
        )
        assert terminal.report.probe_audit[0].session_elapsed_ms >= 40
        assert terminal.report.probe_audit[-1].session_elapsed_ms <= 5_000
        lane_root = workspace_root / work.workspace_id
        adaptive_run = await SqliteDurableRuntimeStore(
            lane_root / "runtime-adaptive.sqlite3"
        ).get_run(created.snapshot.investigation_id)
        fixed_run = await SqliteDurableRuntimeStore(
            lane_root / "runtime-fixed.sqlite3"
        ).get_run(created.snapshot.investigation_id)
        assert adaptive_run.created_at == fixed_run.created_at == work.invoked_at

    asyncio.run(exercise())


def test_adaptive_recovery_without_existing_lane_fails_closed(
    tmp_path: Path,
) -> None:
    async def exercise() -> None:
        os.chmod(tmp_path, 0o700)
        workspace_root = tmp_path / "workspaces"
        workspace_root.mkdir(mode=0o700)
        planner_dispatches = 0

        def planner_factory(_scenario):
            nonlocal planner_dispatches
            planner_dispatches += 1
            return _ScriptedPlanner((SANDBOX_ORDER_FIXED_PROBE_PLAN.steps[0].request,))

        store = SqliteScenarioStore(tmp_path / "parent.sqlite3")
        workflow = DurableScenarioWorkflow(
            store,
            workspace_root,
            semantic_config_sha256="4" * 64,
            planner_factory=planner_factory,
        )
        bound = await _bind(
            workflow,
            launch_id="adaptive-boundary",
            scenario=ScenarioLaunchName.SANDBOX_ORDER,
            mode=ScenarioRunMode.ADAPTIVE,
        )
        await _record_mutation_and_start_investigation(
            store,
            workspace_root,
            bound,
        )
        investigation_id = bound.work.scenario_request.investigation_id
        lane_path = (
            workspace_root / bound.work.workspace_id / "runtime-adaptive.sqlite3"
        )
        assert not lane_path.exists()

        service = OperatorApplicationService(
            runner=workflow,
            projection_store=store,
        )
        await service.start()
        terminal = await _terminal(service, investigation_id)
        recovered = await store.get_work(investigation_id)
        await service.aclose()

        assert terminal.lifecycle is ScenarioRunLifecycle.FAILED
        assert planner_dispatches == 0
        assert not lane_path.exists()
        assert (
            recovered.investigation_state
            is ScenarioInvestigationState.ESCALATION_REQUIRED
        )
        assert recovered.recovery_failure_code == ("durable-lane-escalation-required")

    asyncio.run(exercise())


@pytest.mark.parametrize(
    "mode",
    (ScenarioRunMode.ADAPTIVE, ScenarioRunMode.COMPARE),
)
def test_adaptive_recovery_with_empty_valid_lane_fails_closed(
    tmp_path: Path,
    mode: ScenarioRunMode,
) -> None:
    async def exercise() -> None:
        os.chmod(tmp_path, 0o700)
        workspace_root = tmp_path / "workspaces"
        workspace_root.mkdir(mode=0o700)
        planner_factories = 0

        def planner_factory(_scenario):
            nonlocal planner_factories
            planner_factories += 1
            return _ScriptedPlanner((SANDBOX_ORDER_FIXED_PROBE_PLAN.steps[0].request,))

        store = SqliteScenarioStore(tmp_path / "parent.sqlite3")
        workflow = DurableScenarioWorkflow(
            store,
            workspace_root,
            semantic_config_sha256="5" * 64,
            planner_factory=planner_factory,
        )
        bound = await _bind(
            workflow,
            launch_id=f"empty-adaptive-{mode.value.lower()}",
            scenario=ScenarioLaunchName.SANDBOX_ORDER,
            mode=mode,
        )
        await _record_mutation_and_start_investigation(
            store,
            workspace_root,
            bound,
        )
        investigation_id = bound.work.scenario_request.investigation_id
        lane_path = (
            workspace_root / bound.work.workspace_id / "runtime-adaptive.sqlite3"
        )
        empty_lane = SqliteDurableRuntimeStore(lane_path)
        assert await empty_lane.list_runs() == ()

        service = OperatorApplicationService(
            runner=workflow,
            projection_store=store,
        )
        await service.start()
        terminal = await _terminal(service, investigation_id)
        recovered = await store.get_work(investigation_id)
        await service.aclose()

        assert terminal.lifecycle is ScenarioRunLifecycle.FAILED
        assert planner_factories == 0
        assert await empty_lane.list_runs() == ()
        with sqlite3.connect(lane_path) as connection:
            assert connection.execute(
                "SELECT COUNT(*) FROM runtime_cost_entries"
            ).fetchone() == (0,)
        assert (
            recovered.investigation_state
            is ScenarioInvestigationState.ESCALATION_REQUIRED
        )
        assert recovered.recovery_failure_code == ("durable-lane-escalation-required")
        assert recovered.cleanup_status is CleanupStatus.NOT_REQUESTED
        assert recovered.workflow_result is None

    asyncio.run(exercise())


@pytest.mark.parametrize("foreign_run_count", (1, 2))
def test_fixed_lane_rejects_foreign_or_extra_runs_before_dispatch(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    foreign_run_count: int,
) -> None:
    async def exercise() -> None:
        os.chmod(tmp_path, 0o700)
        workspace_root = tmp_path / "workspaces"
        workspace_root.mkdir(mode=0o700)
        fixed_dispatches = 0

        async def unexpected_fixed_dispatch(*args, **kwargs):
            del args, kwargs
            nonlocal fixed_dispatches
            fixed_dispatches += 1
            raise AssertionError("fixed investigation must not dispatch")

        monkeypatch.setattr(
            durable_scenarios_module,
            "_fixed_investigation",
            unexpected_fixed_dispatch,
        )
        store = SqliteScenarioStore(tmp_path / "parent.sqlite3")
        workflow = DurableScenarioWorkflow(
            store,
            workspace_root,
            semantic_config_sha256="6" * 64,
        )
        bound = await _bind(workflow, launch_id=f"foreign-fixed-{foreign_run_count}")
        await _record_mutation_and_start_investigation(
            store,
            workspace_root,
            bound,
        )
        investigation_id = bound.work.scenario_request.investigation_id
        lane_path = workspace_root / bound.work.workspace_id / "runtime-fixed.sqlite3"
        lane = SqliteDurableRuntimeStore(lane_path)
        for index in range(foreign_run_count):
            foreign = make_envelope().model_copy(
                update={"investigation_id": f"foreign-investigation-{index + 1}"}
            )
            created_at = datetime.now(UTC)
            await lane.create_run(
                foreign,
                created_at=created_at,
                limits=runtime_limits_for(
                    foreign,
                    started_at=created_at,
                    max_provider_calls=0,
                    max_estimated_cost_microunits=0,
                ),
                runtime_provenance_sha256="7" * 64,
            )

        service = OperatorApplicationService(
            runner=workflow,
            projection_store=store,
        )
        await service.start()
        terminal = await _terminal(service, investigation_id)
        recovered = await store.get_work(investigation_id)
        await service.aclose()

        assert terminal.lifecycle is ScenarioRunLifecycle.FAILED
        assert fixed_dispatches == 0
        assert len(await lane.list_runs()) == foreign_run_count
        assert (
            recovered.investigation_state
            is ScenarioInvestigationState.ESCALATION_REQUIRED
        )
        assert recovered.cleanup_status is CleanupStatus.NOT_REQUESTED

    asyncio.run(exercise())


def test_child_lane_symlink_is_rejected_without_touching_target(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def exercise() -> None:
        os.chmod(tmp_path, 0o700)
        workspace_root = tmp_path / "workspaces"
        workspace_root.mkdir(mode=0o700)
        fixed_dispatches = 0

        async def unexpected_fixed_dispatch(*args, **kwargs):
            del args, kwargs
            nonlocal fixed_dispatches
            fixed_dispatches += 1
            raise AssertionError("fixed investigation must not dispatch")

        monkeypatch.setattr(
            durable_scenarios_module,
            "_fixed_investigation",
            unexpected_fixed_dispatch,
        )
        store = SqliteScenarioStore(tmp_path / "parent.sqlite3")
        workflow = DurableScenarioWorkflow(
            store,
            workspace_root,
            semantic_config_sha256="8" * 64,
        )
        bound = await _bind(workflow, launch_id="symlink-fixed-lane")
        await _record_mutation_and_start_investigation(
            store,
            workspace_root,
            bound,
        )
        investigation_id = bound.work.scenario_request.investigation_id
        sentinel = tmp_path / "external-sentinel.sqlite3"
        sentinel.write_bytes(b"external-sentinel")
        os.chmod(sentinel, 0o640)
        original_mode = sentinel.stat().st_mode
        lane_path = workspace_root / bound.work.workspace_id / "runtime-fixed.sqlite3"
        lane_path.symlink_to(sentinel)

        service = OperatorApplicationService(
            runner=workflow,
            projection_store=store,
        )
        await service.start()
        terminal = await _terminal(service, investigation_id)
        recovered = await store.get_work(investigation_id)
        await service.aclose()

        assert terminal.lifecycle is ScenarioRunLifecycle.FAILED
        assert fixed_dispatches == 0
        assert lane_path.is_symlink()
        assert sentinel.read_bytes() == b"external-sentinel"
        assert sentinel.stat().st_mode == original_mode
        assert (
            recovered.investigation_state
            is ScenarioInvestigationState.ESCALATION_REQUIRED
        )
        assert recovered.cleanup_status is CleanupStatus.NOT_REQUESTED

    asyncio.run(exercise())


def test_pristine_bound_workspace_is_repaired_before_mutation(tmp_path: Path) -> None:
    async def exercise() -> None:
        os.chmod(tmp_path, 0o700)
        workspace_root = tmp_path / "workspaces"
        workspace_root.mkdir(mode=0o700)
        store = SqliteScenarioStore(tmp_path / "parent.sqlite3")
        workflow = DurableScenarioWorkflow(
            store,
            workspace_root,
            semantic_config_sha256="a" * 64,
        )
        bound = await _bind(workflow, launch_id="pristine-workspace-repair")
        investigation_id = bound.work.scenario_request.investigation_id
        workspace = workspace_root / bound.work.workspace_id
        workspace.rmdir()

        service = OperatorApplicationService(
            runner=workflow,
            projection_store=store,
        )
        await service.start()
        terminal = await _terminal(service, investigation_id)
        recovered = await store.get_work(investigation_id)
        await service.aclose()

        assert terminal.lifecycle is ScenarioRunLifecycle.COMPLETED
        assert workspace.is_dir()
        assert workspace.stat().st_mode & 0o077 == 0
        assert recovered.mutation_state is ScenarioMutationState.RECORDED
        assert recovered.investigation_state is ScenarioInvestigationState.RECORDED

    asyncio.run(exercise())


def test_missing_workspace_after_mutation_start_is_not_recreated(
    tmp_path: Path,
) -> None:
    async def exercise() -> None:
        os.chmod(tmp_path, 0o700)
        workspace_root = tmp_path / "workspaces"
        workspace_root.mkdir(mode=0o700)
        store = SqliteScenarioStore(tmp_path / "parent.sqlite3")
        workflow = DurableScenarioWorkflow(
            store,
            workspace_root,
            semantic_config_sha256="b" * 64,
        )
        bound = await _bind(workflow, launch_id="started-workspace-missing")
        investigation_id = bound.work.scenario_request.investigation_id
        acquired_at = datetime.now(UTC)
        token = await store.acquire_scenario_lease(
            investigation_id,
            "workspace-boundary",
            now=acquired_at,
        )
        await store.record_mutation_started(
            token,
            prepared_envelope_sha256="1" * 64,
            cleanup_manifest_sha256="2" * 64,
            occurred_at=acquired_at,
        )
        await store.release_scenario_lease(token, now=acquired_at)
        workspace = workspace_root / bound.work.workspace_id
        workspace.rmdir()

        service = OperatorApplicationService(
            runner=workflow,
            projection_store=store,
        )
        await service.start()
        terminal = await _terminal(service, investigation_id)
        recovered = await store.get_work(investigation_id)
        await service.aclose()

        assert terminal.lifecycle is ScenarioRunLifecycle.FAILED
        assert not workspace.exists()
        assert recovered.mutation_state is ScenarioMutationState.STARTED
        assert (
            recovered.investigation_state
            is ScenarioInvestigationState.ESCALATION_REQUIRED
        )
        assert recovered.recovery_failure_code == "scenario-workspace-drift"
        assert recovered.cleanup_status is CleanupStatus.NOT_REQUESTED

    asyncio.run(exercise())


@pytest.mark.parametrize(
    ("mode", "result_kind"),
    (
        (ScenarioRunMode.COMPARE, "report"),
        (ScenarioRunMode.FIXED, "comparison"),
        (ScenarioRunMode.ADAPTIVE, "comparison"),
    ),
)
def test_workflow_result_type_must_match_strategy(
    tmp_path: Path,
    mode: ScenarioRunMode,
    result_kind: str,
) -> None:
    async def exercise() -> None:
        store, work, token = await _ready_parent_for_workflow_result(
            tmp_path,
            launch_id=f"result-type-{mode.value.lower()}",
            mode=mode,
        )
        result = (
            _report_for_work(work)
            if result_kind == "report"
            else _comparison_for_work(work)
        )

        with pytest.raises(ScenarioStateConflict):
            await store.record_workflow_result(
                token,
                result,
                occurred_at=datetime.now(UTC),
            )
        current = await store.get_work(work.scenario_request.investigation_id)
        await store.release_scenario_lease(token, now=datetime.now(UTC))

        assert current.investigation_state is ScenarioInvestigationState.STARTED
        assert current.workflow_result is None
        assert current.cleanup_status is CleanupStatus.NOT_REQUESTED

    asyncio.run(exercise())


def test_comparison_result_cannot_borrow_another_scenario_with_same_envelope(
    tmp_path: Path,
) -> None:
    async def exercise() -> None:
        store, work, token = await _ready_parent_for_workflow_result(
            tmp_path,
            launch_id="comparison-foreign-scenario",
            mode=ScenarioRunMode.COMPARE,
        )
        valid = _comparison_for_work(work)
        assert valid.adaptive is not None
        await store.record_lane_result(
            token,
            ScenarioLane.FIXED,
            valid.baseline,
            occurred_at=datetime.now(UTC),
        )
        await store.record_lane_result(
            token,
            ScenarioLane.ADAPTIVE,
            valid.adaptive,
            occurred_at=datetime.now(UTC),
        )
        foreign = _comparison_for_work(
            work,
            scenario=FIRESTORE_BUSINESS_SCENARIO,
        )

        with pytest.raises(ScenarioStateConflict):
            await store.record_workflow_result(
                token,
                foreign,
                occurred_at=datetime.now(UTC),
            )
        current = await store.get_work(work.scenario_request.investigation_id)
        listed = await store.list_work()
        await store.release_scenario_lease(token, now=datetime.now(UTC))

        assert current.investigation_state is ScenarioInvestigationState.STARTED
        assert current.workflow_result is None
        assert listed == (current,)

    asyncio.run(exercise())


def test_noncompleted_report_cannot_record_parent_result(tmp_path: Path) -> None:
    async def exercise() -> None:
        store, work, token = await _ready_parent_for_workflow_result(
            tmp_path,
            launch_id="noncompleted-parent-report",
            mode=ScenarioRunMode.FIXED,
        )
        report = _report_for_work(
            work,
            status=InvestigationStatus.INVESTIGATING,
        )

        with pytest.raises(ScenarioStateConflict):
            await store.record_workflow_result(
                token,
                report,
                occurred_at=datetime.now(UTC),
            )
        current = await store.get_work(work.scenario_request.investigation_id)
        await store.release_scenario_lease(token, now=datetime.now(UTC))

        assert current.investigation_state is ScenarioInvestigationState.STARTED
        assert current.workflow_result is None

    asyncio.run(exercise())


@pytest.mark.parametrize("missing_lane", (ScenarioLane.FIXED, ScenarioLane.ADAPTIVE))
def test_comparison_result_requires_both_exact_lane_rows(
    tmp_path: Path,
    missing_lane: ScenarioLane,
) -> None:
    async def exercise() -> None:
        store, work, token = await _ready_parent_for_workflow_result(
            tmp_path,
            launch_id=f"missing-{missing_lane.value.lower()}-lane",
            mode=ScenarioRunMode.COMPARE,
        )
        comparison = _comparison_for_work(work)
        assert comparison.adaptive is not None
        present_lane = (
            ScenarioLane.ADAPTIVE
            if missing_lane is ScenarioLane.FIXED
            else ScenarioLane.FIXED
        )
        present_result = (
            comparison.adaptive
            if present_lane is ScenarioLane.ADAPTIVE
            else comparison.baseline
        )
        await store.record_lane_result(
            token,
            present_lane,
            present_result,
            occurred_at=datetime.now(UTC),
        )

        with pytest.raises(ScenarioStateConflict):
            await store.record_workflow_result(
                token,
                comparison,
                occurred_at=datetime.now(UTC),
            )
        current = await store.get_work(work.scenario_request.investigation_id)
        listed = await store.list_work()
        await store.release_scenario_lease(token, now=datetime.now(UTC))

        assert current.investigation_state is ScenarioInvestigationState.STARTED
        assert current.workflow_result is None
        assert listed == (current,)

    asyncio.run(exercise())


def test_comparison_result_rejects_divergent_lane_row(tmp_path: Path) -> None:
    async def exercise() -> None:
        store, work, token = await _ready_parent_for_workflow_result(
            tmp_path,
            launch_id="divergent-comparison-lane",
            mode=ScenarioRunMode.COMPARE,
        )
        comparison = _comparison_for_work(work)
        assert comparison.adaptive is not None
        divergent_adaptive = comparison.adaptive.model_copy(
            update={"plan_sha256": "f" * 64}
        )
        await store.record_lane_result(
            token,
            ScenarioLane.FIXED,
            comparison.baseline,
            occurred_at=datetime.now(UTC),
        )
        await store.record_lane_result(
            token,
            ScenarioLane.ADAPTIVE,
            divergent_adaptive,
            occurred_at=datetime.now(UTC),
        )

        with pytest.raises(ScenarioStateConflict):
            await store.record_workflow_result(
                token,
                comparison,
                occurred_at=datetime.now(UTC),
            )
        current = await store.get_work(work.scenario_request.investigation_id)
        await store.release_scenario_lease(token, now=datetime.now(UTC))

        assert current.investigation_state is ScenarioInvestigationState.STARTED
        assert current.workflow_result is None

    asyncio.run(exercise())


def test_lane_result_read_rejects_noncanonical_payload_with_matching_digest(
    tmp_path: Path,
) -> None:
    async def exercise() -> None:
        store, work, token = await _ready_parent_for_workflow_result(
            tmp_path,
            launch_id="noncanonical-comparison-lane",
            mode=ScenarioRunMode.COMPARE,
        )
        comparison = _comparison_for_work(work)
        await store.record_lane_result(
            token,
            ScenarioLane.FIXED,
            comparison.baseline,
            occurred_at=datetime.now(UTC),
        )
        database = tmp_path / "parent.sqlite3"
        noncanonical = b" " + canonical_json_bytes(comparison.baseline)
        with sqlite3.connect(database) as connection:
            connection.execute(
                "UPDATE scenario_lane_results SET sha256 = ?, payload = ? "
                "WHERE investigation_id = ? AND lane = ?",
                (
                    hashlib.sha256(noncanonical).hexdigest(),
                    noncanonical,
                    work.scenario_request.investigation_id,
                    ScenarioLane.FIXED.value,
                ),
            )

        with pytest.raises(CorruptScenarioState):
            await store.get_lane_result(
                work.scenario_request.investigation_id,
                ScenarioLane.FIXED,
            )

    asyncio.run(exercise())


@pytest.mark.parametrize("mode", (ScenarioRunMode.FIXED, ScenarioRunMode.ADAPTIVE))
def test_completed_report_is_valid_for_noncomparison_strategy(
    tmp_path: Path,
    mode: ScenarioRunMode,
) -> None:
    async def exercise() -> None:
        store, work, token = await _ready_parent_for_workflow_result(
            tmp_path,
            launch_id=f"valid-report-{mode.value.lower()}",
            mode=mode,
        )
        report = _report_for_work(work)
        recorded = await store.record_workflow_result(
            token,
            report,
            occurred_at=datetime.now(UTC),
        )
        await store.release_scenario_lease(token, now=datetime.now(UTC))

        assert recorded.investigation_state is ScenarioInvestigationState.RECORDED
        assert recorded.workflow_result == report

    asyncio.run(exercise())


def test_comparison_result_is_valid_only_with_exact_lane_rows(tmp_path: Path) -> None:
    async def exercise() -> None:
        store, work, token = await _ready_parent_for_workflow_result(
            tmp_path,
            launch_id="valid-comparison-lanes",
            mode=ScenarioRunMode.COMPARE,
        )
        comparison = _comparison_for_work(work)
        assert comparison.adaptive is not None
        await store.record_lane_result(
            token,
            ScenarioLane.FIXED,
            comparison.baseline,
            occurred_at=datetime.now(UTC),
        )
        await store.record_lane_result(
            token,
            ScenarioLane.ADAPTIVE,
            comparison.adaptive,
            occurred_at=datetime.now(UTC),
        )
        recorded = await store.record_workflow_result(
            token,
            comparison,
            occurred_at=datetime.now(UTC),
        )
        await store.release_scenario_lease(token, now=datetime.now(UTC))

        assert recorded.investigation_state is ScenarioInvestigationState.RECORDED
        assert recorded.workflow_result == comparison
        assert await store.get_work(work.scenario_request.investigation_id) == recorded
        assert await store.list_work() == (recorded,)

    asyncio.run(exercise())


def test_recorded_comparison_get_and_list_reject_missing_or_weakened_lane_authority(
    tmp_path: Path,
) -> None:
    async def exercise() -> None:
        store, work, token = await _ready_parent_for_workflow_result(
            tmp_path,
            launch_id="tampered-recorded-comparison",
            mode=ScenarioRunMode.COMPARE,
        )
        comparison = _comparison_for_work(work)
        assert comparison.adaptive is not None
        await store.record_lane_result(
            token,
            ScenarioLane.FIXED,
            comparison.baseline,
            occurred_at=datetime.now(UTC),
        )
        await store.record_lane_result(
            token,
            ScenarioLane.ADAPTIVE,
            comparison.adaptive,
            occurred_at=datetime.now(UTC),
        )
        recorded = await store.record_workflow_result(
            token,
            comparison,
            occurred_at=datetime.now(UTC),
        )
        await store.release_scenario_lease(token, now=datetime.now(UTC))
        investigation_id = work.scenario_request.investigation_id
        database = tmp_path / "parent.sqlite3"
        with sqlite3.connect(database) as connection:
            connection.execute(
                "DELETE FROM scenario_lane_results "
                "WHERE investigation_id = ? AND lane = ?",
                (investigation_id, ScenarioLane.ADAPTIVE.value),
            )

        with pytest.raises(CorruptScenarioState):
            await store.get_work(investigation_id)
        with pytest.raises(CorruptScenarioState):
            await store.list_work()

        adaptive_payload = canonical_json_bytes(comparison.adaptive)
        weakened = recorded.model_copy(
            update={"workflow_result": comparison.model_copy(update={"adaptive": None})}
        )
        with sqlite3.connect(database) as connection:
            connection.execute(
                "INSERT INTO scenario_lane_results "
                "(investigation_id, lane, sha256, payload) VALUES (?, ?, ?, ?)",
                (
                    investigation_id,
                    ScenarioLane.ADAPTIVE.value,
                    hashlib.sha256(adaptive_payload).hexdigest(),
                    adaptive_payload,
                ),
            )
            connection.execute(
                "UPDATE scenario_work_items SET payload = ? WHERE investigation_id = ?",
                (canonical_json_bytes(weakened), investigation_id),
            )

        with pytest.raises(CorruptScenarioState):
            await store.get_work(investigation_id)
        with pytest.raises(CorruptScenarioState):
            await store.list_work()

    asyncio.run(exercise())


def test_recorded_noncomparison_get_and_list_reject_stray_lane_row(
    tmp_path: Path,
) -> None:
    async def exercise() -> None:
        store, work, token = await _ready_parent_for_workflow_result(
            tmp_path,
            launch_id="stray-fixed-parent-lane",
            mode=ScenarioRunMode.FIXED,
        )
        report = _report_for_work(work)
        await store.record_workflow_result(
            token,
            report,
            occurred_at=datetime.now(UTC),
        )
        await store.release_scenario_lease(token, now=datetime.now(UTC))
        stray = _comparison_for_work(work).baseline
        payload = canonical_json_bytes(stray)
        investigation_id = work.scenario_request.investigation_id
        with sqlite3.connect(tmp_path / "parent.sqlite3") as connection:
            connection.execute(
                "INSERT INTO scenario_lane_results "
                "(investigation_id, lane, sha256, payload) VALUES (?, ?, ?, ?)",
                (
                    investigation_id,
                    ScenarioLane.FIXED.value,
                    hashlib.sha256(payload).hexdigest(),
                    payload,
                ),
            )

        with pytest.raises(CorruptScenarioState):
            await store.get_work(investigation_id)
        with pytest.raises(CorruptScenarioState):
            await store.list_work()

    asyncio.run(exercise())


def test_compare_lane_before_investigation_start_is_corruption(
    tmp_path: Path,
) -> None:
    async def exercise() -> None:
        os.chmod(tmp_path, 0o700)
        workspace_root = tmp_path / "workspaces"
        workspace_root.mkdir(mode=0o700)
        database = tmp_path / "parent.sqlite3"
        store = SqliteScenarioStore(database)
        workflow = DurableScenarioWorkflow(
            store,
            workspace_root,
            semantic_config_sha256="2" * 64,
        )
        bound = await _bind(
            workflow,
            launch_id="lane-before-investigation-start",
            mode=ScenarioRunMode.COMPARE,
        )
        await _record_mutation_and_start_investigation(
            store,
            workspace_root,
            bound,
            start_investigation=False,
        )
        work = await store.get_work(bound.work.scenario_request.investigation_id)
        assert work.investigation_state is ScenarioInvestigationState.NOT_STARTED
        lane = _comparison_for_work(work).baseline
        payload = canonical_json_bytes(lane)
        with sqlite3.connect(database) as connection:
            connection.execute(
                "INSERT INTO scenario_lane_results "
                "(investigation_id, lane, sha256, payload) VALUES (?, ?, ?, ?)",
                (
                    work.scenario_request.investigation_id,
                    ScenarioLane.FIXED.value,
                    hashlib.sha256(payload).hexdigest(),
                    payload,
                ),
            )

        with pytest.raises(CorruptScenarioState):
            await store.get_work(work.scenario_request.investigation_id)
        with pytest.raises(CorruptScenarioState):
            await store.list_work()

    asyncio.run(exercise())


def test_escalated_comparison_retains_valid_partial_lane_authority(
    tmp_path: Path,
) -> None:
    async def exercise() -> None:
        store, work, token = await _ready_parent_for_workflow_result(
            tmp_path,
            launch_id="escalated-partial-comparison-lane",
            mode=ScenarioRunMode.COMPARE,
        )
        comparison = _comparison_for_work(work)
        await store.record_lane_result(
            token,
            ScenarioLane.FIXED,
            comparison.baseline,
            occurred_at=datetime.now(UTC),
        )
        escalated = await store.require_scenario_escalation(
            token,
            "partial-lane-escalation",
            occurred_at=datetime.now(UTC),
        )
        current = await store.get_work(work.scenario_request.investigation_id)
        listed = await store.list_work()
        await store.release_scenario_lease(token, now=datetime.now(UTC))

        assert current == escalated
        assert current.investigation_state is (
            ScenarioInvestigationState.ESCALATION_REQUIRED
        )
        assert listed == (current,)
        assert (
            await store.get_lane_result(
                work.scenario_request.investigation_id,
                ScenarioLane.FIXED,
            )
            == comparison.baseline
        )

    asyncio.run(exercise())


def test_terminal_comparison_startup_reaudits_canonical_lane_rows(
    tmp_path: Path,
) -> None:
    async def exercise() -> None:
        os.chmod(tmp_path, 0o700)
        workspace_root = tmp_path / "workspaces"
        workspace_root.mkdir(mode=0o700)
        database = tmp_path / "parent.sqlite3"
        store = SqliteScenarioStore(database)
        workflow = DurableScenarioWorkflow(
            store,
            workspace_root,
            semantic_config_sha256="1" * 64,
            planner_factory=lambda _scenario: _ScriptedPlanner(
                tuple(step.request for step in STORAGE_FIXED_PROBE_PLAN.steps)
            ),
        )
        first = OperatorApplicationService(
            runner=workflow,
            projection_store=store,
        )
        await first.start()
        created = await first.launch(
            ScenarioLaunchRequest(
                schema_version=SCENARIO_LAUNCH_REQUEST_VERSION,
                launch_id="terminal-comparison-lane-audit",
                scenario=ScenarioLaunchName.STORAGE,
                mode=ScenarioRunMode.COMPARE,
            )
        )
        investigation_id = created.snapshot.investigation_id
        assert (await _terminal(first, investigation_id)).lifecycle is (
            ScenarioRunLifecycle.COMPLETED
        )
        await first.aclose()

        with sqlite3.connect(database) as connection:
            row = connection.execute(
                "SELECT payload FROM scenario_lane_results "
                "WHERE investigation_id = ? AND lane = ?",
                (investigation_id, ScenarioLane.FIXED.value),
            ).fetchone()
            assert row is not None
            noncanonical = b" " + bytes(row[0])
            connection.execute(
                "UPDATE scenario_lane_results SET sha256 = ?, payload = ? "
                "WHERE investigation_id = ? AND lane = ?",
                (
                    hashlib.sha256(noncanonical).hexdigest(),
                    noncanonical,
                    investigation_id,
                    ScenarioLane.FIXED.value,
                ),
            )

        second = OperatorApplicationService(
            runner=workflow,
            projection_store=store,
        )
        with pytest.raises(CorruptScenarioState):
            await second.start()
        await second.aclose()

    asyncio.run(exercise())


def test_stale_parent_fence_cannot_insert_or_adopt_lane_result(
    tmp_path: Path,
) -> None:
    async def exercise() -> None:
        os.chmod(tmp_path, 0o700)
        workspace_root = tmp_path / "workspaces"
        workspace_root.mkdir(mode=0o700)
        store = SqliteScenarioStore(tmp_path / "parent.sqlite3")
        workflow = DurableScenarioWorkflow(
            store,
            workspace_root,
            semantic_config_sha256="8" * 64,
            planner_factory=lambda _scenario: _ScriptedPlanner(
                (STORAGE_FIXED_PROBE_PLAN.steps[0].request,)
            ),
        )
        bound = await _bind(
            workflow,
            launch_id="stale-lane-fence",
            mode=ScenarioRunMode.COMPARE,
        )
        await _record_mutation_and_start_investigation(
            store,
            workspace_root,
            bound,
        )
        work = await store.get_work(bound.work.scenario_request.investigation_id)
        assert work.envelope_sha256 is not None
        comparison = make_comparison_record().baseline.model_copy(
            update={
                "scenario": work.scenario_request.scenario,
                "envelope_sha256": work.envelope_sha256,
            }
        )
        acquired_at = datetime.now(UTC)
        stale = await store.acquire_scenario_lease(
            work.scenario_request.investigation_id,
            "owner-a",
            now=acquired_at,
        )
        takeover_at = acquired_at + timedelta(seconds=31)
        current = await store.acquire_scenario_lease(
            work.scenario_request.investigation_id,
            "owner-b",
            now=takeover_at,
        )

        with pytest.raises(StaleScenarioLease):
            await store.record_lane_result(
                stale,
                ScenarioLane.FIXED,
                comparison,
                occurred_at=takeover_at,
            )
        await store.record_lane_result(
            current,
            ScenarioLane.FIXED,
            comparison,
            occurred_at=takeover_at,
        )
        with pytest.raises(StaleScenarioLease):
            await store.record_lane_result(
                stale,
                ScenarioLane.FIXED,
                comparison,
                occurred_at=takeover_at,
            )
        assert (
            await store.get_lane_result(
                work.scenario_request.investigation_id,
                ScenarioLane.FIXED,
            )
            == comparison
        )

    asyncio.run(exercise())


@pytest.mark.parametrize(
    ("expired", "mismatch"),
    (
        (False, "investigation_id"),
        (False, "fence"),
        (True, "investigation_id"),
        (True, "fence"),
    ),
)
def test_scenario_lease_payload_mismatch_is_corruption_before_expiry_decision(
    tmp_path: Path,
    *,
    expired: bool,
    mismatch: str,
) -> None:
    async def exercise() -> None:
        os.chmod(tmp_path, 0o700)
        workspace_root = tmp_path / "workspaces"
        workspace_root.mkdir(mode=0o700)
        database = tmp_path / "parent.sqlite3"
        store = SqliteScenarioStore(database)
        workflow = DurableScenarioWorkflow(
            store,
            workspace_root,
            semantic_config_sha256="c" * 64,
        )
        bound = await _bind(
            workflow,
            launch_id=f"lease-corruption-{expired}-{mismatch}",
        )
        investigation_id = bound.work.scenario_request.investigation_id
        acquired_at = datetime.now(UTC)
        token = await store.acquire_scenario_lease(
            investigation_id,
            "lease-owner-a",
            now=acquired_at,
        )
        forged = token.model_copy(
            update={
                mismatch: (
                    "foreign-investigation"
                    if mismatch == "investigation_id"
                    else token.fence + 7
                )
            }
        )
        forged_payload = canonical_json_bytes(forged)
        with sqlite3.connect(database) as connection:
            connection.execute(
                "UPDATE scenario_leases SET payload = ? WHERE investigation_id = ?",
                (forged_payload, investigation_id),
            )
        attempted_at = acquired_at + timedelta(seconds=31 if expired else 1)

        with pytest.raises(CorruptScenarioState):
            await store.acquire_scenario_lease(
                investigation_id,
                "lease-owner-b",
                now=attempted_at,
            )
        with sqlite3.connect(database) as connection:
            persisted = connection.execute(
                "SELECT fence, payload FROM scenario_leases WHERE investigation_id = ?",
                (investigation_id,),
            ).fetchone()
        assert persisted == (token.fence, forged_payload)

    asyncio.run(exercise())


def test_valid_scenario_lease_availability_and_expired_takeover(tmp_path: Path) -> None:
    async def exercise() -> None:
        os.chmod(tmp_path, 0o700)
        workspace_root = tmp_path / "workspaces"
        workspace_root.mkdir(mode=0o700)
        store = SqliteScenarioStore(tmp_path / "parent.sqlite3")
        workflow = DurableScenarioWorkflow(
            store,
            workspace_root,
            semantic_config_sha256="d" * 64,
        )
        bound = await _bind(workflow, launch_id="valid-lease-takeover")
        investigation_id = bound.work.scenario_request.investigation_id
        acquired_at = datetime.now(UTC)
        first = await store.acquire_scenario_lease(
            investigation_id,
            "lease-owner-a",
            now=acquired_at,
        )
        with pytest.raises(ScenarioLeaseUnavailable):
            await store.acquire_scenario_lease(
                investigation_id,
                "lease-owner-b",
                now=acquired_at + timedelta(seconds=1),
            )
        takeover = await store.acquire_scenario_lease(
            investigation_id,
            "lease-owner-b",
            now=acquired_at + timedelta(seconds=31),
        )
        assert takeover.investigation_id == investigation_id
        assert takeover.owner_id == "lease-owner-b"
        assert takeover.fence == first.fence + 1

    asyncio.run(exercise())


def test_default_api_reconnects_to_exact_durable_v1_projection(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    os.chmod(tmp_path, 0o700)
    database = tmp_path / "operator.sqlite3"
    monkeypatch.setenv("RECONCILE_RUNTIME_DATABASE", str(database))
    monkeypatch.setenv("RECONCILE_SEMANTIC_CONFIG_SHA256", "9" * 64)
    monkeypatch.delenv("RECONCILE_VERTEX_PROJECT", raising=False)
    monkeypatch.delenv("RECONCILE_VERTEX_LOCATION", raising=False)
    monkeypatch.delenv("RECONCILE_VERTEX_MODEL", raising=False)
    launch = ScenarioLaunchRequest(
        schema_version=SCENARIO_LAUNCH_REQUEST_VERSION,
        launch_id="api-durable-reconnect",
        scenario=ScenarioLaunchName.STORAGE,
        mode=ScenarioRunMode.FIXED,
    )

    with TestClient(create_app()) as client:
        response = client.post(
            "/api/v1/scenario-runs",
            content=canonical_json_bytes(launch),
            headers={"Content-Type": "application/json"},
        )
        assert response.status_code == 202
        accepted = decode_contract(response.content, ScenarioRunSnapshot)
        deadline = time.monotonic() + 20
        while True:
            current_response = client.get(
                f"/api/v1/scenario-runs/{accepted.investigation_id}"
            )
            current = decode_contract(current_response.content, ScenarioRunSnapshot)
            if current.lifecycle is ScenarioRunLifecycle.COMPLETED:
                break
            assert current.lifecycle in {
                ScenarioRunLifecycle.ACCEPTED,
                ScenarioRunLifecycle.RUNNING,
            }
            assert time.monotonic() < deadline
            time.sleep(0.02)
        terminal_bytes = current_response.content

    with TestClient(create_app()) as client:
        reconnected = client.get(f"/api/v1/scenario-runs/{accepted.investigation_id}")
        events = client.get(f"/api/v1/scenario-runs/{accepted.investigation_id}/events")

    assert reconnected.status_code == 200
    assert reconnected.content == terminal_bytes
    assert events.status_code == 200
    assert f"id: {current.event_cursor}\n".encode() in events.content
