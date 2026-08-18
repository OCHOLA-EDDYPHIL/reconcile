from __future__ import annotations

import asyncio
import json
from datetime import UTC, datetime, timedelta

import httpx
import pytest
from textual.widgets import Input

from reconcile.contracts import (
    SCENARIO_LAUNCH_REQUEST_VERSION,
    SCENARIO_RUN_EVENT_VERSION,
    SCENARIO_RUN_SNAPSHOT_VERSION,
    Classification,
    EnvelopeSummaryEventPayload,
    ExecutionEnvelope,
    InvestigationReport,
    ScenarioLaunchName,
    ScenarioLaunchRequest,
    ScenarioLifecycleEventPayload,
    ScenarioRunEvent,
    ScenarioRunEventType,
    ScenarioRunFailureCategory,
    ScenarioRunLifecycle,
    ScenarioRunMode,
    ScenarioRunSnapshot,
)
from reconcile.hosted.firestore_cas import (
    FirestoreCasCollection,
    FirestoreCasConflict,
    FirestoreCasDocument,
    FirestoreCasSnapshot,
    firestore_cas_document_key,
)
from reconcile.hosted.firestore_scenarios import FirestoreScenarioStore
from reconcile.hosted.provider import (
    HOSTED_CANDIDATE_IDENTITY_VERSION,
    HostedCandidateIdentity,
)
from reconcile.hosted.workflow import (
    HOSTED_INVESTIGATION_RESULT_VERSION,
    HOSTED_OPERATION_RECEIPT_VERSION,
    HOSTED_SCENARIO_PREPARATION_VERSION,
    HostedInvestigationResult,
    HostedOperationReceipt,
    HostedOperationScope,
    HostedScenarioPreparation,
    HostedScenarioWorkflow,
    HostedWorkflowOperation,
)
from reconcile.interfaces import cli as cli_module
from reconcile.interfaces.api import create_app
from reconcile.interfaces.cli import StructuredOutput
from reconcile.interfaces.operator_api_client import OperatorApiClient
from reconcile.interfaces.tui import ReconcileApp
from reconcile.operator import OperatorApplicationService, sanitize_report
from reconcile.persistence import (
    CleanupStatus,
    ScenarioInvestigationState,
    ScenarioMutationState,
)
from reconcile.scenarios.service import (
    ScenarioName,
    _envelope_summary,
    scenario_investigation_id,
)
from tests.contract._factories import NOW, make_envelope, make_report

pytestmark = pytest.mark.integration

CANDIDATE = HostedCandidateIdentity(
    schema_version=HOSTED_CANDIDATE_IDENTITY_VERSION,
    source_revision="a" * 40,
    image_digest=f"sha256:{'b' * 64}",
    infrastructure_revision="c" * 64,
    semantic_config_sha256="1" * 64,
    project_id="reconcile-dev-260813-14fa6d",
    vertex_location="us",
    configured_model="gemini-3.5-flash",
    prompt_version="hosted-acquisition-v1",
    prompt_sha256="d" * 64,
    maximum_input_tokens=12_000,
    maximum_output_tokens=1_024,
    thinking_level="MINIMAL",
    maximum_count_tokens_attempts=1,
    maximum_generation_attempts=1,
)


class _MemoryCasStore:
    def __init__(self) -> None:
        self._clock = 0
        self.documents: dict[
            tuple[FirestoreCasCollection, str], FirestoreCasSnapshot
        ] = {}
        self.writes: list[FirestoreCasDocument] = []

    def _snapshot(self, document: FirestoreCasDocument) -> FirestoreCasSnapshot:
        self._clock += 1
        return FirestoreCasSnapshot(
            collection=document.kind,
            document_key=firestore_cas_document_key(
                document.kind,
                document.logical_id,
            ),
            document=document,
            update_time=datetime(2026, 8, 18, tzinfo=UTC)
            + timedelta(microseconds=self._clock),
        )

    async def read(
        self,
        collection: FirestoreCasCollection,
        logical_id: str,
    ) -> FirestoreCasSnapshot | None:
        return self.documents.get((collection, logical_id))

    async def create_pair(
        self,
        first: FirestoreCasDocument,
        second: FirestoreCasDocument,
    ) -> tuple[FirestoreCasSnapshot, FirestoreCasSnapshot]:
        keys = (
            (first.kind, first.logical_id),
            (second.kind, second.logical_id),
        )
        if any(key in self.documents for key in keys):
            raise FirestoreCasConflict
        snapshots = (self._snapshot(first), self._snapshot(second))
        self.documents[keys[0]] = snapshots[0]
        self.documents[keys[1]] = snapshots[1]
        self.writes.extend((first, second))
        return snapshots

    async def update(
        self,
        current: FirestoreCasSnapshot,
        replacement: FirestoreCasDocument,
    ) -> FirestoreCasSnapshot:
        key = (replacement.kind, replacement.logical_id)
        stored = self.documents.get(key)
        if (
            stored is None
            or stored.update_time != current.update_time
            or replacement.revision != stored.document.revision + 1
        ):
            raise FirestoreCasConflict
        snapshot = self._snapshot(replacement)
        self.documents[key] = snapshot
        self.writes.append(replacement)
        return snapshot


class _Preparer:
    def __init__(self) -> None:
        self.calls: list[str] = []
        self.preparations: dict[str, HostedScenarioPreparation] = {}

    def __call__(
        self,
        request,
        *,
        invoked_at: datetime,
    ) -> HostedScenarioPreparation:
        self.calls.append(request.investigation_id)
        payload = make_envelope().model_dump(mode="python")
        payload["investigation_id"] = request.investigation_id
        payload["operation_id"] = request.operation_id
        payload["invoked_at"] = invoked_at
        payload["context"]["invocation"]["invocation_id"] = request.invocation_id
        payload["context"]["invocation"]["function_call_id"] = request.function_call_id
        envelope = ExecutionEnvelope.model_validate(payload)
        preparation = HostedScenarioPreparation(
            schema_version=HOSTED_SCENARIO_PREPARATION_VERSION,
            namespace_id=f"namespace-{request.run_id}",
            execution_envelope=envelope,
            cleanup_resource_ids=(f"sandbox:{request.run_id}",),
        )
        self.preparations[request.investigation_id] = preparation
        return preparation


class _Gateway:
    def __init__(
        self,
        cas_store: _MemoryCasStore,
        *,
        mutation_behavior: str = "success",
    ) -> None:
        self._cas_store = cas_store
        self._mutation_behavior = mutation_behavior
        self.calls: list[HostedWorkflowOperation] = []
        self.pre_dispatch_payloads: list[dict[str, object]] = []
        self.mutation_entered = asyncio.Event()
        self.release_mutation = asyncio.Event()
        self.mutation_cancelled = False
        self.investigation_entered = asyncio.Event()
        self.release_investigation = asyncio.Event()
        self.investigation_cancelled = False

    @staticmethod
    def _receipt(
        scope: HostedOperationScope,
        *,
        started_at: datetime,
        completed_at: datetime,
        scope_sha256: str | None = None,
    ) -> HostedOperationReceipt:
        return HostedOperationReceipt(
            schema_version=HOSTED_OPERATION_RECEIPT_VERSION,
            operation=scope.operation,
            scope_sha256=scope.sha256 if scope_sha256 is None else scope_sha256,
            started_at=started_at,
            completed_at=completed_at,
        )

    async def execute_fault(
        self,
        scope: HostedOperationScope,
    ) -> HostedOperationReceipt:
        self.calls.append(HostedWorkflowOperation.EXECUTE_FAULT)
        snapshot = self._cas_store.documents[
            (FirestoreCasCollection.SCENARIO, scope.launch_id)
        ]
        payload = json.loads(snapshot.document.canonical_payload)
        self.pre_dispatch_payloads.append(payload)
        assert payload["candidate"] == CANDIDATE.model_dump(mode="json")
        assert payload["prepared_envelope"] is not None
        assert payload["work"]["mutation_state"] == "STARTED"
        assert payload["work"]["prepared_envelope_sha256"] == scope.envelope_sha256
        assert (
            payload["work"]["cleanup_manifest_sha256"] == scope.cleanup_manifest_sha256
        )
        self.mutation_entered.set()
        if self._mutation_behavior == "block":
            try:
                await self.release_mutation.wait()
            except asyncio.CancelledError:
                self.mutation_cancelled = True
                raise
        elif self._mutation_behavior == "dependency-denied":
            raise RuntimeError("dependency denied")
        elif self._mutation_behavior == "wrong-scope":
            return self._receipt(
                scope,
                started_at=NOW + timedelta(seconds=1),
                completed_at=NOW + timedelta(seconds=2),
                scope_sha256="f" * 64,
            )
        elif self._mutation_behavior == "forbidden":
            raise AssertionError("mutation dispatch was forbidden")
        return self._receipt(
            scope,
            started_at=NOW + timedelta(seconds=1),
            completed_at=NOW + timedelta(seconds=2),
        )

    async def investigate(
        self,
        scope: HostedOperationScope,
    ) -> HostedInvestigationResult:
        self.calls.append(HostedWorkflowOperation.INVESTIGATE)
        self.investigation_entered.set()
        if self._mutation_behavior == "block-investigation":
            try:
                await self.release_investigation.wait()
            except asyncio.CancelledError:
                self.investigation_cancelled = True
                raise
        if self._mutation_behavior == "forbidden":
            raise AssertionError("investigation dispatch was forbidden")
        payload = make_report(Classification.COMMITTED).model_dump(mode="python")
        payload["investigation_id"] = scope.investigation_id
        payload["envelope_sha256"] = scope.envelope_sha256
        report = InvestigationReport.model_validate(payload)
        return HostedInvestigationResult(
            schema_version=HOSTED_INVESTIGATION_RESULT_VERSION,
            scope_sha256=scope.sha256,
            report=report,
        )

    async def cleanup(
        self,
        scope: HostedOperationScope,
    ) -> HostedOperationReceipt:
        self.calls.append(HostedWorkflowOperation.CLEANUP)
        if self._mutation_behavior == "forbidden":
            raise AssertionError("cleanup dispatch was forbidden")
        return self._receipt(
            scope,
            started_at=NOW + timedelta(seconds=6),
            completed_at=NOW + timedelta(seconds=7),
        )


def _launch(launch_id: str) -> ScenarioLaunchRequest:
    return ScenarioLaunchRequest(
        schema_version=SCENARIO_LAUNCH_REQUEST_VERSION,
        launch_id=launch_id,
        scenario=ScenarioLaunchName.STORAGE,
        mode=ScenarioRunMode.FIXED,
    )


def _stack(
    cas_store: _MemoryCasStore,
    preparer: _Preparer,
    gateway: _Gateway,
) -> tuple[
    FirestoreScenarioStore,
    HostedScenarioWorkflow,
    OperatorApplicationService,
]:
    store = FirestoreScenarioStore(cas_store, CANDIDATE)
    workflow = HostedScenarioWorkflow(
        store,
        preparer,
        gateway,
        semantic_config_sha256="1" * 64,
        runtime_provenance_sha256="2" * 64,
        provider_available=False,
        clock=lambda: NOW,
    )
    operator = OperatorApplicationService(
        runner=workflow,
        projection_store=store,
        clock=lambda: NOW,
    )
    return store, workflow, operator


async def _bind_only(
    workflow: HostedScenarioWorkflow,
    launch: ScenarioLaunchRequest,
):
    investigation_id = scenario_investigation_id(
        ScenarioName.STORAGE,
        launch.launch_id,
    )
    accepted_event = ScenarioRunEvent(
        schema_version=SCENARIO_RUN_EVENT_VERSION,
        investigation_id=investigation_id,
        cursor=1,
        type=ScenarioRunEventType.LIFECYCLE,
        occurred_at=NOW,
        payload=ScenarioLifecycleEventPayload(lifecycle=ScenarioRunLifecycle.ACCEPTED),
    )
    snapshot = ScenarioRunSnapshot(
        schema_version=SCENARIO_RUN_SNAPSHOT_VERSION,
        launch_id=launch.launch_id,
        investigation_id=investigation_id,
        scenario=launch.scenario,
        mode=launch.mode,
        lifecycle=ScenarioRunLifecycle.ACCEPTED,
        event_cursor=1,
        envelope_summary=None,
        report=None,
        comparison=None,
        failure_category=None,
        accepted_at=NOW,
        updated_at=NOW,
    )
    created = await workflow.bind_launch(
        launch,
        snapshot=snapshot,
        accepted_event=accepted_event,
    )
    assert created.created is True
    return created.work


async def _append_running(
    store: FirestoreScenarioStore,
    investigation_id: str,
) -> None:
    work = await store.get_work(investigation_id)
    occurred_at = NOW + timedelta(milliseconds=10)
    event = ScenarioRunEvent(
        schema_version=SCENARIO_RUN_EVENT_VERSION,
        investigation_id=investigation_id,
        cursor=2,
        type=ScenarioRunEventType.LIFECYCLE,
        occurred_at=occurred_at,
        payload=ScenarioLifecycleEventPayload(lifecycle=ScenarioRunLifecycle.RUNNING),
    )
    snapshot = work.snapshot.model_copy(
        update={
            "lifecycle": ScenarioRunLifecycle.RUNNING,
            "event_cursor": 2,
            "updated_at": occurred_at,
        }
    )
    await store.append_projection(snapshot, event, terminal=False)


async def _append_envelope(
    store: FirestoreScenarioStore,
    investigation_id: str,
) -> None:
    work = await store.get_work(investigation_id)
    assert work.scenario_result is not None
    assert work.scenario_result.execution_envelope is not None
    occurred_at = NOW + timedelta(milliseconds=50)
    summary = _envelope_summary(work.scenario_result.execution_envelope)
    event = ScenarioRunEvent(
        schema_version=SCENARIO_RUN_EVENT_VERSION,
        investigation_id=investigation_id,
        cursor=3,
        type=ScenarioRunEventType.ENVELOPE_SUMMARY,
        occurred_at=occurred_at,
        payload=EnvelopeSummaryEventPayload(summary=summary),
    )
    snapshot = work.snapshot.model_copy(
        update={
            "event_cursor": 3,
            "envelope_summary": summary,
            "updated_at": occurred_at,
        }
    )
    await store.append_projection(snapshot, event, terminal=False)


async def _seed_mutation_started(
    store: FirestoreScenarioStore,
    workflow: HostedScenarioWorkflow,
    preparer: _Preparer,
    launch: ScenarioLaunchRequest,
):
    work = await _bind_only(workflow, launch)
    await _append_running(store, work.scenario_request.investigation_id)
    token = await store.acquire_scenario_lease(
        work.scenario_request.investigation_id,
        "seed-owner",
        now=NOW,
    )
    preparation = preparer(
        work.scenario_request,
        invoked_at=work.invoked_at,
    )
    started = await store.record_mutation_started(
        token,
        prepared_envelope=preparation.execution_envelope,
        prepared_envelope_sha256=preparation.envelope_sha256,
        cleanup_manifest_sha256=preparation.cleanup_manifest_sha256,
        occurred_at=NOW + timedelta(milliseconds=20),
    )
    return token, preparation, started


async def _seed_investigation_started(
    store: FirestoreScenarioStore,
    workflow: HostedScenarioWorkflow,
    preparer: _Preparer,
    launch: ScenarioLaunchRequest,
):
    token, preparation, started = await _seed_mutation_started(
        store,
        workflow,
        preparer,
        launch,
    )
    scope = workflow._scope(
        started,
        token,
        HostedWorkflowOperation.EXECUTE_FAULT,
    )
    receipt = _Gateway._receipt(
        scope,
        started_at=NOW + timedelta(milliseconds=30),
        completed_at=NOW + timedelta(milliseconds=40),
    )
    result = workflow._mutation_result(started, preparation, receipt)
    recorded = await store.record_mutation_result(
        token,
        result,
        prepared_envelope_bytes=preparation.envelope_bytes,
        occurred_at=receipt.completed_at,
    )
    await _append_envelope(store, recorded.scenario_request.investigation_id)
    started_investigation = await store.mark_investigation_started(
        token,
        occurred_at=NOW + timedelta(milliseconds=60),
    )
    return token, started_investigation


def _report_for(work) -> InvestigationReport:
    assert work.envelope_sha256 is not None
    payload = make_report(Classification.COMMITTED).model_dump(mode="python")
    payload["investigation_id"] = work.scenario_request.investigation_id
    payload["envelope_sha256"] = work.envelope_sha256
    return InvestigationReport.model_validate(payload)


def _assert_no_operator_tasks(
    operator: OperatorApplicationService,
    investigation_id: str,
) -> None:
    state = operator._by_investigation_id[investigation_id]
    assert state.task is None
    assert state.task_exit_notifier is None
    owned_names = {
        f"reconcile-scenario-{investigation_id}",
        f"reconcile-hosted-heartbeat-{investigation_id}",
    }
    assert not any(task.get_name() in owned_names for task in asyncio.all_tasks())


def test_compare_is_rejected_before_work_or_mutation_authority_exists() -> None:
    async def scenario() -> None:
        cas_store = _MemoryCasStore()
        preparer = _Preparer()
        gateway = _Gateway(cas_store, mutation_behavior="forbidden")
        _, workflow, operator = _stack(cas_store, preparer, gateway)
        launch = _launch("hosted-compare-denied").model_copy(
            update={"mode": ScenarioRunMode.COMPARE}
        )

        with pytest.raises(ValueError, match="comparison"):
            await _bind_only(workflow, launch)

        assert cas_store.documents == {}
        assert cas_store.writes == []
        assert preparer.calls == []
        assert gateway.calls == []
        await operator.aclose()

    asyncio.run(scenario())


def test_success_is_ordered_durable_and_exact_replay_never_redispatches() -> None:
    async def check() -> None:
        cas_store = _MemoryCasStore()
        preparer = _Preparer()
        gateway = _Gateway(cas_store)
        store, _, operator = _stack(cas_store, preparer, gateway)
        launch = _launch("hosted-success")
        investigation_id = scenario_investigation_id(
            ScenarioName.STORAGE,
            launch.launch_id,
        )

        terminal = await operator.launch_and_wait(launch)

        assert terminal.lifecycle is ScenarioRunLifecycle.COMPLETED
        assert terminal.report is not None
        assert terminal.report.classification is Classification.COMMITTED
        assert gateway.calls == [
            HostedWorkflowOperation.EXECUTE_FAULT,
            HostedWorkflowOperation.INVESTIGATE,
            HostedWorkflowOperation.CLEANUP,
        ]
        assert len(gateway.pre_dispatch_payloads) == 1
        work = await FirestoreScenarioStore(cas_store, CANDIDATE).get_work(
            investigation_id
        )
        assert work.mutation_state is ScenarioMutationState.RECORDED
        assert work.investigation_state is ScenarioInvestigationState.RECORDED
        assert work.cleanup_status is CleanupStatus.SUCCEEDED
        assert work.workflow_result is not None
        assert terminal.report == sanitize_report(work.workflow_result)
        projection = await store.snapshot_projection(investigation_id)
        assert projection.snapshot == terminal
        assert projection.terminal is True
        _assert_no_operator_tasks(operator, investigation_id)

        read_gateway = _Gateway(cas_store, mutation_behavior="forbidden")
        _, _, read_operator = _stack(
            cas_store,
            _Preparer(),
            read_gateway,
        )
        assert await read_operator.get(investigation_id) == terminal
        read_events = await read_operator.snapshot(investigation_id)
        assert read_events.events == projection.events
        assert read_events.terminal is True
        assert (
            await read_operator.get_operational_status(investigation_id)
        ).investigation_id == investigation_id
        assert read_gateway.calls == []
        _assert_no_operator_tasks(read_operator, investigation_id)

        replay_preparer = _Preparer()
        replay_gateway = _Gateway(cas_store, mutation_behavior="forbidden")
        replay_store, _, replay_operator = _stack(
            cas_store,
            replay_preparer,
            replay_gateway,
        )
        replay = await replay_operator.launch_and_wait(launch)

        assert replay == terminal
        assert replay_preparer.calls == []
        assert replay_gateway.calls == []
        assert (
            await replay_store.snapshot_projection(investigation_id)
        ).snapshot == terminal
        _assert_no_operator_tasks(replay_operator, investigation_id)
        await operator.aclose()
        await read_operator.aclose()
        await replay_operator.aclose()

    asyncio.run(check())


def test_fresh_remote_api_cli_and_tui_share_the_durable_terminal_report(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def check() -> None:
        cas_store = _MemoryCasStore()
        seed_store, _, seed_operator = _stack(
            cas_store,
            _Preparer(),
            _Gateway(cas_store),
        )
        launch = _launch("hosted-remote-projection")
        terminal = await seed_operator.launch_and_wait(launch)
        investigation_id = terminal.investigation_id
        work = await seed_store.get_work(investigation_id)
        assert work.workflow_result is not None
        expected_report = sanitize_report(work.workflow_result)

        remote_gateway = _Gateway(cas_store, mutation_behavior="forbidden")
        _, _, remote_operator = _stack(
            cas_store,
            _Preparer(),
            remote_gateway,
        )
        application = create_app(
            operator_service=remote_operator,
            hosted=True,
        )

        def remote_client(*_args: object, **_kwargs: object) -> OperatorApiClient:
            return OperatorApiClient(
                transport=httpx.ASGITransport(app=application),
            )

        direct_client = remote_client()
        direct = await direct_client.get_snapshot(investigation_id)
        await direct_client.aclose()

        monkeypatch.setattr(cli_module, "OperatorApiClient", remote_client)
        cli_snapshot, _ = await cli_module._remote_scenario_watch(
            api_url="http://127.0.0.1:8000",
            investigation_id=investigation_id,
            after=0,
            output=StructuredOutput.JSON,
        )

        tui = ReconcileApp(client=remote_client())
        async with tui.run_test(size=(120, 40)) as pilot:
            tui.query_one("#investigation-id", Input).value = investigation_id
            await pilot.click("#attach-button")
            await tui.workers.wait_for_complete()
            await pilot.pause()
            tui_snapshot = tui.operator_view_state.snapshot

        assert direct.report == expected_report
        assert cli_snapshot.report == expected_report
        assert tui_snapshot is not None
        assert tui_snapshot.report == expected_report
        assert direct == cli_snapshot == tui_snapshot == terminal
        assert remote_gateway.calls == []
        _assert_no_operator_tasks(remote_operator, investigation_id)
        await seed_operator.aclose()
        await remote_operator.aclose()

    asyncio.run(check())


def test_started_mutation_restart_escalates_without_any_remote_call() -> None:
    async def check() -> None:
        cas_store = _MemoryCasStore()
        seed_preparer = _Preparer()
        seed_gateway = _Gateway(cas_store)
        seed_store, seed_workflow, _ = _stack(
            cas_store,
            seed_preparer,
            seed_gateway,
        )
        launch = _launch("hosted-mutation-restart")
        token, _, started = await _seed_mutation_started(
            seed_store,
            seed_workflow,
            seed_preparer,
            launch,
        )
        await seed_store.release_scenario_lease(
            token,
            now=NOW + timedelta(milliseconds=30),
        )

        gateway = _Gateway(cas_store, mutation_behavior="forbidden")
        store, _, operator = _stack(cas_store, _Preparer(), gateway)
        terminal = await operator.launch_and_wait(launch)

        assert terminal.lifecycle is ScenarioRunLifecycle.FAILED
        assert terminal.failure_category is (
            ScenarioRunFailureCategory.SCENARIO_EXECUTION_FAILED
        )
        assert gateway.calls == []
        work = await store.get_work(started.scenario_request.investigation_id)
        assert work.mutation_state is ScenarioMutationState.STARTED
        assert work.investigation_state is (
            ScenarioInvestigationState.ESCALATION_REQUIRED
        )
        assert work.recovery_failure_code == "mutation-outcome-unknown"
        _assert_no_operator_tasks(operator, work.scenario_request.investigation_id)
        await operator.aclose()

    asyncio.run(check())


def test_started_investigation_restart_only_investigates_then_cleans_up() -> None:
    async def check() -> None:
        cas_store = _MemoryCasStore()
        seed_preparer = _Preparer()
        seed_gateway = _Gateway(cas_store)
        seed_store, seed_workflow, _ = _stack(
            cas_store,
            seed_preparer,
            seed_gateway,
        )
        launch = _launch("hosted-investigation-restart")
        token, started = await _seed_investigation_started(
            seed_store,
            seed_workflow,
            seed_preparer,
            launch,
        )
        await seed_store.release_scenario_lease(
            token,
            now=NOW + timedelta(milliseconds=70),
        )

        preparer = _Preparer()
        gateway = _Gateway(cas_store)
        store, _, operator = _stack(cas_store, preparer, gateway)
        terminal = await operator.launch_and_wait(launch)

        assert terminal.lifecycle is ScenarioRunLifecycle.COMPLETED
        assert terminal.report is not None
        assert terminal.report.classification is Classification.COMMITTED
        assert preparer.calls == []
        assert gateway.calls == [
            HostedWorkflowOperation.INVESTIGATE,
            HostedWorkflowOperation.CLEANUP,
        ]
        work = await store.get_work(started.scenario_request.investigation_id)
        assert work.mutation_state is ScenarioMutationState.RECORDED
        assert work.investigation_state is ScenarioInvestigationState.RECORDED
        assert work.cleanup_status is CleanupStatus.SUCCEEDED
        _assert_no_operator_tasks(operator, work.scenario_request.investigation_id)
        await operator.aclose()

    asyncio.run(check())


def test_pending_cleanup_restart_marks_failed_without_losing_report() -> None:
    async def check() -> None:
        cas_store = _MemoryCasStore()
        seed_preparer = _Preparer()
        seed_gateway = _Gateway(cas_store)
        seed_store, seed_workflow, _ = _stack(
            cas_store,
            seed_preparer,
            seed_gateway,
        )
        launch = _launch("hosted-cleanup-restart")
        token, started = await _seed_investigation_started(
            seed_store,
            seed_workflow,
            seed_preparer,
            launch,
        )
        report = _report_for(started)
        recorded = await seed_store.record_workflow_result(
            token,
            report,
            occurred_at=report.updated_at,
        )
        await seed_store.record_scenario_cleanup(
            token,
            CleanupStatus.PENDING,
            occurred_at=NOW + timedelta(seconds=6),
        )
        await seed_store.release_scenario_lease(
            token,
            now=NOW + timedelta(seconds=7),
        )

        gateway = _Gateway(cas_store, mutation_behavior="forbidden")
        store, _, operator = _stack(cas_store, _Preparer(), gateway)
        terminal = await operator.launch_and_wait(launch)

        assert terminal.lifecycle is ScenarioRunLifecycle.COMPLETED
        assert terminal.report is not None
        assert terminal.report.classification is Classification.COMMITTED
        assert gateway.calls == []
        work = await store.get_work(recorded.scenario_request.investigation_id)
        assert work.cleanup_status is CleanupStatus.FAILED
        assert work.cleanup_failure_code == "cleanup-outcome-unknown"
        assert work.workflow_result == report
        assert work.workflow_result.classification is Classification.COMMITTED
        _assert_no_operator_tasks(operator, work.scenario_request.investigation_id)
        await operator.aclose()

    asyncio.run(check())


@pytest.mark.parametrize("mutation_behavior", ["wrong-scope", "dependency-denied"])
def test_mutation_boundary_failure_escalates_and_leaves_no_owned_task(
    mutation_behavior: str,
) -> None:
    async def check() -> None:
        cas_store = _MemoryCasStore()
        gateway = _Gateway(cas_store, mutation_behavior=mutation_behavior)
        store, _, operator = _stack(cas_store, _Preparer(), gateway)
        launch = _launch(f"hosted-{mutation_behavior}")
        investigation_id = scenario_investigation_id(
            ScenarioName.STORAGE,
            launch.launch_id,
        )

        terminal = await operator.launch_and_wait(launch)

        assert terminal.lifecycle is ScenarioRunLifecycle.FAILED
        assert terminal.failure_category is (
            ScenarioRunFailureCategory.SCENARIO_EXECUTION_FAILED
        )
        assert gateway.calls == [HostedWorkflowOperation.EXECUTE_FAULT]
        work = await store.get_work(investigation_id)
        assert work.mutation_state is ScenarioMutationState.STARTED
        assert work.investigation_state is (
            ScenarioInvestigationState.ESCALATION_REQUIRED
        )
        assert work.recovery_failure_code is not None
        assert work.cleanup_status is CleanupStatus.NOT_REQUESTED
        _assert_no_operator_tasks(operator, investigation_id)
        await operator.aclose()

    asyncio.run(check())


def test_cancellation_releases_authority_and_restart_escalates_without_dispatch() -> (
    None
):
    async def check() -> None:
        cas_store = _MemoryCasStore()
        gateway = _Gateway(cas_store, mutation_behavior="block")
        store, _, operator = _stack(cas_store, _Preparer(), gateway)
        launch = _launch("hosted-cancelled")
        investigation_id = scenario_investigation_id(
            ScenarioName.STORAGE,
            launch.launch_id,
        )
        pending = asyncio.create_task(operator.launch_and_wait(launch))
        await gateway.mutation_entered.wait()

        pending.cancel()
        with pytest.raises(asyncio.CancelledError):
            await pending

        assert gateway.mutation_cancelled is True
        work = await store.get_work(investigation_id)
        assert work.mutation_state is ScenarioMutationState.STARTED
        assert work.investigation_state is (
            ScenarioInvestigationState.ESCALATION_REQUIRED
        )
        assert work.recovery_failure_code == "mutation-outcome-unknown"
        probe_token = await store.acquire_scenario_lease(
            investigation_id,
            "release-probe",
            now=NOW,
        )
        await store.release_scenario_lease(probe_token, now=NOW)
        _assert_no_operator_tasks(operator, investigation_id)

        restart_gateway = _Gateway(cas_store, mutation_behavior="forbidden")
        restart_store, _, restart_operator = _stack(
            cas_store,
            _Preparer(),
            restart_gateway,
        )
        terminal = await restart_operator.launch_and_wait(launch)
        assert terminal.lifecycle is ScenarioRunLifecycle.FAILED
        assert restart_gateway.calls == []
        restarted = await restart_store.get_work(investigation_id)
        assert restarted.investigation_state is (
            ScenarioInvestigationState.ESCALATION_REQUIRED
        )
        _assert_no_operator_tasks(restart_operator, investigation_id)
        await operator.aclose()
        await restart_operator.aclose()

    asyncio.run(check())


def test_investigation_cancellation_resumes_only_the_read_only_call() -> None:
    async def check() -> None:
        cas_store = _MemoryCasStore()
        gateway = _Gateway(cas_store, mutation_behavior="block-investigation")
        store, _, operator = _stack(cas_store, _Preparer(), gateway)
        launch = _launch("hosted-investigation-cancelled")
        investigation_id = scenario_investigation_id(
            ScenarioName.STORAGE,
            launch.launch_id,
        )
        pending = asyncio.create_task(operator.launch_and_wait(launch))
        await gateway.investigation_entered.wait()

        pending.cancel()
        with pytest.raises(asyncio.CancelledError):
            await pending

        assert gateway.investigation_cancelled is True
        assert gateway.calls == [
            HostedWorkflowOperation.EXECUTE_FAULT,
            HostedWorkflowOperation.INVESTIGATE,
        ]
        work = await store.get_work(investigation_id)
        assert work.mutation_state is ScenarioMutationState.RECORDED
        assert work.investigation_state is ScenarioInvestigationState.STARTED
        assert work.recovery_failure_code is None
        probe_token = await store.acquire_scenario_lease(
            investigation_id,
            "investigation-release-probe",
            now=NOW,
        )
        await store.release_scenario_lease(probe_token, now=NOW)
        _assert_no_operator_tasks(operator, investigation_id)

        restart_gateway = _Gateway(cas_store)
        restart_store, _, restart_operator = _stack(
            cas_store,
            _Preparer(),
            restart_gateway,
        )
        terminal = await restart_operator.launch_and_wait(launch)

        assert terminal.lifecycle is ScenarioRunLifecycle.COMPLETED
        assert terminal.report is not None
        assert terminal.report.classification is Classification.COMMITTED
        assert restart_gateway.calls == [
            HostedWorkflowOperation.INVESTIGATE,
            HostedWorkflowOperation.CLEANUP,
        ]
        restarted = await restart_store.get_work(investigation_id)
        assert restarted.investigation_state is ScenarioInvestigationState.RECORDED
        assert restarted.cleanup_status is CleanupStatus.SUCCEEDED
        _assert_no_operator_tasks(restart_operator, investigation_id)
        await operator.aclose()
        await restart_operator.aclose()

    asyncio.run(check())
