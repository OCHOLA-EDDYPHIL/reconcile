"""Authority checks for the durable operational-status projection."""

from __future__ import annotations

import asyncio
import json
import os
import sqlite3
from datetime import UTC, datetime
from pathlib import Path

import pytest

from reconcile.contracts import (
    SCENARIO_LAUNCH_REQUEST_VERSION,
    SCENARIO_RUN_EVENT_VERSION,
    SCENARIO_RUN_SNAPSHOT_VERSION,
    ScenarioLaunchName,
    ScenarioLaunchRequest,
    ScenarioLifecycleEventPayload,
    ScenarioOperationalCleanupState,
    ScenarioOperationalInvestigationState,
    ScenarioOperationalMutationState,
    ScenarioOperationalRecoveryState,
    ScenarioRunEvent,
    ScenarioRunEventType,
    ScenarioRunLifecycle,
    ScenarioRunMode,
    ScenarioRunSnapshot,
)
from reconcile.durable_scenarios import DurableScenarioWorkflow
from reconcile.operator import (
    OperatorApplicationService,
    OperatorServiceUnavailable,
    ScenarioRunNotFound,
)
from reconcile.persistence import SqliteScenarioStore
from reconcile.scenarios.service import ScenarioName, scenario_investigation_id

pytestmark = pytest.mark.integration


async def _bind(
    workflow: DurableScenarioWorkflow,
    *,
    launch_id: str,
) -> tuple[ScenarioLaunchRequest, str]:
    launch = ScenarioLaunchRequest(
        schema_version=SCENARIO_LAUNCH_REQUEST_VERSION,
        launch_id=launch_id,
        scenario=ScenarioLaunchName.STORAGE,
        mode=ScenarioRunMode.FIXED,
    )
    investigation_id = scenario_investigation_id(
        ScenarioName.STORAGE,
        launch_id,
    )
    accepted_at = datetime.now(UTC)
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
        scenario=launch.scenario,
        mode=launch.mode,
        lifecycle=ScenarioRunLifecycle.ACCEPTED,
        event_cursor=1,
        envelope_summary=None,
        report=None,
        comparison=None,
        failure_category=None,
        accepted_at=accepted_at,
        updated_at=accepted_at,
    )
    await workflow.bind_launch(
        launch,
        snapshot=snapshot,
        accepted_event=event,
    )
    return launch, investigation_id


def _environment(tmp_path: Path) -> tuple[Path, Path, SqliteScenarioStore]:
    os.chmod(tmp_path, 0o700)
    workspace_root = tmp_path / "workspaces"
    workspace_root.mkdir(mode=0o700)
    database = tmp_path / "parent.sqlite3"
    return database, workspace_root, SqliteScenarioStore(database)


def _replace_work_field(
    database: Path,
    investigation_id: str,
    field: str,
    value: object,
) -> None:
    with sqlite3.connect(database) as connection:
        row = connection.execute(
            "SELECT payload FROM scenario_work_items WHERE investigation_id = ?",
            (investigation_id,),
        ).fetchone()
        assert row is not None
        payload = json.loads(bytes(row[0]))
        payload[field] = value
        sealed = json.dumps(
            payload,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
        connection.execute(
            "UPDATE scenario_work_items SET payload = ? WHERE investigation_id = ?",
            (sealed, investigation_id),
        )


class _PassiveCoordinator:
    def __init__(self, workflow: DurableScenarioWorkflow) -> None:
        self.workflow = workflow
        self.override = None

    @property
    def provider_available(self) -> bool:
        return False

    async def bind_launch(self, launch, *, snapshot, accepted_event):
        return await self.workflow.bind_launch(
            launch,
            snapshot=snapshot,
            accepted_event=accepted_event,
        )

    async def audit_terminal_projection(self, investigation_id: str) -> None:
        await self.workflow.audit_terminal_projection(investigation_id)

    async def get_operational_status(self, investigation_id: str):
        if self.override is not None:
            return self.override
        return await self.workflow.get_operational_status(investigation_id)

    async def __call__(
        self,
        _scenario,
        _mode,
        *,
        vertex_config,
        run_id,
        progress_callback,
        cancellation_event,
    ):
        del vertex_config, run_id, progress_callback
        assert cancellation_event is not None
        await cancellation_event.wait()
        raise asyncio.CancelledError


def test_projection_reads_validated_authority_without_ownership_or_repair(
    tmp_path: Path,
) -> None:
    async def exercise() -> None:
        database, workspace_root, store = _environment(tmp_path)
        workflow = DurableScenarioWorkflow(
            store,
            workspace_root,
            semantic_config_sha256="a" * 64,
        )
        launch, investigation_id = await _bind(
            workflow,
            launch_id="read-only-status",
        )
        before = await store.get_work(investigation_id)
        workspace = workspace_root / before.workspace_id
        workspace.rmdir()

        status = await workflow.get_operational_status(investigation_id)
        after = await store.get_work(investigation_id)
        with sqlite3.connect(database) as connection:
            lease = connection.execute(
                "SELECT payload FROM scenario_leases WHERE investigation_id = ?",
                (investigation_id,),
            ).fetchone()

        assert status.launch_id == launch.launch_id
        assert status.investigation_id == investigation_id
        assert status.revision == before.revision
        assert status.mutation_state is ScenarioOperationalMutationState.NOT_STARTED
        assert (
            status.investigation_state
            is ScenarioOperationalInvestigationState.NOT_STARTED
        )
        assert status.cleanup_state is ScenarioOperationalCleanupState.NOT_REQUESTED
        assert status.recovery_state is ScenarioOperationalRecoveryState.NOT_ESCALATED
        assert after == before
        assert lease is None
        assert not workspace.exists()

    asyncio.run(exercise())


@pytest.mark.parametrize(
    ("field", "value"),
    (
        ("strategy_sha256", "1" * 64),
        ("semantic_config_sha256", "2" * 64),
        ("runtime_provenance_sha256", "3" * 64),
        ("workspace_id", "scenario-workspace-incompatible"),
    ),
)
def test_projection_rejects_dependency_or_workspace_drift(
    tmp_path: Path,
    field: str,
    value: str,
) -> None:
    async def exercise() -> None:
        database, workspace_root, store = _environment(tmp_path)
        workflow = DurableScenarioWorkflow(
            store,
            workspace_root,
            semantic_config_sha256="a" * 64,
        )
        _, investigation_id = await _bind(
            workflow,
            launch_id=f"drift-{field}",
        )
        _replace_work_field(database, investigation_id, field, value)

        with pytest.raises(ValueError, match="authority is incompatible"):
            await workflow.get_operational_status(investigation_id)

    asyncio.run(exercise())


def test_operator_delegates_only_to_durable_status_and_cross_checks_v1_identity(
    tmp_path: Path,
) -> None:
    async def exercise() -> None:
        _, workspace_root, store = _environment(tmp_path)
        workflow = DurableScenarioWorkflow(
            store,
            workspace_root,
            semantic_config_sha256="a" * 64,
        )
        _, investigation_id = await _bind(
            workflow,
            launch_id="identity-status",
        )
        coordinator = _PassiveCoordinator(workflow)
        service = OperatorApplicationService(
            runner=coordinator,
            projection_store=store,
        )
        await service.start()
        status = await service.get_operational_status(investigation_id)
        coordinator.override = status.model_copy(update={"launch_id": "other-launch"})

        with pytest.raises(OperatorServiceUnavailable):
            await service.get_operational_status(investigation_id)
        with pytest.raises(ScenarioRunNotFound):
            await service.get_operational_status("missing-investigation")
        await service.aclose()

    asyncio.run(exercise())


def test_operator_normalizes_durable_drift_and_corruption_as_unavailable(
    tmp_path: Path,
) -> None:
    async def exercise() -> None:
        database, workspace_root, store = _environment(tmp_path)
        workflow = DurableScenarioWorkflow(
            store,
            workspace_root,
            semantic_config_sha256="a" * 64,
        )
        _, investigation_id = await _bind(
            workflow,
            launch_id="unavailable-status",
        )
        coordinator = _PassiveCoordinator(workflow)
        service = OperatorApplicationService(
            runner=coordinator,
            projection_store=store,
        )
        await service.start()
        _replace_work_field(database, investigation_id, "strategy_sha256", "1" * 64)
        with pytest.raises(OperatorServiceUnavailable):
            await service.get_operational_status(investigation_id)
        await service.aclose()

        _, other_workspace_root, other_store = _environment(tmp_path / "corrupt")
        other_workflow = DurableScenarioWorkflow(
            other_store,
            other_workspace_root,
            semantic_config_sha256="a" * 64,
        )
        _, other_id = await _bind(
            other_workflow,
            launch_id="corrupt-status",
        )
        other_coordinator = _PassiveCoordinator(other_workflow)
        other_service = OperatorApplicationService(
            runner=other_coordinator,
            projection_store=other_store,
        )
        await other_service.start()
        with sqlite3.connect(tmp_path / "corrupt" / "parent.sqlite3") as connection:
            connection.execute(
                "UPDATE scenario_work_items SET payload = ? WHERE investigation_id = ?",
                (b"{}", other_id),
            )
        with pytest.raises(OperatorServiceUnavailable):
            await other_service.get_operational_status(other_id)
        await other_service.aclose()

    (tmp_path / "corrupt").mkdir(mode=0o700)
    asyncio.run(exercise())


def test_non_durable_operator_refuses_operational_status() -> None:
    async def passive_runner(
        _scenario,
        _mode,
        *,
        vertex_config,
        run_id,
        progress_callback,
        cancellation_event,
    ):
        del vertex_config, run_id, progress_callback
        assert cancellation_event is not None
        await cancellation_event.wait()
        raise asyncio.CancelledError

    async def exercise() -> None:
        service = OperatorApplicationService(runner=passive_runner)
        launch = ScenarioLaunchRequest(
            schema_version=SCENARIO_LAUNCH_REQUEST_VERSION,
            launch_id="volatile-status",
            scenario=ScenarioLaunchName.STORAGE,
            mode=ScenarioRunMode.FIXED,
        )
        created = await service.launch(launch)

        with pytest.raises(OperatorServiceUnavailable):
            await service.get_operational_status(created.snapshot.investigation_id)
        await service.aclose()

    asyncio.run(exercise())
