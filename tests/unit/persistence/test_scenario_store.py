from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import pytest

from reconcile.durable_scenarios import DurableScenarioWorkflow
from reconcile.persistence import ScenarioStore, SqliteScenarioStore

_SCENARIO_STORE_METHODS = (
    "acquire_scenario_lease",
    "append_projection",
    "create_work",
    "get_lane_result",
    "get_work",
    "list_work",
    "mark_investigation_started",
    "record_lane_result",
    "record_mutation_result",
    "record_mutation_started",
    "record_scenario_cleanup",
    "record_workflow_result",
    "release_scenario_lease",
    "renew_scenario_lease",
    "require_scenario_escalation",
    "snapshot_projection",
)


@pytest.mark.unit
def test_durable_workflow_accepts_a_structural_scenario_store(
    tmp_path: Path,
) -> None:
    workspace_root = tmp_path / "workspaces"
    workspace_root.mkdir(mode=0o700)
    sqlite_store = SqliteScenarioStore(tmp_path / "scenario.sqlite3")
    structural_store = SimpleNamespace(
        **{name: getattr(sqlite_store, name) for name in _SCENARIO_STORE_METHODS}
    )

    assert isinstance(structural_store, ScenarioStore)
    assert not isinstance(structural_store, SqliteScenarioStore)

    DurableScenarioWorkflow(
        structural_store,
        workspace_root,
        semantic_config_sha256="0" * 64,
    )


@pytest.mark.unit
def test_durable_workflow_rejects_an_incomplete_scenario_store(
    tmp_path: Path,
) -> None:
    workspace_root = tmp_path / "workspaces"
    workspace_root.mkdir(mode=0o700)
    incomplete_store = SimpleNamespace()

    assert not isinstance(incomplete_store, ScenarioStore)
    with pytest.raises(TypeError, match="requires a scenario store"):
        DurableScenarioWorkflow(
            incomplete_store,
            workspace_root,
            semantic_config_sha256="0" * 64,
        )
