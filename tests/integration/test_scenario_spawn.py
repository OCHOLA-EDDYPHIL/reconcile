"""Process-start safety for the canonical local scenario mutations."""

from __future__ import annotations

import threading
import warnings
from datetime import UTC, datetime
from pathlib import Path

import pytest

from reconcile.contracts import (
    SCENARIO_RUN_REQUEST_VERSION,
    ScenarioCallerObservation,
    ScenarioCleanupDisposition,
    ScenarioFaultAction,
    ScenarioFaultInstruction,
    ScenarioFaultPoint,
    ScenarioRunRequest,
    ScenarioWorkerTermination,
)
from reconcile.scenarios.firestore_business import (
    FIRESTORE_BUSINESS_SCENARIO,
    FirestoreBusinessScenarioDefinition,
)
from reconcile.scenarios.local_order import HiddenOrderOutcome, LocalOrderHarness
from reconcile.scenarios.runner import ScenarioDefinition, ScenarioRunner
from reconcile.scenarios.sandbox_order import (
    SANDBOX_ORDER_ITEM_CODE,
    SANDBOX_ORDER_QUANTITY,
    SANDBOX_ORDER_SCENARIO,
    SandboxOrderScenarioDefinition,
)
from reconcile.scenarios.storage import STORAGE_SCENARIO, StorageScenarioDefinition
from tests._clocks import ConstantClock

pytestmark = pytest.mark.integration

NOW = datetime(2026, 8, 14, 12, 0, tzinfo=UTC)


def _canonical_scenario(
    name: str,
    root: Path,
) -> tuple[ScenarioRunRequest, ScenarioDefinition]:
    if name == "storage":
        scenario = STORAGE_SCENARIO
        seed = 39
        definition: ScenarioDefinition = StorageScenarioDefinition(
            root / "storage.sqlite3",
            invoked_at=NOW,
            target_clock=ConstantClock(NOW),
        )
    elif name == "firestore-business":
        scenario = FIRESTORE_BUSINESS_SCENARIO
        seed = 0b011
        definition = FirestoreBusinessScenarioDefinition(
            root / "firestore.sqlite3",
            invoked_at=NOW,
            target_clock=ConstantClock(NOW),
        )
    else:
        scenario = SANDBOX_ORDER_SCENARIO
        seed = 41
        private_path = root / "sandbox-private.sqlite3"
        observation_path = root / "sandbox-observations.sqlite3"
        LocalOrderHarness(
            private_path,
            observation_path,
            clock=ConstantClock(NOW),
        ).seed_duplicate_looking_order(
            item_code=SANDBOX_ORDER_ITEM_CODE,
            quantity=SANDBOX_ORDER_QUANTITY,
        )
        definition = SandboxOrderScenarioDefinition(
            private_path,
            observation_path,
            hidden_outcome=HiddenOrderOutcome.COMMIT,
            invoked_at=NOW,
            target_clock=ConstantClock(NOW),
        )

    request = ScenarioRunRequest(
        schema_version=SCENARIO_RUN_REQUEST_VERSION,
        scenario=scenario,
        run_id=f"run-spawn-{name}",
        investigation_id=f"investigation-spawn-{name}",
        operation_id=f"operation-spawn-{name}",
        invocation_id=f"invocation-spawn-{name}",
        function_call_id=f"function-call-spawn-{name}",
        seed=seed,
        fault=ScenarioFaultInstruction(
            point=ScenarioFaultPoint.POST_COMMIT,
            action=ScenarioFaultAction.INTERRUPT_PROCESS,
        ),
    )
    return request, definition


@pytest.mark.parametrize(
    "scenario_name",
    ("storage", "firestore-business", "sandbox-order"),
)
def test_canonical_worker_start_is_safe_with_a_live_background_thread(
    tmp_path: Path,
    scenario_name: str,
) -> None:
    request, definition = _canonical_scenario(scenario_name, tmp_path)
    runner = ScenarioRunner()
    started = threading.Event()
    release = threading.Event()

    def hold_background_thread() -> None:
        started.set()
        release.wait()

    thread = threading.Thread(target=hold_background_thread, daemon=True)
    thread.start()
    assert started.wait(timeout=1.0)
    try:
        with warnings.catch_warnings(record=True) as captured:
            warnings.simplefilter("always", DeprecationWarning)
            result = runner.run(request, definition)
        cleanup = runner.cleanup(
            runner.build_cleanup_request(request, result),
            definition,
        )
        assert thread.is_alive()
    finally:
        release.set()
        thread.join(timeout=2.0)

    assert not thread.is_alive()
    assert not any(
        item.category is DeprecationWarning
        and "multi-threaded" in str(item.message)
        and "fork" in str(item.message)
        for item in captured
    )
    assert result.trace.worker_termination is ScenarioWorkerTermination.SIGNALED
    assert result.trace.caller_observation is ScenarioCallerObservation.NO_RESPONSE
    assert result.execution_envelope is not None
    assert cleanup.disposition is ScenarioCleanupDisposition.CLEANED
    assert cleanup.remaining_count == 0
