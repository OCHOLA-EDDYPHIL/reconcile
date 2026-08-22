import asyncio
import threading

import pytest

import reconcile.scenarios.service as scenario_service
from reconcile.contracts import (
    Classification,
    ScenarioCleanupDisposition,
    ScenarioCleanupResult,
)
from reconcile.progress import ProgressDeliveryError
from reconcile.scenarios.runner import ScenarioRunner
from reconcile.scenarios.service import (
    ScenarioMode,
    ScenarioName,
    ScenarioWorkflowError,
    ScenarioWorkflowErrorCategory,
    run_one,
)

pytestmark = pytest.mark.integration

_EVENT_TIMEOUT_SECONDS = 30.0
_RUN_TIMEOUT_SECONDS = 30.0


async def _wait_for_thread_event(event: threading.Event) -> None:
    observed = await asyncio.wait_for(
        asyncio.to_thread(event.wait, _EVENT_TIMEOUT_SECONDS),
        timeout=_EVENT_TIMEOUT_SECONDS + 1,
    )
    assert observed


async def _next_loop_turn() -> None:
    reached = asyncio.Event()
    asyncio.get_running_loop().call_soon(reached.set)
    await asyncio.wait_for(reached.wait(), timeout=_EVENT_TIMEOUT_SECONDS)


def test_synchronous_runner_does_not_block_the_asyncio_loop(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path,
) -> None:
    original_run = ScenarioRunner.run
    runner_entered = threading.Event()
    runner_release = threading.Event()

    def blocked_run(self, request, definition):
        runner_entered.set()
        if not runner_release.wait(_EVENT_TIMEOUT_SECONDS):
            raise AssertionError("scenario runner was not released")
        return original_run(self, request, definition)

    monkeypatch.setattr(ScenarioRunner, "run", blocked_run)

    async def exercise() -> None:
        task = asyncio.create_task(
            run_one(
                ScenarioName.STORAGE,
                ScenarioMode.FIXED,
                workspace=tmp_path,
                run_id="responsive-runner",
            )
        )
        try:
            await _wait_for_thread_event(runner_entered)

            loop_remained_responsive = asyncio.Event()
            asyncio.get_running_loop().call_soon(loop_remained_responsive.set)
            await asyncio.wait_for(
                loop_remained_responsive.wait(),
                timeout=_EVENT_TIMEOUT_SECONDS,
            )
            assert not task.done()

            runner_release.set()
            report = await asyncio.wait_for(task, timeout=_RUN_TIMEOUT_SECONDS)
            assert report.classification is Classification.COMMITTED
        finally:
            runner_release.set()
            if not task.done():
                await asyncio.gather(task, return_exceptions=True)

    asyncio.run(exercise())


def test_cancellation_joins_owned_runner_before_workspace_cleanup(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path,
) -> None:
    original_run = ScenarioRunner.run
    runner_entered = threading.Event()
    runner_release = threading.Event()

    def blocked_run(self, request, definition):
        runner_entered.set()
        if not runner_release.wait(_EVENT_TIMEOUT_SECONDS):
            raise AssertionError("scenario runner was not released")
        return original_run(self, request, definition)

    monkeypatch.setattr(ScenarioRunner, "run", blocked_run)

    async def exercise() -> None:
        task = asyncio.create_task(
            run_one(
                ScenarioName.STORAGE,
                ScenarioMode.FIXED,
                workspace=tmp_path,
                run_id="cancelled-owned-runner",
            )
        )
        try:
            await _wait_for_thread_event(runner_entered)
            assert any(tmp_path.iterdir())

            task.cancel()
            await _next_loop_turn()

            assert not task.done()
            assert any(tmp_path.iterdir())

            runner_release.set()
            with pytest.raises(asyncio.CancelledError):
                await asyncio.wait_for(task, timeout=_RUN_TIMEOUT_SECONDS)

            assert not any(tmp_path.iterdir())
        finally:
            runner_release.set()
            if not task.done():
                await asyncio.gather(task, return_exceptions=True)

    asyncio.run(exercise())


def test_repeated_cancellation_still_joins_runner_before_workspace_cleanup(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path,
) -> None:
    original_run = ScenarioRunner.run
    runner_entered = threading.Event()
    runner_release = threading.Event()

    def blocked_run(self, request, definition):
        runner_entered.set()
        if not runner_release.wait(_EVENT_TIMEOUT_SECONDS):
            raise AssertionError("scenario runner was not released")
        return original_run(self, request, definition)

    monkeypatch.setattr(ScenarioRunner, "run", blocked_run)

    async def exercise() -> None:
        task = asyncio.create_task(
            run_one(
                ScenarioName.STORAGE,
                ScenarioMode.FIXED,
                workspace=tmp_path,
                run_id="repeatedly-cancelled-owned-runner",
            )
        )
        try:
            await _wait_for_thread_event(runner_entered)
            assert any(tmp_path.iterdir())

            task.cancel()
            await _next_loop_turn()
            task.cancel()
            await _next_loop_turn()

            assert not task.done()
            assert any(tmp_path.iterdir())

            runner_release.set()
            with pytest.raises(asyncio.CancelledError):
                await asyncio.wait_for(task, timeout=_RUN_TIMEOUT_SECONDS)

            assert not any(tmp_path.iterdir())
        finally:
            runner_release.set()
            if not task.done():
                await asyncio.gather(task, return_exceptions=True)

    asyncio.run(exercise())


@pytest.mark.parametrize("cleanup_failure", ["exception", "failed-result"])
def test_cancellation_during_cleanup_cannot_mask_cleanup_failure(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path,
    cleanup_failure: str,
) -> None:
    original_cleanup = ScenarioRunner.cleanup
    cleanup_entered = threading.Event()
    cleanup_release = threading.Event()

    def blocked_failed_cleanup(self, request, definition):
        cleanup_entered.set()
        if not cleanup_release.wait(_EVENT_TIMEOUT_SECONDS):
            raise AssertionError("cleanup was not released")
        if cleanup_failure == "exception":
            raise RuntimeError("cleanup failed after cancellation")
        result = original_cleanup(self, request, definition)
        payload = result.model_dump(mode="python")
        payload.update(
            {
                "disposition": ScenarioCleanupDisposition.FAILED,
                "remaining_count": 1,
                "failure_code": "cleanup_verification_failed",
            }
        )
        return ScenarioCleanupResult.model_validate(payload)

    monkeypatch.setattr(ScenarioRunner, "cleanup", blocked_failed_cleanup)

    async def exercise() -> None:
        task = asyncio.create_task(
            run_one(
                ScenarioName.STORAGE,
                ScenarioMode.FIXED,
                workspace=tmp_path,
                run_id=f"cancelled-{cleanup_failure}-cleanup",
            )
        )
        try:
            await _wait_for_thread_event(cleanup_entered)
            task.cancel()
            await _next_loop_turn()
            assert not task.done()

            cleanup_release.set()
            with pytest.raises(ScenarioWorkflowError) as captured:
                await asyncio.wait_for(task, timeout=_RUN_TIMEOUT_SECONDS)

            assert captured.value.category is (
                ScenarioWorkflowErrorCategory.CLEANUP_FAILED
            )
            assert not any(tmp_path.iterdir())
        finally:
            cleanup_release.set()
            if not task.done():
                await asyncio.gather(task, return_exceptions=True)

    asyncio.run(exercise())


def test_progress_failure_surfaces_after_deterministic_work_and_cleanup(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path,
) -> None:
    original_fixed_investigation = scenario_service._fixed_investigation
    callback_failed = asyncio.Event()
    deterministic_work_completed = asyncio.Event()
    lifecycle: list[str] = []

    async def fixed_after_callback_failure(*args, **kwargs):
        await asyncio.wait_for(
            callback_failed.wait(),
            timeout=_EVENT_TIMEOUT_SECONDS,
        )
        result = await original_fixed_investigation(*args, **kwargs)
        lifecycle.append("deterministic-work-completed")
        deterministic_work_completed.set()
        return result

    monkeypatch.setattr(
        scenario_service,
        "_fixed_investigation",
        fixed_after_callback_failure,
    )

    async def failing_callback(_event) -> None:
        lifecycle.append("callback-failed")
        callback_failed.set()
        raise RuntimeError("progress consumer rejected the event")

    async def exercise() -> None:
        with pytest.raises(ProgressDeliveryError):
            await asyncio.wait_for(
                run_one(
                    ScenarioName.STORAGE,
                    ScenarioMode.FIXED,
                    workspace=tmp_path,
                    run_id="failed-progress-delivery",
                    progress_callback=failing_callback,
                ),
                timeout=_RUN_TIMEOUT_SECONDS,
            )
        lifecycle.append("failure-surfaced")

        assert deterministic_work_completed.is_set()
        assert lifecycle == [
            "callback-failed",
            "deterministic-work-completed",
            "failure-surfaced",
        ]
        assert not any(tmp_path.iterdir())

    asyncio.run(exercise())
