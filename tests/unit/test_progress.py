import asyncio
from datetime import UTC, datetime

import pytest

from reconcile.contracts import ComparisonStrategyKind
from reconcile.progress import (
    ProgressDispatcher,
    StrategyProgress,
    StrategyProgressStage,
)

pytestmark = pytest.mark.unit


def _started_progress() -> StrategyProgress:
    return StrategyProgress(
        occurred_at=datetime(2026, 8, 14, 12, 0, tzinfo=UTC),
        investigation_id="investigation-progress-1",
        strategy=ComparisonStrategyKind.FIXED,
        stage=StrategyProgressStage.STARTED,
    )


def test_dispatcher_cancellation_joins_a_blocked_delivery_worker() -> None:
    async def scenario() -> None:
        callback_started = asyncio.Event()
        callback_release = asyncio.Event()

        async def blocked_callback(_event) -> None:
            callback_started.set()
            await callback_release.wait()

        dispatcher = ProgressDispatcher(blocked_callback)
        dispatcher.emit(_started_progress())
        await callback_started.wait()

        finishing = asyncio.create_task(dispatcher.finish())
        await asyncio.sleep(0)
        finishing.cancel()
        with pytest.raises(asyncio.CancelledError):
            await finishing

        assert all(
            task.get_name() != "reconcile-progress-dispatch"
            for task in asyncio.all_tasks()
            if task is not asyncio.current_task()
        )

    asyncio.run(scenario())


def test_dispatcher_abort_never_waits_for_or_surfaces_callback_failure() -> None:
    async def scenario() -> None:
        callback_started = asyncio.Event()

        async def blocked_callback(_event) -> None:
            callback_started.set()
            await asyncio.Event().wait()

        dispatcher = ProgressDispatcher(blocked_callback)
        dispatcher.emit(_started_progress())
        await callback_started.wait()
        await asyncio.wait_for(dispatcher.abort(), timeout=0.2)

    asyncio.run(scenario())
