"""Real loopback API journeys through the API-only Textual surface."""

from __future__ import annotations

import asyncio

import httpx
import pytest
from textual.widgets import Input, Static

from reconcile.contracts import (
    SCENARIO_LAUNCH_REQUEST_VERSION,
    Classification,
    ScenarioLaunchName,
    ScenarioLaunchRequest,
    ScenarioRunLifecycle,
)
from reconcile.interfaces.api import create_app
from reconcile.interfaces.operator_api_client import OperatorApiClient
from reconcile.interfaces.tui import ReconcileApp
from reconcile.operator import OperatorApplicationService

pytestmark = pytest.mark.integration


def test_async_client_reaches_a_real_fixed_operator_run() -> None:
    async def journey() -> None:
        service = OperatorApplicationService()
        client = OperatorApiClient(
            transport=httpx.ASGITransport(
                app=create_app(operator_service=service),
            )
        )
        try:
            launched = await client.launch(
                ScenarioLaunchRequest(
                    schema_version=SCENARIO_LAUNCH_REQUEST_VERSION,
                    launch_id="operator-client-real-storage",
                    scenario=ScenarioLaunchName.STORAGE,
                )
            )
            events = tuple(
                [
                    event
                    async for event in client.events(
                        launched.snapshot.investigation_id,
                        max_reconnects=0,
                    )
                ]
            )
            snapshot = await client.get_snapshot(launched.snapshot.investigation_id)

            assert events
            assert snapshot.lifecycle is ScenarioRunLifecycle.COMPLETED
            assert snapshot.report is not None
            assert snapshot.report.classification is Classification.COMMITTED
        finally:
            await client.aclose()
            await service.aclose()

    asyncio.run(journey())


@pytest.mark.parametrize(
    ("scenario", "classification"),
    (
        (ScenarioLaunchName.STORAGE, Classification.COMMITTED),
        (ScenarioLaunchName.FIRESTORE_BUSINESS, Classification.PARTIAL),
        (ScenarioLaunchName.SANDBOX_ORDER, Classification.UNKNOWN),
    ),
)
def test_fixed_terminal_scenario_journey_uses_only_the_loopback_api(
    scenario: ScenarioLaunchName,
    classification: Classification,
) -> None:
    async def journey() -> None:
        service = OperatorApplicationService()
        launched = await service.launch(
            ScenarioLaunchRequest(
                schema_version=SCENARIO_LAUNCH_REQUEST_VERSION,
                launch_id=f"tui-fixed-{scenario.value}",
                scenario=scenario,
            )
        )
        cursor = 0
        while True:
            suffix = await service.wait_for_events(
                launched.snapshot.investigation_id,
                after=cursor,
            )
            cursor = suffix.cursor
            if suffix.terminal:
                break
        transport = httpx.ASGITransport(
            app=create_app(operator_service=service),
        )
        client = OperatorApiClient(transport=transport)
        app = ReconcileApp(client=client)
        try:
            async with app.run_test(size=(120, 40)) as pilot:
                app.query_one(
                    "#investigation-id", Input
                ).value = launched.snapshot.investigation_id

                await pilot.click("#attach-button")
                await app.workers.wait_for_complete()
                await pilot.pause()

                snapshot = app.operator_view_state.snapshot
                assert snapshot is not None
                assert snapshot.lifecycle is ScenarioRunLifecycle.COMPLETED
                assert snapshot.report is not None
                assert snapshot.report.classification is classification
                assert app.operator_view_state.timeline_complete is True
                deterministic = str(
                    app.query_one("#deterministic-panel", Static).content
                )
                assert classification.value in deterministic
                assert "Terminal snapshot confirmed by the API." == str(
                    app.query_one("#operator-message", Static).content
                )
        finally:
            await service.aclose()

    asyncio.run(journey())
