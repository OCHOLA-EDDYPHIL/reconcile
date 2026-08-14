import asyncio

import pytest

from reconcile.contracts import (
    SCENARIO_LAUNCH_REQUEST_VERSION,
    Classification,
    ScenarioLaunchName,
    ScenarioLaunchRequest,
    ScenarioRunEventType,
    ScenarioRunLifecycle,
)
from reconcile.operator import OperatorApplicationService

pytestmark = pytest.mark.integration


@pytest.mark.parametrize(
    ("scenario", "classification"),
    (
        (ScenarioLaunchName.STORAGE, Classification.COMMITTED),
        (ScenarioLaunchName.FIRESTORE_BUSINESS, Classification.PARTIAL),
        (ScenarioLaunchName.SANDBOX_ORDER, Classification.UNKNOWN),
    ),
)
def test_fixed_operator_run_reaches_the_canonical_terminal_state(
    scenario: ScenarioLaunchName,
    classification: Classification,
) -> None:
    async def run() -> None:
        service = OperatorApplicationService()
        try:
            launched = await service.launch(
                ScenarioLaunchRequest(
                    schema_version=SCENARIO_LAUNCH_REQUEST_VERSION,
                    launch_id=f"operator-{scenario.value}",
                    scenario=scenario,
                )
            )
            cursor = 0
            observed = []
            while True:
                suffix = await service.wait_for_events(
                    launched.snapshot.investigation_id,
                    after=cursor,
                )
                observed.extend(suffix.events)
                cursor = suffix.cursor
                if suffix.terminal:
                    break

            snapshot = await service.get(launched.snapshot.investigation_id)
            summary = await service.get_envelope_summary(snapshot.investigation_id)

            assert snapshot.lifecycle is ScenarioRunLifecycle.COMPLETED
            assert snapshot.failure_category is None
            assert snapshot.report is not None
            assert snapshot.report.classification is classification
            assert snapshot.report.investigation_id == snapshot.investigation_id
            assert summary == snapshot.envelope_summary
            assert snapshot.event_cursor == len(observed) == cursor
            assert observed[0].type is ScenarioRunEventType.LIFECYCLE
            assert observed[-1].type is ScenarioRunEventType.TERMINAL
            assert any(
                event.type is ScenarioRunEventType.PROBE_REQUEST for event in observed
            )
            assert any(
                event.type is ScenarioRunEventType.EVIDENCE_DECISION
                for event in observed
            )
        finally:
            await service.aclose()

    asyncio.run(run())
