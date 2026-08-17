from __future__ import annotations

import asyncio
import hashlib
from pathlib import Path

import pytest

import reconcile.adaptive as adaptive_module
import reconcile.scenarios.service as service_module
from reconcile.adaptive import (
    AdvisoryPlannerMetadata,
    AdvisoryPlannerTurn,
    PlannerFailureKind,
)
from reconcile.adk_planner import VertexAdcPlannerConfig
from reconcile.contracts import (
    ADAPTIVE_PLANNER_INPUT_VERSION,
    ADAPTIVE_PLANNER_OUTPUT_VERSION,
    AdaptivePlannerInput,
    Classification,
    RequestedAction,
    ScenarioHybridOutcome,
    ScenarioHybridRoute,
    canonical_json_bytes,
)
from reconcile.scenarios.sandbox_order import (
    SANDBOX_ORDER_FIXED_PROBE_PLAN,
    SandboxOrderScenarioDefinition,
)
from reconcile.scenarios.service import (
    BOUNDED_HYBRID_ADVISORY_PROVENANCE,
    BOUNDED_HYBRID_EXPLICIT_UNKNOWN_PROVENANCE,
    BOUNDED_HYBRID_FALLBACK_PROVENANCE,
    BOUNDED_HYBRID_FIXED_PROVENANCE,
    BOUNDED_HYBRID_PROVIDER_CLEANUP_PROVENANCE,
    BOUNDED_HYBRID_ROUTE_POLICY_VERSION,
    ScenarioMode,
    ScenarioName,
    ScenarioWorkflowError,
    ScenarioWorkflowErrorCategory,
    bounded_hybrid_route_for,
    bounded_hybrid_route_provenance,
    is_bounded_hybrid_explicit_unknown,
    is_bounded_hybrid_fixed_fallback,
    mark_bounded_hybrid_fixed_fallback,
    run_one,
    run_suite,
)
from tests.integration.test_adaptive_scenarios import _ScriptedPlanner

pytestmark = pytest.mark.integration


def _metadata() -> AdvisoryPlannerMetadata:
    return AdvisoryPlannerMetadata(
        provider_name="scripted-local",
        configured_model="scripted-model-v1",
        reported_model="scripted-model-v1",
        adk_version="test-adk-v1",
        genai_version="test-genai-v1",
        prompt_version="test-prompt-v1",
        prompt_sha256="a" * 64,
        input_schema_version=ADAPTIVE_PLANNER_INPUT_VERSION,
        output_schema_version=ADAPTIVE_PLANNER_OUTPUT_VERSION,
    )


class _FailurePlanner:
    def __init__(self, failure: PlannerFailureKind) -> None:
        self._metadata = _metadata()
        self.failure = failure
        self.calls = 0
        self.closed = False

    @property
    def metadata(self) -> AdvisoryPlannerMetadata:
        return self._metadata

    async def plan(self, planner_input: AdaptivePlannerInput) -> AdvisoryPlannerTurn:
        self.calls += 1
        input_sha256 = hashlib.sha256(canonical_json_bytes(planner_input)).hexdigest()
        return AdvisoryPlannerTurn(
            output=None,
            failure=self.failure,
            metadata=self._metadata,
            input_sha256=input_sha256,
            output_sha256=None,
            usage=None,
        )

    async def aclose(self) -> None:
        self.closed = True


@pytest.mark.parametrize(
    ("scenario", "expected", "expected_probe"),
    (
        (
            ScenarioName.STORAGE,
            Classification.COMMITTED,
            ("storage-object-metadata-readback", "1.0.0"),
        ),
        (
            ScenarioName.FIRESTORE_BUSINESS,
            Classification.PARTIAL,
            ("business-operation-composite-readback", "1.0.0"),
        ),
    ),
)
def test_policy_direct_fixed_routes_never_construct_a_planner(
    tmp_path: Path,
    scenario: ScenarioName,
    expected: Classification,
    expected_probe: tuple[str, str],
) -> None:
    factory_calls: list[ScenarioName] = []

    def forbidden_factory(selected: ScenarioName):
        factory_calls.append(selected)
        raise AssertionError("the direct fixed route constructed a planner")

    report = asyncio.run(
        run_one(
            scenario,
            ScenarioMode.ADAPTIVE,
            planner_factory=forbidden_factory,
            workspace=tmp_path,
            run_id=f"direct-fixed-{scenario.value}",
        )
    )

    assert report.classification is expected
    assert factory_calls == []
    assert tuple(
        (audit.capability_name, audit.capability_version)
        for audit in report.probe_audit
    ) == (expected_probe,)
    assert not is_bounded_hybrid_fixed_fallback(report)
    assert BOUNDED_HYBRID_FIXED_PROVENANCE in report.limitations
    route = bounded_hybrid_route_provenance(report)
    assert route is not None
    assert route.route is ScenarioHybridRoute.FIXED_AUTHORITATIVE
    assert route.outcome is ScenarioHybridOutcome.FIXED_AUTHORITATIVE
    assert not route.planner_invoked
    assert list(tmp_path.iterdir()) == []


@pytest.mark.parametrize(
    "failure",
    (
        PlannerFailureKind.UNAVAILABLE,
        PlannerFailureKind.TIMEOUT,
        PlannerFailureKind.SCHEMA_INVALID,
    ),
)
def test_sandbox_sanitized_provider_failure_runs_fresh_fixed_investigation(
    tmp_path: Path,
    failure: PlannerFailureKind,
) -> None:
    planner = _FailurePlanner(failure)

    report = asyncio.run(
        run_one(
            ScenarioName.SANDBOX_ORDER,
            ScenarioMode.ADAPTIVE,
            planner=planner,
            workspace=tmp_path,
            run_id=f"sandbox-fallback-{failure.value}",
        )
    )

    assert report.classification is Classification.UNKNOWN
    assert len(report.probe_audit) == 2
    assert planner.calls == 1
    assert report.advisory_explanation is None
    gates = {gate.requested_action: gate for gate in report.action_gate}
    assert not gates[RequestedAction.CONTINUE].allowed
    assert not gates[RequestedAction.RETRY].allowed
    assert not gates[RequestedAction.COMPENSATE].allowed
    assert is_bounded_hybrid_fixed_fallback(report)
    assert report.limitations.count(BOUNDED_HYBRID_FALLBACK_PROVENANCE) == 1
    route = bounded_hybrid_route_provenance(report)
    assert route is not None
    assert route.outcome is ScenarioHybridOutcome.FIXED_FALLBACK
    assert route.planner_invoked
    assert list(tmp_path.iterdir()) == []


def test_sandbox_missing_or_failed_factory_uses_inspectable_fixed_fallback(
    tmp_path: Path,
) -> None:
    missing = asyncio.run(
        run_one(
            ScenarioName.SANDBOX_ORDER,
            ScenarioMode.ADAPTIVE,
            workspace=tmp_path,
            run_id="sandbox-missing-planner",
        )
    )
    factory_calls: list[ScenarioName] = []

    def failed_factory(scenario: ScenarioName):
        factory_calls.append(scenario)
        raise RuntimeError("private provider construction detail")

    failed = asyncio.run(
        run_one(
            ScenarioName.SANDBOX_ORDER,
            ScenarioMode.ADAPTIVE,
            planner_factory=failed_factory,
            workspace=tmp_path,
            run_id="sandbox-failed-factory",
        )
    )

    assert factory_calls == [ScenarioName.SANDBOX_ORDER]
    assert missing.classification is failed.classification is Classification.UNKNOWN
    assert is_bounded_hybrid_fixed_fallback(missing)
    assert is_bounded_hybrid_fixed_fallback(failed)
    assert canonical_json_bytes(mark_bounded_hybrid_fixed_fallback(failed)) == (
        canonical_json_bytes(failed)
    )
    assert list(tmp_path.iterdir()) == []


def test_sandbox_successful_planning_retains_bounded_advisory_provenance(
    tmp_path: Path,
) -> None:
    planner = _ScriptedPlanner(
        tuple(step.request for step in SANDBOX_ORDER_FIXED_PROBE_PLAN.steps)
    )

    report = asyncio.run(
        run_one(
            ScenarioName.SANDBOX_ORDER,
            ScenarioMode.ADAPTIVE,
            planner=planner,
            workspace=tmp_path,
            run_id="sandbox-advisory-route",
        )
    )

    assert planner.inputs
    assert BOUNDED_HYBRID_ADVISORY_PROVENANCE in report.limitations
    assert BOUNDED_HYBRID_FIXED_PROVENANCE not in report.limitations
    assert not is_bounded_hybrid_fixed_fallback(report)
    route = bounded_hybrid_route_provenance(report)
    assert route is not None
    assert route.outcome is ScenarioHybridOutcome.PLANNER_EVIDENCE
    assert route.planner_invoked
    assert not route.fixed_connector_invoked
    assert list(tmp_path.iterdir()) == []


def test_late_provider_failure_retains_unknown_without_replaying_fixed_reads(
    tmp_path: Path,
) -> None:
    first_request = SANDBOX_ORDER_FIXED_PROBE_PLAN.steps[0].request

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

    planner = LateFailurePlanner((first_request,))
    report = asyncio.run(
        run_one(
            ScenarioName.SANDBOX_ORDER,
            ScenarioMode.ADAPTIVE,
            planner=planner,
            workspace=tmp_path,
            run_id="sandbox-late-provider-failure",
        )
    )

    assert len(planner.inputs) == 2
    assert report.classification is Classification.UNKNOWN
    assert len(report.probe_audit) == 1
    assert is_bounded_hybrid_explicit_unknown(report)
    assert not is_bounded_hybrid_fixed_fallback(report)
    assert BOUNDED_HYBRID_EXPLICIT_UNKNOWN_PROVENANCE in report.limitations
    route = bounded_hybrid_route_provenance(report)
    assert route is not None
    assert route.outcome is ScenarioHybridOutcome.EXPLICIT_UNKNOWN
    assert route.planner_invoked
    assert not route.fixed_connector_invoked
    assert route.provider_failure
    assert list(tmp_path.iterdir()) == []


def test_provider_cleanup_failure_preserves_result_and_is_observable(
    tmp_path: Path,
) -> None:
    planners: list[_ScriptedPlanner] = []

    class CleanupFailurePlanner(_ScriptedPlanner):
        async def aclose(self) -> None:
            raise RuntimeError("private provider cleanup detail")

    def factory(_scenario: ScenarioName) -> _ScriptedPlanner:
        planner = CleanupFailurePlanner(
            tuple(step.request for step in SANDBOX_ORDER_FIXED_PROBE_PLAN.steps)
        )
        planners.append(planner)
        return planner

    report = asyncio.run(
        run_one(
            ScenarioName.SANDBOX_ORDER,
            ScenarioMode.ADAPTIVE,
            planner_factory=factory,
            workspace=tmp_path,
            run_id="sandbox-provider-cleanup-failure",
        )
    )

    assert len(planners) == 1
    assert len(planners[0].inputs) >= 1
    assert not is_bounded_hybrid_fixed_fallback(report)
    assert BOUNDED_HYBRID_PROVIDER_CLEANUP_PROVENANCE in report.limitations
    route = bounded_hybrid_route_provenance(report)
    assert route is not None
    assert route.outcome is ScenarioHybridOutcome.PLANNER_EVIDENCE
    assert route.provider_cleanup_failure
    assert list(tmp_path.iterdir()) == []


def test_provider_cleanup_attribute_failure_is_sanitized_and_observable(
    tmp_path: Path,
) -> None:
    class CleanupAttributeFailurePlanner(_ScriptedPlanner):
        @property
        def aclose(self):
            raise RuntimeError("private provider cleanup descriptor detail")

    report = asyncio.run(
        run_one(
            ScenarioName.SANDBOX_ORDER,
            ScenarioMode.ADAPTIVE,
            planner_factory=lambda _scenario: CleanupAttributeFailurePlanner(
                tuple(step.request for step in SANDBOX_ORDER_FIXED_PROBE_PLAN.steps)
            ),
            workspace=tmp_path,
            run_id="sandbox-provider-cleanup-attribute-failure",
        )
    )

    route = bounded_hybrid_route_provenance(report)
    assert route is not None
    assert route.outcome is ScenarioHybridOutcome.PLANNER_EVIDENCE
    assert route.provider_cleanup_failure
    assert list(tmp_path.iterdir()) == []


def test_local_fallback_carries_adaptive_elapsed_budget(tmp_path: Path) -> None:
    class SlowFailurePlanner(_FailurePlanner):
        async def plan(
            self,
            planner_input: AdaptivePlannerInput,
        ) -> AdvisoryPlannerTurn:
            await asyncio.sleep(0.05)
            return await super().plan(planner_input)

    report = asyncio.run(
        run_one(
            ScenarioName.SANDBOX_ORDER,
            ScenarioMode.ADAPTIVE,
            planner=SlowFailurePlanner(PlannerFailureKind.UNAVAILABLE),
            workspace=tmp_path,
            run_id="sandbox-fallback-elapsed-budget",
        )
    )

    assert is_bounded_hybrid_fixed_fallback(report)
    assert report.probe_audit[0].session_elapsed_ms >= 40
    assert report.probe_audit[-1].session_elapsed_ms <= 5_000
    assert list(tmp_path.iterdir()) == []


def test_trusted_planner_input_failure_is_not_masked_as_provider_fallback(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    planner = _FailurePlanner(PlannerFailureKind.UNAVAILABLE)

    def fail_input(**_kwargs):
        raise ValueError("private trusted input construction detail")

    monkeypatch.setattr(adaptive_module, "_planner_input", fail_input)

    with pytest.raises(ScenarioWorkflowError) as captured:
        asyncio.run(
            run_one(
                ScenarioName.SANDBOX_ORDER,
                ScenarioMode.ADAPTIVE,
                planner=planner,
                workspace=tmp_path,
                run_id="sandbox-trusted-input-failure",
            )
        )

    assert captured.value.category is (
        ScenarioWorkflowErrorCategory.SCENARIO_EXECUTION_FAILED
    )
    assert planner.calls == 0
    assert list(tmp_path.iterdir()) == []


def test_vertex_construction_failure_falls_back_only_for_adaptive(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = VertexAdcPlannerConfig(
        project="test-project",
        location="us-central1",
        model="gemini-test",
    )
    construction_calls = 0

    def fail_construction(_config: VertexAdcPlannerConfig):
        nonlocal construction_calls
        construction_calls += 1
        raise RuntimeError("private provider construction detail")

    monkeypatch.setattr(
        service_module.AdkGeminiPlanner,
        "from_vertex_adc",
        fail_construction,
    )

    adaptive = asyncio.run(
        run_one(
            ScenarioName.SANDBOX_ORDER,
            ScenarioMode.ADAPTIVE,
            vertex_config=config,
            workspace=tmp_path,
            run_id="adaptive-provider-construction",
        )
    )
    with pytest.raises(ScenarioWorkflowError) as captured:
        asyncio.run(
            run_one(
                ScenarioName.SANDBOX_ORDER,
                ScenarioMode.COMPARE,
                vertex_config=config,
                workspace=tmp_path,
                run_id="compare-provider-construction",
            )
        )

    assert adaptive.classification is Classification.UNKNOWN
    assert is_bounded_hybrid_fixed_fallback(adaptive)
    assert construction_calls == 2
    assert captured.value.category is ScenarioWorkflowErrorCategory.PROVIDER_FAILED
    assert list(tmp_path.iterdir()) == []


def test_adaptive_suite_constructs_and_calls_a_planner_only_for_sandbox(
    tmp_path: Path,
) -> None:
    factory_calls: list[ScenarioName] = []
    planners: list[_FailurePlanner] = []

    def factory(scenario: ScenarioName) -> _FailurePlanner:
        factory_calls.append(scenario)
        planner = _FailurePlanner(PlannerFailureKind.UNAVAILABLE)
        planners.append(planner)
        return planner

    reports = asyncio.run(
        run_suite(
            ScenarioMode.ADAPTIVE,
            planner_factory=factory,
            workspace=tmp_path,
            run_id="bounded-hybrid-suite",
        )
    )

    assert tuple(report.classification for report in reports) == (
        Classification.COMMITTED,
        Classification.PARTIAL,
        Classification.UNKNOWN,
    )
    assert factory_calls == [ScenarioName.SANDBOX_ORDER]
    assert len(planners) == 1
    assert planners[0].calls == 1
    assert planners[0].closed
    assert tuple(is_bounded_hybrid_fixed_fallback(report) for report in reports) == (
        False,
        False,
        True,
    )
    assert list(tmp_path.iterdir()) == []


def test_internal_adaptive_exception_is_not_relabelled_as_provider_fallback(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def fail_adaptive(*args, **kwargs):
        del args, kwargs
        raise RuntimeError("private controller failure detail")

    monkeypatch.setattr(SandboxOrderScenarioDefinition, "adaptive", fail_adaptive)
    planner = _FailurePlanner(PlannerFailureKind.UNAVAILABLE)

    with pytest.raises(ScenarioWorkflowError) as captured:
        asyncio.run(
            run_one(
                ScenarioName.SANDBOX_ORDER,
                ScenarioMode.ADAPTIVE,
                planner=planner,
                workspace=tmp_path,
                run_id="controller-error-not-fallback",
            )
        )

    assert captured.value.category is (
        ScenarioWorkflowErrorCategory.SCENARIO_EXECUTION_FAILED
    )
    assert planner.calls == 0
    assert list(tmp_path.iterdir()) == []


def test_cleanup_attribute_failure_cannot_replace_controller_failure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def fail_adaptive(*args, **kwargs):
        del args, kwargs
        raise RuntimeError("private controller failure detail")

    class CleanupAttributeFailurePlanner(_FailurePlanner):
        @property
        def aclose(self):
            raise RuntimeError("private provider cleanup descriptor detail")

    monkeypatch.setattr(SandboxOrderScenarioDefinition, "adaptive", fail_adaptive)

    with pytest.raises(ScenarioWorkflowError) as captured:
        asyncio.run(
            run_one(
                ScenarioName.SANDBOX_ORDER,
                ScenarioMode.ADAPTIVE,
                planner_factory=lambda _scenario: CleanupAttributeFailurePlanner(
                    PlannerFailureKind.UNAVAILABLE
                ),
                workspace=tmp_path,
                run_id="controller-error-survives-cleanup-attribute-failure",
            )
        )

    assert captured.value.category is (
        ScenarioWorkflowErrorCategory.SCENARIO_EXECUTION_FAILED
    )
    assert list(tmp_path.iterdir()) == []


def test_route_policy_is_versioned_and_compare_stays_strict(tmp_path: Path) -> None:
    assert BOUNDED_HYBRID_ROUTE_POLICY_VERSION == "1.0.0"
    assert bounded_hybrid_route_for(ScenarioName.STORAGE) is (
        ScenarioHybridRoute.FIXED_AUTHORITATIVE
    )
    assert bounded_hybrid_route_for(ScenarioName.FIRESTORE_BUSINESS) is (
        ScenarioHybridRoute.FIXED_AUTHORITATIVE
    )
    assert bounded_hybrid_route_for(ScenarioName.SANDBOX_ORDER) is (
        ScenarioHybridRoute.PLANNER_HETEROGENEOUS
    )

    with pytest.raises(ScenarioWorkflowError) as captured:
        asyncio.run(
            run_one(
                ScenarioName.SANDBOX_ORDER,
                ScenarioMode.COMPARE,
                workspace=tmp_path,
                run_id="compare-requires-provider",
            )
        )

    assert (
        captured.value.category is ScenarioWorkflowErrorCategory.INVALID_CONFIGURATION
    )
    assert list(tmp_path.iterdir()) == []
