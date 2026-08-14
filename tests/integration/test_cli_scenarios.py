from __future__ import annotations

import asyncio
import hashlib
from pathlib import Path

import pytest

import reconcile.scenarios.service as service_module
from reconcile.adaptive import (
    AdvisoryPlannerMetadata,
    AdvisoryPlannerTurn,
    AdvisoryPlannerUsage,
)
from reconcile.contracts import (
    ADAPTIVE_PLANNER_INPUT_VERSION,
    ADAPTIVE_PLANNER_OUTPUT_VERSION,
    PROBE_REQUEST_VERSION,
    AdaptivePlannerInput,
    AdaptivePlannerOutput,
    AdaptivePlannerPhase,
    Classification,
    ComparisonModelUsageStatus,
    ComparisonStrategyKind,
    InvestigationComparisonRecord,
    InvestigationReport,
    PlannerAcquisitionAdvice,
    PlannerCitationRefs,
    PlannerExplanation,
    PlannerMissingEvidenceNote,
    PlannerStopAdvice,
    ProbeRequest,
    canonical_json_bytes,
)
from reconcile.scenarios.runner import ScenarioRunner
from reconcile.scenarios.service import (
    SCENARIO_SUITE,
    ScenarioMode,
    ScenarioName,
    ScenarioWorkflowError,
    ScenarioWorkflowErrorCategory,
    _adaptive_model_usage,
    run_one,
    run_suite,
)

pytestmark = pytest.mark.integration


class _ScriptedPlanner:
    def __init__(self, *, unsupported: bool = False) -> None:
        self._metadata = AdvisoryPlannerMetadata(
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
        self.input_bytes: list[bytes] = []
        self.closed = False
        self.unsupported = unsupported

    @property
    def metadata(self) -> AdvisoryPlannerMetadata:
        return self._metadata

    async def plan(
        self,
        planner_input: AdaptivePlannerInput,
    ) -> AdvisoryPlannerTurn:
        payload = canonical_json_bytes(planner_input)
        self.input_bytes.append(payload)
        proposals: tuple[ProbeRequest, ...] = ()
        if planner_input.phase is AdaptivePlannerPhase.ACQUIRE_EVIDENCE:
            capability = next(
                (
                    item
                    for item in planner_input.capabilities
                    if item.remaining_invocations > 0
                ),
                None,
            )
            if capability is not None:
                selected = ProbeRequest(
                    schema_version=PROBE_REQUEST_VERSION,
                    capability_name=capability.name,
                    capability_version=capability.version,
                    relevant_effect_ids=tuple(
                        item.effect_id
                        for item in planner_input.envelope.expected_effects
                    ),
                    arguments={},
                    rationale="Use the next bounded read-only capability.",
                )
                proposals = (selected,)
                if self.unsupported:
                    proposals = (
                        ProbeRequest(
                            schema_version=PROBE_REQUEST_VERSION,
                            capability_name="unsupported-read",
                            capability_version=capability.version,
                            relevant_effect_ids=selected.relevant_effect_ids,
                            arguments={},
                            rationale="This proposal must remain rejected.",
                        ),
                        selected,
                    )

        admitted_ids = tuple(
            item.evidence_id for item in planner_input.admitted_evidence
        )
        weak_ids = tuple(item.evidence_id for item in planner_input.weak_evidence)
        rejected_ids = tuple(
            item.evidence_id for item in planner_input.rejected_evidence
        )
        missing_ids = tuple(item.effect_id for item in planner_input.missing_evidence)
        output = AdaptivePlannerOutput(
            schema_version=ADAPTIVE_PLANNER_OUTPUT_VERSION,
            probe_proposals=proposals,
            acquisition_advice=PlannerAcquisitionAdvice(
                summary="Use only the next bounded proposal."
            ),
            stop_advice=PlannerStopAdvice(
                recommend_stop=True,
                reason="The controller retains stop authority.",
            ),
            missing_evidence_notes=(
                ()
                if not missing_ids
                else (
                    PlannerMissingEvidenceNote(
                        effect_ids=missing_ids,
                        note="Authoritative evidence remains missing.",
                    ),
                )
            ),
            explanation=PlannerExplanation(
                summary="The cited evidence categories remain distinct.",
                admitted_evidence=(
                    "Authoritative evidence was admitted." if admitted_ids else None
                ),
                weak_evidence=(
                    "Weak evidence remains non-authoritative." if weak_ids else None
                ),
                rejected_evidence=(
                    "Rejected evidence is not relied upon." if rejected_ids else None
                ),
                missing_evidence=(
                    "Declared effects still lack authoritative evidence."
                    if missing_ids
                    else None
                ),
                citations=PlannerCitationRefs(
                    admitted_evidence_ids=admitted_ids,
                    weak_evidence_ids=weak_ids,
                    rejected_evidence_ids=rejected_ids,
                    missing_effect_ids=missing_ids,
                ),
            ),
        )
        output_bytes = canonical_json_bytes(output)
        return AdvisoryPlannerTurn(
            output=output,
            failure=None,
            metadata=self._metadata,
            input_sha256=hashlib.sha256(payload).hexdigest(),
            output_sha256=hashlib.sha256(output_bytes).hexdigest(),
            usage=AdvisoryPlannerUsage(
                prompt_tokens=3,
                output_tokens=2,
                total_tokens=5,
            ),
        )

    async def aclose(self) -> None:
        self.closed = True


def test_run_one_defaults_to_credential_free_fixed_mode(
    tmp_path: Path,
    capfd: pytest.CaptureFixture[str],
) -> None:
    result = asyncio.run(
        run_one(
            ScenarioName.STORAGE,
            workspace=tmp_path,
            run_id="one-fixed-storage",
        )
    )

    assert type(result) is InvestigationReport
    assert result.classification is Classification.COMMITTED
    assert list(tmp_path.iterdir()) == []
    assert capfd.readouterr().err == ""


def test_fixed_suite_is_ordered_and_credential_free(tmp_path: Path) -> None:
    results = asyncio.run(
        run_suite(
            workspace=tmp_path,
            run_id="fixed-suite",
        )
    )

    assert SCENARIO_SUITE == (
        ScenarioName.STORAGE,
        ScenarioName.FIRESTORE_BUSINESS,
        ScenarioName.SANDBOX_ORDER,
    )
    assert all(type(result) is InvestigationReport for result in results)
    assert tuple(result.classification for result in results) == (
        Classification.COMMITTED,
        Classification.PARTIAL,
        Classification.UNKNOWN,
    )
    assert list(tmp_path.iterdir()) == []


def test_injected_adaptive_suite_uses_public_evidence_only(tmp_path: Path) -> None:
    planner = _ScriptedPlanner()

    results = asyncio.run(
        run_suite(
            ScenarioMode.ADAPTIVE,
            planner=planner,
            workspace=tmp_path,
            run_id="adaptive-suite",
        )
    )

    assert all(type(result) is InvestigationReport for result in results)
    assert tuple(result.classification for result in results) == (
        Classification.COMMITTED,
        Classification.PARTIAL,
        Classification.UNKNOWN,
    )
    assert planner.closed is False
    public_material = b"".join(
        [
            *(canonical_json_bytes(result) for result in results),
            *planner.input_bytes,
        ]
    )
    assert str(tmp_path).encode() not in public_material
    for forbidden in (
        b'"COMMIT"',
        b'"DISCARD"',
        b"hidden_outcome",
        b"owner_token",
        b"sandbox-private.sqlite3",
    ):
        assert forbidden not in public_material
    assert list(tmp_path.iterdir()) == []


def test_comparison_suite_uses_actual_metrics_and_closes_factory_planners(
    tmp_path: Path,
) -> None:
    planners: list[_ScriptedPlanner] = []

    def factory(_scenario: ScenarioName) -> _ScriptedPlanner:
        planner = _ScriptedPlanner()
        planners.append(planner)
        return planner

    results = asyncio.run(
        run_suite(
            ScenarioMode.COMPARE,
            planner_factory=factory,
            workspace=tmp_path,
            run_id="comparison-suite",
        )
    )

    assert all(type(result) is InvestigationComparisonRecord for result in results)
    assert tuple(result.scenario.name for result in results) == (
        "storage-object",
        "firestore-business-operation",
        "sandbox-order-unknown",
    )
    assert tuple(
        result.preregistered_expectation.expected_classification for result in results
    ) == (
        Classification.COMMITTED,
        Classification.PARTIAL,
        Classification.UNKNOWN,
    )
    for result in results:
        assert result.baseline.strategy_kind is ComparisonStrategyKind.FIXED
        assert result.adaptive is not None
        assert result.adaptive.strategy_kind is ComparisonStrategyKind.ADAPTIVE
        assert result.baseline.envelope_sha256 == result.envelope_sha256
        assert result.adaptive.envelope_sha256 == result.envelope_sha256
        assert result.baseline.matches_preregistered_expectation is True
        assert result.adaptive.matches_preregistered_expectation is True
        assert (
            result.baseline.model_usage.status
            is ComparisonModelUsageStatus.NOT_APPLICABLE
        )
        assert result.adaptive.model_usage.status is ComparisonModelUsageStatus.MEASURED
        assert result.adaptive.model_usage.model_call_count > 0
        assert result.adaptive.model_usage.total_token_count == (
            result.adaptive.model_usage.input_token_count
            + result.adaptive.model_usage.output_token_count
        )
        assert result.adaptive.executed_probe_count <= (
            result.adaptive.planned_probe_count
        )
    assert len(planners) == len(SCENARIO_SUITE)
    assert all(planner.closed for planner in planners)
    public_material = b"".join(canonical_json_bytes(result) for result in results)
    assert str(tmp_path).encode() not in public_material
    assert b"hidden_outcome" not in public_material
    assert b"owner_token" not in public_material
    planner_material = b"".join(
        payload for planner in planners for payload in planner.input_bytes
    )
    assert b"expected_classification" not in planner_material
    assert b"preregistered_expectation" not in planner_material
    assert list(tmp_path.iterdir()) == []


def test_adaptive_requires_one_explicit_provider_source(tmp_path: Path) -> None:
    with pytest.raises(ScenarioWorkflowError) as captured:
        asyncio.run(
            run_one(
                ScenarioName.STORAGE,
                ScenarioMode.ADAPTIVE,
                workspace=tmp_path,
                run_id="missing-provider",
            )
        )

    assert (
        captured.value.category is ScenarioWorkflowErrorCategory.INVALID_CONFIGURATION
    )
    assert str(tmp_path) not in str(captured.value)


def test_scenario_run_identifier_rejects_secret_signatures_before_setup(
    tmp_path: Path,
) -> None:
    with pytest.raises(ScenarioWorkflowError) as captured:
        asyncio.run(
            run_one(
                ScenarioName.STORAGE,
                ScenarioMode.FIXED,
                workspace=tmp_path,
                run_id="token:private-marker",
            )
        )

    assert (
        captured.value.category is ScenarioWorkflowErrorCategory.INVALID_CONFIGURATION
    )
    assert list(tmp_path.iterdir()) == []


def test_zero_call_adaptive_usage_is_never_fabricated() -> None:
    class _ZeroCallResult:
        model_invocation_count = 0

    with pytest.raises(ScenarioWorkflowError) as captured:
        _adaptive_model_usage(
            ScenarioName.STORAGE,
            _ZeroCallResult(),  # type: ignore[arg-type]
        )

    assert (
        captured.value.category
        is ScenarioWorkflowErrorCategory.COMPARISON_UNREPRESENTABLE
    )


def test_rejected_proposals_are_not_mislabeled_as_executed_probe_findings(
    tmp_path: Path,
) -> None:
    result = asyncio.run(
        run_one(
            ScenarioName.STORAGE,
            ScenarioMode.COMPARE,
            planner=_ScriptedPlanner(unsupported=True),
            workspace=tmp_path,
            run_id="unsupported-proposal-comparison",
        )
    )

    assert type(result) is InvestigationComparisonRecord
    assert result.adaptive is not None
    assert result.adaptive.planned_probe_count == 1
    assert result.adaptive.executed_probe_count == 1
    assert result.adaptive.unsupported_probe_count == 0
    assert result.adaptive.duplicate_probe_count == 0
    assert result.adaptive.model_usage.model_call_count > 0


def test_failed_manifest_cleanup_fails_the_workflow(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def fail_cleanup(*_args: object, **_kwargs: object) -> None:
        raise OSError("private cleanup detail")

    monkeypatch.setattr(ScenarioRunner, "cleanup", fail_cleanup)

    with pytest.raises(ScenarioWorkflowError) as captured:
        asyncio.run(
            run_one(
                ScenarioName.STORAGE,
                workspace=tmp_path,
                run_id="cleanup-failure",
            )
        )

    assert captured.value.category is ScenarioWorkflowErrorCategory.CLEANUP_FAILED
    assert "private cleanup detail" not in str(captured.value)
    assert list(tmp_path.iterdir()) == []


def test_run_failure_without_result_still_performs_manifest_cleanup(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    cleanup_calls = 0
    original_cleanup = ScenarioRunner.cleanup

    def fail_invocation(*_args: object, **_kwargs: object) -> None:
        raise RuntimeError("private run failure")

    def record_cleanup(*args: object, **kwargs: object):
        nonlocal cleanup_calls
        cleanup_calls += 1
        return original_cleanup(*args, **kwargs)

    monkeypatch.setattr(ScenarioRunner, "_invoke", fail_invocation)
    monkeypatch.setattr(ScenarioRunner, "cleanup", record_cleanup)

    with pytest.raises(ScenarioWorkflowError) as captured:
        asyncio.run(
            run_one(
                ScenarioName.STORAGE,
                workspace=tmp_path,
                run_id="failed-before-result",
            )
        )

    assert (
        captured.value.category
        is ScenarioWorkflowErrorCategory.SCENARIO_EXECUTION_FAILED
    )
    assert cleanup_calls == 1
    assert "private run failure" not in str(captured.value)
    assert list(tmp_path.iterdir()) == []


def test_cancellation_after_mutation_still_performs_manifest_cleanup(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    cleanup_calls = 0
    original_cleanup = ScenarioRunner.cleanup

    async def cancel_investigation(*_args: object, **_kwargs: object) -> None:
        raise asyncio.CancelledError

    def record_cleanup(*args: object, **kwargs: object):
        nonlocal cleanup_calls
        cleanup_calls += 1
        return original_cleanup(*args, **kwargs)

    monkeypatch.setattr(service_module, "_investigate", cancel_investigation)
    monkeypatch.setattr(ScenarioRunner, "cleanup", record_cleanup)

    with pytest.raises(asyncio.CancelledError):
        asyncio.run(
            run_one(
                ScenarioName.STORAGE,
                workspace=tmp_path,
                run_id="cancelled-after-mutation",
            )
        )

    assert cleanup_calls == 1
    assert list(tmp_path.iterdir()) == []
