"""Cross-scenario acceptance evidence for the canonical fixed baselines."""

from __future__ import annotations

import asyncio
import hashlib
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from reconcile.baseline import FixedBaselineResult, FixedBaselineStopReason
from reconcile.contracts import (
    INVESTIGATION_COMPARISON_RECORD_VERSION,
    SCENARIO_RUN_REQUEST_VERSION,
    Classification,
    ComparisonModelUsage,
    ComparisonModelUsageStatus,
    ComparisonRun,
    ComparisonStrategyKind,
    ExecutionEnvelope,
    ExplanationCompleteness,
    InvestigationComparisonRecord,
    PreregisteredExpectedClassification,
    RequestedAction,
    ScenarioFaultAction,
    ScenarioFaultInstruction,
    ScenarioFaultPoint,
    ScenarioRef,
    ScenarioRunRequest,
    canonical_json_bytes,
    canonical_sha256,
)
from reconcile.scenarios.firestore_business import (
    FIRESTORE_BUSINESS_EFFECT_IDS,
    FIRESTORE_BUSINESS_FIXED_PROBE_PLAN,
    FIRESTORE_BUSINESS_SCENARIO,
    FirestoreBusinessScenarioDefinition,
)
from reconcile.scenarios.local_order import HiddenOrderOutcome, LocalOrderHarness
from reconcile.scenarios.local_storage import LocalStorageReadTarget
from reconcile.scenarios.runner import ScenarioRunner
from reconcile.scenarios.sandbox_order import (
    SANDBOX_ORDER_AGGREGATE_FIRST,
    SANDBOX_ORDER_EFFECT_ID,
    SANDBOX_ORDER_FIXED_PROBE_PLAN,
    SANDBOX_ORDER_INGRESS_FIRST,
    SANDBOX_ORDER_ITEM_CODE,
    SANDBOX_ORDER_QUANTITY,
    SANDBOX_ORDER_SCENARIO,
    SandboxOrderScenarioDefinition,
)
from reconcile.scenarios.storage import (
    STORAGE_EFFECT_ID,
    STORAGE_FIXED_PROBE_PLAN,
    STORAGE_SCENARIO,
    StorageScenarioDefinition,
    execute_storage_baseline,
)
from tests._clocks import ConstantClock

pytestmark = pytest.mark.integration

NOW = datetime(2026, 8, 13, 23, 0, tzinfo=UTC)


class _StepClock:
    def __init__(self, current: datetime) -> None:
        self._current = current
        self._monotonic = 100.0

    def now(self) -> datetime:
        result = self._current
        self._current += timedelta(milliseconds=1)
        return result

    def monotonic(self) -> float:
        self._monotonic += 0.001
        return self._monotonic


def _request(
    scenario: ScenarioRef,
    *,
    suffix: str,
    seed: int,
) -> ScenarioRunRequest:
    return ScenarioRunRequest(
        schema_version=SCENARIO_RUN_REQUEST_VERSION,
        scenario=scenario,
        run_id=f"run-fixed-{suffix}",
        investigation_id=f"investigation-fixed-{suffix}",
        operation_id=f"operation-fixed-{suffix}",
        invocation_id=f"invocation-fixed-{suffix}",
        function_call_id=f"function-call-fixed-{suffix}",
        seed=seed,
        fault=ScenarioFaultInstruction(
            point=ScenarioFaultPoint.POST_COMMIT,
            action=ScenarioFaultAction.INTERRUPT_PROCESS,
        ),
    )


def _run_storage(
    tmp_path: Path,
    *,
    suffix: str,
) -> tuple[StorageScenarioDefinition, ExecutionEnvelope, Path]:
    database_path = tmp_path / f"{suffix}-storage.sqlite3"
    definition = StorageScenarioDefinition(
        database_path,
        invoked_at=NOW,
        target_clock=ConstantClock(NOW),
    )
    result = ScenarioRunner(clock=_StepClock(NOW + timedelta(seconds=1))).run(
        _request(STORAGE_SCENARIO, suffix=suffix, seed=39),
        definition,
    )
    assert result.execution_envelope is not None
    return definition, result.execution_envelope, database_path


def _run_firestore(
    tmp_path: Path,
    *,
    suffix: str,
) -> tuple[FirestoreBusinessScenarioDefinition, ExecutionEnvelope]:
    definition = FirestoreBusinessScenarioDefinition(
        tmp_path / f"{suffix}-firestore.sqlite3",
        invoked_at=NOW,
        target_clock=ConstantClock(NOW),
    )
    result = ScenarioRunner(clock=_StepClock(NOW + timedelta(seconds=1))).run(
        _request(FIRESTORE_BUSINESS_SCENARIO, suffix=suffix, seed=0b011),
        definition,
    )
    assert result.execution_envelope is not None
    return definition, result.execution_envelope


def _run_sandbox(
    tmp_path: Path,
    *,
    suffix: str,
) -> tuple[SandboxOrderScenarioDefinition, ExecutionEnvelope]:
    private_path = tmp_path / f"{suffix}-order-private.sqlite3"
    observation_path = tmp_path / f"{suffix}-order-observations.sqlite3"
    LocalOrderHarness(
        private_path,
        observation_path,
        clock=lambda: NOW,
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
    result = ScenarioRunner(clock=_StepClock(NOW + timedelta(seconds=1))).run(
        _request(SANDBOX_ORDER_SCENARIO, suffix=suffix, seed=41),
        definition,
    )
    assert result.execution_envelope is not None
    return definition, result.execution_envelope


def _clock() -> _StepClock:
    return _StepClock(NOW + timedelta(seconds=2))


def _metric_tuple(result: FixedBaselineResult) -> tuple[object, ...]:
    return (
        result.plan_name,
        result.plan_version,
        result.plan_sha256,
        result.stop_reason,
        result.planned_probe_count,
        result.attempted_probe_count,
        result.probe_count_used,
        result.cost_units_used,
        result.result_bytes_acquired,
        result.total_elapsed_ms,
        result.sufficient_probe_sequence,
        result.time_to_sufficient_evidence_ms,
        result.unsupported_probe_count,
        result.unavailable_probe_count,
        result.redundant_probe_count,
        result.duplicate_probe_count,
        result.model_invocation_count,
    )


def test_canonical_baselines_cover_strong_partial_and_unknown_outcomes(
    tmp_path: Path,
) -> None:
    storage_definition, storage_envelope, _ = _run_storage(
        tmp_path,
        suffix="outcomes",
    )
    firestore_definition, firestore_envelope = _run_firestore(
        tmp_path,
        suffix="outcomes",
    )
    sandbox_definition, sandbox_envelope = _run_sandbox(
        tmp_path,
        suffix="outcomes",
    )

    storage = storage_definition.baseline(storage_envelope, clock=_clock())
    firestore = firestore_definition.baseline(firestore_envelope, clock=_clock())
    sandbox = sandbox_definition.baseline(sandbox_envelope, clock=_clock())

    assert storage.classification is Classification.COMMITTED
    assert firestore.classification is Classification.PARTIAL
    assert sandbox.classification is Classification.UNKNOWN

    for result, plan in (
        (storage, STORAGE_FIXED_PROBE_PLAN),
        (firestore, FIRESTORE_BUSINESS_FIXED_PROBE_PLAN),
    ):
        assert result.stop_reason is FixedBaselineStopReason.SUFFICIENT_EVIDENCE
        assert result.plan_sha256 == plan.sha256
        assert result.planned_probe_count == 1
        assert result.attempted_probe_count == 1
        assert result.sufficient_probe_sequence == 1
        assert result.time_to_sufficient_evidence_ms is not None
        assert result.model_invocation_count == 0

    assert sandbox.plan_sha256 == SANDBOX_ORDER_FIXED_PROBE_PLAN.sha256
    assert sandbox.stop_reason is FixedBaselineStopReason.PLAN_EXHAUSTED
    assert sandbox.planned_probe_count == 2
    assert sandbox.attempted_probe_count == 2
    assert sandbox.sufficient_probe_sequence is None
    assert sandbox.time_to_sufficient_evidence_ms is None
    assert sandbox.model_invocation_count == 0

    assert STORAGE_FIXED_PROBE_PLAN.steps[0].request.arguments == {}
    assert STORAGE_FIXED_PROBE_PLAN.steps[0].request.relevant_effect_ids == (
        STORAGE_EFFECT_ID,
    )
    assert FIRESTORE_BUSINESS_FIXED_PROBE_PLAN.steps[0].request.arguments == {}
    assert (
        FIRESTORE_BUSINESS_FIXED_PROBE_PLAN.steps[0].request.relevant_effect_ids
        == FIRESTORE_BUSINESS_EFFECT_IDS
    )
    assert (
        tuple(
            step.request.capability_name
            for step in SANDBOX_ORDER_FIXED_PROBE_PLAN.steps
        )
        == SANDBOX_ORDER_INGRESS_FIRST
    )

    assert "partial multi-step business operation" in " ".join(
        firestore.report.limitations
    )
    assert "weak, non-discriminating observations" in " ".join(
        sandbox.report.limitations
    )


def test_baseline_reports_and_neutral_measurements_are_repeatable(
    tmp_path: Path,
) -> None:
    definitions_and_envelopes = (
        _run_storage(tmp_path, suffix="repeatable")[:2],
        _run_firestore(tmp_path, suffix="repeatable"),
        _run_sandbox(tmp_path, suffix="repeatable"),
    )

    for definition, envelope in definitions_and_envelopes:
        first = definition.baseline(envelope, clock=_clock())
        second = definition.baseline(envelope, clock=_clock())
        legacy_report = definition.investigate(envelope, clock=_clock())

        assert canonical_json_bytes(first.report) == canonical_json_bytes(second.report)
        assert canonical_json_bytes(first.report) == canonical_json_bytes(legacy_report)
        assert _metric_tuple(first) == _metric_tuple(second)
        assert first.model_invocation_count == 0


@pytest.mark.parametrize(
    ("failure", "expected_stop_reason", "expected_unavailable_count"),
    (
        (
            lambda: ValueError("malformed required probe"),
            FixedBaselineStopReason.REQUIRED_PROBE_FAILED,
            0,
        ),
        (
            lambda: OSError("required capability unavailable"),
            FixedBaselineStopReason.REQUIRED_CAPABILITY_UNAVAILABLE,
            1,
        ),
    ),
)
def test_required_storage_probe_failure_stops_and_fails_closed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    failure: Callable[[], Exception],
    expected_stop_reason: FixedBaselineStopReason,
    expected_unavailable_count: int,
) -> None:
    definition, envelope, _ = _run_storage(
        tmp_path, suffix=failure().__class__.__name__
    )

    def fail_read(self: LocalStorageReadTarget, **coordinates: str):
        del self, coordinates
        raise failure()

    monkeypatch.setattr(LocalStorageReadTarget, "read", fail_read)

    result = definition.baseline(envelope, clock=_clock())

    assert result.classification is Classification.UNKNOWN
    assert result.stop_reason is expected_stop_reason
    assert result.attempted_probe_count == 1
    assert result.unavailable_probe_count == expected_unavailable_count
    assert result.model_invocation_count == 0
    gates = {gate.requested_action: gate.allowed for gate in result.report.action_gate}
    assert gates[RequestedAction.RETRY] is False
    assert gates[RequestedAction.COMPENSATE] is False
    assert gates[RequestedAction.ESCALATE] is True


def test_async_baseline_matches_sync_single_read_shape(tmp_path: Path) -> None:
    definition, envelope, database_path = _run_storage(tmp_path, suffix="async")

    sync_result = definition.baseline(envelope, clock=_clock())
    async_result = asyncio.run(
        execute_storage_baseline(
            envelope,
            LocalStorageReadTarget(database_path),
            clock=_clock(),
        )
    )

    assert canonical_json_bytes(sync_result.report) == canonical_json_bytes(
        async_result.report
    )
    assert _metric_tuple(sync_result) == _metric_tuple(async_result)
    assert sync_result.planned_probe_count == sync_result.attempted_probe_count == 1
    assert sync_result.model_invocation_count == 0


def test_alternate_sandbox_order_preserves_classification_and_action_gates(
    tmp_path: Path,
) -> None:
    definition, envelope = _run_sandbox(tmp_path, suffix="alternate")

    canonical = definition.baseline(
        envelope,
        probe_order=SANDBOX_ORDER_INGRESS_FIRST,
        clock=_clock(),
    )
    alternate = definition.baseline(
        envelope,
        probe_order=SANDBOX_ORDER_AGGREGATE_FIRST,
        clock=_clock(),
    )

    assert (
        canonical.classification is alternate.classification is Classification.UNKNOWN
    )
    assert canonical.report.proof == alternate.report.proof
    assert canonical.report.action_gate == alternate.report.action_gate
    assert canonical.stop_reason is FixedBaselineStopReason.PLAN_EXHAUSTED
    assert alternate.stop_reason is FixedBaselineStopReason.PLAN_EXHAUSTED
    assert canonical.plan_name == alternate.plan_name
    assert canonical.plan_version != alternate.plan_version
    assert canonical.plan_sha256 != alternate.plan_sha256
    assert canonical.model_invocation_count == alternate.model_invocation_count == 0
    assert canonical.report.proof is not None
    assert (
        canonical.report.proof.effect_findings[0].effect_id == SANDBOX_ORDER_EFFECT_ID
    )


def test_canonical_baseline_populates_neutral_comparison_fields(tmp_path: Path) -> None:
    definition, envelope = _run_sandbox(tmp_path, suffix="comparison")
    result = definition.baseline(envelope, clock=_clock())
    report = result.report
    retained_evidence_ids = {item.evidence_id for item in report.evidence}
    cited_evidence_ids = (
        ()
        if report.advisory_explanation is None
        else report.advisory_explanation.cited_evidence_ids
    )
    valid_citation_count = sum(
        evidence_id in retained_evidence_ids for evidence_id in cited_evidence_ids
    )
    missing_citation_count = len(cited_evidence_ids) - valid_citation_count

    comparison = InvestigationComparisonRecord(
        schema_version=INVESTIGATION_COMPARISON_RECORD_VERSION,
        comparison_id="comparison-sandbox-fixed-v1",
        case_id="case-sandbox-unknown-v1",
        scenario=SANDBOX_ORDER_SCENARIO,
        envelope_sha256=canonical_sha256(envelope),
        preregistered_expectation=PreregisteredExpectedClassification(
            registration_id="expectation-sandbox-unknown-v1",
            metadata_sha256=hashlib.sha256(
                b"expectation-sandbox-unknown-v1"
            ).hexdigest(),
            expected_classification=Classification.UNKNOWN,
        ),
        baseline=ComparisonRun(
            scenario=SANDBOX_ORDER_SCENARIO,
            envelope_sha256=canonical_sha256(envelope),
            strategy_kind=ComparisonStrategyKind.FIXED,
            strategy_version=f"{result.plan_name}:{result.plan_version}",
            plan_sha256=result.plan_sha256,
            report_sha256=canonical_sha256(report),
            classification=result.classification,
            matches_preregistered_expectation=True,
            planned_probe_count=result.planned_probe_count,
            executed_probe_count=result.attempted_probe_count,
            controller_cost_units_used=result.cost_units_used,
            controller_result_bytes_acquired=result.result_bytes_acquired,
            total_elapsed_ms=result.total_elapsed_ms,
            time_to_sufficient_evidence_ms=(result.time_to_sufficient_evidence_ms),
            stop_reason=result.stop_reason.value,
            unsupported_probe_count=result.unsupported_probe_count,
            unnecessary_probe_count=result.redundant_probe_count,
            duplicate_probe_count=result.duplicate_probe_count,
            explanation_completeness=ExplanationCompleteness(
                required_evidence_citation_count=len(cited_evidence_ids),
                valid_evidence_citation_count=valid_citation_count,
                missing_evidence_citation_count=missing_citation_count,
                complete=missing_citation_count == 0,
            ),
            model_usage=ComparisonModelUsage(
                status=ComparisonModelUsageStatus.NOT_APPLICABLE,
                model_call_count=result.model_invocation_count,
                input_token_count=0,
                output_token_count=0,
                total_token_count=0,
            ),
        ),
        adaptive=None,
    )

    assert comparison.adaptive is None
    assert comparison.baseline.executed_probe_count == result.attempted_probe_count
    assert comparison.baseline.controller_cost_units_used == result.cost_units_used
    assert (
        comparison.baseline.controller_result_bytes_acquired
        == result.result_bytes_acquired
    )
    assert comparison.baseline.total_elapsed_ms == result.total_elapsed_ms
    assert (
        comparison.baseline.time_to_sufficient_evidence_ms
        == result.time_to_sufficient_evidence_ms
    )
    assert comparison.baseline.stop_reason == result.stop_reason.value
    assert comparison.baseline.unsupported_probe_count == result.unsupported_probe_count
    assert comparison.baseline.unnecessary_probe_count == result.redundant_probe_count
    assert comparison.baseline.duplicate_probe_count == result.duplicate_probe_count
    assert (
        comparison.baseline.model_usage.status
        is ComparisonModelUsageStatus.NOT_APPLICABLE
    )
    assert comparison.baseline.model_usage.model_call_count == 0
    serialized = canonical_json_bytes(comparison).lower()
    assert all(
        forbidden not in serialized
        for forbidden in (b"winner", b"improvement", b"superiority")
    )
