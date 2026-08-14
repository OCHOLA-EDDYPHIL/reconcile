"""End-to-end local sandbox-order ambiguity and refusal-to-guess behavior."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from reconcile.contracts import (
    SCENARIO_RUN_REQUEST_VERSION,
    AmbiguityKind,
    Classification,
    EffectAssertionState,
    EvidenceAuthority,
    EvidenceDisposition,
    ExecutionEnvelope,
    ProbeOutcome,
    RequestedAction,
    ScenarioCallerObservation,
    ScenarioCleanupDisposition,
    ScenarioFaultAction,
    ScenarioFaultInstruction,
    ScenarioFaultPoint,
    ScenarioRunRequest,
    ScenarioRunResult,
    ScenarioTransportEvent,
    ScenarioWorkerTermination,
    canonical_json_bytes,
)
from reconcile.contracts.base import canonical_json_value_bytes
from reconcile.scenarios.local_order import (
    HiddenOrderOutcome,
    LocalOrderHarness,
    LocalOrderReadTarget,
    WeakOrderCountBand,
    weak_observation_bytes,
)
from reconcile.scenarios.runner import ScenarioRunner
from reconcile.scenarios.sandbox_order import (
    SANDBOX_ORDER_AGGREGATE_FIRST,
    SANDBOX_ORDER_EFFECT_ID,
    SANDBOX_ORDER_INGRESS_FIRST,
    SANDBOX_ORDER_ITEM_CODE,
    SANDBOX_ORDER_QUANTITY,
    SANDBOX_ORDER_SCENARIO,
    SandboxOrderProbeOrder,
    SandboxOrderScenarioDefinition,
)
from tests._clocks import ConstantClock

pytestmark = pytest.mark.integration

NOW = datetime(2026, 8, 13, 22, 0, tzinfo=UTC)


class _StepClock:
    def __init__(
        self,
        current: datetime,
        *,
        wall_step: timedelta = timedelta(milliseconds=1),
        monotonic_step: float = 0.001,
    ) -> None:
        self._current = current
        self._wall_step = wall_step
        self._monotonic = 100.0
        self._monotonic_step = monotonic_step

    def now(self) -> datetime:
        result = self._current
        self._current += self._wall_step
        return result

    def monotonic(self) -> float:
        self._monotonic += self._monotonic_step
        return self._monotonic


@dataclass(frozen=True, slots=True)
class _CompletedRun:
    runner: ScenarioRunner
    definition: SandboxOrderScenarioDefinition
    request: ScenarioRunRequest
    result: ScenarioRunResult
    harness: LocalOrderHarness
    read_target: LocalOrderReadTarget


def _request(*, suffix: str = "paired", seed: int = 41) -> ScenarioRunRequest:
    return ScenarioRunRequest(
        schema_version=SCENARIO_RUN_REQUEST_VERSION,
        scenario=SANDBOX_ORDER_SCENARIO,
        run_id=f"run-sandbox-order-{suffix}",
        investigation_id=f"investigation-sandbox-order-{suffix}",
        operation_id=f"operation-sandbox-order-{suffix}",
        invocation_id=f"invocation-sandbox-order-{suffix}",
        function_call_id=f"function-call-sandbox-order-{suffix}",
        seed=seed,
        fault=ScenarioFaultInstruction(
            point=ScenarioFaultPoint.POST_COMMIT,
            action=ScenarioFaultAction.INTERRUPT_PROCESS,
        ),
    )


def _completed_run(
    tmp_path: Path,
    *,
    name: str,
    outcome: HiddenOrderOutcome,
    request: ScenarioRunRequest | None = None,
) -> _CompletedRun:
    private_path = tmp_path / f"{name}-private.sqlite3"
    observation_path = tmp_path / f"{name}-observations.sqlite3"
    harness = LocalOrderHarness(
        private_path,
        observation_path,
        clock=lambda: NOW,
    )
    harness.seed_duplicate_looking_order(
        item_code=SANDBOX_ORDER_ITEM_CODE,
        quantity=SANDBOX_ORDER_QUANTITY,
    )
    definition = SandboxOrderScenarioDefinition(
        private_path,
        observation_path,
        hidden_outcome=outcome,
        invoked_at=NOW,
        target_clock=ConstantClock(NOW + timedelta(seconds=1)),
    )
    runner = ScenarioRunner(clock=_StepClock(NOW + timedelta(seconds=2)))
    selected_request = request or _request(suffix=name)
    result = runner.run(selected_request, definition)
    assert result.execution_envelope is not None
    return _CompletedRun(
        runner=runner,
        definition=definition,
        request=selected_request,
        result=result,
        harness=harness,
        read_target=LocalOrderReadTarget(observation_path),
    )


def _report(
    completed: _CompletedRun,
    *,
    probe_order: SandboxOrderProbeOrder = SANDBOX_ORDER_INGRESS_FIRST,
    clock: _StepClock | None = None,
    envelope: ExecutionEnvelope | None = None,
):
    selected_envelope = envelope or completed.result.execution_envelope
    assert selected_envelope is not None
    return completed.definition.investigate(
        selected_envelope,
        probe_order=probe_order,
        clock=clock or _StepClock(NOW + timedelta(seconds=3)),
    )


def _owner_token(result: ScenarioRunResult) -> str:
    envelope = result.execution_envelope
    assert envelope is not None
    namespace_id = envelope.target.scope.get("sandbox_id")
    assert isinstance(namespace_id, str)
    material = {
        "namespace_id": namespace_id,
        "operation_id": result.operation_id,
    }
    digest = hashlib.sha256(canonical_json_value_bytes(material)).hexdigest()
    return f"sandbox-owner-{digest[:32]}"


def _assert_unknown_report(report) -> None:
    assert report.classification is Classification.UNKNOWN
    assert report.proof is not None
    assert report.proof.operation_status is None
    assert report.proof.admitted_evidence_ids == ()
    assert len(report.proof.effect_findings) == 1
    assert report.proof.effect_findings[0].effect_id == SANDBOX_ORDER_EFFECT_ID
    assert report.proof.effect_findings[0].state is EffectAssertionState.UNVERIFIED
    assert report.missing_evidence[0].effect_ids == (SANDBOX_ORDER_EFFECT_ID,)
    assert report.missing_evidence[0].reason
    gates = {gate.requested_action: gate for gate in report.action_gate}
    assert gates[RequestedAction.RETRY].allowed is False
    assert gates[RequestedAction.COMPENSATE].allowed is False
    assert gates[RequestedAction.ESCALATE].allowed is True
    limitations = " ".join(report.limitations)
    assert "no authoritative order-status lookup" in limitations
    assert "weak, non-discriminating observations" in limitations
    assert "human operator may escalate" in limitations
    assert "local SQLite sandbox" in limitations


def test_hidden_commit_and_discard_are_publicly_indistinguishable(
    tmp_path: Path,
) -> None:
    request = _request()
    committed = _completed_run(
        tmp_path,
        name="left",
        outcome=HiddenOrderOutcome.COMMIT,
        request=request,
    )
    discarded = _completed_run(
        tmp_path,
        name="right",
        outcome=HiddenOrderOutcome.DISCARD,
        request=request,
    )

    assert canonical_json_bytes(committed.result) == canonical_json_bytes(
        discarded.result
    )
    commit_snapshot = committed.read_target.read_snapshot()
    discard_snapshot = discarded.read_target.read_snapshot()
    assert weak_observation_bytes(commit_snapshot) == weak_observation_bytes(
        discard_snapshot
    )
    assert len(committed.harness.private_orders()) == 2
    assert len(discarded.harness.private_orders()) == 1
    assert {
        (order.item_code, order.quantity)
        for order in committed.harness.private_orders()
    } == {(SANDBOX_ORDER_ITEM_CODE, SANDBOX_ORDER_QUANTITY)}
    assert {
        (order.item_code, order.quantity)
        for order in discarded.harness.private_orders()
    } == {(SANDBOX_ORDER_ITEM_CODE, SANDBOX_ORDER_QUANTITY)}

    envelope = committed.result.execution_envelope
    assert envelope is not None
    assert envelope.context.correlation_fields == {}
    assert envelope.context.invocation.arguments == {
        "item_code": SANDBOX_ORDER_ITEM_CODE,
        "quantity": SANDBOX_ORDER_QUANTITY,
    }
    assert envelope.expected_effects[0].predicate == {
        "item_code": SANDBOX_ORDER_ITEM_CODE,
        "quantity": SANDBOX_ORDER_QUANTITY,
    }
    trace = committed.result.trace
    assert trace.caller_observation is ScenarioCallerObservation.NO_RESPONSE
    assert trace.worker_termination is ScenarioWorkerTermination.SIGNALED
    assert ScenarioTransportEvent.POST_COMMIT_REACHED in {
        event.event for event in trace.events
    }
    assert ScenarioTransportEvent.RESPONSE_AVAILABLE not in {
        event.event for event in trace.events
    }
    assert envelope.ambiguity.kind is AmbiguityKind.PROCESS_INTERRUPTED

    for probe_order in (
        SANDBOX_ORDER_INGRESS_FIRST,
        SANDBOX_ORDER_AGGREGATE_FIRST,
    ):
        commit_report = _report(committed, probe_order=probe_order)
        discard_report = _report(discarded, probe_order=probe_order)
        assert canonical_json_bytes(commit_report) == canonical_json_bytes(
            discard_report
        )
        _assert_unknown_report(commit_report)
        assert commit_report.missing_evidence[0].reason == "non_authoritative_log_only"
        assert {item.authority for item in commit_report.evidence} == {
            EvidenceAuthority.SUPPLEMENTARY
        }
        assert {item.operation_status for item in commit_report.evidence} == {None}
        assert {tuple(item.correlation.items()) for item in commit_report.evidence} == {
            ()
        }
        assert {
            decision.disposition for decision in commit_report.evidence_decisions
        } == {EvidenceDisposition.WEAK}

    public_bytes = (
        canonical_json_bytes(committed.result)
        + weak_observation_bytes(commit_snapshot)
        + canonical_json_bytes(
            _report(committed, probe_order=SANDBOX_ORDER_INGRESS_FIRST)
        )
    )
    for hidden_value in (
        b'"COMMIT"',
        b'"DISCARD"',
        b'"hidden_outcome"',
        b'"owner_token"',
    ):
        assert hidden_value not in public_bytes


@pytest.mark.parametrize("monotonic_step", (0.001, 0.1))
def test_latency_variation_never_becomes_order_evidence(
    tmp_path: Path,
    monotonic_step: float,
) -> None:
    completed = _completed_run(
        tmp_path,
        name=f"latency-{str(monotonic_step).replace('.', '-')}",
        outcome=HiddenOrderOutcome.COMMIT,
    )

    report = _report(
        completed,
        clock=_StepClock(
            NOW + timedelta(seconds=3),
            monotonic_step=monotonic_step,
        ),
    )

    _assert_unknown_report(report)
    assert report.missing_evidence[0].reason == "non_authoritative_log_only"
    assert all(
        evidence.authority is EvidenceAuthority.SUPPLEMENTARY
        for evidence in report.evidence
    )


def test_missing_weak_logs_and_aggregate_remain_unknown(tmp_path: Path) -> None:
    completed = _completed_run(
        tmp_path,
        name="missing",
        outcome=HiddenOrderOutcome.DISCARD,
    )
    assert completed.harness.delete_ingress_observations() == 1
    assert completed.harness.delete_aggregate() is True

    report = _report(completed)

    _assert_unknown_report(report)
    assert report.missing_evidence[0].reason == "not_found_absence_only"
    assert {item.authority for item in report.evidence} == {EvidenceAuthority.WEAK}
    assert {decision.disposition for decision in report.evidence_decisions} == {
        EvidenceDisposition.WEAK
    }


def test_malformed_weak_storage_fails_closed(tmp_path: Path) -> None:
    completed = _completed_run(
        tmp_path,
        name="malformed",
        outcome=HiddenOrderOutcome.COMMIT,
    )
    completed.harness.corrupt_latest_ingress(event_sha256="f" * 64)

    report = _report(completed)

    _assert_unknown_report(report)
    assert report.missing_evidence[0].reason == "non_authoritative_log_only"
    assert report.evidence_decisions[0].disposition is EvidenceDisposition.REJECTED
    assert report.evidence_decisions[1].disposition is EvidenceDisposition.WEAK


def test_unavailable_weak_api_fails_closed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    completed = _completed_run(
        tmp_path,
        name="unavailable",
        outcome=HiddenOrderOutcome.DISCARD,
    )

    def denied(_target: LocalOrderReadTarget) -> None:
        raise PermissionError("weak sandbox read denied")

    monkeypatch.setattr(LocalOrderReadTarget, "read_ingress", denied)
    monkeypatch.setattr(LocalOrderReadTarget, "read_aggregate", denied)

    report = _report(completed)

    _assert_unknown_report(report)
    assert report.missing_evidence[0].reason == "unverifiable_authority"
    assert not report.evidence
    assert {decision.disposition for decision in report.evidence_decisions} == {
        EvidenceDisposition.REJECTED
    }


def test_exhausted_probe_budget_preserves_unknown(tmp_path: Path) -> None:
    completed = _completed_run(
        tmp_path,
        name="budget",
        outcome=HiddenOrderOutcome.COMMIT,
    )
    envelope = completed.result.execution_envelope
    assert envelope is not None
    payload = envelope.model_dump(mode="python")
    payload["context"]["evidence_budget"]["max_probes"] = 1
    constrained = ExecutionEnvelope.model_validate(payload)

    report = _report(completed, envelope=constrained)

    _assert_unknown_report(report)
    assert report.missing_evidence[0].reason == "budget_exhausted"
    assert len(report.probe_audit) == 2
    assert report.probe_audit[1].outcome is ProbeOutcome.BUDGET_EXHAUSTED
    assert report.evidence_decisions[1].disposition is EvidenceDisposition.REJECTED


@pytest.mark.parametrize(
    ("outcome", "removed_count"),
    (
        (HiddenOrderOutcome.COMMIT, 3),
        (HiddenOrderOutcome.DISCARD, 2),
    ),
)
def test_cleanup_is_exact_idempotent_and_preserves_duplicate_order(
    tmp_path: Path,
    outcome: HiddenOrderOutcome,
    removed_count: int,
) -> None:
    completed = _completed_run(
        tmp_path,
        name=f"cleanup-{outcome.value.lower()}",
        outcome=outcome,
    )
    report = _report(completed)
    report_bytes = canonical_json_bytes(report)
    cleanup_request = completed.runner.build_cleanup_request(
        completed.request,
        completed.result,
    )

    first = completed.runner.cleanup(cleanup_request, completed.definition)
    second = completed.runner.cleanup(cleanup_request, completed.definition)

    assert first.disposition is ScenarioCleanupDisposition.CLEANED
    assert first.removed_count == removed_count
    assert first.remaining_count == 0
    assert second.disposition is ScenarioCleanupDisposition.ALREADY_CLEAN
    assert len(completed.harness.private_orders()) == 1
    snapshot = completed.read_target.read_snapshot()
    assert snapshot.ingress is None
    assert snapshot.aggregate is not None
    assert snapshot.aggregate.count_band is WeakOrderCountBand.ONE_OR_MORE
    assert canonical_json_bytes(report) == report_bytes


def test_cleanup_failure_preserves_a_replacement_private_order(
    tmp_path: Path,
) -> None:
    completed = _completed_run(
        tmp_path,
        name="replacement",
        outcome=HiddenOrderOutcome.COMMIT,
    )
    replacement = completed.harness.replace_owned_order(
        owner_token=_owner_token(completed.result),
        item_code="replacement-item",
        quantity=9,
    )

    cleanup = completed.runner.cleanup(
        completed.runner.build_cleanup_request(
            completed.request,
            completed.result,
        ),
        completed.definition,
    )

    assert cleanup.disposition is ScenarioCleanupDisposition.FAILED
    assert cleanup.failure_code == "cleanup_verification_failed"
    assert replacement in completed.harness.private_orders()
    assert completed.read_target.read_ingress() is not None


def test_probe_order_must_be_one_of_the_two_permitted_strategies(
    tmp_path: Path,
) -> None:
    completed = _completed_run(
        tmp_path,
        name="invalid-order",
        outcome=HiddenOrderOutcome.DISCARD,
    )

    with pytest.raises(ValueError, match="permitted probe order"):
        _report(
            completed,
            probe_order=(
                SANDBOX_ORDER_INGRESS_FIRST[0],
                SANDBOX_ORDER_INGRESS_FIRST[0],
            ),
        )
