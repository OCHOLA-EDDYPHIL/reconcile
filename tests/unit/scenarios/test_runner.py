"""Deterministic subprocess scenario-runner behavior."""

from __future__ import annotations

import hashlib
import json
import os
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest

from reconcile.contracts import (
    EXECUTION_ENVELOPE_VERSION,
    EXPECTED_EFFECT_VERSION,
    SCENARIO_RUN_REQUEST_VERSION,
    AmbiguityKind,
    AmbiguousExecution,
    CapabilityRef,
    EnvelopeContext,
    EvidenceBudget,
    ExecutionEnvelope,
    ExpectedEffect,
    FreshnessPolicy,
    OriginalInvocation,
    PolicyReferences,
    ScenarioCallerObservation,
    ScenarioCleanupDisposition,
    ScenarioCleanupRequest,
    ScenarioFaultAction,
    ScenarioFaultInstruction,
    ScenarioFaultPoint,
    ScenarioRef,
    ScenarioRunRequest,
    ScenarioTransportEvent,
    ScenarioWorkerTermination,
    TargetBinding,
    canonical_json_bytes,
)
from reconcile.contracts.base import canonical_json_value_bytes
from reconcile.scenarios import (
    MutationBoundary,
    PreparedScenario,
    ScenarioCleanupManifest,
    ScenarioCleanupOutcome,
    ScenarioMutationResponse,
    ScenarioPlan,
    ScenarioPreparation,
    ScenarioRunner,
)

pytestmark = pytest.mark.unit

_SCENARIO = ScenarioRef(name="durable-file", version="1.0.0")
_INVOKED_AT = datetime(2026, 8, 13, 15, 0, tzinfo=UTC)


class _StepClock:
    def __init__(self) -> None:
        self._current = datetime(2026, 8, 13, 16, 0, tzinfo=UTC)

    def now(self) -> datetime:
        result = self._current
        self._current += timedelta(milliseconds=1)
        return result


class _RecordingSleeper:
    def __init__(self) -> None:
        self.calls: list[float] = []

    def __call__(self, seconds: float) -> None:
        self.calls.append(seconds)


def _response_payload(operation_id: str, invocation_id: str) -> dict[str, object]:
    return {
        "body": "bounded-response-value",
        "invocation_id": invocation_id,
        "operation_id": operation_id,
    }


def _error_payload(operation_id: str) -> dict[str, object]:
    return {
        "code": "target-rejected",
        "operation_id": operation_id,
    }


def _envelope(plan: ScenarioPlan) -> ExecutionEnvelope:
    identifiers = plan.identifiers
    arguments = {"request_id": identifiers.operation_id}
    invocation = OriginalInvocation(
        invocation_id=identifiers.invocation_id,
        function_call_id=identifiers.function_call_id,
        tool_name="durable-file-write",
        tool_version="1.0.0",
        arguments=arguments,
        arguments_sha256=hashlib.sha256(
            canonical_json_value_bytes(arguments)
        ).hexdigest(),
    )
    return ExecutionEnvelope(
        schema_version=EXECUTION_ENVELOPE_VERSION,
        investigation_id=identifiers.investigation_id,
        operation_id=identifiers.operation_id,
        target=TargetBinding(
            target_kind="test.durable-file",
            scope={"namespace": plan.namespace_id},
            resource={"record": identifiers.operation_id},
        ),
        invoked_at=_INVOKED_AT,
        ambiguity=AmbiguousExecution(
            kind=AmbiguityKind.OTHER,
            observed_at=_INVOKED_AT,
            detail="Sealed scenario envelope template.",
        ),
        expected_effects=(
            ExpectedEffect(
                schema_version=EXPECTED_EFFECT_VERSION,
                effect_id="durable-record",
                commit_scope="write",
                predicate={"request_id": identifiers.operation_id},
                description="The correlated durable record exists.",
            ),
        ),
        context=EnvelopeContext(
            invocation=invocation,
            enabled_capabilities=(
                CapabilityRef(name="durable-file-readback", version="1.0.0"),
            ),
            correlation_fields={"request_id": identifiers.operation_id},
            evidence_budget=EvidenceBudget(
                max_probes=2,
                max_elapsed_ms=1_000,
                max_total_result_bytes=4_096,
                max_cost_units=2,
            ),
            freshness=FreshnessPolicy(max_age_seconds=60, clock_skew_seconds=1),
            policies=PolicyReferences(
                authority="authority-test-v1",
                classification="classification-test-v1",
                action="action-test-v1",
            ),
        ),
    )


class _FileScenario:
    scenario = _SCENARIO

    def __init__(
        self,
        root: Path,
        *,
        error_response: bool = False,
        raise_after_commit: bool = False,
        cleanup_failure: bool = False,
        cleanup_reports_undeclared: bool = False,
        cleanup_reports_zero: bool = False,
    ) -> None:
        self._root = root
        self._error_response = error_response
        self._raise_after_commit = raise_after_commit
        self._cleanup_failure = cleanup_failure
        self._cleanup_reports_undeclared = cleanup_reports_undeclared
        self._cleanup_reports_zero = cleanup_reports_zero
        self.prepared_templates: list[ExecutionEnvelope] = []
        self.prepared_envelopes: list[bytes] = []
        self.prepared_namespaces: list[str] = []
        self.setup_namespaces: list[str] = []
        self.cleanup_namespaces: list[str] = []

    def namespace_path(self, namespace_id: str) -> Path:
        return self._root / namespace_id

    def state_path(self, namespace_id: str) -> Path:
        return self.namespace_path(namespace_id) / "target-state.jsonl"

    def line_count(self, namespace_id: str) -> int:
        path = self.state_path(namespace_id)
        if not path.exists():
            return 0
        return len(path.read_text(encoding="utf-8").splitlines())

    def records(self, namespace_id: str) -> list[dict[str, object]]:
        path = self.state_path(namespace_id)
        if not path.exists():
            return []
        return [
            json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()
        ]

    def prepare(self, plan: ScenarioPlan) -> ScenarioPreparation:
        envelope = _envelope(plan)
        self.prepared_templates.append(envelope)
        self.prepared_envelopes.append(canonical_json_bytes(envelope))
        self.prepared_namespaces.append(plan.namespace_id)
        return ScenarioPreparation(
            execution_envelope=envelope,
            cleanup_manifest=ScenarioCleanupManifest(
                resource_ids=("target-state.jsonl",),
            ),
        )

    def setup(self, prepared: PreparedScenario) -> None:
        namespace_id = prepared.plan.namespace_id
        self.setup_namespaces.append(namespace_id)
        self.namespace_path(namespace_id).mkdir(parents=True, exist_ok=True)

    def mutate(
        self,
        boundary: MutationBoundary,
        prepared: PreparedScenario,
    ) -> ScenarioMutationResponse:
        identifiers = prepared.plan.identifiers
        boundary.before_commit()
        if self._error_response:
            return ScenarioMutationResponse(
                is_error=True,
                payload=_error_payload(identifiers.operation_id),
            )
        record = json.dumps(
            {
                "invocation_id": identifiers.invocation_id,
                "operation_id": identifiers.operation_id,
            },
            sort_keys=True,
            separators=(",", ":"),
        )
        with self.state_path(prepared.plan.namespace_id).open(
            "a",
            encoding="utf-8",
        ) as handle:
            handle.write(record + "\n")
            handle.flush()
            os.fsync(handle.fileno())
        boundary.after_commit()
        if self._raise_after_commit:
            raise RuntimeError("unexpected failure after the commit checkpoint")
        return ScenarioMutationResponse(
            is_error=False,
            payload=_response_payload(
                identifiers.operation_id,
                identifiers.invocation_id,
            ),
        )

    def remaining(self, prepared: PreparedScenario) -> int:
        return int(self.state_path(prepared.plan.namespace_id).exists())

    def cleanup(self, prepared: PreparedScenario) -> ScenarioCleanupOutcome:
        namespace_id = prepared.plan.namespace_id
        self.cleanup_namespaces.append(namespace_id)
        if self._cleanup_failure:
            raise OSError("isolated cleanup failure")
        state_path = self.state_path(namespace_id)
        if not state_path.exists():
            return ScenarioCleanupOutcome(removed_resource_ids=())
        state_path.unlink()
        if self._cleanup_reports_undeclared:
            return ScenarioCleanupOutcome(removed_resource_ids=("foreign-file",))
        if self._cleanup_reports_zero:
            return ScenarioCleanupOutcome(removed_resource_ids=())
        return ScenarioCleanupOutcome(
            removed_resource_ids=("target-state.jsonl",),
        )


class _MutatingSetupScenario(_FileScenario):
    def setup(self, prepared: PreparedScenario) -> None:
        template = self.prepared_templates[-1]
        template.target.scope["namespace"] = "retargeted-after-seal"
        template.expected_effects[0].predicate["request_id"] = "changed-after-seal"
        template.context.correlation_fields["request_id"] = "changed-after-seal"
        super().setup(prepared)


class _PidFileScenario(_FileScenario):
    def pid_path(self, namespace_id: str) -> Path:
        return self.namespace_path(namespace_id) / "worker.pid"

    def mutate(
        self,
        boundary: MutationBoundary,
        prepared: PreparedScenario,
    ) -> ScenarioMutationResponse:
        self.pid_path(prepared.plan.namespace_id).write_text(
            str(os.getpid()),
            encoding="ascii",
        )
        return super().mutate(boundary, prepared)


def _fault(
    point: ScenarioFaultPoint,
    action: ScenarioFaultAction,
    *,
    delay_ms: int = 0,
) -> ScenarioFaultInstruction:
    return ScenarioFaultInstruction(
        point=point,
        action=action,
        delay_ms=delay_ms,
    )


def _request(
    fault: ScenarioFaultInstruction,
    *,
    identity: str = "stable",
    seed: int = 7,
) -> ScenarioRunRequest:
    return ScenarioRunRequest(
        schema_version=SCENARIO_RUN_REQUEST_VERSION,
        scenario=_SCENARIO,
        run_id=f"run-{identity}",
        investigation_id=f"investigation-{identity}",
        operation_id=f"operation-{identity}",
        invocation_id=f"invocation-{identity}",
        function_call_id=f"call-{identity}",
        seed=seed,
        fault=fault,
    )


def _event_kinds(result: Any) -> tuple[ScenarioTransportEvent, ...]:
    return tuple(event.event for event in result.trace.events)


@pytest.mark.parametrize(
    (
        "fault",
        "observation",
        "termination",
        "events",
        "commits",
        "has_envelope",
        "delay_ms",
    ),
    (
        (
            _fault(ScenarioFaultPoint.UNINTERRUPTED, ScenarioFaultAction.NONE),
            ScenarioCallerObservation.VALUE_RESPONSE,
            ScenarioWorkerTermination.EXITED,
            (
                ScenarioTransportEvent.RUN_STARTED,
                ScenarioTransportEvent.DISPATCH_STARTED,
                ScenarioTransportEvent.PRE_COMMIT_REACHED,
                ScenarioTransportEvent.POST_COMMIT_REACHED,
                ScenarioTransportEvent.RESPONSE_AVAILABLE,
                ScenarioTransportEvent.RESPONSE_OBSERVED,
                ScenarioTransportEvent.RUN_COMPLETED,
            ),
            1,
            False,
            0,
        ),
        (
            _fault(
                ScenarioFaultPoint.PRE_DISPATCH,
                ScenarioFaultAction.SUPPRESS_DISPATCH,
            ),
            ScenarioCallerObservation.NOT_DISPATCHED,
            ScenarioWorkerTermination.NOT_STARTED,
            (
                ScenarioTransportEvent.RUN_STARTED,
                ScenarioTransportEvent.DISPATCH_SUPPRESSED,
                ScenarioTransportEvent.RUN_COMPLETED,
            ),
            0,
            False,
            0,
        ),
        (
            _fault(
                ScenarioFaultPoint.PRE_COMMIT,
                ScenarioFaultAction.INTERRUPT_PROCESS,
            ),
            ScenarioCallerObservation.NO_RESPONSE,
            ScenarioWorkerTermination.SIGNALED,
            (
                ScenarioTransportEvent.RUN_STARTED,
                ScenarioTransportEvent.DISPATCH_STARTED,
                ScenarioTransportEvent.PRE_COMMIT_REACHED,
                ScenarioTransportEvent.WORKER_INTERRUPTED,
                ScenarioTransportEvent.RUN_COMPLETED,
            ),
            0,
            True,
            0,
        ),
        (
            _fault(
                ScenarioFaultPoint.POST_COMMIT,
                ScenarioFaultAction.INTERRUPT_PROCESS,
            ),
            ScenarioCallerObservation.NO_RESPONSE,
            ScenarioWorkerTermination.SIGNALED,
            (
                ScenarioTransportEvent.RUN_STARTED,
                ScenarioTransportEvent.DISPATCH_STARTED,
                ScenarioTransportEvent.PRE_COMMIT_REACHED,
                ScenarioTransportEvent.POST_COMMIT_REACHED,
                ScenarioTransportEvent.WORKER_INTERRUPTED,
                ScenarioTransportEvent.RUN_COMPLETED,
            ),
            1,
            True,
            0,
        ),
        (
            _fault(
                ScenarioFaultPoint.POST_RESPONSE,
                ScenarioFaultAction.DROP_RESPONSE,
            ),
            ScenarioCallerObservation.NO_RESPONSE,
            ScenarioWorkerTermination.EXITED,
            (
                ScenarioTransportEvent.RUN_STARTED,
                ScenarioTransportEvent.DISPATCH_STARTED,
                ScenarioTransportEvent.PRE_COMMIT_REACHED,
                ScenarioTransportEvent.POST_COMMIT_REACHED,
                ScenarioTransportEvent.RESPONSE_AVAILABLE,
                ScenarioTransportEvent.RESPONSE_DROPPED,
                ScenarioTransportEvent.RUN_COMPLETED,
            ),
            1,
            True,
            0,
        ),
        (
            _fault(
                ScenarioFaultPoint.POST_RESPONSE,
                ScenarioFaultAction.DELAY_RESPONSE,
                delay_ms=25,
            ),
            ScenarioCallerObservation.VALUE_RESPONSE,
            ScenarioWorkerTermination.EXITED,
            (
                ScenarioTransportEvent.RUN_STARTED,
                ScenarioTransportEvent.DISPATCH_STARTED,
                ScenarioTransportEvent.PRE_COMMIT_REACHED,
                ScenarioTransportEvent.POST_COMMIT_REACHED,
                ScenarioTransportEvent.RESPONSE_AVAILABLE,
                ScenarioTransportEvent.RESPONSE_DELAY_STARTED,
                ScenarioTransportEvent.RESPONSE_OBSERVED,
                ScenarioTransportEvent.RUN_COMPLETED,
            ),
            1,
            False,
            25,
        ),
    ),
)
def test_fault_matrix_records_transport_without_inferring_target_state(
    tmp_path: Path,
    fault: ScenarioFaultInstruction,
    observation: ScenarioCallerObservation,
    termination: ScenarioWorkerTermination,
    events: tuple[ScenarioTransportEvent, ...],
    commits: int,
    has_envelope: bool,
    delay_ms: int,
) -> None:
    definition = _FileScenario(tmp_path)
    sleeper = _RecordingSleeper()
    runner = ScenarioRunner(clock=_StepClock(), sleeper=sleeper)

    result = runner.run(_request(fault), definition)

    assert result.trace.configured_fault == fault
    assert result.trace.caller_observation is observation
    assert result.trace.worker_termination is termination
    assert _event_kinds(result) == events
    assert definition.line_count(result.fixture.namespace_id) == commits
    assert (result.execution_envelope is not None) is has_envelope
    assert result.trace.applied_delay_ms == delay_ms
    assert sleeper.calls == ([0.025] if delay_ms else [])
    assert definition.setup_namespaces == [result.fixture.namespace_id]
    response_available = ScenarioTransportEvent.RESPONSE_AVAILABLE in events
    assert (result.trace.response_sha256 is not None) is response_available
    assert (result.trace.response_byte_count is not None) is response_available
    if termination is ScenarioWorkerTermination.EXITED:
        assert result.trace.exit_code == 0
        assert result.trace.signal is None
    elif termination is ScenarioWorkerTermination.SIGNALED:
        assert result.trace.exit_code is None
        assert result.trace.signal is not None
    else:
        assert result.trace.exit_code is None
        assert result.trace.signal is None


def test_explicit_tool_error_is_a_delivered_response(tmp_path: Path) -> None:
    definition = _FileScenario(tmp_path, error_response=True)
    request = _request(
        _fault(ScenarioFaultPoint.UNINTERRUPTED, ScenarioFaultAction.NONE)
    )

    result = ScenarioRunner(clock=_StepClock()).run(request, definition)

    response_bytes = canonical_json_value_bytes(_error_payload(request.operation_id))
    assert result.trace.caller_observation is ScenarioCallerObservation.ERROR_RESPONSE
    assert result.trace.worker_termination is ScenarioWorkerTermination.EXITED
    assert result.trace.exit_code == 0
    assert result.trace.response_sha256 == hashlib.sha256(response_bytes).hexdigest()
    assert result.trace.response_byte_count == len(response_bytes)
    assert result.execution_envelope is None
    assert definition.line_count(result.fixture.namespace_id) == 0
    assert _event_kinds(result) == (
        ScenarioTransportEvent.RUN_STARTED,
        ScenarioTransportEvent.DISPATCH_STARTED,
        ScenarioTransportEvent.PRE_COMMIT_REACHED,
        ScenarioTransportEvent.RESPONSE_AVAILABLE,
        ScenarioTransportEvent.RESPONSE_OBSERVED,
        ScenarioTransportEvent.RUN_COMPLETED,
    )


def test_setup_cannot_mutate_the_presealed_envelope(tmp_path: Path) -> None:
    definition = _MutatingSetupScenario(tmp_path)
    request = _request(
        _fault(
            ScenarioFaultPoint.POST_COMMIT,
            ScenarioFaultAction.INTERRUPT_PROCESS,
        )
    )

    result = ScenarioRunner(clock=_StepClock()).run(request, definition)

    assert result.execution_envelope is not None
    assert result.execution_envelope.target.scope == {
        "namespace": result.fixture.namespace_id
    }
    assert result.execution_envelope.expected_effects[0].predicate == {
        "request_id": request.operation_id
    }
    assert result.execution_envelope.context.correlation_fields == {
        "request_id": request.operation_id
    }


def test_parent_interruption_during_delay_reaps_the_worker(tmp_path: Path) -> None:
    definition = _PidFileScenario(tmp_path)
    request = _request(
        _fault(
            ScenarioFaultPoint.POST_RESPONSE,
            ScenarioFaultAction.DELAY_RESPONSE,
            delay_ms=25,
        )
    )

    def interrupt_delay(_seconds: float) -> None:
        raise RuntimeError("parent interrupted delayed delivery")

    with pytest.raises(RuntimeError, match="parent interrupted"):
        ScenarioRunner(clock=_StepClock(), sleeper=interrupt_delay).run(
            request,
            definition,
        )

    namespace_id = definition.prepared_namespaces[-1]
    worker_pid = int(definition.pid_path(namespace_id).read_text(encoding="ascii"))
    with pytest.raises(ProcessLookupError):
        os.kill(worker_pid, 0)


def test_unexpected_failure_after_commit_remains_ambiguous(tmp_path: Path) -> None:
    definition = _FileScenario(tmp_path, raise_after_commit=True)
    request = _request(
        _fault(ScenarioFaultPoint.UNINTERRUPTED, ScenarioFaultAction.NONE)
    )

    result = ScenarioRunner(clock=_StepClock()).run(request, definition)

    assert definition.line_count(result.fixture.namespace_id) == 1
    assert result.trace.caller_observation is ScenarioCallerObservation.NO_RESPONSE
    assert result.trace.worker_termination in {
        ScenarioWorkerTermination.EXITED,
        ScenarioWorkerTermination.SIGNALED,
    }
    assert _event_kinds(result) == (
        ScenarioTransportEvent.RUN_STARTED,
        ScenarioTransportEvent.DISPATCH_STARTED,
        ScenarioTransportEvent.PRE_COMMIT_REACHED,
        ScenarioTransportEvent.POST_COMMIT_REACHED,
        ScenarioTransportEvent.WORKER_INTERRUPTED,
        ScenarioTransportEvent.RUN_COMPLETED,
    )
    assert result.execution_envelope is not None
    assert result.execution_envelope.ambiguity.kind is AmbiguityKind.PROCESS_INTERRUPTED
    assert result.trace.response_sha256 is None
    assert result.trace.response_byte_count is None


def test_duplicate_delivery_reuses_caller_owned_stable_ids(tmp_path: Path) -> None:
    definition = _FileScenario(tmp_path)
    runner = ScenarioRunner(clock=_StepClock())
    interrupted_request = _request(
        _fault(
            ScenarioFaultPoint.POST_COMMIT,
            ScenarioFaultAction.INTERRUPT_PROCESS,
        )
    )
    delivered_request = _request(
        _fault(ScenarioFaultPoint.UNINTERRUPTED, ScenarioFaultAction.NONE)
    )

    first = runner.run(interrupted_request, definition)
    second = runner.run(delivered_request, definition)

    expected_ids = (
        interrupted_request.run_id,
        interrupted_request.investigation_id,
        interrupted_request.operation_id,
        interrupted_request.invocation_id,
        interrupted_request.function_call_id,
    )
    assert (
        first.run_id,
        first.investigation_id,
        first.operation_id,
        first.invocation_id,
        first.function_call_id,
    ) == expected_ids
    assert (
        second.run_id,
        second.investigation_id,
        second.operation_id,
        second.invocation_id,
        second.function_call_id,
    ) == expected_ids
    assert first.fixture == second.fixture
    assert first.execution_envelope is not None
    assert second.execution_envelope is None
    assert definition.setup_namespaces == [
        first.fixture.namespace_id,
        first.fixture.namespace_id,
    ]
    assert definition.records(first.fixture.namespace_id) == [
        {
            "invocation_id": interrupted_request.invocation_id,
            "operation_id": interrupted_request.operation_id,
        },
        {
            "invocation_id": interrupted_request.invocation_id,
            "operation_id": interrupted_request.operation_id,
        },
    ]


def test_fault_changes_do_not_change_ids_namespace_or_presealed_envelope(
    tmp_path: Path,
) -> None:
    definition = _FileScenario(tmp_path)
    runner = ScenarioRunner(clock=_StepClock())
    suppressed = _request(
        _fault(
            ScenarioFaultPoint.PRE_DISPATCH,
            ScenarioFaultAction.SUPPRESS_DISPATCH,
        )
    )
    interrupted = _request(
        _fault(
            ScenarioFaultPoint.POST_COMMIT,
            ScenarioFaultAction.INTERRUPT_PROCESS,
        )
    )

    first = runner.run(suppressed, definition)
    second = runner.run(interrupted, definition)

    assert (
        first.run_id,
        first.investigation_id,
        first.operation_id,
        first.invocation_id,
        first.function_call_id,
    ) == (
        second.run_id,
        second.investigation_id,
        second.operation_id,
        second.invocation_id,
        second.function_call_id,
    )
    assert first.fixture == second.fixture
    assert definition.prepared_namespaces == [
        first.fixture.namespace_id,
        first.fixture.namespace_id,
    ]
    assert definition.prepared_envelopes[0] == definition.prepared_envelopes[1]
    assert first.request_sha256 != second.request_sha256


def test_dropped_response_records_only_its_bounded_identity(tmp_path: Path) -> None:
    definition = _FileScenario(tmp_path)
    request = _request(
        _fault(
            ScenarioFaultPoint.POST_RESPONSE,
            ScenarioFaultAction.DROP_RESPONSE,
        )
    )

    result = ScenarioRunner(clock=_StepClock()).run(request, definition)

    response_bytes = canonical_json_value_bytes(
        _response_payload(request.operation_id, request.invocation_id)
    )
    assert result.trace.response_sha256 == hashlib.sha256(response_bytes).hexdigest()
    assert result.trace.response_byte_count == len(response_bytes)
    assert result.trace.caller_observation is ScenarioCallerObservation.NO_RESPONSE
    assert result.trace.worker_termination is ScenarioWorkerTermination.EXITED
    assert result.trace.exit_code == 0
    assert b"bounded-response-value" not in canonical_json_bytes(result.trace)


def test_trace_contains_transport_metadata_not_target_truth(tmp_path: Path) -> None:
    result = ScenarioRunner(clock=_StepClock()).run(
        _request(
            _fault(
                ScenarioFaultPoint.POST_RESPONSE,
                ScenarioFaultAction.DROP_RESPONSE,
            )
        ),
        _FileScenario(tmp_path),
    )
    payload = json.loads(canonical_json_bytes(result.trace))

    def keys(value: object) -> set[str]:
        if isinstance(value, dict):
            return set(value).union(*(keys(item) for item in value.values()))
        if isinstance(value, list):
            return set().union(*(keys(item) for item in value))
        return set()

    assert keys(payload).isdisjoint(
        {
            "classification",
            "committed",
            "effect_state",
            "mutation_succeeded",
            "operation_state",
            "target_state",
        }
    )


def test_setup_and_cleanup_are_isolated_between_namespaces(tmp_path: Path) -> None:
    definition = _FileScenario(tmp_path / "owned")
    runner = ScenarioRunner(clock=_StepClock())
    fault = _fault(ScenarioFaultPoint.UNINTERRUPTED, ScenarioFaultAction.NONE)
    first_request = _request(fault, identity="first")
    second_request = _request(fault, identity="second")
    first = runner.run(first_request, definition)
    second = runner.run(second_request, definition)
    foreign = tmp_path / "foreign" / "sentinel.txt"
    foreign.parent.mkdir()
    foreign.write_text("preserve", encoding="utf-8")

    cleanup = runner.cleanup(
        runner.build_cleanup_request(first_request, first),
        definition,
    )

    assert cleanup.disposition is ScenarioCleanupDisposition.CLEANED
    assert definition.line_count(first.fixture.namespace_id) == 0
    assert definition.line_count(second.fixture.namespace_id) == 1
    assert foreign.read_text(encoding="utf-8") == "preserve"
    assert definition.cleanup_namespaces == [first.fixture.namespace_id]


def test_cleanup_is_idempotent_and_cannot_rewrite_the_run_result(
    tmp_path: Path,
) -> None:
    definition = _FileScenario(tmp_path)
    runner = ScenarioRunner(clock=_StepClock())
    request = _request(
        _fault(
            ScenarioFaultPoint.POST_COMMIT,
            ScenarioFaultAction.INTERRUPT_PROCESS,
        )
    )
    result = runner.run(request, definition)
    result_bytes = canonical_json_bytes(result)
    cleanup_request = runner.build_cleanup_request(request, result)

    first = runner.cleanup(cleanup_request, definition)
    second = runner.cleanup(cleanup_request, definition)

    assert first.disposition is ScenarioCleanupDisposition.CLEANED
    assert first.removed_count == 1
    assert first.remaining_count == 0
    assert second.disposition is ScenarioCleanupDisposition.ALREADY_CLEAN
    assert second.removed_count == 0
    assert second.remaining_count == 0
    assert definition.cleanup_namespaces == [result.fixture.namespace_id]
    assert canonical_json_bytes(result) == result_bytes


def test_cleanup_authority_can_be_rederived_for_an_attempt_without_a_result(
    tmp_path: Path,
) -> None:
    definition = _FileScenario(tmp_path)
    runner = ScenarioRunner(clock=_StepClock())
    request = _request(
        _fault(ScenarioFaultPoint.UNINTERRUPTED, ScenarioFaultAction.NONE)
    )
    attempted_cleanup = runner.build_cleanup_request_for_attempt(request, definition)
    result = runner.run(request, definition)

    assert attempted_cleanup == runner.build_cleanup_request(request, result)
    cleanup = runner.cleanup(attempted_cleanup, definition)
    assert cleanup.disposition is ScenarioCleanupDisposition.CLEANED
    assert cleanup.remaining_count == 0


@pytest.mark.parametrize(
    ("field", "value"),
    (
        ("namespace_id", "foreign-namespace"),
        ("cleanup_manifest_sha256", "0" * 64),
    ),
)
def test_cleanup_rejects_ownership_mismatch_before_deletion(
    tmp_path: Path,
    field: str,
    value: str,
) -> None:
    definition = _FileScenario(tmp_path)
    runner = ScenarioRunner(clock=_StepClock())
    request = _request(
        _fault(ScenarioFaultPoint.UNINTERRUPTED, ScenarioFaultAction.NONE)
    )
    result = runner.run(request, definition)
    cleanup_request = runner.build_cleanup_request(request, result)
    payload = cleanup_request.model_dump(mode="json")
    payload[field] = value
    mismatched = ScenarioCleanupRequest(**payload)

    cleanup = runner.cleanup(mismatched, definition)

    assert cleanup.disposition is ScenarioCleanupDisposition.FAILED
    assert cleanup.failure_code == "cleanup_ownership_mismatch"
    assert definition.line_count(result.fixture.namespace_id) == 1
    assert definition.cleanup_namespaces == []


def test_cleanup_failure_is_reported_separately_from_the_run(tmp_path: Path) -> None:
    definition = _FileScenario(tmp_path, cleanup_failure=True)
    runner = ScenarioRunner(clock=_StepClock())
    request = _request(
        _fault(
            ScenarioFaultPoint.POST_RESPONSE,
            ScenarioFaultAction.DROP_RESPONSE,
        )
    )
    result = runner.run(request, definition)
    result_bytes = canonical_json_bytes(result)

    cleanup = runner.cleanup(
        runner.build_cleanup_request(request, result),
        definition,
    )

    assert cleanup.disposition is ScenarioCleanupDisposition.FAILED
    assert cleanup.failure_code == "cleanup_failed"
    assert cleanup.removed_count == 0
    assert cleanup.remaining_count is None
    assert definition.line_count(result.fixture.namespace_id) == 1
    assert canonical_json_bytes(result) == result_bytes


@pytest.mark.parametrize(
    ("definition_kwargs", "failure_code"),
    (
        ({"cleanup_reports_undeclared": True}, "cleanup_failed"),
        ({"cleanup_reports_zero": True}, "cleanup_count_inconsistent"),
    ),
)
def test_cleanup_fails_closed_on_scope_or_counter_contradictions(
    tmp_path: Path,
    definition_kwargs: dict[str, bool],
    failure_code: str,
) -> None:
    definition = _FileScenario(tmp_path, **definition_kwargs)
    runner = ScenarioRunner(clock=_StepClock())
    request = _request(
        _fault(ScenarioFaultPoint.UNINTERRUPTED, ScenarioFaultAction.NONE)
    )
    result = runner.run(request, definition)

    cleanup = runner.cleanup(
        runner.build_cleanup_request(request, result),
        definition,
    )

    assert cleanup.disposition is ScenarioCleanupDisposition.FAILED
    assert cleanup.failure_code == failure_code
    assert cleanup.remaining_count is None
