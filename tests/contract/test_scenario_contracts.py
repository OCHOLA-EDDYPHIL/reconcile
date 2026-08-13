"""Cross-field invariants for public scenario contracts."""

from __future__ import annotations

import json
from collections.abc import Callable
from datetime import timedelta

import pytest
from pydantic import BaseModel, ValidationError

from reconcile.contracts import (
    SCENARIO_CLEANUP_RESULT_VERSION,
    SCENARIO_FAULT_TRACE_VERSION,
    AmbiguityKind,
    ScenarioCallerObservation,
    ScenarioCleanupDisposition,
    ScenarioCleanupRequest,
    ScenarioCleanupResult,
    ScenarioFaultAction,
    ScenarioFaultInstruction,
    ScenarioFaultPoint,
    ScenarioFaultTrace,
    ScenarioRunRequest,
    ScenarioRunResult,
    ScenarioTraceEvent,
    ScenarioTransportEvent,
    ScenarioWorkerTermination,
    canonical_json_bytes,
    canonical_sha256,
)
from tests.contract._factories import (
    NOW,
    make_cleanup_request,
    make_cleanup_result,
    make_scenario_request,
    make_scenario_result,
    make_scenario_trace,
)

pytestmark = pytest.mark.contract

_LEGAL_FAULTS = (
    (ScenarioFaultPoint.UNINTERRUPTED, ScenarioFaultAction.NONE),
    (ScenarioFaultPoint.PRE_DISPATCH, ScenarioFaultAction.SUPPRESS_DISPATCH),
    (ScenarioFaultPoint.PRE_COMMIT, ScenarioFaultAction.INTERRUPT_PROCESS),
    (ScenarioFaultPoint.POST_COMMIT, ScenarioFaultAction.INTERRUPT_PROCESS),
    (ScenarioFaultPoint.POST_RESPONSE, ScenarioFaultAction.DROP_RESPONSE),
    (ScenarioFaultPoint.POST_RESPONSE, ScenarioFaultAction.DELAY_RESPONSE),
)

_EXPECTED_EVENTS = {
    (
        ScenarioFaultPoint.UNINTERRUPTED,
        ScenarioFaultAction.NONE,
    ): (
        ScenarioTransportEvent.RUN_STARTED,
        ScenarioTransportEvent.DISPATCH_STARTED,
        ScenarioTransportEvent.PRE_COMMIT_REACHED,
        ScenarioTransportEvent.POST_COMMIT_REACHED,
        ScenarioTransportEvent.RESPONSE_AVAILABLE,
        ScenarioTransportEvent.RESPONSE_OBSERVED,
        ScenarioTransportEvent.RUN_COMPLETED,
    ),
    (
        ScenarioFaultPoint.PRE_DISPATCH,
        ScenarioFaultAction.SUPPRESS_DISPATCH,
    ): (
        ScenarioTransportEvent.RUN_STARTED,
        ScenarioTransportEvent.DISPATCH_SUPPRESSED,
        ScenarioTransportEvent.RUN_COMPLETED,
    ),
    (
        ScenarioFaultPoint.PRE_COMMIT,
        ScenarioFaultAction.INTERRUPT_PROCESS,
    ): (
        ScenarioTransportEvent.RUN_STARTED,
        ScenarioTransportEvent.DISPATCH_STARTED,
        ScenarioTransportEvent.PRE_COMMIT_REACHED,
        ScenarioTransportEvent.WORKER_INTERRUPTED,
        ScenarioTransportEvent.RUN_COMPLETED,
    ),
    (
        ScenarioFaultPoint.POST_COMMIT,
        ScenarioFaultAction.INTERRUPT_PROCESS,
    ): (
        ScenarioTransportEvent.RUN_STARTED,
        ScenarioTransportEvent.DISPATCH_STARTED,
        ScenarioTransportEvent.PRE_COMMIT_REACHED,
        ScenarioTransportEvent.POST_COMMIT_REACHED,
        ScenarioTransportEvent.WORKER_INTERRUPTED,
        ScenarioTransportEvent.RUN_COMPLETED,
    ),
    (
        ScenarioFaultPoint.POST_RESPONSE,
        ScenarioFaultAction.DROP_RESPONSE,
    ): (
        ScenarioTransportEvent.RUN_STARTED,
        ScenarioTransportEvent.DISPATCH_STARTED,
        ScenarioTransportEvent.PRE_COMMIT_REACHED,
        ScenarioTransportEvent.POST_COMMIT_REACHED,
        ScenarioTransportEvent.RESPONSE_AVAILABLE,
        ScenarioTransportEvent.RESPONSE_DROPPED,
        ScenarioTransportEvent.RUN_COMPLETED,
    ),
    (
        ScenarioFaultPoint.POST_RESPONSE,
        ScenarioFaultAction.DELAY_RESPONSE,
    ): (
        ScenarioTransportEvent.RUN_STARTED,
        ScenarioTransportEvent.DISPATCH_STARTED,
        ScenarioTransportEvent.PRE_COMMIT_REACHED,
        ScenarioTransportEvent.POST_COMMIT_REACHED,
        ScenarioTransportEvent.RESPONSE_AVAILABLE,
        ScenarioTransportEvent.RESPONSE_DELAY_STARTED,
        ScenarioTransportEvent.RESPONSE_OBSERVED,
        ScenarioTransportEvent.RUN_COMPLETED,
    ),
}


def _payload(model: BaseModel) -> dict[str, object]:
    return json.loads(canonical_json_bytes(model))


def _trace_for(
    point: ScenarioFaultPoint,
    action: ScenarioFaultAction,
    *,
    caller_observation: ScenarioCallerObservation | None = None,
    events: tuple[ScenarioTransportEvent, ...] | None = None,
    delay_ms: int | None = None,
    worker_termination: ScenarioWorkerTermination | None = None,
    exit_code: int | None = None,
    signal: int | None = None,
) -> ScenarioFaultTrace:
    request = make_scenario_request()
    event_kinds = events or _EXPECTED_EVENTS[(point, action)]
    if caller_observation is None:
        if action is ScenarioFaultAction.SUPPRESS_DISPATCH:
            caller_observation = ScenarioCallerObservation.NOT_DISPATCHED
        elif action in {
            ScenarioFaultAction.INTERRUPT_PROCESS,
            ScenarioFaultAction.DROP_RESPONSE,
        }:
            caller_observation = ScenarioCallerObservation.NO_RESPONSE
        else:
            caller_observation = ScenarioCallerObservation.VALUE_RESPONSE
    if worker_termination is None:
        worker_termination = (
            ScenarioWorkerTermination.NOT_STARTED
            if action is ScenarioFaultAction.SUPPRESS_DISPATCH
            else ScenarioWorkerTermination.SIGNALED
            if action is ScenarioFaultAction.INTERRUPT_PROCESS
            else ScenarioWorkerTermination.EXITED
        )
    if worker_termination is ScenarioWorkerTermination.EXITED and exit_code is None:
        exit_code = 0
    if worker_termination is ScenarioWorkerTermination.SIGNALED and signal is None:
        signal = 9
    applied_delay = (
        (25 if action is ScenarioFaultAction.DELAY_RESPONSE else 0)
        if delay_ms is None
        else delay_ms
    )
    response_available = ScenarioTransportEvent.RESPONSE_AVAILABLE in event_kinds
    completed_at = NOW + timedelta(milliseconds=len(event_kinds) - 1)
    return ScenarioFaultTrace(
        schema_version=SCENARIO_FAULT_TRACE_VERSION,
        scenario=request.scenario,
        run_id=request.run_id,
        investigation_id=request.investigation_id,
        operation_id=request.operation_id,
        invocation_id=request.invocation_id,
        function_call_id=request.function_call_id,
        configured_fault=ScenarioFaultInstruction(
            point=point,
            action=action,
            delay_ms=applied_delay,
        ),
        events=tuple(
            ScenarioTraceEvent(
                sequence=index,
                event=event,
                occurred_at=NOW + timedelta(milliseconds=index - 1),
            )
            for index, event in enumerate(event_kinds, start=1)
        ),
        caller_observation=caller_observation,
        worker_termination=worker_termination,
        exit_code=exit_code,
        signal=signal,
        applied_delay_ms=applied_delay,
        response_sha256="a" * 64 if response_available else None,
        response_byte_count=128 if response_available else None,
        started_at=NOW,
        completed_at=completed_at,
    )


def _result_payload(
    trace: ScenarioFaultTrace,
    ambiguity_kind: AmbiguityKind | None,
) -> dict[str, object]:
    payload = _payload(make_scenario_result())
    payload["trace"] = _payload(trace)
    if ambiguity_kind is None:
        payload["execution_envelope"] = None
    else:
        envelope = payload["execution_envelope"]
        assert isinstance(envelope, dict)
        ambiguity = envelope["ambiguity"]
        assert isinstance(ambiguity, dict)
        ambiguity["kind"] = ambiguity_kind.value
        ambiguity["observed_at"] = trace.events[-2].occurred_at.isoformat()
    return payload


@pytest.mark.parametrize(("point", "action"), _LEGAL_FAULTS)
def test_only_supported_fault_point_action_pairs_are_accepted(
    point: ScenarioFaultPoint,
    action: ScenarioFaultAction,
) -> None:
    delay_ms = 1 if action is ScenarioFaultAction.DELAY_RESPONSE else 0

    instruction = ScenarioFaultInstruction(
        point=point,
        action=action,
        delay_ms=delay_ms,
    )

    assert instruction.point is point
    assert instruction.action is action


_ILLEGAL_FAULTS = tuple(
    (point, action)
    for point in ScenarioFaultPoint
    for action in ScenarioFaultAction
    if (point, action) not in _LEGAL_FAULTS
)


@pytest.mark.parametrize(("point", "action"), _ILLEGAL_FAULTS)
def test_unsupported_fault_point_action_pairs_are_rejected(
    point: ScenarioFaultPoint,
    action: ScenarioFaultAction,
) -> None:
    delay_ms = 1 if action is ScenarioFaultAction.DELAY_RESPONSE else 0

    with pytest.raises(ValidationError, match="not a supported combination"):
        ScenarioFaultInstruction(
            point=point,
            action=action,
            delay_ms=delay_ms,
        )


@pytest.mark.parametrize(
    ("point", "action", "delay_ms"),
    (
        (
            ScenarioFaultPoint.POST_RESPONSE,
            ScenarioFaultAction.DELAY_RESPONSE,
            0,
        ),
        (ScenarioFaultPoint.UNINTERRUPTED, ScenarioFaultAction.NONE, 1),
        (
            ScenarioFaultPoint.POST_RESPONSE,
            ScenarioFaultAction.DROP_RESPONSE,
            1,
        ),
    ),
)
def test_only_delayed_responses_carry_a_positive_delay(
    point: ScenarioFaultPoint,
    action: ScenarioFaultAction,
    delay_ms: int,
) -> None:
    with pytest.raises(ValidationError, match="positive delay"):
        ScenarioFaultInstruction(point=point, action=action, delay_ms=delay_ms)


@pytest.mark.parametrize(("point", "action"), _LEGAL_FAULTS)
def test_each_configured_fault_has_one_exact_normal_transport_path(
    point: ScenarioFaultPoint,
    action: ScenarioFaultAction,
) -> None:
    trace = _trace_for(point, action)

    assert (
        tuple(event.event for event in trace.events)
        == _EXPECTED_EVENTS[(point, action)]
    )
    assert trace.events[0].occurred_at == trace.started_at
    assert trace.events[-1].occurred_at == trace.completed_at


@pytest.mark.parametrize(
    ("index", "replacement"),
    (
        (2, ScenarioTransportEvent.POST_COMMIT_REACHED),
        (4, ScenarioTransportEvent.RESPONSE_OBSERVED),
        (5, ScenarioTransportEvent.RESPONSE_OBSERVED),
        (6, ScenarioTransportEvent.WORKER_INTERRUPTED),
    ),
)
def test_normal_transport_path_rejects_missing_reordered_or_spurious_events(
    index: int,
    replacement: ScenarioTransportEvent,
) -> None:
    payload = _payload(make_scenario_trace())
    events = payload["events"]
    assert isinstance(events, list)
    event = events[index]
    assert isinstance(event, dict)
    event["event"] = replacement.value

    with pytest.raises(ValidationError, match="configured fault"):
        ScenarioFaultTrace.model_validate_json(json.dumps(payload))


def test_trace_rejects_an_omitted_transport_checkpoint() -> None:
    payload = _payload(make_scenario_trace())
    events = payload["events"]
    assert isinstance(events, list)
    events.pop(3)
    for sequence, event in enumerate(events, start=1):
        assert isinstance(event, dict)
        event["sequence"] = sequence

    with pytest.raises(ValidationError, match="configured fault"):
        ScenarioFaultTrace.model_validate_json(json.dumps(payload))


def test_proxy_response_availability_is_not_caller_observation() -> None:
    trace = make_scenario_trace()
    event_kinds = tuple(event.event for event in trace.events)

    assert ScenarioTransportEvent.RESPONSE_AVAILABLE in event_kinds
    assert ScenarioTransportEvent.RESPONSE_DROPPED in event_kinds
    assert ScenarioTransportEvent.RESPONSE_OBSERVED not in event_kinds
    assert trace.caller_observation is ScenarioCallerObservation.NO_RESPONSE
    assert trace.response_sha256 == "a" * 64
    assert trace.response_byte_count == 128

    payload = _payload(trace)
    payload["caller_observation"] = ScenarioCallerObservation.VALUE_RESPONSE.value
    with pytest.raises(ValidationError, match="caller observation"):
        ScenarioFaultTrace.model_validate_json(json.dumps(payload))


def test_response_identity_exists_exactly_when_the_proxy_has_a_response() -> None:
    available = _payload(make_scenario_trace())
    available["response_sha256"] = None
    with pytest.raises(ValidationError, match="bounded response identity"):
        ScenarioFaultTrace.model_validate_json(json.dumps(available))

    unavailable = _payload(
        _trace_for(
            ScenarioFaultPoint.PRE_COMMIT,
            ScenarioFaultAction.INTERRUPT_PROCESS,
        )
    )
    unavailable["response_sha256"] = "b" * 64
    unavailable["response_byte_count"] = 64
    with pytest.raises(ValidationError, match="bounded response identity"):
        ScenarioFaultTrace.model_validate_json(json.dumps(unavailable))


def test_delayed_response_is_available_before_it_is_observed() -> None:
    trace = _trace_for(
        ScenarioFaultPoint.POST_RESPONSE,
        ScenarioFaultAction.DELAY_RESPONSE,
        caller_observation=ScenarioCallerObservation.ERROR_RESPONSE,
    )
    events = tuple(event.event for event in trace.events)

    assert events.index(ScenarioTransportEvent.RESPONSE_AVAILABLE) < events.index(
        ScenarioTransportEvent.RESPONSE_DELAY_STARTED
    )
    assert events.index(ScenarioTransportEvent.RESPONSE_DELAY_STARTED) < events.index(
        ScenarioTransportEvent.RESPONSE_OBSERVED
    )
    assert trace.caller_observation is ScenarioCallerObservation.ERROR_RESPONSE
    assert trace.applied_delay_ms == trace.configured_fault.delay_ms


@pytest.mark.parametrize(
    "events",
    (
        (
            ScenarioTransportEvent.RUN_STARTED,
            ScenarioTransportEvent.DISPATCH_STARTED,
            ScenarioTransportEvent.RESPONSE_AVAILABLE,
            ScenarioTransportEvent.RESPONSE_OBSERVED,
            ScenarioTransportEvent.RUN_COMPLETED,
        ),
        (
            ScenarioTransportEvent.RUN_STARTED,
            ScenarioTransportEvent.DISPATCH_STARTED,
            ScenarioTransportEvent.PRE_COMMIT_REACHED,
            ScenarioTransportEvent.RESPONSE_AVAILABLE,
            ScenarioTransportEvent.RESPONSE_OBSERVED,
            ScenarioTransportEvent.RUN_COMPLETED,
        ),
    ),
)
def test_uninterrupted_path_accepts_a_delivered_error_before_commit(
    events: tuple[ScenarioTransportEvent, ...],
) -> None:
    trace = _trace_for(
        ScenarioFaultPoint.UNINTERRUPTED,
        ScenarioFaultAction.NONE,
        events=events,
        caller_observation=ScenarioCallerObservation.ERROR_RESPONSE,
        worker_termination=ScenarioWorkerTermination.EXITED,
        exit_code=0,
    )

    assert trace.caller_observation is ScenarioCallerObservation.ERROR_RESPONSE
    assert ScenarioTransportEvent.POST_COMMIT_REACHED not in events

    payload = _payload(trace)
    payload["caller_observation"] = ScenarioCallerObservation.VALUE_RESPONSE.value
    with pytest.raises(ValidationError, match="explicit tool error"):
        ScenarioFaultTrace.model_validate_json(json.dumps(payload))


@pytest.mark.parametrize(
    ("trace_factory", "ambiguity_kind"),
    (
        (
            lambda: _trace_for(
                ScenarioFaultPoint.PRE_DISPATCH,
                ScenarioFaultAction.SUPPRESS_DISPATCH,
            ),
            None,
        ),
        (
            lambda: _trace_for(
                ScenarioFaultPoint.UNINTERRUPTED,
                ScenarioFaultAction.NONE,
            ),
            None,
        ),
        (
            lambda: _trace_for(
                ScenarioFaultPoint.POST_RESPONSE,
                ScenarioFaultAction.DELAY_RESPONSE,
            ),
            None,
        ),
        (
            lambda: _trace_for(
                ScenarioFaultPoint.PRE_COMMIT,
                ScenarioFaultAction.INTERRUPT_PROCESS,
            ),
            AmbiguityKind.PROCESS_INTERRUPTED,
        ),
        (
            lambda: _trace_for(
                ScenarioFaultPoint.POST_COMMIT,
                ScenarioFaultAction.INTERRUPT_PROCESS,
            ),
            AmbiguityKind.PROCESS_INTERRUPTED,
        ),
        (
            make_scenario_trace,
            AmbiguityKind.MISSING_TOOL_RESULT,
        ),
    ),
)
def test_envelope_exists_iff_a_dispatched_call_has_no_caller_response(
    trace_factory: Callable[[], ScenarioFaultTrace],
    ambiguity_kind: AmbiguityKind | None,
) -> None:
    trace = trace_factory()
    payload = _result_payload(trace, ambiguity_kind)

    result = ScenarioRunResult.model_validate_json(json.dumps(payload))

    assert (result.execution_envelope is not None) is (ambiguity_kind is not None)

    if ambiguity_kind is None:
        payload["execution_envelope"] = _payload(make_scenario_result())[
            "execution_envelope"
        ]
    else:
        payload["execution_envelope"] = None
    with pytest.raises(ValidationError, match="require an envelope"):
        ScenarioRunResult.model_validate_json(json.dumps(payload))


def test_interruption_after_proxy_availability_remains_no_response() -> None:
    events = (
        ScenarioTransportEvent.RUN_STARTED,
        ScenarioTransportEvent.DISPATCH_STARTED,
        ScenarioTransportEvent.PRE_COMMIT_REACHED,
        ScenarioTransportEvent.POST_COMMIT_REACHED,
        ScenarioTransportEvent.RESPONSE_AVAILABLE,
        ScenarioTransportEvent.WORKER_INTERRUPTED,
        ScenarioTransportEvent.RUN_COMPLETED,
    )
    trace = _trace_for(
        ScenarioFaultPoint.POST_RESPONSE,
        ScenarioFaultAction.DROP_RESPONSE,
        events=events,
        caller_observation=ScenarioCallerObservation.NO_RESPONSE,
        worker_termination=ScenarioWorkerTermination.SIGNALED,
        signal=9,
    )
    payload = _result_payload(trace, AmbiguityKind.PROCESS_INTERRUPTED)

    result = ScenarioRunResult.model_validate_json(json.dumps(payload))

    assert result.execution_envelope is not None
    assert result.execution_envelope.ambiguity.kind is AmbiguityKind.PROCESS_INTERRUPTED


@pytest.mark.parametrize(
    ("field", "replacement"),
    (
        ("scenario", {"name": "other-scenario", "version": "1.0.0"}),
        ("run_id", "run-other"),
        ("investigation_id", "investigation-other"),
        ("operation_id", "operation-other"),
        ("invocation_id", "invocation-other"),
        ("function_call_id", "call-other"),
    ),
)
def test_result_and_trace_require_the_same_stable_identities(
    field: str,
    replacement: object,
) -> None:
    payload = _payload(make_scenario_result())
    trace = payload["trace"]
    assert isinstance(trace, dict)
    trace[field] = replacement

    with pytest.raises(ValidationError, match="trace identities must match"):
        ScenarioRunResult.model_validate_json(json.dumps(payload))


@pytest.mark.parametrize(
    ("path", "replacement"),
    (
        (("investigation_id",), "investigation-other"),
        (("operation_id",), "operation-other"),
        (("context", "invocation", "invocation_id"), "invocation-other"),
        (("context", "invocation", "function_call_id"), "call-other"),
    ),
)
def test_result_and_envelope_require_the_same_stable_identities(
    path: tuple[str, ...],
    replacement: object,
) -> None:
    payload = _payload(make_scenario_result())
    envelope = payload["execution_envelope"]
    assert isinstance(envelope, dict)
    cursor = envelope
    for part in path[:-1]:
        child = cursor[part]
        assert isinstance(child, dict)
        cursor = child
    cursor[path[-1]] = replacement

    with pytest.raises(ValidationError, match="execution envelope"):
        ScenarioRunResult.model_validate_json(json.dumps(payload))


def test_envelope_ambiguity_matches_the_trace_and_occurs_within_it() -> None:
    wrong_kind = _payload(make_scenario_result())
    envelope = wrong_kind["execution_envelope"]
    assert isinstance(envelope, dict)
    ambiguity = envelope["ambiguity"]
    assert isinstance(ambiguity, dict)
    ambiguity["kind"] = AmbiguityKind.PROCESS_INTERRUPTED.value
    with pytest.raises(ValidationError, match="ambiguity must match"):
        ScenarioRunResult.model_validate_json(json.dumps(wrong_kind))

    outside = _payload(make_scenario_result())
    envelope = outside["execution_envelope"]
    assert isinstance(envelope, dict)
    ambiguity = envelope["ambiguity"]
    assert isinstance(ambiguity, dict)
    ambiguity["observed_at"] = (NOW + timedelta(seconds=1)).isoformat()
    with pytest.raises(ValidationError, match="within the transport trace"):
        ScenarioRunResult.model_validate_json(json.dumps(outside))


def test_scenario_factory_chain_preserves_request_and_fixture_identity() -> None:
    request = make_scenario_request()
    result = make_scenario_result()
    cleanup_request = make_cleanup_request()
    cleanup_result = make_cleanup_result()

    assert result.request_sha256 == canonical_sha256(request)
    assert result.scenario == request.scenario == cleanup_request.scenario
    assert result.run_id == request.run_id == cleanup_request.run_id
    assert result.fixture.namespace_id == cleanup_request.namespace_id
    assert (
        result.fixture.cleanup_manifest_sha256
        == cleanup_request.cleanup_manifest_sha256
        == cleanup_result.cleanup_manifest_sha256
    )
    assert cleanup_result.cleanup_request_sha256 == canonical_sha256(cleanup_request)


def test_cleanup_request_is_strict_and_carries_stable_run_identity() -> None:
    request = make_cleanup_request()
    scenario_request = make_scenario_request()

    assert request.run_id == scenario_request.run_id
    assert request.investigation_id == scenario_request.investigation_id
    assert request.operation_id == scenario_request.operation_id
    assert request.invocation_id == scenario_request.invocation_id
    assert request.function_call_id == scenario_request.function_call_id
    assert request.seed == scenario_request.seed

    payload = _payload(request)
    payload["target_state"] = "committed"
    with pytest.raises(ValidationError):
        ScenarioCleanupRequest.model_validate_json(json.dumps(payload))


@pytest.mark.parametrize(
    ("disposition", "removed", "remaining", "failure_code"),
    (
        (ScenarioCleanupDisposition.CLEANED, 1, 0, None),
        (ScenarioCleanupDisposition.ALREADY_CLEAN, 0, 0, None),
        (ScenarioCleanupDisposition.FAILED, 0, 1, "cleanup-failed"),
        (ScenarioCleanupDisposition.FAILED, 1, None, "cleanup-unverified"),
    ),
)
def test_cleanup_dispositions_have_distinct_verified_counters(
    disposition: ScenarioCleanupDisposition,
    removed: int,
    remaining: int | None,
    failure_code: str | None,
) -> None:
    payload = _payload(make_cleanup_result())
    payload["disposition"] = disposition.value
    payload["removed_count"] = removed
    payload["remaining_count"] = remaining
    payload["failure_code"] = failure_code

    result = ScenarioCleanupResult.model_validate_json(json.dumps(payload))

    assert result.disposition is disposition


@pytest.mark.parametrize(
    ("disposition", "removed", "remaining", "failure_code"),
    (
        (ScenarioCleanupDisposition.CLEANED, 0, 0, None),
        (ScenarioCleanupDisposition.CLEANED, 1, 1, None),
        (ScenarioCleanupDisposition.CLEANED, 1, 0, "cleanup-failed"),
        (ScenarioCleanupDisposition.ALREADY_CLEAN, 1, 0, None),
        (ScenarioCleanupDisposition.ALREADY_CLEAN, 0, 1, None),
        (ScenarioCleanupDisposition.ALREADY_CLEAN, 0, 0, "cleanup-failed"),
        (ScenarioCleanupDisposition.FAILED, 0, 0, "cleanup-failed"),
        (ScenarioCleanupDisposition.FAILED, 0, 1, None),
    ),
)
def test_cleanup_rejects_counters_that_contradict_the_disposition(
    disposition: ScenarioCleanupDisposition,
    removed: int,
    remaining: int | None,
    failure_code: str | None,
) -> None:
    payload = _payload(make_cleanup_result())
    payload["disposition"] = disposition.value
    payload["removed_count"] = removed
    payload["remaining_count"] = remaining
    payload["failure_code"] = failure_code

    with pytest.raises(ValidationError, match="cleanup counters"):
        ScenarioCleanupResult.model_validate_json(json.dumps(payload))


def test_cleanup_completion_cannot_precede_its_start() -> None:
    payload = _payload(make_cleanup_result())
    payload["completed_at"] = (NOW - timedelta(seconds=1)).isoformat()

    with pytest.raises(ValidationError, match="cannot precede"):
        ScenarioCleanupResult.model_validate_json(json.dumps(payload))


@pytest.mark.parametrize(
    ("model", "factory"),
    (
        (ScenarioRunRequest, make_scenario_request),
        (ScenarioFaultTrace, make_scenario_trace),
        (ScenarioRunResult, make_scenario_result),
        (ScenarioCleanupRequest, make_cleanup_request),
        (ScenarioCleanupResult, make_cleanup_result),
    ),
)
@pytest.mark.parametrize(
    ("field", "value"),
    (
        ("classification", "COMMITTED"),
        ("target_state", "committed"),
        ("evidence", []),
        ("mutation_committed", True),
    ),
)
def test_scenario_contracts_reject_target_truth_classification_and_extra_fields(
    model: type[BaseModel],
    factory: Callable[[], BaseModel],
    field: str,
    value: object,
) -> None:
    payload = _payload(factory())
    payload[field] = value

    with pytest.raises(ValidationError):
        model.model_validate_json(json.dumps(payload))


def test_trace_exposes_only_a_bounded_response_identity() -> None:
    payload = _payload(make_scenario_trace())
    payload["response"] = {"provider": "opaque-payload"}

    with pytest.raises(ValidationError):
        ScenarioFaultTrace.model_validate_json(json.dumps(payload))


def test_nested_fault_instruction_rejects_extra_truth_fields() -> None:
    payload = _payload(make_scenario_request())
    fault = payload["fault"]
    assert isinstance(fault, dict)
    fault["committed"] = True

    with pytest.raises(ValidationError):
        ScenarioRunRequest.model_validate_json(json.dumps(payload))


def test_trace_rejects_unknown_version_and_extra_fields() -> None:
    payload = _payload(make_scenario_trace())
    payload["schema_version"] = "reconcile/scenario-fault-trace/v2"
    with pytest.raises(ValidationError):
        ScenarioFaultTrace.model_validate_json(json.dumps(payload))

    payload["schema_version"] = SCENARIO_FAULT_TRACE_VERSION
    payload["committed"] = True
    with pytest.raises(ValidationError):
        ScenarioFaultTrace.model_validate_json(json.dumps(payload))


def test_cleanup_result_rejects_unknown_version() -> None:
    payload = _payload(make_cleanup_result())
    payload["schema_version"] = "reconcile/scenario-cleanup-result/v2"

    with pytest.raises(ValidationError):
        ScenarioCleanupResult.model_validate_json(json.dumps(payload))

    assert SCENARIO_CLEANUP_RESULT_VERSION.endswith("/v1")
