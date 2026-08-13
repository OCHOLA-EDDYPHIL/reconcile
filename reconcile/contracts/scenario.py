"""Versioned contracts for deterministic local scenario execution."""

from __future__ import annotations

from enum import StrEnum
from typing import Literal

from pydantic import Field, model_validator

from reconcile.contracts.base import (
    AwareDatetime,
    Identifier,
    Sha256Digest,
    StrictModel,
)
from reconcile.contracts.common import AmbiguityKind
from reconcile.contracts.envelope import ExecutionEnvelope

SCENARIO_RUN_REQUEST_VERSION = "reconcile/scenario-run-request/v1"
SCENARIO_FAULT_TRACE_VERSION = "reconcile/scenario-fault-trace/v1"
SCENARIO_RUN_RESULT_VERSION = "reconcile/scenario-run-result/v1"
SCENARIO_CLEANUP_REQUEST_VERSION = "reconcile/scenario-cleanup-request/v1"
SCENARIO_CLEANUP_RESULT_VERSION = "reconcile/scenario-cleanup-result/v1"


class ScenarioFaultPoint(StrEnum):
    UNINTERRUPTED = "UNINTERRUPTED"
    PRE_DISPATCH = "PRE_DISPATCH"
    PRE_COMMIT = "PRE_COMMIT"
    POST_COMMIT = "POST_COMMIT"
    POST_RESPONSE = "POST_RESPONSE"


class ScenarioFaultAction(StrEnum):
    NONE = "NONE"
    SUPPRESS_DISPATCH = "SUPPRESS_DISPATCH"
    INTERRUPT_PROCESS = "INTERRUPT_PROCESS"
    DROP_RESPONSE = "DROP_RESPONSE"
    DELAY_RESPONSE = "DELAY_RESPONSE"


class ScenarioTransportEvent(StrEnum):
    RUN_STARTED = "RUN_STARTED"
    DISPATCH_SUPPRESSED = "DISPATCH_SUPPRESSED"
    DISPATCH_STARTED = "DISPATCH_STARTED"
    PRE_COMMIT_REACHED = "PRE_COMMIT_REACHED"
    POST_COMMIT_REACHED = "POST_COMMIT_REACHED"
    RESPONSE_AVAILABLE = "RESPONSE_AVAILABLE"
    RESPONSE_DELAY_STARTED = "RESPONSE_DELAY_STARTED"
    RESPONSE_DROPPED = "RESPONSE_DROPPED"
    RESPONSE_OBSERVED = "RESPONSE_OBSERVED"
    WORKER_INTERRUPTED = "WORKER_INTERRUPTED"
    RUN_COMPLETED = "RUN_COMPLETED"


class ScenarioCallerObservation(StrEnum):
    NOT_DISPATCHED = "NOT_DISPATCHED"
    VALUE_RESPONSE = "VALUE_RESPONSE"
    ERROR_RESPONSE = "ERROR_RESPONSE"
    NO_RESPONSE = "NO_RESPONSE"


class ScenarioWorkerTermination(StrEnum):
    NOT_STARTED = "NOT_STARTED"
    EXITED = "EXITED"
    SIGNALED = "SIGNALED"


class ScenarioCleanupDisposition(StrEnum):
    CLEANED = "CLEANED"
    ALREADY_CLEAN = "ALREADY_CLEAN"
    FAILED = "FAILED"


class ScenarioRef(StrictModel):
    name: Identifier
    version: Identifier


class ScenarioFaultInstruction(StrictModel):
    point: ScenarioFaultPoint
    action: ScenarioFaultAction
    delay_ms: int = Field(default=0, ge=0, le=60_000)

    @model_validator(mode="after")
    def validate_instruction(self) -> ScenarioFaultInstruction:
        valid = {
            (ScenarioFaultPoint.UNINTERRUPTED, ScenarioFaultAction.NONE),
            (
                ScenarioFaultPoint.PRE_DISPATCH,
                ScenarioFaultAction.SUPPRESS_DISPATCH,
            ),
            (
                ScenarioFaultPoint.PRE_COMMIT,
                ScenarioFaultAction.INTERRUPT_PROCESS,
            ),
            (
                ScenarioFaultPoint.POST_COMMIT,
                ScenarioFaultAction.INTERRUPT_PROCESS,
            ),
            (
                ScenarioFaultPoint.POST_RESPONSE,
                ScenarioFaultAction.DROP_RESPONSE,
            ),
            (
                ScenarioFaultPoint.POST_RESPONSE,
                ScenarioFaultAction.DELAY_RESPONSE,
            ),
        }
        if (self.point, self.action) not in valid:
            raise ValueError("fault point and action are not a supported combination")
        delayed = self.action is ScenarioFaultAction.DELAY_RESPONSE
        if delayed != (self.delay_ms > 0):
            raise ValueError("only delayed responses require a positive delay")
        return self


class ScenarioFixtureRef(StrictModel):
    namespace_id: Identifier
    cleanup_manifest_sha256: Sha256Digest


class ScenarioRunRequest(StrictModel):
    schema_version: Literal[SCENARIO_RUN_REQUEST_VERSION]
    scenario: ScenarioRef
    run_id: Identifier
    investigation_id: Identifier
    operation_id: Identifier
    invocation_id: Identifier
    function_call_id: Identifier | None = None
    seed: int = Field(ge=0, le=2**63 - 1)
    fault: ScenarioFaultInstruction


class ScenarioTraceEvent(StrictModel):
    sequence: int = Field(ge=1, le=16)
    event: ScenarioTransportEvent
    occurred_at: AwareDatetime


def _normal_events(
    fault: ScenarioFaultInstruction,
) -> tuple[ScenarioTransportEvent, ...]:
    start = (ScenarioTransportEvent.RUN_STARTED,)
    dispatch = (*start, ScenarioTransportEvent.DISPATCH_STARTED)
    pre_commit = (*dispatch, ScenarioTransportEvent.PRE_COMMIT_REACHED)
    post_commit = (*pre_commit, ScenarioTransportEvent.POST_COMMIT_REACHED)
    response = (*post_commit, ScenarioTransportEvent.RESPONSE_AVAILABLE)
    completed = (ScenarioTransportEvent.RUN_COMPLETED,)
    definitions = {
        (ScenarioFaultPoint.UNINTERRUPTED, ScenarioFaultAction.NONE): (
            *response,
            ScenarioTransportEvent.RESPONSE_OBSERVED,
            *completed,
        ),
        (
            ScenarioFaultPoint.PRE_DISPATCH,
            ScenarioFaultAction.SUPPRESS_DISPATCH,
        ): (*start, ScenarioTransportEvent.DISPATCH_SUPPRESSED, *completed),
        (
            ScenarioFaultPoint.PRE_COMMIT,
            ScenarioFaultAction.INTERRUPT_PROCESS,
        ): (*pre_commit, ScenarioTransportEvent.WORKER_INTERRUPTED, *completed),
        (
            ScenarioFaultPoint.POST_COMMIT,
            ScenarioFaultAction.INTERRUPT_PROCESS,
        ): (*post_commit, ScenarioTransportEvent.WORKER_INTERRUPTED, *completed),
        (
            ScenarioFaultPoint.POST_RESPONSE,
            ScenarioFaultAction.DROP_RESPONSE,
        ): (*response, ScenarioTransportEvent.RESPONSE_DROPPED, *completed),
        (
            ScenarioFaultPoint.POST_RESPONSE,
            ScenarioFaultAction.DELAY_RESPONSE,
        ): (
            *response,
            ScenarioTransportEvent.RESPONSE_DELAY_STARTED,
            ScenarioTransportEvent.RESPONSE_OBSERVED,
            *completed,
        ),
    }
    return definitions[(fault.point, fault.action)]


def _is_unexpected_interruption(events: tuple[ScenarioTransportEvent, ...]) -> bool:
    progress = (
        ScenarioTransportEvent.RUN_STARTED,
        ScenarioTransportEvent.DISPATCH_STARTED,
        ScenarioTransportEvent.PRE_COMMIT_REACHED,
        ScenarioTransportEvent.POST_COMMIT_REACHED,
        ScenarioTransportEvent.RESPONSE_AVAILABLE,
    )
    if len(events) < 4:
        return False
    prefix = events[:-2]
    return (
        events[-2:]
        == (
            ScenarioTransportEvent.WORKER_INTERRUPTED,
            ScenarioTransportEvent.RUN_COMPLETED,
        )
        and len(prefix) >= 2
        and prefix == progress[: len(prefix)]
    )


def _is_early_error_response(
    fault: ScenarioFaultInstruction,
    events: tuple[ScenarioTransportEvent, ...],
) -> bool:
    if fault != ScenarioFaultInstruction(
        point=ScenarioFaultPoint.UNINTERRUPTED,
        action=ScenarioFaultAction.NONE,
    ):
        return False
    progress = (
        ScenarioTransportEvent.RUN_STARTED,
        ScenarioTransportEvent.DISPATCH_STARTED,
        ScenarioTransportEvent.PRE_COMMIT_REACHED,
    )
    suffix = (
        ScenarioTransportEvent.RESPONSE_AVAILABLE,
        ScenarioTransportEvent.RESPONSE_OBSERVED,
        ScenarioTransportEvent.RUN_COMPLETED,
    )
    prefix = events[:-3]
    return events[-3:] == suffix and prefix in {progress[:2], progress}


class ScenarioFaultTrace(StrictModel):
    schema_version: Literal[SCENARIO_FAULT_TRACE_VERSION]
    scenario: ScenarioRef
    run_id: Identifier
    investigation_id: Identifier
    operation_id: Identifier
    invocation_id: Identifier
    function_call_id: Identifier | None = None
    configured_fault: ScenarioFaultInstruction
    events: tuple[ScenarioTraceEvent, ...] = Field(min_length=1, max_length=16)
    caller_observation: ScenarioCallerObservation
    worker_termination: ScenarioWorkerTermination
    exit_code: int | None = Field(default=None, ge=0, le=255)
    signal: int | None = Field(default=None, ge=1, le=127)
    applied_delay_ms: int = Field(ge=0, le=60_000)
    response_sha256: Sha256Digest | None = None
    response_byte_count: int | None = Field(default=None, ge=0, le=2**63 - 1)
    started_at: AwareDatetime
    completed_at: AwareDatetime

    @model_validator(mode="after")
    def validate_trace(self) -> ScenarioFaultTrace:
        if self.completed_at < self.started_at:
            raise ValueError("scenario completion cannot precede its start")
        sequences = [event.sequence for event in self.events]
        if sequences != list(range(1, len(sequences) + 1)):
            raise ValueError("scenario trace events must be contiguous and ordered")
        timestamps = [event.occurred_at for event in self.events]
        if timestamps != sorted(timestamps):
            raise ValueError("scenario trace timestamps must be ordered")
        if timestamps[0] != self.started_at or timestamps[-1] != self.completed_at:
            raise ValueError("trace boundaries must match the first and last events")

        event_kinds = tuple(event.event for event in self.events)
        normal = event_kinds == _normal_events(self.configured_fault)
        unexpected = _is_unexpected_interruption(event_kinds)
        early_error = _is_early_error_response(self.configured_fault, event_kinds)
        if not normal and not unexpected and not early_error:
            raise ValueError("trace events do not match the configured fault")

        if unexpected:
            if self.caller_observation is not ScenarioCallerObservation.NO_RESPONSE:
                raise ValueError("an interrupted worker cannot deliver a response")
            if self.worker_termination not in {
                ScenarioWorkerTermination.EXITED,
                ScenarioWorkerTermination.SIGNALED,
            }:
                raise ValueError("an interrupted worker must have terminated")
        elif early_error:
            if self.caller_observation is not ScenarioCallerObservation.ERROR_RESPONSE:
                raise ValueError("an early response must be an explicit tool error")
            if self.worker_termination is not ScenarioWorkerTermination.EXITED:
                raise ValueError("a delivered tool error requires a clean worker exit")
        else:
            self._validate_normal_outcome()
        self._validate_termination(
            normal=normal or early_error,
            unexpected=unexpected,
        )

        response_available = ScenarioTransportEvent.RESPONSE_AVAILABLE in event_kinds
        has_response_identity = (
            self.response_sha256 is not None and self.response_byte_count is not None
        )
        if response_available != has_response_identity:
            raise ValueError("available responses require a bounded response identity")

        response_observed = ScenarioTransportEvent.RESPONSE_OBSERVED in event_kinds
        caller_received = self.caller_observation in {
            ScenarioCallerObservation.VALUE_RESPONSE,
            ScenarioCallerObservation.ERROR_RESPONSE,
        }
        if response_observed != caller_received:
            raise ValueError("caller observation must match response delivery")

        delayed = (
            normal
            and self.configured_fault.action is ScenarioFaultAction.DELAY_RESPONSE
        )
        expected_delay = self.configured_fault.delay_ms if delayed else 0
        if self.applied_delay_ms != expected_delay:
            raise ValueError("applied delay does not match the fault instruction")
        return self

    def _validate_normal_outcome(self) -> None:
        action = self.configured_fault.action
        if action is ScenarioFaultAction.SUPPRESS_DISPATCH:
            expected_observation = ScenarioCallerObservation.NOT_DISPATCHED
            expected_termination = ScenarioWorkerTermination.NOT_STARTED
        elif action is ScenarioFaultAction.INTERRUPT_PROCESS:
            expected_observation = ScenarioCallerObservation.NO_RESPONSE
            expected_termination = ScenarioWorkerTermination.SIGNALED
        elif action is ScenarioFaultAction.DROP_RESPONSE:
            expected_observation = ScenarioCallerObservation.NO_RESPONSE
            expected_termination = ScenarioWorkerTermination.EXITED
        else:
            if self.caller_observation not in {
                ScenarioCallerObservation.VALUE_RESPONSE,
                ScenarioCallerObservation.ERROR_RESPONSE,
            }:
                raise ValueError("delivered paths require a caller response")
            expected_observation = self.caller_observation
            expected_termination = ScenarioWorkerTermination.EXITED
        if self.caller_observation is not expected_observation:
            raise ValueError("caller observation does not match the configured fault")
        if self.worker_termination is not expected_termination:
            raise ValueError("worker termination does not match the configured fault")

    def _validate_termination(self, *, normal: bool, unexpected: bool) -> None:
        if self.worker_termination is ScenarioWorkerTermination.EXITED:
            if self.exit_code is None or self.signal is not None:
                raise ValueError("exited workers require only an exit code")
            if normal and not unexpected and self.exit_code != 0:
                raise ValueError("normal worker exits must be successful")
            if unexpected and self.exit_code == 0:
                raise ValueError("unexpected worker exits must be unsuccessful")
        elif self.worker_termination is ScenarioWorkerTermination.SIGNALED:
            if self.signal is None or self.exit_code is not None:
                raise ValueError("signaled workers require only a signal")
        elif self.exit_code is not None or self.signal is not None:
            raise ValueError("unstarted workers cannot carry termination data")


class ScenarioRunResult(StrictModel):
    schema_version: Literal[SCENARIO_RUN_RESULT_VERSION]
    request_sha256: Sha256Digest
    scenario: ScenarioRef
    run_id: Identifier
    investigation_id: Identifier
    operation_id: Identifier
    invocation_id: Identifier
    function_call_id: Identifier | None = None
    fixture: ScenarioFixtureRef
    trace: ScenarioFaultTrace
    execution_envelope: ExecutionEnvelope | None = None

    @model_validator(mode="after")
    def validate_references(self) -> ScenarioRunResult:
        identities = (
            self.scenario,
            self.run_id,
            self.investigation_id,
            self.operation_id,
            self.invocation_id,
            self.function_call_id,
        )
        trace_identities = (
            self.trace.scenario,
            self.trace.run_id,
            self.trace.investigation_id,
            self.trace.operation_id,
            self.trace.invocation_id,
            self.trace.function_call_id,
        )
        if identities != trace_identities:
            raise ValueError("scenario result and trace identities must match")
        ambiguous = (
            self.trace.caller_observation is ScenarioCallerObservation.NO_RESPONSE
        )
        if ambiguous != (self.execution_envelope is not None):
            raise ValueError(
                "only dispatched calls without a response require an envelope"
            )
        if self.execution_envelope is not None:
            envelope = self.execution_envelope
            invocation = envelope.context.invocation
            if (
                envelope.investigation_id != self.investigation_id
                or envelope.operation_id != self.operation_id
                or invocation.invocation_id != self.invocation_id
                or invocation.function_call_id != self.function_call_id
            ):
                raise ValueError(
                    "scenario identifiers must match the execution envelope"
                )
            event_kinds = {event.event for event in self.trace.events}
            expected_kind = (
                AmbiguityKind.MISSING_TOOL_RESULT
                if ScenarioTransportEvent.RESPONSE_DROPPED in event_kinds
                else AmbiguityKind.PROCESS_INTERRUPTED
            )
            if envelope.ambiguity.kind is not expected_kind:
                raise ValueError("envelope ambiguity must match the transport trace")
            if (
                not self.trace.started_at
                <= envelope.ambiguity.observed_at
                <= (self.trace.completed_at)
            ):
                raise ValueError("ambiguity time must fall within the transport trace")
        return self


class ScenarioCleanupRequest(StrictModel):
    schema_version: Literal[SCENARIO_CLEANUP_REQUEST_VERSION]
    scenario: ScenarioRef
    run_id: Identifier
    investigation_id: Identifier
    operation_id: Identifier
    invocation_id: Identifier
    function_call_id: Identifier | None = None
    seed: int = Field(ge=0, le=2**63 - 1)
    namespace_id: Identifier
    cleanup_manifest_sha256: Sha256Digest


class ScenarioCleanupResult(StrictModel):
    schema_version: Literal[SCENARIO_CLEANUP_RESULT_VERSION]
    cleanup_request_sha256: Sha256Digest
    run_id: Identifier
    namespace_id: Identifier
    cleanup_manifest_sha256: Sha256Digest
    disposition: ScenarioCleanupDisposition
    removed_count: int = Field(ge=0, le=2**63 - 1)
    remaining_count: int | None = Field(default=None, ge=0, le=2**63 - 1)
    started_at: AwareDatetime
    completed_at: AwareDatetime
    failure_code: Identifier | None = None

    @model_validator(mode="after")
    def validate_cleanup(self) -> ScenarioCleanupResult:
        if self.completed_at < self.started_at:
            raise ValueError("cleanup completion cannot precede its start")
        if self.disposition is ScenarioCleanupDisposition.CLEANED:
            valid = (
                self.removed_count > 0
                and self.remaining_count == 0
                and self.failure_code is None
            )
        elif self.disposition is ScenarioCleanupDisposition.ALREADY_CLEAN:
            valid = (
                self.removed_count == 0
                and self.remaining_count == 0
                and self.failure_code is None
            )
        else:
            valid = self.failure_code is not None and self.remaining_count != 0
        if not valid:
            raise ValueError("cleanup counters do not match the disposition")
        return self


__all__ = [
    "SCENARIO_CLEANUP_REQUEST_VERSION",
    "SCENARIO_CLEANUP_RESULT_VERSION",
    "SCENARIO_FAULT_TRACE_VERSION",
    "SCENARIO_RUN_REQUEST_VERSION",
    "SCENARIO_RUN_RESULT_VERSION",
    "ScenarioCallerObservation",
    "ScenarioCleanupDisposition",
    "ScenarioCleanupRequest",
    "ScenarioCleanupResult",
    "ScenarioFaultAction",
    "ScenarioFaultInstruction",
    "ScenarioFaultPoint",
    "ScenarioFaultTrace",
    "ScenarioFixtureRef",
    "ScenarioRef",
    "ScenarioRunRequest",
    "ScenarioRunResult",
    "ScenarioTraceEvent",
    "ScenarioTransportEvent",
    "ScenarioWorkerTermination",
]
