"""Deterministic subprocess runner for ambiguous mutation outcomes."""

from __future__ import annotations

import hashlib
import multiprocessing
import time
import warnings
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from multiprocessing.connection import Connection
from typing import Protocol

from reconcile.contracts import (
    SCENARIO_CLEANUP_REQUEST_VERSION,
    SCENARIO_CLEANUP_RESULT_VERSION,
    SCENARIO_FAULT_TRACE_VERSION,
    SCENARIO_RUN_RESULT_VERSION,
    AmbiguityKind,
    AmbiguousExecution,
    ExecutionEnvelope,
    ScenarioCallerObservation,
    ScenarioCleanupDisposition,
    ScenarioCleanupRequest,
    ScenarioCleanupResult,
    ScenarioFaultAction,
    ScenarioFaultPoint,
    ScenarioFaultTrace,
    ScenarioFixtureRef,
    ScenarioRef,
    ScenarioRunRequest,
    ScenarioRunResult,
    ScenarioTraceEvent,
    ScenarioTransportEvent,
    ScenarioWorkerTermination,
    canonical_json_bytes,
    canonical_sha256,
    decode_contract,
)
from reconcile.contracts.base import JsonObject, canonical_json_value_bytes

_CHILD_READY = "child_ready"
_CHECKPOINT = "checkpoint"
_CONTINUE = "continue"
_RESPONSE = "response"
_RESPONSE_ACK = "response_ack"
_WORKER_ERROR = "worker_error"
_WORKER_ERROR_EXIT_CODE = 70
_WORKER_TIMEOUT_SECONDS = 10.0


class ScenarioClock(Protocol):
    def now(self) -> datetime:
        """Return an aware timestamp for the next transport event."""


class _SystemClock:
    def now(self) -> datetime:
        return datetime.now(UTC)


@dataclass(frozen=True, slots=True)
class ScenarioIdentifiers:
    run_id: str
    investigation_id: str
    operation_id: str
    invocation_id: str
    function_call_id: str | None


@dataclass(frozen=True, slots=True)
class ScenarioPlan:
    """Fault-independent inputs available to a scenario definition."""

    scenario: ScenarioRef
    identifiers: ScenarioIdentifiers
    seed: int
    namespace_id: str


@dataclass(frozen=True, slots=True)
class ScenarioCleanupManifest:
    """Logical resources that one scenario cleanup is permitted to remove."""

    resource_ids: tuple[str, ...]

    def __post_init__(self) -> None:
        _validate_resource_ids(self.resource_ids, allow_empty=False)


@dataclass(frozen=True, slots=True)
class ScenarioCleanupOutcome:
    """Logical resources a cleanup adapter reports removing."""

    removed_resource_ids: tuple[str, ...]

    def __post_init__(self) -> None:
        _validate_resource_ids(self.removed_resource_ids, allow_empty=True)


@dataclass(frozen=True, slots=True)
class ScenarioPreparation:
    """Definition-owned material sealed before setup or dispatch."""

    execution_envelope: ExecutionEnvelope
    cleanup_manifest: ScenarioCleanupManifest


@dataclass(frozen=True, slots=True)
class PreparedScenario:
    """Canonical scenario material with no fault configuration or trace oracle."""

    plan: ScenarioPlan
    execution_envelope_bytes: bytes
    cleanup_resource_ids: tuple[str, ...]
    cleanup_manifest_bytes: bytes
    cleanup_manifest_sha256: str


@dataclass(frozen=True, slots=True)
class ScenarioMutationResponse:
    """A value or explicit tool-error response returned through the proxy."""

    is_error: bool
    payload: JsonObject


class MutationBoundary:
    """Child-side synchronization points surrounding the target commit."""

    def __init__(self, connection: Connection) -> None:
        self._connection = connection

    def before_commit(self) -> None:
        self._checkpoint(ScenarioFaultPoint.PRE_COMMIT)

    def after_commit(self) -> None:
        self._checkpoint(ScenarioFaultPoint.POST_COMMIT)

    def _checkpoint(self, point: ScenarioFaultPoint) -> None:
        self._connection.send((_CHECKPOINT, point.value))
        instruction = self._connection.recv()
        if instruction != _CONTINUE:
            raise RuntimeError("scenario runner rejected a mutation checkpoint")


class ScenarioDefinition(Protocol):
    scenario: ScenarioRef

    def prepare(self, plan: ScenarioPlan) -> ScenarioPreparation:
        """Declare the envelope and cleanup scope before target setup."""

    def setup(self, prepared: PreparedScenario) -> None:
        """Create one isolated target namespace idempotently."""

    def mutate(
        self,
        boundary: MutationBoundary,
        prepared: PreparedScenario,
    ) -> ScenarioMutationResponse:
        """Perform one target mutation and cross both commit checkpoints."""

    def remaining(self, prepared: PreparedScenario) -> int | None:
        """Return remaining owned resources, or None when absence is unverified."""

    def cleanup(self, prepared: PreparedScenario) -> ScenarioCleanupOutcome:
        """Remove only manifest-owned resources and identify each removal."""


class ScenarioRunnerError(RuntimeError):
    """The harness could not produce a trustworthy bounded result."""


@dataclass(frozen=True, slots=True)
class _InvocationResult:
    trace: ScenarioFaultTrace
    ambiguity: AmbiguousExecution | None


def _validate_resource_ids(
    resource_ids: tuple[str, ...],
    *,
    allow_empty: bool,
) -> None:
    if type(resource_ids) is not tuple:
        raise TypeError("cleanup resource identifiers must be a tuple")
    minimum = 0 if allow_empty else 1
    if not minimum <= len(resource_ids) <= 128:
        raise ValueError("cleanup resource identifier count is outside bounds")
    if any(type(item) is not str or not 1 <= len(item) <= 256 for item in resource_ids):
        raise ValueError("cleanup resource identifiers must be bounded strings")
    if len(resource_ids) != len(set(resource_ids)):
        raise ValueError("cleanup resource identifiers must be unique")


def _namespace_id(scenario: ScenarioRef, run_id: str) -> str:
    identity = {
        "run_id": run_id,
        "scenario": scenario.model_dump(mode="json"),
    }
    digest = hashlib.sha256(canonical_json_value_bytes(identity)).hexdigest()
    return f"scenario-{digest[:32]}"


def _worker_main(
    connection: Connection,
    mutation: Callable[
        [MutationBoundary, PreparedScenario],
        ScenarioMutationResponse,
    ],
    prepared: PreparedScenario,
) -> None:
    exit_code = 0
    try:
        connection.send((_CHILD_READY, None))
        if connection.recv() != _CONTINUE:
            raise RuntimeError("scenario runner did not dispatch the mutation")
        with warnings.catch_warnings():
            warnings.filterwarnings(
                "ignore",
                message=(
                    r"\[EXPERIMENTAL\] feature "
                    r"FeatureName\.JSON_SCHEMA_FOR_FUNC_DECL is enabled\."
                ),
                category=UserWarning,
                module=r"google\.adk\.models\.llm_request",
            )
            response = mutation(MutationBoundary(connection), prepared)
        if type(response) is not ScenarioMutationResponse:
            raise TypeError("scenario mutation returned an invalid response")
        response_bytes = canonical_json_value_bytes(response.payload)
        connection.send((_RESPONSE, (response.is_error, response_bytes)))
        if connection.recv() != _RESPONSE_ACK:
            raise RuntimeError("scenario runner did not acknowledge the response")
    except BaseException:
        exit_code = _WORKER_ERROR_EXIT_CODE
        try:
            connection.send((_WORKER_ERROR, None))
        except (BrokenPipeError, EOFError, OSError):
            pass
    finally:
        connection.close()
    if exit_code:
        raise SystemExit(exit_code)


class _TraceBuilder:
    def __init__(
        self,
        request: ScenarioRunRequest,
        clock: ScenarioClock,
    ) -> None:
        self._request = request
        self._clock = clock
        self._events: list[ScenarioTraceEvent] = []

    def add(self, event: ScenarioTransportEvent) -> datetime:
        occurred_at = self._clock.now()
        self._events.append(
            ScenarioTraceEvent(
                sequence=len(self._events) + 1,
                event=event,
                occurred_at=occurred_at,
            )
        )
        return occurred_at

    def finish(
        self,
        *,
        caller_observation: ScenarioCallerObservation,
        worker_termination: ScenarioWorkerTermination,
        exit_code: int | None = None,
        signal: int | None = None,
        applied_delay_ms: int = 0,
        response_sha256: str | None = None,
        response_byte_count: int | None = None,
    ) -> ScenarioFaultTrace:
        first = self._events[0].occurred_at
        last = self._events[-1].occurred_at
        request = self._request
        return ScenarioFaultTrace(
            schema_version=SCENARIO_FAULT_TRACE_VERSION,
            scenario=request.scenario,
            run_id=request.run_id,
            investigation_id=request.investigation_id,
            operation_id=request.operation_id,
            invocation_id=request.invocation_id,
            function_call_id=request.function_call_id,
            configured_fault=request.fault,
            events=tuple(self._events),
            caller_observation=caller_observation,
            worker_termination=worker_termination,
            exit_code=exit_code,
            signal=signal,
            applied_delay_ms=applied_delay_ms,
            response_sha256=response_sha256,
            response_byte_count=response_byte_count,
            started_at=first,
            completed_at=last,
        )


def _interrupt_process(process: multiprocessing.Process) -> int:
    if process.is_alive():
        process.kill()
    process.join(timeout=1.0)
    if process.is_alive():
        process.terminate()
        process.join(timeout=1.0)
    if process.is_alive() or process.exitcode is None:
        raise ScenarioRunnerError("scenario worker could not be interrupted")
    if process.exitcode >= 0:
        raise ScenarioRunnerError("scenario worker exited before interruption")
    return -process.exitcode


def _stop_process(process: multiprocessing.Process) -> None:
    if process.is_alive():
        process.kill()
        process.join(timeout=1.0)
    if process.is_alive():
        process.terminate()
        process.join(timeout=1.0)
    if process.is_alive() or process.exitcode is None:
        raise ScenarioRunnerError("scenario worker could not be stopped")


class ScenarioRunner:
    """Run a declared mutation without promoting harness truth into product state."""

    def __init__(
        self,
        *,
        clock: ScenarioClock | None = None,
        sleeper: Callable[[float], None] = time.sleep,
    ) -> None:
        self._clock = clock or _SystemClock()
        self._sleeper = sleeper

    def run(
        self,
        request: ScenarioRunRequest,
        definition: ScenarioDefinition,
    ) -> ScenarioRunResult:
        request = decode_contract(canonical_json_bytes(request), ScenarioRunRequest)
        prepared = self._prepare_run(request, definition)
        definition.setup(prepared)
        invocation = self._invoke(request, definition, prepared)
        envelope = None
        if invocation.ambiguity is not None:
            envelope = self._with_ambiguity(
                prepared.execution_envelope_bytes,
                invocation.ambiguity,
            )
        return ScenarioRunResult(
            schema_version=SCENARIO_RUN_RESULT_VERSION,
            request_sha256=canonical_sha256(request),
            scenario=request.scenario,
            run_id=request.run_id,
            investigation_id=request.investigation_id,
            operation_id=request.operation_id,
            invocation_id=request.invocation_id,
            function_call_id=request.function_call_id,
            fixture=ScenarioFixtureRef(
                namespace_id=prepared.plan.namespace_id,
                cleanup_manifest_sha256=prepared.cleanup_manifest_sha256,
            ),
            trace=invocation.trace,
            execution_envelope=envelope,
        )

    def build_cleanup_request(
        self,
        request: ScenarioRunRequest,
        result: ScenarioRunResult,
    ) -> ScenarioCleanupRequest:
        request = decode_contract(canonical_json_bytes(request), ScenarioRunRequest)
        result = decode_contract(canonical_json_bytes(result), ScenarioRunResult)
        if result.request_sha256 != canonical_sha256(request):
            raise ValueError("scenario result does not match the run request")
        result_identity = (
            result.scenario,
            result.run_id,
            result.investigation_id,
            result.operation_id,
            result.invocation_id,
            result.function_call_id,
        )
        request_identity = (
            request.scenario,
            request.run_id,
            request.investigation_id,
            request.operation_id,
            request.invocation_id,
            request.function_call_id,
        )
        if result_identity != request_identity:
            raise ValueError("scenario result identifiers do not match the run request")
        return ScenarioCleanupRequest(
            schema_version=SCENARIO_CLEANUP_REQUEST_VERSION,
            scenario=request.scenario,
            run_id=request.run_id,
            investigation_id=request.investigation_id,
            operation_id=request.operation_id,
            invocation_id=request.invocation_id,
            function_call_id=request.function_call_id,
            seed=request.seed,
            namespace_id=result.fixture.namespace_id,
            cleanup_manifest_sha256=result.fixture.cleanup_manifest_sha256,
        )

    def build_cleanup_request_for_attempt(
        self,
        request: ScenarioRunRequest,
        definition: ScenarioDefinition,
    ) -> ScenarioCleanupRequest:
        """Re-derive cleanup authority when an attempted run produced no result."""

        request = decode_contract(canonical_json_bytes(request), ScenarioRunRequest)
        prepared = self._prepare_run(request, definition)
        identifiers = prepared.plan.identifiers
        return ScenarioCleanupRequest(
            schema_version=SCENARIO_CLEANUP_REQUEST_VERSION,
            scenario=request.scenario,
            run_id=identifiers.run_id,
            investigation_id=identifiers.investigation_id,
            operation_id=identifiers.operation_id,
            invocation_id=identifiers.invocation_id,
            function_call_id=identifiers.function_call_id,
            seed=request.seed,
            namespace_id=prepared.plan.namespace_id,
            cleanup_manifest_sha256=prepared.cleanup_manifest_sha256,
        )

    def cleanup(
        self,
        request: ScenarioCleanupRequest,
        definition: ScenarioDefinition,
    ) -> ScenarioCleanupResult:
        request = decode_contract(canonical_json_bytes(request), ScenarioCleanupRequest)
        started_at = self._clock.now()
        request_sha256 = canonical_sha256(request)
        try:
            prepared = self._prepare_cleanup(request, definition)
        except Exception:
            return self._cleanup_failure(
                request,
                request_sha256,
                started_at,
                "cleanup_ownership_mismatch",
            )

        try:
            before = self._count(definition.remaining(prepared))
        except Exception:
            return self._cleanup_failure(
                request,
                request_sha256,
                started_at,
                "cleanup_verification_failed",
            )
        if before == 0:
            return self._cleanup_result(
                request,
                request_sha256,
                started_at,
                disposition=ScenarioCleanupDisposition.ALREADY_CLEAN,
                removed_count=0,
                remaining_count=0,
            )

        try:
            removed_count = self._removed_count(
                definition.cleanup(prepared),
                prepared.cleanup_resource_ids,
            )
            remaining_count = self._count(definition.remaining(prepared))
        except Exception:
            return self._cleanup_failure(
                request,
                request_sha256,
                started_at,
                "cleanup_failed",
            )
        if remaining_count is None or remaining_count > 0:
            return self._cleanup_failure(
                request,
                request_sha256,
                started_at,
                "cleanup_incomplete",
                removed_count=removed_count,
                remaining_count=remaining_count,
            )
        if removed_count == 0:
            return self._cleanup_failure(
                request,
                request_sha256,
                started_at,
                "cleanup_count_inconsistent",
            )
        return self._cleanup_result(
            request,
            request_sha256,
            started_at,
            disposition=ScenarioCleanupDisposition.CLEANED,
            removed_count=removed_count,
            remaining_count=0,
        )

    def _prepare_run(
        self,
        request: ScenarioRunRequest,
        definition: ScenarioDefinition,
    ) -> PreparedScenario:
        plan = ScenarioPlan(
            scenario=request.scenario,
            identifiers=ScenarioIdentifiers(
                run_id=request.run_id,
                investigation_id=request.investigation_id,
                operation_id=request.operation_id,
                invocation_id=request.invocation_id,
                function_call_id=request.function_call_id,
            ),
            seed=request.seed,
            namespace_id=_namespace_id(request.scenario, request.run_id),
        )
        return self._seal(plan, definition)

    def _prepare_cleanup(
        self,
        request: ScenarioCleanupRequest,
        definition: ScenarioDefinition,
    ) -> PreparedScenario:
        expected_namespace = _namespace_id(request.scenario, request.run_id)
        if request.namespace_id != expected_namespace:
            raise ValueError("cleanup namespace does not match the scenario identity")
        plan = ScenarioPlan(
            scenario=request.scenario,
            identifiers=ScenarioIdentifiers(
                run_id=request.run_id,
                investigation_id=request.investigation_id,
                operation_id=request.operation_id,
                invocation_id=request.invocation_id,
                function_call_id=request.function_call_id,
            ),
            seed=request.seed,
            namespace_id=request.namespace_id,
        )
        prepared = self._seal(plan, definition)
        if prepared.cleanup_manifest_sha256 != request.cleanup_manifest_sha256:
            raise ValueError("cleanup manifest does not match the sealed fixture")
        return prepared

    def _seal(
        self,
        plan: ScenarioPlan,
        definition: ScenarioDefinition,
    ) -> PreparedScenario:
        if definition.scenario != plan.scenario:
            raise ValueError("scenario definition does not match the request")
        preparation = definition.prepare(plan)
        if type(preparation) is not ScenarioPreparation:
            raise TypeError("scenario definition returned an invalid preparation")
        envelope_bytes = canonical_json_bytes(preparation.execution_envelope)
        envelope = decode_contract(envelope_bytes, ExecutionEnvelope)
        identifiers = plan.identifiers
        invocation = envelope.context.invocation
        if (
            envelope.investigation_id != identifiers.investigation_id
            or envelope.operation_id != identifiers.operation_id
            or invocation.invocation_id != identifiers.invocation_id
            or invocation.function_call_id != identifiers.function_call_id
        ):
            raise ValueError(
                "prepared envelope does not match the scenario identifiers"
            )
        manifest = preparation.cleanup_manifest
        if type(manifest) is not ScenarioCleanupManifest:
            raise TypeError("scenario definition returned an invalid cleanup manifest")
        resource_ids = manifest.resource_ids
        manifest_bytes = canonical_json_value_bytes(
            {"resource_ids": list(resource_ids)}
        )
        return PreparedScenario(
            plan=plan,
            execution_envelope_bytes=envelope_bytes,
            cleanup_resource_ids=resource_ids,
            cleanup_manifest_bytes=manifest_bytes,
            cleanup_manifest_sha256=hashlib.sha256(manifest_bytes).hexdigest(),
        )

    def _invoke(
        self,
        request: ScenarioRunRequest,
        definition: ScenarioDefinition,
        prepared: PreparedScenario,
    ) -> _InvocationResult:
        trace = _TraceBuilder(request, self._clock)
        trace.add(ScenarioTransportEvent.RUN_STARTED)
        if request.fault.action is ScenarioFaultAction.SUPPRESS_DISPATCH:
            trace.add(ScenarioTransportEvent.DISPATCH_SUPPRESSED)
            trace.add(ScenarioTransportEvent.RUN_COMPLETED)
            return _InvocationResult(
                trace=trace.finish(
                    caller_observation=ScenarioCallerObservation.NOT_DISPATCHED,
                    worker_termination=ScenarioWorkerTermination.NOT_STARTED,
                ),
                ambiguity=None,
            )

        context = multiprocessing.get_context("spawn")
        parent_connection, child_connection = context.Pipe(duplex=True)
        process = context.Process(
            target=_worker_main,
            args=(child_connection, definition.mutate, prepared),
        )
        try:
            process.start()
            child_connection.close()
            trace.add(ScenarioTransportEvent.DISPATCH_STARTED)
            message = self._receive(parent_connection, process)
            if message[0] != _CHILD_READY:
                return self._unexpected_interruption(trace, process)
            parent_connection.send(_CONTINUE)
            expected_boundaries = [
                ScenarioFaultPoint.PRE_COMMIT,
                ScenarioFaultPoint.POST_COMMIT,
            ]
            boundary_index = 0
            while True:
                message_type, value = self._receive(parent_connection, process)
                if message_type == _CHECKPOINT:
                    try:
                        boundary = ScenarioFaultPoint(value)
                    except (TypeError, ValueError):
                        return self._unexpected_interruption(trace, process)
                    if (
                        boundary_index >= len(expected_boundaries)
                        or boundary is not expected_boundaries[boundary_index]
                    ):
                        return self._unexpected_interruption(trace, process)
                    boundary_index += 1
                    event = (
                        ScenarioTransportEvent.PRE_COMMIT_REACHED
                        if boundary is ScenarioFaultPoint.PRE_COMMIT
                        else ScenarioTransportEvent.POST_COMMIT_REACHED
                    )
                    trace.add(event)
                    if (
                        request.fault.action is ScenarioFaultAction.INTERRUPT_PROCESS
                        and request.fault.point is boundary
                    ):
                        return self._injected_interruption(trace, process)
                    parent_connection.send(_CONTINUE)
                    continue
                if message_type == _WORKER_ERROR:
                    return self._unexpected_interruption(trace, process)
                if message_type != _RESPONSE:
                    return self._unexpected_interruption(trace, process)
                try:
                    is_error, response_bytes = value
                except (TypeError, ValueError):
                    return self._unexpected_interruption(trace, process)
                if type(is_error) is not bool or type(response_bytes) is not bytes:
                    return self._unexpected_interruption(trace, process)
                early_error = (
                    is_error
                    and request.fault.point is ScenarioFaultPoint.UNINTERRUPTED
                    and request.fault.action is ScenarioFaultAction.NONE
                    and boundary_index in {0, 1}
                )
                if boundary_index != 2 and not early_error:
                    return self._unexpected_interruption(trace, process)
                response_sha256 = hashlib.sha256(response_bytes).hexdigest()
                response_byte_count = len(response_bytes)
                trace.add(ScenarioTransportEvent.RESPONSE_AVAILABLE)
                return self._handle_response(
                    request,
                    trace,
                    parent_connection,
                    process,
                    is_error=is_error,
                    response_sha256=response_sha256,
                    response_byte_count=response_byte_count,
                )
        finally:
            try:
                parent_connection.close()
            finally:
                try:
                    child_connection.close()
                finally:
                    if process.pid is not None:
                        _stop_process(process)

    def _handle_response(
        self,
        request: ScenarioRunRequest,
        trace: _TraceBuilder,
        connection: Connection,
        process: multiprocessing.Process,
        *,
        is_error: bool,
        response_sha256: str,
        response_byte_count: int,
    ) -> _InvocationResult:
        action = request.fault.action
        if action is ScenarioFaultAction.DROP_RESPONSE:
            observed_at = trace.add(ScenarioTransportEvent.RESPONSE_DROPPED)
            self._ack_and_join(connection, process)
            trace.add(ScenarioTransportEvent.RUN_COMPLETED)
            ambiguity = AmbiguousExecution(
                kind=AmbiguityKind.MISSING_TOOL_RESULT,
                observed_at=observed_at,
                detail="The proxy received the mutation response but did not deliver it.",
            )
            return _InvocationResult(
                trace=trace.finish(
                    caller_observation=ScenarioCallerObservation.NO_RESPONSE,
                    worker_termination=ScenarioWorkerTermination.EXITED,
                    exit_code=0,
                    response_sha256=response_sha256,
                    response_byte_count=response_byte_count,
                ),
                ambiguity=ambiguity,
            )
        applied_delay_ms = 0
        if action is ScenarioFaultAction.DELAY_RESPONSE:
            trace.add(ScenarioTransportEvent.RESPONSE_DELAY_STARTED)
            applied_delay_ms = request.fault.delay_ms
            self._sleeper(applied_delay_ms / 1000)
        trace.add(ScenarioTransportEvent.RESPONSE_OBSERVED)
        self._ack_and_join(connection, process)
        trace.add(ScenarioTransportEvent.RUN_COMPLETED)
        caller_observation = (
            ScenarioCallerObservation.ERROR_RESPONSE
            if is_error
            else ScenarioCallerObservation.VALUE_RESPONSE
        )
        return _InvocationResult(
            trace=trace.finish(
                caller_observation=caller_observation,
                worker_termination=ScenarioWorkerTermination.EXITED,
                exit_code=0,
                applied_delay_ms=applied_delay_ms,
                response_sha256=response_sha256,
                response_byte_count=response_byte_count,
            ),
            ambiguity=None,
        )

    def _injected_interruption(
        self,
        trace: _TraceBuilder,
        process: multiprocessing.Process,
    ) -> _InvocationResult:
        signal = _interrupt_process(process)
        observed_at = trace.add(ScenarioTransportEvent.WORKER_INTERRUPTED)
        trace.add(ScenarioTransportEvent.RUN_COMPLETED)
        ambiguity = AmbiguousExecution(
            kind=AmbiguityKind.PROCESS_INTERRUPTED,
            observed_at=observed_at,
            detail="The mutation subprocess ended before a response was available.",
        )
        return _InvocationResult(
            trace=trace.finish(
                caller_observation=ScenarioCallerObservation.NO_RESPONSE,
                worker_termination=ScenarioWorkerTermination.SIGNALED,
                signal=signal,
            ),
            ambiguity=ambiguity,
        )

    def _unexpected_interruption(
        self,
        trace: _TraceBuilder,
        process: multiprocessing.Process,
    ) -> _InvocationResult:
        if process.is_alive():
            signal = _interrupt_process(process)
            termination = ScenarioWorkerTermination.SIGNALED
            exit_code = None
        else:
            process.join(timeout=1.0)
            if process.exitcode is None:
                raise ScenarioRunnerError("scenario worker termination is unavailable")
            if process.exitcode < 0:
                signal = -process.exitcode
                termination = ScenarioWorkerTermination.SIGNALED
                exit_code = None
            else:
                signal = None
                termination = ScenarioWorkerTermination.EXITED
                exit_code = process.exitcode
        observed_at = trace.add(ScenarioTransportEvent.WORKER_INTERRUPTED)
        trace.add(ScenarioTransportEvent.RUN_COMPLETED)
        ambiguity = AmbiguousExecution(
            kind=AmbiguityKind.PROCESS_INTERRUPTED,
            observed_at=observed_at,
            detail="The subprocess ended without a response delivered to the caller.",
        )
        return _InvocationResult(
            trace=trace.finish(
                caller_observation=ScenarioCallerObservation.NO_RESPONSE,
                worker_termination=termination,
                exit_code=exit_code,
                signal=signal,
            ),
            ambiguity=ambiguity,
        )

    def _receive(
        self,
        connection: Connection,
        process: multiprocessing.Process,
    ) -> tuple[str, object]:
        if not connection.poll(_WORKER_TIMEOUT_SECONDS):
            return ("worker_timeout", process.exitcode)
        try:
            message = connection.recv()
        except EOFError:
            return ("worker_eof", process.exitcode)
        if (
            type(message) is not tuple
            or len(message) != 2
            or type(message[0]) is not str
        ):
            return ("malformed_message", None)
        return message

    @staticmethod
    def _ack_and_join(
        connection: Connection,
        process: multiprocessing.Process,
    ) -> None:
        connection.send(_RESPONSE_ACK)
        process.join(timeout=_WORKER_TIMEOUT_SECONDS)
        if process.is_alive() or process.exitcode != 0:
            raise ScenarioRunnerError("scenario worker did not exit cleanly")

    @staticmethod
    def _with_ambiguity(
        template_bytes: bytes,
        ambiguity: AmbiguousExecution,
    ) -> ExecutionEnvelope:
        template = decode_contract(template_bytes, ExecutionEnvelope)
        payload = template.model_dump(mode="json")
        payload["ambiguity"] = ambiguity.model_dump(mode="json")
        return decode_contract(
            canonical_json_value_bytes(payload),
            ExecutionEnvelope,
        )

    @staticmethod
    def _count(value: int | None) -> int | None:
        if value is None:
            return None
        if type(value) is not int or value < 0:
            raise ValueError("scenario remaining count must be a nonnegative integer")
        return value

    @staticmethod
    def _removed_count(
        outcome: ScenarioCleanupOutcome,
        allowed_resource_ids: tuple[str, ...],
    ) -> int:
        if type(outcome) is not ScenarioCleanupOutcome:
            raise TypeError("scenario cleanup returned an invalid outcome")
        removed = set(outcome.removed_resource_ids)
        if not removed.issubset(allowed_resource_ids):
            raise ValueError("scenario cleanup reported an undeclared resource")
        return len(removed)

    def _cleanup_failure(
        self,
        request: ScenarioCleanupRequest,
        request_sha256: str,
        started_at: datetime,
        failure_code: str,
        *,
        removed_count: int = 0,
        remaining_count: int | None = None,
    ) -> ScenarioCleanupResult:
        return self._cleanup_result(
            request,
            request_sha256,
            started_at,
            disposition=ScenarioCleanupDisposition.FAILED,
            removed_count=removed_count,
            remaining_count=remaining_count,
            failure_code=failure_code,
        )

    def _cleanup_result(
        self,
        request: ScenarioCleanupRequest,
        request_sha256: str,
        started_at: datetime,
        *,
        disposition: ScenarioCleanupDisposition,
        removed_count: int,
        remaining_count: int | None,
        failure_code: str | None = None,
    ) -> ScenarioCleanupResult:
        return ScenarioCleanupResult(
            schema_version=SCENARIO_CLEANUP_RESULT_VERSION,
            cleanup_request_sha256=request_sha256,
            run_id=request.run_id,
            namespace_id=request.namespace_id,
            cleanup_manifest_sha256=request.cleanup_manifest_sha256,
            disposition=disposition,
            removed_count=removed_count,
            remaining_count=remaining_count,
            started_at=started_at,
            completed_at=self._clock.now(),
            failure_code=failure_code,
        )


__all__ = [
    "MutationBoundary",
    "PreparedScenario",
    "ScenarioCleanupManifest",
    "ScenarioCleanupOutcome",
    "ScenarioClock",
    "ScenarioDefinition",
    "ScenarioIdentifiers",
    "ScenarioMutationResponse",
    "ScenarioPlan",
    "ScenarioPreparation",
    "ScenarioRunner",
    "ScenarioRunnerError",
]
