"""Loopback FastAPI boundary for versioned investigation contracts."""

from __future__ import annotations

import asyncio
import os
import re
from collections.abc import AsyncIterator, Awaitable
from contextlib import asynccontextmanager
from http import HTTPStatus
from typing import Protocol, cast

import uvicorn
from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import Response, StreamingResponse

from reconcile import __version__
from reconcile.contracts import (
    ERROR_VERSION,
    MAX_INVESTIGATION_EVENTS,
    MAX_SCENARIO_RUN_EVENTS,
    ApiError,
    ApiErrorCode,
    ContractError,
    ExecutionEnvelope,
    ExecutionEnvelopeSummary,
    InvestigationEvent,
    InvestigationReport,
    ScenarioLaunchName,
    ScenarioLaunchRequest,
    ScenarioLifecycleEventPayload,
    ScenarioRunEvent,
    ScenarioRunEventType,
    ScenarioRunLifecycle,
    ScenarioRunMode,
    ScenarioRunSnapshot,
    canonical_json_bytes,
    canonical_sha256,
    decode_contract,
)
from reconcile.operator import (
    InvalidScenarioEventCursor,
    OperatorCapacityExceeded,
    OperatorServiceClosed,
    OperatorServiceError,
    ScenarioEnvelopeUnavailable,
    ScenarioEventJournalFull,
    ScenarioEventJournalTerminal,
    ScenarioLaunchConflict,
    ScenarioRunEventSnapshot,
    ScenarioRunNotFound,
)
from reconcile.persistence import (
    DuplicateInvestigationId,
    EventJournalError,
    EventJournalSnapshot,
    InMemoryInvestigationEventJournal,
    InMemoryInvestigationRepository,
    InvalidCursor,
    InvestigationNotFound,
    JournalNotFound,
    RepositoryError,
    WriteOutcomeUnknown,
)
from reconcile.scenarios.service import ScenarioName, scenario_investigation_id
from reconcile.security import contains_sensitive_material

_MAX_REQUEST_BYTES = 1_048_576
_IDENTIFIER_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")


class _CreateResult(Protocol):
    report: InvestigationReport
    created: bool


class _InvestigationService(Protocol):
    async def create(
        self,
        envelope: ExecutionEnvelope,
    ) -> _CreateResult: ...

    async def get(self, investigation_id: str) -> InvestigationReport: ...

    async def snapshot(
        self,
        investigation_id: str,
        *,
        after: int = 0,
    ) -> EventJournalSnapshot: ...

    async def wait_for_events(
        self,
        investigation_id: str,
        *,
        after: int = 0,
        cancellation_event: asyncio.Event | None = None,
    ) -> EventJournalSnapshot: ...

    async def aclose(self) -> None: ...


class _LaunchScenarioResult(Protocol):
    snapshot: ScenarioRunSnapshot
    created: bool


class _OperatorService(Protocol):
    async def launch(
        self,
        request: ScenarioLaunchRequest,
    ) -> _LaunchScenarioResult: ...

    async def get(self, investigation_id: str) -> ScenarioRunSnapshot: ...

    async def get_envelope_summary(
        self,
        investigation_id: str,
    ) -> ExecutionEnvelopeSummary: ...

    async def snapshot(
        self,
        investigation_id: str,
        *,
        after: int = 0,
    ) -> ScenarioRunEventSnapshot: ...

    async def wait_for_events(
        self,
        investigation_id: str,
        *,
        after: int = 0,
        cancellation_event: asyncio.Event | None = None,
    ) -> ScenarioRunEventSnapshot: ...

    async def aclose(self) -> None: ...


class _FailClosedExecutor:
    async def __call__(
        self,
        _envelope: ExecutionEnvelope,
        *,
        revision: int,
        cancellation_event: asyncio.Event,
    ) -> InvestigationReport:
        del revision, cancellation_event
        raise RuntimeError("no investigation executor is configured")


class _ApiBoundaryError(Exception):
    pass


class _InvalidApiRequest(_ApiBoundaryError):
    pass


class _IncompatibleContract(_ApiBoundaryError):
    pass


class _DependencyUnavailable(_ApiBoundaryError):
    pass


class _InternalApiFailure(_ApiBoundaryError):
    pass


def _build_default_service() -> _InvestigationService:
    from reconcile.application import InvestigationApplicationService

    return InvestigationApplicationService(
        InMemoryInvestigationRepository(),
        InMemoryInvestigationEventJournal(),
        _FailClosedExecutor(),
    )


def _build_default_operator_service() -> _OperatorService:
    from reconcile.adk_planner import VertexAdcPlannerConfig
    from reconcile.operator import OperatorApplicationService

    values = tuple(
        os.environ.get(name)
        for name in (
            "RECONCILE_VERTEX_PROJECT",
            "RECONCILE_VERTEX_LOCATION",
            "RECONCILE_VERTEX_MODEL",
        )
    )
    if all(value is None for value in values):
        vertex_config = None
    elif any(value is None or not value for value in values):
        raise ValueError("operator Vertex configuration is incomplete")
    else:
        vertex_config = VertexAdcPlannerConfig(
            project=values[0],  # type: ignore[arg-type]
            location=values[1],  # type: ignore[arg-type]
            model=values[2],  # type: ignore[arg-type]
            timeout_seconds=3.75,
            max_output_tokens=1_024,
        )
    return OperatorApplicationService(vertex_config=vertex_config)


def _validated_investigation_id(value: object) -> str | None:
    if (
        not isinstance(value, str)
        or _IDENTIFIER_PATTERN.fullmatch(value) is None
        or contains_sensitive_material(value)
    ):
        return None
    return value


def _request_investigation_id(request: Request) -> str | None:
    path_identity = _validated_investigation_id(
        request.path_params.get("investigation_id")
    )
    if path_identity is not None:
        return path_identity
    return _validated_investigation_id(getattr(request.state, "investigation_id", None))


def _api_error_response(
    code: ApiErrorCode,
    status_code: int,
    message: str,
    *,
    investigation_id: str | None = None,
) -> Response:
    error = ApiError(
        schema_version=ERROR_VERSION,
        code=code,
        message=message,
        details=(
            {"investigation_id": investigation_id}
            if investigation_id is not None
            else {}
        ),
    )
    return Response(
        content=canonical_json_bytes(error),
        status_code=status_code,
        media_type="application/json",
    )


def _register_error_handler(
    application: FastAPI,
    exception_type: type[Exception],
    *,
    code: ApiErrorCode,
    status_code: int,
    message: str,
) -> None:
    async def handler(request: Request, error: Exception) -> Response:
        investigation_id = _request_investigation_id(request)
        if investigation_id is None:
            investigation_id = _validated_investigation_id(
                getattr(error, "investigation_id", None)
            )
        return _api_error_response(
            code,
            status_code,
            message,
            investigation_id=investigation_id,
        )

    application.add_exception_handler(exception_type, handler)


def _install_error_handlers(application: FastAPI) -> None:
    _register_error_handler(
        application,
        _InvalidApiRequest,
        code=ApiErrorCode.INVALID_CONTRACT,
        status_code=HTTPStatus.BAD_REQUEST,
        message="The request is invalid.",
    )
    _register_error_handler(
        application,
        RequestValidationError,
        code=ApiErrorCode.INVALID_CONTRACT,
        status_code=HTTPStatus.BAD_REQUEST,
        message="The request is invalid.",
    )
    _register_error_handler(
        application,
        InvalidCursor,
        code=ApiErrorCode.INVALID_CONTRACT,
        status_code=HTTPStatus.BAD_REQUEST,
        message="The event cursor is invalid.",
    )
    _register_error_handler(
        application,
        InvalidScenarioEventCursor,
        code=ApiErrorCode.INVALID_CONTRACT,
        status_code=HTTPStatus.BAD_REQUEST,
        message="The event cursor is invalid.",
    )
    _register_error_handler(
        application,
        _IncompatibleContract,
        code=ApiErrorCode.UNSUPPORTED_CONTRACT_VERSION,
        status_code=HTTPStatus.UNPROCESSABLE_ENTITY,
        message="The contract version is unsupported.",
    )
    _register_error_handler(
        application,
        InvestigationNotFound,
        code=ApiErrorCode.INVESTIGATION_NOT_FOUND,
        status_code=HTTPStatus.NOT_FOUND,
        message="The investigation was not found.",
    )
    _register_error_handler(
        application,
        JournalNotFound,
        code=ApiErrorCode.INVESTIGATION_NOT_FOUND,
        status_code=HTTPStatus.NOT_FOUND,
        message="The investigation was not found.",
    )
    _register_error_handler(
        application,
        ScenarioRunNotFound,
        code=ApiErrorCode.INVESTIGATION_NOT_FOUND,
        status_code=HTTPStatus.NOT_FOUND,
        message="The scenario run was not found.",
    )
    _register_error_handler(
        application,
        DuplicateInvestigationId,
        code=ApiErrorCode.DUPLICATE_INVESTIGATION_ID,
        status_code=HTTPStatus.CONFLICT,
        message="The investigation identity conflicts with an existing envelope.",
    )
    _register_error_handler(
        application,
        ScenarioLaunchConflict,
        code=ApiErrorCode.DUPLICATE_INVESTIGATION_ID,
        status_code=HTTPStatus.CONFLICT,
        message="The scenario launch identity conflicts with an existing run.",
    )
    _register_error_handler(
        application,
        WriteOutcomeUnknown,
        code=ApiErrorCode.DEPENDENCY_UNAVAILABLE,
        status_code=HTTPStatus.SERVICE_UNAVAILABLE,
        message="A required dependency is unavailable.",
    )
    _register_error_handler(
        application,
        _DependencyUnavailable,
        code=ApiErrorCode.DEPENDENCY_UNAVAILABLE,
        status_code=HTTPStatus.SERVICE_UNAVAILABLE,
        message="A required dependency is unavailable.",
    )
    for exception_type in (
        OperatorCapacityExceeded,
        OperatorServiceClosed,
        ScenarioEnvelopeUnavailable,
    ):
        _register_error_handler(
            application,
            exception_type,
            code=ApiErrorCode.DEPENDENCY_UNAVAILABLE,
            status_code=HTTPStatus.SERVICE_UNAVAILABLE,
            message="A required dependency is unavailable.",
        )
    for exception_type in (
        _InternalApiFailure,
        RepositoryError,
        EventJournalError,
        ScenarioEventJournalFull,
        ScenarioEventJournalTerminal,
        OperatorServiceError,
    ):
        _register_error_handler(
            application,
            exception_type,
            code=ApiErrorCode.INTERNAL_FAILURE,
            status_code=HTTPStatus.INTERNAL_SERVER_ERROR,
            message="The request could not be completed.",
        )


async def _read_contract_body(request: Request) -> bytes:
    content_type = request.headers.get("content-type", "").split(";", 1)[0]
    if content_type.strip().lower() != "application/json":
        raise _InvalidApiRequest

    content_length = request.headers.get("content-length")
    if content_length is not None:
        try:
            declared_length = int(content_length)
        except ValueError as error:
            raise _InvalidApiRequest from error
        if declared_length < 0 or declared_length > _MAX_REQUEST_BYTES:
            raise _InvalidApiRequest

    body = bytearray()
    async for chunk in request.stream():
        body.extend(chunk)
        if len(body) > _MAX_REQUEST_BYTES:
            raise _InvalidApiRequest
    if not body:
        raise _InvalidApiRequest
    return bytes(body)


def _decode_envelope(payload: bytes) -> ExecutionEnvelope:
    try:
        return decode_contract(payload, ExecutionEnvelope)
    except ContractError as error:
        if error.code == "unsupported_contract_version":
            raise _IncompatibleContract from error
        raise _InvalidApiRequest from error


def _decode_scenario_launch(payload: bytes) -> ScenarioLaunchRequest:
    try:
        return decode_contract(payload, ScenarioLaunchRequest)
    except ContractError as error:
        if error.code == "unsupported_contract_version":
            raise _IncompatibleContract from error
        raise _InvalidApiRequest from error


def _reject_query_parameters(request: Request, *, allowed: set[str]) -> None:
    if not set(request.query_params).issubset(allowed):
        raise _InvalidApiRequest


def _parse_cursor_value(value: str, *, maximum: int) -> int:
    if value == "0":
        return 0
    maximum_digits = len(str(maximum))
    if re.fullmatch(rf"[1-9][0-9]{{0,{maximum_digits - 1}}}", value) is None:
        raise _InvalidApiRequest
    cursor = int(value)
    if cursor > maximum:
        raise _InvalidApiRequest
    return cursor


def _resume_cursor(
    request: Request,
    *,
    maximum: int = MAX_INVESTIGATION_EVENTS,
) -> int:
    _reject_query_parameters(request, allowed={"after"})
    query_values = request.query_params.getlist("after")
    header_values = request.headers.getlist("last-event-id")
    if len(query_values) > 1 or len(header_values) > 1:
        raise _InvalidApiRequest

    query_cursor = (
        _parse_cursor_value(query_values[0], maximum=maximum) if query_values else None
    )
    header_cursor = (
        _parse_cursor_value(header_values[0], maximum=maximum)
        if header_values
        else None
    )
    if (
        query_cursor is not None
        and header_cursor is not None
        and query_cursor != header_cursor
    ):
        raise _InvalidApiRequest
    return query_cursor if query_cursor is not None else header_cursor or 0


def _service(application: FastAPI) -> _InvestigationService:
    service = application.state.investigation_service
    if service is None:
        raise _DependencyUnavailable
    return cast(_InvestigationService, service)


def _operator_service(application: FastAPI) -> _OperatorService:
    service = application.state.operator_service
    if service is None:
        raise _DependencyUnavailable
    return cast(_OperatorService, service)


async def _call_service[Result](operation: Awaitable[Result]) -> Result:
    try:
        return await operation
    except (
        _ApiBoundaryError,
        RepositoryError,
        EventJournalError,
        OperatorServiceError,
    ):
        raise
    except Exception as error:
        raise _InternalApiFailure from error


def _validated_report(
    value: object,
    *,
    investigation_id: str,
    envelope_sha256: str | None = None,
) -> InvestigationReport:
    if type(value) is not InvestigationReport:
        raise _InternalApiFailure
    try:
        canonical_json_bytes(value)
    except (TypeError, ValueError) as error:
        raise _InternalApiFailure from error
    if value.investigation_id != investigation_id:
        raise _InternalApiFailure
    if envelope_sha256 is not None and value.envelope_sha256 != envelope_sha256:
        raise _InternalApiFailure
    return value


def _validated_snapshot(
    value: object,
    *,
    investigation_id: str,
    after: int,
) -> EventJournalSnapshot:
    if type(value) is not EventJournalSnapshot:
        raise _InternalApiFailure
    if (
        isinstance(value.cursor, bool)
        or not isinstance(value.cursor, int)
        or not after <= value.cursor <= MAX_INVESTIGATION_EVENTS
        or not isinstance(value.terminal, bool)
        or not isinstance(value.events, tuple)
    ):
        raise _InternalApiFailure
    if any(type(event) is not InvestigationEvent for event in value.events):
        raise _InternalApiFailure
    expected_sequences = tuple(range(after + 1, value.cursor + 1))
    actual_sequences = tuple(event.sequence for event in value.events)
    if actual_sequences != expected_sequences:
        raise _InternalApiFailure
    for event in value.events:
        if event.investigation_id != investigation_id:
            raise _InternalApiFailure
        try:
            canonical_json_bytes(event)
        except (TypeError, ValueError) as error:
            raise _InternalApiFailure from error
    return value


def _validated_scenario_snapshot(
    value: object,
    *,
    investigation_id: str | None = None,
    launch_id: str | None = None,
    scenario: ScenarioLaunchName | None = None,
    mode: ScenarioRunMode | None = None,
) -> ScenarioRunSnapshot:
    if type(value) is not ScenarioRunSnapshot:
        raise _InternalApiFailure
    try:
        canonical_json_bytes(value)
    except (TypeError, ValueError) as error:
        raise _InternalApiFailure from error
    if investigation_id is not None and value.investigation_id != investigation_id:
        raise _InternalApiFailure
    if launch_id is not None and value.launch_id != launch_id:
        raise _InternalApiFailure
    if scenario is not None and value.scenario is not scenario:
        raise _InternalApiFailure
    if mode is not None and value.mode is not mode:
        raise _InternalApiFailure
    return value


def _validated_envelope_summary(
    value: object,
    *,
    investigation_id: str,
) -> ExecutionEnvelopeSummary:
    if type(value) is not ExecutionEnvelopeSummary:
        raise _InternalApiFailure
    try:
        canonical_json_bytes(value)
    except (TypeError, ValueError) as error:
        raise _InternalApiFailure from error
    if value.investigation_id != investigation_id:
        raise _InternalApiFailure
    return value


def _validated_scenario_event_snapshot(
    value: object,
    *,
    investigation_id: str,
    after: int,
) -> ScenarioRunEventSnapshot:
    if type(value) is not ScenarioRunEventSnapshot:
        raise _InternalApiFailure
    if (
        isinstance(value.cursor, bool)
        or not isinstance(value.cursor, int)
        or not max(1, after) <= value.cursor <= MAX_SCENARIO_RUN_EVENTS
        or type(value.terminal) is not bool
        or type(value.events) is not tuple
    ):
        raise _InternalApiFailure
    if any(type(event) is not ScenarioRunEvent for event in value.events):
        raise _InternalApiFailure
    expected_cursors = tuple(range(after + 1, value.cursor + 1))
    actual_cursors = tuple(event.cursor for event in value.events)
    if actual_cursors != expected_cursors:
        raise _InternalApiFailure
    for event in value.events:
        if event.investigation_id != investigation_id:
            raise _InternalApiFailure
        try:
            canonical_json_bytes(event)
        except (TypeError, ValueError) as error:
            raise _InternalApiFailure from error
    terminal_positions = tuple(
        index
        for index, event in enumerate(value.events)
        if event.type is ScenarioRunEventType.TERMINAL
    )
    if after == 0:
        if not value.events:
            raise _InternalApiFailure
        first = value.events[0]
        if (
            first.type is not ScenarioRunEventType.LIFECYCLE
            or type(first.payload) is not ScenarioLifecycleEventPayload
            or first.payload.lifecycle is not ScenarioRunLifecycle.ACCEPTED
        ):
            raise _InternalApiFailure
    if value.terminal:
        if value.events and terminal_positions != (len(value.events) - 1,):
            raise _InternalApiFailure
    elif terminal_positions:
        raise _InternalApiFailure
    return value


def _sse_event(event: InvestigationEvent) -> bytes:
    return (
        f"id: {event.sequence}\nevent: {event.type.value}\ndata: ".encode()
        + canonical_json_bytes(event)
        + b"\n\n"
    )


def _scenario_sse_event(event: ScenarioRunEvent) -> bytes:
    return (
        f"id: {event.cursor}\nevent: {event.type.value}\ndata: ".encode()
        + canonical_json_bytes(event)
        + b"\n\n"
    )


_TERMINAL_SCENARIO_LIFECYCLES = frozenset(
    {
        ScenarioRunLifecycle.COMPLETED,
        ScenarioRunLifecycle.FAILED,
        ScenarioRunLifecycle.CANCELLED,
    }
)


async def _wait_for_envelope_summary(
    service: _OperatorService,
    investigation_id: str,
) -> ExecutionEnvelopeSummary:
    cancellation_event = asyncio.Event()
    journal_terminal = False
    try:
        while True:
            snapshot = _validated_scenario_snapshot(
                await _call_service(service.get(investigation_id)),
                investigation_id=investigation_id,
            )
            if (
                journal_terminal
                and snapshot.lifecycle not in _TERMINAL_SCENARIO_LIFECYCLES
            ):
                raise _InternalApiFailure
            if snapshot.envelope_summary is not None:
                summary = _validated_envelope_summary(
                    await _call_service(service.get_envelope_summary(investigation_id)),
                    investigation_id=investigation_id,
                )
                if summary != snapshot.envelope_summary:
                    raise _InternalApiFailure
                return summary
            if snapshot.lifecycle in _TERMINAL_SCENARIO_LIFECYCLES:
                raise ScenarioEnvelopeUnavailable(investigation_id)
            event_snapshot = _validated_scenario_event_snapshot(
                await _call_service(
                    service.wait_for_events(
                        investigation_id,
                        after=snapshot.event_cursor,
                        cancellation_event=cancellation_event,
                    )
                ),
                investigation_id=investigation_id,
                after=snapshot.event_cursor,
            )
            if not event_snapshot.events and not event_snapshot.terminal:
                raise _InternalApiFailure
            journal_terminal = event_snapshot.terminal
    finally:
        cancellation_event.set()


def create_app(
    service: _InvestigationService | None = None,
    *,
    operator_service: _OperatorService | None = None,
) -> FastAPI:
    """Create the isolated single-process API and own its service lifetime."""

    @asynccontextmanager
    async def lifespan(application: FastAPI) -> AsyncIterator[None]:
        if application.state.investigation_service is None:
            application.state.investigation_service = _build_default_service()
        if application.state.operator_service is None:
            application.state.operator_service = _build_default_operator_service()
        try:
            yield
        finally:
            active_operator_service = application.state.operator_service
            try:
                if active_operator_service is not None:
                    await active_operator_service.aclose()
            finally:
                active_service = application.state.investigation_service
                if active_service is not None:
                    await active_service.aclose()

    application = FastAPI(
        title="RECONCILE",
        version=__version__,
        description=(
            "Loopback-only, single-process, single-tenant investigation API. "
            "Authentication and multi-tenant authorization are deferred."
        ),
        lifespan=lifespan,
    )
    application.state.investigation_service = service
    application.state.operator_service = operator_service
    _install_error_handlers(application)

    @application.get("/health", response_model=None)
    async def health() -> Response:
        return Response(
            content=b'{"status":"ok"}',
            media_type="application/json",
        )

    @application.post(
        "/api/v1/scenario-runs",
        response_model=None,
        responses={
            HTTPStatus.OK: {"description": "Existing identical scenario run"},
            HTTPStatus.ACCEPTED: {"description": "Scenario run accepted"},
        },
    )
    async def launch_scenario(request: Request) -> Response:
        _reject_query_parameters(request, allowed=set())
        launch = _decode_scenario_launch(await _read_contract_body(request))
        result = await _call_service(_operator_service(application).launch(launch))
        try:
            created = result.created
            result_snapshot = result.snapshot
        except Exception as error:
            raise _InternalApiFailure from error
        if type(created) is not bool:
            raise _InternalApiFailure
        snapshot = _validated_scenario_snapshot(
            result_snapshot,
            investigation_id=scenario_investigation_id(
                ScenarioName(launch.scenario.value),
                launch.launch_id,
            ),
            launch_id=launch.launch_id,
            scenario=launch.scenario,
            mode=launch.mode,
        )
        request.state.investigation_id = snapshot.investigation_id
        return Response(
            content=canonical_json_bytes(snapshot),
            status_code=(HTTPStatus.ACCEPTED if created else HTTPStatus.OK),
            media_type="application/json",
        )

    @application.get(
        "/api/v1/scenario-runs/{investigation_id}",
        response_model=None,
    )
    async def get_scenario_run(
        investigation_id: str,
        request: Request,
    ) -> Response:
        _reject_query_parameters(request, allowed=set())
        validated_id = _validated_investigation_id(investigation_id)
        if validated_id is None:
            raise _InvalidApiRequest
        snapshot = _validated_scenario_snapshot(
            await _call_service(_operator_service(application).get(validated_id)),
            investigation_id=validated_id,
        )
        return Response(
            content=canonical_json_bytes(snapshot),
            media_type="application/json",
        )

    @application.get(
        "/api/v1/scenario-runs/{investigation_id}/events",
        response_model=None,
    )
    async def stream_scenario_run_events(
        investigation_id: str,
        request: Request,
    ) -> StreamingResponse:
        validated_id = _validated_investigation_id(investigation_id)
        if validated_id is None:
            raise _InvalidApiRequest
        after = _resume_cursor(request, maximum=MAX_SCENARIO_RUN_EVENTS)
        active_service = _operator_service(application)
        initial = _validated_scenario_event_snapshot(
            await _call_service(active_service.snapshot(validated_id, after=after)),
            investigation_id=validated_id,
            after=after,
        )

        async def events() -> AsyncIterator[bytes]:
            cancellation_event = asyncio.Event()
            cursor = after
            snapshot = initial
            try:
                while True:
                    for event in snapshot.events:
                        yield _scenario_sse_event(event)
                    cursor = snapshot.cursor
                    if snapshot.terminal or await request.is_disconnected():
                        return
                    snapshot = _validated_scenario_event_snapshot(
                        await _call_service(
                            active_service.wait_for_events(
                                validated_id,
                                after=cursor,
                                cancellation_event=cancellation_event,
                            )
                        ),
                        investigation_id=validated_id,
                        after=cursor,
                    )
                    if not snapshot.events and not snapshot.terminal:
                        raise _InternalApiFailure
            finally:
                cancellation_event.set()

        return StreamingResponse(
            events(),
            media_type="text/event-stream",
            headers={
                "Cache-Control": "no-cache",
                "X-Accel-Buffering": "no",
                "X-Content-Type-Options": "nosniff",
            },
        )

    @application.get(
        "/api/v1/investigations/{investigation_id}/envelope-summary",
        response_model=None,
    )
    async def get_envelope_summary(
        investigation_id: str,
        request: Request,
    ) -> Response:
        _reject_query_parameters(request, allowed=set())
        validated_id = _validated_investigation_id(investigation_id)
        if validated_id is None:
            raise _InvalidApiRequest
        summary = await _wait_for_envelope_summary(
            _operator_service(application),
            validated_id,
        )
        return Response(
            content=canonical_json_bytes(summary),
            media_type="application/json",
        )

    @application.post(
        "/api/v1/investigations",
        response_model=None,
        responses={
            HTTPStatus.OK: {"description": "Existing identical investigation"},
            HTTPStatus.CREATED: {"description": "Investigation created"},
        },
    )
    async def create_investigation(request: Request) -> Response:
        _reject_query_parameters(request, allowed=set())
        envelope = _decode_envelope(await _read_contract_body(request))
        request.state.investigation_id = envelope.investigation_id
        result = await _call_service(_service(application).create(envelope))
        try:
            created = result.created
            result_report = result.report
        except Exception as error:
            raise _InternalApiFailure from error
        if not isinstance(created, bool):
            raise _InternalApiFailure
        report = _validated_report(
            result_report,
            investigation_id=envelope.investigation_id,
            envelope_sha256=canonical_sha256(envelope),
        )
        return Response(
            content=canonical_json_bytes(report),
            status_code=(HTTPStatus.CREATED if created else HTTPStatus.OK),
            media_type="application/json",
        )

    @application.get(
        "/api/v1/investigations/{investigation_id}",
        response_model=None,
    )
    async def get_investigation(
        investigation_id: str,
        request: Request,
    ) -> Response:
        _reject_query_parameters(request, allowed=set())
        validated_id = _validated_investigation_id(investigation_id)
        if validated_id is None:
            raise _InvalidApiRequest
        report = _validated_report(
            await _call_service(_service(application).get(validated_id)),
            investigation_id=validated_id,
        )
        return Response(
            content=canonical_json_bytes(report),
            media_type="application/json",
        )

    @application.get(
        "/api/v1/investigations/{investigation_id}/events",
        response_model=None,
    )
    async def stream_investigation_events(
        investigation_id: str,
        request: Request,
    ) -> StreamingResponse:
        validated_id = _validated_investigation_id(investigation_id)
        if validated_id is None:
            raise _InvalidApiRequest
        after = _resume_cursor(request)
        active_service = _service(application)
        initial = _validated_snapshot(
            await _call_service(active_service.snapshot(validated_id, after=after)),
            investigation_id=validated_id,
            after=after,
        )

        async def events() -> AsyncIterator[bytes]:
            cancellation_event = asyncio.Event()
            cursor = after
            snapshot = initial
            try:
                while True:
                    for event in snapshot.events:
                        yield _sse_event(event)
                    cursor = snapshot.cursor
                    if snapshot.terminal or await request.is_disconnected():
                        return
                    snapshot = _validated_snapshot(
                        await _call_service(
                            active_service.wait_for_events(
                                validated_id,
                                after=cursor,
                                cancellation_event=cancellation_event,
                            )
                        ),
                        investigation_id=validated_id,
                        after=cursor,
                    )
                    if not snapshot.events and not snapshot.terminal:
                        raise _InternalApiFailure
            finally:
                cancellation_event.set()

        return StreamingResponse(
            events(),
            media_type="text/event-stream",
            headers={
                "Cache-Control": "no-cache",
                "X-Accel-Buffering": "no",
                "X-Content-Type-Options": "nosniff",
            },
        )

    return application


app = create_app()


def main() -> None:
    """Run the API on the loopback interface."""

    uvicorn.run(app, host="127.0.0.1", port=8000)
