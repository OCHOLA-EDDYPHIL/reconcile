"""Loopback FastAPI boundary for versioned investigation contracts."""

from __future__ import annotations

import asyncio
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
    ApiError,
    ApiErrorCode,
    ContractError,
    ExecutionEnvelope,
    InvestigationEvent,
    InvestigationReport,
    canonical_json_bytes,
    canonical_sha256,
    decode_contract,
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


def _validated_investigation_id(value: object) -> str | None:
    if not isinstance(value, str) or _IDENTIFIER_PATTERN.fullmatch(value) is None:
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
        DuplicateInvestigationId,
        code=ApiErrorCode.DUPLICATE_INVESTIGATION_ID,
        status_code=HTTPStatus.CONFLICT,
        message="The investigation identity conflicts with an existing envelope.",
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
        _InternalApiFailure,
        RepositoryError,
        EventJournalError,
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


def _reject_query_parameters(request: Request, *, allowed: set[str]) -> None:
    if not set(request.query_params).issubset(allowed):
        raise _InvalidApiRequest


def _parse_cursor_value(value: str) -> int:
    if value == "0":
        return 0
    if re.fullmatch(r"[1-9][0-9]{0,2}", value) is None:
        raise _InvalidApiRequest
    cursor = int(value)
    if cursor > MAX_INVESTIGATION_EVENTS:
        raise _InvalidApiRequest
    return cursor


def _resume_cursor(request: Request) -> int:
    _reject_query_parameters(request, allowed={"after"})
    query_values = request.query_params.getlist("after")
    header_values = request.headers.getlist("last-event-id")
    if len(query_values) > 1 or len(header_values) > 1:
        raise _InvalidApiRequest

    query_cursor = _parse_cursor_value(query_values[0]) if query_values else None
    header_cursor = _parse_cursor_value(header_values[0]) if header_values else None
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


async def _call_service[Result](operation: Awaitable[Result]) -> Result:
    try:
        return await operation
    except (_ApiBoundaryError, RepositoryError, EventJournalError):
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


def _sse_event(event: InvestigationEvent) -> bytes:
    return (
        f"id: {event.sequence}\nevent: {event.type.value}\ndata: ".encode()
        + canonical_json_bytes(event)
        + b"\n\n"
    )


def create_app(service: _InvestigationService | None = None) -> FastAPI:
    """Create the isolated single-process API and own its service lifetime."""

    @asynccontextmanager
    async def lifespan(application: FastAPI) -> AsyncIterator[None]:
        if application.state.investigation_service is None:
            application.state.investigation_service = _build_default_service()
        try:
            yield
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
    _install_error_handlers(application)

    @application.get("/health", response_model=None)
    async def health() -> Response:
        return Response(
            content=b'{"status":"ok"}',
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
