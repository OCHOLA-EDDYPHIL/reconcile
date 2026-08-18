"""Strict asynchronous client for the operator scenario API."""

from __future__ import annotations

import asyncio
import inspect
import ipaddress
import re
from collections.abc import AsyncIterator, Awaitable, Callable
from contextlib import suppress
from dataclasses import dataclass
from http import HTTPStatus
from typing import Self
from urllib.parse import urlsplit

import httpx

from reconcile.contracts import (
    MAX_SCENARIO_RUN_EVENTS,
    ApiError,
    ApiErrorCode,
    Classification,
    ContractError,
    ExecutionEnvelopeSummary,
    ScenarioLaunchRequest,
    ScenarioLifecycleEventPayload,
    ScenarioOperationalStatus,
    ScenarioRunEvent,
    ScenarioRunEventType,
    ScenarioRunLifecycle,
    ScenarioRunMode,
    ScenarioRunResultKind,
    ScenarioRunSnapshot,
    TerminalStateEventPayload,
    canonical_json_bytes,
    decode_contract,
)
from reconcile.interfaces.api_client import (
    InvalidRequestError,
    InvestigationApiClientError,
    InvestigationConflictError,
    InvestigationNotFoundError,
    RemoteInternalError,
    RemoteProtocolError,
    ServiceUnavailableError,
    TransportError,
    _identity_authorization_headers,
    _IdentityUnavailableError,
    _validated_identity_audience,
)
from reconcile.security import contains_sensitive_material

DEFAULT_OPERATOR_API_BASE_URL = "http://127.0.0.1:8000"

_MAX_BASE_URL_LENGTH = 2_048
_MAX_JSON_RESPONSE_BYTES = 1_048_576
_MAX_SSE_LINE_BYTES = 1_048_576
_MAX_SSE_EVENT_BYTES = 1_048_576
_MAX_SSE_EMPTY_LINES = MAX_SCENARIO_RUN_EVENTS
_MAX_RECONNECTS = 10
_DEFAULT_RECONNECTS = 3
_CONNECT_TIMEOUT_SECONDS = 5.0
_JSON_READ_TIMEOUT_SECONDS = 10.0
_WRITE_TIMEOUT_SECONDS = 5.0
_POOL_TIMEOUT_SECONDS = 5.0
_IDENTIFIER_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")

type OperatorIdentityTokenSupplier = Callable[[str], str | Awaitable[str]]

_ERROR_STATUS = {
    ApiErrorCode.INVALID_CONTRACT: HTTPStatus.BAD_REQUEST,
    ApiErrorCode.UNSUPPORTED_CONTRACT_VERSION: HTTPStatus.UNPROCESSABLE_ENTITY,
    ApiErrorCode.INVESTIGATION_NOT_FOUND: HTTPStatus.NOT_FOUND,
    ApiErrorCode.DUPLICATE_INVESTIGATION_ID: HTTPStatus.CONFLICT,
    ApiErrorCode.DEPENDENCY_UNAVAILABLE: HTTPStatus.SERVICE_UNAVAILABLE,
    ApiErrorCode.INTERNAL_FAILURE: HTTPStatus.INTERNAL_SERVER_ERROR,
}

_ERROR_TYPES: dict[ApiErrorCode, type[InvestigationApiClientError]] = {
    ApiErrorCode.INVALID_CONTRACT: InvalidRequestError,
    ApiErrorCode.UNSUPPORTED_CONTRACT_VERSION: InvalidRequestError,
    ApiErrorCode.INVESTIGATION_NOT_FOUND: InvestigationNotFoundError,
    ApiErrorCode.DUPLICATE_INVESTIGATION_ID: InvestigationConflictError,
    ApiErrorCode.DEPENDENCY_UNAVAILABLE: ServiceUnavailableError,
    ApiErrorCode.INTERNAL_FAILURE: RemoteInternalError,
}

_TERMINAL_LIFECYCLES = frozenset(
    {
        ScenarioRunLifecycle.COMPLETED,
        ScenarioRunLifecycle.FAILED,
        ScenarioRunLifecycle.CANCELLED,
    }
)


class LaunchOutcomeUnknownError(TransportError):
    """The launch request may have reached the API, so replay must be explicit."""

    message = "The scenario launch outcome is unknown."


class StreamInterruptedError(TransportError):
    """A scenario stream ended before terminal state was confirmed."""

    message = "The scenario event stream was interrupted."

    def __init__(self, last_cursor: int) -> None:
        super().__init__()
        self.last_cursor = last_cursor


@dataclass(frozen=True, slots=True)
class ScenarioLaunchResult:
    """Transport result for a newly accepted or exactly replayed launch."""

    created: bool
    snapshot: ScenarioRunSnapshot


def _invalid_request() -> InvalidRequestError:
    return InvalidRequestError()


def _protocol_error() -> RemoteProtocolError:
    return RemoteProtocolError()


def _validated_base_url(value: str) -> httpx.URL:
    if (
        not isinstance(value, str)
        or not value
        or len(value) > _MAX_BASE_URL_LENGTH
        or any(character.isspace() or ord(character) < 32 for character in value)
        or "\x7f" in value
        or "\\" in value
        or "@" in value
        or "?" in value
        or "#" in value
    ):
        raise _invalid_request() from None

    try:
        split = urlsplit(value)
        split_port = split.port
        url = httpx.URL(value)
        port = url.port
    except Exception:
        raise _invalid_request() from None

    if (
        url.scheme not in {"http", "https"}
        or not url.host
        or url.username
        or url.password
        or url.path != "/"
        or split.path not in {"", "/"}
        or url.query
        or url.fragment
        or "%" in url.host
        or (port is not None and not 1 <= port <= 65_535)
        or (split_port is not None and not 1 <= split_port <= 65_535)
    ):
        raise _invalid_request() from None

    if url.scheme == "http":
        host = url.host.lower()
        if host != "localhost":
            try:
                address = ipaddress.ip_address(host)
            except ValueError:
                raise _invalid_request() from None
            if not address.is_loopback:
                raise _invalid_request() from None
    return url.copy_with(path="")


def _validated_investigation_id(value: str) -> str:
    if (
        not isinstance(value, str)
        or _IDENTIFIER_PATTERN.fullmatch(value) is None
        or contains_sensitive_material(value)
    ):
        raise _invalid_request() from None
    return value


def _validated_cursor(value: int) -> int:
    if (
        isinstance(value, bool)
        or not isinstance(value, int)
        or not 0 <= value <= MAX_SCENARIO_RUN_EVENTS
    ):
        raise _invalid_request() from None
    return value


def _validated_reconnects(value: int) -> int:
    if (
        isinstance(value, bool)
        or not isinstance(value, int)
        or not 0 <= value <= _MAX_RECONNECTS
    ):
        raise _invalid_request() from None
    return value


def _require_content_type(response: httpx.Response, expected: str) -> None:
    values = response.headers.get_list("content-type")
    if len(values) != 1:
        raise _protocol_error() from None
    media_type = values[0].split(";", 1)[0].strip().lower()
    if media_type != expected:
        raise _protocol_error() from None


def _require_identity_encoding(response: httpx.Response) -> None:
    values = response.headers.get_list("content-encoding")
    if values and (len(values) != 1 or values[0].strip().lower() != "identity"):
        raise _protocol_error() from None


def _declared_content_length(response: httpx.Response) -> int | None:
    values = response.headers.get_list("content-length")
    if not values:
        return None
    if len(values) != 1 or re.fullmatch(r"0|[1-9][0-9]*", values[0]) is None:
        raise _protocol_error() from None
    length = int(values[0])
    if length > _MAX_JSON_RESPONSE_BYTES:
        raise _protocol_error() from None
    return length


async def _bounded_response_body(response: httpx.Response) -> bytes:
    _require_identity_encoding(response)
    declared_length = _declared_content_length(response)
    body = bytearray()
    async for chunk in response.aiter_bytes():
        if len(body) + len(chunk) > _MAX_JSON_RESPONSE_BYTES:
            raise _protocol_error() from None
        body.extend(chunk)
    if declared_length is not None and len(body) != declared_length:
        raise _protocol_error() from None
    return bytes(body)


def _decode_canonical[ContractModel](
    payload: bytes,
    model_type: type[ContractModel],
) -> ContractModel:
    try:
        model = decode_contract(payload, model_type)
        if canonical_json_bytes(model) != payload:
            raise _protocol_error()
    except InvestigationApiClientError:
        raise
    except (ContractError, TypeError, ValueError):
        raise _protocol_error() from None
    return model


async def _decode_json_response[ContractModel](
    response: httpx.Response,
    model_type: type[ContractModel],
) -> ContractModel:
    _require_content_type(response, "application/json")
    return _decode_canonical(await _bounded_response_body(response), model_type)


async def _raise_api_error(response: httpx.Response) -> None:
    error = await _decode_json_response(response, ApiError)
    if response.status_code != _ERROR_STATUS[error.code]:
        raise _protocol_error() from None
    error_type = _ERROR_TYPES[error.code]
    raise error_type(error.code) from None


async def _bounded_sse_lines(response: httpx.Response) -> AsyncIterator[bytes]:
    buffer = bytearray()
    async for chunk in response.aiter_bytes():
        start = 0
        while start < len(chunk):
            newline = chunk.find(b"\n", start)
            if newline < 0:
                remainder = chunk[start:]
                if len(buffer) + len(remainder) > _MAX_SSE_LINE_BYTES:
                    raise _protocol_error() from None
                buffer.extend(remainder)
                break
            segment = chunk[start:newline]
            if len(buffer) + len(segment) > _MAX_SSE_LINE_BYTES:
                raise _protocol_error() from None
            buffer.extend(segment)
            line = bytes(buffer)
            buffer.clear()
            if line.endswith(b"\r"):
                line = line[:-1]
            yield line
            start = newline + 1
    if buffer:
        raise _protocol_error() from None


async def _sse_records(response: httpx.Response) -> AsyncIterator[dict[bytes, bytes]]:
    fields: dict[bytes, bytes] = {}
    event_size = 0
    empty_line_count = 0
    allowed_fields = {b"id", b"event", b"data"}
    async for line in _bounded_sse_lines(response):
        if not line:
            if fields:
                if set(fields) != allowed_fields:
                    raise _protocol_error() from None
                yield fields
                fields = {}
                event_size = 0
            else:
                empty_line_count += 1
                if empty_line_count > _MAX_SSE_EMPTY_LINES:
                    raise _protocol_error() from None
            continue

        event_size += len(line) + 1
        if event_size > _MAX_SSE_EVENT_BYTES or b": " not in line:
            raise _protocol_error() from None
        name, value = line.split(b": ", 1)
        if name not in allowed_fields or name in fields:
            raise _protocol_error() from None
        fields[name] = value

    if fields:
        raise _protocol_error() from None


def _decode_sse_event(
    fields: dict[bytes, bytes],
    *,
    investigation_id: str,
    expected_cursor: int,
) -> ScenarioRunEvent:
    try:
        cursor_text = fields[b"id"].decode("ascii")
        event_type = fields[b"event"].decode("ascii")
    except (KeyError, UnicodeDecodeError):
        raise _protocol_error() from None

    if cursor_text != str(expected_cursor):
        raise _protocol_error() from None
    event = _decode_canonical(fields[b"data"], ScenarioRunEvent)
    if (
        event.cursor != expected_cursor
        or event.investigation_id != investigation_id
        or event.type.value != event_type
    ):
        raise _protocol_error() from None
    return event


def _is_accepted(event: ScenarioRunEvent) -> bool:
    return (
        event.type is ScenarioRunEventType.LIFECYCLE
        and type(event.payload) is ScenarioLifecycleEventPayload
        and event.payload.lifecycle is ScenarioRunLifecycle.ACCEPTED
    )


def _is_terminal(event: ScenarioRunEvent) -> bool:
    return (
        event.type is ScenarioRunEventType.TERMINAL
        and type(event.payload) is TerminalStateEventPayload
    )


def _validate_terminal_snapshot(
    event: ScenarioRunEvent,
    snapshot: ScenarioRunSnapshot,
) -> None:
    if not _is_terminal(event):
        raise _protocol_error() from None
    terminal = event.payload.terminal
    if (
        snapshot.investigation_id != event.investigation_id
        or snapshot.event_cursor != event.cursor
        or snapshot.lifecycle is not terminal.lifecycle
        or snapshot.failure_category is not terminal.failure_category
    ):
        raise _protocol_error() from None

    if terminal.result_kind is ScenarioRunResultKind.REPORT:
        report = snapshot.report
        if (
            snapshot.mode is ScenarioRunMode.COMPARE
            or report is None
            or snapshot.comparison is not None
            or report.classification is not terminal.classification
            or sum(item.allowed for item in report.action_gate)
            != terminal.action_gate_allowed_count
            or sum(not item.allowed for item in report.action_gate)
            != terminal.action_gate_denied_count
            or len(report.missing_evidence) != terminal.missing_evidence_count
            or (report.classification is not Classification.COMMITTED)
            is not terminal.escalation_required
        ):
            raise _protocol_error() from None
    elif terminal.result_kind is ScenarioRunResultKind.COMPARISON:
        if (
            snapshot.mode is not ScenarioRunMode.COMPARE
            or snapshot.comparison is None
            or snapshot.report is not None
        ):
            raise _protocol_error() from None
    elif snapshot.report is not None or snapshot.comparison is not None:
        raise _protocol_error() from None


class OperatorApiClient:
    """Strict async-only remote boundary for operator scenario operations."""

    def __init__(
        self,
        base_url: str = DEFAULT_OPERATOR_API_BASE_URL,
        *,
        transport: httpx.AsyncBaseTransport | None = None,
        identity_token_supplier: OperatorIdentityTokenSupplier | None = None,
        identity_audience: str | None = None,
    ) -> None:
        validated_url = _validated_base_url(base_url)
        if (identity_token_supplier is None) is not (identity_audience is None):
            raise _invalid_request() from None
        if identity_token_supplier is not None:
            if not callable(identity_token_supplier) or validated_url.scheme != "https":
                raise _invalid_request() from None
            validated_audience = _validated_identity_audience(identity_audience)
        else:
            validated_audience = None
        timeout = httpx.Timeout(
            connect=_CONNECT_TIMEOUT_SECONDS,
            read=_JSON_READ_TIMEOUT_SECONDS,
            write=_WRITE_TIMEOUT_SECONDS,
            pool=_POOL_TIMEOUT_SECONDS,
        )
        self._event_timeout = httpx.Timeout(
            connect=_CONNECT_TIMEOUT_SECONDS,
            read=None,
            write=_WRITE_TIMEOUT_SECONDS,
            pool=_POOL_TIMEOUT_SECONDS,
        )
        try:
            self._client = httpx.AsyncClient(
                base_url=validated_url,
                timeout=timeout,
                follow_redirects=False,
                trust_env=False,
                transport=transport,
            )
        except Exception:
            raise _invalid_request() from None
        self._identity_token_supplier = identity_token_supplier
        self._identity_audience = validated_audience
        self._closed = False
        self._close_lock = asyncio.Lock()
        self._close_task: asyncio.Task[None] | None = None

    async def _request_headers(self, accept: str) -> dict[str, str]:
        headers = {"Accept": accept}
        supplier = self._identity_token_supplier
        audience = self._identity_audience
        if supplier is None or audience is None:
            return headers
        try:
            if inspect.iscoroutinefunction(supplier):
                token = supplier(audience)
            else:
                token = await asyncio.to_thread(supplier, audience)
            if inspect.isawaitable(token):
                token = await token
            headers.update(_identity_authorization_headers(token))
        except _IdentityUnavailableError:
            raise
        except Exception:
            raise _IdentityUnavailableError from None
        return headers

    async def __aenter__(self) -> Self:
        self._ensure_open()
        return self

    async def __aexit__(
        self,
        exception_type: type[BaseException] | None,
        _exception: BaseException | None,
        _traceback: object,
    ) -> None:
        try:
            await self.aclose()
        except TransportError:
            if exception_type is None:
                raise

    def _ensure_open(self) -> None:
        if self._closed:
            raise _invalid_request() from None

    async def _finish_close(self) -> None:
        try:
            await self._client.aclose()
        except Exception:
            raise TransportError() from None

    @staticmethod
    async def _join_close_task(task: asyncio.Task[None]) -> None:
        try:
            await asyncio.shield(task)
        except asyncio.CancelledError:
            while not task.done():
                try:
                    await asyncio.shield(task)
                except asyncio.CancelledError:
                    continue
                except BaseException:
                    break
            with suppress(asyncio.CancelledError):
                task.exception()
            raise

    async def aclose(self) -> None:
        """Close once; concurrent and cancelled callers join the same cleanup."""

        async with self._close_lock:
            if self._close_task is None:
                self._closed = True
                self._close_task = asyncio.create_task(
                    self._finish_close(),
                    name="reconcile-operator-api-client-shutdown",
                )
            close_task = self._close_task
        await self._join_close_task(close_task)

    async def launch(self, request: ScenarioLaunchRequest) -> ScenarioLaunchResult:
        """Launch or replay one scenario without automatically retrying the POST."""

        self._ensure_open()
        try:
            if type(request) is not ScenarioLaunchRequest:
                raise TypeError
            sealed_request = decode_contract(
                canonical_json_bytes(request),
                ScenarioLaunchRequest,
            )
            payload = canonical_json_bytes(sealed_request)
        except Exception:
            raise _invalid_request() from None

        try:
            headers = await self._request_headers("application/json")
            headers["Content-Type"] = "application/json"
            async with self._client.stream(
                "POST",
                "/api/v1/scenario-runs",
                content=payload,
                headers=headers,
            ) as response:
                if response.status_code not in {HTTPStatus.OK, HTTPStatus.ACCEPTED}:
                    await _raise_api_error(response)
                snapshot = await _decode_json_response(response, ScenarioRunSnapshot)
        except InvestigationApiClientError:
            raise
        except Exception:
            raise LaunchOutcomeUnknownError() from None

        if (
            snapshot.launch_id != sealed_request.launch_id
            or snapshot.scenario is not sealed_request.scenario
            or snapshot.mode is not sealed_request.mode
        ):
            raise _protocol_error() from None
        return ScenarioLaunchResult(
            created=response.status_code == HTTPStatus.ACCEPTED,
            snapshot=snapshot,
        )

    async def get_snapshot(self, investigation_id: str) -> ScenarioRunSnapshot:
        """Retrieve one path-bound canonical operator snapshot."""

        self._ensure_open()
        validated_id = _validated_investigation_id(investigation_id)
        try:
            async with self._client.stream(
                "GET",
                f"/api/v1/scenario-runs/{validated_id}",
                headers=await self._request_headers("application/json"),
            ) as response:
                if response.status_code != HTTPStatus.OK:
                    await _raise_api_error(response)
                snapshot = await _decode_json_response(response, ScenarioRunSnapshot)
        except InvestigationApiClientError:
            raise
        except Exception:
            raise TransportError() from None
        if snapshot.investigation_id != validated_id:
            raise _protocol_error() from None
        return snapshot

    async def get_operational_status(
        self,
        investigation_id: str,
    ) -> ScenarioOperationalStatus:
        """Retrieve one path-bound canonical operational-status projection."""

        self._ensure_open()
        validated_id = _validated_investigation_id(investigation_id)
        try:
            async with self._client.stream(
                "GET",
                f"/api/v2/scenario-runs/{validated_id}/operational-status",
                headers=await self._request_headers("application/json"),
            ) as response:
                if response.status_code != HTTPStatus.OK:
                    await _raise_api_error(response)
                status = await _decode_json_response(
                    response,
                    ScenarioOperationalStatus,
                )
        except InvestigationApiClientError:
            raise
        except Exception:
            raise TransportError() from None
        if status.investigation_id != validated_id:
            raise _protocol_error() from None
        return status

    async def get_envelope_summary(
        self,
        investigation_id: str,
    ) -> ExecutionEnvelopeSummary:
        """Retrieve the server-owned sanitized execution-envelope projection."""

        self._ensure_open()
        validated_id = _validated_investigation_id(investigation_id)
        try:
            async with self._client.stream(
                "GET",
                f"/api/v1/investigations/{validated_id}/envelope-summary",
                headers=await self._request_headers("application/json"),
            ) as response:
                if response.status_code != HTTPStatus.OK:
                    await _raise_api_error(response)
                summary = await _decode_json_response(
                    response,
                    ExecutionEnvelopeSummary,
                )
        except InvestigationApiClientError:
            raise
        except Exception:
            raise TransportError() from None
        if summary.investigation_id != validated_id:
            raise _protocol_error() from None
        return summary

    def events(
        self,
        investigation_id: str,
        *,
        after: int = 0,
        max_reconnects: int = _DEFAULT_RECONNECTS,
    ) -> AsyncIterator[ScenarioRunEvent]:
        """Iterate an exclusive contiguous suffix through confirmed terminal state."""

        self._ensure_open()
        validated_id = _validated_investigation_id(investigation_id)
        cursor = _validated_cursor(after)
        reconnect_limit = _validated_reconnects(max_reconnects)
        return self._event_iterator(
            validated_id,
            cursor=cursor,
            reconnect_limit=reconnect_limit,
        )

    async def _event_iterator(
        self,
        investigation_id: str,
        *,
        cursor: int,
        reconnect_limit: int,
    ) -> AsyncIterator[ScenarioRunEvent]:
        reconnects = 0
        initial_cursor = cursor
        while True:
            pending_terminal: ScenarioRunEvent | None = None

            try:
                headers = await self._request_headers("text/event-stream")
                if cursor:
                    headers["Last-Event-ID"] = str(cursor)
                async with self._client.stream(
                    "GET",
                    f"/api/v1/scenario-runs/{investigation_id}/events",
                    headers=headers,
                    timeout=self._event_timeout,
                ) as response:
                    if response.status_code != HTTPStatus.OK:
                        await _raise_api_error(response)
                    _require_content_type(response, "text/event-stream")
                    _require_identity_encoding(response)

                    async for fields in _sse_records(response):
                        event = _decode_sse_event(
                            fields,
                            investigation_id=investigation_id,
                            expected_cursor=cursor + 1,
                        )
                        if (
                            cursor == 0
                            and initial_cursor == 0
                            and not _is_accepted(event)
                        ):
                            raise _protocol_error() from None
                        if _is_terminal(event):
                            pending_terminal = event
                            break
                        cursor = event.cursor
                        yield event
                        if cursor >= MAX_SCENARIO_RUN_EVENTS:
                            raise _protocol_error() from None

                if pending_terminal is not None:
                    snapshot = await self.get_snapshot(investigation_id)
                    _validate_terminal_snapshot(pending_terminal, snapshot)
                    cursor = pending_terminal.cursor
                    yield pending_terminal
                    return

                snapshot = await self.get_snapshot(investigation_id)
                if snapshot.event_cursor < cursor:
                    raise _protocol_error() from None
                if (
                    snapshot.lifecycle in _TERMINAL_LIFECYCLES
                    and snapshot.event_cursor == cursor
                ):
                    if initial_cursor == 0 and cursor == 0:
                        raise _protocol_error() from None
                    return
                raise StreamInterruptedError(cursor)
            except _IdentityUnavailableError:
                raise
            except InvestigationApiClientError as error:
                if not isinstance(error, TransportError):
                    raise
            except Exception:
                pass

            if reconnects >= reconnect_limit:
                raise StreamInterruptedError(cursor) from None
            reconnects += 1
            delay = min(0.01 * (2 ** (reconnects - 1) - 1), 0.25)
            if delay:
                await asyncio.sleep(delay)


__all__ = [
    "DEFAULT_OPERATOR_API_BASE_URL",
    "LaunchOutcomeUnknownError",
    "OperatorApiClient",
    "ScenarioLaunchResult",
    "StreamInterruptedError",
]
