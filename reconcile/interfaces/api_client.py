"""Synchronous client for the versioned investigation API."""

from __future__ import annotations

import inspect
import ipaddress
import re
from collections.abc import Callable, Iterator
from http import HTTPStatus
from urllib.parse import urlsplit

import httpx

from reconcile.contracts import (
    MAX_INVESTIGATION_EVENTS,
    ApiError,
    ApiErrorCode,
    ContractError,
    ExecutionEnvelope,
    InvestigationEvent,
    InvestigationEventType,
    InvestigationReport,
    InvestigationStatus,
    LifecycleEventPayload,
    canonical_json_bytes,
    canonical_sha256,
    decode_contract,
)
from reconcile.security import contains_sensitive_material

DEFAULT_API_BASE_URL = "http://127.0.0.1:8000"

_MAX_BASE_URL_LENGTH = 2_048
_MAX_JSON_RESPONSE_BYTES = 1_048_576
_MAX_SSE_LINE_BYTES = 1_048_576
_MAX_SSE_EVENT_BYTES = 1_048_576
_MAX_SSE_EMPTY_LINES = MAX_INVESTIGATION_EVENTS
_MAX_RECONNECTS = 10
_DEFAULT_RECONNECTS = 3
_CONNECT_TIMEOUT_SECONDS = 5.0
_JSON_READ_TIMEOUT_SECONDS = 10.0
_WRITE_TIMEOUT_SECONDS = 5.0
_POOL_TIMEOUT_SECONDS = 5.0
_MAX_IDENTITY_AUDIENCE_BYTES = 2_048
_MAX_IDENTITY_TOKEN_BYTES = 6_144
_IDENTIFIER_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_JWT_SEGMENT_PATTERN = re.compile(r"^[A-Za-z0-9_-]+$")

type DestinationIdentityTokenSupplier = Callable[[str], str]

_ERROR_STATUS = {
    ApiErrorCode.INVALID_CONTRACT: HTTPStatus.BAD_REQUEST,
    ApiErrorCode.UNSUPPORTED_CONTRACT_VERSION: HTTPStatus.UNPROCESSABLE_ENTITY,
    ApiErrorCode.INVESTIGATION_NOT_FOUND: HTTPStatus.NOT_FOUND,
    ApiErrorCode.DUPLICATE_INVESTIGATION_ID: HTTPStatus.CONFLICT,
    ApiErrorCode.DEPENDENCY_UNAVAILABLE: HTTPStatus.SERVICE_UNAVAILABLE,
    ApiErrorCode.INTERNAL_FAILURE: HTTPStatus.INTERNAL_SERVER_ERROR,
}


class InvestigationApiClientError(Exception):
    """Base class for failures safe to present at the CLI boundary."""

    message = "The request could not be completed."

    def __init__(self, api_error_code: ApiErrorCode | None = None) -> None:
        super().__init__(self.message)
        self.api_error_code = api_error_code


class InvalidRequestError(InvestigationApiClientError):
    message = "The request is invalid."


class InvestigationNotFoundError(InvestigationApiClientError):
    message = "The investigation was not found."


class InvestigationConflictError(InvestigationApiClientError):
    message = "The investigation conflicts with an existing request."


class ServiceUnavailableError(InvestigationApiClientError):
    message = "A required service is unavailable."


class RemoteInternalError(InvestigationApiClientError):
    message = "The service could not complete the request."


class RemoteProtocolError(InvestigationApiClientError):
    message = "The service response is invalid."


class TransportError(InvestigationApiClientError):
    message = "The service could not be reached."


class _IdentityUnavailableError(TransportError):
    pass


_ERROR_TYPES: dict[ApiErrorCode, type[InvestigationApiClientError]] = {
    ApiErrorCode.INVALID_CONTRACT: InvalidRequestError,
    ApiErrorCode.UNSUPPORTED_CONTRACT_VERSION: InvalidRequestError,
    ApiErrorCode.INVESTIGATION_NOT_FOUND: InvestigationNotFoundError,
    ApiErrorCode.DUPLICATE_INVESTIGATION_ID: InvestigationConflictError,
    ApiErrorCode.DEPENDENCY_UNAVAILABLE: ServiceUnavailableError,
    ApiErrorCode.INTERNAL_FAILURE: RemoteInternalError,
}


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


def _validated_identity_audience(value: object) -> str:
    if type(value) is not str or not value:
        raise _invalid_request() from None
    try:
        encoded = value.encode("ascii")
    except UnicodeEncodeError:
        raise _invalid_request() from None
    if (
        len(encoded) > _MAX_IDENTITY_AUDIENCE_BYTES
        or any(character.isspace() for character in value)
        or any(ord(character) < 33 or ord(character) == 127 for character in value)
    ):
        raise _invalid_request() from None
    return value


def _identity_authorization_headers(token: object) -> dict[str, str]:
    if type(token) is not str or not token:
        raise _IdentityUnavailableError from None
    try:
        encoded = token.encode("ascii")
    except UnicodeEncodeError:
        raise _IdentityUnavailableError from None
    segments = token.split(".")
    if (
        len(encoded) > _MAX_IDENTITY_TOKEN_BYTES
        or len(segments) != 3
        or any(_JWT_SEGMENT_PATTERN.fullmatch(segment) is None for segment in segments)
    ):
        raise _IdentityUnavailableError from None
    authorization = f"Bearer {token}"
    return {
        "Authorization": authorization,
        "X-Serverless-Authorization": authorization,
    }


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
        or not 0 <= value <= MAX_INVESTIGATION_EVENTS
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


def _bounded_response_body(response: httpx.Response) -> bytes:
    _require_identity_encoding(response)
    declared_length = _declared_content_length(response)
    body = bytearray()
    for chunk in response.iter_bytes():
        if len(body) + len(chunk) > _MAX_JSON_RESPONSE_BYTES:
            raise _protocol_error() from None
        body.extend(chunk)
    if declared_length is not None and len(body) != declared_length:
        raise _protocol_error() from None
    return bytes(body)


def _decode_canonical[
    ContractModel: InvestigationReport | ApiError | InvestigationEvent,
](payload: bytes, model_type: type[ContractModel]) -> ContractModel:
    try:
        model = decode_contract(payload, model_type)
        if canonical_json_bytes(model) != payload:
            raise _protocol_error()
    except InvestigationApiClientError:
        raise
    except (ContractError, TypeError, ValueError):
        raise _protocol_error() from None
    return model


def _decode_report(
    response: httpx.Response,
    *,
    investigation_id: str,
    envelope_sha256: str | None = None,
) -> InvestigationReport:
    _require_content_type(response, "application/json")
    report = _decode_canonical(
        _bounded_response_body(response),
        InvestigationReport,
    )
    if report.investigation_id != investigation_id or (
        envelope_sha256 is not None and report.envelope_sha256 != envelope_sha256
    ):
        raise _protocol_error() from None
    return report


def _raise_api_error(response: httpx.Response) -> None:
    _require_content_type(response, "application/json")
    error = _decode_canonical(_bounded_response_body(response), ApiError)
    if response.status_code != _ERROR_STATUS[error.code]:
        raise _protocol_error() from None
    error_type = _ERROR_TYPES[error.code]
    raise error_type(error.code) from None


def _bounded_sse_lines(response: httpx.Response) -> Iterator[bytes]:
    buffer = bytearray()
    for chunk in response.iter_bytes():
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


def _sse_records(response: httpx.Response) -> Iterator[dict[bytes, bytes]]:
    fields: dict[bytes, bytes] = {}
    event_size = 0
    empty_line_count = 0
    allowed_fields = {b"id", b"event", b"data"}
    for line in _bounded_sse_lines(response):
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
        if event_size > _MAX_SSE_EVENT_BYTES:
            raise _protocol_error() from None
        if b": " not in line:
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
    expected_sequence: int,
) -> InvestigationEvent:
    try:
        sequence_text = fields[b"id"].decode("ascii")
        event_type = fields[b"event"].decode("ascii")
    except (KeyError, UnicodeDecodeError):
        raise _protocol_error() from None

    if sequence_text != str(expected_sequence):
        raise _protocol_error() from None
    event = _decode_canonical(fields[b"data"], InvestigationEvent)
    if (
        event.sequence != expected_sequence
        or event.investigation_id != investigation_id
        or event.type.value != event_type
    ):
        raise _protocol_error() from None
    return event


def _is_terminal(event: InvestigationEvent) -> bool:
    return (
        event.type is InvestigationEventType.LIFECYCLE
        and isinstance(event.payload, LifecycleEventPayload)
        and event.payload.status is InvestigationStatus.COMPLETED
    )


class InvestigationApiClient:
    """Strict synchronous remote boundary for investigation operations."""

    def __init__(
        self,
        base_url: str = DEFAULT_API_BASE_URL,
        *,
        transport: httpx.BaseTransport | None = None,
        identity_token_supplier: DestinationIdentityTokenSupplier | None = None,
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
            self._client = httpx.Client(
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

    def _request_headers(self, accept: str) -> dict[str, str]:
        headers = {"Accept": accept}
        supplier = self._identity_token_supplier
        audience = self._identity_audience
        if supplier is None or audience is None:
            return headers
        try:
            token = supplier(audience)
            if inspect.isawaitable(token):
                close = getattr(token, "close", None)
                if callable(close):
                    close()
                raise _IdentityUnavailableError
            headers.update(_identity_authorization_headers(token))
        except _IdentityUnavailableError:
            raise
        except Exception:
            raise _IdentityUnavailableError from None
        return headers

    def __enter__(self) -> InvestigationApiClient:
        self._ensure_open()
        return self

    def __exit__(
        self,
        exception_type: type[BaseException] | None,
        _exception: BaseException | None,
        _traceback: object,
    ) -> None:
        try:
            self.close()
        except TransportError:
            if exception_type is None:
                raise

    def close(self) -> None:
        if not self._closed:
            self._closed = True
            try:
                self._client.close()
            except Exception:
                raise TransportError() from None

    def _ensure_open(self) -> None:
        if self._closed:
            raise _invalid_request() from None

    def create(self, envelope: ExecutionEnvelope) -> InvestigationReport:
        """Create or replay an investigation without retrying the request."""

        self._ensure_open()
        try:
            payload = canonical_json_bytes(envelope)
            sealed_envelope = decode_contract(payload, ExecutionEnvelope)
            payload = canonical_json_bytes(sealed_envelope)
        except Exception:
            raise _invalid_request() from None

        try:
            headers = self._request_headers("application/json")
            headers["Content-Type"] = "application/json"
            with self._client.stream(
                "POST",
                "/api/v1/investigations",
                content=payload,
                headers=headers,
            ) as response:
                if response.status_code not in {HTTPStatus.OK, HTTPStatus.CREATED}:
                    _raise_api_error(response)
                return _decode_report(
                    response,
                    investigation_id=sealed_envelope.investigation_id,
                    envelope_sha256=canonical_sha256(sealed_envelope),
                )
        except InvestigationApiClientError:
            raise
        except Exception:
            raise TransportError() from None

    def get(self, investigation_id: str) -> InvestigationReport:
        """Retrieve one canonical investigation report without retrying."""

        self._ensure_open()
        validated_id = _validated_investigation_id(investigation_id)
        try:
            with self._client.stream(
                "GET",
                f"/api/v1/investigations/{validated_id}",
                headers=self._request_headers("application/json"),
            ) as response:
                if response.status_code != HTTPStatus.OK:
                    _raise_api_error(response)
                return _decode_report(response, investigation_id=validated_id)
        except InvestigationApiClientError:
            raise
        except Exception:
            raise TransportError() from None

    def events(
        self,
        investigation_id: str,
        *,
        after: int = 0,
        max_reconnects: int = _DEFAULT_RECONNECTS,
    ) -> Iterator[InvestigationEvent]:
        """Iterate a contiguous event stream through terminal completion."""

        self._ensure_open()
        validated_id = _validated_investigation_id(investigation_id)
        cursor = _validated_cursor(after)
        reconnect_limit = _validated_reconnects(max_reconnects)
        return self._event_iterator(
            validated_id,
            cursor=cursor,
            reconnect_limit=reconnect_limit,
        )

    def _event_iterator(
        self,
        investigation_id: str,
        *,
        cursor: int,
        reconnect_limit: int,
    ) -> Iterator[InvestigationEvent]:
        reconnects = 0
        while True:
            terminal_seen = False
            connection_cursor = cursor
            headers = self._request_headers("text/event-stream")
            if cursor:
                headers["Last-Event-ID"] = str(cursor)

            try:
                with self._client.stream(
                    "GET",
                    f"/api/v1/investigations/{investigation_id}/events",
                    headers=headers,
                    timeout=self._event_timeout,
                ) as response:
                    if response.status_code != HTTPStatus.OK:
                        _raise_api_error(response)
                    _require_content_type(response, "text/event-stream")
                    _require_identity_encoding(response)

                    for fields in _sse_records(response):
                        event = _decode_sse_event(
                            fields,
                            investigation_id=investigation_id,
                            expected_sequence=cursor + 1,
                        )
                        cursor = event.sequence
                        terminal_seen = _is_terminal(event)
                        yield event
                        if terminal_seen:
                            break
                        if cursor >= MAX_INVESTIGATION_EVENTS:
                            raise _protocol_error() from None
            except InvestigationApiClientError:
                raise
            except Exception:
                if terminal_seen:
                    raise TransportError() from None
                if reconnects >= reconnect_limit:
                    raise TransportError() from None
                reconnects += 1
                continue

            if terminal_seen:
                report = self.get(investigation_id)
                if report.status is not InvestigationStatus.COMPLETED:
                    raise _protocol_error() from None
                return

            if cursor == connection_cursor and cursor > 0:
                report = self.get(investigation_id)
                if report.status is InvestigationStatus.COMPLETED:
                    return

            if reconnects >= reconnect_limit:
                raise _protocol_error() from None
            reconnects += 1
