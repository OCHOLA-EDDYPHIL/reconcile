"""Deterministic coverage for the synchronous investigation API client."""

from __future__ import annotations

import gzip
import json
from collections.abc import Callable, Iterator
from typing import Any

import httpx
import pytest

from reconcile.contracts import (
    ERROR_VERSION,
    INVESTIGATION_EVENT_VERSION,
    INVESTIGATION_REPORT_VERSION,
    ApiError,
    ApiErrorCode,
    Classification,
    InvestigationEvent,
    InvestigationEventType,
    InvestigationReport,
    InvestigationStatus,
    LifecycleEventPayload,
    canonical_json_bytes,
    canonical_sha256,
    decode_contract,
)
from reconcile.interfaces.api_client import (
    _MAX_JSON_RESPONSE_BYTES,
    _MAX_SSE_EMPTY_LINES,
    _MAX_SSE_EVENT_BYTES,
    _MAX_SSE_LINE_BYTES,
    InvalidRequestError,
    InvestigationApiClient,
    InvestigationApiClientError,
    InvestigationConflictError,
    InvestigationNotFoundError,
    RemoteInternalError,
    RemoteProtocolError,
    ServiceUnavailableError,
    TransportError,
)
from tests.contract._factories import NOW, make_envelope, make_report

pytestmark = pytest.mark.unit


class _Chunks(httpx.SyncByteStream):
    def __init__(
        self,
        chunks: tuple[bytes, ...],
        failure: BaseException | None = None,
    ) -> None:
        self._chunks = chunks
        self._failure = failure

    def __iter__(self) -> Iterator[bytes]:
        yield from self._chunks
        if self._failure is not None:
            raise self._failure


class _CloseFailureTransport(httpx.BaseTransport):
    def handle_request(self, _request: httpx.Request) -> httpx.Response:
        return httpx.Response(500)

    def close(self) -> None:
        raise RuntimeError("private-close-credential")


def _client(
    handler: Callable[[httpx.Request], httpx.Response],
    *,
    base_url: str = "http://127.0.0.1:8000",
) -> InvestigationApiClient:
    return InvestigationApiClient(
        base_url,
        transport=httpx.MockTransport(handler),
    )


def _report_response(
    report: InvestigationReport,
    *,
    status_code: int = 200,
    headers: dict[str, str] | None = None,
    content: bytes | None = None,
) -> httpx.Response:
    response_headers = {"Content-Type": "application/json"}
    if headers is not None:
        response_headers.update(headers)
    return httpx.Response(
        status_code,
        headers=response_headers,
        content=canonical_json_bytes(report) if content is None else content,
    )


def _api_error_response(
    code: ApiErrorCode,
    status_code: int,
    *,
    message: str = "The request could not be completed.",
) -> httpx.Response:
    error = ApiError(
        schema_version=ERROR_VERSION,
        code=code,
        message=message,
        details={},
    )
    return httpx.Response(
        status_code,
        headers={"Content-Type": "application/json"},
        content=canonical_json_bytes(error),
    )


def _lifecycle_event(
    sequence: int,
    status: InvestigationStatus,
    *,
    investigation_id: str = "investigation-7",
) -> InvestigationEvent:
    return InvestigationEvent(
        schema_version=INVESTIGATION_EVENT_VERSION,
        investigation_id=investigation_id,
        sequence=sequence,
        type=InvestigationEventType.LIFECYCLE,
        occurred_at=NOW,
        payload=LifecycleEventPayload(status=status),
    )


def _active_report(
    status: InvestigationStatus = InvestigationStatus.INVESTIGATING,
) -> InvestigationReport:
    envelope = make_envelope()
    return InvestigationReport(
        schema_version=INVESTIGATION_REPORT_VERSION,
        investigation_id=envelope.investigation_id,
        envelope_sha256=canonical_sha256(envelope),
        status=status,
        created_at=NOW,
        updated_at=NOW,
        revision=1,
    )


def _sse_wire(
    event: InvestigationEvent,
    *,
    event_id: str | None = None,
    event_type: str | None = None,
    data: bytes | None = None,
    newline: bytes = b"\n",
) -> bytes:
    return newline.join(
        (
            f"id: {event_id or event.sequence}".encode(),
            f"event: {event_type or event.type.value}".encode(),
            b"data: " + (canonical_json_bytes(event) if data is None else data),
            b"",
            b"",
        )
    )


def _sse_response(
    content: bytes | None = None,
    *,
    stream: httpx.SyncByteStream | None = None,
    status_code: int = 200,
    content_type: str = "text/event-stream; charset=utf-8",
) -> httpx.Response:
    options: dict[str, Any] = {
        "status_code": status_code,
        "headers": {"Content-Type": content_type},
    }
    if stream is not None:
        options["stream"] = stream
    else:
        options["content"] = content or b""
    return httpx.Response(**options)


def _confirming_event_handler(
    handler: Callable[[httpx.Request], httpx.Response],
    *,
    report: InvestigationReport | None = None,
) -> Callable[[httpx.Request], httpx.Response]:
    terminal_report = report or make_report(Classification.COMMITTED)

    def wrapped(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("/events"):
            return handler(request)
        assert request.url.path == "/api/v1/investigations/investigation-7"
        return _report_response(terminal_report)

    return wrapped


@pytest.mark.parametrize(
    "base_url",
    (
        "http://127.0.0.1:8000",
        "http://127.255.255.254",
        "http://localhost",
        "http://[::1]:8000",
        "https://api.example.test",
        "https://203.0.113.8:8443/",
    ),
)
def test_base_url_accepts_loopback_http_and_https(base_url: str) -> None:
    client = _client(lambda _request: httpx.Response(500), base_url=base_url)

    client.close()


@pytest.mark.parametrize(
    "base_url",
    (
        "",
        "ftp://127.0.0.1",
        "http://example.test",
        "http://0.0.0.0",
        "http://127.0.0.1/path",
        "http://127.0.0.1?query=1",
        "http://127.0.0.1#fragment",
        "https://user:password@example.test",
        "https://@example.test",
        "https://example.test\\redirect",
        "https://example.test\n",
        "https://example.test:0",
        "https://example.test:65536",
        "https://example.test/a/..",
        "https://example.test%2f.invalid",
    ),
)
def test_base_url_rejects_unsafe_or_ambiguous_values(base_url: str) -> None:
    with pytest.raises(InvalidRequestError) as captured:
        _client(lambda _request: httpx.Response(500), base_url=base_url)

    assert str(captured.value) == "The request is invalid."


def test_client_disables_environment_proxies_and_redirects_and_sets_timeouts(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("HTTP_PROXY", "http://credential.invalid")
    client = _client(lambda _request: httpx.Response(500))

    assert client._client._trust_env is False  # type: ignore[attr-defined]
    assert client._client.follow_redirects is False
    assert client._client.timeout.connect == 5.0
    assert client._client.timeout.write == 5.0
    assert client._client.timeout.pool == 5.0
    assert client._client.timeout.read == 10.0
    assert client._event_timeout.read is None
    client.close()


def test_only_event_streaming_disables_the_read_timeout() -> None:
    terminal = _lifecycle_event(1, InvestigationStatus.COMPLETED)
    timeouts: list[dict[str, float | None]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        timeouts.append(request.extensions["timeout"])
        if request.url.path.endswith("/events"):
            return _sse_response(_sse_wire(terminal))
        return _report_response(make_report(Classification.COMMITTED))

    with _client(handler) as client:
        assert tuple(client.events("investigation-7", max_reconnects=0)) == (terminal,)

    assert timeouts == [
        {"connect": 5.0, "read": None, "write": 5.0, "pool": 5.0},
        {"connect": 5.0, "read": 10.0, "write": 5.0, "pool": 5.0},
    ]


@pytest.mark.parametrize("status_code", (200, 201))
def test_create_sends_one_canonical_envelope_and_accepts_create_or_replay(
    status_code: int,
) -> None:
    envelope = make_envelope()
    report = make_report(Classification.COMMITTED)
    requests: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        assert request.method == "POST"
        assert request.url.path == "/api/v1/investigations"
        assert request.url.query == b""
        assert request.headers["content-type"] == "application/json"
        assert request.headers["accept"] == "application/json"
        assert request.content == canonical_json_bytes(envelope)
        assert request.extensions["timeout"] == {
            "connect": 5.0,
            "read": 10.0,
            "write": 5.0,
            "pool": 5.0,
        }
        return _report_response(report, status_code=status_code)

    with _client(handler) as client:
        result = client.create(envelope)

    assert result == report
    assert len(requests) == 1


def test_create_never_retries_transport_failure_and_redacts_the_exception() -> None:
    calls = 0
    secret = "credential-value-at-https://user:password@example.test"

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        raise httpx.ConnectError(secret, request=request)

    with _client(handler) as client:
        with pytest.raises(TransportError) as captured:
            client.create(make_envelope())

    assert calls == 1
    assert str(captured.value) == "The service could not be reached."
    assert secret not in str(captured.value)
    assert captured.value.__cause__ is None


def test_get_returns_exact_canonical_report_once() -> None:
    report = make_report(Classification.UNKNOWN)
    requests: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        assert request.method == "GET"
        assert request.url.path == "/api/v1/investigations/investigation-7"
        assert request.headers["accept"] == "application/json"
        return _report_response(report)

    with _client(handler) as client:
        result = client.get("investigation-7")

    assert result.classification is Classification.UNKNOWN
    assert len(requests) == 1


@pytest.mark.parametrize(
    ("code", "status", "error_type"),
    (
        (ApiErrorCode.INVALID_CONTRACT, 400, InvalidRequestError),
        (ApiErrorCode.UNSUPPORTED_CONTRACT_VERSION, 422, InvalidRequestError),
        (ApiErrorCode.INVESTIGATION_NOT_FOUND, 404, InvestigationNotFoundError),
        (ApiErrorCode.DUPLICATE_INVESTIGATION_ID, 409, InvestigationConflictError),
        (ApiErrorCode.DEPENDENCY_UNAVAILABLE, 503, ServiceUnavailableError),
        (ApiErrorCode.INTERNAL_FAILURE, 500, RemoteInternalError),
    ),
)
def test_frozen_api_errors_map_to_safe_typed_failures(
    code: ApiErrorCode,
    status: int,
    error_type: type[InvestigationApiClientError],
) -> None:
    sentinel = "remote-credential-sentinel"

    with _client(
        lambda _request: _api_error_response(code, status, message=sentinel)
    ) as client:
        with pytest.raises(error_type) as captured:
            client.get("investigation-7")

    assert captured.value.api_error_code is code
    assert sentinel not in str(captured.value)
    assert set(vars(captured.value)) == {"api_error_code"}


def test_error_code_and_http_status_must_agree() -> None:
    with _client(
        lambda _request: _api_error_response(ApiErrorCode.INTERNAL_FAILURE, 404)
    ) as client:
        with pytest.raises(RemoteProtocolError):
            client.get("investigation-7")


@pytest.mark.parametrize(
    "response",
    (
        httpx.Response(200, headers={"Content-Type": "text/plain"}, content=b"{}"),
        _report_response(
            make_report(Classification.COMMITTED),
            content=b" " + canonical_json_bytes(make_report(Classification.COMMITTED)),
        ),
        _report_response(
            make_report(Classification.COMMITTED),
            content=b'{"schema_version":"reconcile/investigation-report/v1"}',
        ),
        _report_response(
            make_report(Classification.COMMITTED),
            headers={"Content-Encoding": "gzip"},
            content=gzip.compress(
                canonical_json_bytes(make_report(Classification.COMMITTED))
            ),
        ),
        _report_response(
            make_report(Classification.COMMITTED),
            headers={"Content-Length": str(_MAX_JSON_RESPONSE_BYTES + 1)},
        ),
    ),
)
def test_get_rejects_noncanonical_or_unbounded_success_responses(
    response: httpx.Response,
) -> None:
    with _client(lambda _request: response) as client:
        with pytest.raises(RemoteProtocolError):
            client.get("investigation-7")


def test_get_bounds_chunked_response_without_content_length() -> None:
    response = httpx.Response(
        200,
        headers={"Content-Type": "application/json"},
        stream=_Chunks((b"x" * _MAX_JSON_RESPONSE_BYTES, b"x")),
    )

    with _client(lambda _request: response) as client:
        with pytest.raises(RemoteProtocolError):
            client.get("investigation-7")


@pytest.mark.parametrize("field", ("investigation_id", "envelope_sha256"))
def test_create_rejects_report_identity_mismatch(field: str) -> None:
    payload = json.loads(canonical_json_bytes(make_report(Classification.COMMITTED)))
    payload[field] = (
        "different-investigation" if field == "investigation_id" else "f" * 64
    )
    report = decode_contract(json.dumps(payload), InvestigationReport)

    with _client(lambda _request: _report_response(report, status_code=201)) as client:
        with pytest.raises(RemoteProtocolError):
            client.create(make_envelope())


def test_get_does_not_follow_redirects() -> None:
    calls = 0

    def handler(_request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        return httpx.Response(
            307,
            headers={"Location": "https://credential.invalid/private"},
        )

    with _client(handler) as client:
        with pytest.raises(RemoteProtocolError):
            client.get("investigation-7")

    assert calls == 1


@pytest.mark.parametrize(
    ("investigation_id", "after", "max_reconnects"),
    (
        ("bad id", 0, 0),
        ("token:private-marker", 0, 0),
        ("investigation-7", -1, 0),
        ("investigation-7", 138, 0),
        ("investigation-7", True, 0),
        ("investigation-7", 0, -1),
        ("investigation-7", 0, 11),
        ("investigation-7", 0, True),
    ),
)
def test_events_rejects_invalid_identity_cursor_and_reconnect_bound(
    investigation_id: str,
    after: int,
    max_reconnects: int,
) -> None:
    with _client(
        lambda _request: pytest.fail("transport must not be called")
    ) as client:
        with pytest.raises(InvalidRequestError):
            client.events(
                investigation_id,
                after=after,
                max_reconnects=max_reconnects,
            )


def test_events_accepts_chunked_crlf_terminal_event() -> None:
    terminal = _lifecycle_event(1, InvestigationStatus.COMPLETED)
    wire = _sse_wire(terminal, newline=b"\r\n")
    chunks = tuple(wire[index : index + 7] for index in range(0, len(wire), 7))

    handler = _confirming_event_handler(
        lambda _request: _sse_response(stream=_Chunks(chunks))
    )
    with _client(handler) as client:
        events = tuple(client.events("investigation-7", max_reconnects=0))

    assert events == (terminal,)


def test_events_confirms_terminal_event_with_completed_report() -> None:
    terminal = _lifecycle_event(1, InvestigationStatus.COMPLETED)
    paths: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        paths.append(request.url.path)
        if request.url.path.endswith("/events"):
            return _sse_response(_sse_wire(terminal))
        return _report_response(make_report(Classification.UNKNOWN))

    with _client(handler) as client:
        assert tuple(client.events("investigation-7", max_reconnects=0)) == (terminal,)

    assert paths == [
        "/api/v1/investigations/investigation-7/events",
        "/api/v1/investigations/investigation-7",
    ]


def test_events_rejects_terminal_event_when_report_is_not_completed() -> None:
    terminal = _lifecycle_event(1, InvestigationStatus.COMPLETED)

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("/events"):
            return _sse_response(_sse_wire(terminal))
        return _report_response(_active_report())

    with _client(handler) as client:
        iterator = client.events("investigation-7", max_reconnects=0)
        assert next(iterator) == terminal
        with pytest.raises(RemoteProtocolError):
            next(iterator)


def test_events_restores_completed_report_when_cursor_is_already_terminal() -> None:
    paths: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        paths.append(request.url.path)
        if request.url.path.endswith("/events"):
            assert request.headers["last-event-id"] == "11"
            return _sse_response(b"")
        return _report_response(make_report(Classification.COMMITTED))

    with _client(handler) as client:
        assert tuple(client.events("investigation-7", after=11)) == ()

    assert paths == [
        "/api/v1/investigations/investigation-7/events",
        "/api/v1/investigations/investigation-7",
    ]


def test_events_reconnects_empty_terminal_cursor_while_report_is_active() -> None:
    paths: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        paths.append(request.url.path)
        if request.url.path.endswith("/events"):
            return _sse_response(b"")
        return _report_response(_active_report())

    with _client(handler) as client:
        with pytest.raises(RemoteProtocolError):
            tuple(
                client.events(
                    "investigation-7",
                    after=5,
                    max_reconnects=1,
                )
            )

    assert paths == [
        "/api/v1/investigations/investigation-7/events",
        "/api/v1/investigations/investigation-7",
        "/api/v1/investigations/investigation-7/events",
        "/api/v1/investigations/investigation-7",
    ]


def test_empty_initial_stream_cannot_skip_the_terminal_event() -> None:
    paths: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        paths.append(request.url.path)
        return _sse_response(b"")

    with _client(handler) as client:
        with pytest.raises(RemoteProtocolError):
            tuple(client.events("investigation-7", max_reconnects=0))

    assert paths == ["/api/v1/investigations/investigation-7/events"]


def test_events_resumes_from_explicit_cursor() -> None:
    terminal = _lifecycle_event(6, InvestigationStatus.COMPLETED)

    def handler(request: httpx.Request) -> httpx.Response:
        assert request.headers["last-event-id"] == "5"
        assert request.headers["accept"] == "text/event-stream"
        return _sse_response(_sse_wire(terminal))

    with _client(_confirming_event_handler(handler)) as client:
        assert tuple(client.events("investigation-7", after=5)) == (terminal,)


def test_events_reconnects_from_last_yielded_sequence_without_duplicates() -> None:
    first = _lifecycle_event(1, InvestigationStatus.INVESTIGATING)
    terminal = _lifecycle_event(2, InvestigationStatus.COMPLETED)
    requests: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        if len(requests) == 1:
            assert "last-event-id" not in request.headers
            return _sse_response(_sse_wire(first))
        assert request.headers["last-event-id"] == "1"
        return _sse_response(_sse_wire(terminal))

    with _client(_confirming_event_handler(handler)) as client:
        events = tuple(client.events("investigation-7", max_reconnects=1))

    assert events == (first, terminal)
    assert len(requests) == 2


def test_events_reconnects_after_transport_break_from_last_complete_event() -> None:
    first = _lifecycle_event(1, InvestigationStatus.INVESTIGATING)
    terminal = _lifecycle_event(2, InvestigationStatus.COMPLETED)
    cursors: list[str | None] = []

    def handler(request: httpx.Request) -> httpx.Response:
        cursors.append(request.headers.get("last-event-id"))
        if len(cursors) == 1:
            return _sse_response(
                stream=_Chunks(
                    (_sse_wire(first),),
                    httpx.ReadError("private transport material", request=request),
                )
            )
        return _sse_response(_sse_wire(terminal))

    with _client(_confirming_event_handler(handler)) as client:
        events = tuple(client.events("investigation-7", max_reconnects=1))

    assert events == (first, terminal)
    assert cursors == [None, "1"]


def test_events_rejects_duplicate_after_reconnect_without_yielding_it() -> None:
    first = _lifecycle_event(1, InvestigationStatus.INVESTIGATING)
    calls = 0

    def handler(_request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        return _sse_response(_sse_wire(first))

    with _client(handler) as client:
        iterator = client.events("investigation-7", max_reconnects=1)
        assert next(iterator) == first
        with pytest.raises(RemoteProtocolError):
            next(iterator)

    assert calls == 2


@pytest.mark.parametrize(
    "wire",
    (
        _sse_wire(
            _lifecycle_event(2, InvestigationStatus.COMPLETED),
            event_id="2",
        ),
        _sse_wire(
            _lifecycle_event(1, InvestigationStatus.COMPLETED),
            event_id="01",
        ),
        _sse_wire(
            _lifecycle_event(1, InvestigationStatus.COMPLETED),
            event_type="PROBE",
        ),
        _sse_wire(
            _lifecycle_event(
                1,
                InvestigationStatus.COMPLETED,
                investigation_id="other-investigation",
            )
        ),
        _sse_wire(
            _lifecycle_event(1, InvestigationStatus.COMPLETED),
            data=b" "
            + canonical_json_bytes(_lifecycle_event(1, InvestigationStatus.COMPLETED)),
        ),
        b"id: 1\nevent: LIFECYCLE\n\n",
        b"id: 1\nid: 1\nevent: LIFECYCLE\ndata: {}\n\n",
        b"id: 1\nevent: LIFECYCLE\nunknown: value\ndata: {}\n\n",
        b"id: 1\nevent: LIFECYCLE\ndata: {}",
    ),
)
def test_events_rejects_gaps_identity_mismatch_and_malformed_frames(
    wire: bytes,
) -> None:
    with _client(lambda _request: _sse_response(wire)) as client:
        with pytest.raises(RemoteProtocolError):
            tuple(client.events("investigation-7", max_reconnects=0))


def test_events_requires_event_stream_content_type() -> None:
    with _client(
        lambda _request: _sse_response(b"{}", content_type="application/json")
    ) as client:
        with pytest.raises(RemoteProtocolError):
            tuple(client.events("investigation-7", max_reconnects=0))


@pytest.mark.parametrize(
    "wire",
    (
        b"x" * (_MAX_SSE_LINE_BYTES + 1) + b"\n",
        b"id: 1\nevent: LIFECYCLE\ndata: "
        + b"x" * (_MAX_SSE_EVENT_BYTES - 10)
        + b"\n\n",
    ),
)
def test_events_bounds_each_line_and_event(wire: bytes) -> None:
    with _client(lambda _request: _sse_response(wire)) as client:
        with pytest.raises(RemoteProtocolError):
            tuple(client.events("investigation-7", max_reconnects=0))


def test_events_bounds_empty_delimiters() -> None:
    wire = b"\n" * (_MAX_SSE_EMPTY_LINES + 1)

    with _client(lambda _request: _sse_response(wire)) as client:
        with pytest.raises(RemoteProtocolError):
            tuple(client.events("investigation-7", max_reconnects=0))


def test_events_requires_terminal_completion_after_reconnect_bound() -> None:
    active = _lifecycle_event(1, InvestigationStatus.INVESTIGATING)
    event_calls = 0
    paths: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal event_calls
        paths.append(request.url.path)
        if not request.url.path.endswith("/events"):
            return _report_response(_active_report())
        event_calls += 1
        return _sse_response(_sse_wire(active) if event_calls == 1 else b"")

    with _client(handler) as client:
        iterator = client.events("investigation-7", max_reconnects=1)
        assert next(iterator) == active
        with pytest.raises(RemoteProtocolError):
            next(iterator)

    assert event_calls == 2
    assert paths == [
        "/api/v1/investigations/investigation-7/events",
        "/api/v1/investigations/investigation-7/events",
        "/api/v1/investigations/investigation-7",
    ]


def test_events_fails_when_capacity_is_exhausted_without_terminal() -> None:
    final_nonterminal = _lifecycle_event(137, InvestigationStatus.INVESTIGATING)
    calls = 0

    def handler(_request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        return _sse_response(_sse_wire(final_nonterminal))

    with _client(handler) as client:
        iterator = client.events("investigation-7", after=136)
        assert next(iterator) == final_nonterminal
        with pytest.raises(RemoteProtocolError):
            next(iterator)

    assert calls == 1


def test_events_maps_json_api_error_before_streaming() -> None:
    response = _api_error_response(ApiErrorCode.INVESTIGATION_NOT_FOUND, 404)

    with _client(lambda _request: response) as client:
        with pytest.raises(InvestigationNotFoundError):
            tuple(client.events("investigation-7"))


def test_events_exhausts_transport_reconnects_with_safe_failure() -> None:
    calls = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        raise httpx.ReadError("credential-sentinel", request=request)

    with _client(handler) as client:
        with pytest.raises(TransportError) as captured:
            tuple(client.events("investigation-7", max_reconnects=2))

    assert calls == 3
    assert "credential-sentinel" not in str(captured.value)


def test_keyboard_interrupt_is_not_translated_or_retried() -> None:
    calls = 0

    def handler(_request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        raise KeyboardInterrupt

    with _client(handler) as client:
        with pytest.raises(KeyboardInterrupt):
            tuple(client.events("investigation-7"))

    assert calls == 1


def test_closed_client_rejects_new_operations() -> None:
    client = _client(lambda _request: pytest.fail("transport must not be called"))
    client.close()
    client.close()

    with pytest.raises(InvalidRequestError):
        client.get("investigation-7")


def test_close_failure_is_sanitized_and_not_repeated() -> None:
    client = InvestigationApiClient(transport=_CloseFailureTransport())

    with pytest.raises(TransportError) as captured:
        client.close()
    client.close()

    assert str(captured.value) == "The service could not be reached."
    assert "private-close-credential" not in str(captured.value)


def test_close_failure_does_not_replace_an_active_typed_failure() -> None:
    client = InvestigationApiClient(transport=_CloseFailureTransport())

    with pytest.raises(InvestigationNotFoundError):
        with client:
            raise InvestigationNotFoundError()
