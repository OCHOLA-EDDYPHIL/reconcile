"""Deterministic coverage for the asynchronous operator API client."""

from __future__ import annotations

import ast
import asyncio
import gzip
import json
from collections.abc import AsyncIterator, Awaitable, Callable
from datetime import timedelta
from http import HTTPStatus
from pathlib import Path
from typing import Any

import httpx
import pytest

from reconcile.contracts import (
    ERROR_VERSION,
    EXECUTION_ENVELOPE_SUMMARY_VERSION,
    SCENARIO_LAUNCH_REQUEST_VERSION,
    SCENARIO_OPERATIONAL_STATUS_VERSION,
    SCENARIO_RUN_EVENT_VERSION,
    SCENARIO_RUN_SNAPSHOT_VERSION,
    ApiError,
    ApiErrorCode,
    Classification,
    EnvelopeEffectSummary,
    ExecutionEnvelopeSummary,
    ScenarioLaunchName,
    ScenarioLaunchRequest,
    ScenarioLifecycleEventPayload,
    ScenarioOperationalCleanupState,
    ScenarioOperationalInvestigationState,
    ScenarioOperationalMutationState,
    ScenarioOperationalRecoveryState,
    ScenarioOperationalStatus,
    ScenarioRunEvent,
    ScenarioRunEventType,
    ScenarioRunFailureCategory,
    ScenarioRunLifecycle,
    ScenarioRunMode,
    ScenarioRunResultKind,
    ScenarioRunSnapshot,
    TerminalStateEventPayload,
    TerminalStateSummary,
    canonical_json_bytes,
    canonical_sha256,
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
)
from reconcile.interfaces.operator_api_client import (
    _MAX_JSON_RESPONSE_BYTES,
    _MAX_SSE_EVENT_BYTES,
    _MAX_SSE_LINE_BYTES,
    DEFAULT_OPERATOR_API_BASE_URL,
    LaunchOutcomeUnknownError,
    OperatorApiClient,
    StreamInterruptedError,
)
from reconcile.operator import sanitize_report
from tests.contract._factories import NOW, make_envelope, make_report

pytestmark = pytest.mark.unit


class _Chunks(httpx.AsyncByteStream):
    def __init__(
        self,
        chunks: tuple[bytes, ...],
        failure: BaseException | None = None,
    ) -> None:
        self._chunks = chunks
        self._failure = failure
        self.closed = False

    async def __aiter__(self) -> AsyncIterator[bytes]:
        for chunk in self._chunks:
            yield chunk
        if self._failure is not None:
            raise self._failure

    async def aclose(self) -> None:
        self.closed = True


class _BlockingStream(httpx.AsyncByteStream):
    def __init__(self) -> None:
        self.started = asyncio.Event()
        self.release = asyncio.Event()
        self.closed = False

    async def __aiter__(self) -> AsyncIterator[bytes]:
        self.started.set()
        await self.release.wait()
        if False:
            yield b""

    async def aclose(self) -> None:
        self.closed = True


class _CloseFailureTransport(httpx.AsyncBaseTransport):
    async def handle_async_request(self, _request: httpx.Request) -> httpx.Response:
        return httpx.Response(500)

    async def aclose(self) -> None:
        raise RuntimeError("private-close-credential")


class _BlockingCloseTransport(httpx.AsyncBaseTransport):
    def __init__(self) -> None:
        self.started = asyncio.Event()
        self.release = asyncio.Event()
        self.calls = 0

    async def handle_async_request(self, _request: httpx.Request) -> httpx.Response:
        return httpx.Response(500)

    async def aclose(self) -> None:
        self.calls += 1
        self.started.set()
        await self.release.wait()


def _client(
    handler: Callable[[httpx.Request], httpx.Response],
    *,
    base_url: str = "http://127.0.0.1:8000",
    identity_token_supplier: (Callable[[str], str | Awaitable[str]] | None) = None,
    identity_audience: str | None = None,
) -> OperatorApiClient:
    return OperatorApiClient(
        base_url,
        transport=httpx.MockTransport(handler),
        identity_token_supplier=identity_token_supplier,
        identity_audience=identity_audience,
    )


def _launch() -> ScenarioLaunchRequest:
    return ScenarioLaunchRequest(
        schema_version=SCENARIO_LAUNCH_REQUEST_VERSION,
        launch_id="launch-7",
        scenario=ScenarioLaunchName.STORAGE,
        mode=ScenarioRunMode.FIXED,
    )


def _summary() -> ExecutionEnvelopeSummary:
    envelope = make_envelope()
    return ExecutionEnvelopeSummary(
        schema_version=EXECUTION_ENVELOPE_SUMMARY_VERSION,
        investigation_id=envelope.investigation_id,
        envelope_sha256=canonical_sha256(envelope),
        target_kind=envelope.target.target_kind,
        invoked_at=envelope.invoked_at,
        ambiguity_kind=envelope.ambiguity.kind,
        ambiguity_observed_at=envelope.ambiguity.observed_at,
        expected_effects=tuple(
            EnvelopeEffectSummary(
                effect_id=item.effect_id,
                commit_scope=item.commit_scope,
            )
            for item in envelope.expected_effects
        ),
        enabled_capabilities=envelope.context.enabled_capabilities,
        evidence_budget=envelope.context.evidence_budget,
    )


def _snapshot(
    lifecycle: ScenarioRunLifecycle = ScenarioRunLifecycle.ACCEPTED,
    *,
    cursor: int = 1,
    investigation_id: str = "investigation-7",
) -> ScenarioRunSnapshot:
    failure = (
        ScenarioRunFailureCategory.MODEL_UNAVAILABLE
        if lifecycle is ScenarioRunLifecycle.FAILED
        else None
    )
    return ScenarioRunSnapshot(
        schema_version=SCENARIO_RUN_SNAPSHOT_VERSION,
        launch_id="launch-7",
        investigation_id=investigation_id,
        scenario=ScenarioLaunchName.STORAGE,
        mode=ScenarioRunMode.FIXED,
        lifecycle=lifecycle,
        event_cursor=cursor,
        envelope_summary=None,
        report=None,
        comparison=None,
        failure_category=failure,
        accepted_at=NOW,
        updated_at=NOW + timedelta(milliseconds=cursor),
    )


def _operational_status(
    *,
    investigation_id: str = "investigation-7",
    cleanup_state: ScenarioOperationalCleanupState = (
        ScenarioOperationalCleanupState.NOT_REQUESTED
    ),
    recovery_state: ScenarioOperationalRecoveryState = (
        ScenarioOperationalRecoveryState.NOT_ESCALATED
    ),
) -> ScenarioOperationalStatus:
    investigation_state = (
        ScenarioOperationalInvestigationState.ESCALATION_REQUIRED
        if recovery_state is ScenarioOperationalRecoveryState.HUMAN_ESCALATION_REQUIRED
        else ScenarioOperationalInvestigationState.NOT_STARTED
    )
    if cleanup_state is not ScenarioOperationalCleanupState.NOT_REQUESTED:
        investigation_state = ScenarioOperationalInvestigationState.RECORDED
    return ScenarioOperationalStatus(
        schema_version=SCENARIO_OPERATIONAL_STATUS_VERSION,
        launch_id="launch-7",
        investigation_id=investigation_id,
        scenario=ScenarioLaunchName.STORAGE,
        mode=ScenarioRunMode.FIXED,
        revision=7,
        mutation_state=(
            ScenarioOperationalMutationState.RECORDED
            if investigation_state is ScenarioOperationalInvestigationState.RECORDED
            else ScenarioOperationalMutationState.NOT_STARTED
        ),
        investigation_state=investigation_state,
        cleanup_state=cleanup_state,
        recovery_state=recovery_state,
        updated_at=NOW,
    )


def _completed_unknown_snapshot(*, cursor: int = 3) -> ScenarioRunSnapshot:
    report = sanitize_report(make_report(Classification.UNKNOWN))
    return ScenarioRunSnapshot(
        schema_version=SCENARIO_RUN_SNAPSHOT_VERSION,
        launch_id="launch-7",
        investigation_id=report.investigation_id,
        scenario=ScenarioLaunchName.STORAGE,
        mode=ScenarioRunMode.FIXED,
        lifecycle=ScenarioRunLifecycle.COMPLETED,
        event_cursor=cursor,
        envelope_summary=_summary(),
        report=report,
        comparison=None,
        failure_category=None,
        accepted_at=NOW,
        updated_at=NOW + timedelta(milliseconds=cursor),
    )


def _event(
    cursor: int,
    event_type: ScenarioRunEventType,
    payload: object,
    *,
    investigation_id: str = "investigation-7",
) -> ScenarioRunEvent:
    return ScenarioRunEvent(
        schema_version=SCENARIO_RUN_EVENT_VERSION,
        investigation_id=investigation_id,
        cursor=cursor,
        type=event_type,
        occurred_at=NOW + timedelta(milliseconds=cursor),
        payload=payload,  # type: ignore[arg-type]
    )


def _accepted(cursor: int = 1) -> ScenarioRunEvent:
    return _event(
        cursor,
        ScenarioRunEventType.LIFECYCLE,
        ScenarioLifecycleEventPayload(lifecycle=ScenarioRunLifecycle.ACCEPTED),
    )


def _running(cursor: int = 2) -> ScenarioRunEvent:
    return _event(
        cursor,
        ScenarioRunEventType.LIFECYCLE,
        ScenarioLifecycleEventPayload(lifecycle=ScenarioRunLifecycle.RUNNING),
    )


def _failed_terminal(cursor: int = 3) -> ScenarioRunEvent:
    return _event(
        cursor,
        ScenarioRunEventType.TERMINAL,
        TerminalStateEventPayload(
            terminal=TerminalStateSummary(
                lifecycle=ScenarioRunLifecycle.FAILED,
                result_kind=ScenarioRunResultKind.NONE,
                classification=None,
                action_gate_allowed_count=0,
                action_gate_denied_count=0,
                missing_evidence_count=0,
                escalation_required=None,
                failure_category=ScenarioRunFailureCategory.MODEL_UNAVAILABLE,
            )
        ),
    )


def _unknown_terminal(cursor: int = 3) -> ScenarioRunEvent:
    report = _completed_unknown_snapshot(cursor=cursor).report
    assert report is not None
    return _event(
        cursor,
        ScenarioRunEventType.TERMINAL,
        TerminalStateEventPayload(
            terminal=TerminalStateSummary(
                lifecycle=ScenarioRunLifecycle.COMPLETED,
                result_kind=ScenarioRunResultKind.REPORT,
                classification=report.classification,
                action_gate_allowed_count=sum(
                    item.allowed for item in report.action_gate
                ),
                action_gate_denied_count=sum(
                    not item.allowed for item in report.action_gate
                ),
                missing_evidence_count=len(report.missing_evidence),
                escalation_required=True,
                failure_category=None,
            )
        ),
        investigation_id=report.investigation_id,
    )


def _json_response(
    model: object,
    *,
    status_code: int = 200,
    content: bytes | None = None,
    headers: dict[str, str] | None = None,
    stream: httpx.AsyncByteStream | None = None,
) -> httpx.Response:
    response_headers = {"Content-Type": "application/json"}
    if headers is not None:
        response_headers.update(headers)
    options: dict[str, Any] = {
        "status_code": status_code,
        "headers": response_headers,
    }
    if stream is not None:
        options["stream"] = stream
    else:
        options["content"] = canonical_json_bytes(model) if content is None else content
    return httpx.Response(**options)


def _api_error_response(code: ApiErrorCode, status_code: int) -> httpx.Response:
    return _json_response(
        ApiError(
            schema_version=ERROR_VERSION,
            code=code,
            message="remote-private-sentinel",
            details={},
        ),
        status_code=status_code,
    )


def _sse_wire(
    event: ScenarioRunEvent,
    *,
    event_id: str | None = None,
    event_type: str | None = None,
    data: bytes | None = None,
    newline: bytes = b"\n",
) -> bytes:
    return newline.join(
        (
            f"id: {event_id or event.cursor}".encode(),
            f"event: {event_type or event.type.value}".encode(),
            b"data: " + (canonical_json_bytes(event) if data is None else data),
            b"",
            b"",
        )
    )


def _sse_response(
    content: bytes | None = None,
    *,
    stream: httpx.AsyncByteStream | None = None,
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


async def _collect(
    iterator: AsyncIterator[ScenarioRunEvent],
) -> tuple[ScenarioRunEvent, ...]:
    return tuple([event async for event in iterator])


def test_operator_client_has_no_privileged_runtime_imports() -> None:
    path = Path("reconcile/interfaces/operator_api_client.py")
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    imported: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported.extend(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imported.append(node.module)

    assert not any(
        name == forbidden or name.startswith(f"{forbidden}.")
        for name in imported
        for forbidden in (
            "reconcile.operator",
            "reconcile.scenarios",
            "reconcile.controller",
            "reconcile.classifier",
        )
    )


@pytest.mark.parametrize(
    "base_url",
    (
        "http://127.0.0.1:8000",
        "https://127.255.255.254",
        "http://localhost",
        "https://localhost:8443/",
        "http://[::1]:8000",
        "https://api.example.test",
        "https://203.0.113.8:8443/",
    ),
)
def test_base_url_accepts_loopback_http_and_https(base_url: str) -> None:
    async def scenario() -> None:
        client = _client(lambda _request: httpx.Response(500), base_url=base_url)
        await client.aclose()

    asyncio.run(scenario())


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
        "https://user:password@localhost",
        "https://@localhost",
        "https://localhost\\redirect",
        "https://localhost\n",
        "https://localhost:0",
        "https://localhost:65536",
        "https://localhost/a/..",
        "https://localhost%2f.invalid",
    ),
)
def test_base_url_rejects_remote_unsafe_or_ambiguous_values(base_url: str) -> None:
    with pytest.raises(InvalidRequestError):
        _client(lambda _request: httpx.Response(500), base_url=base_url)


def test_operator_default_url_is_explicit_loopback() -> None:
    assert DEFAULT_OPERATOR_API_BASE_URL == "http://127.0.0.1:8000"


def test_destination_identity_is_refreshed_for_each_remote_request() -> None:
    tokens = iter(("header.payload1.signature", "header.payload2.signature"))
    audiences: list[str] = []
    headers: list[tuple[str, str]] = []

    async def supply_token(audience: str) -> str:
        audiences.append(audience)
        await asyncio.sleep(0)
        return next(tokens)

    def handler(request: httpx.Request) -> httpx.Response:
        headers.append(
            (
                request.headers["authorization"],
                request.headers["x-serverless-authorization"],
            )
        )
        return _json_response(_snapshot())

    async def scenario() -> None:
        async with _client(
            handler,
            base_url="https://api.example.test",
            identity_token_supplier=supply_token,
            identity_audience="https://service.example.test",
        ) as client:
            await client.get_snapshot("investigation-7")
            await client.get_snapshot("investigation-7")

    asyncio.run(scenario())
    assert audiences == [
        "https://service.example.test",
        "https://service.example.test",
    ]
    assert headers == [
        ("Bearer header.payload1.signature", "Bearer header.payload1.signature"),
        ("Bearer header.payload2.signature", "Bearer header.payload2.signature"),
    ]


def test_default_client_does_not_send_destination_identity_headers() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        assert "authorization" not in request.headers
        assert "x-serverless-authorization" not in request.headers
        return _json_response(_snapshot())

    async def scenario() -> None:
        async with _client(handler) as client:
            await client.get_snapshot("investigation-7")

    asyncio.run(scenario())


def test_sync_destination_identity_supplier_is_supported() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.headers["authorization"] == "Bearer header.payload.signature"
        return _json_response(_snapshot())

    async def scenario() -> None:
        async with _client(
            handler,
            base_url="https://api.example.test",
            identity_token_supplier=lambda _audience: "header.payload.signature",
            identity_audience="https://service.example.test",
        ) as client:
            await client.get_snapshot("investigation-7")

    asyncio.run(scenario())


@pytest.mark.parametrize(
    ("base_url", "supplier", "audience"),
    (
        ("https://api.example.test", lambda _audience: "a.b.c", None),
        ("https://api.example.test", None, "https://service.example.test"),
        (
            "http://127.0.0.1:8000",
            lambda _audience: "a.b.c",
            "https://service.example.test",
        ),
        (
            "https://api.example.test",
            lambda _audience: "a.b.c",
            "bad audience",
        ),
    ),
)
def test_destination_identity_configuration_is_explicit_and_https_only(
    base_url: str,
    supplier: Callable[[str], str | Awaitable[str]] | None,
    audience: str | None,
) -> None:
    with pytest.raises(InvalidRequestError):
        _client(
            lambda _request: pytest.fail("transport must not be called"),
            base_url=base_url,
            identity_token_supplier=supplier,
            identity_audience=audience,
        )


def test_destination_identity_failure_is_sanitized_and_not_retried() -> None:
    supplier_calls = 0
    transport_calls = 0

    async def supply_token(_audience: str) -> str:
        nonlocal supplier_calls
        supplier_calls += 1
        raise RuntimeError("private-identity-provider-detail")

    def handler(_request: httpx.Request) -> httpx.Response:
        nonlocal transport_calls
        transport_calls += 1
        return httpx.Response(500)

    async def scenario() -> None:
        async with _client(
            handler,
            base_url="https://api.example.test",
            identity_token_supplier=supply_token,
            identity_audience="https://service.example.test",
        ) as client:
            with pytest.raises(TransportError) as captured:
                await _collect(client.events("investigation-7", max_reconnects=3))
        assert str(captured.value) == "The service could not be reached."
        assert captured.value.__cause__ is None
        assert "private-identity-provider-detail" not in str(captured.value)

    asyncio.run(scenario())
    assert supplier_calls == 1
    assert transport_calls == 0


def test_destination_identity_supplier_cancellation_propagates() -> None:
    supplier_started = asyncio.Event()
    supplier_release = asyncio.Event()
    transport_calls = 0

    async def supply_token(_audience: str) -> str:
        supplier_started.set()
        await supplier_release.wait()
        return "header.payload.signature"

    def handler(_request: httpx.Request) -> httpx.Response:
        nonlocal transport_calls
        transport_calls += 1
        return _json_response(_snapshot())

    async def scenario() -> None:
        async with _client(
            handler,
            base_url="https://api.example.test",
            identity_token_supplier=supply_token,
            identity_audience="https://service.example.test",
        ) as client:
            task = asyncio.create_task(client.get_snapshot("investigation-7"))
            await supplier_started.wait()
            task.cancel()
            with pytest.raises(asyncio.CancelledError):
                await task

    asyncio.run(scenario())
    assert transport_calls == 0


@pytest.mark.parametrize(("status_code", "created"), ((202, True), (200, False)))
def test_launch_sends_one_canonical_request_and_binds_response(
    status_code: int,
    created: bool,
) -> None:
    requests: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        assert request.method == "POST"
        assert request.url.path == "/api/v1/scenario-runs"
        assert request.url.query == b""
        assert request.headers["accept"] == "application/json"
        assert request.headers["content-type"] == "application/json"
        assert request.content == canonical_json_bytes(_launch())
        return _json_response(_snapshot(), status_code=status_code)

    async def scenario() -> None:
        async with _client(handler) as client:
            result = await client.launch(_launch())
        assert result.created is created
        assert result.snapshot == _snapshot()

    asyncio.run(scenario())
    assert len(requests) == 1


def test_launch_never_retries_ambiguous_transport_failure_and_redacts_it() -> None:
    calls = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        raise httpx.ReadError("private-launch-credential", request=request)

    async def scenario() -> None:
        async with _client(handler) as client:
            with pytest.raises(LaunchOutcomeUnknownError) as captured:
                await client.launch(_launch())
        assert str(captured.value) == "The scenario launch outcome is unknown."
        assert captured.value.__cause__ is None
        assert "private-launch-credential" not in str(captured.value)

    asyncio.run(scenario())
    assert calls == 1


@pytest.mark.parametrize("field", ("launch_id", "scenario", "mode"))
def test_launch_rejects_response_not_bound_to_request(field: str) -> None:
    replacements = {
        "launch_id": "different-launch",
        "scenario": ScenarioLaunchName.SANDBOX_ORDER,
        "mode": ScenarioRunMode.ADAPTIVE,
    }
    snapshot = _snapshot().model_copy(update={field: replacements[field]})

    async def scenario() -> None:
        async with _client(
            lambda _request: _json_response(snapshot, status_code=202)
        ) as client:
            with pytest.raises(RemoteProtocolError):
                await client.launch(_launch())

    asyncio.run(scenario())


def test_snapshot_and_envelope_are_canonical_and_path_bound() -> None:
    summary = _summary()
    paths: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        paths.append(request.url.path)
        if request.url.path.endswith("/envelope-summary"):
            return _json_response(summary)
        return _json_response(_snapshot())

    async def scenario() -> None:
        async with _client(handler) as client:
            assert await client.get_snapshot("investigation-7") == _snapshot()
            assert (
                await client.get_envelope_summary(summary.investigation_id) == summary
            )

    asyncio.run(scenario())
    assert paths == [
        "/api/v1/scenario-runs/investigation-7",
        f"/api/v1/investigations/{summary.investigation_id}/envelope-summary",
    ]


def test_operational_status_is_canonical_and_path_bound() -> None:
    status = _operational_status()
    requests: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        return _json_response(status)

    async def scenario() -> None:
        async with _client(handler) as client:
            assert await client.get_operational_status("investigation-7") == status

    asyncio.run(scenario())
    assert len(requests) == 1
    assert requests[0].method == "GET"
    assert requests[0].url.path == (
        "/api/v2/scenario-runs/investigation-7/operational-status"
    )
    assert requests[0].url.query == b""
    assert requests[0].headers["accept"] == "application/json"


def test_operational_status_rejects_malformed_or_wrong_identity_response() -> None:
    status = _operational_status()
    responses = iter(
        (
            _json_response(
                status,
                content=b" " + canonical_json_bytes(status),
            ),
            _json_response(_operational_status(investigation_id="other-investigation")),
        )
    )

    async def scenario() -> None:
        async with _client(lambda _request: next(responses)) as client:
            with pytest.raises(RemoteProtocolError):
                await client.get_operational_status("investigation-7")
            with pytest.raises(RemoteProtocolError):
                await client.get_operational_status("investigation-7")

    asyncio.run(scenario())


def test_operational_status_preserves_existing_api_error_mapping() -> None:
    async def scenario() -> None:
        async with _client(
            lambda _request: _api_error_response(
                ApiErrorCode.DEPENDENCY_UNAVAILABLE,
                HTTPStatus.SERVICE_UNAVAILABLE,
            )
        ) as client:
            with pytest.raises(ServiceUnavailableError):
                await client.get_operational_status("investigation-7")

    asyncio.run(scenario())


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
def test_operator_api_errors_map_to_safe_existing_types(
    code: ApiErrorCode,
    status: int,
    error_type: type[InvestigationApiClientError],
) -> None:
    async def scenario() -> None:
        async with _client(
            lambda _request: _api_error_response(code, status)
        ) as client:
            with pytest.raises(error_type) as captured:
                await client.get_snapshot("investigation-7")
        assert captured.value.api_error_code is code
        assert "remote-private-sentinel" not in str(captured.value)

    asyncio.run(scenario())


@pytest.mark.parametrize(
    "response",
    (
        httpx.Response(200, headers={"Content-Type": "text/plain"}, content=b"{}"),
        _json_response(
            _snapshot(),
            content=b" " + canonical_json_bytes(_snapshot()),
        ),
        _json_response(
            _snapshot(),
            headers={"Content-Encoding": "gzip"},
            content=gzip.compress(canonical_json_bytes(_snapshot())),
        ),
        _json_response(
            _snapshot(),
            headers={"Content-Length": str(_MAX_JSON_RESPONSE_BYTES + 1)},
        ),
    ),
)
def test_snapshot_rejects_noncanonical_or_unbounded_response(
    response: httpx.Response,
) -> None:
    async def scenario() -> None:
        async with _client(lambda _request: response) as client:
            with pytest.raises(RemoteProtocolError):
                await client.get_snapshot("investigation-7")

    asyncio.run(scenario())


def test_snapshot_bounds_chunked_body_and_rejects_path_mismatch() -> None:
    responses = iter(
        (
            _json_response(
                _snapshot(),
                stream=_Chunks((b"x" * _MAX_JSON_RESPONSE_BYTES, b"x")),
            ),
            _json_response(_snapshot(investigation_id="other-investigation")),
        )
    )

    async def scenario() -> None:
        async with _client(lambda _request: next(responses)) as client:
            with pytest.raises(RemoteProtocolError):
                await client.get_snapshot("investigation-7")
            with pytest.raises(RemoteProtocolError):
                await client.get_snapshot("investigation-7")

    asyncio.run(scenario())


def test_terminal_stream_is_fragmented_ordered_and_snapshot_confirmed() -> None:
    events = (_accepted(), _running(), _failed_terminal())
    wire = b"".join(_sse_wire(event, newline=b"\r\n") for event in events)
    chunks = tuple(wire[index : index + 7] for index in range(0, len(wire), 7))
    paths: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        paths.append(request.url.path)
        if request.url.path.endswith("/events"):
            return _sse_response(stream=_Chunks(chunks))
        return _json_response(_snapshot(ScenarioRunLifecycle.FAILED, cursor=3))

    async def scenario() -> None:
        async with _client(handler) as client:
            assert await _collect(
                client.events("investigation-7", max_reconnects=0)
            ) == (events)

    asyncio.run(scenario())
    assert paths == [
        "/api/v1/scenario-runs/investigation-7/events",
        "/api/v1/scenario-runs/investigation-7",
    ]


def test_terminal_unknown_is_preserved_and_cross_checked() -> None:
    events = (_accepted(), _running(), _unknown_terminal())
    snapshot = _completed_unknown_snapshot()

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("/events"):
            return _sse_response(b"".join(map(_sse_wire, events)))
        return _json_response(snapshot)

    async def scenario() -> None:
        async with _client(handler) as client:
            observed = await _collect(client.events("investigation-7"))
        terminal = observed[-1].payload
        assert type(terminal) is TerminalStateEventPayload
        assert terminal.terminal.classification is Classification.UNKNOWN
        assert snapshot.report is not None
        assert snapshot.report.classification is Classification.UNKNOWN

    asyncio.run(scenario())


def test_stream_reconnects_exclusively_after_last_complete_event() -> None:
    event_calls = 0
    cursors: list[str | None] = []
    first = _accepted()
    terminal = _failed_terminal(cursor=2)
    terminal_snapshot = _snapshot(ScenarioRunLifecycle.FAILED, cursor=2)

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal event_calls
        if not request.url.path.endswith("/events"):
            return _json_response(terminal_snapshot)
        event_calls += 1
        cursors.append(request.headers.get("last-event-id"))
        if event_calls == 1:
            return _sse_response(
                stream=_Chunks(
                    (_sse_wire(first),),
                    httpx.ReadError("private-stream-detail", request=request),
                )
            )
        return _sse_response(_sse_wire(terminal))

    async def scenario() -> None:
        async with _client(handler) as client:
            observed = await _collect(
                client.events("investigation-7", max_reconnects=1)
            )
        assert observed == (first, terminal)

    asyncio.run(scenario())
    assert cursors == [None, "1"]


def test_empty_stream_at_confirmed_terminal_cursor_completes_cleanly() -> None:
    paths: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        paths.append(request.url.path)
        if request.url.path.endswith("/events"):
            assert request.headers["last-event-id"] == "3"
            return _sse_response()
        return _json_response(_snapshot(ScenarioRunLifecycle.FAILED, cursor=3))

    async def scenario() -> None:
        async with _client(handler) as client:
            assert await _collect(client.events("investigation-7", after=3)) == ()

    asyncio.run(scenario())
    assert paths == [
        "/api/v1/scenario-runs/investigation-7/events",
        "/api/v1/scenario-runs/investigation-7",
    ]


def test_empty_initial_stream_cannot_skip_the_accepted_event() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("/events"):
            return _sse_response()
        return _json_response(_snapshot(ScenarioRunLifecycle.CANCELLED, cursor=0))

    async def scenario() -> None:
        async with _client(handler) as client:
            with pytest.raises(RemoteProtocolError):
                await _collect(client.events("investigation-7", max_reconnects=0))

    asyncio.run(scenario())


def test_duplicate_after_reconnect_is_a_protocol_failure() -> None:
    calls = 0
    first = _accepted()

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal calls
        if not request.url.path.endswith("/events"):
            return _json_response(_snapshot(ScenarioRunLifecycle.RUNNING, cursor=1))
        calls += 1
        return _sse_response(_sse_wire(first))

    async def scenario() -> None:
        async with _client(handler) as client:
            iterator = client.events("investigation-7", max_reconnects=1)
            assert await anext(iterator) == first
            with pytest.raises(RemoteProtocolError):
                await anext(iterator)

    asyncio.run(scenario())
    assert calls == 2


@pytest.mark.parametrize(
    "wire",
    (
        _sse_wire(_failed_terminal(cursor=2)),
        _sse_wire(_accepted(), event_id="01"),
        _sse_wire(_accepted(), event_type="PROBE_RESULT"),
        _sse_wire(
            _event(
                1,
                ScenarioRunEventType.LIFECYCLE,
                ScenarioLifecycleEventPayload(lifecycle=ScenarioRunLifecycle.ACCEPTED),
                investigation_id="other-investigation",
            )
        ),
        _sse_wire(
            _accepted(),
            data=b" " + canonical_json_bytes(_accepted()),
        ),
        _sse_wire(_running(cursor=1)),
        b"id: 1\nevent: LIFECYCLE\n\n",
        b"id: 1\nid: 1\nevent: LIFECYCLE\ndata: {}\n\n",
        b"id: 1\nevent: LIFECYCLE\nunknown: value\ndata: {}\n\n",
        b"id: 1\nevent: LIFECYCLE\ndata: {}",
    ),
)
def test_stream_rejects_gaps_identity_mismatch_and_malformed_frames(
    wire: bytes,
) -> None:
    async def scenario() -> None:
        async with _client(lambda _request: _sse_response(wire)) as client:
            with pytest.raises(RemoteProtocolError):
                await _collect(client.events("investigation-7", max_reconnects=0))

    asyncio.run(scenario())


@pytest.mark.parametrize(
    "wire",
    (
        b"x" * (_MAX_SSE_LINE_BYTES + 1) + b"\n",
        b"id: 1\nevent: LIFECYCLE\ndata: "
        + b"x" * (_MAX_SSE_EVENT_BYTES - 10)
        + b"\n\n",
    ),
)
def test_stream_bounds_each_line_and_event(wire: bytes) -> None:
    async def scenario() -> None:
        async with _client(lambda _request: _sse_response(wire)) as client:
            with pytest.raises(RemoteProtocolError):
                await _collect(client.events("investigation-7", max_reconnects=0))

    asyncio.run(scenario())


def test_stream_interruption_is_typed_safe_and_carries_last_cursor() -> None:
    calls = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        raise httpx.ConnectError("private-stream-credential", request=request)

    async def scenario() -> None:
        async with _client(handler) as client:
            with pytest.raises(StreamInterruptedError) as captured:
                await _collect(
                    client.events(
                        "investigation-7",
                        after=7,
                        max_reconnects=2,
                    )
                )
        assert captured.value.last_cursor == 7
        assert str(captured.value) == "The scenario event stream was interrupted."
        assert captured.value.__cause__ is None
        assert "private-stream-credential" not in str(captured.value)

    asyncio.run(scenario())
    assert calls == 3


def test_terminal_event_is_not_yielded_when_snapshot_disagrees() -> None:
    events = (_accepted(), _running(), _failed_terminal())

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("/events"):
            return _sse_response(b"".join(map(_sse_wire, events)))
        return _json_response(_snapshot(ScenarioRunLifecycle.CANCELLED, cursor=3))

    async def scenario() -> None:
        async with _client(handler) as client:
            iterator = client.events("investigation-7", max_reconnects=0)
            assert await anext(iterator) == events[0]
            assert await anext(iterator) == events[1]
            with pytest.raises(RemoteProtocolError):
                await anext(iterator)

    asyncio.run(scenario())


@pytest.mark.parametrize(
    ("investigation_id", "after", "max_reconnects"),
    (
        ("bad id", 0, 0),
        ("token:private-marker", 0, 0),
        ("investigation-7", -1, 0),
        ("investigation-7", 1025, 0),
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
    async def scenario() -> None:
        async with _client(
            lambda _request: pytest.fail("transport must not be called")
        ) as client:
            with pytest.raises(InvalidRequestError):
                client.events(
                    investigation_id,
                    after=after,
                    max_reconnects=max_reconnects,
                )

    asyncio.run(scenario())


def test_stream_cancellation_closes_the_active_response_without_translation() -> None:
    stream: _BlockingStream | None = None

    def handler(_request: httpx.Request) -> httpx.Response:
        nonlocal stream
        stream = _BlockingStream()
        return _sse_response(stream=stream)

    async def scenario() -> None:
        async with _client(handler) as client:
            task = asyncio.create_task(
                _collect(client.events("investigation-7")),
            )
            while stream is None:
                await asyncio.sleep(0)
            await stream.started.wait()
            task.cancel()
            with pytest.raises(asyncio.CancelledError):
                await task
            assert stream.closed is True

    asyncio.run(scenario())


def test_close_failure_is_sanitized_shared_and_not_repeated() -> None:
    async def scenario() -> None:
        client = OperatorApiClient(transport=_CloseFailureTransport())
        with pytest.raises(TransportError) as captured:
            await client.aclose()
        with pytest.raises(TransportError):
            await client.aclose()
        assert str(captured.value) == "The service could not be reached."
        assert captured.value.__cause__ is None
        assert "private-close-credential" not in str(captured.value)

    asyncio.run(scenario())


def test_concurrent_close_callers_share_cancellation_safe_cleanup() -> None:
    async def scenario() -> None:
        transport = _BlockingCloseTransport()
        client = OperatorApiClient(transport=transport)
        first = asyncio.create_task(client.aclose())
        await transport.started.wait()
        second = asyncio.create_task(client.aclose())
        first.cancel()
        await asyncio.sleep(0)
        assert not first.done()
        assert not second.done()
        transport.release.set()
        results = await asyncio.gather(first, second, return_exceptions=True)
        assert isinstance(results[0], asyncio.CancelledError)
        assert results[1] is None
        assert transport.calls == 1

    asyncio.run(scenario())


def test_closed_client_rejects_new_operations() -> None:
    async def scenario() -> None:
        client = _client(lambda _request: pytest.fail("transport must not be called"))
        await client.aclose()
        with pytest.raises(InvalidRequestError):
            await client.get_snapshot("investigation-7")

    asyncio.run(scenario())


def test_status_and_error_code_must_agree_and_redirects_are_not_followed() -> None:
    responses = iter(
        (
            _api_error_response(ApiErrorCode.INTERNAL_FAILURE, 404),
            httpx.Response(
                HTTPStatus.TEMPORARY_REDIRECT,
                headers={"Location": "https://credential.invalid/private"},
            ),
        )
    )

    async def scenario() -> None:
        async with _client(lambda _request: next(responses)) as client:
            with pytest.raises(RemoteProtocolError):
                await client.get_snapshot("investigation-7")
            with pytest.raises(RemoteProtocolError):
                await client.get_snapshot("investigation-7")

    asyncio.run(scenario())


def test_client_disables_environment_proxy_redirects_and_bounds_timeouts(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("HTTP_PROXY", "http://credential.invalid")
    client = _client(lambda _request: httpx.Response(500))
    assert client._client._trust_env is False  # type: ignore[attr-defined]
    assert client._client.follow_redirects is False
    assert client._client.timeout.connect == 5.0
    assert client._client.timeout.read == 10.0
    assert client._event_timeout.read is None
    asyncio.run(client.aclose())


def test_snapshot_rejects_non_contract_json() -> None:
    payload = json.dumps({"schema_version": SCENARIO_RUN_SNAPSHOT_VERSION}).encode()

    async def scenario() -> None:
        async with _client(
            lambda _request: _json_response(_snapshot(), content=payload)
        ) as client:
            with pytest.raises(RemoteProtocolError):
                await client.get_snapshot("investigation-7")

    asyncio.run(scenario())


def test_error_response_itself_must_be_canonical() -> None:
    error = ApiError(
        schema_version=ERROR_VERSION,
        code=ApiErrorCode.INVESTIGATION_NOT_FOUND,
        message="not found",
        details={},
    )

    async def scenario() -> None:
        async with _client(
            lambda _request: _json_response(
                error,
                status_code=404,
                content=b" " + canonical_json_bytes(error),
            )
        ) as client:
            with pytest.raises(RemoteProtocolError):
                await client.get_snapshot("investigation-7")

    asyncio.run(scenario())


def test_decoded_snapshot_round_trips_through_public_contract() -> None:
    snapshot = _snapshot()
    encoded = canonical_json_bytes(snapshot)

    assert decode_contract(encoded, ScenarioRunSnapshot) == snapshot
