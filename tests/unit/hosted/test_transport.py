"""Deterministic checks for bounded hosted service transport."""

from __future__ import annotations

import asyncio
import inspect

import httpx
import pytest

import reconcile.hosted.transport as transport_module
from reconcile.hosted.transport import (
    HostedHttpTransport,
    HostedRequestError,
    HostedTransportError,
)

pytestmark = pytest.mark.unit

DESTINATION = "https://controller.example.test/internal/v1/operation"
AUDIENCE = "https://controller.example.test"


def test_request_mints_fresh_destination_token_and_sets_independent_headers() -> None:
    audiences: list[str] = []
    requests: list[httpx.Request] = []

    def token_supplier(audience: str) -> str:
        audiences.append(audience)
        return f"header.payload.signature{len(audiences)}"

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        return httpx.Response(200, content=b'{"ok":true}')

    async def exercise() -> tuple[bytes, bytes]:
        async with httpx.AsyncClient(
            transport=httpx.MockTransport(handler),
        ) as client:
            transport = HostedHttpTransport(token_supplier, client)
            first = await transport.request(
                "POST",
                DESTINATION,
                audience=AUDIENCE,
                content=b'{"request":1}',
            )
            second = await transport.request(
                "POST",
                DESTINATION,
                audience=AUDIENCE,
                content=b'{"request":2}',
            )
            assert first.status_code == second.status_code == 200
            return first.content, second.content

    assert asyncio.run(exercise()) == (b'{"ok":true}', b'{"ok":true}')
    assert audiences == [AUDIENCE, AUDIENCE]
    assert len(requests) == 2
    for index, request in enumerate(requests, start=1):
        expected = f"Bearer header.payload.signature{index}"
        assert request.headers["Authorization"] == expected
        assert request.headers["X-Serverless-Authorization"] == expected
        assert request.headers["Accept"] == "application/json"
        assert request.headers["Content-Type"] == "application/json"
        assert request.url == httpx.URL(DESTINATION)
    assert requests[0].content == b'{"request":1}'
    assert requests[1].content == b'{"request":2}'


def test_transport_has_no_inbound_header_forwarding_surface() -> None:
    parameters = inspect.signature(HostedHttpTransport.request).parameters

    assert "headers" not in parameters
    assert "authorization" not in parameters
    assert "x_serverless_authorization" not in parameters


def test_async_token_supplier_receives_exact_destination_audience() -> None:
    audiences: list[str] = []

    async def token_supplier(audience: str) -> str:
        audiences.append(audience)
        return "header.payload.signature"

    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, content=b"{}")

    async def exercise():
        async with httpx.AsyncClient(
            transport=httpx.MockTransport(handler),
        ) as client:
            transport = HostedHttpTransport(token_supplier, client)
            return await transport.request("GET", DESTINATION, audience=AUDIENCE)

    response = asyncio.run(exercise())

    assert response.status_code == 200
    assert audiences == [AUDIENCE]


def test_http_failure_is_one_attempt_and_sanitized() -> None:
    attempts = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal attempts
        attempts += 1
        raise httpx.ConnectError("Bearer private.header.signature", request=request)

    async def exercise() -> None:
        async with httpx.AsyncClient(
            transport=httpx.MockTransport(handler),
        ) as client:
            transport = HostedHttpTransport(
                lambda _audience: "header.payload.signature",
                client,
            )
            with pytest.raises(HostedTransportError) as captured:
                await transport.request("GET", DESTINATION, audience=AUDIENCE)
            assert str(captured.value) == "internal service request failed"
            assert captured.value.__cause__ is None
            assert "private" not in repr(captured.value)

    asyncio.run(exercise())
    assert attempts == 1


def test_non_success_response_is_bounded_and_not_retried() -> None:
    attempts = 0

    def handler(_request: httpx.Request) -> httpx.Response:
        nonlocal attempts
        attempts += 1
        return httpx.Response(503, content=b'{"available":false}')

    async def exercise() -> None:
        async with httpx.AsyncClient(
            transport=httpx.MockTransport(handler),
        ) as client:
            transport = HostedHttpTransport(
                lambda _audience: "header.payload.signature",
                client,
            )
            response = await transport.request(
                "GET",
                DESTINATION,
                audience=AUDIENCE,
            )
            assert response.status_code == 503
            assert response.content == b'{"available":false}'

    asyncio.run(exercise())
    assert attempts == 1


@pytest.mark.parametrize(
    ("method", "url", "audience", "content"),
    (
        ("post", DESTINATION, AUDIENCE, b"{}"),
        ("DELETE", DESTINATION, AUDIENCE, b"{}"),
        ("POST", "http://controller.example.test/operation", AUDIENCE, b"{}"),
        ("POST", "https://user@controller.example.test/operation", AUDIENCE, b"{}"),
        ("POST", f"{DESTINATION}?debug=true", AUDIENCE, b"{}"),
        ("POST", DESTINATION, f"{AUDIENCE} audience", b"{}"),
        ("GET", DESTINATION, AUDIENCE, b"{}"),
        ("POST", DESTINATION, AUDIENCE, b"x" * 1_048_577),
    ),
)
def test_request_policy_rejects_invalid_input_before_identity_or_http(
    method: str,
    url: str,
    audience: str,
    content: bytes,
) -> None:
    supplier_calls = 0
    http_calls = 0

    def supplier(_audience: str) -> str:
        nonlocal supplier_calls
        supplier_calls += 1
        return "header.payload.signature"

    def handler(_request: httpx.Request) -> httpx.Response:
        nonlocal http_calls
        http_calls += 1
        return httpx.Response(200, content=b"{}")

    async def exercise() -> None:
        async with httpx.AsyncClient(
            transport=httpx.MockTransport(handler),
        ) as client:
            transport = HostedHttpTransport(supplier, client)
            with pytest.raises(HostedRequestError):
                await transport.request(
                    method,
                    url,
                    audience=audience,
                    content=content,
                )

    asyncio.run(exercise())
    assert supplier_calls == 0
    assert http_calls == 0


@pytest.mark.parametrize(
    "token",
    (
        "",
        "header.payload.",
        "header.payload.sign/ature",
        "header payload.signature",
        "x" * 6_145,
    ),
)
def test_invalid_supplied_token_fails_before_http(token: str) -> None:
    http_calls = 0

    def handler(_request: httpx.Request) -> httpx.Response:
        nonlocal http_calls
        http_calls += 1
        return httpx.Response(200, content=b"{}")

    async def exercise() -> None:
        async with httpx.AsyncClient(
            transport=httpx.MockTransport(handler),
        ) as client:
            transport = HostedHttpTransport(lambda _audience: token, client)
            with pytest.raises(HostedTransportError):
                await transport.request("GET", DESTINATION, audience=AUDIENCE)

    asyncio.run(exercise())
    assert http_calls == 0


def test_token_supplier_failure_is_sanitized() -> None:
    def supplier(_audience: str) -> str:
        raise RuntimeError("metadata-credential-secret")

    transport = HostedHttpTransport(supplier)

    with pytest.raises(HostedTransportError) as captured:
        asyncio.run(transport.request("GET", DESTINATION, audience=AUDIENCE))

    assert str(captured.value) == "internal service request failed"
    assert captured.value.__cause__ is None
    assert "credential" not in repr(captured.value)


def test_total_timeout_includes_destination_token_supply(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(transport_module, "_TOTAL_TIMEOUT_SECONDS", 0.01)

    async def supplier(_audience: str) -> str:
        await asyncio.sleep(60)
        return "header.payload.signature"

    with pytest.raises(HostedTransportError):
        asyncio.run(
            HostedHttpTransport(supplier).request(
                "GET",
                DESTINATION,
                audience=AUDIENCE,
            )
        )


def test_default_token_supplier_bounds_metadata_fetch_without_environment_proxy(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from google.auth.transport.requests import Request
    from google.oauth2 import id_token

    requests: list[tuple[str, float, bool]] = []

    def request_call(
        self: Request,
        url: str,
        _method: str = "GET",
        _body: bytes | None = None,
        _headers: dict[str, str] | None = None,
        timeout: float = 120,
        **_kwargs: object,
    ) -> object:
        requests.append((url, timeout, self.session.trust_env))
        return object()

    def fetch_token(request: object, audience: str) -> str:
        assert audience == AUDIENCE
        assert callable(request)
        request("http://metadata.example.test", timeout=120)
        return "header.payload.signature"

    monkeypatch.setattr(Request, "__call__", request_call)
    monkeypatch.setattr(id_token, "fetch_id_token", fetch_token)

    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, content=b"{}")

    async def exercise() -> None:
        async with httpx.AsyncClient(
            transport=httpx.MockTransport(handler),
        ) as client:
            transport = HostedHttpTransport(http_client=client)
            response = await transport.request(
                "GET",
                DESTINATION,
                audience=AUDIENCE,
            )
            assert response.status_code == 200

    asyncio.run(exercise())
    assert requests == [("http://metadata.example.test", 5.0, False)]


@pytest.mark.parametrize(
    "response",
    (
        httpx.Response(200, content=b"x" * 1_048_577),
        httpx.Response(
            200,
            headers={"Content-Encoding": "gzip"},
            stream=httpx.ByteStream(b"compressed"),
        ),
        httpx.Response(
            200,
            headers={"Content-Length": "2"},
            content=b"one",
        ),
    ),
)
def test_response_bounds_fail_closed(response: httpx.Response) -> None:
    def handler(_request: httpx.Request) -> httpx.Response:
        return response

    async def exercise() -> None:
        async with httpx.AsyncClient(
            transport=httpx.MockTransport(handler),
        ) as client:
            transport = HostedHttpTransport(
                lambda _audience: "header.payload.signature",
                client,
            )
            with pytest.raises(HostedTransportError):
                await transport.request("GET", DESTINATION, audience=AUDIENCE)

    asyncio.run(exercise())
