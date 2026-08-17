"""Bounded authenticated transport for hosted internal service calls."""

from __future__ import annotations

import asyncio
import inspect
import re
from collections.abc import Awaitable
from dataclasses import dataclass
from typing import Any, Protocol
from urllib.parse import urlsplit

_MAX_URL_BYTES = 2_048
_MAX_AUDIENCE_BYTES = 2_048
_MAX_TOKEN_BYTES = 6_144
_MAX_BODY_BYTES = 1_048_576
_REQUEST_TIMEOUT_SECONDS = 10.0
_TOTAL_TIMEOUT_SECONDS = 15.0
_GOOGLE_REQUEST_TIMEOUT_SECONDS = 5.0
_ALLOWED_METHODS = frozenset({"GET", "POST"})
_JWT_SEGMENT = re.compile(r"^[A-Za-z0-9_-]+$")


class DestinationTokenSupplier(Protocol):
    def __call__(self, audience: str) -> str | Awaitable[str]: ...


class AsyncHttpClient(Protocol):
    def stream(self, method: str, url: str, **kwargs: Any) -> Any: ...


class HostedRequestError(Exception):
    """A destination or bounded request does not satisfy the transport policy."""

    def __init__(self) -> None:
        super().__init__("internal service request is invalid")


class HostedTransportError(Exception):
    """A destination token or one no-retry HTTP attempt failed."""

    def __init__(self) -> None:
        super().__init__("internal service request failed")


@dataclass(frozen=True, slots=True)
class HostedHttpResponse:
    """Bounded response material retained from one internal request."""

    status_code: int
    content: bytes


def _request_error() -> HostedRequestError:
    return HostedRequestError()


def _transport_error() -> HostedTransportError:
    return HostedTransportError()


def _bounded_ascii(value: object, *, maximum: int) -> str:
    if type(value) is not str or not value:
        raise _request_error() from None
    try:
        encoded = value.encode("ascii")
    except UnicodeEncodeError:
        raise _request_error() from None
    if (
        len(encoded) > maximum
        or any(character.isspace() for character in value)
        or any(ord(character) < 33 or ord(character) == 127 for character in value)
    ):
        raise _request_error() from None
    return value


def _validated_method(value: object) -> str:
    if type(value) is not str or value not in _ALLOWED_METHODS:
        raise _request_error() from None
    return value


def _validated_url(value: object) -> str:
    url = _bounded_ascii(value, maximum=_MAX_URL_BYTES)
    if any(character in url for character in ("\\", "@", "?", "#", "%")):
        raise _request_error() from None
    try:
        parsed = urlsplit(url)
        port = parsed.port
    except Exception:
        raise _request_error() from None
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
        or (port is not None and not 1 <= port <= 65_535)
        or not parsed.path.startswith("/")
        or "//" in parsed.path
    ):
        raise _request_error() from None
    return url


def _validated_audience(value: object) -> str:
    return _bounded_ascii(value, maximum=_MAX_AUDIENCE_BYTES)


def _validated_body(value: object, *, method: str) -> bytes:
    if type(value) is not bytes or len(value) > _MAX_BODY_BYTES:
        raise _request_error() from None
    if method == "GET" and value:
        raise _request_error() from None
    return value


def _authorization_header(token: object) -> str:
    if type(token) is not str or not token:
        raise _transport_error() from None
    try:
        encoded = token.encode("ascii")
    except UnicodeEncodeError:
        raise _transport_error() from None
    segments = token.split(".")
    if (
        len(encoded) > _MAX_TOKEN_BYTES
        or len(segments) != 3
        or any(_JWT_SEGMENT.fullmatch(segment) is None for segment in segments)
    ):
        raise _transport_error() from None
    return f"Bearer {token}"


async def _supply_token(
    supplier: DestinationTokenSupplier,
    audience: str,
) -> str:
    if inspect.iscoroutinefunction(supplier):
        supplied = supplier(audience)
    else:
        supplied = await asyncio.to_thread(supplier, audience)
    return await supplied if inspect.isawaitable(supplied) else supplied


async def _default_token_supplier(audience: str) -> str:
    def fetch() -> str:
        try:
            from google.auth.transport.requests import Request
            from google.oauth2 import id_token

            request = Request()
            request.session.trust_env = False

            def bounded_request(
                url: str,
                method: str = "GET",
                body: bytes | None = None,
                headers: dict[str, str] | None = None,
                **kwargs: Any,
            ) -> Any:
                kwargs.pop("timeout", None)
                return request(
                    url,
                    method=method,
                    body=body,
                    headers=headers,
                    timeout=_GOOGLE_REQUEST_TIMEOUT_SECONDS,
                    **kwargs,
                )

            return id_token.fetch_id_token(bounded_request, audience)
        except Exception:
            raise _transport_error() from None

    return await asyncio.to_thread(fetch)


def _header_values(response: Any, name: str) -> list[str]:
    try:
        values = response.headers.get_list(name)
    except Exception:
        raise _transport_error() from None
    if not isinstance(values, list) or any(type(value) is not str for value in values):
        raise _transport_error() from None
    return values


def _declared_response_length(response: Any) -> int | None:
    values = _header_values(response, "content-length")
    if not values:
        return None
    if len(values) != 1 or re.fullmatch(r"0|[1-9][0-9]*", values[0]) is None:
        raise _transport_error() from None
    length = int(values[0])
    if length > _MAX_BODY_BYTES:
        raise _transport_error() from None
    return length


async def _bounded_response(response: Any) -> HostedHttpResponse:
    if type(response.status_code) is not int or not 100 <= response.status_code <= 599:
        raise _transport_error() from None

    encodings = _header_values(response, "content-encoding")
    if encodings and (len(encodings) != 1 or encodings[0].lower() != "identity"):
        raise _transport_error() from None
    declared_length = _declared_response_length(response)

    content = bytearray()
    try:
        async for chunk in response.aiter_bytes():
            if type(chunk) is not bytes or len(content) + len(chunk) > _MAX_BODY_BYTES:
                raise _transport_error()
            content.extend(chunk)
    except HostedTransportError:
        raise
    except Exception:
        raise _transport_error() from None
    if declared_length is not None and len(content) != declared_length:
        raise _transport_error() from None
    return HostedHttpResponse(
        status_code=response.status_code,
        content=bytes(content),
    )


class HostedHttpTransport:
    """Make one authenticated request without redirects, retries, or header forwarding."""

    def __init__(
        self,
        token_supplier: DestinationTokenSupplier | None = None,
        http_client: AsyncHttpClient | None = None,
    ) -> None:
        self._token_supplier = token_supplier or _default_token_supplier
        self._http_client = http_client

    async def request(
        self,
        method: str,
        url: str,
        *,
        audience: str,
        content: bytes = b"",
    ) -> HostedHttpResponse:
        """Send one bounded JSON request with fresh destination-bound identity."""

        validated_method = _validated_method(method)
        validated_url = _validated_url(url)
        validated_audience = _validated_audience(audience)
        validated_content = _validated_body(content, method=validated_method)

        try:
            async with asyncio.timeout(_TOTAL_TIMEOUT_SECONDS):
                token = await _supply_token(self._token_supplier, validated_audience)
                authorization = _authorization_header(token)
                headers = {
                    "Accept": "application/json",
                    "Authorization": authorization,
                    "Content-Type": "application/json",
                    "X-Serverless-Authorization": authorization,
                }
                if self._http_client is None:
                    return await self._request_with_default_client(
                        validated_method,
                        validated_url,
                        headers=headers,
                        content=validated_content,
                    )
                return await self._request_with_client(
                    self._http_client,
                    validated_method,
                    validated_url,
                    headers=headers,
                    content=validated_content,
                )
        except HostedRequestError:
            raise
        except HostedTransportError:
            raise
        except Exception:
            raise _transport_error() from None

    async def _request_with_default_client(
        self,
        method: str,
        url: str,
        *,
        headers: dict[str, str],
        content: bytes,
    ) -> HostedHttpResponse:
        try:
            import httpx

            async with httpx.AsyncClient(
                follow_redirects=False,
                timeout=_REQUEST_TIMEOUT_SECONDS,
                trust_env=False,
            ) as client:
                return await self._request_with_client(
                    client,
                    method,
                    url,
                    headers=headers,
                    content=content,
                )
        except HostedTransportError:
            raise
        except Exception:
            raise _transport_error() from None

    async def _request_with_client(
        self,
        client: AsyncHttpClient,
        method: str,
        url: str,
        *,
        headers: dict[str, str],
        content: bytes,
    ) -> HostedHttpResponse:
        try:
            async with client.stream(
                method,
                url,
                headers=headers,
                content=content,
                follow_redirects=False,
                timeout=_REQUEST_TIMEOUT_SECONDS,
            ) as response:
                return await _bounded_response(response)
        except HostedTransportError:
            raise
        except Exception:
            raise _transport_error() from None


__all__ = [
    "AsyncHttpClient",
    "DestinationTokenSupplier",
    "HostedHttpResponse",
    "HostedHttpTransport",
    "HostedRequestError",
    "HostedTransportError",
]
