"""Authenticated FastAPI boundaries for the four hosted components."""

from __future__ import annotations

import asyncio
import re
from collections.abc import Collection
from http import HTTPStatus
from typing import Protocol

from fastapi import FastAPI, Request
from fastapi.responses import Response
from starlette.types import ASGIApp, Receive, Scope, Send

from reconcile.contracts.codec import decode_contract
from reconcile.hosted.config import Component, HostedConfig
from reconcile.hosted.contracts import (
    INTERNAL_OPERATION_RESPONSE_VERSION,
    MAX_INTERNAL_PAYLOAD_BYTES,
    InternalOperation,
    InternalOperationRequest,
    InternalOperationResponse,
    canonical_internal_json_bytes,
)
from reconcile.hosted.identity import (
    GoogleIdentityVerifier,
    IdentityVerificationError,
    VerifiedCaller,
    validate_platform_authorization,
)
from reconcile.hosted.sandbox import (
    SandboxEvidenceReader,
    SandboxEvidenceRequest,
    sandbox_evidence_payload,
)
from reconcile.hosted.transport import HostedHttpTransport
from reconcile.interfaces.api import create_app

_MAX_INTERNAL_REQUEST_BYTES = MAX_INTERNAL_PAYLOAD_BYTES + 4_096

_CONTROLLER_PATH = "/internal/v1/investigations"
_FAULT_PATH = "/internal/v1/faults"
_EVIDENCE_PATH = "/internal/v1/evidence"
_MUTATION_PATH = "/internal/v1/mutations"
_CLEANUP_PATH = "/internal/v1/cleanup"

_IDENTIFIER_PATH = rb"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}"
_API_PATHS = (
    ("POST", re.compile(rb"/api/v1/scenario-runs")),
    ("GET", re.compile(rb"/api/v1/scenario-runs/" + _IDENTIFIER_PATH)),
    (
        "GET",
        re.compile(
            rb"/api/v2/scenario-runs/" + _IDENTIFIER_PATH + rb"/operational-status"
        ),
    ),
    (
        "GET",
        re.compile(rb"/api/v1/scenario-runs/" + _IDENTIFIER_PATH + rb"/events"),
    ),
    (
        "GET",
        re.compile(
            rb"/api/v1/investigations/" + _IDENTIFIER_PATH + rb"/envelope-summary"
        ),
    ),
    ("POST", re.compile(rb"/api/v1/investigations")),
    ("GET", re.compile(rb"/api/v1/investigations/" + _IDENTIFIER_PATH)),
    (
        "GET",
        re.compile(rb"/api/v1/investigations/" + _IDENTIFIER_PATH + rb"/events"),
    ),
)
_INTERNAL_PATHS = {
    Component.CONTROLLER: frozenset({("POST", _CONTROLLER_PATH.encode("ascii"))}),
    Component.FAULT_PROXY: frozenset(
        {
            ("POST", _FAULT_PATH.encode("ascii")),
            ("POST", _CLEANUP_PATH.encode("ascii")),
        }
    ),
}


class _Verifier(Protocol):
    def verify(
        self,
        authorization_header: str | None,
        expected_audience: str,
        allowed_emails: Collection[str],
    ) -> VerifiedCaller: ...


def _single_header(scope: Scope, name: bytes) -> str | None:
    values = [value for key, value in scope.get("headers", ()) if key.lower() == name]
    if not values:
        return None
    if len(values) != 1:
        raise IdentityVerificationError
    try:
        return values[0].decode("ascii")
    except UnicodeDecodeError:
        raise IdentityVerificationError from None


def _allowed_callers(
    config: HostedConfig,
    method: str,
    raw_path: bytes,
) -> tuple[str, ...]:
    if config.component is Component.API:
        if any(
            method == allowed_method and pattern.fullmatch(raw_path) is not None
            for allowed_method, pattern in _API_PATHS
        ):
            return config.allowed_caller_emails
        return ()
    if config.component in _INTERNAL_PATHS:
        if (method, raw_path) in _INTERNAL_PATHS[config.component]:
            return config.allowed_caller_emails
        return ()
    if config.component is not Component.SANDBOX:
        return ()
    try:
        path = raw_path.decode("ascii")
    except UnicodeDecodeError:
        return ()
    if method != "POST":
        return ()
    if path == _EVIDENCE_PATH and config.sandbox_read_caller_email is not None:
        return (config.sandbox_read_caller_email,)
    if path in {_MUTATION_PATH, _CLEANUP_PATH} and (
        config.sandbox_mutation_caller_email is not None
    ):
        return (config.sandbox_mutation_caller_email,)
    return ()


def _validated_scope(scope: Scope) -> tuple[str, str, bytes, bytes]:
    method = scope.get("method")
    path = scope.get("path")
    raw_path = scope.get("raw_path")
    query = scope.get("query_string", b"")
    headers = scope.get("headers")
    if (
        type(method) is not str
        or type(path) is not str
        or type(raw_path) is not bytes
        or type(query) is not bytes
        or not method.isascii()
        or len(method) > 16
        or len(path) > 512
        or not 1 <= len(raw_path) <= 512
        or len(query) > 1_024
        or not isinstance(headers, (list, tuple))
        or len(headers) > 64
    ):
        raise IdentityVerificationError
    aggregate = 0
    for item in headers:
        if (
            not isinstance(item, (list, tuple))
            or len(item) != 2
            or type(item[0]) is not bytes
            or type(item[1]) is not bytes
            or not 1 <= len(item[0]) <= 256
            or len(item[1]) > 8_192
        ):
            raise IdentityVerificationError
        aggregate += len(item[0]) + len(item[1])
    if aggregate > 32_768:
        raise IdentityVerificationError
    return method, path, raw_path, query


def _unauthorized() -> Response:
    return Response(
        content=b'{"code":"unauthorized"}',
        status_code=HTTPStatus.UNAUTHORIZED,
        media_type="application/json",
        headers={"Cache-Control": "no-store"},
    )


class ApplicationIdentityMiddleware:
    """Require independent platform and application identity on every route."""

    def __init__(
        self,
        app: ASGIApp,
        *,
        config: HostedConfig,
        verifier: _Verifier,
    ) -> None:
        self._app = app
        self._config = config
        self._verifier = verifier

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self._app(scope, receive, send)
            return
        try:
            method, path, raw_path, query = _validated_scope(scope)
            if (
                method == "GET"
                and path == "/health"
                and raw_path == b"/health"
                and not query
            ):
                await self._app(scope, receive, send)
                return
            platform_header = _single_header(
                scope,
                b"x-serverless-authorization",
            )
            application_header = _single_header(scope, b"authorization")
            validate_platform_authorization(platform_header)
            async with asyncio.timeout(6.0):
                caller = await asyncio.to_thread(
                    self._verifier.verify,
                    application_header,
                    self._config.auth_audience,
                    _allowed_callers(self._config, method, raw_path),
                )
            state = scope.setdefault("state", {})
            if type(state) is not dict:
                raise IdentityVerificationError
            state["verified_caller"] = caller
        except Exception:
            await _unauthorized()(scope, receive, send)
            return
        await self._app(scope, receive, send)


async def _read_internal_request(request: Request) -> InternalOperationRequest:
    if request.url.query:
        raise ValueError("internal request query is not allowed")
    content_type = request.headers.get("content-type", "").split(";", 1)[0]
    if content_type.strip().lower() != "application/json":
        raise ValueError("internal request is not canonical JSON")
    content_length = request.headers.get("content-length")
    if content_length is not None:
        try:
            declared = int(content_length)
        except ValueError as error:
            raise ValueError("internal request length is invalid") from error
        if declared < 1 or declared > _MAX_INTERNAL_REQUEST_BYTES:
            raise ValueError("internal request length is invalid")
    body = bytearray()
    async for chunk in request.stream():
        body.extend(chunk)
        if len(body) > _MAX_INTERNAL_REQUEST_BYTES:
            raise ValueError("internal request is too large")
    if not body:
        raise ValueError("internal request is empty")
    decoded = decode_contract(bytes(body), InternalOperationRequest)
    if bytes(body) != canonical_internal_json_bytes(decoded):
        raise ValueError("internal request is not canonical JSON")
    return decoded


def _install_placeholder(
    application: FastAPI,
    path: str,
    operation: InternalOperation,
) -> None:
    async def placeholder(request: Request) -> Response:
        try:
            internal = await _read_internal_request(request)
        except (TypeError, ValueError):
            return Response(
                content=b'{"code":"invalid-contract"}',
                status_code=HTTPStatus.BAD_REQUEST,
                media_type="application/json",
            )
        if internal.operation is not operation:
            return Response(
                content=b'{"code":"invalid-operation"}',
                status_code=HTTPStatus.UNPROCESSABLE_ENTITY,
                media_type="application/json",
            )
        response = InternalOperationResponse(
            schema_version=INTERNAL_OPERATION_RESPONSE_VERSION,
            request_id=internal.request_id,
            operation=internal.operation,
            accepted=False,
            payload={"status": "not-implemented"},
        )
        return Response(
            content=canonical_internal_json_bytes(response),
            status_code=HTTPStatus.NOT_IMPLEMENTED,
            media_type="application/json",
        )

    application.add_api_route(
        path,
        placeholder,
        methods=["POST"],
        response_model=None,
    )


def _install_sandbox_evidence(
    application: FastAPI,
    reader: SandboxEvidenceReader,
) -> None:
    async def read_evidence(request: Request) -> Response:
        try:
            internal = await _read_internal_request(request)
        except (TypeError, ValueError):
            return Response(
                content=b'{"code":"invalid-contract"}',
                status_code=HTTPStatus.BAD_REQUEST,
                media_type="application/json",
            )
        if internal.operation is not InternalOperation.READ_EVIDENCE:
            return Response(
                content=b'{"code":"invalid-operation"}',
                status_code=HTTPStatus.UNPROCESSABLE_ENTITY,
                media_type="application/json",
            )
        try:
            selection = SandboxEvidenceRequest.model_validate(internal.payload)
        except (TypeError, ValueError):
            return Response(
                content=b'{"code":"invalid-contract"}',
                status_code=HTTPStatus.BAD_REQUEST,
                media_type="application/json",
            )
        try:
            evidence = await reader.read_evidence(selection)
            payload = sandbox_evidence_payload(selection, evidence)
            response = InternalOperationResponse(
                schema_version=INTERNAL_OPERATION_RESPONSE_VERSION,
                request_id=internal.request_id,
                operation=internal.operation,
                accepted=True,
                payload=payload,  # type: ignore[arg-type]
            )
        except Exception:
            return Response(
                content=b'{"code":"evidence-unavailable"}',
                status_code=HTTPStatus.SERVICE_UNAVAILABLE,
                media_type="application/json",
                headers={"Cache-Control": "no-store"},
            )
        return Response(
            content=canonical_internal_json_bytes(response),
            status_code=HTTPStatus.OK,
            media_type="application/json",
            headers={"Cache-Control": "no-store"},
        )

    application.add_api_route(
        _EVIDENCE_PATH,
        read_evidence,
        methods=["POST"],
        response_model=None,
    )


def _internal_app(
    config: HostedConfig,
    *,
    sandbox_evidence_reader: SandboxEvidenceReader | None,
) -> FastAPI:
    application = FastAPI(
        title=f"RECONCILE {config.component.value}",
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
        redirect_slashes=False,
    )

    @application.get("/health", response_model=None)
    async def health() -> Response:
        return Response(content=b'{"status":"ok"}', media_type="application/json")

    if config.component is Component.CONTROLLER:
        _install_placeholder(
            application,
            _CONTROLLER_PATH,
            InternalOperation.INVESTIGATE,
        )
    elif config.component is Component.FAULT_PROXY:
        _install_placeholder(application, _FAULT_PATH, InternalOperation.EXECUTE_FAULT)
        _install_placeholder(application, _CLEANUP_PATH, InternalOperation.CLEANUP)
    elif config.component is Component.SANDBOX:
        if sandbox_evidence_reader is None:
            _install_placeholder(
                application,
                _EVIDENCE_PATH,
                InternalOperation.READ_EVIDENCE,
            )
        else:
            _install_sandbox_evidence(application, sandbox_evidence_reader)
        _install_placeholder(
            application,
            _MUTATION_PATH,
            InternalOperation.EXECUTE_FAULT,
        )
        _install_placeholder(application, _CLEANUP_PATH, InternalOperation.CLEANUP)
    else:  # pragma: no cover - caller dispatches API separately.
        raise TypeError("internal app requires an internal component")
    return application


def create_component_app(
    config: HostedConfig,
    *,
    verifier: _Verifier | None = None,
    transport: HostedHttpTransport | None = None,
    investigation_service: object | None = None,
    operator_service: object | None = None,
    sandbox_evidence_reader: SandboxEvidenceReader | None = None,
) -> FastAPI:
    """Build one exact component boundary without resolving credentials eagerly."""

    if type(config) is not HostedConfig:
        raise TypeError("hosted app requires exact configuration")
    if (
        sandbox_evidence_reader is not None
        and config.component is not Component.SANDBOX
    ):
        raise ValueError("only the sandbox component accepts an evidence reader")
    if config.component is Component.API:
        application = create_app(
            investigation_service,  # type: ignore[arg-type]
            operator_service=operator_service,  # type: ignore[arg-type]
            hosted=True,
        )
    else:
        if investigation_service is not None or operator_service is not None:
            raise ValueError("internal components cannot receive API services")
        application = _internal_app(
            config,
            sandbox_evidence_reader=sandbox_evidence_reader,
        )
    application.state.hosted_config = config
    application.state.hosted_transport = transport or HostedHttpTransport()
    application.add_middleware(
        ApplicationIdentityMiddleware,
        config=config,
        verifier=verifier or GoogleIdentityVerifier(),
    )
    return application


__all__ = ["ApplicationIdentityMiddleware", "create_component_app"]
