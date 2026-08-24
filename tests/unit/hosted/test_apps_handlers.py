"""Exact authenticated operation handlers for hosted internal applications."""

from __future__ import annotations

import asyncio
from collections.abc import Collection
from http import HTTPStatus
from typing import Any

import httpx
import pytest
from fastapi.testclient import TestClient

from reconcile.contracts.codec import decode_contract
from reconcile.hosted.apps import (
    InternalOperationConflict,
    InternalOperationDenied,
    create_component_app,
)
from reconcile.hosted.config import Component, HostedConfig
from reconcile.hosted.contracts import (
    INTERNAL_OPERATION_REQUEST_VERSION,
    INTERNAL_OPERATION_RESPONSE_VERSION,
    InternalOperation,
    InternalOperationRequest,
    InternalOperationResponse,
    canonical_internal_json_bytes,
)
from reconcile.hosted.identity import IdentityVerificationError, VerifiedCaller

pytestmark = pytest.mark.unit

_PROJECT = "reconcile-dev-260813-14fa6d"
_CALLER_EMAIL = f"rec-p5-api@{_PROJECT}.iam.gserviceaccount.com"
_CALLER = VerifiedCaller(
    email=_CALLER_EMAIL,
    subject="subject-api",
    issuer="https://accounts.google.com",
    audience=f"https://reconcile.invalid/phase5/{_PROJECT}/target",
    expires_at=2**31,
)
_HEADERS = {
    "Authorization": "Bearer hdr.caller.sig",
    "Content-Type": "application/json",
    "X-Serverless-Authorization": "Bearer e30.e30.",
}


class _Verifier:
    def verify(
        self,
        authorization_header: str | None,
        expected_audience: str,
        allowed_emails: Collection[str],
    ) -> VerifiedCaller:
        if (
            authorization_header != "Bearer hdr.caller.sig"
            or _CALLER_EMAIL not in allowed_emails
        ):
            raise IdentityVerificationError
        return VerifiedCaller(
            email=_CALLER.email,
            subject=_CALLER.subject,
            issuer=_CALLER.issuer,
            audience=expected_audience,
            expires_at=_CALLER.expires_at,
        )


class _CallerSubclass(VerifiedCaller):
    pass


class _InexactVerifier:
    def verify(
        self,
        authorization_header: str | None,
        expected_audience: str,
        allowed_emails: Collection[str],
    ) -> VerifiedCaller:
        return _CallerSubclass(
            email=_CALLER.email,
            subject=_CALLER.subject,
            issuer=_CALLER.issuer,
            audience=expected_audience,
            expires_at=_CALLER.expires_at,
        )


def _config(component: Component) -> HostedConfig:
    return HostedConfig(
        component=component,
        port=8080,
        project_id=_PROJECT,
        auth_audience=f"https://reconcile.invalid/phase5/{_PROJECT}/{component.value}",
        allowed_caller_emails=(_CALLER_EMAIL,),
        source_revision="a" * 40,
        image_digest=f"sha256:{'b' * 64}",
        infra_revision="c" * 64,
        semantic_config_sha256="d" * 64,
        sandbox_read_caller_email=_CALLER_EMAIL,
        sandbox_mutation_caller_email=_CALLER_EMAIL,
    )


def _request(operation: InternalOperation) -> InternalOperationRequest:
    return InternalOperationRequest(
        schema_version=INTERNAL_OPERATION_REQUEST_VERSION,
        request_id=f"request-{operation.value}",
        operation=operation,
        payload={"scope": "bounded-test"},
    )


def _response(
    request: InternalOperationRequest,
    *,
    accepted: bool = True,
    request_id: str | None = None,
    operation: InternalOperation | None = None,
) -> InternalOperationResponse:
    return InternalOperationResponse(
        schema_version=INTERNAL_OPERATION_RESPONSE_VERSION,
        request_id=request_id or request.request_id,
        operation=operation or request.operation,
        accepted=accepted,
        payload={"status": "recorded"},
    )


def _post(
    application: Any,
    path: str,
    operation: InternalOperation,
) -> Any:
    with TestClient(application) as client:
        return client.post(
            path,
            content=canonical_internal_json_bytes(_request(operation)),
            headers=_HEADERS,
        )


@pytest.mark.parametrize(
    ("component", "path", "operation"),
    (
        (
            Component.CONTROLLER,
            "/internal/v1/investigations",
            InternalOperation.INVESTIGATE,
        ),
        (
            Component.CONTROLLER,
            "/internal/v1/recovery-runs",
            InternalOperation.RECOVER,
        ),
        (
            Component.FAULT_PROXY,
            "/internal/v1/faults",
            InternalOperation.EXECUTE_FAULT,
        ),
        (
            Component.FAULT_PROXY,
            "/internal/v1/cleanup",
            InternalOperation.CLEANUP,
        ),
        (
            Component.SANDBOX,
            "/internal/v1/mutations",
            InternalOperation.EXECUTE_FAULT,
        ),
        (
            Component.SANDBOX,
            "/internal/v1/cleanup",
            InternalOperation.CLEANUP,
        ),
    ),
)
def test_each_allowed_handler_receives_exact_caller_and_request(
    component: Component,
    path: str,
    operation: InternalOperation,
) -> None:
    calls: list[tuple[VerifiedCaller, InternalOperationRequest]] = []

    async def handler(
        caller: VerifiedCaller,
        internal: InternalOperationRequest,
    ) -> InternalOperationResponse:
        calls.append((caller, internal))
        return _response(internal)

    configured = {operation: handler}
    application = create_component_app(
        _config(component),
        verifier=_Verifier(),
        internal_operation_handlers=configured,
    )
    configured.clear()

    response = _post(application, path, operation)

    expected_request = _request(operation)
    expected_response = _response(expected_request)
    assert response.status_code == HTTPStatus.OK
    assert response.content == canonical_internal_json_bytes(expected_response)
    assert response.headers["cache-control"] == "no-store"
    assert calls == [
        (
            VerifiedCaller(
                email=_CALLER.email,
                subject=_CALLER.subject,
                issuer=_CALLER.issuer,
                audience=_config(component).auth_audience,
                expires_at=_CALLER.expires_at,
            ),
            expected_request,
        )
    ]


@pytest.mark.parametrize(
    ("component", "path", "operation"),
    (
        (
            Component.CONTROLLER,
            "/internal/v1/investigations",
            InternalOperation.INVESTIGATE,
        ),
        (
            Component.CONTROLLER,
            "/internal/v1/recovery-runs",
            InternalOperation.RECOVER,
        ),
        (
            Component.FAULT_PROXY,
            "/internal/v1/faults",
            InternalOperation.EXECUTE_FAULT,
        ),
        (
            Component.FAULT_PROXY,
            "/internal/v1/cleanup",
            InternalOperation.CLEANUP,
        ),
        (
            Component.SANDBOX,
            "/internal/v1/mutations",
            InternalOperation.EXECUTE_FAULT,
        ),
        (
            Component.SANDBOX,
            "/internal/v1/cleanup",
            InternalOperation.CLEANUP,
        ),
    ),
)
def test_every_missing_allowed_handler_retains_the_exact_placeholder(
    component: Component,
    path: str,
    operation: InternalOperation,
) -> None:
    response = _post(
        create_component_app(_config(component), verifier=_Verifier()),
        path,
        operation,
    )

    decoded = decode_contract(response.content, InternalOperationResponse)
    assert response.status_code == HTTPStatus.NOT_IMPLEMENTED
    assert decoded == InternalOperationResponse(
        schema_version=INTERNAL_OPERATION_RESPONSE_VERSION,
        request_id=_request(operation).request_id,
        operation=operation,
        accepted=False,
        payload={"status": "not-implemented"},
    )


@pytest.mark.parametrize(
    ("component", "operation"),
    (
        (Component.API, InternalOperation.INVESTIGATE),
        (Component.CONTROLLER, InternalOperation.CLEANUP),
        (Component.FAULT_PROXY, InternalOperation.RECOVER),
        (Component.FAULT_PROXY, InternalOperation.INVESTIGATE),
        (Component.SANDBOX, InternalOperation.INVESTIGATE),
        (Component.SANDBOX, InternalOperation.READ_EVIDENCE),
    ),
)
def test_wrong_component_handler_injection_is_rejected(
    component: Component,
    operation: InternalOperation,
) -> None:
    async def handler(
        caller: VerifiedCaller,
        internal: InternalOperationRequest,
    ) -> InternalOperationResponse:
        return _response(internal)

    with pytest.raises(ValueError, match="unsupported operation handler"):
        create_component_app(
            _config(component),
            verifier=_Verifier(),
            internal_operation_handlers={operation: handler},
        )


def test_handler_mapping_and_entries_are_strict() -> None:
    with pytest.raises(TypeError, match="must be a mapping"):
        create_component_app(
            _config(Component.CONTROLLER),
            verifier=_Verifier(),
            internal_operation_handlers=[],  # type: ignore[arg-type]
        )
    with pytest.raises(TypeError, match="entries must be exact"):
        create_component_app(
            _config(Component.CONTROLLER),
            verifier=_Verifier(),
            internal_operation_handlers={"investigate": object()},  # type: ignore[dict-item]
        )
    with pytest.raises(TypeError, match="entries must be exact"):
        create_component_app(
            _config(Component.CONTROLLER),
            verifier=_Verifier(),
            internal_operation_handlers={InternalOperation.INVESTIGATE: object()},  # type: ignore[dict-item]
        )


@pytest.mark.parametrize(
    ("failure", "expected_status", "expected_content"),
    (
        (
            "returned-denial",
            HTTPStatus.FORBIDDEN,
            b'{"code":"operation-denied"}',
        ),
        (
            "raised-denial",
            HTTPStatus.FORBIDDEN,
            b'{"code":"operation-denied"}',
        ),
        (
            "dependency-failure",
            HTTPStatus.SERVICE_UNAVAILABLE,
            b'{"code":"operation-unavailable"}',
        ),
        (
            "raised-conflict",
            HTTPStatus.CONFLICT,
            b'{"code":"operation-conflict"}',
        ),
    ),
)
def test_handler_denial_and_failure_are_sanitized_and_not_cached(
    failure: str,
    expected_status: HTTPStatus,
    expected_content: bytes,
) -> None:
    async def handler(
        caller: VerifiedCaller,
        internal: InternalOperationRequest,
    ) -> InternalOperationResponse:
        if failure == "returned-denial":
            denied = _response(internal, accepted=False)
            denied.payload["private-detail"] = "must-not-cross-boundary"
            return denied
        if failure == "raised-denial":
            raise InternalOperationDenied
        if failure == "raised-conflict":
            raise InternalOperationConflict
        raise RuntimeError("private dependency failure")

    application = create_component_app(
        _config(Component.CONTROLLER),
        verifier=_Verifier(),
        internal_operation_handlers={InternalOperation.INVESTIGATE: handler},
    )

    response = _post(
        application,
        "/internal/v1/investigations",
        InternalOperation.INVESTIGATE,
    )

    assert response.status_code == expected_status
    assert response.content == expected_content
    assert response.headers["cache-control"] == "no-store"
    assert b"private" not in response.content


@pytest.mark.parametrize(
    "failure",
    ("wrong-type", "wrong-request", "wrong-operation", "mutated-payload"),
)
def test_invalid_handler_responses_fail_closed(failure: str) -> None:
    async def handler(
        caller: VerifiedCaller,
        internal: InternalOperationRequest,
    ) -> InternalOperationResponse:
        if failure == "wrong-type":
            return object()  # type: ignore[return-value]
        if failure == "wrong-request":
            return _response(internal, request_id="another-request")
        if failure == "wrong-operation":
            return _response(internal, operation=InternalOperation.CLEANUP)
        response = _response(internal)
        response.payload["authorization"] = "Bearer hdr.private.sig"
        return response

    application = create_component_app(
        _config(Component.CONTROLLER),
        verifier=_Verifier(),
        internal_operation_handlers={InternalOperation.INVESTIGATE: handler},
    )

    response = _post(
        application,
        "/internal/v1/investigations",
        InternalOperation.INVESTIGATE,
    )

    assert response.status_code == HTTPStatus.SERVICE_UNAVAILABLE
    assert response.content == b'{"code":"operation-unavailable"}'
    assert response.headers["cache-control"] == "no-store"
    assert b"private" not in response.content


def test_invalid_wire_operation_never_reaches_injected_handler() -> None:
    calls = 0

    async def handler(
        caller: VerifiedCaller,
        internal: InternalOperationRequest,
    ) -> InternalOperationResponse:
        nonlocal calls
        calls += 1
        return _response(internal)

    application = create_component_app(
        _config(Component.CONTROLLER),
        verifier=_Verifier(),
        internal_operation_handlers={InternalOperation.INVESTIGATE: handler},
    )

    response = _post(
        application,
        "/internal/v1/investigations",
        InternalOperation.CLEANUP,
    )

    assert response.status_code == HTTPStatus.UNPROCESSABLE_ENTITY
    assert response.content == b'{"code":"invalid-operation"}'
    assert response.headers["cache-control"] == "no-store"
    assert calls == 0


def test_handler_requires_an_exact_verified_caller() -> None:
    calls = 0

    async def handler(
        caller: VerifiedCaller,
        internal: InternalOperationRequest,
    ) -> InternalOperationResponse:
        nonlocal calls
        calls += 1
        return _response(internal)

    application = create_component_app(
        _config(Component.CONTROLLER),
        verifier=_InexactVerifier(),
        internal_operation_handlers={InternalOperation.INVESTIGATE: handler},
    )

    response = _post(
        application,
        "/internal/v1/investigations",
        InternalOperation.INVESTIGATE,
    )

    assert response.status_code == HTTPStatus.SERVICE_UNAVAILABLE
    assert response.content == b'{"code":"operation-unavailable"}'
    assert response.headers["cache-control"] == "no-store"
    assert calls == 0


def test_handler_cancellation_propagates() -> None:
    async def handler(
        caller: VerifiedCaller,
        internal: InternalOperationRequest,
    ) -> InternalOperationResponse:
        raise asyncio.CancelledError

    application = create_component_app(
        _config(Component.CONTROLLER),
        verifier=_Verifier(),
        internal_operation_handlers={InternalOperation.INVESTIGATE: handler},
    )

    async def send() -> None:
        transport = httpx.ASGITransport(app=application)
        async with httpx.AsyncClient(
            transport=transport,
            base_url="https://controller.example.test",
        ) as client:
            await client.post(
                "/internal/v1/investigations",
                content=canonical_internal_json_bytes(
                    _request(InternalOperation.INVESTIGATE)
                ),
                headers=_HEADERS,
            )

    with pytest.raises(asyncio.CancelledError):
        asyncio.run(send())
