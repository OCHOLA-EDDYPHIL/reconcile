from __future__ import annotations

from collections.abc import Collection
from http import HTTPStatus

import pytest
from fastapi.testclient import TestClient

from reconcile.contracts.codec import decode_contract
from reconcile.hosted.apps import create_component_app
from reconcile.hosted.config import Component, HostedConfig
from reconcile.hosted.contracts import (
    INTERNAL_OPERATION_REQUEST_VERSION,
    InternalOperation,
    InternalOperationRequest,
    InternalOperationResponse,
    canonical_internal_json_bytes,
)
from reconcile.hosted.identity import IdentityVerificationError, VerifiedCaller

pytestmark = pytest.mark.integration

_PROJECT = "reconcile-dev-260813-14fa6d"
_OWNER = "eddyphilochola13@gmail.com"
_API = f"rec-p5-api@{_PROJECT}.iam.gserviceaccount.com"
_CONTROLLER = f"rec-p5-controller@{_PROJECT}.iam.gserviceaccount.com"
_FAULT = f"rec-p5-fault@{_PROJECT}.iam.gserviceaccount.com"
_PLATFORM_HEADER = "Bearer e30.e30."


class _Verifier:
    def __init__(self) -> None:
        self.calls: list[tuple[str | None, str, tuple[str, ...]]] = []

    def verify(
        self,
        authorization_header: str | None,
        expected_audience: str,
        allowed_emails: Collection[str],
    ) -> VerifiedCaller:
        allowed = tuple(allowed_emails)
        self.calls.append((authorization_header, expected_audience, allowed))
        identities = {
            "Bearer hdr.owner.sig": _OWNER,
            "Bearer hdr.api.sig": _API,
            "Bearer hdr.controller.sig": _CONTROLLER,
            "Bearer hdr.fault.sig": _FAULT,
        }
        email = identities.get(authorization_header)
        if email is None or email not in allowed:
            raise IdentityVerificationError
        return VerifiedCaller(
            email=email,
            subject=f"subject-{email.split('@', 1)[0]}",
            issuer="https://accounts.google.com",
            audience=expected_audience,
            expires_at=2**31,
        )


def _config(component: Component) -> HostedConfig:
    common: dict[str, object] = {
        "component": component,
        "port": 8080,
        "project_id": _PROJECT,
        "auth_audience": (
            f"https://reconcile.invalid/phase5/{_PROJECT}/{component.value}"
        ),
        "source_revision": "a" * 40,
        "image_digest": f"sha256:{'b' * 64}",
        "infra_revision": "c" * 64,
        "semantic_config_sha256": "d" * 64,
    }
    if component is Component.API:
        specific = {
            "allowed_caller_emails": (_OWNER,),
            "runtime_database": "reconcile-p5-runtime",
            "controller_url": "https://controller.example.com",
            "controller_audience": (
                f"https://reconcile.invalid/phase5/{_PROJECT}/controller"
            ),
            "fault_proxy_url": "https://fault.example.com",
            "fault_proxy_audience": (
                f"https://reconcile.invalid/phase5/{_PROJECT}/fault-proxy"
            ),
        }
    elif component is Component.CONTROLLER:
        specific = {
            "allowed_caller_emails": (_API,),
            "runtime_database": "reconcile-p5-runtime",
            "target_database": "reconcile-p5-target",
            "target_bucket": f"{_PROJECT}-p5-target",
            "sandbox_url": "https://sandbox.example.com",
            "sandbox_audience": (
                f"https://reconcile.invalid/phase5/{_PROJECT}/sandbox"
            ),
            "vertex_location": "us",
            "vertex_model": "gemini-3.5-flash",
            "vertex_max_calls": 1,
            "vertex_max_input_tokens": 12_000,
            "vertex_max_output_tokens": 1_024,
            "vertex_thinking_level": "MINIMAL",
        }
    elif component is Component.FAULT_PROXY:
        specific = {
            "allowed_caller_emails": (_API,),
            "target_database": "reconcile-p5-target",
            "target_bucket": f"{_PROJECT}-p5-target",
            "sandbox_url": "https://sandbox.example.com",
            "sandbox_audience": (
                f"https://reconcile.invalid/phase5/{_PROJECT}/sandbox"
            ),
        }
    else:
        specific = {
            "allowed_caller_emails": (_CONTROLLER, _FAULT),
            "target_database": "reconcile-p5-target",
            "sandbox_read_caller_email": _CONTROLLER,
            "sandbox_mutation_caller_email": _FAULT,
        }
    return HostedConfig(**common, **specific)  # type: ignore[arg-type]


def _headers(identity: str) -> dict[str, str]:
    return {
        "Authorization": f"Bearer hdr.{identity}.sig",
        "Content-Type": "application/json",
        "X-Serverless-Authorization": f"Bearer hdr.{identity}.",
    }


def _request(operation: InternalOperation) -> bytes:
    return canonical_internal_json_bytes(
        InternalOperationRequest(
            schema_version=INTERNAL_OPERATION_REQUEST_VERSION,
            request_id="hosted-auth-test",
            operation=operation,
            payload={},
        )
    )


def test_health_is_the_only_unauthenticated_hosted_route() -> None:
    verifier = _Verifier()
    application = create_component_app(
        _config(Component.CONTROLLER),
        verifier=verifier,
    )
    with TestClient(application) as client:
        assert client.get("/health").status_code == HTTPStatus.OK
        for method, path in (
            ("GET", "/health?detail=true"),
            ("GET", "/health/"),
            ("GET", "/%68ealth"),
            ("HEAD", "/health"),
            ("POST", "/health"),
        ):
            assert client.request(method, path).status_code == HTTPStatus.UNAUTHORIZED
        assert (
            client.post(
                "/internal/v1/investigations",
                content=_request(InternalOperation.INVESTIGATE),
                headers={"Content-Type": "application/json"},
            ).status_code
            == HTTPStatus.UNAUTHORIZED
        )
        assert (
            client.post(
                "/internal/v1/investigations",
                content=_request(InternalOperation.INVESTIGATE),
                headers={
                    "Authorization": "Bearer hdr.api.sig",
                    "Content-Type": "application/json",
                },
            ).status_code
            == HTTPStatus.UNAUTHORIZED
        )
        assert (
            client.post(
                "/internal/v1/investigations",
                content=_request(InternalOperation.INVESTIGATE),
                headers={
                    "Content-Type": "application/json",
                    "X-Serverless-Authorization": _PLATFORM_HEADER,
                },
            ).status_code
            == HTTPStatus.UNAUTHORIZED
        )
    assert [call[0] for call in verifier.calls] == [None]


def test_middleware_rejects_ambiguous_or_oversized_headers_before_verification() -> (
    None
):
    verifier = _Verifier()
    application = create_component_app(
        _config(Component.CONTROLLER),
        verifier=verifier,
    )
    base_headers = list(_headers("api").items())
    cases = (
        [*base_headers, ("Authorization", "Bearer hdr.api.sig")],
        [*base_headers, ("X-Serverless-Authorization", _PLATFORM_HEADER)],
        [*base_headers, ("X-Oversized", "x" * 8_193)],
        [*base_headers, *((f"X-Header-{index}", "x") for index in range(65))],
        [*base_headers, *((f"X-Large-{index}", "x" * 7_000) for index in range(5))],
    )
    with TestClient(application) as client:
        for headers in cases:
            response = client.post(
                "/internal/v1/investigations",
                content=_request(InternalOperation.INVESTIGATE),
                headers=headers,
            )
            assert response.status_code == HTTPStatus.UNAUTHORIZED

    assert not verifier.calls


def test_controller_accepts_only_api_application_identity() -> None:
    verifier = _Verifier()
    application = create_component_app(
        _config(Component.CONTROLLER),
        verifier=verifier,
    )
    body = _request(InternalOperation.INVESTIGATE)
    with TestClient(application) as client:
        denied = client.post(
            "/internal/v1/investigations",
            content=body,
            headers=_headers("owner"),
        )
        accepted_boundary = client.post(
            "/internal/v1/investigations",
            content=body,
            headers=_headers("api"),
        )

    assert denied.status_code == HTTPStatus.UNAUTHORIZED
    assert accepted_boundary.status_code == HTTPStatus.NOT_IMPLEMENTED
    response = decode_contract(accepted_boundary.content, InternalOperationResponse)
    assert response.operation is InternalOperation.INVESTIGATE
    assert response.accepted is False


def test_internal_request_requires_exact_canonical_wire_encoding() -> None:
    application = create_component_app(
        _config(Component.CONTROLLER),
        verifier=_Verifier(),
    )
    noncanonical = _request(InternalOperation.INVESTIGATE).replace(b"{", b"{ ", 1)
    with TestClient(application) as client:
        response = client.post(
            "/internal/v1/investigations",
            content=noncanonical,
            headers=_headers("api"),
        )

    assert response.status_code == HTTPStatus.BAD_REQUEST


def test_platform_header_representation_is_independent_of_application_token() -> None:
    application = create_component_app(
        _config(Component.CONTROLLER),
        verifier=_Verifier(),
    )
    headers = _headers("api")
    headers["X-Serverless-Authorization"] = "cloud-run-verified-header"
    with TestClient(application) as client:
        response = client.post(
            "/internal/v1/investigations",
            content=_request(InternalOperation.INVESTIGATE),
            headers=headers,
        )

    assert response.status_code == HTTPStatus.NOT_IMPLEMENTED


def test_sandbox_enforces_read_and_mutation_caller_routes() -> None:
    verifier = _Verifier()
    application = create_component_app(
        _config(Component.SANDBOX),
        verifier=verifier,
    )
    cases = (
        (
            "controller",
            "/internal/v1/evidence",
            InternalOperation.READ_EVIDENCE,
            HTTPStatus.NOT_IMPLEMENTED,
        ),
        (
            "controller",
            "/internal/v1/mutations",
            InternalOperation.EXECUTE_FAULT,
            HTTPStatus.UNAUTHORIZED,
        ),
        (
            "fault",
            "/internal/v1/evidence",
            InternalOperation.READ_EVIDENCE,
            HTTPStatus.UNAUTHORIZED,
        ),
        (
            "fault",
            "/internal/v1/mutations",
            InternalOperation.EXECUTE_FAULT,
            HTTPStatus.NOT_IMPLEMENTED,
        ),
        (
            "fault",
            "/internal/v1/cleanup",
            InternalOperation.CLEANUP,
            HTTPStatus.NOT_IMPLEMENTED,
        ),
        (
            "owner",
            "/internal/v1/evidence",
            InternalOperation.READ_EVIDENCE,
            HTTPStatus.UNAUTHORIZED,
        ),
        (
            "api",
            "/internal/v1/evidence",
            InternalOperation.READ_EVIDENCE,
            HTTPStatus.UNAUTHORIZED,
        ),
        (
            "owner",
            "/internal/v1/mutations",
            InternalOperation.EXECUTE_FAULT,
            HTTPStatus.UNAUTHORIZED,
        ),
        (
            "api",
            "/internal/v1/mutations",
            InternalOperation.EXECUTE_FAULT,
            HTTPStatus.UNAUTHORIZED,
        ),
    )
    with TestClient(application) as client:
        for identity, path, operation, expected in cases:
            response = client.post(
                path,
                content=_request(operation),
                headers=_headers(identity),
            )
            assert response.status_code == expected
        for method, path in (
            ("GET", "/internal/v1/evidence"),
            ("POST", "/internal/v1/evidence/"),
            ("POST", "/internal/v1/unknown"),
        ):
            assert (
                client.request(
                    method,
                    path,
                    content=_request(InternalOperation.READ_EVIDENCE),
                    headers=_headers("controller"),
                ).status_code
                == HTTPStatus.UNAUTHORIZED
            )


def test_fault_proxy_accepts_only_api_on_exact_fault_routes() -> None:
    verifier = _Verifier()
    application = create_component_app(
        _config(Component.FAULT_PROXY),
        verifier=verifier,
    )
    with TestClient(application) as client:
        for path, operation in (
            ("/internal/v1/faults", InternalOperation.EXECUTE_FAULT),
            ("/internal/v1/cleanup", InternalOperation.CLEANUP),
        ):
            assert (
                client.post(
                    path,
                    content=_request(operation),
                    headers=_headers("api"),
                ).status_code
                == HTTPStatus.NOT_IMPLEMENTED
            )
            for identity in ("owner", "controller", "fault"):
                assert (
                    client.post(
                        path,
                        content=_request(operation),
                        headers=_headers(identity),
                    ).status_code
                    == HTTPStatus.UNAUTHORIZED
                )
        assert (
            client.post(
                "/internal/v1/faults/",
                content=_request(InternalOperation.EXECUTE_FAULT),
                headers=_headers("api"),
            ).status_code
            == HTTPStatus.UNAUTHORIZED
        )


def test_hosted_api_disables_schema_routes_and_requires_owner_identity() -> None:
    verifier = _Verifier()
    application = create_component_app(
        _config(Component.API),
        verifier=verifier,
    )
    with TestClient(application) as client:
        assert client.get("/docs").status_code == HTTPStatus.UNAUTHORIZED
        assert client.get("/docs", headers=_headers("owner")).status_code == (
            HTTPStatus.UNAUTHORIZED
        )
        assert client.get("/openapi.json", headers=_headers("owner")).status_code == (
            HTTPStatus.UNAUTHORIZED
        )
        assert client.get("/health").status_code == HTTPStatus.OK


@pytest.mark.parametrize(
    ("method", "path"),
    (
        ("POST", "/api/v1/scenario-runs"),
        ("GET", "/api/v1/scenario-runs/missing"),
        ("GET", "/api/v2/scenario-runs/missing/operational-status"),
        ("GET", "/api/v1/scenario-runs/missing/events"),
        ("GET", "/api/v1/investigations/missing/envelope-summary"),
        ("POST", "/api/v1/investigations"),
        ("GET", "/api/v1/investigations/missing"),
        ("GET", "/api/v1/investigations/missing/events"),
    ),
)
def test_hosted_api_owner_reaches_each_exact_public_route(
    method: str,
    path: str,
) -> None:
    application = create_component_app(
        _config(Component.API),
        verifier=_Verifier(),
    )
    with TestClient(application) as client:
        response = client.request(
            method,
            path,
            content=b"{}" if method == "POST" else None,
            headers=_headers("owner"),
        )
        cross_caller = client.request(
            method,
            path,
            content=b"{}" if method == "POST" else None,
            headers=_headers("api"),
        )

    assert response.status_code != HTTPStatus.UNAUTHORIZED
    assert cross_caller.status_code == HTTPStatus.UNAUTHORIZED


@pytest.mark.parametrize(
    ("method", "path"),
    (
        ("GET", "/api/v1/scenario-runs"),
        ("POST", "/api/v1/scenario-runs/identifier"),
        ("GET", "/api/v1/investigations/invalid%2Fidentifier"),
        ("GET", "/api/v1/investigations/identifier/unknown"),
        ("GET", "/api/v1/investigations/identifier/"),
        ("GET", "/unknown"),
    ),
)
def test_hosted_api_denies_owner_on_nonallowlisted_routes(
    method: str,
    path: str,
) -> None:
    application = create_component_app(
        _config(Component.API),
        verifier=_Verifier(),
    )
    with TestClient(application) as client:
        response = client.request(method, path, headers=_headers("owner"))

    assert response.status_code == HTTPStatus.UNAUTHORIZED
