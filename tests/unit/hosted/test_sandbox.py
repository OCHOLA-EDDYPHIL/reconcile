"""Restricted hosted sandbox observation reads and route behavior."""

from __future__ import annotations

import asyncio
import hashlib
from collections.abc import Collection
from copy import deepcopy
from dataclasses import dataclass, replace
from datetime import UTC, datetime
from http import HTTPStatus
from typing import Any

import httpx
import pytest
from fastapi.testclient import TestClient
from pydantic import ValidationError

from reconcile.contracts.base import canonical_json_value_bytes
from reconcile.contracts.codec import decode_contract
from reconcile.hosted.apps import create_component_app
from reconcile.hosted.config import Component, HostedConfig
from reconcile.hosted.contracts import (
    INTERNAL_OPERATION_REQUEST_VERSION,
    INTERNAL_OPERATION_RESPONSE_VERSION,
    InternalOperation,
    InternalOperationRequest,
    InternalOperationResponse,
    canonical_internal_json_bytes,
)
from reconcile.hosted.identity import VerifiedCaller
from reconcile.hosted.sandbox import (
    SANDBOX_AGGREGATE_SCHEMA_VERSION,
    SANDBOX_FIRESTORE_TIMEOUT_SECONDS,
    SANDBOX_INGRESS_SCHEMA_VERSION,
    SANDBOX_TARGET_DATABASE_ID,
    FirestoreSandboxEvidenceReader,
    HostedSandboxEvidenceTarget,
    SandboxAggregateEvidence,
    SandboxAggregateObservation,
    SandboxEvidenceError,
    SandboxEvidenceFailure,
    SandboxEvidenceRequest,
    SandboxIngressEvidence,
    SandboxIngressObservation,
    sandbox_evidence_payload,
)
from reconcile.hosted.transport import HostedHttpTransport
from reconcile.scenarios.local_order import (
    WeakIngressObservation,
    WeakOrderAggregateObservation,
    WeakOrderCountBand,
)

pytestmark = pytest.mark.unit

_PROJECT = "reconcile-dev-260813-14fa6d"
_DATABASE = "reconcile-p5-target"
_SANDBOX = "sandbox-run-7"
_NOW = datetime(2026, 8, 17, 20, 0, tzinfo=UTC)
_CONTROLLER = f"rec-p5-controller@{_PROJECT}.iam.gserviceaccount.com"
_FAULT = f"rec-p5-fault@{_PROJECT}.iam.gserviceaccount.com"
_SANDBOX_URL = "https://sandbox.example.test"
_SANDBOX_AUDIENCE = f"https://reconcile.invalid/phase5/{_PROJECT}/sandbox"


@dataclass(frozen=True, slots=True)
class _Reference:
    path: str


@dataclass(slots=True)
class _Snapshot:
    reference: _Reference
    exists: bool
    read_time: object
    update_time: object | None
    data: dict[str, Any] | None

    def to_dict(self) -> dict[str, Any] | None:
        return deepcopy(self.data)


class _Client:
    def __init__(self) -> None:
        self.documents: dict[str, dict[str, Any]] = {}
        self.document_calls: list[tuple[str, ...]] = []
        self.get_calls: list[
            tuple[
                tuple[str, ...],
                object | None,
                object | None,
                object | None,
                float | None,
                datetime | None,
            ]
        ] = []
        self.get_error: BaseException | None = None
        self.duplicate_snapshot = False
        self.reference_override: str | None = None
        self.exists_override: object | None = None
        self.update_time_override: object | None = None

    def document(self, *document_path: str) -> _Reference:
        self.document_calls.append(document_path)
        return _Reference("/".join(document_path))

    async def get_all(
        self,
        references: list[_Reference],
        field_paths: object | None = None,
        transaction: object | None = None,
        retry: object | None = None,
        timeout: float | None = None,
        *,
        read_time: datetime | None = None,
    ):
        self.get_calls.append(
            (
                tuple(reference.path for reference in references),
                field_paths,
                transaction,
                retry,
                timeout,
                read_time,
            )
        )
        if self.get_error is not None:
            raise self.get_error
        for reference in references:
            data = self.documents.get(reference.path)
            exists: object = data is not None
            if self.exists_override is not None:
                exists = self.exists_override
            snapshot = _Snapshot(
                reference=_Reference(self.reference_override or reference.path),
                exists=exists,  # type: ignore[arg-type]
                read_time=_NOW,
                update_time=(
                    self.update_time_override
                    if self.update_time_override is not None
                    else (_NOW if data is not None else None)
                ),
                data=deepcopy(data),
            )
            yield snapshot
            if self.duplicate_snapshot:
                yield snapshot


class _Factory:
    def __init__(self, client: _Client) -> None:
        self.client = client
        self.calls = 0

    def __call__(self) -> _Client:
        self.calls += 1
        return self.client


def _request(observation: str) -> SandboxEvidenceRequest:
    return SandboxEvidenceRequest(
        sandbox_id=_SANDBOX,
        observation=observation,  # type: ignore[arg-type]
    )


def _reader(
    client: _Client,
    factory: _Factory | None = None,
) -> FirestoreSandboxEvidenceReader:
    return FirestoreSandboxEvidenceReader(
        project_id=_PROJECT,
        database_id=_DATABASE,
        client_factory=factory or _Factory(client),
    )


def _path(observation: str) -> str:
    return f"reconcile-sandbox-observations/{_SANDBOX}/weak-observations/{observation}"


def _expected_hosted_request(observation: str) -> InternalOperationRequest:
    payload = {"sandbox_id": _SANDBOX, "observation": observation}
    digest = hashlib.sha256(canonical_json_value_bytes(payload)).hexdigest()
    return InternalOperationRequest(
        schema_version=INTERNAL_OPERATION_REQUEST_VERSION,
        request_id=f"sandbox-evidence-{observation}-{digest[:32]}",
        operation=InternalOperation.READ_EVIDENCE,
        payload=payload,
    )


def test_request_is_strict_and_bounded() -> None:
    assert _request("ingress").model_dump(mode="json") == {
        "sandbox_id": _SANDBOX,
        "observation": "ingress",
    }

    for value in (
        {"sandbox_id": _SANDBOX, "observation": "private-order"},
        {"sandbox_id": "bad/path", "observation": "aggregate"},
        {"sandbox_id": _SANDBOX, "observation": "ingress", "extra": True},
        {"sandbox_id": _SANDBOX},
    ):
        with pytest.raises(ValidationError):
            SandboxEvidenceRequest.model_validate(value)


def test_firestore_reader_requires_the_exact_target_database() -> None:
    assert SANDBOX_TARGET_DATABASE_ID == _DATABASE
    with pytest.raises(ValueError, match="database identifier"):
        FirestoreSandboxEvidenceReader(
            project_id=_PROJECT,
            database_id="another-target",
            client_factory=_Factory(_Client()),
        )


def test_reader_is_lazy_and_projects_one_exact_ingress_document() -> None:
    client = _Client()
    client.documents[_path("ingress")] = {
        "schema_version": SANDBOX_INGRESS_SCHEMA_VERSION,
        "sandbox_id": _SANDBOX,
        "event_kind": "REQUEST_SEEN",
        "observed_at": _NOW,
    }
    factory = _Factory(client)
    reader = _reader(client, factory)

    assert factory.calls == 0
    result = asyncio.run(reader.read_evidence(_request("ingress")))

    assert result == SandboxIngressEvidence(
        ingress=SandboxIngressObservation(
            event_kind="REQUEST_SEEN",
            observed_at=_NOW,
        )
    )
    assert factory.calls == 1
    assert client.document_calls == [
        (
            "reconcile-sandbox-observations",
            _SANDBOX,
            "weak-observations",
            "ingress",
        )
    ]
    assert client.get_calls == [
        (
            (_path("ingress"),),
            ("event_kind", "observed_at", "sandbox_id", "schema_version"),
            None,
            None,
            SANDBOX_FIRESTORE_TIMEOUT_SECONDS,
            None,
        )
    ]


def test_reader_projects_one_exact_aggregate_and_reuses_its_lazy_client() -> None:
    client = _Client()
    client.documents[_path("aggregate")] = {
        "schema_version": SANDBOX_AGGREGATE_SCHEMA_VERSION,
        "sandbox_id": _SANDBOX,
        "count_band": "ONE_OR_MORE",
        "observed_at": _NOW,
    }
    factory = _Factory(client)
    reader = _reader(client, factory)

    first = asyncio.run(reader.read_evidence(_request("aggregate")))
    second = asyncio.run(reader.read_evidence(_request("ingress")))

    assert first == SandboxAggregateEvidence(
        aggregate=SandboxAggregateObservation(
            count_band="ONE_OR_MORE",
            observed_at=_NOW,
        )
    )
    assert second == SandboxIngressEvidence(ingress=None)
    assert factory.calls == 1
    assert client.get_calls[0] == (
        (_path("aggregate"),),
        ("count_band", "observed_at", "sandbox_id", "schema_version"),
        None,
        None,
        SANDBOX_FIRESTORE_TIMEOUT_SECONDS,
        None,
    )


def test_public_payload_contains_only_the_selected_weak_fields() -> None:
    ingress = sandbox_evidence_payload(
        _request("ingress"),
        SandboxIngressEvidence(
            ingress=SandboxIngressObservation(
                event_kind="REQUEST_SEEN",
                observed_at=_NOW,
            )
        ),
    )
    aggregate = sandbox_evidence_payload(
        _request("aggregate"),
        SandboxAggregateEvidence(
            aggregate=SandboxAggregateObservation(
                count_band="ZERO",
                observed_at=_NOW,
            )
        ),
    )

    assert ingress == {
        "ingress": {
            "event_kind": "REQUEST_SEEN",
            "observed_at": "2026-08-17T20:00:00+00:00",
        }
    }
    assert aggregate == {
        "aggregate": {
            "count_band": "ZERO",
            "observed_at": "2026-08-17T20:00:00+00:00",
        }
    }
    serialized = str(ingress)
    assert all(
        private_field not in serialized
        for private_field in ("order", "outcome", "correlation")
    )

    with pytest.raises(TypeError, match="does not match"):
        sandbox_evidence_payload(
            _request("ingress"),
            SandboxAggregateEvidence(aggregate=None),
        )


@pytest.mark.parametrize(
    "change",
    (
        lambda data: data.update({"correlation": {"operation_id": "private"}}),
        lambda data: data.update({"sandbox_id": "another-sandbox"}),
        lambda data: data.update({"event_kind": "ORDER_ACCEPTED"}),
        lambda data: data.pop("schema_version"),
    ),
)
def test_reader_fails_closed_on_nonexact_stored_ingress(
    change: Any,
) -> None:
    client = _Client()
    data = {
        "schema_version": SANDBOX_INGRESS_SCHEMA_VERSION,
        "sandbox_id": _SANDBOX,
        "event_kind": "REQUEST_SEEN",
        "observed_at": _NOW,
    }
    change(data)
    client.documents[_path("ingress")] = data

    with pytest.raises(SandboxEvidenceError) as failure:
        asyncio.run(_reader(client).read_evidence(_request("ingress")))

    assert failure.value.code is SandboxEvidenceFailure.MALFORMED_RESPONSE
    assert str(failure.value) == "malformed-response"


@pytest.mark.parametrize("malformation", ("duplicate", "reference", "exists"))
def test_reader_rejects_malformed_provider_snapshot(malformation: str) -> None:
    client = _Client()
    if malformation == "duplicate":
        client.duplicate_snapshot = True
    elif malformation == "reference":
        client.reference_override = "another/document"
    else:
        client.exists_override = 1

    with pytest.raises(SandboxEvidenceError) as failure:
        asyncio.run(_reader(client).read_evidence(_request("aggregate")))

    assert failure.value.code is SandboxEvidenceFailure.MALFORMED_RESPONSE


def test_reader_sanitizes_provider_failures_and_propagates_cancellation() -> None:
    client = _Client()
    client.get_error = RuntimeError("private provider response")
    with pytest.raises(SandboxEvidenceError) as failure:
        asyncio.run(_reader(client).read_evidence(_request("ingress")))

    assert failure.value.code is SandboxEvidenceFailure.UNAVAILABLE
    assert str(failure.value) == "unavailable"
    assert "private" not in str(failure.value)

    cancelled_client = _Client()
    cancelled_client.get_error = asyncio.CancelledError()
    with pytest.raises(asyncio.CancelledError):
        asyncio.run(_reader(cancelled_client).read_evidence(_request("aggregate")))


def test_hosted_target_posts_one_canonical_ingress_request_and_converts_response() -> (
    None
):
    requests: list[httpx.Request] = []
    audiences: list[str] = []

    def token_supplier(audience: str) -> str:
        audiences.append(audience)
        return "header.payload.signature"

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        expected = _expected_hosted_request("ingress")
        assert request.content == canonical_internal_json_bytes(expected)
        decoded = decode_contract(request.content, InternalOperationRequest)
        assert decoded == expected
        response = InternalOperationResponse(
            schema_version=INTERNAL_OPERATION_RESPONSE_VERSION,
            request_id=decoded.request_id,
            operation=InternalOperation.READ_EVIDENCE,
            accepted=True,
            payload={
                "ingress": {
                    "event_kind": "REQUEST_SEEN",
                    "observed_at": "2026-08-17T20:00:00+00:00",
                }
            },
        )
        return httpx.Response(200, content=canonical_internal_json_bytes(response))

    async def exercise() -> WeakIngressObservation | None:
        async with httpx.AsyncClient(
            transport=httpx.MockTransport(handler),
        ) as client:
            target = HostedSandboxEvidenceTarget(
                sandbox_url=_SANDBOX_URL,
                sandbox_audience=_SANDBOX_AUDIENCE,
                sandbox_id=_SANDBOX,
                transport=HostedHttpTransport(token_supplier, client),
            )
            return await target.read_ingress_observation()

    result = asyncio.run(exercise())

    assert result == WeakIngressObservation(
        event_kind="REQUEST_SEEN",
        observed_at=_NOW,
    )
    assert audiences == [_SANDBOX_AUDIENCE]
    assert len(requests) == 1
    assert requests[0].method == "POST"
    assert requests[0].url == httpx.URL(f"{_SANDBOX_URL}/internal/v1/evidence")
    assert requests[0].headers["Authorization"] == "Bearer header.payload.signature"


def test_hosted_target_converts_aggregate_and_missing_weak_observations() -> None:
    calls: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        decoded = decode_contract(request.content, InternalOperationRequest)
        observation = decoded.payload["observation"]
        assert type(observation) is str
        calls.append(observation)
        payload = (
            {
                "aggregate": {
                    "count_band": "ONE_OR_MORE",
                    "observed_at": "2026-08-17T20:00:00+00:00",
                }
            }
            if observation == "aggregate"
            else {"ingress": None}
        )
        response = InternalOperationResponse(
            schema_version=INTERNAL_OPERATION_RESPONSE_VERSION,
            request_id=decoded.request_id,
            operation=InternalOperation.READ_EVIDENCE,
            accepted=True,
            payload=payload,
        )
        return httpx.Response(200, content=canonical_internal_json_bytes(response))

    async def exercise() -> tuple[
        WeakOrderAggregateObservation | None,
        WeakIngressObservation | None,
    ]:
        async with httpx.AsyncClient(
            transport=httpx.MockTransport(handler),
        ) as client:
            target = HostedSandboxEvidenceTarget(
                sandbox_url=_SANDBOX_URL,
                sandbox_audience=_SANDBOX_AUDIENCE,
                sandbox_id=_SANDBOX,
                transport=HostedHttpTransport(
                    lambda _audience: "header.payload.signature",
                    client,
                ),
            )
            return (
                await target.read_aggregate_observation(),
                await target.read_ingress_observation(),
            )

    aggregate, ingress = asyncio.run(exercise())

    assert aggregate == WeakOrderAggregateObservation(
        count_band=WeakOrderCountBand.ONE_OR_MORE,
        observed_at=_NOW,
    )
    assert ingress is None
    assert calls == ["aggregate", "ingress"]


@pytest.mark.parametrize(
    ("malformation", "expected_code"),
    (
        ("noncanonical", SandboxEvidenceFailure.MALFORMED_RESPONSE),
        ("wrong-request", SandboxEvidenceFailure.MALFORMED_RESPONSE),
        ("wrong-operation", SandboxEvidenceFailure.MALFORMED_RESPONSE),
        ("not-accepted", SandboxEvidenceFailure.MALFORMED_RESPONSE),
        ("private-field", SandboxEvidenceFailure.MALFORMED_RESPONSE),
        ("noncanonical-payload", SandboxEvidenceFailure.MALFORMED_RESPONSE),
        ("wrong-selection", SandboxEvidenceFailure.MALFORMED_RESPONSE),
        ("non-success", SandboxEvidenceFailure.UNAVAILABLE),
    ),
)
def test_hosted_target_fails_closed_on_nonexact_response(
    malformation: str,
    expected_code: SandboxEvidenceFailure,
) -> None:
    attempts = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal attempts
        attempts += 1
        decoded = decode_contract(request.content, InternalOperationRequest)
        if malformation == "non-success":
            return httpx.Response(503, content=b'{"code":"unavailable"}')
        payload: dict[str, object] = {
            "ingress": {
                "event_kind": "REQUEST_SEEN",
                "observed_at": "2026-08-17T20:00:00+00:00",
            }
        }
        if malformation == "private-field":
            payload["ingress"] = {
                "event_kind": "REQUEST_SEEN",
                "observed_at": "2026-08-17T20:00:00+00:00",
                "outcome": "private",
            }
        elif malformation == "noncanonical-payload":
            payload["ingress"] = {
                "event_kind": "REQUEST_SEEN",
                "observed_at": "2026-08-17T20:00:00Z",
            }
        elif malformation == "wrong-selection":
            payload = {"aggregate": None}
        response = InternalOperationResponse(
            schema_version=INTERNAL_OPERATION_RESPONSE_VERSION,
            request_id=(
                "different-request"
                if malformation == "wrong-request"
                else decoded.request_id
            ),
            operation=(
                InternalOperation.CLEANUP
                if malformation == "wrong-operation"
                else InternalOperation.READ_EVIDENCE
            ),
            accepted=malformation != "not-accepted",
            payload=payload,  # type: ignore[arg-type]
        )
        content = canonical_internal_json_bytes(response)
        if malformation == "noncanonical":
            content = content.replace(b"{", b"{ ", 1)
        return httpx.Response(200, content=content)

    async def exercise() -> None:
        async with httpx.AsyncClient(
            transport=httpx.MockTransport(handler),
        ) as client:
            target = HostedSandboxEvidenceTarget(
                sandbox_url=_SANDBOX_URL,
                sandbox_audience=_SANDBOX_AUDIENCE,
                sandbox_id=_SANDBOX,
                transport=HostedHttpTransport(
                    lambda _audience: "header.payload.signature",
                    client,
                ),
            )
            with pytest.raises(SandboxEvidenceError) as failure:
                await target.read_ingress_observation()
            assert failure.value.code is expected_code
            assert str(failure.value) == expected_code.value

    asyncio.run(exercise())
    assert attempts == 1


def test_hosted_target_sanitizes_transport_failure_without_retry() -> None:
    attempts = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal attempts
        attempts += 1
        raise httpx.ConnectError("private order response", request=request)

    async def exercise() -> None:
        async with httpx.AsyncClient(
            transport=httpx.MockTransport(handler),
        ) as client:
            target = HostedSandboxEvidenceTarget(
                sandbox_url=_SANDBOX_URL,
                sandbox_audience=_SANDBOX_AUDIENCE,
                sandbox_id=_SANDBOX,
                transport=HostedHttpTransport(
                    lambda _audience: "header.payload.signature",
                    client,
                ),
            )
            with pytest.raises(SandboxEvidenceError) as failure:
                await target.read_aggregate_observation()
            assert failure.value.code is SandboxEvidenceFailure.UNAVAILABLE
            assert str(failure.value) == "unavailable"
            assert "private" not in repr(failure.value)

    asyncio.run(exercise())
    assert attempts == 1


@pytest.mark.parametrize(
    ("field", "value"),
    (
        ("sandbox_url", "https://sandbox.example.test/"),
        ("sandbox_url", "http://sandbox.example.test"),
        ("sandbox_audience", "audience with spaces"),
        ("sandbox_id", "private/sandbox"),
    ),
)
def test_hosted_target_rejects_nonexact_coordinates(
    field: str,
    value: str,
) -> None:
    values = {
        "sandbox_url": _SANDBOX_URL,
        "sandbox_audience": _SANDBOX_AUDIENCE,
        "sandbox_id": _SANDBOX,
    }
    values[field] = value

    with pytest.raises((TypeError, ValueError)):
        HostedSandboxEvidenceTarget(
            **values,
            transport=HostedHttpTransport(lambda _audience: "header.payload.signature"),
        )


class _Verifier:
    def verify(
        self,
        authorization_header: str | None,
        expected_audience: str,
        allowed_emails: Collection[str],
    ) -> VerifiedCaller:
        assert authorization_header == "Bearer hdr.controller.sig"
        assert tuple(allowed_emails) == (_CONTROLLER,)
        return VerifiedCaller(
            email=_CONTROLLER,
            subject="controller-subject",
            issuer="https://accounts.google.com",
            audience=expected_audience,
            expires_at=2**31,
        )


class _InjectedReader:
    def __init__(self) -> None:
        self.requests: list[SandboxEvidenceRequest] = []
        self.error: Exception | None = None

    async def read_evidence(
        self,
        request: SandboxEvidenceRequest,
    ) -> SandboxIngressEvidence:
        self.requests.append(request)
        if self.error is not None:
            raise self.error
        return SandboxIngressEvidence(
            ingress=SandboxIngressObservation(
                event_kind="REQUEST_SEEN",
                observed_at=_NOW,
            )
        )


def _config() -> HostedConfig:
    return HostedConfig(
        component=Component.SANDBOX,
        port=8080,
        project_id=_PROJECT,
        auth_audience=f"https://reconcile.invalid/phase5/{_PROJECT}/sandbox",
        allowed_caller_emails=(_CONTROLLER, _FAULT),
        source_revision="a" * 40,
        image_digest=f"sha256:{'b' * 64}",
        infra_revision="c" * 64,
        semantic_config_sha256="d" * 64,
        target_database=_DATABASE,
        sandbox_read_caller_email=_CONTROLLER,
        sandbox_mutation_caller_email=_FAULT,
    )


def _headers() -> dict[str, str]:
    return {
        "Authorization": "Bearer hdr.controller.sig",
        "Content-Type": "application/json",
        "X-Serverless-Authorization": "Bearer e30.e30.",
    }


def _internal_request(**payload: object) -> bytes:
    return canonical_internal_json_bytes(
        InternalOperationRequest(
            schema_version=INTERNAL_OPERATION_REQUEST_VERSION,
            request_id="sandbox-evidence-7",
            operation=InternalOperation.READ_EVIDENCE,
            payload=payload,  # type: ignore[arg-type]
        )
    )


def test_injected_reader_serves_the_canonical_internal_evidence_route() -> None:
    reader = _InjectedReader()
    application = create_component_app(
        _config(),
        verifier=_Verifier(),
        sandbox_evidence_reader=reader,
    )

    with TestClient(application) as client:
        response = client.post(
            "/internal/v1/evidence",
            content=_internal_request(
                sandbox_id=_SANDBOX,
                observation="ingress",
            ),
            headers=_headers(),
        )
        fault_headers = _headers()
        fault_headers["Authorization"] = "Bearer hdr.fault.sig"
        denied = client.post(
            "/internal/v1/evidence",
            content=_internal_request(
                sandbox_id=_SANDBOX,
                observation="ingress",
            ),
            headers=fault_headers,
        )

    assert response.status_code == HTTPStatus.OK
    assert denied.status_code == HTTPStatus.UNAUTHORIZED
    assert response.headers["cache-control"] == "no-store"
    assert reader.requests == [_request("ingress")]
    decoded = decode_contract(response.content, InternalOperationResponse)
    assert decoded.accepted is True
    assert decoded.operation is InternalOperation.READ_EVIDENCE
    assert decoded.payload == {
        "ingress": {
            "event_kind": "REQUEST_SEEN",
            "observed_at": "2026-08-17T20:00:00+00:00",
        }
    }
    assert response.content == canonical_internal_json_bytes(decoded)


def test_evidence_route_rejects_nonexact_input_and_sanitizes_reader_failure() -> None:
    reader = _InjectedReader()
    application = create_component_app(
        _config(),
        verifier=_Verifier(),
        sandbox_evidence_reader=reader,
    )
    with TestClient(application) as client:
        invalid = client.post(
            "/internal/v1/evidence",
            content=_internal_request(
                sandbox_id=_SANDBOX,
                observation="ingress",
                correlation="forbidden",
            ),
            headers=_headers(),
        )
        reader.error = RuntimeError("private order response")
        unavailable = client.post(
            "/internal/v1/evidence",
            content=_internal_request(
                sandbox_id=_SANDBOX,
                observation="ingress",
            ),
            headers=_headers(),
        )

    assert invalid.status_code == HTTPStatus.BAD_REQUEST
    assert invalid.content == b'{"code":"invalid-contract"}'
    assert unavailable.status_code == HTTPStatus.SERVICE_UNAVAILABLE
    assert unavailable.content == b'{"code":"evidence-unavailable"}'
    assert b"private" not in unavailable.content


def test_evidence_reader_is_rejected_by_non_sandbox_components() -> None:
    controller_config = replace(
        _config(),
        component=Component.CONTROLLER,
        allowed_caller_emails=(_FAULT,),
        sandbox_read_caller_email=None,
        sandbox_mutation_caller_email=None,
    )
    with pytest.raises(ValueError, match="only the sandbox"):
        create_component_app(
            controller_config,
            verifier=_Verifier(),
            sandbox_evidence_reader=_InjectedReader(),
        )
