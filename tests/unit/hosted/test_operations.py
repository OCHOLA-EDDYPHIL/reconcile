"""Exact hosted workflow operation wire-adapter tests."""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime, timedelta

import pytest

from reconcile.contracts import Classification, canonical_sha256
from reconcile.contracts.base import canonical_json_value_bytes
from reconcile.contracts.codec import decode_contract
from reconcile.hosted.apps import InternalOperationDenied
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
from reconcile.hosted.operations import (
    HOSTED_INVESTIGATION_RECEIPT_VERSION,
    HostedHttpWorkflowGateway,
    HostedInvestigationHandler,
    HostedInvestigationReceipt,
    HostedOperationHandler,
    HostedWorkflowGatewayError,
)
from reconcile.hosted.transport import HostedHttpResponse, HostedHttpTransport
from reconcile.hosted.workflow import (
    HOSTED_INVESTIGATION_RESULT_VERSION,
    HOSTED_OPERATION_RECEIPT_VERSION,
    HOSTED_OPERATION_SCOPE_VERSION,
    HostedInvestigationResult,
    HostedOperationReceipt,
    HostedOperationScope,
    HostedWorkflowOperation,
)
from tests.contract._factories import make_report

pytestmark = pytest.mark.unit

NOW = datetime(2026, 8, 18, 3, 0, tzinfo=UTC)
CALLER = VerifiedCaller(
    email="rec-p5-api@reconcile-dev-260813-14fa6d.iam.gserviceaccount.com",
    subject="caller-subject",
    issuer="https://accounts.google.com",
    audience="https://reconcile.invalid/phase5/controller",
    expires_at=2_000_000_000,
)


def _scope(operation: HostedWorkflowOperation) -> HostedOperationScope:
    return HostedOperationScope(
        schema_version=HOSTED_OPERATION_SCOPE_VERSION,
        operation=operation,
        launch_id="launch-7",
        launch_sha256="1" * 64,
        scenario_request_sha256="2" * 64,
        investigation_id="investigation-7",
        operation_id="operation-7",
        invocation_id="invocation-7",
        function_call_id="function-call-7",
        envelope_sha256="3" * 64,
        cleanup_manifest_sha256="4" * 64,
        lease_fence=7,
    )


def _internal(scope: HostedOperationScope) -> InternalOperationRequest:
    operation = InternalOperation(scope.operation.value)
    return InternalOperationRequest(
        schema_version=INTERNAL_OPERATION_REQUEST_VERSION,
        request_id=f"request-{scope.operation.value}",
        operation=operation,
        payload=scope.model_dump(mode="json"),
    )


def _receipt(scope: HostedOperationScope) -> HostedOperationReceipt:
    return HostedOperationReceipt(
        schema_version=HOSTED_OPERATION_RECEIPT_VERSION,
        operation=scope.operation,
        scope_sha256=scope.sha256,
        started_at=NOW,
        completed_at=NOW + timedelta(milliseconds=1),
    )


def _report(scope: HostedOperationScope):
    return make_report(Classification.COMMITTED).model_copy(
        update={
            "investigation_id": scope.investigation_id,
            "envelope_sha256": scope.envelope_sha256,
        }
    )


def _api_config() -> HostedConfig:
    return HostedConfig(
        component=Component.API,
        port=8080,
        project_id="reconcile-dev-260813-14fa6d",
        auth_audience="https://reconcile.invalid/phase5/api",
        allowed_caller_emails=("eddyphilochola13@gmail.com",),
        source_revision="1" * 40,
        image_digest=f"sha256:{'2' * 64}",
        infra_revision="3" * 64,
        semantic_config_sha256="4" * 64,
        runtime_database="reconcile-p5-runtime",
        controller_url="https://controller.example.test",
        controller_audience="https://reconcile.invalid/phase5/controller",
        fault_proxy_url="https://fault.example.test",
        fault_proxy_audience="https://reconcile.invalid/phase5/fault-proxy",
    )


def test_operation_handlers_bind_caller_scope_and_result_identity() -> None:
    async def scenario() -> None:
        mutation_scope = _scope(HostedWorkflowOperation.EXECUTE_FAULT)
        calls: list[HostedOperationScope] = []
        authorized: list[HostedOperationScope] = []

        async def authorize(scope: HostedOperationScope) -> None:
            authorized.append(scope)

        async def dispatch(scope: HostedOperationScope) -> HostedOperationReceipt:
            calls.append(scope)
            return _receipt(scope)

        handler = HostedOperationHandler(
            operation=HostedWorkflowOperation.EXECUTE_FAULT,
            expected_caller_email=CALLER.email,
            authorizer=authorize,
            dispatcher=dispatch,
        )
        request = _internal(mutation_scope)
        response = await handler(CALLER, request)
        assert response == InternalOperationResponse(
            schema_version=INTERNAL_OPERATION_RESPONSE_VERSION,
            request_id=request.request_id,
            operation=request.operation,
            accepted=True,
            payload=_receipt(mutation_scope).model_dump(mode="json"),
        )
        assert calls == [mutation_scope]
        assert authorized == [mutation_scope]

        wrong_caller = VerifiedCaller(
            email="rec-p5-controller@example.test",
            subject=CALLER.subject,
            issuer=CALLER.issuer,
            audience=CALLER.audience,
            expires_at=CALLER.expires_at,
        )
        with pytest.raises(InternalOperationDenied):
            await handler(wrong_caller, request)
        assert calls == [mutation_scope]
        assert authorized == [mutation_scope]

        mismatched = _internal(_scope(HostedWorkflowOperation.CLEANUP)).model_copy(
            update={"operation": InternalOperation.EXECUTE_FAULT}
        )
        with pytest.raises(ValueError):
            await handler(CALLER, mismatched)
        assert calls == [mutation_scope]
        assert authorized == [mutation_scope]

        async def deny(_scope: HostedOperationScope) -> None:
            raise InternalOperationDenied

        denied = HostedOperationHandler(
            operation=HostedWorkflowOperation.EXECUTE_FAULT,
            expected_caller_email=CALLER.email,
            authorizer=deny,
            dispatcher=dispatch,
        )
        with pytest.raises(InternalOperationDenied):
            await denied(CALLER, request)
        assert calls == [mutation_scope]

    asyncio.run(scenario())


def test_investigation_handler_returns_only_durable_report_identity() -> None:
    async def scenario() -> None:
        scope = _scope(HostedWorkflowOperation.INVESTIGATE)
        report = _report(scope)
        authorized: list[HostedOperationScope] = []

        async def authorize(received: HostedOperationScope) -> None:
            authorized.append(received)

        async def dispatch(
            received: HostedOperationScope,
        ) -> HostedInvestigationResult:
            assert received == scope
            return HostedInvestigationResult(
                schema_version=HOSTED_INVESTIGATION_RESULT_VERSION,
                scope_sha256=received.sha256,
                report=report,
            )

        handler = HostedInvestigationHandler(
            expected_caller_email=CALLER.email,
            authorizer=authorize,
            dispatcher=dispatch,
        )
        request = _internal(scope)
        response = await handler(CALLER, request)
        receipt = HostedInvestigationReceipt(
            schema_version=HOSTED_INVESTIGATION_RECEIPT_VERSION,
            scope_sha256=scope.sha256,
            report_sha256=canonical_sha256(report),
        )
        assert response.payload == receipt.model_dump(mode="json")
        assert "report" not in response.payload
        assert authorized == [scope]

    asyncio.run(scenario())


def test_http_gateway_routes_once_and_loads_the_exact_durable_report(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def scenario() -> None:
        transport = HostedHttpTransport()
        requests: list[tuple[str, str, str, bytes]] = []
        report_by_id = {}

        async def request(
            method: str,
            url: str,
            *,
            audience: str,
            content: bytes = b"",
        ) -> HostedHttpResponse:
            requests.append((method, url, audience, content))
            internal = decode_contract(content, InternalOperationRequest)
            scope = HostedOperationScope.model_validate_json(
                canonical_json_value_bytes(internal.payload)
            )
            if scope.operation is HostedWorkflowOperation.INVESTIGATE:
                report = _report(scope)
                report_by_id[scope.investigation_id] = report
                payload = HostedInvestigationReceipt(
                    schema_version=HOSTED_INVESTIGATION_RECEIPT_VERSION,
                    scope_sha256=scope.sha256,
                    report_sha256=canonical_sha256(report),
                ).model_dump(mode="json")
            else:
                payload = _receipt(scope).model_dump(mode="json")
            response = InternalOperationResponse(
                schema_version=INTERNAL_OPERATION_RESPONSE_VERSION,
                request_id=internal.request_id,
                operation=internal.operation,
                accepted=True,
                payload=payload,
            )
            return HostedHttpResponse(
                status_code=200,
                content=canonical_internal_json_bytes(response),
            )

        monkeypatch.setattr(transport, "request", request)

        class Loader:
            async def load_report(self, investigation_id: str):
                return report_by_id[investigation_id]

        gateway = HostedHttpWorkflowGateway(_api_config(), transport, Loader())
        mutation = _scope(HostedWorkflowOperation.EXECUTE_FAULT)
        cleanup = _scope(HostedWorkflowOperation.CLEANUP)
        investigation = _scope(HostedWorkflowOperation.INVESTIGATE)

        assert await gateway.execute_fault(mutation) == _receipt(mutation)
        result = await gateway.investigate(investigation)
        assert result.report == _report(investigation)
        assert result.scope_sha256 == investigation.sha256
        assert await gateway.cleanup(cleanup) == _receipt(cleanup)

        assert [(method, url, audience) for method, url, audience, _ in requests] == [
            (
                "POST",
                "https://fault.example.test/internal/v1/faults",
                "https://reconcile.invalid/phase5/fault-proxy",
            ),
            (
                "POST",
                "https://controller.example.test/internal/v1/investigations",
                "https://reconcile.invalid/phase5/controller",
            ),
            (
                "POST",
                "https://fault.example.test/internal/v1/cleanup",
                "https://reconcile.invalid/phase5/fault-proxy",
            ),
        ]
        for _, _, _, content in requests:
            decoded = decode_contract(content, InternalOperationRequest)
            assert content == canonical_internal_json_bytes(decoded)

    asyncio.run(scenario())


def test_http_gateway_fails_closed_on_wrong_report_without_retry(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def scenario() -> None:
        transport = HostedHttpTransport()
        calls = 0
        scope = _scope(HostedWorkflowOperation.INVESTIGATE)
        wrong_report = _report(scope).model_copy(update={"envelope_sha256": "9" * 64})

        async def request(
            _method: str,
            _url: str,
            *,
            audience: str,
            content: bytes = b"",
        ) -> HostedHttpResponse:
            nonlocal calls
            del audience
            calls += 1
            internal = decode_contract(content, InternalOperationRequest)
            receipt = HostedInvestigationReceipt(
                schema_version=HOSTED_INVESTIGATION_RECEIPT_VERSION,
                scope_sha256=scope.sha256,
                report_sha256=canonical_sha256(wrong_report),
            )
            response = InternalOperationResponse(
                schema_version=INTERNAL_OPERATION_RESPONSE_VERSION,
                request_id=internal.request_id,
                operation=internal.operation,
                accepted=True,
                payload=receipt.model_dump(mode="json"),
            )
            return HostedHttpResponse(
                status_code=200,
                content=canonical_internal_json_bytes(response),
            )

        monkeypatch.setattr(transport, "request", request)

        class Loader:
            async def load_report(self, _investigation_id: str):
                return wrong_report

        gateway = HostedHttpWorkflowGateway(_api_config(), transport, Loader())
        with pytest.raises(HostedWorkflowGatewayError) as captured:
            await gateway.investigate(scope)
        assert str(captured.value) == "hosted workflow dependency is unavailable"
        assert captured.value.__cause__ is None
        assert calls == 1

    asyncio.run(scenario())


def test_http_gateway_sanitizes_a_malformed_transport_return_without_retry(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def scenario() -> None:
        transport = HostedHttpTransport()
        calls = 0

        async def request(
            _method: str,
            _url: str,
            *,
            audience: str,
            content: bytes = b"",
        ) -> object:
            nonlocal calls
            del audience, content
            calls += 1
            return object()

        monkeypatch.setattr(transport, "request", request)

        class Loader:
            async def load_report(self, _investigation_id: str):
                raise AssertionError("a mutation response must not load a report")

        gateway = HostedHttpWorkflowGateway(_api_config(), transport, Loader())
        with pytest.raises(HostedWorkflowGatewayError) as captured:
            await gateway.execute_fault(_scope(HostedWorkflowOperation.EXECUTE_FAULT))
        assert str(captured.value) == "hosted workflow dependency is unavailable"
        assert captured.value.__cause__ is None
        assert calls == 1

    asyncio.run(scenario())
