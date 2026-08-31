"""Exact hosted workflow operation wire-adapter tests."""

from __future__ import annotations

import asyncio
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from http import HTTPStatus

import pytest

from reconcile.contracts import (
    Classification,
    RecoveryRunEventPayload,
    RecoveryRunEventType,
    RecoveryRunFailureCategory,
    RecoveryRunFault,
    RecoveryRunLifecycle,
    RecoveryRunPolicy,
    canonical_sha256,
)
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
    HOSTED_RECOVERY_RECEIPT_VERSION,
    HostedHttpWorkflowGateway,
    HostedInvestigationHandler,
    HostedInvestigationReceipt,
    HostedOperationHandler,
    HostedRecoveryGatewayError,
    HostedRecoveryHandler,
    HostedRecoveryReceipt,
    HostedRecoveryRunGateway,
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
from reconcile.persistence import InMemoryRecoveryRunStore, RecoveryRunConflict
from reconcile.recovery_workflow import RecoveryRunLaunchResult
from tests.contract._factories import make_recovery_run_examples, make_report

pytestmark = pytest.mark.unit

NOW = datetime(2026, 8, 18, 3, 0, tzinfo=UTC)
CALLER = VerifiedCaller(
    email="rec-p5-api@example-project-id.iam.gserviceaccount.com",
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
        project_id="example-project-id",
        auth_audience="https://reconcile.invalid/phase5/api",
        allowed_caller_emails=(
            "rec-p5-apply@example-project-id.iam.gserviceaccount.com",
        ),
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


async def _terminal_recovery(store: InMemoryRecoveryRunStore):
    request, _event, _launch, initial, _scope = make_recovery_run_examples()
    snapshot, created = await store.create(
        request,
        initial.chain,
        created_at=NOW,
    )
    snapshot = await store.append(
        request.run_id,
        expected_revision=snapshot.revision,
        event_type=RecoveryRunEventType.LIFECYCLE,
        payload=RecoveryRunEventPayload(lifecycle=RecoveryRunLifecycle.RUNNING),
        occurred_at=NOW + timedelta(seconds=1),
    )
    snapshot = await store.append(
        request.run_id,
        expected_revision=snapshot.revision,
        event_type=RecoveryRunEventType.LIFECYCLE,
        payload=RecoveryRunEventPayload(
            lifecycle=RecoveryRunLifecycle.FAILED,
            failure_category=RecoveryRunFailureCategory.INTERNAL_FAILURE,
        ),
        occurred_at=NOW + timedelta(seconds=2),
    )
    return request, snapshot, created


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


def test_recovery_handler_returns_only_the_terminal_snapshot_identity() -> None:
    async def scenario() -> None:
        store = InMemoryRecoveryRunStore()
        request, snapshot, created = await _terminal_recovery(store)

        class Service:
            async def launch_and_wait_result(self, received):
                assert received == request
                return RecoveryRunLaunchResult(snapshot=snapshot, created=created)

        handler = HostedRecoveryHandler(
            expected_caller_email=CALLER.email,
            service=Service(),
        )
        internal = InternalOperationRequest(
            schema_version=INTERNAL_OPERATION_REQUEST_VERSION,
            request_id="hosted-recover-request-7",
            operation=InternalOperation.RECOVER,
            payload=request.model_dump(mode="json"),
        )
        response = await handler(CALLER, internal)
        receipt = HostedRecoveryReceipt(
            schema_version=HOSTED_RECOVERY_RECEIPT_VERSION,
            run_id=request.run_id,
            request_sha256=canonical_sha256(request),
            snapshot_sha256=canonical_sha256(snapshot),
            created=True,
        )
        assert response.payload == receipt.model_dump(mode="json")
        assert "snapshot" not in response.payload
        assert len(canonical_internal_json_bytes(response)) < 1_024

    asyncio.run(scenario())


def test_recovery_handler_rejects_blind_policy_before_service_contact() -> None:
    async def scenario() -> None:
        request = make_recovery_run_examples()[0].model_copy(
            update={"policy": RecoveryRunPolicy.BLIND_RETRY}
        )

        class Service:
            calls = 0

            async def launch_and_wait_result(self, _received):
                self.calls += 1
                raise AssertionError("blind request reached recovery service")

        service = Service()
        handler = HostedRecoveryHandler(
            expected_caller_email=CALLER.email,
            service=service,
        )
        internal = InternalOperationRequest(
            schema_version=INTERNAL_OPERATION_REQUEST_VERSION,
            request_id="hosted-blind-request-7",
            operation=InternalOperation.RECOVER,
            payload=request.model_dump(mode="json"),
        )

        with pytest.raises(HostedRecoveryGatewayError):
            await handler(CALLER, internal)
        assert service.calls == 0

    asyncio.run(scenario())


@pytest.mark.parametrize(
    "fault",
    tuple(
        fault for fault in RecoveryRunFault if fault is not RecoveryRunFault.NO_FAULT
    ),
)
def test_production_recovery_handler_rejects_every_fault(
    fault: RecoveryRunFault,
) -> None:
    async def scenario() -> None:
        request = make_recovery_run_examples()[0].model_copy(
            update={
                "run_id": f"p5w-fixed-{'a' * 32}",
                "fault": fault,
                "policy": RecoveryRunPolicy.FIXED,
            }
        )

        class Service:
            calls = 0

            async def launch_and_wait_result(self, _received):
                self.calls += 1
                raise AssertionError("production fault reached recovery service")

        service = Service()
        handler = HostedRecoveryHandler(
            expected_caller_email=CALLER.email,
            service=service,
            operating_profile="production",
        )
        internal = InternalOperationRequest(
            schema_version=INTERNAL_OPERATION_REQUEST_VERSION,
            request_id="hosted-production-recover-request-7",
            operation=InternalOperation.RECOVER,
            payload=request.model_dump(mode="json"),
        )

        with pytest.raises(HostedRecoveryGatewayError):
            await handler(CALLER, internal)
        assert service.calls == 0

    asyncio.run(scenario())


@pytest.mark.parametrize(
    "fault",
    tuple(
        fault for fault in RecoveryRunFault if fault is not RecoveryRunFault.NO_FAULT
    ),
)
def test_production_recovery_gateway_rejects_every_fault(
    monkeypatch: pytest.MonkeyPatch,
    fault: RecoveryRunFault,
) -> None:
    async def scenario() -> None:
        request = make_recovery_run_examples()[0].model_copy(
            update={
                "run_id": f"p5w-fixed-{'a' * 32}",
                "fault": fault,
                "policy": RecoveryRunPolicy.FIXED,
            }
        )
        transport = HostedHttpTransport()
        calls = 0

        async def send(*_args, **_kwargs):
            nonlocal calls
            calls += 1
            raise AssertionError("production fault reached controller transport")

        monkeypatch.setattr(transport, "request", send)
        gateway = HostedRecoveryRunGateway(
            replace(_api_config(), operating_profile="production"),
            transport,
            InMemoryRecoveryRunStore(),
        )

        with pytest.raises(HostedRecoveryGatewayError):
            await gateway.launch_and_wait_result(request)
        assert calls == 0

    asyncio.run(scenario())


def test_recovery_gateway_rereads_and_verifies_the_firestore_snapshot(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def scenario() -> None:
        store = InMemoryRecoveryRunStore()
        request, snapshot, _created = await _terminal_recovery(store)
        transport = HostedHttpTransport()
        calls: list[tuple[str, str, str]] = []

        async def send(method, url, *, audience, content=b""):
            calls.append((method, url, audience))
            internal = decode_contract(content, InternalOperationRequest)
            assert internal.operation is InternalOperation.RECOVER
            assert internal.payload == request.model_dump(mode="json")
            receipt = HostedRecoveryReceipt(
                schema_version=HOSTED_RECOVERY_RECEIPT_VERSION,
                run_id=request.run_id,
                request_sha256=canonical_sha256(request),
                snapshot_sha256=canonical_sha256(snapshot),
                created=True,
            )
            response = InternalOperationResponse(
                schema_version=INTERNAL_OPERATION_RESPONSE_VERSION,
                request_id=internal.request_id,
                operation=internal.operation,
                accepted=True,
                payload=receipt.model_dump(mode="json"),
            )
            return HostedHttpResponse(
                status_code=HTTPStatus.OK,
                content=canonical_internal_json_bytes(response),
            )

        monkeypatch.setattr(transport, "request", send)
        gateway = HostedRecoveryRunGateway(_api_config(), transport, store)
        result = await gateway.launch_and_wait_result(request)

        assert result == RecoveryRunLaunchResult(snapshot=snapshot, created=True)
        assert calls == [
            (
                "POST",
                "https://controller.example.test/internal/v1/recovery-runs",
                "https://reconcile.invalid/phase5/controller",
            )
        ]

    asyncio.run(scenario())


def test_recovery_gateway_fails_closed_when_receipt_differs_from_firestore(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def scenario() -> None:
        store = InMemoryRecoveryRunStore()
        request, _snapshot, _created = await _terminal_recovery(store)
        transport = HostedHttpTransport()

        async def send(_method, _url, *, audience, content=b""):
            del audience
            internal = decode_contract(content, InternalOperationRequest)
            receipt = HostedRecoveryReceipt(
                schema_version=HOSTED_RECOVERY_RECEIPT_VERSION,
                run_id=request.run_id,
                request_sha256=canonical_sha256(request),
                snapshot_sha256="9" * 64,
                created=True,
            )
            response = InternalOperationResponse(
                schema_version=INTERNAL_OPERATION_RESPONSE_VERSION,
                request_id=internal.request_id,
                operation=internal.operation,
                accepted=True,
                payload=receipt.model_dump(mode="json"),
            )
            return HostedHttpResponse(
                status_code=HTTPStatus.OK,
                content=canonical_internal_json_bytes(response),
            )

        monkeypatch.setattr(transport, "request", send)
        gateway = HostedRecoveryRunGateway(_api_config(), transport, store)
        with pytest.raises(HostedRecoveryGatewayError) as captured:
            await gateway.launch_and_wait_result(request)
        assert captured.value.__cause__ is None

    asyncio.run(scenario())


def test_recovery_gateway_preserves_durable_identity_conflicts(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def scenario() -> None:
        request = make_recovery_run_examples()[0]
        transport = HostedHttpTransport()

        async def send(_method, _url, *, audience, content=b""):
            del audience, content
            return HostedHttpResponse(
                status_code=HTTPStatus.CONFLICT,
                content=b'{"code":"operation-conflict"}',
            )

        monkeypatch.setattr(transport, "request", send)
        gateway = HostedRecoveryRunGateway(
            _api_config(),
            transport,
            InMemoryRecoveryRunStore(),
        )
        with pytest.raises(RecoveryRunConflict) as captured:
            await gateway.launch_and_wait_result(request)
        assert captured.value.run_id == request.run_id

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
