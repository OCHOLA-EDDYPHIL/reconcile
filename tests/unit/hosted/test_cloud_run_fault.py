from __future__ import annotations

import socket
import threading
import time
from collections.abc import Collection
from datetime import UTC, datetime

import httpx
import pytest
import uvicorn
from fastapi.testclient import TestClient
from google.cloud import run_v2

from reconcile.contracts.codec import canonical_json_bytes, decode_contract
from reconcile.hosted.apps import create_component_app
from reconcile.hosted.cloud_run_canary import (
    CloudRunCanaryAction,
    CloudRunCanaryActionAdapter,
    CloudRunCanaryFaultProxy,
    CloudRunCanaryTarget,
    CloudRunFaultMode,
)
from reconcile.hosted.cloud_run_fault import (
    CLOUD_RUN_CANARY_ACTION_PATH,
    CLOUD_RUN_CANARY_ACTION_REQUEST_VERSION,
    ClosedCloudRunCanaryActionAuthorizer,
    CloudRunCanaryActionRequest,
    CloudRunCanaryActionResponse,
    cloud_run_release_id,
)
from reconcile.hosted.config import Component, HostedConfig
from reconcile.hosted.identity import IdentityVerificationError, VerifiedCaller
from reconcile.hosted.workflow import (
    HOSTED_OPERATION_SCOPE_VERSION,
    HostedOperationScope,
    HostedWorkflowOperation,
)

pytestmark = pytest.mark.unit

PROJECT = "example-project-id"
CALLER = f"rec-p5-api@{PROJECT}.iam.gserviceaccount.com"
SERVICE = "reconcile-p5-canary"
BASELINE = f"{SERVICE}-baseline"
DIGEST = f"sha256:{'a' * 64}"
CONFIGURATION = "b" * 64
OPERATION = f"projects/{PROJECT}/locations/us-central1/operations/op-7"
NOW = datetime(2026, 8, 22, 12, 0, tzinfo=UTC)


class _Verifier:
    def verify(
        self,
        authorization_header: str | None,
        expected_audience: str,
        allowed_emails: Collection[str],
    ) -> VerifiedCaller:
        if (
            authorization_header != "Bearer hdr.caller.sig"
            or CALLER not in allowed_emails
        ):
            raise IdentityVerificationError
        return VerifiedCaller(
            email=CALLER,
            subject="api-subject",
            issuer="https://accounts.google.com",
            audience=expected_audience,
            expires_at=2**31,
        )


class _Operation:
    name = OPERATION


class _Services:
    def __init__(self) -> None:
        self.updates: list[run_v2.UpdateServiceRequest] = []

    def get_service(self, **_: object) -> run_v2.Service:
        return run_v2.Service(
            name=f"projects/{PROJECT}/locations/us-central1/services/{SERVICE}",
            etag="etag-7",
            terminal_condition=run_v2.Condition(
                type_="Ready",
                state=run_v2.Condition.State.CONDITION_SUCCEEDED,
            ),
            template=run_v2.RevisionTemplate(
                containers=(
                    run_v2.Container(
                        image=(
                            f"us-central1-docker.pkg.dev/{PROJECT}/"
                            f"reconcile-p5/reconcile@{DIGEST}"
                        )
                    ),
                )
            ),
            traffic_statuses=(
                run_v2.TrafficTargetStatus(revision=BASELINE, percent=100),
            ),
        )

    def update_service(self, **kwargs: object) -> _Operation:
        self.updates.append(kwargs["request"])  # type: ignore[arg-type]
        return _Operation()


class _Revisions:
    pass


class _Authorizer:
    def __init__(self, *, denied: bool = False) -> None:
        self.denied = denied
        self.calls: list[HostedOperationScope] = []

    async def __call__(self, request: CloudRunCanaryActionRequest) -> None:
        self.calls.append(request.scope)
        if self.denied:
            raise RuntimeError("private authority detail")


def _config() -> HostedConfig:
    return HostedConfig(
        component=Component.FAULT_PROXY,
        port=8080,
        project_id=PROJECT,
        auth_audience=(f"https://reconcile.invalid/phase5/{PROJECT}/fault-proxy"),
        allowed_caller_emails=(CALLER,),
        source_revision="c" * 40,
        image_digest=DIGEST,
        infra_revision="d" * 64,
        semantic_config_sha256=CONFIGURATION,
        canary_location="us-central1",
        canary_service=SERVICE,
        canary_baseline_revision=BASELINE,
        canary_audience=f"https://reconcile.invalid/phase5/{PROJECT}/canary",
        recovery_action_caller_email=CALLER,
    )


def _application(services: _Services, authorizer: object | None = None):
    target = CloudRunCanaryTarget(
        project=PROJECT,
        location="us-central1",
        service=SERVICE,
        image_repository=(
            f"us-central1-docker.pkg.dev/{PROJECT}/reconcile-p5/reconcile"
        ),
        baseline_revision=BASELINE,
        health_audience=f"https://reconcile.invalid/phase5/{PROJECT}/canary",
    )
    adapter = CloudRunCanaryActionAdapter(
        target=target,
        services_factory=lambda: services,
        revisions_factory=_Revisions,
        clock=lambda: NOW,
    )
    return create_component_app(
        _config(),
        verifier=_Verifier(),
        cloud_run_canary_fault_proxy=CloudRunCanaryFaultProxy(adapter),
        cloud_run_canary_action_authorizer=authorizer or _Authorizer(),
    )


def _scope() -> HostedOperationScope:
    return HostedOperationScope(
        schema_version=HOSTED_OPERATION_SCOPE_VERSION,
        operation=HostedWorkflowOperation.EXECUTE_FAULT,
        launch_id="launch-7",
        launch_sha256="1" * 64,
        scenario_request_sha256="2" * 64,
        investigation_id="investigation-7",
        operation_id="operation-7",
        invocation_id="invocation-7",
        function_call_id="call-7",
        envelope_sha256="3" * 64,
        cleanup_manifest_sha256="4" * 64,
        lease_fence=1,
    )


def _request(mode: CloudRunFaultMode) -> CloudRunCanaryActionRequest:
    scope = _scope()
    return CloudRunCanaryActionRequest(
        schema_version=CLOUD_RUN_CANARY_ACTION_REQUEST_VERSION,
        request_id="request-7",
        action=CloudRunCanaryAction.STAGE,
        fault_mode=mode,
        operation_id="operation-7",
        release_id=cloud_run_release_id(scope),
        image_digest=DIGEST,
        configuration_sha256=CONFIGURATION,
        scope=scope,
    )


HEADERS = {
    "Authorization": "Bearer hdr.caller.sig",
    "Content-Type": "application/json",
    "X-Serverless-Authorization": "Bearer e30.e30.",
}


def test_hosted_fault_proxy_route_returns_exact_provider_acceptance() -> None:
    services = _Services()
    authorizer = _Authorizer()
    response = TestClient(_application(services, authorizer)).post(
        CLOUD_RUN_CANARY_ACTION_PATH,
        content=canonical_json_bytes(_request(CloudRunFaultMode.PASS_THROUGH)),
        headers=HEADERS,
    )

    assert response.status_code == 200
    receipt = decode_contract(response.content, CloudRunCanaryActionResponse)
    assert receipt.request_id == "request-7"
    assert receipt.operation_name == OPERATION
    assert receipt.accepted_at == NOW
    assert len(services.updates) == 1
    assert authorizer.calls == [_scope()]


def test_hosted_drop_occurs_after_provider_acceptance_and_hides_receipt() -> None:
    services = _Services()
    application = _application(services)
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.bind(("127.0.0.1", 0))
    listener.listen()
    port = listener.getsockname()[1]
    server = uvicorn.Server(
        uvicorn.Config(
            application,
            log_level="critical",
            access_log=False,
            lifespan="off",
        )
    )
    thread = threading.Thread(
        target=server.run,
        kwargs={"sockets": [listener]},
        daemon=True,
    )
    thread.start()
    deadline = time.monotonic() + 5
    while not server.started and thread.is_alive() and time.monotonic() < deadline:
        time.sleep(0.01)
    try:
        assert server.started
        with httpx.Client(timeout=5, trust_env=False) as client:
            with pytest.raises(httpx.RemoteProtocolError) as raised:
                client.post(
                    f"http://127.0.0.1:{port}{CLOUD_RUN_CANARY_ACTION_PATH}",
                    content=canonical_json_bytes(
                        _request(CloudRunFaultMode.DROP_AFTER_ACCEPT)
                    ),
                    headers=HEADERS,
                )
    finally:
        server.should_exit = True
        thread.join(timeout=5)
        listener.close()

    assert not thread.is_alive()
    assert len(services.updates) == 1
    assert OPERATION not in str(raised.value)


def test_canary_mutation_route_is_not_available_on_other_components() -> None:
    config = _config()
    api_config = HostedConfig(
        component=Component.API,
        port=config.port,
        project_id=config.project_id,
        auth_audience=f"https://reconcile.invalid/phase5/{PROJECT}/api",
        allowed_caller_emails=config.allowed_caller_emails,
        source_revision=config.source_revision,
        image_digest=config.image_digest,
        infra_revision=config.infra_revision,
        semantic_config_sha256=config.semantic_config_sha256,
    )
    target = CloudRunCanaryTarget(
        project=PROJECT,
        location="us-central1",
        service=SERVICE,
        image_repository=(
            f"us-central1-docker.pkg.dev/{PROJECT}/reconcile-p5/reconcile"
        ),
        baseline_revision=BASELINE,
        health_audience=f"https://reconcile.invalid/phase5/{PROJECT}/canary",
    )
    with pytest.raises(ValueError, match="only the fault proxy"):
        create_component_app(
            api_config,
            cloud_run_canary_fault_proxy=CloudRunCanaryFaultProxy(
                CloudRunCanaryActionAdapter(target=target)
            ),
            cloud_run_canary_action_authorizer=_Authorizer(),
        )


def test_hosted_route_requires_live_scope_and_server_bound_candidate() -> None:
    services = _Services()
    denied = _Authorizer(denied=True)
    response = TestClient(_application(services, denied)).post(
        CLOUD_RUN_CANARY_ACTION_PATH,
        content=canonical_json_bytes(_request(CloudRunFaultMode.PASS_THROUGH)),
        headers=HEADERS,
    )
    assert response.status_code == 403
    assert response.json() == {"code": "operation-denied"}
    assert len(denied.calls) == 1
    assert services.updates == []

    for update in (
        {"image_digest": f"sha256:{'e' * 64}"},
        {"release_id": "release-unbound"},
    ):
        mismatched = _request(CloudRunFaultMode.PASS_THROUGH).model_copy(update=update)
        response = TestClient(_application(services)).post(
            CLOUD_RUN_CANARY_ACTION_PATH,
            content=canonical_json_bytes(mismatched),
            headers=HEADERS,
        )
        assert response.status_code == 403
        assert response.json() == {"code": "operation-denied"}
    assert services.updates == []


def test_deployed_closed_authority_makes_zero_provider_calls() -> None:
    services = _Services()
    response = TestClient(
        _application(services, ClosedCloudRunCanaryActionAuthorizer())
    ).post(
        CLOUD_RUN_CANARY_ACTION_PATH,
        content=canonical_json_bytes(_request(CloudRunFaultMode.PASS_THROUGH)),
        headers=HEADERS,
    )

    assert response.status_code == 403
    assert response.json() == {"code": "operation-denied"}
    assert services.updates == []
