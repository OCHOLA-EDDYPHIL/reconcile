"""Hosted action routes claim each recovery authority exactly once."""

from __future__ import annotations

import asyncio
from datetime import timedelta

import httpx
import pytest
from fastapi import FastAPI, Request

from reconcile.contracts import (
    RECOVERY_RUN_REQUEST_VERSION,
    ActionPermitState,
    RecoveryReceiptOutcome,
    RecoveryRunFault,
    RecoveryRunLifecycle,
    RecoveryRunPolicy,
    RecoveryRunRequest,
)
from reconcile.contracts.codec import decode_contract
from reconcile.controller.permits import PermitAuthority
from reconcile.hosted.cloud_run_fault import (
    CLOUD_RUN_CANARY_ACTION_PATH,
    RecoveryCloudRunCanaryActionAuthorizer,
    install_cloud_run_canary_fault_route,
)
from reconcile.hosted.firestore_release_action import (
    FIRESTORE_RELEASE_ACTION_PATH,
    FirestoreReleaseActionRequest,
    RecoveryFirestoreReleaseActionAuthorizer,
    install_firestore_release_action_route,
)
from reconcile.hosted.identity import VerifiedCaller
from reconcile.hosted.recovery_dispatch import HostedRecoveryDispatchGateway
from reconcile.hosted.transport import HostedHttpTransport
from reconcile.persistence import InMemoryRecoveryRunStore, SqliteDurableRuntimeStore
from reconcile.recovery_agents import RecoveryAgent
from reconcile.recovery_scenario import (
    build_release_chain_definition,
    build_release_chain_workflow,
)
from tests.integration.test_recovery_release_chain import (
    BASELINE,
    NOW,
    _output,
    _Planner,
    _provider,
    _settings,
)

pytestmark = pytest.mark.integration

CALLER = "controller@example.test"


class _RecordingHttpClient:
    def __init__(self, delegate: httpx.AsyncClient) -> None:
        self.delegate = delegate
        self.requests: list[tuple[str, bytes]] = []

    def stream(self, method: str, url: str, **kwargs: object):
        content = kwargs.get("content")
        assert type(content) is bytes
        self.requests.append((url, content))
        return self.delegate.stream(method, url, **kwargs)


def test_hosted_suppression_retries_once_without_a_controller_side_claim(
    tmp_path,
) -> None:
    settings = _settings()
    (
        cloud_state,
        cloud_adapter,
        cloud_proxy,
        cloud_reader,
        firestore,
        firestore_client,
    ) = _provider(settings)
    store = InMemoryRecoveryRunStore()
    authority = PermitAuthority(
        SqliteDurableRuntimeStore(tmp_path / "hosted-actions.sqlite3"),
        clock=lambda: NOW + timedelta(seconds=2),
    )
    cloud_authorizer = RecoveryCloudRunCanaryActionAuthorizer(
        recovery_store=store,
        permit_authority=authority,
        target=cloud_adapter.target,
        clock=lambda: NOW + timedelta(seconds=2),
    )
    firestore_authorizer = RecoveryFirestoreReleaseActionAuthorizer(
        recovery_store=store,
        permit_authority=authority,
        target=firestore,
        clock=lambda: NOW + timedelta(seconds=2),
    )
    application = FastAPI()

    @application.middleware("http")
    async def bind_caller(request: Request, call_next):
        request.state.verified_caller = VerifiedCaller(
            email=CALLER,
            subject="controller-subject",
            issuer="https://accounts.google.com",
            audience="https://fault.example.test",
            expires_at=2**31,
        )
        return await call_next(request)

    install_cloud_run_canary_fault_route(
        application,
        proxy=cloud_proxy,
        action_authorizer=cloud_authorizer,
        expected_caller_email=CALLER,
        expected_image_digest=settings.image_digest,
        expected_configuration_sha256=settings.configuration_sha256,
    )
    install_firestore_release_action_route(
        application,
        target=firestore,
        authorizer=firestore_authorizer,
        expected_caller_email=CALLER,
    )

    async def exercise():
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=application),
            base_url="https://fault.example.test",
        ) as client:
            recording = _RecordingHttpClient(client)
            gateway = HostedRecoveryDispatchGateway(
                fault_proxy_url="https://fault.example.test",
                fault_proxy_audience="https://fault.example.test",
                transport=HostedHttpTransport(
                    token_supplier=lambda _audience: "e30.e30.sig",
                    http_client=recording,
                ),
                recovery_store=store,
                permit_authority=authority,
            )
            definition = build_release_chain_definition(settings, invoked_at=NOW)
            workflow = build_release_chain_workflow(
                settings=settings,
                invoked_at=NOW,
                store=store,
                permit_authority=authority,
                recovery_agent=RecoveryAgent(
                    _Planner(output=_output(probe_count=0)),
                    clock=lambda: NOW + timedelta(seconds=2),
                ),
                cloud_action=None,
                cloud_reader=cloud_reader,
                firestore=firestore,
                dispatch_gateway=gateway,
                clock=lambda: NOW + timedelta(seconds=2),
            )
            request = RecoveryRunRequest(
                schema_version=RECOVERY_RUN_REQUEST_VERSION,
                run_id="hosted-suppression-actions",
                scenario="cloud-run-rollout",
                policy=RecoveryRunPolicy.FIXED,
                fault=RecoveryRunFault.SUPPRESS_BEFORE_DISPATCH,
            )
            await store.create(request, definition.chain, created_at=NOW)
            snapshot = await workflow.run(request.run_id)
            firestore_requests = tuple(
                content
                for url, content in recording.requests
                if url.endswith(FIRESTORE_RELEASE_ACTION_PATH)
            )
            assert len(firestore_requests) == 2
            replay = await client.post(
                FIRESTORE_RELEASE_ACTION_PATH,
                content=firestore_requests[-1],
                headers={"Content-Type": "application/json"},
            )
            return snapshot, firestore_requests, replay

    snapshot, firestore_requests, replay = asyncio.run(exercise())
    reference = firestore_client.document("releases", settings.release_id)
    decoded = tuple(
        decode_contract(content, FirestoreReleaseActionRequest)
        for content in firestore_requests
    )

    assert snapshot.lifecycle is RecoveryRunLifecycle.COMPLETED
    assert [item.scope.permit_action.value for item in decoded] == [
        "CONTINUE",
        "RETRY",
    ]
    assert all(item.suppress_before_dispatch for item in decoded)
    assert reference.create_attempt_count == reference.create_count == 1
    assert cloud_state.update_count == 2
    assert [item.provider_contact for item in snapshot.dispatch_receipts] == [
        False,
        True,
    ]
    assert snapshot.dispatch_receipts[0].outcome is (
        RecoveryReceiptOutcome.SUPPRESSED_BEFORE_DISPATCH
    )
    assert all(
        permit.state is ActionPermitState.COMPLETED
        for permit in snapshot.action_permits
    )
    assert replay.status_code == 403
    assert reference.create_attempt_count == 1
    assert cloud_state.service.traffic_statuses[0].revision != BASELINE


def test_cloud_run_and_firestore_action_paths_are_distinct() -> None:
    assert CLOUD_RUN_CANARY_ACTION_PATH != FIRESTORE_RELEASE_ACTION_PATH
