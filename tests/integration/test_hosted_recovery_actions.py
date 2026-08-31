"""Hosted action routes claim each recovery authority exactly once."""

from __future__ import annotations

import asyncio
from datetime import timedelta

import httpx
import pytest
from fastapi import FastAPI, Request

from reconcile.adapters.cloud_run import (
    CLOUD_RUN_HEALTH_CAPABILITY,
    CLOUD_RUN_REVISION_CAPABILITY,
    CLOUD_RUN_SERVICE_CAPABILITY,
)
from reconcile.contracts import (
    RECOVERY_ACTION_SCOPE_VERSION,
    RECOVERY_LAUNCH_PERMIT_VERSION,
    RECOVERY_RUN_REQUEST_VERSION,
    ActionPermitState,
    AmbiguityWitness,
    Classification,
    ProbeOutcome,
    RecoveryActionScope,
    RecoveryAuthorityKind,
    RecoveryLaunchPermit,
    RecoveryLaunchPermitState,
    RecoveryNodeProgress,
    RecoveryNodeState,
    RecoveryReceiptOutcome,
    RecoveryRunEventPayload,
    RecoveryRunEventType,
    RecoveryRunFault,
    RecoveryRunLifecycle,
    RecoveryRunPolicy,
    RecoveryRunRequest,
)
from reconcile.contracts.codec import canonical_sha256, decode_contract
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
from reconcile.hosted.recovery_acceptance import HostedRecoveryAcceptanceObserver
from reconcile.hosted.recovery_dispatch import HostedRecoveryDispatchGateway
from reconcile.hosted.transport import HostedHttpTransport
from reconcile.persistence import InMemoryRecoveryRunStore, SqliteDurableRuntimeStore
from reconcile.recovery_agents import RecoveryAgent
from reconcile.recovery_scenario import (
    ReleaseChainActionPreparer,
    ReleaseChainResetter,
    build_release_chain_definition,
    build_release_chain_workflow,
)
from reconcile.recovery_workflow import RecoveryRunApplicationService
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
            transport = HostedHttpTransport(
                token_supplier=lambda _audience: "e30.e30.sig",
                http_client=recording,
            )
            gateway = HostedRecoveryDispatchGateway(
                fault_proxy_url="https://fault.example.test",
                fault_proxy_audience="https://fault.example.test",
                transport=transport,
                recovery_store=store,
                permit_authority=authority,
                observer=HostedRecoveryAcceptanceObserver(
                    fault_proxy_url="https://fault.example.test",
                    fault_proxy_audience="https://fault.example.test",
                    transport=transport,
                    recovery_store=store,
                ),
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
        True,
        True,
        False,
        True,
    ]
    assert snapshot.dispatch_receipts[2].outcome is (
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


def test_partial_read_outage_produces_a_replay_stable_ambiguity_witness(
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
        SqliteDurableRuntimeStore(tmp_path / "partial-read-outage.sqlite3"),
        clock=lambda: NOW + timedelta(seconds=2),
    )
    cloud_authorizer = RecoveryCloudRunCanaryActionAuthorizer(
        recovery_store=store,
        permit_authority=authority,
        target=cloud_adapter.target,
        acceptance_partial_read_outage_enabled=True,
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
            transport = HostedHttpTransport(
                token_supplier=lambda _audience: "e30.e30.sig",
                http_client=recording,
            )
            gateway = HostedRecoveryDispatchGateway(
                fault_proxy_url="https://fault.example.test",
                fault_proxy_audience="https://fault.example.test",
                transport=transport,
                recovery_store=store,
                permit_authority=authority,
                observer=HostedRecoveryAcceptanceObserver(
                    fault_proxy_url="https://fault.example.test",
                    fault_proxy_audience="https://fault.example.test",
                    transport=transport,
                    recovery_store=store,
                ),
            )
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
                acceptance_partial_read_outage_enabled=True,
                clock=lambda: NOW + timedelta(seconds=2),
            )
            service = RecoveryRunApplicationService(
                workflow,
                store,
                clock=lambda: NOW + timedelta(seconds=2),
            )
            request = RecoveryRunRequest(
                schema_version=RECOVERY_RUN_REQUEST_VERSION,
                run_id=f"p5w-fixed-{'0' * 32}",
                scenario="cloud-run-rollout",
                policy=RecoveryRunPolicy.FIXED,
                fault=(
                    RecoveryRunFault.ACCEPTANCE_DROP_AFTER_ACCEPT_PARTIAL_READ_OUTAGE
                ),
            )
            first = await service.launch_and_wait_result(request)
            provider_counts = (
                cloud_state.update_count,
                cloud_state.service_read_count,
                cloud_state.revision_read_count,
                cloud_state.health_read_count,
            )
            request_count = len(recording.requests)
            replayed = await service.launch_and_wait_result(request)
            await service.aclose()

            direct_revision = cloud_reader.read_revision(
                release_id=settings.release_id,
                revision=settings.staged_revision,
            )
            direct_health = cloud_reader.read_health(
                release_id=settings.release_id,
                revision=settings.staged_revision,
            )
            reset = await ReleaseChainResetter(
                settings=settings,
                cloud_action=cloud_proxy,
                cloud_reader=cloud_reader,
                firestore=firestore,
                baseline_revision=BASELINE,
                clock=lambda: NOW + timedelta(seconds=3),
                poll_interval_seconds=0,
            ).reset()
            return (
                first,
                replayed,
                tuple(recording.requests),
                provider_counts,
                request_count,
                direct_revision,
                direct_health,
                reset,
            )

    (
        first,
        replayed,
        requests,
        provider_counts,
        request_count,
        direct_revision,
        direct_health,
        reset,
    ) = asyncio.run(exercise())
    snapshot = first.snapshot
    replay_snapshot = replayed.snapshot
    witness = snapshot.witnesses[0]
    stage_report = snapshot.reports[-1]
    cloud_requests = tuple(
        content
        for url, content in requests
        if url.endswith(CLOUD_RUN_CANARY_ACTION_PATH)
    )

    assert first.created is True
    assert replayed.created is False
    assert replay_snapshot == snapshot
    assert canonical_sha256(replay_snapshot.witnesses[0]) == canonical_sha256(witness)
    assert snapshot.lifecycle is RecoveryRunLifecycle.ESCALATED
    assert snapshot.decision.value == "ESCALATE"
    assert len(snapshot.reports) == 2
    assert tuple(len(report.probe_audit) for report in snapshot.reports) == (1, 3)
    assert type(witness) is AmbiguityWitness
    assert witness.report_sha256 == canonical_sha256(stage_report)
    assert len(witness.possible_histories) == 2
    assert {history.history_id for history in witness.possible_histories} == {
        "effects-occurred",
        "effects-not-occurred",
    }
    assert (
        len({canonical_sha256(history) for history in witness.possible_histories}) == 2
    )
    evidence_ids = {binding.evidence_id for binding in witness.evidence}
    assert all(
        set(history.compatible_evidence_ids) <= evidence_ids
        for history in witness.possible_histories
    )
    assert stage_report.classification is Classification.UNKNOWN
    assert snapshot.certificates == ()
    assert snapshot.action_permits == ()
    assert [node.state for node in snapshot.nodes] == [
        RecoveryNodeState.ESCALATED,
        RecoveryNodeState.WAITING,
        RecoveryNodeState.WAITING,
    ]
    assert tuple(item.capability_name for item in stage_report.probe_audit) == (
        CLOUD_RUN_SERVICE_CAPABILITY,
        CLOUD_RUN_REVISION_CAPABILITY,
        CLOUD_RUN_HEALTH_CAPABILITY,
    )
    assert tuple(item.outcome for item in stage_report.probe_audit) == (
        ProbeOutcome.COMPLETED,
        ProbeOutcome.UNAVAILABLE,
        ProbeOutcome.UNAVAILABLE,
    )
    assert provider_counts == (1, 2, 0, 0)
    assert len(cloud_requests) == 2
    assert cloud_requests[0] == cloud_requests[1]
    assert request_count == len(requests) == 2
    assert sum(receipt.provider_contact for receipt in snapshot.dispatch_receipts) == 1
    assert tuple(
        (receipt.outcome, receipt.provider_contact)
        for receipt in snapshot.dispatch_receipts
    ) == (
        (RecoveryReceiptOutcome.PROVIDER_CONTACTED, True),
        (RecoveryReceiptOutcome.REJECTED_BEFORE_PROVIDER_CONTACT, False),
    )
    assert snapshot.launch_permit is not None
    assert snapshot.launch_permit.state is RecoveryLaunchPermitState.COMPLETED
    assert snapshot.launch_permit.outcome.value == "OUTCOME_UNKNOWN"
    assert firestore_client.document("releases", settings.release_id).create_count == 0
    assert direct_revision.revision == settings.staged_revision
    assert direct_health.revision == settings.staged_revision
    assert reset.serving_revision == BASELINE
    assert reset.serving_percent == 100
    assert reset.release_record_absent is True


def test_acceptance_stage_replay_is_denied_before_a_second_provider_call(
    tmp_path,
) -> None:
    settings = _settings()
    cloud_state, cloud_adapter, cloud_proxy, _reader, _firestore, _client = _provider(
        settings
    )
    store = InMemoryRecoveryRunStore()
    authority = PermitAuthority(
        SqliteDurableRuntimeStore(tmp_path / "acceptance-replay.sqlite3"),
        clock=lambda: NOW + timedelta(seconds=2),
    )
    authorizer = RecoveryCloudRunCanaryActionAuthorizer(
        recovery_store=store,
        permit_authority=authority,
        target=cloud_adapter.target,
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
        action_authorizer=authorizer,
        expected_caller_email=CALLER,
        expected_image_digest=settings.image_digest,
        expected_configuration_sha256=settings.configuration_sha256,
    )

    async def exercise():
        run_id = f"p5r-fixed-{'0' * 32}"
        request = RecoveryRunRequest(
            schema_version=RECOVERY_RUN_REQUEST_VERSION,
            run_id=run_id,
            scenario="cloud-run-rollout",
            policy=RecoveryRunPolicy.FIXED,
            fault=RecoveryRunFault.NO_FAULT,
        )
        definition = build_release_chain_definition(settings, invoked_at=NOW)
        stage = definition.chain.nodes[0]
        prepared = ReleaseChainActionPreparer().prepare(
            request,
            definition.chain,
            stage,
            stage,
            None,
            None,
        )
        launch = RecoveryLaunchPermit(
            schema_version=RECOVERY_LAUNCH_PERMIT_VERSION,
            launch_permit_id="launch-permit-acceptance-replay",
            run_id=run_id,
            node_id=stage.node_id,
            semantic_action_sha256=stage.semantic_action.semantic_action_sha256,
            action_request_sha256=prepared.action_request_sha256,
            issued_at=NOW,
            state=RecoveryLaunchPermitState.ISSUED,
            revision=0,
        )
        snapshot, _created = await store.create(
            request,
            definition.chain,
            created_at=NOW,
        )
        for event_type, payload in (
            (
                RecoveryRunEventType.LIFECYCLE,
                RecoveryRunEventPayload(lifecycle=RecoveryRunLifecycle.RUNNING),
            ),
            (
                RecoveryRunEventType.LAUNCH_PERMIT,
                RecoveryRunEventPayload(launch_permit=launch),
            ),
            (
                RecoveryRunEventType.NODE,
                RecoveryRunEventPayload(
                    node=RecoveryNodeProgress(
                        node_id=stage.node_id,
                        state=RecoveryNodeState.DISPATCH_PENDING,
                        attempt=1,
                    )
                ),
            ),
        ):
            snapshot = await store.append(
                run_id,
                expected_revision=snapshot.revision,
                event_type=event_type,
                payload=payload,
                occurred_at=NOW,
            )
        scope = RecoveryActionScope(
            schema_version=RECOVERY_ACTION_SCOPE_VERSION,
            authority_kind=RecoveryAuthorityKind.LAUNCH_PERMIT,
            run_id=run_id,
            source_node_id=stage.node_id,
            target_node_id=stage.node_id,
            semantic_action_sha256=stage.semantic_action.semantic_action_sha256,
            action_request_sha256=prepared.action_request_sha256,
            authority_id=launch.launch_permit_id,
            authority_sha256=canonical_sha256(launch),
            claim_id="claim-acceptance-replay",
        )
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=application),
            base_url="https://fault.example.test",
        ) as client:
            recording = _RecordingHttpClient(client)
            transport = HostedHttpTransport(
                token_supplier=lambda _audience: "e30.e30.sig",
                http_client=recording,
            )
            gateway = HostedRecoveryDispatchGateway(
                fault_proxy_url="https://fault.example.test",
                fault_proxy_audience="https://fault.example.test",
                transport=transport,
                recovery_store=store,
                permit_authority=authority,
                observer=HostedRecoveryAcceptanceObserver(
                    fault_proxy_url="https://fault.example.test",
                    fault_proxy_audience="https://fault.example.test",
                    transport=transport,
                    recovery_store=store,
                ),
            )
            dispatch = await gateway.dispatch(prepared, scope)
            resumed = await gateway.dispatch(prepared, scope)
        return dispatch, resumed, await store.get(run_id), recording.requests

    dispatch, resumed, snapshot, requests = asyncio.run(exercise())
    cloud_requests = tuple(
        content
        for url, content in requests
        if url.endswith(CLOUD_RUN_CANARY_ACTION_PATH)
    )

    assert dispatch.outcome.value == "SUCCEEDED"
    assert resumed == dispatch
    assert cloud_state.update_count == 1
    assert len(cloud_requests) == 3
    assert cloud_requests[0] == cloud_requests[1] == cloud_requests[2]
    assert tuple(
        (receipt.outcome, receipt.provider_contact)
        for receipt in snapshot.dispatch_receipts
    ) == (
        (RecoveryReceiptOutcome.PROVIDER_CONTACTED, True),
        (RecoveryReceiptOutcome.REJECTED_BEFORE_PROVIDER_CONTACT, False),
    )
