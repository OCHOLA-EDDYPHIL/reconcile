"""Cloud Run mutation claims recovery authority before provider contact."""

from __future__ import annotations

import asyncio
from datetime import timedelta

import pytest

from reconcile.contracts import (
    RECOVERY_ACTION_SCOPE_VERSION,
    RECOVERY_LAUNCH_PERMIT_VERSION,
    RECOVERY_RUN_REQUEST_VERSION,
    RecoveryActionScope,
    RecoveryAuthorityKind,
    RecoveryDecision,
    RecoveryDispatchOutcome,
    RecoveryLaunchPermit,
    RecoveryLaunchPermitState,
    RecoveryNodeProgress,
    RecoveryNodeState,
    RecoveryRunEventPayload,
    RecoveryRunEventType,
    RecoveryRunFault,
    RecoveryRunLifecycle,
    RecoveryRunPolicy,
    RecoveryRunRequest,
    canonical_sha256,
)
from reconcile.controller.permits import PermitAuthority
from reconcile.hosted.cloud_run_canary import CloudRunCanaryAction, CloudRunFaultMode
from reconcile.hosted.cloud_run_fault import (
    CLOUD_RUN_CANARY_ACTION_REQUEST_VERSION,
    CloudRunCanaryActionRequest,
    RecoveryCloudRunCanaryActionAuthorizer,
    cloud_run_action_request_sha256,
)
from reconcile.persistence import InMemoryRecoveryRunStore, SqliteDurableRuntimeStore
from tests.unit.evidence.test_recovery_verification import (
    CONFIGURATION_SHA256,
    IMAGE_DIGEST,
    NOW,
    RELEASE_ID,
    REVISION,
    _chain,
    _verify,
)
from tests.unit.hosted.test_cloud_run_fault import _request as legacy_request

pytestmark = pytest.mark.unit


def _run_request(run_id: str) -> RecoveryRunRequest:
    return RecoveryRunRequest(
        schema_version=RECOVERY_RUN_REQUEST_VERSION,
        run_id=run_id,
        scenario="cloud-run-rollout",
        policy=RecoveryRunPolicy.ADAPTIVE,
        fault=RecoveryRunFault.DROP_AFTER_ACCEPT,
    )


def _provisional_scope(
    *,
    run_id: str,
    source_node_id: str,
    target_node_id: str,
    semantic_action_sha256: str,
    authority_kind: RecoveryAuthorityKind,
    authority_id: str,
    permit_action=None,
    certificate_id: str | None = None,
    certificate_sha256: str | None = None,
) -> RecoveryActionScope:
    return RecoveryActionScope(
        schema_version=RECOVERY_ACTION_SCOPE_VERSION,
        authority_kind=authority_kind,
        run_id=run_id,
        source_node_id=source_node_id,
        target_node_id=target_node_id,
        semantic_action_sha256=semantic_action_sha256,
        action_request_sha256="0" * 64,
        authority_id=authority_id,
        authority_sha256="0" * 64,
        claim_id="claim-7",
        permit_action=permit_action,
        certificate_id=certificate_id,
        certificate_sha256=certificate_sha256,
    )


def test_recovery_launch_permit_has_one_claim_winner(tmp_path) -> None:
    chain, _envelopes = _chain()
    request = _run_request("recovery-launch-authority-7")
    node = chain.nodes[0]
    provisional = _provisional_scope(
        run_id=request.run_id,
        source_node_id=node.node_id,
        target_node_id=node.node_id,
        semantic_action_sha256=node.semantic_action.semantic_action_sha256,
        authority_kind=RecoveryAuthorityKind.LAUNCH_PERMIT,
        authority_id="launch-permit-7",
    )
    action = CloudRunCanaryActionRequest(
        schema_version=CLOUD_RUN_CANARY_ACTION_REQUEST_VERSION,
        request_id="request-stage-7",
        action=CloudRunCanaryAction.STAGE,
        fault_mode=CloudRunFaultMode.DROP_AFTER_ACCEPT,
        operation_id=node.envelope.operation_id,
        release_id=RELEASE_ID,
        image_digest=IMAGE_DIGEST,
        configuration_sha256=CONFIGURATION_SHA256,
        scope=provisional,
    )
    action_sha256 = cloud_run_action_request_sha256(action)
    launch = RecoveryLaunchPermit(
        schema_version=RECOVERY_LAUNCH_PERMIT_VERSION,
        launch_permit_id="launch-permit-7",
        run_id=request.run_id,
        node_id=node.node_id,
        semantic_action_sha256=node.semantic_action.semantic_action_sha256,
        action_request_sha256=action_sha256,
        issued_at=NOW,
        state=RecoveryLaunchPermitState.ISSUED,
        revision=0,
    )
    scope = provisional.model_copy(
        update={
            "action_request_sha256": action_sha256,
            "authority_sha256": canonical_sha256(launch),
        }
    )
    action = action.model_copy(update={"scope": scope})
    store = InMemoryRecoveryRunStore()
    permit_authority = PermitAuthority(
        SqliteDurableRuntimeStore(tmp_path / "unused-authority.sqlite3"),
        clock=lambda: NOW + timedelta(seconds=1),
    )
    authorizer = RecoveryCloudRunCanaryActionAuthorizer(
        recovery_store=store,
        permit_authority=permit_authority,
        clock=lambda: NOW + timedelta(seconds=1),
    )

    async def exercise():
        snapshot, _created = await store.create(request, chain, created_at=NOW)
        snapshot = await store.append(
            request.run_id,
            expected_revision=snapshot.revision,
            event_type=RecoveryRunEventType.LIFECYCLE,
            payload=RecoveryRunEventPayload(lifecycle=RecoveryRunLifecycle.RUNNING),
            occurred_at=NOW,
        )
        snapshot = await store.append(
            request.run_id,
            expected_revision=snapshot.revision,
            event_type=RecoveryRunEventType.LAUNCH_PERMIT,
            payload=RecoveryRunEventPayload(launch_permit=launch),
            occurred_at=NOW,
        )
        await store.append(
            request.run_id,
            expected_revision=snapshot.revision,
            event_type=RecoveryRunEventType.NODE,
            payload=RecoveryRunEventPayload(
                node=RecoveryNodeProgress(
                    node_id=node.node_id,
                    state=RecoveryNodeState.DISPATCH_PENDING,
                    attempt=1,
                )
            ),
            occurred_at=NOW,
        )
        return await asyncio.gather(
            authorizer.claim(action),
            authorizer.claim(action),
            return_exceptions=True,
        )

    results = asyncio.run(exercise())
    leases = [item for item in results if not isinstance(item, BaseException)]
    denied = [item for item in results if isinstance(item, BaseException)]
    assert len(leases) == 1
    assert len(denied) == 1


def test_recovery_authorizer_rejects_legacy_replayable_scope(tmp_path) -> None:
    authorizer = RecoveryCloudRunCanaryActionAuthorizer(
        recovery_store=InMemoryRecoveryRunStore(),
        permit_authority=PermitAuthority(
            SqliteDurableRuntimeStore(tmp_path / "legacy.sqlite3")
        ),
    )
    with pytest.raises(PermissionError, match="legacy"):
        asyncio.run(authorizer.claim(legacy_request(CloudRunFaultMode.PASS_THROUGH)))


def test_certificate_bound_promotion_rejects_tampering_before_claim(tmp_path) -> None:
    certificate, _evaluation, report, chain, _envelope = _verify(
        node_id="stage",
        kind="committed",
    )
    assert certificate.transition is not None
    request = _run_request("recovery-promotion-authority-7")
    store = InMemoryRecoveryRunStore()
    permit_authority = PermitAuthority(
        SqliteDurableRuntimeStore(tmp_path / "promotion.sqlite3"),
        clock=lambda: NOW + timedelta(seconds=7),
    )
    permit = asyncio.run(permit_authority.issue_permit(certificate))
    assert permit is not None
    target = chain.nodes[1]
    provisional = _provisional_scope(
        run_id=request.run_id,
        source_node_id=certificate.node_id,
        target_node_id=target.node_id,
        semantic_action_sha256=target.semantic_action.semantic_action_sha256,
        authority_kind=RecoveryAuthorityKind.ACTION_PERMIT,
        authority_id=permit.permit_id,
        permit_action=permit.action,
        certificate_id=certificate.certificate_id,
        certificate_sha256=canonical_sha256(certificate),
    )
    action = CloudRunCanaryActionRequest(
        schema_version=CLOUD_RUN_CANARY_ACTION_REQUEST_VERSION,
        request_id="request-promote-7",
        action=CloudRunCanaryAction.PROMOTE,
        fault_mode=CloudRunFaultMode.PASS_THROUGH,
        release_id=RELEASE_ID,
        revision=REVISION,
        service_etag="etag-release-7",
        scope=provisional,
    )
    scope = provisional.model_copy(
        update={
            "action_request_sha256": cloud_run_action_request_sha256(action),
            "authority_sha256": canonical_sha256(permit),
        }
    )
    action = action.model_copy(update={"scope": scope})
    authorizer = RecoveryCloudRunCanaryActionAuthorizer(
        recovery_store=store,
        permit_authority=permit_authority,
        clock=lambda: NOW + timedelta(seconds=7),
    )

    async def exercise():
        snapshot, _created = await store.create(request, chain, created_at=NOW)
        snapshot = await store.append(
            request.run_id,
            expected_revision=snapshot.revision,
            event_type=RecoveryRunEventType.LIFECYCLE,
            payload=RecoveryRunEventPayload(lifecycle=RecoveryRunLifecycle.RUNNING),
            occurred_at=NOW,
        )
        snapshot = await store.append(
            request.run_id,
            expected_revision=snapshot.revision,
            event_type=RecoveryRunEventType.EVIDENCE,
            payload=RecoveryRunEventPayload(report=report),
            occurred_at=NOW + timedelta(seconds=5),
        )
        await store.append(
            request.run_id,
            expected_revision=snapshot.revision,
            event_type=RecoveryRunEventType.DECISION,
            payload=RecoveryRunEventPayload(
                decision=RecoveryDecision.CONTINUE,
                certificate=certificate,
            ),
            occurred_at=NOW + timedelta(seconds=6),
        )
        tampered = action.model_copy(update={"revision": "other-revision"})
        with pytest.raises(PermissionError, match="request"):
            await authorizer.claim(tampered)
        claimed = await authorizer.claim(action)
        return await authorizer.complete(
            claimed,
            RecoveryDispatchOutcome.SUCCEEDED,
        )

    completed = asyncio.run(exercise())
    assert completed.state.value == "COMPLETED"
    assert completed.claim_id == "claim-7"
