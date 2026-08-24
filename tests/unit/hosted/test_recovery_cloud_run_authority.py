"""Cloud Run mutation claims recovery authority before provider contact."""

from __future__ import annotations

import asyncio
from dataclasses import replace
from datetime import timedelta

import pytest
from fastapi import FastAPI

from reconcile.contracts import (
    RECOVERY_ACTION_SCOPE_VERSION,
    RECOVERY_LAUNCH_PERMIT_VERSION,
    RECOVERY_RUN_REQUEST_VERSION,
    ActionPermitState,
    AdvisoryExplanation,
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
    RecoveryRunFailureCategory,
    RecoveryRunFault,
    RecoveryRunLifecycle,
    RecoveryRunPolicy,
    RecoveryRunRequest,
    VerifiedCertificate,
    canonical_sha256,
)
from reconcile.controller.permits import PermitAuthority, action_permit_from_certificate
from reconcile.evidence.recovery_verification import verify_recovery
from reconcile.hosted.cloud_run_canary import (
    CloudRunCanaryAction,
    CloudRunCanaryActionAdapter,
    CloudRunCanaryFaultProxy,
    CloudRunFaultMode,
)
from reconcile.hosted.cloud_run_fault import (
    CLOUD_RUN_CANARY_ACTION_REQUEST_VERSION,
    CloudRunCanaryActionRequest,
    RecoveryCloudRunCanaryActionAuthorizer,
    cloud_run_action_request_sha256,
    install_cloud_run_canary_fault_route,
)
from reconcile.persistence import InMemoryRecoveryRunStore, SqliteDurableRuntimeStore
from reconcile.persistence.permits import PermitClaimDenied
from tests.unit.evidence.test_recovery_verification import (
    CONFIGURATION_SHA256,
    IMAGE_DIGEST,
    NOW,
    RELEASE_ID,
    REVISION,
    _chain,
    _verify,
)
from tests.unit.hosted.test_cloud_run_canary import _target as canary_target
from tests.unit.hosted.test_cloud_run_fault import _request as legacy_request

pytestmark = pytest.mark.unit


class _PausingPermitStore:
    def __init__(self, delegate) -> None:
        self.delegate = delegate
        self.get_calls = 0
        self.paused = asyncio.Event()
        self.release = asyncio.Event()

    async def issue_permit(self, permit):
        return await self.delegate.issue_permit(permit)

    async def get_permit(self, permit_id):
        self.get_calls += 1
        if self.get_calls == 2:
            self.paused.set()
            await self.release.wait()
        return await self.delegate.get_permit(permit_id)

    async def claim_permit(self, request):
        return await self.delegate.claim_permit(request)

    async def complete_permit(self, request):
        return await self.delegate.complete_permit(request)

    async def permit_audit_events(self, permit_id):
        return await self.delegate.permit_audit_events(permit_id)


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


async def _record_dispatchable_promotion(
    store: InMemoryRecoveryRunStore,
    request: RecoveryRunRequest,
    chain,
    report,
    certificate,
    permit,
) -> None:
    snapshot, _created = await store.create(request, chain, created_at=NOW)
    for event_type, payload, occurred_at in (
        (
            RecoveryRunEventType.LIFECYCLE,
            RecoveryRunEventPayload(lifecycle=RecoveryRunLifecycle.RUNNING),
            NOW,
        ),
        (
            RecoveryRunEventType.NODE,
            RecoveryRunEventPayload(
                node=RecoveryNodeProgress(
                    node_id=certificate.node_id,
                    state=RecoveryNodeState.RECONCILING,
                    attempt=1,
                )
            ),
            NOW,
        ),
        (
            RecoveryRunEventType.EVIDENCE,
            RecoveryRunEventPayload(report=report),
            NOW + timedelta(seconds=5),
        ),
        (
            RecoveryRunEventType.DECISION,
            RecoveryRunEventPayload(
                decision=RecoveryDecision.CONTINUE,
                certificate=certificate,
            ),
            NOW + timedelta(seconds=6),
        ),
        (
            RecoveryRunEventType.NODE,
            RecoveryRunEventPayload(
                node=RecoveryNodeProgress(
                    node_id=certificate.node_id,
                    state=RecoveryNodeState.VERIFIED,
                    attempt=1,
                )
            ),
            NOW + timedelta(seconds=6),
        ),
        (
            RecoveryRunEventType.ACTION_PERMIT,
            RecoveryRunEventPayload(action_permit=permit),
            NOW + timedelta(seconds=6),
        ),
        (
            RecoveryRunEventType.NODE,
            RecoveryRunEventPayload(
                node=RecoveryNodeProgress(
                    node_id=certificate.node_id,
                    state=RecoveryNodeState.PERMITTED,
                    attempt=1,
                )
            ),
            NOW + timedelta(seconds=6),
        ),
    ):
        snapshot = await store.append(
            request.run_id,
            expected_revision=snapshot.revision,
            event_type=event_type,
            payload=payload,
            occurred_at=occurred_at,
        )


def _promotion_action(
    request: RecoveryRunRequest,
    chain,
    certificate,
    permit,
    *,
    source_node_id: str | None = None,
    fault_mode: CloudRunFaultMode = CloudRunFaultMode.PASS_THROUGH,
) -> CloudRunCanaryActionRequest:
    target = chain.nodes[1]
    provisional = _provisional_scope(
        run_id=request.run_id,
        source_node_id=source_node_id or certificate.node_id,
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
        fault_mode=fault_mode,
        release_id=RELEASE_ID,
        revision=REVISION,
        service_etag="etag-release-7",
        scope=provisional,
    )
    return action.model_copy(
        update={
            "scope": provisional.model_copy(
                update={
                    "action_request_sha256": cloud_run_action_request_sha256(action),
                    "authority_sha256": canonical_sha256(permit),
                }
            )
        }
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
        target=canary_target(),
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
        target=canary_target(),
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
    action = _promotion_action(request, chain, certificate, permit)
    authorizer = RecoveryCloudRunCanaryActionAuthorizer(
        recovery_store=store,
        permit_authority=permit_authority,
        target=canary_target(),
        clock=lambda: NOW + timedelta(seconds=7),
    )

    async def exercise():
        await _record_dispatchable_promotion(
            store,
            request,
            chain,
            report,
            certificate,
            permit,
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


def test_missing_promotion_authority_is_rejected_before_claim(tmp_path) -> None:
    certificate, _evaluation, report, chain, _envelope = _verify(
        node_id="stage",
        kind="committed",
    )
    request = _run_request("recovery-missing-promotion-7")
    store = InMemoryRecoveryRunStore()
    permit_authority = PermitAuthority(
        SqliteDurableRuntimeStore(tmp_path / "missing-promotion.sqlite3"),
        clock=lambda: NOW + timedelta(seconds=7),
    )
    permit = asyncio.run(permit_authority.issue_permit(certificate))
    assert permit is not None
    action = _promotion_action(request, chain, certificate, permit)
    action = action.model_copy(
        update={
            "scope": action.scope.model_copy(
                update={
                    "authority_id": "permit-missing-7",
                    "authority_sha256": "0" * 64,
                }
            )
        }
    )
    authorizer = RecoveryCloudRunCanaryActionAuthorizer(
        recovery_store=store,
        permit_authority=permit_authority,
        target=canary_target(),
        clock=lambda: NOW + timedelta(seconds=7),
    )

    async def exercise():
        await _record_dispatchable_promotion(
            store,
            request,
            chain,
            report,
            certificate,
            permit,
        )
        with pytest.raises(PermissionError, match="unavailable"):
            await authorizer.claim(action)
        return await permit_authority.get_permit(permit.permit_id)

    retained = asyncio.run(exercise())
    assert retained.state is ActionPermitState.ISSUED
    assert retained.claim_id is None


def test_expired_promotion_permit_is_rejected_before_provider_authority(
    tmp_path,
) -> None:
    certificate, _evaluation, report, chain, _envelope = _verify(
        node_id="stage",
        kind="committed",
    )
    request = _run_request("recovery-expired-promotion-7")
    store = InMemoryRecoveryRunStore()
    permit_store = SqliteDurableRuntimeStore(tmp_path / "expired-promotion.sqlite3")
    issuing_authority = PermitAuthority(
        permit_store,
        clock=lambda: NOW + timedelta(seconds=7),
    )
    permit = asyncio.run(issuing_authority.issue_permit(certificate))
    assert permit is not None
    action = _promotion_action(request, chain, certificate, permit)
    expired_authority = PermitAuthority(
        permit_store,
        clock=lambda: certificate.expires_at,
    )
    authorizer = RecoveryCloudRunCanaryActionAuthorizer(
        recovery_store=store,
        permit_authority=expired_authority,
        target=canary_target(),
        clock=lambda: certificate.expires_at,
    )

    async def exercise():
        await _record_dispatchable_promotion(
            store,
            request,
            chain,
            report,
            certificate,
            permit,
        )
        with pytest.raises(PermitClaimDenied, match="expired"):
            await authorizer.claim(action)
        return await expired_authority.get_permit(permit.permit_id)

    retained = asyncio.run(exercise())
    assert retained.state is ActionPermitState.EXPIRED
    assert retained.claim_id is None


@pytest.mark.parametrize(
    ("source_node_id", "fault_mode", "message"),
    (
        ("record", CloudRunFaultMode.PASS_THROUGH, "action permit"),
        ("stage", CloudRunFaultMode.DROP_AFTER_ACCEPT, "fault mode"),
    ),
)
def test_certificate_bound_promotion_rejects_self_consistent_scope_tampering(
    tmp_path,
    source_node_id: str,
    fault_mode: CloudRunFaultMode,
    message: str,
) -> None:
    certificate, _evaluation, report, chain, _envelope = _verify(
        node_id="stage",
        kind="committed",
    )
    request = _run_request(f"recovery-scope-{source_node_id}-{fault_mode.value}")
    store = InMemoryRecoveryRunStore()
    permit_authority = PermitAuthority(
        SqliteDurableRuntimeStore(tmp_path / "tampered-scope.sqlite3"),
        clock=lambda: NOW + timedelta(seconds=7),
    )
    permit = asyncio.run(permit_authority.issue_permit(certificate))
    assert permit is not None
    action = _promotion_action(
        request,
        chain,
        certificate,
        permit,
        source_node_id=source_node_id,
        fault_mode=fault_mode,
    )
    authorizer = RecoveryCloudRunCanaryActionAuthorizer(
        recovery_store=store,
        permit_authority=permit_authority,
        target=canary_target(),
        clock=lambda: NOW + timedelta(seconds=7),
    )

    async def exercise():
        await _record_dispatchable_promotion(
            store,
            request,
            chain,
            report,
            certificate,
            permit,
        )
        with pytest.raises(PermissionError, match=message):
            await authorizer.claim(action)
        return await permit_authority.get_permit(permit.permit_id)

    retained = asyncio.run(exercise())
    assert retained.state is ActionPermitState.ISSUED


@pytest.mark.parametrize(
    ("lifecycle", "category"),
    (
        (
            RecoveryRunLifecycle.FAILED,
            RecoveryRunFailureCategory.INTERNAL_FAILURE,
        ),
        (
            RecoveryRunLifecycle.CANCELLED,
            RecoveryRunFailureCategory.CANCELLED,
        ),
    ),
)
def test_terminal_recovery_run_cannot_claim_an_unspent_action_permit(
    tmp_path,
    lifecycle: RecoveryRunLifecycle,
    category: RecoveryRunFailureCategory,
) -> None:
    certificate, _evaluation, report, chain, _envelope = _verify(
        node_id="stage",
        kind="committed",
    )
    request = _run_request(f"recovery-terminal-{lifecycle.value.lower()}")
    store = InMemoryRecoveryRunStore()
    permit_authority = PermitAuthority(
        SqliteDurableRuntimeStore(tmp_path / "terminal-scope.sqlite3"),
        clock=lambda: NOW + timedelta(seconds=7),
    )
    permit = asyncio.run(permit_authority.issue_permit(certificate))
    assert permit is not None
    action = _promotion_action(request, chain, certificate, permit)
    authorizer = RecoveryCloudRunCanaryActionAuthorizer(
        recovery_store=store,
        permit_authority=permit_authority,
        target=canary_target(),
        clock=lambda: NOW + timedelta(seconds=7),
    )

    async def exercise():
        await _record_dispatchable_promotion(
            store,
            request,
            chain,
            report,
            certificate,
            permit,
        )
        snapshot = await store.get(request.run_id)
        await store.append(
            request.run_id,
            expected_revision=snapshot.revision,
            event_type=RecoveryRunEventType.LIFECYCLE,
            payload=RecoveryRunEventPayload(
                lifecycle=lifecycle,
                failure_category=category,
            ),
            occurred_at=NOW + timedelta(seconds=7),
        )
        with pytest.raises(PermissionError, match="not active"):
            await authorizer.claim(action)
        return await permit_authority.get_permit(permit.permit_id)

    retained = asyncio.run(exercise())
    assert retained.state is ActionPermitState.ISSUED


def test_certificate_presentation_variant_reuses_durable_dispatch_authority(
    tmp_path,
) -> None:
    certificate, evaluation, report, chain, envelope = _verify(
        node_id="stage",
        kind="committed",
    )
    assert isinstance(certificate, VerifiedCertificate)
    cited = (certificate.evidence[0].evidence_id,)
    variant_report = type(report).model_validate(
        report.model_copy(
            update={
                "advisory_explanation": AdvisoryExplanation(
                    text="Equivalent advisory presentation.",
                    cited_evidence_ids=cited,
                )
            }
        )
    )
    _same_chain, envelopes = _chain()
    variant = verify_recovery(
        chain=chain,
        node_id="stage",
        envelope=envelope,
        report=variant_report,
        evaluation=evaluation,
        verified_at=certificate.issued_at,
        successor_envelope=envelopes["promote"],
    )
    assert isinstance(variant, VerifiedCertificate)
    assert variant.certificate_id == certificate.certificate_id
    assert canonical_sha256(variant) != canonical_sha256(certificate)

    request = _run_request("recovery-presentation-variant-7")
    store = InMemoryRecoveryRunStore()
    permit_store = SqliteDurableRuntimeStore(tmp_path / "presentation.sqlite3")
    permit_authority = PermitAuthority(
        permit_store,
        clock=lambda: NOW + timedelta(seconds=7),
    )
    durable = asyncio.run(permit_authority.issue_permit(certificate))
    projected = action_permit_from_certificate(variant)
    assert durable is not None and projected is not None
    action = _promotion_action(request, chain, variant, durable)
    authorizer = RecoveryCloudRunCanaryActionAuthorizer(
        recovery_store=store,
        permit_authority=permit_authority,
        target=canary_target(),
        clock=lambda: NOW + timedelta(seconds=7),
    )

    async def exercise():
        await _record_dispatchable_promotion(
            store,
            request,
            chain,
            variant_report,
            variant,
            projected,
        )
        lease = await authorizer.claim(action)
        assert lease.action_permit is not None
        completed = await authorizer.complete(
            lease,
            RecoveryDispatchOutcome.SUCCEEDED,
        )
        snapshot = await store.get(request.run_id)
        for lifecycle in (lease.action_permit, completed):
            snapshot = await store.append(
                request.run_id,
                expected_revision=snapshot.revision,
                event_type=RecoveryRunEventType.ACTION_PERMIT,
                payload=RecoveryRunEventPayload(action_permit=lifecycle),
                occurred_at=NOW + timedelta(seconds=7),
            )
        return completed, snapshot

    completed, snapshot = asyncio.run(exercise())
    assert completed.state is ActionPermitState.COMPLETED
    assert completed.certificate_sha256 == canonical_sha256(certificate)
    assert snapshot.action_permits == (completed,)


def test_cancellation_winning_during_permit_claim_suppresses_provider_lease(
    tmp_path,
) -> None:
    certificate, _evaluation, report, chain, _envelope = _verify(
        node_id="stage",
        kind="committed",
    )
    request = _run_request("recovery-cancel-during-claim-7")
    store = InMemoryRecoveryRunStore()
    paused_store = _PausingPermitStore(
        SqliteDurableRuntimeStore(tmp_path / "cancel-during-claim.sqlite3")
    )
    permit_authority = PermitAuthority(
        paused_store,
        clock=lambda: NOW + timedelta(seconds=7),
    )
    permit = asyncio.run(permit_authority.issue_permit(certificate))
    assert permit is not None
    action = _promotion_action(request, chain, certificate, permit)
    authorizer = RecoveryCloudRunCanaryActionAuthorizer(
        recovery_store=store,
        permit_authority=permit_authority,
        target=canary_target(),
        clock=lambda: NOW + timedelta(seconds=7),
    )

    async def exercise():
        await _record_dispatchable_promotion(
            store,
            request,
            chain,
            report,
            certificate,
            permit,
        )
        claim = asyncio.create_task(authorizer.claim(action))
        await paused_store.paused.wait()
        snapshot = await store.get(request.run_id)
        await store.append(
            request.run_id,
            expected_revision=snapshot.revision,
            event_type=RecoveryRunEventType.LIFECYCLE,
            payload=RecoveryRunEventPayload(
                lifecycle=RecoveryRunLifecycle.CANCELLED,
                failure_category=RecoveryRunFailureCategory.CANCELLED,
            ),
            occurred_at=NOW + timedelta(seconds=7),
        )
        paused_store.release.set()
        with pytest.raises(PermissionError, match="changed during permit claim"):
            await claim
        return (
            await permit_authority.get_permit(permit.permit_id),
            await store.get(request.run_id),
        )

    claimed, snapshot = asyncio.run(exercise())
    assert claimed.state is ActionPermitState.CLAIMED
    assert snapshot.lifecycle is RecoveryRunLifecycle.CANCELLED
    assert snapshot.action_permits[0].state is ActionPermitState.CLAIMED
    events = asyncio.run(store.events(request.run_id))
    assert events.events[-2].type is RecoveryRunEventType.LIFECYCLE
    assert events.events[-1].type is RecoveryRunEventType.ACTION_PERMIT


def test_recovery_authorizer_rejects_a_different_canary_target(tmp_path) -> None:
    certificate, _evaluation, report, chain, _envelope = _verify(
        node_id="stage",
        kind="committed",
    )
    request = _run_request("recovery-wrong-canary-target-7")
    store = InMemoryRecoveryRunStore()
    permit_authority = PermitAuthority(
        SqliteDurableRuntimeStore(tmp_path / "wrong-canary-target.sqlite3"),
        clock=lambda: NOW + timedelta(seconds=7),
    )
    permit = asyncio.run(permit_authority.issue_permit(certificate))
    assert permit is not None
    action = _promotion_action(request, chain, certificate, permit)
    authorizer = RecoveryCloudRunCanaryActionAuthorizer(
        recovery_store=store,
        permit_authority=permit_authority,
        target=replace(
            canary_target(),
            service="another-canary",
            baseline_revision="another-canary-baseline",
        ),
        clock=lambda: NOW + timedelta(seconds=7),
    )

    async def exercise():
        await _record_dispatchable_promotion(
            store,
            request,
            chain,
            report,
            certificate,
            permit,
        )
        with pytest.raises(PermissionError, match="semantic action"):
            await authorizer.claim(action)
        return await permit_authority.get_permit(permit.permit_id)

    retained = asyncio.run(exercise())
    assert retained.state is ActionPermitState.ISSUED


def test_fault_route_rejects_mismatched_proxy_and_authority_targets(tmp_path) -> None:
    target = canary_target()
    authority_target = replace(
        target,
        service="another-canary",
        baseline_revision="another-canary-baseline",
    )
    authorizer = RecoveryCloudRunCanaryActionAuthorizer(
        recovery_store=InMemoryRecoveryRunStore(),
        permit_authority=PermitAuthority(
            SqliteDurableRuntimeStore(tmp_path / "route-target.sqlite3")
        ),
        target=authority_target,
    )

    with pytest.raises(ValueError, match="targets differ"):
        install_cloud_run_canary_fault_route(
            FastAPI(),
            proxy=CloudRunCanaryFaultProxy(CloudRunCanaryActionAdapter(target=target)),
            action_authorizer=authorizer,
            expected_caller_email="caller@example.test",
            expected_image_digest=IMAGE_DIGEST,
            expected_configuration_sha256=CONFIGURATION_SHA256,
        )
