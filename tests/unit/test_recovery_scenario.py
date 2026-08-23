from __future__ import annotations

import asyncio
import os
from datetime import UTC, datetime, timedelta

import pytest

from reconcile.contracts import (
    RECOVERY_ACTION_SCOPE_VERSION,
    RECOVERY_LAUNCH_PERMIT_VERSION,
    RECOVERY_POLICY_RESULT_VERSION,
    RECOVERY_RUN_REQUEST_VERSION,
    RecoveryActionScope,
    RecoveryAuthorityKind,
    RecoveryLaunchPermit,
    RecoveryLaunchPermitState,
    RecoveryPolicyResult,
    RecoveryRunEventPayload,
    RecoveryRunEventType,
    RecoveryRunFault,
    RecoveryRunLifecycle,
    RecoveryRunPolicy,
    RecoveryRunRequest,
    canonical_json_bytes,
    canonical_sha256,
)
from reconcile.controller.permits import PermitAuthority
from reconcile.hosted.cloud_run_canary import CloudRunCanaryTarget
from reconcile.hosted.firestore_release import FIRESTORE_RELEASE_DATABASE
from reconcile.persistence import InMemoryRecoveryRunStore, SqliteDurableRuntimeStore
from reconcile.recovery_scenario import (
    BlindPolicyExecutor,
    RecoveryPolicyComparisonRunner,
    ReleaseChainActionPreparer,
    ReleaseChainDispatchGateway,
    ReleaseChainSettings,
    build_release_chain_definition,
    export_recovery_comparison,
    recovery_experiment_binding,
)
from tests.contract._factories import make_recovery_scenario_examples

pytestmark = pytest.mark.unit

NOW = datetime(2026, 8, 22, 12, 0, tzinfo=UTC)


def _settings() -> ReleaseChainSettings:
    return ReleaseChainSettings(
        project="demo-project",
        location="us-central1",
        service="reconcile-canary",
        release_id="release-7",
        image_digest="sha256:" + "a" * 64,
        configuration_sha256="b" * 64,
        payload_sha256="c" * 64,
    )


def test_release_chain_has_stable_semantic_keys_and_declared_effect_dependencies() -> (
    None
):
    first = build_release_chain_definition(_settings(), invoked_at=NOW)
    second = build_release_chain_definition(_settings(), invoked_at=NOW)

    assert first == second
    assert tuple(node.node_id for node in first.chain.nodes) == (
        "stage",
        "promote",
        "record",
    )
    assert tuple(node.depends_on for node in first.chain.nodes) == (
        (),
        ("stage",),
        ("promote",),
    )
    assert (
        len({node.semantic_action.semantic_action_sha256 for node in first.chain.nodes})
        == 3
    )
    assert all(
        node.semantic_action.expected_effect_sha256s for node in first.chain.nodes
    )
    assert (
        first.envelopes["record"].expected_effects[0].predicate["cloud_run_revision"]
        == _settings().staged_revision
    )


def test_common_experiment_binding_changes_only_with_fault_boundary() -> None:
    dropped = recovery_experiment_binding(
        _settings(), RecoveryRunFault.DROP_AFTER_ACCEPT
    )
    suppressed = recovery_experiment_binding(
        _settings(), RecoveryRunFault.SUPPRESS_BEFORE_DISPATCH
    )

    assert dropped.target_sha256 == suppressed.target_sha256
    assert dropped.input_intent_sha256 == suppressed.input_intent_sha256
    assert dropped.observation_catalog_sha256 == suppressed.observation_catalog_sha256
    assert dropped.fault_boundary_sha256 != suppressed.fault_boundary_sha256


class _ObservedCloud:
    def __init__(
        self,
        store: InMemoryRecoveryRunStore,
        *,
        service: str = "reconcile-canary",
    ) -> None:
        self.store = store
        self.saw_claim_before_contact = False
        self.saw_receipt_before_contact = False
        self.target = CloudRunCanaryTarget(
            project="demo-project",
            location="us-central1",
            service=service,
            image_repository=(
                "us-central1-docker.pkg.dev/demo-project/reconcile-p5/reconcile"
            ),
            baseline_revision=f"{service}-baseline",
            health_audience="https://canary.example.test",
        )

    async def stage_revision(self, **_kwargs):
        snapshot = await self.store.get("release-gateway-run")
        self.saw_claim_before_contact = (
            snapshot.launch_permit is not None
            and snapshot.launch_permit.state is RecoveryLaunchPermitState.CLAIMED
        )
        self.saw_receipt_before_contact = bool(snapshot.dispatch_receipts)
        return object()

    async def promote_revision(self, **_kwargs):
        raise AssertionError("promotion is outside this focused dispatch")


class _UnusedFirestore:
    project_id = "demo-project"
    database_id = FIRESTORE_RELEASE_DATABASE

    async def create(self, _record):
        raise AssertionError("Firestore is outside this focused dispatch")


def test_gateway_persists_launch_claim_and_receipt_before_provider_contact(
    tmp_path,
) -> None:
    definition = build_release_chain_definition(_settings(), invoked_at=NOW)
    node = definition.chain.nodes[0]
    request = RecoveryRunRequest(
        schema_version=RECOVERY_RUN_REQUEST_VERSION,
        run_id="release-gateway-run",
        scenario="cloud-run-rollout",
        policy=RecoveryRunPolicy.FIXED,
        fault=RecoveryRunFault.DROP_AFTER_ACCEPT,
    )
    store = InMemoryRecoveryRunStore()
    authority = PermitAuthority(
        SqliteDurableRuntimeStore(tmp_path / "permits.sqlite3"),
        clock=lambda: NOW + timedelta(seconds=1),
    )
    prepared = ReleaseChainActionPreparer().prepare(
        request,
        definition.chain,
        node,
        node,
        None,
        None,
    )
    launch = RecoveryLaunchPermit(
        schema_version=RECOVERY_LAUNCH_PERMIT_VERSION,
        launch_permit_id="launch-release-7",
        run_id=request.run_id,
        node_id=node.node_id,
        semantic_action_sha256=node.semantic_action.semantic_action_sha256,
        action_request_sha256=prepared.action_request_sha256,
        issued_at=NOW,
        state=RecoveryLaunchPermitState.ISSUED,
        revision=0,
    )
    scope = RecoveryActionScope(
        schema_version=RECOVERY_ACTION_SCOPE_VERSION,
        authority_kind=RecoveryAuthorityKind.LAUNCH_PERMIT,
        run_id=request.run_id,
        source_node_id=node.node_id,
        target_node_id=node.node_id,
        semantic_action_sha256=node.semantic_action.semantic_action_sha256,
        action_request_sha256=prepared.action_request_sha256,
        authority_id=launch.launch_permit_id,
        authority_sha256=canonical_sha256(launch),
        claim_id="claim-release-7",
    )
    cloud = _ObservedCloud(store)
    gateway = ReleaseChainDispatchGateway(
        settings=_settings(),
        store=store,
        permit_authority=authority,
        cloud_run=cloud,
        firestore=_UnusedFirestore(),
        clock=lambda: NOW + timedelta(seconds=1),
    )

    async def exercise():
        snapshot, _created = await store.create(
            request,
            definition.chain,
            created_at=NOW,
        )
        snapshot = await store.append(
            request.run_id,
            expected_revision=snapshot.revision,
            event_type=RecoveryRunEventType.LIFECYCLE,
            payload=RecoveryRunEventPayload(lifecycle=RecoveryRunLifecycle.RUNNING),
            occurred_at=NOW,
        )
        await store.append(
            request.run_id,
            expected_revision=snapshot.revision,
            event_type=RecoveryRunEventType.LAUNCH_PERMIT,
            payload=RecoveryRunEventPayload(launch_permit=launch),
            occurred_at=NOW,
        )
        receipt = await gateway.dispatch(prepared, scope)
        events = await store.events(request.run_id)
        return receipt, events

    receipt, events = asyncio.run(exercise())

    assert receipt.outcome.value == "SUCCEEDED"
    assert cloud.saw_claim_before_contact is True
    assert cloud.saw_receipt_before_contact is False
    assert tuple(event.type for event in events.events[-3:]) == (
        RecoveryRunEventType.LAUNCH_PERMIT,
        RecoveryRunEventType.DISPATCH_RECEIPT,
        RecoveryRunEventType.LAUNCH_PERMIT,
    )


def test_gateway_rejects_miswired_provider_targets_before_dispatch(tmp_path) -> None:
    settings = _settings()
    store = InMemoryRecoveryRunStore()
    authority = PermitAuthority(
        SqliteDurableRuntimeStore(tmp_path / "miswired.sqlite3"),
        clock=lambda: NOW + timedelta(seconds=1),
    )

    with pytest.raises(ValueError, match="Cloud Run provider target"):
        ReleaseChainDispatchGateway(
            settings=settings,
            store=store,
            permit_authority=authority,
            cloud_run=_ObservedCloud(store, service="other-canary"),
            firestore=_UnusedFirestore(),
        )

    firestore = _UnusedFirestore()
    firestore.project_id = "other-project"
    with pytest.raises(ValueError, match="Firestore provider target"):
        ReleaseChainDispatchGateway(
            settings=settings,
            store=store,
            permit_authority=authority,
            cloud_run=_ObservedCloud(store),
            firestore=firestore,
        )


class _BlindMutator:
    def __init__(self) -> None:
        self.revisions = []
        self.promotions = 0
        self.records = 0
        self.suppressions = 0

    async def stage(self, *, operation_id: str, drop_after_accept: bool) -> None:
        self.revisions.append(operation_id)
        if drop_after_accept:
            raise ConnectionError("acknowledgement lost")

    async def promote(self) -> None:
        self.promotions += 1

    async def create_record(self, *, suppress_before_dispatch: bool) -> None:
        if suppress_before_dispatch:
            self.suppressions += 1
            raise ConnectionError("dispatch suppressed")
        self.records += 1


def test_blind_baselines_are_isolated_and_expose_duplicate_or_incomplete_chain() -> (
    None
):
    retry_mutator = _BlindMutator()
    abort_mutator = _BlindMutator()

    asyncio.run(
        BlindPolicyExecutor(retry_mutator).blind_retry(operation_id="stage-release-7")
    )
    asyncio.run(
        BlindPolicyExecutor(abort_mutator).blind_abort(operation_id="stage-release-7")
    )

    assert retry_mutator.revisions == ["stage-release-7", "stage-release-7-retry"]
    assert (retry_mutator.promotions, retry_mutator.records) == (1, 1)
    assert abort_mutator.revisions == ["stage-release-7"]
    assert (abort_mutator.promotions, abort_mutator.records) == (0, 0)


def test_blind_baselines_apply_the_same_pre_dispatch_fault_boundary() -> None:
    retry_mutator = _BlindMutator()
    abort_mutator = _BlindMutator()

    retry_completed = asyncio.run(
        BlindPolicyExecutor(retry_mutator).blind_retry(
            operation_id="stage-release-7",
            fault=RecoveryRunFault.SUPPRESS_BEFORE_DISPATCH,
        )
    )
    abort_completed = asyncio.run(
        BlindPolicyExecutor(abort_mutator).blind_abort(
            operation_id="stage-release-7",
            fault=RecoveryRunFault.SUPPRESS_BEFORE_DISPATCH,
        )
    )

    assert retry_completed.chain_completed is True
    assert retry_completed.provider_contacts == 3
    assert retry_mutator.revisions == ["stage-release-7"]
    assert (retry_mutator.promotions, retry_mutator.suppressions) == (1, 1)
    assert retry_mutator.records == 1
    assert abort_completed.chain_completed is False
    assert abort_completed.provider_contacts == 2
    assert abort_mutator.revisions == ["stage-release-7"]
    assert (abort_mutator.promotions, abort_mutator.suppressions) == (1, 1)
    assert abort_mutator.records == 0


def test_canonical_comparison_export_is_private_and_never_overwrites(tmp_path) -> None:
    _receipt, comparison = make_recovery_scenario_examples()
    path = tmp_path / "comparison.json"

    digest = export_recovery_comparison(path, comparison)

    assert path.read_bytes() == canonical_json_bytes(comparison)
    assert digest == __import__("hashlib").sha256(path.read_bytes()).hexdigest()
    assert os.stat(path).st_mode & 0o777 == 0o600
    with pytest.raises(FileExistsError):
        export_recovery_comparison(path, comparison)


def test_interrupted_comparison_export_leaves_destination_retryable(
    tmp_path,
    monkeypatch,
) -> None:
    _receipt, comparison = make_recovery_scenario_examples()
    path = tmp_path / "comparison.json"
    real_fsync = os.fsync
    calls = 0

    def fail_first_fsync(descriptor: int) -> None:
        nonlocal calls
        calls += 1
        if calls == 1:
            raise OSError("simulated interrupted write")
        real_fsync(descriptor)

    monkeypatch.setattr(os, "fsync", fail_first_fsync)
    with pytest.raises(OSError, match="interrupted write"):
        export_recovery_comparison(path, comparison)

    assert not path.exists()
    assert tuple(tmp_path.iterdir()) == ()
    monkeypatch.setattr(os, "fsync", real_fsync)
    export_recovery_comparison(path, comparison)
    assert path.read_bytes() == canonical_json_bytes(comparison)


class _ComparisonLanes:
    def __init__(self) -> None:
        self.calls = []
        self.templates = {
            lane.policy: lane for lane in make_recovery_scenario_examples()[1].lanes
        }

    async def execute(self, *, policy, fault, binding):
        self.calls.append((policy, fault))
        payload = self.templates[policy].model_dump(mode="python")
        payload.update(
            {
                "schema_version": RECOVERY_POLICY_RESULT_VERSION,
                "run_id": f"{policy}-{fault.value}-run",
                "fault": fault.value,
                "target_sha256": binding.target_sha256,
                "input_intent_sha256": binding.input_intent_sha256,
                "fault_boundary_sha256": binding.fault_boundary_sha256,
                "observation_catalog_sha256": binding.observation_catalog_sha256,
            }
        )
        return RecoveryPolicyResult.model_validate(payload)


class _ComparisonResetter:
    def __init__(self) -> None:
        self.calls = 0
        self.template = make_recovery_scenario_examples()[1].reset_results[0]

    async def reset(self):
        self.calls += 1
        return self.template


def test_comparison_runner_binds_four_isolated_lanes_and_resets_each() -> None:
    lanes = _ComparisonLanes()
    resetter = _ComparisonResetter()
    runner = RecoveryPolicyComparisonRunner(
        settings=_settings(),
        lane_executor=lanes,
        resetter=resetter,
        clock=lambda: NOW,
    )

    comparison = asyncio.run(runner.run(RecoveryRunFault.DROP_AFTER_ACCEPT))

    assert tuple(lane.policy for lane in comparison.lanes) == (
        "blind-retry",
        "blind-abort",
        "fixed",
        "adaptive",
    )
    assert len({lane.run_id for lane in comparison.lanes}) == 4
    assert all(lane.fault == comparison.fault for lane in comparison.lanes)
    assert resetter.calls == 4


def test_comparison_runner_resets_a_failed_lane_before_propagating() -> None:
    class _FailedLanes:
        async def execute(self, **_kwargs):
            raise RuntimeError("lane failed")

    resetter = _ComparisonResetter()
    runner = RecoveryPolicyComparisonRunner(
        settings=_settings(),
        lane_executor=_FailedLanes(),
        resetter=resetter,
    )

    with pytest.raises(RuntimeError, match="lane failed"):
        asyncio.run(runner.run(RecoveryRunFault.DROP_AFTER_ACCEPT))
    assert resetter.calls == 1
