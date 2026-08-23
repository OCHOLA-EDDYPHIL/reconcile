"""Two-agent orchestration keeps hypotheses, proof, and mutation authority separate."""

from __future__ import annotations

import asyncio
import hashlib
from datetime import timedelta

import pytest

import reconcile.recovery_workflow as workflow_module
from reconcile.adaptive import PlannerFailureKind
from reconcile.contracts import (
    PROBE_REQUEST_VERSION,
    RECOVERY_PREPARED_ACTION_VERSION,
    RECOVERY_RUN_REQUEST_VERSION,
    ActionPermitState,
    Classification,
    PermitCompletionOutcome,
    PlannerCitationRefs,
    PlannerRemainingBudget,
    ProbeRequest,
    RecoveryAuthorityKind,
    RecoveryDispatchOutcome,
    RecoveryLaunchPermitState,
    RecoveryNodeProgress,
    RecoveryNodeState,
    RecoveryPreparedAction,
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
from reconcile.contracts.base import canonical_json_value_bytes
from reconcile.controller.permits import PermitAuthority
from reconcile.persistence import InMemoryRecoveryRunStore, SqliteDurableRuntimeStore
from reconcile.recovery_agents import (
    RecoveryAgent,
    RecoveryDispatchReceipt,
    RolloutAgent,
)
from reconcile.recovery_workflow import (
    ProofToPermitWorkflow,
    RecoveryEvidenceState,
    RecoveryRunApplicationService,
    RecoveryRunDefinition,
    RecoveryWorkflowError,
)
from tests.contract._factories import (
    make_capability,
    make_envelope,
    make_probe,
    make_recovery_examples,
)
from tests.unit.evidence.test_recovery_verification import (
    NOW,
    _capability,
    _chain,
    _verify,
)
from tests.unit.test_recovery_agents import _output, _Planner

pytestmark = pytest.mark.unit


class _Evidence:
    def __init__(self, states: dict[str, RecoveryEvidenceState]) -> None:
        self.states = states
        self.current_calls: list[str] = []
        self.fixed_calls: list[str] = []
        self.probe_calls: list[str] = []

    async def current(self, _run_id, node, _envelope):
        self.current_calls.append(node.node_id)
        return self.states[node.node_id]

    async def fixed(self, _run_id, node, _envelope):
        self.fixed_calls.append(node.node_id)
        return self.states[node.node_id]

    async def probe(self, _run_id, node, _envelope, _request):
        self.probe_calls.append(node.node_id)
        return self.states[node.node_id]


class _BlockingEvidence:
    def __init__(self) -> None:
        self.started = asyncio.Event()

    async def current(self, *_args):
        self.started.set()
        await asyncio.Event().wait()

    async def fixed(self, *_args):
        pytest.fail("fixed evidence must not run after cancellation")

    async def probe(self, *_args):
        pytest.fail("a probe must not run after cancellation")


class _DynamicPlanner(_Planner):
    def __init__(self) -> None:
        super().__init__(output=_output(probe_count=0))

    async def plan(self, planner_input):
        evidence_id = planner_input.admitted_evidence[0].evidence_id
        explanation = self.output.explanation.model_copy(  # type: ignore[union-attr]
            update={
                "citations": PlannerCitationRefs(
                    admitted_evidence_ids=(evidence_id,),
                    weak_evidence_ids=(),
                    rejected_evidence_ids=(),
                    missing_effect_ids=(),
                )
            }
        )
        self.output = self.output.model_copy(  # type: ignore[union-attr]
            update={"explanation": explanation}
        )
        return await super().plan(planner_input)


class _UnsupportedProbePlanner(_Planner):
    def __init__(self) -> None:
        super().__init__(output=_output(probe_count=0))

    async def plan(self, planner_input):
        base = _output(probe_count=0)
        evidence_id = planner_input.admitted_evidence[0].evidence_id
        explanation = base.explanation.model_copy(
            update={
                "citations": PlannerCitationRefs(
                    admitted_evidence_ids=(evidence_id,),
                    weak_evidence_ids=(),
                    rejected_evidence_ids=(),
                    missing_effect_ids=(),
                )
            }
        )
        probe = ProbeRequest(
            schema_version=PROBE_REQUEST_VERSION,
            capability_name="untrusted-write",
            capability_version="1.0.0",
            relevant_effect_ids=(planner_input.envelope.expected_effects[0].effect_id,),
            arguments={},
            rationale="Try an undeclared capability.",
        )
        self.output = base.model_copy(
            update={"probe_proposals": (probe,), "explanation": explanation}
        )
        return await _Planner.plan(self, planner_input)


class _ValidProbePlanner(_Planner):
    def __init__(self) -> None:
        super().__init__(output=_output(probe_count=0))

    async def plan(self, planner_input):
        base = _output(probe_count=0)
        evidence_id = planner_input.admitted_evidence[0].evidence_id
        capability = planner_input.capabilities[0]
        self.output = base.model_copy(
            update={
                "probe_proposals": (
                    ProbeRequest(
                        schema_version=PROBE_REQUEST_VERSION,
                        capability_name=capability.name,
                        capability_version=capability.version,
                        relevant_effect_ids=(
                            planner_input.envelope.expected_effects[0].effect_id,
                        ),
                        arguments={},
                        rationale="Read the declared target state.",
                    ),
                ),
                "explanation": base.explanation.model_copy(
                    update={
                        "citations": PlannerCitationRefs(
                            admitted_evidence_ids=(evidence_id,),
                            weak_evidence_ids=(),
                            rejected_evidence_ids=(),
                            missing_effect_ids=(),
                        )
                    }
                ),
            }
        )
        return await _Planner.plan(self, planner_input)


class _Preparer:
    def __init__(self, *, stale_promote_etag: bool = False) -> None:
        self.stale_promote_etag = stale_promote_etag
        self.prepared: list[RecoveryPreparedAction] = []

    def prepare(
        self,
        request,
        chain,
        source_node,
        target_node,
        report,
        certificate,
    ):
        action = target_node.semantic_action
        arguments = action.semantic_arguments
        if target_node.node_id == "stage":
            precondition = {"none": True}
            request_payload = {
                "action": "stage",
                "configuration_sha256": arguments["configuration_sha256"],
                "fault_mode": request.fault.value,
                "image_digest": arguments["image_digest"],
                "operation_id": target_node.envelope.operation_id,
                "release_id": arguments["release_id"],
                "revision": None,
                "service_etag": None,
            }
        elif target_node.node_id == "promote":
            assert report is not None
            assert certificate is not None
            evidence_ids = {item.evidence_id for item in certificate.evidence}
            etags = {
                item.correlation["service_etag"]
                for item in report.evidence
                if item.evidence_id in evidence_ids
                and "service_etag" in item.correlation
            }
            assert etags == {"etag-release-7"}
            service_etag = (
                "etag-before-stage" if self.stale_promote_etag else next(iter(etags))
            )
            precondition = {"service_etag": service_etag}
            request_payload = {
                "action": "promote",
                "configuration_sha256": None,
                "fault_mode": request.fault.value,
                "image_digest": None,
                "operation_id": None,
                "release_id": arguments["release_id"],
                "revision": arguments["revision"],
                "service_etag": service_etag,
            }
        else:
            precondition = {"exists": False}
            request_payload = {
                "action": "record",
                "fault_mode": request.fault.value,
                "payload_sha256": arguments["payload_sha256"],
                "release_id": arguments["release_id"],
            }
        prepared = RecoveryPreparedAction(
            schema_version=RECOVERY_PREPARED_ACTION_VERSION,
            authority_kind=(
                RecoveryAuthorityKind.LAUNCH_PERMIT
                if certificate is None
                else RecoveryAuthorityKind.ACTION_PERMIT
            ),
            run_id=request.run_id,
            chain_id=chain.chain_id,
            source_node_id=source_node.node_id,
            target_node_id=target_node.node_id,
            semantic_action_sha256=action.semantic_action_sha256,
            tool_name=action.tool_name,
            tool_version=action.tool_version,
            arguments=arguments,
            arguments_sha256=hashlib.sha256(
                canonical_json_value_bytes(arguments)
            ).hexdigest(),
            target=action.target,
            target_sha256=canonical_sha256(action.target),
            precondition=precondition,
            precondition_sha256=hashlib.sha256(
                canonical_json_value_bytes(precondition)
            ).hexdigest(),
            request_payload=request_payload,
            action_request_sha256=hashlib.sha256(
                canonical_json_value_bytes(request_payload)
            ).hexdigest(),
            permit_action=(
                None if certificate is None else certificate.transition.action
            ),
            report_sha256=(None if certificate is None else certificate.report_sha256),
            certificate_id=(
                None if certificate is None else certificate.certificate_id
            ),
            certificate_sha256=(
                None if certificate is None else canonical_sha256(certificate)
            ),
        )
        self.prepared.append(prepared)
        return prepared


class _Gateway:
    def __init__(
        self,
        store,
        authority,
        definition,
        *,
        crash_after_claim: bool = False,
    ) -> None:
        self.store = store
        self.authority = authority
        self.definition = definition
        self.scopes = []
        self.prepared = []
        self.provider_calls = 0
        self.crash_after_claim = crash_after_claim

    async def dispatch(self, prepared, scope):
        assert prepared.action_request_sha256 == scope.action_request_sha256
        self.prepared.append(prepared)
        self.scopes.append(scope)
        if scope.authority_kind is RecoveryAuthorityKind.LAUNCH_PERMIT:
            snapshot = await self.store.get(scope.run_id)
            progress = next(
                item for item in snapshot.nodes if item.node_id == scope.target_node_id
            )
            assert progress.state is RecoveryNodeState.DISPATCH_PENDING
            claimed = await self.store.claim_launch(
                scope.run_id,
                launch_permit_id=scope.authority_id,
                claim_id=scope.claim_id,
                action_request_sha256=scope.action_request_sha256,
                claimed_at=NOW + timedelta(seconds=7),
            )
            completed = await self.store.complete_launch(
                scope.run_id,
                launch_permit_id=scope.authority_id,
                claim_id=scope.claim_id,
                outcome=RecoveryDispatchOutcome.OUTCOME_UNKNOWN,
                completed_at=NOW + timedelta(seconds=7),
            )
            assert claimed.state is RecoveryLaunchPermitState.CLAIMED
            return RecoveryDispatchReceipt(
                outcome=RecoveryDispatchOutcome.OUTCOME_UNKNOWN,
                launch_permit=completed,
            )

        snapshot = await self.store.get(scope.run_id)
        certificate = next(
            item
            for item in snapshot.certificates
            if item.certificate_id == scope.certificate_id
        )
        target = next(
            item
            for item in self.definition.chain.nodes
            if item.node_id == scope.target_node_id
        )
        claimed = await self.authority.claim_for_dispatch(
            permit_id=scope.authority_id,
            certificate=certificate,
            semantic_action=target.semantic_action,
            tool_name=target.semantic_action.tool_name,
            tool_version=target.semantic_action.tool_version,
            arguments=prepared.arguments,
            target=prepared.target,
            precondition=prepared.precondition,
            claim_id=scope.claim_id,
        )
        if self.crash_after_claim:
            self.crash_after_claim = False
            raise _ProcessCrash
        self.provider_calls += 1
        completed = await self.authority.complete_dispatch(
            claimed,
            PermitCompletionOutcome.SUCCEEDED,
        )
        return RecoveryDispatchReceipt(
            outcome=RecoveryDispatchOutcome.SUCCEEDED,
            action_permit=completed,
        )


class _BlockingClaimGateway(_Gateway):
    def __init__(self, store, authority, definition) -> None:
        super().__init__(store, authority, definition)
        self.claimed = asyncio.Event()

    async def dispatch(self, prepared, scope):
        if scope.authority_kind is RecoveryAuthorityKind.LAUNCH_PERMIT:
            return await super().dispatch(prepared, scope)
        self.prepared.append(prepared)
        self.scopes.append(scope)
        snapshot = await self.store.get(scope.run_id)
        certificate = next(
            item
            for item in snapshot.certificates
            if item.certificate_id == scope.certificate_id
        )
        target = next(
            item
            for item in self.definition.chain.nodes
            if item.node_id == scope.target_node_id
        )
        await self.authority.claim_for_dispatch(
            permit_id=scope.authority_id,
            certificate=certificate,
            semantic_action=target.semantic_action,
            tool_name=target.semantic_action.tool_name,
            tool_version=target.semantic_action.tool_version,
            arguments=prepared.arguments,
            target=prepared.target,
            precondition=prepared.precondition,
            claim_id=scope.claim_id,
        )
        self.claimed.set()
        await asyncio.Event().wait()
        raise AssertionError("blocked dispatch unexpectedly resumed")


class _CancelAfterCompletionGateway(_Gateway):
    def __init__(self, store, authority, definition) -> None:
        super().__init__(store, authority, definition)
        self.completed = asyncio.Event()

    async def dispatch(self, prepared, scope):
        receipt = await super().dispatch(prepared, scope)
        if scope.authority_kind is RecoveryAuthorityKind.ACTION_PERMIT:
            self.completed.set()
            task = asyncio.current_task()
            assert task is not None
            task.cancel()
        return receipt


class _ProcessCrash(BaseException):
    """Simulate abrupt worker loss, bypassing in-process error recovery."""


def test_issued_launch_permit_resumes_through_dispatch_pending_after_restart(
    tmp_path,
) -> None:
    definition, states = _definition_and_states()
    request = RecoveryRunRequest(
        schema_version=RECOVERY_RUN_REQUEST_VERSION,
        run_id="recovery-launch-restart-7",
        scenario="cloud-run-rollout",
        policy=RecoveryRunPolicy.ADAPTIVE,
        fault=RecoveryRunFault.DROP_AFTER_ACCEPT,
    )
    store = InMemoryRecoveryRunStore()
    authority = PermitAuthority(
        SqliteDurableRuntimeStore(tmp_path / "launch-restart.sqlite3"),
        clock=lambda: NOW + timedelta(seconds=7),
    )
    first_gateway = _Gateway(store, authority, definition)
    first_worker = ProofToPermitWorkflow(
        store=store,
        definition_factory=lambda _request: definition,
        evidence_source=_Evidence(states),
        action_preparer=_Preparer(),
        recovery_agent=RecoveryAgent(_DynamicPlanner()),
        rollout_agent=RolloutAgent(first_gateway),
        permit_authority=authority,
        clock=lambda: NOW + timedelta(seconds=7),
        claim_id_factory=lambda: "claim-launch-before-crash",
    )

    async def crash_before_pending(run_id, node_id, state, *, attempt):
        assert run_id == request.run_id
        assert node_id == "stage"
        assert state is RecoveryNodeState.DISPATCH_PENDING
        assert attempt == 1
        raise _ProcessCrash

    first_worker._node_state = crash_before_pending

    async def crash():
        await store.create(request, definition.chain, created_at=NOW)
        await first_worker.run(request.run_id)

    with pytest.raises(_ProcessCrash):
        asyncio.run(crash())
    interrupted = asyncio.run(store.get(request.run_id))
    assert interrupted.launch_permit is not None
    assert interrupted.launch_permit.state is RecoveryLaunchPermitState.ISSUED
    assert interrupted.nodes[0].state is RecoveryNodeState.WAITING
    assert first_gateway.scopes == []

    resumed_gateway = _Gateway(store, authority, definition)
    resumed_worker = ProofToPermitWorkflow(
        store=store,
        definition_factory=lambda _request: definition,
        evidence_source=_Evidence(states),
        action_preparer=_Preparer(),
        recovery_agent=RecoveryAgent(_DynamicPlanner()),
        rollout_agent=RolloutAgent(resumed_gateway),
        permit_authority=authority,
        clock=lambda: NOW + timedelta(seconds=7),
        claim_id_factory=iter(
            ("claim-launch-after-restart", "claim-promote", "claim-record")
        ).__next__,
    )
    completed = asyncio.run(resumed_worker.run(request.run_id))

    assert completed.lifecycle is RecoveryRunLifecycle.COMPLETED
    assert (
        resumed_gateway.scopes[0].authority_kind is RecoveryAuthorityKind.LAUNCH_PERMIT
    )
    assert completed.launch_permit is not None
    assert completed.launch_permit.state is RecoveryLaunchPermitState.COMPLETED


def test_model_action_and_repeated_probe_are_never_selected_for_execution() -> None:
    action_hypothesis = make_recovery_examples()[1]
    remaining = PlannerRemainingBudget(
        probes=1,
        elapsed_ms=1,
        result_bytes=1,
        cost_units=1,
        deadline_at=NOW,
    )
    assert (
        workflow_module._probe_disposition(
            action_hypothesis,
            envelope=make_envelope(),
            capabilities=(make_capability(),),
            prior_probe_sha256s=frozenset(),
            remaining_budget=remaining,
        ).value
        == "UNSUPPORTED_ACTION"
    )

    probe = make_probe()
    repeated_hypothesis = type(action_hypothesis).model_validate(
        action_hypothesis.model_copy(
            update={"proposed_probe": probe, "proposed_transition": None}
        )
    )
    assert (
        workflow_module._probe_disposition(
            repeated_hypothesis,
            envelope=make_envelope(),
            capabilities=(make_capability(),),
            prior_probe_sha256s=frozenset(
                {workflow_module.probe_request_sha256(probe)}
            ),
            remaining_budget=remaining,
        ).value
        == "DUPLICATE_PROBE"
    )


@pytest.mark.parametrize(
    "exhausted",
    ("probes", "elapsed_ms", "result_bytes", "cost_units"),
)
def test_valid_probe_is_rejected_when_any_budget_dimension_is_exhausted(
    exhausted: str,
) -> None:
    base = {
        "probes": 1,
        "elapsed_ms": 1,
        "result_bytes": 1,
        "cost_units": 1,
    }
    base[exhausted] = 0
    action_hypothesis = make_recovery_examples()[1]
    valid_probe_hypothesis = type(action_hypothesis).model_validate(
        action_hypothesis.model_copy(
            update={"proposed_probe": make_probe(), "proposed_transition": None}
        )
    )

    disposition = workflow_module._probe_disposition(
        valid_probe_hypothesis,
        envelope=make_envelope(),
        capabilities=(make_capability(),),
        prior_probe_sha256s=frozenset(),
        remaining_budget=PlannerRemainingBudget(
            **base,
            deadline_at=NOW,
        ),
    )

    assert disposition is workflow_module.RecoveryHypothesisDisposition.BUDGET_EXHAUSTED


def test_deterministic_budget_blocks_valid_model_probe_without_fixed_probe(
    tmp_path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    definition, states = _definition_and_states()
    request = RecoveryRunRequest(
        schema_version=RECOVERY_RUN_REQUEST_VERSION,
        run_id="recovery-budget-exhausted-7",
        scenario="cloud-run-rollout",
        policy=RecoveryRunPolicy.ADAPTIVE,
        fault=RecoveryRunFault.DROP_AFTER_ACCEPT,
    )
    store = InMemoryRecoveryRunStore()
    authority = PermitAuthority(
        SqliteDurableRuntimeStore(tmp_path / "budget-exhausted.sqlite3"),
        clock=lambda: NOW + timedelta(seconds=7),
    )
    evidence = _Evidence(states)
    workflow = ProofToPermitWorkflow(
        store=store,
        definition_factory=lambda _request: definition,
        evidence_source=evidence,
        action_preparer=_Preparer(),
        recovery_agent=RecoveryAgent(_ValidProbePlanner()),
        rollout_agent=RolloutAgent(_Gateway(store, authority, definition)),
        permit_authority=authority,
        clock=lambda: NOW + timedelta(seconds=7),
        claim_id_factory=iter(
            ("claim-launch", "claim-promote", "claim-record")
        ).__next__,
    )
    monkeypatch.setattr(
        workflow_module,
        "recovery_remaining_budget",
        lambda *_args, **_kwargs: PlannerRemainingBudget(
            probes=0,
            elapsed_ms=0,
            result_bytes=0,
            cost_units=0,
            deadline_at=NOW,
        ),
    )

    async def exercise():
        await store.create(request, definition.chain, created_at=NOW)
        completed = await workflow.run(request.run_id)
        return completed, await store.events(request.run_id)

    completed, events = asyncio.run(exercise())

    assert completed.lifecycle is RecoveryRunLifecycle.COMPLETED
    assert evidence.probe_calls == []
    assert evidence.fixed_calls == []
    assert (
        tuple(
            event.payload.hypothesis_disposition
            for event in events.events
            if event.type is RecoveryRunEventType.HYPOTHESIS
        )
        == (workflow_module.RecoveryHypothesisDisposition.BUDGET_EXHAUSTED,) * 3
    )


def _definition_and_states():
    chain, envelopes = _chain()
    states = {}
    for node_id in ("stage", "promote", "record"):
        _artifact, evaluation, report, returned_chain, envelope = _verify(
            node_id=node_id,
            kind="committed",
        )
        assert returned_chain == chain
        assert envelope == envelopes[node_id]
        states[node_id] = RecoveryEvidenceState(envelope, report, evaluation)
    definition = RecoveryRunDefinition(
        chain=chain,
        envelopes=envelopes,
        capabilities={
            node_id: tuple(
                _capability(envelope, reference.name)
                for reference in envelope.context.enabled_capabilities
            )
            for node_id, envelope in envelopes.items()
        },
    )
    return definition, states


def test_adaptive_workflow_completes_with_model_hypotheses_and_exact_permits(
    tmp_path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    definition, states = _definition_and_states()
    request = RecoveryRunRequest(
        schema_version=RECOVERY_RUN_REQUEST_VERSION,
        run_id="recovery-workflow-7",
        scenario="cloud-run-rollout",
        policy=RecoveryRunPolicy.ADAPTIVE,
        fault=RecoveryRunFault.DROP_AFTER_ACCEPT,
    )
    store = InMemoryRecoveryRunStore()
    authority = PermitAuthority(
        SqliteDurableRuntimeStore(tmp_path / "authority.sqlite3"),
        clock=lambda: NOW + timedelta(seconds=7),
    )
    planner = _DynamicPlanner()
    evidence = _Evidence(states)
    gateway = _Gateway(store, authority, definition)
    preparer = _Preparer()
    verifier_calls = []
    original_verify = workflow_module.verify_recovery

    def observed_verify(**kwargs):
        verifier_calls.append(kwargs)
        return original_verify(**kwargs)

    monkeypatch.setattr(workflow_module, "verify_recovery", observed_verify)
    workflow = ProofToPermitWorkflow(
        store=store,
        definition_factory=lambda _request: definition,
        evidence_source=evidence,
        action_preparer=preparer,
        recovery_agent=RecoveryAgent(
            planner,
            clock=lambda: NOW + timedelta(seconds=6),
        ),
        rollout_agent=RolloutAgent(gateway),
        permit_authority=authority,
        clock=lambda: NOW + timedelta(seconds=7),
        claim_id_factory=iter(
            ("claim-launch", "claim-promote", "claim-record")
        ).__next__,
    )

    async def exercise():
        await store.create(request, definition.chain, created_at=NOW)
        return await workflow.run(request.run_id)

    snapshot = asyncio.run(exercise())

    assert snapshot.lifecycle is RecoveryRunLifecycle.COMPLETED
    assert len(snapshot.hypotheses) == 3
    assert len(snapshot.certificates) == 3
    assert all(
        hypothesis.proposed_classification is Classification.UNKNOWN
        for hypothesis in snapshot.hypotheses
    )
    assert all(
        certificate.classification is Classification.COMMITTED
        for certificate in snapshot.certificates
    )
    assert snapshot.witnesses == ()
    assert snapshot.launch_permit is not None
    assert snapshot.launch_permit.state is RecoveryLaunchPermitState.COMPLETED
    assert tuple(permit.state for permit in snapshot.action_permits) == (
        ActionPermitState.COMPLETED,
        ActionPermitState.COMPLETED,
    )
    assert len(gateway.scopes) == 3
    assert tuple(item.target_node_id for item in preparer.prepared) == (
        "stage",
        "promote",
        "record",
    )
    assert preparer.prepared[1].precondition == {"service_etag": "etag-release-7"}
    assert preparer.prepared[1].request_payload["service_etag"] == "etag-release-7"
    assert all(scope.schema_version.endswith("/v2") for scope in gateway.scopes)
    assert all("hypothesis" not in call for call in verifier_calls)
    assert evidence.fixed_calls == []
    assert evidence.probe_calls == []
    event_snapshot = asyncio.run(store.events(request.run_id))
    assert event_snapshot.events[-1].type is RecoveryRunEventType.LIFECYCLE


def test_claimed_action_permit_is_reconciled_after_restart_without_redispatch(
    tmp_path,
) -> None:
    definition, states = _definition_and_states()
    request = RecoveryRunRequest(
        schema_version=RECOVERY_RUN_REQUEST_VERSION,
        run_id="recovery-restart-7",
        scenario="cloud-run-rollout",
        policy=RecoveryRunPolicy.ADAPTIVE,
        fault=RecoveryRunFault.DROP_AFTER_ACCEPT,
    )
    store = InMemoryRecoveryRunStore()
    authority = PermitAuthority(
        SqliteDurableRuntimeStore(tmp_path / "restart.sqlite3"),
        clock=lambda: NOW + timedelta(seconds=7),
    )
    planner = _DynamicPlanner()
    crashing_gateway = _Gateway(
        store,
        authority,
        definition,
        crash_after_claim=True,
    )
    first_worker = ProofToPermitWorkflow(
        store=store,
        definition_factory=lambda _request: definition,
        evidence_source=_Evidence(states),
        action_preparer=_Preparer(),
        recovery_agent=RecoveryAgent(planner),
        rollout_agent=RolloutAgent(crashing_gateway),
        permit_authority=authority,
        clock=lambda: NOW + timedelta(seconds=7),
        claim_id_factory=iter(("claim-launch", "claim-promote")).__next__,
    )

    async def crash():
        await store.create(request, definition.chain, created_at=NOW)
        await first_worker.run(request.run_id)

    with pytest.raises(_ProcessCrash):
        asyncio.run(crash())
    interrupted = asyncio.run(store.get(request.run_id))
    assert interrupted.lifecycle is RecoveryRunLifecycle.RUNNING
    assert interrupted.nodes[0].state.value == "PERMITTED"
    assert interrupted.action_permits[0].state is ActionPermitState.ISSUED

    async def persist_post_claim_crash_boundary():
        claimed = await authority.get_permit(interrupted.action_permits[0].permit_id)
        snapshot = await store.get(request.run_id)
        snapshot = await store.append(
            request.run_id,
            expected_revision=snapshot.revision,
            event_type=RecoveryRunEventType.ACTION_PERMIT,
            payload=RecoveryRunEventPayload(action_permit=claimed),
            occurred_at=NOW + timedelta(seconds=8),
        )
        return await store.append(
            request.run_id,
            expected_revision=snapshot.revision,
            event_type=RecoveryRunEventType.NODE,
            payload=RecoveryRunEventPayload(
                node=RecoveryNodeProgress(
                    node_id=definition.chain.nodes[0].node_id,
                    state=RecoveryNodeState.DISPATCH_CLAIMED,
                    attempt=interrupted.nodes[0].attempt,
                )
            ),
            occurred_at=NOW + timedelta(seconds=8),
        )

    projected = asyncio.run(persist_post_claim_crash_boundary())
    assert projected.nodes[0].state is RecoveryNodeState.DISPATCH_CLAIMED
    assert projected.action_permits[0].state is ActionPermitState.CLAIMED

    resumed_gateway = _Gateway(store, authority, definition)
    resumed_worker = ProofToPermitWorkflow(
        store=store,
        definition_factory=lambda _request: definition,
        evidence_source=_Evidence(states),
        action_preparer=_Preparer(),
        recovery_agent=RecoveryAgent(_DynamicPlanner()),
        rollout_agent=RolloutAgent(resumed_gateway),
        permit_authority=authority,
        clock=lambda: NOW + timedelta(seconds=7),
        claim_id_factory=lambda: "claim-record",
    )
    original_node_state = resumed_worker._node_state

    async def crash_after_claimed_state(run_id, node_id, state, *, attempt):
        result = await original_node_state(
            run_id,
            node_id,
            state,
            attempt=attempt,
        )
        if node_id == "stage" and state is RecoveryNodeState.DISPATCH_CLAIMED:
            raise _ProcessCrash
        return result

    resumed_worker._node_state = crash_after_claimed_state
    with pytest.raises(_ProcessCrash):
        asyncio.run(resumed_worker.run(request.run_id))
    claimed_projection = asyncio.run(store.get(request.run_id))
    assert claimed_projection.nodes[0].state is RecoveryNodeState.DISPATCH_CLAIMED

    final_gateway = _Gateway(store, authority, definition)
    final_worker = ProofToPermitWorkflow(
        store=store,
        definition_factory=lambda _request: definition,
        evidence_source=_Evidence(states),
        action_preparer=_Preparer(),
        recovery_agent=RecoveryAgent(_DynamicPlanner()),
        rollout_agent=RolloutAgent(final_gateway),
        permit_authority=authority,
        clock=lambda: NOW + timedelta(seconds=7),
        claim_id_factory=lambda: "claim-record",
    )
    completed = asyncio.run(final_worker.run(request.run_id))
    assert completed.lifecycle is RecoveryRunLifecycle.COMPLETED
    assert len(crashing_gateway.scopes) == 2
    assert resumed_gateway.scopes == []
    assert len(final_gateway.scopes) == 1
    assert final_gateway.scopes[0].target_node_id == "record"
    assert completed.action_permits[0].state is ActionPermitState.CLAIMED
    # A terminal replay is also a pure read.
    replayed = asyncio.run(final_worker.run(request.run_id))
    assert replayed == completed
    assert len(final_gateway.scopes) == 1


def test_completed_continue_dispatch_resumes_after_successor_activation(
    tmp_path,
) -> None:
    definition, states = _definition_and_states()
    request = RecoveryRunRequest(
        schema_version=RECOVERY_RUN_REQUEST_VERSION,
        run_id="recovery-successor-restart-7",
        scenario="cloud-run-rollout",
        policy=RecoveryRunPolicy.ADAPTIVE,
        fault=RecoveryRunFault.DROP_AFTER_ACCEPT,
    )
    store = InMemoryRecoveryRunStore()
    authority = PermitAuthority(
        SqliteDurableRuntimeStore(tmp_path / "successor-restart.sqlite3"),
        clock=lambda: NOW + timedelta(seconds=7),
    )
    first_gateway = _Gateway(store, authority, definition)
    first_worker = ProofToPermitWorkflow(
        store=store,
        definition_factory=lambda _request: definition,
        evidence_source=_Evidence(states),
        action_preparer=_Preparer(),
        recovery_agent=RecoveryAgent(_DynamicPlanner()),
        rollout_agent=RolloutAgent(first_gateway),
        permit_authority=authority,
        clock=lambda: NOW + timedelta(seconds=7),
        claim_id_factory=iter(("claim-launch", "claim-promote")).__next__,
    )
    original_node_state = first_worker._node_state

    async def crash_after_successor_state(run_id, node_id, state, *, attempt):
        result = await original_node_state(
            run_id,
            node_id,
            state,
            attempt=attempt,
        )
        if node_id == "promote" and state is RecoveryNodeState.RECONCILING:
            raise _ProcessCrash
        return result

    first_worker._node_state = crash_after_successor_state

    async def crash():
        await store.create(request, definition.chain, created_at=NOW)
        await first_worker.run(request.run_id)

    with pytest.raises(_ProcessCrash):
        asyncio.run(crash())
    interrupted = asyncio.run(store.get(request.run_id))
    assert interrupted.nodes[0].state is RecoveryNodeState.PERMITTED
    assert interrupted.nodes[1].state is RecoveryNodeState.RECONCILING
    assert interrupted.action_permits[0].state is ActionPermitState.COMPLETED

    final_gateway = _Gateway(store, authority, definition)
    final_worker = ProofToPermitWorkflow(
        store=store,
        definition_factory=lambda _request: definition,
        evidence_source=_Evidence(states),
        action_preparer=_Preparer(),
        recovery_agent=RecoveryAgent(_DynamicPlanner()),
        rollout_agent=RolloutAgent(final_gateway),
        permit_authority=authority,
        clock=lambda: NOW + timedelta(seconds=7),
        claim_id_factory=lambda: "claim-record",
    )
    completed = asyncio.run(final_worker.run(request.run_id))

    assert completed.lifecycle is RecoveryRunLifecycle.COMPLETED
    assert len(first_gateway.scopes) == 2
    assert len(final_gateway.scopes) == 1
    assert final_gateway.scopes[0].target_node_id == "record"


def test_recorded_decision_resumes_without_duplicate_certificate_or_probe(
    tmp_path,
) -> None:
    definition, states = _definition_and_states()
    request = RecoveryRunRequest(
        schema_version=RECOVERY_RUN_REQUEST_VERSION,
        run_id="recovery-decision-restart-7",
        scenario="cloud-run-rollout",
        policy=RecoveryRunPolicy.ADAPTIVE,
        fault=RecoveryRunFault.DROP_AFTER_ACCEPT,
    )
    store = InMemoryRecoveryRunStore()
    authority = PermitAuthority(
        SqliteDurableRuntimeStore(tmp_path / "decision-restart.sqlite3"),
        clock=lambda: NOW + timedelta(seconds=7),
    )
    first_evidence = _Evidence(states)
    first_worker = ProofToPermitWorkflow(
        store=store,
        definition_factory=lambda _request: definition,
        evidence_source=first_evidence,
        action_preparer=_Preparer(),
        recovery_agent=RecoveryAgent(_DynamicPlanner()),
        rollout_agent=RolloutAgent(_Gateway(store, authority, definition)),
        permit_authority=authority,
        clock=lambda: NOW + timedelta(seconds=7),
        claim_id_factory=lambda: "claim-launch",
    )
    original_record_decision = first_worker._record_decision

    async def crash_after_decision(run_id, artifact, decision):
        await original_record_decision(run_id, artifact, decision)
        raise _ProcessCrash

    first_worker._record_decision = crash_after_decision

    async def crash():
        await store.create(request, definition.chain, created_at=NOW)
        await first_worker.run(request.run_id)

    with pytest.raises(_ProcessCrash):
        asyncio.run(crash())
    interrupted = asyncio.run(store.get(request.run_id))
    assert interrupted.nodes[0].state is RecoveryNodeState.RECONCILING
    assert len(interrupted.certificates) == 1

    resumed_evidence = _Evidence(states)
    resumed_gateway = _Gateway(store, authority, definition)
    resumed_worker = ProofToPermitWorkflow(
        store=store,
        definition_factory=lambda _request: definition,
        evidence_source=resumed_evidence,
        action_preparer=_Preparer(),
        recovery_agent=RecoveryAgent(_DynamicPlanner()),
        rollout_agent=RolloutAgent(resumed_gateway),
        permit_authority=authority,
        clock=lambda: NOW + timedelta(seconds=7),
        claim_id_factory=iter(("claim-promote", "claim-record")).__next__,
    )
    completed = asyncio.run(resumed_worker.run(request.run_id))

    assert completed.lifecycle is RecoveryRunLifecycle.COMPLETED
    assert len(completed.certificates) == 3
    assert resumed_evidence.current_calls == ["promote", "record"]
    assert tuple(scope.target_node_id for scope in resumed_gateway.scopes) == (
        "promote",
        "record",
    )


def test_expiry_during_claim_never_advances_or_contacts_provider(tmp_path) -> None:
    definition, states = _definition_and_states()
    certificate, *_rest = _verify(node_id="stage", kind="committed")
    assert isinstance(certificate, VerifiedCertificate)
    request = RecoveryRunRequest(
        schema_version=RECOVERY_RUN_REQUEST_VERSION,
        run_id="recovery-expiry-at-claim-7",
        scenario="cloud-run-rollout",
        policy=RecoveryRunPolicy.ADAPTIVE,
        fault=RecoveryRunFault.DROP_AFTER_ACCEPT,
    )
    authority_times = iter(
        (
            certificate.expires_at - timedelta(microseconds=1),
            certificate.expires_at,
        )
    )
    store = InMemoryRecoveryRunStore()
    authority = PermitAuthority(
        SqliteDurableRuntimeStore(tmp_path / "expiry-at-claim.sqlite3"),
        clock=authority_times.__next__,
    )
    gateway = _Gateway(store, authority, definition)
    workflow = ProofToPermitWorkflow(
        store=store,
        definition_factory=lambda _request: definition,
        evidence_source=_Evidence(states),
        action_preparer=_Preparer(),
        recovery_agent=RecoveryAgent(_DynamicPlanner()),
        rollout_agent=RolloutAgent(gateway),
        permit_authority=authority,
        clock=lambda: NOW + timedelta(seconds=7),
        claim_id_factory=iter(("claim-launch", "claim-promote")).__next__,
    )

    async def exercise():
        await store.create(request, definition.chain, created_at=NOW)
        await workflow.run(request.run_id)

    with pytest.raises(RecoveryWorkflowError, match="expired before dispatch"):
        asyncio.run(exercise())
    snapshot = asyncio.run(store.get(request.run_id))
    assert gateway.provider_calls == 0
    assert snapshot.action_permits[0].state is ActionPermitState.EXPIRED
    assert snapshot.nodes[0].state is RecoveryNodeState.PERMITTED
    assert snapshot.nodes[1].state is RecoveryNodeState.WAITING


def test_retry_bound_survives_crash_after_second_attempt_decision(tmp_path) -> None:
    definition, states = _definition_and_states()
    _artifact, evaluation, report, chain, envelope = _verify(
        node_id="record",
        kind="not-committed",
    )
    assert chain == definition.chain
    states["record"] = RecoveryEvidenceState(envelope, report, evaluation)
    request = RecoveryRunRequest(
        schema_version=RECOVERY_RUN_REQUEST_VERSION,
        run_id="recovery-retry-bound-restart-7",
        scenario="cloud-run-rollout",
        policy=RecoveryRunPolicy.ADAPTIVE,
        fault=RecoveryRunFault.SUPPRESS_BEFORE_DISPATCH,
    )
    store = InMemoryRecoveryRunStore()
    authority = PermitAuthority(
        SqliteDurableRuntimeStore(tmp_path / "retry-bound.sqlite3"),
        clock=lambda: NOW + timedelta(seconds=7),
    )
    gateway = _Gateway(store, authority, definition)
    first_worker = ProofToPermitWorkflow(
        store=store,
        definition_factory=lambda _request: definition,
        evidence_source=_Evidence(states),
        action_preparer=_Preparer(),
        recovery_agent=RecoveryAgent(_DynamicPlanner()),
        rollout_agent=RolloutAgent(gateway),
        permit_authority=authority,
        clock=lambda: NOW + timedelta(seconds=7),
        claim_id_factory=iter(
            ("claim-launch", "claim-promote", "claim-record", "claim-retry")
        ).__next__,
    )
    original_node_state = first_worker._node_state

    async def crash_after_second_decision(run_id, node_id, state, *, attempt):
        result = await original_node_state(
            run_id,
            node_id,
            state,
            attempt=attempt,
        )
        if node_id == "record" and state is RecoveryNodeState.VERIFIED and attempt == 2:
            raise _ProcessCrash
        return result

    first_worker._node_state = crash_after_second_decision

    async def crash():
        await store.create(request, definition.chain, created_at=NOW)
        await first_worker.run(request.run_id)

    with pytest.raises(_ProcessCrash):
        asyncio.run(crash())
    interrupted = asyncio.run(store.get(request.run_id))
    assert interrupted.nodes[2].state is RecoveryNodeState.VERIFIED
    assert interrupted.nodes[2].attempt == 2
    scope_count = len(gateway.scopes)

    resumed = ProofToPermitWorkflow(
        store=store,
        definition_factory=lambda _request: definition,
        evidence_source=_Evidence(states),
        action_preparer=_Preparer(),
        recovery_agent=RecoveryAgent(_DynamicPlanner()),
        rollout_agent=RolloutAgent(gateway),
        permit_authority=authority,
        clock=lambda: NOW + timedelta(seconds=7),
        claim_id_factory=lambda: "claim-third-attempt",
    )
    with pytest.raises(RecoveryWorkflowError, match="bounded recovery retry"):
        asyncio.run(resumed.run(request.run_id))
    assert len(gateway.scopes) == scope_count


def test_stale_pre_stage_etag_cannot_enter_a_certificate_scoped_dispatch(
    tmp_path,
) -> None:
    definition, states = _definition_and_states()
    request = RecoveryRunRequest(
        schema_version=RECOVERY_RUN_REQUEST_VERSION,
        run_id="recovery-stale-etag-7",
        scenario="cloud-run-rollout",
        policy=RecoveryRunPolicy.ADAPTIVE,
        fault=RecoveryRunFault.DROP_AFTER_ACCEPT,
    )
    store = InMemoryRecoveryRunStore()
    authority = PermitAuthority(
        SqliteDurableRuntimeStore(tmp_path / "stale-etag.sqlite3"),
        clock=lambda: NOW + timedelta(seconds=7),
    )
    gateway = _Gateway(store, authority, definition)
    preparer = _Preparer(stale_promote_etag=True)
    workflow = ProofToPermitWorkflow(
        store=store,
        definition_factory=lambda _request: definition,
        evidence_source=_Evidence(states),
        action_preparer=preparer,
        recovery_agent=RecoveryAgent(_DynamicPlanner()),
        rollout_agent=RolloutAgent(gateway),
        permit_authority=authority,
        clock=lambda: NOW + timedelta(seconds=7),
        claim_id_factory=iter(("claim-launch", "claim-promote")).__next__,
    )

    async def exercise():
        await store.create(request, definition.chain, created_at=NOW)
        with pytest.raises(
            RecoveryWorkflowError,
            match="not bound to certified authority",
        ):
            await workflow.run(request.run_id)
        return await store.get(request.run_id)

    interrupted = asyncio.run(exercise())

    assert tuple(item.target_node_id for item in preparer.prepared) == (
        "stage",
        "promote",
    )
    assert preparer.prepared[-1].precondition == {"service_etag": "etag-before-stage"}
    assert len(gateway.scopes) == 1
    assert interrupted.action_permits[0].state is ActionPermitState.ISSUED


def test_pending_provider_state_is_observed_without_mutation_then_escalates(
    tmp_path,
) -> None:
    definition, states = _definition_and_states()
    _artifact, evaluation, report, chain, envelope = _verify(
        node_id="stage",
        kind="pending",
    )
    assert chain == definition.chain
    states["stage"] = RecoveryEvidenceState(envelope, report, evaluation)
    request = RecoveryRunRequest(
        schema_version=RECOVERY_RUN_REQUEST_VERSION,
        run_id="recovery-pending-7",
        scenario="cloud-run-rollout",
        policy=RecoveryRunPolicy.ADAPTIVE,
        fault=RecoveryRunFault.DROP_AFTER_ACCEPT,
    )
    store = InMemoryRecoveryRunStore()
    authority = PermitAuthority(
        SqliteDurableRuntimeStore(tmp_path / "pending.sqlite3"),
        clock=lambda: NOW + timedelta(seconds=7),
    )
    gateway = _Gateway(store, authority, definition)
    workflow = ProofToPermitWorkflow(
        store=store,
        definition_factory=lambda _request: definition,
        evidence_source=_Evidence(states),
        action_preparer=_Preparer(),
        recovery_agent=RecoveryAgent(
            _DynamicPlanner(),
            clock=lambda: NOW + timedelta(seconds=6),
        ),
        rollout_agent=RolloutAgent(gateway),
        permit_authority=authority,
        clock=lambda: NOW + timedelta(seconds=7),
        claim_id_factory=lambda: "claim-launch",
    )

    async def exercise():
        await store.create(request, definition.chain, created_at=NOW)
        completed = await workflow.run(request.run_id)
        events = await store.events(request.run_id)
        return completed, events

    completed, events = asyncio.run(exercise())
    decisions = tuple(
        event.payload.decision
        for event in events.events
        if event.type is RecoveryRunEventType.DECISION
    )

    assert completed.lifecycle is RecoveryRunLifecycle.ESCALATED
    assert decisions[:-1] == (workflow_module.RecoveryDecision.OBSERVE,) * 7
    assert decisions[-1] is workflow_module.RecoveryDecision.ESCALATE
    assert len(gateway.scopes) == 1
    assert completed.action_permits == ()


def test_unsupported_model_probe_is_never_executed_and_uses_fixed_fallback(
    tmp_path,
) -> None:
    definition, states = _definition_and_states()
    request = RecoveryRunRequest(
        schema_version=RECOVERY_RUN_REQUEST_VERSION,
        run_id="recovery-unsupported-probe-7",
        scenario="cloud-run-rollout",
        policy=RecoveryRunPolicy.ADAPTIVE,
        fault=RecoveryRunFault.DROP_AFTER_ACCEPT,
    )
    store = InMemoryRecoveryRunStore()
    authority = PermitAuthority(
        SqliteDurableRuntimeStore(tmp_path / "fallback.sqlite3"),
        clock=lambda: NOW + timedelta(seconds=7),
    )
    evidence = _Evidence(states)
    gateway = _Gateway(store, authority, definition)
    workflow = ProofToPermitWorkflow(
        store=store,
        definition_factory=lambda _request: definition,
        evidence_source=evidence,
        action_preparer=_Preparer(),
        recovery_agent=RecoveryAgent(_UnsupportedProbePlanner()),
        rollout_agent=RolloutAgent(gateway),
        permit_authority=authority,
        clock=lambda: NOW + timedelta(seconds=7),
        claim_id_factory=iter(
            ("claim-launch", "claim-promote", "claim-record")
        ).__next__,
    )

    async def exercise():
        await store.create(request, definition.chain, created_at=NOW)
        completed = await workflow.run(request.run_id)
        events = await store.events(request.run_id)
        return completed, events

    completed, events = asyncio.run(exercise())
    dispositions = tuple(
        event.payload.hypothesis_disposition
        for event in events.events
        if event.type is RecoveryRunEventType.HYPOTHESIS
    )
    assert completed.lifecycle is RecoveryRunLifecycle.COMPLETED
    assert evidence.probe_calls == []
    assert evidence.fixed_calls == ["stage", "promote", "record"]
    assert tuple(item.value for item in dispositions) == (
        "UNSUPPORTED_PROBE",
        "FIXED_FALLBACK",
        "UNSUPPORTED_PROBE",
        "FIXED_FALLBACK",
        "UNSUPPORTED_PROBE",
        "FIXED_FALLBACK",
    )


def test_explicit_cancellation_is_terminal_but_shutdown_remains_restartable(
    tmp_path,
) -> None:
    definition, _states = _definition_and_states()
    request = RecoveryRunRequest(
        schema_version=RECOVERY_RUN_REQUEST_VERSION,
        run_id="recovery-cancel-7",
        scenario="cloud-run-rollout",
        policy=RecoveryRunPolicy.ADAPTIVE,
        fault=RecoveryRunFault.DROP_AFTER_ACCEPT,
    )
    store = InMemoryRecoveryRunStore()
    authority = PermitAuthority(
        SqliteDurableRuntimeStore(tmp_path / "cancel.sqlite3"),
        clock=lambda: NOW + timedelta(seconds=7),
    )
    evidence = _BlockingEvidence()
    gateway = _Gateway(store, authority, definition)
    workflow = ProofToPermitWorkflow(
        store=store,
        definition_factory=lambda _request: definition,
        evidence_source=evidence,
        action_preparer=_Preparer(),
        recovery_agent=RecoveryAgent(_DynamicPlanner()),
        rollout_agent=RolloutAgent(gateway),
        permit_authority=authority,
        clock=lambda: NOW + timedelta(seconds=7),
        claim_id_factory=lambda: "claim-launch",
    )
    service = RecoveryRunApplicationService(
        workflow,
        store,
        clock=lambda: NOW,
    )

    async def exercise():
        await service.launch(request)
        await asyncio.wait_for(evidence.started.wait(), timeout=1)
        cancelled = await service.cancel(request.run_id)
        await service.aclose()
        return cancelled

    cancelled = asyncio.run(exercise())
    assert cancelled.lifecycle is RecoveryRunLifecycle.CANCELLED
    assert cancelled.failure_category is RecoveryRunFailureCategory.CANCELLED
    assert cancelled.nodes[0].state is RecoveryNodeState.RECONCILING
    assert len(gateway.scopes) == 1


def test_cancellation_after_action_claim_mirrors_authority_and_never_redispatches(
    tmp_path,
) -> None:
    definition, states = _definition_and_states()
    request = RecoveryRunRequest(
        schema_version=RECOVERY_RUN_REQUEST_VERSION,
        run_id="recovery-cancel-after-claim-7",
        scenario="cloud-run-rollout",
        policy=RecoveryRunPolicy.ADAPTIVE,
        fault=RecoveryRunFault.DROP_AFTER_ACCEPT,
    )
    store = InMemoryRecoveryRunStore()
    authority = PermitAuthority(
        SqliteDurableRuntimeStore(tmp_path / "cancel-after-claim.sqlite3"),
        clock=lambda: NOW + timedelta(seconds=7),
    )
    blocking_gateway = _BlockingClaimGateway(store, authority, definition)
    service = RecoveryRunApplicationService(
        ProofToPermitWorkflow(
            store=store,
            definition_factory=lambda _request: definition,
            evidence_source=_Evidence(states),
            action_preparer=_Preparer(),
            recovery_agent=RecoveryAgent(_DynamicPlanner()),
            rollout_agent=RolloutAgent(blocking_gateway),
            permit_authority=authority,
            clock=lambda: NOW + timedelta(seconds=7),
            claim_id_factory=iter(("claim-launch", "claim-promote")).__next__,
        ),
        store,
        clock=lambda: NOW,
    )

    async def cancel_after_claim():
        await service.launch(request)
        await asyncio.wait_for(blocking_gateway.claimed.wait(), timeout=10)
        snapshot = await service.cancel(request.run_id)
        await service.aclose()
        return snapshot

    cancelled = asyncio.run(cancel_after_claim())
    assert cancelled.lifecycle is RecoveryRunLifecycle.CANCELLED
    assert cancelled.failure_category is RecoveryRunFailureCategory.CANCELLED
    assert cancelled.nodes[0].state is RecoveryNodeState.DISPATCH_CLAIMED
    assert cancelled.action_permits[0].state is ActionPermitState.CLAIMED

    replay_gateway = _Gateway(store, authority, definition)
    replay = ProofToPermitWorkflow(
        store=store,
        definition_factory=lambda _request: definition,
        evidence_source=_Evidence(states),
        action_preparer=_Preparer(),
        recovery_agent=RecoveryAgent(_DynamicPlanner()),
        rollout_agent=RolloutAgent(replay_gateway),
        permit_authority=authority,
        clock=lambda: NOW + timedelta(seconds=7),
        claim_id_factory=lambda: "never-dispatched",
    )
    assert asyncio.run(replay.run(request.run_id)) == cancelled
    assert replay_gateway.scopes == []


def test_cancellation_after_action_completion_mirrors_authority_before_terminal(
    tmp_path,
) -> None:
    definition, states = _definition_and_states()
    request = RecoveryRunRequest(
        schema_version=RECOVERY_RUN_REQUEST_VERSION,
        run_id="recovery-cancel-after-completion-7",
        scenario="cloud-run-rollout",
        policy=RecoveryRunPolicy.ADAPTIVE,
        fault=RecoveryRunFault.DROP_AFTER_ACCEPT,
    )
    store = InMemoryRecoveryRunStore()
    authority = PermitAuthority(
        SqliteDurableRuntimeStore(tmp_path / "cancel-after-completion.sqlite3"),
        clock=lambda: NOW + timedelta(seconds=7),
    )
    gateway = _CancelAfterCompletionGateway(store, authority, definition)
    service = RecoveryRunApplicationService(
        ProofToPermitWorkflow(
            store=store,
            definition_factory=lambda _request: definition,
            evidence_source=_Evidence(states),
            action_preparer=_Preparer(),
            recovery_agent=RecoveryAgent(_DynamicPlanner()),
            rollout_agent=RolloutAgent(gateway),
            permit_authority=authority,
            clock=lambda: NOW + timedelta(seconds=7),
            claim_id_factory=iter(("claim-launch", "claim-promote")).__next__,
        ),
        store,
        clock=lambda: NOW,
    )

    async def cancel_after_completion():
        await service.launch(request)
        await asyncio.wait_for(gateway.completed.wait(), timeout=10)
        cancelled = await service.cancel(request.run_id)
        permit = await authority.get_permit(cancelled.action_permits[0].permit_id)
        events = await store.events(request.run_id)
        await service.aclose()
        return cancelled, permit, events

    cancelled, durable_permit, events = asyncio.run(cancel_after_completion())
    projected_permit = cancelled.action_permits[0]

    assert cancelled.lifecycle is RecoveryRunLifecycle.CANCELLED
    assert cancelled.failure_category is RecoveryRunFailureCategory.CANCELLED
    assert projected_permit.state is ActionPermitState.COMPLETED
    assert projected_permit == durable_permit
    assert gateway.provider_calls == 1
    assert tuple(event.type for event in events.events[-2:]) == (
        RecoveryRunEventType.ACTION_PERMIT,
        RecoveryRunEventType.LIFECYCLE,
    )


@pytest.mark.parametrize(
    ("planner", "expected"),
    (
        (_Planner(failure=PlannerFailureKind.TIMEOUT), "MODEL_TIMEOUT"),
        (_Planner(output=_output(probe_count=2)), "MALFORMED_MODEL_OUTPUT"),
    ),
)
def test_model_failure_uses_the_same_fixed_evidence_and_verifier(
    tmp_path,
    planner: _Planner,
    expected: str,
) -> None:
    definition, states = _definition_and_states()
    request = RecoveryRunRequest(
        schema_version=RECOVERY_RUN_REQUEST_VERSION,
        run_id=f"recovery-model-{expected.lower()}",
        scenario="cloud-run-rollout",
        policy=RecoveryRunPolicy.ADAPTIVE,
        fault=RecoveryRunFault.DROP_AFTER_ACCEPT,
    )
    store = InMemoryRecoveryRunStore()
    authority = PermitAuthority(
        SqliteDurableRuntimeStore(tmp_path / f"{expected}.sqlite3"),
        clock=lambda: NOW + timedelta(seconds=7),
    )
    evidence = _Evidence(states)
    workflow = ProofToPermitWorkflow(
        store=store,
        definition_factory=lambda _request: definition,
        evidence_source=evidence,
        action_preparer=_Preparer(),
        recovery_agent=RecoveryAgent(planner),
        rollout_agent=RolloutAgent(_Gateway(store, authority, definition)),
        permit_authority=authority,
        clock=lambda: NOW + timedelta(seconds=7),
        claim_id_factory=iter(
            ("claim-launch", "claim-promote", "claim-record")
        ).__next__,
    )

    async def exercise():
        await store.create(request, definition.chain, created_at=NOW)
        completed = await workflow.run(request.run_id)
        events = await store.events(request.run_id)
        return completed, events

    completed, events = asyncio.run(exercise())
    dispositions = tuple(
        event.payload.hypothesis_disposition.value
        for event in events.events
        if event.type is RecoveryRunEventType.HYPOTHESIS
    )
    assert completed.lifecycle is RecoveryRunLifecycle.COMPLETED
    assert evidence.fixed_calls == ["stage", "promote", "record"]
    assert dispositions == (expected, expected, expected)
