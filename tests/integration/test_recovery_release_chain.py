"""Concrete stage -> promote -> release-record recovery acceptance coverage."""

from __future__ import annotations

import asyncio
import json
from datetime import UTC, datetime, timedelta

import pytest
from google.api_core import exceptions as api_exceptions
from google.cloud import run_v2

from reconcile.contracts import (
    ADAPTIVE_PLANNER_OUTPUT_VERSION,
    PROBE_REQUEST_VERSION,
    RECOVERY_RUN_REQUEST_VERSION,
    ActionPermitState,
    AdaptivePlannerOutput,
    Classification,
    PermitAction,
    PlannerAcquisitionAdvice,
    PlannerCitationRefs,
    PlannerExplanation,
    PlannerStopAdvice,
    ProbeRequest,
    RecoveryDecision,
    RecoveryReceiptOutcome,
    RecoveryRunFault,
    RecoveryRunLifecycle,
    RecoveryRunPolicy,
    RecoveryRunRequest,
    VerifiedCertificate,
)
from reconcile.controller.permits import PermitAuthority
from reconcile.evidence.recovery_verification import verify_recovery
from reconcile.hosted.cloud_run_canary import (
    CLOUD_RUN_CANARY_HEALTH_VERSION,
    CloudRunCanaryActionAdapter,
    CloudRunCanaryFaultProxy,
    CloudRunCanaryReader,
    CloudRunCanaryTarget,
    CloudRunFaultMode,
)
from reconcile.hosted.firestore_release import (
    FIRESTORE_RELEASE_RECORD_VERSION,
    FirestoreReleaseRecord,
    GoogleFirestoreReleaseTarget,
)
from reconcile.persistence import InMemoryRecoveryRunStore, SqliteDurableRuntimeStore
from reconcile.recovery_agents import RecoveryAgent
from reconcile.recovery_scenario import (
    BlindPolicyExecutor,
    RecoveryLaneBaseline,
    RecoveryPolicyComparisonRunner,
    RecoveryPolicyResultRecorder,
    ReleaseChainBlindMutator,
    ReleaseChainError,
    ReleaseChainEvidenceSource,
    ReleaseChainLaneResources,
    ReleaseChainPolicyLaneExecutor,
    ReleaseChainResetter,
    ReleaseChainSettings,
    build_release_chain_definition,
    build_release_chain_workflow,
    recovery_experiment_binding,
)
from tests.unit.test_recovery_agents import _output, _Planner

pytestmark = pytest.mark.integration

NOW = datetime(2026, 8, 22, 12, 0, tzinfo=UTC)
PROJECT = "demo-project"
LOCATION = "us-central1"
SERVICE = "reconcile-canary"
BASELINE = "reconcile-canary-baseline"
SERVICE_URI = "https://reconcile-canary-demo-hash-uc.a.run.app"


def _ready() -> run_v2.Condition:
    return run_v2.Condition(
        type_="Ready",
        state=run_v2.Condition.State.CONDITION_SUCCEEDED,
    )


def _pending() -> run_v2.Condition:
    return run_v2.Condition(
        type_="Ready",
        state=run_v2.Condition.State.CONDITION_RECONCILING,
    )


class _Accepted:
    def __init__(self, name: str) -> None:
        self.name = name


class _CloudState:
    def __init__(self, settings: ReleaseChainSettings) -> None:
        self.settings = settings
        self.generation = 1
        self.update_count = 0
        self.revision_read_count = 0
        self.health_ready = True
        self.provider_reads_unavailable_after_stage = False
        self.unhealthy_after_stage = False
        self.pending_reset_reads = 0
        self.pending_reset_traffic = None
        self.service_read_count = 0
        self.stage_pending = False
        self.ready_on_revision_read = None
        self.revisions = {
            BASELINE: run_v2.Revision(
                name=f"projects/{PROJECT}/locations/{LOCATION}/services/{SERVICE}/revisions/{BASELINE}",
                service=f"projects/{PROJECT}/locations/{LOCATION}/services/{SERVICE}",
                generation=1,
                observed_generation=1,
                containers=(
                    run_v2.Container(
                        image=(
                            f"{LOCATION}-docker.pkg.dev/{PROJECT}/reconcile-p5/"
                            f"reconcile@{settings.image_digest}"
                        )
                    ),
                ),
                conditions=(_ready(),),
            )
        }
        self.service = run_v2.Service(
            name=f"projects/{PROJECT}/locations/{LOCATION}/services/{SERVICE}",
            etag="etag-1",
            generation=1,
            observed_generation=1,
            terminal_condition=_ready(),
            reconciling=False,
            uri=SERVICE_URI,
            latest_ready_revision=BASELINE,
            template=run_v2.RevisionTemplate(
                containers=(
                    run_v2.Container(
                        image=(
                            f"{LOCATION}-docker.pkg.dev/{PROJECT}/reconcile-p5/"
                            f"reconcile@{settings.image_digest}"
                        )
                    ),
                )
            ),
            traffic_statuses=(
                run_v2.TrafficTargetStatus(revision=BASELINE, percent=100),
            ),
        )

    @property
    def service_name(self) -> str:
        return f"projects/{PROJECT}/locations/{LOCATION}/services/{SERVICE}"

    def _statuses(self, traffic) -> tuple[run_v2.TrafficTargetStatus, ...]:
        values = []
        for item in traffic:
            uri = (
                f"https://{item.tag}---{SERVICE_URI.removeprefix('https://')}"
                if item.tag
                else ""
            )
            values.append(
                run_v2.TrafficTargetStatus(
                    revision=item.revision,
                    percent=item.percent,
                    tag=item.tag,
                    uri=uri,
                )
            )
        return tuple(values)

    def update(self, request: run_v2.UpdateServiceRequest):
        candidate = request.service
        paths = tuple(request.update_mask.paths)
        if "template" in paths:
            template = candidate.template
            revision = template.revision
            self.revisions[revision] = run_v2.Revision(
                name=f"{self.service_name}/revisions/{revision}",
                service=self.service_name,
                generation=1,
                observed_generation=1,
                labels=dict(template.labels),
                annotations=dict(template.annotations),
                containers=tuple(template.containers),
                conditions=((_pending(),) if self.stage_pending else (_ready(),)),
                reconciling=self.stage_pending,
            )
            if self.stage_pending:
                self.health_ready = False
            self.service.template = template
            self.service.latest_ready_revision = revision
        candidate_statuses = self._statuses(candidate.traffic)
        resetting = (
            paths == ("traffic",)
            and len(candidate_statuses) == 1
            and candidate_statuses[0].revision == BASELINE
            and candidate_statuses[0].percent == 100
        )
        if resetting and self.pending_reset_reads:
            self.pending_reset_traffic = candidate_statuses
            self.service.reconciling = True
            self.service.terminal_condition = _pending()
        else:
            self.service.traffic_statuses = candidate_statuses
        self.generation += 1
        self.update_count += 1
        self.service.generation = self.generation
        self.service.observed_generation = self.generation
        self.service.etag = f"etag-{self.generation}"
        if self.pending_reset_traffic is None:
            self.service.terminal_condition = _ready()
            self.service.reconciling = False
        return _Accepted(
            f"projects/{PROJECT}/locations/{LOCATION}/operations/op-{self.update_count}"
        )


class _Services:
    def __init__(self, state: _CloudState) -> None:
        self.state = state

    def get_service(self, **_kwargs):
        if (
            self.state.provider_reads_unavailable_after_stage
            and self.state.update_count
        ):
            raise api_exceptions.ServiceUnavailable("provider unavailable")
        self.state.service_read_count += 1
        if self.state.pending_reset_traffic is not None:
            self.state.pending_reset_reads -= 1
            if self.state.pending_reset_reads <= 0:
                self.state.service.traffic_statuses = self.state.pending_reset_traffic
                self.state.pending_reset_traffic = None
                self.state.service.reconciling = False
                self.state.service.terminal_condition = _ready()
        return run_v2.Service(self.state.service)

    def update_service(self, **kwargs):
        return self.state.update(kwargs["request"])

    def get_operation(self, **_kwargs):
        raise api_exceptions.NotFound("operation intentionally unavailable")


class _Revisions:
    def __init__(self, state: _CloudState) -> None:
        self.state = state

    def list_revisions(self, **_kwargs):
        if (
            self.state.provider_reads_unavailable_after_stage
            and self.state.update_count
        ):
            raise api_exceptions.ServiceUnavailable("provider unavailable")
        return tuple(run_v2.Revision(value) for value in self.state.revisions.values())

    def get_revision(self, **kwargs):
        if (
            self.state.provider_reads_unavailable_after_stage
            and self.state.update_count
        ):
            raise api_exceptions.ServiceUnavailable("provider unavailable")
        self.state.revision_read_count += 1
        revision = kwargs["request"].name.rsplit("/", 1)[-1]
        if (
            self.state.ready_on_revision_read == self.state.revision_read_count
            and revision != BASELINE
        ):
            self.state.revisions[revision].conditions = (_ready(),)
            self.state.revisions[revision].reconciling = False
            self.state.health_ready = True
        try:
            return run_v2.Revision(self.state.revisions[revision])
        except KeyError:
            raise api_exceptions.NotFound("missing") from None


class _Health:
    def __init__(
        self,
        settings: ReleaseChainSettings,
        state: _CloudState,
    ) -> None:
        self.settings = settings
        self.state = state

    def get(self, **_kwargs):
        if self.state.unhealthy_after_stage or not self.state.health_ready:
            return 503, b"{}"
        return 200, json.dumps(
            {
                "schema_version": CLOUD_RUN_CANARY_HEALTH_VERSION,
                "release_id": self.settings.release_id,
                "revision": self.settings.staged_revision,
                "status": "READY",
                "image_digest": self.settings.image_digest,
                "configuration_sha256": self.settings.configuration_sha256,
            },
            separators=(",", ":"),
            sort_keys=True,
        ).encode()


class _WriteResult:
    def __init__(self, update_time: datetime) -> None:
        self.update_time = update_time


class _DocumentSnapshot:
    def __init__(self, reference: _DocumentReference) -> None:
        self.reference = reference
        self.exists = reference.data is not None
        self.read_time = NOW + timedelta(seconds=1)
        self.update_time = reference.update_time if self.exists else None

    def to_dict(self):
        return None if self.reference.data is None else dict(self.reference.data)


class _DocumentReference:
    def __init__(self, path: str) -> None:
        self.path = path
        self.data = None
        self.update_time = None
        self.create_attempt_count = 0
        self.create_count = 0

    async def get(self, **_kwargs):
        return _DocumentSnapshot(self)

    async def create(self, data, **_kwargs):
        self.create_attempt_count += 1
        if self.data is not None:
            raise api_exceptions.AlreadyExists("exists")
        self.data = dict(data)
        self.create_count += 1
        self.update_time = NOW + timedelta(seconds=1)
        return _WriteResult(self.update_time)

    async def delete(self, **_kwargs):
        self.data = None
        self.update_time = None
        return _WriteResult(NOW + timedelta(seconds=2))


class _FirestoreClient:
    def __init__(self) -> None:
        self.references = {}

    def document(self, *segments):
        path = "/".join(segments)
        return self.references.setdefault(path, _DocumentReference(path))

    def write_option(self, **kwargs):
        return kwargs["last_update_time"]


def _settings() -> ReleaseChainSettings:
    return ReleaseChainSettings(
        project=PROJECT,
        location=LOCATION,
        service=SERVICE,
        release_id="release-7",
        image_digest="sha256:" + "a" * 64,
        configuration_sha256="b" * 64,
        payload_sha256="c" * 64,
    )


def _provider(settings: ReleaseChainSettings):
    state = _CloudState(settings)
    services = _Services(state)
    revisions = _Revisions(state)
    target = CloudRunCanaryTarget(
        project=PROJECT,
        location=LOCATION,
        service=SERVICE,
        image_repository=f"{LOCATION}-docker.pkg.dev/{PROJECT}/reconcile-p5/reconcile",
        baseline_revision=BASELINE,
        health_audience="https://canary.example.test",
    )
    adapter = CloudRunCanaryActionAdapter(
        target=target,
        services_factory=lambda: services,
        revisions_factory=lambda: revisions,
        clock=lambda: NOW + timedelta(seconds=1),
    )
    reader = CloudRunCanaryReader(
        target=target,
        services_factory=lambda: services,
        revisions_factory=lambda: revisions,
        health_client=_Health(settings, state),
        clock=lambda: NOW + timedelta(seconds=1),
    )
    firestore_client = _FirestoreClient()
    firestore = GoogleFirestoreReleaseTarget(
        project_id=PROJECT,
        client_factory=lambda: firestore_client,
        clock=lambda: NOW + timedelta(seconds=1),
    )
    return (
        state,
        adapter,
        CloudRunCanaryFaultProxy(adapter),
        reader,
        firestore,
        firestore_client,
    )


class _ReleasePlanner(_Planner):
    def __init__(self) -> None:
        super().__init__(output=_output(probe_count=0))

    async def plan(self, planner_input):
        tool_name = planner_input.envelope.context.invocation.tool_name
        prior_count = len(planner_input.prior_executable_request_hashes)
        capability_name = None
        if tool_name == "stage-cloud-run-revision":
            capability_name = (
                "cloud-run-revision-get"
                if prior_count == 0
                else "cloud-run-revision-health"
                if prior_count == 1
                else None
            )
        elif tool_name == "create-firestore-release-record" and (
            planner_input.missing_evidence
        ):
            capability_name = "reconcile-dispatch-receipt-get"
        admitted = tuple(item.evidence_id for item in planner_input.admitted_evidence)
        missing = tuple(
            dict.fromkeys(
                effect_id
                for item in planner_input.missing_evidence
                for effect_id in item.effect_ids
            )
        )
        proposal = (
            ()
            if capability_name is None
            else (
                ProbeRequest(
                    schema_version=PROBE_REQUEST_VERSION,
                    capability_name=capability_name,
                    capability_version="1.0.0",
                    relevant_effect_ids=tuple(
                        effect.effect_id
                        for effect in planner_input.envelope.expected_effects
                    ),
                    arguments={},
                    rationale="Acquire the next exact provider observation.",
                ),
            )
        )
        self.output = AdaptivePlannerOutput(
            schema_version=ADAPTIVE_PLANNER_OUTPUT_VERSION,
            probe_proposals=proposal,
            acquisition_advice=PlannerAcquisitionAdvice(
                summary="Read one exact target-bound provider resource."
            ),
            stop_advice=PlannerStopAdvice(
                recommend_stop=not proposal,
                reason=(
                    "The deterministic report is sufficient."
                    if not proposal
                    else "Another allowlisted read can resolve the remaining history."
                ),
            ),
            missing_evidence_notes=(),
            explanation=PlannerExplanation(
                summary="Choose a bounded read; deterministic proof retains authority.",
                admitted_evidence=(
                    "The current provider reads are admitted." if admitted else None
                ),
                weak_evidence=None,
                rejected_evidence=None,
                missing_evidence=(
                    "These effects still need provider evidence." if missing else None
                ),
                citations=PlannerCitationRefs(
                    admitted_evidence_ids=admitted,
                    weak_evidence_ids=(),
                    rejected_evidence_ids=(),
                    missing_effect_ids=missing,
                ),
            ),
        )
        return await super().plan(planner_input)


def test_evidence_source_repolls_pending_provider_state_in_a_new_bounded_round() -> (
    None
):
    settings = _settings()
    state, _adapter, action, reader, firestore, _client = _provider(settings)
    action.stage_revision(
        mode=CloudRunFaultMode.PASS_THROUGH,
        operation_id=settings.stage_operation_id,
        release_id=settings.release_id,
        image_digest=settings.image_digest,
        configuration_sha256=settings.configuration_sha256,
    )
    staged = state.revisions[settings.staged_revision]
    staged.conditions = (_pending(),)
    staged.reconciling = True
    state.health_ready = False
    definition = build_release_chain_definition(settings, invoked_at=NOW)
    node = definition.chain.nodes[0]
    envelope = definition.envelopes[node.node_id]
    store = InMemoryRecoveryRunStore()
    source = ReleaseChainEvidenceSource(
        store=store,
        definition=definition,
        settings=settings,
        cloud_run=reader,
        firestore=firestore,
        clock=lambda: NOW + timedelta(seconds=2),
    )
    request = RecoveryRunRequest(
        schema_version=RECOVERY_RUN_REQUEST_VERSION,
        run_id="pending-to-ready-run",
        scenario="cloud-run-rollout",
        policy=RecoveryRunPolicy.FIXED,
        fault=RecoveryRunFault.DROP_AFTER_ACCEPT,
    )

    async def exercise():
        await store.create(request, definition.chain, created_at=NOW)
        await source.current(request.run_id, node, envelope)
        pending = await source.fixed(request.run_id, node, envelope)
        staged.conditions = (_ready(),)
        staged.reconciling = False
        state.health_ready = True
        await source.current(request.run_id, node, envelope)
        terminal = await source.fixed(request.run_id, node, envelope)
        return pending, terminal

    pending, terminal = asyncio.run(exercise())

    pending_artifact = verify_recovery(
        chain=definition.chain,
        node_id=node.node_id,
        envelope=envelope,
        report=pending.report,
        evaluation=pending.evaluation,
        verified_at=pending.report.updated_at,
        successor_envelope=definition.envelopes["promote"],
    )
    terminal_artifact = verify_recovery(
        chain=definition.chain,
        node_id=node.node_id,
        envelope=envelope,
        report=terminal.report,
        evaluation=terminal.evaluation,
        verified_at=terminal.report.updated_at,
        successor_envelope=definition.envelopes["promote"],
    )

    assert pending.evaluation.classification is Classification.PENDING
    assert terminal.evaluation.classification is Classification.COMMITTED
    assert isinstance(pending_artifact, VerifiedCertificate)
    assert pending_artifact.classification is Classification.PENDING
    assert pending_artifact.transition is None
    assert isinstance(terminal_artifact, VerifiedCertificate)
    assert terminal_artifact.classification is Classification.COMMITTED
    assert terminal_artifact.transition is not None
    assert len(pending.report.probe_audit) == 3
    assert len(terminal.report.probe_audit) == 3
    assert state.revision_read_count == 2


def test_fixed_workflow_observes_pending_then_resumes_on_terminal_evidence(
    tmp_path,
) -> None:
    settings = _settings()
    state, _adapter, action, reader, firestore, _client = _provider(settings)
    state.stage_pending = True
    state.ready_on_revision_read = 8
    store = InMemoryRecoveryRunStore()
    authority = PermitAuthority(
        SqliteDurableRuntimeStore(tmp_path / "pending-resume.sqlite3"),
        clock=lambda: NOW + timedelta(seconds=2),
    )
    workflow = build_release_chain_workflow(
        settings=settings,
        invoked_at=NOW,
        store=store,
        permit_authority=authority,
        recovery_agent=RecoveryAgent(_Planner(output=_output(probe_count=0))),
        cloud_action=action,
        cloud_reader=reader,
        firestore=firestore,
        clock=lambda: NOW + timedelta(seconds=2),
    )
    request = RecoveryRunRequest(
        schema_version=RECOVERY_RUN_REQUEST_VERSION,
        run_id="fixed-pending-resume",
        scenario="cloud-run-rollout",
        policy=RecoveryRunPolicy.FIXED,
        fault=RecoveryRunFault.DROP_AFTER_ACCEPT,
    )
    recorder = RecoveryPolicyResultRecorder(
        settings=settings,
        baseline_revision=BASELINE,
        cloud_reader=reader,
        firestore=firestore,
    )

    async def exercise():
        baseline = await recorder.capture_baseline()
        definition = await workflow.definition(request)
        await store.create(request, definition.chain, created_at=NOW)
        snapshot = await workflow.run(request.run_id)
        events = await store.events(request.run_id)
        result = await recorder.record_proof(
            snapshot=snapshot,
            events=events,
            binding=recovery_experiment_binding(
                settings,
                RecoveryRunFault.DROP_AFTER_ACCEPT,
            ),
            baseline=baseline,
        )
        return snapshot, events, result

    snapshot, events, result = asyncio.run(exercise())
    decisions = tuple(
        event.payload.decision
        for event in events.events
        if event.type.value == "DECISION"
    )

    assert snapshot.lifecycle is RecoveryRunLifecycle.COMPLETED
    assert decisions[:7] == (RecoveryDecision.OBSERVE,) * 7
    assert decisions[7] is RecoveryDecision.CONTINUE
    assert len(snapshot.certificates) == 10
    assert len(result.certificate_sha256s) == 10
    assert state.revision_read_count >= 3
    assert state.update_count == 2


@pytest.mark.parametrize("evidence_condition", ["missing", "conflicting"])
def test_missing_or_conflicting_evidence_witnesses_without_an_extra_mutation(
    tmp_path,
    evidence_condition: str,
) -> None:
    settings = _settings()
    state, _adapter, action, reader, firestore, _client = _provider(settings)
    state.provider_reads_unavailable_after_stage = evidence_condition == "missing"
    state.unhealthy_after_stage = evidence_condition == "conflicting"
    store = InMemoryRecoveryRunStore()
    authority = PermitAuthority(
        SqliteDurableRuntimeStore(tmp_path / f"{evidence_condition}.sqlite3"),
        clock=lambda: NOW + timedelta(seconds=2),
    )
    workflow = build_release_chain_workflow(
        settings=settings,
        invoked_at=NOW,
        store=store,
        permit_authority=authority,
        recovery_agent=RecoveryAgent(_Planner(output=_output(probe_count=0))),
        cloud_action=action,
        cloud_reader=reader,
        firestore=firestore,
        clock=lambda: NOW + timedelta(seconds=2),
    )
    request = RecoveryRunRequest(
        schema_version=RECOVERY_RUN_REQUEST_VERSION,
        run_id=f"fixed-{evidence_condition}-evidence",
        scenario="cloud-run-rollout",
        policy=RecoveryRunPolicy.FIXED,
        fault=RecoveryRunFault.DROP_AFTER_ACCEPT,
    )

    async def exercise():
        definition = await workflow.definition(request)
        await store.create(request, definition.chain, created_at=NOW)
        return await workflow.run(request.run_id)

    snapshot = asyncio.run(exercise())

    assert snapshot.lifecycle is RecoveryRunLifecycle.ESCALATED
    assert len(snapshot.witnesses) == 1
    assert snapshot.action_permits == ()
    assert state.update_count == 1
    assert state.service.traffic_statuses[0].revision == BASELINE


@pytest.mark.parametrize(
    "fault",
    [RecoveryRunFault.DROP_AFTER_ACCEPT, RecoveryRunFault.SUPPRESS_BEFORE_DISPATCH],
)
@pytest.mark.parametrize(
    "policy",
    [RecoveryRunPolicy.FIXED, RecoveryRunPolicy.ADAPTIVE],
)
def test_proof_to_permit_completes_once_and_suppression_retries_once(
    tmp_path,
    fault: RecoveryRunFault,
    policy: RecoveryRunPolicy,
) -> None:
    settings = _settings()
    (
        cloud_state,
        cloud_adapter,
        cloud_action,
        cloud_reader,
        firestore,
        firestore_client,
    ) = _provider(settings)
    store = InMemoryRecoveryRunStore()
    authority = PermitAuthority(
        SqliteDurableRuntimeStore(tmp_path / f"{fault.value}.sqlite3"),
        clock=lambda: NOW + timedelta(seconds=2),
    )
    workflow = build_release_chain_workflow(
        settings=settings,
        invoked_at=NOW,
        store=store,
        permit_authority=authority,
        recovery_agent=RecoveryAgent(
            (
                _ReleasePlanner()
                if policy is RecoveryRunPolicy.ADAPTIVE
                else _Planner(output=_output(probe_count=0))
            ),
            clock=lambda: NOW + timedelta(seconds=2),
        ),
        cloud_action=(
            cloud_adapter
            if fault is RecoveryRunFault.SUPPRESS_BEFORE_DISPATCH
            else cloud_action
        ),
        cloud_reader=cloud_reader,
        firestore=firestore,
        clock=lambda: NOW + timedelta(seconds=2),
    )
    request = RecoveryRunRequest(
        schema_version=RECOVERY_RUN_REQUEST_VERSION,
        run_id=f"{policy.value}-{fault.value}",
        scenario="cloud-run-rollout",
        policy=policy,
        fault=fault,
    )
    recorder = RecoveryPolicyResultRecorder(
        settings=settings,
        baseline_revision=BASELINE,
        cloud_reader=cloud_reader,
        firestore=firestore,
    )

    async def exercise():
        baseline = await recorder.capture_baseline()
        definition = await workflow.definition(request)
        await store.create(request, definition.chain, created_at=NOW)
        snapshot = await workflow.run(request.run_id)
        events = await store.events(request.run_id)
        policy_result = await recorder.record_proof(
            snapshot=snapshot,
            events=events,
            binding=recovery_experiment_binding(settings, fault),
            baseline=baseline,
        )
        promoted = cloud_reader.read_service(
            release_id=settings.release_id,
            revision=settings.staged_revision,
        )
        release_record = await firestore.read(settings.release_id)
        reset = await ReleaseChainResetter(
            settings=settings,
            cloud_action=cloud_adapter,
            cloud_reader=cloud_reader,
            firestore=firestore,
            baseline_revision=BASELINE,
            clock=lambda: NOW + timedelta(seconds=3),
        ).reset()
        return snapshot, policy_result, promoted, release_record, reset

    snapshot, policy_result, promoted, release_record, reset = asyncio.run(exercise())
    release_revisions = tuple(
        name for name in cloud_state.revisions if name != BASELINE
    )
    release_reference = next(iter(firestore_client.references.values()))

    assert snapshot.lifecycle is RecoveryRunLifecycle.COMPLETED
    assert policy_result.run_id == request.run_id
    assert policy_result.chain_completed is True
    assert policy_result.counters.revisions_created == 1
    assert policy_result.counters.promotions_accepted == 1
    assert policy_result.counters.release_records_created == 1
    assert policy_result.firestore.cloud_run_revision == settings.staged_revision
    assert policy_result.counters.continue_permits_issued == 2
    assert policy_result.counters.retry_permits_issued == (
        1 if fault is RecoveryRunFault.SUPPRESS_BEFORE_DISPATCH else 0
    )
    assert policy_result.counters.retry_permits_consumed == (
        1 if fault is RecoveryRunFault.SUPPRESS_BEFORE_DISPATCH else 0
    )
    assert release_revisions == (settings.staged_revision,)
    assert cloud_state.update_count == 3
    assert release_reference.create_count == 1
    assert release_reference.data is None
    assert promoted.revision_traffic_percent == 100
    assert release_record is not None
    assert release_record.record.cloud_run_revision == settings.staged_revision
    assert reset.release_revisions_before == (settings.staged_revision,)
    assert reset.release_revisions_after == (settings.staged_revision,)
    assert reset.serving_revision == BASELINE
    assert reset.serving_percent == 100
    assert reset.release_record_absent is True
    assert all(
        permit.state is ActionPermitState.COMPLETED
        for permit in snapshot.action_permits
    )
    assert tuple(receipt.outcome for receipt in snapshot.dispatch_receipts).count(
        RecoveryReceiptOutcome.SUPPRESSED_BEFORE_DISPATCH
    ) == (1 if fault is RecoveryRunFault.SUPPRESS_BEFORE_DISPATCH else 0)
    retries = tuple(
        permit
        for permit in snapshot.action_permits
        if permit.action is PermitAction.RETRY
    )
    assert len(retries) == (
        1 if fault is RecoveryRunFault.SUPPRESS_BEFORE_DISPATCH else 0
    )
    assert bool(snapshot.hypotheses) is (policy is RecoveryRunPolicy.ADAPTIVE)


@pytest.mark.parametrize("mismatch", ["wrong-revision", "wrong-semantic-action"])
def test_wrong_release_record_binding_yields_ambiguity_without_retry(
    tmp_path,
    mismatch: str,
) -> None:
    settings = _settings()
    state, _adapter, action, reader, firestore, firestore_client = _provider(settings)
    definition = build_release_chain_definition(settings, invoked_at=NOW)
    record_action = definition.chain.nodes[-1].semantic_action
    reference = firestore_client.document("releases", settings.release_id)
    reference.data = FirestoreReleaseRecord(
        schema_version=FIRESTORE_RELEASE_RECORD_VERSION,
        release_id=settings.release_id,
        cloud_run_revision=(
            f"{SERVICE}-wrong-revision"
            if mismatch == "wrong-revision"
            else settings.staged_revision
        ),
        payload_sha256=settings.payload_sha256,
        semantic_action_sha256=(
            "f" * 64
            if mismatch == "wrong-semantic-action"
            else record_action.semantic_action_sha256
        ),
        created_at=NOW,
    ).model_dump(mode="python")
    reference.update_time = NOW
    store = InMemoryRecoveryRunStore()
    authority = PermitAuthority(
        SqliteDurableRuntimeStore(tmp_path / f"{mismatch}.sqlite3"),
        clock=lambda: NOW + timedelta(seconds=2),
    )
    workflow = build_release_chain_workflow(
        settings=settings,
        invoked_at=NOW,
        store=store,
        permit_authority=authority,
        recovery_agent=RecoveryAgent(_Planner(output=_output(probe_count=0))),
        cloud_action=action,
        cloud_reader=reader,
        firestore=firestore,
        clock=lambda: NOW + timedelta(seconds=2),
    )
    request = RecoveryRunRequest(
        schema_version=RECOVERY_RUN_REQUEST_VERSION,
        run_id=f"fixed-{mismatch}",
        scenario="cloud-run-rollout",
        policy=RecoveryRunPolicy.FIXED,
        fault=RecoveryRunFault.DROP_AFTER_ACCEPT,
    )

    async def exercise():
        await store.create(request, definition.chain, created_at=NOW)
        return await workflow.run(request.run_id)

    snapshot = asyncio.run(exercise())

    assert snapshot.lifecycle is RecoveryRunLifecycle.ESCALATED
    assert len(snapshot.witnesses) == 1
    assert all(
        permit.action is PermitAction.CONTINUE for permit in snapshot.action_permits
    )
    assert state.update_count == 2
    assert reference.create_attempt_count == 1
    assert reference.create_count == 0


def test_policy_result_reports_the_observed_firestore_identity() -> None:
    settings = _settings()
    _state, _adapter, _action, reader, firestore, firestore_client = _provider(settings)
    reference = firestore_client.document("releases", settings.release_id)
    reference.data = FirestoreReleaseRecord(
        schema_version=FIRESTORE_RELEASE_RECORD_VERSION,
        release_id=settings.release_id,
        cloud_run_revision=settings.staged_revision,
        payload_sha256="d" * 64,
        semantic_action_sha256="e" * 64,
        created_at=NOW,
    ).model_dump(mode="python")
    reference.update_time = NOW
    recorder = RecoveryPolicyResultRecorder(
        settings=settings,
        baseline_revision=BASELINE,
        cloud_reader=reader,
        firestore=firestore,
    )

    _cloud, observed, _revisions, _promotions, records = asyncio.run(
        recorder._observe_provider(RecoveryLaneBaseline(release_revisions=()))
    )

    assert records == 1
    assert observed.payload_sha256 == "d" * 64
    assert observed.semantic_action_sha256 == "e" * 64


def test_reset_waits_for_settled_baseline_and_supports_the_fault_proxy() -> None:
    settings = _settings()
    state, _adapter, action, reader, firestore, _client = _provider(settings)
    definition = build_release_chain_definition(settings, invoked_at=NOW)

    async def no_sleep(_seconds: float) -> None:
        return None

    async def exercise():
        action.stage_revision(
            mode=CloudRunFaultMode.PASS_THROUGH,
            operation_id=settings.stage_operation_id,
            release_id=settings.release_id,
            image_digest=settings.image_digest,
            configuration_sha256=settings.configuration_sha256,
        )
        service = reader.read_service(
            release_id=settings.release_id,
            revision=settings.staged_revision,
        )
        action.promote_revision(
            mode=CloudRunFaultMode.PASS_THROUGH,
            release_id=settings.release_id,
            revision=settings.staged_revision,
            service_etag=service.service_etag,
        )
        await firestore.create(
            FirestoreReleaseRecord(
                schema_version=FIRESTORE_RELEASE_RECORD_VERSION,
                release_id=settings.release_id,
                cloud_run_revision=settings.staged_revision,
                payload_sha256=settings.payload_sha256,
                semantic_action_sha256=definition.chain.nodes[
                    -1
                ].semantic_action.semantic_action_sha256,
                created_at=NOW,
            )
        )
        state.pending_reset_reads = 3
        return await ReleaseChainResetter(
            settings=settings,
            cloud_action=action,
            cloud_reader=reader,
            firestore=firestore,
            baseline_revision=BASELINE,
            clock=lambda: NOW + timedelta(seconds=3),
            max_observations=4,
            poll_interval_seconds=0,
            sleep=no_sleep,
        ).reset()

    result = asyncio.run(exercise())

    assert result.serving_revision == BASELINE
    assert result.serving_percent == 100
    assert result.release_record_absent is True
    assert state.pending_reset_traffic is None


def test_reset_fails_closed_when_cloud_run_never_settles() -> None:
    settings = _settings()
    state, _adapter, action, reader, firestore, _client = _provider(settings)
    definition = build_release_chain_definition(settings, invoked_at=NOW)

    async def no_sleep(_seconds: float) -> None:
        return None

    async def exercise():
        await firestore.create(
            FirestoreReleaseRecord(
                schema_version=FIRESTORE_RELEASE_RECORD_VERSION,
                release_id=settings.release_id,
                cloud_run_revision=settings.staged_revision,
                payload_sha256=settings.payload_sha256,
                semantic_action_sha256=definition.chain.nodes[
                    -1
                ].semantic_action.semantic_action_sha256,
                created_at=NOW,
            )
        )
        state.pending_reset_reads = 100
        resetter = ReleaseChainResetter(
            settings=settings,
            cloud_action=action,
            cloud_reader=reader,
            firestore=firestore,
            baseline_revision=BASELINE,
            clock=lambda: NOW + timedelta(seconds=3),
            max_observations=2,
            poll_interval_seconds=0,
            sleep=no_sleep,
        )
        with pytest.raises(ReleaseChainError, match="safe baseline"):
            await resetter.reset()
        return await firestore.read(settings.release_id)

    assert asyncio.run(exercise()) is not None


def test_provider_backed_blind_baselines_expose_duplicate_and_incomplete_release() -> (
    None
):
    settings = _settings()
    retry = _provider(settings)
    abort = _provider(settings)
    retry_mutator = ReleaseChainBlindMutator(
        settings=settings,
        cloud_action=retry[2],
        cloud_reader=retry[3],
        firestore=retry[4],
        invoked_at=NOW,
        clock=lambda: NOW + timedelta(seconds=2),
    )
    abort_mutator = ReleaseChainBlindMutator(
        settings=settings,
        cloud_action=abort[2],
        cloud_reader=abort[3],
        firestore=abort[4],
        invoked_at=NOW,
        clock=lambda: NOW + timedelta(seconds=2),
    )
    retry_recorder = RecoveryPolicyResultRecorder(
        settings=settings,
        baseline_revision=BASELINE,
        cloud_reader=retry[3],
        firestore=retry[4],
    )
    abort_recorder = RecoveryPolicyResultRecorder(
        settings=settings,
        baseline_revision=BASELINE,
        cloud_reader=abort[3],
        firestore=abort[4],
    )

    async def exercise():
        retry_baseline = await retry_recorder.capture_baseline()
        abort_baseline = await abort_recorder.capture_baseline()
        retry_outcome = await BlindPolicyExecutor(retry_mutator).blind_retry(
            operation_id=settings.stage_operation_id,
            fault=RecoveryRunFault.DROP_AFTER_ACCEPT,
        )
        abort_outcome = await BlindPolicyExecutor(abort_mutator).blind_abort(
            operation_id=settings.stage_operation_id,
            fault=RecoveryRunFault.DROP_AFTER_ACCEPT,
        )
        retry_result = await retry_recorder.record_blind(
            run_id="blind-retry-drop-run",
            policy=RecoveryRunPolicy.BLIND_RETRY,
            fault=RecoveryRunFault.DROP_AFTER_ACCEPT,
            binding=recovery_experiment_binding(
                settings, RecoveryRunFault.DROP_AFTER_ACCEPT
            ),
            baseline=retry_baseline,
            outcome=retry_outcome,
        )
        abort_result = await abort_recorder.record_blind(
            run_id="blind-abort-drop-run",
            policy=RecoveryRunPolicy.BLIND_ABORT,
            fault=RecoveryRunFault.DROP_AFTER_ACCEPT,
            binding=recovery_experiment_binding(
                settings, RecoveryRunFault.DROP_AFTER_ACCEPT
            ),
            baseline=abort_baseline,
            outcome=abort_outcome,
        )
        return retry_outcome, abort_outcome, retry_result, abort_result

    retry_completed, abort_completed, retry_result, abort_result = asyncio.run(
        exercise()
    )
    retry_revisions = retry[3].list_release_revisions(
        release_id=settings.release_id,
        image_digest=settings.image_digest,
        configuration_sha256=settings.configuration_sha256,
    )
    abort_revisions = abort[3].list_release_revisions(
        release_id=settings.release_id,
        image_digest=settings.image_digest,
        configuration_sha256=settings.configuration_sha256,
    )

    assert retry_completed.chain_completed is True
    assert retry_completed.provider_contacts == 4
    assert retry_result.chain_completed is True
    assert retry_result.counters.revisions_created == 2
    assert retry_result.counters.promotions_accepted == 1
    assert retry_result.counters.release_records_created == 1
    assert retry_result.counters.provider_contacts == 4
    assert len(retry_revisions) == 2
    assert retry[0].update_count == 3
    assert next(iter(retry[5].references.values())).create_count == 1
    assert abort_completed.chain_completed is False
    assert abort_completed.provider_contacts == 1
    assert abort_result.chain_completed is False
    assert abort_result.terminal_disposition == "ABORTED"
    assert abort_result.counters.revisions_created == 1
    assert abort_result.counters.promotions_accepted == 0
    assert abort_result.counters.release_records_created == 0
    assert abort_result.counters.provider_contacts == 1
    assert abort_revisions == (settings.staged_revision,)
    assert abort[0].update_count == 1
    assert abort[0].service.traffic_statuses[0].revision == BASELINE
    assert all(
        reference.data is None and reference.create_count == 0
        for reference in abort[5].references.values()
    )


def test_concrete_policy_harness_runs_four_isolated_provider_backed_lanes(
    tmp_path,
) -> None:
    settings = _settings()
    lane_index = 0

    def lane_factory(*, policy, fault, binding):
        nonlocal lane_index
        assert fault is RecoveryRunFault.DROP_AFTER_ACCEPT
        assert binding == recovery_experiment_binding(settings, fault)
        lane_index += 1
        _state, _adapter, action, reader, firestore, _client = _provider(settings)
        return ReleaseChainLaneResources(
            store=InMemoryRecoveryRunStore(),
            permit_authority=PermitAuthority(
                SqliteDurableRuntimeStore(tmp_path / f"lane-{lane_index}.sqlite3"),
                clock=lambda: NOW + timedelta(seconds=2),
            ),
            recovery_agent=RecoveryAgent(
                (
                    _ReleasePlanner()
                    if policy is RecoveryRunPolicy.ADAPTIVE
                    else _Planner(output=_output(probe_count=0))
                ),
                clock=lambda: NOW + timedelta(seconds=2),
            ),
            cloud_action=action,
            cloud_reader=reader,
            firestore=firestore,
            baseline_revision=BASELINE,
        )

    lanes = ReleaseChainPolicyLaneExecutor(
        settings=settings,
        invoked_at=NOW,
        lane_factory=lane_factory,
        clock=lambda: NOW + timedelta(seconds=2),
        reset_poll_interval_seconds=0,
    )
    comparison = asyncio.run(
        RecoveryPolicyComparisonRunner(
            settings=settings,
            lane_executor=lanes,
            resetter=lanes,
            clock=lambda: NOW + timedelta(seconds=3),
        ).run(RecoveryRunFault.DROP_AFTER_ACCEPT)
    )

    assert tuple(lane.policy for lane in comparison.lanes) == (
        "blind-retry",
        "blind-abort",
        "fixed",
        "adaptive",
    )
    assert tuple(lane.counters.revisions_created for lane in comparison.lanes) == (
        2,
        1,
        1,
        1,
    )
    assert tuple(lane.chain_completed for lane in comparison.lanes) == (
        True,
        False,
        True,
        True,
    )
    assert len({lane.run_id for lane in comparison.lanes}) == 4
    assert lane_index == 4
    assert all(reset.release_record_absent for reset in comparison.reset_results)


def test_policy_lane_resumes_an_existing_durable_run(tmp_path) -> None:
    settings = _settings()
    state, adapter, _fault_proxy, reader, firestore, _client = _provider(settings)
    store = InMemoryRecoveryRunStore()
    resources = ReleaseChainLaneResources(
        store=store,
        permit_authority=PermitAuthority(
            SqliteDurableRuntimeStore(tmp_path / "resumed-lane.sqlite3"),
            clock=lambda: NOW + timedelta(seconds=2),
        ),
        recovery_agent=RecoveryAgent(
            _Planner(output=_output(probe_count=0)),
            clock=lambda: NOW + timedelta(seconds=2),
        ),
        cloud_action=adapter,
        cloud_reader=reader,
        firestore=firestore,
        baseline_revision=BASELINE,
    )
    executor = ReleaseChainPolicyLaneExecutor(
        settings=settings,
        invoked_at=NOW,
        lane_factory=lambda **_kwargs: resources,
        clock=lambda: NOW + timedelta(seconds=2),
        reset_poll_interval_seconds=0,
    )
    fault = RecoveryRunFault.SUPPRESS_BEFORE_DISPATCH
    binding = recovery_experiment_binding(settings, fault)
    run_id = executor._run_id(RecoveryRunPolicy.FIXED, fault, binding)
    request = RecoveryRunRequest(
        schema_version=RECOVERY_RUN_REQUEST_VERSION,
        run_id=run_id,
        scenario="cloud-run-rollout",
        policy=RecoveryRunPolicy.FIXED,
        fault=fault,
    )
    definition = build_release_chain_definition(settings, invoked_at=NOW)
    asyncio.run(store.create(request, definition.chain, created_at=NOW))

    result = asyncio.run(executor.execute(policy="fixed", fault=fault, binding=binding))

    assert result.chain_completed is True
    assert result.counters.revisions_created == 1
    assert result.counters.release_records_created == 1
    assert state.update_count == 2
