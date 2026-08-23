"""Provider-backed execution support for recovery qualification v1.

The qualification fixture describes provider behavior and expected assertions;
it never supplies the controller decision.  Every proof lane below runs the
production #171 evidence, verification, permit, dispatch, and persistence
components against SDK-level deterministic provider doubles.
"""

from __future__ import annotations

import asyncio
import hashlib
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, replace
from pathlib import Path

from reconcile.adaptive import (
    AdvisoryPlannerMetadata,
    AdvisoryPlannerTurn,
    AdvisoryPlannerUsage,
)
from reconcile.contracts import (
    ADAPTIVE_PLANNER_INPUT_VERSION,
    ADAPTIVE_PLANNER_OUTPUT_VERSION,
    PROBE_REQUEST_VERSION,
    RECOVERY_RUN_REQUEST_VERSION,
    ActionPermit,
    ActionPermitState,
    AdaptivePlannerInput,
    AdaptivePlannerOutput,
    AmbiguityWitness,
    ExecutionEnvelope,
    PermitAction,
    PlannerAcquisitionAdvice,
    PlannerCitationRefs,
    PlannerExplanation,
    PlannerStopAdvice,
    ProbeOutcome,
    ProbeRequest,
    RecoveryActionNode,
    RecoveryActionScope,
    RecoveryDecision,
    RecoveryHypothesisDisposition,
    RecoveryPreparedAction,
    RecoveryRunFault,
    RecoveryRunPolicy,
    RecoveryRunRequest,
    VerifiedCertificate,
    canonical_sha256,
)
from reconcile.contracts.base import canonical_json_value_bytes
from reconcile.contracts.recovery_qualification import (
    RecoveryQualificationArtifactKind,
    RecoveryQualificationModelUsage,
    RecoveryQualificationModelUsageStatus,
    RecoveryQualificationPolicy,
    RecoveryQualificationProviderMutations,
    RecoveryQualificationResolution,
)
from reconcile.controller import ControllerAuditRecord, ProbeStopReason
from reconcile.controller.permits import action_permit_from_certificate
from reconcile.evidence.classification import evaluate_evidence
from reconcile.evidence.recovery_verification import verify_recovery
from reconcile.hosted.cloud_run_canary import (
    CloudRunCanaryAction,
    CloudRunCanaryError,
    CloudRunCanaryErrorCode,
)
from reconcile.hosted.firestore_release import (
    FirestoreReleaseConflict,
    FirestoreReleaseOutcomeUnknown,
    FirestoreReleaseProviderUnavailable,
)
from reconcile.persistence.recovery_runs import RecoveryRunEventSnapshot
from reconcile.recovery_agents import (
    RecoveryAgent,
    RecoveryDispatchReceipt,
    RolloutAgent,
)
from reconcile.recovery_qualification_fixtures import RecoveryQualificationFixture
from reconcile.recovery_qualification_provider import (
    RecoveryQualificationFoundation,
    RecoveryQualificationProviderResources,
    RecoveryQualificationStores,
    build_recovery_qualification_foundation,
)
from reconcile.recovery_scenario import (
    ReleaseChainActionPreparer,
    ReleaseChainBlindMutator,
    ReleaseChainDispatchGateway,
    ReleaseChainEvidenceSource,
    build_release_chain_definition,
)
from reconcile.recovery_workflow import (
    ProofToPermitWorkflow,
    RecoveryEvidenceState,
    RecoveryRunDefinition,
)

_WRONG_VARIANTS = ("unknown-capability", "invalid-arguments", "foreign-effect")


@dataclass(frozen=True, slots=True)
class RecoveryQualificationWrongExecution:
    variant_id: str
    planner_output_sha256: str
    hypothesis_sha256: str | None
    disposition: RecoveryHypothesisDisposition
    decision_sha256: str
    permit_sha256: str | None


@dataclass(frozen=True, slots=True)
class RecoveryQualificationProofExecution:
    policy: RecoveryQualificationPolicy
    resolution: RecoveryQualificationResolution
    permit_action: PermitAction | None
    permit_sha256: str | None
    raw_permit_sha256: str | None
    admitted_evidence_sha256: str
    decision_sha256: str
    artifact_kind: RecoveryQualificationArtifactKind
    artifact_sha256: str
    ambiguity_witness_sha256: str | None
    probe_count: int
    time_to_sufficient_evidence_ms: int
    unsupported_probe_count: int
    provider_mutations: RecoveryQualificationProviderMutations
    model_usage: RecoveryQualificationModelUsage
    snapshot_sha256: str
    restarted_snapshot_sha256: str | None
    restarted_decision_sha256: str | None
    restarted_permit_sha256: str | None
    wrong_hypotheses: tuple[RecoveryQualificationWrongExecution, ...]
    witness_semantic_sha256: str | None
    reordered_witness_semantic_sha256: str | None
    duplicated_witness_semantic_sha256: str | None


@dataclass(frozen=True, slots=True)
class RecoveryQualificationBlindExecution:
    resolution: RecoveryQualificationResolution
    provider_mutations: RecoveryQualificationProviderMutations


class _ScriptedPlanner:
    """Deterministic Gemini-shaped planner with no mutation authority."""

    def __init__(self, variant: str = "normal") -> None:
        self.variant = variant
        self.turns: list[AdvisoryPlannerTurn] = []
        self.call_tools: list[str] = []
        self.calls_by_tool: dict[str, int] = {}
        self.last_output_sha256: str | None = None
        self.metadata = AdvisoryPlannerMetadata(
            provider_name="scripted-gemini",
            configured_model="gemini-scripted-qualification",
            reported_model="gemini-scripted-qualification",
            adk_version="qualification-v1",
            genai_version="qualification-v1",
            prompt_version="recovery-qualification-v1",
            prompt_sha256=hashlib.sha256(b"recovery-qualification-v1").hexdigest(),
            input_schema_version=ADAPTIVE_PLANNER_INPUT_VERSION,
            output_schema_version=ADAPTIVE_PLANNER_OUTPUT_VERSION,
        )

    @staticmethod
    def _normal_capability(planner_input: AdaptivePlannerInput) -> str | None:
        envelope = planner_input.envelope
        tool_name = envelope.context.invocation.tool_name
        prior_count = len(planner_input.prior_executable_request_hashes)
        if tool_name == "stage-cloud-run-revision":
            return (
                "cloud-run-revision-get"
                if prior_count == 0
                else "cloud-run-revision-health"
                if prior_count == 1
                else None
            )
        if tool_name == "create-firestore-release-record" and (
            planner_input.missing_evidence
        ):
            return "reconcile-dispatch-receipt-get"
        return None

    async def plan(self, planner_input: AdaptivePlannerInput) -> AdvisoryPlannerTurn:
        tool_name = planner_input.envelope.context.invocation.tool_name
        self.calls_by_tool[tool_name] = self.calls_by_tool.get(tool_name, 0) + 1
        capability = self._normal_capability(planner_input)
        arguments: dict[str, object] = {}
        effects = tuple(
            effect.effect_id for effect in planner_input.envelope.expected_effects
        )
        relevant_effects = effects
        if self.variant == "unknown-capability":
            capability = "qualification-untrusted-write"
        elif self.variant == "invalid-arguments":
            capability = capability or planner_input.capabilities[0].name
            arguments = {"unexpected": True}
        elif self.variant == "foreign-effect":
            capability = capability or planner_input.capabilities[0].name
            relevant_effects = ("qualification-foreign-effect",)
        elif self.variant != "normal":
            raise ValueError("unknown scripted qualification planner variant")

        admitted = tuple(item.evidence_id for item in planner_input.admitted_evidence)
        weak = tuple(item.evidence_id for item in planner_input.weak_evidence)
        rejected = tuple(item.evidence_id for item in planner_input.rejected_evidence)
        missing = tuple(
            dict.fromkeys(item.effect_id for item in planner_input.missing_evidence)
        )
        citations = PlannerCitationRefs(
            admitted_evidence_ids=admitted,
            weak_evidence_ids=weak,
            rejected_evidence_ids=rejected,
            missing_effect_ids=missing,
        )
        proposal = (
            ()
            if capability is None
            else (
                ProbeRequest(
                    schema_version=PROBE_REQUEST_VERSION,
                    capability_name=capability,
                    capability_version="1.0.0",
                    relevant_effect_ids=relevant_effects,
                    arguments=arguments,
                    rationale="Acquire one bounded provider observation.",
                ),
            )
        )
        output = AdaptivePlannerOutput(
            schema_version=ADAPTIVE_PLANNER_OUTPUT_VERSION,
            probe_proposals=proposal,
            acquisition_advice=PlannerAcquisitionAdvice(
                summary="Use one bounded read from the sealed catalog."
            ),
            stop_advice=PlannerStopAdvice(
                recommend_stop=not proposal,
                reason=(
                    "The deterministic report is sufficient."
                    if not proposal
                    else "One additional read may resolve the history."
                ),
            ),
            missing_evidence_notes=(),
            explanation=PlannerExplanation(
                summary="The planner advises; deterministic proof retains authority.",
                admitted_evidence=(
                    "Admitted evidence was cited." if admitted else None
                ),
                weak_evidence=("Weak evidence was cited." if weak else None),
                rejected_evidence=(
                    "Rejected evidence was cited." if rejected else None
                ),
                missing_evidence=("Missing effects were cited." if missing else None),
                citations=citations,
            ),
        )
        output_sha256 = canonical_sha256(output)
        turn = AdvisoryPlannerTurn(
            output=output,
            failure=None,
            metadata=self.metadata,
            input_sha256=canonical_sha256(planner_input),
            output_sha256=output_sha256,
            usage=AdvisoryPlannerUsage(
                prompt_tokens=0,
                output_tokens=0,
                total_tokens=0,
            ),
        )
        self.last_output_sha256 = output_sha256
        self.turns.append(turn)
        self.call_tools.append(tool_name)
        return turn


class _RecordingEvidenceSource:
    def __init__(
        self,
        delegate: ReleaseChainEvidenceSource,
        target_node_id: str,
        *,
        repeat_target_primary: bool,
    ) -> None:
        self.delegate = delegate
        self.target_node_id = target_node_id
        self.repeat_target_primary = repeat_target_primary
        self._target_primary_repeated = False
        self.probe_count = 0
        self.unsupported_probe_count = 0
        self._round_audit_count = 0
        self.states: list[RecoveryEvidenceState] = []

    def _record(
        self,
        node: RecoveryActionNode,
        state: RecoveryEvidenceState,
        *,
        refresh: bool,
    ) -> RecoveryEvidenceState:
        if node.node_id == self.target_node_id:
            current = len(state.report.probe_audit)
            records = (
                state.report.probe_audit
                if refresh
                else state.report.probe_audit[self._round_audit_count :]
            )
            self.probe_count += len(records)
            self.unsupported_probe_count += sum(
                item.outcome is not ProbeOutcome.COMPLETED for item in records
            )
            self._round_audit_count = current
            self.states.append(state)
        return state

    async def current(
        self,
        run_id: str,
        node: RecoveryActionNode,
        envelope: ExecutionEnvelope,
    ) -> RecoveryEvidenceState:
        state = await self.delegate.current(run_id, node, envelope)
        if (
            node.node_id == self.target_node_id
            and self.repeat_target_primary
            and not self._target_primary_repeated
        ):
            self._target_primary_repeated = True
            state = await self.delegate.probe(
                run_id,
                node,
                envelope,
                ProbeRequest(
                    schema_version=PROBE_REQUEST_VERSION,
                    capability_name="cloud-run-service-get",
                    capability_version="1.0.0",
                    relevant_effect_ids=tuple(
                        effect.effect_id for effect in envelope.expected_effects
                    ),
                    arguments={},
                    rationale=(
                        "Repeat the target-state read to expose provider disagreement."
                    ),
                ),
            )
        return self._record(node, state, refresh=True)

    async def fixed(
        self,
        run_id: str,
        node: RecoveryActionNode,
        envelope: ExecutionEnvelope,
    ) -> RecoveryEvidenceState:
        return self._record(
            node,
            await self.delegate.fixed(run_id, node, envelope),
            refresh=False,
        )

    async def probe(
        self,
        run_id: str,
        node: RecoveryActionNode,
        envelope: ExecutionEnvelope,
        request: ProbeRequest,
    ) -> RecoveryEvidenceState:
        return self._record(
            node,
            await self.delegate.probe(run_id, node, envelope, request),
            refresh=False,
        )


class _QualificationActionPreparer:
    """Bind #171's two fault toggles to only the frozen target boundary."""

    def __init__(self, fixture: RecoveryQualificationFixture) -> None:
        self._fixture = fixture
        self._delegate = ReleaseChainActionPreparer()

    def prepare(
        self,
        request: RecoveryRunRequest,
        chain: object,
        source_node: RecoveryActionNode,
        target_node: RecoveryActionNode,
        report: object | None,
        certificate: VerifiedCertificate | None,
    ) -> RecoveryPreparedAction:
        target_stage = self._fixture.archetype.stage.value
        if target_node.node_id == "stage":
            fault = (
                RecoveryRunFault.DROP_AFTER_ACCEPT
                if target_stage == "stage"
                and self._fixture.archetype.fault_class.value
                == "drop-after-accept"
                else RecoveryRunFault.SUPPRESS_BEFORE_DISPATCH
            )
        elif target_node.node_id == "record":
            fault = (
                RecoveryRunFault.SUPPRESS_BEFORE_DISPATCH
                if target_stage == "record"
                and self._fixture.archetype.fault_class.value
                == "suppress-before-dispatch"
                else RecoveryRunFault.DROP_AFTER_ACCEPT
            )
        else:
            fault = RecoveryRunFault.DROP_AFTER_ACCEPT
        return self._delegate.prepare(
            request.model_copy(update={"fault": fault}),
            chain,  # type: ignore[arg-type]
            source_node,
            target_node,
            report,
            certificate,
        )


class _CrashAfterCompletedTargetDispatch:
    """Fallback interruption for boundaries with no accepted provider write."""

    def __init__(
        self,
        delegate: ReleaseChainDispatchGateway,
        target_node_id: str,
    ) -> None:
        self._delegate = delegate
        self._target_node_id = target_node_id
        self._armed = True

    async def dispatch(
        self,
        prepared: RecoveryPreparedAction,
        scope: RecoveryActionScope,
    ) -> RecoveryDispatchReceipt:
        receipt = await self._delegate.dispatch(prepared, scope)
        if self._armed and prepared.target_node_id == self._target_node_id:
            self._armed = False
            raise asyncio.CancelledError
        return receipt


def _target_node_id(fixture: RecoveryQualificationFixture) -> str:
    return fixture.archetype.stage.value


def _fault(fixture: RecoveryQualificationFixture) -> RecoveryRunFault:
    if fixture.archetype.archetype_id == "record-predispatch-retry":
        return RecoveryRunFault.SUPPRESS_BEFORE_DISPATCH
    if fixture.archetype.fault_class.value == "drop-after-accept":
        return RecoveryRunFault.DROP_AFTER_ACCEPT
    # #171 exposes two deliberate fault toggles.  Extended qualification
    # states are supplied by provider scripts; this inert value is rewritten
    # per target by ``_QualificationActionPreparer``.
    return RecoveryRunFault.SUPPRESS_BEFORE_DISPATCH


_EXPECTED_BLIND_CLOUD_ERRORS = {
    CloudRunCanaryErrorCode.PROVIDER_UNAVAILABLE,
    CloudRunCanaryErrorCode.STALE_ETAG,
    CloudRunCanaryErrorCode.REVISION_NOT_FOUND,
    CloudRunCanaryErrorCode.REVISION_NOT_READY,
    CloudRunCanaryErrorCode.ACCEPTANCE_AMBIGUOUS,
}


def _is_expected_blind_failure(error: BaseException) -> bool:
    if isinstance(error, CloudRunCanaryError):
        return error.code in _EXPECTED_BLIND_CLOUD_ERRORS
    return isinstance(
        error,
        (
            FirestoreReleaseConflict,
            FirestoreReleaseOutcomeUnknown,
            FirestoreReleaseProviderUnavailable,
        ),
    )


async def _blind_attempt(
    operation: Callable[[], Awaitable[object]],
    *,
    retry: Callable[[], Awaitable[object]] | None,
) -> bool:
    """Execute one blind mutation, retrying only a known provider outcome."""

    try:
        await operation()
        return True
    except asyncio.CancelledError:
        raise
    except Exception as error:
        if not _is_expected_blind_failure(error):
            raise
        if retry is None:
            return False
    try:
        await retry()
        return True
    except asyncio.CancelledError:
        raise
    except Exception as error:
        if not _is_expected_blind_failure(error):
            raise
        return False


def _slice_definition(
    provider: RecoveryQualificationProviderResources,
    _fixture: RecoveryQualificationFixture,
) -> RecoveryRunDefinition:
    # Recovery verification deliberately rejects partial chains.  Keeping the
    # complete production path also makes later-node cases exercise their real
    # predecessor certificates and dispatches.
    full = build_release_chain_definition(
        provider.settings,
        invoked_at=provider.invoked_at,
    )
    envelopes: dict[str, ExecutionEnvelope] = {}
    nodes = []
    for node in full.chain.nodes:
        envelope = full.envelopes[node.node_id]
        budget = envelope.context.evidence_budget.model_copy(
            update={"max_elapsed_ms": 300_000}
        )
        context = envelope.context.model_copy(update={"evidence_budget": budget})
        expanded = envelope.model_copy(update={"context": context})
        envelopes[node.node_id] = expanded
        reference = node.envelope.model_copy(
            update={"envelope_sha256": canonical_sha256(expanded)}
        )
        nodes.append(node.model_copy(update={"envelope": reference}))
    return RecoveryRunDefinition(
        chain=full.chain.model_copy(update={"nodes": tuple(nodes)}),
        envelopes=envelopes,
        capabilities=full.capabilities,
    )


def _semantic_evidence_sha256(
    state: RecoveryEvidenceState,
    artifact: VerifiedCertificate | AmbiguityWitness,
) -> str:
    decisions = {item.evidence_id: item for item in state.evaluation.decisions}
    supporting = {item.evidence_id for item in artifact.evidence}
    values = []
    for evidence in state.evaluation.evidence:
        if evidence.evidence_id not in supporting:
            continue
        decision = decisions[evidence.evidence_id]
        if decision.disposition.value != "ADMITTED":
            continue
        values.append(
            {
                "authority": evidence.authority.value,
                "capability_name": evidence.capability_name,
                "capability_version": evidence.capability_version,
                "effect_assertions": [
                    {
                        "effect_id": item.effect_id,
                        "state": item.state.value,
                    }
                    for item in evidence.effect_assertions
                ],
                "operation_status": (
                    None
                    if evidence.operation_status is None
                    else evidence.operation_status.value
                ),
                "correlation": {
                    key: value
                    for key, value in evidence.correlation.items()
                    if key not in {"receipt_id"}
                },
                "target": evidence.target.model_dump(mode="json"),
            }
        )
    unique = {canonical_json_value_bytes(value): value for value in values}
    return hashlib.sha256(
        canonical_json_value_bytes([unique[key] for key in sorted(unique)])
    ).hexdigest()


def _transition_value(artifact: VerifiedCertificate) -> dict[str, object] | None:
    transition = artifact.transition
    if transition is None:
        return None
    return {
        "action": transition.action.value,
        "source_node_id": transition.source_node_id,
        "target_node_id": transition.target_node_id,
        "semantic_action_sha256": transition.semantic_action_sha256,
        "tool_name": transition.tool_name,
        "tool_version": transition.tool_version,
        "arguments_sha256": transition.arguments_sha256,
        "target_sha256": transition.target_sha256,
        "precondition_sha256": transition.precondition_sha256,
    }


def _witness_semantics(artifact: AmbiguityWitness) -> dict[str, object]:
    return {
        "node_id": artifact.node_id,
        "semantic_action_sha256": artifact.semantic_action_sha256,
        "target": artifact.target.model_dump(mode="json"),
        "histories": [
            {
                "classification": classification,
                "effect_states": [
                    {"effect_id": effect_id, "state": state}
                    for effect_id, state in effects
                ],
            }
            for classification, effects in sorted(
                (
                    history.classification.value,
                    tuple(
                        sorted(
                            (effect.effect_id, effect.state.value)
                            for effect in history.effect_states
                        )
                    ),
                )
                for history in artifact.possible_histories
            )
        ],
        "discriminating_observations": [
            {
                "capability_name": capability_name,
                "capability_version": capability_version,
                "relevant_effect_ids": list(relevant_effect_ids),
            }
            for capability_name, capability_version, relevant_effect_ids in sorted(
                (
                    item.capability_name,
                    item.capability_version,
                    tuple(sorted(item.relevant_effect_ids)),
                )
                for item in artifact.discriminating_observations
            )
        ],
        "conflict_count": len(artifact.conflicting_evidence_ids),
    }


def _artifact_semantic_sha256(
    artifact: VerifiedCertificate | AmbiguityWitness,
) -> str:
    if isinstance(artifact, VerifiedCertificate):
        value: object = {
            "kind": "VERIFIED_CERTIFICATE",
            "classification": artifact.classification.value,
            "node_id": artifact.node_id,
            "semantic_action_sha256": artifact.semantic_action_sha256,
            "transition": _transition_value(artifact),
        }
    else:
        value = {"kind": "AMBIGUITY_WITNESS", **_witness_semantics(artifact)}
    return hashlib.sha256(canonical_json_value_bytes(value)).hexdigest()


def _permit_semantic_sha256(
    artifact: VerifiedCertificate | AmbiguityWitness,
) -> str | None:
    if not isinstance(artifact, VerifiedCertificate) or artifact.transition is None:
        return None
    return hashlib.sha256(
        canonical_json_value_bytes(_transition_value(artifact))
    ).hexdigest()


def _resolution(
    decision: RecoveryDecision,
    artifact: VerifiedCertificate | AmbiguityWitness,
) -> RecoveryQualificationResolution:
    if decision is RecoveryDecision.RETRY:
        return RecoveryQualificationResolution.RETRY
    if decision is RecoveryDecision.ESCALATE:
        return RecoveryQualificationResolution.ESCALATE
    if decision is RecoveryDecision.CONTINUE and isinstance(
        artifact, VerifiedCertificate
    ):
        return (
            RecoveryQualificationResolution.COMPLETED
            if artifact.transition is None
            else RecoveryQualificationResolution.CONTINUE
        )
    raise ValueError("target decision is not terminal")


def _target_decision(
    events: RecoveryRunEventSnapshot,
    node_id: str,
) -> tuple[RecoveryDecision, VerifiedCertificate | AmbiguityWitness]:
    for event in events.events:
        payload = event.payload
        artifact = payload.certificate or payload.witness
        if (
            payload.decision
            in {
                RecoveryDecision.CONTINUE,
                RecoveryDecision.RETRY,
                RecoveryDecision.ESCALATE,
            }
            and artifact is not None
            and artifact.node_id == node_id
        ):
            return payload.decision, artifact
    raise ValueError("qualification target has no terminal deterministic decision")


def _state_for_artifact(
    source: _RecordingEvidenceSource,
    artifact: VerifiedCertificate | AmbiguityWitness,
) -> RecoveryEvidenceState:
    matches = tuple(
        state
        for state in source.states
        if canonical_sha256(state.report) == artifact.report_sha256
    )
    if not matches:
        raise ValueError("qualification terminal evidence state is unavailable")
    return matches[-1]


def _successor_envelope(
    definition: RecoveryRunDefinition,
    node_id: str,
) -> ExecutionEnvelope | None:
    for node in definition.chain.nodes:
        if node_id in node.depends_on:
            return definition.envelopes[node.node_id]
    return None


async def _wrong_hypotheses(
    *,
    fixture: RecoveryQualificationFixture,
    state_directory: Path,
    baseline_artifact: VerifiedCertificate | AmbiguityWitness,
) -> tuple[RecoveryQualificationWrongExecution, ...]:
    """Run each bad Gemini proposal through an isolated production workflow."""

    baseline_decision = _artifact_semantic_sha256(baseline_artifact)
    baseline_permit = _permit_semantic_sha256(baseline_artifact)
    results = []
    for index, variant in enumerate(_WRONG_VARIANTS, 1):
        foundation = build_recovery_qualification_foundation(
            fixture,
            state_directory=state_directory / variant,
        )
        provider = foundation.provider
        provider.require_supported()
        target_node_id = _target_node_id(fixture)
        definition = _slice_definition(provider, fixture)
        if fixture.archetype.archetype_id == "record-predispatch-conflict":
            record_node = next(
                node for node in definition.chain.nodes if node.node_id == "record"
            )
            provider.seed_release_record(
                semantic_action_sha256=(
                    record_node.semantic_action.semantic_action_sha256
                ),
                conflicting=True,
            )
        planner = _ScriptedPlanner(variant)
        stores = foundation.stores.open()
        workflow, _source = _build_workflow(
            foundation=foundation,
            stores=stores,
            definition=definition,
            planner=planner,
            target_node_id=target_node_id,
            fixture=fixture,
        )
        request = RecoveryRunRequest(
            schema_version=RECOVERY_RUN_REQUEST_VERSION,
            run_id=f"{fixture.case_id}-wrong-{index}",
            scenario="cloud-run-rollout",
            policy=RecoveryRunPolicy.ADAPTIVE,
            fault=_fault(fixture),
        )
        await stores.run_store.create(
            request,
            definition.chain,
            created_at=provider.invoked_at,
        )
        snapshot = await workflow.run(request.run_id)
        events = await stores.run_store.events(request.run_id)
        _decision, artifact = _target_decision(events, target_node_id)
        hypothesis_events = tuple(
            event
            for event in events.events
            if event.payload.hypothesis_disposition is not None
            and event.payload.hypothesis_disposition
            is not RecoveryHypothesisDisposition.FIXED_FALLBACK
        )
        if len(hypothesis_events) != len(planner.call_tools):
            raise AssertionError("persisted wrong-hypothesis audit is incomplete")
        target_tool_name = definition.envelopes[
            target_node_id
        ].context.invocation.tool_name
        target_index = next(
            (
                call_index
                for call_index, tool_name in enumerate(planner.call_tools)
                if tool_name == target_tool_name
            ),
            None,
        )
        if target_index is None:
            raise AssertionError("wrong hypothesis did not traverse the target node")
        target_event = hypothesis_events[target_index]
        hypothesis = target_event.payload.hypothesis
        disposition = target_event.payload.hypothesis_disposition
        if hypothesis is not None and hypothesis.node_id != target_node_id:
            raise AssertionError("wrong hypothesis audit changed target identity")
        if disposition not in {
            RecoveryHypothesisDisposition.UNSUPPORTED_ACTION,
            RecoveryHypothesisDisposition.UNSUPPORTED_PROBE,
            RecoveryHypothesisDisposition.INVALID_BINDING,
            RecoveryHypothesisDisposition.MALFORMED_MODEL_OUTPUT,
        }:
            raise AssertionError("wrong qualification hypothesis was not rejected")
        decision_sha256 = _artifact_semantic_sha256(artifact)
        permit_sha256 = _permit_semantic_sha256(artifact)
        if permit_sha256 is not None and not any(
            item.certificate_id
            == (
                artifact.certificate_id
                if isinstance(artifact, VerifiedCertificate)
                else None
            )
            for item in snapshot.action_permits
        ):
            raise AssertionError("wrong-hypothesis replay lost its durable permit")
        results.append(
            RecoveryQualificationWrongExecution(
                variant_id=f"wrong-gemini-hypothesis-{index}",
                planner_output_sha256=planner.turns[target_index].output_sha256,
                hypothesis_sha256=(
                    None if hypothesis is None else canonical_sha256(hypothesis)
                ),
                disposition=disposition,
                decision_sha256=decision_sha256,
                permit_sha256=permit_sha256,
            )
        )
        if decision_sha256 != baseline_decision or permit_sha256 != baseline_permit:
            raise AssertionError("wrong hypothesis changed deterministic authority")
    return tuple(results)


async def _witness_replays(
    *,
    run_id: str,
    definition: RecoveryRunDefinition,
    node: RecoveryActionNode,
    state: RecoveryEvidenceState,
    source: _RecordingEvidenceSource,
    baseline: AmbiguityWitness,
) -> tuple[str, str, str]:
    semantic = hashlib.sha256(
        canonical_json_value_bytes(_witness_semantics(baseline))
    ).hexdigest()
    controller_audit = tuple(
        ControllerAuditRecord.model_validate(
            {
                **record.model_dump(
                    mode="python",
                    exclude={"evidence_ids", "probe_sequence"},
                ),
                "sequence": record.probe_sequence,
                "stop_reason": ProbeStopReason(record.stop_reason),
            },
        )
        for record in state.report.probe_audit
    )
    reordered_evaluation = evaluate_evidence(
        state.envelope,
        tuple(reversed(state.evaluation.attempts)),
        tuple(reversed(controller_audit)),
    )
    reordered = verify_recovery(
        chain=definition.chain,
        node_id=node.node_id,
        envelope=state.envelope,
        report=state.report,
        evaluation=reordered_evaluation,
        verified_at=state.report.updated_at,
        successor_envelope=_successor_envelope(definition, node.node_id),
    )
    if not isinstance(reordered, AmbiguityWitness):
        raise AssertionError("reordered ambiguous evidence gained authority")
    prior_capability = next(
        (
            item.capability_name
            for item in state.report.probe_audit
            if item.capability_name is not None
        ),
        None,
    )
    capability = next(
        (
            item
            for item in definition.capabilities[node.node_id]
            if item.name == prior_capability
        ),
        definition.capabilities[node.node_id][0],
    )
    duplicated_state = await source.delegate.probe(
        run_id,
        node,
        state.envelope,
        ProbeRequest(
            schema_version=PROBE_REQUEST_VERSION,
            capability_name=capability.name,
            capability_version=capability.version,
            relevant_effect_ids=tuple(
                effect.effect_id for effect in state.envelope.expected_effects
            ),
            arguments={},
            rationale="Repeat an identical read to test evidence deduplication.",
        ),
    )
    duplicated = verify_recovery(
        chain=definition.chain,
        node_id=node.node_id,
        envelope=duplicated_state.envelope,
        report=duplicated_state.report,
        evaluation=duplicated_state.evaluation,
        verified_at=duplicated_state.report.updated_at,
        successor_envelope=_successor_envelope(definition, node.node_id),
    )
    if not isinstance(duplicated, AmbiguityWitness):
        raise AssertionError("duplicated ambiguous evidence gained authority")
    return (
        semantic,
        hashlib.sha256(
            canonical_json_value_bytes(_witness_semantics(reordered))
        ).hexdigest(),
        hashlib.sha256(
            canonical_json_value_bytes(_witness_semantics(duplicated))
        ).hexdigest(),
    )


def _scripted_usage(call_count: int) -> RecoveryQualificationModelUsage:
    return RecoveryQualificationModelUsage(
        status=RecoveryQualificationModelUsageStatus.SCRIPTED,
        provider_name=None,
        model_name=None,
        model_call_count=call_count,
        input_token_count=0,
        output_token_count=0,
        total_token_count=0,
        input_cost_nano_units_per_token=0,
        output_cost_nano_units_per_token=0,
        model_cost_nano_units=0,
        live_vertex_backed=False,
    )


def _not_applicable_usage() -> RecoveryQualificationModelUsage:
    return RecoveryQualificationModelUsage(
        status=RecoveryQualificationModelUsageStatus.NOT_APPLICABLE,
        provider_name=None,
        model_name=None,
        model_call_count=0,
        input_token_count=0,
        output_token_count=0,
        total_token_count=0,
        input_cost_nano_units_per_token=0,
        output_cost_nano_units_per_token=0,
        model_cost_nano_units=0,
        live_vertex_backed=False,
    )


def _build_workflow(
    *,
    foundation: RecoveryQualificationFoundation,
    stores: RecoveryQualificationStores,
    definition: RecoveryRunDefinition,
    planner: _ScriptedPlanner,
    target_node_id: str,
    fixture: RecoveryQualificationFixture,
    crash_after_completed_target_dispatch: bool = False,
) -> tuple[ProofToPermitWorkflow, _RecordingEvidenceSource]:
    provider = foundation.provider
    evidence = _RecordingEvidenceSource(
        ReleaseChainEvidenceSource(
            store=stores.run_store,
            definition=definition,
            settings=provider.settings,
            cloud_run=provider.cloud_reader,
            firestore=provider.firestore,
            clock=provider.clock,
        ),
        target_node_id,
        repeat_target_primary=provider.archetype_id
        in {"stage-conflict", "promote-conflict"},
    )
    gateway = ReleaseChainDispatchGateway(
        settings=provider.settings,
        store=stores.run_store,
        permit_authority=stores.permit_authority,
        cloud_run=provider.cloud_action,
        firestore=provider.firestore,
        clock=provider.clock,
    )
    dispatch_gateway = (
        _CrashAfterCompletedTargetDispatch(gateway, target_node_id)
        if crash_after_completed_target_dispatch
        else gateway
    )
    workflow = ProofToPermitWorkflow(
        store=stores.run_store,
        definition_factory=lambda _request: definition,
        evidence_source=evidence,
        action_preparer=_QualificationActionPreparer(fixture),
        recovery_agent=RecoveryAgent(planner, clock=provider.clock),
        rollout_agent=RolloutAgent(dispatch_gateway),
        permit_authority=stores.permit_authority,
        clock=provider.clock,
    )
    return workflow, evidence


async def execute_recovery_qualification_proof_lane(
    fixture: RecoveryQualificationFixture,
    *,
    policy: RecoveryQualificationPolicy,
    state_directory: str | Path,
    restart: bool,
    _crash_after_provider: bool = False,
    _include_safety_replays: bool = True,
) -> RecoveryQualificationProofExecution:
    if policy not in {
        RecoveryQualificationPolicy.FIXED,
        RecoveryQualificationPolicy.ADAPTIVE,
    }:
        raise ValueError("proof execution requires fixed or adaptive policy")
    foundation = build_recovery_qualification_foundation(
        fixture,
        state_directory=state_directory,
    )
    provider = foundation.provider
    provider.require_supported()
    target_node_id = _target_node_id(fixture)
    crash_after_completed_target_dispatch = False
    if _crash_after_provider:
        if target_node_id == "stage":
            provider.cloud_state.arm_crash_after_accept(CloudRunCanaryAction.STAGE)
        elif target_node_id == "promote":
            if fixture.archetype.archetype_id == "promote-stale-precondition":
                crash_after_completed_target_dispatch = True
            else:
                provider.cloud_state.arm_crash_after_accept(
                    CloudRunCanaryAction.PROMOTE
                )
        elif fixture.archetype.archetype_id == "record-predispatch-retry":
            crash_after_completed_target_dispatch = True
        else:
            provider.release_client.arm_crash_after_attempt()
    definition = _slice_definition(provider, fixture)
    if fixture.archetype.archetype_id == "record-predispatch-conflict":
        record_node = next(
            node for node in definition.chain.nodes if node.node_id == "record"
        )
        provider.seed_release_record(
            semantic_action_sha256=record_node.semantic_action.semantic_action_sha256,
            conflicting=True,
        )
    planner = _ScriptedPlanner()
    stores = foundation.stores.open()
    workflow, source = _build_workflow(
        foundation=foundation,
        stores=stores,
        definition=definition,
        planner=planner,
        target_node_id=target_node_id,
        fixture=fixture,
        crash_after_completed_target_dispatch=(
            crash_after_completed_target_dispatch
        ),
    )
    request = RecoveryRunRequest(
        schema_version=RECOVERY_RUN_REQUEST_VERSION,
        run_id=f"{fixture.case_id}-{policy.value}",
        scenario="cloud-run-rollout",
        policy=RecoveryRunPolicy(policy.value),
        fault=_fault(fixture),
    )
    await stores.run_store.create(
        request,
        definition.chain,
        created_at=provider.invoked_at,
    )
    restarted_snapshot_sha256 = None
    restarted_decision_sha256 = None
    restarted_permit_sha256 = None
    if _crash_after_provider:
        try:
            await workflow.run(request.run_id)
        except asyncio.CancelledError:
            pass
        else:  # pragma: no cover - guarded by the deterministic fault boundary
            raise AssertionError("qualification restart boundary did not interrupt")
        stores = foundation.stores.open()
        planner = _ScriptedPlanner()
        workflow, source = _build_workflow(
            foundation=foundation,
            stores=stores,
            definition=definition,
            planner=planner,
            target_node_id=target_node_id,
            fixture=fixture,
        )
    snapshot = await workflow.run(request.run_id)
    events = await stores.run_store.events(request.run_id)
    decision, artifact = _target_decision(events, target_node_id)
    state = _state_for_artifact(source, artifact)
    resolution = _resolution(decision, artifact)
    semantic_decision = _artifact_semantic_sha256(artifact)
    semantic_permit = _permit_semantic_sha256(artifact)
    permit_action = (
        artifact.transition.action
        if isinstance(artifact, VerifiedCertificate) and artifact.transition is not None
        else None
    )
    permit: ActionPermit | None = next(
        (
            item
            for item in snapshot.action_permits
            if isinstance(artifact, VerifiedCertificate)
            and item.certificate_id == artifact.certificate_id
            and item.certificate_sha256 == canonical_sha256(artifact)
        ),
        None,
    )
    if permit_action is not None and permit is None:
        raise AssertionError("certified qualification action has no durable permit")
    if permit is not None:
        if not isinstance(artifact, VerifiedCertificate):  # pragma: no cover
            raise AssertionError("durable permit has no certificate")
        expected_permit = action_permit_from_certificate(artifact)
        issued_projection = permit.model_copy(
            update={
                "state": ActionPermitState.ISSUED,
                "revision": 0,
                "claim_id": None,
                "claimed_at": None,
                "completed_at": None,
                "completion_outcome": None,
                "expired_at": None,
            }
        )
        if expected_permit is None or issued_projection != expected_permit:
            raise AssertionError(
                "qualification permit is not exactly bound to its certificate"
            )
    target_node = next(
        node for node in definition.chain.nodes if node.node_id == target_node_id
    )
    wrong = (
        await _wrong_hypotheses(
            fixture=fixture,
            state_directory=Path(state_directory) / "wrong-hypotheses",
            baseline_artifact=artifact,
        )
        if policy is RecoveryQualificationPolicy.FIXED and _include_safety_replays
        else ()
    )
    witness_values: tuple[str | None, str | None, str | None] = (None, None, None)
    if (
        policy is RecoveryQualificationPolicy.FIXED
        and _include_safety_replays
        and isinstance(artifact, AmbiguityWitness)
    ):
        witness_values = await _witness_replays(
            run_id=request.run_id,
            definition=definition,
            node=target_node,
            state=state,
            source=source,
            baseline=artifact,
        )
    target_tool_name = definition.envelopes[target_node_id].context.invocation.tool_name
    artifact_kind = (
        RecoveryQualificationArtifactKind.VERIFIED_CERTIFICATE
        if isinstance(artifact, VerifiedCertificate)
        else RecoveryQualificationArtifactKind.AMBIGUITY_WITNESS
    )
    result = RecoveryQualificationProofExecution(
        policy=policy,
        resolution=resolution,
        permit_action=permit_action,
        permit_sha256=semantic_permit,
        raw_permit_sha256=None if permit is None else canonical_sha256(permit),
        admitted_evidence_sha256=_semantic_evidence_sha256(state, artifact),
        decision_sha256=semantic_decision,
        artifact_kind=artifact_kind,
        artifact_sha256=canonical_sha256(artifact),
        ambiguity_witness_sha256=(
            canonical_sha256(artifact)
            if isinstance(artifact, AmbiguityWitness)
            else None
        ),
        probe_count=source.probe_count,
        time_to_sufficient_evidence_ms=max(
            0,
            int(
                (
                    state.report.updated_at - source.states[0].report.created_at
                ).total_seconds()
                * 1000
            ),
        ),
        unsupported_probe_count=source.unsupported_probe_count,
        provider_mutations=provider.counters.provider_mutations(),
        model_usage=(
            _scripted_usage(planner.calls_by_tool.get(target_tool_name, 0))
            if policy is RecoveryQualificationPolicy.ADAPTIVE
            else _not_applicable_usage()
        ),
        snapshot_sha256=canonical_sha256(snapshot),
        restarted_snapshot_sha256=restarted_snapshot_sha256,
        restarted_decision_sha256=restarted_decision_sha256,
        restarted_permit_sha256=restarted_permit_sha256,
        wrong_hypotheses=wrong,
        witness_semantic_sha256=witness_values[0],
        reordered_witness_semantic_sha256=witness_values[1],
        duplicated_witness_semantic_sha256=witness_values[2],
    )
    if restart:
        if _crash_after_provider:
            raise ValueError("nested qualification restart is unsupported")
        restarted = await execute_recovery_qualification_proof_lane(
            fixture,
            policy=policy,
            state_directory=Path(state_directory) / "restart-replay",
            restart=False,
            _crash_after_provider=True,
            _include_safety_replays=False,
        )
        if (
            restarted.resolution is not result.resolution
            or restarted.artifact_kind is not result.artifact_kind
            or restarted.admitted_evidence_sha256 != result.admitted_evidence_sha256
        ):
            raise AssertionError("restart changed deterministic recovery evidence")
        return replace(
            result,
            restarted_snapshot_sha256=restarted.snapshot_sha256,
            restarted_decision_sha256=restarted.decision_sha256,
            restarted_permit_sha256=restarted.permit_sha256,
        )
    return result


async def execute_recovery_qualification_blind_lane(
    fixture: RecoveryQualificationFixture,
    *,
    policy: RecoveryQualificationPolicy,
) -> RecoveryQualificationBlindExecution:
    if policy not in {
        RecoveryQualificationPolicy.BLIND_RETRY,
        RecoveryQualificationPolicy.BLIND_ABORT,
    }:
        raise ValueError("blind execution requires a blind policy")
    provider = build_recovery_qualification_foundation(
        fixture,
        state_directory=Path.cwd(),
    ).provider
    provider.require_supported()
    if fixture.archetype.archetype_id == "record-predispatch-conflict":
        definition = build_release_chain_definition(
            provider.settings,
            invoked_at=provider.invoked_at,
        )
        record_node = next(
            node for node in definition.chain.nodes if node.node_id == "record"
        )
        provider.seed_release_record(
            semantic_action_sha256=record_node.semantic_action.semantic_action_sha256,
            conflicting=True,
        )
    mutator = ReleaseChainBlindMutator(
        settings=provider.settings,
        cloud_action=provider.cloud_action,
        cloud_reader=provider.cloud_reader,
        firestore=provider.firestore,
        invoked_at=provider.invoked_at,
        clock=provider.clock,
    )
    retries = policy is RecoveryQualificationPolicy.BLIND_RETRY
    target = _target_node_id(fixture)
    drop_stage_ack = (
        target == "stage"
        and fixture.archetype.fault_class.value == "drop-after-accept"
    )
    stage_succeeded = await _blind_attempt(
        lambda: mutator.stage(
            operation_id=provider.settings.stage_operation_id,
            drop_after_accept=drop_stage_ack,
        ),
        retry=(
            (lambda: mutator.stage(
                operation_id=f"{provider.settings.stage_operation_id}-retry",
                drop_after_accept=False,
            ))
            if retries
            else None
        ),
    )
    if stage_succeeded:
        promote_succeeded = await _blind_attempt(
            mutator.promote,
            retry=mutator.promote if retries else None,
        )
    else:
        promote_succeeded = False
    if promote_succeeded:
        suppress_record = (
            target == "record"
            and fixture.archetype.fault_class.value == "suppress-before-dispatch"
        )
        if suppress_record:
            if retries:
                await _blind_attempt(
                    lambda: mutator.create_record(suppress_before_dispatch=False),
                    retry=None,
                )
        else:
            await _blind_attempt(
                lambda: mutator.create_record(suppress_before_dispatch=False),
                retry=(
                    (lambda: mutator.create_record(suppress_before_dispatch=False))
                    if retries
                    else None
                ),
            )
    resolution = (
        RecoveryQualificationResolution.RETRY
        if retries
        else RecoveryQualificationResolution.ABORT
    )
    return RecoveryQualificationBlindExecution(
        resolution=resolution,
        provider_mutations=provider.counters.provider_mutations(),
    )


__all__ = [
    "RecoveryQualificationBlindExecution",
    "RecoveryQualificationProofExecution",
    "RecoveryQualificationWrongExecution",
    "execute_recovery_qualification_blind_lane",
    "execute_recovery_qualification_proof_lane",
]
