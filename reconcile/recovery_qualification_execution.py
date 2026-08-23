"""Provider-backed execution support for recovery qualification v1.

The qualification fixture describes provider behavior and expected assertions;
it never supplies the controller decision.  Every proof lane below runs the
production #171 evidence, verification, permit, dispatch, and persistence
components against SDK-level deterministic provider doubles.
"""

from __future__ import annotations

import asyncio
import hashlib
from collections import Counter
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, replace
from datetime import datetime
from pathlib import Path

from reconcile.adapters.cloud_run import (
    CLOUD_RUN_HEALTH_CAPABILITY,
    CLOUD_RUN_OPERATION_CAPABILITY,
    CLOUD_RUN_REVISION_CAPABILITY,
    CLOUD_RUN_SERVICE_CAPABILITY,
    CloudRunProbeBinding,
    build_cloud_run_capability_registration,
    build_cloud_run_rule_registration,
)
from reconcile.adapters.firestore_release import (
    DISPATCH_RECEIPT_CAPABILITY,
    FIRESTORE_RELEASE_CAPABILITY,
    FirestoreReleaseProbeBinding,
    build_firestore_release_capability_registration,
    build_firestore_release_rule_registration,
)
from reconcile.adaptive import (
    AdvisoryPlannerMetadata,
    AdvisoryPlannerTurn,
    AdvisoryPlannerUsage,
)
from reconcile.contracts import (
    ADAPTIVE_PLANNER_INPUT_VERSION,
    ADAPTIVE_PLANNER_OUTPUT_VERSION,
    PROBE_REQUEST_VERSION,
    RECOVERY_ACTION_SCOPE_VERSION,
    RECOVERY_RUN_REQUEST_VERSION,
    ActionPermit,
    ActionPermitState,
    AdaptivePlannerInput,
    AdaptivePlannerOutput,
    AmbiguityWitness,
    Classification,
    EffectAssertionState,
    EvidenceAuthority,
    EvidenceDisposition,
    EvidenceReason,
    ExecutionEnvelope,
    GeminiHypothesis,
    HypothesizedEffect,
    InvestigationReport,
    NormalizedEvidence,
    OperationStatus,
    PermitAction,
    PlannerAcquisitionAdvice,
    PlannerCitationRefs,
    PlannerExplanation,
    PlannerStopAdvice,
    PossibleHistory,
    ProbeOutcome,
    ProbeRequest,
    RecoveryActionNode,
    RecoveryActionScope,
    RecoveryAuthorityKind,
    RecoveryDecision,
    RecoveryHypothesisDisposition,
    RecoveryPreparedAction,
    RecoveryRunFault,
    RecoveryRunPolicy,
    RecoveryRunRequest,
    RecoveryRunSnapshot,
    VerifiedCertificate,
    canonical_sha256,
)
from reconcile.contracts.base import canonical_json_value_bytes
from reconcile.contracts.recovery_qualification import (
    RECOVERY_QUALIFICATION_CONTENTION_WIDTH,
    RecoveryQualificationArtifactKind,
    RecoveryQualificationHypothesisWrongnessKind,
    RecoveryQualificationModelUsage,
    RecoveryQualificationModelUsageStatus,
    RecoveryQualificationPolicy,
    RecoveryQualificationProviderMutations,
    RecoveryQualificationResolution,
    RecoveryQualificationStorageBackend,
    RecoveryQualificationWitnessReplayKind,
)
from reconcile.controller import (
    CapabilityRegistration,
    CapabilityRegistry,
    ControllerAuditRecord,
    ProbeController,
    ProbeStopReason,
)
from reconcile.controller.permits import PermitAuthority, action_permit_from_certificate
from reconcile.evidence import EvidenceEngine, ProbeRun, TargetRuleRegistry
from reconcile.evidence.classification import evaluate_evidence
from reconcile.evidence.recovery_rules import (
    CLOUD_RUN_HEALTH_OBSERVATION_VERSION,
    CLOUD_RUN_REVISION_OBSERVATION_VERSION,
    CLOUD_RUN_SERVICE_OBSERVATION_VERSION,
    DISPATCH_RECEIPT_OBSERVATION_VERSION,
    FIRESTORE_DOCUMENT_OBSERVATION_VERSION,
    RECOVERY_CAPABILITY_VERSION,
)
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
from reconcile.persistence.permits import ActionPermitStore
from reconcile.persistence.recovery_runs import RecoveryRunEventSnapshot
from reconcile.recovery_agents import (
    RecoveryAgent,
    RecoveryDispatchReceipt,
    RolloutAgent,
)
from reconcile.recovery_qualification_fixtures import RecoveryQualificationFixture
from reconcile.recovery_qualification_provider import (
    DeterministicAsyncFirestoreCasClient,
    RecoveryQualificationFoundation,
    RecoveryQualificationProviderResources,
    RecoveryQualificationStores,
    build_qualification_firestore_store_factory,
    build_recovery_qualification_foundation,
)
from reconcile.recovery_scenario import (
    RecoveryRunReceiptReader,
    ReleaseChainActionPreparer,
    ReleaseChainBlindMutator,
    ReleaseChainDispatchGateway,
    ReleaseChainError,
    ReleaseChainEvidenceSource,
    build_release_chain_definition,
)
from reconcile.recovery_workflow import (
    ProofToPermitWorkflow,
    RecoveryEvidenceState,
    RecoveryRunDefinition,
)

_WRONG_VARIANTS = (
    "wrong-classification",
    "wrong-effect-state",
    "wrong-alternative-history",
)
_UNSUPPORTED_STOP_REASONS = frozenset(
    {
        ProbeStopReason.INVALID_REQUEST,
        ProbeStopReason.UNKNOWN_CAPABILITY,
        ProbeStopReason.CAPABILITY_DISABLED,
        ProbeStopReason.CAPABILITY_NOT_ENABLED,
        ProbeStopReason.CAPABILITY_MUTATING,
        ProbeStopReason.CAPABILITY_SEMANTICS_AMBIGUOUS,
        ProbeStopReason.TARGET_KIND_MISMATCH,
        ProbeStopReason.TARGET_SCOPE_MISMATCH,
        ProbeStopReason.INVALID_EFFECT_REFERENCE,
        ProbeStopReason.INVALID_ARGUMENTS,
        ProbeStopReason.ARGUMENTS_TOO_LARGE,
        ProbeStopReason.TARGET_PARAMETER_INJECTION,
        ProbeStopReason.CORRELATION_MISMATCH,
    }
)


@dataclass(frozen=True, slots=True)
class RecoveryQualificationWrongExecution:
    variant_id: str
    wrongness_kind: RecoveryQualificationHypothesisWrongnessKind
    planner_output_sha256: str
    report: InvestigationReport
    expected_hypothesis: GeminiHypothesis
    hypothesis: GeminiHypothesis
    hypothesis_sha256: str
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
    demonstrated_evidence_profile: tuple[str, ...]
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
    restarted_provider_mutations: RecoveryQualificationProviderMutations | None
    wrong_hypotheses: tuple[RecoveryQualificationWrongExecution, ...]
    witness_semantic_sha256: str | None
    reordered_witness_semantic_sha256: str | None
    replayed_witness_semantic_sha256: str | None
    witness_replay_kind: RecoveryQualificationWitnessReplayKind | None


@dataclass(frozen=True, slots=True)
class RecoveryQualificationBlindExecution:
    resolution: RecoveryQualificationResolution
    provider_mutations: RecoveryQualificationProviderMutations


@dataclass(frozen=True, slots=True)
class RecoveryQualificationContentionDispatch:
    """A real issued permit and production dispatch path held before contact."""

    foundation: RecoveryQualificationFoundation
    stores: RecoveryQualificationStores
    rollout_agent: RolloutAgent
    prepared: RecoveryPreparedAction
    scope: RecoveryActionScope
    permit: ActionPermit
    baseline_provider_mutations: RecoveryQualificationProviderMutations
    firestore_client: DeterministicAsyncFirestoreCasClient | None


class _ClaimRendezvousStore:
    """Hold only the first claim wave before entering the real permit store."""

    def __init__(self, delegate: ActionPermitStore, width: int) -> None:
        self._delegate = delegate
        self._width = width
        self._arrivals = 0
        self._lock = asyncio.Lock()
        self._ready = asyncio.Event()

    async def issue_permit(self, permit: object):
        return await self._delegate.issue_permit(permit)  # type: ignore[arg-type]

    async def get_permit(self, permit_id: str):
        return await self._delegate.get_permit(permit_id)

    async def claim_permit(self, request: object):
        async with self._lock:
            self._arrivals += 1
            if self._arrivals == self._width:
                self._ready.set()
        await self._ready.wait()
        return await self._delegate.claim_permit(request)  # type: ignore[arg-type]

    async def complete_permit(self, request: object):
        return await self._delegate.complete_permit(request)  # type: ignore[arg-type]

    async def permit_audit_events(self, permit_id: str):
        return await self._delegate.permit_audit_events(permit_id)


def _different_classification(value: Classification) -> Classification:
    return (
        Classification.NOT_COMMITTED
        if value is Classification.COMMITTED
        else Classification.COMMITTED
    )


def _different_effect_state(value: EffectAssertionState) -> EffectAssertionState:
    return (
        EffectAssertionState.NOT_ESTABLISHED
        if value is EffectAssertionState.ESTABLISHED
        else EffectAssertionState.ESTABLISHED
    )


class _ScriptedPlanner:
    """Deterministic Gemini-shaped planner with no mutation authority."""

    def __init__(
        self,
        variant: str = "normal",
        *,
        target_node_id: str | None = None,
    ) -> None:
        self.variant = variant
        self.target_node_id = target_node_id
        self.turns: list[AdvisoryPlannerTurn] = []
        self.call_tools: list[str] = []
        self.calls_by_tool: dict[str, int] = {}
        self.expected_hypotheses_by_id: dict[str, GeminiHypothesis] = {}
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
            service_observations = sum(
                item.capability_name == CLOUD_RUN_SERVICE_CAPABILITY
                for item in planner_input.admitted_evidence
            )
            sequence = (
                (
                    CLOUD_RUN_OPERATION_CAPABILITY,
                    CLOUD_RUN_REVISION_CAPABILITY,
                    CLOUD_RUN_HEALTH_CAPABILITY,
                )
                if service_observations > 1
                else (
                    CLOUD_RUN_REVISION_CAPABILITY,
                    CLOUD_RUN_HEALTH_CAPABILITY,
                )
            )
            return sequence[prior_count] if prior_count < len(sequence) else None
        if (
            tool_name == "create-firestore-release-record"
            and planner_input.missing_evidence
            and prior_count == 0
        ):
            return "reconcile-dispatch-receipt-get"
        return None

    async def plan(self, planner_input: AdaptivePlannerInput) -> AdvisoryPlannerTurn:
        tool_name = planner_input.envelope.context.invocation.tool_name
        self.calls_by_tool[tool_name] = self.calls_by_tool.get(tool_name, 0) + 1
        capability = self._normal_capability(planner_input)
        target_tool_name = {
            "stage": "stage-cloud-run-revision",
            "promote": "promote-cloud-run-traffic",
            "record": "create-firestore-release-record",
        }.get(self.target_node_id)
        if self.variant in _WRONG_VARIANTS and tool_name == target_tool_name:
            capability = None
        arguments: dict[str, object] = {}
        effects = tuple(
            effect.effect_id for effect in planner_input.envelope.expected_effects
        )
        if self.variant not in {"normal", *_WRONG_VARIANTS}:
            raise ValueError("unknown scripted qualification planner variant")

        admitted = tuple(item.evidence_id for item in planner_input.admitted_evidence)
        weak = tuple(item.evidence_id for item in planner_input.weak_evidence)
        missing = tuple(
            dict.fromkeys(item.effect_id for item in planner_input.missing_evidence)
        )
        if not admitted and not weak and not missing:
            missing = effects
        citations = PlannerCitationRefs(
            admitted_evidence_ids=admitted,
            weak_evidence_ids=weak,
            # Rejected candidates are not retained in ``EvidenceReport.evidence``
            # and therefore cannot be cited by a well-formed Gemini hypothesis.
            rejected_evidence_ids=(),
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
                    relevant_effect_ids=effects,
                    arguments=arguments,
                    rationale="Acquire one bounded provider observation.",
                ),
            )
        )
        output = AdaptivePlannerOutput(
            schema_version=ADAPTIVE_PLANNER_OUTPUT_VERSION,
            probe_proposals=proposal,
            acquisition_advice=PlannerAcquisitionAdvice(
                summary=(
                    "Use one bounded read from the sealed catalog."
                    if self.variant == "normal"
                    else f"Use one bounded read for {self.variant}."
                )
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
                rejected_evidence=None,
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

    def transform_hypothesis(
        self,
        hypothesis: GeminiHypothesis,
        _report: InvestigationReport,
    ) -> GeminiHypothesis:
        """Inject one schema-valid factual error at the selected target node."""

        if self.variant == "normal" or hypothesis.node_id != self.target_node_id:
            return hypothesis
        self.expected_hypotheses_by_id[hypothesis.hypothesis_id] = hypothesis
        update: dict[str, object]
        if self.variant == "wrong-classification":
            update = {
                "proposed_classification": _different_classification(
                    hypothesis.proposed_classification
                )
            }
        elif self.variant == "wrong-effect-state":
            effects = list(hypothesis.effect_hypotheses)
            first = effects[0]
            effects[0] = first.model_copy(
                update={"state": _different_effect_state(first.state)}
            )
            update = {"effect_hypotheses": tuple(effects)}
        elif self.variant == "wrong-alternative-history":
            classification = _different_classification(
                hypothesis.proposed_classification
            )
            state = (
                EffectAssertionState.ESTABLISHED
                if classification is Classification.COMMITTED
                else EffectAssertionState.NOT_ESTABLISHED
            )
            update = {
                "alternative_histories": (
                    PossibleHistory(
                        history_id="qualification-wrong-alternative",
                        classification=classification,
                        effect_states=tuple(
                            HypothesizedEffect(
                                effect_id=item.effect_id,
                                state=state,
                                cited_evidence_ids=item.cited_evidence_ids,
                            )
                            for item in hypothesis.effect_hypotheses
                        ),
                        compatible_evidence_ids=hypothesis.cited_evidence_ids,
                        summary="A schema-valid but factually incorrect history.",
                    ),
                )
            }
        else:  # pragma: no cover - constructor/plan validates the variant
            raise AssertionError("unknown wrong-hypothesis variant")
        return GeminiHypothesis.model_validate(
            hypothesis.model_copy(update=update).model_dump(mode="python")
        )


class _RecordingEvidenceSource:
    def __init__(
        self,
        delegate: ReleaseChainEvidenceSource,
        target_node_id: str,
        *,
        repeat_target_primary: bool,
        target_replay_state: RecoveryEvidenceState | None,
    ) -> None:
        self.delegate = delegate
        self.target_node_id = target_node_id
        self.repeat_target_primary = repeat_target_primary
        self.target_replay_state = target_replay_state
        self._target_primary_repeated = False
        self.probe_count = 0
        self.elapsed_ms = 0
        self.unsupported_probe_count = 0
        self._round_audit_count = 0
        self._round_probe_count_used = 0
        self._round_elapsed_ms = 0
        self.states: list[RecoveryEvidenceState] = []
        self._measurements_by_report: dict[str, tuple[int, int, int]] = {}

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
            current_probe_count_used = (
                state.report.probe_audit[-1].probe_count_used
                if state.report.probe_audit
                else 0
            )
            current_elapsed_ms = (
                state.report.probe_audit[-1].session_elapsed_ms
                if state.report.probe_audit
                else 0
            )
            self.probe_count += (
                current_probe_count_used
                if refresh
                else current_probe_count_used - self._round_probe_count_used
            )
            self.elapsed_ms += (
                current_elapsed_ms
                if refresh
                else current_elapsed_ms - self._round_elapsed_ms
            )
            decisions = {
                item.evidence_id: item for item in state.report.evidence_decisions
            }
            self.unsupported_probe_count += sum(
                ProbeStopReason(item.stop_reason) in _UNSUPPORTED_STOP_REASONS
                or any(
                    decisions[evidence_id].reason
                    is EvidenceReason.UNSUPPORTED_CAPABILITY
                    for evidence_id in item.evidence_ids
                )
                for item in records
            )
            self._round_audit_count = current
            self._round_probe_count_used = current_probe_count_used
            self._round_elapsed_ms = current_elapsed_ms
            self.states.append(state)
            self._measurements_by_report.setdefault(
                canonical_sha256(state.report),
                (
                    self.probe_count,
                    self.elapsed_ms,
                    self.unsupported_probe_count,
                ),
            )
        return state

    def measurement_for_report(self, report_sha256: str) -> tuple[int, int, int]:
        """Return cumulative acquisition cost when a proof report first appeared."""

        try:
            return self._measurements_by_report[report_sha256]
        except KeyError:
            raise ValueError(
                "qualification proof report has no acquisition measurement"
            ) from None

    async def current(
        self,
        run_id: str,
        node: RecoveryActionNode,
        envelope: ExecutionEnvelope,
    ) -> RecoveryEvidenceState:
        if node.node_id == self.target_node_id and self.target_replay_state is not None:
            return self._record(node, self.target_replay_state, refresh=True)
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


class _QualificationControllerClock:
    def __init__(self, now: Callable[[], datetime]) -> None:
        self._now = now
        self._monotonic_ms = 0

    def monotonic(self) -> float:
        value = self._monotonic_ms / 1_000
        self._monotonic_ms += 1
        return value

    def now(self) -> datetime:
        return self._now()


class _ReplayObservationHandler:
    """Replay one captured provider response byte-for-byte on the final call."""

    def __init__(
        self,
        delegate: object,
        replay_at_call: int,
        replay_observation_index: int | None,
    ) -> None:
        if not callable(delegate):
            raise TypeError("qualification replay requires a callable provider")
        self._delegate = delegate
        self._replay_at_call = replay_at_call
        self._replay_observation_index = replay_observation_index
        self._calls = 0
        self._observations: list[object] = []
        self.replayed = False

    async def __call__(self, probe: object) -> object:
        self._calls += 1
        if (
            self._calls == self._replay_at_call
            and self._replay_observation_index is not None
            and len(self._observations) > self._replay_observation_index
        ):
            self.replayed = True
            return self._observations[self._replay_observation_index]
        value = await self._delegate(probe)  # type: ignore[misc]
        self._observations.append(value)
        return value


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


class _QualificationDispatchHeld(asyncio.CancelledError):
    """Internal signal that a safety replay reached its dispatch boundary."""


async def _run_to_qualification_dispatch_boundary(
    workflow: ProofToPermitWorkflow,
    run_id: str,
) -> RecoveryRunSnapshot | None:
    """Return ``None`` only for the runner's private dispatch-hold signal."""

    try:
        return await workflow.run(run_id)
    except _QualificationDispatchHeld:
        return None


class _StopBeforeTargetDispatch:
    """Stop a safety replay after its target permit is durably issued."""

    def __init__(
        self,
        delegate: ReleaseChainDispatchGateway,
        target_node_id: str,
    ) -> None:
        self._delegate = delegate
        self._target_node_id = target_node_id

    async def dispatch(
        self,
        prepared: RecoveryPreparedAction,
        scope: RecoveryActionScope,
    ) -> RecoveryDispatchReceipt:
        if (
            scope.authority_kind is RecoveryAuthorityKind.ACTION_PERMIT
            and prepared.source_node_id == self._target_node_id
        ):
            raise _QualificationDispatchHeld
        return await self._delegate.dispatch(prepared, scope)


def _target_node_id(fixture: RecoveryQualificationFixture) -> str:
    return fixture.archetype.stage.value


def _fault(fixture: RecoveryQualificationFixture) -> RecoveryRunFault:
    if fixture.archetype.archetype_id == "record-predispatch-retry":
        return RecoveryRunFault.SUPPRESS_BEFORE_DISPATCH
    if (
        fixture.archetype.stage.value == "stage"
        and fixture.archetype.fault_class.value == "drop-after-accept"
    ):
        return RecoveryRunFault.DROP_AFTER_ACCEPT
    # All other qualification states come from provider-visible observations;
    # they must not borrow either production fault-injection boundary.
    return RecoveryRunFault.NO_FAULT


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


def _observed_evidence_profile(
    state: RecoveryEvidenceState,
    snapshot: RecoveryRunSnapshot,
    node_id: str,
) -> tuple[str, ...]:
    """Derive the public coverage vocabulary from sealed evidence and receipts."""

    tool_name = state.envelope.context.invocation.tool_name
    stage = tool_name == "stage-cloud-run-revision"
    promote = tool_name == "promote-cloud-run-traffic"
    record = tool_name == "create-firestore-release-record"
    if not (stage or promote or record):  # pragma: no cover - sealed definition
        raise AssertionError("qualification target tool is outside the frozen chain")

    facts: set[str] = set()
    evidence_by_id = {item.evidence_id: item for item in state.report.evidence}
    decisions_by_id = {
        item.evidence_id: item for item in state.report.evidence_decisions
    }
    evidence_by_capability: dict[str, list[NormalizedEvidence]] = {}
    for audit in state.report.probe_audit:
        capability_name = audit.capability_name
        if capability_name is None:  # pragma: no cover - controller invariant
            continue
        evidence_id = audit.evidence_ids[0]
        evidence = evidence_by_id.get(evidence_id)
        decision = decisions_by_id[evidence_id]
        if audit.outcome is ProbeOutcome.UNAVAILABLE and (
            audit.stop_reason == ProbeStopReason.CAPABILITY_UNAVAILABLE.value
        ):
            if stage and capability_name == CLOUD_RUN_SERVICE_CAPABILITY:
                facts.add("stage-service-read-unavailable")
            elif promote and capability_name == CLOUD_RUN_SERVICE_CAPABILITY:
                facts.add("promote-service-read-unavailable")
            elif record and capability_name == FIRESTORE_RELEASE_CAPABILITY:
                facts.add("record-state-read-unavailable")
        if (
            stage
            and audit.outcome is ProbeOutcome.COMPLETED
            and evidence is None
            and decision.reason is EvidenceReason.UNVERIFIABLE_AUTHORITY
        ):
            facts.add("stage-observation-stale")
        if (
            record
            and capability_name == FIRESTORE_RELEASE_CAPABILITY
            and audit.outcome is ProbeOutcome.COMPLETED
            and evidence is None
            and decision.reason
            in {
                EvidenceReason.CORRELATION_MISMATCH,
                EvidenceReason.EXPECTED_EFFECT_MISMATCH,
                EvidenceReason.MALFORMED_OBSERVATION,
            }
        ):
            facts.add("record-target-mismatch")
        if (
            record
            and capability_name == DISPATCH_RECEIPT_CAPABILITY
            and audit.outcome is ProbeOutcome.COMPLETED
            and evidence is None
            and decision.reason is EvidenceReason.MALFORMED_OBSERVATION
        ):
            facts.add("record-noncontact-receipt-absent")
        if evidence is None:
            continue
        if evidence.capability_version != RECOVERY_CAPABILITY_VERSION:
            raise AssertionError("qualification evidence capability version changed")
        evidence_by_capability.setdefault(capability_name, []).append(evidence)
        correlation = evidence.correlation
        if stage:
            facts.add("stage-observation-fresh")
            if capability_name == CLOUD_RUN_SERVICE_CAPABILITY and (
                correlation.get("observation_schema")
                == CLOUD_RUN_SERVICE_OBSERVATION_VERSION
                and evidence.authority is EvidenceAuthority.TARGET_STATE
                and decision.disposition is EvidenceDisposition.ADMITTED
                and decision.reason
                in {
                    EvidenceReason.AUTHORITATIVE_EXACT_CORRELATION,
                    EvidenceReason.AUTHORITATIVE_ACTIVE_STATUS,
                }
                and correlation.get("revision_traffic_percent") == "0"
            ):
                facts.add("stage-traffic-unchanged")
            elif capability_name == CLOUD_RUN_REVISION_CAPABILITY and (
                correlation.get("observation_schema")
                == CLOUD_RUN_REVISION_OBSERVATION_VERSION
            ):
                if correlation:
                    facts.add("stage-revision-exists")
                if correlation.get("readiness") == "READY":
                    facts.add("stage-revision-ready")
                if correlation.get("reconciling") == "true":
                    facts.add("stage-revision-reconciling")
                if correlation.get("terminal_condition") == "FAILED":
                    facts.add("stage-revision-terminal-failed")
            elif capability_name == CLOUD_RUN_HEALTH_CAPABILITY and (
                correlation.get("observation_schema")
                == CLOUD_RUN_HEALTH_OBSERVATION_VERSION
            ):
                health_status = correlation.get("health_status")
                if health_status == "READY":
                    facts.add("stage-health-ready")
                elif health_status == "UNHEALTHY":
                    facts.add("stage-health-unhealthy")
            if (
                capability_name == CLOUD_RUN_REVISION_CAPABILITY
                and not correlation
                and decision.reason
                in {
                    EvidenceReason.CORRELATION_MISMATCH,
                    EvidenceReason.NOT_FOUND_ABSENCE_ONLY,
                }
            ):
                facts.add("stage-revision-not-found")
        elif (
            promote
            and capability_name == CLOUD_RUN_SERVICE_CAPABILITY
            and (
                correlation.get("observation_schema")
                == CLOUD_RUN_SERVICE_OBSERVATION_VERSION
            )
        ):
            facts.add("promote-service-fresh")
            if evidence.operation_status is OperationStatus.ACTIVE:
                facts.add("promote-service-reconciling")
            traffic = correlation.get("revision_traffic_percent")
            if traffic == "100":
                facts.add("promote-serving-intended")
            elif traffic == "0":
                facts.add("promote-serving-baseline")
        elif (
            record
            and capability_name == FIRESTORE_RELEASE_CAPABILITY
            and (
                correlation.get("observation_schema")
                == FIRESTORE_DOCUMENT_OBSERVATION_VERSION
            )
        ):
            if correlation.get("exists") == "true":
                if any(
                    assertion.state is EffectAssertionState.ESTABLISHED
                    for assertion in evidence.effect_assertions
                ):
                    facts.update({"record-exists", "record-payload-matches"})
            elif correlation.get("exists") == "false":
                facts.add("record-absent")
        elif (
            record
            and capability_name == DISPATCH_RECEIPT_CAPABILITY
            and (
                correlation.get("observation_schema")
                == DISPATCH_RECEIPT_OBSERVATION_VERSION
            )
        ):
            if correlation.get("outcome") == "SUPPRESSED_BEFORE_DISPATCH":
                facts.update(
                    {"record-provider-not-contacted", "record-receipt-suppressed"}
                )

    if stage or promote:
        service_etags = {
            item.correlation.get("service_etag")
            for item in evidence_by_capability.get(CLOUD_RUN_SERVICE_CAPABILITY, ())
        }
        service_etags.discard(None)
        if len(service_etags) > 1:
            facts.add(
                "stage-service-etag-conflict"
                if stage
                else "promote-service-etag-conflict"
            )
    if record and any(
        receipt.node_id == node_id and receipt.provider_contact
        for receipt in snapshot.dispatch_receipts
    ):
        facts.add("record-provider-contacted")
    return tuple(sorted(facts))


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


def _evidence_semantics(evidence: NormalizedEvidence) -> dict[str, object]:
    return {
        "authority": evidence.authority.value,
        "capability_name": evidence.capability_name,
        "capability_version": evidence.capability_version,
        "effect_assertions": [
            {"effect_id": item.effect_id, "state": item.state.value}
            for item in sorted(
                evidence.effect_assertions,
                key=lambda assertion: (assertion.effect_id, assertion.state.value),
            )
        ],
        "operation_status": (
            None
            if evidence.operation_status is None
            else evidence.operation_status.value
        ),
        "correlation": {
            key: value
            for key, value in evidence.correlation.items()
            if key != "receipt_id"
        },
        "provenance": {
            "source": evidence.provenance.source,
            "source_record": evidence.provenance.source_record,
            "adapter_version": evidence.provenance.adapter_version,
        },
        "target": evidence.target.model_dump(mode="json"),
    }


def _witness_semantics(
    artifact: AmbiguityWitness,
    evidence_by_id: dict[str, NormalizedEvidence] | None = None,
) -> dict[str, object]:
    value: dict[str, object] = {
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
    if evidence_by_id is not None:
        value["supporting_evidence_count"] = len(artifact.evidence)
        value["supporting_evidence"] = sorted(
            (
                _evidence_semantics(evidence_by_id[binding.evidence_id])
                for binding in artifact.evidence
            ),
            key=canonical_json_value_bytes,
        )
        value["conflicting_evidence"] = sorted(
            (
                _evidence_semantics(evidence_by_id[evidence_id])
                for evidence_id in artifact.conflicting_evidence_ids
            ),
            key=canonical_json_value_bytes,
        )
    return value


def _artifact_semantic_sha256(
    artifact: VerifiedCertificate | AmbiguityWitness,
    *,
    evidence_by_id: dict[str, NormalizedEvidence] | None = None,
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
        value = {
            "kind": "AMBIGUITY_WITNESS",
            **_witness_semantics(artifact, evidence_by_id),
        }
    return hashlib.sha256(canonical_json_value_bytes(value)).hexdigest()


def _decision_semantic_sha256(
    decision: RecoveryDecision,
    artifact: VerifiedCertificate | AmbiguityWitness,
    state: RecoveryEvidenceState,
) -> str:
    evidence_by_id = {item.evidence_id: item for item in state.evaluation.evidence}
    return hashlib.sha256(
        canonical_json_value_bytes(
            {
                "decision": decision.value,
                "artifact_sha256": _artifact_semantic_sha256(
                    artifact,
                    evidence_by_id=(
                        evidence_by_id
                        if isinstance(artifact, AmbiguityWitness)
                        else None
                    ),
                ),
                "admitted_evidence_sha256": _semantic_evidence_sha256(
                    state,
                    artifact,
                ),
            }
        )
    ).hexdigest()


def _permit_semantic_sha256(
    artifact: VerifiedCertificate | AmbiguityWitness,
) -> str | None:
    if not isinstance(artifact, VerifiedCertificate) or artifact.transition is None:
        return None
    return hashlib.sha256(
        canonical_json_value_bytes(_transition_value(artifact))
    ).hexdigest()


def _require_exact_artifact_permit(
    action_permits: tuple[ActionPermit, ...],
    artifact: VerifiedCertificate | AmbiguityWitness,
) -> ActionPermit | None:
    target_permits = tuple(
        item for item in action_permits if item.source_node_id == artifact.node_id
    )
    if not isinstance(artifact, VerifiedCertificate):
        if target_permits:
            raise AssertionError("ambiguity witness gained a durable permit")
        return None
    matches = tuple(
        item
        for item in action_permits
        if item.certificate_id == artifact.certificate_id
        and item.certificate_sha256 == canonical_sha256(artifact)
    )
    expected = action_permit_from_certificate(artifact)
    if artifact.transition is None:
        if expected is not None or target_permits:
            raise AssertionError("non-authorizing certificate gained a durable permit")
        return None
    if len(matches) != 1 or target_permits != matches or expected is None:
        raise AssertionError("certified qualification action has no unique permit")
    permit = matches[0]
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
    if issued_projection != expected:
        raise AssertionError(
            "qualification permit is not exactly bound to its certificate"
        )
    return permit


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
    baseline_decision: RecoveryDecision,
    baseline_artifact: VerifiedCertificate | AmbiguityWitness,
    baseline_state: RecoveryEvidenceState,
    permit_clock: Callable[[], datetime],
) -> tuple[RecoveryQualificationWrongExecution, ...]:
    """Run each bad Gemini proposal through an isolated production workflow."""

    baseline_decision_sha256 = _decision_semantic_sha256(
        baseline_decision,
        baseline_artifact,
        baseline_state,
    )
    baseline_permit = _permit_semantic_sha256(baseline_artifact)
    results = []
    for index, variant in enumerate(_WRONG_VARIANTS, 1):
        foundation = build_recovery_qualification_foundation(
            fixture,
            state_directory=state_directory / variant,
            # Replay certificates retain the baseline evidence timestamp, so
            # their authority must advance from that same per-case clock.
            permit_clock=permit_clock,
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
        planner = _ScriptedPlanner(variant, target_node_id=target_node_id)
        stores = foundation.stores.open()
        workflow, source = _build_workflow(
            foundation=foundation,
            stores=stores,
            definition=definition,
            planner=planner,
            target_node_id=target_node_id,
            fixture=fixture,
            stop_before_target_dispatch=True,
            target_replay_state=baseline_state,
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
        snapshot = await _run_to_qualification_dispatch_boundary(
            workflow,
            request.run_id,
        )
        if snapshot is None:
            snapshot = await stores.run_store.get(request.run_id)
        events = await stores.run_store.events(request.run_id)
        decision, artifact = _target_decision(events, target_node_id)
        state = _state_for_artifact(source, artifact)
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
        if hypothesis is None:
            raise AssertionError(
                f"wrong hypothesis {variant!r} was not well formed: {disposition}"
            )
        if hypothesis.node_id != target_node_id:
            raise AssertionError("wrong hypothesis audit changed target identity")
        if disposition not in {
            RecoveryHypothesisDisposition.SELECTED,
            RecoveryHypothesisDisposition.NO_PROBE,
        }:
            raise AssertionError("wrong factual hypothesis used an invalid probe path")
        expected_hypothesis = planner.expected_hypotheses_by_id.get(
            hypothesis.hypothesis_id
        )
        if expected_hypothesis is None:
            raise AssertionError("wrong hypothesis lacks its expected oracle")
        wrongness_kind = {
            "wrong-classification": (
                RecoveryQualificationHypothesisWrongnessKind.CLASSIFICATION
            ),
            "wrong-effect-state": (
                RecoveryQualificationHypothesisWrongnessKind.EFFECT_STATE
            ),
            "wrong-alternative-history": (
                RecoveryQualificationHypothesisWrongnessKind.ALTERNATIVE_HISTORIES
            ),
        }[variant]
        decision_sha256 = _decision_semantic_sha256(decision, artifact, state)
        permit_sha256 = _permit_semantic_sha256(artifact)
        _require_exact_artifact_permit(snapshot.action_permits, artifact)
        results.append(
            RecoveryQualificationWrongExecution(
                variant_id=variant,
                wrongness_kind=wrongness_kind,
                planner_output_sha256=planner.turns[target_index].output_sha256,
                report=state.report,
                expected_hypothesis=expected_hypothesis,
                hypothesis=hypothesis,
                hypothesis_sha256=canonical_sha256(hypothesis),
                disposition=disposition,
                decision_sha256=decision_sha256,
                permit_sha256=permit_sha256,
            )
        )
        if (
            decision_sha256 != baseline_decision_sha256
            or permit_sha256 != baseline_permit
        ):
            raise AssertionError(
                f"wrong hypothesis {variant!r} changed deterministic authority: "
                f"decision {decision_sha256} != {baseline_decision_sha256} or "
                f"permit {permit_sha256} != {baseline_permit}"
            )
    return tuple(results)


async def _duplicate_witness_state(
    *,
    foundation: RecoveryQualificationFoundation,
    stores: RecoveryQualificationStores,
    run_id: str,
    node: RecoveryActionNode,
    baseline: RecoveryEvidenceState,
) -> tuple[RecoveryEvidenceState, RecoveryQualificationWitnessReplayKind]:
    """Replay admitted bytes or repeat one response-free rejected request."""

    provider = foundation.provider
    envelope = baseline.envelope
    capability_sequence = tuple(
        record.capability_name
        for record in baseline.report.probe_audit
        if record.capability_name is not None
    )
    if not capability_sequence:
        raise AssertionError("witness replay has no provider attempt to duplicate")
    attempts_by_sequence = {
        attempt.probe_sequence: attempt for attempt in baseline.evaluation.attempts
    }
    completed_admitted_records = tuple(
        record
        for record in baseline.report.probe_audit
        if record.outcome is ProbeOutcome.COMPLETED
        and record.capability_name is not None
        and record.result_sha256 is not None
        and (attempt := attempts_by_sequence.get(record.probe_sequence)) is not None
        and attempt.evidence is not None
        and attempt.decision.disposition is EvidenceDisposition.ADMITTED
    )
    if completed_admitted_records:
        selected_record = completed_admitted_records[0]
        duplicate_capability = selected_record.capability_name
        if duplicate_capability is None:  # pragma: no cover - selection invariant
            raise AssertionError("witness replay lost its selected capability")
        selected_occurrence = sum(
            record.capability_name == duplicate_capability
            for record in baseline.report.probe_audit
            if record.probe_sequence < selected_record.probe_sequence
        )
        replay_sequence = (*capability_sequence, duplicate_capability)
        expected_replay_kind = (
            RecoveryQualificationWitnessReplayKind.EVIDENCE_DUPLICATION
        )
    else:
        # A weak, rejected, or unavailable observation is not admitted evidence.
        # Exercise a literal response-free replay instead of mislabeling it as
        # evidence duplication: the same unknown read is rejected twice before
        # any provider handler can run.
        duplicate_capability = "qualification-zero-evidence-probe"
        selected_occurrence = None
        replay_sequence = (
            *capability_sequence,
            duplicate_capability,
            duplicate_capability,
        )
        expected_replay_kind = (
            RecoveryQualificationWitnessReplayKind.ZERO_EVIDENCE_REPLAY
        )
    if len(replay_sequence) > envelope.context.evidence_budget.max_probes:
        raise AssertionError(
            "witness replay exceeds the preregistered probe-count boundary"
        )
    invocation_counts = Counter(capability_sequence)
    capabilities = CapabilityRegistry()
    rules = TargetRuleRegistry()
    replay_handler: _ReplayObservationHandler | None = None

    if node.node_id in {"stage", "promote"}:
        binding = (
            CloudRunProbeBinding.for_stage(
                release_id=provider.settings.release_id,
                image_digest=provider.settings.image_digest,
                configuration_sha256=provider.settings.configuration_sha256,
                expected_revision=provider.settings.staged_revision,
            )
            if node.node_id == "stage"
            else CloudRunProbeBinding.for_promotion(
                release_id=provider.settings.release_id,
                revision=provider.settings.staged_revision,
            )
        )
        for reference in envelope.context.enabled_capabilities:
            registration = build_cloud_run_capability_registration(
                reader=provider.cloud_reader,
                binding=binding,
                capability_name=reference.name,
                target=envelope.target,
                clock=provider.clock,
            )
            if reference.name == duplicate_capability:
                if registration.handler is None:  # pragma: no cover - sealed builder
                    raise AssertionError("duplicate replay capability has no handler")
                replay_handler = _ReplayObservationHandler(
                    registration.handler,
                    invocation_counts[reference.name] + 1,
                    (
                        selected_occurrence
                        if expected_replay_kind
                        is RecoveryQualificationWitnessReplayKind.EVIDENCE_DUPLICATION
                        else None
                    ),
                )
                registration = CapabilityRegistration(
                    capability=registration.capability,
                    semantics=registration.semantics,
                    enabled=registration.enabled,
                    argument_byte_ceiling=registration.argument_byte_ceiling,
                    max_invocations=max(
                        registration.max_invocations,
                        invocation_counts[reference.name] + 1,
                    ),
                    handler=replay_handler,
                )
            capabilities.register(registration)
            rules.register(
                build_cloud_run_rule_registration(
                    capability_name=reference.name,
                    binding=binding,
                )
            )
    else:
        snapshot = await stores.run_store.get(run_id)
        progress = next(item for item in snapshot.nodes if item.node_id == node.node_id)
        binding = FirestoreReleaseProbeBinding(
            run_id=run_id,
            node_id=node.node_id,
            attempt=max(1, progress.attempt),
            release_id=provider.settings.release_id,
            cloud_run_revision=provider.settings.staged_revision,
            payload_sha256=provider.settings.payload_sha256,
            semantic_action_sha256=node.semantic_action.semantic_action_sha256,
        )
        receipts = RecoveryRunReceiptReader(stores.run_store)
        for reference in envelope.context.enabled_capabilities:
            registration = build_firestore_release_capability_registration(
                target=provider.firestore,
                receipts=receipts,
                binding=binding,
                capability_name=reference.name,
                action_target=envelope.target,
                clock=provider.clock,
            )
            if reference.name == duplicate_capability:
                if registration.handler is None:  # pragma: no cover - sealed builder
                    raise AssertionError("duplicate replay capability has no handler")
                replay_handler = _ReplayObservationHandler(
                    registration.handler,
                    invocation_counts[reference.name] + 1,
                    (
                        selected_occurrence
                        if expected_replay_kind
                        is RecoveryQualificationWitnessReplayKind.EVIDENCE_DUPLICATION
                        else None
                    ),
                )
                registration = CapabilityRegistration(
                    capability=registration.capability,
                    semantics=registration.semantics,
                    enabled=registration.enabled,
                    argument_byte_ceiling=registration.argument_byte_ceiling,
                    max_invocations=max(
                        registration.max_invocations,
                        invocation_counts[reference.name] + 1,
                    ),
                    handler=replay_handler,
                )
            capabilities.register(registration)
            rules.register(
                build_firestore_release_rule_registration(
                    capability_name=reference.name,
                    binding=binding,
                )
            )

    controller = ProbeController(
        envelope,
        capabilities,
        clock=_QualificationControllerClock(provider.clock),
    )
    engine = EvidenceEngine(envelope, rules)
    relevant_effect_ids = tuple(
        effect.effect_id for effect in envelope.expected_effects
    )
    for capability_name in replay_sequence:
        request = ProbeRequest(
            schema_version=PROBE_REQUEST_VERSION,
            capability_name=capability_name,
            capability_version="1.0.0",
            relevant_effect_ids=relevant_effect_ids,
            arguments={},
            rationale="Replay one exact target-bound provider observation.",
        )
        execution = await controller.execute(request)
        if execution.audit.sequence <= len(engine.attempts):
            raise AssertionError(
                "witness replay reached a terminal controller state before "
                "the preregistered sequence completed"
            )
        engine.process(ProbeRun(request=request, execution=execution))
    audit = controller.audit_trail
    evaluation = engine.evaluate(audit)
    appended = evaluation.attempts[-1]
    prior = evaluation.attempts[:-1]
    if (
        expected_replay_kind
        is RecoveryQualificationWitnessReplayKind.EVIDENCE_DUPLICATION
    ):
        if (
            replay_handler is None
            or not replay_handler.replayed
            or appended.decision.disposition is not EvidenceDisposition.REJECTED
            or appended.decision.reason is not EvidenceReason.DUPLICATE_CANDIDATES
            or not any(
                item.request_sha256 == appended.request_sha256
                and item.raw_sha256 == appended.raw_sha256
                and item.evidence is not None
                and item.decision.disposition is EvidenceDisposition.ADMITTED
                for item in prior
            )
        ):
            raise AssertionError("exact replay did not enter evidence deduplication")
        replay_kind = RecoveryQualificationWitnessReplayKind.EVIDENCE_DUPLICATION
    else:
        if (
            replay_handler is not None
            or appended.evidence is not None
            or not any(
                item.evidence is None
                and item.request_sha256 == appended.request_sha256
                and item.raw_sha256 == appended.raw_sha256
                and item.decision.reason is appended.decision.reason
                for item in prior
            )
        ):
            raise AssertionError("zero-evidence witness attempt did not repeat exactly")
        replay_kind = RecoveryQualificationWitnessReplayKind.ZERO_EVIDENCE_REPLAY
    now = provider.clock()
    report = engine.report(
        audit,
        created_at=min(baseline.report.created_at, now),
        updated_at=max(baseline.report.created_at, now),
        revision=max(1, len(audit)),
    )
    return RecoveryEvidenceState(envelope, report, evaluation), replay_kind


async def _witness_replays(
    *,
    foundation: RecoveryQualificationFoundation,
    stores: RecoveryQualificationStores,
    run_id: str,
    definition: RecoveryRunDefinition,
    node: RecoveryActionNode,
    state: RecoveryEvidenceState,
    baseline: AmbiguityWitness,
) -> tuple[str, str, str, RecoveryQualificationWitnessReplayKind]:
    baseline_evidence = {item.evidence_id: item for item in state.evaluation.evidence}
    semantic = hashlib.sha256(
        canonical_json_value_bytes(_witness_semantics(baseline, baseline_evidence))
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
    duplicated_state, replay_kind = await _duplicate_witness_state(
        foundation=foundation,
        stores=stores,
        run_id=run_id,
        node=node,
        baseline=state,
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
            canonical_json_value_bytes(_witness_semantics(reordered, baseline_evidence))
        ).hexdigest(),
        hashlib.sha256(
            canonical_json_value_bytes(
                _witness_semantics(
                    duplicated,
                    {
                        item.evidence_id: item
                        for item in duplicated_state.evaluation.evidence
                    },
                )
            )
        ).hexdigest(),
        replay_kind,
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
    stop_before_target_dispatch: bool = False,
    target_replay_state: RecoveryEvidenceState | None = None,
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
            controller_clock=_QualificationControllerClock(provider.clock),
        ),
        target_node_id,
        repeat_target_primary=provider.archetype_id
        in {"stage-conflict", "promote-conflict"},
        target_replay_state=target_replay_state,
    )
    gateway = ReleaseChainDispatchGateway(
        settings=provider.settings,
        store=stores.run_store,
        permit_authority=stores.permit_authority,
        cloud_run=provider.cloud_action,
        firestore=provider.firestore,
        clock=provider.clock,
    )
    if crash_after_completed_target_dispatch and stop_before_target_dispatch:
        raise ValueError("qualification dispatch boundaries are mutually exclusive")
    if crash_after_completed_target_dispatch:
        dispatch_gateway = _CrashAfterCompletedTargetDispatch(gateway, target_node_id)
    elif stop_before_target_dispatch:
        dispatch_gateway = _StopBeforeTargetDispatch(gateway, target_node_id)
    else:
        dispatch_gateway = gateway
    workflow = ProofToPermitWorkflow(
        store=stores.run_store,
        definition_factory=lambda _request: definition,
        evidence_source=evidence,
        action_preparer=ReleaseChainActionPreparer(),
        recovery_agent=RecoveryAgent(
            planner,
            clock=provider.clock,
            hypothesis_transformer=(
                planner.transform_hypothesis if planner.variant != "normal" else None
            ),
        ),
        rollout_agent=RolloutAgent(dispatch_gateway),
        permit_authority=stores.permit_authority,
        clock=provider.clock,
        claim_id_factory=foundation.stores.next_claim_id,
    )
    return workflow, evidence


async def prepare_recovery_qualification_contention_dispatch(
    fixture: RecoveryQualificationFixture,
    *,
    state_directory: str | Path,
    permit_backend: RecoveryQualificationStorageBackend,
) -> RecoveryQualificationContentionDispatch:
    """Run fixed proof until its target transition is issued but undispatched."""

    action = fixture.archetype.expected_permit_action
    if action not in {PermitAction.CONTINUE, PermitAction.RETRY}:
        raise ValueError("contention fixture must issue CONTINUE or RETRY")
    foundation = build_recovery_qualification_foundation(
        fixture,
        state_directory=state_directory,
    )
    provider = foundation.provider
    provider.require_supported()
    definition = _slice_definition(provider, fixture)
    planner = _ScriptedPlanner()
    stores = foundation.stores.open()
    target_node_id = _target_node_id(fixture)
    workflow, _source = _build_workflow(
        foundation=foundation,
        stores=stores,
        definition=definition,
        planner=planner,
        target_node_id=target_node_id,
        fixture=fixture,
        stop_before_target_dispatch=True,
    )
    request = RecoveryRunRequest(
        schema_version=RECOVERY_RUN_REQUEST_VERSION,
        run_id=f"{fixture.case_id}-contention",
        scenario="cloud-run-rollout",
        policy=RecoveryRunPolicy.FIXED,
        fault=_fault(fixture),
    )
    await stores.run_store.create(
        request,
        definition.chain,
        created_at=provider.invoked_at,
    )
    held_snapshot = await _run_to_qualification_dispatch_boundary(
        workflow,
        request.run_id,
    )
    if held_snapshot is not None:  # pragma: no cover - guarded by the boundary
        raise AssertionError("contention setup dispatched its target transition")

    snapshot = await stores.run_store.get(request.run_id)
    issued = tuple(
        permit
        for permit in snapshot.action_permits
        if permit.state is ActionPermitState.ISSUED and permit.action is action
    )
    if len(issued) != 1:
        raise AssertionError("contention setup did not retain one issued permit")
    permit = await stores.permit_authority.get_permit(issued[0].permit_id)
    certificate = next(
        (
            item
            for item in snapshot.certificates
            if item.certificate_id == permit.certificate_id
            and canonical_sha256(item) == permit.certificate_sha256
        ),
        None,
    )
    if certificate is None or certificate.transition is None:
        raise AssertionError("contention permit lost its verified certificate")
    events = await stores.run_store.events(request.run_id)
    report = next(
        (
            event.payload.report
            for event in reversed(events.events)
            if event.payload.report is not None
            and canonical_sha256(event.payload.report) == certificate.report_sha256
        ),
        None,
    )
    if report is None:
        raise AssertionError("contention certificate report is unavailable")
    firestore_client = None
    if permit_backend is RecoveryQualificationStorageBackend.FIRESTORE:
        permit_factory = build_qualification_firestore_store_factory(
            f"contention-{fixture.case_id}",
            provider.clock,
            counters=provider.counters,
        )
        permit_stores = permit_factory.open()
        await permit_stores.permit_authority.issue_permit(certificate)
        rendezvous_store = _ClaimRendezvousStore(
            permit_stores.permit_store,
            RECOVERY_QUALIFICATION_CONTENTION_WIDTH,
        )
        stores = RecoveryQualificationStores(
            run_store=stores.run_store,
            permit_store=rendezvous_store,
            permit_authority=PermitAuthority(
                rendezvous_store,
                clock=provider.clock,
                claim_id_factory=permit_factory.next_claim_id,
            ),
            cas_store=permit_stores.cas_store,
        )
        firestore_client = permit_factory.firestore_client
    elif permit_backend is not RecoveryQualificationStorageBackend.SQLITE:
        raise ValueError("contention permit backend is unsupported")
    source_node = next(
        node for node in definition.chain.nodes if node.node_id == permit.source_node_id
    )
    target_node = next(
        node for node in definition.chain.nodes if node.node_id == permit.target_node_id
    )
    prepared = ReleaseChainActionPreparer().prepare(
        request,
        definition.chain,
        source_node,
        target_node,
        report,
        certificate,
    )
    scope = RecoveryActionScope(
        schema_version=RECOVERY_ACTION_SCOPE_VERSION,
        authority_kind=RecoveryAuthorityKind.ACTION_PERMIT,
        run_id=request.run_id,
        source_node_id=permit.source_node_id,
        target_node_id=permit.target_node_id,
        semantic_action_sha256=permit.semantic_action_sha256,
        action_request_sha256=prepared.action_request_sha256,
        authority_id=permit.permit_id,
        authority_sha256=canonical_sha256(permit),
        claim_id="qualification-claim-00",
        permit_action=permit.action,
        certificate_id=certificate.certificate_id,
        certificate_sha256=canonical_sha256(certificate),
    )
    gateway = ReleaseChainDispatchGateway(
        settings=provider.settings,
        store=stores.run_store,
        permit_authority=stores.permit_authority,
        cloud_run=provider.cloud_action,
        firestore=provider.firestore,
        clock=provider.clock,
    )
    return RecoveryQualificationContentionDispatch(
        foundation=foundation,
        stores=stores,
        rollout_agent=RolloutAgent(gateway),
        prepared=prepared,
        scope=scope,
        permit=permit,
        baseline_provider_mutations=provider.counters.provider_mutations(),
        firestore_client=firestore_client,
    )


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
        crash_after_completed_target_dispatch=(crash_after_completed_target_dispatch),
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
            current_task = asyncio.current_task()
            if current_task is not None and current_task.cancelling():
                raise
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
    if policy is RecoveryQualificationPolicy.ADAPTIVE:
        planner_events = tuple(
            event
            for event in events.events
            if event.payload.hypothesis_disposition is not None
        )
        if len(planner_events) != len(planner.turns) or any(
            event.payload.hypothesis is None
            or event.payload.hypothesis_disposition
            not in {
                RecoveryHypothesisDisposition.SELECTED,
                RecoveryHypothesisDisposition.NO_PROBE,
            }
            for event in planner_events
        ):
            raise AssertionError(
                "scripted adaptive lane emitted an invalid hypothesis or fallback: "
                + repr(
                    tuple(
                        (
                            event.payload.hypothesis is not None,
                            event.payload.hypothesis_disposition,
                        )
                        for event in planner_events
                    )
                )
            )
    decision, artifact = _target_decision(events, target_node_id)
    state = _state_for_artifact(source, artifact)
    resolution = _resolution(decision, artifact)
    available_evidence_profile = _observed_evidence_profile(
        state,
        snapshot,
        target_node_id,
    )
    missing_profile = set(fixture.archetype.evidence_profile).difference(
        available_evidence_profile
    )
    if missing_profile:
        raise AssertionError(
            "qualification evidence profile was not observed: "
            + ", ".join(sorted(missing_profile))
        )
    semantic_decision = _decision_semantic_sha256(decision, artifact, state)
    semantic_permit = _permit_semantic_sha256(artifact)
    probe_count, elapsed_ms, unsupported_probe_count = source.measurement_for_report(
        artifact.report_sha256
    )
    permit_action = (
        artifact.transition.action
        if isinstance(artifact, VerifiedCertificate) and artifact.transition is not None
        else None
    )
    permit = _require_exact_artifact_permit(snapshot.action_permits, artifact)
    if (permit is None) is not (permit_action is None):
        raise AssertionError("qualification permit authority changed")
    target_node = next(
        node for node in definition.chain.nodes if node.node_id == target_node_id
    )
    wrong = (
        await _wrong_hypotheses(
            fixture=fixture,
            state_directory=Path(state_directory) / "wrong-hypotheses",
            baseline_decision=decision,
            baseline_artifact=artifact,
            baseline_state=state,
            permit_clock=provider.clock,
        )
        if policy is RecoveryQualificationPolicy.FIXED and _include_safety_replays
        else ()
    )
    witness_values: tuple[
        str | None,
        str | None,
        str | None,
        RecoveryQualificationWitnessReplayKind | None,
    ] = (None, None, None, None)
    if (
        policy is RecoveryQualificationPolicy.FIXED
        and _include_safety_replays
        and isinstance(artifact, AmbiguityWitness)
    ):
        witness_values = await _witness_replays(
            foundation=foundation,
            stores=stores,
            run_id=request.run_id,
            definition=definition,
            node=target_node,
            state=state,
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
        demonstrated_evidence_profile=fixture.archetype.evidence_profile,
        decision_sha256=semantic_decision,
        artifact_kind=artifact_kind,
        artifact_sha256=canonical_sha256(artifact),
        ambiguity_witness_sha256=(
            canonical_sha256(artifact)
            if isinstance(artifact, AmbiguityWitness)
            else None
        ),
        probe_count=probe_count,
        time_to_sufficient_evidence_ms=elapsed_ms,
        unsupported_probe_count=unsupported_probe_count,
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
        restarted_provider_mutations=None,
        wrong_hypotheses=wrong,
        witness_semantic_sha256=witness_values[0],
        reordered_witness_semantic_sha256=witness_values[1],
        replayed_witness_semantic_sha256=witness_values[2],
        witness_replay_kind=witness_values[3],
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
            or restarted.demonstrated_evidence_profile
            != result.demonstrated_evidence_profile
            or restarted.provider_mutations != result.provider_mutations
        ):
            raise AssertionError(
                "restart changed recovery evidence or provider effects"
            )
        return replace(
            result,
            restarted_snapshot_sha256=restarted.snapshot_sha256,
            restarted_decision_sha256=restarted.decision_sha256,
            restarted_permit_sha256=restarted.permit_sha256,
            restarted_provider_mutations=restarted.provider_mutations,
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
        target == "stage" and fixture.archetype.fault_class.value == "drop-after-accept"
    )
    stage_succeeded = await _blind_attempt(
        lambda: mutator.stage(
            operation_id=provider.settings.stage_operation_id,
            drop_after_accept=drop_stage_ack,
        ),
        retry=(
            (
                lambda: mutator.stage(
                    operation_id=f"{provider.settings.stage_operation_id}-retry",
                    drop_after_accept=False,
                )
            )
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
    record_succeeded = False
    if promote_succeeded:
        suppress_record = (
            target == "record"
            and fixture.archetype.fault_class.value == "suppress-before-dispatch"
        )
        if suppress_record:
            try:
                await mutator.create_record(suppress_before_dispatch=True)
            except ReleaseChainError as error:
                if str(error) != "blind release-record dispatch was suppressed":
                    raise
            else:  # pragma: no cover - guarded by the production mutator
                raise AssertionError("blind suppression boundary was not exercised")
            if retries:
                record_succeeded = await _blind_attempt(
                    lambda: mutator.create_record(suppress_before_dispatch=False),
                    retry=None,
                )
        else:
            record_succeeded = await _blind_attempt(
                lambda: mutator.create_record(suppress_before_dispatch=False),
                retry=(
                    (lambda: mutator.create_record(suppress_before_dispatch=False))
                    if retries
                    else None
                ),
            )
    resolution = (
        RecoveryQualificationResolution.COMPLETED
        if record_succeeded
        else RecoveryQualificationResolution.ABORT
    )
    return RecoveryQualificationBlindExecution(
        resolution=resolution,
        provider_mutations=provider.counters.provider_mutations(),
    )


__all__ = [
    "RecoveryQualificationBlindExecution",
    "RecoveryQualificationContentionDispatch",
    "RecoveryQualificationProofExecution",
    "RecoveryQualificationWrongExecution",
    "execute_recovery_qualification_blind_lane",
    "execute_recovery_qualification_proof_lane",
    "prepare_recovery_qualification_contention_dispatch",
]
