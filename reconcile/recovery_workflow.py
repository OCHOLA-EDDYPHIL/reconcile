"""Durable two-agent orchestration with deterministic proof authority."""

from __future__ import annotations

import asyncio
import hashlib
import inspect
from collections.abc import Awaitable, Callable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Protocol
from uuid import uuid4

from jsonschema import Draft202012Validator

from reconcile.adaptive import PlannerFailureKind
from reconcile.contracts import (
    RECOVERY_ACTION_SCOPE_VERSION,
    RECOVERY_LAUNCH_PERMIT_VERSION,
    ActionPermit,
    ActionPermitState,
    AmbiguityWitness,
    Classification,
    ExecutionEnvelope,
    GeminiHypothesis,
    InvestigationReport,
    ObservationCapability,
    PermitAction,
    RecoveryActionNode,
    RecoveryActionScope,
    RecoveryAuthorityKind,
    RecoveryChain,
    RecoveryDecision,
    RecoveryHypothesisDisposition,
    RecoveryLaunchPermit,
    RecoveryLaunchPermitState,
    RecoveryNodeProgress,
    RecoveryNodeState,
    RecoveryPreparedAction,
    RecoveryRunEventPayload,
    RecoveryRunEventType,
    RecoveryRunFailureCategory,
    RecoveryRunLifecycle,
    RecoveryRunPolicy,
    RecoveryRunRequest,
    RecoveryRunSnapshot,
    VerifiedCertificate,
    canonical_sha256,
)
from reconcile.controller.permits import (
    PermitAuthority,
    action_permit_from_certificate,
    dispatch_arguments_sha256,
    dispatch_precondition_sha256,
)
from reconcile.evidence.classification import CoreEvaluation
from reconcile.evidence.recovery_rules import validate_recovery_dispatch
from reconcile.evidence.recovery_verification import (
    RecoveryVerificationResult,
    verify_recovery,
)
from reconcile.persistence.permits import PermitNotFound
from reconcile.persistence.recovery_runs import (
    RecoveryRunConflict,
    RecoveryRunEventSnapshot,
    RecoveryRunStore,
)
from reconcile.recovery_agents import (
    RecoveryAgent,
    RolloutAgent,
    probe_request_sha256,
)

_MAX_ADAPTIVE_TURNS = 8
_MAX_OBSERVATION_ROUNDS = 8


class RecoveryWorkflowError(RuntimeError):
    """Sanitized workflow failure."""


class RecoveryDefinitionError(RecoveryWorkflowError):
    pass


class RecoveryEvidenceUnavailable(RecoveryWorkflowError):
    pass


@dataclass(frozen=True, slots=True)
class RecoveryEvidenceState:
    envelope: ExecutionEnvelope
    report: InvestigationReport
    evaluation: CoreEvaluation

    def __post_init__(self) -> None:
        if (
            type(self.envelope) is not ExecutionEnvelope
            or type(self.report) is not InvestigationReport
            or type(self.evaluation) is not CoreEvaluation
            or not self.evaluation.is_engine_output()
        ):
            raise TypeError("recovery evidence state must be sealed and exact")


class RecoveryEvidenceSource(Protocol):
    async def current(
        self,
        run_id: str,
        node: RecoveryActionNode,
        envelope: ExecutionEnvelope,
    ) -> RecoveryEvidenceState: ...

    async def probe(
        self,
        run_id: str,
        node: RecoveryActionNode,
        envelope: ExecutionEnvelope,
        request: object,
    ) -> RecoveryEvidenceState: ...

    async def fixed(
        self,
        run_id: str,
        node: RecoveryActionNode,
        envelope: ExecutionEnvelope,
    ) -> RecoveryEvidenceState: ...


class RecoveryActionPreparer(Protocol):
    """Prepare one exact outbound request from controller-admitted state."""

    def prepare(
        self,
        request: RecoveryRunRequest,
        chain: RecoveryChain,
        source_node: RecoveryActionNode,
        target_node: RecoveryActionNode,
        report: InvestigationReport | None,
        certificate: VerifiedCertificate | None,
    ) -> RecoveryPreparedAction | Awaitable[RecoveryPreparedAction]: ...


@dataclass(frozen=True, slots=True)
class RecoveryRunDefinition:
    chain: RecoveryChain
    envelopes: Mapping[str, ExecutionEnvelope]
    capabilities: Mapping[str, tuple[ObservationCapability, ...]]

    def __post_init__(self) -> None:
        if type(self.chain) is not RecoveryChain:
            raise TypeError("recovery definition requires an exact chain")
        node_ids = tuple(node.node_id for node in self.chain.nodes)
        if set(self.envelopes) != set(node_ids) or set(self.capabilities) != set(
            node_ids
        ):
            raise RecoveryDefinitionError(
                "recovery definition does not bind every node"
            )
        for node in self.chain.nodes:
            envelope = self.envelopes[node.node_id]
            if (
                type(envelope) is not ExecutionEnvelope
                or canonical_sha256(envelope) != node.envelope.envelope_sha256
                or envelope.investigation_id != node.envelope.investigation_id
                or envelope.operation_id != node.envelope.operation_id
            ):
                raise RecoveryDefinitionError("recovery envelope binding changed")
            capabilities = self.capabilities[node.node_id]
            if type(capabilities) is not tuple or any(
                type(item) is not ObservationCapability for item in capabilities
            ):
                raise RecoveryDefinitionError("recovery capability catalog is invalid")
            enabled = {
                (item.name, item.version)
                for item in envelope.context.enabled_capabilities
            }
            actual = {(item.name, item.version) for item in capabilities}
            if actual != enabled or any(not item.read_only for item in capabilities):
                raise RecoveryDefinitionError(
                    "recovery probes are not exactly allowlisted"
                )


type RecoveryDefinitionFactory = Callable[
    [RecoveryRunRequest],
    RecoveryRunDefinition | Awaitable[RecoveryRunDefinition],
]


def _node(chain: RecoveryChain, node_id: str) -> RecoveryActionNode:
    matches = tuple(node for node in chain.nodes if node.node_id == node_id)
    if len(matches) != 1:
        raise RecoveryDefinitionError("recovery node is not unique")
    return matches[0]


def _successor_envelope(
    definition: RecoveryRunDefinition,
    node: RecoveryActionNode,
) -> ExecutionEnvelope | None:
    successors = tuple(
        candidate
        for candidate in definition.chain.nodes
        if node.node_id in candidate.depends_on
    )
    if not successors:
        return None
    if len(successors) != 1:
        raise RecoveryDefinitionError("recovery chain is not a single declared path")
    return definition.envelopes[successors[0].node_id]


def _validate_hypothesis(
    hypothesis: GeminiHypothesis,
    *,
    chain: RecoveryChain,
    node: RecoveryActionNode,
    report: InvestigationReport,
) -> bool:
    return (
        type(hypothesis) is GeminiHypothesis
        and hypothesis.chain_id == chain.chain_id
        and hypothesis.node_id == node.node_id
        and hypothesis.semantic_action_sha256
        == node.semantic_action.semantic_action_sha256
        and hypothesis.report_sha256 == canonical_sha256(report)
        and set(hypothesis.cited_evidence_ids)
        <= {item.evidence_id for item in report.evidence}
    )


def _probe_disposition(
    hypothesis: GeminiHypothesis,
    *,
    envelope: ExecutionEnvelope,
    capabilities: tuple[ObservationCapability, ...],
    prior_probe_sha256s: frozenset[str],
) -> RecoveryHypothesisDisposition:
    if hypothesis.proposed_transition is not None:
        return RecoveryHypothesisDisposition.UNSUPPORTED_ACTION
    request = hypothesis.proposed_probe
    if request is None:
        return RecoveryHypothesisDisposition.NO_PROBE
    digest = probe_request_sha256(request)
    if digest in prior_probe_sha256s:
        return RecoveryHypothesisDisposition.DUPLICATE_PROBE
    matches = tuple(
        capability
        for capability in capabilities
        if (capability.name, capability.version)
        == (request.capability_name, request.capability_version)
    )
    expected_effects = {effect.effect_id for effect in envelope.expected_effects}
    if (
        len(matches) != 1
        or not matches[0].read_only
        or not set(request.relevant_effect_ids) <= expected_effects
        or not Draft202012Validator(matches[0].argument_schema).is_valid(
            request.arguments
        )
    ):
        return RecoveryHypothesisDisposition.UNSUPPORTED_PROBE
    return RecoveryHypothesisDisposition.SELECTED


def _planner_disposition(failure: PlannerFailureKind) -> RecoveryHypothesisDisposition:
    return {
        PlannerFailureKind.UNAVAILABLE: RecoveryHypothesisDisposition.MODEL_UNAVAILABLE,
        PlannerFailureKind.TIMEOUT: RecoveryHypothesisDisposition.MODEL_TIMEOUT,
        PlannerFailureKind.SCHEMA_INVALID: (
            RecoveryHypothesisDisposition.MALFORMED_MODEL_OUTPUT
        ),
    }[failure]


def _certificate_decision(
    definition: RecoveryRunDefinition,
    node: RecoveryActionNode,
    certificate: VerifiedCertificate,
    *,
    observation_round: int,
) -> RecoveryDecision:
    transition = certificate.transition
    if transition is not None:
        return (
            RecoveryDecision.CONTINUE
            if transition.action is PermitAction.CONTINUE
            else RecoveryDecision.RETRY
        )
    if certificate.classification is Classification.PENDING:
        return (
            RecoveryDecision.OBSERVE
            if observation_round < _MAX_OBSERVATION_ROUNDS
            else RecoveryDecision.ESCALATE
        )
    if (
        certificate.classification is Classification.COMMITTED
        and node.node_id == definition.chain.nodes[-1].node_id
    ):
        return RecoveryDecision.CONTINUE
    return RecoveryDecision.ESCALATE


class ProofToPermitWorkflow:
    """Run the declared chain while keeping model, proof, and mutation roles apart."""

    def __init__(
        self,
        *,
        store: RecoveryRunStore,
        definition_factory: RecoveryDefinitionFactory,
        evidence_source: RecoveryEvidenceSource,
        action_preparer: RecoveryActionPreparer,
        recovery_agent: RecoveryAgent,
        rollout_agent: RolloutAgent,
        permit_authority: PermitAuthority,
        clock: Callable[[], datetime] | None = None,
        claim_id_factory: Callable[[], str] | None = None,
    ) -> None:
        if not isinstance(store, RecoveryRunStore):
            raise TypeError("recovery workflow requires a recovery store")
        if not callable(definition_factory):
            raise TypeError("recovery workflow requires a definition factory")
        if not callable(getattr(action_preparer, "prepare", None)):
            raise TypeError("recovery workflow requires an action preparer")
        if type(recovery_agent) is not RecoveryAgent:
            raise TypeError("recovery workflow requires an exact RecoveryAgent")
        if type(rollout_agent) is not RolloutAgent:
            raise TypeError("recovery workflow requires an exact RolloutAgent")
        if type(permit_authority) is not PermitAuthority:
            raise TypeError("recovery workflow requires an exact PermitAuthority")
        self._store = store
        self._definition_factory = definition_factory
        self._evidence = evidence_source
        self._action_preparer = action_preparer
        self._recovery_agent = recovery_agent
        self._rollout_agent = rollout_agent
        self._permit_authority = permit_authority
        self._clock = clock or (lambda: datetime.now(UTC))
        self._claim_id_factory = claim_id_factory or (lambda: f"claim-{uuid4().hex}")

    def _now(self, snapshot: RecoveryRunSnapshot | None = None) -> datetime:
        value = self._clock()
        if value.tzinfo is None or value.utcoffset() is None:
            raise RecoveryWorkflowError("recovery clock is invalid")
        value = value.astimezone(UTC)
        return value if snapshot is None else max(value, snapshot.updated_at)

    async def definition(self, request: RecoveryRunRequest) -> RecoveryRunDefinition:
        value = self._definition_factory(request)
        if inspect.isawaitable(value):
            value = await value
        if type(value) is not RecoveryRunDefinition:
            raise RecoveryDefinitionError(
                "recovery definition factory returned invalid data"
            )
        return value

    async def aclose(self) -> None:
        await self._recovery_agent.aclose()

    async def _append(
        self,
        run_id: str,
        event_type: RecoveryRunEventType,
        payload: RecoveryRunEventPayload,
    ) -> RecoveryRunSnapshot:
        snapshot = await self._store.get(run_id)
        return await self._store.append(
            run_id,
            expected_revision=snapshot.revision,
            event_type=event_type,
            payload=payload,
            occurred_at=self._now(snapshot),
        )

    async def _node_state(
        self,
        run_id: str,
        node_id: str,
        state: RecoveryNodeState,
        *,
        attempt: int,
    ) -> RecoveryRunSnapshot:
        return await self._append(
            run_id,
            RecoveryRunEventType.NODE,
            RecoveryRunEventPayload(
                node=RecoveryNodeProgress(
                    node_id=node_id,
                    state=state,
                    attempt=attempt,
                )
            ),
        )

    async def _prepare_action(
        self,
        *,
        request: RecoveryRunRequest,
        definition: RecoveryRunDefinition,
        source_node: RecoveryActionNode,
        target_node: RecoveryActionNode,
        report: InvestigationReport | None,
        certificate: VerifiedCertificate | None,
    ) -> RecoveryPreparedAction:
        value = self._action_preparer.prepare(
            request,
            definition.chain,
            source_node,
            target_node,
            report,
            certificate,
        )
        if inspect.isawaitable(value):
            value = await value
        if type(value) is not RecoveryPreparedAction:
            raise RecoveryWorkflowError("action preparer returned invalid data")
        action = target_node.semantic_action
        common_valid = (
            value.run_id == request.run_id
            and value.chain_id == definition.chain.chain_id
            and value.source_node_id == source_node.node_id
            and value.target_node_id == target_node.node_id
            and value.semantic_action_sha256 == action.semantic_action_sha256
            and value.tool_name == action.tool_name
            and value.tool_version == action.tool_version
            and value.arguments == action.semantic_arguments
            and value.arguments_sha256
            == dispatch_arguments_sha256(action.semantic_arguments)
            and value.target == action.target
            and value.target_sha256 == canonical_sha256(action.target)
        )
        try:
            validate_recovery_dispatch(
                action,
                tool_name=value.tool_name,
                tool_version=value.tool_version,
                arguments=value.arguments,
                target=value.target,
                precondition=value.precondition,
            )
        except (TypeError, ValueError) as error:
            raise RecoveryWorkflowError(
                "prepared action is outside the sealed dispatch profile"
            ) from error
        if not common_valid:
            raise RecoveryWorkflowError("prepared action identity changed")

        if certificate is None:
            valid_authority = (
                report is None
                and value.authority_kind is RecoveryAuthorityKind.LAUNCH_PERMIT
                and value.permit_action is None
                and value.report_sha256 is None
                and value.certificate_id is None
                and value.certificate_sha256 is None
                and source_node.node_id == target_node.node_id
            )
        else:
            transition = certificate.transition
            valid_authority = (
                report is not None
                and transition is not None
                and canonical_sha256(report) == certificate.report_sha256
                and value.authority_kind is RecoveryAuthorityKind.ACTION_PERMIT
                and value.permit_action is transition.action
                and value.report_sha256 == certificate.report_sha256
                and value.certificate_id == certificate.certificate_id
                and value.certificate_sha256 == canonical_sha256(certificate)
                and value.semantic_action_sha256 == transition.semantic_action_sha256
                and value.tool_name == transition.tool_name
                and value.tool_version == transition.tool_version
                and value.arguments_sha256 == transition.arguments_sha256
                and value.target_sha256 == transition.target_sha256
                and value.precondition_sha256 == transition.precondition_sha256
                and value.precondition_sha256
                == dispatch_precondition_sha256(value.precondition)
            )
        if not valid_authority:
            raise RecoveryWorkflowError(
                "prepared action is not bound to certified authority"
            )
        return value

    async def _initial_dispatch(
        self,
        snapshot: RecoveryRunSnapshot,
        definition: RecoveryRunDefinition,
        node: RecoveryActionNode,
    ) -> None:
        run_id = snapshot.request.run_id
        launch = snapshot.launch_permit
        prepared: RecoveryPreparedAction | None = None
        if launch is None or launch.state is RecoveryLaunchPermitState.ISSUED:
            prepared = await self._prepare_action(
                request=snapshot.request,
                definition=definition,
                source_node=node,
                target_node=node,
                report=None,
                certificate=None,
            )
        if launch is None:
            if prepared is None:  # pragma: no cover - guarded above
                raise RecoveryWorkflowError("initial recovery action was not prepared")
            digest = hashlib.sha256(
                f"{run_id}\0{node.node_id}\0launch".encode()
            ).hexdigest()
            launch = RecoveryLaunchPermit(
                schema_version=RECOVERY_LAUNCH_PERMIT_VERSION,
                launch_permit_id=f"launch-permit-{digest[:32]}",
                run_id=run_id,
                node_id=node.node_id,
                semantic_action_sha256=node.semantic_action.semantic_action_sha256,
                action_request_sha256=prepared.action_request_sha256,
                issued_at=self._now(snapshot),
                state=RecoveryLaunchPermitState.ISSUED,
                revision=0,
            )
            snapshot = await self._append(
                run_id,
                RecoveryRunEventType.LAUNCH_PERMIT,
                RecoveryRunEventPayload(launch_permit=launch),
            )
            await self._node_state(
                run_id,
                node.node_id,
                RecoveryNodeState.DISPATCH_PENDING,
                attempt=1,
            )
        if launch.state is RecoveryLaunchPermitState.ISSUED:
            if (
                prepared is None
                or prepared.action_request_sha256 != launch.action_request_sha256
            ):
                raise RecoveryWorkflowError("prepared launch request changed")
            claim_id = self._claim_id_factory()
            scope = RecoveryActionScope(
                schema_version=RECOVERY_ACTION_SCOPE_VERSION,
                authority_kind=RecoveryAuthorityKind.LAUNCH_PERMIT,
                run_id=run_id,
                source_node_id=node.node_id,
                target_node_id=node.node_id,
                semantic_action_sha256=node.semantic_action.semantic_action_sha256,
                action_request_sha256=launch.action_request_sha256,
                authority_id=launch.launch_permit_id,
                authority_sha256=canonical_sha256(launch),
                claim_id=claim_id,
            )
            try:
                receipt = await self._rollout_agent.execute(prepared, scope)
            except asyncio.CancelledError:
                raise
            except Exception:
                # The authority store is the fault boundary. If it was claimed,
                # provider dispatch may have happened and the only safe action is
                # evidence reconciliation, never another dispatch.
                latest = (await self._store.get(run_id)).launch_permit
                if latest is None or latest.state is RecoveryLaunchPermitState.ISSUED:
                    raise
                receipt = None
            if receipt is None:
                await self._node_state(
                    run_id,
                    node.node_id,
                    RecoveryNodeState.DISPATCH_CLAIMED,
                    attempt=1,
                )
            else:
                completed = receipt.launch_permit
                if (
                    completed is None
                    or completed.launch_permit_id != launch.launch_permit_id
                    or completed.claim_id != claim_id
                    or completed.state is not RecoveryLaunchPermitState.COMPLETED
                    or completed.outcome is not receipt.outcome
                ):
                    raise RecoveryWorkflowError(
                        "initial dispatch authority was not completed"
                    )
        # ISSUED can be sent exactly once; CLAIMED or COMPLETED must only reconcile.
        await self._node_state(
            run_id,
            node.node_id,
            RecoveryNodeState.RECONCILING,
            attempt=1,
        )

    async def _record_evidence(
        self,
        run_id: str,
        state: RecoveryEvidenceState,
    ) -> None:
        await self._append(
            run_id,
            RecoveryRunEventType.EVIDENCE,
            RecoveryRunEventPayload(report=state.report),
        )

    async def _investigate(
        self,
        snapshot: RecoveryRunSnapshot,
        definition: RecoveryRunDefinition,
        node: RecoveryActionNode,
    ) -> tuple[RecoveryEvidenceState, RecoveryVerificationResult]:
        run_id = snapshot.request.run_id
        envelope = definition.envelopes[node.node_id]
        try:
            state = await self._evidence.current(run_id, node, envelope)
        except asyncio.CancelledError:
            raise
        except Exception as error:
            raise RecoveryEvidenceUnavailable from error
        await self._record_evidence(run_id, state)

        if snapshot.request.policy is RecoveryRunPolicy.FIXED:
            try:
                state = await self._evidence.fixed(run_id, node, envelope)
            except asyncio.CancelledError:
                raise
            except Exception as error:
                raise RecoveryEvidenceUnavailable from error
            await self._record_evidence(run_id, state)
            return state, self._verify(definition, node, state)
        if snapshot.request.policy is not RecoveryRunPolicy.ADAPTIVE:
            raise RecoveryDefinitionError("baseline policies are implemented by #171")

        prior: set[str] = set()
        artifact: RecoveryVerificationResult | None = None
        for _turn_index in range(_MAX_ADAPTIVE_TURNS):
            turn = await self._recovery_agent.hypothesize(
                chain=definition.chain,
                node=node,
                envelope=envelope,
                report=state.report,
                capabilities=definition.capabilities[node.node_id],
                prior_probe_sha256s=tuple(sorted(prior)),
            )
            if turn.failure is not None:
                await self._append(
                    run_id,
                    RecoveryRunEventType.HYPOTHESIS,
                    RecoveryRunEventPayload(
                        hypothesis_disposition=_planner_disposition(turn.failure),
                        note="Gemini was unavailable or invalid; fixed read policy selected.",
                    ),
                )
                state = await self._evidence.fixed(run_id, node, envelope)
                await self._record_evidence(run_id, state)
                return state, self._verify(definition, node, state)
            hypothesis = turn.hypothesis
            if hypothesis is None or not _validate_hypothesis(
                hypothesis,
                chain=definition.chain,
                node=node,
                report=state.report,
            ):
                disposition = RecoveryHypothesisDisposition.INVALID_BINDING
            else:
                disposition = _probe_disposition(
                    hypothesis,
                    envelope=envelope,
                    capabilities=definition.capabilities[node.node_id],
                    prior_probe_sha256s=frozenset(prior),
                )
            await self._append(
                run_id,
                RecoveryRunEventType.HYPOTHESIS,
                RecoveryRunEventPayload(
                    hypothesis=hypothesis,
                    hypothesis_disposition=disposition,
                    note="Gemini advice was recorded without proof or mutation authority.",
                ),
            )
            if disposition is RecoveryHypothesisDisposition.SELECTED:
                assert hypothesis is not None and hypothesis.proposed_probe is not None
                request = hypothesis.proposed_probe
                prior.add(probe_request_sha256(request))
                try:
                    state = await self._evidence.probe(
                        run_id,
                        node,
                        envelope,
                        request,
                    )
                except asyncio.CancelledError:
                    raise
                except Exception as error:
                    raise RecoveryEvidenceUnavailable from error
                await self._record_evidence(run_id, state)
                artifact = self._verify(definition, node, state)
                if isinstance(artifact, VerifiedCertificate):
                    return state, artifact
                continue
            if disposition in {
                RecoveryHypothesisDisposition.UNSUPPORTED_PROBE,
                RecoveryHypothesisDisposition.UNSUPPORTED_ACTION,
                RecoveryHypothesisDisposition.DUPLICATE_PROBE,
                RecoveryHypothesisDisposition.INVALID_BINDING,
            }:
                state = await self._evidence.fixed(run_id, node, envelope)
                await self._append(
                    run_id,
                    RecoveryRunEventType.HYPOTHESIS,
                    RecoveryRunEventPayload(
                        hypothesis_disposition=RecoveryHypothesisDisposition.FIXED_FALLBACK,
                        note="Deterministic fixed probe policy replaced rejected advice.",
                    ),
                )
                await self._record_evidence(run_id, state)
            artifact = self._verify(definition, node, state)
            return state, artifact
        if artifact is None:
            artifact = self._verify(definition, node, state)
        return state, artifact

    @staticmethod
    def _verify(
        definition: RecoveryRunDefinition,
        node: RecoveryActionNode,
        state: RecoveryEvidenceState,
    ) -> RecoveryVerificationResult:
        # Hypotheses are intentionally absent from this authority call.
        return verify_recovery(
            chain=definition.chain,
            node_id=node.node_id,
            envelope=state.envelope,
            report=state.report,
            evaluation=state.evaluation,
            verified_at=state.report.updated_at,
            successor_envelope=_successor_envelope(definition, node),
        )

    async def _record_decision(
        self,
        run_id: str,
        artifact: RecoveryVerificationResult,
        decision: RecoveryDecision,
    ) -> RecoveryRunSnapshot:
        if isinstance(artifact, VerifiedCertificate):
            payload = RecoveryRunEventPayload(
                decision=decision,
                certificate=artifact,
            )
        else:
            if decision is not RecoveryDecision.ESCALATE:
                raise RecoveryWorkflowError("ambiguity witness must escalate")
            payload = RecoveryRunEventPayload(
                decision=decision,
                witness=artifact,
            )
        return await self._append(run_id, RecoveryRunEventType.DECISION, payload)

    async def _mirror_action_permit(
        self,
        run_id: str,
        permit: ActionPermit,
    ) -> None:
        snapshot = await self._store.get(run_id)
        projected = tuple(
            item
            for item in snapshot.action_permits
            if item.permit_id == permit.permit_id
        )
        if len(projected) > 1:
            raise RecoveryWorkflowError("action permit projection is ambiguous")
        current_revision = -1 if not projected else projected[0].revision
        if projected and current_revision == permit.revision:
            if projected[0] != permit:
                raise RecoveryWorkflowError("action permit projection changed")
            return
        if current_revision > permit.revision:
            raise RecoveryWorkflowError("action permit projection moved backwards")

        states: list[ActionPermit] = []
        if current_revision < 0:
            states.append(
                ActionPermit.model_validate(
                    permit.model_copy(
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
                )
            )
            current_revision = 0
        if current_revision < 1 and permit.revision >= 1:
            if permit.state is ActionPermitState.EXPIRED:
                states.append(permit)
            else:
                states.append(
                    ActionPermit.model_validate(
                        permit.model_copy(
                            update={
                                "state": ActionPermitState.CLAIMED,
                                "revision": 1,
                                "completed_at": None,
                                "completion_outcome": None,
                            }
                        )
                    )
                )
            current_revision = 1
        if current_revision < 2 and permit.revision == 2:
            states.append(permit)
        for state in states:
            await self._append(
                run_id,
                RecoveryRunEventType.ACTION_PERMIT,
                RecoveryRunEventPayload(action_permit=state),
            )

    async def _permitted_dispatch(
        self,
        snapshot: RecoveryRunSnapshot,
        definition: RecoveryRunDefinition,
        certificate: VerifiedCertificate,
    ) -> None:
        transition = certificate.transition
        if transition is None:
            return
        target_node = _node(definition.chain, transition.target_node_id)
        expected = action_permit_from_certificate(certificate)
        if expected is None:
            raise RecoveryWorkflowError("verified transition did not issue a permit")
        try:
            permit = await self._permit_authority.get_permit(expected.permit_id)
        except PermitNotFound:
            issued = await self._permit_authority.issue_permit(certificate)
            if issued is None:
                raise RecoveryWorkflowError(
                    "verified transition did not issue a permit"
                ) from None
            permit = issued
        issued = permit.model_copy(
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
        if type(permit) is not type(expected) or issued != expected:
            raise RecoveryWorkflowError("durable action permit identity changed")
        run_id = snapshot.request.run_id
        await self._mirror_action_permit(run_id, permit)
        if permit.state in {ActionPermitState.CLAIMED, ActionPermitState.COMPLETED}:
            await self._node_state(
                run_id,
                transition.source_node_id,
                RecoveryNodeState.DISPATCH_CLAIMED,
                attempt=max(
                    1,
                    next(
                        item.attempt
                        for item in (await self._store.get(run_id)).nodes
                        if item.node_id == transition.source_node_id
                    ),
                ),
            )
            return
        if permit.state is not ActionPermitState.ISSUED:
            raise RecoveryWorkflowError(
                "expired action permit cannot authorize dispatch"
            )
        source_progress = next(
            item
            for item in (await self._store.get(run_id)).nodes
            if item.node_id == transition.source_node_id
        )
        reports = tuple(
            report
            for report in snapshot.reports
            if canonical_sha256(report) == certificate.report_sha256
        )
        if not reports:
            raise RecoveryWorkflowError(
                "certificate-bound recovery report is unavailable"
            )
        prepared = await self._prepare_action(
            request=snapshot.request,
            definition=definition,
            source_node=_node(definition.chain, transition.source_node_id),
            target_node=target_node,
            report=reports[-1],
            certificate=certificate,
        )
        await self._node_state(
            run_id,
            transition.source_node_id,
            RecoveryNodeState.PERMITTED,
            attempt=max(1, source_progress.attempt),
        )
        claim_id = self._claim_id_factory()
        scope = RecoveryActionScope(
            schema_version=RECOVERY_ACTION_SCOPE_VERSION,
            authority_kind=RecoveryAuthorityKind.ACTION_PERMIT,
            run_id=run_id,
            source_node_id=transition.source_node_id,
            target_node_id=transition.target_node_id,
            semantic_action_sha256=transition.semantic_action_sha256,
            action_request_sha256=prepared.action_request_sha256,
            authority_id=permit.permit_id,
            authority_sha256=canonical_sha256(permit),
            claim_id=claim_id,
            permit_action=permit.action,
            certificate_id=certificate.certificate_id,
            certificate_sha256=canonical_sha256(certificate),
        )
        try:
            receipt = await self._rollout_agent.execute(prepared, scope)
        except asyncio.CancelledError:
            raise
        except Exception:
            latest = await self._permit_authority.get_permit(permit.permit_id)
            if latest.state is ActionPermitState.ISSUED:
                raise
            await self._mirror_action_permit(run_id, latest)
            await self._node_state(
                run_id,
                transition.source_node_id,
                RecoveryNodeState.DISPATCH_CLAIMED,
                attempt=max(1, source_progress.attempt),
            )
            return
        completed = receipt.action_permit
        if (
            completed is None
            or completed.permit_id != permit.permit_id
            or completed.claim_id != claim_id
            or completed.state is not ActionPermitState.COMPLETED
            or completed.completion_outcome is None
            or completed.completion_outcome.value != receipt.outcome.value
        ):
            raise RecoveryWorkflowError(
                "permitted dispatch authority was not completed"
            )
        await self._mirror_action_permit(run_id, completed)

    async def run(self, run_id: str) -> RecoveryRunSnapshot:
        snapshot = await self._store.get(run_id)
        definition = await self.definition(snapshot.request)
        if definition.chain != snapshot.chain:
            raise RecoveryDefinitionError("durable recovery chain changed")
        if snapshot.lifecycle is RecoveryRunLifecycle.ACCEPTED:
            snapshot = await self._append(
                run_id,
                RecoveryRunEventType.LIFECYCLE,
                RecoveryRunEventPayload(lifecycle=RecoveryRunLifecycle.RUNNING),
            )
        if snapshot.lifecycle is not RecoveryRunLifecycle.RUNNING:
            return snapshot

        index = 0
        while index < len(definition.chain.nodes):
            node = definition.chain.nodes[index]
            snapshot = await self._store.get(run_id)
            progress = next(
                item for item in snapshot.nodes if item.node_id == node.node_id
            )
            if progress.state is RecoveryNodeState.COMPLETED:
                index += 1
                continue
            if progress.state is RecoveryNodeState.ESCALATED:
                return await self._append(
                    run_id,
                    RecoveryRunEventType.LIFECYCLE,
                    RecoveryRunEventPayload(lifecycle=RecoveryRunLifecycle.ESCALATED),
                )
            if index == 0 and progress.state in {
                RecoveryNodeState.WAITING,
                RecoveryNodeState.DISPATCH_PENDING,
                RecoveryNodeState.DISPATCH_CLAIMED,
            }:
                await self._initial_dispatch(snapshot, definition, node)
            elif progress.state is RecoveryNodeState.WAITING:
                # A successor cannot be reached without a completed permit dispatch.
                raise RecoveryWorkflowError("successor node has no dispatch authority")

            snapshot = await self._store.get(run_id)
            progress = next(
                item for item in snapshot.nodes if item.node_id == node.node_id
            )
            if progress.state is RecoveryNodeState.VERIFIED:
                certificates = tuple(
                    certificate
                    for certificate in snapshot.certificates
                    if certificate.node_id == node.node_id
                )
                if not certificates:
                    raise RecoveryWorkflowError(
                        "verified recovery node has no certificate"
                    )
                latest = certificates[-1]
                if latest.transition is None:
                    if snapshot.decision is RecoveryDecision.OBSERVE:
                        await self._node_state(
                            run_id,
                            node.node_id,
                            RecoveryNodeState.RECONCILING,
                            attempt=max(1, progress.attempt),
                        )
                        continue
                    if snapshot.decision is RecoveryDecision.ESCALATE:
                        await self._node_state(
                            run_id,
                            node.node_id,
                            RecoveryNodeState.ESCALATED,
                            attempt=max(1, progress.attempt),
                        )
                        return await self._append(
                            run_id,
                            RecoveryRunEventType.LIFECYCLE,
                            RecoveryRunEventPayload(
                                lifecycle=RecoveryRunLifecycle.ESCALATED
                            ),
                        )
                    if (
                        snapshot.decision is RecoveryDecision.CONTINUE
                        and node.node_id == definition.chain.nodes[-1].node_id
                    ):
                        await self._node_state(
                            run_id,
                            node.node_id,
                            RecoveryNodeState.COMPLETED,
                            attempt=max(1, progress.attempt),
                        )
                        index += 1
                        continue
                    raise RecoveryWorkflowError(
                        "non-authorizing certificate cannot advance recovery"
                    )
            if progress.state in {
                RecoveryNodeState.VERIFIED,
                RecoveryNodeState.PERMITTED,
                RecoveryNodeState.DISPATCH_CLAIMED,
            }:
                certificates = tuple(
                    certificate
                    for certificate in snapshot.certificates
                    if certificate.node_id == node.node_id
                )
                if not certificates or certificates[-1].transition is None:
                    raise RecoveryWorkflowError(
                        "certified recovery dispatch cannot be resumed"
                    )
                artifact = certificates[-1]
                transition = artifact.transition
                await self._permitted_dispatch(snapshot, definition, artifact)
                next_attempt = progress.attempt + int(
                    transition.target_node_id == node.node_id
                )
                await self._node_state(
                    run_id,
                    transition.target_node_id,
                    RecoveryNodeState.RECONCILING,
                    attempt=max(1, next_attempt),
                )
                if transition.target_node_id == node.node_id:
                    continue
                await self._node_state(
                    run_id,
                    node.node_id,
                    RecoveryNodeState.COMPLETED,
                    attempt=max(1, progress.attempt),
                )
                index += 1
                continue

            snapshot = await self._store.get(run_id)
            if snapshot.decision is RecoveryDecision.ESCALATE:
                artifacts = (*snapshot.certificates, *snapshot.witnesses)
                if artifacts and artifacts[-1].node_id == node.node_id:
                    await self._node_state(
                        run_id,
                        node.node_id,
                        RecoveryNodeState.ESCALATED,
                        attempt=max(1, progress.attempt),
                    )
                    return await self._append(
                        run_id,
                        RecoveryRunEventType.LIFECYCLE,
                        RecoveryRunEventPayload(
                            lifecycle=RecoveryRunLifecycle.ESCALATED
                        ),
                    )
            _state, artifact = await self._investigate(snapshot, definition, node)
            if isinstance(artifact, VerifiedCertificate):
                observation_round = 1 + sum(
                    certificate.node_id == node.node_id
                    and certificate.classification is Classification.PENDING
                    for certificate in snapshot.certificates
                )
                decision = _certificate_decision(
                    definition,
                    node,
                    artifact,
                    observation_round=observation_round,
                )
            else:
                decision = RecoveryDecision.ESCALATE
            snapshot = await self._record_decision(run_id, artifact, decision)
            if isinstance(artifact, AmbiguityWitness):
                await self._node_state(
                    run_id,
                    node.node_id,
                    RecoveryNodeState.ESCALATED,
                    attempt=max(1, progress.attempt),
                )
                return await self._append(
                    run_id,
                    RecoveryRunEventType.LIFECYCLE,
                    RecoveryRunEventPayload(lifecycle=RecoveryRunLifecycle.ESCALATED),
                )

            await self._node_state(
                run_id,
                node.node_id,
                RecoveryNodeState.VERIFIED,
                attempt=max(1, progress.attempt),
            )
            if decision is RecoveryDecision.ESCALATE:
                await self._node_state(
                    run_id,
                    node.node_id,
                    RecoveryNodeState.ESCALATED,
                    attempt=max(1, progress.attempt),
                )
                return await self._append(
                    run_id,
                    RecoveryRunEventType.LIFECYCLE,
                    RecoveryRunEventPayload(lifecycle=RecoveryRunLifecycle.ESCALATED),
                )
            if decision is RecoveryDecision.OBSERVE:
                await self._node_state(
                    run_id,
                    node.node_id,
                    RecoveryNodeState.RECONCILING,
                    attempt=max(1, progress.attempt),
                )
                continue
            if artifact.transition is not None:
                if (
                    artifact.transition.action is PermitAction.RETRY
                    and progress.attempt >= 2
                ):
                    raise RecoveryWorkflowError("bounded recovery retry was exhausted")
                await self._permitted_dispatch(snapshot, definition, artifact)
                target = artifact.transition.target_node_id
                if target != node.node_id:
                    await self._node_state(
                        run_id,
                        target,
                        RecoveryNodeState.RECONCILING,
                        attempt=1,
                    )
                    await self._node_state(
                        run_id,
                        node.node_id,
                        RecoveryNodeState.COMPLETED,
                        attempt=max(1, progress.attempt),
                    )
                    index += 1
                else:
                    await self._node_state(
                        run_id,
                        target,
                        RecoveryNodeState.RECONCILING,
                        attempt=max(1, progress.attempt) + 1,
                    )
                continue
            await self._node_state(
                run_id,
                node.node_id,
                RecoveryNodeState.COMPLETED,
                attempt=max(1, progress.attempt),
            )
            index += 1

        return await self._append(
            run_id,
            RecoveryRunEventType.LIFECYCLE,
            RecoveryRunEventPayload(lifecycle=RecoveryRunLifecycle.COMPLETED),
        )


@dataclass(frozen=True, slots=True)
class RecoveryRunLaunchResult:
    snapshot: RecoveryRunSnapshot
    created: bool


class RecoveryRunApplicationService:
    """Launch, resume, observe, and safely stop durable recovery workers."""

    def __init__(
        self,
        workflow: ProofToPermitWorkflow,
        store: RecoveryRunStore,
        *,
        poll_interval_seconds: float = 0.01,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        if type(workflow) is not ProofToPermitWorkflow or not isinstance(
            store, RecoveryRunStore
        ):
            raise TypeError("recovery service dependencies are invalid")
        self._workflow = workflow
        self._store = store
        self._poll = poll_interval_seconds
        self._clock = clock or (lambda: datetime.now(UTC))
        self._tasks: dict[str, asyncio.Task[None]] = {}
        self._lock = asyncio.Lock()
        self._closed = False

    def _now(self, snapshot: RecoveryRunSnapshot | None = None) -> datetime:
        value = self._clock()
        if value.tzinfo is None or value.utcoffset() is None:
            raise RecoveryWorkflowError("recovery service clock is invalid")
        value = value.astimezone(UTC)
        return value if snapshot is None else max(value, snapshot.updated_at)

    async def _worker(self, run_id: str) -> None:
        try:
            await self._workflow.run(run_id)
        except asyncio.CancelledError:
            raise
        except RecoveryRunConflict:
            # Another durable worker won the next transition. Its authority
            # record remains canonical; this worker must stop without turning
            # benign contention into a terminal failure.
            return
        except Exception:
            try:
                snapshot = await self._store.get(run_id)
                if snapshot.lifecycle is RecoveryRunLifecycle.RUNNING:
                    await self._store.append(
                        run_id,
                        expected_revision=snapshot.revision,
                        event_type=RecoveryRunEventType.LIFECYCLE,
                        payload=RecoveryRunEventPayload(
                            lifecycle=RecoveryRunLifecycle.FAILED,
                            failure_category=RecoveryRunFailureCategory.INTERNAL_FAILURE,
                        ),
                        occurred_at=self._now(snapshot),
                    )
            except Exception:
                pass

    async def _schedule(self, run_id: str) -> None:
        async with self._lock:
            task = self._tasks.get(run_id)
            if task is None or task.done():
                self._tasks[run_id] = asyncio.create_task(
                    self._worker(run_id),
                    name=f"recovery-run-{run_id}",
                )

    async def launch(self, request: RecoveryRunRequest) -> RecoveryRunLaunchResult:
        if self._closed:
            raise RecoveryRunConflict(request.run_id)
        definition = await self._workflow.definition(request)
        snapshot, created = await self._store.create(
            request,
            definition.chain,
            created_at=self._now(),
        )
        if snapshot.lifecycle in {
            RecoveryRunLifecycle.ACCEPTED,
            RecoveryRunLifecycle.RUNNING,
        }:
            await self._schedule(request.run_id)
        return RecoveryRunLaunchResult(snapshot=snapshot, created=created)

    async def get(self, run_id: str) -> RecoveryRunSnapshot:
        return await self._store.get(run_id)

    async def snapshot(
        self,
        run_id: str,
        *,
        after: int = 0,
    ) -> RecoveryRunEventSnapshot:
        return await self._store.events(run_id, after=after)

    async def wait_for_events(
        self,
        run_id: str,
        *,
        after: int = 0,
        cancellation_event: asyncio.Event | None = None,
    ) -> RecoveryRunEventSnapshot:
        while True:
            snapshot = await self.snapshot(run_id, after=after)
            if snapshot.events or snapshot.terminal:
                return snapshot
            if cancellation_event is not None and cancellation_event.is_set():
                return snapshot
            await asyncio.sleep(self._poll)

    async def cancel(self, run_id: str) -> RecoveryRunSnapshot:
        async with self._lock:
            task = self._tasks.get(run_id)
            if task is not None and not task.done():
                task.cancel()
        if task is not None:
            try:
                await task
            except asyncio.CancelledError:
                pass
        snapshot = await self._store.get(run_id)
        if snapshot.lifecycle in {
            RecoveryRunLifecycle.ACCEPTED,
            RecoveryRunLifecycle.RUNNING,
        }:
            if snapshot.lifecycle is RecoveryRunLifecycle.ACCEPTED:
                snapshot = await self._store.append(
                    run_id,
                    expected_revision=snapshot.revision,
                    event_type=RecoveryRunEventType.LIFECYCLE,
                    payload=RecoveryRunEventPayload(
                        lifecycle=RecoveryRunLifecycle.RUNNING
                    ),
                    occurred_at=self._now(snapshot),
                )
            snapshot = await self._store.append(
                run_id,
                expected_revision=snapshot.revision,
                event_type=RecoveryRunEventType.LIFECYCLE,
                payload=RecoveryRunEventPayload(
                    lifecycle=RecoveryRunLifecycle.CANCELLED,
                    failure_category=RecoveryRunFailureCategory.CANCELLED,
                ),
                occurred_at=self._now(snapshot),
            )
        return snapshot

    async def aclose(self) -> None:
        self._closed = True
        async with self._lock:
            tasks = tuple(task for task in self._tasks.values() if not task.done())
            for task in tasks:
                task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
        await self._recovery_agent_close()

    async def _recovery_agent_close(self) -> None:
        await self._workflow.aclose()


__all__ = [
    "ProofToPermitWorkflow",
    "RecoveryActionPreparer",
    "RecoveryDefinitionError",
    "RecoveryDefinitionFactory",
    "RecoveryEvidenceSource",
    "RecoveryEvidenceState",
    "RecoveryEvidenceUnavailable",
    "RecoveryRunApplicationService",
    "RecoveryRunDefinition",
    "RecoveryRunLaunchResult",
    "RecoveryWorkflowError",
]
