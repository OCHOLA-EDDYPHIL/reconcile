"""Focused RecoveryAgent and RolloutAgent boundaries for proof-to-permit."""

from __future__ import annotations

import asyncio
import hashlib
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Protocol

from pydantic import JsonValue

from reconcile.adaptive import AdvisoryPlanner, PlannerFailureKind
from reconcile.adk_planner import AdkGeminiPlanner, VertexAdcPlannerConfig
from reconcile.contracts import (
    ADAPTIVE_PLANNER_INPUT_VERSION,
    GEMINI_HYPOTHESIS_VERSION,
    ActionPermit,
    AdaptivePlannerInput,
    AdaptivePlannerPhase,
    Classification,
    EffectAssertionState,
    EvidenceDisposition,
    GeminiHypothesis,
    HypothesisMissingEvidence,
    HypothesizedEffect,
    InvestigationReport,
    ObservationCapability,
    PlannerAdmittedEvidence,
    PlannerCapability,
    PlannerMissingEvidence,
    PlannerRejectedEvidence,
    PlannerRemainingBudget,
    PlannerVersionMetadata,
    PlannerWeakEvidence,
    PossibleHistory,
    ProbeRequest,
    RecoveryActionNode,
    RecoveryActionScope,
    RecoveryChain,
    RecoveryDispatchOutcome,
    RecoveryLaunchPermit,
    RecoveryPreparedAction,
    canonical_json_bytes,
    canonical_sha256,
)
from reconcile.contracts.base import canonical_json_value_bytes

RECOVERY_AGENT_PROMPT_VERSION = "proof-to-permit-recovery-agent-v1"
RECOVERY_CAPABILITY_CATALOG_VERSION = "recovery-read-catalog-v1"


@dataclass(frozen=True, slots=True)
class RecoveryAgentTurn:
    hypothesis: GeminiHypothesis | None
    failure: PlannerFailureKind | None
    input_sha256: str
    output_sha256: str | None

    def __post_init__(self) -> None:
        if (self.hypothesis is None) == (self.failure is None):
            raise ValueError("a recovery turn requires one hypothesis or failure")
        if self.hypothesis is not None:
            if type(self.hypothesis) is not GeminiHypothesis:
                raise TypeError(
                    "successful recovery output requires an exact hypothesis"
                )
            if self.output_sha256 != canonical_sha256(self.hypothesis):
                raise ValueError(
                    "successful recovery output must identify its hypothesis"
                )


class RecoveryHypothesisAgent(Protocol):
    """Narrow advisory boundary consumed by the deterministic workflow."""

    async def hypothesize(
        self,
        *,
        chain: RecoveryChain,
        node: RecoveryActionNode,
        envelope: object,
        report: InvestigationReport,
        capabilities: tuple[ObservationCapability, ...],
        prior_probe_sha256s: tuple[str, ...] = (),
    ) -> RecoveryAgentTurn: ...

    async def aclose(self) -> None: ...


def _evidence_views(
    report: InvestigationReport,
) -> tuple[
    tuple[PlannerAdmittedEvidence, ...],
    tuple[PlannerWeakEvidence, ...],
    tuple[PlannerRejectedEvidence, ...],
]:
    evidence = {item.evidence_id: item for item in report.evidence}
    all_effect_ids = tuple(
        finding.effect_id for finding in report.proof.effect_findings
    )
    admitted: list[PlannerAdmittedEvidence] = []
    weak: list[PlannerWeakEvidence] = []
    rejected: list[PlannerRejectedEvidence] = []
    for decision in report.evidence_decisions:
        item = evidence.get(decision.evidence_id)
        if decision.disposition is EvidenceDisposition.ADMITTED:
            if item is None:
                raise ValueError("admitted recovery evidence is unavailable")
            admitted.append(
                PlannerAdmittedEvidence(
                    evidence_id=item.evidence_id,
                    capability_name=item.capability_name,
                    capability_version=item.capability_version,
                    reason=decision.reason,
                    effect_assertions=item.effect_assertions,
                    operation_status=item.operation_status,
                )
            )
        elif decision.disposition is EvidenceDisposition.WEAK:
            weak.append(
                PlannerWeakEvidence(
                    evidence_id=decision.evidence_id,
                    capability_name=(None if item is None else item.capability_name),
                    capability_version=(
                        None if item is None else item.capability_version
                    ),
                    reason=decision.reason,
                    relevant_effect_ids=(
                        all_effect_ids
                        if item is None
                        else tuple(
                            assertion.effect_id for assertion in item.effect_assertions
                        )
                    ),
                )
            )
        else:
            rejected.append(
                PlannerRejectedEvidence(
                    evidence_id=decision.evidence_id,
                    capability_name=(None if item is None else item.capability_name),
                    capability_version=(
                        None if item is None else item.capability_version
                    ),
                    reason=decision.reason,
                    relevant_effect_ids=(
                        all_effect_ids
                        if item is None
                        else tuple(
                            assertion.effect_id for assertion in item.effect_assertions
                        )
                    ),
                )
            )
    return tuple(admitted), tuple(weak), tuple(rejected)


def _planner_input(
    *,
    envelope: object,
    report: InvestigationReport,
    capabilities: tuple[ObservationCapability, ...],
    prior_probe_sha256s: tuple[str, ...],
    planner: AdvisoryPlanner,
    now: datetime,
) -> AdaptivePlannerInput:
    from reconcile.contracts import ExecutionEnvelope

    if type(envelope) is not ExecutionEnvelope:
        raise TypeError("recovery agent envelope must be exact")
    admitted, weak, rejected = _evidence_views(report)
    metadata = planner.metadata
    remaining = recovery_remaining_budget(envelope, report, now=now)
    return AdaptivePlannerInput(
        schema_version=ADAPTIVE_PLANNER_INPUT_VERSION,
        phase=AdaptivePlannerPhase.ACQUIRE_EVIDENCE,
        envelope=envelope,
        capabilities=tuple(
            PlannerCapability(
                name=capability.name,
                version=capability.version,
                description=f"Read-only recovery probe {capability.name}.",
                read_only=capability.read_only,
                argument_schema=capability.argument_schema,
                cost_units=capability.cost_units,
                remaining_invocations=remaining.probes,
            )
            for capability in capabilities
        ),
        admitted_evidence=admitted,
        weak_evidence=weak,
        rejected_evidence=rejected,
        missing_evidence=tuple(
            PlannerMissingEvidence(effect_id=effect_id, reason=missing.reason)
            for missing in report.missing_evidence
            for effect_id in missing.effect_ids
        ),
        prior_executable_request_hashes=prior_probe_sha256s,
        remaining_budget=remaining,
        versions=PlannerVersionMetadata(
            provider_name=metadata.provider_name,
            model_name=metadata.configured_model,
            adk_version=metadata.adk_version,
            genai_version=metadata.genai_version,
            prompt_version=metadata.prompt_version,
            capability_catalog_version=RECOVERY_CAPABILITY_CATALOG_VERSION,
            authority_policy_version=envelope.context.policies.authority,
            classification_policy_version=envelope.context.policies.classification,
            action_policy_version=envelope.context.policies.action,
            input_schema_version=metadata.input_schema_version,
            output_schema_version=metadata.output_schema_version,
        ),
    )


def recovery_remaining_budget(
    envelope: object,
    report: InvestigationReport,
    *,
    now: datetime,
) -> PlannerRemainingBudget:
    """Derive fail-closed remaining probe authority from durable audit totals."""

    from reconcile.contracts import ExecutionEnvelope

    if (
        type(envelope) is not ExecutionEnvelope
        or type(report) is not InvestigationReport
    ):
        raise TypeError("exact recovery budget inputs are required")
    if now.tzinfo is None or now.utcoffset() is None:
        raise ValueError("recovery budget clock must be timezone-aware")
    now = now.astimezone(UTC)
    maximum = envelope.context.evidence_budget
    audits = report.probe_audit
    probes_used = max(
        len(audits),
        max((item.probe_count_used for item in audits), default=0),
    )
    reported_elapsed_ms = max(
        (item.session_elapsed_ms for item in audits),
        default=0,
    )
    wall_elapsed_ms = max(
        0,
        int((now - report.created_at).total_seconds() * 1_000),
    )
    result_bytes_used = max(
        (item.result_bytes_acquired for item in audits),
        default=0,
    )
    cost_units_used = max(
        (item.cost_units_used for item in audits),
        default=0,
    )
    remaining_elapsed_ms = max(
        0,
        maximum.max_elapsed_ms - max(reported_elapsed_ms, wall_elapsed_ms),
    )
    return PlannerRemainingBudget(
        probes=max(0, maximum.max_probes - probes_used),
        elapsed_ms=remaining_elapsed_ms,
        result_bytes=max(
            0,
            maximum.max_total_result_bytes - result_bytes_used,
        ),
        cost_units=max(0, maximum.max_cost_units - cost_units_used),
        deadline_at=max(
            envelope.invoked_at,
            report.created_at + timedelta(milliseconds=maximum.max_elapsed_ms),
        ),
    )


def _alternative_histories(report: InvestigationReport) -> tuple[PossibleHistory, ...]:
    citations = tuple(
        sorted(
            decision.evidence_id
            for decision in report.evidence_decisions
            if decision.disposition is EvidenceDisposition.ADMITTED
        )
    )
    unresolved = any(
        finding.state is EffectAssertionState.UNVERIFIED
        for finding in report.proof.effect_findings
    )
    if not unresolved:
        return ()
    histories = []
    for history_id, unresolved_state, summary in (
        (
            "model-history-effects-occurred",
            EffectAssertionState.ESTABLISHED,
            "The unresolved effects may already have occurred.",
        ),
        (
            "model-history-effects-not-occurred",
            EffectAssertionState.NOT_ESTABLISHED,
            "The unresolved effects may not have occurred.",
        ),
    ):
        effect_states = tuple(
            HypothesizedEffect(
                effect_id=finding.effect_id,
                state=(
                    finding.state
                    if finding.state is not EffectAssertionState.UNVERIFIED
                    else unresolved_state
                ),
                cited_evidence_ids=(
                    finding.evidence_ids
                    if finding.state is not EffectAssertionState.UNVERIFIED
                    else ()
                ),
            )
            for finding in report.proof.effect_findings
        )
        states = {effect.state for effect in effect_states}
        classification = (
            Classification.COMMITTED
            if states == {EffectAssertionState.ESTABLISHED}
            else (
                Classification.NOT_COMMITTED
                if states == {EffectAssertionState.NOT_ESTABLISHED}
                else Classification.PARTIAL
            )
        )
        histories.append(
            PossibleHistory(
                history_id=history_id,
                classification=classification,
                effect_states=effect_states,
                compatible_evidence_ids=citations,
                summary=summary,
            )
        )
    return tuple(histories)


class RecoveryAgent:
    """Bind one Gemini advisory turn to trusted run and report identities."""

    def __init__(
        self,
        planner: AdvisoryPlanner,
        *,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        if not callable(getattr(planner, "plan", None)) or not hasattr(
            planner, "metadata"
        ):
            raise TypeError("RecoveryAgent requires an advisory planner")
        self._planner = planner
        self._clock = clock or (lambda: datetime.now(UTC))

    @classmethod
    def from_vertex_adc(
        cls,
        config: VertexAdcPlannerConfig,
    ) -> RecoveryAgent:
        """Build the hosted RecoveryAgent on the configured Vertex Gemini model."""

        return cls(AdkGeminiPlanner.from_vertex_adc(config))

    async def hypothesize(
        self,
        *,
        chain: RecoveryChain,
        node: RecoveryActionNode,
        envelope: object,
        report: InvestigationReport,
        capabilities: tuple[ObservationCapability, ...],
        prior_probe_sha256s: tuple[str, ...] = (),
    ) -> RecoveryAgentTurn:
        now = self._clock()
        if now.tzinfo is None or now.utcoffset() is None:
            raise ValueError("RecoveryAgent clock must be timezone-aware")
        now = now.astimezone(UTC)
        planner_input = _planner_input(
            envelope=envelope,
            report=report,
            capabilities=capabilities,
            prior_probe_sha256s=prior_probe_sha256s,
            planner=self._planner,
            now=now,
        )
        input_sha256 = canonical_sha256(planner_input)
        try:
            turn = await self._planner.plan(planner_input)
        except asyncio.CancelledError:
            raise
        except Exception:
            return RecoveryAgentTurn(
                hypothesis=None,
                failure=PlannerFailureKind.UNAVAILABLE,
                input_sha256=input_sha256,
                output_sha256=None,
            )
        if turn.failure is not None or turn.output is None:
            return RecoveryAgentTurn(
                hypothesis=None,
                failure=turn.failure or PlannerFailureKind.SCHEMA_INVALID,
                input_sha256=input_sha256,
                output_sha256=turn.output_sha256,
            )
        output = turn.output
        if len(output.probe_proposals) > 1:
            return RecoveryAgentTurn(
                hypothesis=None,
                failure=PlannerFailureKind.SCHEMA_INVALID,
                input_sha256=input_sha256,
                output_sha256=turn.output_sha256,
            )
        citations = tuple(
            dict.fromkeys(
                (
                    *output.explanation.citations.admitted_evidence_ids,
                    *output.explanation.citations.weak_evidence_ids,
                    *output.explanation.citations.rejected_evidence_ids,
                )
            )
        )
        known_evidence = {item.evidence_id for item in report.evidence}
        if not set(citations) <= known_evidence:
            return RecoveryAgentTurn(
                hypothesis=None,
                failure=PlannerFailureKind.SCHEMA_INVALID,
                input_sha256=input_sha256,
                output_sha256=turn.output_sha256,
            )
        classification = (
            report.classification
            if output.stop_advice.recommend_stop and report.classification is not None
            else Classification.UNKNOWN
        )
        effect_citations = {
            finding.effect_id: tuple(
                evidence_id
                for evidence_id in finding.evidence_ids
                if evidence_id in citations
            )
            for finding in report.proof.effect_findings
        }
        missing = tuple(
            HypothesisMissingEvidence(
                effect_ids=note.effect_ids,
                reason=note.note,
            )
            for note in output.missing_evidence_notes
        ) or tuple(
            HypothesisMissingEvidence(
                effect_ids=item.effect_ids,
                reason=item.reason,
            )
            for item in report.missing_evidence
        )
        if not citations and not missing:
            missing = (
                HypothesisMissingEvidence(
                    effect_ids=tuple(
                        finding.effect_id for finding in report.proof.effect_findings
                    ),
                    reason="The model cited no retained evidence.",
                ),
            )
        identity_material: Mapping[str, JsonValue] = {
            "chain_sha256": canonical_sha256(chain),
            "input_sha256": input_sha256,
            "node_sha256": canonical_sha256(node),
            "output_sha256": turn.output_sha256,
        }
        hypothesis_id = (
            "hypothesis-"
            + hashlib.sha256(
                canonical_json_value_bytes(dict(identity_material))
            ).hexdigest()[:32]
        )
        try:
            hypothesis = GeminiHypothesis(
                schema_version=GEMINI_HYPOTHESIS_VERSION,
                hypothesis_id=hypothesis_id,
                chain_id=chain.chain_id,
                node_id=node.node_id,
                semantic_action_sha256=node.semantic_action.semantic_action_sha256,
                report_sha256=canonical_sha256(report),
                proposed_classification=classification,
                effect_hypotheses=tuple(
                    HypothesizedEffect(
                        effect_id=finding.effect_id,
                        state=finding.state,
                        cited_evidence_ids=effect_citations[finding.effect_id],
                    )
                    for finding in report.proof.effect_findings
                ),
                cited_evidence_ids=citations,
                confidence_basis_points=(
                    9_000 if output.stop_advice.recommend_stop else 5_000
                ),
                alternative_histories=_alternative_histories(report),
                missing_evidence=missing,
                proposed_probe=(
                    output.probe_proposals[0] if output.probe_proposals else None
                ),
                proposed_transition=None,
                explanation=output.explanation.summary,
                created_at=now,
            )
        except Exception:
            return RecoveryAgentTurn(
                hypothesis=None,
                failure=PlannerFailureKind.SCHEMA_INVALID,
                input_sha256=input_sha256,
                output_sha256=turn.output_sha256,
            )
        return RecoveryAgentTurn(
            hypothesis=hypothesis,
            failure=None,
            input_sha256=input_sha256,
            output_sha256=canonical_sha256(hypothesis),
        )

    async def aclose(self) -> None:
        closer = getattr(self._planner, "aclose", None)
        if callable(closer):
            result = closer()
            if hasattr(result, "__await__"):
                await result


@dataclass(frozen=True, slots=True)
class RecoveryDispatchReceipt:
    outcome: RecoveryDispatchOutcome
    launch_permit: RecoveryLaunchPermit | None = None
    action_permit: ActionPermit | None = None

    def __post_init__(self) -> None:
        if (self.launch_permit is None) == (self.action_permit is None):
            raise ValueError("a dispatch receipt requires one authority record")


class RecoveryDispatchGateway(Protocol):
    async def dispatch(
        self,
        prepared: RecoveryPreparedAction,
        scope: RecoveryActionScope,
    ) -> RecoveryDispatchReceipt: ...


class RolloutAgent:
    """Execute only controller-built recovery scopes through a guarded gateway."""

    def __init__(self, gateway: RecoveryDispatchGateway) -> None:
        if not callable(getattr(gateway, "dispatch", None)):
            raise TypeError("RolloutAgent requires a dispatch gateway")
        self._gateway = gateway

    async def execute(
        self,
        prepared: RecoveryPreparedAction,
        scope: RecoveryActionScope,
    ) -> RecoveryDispatchReceipt:
        if (
            type(prepared) is not RecoveryPreparedAction
            or type(scope) is not RecoveryActionScope
        ):
            raise TypeError("RolloutAgent requires exact prepared action and scope")
        if (
            prepared.authority_kind is not scope.authority_kind
            or prepared.run_id != scope.run_id
            or prepared.source_node_id != scope.source_node_id
            or prepared.target_node_id != scope.target_node_id
            or prepared.semantic_action_sha256 != scope.semantic_action_sha256
            or prepared.action_request_sha256 != scope.action_request_sha256
            or prepared.permit_action is not scope.permit_action
            or prepared.certificate_id != scope.certificate_id
            or prepared.certificate_sha256 != scope.certificate_sha256
        ):
            raise RuntimeError("prepared recovery action does not match its scope")
        outcome = await self._gateway.dispatch(prepared, scope)
        if type(outcome) is not RecoveryDispatchReceipt:
            raise RuntimeError("recovery gateway returned an invalid outcome")
        return outcome


def probe_request_sha256(request: ProbeRequest) -> str:
    if type(request) is not ProbeRequest:
        raise TypeError("an exact probe request is required")
    return hashlib.sha256(canonical_json_bytes(request)).hexdigest()


__all__ = [
    "RECOVERY_AGENT_PROMPT_VERSION",
    "RECOVERY_CAPABILITY_CATALOG_VERSION",
    "RecoveryAgent",
    "RecoveryAgentTurn",
    "RecoveryDispatchGateway",
    "RecoveryDispatchReceipt",
    "RecoveryHypothesisAgent",
    "RolloutAgent",
    "probe_request_sha256",
    "recovery_remaining_budget",
]
