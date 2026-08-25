"""Gemini advisory output remains bounded to hypotheses and read probes."""

from __future__ import annotations

import asyncio
from datetime import timedelta

import pytest

from reconcile.adaptive import (
    AdvisoryPlannerMetadata,
    AdvisoryPlannerTurn,
    AdvisoryPlannerUsage,
    PlannerFailureKind,
)
from reconcile.contracts import (
    ADAPTIVE_PLANNER_INPUT_VERSION,
    ADAPTIVE_PLANNER_OUTPUT_VERSION,
    EVIDENCE_DECISION_VERSION,
    AdaptivePlannerOutput,
    Classification,
    EffectAssertionState,
    EvidenceDecision,
    EvidenceDisposition,
    EvidenceReason,
    InvestigationReport,
    PlannerAcquisitionAdvice,
    PlannerCitationRefs,
    PlannerExplanation,
    PlannerStopAdvice,
    ProbeOutcome,
    canonical_sha256,
)
from reconcile.recovery_agents import (
    RecoveryAgent,
    RecoveryAgentTurn,
    _alternative_histories,
    recovery_hypothesis_id,
    recovery_hypothesis_id_from_hashes,
    recovery_remaining_budget,
)
from tests.contract._factories import (
    make_capability,
    make_envelope,
    make_probe,
    make_recovery_examples,
    make_report,
)

pytestmark = pytest.mark.unit


def test_recovery_hypothesis_identity_binds_all_provider_inputs() -> None:
    chain = make_recovery_examples()[0]
    node = chain.nodes[0]
    expected = recovery_hypothesis_id(
        chain=chain,
        node=node,
        input_sha256="1" * 64,
        output_sha256="2" * 64,
    )
    assert expected == recovery_hypothesis_id_from_hashes(
        chain_sha256=canonical_sha256(chain),
        node_sha256=canonical_sha256(node),
        input_sha256="1" * 64,
        output_sha256="2" * 64,
    )

    assert expected == recovery_hypothesis_id(
        chain=chain,
        node=node,
        input_sha256="1" * 64,
        output_sha256="2" * 64,
    )
    assert expected != recovery_hypothesis_id(
        chain=chain,
        node=node,
        input_sha256="3" * 64,
        output_sha256="2" * 64,
    )
    assert expected != recovery_hypothesis_id(
        chain=chain,
        node=node,
        input_sha256="1" * 64,
        output_sha256="4" * 64,
    )


def _output(
    *,
    probe_count: int = 1,
    citations: PlannerCitationRefs | None = None,
) -> AdaptivePlannerOutput:
    citation_refs = citations or PlannerCitationRefs(
        admitted_evidence_ids=("evidence-7",),
        weak_evidence_ids=(),
        rejected_evidence_ids=(),
        missing_effect_ids=(),
    )
    return AdaptivePlannerOutput(
        schema_version=ADAPTIVE_PLANNER_OUTPUT_VERSION,
        probe_proposals=tuple(make_probe() for _ in range(probe_count)),
        acquisition_advice=PlannerAcquisitionAdvice(
            summary="Read the exact target state once."
        ),
        stop_advice=PlannerStopAdvice(
            recommend_stop=False,
            reason="One effect still needs direct evidence.",
        ),
        missing_evidence_notes=(),
        explanation=PlannerExplanation(
            summary="The admitted observation supports the current hypothesis.",
            admitted_evidence=(
                "The exact target read is authoritative."
                if citation_refs.admitted_evidence_ids
                else None
            ),
            weak_evidence=(
                "The retained observation is supplementary."
                if citation_refs.weak_evidence_ids
                else None
            ),
            rejected_evidence=(
                "The unavailable observation cannot prove the effect."
                if citation_refs.rejected_evidence_ids
                else None
            ),
            missing_evidence=(
                "The effect still requires authoritative proof."
                if citation_refs.missing_effect_ids
                else None
            ),
            citations=citation_refs,
        ),
    )


class _Planner:
    def __init__(
        self,
        *,
        output: AdaptivePlannerOutput | None = None,
        failure: PlannerFailureKind | None = None,
    ) -> None:
        self.output = output
        self.failure = failure
        self.inputs = []
        self.metadata = AdvisoryPlannerMetadata(
            provider_name="google",
            configured_model="gemini-3.5-flash",
            reported_model="gemini-3.5-flash",
            adk_version="2.6.3",
            genai_version="2.18.0",
            prompt_version="adaptive-planner-v3",
            prompt_sha256="a" * 64,
            input_schema_version=ADAPTIVE_PLANNER_INPUT_VERSION,
            output_schema_version=ADAPTIVE_PLANNER_OUTPUT_VERSION,
        )

    async def plan(self, planner_input):
        self.inputs.append(planner_input)
        output_sha256 = None if self.output is None else canonical_sha256(self.output)
        return AdvisoryPlannerTurn(
            output=self.output,
            failure=self.failure,
            metadata=self.metadata,
            input_sha256=canonical_sha256(planner_input),
            output_sha256=output_sha256,
            usage=(
                None
                if self.output is None
                else AdvisoryPlannerUsage(
                    prompt_tokens=10,
                    output_tokens=5,
                    total_tokens=15,
                )
            ),
        )


def test_recovery_agent_builds_evidence_cited_non_authoritative_hypothesis() -> None:
    planner = _Planner(output=_output())
    report = make_report(Classification.COMMITTED)
    agent = RecoveryAgent(
        planner,
        clock=lambda: report.updated_at,
    )
    chain = make_recovery_examples()[0]

    async def exercise():
        return await agent.hypothesize(
            chain=chain,
            node=chain.nodes[0],
            envelope=make_envelope(),
            report=report,
            capabilities=(make_capability(),),
        )

    turn = asyncio.run(exercise())

    assert turn.failure is None
    assert turn.hypothesis is not None
    assert turn.hypothesis.cited_evidence_ids == ("evidence-7",)
    assert turn.hypothesis.confidence_basis_points == 5_000
    assert turn.hypothesis.proposed_probe == make_probe()
    assert turn.hypothesis.proposed_transition is None
    assert turn.hypothesis.proposed_classification is Classification.UNKNOWN


def _report_with_rejected_probe() -> InvestigationReport:
    report = make_report(Classification.UNKNOWN)
    rejected_evidence_id = "evidence-revision-unavailable"
    rejected = EvidenceDecision(
        schema_version=EVIDENCE_DECISION_VERSION,
        evidence_id=rejected_evidence_id,
        disposition=EvidenceDisposition.REJECTED,
        reason=EvidenceReason.PROBE_TIMEOUT,
    )
    rejected_audit = report.probe_audit[0].model_copy(
        update={
            "probe_sequence": 2,
            "outcome": ProbeOutcome.REJECTED,
            "stop_reason": "probe_timeout",
            "started_at": report.probe_audit[0].completed_at,
            "completed_at": report.probe_audit[0].completed_at,
            "result_bytes_acquired": 0,
            "result_sha256": None,
            "result_byte_count": None,
            "evidence_ids": (rejected_evidence_id,),
        }
    )
    return InvestigationReport.model_validate(
        report.model_copy(
            update={
                "probe_audit": (*report.probe_audit, rejected_audit),
                "evidence_decisions": (*report.evidence_decisions, rejected),
            }
        )
    )


def test_recovery_agent_keeps_rejected_probe_citations_out_of_hypothesis() -> None:
    report = _report_with_rejected_probe()
    planner = _Planner(
        output=_output(
            citations=PlannerCitationRefs(
                admitted_evidence_ids=(),
                weak_evidence_ids=("evidence-7",),
                rejected_evidence_ids=("evidence-revision-unavailable",),
                missing_effect_ids=("business-record", "audit-record"),
            )
        )
    )
    chain = make_recovery_examples()[0]

    turn = asyncio.run(
        RecoveryAgent(planner, clock=lambda: report.updated_at).hypothesize(
            chain=chain,
            node=chain.nodes[0],
            envelope=make_envelope(),
            report=report,
            capabilities=(make_capability(),),
        )
    )

    assert turn.failure is None
    assert turn.hypothesis is not None
    assert turn.hypothesis.cited_evidence_ids == ("evidence-7",)
    assert "evidence-revision-unavailable" not in {
        evidence_id
        for effect in turn.hypothesis.effect_hypotheses
        for evidence_id in effect.cited_evidence_ids
    }
    assert set(turn.hypothesis.cited_evidence_ids) <= {
        item.evidence_id for item in report.evidence
    }


@pytest.mark.parametrize(
    "citations",
    (
        PlannerCitationRefs(
            admitted_evidence_ids=("evidence-7",),
            weak_evidence_ids=(),
            rejected_evidence_ids=(),
            missing_effect_ids=(),
        ),
        PlannerCitationRefs(
            admitted_evidence_ids=(),
            weak_evidence_ids=(),
            rejected_evidence_ids=("evidence-not-supplied",),
            missing_effect_ids=(),
        ),
        PlannerCitationRefs(
            admitted_evidence_ids=(),
            weak_evidence_ids=(),
            rejected_evidence_ids=(),
            missing_effect_ids=("effect-not-supplied",),
        ),
    ),
)
def test_recovery_agent_rejects_citations_outside_the_supplied_category(
    citations: PlannerCitationRefs,
) -> None:
    report = _report_with_rejected_probe()
    planner = _Planner(output=_output(citations=citations))
    chain = make_recovery_examples()[0]

    turn = asyncio.run(
        RecoveryAgent(planner, clock=lambda: report.updated_at).hypothesize(
            chain=chain,
            node=chain.nodes[0],
            envelope=make_envelope(),
            report=report,
            capabilities=(make_capability(),),
        )
    )

    assert turn.hypothesis is None
    assert turn.failure is PlannerFailureKind.SCHEMA_INVALID


def test_recovery_agent_considers_only_first_of_multiple_advisory_probes() -> None:
    planner = _Planner(output=_output(probe_count=2))
    report = make_report(Classification.COMMITTED)
    agent = RecoveryAgent(planner, clock=lambda: report.updated_at)
    chain = make_recovery_examples()[0]

    async def exercise():
        return await agent.hypothesize(
            chain=chain,
            node=chain.nodes[0],
            envelope=make_envelope(),
            report=report,
            capabilities=(make_capability(),),
        )

    turn = asyncio.run(exercise())

    assert turn.failure is None
    assert turn.hypothesis is not None
    assert turn.hypothesis.proposed_probe == make_probe()
    assert turn.output_sha256 == canonical_sha256(turn.hypothesis)
    assert planner.inputs[0].envelope == make_envelope()
    assert planner.inputs[0].remaining_budget.probes == 2
    assert planner.inputs[0].remaining_budget.elapsed_ms == 0
    assert planner.inputs[0].remaining_budget.result_bytes == 65_024
    assert planner.inputs[0].remaining_budget.cost_units == 2
    assert planner.inputs[0].remaining_budget.deadline_at == report.updated_at
    assert planner.inputs[0].capabilities[0].remaining_invocations == 2


def test_successful_recovery_turn_rejects_a_stale_hypothesis_digest() -> None:
    planner = _Planner(output=_output())
    report = make_report(Classification.COMMITTED)
    chain = make_recovery_examples()[0]
    turn = asyncio.run(
        RecoveryAgent(planner, clock=lambda: report.updated_at).hypothesize(
            chain=chain,
            node=chain.nodes[0],
            envelope=make_envelope(),
            report=report,
            capabilities=(make_capability(),),
        )
    )
    assert turn.hypothesis is not None

    with pytest.raises(ValueError, match="identify its hypothesis"):
        RecoveryAgentTurn(
            hypothesis=turn.hypothesis,
            failure=None,
            input_sha256=turn.input_sha256,
            output_sha256="0" * 64,
        )


def test_recovery_agent_has_no_post_planner_hypothesis_mutation_hook() -> None:
    with pytest.raises(TypeError, match="unexpected keyword"):
        RecoveryAgent(
            _Planner(output=_output()),
            **{"hypothesis_transformer": lambda hypothesis, _report: hypothesis},
        )


def test_recovery_agent_uses_one_stable_cumulative_budget_deadline() -> None:
    envelope = make_envelope()
    report = make_report(Classification.COMMITTED)
    at_deadline = recovery_remaining_budget(
        envelope,
        report,
        now=report.updated_at,
    )
    long_after_deadline = recovery_remaining_budget(
        envelope,
        report,
        now=report.updated_at + timedelta(hours=1),
    )

    assert at_deadline.probes == 2
    assert at_deadline.elapsed_ms == 0
    assert at_deadline.result_bytes == 65_024
    assert at_deadline.cost_units == 2
    assert at_deadline.deadline_at == report.created_at + timedelta(
        milliseconds=envelope.context.evidence_budget.max_elapsed_ms
    )
    assert long_after_deadline == at_deadline


def test_alternative_histories_classify_mixed_known_and_unresolved_effects() -> None:
    report = make_report(Classification.UNKNOWN)
    findings = list(report.proof.effect_findings)
    findings[0] = findings[0].model_copy(
        update={"state": EffectAssertionState.ESTABLISHED}
    )
    report = report.model_copy(
        update={"proof": report.proof.model_copy(update={"effect_findings": findings})}
    )

    histories = _alternative_histories(report)

    assert tuple(item.classification for item in histories) == (
        Classification.COMMITTED,
        Classification.PARTIAL,
    )


def test_recovery_agent_fails_closed_on_unavailable_model() -> None:
    planner = _Planner(failure=PlannerFailureKind.TIMEOUT)
    chain = make_recovery_examples()[0]
    agent = RecoveryAgent(planner)

    async def exercise():
        return await agent.hypothesize(
            chain=chain,
            node=chain.nodes[0],
            envelope=make_envelope(),
            report=make_report(Classification.COMMITTED),
            capabilities=(make_capability(),),
        )

    turn = asyncio.run(exercise())
    assert turn.failure is PlannerFailureKind.TIMEOUT
    assert turn.hypothesis is None
