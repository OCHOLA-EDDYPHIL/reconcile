"""Gemini advisory output remains bounded to hypotheses and read probes."""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime

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
    AdaptivePlannerOutput,
    Classification,
    PlannerAcquisitionAdvice,
    PlannerCitationRefs,
    PlannerExplanation,
    PlannerStopAdvice,
    canonical_sha256,
)
from reconcile.recovery_agents import RecoveryAgent
from tests.contract._factories import (
    make_capability,
    make_envelope,
    make_probe,
    make_recovery_examples,
    make_report,
)

pytestmark = pytest.mark.unit


def _output(*, probe_count: int = 1) -> AdaptivePlannerOutput:
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
            admitted_evidence="The exact target read is authoritative.",
            weak_evidence=None,
            rejected_evidence=None,
            missing_evidence=None,
            citations=PlannerCitationRefs(
                admitted_evidence_ids=("evidence-7",),
                weak_evidence_ids=(),
                rejected_evidence_ids=(),
                missing_effect_ids=(),
            ),
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
    agent = RecoveryAgent(
        planner,
        clock=lambda: datetime(2026, 8, 22, 12, 0, tzinfo=UTC),
    )
    chain = make_recovery_examples()[0]

    async def exercise():
        return await agent.hypothesize(
            chain=chain,
            node=chain.nodes[0],
            envelope=make_envelope(),
            report=make_report(Classification.COMMITTED),
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
    assert planner.inputs[0].envelope == make_envelope()


@pytest.mark.parametrize(
    ("planner", "expected"),
    (
        (_Planner(output=_output(probe_count=2)), PlannerFailureKind.SCHEMA_INVALID),
        (_Planner(failure=PlannerFailureKind.TIMEOUT), PlannerFailureKind.TIMEOUT),
    ),
)
def test_recovery_agent_fails_closed_on_malformed_or_unavailable_model(
    planner: _Planner,
    expected: PlannerFailureKind,
) -> None:
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
    assert turn.failure is expected
    assert turn.hypothesis is None
