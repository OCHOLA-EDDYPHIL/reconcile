"""Cross-scenario integration coverage for bounded adaptive investigation."""

from __future__ import annotations

import asyncio
import hashlib
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from reconcile.adaptive import (
    AdaptiveInvestigationResult,
    AdaptiveStopReason,
    AdvisoryPlannerMetadata,
    AdvisoryPlannerTurn,
    AdvisoryPlannerUsage,
)
from reconcile.contracts import (
    ADAPTIVE_PLANNER_INPUT_VERSION,
    ADAPTIVE_PLANNER_OUTPUT_VERSION,
    PROBE_REQUEST_VERSION,
    SCENARIO_RUN_REQUEST_VERSION,
    AdaptivePlannerInput,
    AdaptivePlannerOutput,
    AdaptivePlannerPhase,
    Classification,
    ExecutionEnvelope,
    PlannerAcquisitionAdvice,
    PlannerCitationRefs,
    PlannerExplanation,
    PlannerMissingEvidenceNote,
    PlannerStopAdvice,
    ProbeRequest,
    ScenarioFaultAction,
    ScenarioFaultInstruction,
    ScenarioFaultPoint,
    ScenarioRef,
    ScenarioRunRequest,
    canonical_json_bytes,
    decode_contract,
)
from reconcile.contracts.base import canonical_json_value_bytes
from reconcile.scenarios.firestore_business import (
    FIRESTORE_BUSINESS_ADAPTIVE_POLICY,
    FIRESTORE_BUSINESS_FIXED_PROBE_PLAN,
    FIRESTORE_BUSINESS_SCENARIO,
    FirestoreBusinessScenarioDefinition,
)
from reconcile.scenarios.local_order import (
    HiddenOrderOutcome,
    LocalOrderHarness,
    LocalOrderMutationTarget,
)
from reconcile.scenarios.runner import ScenarioRunner
from reconcile.scenarios.sandbox_order import (
    SANDBOX_ORDER_ADAPTIVE_POLICY,
    SANDBOX_ORDER_FIXED_PROBE_PLAN,
    SANDBOX_ORDER_ITEM_CODE,
    SANDBOX_ORDER_QUANTITY,
    SANDBOX_ORDER_SCENARIO,
    SandboxOrderScenarioDefinition,
)
from reconcile.scenarios.storage import (
    STORAGE_ADAPTIVE_POLICY,
    STORAGE_FIXED_PROBE_PLAN,
    STORAGE_SCENARIO,
    StorageScenarioDefinition,
)
from tests._clocks import ConstantClock

pytestmark = pytest.mark.integration

NOW = datetime(2026, 8, 13, 23, 30, tzinfo=UTC)


class _StepClock:
    def __init__(self, current: datetime) -> None:
        self._current = current
        self._monotonic = 100.0

    def now(self) -> datetime:
        result = self._current
        self._current += timedelta(milliseconds=1)
        return result

    def monotonic(self) -> float:
        self._monotonic += 0.001
        return self._monotonic


class _ScriptedPlanner:
    def __init__(self, proposals: tuple[ProbeRequest, ...]) -> None:
        self._proposals = proposals
        self._acquisition_index = 0
        self._metadata = AdvisoryPlannerMetadata(
            provider_name="scripted-local",
            configured_model="scripted-model-v1",
            reported_model="scripted-model-v1",
            adk_version="test-adk-v1",
            genai_version="test-genai-v1",
            prompt_version="test-prompt-v1",
            prompt_sha256="a" * 64,
            input_schema_version=ADAPTIVE_PLANNER_INPUT_VERSION,
            output_schema_version=ADAPTIVE_PLANNER_OUTPUT_VERSION,
        )
        self.inputs: list[AdaptivePlannerInput] = []
        self.input_bytes: list[bytes] = []

    @property
    def metadata(self) -> AdvisoryPlannerMetadata:
        return self._metadata

    async def plan(
        self,
        planner_input: AdaptivePlannerInput,
    ) -> AdvisoryPlannerTurn:
        payload = canonical_json_bytes(planner_input)
        self.inputs.append(planner_input)
        self.input_bytes.append(payload)

        proposal: ProbeRequest | None = None
        if planner_input.phase is AdaptivePlannerPhase.ACQUIRE_EVIDENCE:
            if self._acquisition_index < len(self._proposals):
                proposal = self._proposals[self._acquisition_index]
            self._acquisition_index += 1

        admitted_ids = tuple(
            item.evidence_id for item in planner_input.admitted_evidence
        )
        weak_ids = tuple(item.evidence_id for item in planner_input.weak_evidence)
        rejected_ids = tuple(
            item.evidence_id for item in planner_input.rejected_evidence
        )
        missing_ids = tuple(item.effect_id for item in planner_input.missing_evidence)
        output = AdaptivePlannerOutput(
            schema_version=ADAPTIVE_PLANNER_OUTPUT_VERSION,
            probe_proposals=() if proposal is None else (proposal,),
            acquisition_advice=PlannerAcquisitionAdvice(
                summary="Use only the next bounded read-only proposal."
            ),
            stop_advice=PlannerStopAdvice(
                recommend_stop=True,
                reason="Advisory stop recommendation without controller authority.",
            ),
            missing_evidence_notes=(
                ()
                if not missing_ids
                else (
                    PlannerMissingEvidenceNote(
                        effect_ids=missing_ids,
                        note="Authoritative evidence remains missing.",
                    ),
                )
            ),
            explanation=PlannerExplanation(
                summary="Evidence categories are cited without classifying the result.",
                admitted_evidence=(
                    "Authoritative evidence was admitted." if admitted_ids else None
                ),
                weak_evidence=(
                    "Weak evidence remains non-authoritative." if weak_ids else None
                ),
                rejected_evidence=(
                    "Rejected evidence is not relied upon." if rejected_ids else None
                ),
                missing_evidence=(
                    "Declared effects still lack authoritative evidence."
                    if missing_ids
                    else None
                ),
                citations=PlannerCitationRefs(
                    admitted_evidence_ids=admitted_ids,
                    weak_evidence_ids=weak_ids,
                    rejected_evidence_ids=rejected_ids,
                    missing_effect_ids=missing_ids,
                ),
            ),
        )
        output_bytes = canonical_json_bytes(output)
        return AdvisoryPlannerTurn(
            output=output,
            failure=None,
            metadata=self._metadata,
            input_sha256=hashlib.sha256(payload).hexdigest(),
            output_sha256=hashlib.sha256(output_bytes).hexdigest(),
            usage=AdvisoryPlannerUsage(
                prompt_tokens=1,
                output_tokens=1,
                total_tokens=2,
            ),
        )


def _request(
    scenario: ScenarioRef,
    *,
    suffix: str,
    seed: int,
) -> ScenarioRunRequest:
    return ScenarioRunRequest(
        schema_version=SCENARIO_RUN_REQUEST_VERSION,
        scenario=scenario,
        run_id=f"run-adaptive-{suffix}",
        investigation_id=f"investigation-adaptive-{suffix}",
        operation_id=f"operation-adaptive-{suffix}",
        invocation_id=f"invocation-adaptive-{suffix}",
        function_call_id=f"function-call-adaptive-{suffix}",
        seed=seed,
        fault=ScenarioFaultInstruction(
            point=ScenarioFaultPoint.POST_COMMIT,
            action=ScenarioFaultAction.INTERRUPT_PROCESS,
        ),
    )


def _proposal_trace_bytes(result: AdaptiveInvestigationResult) -> bytes:
    return canonical_json_value_bytes(
        [
            {
                "phase": turn.phase.value,
                "planner_recommended_stop": turn.planner_recommended_stop,
                "proposals": [
                    {
                        "capability_name": proposal.capability_name,
                        "capability_version": proposal.capability_version,
                        "disposition": proposal.disposition.value,
                        "proposal_sequence": proposal.proposal_sequence,
                        "request_sha256": proposal.request_sha256,
                    }
                    for proposal in turn.proposals
                ],
                "selected_request_sha256": turn.selected_request_sha256,
            }
            for turn in result.turns
        ]
    )


def test_canonical_adaptive_paths_resolve_storage_and_partial_business_operation(
    tmp_path: Path,
) -> None:
    storage_definition = StorageScenarioDefinition(
        tmp_path / "storage.sqlite3",
        invoked_at=NOW,
        target_clock=ConstantClock(NOW),
    )
    storage_run = ScenarioRunner(clock=_StepClock(NOW + timedelta(seconds=1))).run(
        _request(STORAGE_SCENARIO, suffix="storage", seed=39),
        storage_definition,
    )
    assert storage_run.execution_envelope is not None
    fixed_storage_report = storage_definition.investigate(
        storage_run.execution_envelope,
        clock=_StepClock(NOW + timedelta(seconds=2)),
    )
    storage_planner = _ScriptedPlanner((STORAGE_FIXED_PROBE_PLAN.steps[0].request,))
    storage = asyncio.run(
        storage_definition.adaptive(
            storage_run.execution_envelope,
            storage_planner,
            clock=_StepClock(NOW + timedelta(seconds=2)),
        )
    )

    firestore_definition = FirestoreBusinessScenarioDefinition(
        tmp_path / "firestore.sqlite3",
        invoked_at=NOW,
        target_clock=ConstantClock(NOW),
    )
    firestore_run = ScenarioRunner(clock=_StepClock(NOW + timedelta(seconds=1))).run(
        _request(FIRESTORE_BUSINESS_SCENARIO, suffix="firestore", seed=0b011),
        firestore_definition,
    )
    assert firestore_run.execution_envelope is not None
    fixed_firestore_report = firestore_definition.investigate(
        firestore_run.execution_envelope,
        clock=_StepClock(NOW + timedelta(seconds=2)),
    )
    firestore_planner = _ScriptedPlanner(
        (FIRESTORE_BUSINESS_FIXED_PROBE_PLAN.steps[0].request,)
    )
    firestore = asyncio.run(
        firestore_definition.adaptive(
            firestore_run.execution_envelope,
            firestore_planner,
            clock=_StepClock(NOW + timedelta(seconds=2)),
        )
    )

    assert fixed_storage_report.classification is Classification.COMMITTED
    assert fixed_storage_report.advisory_explanation is None
    assert storage.classification is Classification.COMMITTED
    assert storage.stop_reason is AdaptiveStopReason.SUFFICIENT_EVIDENCE
    assert storage.policy_sha256 == STORAGE_ADAPTIVE_POLICY.sha256
    assert storage.explanation_valid is True
    assert storage.report.advisory_explanation is not None

    assert fixed_firestore_report.classification is Classification.PARTIAL
    assert fixed_firestore_report.advisory_explanation is None
    assert firestore.classification is Classification.PARTIAL
    assert firestore.stop_reason is AdaptiveStopReason.SUFFICIENT_EVIDENCE
    assert firestore.policy_sha256 == FIRESTORE_BUSINESS_ADAPTIVE_POLICY.sha256
    assert firestore.explanation_valid is True
    assert "partial multi-step business operation" in " ".join(
        firestore.report.limitations
    )


def _sandbox_run(
    tmp_path: Path,
    *,
    name: str,
    outcome: HiddenOrderOutcome,
    request: ScenarioRunRequest,
) -> tuple[SandboxOrderScenarioDefinition, ExecutionEnvelope, Path]:
    private_path = tmp_path / f"{name}-private.sqlite3"
    observation_path = tmp_path / f"{name}-observations.sqlite3"
    LocalOrderHarness(
        private_path,
        observation_path,
        clock=lambda: NOW,
    ).seed_duplicate_looking_order(
        item_code=SANDBOX_ORDER_ITEM_CODE,
        quantity=SANDBOX_ORDER_QUANTITY,
    )
    definition = SandboxOrderScenarioDefinition(
        private_path,
        observation_path,
        hidden_outcome=outcome,
        invoked_at=NOW,
        target_clock=ConstantClock(NOW + timedelta(seconds=1)),
    )
    LocalOrderMutationTarget(
        private_path,
        observation_path,
        hidden_outcome=outcome,
        clock=lambda: NOW + timedelta(seconds=1),
    ).submit_order(
        owner_token=f"adaptive-fixture-owner-{name}",
        item_code=SANDBOX_ORDER_ITEM_CODE,
        quantity=SANDBOX_ORDER_QUANTITY,
    )
    prepared = ScenarioRunner(clock=_StepClock(NOW + timedelta(seconds=2))).prepare(
        request,
        definition,
    )
    envelope = decode_contract(
        prepared.execution_envelope_bytes,
        ExecutionEnvelope,
    )
    return definition, envelope, private_path


def _sandbox_adaptive(
    definition: SandboxOrderScenarioDefinition,
    envelope: ExecutionEnvelope,
) -> tuple[AdaptiveInvestigationResult, _ScriptedPlanner]:
    planner = _ScriptedPlanner(
        tuple(step.request for step in SANDBOX_ORDER_FIXED_PROBE_PLAN.steps)
    )
    result = asyncio.run(
        definition.adaptive(
            envelope,
            planner,
            clock=_StepClock(NOW + timedelta(seconds=3)),
        )
    )
    return result, planner


def test_sandbox_adaptive_inputs_and_outputs_hide_private_outcomes(
    tmp_path: Path,
) -> None:
    request = _request(SANDBOX_ORDER_SCENARIO, suffix="paired", seed=41)
    committed_definition, committed_envelope, committed_private_path = _sandbox_run(
        tmp_path,
        name="committed",
        outcome=HiddenOrderOutcome.COMMIT,
        request=request,
    )
    discarded_definition, discarded_envelope, discarded_private_path = _sandbox_run(
        tmp_path,
        name="discarded",
        outcome=HiddenOrderOutcome.DISCARD,
        request=request,
    )
    assert canonical_json_bytes(committed_envelope) == canonical_json_bytes(
        discarded_envelope
    )

    committed, committed_planner = _sandbox_adaptive(
        committed_definition,
        committed_envelope,
    )
    discarded, discarded_planner = _sandbox_adaptive(
        discarded_definition,
        discarded_envelope,
    )

    for result in (committed, discarded):
        assert result.classification is Classification.UNKNOWN
        assert result.stop_reason is AdaptiveStopReason.NON_PROGRESS
        assert result.policy_sha256 == SANDBOX_ORDER_ADAPTIVE_POLICY.sha256
        assert result.attempted_probe_count == 2
        assert result.acquisition_turn_count == 2
        assert result.explanation_valid is True
        assert result.turns[0].planner_recommended_stop is True
        assert result.turns[1].phase is AdaptivePlannerPhase.ACQUIRE_EVIDENCE

    acquisition_inputs = tuple(
        item
        for item in committed_planner.inputs
        if item.phase is AdaptivePlannerPhase.ACQUIRE_EVIDENCE
    )
    assert len(acquisition_inputs) == 2
    assert acquisition_inputs[0].weak_evidence == ()
    assert acquisition_inputs[0].prior_executable_request_hashes == ()
    assert len(acquisition_inputs[1].weak_evidence) == 1
    assert len(acquisition_inputs[1].prior_executable_request_hashes) == 1
    assert canonical_json_bytes(acquisition_inputs[0]) != canonical_json_bytes(
        acquisition_inputs[1]
    )

    assert committed_planner.input_bytes == discarded_planner.input_bytes
    assert _proposal_trace_bytes(committed) == _proposal_trace_bytes(discarded)
    assert canonical_json_bytes(committed.report) == canonical_json_bytes(
        discarded.report
    )
    assert committed.report.action_gate == discarded.report.action_gate

    public_inputs = b"".join(committed_planner.input_bytes)
    assert str(committed_private_path).encode() not in public_inputs
    assert str(discarded_private_path).encode() not in public_inputs
    for forbidden in (b'"COMMIT"', b'"DISCARD"', b"hidden_outcome", b"owner_token"):
        assert forbidden not in public_inputs


def test_scripted_proposals_remain_fully_typed() -> None:
    for request in (
        STORAGE_FIXED_PROBE_PLAN.steps[0].request,
        FIRESTORE_BUSINESS_FIXED_PROBE_PLAN.steps[0].request,
        *(step.request for step in SANDBOX_ORDER_FIXED_PROBE_PLAN.steps),
    ):
        assert request.schema_version == PROBE_REQUEST_VERSION
        assert request.arguments == {}
