"""Hosted conditional planning over the sandbox weak-observation boundary."""

from __future__ import annotations

import asyncio
import hashlib
from datetime import UTC, datetime, timedelta
from pathlib import Path

import httpx
import pytest

from reconcile.adapters.sandbox_order import (
    SANDBOX_ORDER_AGGREGATE_CAPABILITY_NAME,
    SANDBOX_ORDER_CLOUD_AUTHORITY_POLICY_VERSION,
    SANDBOX_ORDER_CLOUD_PROFILE,
    SANDBOX_ORDER_INGRESS_CAPABILITY_NAME,
    build_sandbox_order_target,
)
from reconcile.adaptive import (
    AdaptiveStopReason,
    AdvisoryPlannerMetadata,
    AdvisoryPlannerTurn,
    AdvisoryPlannerUsage,
    PlannerFailureKind,
    ProposalDisposition,
)
from reconcile.contracts import (
    ADAPTIVE_PLANNER_INPUT_VERSION,
    ADAPTIVE_PLANNER_OUTPUT_VERSION,
    SCENARIO_RUN_REQUEST_VERSION,
    AdaptivePlannerInput,
    AdaptivePlannerOutput,
    Classification,
    PlannerAcquisitionAdvice,
    PlannerCitationRefs,
    PlannerExplanation,
    PlannerStopAdvice,
    ProbeRequest,
    RequestedAction,
    ScenarioFaultAction,
    ScenarioFaultInstruction,
    ScenarioFaultPoint,
    ScenarioRunRequest,
    canonical_json_bytes,
    decode_contract,
)
from reconcile.hosted.contracts import (
    INTERNAL_OPERATION_RESPONSE_VERSION,
    InternalOperation,
    InternalOperationRequest,
    InternalOperationResponse,
    canonical_internal_json_bytes,
)
from reconcile.hosted.sandbox import HostedSandboxEvidenceTarget
from reconcile.hosted.transport import HostedHttpTransport
from reconcile.scenarios.local_order import (
    HiddenOrderOutcome,
    LocalOrderHarness,
    LocalOrderReadTarget,
)
from reconcile.scenarios.runner import ScenarioRunner
from reconcile.scenarios.sandbox_order import (
    SANDBOX_ORDER_FIXED_PROBE_PLAN,
    SANDBOX_ORDER_ITEM_CODE,
    SANDBOX_ORDER_QUANTITY,
    SANDBOX_ORDER_SCENARIO,
    SandboxOrderScenarioDefinition,
    execute_sandbox_order_conditional,
)
from tests._clocks import ConstantClock

pytestmark = pytest.mark.integration

NOW = datetime(2026, 8, 13, 23, 45, tzinfo=UTC)


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


def _metadata() -> AdvisoryPlannerMetadata:
    return AdvisoryPlannerMetadata(
        provider_name="scripted-hosted",
        configured_model="scripted-hosted-v1",
        reported_model="scripted-hosted-v1",
        adk_version="test-adk-v1",
        genai_version="test-genai-v1",
        prompt_version="test-prompt-v1",
        prompt_sha256="a" * 64,
        input_schema_version=ADAPTIVE_PLANNER_INPUT_VERSION,
        output_schema_version=ADAPTIVE_PLANNER_OUTPUT_VERSION,
    )


class _Planner:
    def __init__(
        self,
        proposal: ProbeRequest,
        *,
        failure: PlannerFailureKind | None = None,
    ) -> None:
        self._proposal = proposal
        self._failure = failure
        self.metadata = _metadata()
        self.inputs: list[AdaptivePlannerInput] = []
        self.input_bytes: list[bytes] = []

    async def plan(self, planner_input: AdaptivePlannerInput) -> AdvisoryPlannerTurn:
        payload = canonical_json_bytes(planner_input)
        self.inputs.append(planner_input)
        self.input_bytes.append(payload)
        digest = hashlib.sha256(payload).hexdigest()
        if self._failure is not None:
            return AdvisoryPlannerTurn(
                output=None,
                failure=self._failure,
                metadata=self.metadata,
                input_sha256=digest,
                output_sha256=None,
                usage=None,
            )

        weak_ids = tuple(item.evidence_id for item in planner_input.weak_evidence)
        rejected_ids = tuple(
            item.evidence_id for item in planner_input.rejected_evidence
        )
        missing_ids = tuple(item.effect_id for item in planner_input.missing_evidence)
        output = AdaptivePlannerOutput(
            schema_version=ADAPTIVE_PLANNER_OUTPUT_VERSION,
            probe_proposals=(self._proposal,),
            acquisition_advice=PlannerAcquisitionAdvice(
                summary="Consider one remaining bounded read."
            ),
            stop_advice=PlannerStopAdvice(
                recommend_stop=True,
                reason="Deterministic policy retains stop authority.",
            ),
            missing_evidence_notes=(),
            explanation=PlannerExplanation(
                summary="Cite the normalized bootstrap evidence.",
                admitted_evidence=None,
                weak_evidence="Bootstrap evidence remains weak." if weak_ids else None,
                rejected_evidence=(
                    "Bootstrap evidence was rejected." if rejected_ids else None
                ),
                missing_evidence=(
                    "Authoritative evidence remains missing." if missing_ids else None
                ),
                citations=PlannerCitationRefs(
                    admitted_evidence_ids=(),
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
            metadata=self.metadata,
            input_sha256=digest,
            output_sha256=hashlib.sha256(output_bytes).hexdigest(),
            usage=AdvisoryPlannerUsage(
                prompt_tokens=10,
                output_tokens=4,
                total_tokens=14,
            ),
        )


def _prepared_sandbox(tmp_path: Path, suffix: str):
    private_path = tmp_path / f"{suffix}-private.sqlite3"
    observation_path = tmp_path / f"{suffix}-observations.sqlite3"
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
        hidden_outcome=HiddenOrderOutcome.COMMIT,
        invoked_at=NOW,
        target_clock=ConstantClock(NOW + timedelta(seconds=1)),
    )
    request = ScenarioRunRequest(
        schema_version=SCENARIO_RUN_REQUEST_VERSION,
        scenario=SANDBOX_ORDER_SCENARIO,
        run_id=f"run-hosted-{suffix}",
        investigation_id=f"investigation-hosted-{suffix}",
        operation_id=f"operation-hosted-{suffix}",
        invocation_id=f"invocation-hosted-{suffix}",
        function_call_id=f"function-call-hosted-{suffix}",
        seed=47,
        fault=ScenarioFaultInstruction(
            point=ScenarioFaultPoint.POST_COMMIT,
            action=ScenarioFaultAction.INTERRUPT_PROCESS,
        ),
    )
    run = ScenarioRunner(clock=_StepClock(NOW + timedelta(seconds=2))).run(
        request,
        definition,
    )
    assert run.execution_envelope is not None
    return run.execution_envelope, LocalOrderReadTarget(observation_path), private_path


def test_conditional_sandbox_input_contains_bootstrap_and_only_one_remaining_read(
    tmp_path: Path,
) -> None:
    envelope, read_target, private_path = _prepared_sandbox(tmp_path, "success")
    aggregate = SANDBOX_ORDER_FIXED_PROBE_PLAN.steps[1].request
    planner = _Planner(aggregate)

    result = asyncio.run(
        execute_sandbox_order_conditional(
            envelope,
            read_target,
            planner,
            clock=_StepClock(NOW + timedelta(seconds=3)),
        )
    )

    assert result.classification is Classification.UNKNOWN
    assert result.stop_reason is AdaptiveStopReason.NON_PROGRESS
    assert result.attempted_probe_count == 2
    assert result.acquisition_turn_count == result.model_invocation_count == 1
    assert result.explanation_valid is None
    assert result.report.advisory_explanation is None
    assert tuple(item.capability_name for item in result.report.probe_audit) == (
        SANDBOX_ORDER_INGRESS_CAPABILITY_NAME,
        SANDBOX_ORDER_AGGREGATE_CAPABILITY_NAME,
    )
    assert len(planner.inputs) == 1
    planner_input = planner.inputs[0]
    assert tuple(item.name for item in planner_input.capabilities) == (
        SANDBOX_ORDER_AGGREGATE_CAPABILITY_NAME,
        SANDBOX_ORDER_INGRESS_CAPABILITY_NAME,
    )
    assert {
        item.name: item.remaining_invocations for item in planner_input.capabilities
    } == {
        SANDBOX_ORDER_AGGREGATE_CAPABILITY_NAME: 1,
        SANDBOX_ORDER_INGRESS_CAPABILITY_NAME: 0,
    }
    assert len(planner_input.weak_evidence) == 1
    assert planner_input.weak_evidence[0].capability_name == (
        SANDBOX_ORDER_INGRESS_CAPABILITY_NAME
    )
    assert len(planner_input.prior_executable_request_hashes) == 1
    gates = {item.requested_action: item for item in result.report.action_gate}
    assert not gates[RequestedAction.RETRY].allowed
    assert str(private_path).encode() not in planner.input_bytes[0]


def test_conditional_provider_failure_keeps_only_bootstrap_audit(
    tmp_path: Path,
) -> None:
    envelope, read_target, _ = _prepared_sandbox(tmp_path, "failure")
    planner = _Planner(
        SANDBOX_ORDER_FIXED_PROBE_PLAN.steps[1].request,
        failure=PlannerFailureKind.UNAVAILABLE,
    )

    result = asyncio.run(
        execute_sandbox_order_conditional(
            envelope,
            read_target,
            planner,
            clock=_StepClock(NOW + timedelta(seconds=3)),
        )
    )

    assert result.stop_reason is AdaptiveStopReason.PLANNER_UNAVAILABLE
    assert result.classification is Classification.UNKNOWN
    assert result.attempted_probe_count == 1
    assert result.model_invocation_count == 1
    assert tuple(item.capability_name for item in result.report.probe_audit) == (
        SANDBOX_ORDER_INGRESS_CAPABILITY_NAME,
    )


def test_conditional_planner_cannot_reselect_consumed_ingress(tmp_path: Path) -> None:
    envelope, read_target, _ = _prepared_sandbox(tmp_path, "reselect")
    ingress = SANDBOX_ORDER_FIXED_PROBE_PLAN.steps[0].request.model_copy(
        update={"rationale": "Attempt to select the consumed ingress read again."}
    )
    planner = _Planner(ingress)

    result = asyncio.run(
        execute_sandbox_order_conditional(
            envelope,
            read_target,
            planner,
            clock=_StepClock(NOW + timedelta(seconds=3)),
        )
    )

    assert result.stop_reason is AdaptiveStopReason.NON_PROGRESS
    assert result.attempted_probe_count == 1
    assert result.proposal_count == 1
    assert result.turns[0].proposals[0].disposition is (ProposalDisposition.DUPLICATE)
    assert tuple(item.capability_name for item in result.report.probe_audit) == (
        SANDBOX_ORDER_INGRESS_CAPABILITY_NAME,
    )


def test_hosted_target_runs_bootstrap_then_one_selected_weak_read(
    tmp_path: Path,
) -> None:
    local_envelope, _, private_path = _prepared_sandbox(tmp_path, "hosted-route")
    sandbox_id = local_envelope.target.scope["sandbox_id"]
    hosted_context = local_envelope.context.model_copy(
        update={
            "policies": local_envelope.context.policies.model_copy(
                update={
                    "authority": SANDBOX_ORDER_CLOUD_AUTHORITY_POLICY_VERSION,
                }
            )
        }
    )
    hosted_envelope = decode_contract(
        canonical_json_bytes(
            local_envelope.model_copy(
                update={
                    "target": build_sandbox_order_target(
                        sandbox_id=sandbox_id,
                        profile=SANDBOX_ORDER_CLOUD_PROFILE,
                    ),
                    "context": hosted_context,
                }
            )
        ),
        type(local_envelope),
    )
    aggregate = SANDBOX_ORDER_FIXED_PROBE_PLAN.steps[1].request
    planner = _Planner(aggregate)
    observations: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        internal = decode_contract(request.content, InternalOperationRequest)
        observation = internal.payload["observation"]
        assert type(observation) is str
        observations.append(observation)
        payload = (
            {
                "ingress": {
                    "event_kind": "REQUEST_SEEN",
                    "observed_at": NOW.isoformat(),
                }
            }
            if observation == "ingress"
            else {
                "aggregate": {
                    "count_band": "ONE_OR_MORE",
                    "observed_at": NOW.isoformat(),
                }
            }
        )
        response = InternalOperationResponse(
            schema_version=INTERNAL_OPERATION_RESPONSE_VERSION,
            request_id=internal.request_id,
            operation=InternalOperation.READ_EVIDENCE,
            accepted=True,
            payload=payload,
        )
        return httpx.Response(200, content=canonical_internal_json_bytes(response))

    async def exercise():
        async with httpx.AsyncClient(
            transport=httpx.MockTransport(handler),
        ) as client:
            target = HostedSandboxEvidenceTarget(
                sandbox_url="https://sandbox.example.test",
                sandbox_audience="https://sandbox.example.test",
                sandbox_id=sandbox_id,
                transport=HostedHttpTransport(
                    lambda _audience: "header.payload.signature",
                    client,
                ),
            )
            return await execute_sandbox_order_conditional(
                hosted_envelope,
                target,
                planner,
                clock=_StepClock(NOW + timedelta(seconds=3)),
            )

    result = asyncio.run(exercise())

    assert observations == ["ingress", "aggregate"]
    assert result.classification is Classification.UNKNOWN
    assert result.attempted_probe_count == 2
    assert result.model_invocation_count == 1
    assert tuple(item.capability_name for item in result.report.probe_audit) == (
        SANDBOX_ORDER_INGRESS_CAPABILITY_NAME,
        SANDBOX_ORDER_AGGREGATE_CAPABILITY_NAME,
    )
    assert planner.inputs[0].envelope.target.scope["environment"] == (
        SANDBOX_ORDER_CLOUD_PROFILE.environment
    )
    assert all("local SQLite" not in item for item in result.report.limitations)
    assert str(private_path).encode() not in planner.input_bytes[0]
