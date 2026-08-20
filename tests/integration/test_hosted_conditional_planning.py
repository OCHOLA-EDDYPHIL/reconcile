"""Hosted conditional planning over the sandbox weak-observation boundary."""

from __future__ import annotations

import asyncio
import hashlib
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace

import httpx
import pytest

import reconcile.hosted.runtime as hosted_runtime
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
    ExecutionEnvelope,
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
from reconcile.durable_application import (
    DurableExecutionStrategy,
    DurableInvestigationApplicationService,
)
from reconcile.hosted.contracts import (
    INTERNAL_OPERATION_RESPONSE_VERSION,
    InternalOperation,
    InternalOperationRequest,
    InternalOperationResponse,
    canonical_internal_json_bytes,
)
from reconcile.hosted.runtime import HostedFixedExecutor, HostedHybridExecutor
from reconcile.hosted.sandbox import HostedSandboxEvidenceTarget
from reconcile.hosted.transport import HostedHttpTransport
from reconcile.persistence import DurableRunState, SqliteDurableRuntimeStore
from reconcile.scenarios.local_order import (
    HiddenOrderOutcome,
    LocalOrderHarness,
    LocalOrderReadTarget,
)
from reconcile.scenarios.runner import ScenarioRunner
from reconcile.scenarios.sandbox_order import (
    SANDBOX_ORDER_CONDITIONAL_POLICY,
    SANDBOX_ORDER_FIXED_PROBE_PLAN,
    SANDBOX_ORDER_ITEM_CODE,
    SANDBOX_ORDER_QUANTITY,
    SANDBOX_ORDER_SCENARIO,
    SandboxOrderScenarioDefinition,
    execute_sandbox_order_baseline,
    execute_sandbox_order_conditional,
)
from reconcile.scenarios.service import (
    bounded_hybrid_route_provenance,
    is_bounded_hybrid_explicit_unknown,
    is_bounded_hybrid_fixed_fallback,
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


class _MutableClock:
    def __init__(self, current: datetime) -> None:
        self._current = current
        self._monotonic = 100.0

    def now(self) -> datetime:
        return self._current

    def monotonic(self) -> float:
        return self._monotonic

    def advance(self, seconds: float) -> None:
        self._current += timedelta(seconds=seconds)
        self._monotonic += seconds


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


class _HangingProviderPlanner:
    """Model a provider that hangs until its inner boundary sanitizes timeout."""

    def __init__(self, *, timeout_seconds: float = 0.01) -> None:
        self.metadata = _metadata()
        self.timeout_seconds = timeout_seconds
        self.inputs: list[AdaptivePlannerInput] = []

    async def plan(self, planner_input: AdaptivePlannerInput) -> AdvisoryPlannerTurn:
        self.inputs.append(planner_input)
        input_sha256 = hashlib.sha256(canonical_json_bytes(planner_input)).hexdigest()
        try:
            async with asyncio.timeout(self.timeout_seconds):
                await asyncio.Event().wait()
        except TimeoutError:
            return AdvisoryPlannerTurn(
                output=None,
                failure=PlannerFailureKind.TIMEOUT,
                metadata=self.metadata,
                input_sha256=input_sha256,
                output_sha256=None,
                usage=None,
            )
        raise AssertionError("hanging provider unexpectedly returned")


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


def _hosted_envelope(envelope: ExecutionEnvelope) -> ExecutionEnvelope:
    sandbox_id = envelope.target.scope["sandbox_id"]
    hosted_context = envelope.context.model_copy(
        update={
            "policies": envelope.context.policies.model_copy(
                update={
                    "authority": SANDBOX_ORDER_CLOUD_AUTHORITY_POLICY_VERSION,
                }
            )
        }
    )
    return decode_contract(
        canonical_json_bytes(
            envelope.model_copy(
                update={
                    "target": build_sandbox_order_target(
                        sandbox_id=sandbox_id,
                        profile=SANDBOX_ORDER_CLOUD_PROFILE,
                    ),
                    "context": hosted_context,
                }
            )
        ),
        ExecutionEnvelope,
    )


class _CompletionRuntime:
    def __init__(self) -> None:
        self.reports: list[object] = []

    async def complete(self, report: object) -> SimpleNamespace:
        self.reports.append(report)
        return SimpleNamespace(report=report)


def _fixed_executor() -> HostedFixedExecutor:
    return HostedFixedExecutor(
        storage_reader=object(),  # type: ignore[arg-type]
        firestore_reader=object(),  # type: ignore[arg-type]
        sandbox_url="https://sandbox.example.test",
        sandbox_audience="https://sandbox.example.test",
        transport=HostedHttpTransport(),
    )


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
    hosted_envelope = _hosted_envelope(local_envelope)
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


def test_hosted_runtime_predispatch_planner_failure_uses_fresh_fixed_path(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    local_envelope, read_target, _ = _prepared_sandbox(
        tmp_path,
        "runtime-predispatch-failure",
    )
    fixed_result = asyncio.run(
        execute_sandbox_order_baseline(
            local_envelope,
            read_target,
            clock=_StepClock(NOW + timedelta(seconds=3)),
        )
    )
    hosted_envelope = _hosted_envelope(local_envelope)
    calls: list[str] = []

    async def fixed(*_args: object, **_kwargs: object):
        calls.append("fixed")
        return fixed_result

    async def conditional(*_args: object, **_kwargs: object):
        calls.append("conditional")
        raise AssertionError("predispatch failure cannot start conditional reads")

    def unavailable_planner():
        calls.append("planner-factory")
        raise RuntimeError("sanitized provider unavailable")

    monkeypatch.setattr(hosted_runtime, "execute_hosted_sandbox_order_fixed", fixed)
    monkeypatch.setattr(
        hosted_runtime,
        "execute_sandbox_order_conditional",
        conditional,
    )
    runtime = _CompletionRuntime()
    executor = HostedHybridExecutor(
        fixed=_fixed_executor(),
        planner_factory=unavailable_planner,
    )

    outcome = asyncio.run(
        executor(
            hosted_envelope,
            revision=1,
            cancellation_event=asyncio.Event(),
            runtime=runtime,  # type: ignore[arg-type]
        )
    )

    assert calls == ["planner-factory", "fixed"]
    assert is_bounded_hybrid_fixed_fallback(outcome.report)
    assert len(outcome.report.probe_audit) == 2
    route = bounded_hybrid_route_provenance(outcome.report)
    assert route is not None
    assert route.provider_failure
    assert route.fixed_connector_invoked
    assert not route.planner_invoked


def test_hosted_runtime_postread_provider_failure_stops_unknown_without_replay(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    local_envelope, read_target, _ = _prepared_sandbox(
        tmp_path,
        "runtime-postread-failure",
    )
    failed_planner = _Planner(
        SANDBOX_ORDER_FIXED_PROBE_PLAN.steps[1].request,
        failure=PlannerFailureKind.UNAVAILABLE,
    )
    failed_result = asyncio.run(
        execute_sandbox_order_conditional(
            local_envelope,
            read_target,
            failed_planner,
            clock=_StepClock(NOW + timedelta(seconds=3)),
        )
    )
    hosted_envelope = _hosted_envelope(local_envelope)
    fixed_calls = 0

    async def conditional(*_args: object, **_kwargs: object):
        return failed_result

    async def fixed(*_args: object, **_kwargs: object):
        nonlocal fixed_calls
        fixed_calls += 1
        raise AssertionError("post-read provider failure cannot replay fixed reads")

    monkeypatch.setattr(
        hosted_runtime,
        "execute_sandbox_order_conditional",
        conditional,
    )
    monkeypatch.setattr(hosted_runtime, "execute_hosted_sandbox_order_fixed", fixed)
    runtime = _CompletionRuntime()
    executor = HostedHybridExecutor(
        fixed=_fixed_executor(),
        planner_factory=lambda: _Planner(
            SANDBOX_ORDER_FIXED_PROBE_PLAN.steps[1].request
        ),
    )

    outcome = asyncio.run(
        executor(
            hosted_envelope,
            revision=1,
            cancellation_event=asyncio.Event(),
            runtime=runtime,  # type: ignore[arg-type]
        )
    )

    assert len(failed_planner.inputs) == 1
    assert fixed_calls == 0
    assert is_bounded_hybrid_explicit_unknown(outcome.report)
    assert not is_bounded_hybrid_fixed_fallback(outcome.report)
    assert outcome.report.classification is Classification.UNKNOWN
    assert tuple(item.capability_name for item in outcome.report.probe_audit) == (
        SANDBOX_ORDER_INGRESS_CAPABILITY_NAME,
    )
    route = bounded_hybrid_route_provenance(outcome.report)
    assert route is not None
    assert route.provider_failure
    assert route.planner_invoked
    assert not route.fixed_connector_invoked


def test_hosted_runtime_bootstrap_failure_does_not_claim_planner_invocation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    local_envelope, _, _ = _prepared_sandbox(tmp_path, "bootstrap-failure")
    hosted_envelope = _hosted_envelope(local_envelope)
    sandbox_id = hosted_envelope.target.scope["sandbox_id"]
    assert type(sandbox_id) is str
    planner = _Planner(SANDBOX_ORDER_FIXED_PROBE_PLAN.steps[1].request)

    async def fail_bootstrap():
        async with httpx.AsyncClient(
            transport=httpx.MockTransport(
                lambda _request: httpx.Response(503, content=b"unavailable")
            )
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

    failed_result = asyncio.run(fail_bootstrap())
    assert failed_result.classification is Classification.UNKNOWN
    assert failed_result.model_invocation_count == 0
    assert failed_result.attempted_probe_count == 1
    assert planner.inputs == []

    async def conditional(*_args: object, **_kwargs: object):
        return failed_result

    async def fixed(*_args: object, **_kwargs: object):
        raise AssertionError("a consumed bootstrap read cannot be replayed")

    monkeypatch.setattr(
        hosted_runtime,
        "execute_sandbox_order_conditional",
        conditional,
    )
    monkeypatch.setattr(hosted_runtime, "execute_hosted_sandbox_order_fixed", fixed)
    outcome = asyncio.run(
        HostedHybridExecutor(
            fixed=_fixed_executor(),
            planner_factory=lambda: planner,
        )(
            hosted_envelope,
            revision=1,
            cancellation_event=asyncio.Event(),
            runtime=_CompletionRuntime(),  # type: ignore[arg-type]
        )
    )

    assert is_bounded_hybrid_explicit_unknown(outcome.report)
    route = bounded_hybrid_route_provenance(outcome.report)
    assert route is not None
    assert not route.planner_invoked
    assert not route.fixed_connector_invoked
    assert not route.provider_failure


def test_durable_hosted_predispatch_failure_completes_fixed_fallback(
    tmp_path: Path,
) -> None:
    local_envelope, _, _ = _prepared_sandbox(
        tmp_path,
        "durable-predispatch-failure",
    )
    hosted_envelope = _hosted_envelope(local_envelope)
    observations: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        internal = decode_contract(request.content, InternalOperationRequest)
        observation = internal.payload["observation"]
        assert type(observation) is str
        observations.append(observation)
        observed_at = datetime.now(UTC).isoformat()
        payload = (
            {
                "ingress": {
                    "event_kind": "REQUEST_SEEN",
                    "observed_at": observed_at,
                }
            }
            if observation == "ingress"
            else {
                "aggregate": {
                    "count_band": "ONE_OR_MORE",
                    "observed_at": observed_at,
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

    async def exercise() -> None:
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
            transport = HostedHttpTransport(
                lambda _audience: "header.payload.signature",
                client,
            )
            fixed = HostedFixedExecutor(
                storage_reader=object(),  # type: ignore[arg-type]
                firestore_reader=object(),  # type: ignore[arg-type]
                sandbox_url="https://sandbox.example.test",
                sandbox_audience="https://sandbox.example.test",
                transport=transport,
            )

            def unavailable_planner():
                raise RuntimeError("sanitized provider unavailable")

            store = SqliteDurableRuntimeStore(tmp_path / "predispatch-runtime.sqlite3")
            service = DurableInvestigationApplicationService(
                store,
                HostedHybridExecutor(
                    fixed=fixed,
                    planner_factory=unavailable_planner,
                ),
                strategy=DurableExecutionStrategy.ADAPTIVE,
                owner_id="hosted-predispatch-regression",
                semantic_config_sha256="b" * 64,
                max_provider_calls=1,
                max_estimated_cost_microunits=1,
            )
            result = await service.create_and_wait_result(hosted_envelope)
            run = await store.get_run(hosted_envelope.investigation_id)
            receipts = await store.provider_call_receipts(
                hosted_envelope.investigation_id
            )
            await service.aclose()

        assert result.report.classification is Classification.UNKNOWN
        assert run.state is DurableRunState.TERMINAL
        assert receipts == ()
        assert observations == ["ingress", "aggregate"]
        route = bounded_hybrid_route_provenance(result.report)
        assert route is not None
        assert route.provider_failure
        assert route.fixed_connector_invoked
        assert not route.planner_invoked

    asyncio.run(exercise())


def test_durable_hosted_provider_timeout_completes_unknown_without_replay(
    tmp_path: Path,
) -> None:
    local_envelope, _, _ = _prepared_sandbox(
        tmp_path,
        "durable-provider-timeout",
    )
    hosted_envelope = _hosted_envelope(local_envelope)
    planner = _HangingProviderPlanner()
    observations: list[str] = []

    assert (
        hosted_runtime._HOSTED_PROVIDER_TIMEOUT_SECONDS * 1_000
        < SANDBOX_ORDER_CONDITIONAL_POLICY.planner_timeout_ms
        < hosted_envelope.context.evidence_budget.max_elapsed_ms
    )

    def handler(request: httpx.Request) -> httpx.Response:
        internal = decode_contract(request.content, InternalOperationRequest)
        observation = internal.payload["observation"]
        assert type(observation) is str
        observations.append(observation)
        payload = (
            {
                "ingress": {
                    "event_kind": "REQUEST_SEEN",
                    "observed_at": datetime.now(UTC).isoformat(),
                }
            }
            if observation == "ingress"
            else {
                "aggregate": {
                    "count_band": "ONE_OR_MORE",
                    "observed_at": datetime.now(UTC).isoformat(),
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

    async def exercise() -> None:
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
            transport = HostedHttpTransport(
                lambda _audience: "header.payload.signature",
                client,
            )
            fixed = HostedFixedExecutor(
                storage_reader=object(),  # type: ignore[arg-type]
                firestore_reader=object(),  # type: ignore[arg-type]
                sandbox_url="https://sandbox.example.test",
                sandbox_audience="https://sandbox.example.test",
                transport=transport,
            )
            store = SqliteDurableRuntimeStore(tmp_path / "timeout-runtime.sqlite3")
            service = DurableInvestigationApplicationService(
                store,
                HostedHybridExecutor(
                    fixed=fixed,
                    planner_factory=lambda: planner,
                ),
                strategy=DurableExecutionStrategy.ADAPTIVE,
                owner_id="hosted-provider-timeout-regression",
                semantic_config_sha256="d" * 64,
                max_provider_calls=1,
                max_estimated_cost_microunits=1,
            )
            result = await service.create_and_wait_result(hosted_envelope)
            run = await store.get_run(hosted_envelope.investigation_id)
            receipts = await store.provider_call_receipts(
                hosted_envelope.investigation_id
            )
            await service.aclose()

        assert result.report.classification is Classification.UNKNOWN
        assert run.state is DurableRunState.TERMINAL
        assert len(receipts) == 1
        assert receipts[0].estimated_cost_microunits == 1
        assert observations == ["ingress"]
        assert len(planner.inputs) == 1
        assert is_bounded_hybrid_explicit_unknown(result.report)
        assert not is_bounded_hybrid_fixed_fallback(result.report)
        route = bounded_hybrid_route_provenance(result.report)
        assert route is not None
        assert route.provider_failure
        assert route.planner_invoked
        assert not route.fixed_connector_invoked

    asyncio.run(exercise())


def test_durable_hosted_late_provider_window_completes_predispatch_unknown(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    local_envelope, _, _ = _prepared_sandbox(
        tmp_path,
        "durable-late-provider-window",
    )
    hosted_envelope = _hosted_envelope(local_envelope)
    hosted_envelope = decode_contract(
        canonical_json_bytes(
            hosted_envelope.model_copy(
                update={
                    "context": hosted_envelope.context.model_copy(
                        update={
                            "evidence_budget": (
                                hosted_envelope.context.evidence_budget.model_copy(
                                    update={"max_elapsed_ms": 500}
                                )
                            )
                        }
                    )
                }
            )
        ),
        ExecutionEnvelope,
    )
    planner = _Planner(SANDBOX_ORDER_FIXED_PROBE_PLAN.steps[1].request)
    observations: list[str] = []
    clock = _MutableClock(datetime.now(UTC))

    def handler(request: httpx.Request) -> httpx.Response:
        internal = decode_contract(request.content, InternalOperationRequest)
        observation = internal.payload["observation"]
        assert observation == "ingress"
        observations.append(observation)
        clock.advance(4.2)
        response = InternalOperationResponse(
            schema_version=INTERNAL_OPERATION_RESPONSE_VERSION,
            request_id=internal.request_id,
            operation=InternalOperation.READ_EVIDENCE,
            accepted=True,
            payload={
                "ingress": {
                    "event_kind": "REQUEST_SEEN",
                    "observed_at": clock.now().isoformat(),
                }
            },
        )
        return httpx.Response(200, content=canonical_internal_json_bytes(response))

    async def exercise() -> None:
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
            transport = HostedHttpTransport(
                lambda _audience: "header.payload.signature",
                client,
            )
            fixed = HostedFixedExecutor(
                storage_reader=object(),  # type: ignore[arg-type]
                firestore_reader=object(),  # type: ignore[arg-type]
                sandbox_url="https://sandbox.example.test",
                sandbox_audience="https://sandbox.example.test",
                transport=transport,
            )
            store = SqliteDurableRuntimeStore(tmp_path / "late-window-runtime.sqlite3")
            establish_report = store.establish_report

            async def delayed_establish_report(*args, **kwargs):
                await asyncio.sleep(0.75)
                return await establish_report(*args, **kwargs)

            monkeypatch.setattr(store, "establish_report", delayed_establish_report)
            service = DurableInvestigationApplicationService(
                store,
                HostedHybridExecutor(
                    fixed=fixed,
                    planner_factory=lambda: planner,
                ),
                strategy=DurableExecutionStrategy.ADAPTIVE,
                owner_id="hosted-late-window-regression",
                semantic_config_sha256="e" * 64,
                max_provider_calls=1,
                max_estimated_cost_microunits=1,
                clock=clock.now,
                monotonic_clock=clock.monotonic,
            )
            result = await service.create_and_wait_result(hosted_envelope)
            run = await store.get_run(hosted_envelope.investigation_id)
            receipts = await store.provider_call_receipts(
                hosted_envelope.investigation_id
            )
            await service.aclose()

        assert result.report.classification is Classification.UNKNOWN
        assert run.state is DurableRunState.TERMINAL
        assert receipts == ()
        assert observations == ["ingress"]
        assert planner.inputs == []
        assert is_bounded_hybrid_explicit_unknown(result.report)
        assert not is_bounded_hybrid_fixed_fallback(result.report)
        route = bounded_hybrid_route_provenance(result.report)
        assert route is not None
        assert not route.provider_failure
        assert not route.planner_invoked
        assert not route.fixed_connector_invoked

    asyncio.run(exercise())


def test_durable_hosted_bootstrap_failure_completes_preplanner_unknown(
    tmp_path: Path,
) -> None:
    local_envelope, _, _ = _prepared_sandbox(
        tmp_path,
        "durable-bootstrap-failure",
    )
    hosted_envelope = _hosted_envelope(local_envelope)
    planner = _Planner(SANDBOX_ORDER_FIXED_PROBE_PLAN.steps[1].request)
    requests = 0

    def handler(_request: httpx.Request) -> httpx.Response:
        nonlocal requests
        requests += 1
        return httpx.Response(503, content=b"unavailable")

    async def exercise() -> None:
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
            transport = HostedHttpTransport(
                lambda _audience: "header.payload.signature",
                client,
            )
            fixed = HostedFixedExecutor(
                storage_reader=object(),  # type: ignore[arg-type]
                firestore_reader=object(),  # type: ignore[arg-type]
                sandbox_url="https://sandbox.example.test",
                sandbox_audience="https://sandbox.example.test",
                transport=transport,
            )
            store = SqliteDurableRuntimeStore(tmp_path / "bootstrap-runtime.sqlite3")
            service = DurableInvestigationApplicationService(
                store,
                HostedHybridExecutor(
                    fixed=fixed,
                    planner_factory=lambda: planner,
                ),
                strategy=DurableExecutionStrategy.ADAPTIVE,
                owner_id="hosted-bootstrap-regression",
                semantic_config_sha256="c" * 64,
                max_provider_calls=1,
                max_estimated_cost_microunits=1,
            )
            result = await service.create_and_wait_result(hosted_envelope)
            run = await store.get_run(hosted_envelope.investigation_id)
            receipts = await store.provider_call_receipts(
                hosted_envelope.investigation_id
            )
            await service.aclose()

        assert result.report.classification is Classification.UNKNOWN
        assert run.state is DurableRunState.TERMINAL
        assert receipts == ()
        assert requests == 1
        assert planner.inputs == []
        route = bounded_hybrid_route_provenance(result.report)
        assert route is not None
        assert not route.provider_failure
        assert not route.fixed_connector_invoked
        assert not route.planner_invoked

    asyncio.run(exercise())
