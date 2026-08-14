"""Deterministic fixed-plan execution through shared safety boundaries."""

from __future__ import annotations

import asyncio
import json
from datetime import UTC, datetime, timedelta

import pytest

from reconcile.baseline import (
    FixedBaselineStopReason,
    FixedProbePlan,
    FixedProbeStep,
    execute_fixed_plan,
    run_fixed_plan,
)
from reconcile.contracts import (
    OBSERVATION_CAPABILITY_VERSION,
    PROBE_REQUEST_VERSION,
    Classification,
    EffectAssertion,
    EffectAssertionState,
    ExecutionEnvelope,
    ObservationCapability,
    OperationStatus,
    ProbeOutcome,
    ProbeRequest,
    RequestedAction,
    TargetConstraint,
    canonical_json_bytes,
    decode_contract,
)
from reconcile.controller import (
    BoundProbe,
    CapabilityRegistration,
    CapabilityRegistry,
    CapabilitySemantics,
    CapabilityUnavailable,
    ProbeObservation,
)
from reconcile.evidence import (
    RuleInput,
    RuleObservation,
    RuleVerdict,
    TargetRuleDescriptor,
    TargetRuleRegistration,
    TargetRuleRegistry,
)
from reconcile.progress import (
    EvidenceProgress,
    ProbeProgress,
    ProbeProgressStage,
    ProgressDeliveryError,
    ProgressDispatcher,
    StrategyProgress,
    StrategyProgressStage,
)
from tests.contract._factories import make_envelope, make_target

pytestmark = pytest.mark.unit

NOW = datetime(2026, 8, 13, 12, 0, tzinfo=UTC)
VERSION = "1.0.0"
EFFECT_IDS = ("business-record", "audit-record")


class _Clock:
    def __init__(self) -> None:
        self.seconds = 0.0

    def monotonic(self) -> float:
        return self.seconds

    def now(self) -> datetime:
        return NOW + timedelta(seconds=4 + self.seconds)

    def advance_ms(self, milliseconds: int) -> None:
        self.seconds += milliseconds / 1_000


class _TickingNowClock(_Clock):
    def __init__(self) -> None:
        super().__init__()
        self.now_calls = 0

    def now(self) -> datetime:
        self.now_calls += 1
        return super().now() + timedelta(microseconds=self.now_calls)


class _Handler:
    def __init__(
        self,
        clock: _Clock,
        observations: tuple[ProbeObservation, ...] = (),
        *,
        error: BaseException | None = None,
        call_order: list[str] | None = None,
    ) -> None:
        self.clock = clock
        self.observations = list(observations)
        self.error = error
        self.call_order = call_order
        self.calls: list[BoundProbe] = []

    async def __call__(self, probe: BoundProbe) -> ProbeObservation:
        self.calls.append(probe)
        if self.call_order is not None:
            self.call_order.append(probe.capability_name)
        self.clock.advance_ms(10)
        if self.error is not None:
            raise self.error
        if not self.observations:
            raise RuntimeError("the deterministic test handler has no observation")
        return self.observations.pop(0)


class _Normalizer:
    def __call__(self, rule_input: RuleInput) -> RuleObservation:
        observation = ProbeObservation.model_validate_json(rule_input.observation)
        kind = observation.payload.get("kind")
        record = observation.payload.get("record")
        if kind not in {"committed", "weak"} or not isinstance(record, str):
            raise ValueError("the fixed test observation is malformed")
        authoritative = kind == "committed"
        return RuleObservation(
            target=rule_input.envelope.target,
            source_record=record,
            observed_at=observation.observed_at,
            operation_id=(rule_input.envelope.operation_id if authoritative else None),
            correlation=(
                dict(rule_input.envelope.context.correlation_fields)
                if authoritative
                else {}
            ),
            effect_assertions=tuple(
                EffectAssertion(
                    effect_id=effect_id,
                    state=(
                        EffectAssertionState.ESTABLISHED
                        if authoritative
                        else EffectAssertionState.UNVERIFIED
                    ),
                )
                for effect_id in EFFECT_IDS
            ),
            operation_status=(
                OperationStatus.TERMINAL_COMMITTED if authoritative else None
            ),
            verdict=(
                RuleVerdict.AUTHORITATIVE_EFFECTS
                if authoritative
                else RuleVerdict.SUPPLEMENTARY
            ),
        )


def _observation(kind: str, *, record: str = "record-1") -> ProbeObservation:
    return ProbeObservation(
        observed_at=NOW + timedelta(seconds=3),
        payload={"kind": kind, "record": record},
    )


def _envelope(
    names: tuple[str, ...],
    *,
    max_probes: int = 8,
    max_cost_units: int = 8,
    max_elapsed_ms: int = 5_000,
) -> ExecutionEnvelope:
    payload = json.loads(canonical_json_bytes(make_envelope()))
    payload["context"]["enabled_capabilities"] = [
        {"name": name, "version": VERSION} for name in names
    ]
    payload["context"]["evidence_budget"].update(
        {
            "max_probes": max_probes,
            "max_cost_units": max_cost_units,
            "max_elapsed_ms": max_elapsed_ms,
        }
    )
    return decode_contract(json.dumps(payload), ExecutionEnvelope)


def _capability(name: str) -> ObservationCapability:
    target = make_target()
    return ObservationCapability(
        schema_version=OBSERVATION_CAPABILITY_VERSION,
        name=name,
        version=VERSION,
        read_only=True,
        argument_schema={
            "$schema": "https://json-schema.org/draft/2020-12/schema",
            "type": "object",
            "properties": {
                "order_id": {
                    "type": "string",
                    "minLength": 1,
                    "maxLength": 128,
                }
            },
            "required": ["order_id"],
            "additionalProperties": False,
        },
        allowed_targets=(
            TargetConstraint(
                target_kind=target.target_kind,
                scope=dict(target.scope),
            ),
        ),
        timeout_ms=2_000,
        result_byte_ceiling=65_536,
        cost_units=1,
    )


def _request(name: str, *, rationale: str | None = None) -> ProbeRequest:
    return ProbeRequest(
        schema_version=PROBE_REQUEST_VERSION,
        capability_name=name,
        capability_version=VERSION,
        relevant_effect_ids=EFFECT_IDS,
        arguments={"order_id": "order-7"},
        rationale=rationale or f"Read {name} through the fixed test capability.",
    )


def _registries(
    definitions: dict[str, tuple[_Handler, bool]],
) -> tuple[CapabilityRegistry, TargetRuleRegistry]:
    capabilities = CapabilityRegistry()
    rules = TargetRuleRegistry()
    for name, (handler, include_rule) in definitions.items():
        capabilities.register(
            CapabilityRegistration(
                capability=_capability(name),
                semantics=CapabilitySemantics.READ_ONLY,
                enabled=True,
                argument_byte_ceiling=4_096,
                max_invocations=8,
                handler=handler,
            )
        )
        if include_rule:
            rules.register(
                TargetRuleRegistration(
                    descriptor=TargetRuleDescriptor(
                        target_kind="gcs.object",
                        capability_name=name,
                        capability_version=VERSION,
                        authority_policy_version="authority-gcs-v1",
                        classification_policy_version="classification-v1",
                        source=f"fixed-test-{name}",
                        adapter_version=VERSION,
                    ),
                    normalizer=_Normalizer(),
                )
            )
    return capabilities, rules


def _plan(
    names: tuple[str, ...],
    *,
    required: tuple[bool, ...] | None = None,
    sufficient: tuple[Classification, ...] = (),
    rationales: tuple[str, ...] | None = None,
    name: str = "fixed-test-plan",
) -> FixedProbePlan:
    required = required or tuple(True for _ in names)
    rationales = rationales or tuple(f"Read {item}." for item in names)
    return FixedProbePlan(
        name=name,
        version=VERSION,
        steps=tuple(
            FixedProbeStep(
                request=_request(capability_name, rationale=rationale),
                required=is_required,
            )
            for capability_name, is_required, rationale in zip(
                names,
                required,
                rationales,
                strict=True,
            )
        ),
        sufficient_classifications=sufficient,
    )


def test_early_sufficiency_stops_before_a_later_planned_probe() -> None:
    clock = _Clock()
    authoritative = _Handler(clock, (_observation("committed"),))
    later = _Handler(clock, (_observation("weak", record="later"),))
    capabilities, rules = _registries(
        {
            "authoritative-read": (authoritative, True),
            "later-read": (later, True),
        }
    )
    plan = _plan(
        ("authoritative-read", "later-read"),
        sufficient=(Classification.COMMITTED,),
    )

    result = run_fixed_plan(
        _envelope(("authoritative-read", "later-read")),
        capabilities,
        rules,
        plan,
        clock=clock,
        additional_limitations=("This fixed test uses a local semantic target.",),
    )

    assert result.classification is Classification.COMMITTED
    assert result.stop_reason is FixedBaselineStopReason.SUFFICIENT_EVIDENCE
    assert result.planned_probe_count == 2
    assert result.attempted_probe_count == 1
    assert result.probe_count_used == 1
    assert result.sufficient_probe_sequence == 1
    assert result.time_to_sufficient_evidence_ms == 10
    assert result.total_elapsed_ms == 10
    assert authoritative.calls
    assert later.calls == []
    assert result.model_invocation_count == 0
    assert result.report.limitations[-1] == (
        "This fixed test uses a local semantic target."
    )


def test_weak_only_plan_exhausts_in_order_and_preserves_unknown() -> None:
    clock = _Clock()
    order: list[str] = []
    first = _Handler(
        clock,
        (_observation("weak", record="weak-a"),),
        call_order=order,
    )
    second = _Handler(
        clock,
        (_observation("weak", record="weak-b"),),
        call_order=order,
    )
    capabilities, rules = _registries(
        {"weak-b": (second, True), "weak-a": (first, True)}
    )
    plan = _plan(
        ("weak-a", "weak-b"),
        sufficient=(Classification.COMMITTED,),
    )

    result = run_fixed_plan(
        _envelope(("weak-a", "weak-b")),
        capabilities,
        rules,
        plan,
        clock=clock,
    )

    assert order == ["weak-a", "weak-b"]
    assert result.classification is Classification.UNKNOWN
    assert result.stop_reason is FixedBaselineStopReason.PLAN_EXHAUSTED
    assert result.attempted_probe_count == 2
    assert result.sufficient_probe_sequence is None
    assert result.time_to_sufficient_evidence_ms is None
    gates = {gate.requested_action: gate for gate in result.report.action_gate}
    assert gates[RequestedAction.RETRY].allowed is False
    assert gates[RequestedAction.COMPENSATE].allowed is False


def test_required_unavailable_stops_but_optional_unavailable_can_continue() -> None:
    required_clock = _Clock()
    required_handler = _Handler(required_clock, error=CapabilityUnavailable())
    unused = _Handler(required_clock, (_observation("committed"),))
    required_capabilities, required_rules = _registries(
        {
            "unavailable-read": (required_handler, True),
            "authoritative-read": (unused, True),
        }
    )

    required_result = run_fixed_plan(
        _envelope(("unavailable-read", "authoritative-read")),
        required_capabilities,
        required_rules,
        _plan(
            ("unavailable-read", "authoritative-read"),
            sufficient=(Classification.COMMITTED,),
        ),
        clock=required_clock,
    )

    assert required_result.classification is Classification.UNKNOWN
    assert (
        required_result.stop_reason
        is FixedBaselineStopReason.REQUIRED_CAPABILITY_UNAVAILABLE
    )
    assert required_result.unavailable_probe_count == 1
    assert required_result.attempted_probe_count == 1
    assert unused.calls == []

    optional_clock = _Clock()
    optional_handler = _Handler(optional_clock, error=CapabilityUnavailable())
    authoritative = _Handler(optional_clock, (_observation("committed"),))
    optional_capabilities, optional_rules = _registries(
        {
            "unavailable-read": (optional_handler, True),
            "authoritative-read": (authoritative, True),
        }
    )

    optional_result = run_fixed_plan(
        _envelope(("unavailable-read", "authoritative-read")),
        optional_capabilities,
        optional_rules,
        _plan(
            ("unavailable-read", "authoritative-read"),
            required=(False, True),
            sufficient=(Classification.COMMITTED,),
        ),
        clock=optional_clock,
    )

    assert optional_result.classification is Classification.COMMITTED
    assert optional_result.stop_reason is FixedBaselineStopReason.SUFFICIENT_EVIDENCE
    assert optional_result.unavailable_probe_count == 1
    assert optional_result.attempted_probe_count == 2


def test_controller_budget_stops_without_executing_a_second_handler() -> None:
    clock = _Clock()
    first = _Handler(clock, (_observation("weak", record="first"),))
    second = _Handler(clock, (_observation("weak", record="second"),))
    capabilities, rules = _registries(
        {"first-read": (first, True), "second-read": (second, True)}
    )

    result = run_fixed_plan(
        _envelope(("first-read", "second-read"), max_probes=1),
        capabilities,
        rules,
        _plan(("first-read", "second-read")),
        clock=clock,
    )

    assert result.stop_reason is FixedBaselineStopReason.BUDGET_EXHAUSTED
    assert result.classification is Classification.UNKNOWN
    assert result.attempted_probe_count == 2
    assert result.probe_count_used == 1
    assert len(first.calls) == 1
    assert second.calls == []


def test_controller_deadline_is_an_explicit_terminal_stop() -> None:
    clock = _Clock()
    handler = _Handler(clock, (_observation("committed"),))
    capabilities, rules = _registries({"slow-read": (handler, True)})

    result = run_fixed_plan(
        _envelope(("slow-read",), max_elapsed_ms=5),
        capabilities,
        rules,
        _plan(("slow-read",), sufficient=(Classification.COMMITTED,)),
        clock=clock,
    )

    assert result.stop_reason is FixedBaselineStopReason.DEADLINE_EXHAUSTED
    assert result.classification is Classification.UNKNOWN
    assert result.probe_count_used == 1
    assert len(handler.calls) == 1


def test_repeated_request_with_unchanged_proof_stops_as_non_progress() -> None:
    clock = _Clock()
    repeated = _Handler(
        clock,
        (
            _observation("weak", record="same"),
            _observation("weak", record="same"),
        ),
    )
    capabilities, rules = _registries({"weak-read": (repeated, True)})

    result = run_fixed_plan(
        _envelope(("weak-read",)),
        capabilities,
        rules,
        _plan(("weak-read", "weak-read")),
        clock=clock,
    )

    assert result.stop_reason is FixedBaselineStopReason.NON_PROGRESS
    assert result.classification is Classification.UNKNOWN
    assert result.attempted_probe_count == 2
    assert result.redundant_probe_count == 1
    assert result.duplicate_probe_count == 1
    assert len(repeated.calls) == 2
    assert any(
        decision.reason.value == "duplicate_candidates"
        for decision in result.report.evidence_decisions
    )


def test_repeated_request_with_changed_proof_is_not_redundant() -> None:
    clock = _Clock()
    repeated = _Handler(
        clock,
        (
            _observation("weak", record="first-weak-read"),
            _observation("committed", record="later-authoritative-read"),
        ),
    )
    capabilities, rules = _registries({"read": (repeated, True)})

    result = run_fixed_plan(
        _envelope(("read",)),
        capabilities,
        rules,
        _plan(
            ("read", "read"),
            sufficient=(Classification.COMMITTED,),
        ),
        clock=clock,
    )

    assert result.stop_reason is FixedBaselineStopReason.SUFFICIENT_EVIDENCE
    assert result.classification is Classification.COMMITTED
    assert result.attempted_probe_count == 2
    assert result.duplicate_probe_count == 1
    assert result.redundant_probe_count == 0
    assert len(repeated.calls) == 2


def test_missing_target_rule_is_counted_as_unsupported_and_fails_required_step() -> (
    None
):
    clock = _Clock()
    handler = _Handler(clock, (_observation("weak"),))
    capabilities, rules = _registries({"unsupported-read": (handler, False)})

    result = run_fixed_plan(
        _envelope(("unsupported-read",)),
        capabilities,
        rules,
        _plan(("unsupported-read",)),
        clock=clock,
    )

    assert result.stop_reason is FixedBaselineStopReason.REQUIRED_PROBE_FAILED
    assert result.unsupported_probe_count == 1
    assert result.classification is Classification.UNKNOWN


def test_pre_requested_cancellation_is_reported_without_handler_dispatch() -> None:
    async def execute(progress_emitter=None):
        clock = _Clock()
        handler = _Handler(clock, (_observation("committed"),))
        capabilities, rules = _registries({"read": (handler, True)})
        cancellation = asyncio.Event()
        cancellation.set()
        result = await execute_fixed_plan(
            _envelope(("read",)),
            capabilities,
            rules,
            _plan(("read",), sufficient=(Classification.COMMITTED,)),
            clock=clock,
            cancellation_event=cancellation,
            progress_emitter=progress_emitter,
        )
        return result, handler

    async def scenario() -> None:
        baseline, _ = await execute()
        observed = []
        result, handler = await execute(observed.append)

        assert result.stop_reason is FixedBaselineStopReason.CANCELLED
        assert result.classification is Classification.UNKNOWN
        assert result.probe_count_used == 0
        assert handler.calls == []
        assert canonical_json_bytes(result.report) == canonical_json_bytes(
            baseline.report
        )
        completed = next(
            event
            for event in observed
            if type(event) is ProbeProgress
            and event.stage is ProbeProgressStage.COMPLETED
        )
        assert completed.outcome is ProbeOutcome.CANCELLED
        assert completed.capability_name is None
        assert completed.capability_version is None
        assert completed.request_sha256 is None

    asyncio.run(scenario())


def test_budget_terminal_progress_is_observational_only() -> None:
    async def execute(progress_emitter=None):
        clock = _Clock()
        first = _Handler(clock, (_observation("weak", record="first"),))
        second = _Handler(clock, (_observation("weak", record="second"),))
        capabilities, rules = _registries(
            {"first-read": (first, True), "second-read": (second, True)}
        )
        result = await execute_fixed_plan(
            _envelope(("first-read", "second-read"), max_probes=1),
            capabilities,
            rules,
            _plan(("first-read", "second-read")),
            clock=clock,
            progress_emitter=progress_emitter,
        )
        return result, first, second

    async def scenario() -> None:
        baseline, _, _ = await execute()
        observed = []
        result, first, second = await execute(observed.append)

        assert result.stop_reason is FixedBaselineStopReason.BUDGET_EXHAUSTED
        assert result.classification is Classification.UNKNOWN
        assert len(first.calls) == 1
        assert second.calls == []
        assert canonical_json_bytes(result.report) == canonical_json_bytes(
            baseline.report
        )
        completed = [
            event
            for event in observed
            if type(event) is ProbeProgress
            and event.stage is ProbeProgressStage.COMPLETED
        ][-1]
        assert completed.outcome is ProbeOutcome.BUDGET_EXHAUSTED
        assert completed.capability_name is None
        assert completed.capability_version is None
        assert completed.request_sha256 is None

    asyncio.run(scenario())


def test_identical_admitted_evidence_has_identical_classification_and_gates() -> None:
    def run(rationale: str, plan_name: str):
        clock = _Clock()
        handler = _Handler(clock, (_observation("committed"),))
        capabilities, rules = _registries({"authoritative-read": (handler, True)})
        return run_fixed_plan(
            _envelope(("authoritative-read",)),
            capabilities,
            rules,
            _plan(
                ("authoritative-read",),
                rationales=(rationale,),
                sufficient=(Classification.COMMITTED,),
                name=plan_name,
            ),
            clock=clock,
        )

    first = run("Read the fixed target.", "fixed-plan-a")
    second = run("Different advisory wording.", "fixed-plan-b")

    assert canonical_json_bytes(first.report.evidence[0]) == canonical_json_bytes(
        second.report.evidence[0]
    )
    assert first.classification is second.classification is Classification.COMMITTED
    assert first.report.proof == second.report.proof
    assert first.report.action_gate == second.report.action_gate


def test_plan_is_immutable_and_unknown_cannot_be_a_sufficient_state() -> None:
    request = _request("read")
    step = FixedProbeStep(request=request)
    plan = FixedProbePlan(
        name="fixed-plan",
        version=VERSION,
        steps=(step,),
        sufficient_classifications=(Classification.COMMITTED,),
    )
    original_sha = plan.sha256
    request.arguments["order_id"] = "mutated-after-plan"

    assert plan.steps[0].request.arguments["order_id"] == "order-7"
    assert plan.sha256 == original_sha
    with pytest.raises(ValueError, match="UNKNOWN cannot be declared sufficient"):
        FixedProbePlan(
            name="invalid-plan",
            version=VERSION,
            steps=(step,),
            sufficient_classifications=(Classification.UNKNOWN,),
        )


def test_progress_is_ordered_sanitized_and_cannot_control_fixed_execution() -> None:
    async def execute(progress_emitter=None):
        clock = _TickingNowClock()
        handler = _Handler(clock, (_observation("committed"),))
        capabilities, rules = _registries({"authoritative-read": (handler, True)})
        result = await execute_fixed_plan(
            _envelope(("authoritative-read",)),
            capabilities,
            rules,
            _plan(
                ("authoritative-read",),
                rationales=("Private rationale must not become progress.",),
                sufficient=(Classification.COMMITTED,),
            ),
            clock=clock,
            progress_emitter=progress_emitter,
        )
        return result, handler, clock

    async def scenario() -> None:
        baseline, _, baseline_clock = await execute()
        release = asyncio.Event()
        observed = []

        async def slow_callback(event) -> None:
            observed.append(event)
            if len(observed) == 1:
                await release.wait()

        dispatcher = ProgressDispatcher(slow_callback, flush_timeout_seconds=0.5)
        instrumented, handler, instrumented_clock = await asyncio.wait_for(
            execute(dispatcher.emit),
            timeout=0.2,
        )
        assert instrumented.classification is Classification.COMMITTED
        assert len(handler.calls) == 1
        release.set()
        await dispatcher.finish()

        assert canonical_json_bytes(instrumented.report) == canonical_json_bytes(
            baseline.report
        )
        assert instrumented_clock.now_calls == baseline_clock.now_calls
        assert [type(event) for event in observed] == [
            StrategyProgress,
            ProbeProgress,
            ProbeProgress,
            EvidenceProgress,
            StrategyProgress,
        ]
        assert observed[0].stage is StrategyProgressStage.STARTED
        assert observed[1].stage is ProbeProgressStage.REQUESTED
        assert observed[2].stage is ProbeProgressStage.COMPLETED
        assert observed[-1].stage is StrategyProgressStage.COMPLETED
        assert observed[2].evidence_ids == (observed[3].evidence_id,)
        serialized = json.dumps(
            [event.model_dump(mode="json") for event in observed],
            sort_keys=True,
        )
        for private_value in (
            "order-7",
            "demo-project",
            "demo-bucket",
            "receipts/order-7.json",
            "Private rationale",
        ):
            assert private_value not in serialized

        async def failing_callback(_event) -> None:
            raise RuntimeError("private callback failure detail")

        failed_dispatcher = ProgressDispatcher(failing_callback)
        completed, failed_handler, _ = await execute(failed_dispatcher.emit)
        assert completed.classification is Classification.COMMITTED
        assert len(failed_handler.calls) == 1
        with pytest.raises(
            ProgressDeliveryError,
            match="investigation progress delivery failed",
        ) as captured:
            await failed_dispatcher.finish()
        assert captured.value.__cause__ is None
        assert "private callback failure detail" not in str(captured.value)

    asyncio.run(scenario())
