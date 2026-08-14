"""Fail-closed execution behavior for one bounded probe investigation."""

from __future__ import annotations

import asyncio
import gzip
import hashlib
import json
from copy import deepcopy
from datetime import UTC, datetime, timedelta

import pytest

from reconcile.contracts import (
    OBSERVATION_CAPABILITY_VERSION,
    PROBE_REQUEST_VERSION,
    ExecutionEnvelope,
    ObservationCapability,
    ProbeRequest,
    TargetConstraint,
    canonical_json_bytes,
    decode_contract,
)
from reconcile.contracts.report import ProbeOutcome
from reconcile.controller.capabilities import (
    BoundProbe,
    CapabilityRegistration,
    CapabilityRegistry,
    CapabilitySemantics,
    CapabilityUnavailable,
    ProbeObservation,
)
from reconcile.controller.executor import (
    ProbeController,
    ProbeStopReason,
)
from tests.contract._factories import make_capability, make_envelope

pytestmark = pytest.mark.unit

NOW = datetime(2026, 8, 13, 12, 0, tzinfo=UTC)


class FakeClock:
    def __init__(self) -> None:
        self.seconds = 0.0

    def monotonic(self) -> float:
        return self.seconds

    def now(self) -> datetime:
        return NOW + timedelta(seconds=self.seconds)

    def advance_ms(self, milliseconds: int) -> None:
        self.seconds += milliseconds / 1000


class RegressingWallClock:
    def __init__(self) -> None:
        self.wall_reads = 0

    def monotonic(self) -> float:
        return 0.0

    def now(self) -> datetime:
        self.wall_reads += 1
        return NOW if self.wall_reads == 1 else NOW - timedelta(seconds=1)


class ScriptedMonotonicClock:
    def __init__(self, *values: float) -> None:
        self.values = list(values)
        self.last = values[-1]

    def monotonic(self) -> float:
        if self.values:
            self.last = self.values.pop(0)
        return self.last

    def now(self) -> datetime:
        return NOW


class SpyHandler:
    def __init__(
        self,
        observation: ProbeObservation | object | None = None,
        *,
        error: BaseException | None = None,
    ) -> None:
        self.observation = observation or _observation()
        self.error = error
        self.calls: list[BoundProbe] = []

    async def __call__(self, probe: BoundProbe) -> ProbeObservation:
        self.calls.append(probe)
        if self.error is not None:
            raise self.error
        return self.observation  # type: ignore[return-value]


class BlockingHandler:
    def __init__(self) -> None:
        self.calls: list[BoundProbe] = []
        self.started = asyncio.Event()
        self.release = asyncio.Event()
        self.cancelled = asyncio.Event()
        self.active = 0
        self.max_active = 0

    async def __call__(self, probe: BoundProbe) -> ProbeObservation:
        self.calls.append(probe)
        self.active += 1
        self.max_active = max(self.max_active, self.active)
        self.started.set()
        try:
            await self.release.wait()
            return _observation(order_id=probe.arguments["order_id"])
        except asyncio.CancelledError:
            self.cancelled.set()
            raise
        finally:
            self.active -= 1


class ClockAdvancingHandler(SpyHandler):
    def __init__(self, clock: FakeClock, milliseconds: int) -> None:
        super().__init__()
        self.clock = clock
        self.milliseconds = milliseconds

    async def __call__(self, probe: BoundProbe) -> ProbeObservation:
        self.calls.append(probe)
        self.clock.advance_ms(self.milliseconds)
        return self.observation  # type: ignore[return-value]


class CancellationSuppressingHandler:
    def __init__(self) -> None:
        self.calls: list[BoundProbe] = []
        self.started = asyncio.Event()
        self.release = asyncio.Event()
        self.active = 0
        self.max_active = 0

    async def __call__(self, probe: BoundProbe) -> ProbeObservation:
        self.calls.append(probe)
        self.active += 1
        self.max_active = max(self.max_active, self.active)
        self.started.set()
        try:
            try:
                await asyncio.Future()
            except asyncio.CancelledError:
                await self.release.wait()
            return _observation()
        finally:
            self.active -= 1


def _observation(
    *,
    order_id: object = "order-7",
    padding: str = "",
) -> ProbeObservation:
    return ProbeObservation(
        observed_at=NOW,
        payload={"exists": True, "order_id": order_id, "padding": padding},
    )


def _closed_capability(
    *,
    name: str = "gcs-object-readback",
    version: str = "1.0.0",
    target_kind: str = "gcs.object",
    target_scope: dict[str, object] | None = None,
    timeout_ms: int = 2_000,
    result_byte_ceiling: int = 65_536,
    cost_units: int = 1,
    max_argument_length: int = 512,
    argument_schema: dict[str, object] | None = None,
) -> ObservationCapability:
    base = make_capability()
    schema = (
        deepcopy(base.argument_schema)
        if argument_schema is None
        else deepcopy(argument_schema)
    )
    if argument_schema is None:
        schema["properties"]["order_id"]["maxLength"] = max_argument_length  # type: ignore[index]
    scope = target_scope or dict(base.allowed_targets[0].scope)
    return ObservationCapability(
        schema_version=OBSERVATION_CAPABILITY_VERSION,
        name=name,
        version=version,
        read_only=True,
        argument_schema=schema,
        allowed_targets=(TargetConstraint(target_kind=target_kind, scope=scope),),
        timeout_ms=timeout_ms,
        result_byte_ceiling=result_byte_ceiling,
        cost_units=cost_units,
    )


def _envelope(
    *,
    max_probes: int = 8,
    max_elapsed_ms: int = 10_000,
    max_total_result_bytes: int = 1_000_000,
    max_cost_units: int = 8,
    enabled: tuple[tuple[str, str], ...] = (("gcs-object-readback", "1.0.0"),),
    target_scope: dict[str, object] | None = None,
) -> ExecutionEnvelope:
    payload = json.loads(canonical_json_bytes(make_envelope()))
    if target_scope is not None:
        payload["target"]["scope"] = target_scope
    payload["context"]["enabled_capabilities"] = [
        {"name": name, "version": version} for name, version in enabled
    ]
    payload["context"]["evidence_budget"] = {
        "max_probes": max_probes,
        "max_elapsed_ms": max_elapsed_ms,
        "max_total_result_bytes": max_total_result_bytes,
        "max_cost_units": max_cost_units,
    }
    return decode_contract(json.dumps(payload), ExecutionEnvelope)


def _request(
    *,
    name: str = "gcs-object-readback",
    version: str = "1.0.0",
    order_id: object = "order-7",
    effect_ids: tuple[str, ...] = ("business-record",),
    rationale: str = "Read the fixed target.",
    extra_arguments: dict[str, object] | None = None,
    arguments: dict[str, object] | None = None,
) -> ProbeRequest:
    request_arguments = {"order_id": order_id} if arguments is None else arguments
    if extra_arguments:
        request_arguments.update(extra_arguments)
    return ProbeRequest(
        schema_version=PROBE_REQUEST_VERSION,
        capability_name=name,
        capability_version=version,
        relevant_effect_ids=effect_ids,
        arguments=request_arguments,
        rationale=rationale,
    )


def _registry(
    handler: object,
    *,
    capability: ObservationCapability | None = None,
    semantics: CapabilitySemantics = CapabilitySemantics.READ_ONLY,
    enabled: bool = True,
    argument_byte_ceiling: int = 4_096,
    max_invocations: int = 8,
) -> CapabilityRegistry:
    registry = CapabilityRegistry()
    executable_handler = (
        handler if enabled and semantics is CapabilitySemantics.READ_ONLY else None
    )
    registry.register(
        CapabilityRegistration(
            capability=capability or _closed_capability(),
            semantics=semantics,
            enabled=enabled,
            argument_byte_ceiling=argument_byte_ceiling,
            max_invocations=max_invocations,
            handler=executable_handler,  # type: ignore[arg-type]
        )
    )
    return registry


def test_success_binds_only_the_snapshotted_target_and_emits_digest_audit() -> None:
    async def scenario() -> None:
        envelope = _envelope()
        handler = SpyHandler()
        controller = ProbeController(envelope, _registry(handler))
        envelope.target.scope["project_id"] = "mutated-after-snapshot"
        request = _request(rationale="PASSWORD=must-not-enter-audit")

        execution = await controller.execute(request)

        assert execution.audit.outcome is ProbeOutcome.COMPLETED
        assert execution.audit.stop_reason is ProbeStopReason.PROBE_COMPLETED
        assert execution.observation is not None
        assert (
            execution.observation.sha256
            == hashlib.sha256(execution.observation.canonical_json).hexdigest()
        )
        assert len(handler.calls) == 1
        assert handler.calls[0].target.scope["project_id"] == "demo-project"
        assert not hasattr(handler.calls[0], "rationale")
        audit_json = json.dumps(execution.audit.model_dump(mode="json"))
        assert "PASSWORD" not in audit_json
        assert "order-7" not in audit_json
        assert "padding" not in audit_json

    asyncio.run(scenario())


@pytest.mark.parametrize(
    ("name", "version"),
    (
        ("GCS-object-readback", "1.0.0"),
        ("gcs-object-readback", "1.0"),
        ("gcs-object-readback-substitute", "1.0.0"),
    ),
)
def test_tool_name_or_version_substitution_is_rejected_before_transport(
    name: str,
    version: str,
) -> None:
    async def scenario() -> None:
        handler = SpyHandler()
        controller = ProbeController(_envelope(), _registry(handler))

        execution = await controller.execute(_request(name=name, version=version))

        assert execution.audit.stop_reason is ProbeStopReason.UNKNOWN_CAPABILITY
        assert handler.calls == []

    asyncio.run(scenario())


def test_unknown_model_authored_identity_is_hashed_not_copied_into_audit() -> None:
    async def scenario() -> None:
        handler = SpyHandler()
        controller = ProbeController(_envelope(), _registry(handler))

        execution = await controller.execute(
            _request(name="PASSWORD-must-not-enter-audit")
        )

        audit_json = json.dumps(execution.audit.model_dump(mode="json"))
        assert execution.audit.stop_reason is ProbeStopReason.UNKNOWN_CAPABILITY
        assert execution.audit.capability_name is None
        assert execution.audit.capability_version is None
        assert execution.audit.request_sha256 is not None
        assert "PASSWORD" not in audit_json
        assert handler.calls == []

    asyncio.run(scenario())


def test_registered_but_investigation_disabled_capability_is_rejected() -> None:
    async def scenario() -> None:
        handler = SpyHandler()
        capability = _closed_capability(name="other-read")
        controller = ProbeController(
            _envelope(), _registry(handler, capability=capability)
        )

        execution = await controller.execute(_request(name="other-read"))

        assert execution.audit.stop_reason is ProbeStopReason.CAPABILITY_NOT_ENABLED
        assert handler.calls == []

    asyncio.run(scenario())


@pytest.mark.parametrize(
    ("semantics", "enabled", "reason"),
    (
        (
            CapabilitySemantics.READ_ONLY,
            False,
            ProbeStopReason.CAPABILITY_DISABLED,
        ),
        (
            CapabilitySemantics.MUTATING,
            True,
            ProbeStopReason.CAPABILITY_MUTATING,
        ),
        (
            CapabilitySemantics.AMBIGUOUS,
            True,
            ProbeStopReason.CAPABILITY_SEMANTICS_AMBIGUOUS,
        ),
    ),
)
def test_non_executable_semantics_never_store_or_invoke_a_handler(
    semantics: CapabilitySemantics,
    enabled: bool,
    reason: ProbeStopReason,
) -> None:
    async def scenario() -> None:
        controller = ProbeController(
            _envelope(),
            _registry(SpyHandler(), semantics=semantics, enabled=enabled),
        )

        execution = await controller.execute(_request())

        assert execution.audit.stop_reason is reason
        assert execution.audit.outcome is ProbeOutcome.REJECTED

    asyncio.run(scenario())


@pytest.mark.parametrize(
    ("capability", "reason"),
    (
        (
            _closed_capability(target_kind="firestore.document"),
            ProbeStopReason.TARGET_KIND_MISMATCH,
        ),
        (
            _closed_capability(
                target_scope={"project_id": "other", "bucket_name": "demo-bucket"}
            ),
            ProbeStopReason.TARGET_SCOPE_MISMATCH,
        ),
    ),
)
def test_target_kind_and_exact_scope_must_match_the_envelope(
    capability: ObservationCapability,
    reason: ProbeStopReason,
) -> None:
    async def scenario() -> None:
        handler = SpyHandler()
        controller = ProbeController(
            _envelope(),
            _registry(handler, capability=capability),
        )

        execution = await controller.execute(_request())

        assert execution.audit.stop_reason is reason
        assert handler.calls == []

    asyncio.run(scenario())


@pytest.mark.parametrize("colliding_value", (True, 1.0))
def test_target_scope_uses_canonical_json_not_python_numeric_equality(
    colliding_value: object,
) -> None:
    async def scenario() -> None:
        handler = SpyHandler()
        capability = _closed_capability(target_scope={"slot": 1})
        controller = ProbeController(
            _envelope(target_scope={"slot": colliding_value}),
            _registry(handler, capability=capability),
        )

        execution = await controller.execute(_request())

        assert execution.audit.stop_reason is ProbeStopReason.TARGET_SCOPE_MISMATCH
        assert handler.calls == []

    asyncio.run(scenario())


@pytest.mark.parametrize(
    ("probe_request", "reason"),
    (
        (
            _request(effect_ids=("unknown-effect",)),
            ProbeStopReason.INVALID_EFFECT_REFERENCE,
        ),
        (_request(order_id=7), ProbeStopReason.INVALID_ARGUMENTS),
        (
            _request(extra_arguments={"unexpected": "value"}),
            ProbeStopReason.INVALID_ARGUMENTS,
        ),
        (
            _request(order_id="https://other.example/resource"),
            ProbeStopReason.TARGET_PARAMETER_INJECTION,
        ),
        (
            _request(order_id="projects/other/buckets/redirected"),
            ProbeStopReason.TARGET_PARAMETER_INJECTION,
        ),
        (
            _request(order_id="order-8"),
            ProbeStopReason.CORRELATION_MISMATCH,
        ),
    ),
)
def test_effect_schema_and_value_injection_fail_before_transport(
    probe_request: ProbeRequest,
    reason: ProbeStopReason,
) -> None:
    async def scenario() -> None:
        handler = SpyHandler()
        controller = ProbeController(_envelope(), _registry(handler))

        execution = await controller.execute(probe_request)

        assert execution.audit.stop_reason is reason
        assert handler.calls == []

    asyncio.run(scenario())


@pytest.mark.parametrize(
    ("value", "admitted"),
    ((1, True), (1.0, False), (True, False), ("1", False)),
)
def test_integer_argument_schema_does_not_coerce_json_values(
    value: object,
    admitted: bool,
) -> None:
    async def scenario() -> None:
        schema = {
            "$schema": "https://json-schema.org/draft/2020-12/schema",
            "type": "object",
            "properties": {"attempt": {"type": "integer", "minimum": 0, "maximum": 3}},
            "required": ["attempt"],
            "additionalProperties": False,
        }
        handler = SpyHandler()
        controller = ProbeController(
            _envelope(),
            _registry(handler, capability=_closed_capability(argument_schema=schema)),
        )

        execution = await controller.execute(_request(arguments={"attempt": value}))

        assert (execution.audit.outcome is ProbeOutcome.COMPLETED) is admitted
        assert len(handler.calls) == int(admitted)
        if not admitted:
            assert execution.audit.stop_reason is ProbeStopReason.INVALID_ARGUMENTS

    asyncio.run(scenario())


def test_oversized_arguments_and_post_validation_mutation_fail_closed() -> None:
    async def scenario() -> None:
        oversized_handler = SpyHandler()
        oversized = ProbeController(
            _envelope(),
            _registry(
                oversized_handler,
                capability=_closed_capability(max_argument_length=24),
                argument_byte_ceiling=24,
            ),
        )
        too_large = await oversized.execute(_request(order_id="x" * 24))
        assert too_large.audit.stop_reason is ProbeStopReason.ARGUMENTS_TOO_LARGE
        assert oversized_handler.calls == []

        mutated_handler = SpyHandler()
        mutated = ProbeController(_envelope(), _registry(mutated_handler))
        request = _request()
        request.arguments["project_id"] = "redirected"
        invalid = await mutated.execute(request)
        assert invalid.audit.stop_reason is ProbeStopReason.INVALID_REQUEST
        assert mutated_handler.calls == []

    asyncio.run(scenario())


def test_repeated_reads_consume_every_budget_without_hidden_mutation_retry() -> None:
    async def scenario() -> None:
        handler = SpyHandler()
        controller = ProbeController(
            _envelope(max_probes=3, max_cost_units=2),
            _registry(handler, max_invocations=2),
        )
        request = _request()

        first = await controller.execute(request)
        second = await controller.execute(
            _request(rationale="Changing model prose cannot bypass identity.")
        )
        third = await controller.execute(request)

        assert first.audit.outcome is ProbeOutcome.COMPLETED
        assert second.audit.outcome is ProbeOutcome.COMPLETED
        assert second.audit.probe_count_used == 2
        assert second.audit.cost_units_used == 2
        assert (
            third.audit.stop_reason is ProbeStopReason.CAPABILITY_PROBE_LIMIT_EXHAUSTED
        )
        assert third.audit.probe_count_used == 3
        assert third.audit.cost_units_used == 2
        assert len(handler.calls) == 2

    asyncio.run(scenario())


def test_probe_count_elapsed_cost_and_capability_budgets_are_independent() -> None:
    async def scenario() -> None:
        count_handler = SpyHandler()
        count_controller = ProbeController(
            _envelope(max_probes=1),
            _registry(count_handler),
        )
        await count_controller.execute(_request(name="unknown"))
        count = await count_controller.execute(_request())
        repeated_terminal = await count_controller.execute(_request())
        assert count.audit.stop_reason is ProbeStopReason.PROBE_COUNT_EXHAUSTED
        assert repeated_terminal is count
        assert len(count_controller.audit_trail) == 2
        assert count_handler.calls == []

        clock = FakeClock()
        elapsed_handler = SpyHandler()
        elapsed_controller = ProbeController(
            _envelope(max_elapsed_ms=5),
            _registry(elapsed_handler),
            clock=clock,
        )
        clock.advance_ms(6)
        elapsed = await elapsed_controller.execute(_request())
        assert elapsed.audit.stop_reason is ProbeStopReason.ELAPSED_BUDGET_EXHAUSTED
        assert elapsed_handler.calls == []

        cost_handler = SpyHandler()
        cost_controller = ProbeController(
            _envelope(max_cost_units=1),
            _registry(
                cost_handler,
                capability=_closed_capability(cost_units=2),
            ),
        )
        cost = await cost_controller.execute(_request())
        assert cost.audit.stop_reason is ProbeStopReason.COST_BUDGET_EXHAUSTED
        assert cost_handler.calls == []

        limit_handler = SpyHandler()
        limit_controller = ProbeController(
            _envelope(),
            _registry(limit_handler, max_invocations=1),
        )
        assert (await limit_controller.execute(_request())).observation is not None
        limited = await limit_controller.execute(_request())
        assert (
            limited.audit.stop_reason
            is ProbeStopReason.CAPABILITY_PROBE_LIMIT_EXHAUSTED
        )
        assert len(limit_handler.calls) == 1

    asyncio.run(scenario())


def test_per_result_and_total_byte_limits_are_independent_and_discard_output() -> None:
    async def scenario() -> None:
        observation = _observation(padding="bounded")
        byte_count = len(canonical_json_bytes(observation))

        exact_handler = SpyHandler(observation)
        exact = ProbeController(
            _envelope(max_total_result_bytes=byte_count),
            _registry(
                exact_handler,
                capability=_closed_capability(result_byte_ceiling=byte_count),
            ),
        )
        assert (await exact.execute(_request())).observation is not None

        tool_handler = SpyHandler(observation)
        tool = ProbeController(
            _envelope(max_total_result_bytes=byte_count * 2),
            _registry(
                tool_handler,
                capability=_closed_capability(result_byte_ceiling=byte_count - 1),
            ),
        )
        too_large = await tool.execute(_request())
        assert too_large.audit.stop_reason is ProbeStopReason.RESULT_TOO_LARGE
        assert too_large.observation is None
        assert too_large.audit.result_bytes_acquired == byte_count

        total_handler = SpyHandler(observation)
        total = ProbeController(
            _envelope(max_total_result_bytes=byte_count - 1),
            _registry(
                total_handler,
                capability=_closed_capability(result_byte_ceiling=byte_count),
            ),
        )
        exhausted = await total.execute(_request())
        assert (
            exhausted.audit.stop_reason is ProbeStopReason.TOTAL_RESULT_BYTES_EXHAUSTED
        )
        assert exhausted.observation is None
        assert exhausted.audit.result_bytes_acquired == byte_count

    asyncio.run(scenario())


def test_concurrent_submissions_cannot_overshoot_a_single_probe_budget() -> None:
    async def scenario() -> None:
        handler = BlockingHandler()
        controller = ProbeController(
            _envelope(max_probes=1),
            _registry(handler),
        )
        first_task = asyncio.create_task(controller.execute(_request()))
        await handler.started.wait()
        second_task = asyncio.create_task(controller.execute(_request()))
        handler.release.set()

        first, second = await asyncio.gather(first_task, second_task)

        assert first.audit.outcome is ProbeOutcome.COMPLETED
        assert second.audit.stop_reason is ProbeStopReason.PROBE_COUNT_EXHAUSTED
        assert handler.max_active == 1
        assert len(handler.calls) == 1
        assert [record.sequence for record in controller.audit_trail] == [1, 2]

    asyncio.run(scenario())


def test_tool_timeout_and_shorter_investigation_deadline_have_distinct_reasons() -> (
    None
):
    async def scenario() -> None:
        tool_handler = BlockingHandler()
        tool = ProbeController(
            _envelope(max_elapsed_ms=1_000),
            _registry(
                tool_handler,
                capability=_closed_capability(timeout_ms=50),
            ),
        )
        timed_out = await tool.execute(_request())
        assert timed_out.audit.outcome is ProbeOutcome.TIMED_OUT
        assert timed_out.audit.stop_reason is ProbeStopReason.PROBE_TIMEOUT
        assert len(tool_handler.calls) == 1
        await asyncio.sleep(0)
        assert tool_handler.cancelled.is_set()

        elapsed_clock = FakeClock()
        elapsed_handler = BlockingHandler()
        elapsed = ProbeController(
            _envelope(max_elapsed_ms=1_000),
            _registry(
                elapsed_handler,
                capability=_closed_capability(timeout_ms=1_000),
            ),
            clock=elapsed_clock,
        )
        elapsed_clock.advance_ms(990)
        deadline = await elapsed.execute(_request())
        assert deadline.audit.outcome is ProbeOutcome.BUDGET_EXHAUSTED
        assert deadline.audit.stop_reason is ProbeStopReason.ELAPSED_BUDGET_EXHAUSTED
        assert len(elapsed_handler.calls) == 1

    asyncio.run(scenario())


def test_elapsed_deadline_is_rechecked_before_admitting_observation() -> None:
    async def scenario() -> None:
        clock = FakeClock()
        handler = ClockAdvancingHandler(clock, milliseconds=100)
        controller = ProbeController(
            _envelope(max_elapsed_ms=50),
            _registry(
                handler,
                capability=_closed_capability(timeout_ms=1_000),
            ),
            clock=clock,
        )

        execution = await controller.execute(_request())

        assert execution.audit.outcome is ProbeOutcome.BUDGET_EXHAUSTED
        assert execution.audit.stop_reason is ProbeStopReason.ELAPSED_BUDGET_EXHAUSTED
        assert execution.observation is None
        assert handler.calls[0].timeout_ms == 50

    asyncio.run(scenario())


def test_elapsed_deadline_crossing_during_binding_stops_before_transport() -> None:
    async def scenario() -> None:
        clock = ScriptedMonotonicClock(0.0, 0.0, 0.049, 0.051)
        handler = SpyHandler()
        controller = ProbeController(
            _envelope(max_elapsed_ms=50),
            _registry(
                handler,
                capability=_closed_capability(timeout_ms=1_000),
            ),
            clock=clock,
        )

        execution = await controller.execute(_request())

        assert execution.audit.outcome is ProbeOutcome.BUDGET_EXHAUSTED
        assert execution.audit.stop_reason is ProbeStopReason.ELAPSED_BUDGET_EXHAUSTED
        assert execution.observation is None
        assert handler.calls == []

    asyncio.run(scenario())


def test_tool_deadline_is_rechecked_after_a_non_yielding_handler_returns() -> None:
    async def scenario() -> None:
        clock = FakeClock()
        handler = ClockAdvancingHandler(clock, milliseconds=100)
        controller = ProbeController(
            _envelope(max_elapsed_ms=1_000),
            _registry(
                handler,
                capability=_closed_capability(timeout_ms=50),
            ),
            clock=clock,
        )

        execution = await controller.execute(_request())

        assert execution.audit.outcome is ProbeOutcome.TIMED_OUT
        assert execution.audit.stop_reason is ProbeStopReason.PROBE_TIMEOUT
        assert execution.observation is None
        assert handler.calls[0].timeout_ms == 50

    asyncio.run(scenario())


def test_timeout_terminalizes_session_while_cancel_suppressing_handler_lives() -> None:
    async def scenario() -> None:
        handler = CancellationSuppressingHandler()
        controller = ProbeController(
            _envelope(max_elapsed_ms=1_000),
            _registry(
                handler,
                capability=_closed_capability(timeout_ms=50),
            ),
        )

        timed_out = await controller.execute(_request())
        repeated = await controller.execute(_request())

        assert timed_out.audit.stop_reason is ProbeStopReason.PROBE_TIMEOUT
        assert repeated is timed_out
        assert len(controller.audit_trail) == 1
        assert len(handler.calls) == 1
        assert handler.max_active == 1
        handler.release.set()
        await asyncio.sleep(0)

    asyncio.run(scenario())


def test_cancellation_before_during_and_outside_execution_is_audited() -> None:
    async def scenario() -> None:
        before_handler = SpyHandler()
        before = ProbeController(_envelope(), _registry(before_handler))
        before.cancel()
        cancelled = await before.execute(_request())
        assert cancelled.audit.stop_reason is ProbeStopReason.PROBE_CANCELLED
        assert cancelled.audit.probe_count_used == 0
        assert before_handler.calls == []

        during_handler = BlockingHandler()
        during = ProbeController(_envelope(), _registry(during_handler))
        during_task = asyncio.create_task(during.execute(_request()))
        await during_handler.started.wait()
        during.cancel()
        during_result = await during_task
        assert during_result.audit.outcome is ProbeOutcome.CANCELLED
        await asyncio.sleep(0)
        assert during_handler.cancelled.is_set()

        external_handler = BlockingHandler()
        external = ProbeController(_envelope(), _registry(external_handler))
        external_task = asyncio.create_task(external.execute(_request()))
        await external_handler.started.wait()
        external_task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await external_task
        assert external.audit_trail[-1].outcome is ProbeOutcome.CANCELLED
        assert external.audit_trail[-1].stop_reason is ProbeStopReason.PROBE_CANCELLED

        self_cancelled = ProbeController(
            _envelope(),
            _registry(SpyHandler(error=asyncio.CancelledError())),
        )
        self_cancelled_result = await self_cancelled.execute(_request())
        assert self_cancelled_result.audit.outcome is ProbeOutcome.CANCELLED
        assert (
            self_cancelled_result.audit.stop_reason is ProbeStopReason.PROBE_CANCELLED
        )

    asyncio.run(scenario())


def test_wall_clock_regression_is_clamped_without_changing_monotonic_budgets() -> None:
    async def scenario() -> None:
        clock = RegressingWallClock()
        controller = ProbeController(
            _envelope(),
            _registry(SpyHandler()),
            clock=clock,
        )

        execution = await controller.execute(_request())

        assert execution.audit.outcome is ProbeOutcome.COMPLETED
        assert execution.audit.completed_at == execution.audit.started_at

    asyncio.run(scenario())


@pytest.mark.parametrize(
    "error",
    (CapabilityUnavailable(), RuntimeError("PASSWORD=never-audit-this")),
)
def test_unavailable_handlers_return_sanitized_stable_audit(error: Exception) -> None:
    async def scenario() -> None:
        handler = SpyHandler(error=error)
        controller = ProbeController(_envelope(), _registry(handler))

        execution = await controller.execute(_request())

        assert execution.audit.outcome is ProbeOutcome.UNAVAILABLE
        assert execution.audit.stop_reason is ProbeStopReason.CAPABILITY_UNAVAILABLE
        assert "PASSWORD" not in json.dumps(execution.audit.model_dump(mode="json"))
        assert len(handler.calls) == 1

    asyncio.run(scenario())


@pytest.mark.parametrize(
    "observation",
    (
        {"observed_at": "2026-08-13T12:00:00Z", "payload": {}},
        object(),
        gzip.compress(b"x" * 1_000_000),
        ProbeObservation.model_construct(
            observed_at=NOW,
            payload={"access_token": "must-not-pass"},
        ),
    ),
)
def test_malformed_or_secret_bearing_results_never_become_observations(
    observation: object,
) -> None:
    async def scenario() -> None:
        handler = SpyHandler(observation)
        controller = ProbeController(_envelope(), _registry(handler))

        execution = await controller.execute(_request())

        assert execution.audit.outcome is ProbeOutcome.MALFORMED
        assert execution.audit.stop_reason is ProbeStopReason.MALFORMED_OBSERVATION
        assert execution.observation is None
        assert execution.audit.result_sha256 is None
        assert "must-not-pass" not in json.dumps(
            execution.audit.model_dump(mode="json")
        )

    asyncio.run(scenario())
