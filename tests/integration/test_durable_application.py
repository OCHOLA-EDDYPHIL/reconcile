from __future__ import annotations

import asyncio
import json
import os
import sqlite3
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from reconcile.baseline import FixedProbePlan, FixedProbeStep, execute_fixed_plan
from reconcile.contracts import (
    OBSERVATION_CAPABILITY_VERSION,
    PROBE_REQUEST_VERSION,
    Classification,
    EffectAssertion,
    EffectAssertionState,
    ExecutionEnvelope,
    InvestigationStatus,
    ObservationCapability,
    OperationStatus,
    ProbeOutcome,
    ProbeRequest,
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
    ObservationHandler,
    ProbeObservation,
    ProbeStopReason,
)
from reconcile.durable_application import (
    DurableEscalationRequired,
    DurableExecutionContext,
    DurableExecutionStrategy,
    DurableInvestigationApplicationService,
    DurableServiceUnavailable,
)
from reconcile.evidence import (
    RuleInput,
    RuleObservation,
    RuleVerdict,
    TargetRuleDescriptor,
    TargetRuleRegistration,
    TargetRuleRegistry,
)
from reconcile.persistence import (
    CleanupStatus,
    CostLedgerEntry,
    DurableRunState,
    LeaseUnavailable,
    ProbeCheckpointState,
    RuntimeTelemetryKind,
    RuntimeTelemetryRecord,
    SqliteDurableRuntimeStore,
)
from reconcile.persistence.durable import RUNTIME_TELEMETRY_VERSION
from tests.contract._factories import make_envelope, make_target

pytestmark = pytest.mark.integration

_PROVENANCE = "a" * 64
_VERSION = "1.0.0"
_EFFECT_IDS = ("business-record", "audit-record")


def _envelope(*, max_elapsed_ms: int = 30_000) -> ExecutionEnvelope:
    now = datetime.now(UTC)
    payload = json.loads(canonical_json_bytes(make_envelope()))
    payload["invoked_at"] = now.isoformat()
    payload["ambiguity"]["observed_at"] = (now + timedelta(milliseconds=1)).isoformat()
    payload["context"]["evidence_budget"] = {
        "max_probes": 3,
        "max_elapsed_ms": max_elapsed_ms,
        "max_total_result_bytes": 4_096,
        "max_cost_units": 3,
    }
    return decode_contract(json.dumps(payload), ExecutionEnvelope)


def _request(*, rationale: str = "Read the sealed target.") -> ProbeRequest:
    return ProbeRequest(
        schema_version=PROBE_REQUEST_VERSION,
        capability_name="gcs-object-readback",
        capability_version=_VERSION,
        relevant_effect_ids=_EFFECT_IDS,
        arguments={"order_id": "order-7"},
        rationale=rationale,
    )


class _ReadHandler:
    def __init__(self, *, blocking: bool = False, clock=None) -> None:
        self.calls: list[BoundProbe] = []
        self.clock = clock
        self.started = asyncio.Event()
        self.release = asyncio.Event()
        if not blocking:
            self.release.set()

    async def __call__(self, probe: BoundProbe) -> ProbeObservation:
        self.calls.append(probe)
        self.started.set()
        await self.release.wait()
        return ProbeObservation(
            observed_at=(datetime.now(UTC) if self.clock is None else self.clock.now()),
            payload={"kind": "committed", "record": "record-7"},
        )


class _UnavailableReadHandler:
    async def __call__(self, probe: BoundProbe) -> ProbeObservation:
        del probe
        raise CapabilityUnavailable


class _MutableClock:
    def __init__(self, now: datetime) -> None:
        self.current = now
        self.seconds = 0.0

    def now(self) -> datetime:
        return self.current

    def monotonic(self) -> float:
        return self.seconds

    def advance(self, seconds: float) -> None:
        self.current += timedelta(seconds=seconds)
        self.seconds += seconds


class _Normalizer:
    def __call__(self, rule_input: RuleInput) -> RuleObservation:
        observation = ProbeObservation.model_validate_json(rule_input.observation)
        if observation.payload != {"kind": "committed", "record": "record-7"}:
            raise ValueError("observation is not the sealed committed fixture")
        return RuleObservation(
            target=rule_input.envelope.target,
            source_record="record-7",
            observed_at=observation.observed_at,
            operation_id=rule_input.envelope.operation_id,
            correlation=dict(rule_input.envelope.context.correlation_fields),
            effect_assertions=tuple(
                EffectAssertion(
                    effect_id=effect_id,
                    state=EffectAssertionState.ESTABLISHED,
                )
                for effect_id in _EFFECT_IDS
            ),
            operation_status=OperationStatus.TERMINAL_COMMITTED,
            verdict=RuleVerdict.AUTHORITATIVE_EFFECTS,
        )


def _registries(
    handler: ObservationHandler | None,
) -> tuple[CapabilityRegistry, TargetRuleRegistry]:
    target = make_target()
    capability = ObservationCapability(
        schema_version=OBSERVATION_CAPABILITY_VERSION,
        name="gcs-object-readback",
        version=_VERSION,
        read_only=True,
        argument_schema={
            "$schema": "https://json-schema.org/draft/2020-12/schema",
            "type": "object",
            "properties": {"order_id": {"type": "string", "maxLength": 128}},
            "required": ["order_id"],
            "additionalProperties": False,
        },
        allowed_targets=(
            TargetConstraint(
                target_kind=target.target_kind,
                scope=dict(target.scope),
            ),
        ),
        timeout_ms=5_000,
        result_byte_ceiling=1_024,
        cost_units=1,
    )
    capabilities = CapabilityRegistry()
    capabilities.register(
        CapabilityRegistration(
            capability=capability,
            semantics=CapabilitySemantics.READ_ONLY,
            enabled=True,
            argument_byte_ceiling=1_024,
            max_invocations=3,
            handler=handler,
        )
    )
    rules = TargetRuleRegistry()
    rules.register(
        TargetRuleRegistration(
            descriptor=TargetRuleDescriptor(
                target_kind=target.target_kind,
                capability_name=capability.name,
                capability_version=capability.version,
                authority_policy_version="authority-gcs-v1",
                classification_policy_version="classification-v1",
                source="durable-test-target",
                adapter_version=_VERSION,
            ),
            normalizer=_Normalizer(),
        )
    )
    return capabilities, rules


def _plan(*, rationale: str = "Read the sealed target.") -> FixedProbePlan:
    return FixedProbePlan(
        name="durable-fixed-plan",
        version=_VERSION,
        steps=(FixedProbeStep(request=_request(rationale=rationale)),),
        sufficient_classifications=(Classification.COMMITTED,),
    )


class _FixedExecutor:
    def __init__(
        self,
        handler: _ReadHandler,
        *,
        rationale: str = "Read the sealed target.",
        clock=None,
    ):
        self.handler = handler
        self.rationale = rationale
        self.clock = clock

    async def __call__(
        self,
        envelope: ExecutionEnvelope,
        *,
        revision: int,
        cancellation_event: asyncio.Event,
        runtime: DurableExecutionContext,
    ):
        capabilities, rules = _registries(self.handler)
        result = await execute_fixed_plan(
            envelope,
            capabilities,
            rules,
            _plan(rationale=self.rationale),
            revision=revision,
            cancellation_event=cancellation_event,
            durability_observer=runtime,
            clock=self.clock,
        )
        return await runtime.complete(result.report)


class _UnknownThenFixedExecutor:
    def __init__(self, handler: _ReadHandler, *, clock=None) -> None:
        self.handler = handler
        self.clock = clock

    async def __call__(
        self,
        envelope: ExecutionEnvelope,
        *,
        revision: int,
        cancellation_event: asyncio.Event,
        runtime: DurableExecutionContext,
    ):
        capabilities, rules = _registries(self.handler)
        unknown = ProbeRequest(
            schema_version=PROBE_REQUEST_VERSION,
            capability_name="unknown-readback",
            capability_version=_VERSION,
            relevant_effect_ids=_EFFECT_IDS,
            arguments={"order_id": "order-7"},
            rationale="Exercise a non-dispatched controller outcome.",
        )
        plan = FixedProbePlan(
            name="unknown-then-fixed",
            version=_VERSION,
            steps=(
                FixedProbeStep(request=unknown, required=False),
                FixedProbeStep(request=_request()),
            ),
            sufficient_classifications=(Classification.COMMITTED,),
        )
        result = await execute_fixed_plan(
            envelope,
            capabilities,
            rules,
            plan,
            revision=revision,
            cancellation_event=cancellation_event,
            durability_observer=runtime,
            clock=self.clock,
        )
        return await runtime.complete(result.report)


class _UnavailableFixedExecutor:
    async def __call__(
        self,
        envelope: ExecutionEnvelope,
        *,
        revision: int,
        cancellation_event: asyncio.Event,
        runtime: DurableExecutionContext,
    ):
        capabilities, rules = _registries(_UnavailableReadHandler())
        result = await execute_fixed_plan(
            envelope,
            capabilities,
            rules,
            _plan(),
            revision=revision,
            cancellation_event=cancellation_event,
            durability_observer=runtime,
        )
        return await runtime.complete(result.report)


class _MeteredAdaptiveExecutor:
    def __init__(self, handler: _ReadHandler) -> None:
        self.handler = handler
        self.external_calls = 0

    async def __call__(self, envelope, *, revision, cancellation_event, runtime):
        async def provider_call() -> str:
            self.external_calls += 1
            return "sanitized-provider-result"

        await runtime.call_provider(
            "turn-1",
            estimated_cost_microunits=40,
            operation=provider_call,
        )
        return await _FixedExecutor(self.handler)(
            envelope,
            revision=revision,
            cancellation_event=cancellation_event,
            runtime=runtime,
        )


class _PauseAfterProviderExecutor:
    def __init__(self) -> None:
        self.executor_calls = 0
        self.external_calls = 0
        self.provider_called = asyncio.Event()

    async def __call__(self, envelope, *, revision, cancellation_event, runtime):
        del envelope, revision, cancellation_event
        self.executor_calls += 1

        async def provider_call() -> str:
            self.external_calls += 1
            self.provider_called.set()
            return "sanitized-provider-result"

        await runtime.call_provider(
            "turn-1",
            estimated_cost_microunits=40,
            operation=provider_call,
        )
        await asyncio.Future()


class _DeadlineCrossingProviderExecutor:
    def __init__(self, clock: _MutableClock) -> None:
        self.clock = clock
        self.external_calls = 0

    async def __call__(self, envelope, *, revision, cancellation_event, runtime):
        del envelope, revision, cancellation_event

        async def provider_call() -> str:
            self.external_calls += 1
            self.clock.advance(31)
            return "late-provider-result"

        await runtime.call_provider(
            "turn-crosses-deadline",
            estimated_cost_microunits=40,
            operation=provider_call,
        )
        raise AssertionError("a result beyond the durable deadline was accepted")


class _CancellationSuppressingProviderExecutor:
    def __init__(self) -> None:
        self.started = asyncio.Event()
        self.cancelled = asyncio.Event()
        self.release = asyncio.Event()
        self.exited = asyncio.Event()

    async def __call__(self, envelope, *, revision, cancellation_event, runtime):
        del envelope, revision, cancellation_event

        async def provider_call() -> str:
            self.started.set()
            try:
                await asyncio.Future()
            except asyncio.CancelledError:
                self.cancelled.set()
                await self.release.wait()
            self.exited.set()
            return "late-provider-result"

        await runtime.call_provider(
            "turn-suppresses-cancellation",
            estimated_cost_microunits=40,
            operation=provider_call,
        )
        raise AssertionError("a late provider result was accepted")


class _SingleProviderExecutor:
    def __init__(self) -> None:
        self.external_calls = 0

    async def __call__(self, envelope, *, revision, cancellation_event, runtime):
        del envelope, revision, cancellation_event

        async def provider_call() -> str:
            self.external_calls += 1
            return "sanitized-provider-result"

        await runtime.call_provider(
            "turn-single",
            estimated_cost_microunits=40,
            operation=provider_call,
        )
        raise AssertionError("single provider result unexpectedly returned")


class _SelfCancellingProviderExecutor:
    def __init__(self) -> None:
        self.external_calls = 0

    async def __call__(self, envelope, *, revision, cancellation_event, runtime):
        del envelope, revision, cancellation_event

        async def provider_call() -> str:
            self.external_calls += 1
            raise asyncio.CancelledError

        await runtime.call_provider(
            "turn-self-cancelled",
            estimated_cost_microunits=40,
            operation=provider_call,
        )
        raise AssertionError("provider cancellation was accepted")


class _RegressedClockProviderExecutor:
    def __init__(self, clock: _MutableClock) -> None:
        self.clock = clock
        self.external_calls = 0
        self.elapsed_floor_ms = 0
        self.remaining_ms = 0

    async def __call__(self, envelope, *, revision, cancellation_event, runtime):
        del envelope, revision, cancellation_event
        self.clock.advance(0.9)
        self.elapsed_floor_ms = runtime.elapsed_floor_ms(self.clock.now())
        self.clock.current -= timedelta(seconds=0.8)
        self.remaining_ms = runtime.remaining_elapsed_ms(self.clock.now())

        async def provider_call() -> str:
            await asyncio.sleep(0.2)
            self.external_calls += 1
            return "provider-dispatched-after-regressed-clock"

        await runtime.call_provider(
            "turn-regressed-clock",
            estimated_cost_microunits=40,
            operation=provider_call,
        )
        raise AssertionError("regressed wall clock reopened elapsed provider budget")


class _TamperProviderReceiptExecutor:
    def __init__(self, inner, database: Path) -> None:
        self.inner = inner
        self.database = database

    async def __call__(self, *args, **kwargs):
        outcome = await self.inner(*args, **kwargs)
        with sqlite3.connect(self.database) as connection:
            row = connection.execute(
                """
                SELECT payload
                FROM runtime_cost_entries
                WHERE entry_id = 'provider-turn-1'
                """
            ).fetchone()
            assert row is not None
            entry = CostLedgerEntry.model_validate_json(row[0])
            forged = entry.model_copy(update={"entry_id": "provider-forged"})
            connection.execute(
                """
                UPDATE runtime_cost_entries
                SET entry_id = ?, payload = ?
                WHERE entry_id = 'provider-turn-1'
                """,
                (forged.entry_id, canonical_json_bytes(forged)),
            )
        return outcome


class _PauseAfterRecordedExecutor:
    def __init__(self, handler: _ReadHandler, *, pause: bool = True) -> None:
        self.handler = handler
        self.pause = pause
        self.recorded = asyncio.Event()

    async def __call__(
        self,
        envelope: ExecutionEnvelope,
        *,
        revision: int,
        cancellation_event: asyncio.Event,
        runtime: DurableExecutionContext,
    ):
        if not self.pause:
            return await _FixedExecutor(self.handler)(
                envelope,
                revision=revision,
                cancellation_event=cancellation_event,
                runtime=runtime,
            )
        capabilities, _ = _registries(self.handler)
        controller = runtime.controller(capabilities)
        await controller.execute(_request())
        self.recorded.set()
        await asyncio.Future()


class _PauseAfterNonDispatchedExecutor:
    def __init__(self) -> None:
        self.recorded = asyncio.Event()

    async def __call__(
        self,
        envelope: ExecutionEnvelope,
        *,
        revision: int,
        cancellation_event: asyncio.Event,
        runtime: DurableExecutionContext,
    ):
        del envelope, revision, cancellation_event
        capabilities, _ = _registries(_ReadHandler())
        controller = runtime.controller(capabilities)
        request = ProbeRequest(
            schema_version=PROBE_REQUEST_VERSION,
            capability_name="unknown-readback",
            capability_version=_VERSION,
            relevant_effect_ids=_EFFECT_IDS,
            arguments={"order_id": "order-7"},
            rationale="Exercise a non-dispatched controller outcome.",
        )
        await controller.execute(request)
        self.recorded.set()
        await asyncio.Future()


class _PauseBeforeWorkExecutor:
    def __init__(
        self,
        handler: _ReadHandler | None = None,
        *,
        clock=None,
        pause: bool = True,
    ) -> None:
        self.handler = handler
        self.clock = clock
        self.pause = pause
        self.started = asyncio.Event()

    async def __call__(self, envelope, *, revision, cancellation_event, runtime):
        if self.pause:
            self.started.set()
            await asyncio.Future()
        if self.handler is None:
            raise RuntimeError("non-pausing test executor requires a handler")
        return await _FixedExecutor(self.handler, clock=self.clock)(
            envelope,
            revision=revision,
            cancellation_event=cancellation_event,
            runtime=runtime,
        )


class _ProviderBudgetExecutor:
    def __init__(self) -> None:
        self.external_calls = 0

    async def __call__(self, envelope, *, revision, cancellation_event, runtime):
        del envelope, revision, cancellation_event

        async def provider_call() -> str:
            self.external_calls += 1
            return "sanitized-provider-result"

        await runtime.call_provider(
            "turn-1",
            estimated_cost_microunits=40,
            operation=provider_call,
        )
        await runtime.call_provider(
            "turn-2",
            estimated_cost_microunits=40,
            operation=provider_call,
        )
        raise AssertionError("the second provider reservation must fail closed")


class _DuplicateProviderCallExecutor:
    def __init__(self) -> None:
        self.external_calls = 0

    async def __call__(self, envelope, *, revision, cancellation_event, runtime):
        del envelope, revision, cancellation_event

        async def provider_call() -> str:
            self.external_calls += 1
            return "sanitized-provider-result"

        await runtime.call_provider(
            "same-turn",
            estimated_cost_microunits=40,
            operation=provider_call,
        )
        await runtime.call_provider(
            "same-turn",
            estimated_cost_microunits=40,
            operation=provider_call,
        )
        raise AssertionError("a consumed provider call identifier was dispatched")


class _SyncProviderFailureThenFixedExecutor:
    def __init__(self, handler: _ReadHandler) -> None:
        self.handler = handler
        self.external_calls = 0

    async def __call__(self, envelope, *, revision, cancellation_event, runtime):
        def provider_call():
            self.external_calls += 1
            raise RuntimeError("sanitized synchronous provider failure")

        with pytest.raises(RuntimeError, match="synchronous provider failure"):
            await runtime.call_provider(
                "turn-sync-failure",
                estimated_cost_microunits=40,
                operation=provider_call,
            )
        return await _FixedExecutor(self.handler)(
            envelope,
            revision=revision,
            cancellation_event=cancellation_event,
            runtime=runtime,
        )


class _FailingCleanup:
    async def __call__(self, envelope, report) -> None:
        del envelope, report
        raise RuntimeError("sanitized cleanup failure")


class _BlockingCleanup:
    def __init__(self) -> None:
        self.started = asyncio.Event()

    async def __call__(self, envelope, report) -> None:
        del envelope, report
        self.started.set()
        await asyncio.Future()


class _CountingCleanup:
    def __init__(self) -> None:
        self.calls = 0

    async def __call__(self, envelope, report) -> None:
        del envelope, report
        self.calls += 1


class _FailRecordOnceStore:
    def __init__(self, store: SqliteDurableRuntimeStore) -> None:
        self._store = store
        self.failed = False

    def __getattr__(self, name: str):
        return getattr(self._store, name)

    async def record_probe(self, *args, **kwargs):
        if not self.failed:
            self.failed = True
            raise RuntimeError("simulated lost checkpoint acknowledgement")
        return await self._store.record_probe(*args, **kwargs)


class _AlwaysFailRecordStore:
    def __init__(self, store: SqliteDurableRuntimeStore) -> None:
        self._store = store

    def __getattr__(self, name: str):
        return getattr(self._store, name)

    async def record_probe(self, *args, **kwargs):
        del args, kwargs
        raise RuntimeError("simulated repeated lost checkpoint acknowledgement")


class _FailClassifierTelemetryOnceStore:
    def __init__(self, store: SqliteDurableRuntimeStore) -> None:
        self._store = store
        self.failed = False

    def __getattr__(self, name: str):
        return getattr(self._store, name)

    async def append_telemetry(self, lease, record, *, now):
        if record.telemetry_id == "classification" and not self.failed:
            self.failed = True
            raise RuntimeError("simulated telemetry dependency interruption")
        return await self._store.append_telemetry(lease, record, now=now)


class _RaceReleaseStore:
    def __init__(self, store: SqliteDurableRuntimeStore) -> None:
        self._store = store
        self.release_started = asyncio.Event()
        self.allow_release = asyncio.Event()

    def __getattr__(self, name: str):
        return getattr(self._store, name)

    async def release_lease(self, *args, **kwargs) -> None:
        self.release_started.set()
        await self.allow_release.wait()
        await self._store.release_lease(*args, **kwargs)


class _QueuedTakeoverStore:
    def __init__(self, store: SqliteDurableRuntimeStore, clock: _MutableClock) -> None:
        self._store = store
        self.clock = clock
        self.takeover = None
        self.takeover_acquired = asyncio.Event()
        self._takeover_queued = False

    def __getattr__(self, name: str):
        return getattr(self._store, name)

    def _queue_takeover(self, investigation_id: str) -> None:
        if self._takeover_queued:
            return
        self._takeover_queued = True

        def acquire() -> None:
            self.clock.advance(31)
            self.takeover = self._store._acquire_lease(
                investigation_id,
                "worker-race-takeover",
                self.clock.now(),
            )
            self.takeover_acquired.set()

        asyncio.get_running_loop().call_soon(acquire)


class _TakeoverAfterProbeStartStore(_QueuedTakeoverStore):
    async def start_probe(self, lease, **kwargs):
        checkpoint = await self._store.start_probe(lease, **kwargs)
        self._queue_takeover(lease.investigation_id)
        return checkpoint


class _TakeoverAfterProviderReceiptStore(_QueuedTakeoverStore):
    async def provider_call_receipts(self, investigation_id: str):
        receipts = await self._store.provider_call_receipts(investigation_id)
        self._queue_takeover(investigation_id)
        return receipts


class _TakeoverAfterCleanupPendingStore(_QueuedTakeoverStore):
    async def record_cleanup(self, lease, status, **kwargs):
        run = await self._store.record_cleanup(lease, status, **kwargs)
        if status is CleanupStatus.PENDING:
            self._queue_takeover(lease.investigation_id)
        return run


class _AdvanceClockAfterProviderReceiptStore:
    def __init__(self, store: SqliteDurableRuntimeStore, clock: _MutableClock) -> None:
        self._store = store
        self._clock = clock
        self._advanced = False

    def __getattr__(self, name: str):
        return getattr(self._store, name)

    async def provider_call_receipts(self, investigation_id: str):
        receipts = await self._store.provider_call_receipts(investigation_id)
        if not self._advanced:
            self._advanced = True
            self._clock.advance(2)
        return receipts


class _AdvanceClockAfterProbeStartStore:
    def __init__(self, store: SqliteDurableRuntimeStore, clock: _MutableClock) -> None:
        self._store = store
        self.clock = clock

    def __getattr__(self, name: str):
        return getattr(self._store, name)

    async def start_probe(self, lease, **kwargs):
        checkpoint = await self._store.start_probe(lease, **kwargs)
        asyncio.get_running_loop().call_soon(self.clock.advance, 2)
        return checkpoint


class _AdvanceClockAfterLeaseValidationStore:
    def __init__(
        self,
        store: SqliteDurableRuntimeStore,
        clock: _MutableClock,
        *,
        seconds: float,
    ) -> None:
        self._store = store
        self.clock = clock
        self.seconds = seconds
        self._advanced = False

    def __getattr__(self, name: str):
        return getattr(self._store, name)

    async def validate_lease(self, lease, *, now) -> None:
        await self._store.validate_lease(lease, now=now)
        if not self._advanced:
            self._advanced = True
            self.clock.advance(self.seconds)


def _service(
    store,
    executor,
    *,
    owner_id: str,
    strategy: DurableExecutionStrategy = DurableExecutionStrategy.FIXED,
    cleanup=None,
    provenance: str = _PROVENANCE,
    max_provider_calls: int = 0,
    clock=None,
    monotonic_clock=None,
) -> DurableInvestigationApplicationService:
    return DurableInvestigationApplicationService(
        store,
        executor,
        strategy=strategy,
        cleanup=cleanup,
        max_provider_calls=max_provider_calls,
        max_estimated_cost_microunits=100,
        owner_id=owner_id,
        semantic_config_sha256=provenance,
        event_poll_interval=0.01,
        clock=clock,
        monotonic_clock=monotonic_clock,
    )


async def _wait_for(
    predicate,
    *,
    timeout: float = 3.0,
) -> None:
    async with asyncio.timeout(timeout):
        while not await predicate():
            await asyncio.sleep(0.01)


async def _call_count_is(handler: _ReadHandler, expected: int) -> bool:
    return len(handler.calls) == expected


@pytest.mark.integration
def test_durable_service_establishes_report_events_telemetry_and_cleanup_separately(
    tmp_path: Path,
) -> None:
    async def scenario() -> None:
        database = tmp_path / "runtime.sqlite3"
        store = SqliteDurableRuntimeStore(database)
        handler = _ReadHandler()
        service = _service(
            store,
            _FixedExecutor(handler),
            owner_id="worker-main",
            cleanup=_FailingCleanup(),
        )
        envelope = _envelope()
        created = await service.create(envelope)
        replay = await service.create(envelope)
        assert created.created is True
        assert replay.created is False

        async def cleanup_finished() -> bool:
            return (
                await store.get_run(envelope.investigation_id)
            ).cleanup_status is CleanupStatus.FAILED

        await _wait_for(cleanup_finished)
        run = await store.get_run(envelope.investigation_id)
        report = await service.get(envelope.investigation_id)
        events = await service.snapshot(envelope.investigation_id)
        costs = await store.cost_snapshot(envelope.investigation_id)
        telemetry = await store.telemetry_records(envelope.investigation_id)

        assert len(handler.calls) == 1
        assert run.state is DurableRunState.TERMINAL
        assert run.classification is Classification.COMMITTED
        assert run.cleanup_failure_code == "cleanup-failed"
        assert report == run.established_report
        assert events.terminal is True
        assert events.events[0].payload.status is InvestigationStatus.CREATED  # type: ignore[union-attr]
        assert events.events[1].payload.status is InvestigationStatus.INVESTIGATING  # type: ignore[union-attr]
        assert events.events[-1].payload.status is InvestigationStatus.COMPLETED  # type: ignore[union-attr]
        assert costs.probe_count == 1
        assert costs.controller_cost_units == 1
        assert costs.evidence_bytes == 1_024
        assert costs.provider_calls == 0
        assert {
            RuntimeTelemetryKind.RUN,
            RuntimeTelemetryKind.PROBE,
            RuntimeTelemetryKind.EVIDENCE_DECISION,
            RuntimeTelemetryKind.CLASSIFIER,
            RuntimeTelemetryKind.ACTION_GATE,
            RuntimeTelemetryKind.CLEANUP,
        } <= {item.kind for item in telemetry}
        assert os.stat(database).st_mode & 0o777 == 0o600
        await service.aclose()

    asyncio.run(scenario())


def test_non_dispatched_audits_are_attested_without_read_checkpoints(
    tmp_path: Path,
) -> None:
    async def scenario() -> None:
        first_store = SqliteDurableRuntimeStore(tmp_path / "unknown.sqlite3")
        first_envelope = _envelope()
        handler = _ReadHandler()
        first = _service(
            first_store,
            _UnknownThenFixedExecutor(handler),
            owner_id="worker-unknown-then-fixed",
        )
        await first.create(first_envelope)

        async def first_terminal() -> bool:
            return (
                await first_store.get_run(first_envelope.investigation_id)
            ).state is DurableRunState.TERMINAL

        await _wait_for(first_terminal)
        first_run = await first_store.get_run(first_envelope.investigation_id)
        first_audits = await first_store.controller_audits(
            first_envelope.investigation_id
        )
        first_checkpoints = await first_store.probe_checkpoints(
            first_envelope.investigation_id
        )
        assert first_run.classification is Classification.COMMITTED
        assert tuple(item.stop_reason for item in first_audits) == (
            ProbeStopReason.UNKNOWN_CAPABILITY,
            ProbeStopReason.PROBE_COMPLETED,
        )
        assert tuple(item.step_sequence for item in first_checkpoints) == (2,)
        assert len(handler.calls) == 1
        await first.aclose()

        second_store = SqliteDurableRuntimeStore(tmp_path / "unavailable.sqlite3")
        second_envelope = _envelope()
        second = _service(
            second_store,
            _UnavailableFixedExecutor(),
            owner_id="worker-unavailable-handler",
        )
        await second.create(second_envelope)

        async def second_terminal() -> bool:
            return (
                await second_store.get_run(second_envelope.investigation_id)
            ).state is DurableRunState.TERMINAL

        await _wait_for(second_terminal)
        second_run = await second_store.get_run(second_envelope.investigation_id)
        second_audits = await second_store.controller_audits(
            second_envelope.investigation_id
        )
        assert second_run.classification is Classification.UNKNOWN
        assert len(second_audits) == 1
        assert second_audits[0].stop_reason is ProbeStopReason.CAPABILITY_UNAVAILABLE
        second_checkpoints = await second_store.probe_checkpoints(
            second_envelope.investigation_id
        )
        assert len(second_checkpoints) == 1
        assert second_checkpoints[0].audit == second_audits[0]
        second_costs = await second_store.cost_snapshot(
            second_envelope.investigation_id
        )
        assert second_costs.probe_count == 1
        await second.aclose()

    asyncio.run(scenario())


@pytest.mark.integration
def test_two_application_instances_never_dispatch_the_same_read_concurrently(
    tmp_path: Path,
) -> None:
    async def scenario() -> None:
        store = SqliteDurableRuntimeStore(tmp_path / "runtime.sqlite3")
        envelope = _envelope()
        handler = _ReadHandler(blocking=True)
        first = _service(store, _FixedExecutor(handler), owner_id="same-owner")
        second = _service(store, _FixedExecutor(handler), owner_id="same-owner")
        first_result, second_result = await asyncio.gather(
            first.create(envelope),
            second.create(envelope),
        )
        await asyncio.wait_for(handler.started.wait(), timeout=2)
        await asyncio.sleep(0.05)
        assert {first_result.created, second_result.created} == {False, True}
        assert len(handler.calls) == 1
        handler.release.set()

        async def terminal() -> bool:
            return (
                await store.get_run(envelope.investigation_id)
            ).state is DurableRunState.TERMINAL

        await _wait_for(terminal)
        assert len(handler.calls) == 1
        await first.aclose()
        await second.aclose()

    asyncio.run(scenario())


@pytest.mark.integration
def test_expired_owner_cannot_commit_after_fenced_takeover(tmp_path: Path) -> None:
    async def scenario() -> None:
        database = tmp_path / "runtime.sqlite3"
        store = SqliteDurableRuntimeStore(database)
        envelope = _envelope(max_elapsed_ms=120_000)
        clock = _MutableClock(envelope.invoked_at)
        stale_handler = _ReadHandler(blocking=True, clock=clock)
        stale = _service(
            store,
            _FixedExecutor(stale_handler, clock=clock),
            owner_id="worker-that-loses-lease",
            clock=clock.now,
        )
        await stale.create(envelope)
        await asyncio.wait_for(stale_handler.started.wait(), timeout=2)

        clock.advance(31)
        winner_handler = _ReadHandler(clock=clock)
        winner = _service(
            SqliteDurableRuntimeStore(database),
            _FixedExecutor(winner_handler, clock=clock),
            owner_id="worker-that-takes-over",
            clock=clock.now,
        )
        await winner.create(envelope)

        async def terminal() -> bool:
            return (
                await store.get_run(envelope.investigation_id)
            ).state is DurableRunState.TERMINAL

        await _wait_for(terminal)
        before_release = await store.probe_checkpoints(envelope.investigation_id)
        assert len(stale_handler.calls) == 1
        assert len(winner_handler.calls) == 1
        assert before_release[0].state is ProbeCheckpointState.RECORDED

        stale_handler.release.set()

        async def stale_failed_closed() -> bool:
            try:
                await stale.get(envelope.investigation_id)
            except DurableServiceUnavailable:
                return True
            return False

        await _wait_for(stale_failed_closed)
        assert (
            await store.probe_checkpoints(envelope.investigation_id) == before_release
        )
        costs = await store.cost_snapshot(envelope.investigation_id)
        assert costs.probe_count == 2
        await stale.aclose()
        await winner.aclose()

    asyncio.run(scenario())


def test_takeover_acquired_after_started_checkpoint_blocks_stale_read_dispatch(
    tmp_path: Path,
) -> None:
    async def scenario() -> None:
        database = tmp_path / "read-takeover.sqlite3"
        durable = SqliteDurableRuntimeStore(database)
        envelope = _envelope(max_elapsed_ms=120_000)
        clock = _MutableClock(envelope.ambiguity.observed_at)
        takeover_store = _TakeoverAfterProbeStartStore(durable, clock)
        first_handler = _ReadHandler(clock=clock)
        first = _service(
            takeover_store,
            _FixedExecutor(first_handler, clock=clock),
            owner_id="worker-before-read-takeover",
            clock=clock.now,
        )
        await first.create(envelope)
        await asyncio.wait_for(takeover_store.takeover_acquired.wait(), timeout=2)

        async def unavailable() -> bool:
            try:
                await first.get(envelope.investigation_id)
            except DurableServiceUnavailable:
                return True
            return False

        await _wait_for(unavailable)
        assert first_handler.calls == []
        checkpoints = await durable.probe_checkpoints(envelope.investigation_id)
        assert len(checkpoints) == 1
        assert checkpoints[0].state is ProbeCheckpointState.STARTED
        assert takeover_store.takeover is not None
        await first.aclose()
        await durable.release_lease(takeover_store.takeover, now=clock.now())

        replay_handler = _ReadHandler(clock=clock)
        replay = _service(
            SqliteDurableRuntimeStore(database),
            _FixedExecutor(replay_handler, clock=clock),
            owner_id="worker-after-read-takeover",
            clock=clock.now,
        )
        await replay.start()

        async def terminal() -> bool:
            return (
                await durable.get_run(envelope.investigation_id)
            ).state is DurableRunState.TERMINAL

        await _wait_for(terminal)
        assert len(replay_handler.calls) == 1
        costs = await durable.cost_snapshot(envelope.investigation_id)
        assert costs.probe_count == 2
        assert costs.controller_cost_units == 2
        await replay.aclose()

    asyncio.run(scenario())


def test_deadline_crossing_before_safe_read_dispatch_records_budget_exhaustion(
    tmp_path: Path,
) -> None:
    async def scenario() -> None:
        database = tmp_path / "read-deadline.sqlite3"
        durable = SqliteDurableRuntimeStore(database)
        envelope = _envelope(max_elapsed_ms=1_000)
        clock = _MutableClock(envelope.ambiguity.observed_at)
        store = _AdvanceClockAfterProbeStartStore(durable, clock)
        handler = _ReadHandler(clock=clock)
        service = _service(
            store,
            _FixedExecutor(handler, clock=clock),
            owner_id="worker-read-deadline",
            clock=clock.now,
        )
        await service.create(envelope)

        async def terminal() -> bool:
            return (
                await durable.get_run(envelope.investigation_id)
            ).state is DurableRunState.TERMINAL

        await _wait_for(terminal)
        assert handler.calls == []
        audits = await durable.controller_audits(envelope.investigation_id)
        assert len(audits) == 1
        assert audits[0].outcome is ProbeOutcome.BUDGET_EXHAUSTED
        assert audits[0].stop_reason is ProbeStopReason.ELAPSED_BUDGET_EXHAUSTED
        await service.aclose()

    asyncio.run(scenario())


def test_safe_read_rechecks_deadline_after_persisted_authority_validation(
    tmp_path: Path,
) -> None:
    async def scenario() -> None:
        durable = SqliteDurableRuntimeStore(tmp_path / "read-validation-delay.sqlite3")
        envelope = _envelope(max_elapsed_ms=1_000)
        clock = _MutableClock(envelope.ambiguity.observed_at)
        store = _AdvanceClockAfterLeaseValidationStore(
            durable,
            clock,
            seconds=2,
        )
        handler = _ReadHandler(clock=clock)
        service = _service(
            store,
            _FixedExecutor(handler, clock=clock),
            owner_id="worker-read-validation-delay",
            clock=clock.now,
        )
        await service.create(envelope)

        async def terminal() -> bool:
            return (
                await durable.get_run(envelope.investigation_id)
            ).state is DurableRunState.TERMINAL

        await _wait_for(terminal)
        assert handler.calls == []
        audits = await durable.controller_audits(envelope.investigation_id)
        assert audits[0].outcome is ProbeOutcome.BUDGET_EXHAUSTED
        assert audits[0].stop_reason is ProbeStopReason.ELAPSED_BUDGET_EXHAUSTED
        await service.aclose()

    asyncio.run(scenario())


@pytest.mark.integration
def test_restart_reuses_a_recorded_read_without_target_redispatch(
    tmp_path: Path,
) -> None:
    async def scenario() -> None:
        database = tmp_path / "runtime.sqlite3"
        store = SqliteDurableRuntimeStore(database)
        envelope = _envelope()
        handler = _ReadHandler()
        pausing = _PauseAfterRecordedExecutor(handler)
        first = _service(store, pausing, owner_id="worker-before-restart")
        await first.create(envelope)
        await asyncio.wait_for(pausing.recorded.wait(), timeout=2)
        assert (await store.probe_checkpoints(envelope.investigation_id))[
            0
        ].state is ProbeCheckpointState.RECORDED
        await first.aclose()

        reopened = SqliteDurableRuntimeStore(database)
        second = _service(
            reopened,
            _PauseAfterRecordedExecutor(handler, pause=False),
            owner_id="worker-after-restart",
        )
        await second.start()

        async def terminal() -> bool:
            return (
                await reopened.get_run(envelope.investigation_id)
            ).state is DurableRunState.TERMINAL

        await _wait_for(terminal)
        assert len(handler.calls) == 1
        assert (await second.get(envelope.investigation_id)).classification is (
            Classification.COMMITTED
        )
        await second.aclose()

    asyncio.run(scenario())


def test_restart_elapsed_audit_includes_precontroller_and_downtime(
    tmp_path: Path,
) -> None:
    async def scenario() -> None:
        database = tmp_path / "runtime-elapsed.sqlite3"
        envelope = _envelope(max_elapsed_ms=30_000)
        clock = _MutableClock(envelope.ambiguity.observed_at)
        first_store = SqliteDurableRuntimeStore(database)
        paused = _PauseBeforeWorkExecutor()
        first = _service(
            first_store,
            paused,
            owner_id="worker-before-elapsed-restart",
            clock=clock.now,
        )
        await first.create(envelope)
        await asyncio.wait_for(paused.started.wait(), timeout=2)
        clock.advance(4)
        await first.aclose()
        clock.advance(3)

        reopened = SqliteDurableRuntimeStore(database)
        second = _service(
            reopened,
            _PauseBeforeWorkExecutor(
                _ReadHandler(clock=clock),
                clock=clock,
                pause=False,
            ),
            owner_id="worker-after-elapsed-restart",
            clock=clock.now,
        )
        await second.start()

        async def terminal() -> bool:
            return (
                await reopened.get_run(envelope.investigation_id)
            ).state is DurableRunState.TERMINAL

        await _wait_for(terminal)
        audits = await reopened.controller_audits(envelope.investigation_id)
        assert len(audits) == 1
        assert audits[0].session_elapsed_ms >= 7_000
        assert audits[0].session_elapsed_ms <= 30_000
        await second.aclose()

    asyncio.run(scenario())


def test_restart_with_non_dispatched_audit_escalates_before_recomputation(
    tmp_path: Path,
) -> None:
    async def scenario() -> None:
        database = tmp_path / "runtime-nondispatched-restart.sqlite3"
        store = SqliteDurableRuntimeStore(database)
        envelope = _envelope()
        paused = _PauseAfterNonDispatchedExecutor()
        first = _service(
            store,
            paused,
            owner_id="worker-before-nondispatched-restart",
        )
        await first.create(envelope)
        await asyncio.wait_for(paused.recorded.wait(), timeout=2)
        assert len(await store.controller_audits(envelope.investigation_id)) == 1
        assert await store.probe_checkpoints(envelope.investigation_id) == ()
        await first.aclose()

        second = _service(
            SqliteDurableRuntimeStore(database),
            _PauseAfterNonDispatchedExecutor(),
            owner_id="worker-after-nondispatched-restart",
        )
        await second.start()

        async def escalated() -> bool:
            return (
                await store.get_run(envelope.investigation_id)
            ).state is DurableRunState.ESCALATION_REQUIRED

        await _wait_for(escalated)
        run = await store.get_run(envelope.investigation_id)
        assert run.recovery_failure_code == (
            "non-dispatched-audit-recovery-unsupported"
        )
        await second.aclose()

    asyncio.run(scenario())


def test_shutdown_release_survives_repeated_cancellation_and_restarts_immediately(
    tmp_path: Path,
) -> None:
    async def scenario() -> None:
        for iteration in range(5):
            database = tmp_path / f"release-race-{iteration}.sqlite3"
            durable = SqliteDurableRuntimeStore(database)
            racing = _RaceReleaseStore(durable)
            envelope = _envelope()
            paused = _PauseBeforeWorkExecutor()
            first = _service(
                racing,
                paused,
                owner_id=f"worker-release-race-{iteration}",
            )
            await first.create(envelope)
            await asyncio.wait_for(paused.started.wait(), timeout=2)

            closing = asyncio.create_task(first.aclose())
            await asyncio.wait_for(racing.release_started.wait(), timeout=2)
            closing.cancel()
            await asyncio.sleep(0)
            racing.allow_release.set()
            with pytest.raises(asyncio.CancelledError):
                await closing

            reopened = SqliteDurableRuntimeStore(database)
            second = _service(
                reopened,
                _PauseBeforeWorkExecutor(_ReadHandler(), pause=False),
                owner_id=f"worker-immediate-restart-{iteration}",
            )
            await second.start()

            async def terminal(
                store=reopened,
                investigation_id=envelope.investigation_id,
            ) -> bool:
                return (
                    await store.get_run(investigation_id)
                ).state is DurableRunState.TERMINAL

            await _wait_for(terminal, timeout=1)
            await second.aclose()

    asyncio.run(scenario())


@pytest.mark.integration
def test_lost_probe_recording_leaves_started_and_repeats_only_the_safe_read(
    tmp_path: Path,
) -> None:
    async def scenario() -> None:
        database = tmp_path / "runtime.sqlite3"
        durable = SqliteDurableRuntimeStore(database)
        failing = _FailRecordOnceStore(durable)
        envelope = _envelope()
        handler = _ReadHandler()
        first = _service(
            failing,
            _FixedExecutor(handler),
            owner_id="worker-lost-record",
        )
        await first.create(envelope)

        async def started_checkpoint() -> bool:
            checkpoints = await durable.probe_checkpoints(envelope.investigation_id)
            return (
                failing.failed
                and bool(checkpoints)
                and (checkpoints[0].state is ProbeCheckpointState.STARTED)
            )

        await _wait_for(started_checkpoint)
        assert failing.failed is True
        assert len(handler.calls) == 1
        await first.aclose()

        reopened = SqliteDurableRuntimeStore(database)
        second = _service(
            reopened,
            _FixedExecutor(handler),
            owner_id="worker-retry-safe-read",
        )
        await second.start()

        async def terminal() -> bool:
            return (
                await reopened.get_run(envelope.investigation_id)
            ).state is DurableRunState.TERMINAL

        await _wait_for(terminal)
        assert len(handler.calls) == 2
        costs = await reopened.cost_snapshot(envelope.investigation_id)
        assert costs.entry_count == 2
        assert costs.probe_count == 2
        assert costs.controller_cost_units == 2
        assert costs.evidence_bytes == 2_048
        await second.aclose()

    asyncio.run(scenario())


@pytest.mark.integration
def test_repeated_safe_read_recovery_consumes_attempt_budget_before_dispatch(
    tmp_path: Path,
) -> None:
    async def scenario() -> None:
        database = tmp_path / "runtime.sqlite3"
        envelope = _envelope()
        handler = _ReadHandler()
        first_store = SqliteDurableRuntimeStore(database)
        first = _service(
            _AlwaysFailRecordStore(first_store),
            _FixedExecutor(handler),
            owner_id="worker-attempt-1",
        )
        await first.create(envelope)
        await _wait_for(lambda: _call_count_is(handler, 1))
        await first.aclose()

        for attempt in (2, 3):
            reopened = SqliteDurableRuntimeStore(database)
            service = _service(
                _AlwaysFailRecordStore(reopened),
                _FixedExecutor(handler),
                owner_id=f"worker-attempt-{attempt}",
            )
            await service.start()
            await _wait_for(lambda attempt=attempt: _call_count_is(handler, attempt))
            await service.aclose()

        final_store = SqliteDurableRuntimeStore(database)
        exhausted = _service(
            _AlwaysFailRecordStore(final_store),
            _FixedExecutor(handler),
            owner_id="worker-attempt-exhausted",
        )
        await exhausted.start()

        async def escalated() -> bool:
            return (
                await final_store.get_run(envelope.investigation_id)
            ).state is DurableRunState.ESCALATION_REQUIRED

        await _wait_for(escalated)
        costs = await final_store.cost_snapshot(envelope.investigation_id)
        assert len(handler.calls) == 3
        assert costs.probe_count == 3
        assert costs.controller_cost_units == 3
        assert costs.evidence_bytes == 3_072
        await exhausted.aclose()

    asyncio.run(scenario())


@pytest.mark.integration
def test_provenance_drift_and_adaptive_restart_fail_closed_before_work(
    tmp_path: Path,
) -> None:
    async def scenario() -> None:
        database = tmp_path / "runtime.sqlite3"
        store = SqliteDurableRuntimeStore(database)
        envelope = _envelope()
        paused = _PauseBeforeWorkExecutor()
        first = _service(store, paused, owner_id="worker-origin")
        await first.create(envelope)
        await asyncio.wait_for(paused.started.wait(), timeout=2)
        await first.aclose()

        drifted = _service(
            SqliteDurableRuntimeStore(database),
            _PauseBeforeWorkExecutor(),
            owner_id="worker-drifted",
            provenance="b" * 64,
        )
        await drifted.start()
        with pytest.raises(DurableServiceUnavailable):
            await drifted.get(envelope.investigation_id)
        await drifted.aclose()

        strategy_drifted = _service(
            SqliteDurableRuntimeStore(database),
            _PauseBeforeWorkExecutor(),
            owner_id="worker-strategy-drifted",
            strategy=DurableExecutionStrategy.ADAPTIVE,
        )
        await strategy_drifted.start()
        with pytest.raises(DurableServiceUnavailable):
            await strategy_drifted.get(envelope.investigation_id)
        await strategy_drifted.aclose()

        adaptive_database = tmp_path / "adaptive-runtime.sqlite3"
        adaptive_store = SqliteDurableRuntimeStore(adaptive_database)
        adaptive_envelope = _envelope()
        adaptive_pause = _PauseBeforeWorkExecutor()
        initial_adaptive = _service(
            adaptive_store,
            adaptive_pause,
            owner_id="worker-adaptive-origin",
            strategy=DurableExecutionStrategy.ADAPTIVE,
            max_provider_calls=1,
        )
        await initial_adaptive.create(adaptive_envelope)
        await asyncio.wait_for(adaptive_pause.started.wait(), timeout=2)
        await initial_adaptive.aclose()

        adaptive = _service(
            SqliteDurableRuntimeStore(adaptive_database),
            _PauseBeforeWorkExecutor(),
            owner_id="worker-adaptive",
            strategy=DurableExecutionStrategy.ADAPTIVE,
            max_provider_calls=1,
        )
        await adaptive.start()

        async def escalated() -> bool:
            return (
                await adaptive_store.get_run(adaptive_envelope.investigation_id)
            ).state is DurableRunState.ESCALATION_REQUIRED

        await _wait_for(escalated)
        with pytest.raises(DurableEscalationRequired):
            await adaptive.get(adaptive_envelope.investigation_id)
        with pytest.raises(DurableEscalationRequired):
            await adaptive.snapshot(adaptive_envelope.investigation_id)
        with pytest.raises(DurableEscalationRequired):
            await adaptive.wait_for_events(adaptive_envelope.investigation_id)
        await adaptive.aclose()

    asyncio.run(scenario())


def test_executor_and_cleanup_implementation_drift_block_active_recovery(
    tmp_path: Path,
) -> None:
    async def scenario() -> None:
        executor_database = tmp_path / "executor-drift.sqlite3"
        envelope = _envelope()
        paused = _PauseBeforeWorkExecutor()
        first = _service(
            SqliteDurableRuntimeStore(executor_database),
            paused,
            owner_id="worker-executor-origin",
        )
        await first.create(envelope)
        await asyncio.wait_for(paused.started.wait(), timeout=2)
        await first.aclose()

        handler = _ReadHandler()
        executor_drifted = _service(
            SqliteDurableRuntimeStore(executor_database),
            _FixedExecutor(handler),
            owner_id="worker-executor-drifted",
        )
        await executor_drifted.start()
        with pytest.raises(DurableServiceUnavailable):
            await executor_drifted.get(envelope.investigation_id)
        assert handler.calls == []
        await executor_drifted.aclose()

        cleanup_database = tmp_path / "cleanup-drift.sqlite3"
        cleanup_envelope = _envelope()
        cleanup_pause = _PauseBeforeWorkExecutor()
        cleanup_origin = _service(
            SqliteDurableRuntimeStore(cleanup_database),
            cleanup_pause,
            owner_id="worker-cleanup-origin",
            cleanup=_CountingCleanup(),
        )
        await cleanup_origin.create(cleanup_envelope)
        await asyncio.wait_for(cleanup_pause.started.wait(), timeout=2)
        await cleanup_origin.aclose()

        cleanup_drifted = _service(
            SqliteDurableRuntimeStore(cleanup_database),
            _PauseBeforeWorkExecutor(),
            owner_id="worker-cleanup-drifted",
            cleanup=_FailingCleanup(),
        )
        await cleanup_drifted.start()
        with pytest.raises(DurableServiceUnavailable):
            await cleanup_drifted.get(cleanup_envelope.investigation_id)
        await cleanup_drifted.aclose()

        with sqlite3.connect(executor_database) as connection:
            row = connection.execute("SELECT sha256 FROM runtime_provenance").fetchone()
        assert row is not None
        assert len(row[0]) == 64
        assert str(tmp_path) not in row[0]

    asyncio.run(scenario())


@pytest.mark.integration
def test_missing_runtime_provenance_binding_blocks_recovery_before_work(
    tmp_path: Path,
) -> None:
    async def scenario() -> None:
        database = tmp_path / "runtime.sqlite3"
        store = SqliteDurableRuntimeStore(database)
        envelope = _envelope()
        pause = _PauseBeforeWorkExecutor()
        first = _service(store, pause, owner_id="worker-before-corruption")
        await first.create(envelope)
        await asyncio.wait_for(pause.started.wait(), timeout=2)
        await first.aclose()

        with sqlite3.connect(database) as connection:
            connection.execute(
                "DELETE FROM runtime_provenance WHERE investigation_id = ?",
                (envelope.investigation_id,),
            )

        handler = _ReadHandler()
        recovered = _service(
            SqliteDurableRuntimeStore(database),
            _FixedExecutor(handler),
            owner_id="worker-after-corruption",
        )
        await recovered.start()
        with pytest.raises(DurableServiceUnavailable):
            await recovered.get(envelope.investigation_id)
        assert handler.calls == []
        await recovered.aclose()

    asyncio.run(scenario())


@pytest.mark.integration
def test_provider_budget_is_charged_before_each_external_call(tmp_path: Path) -> None:
    async def scenario() -> None:
        store = SqliteDurableRuntimeStore(tmp_path / "runtime.sqlite3")
        envelope = _envelope()
        executor = _ProviderBudgetExecutor()
        service = _service(
            store,
            executor,
            owner_id="worker-provider-budget",
            strategy=DurableExecutionStrategy.ADAPTIVE,
            max_provider_calls=1,
        )
        await service.create(envelope)

        async def escalated() -> bool:
            return (
                await store.get_run(envelope.investigation_id)
            ).state is DurableRunState.ESCALATION_REQUIRED

        await _wait_for(escalated)
        costs = await store.cost_snapshot(envelope.investigation_id)
        assert executor.external_calls == 1
        assert costs.provider_calls == 1
        assert costs.estimated_cost_microunits == 40
        await service.aclose()

    asyncio.run(scenario())


@pytest.mark.integration
def test_fixed_strategy_rejects_provider_dispatch_before_external_work(
    tmp_path: Path,
) -> None:
    async def scenario() -> None:
        store = SqliteDurableRuntimeStore(tmp_path / "runtime.sqlite3")
        envelope = _envelope()
        executor = _MeteredAdaptiveExecutor(_ReadHandler())
        service = _service(
            store,
            executor,
            owner_id="worker-fixed-provider",
            strategy=DurableExecutionStrategy.FIXED,
            max_provider_calls=1,
        )
        await service.create(envelope)

        async def escalated() -> bool:
            return (
                await store.get_run(envelope.investigation_id)
            ).state is DurableRunState.ESCALATION_REQUIRED

        await _wait_for(escalated)
        assert executor.external_calls == 0
        costs = await store.cost_snapshot(envelope.investigation_id)
        assert costs.provider_calls == 0
        assert costs.estimated_cost_microunits == 0
        await service.aclose()

    asyncio.run(scenario())


@pytest.mark.integration
@pytest.mark.parametrize(
    "strategy",
    (DurableExecutionStrategy.ADAPTIVE, DurableExecutionStrategy.COMPARE),
)
def test_planner_recovery_never_reenters_after_provider_reservation(
    tmp_path: Path,
    strategy: DurableExecutionStrategy,
) -> None:
    async def scenario() -> None:
        database = tmp_path / f"{strategy.value.lower()}.sqlite3"
        first_store = SqliteDurableRuntimeStore(database)
        envelope = _envelope()
        first_executor = _PauseAfterProviderExecutor()
        first = _service(
            first_store,
            first_executor,
            owner_id=f"worker-{strategy.value.lower()}-first",
            strategy=strategy,
            max_provider_calls=1,
        )
        await first.create(envelope)
        await asyncio.wait_for(first_executor.provider_called.wait(), timeout=2)
        await first.aclose()

        initial_costs = await first_store.cost_snapshot(envelope.investigation_id)
        assert first_executor.executor_calls == 1
        assert first_executor.external_calls == 1
        assert initial_costs.provider_calls == 1
        assert initial_costs.estimated_cost_microunits == 40

        second_executor = _PauseAfterProviderExecutor()
        second_store = SqliteDurableRuntimeStore(database)
        recovered = _service(
            second_store,
            second_executor,
            owner_id=f"worker-{strategy.value.lower()}-second",
            strategy=strategy,
            max_provider_calls=1,
        )
        await recovered.start()

        async def escalated() -> bool:
            return (
                await second_store.get_run(envelope.investigation_id)
            ).state is DurableRunState.ESCALATION_REQUIRED

        await _wait_for(escalated)
        assert second_executor.executor_calls == 0
        assert second_executor.external_calls == 0
        recovered_costs = await second_store.cost_snapshot(envelope.investigation_id)
        assert recovered_costs == initial_costs
        await recovered.aclose()

    asyncio.run(scenario())


@pytest.mark.integration
def test_adaptive_terminal_receipt_matches_exact_provider_ledger(
    tmp_path: Path,
) -> None:
    async def scenario() -> None:
        store = SqliteDurableRuntimeStore(tmp_path / "runtime.sqlite3")
        envelope = _envelope()
        executor = _MeteredAdaptiveExecutor(_ReadHandler())
        service = _service(
            store,
            executor,
            owner_id="worker-provider-receipt",
            strategy=DurableExecutionStrategy.ADAPTIVE,
            max_provider_calls=1,
        )
        await service.create(envelope)

        async def terminal() -> bool:
            return (
                await store.get_run(envelope.investigation_id)
            ).state is DurableRunState.TERMINAL

        await _wait_for(terminal)
        costs = await store.cost_snapshot(envelope.investigation_id)
        assert executor.external_calls == 1
        assert costs.provider_calls == 1
        assert costs.estimated_cost_microunits == 40
        await service.aclose()

    asyncio.run(scenario())


def test_terminal_rejects_renamed_provider_reservation_receipt(
    tmp_path: Path,
) -> None:
    async def scenario() -> None:
        database = tmp_path / "runtime.sqlite3"
        store = SqliteDurableRuntimeStore(database)
        envelope = _envelope()
        inner = _MeteredAdaptiveExecutor(_ReadHandler())
        service = _service(
            store,
            _TamperProviderReceiptExecutor(inner, database),
            owner_id="worker-forged-provider-receipt",
            strategy=DurableExecutionStrategy.ADAPTIVE,
            max_provider_calls=1,
        )
        await service.create(envelope)

        async def escalated() -> bool:
            return (
                await store.get_run(envelope.investigation_id)
            ).state is DurableRunState.ESCALATION_REQUIRED

        await _wait_for(escalated)
        receipts = await store.provider_call_receipts(envelope.investigation_id)
        assert inner.external_calls == 1
        assert tuple(item.call_id for item in receipts) == ("forged",)
        assert (
            await store.get_run(envelope.investigation_id)
        ).established_report is None
        await service.aclose()

    asyncio.run(scenario())


def test_provider_result_crossing_absolute_deadline_is_never_accepted(
    tmp_path: Path,
) -> None:
    async def scenario() -> None:
        database = tmp_path / "runtime-deadline.sqlite3"
        envelope = _envelope(max_elapsed_ms=30_000)
        clock = _MutableClock(envelope.ambiguity.observed_at)
        store = SqliteDurableRuntimeStore(database)
        executor = _DeadlineCrossingProviderExecutor(clock)
        first = _service(
            store,
            executor,
            owner_id="worker-provider-deadline",
            strategy=DurableExecutionStrategy.ADAPTIVE,
            max_provider_calls=1,
            clock=clock.now,
        )
        await first.create(envelope)

        async def first_failed_closed() -> bool:
            try:
                await first.get(envelope.investigation_id)
            except DurableServiceUnavailable:
                return True
            return False

        await _wait_for(first_failed_closed)
        assert executor.external_calls == 1
        assert (
            await store.get_run(envelope.investigation_id)
        ).established_report is None
        await first.aclose()

        second = _service(
            SqliteDurableRuntimeStore(database),
            _DeadlineCrossingProviderExecutor(clock),
            owner_id="worker-provider-deadline-recovery",
            strategy=DurableExecutionStrategy.ADAPTIVE,
            max_provider_calls=1,
            clock=clock.now,
        )
        await second.start()

        async def escalated() -> bool:
            return (
                await store.get_run(envelope.investigation_id)
            ).state is DurableRunState.ESCALATION_REQUIRED

        await _wait_for(escalated)
        receipts = await store.provider_call_receipts(envelope.investigation_id)
        assert tuple(item.call_id for item in receipts) == ("turn-crosses-deadline",)
        await second.aclose()

    asyncio.run(scenario())


def test_cancellation_suppressing_provider_cannot_hold_run_past_deadline(
    tmp_path: Path,
) -> None:
    async def scenario() -> None:
        store = SqliteDurableRuntimeStore(
            tmp_path / "runtime-stubborn-provider.sqlite3"
        )
        envelope = _envelope(max_elapsed_ms=500)
        clock = _MutableClock(envelope.ambiguity.observed_at)
        executor = _CancellationSuppressingProviderExecutor()
        service = _service(
            store,
            executor,
            owner_id="worker-stubborn-provider",
            strategy=DurableExecutionStrategy.ADAPTIVE,
            max_provider_calls=1,
            clock=clock.now,
            monotonic_clock=lambda: 0.0,
        )
        await service.create(envelope)
        await asyncio.wait_for(executor.started.wait(), timeout=2)
        await asyncio.wait_for(executor.cancelled.wait(), timeout=2)

        async def escalated() -> bool:
            return (
                await store.get_run(envelope.investigation_id)
            ).state is DurableRunState.ESCALATION_REQUIRED

        await _wait_for(escalated, timeout=1)
        assert executor.exited.is_set() is False

        reacquired = None

        async def lease_released() -> bool:
            nonlocal reacquired
            try:
                reacquired = await store.acquire_lease(
                    envelope.investigation_id,
                    "worker-after-stubborn-provider",
                    now=datetime.now(UTC),
                )
            except LeaseUnavailable:
                return False
            return True

        await _wait_for(lease_released, timeout=1)
        assert reacquired is not None
        await store.release_lease(reacquired, now=datetime.now(UTC))

        executor.release.set()
        await asyncio.wait_for(executor.exited.wait(), timeout=1)
        await asyncio.sleep(0)
        assert not any(
            task.get_name() == "reconcile-provider-turn-suppresses-cancellation"
            for task in asyncio.all_tasks()
            if not task.done()
        )
        run = await store.get_run(envelope.investigation_id)
        assert run.state is DurableRunState.ESCALATION_REQUIRED
        assert run.established_report is None
        receipts = await store.provider_call_receipts(envelope.investigation_id)
        assert tuple(item.call_id for item in receipts) == (
            "turn-suppresses-cancellation",
        )
        await service.aclose()

    asyncio.run(scenario())


def test_provider_never_dispatches_after_stalled_receipt_lookup_deadline(
    tmp_path: Path,
) -> None:
    async def scenario() -> None:
        durable = SqliteDurableRuntimeStore(tmp_path / "provider-stall.sqlite3")
        envelope = _envelope(max_elapsed_ms=1_000)
        clock = _MutableClock(envelope.ambiguity.observed_at)
        store = _AdvanceClockAfterProviderReceiptStore(durable, clock)
        executor = _SingleProviderExecutor()
        service = _service(
            store,
            executor,
            owner_id="worker-provider-stall",
            strategy=DurableExecutionStrategy.ADAPTIVE,
            max_provider_calls=1,
            clock=clock.now,
        )
        await service.create(envelope)

        async def escalated() -> bool:
            return (
                await durable.get_run(envelope.investigation_id)
            ).state is DurableRunState.ESCALATION_REQUIRED

        await _wait_for(escalated)
        assert executor.external_calls == 0
        receipts = await durable.provider_call_receipts(envelope.investigation_id)
        assert tuple(item.call_id for item in receipts) == ("turn-single",)
        await service.aclose()

    asyncio.run(scenario())


def test_provider_rechecks_deadline_after_persisted_authority_validation(
    tmp_path: Path,
) -> None:
    async def scenario() -> None:
        durable = SqliteDurableRuntimeStore(
            tmp_path / "provider-validation-delay.sqlite3"
        )
        envelope = _envelope(max_elapsed_ms=1_000)
        clock = _MutableClock(envelope.ambiguity.observed_at)
        store = _AdvanceClockAfterLeaseValidationStore(
            durable,
            clock,
            seconds=2,
        )
        executor = _SingleProviderExecutor()
        service = _service(
            store,
            executor,
            owner_id="worker-provider-validation-delay",
            strategy=DurableExecutionStrategy.ADAPTIVE,
            max_provider_calls=1,
            clock=clock.now,
        )
        await service.create(envelope)

        async def escalated() -> bool:
            return (
                await durable.get_run(envelope.investigation_id)
            ).state is DurableRunState.ESCALATION_REQUIRED

        await _wait_for(escalated)
        assert executor.external_calls == 0
        await service.aclose()

    asyncio.run(scenario())


def test_wall_clock_regression_cannot_reopen_provider_elapsed_budget(
    tmp_path: Path,
) -> None:
    async def scenario() -> None:
        store = SqliteDurableRuntimeStore(
            tmp_path / "provider-clock-regression.sqlite3"
        )
        envelope = _envelope(max_elapsed_ms=1_000)
        clock = _MutableClock(envelope.ambiguity.observed_at)
        executor = _RegressedClockProviderExecutor(clock)
        service = _service(
            store,
            executor,
            owner_id="worker-provider-clock-regression",
            strategy=DurableExecutionStrategy.ADAPTIVE,
            max_provider_calls=1,
            clock=clock.now,
        )
        await service.create(envelope)

        async def escalated() -> bool:
            return (
                await store.get_run(envelope.investigation_id)
            ).state is DurableRunState.ESCALATION_REQUIRED

        await _wait_for(escalated)
        assert 900 <= executor.elapsed_floor_ms <= 1_000
        assert 0 < executor.remaining_ms <= 100
        assert executor.external_calls == 0
        receipts = await store.provider_call_receipts(envelope.investigation_id)
        assert tuple(item.call_id for item in receipts) == ("turn-regressed-clock",)
        await service.aclose()

    asyncio.run(scenario())


def test_provider_originated_cancellation_escalates_instead_of_stranding_active(
    tmp_path: Path,
) -> None:
    async def scenario() -> None:
        store = SqliteDurableRuntimeStore(tmp_path / "provider-cancelled.sqlite3")
        envelope = _envelope()
        executor = _SelfCancellingProviderExecutor()
        service = _service(
            store,
            executor,
            owner_id="worker-provider-self-cancelled",
            strategy=DurableExecutionStrategy.ADAPTIVE,
            max_provider_calls=1,
        )
        await service.create(envelope)

        async def escalated() -> bool:
            return (
                await store.get_run(envelope.investigation_id)
            ).state is DurableRunState.ESCALATION_REQUIRED

        await _wait_for(escalated)
        run = await store.get_run(envelope.investigation_id)
        assert run.recovery_failure_code == "durable-execution-failed"
        assert executor.external_calls == 1
        receipts = await store.provider_call_receipts(envelope.investigation_id)
        assert tuple(item.call_id for item in receipts) == ("turn-self-cancelled",)
        await service.aclose()

    asyncio.run(scenario())


def test_provider_takeover_before_operation_prevents_stale_dispatch(
    tmp_path: Path,
) -> None:
    async def scenario() -> None:
        database = tmp_path / "provider-takeover.sqlite3"
        durable = SqliteDurableRuntimeStore(database)
        envelope = _envelope(max_elapsed_ms=60_000)
        clock = _MutableClock(envelope.ambiguity.observed_at)
        takeover_store = _TakeoverAfterProviderReceiptStore(durable, clock)
        first_executor = _SingleProviderExecutor()
        first = _service(
            takeover_store,
            first_executor,
            owner_id="worker-before-provider-takeover",
            strategy=DurableExecutionStrategy.ADAPTIVE,
            max_provider_calls=1,
            clock=clock.now,
        )
        await first.create(envelope)
        await asyncio.wait_for(takeover_store.takeover_acquired.wait(), timeout=2)

        async def unavailable() -> bool:
            try:
                await first.get(envelope.investigation_id)
            except DurableServiceUnavailable:
                return True
            return False

        await _wait_for(unavailable)
        assert first_executor.external_calls == 0
        assert (await durable.get_run(envelope.investigation_id)).state is (
            DurableRunState.ACTIVE
        )
        assert takeover_store.takeover is not None
        await first.aclose()
        await durable.release_lease(takeover_store.takeover, now=clock.now())

        recovered_executor = _SingleProviderExecutor()
        recovered = _service(
            SqliteDurableRuntimeStore(database),
            recovered_executor,
            owner_id="worker-after-provider-takeover",
            strategy=DurableExecutionStrategy.ADAPTIVE,
            max_provider_calls=1,
            clock=clock.now,
        )
        await recovered.start()

        async def escalated() -> bool:
            return (
                await durable.get_run(envelope.investigation_id)
            ).state is DurableRunState.ESCALATION_REQUIRED

        await _wait_for(escalated)
        assert recovered_executor.external_calls == 0
        receipts = await durable.provider_call_receipts(envelope.investigation_id)
        assert tuple(item.call_id for item in receipts) == ("turn-single",)
        await recovered.aclose()

    asyncio.run(scenario())


@pytest.mark.integration
def test_consumed_provider_call_identifier_never_dispatches_twice(
    tmp_path: Path,
) -> None:
    async def scenario() -> None:
        store = SqliteDurableRuntimeStore(tmp_path / "runtime.sqlite3")
        envelope = _envelope()
        executor = _DuplicateProviderCallExecutor()
        service = _service(
            store,
            executor,
            owner_id="worker-provider-duplicate",
            strategy=DurableExecutionStrategy.ADAPTIVE,
            max_provider_calls=2,
        )
        await service.create(envelope)

        async def escalated() -> bool:
            return (
                await store.get_run(envelope.investigation_id)
            ).state is DurableRunState.ESCALATION_REQUIRED

        await _wait_for(escalated)
        costs = await store.cost_snapshot(envelope.investigation_id)
        assert executor.external_calls == 1
        assert costs.provider_calls == 1
        assert costs.estimated_cost_microunits == 40
        await service.aclose()

    asyncio.run(scenario())


def test_synchronous_provider_failure_clears_inflight_receipt_state(
    tmp_path: Path,
) -> None:
    async def scenario() -> None:
        store = SqliteDurableRuntimeStore(tmp_path / "runtime-sync-provider.sqlite3")
        envelope = _envelope()
        executor = _SyncProviderFailureThenFixedExecutor(_ReadHandler())
        service = _service(
            store,
            executor,
            owner_id="worker-sync-provider-failure",
            strategy=DurableExecutionStrategy.ADAPTIVE,
            max_provider_calls=1,
        )
        await service.create(envelope)

        async def terminal() -> bool:
            return (
                await store.get_run(envelope.investigation_id)
            ).state is DurableRunState.TERMINAL

        await _wait_for(terminal)
        receipts = await store.provider_call_receipts(envelope.investigation_id)
        assert executor.external_calls == 1
        assert tuple(item.call_id for item in receipts) == ("turn-sync-failure",)
        await service.aclose()

    asyncio.run(scenario())


@pytest.mark.integration
def test_terminal_restart_repairs_partial_telemetry_and_event_projection(
    tmp_path: Path,
) -> None:
    async def scenario() -> None:
        database = tmp_path / "runtime.sqlite3"
        durable = SqliteDurableRuntimeStore(database)
        interrupted = _FailClassifierTelemetryOnceStore(durable)
        envelope = _envelope()
        handler = _ReadHandler()
        first = _service(
            interrupted,
            _FixedExecutor(handler),
            owner_id="worker-telemetry-interrupted",
        )
        await first.create(envelope)

        async def interrupted_after_terminal() -> bool:
            run = await durable.get_run(envelope.investigation_id)
            return interrupted.failed and run.state is DurableRunState.TERMINAL

        await _wait_for(interrupted_after_terminal)
        established = await durable.get_run(envelope.investigation_id)
        assert established.classification is Classification.COMMITTED
        assert (
            await durable.snapshot_events(envelope.investigation_id)
        ).terminal is False
        await first.aclose()

        reopened = SqliteDurableRuntimeStore(database)
        second = _service(
            reopened,
            _FixedExecutor(handler),
            owner_id="worker-telemetry-repair",
        )
        await second.start()

        async def projection_complete() -> bool:
            return (await reopened.snapshot_events(envelope.investigation_id)).terminal

        await _wait_for(projection_complete)
        telemetry = await reopened.telemetry_records(envelope.investigation_id)
        assert len(handler.calls) == 1
        assert any(item.kind is RuntimeTelemetryKind.CLASSIFIER for item in telemetry)
        assert (
            await reopened.get_run(envelope.investigation_id)
        ).classification is Classification.COMMITTED
        await second.aclose()

    asyncio.run(scenario())


@pytest.mark.integration
def test_telemetry_identifier_collision_fails_closed_without_overwrite(
    tmp_path: Path,
) -> None:
    async def scenario() -> None:
        database = tmp_path / "runtime.sqlite3"
        store = SqliteDurableRuntimeStore(database)
        envelope = _envelope()
        pause = _PauseBeforeWorkExecutor()
        first = _service(store, pause, owner_id="worker-before-collision")
        await first.create(envelope)
        await asyncio.wait_for(pause.started.wait(), timeout=2)
        await first.aclose()

        run = await store.get_run(envelope.investigation_id)
        now = max(datetime.now(UTC), run.updated_at)
        lease = await store.acquire_lease(
            envelope.investigation_id,
            "collision-writer",
            now=now,
        )
        forged = RuntimeTelemetryRecord(
            schema_version=RUNTIME_TELEMETRY_VERSION,
            investigation_id=envelope.investigation_id,
            telemetry_id="classification",
            sequence=2,
            kind=RuntimeTelemetryKind.RUN,
            occurred_at=now,
            trace_id="trace-forged",
            span_id="span-forged",
            outcome="forged",
        )
        await store.append_telemetry(lease, forged, now=now)
        await store.release_lease(lease, now=now)

        second = _service(
            SqliteDurableRuntimeStore(database),
            _PauseBeforeWorkExecutor(_ReadHandler(), pause=False),
            owner_id="worker-detecting-collision",
        )
        await second.start()

        async def unavailable() -> bool:
            try:
                await second.get(envelope.investigation_id)
            except DurableServiceUnavailable:
                return True
            return False

        await _wait_for(unavailable)
        records = await store.telemetry_records(envelope.investigation_id)
        collision = next(
            item for item in records if item.telemetry_id == "classification"
        )
        assert collision == forged
        assert (await store.get_run(envelope.investigation_id)).state is (
            DurableRunState.TERMINAL
        )
        assert (
            await store.snapshot_events(envelope.investigation_id)
        ).terminal is False
        await second.aclose()

    asyncio.run(scenario())


@pytest.mark.integration
def test_cleanup_identity_drift_blocks_late_addition_and_pending_is_never_retried(
    tmp_path: Path,
) -> None:
    async def scenario() -> None:
        first_database = tmp_path / "unrequested.sqlite3"
        first_store = SqliteDurableRuntimeStore(first_database)
        first_envelope = _envelope()
        first_handler = _ReadHandler()
        without_cleanup = _service(
            first_store,
            _FixedExecutor(first_handler),
            owner_id="worker-no-cleanup",
        )
        await without_cleanup.create(first_envelope)

        async def first_terminal() -> bool:
            return (
                await first_store.get_run(first_envelope.investigation_id)
            ).state is DurableRunState.TERMINAL

        await _wait_for(first_terminal)
        await without_cleanup.aclose()
        delayed_cleanup = _CountingCleanup()
        resumed = _service(
            SqliteDurableRuntimeStore(first_database),
            _FixedExecutor(first_handler),
            owner_id="worker-delayed-cleanup",
            cleanup=delayed_cleanup,
        )
        await resumed.start()

        with pytest.raises(DurableServiceUnavailable):
            await resumed.get(first_envelope.investigation_id)
        assert delayed_cleanup.calls == 0
        assert (
            await first_store.get_run(first_envelope.investigation_id)
        ).cleanup_status is CleanupStatus.NOT_REQUESTED
        await resumed.aclose()

        second_database = tmp_path / "pending.sqlite3"
        second_store = SqliteDurableRuntimeStore(second_database)
        second_envelope = _envelope()
        blocking_cleanup = _BlockingCleanup()
        second = _service(
            second_store,
            _FixedExecutor(_ReadHandler()),
            owner_id="worker-cleanup-unknown",
            cleanup=blocking_cleanup,
        )
        await second.create(second_envelope)
        await asyncio.wait_for(blocking_cleanup.started.wait(), timeout=2)
        pending = await second_store.get_run(second_envelope.investigation_id)
        assert pending.state is DurableRunState.TERMINAL
        assert pending.cleanup_status is CleanupStatus.PENDING
        await second.aclose()

        must_not_repeat = _BlockingCleanup()
        recovered = _service(
            SqliteDurableRuntimeStore(second_database),
            _FixedExecutor(_ReadHandler()),
            owner_id="worker-cleanup-fail-closed",
            cleanup=must_not_repeat,
        )
        await recovered.start()

        async def unknown_visible() -> bool:
            return (
                await second_store.get_run(second_envelope.investigation_id)
            ).cleanup_status is CleanupStatus.FAILED

        await _wait_for(unknown_visible)
        final = await second_store.get_run(second_envelope.investigation_id)
        assert final.cleanup_failure_code == "cleanup-outcome-unknown"
        assert final.classification is Classification.COMMITTED
        assert must_not_repeat.started.is_set() is False
        await recovered.aclose()

    asyncio.run(scenario())


def test_cleanup_takeover_after_pending_prevents_stale_external_dispatch(
    tmp_path: Path,
) -> None:
    async def scenario() -> None:
        database = tmp_path / "cleanup-takeover.sqlite3"
        durable = SqliteDurableRuntimeStore(database)
        envelope = _envelope(max_elapsed_ms=120_000)
        clock = _MutableClock(envelope.ambiguity.observed_at)
        takeover_store = _TakeoverAfterCleanupPendingStore(durable, clock)
        first_cleanup = _CountingCleanup()
        first = _service(
            takeover_store,
            _FixedExecutor(_ReadHandler(clock=clock), clock=clock),
            owner_id="worker-before-cleanup-takeover",
            cleanup=first_cleanup,
            clock=clock.now,
        )
        await first.create(envelope)
        await asyncio.wait_for(takeover_store.takeover_acquired.wait(), timeout=2)

        async def unavailable() -> bool:
            try:
                await first.get(envelope.investigation_id)
            except DurableServiceUnavailable:
                return True
            return False

        await _wait_for(unavailable)
        assert first_cleanup.calls == 0
        pending = await durable.get_run(envelope.investigation_id)
        assert pending.state is DurableRunState.TERMINAL
        assert pending.cleanup_status is CleanupStatus.PENDING
        assert takeover_store.takeover is not None
        await first.aclose()
        await durable.release_lease(takeover_store.takeover, now=clock.now())

        recovered_cleanup = _CountingCleanup()
        recovered = _service(
            SqliteDurableRuntimeStore(database),
            _FixedExecutor(_ReadHandler(clock=clock), clock=clock),
            owner_id="worker-after-cleanup-takeover",
            cleanup=recovered_cleanup,
            clock=clock.now,
        )
        await recovered.start()

        async def unknown_recorded() -> bool:
            return (
                await durable.get_run(envelope.investigation_id)
            ).cleanup_status is CleanupStatus.FAILED

        await _wait_for(unknown_recorded)
        final = await durable.get_run(envelope.investigation_id)
        assert final.cleanup_failure_code == "cleanup-outcome-unknown"
        assert recovered_cleanup.calls == 0
        await recovered.aclose()

    asyncio.run(scenario())
