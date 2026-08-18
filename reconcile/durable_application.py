"""Fenced durable ownership for the investigation application lifecycle."""

from __future__ import annotations

import asyncio
import hashlib
import time
from collections.abc import AsyncIterator, Awaitable, Callable
from contextlib import asynccontextmanager, suppress
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from itertools import pairwise
from typing import Protocol
from uuid import uuid4

from reconcile.application import CreateInvestigationResult
from reconcile.contracts.api import (
    INVESTIGATION_EVENT_VERSION,
    ActionGateEventPayload,
    ClassificationEventPayload,
    EvidenceDecisionEventPayload,
    InvestigationEvent,
    InvestigationEventPayload,
    InvestigationEventType,
    LifecycleEventPayload,
    ProbeEventPayload,
)
from reconcile.contracts.codec import (
    canonical_json_bytes,
    decode_contract,
)
from reconcile.contracts.envelope import ExecutionEnvelope, ProbeRequest
from reconcile.contracts.report import (
    INVESTIGATION_REPORT_VERSION,
    InvestigationReport,
    InvestigationStatus,
    ProbeAuditRecord,
)
from reconcile.controller import (
    CapabilityRegistry,
    ControllerAuditRecord,
    ControllerClock,
    ProbeController,
    ProbeDurabilityObserver,
    ProbeExecution,
    ProbeObservation,
    RestoredProbe,
    probe_request_sha256,
)
from reconcile.persistence.durable import (
    RUNTIME_TELEMETRY_VERSION,
    BudgetExceeded,
    CleanupStatus,
    DurableRunRecord,
    DurableRunState,
    DurableRuntimeError,
    DurableRuntimeStore,
    LeaseToken,
    LeaseUnavailable,
    ProbeCheckpointState,
    ProbeReplaySafety,
    ProviderCallReceipt,
    RuntimeCostDelta,
    RuntimeTelemetryKind,
    RuntimeTelemetryRecord,
    StaleLease,
    runtime_limits_for,
)
from reconcile.persistence.events import EventJournalSnapshot
from reconcile.runtime_provenance import build_runtime_provenance


class DurableExecutionStrategy(StrEnum):
    FIXED = "FIXED"
    ADAPTIVE = "ADAPTIVE"
    COMPARE = "COMPARE"


class DurableApplicationError(RuntimeError):
    """Base class for application-level durable lifecycle failures."""


class DurableDependencyDrift(DurableApplicationError):
    def __init__(self, investigation_id: str) -> None:
        self.investigation_id = investigation_id
        super().__init__(f"durable probe plan drifted: {investigation_id}")


class DurableServiceUnavailable(DurableApplicationError):
    pass


class DurableEscalationRequired(DurableApplicationError):
    def __init__(self, investigation_id: str) -> None:
        self.investigation_id = investigation_id
        super().__init__(f"durable recovery requires escalation: {investigation_id}")


class _RecoverableProbeRecordingError(DurableApplicationError):
    pass


def _allows_zero_provider_receipts(
    strategy: DurableExecutionStrategy,
    run: DurableRunRecord,
    report: InvestigationReport,
) -> bool:
    """Admit only sealed sandbox outcomes that stopped before provider dispatch."""

    if strategy is not DurableExecutionStrategy.ADAPTIVE:
        return False

    # Keep the durable core independent of scenario imports during module loading.
    # This boundary is reached only after the report and its envelope are sealed.
    from reconcile.adapters.sandbox_order import SANDBOX_ORDER_TARGET_KIND
    from reconcile.contracts import (
        Classification,
        ScenarioHybridOutcome,
        ScenarioHybridRoute,
    )
    from reconcile.scenarios.service import bounded_hybrid_route_provenance

    if run.envelope.target.target_kind != SANDBOX_ORDER_TARGET_KIND:
        return False
    provenance = bounded_hybrid_route_provenance(report)
    if (
        provenance is None
        or provenance.route is not ScenarioHybridRoute.PLANNER_HETEROGENEOUS
        or provenance.planner_invoked
    ):
        return False
    if provenance.outcome is ScenarioHybridOutcome.FIXED_FALLBACK:
        return provenance.fixed_connector_invoked and provenance.provider_failure
    return (
        provenance.outcome is ScenarioHybridOutcome.EXPLICIT_UNKNOWN
        and report.classification is Classification.UNKNOWN
        and not provenance.fixed_connector_invoked
        and not provenance.provider_failure
    )


_EXECUTION_OUTCOME_SEAL = object()


@dataclass(frozen=True, slots=True, init=False)
class DurableExecutionOutcome:
    """Terminal report plus an unforgeable receipt from the metered context."""

    investigation_id: str
    report: InvestigationReport
    provider_call_receipts: tuple[ProviderCallReceipt, ...]

    def __init__(
        self,
        *,
        investigation_id: str,
        report: InvestigationReport,
        provider_call_receipts: tuple[ProviderCallReceipt, ...],
        _seal: object,
    ) -> None:
        if _seal is not _EXECUTION_OUTCOME_SEAL:
            raise TypeError("durable outcomes are issued only by the runtime context")
        object.__setattr__(self, "investigation_id", investigation_id)
        object.__setattr__(self, "report", report)
        if any(
            type(item) is not ProviderCallReceipt for item in provider_call_receipts
        ):
            raise TypeError("provider call receipts must be exact")
        object.__setattr__(
            self,
            "provider_call_receipts",
            provider_call_receipts,
        )


class DurableInvestigationExecutor(Protocol):
    """Trusted executor whose advisory provider I/O crosses only the runtime seam."""

    async def __call__(
        self,
        envelope: ExecutionEnvelope,
        *,
        revision: int,
        cancellation_event: asyncio.Event,
        runtime: DurableExecutionContext,
    ) -> DurableExecutionOutcome: ...


class DurableCleanup(Protocol):
    async def __call__(
        self,
        envelope: ExecutionEnvelope,
        report: InvestigationReport,
    ) -> None: ...


def _aware_utc(value: datetime) -> datetime:
    if (
        not isinstance(value, datetime)
        or value.tzinfo is None
        or value.utcoffset() is None
    ):
        raise ValueError("durable application timestamps must be timezone-aware")
    return value.astimezone(UTC)


class _LeaseAuthority:
    def __init__(
        self,
        store: DurableRuntimeStore,
        lease: LeaseToken,
        clock: Callable[[], datetime],
    ) -> None:
        self._store = store
        self._lease = lease
        self._clock = clock
        self._lock = asyncio.Lock()
        self._released = False

    @property
    def investigation_id(self) -> str:
        return self._lease.investigation_id

    @asynccontextmanager
    async def hold(self, occurred_at: datetime) -> AsyncIterator[LeaseToken]:
        occurred_at = _aware_utc(occurred_at)
        async with self._lock:
            if self._released:
                raise StaleLease(self._lease.investigation_id)
            if occurred_at < self._lease.renewed_at:
                occurred_at = self._lease.renewed_at
            if self._lease.renewal_due(occurred_at):
                self._lease = await self._store.renew_lease(
                    self._lease,
                    now=occurred_at,
                )
            if self._lease.expired(occurred_at):
                raise StaleLease(self._lease.investigation_id)
            yield self._lease

    async def renew(self) -> None:
        now = _aware_utc(self._clock())
        async with self._lock:
            if self._released:
                return
            if self._lease.renewal_due(now):
                self._lease = await self._store.renew_lease(
                    self._lease,
                    now=now,
                )

    async def release(self) -> None:
        now = _aware_utc(self._clock())
        async with self._lock:
            if self._released:
                return
            if now < self._lease.renewed_at:
                now = self._lease.renewed_at
            try:
                await self._store.release_lease(self._lease, now=now)
            except StaleLease:
                pass
            self._released = True


class DurableExecutionContext(ProbeDurabilityObserver):
    """Controller-bound checkpoint, cost, and telemetry operations for one run."""

    def __init__(
        self,
        store: DurableRuntimeStore,
        authority: _LeaseAuthority,
        run: DurableRunRecord,
        *,
        strategy: DurableExecutionStrategy,
        clock: Callable[[], datetime],
        monotonic_clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self._store = store
        self._authority = authority
        self._run = run
        self._strategy = strategy
        self._clock = clock
        self._monotonic_clock = monotonic_clock
        digest = hashlib.sha256(run.investigation_id.encode("utf-8")).hexdigest()
        self._trace_id = f"trace-{digest[:24]}"
        self._provider_call_ids: set[str] = set()
        self._charged_provider_receipts: list[ProviderCallReceipt] = []
        self._provider_calls_in_flight: set[str] = set()
        self._detached_provider_tasks: set[asyncio.Task] = set()
        self._provider_deadline_exhausted = False
        self._provider_call_lock = asyncio.Lock()
        budget_ms = self._run.envelope.context.evidence_budget.max_elapsed_ms
        initial_wall_ms = max(
            0,
            int(
                (_aware_utc(self._clock()) - self._run.created_at).total_seconds()
                * 1_000
            ),
        )
        self._elapsed_floor_high_water_ms = min(initial_wall_ms, budget_ms)
        self._elapsed_monotonic_base_ms = self._elapsed_floor_high_water_ms
        self._elapsed_monotonic_anchor = self._monotonic_clock()

    def controller(
        self,
        capabilities: CapabilityRegistry,
        *,
        clock: ControllerClock | None = None,
    ) -> ProbeController:
        """Construct the only controller path whose reads are durably fenced."""

        return ProbeController(
            self._run.envelope,
            capabilities,
            clock=clock,
            durability_observer=self,
        )

    def _effective_elapsed_ms(self, now: datetime) -> int:
        trusted_now = max(_aware_utc(now), _aware_utc(self._clock()))
        budget_ms = self._run.envelope.context.evidence_budget.max_elapsed_ms
        wall_elapsed_ms = max(
            0,
            int((trusted_now - self._run.created_at).total_seconds() * 1_000),
        )
        monotonic_now = self._monotonic_clock()
        monotonic_elapsed_ms = self._elapsed_monotonic_base_ms + max(
            0,
            int((monotonic_now - self._elapsed_monotonic_anchor) * 1_000),
        )
        measured = max(
            self._elapsed_floor_high_water_ms,
            wall_elapsed_ms,
            monotonic_elapsed_ms,
        )
        if wall_elapsed_ms > monotonic_elapsed_ms:
            self._elapsed_monotonic_base_ms = wall_elapsed_ms
            self._elapsed_monotonic_anchor = monotonic_now
        self._elapsed_floor_high_water_ms = min(measured, budget_ms)
        return self._elapsed_floor_high_water_ms

    def remaining_elapsed_ms(self, now: datetime) -> int:
        budget_ms = self._run.envelope.context.evidence_budget.max_elapsed_ms
        return max(0, budget_ms - self._effective_elapsed_ms(now))

    def elapsed_floor_ms(self, now: datetime) -> int:
        return self._effective_elapsed_ms(now)

    async def _telemetry(
        self,
        telemetry_id: str,
        kind: RuntimeTelemetryKind,
        outcome: str,
        *,
        occurred_at: datetime,
        probe_sequence: int | None = None,
        evidence_id: str | None = None,
        classification=None,
        requested_action=None,
        attributes: dict[str, object] | None = None,
    ) -> RuntimeTelemetryRecord:
        occurred_at = _aware_utc(occurred_at)
        now = _aware_utc(self._clock())
        async with self._authority.hold(now) as lease:
            records = await self._store.telemetry_records(self._run.investigation_id)
            existing = next(
                (record for record in records if record.telemetry_id == telemetry_id),
                None,
            )
            sequence = len(records) + 1 if existing is None else existing.sequence
            record = RuntimeTelemetryRecord(
                schema_version=RUNTIME_TELEMETRY_VERSION,
                investigation_id=self._run.investigation_id,
                telemetry_id=telemetry_id,
                sequence=sequence,
                kind=kind,
                occurred_at=occurred_at,
                trace_id=self._trace_id,
                span_id=f"span-{sequence}",
                outcome=outcome,
                probe_sequence=probe_sequence,
                evidence_id=evidence_id,
                classification=classification,
                requested_action=requested_action,
                attributes={} if attributes is None else attributes,
            )
            if existing is not None:
                if existing != record:
                    raise DurableDependencyDrift(self._run.investigation_id)
                return existing
            return await self._store.append_telemetry(lease, record, now=now)

    async def before_dispatch(
        self,
        request: ProbeRequest,
        *,
        sequence: int,
        controller_cost_units: int,
        evidence_byte_reservation: int,
        started_at: datetime,
    ) -> RestoredProbe | None:
        request = decode_contract(canonical_json_bytes(request), ProbeRequest)
        checkpoints = await self._store.probe_checkpoints(self._run.investigation_id)
        existing = next(
            (
                checkpoint
                for checkpoint in checkpoints
                if checkpoint.step_sequence == sequence
            ),
            None,
        )
        request_digest = probe_request_sha256(request)
        checkpoint_id = f"read-{sequence}-{request_digest[:16]}"
        if existing is not None and (
            existing.step_sequence != sequence
            or existing.checkpoint_id != checkpoint_id
            or existing.request_sha256 != request_digest
            or existing.replay_safety is not ProbeReplaySafety.SAFE_READ
        ):
            raise DurableDependencyDrift(self._run.investigation_id)
        if (
            existing is None
            and checkpoints
            and sequence <= checkpoints[-1].step_sequence
        ):
            raise DurableDependencyDrift(self._run.investigation_id)
        if existing is not None and existing.request != request:
            raise DurableDependencyDrift(self._run.investigation_id)
        if existing is not None and existing.state is ProbeCheckpointState.RECORDED:
            if existing.audit is None:
                raise DurableDependencyDrift(self._run.investigation_id)
            audits = await self._store.controller_audits(self._run.investigation_id)
            if sequence > len(audits) or audits[sequence - 1] != existing.audit:
                raise DurableDependencyDrift(self._run.investigation_id)
            return RestoredProbe(
                audit=existing.audit,
                observation=existing.observation,
            )
        audits = await self._store.controller_audits(self._run.investigation_id)
        if sequence <= len(audits):
            raise DurableDependencyDrift(self._run.investigation_id)

        started_at = _aware_utc(started_at)
        occurred_at = max(started_at, _aware_utc(self._clock()))
        delta = RuntimeCostDelta(
            probe_count=1,
            evidence_bytes=evidence_byte_reservation,
            controller_cost_units=controller_cost_units,
        )
        async with self._authority.hold(occurred_at) as lease:
            occurred_at = max(occurred_at, lease.renewed_at)
            await self._store.charge(
                lease,
                entry_id=f"reserve-{checkpoint_id}-{uuid4().hex}",
                category="safe-read-reservation",
                occurred_at=occurred_at,
                delta=delta,
            )
            checkpoint = await self._store.start_probe(
                lease,
                checkpoint_id=checkpoint_id,
                step_sequence=sequence,
                request=request,
                replay_safety=ProbeReplaySafety.SAFE_READ,
                started_at=started_at,
                now=occurred_at,
            )
        if checkpoint.state is ProbeCheckpointState.RECORDED:
            raise DurableDependencyDrift(self._run.investigation_id)
        return None

    async def after_dispatch(
        self,
        request: ProbeRequest,
        execution: ProbeExecution,
    ) -> None:
        request_digest = probe_request_sha256(request)
        checkpoint_id = f"read-{execution.audit.sequence}-{request_digest[:16]}"
        observation: ProbeObservation | None = None
        if execution.observation is not None:
            observation = ProbeObservation.model_validate_json(
                execution.observation.canonical_json
            )
        recorded_at = max(
            _aware_utc(self._clock()),
            execution.audit.completed_at.astimezone(UTC),
        )
        try:
            async with self._authority.hold(recorded_at) as lease:
                await self._store.record_probe(
                    lease,
                    checkpoint_id,
                    audit=execution.audit,
                    observation=observation,
                    recorded_at=recorded_at,
                )
        except DurableRuntimeError:
            raise
        except Exception as error:
            raise _RecoverableProbeRecordingError from error

    async def after_execution(self, execution: ProbeExecution) -> None:
        recorded_at = max(
            _aware_utc(self._clock()),
            execution.audit.completed_at.astimezone(UTC),
        )
        async with self._authority.hold(recorded_at) as lease:
            await self._store.record_controller_audit(
                lease,
                execution.audit,
                recorded_at=recorded_at,
            )

    async def authorize_dispatch(
        self,
        request: ProbeRequest,
        *,
        sequence: int,
        dispatched_at: datetime,
    ) -> bool:
        """Revalidate the durable fence immediately before handler invocation."""

        request = decode_contract(canonical_json_bytes(request), ProbeRequest)
        request_digest = probe_request_sha256(request)
        checkpoint_id = f"read-{sequence}-{request_digest[:16]}"
        checkpoints = await self._store.probe_checkpoints(self._run.investigation_id)
        checkpoint = next(
            (item for item in checkpoints if item.step_sequence == sequence),
            None,
        )
        if (
            checkpoint is None
            or checkpoint.checkpoint_id != checkpoint_id
            or checkpoint.request != request
            or checkpoint.state is not ProbeCheckpointState.STARTED
        ):
            raise DurableDependencyDrift(self._run.investigation_id)
        now = max(_aware_utc(dispatched_at), _aware_utc(self._clock()))
        if self.remaining_elapsed_ms(now) <= 0:
            return False
        async with self._authority.hold(now) as lease:
            # This persisted check is intentionally the final await before the
            # controller calls the handler. It prevents an already-completed
            # takeover from being followed by stale-worker external dispatch.
            # It is not a downstream fencing token: SAFE_READ remains the only
            # replayable overlap class when a remote takeover races afterward.
            await self._store.validate_lease(lease, now=now)
            dispatch_at = _aware_utc(self._clock())
            if lease.expired(dispatch_at):
                raise StaleLease(self._run.investigation_id)
            if self.remaining_elapsed_ms(dispatch_at) <= 0:
                return False
        return True

    async def call_provider[Result](
        self,
        call_id: str,
        *,
        estimated_cost_microunits: int,
        operation: Callable[[], Awaitable[Result]],
    ) -> Result:
        """Charge one advisory provider call before one bounded invocation attempt."""

        if type(call_id) is not str or not call_id:
            raise ValueError("provider call identifier must be a nonempty string")
        if self._strategy is DurableExecutionStrategy.FIXED:
            raise DurableDependencyDrift(self._run.investigation_id)

        async with self._provider_call_lock:
            if call_id in self._provider_call_ids:
                raise DurableDependencyDrift(self._run.investigation_id)
            self._provider_call_ids.add(call_id)
            occurred_at = _aware_utc(self._clock())
            async with self._authority.hold(occurred_at) as lease:
                await self._store.reserve_provider_call(
                    lease,
                    call_id=call_id,
                    occurred_at=occurred_at,
                    estimated_cost_microunits=estimated_cost_microunits,
                )
                receipts = await self._store.provider_call_receipts(
                    self._run.investigation_id
                )
            if (
                len(receipts) != len(self._charged_provider_receipts) + 1
                or receipts[:-1] != tuple(self._charged_provider_receipts)
                or receipts[-1].call_id != call_id
                or receipts[-1].estimated_cost_microunits != estimated_cost_microunits
            ):
                raise DurableDependencyDrift(self._run.investigation_id)
            self._charged_provider_receipts.append(receipts[-1])
            self._provider_calls_in_flight.add(call_id)
        remaining_ms = self.remaining_elapsed_ms(_aware_utc(self._clock()))
        if remaining_ms <= 0:
            self._provider_calls_in_flight.discard(call_id)
            self._provider_deadline_exhausted = True
            raise BudgetExceeded(self._run.investigation_id, "deadline")

        async def invoke_provider() -> Result:
            now = _aware_utc(self._clock())
            if self.remaining_elapsed_ms(now) <= 0:
                self._provider_deadline_exhausted = True
                raise BudgetExceeded(self._run.investigation_id, "deadline")
            async with self._authority.hold(now) as lease:
                # This is the final await before advisory provider dispatch and
                # rejects an already-acquired takeover fence. Providers do not
                # consume this local fence, so no distributed exactly-once
                # guarantee is implied after the operation begins.
                await self._store.validate_lease(lease, now=now)
                dispatch_at = _aware_utc(self._clock())
                if lease.expired(dispatch_at):
                    raise StaleLease(self._run.investigation_id)
                if self.remaining_elapsed_ms(dispatch_at) <= 0:
                    self._provider_deadline_exhausted = True
                    raise BudgetExceeded(self._run.investigation_id, "deadline")
            return await operation()

        provider_task = asyncio.create_task(
            invoke_provider(),
            name=f"reconcile-provider-{call_id}",
        )
        try:
            done, _ = await asyncio.wait(
                {provider_task},
                timeout=remaining_ms / 1_000,
                return_when=asyncio.FIRST_COMPLETED,
            )
            if not done:
                self._provider_deadline_exhausted = True
                self._detach_provider_task(provider_task)
                raise BudgetExceeded(
                    self._run.investigation_id,
                    "deadline",
                )
            if provider_task.cancelled():
                raise DurableDependencyDrift(self._run.investigation_id)
            result = provider_task.result()
            if self.remaining_elapsed_ms(_aware_utc(self._clock())) <= 0:
                self._provider_deadline_exhausted = True
                raise BudgetExceeded(self._run.investigation_id, "deadline")
            return result
        except asyncio.CancelledError:
            self._provider_deadline_exhausted = True
            self._detach_provider_task(provider_task)
            raise
        finally:
            self._provider_calls_in_flight.discard(call_id)

    def _detach_provider_task(self, task: asyncio.Task) -> None:
        if task.done():
            if not task.cancelled():
                task.exception()
            return
        self._detached_provider_tasks.add(task)
        task.cancel()
        task.add_done_callback(self._provider_task_done)

    def _provider_task_done(self, task: asyncio.Task) -> None:
        self._detached_provider_tasks.discard(task)
        if not task.cancelled():
            task.exception()

    async def complete(
        self,
        report: InvestigationReport,
    ) -> DurableExecutionOutcome:
        """Seal a report with exact metered-provider receipt evidence."""

        if type(report) is not InvestigationReport:
            raise TypeError("durable completion requires an exact report")
        sealed = decode_contract(canonical_json_bytes(report), InvestigationReport)
        async with self._provider_call_lock:
            if (
                self._provider_calls_in_flight
                or self._detached_provider_tasks
                or self._provider_deadline_exhausted
            ):
                raise DurableDependencyDrift(self._run.investigation_id)
            return DurableExecutionOutcome(
                investigation_id=self._run.investigation_id,
                report=sealed,
                provider_call_receipts=tuple(self._charged_provider_receipts),
                _seal=_EXECUTION_OUTCOME_SEAL,
            )

    async def emit_report_telemetry(self, report: InvestigationReport) -> None:
        audits = await self._store.controller_audits(self._run.investigation_id)
        if len(audits) != len(report.probe_audit):
            raise DurableDependencyDrift(self._run.investigation_id)
        for public, audit in zip(report.probe_audit, audits, strict=True):
            if not DurableInvestigationApplicationService._audit_matches(
                public,
                audit,
            ):
                raise DurableDependencyDrift(self._run.investigation_id)
            await self._telemetry(
                f"probe-{audit.sequence}",
                RuntimeTelemetryKind.PROBE,
                audit.outcome.value.lower(),
                occurred_at=audit.completed_at,
                probe_sequence=audit.sequence,
                attributes={
                    "capability_name": audit.capability_name or "none",
                    "capability_version": audit.capability_version or "none",
                    "request_sha256": audit.request_sha256 or "none",
                },
            )
        for sequence, decision in enumerate(report.evidence_decisions, 1):
            await self._telemetry(
                f"evidence-{sequence}",
                RuntimeTelemetryKind.EVIDENCE_DECISION,
                decision.disposition.value.lower(),
                occurred_at=report.updated_at,
                evidence_id=decision.evidence_id,
            )
        if report.classification is None:
            raise ValueError("terminal report omitted classification")
        await self._telemetry(
            "classification",
            RuntimeTelemetryKind.CLASSIFIER,
            "established",
            occurred_at=report.updated_at,
            classification=report.classification,
        )
        for gate in report.action_gate:
            await self._telemetry(
                f"gate-{gate.requested_action.value.lower()}",
                RuntimeTelemetryKind.ACTION_GATE,
                "allowed" if gate.allowed else "blocked",
                occurred_at=report.updated_at,
                classification=report.classification,
                requested_action=gate.requested_action,
            )


class DurableInvestigationApplicationService:
    """Persist ownership, read checkpoints, reports, and resumable events."""

    def __init__(
        self,
        store: DurableRuntimeStore,
        executor: DurableInvestigationExecutor,
        *,
        strategy: DurableExecutionStrategy = DurableExecutionStrategy.FIXED,
        cleanup: DurableCleanup | None = None,
        max_provider_calls: int = 0,
        max_estimated_cost_microunits: int = 0,
        owner_id: str,
        semantic_config_sha256: str | None = None,
        runtime_provenance_sha256: str | None = None,
        clock: Callable[[], datetime] | None = None,
        monotonic_clock: Callable[[], float] | None = None,
        event_poll_interval: float = 0.05,
    ) -> None:
        """Bind resolved executable provenance and semantic configuration."""

        if not owner_id:
            raise ValueError("durable application owner identifier is required")
        if type(strategy) is not DurableExecutionStrategy:
            raise TypeError("durable execution strategy must be exact")
        if not callable(executor):
            raise TypeError("durable investigation executor must be callable")
        if (
            type(max_provider_calls) is not int
            or max_provider_calls < 0
            or type(max_estimated_cost_microunits) is not int
            or max_estimated_cost_microunits < 0
        ):
            raise ValueError("durable provider limits must be nonnegative integers")
        if (
            type(event_poll_interval) not in {int, float}
            or isinstance(event_poll_interval, bool)
            or event_poll_interval <= 0
        ):
            raise ValueError("event poll interval must be positive")
        if semantic_config_sha256 is None:
            semantic_config_sha256 = runtime_provenance_sha256
        elif runtime_provenance_sha256 is not None:
            raise ValueError("semantic configuration attestation is ambiguous")
        if semantic_config_sha256 is None:
            raise ValueError("semantic configuration attestation is required")
        self._store = store
        self._executor = executor
        self._strategy = strategy
        self._cleanup = cleanup
        self._max_provider_calls = max_provider_calls
        self._max_estimated_cost_microunits = max_estimated_cost_microunits
        owner_material = f"{owner_id}:{uuid4().hex}".encode()
        self._owner_id = f"owner-{hashlib.sha256(owner_material).hexdigest()[:32]}"
        self._runtime_provenance_sha256 = build_runtime_provenance(
            executor=executor,
            cleanup=cleanup,
            strategy=strategy.value,
            max_provider_calls=max_provider_calls,
            max_estimated_cost_microunits=max_estimated_cost_microunits,
            semantic_config_sha256=semantic_config_sha256,
        ).sha256
        self._clock = clock or (lambda: datetime.now(UTC))
        self._monotonic_clock = monotonic_clock or time.monotonic
        self._event_poll_interval = event_poll_interval
        self._tasks: dict[str, asyncio.Task[None]] = {}
        self._cancellation_events: dict[str, asyncio.Event] = {}
        self._task_exits: dict[str, Exception] = {}
        self._task_lock = asyncio.Lock()
        self._closed = False
        self._startup_error: Exception | None = None

    @property
    def runtime_provenance_sha256(self) -> str:
        """Return the resolved executable provenance bound to new runs."""

        return self._runtime_provenance_sha256

    def _now(self, *, not_before: datetime | None = None) -> datetime:
        value = _aware_utc(self._clock())
        if not_before is not None:
            value = max(value, _aware_utc(not_before))
        return value

    async def start(self) -> None:
        """Recover unfinished durable runs without blocking API health checks."""

        if self._closed:
            raise RuntimeError("durable application service is closed")
        try:
            runs = await self._store.list_runs()
        except Exception as error:
            self._startup_error = error
            return
        for run in runs:
            try:
                provenance = await self._store.runtime_provenance_sha256(
                    run.investigation_id
                )
            except Exception as error:
                self._startup_error = error
                return
            if provenance != self._runtime_provenance_sha256:
                self._startup_error = DurableDependencyDrift(run.investigation_id)
                return
        for run in runs:
            if run.state is not DurableRunState.ESCALATION_REQUIRED:
                await self._ensure_task(run.investigation_id, recovering=True)

    def _assert_available(self) -> None:
        if self._closed:
            raise RuntimeError("durable application service is closed")
        if self._startup_error is not None:
            raise DurableServiceUnavailable from self._startup_error

    @staticmethod
    def _validated_envelope(envelope: ExecutionEnvelope) -> ExecutionEnvelope:
        if type(envelope) is not ExecutionEnvelope:
            raise TypeError("create requires an execution envelope")
        return decode_contract(canonical_json_bytes(envelope), ExecutionEnvelope)

    async def create(
        self,
        envelope: ExecutionEnvelope,
        *,
        started_at: datetime | None = None,
    ) -> CreateInvestigationResult:
        self._assert_available()
        envelope = self._validated_envelope(envelope)
        now = self._now()
        created_at = now if started_at is None else _aware_utc(started_at)
        if created_at > now:
            raise ValueError("durable investigation start cannot be in the future")
        result = await self._store.create_run(
            envelope,
            created_at=created_at,
            limits=runtime_limits_for(
                envelope,
                started_at=created_at,
                max_provider_calls=self._max_provider_calls,
                max_estimated_cost_microunits=(self._max_estimated_cost_microunits),
            ),
            runtime_provenance_sha256=self._runtime_provenance_sha256,
        )
        provenance = await self._store.runtime_provenance_sha256(
            envelope.investigation_id
        )
        if provenance != self._runtime_provenance_sha256:
            raise DurableDependencyDrift(envelope.investigation_id)
        if result.run.state is not DurableRunState.ESCALATION_REQUIRED:
            await self._ensure_task(
                envelope.investigation_id,
                recovering=not result.created,
            )
        return CreateInvestigationResult(
            report=self._report_for(result.run),
            created=result.created,
        )

    async def create_and_wait(
        self,
        envelope: ExecutionEnvelope,
        *,
        started_at: datetime | None = None,
    ) -> InvestigationReport:
        """Create or replay one run and join its exact owned durable execution."""

        return (
            await self.create_and_wait_result(envelope, started_at=started_at)
        ).report

    async def create_and_wait_result(
        self,
        envelope: ExecutionEnvelope,
        *,
        started_at: datetime | None = None,
    ) -> CreateInvestigationResult:
        """Join one owned request and retain whether it first created the run."""

        sealed_envelope = self._validated_envelope(envelope)
        if started_at is not None:
            normalized_start = _aware_utc(started_at)
            if normalized_start > self._now():
                raise ValueError("durable investigation start cannot be in the future")
            started_at = normalized_start
        investigation_id = sealed_envelope.investigation_id
        task: asyncio.Task[None] | None = None
        terminal_before_wait = False
        created = False
        try:
            creation = await self.create(sealed_envelope, started_at=started_at)
            created = creation.created
            async with self._task_lock:
                task = self._tasks.get(investigation_id)
            current = await self._sealed_run(investigation_id)
            terminal_before_wait = current.state is DurableRunState.TERMINAL
            if task is None:
                if current.state not in {
                    DurableRunState.TERMINAL,
                    DurableRunState.ESCALATION_REQUIRED,
                }:
                    raise RuntimeError("durable request lost its owned task")
            else:
                try:
                    await self._await_owned_task(task, current.limits.deadline_at)
                except TimeoutError:
                    if not terminal_before_wait:
                        raise
        except asyncio.CancelledError:
            settlement = asyncio.create_task(
                self._settle_owned_task(investigation_id, task, cancel=True),
                name=f"reconcile-request-cancel-{investigation_id}",
            )
            await self._join_owned_tasks((settlement,))
            raise
        except DurableEscalationRequired:
            await self._settle_owned_task(investigation_id, task, cancel=True)
            raise
        except DurableDependencyDrift:
            await self._settle_owned_task(investigation_id, task, cancel=True)
            raise
        except Exception:
            await self._settle_owned_task(investigation_id, task, cancel=True)
            raise DurableServiceUnavailable from None

        await self._settle_owned_task(
            investigation_id,
            task,
            cancel=task is not None and not task.done(),
        )
        try:
            run = await self._sealed_run(investigation_id)
            if canonical_json_bytes(run.envelope) != canonical_json_bytes(
                sealed_envelope
            ):
                raise DurableDependencyDrift(investigation_id)
            if run.state is DurableRunState.ESCALATION_REQUIRED:
                raise DurableEscalationRequired(investigation_id)
            if (
                run.state is not DurableRunState.TERMINAL
                or run.established_report is None
            ):
                raise DurableServiceUnavailable
            report = decode_contract(
                canonical_json_bytes(run.established_report),
                InvestigationReport,
            )
            if (
                report != run.established_report
                or report.investigation_id != investigation_id
                or report.envelope_sha256 != run.envelope_sha256
                or report.status is not InvestigationStatus.COMPLETED
                or report.revision != 2
                or report.classification is None
                or report.proof is None
            ):
                raise DurableDependencyDrift(investigation_id)
            return CreateInvestigationResult(report=report, created=created)
        except (DurableDependencyDrift, DurableEscalationRequired):
            raise
        except Exception:
            raise DurableServiceUnavailable from None

    async def _sealed_run(self, investigation_id: str) -> DurableRunRecord:
        run = await self._store.get_run(investigation_id)
        if type(run) is not DurableRunRecord:
            raise TypeError("durable store returned an inexact run")
        return decode_contract(canonical_json_bytes(run), DurableRunRecord)

    async def _await_owned_task(
        self,
        task: asyncio.Task[None],
        deadline_at: datetime,
    ) -> None:
        if not task.done():
            remaining = (deadline_at - self._now()).total_seconds()
            if remaining <= 0:
                raise TimeoutError
            done, _ = await asyncio.wait({task}, timeout=remaining)
            if not done:
                raise TimeoutError
        if task.cancelled():
            raise RuntimeError("durable request task was cancelled")
        failure = task.exception()
        if failure is not None:
            raise failure

    @staticmethod
    async def _join_owned_tasks(tasks: tuple[asyncio.Task[None], ...]) -> None:
        for task in tasks:
            while not task.done():
                try:
                    await asyncio.shield(task)
                except asyncio.CancelledError:
                    if task.done():
                        break
                    continue
                except Exception:
                    break
            if task.done():
                with suppress(asyncio.CancelledError):
                    task.exception()

    async def _settle_owned_task(
        self,
        investigation_id: str,
        task: asyncio.Task[None] | None,
        *,
        cancel: bool,
    ) -> None:
        async with self._task_lock:
            current = self._tasks.pop(investigation_id, None)
            cancellation_event = self._cancellation_events.pop(
                investigation_id,
                None,
            )
            candidates = tuple(
                dict.fromkeys(item for item in (task, current) if item is not None)
            )
            if any(not item.done() for item in candidates):
                cancel = True
            if cancel and cancellation_event is not None:
                cancellation_event.set()
            if cancel:
                for item in candidates:
                    if not item.done():
                        item.cancel()
            self._task_exits.pop(investigation_id, None)
        await self._join_owned_tasks(candidates)
        async with self._task_lock:
            self._task_exits.pop(investigation_id, None)

    async def _ensure_task(self, investigation_id: str, *, recovering: bool) -> None:
        async with self._task_lock:
            if self._closed:
                return
            current = self._tasks.get(investigation_id)
            if current is not None and not current.done():
                return
            self._task_exits.pop(investigation_id, None)
            cancellation_event = asyncio.Event()
            task = asyncio.create_task(
                self._run(investigation_id, cancellation_event, recovering),
                name=f"reconcile-durable-{investigation_id}",
            )
            self._tasks[investigation_id] = task
            self._cancellation_events[investigation_id] = cancellation_event
            task.add_done_callback(
                lambda completed: self._task_done(investigation_id, completed)
            )

    def _task_done(self, investigation_id: str, task: asyncio.Task[None]) -> None:
        if self._tasks.get(investigation_id) is not task:
            return
        if task.cancelled():
            failure = RuntimeError(
                "durable child task was cancelled before the waiter observed terminal state"
            )
        else:
            failure = task.exception() or RuntimeError(
                "durable child task exited before the waiter observed terminal state"
            )
        self._task_exits[investigation_id] = failure
        self._tasks.pop(investigation_id, None)
        self._cancellation_events.pop(investigation_id, None)

    @staticmethod
    def _report_for(run: DurableRunRecord) -> InvestigationReport:
        if run.state is DurableRunState.ESCALATION_REQUIRED:
            raise DurableEscalationRequired(run.investigation_id)
        if run.established_report is not None:
            return run.established_report
        active = run.state is not DurableRunState.CREATED
        return InvestigationReport(
            schema_version=INVESTIGATION_REPORT_VERSION,
            investigation_id=run.investigation_id,
            envelope_sha256=run.envelope_sha256,
            status=(
                InvestigationStatus.INVESTIGATING
                if active
                else InvestigationStatus.CREATED
            ),
            created_at=run.created_at,
            updated_at=run.updated_at,
            revision=1 if active else 0,
        )

    async def get(self, investigation_id: str) -> InvestigationReport:
        self._assert_available()
        return self._report_for(await self._store.get_run(investigation_id))

    async def snapshot(
        self,
        investigation_id: str,
        *,
        after: int = 0,
    ) -> EventJournalSnapshot:
        self._assert_available()
        self._report_for(await self._store.get_run(investigation_id))
        return await self._store.snapshot_events(investigation_id, after=after)

    async def wait_for_events(
        self,
        investigation_id: str,
        *,
        after: int = 0,
        cancellation_event: asyncio.Event | None = None,
    ) -> EventJournalSnapshot:
        self._assert_available()
        while True:
            self._assert_available()
            self._report_for(await self._store.get_run(investigation_id))
            snapshot = await self._store.snapshot_events(
                investigation_id,
                after=after,
            )
            if snapshot.events or snapshot.terminal:
                return snapshot
            task_exit = self._task_exits.get(investigation_id)
            if task_exit is not None:
                raise DurableServiceUnavailable from task_exit
            if cancellation_event is not None and cancellation_event.is_set():
                raise asyncio.CancelledError
            await asyncio.sleep(self._event_poll_interval)

    @staticmethod
    def _event(
        investigation_id: str,
        sequence: int,
        occurred_at: datetime,
        event_type: InvestigationEventType,
        payload: InvestigationEventPayload,
    ) -> InvestigationEvent:
        return InvestigationEvent(
            schema_version=INVESTIGATION_EVENT_VERSION,
            investigation_id=investigation_id,
            sequence=sequence,
            type=event_type,
            occurred_at=occurred_at,
            payload=payload,
        )

    async def _append_lifecycle_prefix(
        self,
        run: DurableRunRecord,
        authority: _LeaseAuthority,
    ) -> DurableRunRecord:
        snapshot = await self._store.snapshot_events(run.investigation_id)
        if snapshot.cursor == 0:
            async with authority.hold(run.created_at) as lease:
                await self._store.append_event(
                    lease,
                    self._event(
                        run.investigation_id,
                        1,
                        run.created_at,
                        InvestigationEventType.LIFECYCLE,
                        LifecycleEventPayload(status=InvestigationStatus.CREATED),
                    ),
                    now=max(run.created_at, lease.renewed_at),
                )
            snapshot = await self._store.snapshot_events(run.investigation_id)
        self._validate_lifecycle_prefix(snapshot, run.investigation_id)
        if (run.state is DurableRunState.CREATED and snapshot.cursor != 1) or (
            run.state is DurableRunState.ACTIVE and snapshot.cursor not in {1, 2}
        ):
            raise DurableDependencyDrift(run.investigation_id)
        if snapshot.events[0].occurred_at != run.created_at:
            raise DurableDependencyDrift(run.investigation_id)
        if run.state is DurableRunState.CREATED:
            occurred_at = self._now(not_before=run.updated_at)
            async with authority.hold(occurred_at) as lease:
                run = await self._store.mark_active(lease, occurred_at=occurred_at)
        if snapshot.cursor == 1:
            async with authority.hold(run.updated_at) as lease:
                await self._store.append_event(
                    lease,
                    self._event(
                        run.investigation_id,
                        2,
                        run.updated_at,
                        InvestigationEventType.LIFECYCLE,
                        LifecycleEventPayload(status=InvestigationStatus.INVESTIGATING),
                    ),
                    now=max(run.updated_at, lease.renewed_at),
                )
        return run

    @staticmethod
    def _validate_lifecycle_prefix(
        snapshot: EventJournalSnapshot,
        investigation_id: str,
    ) -> None:
        if not snapshot.events:
            raise DurableDependencyDrift(investigation_id)
        created = snapshot.events[0]
        if (
            created.sequence != 1
            or created.type is not InvestigationEventType.LIFECYCLE
            or not isinstance(created.payload, LifecycleEventPayload)
            or created.payload.status is not InvestigationStatus.CREATED
        ):
            raise DurableDependencyDrift(investigation_id)
        if snapshot.cursor >= 2:
            investigating = snapshot.events[1]
            if (
                investigating.sequence != 2
                or investigating.type is not InvestigationEventType.LIFECYCLE
                or not isinstance(investigating.payload, LifecycleEventPayload)
                or investigating.payload.status is not InvestigationStatus.INVESTIGATING
                or investigating.occurred_at < created.occurred_at
            ):
                raise DurableDependencyDrift(investigation_id)

    async def _run(
        self,
        investigation_id: str,
        cancellation_event: asyncio.Event,
        recovering: bool,
    ) -> None:
        try:
            provenance = await self._store.runtime_provenance_sha256(investigation_id)
        except Exception as error:
            self._startup_error = error
            return
        if provenance != self._runtime_provenance_sha256:
            self._startup_error = DurableDependencyDrift(investigation_id)
            return
        while True:
            try:
                lease = await self._store.acquire_lease(
                    investigation_id,
                    self._owner_id,
                    now=self._now(),
                )
                break
            except LeaseUnavailable:
                try:
                    await asyncio.wait_for(
                        cancellation_event.wait(),
                        timeout=max(self._event_poll_interval, 0.1),
                    )
                except TimeoutError:
                    continue
                return
            except Exception as error:
                self._startup_error = error
                return
        authority = _LeaseAuthority(self._store, lease, self._clock)
        heartbeat = asyncio.create_task(
            self._heartbeat(authority, cancellation_event),
            name=f"reconcile-lease-{investigation_id}",
        )
        try:
            run = await self._store.get_run(investigation_id)
            if run.state is DurableRunState.TERMINAL:
                context = DurableExecutionContext(
                    self._store,
                    authority,
                    run,
                    strategy=self._strategy,
                    clock=self._clock,
                    monotonic_clock=self._monotonic_clock,
                )
                await context.emit_report_telemetry(run.established_report)  # type: ignore[arg-type]
                await self._project_terminal(run, authority)
                await self._recover_cleanup(run, authority, context)
                recovered = await self._store.get_run(investigation_id)
                if recovered.cleanup_status in {
                    CleanupStatus.SUCCEEDED,
                    CleanupStatus.FAILED,
                }:
                    await context._telemetry(
                        "cleanup",
                        RuntimeTelemetryKind.CLEANUP,
                        recovered.cleanup_status.value.lower(),
                        occurred_at=recovered.updated_at,
                    )
                return
            if run.state is DurableRunState.ESCALATION_REQUIRED:
                return
            run = await self._append_lifecycle_prefix(run, authority)
            context = DurableExecutionContext(
                self._store,
                authority,
                run,
                strategy=self._strategy,
                clock=self._clock,
                monotonic_clock=self._monotonic_clock,
            )
            await context._telemetry(
                "run-active",
                RuntimeTelemetryKind.RUN,
                "active",
                occurred_at=run.updated_at,
                attributes={"strategy": self._strategy.value},
            )
            checkpoints = await self._store.probe_checkpoints(investigation_id)
            audits = await self._store.controller_audits(investigation_id)
            checkpoint_sequences = {
                checkpoint.step_sequence for checkpoint in checkpoints
            }
            if recovering and any(
                audit.sequence not in checkpoint_sequences for audit in audits
            ):
                await self._escalate(
                    authority,
                    "non-dispatched-audit-recovery-unsupported",
                )
                return
            if recovering and self._strategy in {
                DurableExecutionStrategy.ADAPTIVE,
                DurableExecutionStrategy.COMPARE,
            }:
                await self._escalate(
                    authority,
                    "planner-recovery-unsupported",
                )
                return
            if self._strategy is DurableExecutionStrategy.FIXED:
                plan = await self._store.resume_plan(
                    investigation_id,
                    now=self._now(),
                )
                if plan.requires_escalation:
                    await self._escalate(authority, "unsafe-recovery-state")
                    return
            elif checkpoints and recovering:
                await self._escalate(
                    authority,
                    "planner-recovery-unsupported",
                )
                return

            outcome = await self._executor(
                run.envelope,
                revision=2,
                cancellation_event=cancellation_event,
                runtime=context,
            )
            report = await self._validated_terminal_report(outcome, run)
            occurred_at = self._now(not_before=report.updated_at)
            async with authority.hold(occurred_at) as active_lease:
                terminal = await self._store.establish_report(
                    active_lease,
                    report,
                    occurred_at=occurred_at,
                )
            await context.emit_report_telemetry(report)
            await self._project_terminal(terminal, authority)
            if self._cleanup is not None:
                pending_at = self._now(not_before=report.updated_at)
                async with authority.hold(pending_at) as active_lease:
                    terminal = await self._store.record_cleanup(
                        active_lease,
                        CleanupStatus.PENDING,
                        occurred_at=pending_at,
                    )
                await self._execute_cleanup(terminal, authority, context)
        except asyncio.CancelledError:
            cancellation_event.set()
            raise
        except _RecoverableProbeRecordingError:
            return
        except Exception as error:
            try:
                current = await self._store.get_run(investigation_id)
                if current.state not in {
                    DurableRunState.TERMINAL,
                    DurableRunState.ESCALATION_REQUIRED,
                }:
                    await self._escalate(authority, "durable-execution-failed")
                elif current.state is DurableRunState.TERMINAL:
                    self._startup_error = error
            except Exception as recovery_error:
                self._startup_error = recovery_error
        finally:
            cancellation_event.set()
            heartbeat.cancel()
            try:
                await asyncio.gather(heartbeat, return_exceptions=True)
            finally:
                await self._release_authority(authority)

    @staticmethod
    async def _release_authority(authority: _LeaseAuthority) -> None:
        release_task = asyncio.create_task(
            authority.release(),
            name=f"reconcile-release-{authority.investigation_id}",
        )
        interrupted = False
        while True:
            try:
                await asyncio.shield(release_task)
                break
            except asyncio.CancelledError:
                if release_task.done():
                    await release_task
                    raise
                interrupted = True
        if interrupted:
            raise asyncio.CancelledError

    async def _heartbeat(
        self,
        authority: _LeaseAuthority,
        cancellation_event: asyncio.Event,
    ) -> None:
        while not cancellation_event.is_set():
            try:
                await asyncio.wait_for(cancellation_event.wait(), timeout=5.0)
            except TimeoutError:
                await authority.renew()

    async def _escalate(
        self,
        authority: _LeaseAuthority,
        failure_code: str,
    ) -> None:
        occurred_at = self._now()
        async with authority.hold(occurred_at) as lease:
            await self._store.require_escalation(
                lease,
                failure_code=failure_code,
                occurred_at=occurred_at,
            )

    @staticmethod
    def _audit_matches(
        public: ProbeAuditRecord,
        durable: ControllerAuditRecord,
    ) -> bool:
        return (
            public.probe_sequence == durable.sequence
            and public.capability_name == durable.capability_name
            and public.capability_version == durable.capability_version
            and public.request_sha256 == durable.request_sha256
            and public.target_sha256 == durable.target_sha256
            and public.outcome is durable.outcome
            and public.stop_reason == durable.stop_reason.value
            and public.started_at == durable.started_at
            and public.completed_at == durable.completed_at
            and public.session_elapsed_ms == durable.session_elapsed_ms
            and public.probe_count_used == durable.probe_count_used
            and public.cost_units_used == durable.cost_units_used
            and public.result_bytes_acquired == durable.result_bytes_acquired
            and public.result_sha256 == durable.result_sha256
            and public.result_byte_count == durable.result_byte_count
        )

    async def _validated_terminal_report(
        self,
        candidate: object,
        run: DurableRunRecord,
    ) -> InvestigationReport:
        if type(candidate) is not DurableExecutionOutcome:
            raise TypeError("executor must return a context-sealed durable outcome")
        if candidate.investigation_id != run.investigation_id:
            raise ValueError("durable execution receipt belongs to another run")
        report = decode_contract(
            canonical_json_bytes(candidate.report),
            InvestigationReport,
        )
        if report.status is not InvestigationStatus.COMPLETED or report.revision != 2:
            raise ValueError("executor report must be completed at revision 2")
        if (
            report.investigation_id != run.investigation_id
            or report.envelope_sha256 != run.envelope_sha256
            or report.classification is None
            or report.proof is None
        ):
            raise ValueError("executor report does not match the durable run")
        expected_findings = tuple(
            (effect.effect_id, effect.commit_scope)
            for effect in run.envelope.expected_effects
        )
        actual_findings = tuple(
            (finding.effect_id, finding.commit_scope)
            for finding in report.proof.effect_findings
        )
        if actual_findings != expected_findings:
            raise ValueError("executor proof does not match expected effects")
        policies = run.envelope.context.policies
        if any(
            evidence.authority_policy_version != policies.authority
            for evidence in report.evidence
        ) or any(
            gate.classification_policy_version != policies.classification
            or gate.action_policy_version != policies.action
            for gate in report.action_gate
        ):
            raise ValueError("executor report uses a foreign policy")
        audits = await self._store.controller_audits(run.investigation_id)
        if len(audits) != len(report.probe_audit) or any(
            not self._audit_matches(public, audit)
            for public, audit in zip(report.probe_audit, audits, strict=True)
        ):
            raise ValueError("executor report contains an unattested controller audit")
        checkpoints = await self._store.probe_checkpoints(run.investigation_id)
        if any(
            checkpoint.state is not ProbeCheckpointState.RECORDED
            or checkpoint.audit is None
            or checkpoint.step_sequence > len(audits)
            or checkpoint.audit != audits[checkpoint.step_sequence - 1]
            for checkpoint in checkpoints
        ):
            raise ValueError("executor report contains an invalid read checkpoint")
        ledger = await self._store.cost_snapshot(run.investigation_id)
        provider_receipts = await self._store.provider_call_receipts(
            run.investigation_id
        )
        if (
            ledger.probe_count < len(checkpoints)
            or provider_receipts != candidate.provider_call_receipts
            or ledger.provider_calls != len(provider_receipts)
            or ledger.estimated_cost_microunits
            != sum(item.estimated_cost_microunits for item in provider_receipts)
            or (
                report.probe_audit
                and ledger.controller_cost_units
                < report.probe_audit[-1].cost_units_used
            )
            or (
                report.probe_audit
                and ledger.evidence_bytes < report.probe_audit[-1].result_bytes_acquired
            )
        ):
            raise ValueError("durable cost ledger does not cover the report")
        if (
            self._strategy
            in {
                DurableExecutionStrategy.ADAPTIVE,
                DurableExecutionStrategy.COMPARE,
            }
            and not candidate.provider_call_receipts
            and not _allows_zero_provider_receipts(self._strategy, run, report)
        ):
            raise ValueError("adaptive execution omitted provider precharge")
        cumulative = (
            (
                tuple(item.probe_count_used for item in report.probe_audit),
                run.limits.max_probe_count,
            ),
            (
                tuple(item.cost_units_used for item in report.probe_audit),
                run.limits.max_controller_cost_units,
            ),
            (
                tuple(item.result_bytes_acquired for item in report.probe_audit),
                run.limits.max_evidence_bytes,
            ),
            (
                tuple(item.session_elapsed_ms for item in report.probe_audit),
                run.envelope.context.evidence_budget.max_elapsed_ms,
            ),
        )
        if any(
            any(current < previous for previous, current in pairwise(values))
            or (values and values[-1] > limit)
            for values, limit in cumulative
        ):
            raise ValueError("executor report has invalid cumulative counters")
        normalized = report.model_copy(
            update={
                "created_at": run.created_at,
                "updated_at": self._now(not_before=run.updated_at),
            }
        )
        return decode_contract(canonical_json_bytes(normalized), InvestigationReport)

    @staticmethod
    def _terminal_payloads(
        report: InvestigationReport,
    ) -> tuple[tuple[InvestigationEventType, InvestigationEventPayload], ...]:
        payloads: list[tuple[InvestigationEventType, InvestigationEventPayload]] = []
        payloads.extend(
            (
                InvestigationEventType.PROBE,
                ProbeEventPayload(probe_audit=audit),
            )
            for audit in report.probe_audit
        )
        payloads.extend(
            (
                InvestigationEventType.EVIDENCE_DECISION,
                EvidenceDecisionEventPayload(decision=decision),
            )
            for decision in report.evidence_decisions
        )
        if report.classification is None:
            raise ValueError("terminal report omitted classification")
        payloads.append(
            (
                InvestigationEventType.CLASSIFICATION,
                ClassificationEventPayload(classification=report.classification),
            )
        )
        payloads.extend(
            (
                InvestigationEventType.ACTION_GATE,
                ActionGateEventPayload(action_gate=gate),
            )
            for gate in report.action_gate
        )
        payloads.append(
            (
                InvestigationEventType.LIFECYCLE,
                LifecycleEventPayload(status=InvestigationStatus.COMPLETED),
            )
        )
        return tuple(payloads)

    async def _project_terminal(
        self,
        run: DurableRunRecord,
        authority: _LeaseAuthority,
    ) -> None:
        report = run.established_report
        if report is None:
            raise ValueError("terminal durable run omitted its report")
        expected = self._terminal_payloads(report)
        snapshot = await self._store.snapshot_events(run.investigation_id)
        self._validate_lifecycle_prefix(snapshot, run.investigation_id)
        accepted = snapshot.events[2:]
        if len(accepted) > len(expected):
            raise DurableDependencyDrift(run.investigation_id)
        for offset, (event, (event_type, payload)) in enumerate(
            zip(accepted, expected, strict=False),
            start=3,
        ):
            if event != self._event(
                run.investigation_id,
                offset,
                report.updated_at,
                event_type,
                payload,
            ):
                raise DurableDependencyDrift(run.investigation_id)
        for event_type, payload in expected[len(accepted) :]:
            sequence = snapshot.cursor + 1
            event = self._event(
                run.investigation_id,
                sequence,
                report.updated_at,
                event_type,
                payload,
            )
            now = self._now(not_before=report.updated_at)
            async with authority.hold(now) as lease:
                await self._store.append_event(lease, event, now=now)
            snapshot = await self._store.snapshot_events(run.investigation_id)

    async def _execute_cleanup(
        self,
        run: DurableRunRecord,
        authority: _LeaseAuthority,
        context: DurableExecutionContext,
    ) -> None:
        report = run.established_report
        if report is None or self._cleanup is None:
            return
        authorized_at = self._now(not_before=report.updated_at)
        async with authority.hold(authorized_at) as lease:
            # PENDING was persisted before this check. If ownership was lost,
            # the external cleanup is not dispatched and recovery preserves
            # PENDING as an unknown, non-retryable outcome.
            await self._store.validate_lease(lease, now=authorized_at)
            if lease.expired(_aware_utc(self._clock())):
                raise StaleLease(run.investigation_id)
        try:
            await self._cleanup(run.envelope, report)
        except Exception:
            status = CleanupStatus.FAILED
            failure_code = "cleanup-failed"
        else:
            status = CleanupStatus.SUCCEEDED
            failure_code = None
        occurred_at = self._now(not_before=report.updated_at)
        async with authority.hold(occurred_at) as lease:
            await self._store.record_cleanup(
                lease,
                status,
                occurred_at=occurred_at,
                failure_code=failure_code,
            )
        await context._telemetry(
            "cleanup",
            RuntimeTelemetryKind.CLEANUP,
            status.value.lower(),
            occurred_at=occurred_at,
        )

    async def _recover_cleanup(
        self,
        run: DurableRunRecord,
        authority: _LeaseAuthority,
        context: DurableExecutionContext,
    ) -> None:
        if run.cleanup_status is CleanupStatus.NOT_REQUESTED:
            if self._cleanup is None:
                return
            occurred_at = self._now(not_before=run.updated_at)
            async with authority.hold(occurred_at) as lease:
                pending = await self._store.record_cleanup(
                    lease,
                    CleanupStatus.PENDING,
                    occurred_at=occurred_at,
                )
            await self._execute_cleanup(pending, authority, context)
            return
        if run.cleanup_status is not CleanupStatus.PENDING:
            return
        occurred_at = self._now(not_before=run.updated_at)
        async with authority.hold(occurred_at) as lease:
            await self._store.record_cleanup(
                lease,
                CleanupStatus.FAILED,
                occurred_at=occurred_at,
                failure_code="cleanup-outcome-unknown",
            )

    async def aclose(self) -> None:
        async with self._task_lock:
            if self._closed:
                return
            self._closed = True
            tasks = tuple(self._tasks.items())
            for investigation_id, task in tasks:
                self._cancellation_events[investigation_id].set()
                task.cancel()
        if tasks:
            await asyncio.gather(
                *(task for _, task in tasks),
                return_exceptions=True,
            )


__all__ = [
    "DurableApplicationError",
    "DurableCleanup",
    "DurableDependencyDrift",
    "DurableEscalationRequired",
    "DurableExecutionContext",
    "DurableExecutionOutcome",
    "DurableExecutionStrategy",
    "DurableInvestigationApplicationService",
    "DurableInvestigationExecutor",
    "DurableServiceUnavailable",
]
