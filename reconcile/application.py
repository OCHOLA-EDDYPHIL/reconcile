"""Application-owned investigation lifecycle and event projection."""

from __future__ import annotations

import asyncio
from collections.abc import Callable
from contextlib import suppress
from dataclasses import dataclass
from datetime import UTC, datetime
from itertools import pairwise
from typing import Protocol

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
    canonical_sha256,
    decode_contract,
)
from reconcile.contracts.envelope import ExecutionEnvelope
from reconcile.contracts.report import (
    INVESTIGATION_REPORT_VERSION,
    InvestigationReport,
    InvestigationStatus,
)
from reconcile.evidence import EvidenceEngine, TargetRuleRegistry
from reconcile.persistence.events import (
    EventJournalSnapshot,
    InMemoryInvestigationEventJournal,
    JournalAlreadyRegistered,
    JournalNotFound,
)
from reconcile.persistence.models import InvestigationRecord, new_investigation_record
from reconcile.persistence.repository import InvestigationRepository


class InvestigationExecutor(Protocol):
    """Trusted boundary that produces one deterministic terminal report."""

    async def __call__(
        self,
        envelope: ExecutionEnvelope,
        *,
        revision: int,
        cancellation_event: asyncio.Event,
    ) -> InvestigationReport: ...


@dataclass(frozen=True, slots=True)
class CreateInvestigationResult:
    """The current report and whether this call first bound the identifier."""

    report: InvestigationReport
    created: bool


class InvestigationApplicationService:
    """Own lifecycle transitions, background execution, and event ordering."""

    def __init__(
        self,
        repository: InvestigationRepository,
        event_journal: InMemoryInvestigationEventJournal,
        executor: InvestigationExecutor,
        *,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        self._repository = repository
        self._event_journal = event_journal
        self._executor = executor
        self._clock = clock or (lambda: datetime.now(UTC))
        self._create_lock = asyncio.Lock()
        self._investigation_locks: dict[str, asyncio.Lock] = {}
        self._tasks: dict[str, asyncio.Task[None]] = {}
        self._cancellation_events: dict[str, asyncio.Event] = {}
        self._closed = False

    async def __aenter__(self) -> InvestigationApplicationService:
        if self._closed:
            raise RuntimeError("investigation application service is closed")
        return self

    async def __aexit__(self, *exc_info: object) -> None:
        await self.aclose()

    def _now(self, *, not_before: datetime | None = None) -> datetime:
        value = self._clock()
        if not isinstance(value, datetime):
            raise TypeError("application clock must return a datetime")
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("application clock must return an aware datetime")
        value = value.astimezone(UTC)
        if not_before is not None:
            floor = not_before.astimezone(UTC)
            if value < floor:
                value = floor
        return value

    def _lock_for(self, investigation_id: str) -> asyncio.Lock:
        return self._investigation_locks.setdefault(
            investigation_id,
            asyncio.Lock(),
        )

    @staticmethod
    def _validated_envelope(envelope: ExecutionEnvelope) -> ExecutionEnvelope:
        if type(envelope) is not ExecutionEnvelope:
            raise TypeError("create requires an execution envelope")
        return decode_contract(
            canonical_json_bytes(envelope),
            ExecutionEnvelope,
        )

    @staticmethod
    def _event(
        investigation_id: str,
        *,
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

    async def create(
        self,
        envelope: ExecutionEnvelope,
    ) -> CreateInvestigationResult:
        """Create once, replay exact envelopes, and start one owned executor task."""

        envelope = self._validated_envelope(envelope)
        interrupted = False
        async with self._create_lock:
            if self._closed:
                raise RuntimeError("investigation application service is closed")

            lock = self._lock_for(envelope.investigation_id)
            async with lock:
                attempted = new_investigation_record(
                    envelope,
                    created_at=self._now(),
                )
                result = await self._repository.create(attempted)
                initialization = asyncio.create_task(
                    self._ensure_created_event(result.record),
                    name=(f"reconcile-created-event-{envelope.investigation_id}"),
                )
                try:
                    await asyncio.shield(initialization)
                except asyncio.CancelledError:
                    interrupted = True
                    await initialization
                if result.record.revision == 2:
                    await self._project_terminal_locked(result.record)

            if (
                result.record.revision < 2
                and envelope.investigation_id not in self._tasks
            ):
                self._start_investigation_task(envelope.investigation_id)

            if interrupted:
                raise asyncio.CancelledError

            return CreateInvestigationResult(
                report=result.record.report,
                created=result.created,
            )

    async def _ensure_created_event(
        self,
        record: InvestigationRecord,
    ) -> EventJournalSnapshot:
        investigation_id = record.investigation_id
        created_event = self._event(
            investigation_id,
            sequence=1,
            occurred_at=record.report.created_at,
            event_type=InvestigationEventType.LIFECYCLE,
            payload=LifecycleEventPayload(status=InvestigationStatus.CREATED),
        )
        try:
            snapshot = await self._event_journal.snapshot(investigation_id)
        except JournalNotFound:
            if record.revision != 0:
                raise RuntimeError(
                    "an active investigation is missing its event journal"
                ) from None
            try:
                await self._event_journal.register(investigation_id)
            except JournalAlreadyRegistered:
                pass
            snapshot = await self._event_journal.snapshot(investigation_id)

        if snapshot.cursor == 0:
            if record.revision != 0:
                raise RuntimeError("an active investigation has an empty event journal")
            await self._event_journal.append(created_event)
            snapshot = await self._event_journal.snapshot(investigation_id)

        self._validate_lifecycle_prefix(snapshot, record)
        if snapshot.events[0] != created_event:
            raise RuntimeError("investigation journal has a divergent created event")
        if record.revision == 0 and snapshot.cursor != 1:
            raise RuntimeError(
                "a created investigation has divergent non-created events"
            )
        return snapshot

    def _start_investigation_task(self, investigation_id: str) -> None:
        cancellation_event = asyncio.Event()
        task = asyncio.create_task(
            self._run_investigation(investigation_id, cancellation_event),
            name=f"reconcile-investigation-{investigation_id}",
        )
        self._tasks[investigation_id] = task
        self._cancellation_events[investigation_id] = cancellation_event
        task.add_done_callback(
            lambda completed: self._task_done(investigation_id, completed)
        )

    async def get(self, investigation_id: str) -> InvestigationReport:
        """Return one report coherent with all projected events for its revision."""

        lock = self._lock_for(investigation_id)
        async with lock:
            record = await self._repository.get(investigation_id)
            if record.revision == 2:
                await self._project_terminal_locked(record)
            else:
                snapshot = await self._event_journal.snapshot(investigation_id)
                self._validate_lifecycle_prefix(snapshot, record)
            return record.report

    async def snapshot(
        self,
        investigation_id: str,
        *,
        after: int = 0,
    ) -> EventJournalSnapshot:
        """Return accepted events strictly after an exclusive cursor."""

        lock = self._lock_for(investigation_id)
        async with lock:
            record = await self._repository.get(investigation_id)
            if record.revision == 2:
                await self._project_terminal_locked(record)
            return await self._event_journal.snapshot(investigation_id, after=after)

    async def wait_for_events(
        self,
        investigation_id: str,
        *,
        after: int = 0,
        cancellation_event: asyncio.Event | None = None,
    ) -> EventJournalSnapshot:
        """Wait for an event suffix or terminal journal state."""

        lock = self._lock_for(investigation_id)
        async with lock:
            record = await self._repository.get(investigation_id)
            if record.revision == 2:
                await self._project_terminal_locked(record)
        return await self._event_journal.wait_for_events(
            investigation_id,
            after=after,
            cancellation_event=cancellation_event,
        )

    async def aclose(self) -> None:
        """Cancel, join, and deterministically terminalize every owned task."""

        async with self._create_lock:
            if self._closed:
                return
            self._closed = True
            active = tuple(self._tasks.items())
            for investigation_id, _ in active:
                self._cancellation_events[investigation_id].set()
            for _, task in active:
                task.cancel()

        if active:
            await asyncio.gather(
                *(task for _, task in active),
                return_exceptions=True,
            )
            for investigation_id, _ in active:
                await self._finish_terminal(investigation_id, candidate=None)

    def _task_done(
        self,
        investigation_id: str,
        task: asyncio.Task[None],
    ) -> None:
        if self._tasks.get(investigation_id) is task:
            self._tasks.pop(investigation_id, None)
            self._cancellation_events.pop(investigation_id, None)
        with suppress(asyncio.CancelledError):
            task.exception()

    async def _run_investigation(
        self,
        investigation_id: str,
        cancellation_event: asyncio.Event,
    ) -> None:
        try:
            record = await self._mark_investigating(investigation_id)
            candidate = await self._executor(
                record.envelope,
                revision=2,
                cancellation_event=cancellation_event,
            )
            await self._finish_terminal(investigation_id, candidate=candidate)
        except asyncio.CancelledError:
            await self._finish_terminal(investigation_id, candidate=None)
        except Exception:
            await self._finish_terminal(investigation_id, candidate=None)

    async def _mark_investigating(
        self,
        investigation_id: str,
    ) -> InvestigationRecord:
        lock = self._lock_for(investigation_id)
        async with lock:
            record = await self._repository.get(investigation_id)
            return await self._ensure_investigating_locked(record)

    async def _ensure_investigating_locked(
        self,
        record: InvestigationRecord,
    ) -> InvestigationRecord:
        investigation_id = record.investigation_id
        if record.revision == 0:
            updated_at = self._now(not_before=record.report.created_at)
            investigating = InvestigationReport(
                schema_version=INVESTIGATION_REPORT_VERSION,
                investigation_id=investigation_id,
                envelope_sha256=record.envelope_sha256,
                status=InvestigationStatus.INVESTIGATING,
                created_at=record.report.created_at,
                updated_at=updated_at,
                revision=1,
            )
            record = await self._repository.replace_report(
                investigation_id,
                0,
                investigating,
            )
        elif record.revision not in {1, 2}:
            raise RuntimeError("application service encountered an unknown revision")

        snapshot = await self._event_journal.snapshot(investigation_id)
        self._validate_lifecycle_prefix(snapshot, record)
        if snapshot.cursor == 1:
            occurred_at = (
                record.report.updated_at
                if record.revision == 1
                else record.report.created_at
            )
            await self._event_journal.append(
                self._event(
                    investigation_id,
                    sequence=2,
                    occurred_at=occurred_at,
                    event_type=InvestigationEventType.LIFECYCLE,
                    payload=LifecycleEventPayload(
                        status=InvestigationStatus.INVESTIGATING
                    ),
                )
            )
        return record

    @staticmethod
    def _validate_lifecycle_prefix(
        snapshot: EventJournalSnapshot,
        record: InvestigationRecord,
    ) -> None:
        if not snapshot.events or snapshot.cursor < 1:
            raise RuntimeError("investigation journal is missing its created event")
        created = snapshot.events[0]
        if (
            created.investigation_id != record.investigation_id
            or created.type is not InvestigationEventType.LIFECYCLE
            or not isinstance(created.payload, LifecycleEventPayload)
            or created.payload.status is not InvestigationStatus.CREATED
        ):
            raise RuntimeError("investigation journal has an invalid created event")
        if snapshot.cursor >= 2:
            investigating = snapshot.events[1]
            if (
                investigating.type is not InvestigationEventType.LIFECYCLE
                or not isinstance(investigating.payload, LifecycleEventPayload)
                or investigating.payload.status is not InvestigationStatus.INVESTIGATING
            ):
                raise RuntimeError(
                    "investigation journal has an invalid investigating event"
                )

    def _validated_terminal_report(
        self,
        candidate: object,
        record: InvestigationRecord,
    ) -> InvestigationReport:
        if type(candidate) is not InvestigationReport:
            raise TypeError("executor must return an exact investigation report")
        report = decode_contract(
            canonical_json_bytes(candidate),
            InvestigationReport,
        )
        if report.status is not InvestigationStatus.COMPLETED or report.revision != 2:
            raise ValueError("executor report must be completed at revision 2")
        if (
            report.investigation_id != record.investigation_id
            or report.envelope_sha256 != record.envelope_sha256
        ):
            raise ValueError("executor report belongs to another envelope")

        proof = report.proof
        if proof is None:
            raise ValueError("executor report omitted deterministic proof")
        expected_findings = tuple(
            (effect.effect_id, effect.commit_scope)
            for effect in record.envelope.expected_effects
        )
        actual_findings = tuple(
            (finding.effect_id, finding.commit_scope)
            for finding in proof.effect_findings
        )
        if actual_findings != expected_findings:
            raise ValueError("executor proof does not match the expected effects")

        policies = record.envelope.context.policies
        if any(
            evidence.authority_policy_version != policies.authority
            for evidence in report.evidence
        ):
            raise ValueError("executor evidence uses a foreign authority policy")
        if any(
            gate.classification_policy_version != policies.classification
            or gate.action_policy_version != policies.action
            for gate in report.action_gate
        ):
            raise ValueError("executor action gates use foreign policies")

        enabled = {
            (reference.name, reference.version)
            for reference in record.envelope.context.enabled_capabilities
        }
        target_sha256 = canonical_sha256(record.envelope.target)
        if any(
            audit.target_sha256 != target_sha256
            or (
                audit.capability_name is not None
                and (audit.capability_name, audit.capability_version) not in enabled
            )
            for audit in report.probe_audit
        ):
            raise ValueError("executor probe audit escaped the sealed envelope")

        budget = record.envelope.context.evidence_budget
        if len(report.probe_audit) > budget.max_probes:
            raise ValueError("executor report exceeds the probe-count budget")
        cumulative_counters = (
            (
                tuple(audit.probe_count_used for audit in report.probe_audit),
                budget.max_probes,
            ),
            (
                tuple(audit.session_elapsed_ms for audit in report.probe_audit),
                budget.max_elapsed_ms,
            ),
            (
                tuple(audit.result_bytes_acquired for audit in report.probe_audit),
                budget.max_total_result_bytes,
            ),
            (
                tuple(audit.cost_units_used for audit in report.probe_audit),
                budget.max_cost_units,
            ),
        )
        if any(
            any(current < previous for previous, current in pairwise(values))
            or (values and max(values) > limit)
            for values, limit in cumulative_counters
        ):
            raise ValueError(
                "executor report has invalid cumulative evidence-budget counters"
            )

        updated_at = self._now(not_before=record.report.created_at)
        normalized = report.model_copy(
            update={
                "created_at": record.report.created_at,
                "updated_at": updated_at,
            }
        )
        return decode_contract(
            canonical_json_bytes(normalized),
            InvestigationReport,
        )

    def _fallback_report(self, record: InvestigationRecord) -> InvestigationReport:
        updated_at = self._now(not_before=record.report.created_at)
        return EvidenceEngine(
            record.envelope,
            TargetRuleRegistry(),
        ).report(
            (),
            created_at=record.report.created_at,
            updated_at=updated_at,
            revision=2,
        )

    async def _finish_terminal(
        self,
        investigation_id: str,
        *,
        candidate: object | None,
    ) -> None:
        lock = self._lock_for(investigation_id)
        async with lock:
            record = await self._repository.get(investigation_id)
            record = await self._ensure_investigating_locked(record)
            if record.revision == 1:
                terminal = (
                    self._fallback_report(record)
                    if candidate is None
                    else self._validated_terminal_report(candidate, record)
                )
                record = await self._repository.replace_report(
                    investigation_id,
                    1,
                    terminal,
                )
            elif record.revision != 2:
                raise RuntimeError("terminal transition requires revision 1 or 2")
            await self._project_terminal_locked(record)

    @staticmethod
    def _terminal_payloads(
        report: InvestigationReport,
    ) -> tuple[tuple[InvestigationEventType, InvestigationEventPayload], ...]:
        events: list[tuple[InvestigationEventType, InvestigationEventPayload]] = []
        for audit in report.probe_audit:
            events.append(
                (
                    InvestigationEventType.PROBE,
                    ProbeEventPayload(probe_audit=audit),
                )
            )
        for decision in report.evidence_decisions:
            events.append(
                (
                    InvestigationEventType.EVIDENCE_DECISION,
                    EvidenceDecisionEventPayload(decision=decision),
                )
            )

        if report.classification is None:
            raise RuntimeError("terminal report is missing its classification")
        events.append(
            (
                InvestigationEventType.CLASSIFICATION,
                ClassificationEventPayload(classification=report.classification),
            )
        )
        events.extend(
            (
                InvestigationEventType.ACTION_GATE,
                ActionGateEventPayload(action_gate=gate),
            )
            for gate in report.action_gate
        )
        events.append(
            (
                InvestigationEventType.LIFECYCLE,
                LifecycleEventPayload(status=InvestigationStatus.COMPLETED),
            )
        )
        return tuple(events)

    async def _project_terminal_locked(self, record: InvestigationRecord) -> None:
        report = record.report
        if record.revision != 2 or report.status is not InvestigationStatus.COMPLETED:
            raise RuntimeError("only a revision-2 completed report can be projected")
        expected = self._terminal_payloads(report)
        snapshot = await self._event_journal.snapshot(record.investigation_id)
        self._validate_lifecycle_prefix(snapshot, record)
        if snapshot.cursor < 2:
            raise RuntimeError("terminal projection requires investigating state")

        accepted_terminal = snapshot.events[2:]
        if len(accepted_terminal) > len(expected):
            raise RuntimeError("investigation journal exceeds its terminal projection")
        for offset, (accepted, (event_type, payload)) in enumerate(
            zip(accepted_terminal, expected, strict=False),
            start=3,
        ):
            expected_event = self._event(
                record.investigation_id,
                sequence=offset,
                occurred_at=report.updated_at,
                event_type=event_type,
                payload=payload,
            )
            if accepted != expected_event:
                raise RuntimeError(
                    "investigation journal diverges from its terminal report"
                )

        for event_type, payload in expected[len(accepted_terminal) :]:
            sequence = snapshot.cursor + 1
            projected = self._event(
                record.investigation_id,
                sequence=sequence,
                occurred_at=report.updated_at,
                event_type=event_type,
                payload=payload,
            )
            accepted = await self._event_journal.append(projected)
            snapshot = EventJournalSnapshot(
                events=(*snapshot.events, accepted),
                cursor=sequence,
                terminal=(
                    event_type is InvestigationEventType.LIFECYCLE
                    and isinstance(payload, LifecycleEventPayload)
                    and payload.status is InvestigationStatus.COMPLETED
                ),
            )


__all__ = [
    "CreateInvestigationResult",
    "InvestigationApplicationService",
    "InvestigationExecutor",
]
