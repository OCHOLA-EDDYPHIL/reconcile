from __future__ import annotations

import asyncio
from contextlib import suppress
from datetime import timedelta
from typing import Any, cast

import pytest

from reconcile.application import InvestigationApplicationService
from reconcile.contracts.api import (
    INVESTIGATION_EVENT_VERSION,
    ActionGateEventPayload,
    EvidenceDecisionEventPayload,
    InvestigationEvent,
    InvestigationEventType,
    LifecycleEventPayload,
    ProbeEventPayload,
)
from reconcile.contracts.codec import canonical_sha256
from reconcile.contracts.common import Classification
from reconcile.contracts.envelope import ExecutionEnvelope
from reconcile.contracts.evidence import (
    EVIDENCE_DECISION_VERSION,
    EvidenceDecision,
    EvidenceDisposition,
    EvidenceReason,
)
from reconcile.contracts.report import (
    InvestigationReport,
    InvestigationStatus,
    ProbeAuditRecord,
    ProbeOutcome,
    RequestedAction,
)
from reconcile.evidence import EvidenceEngine, TargetRuleRegistry
from reconcile.persistence.events import InMemoryInvestigationEventJournal
from reconcile.persistence.memory import InMemoryInvestigationRepository
from reconcile.persistence.repository import DuplicateInvestigationId
from tests.contract._factories import NOW, make_envelope, make_report


class _FailOnceCreatedJournal(InMemoryInvestigationEventJournal):
    def __init__(self, fault_point: str) -> None:
        super().__init__()
        self._fault_point = fault_point
        self._failed = False

    async def register(self, investigation_id: str) -> None:
        if self._fault_point == "register" and not self._failed:
            self._failed = True
            raise RuntimeError("injected created-journal registration failure")
        await super().register(investigation_id)

    async def append(self, event: InvestigationEvent) -> InvestigationEvent:
        if self._fault_point == "append" and event.sequence == 1 and not self._failed:
            self._failed = True
            raise RuntimeError("injected created-event append failure")
        accepted = await super().append(event)
        if (
            self._fault_point == "append_after"
            and event.sequence == 1
            and not self._failed
        ):
            self._failed = True
            raise RuntimeError("injected post-append response failure")
        return accepted


class _BlockingCreatedJournal(InMemoryInvestigationEventJournal):
    def __init__(self) -> None:
        super().__init__()
        self.append_started = asyncio.Event()
        self.release_append = asyncio.Event()
        self._blocked = False

    async def append(self, event: InvestigationEvent) -> InvestigationEvent:
        if event.sequence == 1 and not self._blocked:
            self._blocked = True
            self.append_started.set()
            await self.release_append.wait()
        return await super().append(event)


class _FaultingTerminalJournal(InMemoryInvestigationEventJournal):
    def __init__(self, mode: str) -> None:
        super().__init__()
        self._mode = mode
        self._failures_remaining = 2
        self.faults_exhausted = asyncio.Event()

    async def append(self, event: InvestigationEvent) -> InvestigationEvent:
        should_fail = event.sequence >= 3 and self._failures_remaining > 0
        if should_fail and self._mode == "before":
            self._record_failure()
            raise RuntimeError("injected terminal append failure")

        accepted = await super().append(event)
        if should_fail and self._mode == "after":
            self._record_failure()
            raise RuntimeError("injected terminal append response loss")
        return accepted

    def _record_failure(self) -> None:
        self._failures_remaining -= 1
        if self._failures_remaining == 0:
            self.faults_exhausted.set()


def _probe_report(*, revision: int = 2) -> InvestigationReport:
    report = make_report(Classification.COMMITTED).model_copy(
        update={"revision": revision}
    )
    return InvestigationReport.model_validate(report)


def _two_probe_report() -> InvestigationReport:
    report = _probe_report()
    second_evidence_id = "evidence-rejected-2"
    second_audit = ProbeAuditRecord(
        probe_sequence=2,
        target_sha256=report.probe_audit[0].target_sha256,
        outcome=ProbeOutcome.REJECTED,
        stop_reason="invalid_request",
        started_at=NOW + timedelta(seconds=4),
        completed_at=NOW + timedelta(seconds=5),
        session_elapsed_ms=3_000,
        probe_count_used=1,
        cost_units_used=1,
        result_bytes_acquired=512,
        evidence_ids=(second_evidence_id,),
    )
    second_decision = EvidenceDecision(
        schema_version=EVIDENCE_DECISION_VERSION,
        evidence_id=second_evidence_id,
        disposition=EvidenceDisposition.REJECTED,
        reason=EvidenceReason.MALFORMED_OBSERVATION,
    )
    return InvestigationReport.model_validate(
        report.model_copy(
            update={
                "probe_audit": (*report.probe_audit, second_audit),
                "evidence_decisions": (
                    *report.evidence_decisions,
                    second_decision,
                ),
            }
        )
    )


def _zero_evidence_report(
    envelope: ExecutionEnvelope,
    *,
    revision: int = 2,
) -> InvestigationReport:
    return EvidenceEngine(envelope, TargetRuleRegistry()).report(
        (),
        created_at=NOW,
        updated_at=NOW + timedelta(seconds=5),
        revision=revision,
    )


async def _terminal_transcript(
    service: InvestigationApplicationService,
    investigation_id: str,
) -> tuple[InvestigationEvent, ...]:
    events: list[InvestigationEvent] = []
    cursor = 0
    async with asyncio.timeout(2):
        while True:
            snapshot = await service.wait_for_events(
                investigation_id,
                after=cursor,
            )
            events.extend(snapshot.events)
            cursor = snapshot.cursor
            if snapshot.terminal:
                return tuple(events)


@pytest.mark.unit
def test_create_replays_exact_envelopes_and_conflicts_on_identifier_reuse() -> None:
    async def scenario() -> None:
        started = asyncio.Event()
        release = asyncio.Event()
        calls = 0

        async def executor(
            envelope: ExecutionEnvelope,
            *,
            revision: int,
            cancellation_event: asyncio.Event,
        ) -> InvestigationReport:
            nonlocal calls
            calls += 1
            assert revision == 2
            assert not cancellation_event.is_set()
            started.set()
            await release.wait()
            return _zero_evidence_report(envelope, revision=revision)

        service = InvestigationApplicationService(
            InMemoryInvestigationRepository(),
            InMemoryInvestigationEventJournal(),
            executor,
            clock=lambda: NOW,
        )
        envelope = make_envelope()
        try:
            created = await service.create(envelope)
            replayed = await service.create(envelope)

            assert created.created is True
            assert created.report.status is InvestigationStatus.CREATED
            assert created.report.revision == 0
            assert replayed.created is False
            assert replayed.report.investigation_id == created.report.investigation_id

            conflict_values = envelope.model_dump(mode="python")
            conflict_values["operation_id"] = "operation-conflict"
            conflict = ExecutionEnvelope.model_validate(conflict_values)
            with pytest.raises(DuplicateInvestigationId):
                await service.create(conflict)

            await started.wait()
            assert calls == 1
            release.set()
            await _terminal_transcript(service, envelope.investigation_id)
        finally:
            release.set()
            await service.aclose()

    asyncio.run(scenario())


@pytest.mark.unit
@pytest.mark.parametrize("fault_point", ["register", "append", "append_after"])
def test_exact_replay_repairs_interrupted_created_journal(
    fault_point: str,
) -> None:
    async def scenario() -> None:
        started = asyncio.Event()
        release = asyncio.Event()
        calls = 0

        async def executor(
            envelope: ExecutionEnvelope,
            *,
            revision: int,
            cancellation_event: asyncio.Event,
        ) -> InvestigationReport:
            nonlocal calls
            calls += 1
            started.set()
            await release.wait()
            return _zero_evidence_report(envelope, revision=revision)

        journal = _FailOnceCreatedJournal(fault_point)
        service = InvestigationApplicationService(
            InMemoryInvestigationRepository(),
            journal,
            executor,
            clock=lambda: NOW,
        )
        envelope = make_envelope()
        try:
            with pytest.raises(RuntimeError, match="injected"):
                await service.create(envelope)
            assert calls == 0

            repaired = await service.create(envelope)
            assert repaired.created is False
            assert repaired.report.revision == 0
            await started.wait()
            replayed = await service.create(envelope)
            assert replayed.created is False
            assert calls == 1

            release.set()
            events = await _terminal_transcript(service, envelope.investigation_id)
            created_events = [
                event
                for event in events
                if isinstance(event.payload, LifecycleEventPayload)
                and event.payload.status is InvestigationStatus.CREATED
            ]
            assert len(created_events) == 1
            assert created_events[0].sequence == 1
        finally:
            release.set()
            await service.aclose()

    asyncio.run(scenario())


@pytest.mark.unit
def test_cancellation_after_repository_create_finishes_created_event_once() -> None:
    async def scenario() -> None:
        executor_started = asyncio.Event()
        release_executor = asyncio.Event()
        calls = 0

        async def executor(
            envelope: ExecutionEnvelope,
            *,
            revision: int,
            cancellation_event: asyncio.Event,
        ) -> InvestigationReport:
            nonlocal calls
            calls += 1
            executor_started.set()
            await release_executor.wait()
            return _zero_evidence_report(envelope, revision=revision)

        journal = _BlockingCreatedJournal()
        service = InvestigationApplicationService(
            InMemoryInvestigationRepository(),
            journal,
            executor,
            clock=lambda: NOW,
        )
        envelope = make_envelope()
        create_task = asyncio.create_task(service.create(envelope))
        try:
            await journal.append_started.wait()
            create_task.cancel()
            await asyncio.sleep(0)
            assert not create_task.done()

            journal.release_append.set()
            with pytest.raises(asyncio.CancelledError):
                await create_task

            await executor_started.wait()
            replayed = await service.create(envelope)
            assert replayed.created is False
            assert calls == 1

            release_executor.set()
            events = await _terminal_transcript(service, envelope.investigation_id)
            assert (
                sum(
                    isinstance(event.payload, LifecycleEventPayload)
                    and event.payload.status is InvestigationStatus.CREATED
                    for event in events
                )
                == 1
            )
        finally:
            journal.release_append.set()
            release_executor.set()
            if not create_task.done():
                create_task.cancel()
            with suppress(asyncio.CancelledError):
                await create_task
            await service.aclose()

    asyncio.run(scenario())


@pytest.mark.unit
def test_replay_rejects_a_divergent_nonempty_created_journal() -> None:
    async def scenario() -> None:
        calls = 0

        async def executor(
            envelope: ExecutionEnvelope,
            *,
            revision: int,
            cancellation_event: asyncio.Event,
        ) -> InvestigationReport:
            nonlocal calls
            calls += 1
            return _zero_evidence_report(envelope, revision=revision)

        journal = InMemoryInvestigationEventJournal()
        envelope = make_envelope()
        await journal.register(envelope.investigation_id)
        await journal.append(
            InvestigationEvent(
                schema_version=INVESTIGATION_EVENT_VERSION,
                investigation_id=envelope.investigation_id,
                sequence=1,
                type=InvestigationEventType.LIFECYCLE,
                occurred_at=NOW + timedelta(seconds=1),
                payload=LifecycleEventPayload(status=InvestigationStatus.CREATED),
            )
        )
        service = InvestigationApplicationService(
            InMemoryInvestigationRepository(),
            journal,
            executor,
            clock=lambda: NOW,
        )
        try:
            with pytest.raises(RuntimeError, match="divergent created event"):
                await service.create(envelope)
            with pytest.raises(RuntimeError, match="divergent created event"):
                await service.create(envelope)
            assert calls == 0
        finally:
            await service.aclose()

    asyncio.run(scenario())


@pytest.mark.unit
@pytest.mark.parametrize("fault_mode", ["before", "after"])
def test_exact_replay_completes_an_interrupted_terminal_projection(
    fault_mode: str,
) -> None:
    async def scenario() -> None:
        calls = 0

        async def executor(
            envelope: ExecutionEnvelope,
            *,
            revision: int,
            cancellation_event: asyncio.Event,
        ) -> InvestigationReport:
            nonlocal calls
            calls += 1
            return _zero_evidence_report(envelope, revision=revision)

        journal = _FaultingTerminalJournal(fault_mode)
        service = InvestigationApplicationService(
            InMemoryInvestigationRepository(),
            journal,
            executor,
            clock=lambda: NOW,
        )
        envelope = make_envelope()
        try:
            await service.create(envelope)
            async with asyncio.timeout(2):
                await journal.faults_exhausted.wait()

            partial = await journal.snapshot(envelope.investigation_id)
            assert partial.terminal is False
            assert partial.cursor == (2 if fault_mode == "before" else 4)

            replayed = await service.create(envelope)
            assert replayed.created is False
            assert replayed.report.revision == 2
            assert calls == 1

            terminal = await service.snapshot(envelope.investigation_id)
            assert terminal.terminal is True
            assert [event.sequence for event in terminal.events] == list(
                range(1, terminal.cursor + 1)
            )
            assert (
                sum(
                    isinstance(event.payload, LifecycleEventPayload)
                    and event.payload.status is InvestigationStatus.CREATED
                    for event in terminal.events
                )
                == 1
            )
            assert (
                sum(
                    isinstance(event.payload, LifecycleEventPayload)
                    and event.payload.status is InvestigationStatus.COMPLETED
                    for event in terminal.events
                )
                == 1
            )

            report = await service.get(envelope.investigation_id)
            assert report.status is InvestigationStatus.COMPLETED
            replay = await service.wait_for_events(
                envelope.investigation_id,
                after=terminal.cursor,
            )
            assert replay.events == ()
            assert replay.terminal is True
        finally:
            await service.aclose()

    asyncio.run(scenario())


@pytest.mark.unit
def test_get_repairs_terminal_projection_before_sse_observes_report() -> None:
    async def scenario() -> None:
        calls = 0

        async def executor(
            envelope: ExecutionEnvelope,
            *,
            revision: int,
            cancellation_event: asyncio.Event,
        ) -> InvestigationReport:
            nonlocal calls
            calls += 1
            return _zero_evidence_report(envelope, revision=revision)

        journal = _FaultingTerminalJournal("before")
        service = InvestigationApplicationService(
            InMemoryInvestigationRepository(),
            journal,
            executor,
            clock=lambda: NOW,
        )
        envelope = make_envelope()
        try:
            await service.create(envelope)
            async with asyncio.timeout(2):
                await journal.faults_exhausted.wait()
            assert (await journal.snapshot(envelope.investigation_id)).terminal is False

            report = await service.get(envelope.investigation_id)
            assert report.status is InvestigationStatus.COMPLETED
            events = await service.wait_for_events(envelope.investigation_id)
            assert events.terminal is True
            assert events.events[-1].type is InvestigationEventType.LIFECYCLE
            assert isinstance(events.events[-1].payload, LifecycleEventPayload)
            assert events.events[-1].payload.status is InvestigationStatus.COMPLETED
            assert calls == 1
        finally:
            await service.aclose()

    asyncio.run(scenario())


@pytest.mark.unit
def test_terminal_repair_rejects_a_divergent_accepted_suffix() -> None:
    async def scenario() -> None:
        calls = 0

        async def executor(
            envelope: ExecutionEnvelope,
            *,
            revision: int,
            cancellation_event: asyncio.Event,
        ) -> InvestigationReport:
            nonlocal calls
            calls += 1
            return _zero_evidence_report(envelope, revision=revision)

        journal = _FaultingTerminalJournal("before")
        service = InvestigationApplicationService(
            InMemoryInvestigationRepository(),
            journal,
            executor,
            clock=lambda: NOW,
        )
        envelope = make_envelope()
        try:
            await service.create(envelope)
            async with asyncio.timeout(2):
                await journal.faults_exhausted.wait()
            await journal.append(
                InvestigationEvent(
                    schema_version=INVESTIGATION_EVENT_VERSION,
                    investigation_id=envelope.investigation_id,
                    sequence=3,
                    type=InvestigationEventType.LIFECYCLE,
                    occurred_at=NOW,
                    payload=LifecycleEventPayload(status=InvestigationStatus.COMPLETED),
                )
            )

            with pytest.raises(RuntimeError, match="diverges"):
                await service.create(envelope)
            with pytest.raises(RuntimeError, match="diverges"):
                await service.get(envelope.investigation_id)
            assert calls == 1
        finally:
            await service.aclose()

    asyncio.run(scenario())


@pytest.mark.unit
def test_terminal_projection_preserves_complete_semantic_event_order() -> None:
    async def scenario() -> None:
        terminal_report = _two_probe_report()

        async def executor(
            envelope: ExecutionEnvelope,
            *,
            revision: int,
            cancellation_event: asyncio.Event,
        ) -> InvestigationReport:
            assert envelope == make_envelope()
            assert revision == 2
            assert not cancellation_event.is_set()
            assert terminal_report.revision == revision
            return terminal_report

        service = InvestigationApplicationService(
            InMemoryInvestigationRepository(),
            InMemoryInvestigationEventJournal(),
            executor,
            clock=lambda: NOW,
        )
        investigation_id = make_envelope().investigation_id
        try:
            result = await service.create(make_envelope())
            assert result.created is True
            events = await _terminal_transcript(service, investigation_id)

            assert [event.sequence for event in events] == list(
                range(1, len(events) + 1)
            )
            assert [event.type for event in events] == [
                InvestigationEventType.LIFECYCLE,
                InvestigationEventType.LIFECYCLE,
                InvestigationEventType.PROBE,
                InvestigationEventType.PROBE,
                InvestigationEventType.EVIDENCE_DECISION,
                InvestigationEventType.EVIDENCE_DECISION,
                InvestigationEventType.CLASSIFICATION,
                *([InvestigationEventType.ACTION_GATE] * 5),
                InvestigationEventType.LIFECYCLE,
            ]
            assert isinstance(events[0].payload, LifecycleEventPayload)
            assert events[0].payload.status is InvestigationStatus.CREATED
            assert isinstance(events[1].payload, LifecycleEventPayload)
            assert events[1].payload.status is InvestigationStatus.INVESTIGATING
            probe_events = events[2:4]
            decision_events = events[4:6]
            assert all(
                isinstance(event.payload, ProbeEventPayload) for event in probe_events
            )
            assert all(
                isinstance(event.payload, EvidenceDecisionEventPayload)
                for event in decision_events
            )
            assert [
                cast(ProbeEventPayload, event.payload).probe_audit
                for event in probe_events
            ] == list(terminal_report.probe_audit)
            assert [
                cast(EvidenceDecisionEventPayload, event.payload).decision
                for event in decision_events
            ] == list(terminal_report.evidence_decisions)
            gate_events = events[7:12]
            assert all(
                isinstance(event.payload, ActionGateEventPayload)
                for event in gate_events
            )
            assert [
                cast(ActionGateEventPayload, event.payload).action_gate.requested_action
                for event in gate_events
            ] == list(RequestedAction)
            assert isinstance(events[-1].payload, LifecycleEventPayload)
            assert events[-1].payload.status is InvestigationStatus.COMPLETED
            report = await service.get(investigation_id)
            assert report.status is InvestigationStatus.COMPLETED
            assert report.classification is Classification.COMMITTED
            assert report.revision == 2
            terminal_replay = await service.snapshot(
                investigation_id,
                after=len(events),
            )
            assert terminal_replay.events == ()
            assert terminal_replay.terminal is True
        finally:
            await service.aclose()

    asyncio.run(scenario())


@pytest.mark.unit
def test_executor_failure_becomes_zero_evidence_unknown_terminal_report() -> None:
    async def scenario() -> None:
        async def executor(
            envelope: ExecutionEnvelope,
            *,
            revision: int,
            cancellation_event: asyncio.Event,
        ) -> InvestigationReport:
            raise RuntimeError("controller dependency failed")

        service = InvestigationApplicationService(
            InMemoryInvestigationRepository(),
            InMemoryInvestigationEventJournal(),
            executor,
            clock=lambda: NOW,
        )
        investigation_id = make_envelope().investigation_id
        try:
            await service.create(make_envelope())
            events = await _terminal_transcript(service, investigation_id)
            report = await service.get(investigation_id)

            assert report.status is InvestigationStatus.COMPLETED
            assert report.revision == 2
            assert report.classification is Classification.UNKNOWN
            assert report.probe_audit == ()
            assert report.evidence == ()
            assert report.evidence_decisions == ()
            assert [gate.requested_action for gate in report.action_gate] == list(
                RequestedAction
            )
            assert [event.type for event in events] == [
                InvestigationEventType.LIFECYCLE,
                InvestigationEventType.LIFECYCLE,
                InvestigationEventType.CLASSIFICATION,
                *([InvestigationEventType.ACTION_GATE] * 5),
                InvestigationEventType.LIFECYCLE,
            ]
        finally:
            await service.aclose()

    asyncio.run(scenario())


@pytest.mark.unit
def test_concurrent_reads_are_coherent_during_active_and_terminal_states() -> None:
    async def scenario() -> None:
        started = asyncio.Event()
        release = asyncio.Event()

        async def executor(
            envelope: ExecutionEnvelope,
            *,
            revision: int,
            cancellation_event: asyncio.Event,
        ) -> InvestigationReport:
            started.set()
            await release.wait()
            return _zero_evidence_report(envelope, revision=revision)

        service = InvestigationApplicationService(
            InMemoryInvestigationRepository(),
            InMemoryInvestigationEventJournal(),
            executor,
            clock=lambda: NOW,
        )
        investigation_id = make_envelope().investigation_id
        try:
            await service.create(make_envelope())
            await started.wait()

            active_reads = await asyncio.gather(
                *(service.get(investigation_id) for _ in range(32))
            )
            assert {(report.status, report.revision) for report in active_reads} == {
                (InvestigationStatus.INVESTIGATING, 1)
            }
            assert (await service.snapshot(investigation_id)).cursor == 2

            release.set()
            events = await _terminal_transcript(service, investigation_id)
            terminal_reads = await asyncio.gather(
                *(service.get(investigation_id) for _ in range(32))
            )
            assert {(report.status, report.revision) for report in terminal_reads} == {
                (InvestigationStatus.COMPLETED, 2)
            }
            assert (await service.snapshot(investigation_id)).cursor == len(events)
        finally:
            release.set()
            await service.aclose()

    asyncio.run(scenario())


@pytest.mark.unit
def test_close_cancels_owned_execution_and_finishes_unknown() -> None:
    async def scenario() -> None:
        started = asyncio.Event()
        finalized = asyncio.Event()

        async def executor(
            envelope: ExecutionEnvelope,
            *,
            revision: int,
            cancellation_event: asyncio.Event,
        ) -> InvestigationReport:
            started.set()
            try:
                await asyncio.Event().wait()
            finally:
                finalized.set()

        service = InvestigationApplicationService(
            InMemoryInvestigationRepository(),
            InMemoryInvestigationEventJournal(),
            executor,
            clock=lambda: NOW,
        )
        envelope = make_envelope()
        await service.create(envelope)
        await started.wait()

        await service.aclose()
        await service.aclose()

        assert finalized.is_set()
        report = await service.get(envelope.investigation_id)
        assert report.status is InvestigationStatus.COMPLETED
        assert report.classification is Classification.UNKNOWN
        snapshot = await service.snapshot(envelope.investigation_id)
        assert snapshot.terminal is True
        with pytest.raises(RuntimeError, match="closed"):
            await service.create(envelope)

    asyncio.run(scenario())


@pytest.mark.unit
def test_malformed_foreign_and_wrong_policy_reports_are_never_accepted() -> None:
    async def scenario() -> None:
        envelope = make_envelope()
        foreign_values = envelope.model_dump(mode="python")
        foreign_values["investigation_id"] = "investigation-foreign"
        foreign_envelope = ExecutionEnvelope.model_validate(foreign_values)

        wrong_policy_base = _probe_report()
        wrong_policy_gates = tuple(
            gate.model_copy(update={"action_policy_version": "action-foreign-v1"})
            for gate in wrong_policy_base.action_gate
        )
        wrong_policy = InvestigationReport.model_validate(
            wrong_policy_base.model_copy(update={"action_gate": wrong_policy_gates})
        )
        candidates: tuple[object, ...] = (
            object(),
            _zero_evidence_report(foreign_envelope),
            wrong_policy,
        )

        for candidate in candidates:

            async def executor(
                received: ExecutionEnvelope,
                *,
                revision: int,
                cancellation_event: asyncio.Event,
                candidate: object = candidate,
            ) -> Any:
                return candidate

            service = InvestigationApplicationService(
                InMemoryInvestigationRepository(),
                InMemoryInvestigationEventJournal(),
                executor,
                clock=lambda: NOW,
            )
            try:
                await service.create(envelope)
                await _terminal_transcript(service, envelope.investigation_id)
                report = await service.get(envelope.investigation_id)
                assert report.investigation_id == envelope.investigation_id
                assert report.envelope_sha256 == canonical_sha256(envelope)
                assert report.classification is Classification.UNKNOWN
                assert report.probe_audit == ()
            finally:
                await service.aclose()

    asyncio.run(scenario())


@pytest.mark.unit
def test_reports_exceeding_or_reversing_sealed_budget_counters_are_rejected() -> None:
    async def scenario() -> None:
        envelope = make_envelope()
        budget = envelope.context.evidence_budget
        one_probe = _probe_report()

        def with_first_audit(**updates: int) -> InvestigationReport:
            audit = one_probe.probe_audit[0].model_copy(update=updates)
            return InvestigationReport.model_validate(
                one_probe.model_copy(update={"probe_audit": (audit,)})
            )

        over_limit = (
            with_first_audit(probe_count_used=budget.max_probes + 1),
            with_first_audit(session_elapsed_ms=budget.max_elapsed_ms + 1),
            with_first_audit(result_bytes_acquired=budget.max_total_result_bytes + 1),
            with_first_audit(cost_units_used=budget.max_cost_units + 1),
        )

        two_probe = _two_probe_report()
        reversed_second = two_probe.probe_audit[1].model_copy(
            update={"session_elapsed_ms": 1_000}
        )
        reversed_cumulative = InvestigationReport.model_validate(
            two_probe.model_copy(
                update={"probe_audit": (two_probe.probe_audit[0], reversed_second)}
            )
        )

        constrained_budget = budget.model_copy(update={"max_probes": 1})
        constrained_context = envelope.context.model_copy(
            update={"evidence_budget": constrained_budget}
        )
        constrained_envelope = ExecutionEnvelope.model_validate(
            envelope.model_copy(update={"context": constrained_context})
        )
        over_audit_count = InvestigationReport.model_validate(
            two_probe.model_copy(
                update={"envelope_sha256": canonical_sha256(constrained_envelope)}
            )
        )

        cases = (
            *((envelope, candidate) for candidate in over_limit),
            (envelope, reversed_cumulative),
            (constrained_envelope, over_audit_count),
        )
        for sealed_envelope, candidate in cases:

            async def executor(
                received: ExecutionEnvelope,
                *,
                revision: int,
                cancellation_event: asyncio.Event,
                candidate: InvestigationReport = candidate,
            ) -> InvestigationReport:
                return candidate

            service = InvestigationApplicationService(
                InMemoryInvestigationRepository(),
                InMemoryInvestigationEventJournal(),
                executor,
                clock=lambda: NOW,
            )
            try:
                await service.create(sealed_envelope)
                await _terminal_transcript(service, sealed_envelope.investigation_id)
                report = await service.get(sealed_envelope.investigation_id)
                assert report.classification is Classification.UNKNOWN
                assert report.probe_audit == ()
            finally:
                await service.aclose()

    asyncio.run(scenario())


@pytest.mark.unit
def test_create_requires_the_exact_versioned_envelope_contract() -> None:
    async def scenario() -> None:
        async def executor(
            envelope: ExecutionEnvelope,
            *,
            revision: int,
            cancellation_event: asyncio.Event,
        ) -> InvestigationReport:
            return _zero_evidence_report(envelope, revision=revision)

        service = InvestigationApplicationService(
            InMemoryInvestigationRepository(),
            InMemoryInvestigationEventJournal(),
            executor,
            clock=lambda: NOW,
        )
        try:
            unsupported = {
                "schema_version": "reconcile/execution-envelope/v2",
            }
            with pytest.raises(TypeError, match="execution envelope"):
                await service.create(cast(ExecutionEnvelope, unsupported))
        finally:
            await service.aclose()

    asyncio.run(scenario())
