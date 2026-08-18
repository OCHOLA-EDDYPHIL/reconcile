"""Firestore-backed request-scoped scenario aggregate tests."""

from __future__ import annotations

import asyncio
import json
from datetime import UTC, datetime, timedelta

import pytest

from reconcile.contracts import (
    SCENARIO_LAUNCH_REQUEST_VERSION,
    SCENARIO_RUN_EVENT_VERSION,
    SCENARIO_RUN_SNAPSHOT_VERSION,
    Classification,
    ComparisonStrategyKind,
    EnvelopeSummaryEventPayload,
    ScenarioLaunchName,
    ScenarioLaunchRequest,
    ScenarioLifecycleEventPayload,
    ScenarioRunEvent,
    ScenarioRunEventType,
    ScenarioRunFailureCategory,
    ScenarioRunLifecycle,
    ScenarioRunMode,
    ScenarioRunResultKind,
    ScenarioRunSnapshot,
    TerminalStateEventPayload,
    TerminalStateSummary,
    canonical_json_bytes,
    canonical_sha256,
)
from reconcile.contracts.comparison import InvestigationComparisonRecord
from reconcile.hosted.apps import InternalOperationDenied
from reconcile.hosted.firestore_cas import (
    FirestoreCasCollection,
    FirestoreCasConflict,
    FirestoreCasDocument,
    FirestoreCasOutcomeUnknown,
    FirestoreCasSnapshot,
    firestore_cas_document_key,
)
from reconcile.hosted.firestore_scenarios import (
    FIRESTORE_SCENARIO_AGGREGATE_VERSION,
    FIRESTORE_SCENARIO_INDEX_VERSION,
    FirestoreScenarioEnumerationUnavailable,
    FirestoreScenarioStore,
    FirestoreScenarioStoreError,
)
from reconcile.hosted.operations import FirestoreHostedOperationScopeAuthorizer
from reconcile.hosted.provider import (
    HOSTED_CANDIDATE_IDENTITY_VERSION,
    HostedCandidateIdentity,
)
from reconcile.hosted.workflow import (
    HOSTED_OPERATION_SCOPE_VERSION,
    HostedOperationScope,
    HostedWorkflowOperation,
)
from reconcile.operator import sanitize_report
from reconcile.persistence import (
    CleanupStatus,
    CorruptScenarioState,
    ScenarioLane,
    ScenarioLeaseUnavailable,
    ScenarioStateConflict,
    ScenarioWorkConflict,
    StaleScenarioLease,
)
from reconcile.scenarios.service import _envelope_summary
from tests.contract._factories import (
    NOW,
    make_comparison_record,
    make_report,
    make_scenario_request,
    make_scenario_result,
)

pytestmark = pytest.mark.unit

CANDIDATE = HostedCandidateIdentity(
    schema_version=HOSTED_CANDIDATE_IDENTITY_VERSION,
    source_revision="a" * 40,
    image_digest=f"sha256:{'b' * 64}",
    infrastructure_revision="c" * 64,
    semantic_config_sha256="2" * 64,
    project_id="reconcile-dev-260813-14fa6d",
    vertex_location="us",
    configured_model="gemini-3.5-flash",
    prompt_version="hosted-acquisition-v1",
    prompt_sha256="d" * 64,
    maximum_input_tokens=12_000,
    maximum_output_tokens=1_024,
    thinking_level="MINIMAL",
    maximum_count_tokens_attempts=1,
    maximum_generation_attempts=1,
)


class _MemoryCasStore:
    def __init__(self, *, synchronize_creates: int = 0) -> None:
        self._lock = asyncio.Lock()
        self._clock = 0
        self._create_target = synchronize_creates
        self._create_waiters = 0
        self._create_gate = asyncio.Event()
        self.documents: dict[
            tuple[FirestoreCasCollection, str], FirestoreCasSnapshot
        ] = {}
        self.reads: list[tuple[FirestoreCasCollection, str]] = []
        self.create_pairs: list[tuple[FirestoreCasDocument, FirestoreCasDocument]] = []
        self.updates: list[tuple[FirestoreCasSnapshot, FirestoreCasDocument]] = []
        self.writes: list[FirestoreCasDocument] = []
        self.read_error: BaseException | None = None
        self.create_error: BaseException | None = None
        self.update_error: BaseException | None = None

    def _snapshot(self, document: FirestoreCasDocument) -> FirestoreCasSnapshot:
        self._clock += 1
        return FirestoreCasSnapshot(
            collection=document.kind,
            document_key=firestore_cas_document_key(
                document.kind,
                document.logical_id,
            ),
            document=document,
            update_time=datetime(2026, 8, 18, tzinfo=UTC)
            + timedelta(microseconds=self._clock),
        )

    async def read(
        self,
        collection: FirestoreCasCollection,
        logical_id: str,
    ) -> FirestoreCasSnapshot | None:
        self.reads.append((collection, logical_id))
        if self.read_error is not None:
            raise self.read_error
        return self.documents.get((collection, logical_id))

    async def create_pair(
        self,
        first: FirestoreCasDocument,
        second: FirestoreCasDocument,
    ) -> tuple[FirestoreCasSnapshot, FirestoreCasSnapshot]:
        self.create_pairs.append((first, second))
        if self._create_target:
            self._create_waiters += 1
            if self._create_waiters == self._create_target:
                self._create_gate.set()
            await self._create_gate.wait()
        if self.create_error is not None:
            raise self.create_error
        async with self._lock:
            keys = (
                (first.kind, first.logical_id),
                (second.kind, second.logical_id),
            )
            if any(key in self.documents for key in keys):
                raise FirestoreCasConflict
            snapshots = (self._snapshot(first), self._snapshot(second))
            self.documents[keys[0]] = snapshots[0]
            self.documents[keys[1]] = snapshots[1]
            self.writes.extend((first, second))
            return snapshots

    async def update(
        self,
        current: FirestoreCasSnapshot,
        replacement: FirestoreCasDocument,
    ) -> FirestoreCasSnapshot:
        self.updates.append((current, replacement))
        if self.update_error is not None:
            raise self.update_error
        async with self._lock:
            key = (replacement.kind, replacement.logical_id)
            stored = self.documents.get(key)
            if stored is None or stored.update_time != current.update_time:
                raise FirestoreCasConflict
            if replacement.revision != stored.document.revision + 1:
                raise FirestoreCasConflict
            snapshot = self._snapshot(replacement)
            self.documents[key] = snapshot
            self.writes.append(replacement)
            return snapshot


def _creation_values(
    *,
    mode: ScenarioRunMode = ScenarioRunMode.FIXED,
) -> dict[str, object]:
    request = make_scenario_request()
    launch = ScenarioLaunchRequest(
        schema_version=SCENARIO_LAUNCH_REQUEST_VERSION,
        launch_id=request.run_id,
        scenario=ScenarioLaunchName.STORAGE,
        mode=mode,
    )
    accepted = ScenarioRunEvent(
        schema_version=SCENARIO_RUN_EVENT_VERSION,
        investigation_id=request.investigation_id,
        cursor=1,
        type=ScenarioRunEventType.LIFECYCLE,
        occurred_at=NOW,
        payload=ScenarioLifecycleEventPayload(lifecycle=ScenarioRunLifecycle.ACCEPTED),
    )
    snapshot = ScenarioRunSnapshot(
        schema_version=SCENARIO_RUN_SNAPSHOT_VERSION,
        launch_id=launch.launch_id,
        investigation_id=request.investigation_id,
        scenario=launch.scenario,
        mode=mode,
        lifecycle=ScenarioRunLifecycle.ACCEPTED,
        event_cursor=1,
        envelope_summary=None,
        report=None,
        comparison=None,
        failure_category=None,
        accepted_at=NOW,
        updated_at=NOW,
    )
    return {
        "launch_request": launch,
        "scenario_request": request,
        "strategy_sha256": "1" * 64,
        "semantic_config_sha256": "2" * 64,
        "runtime_provenance_sha256": "3" * 64,
        "workspace_id": "workspace-7",
        "invoked_at": NOW,
        "snapshot": snapshot,
        "accepted_event": accepted,
        "created_at": NOW,
    }


async def _create(
    store: _MemoryCasStore,
    *,
    mode: ScenarioRunMode = ScenarioRunMode.FIXED,
) -> tuple[FirestoreScenarioStore, object]:
    scenarios = FirestoreScenarioStore(store, CANDIDATE)
    created = await scenarios.create_work(**_creation_values(mode=mode))  # type: ignore[arg-type]
    return scenarios, created.work


async def _record_mutation_and_start(
    scenarios: FirestoreScenarioStore,
    *,
    now: datetime,
):
    result = make_scenario_result()
    assert result.execution_envelope is not None
    prepared = canonical_json_bytes(result.execution_envelope)
    token = await scenarios.acquire_scenario_lease(
        result.investigation_id,
        "owner-7",
        now=now,
    )
    await scenarios.record_mutation_started(
        token,
        prepared_envelope=result.execution_envelope,
        prepared_envelope_sha256=canonical_sha256(result.execution_envelope),
        cleanup_manifest_sha256=result.fixture.cleanup_manifest_sha256,
        occurred_at=now + timedelta(milliseconds=1),
    )
    await scenarios.record_mutation_result(
        token,
        result,
        prepared_envelope_bytes=prepared,
        occurred_at=now + timedelta(milliseconds=2),
    )
    work = await scenarios.mark_investigation_started(
        token,
        occurred_at=now + timedelta(milliseconds=3),
    )
    return token, work


def _operation_scope(
    work: object,
    token: object,
    operation: HostedWorkflowOperation,
) -> HostedOperationScope:
    request = work.scenario_request  # type: ignore[attr-defined]
    function_call_id = request.function_call_id
    envelope_sha256 = (
        work.prepared_envelope_sha256  # type: ignore[attr-defined]
        if operation is HostedWorkflowOperation.EXECUTE_FAULT
        else work.envelope_sha256  # type: ignore[attr-defined]
    )
    cleanup_manifest_sha256 = work.cleanup_manifest_sha256  # type: ignore[attr-defined]
    assert function_call_id is not None
    assert envelope_sha256 is not None
    assert cleanup_manifest_sha256 is not None
    return HostedOperationScope(
        schema_version=HOSTED_OPERATION_SCOPE_VERSION,
        operation=operation,
        launch_id=work.launch_request.launch_id,  # type: ignore[attr-defined]
        launch_sha256=work.launch_sha256,  # type: ignore[attr-defined]
        scenario_request_sha256=work.scenario_request_sha256,  # type: ignore[attr-defined]
        investigation_id=request.investigation_id,
        operation_id=request.operation_id,
        invocation_id=request.invocation_id,
        function_call_id=function_call_id,
        envelope_sha256=envelope_sha256,
        cleanup_manifest_sha256=cleanup_manifest_sha256,
        lease_fence=token.fence,  # type: ignore[attr-defined]
    )


def _comparison(work: object) -> InvestigationComparisonRecord:
    template = make_comparison_record(include_adaptive=True)
    assert template.adaptive is not None
    scenario = work.scenario_request.scenario  # type: ignore[attr-defined]
    envelope_sha256 = work.envelope_sha256  # type: ignore[attr-defined]
    baseline = template.baseline.model_copy(
        update={"scenario": scenario, "envelope_sha256": envelope_sha256}
    )
    adaptive = template.adaptive.model_copy(
        update={"scenario": scenario, "envelope_sha256": envelope_sha256}
    )
    return template.model_copy(
        update={
            "scenario": scenario,
            "envelope_sha256": envelope_sha256,
            "baseline": baseline,
            "adaptive": adaptive,
        }
    )


def test_atomic_create_index_exact_replay_and_fresh_instance_reads() -> None:
    async def scenario() -> None:
        store = _MemoryCasStore()
        _, work = await _create(store)

        assert len(store.create_pairs) == 1
        aggregate, index = store.create_pairs[0]
        assert aggregate.kind is FirestoreCasCollection.SCENARIO
        assert aggregate.logical_id == "run-7"
        assert aggregate.revision == 0
        assert index.kind is FirestoreCasCollection.SCENARIO_INDEX
        assert index.logical_id == "investigation-7"
        assert index.revision == 0
        assert aggregate.mutation_id != index.mutation_id

        aggregate_payload = json.loads(aggregate.canonical_payload)
        index_payload = json.loads(index.canonical_payload)
        assert (
            aggregate_payload["schema_version"] == FIRESTORE_SCENARIO_AGGREGATE_VERSION
        )
        assert index_payload["schema_version"] == FIRESTORE_SCENARIO_INDEX_VERSION
        assert index_payload["launch_sha256"] == work.launch_sha256
        assert index_payload["scenario_request_sha256"] == work.scenario_request_sha256
        assert index_payload["strategy_sha256"] == "1" * 64
        assert index_payload["semantic_config_sha256"] == "2" * 64
        assert index_payload["runtime_provenance_sha256"] == "3" * 64
        assert aggregate_payload["candidate"] == CANDIDATE.model_dump(mode="json")
        assert index_payload["candidate_id"] == CANDIDATE.candidate_id
        assert index_payload["candidate_sha256"] == CANDIDATE.sha256

        restarted = FirestoreScenarioStore(store, CANDIDATE)
        assert await restarted.get_work("investigation-7") == work
        projection = await restarted.snapshot_projection("investigation-7")
        assert projection.snapshot == work.snapshot
        assert projection.cursor == 1
        assert len(projection.events) == 1
        assert projection.terminal is False

        replay = await restarted.create_work(**_creation_values())  # type: ignore[arg-type]
        assert replay.created is False
        assert replay.work == work
        assert len(store.create_pairs) == 1

        conflict_values = _creation_values()
        conflict_values["strategy_sha256"] = "9" * 64
        with pytest.raises(ScenarioWorkConflict):
            await restarted.create_work(**conflict_values)  # type: ignore[arg-type]
        drifted_candidate = CANDIDATE.model_copy(update={"source_revision": "e" * 40})
        with pytest.raises(ScenarioWorkConflict):
            await FirestoreScenarioStore(
                store,
                drifted_candidate,
            ).create_work(**_creation_values())  # type: ignore[arg-type]
        with pytest.raises(CorruptScenarioState):
            await FirestoreScenarioStore(
                store,
                drifted_candidate,
            ).get_work("investigation-7")
        assert len(store.create_pairs) == 1

    asyncio.run(scenario())


def test_concurrent_exact_create_has_one_atomic_create_and_one_replay() -> None:
    async def scenario() -> None:
        store = _MemoryCasStore(synchronize_creates=2)
        first = FirestoreScenarioStore(store, CANDIDATE)
        second = FirestoreScenarioStore(store, CANDIDATE)
        results = await asyncio.gather(
            first.create_work(**_creation_values()),  # type: ignore[arg-type]
            second.create_work(**_creation_values()),  # type: ignore[arg-type]
        )

        assert sorted(result.created for result in results) == [False, True]
        assert results[0].work == results[1].work
        assert len(store.create_pairs) == 2
        assert len(store.writes) == 2
        assert {document.kind for document in store.writes} == {
            FirestoreCasCollection.SCENARIO,
            FirestoreCasCollection.SCENARIO_INDEX,
        }

    asyncio.run(scenario())


def test_create_resolves_atomic_commit_between_preliminary_reads() -> None:
    class _CommitBetweenReads(_MemoryCasStore):
        def __init__(
            self,
            committed: dict[tuple[FirestoreCasCollection, str], FirestoreCasSnapshot],
        ) -> None:
            super().__init__()
            self._committed = committed

        async def read(
            self,
            collection: FirestoreCasCollection,
            logical_id: str,
        ) -> FirestoreCasSnapshot | None:
            result = await super().read(collection, logical_id)
            if len(self.reads) == 1:
                self.documents.update(self._committed)
            return result

    async def scenario() -> None:
        committed = _MemoryCasStore()
        original = await FirestoreScenarioStore(committed, CANDIDATE).create_work(
            **_creation_values()  # type: ignore[arg-type]
        )
        interleaved = _CommitBetweenReads(dict(committed.documents))

        replay = await FirestoreScenarioStore(interleaved, CANDIDATE).create_work(
            **_creation_values()  # type: ignore[arg-type]
        )

        assert replay.created is False
        assert replay.work == original.work
        assert interleaved.create_pairs == []
        assert interleaved.reads == [
            (FirestoreCasCollection.SCENARIO, "run-7"),
            (FirestoreCasCollection.SCENARIO_INDEX, "investigation-7"),
            (FirestoreCasCollection.SCENARIO, "run-7"),
        ]

    asyncio.run(scenario())


def test_fixed_state_machine_is_one_cas_per_transition_and_never_replays() -> None:
    async def scenario() -> None:
        store = _MemoryCasStore()
        scenarios, _ = await _create(store)
        now = NOW + timedelta(seconds=1)
        token = await scenarios.acquire_scenario_lease(
            "investigation-7",
            "owner-7",
            now=now,
        )
        token = await scenarios.renew_scenario_lease(
            token,
            now=now + timedelta(seconds=1),
        )
        result = make_scenario_result()
        assert result.execution_envelope is not None
        prepared = canonical_json_bytes(result.execution_envelope)
        await scenarios.record_mutation_started(
            token,
            prepared_envelope=result.execution_envelope,
            prepared_envelope_sha256=canonical_sha256(result.execution_envelope),
            cleanup_manifest_sha256=result.fixture.cleanup_manifest_sha256,
            occurred_at=now + timedelta(seconds=2),
        )
        started_payload = json.loads(store.updates[-1][1].canonical_payload)
        assert started_payload["prepared_envelope"] == (
            result.execution_envelope.model_dump(mode="json")
        )
        assert started_payload["work"]["prepared_envelope_sha256"] == (
            canonical_sha256(result.execution_envelope)
        )
        await scenarios.record_mutation_result(
            token,
            result,
            prepared_envelope_bytes=prepared,
            occurred_at=now + timedelta(seconds=3),
        )
        work = await scenarios.mark_investigation_started(
            token,
            occurred_at=now + timedelta(seconds=4),
        )
        report = make_report(Classification.COMMITTED).model_copy(
            update={
                "investigation_id": "investigation-7",
                "envelope_sha256": work.envelope_sha256,
            }
        )
        work = await scenarios.record_workflow_result(
            token,
            report,
            occurred_at=now + timedelta(seconds=5),
        )
        assert work.workflow_result == report
        await scenarios.record_scenario_cleanup(
            token,
            CleanupStatus.PENDING,
            occurred_at=now + timedelta(seconds=6),
        )
        final = await scenarios.record_scenario_cleanup(
            token,
            CleanupStatus.SUCCEEDED,
            occurred_at=now + timedelta(seconds=7),
        )
        await scenarios.release_scenario_lease(
            token,
            now=now + timedelta(seconds=8),
        )

        assert final.cleanup_status is CleanupStatus.SUCCEEDED
        assert [document.revision for _, document in store.updates] == list(
            range(1, 10)
        )
        assert len({document.mutation_id for _, document in store.updates}) == 9
        assert all(
            document.kind is FirestoreCasCollection.SCENARIO
            and document.logical_id == "run-7"
            for _, document in store.updates
        )

        update_count = len(store.updates)
        with pytest.raises(ScenarioStateConflict):
            await scenarios.record_mutation_started(
                token,
                prepared_envelope=result.execution_envelope,
                prepared_envelope_sha256=canonical_sha256(result.execution_envelope),
                cleanup_manifest_sha256=result.fixture.cleanup_manifest_sha256,
                occurred_at=now + timedelta(seconds=9),
            )
        with pytest.raises(ScenarioStateConflict):
            await scenarios.record_workflow_result(
                token,
                report,
                occurred_at=now + timedelta(seconds=9),
            )
        with pytest.raises(ScenarioStateConflict):
            await scenarios.record_scenario_cleanup(
                token,
                CleanupStatus.SUCCEEDED,
                occurred_at=now + timedelta(seconds=9),
            )
        assert len(store.updates) == update_count
        assert (
            await FirestoreScenarioStore(store, CANDIDATE).get_work("investigation-7")
        ).cleanup_status is CleanupStatus.SUCCEEDED

    asyncio.run(scenario())


def test_compare_lanes_are_exact_idempotent_and_required_by_result() -> None:
    async def scenario() -> None:
        store = _MemoryCasStore()
        scenarios, _ = await _create(store, mode=ScenarioRunMode.COMPARE)
        token, work = await _record_mutation_and_start(
            scenarios,
            now=NOW + timedelta(seconds=1),
        )
        comparison = _comparison(work)
        assert comparison.adaptive is not None

        await scenarios.record_lane_result(
            token,
            ScenarioLane.FIXED,
            comparison.baseline,
            occurred_at=NOW + timedelta(seconds=2),
        )
        update_count = len(store.updates)
        await scenarios.record_lane_result(
            token,
            ScenarioLane.FIXED,
            comparison.baseline,
            occurred_at=NOW + timedelta(seconds=2),
        )
        assert len(store.updates) == update_count
        assert (
            await FirestoreScenarioStore(store, CANDIDATE).get_lane_result(
                "investigation-7",
                ScenarioLane.FIXED,
            )
            == comparison.baseline
        )

        with pytest.raises(ScenarioStateConflict):
            await scenarios.record_workflow_result(
                token,
                comparison,
                occurred_at=NOW + timedelta(seconds=3),
            )
        divergent = comparison.baseline.model_copy(
            update={"strategy_kind": ComparisonStrategyKind.ADAPTIVE}
        )
        with pytest.raises(ScenarioStateConflict):
            await scenarios.record_lane_result(
                token,
                ScenarioLane.FIXED,
                divergent,
                occurred_at=NOW + timedelta(seconds=3),
            )

        await scenarios.record_lane_result(
            token,
            ScenarioLane.ADAPTIVE,
            comparison.adaptive,
            occurred_at=NOW + timedelta(seconds=3),
        )
        recorded = await scenarios.record_workflow_result(
            token,
            comparison,
            occurred_at=NOW + timedelta(seconds=4),
        )
        assert recorded.workflow_result == comparison
        assert (
            await FirestoreScenarioStore(store, CANDIDATE).get_lane_result(
                "investigation-7",
                ScenarioLane.ADAPTIVE,
            )
            == comparison.adaptive
        )

    asyncio.run(scenario())


def test_list_work_fails_without_reading_or_enumerating() -> None:
    async def scenario() -> None:
        store = _MemoryCasStore()
        scenarios = FirestoreScenarioStore(store, CANDIDATE)
        with pytest.raises(FirestoreScenarioEnumerationUnavailable) as captured:
            await scenarios.list_work()
        assert str(captured.value) == (
            "hosted scenario work enumeration is unavailable"
        )
        assert store.reads == []

    asyncio.run(scenario())


def test_cas_failures_are_sanitized_one_attempt_and_cancellation_propagates() -> None:
    async def scenario() -> None:
        create_store = _MemoryCasStore()
        create_store.create_error = FirestoreCasOutcomeUnknown()
        with pytest.raises(FirestoreScenarioStoreError) as create_failure:
            await FirestoreScenarioStore(create_store, CANDIDATE).create_work(
                **_creation_values()  # type: ignore[arg-type]
            )
        assert str(create_failure.value) == (
            "hosted scenario persistence is unavailable"
        )
        assert create_failure.value.__cause__ is None
        assert len(create_store.create_pairs) == 1

        update_store = _MemoryCasStore()
        scenarios, _ = await _create(update_store)
        update_store.update_error = RuntimeError("private provider response")
        with pytest.raises(FirestoreScenarioStoreError) as update_failure:
            await scenarios.acquire_scenario_lease(
                "investigation-7",
                "owner-7",
                now=NOW,
            )
        assert "private" not in str(update_failure.value)
        assert update_failure.value.__cause__ is None
        assert len(update_store.updates) == 1

        cancel_store = _MemoryCasStore()
        cancel_store.create_error = asyncio.CancelledError()
        with pytest.raises(asyncio.CancelledError):
            await FirestoreScenarioStore(cancel_store, CANDIDATE).create_work(
                **_creation_values()  # type: ignore[arg-type]
            )
        assert len(cancel_store.create_pairs) == 1

    asyncio.run(scenario())


def test_index_without_its_bound_aggregate_fails_closed() -> None:
    async def scenario() -> None:
        store = _MemoryCasStore()
        await _create(store)
        aggregate_key = (FirestoreCasCollection.SCENARIO, "run-7")
        store.documents.pop(aggregate_key)
        with pytest.raises(CorruptScenarioState):
            await FirestoreScenarioStore(store, CANDIDATE).get_work("investigation-7")

    asyncio.run(scenario())


def test_mutation_start_rejects_digest_or_identity_before_cas() -> None:
    async def scenario() -> None:
        store = _MemoryCasStore()
        scenarios, _ = await _create(store)
        token = await scenarios.acquire_scenario_lease(
            "investigation-7",
            "owner-7",
            now=NOW,
        )
        result = make_scenario_result()
        assert result.execution_envelope is not None
        update_count = len(store.updates)
        with pytest.raises(TypeError):
            await scenarios.record_mutation_started(
                token,
                prepared_envelope_sha256=canonical_sha256(result.execution_envelope),
                cleanup_manifest_sha256=result.fixture.cleanup_manifest_sha256,
                occurred_at=NOW + timedelta(seconds=1),
            )
        with pytest.raises(ScenarioStateConflict):
            await scenarios.record_mutation_started(
                token,
                prepared_envelope=result.execution_envelope,
                prepared_envelope_sha256="9" * 64,
                cleanup_manifest_sha256=result.fixture.cleanup_manifest_sha256,
                occurred_at=NOW + timedelta(seconds=1),
            )
        wrong_envelope = result.execution_envelope.model_copy(
            update={"investigation_id": "investigation-other"}
        )
        with pytest.raises(ScenarioStateConflict):
            await scenarios.record_mutation_started(
                token,
                prepared_envelope=wrong_envelope,
                prepared_envelope_sha256=canonical_sha256(wrong_envelope),
                cleanup_manifest_sha256=result.fixture.cleanup_manifest_sha256,
                occurred_at=NOW + timedelta(seconds=1),
            )
        assert len(store.updates) == update_count

    asyncio.run(scenario())


def test_escalation_is_lease_fenced_and_durable_across_instances() -> None:
    async def scenario() -> None:
        store = _MemoryCasStore()
        scenarios, _ = await _create(store)
        token = await scenarios.acquire_scenario_lease(
            "investigation-7",
            "owner-7",
            now=NOW,
        )
        escalated = await scenarios.require_scenario_escalation(
            token,
            "mutation-outcome-unknown",
            occurred_at=NOW + timedelta(seconds=1),
        )
        assert escalated.recovery_failure_code == "mutation-outcome-unknown"
        running_at = NOW + timedelta(milliseconds=1_250)
        running_event = ScenarioRunEvent(
            schema_version=SCENARIO_RUN_EVENT_VERSION,
            investigation_id="investigation-7",
            cursor=2,
            type=ScenarioRunEventType.LIFECYCLE,
            occurred_at=running_at,
            payload=ScenarioLifecycleEventPayload(
                lifecycle=ScenarioRunLifecycle.RUNNING
            ),
        )
        running_snapshot = escalated.snapshot.model_copy(
            update={
                "lifecycle": ScenarioRunLifecycle.RUNNING,
                "event_cursor": 2,
                "updated_at": running_at,
            }
        )
        escalated = await scenarios.append_projection(
            running_snapshot,
            running_event,
            terminal=False,
        )
        terminal_at = NOW + timedelta(milliseconds=1_500)
        cancelled_summary = TerminalStateSummary(
            lifecycle=ScenarioRunLifecycle.CANCELLED,
            result_kind=ScenarioRunResultKind.NONE,
            classification=None,
            action_gate_allowed_count=0,
            action_gate_denied_count=0,
            missing_evidence_count=0,
            escalation_required=None,
            failure_category=None,
        )
        cancelled_event = ScenarioRunEvent(
            schema_version=SCENARIO_RUN_EVENT_VERSION,
            investigation_id="investigation-7",
            cursor=3,
            type=ScenarioRunEventType.TERMINAL,
            occurred_at=terminal_at,
            payload=TerminalStateEventPayload(terminal=cancelled_summary),
        )
        cancelled_snapshot = escalated.snapshot.model_copy(
            update={
                "lifecycle": ScenarioRunLifecycle.CANCELLED,
                "event_cursor": 3,
                "updated_at": terminal_at,
            }
        )
        with pytest.raises(ScenarioStateConflict, match="terminal authority"):
            await scenarios.append_projection(
                cancelled_snapshot,
                cancelled_event,
                terminal=True,
            )

        failed_summary = cancelled_summary.model_copy(
            update={
                "lifecycle": ScenarioRunLifecycle.FAILED,
                "failure_category": ScenarioRunFailureCategory.INTERNAL_FAILURE,
            }
        )
        failed_event = cancelled_event.model_copy(
            update={"payload": TerminalStateEventPayload(terminal=failed_summary)}
        )
        failed_snapshot = cancelled_snapshot.model_copy(
            update={
                "lifecycle": ScenarioRunLifecycle.FAILED,
                "failure_category": ScenarioRunFailureCategory.INTERNAL_FAILURE,
            }
        )
        await scenarios.append_projection(
            failed_snapshot,
            failed_event,
            terminal=True,
        )
        restarted = FirestoreScenarioStore(store, CANDIDATE)
        assert (
            await restarted.get_work("investigation-7")
        ).recovery_failure_code == "mutation-outcome-unknown"

        await scenarios.release_scenario_lease(
            token,
            now=NOW + timedelta(seconds=2),
        )
        with pytest.raises(StaleScenarioLease):
            await scenarios.require_scenario_escalation(
                token,
                "second-reason",
                occurred_at=NOW + timedelta(seconds=3),
            )

    asyncio.run(scenario())


def test_lease_fence_is_retained_and_expired_or_stale_tokens_cannot_mutate() -> None:
    async def scenario() -> None:
        store = _MemoryCasStore()
        scenarios, _ = await _create(store)
        first = await scenarios.acquire_scenario_lease(
            "investigation-7",
            "first-owner",
            now=NOW,
        )
        with pytest.raises(ScenarioLeaseUnavailable):
            await scenarios.acquire_scenario_lease(
                "investigation-7",
                "second-owner",
                now=NOW + timedelta(seconds=1),
            )
        with pytest.raises(StaleScenarioLease):
            await scenarios.renew_scenario_lease(first, now=first.expires_at)

        second = await scenarios.acquire_scenario_lease(
            "investigation-7",
            "second-owner",
            now=first.expires_at,
        )
        assert second.fence == first.fence + 1 == 2
        with pytest.raises(StaleScenarioLease):
            await scenarios.release_scenario_lease(
                first,
                now=first.renewed_at,
            )
        await scenarios.release_scenario_lease(second, now=second.renewed_at)
        third = await scenarios.acquire_scenario_lease(
            "investigation-7",
            "third-owner",
            now=second.renewed_at,
        )
        assert third.fence == 3

    asyncio.run(scenario())


def test_projection_is_contiguous_coherent_and_available_after_restart() -> None:
    async def scenario() -> None:
        store = _MemoryCasStore()
        scenarios, work = await _create(store)
        occurred_at = NOW + timedelta(milliseconds=1)
        running = ScenarioRunEvent(
            schema_version=SCENARIO_RUN_EVENT_VERSION,
            investigation_id="investigation-7",
            cursor=2,
            type=ScenarioRunEventType.LIFECYCLE,
            occurred_at=occurred_at,
            payload=ScenarioLifecycleEventPayload(
                lifecycle=ScenarioRunLifecycle.RUNNING
            ),
        )
        snapshot = work.snapshot.model_copy(
            update={
                "lifecycle": ScenarioRunLifecycle.RUNNING,
                "event_cursor": 2,
                "updated_at": occurred_at,
            }
        )
        updated = await scenarios.append_projection(
            snapshot,
            running,
            terminal=False,
        )
        assert updated.snapshot == snapshot

        projection = await FirestoreScenarioStore(store, CANDIDATE).snapshot_projection(
            "investigation-7",
            after=1,
        )
        assert projection.events == (running,)
        assert projection.cursor == 2
        assert projection.terminal is False

        update_count = len(store.updates)
        with pytest.raises(ScenarioStateConflict):
            await scenarios.append_projection(snapshot, running, terminal=False)
        with pytest.raises(ValueError):
            await scenarios.snapshot_projection("investigation-7", after=3)
        assert len(store.updates) == update_count

    asyncio.run(scenario())


def test_completed_projection_must_match_recorded_workflow_authority() -> None:
    async def scenario() -> None:
        store = _MemoryCasStore()
        scenarios, _ = await _create(store)
        token, work = await _record_mutation_and_start(
            scenarios,
            now=NOW + timedelta(seconds=1),
        )
        authority = make_report(Classification.COMMITTED).model_copy(
            update={
                "investigation_id": "investigation-7",
                "envelope_sha256": work.envelope_sha256,
            }
        )
        work = await scenarios.record_workflow_result(
            token,
            authority,
            occurred_at=NOW + timedelta(seconds=2),
        )

        running_at = NOW + timedelta(seconds=3)
        running = ScenarioRunEvent(
            schema_version=SCENARIO_RUN_EVENT_VERSION,
            investigation_id="investigation-7",
            cursor=2,
            type=ScenarioRunEventType.LIFECYCLE,
            occurred_at=running_at,
            payload=ScenarioLifecycleEventPayload(
                lifecycle=ScenarioRunLifecycle.RUNNING
            ),
        )
        snapshot = work.snapshot.model_copy(
            update={
                "lifecycle": ScenarioRunLifecycle.RUNNING,
                "event_cursor": 2,
                "updated_at": running_at,
            }
        )
        work = await scenarios.append_projection(snapshot, running, terminal=False)
        assert work.scenario_result is not None
        assert work.scenario_result.execution_envelope is not None
        summary = _envelope_summary(work.scenario_result.execution_envelope)
        envelope_at = NOW + timedelta(seconds=4)
        envelope_event = ScenarioRunEvent(
            schema_version=SCENARIO_RUN_EVENT_VERSION,
            investigation_id="investigation-7",
            cursor=3,
            type=ScenarioRunEventType.ENVELOPE_SUMMARY,
            occurred_at=envelope_at,
            payload=EnvelopeSummaryEventPayload(summary=summary),
        )
        snapshot = snapshot.model_copy(
            update={
                "event_cursor": 3,
                "envelope_summary": summary,
                "updated_at": envelope_at,
            }
        )
        await scenarios.append_projection(snapshot, envelope_event, terminal=False)

        divergent = make_report(Classification.NOT_COMMITTED).model_copy(
            update={
                "investigation_id": "investigation-7",
                "envelope_sha256": work.envelope_sha256,
            }
        )
        projected = sanitize_report(divergent)
        allowed = sum(gate.allowed for gate in projected.action_gate)
        terminal_at = NOW + timedelta(seconds=5)
        terminal = TerminalStateSummary(
            lifecycle=ScenarioRunLifecycle.COMPLETED,
            result_kind=ScenarioRunResultKind.REPORT,
            classification=projected.classification,
            action_gate_allowed_count=allowed,
            action_gate_denied_count=len(projected.action_gate) - allowed,
            missing_evidence_count=len(projected.missing_evidence),
            escalation_required=True,
            failure_category=None,
            route_provenance=projected.route_provenance,
        )
        terminal_event = ScenarioRunEvent(
            schema_version=SCENARIO_RUN_EVENT_VERSION,
            investigation_id="investigation-7",
            cursor=4,
            type=ScenarioRunEventType.TERMINAL,
            occurred_at=terminal_at,
            payload=TerminalStateEventPayload(terminal=terminal),
        )
        terminal_snapshot = snapshot.model_copy(
            update={
                "lifecycle": ScenarioRunLifecycle.COMPLETED,
                "event_cursor": 4,
                "report": projected,
                "updated_at": terminal_at,
            }
        )

        with pytest.raises(ScenarioStateConflict, match="terminal authority"):
            await scenarios.append_projection(
                terminal_snapshot,
                terminal_event,
                terminal=True,
            )

        for lifecycle, failure_category in (
            (
                ScenarioRunLifecycle.FAILED,
                ScenarioRunFailureCategory.EVENT_JOURNAL_FAILED,
            ),
            (ScenarioRunLifecycle.CANCELLED, None),
        ):
            contradictory_terminal = TerminalStateSummary(
                lifecycle=lifecycle,
                result_kind=ScenarioRunResultKind.NONE,
                classification=None,
                action_gate_allowed_count=0,
                action_gate_denied_count=0,
                missing_evidence_count=0,
                escalation_required=None,
                failure_category=failure_category,
            )
            contradictory_event = terminal_event.model_copy(
                update={
                    "payload": TerminalStateEventPayload(
                        terminal=contradictory_terminal
                    )
                }
            )
            contradictory_snapshot = snapshot.model_copy(
                update={
                    "lifecycle": lifecycle,
                    "event_cursor": 4,
                    "report": None,
                    "failure_category": failure_category,
                    "updated_at": terminal_at,
                }
            )
            with pytest.raises(ScenarioStateConflict, match="terminal authority"):
                await scenarios.append_projection(
                    contradictory_snapshot,
                    contradictory_event,
                    terminal=True,
                )

    asyncio.run(scenario())


def test_operation_scope_authorizer_is_read_only_exact_and_state_specific() -> None:
    async def scenario() -> None:
        store = _MemoryCasStore()
        scenarios, _ = await _create(store)
        token = await scenarios.acquire_scenario_lease(
            "investigation-7",
            "owner-7",
            now=NOW + timedelta(seconds=1),
        )
        result = make_scenario_result()
        assert result.execution_envelope is not None
        prepared = canonical_json_bytes(result.execution_envelope)
        work = await scenarios.record_mutation_started(
            token,
            prepared_envelope=result.execution_envelope,
            prepared_envelope_sha256=canonical_sha256(result.execution_envelope),
            cleanup_manifest_sha256=result.fixture.cleanup_manifest_sha256,
            occurred_at=NOW + timedelta(milliseconds=1_100),
        )
        authorizer = FirestoreHostedOperationScopeAuthorizer(
            scenarios,
            clock=lambda: NOW + timedelta(seconds=2),
        )
        execute_scope = _operation_scope(
            work,
            token,
            HostedWorkflowOperation.EXECUTE_FAULT,
        )

        reads_before = len(store.reads)
        updates_before = len(store.updates)
        await authorizer(execute_scope)
        assert store.reads[reads_before:] == [
            (FirestoreCasCollection.SCENARIO_INDEX, "investigation-7"),
            (FirestoreCasCollection.SCENARIO, "run-7"),
        ]
        assert len(store.updates) == updates_before

        mismatches = (
            {"launch_id": "wrong-launch"},
            {"launch_sha256": "9" * 64},
            {"scenario_request_sha256": "9" * 64},
            {"operation_id": "wrong-operation"},
            {"invocation_id": "wrong-invocation"},
            {"function_call_id": "wrong-function-call"},
            {"envelope_sha256": "9" * 64},
            {"cleanup_manifest_sha256": "9" * 64},
            {"lease_fence": token.fence + 1},
        )
        for mismatch in mismatches:
            with pytest.raises(InternalOperationDenied):
                await authorizer(execute_scope.model_copy(update=mismatch))
        assert len(store.updates) == updates_before

        with pytest.raises(InternalOperationDenied):
            await FirestoreHostedOperationScopeAuthorizer(
                scenarios,
                clock=lambda: token.expires_at,
            )(execute_scope)
        with pytest.raises(InternalOperationDenied):
            await authorizer(
                execute_scope.model_copy(
                    update={"investigation_id": "missing-investigation"}
                )
            )

        work = await scenarios.record_mutation_result(
            token,
            result,
            prepared_envelope_bytes=prepared,
            occurred_at=NOW + timedelta(milliseconds=1_200),
        )
        work = await scenarios.mark_investigation_started(
            token,
            occurred_at=NOW + timedelta(milliseconds=1_300),
        )
        investigate_scope = _operation_scope(
            work,
            token,
            HostedWorkflowOperation.INVESTIGATE,
        )
        await authorizer(investigate_scope)
        with pytest.raises(InternalOperationDenied):
            await authorizer(execute_scope)

        report = make_report(Classification.COMMITTED).model_copy(
            update={
                "investigation_id": "investigation-7",
                "envelope_sha256": work.envelope_sha256,
            }
        )
        work = await scenarios.record_workflow_result(
            token,
            report,
            occurred_at=NOW + timedelta(milliseconds=1_400),
        )
        work = await scenarios.record_scenario_cleanup(
            token,
            CleanupStatus.PENDING,
            occurred_at=NOW + timedelta(milliseconds=1_500),
        )
        cleanup_scope = _operation_scope(
            work,
            token,
            HostedWorkflowOperation.CLEANUP,
        )
        await authorizer(cleanup_scope)
        with pytest.raises(InternalOperationDenied):
            await authorizer(investigate_scope)
        assert len(store.updates) == updates_before + 4

        class _CancelledStore:
            async def operation_authority(self, _investigation_id: str):
                raise asyncio.CancelledError

        with pytest.raises(asyncio.CancelledError):
            await FirestoreHostedOperationScopeAuthorizer(
                _CancelledStore(),
                clock=lambda: NOW,
            )(cleanup_scope)

    asyncio.run(scenario())
