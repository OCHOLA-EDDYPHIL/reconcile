"""Candidate-wide Firestore provider ledger state-machine tests."""

from __future__ import annotations

import asyncio
import json
from datetime import UTC, datetime, timedelta
from typing import cast

import pytest

from reconcile.hosted.firestore_cas import (
    FirestoreCasCollection,
    FirestoreCasConflict,
    FirestoreCasDocument,
    FirestoreCasOutcomeUnknown,
    FirestoreCasSnapshot,
    firestore_cas_document_key,
)
from reconcile.hosted.firestore_provider_ledger import (
    FirestoreHostedProviderLedger,
    HostedProviderLedgerState,
)
from reconcile.hosted.provider import (
    HOSTED_CANDIDATE_IDENTITY_VERSION,
    HOSTED_PROVIDER_DISPATCH_VERSION,
    HostedCandidateIdentity,
    HostedCountFailure,
    HostedCountReservation,
    HostedCountTokensUsage,
    HostedGenerationFailure,
    HostedGenerationReservation,
    HostedGenerationUsage,
    HostedModalityUsage,
    HostedPlannerOutcome,
    HostedProviderDispatch,
    HostedProviderLedgerError,
)

pytestmark = pytest.mark.unit


def _candidate(**updates: object) -> HostedCandidateIdentity:
    values: dict[str, object] = {
        "schema_version": HOSTED_CANDIDATE_IDENTITY_VERSION,
        "source_revision": "a" * 40,
        "image_digest": f"sha256:{'b' * 64}",
        "infrastructure_revision": "c" * 64,
        "semantic_config_sha256": "d" * 64,
        "project_id": "reconcile-dev-260813-14fa6d",
        "vertex_location": "us",
        "configured_model": "gemini-3.5-flash",
        "prompt_version": "hosted-acquisition-v1",
        "prompt_sha256": "e" * 64,
        "maximum_input_tokens": 12_000,
        "maximum_output_tokens": 1_024,
        "thinking_level": "MINIMAL",
        "maximum_count_tokens_attempts": 1,
        "maximum_generation_attempts": 1,
    }
    values.update(updates)
    return HostedCandidateIdentity(**values)  # type: ignore[arg-type]


def _dispatch(**updates: object) -> HostedProviderDispatch:
    values: dict[str, object] = {
        "schema_version": HOSTED_PROVIDER_DISPATCH_VERSION,
        "input_sha256": "1" * 64,
        "count_request_sha256": "2" * 64,
        "generation_request_sha256": "3" * 64,
        "request_byte_count": 1_024,
    }
    values.update(updates)
    return HostedProviderDispatch(**values)  # type: ignore[arg-type]


def _count_usage() -> HostedCountTokensUsage:
    return HostedCountTokensUsage(total_tokens=100, cached_content_tokens=0)


def _generation_usage() -> HostedGenerationUsage:
    return HostedGenerationUsage(
        prompt_tokens=100,
        candidates_tokens=20,
        thoughts_tokens=5,
        tool_use_prompt_tokens=1,
        cached_content_tokens=10,
        total_tokens=126,
        traffic_type="ON_DEMAND",
        prompt_details=(HostedModalityUsage(modality="TEXT", token_count=100),),
        candidates_details=(HostedModalityUsage(modality="TEXT", token_count=20),),
        thoughts_details=(HostedModalityUsage(modality="TEXT", token_count=5),),
        tool_use_prompt_details=(HostedModalityUsage(modality="TEXT", token_count=1),),
        cache_details=(HostedModalityUsage(modality="TEXT", token_count=10),),
    )


class _MemoryCasStore:
    def __init__(self, *, synchronize_creates: int = 0) -> None:
        self._lock = asyncio.Lock()
        self._clock = 0
        self._create_waiters = 0
        self._create_target = synchronize_creates
        self._create_gate = asyncio.Event()
        self.documents: dict[str, FirestoreCasSnapshot] = {}
        self.reads: list[tuple[FirestoreCasCollection, str]] = []
        self.creates: list[FirestoreCasDocument] = []
        self.updates: list[tuple[FirestoreCasSnapshot, FirestoreCasDocument]] = []
        self.writes: list[FirestoreCasDocument] = []
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
        return self.documents.get(logical_id)

    async def create(
        self,
        document: FirestoreCasDocument,
    ) -> FirestoreCasSnapshot:
        self.creates.append(document)
        if self._create_target:
            self._create_waiters += 1
            if self._create_waiters == self._create_target:
                self._create_gate.set()
            await self._create_gate.wait()
        if self.create_error is not None:
            raise self.create_error
        async with self._lock:
            if document.logical_id in self.documents:
                raise FirestoreCasConflict
            snapshot = self._snapshot(document)
            self.documents[document.logical_id] = snapshot
            self.writes.append(document)
            return snapshot

    async def update(
        self,
        current: FirestoreCasSnapshot,
        replacement: FirestoreCasDocument,
    ) -> FirestoreCasSnapshot:
        self.updates.append((current, replacement))
        if self.update_error is not None:
            raise self.update_error
        async with self._lock:
            stored = self.documents.get(replacement.logical_id)
            if stored is None or stored.update_time != current.update_time:
                raise FirestoreCasConflict
            if replacement.revision != stored.document.revision + 1:
                raise FirestoreCasConflict
            snapshot = self._snapshot(replacement)
            self.documents[replacement.logical_id] = snapshot
            self.writes.append(replacement)
            return snapshot


class _MalformedCreateReturnCasStore(_MemoryCasStore):
    async def create(
        self,
        document: FirestoreCasDocument,
    ) -> FirestoreCasSnapshot:
        self.creates.append(document)
        return cast(FirestoreCasSnapshot, object())


class _MalformedUpdateReturnCasStore(_MemoryCasStore):
    async def update(
        self,
        current: FirestoreCasSnapshot,
        replacement: FirestoreCasDocument,
    ) -> FirestoreCasSnapshot:
        self.updates.append((current, replacement))
        return cast(FirestoreCasSnapshot, object())


def _raw_record(
    store: _MemoryCasStore,
    candidate: HostedCandidateIdentity,
) -> dict[str, object]:
    return json.loads(
        store.documents[candidate.candidate_id].document.canonical_payload
    )


async def _reserve_generation(
    ledger: FirestoreHostedProviderLedger,
    candidate: HostedCandidateIdentity,
    dispatch: HostedProviderDispatch,
) -> tuple[HostedCountReservation, HostedGenerationReservation]:
    count = await ledger.reserve_count_tokens(candidate, dispatch)
    generation = await ledger.complete_count_and_reserve_generation(
        count,
        _count_usage(),
    )
    return count, generation


def test_complete_path_persists_identity_usage_model_hashes_and_exact_revisions() -> (
    None
):
    async def scenario() -> None:
        store = _MemoryCasStore()
        ledger = FirestoreHostedProviderLedger(store)
        candidate = _candidate()
        dispatch = _dispatch()

        count = await ledger.reserve_count_tokens(candidate, dispatch)
        first = _raw_record(store, candidate)
        assert first["state"] == HostedProviderLedgerState.COUNT_RESERVED.value
        assert first["revision"] == count.revision == 1
        assert first["candidate_id"] == candidate.candidate_id
        assert first["candidate"] == candidate.model_dump(mode="json")
        assert first["dispatch"] == dispatch.model_dump(mode="json")

        count_usage = _count_usage()
        generation = await ledger.complete_count_and_reserve_generation(
            count,
            count_usage,
        )
        second = _raw_record(store, candidate)
        assert second["state"] == HostedProviderLedgerState.GENERATION_RESERVED.value
        assert second["revision"] == generation.revision == 2
        assert second["count_usage"] == count_usage.model_dump(mode="json")
        assert generation.reservation_id != count.reservation_id

        generation_usage = _generation_usage()
        await ledger.record_generation_usage(generation, generation_usage)
        third = _raw_record(store, candidate)
        assert (
            third["state"] == HostedProviderLedgerState.GENERATION_USAGE_RECORDED.value
        )
        assert third["revision"] == 3
        assert third["generation_usage"] == generation_usage.model_dump(mode="json")

        await ledger.finalize_generation(
            generation,
            HostedPlannerOutcome.SUCCEEDED,
            output_sha256="4" * 64,
            reported_model="gemini-3.5-flash-001",
            reported_model_raw_sha256="5" * 64,
        )
        final = _raw_record(store, candidate)
        assert final["state"] == HostedProviderLedgerState.FINALIZED.value
        assert final["revision"] == 4
        assert final["generation_usage"] == generation_usage.model_dump(mode="json")
        assert final["planner_outcome"] == HostedPlannerOutcome.SUCCEEDED.value
        assert final["output_sha256"] == "4" * 64
        assert final["reported_model"] == "gemini-3.5-flash-001"
        assert final["reported_model_raw_sha256"] == "5" * 64

        observation = await ledger.observe_finalized(candidate)
        assert observation.candidate_sha256 == candidate.sha256
        assert observation.state == HostedProviderLedgerState.FINALIZED
        assert observation.count_attempts == 1
        assert observation.generation_attempts == 1
        assert observation.count_usage == count_usage
        assert observation.generation_usage == generation_usage
        assert observation.output_sha256 == "4" * 64
        assert observation.reported_model == "gemini-3.5-flash-001"

        assert [document.revision for document in store.writes] == [1, 2, 3, 4]
        assert len({document.mutation_id for document in store.writes}) == 4
        assert all(
            document.kind is FirestoreCasCollection.PROVIDER_CANDIDATE
            and document.logical_id == candidate.candidate_id
            for document in store.writes
        )
        assert [current.document.revision for current, _ in store.updates] == [
            1,
            2,
            3,
        ]

    asyncio.run(scenario())


def test_observe_finalized_rejects_nonterminal_or_other_candidate() -> None:
    async def scenario() -> None:
        store = _MemoryCasStore()
        ledger = FirestoreHostedProviderLedger(store)
        candidate = _candidate()
        await ledger.reserve_count_tokens(candidate, _dispatch())

        with pytest.raises(HostedProviderLedgerError):
            await ledger.observe_finalized(candidate)
        with pytest.raises(HostedProviderLedgerError):
            await ledger.observe_finalized(
                _candidate(source_revision="f" * 40),
            )

    asyncio.run(scenario())


def test_count_failure_is_terminal_and_cannot_be_reused_after_restart() -> None:
    async def scenario() -> None:
        store = _MemoryCasStore()
        candidate = _candidate()
        dispatch = _dispatch()
        count = await FirestoreHostedProviderLedger(store).reserve_count_tokens(
            candidate,
            dispatch,
        )
        restarted = FirestoreHostedProviderLedger(store)

        await restarted.fail_count_tokens(count, HostedCountFailure.TIMEOUT)
        record = _raw_record(store, candidate)
        assert record["state"] == HostedProviderLedgerState.COUNT_FAILED.value
        assert record["revision"] == 2
        assert record["count_failure"] == HostedCountFailure.TIMEOUT.value
        assert record["count_usage"] is None

        update_count = len(store.updates)
        with pytest.raises(HostedProviderLedgerError):
            await restarted.complete_count_and_reserve_generation(
                count,
                _count_usage(),
            )
        with pytest.raises(HostedProviderLedgerError):
            await restarted.fail_count_tokens(count, HostedCountFailure.INVALID)
        with pytest.raises(HostedProviderLedgerError):
            await restarted.reserve_count_tokens(candidate, dispatch)
        assert len(store.updates) == update_count
        assert _raw_record(store, candidate) == record

    asyncio.run(scenario())


def test_generation_failure_before_usage_is_terminal_without_fabricated_usage() -> None:
    async def scenario() -> None:
        store = _MemoryCasStore()
        ledger = FirestoreHostedProviderLedger(store)
        candidate = _candidate()
        _, generation = await _reserve_generation(
            ledger,
            candidate,
            _dispatch(),
        )

        await ledger.fail_generation(
            generation,
            HostedGenerationFailure.UNAVAILABLE,
        )
        record = _raw_record(store, candidate)
        assert record["state"] == HostedProviderLedgerState.GENERATION_FAILED.value
        assert record["revision"] == 3
        assert record["generation_usage"] is None
        assert record["generation_failure"] == HostedGenerationFailure.UNAVAILABLE.value

        with pytest.raises(HostedProviderLedgerError):
            await ledger.record_generation_usage(generation, _generation_usage())
        with pytest.raises(HostedProviderLedgerError):
            await ledger.finalize_generation(
                generation,
                HostedPlannerOutcome.UNAVAILABLE,
                output_sha256=None,
                reported_model=None,
                reported_model_raw_sha256=None,
            )

    asyncio.run(scenario())


def test_generation_failure_after_usage_retains_complete_billed_usage() -> None:
    async def scenario() -> None:
        store = _MemoryCasStore()
        ledger = FirestoreHostedProviderLedger(store)
        candidate = _candidate()
        _, generation = await _reserve_generation(
            ledger,
            candidate,
            _dispatch(),
        )
        usage = _generation_usage()
        await ledger.record_generation_usage(generation, usage)

        await ledger.fail_generation(
            generation,
            HostedGenerationFailure.USAGE_INVALID,
        )
        record = _raw_record(store, candidate)
        assert record["state"] == HostedProviderLedgerState.GENERATION_FAILED.value
        assert record["revision"] == 4
        assert record["generation_usage"] == usage.model_dump(mode="json")
        assert (
            record["generation_failure"] == HostedGenerationFailure.USAGE_INVALID.value
        )

    asyncio.run(scenario())


def test_finalize_requires_usage_and_complete_success_or_model_hashes() -> None:
    async def scenario() -> None:
        store = _MemoryCasStore()
        ledger = FirestoreHostedProviderLedger(store)
        candidate = _candidate()
        _, generation = await _reserve_generation(
            ledger,
            candidate,
            _dispatch(),
        )

        updates = len(store.updates)
        with pytest.raises(HostedProviderLedgerError):
            await ledger.finalize_generation(
                generation,
                HostedPlannerOutcome.SUCCEEDED,
                output_sha256="4" * 64,
                reported_model=None,
                reported_model_raw_sha256=None,
            )
        assert len(store.updates) == updates

        await ledger.record_generation_usage(generation, _generation_usage())
        updates = len(store.updates)
        for values in (
            {
                "output_sha256": None,
                "reported_model": None,
                "reported_model_raw_sha256": None,
            },
            {
                "output_sha256": "4" * 64,
                "reported_model": "gemini-3.5-flash-001",
                "reported_model_raw_sha256": None,
            },
        ):
            with pytest.raises(HostedProviderLedgerError):
                await ledger.finalize_generation(
                    generation,
                    HostedPlannerOutcome.SUCCEEDED,
                    **values,  # type: ignore[arg-type]
                )
        assert len(store.updates) == updates

    asyncio.run(scenario())


def test_stale_or_wrong_reservation_identity_fails_closed_without_write() -> None:
    async def scenario() -> None:
        store = _MemoryCasStore()
        ledger = FirestoreHostedProviderLedger(store)
        candidate = _candidate()
        dispatch = _dispatch()
        count = await ledger.reserve_count_tokens(candidate, dispatch)

        for wrong in (
            count.model_copy(update={"reservation_id": "count-wrong"}),
            count.model_copy(update={"revision": 2}),
            count.model_copy(
                update={
                    "dispatch": _dispatch(count_request_sha256="6" * 64),
                }
            ),
        ):
            with pytest.raises(HostedProviderLedgerError):
                await ledger.complete_count_and_reserve_generation(
                    wrong,
                    _count_usage(),
                )
        assert store.updates == []

        generation = await ledger.complete_count_and_reserve_generation(
            count,
            _count_usage(),
        )
        updates = len(store.updates)
        for wrong in (
            generation.model_copy(update={"reservation_id": "generation-wrong"}),
            generation.model_copy(update={"revision": 3}),
            generation.model_copy(
                update={
                    "dispatch": _dispatch(generation_request_sha256="7" * 64),
                }
            ),
        ):
            with pytest.raises(HostedProviderLedgerError):
                await ledger.record_generation_usage(wrong, _generation_usage())
        assert len(store.updates) == updates

        await ledger.record_generation_usage(generation, _generation_usage())
        with pytest.raises(HostedProviderLedgerError):
            await ledger.record_generation_usage(generation, _generation_usage())

    asyncio.run(scenario())


def test_concurrent_candidate_reservation_has_exactly_one_winner() -> None:
    async def scenario() -> None:
        store = _MemoryCasStore(synchronize_creates=2)
        candidate = _candidate()
        dispatch = _dispatch()
        ledgers = (
            FirestoreHostedProviderLedger(store),
            FirestoreHostedProviderLedger(store),
        )

        results = await asyncio.gather(
            ledgers[0].reserve_count_tokens(candidate, dispatch),
            ledgers[1].reserve_count_tokens(candidate, dispatch),
            return_exceptions=True,
        )

        assert sum(type(item) is HostedCountReservation for item in results) == 1
        assert sum(type(item) is HostedProviderLedgerError for item in results) == 1
        assert len(store.creates) == 2
        assert len(store.writes) == 1
        assert (
            _raw_record(store, candidate)["state"]
            == HostedProviderLedgerState.COUNT_RESERVED.value
        )

    asyncio.run(scenario())


@pytest.mark.parametrize(
    "state",
    tuple(HostedProviderLedgerState),
)
def test_restart_never_reopens_any_persisted_state(
    state: HostedProviderLedgerState,
) -> None:
    async def scenario() -> None:
        store = _MemoryCasStore()
        ledger = FirestoreHostedProviderLedger(store)
        candidate = _candidate()
        dispatch = _dispatch()
        count = await ledger.reserve_count_tokens(candidate, dispatch)
        generation: HostedGenerationReservation | None = None

        if state is HostedProviderLedgerState.COUNT_FAILED:
            await ledger.fail_count_tokens(count, HostedCountFailure.UNAVAILABLE)
        elif state is not HostedProviderLedgerState.COUNT_RESERVED:
            generation = await ledger.complete_count_and_reserve_generation(
                count,
                _count_usage(),
            )
            if state in {
                HostedProviderLedgerState.GENERATION_USAGE_RECORDED,
                HostedProviderLedgerState.FINALIZED,
            }:
                await ledger.record_generation_usage(
                    generation,
                    _generation_usage(),
                )
            elif state is HostedProviderLedgerState.GENERATION_FAILED:
                await ledger.fail_generation(
                    generation,
                    HostedGenerationFailure.TIMEOUT,
                )
            if state is HostedProviderLedgerState.FINALIZED:
                await ledger.finalize_generation(
                    generation,
                    HostedPlannerOutcome.SCHEMA_INVALID,
                    output_sha256="8" * 64,
                    reported_model=None,
                    reported_model_raw_sha256=None,
                )

        before = _raw_record(store, candidate)
        restarted = FirestoreHostedProviderLedger(store)
        with pytest.raises(HostedProviderLedgerError):
            await restarted.reserve_count_tokens(candidate, dispatch)
        assert _raw_record(store, candidate) == before
        assert before["state"] == state.value

    asyncio.run(scenario())


def test_ambiguous_or_private_cas_failures_are_sanitized_without_retry() -> None:
    async def scenario() -> None:
        candidate = _candidate()
        dispatch = _dispatch()
        create_store = _MemoryCasStore()
        create_store.create_error = FirestoreCasOutcomeUnknown()
        with pytest.raises(HostedProviderLedgerError) as create_failure:
            await FirestoreHostedProviderLedger(create_store).reserve_count_tokens(
                candidate,
                dispatch,
            )
        assert str(create_failure.value) == "hosted provider authority is unavailable"
        assert create_failure.value.__cause__ is None
        assert len(create_store.creates) == 1

        update_store = _MemoryCasStore()
        ledger = FirestoreHostedProviderLedger(update_store)
        count = await ledger.reserve_count_tokens(candidate, dispatch)
        update_store.update_error = RuntimeError("private provider response")
        with pytest.raises(HostedProviderLedgerError) as update_failure:
            await ledger.fail_count_tokens(count, HostedCountFailure.UNAVAILABLE)
        assert "private" not in str(update_failure.value)
        assert update_failure.value.__cause__ is None
        assert len(update_store.updates) == 1

    asyncio.run(scenario())


def test_malformed_cas_returns_are_sanitized_without_retry() -> None:
    async def scenario() -> None:
        candidate = _candidate()
        dispatch = _dispatch()
        create_store = _MalformedCreateReturnCasStore()
        with pytest.raises(HostedProviderLedgerError) as create_failure:
            await FirestoreHostedProviderLedger(create_store).reserve_count_tokens(
                candidate,
                dispatch,
            )
        assert str(create_failure.value) == "hosted provider authority is unavailable"
        assert create_failure.value.__cause__ is None
        assert len(create_store.creates) == 1

        update_store = _MalformedUpdateReturnCasStore()
        ledger = FirestoreHostedProviderLedger(update_store)
        count = await ledger.reserve_count_tokens(candidate, dispatch)
        with pytest.raises(HostedProviderLedgerError) as update_failure:
            await ledger.fail_count_tokens(count, HostedCountFailure.UNAVAILABLE)
        assert str(update_failure.value) == "hosted provider authority is unavailable"
        assert update_failure.value.__cause__ is None
        assert len(update_store.updates) == 1

    asyncio.run(scenario())


def test_cas_cancellation_propagates_without_reclassification() -> None:
    async def scenario() -> None:
        store = _MemoryCasStore()
        store.create_error = asyncio.CancelledError()
        with pytest.raises(asyncio.CancelledError):
            await FirestoreHostedProviderLedger(store).reserve_count_tokens(
                _candidate(),
                _dispatch(),
            )

    asyncio.run(scenario())
