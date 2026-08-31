"""Hosted Firestore runtime-database compare-and-swap boundaries."""

from __future__ import annotations

import asyncio
import hashlib
from copy import deepcopy
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from google.api_core import exceptions as api_exceptions
from google.cloud import firestore_v1
from pydantic import ValidationError

from reconcile.contracts.base import canonical_json_value_bytes
from reconcile.hosted.firestore_cas import (
    FIRESTORE_CAS_AMBIGUOUS_READ_CONCURRENCY,
    FIRESTORE_CAS_DOCUMENT_VERSION,
    FIRESTORE_CAS_PAYLOAD_BYTE_CEILING,
    FIRESTORE_CAS_TIMEOUT_SECONDS,
    FIRESTORE_RUNTIME_DATABASE,
    FIRESTORE_SANDBOX_DATABASE,
    FirestoreCasCollection,
    FirestoreCasConflict,
    FirestoreCasCorruptDocument,
    FirestoreCasDocument,
    FirestoreCasOutcomeUnknown,
    FirestoreCasProviderUnavailable,
    FirestoreCasSnapshot,
    GoogleFirestoreCasStore,
    build_firestore_cas_document,
    firestore_cas_document_key,
    firestore_cas_document_path,
    new_firestore_cas_mutation_id,
)

pytestmark = pytest.mark.unit

_NOW = datetime(2026, 8, 18, 12, 0, tzinfo=UTC)
_PROJECT = "test-project"
_LOGICAL_ID = "runtime-run-1"


@dataclass(frozen=True, slots=True)
class _Option:
    kind: str
    value: object


@dataclass(frozen=True, slots=True)
class _Result:
    update_time: datetime


@dataclass(slots=True)
class _Snapshot:
    reference: _Reference
    exists: bool
    read_time: datetime
    update_time: datetime | None
    data: dict[str, Any] | None

    def to_dict(self) -> dict[str, Any] | None:
        return deepcopy(self.data)


@dataclass(frozen=True, slots=True)
class _Operation:
    kind: str
    reference: _Reference
    data: dict[str, Any]
    option: _Option | None


class _Reference:
    def __init__(self, client: _Client, path: str) -> None:
        self.client = client
        self.path = path

    async def get(
        self,
        field_paths: object | None = None,
        transaction: object | None = None,
        retry: object | None = None,
        timeout: float | None = None,
        *,
        read_time: datetime | None = None,
    ) -> _Snapshot:
        self.client.gets.append(
            (
                self.path,
                field_paths,
                transaction,
                retry,
                timeout,
                read_time,
            )
        )
        failure = self.client.get_failures.pop(0) if self.client.get_failures else None
        if failure is not None:
            raise failure
        record = self.client.documents.get(self.path)
        returned_path = self.client.returned_paths.get(self.path, self.path)
        return _Snapshot(
            reference=_Reference(self.client, returned_path),
            exists=record is not None,
            read_time=self.client.clock,
            update_time=None if record is None else record[1],
            data=None if record is None else deepcopy(record[0]),
        )


class _Batch:
    def __init__(self, client: _Client) -> None:
        self.client = client
        self.operations: list[_Operation] = []

    def create(self, reference: _Reference, document_data: dict[str, Any]) -> None:
        self.operations.append(
            _Operation("create", reference, deepcopy(document_data), None)
        )

    def update(
        self,
        reference: _Reference,
        field_updates: dict[str, Any],
        option: _Option | None = None,
    ) -> None:
        self.operations.append(
            _Operation("update", reference, deepcopy(field_updates), option)
        )

    async def commit(
        self,
        retry: object | None = None,
        timeout: float | None = None,
    ) -> list[object]:
        self.client.commits.append((tuple(self.operations), retry, timeout))
        number = len(self.client.commits)
        failure = self.client.commit_before.get(number)
        if failure is not None:
            raise failure
        results = self.client.apply(tuple(self.operations))
        failure = self.client.commit_after.get(number)
        if failure is not None:
            raise failure
        return self.client.commit_results.get(number, results)


class _Client:
    def __init__(self) -> None:
        self.documents: dict[str, tuple[dict[str, Any], datetime]] = {}
        self.clock = _NOW
        self.gets: list[
            tuple[
                str,
                object | None,
                object | None,
                object | None,
                float | None,
                datetime | None,
            ]
        ] = []
        self.commits: list[
            tuple[tuple[_Operation, ...], object | None, float | None]
        ] = []
        self.commit_before: dict[int, BaseException] = {}
        self.commit_after: dict[int, BaseException] = {}
        self.commit_results: dict[int, list[object]] = {}
        self.get_failures: list[BaseException] = []
        self.returned_paths: dict[str, str] = {}

    def document(self, *document_path: str) -> _Reference:
        return _Reference(self, "/".join(document_path))

    def batch(self) -> _Batch:
        return _Batch(self)

    def write_option(self, **kwargs: object) -> _Option:
        assert len(kwargs) == 1
        kind, value = next(iter(kwargs.items()))
        return _Option(kind=kind, value=value)

    def apply(self, operations: tuple[_Operation, ...]) -> list[object]:
        proposed = deepcopy(self.documents)
        update_time = self.clock
        self.clock += timedelta(microseconds=1)
        for operation in operations:
            current = proposed.get(operation.reference.path)
            if operation.kind == "create":
                if current is not None:
                    raise api_exceptions.AlreadyExists("private provider response")
            else:
                if (
                    current is None
                    or operation.option is None
                    or operation.option.kind != "last_update_time"
                    or operation.option.value != current[1]
                ):
                    raise api_exceptions.FailedPrecondition("private provider response")
            proposed[operation.reference.path] = (
                deepcopy(operation.data),
                update_time,
            )
        self.documents = proposed
        return [_Result(update_time) for _operation in operations]


class _Factory:
    def __init__(self, client: _Client) -> None:
        self.client = client
        self.calls = 0

    def __call__(self) -> _Client:
        self.calls += 1
        return self.client


def _payload(
    value: object = 1,
    *,
    schema_version: str = "reconcile/test-firestore-state/v1",
) -> bytes:
    return canonical_json_value_bytes(
        {
            "schema_version": schema_version,
            "value": value,
        }
    )


def _document(
    *,
    revision: int = 0,
    mutation_id: str = "mutation-initial",
    value: object = 1,
    collection: FirestoreCasCollection = FirestoreCasCollection.RUNTIME,
    logical_id: str = _LOGICAL_ID,
    payload_schema_version: str = "reconcile/test-firestore-state/v1",
) -> FirestoreCasDocument:
    return build_firestore_cas_document(
        collection=collection,
        logical_id=logical_id,
        revision=revision,
        mutation_id=mutation_id,
        canonical_payload=_payload(value, schema_version=payload_schema_version),
    )


def _store(client: _Client) -> tuple[GoogleFirestoreCasStore, _Factory]:
    factory = _Factory(client)
    return (
        GoogleFirestoreCasStore(project_id=_PROJECT, client_factory=factory),
        factory,
    )


def test_wrapper_paths_and_payload_bounds_are_exact() -> None:
    mutation_id = new_firestore_cas_mutation_id()
    document = _document(mutation_id=mutation_id)

    assert document.schema_version == FIRESTORE_CAS_DOCUMENT_VERSION
    assert document.payload_bytes == _payload()
    assert document.payload_sha256 == hashlib.sha256(_payload()).hexdigest()
    assert mutation_id.startswith("mutation-")
    assert len(mutation_id) == 41
    assert len({item.value for item in FirestoreCasCollection}) == 8
    assert firestore_cas_document_key(
        FirestoreCasCollection.RUNTIME,
        _LOGICAL_ID,
    ) in firestore_cas_document_path(FirestoreCasCollection.RUNTIME, _LOGICAL_ID)
    assert firestore_cas_document_path(
        FirestoreCasCollection.RUNTIME,
        _LOGICAL_ID,
    ).startswith(f"{FirestoreCasCollection.RUNTIME.value}/")

    with pytest.raises(TypeError):
        firestore_cas_document_key("runtime", _LOGICAL_ID)  # type: ignore[arg-type]
    with pytest.raises(ValueError):
        _document(logical_id="invalid/path")
    with pytest.raises(ValueError, match="canonical"):
        build_firestore_cas_document(
            collection=FirestoreCasCollection.RUNTIME,
            logical_id=_LOGICAL_ID,
            revision=0,
            mutation_id="mutation-noncanonical",
            canonical_payload=b'{"value":1, "schema_version":"v1"}',
        )
    with pytest.raises(ValueError, match="canonical"):
        build_firestore_cas_document(
            collection=FirestoreCasCollection.RUNTIME,
            logical_id=_LOGICAL_ID,
            revision=0,
            mutation_id="mutation-duplicate",
            canonical_payload=b'{"value":1,"value":1}',
        )
    with pytest.raises(ValueError, match="byte bounds"):
        build_firestore_cas_document(
            collection=FirestoreCasCollection.RUNTIME,
            logical_id=_LOGICAL_ID,
            revision=0,
            mutation_id="mutation-oversized",
            canonical_payload=b"{" + b"x" * FIRESTORE_CAS_PAYLOAD_BYTE_CEILING,
        )
    with pytest.raises(ValidationError):
        FirestoreCasDocument(
            schema_version=FIRESTORE_CAS_DOCUMENT_VERSION,
            kind=FirestoreCasCollection.RUNTIME,
            logical_id=_LOGICAL_ID,
            revision=0,
            mutation_id="mutation-wrong-digest",
            canonical_payload=_payload().decode(),
            payload_sha256="0" * 64,
        )


def test_configuration_is_exact_and_missing_read_is_lazy_and_strong() -> None:
    async def scenario() -> None:
        client = _Client()
        store, factory = _store(client)
        assert store.database_id == FIRESTORE_RUNTIME_DATABASE
        sandbox_store = GoogleFirestoreCasStore(
            project_id=_PROJECT,
            database_id=FIRESTORE_SANDBOX_DATABASE,
            client_factory=factory,
        )
        assert sandbox_store.database_id == FIRESTORE_SANDBOX_DATABASE
        assert factory.calls == 0

        with pytest.raises(ValueError):
            await store.read(FirestoreCasCollection.RUNTIME, "invalid/path")
        assert factory.calls == 0

        assert await store.read(FirestoreCasCollection.RUNTIME, _LOGICAL_ID) is None
        assert factory.calls == 1
        assert client.gets == [
            (
                firestore_cas_document_path(
                    FirestoreCasCollection.RUNTIME,
                    _LOGICAL_ID,
                ),
                None,
                None,
                None,
                FIRESTORE_CAS_TIMEOUT_SECONDS,
                None,
            )
        ]

        with pytest.raises(ValueError, match="not approved"):
            GoogleFirestoreCasStore(
                project_id=_PROJECT,
                database_id="(default)",
                client_factory=factory,
            )
        assert factory.calls == 1

    asyncio.run(scenario())


def test_default_factory_binds_the_named_database_only_when_first_used(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def scenario() -> None:
        client = _Client()
        calls: list[tuple[str | None, str | None]] = []

        def fake_client(*, project=None, database=None):
            calls.append((project, database))
            return client

        monkeypatch.setattr(firestore_v1, "AsyncClient", fake_client)
        store = GoogleFirestoreCasStore(project_id=_PROJECT)
        assert calls == []

        await store.read(FirestoreCasCollection.RUNTIME, _LOGICAL_ID)

        assert calls == [(_PROJECT, FIRESTORE_RUNTIME_DATABASE)]

        sandbox_store = GoogleFirestoreCasStore(
            project_id=_PROJECT,
            database_id=FIRESTORE_SANDBOX_DATABASE,
        )
        await sandbox_store.read(FirestoreCasCollection.OPERATIONAL_EVENT, _LOGICAL_ID)
        assert calls[-1] == (_PROJECT, FIRESTORE_SANDBOX_DATABASE)

    asyncio.run(scenario())


def test_create_and_update_use_fixed_retry_and_last_update_precondition() -> None:
    async def scenario() -> None:
        client = _Client()
        store, factory = _store(client)
        initial = _document()

        created = await store.create(initial)
        replacement = _document(
            revision=1,
            mutation_id="mutation-replacement",
            value=2,
        )
        updated = await store.update(created, replacement)
        readback = await store.read(FirestoreCasCollection.RUNTIME, _LOGICAL_ID)

        assert factory.calls == 1
        assert created.document == initial
        assert updated.document == replacement
        assert readback is not None and readback.document == replacement
        assert len(client.commits) == 2
        assert all(
            retry is None and timeout == FIRESTORE_CAS_TIMEOUT_SECONDS
            for _operations, retry, timeout in client.commits
        )
        create_operation = client.commits[0][0][0]
        update_operation = client.commits[1][0][0]
        assert create_operation.kind == "create"
        assert create_operation.option is None
        assert update_operation.kind == "update"
        assert update_operation.option == _Option(
            kind="last_update_time",
            value=created.update_time,
        )
        assert set(update_operation.data) == {
            "schema_version",
            "kind",
            "logical_id",
            "revision",
            "mutation_id",
            "canonical_payload",
            "payload_sha256",
        }
        assert client.gets[-1][3:] == (
            None,
            FIRESTORE_CAS_TIMEOUT_SECONDS,
            None,
        )

    asyncio.run(scenario())


def test_known_create_and_stale_update_contention_are_sanitized_conflicts() -> None:
    async def scenario() -> None:
        client = _Client()
        store, _ = _store(client)
        initial = _document()
        stale = await store.create(initial)

        with pytest.raises(FirestoreCasConflict) as duplicate:
            await store.create(initial)
        assert "private" not in str(duplicate.value)

        await store.update(
            stale,
            _document(revision=1, mutation_id="mutation-winner", value="winner"),
        )
        with pytest.raises(FirestoreCasConflict) as conflict:
            await store.update(
                stale,
                _document(revision=1, mutation_id="mutation-stale", value="stale"),
            )
        assert "private" not in str(conflict.value)

    asyncio.run(scenario())


def test_concurrent_compare_and_swap_has_one_winner() -> None:
    async def scenario() -> None:
        client = _Client()
        store, _ = _store(client)
        current = await store.create(_document())

        results = await asyncio.gather(
            store.update(
                current,
                _document(revision=1, mutation_id="mutation-first", value="first"),
            ),
            store.update(
                current,
                _document(revision=1, mutation_id="mutation-second", value="second"),
            ),
            return_exceptions=True,
        )

        assert sum(type(item) is FirestoreCasSnapshot for item in results) == 1
        assert sum(isinstance(item, FirestoreCasConflict) for item in results) == 1

    asyncio.run(scenario())


@pytest.mark.parametrize("malformed_result", (False, True))
def test_ambiguous_committed_create_adopts_only_its_exact_poststate(
    malformed_result: bool,
) -> None:
    async def scenario() -> None:
        client = _Client()
        if malformed_result:
            client.commit_results[1] = []
        else:
            client.commit_after[1] = RuntimeError("private provider response")
        store, _ = _store(client)
        document = _document(mutation_id="mutation-ambiguous-create")

        created = await store.create(document)

        assert created.document == document
        assert len(client.gets) == 1

    asyncio.run(scenario())


@pytest.mark.parametrize("ambiguous", (False, True))
def test_atomic_pair_create_returns_both_exact_snapshots(ambiguous: bool) -> None:
    async def scenario() -> None:
        client = _Client()
        if ambiguous:
            client.commit_after[1] = RuntimeError("private provider response")
        store, _ = _store(client)
        first = _document(mutation_id="mutation-pair-runtime")
        second = _document(
            collection=FirestoreCasCollection.SCENARIO_INDEX,
            logical_id="scenario-index-1",
            mutation_id="mutation-pair-index",
            value="index",
        )

        first_snapshot, second_snapshot = await store.create_pair(first, second)

        assert first_snapshot.document == first
        assert second_snapshot.document == second
        operations, retry, timeout = client.commits[0]
        assert tuple(item.kind for item in operations) == ("create", "create")
        assert retry is None
        assert timeout == FIRESTORE_CAS_TIMEOUT_SECONDS
        assert len(client.gets) == (2 if ambiguous else 0)

    asyncio.run(scenario())


def test_atomic_pair_contention_creates_neither_document() -> None:
    async def scenario() -> None:
        client = _Client()
        store, _ = _store(client)
        occupied = _document(
            collection=FirestoreCasCollection.SCENARIO_INDEX,
            logical_id="scenario-index-occupied",
            mutation_id="mutation-existing-index",
            value="existing",
        )
        await store.create(occupied)
        first = _document(mutation_id="mutation-pair-contender")
        second = _document(
            collection=occupied.kind,
            logical_id=occupied.logical_id,
            mutation_id="mutation-pair-conflict",
            value="conflict",
        )

        with pytest.raises(FirestoreCasConflict):
            await store.create_pair(first, second)

        assert await store.read(first.kind, first.logical_id) is None
        current = await store.read(occupied.kind, occupied.logical_id)
        assert current is not None
        assert current.document == occupied

    asyncio.run(scenario())


def test_atomic_update_and_create_preserves_both_or_neither() -> None:
    async def scenario() -> None:
        client = _Client()
        store, _ = _store(client)
        original = await store.create(_document())
        winner = _document(
            revision=1,
            mutation_id="mutation-winner",
            value="winner",
        )
        await store.update(original, winner)
        contender = _document(
            revision=1,
            mutation_id="mutation-contender",
            value="contender",
        )
        event = _document(
            collection=FirestoreCasCollection.RECOVERY_RUN_EVENT,
            logical_id="recovery-event-1",
            revision=1,
            mutation_id="mutation-event",
            value="event",
        )

        with pytest.raises(FirestoreCasConflict):
            await store.update_and_create_many(original, contender, (event,))

        current = await store.read(original.collection, original.document.logical_id)
        assert current is not None
        assert current.document == winner
        assert await store.read(event.kind, event.logical_id) is None

    asyncio.run(scenario())


def test_same_revision_recovery_rewrite_is_limited_to_versioned_migration() -> None:
    async def scenario() -> None:
        store, _ = _store(_Client())
        original = await store.create(
            _document(
                collection=FirestoreCasCollection.RECOVERY_RUN,
                payload_schema_version="reconcile/recovery-run-aggregate/v1",
            )
        )
        rewritten = _document(
            collection=FirestoreCasCollection.RECOVERY_RUN,
            mutation_id="mutation-rewrite",
            value="rewritten",
            payload_schema_version="reconcile/firestore-recovery-state/v2",
        )

        current = await store.rewrite_recovery_run(original, rewritten)

        assert current.document == rewritten
        with pytest.raises(ValueError, match="supported migration"):
            await store.rewrite_recovery_run(
                current,
                _document(
                    collection=FirestoreCasCollection.RECOVERY_RUN,
                    mutation_id="mutation-current-format-rewrite",
                    value="arbitrary-current-rewrite",
                    payload_schema_version="reconcile/firestore-recovery-state/v2",
                ),
            )
        with pytest.raises(FirestoreCasConflict):
            await store.rewrite_recovery_run(
                original,
                _document(
                    collection=FirestoreCasCollection.RECOVERY_RUN,
                    mutation_id="mutation-stale-rewrite",
                    value="stale",
                    payload_schema_version="reconcile/firestore-recovery-state/v2",
                ),
            )

    asyncio.run(scenario())


def test_ambiguous_batch_readback_has_bounded_concurrency() -> None:
    class BoundedReadStore(GoogleFirestoreCasStore):
        def __init__(self, client: _Client) -> None:
            super().__init__(project_id=_PROJECT, client_factory=lambda: client)
            self.active_reads = 0
            self.maximum_reads = 0

        async def read(self, collection, logical_id):
            self.active_reads += 1
            self.maximum_reads = max(self.maximum_reads, self.active_reads)
            try:
                await asyncio.sleep(0)
                return await super().read(collection, logical_id)
            finally:
                self.active_reads -= 1

    async def scenario() -> None:
        client = _Client()
        client.commit_after[1] = RuntimeError("private provider response")
        store = BoundedReadStore(client)
        documents = tuple(
            _document(
                logical_id=f"ambiguous-batch-{index}",
                mutation_id=f"mutation-ambiguous-batch-{index}",
            )
            for index in range(FIRESTORE_CAS_AMBIGUOUS_READ_CONCURRENCY * 2 + 1)
        )

        written = await store.create_many(documents)

        assert tuple(item.document for item in written) == documents
        assert store.maximum_reads == FIRESTORE_CAS_AMBIGUOUS_READ_CONCURRENCY
        assert len(client.gets) == len(documents)

    asyncio.run(scenario())


def test_ambiguous_uncommitted_or_divergent_write_remains_unknown() -> None:
    async def scenario() -> None:
        client = _Client()
        client.commit_before[1] = RuntimeError("private provider response")
        store, _ = _store(client)

        with pytest.raises(FirestoreCasOutcomeUnknown) as absent:
            await store.create(_document(mutation_id="mutation-before-create"))
        assert len(client.gets) == 1
        assert "private" not in str(absent.value)

        client.commit_before.clear()
        created = await store.create(_document())
        client.commit_before[3] = RuntimeError("private provider response")
        path = firestore_cas_document_path(
            FirestoreCasCollection.RUNTIME,
            _LOGICAL_ID,
        )
        data, update_time = client.documents[path]
        divergent = _document(
            revision=1,
            mutation_id="mutation-other-writer",
            value="other",
        )
        client.documents[path] = (divergent.model_dump(mode="json"), update_time)

        with pytest.raises(FirestoreCasOutcomeUnknown):
            await store.update(
                created,
                _document(
                    revision=1,
                    mutation_id="mutation-unknown-update",
                    value="ours",
                ),
            )
        assert data["revision"] == 0
        assert len(client.gets) == 2

    asyncio.run(scenario())


def test_ambiguous_committed_update_uses_one_exact_readback() -> None:
    async def scenario() -> None:
        client = _Client()
        store, _ = _store(client)
        current = await store.create(_document())
        replacement = _document(
            revision=1,
            mutation_id="mutation-ambiguous-update",
            value="updated",
        )
        client.commit_after[2] = RuntimeError("private provider response")

        updated = await store.update(current, replacement)

        assert updated.document == replacement
        assert len(client.gets) == 1

    asyncio.run(scenario())


@pytest.mark.parametrize(
    "mutation",
    (
        lambda data: data.update(payload_sha256="0" * 64),
        lambda data: data.update(kind=FirestoreCasCollection.SCENARIO.value),
        lambda data: data.update(logical_id="different-logical-id"),
        lambda data: data.update(extra="not-allowed"),
    ),
)
def test_corrupt_provider_wrapper_is_never_admitted(mutation) -> None:
    async def scenario() -> None:
        client = _Client()
        store, _ = _store(client)
        document = _document()
        path = firestore_cas_document_path(document.kind, document.logical_id)
        data = document.model_dump(mode="json")
        mutation(data)
        client.documents[path] = (data, _NOW)

        with pytest.raises(FirestoreCasCorruptDocument) as failure:
            await store.read(document.kind, document.logical_id)
        assert "not-allowed" not in str(failure.value)
        assert "different" not in str(failure.value)

    asyncio.run(scenario())


def test_wrong_provider_reference_path_is_corrupt() -> None:
    async def scenario() -> None:
        client = _Client()
        store, _ = _store(client)
        document = _document()
        path = firestore_cas_document_path(document.kind, document.logical_id)
        client.documents[path] = (document.model_dump(mode="json"), _NOW)
        client.returned_paths[path] = (
            f"{FirestoreCasCollection.SCENARIO.value}/{'f' * 64}"
        )

        with pytest.raises(FirestoreCasCorruptDocument):
            await store.read(document.kind, document.logical_id)

    asyncio.run(scenario())


def test_provider_failures_are_sanitized_and_cancellation_propagates() -> None:
    async def scenario() -> None:
        unavailable_client = _Client()
        unavailable_client.get_failures.append(
            RuntimeError("private provider response and project")
        )
        unavailable, _ = _store(unavailable_client)
        with pytest.raises(FirestoreCasProviderUnavailable) as failure:
            await unavailable.read(FirestoreCasCollection.RUNTIME, _LOGICAL_ID)
        assert "private" not in str(failure.value)
        assert "project" not in str(failure.value)

        read_cancelled_client = _Client()
        read_cancelled_client.get_failures.append(asyncio.CancelledError())
        read_cancelled, _ = _store(read_cancelled_client)
        with pytest.raises(asyncio.CancelledError):
            await read_cancelled.read(FirestoreCasCollection.RUNTIME, _LOGICAL_ID)

        write_cancelled_client = _Client()
        write_cancelled_client.commit_before[1] = asyncio.CancelledError()
        write_cancelled, _ = _store(write_cancelled_client)
        with pytest.raises(asyncio.CancelledError):
            await write_cancelled.create(_document())
        assert write_cancelled_client.gets == []

    asyncio.run(scenario())


def test_replacement_must_advance_revision_and_mutation_identity() -> None:
    async def scenario() -> None:
        client = _Client()
        store, _ = _store(client)
        current = await store.create(_document())
        commits = len(client.commits)

        with pytest.raises(ValueError, match="advance"):
            await store.update(
                current,
                _document(revision=2, mutation_id="mutation-skipped"),
            )
        with pytest.raises(ValueError, match="advance"):
            await store.update(
                current,
                _document(revision=1, mutation_id=current.document.mutation_id),
            )
        with pytest.raises(ValueError, match="advance"):
            await store.update(
                current,
                _document(
                    revision=1,
                    mutation_id="mutation-wrong-kind",
                    collection=FirestoreCasCollection.SCENARIO,
                ),
            )

        assert len(client.commits) == commits

    asyncio.run(scenario())
