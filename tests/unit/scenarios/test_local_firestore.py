"""Local business-document target transaction and ownership behavior."""

from __future__ import annotations

import inspect
import multiprocessing
from datetime import UTC, datetime, timedelta
from itertools import combinations
from pathlib import Path

import pytest

from reconcile.scenarios.local_firestore import (
    BusinessDocumentCoordinate,
    BusinessDocumentWrite,
    BusinessOperationStatus,
    FirestoreOwnershipError,
    LocalFirestoreCleanupTarget,
    LocalFirestoreHarness,
    LocalFirestoreMutationTarget,
    LocalFirestoreReadTarget,
    expected_effect_declarations_sha256,
    expected_effects_sha256,
)

pytestmark = pytest.mark.unit

NOW = datetime(2026, 8, 13, 20, 0, tzinfo=UTC)
EFFECT_IDS = ("primary-request", "audit-record", "processing-index")
CORRELATION = {
    "business_id": "business-7",
    "operation_id": "operation-7",
    "run_id": "run-7",
}
ALL_SUBSETS = tuple(
    tuple(effect_ids)
    for length in range(len(EFFECT_IDS) + 1)
    for effect_ids in combinations(EFFECT_IDS, length)
)


class _StepClock:
    def __init__(self, start: datetime = NOW) -> None:
        self._next = start
        self.calls = 0

    def __call__(self) -> datetime:
        result = self._next
        self._next += timedelta(seconds=1)
        self.calls += 1
        return result


class _FailingClock:
    def __init__(self, successful_calls: int) -> None:
        self._successful_calls = successful_calls
        self.calls = 0

    def __call__(self) -> datetime:
        if self.calls >= self._successful_calls:
            raise RuntimeError("injected clock failure")
        result = NOW + timedelta(seconds=self.calls)
        self.calls += 1
        return result


def _documents(suffix: str = "7") -> tuple[BusinessDocumentWrite, ...]:
    return (
        BusinessDocumentWrite(
            effect_id=EFFECT_IDS[0],
            collection_name="requests",
            document_id=f"request-{suffix}",
            content=f'{{"request":"{suffix}"}}'.encode(),
        ),
        BusinessDocumentWrite(
            effect_id=EFFECT_IDS[1],
            collection_name="audits",
            document_id=f"audit-{suffix}",
            content=f'{{"audit":"{suffix}"}}'.encode(),
        ),
        BusinessDocumentWrite(
            effect_id=EFFECT_IDS[2],
            collection_name="processing-indexes",
            document_id=f"index-{suffix}",
            content=f'{{"index":"{suffix}"}}'.encode(),
        ),
    )


def _coordinates(
    documents: tuple[BusinessDocumentWrite, ...] | None = None,
) -> tuple[BusinessDocumentCoordinate, ...]:
    return tuple(document.coordinate for document in documents or _documents())


def _commit(
    database_path: Path | str,
    *,
    selected: tuple[str, ...],
    suffix: str = "7",
    namespace_id: str = "namespace-7",
    operation_id: str = "operation-7",
    correlation: dict[str, str] | None = None,
    clock: _StepClock | _FailingClock | None = None,
) -> None:
    target = LocalFirestoreMutationTarget(database_path, clock=clock or _StepClock())
    target.commit_business_operation(
        namespace_id=namespace_id,
        operation_id=operation_id,
        manifest_collection="operations",
        manifest_document_id=operation_id,
        documents=_documents(suffix),
        selected_effect_ids=selected,
        correlation=correlation or CORRELATION,
    )


def _read(
    database_path: Path | str,
    *,
    suffix: str = "7",
    namespace_id: str = "namespace-7",
    operation_id: str = "operation-7",
):
    documents = _documents(suffix)
    return LocalFirestoreReadTarget(database_path).read(
        namespace_id=namespace_id,
        operation_id=operation_id,
        manifest_collection="operations",
        manifest_document_id=operation_id,
        document_coordinates=_coordinates(documents),
    )


def _commit_from_subprocess(
    database_path: str,
    index: int,
    results: multiprocessing.Queue,
) -> None:
    suffix = str(index)
    operation_id = f"operation-{index}"
    _commit(
        database_path,
        selected=(EFFECT_IDS[0],),
        suffix=suffix,
        namespace_id=f"namespace-{index}",
        operation_id=operation_id,
        correlation={
            "business_id": f"business-{index}",
            "operation_id": operation_id,
            "run_id": f"run-{index}",
        },
        clock=_StepClock(NOW + timedelta(minutes=index)),
    )
    readback = _read(
        database_path,
        suffix=suffix,
        namespace_id=f"namespace-{index}",
        operation_id=operation_id,
    )
    assert readback.manifest is not None
    results.put(readback.manifest.revision)


def test_subprocesses_share_initialization_and_allocate_unique_revisions(
    tmp_path: Path,
) -> None:
    database_path = str(tmp_path / "shared.sqlite3")
    context = multiprocessing.get_context("spawn")
    results = context.Queue()
    processes = [
        context.Process(
            target=_commit_from_subprocess,
            args=(database_path, index, results),
        )
        for index in range(1, 5)
    ]

    for process in processes:
        process.start()
    for process in processes:
        process.join(timeout=20)

    assert [process.exitcode for process in processes] == [0, 0, 0, 0]
    revisions = [results.get(timeout=1) for _ in processes]
    assert len(set(revisions)) == len(processes)


def test_production_handles_keep_mutation_read_and_cleanup_separate(
    tmp_path: Path,
) -> None:
    database_path = tmp_path / "separated.sqlite3"
    mutation = LocalFirestoreMutationTarget(database_path, clock=_StepClock())

    result = mutation.commit_business_operation(
        namespace_id="namespace-7",
        operation_id="operation-7",
        manifest_collection="operations",
        manifest_document_id="operation-7",
        documents=_documents(),
        selected_effect_ids=(EFFECT_IDS[0],),
        correlation=CORRELATION,
    )

    assert result is None
    assert (
        "observed_at"
        not in inspect.signature(mutation.commit_business_operation).parameters
    )
    assert not hasattr(mutation, "read")
    assert not hasattr(mutation, "delete_owned")
    read_target = LocalFirestoreReadTarget(database_path)
    assert not hasattr(read_target, "commit_business_operation")
    assert not hasattr(read_target, "delete_owned")
    cleanup = LocalFirestoreCleanupTarget(database_path)
    assert not hasattr(cleanup, "read")
    assert not hasattr(cleanup, "commit_business_operation")


@pytest.mark.parametrize("selected", ALL_SUBSETS, ids=lambda value: str(len(value)))
def test_every_effect_subset_has_an_exact_terminal_partition(
    tmp_path: Path,
    selected: tuple[str, ...],
) -> None:
    database_path = tmp_path / "subsets.sqlite3"
    clock = _StepClock()
    documents = _documents()

    _commit(database_path, selected=selected, clock=clock)
    readback = _read(database_path)

    manifest = readback.manifest
    assert manifest is not None
    expected_status = (
        BusinessOperationStatus.TERMINAL_COMMITTED
        if selected
        else BusinessOperationStatus.TERMINAL_NOT_COMMITTED
    )
    assert manifest.status is expected_status
    assert manifest.expected_effect_ids == EFFECT_IDS
    assert manifest.expected_effects_sha256 == expected_effects_sha256(documents)
    assert manifest.established_effect_ids == selected
    assert manifest.not_established_effect_ids == tuple(
        effect_id for effect_id in EFFECT_IDS if effect_id not in selected
    )
    assert set(manifest.effect_revisions) == set(selected)
    assert manifest.correlation == CORRELATION
    expected_last_step = len(selected) if selected else 1
    assert manifest.observed_at == NOW + timedelta(seconds=expected_last_step)
    assert clock.calls == expected_last_step + 1
    by_effect = {document.effect_id: document for document in readback.documents}
    assert set(by_effect) == set(selected)
    for effect_id in selected:
        document = by_effect[effect_id]
        assert document.revision == manifest.effect_revisions[effect_id]
        assert document.content_sha256 == next(
            item.content_sha256 for item in documents if item.effect_id == effect_id
        )
        assert document.correlation == CORRELATION
        assert document.observed_at <= manifest.observed_at
        assert not hasattr(document, "content")


def test_shared_declaration_digest_needs_no_content_bytes() -> None:
    documents = _documents()
    declarations = tuple(
        (
            document.effect_id,
            document.collection_name,
            document.document_id,
            document.content_sha256,
        )
        for document in documents
    )

    assert expected_effect_declarations_sha256(declarations) == (
        expected_effects_sha256(documents)
    )


def test_a_later_step_failure_preserves_prior_separate_commits_as_active(
    tmp_path: Path,
) -> None:
    database_path = tmp_path / "interrupted.sqlite3"
    clock = _FailingClock(successful_calls=2)

    with pytest.raises(RuntimeError, match="injected clock failure"):
        _commit(database_path, selected=EFFECT_IDS, clock=clock)

    readback = _read(database_path)
    manifest = readback.manifest
    assert manifest is not None
    assert manifest.status is BusinessOperationStatus.ACTIVE
    assert manifest.established_effect_ids == (EFFECT_IDS[0],)
    assert manifest.not_established_effect_ids == ()
    assert tuple(document.effect_id for document in readback.documents) == (
        EFFECT_IDS[0],
    )
    assert readback.documents[0].revision == manifest.effect_revisions[EFFECT_IDS[0]]


def test_harness_can_leave_multiple_commits_active(tmp_path: Path) -> None:
    database_path = tmp_path / "active.sqlite3"
    harness = LocalFirestoreHarness(database_path, clock=_StepClock())
    harness.create_active_business_operation(
        namespace_id="namespace-7",
        operation_id="operation-7",
        manifest_collection="operations",
        manifest_document_id="operation-7",
        documents=_documents(),
        selected_effect_ids=EFFECT_IDS[:2],
        correlation=CORRELATION,
    )

    readback = _read(database_path)

    assert readback.manifest is not None
    assert readback.manifest.status is BusinessOperationStatus.ACTIVE
    assert readback.manifest.established_effect_ids == EFFECT_IDS[:2]
    assert readback.manifest.not_established_effect_ids == ()
    assert {item.effect_id for item in readback.documents} == set(EFFECT_IDS[:2])


def test_composite_read_surfaces_extra_correlated_documents(
    tmp_path: Path,
) -> None:
    database_path = tmp_path / "duplicate.sqlite3"
    _commit(database_path, selected=(EFFECT_IDS[0],))
    harness = LocalFirestoreHarness(
        database_path,
        clock=_StepClock(NOW + timedelta(minutes=1)),
    )
    duplicate = harness.insert_document(
        namespace_id="namespace-7",
        operation_id="operation-7",
        document=BusinessDocumentWrite(
            effect_id=EFFECT_IDS[0],
            collection_name="duplicates",
            document_id="duplicate-request-7",
            content=b"duplicate",
        ),
        correlation=CORRELATION,
    )

    readback = _read(database_path)

    assert len(readback.documents) == 2
    assert duplicate in readback.documents


def test_cleanup_is_idempotent_and_preserves_another_namespace(
    tmp_path: Path,
) -> None:
    database_path = tmp_path / "cleanup.sqlite3"
    _commit(database_path, selected=EFFECT_IDS[:2])
    other_correlation = {
        "business_id": "business-8",
        "operation_id": "operation-8",
        "run_id": "run-8",
    }
    _commit(
        database_path,
        selected=EFFECT_IDS,
        suffix="8",
        namespace_id="namespace-8",
        operation_id="operation-8",
        correlation=other_correlation,
        clock=_StepClock(NOW + timedelta(minutes=1)),
    )
    cleanup = LocalFirestoreCleanupTarget(database_path)
    arguments = {
        "namespace_id": "namespace-7",
        "operation_id": "operation-7",
        "manifest_collection": "operations",
        "manifest_document_id": "operation-7",
        "document_coordinates": _coordinates(),
    }

    assert cleanup.count_owned(**arguments) == 3
    first = cleanup.delete_owned(**arguments)
    second = cleanup.delete_owned(**arguments)

    assert first.removed_documents == _coordinates()[:2]
    assert first.manifest_removed is True
    assert first.removed_count == 3
    assert second.removed_count == 0
    other = _read(
        database_path,
        suffix="8",
        namespace_id="namespace-8",
        operation_id="operation-8",
    )
    assert other.manifest is not None
    assert len(other.documents) == 3


def test_cleanup_preserves_a_replacement_and_rolls_back_owned_deletes(
    tmp_path: Path,
) -> None:
    database_path = tmp_path / "replacement.sqlite3"
    _commit(database_path, selected=EFFECT_IDS[:2])
    harness = LocalFirestoreHarness(
        database_path,
        clock=_StepClock(NOW + timedelta(minutes=1)),
    )
    replacement = harness.replace_document(
        namespace_id="namespace-7",
        operation_id="foreign-operation",
        document=BusinessDocumentWrite(
            effect_id=EFFECT_IDS[0],
            collection_name="requests",
            document_id="request-7",
            content=b"replacement",
        ),
        correlation={"run_id": "foreign-run"},
    )
    cleanup = LocalFirestoreCleanupTarget(database_path)

    with pytest.raises(FirestoreOwnershipError):
        cleanup.delete_owned(
            namespace_id="namespace-7",
            operation_id="operation-7",
            manifest_collection="operations",
            manifest_document_id="operation-7",
            document_coordinates=_coordinates(),
        )

    original = _read(database_path)
    assert original.manifest is not None
    assert {item.effect_id for item in original.documents} == {EFFECT_IDS[1]}
    foreign = _read(
        database_path,
        namespace_id="namespace-7",
        operation_id="foreign-operation",
    )
    assert foreign.manifest is None
    assert foreign.documents == (replacement,)


def test_cleanup_preserves_a_foreign_document_at_a_not_established_coordinate(
    tmp_path: Path,
) -> None:
    database_path = tmp_path / "foreign.sqlite3"
    _commit(database_path, selected=(EFFECT_IDS[0],))
    harness = LocalFirestoreHarness(
        database_path,
        clock=_StepClock(NOW + timedelta(minutes=1)),
    )
    foreign = harness.insert_document(
        namespace_id="namespace-7",
        operation_id="foreign-operation",
        document=_documents()[1],
        correlation={"run_id": "foreign-run"},
    )
    cleanup = LocalFirestoreCleanupTarget(database_path)

    removed = cleanup.delete_owned(
        namespace_id="namespace-7",
        operation_id="operation-7",
        manifest_collection="operations",
        manifest_document_id="operation-7",
        document_coordinates=_coordinates(),
    )

    assert removed.removed_count == 2
    remaining = _read(
        database_path,
        namespace_id="namespace-7",
        operation_id="foreign-operation",
    )
    assert remaining.documents == (foreign,)


def test_missing_manifest_never_authorizes_document_deletion(tmp_path: Path) -> None:
    database_path = tmp_path / "missing-manifest.sqlite3"
    _commit(database_path, selected=EFFECT_IDS)
    harness = LocalFirestoreHarness(database_path)
    assert harness.delete_manifest(
        namespace_id="namespace-7",
        operation_id="operation-7",
    )
    cleanup = LocalFirestoreCleanupTarget(database_path)

    with pytest.raises(FirestoreOwnershipError, match="without an ownership manifest"):
        cleanup.count_owned(
            namespace_id="namespace-7",
            operation_id="operation-7",
            manifest_collection="operations",
            manifest_document_id="operation-7",
            document_coordinates=_coordinates(),
        )
    deletion = cleanup.delete_owned(
        namespace_id="namespace-7",
        operation_id="operation-7",
        manifest_collection="operations",
        manifest_document_id="operation-7",
        document_coordinates=_coordinates(),
    )

    assert deletion.removed_count == 0
    assert len(_read(database_path).documents) == 3


def test_cleanup_handles_an_already_missing_owned_document(tmp_path: Path) -> None:
    database_path = tmp_path / "missing-document.sqlite3"
    _commit(database_path, selected=EFFECT_IDS)
    harness = LocalFirestoreHarness(database_path)
    assert harness.delete_document(
        namespace_id="namespace-7",
        collection_name="audits",
        document_id="audit-7",
    )
    cleanup = LocalFirestoreCleanupTarget(database_path)

    deletion = cleanup.delete_owned(
        namespace_id="namespace-7",
        operation_id="operation-7",
        manifest_collection="operations",
        manifest_document_id="operation-7",
        document_coordinates=_coordinates(),
    )

    assert deletion.removed_count == 3
    assert (
        cleanup.count_owned(
            namespace_id="namespace-7",
            operation_id="operation-7",
            manifest_collection="operations",
            manifest_document_id="operation-7",
            document_coordinates=_coordinates(),
        )
        == 0
    )


def test_cleanup_rejects_coordinates_not_bound_by_the_manifest(
    tmp_path: Path,
) -> None:
    database_path = tmp_path / "wrong-coordinates.sqlite3"
    _commit(database_path, selected=(EFFECT_IDS[0],))
    wrong = list(_coordinates())
    wrong[2] = BusinessDocumentCoordinate(
        effect_id=EFFECT_IDS[2],
        collection_name="processing-indexes",
        document_id="wrong-index",
    )
    cleanup = LocalFirestoreCleanupTarget(database_path)

    with pytest.raises(FirestoreOwnershipError):
        cleanup.delete_owned(
            namespace_id="namespace-7",
            operation_id="operation-7",
            manifest_collection="operations",
            manifest_document_id="operation-7",
            document_coordinates=tuple(wrong),
        )

    assert _read(database_path).manifest is not None


def test_invalid_selection_and_secret_shaped_correlation_fail_before_writes(
    tmp_path: Path,
) -> None:
    database_path = tmp_path / "invalid.sqlite3"
    target = LocalFirestoreMutationTarget(database_path, clock=_StepClock())
    arguments = {
        "namespace_id": "namespace-7",
        "operation_id": "operation-7",
        "manifest_collection": "operations",
        "manifest_document_id": "operation-7",
        "documents": _documents(),
    }

    with pytest.raises(ValueError, match="selected effects"):
        target.commit_business_operation(
            **arguments,
            selected_effect_ids=("undeclared-effect",),
            correlation=CORRELATION,
        )
    with pytest.raises(ValueError, match="secret-bearing"):
        target.commit_business_operation(
            **arguments,
            selected_effect_ids=(),
            correlation={"api_token": "value"},
        )

    assert _read(database_path).manifest is None
