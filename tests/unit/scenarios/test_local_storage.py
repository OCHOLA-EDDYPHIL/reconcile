"""Local object metadata and immutable generation receipt behavior."""

from __future__ import annotations

import hashlib
import inspect
import multiprocessing
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from reconcile.scenarios.local_storage import (
    LocalStorageHarness,
    LocalStorageMutationTarget,
    LocalStorageReadTarget,
    StorageObjectAlreadyExists,
    StorageObjectNotFound,
    StorageOwnershipError,
    StorageReceiptAlreadyExists,
    correlation_sha256,
)

pytestmark = pytest.mark.unit

NOW = datetime(2026, 8, 13, 18, 0, tzinfo=UTC)


def _create_from_subprocess(
    database_path: str,
    index: int,
    results: multiprocessing.Queue,
) -> None:
    target = LocalStorageHarness(database_path)
    readback = target.create_object_with_receipt(
        operation_id=f"operation-{index}",
        bucket="local-bucket",
        name=f"objects/{index}.json",
        content=f"payload-{index}".encode(),
        correlation={"run_id": f"run-{index}"},
        observed_at=NOW + timedelta(seconds=index),
    )
    assert readback.object_metadata is not None
    results.put(readback.object_metadata.generation)


def _target(tmp_path: Path) -> LocalStorageHarness:
    return LocalStorageHarness(tmp_path / "storage.sqlite3")


def test_subprocesses_share_initialization_and_generation_allocation(
    tmp_path: Path,
) -> None:
    database_path = str(tmp_path / "shared.sqlite3")
    context = multiprocessing.get_context("spawn")
    results = context.Queue()
    processes = [
        context.Process(
            target=_create_from_subprocess,
            args=(database_path, index, results),
        )
        for index in range(1, 5)
    ]

    for process in processes:
        process.start()
    for process in processes:
        process.join(timeout=20)

    assert [process.exitcode for process in processes] == [0, 0, 0, 0]
    assert sorted(results.get(timeout=1) for _ in processes) == [1, 2, 3, 4]
    reopened = LocalStorageHarness(database_path)
    assert (
        reopened.count_owned(
            bucket="local-bucket",
            name="objects/3.json",
            operation_id="operation-3",
        )
        == 2
    )


def test_mutation_handle_returns_no_generation_or_receipt(
    tmp_path: Path,
) -> None:
    database_path = tmp_path / "separated.sqlite3"
    mutation = LocalStorageMutationTarget(database_path, clock=lambda: NOW)

    result = mutation.commit_object(
        operation_id="operation-7",
        bucket="local-bucket",
        name="object.json",
        content=b"content",
        correlation={"run_id": "run-7"},
    )

    assert result is None
    assert "observed_at" not in inspect.signature(mutation.commit_object).parameters
    assert not hasattr(mutation, "read_receipt")
    assert not hasattr(mutation, "read_object_with_receipt")
    readback = LocalStorageReadTarget(database_path).read(
        bucket="local-bucket",
        name="object.json",
        operation_id="operation-7",
    )
    assert readback.object_metadata is not None
    assert readback.object_metadata.observed_at == NOW
    assert readback.receipt is not None
    assert readback.receipt.observed_at == NOW


def test_create_returns_metadata_and_an_exact_immutable_receipt(
    tmp_path: Path,
) -> None:
    target = _target(tmp_path)
    content = b'{"order":"order-7"}'
    correlation = {"run_id": "run-7", "invocation_id": "invoke-7"}

    created = target.create_object_with_receipt(
        operation_id="operation-7",
        bucket="local-bucket",
        name="scenario-7/object.json",
        content=content,
        correlation=correlation,
        observed_at=NOW,
    )

    metadata = created.object_metadata
    receipt = created.receipt
    assert metadata is not None
    assert receipt is not None
    assert metadata.generation == 1
    assert metadata.content_sha256 == hashlib.sha256(content).hexdigest()
    assert metadata.size == len(content)
    assert metadata.correlation == correlation
    assert metadata.observed_at == NOW
    assert not hasattr(metadata, "content")
    assert receipt.operation_id == "operation-7"
    assert receipt.bucket == metadata.bucket
    assert receipt.name == metadata.name
    assert receipt.generation == metadata.generation
    assert receipt.content_sha256 == metadata.content_sha256
    assert receipt.size == metadata.size
    assert receipt.correlation_sha256 == correlation_sha256(correlation)
    assert receipt.observed_at == metadata.observed_at

    with pytest.raises(StorageReceiptAlreadyExists):
        target.create_receipt(
            operation_id="operation-7",
            object_metadata=metadata,
        )
    assert target.read_receipt(operation_id="operation-7") == receipt


def test_create_only_object_does_not_consume_a_generation_on_rejection(
    tmp_path: Path,
) -> None:
    target = _target(tmp_path)
    first = target.create_object(
        bucket="local-bucket",
        name="one.json",
        content=b"one",
        correlation={},
        observed_at=NOW,
    )

    with pytest.raises(StorageObjectAlreadyExists):
        target.create_object(
            bucket="local-bucket",
            name="one.json",
            content=b"duplicate",
            correlation={},
            observed_at=NOW,
        )
    second = target.create_object(
        bucket="local-bucket",
        name="two.json",
        content=b"two",
        correlation={},
        observed_at=NOW,
    )

    assert (first.generation, second.generation) == (1, 2)


def test_receipt_creation_requires_the_current_stored_generation(
    tmp_path: Path,
) -> None:
    target = _target(tmp_path)
    original = target.create_object(
        bucket="local-bucket",
        name="object.json",
        content=b"original",
        correlation={},
        observed_at=NOW,
    )
    target.overwrite_object(
        bucket="local-bucket",
        name="object.json",
        content=b"replacement",
        correlation={},
        observed_at=NOW + timedelta(seconds=1),
    )

    with pytest.raises(StorageOwnershipError, match="current object generation"):
        target.create_receipt(
            operation_id="operation-7",
            object_metadata=original,
        )
    assert target.read_receipt(operation_id="operation-7") is None


def test_metadata_read_omits_content_and_receipt_can_be_missing(
    tmp_path: Path,
) -> None:
    target = _target(tmp_path)
    created = target.create_object(
        bucket="local-bucket",
        name="object.json",
        content=b"content-is-not-read-back",
        correlation={"run_id": "run-7"},
        observed_at=NOW,
    )

    readback = target.read_object_with_receipt(
        bucket="local-bucket",
        name="object.json",
        operation_id="operation-without-receipt",
    )

    assert readback.object_metadata == created
    assert readback.receipt is None
    assert not hasattr(readback.object_metadata, "content")


def test_overwrite_assigns_a_new_generation_without_changing_receipt(
    tmp_path: Path,
) -> None:
    target = _target(tmp_path)
    original = target.create_object_with_receipt(
        operation_id="operation-7",
        bucket="local-bucket",
        name="object.json",
        content=b"original",
        correlation={"run_id": "run-7"},
        observed_at=NOW,
    )
    receipt = original.receipt

    overwritten = target.overwrite_object(
        bucket="local-bucket",
        name="object.json",
        content=b"replacement",
        correlation={"run_id": "run-8"},
        observed_at=NOW + timedelta(seconds=1),
    )
    readback = target.read_object_with_receipt(
        bucket="local-bucket",
        name="object.json",
        operation_id="operation-7",
    )

    assert overwritten.generation == 2
    assert readback.object_metadata == overwritten
    assert readback.receipt == receipt
    assert readback.receipt is not None
    assert readback.receipt.generation == 1


def test_overwrite_requires_an_existing_exact_object(tmp_path: Path) -> None:
    target = _target(tmp_path)

    with pytest.raises(StorageObjectNotFound):
        target.overwrite_object(
            bucket="local-bucket",
            name="missing.json",
            content=b"replacement",
            correlation={},
            observed_at=NOW,
        )


def test_exact_cleanup_is_idempotent_and_preserves_other_resources(
    tmp_path: Path,
) -> None:
    target = _target(tmp_path)
    for index in (1, 2):
        target.create_object_with_receipt(
            operation_id=f"operation-{index}",
            bucket="local-bucket",
            name=f"object-{index}.json",
            content=f"content-{index}".encode(),
            correlation={"run_id": f"run-{index}"},
            observed_at=NOW,
        )

    first = target.delete_owned(
        bucket="local-bucket",
        name="object-1.json",
        operation_id="operation-1",
    )
    second = target.delete_owned(
        bucket="local-bucket",
        name="object-1.json",
        operation_id="operation-1",
    )

    assert first.object_removed is True
    assert first.receipt_removed is True
    assert first.removed_count == 2
    assert second.removed_count == 0
    assert (
        target.count_owned(
            bucket="local-bucket",
            name="object-2.json",
            operation_id="operation-2",
        )
        == 2
    )
    after_deletion = target.create_object(
        bucket="local-bucket",
        name="object-3.json",
        content=b"content-3",
        correlation={},
        observed_at=NOW,
    )
    assert after_deletion.generation == 3


def test_cleanup_preserves_a_replacement_generation(tmp_path: Path) -> None:
    target = _target(tmp_path)
    created = target.create_object_with_receipt(
        operation_id="operation-7",
        bucket="local-bucket",
        name="object.json",
        content=b"original",
        correlation={"run_id": "run-7"},
        observed_at=NOW,
    )
    replacement = target.overwrite_object(
        bucket="local-bucket",
        name="object.json",
        content=b"replacement",
        correlation={"run_id": "run-8"},
        observed_at=NOW + timedelta(seconds=1),
    )

    with pytest.raises(StorageOwnershipError, match="current object generation"):
        target.delete_owned(
            bucket="local-bucket",
            name="object.json",
            operation_id="operation-7",
        )

    assert (
        target.read_metadata(
            bucket="local-bucket",
            name="object.json",
        )
        == replacement
    )
    assert target.read_receipt(operation_id="operation-7") == created.receipt


@pytest.mark.parametrize(
    "receipt_change",
    (
        {"bucket": "different-bucket"},
        {"name": "different.json"},
        {"generation": 99},
        {"content_sha256": "f" * 64},
        {"size": 99},
        {"correlation_digest": "e" * 64},
        {"observed_at": NOW - timedelta(hours=1)},
    ),
    ids=(
        "bucket",
        "name",
        "generation",
        "content-digest",
        "size",
        "correlation-digest",
        "observed-at",
    ),
)
def test_cleanup_requires_every_receipt_binding(
    tmp_path: Path,
    receipt_change: dict[str, object],
) -> None:
    target = _target(tmp_path)
    created = target.create_object_with_receipt(
        operation_id="operation-7",
        bucket="local-bucket",
        name="object.json",
        content=b"content",
        correlation={},
        observed_at=NOW,
    )
    target.harness_corrupt_receipt(
        operation_id="operation-7",
        **receipt_change,
    )

    with pytest.raises(StorageOwnershipError):
        target.delete_owned(
            bucket="local-bucket",
            name="object.json",
            operation_id="operation-7",
        )
    assert (
        target.read_metadata(
            bucket="local-bucket",
            name="object.json",
        )
        == created.object_metadata
    )
    assert target.read_receipt(operation_id="operation-7") is not None


def test_cleanup_preserves_an_object_when_its_receipt_is_missing(
    tmp_path: Path,
) -> None:
    target = _target(tmp_path)
    created = target.create_object(
        bucket="local-bucket",
        name="object.json",
        content=b"content",
        correlation={"run_id": "run-7"},
        observed_at=NOW,
    )

    first = target.delete_owned(
        bucket="local-bucket",
        name="object.json",
        operation_id="missing-operation",
    )
    second = target.delete_owned(
        bucket="local-bucket",
        name="object.json",
        operation_id="missing-operation",
    )

    assert first.removed_count == 0
    assert second.removed_count == 0
    assert (
        target.read_metadata(
            bucket="local-bucket",
            name="object.json",
        )
        == created
    )


def test_cleanup_removes_a_receipt_when_its_object_is_already_missing(
    tmp_path: Path,
) -> None:
    target = _target(tmp_path)
    target.create_object_with_receipt(
        operation_id="operation-7",
        bucket="local-bucket",
        name="object.json",
        content=b"content",
        correlation={"run_id": "run-7"},
        observed_at=NOW,
    )
    assert target.harness_delete_object(
        bucket="local-bucket",
        name="object.json",
    )

    first = target.delete_owned(
        bucket="local-bucket",
        name="object.json",
        operation_id="operation-7",
    )
    second = target.delete_owned(
        bucket="local-bucket",
        name="object.json",
        operation_id="operation-7",
    )

    assert first.object_removed is False
    assert first.receipt_removed is True
    assert second.removed_count == 0


def test_harness_helpers_create_bounded_negative_control_states(
    tmp_path: Path,
) -> None:
    target = _target(tmp_path)
    target.create_object_with_receipt(
        operation_id="operation-7",
        bucket="local-bucket",
        name="object.json",
        content=b"content",
        correlation={"run_id": "run-7"},
        observed_at=NOW,
    )
    target.harness_corrupt_receipt(
        operation_id="operation-7",
        bucket="wrong-bucket",
        name="wrong.json",
        generation=99,
        content_sha256="f" * 64,
        size=99,
        correlation_digest="e" * 64,
        observed_at=NOW - timedelta(hours=1),
    )
    target.harness_corrupt_object_metadata(
        bucket="local-bucket",
        name="object.json",
        content_sha256="d" * 64,
        size=88,
        correlation={"run_id": "run-8"},
        observed_at=NOW - timedelta(hours=2),
    )

    readback = target.read_object_with_receipt(
        bucket="local-bucket",
        name="object.json",
        operation_id="operation-7",
    )
    assert readback.object_metadata is not None
    assert readback.receipt is not None
    assert readback.object_metadata.content_sha256 == "d" * 64
    assert readback.object_metadata.size == 88
    assert readback.object_metadata.correlation == {"run_id": "run-8"}
    assert readback.receipt.bucket == "wrong-bucket"
    assert readback.receipt.name == "wrong.json"
    assert readback.receipt.generation == 99
    assert readback.receipt.content_sha256 == "f" * 64
    assert readback.receipt.size == 99
    assert readback.receipt.correlation_sha256 == "e" * 64
    assert target.harness_delete_receipt(operation_id="operation-7") is True
    assert target.harness_delete_receipt(operation_id="operation-7") is False
    assert (
        target.harness_delete_object(
            bucket="local-bucket",
            name="object.json",
        )
        is True
    )
    assert (
        target.harness_delete_object(
            bucket="local-bucket",
            name="object.json",
        )
        is False
    )


@pytest.mark.parametrize(
    "key",
    ("api_token", "Authorization", "client-secret", "apiKey"),
)
def test_secret_shaped_correlation_fields_are_rejected(
    tmp_path: Path,
    key: str,
) -> None:
    target = _target(tmp_path)

    with pytest.raises(ValueError, match="secret-bearing"):
        target.create_object(
            bucket="local-bucket",
            name="object.json",
            content=b"content",
            correlation={key: "value"},
            observed_at=NOW,
        )
