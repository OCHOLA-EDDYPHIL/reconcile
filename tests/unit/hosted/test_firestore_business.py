"""Deterministic hosted Firestore business target behavior."""

from __future__ import annotations

import asyncio
from collections.abc import Callable
from copy import deepcopy
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest

from reconcile.hosted.firestore_business import (
    FIRESTORE_EFFECT_SCHEMA_VERSION,
    FirestoreCloudError,
    FirestoreCloudFailure,
    build_google_firestore_business_targets,
)
from reconcile.scenarios.local_firestore import (
    BusinessDocumentCoordinate,
    BusinessDocumentWrite,
    BusinessOperationStatus,
)

pytestmark = pytest.mark.unit

_NOW = datetime(2026, 8, 17, 20, 0, tzinfo=UTC)


class _ServerTimestamp:
    def __deepcopy__(self, memo: dict[int, object]) -> _ServerTimestamp:
        return self


_SERVER_TIMESTAMP = _ServerTimestamp()
_NAMESPACE = "scenario-business-7"
_OPERATION = "operation-business-7"
_MANIFEST_COLLECTION = "operation-manifests"
_MANIFEST_DOCUMENT = "operation-operation-business-7"
_CORRELATION = {
    "business_request_id": "request-7",
    "operation_id": _OPERATION,
    "run_id": "run-7",
}
_EFFECTS = (
    ("primary-request", "requests", "request-7", b"primary"),
    ("audit-record", "audit-records", "audit-7", b"audit"),
    ("processing-index", "processing-indexes", "processing-7", b"index"),
)


@dataclass(frozen=True, slots=True)
class _Option:
    kind: str
    value: object


@dataclass(frozen=True, slots=True)
class _Reference:
    path: str


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
    payload: dict[str, Any] | None
    option: _Option | None


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

    def delete(
        self,
        reference: _Reference,
        option: _Option | None = None,
    ) -> None:
        self.operations.append(_Operation("delete", reference, None, option))

    async def commit(
        self,
        retry: object | None = None,
        timeout: float | None = None,
    ) -> list[_Result]:
        return self.client.apply(self.operations, retry=retry, timeout=timeout)


class _Client:
    def __init__(self) -> None:
        self.documents: dict[str, tuple[dict[str, Any], datetime]] = {}
        self.commits: list[
            tuple[tuple[_Operation, ...], object | None, float | None]
        ] = []
        self.gets: list[tuple[tuple[str, ...], object | None, float | None]] = []
        self.after_apply_failure: dict[int, BaseException] = {}
        self.before_apply_failure: dict[int, BaseException] = {}
        self.before_apply_hook: dict[int, Callable[[_Client], None]] = {}
        self.duplicate_get_path: str | None = None

    def document(self, *document_path: str) -> _Reference:
        return _Reference("/".join(document_path))

    def batch(self) -> _Batch:
        return _Batch(self)

    def write_option(self, **kwargs: object) -> _Option:
        assert len(kwargs) == 1
        kind, value = next(iter(kwargs.items()))
        return _Option(kind, value)

    async def get_all(
        self,
        references: list[_Reference],
        field_paths: object | None = None,
        transaction: object | None = None,
        retry: object | None = None,
        timeout: float | None = None,
        *,
        read_time: datetime | None = None,
    ):
        assert field_paths is None
        assert transaction is None
        assert read_time is None
        self.gets.append((tuple(item.path for item in references), retry, timeout))
        observed = _NOW + timedelta(minutes=10, seconds=len(self.gets))
        snapshots: list[_Snapshot] = []
        for reference in reversed(references):
            stored = self.documents.get(reference.path)
            snapshots.append(
                _Snapshot(
                    reference=reference,
                    exists=stored is not None,
                    read_time=observed,
                    update_time=None if stored is None else stored[1],
                    data=None if stored is None else deepcopy(stored[0]),
                )
            )
        if self.duplicate_get_path is not None:
            snapshots.append(
                next(
                    item
                    for item in snapshots
                    if item.reference.path == self.duplicate_get_path
                )
            )
        for snapshot in snapshots:
            yield snapshot

    @staticmethod
    def _resolved(value: object, commit_time: datetime) -> object:
        if value is _SERVER_TIMESTAMP:
            return commit_time
        if isinstance(value, dict):
            return {
                key: _Client._resolved(item, commit_time) for key, item in value.items()
            }
        if isinstance(value, list):
            return [_Client._resolved(item, commit_time) for item in value]
        return deepcopy(value)

    @staticmethod
    def _check_option(
        current: tuple[dict[str, Any], datetime] | None,
        option: _Option | None,
    ) -> None:
        if option is None:
            return
        if option.kind == "exists":
            if (current is not None) is not option.value:
                raise FirestoreCloudError(FirestoreCloudFailure.PRECONDITION_FAILED)
            return
        if option.kind == "last_update_time":
            if current is None or current[1] != option.value:
                raise FirestoreCloudError(FirestoreCloudFailure.PRECONDITION_FAILED)
            return
        raise AssertionError("unexpected fake write option")

    def apply(
        self,
        operations: list[_Operation],
        *,
        retry: object | None,
        timeout: float | None,
    ) -> list[_Result]:
        commit_number = len(self.commits) + 1
        self.commits.append((tuple(operations), retry, timeout))
        failure = self.before_apply_failure.get(commit_number)
        if failure is not None:
            raise failure
        hook = self.before_apply_hook.get(commit_number)
        if hook is not None:
            hook(self)
        staged = deepcopy(self.documents)
        commit_time = _NOW + timedelta(seconds=commit_number)
        for operation in operations:
            current = staged.get(operation.reference.path)
            if operation.kind == "create":
                if current is not None:
                    raise FirestoreCloudError(FirestoreCloudFailure.ALREADY_EXISTS)
                assert operation.payload is not None
                staged[operation.reference.path] = (
                    self._resolved(operation.payload, commit_time),  # type: ignore[arg-type]
                    commit_time,
                )
            elif operation.kind == "update":
                self._check_option(current, operation.option)
                if current is None:
                    raise FirestoreCloudError(FirestoreCloudFailure.PRECONDITION_FAILED)
                assert operation.payload is not None
                updated = deepcopy(current[0])
                updated.update(self._resolved(operation.payload, commit_time))
                staged[operation.reference.path] = (updated, commit_time)
            elif operation.kind == "delete":
                self._check_option(current, operation.option)
                if current is not None:
                    staged.pop(operation.reference.path)
            else:
                raise AssertionError("unexpected fake operation")
        self.documents = staged
        failure = self.after_apply_failure.get(commit_number)
        if failure is not None:
            raise failure
        return [_Result(commit_time) for _ in operations]


def _documents() -> tuple[BusinessDocumentWrite, ...]:
    return tuple(
        BusinessDocumentWrite(
            effect_id=effect_id,
            collection_name=collection,
            document_id=document_id,
            content=content,
        )
        for effect_id, collection, document_id, content in _EFFECTS
    )


def _coordinates() -> tuple[BusinessDocumentCoordinate, ...]:
    return tuple(document.coordinate for document in _documents())


def _arguments() -> dict[str, object]:
    return {
        "namespace_id": _NAMESPACE,
        "operation_id": _OPERATION,
        "manifest_collection": _MANIFEST_COLLECTION,
        "manifest_document_id": _MANIFEST_DOCUMENT,
        "document_coordinates": _coordinates(),
    }


def _targets(client: _Client, factory_calls: list[int] | None = None):
    def factory() -> _Client:
        if factory_calls is not None:
            factory_calls.append(1)
        return client

    return build_google_firestore_business_targets(
        project_id="reconcile-dev-260813-14fa6d",
        client_factory=factory,
        server_timestamp_factory=lambda: _SERVER_TIMESTAMP,
    )


def test_lazy_client_and_separate_conditioned_effect_commits() -> None:
    client = _Client()
    factory_calls: list[int] = []
    targets = _targets(client, factory_calls)
    assert factory_calls == []

    asyncio.run(
        targets.mutation.commit_business_operation(
            namespace_id=_NAMESPACE,
            operation_id=_OPERATION,
            manifest_collection=_MANIFEST_COLLECTION,
            manifest_document_id=_MANIFEST_DOCUMENT,
            documents=_documents(),
            selected_effect_ids=("primary-request", "processing-index"),
            correlation=_CORRELATION,
        )
    )

    assert factory_calls == [1]
    assert len(client.commits) == 3
    assert all(retry is None and timeout == 5.0 for _, retry, timeout in client.commits)
    create_operations = client.commits[0][0]
    assert [item.kind for item in create_operations] == [
        "delete",
        "delete",
        "delete",
        "create",
    ]
    assert all(
        item.option == _Option("exists", False) for item in create_operations[:3]
    )
    for operations, _, _ in client.commits[1:]:
        assert [item.kind for item in operations] == ["create", "update"]
        assert operations[1].option is not None
        assert operations[1].option.kind == "last_update_time"

    readback = asyncio.run(targets.read.read_business_operation(**_arguments()))
    assert readback.manifest is not None
    assert readback.manifest.status is BusinessOperationStatus.TERMINAL_COMMITTED
    assert readback.manifest.established_effect_ids == (
        "primary-request",
        "processing-index",
    )
    assert readback.manifest.not_established_effect_ids == ("audit-record",)
    assert tuple(item.effect_id for item in readback.documents) == (
        "primary-request",
        "processing-index",
    )
    assert client.gets[-1][1:] == (None, 5.0)


@pytest.mark.parametrize("mask", range(8))
def test_every_effect_partition_is_preserved(mask: int) -> None:
    client = _Client()
    targets = _targets(client)
    selected = tuple(
        effect_id
        for index, (effect_id, _, _, _) in enumerate(_EFFECTS)
        if mask & (1 << index)
    )

    asyncio.run(
        targets.mutation.commit_business_operation(
            namespace_id=_NAMESPACE,
            operation_id=_OPERATION,
            manifest_collection=_MANIFEST_COLLECTION,
            manifest_document_id=_MANIFEST_DOCUMENT,
            documents=_documents(),
            selected_effect_ids=selected,
            correlation=_CORRELATION,
        )
    )
    readback = asyncio.run(targets.read.read_business_operation(**_arguments()))

    assert readback.manifest is not None
    assert readback.manifest.established_effect_ids == selected
    assert readback.manifest.not_established_effect_ids == tuple(
        item[0] for item in _EFFECTS if item[0] not in selected
    )
    assert readback.manifest.status is (
        BusinessOperationStatus.TERMINAL_COMMITTED
        if selected
        else BusinessOperationStatus.TERMINAL_NOT_COMMITTED
    )
    assert len(client.commits) == (1 + len(selected) if selected else 2)


def test_cleanup_guards_present_absent_and_manifest_revisions_atomically() -> None:
    client = _Client()
    targets = _targets(client)
    asyncio.run(
        targets.mutation.commit_business_operation(
            namespace_id=_NAMESPACE,
            operation_id=_OPERATION,
            manifest_collection=_MANIFEST_COLLECTION,
            manifest_document_id=_MANIFEST_DOCUMENT,
            documents=_documents(),
            selected_effect_ids=("audit-record",),
            correlation=_CORRELATION,
        )
    )
    assert asyncio.run(targets.cleanup.count_owned(**_arguments())) == 2
    commit_count = len(client.commits)

    deletion = asyncio.run(targets.cleanup.delete_owned(**_arguments()))

    assert deletion.manifest_removed
    assert tuple(item.effect_id for item in deletion.removed_documents) == (
        "audit-record",
    )
    cleanup_operations = client.commits[-1][0]
    assert len(cleanup_operations) == 4
    assert [item.option.kind for item in cleanup_operations if item.option] == [
        "exists",
        "last_update_time",
        "exists",
        "last_update_time",
    ]
    assert client.documents == {}

    second = asyncio.run(targets.cleanup.delete_owned(**_arguments()))
    assert second.removed_count == 0
    assert len(client.commits) == commit_count + 1


def test_unknown_post_commit_failure_is_sanitized_and_never_replayed() -> None:
    client = _Client()
    client.after_apply_failure[2] = RuntimeError(
        "secret provider metadata must never escape"
    )
    targets = _targets(client)

    with pytest.raises(FirestoreCloudError) as raised:
        asyncio.run(
            targets.mutation.commit_business_operation(
                namespace_id=_NAMESPACE,
                operation_id=_OPERATION,
                manifest_collection=_MANIFEST_COLLECTION,
                manifest_document_id=_MANIFEST_DOCUMENT,
                documents=_documents(),
                selected_effect_ids=("primary-request",),
                correlation=_CORRELATION,
            )
        )

    assert raised.value.code is FirestoreCloudFailure.UNAVAILABLE
    assert str(raised.value) == "unavailable"
    assert raised.value.__cause__ is None
    assert len(client.commits) == 2
    readback = asyncio.run(targets.read.read_business_operation(**_arguments()))
    assert readback.manifest is not None
    assert readback.manifest.established_effect_ids == ("primary-request",)


def test_cleanup_manifest_drift_aborts_the_entire_delete_batch() -> None:
    client = _Client()
    targets = _targets(client)
    asyncio.run(
        targets.mutation.commit_business_operation(
            namespace_id=_NAMESPACE,
            operation_id=_OPERATION,
            manifest_collection=_MANIFEST_COLLECTION,
            manifest_document_id=_MANIFEST_DOCUMENT,
            documents=_documents(),
            selected_effect_ids=("audit-record",),
            correlation=_CORRELATION,
        )
    )
    manifest_path = (
        f"reconcile-business-namespaces/{_NAMESPACE}/"
        f"{_MANIFEST_COLLECTION}/{_MANIFEST_DOCUMENT}"
    )

    def drift(fake: _Client) -> None:
        payload, _ = fake.documents[manifest_path]
        fake.documents[manifest_path] = (payload, _NOW + timedelta(hours=1))

    client.before_apply_hook[3] = drift
    before_paths = set(client.documents)

    with pytest.raises(FirestoreCloudError) as raised:
        asyncio.run(targets.cleanup.delete_owned(**_arguments()))

    assert raised.value.code is FirestoreCloudFailure.PRECONDITION_FAILED
    assert set(client.documents) == before_paths


def test_create_absence_guard_fails_atomically_when_an_effect_is_occupied() -> None:
    client = _Client()
    occupied = f"reconcile-business-namespaces/{_NAMESPACE}/requests/request-7"
    client.documents[occupied] = (
        {
            "schema_version": FIRESTORE_EFFECT_SCHEMA_VERSION,
            "effect_id": "foreign-effect",
        },
        _NOW,
    )
    targets = _targets(client)

    with pytest.raises(FirestoreCloudError) as raised:
        asyncio.run(
            targets.mutation.commit_business_operation(
                namespace_id=_NAMESPACE,
                operation_id=_OPERATION,
                manifest_collection=_MANIFEST_COLLECTION,
                manifest_document_id=_MANIFEST_DOCUMENT,
                documents=_documents(),
                selected_effect_ids=("primary-request",),
                correlation=_CORRELATION,
            )
        )

    assert raised.value.code is FirestoreCloudFailure.PRECONDITION_FAILED
    assert set(client.documents) == {occupied}


def test_composite_read_rejects_duplicate_provider_results() -> None:
    client = _Client()
    targets = _targets(client)
    asyncio.run(
        targets.mutation.commit_business_operation(
            namespace_id=_NAMESPACE,
            operation_id=_OPERATION,
            manifest_collection=_MANIFEST_COLLECTION,
            manifest_document_id=_MANIFEST_DOCUMENT,
            documents=_documents(),
            selected_effect_ids=("primary-request",),
            correlation=_CORRELATION,
        )
    )
    client.duplicate_get_path = next(iter(client.documents))

    with pytest.raises(FirestoreCloudError) as raised:
        asyncio.run(targets.read.read_business_operation(**_arguments()))

    assert raised.value.code is FirestoreCloudFailure.MALFORMED_RESPONSE


def test_cancellation_propagates_without_translation_or_retry() -> None:
    client = _Client()
    client.before_apply_failure[1] = asyncio.CancelledError()
    targets = _targets(client)

    with pytest.raises(asyncio.CancelledError):
        asyncio.run(
            targets.mutation.commit_business_operation(
                namespace_id=_NAMESPACE,
                operation_id=_OPERATION,
                manifest_collection=_MANIFEST_COLLECTION,
                manifest_document_id=_MANIFEST_DOCUMENT,
                documents=_documents(),
                selected_effect_ids=("primary-request",),
                correlation=_CORRELATION,
            )
        )

    assert len(client.commits) == 1


def test_invalid_paths_and_oversized_content_fail_before_adc() -> None:
    client = _Client()
    factory_calls: list[int] = []
    targets = _targets(client, factory_calls)
    oversized = list(_documents())
    oversized[0] = BusinessDocumentWrite(
        effect_id=oversized[0].effect_id,
        collection_name=oversized[0].collection_name,
        document_id=oversized[0].document_id,
        content=b"x" * 16_385,
    )

    with pytest.raises(ValueError, match="byte limit"):
        asyncio.run(
            targets.mutation.commit_business_operation(
                namespace_id=_NAMESPACE,
                operation_id=_OPERATION,
                manifest_collection=_MANIFEST_COLLECTION,
                manifest_document_id=_MANIFEST_DOCUMENT,
                documents=tuple(oversized),
                selected_effect_ids=("primary-request",),
                correlation=_CORRELATION,
            )
        )
    with pytest.raises(ValueError, match="safe Firestore path segment"):
        asyncio.run(
            targets.read.read_business_operation(
                **({**_arguments(), "namespace_id": "escaped/path"})
            )
        )
    assert factory_calls == []
