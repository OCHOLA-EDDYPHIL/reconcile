from __future__ import annotations

import asyncio
import hashlib
import json
from copy import deepcopy
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from google.api_core import exceptions as api_exceptions

from reconcile.adapters.storage import (
    CLOUD_STORAGE_PROFILE,
    build_storage_capability,
    build_storage_rule_descriptor,
    build_storage_target,
)
from reconcile.hosted import storage as hosted_storage
from reconcile.hosted.storage import (
    CLOUD_STORAGE_CORRELATION_BYTE_CEILING,
    CLOUD_STORAGE_OBJECT_BYTE_CEILING,
    CLOUD_STORAGE_RECEIPT_VERSION,
    CLOUD_STORAGE_TIMEOUT_SECONDS,
    CloudStorageAlreadyExists,
    CloudStorageCleanupOutcomeUnknown,
    CloudStorageCleanupTarget,
    CloudStorageCorruptEvidence,
    CloudStorageMutationOutcomeUnknown,
    CloudStorageMutationTarget,
    CloudStorageOwnershipChanged,
    CloudStorageProviderUnavailable,
    CloudStorageReadTarget,
    cloud_storage_receipt_name,
)

pytestmark = pytest.mark.unit

_PROJECT = "example-project-id"
_BUCKET = "example-project-id-p5-target"
_NAME = "runs/storage-run-1/object.json"
_OPERATION = "operation-storage-1"
_CONTENT = b'{"operation":"operation-storage-1"}'
_CORRELATION = {
    "invocation_id": "invocation-storage-1",
    "operation_id": _OPERATION,
    "run_id": "storage-run-1",
}
_NOW = datetime(2026, 8, 17, 12, 0, tzinfo=UTC)


@dataclass
class _Record:
    content: bytes
    metadata: dict[str, str]
    content_type: str
    generation: int
    time_created: datetime
    metageneration: int = 1
    content_encoding: str | None = None


class _FakeBlob:
    def __init__(
        self,
        bucket: _FakeBucket,
        name: str,
        generation: int | None,
    ) -> None:
        self.bucket = bucket
        self.name = name
        self._selected_generation = generation
        self.metadata: dict[str, str] | None = None
        self.generation: int | None = generation
        self.size: int | None = None
        self.time_created: datetime | None = None
        self.metageneration: int | None = None
        self.content_type: str | None = None
        self.content_encoding: str | None = None

    def _load(self, record: _Record) -> None:
        self.metadata = deepcopy(record.metadata)
        self.generation = record.generation
        self.size = len(record.content)
        self.time_created = record.time_created
        self.metageneration = record.metageneration
        self.content_type = record.content_type
        self.content_encoding = record.content_encoding

    def upload_from_string(self, data: bytes, **kwargs: object) -> None:
        self.bucket.calls.append(("upload", self.name, deepcopy(kwargs)))
        failure = self.bucket.upload_before.get(self.name)
        if failure is not None:
            raise failure
        if self.name in self.bucket.records:
            raise api_exceptions.PreconditionFailed("private provider response")
        generation = self.bucket.next_generation
        self.bucket.next_generation += 1
        record = _Record(
            content=bytes(data),
            metadata=deepcopy(self.metadata or {}),
            content_type=str(kwargs["content_type"]),
            generation=generation,
            time_created=self.bucket.clock,
        )
        self.bucket.clock += timedelta(microseconds=1)
        self.bucket.records[self.name] = record
        self._load(record)
        failure = self.bucket.upload_after.get(self.name)
        if failure is not None:
            raise failure

    def reload(self, **kwargs: object) -> None:
        self.bucket.calls.append(("reload", self.name, deepcopy(kwargs)))
        failure = self.bucket.reload_failures.get(self.name)
        if failure is not None:
            raise failure
        record = self.bucket.records.get(self.name)
        if record is None or (
            self._selected_generation is not None
            and record.generation != self._selected_generation
        ):
            raise api_exceptions.NotFound("private provider response")
        self._load(record)

    def download_as_bytes(self, **kwargs: object) -> bytes:
        self.bucket.calls.append(("download", self.name, deepcopy(kwargs)))
        failure = self.bucket.download_failures.get(self.name)
        if failure is not None:
            raise failure
        record = self.bucket.records.get(self.name)
        if record is None or record.generation != self.generation:
            raise api_exceptions.NotFound("private provider response")
        return bytes(record.content)

    def delete(self, **kwargs: object) -> None:
        self.bucket.calls.append(("delete", self.name, deepcopy(kwargs)))
        failure = self.bucket.delete_failures.get(self.name)
        if failure is not None:
            raise failure
        record = self.bucket.records.get(self.name)
        if record is None:
            raise api_exceptions.NotFound("private provider response")
        if (
            self._selected_generation != record.generation
            or kwargs.get("if_generation_match") != record.generation
        ):
            raise api_exceptions.PreconditionFailed("private provider response")
        del self.bucket.records[self.name]


class _FakeBucket:
    def __init__(self) -> None:
        self.records: dict[str, _Record] = {}
        self.next_generation = 1
        self.clock = _NOW
        self.calls: list[tuple[str, str, dict[str, object]]] = []
        self.upload_before: dict[str, BaseException] = {}
        self.upload_after: dict[str, BaseException] = {}
        self.reload_failures: dict[str, BaseException] = {}
        self.download_failures: dict[str, BaseException] = {}
        self.delete_failures: dict[str, BaseException] = {}

    def blob(self, name: str, generation: int | None = None) -> _FakeBlob:
        self.calls.append(("blob", name, {"generation": generation}))
        return _FakeBlob(self, name, generation)


class _FakeClient:
    def __init__(self, bucket: _FakeBucket) -> None:
        self.selected_bucket = bucket
        self.bucket_names: list[str] = []

    def bucket(self, bucket_name: str) -> _FakeBucket:
        self.bucket_names.append(bucket_name)
        return self.selected_bucket


class _Factory:
    def __init__(self, client: _FakeClient) -> None:
        self.client = client
        self.projects: list[str] = []

    def __call__(self, project_id: str) -> _FakeClient:
        self.projects.append(project_id)
        return self.client


def _mutation(factory: _Factory) -> CloudStorageMutationTarget:
    return CloudStorageMutationTarget(
        project_id=_PROJECT,
        bucket_name=_BUCKET,
        client_factory=factory,
    )


def _reader(factory: _Factory) -> CloudStorageReadTarget:
    return CloudStorageReadTarget(
        project_id=_PROJECT,
        bucket_name=_BUCKET,
        client_factory=factory,
    )


def _cleanup(factory: _Factory) -> CloudStorageCleanupTarget:
    return CloudStorageCleanupTarget(
        project_id=_PROJECT,
        bucket_name=_BUCKET,
        client_factory=factory,
    )


def _commit(target: CloudStorageMutationTarget) -> None:
    target.commit_object(
        operation_id=_OPERATION,
        bucket=_BUCKET,
        name=_NAME,
        content=_CONTENT,
        correlation=_CORRELATION,
    )


def _calls(bucket: _FakeBucket, operation: str) -> list[tuple[str, dict[str, object]]]:
    return [(name, kwargs) for kind, name, kwargs in bucket.calls if kind == operation]


def test_cloud_profile_is_sealed_and_preserves_local_default() -> None:
    local = build_storage_target(bucket_name=_BUCKET, object_name=_NAME)
    cloud = build_storage_target(
        bucket_name=_BUCKET,
        object_name=_NAME,
        profile=CLOUD_STORAGE_PROFILE,
    )

    assert local.scope["environment"] == "local-sqlite"
    assert cloud.scope["environment"] == "google-cloud-storage"
    assert (
        build_storage_capability(cloud, profile=CLOUD_STORAGE_PROFILE).timeout_ms
        == 5_000
    )
    descriptor = build_storage_rule_descriptor(profile=CLOUD_STORAGE_PROFILE)
    assert descriptor.authority_policy_version == "authority-cloud-storage-v1"
    assert descriptor.source == "google-cloud-storage-json-v1"

    copied = deepcopy(CLOUD_STORAGE_PROFILE)
    with pytest.raises(TypeError, match="profile"):
        build_storage_target(
            bucket_name=_BUCKET,
            object_name=_NAME,
            profile=copied,
        )


def test_configuration_and_inputs_fail_before_lazy_adc() -> None:
    bucket = _FakeBucket()
    factory = _Factory(_FakeClient(bucket))
    target = _mutation(factory)

    assert factory.projects == []
    with pytest.raises(ValueError, match="byte limit"):
        target.commit_object(
            operation_id=_OPERATION,
            bucket=_BUCKET,
            name=_NAME,
            content=b"x" * (CLOUD_STORAGE_OBJECT_BYTE_CEILING + 1),
            correlation=_CORRELATION,
        )
    with pytest.raises(ValueError, match="correlation metadata"):
        target.commit_object(
            operation_id=_OPERATION,
            bucket=_BUCKET,
            name=_NAME,
            content=_CONTENT,
            correlation={"field": "x" * CLOUD_STORAGE_CORRELATION_BYTE_CEILING},
        )
    assert factory.projects == []
    assert bucket.calls == []


def test_create_only_target_and_canonical_receipt_then_exact_read() -> None:
    bucket = _FakeBucket()
    factory = _Factory(_FakeClient(bucket))
    _commit(_mutation(factory))

    receipt_name = cloud_storage_receipt_name(_OPERATION)
    assert list(bucket.records) == [_NAME, receipt_name]
    assert factory.projects == [_PROJECT]
    uploads = _calls(bucket, "upload")
    assert [name for name, _ in uploads] == [_NAME, receipt_name]
    for _, kwargs in uploads:
        assert kwargs["if_generation_match"] == 0
        assert kwargs["retry"] is None
        assert kwargs["timeout"] == CLOUD_STORAGE_TIMEOUT_SECONDS
        assert kwargs["checksum"] == "crc32c"

    receipt_payload = bucket.records[receipt_name].content
    assert (
        json.dumps(
            json.loads(receipt_payload),
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode()
        == receipt_payload
    )
    receipt_document = json.loads(receipt_payload)
    assert receipt_document["schema_version"] == CLOUD_STORAGE_RECEIPT_VERSION
    assert receipt_document["generation"] == 1

    bucket.calls.clear()
    readback = _reader(_Factory(_FakeClient(bucket))).read(
        bucket=_BUCKET,
        name=_NAME,
        operation_id=_OPERATION,
    )
    assert readback.object_metadata is not None
    assert readback.receipt is not None
    assert readback.object_metadata.generation == 1
    assert (
        readback.object_metadata.content_sha256 == hashlib.sha256(_CONTENT).hexdigest()
    )
    assert readback.object_metadata.correlation == _CORRELATION
    assert readback.receipt.generation == 1

    reloads = _calls(bucket, "reload")
    downloads = _calls(bucket, "download")
    assert [name for name, _ in reloads] == [receipt_name, _NAME]
    assert [name for name, _ in downloads] == [receipt_name, _NAME]
    for _, kwargs in reloads:
        assert kwargs == {
            "projection": "noAcl",
            "timeout": CLOUD_STORAGE_TIMEOUT_SECONDS,
            "retry": None,
        }
    assert downloads[0][1]["if_generation_match"] == 2
    assert downloads[1][1]["if_generation_match"] == 1
    for _, kwargs in downloads:
        assert kwargs["retry"] is None
        assert kwargs["raw_download"] is True
        assert kwargs["single_shot_download"] is True


def test_create_conflict_never_creates_or_replays_receipt() -> None:
    bucket = _FakeBucket()
    factory = _Factory(_FakeClient(bucket))
    target = _mutation(factory)
    _commit(target)
    bucket.calls.clear()

    with pytest.raises(CloudStorageAlreadyExists):
        _commit(target)

    assert [name for name, _ in _calls(bucket, "upload")] == [_NAME]
    assert _calls(bucket, "delete") == []


def test_receipt_failure_leaves_target_and_reports_unknown_without_cleanup() -> None:
    bucket = _FakeBucket()
    receipt_name = cloud_storage_receipt_name(_OPERATION)
    bucket.upload_after[receipt_name] = RuntimeError("private-token-value")

    with pytest.raises(CloudStorageMutationOutcomeUnknown) as raised:
        _commit(_mutation(_Factory(_FakeClient(bucket))))

    assert "private-token-value" not in str(raised.value)
    assert _NAME in bucket.records
    assert receipt_name in bucket.records
    assert len(_calls(bucket, "upload")) == 2
    assert _calls(bucket, "delete") == []


def test_absence_is_only_a_not_found_on_initial_metadata_read() -> None:
    bucket = _FakeBucket()
    result = _reader(_Factory(_FakeClient(bucket))).read(
        bucket=_BUCKET,
        name=_NAME,
        operation_id=_OPERATION,
    )
    assert result == type(result)(object_metadata=None, receipt=None)
    assert len(_calls(bucket, "reload")) == 2
    assert _calls(bucket, "download") == []

    bucket.reload_failures[_NAME] = api_exceptions.ServiceUnavailable(
        "private-token-value"
    )
    bucket.calls.clear()
    with pytest.raises(CloudStorageProviderUnavailable) as raised:
        _reader(_Factory(_FakeClient(bucket))).read(
            bucket=_BUCKET,
            name=_NAME,
            operation_id=_OPERATION,
        )
    assert "private-token-value" not in str(raised.value)
    assert [name for name, _ in _calls(bucket, "reload")] == [
        cloud_storage_receipt_name(_OPERATION),
        _NAME,
    ]


def test_corrupt_or_oversized_generation_never_becomes_absence() -> None:
    bucket = _FakeBucket()
    _commit(_mutation(_Factory(_FakeClient(bucket))))
    bucket.records[_NAME].content = b"changed"
    bucket.calls.clear()

    with pytest.raises(CloudStorageCorruptEvidence) as raised:
        _reader(_Factory(_FakeClient(bucket))).read(
            bucket=_BUCKET,
            name=_NAME,
            operation_id=_OPERATION,
        )
    assert raised.value.__cause__ is None
    assert [name for name, _ in _calls(bucket, "download")] == [
        cloud_storage_receipt_name(_OPERATION),
        _NAME,
    ]

    bucket.records[_NAME].content = b"x" * (CLOUD_STORAGE_OBJECT_BYTE_CEILING + 1)
    bucket.calls.clear()
    with pytest.raises(CloudStorageCorruptEvidence):
        _reader(_Factory(_FakeClient(bucket))).read(
            bucket=_BUCKET,
            name=_NAME,
            operation_id=_OPERATION,
        )
    assert [name for name, _ in _calls(bucket, "download")] == [
        cloud_storage_receipt_name(_OPERATION)
    ]


def test_generation_download_failure_and_cancellation_propagate_without_replay() -> (
    None
):
    bucket = _FakeBucket()
    _commit(_mutation(_Factory(_FakeClient(bucket))))
    bucket.download_failures[_NAME] = api_exceptions.PreconditionFailed(
        "private provider response"
    )
    bucket.calls.clear()
    with pytest.raises(CloudStorageOwnershipChanged):
        _reader(_Factory(_FakeClient(bucket))).read(
            bucket=_BUCKET,
            name=_NAME,
            operation_id=_OPERATION,
        )
    assert [name for name, _ in _calls(bucket, "download")] == [
        cloud_storage_receipt_name(_OPERATION),
        _NAME,
    ]

    bucket.download_failures[_NAME] = asyncio.CancelledError()
    bucket.calls.clear()
    with pytest.raises(asyncio.CancelledError):
        _reader(_Factory(_FakeClient(bucket))).read(
            bucket=_BUCKET,
            name=_NAME,
            operation_id=_OPERATION,
        )
    assert [name for name, _ in _calls(bucket, "download")] == [
        cloud_storage_receipt_name(_OPERATION),
        _NAME,
    ]


def test_cleanup_requires_receipt_and_deletes_exact_target_then_receipt() -> None:
    bucket = _FakeBucket()
    _commit(_mutation(_Factory(_FakeClient(bucket))))
    cleanup = _cleanup(_Factory(_FakeClient(bucket)))
    bucket.calls.clear()

    deletion = cleanup.delete_owned(
        bucket=_BUCKET,
        name=_NAME,
        operation_id=_OPERATION,
    )

    assert deletion.object_removed is True
    assert deletion.receipt_removed is True
    deletes = _calls(bucket, "delete")
    assert [name for name, _ in deletes] == [
        _NAME,
        cloud_storage_receipt_name(_OPERATION),
    ]
    assert deletes[0][1] == {
        "if_generation_match": 1,
        "timeout": CLOUD_STORAGE_TIMEOUT_SECONDS,
        "retry": None,
    }
    assert deletes[1][1] == {
        "if_generation_match": 2,
        "timeout": CLOUD_STORAGE_TIMEOUT_SECONDS,
        "retry": None,
    }


def test_cleanup_without_receipt_never_deletes_target() -> None:
    bucket = _FakeBucket()
    _commit(_mutation(_Factory(_FakeClient(bucket))))
    del bucket.records[cloud_storage_receipt_name(_OPERATION)]
    bucket.calls.clear()

    deletion = _cleanup(_Factory(_FakeClient(bucket))).delete_owned(
        bucket=_BUCKET,
        name=_NAME,
        operation_id=_OPERATION,
    )
    assert deletion.removed_count == 0
    assert _NAME in bucket.records
    assert _calls(bucket, "delete") == []


def test_cleanup_mismatch_or_target_delete_failure_retains_receipt() -> None:
    bucket = _FakeBucket()
    _commit(_mutation(_Factory(_FakeClient(bucket))))
    receipt_name = cloud_storage_receipt_name(_OPERATION)
    receipt_document = json.loads(bucket.records[receipt_name].content)
    receipt_document["object_name"] = "runs/another/object.json"
    bucket.records[receipt_name].content = json.dumps(
        receipt_document,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode()
    bucket.calls.clear()
    with pytest.raises(CloudStorageOwnershipChanged):
        _cleanup(_Factory(_FakeClient(bucket))).delete_owned(
            bucket=_BUCKET,
            name=_NAME,
            operation_id=_OPERATION,
        )
    assert _calls(bucket, "delete") == []

    bucket = _FakeBucket()
    _commit(_mutation(_Factory(_FakeClient(bucket))))
    receipt_name = cloud_storage_receipt_name(_OPERATION)
    bucket.delete_failures[_NAME] = api_exceptions.ServiceUnavailable(
        "private-token-value"
    )
    bucket.calls.clear()
    with pytest.raises(CloudStorageCleanupOutcomeUnknown) as raised:
        _cleanup(_Factory(_FakeClient(bucket))).delete_owned(
            bucket=_BUCKET,
            name=_NAME,
            operation_id=_OPERATION,
        )
    assert "private-token-value" not in str(raised.value)
    assert receipt_name in bucket.records
    assert [name for name, _ in _calls(bucket, "delete")] == [_NAME]


def test_default_adc_transport_disables_storage_and_auth_replay(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from google.auth import default as real_default
    from google.cloud import storage as storage_module

    captured: dict[str, Any] = {}

    class _Client:
        SCOPE = ("scope",)

        def __init__(self, **kwargs: object) -> None:
            captured.update(kwargs)

    credential = object()
    monkeypatch.setattr("google.auth.default", lambda **_: (credential, _PROJECT))
    monkeypatch.setattr(storage_module, "Client", _Client)
    try:
        hosted_storage._default_client_factory(_PROJECT)
    finally:
        monkeypatch.setattr("google.auth.default", real_default)

    session = captured["_http"]
    assert session._max_refresh_attempts == 0
    assert session._refresh_status_codes == ()
    assert session.trust_env is False
    assert session.max_redirects == 0
    assert session.adapters["https://"].max_retries.total == 0
    assert session._auth_request_session.max_redirects == 0
    assert session._auth_request_session.trust_env is False
    assert session._auth_request_session.adapters["https://"].max_retries.total == 0
    session.close()
