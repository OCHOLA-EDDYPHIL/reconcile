from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from google.api_core import exceptions as api_exceptions

from reconcile.hosted.firestore_release import (
    FIRESTORE_RELEASE_RECORD_VERSION,
    FirestoreReleaseConflict,
    FirestoreReleaseRecord,
    GoogleFirestoreReleaseTarget,
    firestore_release_document_path,
)

pytestmark = pytest.mark.unit

NOW = datetime(2026, 8, 22, 12, 0, tzinfo=UTC)


class _WriteResult:
    def __init__(self, update_time: datetime) -> None:
        self.update_time = update_time


class _Snapshot:
    def __init__(self, reference: _Reference) -> None:
        self.reference = reference
        self.exists = reference.data is not None
        self.read_time = NOW + timedelta(seconds=2)
        self.update_time = reference.update_time if self.exists else None

    def to_dict(self):
        return None if self.reference.data is None else dict(self.reference.data)


class _Reference:
    def __init__(self, path: str) -> None:
        self.path = path
        self.data = None
        self.update_time = None
        self.raise_after_create = False

    async def get(self, **_kwargs):
        return _Snapshot(self)

    async def create(self, data, **_kwargs):
        if self.data is not None:
            raise api_exceptions.AlreadyExists("exists")
        self.data = dict(data)
        self.update_time = NOW + timedelta(seconds=1)
        if self.raise_after_create:
            raise RuntimeError("lost acknowledgement")
        return _WriteResult(self.update_time)

    async def delete(self, *, option, **_kwargs):
        if option != self.update_time:
            raise api_exceptions.FailedPrecondition("stale")
        self.data = None
        self.update_time = None
        return _WriteResult(NOW + timedelta(seconds=3))


class _Client:
    def __init__(self) -> None:
        self.references = {}

    def document(self, *segments):
        path = "/".join(segments)
        return self.references.setdefault(path, _Reference(path))

    def write_option(self, **kwargs):
        return kwargs["last_update_time"]


def _record(payload: str = "a" * 64) -> FirestoreReleaseRecord:
    return FirestoreReleaseRecord(
        schema_version=FIRESTORE_RELEASE_RECORD_VERSION,
        release_id="release-7",
        cloud_run_revision="reconcile-canary-r-0123456789abcdef",
        payload_sha256=payload,
        semantic_action_sha256="b" * 64,
        created_at=NOW,
    )


def _target(client: _Client) -> GoogleFirestoreReleaseTarget:
    return GoogleFirestoreReleaseTarget(
        project_id="demo-project",
        client_factory=lambda: client,
        clock=lambda: NOW + timedelta(seconds=2),
    )


def test_release_record_is_create_only_strongly_read_and_exactly_reset() -> None:
    client = _Client()
    target = _target(client)

    async def exercise():
        created = await target.create(_record())
        read = await target.read("release-7")
        deleted = await target.reset(release_id="release-7", payload_sha256="a" * 64)
        absent = await target.read("release-7")
        return created, read, deleted, absent

    created, read, deleted, absent = __import__("asyncio").run(exercise())
    assert created == read
    assert created.document_path == firestore_release_document_path("release-7")
    assert deleted is True
    assert absent is None


def test_release_create_conflict_and_reset_ownership_mismatch_fail_closed() -> None:
    client = _Client()
    target = _target(client)

    async def exercise():
        await target.create(_record())
        with pytest.raises(FirestoreReleaseConflict):
            await target.create(_record())
        with pytest.raises(FirestoreReleaseConflict):
            await target.reset(
                release_id="release-7",
                payload_sha256="c" * 64,
            )

    __import__("asyncio").run(exercise())


def test_lost_create_acknowledgement_is_resolved_by_exact_readback() -> None:
    client = _Client()
    reference = client.document(
        *firestore_release_document_path("release-7").split("/")
    )
    reference.raise_after_create = True
    target = _target(client)

    created = __import__("asyncio").run(target.create(_record()))

    assert created.record == _record()
