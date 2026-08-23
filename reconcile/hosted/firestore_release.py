"""Exact create/read/reset boundary for one release-keyed Firestore record."""

from __future__ import annotations

import asyncio
import re
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any, Literal, Protocol

from google.api_core import exceptions as api_exceptions

from reconcile.contracts.base import (
    AwareDatetime,
    Identifier,
    Sha256Digest,
    StrictModel,
)

FIRESTORE_RELEASE_RECORD_VERSION = "reconcile/firestore-release-record/v1"
FIRESTORE_RELEASE_COLLECTION = "releases"
FIRESTORE_RELEASE_DATABASE = "reconcile-p5-target"
FIRESTORE_RELEASE_TIMEOUT_SECONDS = 5.0

_PROJECT = re.compile(r"[a-z][a-z0-9-]{4,28}[a-z0-9]")
_IDENTIFIER = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}")


class FirestoreReleaseErrorCode(StrEnum):
    CONFLICT = "conflict"
    CORRUPT_RECORD = "corrupt-record"
    OUTCOME_UNKNOWN = "outcome-unknown"
    PROVIDER_UNAVAILABLE = "provider-unavailable"


class FirestoreReleaseError(RuntimeError):
    def __init__(self, code: FirestoreReleaseErrorCode) -> None:
        self.code = code
        super().__init__(f"firestore release {code.value}")


class FirestoreReleaseConflict(FirestoreReleaseError):
    def __init__(self) -> None:
        super().__init__(FirestoreReleaseErrorCode.CONFLICT)


class FirestoreReleaseCorruptRecord(FirestoreReleaseError):
    def __init__(self) -> None:
        super().__init__(FirestoreReleaseErrorCode.CORRUPT_RECORD)


class FirestoreReleaseOutcomeUnknown(FirestoreReleaseError):
    def __init__(self) -> None:
        super().__init__(FirestoreReleaseErrorCode.OUTCOME_UNKNOWN)


class FirestoreReleaseProviderUnavailable(FirestoreReleaseError):
    def __init__(self) -> None:
        super().__init__(FirestoreReleaseErrorCode.PROVIDER_UNAVAILABLE)


class FirestoreReleaseRecord(StrictModel):
    schema_version: Literal[FIRESTORE_RELEASE_RECORD_VERSION]
    release_id: Identifier
    cloud_run_revision: Identifier
    payload_sha256: Sha256Digest
    semantic_action_sha256: Sha256Digest
    created_at: AwareDatetime


@dataclass(frozen=True, slots=True)
class FirestoreReleaseSnapshot:
    document_path: str
    record: FirestoreReleaseRecord
    update_time: datetime
    observed_at: datetime

    def __post_init__(self) -> None:
        if type(self.record) is not FirestoreReleaseRecord:
            raise TypeError("release snapshot requires an exact record")
        if self.document_path != firestore_release_document_path(
            self.record.release_id
        ):
            raise ValueError("release snapshot document identity changed")
        object.__setattr__(self, "update_time", _aware(self.update_time))
        object.__setattr__(self, "observed_at", _aware(self.observed_at))


class _DocumentReference(Protocol):
    path: str

    async def get(
        self,
        field_paths: object | None = None,
        transaction: object | None = None,
        retry: object | None = None,
        timeout: float | None = None,
    ) -> object: ...

    async def create(
        self,
        document_data: dict[str, Any],
        retry: object | None = None,
        timeout: float | None = None,
    ) -> object: ...

    async def delete(
        self,
        option: object | None = None,
        retry: object | None = None,
        timeout: float | None = None,
    ) -> object: ...


class AsyncFirestoreReleaseClient(Protocol):
    def document(self, *document_path: str) -> _DocumentReference: ...

    def write_option(self, **kwargs: object) -> object: ...


type FirestoreReleaseClientFactory = Callable[[], AsyncFirestoreReleaseClient]


def firestore_release_document_id(release_id: str) -> str:
    if type(release_id) is not str or _IDENTIFIER.fullmatch(release_id) is None:
        raise ValueError("release identity is invalid")
    return release_id


def firestore_release_document_path(release_id: str) -> str:
    return f"{FIRESTORE_RELEASE_COLLECTION}/{firestore_release_document_id(release_id)}"


def _aware(value: object) -> datetime:
    if not isinstance(value, datetime) or value.tzinfo is None:
        raise ValueError("Firestore release timestamp is invalid")
    if value.utcoffset() is None:
        raise ValueError("Firestore release timestamp is invalid")
    return value.astimezone(UTC)


def _default_factory(project_id: str) -> FirestoreReleaseClientFactory:
    def create() -> AsyncFirestoreReleaseClient:
        from google.cloud import firestore_v1

        return firestore_v1.AsyncClient(
            project=project_id,
            database=FIRESTORE_RELEASE_DATABASE,
        )

    return create


class GoogleFirestoreReleaseTarget:
    """Create exactly once, strongly read, and explicitly reset one release record."""

    def __init__(
        self,
        *,
        project_id: str,
        database_id: str = FIRESTORE_RELEASE_DATABASE,
        client_factory: FirestoreReleaseClientFactory | None = None,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        if type(project_id) is not str or _PROJECT.fullmatch(project_id) is None:
            raise ValueError("Firestore release project is invalid")
        if database_id != FIRESTORE_RELEASE_DATABASE:
            raise ValueError("Firestore release database is not the isolated target")
        if client_factory is not None and not callable(client_factory):
            raise TypeError("Firestore release client factory must be callable")
        self.project_id = project_id
        self.database_id = database_id
        self._factory = client_factory or _default_factory(project_id)
        self._clock = clock or (lambda: datetime.now(UTC))
        self._instance: AsyncFirestoreReleaseClient | None = None
        self._lock = asyncio.Lock()

    async def _client(self) -> AsyncFirestoreReleaseClient:
        if self._instance is not None:
            return self._instance
        async with self._lock:
            if self._instance is None:
                try:
                    client = self._factory()
                except Exception:
                    raise FirestoreReleaseProviderUnavailable from None
                if any(
                    not callable(getattr(client, name, None))
                    for name in ("document", "write_option")
                ):
                    raise FirestoreReleaseProviderUnavailable
                self._instance = client
            return self._instance

    @staticmethod
    def _reference(
        client: AsyncFirestoreReleaseClient,
        release_id: str,
    ) -> _DocumentReference:
        expected = firestore_release_document_path(release_id)
        try:
            reference = client.document(*expected.split("/"))
        except Exception:
            raise FirestoreReleaseProviderUnavailable from None
        if getattr(reference, "path", None) != expected:
            raise FirestoreReleaseCorruptRecord
        return reference

    def _observed_at(self) -> datetime:
        try:
            return _aware(self._clock())
        except Exception:
            raise FirestoreReleaseProviderUnavailable from None

    async def read(self, release_id: str) -> FirestoreReleaseSnapshot | None:
        client = await self._client()
        reference = self._reference(client, release_id)
        try:
            async with asyncio.timeout(FIRESTORE_RELEASE_TIMEOUT_SECONDS):
                snapshot = await reference.get(
                    field_paths=None,
                    transaction=None,
                    retry=None,
                    timeout=FIRESTORE_RELEASE_TIMEOUT_SECONDS,
                )
        except asyncio.CancelledError:
            raise
        except Exception:
            raise FirestoreReleaseProviderUnavailable from None
        try:
            if snapshot.reference.path != reference.path:
                raise ValueError
            exists = snapshot.exists
            data = snapshot.to_dict()
            update_time = snapshot.update_time
            if type(exists) is not bool:
                raise ValueError
            if not exists:
                if data is not None or update_time is not None:
                    raise ValueError
                return None
            if not isinstance(data, dict):
                raise ValueError
            record = FirestoreReleaseRecord.model_validate(data)
            if record.release_id != release_id:
                raise ValueError
            return FirestoreReleaseSnapshot(
                document_path=reference.path,
                record=record,
                update_time=_aware(update_time),
                observed_at=self._observed_at(),
            )
        except FirestoreReleaseError:
            raise
        except Exception:
            raise FirestoreReleaseCorruptRecord from None

    async def create(
        self,
        record: FirestoreReleaseRecord,
    ) -> FirestoreReleaseSnapshot:
        if type(record) is not FirestoreReleaseRecord:
            raise TypeError("Firestore release create requires an exact record")
        client = await self._client()
        reference = self._reference(client, record.release_id)
        try:
            async with asyncio.timeout(FIRESTORE_RELEASE_TIMEOUT_SECONDS):
                result = await reference.create(
                    record.model_dump(mode="python"),
                    retry=None,
                    timeout=FIRESTORE_RELEASE_TIMEOUT_SECONDS,
                )
            update_time = _aware(result.update_time)
        except asyncio.CancelledError:
            raise
        except (api_exceptions.AlreadyExists, api_exceptions.Conflict):
            raise FirestoreReleaseConflict from None
        except Exception:
            try:
                current = await self.read(record.release_id)
            except Exception:
                raise FirestoreReleaseOutcomeUnknown from None
            if current is not None and current.record == record:
                return current
            raise FirestoreReleaseOutcomeUnknown from None
        return FirestoreReleaseSnapshot(
            document_path=reference.path,
            record=record,
            update_time=update_time,
            observed_at=self._observed_at(),
        )

    async def reset(
        self,
        *,
        release_id: str,
        cloud_run_revisions: tuple[str, ...],
        payload_sha256: str,
        semantic_action_sha256: str,
    ) -> bool:
        """Delete only the exact owned release record under an update precondition."""

        current = await self.read(release_id)
        if current is None:
            return False
        if (
            type(cloud_run_revisions) is not tuple
            or not cloud_run_revisions
            or len(cloud_run_revisions) != len(set(cloud_run_revisions))
            or current.record.cloud_run_revision not in cloud_run_revisions
            or current.record.payload_sha256 != payload_sha256
            or current.record.semantic_action_sha256 != semantic_action_sha256
        ):
            raise FirestoreReleaseConflict
        client = await self._client()
        reference = self._reference(client, release_id)
        try:
            option = client.write_option(last_update_time=current.update_time)
            if option is None:
                raise ValueError
            async with asyncio.timeout(FIRESTORE_RELEASE_TIMEOUT_SECONDS):
                await reference.delete(
                    option=option,
                    retry=None,
                    timeout=FIRESTORE_RELEASE_TIMEOUT_SECONDS,
                )
        except asyncio.CancelledError:
            raise
        except (
            api_exceptions.Aborted,
            api_exceptions.Conflict,
            api_exceptions.FailedPrecondition,
            api_exceptions.NotFound,
        ):
            raise FirestoreReleaseConflict from None
        except Exception:
            raise FirestoreReleaseOutcomeUnknown from None
        if await self.read(release_id) is not None:
            raise FirestoreReleaseOutcomeUnknown
        return True


__all__ = [
    "FIRESTORE_RELEASE_COLLECTION",
    "FIRESTORE_RELEASE_DATABASE",
    "FIRESTORE_RELEASE_RECORD_VERSION",
    "AsyncFirestoreReleaseClient",
    "FirestoreReleaseClientFactory",
    "FirestoreReleaseConflict",
    "FirestoreReleaseCorruptRecord",
    "FirestoreReleaseError",
    "FirestoreReleaseErrorCode",
    "FirestoreReleaseOutcomeUnknown",
    "FirestoreReleaseProviderUnavailable",
    "FirestoreReleaseRecord",
    "FirestoreReleaseSnapshot",
    "GoogleFirestoreReleaseTarget",
    "firestore_release_document_id",
    "firestore_release_document_path",
]
