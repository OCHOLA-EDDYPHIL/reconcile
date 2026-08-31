"""Bounded compare-and-swap documents in the hosted Firestore runtime database."""

from __future__ import annotations

import asyncio
import hashlib
import json
import re
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any, Literal, Protocol
from uuid import uuid4

from google.api_core import exceptions as api_exceptions
from pydantic import Field, ValidationError, model_validator

from reconcile.contracts.base import (
    Identifier,
    Sha256Digest,
    StrictModel,
    canonical_json_value_bytes,
)

FIRESTORE_CAS_DOCUMENT_VERSION = "reconcile/firestore-cas-document/v1"
FIRESTORE_RUNTIME_DATABASE = "reconcile-p5-runtime"
FIRESTORE_CAS_PAYLOAD_BYTE_CEILING = 900_000
FIRESTORE_CAS_TIMEOUT_SECONDS = 5.0
FIRESTORE_CAS_AMBIGUOUS_READ_CONCURRENCY = 32

_PROJECT_PATTERN = re.compile(r"[a-z][a-z0-9-]{4,28}[a-z0-9]")
_DOCUMENT_KEY_PATTERN = re.compile(r"[0-9a-f]{64}")
_WRAPPER_FIELDS = frozenset(
    {
        "schema_version",
        "kind",
        "logical_id",
        "revision",
        "mutation_id",
        "canonical_payload",
        "payload_sha256",
    }
)
_RECOVERY_MIGRATION_SOURCE_VERSIONS = frozenset(
    {
        "reconcile/firestore-recovery-state/v1",
        "reconcile/recovery-run-aggregate/v1",
    }
)
_RECOVERY_MIGRATION_TARGET_VERSION = "reconcile/firestore-recovery-state/v2"


class FirestoreCasCollection(StrEnum):
    """Closed runtime-database collections used by hosted state authorities."""

    RUNTIME = "reconcile-p5-runtime-v1"
    SCENARIO = "reconcile-p5-scenario-v1"
    SCENARIO_INDEX = "reconcile-p5-scenario-index-v1"
    PROVIDER_CANDIDATE = "reconcile-p5-provider-candidates-v1"
    ACTION_PERMIT = "reconcile-action-permits-v1"
    RECOVERY_RUN = "reconcile-recovery-runs-v1"
    RECOVERY_RUN_EVENT = "reconcile-recovery-run-events-v1"
    OPERATIONAL_EVENT = "reconcile-operational-events-v1"


class FirestoreCasErrorCode(StrEnum):
    CONFLICT = "conflict"
    CORRUPT_DOCUMENT = "corrupt-document"
    OUTCOME_UNKNOWN = "outcome-unknown"
    PROVIDER_UNAVAILABLE = "provider-unavailable"


class FirestoreCasError(RuntimeError):
    """Sanitized Firestore CAS failure without provider response material."""

    def __init__(self, code: FirestoreCasErrorCode) -> None:
        if type(code) is not FirestoreCasErrorCode:
            raise TypeError("a Firestore CAS error code is required")
        self.code = code
        super().__init__(f"hosted firestore cas {code.value}")


class FirestoreCasConflict(FirestoreCasError):
    def __init__(self) -> None:
        super().__init__(FirestoreCasErrorCode.CONFLICT)


class FirestoreCasCorruptDocument(FirestoreCasError):
    def __init__(self) -> None:
        super().__init__(FirestoreCasErrorCode.CORRUPT_DOCUMENT)


class FirestoreCasOutcomeUnknown(FirestoreCasError):
    def __init__(self) -> None:
        super().__init__(FirestoreCasErrorCode.OUTCOME_UNKNOWN)


class FirestoreCasProviderUnavailable(FirestoreCasError):
    def __init__(self) -> None:
        super().__init__(FirestoreCasErrorCode.PROVIDER_UNAVAILABLE)


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("canonical payload contains a duplicate key")
        result[key] = value
    return result


def _canonical_payload_text(value: bytes | str) -> str:
    if type(value) is bytes:
        try:
            text = value.decode("utf-8")
        except UnicodeDecodeError as error:
            raise ValueError("canonical payload is not UTF-8") from error
    elif type(value) is str:
        text = value
    else:
        raise TypeError("canonical payload must be exact bytes or text")
    encoded = text.encode("utf-8")
    if not encoded or len(encoded) > FIRESTORE_CAS_PAYLOAD_BYTE_CEILING:
        raise ValueError("canonical payload is outside its byte bounds")
    try:
        decoded = json.loads(
            text,
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=lambda _value: (_ for _ in ()).throw(
                ValueError("canonical payload contains a non-finite number")
            ),
        )
        if not isinstance(decoded, dict):
            raise ValueError("canonical payload must be a JSON object")
        canonical = canonical_json_value_bytes(decoded)
    except (RecursionError, TypeError, ValueError, json.JSONDecodeError) as error:
        raise ValueError("canonical payload is invalid") from error
    if canonical != encoded:
        raise ValueError("canonical payload is not in canonical form")
    return text


def _canonical_payload_schema_version(document: FirestoreCasDocument) -> str:
    try:
        payload = json.loads(document.canonical_payload)
        version = payload["schema_version"]
    except (KeyError, TypeError, ValueError, json.JSONDecodeError) as error:
        raise ValueError(
            "Firestore CAS payload schema version is unavailable"
        ) from error
    if type(version) is not str:
        raise ValueError("Firestore CAS payload schema version is invalid")
    return version


class FirestoreCasDocument(StrictModel):
    """One canonical logical state revision stored in a fixed Firestore wrapper."""

    schema_version: Literal[FIRESTORE_CAS_DOCUMENT_VERSION]
    kind: FirestoreCasCollection
    logical_id: Identifier
    revision: int = Field(ge=0, le=2**63 - 1)
    mutation_id: Identifier
    canonical_payload: str
    payload_sha256: Sha256Digest

    @model_validator(mode="after")
    def validate_payload(self) -> FirestoreCasDocument:
        canonical = _canonical_payload_text(self.canonical_payload)
        if hashlib.sha256(canonical.encode("utf-8")).hexdigest() != self.payload_sha256:
            raise ValueError("canonical payload digest does not match")
        return self

    @property
    def payload_bytes(self) -> bytes:
        return self.canonical_payload.encode("utf-8")


class _LogicalIdentity(StrictModel):
    value: Identifier


def _collection(value: object) -> FirestoreCasCollection:
    if type(value) is not FirestoreCasCollection:
        raise TypeError("Firestore CAS collection must be exact")
    return value


def _logical_id(value: object) -> str:
    try:
        return _LogicalIdentity(value=value).value
    except (TypeError, ValueError, ValidationError) as error:
        raise ValueError("Firestore CAS logical identifier is invalid") from error


def new_firestore_cas_mutation_id() -> str:
    """Return a fresh bounded identifier used to disambiguate one write attempt."""

    return f"mutation-{uuid4().hex}"


def firestore_cas_document_key(
    collection: FirestoreCasCollection,
    logical_id: str,
) -> str:
    """Derive the exact fixed-size document key for one collection identity."""

    selected = _collection(collection)
    identity = _logical_id(logical_id)
    material = f"{selected.value}\0{identity}".encode()
    return hashlib.sha256(material).hexdigest()


def firestore_cas_document_path(
    collection: FirestoreCasCollection,
    logical_id: str,
) -> str:
    """Return the exact two-segment Firestore path for one logical document."""

    selected = _collection(collection)
    return f"{selected.value}/{firestore_cas_document_key(selected, logical_id)}"


def build_firestore_cas_document(
    *,
    collection: FirestoreCasCollection,
    logical_id: str,
    revision: int,
    mutation_id: str,
    canonical_payload: bytes | str,
) -> FirestoreCasDocument:
    """Build a validated fixed wrapper around one canonical JSON object."""

    selected = _collection(collection)
    identity = _logical_id(logical_id)
    payload = _canonical_payload_text(canonical_payload)
    return FirestoreCasDocument(
        schema_version=FIRESTORE_CAS_DOCUMENT_VERSION,
        kind=selected,
        logical_id=identity,
        revision=revision,
        mutation_id=mutation_id,
        canonical_payload=payload,
        payload_sha256=hashlib.sha256(payload.encode("utf-8")).hexdigest(),
    )


@dataclass(frozen=True, slots=True)
class FirestoreCasSnapshot:
    """A validated logical document and its opaque provider update precondition."""

    collection: FirestoreCasCollection
    document_key: str
    document: FirestoreCasDocument
    update_time: datetime

    def __post_init__(self) -> None:
        collection = _collection(self.collection)
        if type(self.document) is not FirestoreCasDocument:
            raise TypeError("Firestore CAS snapshot document must be exact")
        expected_key = firestore_cas_document_key(
            collection,
            self.document.logical_id,
        )
        if (
            self.document.kind is not collection
            or type(self.document_key) is not str
            or _DOCUMENT_KEY_PATTERN.fullmatch(self.document_key) is None
            or self.document_key != expected_key
        ):
            raise ValueError("Firestore CAS snapshot target is invalid")
        object.__setattr__(self, "update_time", _aware_utc(self.update_time))


class _DocumentReferencePort(Protocol):
    path: str

    async def get(
        self,
        field_paths: object | None = None,
        transaction: object | None = None,
        retry: object | None = None,
        timeout: float | None = None,
        *,
        read_time: datetime | None = None,
    ) -> object: ...


class _WriteBatchPort(Protocol):
    def create(
        self,
        reference: _DocumentReferencePort,
        document_data: dict[str, Any],
    ) -> None: ...

    def update(
        self,
        reference: _DocumentReferencePort,
        field_updates: dict[str, Any],
        option: object | None = None,
    ) -> None: ...

    async def commit(
        self,
        retry: object | None = None,
        timeout: float | None = None,
    ) -> list[object]: ...


class AsyncFirestoreCasClientPort(Protocol):
    """Narrow public SDK surface used by the runtime-database CAS boundary."""

    def document(self, *document_path: str) -> _DocumentReferencePort: ...

    def batch(self) -> _WriteBatchPort: ...

    def write_option(self, **kwargs: object) -> object: ...


type FirestoreCasClientFactory = Callable[[], AsyncFirestoreCasClientPort]


def _default_client_factory(project_id: str) -> FirestoreCasClientFactory:
    def create() -> AsyncFirestoreCasClientPort:
        from google.cloud import firestore_v1

        return firestore_v1.AsyncClient(
            project=project_id,
            database=FIRESTORE_RUNTIME_DATABASE,
        )

    return create


def _aware_utc(value: object) -> datetime:
    if not isinstance(value, datetime) or value.tzinfo is None:
        raise ValueError("provider timestamp is invalid")
    if value.utcoffset() is None:
        raise ValueError("provider timestamp is invalid")
    return value.astimezone(UTC)


def _document_data(document: FirestoreCasDocument) -> dict[str, Any]:
    data = document.model_dump(mode="json")
    if set(data) != _WRAPPER_FIELDS:
        raise FirestoreCasCorruptDocument
    return data


def _documents_equal(
    left: FirestoreCasDocument,
    right: FirestoreCasDocument,
) -> bool:
    return left == right and left.mutation_id == right.mutation_id


_KNOWN_CONTENTION = (
    api_exceptions.Aborted,
    api_exceptions.AlreadyExists,
    api_exceptions.Conflict,
    api_exceptions.FailedPrecondition,
    api_exceptions.NotFound,
)


class _AmbiguousWrite(RuntimeError):
    pass


class GoogleFirestoreCasStore:
    """Single-document CAS operations sealed to the hosted runtime database."""

    def __init__(
        self,
        *,
        project_id: str,
        database_id: str = FIRESTORE_RUNTIME_DATABASE,
        client_factory: FirestoreCasClientFactory | None = None,
    ) -> None:
        if (
            type(project_id) is not str
            or _PROJECT_PATTERN.fullmatch(project_id) is None
        ):
            raise ValueError("Firestore CAS project identifier is invalid")
        if database_id != FIRESTORE_RUNTIME_DATABASE:
            raise ValueError("Firestore CAS runtime database is not approved")
        if client_factory is not None and not callable(client_factory):
            raise TypeError("Firestore CAS client factory must be callable")
        self._project_id = project_id
        self._database_id = database_id
        self._client_factory = client_factory or _default_client_factory(project_id)
        self._client_instance: AsyncFirestoreCasClientPort | None = None
        self._client_lock = asyncio.Lock()

    @property
    def database_id(self) -> str:
        return self._database_id

    async def _client(self) -> AsyncFirestoreCasClientPort:
        if self._client_instance is not None:
            return self._client_instance
        async with self._client_lock:
            if self._client_instance is None:
                try:
                    client = self._client_factory()
                except Exception:
                    raise FirestoreCasProviderUnavailable from None
                if any(
                    not callable(getattr(client, name, None))
                    for name in ("batch", "document", "write_option")
                ):
                    raise FirestoreCasProviderUnavailable
                self._client_instance = client
            return self._client_instance

    @staticmethod
    def _reference(
        client: AsyncFirestoreCasClientPort,
        collection: FirestoreCasCollection,
        logical_id: str,
    ) -> _DocumentReferencePort:
        expected_path = firestore_cas_document_path(collection, logical_id)
        document_key = expected_path.rsplit("/", 1)[1]
        try:
            reference = client.document(collection.value, document_key)
            path = reference.path
        except Exception:
            raise FirestoreCasProviderUnavailable from None
        if path != expected_path:
            raise FirestoreCasCorruptDocument
        return reference

    @staticmethod
    def _decode_snapshot(
        snapshot: object,
        *,
        collection: FirestoreCasCollection,
        logical_id: str,
        expected_path: str,
    ) -> FirestoreCasSnapshot | None:
        try:
            reference = snapshot.reference
            if reference.path != expected_path:
                raise ValueError("provider reference path does not match")
            exists = snapshot.exists
            if type(exists) is not bool:
                raise ValueError("provider existence flag is invalid")
            _aware_utc(snapshot.read_time)
            data = snapshot.to_dict()
            update_time = snapshot.update_time
            if not exists:
                if data is not None or update_time is not None:
                    raise ValueError("missing provider document is malformed")
                return None
            if not isinstance(data, dict) or set(data) != _WRAPPER_FIELDS:
                raise ValueError("provider document wrapper is not exact")
            if data.get("kind") != collection.value:
                raise ValueError("provider document kind does not match")
            normalized = dict(data)
            normalized["kind"] = collection
            document = FirestoreCasDocument.model_validate(normalized)
            if document.logical_id != logical_id:
                raise ValueError("provider document identity does not match")
            document_key = expected_path.rsplit("/", 1)[1]
            return FirestoreCasSnapshot(
                collection=collection,
                document_key=document_key,
                document=document,
                update_time=_aware_utc(update_time),
            )
        except FirestoreCasError:
            raise
        except Exception:
            raise FirestoreCasCorruptDocument from None

    async def read(
        self,
        collection: FirestoreCasCollection,
        logical_id: str,
    ) -> FirestoreCasSnapshot | None:
        """Strongly read and validate one exact logical document."""

        selected = _collection(collection)
        identity = _logical_id(logical_id)
        client = await self._client()
        reference = self._reference(client, selected, identity)
        try:
            async with asyncio.timeout(FIRESTORE_CAS_TIMEOUT_SECONDS):
                snapshot = await reference.get(
                    field_paths=None,
                    transaction=None,
                    retry=None,
                    timeout=FIRESTORE_CAS_TIMEOUT_SECONDS,
                    read_time=None,
                )
        except asyncio.CancelledError:
            raise
        except Exception:
            raise FirestoreCasProviderUnavailable from None
        return self._decode_snapshot(
            snapshot,
            collection=selected,
            logical_id=identity,
            expected_path=reference.path,
        )

    @staticmethod
    def _new_batch(client: AsyncFirestoreCasClientPort) -> _WriteBatchPort:
        try:
            batch = client.batch()
        except Exception:
            raise FirestoreCasProviderUnavailable from None
        if any(
            not callable(getattr(batch, name, None))
            for name in ("commit", "create", "update")
        ):
            raise FirestoreCasProviderUnavailable
        return batch

    @staticmethod
    async def _commit(
        batch: _WriteBatchPort,
        *,
        expected_writes: int = 1,
    ) -> tuple[datetime, ...]:
        if type(expected_writes) is not int or not 1 <= expected_writes <= 500:
            raise ValueError("Firestore CAS commit size is invalid")
        try:
            async with asyncio.timeout(FIRESTORE_CAS_TIMEOUT_SECONDS):
                results = await batch.commit(
                    retry=None,
                    timeout=FIRESTORE_CAS_TIMEOUT_SECONDS,
                )
        except asyncio.CancelledError:
            raise
        except _KNOWN_CONTENTION:
            raise FirestoreCasConflict from None
        except Exception:
            raise _AmbiguousWrite from None
        try:
            if type(results) is not list or len(results) != expected_writes:
                raise ValueError("provider write response is malformed")
            return tuple(_aware_utc(item.update_time) for item in results)
        except Exception:
            raise _AmbiguousWrite from None

    async def _resolve_ambiguous(
        self,
        document: FirestoreCasDocument,
    ) -> FirestoreCasSnapshot:
        try:
            current = await self.read(document.kind, document.logical_id)
        except asyncio.CancelledError:
            raise
        except Exception:
            raise FirestoreCasOutcomeUnknown from None
        if current is not None and _documents_equal(current.document, document):
            return current
        raise FirestoreCasOutcomeUnknown

    async def _resolve_ambiguous_pair(
        self,
        first: FirestoreCasDocument,
        second: FirestoreCasDocument,
    ) -> tuple[FirestoreCasSnapshot, FirestoreCasSnapshot]:
        try:
            first_current = await self.read(first.kind, first.logical_id)
            second_current = await self.read(second.kind, second.logical_id)
        except asyncio.CancelledError:
            raise
        except Exception:
            raise FirestoreCasOutcomeUnknown from None
        if (
            first_current is not None
            and second_current is not None
            and _documents_equal(first_current.document, first)
            and _documents_equal(second_current.document, second)
        ):
            return first_current, second_current
        raise FirestoreCasOutcomeUnknown

    async def _resolve_ambiguous_many(
        self,
        documents: tuple[FirestoreCasDocument, ...],
    ) -> tuple[FirestoreCasSnapshot, ...]:
        current: list[FirestoreCasSnapshot | None] = []
        try:
            for start in range(
                0,
                len(documents),
                FIRESTORE_CAS_AMBIGUOUS_READ_CONCURRENCY,
            ):
                selected = documents[
                    start : start + FIRESTORE_CAS_AMBIGUOUS_READ_CONCURRENCY
                ]
                current.extend(
                    await asyncio.gather(
                        *(
                            self.read(document.kind, document.logical_id)
                            for document in selected
                        )
                    )
                )
        except asyncio.CancelledError:
            raise
        except Exception:
            raise FirestoreCasOutcomeUnknown from None
        if all(
            snapshot is not None and _documents_equal(snapshot.document, document)
            for snapshot, document in zip(current, documents, strict=True)
        ):
            return tuple(snapshot for snapshot in current if snapshot is not None)
        raise FirestoreCasOutcomeUnknown

    async def create(
        self,
        document: FirestoreCasDocument,
    ) -> FirestoreCasSnapshot:
        """Create one absent wrapper or conservatively resolve an ambiguous commit."""

        if type(document) is not FirestoreCasDocument:
            raise TypeError("Firestore CAS create document must be exact")
        client = await self._client()
        reference = self._reference(client, document.kind, document.logical_id)
        batch = self._new_batch(client)
        try:
            batch.create(reference, _document_data(document))
        except Exception:
            raise FirestoreCasProviderUnavailable from None
        try:
            (update_time,) = await self._commit(batch)
        except _AmbiguousWrite:
            return await self._resolve_ambiguous(document)
        return FirestoreCasSnapshot(
            collection=document.kind,
            document_key=reference.path.rsplit("/", 1)[1],
            document=document,
            update_time=update_time,
        )

    async def create_pair(
        self,
        first: FirestoreCasDocument,
        second: FirestoreCasDocument,
    ) -> tuple[FirestoreCasSnapshot, FirestoreCasSnapshot]:
        """Atomically create two distinct absent wrappers without replay."""

        created = await self.create_many((first, second))
        return created[0], created[1]

    async def create_many(
        self,
        documents: tuple[FirestoreCasDocument, ...],
    ) -> tuple[FirestoreCasSnapshot, ...]:
        """Atomically create a bounded set of distinct absent wrappers."""

        if (
            type(documents) is not tuple
            or not 1 <= len(documents) <= 500
            or any(type(document) is not FirestoreCasDocument for document in documents)
        ):
            raise TypeError("Firestore CAS create documents must be an exact tuple")
        paths = tuple(
            firestore_cas_document_path(document.kind, document.logical_id)
            for document in documents
        )
        mutation_ids = tuple(document.mutation_id for document in documents)
        if len(set(paths)) != len(paths) or len(set(mutation_ids)) != len(mutation_ids):
            raise ValueError("Firestore CAS create identities must be distinct")
        client = await self._client()
        references = tuple(
            self._reference(client, document.kind, document.logical_id)
            for document in documents
        )
        batch = self._new_batch(client)
        try:
            for reference, document in zip(references, documents, strict=True):
                batch.create(reference, _document_data(document))
        except Exception:
            raise FirestoreCasProviderUnavailable from None
        try:
            update_times = await self._commit(
                batch,
                expected_writes=len(documents),
            )
        except _AmbiguousWrite:
            return await self._resolve_ambiguous_many(documents)
        return tuple(
            FirestoreCasSnapshot(
                collection=document.kind,
                document_key=reference.path.rsplit("/", 1)[1],
                document=document,
                update_time=update_time,
            )
            for reference, document, update_time in zip(
                references,
                documents,
                update_times,
                strict=True,
            )
        )

    async def update_and_create_many(
        self,
        current: FirestoreCasSnapshot,
        replacement: FirestoreCasDocument,
        created: tuple[FirestoreCasDocument, ...],
    ) -> tuple[FirestoreCasSnapshot, ...]:
        """Atomically advance one CAS target and create immutable companions."""

        if type(current) is not FirestoreCasSnapshot:
            raise TypeError("Firestore CAS current snapshot must be exact")
        if type(replacement) is not FirestoreCasDocument:
            raise TypeError("Firestore CAS replacement document must be exact")
        if (
            type(created) is not tuple
            or not 1 <= len(created) <= 499
            or any(type(document) is not FirestoreCasDocument for document in created)
        ):
            raise TypeError("Firestore CAS companion documents must be an exact tuple")
        if (
            replacement.kind is not current.collection
            or replacement.logical_id != current.document.logical_id
            or replacement.revision != current.document.revision + 1
            or replacement.mutation_id == current.document.mutation_id
        ):
            raise ValueError("Firestore CAS replacement does not advance its target")
        documents = (replacement, *created)
        paths = tuple(
            firestore_cas_document_path(document.kind, document.logical_id)
            for document in documents
        )
        mutation_ids = tuple(document.mutation_id for document in documents)
        if len(set(paths)) != len(paths) or len(set(mutation_ids)) != len(mutation_ids):
            raise ValueError("Firestore CAS mutation identities must be distinct")
        client = await self._client()
        references = tuple(
            self._reference(client, document.kind, document.logical_id)
            for document in documents
        )
        batch = self._new_batch(client)
        try:
            option = client.write_option(last_update_time=current.update_time)
            if option is None:
                raise ValueError("provider write option is unavailable")
            batch.update(
                references[0],
                _document_data(replacement),
                option=option,
            )
            for reference, document in zip(
                references[1:],
                created,
                strict=True,
            ):
                batch.create(reference, _document_data(document))
        except Exception:
            raise FirestoreCasProviderUnavailable from None
        try:
            update_times = await self._commit(
                batch,
                expected_writes=len(documents),
            )
        except _AmbiguousWrite:
            return await self._resolve_ambiguous_many(documents)
        return tuple(
            FirestoreCasSnapshot(
                collection=document.kind,
                document_key=reference.path.rsplit("/", 1)[1],
                document=document,
                update_time=update_time,
            )
            for reference, document, update_time in zip(
                references,
                documents,
                update_times,
                strict=True,
            )
        )

    async def rewrite_recovery_run(
        self,
        current: FirestoreCasSnapshot,
        replacement: FirestoreCasDocument,
    ) -> FirestoreCasSnapshot:
        """Rewrite one recovery payload without advancing its logical revision."""

        if type(current) is not FirestoreCasSnapshot:
            raise TypeError("Firestore CAS current snapshot must be exact")
        if type(replacement) is not FirestoreCasDocument:
            raise TypeError("Firestore CAS replacement document must be exact")
        if (
            current.collection is not FirestoreCasCollection.RECOVERY_RUN
            or replacement.kind is not current.collection
            or replacement.logical_id != current.document.logical_id
            or replacement.revision != current.document.revision
            or replacement.mutation_id == current.document.mutation_id
        ):
            raise ValueError("Firestore recovery rewrite changed its logical identity")
        source_version = _canonical_payload_schema_version(current.document)
        target_version = _canonical_payload_schema_version(replacement)
        if (
            source_version not in _RECOVERY_MIGRATION_SOURCE_VERSIONS
            or target_version != _RECOVERY_MIGRATION_TARGET_VERSION
        ):
            raise ValueError("Firestore recovery rewrite is not a supported migration")
        client = await self._client()
        reference = self._reference(
            client,
            replacement.kind,
            replacement.logical_id,
        )
        batch = self._new_batch(client)
        try:
            option = client.write_option(last_update_time=current.update_time)
            if option is None:
                raise ValueError("provider write option is unavailable")
            batch.update(
                reference,
                _document_data(replacement),
                option=option,
            )
        except Exception:
            raise FirestoreCasProviderUnavailable from None
        try:
            (update_time,) = await self._commit(batch)
        except _AmbiguousWrite:
            return await self._resolve_ambiguous(replacement)
        return FirestoreCasSnapshot(
            collection=replacement.kind,
            document_key=reference.path.rsplit("/", 1)[1],
            document=replacement,
            update_time=update_time,
        )

    async def update(
        self,
        current: FirestoreCasSnapshot,
        replacement: FirestoreCasDocument,
    ) -> FirestoreCasSnapshot:
        """Replace one exact revision under its provider update-time precondition."""

        if type(current) is not FirestoreCasSnapshot:
            raise TypeError("Firestore CAS current snapshot must be exact")
        if type(replacement) is not FirestoreCasDocument:
            raise TypeError("Firestore CAS replacement document must be exact")
        if (
            replacement.kind is not current.collection
            or replacement.logical_id != current.document.logical_id
            or replacement.revision != current.document.revision + 1
            or replacement.mutation_id == current.document.mutation_id
        ):
            raise ValueError("Firestore CAS replacement does not advance its target")
        client = await self._client()
        reference = self._reference(
            client,
            replacement.kind,
            replacement.logical_id,
        )
        batch = self._new_batch(client)
        try:
            option = client.write_option(last_update_time=current.update_time)
            if option is None:
                raise ValueError("provider write option is unavailable")
            batch.update(
                reference,
                _document_data(replacement),
                option=option,
            )
        except Exception:
            raise FirestoreCasProviderUnavailable from None
        try:
            (update_time,) = await self._commit(batch)
        except _AmbiguousWrite:
            return await self._resolve_ambiguous(replacement)
        return FirestoreCasSnapshot(
            collection=replacement.kind,
            document_key=reference.path.rsplit("/", 1)[1],
            document=replacement,
            update_time=update_time,
        )


__all__ = [
    "FIRESTORE_CAS_AMBIGUOUS_READ_CONCURRENCY",
    "FIRESTORE_CAS_DOCUMENT_VERSION",
    "FIRESTORE_CAS_PAYLOAD_BYTE_CEILING",
    "FIRESTORE_CAS_TIMEOUT_SECONDS",
    "FIRESTORE_RUNTIME_DATABASE",
    "AsyncFirestoreCasClientPort",
    "FirestoreCasClientFactory",
    "FirestoreCasCollection",
    "FirestoreCasConflict",
    "FirestoreCasCorruptDocument",
    "FirestoreCasDocument",
    "FirestoreCasError",
    "FirestoreCasErrorCode",
    "FirestoreCasOutcomeUnknown",
    "FirestoreCasProviderUnavailable",
    "FirestoreCasSnapshot",
    "GoogleFirestoreCasStore",
    "build_firestore_cas_document",
    "firestore_cas_document_key",
    "firestore_cas_document_path",
    "new_firestore_cas_mutation_id",
]
