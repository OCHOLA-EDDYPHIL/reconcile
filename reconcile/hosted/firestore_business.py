"""Deterministic Cloud Firestore target for the hosted business scenario."""

from __future__ import annotations

import asyncio
import hashlib
import re
from collections.abc import AsyncIterator, Callable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any, Protocol

from pydantic import Field, model_validator

from reconcile.contracts.base import (
    AwareDatetime,
    Identifier,
    NonEmptyText,
    Sha256Digest,
    StrictModel,
    reject_sensitive_keys,
)
from reconcile.scenarios.local_firestore import (
    BusinessDocument,
    BusinessDocumentCoordinate,
    BusinessDocumentWrite,
    BusinessOperationDeletion,
    BusinessOperationManifest,
    BusinessOperationReadback,
    BusinessOperationStatus,
    FirestoreOwnershipError,
    business_correlation_items,
    business_effect_declarations,
    expected_effect_declarations_sha256,
    validate_business_document_coordinates,
    validate_business_operation_input,
)

FIRESTORE_MANIFEST_SCHEMA_VERSION = "reconcile/firestore-business-manifest/v1"
FIRESTORE_EFFECT_SCHEMA_VERSION = "reconcile/firestore-business-effect/v1"
FIRESTORE_TARGET_DATABASE = "reconcile-p5-target"

_ROOT_COLLECTION = "reconcile-business-namespaces"
_DEFAULT_TIMEOUT_SECONDS = 5.0
_MAX_TIMEOUT_SECONDS = 30.0
_MAX_CONTENT_BYTES = 16_384
_SEGMENT = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")


class FirestoreCloudFailure(StrEnum):
    """Stable failure codes that never contain provider response material."""

    ALREADY_EXISTS = "already-exists"
    CREDENTIALS_UNAVAILABLE = "credentials-unavailable"
    DEPENDENCY_UNAVAILABLE = "dependency-unavailable"
    INVALID_REQUEST = "invalid-request"
    MALFORMED_RESPONSE = "malformed-response"
    PRECONDITION_FAILED = "precondition-failed"
    TIMEOUT = "timeout"
    UNAVAILABLE = "unavailable"


class FirestoreCloudError(RuntimeError):
    """Sanitized Cloud Firestore boundary failure."""

    def __init__(self, code: FirestoreCloudFailure) -> None:
        if type(code) is not FirestoreCloudFailure:
            raise TypeError("a Firestore cloud failure code is required")
        self.code = code
        super().__init__(code.value)


class _StoredDeclaration(StrictModel):
    effect_id: Identifier
    collection_name: Identifier
    document_id: Identifier
    content_sha256: Sha256Digest


class _StoredManifest(StrictModel):
    schema_version: str
    namespace_id: Identifier
    operation_id: Identifier
    manifest_collection: Identifier
    manifest_document_id: Identifier
    status: str
    revision: int = Field(ge=1, le=2**63 - 1)
    expected_effect_ids: list[Identifier] = Field(min_length=3, max_length=3)
    expected_effects_sha256: Sha256Digest
    expected_effects: list[_StoredDeclaration] = Field(min_length=3, max_length=3)
    established_effect_ids: list[Identifier] = Field(max_length=3)
    not_established_effect_ids: list[Identifier] = Field(max_length=3)
    effect_revisions: dict[Identifier, int] = Field(max_length=3)
    correlation: dict[Identifier, NonEmptyText] = Field(max_length=32)
    observed_at: AwareDatetime

    @model_validator(mode="after")
    def validate_exact_shape(self) -> _StoredManifest:
        if self.schema_version != FIRESTORE_MANIFEST_SCHEMA_VERSION:
            raise ValueError("stored manifest schema is not supported")
        reject_sensitive_keys(self.correlation)
        return self


class _StoredEffect(StrictModel):
    schema_version: str
    effect_id: Identifier
    collection_name: Identifier
    document_id: Identifier
    operation_id: Identifier
    revision: int = Field(ge=1, le=2**63 - 1)
    content: bytes = Field(max_length=_MAX_CONTENT_BYTES)
    content_sha256: Sha256Digest
    correlation: dict[Identifier, NonEmptyText] = Field(max_length=32)
    observed_at: AwareDatetime

    @model_validator(mode="after")
    def validate_exact_shape(self) -> _StoredEffect:
        if self.schema_version != FIRESTORE_EFFECT_SCHEMA_VERSION:
            raise ValueError("stored effect schema is not supported")
        if hashlib.sha256(self.content).hexdigest() != self.content_sha256:
            raise ValueError("stored effect digest is inconsistent")
        reject_sensitive_keys(self.correlation)
        return self


class _DocumentReferencePort(Protocol):
    path: str


class _DocumentSnapshotPort(Protocol):
    reference: _DocumentReferencePort
    exists: bool
    read_time: object
    update_time: object | None

    def to_dict(self) -> dict[str, Any] | None: ...


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

    def delete(
        self,
        reference: _DocumentReferencePort,
        option: object | None = None,
    ) -> None: ...

    async def commit(
        self,
        retry: object | None = None,
        timeout: float | None = None,
    ) -> list[object]: ...


class AsyncFirestoreClientPort(Protocol):
    """Narrow public SDK surface used by the deterministic connector."""

    def document(self, *document_path: str) -> _DocumentReferencePort: ...

    def batch(self) -> _WriteBatchPort: ...

    def write_option(self, **kwargs: object) -> object: ...

    def get_all(
        self,
        references: list[_DocumentReferencePort],
        field_paths: object | None = None,
        transaction: object | None = None,
        retry: object | None = None,
        timeout: float | None = None,
        *,
        read_time: datetime | None = None,
    ) -> AsyncIterator[_DocumentSnapshotPort]: ...


type FirestoreClientFactory = Callable[[], AsyncFirestoreClientPort]
type ServerTimestampFactory = Callable[[], object]


def _default_client_factory(
    project_id: str,
    database_id: str,
) -> FirestoreClientFactory:
    def create() -> AsyncFirestoreClientPort:
        from google.cloud import firestore_v1

        return firestore_v1.AsyncClient(
            project=project_id,
            database=database_id,
        )

    return create


def _default_server_timestamp() -> object:
    from google.cloud import firestore_v1

    return firestore_v1.SERVER_TIMESTAMP


def _raise_provider_failure(error: Exception) -> None:
    if isinstance(error, FirestoreCloudError):
        raise FirestoreCloudError(error.code) from None
    if isinstance(error, TimeoutError):
        raise FirestoreCloudError(FirestoreCloudFailure.TIMEOUT) from None
    try:
        from google.api_core import exceptions as api_exceptions
        from google.auth import exceptions as auth_exceptions
    except ImportError:
        raise FirestoreCloudError(FirestoreCloudFailure.UNAVAILABLE) from None
    if isinstance(error, auth_exceptions.DefaultCredentialsError):
        code = FirestoreCloudFailure.CREDENTIALS_UNAVAILABLE
    elif isinstance(error, (api_exceptions.AlreadyExists, api_exceptions.Conflict)):
        code = FirestoreCloudFailure.ALREADY_EXISTS
    elif isinstance(
        error,
        (api_exceptions.Aborted, api_exceptions.FailedPrecondition),
    ):
        code = FirestoreCloudFailure.PRECONDITION_FAILED
    elif isinstance(error, api_exceptions.InvalidArgument):
        code = FirestoreCloudFailure.INVALID_REQUEST
    elif isinstance(error, api_exceptions.DeadlineExceeded):
        code = FirestoreCloudFailure.TIMEOUT
    else:
        code = FirestoreCloudFailure.UNAVAILABLE
    raise FirestoreCloudError(code) from None


def _path_segment(value: str, label: str) -> str:
    if type(value) is not str or _SEGMENT.fullmatch(value) is None:
        raise ValueError(f"{label} is not a safe Firestore path segment")
    return value


def _aware_utc(value: object) -> datetime:
    if not isinstance(value, datetime) or value.tzinfo is None:
        raise ValueError("provider timestamp is not timezone-aware")
    if value.utcoffset() is None:
        raise ValueError("provider timestamp is not timezone-aware")
    return value.astimezone(UTC)


@dataclass(frozen=True, slots=True)
class _TargetReferences:
    manifest: _DocumentReferencePort
    effects: tuple[tuple[BusinessDocumentCoordinate, _DocumentReferencePort], ...]


@dataclass(frozen=True, slots=True)
class _CompositeRead:
    references: _TargetReferences
    manifest_snapshot: _DocumentSnapshotPort
    effect_snapshots: tuple[
        tuple[BusinessDocumentCoordinate, _DocumentSnapshotPort], ...
    ]
    readback: BusinessOperationReadback
    declarations: tuple[tuple[str, str, str, str], ...] | None


class _CloudFirestoreBusinessTarget:
    def __init__(
        self,
        *,
        project_id: str,
        database_id: str,
        timeout_seconds: float,
        client_factory: FirestoreClientFactory,
        server_timestamp_factory: ServerTimestampFactory,
    ) -> None:
        self._project_id = _path_segment(project_id, "project identifier")
        if database_id != FIRESTORE_TARGET_DATABASE:
            raise ValueError("hosted Firestore target database is not approved")
        if (
            type(timeout_seconds) not in {int, float}
            or not 0 < timeout_seconds <= _MAX_TIMEOUT_SECONDS
        ):
            raise ValueError("Firestore timeout is outside its fixed bounds")
        if not callable(client_factory) or not callable(server_timestamp_factory):
            raise TypeError("Firestore factories must be callable")
        self._database_id = database_id
        self._timeout_seconds = float(timeout_seconds)
        self._client_factory = client_factory
        self._server_timestamp_factory = server_timestamp_factory
        self._client: AsyncFirestoreClientPort | None = None
        self._server_timestamp: object | None = None
        self._client_lock = asyncio.Lock()

    async def _get_client(self) -> AsyncFirestoreClientPort:
        if self._client is not None:
            return self._client
        async with self._client_lock:
            if self._client is None:
                try:
                    self._client = self._client_factory()
                except ImportError:
                    raise FirestoreCloudError(
                        FirestoreCloudFailure.DEPENDENCY_UNAVAILABLE
                    ) from None
                except Exception as error:
                    _raise_provider_failure(error)
                if any(
                    not callable(getattr(self._client, name, None))
                    for name in ("batch", "document", "get_all", "write_option")
                ):
                    self._client = None
                    raise FirestoreCloudError(FirestoreCloudFailure.UNAVAILABLE)
            return self._client

    @staticmethod
    def _new_batch(client: AsyncFirestoreClientPort) -> _WriteBatchPort:
        try:
            batch = client.batch()
        except Exception as error:
            _raise_provider_failure(error)
        if any(
            not callable(getattr(batch, name, None))
            for name in ("commit", "create", "delete", "update")
        ):
            raise FirestoreCloudError(FirestoreCloudFailure.UNAVAILABLE)
        return batch

    @staticmethod
    def _write_option(
        client: AsyncFirestoreClientPort,
        **kwargs: object,
    ) -> object:
        try:
            return client.write_option(**kwargs)
        except Exception as error:
            _raise_provider_failure(error)

    @staticmethod
    def _reference(
        client: AsyncFirestoreClientPort,
        *segments: str,
    ) -> _DocumentReferencePort:
        expected_path = "/".join(segments)
        try:
            reference = client.document(*segments)
            path = reference.path
        except Exception as error:
            _raise_provider_failure(error)
        if path != expected_path:
            raise FirestoreCloudError(FirestoreCloudFailure.MALFORMED_RESPONSE)
        return reference

    def _timestamp_sentinel(self) -> object:
        if self._server_timestamp is None:
            try:
                self._server_timestamp = self._server_timestamp_factory()
            except ImportError:
                raise FirestoreCloudError(
                    FirestoreCloudFailure.DEPENDENCY_UNAVAILABLE
                ) from None
            except Exception as error:
                _raise_provider_failure(error)
        return self._server_timestamp

    @staticmethod
    def _validate_coordinates(
        *,
        namespace_id: str,
        operation_id: str,
        manifest_collection: str,
        manifest_document_id: str,
        document_coordinates: tuple[BusinessDocumentCoordinate, ...],
    ) -> tuple[BusinessDocumentCoordinate, ...]:
        _path_segment(namespace_id, "namespace identifier")
        _path_segment(operation_id, "operation identifier")
        _path_segment(manifest_collection, "manifest collection")
        _path_segment(manifest_document_id, "manifest document identifier")
        coordinates = validate_business_document_coordinates(document_coordinates)
        for coordinate in coordinates:
            _path_segment(coordinate.effect_id, "effect identifier")
            _path_segment(coordinate.collection_name, "effect collection")
            _path_segment(coordinate.document_id, "effect document identifier")
        return coordinates

    async def _references(
        self,
        *,
        namespace_id: str,
        operation_id: str,
        manifest_collection: str,
        manifest_document_id: str,
        document_coordinates: tuple[BusinessDocumentCoordinate, ...],
    ) -> _TargetReferences:
        coordinates = self._validate_coordinates(
            namespace_id=namespace_id,
            operation_id=operation_id,
            manifest_collection=manifest_collection,
            manifest_document_id=manifest_document_id,
            document_coordinates=document_coordinates,
        )
        client = await self._get_client()
        prefix = (_ROOT_COLLECTION, namespace_id)
        return _TargetReferences(
            manifest=self._reference(
                client,
                *prefix,
                manifest_collection,
                manifest_document_id,
            ),
            effects=tuple(
                (
                    coordinate,
                    self._reference(
                        client,
                        *prefix,
                        coordinate.collection_name,
                        coordinate.document_id,
                    ),
                )
                for coordinate in coordinates
            ),
        )

    async def _commit(
        self,
        batch: _WriteBatchPort,
        *,
        expected_results: int,
    ) -> list[object]:
        try:
            async with asyncio.timeout(self._timeout_seconds):
                results = await batch.commit(
                    retry=None,
                    timeout=self._timeout_seconds,
                )
        except Exception as error:
            _raise_provider_failure(error)
        if type(results) is not list or len(results) != expected_results:
            raise FirestoreCloudError(
                FirestoreCloudFailure.MALFORMED_RESPONSE
            ) from None
        return results

    @staticmethod
    def _write_update_time(result: object) -> object:
        update_time = getattr(result, "update_time", None)
        try:
            _aware_utc(update_time)
        except ValueError:
            raise FirestoreCloudError(
                FirestoreCloudFailure.MALFORMED_RESPONSE
            ) from None
        return update_time

    async def _composite_read(
        self,
        *,
        namespace_id: str,
        operation_id: str,
        manifest_collection: str,
        manifest_document_id: str,
        document_coordinates: tuple[BusinessDocumentCoordinate, ...],
    ) -> _CompositeRead:
        references = await self._references(
            namespace_id=namespace_id,
            operation_id=operation_id,
            manifest_collection=manifest_collection,
            manifest_document_id=manifest_document_id,
            document_coordinates=document_coordinates,
        )
        client = await self._get_client()
        requested = [references.manifest, *(item[1] for item in references.effects)]
        expected = {reference.path: reference for reference in requested}
        snapshots: dict[str, _DocumentSnapshotPort] = {}
        previous_read_time: datetime | None = None
        try:
            async with asyncio.timeout(self._timeout_seconds):
                iterator = client.get_all(
                    requested,
                    retry=None,
                    timeout=self._timeout_seconds,
                )
                async for snapshot in iterator:
                    path = snapshot.reference.path
                    read_time = _aware_utc(snapshot.read_time)
                    if (
                        path not in expected
                        or path in snapshots
                        or (
                            previous_read_time is not None
                            and read_time < previous_read_time
                        )
                    ):
                        raise FirestoreCloudError(
                            FirestoreCloudFailure.MALFORMED_RESPONSE
                        )
                    previous_read_time = read_time
                    snapshots[path] = snapshot
        except FirestoreCloudError:
            raise
        except (TypeError, ValueError, AttributeError):
            raise FirestoreCloudError(
                FirestoreCloudFailure.MALFORMED_RESPONSE
            ) from None
        except Exception as error:
            _raise_provider_failure(error)
        if set(snapshots) != set(expected):
            raise FirestoreCloudError(
                FirestoreCloudFailure.MALFORMED_RESPONSE
            ) from None

        manifest_snapshot = snapshots[references.manifest.path]
        try:
            manifest, declarations = self._manifest_from_snapshot(manifest_snapshot)
            documents: list[BusinessDocument] = []
            effect_snapshots: list[
                tuple[BusinessDocumentCoordinate, _DocumentSnapshotPort]
            ] = []
            for coordinate, reference in references.effects:
                snapshot = snapshots[reference.path]
                effect_snapshots.append((coordinate, snapshot))
                document = self._document_from_snapshot(snapshot)
                if document is not None:
                    documents.append(document)
        except FirestoreCloudError:
            raise
        except Exception:
            raise FirestoreCloudError(
                FirestoreCloudFailure.MALFORMED_RESPONSE
            ) from None
        return _CompositeRead(
            references=references,
            manifest_snapshot=manifest_snapshot,
            effect_snapshots=tuple(effect_snapshots),
            readback=BusinessOperationReadback(
                manifest=manifest,
                documents=tuple(documents),
            ),
            declarations=declarations,
        )

    @staticmethod
    def _manifest_from_snapshot(
        snapshot: _DocumentSnapshotPort,
    ) -> tuple[
        BusinessOperationManifest | None,
        tuple[tuple[str, str, str, str], ...] | None,
    ]:
        if type(snapshot.exists) is not bool:
            raise ValueError("snapshot existence flag is malformed")
        if not snapshot.exists:
            if snapshot.to_dict() is not None or snapshot.update_time is not None:
                raise ValueError("missing manifest snapshot is malformed")
            return None, None
        payload = snapshot.to_dict()
        if not isinstance(payload, dict) or snapshot.update_time is None:
            raise ValueError("manifest snapshot is malformed")
        stored = _StoredManifest.model_validate(payload)
        if stored.observed_at > _aware_utc(snapshot.update_time):
            raise ValueError("manifest timestamp is later than its revision")
        try:
            status = BusinessOperationStatus(stored.status)
        except ValueError as error:
            raise ValueError("stored manifest status is malformed") from error
        declarations = tuple(
            (
                item.effect_id,
                item.collection_name,
                item.document_id,
                item.content_sha256,
            )
            for item in stored.expected_effects
        )
        if (
            tuple(stored.expected_effect_ids) != tuple(item[0] for item in declarations)
            or expected_effect_declarations_sha256(declarations)
            != stored.expected_effects_sha256
            or set(stored.effect_revisions) != set(stored.established_effect_ids)
        ):
            raise ValueError("stored manifest declarations are inconsistent")
        manifest = BusinessOperationManifest(
            namespace_id=stored.namespace_id,
            operation_id=stored.operation_id,
            manifest_collection=stored.manifest_collection,
            manifest_document_id=stored.manifest_document_id,
            status=status,
            revision=stored.revision,
            expected_effect_ids=tuple(stored.expected_effect_ids),
            expected_effects_sha256=stored.expected_effects_sha256,
            established_effect_ids=tuple(stored.established_effect_ids),
            not_established_effect_ids=tuple(stored.not_established_effect_ids),
            effect_revision_items=tuple(
                (effect_id, stored.effect_revisions[effect_id])
                for effect_id in stored.established_effect_ids
            ),
            correlation_items=business_correlation_items(stored.correlation),
            observed_at=stored.observed_at,
        )
        return manifest, declarations

    @staticmethod
    def _document_from_snapshot(
        snapshot: _DocumentSnapshotPort,
    ) -> BusinessDocument | None:
        if type(snapshot.exists) is not bool:
            raise ValueError("snapshot existence flag is malformed")
        if not snapshot.exists:
            if snapshot.to_dict() is not None or snapshot.update_time is not None:
                raise ValueError("missing effect snapshot is malformed")
            return None
        payload = snapshot.to_dict()
        if not isinstance(payload, dict) or snapshot.update_time is None:
            raise ValueError("effect snapshot is malformed")
        stored = _StoredEffect.model_validate(payload)
        if stored.observed_at > _aware_utc(snapshot.update_time):
            raise ValueError("effect timestamp is later than its revision")
        return BusinessDocument(
            effect_id=stored.effect_id,
            collection_name=stored.collection_name,
            document_id=stored.document_id,
            operation_id=stored.operation_id,
            revision=stored.revision,
            content_sha256=stored.content_sha256,
            correlation_items=business_correlation_items(stored.correlation),
            observed_at=stored.observed_at,
        )

    @staticmethod
    def _assert_owned(
        composite: _CompositeRead,
        *,
        namespace_id: str,
        operation_id: str,
        manifest_collection: str,
        manifest_document_id: str,
        document_coordinates: tuple[BusinessDocumentCoordinate, ...],
    ) -> BusinessOperationManifest | None:
        manifest = composite.readback.manifest
        by_coordinate = {
            (document.collection_name, document.document_id): document
            for document in composite.readback.documents
        }
        if manifest is None:
            if by_coordinate:
                raise FirestoreOwnershipError(
                    "documents remain without an ownership manifest"
                )
            return None
        declarations = composite.declarations
        if declarations is None:
            raise FirestoreOwnershipError("operation declarations are unavailable")
        declared_coordinates = tuple(
            BusinessDocumentCoordinate(
                effect_id=effect_id,
                collection_name=collection_name,
                document_id=document_id,
            )
            for effect_id, collection_name, document_id, _ in declarations
        )
        if (
            manifest.namespace_id != namespace_id
            or manifest.operation_id != operation_id
            or manifest.manifest_collection != manifest_collection
            or manifest.manifest_document_id != manifest_document_id
            or declared_coordinates != document_coordinates
        ):
            raise FirestoreOwnershipError(
                "cleanup coordinates do not match the operation manifest"
            )
        declaration_by_id = {item[0]: item for item in declarations}
        established = set(manifest.established_effect_ids)
        for coordinate in document_coordinates:
            document = by_coordinate.get(
                (coordinate.collection_name, coordinate.document_id)
            )
            if coordinate.effect_id not in established:
                if document is not None:
                    raise FirestoreOwnershipError(
                        "an unowned business document occupies an expected coordinate"
                    )
                continue
            declaration = declaration_by_id[coordinate.effect_id]
            if document is None or (
                document.effect_id != coordinate.effect_id
                or document.operation_id != operation_id
                or document.revision
                != manifest.effect_revisions.get(coordinate.effect_id)
                or document.content_sha256 != declaration[3]
                or document.correlation_items != manifest.correlation_items
                or document.observed_at > manifest.observed_at
            ):
                raise FirestoreOwnershipError(
                    "the current document does not match the manifest-owned revision"
                )
        return manifest


class GoogleFirestoreBusinessMutationTarget:
    """Mutation-only handle using one non-retrying commit per business effect."""

    def __init__(self, target: _CloudFirestoreBusinessTarget) -> None:
        self._target = target

    async def commit_business_operation(
        self,
        *,
        namespace_id: str,
        operation_id: str,
        manifest_collection: str,
        manifest_document_id: str,
        documents: tuple[BusinessDocumentWrite, ...],
        selected_effect_ids: tuple[str, ...],
        correlation: Mapping[str, str],
    ) -> None:
        documents = validate_business_operation_input(
            namespace_id=namespace_id,
            operation_id=operation_id,
            manifest_collection=manifest_collection,
            manifest_document_id=manifest_document_id,
            documents=documents,
            selected_effect_ids=selected_effect_ids,
            correlation=correlation,
        )
        if any(len(document.content) > _MAX_CONTENT_BYTES for document in documents):
            raise ValueError("business document content exceeds its byte limit")
        coordinates = tuple(document.coordinate for document in documents)
        references = await self._target._references(
            namespace_id=namespace_id,
            operation_id=operation_id,
            manifest_collection=manifest_collection,
            manifest_document_id=manifest_document_id,
            document_coordinates=coordinates,
        )
        client = await self._target._get_client()
        timestamp = self._target._timestamp_sentinel()
        declarations = business_effect_declarations(documents)
        expected_ids = tuple(document.effect_id for document in documents)
        correlation_value = dict(business_correlation_items(correlation))
        manifest_payload: dict[str, Any] = {
            "schema_version": FIRESTORE_MANIFEST_SCHEMA_VERSION,
            "namespace_id": namespace_id,
            "operation_id": operation_id,
            "manifest_collection": manifest_collection,
            "manifest_document_id": manifest_document_id,
            "status": BusinessOperationStatus.ACTIVE.value,
            "revision": 1,
            "expected_effect_ids": list(expected_ids),
            "expected_effects_sha256": expected_effect_declarations_sha256(
                declarations
            ),
            "expected_effects": [
                {
                    "effect_id": effect_id,
                    "collection_name": collection_name,
                    "document_id": document_id,
                    "content_sha256": content_sha256,
                }
                for effect_id, collection_name, document_id, content_sha256 in declarations
            ],
            "established_effect_ids": [],
            "not_established_effect_ids": [],
            "effect_revisions": {},
            "correlation": correlation_value,
            "observed_at": timestamp,
        }
        create_batch = self._target._new_batch(client)
        for _, reference in references.effects:
            create_batch.delete(
                reference,
                option=self._target._write_option(client, exists=False),
            )
        create_batch.create(references.manifest, manifest_payload)
        create_results = await self._target._commit(
            create_batch,
            expected_results=len(documents) + 1,
        )
        manifest_update_time = self._target._write_update_time(create_results[-1])

        established: list[str] = []
        effect_revisions: dict[str, int] = {}
        documents_by_id = {document.effect_id: document for document in documents}
        references_by_id = {
            coordinate.effect_id: reference
            for coordinate, reference in references.effects
        }
        if not selected_effect_ids:
            update_batch = self._target._new_batch(client)
            update_batch.update(
                references.manifest,
                {
                    "status": BusinessOperationStatus.TERMINAL_NOT_COMMITTED.value,
                    "revision": 2,
                    "not_established_effect_ids": list(expected_ids),
                    "observed_at": timestamp,
                },
                option=self._target._write_option(
                    client,
                    last_update_time=manifest_update_time,
                ),
            )
            await self._target._commit(update_batch, expected_results=1)
            return

        for index, effect_id in enumerate(selected_effect_ids, start=1):
            document = documents_by_id[effect_id]
            revision = index + 1
            established.append(effect_id)
            effect_revisions[effect_id] = revision
            terminal = index == len(selected_effect_ids)
            not_established = (
                [item for item in expected_ids if item not in established]
                if terminal
                else []
            )
            effect_payload = {
                "schema_version": FIRESTORE_EFFECT_SCHEMA_VERSION,
                "effect_id": document.effect_id,
                "collection_name": document.collection_name,
                "document_id": document.document_id,
                "operation_id": operation_id,
                "revision": revision,
                "content": document.content,
                "content_sha256": document.content_sha256,
                "correlation": correlation_value,
                "observed_at": timestamp,
            }
            update_payload = {
                "status": (
                    BusinessOperationStatus.TERMINAL_COMMITTED.value
                    if terminal
                    else BusinessOperationStatus.ACTIVE.value
                ),
                "revision": revision,
                "established_effect_ids": list(established),
                "not_established_effect_ids": not_established,
                "effect_revisions": dict(effect_revisions),
                "observed_at": timestamp,
            }
            effect_batch = self._target._new_batch(client)
            effect_batch.create(references_by_id[effect_id], effect_payload)
            effect_batch.update(
                references.manifest,
                update_payload,
                option=self._target._write_option(
                    client,
                    last_update_time=manifest_update_time,
                ),
            )
            results = await self._target._commit(effect_batch, expected_results=2)
            manifest_update_time = self._target._write_update_time(results[-1])


class GoogleFirestoreBusinessReadTarget:
    """Read-only handle issuing one strong composite BatchGet."""

    def __init__(self, target: _CloudFirestoreBusinessTarget) -> None:
        self._target = target

    async def read_business_operation(
        self,
        *,
        namespace_id: str,
        operation_id: str,
        manifest_collection: str,
        manifest_document_id: str,
        document_coordinates: tuple[BusinessDocumentCoordinate, ...],
    ) -> BusinessOperationReadback:
        composite = await self._target._composite_read(
            namespace_id=namespace_id,
            operation_id=operation_id,
            manifest_collection=manifest_collection,
            manifest_document_id=manifest_document_id,
            document_coordinates=document_coordinates,
        )
        return composite.readback


class GoogleFirestoreBusinessCleanupTarget:
    """Cleanup-only handle requiring exact manifest ownership preconditions."""

    def __init__(self, target: _CloudFirestoreBusinessTarget) -> None:
        self._target = target

    async def _owned(
        self,
        *,
        namespace_id: str,
        operation_id: str,
        manifest_collection: str,
        manifest_document_id: str,
        document_coordinates: tuple[BusinessDocumentCoordinate, ...],
    ) -> tuple[_CompositeRead, BusinessOperationManifest | None]:
        coordinates = self._target._validate_coordinates(
            namespace_id=namespace_id,
            operation_id=operation_id,
            manifest_collection=manifest_collection,
            manifest_document_id=manifest_document_id,
            document_coordinates=document_coordinates,
        )
        composite = await self._target._composite_read(
            namespace_id=namespace_id,
            operation_id=operation_id,
            manifest_collection=manifest_collection,
            manifest_document_id=manifest_document_id,
            document_coordinates=coordinates,
        )
        manifest = self._target._assert_owned(
            composite,
            namespace_id=namespace_id,
            operation_id=operation_id,
            manifest_collection=manifest_collection,
            manifest_document_id=manifest_document_id,
            document_coordinates=coordinates,
        )
        return composite, manifest

    async def count_owned(
        self,
        *,
        namespace_id: str,
        operation_id: str,
        manifest_collection: str,
        manifest_document_id: str,
        document_coordinates: tuple[BusinessDocumentCoordinate, ...],
    ) -> int:
        _, manifest = await self._owned(
            namespace_id=namespace_id,
            operation_id=operation_id,
            manifest_collection=manifest_collection,
            manifest_document_id=manifest_document_id,
            document_coordinates=document_coordinates,
        )
        return 0 if manifest is None else 1 + len(manifest.established_effect_ids)

    async def delete_owned(
        self,
        *,
        namespace_id: str,
        operation_id: str,
        manifest_collection: str,
        manifest_document_id: str,
        document_coordinates: tuple[BusinessDocumentCoordinate, ...],
    ) -> BusinessOperationDeletion:
        composite, manifest = await self._owned(
            namespace_id=namespace_id,
            operation_id=operation_id,
            manifest_collection=manifest_collection,
            manifest_document_id=manifest_document_id,
            document_coordinates=document_coordinates,
        )
        if manifest is None:
            return BusinessOperationDeletion(
                removed_documents=(),
                manifest_removed=False,
            )
        client = await self._target._get_client()
        batch = self._target._new_batch(client)
        established = set(manifest.established_effect_ids)
        removed: list[BusinessDocumentCoordinate] = []
        for coordinate, snapshot in composite.effect_snapshots:
            if coordinate.effect_id in established:
                if snapshot.update_time is None:
                    raise FirestoreCloudError(FirestoreCloudFailure.MALFORMED_RESPONSE)
                batch.delete(
                    snapshot.reference,
                    option=self._target._write_option(
                        client,
                        last_update_time=snapshot.update_time,
                    ),
                )
                removed.append(coordinate)
            else:
                batch.delete(
                    snapshot.reference,
                    option=self._target._write_option(client, exists=False),
                )
        if composite.manifest_snapshot.update_time is None:
            raise FirestoreCloudError(FirestoreCloudFailure.MALFORMED_RESPONSE)
        batch.delete(
            composite.manifest_snapshot.reference,
            option=self._target._write_option(
                client, last_update_time=composite.manifest_snapshot.update_time
            ),
        )
        await self._target._commit(
            batch,
            expected_results=len(document_coordinates) + 1,
        )
        return BusinessOperationDeletion(
            removed_documents=tuple(removed),
            manifest_removed=True,
        )


@dataclass(frozen=True, slots=True)
class GoogleFirestoreBusinessTargets:
    mutation: GoogleFirestoreBusinessMutationTarget
    read: GoogleFirestoreBusinessReadTarget
    cleanup: GoogleFirestoreBusinessCleanupTarget


def build_google_firestore_business_targets(
    *,
    project_id: str,
    database_id: str = FIRESTORE_TARGET_DATABASE,
    timeout_seconds: float = _DEFAULT_TIMEOUT_SECONDS,
    client_factory: FirestoreClientFactory | None = None,
    server_timestamp_factory: ServerTimestampFactory | None = None,
) -> GoogleFirestoreBusinessTargets:
    """Build capability-separated targets without resolving ADC eagerly."""

    shared = _CloudFirestoreBusinessTarget(
        project_id=project_id,
        database_id=database_id,
        timeout_seconds=timeout_seconds,
        client_factory=(
            _default_client_factory(project_id, database_id)
            if client_factory is None
            else client_factory
        ),
        server_timestamp_factory=(
            _default_server_timestamp
            if server_timestamp_factory is None
            else server_timestamp_factory
        ),
    )
    return GoogleFirestoreBusinessTargets(
        mutation=GoogleFirestoreBusinessMutationTarget(shared),
        read=GoogleFirestoreBusinessReadTarget(shared),
        cleanup=GoogleFirestoreBusinessCleanupTarget(shared),
    )


__all__ = [
    "FIRESTORE_EFFECT_SCHEMA_VERSION",
    "FIRESTORE_MANIFEST_SCHEMA_VERSION",
    "FIRESTORE_TARGET_DATABASE",
    "AsyncFirestoreClientPort",
    "FirestoreCloudError",
    "FirestoreCloudFailure",
    "GoogleFirestoreBusinessCleanupTarget",
    "GoogleFirestoreBusinessMutationTarget",
    "GoogleFirestoreBusinessReadTarget",
    "GoogleFirestoreBusinessTargets",
    "build_google_firestore_business_targets",
]
