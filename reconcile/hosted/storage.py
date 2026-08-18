"""Deterministic Google Cloud Storage target boundaries."""

from __future__ import annotations

import hashlib
import json
import re
import threading
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from typing import Literal, Protocol

import requests
from google.api_core import exceptions as api_exceptions
from google.cloud.storage.exceptions import DataCorruption
from pydantic import Field, ValidationError

from reconcile.contracts.base import (
    AwareDatetime,
    Identifier,
    NonEmptyText,
    Sha256Digest,
    StrictModel,
    canonical_json_value_bytes,
)
from reconcile.contracts.codec import canonical_json_bytes
from reconcile.scenarios.local_storage import (
    StorageDeletion,
    StorageGenerationReceipt,
    StorageObjectMetadata,
    StorageReadback,
    correlation_sha256,
    storage_correlation_items,
)

CLOUD_STORAGE_RECEIPT_VERSION = "reconcile/cloud-storage-receipt/v1"
CLOUD_STORAGE_TARGET_METADATA_VERSION = "reconcile/cloud-storage-target/v1"
CLOUD_STORAGE_RECEIPT_METADATA_VERSION = "reconcile/cloud-storage-receipt-metadata/v1"
CLOUD_STORAGE_OBJECT_BYTE_CEILING = 16_384
CLOUD_STORAGE_RECEIPT_BYTE_CEILING = 4_096
CLOUD_STORAGE_CORRELATION_BYTE_CEILING = 2_048
CLOUD_STORAGE_TIMEOUT_SECONDS = 2.0

_RECEIPT_PREFIX = "_reconcile/receipts/"
_TARGET_METADATA_KEYS = frozenset(
    {
        "reconcile-schema-version",
        "reconcile-operation-id",
        "reconcile-content-sha256",
        "reconcile-correlation",
    }
)
_RECEIPT_METADATA_KEYS = frozenset(
    {
        "reconcile-schema-version",
        "reconcile-operation-id",
    }
)
_PROJECT_PATTERN = re.compile(r"[a-z][a-z0-9-]{4,28}[a-z0-9]")
_BUCKET_PATTERN = re.compile(r"[a-z0-9][a-z0-9._-]{1,61}[a-z0-9]")


class CloudStorageErrorCode(StrEnum):
    ALREADY_EXISTS = "already_exists"
    CORRUPT_EVIDENCE = "corrupt_evidence"
    INVALID_CONFIGURATION = "invalid_configuration"
    MUTATION_OUTCOME_UNKNOWN = "mutation_outcome_unknown"
    CLEANUP_OUTCOME_UNKNOWN = "cleanup_outcome_unknown"
    OWNERSHIP_CHANGED = "ownership_changed"
    PROVIDER_UNAVAILABLE = "provider_unavailable"


class CloudStorageError(RuntimeError):
    """Sanitized base error that never includes a provider response."""

    def __init__(self, code: CloudStorageErrorCode) -> None:
        self.code = code
        super().__init__(f"cloud storage {code.value}")


class CloudStorageAlreadyExists(CloudStorageError):
    def __init__(self) -> None:
        super().__init__(CloudStorageErrorCode.ALREADY_EXISTS)


class CloudStorageCorruptEvidence(CloudStorageError):
    def __init__(self) -> None:
        super().__init__(CloudStorageErrorCode.CORRUPT_EVIDENCE)


class CloudStorageMutationOutcomeUnknown(CloudStorageError):
    def __init__(self) -> None:
        super().__init__(CloudStorageErrorCode.MUTATION_OUTCOME_UNKNOWN)


class CloudStorageCleanupOutcomeUnknown(CloudStorageError):
    def __init__(self) -> None:
        super().__init__(CloudStorageErrorCode.CLEANUP_OUTCOME_UNKNOWN)


class CloudStorageOwnershipChanged(CloudStorageError):
    def __init__(self) -> None:
        super().__init__(CloudStorageErrorCode.OWNERSHIP_CHANGED)


class CloudStorageProviderUnavailable(CloudStorageError):
    def __init__(self) -> None:
        super().__init__(CloudStorageErrorCode.PROVIDER_UNAVAILABLE)


class _OperationIdentity(StrictModel):
    value: Identifier


class _ReceiptDocument(StrictModel):
    schema_version: Literal[CLOUD_STORAGE_RECEIPT_VERSION]
    operation_id: Identifier
    bucket_name: NonEmptyText
    object_name: NonEmptyText
    generation: int = Field(ge=1, le=2**63 - 1)
    content_sha256: Sha256Digest
    size_bytes: int = Field(ge=0, le=CLOUD_STORAGE_OBJECT_BYTE_CEILING)
    correlation_sha256: Sha256Digest
    observed_at: AwareDatetime


class _StorageClient(Protocol):
    def bucket(self, bucket_name: str) -> object: ...


type StorageClientFactory = Callable[[str], _StorageClient]


@dataclass(frozen=True, slots=True)
class _PinnedObject:
    metadata: StorageObjectMetadata


@dataclass(frozen=True, slots=True)
class _PinnedReceipt:
    receipt: StorageGenerationReceipt
    resource_generation: int
    resource_name: str


def _coordinate(value: object, label: str) -> str:
    if type(value) is not str or not 1 <= len(value) <= 1_024 or "\x00" in value:
        raise ValueError(f"{label} must be a bounded nonempty string")
    try:
        encoded = value.encode("utf-8")
    except UnicodeEncodeError as error:
        raise ValueError(f"{label} must contain Unicode scalar values") from error
    if len(encoded) > 1_024:
        raise ValueError(f"{label} exceeds its UTF-8 byte limit")
    return value


def _operation_id(value: object) -> str:
    try:
        return _OperationIdentity(value=value).value
    except (TypeError, ValueError, ValidationError) as error:
        raise ValueError("operation identifier is invalid") from error


def cloud_storage_receipt_name(operation_id: str) -> str:
    """Return the immutable sidecar coordinate for one operation."""

    return f"{_RECEIPT_PREFIX}{_operation_id(operation_id)}.json"


def _aware_utc(value: object) -> datetime:
    if not isinstance(value, datetime) or value.tzinfo is None:
        raise ValueError("provider timestamp is invalid")
    if value.utcoffset() is None:
        raise ValueError("provider timestamp is invalid")
    return value.astimezone(UTC)


def _positive_generation(value: object) -> int:
    if type(value) is not int or not 1 <= value < 2**63:
        raise ValueError("provider generation is invalid")
    return value


def _nonnegative_size(value: object, ceiling: int) -> int:
    if type(value) is not int or not 0 <= value <= ceiling:
        raise ValueError("provider object size is invalid")
    return value


def _metadata(value: object, keys: frozenset[str]) -> dict[str, str]:
    if not isinstance(value, dict) or set(value) != keys:
        raise ValueError("provider metadata is invalid")
    if any(
        type(key) is not str or type(item) is not str for key, item in value.items()
    ):
        raise ValueError("provider metadata is invalid")
    return dict(value)


def _validate_loaded_blob(
    blob: object,
    *,
    content_type: str,
    metadata_keys: frozenset[str],
    byte_ceiling: int,
) -> tuple[int, int, dict[str, str], datetime]:
    generation = _positive_generation(getattr(blob, "generation", None))
    size = _nonnegative_size(getattr(blob, "size", None), byte_ceiling)
    metadata = _metadata(getattr(blob, "metadata", None), metadata_keys)
    created_at = _aware_utc(getattr(blob, "time_created", None))
    if getattr(blob, "metageneration", None) != 1:
        raise ValueError("provider metageneration is invalid")
    if getattr(blob, "content_type", None) != content_type:
        raise ValueError("provider content type is invalid")
    if getattr(blob, "content_encoding", None) is not None:
        raise ValueError("provider content encoding is invalid")
    return generation, size, metadata, created_at


def _target_metadata(
    *,
    operation_id: str,
    content_sha256: str,
    correlation_bytes: bytes,
) -> dict[str, str]:
    return {
        "reconcile-schema-version": CLOUD_STORAGE_TARGET_METADATA_VERSION,
        "reconcile-operation-id": operation_id,
        "reconcile-content-sha256": content_sha256,
        "reconcile-correlation": correlation_bytes.decode("utf-8"),
    }


def _receipt_metadata(operation_id: str) -> dict[str, str]:
    return {
        "reconcile-schema-version": CLOUD_STORAGE_RECEIPT_METADATA_VERSION,
        "reconcile-operation-id": operation_id,
    }


def _default_client_factory(project_id: str) -> _StorageClient:
    from google.auth import default as default_credentials
    from google.auth.transport.requests import AuthorizedSession, Request
    from google.cloud import storage

    credentials, _ = default_credentials(scopes=storage.Client.SCOPE)
    auth_session = requests.Session()
    auth_session.trust_env = False
    auth_session.max_redirects = 0
    auth_session.mount("https://", requests.adapters.HTTPAdapter(max_retries=0))
    provider_session = AuthorizedSession(
        credentials,
        refresh_status_codes=(),
        max_refresh_attempts=0,
        auth_request=Request(session=auth_session),
        default_host="storage.googleapis.com",
    )
    provider_session.trust_env = False
    provider_session.max_redirects = 0
    provider_session._auth_request_session = auth_session
    provider_session.mount(
        "https://",
        requests.adapters.HTTPAdapter(max_retries=0),
    )
    return storage.Client(
        project=project_id,
        credentials=credentials,
        _http=provider_session,
    )


class _CloudStorageBackend:
    def __init__(
        self,
        *,
        project_id: str,
        bucket_name: str,
        client_factory: StorageClientFactory | None,
    ) -> None:
        if (
            type(project_id) is not str
            or _PROJECT_PATTERN.fullmatch(project_id) is None
        ):
            raise CloudStorageError(CloudStorageErrorCode.INVALID_CONFIGURATION)
        if (
            type(bucket_name) is not str
            or _BUCKET_PATTERN.fullmatch(bucket_name) is None
        ):
            raise CloudStorageError(CloudStorageErrorCode.INVALID_CONFIGURATION)
        self._project_id = project_id
        self._bucket_name = bucket_name
        self._client_factory = client_factory or _default_client_factory
        self._client_instance: _StorageClient | None = None
        self._client_lock = threading.Lock()

    def _client(self) -> _StorageClient:
        if self._client_instance is not None:
            return self._client_instance
        with self._client_lock:
            if self._client_instance is not None:
                return self._client_instance
            try:
                client = self._client_factory(self._project_id)
            except Exception:
                raise CloudStorageProviderUnavailable from None
            if not callable(getattr(client, "bucket", None)):
                raise CloudStorageProviderUnavailable
            self._client_instance = client
            return client

    def _bucket(self, bucket: str) -> object:
        if _coordinate(bucket, "bucket") != self._bucket_name:
            raise CloudStorageOwnershipChanged
        try:
            selected = self._client().bucket(self._bucket_name)
        except Exception:
            raise CloudStorageProviderUnavailable from None
        if not callable(getattr(selected, "blob", None)):
            raise CloudStorageProviderUnavailable
        return selected

    @staticmethod
    def _prepare_input(
        *,
        operation_id: str,
        bucket: str,
        name: str,
        content: bytes,
        correlation: Mapping[str, str],
    ) -> tuple[str, str, str, bytes, tuple[tuple[str, str], ...], bytes]:
        operation = _operation_id(operation_id)
        bucket_name = _coordinate(bucket, "bucket")
        object_name = _coordinate(name, "object name")
        if object_name.startswith(_RECEIPT_PREFIX):
            raise ValueError("target object uses the reserved receipt prefix")
        if type(content) is not bytes:
            raise TypeError("object content must be immutable bytes")
        if len(content) > CLOUD_STORAGE_OBJECT_BYTE_CEILING:
            raise ValueError("object content exceeds its byte limit")
        items = storage_correlation_items(correlation)
        correlation_bytes = canonical_json_value_bytes(dict(items))
        if len(correlation_bytes) > CLOUD_STORAGE_CORRELATION_BYTE_CEILING:
            raise ValueError("correlation metadata exceeds its byte limit")
        return (
            operation,
            bucket_name,
            object_name,
            content,
            items,
            correlation_bytes,
        )

    def commit_object(
        self,
        *,
        operation_id: str,
        bucket: str,
        name: str,
        content: bytes,
        correlation: Mapping[str, str],
    ) -> None:
        (
            operation,
            bucket_name,
            object_name,
            content_bytes,
            correlation_items,
            correlation_bytes,
        ) = self._prepare_input(
            operation_id=operation_id,
            bucket=bucket,
            name=name,
            content=content,
            correlation=correlation,
        )
        selected_bucket = self._bucket(bucket_name)
        digest = hashlib.sha256(content_bytes).hexdigest()
        try:
            target_blob = selected_bucket.blob(object_name)
            target_blob.metadata = _target_metadata(
                operation_id=operation,
                content_sha256=digest,
                correlation_bytes=correlation_bytes,
            )
            target_blob.upload_from_string(
                content_bytes,
                content_type="application/octet-stream",
                if_generation_match=0,
                timeout=CLOUD_STORAGE_TIMEOUT_SECONDS,
                checksum="crc32c",
                retry=None,
            )
        except api_exceptions.PreconditionFailed:
            raise CloudStorageAlreadyExists from None
        except Exception:
            raise CloudStorageMutationOutcomeUnknown from None
        try:
            generation, size, metadata, observed_at = _validate_loaded_blob(
                target_blob,
                content_type="application/octet-stream",
                metadata_keys=_TARGET_METADATA_KEYS,
                byte_ceiling=CLOUD_STORAGE_OBJECT_BYTE_CEILING,
            )
            if size != len(content_bytes) or metadata != _target_metadata(
                operation_id=operation,
                content_sha256=digest,
                correlation_bytes=correlation_bytes,
            ):
                raise ValueError("created object response is inconsistent")
            object_metadata = StorageObjectMetadata(
                bucket=bucket_name,
                name=object_name,
                generation=generation,
                content_sha256=digest,
                size=size,
                correlation_items=correlation_items,
                observed_at=observed_at,
            )
            receipt = _ReceiptDocument(
                schema_version=CLOUD_STORAGE_RECEIPT_VERSION,
                operation_id=operation,
                bucket_name=bucket_name,
                object_name=object_name,
                generation=generation,
                content_sha256=digest,
                size_bytes=size,
                correlation_sha256=correlation_sha256(dict(correlation_items)),
                observed_at=object_metadata.observed_at,
            )
            receipt_bytes = canonical_json_bytes(receipt)
            if len(receipt_bytes) > CLOUD_STORAGE_RECEIPT_BYTE_CEILING:
                raise ValueError("receipt exceeds its byte limit")
        except (TypeError, ValueError, ValidationError):
            raise CloudStorageMutationOutcomeUnknown from None
        try:
            receipt_blob = selected_bucket.blob(cloud_storage_receipt_name(operation))
            receipt_blob.metadata = _receipt_metadata(operation)
            receipt_blob.upload_from_string(
                receipt_bytes,
                content_type="application/json",
                if_generation_match=0,
                timeout=CLOUD_STORAGE_TIMEOUT_SECONDS,
                checksum="crc32c",
                retry=None,
            )
        except Exception:
            raise CloudStorageMutationOutcomeUnknown from None
        try:
            _, receipt_size, receipt_provider_metadata, _ = _validate_loaded_blob(
                receipt_blob,
                content_type="application/json",
                metadata_keys=_RECEIPT_METADATA_KEYS,
                byte_ceiling=CLOUD_STORAGE_RECEIPT_BYTE_CEILING,
            )
            if receipt_size != len(
                receipt_bytes
            ) or receipt_provider_metadata != _receipt_metadata(operation):
                raise ValueError("created receipt response is inconsistent")
        except (TypeError, ValueError):
            raise CloudStorageMutationOutcomeUnknown from None

    @staticmethod
    def _reload_optional(blob: object) -> bool:
        try:
            blob.reload(
                projection="noAcl",
                timeout=CLOUD_STORAGE_TIMEOUT_SECONDS,
                retry=None,
            )
        except api_exceptions.NotFound:
            return False
        except DataCorruption:
            raise CloudStorageCorruptEvidence from None
        except Exception:
            raise CloudStorageProviderUnavailable from None
        return True

    @staticmethod
    def _download(blob: object, generation: int, ceiling: int) -> bytes:
        try:
            payload = blob.download_as_bytes(
                start=0,
                end=ceiling - 1,
                raw_download=True,
                if_generation_match=generation,
                timeout=CLOUD_STORAGE_TIMEOUT_SECONDS,
                checksum=None,
                retry=None,
                single_shot_download=True,
            )
        except (api_exceptions.NotFound, api_exceptions.PreconditionFailed):
            raise CloudStorageOwnershipChanged from None
        except DataCorruption:
            raise CloudStorageCorruptEvidence from None
        except Exception:
            raise CloudStorageProviderUnavailable from None
        if type(payload) is not bytes or len(payload) > ceiling:
            raise CloudStorageCorruptEvidence
        return payload

    def _read_object_optional(
        self,
        selected_bucket: object,
        *,
        name: str,
        operation_id: str,
        generation: int | None = None,
    ) -> _PinnedObject | None:
        try:
            blob = selected_bucket.blob(name, generation=generation)
        except Exception:
            raise CloudStorageProviderUnavailable from None
        if not self._reload_optional(blob):
            return None
        try:
            generation, size, metadata, observed_at = _validate_loaded_blob(
                blob,
                content_type="application/octet-stream",
                metadata_keys=_TARGET_METADATA_KEYS,
                byte_ceiling=CLOUD_STORAGE_OBJECT_BYTE_CEILING,
            )
            if (
                metadata["reconcile-schema-version"]
                != CLOUD_STORAGE_TARGET_METADATA_VERSION
                or metadata["reconcile-operation-id"] != operation_id
            ):
                raise CloudStorageOwnershipChanged
            correlation_bytes = metadata["reconcile-correlation"].encode("utf-8")
            if len(correlation_bytes) > CLOUD_STORAGE_CORRELATION_BYTE_CEILING:
                raise ValueError("correlation metadata exceeds its byte limit")
            correlation = json.loads(correlation_bytes)
            if not isinstance(correlation, dict):
                raise ValueError("correlation metadata is invalid")
            correlation_items = storage_correlation_items(correlation)
            if canonical_json_value_bytes(dict(correlation_items)) != correlation_bytes:
                raise ValueError("correlation metadata is not canonical")
            expected_digest = metadata["reconcile-content-sha256"]
            if re.fullmatch(r"[0-9a-f]{64}", expected_digest) is None:
                raise ValueError("content digest is invalid")
        except CloudStorageOwnershipChanged:
            raise
        except (TypeError, ValueError, json.JSONDecodeError):
            raise CloudStorageCorruptEvidence from None
        payload = (
            b""
            if size == 0
            else self._download(blob, generation, CLOUD_STORAGE_OBJECT_BYTE_CEILING)
        )
        digest = hashlib.sha256(payload).hexdigest()
        if len(payload) != size or digest != expected_digest:
            raise CloudStorageCorruptEvidence
        try:
            metadata_record = StorageObjectMetadata(
                bucket=self._bucket_name,
                name=name,
                generation=generation,
                content_sha256=digest,
                size=size,
                correlation_items=correlation_items,
                observed_at=observed_at,
            )
        except (TypeError, ValueError):
            raise CloudStorageCorruptEvidence from None
        return _PinnedObject(metadata=metadata_record)

    def _read_receipt_optional(
        self,
        selected_bucket: object,
        *,
        operation_id: str,
        bucket_name: str,
        object_name: str,
    ) -> _PinnedReceipt | None:
        resource_name = cloud_storage_receipt_name(operation_id)
        try:
            blob = selected_bucket.blob(resource_name)
        except Exception:
            raise CloudStorageProviderUnavailable from None
        if not self._reload_optional(blob):
            return None
        try:
            generation, size, metadata, _ = _validate_loaded_blob(
                blob,
                content_type="application/json",
                metadata_keys=_RECEIPT_METADATA_KEYS,
                byte_ceiling=CLOUD_STORAGE_RECEIPT_BYTE_CEILING,
            )
            if metadata != _receipt_metadata(operation_id):
                raise CloudStorageOwnershipChanged
        except CloudStorageOwnershipChanged:
            raise
        except (TypeError, ValueError):
            raise CloudStorageCorruptEvidence from None
        payload = self._download(blob, generation, CLOUD_STORAGE_RECEIPT_BYTE_CEILING)
        if len(payload) != size:
            raise CloudStorageCorruptEvidence
        try:
            document = _ReceiptDocument.model_validate_json(payload)
            if canonical_json_bytes(document) != payload:
                raise ValueError("receipt is not canonical")
            if (
                document.operation_id != operation_id
                or document.bucket_name != bucket_name
                or document.object_name != object_name
            ):
                raise CloudStorageOwnershipChanged
            receipt = StorageGenerationReceipt(
                operation_id=document.operation_id,
                bucket=document.bucket_name,
                name=document.object_name,
                generation=document.generation,
                content_sha256=document.content_sha256,
                size=document.size_bytes,
                correlation_sha256=document.correlation_sha256,
                observed_at=document.observed_at,
            )
        except CloudStorageOwnershipChanged:
            raise
        except (TypeError, ValueError, ValidationError):
            raise CloudStorageCorruptEvidence from None
        return _PinnedReceipt(
            receipt=receipt,
            resource_generation=generation,
            resource_name=resource_name,
        )

    @staticmethod
    def _validate_binding(
        target: _PinnedObject,
        receipt: _PinnedReceipt,
    ) -> None:
        metadata = target.metadata
        bound = receipt.receipt
        if not (
            bound.bucket == metadata.bucket
            and bound.name == metadata.name
            and bound.generation == metadata.generation
            and bound.content_sha256 == metadata.content_sha256
            and bound.size == metadata.size
            and bound.correlation_sha256 == correlation_sha256(metadata.correlation)
            and bound.observed_at == metadata.observed_at
        ):
            raise CloudStorageOwnershipChanged

    def read(
        self,
        *,
        bucket: str,
        name: str,
        operation_id: str,
    ) -> StorageReadback:
        operation = _operation_id(operation_id)
        object_name = _coordinate(name, "object name")
        selected_bucket = self._bucket(bucket)
        receipt = self._read_receipt_optional(
            selected_bucket,
            operation_id=operation,
            bucket_name=self._bucket_name,
            object_name=object_name,
        )
        target = self._read_object_optional(
            selected_bucket,
            name=object_name,
            operation_id=operation,
            generation=(None if receipt is None else receipt.receipt.generation),
        )
        if target is not None and receipt is not None:
            self._validate_binding(target, receipt)
        return StorageReadback(
            object_metadata=None if target is None else target.metadata,
            receipt=None if receipt is None else receipt.receipt,
        )

    def count_owned(self, *, bucket: str, name: str, operation_id: str) -> int:
        readback = self.read(
            bucket=bucket,
            name=name,
            operation_id=operation_id,
        )
        return int(readback.object_metadata is not None) + int(
            readback.receipt is not None
        )

    @staticmethod
    def _delete_generation(
        selected_bucket: object,
        *,
        name: str,
        generation: int,
    ) -> bool:
        try:
            blob = selected_bucket.blob(name, generation=generation)
            blob.delete(
                if_generation_match=generation,
                timeout=CLOUD_STORAGE_TIMEOUT_SECONDS,
                retry=None,
            )
        except api_exceptions.NotFound:
            return False
        except api_exceptions.PreconditionFailed:
            raise CloudStorageOwnershipChanged from None
        except Exception:
            raise CloudStorageCleanupOutcomeUnknown from None
        return True

    def delete_owned(
        self,
        *,
        bucket: str,
        name: str,
        operation_id: str,
    ) -> StorageDeletion:
        operation = _operation_id(operation_id)
        object_name = _coordinate(name, "object name")
        selected_bucket = self._bucket(bucket)
        receipt = self._read_receipt_optional(
            selected_bucket,
            operation_id=operation,
            bucket_name=self._bucket_name,
            object_name=object_name,
        )
        if receipt is None:
            return StorageDeletion(object_removed=False, receipt_removed=False)
        if (
            receipt.receipt.bucket != self._bucket_name
            or receipt.receipt.name != object_name
        ):
            raise CloudStorageOwnershipChanged
        target = self._read_object_optional(
            selected_bucket,
            name=object_name,
            operation_id=operation,
            generation=receipt.receipt.generation,
        )
        if target is not None:
            self._validate_binding(target, receipt)
            object_removed = self._delete_generation(
                selected_bucket,
                name=object_name,
                generation=target.metadata.generation,
            )
        else:
            object_removed = False
        receipt_removed = self._delete_generation(
            selected_bucket,
            name=receipt.resource_name,
            generation=receipt.resource_generation,
        )
        return StorageDeletion(
            object_removed=object_removed,
            receipt_removed=receipt_removed,
        )


class CloudStorageMutationTarget:
    """Create-only target handle that withholds provider generations."""

    def __init__(
        self,
        *,
        project_id: str,
        bucket_name: str,
        client_factory: StorageClientFactory | None = None,
    ) -> None:
        self._backend = _CloudStorageBackend(
            project_id=project_id,
            bucket_name=bucket_name,
            client_factory=client_factory,
        )

    def commit_object(
        self,
        *,
        operation_id: str,
        bucket: str,
        name: str,
        content: bytes,
        correlation: Mapping[str, str],
    ) -> None:
        self._backend.commit_object(
            operation_id=operation_id,
            bucket=bucket,
            name=name,
            content=content,
            correlation=correlation,
        )


class CloudStorageReadTarget:
    """Read-only handle for exact target generations and receipt sidecars."""

    def __init__(
        self,
        *,
        project_id: str,
        bucket_name: str,
        client_factory: StorageClientFactory | None = None,
    ) -> None:
        self._backend = _CloudStorageBackend(
            project_id=project_id,
            bucket_name=bucket_name,
            client_factory=client_factory,
        )

    def read(
        self,
        *,
        bucket: str,
        name: str,
        operation_id: str,
    ) -> StorageReadback:
        return self._backend.read(
            bucket=bucket,
            name=name,
            operation_id=operation_id,
        )


class CloudStorageCleanupTarget:
    """Cleanup-only handle gated by an exact immutable receipt."""

    def __init__(
        self,
        *,
        project_id: str,
        bucket_name: str,
        client_factory: StorageClientFactory | None = None,
    ) -> None:
        self._backend = _CloudStorageBackend(
            project_id=project_id,
            bucket_name=bucket_name,
            client_factory=client_factory,
        )

    def count_owned(self, *, bucket: str, name: str, operation_id: str) -> int:
        return self._backend.count_owned(
            bucket=bucket,
            name=name,
            operation_id=operation_id,
        )

    def delete_owned(
        self,
        *,
        bucket: str,
        name: str,
        operation_id: str,
    ) -> StorageDeletion:
        return self._backend.delete_owned(
            bucket=bucket,
            name=name,
            operation_id=operation_id,
        )


__all__ = [
    "CLOUD_STORAGE_CORRELATION_BYTE_CEILING",
    "CLOUD_STORAGE_OBJECT_BYTE_CEILING",
    "CLOUD_STORAGE_RECEIPT_BYTE_CEILING",
    "CLOUD_STORAGE_RECEIPT_METADATA_VERSION",
    "CLOUD_STORAGE_RECEIPT_VERSION",
    "CLOUD_STORAGE_TARGET_METADATA_VERSION",
    "CLOUD_STORAGE_TIMEOUT_SECONDS",
    "CloudStorageAlreadyExists",
    "CloudStorageCleanupOutcomeUnknown",
    "CloudStorageCleanupTarget",
    "CloudStorageCorruptEvidence",
    "CloudStorageError",
    "CloudStorageErrorCode",
    "CloudStorageMutationOutcomeUnknown",
    "CloudStorageMutationTarget",
    "CloudStorageOwnershipChanged",
    "CloudStorageProviderUnavailable",
    "CloudStorageReadTarget",
    "StorageClientFactory",
    "cloud_storage_receipt_name",
]
