"""SQLite-backed object metadata used by local scenario targets."""

from __future__ import annotations

import hashlib
import json
import re
import sqlite3
from collections.abc import Callable, Iterator, Mapping
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Protocol, runtime_checkable

_SQLITE_TIMEOUT_SECONDS = 30.0
_MAX_COORDINATE_LENGTH = 1_024
_MAX_CORRELATION_FIELDS = 32
_MAX_CORRELATION_VALUE_LENGTH = 4_096
_SHA256_PATTERN = re.compile(r"^[0-9a-f]{64}$")
_SENSITIVE_KEY_TOKENS = frozenset(
    {
        "authorization",
        "cookie",
        "credential",
        "credentials",
        "header",
        "headers",
        "password",
        "secret",
        "token",
    }
)
_SENSITIVE_KEY_NAMES = frozenset(
    {
        "access_key",
        "api_key",
        "private_key",
        "refresh_key",
        "session_key",
        "signing_key",
    }
)


def _utc_now() -> datetime:
    return datetime.now(UTC)


class LocalStorageError(RuntimeError):
    """Base error for the local object target."""


class StorageObjectAlreadyExists(LocalStorageError):
    """The create-only object coordinate is already occupied."""


class StorageObjectNotFound(LocalStorageError):
    """The exact object coordinate does not exist."""


class StorageReceiptAlreadyExists(LocalStorageError):
    """The operation already has an immutable receipt."""


class StorageReceiptNotFound(LocalStorageError):
    """The requested operation receipt does not exist."""


class StorageOwnershipError(LocalStorageError):
    """A receipt does not bind the exact object selected for deletion."""


@dataclass(frozen=True, slots=True)
class StorageObjectMetadata:
    """Metadata returned without reading an object's content bytes."""

    bucket: str
    name: str
    generation: int
    content_sha256: str
    size: int
    correlation_items: tuple[tuple[str, str], ...]
    observed_at: datetime

    def __post_init__(self) -> None:
        _validate_coordinate(self.bucket, "bucket")
        _validate_coordinate(self.name, "object name")
        _validate_generation(self.generation)
        _validate_sha256(self.content_sha256, "content digest")
        if type(self.size) is not int or self.size < 0:
            raise ValueError("object size must be a nonnegative integer")
        if type(self.correlation_items) is not tuple:
            raise TypeError("correlation items must be an immutable tuple")
        normalized = _correlation_items(dict(self.correlation_items))
        if normalized != self.correlation_items:
            raise ValueError("correlation items must be unique and canonically ordered")
        object.__setattr__(self, "observed_at", _aware_utc(self.observed_at))

    @property
    def correlation(self) -> dict[str, str]:
        """Return an isolated copy of the object's correlation metadata."""

        return dict(self.correlation_items)


@dataclass(frozen=True, slots=True)
class StorageGenerationReceipt:
    """Immutable operation binding captured after an object generation exists."""

    operation_id: str
    bucket: str
    name: str
    generation: int
    content_sha256: str
    size: int
    correlation_sha256: str
    observed_at: datetime

    def __post_init__(self) -> None:
        _validate_coordinate(self.operation_id, "operation identifier")
        _validate_coordinate(self.bucket, "bucket")
        _validate_coordinate(self.name, "object name")
        _validate_generation(self.generation)
        _validate_sha256(self.content_sha256, "content digest")
        _validate_sha256(self.correlation_sha256, "correlation digest")
        if type(self.size) is not int or self.size < 0:
            raise ValueError("receipt size must be a nonnegative integer")
        object.__setattr__(self, "observed_at", _aware_utc(self.observed_at))


@dataclass(frozen=True, slots=True)
class StorageReadback:
    """The independent current object metadata and immutable receipt records."""

    object_metadata: StorageObjectMetadata | None
    receipt: StorageGenerationReceipt | None


@dataclass(frozen=True, slots=True)
class StorageDeletion:
    """Exact resources removed by one idempotent cleanup attempt."""

    object_removed: bool
    receipt_removed: bool

    @property
    def removed_count(self) -> int:
        return int(self.object_removed) + int(self.receipt_removed)


@runtime_checkable
class StorageMutationPort(Protocol):
    """Trusted create-only boundary supplied by one configured target."""

    def commit_object(
        self,
        *,
        operation_id: str,
        bucket: str,
        name: str,
        content: bytes,
        correlation: Mapping[str, str],
    ) -> None: ...


@runtime_checkable
class StorageReadPort(Protocol):
    """Trusted exact-object read boundary supplied by one configured target."""

    def read(
        self,
        *,
        bucket: str,
        name: str,
        operation_id: str,
    ) -> StorageReadback: ...


@runtime_checkable
class StorageCleanupPort(Protocol):
    """Trusted receipt-bound cleanup boundary supplied by one configured target."""

    def count_owned(self, *, bucket: str, name: str, operation_id: str) -> int: ...

    def delete_owned(
        self,
        *,
        bucket: str,
        name: str,
        operation_id: str,
    ) -> StorageDeletion: ...


def correlation_sha256(correlation: Mapping[str, str]) -> str:
    """Return the canonical digest used to bind correlation metadata."""

    items = _correlation_items(correlation)
    payload = json.dumps(
        dict(items),
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def storage_correlation_items(
    correlation: Mapping[str, str],
) -> tuple[tuple[str, str], ...]:
    """Validate and canonically order provider-neutral correlation metadata."""

    return _correlation_items(correlation)


def _validate_coordinate(value: str, label: str) -> None:
    if (
        type(value) is not str
        or not 1 <= len(value) <= _MAX_COORDINATE_LENGTH
        or "\x00" in value
    ):
        raise ValueError(f"{label} must be a bounded nonempty string")
    try:
        value.encode("utf-8")
    except UnicodeEncodeError as error:
        raise ValueError(f"{label} must contain Unicode scalar values") from error


def _validate_generation(value: int) -> None:
    if type(value) is not int or not 1 <= value < 2**63:
        raise ValueError("generation must be a positive signed 64-bit integer")


def _validate_sha256(value: str, label: str) -> None:
    if type(value) is not str or _SHA256_PATTERN.fullmatch(value) is None:
        raise ValueError(f"{label} must be a lowercase SHA-256 digest")


def _aware_utc(value: datetime) -> datetime:
    if not isinstance(value, datetime) or value.tzinfo is None:
        raise ValueError("storage timestamps must include a UTC offset")
    if value.utcoffset() is None:
        raise ValueError("storage timestamps must include a UTC offset")
    return value.astimezone(UTC)


def _timestamp_text(value: datetime) -> str:
    return _aware_utc(value).isoformat(timespec="microseconds")


def _timestamp_from_text(value: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(value)
    except (TypeError, ValueError) as error:
        raise LocalStorageError("stored timestamp is malformed") from error
    return _aware_utc(parsed)


def _normalized_sensitive_tokens(key: str) -> set[str]:
    words = re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", key).lower()
    return {part for part in re.split(r"[^a-z0-9]+", words) if part}


def _is_sensitive_key(key: str) -> bool:
    normalized = re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", key).lower()
    normalized = re.sub(r"[^a-z0-9]+", "_", normalized).strip("_")
    wrapped = f"_{normalized}_"
    collapsed = normalized.replace("_", "")
    return bool(
        _normalized_sensitive_tokens(key).intersection(_SENSITIVE_KEY_TOKENS)
        or any(f"_{name}_" in wrapped for name in _SENSITIVE_KEY_NAMES)
        or any(name.replace("_", "") in collapsed for name in _SENSITIVE_KEY_NAMES)
    )


def _correlation_items(
    correlation: Mapping[str, str],
) -> tuple[tuple[str, str], ...]:
    if not isinstance(correlation, Mapping):
        raise TypeError("correlation metadata must be a mapping")
    if len(correlation) > _MAX_CORRELATION_FIELDS:
        raise ValueError("correlation metadata has too many fields")
    items: list[tuple[str, str]] = []
    for key, value in correlation.items():
        if type(key) is not str or not 1 <= len(key) <= 128:
            raise ValueError("correlation keys must be bounded nonempty strings")
        if _is_sensitive_key(key):
            raise ValueError("secret-bearing correlation fields are not allowed")
        if (
            type(value) is not str
            or not 1 <= len(value) <= _MAX_CORRELATION_VALUE_LENGTH
        ):
            raise ValueError("correlation values must be bounded nonempty strings")
        try:
            key.encode("utf-8")
            value.encode("utf-8")
        except UnicodeEncodeError as error:
            raise ValueError(
                "correlation metadata must contain Unicode scalar values"
            ) from error
        items.append((key, value))
    return tuple(sorted(items))


def _correlation_text(correlation: Mapping[str, str]) -> str:
    return json.dumps(
        dict(_correlation_items(correlation)),
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    )


def _correlation_from_text(value: str) -> tuple[tuple[str, str], ...]:
    try:
        decoded = json.loads(value)
    except (TypeError, ValueError) as error:
        raise LocalStorageError("stored correlation metadata is malformed") from error
    if not isinstance(decoded, dict):
        raise LocalStorageError("stored correlation metadata is malformed")
    try:
        return _correlation_items(decoded)
    except (TypeError, ValueError) as error:
        raise LocalStorageError("stored correlation metadata is malformed") from error


class _LocalStorageDatabase:
    """A process-safe local object target with metadata and receipt reads."""

    def __init__(self, database_path: str | Path) -> None:
        path = Path(database_path)
        if str(path) == ":memory:":
            raise ValueError("the local storage target requires a disk database")
        path.parent.mkdir(parents=True, exist_ok=True)
        if path.exists() and path.is_dir():
            raise ValueError("the local storage database path is a directory")
        self._database_path = str(path)
        self.initialize()

    @property
    def database_path(self) -> Path:
        return Path(self._database_path)

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(
            self._database_path,
            timeout=_SQLITE_TIMEOUT_SECONDS,
            isolation_level=None,
        )
        connection.row_factory = sqlite3.Row
        connection.execute(
            f"PRAGMA busy_timeout = {int(_SQLITE_TIMEOUT_SECONDS * 1_000)}"
        )
        connection.execute("PRAGMA foreign_keys = ON")
        return connection

    @contextmanager
    def _write_transaction(self) -> Iterator[sqlite3.Connection]:
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            yield connection
            connection.commit()
        except BaseException:
            connection.rollback()
            raise
        finally:
            connection.close()

    def initialize(self) -> None:
        """Create the database schema safely from any local subprocess."""

        connection = self._connect()
        try:
            connection.execute("PRAGMA journal_mode = WAL")
            connection.execute("PRAGMA synchronous = FULL")
            connection.execute("BEGIN IMMEDIATE")
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS assigned_generations (
                    generation INTEGER PRIMARY KEY AUTOINCREMENT,
                    assigned_at TEXT NOT NULL
                )
                """
            )
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS storage_objects (
                    bucket TEXT NOT NULL,
                    name TEXT NOT NULL,
                    generation INTEGER NOT NULL UNIQUE,
                    content BLOB NOT NULL,
                    content_sha256 TEXT NOT NULL,
                    size INTEGER NOT NULL,
                    correlation_json TEXT NOT NULL,
                    observed_at TEXT NOT NULL,
                    PRIMARY KEY (bucket, name)
                )
                """
            )
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS operation_receipts (
                    operation_id TEXT PRIMARY KEY,
                    bucket TEXT NOT NULL,
                    name TEXT NOT NULL,
                    generation INTEGER NOT NULL,
                    content_sha256 TEXT NOT NULL,
                    size INTEGER NOT NULL,
                    correlation_sha256 TEXT NOT NULL,
                    observed_at TEXT NOT NULL
                )
                """
            )
            connection.commit()
        except BaseException:
            connection.rollback()
            raise
        finally:
            connection.close()

    @staticmethod
    def _next_generation(
        connection: sqlite3.Connection,
        observed_at: datetime,
    ) -> int:
        cursor = connection.execute(
            "INSERT INTO assigned_generations (assigned_at) VALUES (?)",
            (_timestamp_text(observed_at),),
        )
        generation = cursor.lastrowid
        if generation is None:
            raise LocalStorageError("storage generation allocation failed")
        _validate_generation(generation)
        return generation

    def create_object(
        self,
        *,
        bucket: str,
        name: str,
        content: bytes,
        correlation: Mapping[str, str],
        observed_at: datetime | None = None,
    ) -> StorageObjectMetadata:
        """Create one absent object and assign its generation inside SQLite."""

        _validate_coordinate(bucket, "bucket")
        _validate_coordinate(name, "object name")
        if type(content) is not bytes:
            raise TypeError("object content must be immutable bytes")
        correlation_text = _correlation_text(correlation)
        timestamp = _aware_utc(observed_at or datetime.now(UTC))
        digest = hashlib.sha256(content).hexdigest()
        with self._write_transaction() as connection:
            existing = connection.execute(
                "SELECT 1 FROM storage_objects WHERE bucket = ? AND name = ?",
                (bucket, name),
            ).fetchone()
            if existing is not None:
                raise StorageObjectAlreadyExists(
                    "the create-only object coordinate already exists"
                )
            generation = self._next_generation(connection, timestamp)
            connection.execute(
                """
                INSERT INTO storage_objects (
                    bucket,
                    name,
                    generation,
                    content,
                    content_sha256,
                    size,
                    correlation_json,
                    observed_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    bucket,
                    name,
                    generation,
                    content,
                    digest,
                    len(content),
                    correlation_text,
                    _timestamp_text(timestamp),
                ),
            )
        return StorageObjectMetadata(
            bucket=bucket,
            name=name,
            generation=generation,
            content_sha256=digest,
            size=len(content),
            correlation_items=_correlation_items(correlation),
            observed_at=timestamp,
        )

    def create_receipt(
        self,
        *,
        operation_id: str,
        object_metadata: StorageObjectMetadata,
    ) -> StorageGenerationReceipt:
        """Bind one operation to exact target metadata without an update path."""

        _validate_coordinate(operation_id, "operation identifier")
        if type(object_metadata) is not StorageObjectMetadata:
            raise TypeError("receipt input must be exact object metadata")
        receipt = StorageGenerationReceipt(
            operation_id=operation_id,
            bucket=object_metadata.bucket,
            name=object_metadata.name,
            generation=object_metadata.generation,
            content_sha256=object_metadata.content_sha256,
            size=object_metadata.size,
            correlation_sha256=correlation_sha256(object_metadata.correlation),
            observed_at=object_metadata.observed_at,
        )
        with self._write_transaction() as connection:
            existing = connection.execute(
                "SELECT 1 FROM operation_receipts WHERE operation_id = ?",
                (operation_id,),
            ).fetchone()
            if existing is not None:
                raise StorageReceiptAlreadyExists(
                    "the operation receipt is immutable and already exists"
                )
            object_row = connection.execute(
                """
                SELECT
                    bucket,
                    name,
                    generation,
                    content_sha256,
                    size,
                    correlation_json,
                    observed_at
                FROM storage_objects
                WHERE bucket = ? AND name = ?
                """,
                (object_metadata.bucket, object_metadata.name),
            ).fetchone()
            if object_row is None:
                raise StorageObjectNotFound(
                    "receipt creation requires the exact stored object"
                )
            if self._metadata_from_row(object_row) != object_metadata:
                raise StorageOwnershipError(
                    "receipt input does not match the current object generation"
                )
            connection.execute(
                """
                INSERT INTO operation_receipts (
                    operation_id,
                    bucket,
                    name,
                    generation,
                    content_sha256,
                    size,
                    correlation_sha256,
                    observed_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    receipt.operation_id,
                    receipt.bucket,
                    receipt.name,
                    receipt.generation,
                    receipt.content_sha256,
                    receipt.size,
                    receipt.correlation_sha256,
                    _timestamp_text(receipt.observed_at),
                ),
            )
        return receipt

    def create_object_with_receipt(
        self,
        *,
        operation_id: str,
        bucket: str,
        name: str,
        content: bytes,
        correlation: Mapping[str, str],
        observed_at: datetime | None = None,
    ) -> StorageReadback:
        """Commit an object followed by its operation-unique receipt."""

        metadata = self.create_object(
            bucket=bucket,
            name=name,
            content=content,
            correlation=correlation,
            observed_at=observed_at,
        )
        receipt = self.create_receipt(
            operation_id=operation_id,
            object_metadata=metadata,
        )
        return StorageReadback(object_metadata=metadata, receipt=receipt)

    def overwrite_object(
        self,
        *,
        bucket: str,
        name: str,
        content: bytes,
        correlation: Mapping[str, str],
        observed_at: datetime | None = None,
    ) -> StorageObjectMetadata:
        """Replace an existing object's current metadata with a new generation."""

        _validate_coordinate(bucket, "bucket")
        _validate_coordinate(name, "object name")
        if type(content) is not bytes:
            raise TypeError("object content must be immutable bytes")
        correlation_text = _correlation_text(correlation)
        timestamp = _aware_utc(observed_at or datetime.now(UTC))
        digest = hashlib.sha256(content).hexdigest()
        with self._write_transaction() as connection:
            existing = connection.execute(
                "SELECT 1 FROM storage_objects WHERE bucket = ? AND name = ?",
                (bucket, name),
            ).fetchone()
            if existing is None:
                raise StorageObjectNotFound(
                    "the object selected for overwrite is absent"
                )
            generation = self._next_generation(connection, timestamp)
            connection.execute(
                """
                UPDATE storage_objects
                SET generation = ?,
                    content = ?,
                    content_sha256 = ?,
                    size = ?,
                    correlation_json = ?,
                    observed_at = ?
                WHERE bucket = ? AND name = ?
                """,
                (
                    generation,
                    content,
                    digest,
                    len(content),
                    correlation_text,
                    _timestamp_text(timestamp),
                    bucket,
                    name,
                ),
            )
        return StorageObjectMetadata(
            bucket=bucket,
            name=name,
            generation=generation,
            content_sha256=digest,
            size=len(content),
            correlation_items=_correlation_items(correlation),
            observed_at=timestamp,
        )

    @staticmethod
    def _metadata_from_row(row: sqlite3.Row) -> StorageObjectMetadata:
        return StorageObjectMetadata(
            bucket=row["bucket"],
            name=row["name"],
            generation=row["generation"],
            content_sha256=row["content_sha256"],
            size=row["size"],
            correlation_items=_correlation_from_text(row["correlation_json"]),
            observed_at=_timestamp_from_text(row["observed_at"]),
        )

    @staticmethod
    def _receipt_from_row(row: sqlite3.Row) -> StorageGenerationReceipt:
        return StorageGenerationReceipt(
            operation_id=row["operation_id"],
            bucket=row["bucket"],
            name=row["name"],
            generation=row["generation"],
            content_sha256=row["content_sha256"],
            size=row["size"],
            correlation_sha256=row["correlation_sha256"],
            observed_at=_timestamp_from_text(row["observed_at"]),
        )

    @staticmethod
    def _receipt_binds_metadata(
        receipt: StorageGenerationReceipt,
        metadata: StorageObjectMetadata,
    ) -> bool:
        return (
            receipt.bucket == metadata.bucket
            and receipt.name == metadata.name
            and receipt.generation == metadata.generation
            and receipt.content_sha256 == metadata.content_sha256
            and receipt.size == metadata.size
            and receipt.correlation_sha256 == correlation_sha256(metadata.correlation)
            and receipt.observed_at == metadata.observed_at
        )

    def read_metadata(self, *, bucket: str, name: str) -> StorageObjectMetadata | None:
        """Read current metadata without selecting the stored content column."""

        _validate_coordinate(bucket, "bucket")
        _validate_coordinate(name, "object name")
        connection = self._connect()
        try:
            row = connection.execute(
                """
                SELECT
                    bucket,
                    name,
                    generation,
                    content_sha256,
                    size,
                    correlation_json,
                    observed_at
                FROM storage_objects
                WHERE bucket = ? AND name = ?
                """,
                (bucket, name),
            ).fetchone()
        finally:
            connection.close()
        return None if row is None else self._metadata_from_row(row)

    def read_receipt(self, *, operation_id: str) -> StorageGenerationReceipt | None:
        """Read the immutable receipt selected by its operation identifier."""

        _validate_coordinate(operation_id, "operation identifier")
        connection = self._connect()
        try:
            row = connection.execute(
                """
                SELECT
                    operation_id,
                    bucket,
                    name,
                    generation,
                    content_sha256,
                    size,
                    correlation_sha256,
                    observed_at
                FROM operation_receipts
                WHERE operation_id = ?
                """,
                (operation_id,),
            ).fetchone()
        finally:
            connection.close()
        return None if row is None else self._receipt_from_row(row)

    def read_object_with_receipt(
        self,
        *,
        bucket: str,
        name: str,
        operation_id: str,
    ) -> StorageReadback:
        """Read object metadata and its operation receipt from one snapshot."""

        _validate_coordinate(bucket, "bucket")
        _validate_coordinate(name, "object name")
        _validate_coordinate(operation_id, "operation identifier")
        connection = self._connect()
        try:
            connection.execute("BEGIN")
            object_row = connection.execute(
                """
                SELECT
                    bucket,
                    name,
                    generation,
                    content_sha256,
                    size,
                    correlation_json,
                    observed_at
                FROM storage_objects
                WHERE bucket = ? AND name = ?
                """,
                (bucket, name),
            ).fetchone()
            receipt_row = connection.execute(
                """
                SELECT
                    operation_id,
                    bucket,
                    name,
                    generation,
                    content_sha256,
                    size,
                    correlation_sha256,
                    observed_at
                FROM operation_receipts
                WHERE operation_id = ?
                """,
                (operation_id,),
            ).fetchone()
            connection.commit()
        except BaseException:
            connection.rollback()
            raise
        finally:
            connection.close()
        return StorageReadback(
            object_metadata=(
                None if object_row is None else self._metadata_from_row(object_row)
            ),
            receipt=(
                None if receipt_row is None else self._receipt_from_row(receipt_row)
            ),
        )

    def count_owned(self, *, bucket: str, name: str, operation_id: str) -> int:
        """Count only the exact object and receipt selected by a cleanup manifest."""

        readback = self.read_object_with_receipt(
            bucket=bucket,
            name=name,
            operation_id=operation_id,
        )
        return int(readback.object_metadata is not None) + int(
            readback.receipt is not None
        )

    def delete_owned(
        self,
        *,
        bucket: str,
        name: str,
        operation_id: str,
    ) -> StorageDeletion:
        """Delete only one exact object coordinate and its exact receipt."""

        _validate_coordinate(bucket, "bucket")
        _validate_coordinate(name, "object name")
        _validate_coordinate(operation_id, "operation identifier")
        object_removed = False
        receipt_removed = False
        with self._write_transaction() as connection:
            receipt_row = connection.execute(
                """
                SELECT
                    operation_id,
                    bucket,
                    name,
                    generation,
                    content_sha256,
                    size,
                    correlation_sha256,
                    observed_at
                FROM operation_receipts
                WHERE operation_id = ?
                """,
                (operation_id,),
            ).fetchone()
            object_row = connection.execute(
                """
                SELECT
                    bucket,
                    name,
                    generation,
                    content_sha256,
                    size,
                    correlation_json,
                    observed_at
                FROM storage_objects
                WHERE bucket = ? AND name = ?
                """,
                (bucket, name),
            ).fetchone()
            if receipt_row is None:
                return StorageDeletion(
                    object_removed=False,
                    receipt_removed=False,
                )
            receipt = self._receipt_from_row(receipt_row)
            if receipt.bucket != bucket or receipt.name != name:
                raise StorageOwnershipError(
                    "the operation receipt belongs to a different object"
                )
            if object_row is not None:
                metadata = self._metadata_from_row(object_row)
                if not self._receipt_binds_metadata(receipt, metadata):
                    raise StorageOwnershipError(
                        "the operation receipt does not bind the current object "
                        "generation"
                    )
                object_cursor = connection.execute(
                    """
                    DELETE FROM storage_objects
                    WHERE bucket = ? AND name = ? AND generation = ?
                    """,
                    (bucket, name, receipt.generation),
                )
                if object_cursor.rowcount != 1:
                    raise LocalStorageError(
                        "the exact object generation changed during cleanup"
                    )
                object_removed = True
            receipt_cursor = connection.execute(
                "DELETE FROM operation_receipts WHERE operation_id = ?",
                (operation_id,),
            )
            if receipt_cursor.rowcount != 1:
                raise LocalStorageError(
                    "the exact operation receipt changed during cleanup"
                )
            receipt_removed = True
        return StorageDeletion(
            object_removed=object_removed,
            receipt_removed=receipt_removed,
        )

    def harness_corrupt_receipt(
        self,
        *,
        operation_id: str,
        bucket: str | None = None,
        name: str | None = None,
        generation: int | None = None,
        content_sha256: str | None = None,
        size: int | None = None,
        correlation_digest: str | None = None,
        observed_at: datetime | None = None,
    ) -> None:
        """Alter receipt fields solely for deterministic negative-control cases."""

        _validate_coordinate(operation_id, "operation identifier")
        updates: dict[str, object] = {}
        if bucket is not None:
            _validate_coordinate(bucket, "bucket")
            updates["bucket"] = bucket
        if name is not None:
            _validate_coordinate(name, "object name")
            updates["name"] = name
        if generation is not None:
            _validate_generation(generation)
            updates["generation"] = generation
        if content_sha256 is not None:
            _validate_sha256(content_sha256, "content digest")
            updates["content_sha256"] = content_sha256
        if size is not None:
            if type(size) is not int or size < 0:
                raise ValueError("receipt size must be a nonnegative integer")
            updates["size"] = size
        if correlation_digest is not None:
            _validate_sha256(correlation_digest, "correlation digest")
            updates["correlation_sha256"] = correlation_digest
        if observed_at is not None:
            updates["observed_at"] = _timestamp_text(observed_at)
        if not updates:
            raise ValueError("receipt corruption requires at least one field")
        assignments = ", ".join(f"{column} = ?" for column in updates)
        values = [*updates.values(), operation_id]
        with self._write_transaction() as connection:
            cursor = connection.execute(
                f"UPDATE operation_receipts SET {assignments} WHERE operation_id = ?",
                values,
            )
            if cursor.rowcount != 1:
                raise StorageReceiptNotFound(
                    "the receipt selected for corruption is absent"
                )

    def harness_corrupt_object_metadata(
        self,
        *,
        bucket: str,
        name: str,
        content_sha256: str | None = None,
        size: int | None = None,
        correlation: Mapping[str, str] | None = None,
        observed_at: datetime | None = None,
    ) -> None:
        """Alter object metadata solely for deterministic negative-control cases."""

        _validate_coordinate(bucket, "bucket")
        _validate_coordinate(name, "object name")
        updates: dict[str, object] = {}
        if content_sha256 is not None:
            _validate_sha256(content_sha256, "content digest")
            updates["content_sha256"] = content_sha256
        if size is not None:
            if type(size) is not int or size < 0:
                raise ValueError("object size must be a nonnegative integer")
            updates["size"] = size
        if correlation is not None:
            updates["correlation_json"] = _correlation_text(correlation)
        if observed_at is not None:
            updates["observed_at"] = _timestamp_text(observed_at)
        if not updates:
            raise ValueError("object corruption requires at least one field")
        assignments = ", ".join(f"{column} = ?" for column in updates)
        values = [*updates.values(), bucket, name]
        with self._write_transaction() as connection:
            cursor = connection.execute(
                f"""
                UPDATE storage_objects
                SET {assignments}
                WHERE bucket = ? AND name = ?
                """,
                values,
            )
            if cursor.rowcount != 1:
                raise StorageObjectNotFound(
                    "the object selected for corruption is absent"
                )

    def harness_delete_receipt(self, *, operation_id: str) -> bool:
        """Remove one receipt solely for deterministic negative-control cases."""

        _validate_coordinate(operation_id, "operation identifier")
        with self._write_transaction() as connection:
            cursor = connection.execute(
                "DELETE FROM operation_receipts WHERE operation_id = ?",
                (operation_id,),
            )
        return cursor.rowcount == 1

    def harness_delete_object(self, *, bucket: str, name: str) -> bool:
        """Remove one object solely for deterministic negative-control cases."""

        _validate_coordinate(bucket, "bucket")
        _validate_coordinate(name, "object name")
        with self._write_transaction() as connection:
            cursor = connection.execute(
                "DELETE FROM storage_objects WHERE bucket = ? AND name = ?",
                (bucket, name),
            )
        return cursor.rowcount == 1


class LocalStorageMutationTarget:
    """Mutation-only handle that never returns target generation or receipt state."""

    def __init__(
        self,
        database_path: str | Path,
        *,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        self._database = _LocalStorageDatabase(database_path)
        self._clock = clock or _utc_now

    @property
    def database_path(self) -> Path:
        return self._database.database_path

    def initialize(self) -> None:
        self._database.initialize()

    def commit_object(
        self,
        *,
        operation_id: str,
        bucket: str,
        name: str,
        content: bytes,
        correlation: Mapping[str, str],
    ) -> None:
        """Commit an object and private receipt without returning either record."""

        committed_at = _aware_utc(self._clock())
        self._database.create_object_with_receipt(
            operation_id=operation_id,
            bucket=bucket,
            name=name,
            content=content,
            correlation=correlation,
            observed_at=committed_at,
        )


class LocalStorageReadTarget:
    """Receipt-capable handle restricted to the allowlisted read adapter."""

    def __init__(self, database_path: str | Path) -> None:
        self._database = _LocalStorageDatabase(database_path)

    @property
    def database_path(self) -> Path:
        return self._database.database_path

    def read(
        self,
        *,
        bucket: str,
        name: str,
        operation_id: str,
    ) -> StorageReadback:
        return self._database.read_object_with_receipt(
            bucket=bucket,
            name=name,
            operation_id=operation_id,
        )


class LocalStorageCleanupTarget:
    """Cleanup-only handle with receipt-bound ownership verification."""

    def __init__(self, database_path: str | Path) -> None:
        self._database = _LocalStorageDatabase(database_path)

    def count_owned(self, *, bucket: str, name: str, operation_id: str) -> int:
        return self._database.count_owned(
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
        return self._database.delete_owned(
            bucket=bucket,
            name=name,
            operation_id=operation_id,
        )


class LocalStorageHarness(_LocalStorageDatabase):
    """Test-only target inspection and corruption controls."""


__all__ = [
    "LocalStorageCleanupTarget",
    "LocalStorageError",
    "LocalStorageHarness",
    "LocalStorageMutationTarget",
    "LocalStorageReadTarget",
    "StorageCleanupPort",
    "StorageDeletion",
    "StorageGenerationReceipt",
    "StorageMutationPort",
    "StorageObjectAlreadyExists",
    "StorageObjectMetadata",
    "StorageObjectNotFound",
    "StorageOwnershipError",
    "StorageReadPort",
    "StorageReadback",
    "StorageReceiptAlreadyExists",
    "StorageReceiptNotFound",
    "correlation_sha256",
    "storage_correlation_items",
]
