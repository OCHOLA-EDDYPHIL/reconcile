"""SQLite-backed business documents used by local scenario targets."""

from __future__ import annotations

import hashlib
import json
import re
import sqlite3
from collections.abc import Callable, Iterator, Mapping
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path

_SQLITE_TIMEOUT_SECONDS = 30.0
_EFFECT_COUNT = 3
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

type EffectDeclaration = tuple[str, str, str, str]


class LocalFirestoreError(RuntimeError):
    """Base error for the local business-document target."""


class FirestoreResourceAlreadyExists(LocalFirestoreError):
    """A create-only manifest or document coordinate is occupied."""


class FirestoreResourceNotFound(LocalFirestoreError):
    """A requested manifest or document does not exist."""


class FirestoreOwnershipError(LocalFirestoreError):
    """Current records do not match the operation manifest's ownership data."""


class BusinessOperationStatus(StrEnum):
    """Target-native lifecycle state for a multi-step business operation."""

    ACTIVE = "ACTIVE"
    TERMINAL_COMMITTED = "TERMINAL_COMMITTED"
    TERMINAL_NOT_COMMITTED = "TERMINAL_NOT_COMMITTED"


@dataclass(frozen=True, slots=True)
class BusinessDocumentCoordinate:
    """One expected business-effect document coordinate."""

    effect_id: str
    collection_name: str
    document_id: str

    def __post_init__(self) -> None:
        _validate_coordinate(self.effect_id, "effect identifier")
        _validate_coordinate(self.collection_name, "collection name")
        _validate_coordinate(self.document_id, "document identifier")


@dataclass(frozen=True, slots=True)
class BusinessDocumentWrite:
    """Immutable content and coordinate for one requested effect write."""

    effect_id: str
    collection_name: str
    document_id: str
    content: bytes

    def __post_init__(self) -> None:
        BusinessDocumentCoordinate(
            effect_id=self.effect_id,
            collection_name=self.collection_name,
            document_id=self.document_id,
        )
        if type(self.content) is not bytes:
            raise TypeError("business document content must be immutable bytes")

    @property
    def coordinate(self) -> BusinessDocumentCoordinate:
        return BusinessDocumentCoordinate(
            effect_id=self.effect_id,
            collection_name=self.collection_name,
            document_id=self.document_id,
        )

    @property
    def content_sha256(self) -> str:
        return hashlib.sha256(self.content).hexdigest()


@dataclass(frozen=True, slots=True)
class BusinessDocument:
    """Metadata read for one separately committed business effect."""

    effect_id: str
    collection_name: str
    document_id: str
    operation_id: str
    revision: int
    content_sha256: str
    correlation_items: tuple[tuple[str, str], ...]
    observed_at: datetime

    def __post_init__(self) -> None:
        BusinessDocumentCoordinate(
            effect_id=self.effect_id,
            collection_name=self.collection_name,
            document_id=self.document_id,
        )
        _validate_coordinate(self.operation_id, "operation identifier")
        _validate_revision(self.revision)
        _validate_sha256(self.content_sha256, "content digest")
        if type(self.correlation_items) is not tuple:
            raise TypeError("correlation items must be an immutable tuple")
        if _correlation_items(dict(self.correlation_items)) != self.correlation_items:
            raise ValueError("correlation items must be unique and canonically ordered")
        object.__setattr__(self, "observed_at", _aware_utc(self.observed_at))

    @property
    def coordinate(self) -> BusinessDocumentCoordinate:
        return BusinessDocumentCoordinate(
            effect_id=self.effect_id,
            collection_name=self.collection_name,
            document_id=self.document_id,
        )

    @property
    def correlation(self) -> dict[str, str]:
        """Return an isolated copy of the document correlation fields."""

        return dict(self.correlation_items)


@dataclass(frozen=True, slots=True)
class BusinessOperationManifest:
    """Target-native receipt and effect partition for one operation."""

    namespace_id: str
    operation_id: str
    manifest_collection: str
    manifest_document_id: str
    status: BusinessOperationStatus
    revision: int
    expected_effect_ids: tuple[str, ...]
    expected_effects_sha256: str
    established_effect_ids: tuple[str, ...]
    not_established_effect_ids: tuple[str, ...]
    effect_revision_items: tuple[tuple[str, int], ...]
    correlation_items: tuple[tuple[str, str], ...]
    observed_at: datetime

    def __post_init__(self) -> None:
        _validate_coordinate(self.namespace_id, "namespace identifier")
        _validate_coordinate(self.operation_id, "operation identifier")
        _validate_coordinate(self.manifest_collection, "manifest collection")
        _validate_coordinate(self.manifest_document_id, "manifest document identifier")
        if type(self.status) is not BusinessOperationStatus:
            raise TypeError("manifest status must be a business operation status")
        _validate_revision(self.revision)
        expected = _effect_ids(self.expected_effect_ids, require_count=True)
        established = _effect_ids(self.established_effect_ids, require_count=False)
        not_established = _effect_ids(
            self.not_established_effect_ids,
            require_count=False,
        )
        _validate_sha256(self.expected_effects_sha256, "expected-effects digest")
        if not set(established).issubset(expected):
            raise ValueError("established effects must be expected effects")
        if not set(not_established).issubset(expected):
            raise ValueError("not-established effects must be expected effects")
        if set(established).intersection(not_established):
            raise ValueError("manifest effect partitions must be disjoint")
        if type(self.effect_revision_items) is not tuple:
            raise TypeError("effect revisions must be an immutable tuple")
        revision_effects: list[str] = []
        for effect_id, revision in self.effect_revision_items:
            _validate_coordinate(effect_id, "effect identifier")
            _validate_revision(revision)
            revision_effects.append(effect_id)
        if len(revision_effects) != len(set(revision_effects)):
            raise ValueError("effect revisions must have unique effect identifiers")
        if tuple(revision_effects) != established:
            raise ValueError("effect revisions must match established-effect order")
        if any(revision > self.revision for _, revision in self.effect_revision_items):
            raise ValueError("effect revisions cannot exceed the manifest revision")
        if self.status is BusinessOperationStatus.ACTIVE:
            if not_established:
                raise ValueError("an active manifest cannot affirm non-establishment")
        elif self.status is BusinessOperationStatus.TERMINAL_COMMITTED:
            if not established:
                raise ValueError("a committed terminal manifest needs an effect")
            if set(established).union(not_established) != set(expected):
                raise ValueError("a terminal manifest must partition every effect")
        elif self.status is BusinessOperationStatus.TERMINAL_NOT_COMMITTED:
            if established or tuple(not_established) != expected:
                raise ValueError(
                    "a not-committed terminal manifest must reject every effect"
                )
        if type(self.correlation_items) is not tuple:
            raise TypeError("correlation items must be an immutable tuple")
        if _correlation_items(dict(self.correlation_items)) != self.correlation_items:
            raise ValueError("correlation items must be unique and canonically ordered")
        object.__setattr__(self, "observed_at", _aware_utc(self.observed_at))

    @property
    def effect_revisions(self) -> dict[str, int]:
        """Return an isolated copy of established effect revisions."""

        return dict(self.effect_revision_items)

    @property
    def correlation(self) -> dict[str, str]:
        """Return an isolated copy of operation correlation fields."""

        return dict(self.correlation_items)


@dataclass(frozen=True, slots=True)
class BusinessOperationReadback:
    """One-snapshot manifest and operation-correlated document metadata."""

    manifest: BusinessOperationManifest | None
    documents: tuple[BusinessDocument, ...]

    def __post_init__(self) -> None:
        if (
            self.manifest is not None
            and type(self.manifest) is not BusinessOperationManifest
        ):
            raise TypeError("readback manifest has an invalid type")
        if type(self.documents) is not tuple or any(
            type(document) is not BusinessDocument for document in self.documents
        ):
            raise TypeError("readback documents must be an immutable document tuple")


@dataclass(frozen=True, slots=True)
class BusinessOperationDeletion:
    """Manifest-owned records removed by one cleanup attempt."""

    removed_documents: tuple[BusinessDocumentCoordinate, ...]
    manifest_removed: bool

    def __post_init__(self) -> None:
        if type(self.removed_documents) is not tuple or any(
            type(item) is not BusinessDocumentCoordinate
            for item in self.removed_documents
        ):
            raise TypeError("removed documents must be an immutable coordinate tuple")
        if len(self.removed_documents) != len(set(self.removed_documents)):
            raise ValueError("removed document coordinates must be unique")
        if type(self.manifest_removed) is not bool:
            raise TypeError("manifest removal flag must be a boolean")

    @property
    def removed_count(self) -> int:
        return len(self.removed_documents) + int(self.manifest_removed)


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


def _validate_revision(value: int) -> None:
    if type(value) is not int or not 1 <= value < 2**63:
        raise ValueError("revision must be a positive signed 64-bit integer")


def _validate_sha256(value: str, label: str) -> None:
    if type(value) is not str or _SHA256_PATTERN.fullmatch(value) is None:
        raise ValueError(f"{label} must be a lowercase SHA-256 digest")


def _aware_utc(value: datetime) -> datetime:
    if not isinstance(value, datetime) or value.tzinfo is None:
        raise ValueError("target timestamps must include a UTC offset")
    if value.utcoffset() is None:
        raise ValueError("target timestamps must include a UTC offset")
    return value.astimezone(UTC)


def _timestamp_text(value: datetime) -> str:
    return _aware_utc(value).isoformat(timespec="microseconds")


def _timestamp_from_text(value: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(value)
    except (TypeError, ValueError) as error:
        raise LocalFirestoreError("stored timestamp is malformed") from error
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


def _json_text(value: object) -> str:
    return json.dumps(
        value,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    )


def _correlation_text(correlation: Mapping[str, str]) -> str:
    return _json_text(dict(_correlation_items(correlation)))


def _correlation_from_text(value: str) -> tuple[tuple[str, str], ...]:
    try:
        decoded = json.loads(value)
    except (TypeError, ValueError) as error:
        raise LocalFirestoreError("stored correlation metadata is malformed") from error
    if not isinstance(decoded, dict):
        raise LocalFirestoreError("stored correlation metadata is malformed")
    try:
        return _correlation_items(decoded)
    except (TypeError, ValueError) as error:
        raise LocalFirestoreError("stored correlation metadata is malformed") from error


def _effect_ids(
    values: tuple[str, ...],
    *,
    require_count: bool,
) -> tuple[str, ...]:
    if type(values) is not tuple:
        raise TypeError("effect identifiers must be an immutable tuple")
    if require_count and len(values) != _EFFECT_COUNT:
        raise ValueError("the business operation requires exactly three effects")
    if not require_count and len(values) > _EFFECT_COUNT:
        raise ValueError("the effect subset exceeds the declared effects")
    for value in values:
        _validate_coordinate(value, "effect identifier")
    if len(values) != len(set(values)):
        raise ValueError("effect identifiers must be unique")
    return values


def _effect_ids_text(values: tuple[str, ...]) -> str:
    _effect_ids(values, require_count=False)
    return _json_text(list(values))


def _effect_ids_from_text(value: str) -> tuple[str, ...]:
    try:
        decoded = json.loads(value)
    except (TypeError, ValueError) as error:
        raise LocalFirestoreError("stored effect identifiers are malformed") from error
    if not isinstance(decoded, list) or any(type(item) is not str for item in decoded):
        raise LocalFirestoreError("stored effect identifiers are malformed")
    try:
        return _effect_ids(tuple(decoded), require_count=False)
    except (TypeError, ValueError) as error:
        raise LocalFirestoreError("stored effect identifiers are malformed") from error


def _effect_revision_items_text(values: tuple[tuple[str, int], ...]) -> str:
    return _json_text([[effect_id, revision] for effect_id, revision in values])


def _effect_revision_items_from_text(value: str) -> tuple[tuple[str, int], ...]:
    try:
        decoded = json.loads(value)
    except (TypeError, ValueError) as error:
        raise LocalFirestoreError("stored effect revisions are malformed") from error
    if not isinstance(decoded, list):
        raise LocalFirestoreError("stored effect revisions are malformed")
    items: list[tuple[str, int]] = []
    try:
        for item in decoded:
            if not isinstance(item, list) or len(item) != 2:
                raise ValueError
            effect_id, revision = item
            _validate_coordinate(effect_id, "effect identifier")
            _validate_revision(revision)
            items.append((effect_id, revision))
    except (TypeError, ValueError) as error:
        raise LocalFirestoreError("stored effect revisions are malformed") from error
    if len({effect_id for effect_id, _ in items}) != len(items):
        raise LocalFirestoreError("stored effect revisions are malformed")
    return tuple(items)


def _document_coordinates(
    values: tuple[BusinessDocumentCoordinate, ...],
) -> tuple[BusinessDocumentCoordinate, ...]:
    if type(values) is not tuple or any(
        type(value) is not BusinessDocumentCoordinate for value in values
    ):
        raise TypeError("document coordinates must be an immutable coordinate tuple")
    if len(values) != _EFFECT_COUNT:
        raise ValueError("the business operation requires exactly three coordinates")
    if len({value.effect_id for value in values}) != len(values):
        raise ValueError("document coordinate effect identifiers must be unique")
    physical = {(value.collection_name, value.document_id) for value in values}
    if len(physical) != len(values):
        raise ValueError("document coordinates must be physically unique")
    return values


def _document_writes(
    values: tuple[BusinessDocumentWrite, ...],
) -> tuple[BusinessDocumentWrite, ...]:
    if type(values) is not tuple or any(
        type(value) is not BusinessDocumentWrite for value in values
    ):
        raise TypeError("document writes must be an immutable write tuple")
    _document_coordinates(tuple(value.coordinate for value in values))
    return values


def _declarations_from_writes(
    documents: tuple[BusinessDocumentWrite, ...],
) -> tuple[EffectDeclaration, ...]:
    documents = _document_writes(documents)
    return tuple(
        (
            document.effect_id,
            document.collection_name,
            document.document_id,
            document.content_sha256,
        )
        for document in documents
    )


def _validate_declarations(
    declarations: tuple[EffectDeclaration, ...],
) -> tuple[EffectDeclaration, ...]:
    if type(declarations) is not tuple or len(declarations) != _EFFECT_COUNT:
        raise ValueError("expected-effect declarations must contain three entries")
    coordinates: list[BusinessDocumentCoordinate] = []
    for declaration in declarations:
        if type(declaration) is not tuple or len(declaration) != 4:
            raise TypeError("expected-effect declarations must be four-item tuples")
        effect_id, collection_name, document_id, content_sha256 = declaration
        coordinates.append(
            BusinessDocumentCoordinate(
                effect_id=effect_id,
                collection_name=collection_name,
                document_id=document_id,
            )
        )
        _validate_sha256(content_sha256, "content digest")
    _document_coordinates(tuple(coordinates))
    return declarations


def expected_effect_declarations_sha256(
    declarations: tuple[EffectDeclaration, ...],
) -> str:
    """Hash ordered effect declarations without requiring document content."""

    declarations = _validate_declarations(declarations)
    payload = [
        {
            "effect_id": effect_id,
            "collection_name": collection_name,
            "document_id": document_id,
            "content_sha256": content_sha256,
        }
        for effect_id, collection_name, document_id, content_sha256 in declarations
    ]
    return hashlib.sha256(_json_text(payload).encode("utf-8")).hexdigest()


def expected_effects_sha256(
    documents: tuple[BusinessDocumentWrite, ...],
) -> str:
    """Hash the ordered declarations for three requested document writes."""

    return expected_effect_declarations_sha256(_declarations_from_writes(documents))


def _declarations_text(declarations: tuple[EffectDeclaration, ...]) -> str:
    declarations = _validate_declarations(declarations)
    return _json_text([list(declaration) for declaration in declarations])


def _declarations_from_text(value: str) -> tuple[EffectDeclaration, ...]:
    try:
        decoded = json.loads(value)
    except (TypeError, ValueError) as error:
        raise LocalFirestoreError("stored effect declarations are malformed") from error
    if not isinstance(decoded, list):
        raise LocalFirestoreError("stored effect declarations are malformed")
    try:
        declarations = tuple(tuple(item) for item in decoded)
        return _validate_declarations(declarations)  # type: ignore[arg-type]
    except (TypeError, ValueError) as error:
        raise LocalFirestoreError("stored effect declarations are malformed") from error


def _coordinates_from_declarations(
    declarations: tuple[EffectDeclaration, ...],
) -> tuple[BusinessDocumentCoordinate, ...]:
    return tuple(
        BusinessDocumentCoordinate(
            effect_id=effect_id,
            collection_name=collection_name,
            document_id=document_id,
        )
        for effect_id, collection_name, document_id, _ in declarations
    )


class _LocalFirestoreDatabase:
    def __init__(self, database_path: str | Path) -> None:
        path = Path(database_path)
        if str(path) == ":memory:":
            raise ValueError("the local document target requires a disk database")
        path.parent.mkdir(parents=True, exist_ok=True)
        if path.exists() and path.is_dir():
            raise ValueError("the local document database path is a directory")
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
        connection = self._connect()
        try:
            connection.execute("PRAGMA journal_mode = WAL")
            connection.execute("PRAGMA synchronous = FULL")
            connection.execute("BEGIN IMMEDIATE")
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS assigned_revisions (
                    revision INTEGER PRIMARY KEY AUTOINCREMENT,
                    observed_at TEXT NOT NULL
                )
                """
            )
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS business_documents (
                    namespace_id TEXT NOT NULL,
                    collection_name TEXT NOT NULL,
                    document_id TEXT NOT NULL,
                    effect_id TEXT NOT NULL,
                    operation_id TEXT NOT NULL,
                    revision INTEGER NOT NULL UNIQUE,
                    content BLOB NOT NULL,
                    content_sha256 TEXT NOT NULL,
                    correlation_json TEXT NOT NULL,
                    observed_at TEXT NOT NULL,
                    PRIMARY KEY (namespace_id, collection_name, document_id)
                )
                """
            )
            connection.execute(
                """
                CREATE INDEX IF NOT EXISTS business_documents_operation
                ON business_documents (namespace_id, operation_id)
                """
            )
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS operation_manifests (
                    namespace_id TEXT NOT NULL,
                    operation_id TEXT NOT NULL,
                    manifest_collection TEXT NOT NULL,
                    manifest_document_id TEXT NOT NULL,
                    status TEXT NOT NULL,
                    revision INTEGER NOT NULL UNIQUE,
                    expected_effect_ids_json TEXT NOT NULL,
                    expected_effects_sha256 TEXT NOT NULL,
                    expected_effects_json TEXT NOT NULL,
                    established_effect_ids_json TEXT NOT NULL,
                    not_established_effect_ids_json TEXT NOT NULL,
                    effect_revisions_json TEXT NOT NULL,
                    correlation_json TEXT NOT NULL,
                    observed_at TEXT NOT NULL,
                    PRIMARY KEY (namespace_id, operation_id),
                    UNIQUE (
                        namespace_id,
                        manifest_collection,
                        manifest_document_id
                    )
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
    def _next_revision(
        connection: sqlite3.Connection,
        observed_at: datetime,
    ) -> int:
        cursor = connection.execute(
            "INSERT INTO assigned_revisions (observed_at) VALUES (?)",
            (_timestamp_text(observed_at),),
        )
        revision = cursor.lastrowid
        if revision is None:
            raise LocalFirestoreError("target revision allocation failed")
        _validate_revision(revision)
        return revision

    @staticmethod
    def _document_from_row(row: sqlite3.Row) -> BusinessDocument:
        return BusinessDocument(
            effect_id=row["effect_id"],
            collection_name=row["collection_name"],
            document_id=row["document_id"],
            operation_id=row["operation_id"],
            revision=row["revision"],
            content_sha256=row["content_sha256"],
            correlation_items=_correlation_from_text(row["correlation_json"]),
            observed_at=_timestamp_from_text(row["observed_at"]),
        )

    @staticmethod
    def _manifest_from_row(row: sqlite3.Row) -> BusinessOperationManifest:
        try:
            status = BusinessOperationStatus(row["status"])
        except (TypeError, ValueError) as error:
            raise LocalFirestoreError("stored manifest status is malformed") from error
        expected_effect_ids = _effect_ids_from_text(row["expected_effect_ids_json"])
        if len(expected_effect_ids) != _EFFECT_COUNT:
            raise LocalFirestoreError("stored expected effects are malformed")
        try:
            return BusinessOperationManifest(
                namespace_id=row["namespace_id"],
                operation_id=row["operation_id"],
                manifest_collection=row["manifest_collection"],
                manifest_document_id=row["manifest_document_id"],
                status=status,
                revision=row["revision"],
                expected_effect_ids=expected_effect_ids,
                expected_effects_sha256=row["expected_effects_sha256"],
                established_effect_ids=_effect_ids_from_text(
                    row["established_effect_ids_json"]
                ),
                not_established_effect_ids=_effect_ids_from_text(
                    row["not_established_effect_ids_json"]
                ),
                effect_revision_items=_effect_revision_items_from_text(
                    row["effect_revisions_json"]
                ),
                correlation_items=_correlation_from_text(row["correlation_json"]),
                observed_at=_timestamp_from_text(row["observed_at"]),
            )
        except (TypeError, ValueError) as error:
            raise LocalFirestoreError(
                "stored operation manifest is malformed"
            ) from error

    def create_active_manifest(
        self,
        *,
        namespace_id: str,
        operation_id: str,
        manifest_collection: str,
        manifest_document_id: str,
        documents: tuple[BusinessDocumentWrite, ...],
        correlation: Mapping[str, str],
        observed_at: datetime,
    ) -> None:
        documents = _document_writes(documents)
        declarations = _declarations_from_writes(documents)
        expected_ids = tuple(document.effect_id for document in documents)
        correlation_text = _correlation_text(correlation)
        timestamp = _aware_utc(observed_at)
        with self._write_transaction() as connection:
            manifest_exists = connection.execute(
                """
                SELECT 1
                FROM operation_manifests
                WHERE namespace_id = ?
                  AND (
                    operation_id = ?
                    OR (
                        manifest_collection = ?
                        AND manifest_document_id = ?
                    )
                  )
                """,
                (
                    namespace_id,
                    operation_id,
                    manifest_collection,
                    manifest_document_id,
                ),
            ).fetchone()
            if manifest_exists is not None:
                raise FirestoreResourceAlreadyExists(
                    "the operation manifest coordinate is already occupied"
                )
            for document in documents:
                occupied = connection.execute(
                    """
                    SELECT 1
                    FROM business_documents
                    WHERE namespace_id = ?
                      AND collection_name = ?
                      AND document_id = ?
                    """,
                    (
                        namespace_id,
                        document.collection_name,
                        document.document_id,
                    ),
                ).fetchone()
                if occupied is not None:
                    raise FirestoreResourceAlreadyExists(
                        "an expected document coordinate is already occupied"
                    )
            revision = self._next_revision(connection, timestamp)
            connection.execute(
                """
                INSERT INTO operation_manifests (
                    namespace_id,
                    operation_id,
                    manifest_collection,
                    manifest_document_id,
                    status,
                    revision,
                    expected_effect_ids_json,
                    expected_effects_sha256,
                    expected_effects_json,
                    established_effect_ids_json,
                    not_established_effect_ids_json,
                    effect_revisions_json,
                    correlation_json,
                    observed_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    namespace_id,
                    operation_id,
                    manifest_collection,
                    manifest_document_id,
                    BusinessOperationStatus.ACTIVE.value,
                    revision,
                    _effect_ids_text(expected_ids),
                    expected_effect_declarations_sha256(declarations),
                    _declarations_text(declarations),
                    _effect_ids_text(()),
                    _effect_ids_text(()),
                    _effect_revision_items_text(()),
                    correlation_text,
                    _timestamp_text(timestamp),
                ),
            )

    def commit_effect(
        self,
        *,
        namespace_id: str,
        operation_id: str,
        document: BusinessDocumentWrite,
        terminal: bool,
        observed_at: datetime,
    ) -> None:
        if type(document) is not BusinessDocumentWrite:
            raise TypeError("effect commit requires an exact document write")
        if type(terminal) is not bool:
            raise TypeError("terminal effect flag must be a boolean")
        timestamp = _aware_utc(observed_at)
        with self._write_transaction() as connection:
            row = connection.execute(
                """
                SELECT *
                FROM operation_manifests
                WHERE namespace_id = ? AND operation_id = ?
                """,
                (namespace_id, operation_id),
            ).fetchone()
            if row is None:
                raise FirestoreResourceNotFound(
                    "effect commit requires an active operation manifest"
                )
            manifest = self._manifest_from_row(row)
            if manifest.status is not BusinessOperationStatus.ACTIVE:
                raise FirestoreOwnershipError(
                    "effect commit requires an active operation manifest"
                )
            declarations = _declarations_from_text(row["expected_effects_json"])
            expected_by_id = {
                declaration[0]: declaration for declaration in declarations
            }
            declaration = expected_by_id.get(document.effect_id)
            if declaration is None or declaration != (
                document.effect_id,
                document.collection_name,
                document.document_id,
                document.content_sha256,
            ):
                raise FirestoreOwnershipError(
                    "effect write does not match the operation declaration"
                )
            if document.effect_id in manifest.established_effect_ids:
                raise FirestoreResourceAlreadyExists(
                    "the business effect is already established"
                )
            occupied = connection.execute(
                """
                SELECT 1
                FROM business_documents
                WHERE namespace_id = ?
                  AND collection_name = ?
                  AND document_id = ?
                """,
                (
                    namespace_id,
                    document.collection_name,
                    document.document_id,
                ),
            ).fetchone()
            if occupied is not None:
                raise FirestoreResourceAlreadyExists(
                    "the effect document coordinate is already occupied"
                )
            revision = self._next_revision(connection, timestamp)
            connection.execute(
                """
                INSERT INTO business_documents (
                    namespace_id,
                    collection_name,
                    document_id,
                    effect_id,
                    operation_id,
                    revision,
                    content,
                    content_sha256,
                    correlation_json,
                    observed_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    namespace_id,
                    document.collection_name,
                    document.document_id,
                    document.effect_id,
                    operation_id,
                    revision,
                    document.content,
                    document.content_sha256,
                    row["correlation_json"],
                    _timestamp_text(timestamp),
                ),
            )
            established = (*manifest.established_effect_ids, document.effect_id)
            effect_revisions = (
                *manifest.effect_revision_items,
                (document.effect_id, revision),
            )
            if terminal:
                not_established = tuple(
                    effect_id
                    for effect_id in manifest.expected_effect_ids
                    if effect_id not in established
                )
                status = BusinessOperationStatus.TERMINAL_COMMITTED
            else:
                not_established = ()
                status = BusinessOperationStatus.ACTIVE
            cursor = connection.execute(
                """
                UPDATE operation_manifests
                SET status = ?,
                    revision = ?,
                    established_effect_ids_json = ?,
                    not_established_effect_ids_json = ?,
                    effect_revisions_json = ?,
                    observed_at = ?
                WHERE namespace_id = ?
                  AND operation_id = ?
                  AND revision = ?
                  AND status = ?
                """,
                (
                    status.value,
                    revision,
                    _effect_ids_text(established),
                    _effect_ids_text(not_established),
                    _effect_revision_items_text(effect_revisions),
                    _timestamp_text(timestamp),
                    namespace_id,
                    operation_id,
                    manifest.revision,
                    BusinessOperationStatus.ACTIVE.value,
                ),
            )
            if cursor.rowcount != 1:
                raise LocalFirestoreError(
                    "the operation manifest changed during effect commit"
                )

    def terminalize_empty(
        self,
        *,
        namespace_id: str,
        operation_id: str,
        observed_at: datetime,
    ) -> None:
        timestamp = _aware_utc(observed_at)
        with self._write_transaction() as connection:
            row = connection.execute(
                """
                SELECT *
                FROM operation_manifests
                WHERE namespace_id = ? AND operation_id = ?
                """,
                (namespace_id, operation_id),
            ).fetchone()
            if row is None:
                raise FirestoreResourceNotFound(
                    "terminalization requires an active operation manifest"
                )
            manifest = self._manifest_from_row(row)
            if (
                manifest.status is not BusinessOperationStatus.ACTIVE
                or manifest.established_effect_ids
            ):
                raise FirestoreOwnershipError(
                    "empty terminalization requires an untouched active manifest"
                )
            revision = self._next_revision(connection, timestamp)
            cursor = connection.execute(
                """
                UPDATE operation_manifests
                SET status = ?,
                    revision = ?,
                    not_established_effect_ids_json = ?,
                    observed_at = ?
                WHERE namespace_id = ?
                  AND operation_id = ?
                  AND revision = ?
                  AND status = ?
                """,
                (
                    BusinessOperationStatus.TERMINAL_NOT_COMMITTED.value,
                    revision,
                    _effect_ids_text(manifest.expected_effect_ids),
                    _timestamp_text(timestamp),
                    namespace_id,
                    operation_id,
                    manifest.revision,
                    BusinessOperationStatus.ACTIVE.value,
                ),
            )
            if cursor.rowcount != 1:
                raise LocalFirestoreError(
                    "the operation manifest changed during terminalization"
                )

    def read(
        self,
        *,
        namespace_id: str,
        operation_id: str,
        manifest_collection: str,
        manifest_document_id: str,
        document_coordinates: tuple[BusinessDocumentCoordinate, ...],
    ) -> BusinessOperationReadback:
        _validate_coordinate(namespace_id, "namespace identifier")
        _validate_coordinate(operation_id, "operation identifier")
        _validate_coordinate(manifest_collection, "manifest collection")
        _validate_coordinate(manifest_document_id, "manifest document identifier")
        _document_coordinates(document_coordinates)
        connection = self._connect()
        try:
            connection.execute("BEGIN")
            manifest_row = connection.execute(
                """
                SELECT *
                FROM operation_manifests
                WHERE namespace_id = ?
                  AND operation_id = ?
                  AND manifest_collection = ?
                  AND manifest_document_id = ?
                """,
                (
                    namespace_id,
                    operation_id,
                    manifest_collection,
                    manifest_document_id,
                ),
            ).fetchone()
            document_rows = connection.execute(
                """
                SELECT
                    effect_id,
                    collection_name,
                    document_id,
                    operation_id,
                    revision,
                    content_sha256,
                    correlation_json,
                    observed_at
                FROM business_documents
                WHERE namespace_id = ? AND operation_id = ?
                ORDER BY collection_name, document_id, effect_id
                """,
                (namespace_id, operation_id),
            ).fetchall()
            connection.commit()
        except BaseException:
            connection.rollback()
            raise
        finally:
            connection.close()
        return BusinessOperationReadback(
            manifest=(
                None if manifest_row is None else self._manifest_from_row(manifest_row)
            ),
            documents=tuple(self._document_from_row(row) for row in document_rows),
        )

    @staticmethod
    def _assert_cleanup_document(
        *,
        document: BusinessDocument,
        declaration: EffectDeclaration,
        manifest: BusinessOperationManifest,
    ) -> None:
        effect_id, collection_name, document_id, content_sha256 = declaration
        expected_revision = manifest.effect_revisions.get(effect_id)
        if (
            document.effect_id != effect_id
            or document.collection_name != collection_name
            or document.document_id != document_id
            or document.operation_id != manifest.operation_id
            or document.revision != expected_revision
            or document.content_sha256 != content_sha256
            or document.correlation_items != manifest.correlation_items
            or document.observed_at > manifest.observed_at
        ):
            raise FirestoreOwnershipError(
                "the current document does not match the manifest-owned revision"
            )

    @staticmethod
    def _cleanup_manifest(
        row: sqlite3.Row,
        document_coordinates: tuple[BusinessDocumentCoordinate, ...],
    ) -> tuple[BusinessOperationManifest, tuple[EffectDeclaration, ...]]:
        manifest = _LocalFirestoreDatabase._manifest_from_row(row)
        declarations = _declarations_from_text(row["expected_effects_json"])
        if _coordinates_from_declarations(declarations) != document_coordinates:
            raise FirestoreOwnershipError(
                "cleanup coordinates do not match the operation manifest"
            )
        if expected_effect_declarations_sha256(declarations) != (
            manifest.expected_effects_sha256
        ):
            raise FirestoreOwnershipError(
                "the operation manifest declarations are inconsistent"
            )
        return manifest, declarations

    def count_owned(
        self,
        *,
        namespace_id: str,
        operation_id: str,
        manifest_collection: str,
        manifest_document_id: str,
        document_coordinates: tuple[BusinessDocumentCoordinate, ...],
    ) -> int:
        _validate_coordinate(namespace_id, "namespace identifier")
        _validate_coordinate(operation_id, "operation identifier")
        _validate_coordinate(manifest_collection, "manifest collection")
        _validate_coordinate(manifest_document_id, "manifest document identifier")
        document_coordinates = _document_coordinates(document_coordinates)
        connection = self._connect()
        try:
            connection.execute("BEGIN")
            row = connection.execute(
                """
                SELECT *
                FROM operation_manifests
                WHERE namespace_id = ?
                  AND operation_id = ?
                  AND manifest_collection = ?
                  AND manifest_document_id = ?
                """,
                (
                    namespace_id,
                    operation_id,
                    manifest_collection,
                    manifest_document_id,
                ),
            ).fetchone()
            if row is None:
                unverified_document = connection.execute(
                    """
                    SELECT 1
                    FROM business_documents
                    WHERE namespace_id = ? AND operation_id = ?
                    LIMIT 1
                    """,
                    (namespace_id, operation_id),
                ).fetchone()
                if unverified_document is not None:
                    raise FirestoreOwnershipError(
                        "documents remain without an ownership manifest"
                    )
                connection.commit()
                return 0
            manifest, declarations = self._cleanup_manifest(
                row,
                document_coordinates,
            )
            declarations_by_id = {
                declaration[0]: declaration for declaration in declarations
            }
            count = 1
            for effect_id in manifest.established_effect_ids:
                declaration = declarations_by_id[effect_id]
                document_row = connection.execute(
                    """
                    SELECT
                        effect_id,
                        collection_name,
                        document_id,
                        operation_id,
                        revision,
                        content_sha256,
                        correlation_json,
                        observed_at
                    FROM business_documents
                    WHERE namespace_id = ?
                      AND collection_name = ?
                      AND document_id = ?
                    """,
                    (namespace_id, declaration[1], declaration[2]),
                ).fetchone()
                if document_row is not None:
                    document = self._document_from_row(document_row)
                    self._assert_cleanup_document(
                        document=document,
                        declaration=declaration,
                        manifest=manifest,
                    )
                    count += 1
            connection.commit()
            return count
        except BaseException:
            connection.rollback()
            raise
        finally:
            connection.close()

    def delete_owned(
        self,
        *,
        namespace_id: str,
        operation_id: str,
        manifest_collection: str,
        manifest_document_id: str,
        document_coordinates: tuple[BusinessDocumentCoordinate, ...],
    ) -> BusinessOperationDeletion:
        _validate_coordinate(namespace_id, "namespace identifier")
        _validate_coordinate(operation_id, "operation identifier")
        _validate_coordinate(manifest_collection, "manifest collection")
        _validate_coordinate(manifest_document_id, "manifest document identifier")
        document_coordinates = _document_coordinates(document_coordinates)
        removed: list[BusinessDocumentCoordinate] = []
        with self._write_transaction() as connection:
            row = connection.execute(
                """
                SELECT *
                FROM operation_manifests
                WHERE namespace_id = ?
                  AND operation_id = ?
                  AND manifest_collection = ?
                  AND manifest_document_id = ?
                """,
                (
                    namespace_id,
                    operation_id,
                    manifest_collection,
                    manifest_document_id,
                ),
            ).fetchone()
            if row is None:
                return BusinessOperationDeletion(
                    removed_documents=(), manifest_removed=False
                )
            manifest, declarations = self._cleanup_manifest(
                row,
                document_coordinates,
            )
            declarations_by_id = {
                declaration[0]: declaration for declaration in declarations
            }
            owned_rows: list[tuple[EffectDeclaration, BusinessDocument]] = []
            for effect_id in manifest.established_effect_ids:
                declaration = declarations_by_id[effect_id]
                document_row = connection.execute(
                    """
                    SELECT
                        effect_id,
                        collection_name,
                        document_id,
                        operation_id,
                        revision,
                        content_sha256,
                        correlation_json,
                        observed_at
                    FROM business_documents
                    WHERE namespace_id = ?
                      AND collection_name = ?
                      AND document_id = ?
                    """,
                    (namespace_id, declaration[1], declaration[2]),
                ).fetchone()
                if document_row is not None:
                    document = self._document_from_row(document_row)
                    self._assert_cleanup_document(
                        document=document,
                        declaration=declaration,
                        manifest=manifest,
                    )
                    owned_rows.append((declaration, document))
            for declaration, document in owned_rows:
                cursor = connection.execute(
                    """
                    DELETE FROM business_documents
                    WHERE namespace_id = ?
                      AND collection_name = ?
                      AND document_id = ?
                      AND revision = ?
                    """,
                    (
                        namespace_id,
                        declaration[1],
                        declaration[2],
                        document.revision,
                    ),
                )
                if cursor.rowcount != 1:
                    raise LocalFirestoreError(
                        "the manifest-owned document changed during cleanup"
                    )
                removed.append(document.coordinate)
            manifest_cursor = connection.execute(
                """
                DELETE FROM operation_manifests
                WHERE namespace_id = ?
                  AND operation_id = ?
                  AND manifest_collection = ?
                  AND manifest_document_id = ?
                  AND revision = ?
                """,
                (
                    namespace_id,
                    operation_id,
                    manifest_collection,
                    manifest_document_id,
                    manifest.revision,
                ),
            )
            if manifest_cursor.rowcount != 1:
                raise LocalFirestoreError(
                    "the operation manifest changed during cleanup"
                )
        return BusinessOperationDeletion(
            removed_documents=tuple(removed),
            manifest_removed=True,
        )

    def insert_harness_document(
        self,
        *,
        namespace_id: str,
        operation_id: str,
        document: BusinessDocumentWrite,
        correlation: Mapping[str, str],
        observed_at: datetime,
        replace: bool,
    ) -> BusinessDocument:
        _validate_coordinate(namespace_id, "namespace identifier")
        _validate_coordinate(operation_id, "operation identifier")
        if type(document) is not BusinessDocumentWrite:
            raise TypeError("harness document must be an exact document write")
        if type(replace) is not bool:
            raise TypeError("replacement flag must be a boolean")
        timestamp = _aware_utc(observed_at)
        correlation_text = _correlation_text(correlation)
        with self._write_transaction() as connection:
            existing = connection.execute(
                """
                SELECT 1
                FROM business_documents
                WHERE namespace_id = ?
                  AND collection_name = ?
                  AND document_id = ?
                """,
                (namespace_id, document.collection_name, document.document_id),
            ).fetchone()
            if replace and existing is None:
                raise FirestoreResourceNotFound(
                    "the harness replacement coordinate is absent"
                )
            if not replace and existing is not None:
                raise FirestoreResourceAlreadyExists(
                    "the harness document coordinate is already occupied"
                )
            revision = self._next_revision(connection, timestamp)
            if replace:
                connection.execute(
                    """
                    UPDATE business_documents
                    SET effect_id = ?,
                        operation_id = ?,
                        revision = ?,
                        content = ?,
                        content_sha256 = ?,
                        correlation_json = ?,
                        observed_at = ?
                    WHERE namespace_id = ?
                      AND collection_name = ?
                      AND document_id = ?
                    """,
                    (
                        document.effect_id,
                        operation_id,
                        revision,
                        document.content,
                        document.content_sha256,
                        correlation_text,
                        _timestamp_text(timestamp),
                        namespace_id,
                        document.collection_name,
                        document.document_id,
                    ),
                )
            else:
                connection.execute(
                    """
                    INSERT INTO business_documents (
                        namespace_id,
                        collection_name,
                        document_id,
                        effect_id,
                        operation_id,
                        revision,
                        content,
                        content_sha256,
                        correlation_json,
                        observed_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        namespace_id,
                        document.collection_name,
                        document.document_id,
                        document.effect_id,
                        operation_id,
                        revision,
                        document.content,
                        document.content_sha256,
                        correlation_text,
                        _timestamp_text(timestamp),
                    ),
                )
        return BusinessDocument(
            effect_id=document.effect_id,
            collection_name=document.collection_name,
            document_id=document.document_id,
            operation_id=operation_id,
            revision=revision,
            content_sha256=document.content_sha256,
            correlation_items=_correlation_items(correlation),
            observed_at=timestamp,
        )

    def delete_harness_document(
        self,
        *,
        namespace_id: str,
        collection_name: str,
        document_id: str,
    ) -> bool:
        _validate_coordinate(namespace_id, "namespace identifier")
        _validate_coordinate(collection_name, "collection name")
        _validate_coordinate(document_id, "document identifier")
        with self._write_transaction() as connection:
            cursor = connection.execute(
                """
                DELETE FROM business_documents
                WHERE namespace_id = ?
                  AND collection_name = ?
                  AND document_id = ?
                """,
                (namespace_id, collection_name, document_id),
            )
        return cursor.rowcount == 1

    def delete_harness_manifest(
        self,
        *,
        namespace_id: str,
        operation_id: str,
    ) -> bool:
        _validate_coordinate(namespace_id, "namespace identifier")
        _validate_coordinate(operation_id, "operation identifier")
        with self._write_transaction() as connection:
            cursor = connection.execute(
                """
                DELETE FROM operation_manifests
                WHERE namespace_id = ? AND operation_id = ?
                """,
                (namespace_id, operation_id),
            )
        return cursor.rowcount == 1


def _validate_operation_input(
    *,
    namespace_id: str,
    operation_id: str,
    manifest_collection: str,
    manifest_document_id: str,
    documents: tuple[BusinessDocumentWrite, ...],
    selected_effect_ids: tuple[str, ...],
    correlation: Mapping[str, str],
) -> tuple[BusinessDocumentWrite, ...]:
    _validate_coordinate(namespace_id, "namespace identifier")
    _validate_coordinate(operation_id, "operation identifier")
    _validate_coordinate(manifest_collection, "manifest collection")
    _validate_coordinate(manifest_document_id, "manifest document identifier")
    documents = _document_writes(documents)
    selected_effect_ids = _effect_ids(selected_effect_ids, require_count=False)
    expected_ids = {document.effect_id for document in documents}
    if not set(selected_effect_ids).issubset(expected_ids):
        raise ValueError("selected effects must be declared document effects")
    _correlation_items(correlation)
    return documents


class LocalFirestoreMutationTarget:
    """Mutation-only handle for separately committed business effects."""

    def __init__(
        self,
        database_path: str | Path,
        *,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        self._database = _LocalFirestoreDatabase(database_path)
        self._clock = clock or (lambda: datetime.now(UTC))

    @property
    def database_path(self) -> Path:
        return self._database.database_path

    def initialize(self) -> None:
        self._database.initialize()

    def commit_business_operation(
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
        """Commit selected effects separately and finish their exact partition."""

        documents = _validate_operation_input(
            namespace_id=namespace_id,
            operation_id=operation_id,
            manifest_collection=manifest_collection,
            manifest_document_id=manifest_document_id,
            documents=documents,
            selected_effect_ids=selected_effect_ids,
            correlation=correlation,
        )
        documents_by_id = {document.effect_id: document for document in documents}
        self._database.create_active_manifest(
            namespace_id=namespace_id,
            operation_id=operation_id,
            manifest_collection=manifest_collection,
            manifest_document_id=manifest_document_id,
            documents=documents,
            correlation=correlation,
            observed_at=_aware_utc(self._clock()),
        )
        if not selected_effect_ids:
            self._database.terminalize_empty(
                namespace_id=namespace_id,
                operation_id=operation_id,
                observed_at=_aware_utc(self._clock()),
            )
            return
        for index, effect_id in enumerate(selected_effect_ids):
            self._database.commit_effect(
                namespace_id=namespace_id,
                operation_id=operation_id,
                document=documents_by_id[effect_id],
                terminal=index == len(selected_effect_ids) - 1,
                observed_at=_aware_utc(self._clock()),
            )


class LocalFirestoreReadTarget:
    """Manifest-capable handle restricted to the allowlisted read adapter."""

    def __init__(self, database_path: str | Path) -> None:
        self._database = _LocalFirestoreDatabase(database_path)

    @property
    def database_path(self) -> Path:
        return self._database.database_path

    def read(
        self,
        *,
        namespace_id: str,
        operation_id: str,
        manifest_collection: str,
        manifest_document_id: str,
        document_coordinates: tuple[BusinessDocumentCoordinate, ...],
    ) -> BusinessOperationReadback:
        return self._database.read(
            namespace_id=namespace_id,
            operation_id=operation_id,
            manifest_collection=manifest_collection,
            manifest_document_id=manifest_document_id,
            document_coordinates=document_coordinates,
        )


class LocalFirestoreCleanupTarget:
    """Cleanup-only handle constrained by a target-native operation manifest."""

    def __init__(self, database_path: str | Path) -> None:
        self._database = _LocalFirestoreDatabase(database_path)

    def count_owned(
        self,
        *,
        namespace_id: str,
        operation_id: str,
        manifest_collection: str,
        manifest_document_id: str,
        document_coordinates: tuple[BusinessDocumentCoordinate, ...],
    ) -> int:
        return self._database.count_owned(
            namespace_id=namespace_id,
            operation_id=operation_id,
            manifest_collection=manifest_collection,
            manifest_document_id=manifest_document_id,
            document_coordinates=document_coordinates,
        )

    def delete_owned(
        self,
        *,
        namespace_id: str,
        operation_id: str,
        manifest_collection: str,
        manifest_document_id: str,
        document_coordinates: tuple[BusinessDocumentCoordinate, ...],
    ) -> BusinessOperationDeletion:
        return self._database.delete_owned(
            namespace_id=namespace_id,
            operation_id=operation_id,
            manifest_collection=manifest_collection,
            manifest_document_id=manifest_document_id,
            document_coordinates=document_coordinates,
        )


class LocalFirestoreHarness:
    """Test-only target inspection, active-state, and replacement controls."""

    def __init__(
        self,
        database_path: str | Path,
        *,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        self._database = _LocalFirestoreDatabase(database_path)
        self._clock = clock or (lambda: datetime.now(UTC))

    @property
    def database_path(self) -> Path:
        return self._database.database_path

    def initialize(self) -> None:
        self._database.initialize()

    def read(
        self,
        *,
        namespace_id: str,
        operation_id: str,
        manifest_collection: str,
        manifest_document_id: str,
        document_coordinates: tuple[BusinessDocumentCoordinate, ...],
    ) -> BusinessOperationReadback:
        return self._database.read(
            namespace_id=namespace_id,
            operation_id=operation_id,
            manifest_collection=manifest_collection,
            manifest_document_id=manifest_document_id,
            document_coordinates=document_coordinates,
        )

    def create_active_business_operation(
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
        documents = _validate_operation_input(
            namespace_id=namespace_id,
            operation_id=operation_id,
            manifest_collection=manifest_collection,
            manifest_document_id=manifest_document_id,
            documents=documents,
            selected_effect_ids=selected_effect_ids,
            correlation=correlation,
        )
        documents_by_id = {document.effect_id: document for document in documents}
        self._database.create_active_manifest(
            namespace_id=namespace_id,
            operation_id=operation_id,
            manifest_collection=manifest_collection,
            manifest_document_id=manifest_document_id,
            documents=documents,
            correlation=correlation,
            observed_at=_aware_utc(self._clock()),
        )
        for effect_id in selected_effect_ids:
            self._database.commit_effect(
                namespace_id=namespace_id,
                operation_id=operation_id,
                document=documents_by_id[effect_id],
                terminal=False,
                observed_at=_aware_utc(self._clock()),
            )

    def insert_document(
        self,
        *,
        namespace_id: str,
        operation_id: str,
        document: BusinessDocumentWrite,
        correlation: Mapping[str, str],
    ) -> BusinessDocument:
        return self._database.insert_harness_document(
            namespace_id=namespace_id,
            operation_id=operation_id,
            document=document,
            correlation=correlation,
            observed_at=_aware_utc(self._clock()),
            replace=False,
        )

    def replace_document(
        self,
        *,
        namespace_id: str,
        operation_id: str,
        document: BusinessDocumentWrite,
        correlation: Mapping[str, str],
    ) -> BusinessDocument:
        return self._database.insert_harness_document(
            namespace_id=namespace_id,
            operation_id=operation_id,
            document=document,
            correlation=correlation,
            observed_at=_aware_utc(self._clock()),
            replace=True,
        )

    def delete_document(
        self,
        *,
        namespace_id: str,
        collection_name: str,
        document_id: str,
    ) -> bool:
        return self._database.delete_harness_document(
            namespace_id=namespace_id,
            collection_name=collection_name,
            document_id=document_id,
        )

    def delete_manifest(self, *, namespace_id: str, operation_id: str) -> bool:
        return self._database.delete_harness_manifest(
            namespace_id=namespace_id,
            operation_id=operation_id,
        )


__all__ = [
    "BusinessDocument",
    "BusinessDocumentCoordinate",
    "BusinessDocumentWrite",
    "BusinessOperationDeletion",
    "BusinessOperationManifest",
    "BusinessOperationReadback",
    "BusinessOperationStatus",
    "FirestoreOwnershipError",
    "FirestoreResourceAlreadyExists",
    "FirestoreResourceNotFound",
    "LocalFirestoreCleanupTarget",
    "LocalFirestoreError",
    "LocalFirestoreHarness",
    "LocalFirestoreMutationTarget",
    "LocalFirestoreReadTarget",
    "expected_effect_declarations_sha256",
    "expected_effects_sha256",
]
