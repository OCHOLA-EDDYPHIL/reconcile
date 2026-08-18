"""SQLite-backed order sandbox with deliberately weak product observations."""

from __future__ import annotations

import asyncio
import hashlib
import json
import re
import sqlite3
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path
from typing import Protocol, runtime_checkable

_SQLITE_TIMEOUT_SECONDS = 30.0
_MAX_TEXT_LENGTH = 1_024
_MAX_QUANTITY = 1_000_000_000
_SHA256_PATTERN = re.compile(r"^[0-9a-f]{64}$")
_INGRESS_KIND = "REQUEST_SEEN"


def _utc_now() -> datetime:
    return datetime.now(UTC)


class LocalOrderError(RuntimeError):
    """Base error for the local order sandbox."""


class OrderExecutionAlreadyExists(LocalOrderError):
    """The private cleanup owner already identifies one execution."""


class OrderOwnershipError(LocalOrderError):
    """Current sandbox records do not match their private cleanup receipt."""


class OrderOracleNotFound(LocalOrderError):
    """A test-only private order selected by the harness is absent."""


class HiddenOrderOutcome(StrEnum):
    """Out-of-band sandbox behavior that is never returned by product reads."""

    COMMIT = "COMMIT"
    DISCARD = "DISCARD"


class WeakOrderCountBand(StrEnum):
    """A deliberately coarse, non-correlating order-count observation."""

    ZERO = "ZERO"
    ONE_OR_MORE = "ONE_OR_MORE"


@dataclass(frozen=True, slots=True)
class WeakIngressObservation:
    """A generic ingress log with no invocation or order identifier."""

    event_kind: str
    observed_at: datetime

    def __post_init__(self) -> None:
        if self.event_kind != _INGRESS_KIND:
            raise ValueError("the ingress event kind is unsupported")
        object.__setattr__(self, "observed_at", _aware_utc(self.observed_at))


@dataclass(frozen=True, slots=True)
class WeakOrderAggregateObservation:
    """A coarse aggregate that cannot identify one submitted order."""

    count_band: WeakOrderCountBand
    observed_at: datetime

    def __post_init__(self) -> None:
        if type(self.count_band) is not WeakOrderCountBand:
            raise TypeError("the aggregate count band is invalid")
        object.__setattr__(self, "observed_at", _aware_utc(self.observed_at))


@dataclass(frozen=True, slots=True)
class WeakOrderObservationSnapshot:
    """Product-visible weak observations without hidden order state."""

    ingress: WeakIngressObservation | None
    aggregate: WeakOrderAggregateObservation | None

    def __post_init__(self) -> None:
        if (
            self.ingress is not None
            and type(self.ingress) is not WeakIngressObservation
        ):
            raise TypeError("the ingress observation has an invalid type")
        if (
            self.aggregate is not None
            and type(self.aggregate) is not WeakOrderAggregateObservation
        ):
            raise TypeError("the aggregate observation has an invalid type")


@runtime_checkable
class SandboxOrderReadPort(Protocol):
    """Trusted async boundary exposing only the two weak observations."""

    async def read_ingress_observation(self) -> WeakIngressObservation | None: ...

    async def read_aggregate_observation(
        self,
    ) -> WeakOrderAggregateObservation | None: ...


@dataclass(frozen=True, slots=True)
class OrderDeletion:
    """Exact private resources removed by one cleanup attempt."""

    order_removed: bool
    ingress_removed: bool
    receipt_removed: bool

    def __post_init__(self) -> None:
        if any(
            type(value) is not bool
            for value in (
                self.order_removed,
                self.ingress_removed,
                self.receipt_removed,
            )
        ):
            raise TypeError("order deletion flags must be booleans")

    @property
    def removed_count(self) -> int:
        return sum(
            (
                self.order_removed,
                self.ingress_removed,
                self.receipt_removed,
            )
        )


@dataclass(frozen=True, slots=True)
class _OrderOracleRecord:
    """Test-only private order state that product handles never return."""

    row_id: int
    item_code: str
    quantity: int
    revision: int
    content_sha256: str
    created_at: datetime

    def __post_init__(self) -> None:
        _validate_positive_integer(self.row_id, "order row identifier")
        _validate_text(self.item_code, "item code")
        _validate_quantity(self.quantity)
        _validate_positive_integer(self.revision, "order revision")
        _validate_sha256(self.content_sha256, "order content digest")
        object.__setattr__(self, "created_at", _aware_utc(self.created_at))


def _validate_text(value: str, label: str) -> None:
    if (
        type(value) is not str
        or not 1 <= len(value) <= _MAX_TEXT_LENGTH
        or "\x00" in value
    ):
        raise ValueError(f"{label} must be a bounded nonempty string")
    try:
        value.encode("utf-8")
    except UnicodeEncodeError as error:
        raise ValueError(f"{label} must contain Unicode scalar values") from error


def _validate_quantity(value: int) -> None:
    if type(value) is not int or not 1 <= value <= _MAX_QUANTITY:
        raise ValueError("order quantity must be a bounded positive integer")


def _validate_positive_integer(value: int, label: str) -> None:
    if type(value) is not int or not 1 <= value < 2**63:
        raise ValueError(f"{label} must be a positive signed 64-bit integer")


def _validate_sha256(value: str, label: str) -> None:
    if type(value) is not str or _SHA256_PATTERN.fullmatch(value) is None:
        raise ValueError(f"{label} must be a lowercase SHA-256 digest")


def _aware_utc(value: datetime) -> datetime:
    if not isinstance(value, datetime) or value.tzinfo is None:
        raise ValueError("order timestamps must include a UTC offset")
    if value.utcoffset() is None:
        raise ValueError("order timestamps must include a UTC offset")
    return value.astimezone(UTC)


def _timestamp_text(value: datetime) -> str:
    return _aware_utc(value).isoformat(timespec="microseconds")


def _timestamp_from_text(value: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(value)
    except (TypeError, ValueError) as error:
        raise LocalOrderError("a stored order timestamp is malformed") from error
    try:
        return _aware_utc(parsed)
    except ValueError as error:
        raise LocalOrderError("a stored order timestamp is malformed") from error


def _canonical_digest(value: object) -> str:
    payload = json.dumps(
        value,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def _order_digest(item_code: str, quantity: int) -> str:
    _validate_text(item_code, "item code")
    _validate_quantity(quantity)
    return _canonical_digest({"item_code": item_code, "quantity": quantity})


def _ingress_digest(event_kind: str, observed_at: datetime) -> str:
    if event_kind != _INGRESS_KIND:
        raise ValueError("the ingress event kind is unsupported")
    return _canonical_digest(
        {
            "event_kind": event_kind,
            "observed_at": _timestamp_text(observed_at),
        }
    )


def weak_observation_bytes(snapshot: WeakOrderObservationSnapshot) -> bytes:
    """Return canonical bytes for the complete product-visible observation."""

    if type(snapshot) is not WeakOrderObservationSnapshot:
        raise TypeError("the weak observation snapshot has an invalid type")
    ingress = snapshot.ingress
    aggregate = snapshot.aggregate
    return json.dumps(
        {
            "aggregate": (
                None
                if aggregate is None
                else {
                    "count_band": aggregate.count_band.value,
                    "observed_at": _timestamp_text(aggregate.observed_at),
                }
            ),
            "ingress": (
                None
                if ingress is None
                else {
                    "event_kind": ingress.event_kind,
                    "observed_at": _timestamp_text(ingress.observed_at),
                }
            ),
        },
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


def _database_path(value: str | Path, label: str) -> Path:
    path = Path(value)
    if str(path) == ":memory:":
        raise ValueError(f"{label} requires a disk database")
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists() and path.is_dir():
        raise ValueError(f"{label} path is a directory")
    return path


def _connect(path: Path) -> sqlite3.Connection:
    connection = sqlite3.connect(
        str(path),
        timeout=_SQLITE_TIMEOUT_SECONDS,
        isolation_level=None,
    )
    connection.row_factory = sqlite3.Row
    connection.execute(f"PRAGMA busy_timeout = {int(_SQLITE_TIMEOUT_SECONDS * 1_000)}")
    connection.execute("PRAGMA foreign_keys = ON")
    return connection


def _initialize_private(path: Path) -> None:
    connection = _connect(path)
    try:
        connection.execute("PRAGMA journal_mode = DELETE")
        connection.execute("PRAGMA synchronous = FULL")
        connection.executescript(
            """
            CREATE TABLE IF NOT EXISTS sandbox_orders (
                order_row_id INTEGER PRIMARY KEY AUTOINCREMENT,
                item_code TEXT NOT NULL,
                quantity INTEGER NOT NULL,
                revision INTEGER NOT NULL,
                content_sha256 TEXT NOT NULL,
                created_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS execution_receipts (
                owner_token TEXT PRIMARY KEY,
                order_row_id INTEGER,
                order_revision INTEGER,
                order_sha256 TEXT,
                ingress_row_id INTEGER NOT NULL,
                ingress_sha256 TEXT NOT NULL,
                observed_at TEXT NOT NULL,
                CHECK (
                    (
                        order_row_id IS NULL
                        AND order_revision IS NULL
                        AND order_sha256 IS NULL
                    )
                    OR
                    (
                        order_row_id IS NOT NULL
                        AND order_revision IS NOT NULL
                        AND order_sha256 IS NOT NULL
                    )
                )
            );
            """
        )
    finally:
        connection.close()


def _initialize_observations(path: Path) -> None:
    connection = _connect(path)
    try:
        connection.execute("PRAGMA journal_mode = DELETE")
        connection.execute("PRAGMA synchronous = FULL")
        connection.executescript(
            """
            CREATE TABLE IF NOT EXISTS weak_ingress_events (
                event_row_id INTEGER PRIMARY KEY AUTOINCREMENT,
                event_kind TEXT NOT NULL,
                observed_at TEXT NOT NULL,
                event_sha256 TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS weak_order_aggregate (
                singleton_id INTEGER PRIMARY KEY CHECK (singleton_id = 1),
                count_band TEXT NOT NULL,
                observed_at TEXT NOT NULL
            );
            """
        )
    finally:
        connection.close()


class _WeakObservationDatabase:
    """Observation-only storage with no private order database coordinate."""

    def __init__(self, observation_database_path: str | Path) -> None:
        self._path = _database_path(
            observation_database_path,
            "the weak observation target",
        )
        _initialize_observations(self._path)

    @property
    def path(self) -> Path:
        return self._path

    def initialize(self) -> None:
        _initialize_observations(self._path)

    @staticmethod
    def _ingress_from_rows(
        rows: tuple[sqlite3.Row, ...],
    ) -> WeakIngressObservation | None:
        latest: WeakIngressObservation | None = None
        for row in rows:
            try:
                observed_at = _timestamp_from_text(row["observed_at"])
                event = WeakIngressObservation(
                    event_kind=row["event_kind"],
                    observed_at=observed_at,
                )
                digest = row["event_sha256"]
                _validate_sha256(digest, "stored ingress digest")
            except (TypeError, ValueError) as error:
                raise LocalOrderError(
                    "a weak ingress observation is malformed"
                ) from error
            if digest != _ingress_digest(event.event_kind, event.observed_at):
                raise LocalOrderError("a weak ingress observation is inconsistent")
            latest = event
        return latest

    @staticmethod
    def _aggregate_from_row(
        row: sqlite3.Row | None,
    ) -> WeakOrderAggregateObservation | None:
        if row is None:
            return None
        try:
            return WeakOrderAggregateObservation(
                count_band=WeakOrderCountBand(row["count_band"]),
                observed_at=_timestamp_from_text(row["observed_at"]),
            )
        except (TypeError, ValueError) as error:
            raise LocalOrderError("the weak order aggregate is malformed") from error

    @staticmethod
    def _read_ingress_rows(
        connection: sqlite3.Connection,
    ) -> tuple[sqlite3.Row, ...]:
        return tuple(
            connection.execute(
                """
                SELECT event_kind, observed_at, event_sha256
                FROM weak_ingress_events
                ORDER BY event_row_id
                """
            ).fetchall()
        )

    @staticmethod
    def _read_aggregate_row(
        connection: sqlite3.Connection,
    ) -> sqlite3.Row | None:
        return connection.execute(
            """
            SELECT count_band, observed_at
            FROM weak_order_aggregate
            WHERE singleton_id = 1
            """
        ).fetchone()

    @contextmanager
    def _read_transaction(self) -> Iterator[sqlite3.Connection]:
        connection = _connect(self._path)
        try:
            connection.execute("BEGIN")
            yield connection
            connection.commit()
        except BaseException:
            connection.rollback()
            raise
        finally:
            connection.close()

    def read_ingress(self) -> WeakIngressObservation | None:
        with self._read_transaction() as connection:
            rows = self._read_ingress_rows(connection)
        return self._ingress_from_rows(rows)

    def read_aggregate(self) -> WeakOrderAggregateObservation | None:
        with self._read_transaction() as connection:
            row = self._read_aggregate_row(connection)
        return self._aggregate_from_row(row)

    def read_snapshot(self) -> WeakOrderObservationSnapshot:
        with self._read_transaction() as connection:
            ingress_rows = self._read_ingress_rows(connection)
            aggregate_row = self._read_aggregate_row(connection)
        return WeakOrderObservationSnapshot(
            ingress=self._ingress_from_rows(ingress_rows),
            aggregate=self._aggregate_from_row(aggregate_row),
        )


class _OrderSandboxDatabase:
    """Private mutation, oracle, and cleanup access across separate databases."""

    def __init__(
        self,
        private_database_path: str | Path,
        observation_database_path: str | Path,
    ) -> None:
        self._private_path = _database_path(
            private_database_path,
            "the private order target",
        )
        self._observation_path = _database_path(
            observation_database_path,
            "the weak observation target",
        )
        if self._private_path.resolve() == self._observation_path.resolve():
            raise ValueError(
                "private orders and weak observations need separate databases"
            )
        self.initialize()

    def initialize(self) -> None:
        _initialize_private(self._private_path)
        _initialize_observations(self._observation_path)

    @contextmanager
    def _write_transaction(self) -> Iterator[sqlite3.Connection]:
        connection = _connect(self._private_path)
        try:
            connection.execute(
                "ATTACH DATABASE ? AS weak",
                (str(self._observation_path),),
            )
            connection.execute("BEGIN IMMEDIATE")
            yield connection
            connection.commit()
        except BaseException:
            connection.rollback()
            raise
        finally:
            connection.close()

    @staticmethod
    def _next_revision(connection: sqlite3.Connection) -> int:
        row = connection.execute(
            "SELECT COALESCE(MAX(revision), 0) + 1 AS next FROM sandbox_orders"
        ).fetchone()
        revision = row["next"]
        _validate_positive_integer(revision, "next order revision")
        return revision

    @staticmethod
    def _oracle_from_row(row: sqlite3.Row) -> _OrderOracleRecord:
        try:
            return _OrderOracleRecord(
                row_id=row["order_row_id"],
                item_code=row["item_code"],
                quantity=row["quantity"],
                revision=row["revision"],
                content_sha256=row["content_sha256"],
                created_at=_timestamp_from_text(row["created_at"]),
            )
        except (TypeError, ValueError) as error:
            raise LocalOrderError("a private order record is malformed") from error

    def execute(
        self,
        *,
        owner_token: str,
        item_code: str,
        quantity: int,
        hidden_outcome: HiddenOrderOutcome,
        observed_at: datetime,
    ) -> None:
        _validate_text(owner_token, "private cleanup owner")
        _validate_text(item_code, "item code")
        _validate_quantity(quantity)
        if type(hidden_outcome) is not HiddenOrderOutcome:
            raise TypeError("the hidden order outcome is invalid")
        timestamp = _aware_utc(observed_at)
        ingress_digest = _ingress_digest(_INGRESS_KIND, timestamp)
        with self._write_transaction() as connection:
            existing = connection.execute(
                "SELECT 1 FROM execution_receipts WHERE owner_token = ?",
                (owner_token,),
            ).fetchone()
            if existing is not None:
                raise OrderExecutionAlreadyExists(
                    "the private cleanup owner already identifies an execution"
                )
            ingress_cursor = connection.execute(
                """
                INSERT INTO weak.weak_ingress_events (
                    event_kind,
                    observed_at,
                    event_sha256
                ) VALUES (?, ?, ?)
                """,
                (_INGRESS_KIND, _timestamp_text(timestamp), ingress_digest),
            )
            ingress_row_id = ingress_cursor.lastrowid
            _validate_positive_integer(ingress_row_id, "ingress row identifier")

            order_row_id: int | None = None
            order_revision: int | None = None
            order_sha256: str | None = None
            if hidden_outcome is HiddenOrderOutcome.COMMIT:
                order_revision = self._next_revision(connection)
                order_sha256 = _order_digest(item_code, quantity)
                order_cursor = connection.execute(
                    """
                    INSERT INTO sandbox_orders (
                        item_code,
                        quantity,
                        revision,
                        content_sha256,
                        created_at
                    ) VALUES (?, ?, ?, ?, ?)
                    """,
                    (
                        item_code,
                        quantity,
                        order_revision,
                        order_sha256,
                        _timestamp_text(timestamp),
                    ),
                )
                order_row_id = order_cursor.lastrowid
                _validate_positive_integer(order_row_id, "order row identifier")

            connection.execute(
                """
                INSERT INTO execution_receipts (
                    owner_token,
                    order_row_id,
                    order_revision,
                    order_sha256,
                    ingress_row_id,
                    ingress_sha256,
                    observed_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    owner_token,
                    order_row_id,
                    order_revision,
                    order_sha256,
                    ingress_row_id,
                    ingress_digest,
                    _timestamp_text(timestamp),
                ),
            )

    @staticmethod
    def _receipt(
        connection: sqlite3.Connection, owner_token: str
    ) -> sqlite3.Row | None:
        return connection.execute(
            "SELECT * FROM execution_receipts WHERE owner_token = ?",
            (owner_token,),
        ).fetchone()

    @staticmethod
    def _validate_receipt(row: sqlite3.Row) -> None:
        try:
            _validate_text(row["owner_token"], "private cleanup owner")
            _validate_positive_integer(row["ingress_row_id"], "ingress row identifier")
            _validate_sha256(row["ingress_sha256"], "ingress digest")
            observed_at = _timestamp_from_text(row["observed_at"])
            order_values = (
                row["order_row_id"],
                row["order_revision"],
                row["order_sha256"],
            )
            if all(value is None for value in order_values):
                return
            if any(value is None for value in order_values):
                raise ValueError("private order binding is incomplete")
            _validate_positive_integer(row["order_row_id"], "order row identifier")
            _validate_positive_integer(row["order_revision"], "order revision")
            _validate_sha256(row["order_sha256"], "order content digest")
            _aware_utc(observed_at)
        except (TypeError, ValueError) as error:
            raise OrderOwnershipError(
                "the private cleanup receipt is malformed"
            ) from error

    @staticmethod
    def _bound_order(
        connection: sqlite3.Connection,
        receipt: sqlite3.Row,
    ) -> sqlite3.Row | None:
        row_id = receipt["order_row_id"]
        if row_id is None:
            return None
        row = connection.execute(
            "SELECT * FROM sandbox_orders WHERE order_row_id = ?",
            (row_id,),
        ).fetchone()
        if row is None:
            return None
        order = _OrderSandboxDatabase._oracle_from_row(row)
        if (
            order.revision != receipt["order_revision"]
            or order.content_sha256 != receipt["order_sha256"]
            or order.content_sha256 != _order_digest(order.item_code, order.quantity)
        ):
            raise OrderOwnershipError(
                "the current private order does not match its cleanup receipt"
            )
        return row

    @staticmethod
    def _bound_ingress(
        connection: sqlite3.Connection,
        receipt: sqlite3.Row,
    ) -> sqlite3.Row | None:
        row = connection.execute(
            """
            SELECT *
            FROM weak.weak_ingress_events
            WHERE event_row_id = ?
            """,
            (receipt["ingress_row_id"],),
        ).fetchone()
        if row is None:
            return None
        try:
            observed_at = _timestamp_from_text(row["observed_at"])
            digest = row["event_sha256"]
            _validate_sha256(digest, "stored ingress digest")
        except (TypeError, ValueError) as error:
            raise OrderOwnershipError(
                "the current ingress observation is malformed"
            ) from error
        if (
            row["event_kind"] != _INGRESS_KIND
            or digest != receipt["ingress_sha256"]
            or digest != _ingress_digest(row["event_kind"], observed_at)
        ):
            raise OrderOwnershipError(
                "the current ingress observation does not match its cleanup receipt"
            )
        return row

    def count_owned(self, *, owner_token: str) -> int:
        _validate_text(owner_token, "private cleanup owner")
        with self._write_transaction() as connection:
            receipt = self._receipt(connection, owner_token)
            if receipt is None:
                return 0
            self._validate_receipt(receipt)
            order = self._bound_order(connection, receipt)
            ingress = self._bound_ingress(connection, receipt)
            return 1 + int(order is not None) + int(ingress is not None)

    def delete_owned(self, *, owner_token: str) -> OrderDeletion:
        _validate_text(owner_token, "private cleanup owner")
        order_removed = False
        ingress_removed = False
        with self._write_transaction() as connection:
            receipt = self._receipt(connection, owner_token)
            if receipt is None:
                return OrderDeletion(
                    order_removed=False,
                    ingress_removed=False,
                    receipt_removed=False,
                )
            self._validate_receipt(receipt)
            order = self._bound_order(connection, receipt)
            ingress = self._bound_ingress(connection, receipt)

            if order is not None:
                cursor = connection.execute(
                    """
                    DELETE FROM sandbox_orders
                    WHERE order_row_id = ?
                      AND revision = ?
                      AND content_sha256 = ?
                    """,
                    (
                        order["order_row_id"],
                        order["revision"],
                        order["content_sha256"],
                    ),
                )
                if cursor.rowcount != 1:
                    raise LocalOrderError(
                        "the private order changed during exact cleanup"
                    )
                order_removed = True

            if ingress is not None:
                cursor = connection.execute(
                    """
                    DELETE FROM weak.weak_ingress_events
                    WHERE event_row_id = ? AND event_sha256 = ?
                    """,
                    (ingress["event_row_id"], ingress["event_sha256"]),
                )
                if cursor.rowcount != 1:
                    raise LocalOrderError(
                        "the weak ingress observation changed during exact cleanup"
                    )
                ingress_removed = True

            cursor = connection.execute(
                "DELETE FROM execution_receipts WHERE owner_token = ?",
                (owner_token,),
            )
            if cursor.rowcount != 1:
                raise LocalOrderError(
                    "the private cleanup receipt changed during exact cleanup"
                )
        return OrderDeletion(
            order_removed=order_removed,
            ingress_removed=ingress_removed,
            receipt_removed=True,
        )

    def seed_duplicate_looking_order(
        self,
        *,
        item_code: str,
        quantity: int,
        observed_at: datetime,
    ) -> _OrderOracleRecord:
        _validate_text(item_code, "item code")
        _validate_quantity(quantity)
        timestamp = _aware_utc(observed_at)
        with self._write_transaction() as connection:
            revision = self._next_revision(connection)
            digest = _order_digest(item_code, quantity)
            cursor = connection.execute(
                """
                INSERT INTO sandbox_orders (
                    item_code,
                    quantity,
                    revision,
                    content_sha256,
                    created_at
                ) VALUES (?, ?, ?, ?, ?)
                """,
                (
                    item_code,
                    quantity,
                    revision,
                    digest,
                    _timestamp_text(timestamp),
                ),
            )
            row_id = cursor.lastrowid
            _validate_positive_integer(row_id, "order row identifier")
            connection.execute(
                """
                INSERT INTO weak.weak_order_aggregate (
                    singleton_id,
                    count_band,
                    observed_at
                ) VALUES (1, ?, ?)
                ON CONFLICT(singleton_id) DO UPDATE SET
                    count_band = excluded.count_band,
                    observed_at = excluded.observed_at
                """,
                (
                    WeakOrderCountBand.ONE_OR_MORE.value,
                    _timestamp_text(timestamp),
                ),
            )
            row = connection.execute(
                "SELECT * FROM sandbox_orders WHERE order_row_id = ?",
                (row_id,),
            ).fetchone()
        if row is None:
            raise LocalOrderError("the seeded private order was not stored")
        return self._oracle_from_row(row)

    def private_orders(self) -> tuple[_OrderOracleRecord, ...]:
        connection = _connect(self._private_path)
        try:
            connection.execute("BEGIN")
            rows = tuple(
                connection.execute(
                    "SELECT * FROM sandbox_orders ORDER BY order_row_id"
                ).fetchall()
            )
            connection.commit()
        except BaseException:
            connection.rollback()
            raise
        finally:
            connection.close()
        return tuple(self._oracle_from_row(row) for row in rows)

    def replace_owned_order(
        self,
        *,
        owner_token: str,
        item_code: str,
        quantity: int,
        observed_at: datetime,
    ) -> _OrderOracleRecord:
        _validate_text(owner_token, "private cleanup owner")
        _validate_text(item_code, "item code")
        _validate_quantity(quantity)
        timestamp = _aware_utc(observed_at)
        with self._write_transaction() as connection:
            receipt = self._receipt(connection, owner_token)
            if receipt is None or receipt["order_row_id"] is None:
                raise OrderOracleNotFound(
                    "the private committed order selected for replacement is absent"
                )
            row = connection.execute(
                "SELECT * FROM sandbox_orders WHERE order_row_id = ?",
                (receipt["order_row_id"],),
            ).fetchone()
            if row is None:
                raise OrderOracleNotFound(
                    "the private committed order selected for replacement is absent"
                )
            revision = self._next_revision(connection)
            digest = _order_digest(item_code, quantity)
            cursor = connection.execute(
                """
                UPDATE sandbox_orders
                SET item_code = ?,
                    quantity = ?,
                    revision = ?,
                    content_sha256 = ?,
                    created_at = ?
                WHERE order_row_id = ? AND revision = ?
                """,
                (
                    item_code,
                    quantity,
                    revision,
                    digest,
                    _timestamp_text(timestamp),
                    row["order_row_id"],
                    row["revision"],
                ),
            )
            if cursor.rowcount != 1:
                raise LocalOrderError("the private order changed during replacement")
            replacement = connection.execute(
                "SELECT * FROM sandbox_orders WHERE order_row_id = ?",
                (row["order_row_id"],),
            ).fetchone()
        if replacement is None:
            raise LocalOrderError("the replacement private order was not stored")
        return self._oracle_from_row(replacement)

    def delete_ingress_observations(self) -> int:
        with self._write_transaction() as connection:
            cursor = connection.execute("DELETE FROM weak.weak_ingress_events")
        return cursor.rowcount

    def delete_aggregate(self) -> bool:
        with self._write_transaction() as connection:
            cursor = connection.execute(
                "DELETE FROM weak.weak_order_aggregate WHERE singleton_id = 1"
            )
        return cursor.rowcount == 1

    def set_aggregate(
        self,
        *,
        count_band: WeakOrderCountBand,
        observed_at: datetime,
    ) -> None:
        if type(count_band) is not WeakOrderCountBand:
            raise TypeError("the aggregate count band is invalid")
        timestamp = _aware_utc(observed_at)
        with self._write_transaction() as connection:
            connection.execute(
                """
                INSERT INTO weak.weak_order_aggregate (
                    singleton_id,
                    count_band,
                    observed_at
                ) VALUES (1, ?, ?)
                ON CONFLICT(singleton_id) DO UPDATE SET
                    count_band = excluded.count_band,
                    observed_at = excluded.observed_at
                """,
                (count_band.value, _timestamp_text(timestamp)),
            )

    def corrupt_latest_ingress(
        self,
        *,
        event_kind: str | None = None,
        event_sha256: str | None = None,
    ) -> None:
        if event_kind is None and event_sha256 is None:
            raise ValueError("ingress corruption requires one changed field")
        updates: dict[str, str] = {}
        if event_kind is not None:
            _validate_text(event_kind, "corrupt ingress event kind")
            updates["event_kind"] = event_kind
        if event_sha256 is not None:
            _validate_text(event_sha256, "corrupt ingress digest")
            updates["event_sha256"] = event_sha256
        assignments = ", ".join(f"{name} = ?" for name in updates)
        with self._write_transaction() as connection:
            row = connection.execute(
                """
                SELECT event_row_id
                FROM weak.weak_ingress_events
                ORDER BY event_row_id DESC
                LIMIT 1
                """
            ).fetchone()
            if row is None:
                raise OrderOracleNotFound(
                    "the weak ingress observation selected for corruption is absent"
                )
            connection.execute(
                f"""
                UPDATE weak.weak_ingress_events
                SET {assignments}
                WHERE event_row_id = ?
                """,
                (*updates.values(), row["event_row_id"]),
            )

    def corrupt_aggregate(self, *, count_band: str) -> None:
        _validate_text(count_band, "corrupt aggregate count band")
        with self._write_transaction() as connection:
            cursor = connection.execute(
                """
                UPDATE weak.weak_order_aggregate
                SET count_band = ?
                WHERE singleton_id = 1
                """,
                (count_band,),
            )
            if cursor.rowcount != 1:
                raise OrderOracleNotFound(
                    "the weak aggregate selected for corruption is absent"
                )


class LocalOrderMutationTarget:
    """Mutation-only handle configured with one out-of-band hidden outcome."""

    def __init__(
        self,
        private_database_path: str | Path,
        observation_database_path: str | Path,
        *,
        hidden_outcome: HiddenOrderOutcome,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        if type(hidden_outcome) is not HiddenOrderOutcome:
            raise TypeError("the hidden order outcome is invalid")
        self._database = _OrderSandboxDatabase(
            private_database_path,
            observation_database_path,
        )
        self._hidden_outcome = hidden_outcome
        self._clock = clock or _utc_now

    def initialize(self) -> None:
        self._database.initialize()

    def submit_order(
        self,
        *,
        owner_token: str,
        item_code: str,
        quantity: int,
    ) -> None:
        """Apply hidden sandbox behavior without returning any target state."""

        self._database.execute(
            owner_token=owner_token,
            item_code=item_code,
            quantity=quantity,
            hidden_outcome=self._hidden_outcome,
            observed_at=_aware_utc(self._clock()),
        )


class LocalOrderReadTarget:
    """Observation-only handle with no coordinate for the private order store."""

    def __init__(self, observation_database_path: str | Path) -> None:
        self._database = _WeakObservationDatabase(observation_database_path)

    @property
    def observation_database_path(self) -> Path:
        return self._database.path

    def initialize(self) -> None:
        self._database.initialize()

    def read_ingress(self) -> WeakIngressObservation | None:
        return self._database.read_ingress()

    def read_aggregate(self) -> WeakOrderAggregateObservation | None:
        return self._database.read_aggregate()

    async def read_ingress_observation(self) -> WeakIngressObservation | None:
        return await asyncio.to_thread(self.read_ingress)

    async def read_aggregate_observation(
        self,
    ) -> WeakOrderAggregateObservation | None:
        return await asyncio.to_thread(self.read_aggregate)

    def read_snapshot(self) -> WeakOrderObservationSnapshot:
        return self._database.read_snapshot()


class LocalOrderCleanupTarget:
    """Cleanup-only handle constrained by a private ownership receipt."""

    def __init__(
        self,
        private_database_path: str | Path,
        observation_database_path: str | Path,
    ) -> None:
        self._database = _OrderSandboxDatabase(
            private_database_path,
            observation_database_path,
        )

    def count_owned(self, *, owner_token: str) -> int:
        return self._database.count_owned(owner_token=owner_token)

    def delete_owned(self, *, owner_token: str) -> OrderDeletion:
        return self._database.delete_owned(owner_token=owner_token)


class LocalOrderHarness:
    """Test-only private oracle, fixture, and corruption controls."""

    def __init__(
        self,
        private_database_path: str | Path,
        observation_database_path: str | Path,
        *,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        self._database = _OrderSandboxDatabase(
            private_database_path,
            observation_database_path,
        )
        self._clock = clock or _utc_now

    def initialize(self) -> None:
        self._database.initialize()

    def seed_duplicate_looking_order(
        self,
        *,
        item_code: str,
        quantity: int,
    ) -> _OrderOracleRecord:
        return self._database.seed_duplicate_looking_order(
            item_code=item_code,
            quantity=quantity,
            observed_at=_aware_utc(self._clock()),
        )

    def private_orders(self) -> tuple[_OrderOracleRecord, ...]:
        return self._database.private_orders()

    def replace_owned_order(
        self,
        *,
        owner_token: str,
        item_code: str,
        quantity: int,
    ) -> _OrderOracleRecord:
        return self._database.replace_owned_order(
            owner_token=owner_token,
            item_code=item_code,
            quantity=quantity,
            observed_at=_aware_utc(self._clock()),
        )

    def delete_ingress_observations(self) -> int:
        return self._database.delete_ingress_observations()

    def delete_aggregate(self) -> bool:
        return self._database.delete_aggregate()

    def set_aggregate(self, *, count_band: WeakOrderCountBand) -> None:
        self._database.set_aggregate(
            count_band=count_band,
            observed_at=_aware_utc(self._clock()),
        )

    def corrupt_latest_ingress(
        self,
        *,
        event_kind: str | None = None,
        event_sha256: str | None = None,
    ) -> None:
        self._database.corrupt_latest_ingress(
            event_kind=event_kind,
            event_sha256=event_sha256,
        )

    def corrupt_aggregate(self, *, count_band: str) -> None:
        self._database.corrupt_aggregate(count_band=count_band)


__all__ = [
    "HiddenOrderOutcome",
    "LocalOrderCleanupTarget",
    "LocalOrderError",
    "LocalOrderHarness",
    "LocalOrderMutationTarget",
    "LocalOrderReadTarget",
    "OrderDeletion",
    "OrderExecutionAlreadyExists",
    "OrderOracleNotFound",
    "OrderOwnershipError",
    "SandboxOrderReadPort",
    "WeakIngressObservation",
    "WeakOrderAggregateObservation",
    "WeakOrderCountBand",
    "WeakOrderObservationSnapshot",
    "weak_observation_bytes",
]
