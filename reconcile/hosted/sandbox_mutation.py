"""Deterministic Firestore mutation and cleanup for the hosted sandbox."""

from __future__ import annotations

import asyncio
import hashlib
import re
from collections.abc import AsyncIterator, Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any, Literal, Protocol

from pydantic import Field, ValidationError, model_validator

from reconcile.contracts.base import (
    AwareDatetime,
    Identifier,
    Sha256Digest,
    StrictModel,
    canonical_json_value_bytes,
)
from reconcile.hosted.sandbox import (
    SANDBOX_AGGREGATE_SCHEMA_VERSION,
    SANDBOX_FIRESTORE_TIMEOUT_SECONDS,
    SANDBOX_INGRESS_SCHEMA_VERSION,
    SANDBOX_TARGET_DATABASE_ID,
)
from reconcile.scenarios.local_order import (
    HiddenOrderOutcome,
    WeakOrderCountBand,
)

SANDBOX_PRIVATE_SCHEMA_VERSION = "reconcile/sandbox-private-aggregate/v1"
SANDBOX_PRIVATE_COLLECTION = "reconcile-sandbox-private-state"
SANDBOX_OBSERVATION_COLLECTION = "reconcile-sandbox-observations"

_WEAK_OBSERVATION_COLLECTION = "weak-observations"
_INGRESS_DOCUMENT = "ingress"
_AGGREGATE_DOCUMENT = "aggregate"
_INGRESS_EVENT_KIND = "REQUEST_SEEN"
_MAX_TEXT_LENGTH = 1_024
_MAX_QUANTITY = 1_000_000_000
_PROJECT_PATTERN = re.compile(r"[a-z][a-z0-9-]{4,28}[a-z0-9]")


class SandboxTargetFailure(StrEnum):
    """Stable failure codes without provider response material."""

    CONFLICT = "conflict"
    CREDENTIALS_UNAVAILABLE = "credentials-unavailable"
    DEPENDENCY_UNAVAILABLE = "dependency-unavailable"
    INVALID_REQUEST = "invalid-request"
    MALFORMED_RESPONSE = "malformed-response"
    NOT_OWNED = "not-owned"
    OUTCOME_UNKNOWN = "outcome-unknown"
    TIMEOUT = "timeout"
    UNAVAILABLE = "unavailable"


class SandboxTargetError(RuntimeError):
    """Sanitized sandbox mutation or cleanup failure."""

    def __init__(self, code: SandboxTargetFailure) -> None:
        if type(code) is not SandboxTargetFailure:
            raise TypeError("a sandbox target failure code is required")
        self.code = code
        super().__init__(code.value)


class SandboxMutationReceipt(StrictModel):
    """Non-secret identity for one admitted sandbox poststate."""

    sandbox_id: Identifier
    owner_sha256: Sha256Digest
    item_quantity_sha256: Sha256Digest
    state_sha256: Sha256Digest
    order_present: bool
    revision: Literal[1]
    observed_at: AwareDatetime
    provider_update_time: AwareDatetime


class SandboxCleanupReceipt(StrictModel):
    """Exact deletion flags for one scoped cleanup attempt."""

    sandbox_id: Identifier
    owner_sha256: Sha256Digest
    state_sha256: Sha256Digest | None
    private_removed: bool
    ingress_removed: bool
    aggregate_removed: bool

    @property
    def removed_count(self) -> int:
        return sum((self.private_removed, self.ingress_removed, self.aggregate_removed))


class _IngressProjection(StrictModel):
    schema_version: Literal["reconcile/sandbox-ingress-observation/v1"]
    sandbox_id: Identifier
    event_kind: Literal["REQUEST_SEEN"]
    observed_at: AwareDatetime


class _AggregateProjection(StrictModel):
    schema_version: Literal["reconcile/sandbox-aggregate-observation/v1"]
    sandbox_id: Identifier
    count_band: Literal["ZERO", "ONE_OR_MORE"]
    observed_at: AwareDatetime


class _PrivateSandboxAggregate(StrictModel):
    schema_version: Literal["reconcile/sandbox-private-aggregate/v1"]
    sandbox_id: Identifier
    owner_token: str = Field(min_length=1, max_length=_MAX_TEXT_LENGTH)
    item_quantity_sha256: Sha256Digest
    order_present: bool
    ingress: _IngressProjection
    aggregate: _AggregateProjection
    revision: Literal[1]
    updated_at: AwareDatetime

    @model_validator(mode="after")
    def validate_closed_state(self) -> _PrivateSandboxAggregate:
        _validated_text(self.owner_token, "sandbox owner")
        expected_band = (
            WeakOrderCountBand.ONE_OR_MORE.value
            if self.order_present
            else WeakOrderCountBand.ZERO.value
        )
        if (
            self.ingress.sandbox_id != self.sandbox_id
            or self.aggregate.sandbox_id != self.sandbox_id
            or self.ingress.observed_at != self.updated_at
            or self.aggregate.observed_at != self.updated_at
            or self.aggregate.count_band != expected_band
        ):
            raise ValueError("private sandbox projections are inconsistent")
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


class AsyncSandboxMutationClientPort(Protocol):
    """Narrow Async Firestore surface used by the sandbox target."""

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


type SandboxMutationClientFactory = Callable[[], AsyncSandboxMutationClientPort]
type SandboxMutationClock = Callable[[], datetime]


@dataclass(frozen=True, slots=True)
class _References:
    private: _DocumentReferencePort
    ingress: _DocumentReferencePort
    aggregate: _DocumentReferencePort

    @property
    def ordered(self) -> tuple[_DocumentReferencePort, ...]:
        return (self.private, self.ingress, self.aggregate)


@dataclass(frozen=True, slots=True)
class _SnapshotSet:
    private: _DocumentSnapshotPort
    ingress: _DocumentSnapshotPort
    aggregate: _DocumentSnapshotPort

    @property
    def ordered(self) -> tuple[_DocumentSnapshotPort, ...]:
        return (self.private, self.ingress, self.aggregate)


@dataclass(frozen=True, slots=True)
class _OwnedState:
    record: _PrivateSandboxAggregate
    snapshots: _SnapshotSet
    state_sha256: str


class _AmbiguousWrite(Exception):
    pass


def _default_client_factory(
    project_id: str,
    database_id: str,
) -> SandboxMutationClientFactory:
    def create() -> AsyncSandboxMutationClientPort:
        from google.cloud import firestore_v1

        return firestore_v1.AsyncClient(project=project_id, database=database_id)

    return create


def _utc_now() -> datetime:
    return datetime.now(UTC)


def _aware_utc(value: object) -> datetime:
    if (
        not isinstance(value, datetime)
        or value.tzinfo is None
        or value.utcoffset() is None
    ):
        raise ValueError("provider timestamp is not timezone-aware")
    return value.astimezone(UTC)


def _validated_text(value: object, label: str) -> str:
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
    return value


def _validated_quantity(value: object) -> int:
    if type(value) is not int or not 1 <= value <= _MAX_QUANTITY:
        raise ValueError("order quantity must be a bounded positive integer")
    return value


def _item_quantity_digest(item_code: str, quantity: int) -> str:
    item = _validated_text(item_code, "item code")
    bounded_quantity = _validated_quantity(quantity)
    return hashlib.sha256(
        canonical_json_value_bytes({"item_code": item, "quantity": bounded_quantity})
    ).hexdigest()


def _owner_digest(owner_token: str) -> str:
    owner = _validated_text(owner_token, "sandbox owner")
    return hashlib.sha256(owner.encode("utf-8")).hexdigest()


def _state_digest(record: _PrivateSandboxAggregate) -> str:
    return hashlib.sha256(
        canonical_json_value_bytes(record.model_dump(mode="json"))
    ).hexdigest()


def _provider_failure(error: Exception) -> SandboxTargetError:
    if isinstance(error, SandboxTargetError):
        return SandboxTargetError(error.code)
    if isinstance(error, TimeoutError):
        return SandboxTargetError(SandboxTargetFailure.TIMEOUT)
    try:
        from google.api_core import exceptions as api_exceptions
        from google.auth import exceptions as auth_exceptions
    except ImportError:
        return SandboxTargetError(SandboxTargetFailure.DEPENDENCY_UNAVAILABLE)
    if isinstance(error, auth_exceptions.DefaultCredentialsError):
        code = SandboxTargetFailure.CREDENTIALS_UNAVAILABLE
    elif isinstance(
        error,
        (
            api_exceptions.AlreadyExists,
            api_exceptions.Conflict,
            api_exceptions.FailedPrecondition,
        ),
    ):
        code = SandboxTargetFailure.CONFLICT
    elif isinstance(error, api_exceptions.InvalidArgument):
        code = SandboxTargetFailure.INVALID_REQUEST
    elif isinstance(error, api_exceptions.DeadlineExceeded):
        code = SandboxTargetFailure.TIMEOUT
    else:
        code = SandboxTargetFailure.UNAVAILABLE
    return SandboxTargetError(code)


def _known_nonambiguous_write_failure(error: Exception) -> SandboxTargetError | None:
    mapped = _provider_failure(error)
    if mapped.code in {
        SandboxTargetFailure.CONFLICT,
        SandboxTargetFailure.CREDENTIALS_UNAVAILABLE,
        SandboxTargetFailure.DEPENDENCY_UNAVAILABLE,
        SandboxTargetFailure.INVALID_REQUEST,
    }:
        return mapped
    return None


class _SandboxFirestoreTarget:
    def __init__(
        self,
        *,
        project_id: str,
        database_id: str,
        timeout_seconds: float,
        client_factory: SandboxMutationClientFactory,
        clock: SandboxMutationClock,
    ) -> None:
        if (
            type(project_id) is not str
            or _PROJECT_PATTERN.fullmatch(project_id) is None
        ):
            raise ValueError("sandbox Firestore project identifier is invalid")
        if database_id != SANDBOX_TARGET_DATABASE_ID:
            raise ValueError("sandbox Firestore database identifier is invalid")
        if (
            type(timeout_seconds) not in {int, float}
            or float(timeout_seconds) != SANDBOX_FIRESTORE_TIMEOUT_SECONDS
        ):
            raise ValueError("sandbox Firestore timeout must use the fixed value")
        if not callable(client_factory) or not callable(clock):
            raise TypeError("sandbox Firestore factories must be callable")
        self._project_id = project_id
        self._database_id = database_id
        self._timeout_seconds = float(timeout_seconds)
        self._client_factory = client_factory
        self._clock = clock
        self._client: AsyncSandboxMutationClientPort | None = None
        self._client_lock = asyncio.Lock()

    def now(self) -> datetime:
        return _aware_utc(self._clock())

    async def client(self) -> AsyncSandboxMutationClientPort:
        if self._client is not None:
            return self._client
        async with self._client_lock:
            if self._client is None:
                try:
                    candidate = self._client_factory()
                except ImportError:
                    raise SandboxTargetError(
                        SandboxTargetFailure.DEPENDENCY_UNAVAILABLE
                    ) from None
                except Exception as error:
                    raise _provider_failure(error) from None
                try:
                    incomplete = any(
                        not callable(getattr(candidate, name, None))
                        for name in ("batch", "document", "get_all", "write_option")
                    )
                except Exception as error:
                    raise _provider_failure(error) from None
                if incomplete:
                    raise SandboxTargetError(SandboxTargetFailure.UNAVAILABLE) from None
                self._client = candidate
            return self._client

    @staticmethod
    def _reference(
        client: AsyncSandboxMutationClientPort,
        *segments: str,
    ) -> _DocumentReferencePort:
        expected_path = "/".join(segments)
        try:
            reference = client.document(*segments)
            path = reference.path
        except Exception as error:
            raise _provider_failure(error) from None
        if path != expected_path:
            raise SandboxTargetError(SandboxTargetFailure.MALFORMED_RESPONSE) from None
        return reference

    async def references(self, sandbox_id: str) -> _References:
        try:
            _IngressProjection(
                schema_version=SANDBOX_INGRESS_SCHEMA_VERSION,
                sandbox_id=sandbox_id,
                event_kind=_INGRESS_EVENT_KIND,
                observed_at=datetime(2000, 1, 1, tzinfo=UTC),
            )
        except (TypeError, ValueError, ValidationError) as error:
            raise ValueError("sandbox identifier is invalid") from error
        client = await self.client()
        return _References(
            private=self._reference(client, SANDBOX_PRIVATE_COLLECTION, sandbox_id),
            ingress=self._reference(
                client,
                SANDBOX_OBSERVATION_COLLECTION,
                sandbox_id,
                _WEAK_OBSERVATION_COLLECTION,
                _INGRESS_DOCUMENT,
            ),
            aggregate=self._reference(
                client,
                SANDBOX_OBSERVATION_COLLECTION,
                sandbox_id,
                _WEAK_OBSERVATION_COLLECTION,
                _AGGREGATE_DOCUMENT,
            ),
        )

    @staticmethod
    def new_batch(client: AsyncSandboxMutationClientPort) -> _WriteBatchPort:
        try:
            batch = client.batch()
        except Exception as error:
            raise _provider_failure(error) from None
        try:
            incomplete = any(
                not callable(getattr(batch, name, None))
                for name in ("commit", "create", "delete")
            )
        except Exception as error:
            raise _provider_failure(error) from None
        if incomplete:
            raise SandboxTargetError(SandboxTargetFailure.UNAVAILABLE) from None
        return batch

    @staticmethod
    def stage_create(
        batch: _WriteBatchPort,
        reference: _DocumentReferencePort,
        payload: dict[str, Any],
    ) -> None:
        try:
            batch.create(reference, payload)
        except Exception as error:
            raise _provider_failure(error) from None

    @staticmethod
    def stage_delete(
        batch: _WriteBatchPort,
        reference: _DocumentReferencePort,
        *,
        option: object,
    ) -> None:
        try:
            batch.delete(reference, option=option)
        except Exception as error:
            raise _provider_failure(error) from None

    @staticmethod
    def write_option(
        client: AsyncSandboxMutationClientPort,
        *,
        last_update_time: datetime,
    ) -> object:
        try:
            return client.write_option(last_update_time=last_update_time)
        except Exception as error:
            raise _provider_failure(error) from None

    async def commit(
        self,
        batch: _WriteBatchPort,
        *,
        creates_documents: bool,
    ) -> datetime | None:
        try:
            async with asyncio.timeout(self._timeout_seconds):
                results = await batch.commit(
                    retry=None,
                    timeout=self._timeout_seconds,
                )
        except asyncio.CancelledError:
            raise
        except Exception as error:
            known = _known_nonambiguous_write_failure(error)
            if known is not None:
                raise known from None
            raise _AmbiguousWrite from None
        try:
            if type(results) is not list or len(results) != 3:
                raise ValueError("write result count is malformed")
            if not creates_documents:
                if any(
                    result.update_time is not None  # type: ignore[attr-defined]
                    for result in results
                ):
                    raise ValueError("delete write result is malformed")
                return None
            update_times = tuple(
                _aware_utc(result.update_time)  # type: ignore[attr-defined]
                for result in results
            )
            if len(set(update_times)) != 1:
                raise ValueError("atomic write times are inconsistent")
            return update_times[0]
        except (AttributeError, TypeError, ValueError):
            raise _AmbiguousWrite from None

    async def snapshots(self, references: _References) -> _SnapshotSet:
        client = await self.client()
        expected = {reference.path: reference for reference in references.ordered}
        observed: dict[str, _DocumentSnapshotPort] = {}
        try:
            async with asyncio.timeout(self._timeout_seconds):
                iterator = client.get_all(
                    list(references.ordered),
                    field_paths=None,
                    transaction=None,
                    retry=None,
                    timeout=self._timeout_seconds,
                    read_time=None,
                )
                async for snapshot in iterator:
                    path = snapshot.reference.path
                    if path not in expected or path in observed:
                        raise ValueError("provider returned an unexpected document")
                    if type(snapshot.exists) is not bool:
                        raise TypeError("provider existence marker is malformed")
                    _aware_utc(snapshot.read_time)
                    if snapshot.exists:
                        _aware_utc(snapshot.update_time)
                    elif snapshot.update_time is not None:
                        raise ValueError("missing document has an update time")
                    observed[path] = snapshot
        except asyncio.CancelledError:
            raise
        except SandboxTargetError:
            raise
        except (AttributeError, TypeError, ValueError):
            raise SandboxTargetError(SandboxTargetFailure.MALFORMED_RESPONSE) from None
        except Exception as error:
            raise _provider_failure(error) from None
        if set(observed) != set(expected):
            raise SandboxTargetError(SandboxTargetFailure.MALFORMED_RESPONSE) from None
        return _SnapshotSet(
            private=observed[references.private.path],
            ingress=observed[references.ingress.path],
            aggregate=observed[references.aggregate.path],
        )

    @staticmethod
    def data(snapshot: _DocumentSnapshotPort) -> dict[str, Any] | None:
        try:
            data = snapshot.to_dict()
        except Exception as error:
            raise _provider_failure(error) from None
        if snapshot.exists:
            if type(data) is not dict:
                raise SandboxTargetError(
                    SandboxTargetFailure.MALFORMED_RESPONSE
                ) from None
            return data
        if data is not None:
            raise SandboxTargetError(SandboxTargetFailure.MALFORMED_RESPONSE) from None
        return None


def _record(
    *,
    sandbox_id: str,
    owner_token: str,
    item_code: str,
    quantity: int,
    hidden_outcome: HiddenOrderOutcome,
    observed_at: datetime,
) -> _PrivateSandboxAggregate:
    if type(hidden_outcome) is not HiddenOrderOutcome:
        raise TypeError("the hidden order outcome is invalid")
    order_present = hidden_outcome is HiddenOrderOutcome.COMMIT
    count_band = (
        WeakOrderCountBand.ONE_OR_MORE.value
        if order_present
        else WeakOrderCountBand.ZERO.value
    )
    ingress = _IngressProjection(
        schema_version=SANDBOX_INGRESS_SCHEMA_VERSION,
        sandbox_id=sandbox_id,
        event_kind=_INGRESS_EVENT_KIND,
        observed_at=observed_at,
    )
    aggregate = _AggregateProjection(
        schema_version=SANDBOX_AGGREGATE_SCHEMA_VERSION,
        sandbox_id=sandbox_id,
        count_band=count_band,
        observed_at=observed_at,
    )
    return _PrivateSandboxAggregate(
        schema_version=SANDBOX_PRIVATE_SCHEMA_VERSION,
        sandbox_id=sandbox_id,
        owner_token=_validated_text(owner_token, "sandbox owner"),
        item_quantity_sha256=_item_quantity_digest(item_code, quantity),
        order_present=order_present,
        ingress=ingress,
        aggregate=aggregate,
        revision=1,
        updated_at=observed_at,
    )


def _receipt(
    record: _PrivateSandboxAggregate,
    *,
    provider_update_time: datetime,
) -> SandboxMutationReceipt:
    return SandboxMutationReceipt(
        sandbox_id=record.sandbox_id,
        owner_sha256=_owner_digest(record.owner_token),
        item_quantity_sha256=record.item_quantity_sha256,
        state_sha256=_state_digest(record),
        order_present=record.order_present,
        revision=record.revision,
        observed_at=record.updated_at,
        provider_update_time=provider_update_time,
    )


def _expected_payloads(
    record: _PrivateSandboxAggregate,
) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    return (
        record.model_dump(mode="python"),
        record.ingress.model_dump(mode="python"),
        record.aggregate.model_dump(mode="python"),
    )


def _exact_poststate(
    target: _SandboxFirestoreTarget,
    snapshots: _SnapshotSet,
    record: _PrivateSandboxAggregate,
) -> datetime | None:
    expected = _expected_payloads(record)
    actual = tuple(target.data(snapshot) for snapshot in snapshots.ordered)
    if actual != expected:
        return None
    update_times = tuple(
        _aware_utc(snapshot.update_time) for snapshot in snapshots.ordered
    )
    if len(set(update_times)) != 1:
        return None
    return update_times[0]


class GoogleFirestoreSandboxMutationTarget:
    """Create one closed sandbox aggregate and its weak projections once."""

    def __init__(
        self,
        target: _SandboxFirestoreTarget,
        *,
        hidden_outcome: HiddenOrderOutcome,
    ) -> None:
        if type(hidden_outcome) is not HiddenOrderOutcome:
            raise TypeError("the hidden order outcome is invalid")
        self._target = target
        self._hidden_outcome = hidden_outcome

    async def submit_order(
        self,
        *,
        sandbox_id: str,
        owner_token: str,
        item_code: str,
        quantity: int,
    ) -> SandboxMutationReceipt:
        observed_at = self._target.now()
        record = _record(
            sandbox_id=sandbox_id,
            owner_token=owner_token,
            item_code=item_code,
            quantity=quantity,
            hidden_outcome=self._hidden_outcome,
            observed_at=observed_at,
        )
        references = await self._target.references(record.sandbox_id)
        client = await self._target.client()
        batch = self._target.new_batch(client)
        for reference, payload in zip(
            references.ordered,
            _expected_payloads(record),
            strict=True,
        ):
            self._target.stage_create(batch, reference, payload)
        try:
            update_time = await self._target.commit(
                batch,
                creates_documents=True,
            )
        except _AmbiguousWrite:
            try:
                snapshots = await self._target.snapshots(references)
                update_time = _exact_poststate(self._target, snapshots, record)
            except asyncio.CancelledError:
                raise
            except Exception:
                update_time = None
            if update_time is None:
                raise SandboxTargetError(SandboxTargetFailure.OUTCOME_UNKNOWN) from None
        if update_time is None:
            raise SandboxTargetError(SandboxTargetFailure.OUTCOME_UNKNOWN) from None
        return _receipt(record, provider_update_time=update_time)


class GoogleFirestoreSandboxCleanupTarget:
    """Delete only an exact owner-bound sandbox aggregate and its projections."""

    def __init__(
        self,
        target: _SandboxFirestoreTarget,
        *,
        hidden_outcome: HiddenOrderOutcome,
    ) -> None:
        if type(hidden_outcome) is not HiddenOrderOutcome:
            raise TypeError("the hidden order outcome is invalid")
        self._target = target
        self._order_present = hidden_outcome is HiddenOrderOutcome.COMMIT

    async def _owned(
        self,
        *,
        sandbox_id: str,
        owner_token: str,
        item_code: str,
        quantity: int,
    ) -> _OwnedState | None:
        owner = _validated_text(owner_token, "sandbox owner")
        item_quantity_sha256 = _item_quantity_digest(item_code, quantity)
        references = await self._target.references(sandbox_id)
        snapshots = await self._target.snapshots(references)
        data = tuple(self._target.data(snapshot) for snapshot in snapshots.ordered)
        if all(item is None for item in data):
            return None
        if any(item is None for item in data):
            raise SandboxTargetError(SandboxTargetFailure.NOT_OWNED) from None
        try:
            record = _PrivateSandboxAggregate.model_validate(data[0])
            ingress = _IngressProjection.model_validate(data[1])
            aggregate = _AggregateProjection.model_validate(data[2])
        except (TypeError, ValueError, ValidationError):
            raise SandboxTargetError(SandboxTargetFailure.NOT_OWNED) from None
        if (
            record.sandbox_id != sandbox_id
            or record.owner_token != owner
            or record.item_quantity_sha256 != item_quantity_sha256
            or record.order_present is not self._order_present
            or record.ingress != ingress
            or record.aggregate != aggregate
        ):
            raise SandboxTargetError(SandboxTargetFailure.NOT_OWNED) from None
        update_times = tuple(
            _aware_utc(snapshot.update_time) for snapshot in snapshots.ordered
        )
        if len(set(update_times)) != 1:
            raise SandboxTargetError(SandboxTargetFailure.NOT_OWNED) from None
        return _OwnedState(
            record=record,
            snapshots=snapshots,
            state_sha256=_state_digest(record),
        )

    async def count_owned(
        self,
        *,
        sandbox_id: str,
        owner_token: str,
        item_code: str,
        quantity: int,
    ) -> int:
        owned = await self._owned(
            sandbox_id=sandbox_id,
            owner_token=owner_token,
            item_code=item_code,
            quantity=quantity,
        )
        return 0 if owned is None else 3

    async def delete_owned(
        self,
        *,
        sandbox_id: str,
        owner_token: str,
        item_code: str,
        quantity: int,
    ) -> SandboxCleanupReceipt:
        owner_sha256 = _owner_digest(owner_token)
        owned = await self._owned(
            sandbox_id=sandbox_id,
            owner_token=owner_token,
            item_code=item_code,
            quantity=quantity,
        )
        if owned is None:
            return SandboxCleanupReceipt(
                sandbox_id=sandbox_id,
                owner_sha256=owner_sha256,
                state_sha256=None,
                private_removed=False,
                ingress_removed=False,
                aggregate_removed=False,
            )
        client = await self._target.client()
        batch = self._target.new_batch(client)
        for snapshot in owned.snapshots.ordered:
            update_time = _aware_utc(snapshot.update_time)
            self._target.stage_delete(
                batch,
                snapshot.reference,
                option=self._target.write_option(
                    client,
                    last_update_time=update_time,
                ),
            )
        try:
            await self._target.commit(
                batch,
                creates_documents=False,
            )
        except _AmbiguousWrite:
            try:
                references = await self._target.references(sandbox_id)
                snapshots = await self._target.snapshots(references)
                missing = all(
                    self._target.data(snapshot) is None
                    for snapshot in snapshots.ordered
                )
            except asyncio.CancelledError:
                raise
            except Exception:
                missing = False
            if not missing:
                raise SandboxTargetError(SandboxTargetFailure.OUTCOME_UNKNOWN) from None
        return SandboxCleanupReceipt(
            sandbox_id=sandbox_id,
            owner_sha256=owner_sha256,
            state_sha256=owned.state_sha256,
            private_removed=True,
            ingress_removed=True,
            aggregate_removed=True,
        )


@dataclass(frozen=True, slots=True)
class GoogleFirestoreSandboxTargets:
    mutation: GoogleFirestoreSandboxMutationTarget
    cleanup: GoogleFirestoreSandboxCleanupTarget


def build_google_firestore_sandbox_targets(
    *,
    project_id: str,
    hidden_outcome: HiddenOrderOutcome,
    database_id: str = SANDBOX_TARGET_DATABASE_ID,
    timeout_seconds: float = SANDBOX_FIRESTORE_TIMEOUT_SECONDS,
    client_factory: SandboxMutationClientFactory | None = None,
    clock: SandboxMutationClock | None = None,
) -> GoogleFirestoreSandboxTargets:
    """Build capability-separated targets without resolving ADC eagerly."""

    target = _SandboxFirestoreTarget(
        project_id=project_id,
        database_id=database_id,
        timeout_seconds=timeout_seconds,
        client_factory=(
            _default_client_factory(project_id, database_id)
            if client_factory is None
            else client_factory
        ),
        clock=clock or _utc_now,
    )
    return GoogleFirestoreSandboxTargets(
        mutation=GoogleFirestoreSandboxMutationTarget(
            target,
            hidden_outcome=hidden_outcome,
        ),
        cleanup=GoogleFirestoreSandboxCleanupTarget(
            target,
            hidden_outcome=hidden_outcome,
        ),
    )


__all__ = [
    "SANDBOX_OBSERVATION_COLLECTION",
    "SANDBOX_PRIVATE_COLLECTION",
    "SANDBOX_PRIVATE_SCHEMA_VERSION",
    "AsyncSandboxMutationClientPort",
    "GoogleFirestoreSandboxCleanupTarget",
    "GoogleFirestoreSandboxMutationTarget",
    "GoogleFirestoreSandboxTargets",
    "SandboxCleanupReceipt",
    "SandboxMutationClientFactory",
    "SandboxMutationReceipt",
    "SandboxTargetError",
    "SandboxTargetFailure",
    "build_google_firestore_sandbox_targets",
]
