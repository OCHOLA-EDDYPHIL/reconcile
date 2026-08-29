"""Deterministic hosted sandbox mutation and exact cleanup behavior."""

from __future__ import annotations

import asyncio
import hashlib
from collections.abc import Callable
from copy import deepcopy
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest

from reconcile.contracts.base import canonical_json_value_bytes
from reconcile.hosted.sandbox import (
    SANDBOX_AGGREGATE_SCHEMA_VERSION,
    SANDBOX_INGRESS_SCHEMA_VERSION,
    FirestoreSandboxEvidenceReader,
    SandboxAggregateEvidence,
    SandboxEvidenceRequest,
    SandboxIngressEvidence,
)
from reconcile.hosted.sandbox_mutation import (
    SANDBOX_OBSERVATION_COLLECTION,
    SANDBOX_PRIVATE_COLLECTION,
    SANDBOX_PRIVATE_SCHEMA_VERSION,
    SandboxTargetError,
    SandboxTargetFailure,
    build_google_firestore_sandbox_targets,
)
from reconcile.scenarios.local_order import HiddenOrderOutcome

pytestmark = pytest.mark.unit

_PROJECT = "example-project-id"
_SANDBOX = "sandbox-order-hosted-7"
_OWNER = "sandbox-owner-0123456789abcdef"
_ITEM = "widget-blue"
_QUANTITY = 2
_NOW = datetime(2026, 8, 18, 1, 2, 3, tzinfo=UTC)
_PRIVATE_PATH = f"{SANDBOX_PRIVATE_COLLECTION}/{_SANDBOX}"
_INGRESS_PATH = f"{SANDBOX_OBSERVATION_COLLECTION}/{_SANDBOX}/weak-observations/ingress"
_AGGREGATE_PATH = (
    f"{SANDBOX_OBSERVATION_COLLECTION}/{_SANDBOX}/weak-observations/aggregate"
)


@dataclass(frozen=True, slots=True)
class _Option:
    kind: str
    value: object


@dataclass(frozen=True, slots=True)
class _Reference:
    path: str


@dataclass(frozen=True, slots=True)
class _WriteResult:
    update_time: datetime | None


@dataclass(slots=True)
class _Snapshot:
    reference: _Reference
    exists: bool
    read_time: datetime
    update_time: datetime | None
    data: dict[str, Any] | None

    def to_dict(self) -> dict[str, Any] | None:
        return deepcopy(self.data)


@dataclass(frozen=True, slots=True)
class _Operation:
    kind: str
    reference: _Reference
    payload: dict[str, Any] | None
    option: _Option | None


class _Batch:
    def __init__(self, client: _Client) -> None:
        self._client = client
        self._operations: list[_Operation] = []

    def create(self, reference: _Reference, document_data: dict[str, Any]) -> None:
        if self._client.create_staging_failure is not None:
            raise self._client.create_staging_failure
        self._operations.append(
            _Operation("create", reference, deepcopy(document_data), None)
        )

    def delete(
        self,
        reference: _Reference,
        option: _Option | None = None,
    ) -> None:
        if self._client.delete_staging_failure is not None:
            raise self._client.delete_staging_failure
        self._operations.append(_Operation("delete", reference, None, option))

    async def commit(
        self,
        retry: object | None = None,
        timeout: float | None = None,
    ) -> list[_WriteResult]:
        return self._client.apply(
            self._operations,
            retry=retry,
            timeout=timeout,
        )


class _Client:
    def __init__(self) -> None:
        self.documents: dict[str, tuple[dict[str, Any], datetime]] = {}
        self.commits: list[
            tuple[tuple[_Operation, ...], object | None, float | None]
        ] = []
        self.gets: list[
            tuple[
                tuple[str, ...],
                object | None,
                object | None,
                object | None,
                float | None,
                datetime | None,
            ]
        ] = []
        self.before_failure: dict[int, BaseException] = {}
        self.after_failure: dict[int, BaseException] = {}
        self.before_hook: dict[int, Callable[[_Client], None]] = {}
        self.after_hook: dict[int, Callable[[_Client], None]] = {}
        self.malformed_results: set[int] = set()
        self.read_failure: BaseException | None = None
        self.duplicate_snapshot = False
        self.create_staging_failure: BaseException | None = None
        self.delete_staging_failure: BaseException | None = None

    def document(self, *document_path: str) -> _Reference:
        return _Reference("/".join(document_path))

    def batch(self) -> _Batch:
        return _Batch(self)

    def write_option(self, **kwargs: object) -> _Option:
        assert tuple(kwargs) == ("last_update_time",)
        return _Option("last_update_time", kwargs["last_update_time"])

    async def get_all(
        self,
        references: list[_Reference],
        field_paths: object | None = None,
        transaction: object | None = None,
        retry: object | None = None,
        timeout: float | None = None,
        *,
        read_time: datetime | None = None,
    ):
        self.gets.append(
            (
                tuple(reference.path for reference in references),
                field_paths,
                transaction,
                retry,
                timeout,
                read_time,
            )
        )
        if self.read_failure is not None:
            raise self.read_failure
        observed_at = _NOW + timedelta(minutes=10, seconds=len(self.gets))
        snapshots: list[_Snapshot] = []
        for reference in reversed(references):
            stored = self.documents.get(reference.path)
            snapshots.append(
                _Snapshot(
                    reference=reference,
                    exists=stored is not None,
                    read_time=observed_at,
                    update_time=None if stored is None else stored[1],
                    data=None if stored is None else deepcopy(stored[0]),
                )
            )
        if self.duplicate_snapshot:
            snapshots.append(snapshots[0])
        for snapshot in snapshots:
            yield snapshot

    @staticmethod
    def _check_delete(
        current: tuple[dict[str, Any], datetime] | None,
        option: _Option | None,
    ) -> None:
        if (
            option is None
            or option.kind != "last_update_time"
            or current is None
            or current[1] != option.value
        ):
            raise SandboxTargetError(SandboxTargetFailure.CONFLICT)

    def apply(
        self,
        operations: list[_Operation],
        *,
        retry: object | None,
        timeout: float | None,
    ) -> list[_WriteResult]:
        number = len(self.commits) + 1
        self.commits.append((tuple(operations), retry, timeout))
        if number in self.before_hook:
            self.before_hook[number](self)
        if number in self.before_failure:
            raise self.before_failure[number]
        staged = deepcopy(self.documents)
        commit_time = _NOW + timedelta(seconds=number)
        for operation in operations:
            current = staged.get(operation.reference.path)
            if operation.kind == "create":
                if current is not None:
                    raise SandboxTargetError(SandboxTargetFailure.CONFLICT)
                assert operation.payload is not None
                staged[operation.reference.path] = (
                    deepcopy(operation.payload),
                    commit_time,
                )
            elif operation.kind == "delete":
                self._check_delete(current, operation.option)
                del staged[operation.reference.path]
            else:
                raise AssertionError("unexpected fake operation")
        self.documents = staged
        if number in self.after_hook:
            self.after_hook[number](self)
        if number in self.after_failure:
            raise self.after_failure[number]
        if number in self.malformed_results:
            return []
        return [
            _WriteResult(commit_time if operation.kind == "create" else None)
            for operation in operations
        ]


@dataclass(slots=True)
class _Factory:
    client: _Client
    calls: int = 0

    def __call__(self) -> _Client:
        self.calls += 1
        return self.client


def _targets(
    client: _Client,
    *,
    hidden_outcome: HiddenOrderOutcome = HiddenOrderOutcome.COMMIT,
    factory: _Factory | None = None,
):
    return build_google_firestore_sandbox_targets(
        project_id=_PROJECT,
        hidden_outcome=hidden_outcome,
        client_factory=factory or _Factory(client),
        clock=lambda: _NOW,
    )


async def _submit(client: _Client, **updates: object):
    values: dict[str, object] = {
        "sandbox_id": _SANDBOX,
        "owner_token": _OWNER,
        "item_code": _ITEM,
        "quantity": _QUANTITY,
    }
    values.update(updates)
    return await _targets(client).mutation.submit_order(**values)  # type: ignore[arg-type]


def _item_digest() -> str:
    return hashlib.sha256(
        canonical_json_value_bytes({"item_code": _ITEM, "quantity": _QUANTITY})
    ).hexdigest()


def test_builder_is_lazy_and_requires_the_exact_database_and_timeout() -> None:
    client = _Client()
    factory = _Factory(client)

    targets = _targets(client, factory=factory)

    assert factory.calls == 0
    assert targets.mutation is not None
    assert targets.cleanup is not None
    with pytest.raises(ValueError, match="database identifier"):
        build_google_firestore_sandbox_targets(
            project_id=_PROJECT,
            database_id="(default)",
            hidden_outcome=HiddenOrderOutcome.COMMIT,
            client_factory=factory,
        )
    with pytest.raises(ValueError, match="fixed value"):
        build_google_firestore_sandbox_targets(
            project_id=_PROJECT,
            hidden_outcome=HiddenOrderOutcome.COMMIT,
            timeout_seconds=4.9,
            client_factory=factory,
        )


def test_commit_creates_one_private_aggregate_and_exact_public_projections() -> None:
    async def exercise() -> None:
        client = _Client()
        factory = _Factory(client)
        receipt = await _targets(client, factory=factory).mutation.submit_order(
            sandbox_id=_SANDBOX,
            owner_token=_OWNER,
            item_code=_ITEM,
            quantity=_QUANTITY,
        )

        assert factory.calls == 1
        assert tuple(client.documents) == (
            _PRIVATE_PATH,
            _INGRESS_PATH,
            _AGGREGATE_PATH,
        )
        private = client.documents[_PRIVATE_PATH][0]
        assert private == {
            "schema_version": SANDBOX_PRIVATE_SCHEMA_VERSION,
            "sandbox_id": _SANDBOX,
            "owner_token": _OWNER,
            "item_quantity_sha256": _item_digest(),
            "order_present": True,
            "ingress": {
                "schema_version": SANDBOX_INGRESS_SCHEMA_VERSION,
                "sandbox_id": _SANDBOX,
                "event_kind": "REQUEST_SEEN",
                "observed_at": _NOW,
            },
            "aggregate": {
                "schema_version": SANDBOX_AGGREGATE_SCHEMA_VERSION,
                "sandbox_id": _SANDBOX,
                "count_band": "ONE_OR_MORE",
                "observed_at": _NOW,
            },
            "revision": 1,
            "updated_at": _NOW,
        }
        assert client.documents[_INGRESS_PATH][0] == private["ingress"]
        assert client.documents[_AGGREGATE_PATH][0] == private["aggregate"]
        assert receipt.sandbox_id == _SANDBOX
        assert receipt.owner_sha256 == hashlib.sha256(_OWNER.encode()).hexdigest()
        assert receipt.item_quantity_sha256 == _item_digest()
        assert receipt.order_present is True
        assert receipt.provider_update_time == _NOW + timedelta(seconds=1)
        assert _OWNER not in receipt.model_dump_json()
        operations, retry, timeout = client.commits[0]
        assert tuple(operation.kind for operation in operations) == (
            "create",
            "create",
            "create",
        )
        assert retry is None
        assert timeout == 5.0
        assert client.gets == []

    asyncio.run(exercise())


def test_discarded_hidden_outcome_keeps_ingress_and_projects_zero() -> None:
    async def exercise() -> None:
        client = _Client()
        receipt = await _targets(
            client,
            hidden_outcome=HiddenOrderOutcome.DISCARD,
        ).mutation.submit_order(
            sandbox_id=_SANDBOX,
            owner_token=_OWNER,
            item_code=_ITEM,
            quantity=_QUANTITY,
        )

        assert receipt.order_present is False
        assert client.documents[_PRIVATE_PATH][0]["order_present"] is False
        assert client.documents[_AGGREGATE_PATH][0]["count_band"] == "ZERO"
        assert client.documents[_INGRESS_PATH][0]["event_kind"] == "REQUEST_SEEN"

    asyncio.run(exercise())


def test_public_projections_are_compatible_with_the_existing_read_boundary() -> None:
    async def exercise() -> None:
        client = _Client()
        await _submit(client)
        reader = FirestoreSandboxEvidenceReader(
            project_id=_PROJECT,
            database_id="reconcile-p5-sandbox",
            client_factory=_Factory(client),
        )

        ingress = await reader.read_evidence(
            SandboxEvidenceRequest(sandbox_id=_SANDBOX, observation="ingress")
        )
        aggregate = await reader.read_evidence(
            SandboxEvidenceRequest(sandbox_id=_SANDBOX, observation="aggregate")
        )

        assert ingress == SandboxIngressEvidence.model_validate(
            {"ingress": {"event_kind": "REQUEST_SEEN", "observed_at": _NOW}}
        )
        assert aggregate == SandboxAggregateEvidence.model_validate(
            {"aggregate": {"count_band": "ONE_OR_MORE", "observed_at": _NOW}}
        )
        assert all(call[2:] == (None, None, 5.0, None) for call in client.gets)

    asyncio.run(exercise())


@pytest.mark.parametrize(
    ("field", "value"),
    (
        ("sandbox_id", "unsafe/id"),
        ("owner_token", ""),
        ("item_code", ""),
        ("quantity", 0),
        ("quantity", True),
    ),
)
def test_invalid_mutation_input_fails_before_client_resolution(
    field: str,
    value: object,
) -> None:
    async def exercise() -> None:
        client = _Client()
        factory = _Factory(client)
        values: dict[str, object] = {
            "sandbox_id": _SANDBOX,
            "owner_token": _OWNER,
            "item_code": _ITEM,
            "quantity": _QUANTITY,
        }
        values[field] = value
        with pytest.raises((TypeError, ValueError)):
            await _targets(client, factory=factory).mutation.submit_order(  # type: ignore[arg-type]
                **values
            )
        assert factory.calls == 0

    asyncio.run(exercise())


def test_create_conflict_is_sanitized_and_never_read_or_retried() -> None:
    async def exercise() -> None:
        client = _Client()
        await _submit(client)

        with pytest.raises(SandboxTargetError) as raised:
            await _submit(client)

        assert raised.value.code is SandboxTargetFailure.CONFLICT
        assert str(raised.value) == "conflict"
        assert len(client.commits) == 2
        assert client.gets == []

    asyncio.run(exercise())


@pytest.mark.parametrize(
    ("failure", "expected"),
    (
        (RuntimeError("private staging detail"), SandboxTargetFailure.UNAVAILABLE),
        (
            SandboxTargetError(SandboxTargetFailure.INVALID_REQUEST),
            SandboxTargetFailure.INVALID_REQUEST,
        ),
    ),
)
def test_create_staging_failure_is_sanitized_without_commit(
    failure: BaseException,
    expected: SandboxTargetFailure,
) -> None:
    async def exercise() -> None:
        client = _Client()
        client.create_staging_failure = failure

        with pytest.raises(SandboxTargetError) as raised:
            await _submit(client)

        assert raised.value.code is expected
        assert "private" not in str(raised.value)
        assert raised.value.__cause__ is None
        assert client.commits == []
        assert client.gets == []
        assert client.documents == {}

    asyncio.run(exercise())


def test_ambiguous_create_adopts_only_one_exact_strong_readback() -> None:
    async def exercise() -> None:
        client = _Client()
        client.after_failure[1] = TimeoutError("private provider response")

        receipt = await _submit(client)

        assert receipt.state_sha256
        assert len(client.commits) == 1
        assert len(client.gets) == 1
        paths, fields, transaction, retry, timeout, read_time = client.gets[0]
        assert paths == (_PRIVATE_PATH, _INGRESS_PATH, _AGGREGATE_PATH)
        assert (fields, transaction, retry, timeout, read_time) == (
            None,
            None,
            None,
            5.0,
            None,
        )

    asyncio.run(exercise())


def test_ambiguous_create_before_apply_is_unknown_without_write_replay() -> None:
    async def exercise() -> None:
        client = _Client()
        client.before_failure[1] = TimeoutError("private provider response")

        with pytest.raises(SandboxTargetError) as raised:
            await _submit(client)

        assert raised.value.code is SandboxTargetFailure.OUTCOME_UNKNOWN
        assert str(raised.value) == "outcome-unknown"
        assert len(client.commits) == 1
        assert len(client.gets) == 1
        assert client.documents == {}

    asyncio.run(exercise())


def test_ambiguous_create_rejects_a_nonexact_poststate() -> None:
    async def exercise() -> None:
        client = _Client()

        def corrupt_after_apply(current: _Client) -> None:
            payload, updated_at = current.documents[_AGGREGATE_PATH]
            changed = deepcopy(payload)
            changed["count_band"] = "ZERO"
            current.documents[_AGGREGATE_PATH] = (changed, updated_at)

        client.after_hook[1] = corrupt_after_apply
        client.after_failure[1] = TimeoutError("private provider response")

        with pytest.raises(SandboxTargetError) as raised:
            await _submit(client)

        assert raised.value.code is SandboxTargetFailure.OUTCOME_UNKNOWN
        assert len(client.commits) == 1
        assert len(client.gets) == 1

    asyncio.run(exercise())


def test_malformed_commit_result_uses_the_same_single_exact_readback() -> None:
    async def exercise() -> None:
        client = _Client()
        client.malformed_results.add(1)

        receipt = await _submit(client)

        assert receipt.provider_update_time == _NOW + timedelta(seconds=1)
        assert len(client.commits) == 1
        assert len(client.gets) == 1

    asyncio.run(exercise())


def test_cancellation_propagates_without_readback_or_replay() -> None:
    async def exercise() -> None:
        client = _Client()
        client.before_failure[1] = asyncio.CancelledError()

        with pytest.raises(asyncio.CancelledError):
            await _submit(client)

        assert len(client.commits) == 1
        assert client.gets == []

    asyncio.run(exercise())


def test_cleanup_verifies_ownership_then_conditionally_deletes_every_document() -> None:
    async def exercise() -> None:
        client = _Client()
        targets = _targets(client)
        mutation = await targets.mutation.submit_order(
            sandbox_id=_SANDBOX,
            owner_token=_OWNER,
            item_code=_ITEM,
            quantity=_QUANTITY,
        )

        assert (
            await targets.cleanup.count_owned(
                sandbox_id=_SANDBOX,
                owner_token=_OWNER,
                item_code=_ITEM,
                quantity=_QUANTITY,
            )
            == 3
        )
        receipt = await targets.cleanup.delete_owned(
            sandbox_id=_SANDBOX,
            owner_token=_OWNER,
            item_code=_ITEM,
            quantity=_QUANTITY,
        )

        assert receipt.state_sha256 == mutation.state_sha256
        assert receipt.removed_count == 3
        assert receipt.private_removed is True
        assert receipt.ingress_removed is True
        assert receipt.aggregate_removed is True
        assert client.documents == {}
        operations, retry, timeout = client.commits[1]
        assert tuple(operation.kind for operation in operations) == (
            "delete",
            "delete",
            "delete",
        )
        assert all(
            operation.option == _Option("last_update_time", _NOW + timedelta(seconds=1))
            for operation in operations
        )
        assert retry is None
        assert timeout == 5.0

    asyncio.run(exercise())


def test_cleanup_of_absent_scope_is_a_noop_without_a_write() -> None:
    async def exercise() -> None:
        client = _Client()

        receipt = await _targets(client).cleanup.delete_owned(
            sandbox_id=_SANDBOX,
            owner_token=_OWNER,
            item_code=_ITEM,
            quantity=_QUANTITY,
        )

        assert receipt.removed_count == 0
        assert receipt.state_sha256 is None
        assert client.commits == []
        assert len(client.gets) == 1

    asyncio.run(exercise())


@pytest.mark.parametrize(
    "foreign",
    ("owner", "item", "outcome", "projection", "update-time"),
)
def test_cleanup_never_deletes_foreign_or_inconsistent_state(foreign: str) -> None:
    async def exercise() -> None:
        client = _Client()
        targets = _targets(client)
        await targets.mutation.submit_order(
            sandbox_id=_SANDBOX,
            owner_token=_OWNER,
            item_code=_ITEM,
            quantity=_QUANTITY,
        )
        owner = _OWNER
        if foreign == "owner":
            owner = "sandbox-owner-foreign"
        elif foreign == "item":
            payload, update_time = client.documents[_PRIVATE_PATH]
            changed = deepcopy(payload)
            changed["item_quantity_sha256"] = "0" * 64
            client.documents[_PRIVATE_PATH] = (changed, update_time)
        elif foreign == "outcome":
            private, private_time = client.documents[_PRIVATE_PATH]
            changed_private = deepcopy(private)
            changed_private["order_present"] = False
            changed_private["aggregate"]["count_band"] = "ZERO"
            client.documents[_PRIVATE_PATH] = (changed_private, private_time)
            aggregate, aggregate_time = client.documents[_AGGREGATE_PATH]
            changed_aggregate = deepcopy(aggregate)
            changed_aggregate["count_band"] = "ZERO"
            client.documents[_AGGREGATE_PATH] = (
                changed_aggregate,
                aggregate_time,
            )
        elif foreign == "projection":
            payload, update_time = client.documents[_AGGREGATE_PATH]
            changed = deepcopy(payload)
            changed["count_band"] = "ZERO"
            client.documents[_AGGREGATE_PATH] = (changed, update_time)
        else:
            payload, _ = client.documents[_INGRESS_PATH]
            client.documents[_INGRESS_PATH] = (
                payload,
                _NOW + timedelta(minutes=1),
            )

        with pytest.raises(SandboxTargetError) as raised:
            await targets.cleanup.delete_owned(
                sandbox_id=_SANDBOX,
                owner_token=owner,
                item_code=_ITEM,
                quantity=_QUANTITY,
            )

        assert raised.value.code is SandboxTargetFailure.NOT_OWNED
        assert len(client.commits) == 1
        assert len(client.documents) == 3

    asyncio.run(exercise())


def test_cleanup_precondition_conflict_is_atomic_and_never_retried() -> None:
    async def exercise() -> None:
        client = _Client()
        targets = _targets(client)
        await targets.mutation.submit_order(
            sandbox_id=_SANDBOX,
            owner_token=_OWNER,
            item_code=_ITEM,
            quantity=_QUANTITY,
        )

        def race(current: _Client) -> None:
            payload, _ = current.documents[_PRIVATE_PATH]
            current.documents[_PRIVATE_PATH] = (
                payload,
                _NOW + timedelta(minutes=2),
            )

        client.before_hook[2] = race
        with pytest.raises(SandboxTargetError) as raised:
            await targets.cleanup.delete_owned(
                sandbox_id=_SANDBOX,
                owner_token=_OWNER,
                item_code=_ITEM,
                quantity=_QUANTITY,
            )

        assert raised.value.code is SandboxTargetFailure.CONFLICT
        assert len(client.commits) == 2
        assert len(client.documents) == 3

    asyncio.run(exercise())


def test_cleanup_staging_failure_is_sanitized_without_delete_attempt() -> None:
    async def exercise() -> None:
        client = _Client()
        targets = _targets(client)
        await targets.mutation.submit_order(
            sandbox_id=_SANDBOX,
            owner_token=_OWNER,
            item_code=_ITEM,
            quantity=_QUANTITY,
        )
        client.delete_staging_failure = RuntimeError("private cleanup detail")

        with pytest.raises(SandboxTargetError) as raised:
            await targets.cleanup.delete_owned(
                sandbox_id=_SANDBOX,
                owner_token=_OWNER,
                item_code=_ITEM,
                quantity=_QUANTITY,
            )

        assert raised.value.code is SandboxTargetFailure.UNAVAILABLE
        assert "private" not in str(raised.value)
        assert raised.value.__cause__ is None
        assert len(client.commits) == 1
        assert len(client.gets) == 1
        assert len(client.documents) == 3

    asyncio.run(exercise())


def test_ambiguous_cleanup_adopts_only_one_all_missing_readback() -> None:
    async def exercise() -> None:
        client = _Client()
        targets = _targets(client)
        await targets.mutation.submit_order(
            sandbox_id=_SANDBOX,
            owner_token=_OWNER,
            item_code=_ITEM,
            quantity=_QUANTITY,
        )
        client.after_failure[2] = TimeoutError("private provider response")

        receipt = await targets.cleanup.delete_owned(
            sandbox_id=_SANDBOX,
            owner_token=_OWNER,
            item_code=_ITEM,
            quantity=_QUANTITY,
        )

        assert receipt.removed_count == 3
        assert client.documents == {}
        assert len(client.commits) == 2
        assert len(client.gets) == 2

    asyncio.run(exercise())


def test_ambiguous_cleanup_with_present_state_is_unknown_without_delete_replay() -> (
    None
):
    async def exercise() -> None:
        client = _Client()
        targets = _targets(client)
        await targets.mutation.submit_order(
            sandbox_id=_SANDBOX,
            owner_token=_OWNER,
            item_code=_ITEM,
            quantity=_QUANTITY,
        )
        client.before_failure[2] = TimeoutError("private provider response")

        with pytest.raises(SandboxTargetError) as raised:
            await targets.cleanup.delete_owned(
                sandbox_id=_SANDBOX,
                owner_token=_OWNER,
                item_code=_ITEM,
                quantity=_QUANTITY,
            )

        assert raised.value.code is SandboxTargetFailure.OUTCOME_UNKNOWN
        assert str(raised.value) == "outcome-unknown"
        assert len(client.commits) == 2
        assert len(client.gets) == 2
        assert len(client.documents) == 3

    asyncio.run(exercise())


def test_cancellation_during_ambiguous_readback_propagates() -> None:
    async def exercise() -> None:
        client = _Client()
        client.before_failure[1] = TimeoutError("private provider response")
        client.read_failure = asyncio.CancelledError()

        with pytest.raises(asyncio.CancelledError):
            await _submit(client)

        assert len(client.commits) == 1
        assert len(client.gets) == 1

    asyncio.run(exercise())


def test_client_factory_failure_is_sanitized() -> None:
    def unavailable() -> _Client:
        raise RuntimeError("credential private detail")

    async def exercise() -> None:
        targets = build_google_firestore_sandbox_targets(
            project_id=_PROJECT,
            hidden_outcome=HiddenOrderOutcome.COMMIT,
            client_factory=unavailable,
            clock=lambda: _NOW,
        )

        with pytest.raises(SandboxTargetError) as raised:
            await targets.mutation.submit_order(
                sandbox_id=_SANDBOX,
                owner_token=_OWNER,
                item_code=_ITEM,
                quantity=_QUANTITY,
            )

        assert raised.value.code is SandboxTargetFailure.UNAVAILABLE
        assert str(raised.value) == "unavailable"
        assert raised.value.__cause__ is None
        assert raised.value.__suppress_context__ is True

    asyncio.run(exercise())


def test_staging_cancellation_propagates_without_commit_or_delete() -> None:
    async def exercise() -> None:
        mutation_client = _Client()
        mutation_client.create_staging_failure = asyncio.CancelledError()
        with pytest.raises(asyncio.CancelledError):
            await _submit(mutation_client)
        assert mutation_client.commits == []
        assert mutation_client.documents == {}

        cleanup_client = _Client()
        targets = _targets(cleanup_client)
        await targets.mutation.submit_order(
            sandbox_id=_SANDBOX,
            owner_token=_OWNER,
            item_code=_ITEM,
            quantity=_QUANTITY,
        )
        cleanup_client.delete_staging_failure = asyncio.CancelledError()
        with pytest.raises(asyncio.CancelledError):
            await targets.cleanup.delete_owned(
                sandbox_id=_SANDBOX,
                owner_token=_OWNER,
                item_code=_ITEM,
                quantity=_QUANTITY,
            )
        assert len(cleanup_client.commits) == 1
        assert len(cleanup_client.documents) == 3

    asyncio.run(exercise())


def test_protocol_introspection_failures_are_sanitized() -> None:
    class BrokenClient(_Client):
        def __getattribute__(self, name: str):
            if name == "batch":
                raise RuntimeError("private client protocol detail")
            return super().__getattribute__(name)

    class BrokenBatch:
        @property
        def create(self):
            raise RuntimeError("private batch protocol detail")

        async def commit(self, **kwargs: object) -> list[object]:
            del kwargs
            return []

        def delete(self, *args: object, **kwargs: object) -> None:
            del args, kwargs

    class BrokenBatchClient(_Client):
        def batch(self) -> BrokenBatch:
            return BrokenBatch()

    async def exercise() -> None:
        for client in (BrokenClient(), BrokenBatchClient()):
            with pytest.raises(SandboxTargetError) as raised:
                await _submit(client)
            assert raised.value.code is SandboxTargetFailure.UNAVAILABLE
            assert "private" not in str(raised.value)
            assert raised.value.__cause__ is None
            assert client.commits == []
            assert client.documents == {}

    asyncio.run(exercise())
