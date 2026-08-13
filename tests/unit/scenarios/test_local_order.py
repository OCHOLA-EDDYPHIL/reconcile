"""Local order sandbox oracle isolation and ownership behavior."""

from __future__ import annotations

import inspect
import sqlite3
from dataclasses import fields
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from reconcile.scenarios.local_order import (
    HiddenOrderOutcome,
    LocalOrderCleanupTarget,
    LocalOrderError,
    LocalOrderHarness,
    LocalOrderMutationTarget,
    LocalOrderReadTarget,
    OrderExecutionAlreadyExists,
    OrderOwnershipError,
    WeakIngressObservation,
    WeakOrderAggregateObservation,
    WeakOrderCountBand,
    WeakOrderObservationSnapshot,
    weak_observation_bytes,
)

pytestmark = pytest.mark.unit

NOW = datetime(2026, 8, 13, 21, 0, tzinfo=UTC)
ITEM_CODE = "widget-blue"
QUANTITY = 2


class _StepClock:
    def __init__(self, start: datetime = NOW) -> None:
        self._next = start

    def __call__(self) -> datetime:
        result = self._next
        self._next += timedelta(seconds=1)
        return result


def _paths(tmp_path: Path, name: str = "sandbox") -> tuple[Path, Path]:
    return (
        tmp_path / f"{name}-private.sqlite3",
        tmp_path / f"{name}-observations.sqlite3",
    )


def _prepare(
    tmp_path: Path,
    *,
    name: str,
    outcome: HiddenOrderOutcome,
    owner_token: str = "cleanup-owner-7",
) -> tuple[
    tuple[Path, Path],
    LocalOrderHarness,
    LocalOrderReadTarget,
    LocalOrderCleanupTarget,
]:
    private_path, observation_path = _paths(tmp_path, name)
    harness = LocalOrderHarness(
        private_path,
        observation_path,
        clock=lambda: NOW,
    )
    harness.seed_duplicate_looking_order(item_code=ITEM_CODE, quantity=QUANTITY)
    mutation = LocalOrderMutationTarget(
        private_path,
        observation_path,
        hidden_outcome=outcome,
        clock=lambda: NOW + timedelta(seconds=1),
    )
    result = mutation.submit_order(
        owner_token=owner_token,
        item_code=ITEM_CODE,
        quantity=QUANTITY,
    )
    assert result is None
    return (
        (private_path, observation_path),
        harness,
        LocalOrderReadTarget(observation_path),
        LocalOrderCleanupTarget(private_path, observation_path),
    )


def test_hidden_commit_and_discard_have_byte_identical_public_observations(
    tmp_path: Path,
) -> None:
    _, commit_harness, commit_read, _ = _prepare(
        tmp_path,
        name="commit",
        outcome=HiddenOrderOutcome.COMMIT,
    )
    _, discard_harness, discard_read, _ = _prepare(
        tmp_path,
        name="discard",
        outcome=HiddenOrderOutcome.DISCARD,
    )

    commit_snapshot = commit_read.read_snapshot()
    discard_snapshot = discard_read.read_snapshot()

    assert commit_snapshot == discard_snapshot
    assert weak_observation_bytes(commit_snapshot) == weak_observation_bytes(
        discard_snapshot
    )
    assert len(commit_harness.private_orders()) == 2
    assert len(discard_harness.private_orders()) == 1
    assert {
        (order.item_code, order.quantity) for order in commit_harness.private_orders()
    } == {(ITEM_CODE, QUANTITY)}
    assert {
        (order.item_code, order.quantity) for order in discard_harness.private_orders()
    } == {(ITEM_CODE, QUANTITY)}


def test_public_observations_contain_no_owner_request_or_hidden_outcome(
    tmp_path: Path,
) -> None:
    (private_path, observation_path), _, read_target, _ = _prepare(
        tmp_path,
        name="public-shape",
        outcome=HiddenOrderOutcome.COMMIT,
        owner_token="private-owner-do-not-expose",
    )

    snapshot = read_target.read_snapshot()
    payload = weak_observation_bytes(snapshot)

    assert [field.name for field in fields(WeakIngressObservation)] == [
        "event_kind",
        "observed_at",
    ]
    assert [field.name for field in fields(WeakOrderAggregateObservation)] == [
        "count_band",
        "observed_at",
    ]
    assert b"private-owner-do-not-expose" not in payload
    assert ITEM_CODE.encode() not in payload
    assert b"COMMIT" not in payload
    assert b"DISCARD" not in payload
    assert b"operation" not in payload
    assert b"invocation" not in payload

    connection = sqlite3.connect(observation_path)
    try:
        observation_tables = {
            row[0]
            for row in connection.execute(
                "SELECT name FROM sqlite_master WHERE type = 'table'"
            ).fetchall()
        }
        ingress_columns = {
            row[1]
            for row in connection.execute(
                "PRAGMA table_info(weak_ingress_events)"
            ).fetchall()
        }
    finally:
        connection.close()
    private_connection = sqlite3.connect(private_path)
    try:
        private_tables = {
            row[0]
            for row in private_connection.execute(
                "SELECT name FROM sqlite_master WHERE type = 'table'"
            ).fetchall()
        }
    finally:
        private_connection.close()
    assert "sandbox_orders" in private_tables
    assert "execution_receipts" in private_tables
    assert "sandbox_orders" not in observation_tables
    assert "execution_receipts" not in observation_tables
    assert "weak_ingress_events" in observation_tables
    assert "weak_order_aggregate" in observation_tables
    assert "weak_ingress_events" not in private_tables
    assert "weak_order_aggregate" not in private_tables
    assert not ingress_columns.intersection(
        {
            "owner_token",
            "operation_id",
            "invocation_id",
            "item_code",
            "quantity",
            "hidden_outcome",
        }
    )


def test_production_handles_separate_mutation_read_cleanup_and_oracle(
    tmp_path: Path,
) -> None:
    private_path, observation_path = _paths(tmp_path, "handles")
    mutation = LocalOrderMutationTarget(
        private_path,
        observation_path,
        hidden_outcome=HiddenOrderOutcome.DISCARD,
        clock=lambda: NOW,
    )
    read_target = LocalOrderReadTarget(observation_path)
    cleanup = LocalOrderCleanupTarget(private_path, observation_path)

    assert set(inspect.signature(LocalOrderReadTarget).parameters) == {
        "observation_database_path"
    }
    assert "hidden_outcome" not in inspect.signature(mutation.submit_order).parameters
    assert "latency" not in inspect.signature(mutation.submit_order).parameters
    assert not hasattr(mutation, "read_snapshot")
    assert not hasattr(mutation, "private_orders")
    assert not hasattr(mutation, "delete_owned")
    assert not hasattr(read_target, "submit_order")
    assert not hasattr(read_target, "private_orders")
    assert not hasattr(read_target, "delete_owned")
    assert not hasattr(cleanup, "submit_order")
    assert not hasattr(cleanup, "read_snapshot")
    assert not hasattr(cleanup, "private_orders")
    assert not hasattr(read_target._database, "_private_path")


def test_hidden_outcome_is_configured_out_of_band_and_owner_is_single_use(
    tmp_path: Path,
) -> None:
    private_path, observation_path = _paths(tmp_path, "single-use")
    mutation = LocalOrderMutationTarget(
        private_path,
        observation_path,
        hidden_outcome=HiddenOrderOutcome.COMMIT,
        clock=_StepClock(),
    )
    arguments = {
        "owner_token": "cleanup-owner-7",
        "item_code": ITEM_CODE,
        "quantity": QUANTITY,
    }

    mutation.submit_order(**arguments)
    before = LocalOrderReadTarget(observation_path).read_snapshot()
    with pytest.raises(OrderExecutionAlreadyExists):
        mutation.submit_order(**arguments)

    assert LocalOrderReadTarget(observation_path).read_snapshot() == before
    assert len(LocalOrderHarness(private_path, observation_path).private_orders()) == 1


def test_ingress_and_aggregate_are_independent_weak_reads(tmp_path: Path) -> None:
    _, harness, read_target, _ = _prepare(
        tmp_path,
        name="independent",
        outcome=HiddenOrderOutcome.COMMIT,
    )

    assert read_target.read_ingress() == WeakIngressObservation(
        event_kind="REQUEST_SEEN",
        observed_at=NOW + timedelta(seconds=1),
    )
    assert read_target.read_aggregate() == WeakOrderAggregateObservation(
        count_band=WeakOrderCountBand.ONE_OR_MORE,
        observed_at=NOW,
    )

    assert harness.delete_ingress_observations() == 1
    assert read_target.read_ingress() is None
    assert read_target.read_aggregate() is not None

    assert harness.delete_aggregate() is True
    assert read_target.read_snapshot() == WeakOrderObservationSnapshot(
        ingress=None,
        aggregate=None,
    )


@pytest.mark.parametrize(
    ("corrupt", "read"),
    [
        ("event-kind", "ingress"),
        ("event-digest", "ingress"),
        ("aggregate-band", "aggregate"),
    ],
)
def test_malformed_weak_observations_are_rejected(
    tmp_path: Path,
    corrupt: str,
    read: str,
) -> None:
    _, harness, read_target, _ = _prepare(
        tmp_path,
        name=f"malformed-{corrupt}",
        outcome=HiddenOrderOutcome.DISCARD,
    )
    if corrupt == "event-kind":
        harness.corrupt_latest_ingress(event_kind="ORDER_COMMITTED")
    elif corrupt == "event-digest":
        harness.corrupt_latest_ingress(event_sha256="not-a-digest")
    else:
        harness.corrupt_aggregate(count_band="EXACTLY_ONE")

    with pytest.raises(LocalOrderError, match=r"malformed|inconsistent"):
        if read == "ingress":
            read_target.read_ingress()
        else:
            read_target.read_aggregate()


@pytest.mark.parametrize(
    ("outcome", "owned_count", "order_removed"),
    [
        (HiddenOrderOutcome.COMMIT, 3, True),
        (HiddenOrderOutcome.DISCARD, 2, False),
    ],
)
def test_cleanup_is_exact_idempotent_and_preserves_seeded_duplicate(
    tmp_path: Path,
    outcome: HiddenOrderOutcome,
    owned_count: int,
    order_removed: bool,
) -> None:
    _, harness, read_target, cleanup = _prepare(
        tmp_path,
        name=f"cleanup-{outcome.value.lower()}",
        outcome=outcome,
    )

    assert cleanup.count_owned(owner_token="cleanup-owner-7") == owned_count
    first = cleanup.delete_owned(owner_token="cleanup-owner-7")
    second = cleanup.delete_owned(owner_token="cleanup-owner-7")

    assert first.order_removed is order_removed
    assert first.ingress_removed is True
    assert first.receipt_removed is True
    assert first.removed_count == owned_count
    assert second.removed_count == 0
    assert cleanup.count_owned(owner_token="cleanup-owner-7") == 0
    assert len(harness.private_orders()) == 1
    assert read_target.read_ingress() is None
    assert read_target.read_aggregate() == WeakOrderAggregateObservation(
        count_band=WeakOrderCountBand.ONE_OR_MORE,
        observed_at=NOW,
    )


def test_cleanup_allows_an_already_missing_weak_log_without_guessing(
    tmp_path: Path,
) -> None:
    _, harness, read_target, cleanup = _prepare(
        tmp_path,
        name="missing-log-cleanup",
        outcome=HiddenOrderOutcome.COMMIT,
    )
    assert harness.delete_ingress_observations() == 1

    assert cleanup.count_owned(owner_token="cleanup-owner-7") == 2
    deletion = cleanup.delete_owned(owner_token="cleanup-owner-7")

    assert deletion.order_removed is True
    assert deletion.ingress_removed is False
    assert deletion.receipt_removed is True
    assert deletion.removed_count == 2
    assert read_target.read_ingress() is None
    assert len(harness.private_orders()) == 1


def test_cleanup_rejects_and_preserves_a_replacement_private_order(
    tmp_path: Path,
) -> None:
    _, harness, read_target, cleanup = _prepare(
        tmp_path,
        name="replacement",
        outcome=HiddenOrderOutcome.COMMIT,
    )
    replacement = harness.replace_owned_order(
        owner_token="cleanup-owner-7",
        item_code="foreign-item",
        quantity=9,
    )

    with pytest.raises(OrderOwnershipError, match="does not match"):
        cleanup.delete_owned(owner_token="cleanup-owner-7")

    assert replacement in harness.private_orders()
    assert read_target.read_ingress() is not None
    with pytest.raises(OrderOwnershipError, match="does not match"):
        cleanup.count_owned(owner_token="cleanup-owner-7")


def test_cleanup_one_execution_preserves_another_execution_and_global_aggregate(
    tmp_path: Path,
) -> None:
    private_path, observation_path = _paths(tmp_path, "shared")
    harness = LocalOrderHarness(
        private_path,
        observation_path,
        clock=lambda: NOW,
    )
    harness.seed_duplicate_looking_order(item_code=ITEM_CODE, quantity=QUANTITY)
    mutation = LocalOrderMutationTarget(
        private_path,
        observation_path,
        hidden_outcome=HiddenOrderOutcome.COMMIT,
        clock=_StepClock(NOW + timedelta(seconds=1)),
    )
    for index in (1, 2):
        mutation.submit_order(
            owner_token=f"cleanup-owner-{index}",
            item_code=ITEM_CODE,
            quantity=QUANTITY,
        )
    cleanup = LocalOrderCleanupTarget(private_path, observation_path)

    removed = cleanup.delete_owned(owner_token="cleanup-owner-1")

    assert removed.removed_count == 3
    assert cleanup.count_owned(owner_token="cleanup-owner-2") == 3
    assert len(harness.private_orders()) == 2
    snapshot = LocalOrderReadTarget(observation_path).read_snapshot()
    assert snapshot.ingress == WeakIngressObservation(
        event_kind="REQUEST_SEEN",
        observed_at=NOW + timedelta(seconds=2),
    )
    assert snapshot.aggregate is not None
    assert snapshot.aggregate.count_band is WeakOrderCountBand.ONE_OR_MORE


def test_private_and_observation_database_paths_must_be_distinct(
    tmp_path: Path,
) -> None:
    database_path = tmp_path / "same.sqlite3"

    with pytest.raises(ValueError, match="separate databases"):
        LocalOrderHarness(database_path, database_path)


@pytest.mark.parametrize("outcome", ["COMMIT", None, 1])
def test_hidden_outcome_requires_the_exact_enum(
    tmp_path: Path,
    outcome: object,
) -> None:
    private_path, observation_path = _paths(tmp_path, "bad-outcome")

    with pytest.raises(TypeError, match="hidden order outcome"):
        LocalOrderMutationTarget(
            private_path,
            observation_path,
            hidden_outcome=outcome,  # type: ignore[arg-type]
        )
