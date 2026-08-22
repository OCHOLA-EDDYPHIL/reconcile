"""Append-only durable state for recovery runs and their first dispatch."""

from __future__ import annotations

import asyncio
import os
import sqlite3
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path
from typing import Literal, Protocol, runtime_checkable

from pydantic import Field, model_validator

from reconcile.contracts import (
    MAX_RECOVERY_RUN_EVENTS,
    RECOVERY_RUN_EVENT_VERSION,
    RECOVERY_RUN_SNAPSHOT_VERSION,
    ActionPermit,
    ActionPermitState,
    RecoveryChain,
    RecoveryDecision,
    RecoveryDispatchOutcome,
    RecoveryHypothesisDisposition,
    RecoveryLaunchPermit,
    RecoveryLaunchPermitState,
    RecoveryNodeProgress,
    RecoveryNodeState,
    RecoveryRunEvent,
    RecoveryRunEventPayload,
    RecoveryRunEventType,
    RecoveryRunLifecycle,
    RecoveryRunRequest,
    RecoveryRunSnapshot,
    canonical_json_bytes,
    canonical_sha256,
    decode_contract,
)
from reconcile.contracts.base import Identifier, StrictModel
from reconcile.persistence.permits import same_action_permit_authority

RECOVERY_RUN_AGGREGATE_VERSION = "reconcile/recovery-run-aggregate/v1"
RECOVERY_RUN_EVENT_SNAPSHOT_VERSION = "reconcile/recovery-event-snapshot/v1"

_BUSY_TIMEOUT_MS = 5_000


class RecoveryRunStoreError(RuntimeError):
    """Base class for sanitized recovery-run persistence failures."""


class RecoveryRunNotFound(RecoveryRunStoreError):
    def __init__(self, run_id: str) -> None:
        self.run_id = run_id
        super().__init__("recovery run was not found")


class RecoveryRunConflict(RecoveryRunStoreError):
    def __init__(self, run_id: str) -> None:
        self.run_id = run_id
        super().__init__("recovery run conflicts with durable state")


class RecoveryRunCorruptState(RecoveryRunStoreError):
    def __init__(self, run_id: str | None = None) -> None:
        self.run_id = run_id
        super().__init__("recovery run durable state is corrupt")


class RecoveryRunStoreUnavailable(RecoveryRunStoreError):
    pass


class RecoveryLaunchClaimDenied(RecoveryRunStoreError):
    def __init__(self, run_id: str) -> None:
        self.run_id = run_id
        super().__init__("recovery launch permit claim was denied")


class RecoveryRunEventSnapshot(StrictModel):
    schema_version: Literal[RECOVERY_RUN_EVENT_SNAPSHOT_VERSION]
    run_id: Identifier
    cursor: int = Field(ge=1, le=MAX_RECOVERY_RUN_EVENTS)
    terminal: bool
    events: tuple[RecoveryRunEvent, ...]

    @model_validator(mode="after")
    def validate_suffix(self) -> RecoveryRunEventSnapshot:
        if any(event.run_id != self.run_id for event in self.events):
            raise ValueError("recovery event suffix changed run identity")
        cursors = tuple(event.cursor for event in self.events)
        if cursors and (
            cursors != tuple(range(cursors[0], self.cursor + 1))
            or cursors[-1] != self.cursor
        ):
            raise ValueError("recovery event suffix is not contiguous")
        return self


class RecoveryRunAggregate(StrictModel):
    schema_version: Literal[RECOVERY_RUN_AGGREGATE_VERSION]
    snapshot: RecoveryRunSnapshot
    events: tuple[RecoveryRunEvent, ...]

    @model_validator(mode="after")
    def validate_history(self) -> RecoveryRunAggregate:
        if not self.events:
            raise ValueError("recovery event history cannot be empty")
        if tuple(event.cursor for event in self.events) != tuple(
            range(1, len(self.events) + 1)
        ):
            raise ValueError("recovery event history is not contiguous")
        if any(event.run_id != self.snapshot.request.run_id for event in self.events):
            raise ValueError("recovery event history changed run identity")
        if self.snapshot.event_cursor != len(self.events):
            raise ValueError("recovery snapshot cursor differs from event history")
        replayed = _initial_snapshot(
            self.snapshot.request,
            self.snapshot.chain,
            self.events[0].occurred_at,
        )
        if self.events[:2] != _initial_events(
            self.snapshot.request.run_id,
            self.snapshot.chain,
            self.events[0].occurred_at,
        ):
            raise ValueError("recovery history has an invalid creation prefix")
        for event in self.events[2:]:
            replayed = apply_recovery_event(replayed, event)
        if replayed != self.snapshot:
            raise ValueError("recovery event history does not reproduce its snapshot")
        return self


def _aware(value: datetime) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("recovery timestamps must be timezone-aware")
    return value.astimezone(UTC)


def is_terminal_recovery_run(lifecycle: RecoveryRunLifecycle) -> bool:
    return lifecycle in {
        RecoveryRunLifecycle.COMPLETED,
        RecoveryRunLifecycle.ESCALATED,
        RecoveryRunLifecycle.FAILED,
        RecoveryRunLifecycle.CANCELLED,
    }


def _initial_events(
    run_id: str,
    chain: RecoveryChain,
    created_at: datetime,
) -> tuple[RecoveryRunEvent, RecoveryRunEvent]:
    return (
        RecoveryRunEvent(
            schema_version=RECOVERY_RUN_EVENT_VERSION,
            run_id=run_id,
            cursor=1,
            type=RecoveryRunEventType.LIFECYCLE,
            occurred_at=created_at,
            payload=RecoveryRunEventPayload(lifecycle=RecoveryRunLifecycle.ACCEPTED),
        ),
        RecoveryRunEvent(
            schema_version=RECOVERY_RUN_EVENT_VERSION,
            run_id=run_id,
            cursor=2,
            type=RecoveryRunEventType.CHAIN,
            occurred_at=created_at,
            payload=RecoveryRunEventPayload(chain=chain),
        ),
    )


def _initial_snapshot(
    request: RecoveryRunRequest,
    chain: RecoveryChain,
    created_at: datetime,
) -> RecoveryRunSnapshot:
    created_at = _aware(created_at)
    return RecoveryRunSnapshot(
        schema_version=RECOVERY_RUN_SNAPSHOT_VERSION,
        request=request,
        request_sha256=canonical_sha256(request),
        lifecycle=RecoveryRunLifecycle.ACCEPTED,
        event_cursor=2,
        revision=1,
        chain=chain,
        chain_sha256=canonical_sha256(chain),
        nodes=tuple(
            RecoveryNodeProgress(
                node_id=node.node_id,
                state=RecoveryNodeState.WAITING,
                attempt=0,
            )
            for node in chain.nodes
        ),
        created_at=created_at,
        updated_at=created_at,
    )


def create_recovery_run_aggregate(
    request: RecoveryRunRequest,
    chain: RecoveryChain,
    *,
    created_at: datetime,
) -> RecoveryRunAggregate:
    if type(request) is not RecoveryRunRequest or type(chain) is not RecoveryChain:
        raise TypeError("exact recovery creation contracts are required")
    created_at = _aware(created_at)
    return RecoveryRunAggregate(
        schema_version=RECOVERY_RUN_AGGREGATE_VERSION,
        snapshot=_initial_snapshot(request, chain, created_at),
        events=_initial_events(request.run_id, chain, created_at),
    )


def _replace_node(
    run_id: str,
    nodes: tuple[RecoveryNodeProgress, ...],
    replacement: RecoveryNodeProgress,
) -> tuple[RecoveryNodeProgress, ...]:
    matches = tuple(node for node in nodes if node.node_id == replacement.node_id)
    if len(matches) != 1:
        raise RecoveryRunCorruptState
    current = matches[0]
    allowed = {
        RecoveryNodeState.WAITING: {
            RecoveryNodeState.DISPATCH_PENDING,
            RecoveryNodeState.RECONCILING,
        },
        RecoveryNodeState.DISPATCH_PENDING: {
            RecoveryNodeState.DISPATCH_CLAIMED,
            RecoveryNodeState.RECONCILING,
        },
        RecoveryNodeState.DISPATCH_CLAIMED: {
            RecoveryNodeState.RECONCILING,
            RecoveryNodeState.COMPLETED,
        },
        RecoveryNodeState.RECONCILING: {
            RecoveryNodeState.VERIFIED,
            RecoveryNodeState.COMPLETED,
            RecoveryNodeState.ESCALATED,
        },
        RecoveryNodeState.VERIFIED: {
            RecoveryNodeState.PERMITTED,
            RecoveryNodeState.DISPATCH_CLAIMED,
            RecoveryNodeState.RECONCILING,
            RecoveryNodeState.COMPLETED,
            RecoveryNodeState.ESCALATED,
        },
        RecoveryNodeState.PERMITTED: {
            RecoveryNodeState.DISPATCH_CLAIMED,
            RecoveryNodeState.RECONCILING,
            RecoveryNodeState.COMPLETED,
        },
    }.get(current.state, set())
    if (
        replacement.state not in allowed
        or replacement.attempt < current.attempt
        or replacement.attempt > current.attempt + 1
    ):
        raise RecoveryRunConflict(run_id)
    return tuple(
        replacement if node.node_id == replacement.node_id else node for node in nodes
    )


def _upsert_permit(
    run_id: str,
    permits: tuple[ActionPermit, ...],
    replacement: ActionPermit,
) -> tuple[ActionPermit, ...]:
    matching = tuple(
        item for item in permits if item.permit_id == replacement.permit_id
    )
    if len(matching) > 1:
        raise RecoveryRunCorruptState
    if not matching and (
        replacement.revision != 0 or replacement.state is not ActionPermitState.ISSUED
    ):
        raise RecoveryRunConflict(run_id)
    if matching:
        current = matching[0]
        valid_transition = replacement.revision == current.revision + 1 and (
            (
                current.state is ActionPermitState.ISSUED
                and replacement.state
                in {ActionPermitState.CLAIMED, ActionPermitState.EXPIRED}
            )
            or (
                current.state is ActionPermitState.CLAIMED
                and replacement.state is ActionPermitState.COMPLETED
            )
        )
        try:
            same_authority = same_action_permit_authority(current, replacement)
        except (TypeError, ValueError):
            same_authority = False
        if not same_authority or not valid_transition:
            raise RecoveryRunConflict(run_id)
        return tuple(
            replacement if item.permit_id == replacement.permit_id else item
            for item in permits
        )
    return (*permits, replacement)


def apply_recovery_event(
    snapshot: RecoveryRunSnapshot,
    event: RecoveryRunEvent,
) -> RecoveryRunSnapshot:
    """Apply one event to the public projection without external side effects."""

    if type(snapshot) is not RecoveryRunSnapshot or type(event) is not RecoveryRunEvent:
        raise TypeError("exact recovery projection inputs are required")
    terminal_authority_audit = is_terminal_recovery_run(snapshot.lifecycle) and (
        (
            event.type is RecoveryRunEventType.ACTION_PERMIT
            and event.payload.action_permit is not None
            and any(
                permit.permit_id == event.payload.action_permit.permit_id
                for permit in snapshot.action_permits
            )
        )
        or (
            event.type is RecoveryRunEventType.LAUNCH_PERMIT
            and event.payload.launch_permit is not None
            and snapshot.launch_permit is not None
            and snapshot.launch_permit.launch_permit_id
            == event.payload.launch_permit.launch_permit_id
        )
    )
    if (
        event.run_id != snapshot.request.run_id
        or event.cursor != snapshot.event_cursor + 1
        or event.occurred_at < snapshot.updated_at
        or (
            is_terminal_recovery_run(snapshot.lifecycle)
            and not terminal_authority_audit
        )
    ):
        raise RecoveryRunConflict(snapshot.request.run_id)

    updates: dict[str, object] = {
        "event_cursor": event.cursor,
        "revision": event.cursor - 1,
        "updated_at": event.occurred_at,
    }
    payload = event.payload
    if event.type is RecoveryRunEventType.LIFECYCLE:
        lifecycle = payload.lifecycle
        if lifecycle is None:
            raise RecoveryRunCorruptState(snapshot.request.run_id)
        allowed = {
            RecoveryRunLifecycle.ACCEPTED: {RecoveryRunLifecycle.RUNNING},
            RecoveryRunLifecycle.RUNNING: {
                RecoveryRunLifecycle.COMPLETED,
                RecoveryRunLifecycle.ESCALATED,
                RecoveryRunLifecycle.FAILED,
                RecoveryRunLifecycle.CANCELLED,
            },
        }.get(snapshot.lifecycle, set())
        if lifecycle not in allowed:
            raise RecoveryRunConflict(snapshot.request.run_id)
        updates["lifecycle"] = lifecycle
        updates["failure_category"] = payload.failure_category
        if lifecycle is RecoveryRunLifecycle.COMPLETED:
            updates["decision"] = snapshot.decision or RecoveryDecision.CONTINUE
        elif lifecycle is RecoveryRunLifecycle.ESCALATED:
            updates["decision"] = RecoveryDecision.ESCALATE
    elif event.type is RecoveryRunEventType.CHAIN:
        raise RecoveryRunConflict(snapshot.request.run_id)
    elif event.type is RecoveryRunEventType.NODE:
        assert payload.node is not None
        updates["nodes"] = _replace_node(
            snapshot.request.run_id,
            snapshot.nodes,
            payload.node,
        )
        updates["active_node_id"] = payload.node.node_id
    elif event.type is RecoveryRunEventType.HYPOTHESIS:
        if (
            payload.hypothesis is not None
            and payload.hypothesis_disposition
            is not RecoveryHypothesisDisposition.INVALID_BINDING
        ):
            updates["hypotheses"] = (*snapshot.hypotheses, payload.hypothesis)
    elif event.type is RecoveryRunEventType.EVIDENCE:
        assert payload.report is not None
        updates["reports"] = (*snapshot.reports, payload.report)
    elif event.type is RecoveryRunEventType.DECISION:
        assert payload.decision is not None
        updates["decision"] = payload.decision
        if payload.certificate is not None:
            updates["certificates"] = (
                *snapshot.certificates,
                payload.certificate,
            )
        else:
            assert payload.witness is not None
            updates["witnesses"] = (*snapshot.witnesses, payload.witness)
    elif event.type is RecoveryRunEventType.LAUNCH_PERMIT:
        assert payload.launch_permit is not None
        current = snapshot.launch_permit
        replacement = payload.launch_permit
        if current is not None:
            same_identity = (
                current.launch_permit_id == replacement.launch_permit_id
                and current.run_id == replacement.run_id
                and current.node_id == replacement.node_id
                and current.semantic_action_sha256 == replacement.semantic_action_sha256
                and current.action_request_sha256 == replacement.action_request_sha256
                and current.issued_at == replacement.issued_at
            )
            valid_transition = replacement.revision == current.revision + 1 and (
                (
                    current.state is RecoveryLaunchPermitState.ISSUED
                    and replacement.state is RecoveryLaunchPermitState.CLAIMED
                )
                or (
                    current.state is RecoveryLaunchPermitState.CLAIMED
                    and replacement.state is RecoveryLaunchPermitState.COMPLETED
                )
            )
            if not same_identity or not valid_transition:
                raise RecoveryRunConflict(snapshot.request.run_id)
        elif (
            replacement.state is not RecoveryLaunchPermitState.ISSUED
            or replacement.revision != 0
        ):
            raise RecoveryRunConflict(snapshot.request.run_id)
        updates["launch_permit"] = payload.launch_permit
    elif event.type is RecoveryRunEventType.ACTION_PERMIT:
        assert payload.action_permit is not None
        updates["action_permits"] = _upsert_permit(
            snapshot.request.run_id,
            snapshot.action_permits,
            payload.action_permit,
        )
    else:
        assert event.type is RecoveryRunEventType.DISPATCH_RECEIPT
        receipt = payload.dispatch_receipt
        assert receipt is not None
        target_progress = next(
            (node for node in snapshot.nodes if node.node_id == receipt.node_id),
            None,
        )
        launch = snapshot.launch_permit
        launch_match = bool(
            launch is not None
            and launch.state
            in {RecoveryLaunchPermitState.CLAIMED, RecoveryLaunchPermitState.COMPLETED}
            and launch.launch_permit_id == receipt.authority_id
            and launch.claim_id == receipt.claim_id
            and launch.node_id == receipt.node_id
            and launch.semantic_action_sha256 == receipt.semantic_action_sha256
            and launch.action_request_sha256 == receipt.action_request_sha256
            and launch.claimed_at is not None
            and receipt.recorded_at >= launch.claimed_at
        )
        action_matches = tuple(
            permit
            for permit in snapshot.action_permits
            if permit.state in {ActionPermitState.CLAIMED, ActionPermitState.COMPLETED}
            and permit.permit_id == receipt.authority_id
            and permit.claim_id == receipt.claim_id
            and permit.target_node_id == receipt.node_id
            and permit.semantic_action_sha256 == receipt.semantic_action_sha256
            and permit.claimed_at is not None
            and receipt.recorded_at >= permit.claimed_at
        )
        if (
            snapshot.lifecycle is not RecoveryRunLifecycle.RUNNING
            or target_progress is None
            or receipt.attempt != max(1, target_progress.attempt)
            or int(launch_match) + len(action_matches) != 1
            or any(
                existing.receipt_id == receipt.receipt_id
                for existing in snapshot.dispatch_receipts
            )
        ):
            raise RecoveryRunConflict(snapshot.request.run_id)
        updates["dispatch_receipts"] = (*snapshot.dispatch_receipts, receipt)
    try:
        return RecoveryRunSnapshot.model_validate(snapshot.model_copy(update=updates))
    except Exception as error:
        raise RecoveryRunCorruptState(snapshot.request.run_id) from error


def append_recovery_event(
    aggregate: RecoveryRunAggregate,
    *,
    event_type: RecoveryRunEventType,
    payload: RecoveryRunEventPayload,
    occurred_at: datetime,
) -> RecoveryRunAggregate:
    event = RecoveryRunEvent(
        schema_version=RECOVERY_RUN_EVENT_VERSION,
        run_id=aggregate.snapshot.request.run_id,
        cursor=aggregate.snapshot.event_cursor + 1,
        type=event_type,
        occurred_at=_aware(occurred_at),
        payload=payload,
    )
    snapshot = apply_recovery_event(aggregate.snapshot, event)
    return RecoveryRunAggregate(
        schema_version=RECOVERY_RUN_AGGREGATE_VERSION,
        snapshot=snapshot,
        events=(*aggregate.events, event),
    )


@runtime_checkable
class RecoveryRunStore(Protocol):
    async def create(
        self,
        request: RecoveryRunRequest,
        chain: RecoveryChain,
        *,
        created_at: datetime,
    ) -> tuple[RecoveryRunSnapshot, bool]: ...

    async def get(self, run_id: str) -> RecoveryRunSnapshot: ...

    async def events(
        self, run_id: str, *, after: int = 0
    ) -> RecoveryRunEventSnapshot: ...

    async def append(
        self,
        run_id: str,
        *,
        expected_revision: int,
        event_type: RecoveryRunEventType,
        payload: RecoveryRunEventPayload,
        occurred_at: datetime,
    ) -> RecoveryRunSnapshot: ...

    async def claim_launch(
        self,
        run_id: str,
        *,
        launch_permit_id: str,
        claim_id: str,
        action_request_sha256: str,
        claimed_at: datetime,
    ) -> RecoveryLaunchPermit: ...

    async def complete_launch(
        self,
        run_id: str,
        *,
        launch_permit_id: str,
        claim_id: str,
        outcome: RecoveryDispatchOutcome,
        completed_at: datetime,
    ) -> RecoveryLaunchPermit: ...


def claim_recovery_launch(
    aggregate: RecoveryRunAggregate,
    *,
    launch_permit_id: str,
    claim_id: str,
    action_request_sha256: str,
    claimed_at: datetime,
) -> tuple[RecoveryRunAggregate, RecoveryLaunchPermit]:
    permit = aggregate.snapshot.launch_permit
    if (
        permit is None
        or permit.state is not RecoveryLaunchPermitState.ISSUED
        or permit.launch_permit_id != launch_permit_id
        or permit.action_request_sha256 != action_request_sha256
        or claimed_at < permit.issued_at
    ):
        raise RecoveryLaunchClaimDenied(aggregate.snapshot.request.run_id)
    claimed = RecoveryLaunchPermit.model_validate(
        permit.model_copy(
            update={
                "state": RecoveryLaunchPermitState.CLAIMED,
                "revision": 1,
                "claim_id": claim_id,
                "claimed_at": _aware(claimed_at),
            }
        )
    )
    return (
        append_recovery_event(
            aggregate,
            event_type=RecoveryRunEventType.LAUNCH_PERMIT,
            payload=RecoveryRunEventPayload(launch_permit=claimed),
            occurred_at=claimed.claimed_at,
        ),
        claimed,
    )


def complete_recovery_launch(
    aggregate: RecoveryRunAggregate,
    *,
    launch_permit_id: str,
    claim_id: str,
    outcome: RecoveryDispatchOutcome,
    completed_at: datetime,
) -> tuple[RecoveryRunAggregate, RecoveryLaunchPermit]:
    permit = aggregate.snapshot.launch_permit
    if (
        permit is None
        or permit.state is not RecoveryLaunchPermitState.CLAIMED
        or permit.launch_permit_id != launch_permit_id
        or permit.claim_id != claim_id
        or permit.claimed_at is None
        or completed_at < permit.claimed_at
    ):
        raise RecoveryLaunchClaimDenied(aggregate.snapshot.request.run_id)
    completed = RecoveryLaunchPermit.model_validate(
        permit.model_copy(
            update={
                "state": RecoveryLaunchPermitState.COMPLETED,
                "revision": 2,
                "completed_at": _aware(completed_at),
                "outcome": outcome,
            }
        )
    )
    return (
        append_recovery_event(
            aggregate,
            event_type=RecoveryRunEventType.LAUNCH_PERMIT,
            payload=RecoveryRunEventPayload(launch_permit=completed),
            occurred_at=completed.completed_at,
        ),
        completed,
    )


class InMemoryRecoveryRunStore:
    """Lock-protected store used by local API and focused workflow tests."""

    def __init__(self) -> None:
        self._aggregates: dict[str, RecoveryRunAggregate] = {}
        self._lock = asyncio.Lock()

    async def create(
        self,
        request: RecoveryRunRequest,
        chain: RecoveryChain,
        *,
        created_at: datetime,
    ) -> tuple[RecoveryRunSnapshot, bool]:
        candidate = create_recovery_run_aggregate(request, chain, created_at=created_at)
        async with self._lock:
            current = self._aggregates.get(request.run_id)
            if current is not None:
                if (
                    current.snapshot.request != request
                    or current.snapshot.chain != chain
                ):
                    raise RecoveryRunConflict(request.run_id)
                return current.snapshot, False
            self._aggregates[request.run_id] = candidate
            return candidate.snapshot, True

    async def get(self, run_id: str) -> RecoveryRunSnapshot:
        async with self._lock:
            try:
                return self._aggregates[run_id].snapshot
            except KeyError:
                raise RecoveryRunNotFound(run_id) from None

    async def events(self, run_id: str, *, after: int = 0) -> RecoveryRunEventSnapshot:
        async with self._lock:
            try:
                aggregate = self._aggregates[run_id]
            except KeyError:
                raise RecoveryRunNotFound(run_id) from None
            if type(after) is not int or not 0 <= after <= len(aggregate.events):
                raise RecoveryRunConflict(run_id)
            return RecoveryRunEventSnapshot(
                schema_version=RECOVERY_RUN_EVENT_SNAPSHOT_VERSION,
                run_id=run_id,
                cursor=len(aggregate.events),
                terminal=is_terminal_recovery_run(aggregate.snapshot.lifecycle),
                events=aggregate.events[after:],
            )

    async def append(
        self,
        run_id: str,
        *,
        expected_revision: int,
        event_type: RecoveryRunEventType,
        payload: RecoveryRunEventPayload,
        occurred_at: datetime,
    ) -> RecoveryRunSnapshot:
        async with self._lock:
            try:
                current = self._aggregates[run_id]
            except KeyError:
                raise RecoveryRunNotFound(run_id) from None
            if current.snapshot.revision != expected_revision:
                raise RecoveryRunConflict(run_id)
            replacement = append_recovery_event(
                current,
                event_type=event_type,
                payload=payload,
                occurred_at=occurred_at,
            )
            self._aggregates[run_id] = replacement
            return replacement.snapshot

    async def claim_launch(
        self,
        run_id: str,
        *,
        launch_permit_id: str,
        claim_id: str,
        action_request_sha256: str,
        claimed_at: datetime,
    ) -> RecoveryLaunchPermit:
        async with self._lock:
            try:
                aggregate = self._aggregates[run_id]
            except KeyError:
                raise RecoveryRunNotFound(run_id) from None
            replacement, permit = claim_recovery_launch(
                aggregate,
                launch_permit_id=launch_permit_id,
                claim_id=claim_id,
                action_request_sha256=action_request_sha256,
                claimed_at=claimed_at,
            )
            self._aggregates[run_id] = replacement
            return permit

    async def complete_launch(
        self,
        run_id: str,
        *,
        launch_permit_id: str,
        claim_id: str,
        outcome: RecoveryDispatchOutcome,
        completed_at: datetime,
    ) -> RecoveryLaunchPermit:
        async with self._lock:
            try:
                aggregate = self._aggregates[run_id]
            except KeyError:
                raise RecoveryRunNotFound(run_id) from None
            replacement, permit = complete_recovery_launch(
                aggregate,
                launch_permit_id=launch_permit_id,
                claim_id=claim_id,
                outcome=outcome,
                completed_at=completed_at,
            )
            self._aggregates[run_id] = replacement
            return permit


class SqliteRecoveryRunStore:
    """Recovery-only SQLite aggregate; it does not reuse investigation rows."""

    def __init__(self, database_path: str | Path) -> None:
        candidate = Path(database_path)
        if not candidate.name or not candidate.parent.exists():
            raise ValueError("SQLite recovery-run parent directory must exist")
        if candidate.exists() and not candidate.is_file():
            raise ValueError("SQLite recovery-run path must name a file")
        self._path = candidate
        self._initialize()
        os.chmod(candidate, 0o600)

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(
            self._path,
            timeout=_BUSY_TIMEOUT_MS / 1_000,
            isolation_level=None,
        )
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute(f"PRAGMA busy_timeout = {_BUSY_TIMEOUT_MS}")
        return connection

    @contextmanager
    def _write(self) -> Iterator[sqlite3.Connection]:
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

    def _initialize(self) -> None:
        try:
            with self._connect() as connection:
                connection.execute("PRAGMA journal_mode = WAL")
                connection.executescript(
                    """
                    CREATE TABLE IF NOT EXISTS recovery_run_aggregates (
                        run_id TEXT PRIMARY KEY,
                        request_sha256 TEXT NOT NULL,
                        revision INTEGER NOT NULL,
                        payload BLOB NOT NULL
                    );
                    CREATE TABLE IF NOT EXISTS recovery_run_events (
                        run_id TEXT NOT NULL,
                        cursor INTEGER NOT NULL,
                        payload BLOB NOT NULL,
                        PRIMARY KEY (run_id, cursor),
                        FOREIGN KEY (run_id)
                            REFERENCES recovery_run_aggregates(run_id)
                            ON DELETE CASCADE
                    );
                    """
                )
        except sqlite3.DatabaseError as error:
            raise RecoveryRunCorruptState from error

    @staticmethod
    def _decode(payload: object, run_id: str) -> RecoveryRunAggregate:
        try:
            if isinstance(payload, bytes):
                raw = payload
            elif isinstance(payload, memoryview):
                raw = payload.tobytes()
            elif isinstance(payload, str):
                raw = payload.encode()
            else:
                raise TypeError
            return decode_contract(raw, RecoveryRunAggregate)
        except Exception as error:
            raise RecoveryRunCorruptState(run_id) from error

    def _load_locked(
        self,
        connection: sqlite3.Connection,
        run_id: str,
    ) -> RecoveryRunAggregate:
        row = connection.execute(
            "SELECT request_sha256, revision, payload FROM recovery_run_aggregates WHERE run_id = ?",
            (run_id,),
        ).fetchone()
        if row is None:
            raise RecoveryRunNotFound(run_id)
        aggregate = self._decode(row["payload"], run_id)
        if (
            row["request_sha256"] != aggregate.snapshot.request_sha256
            or row["revision"] != aggregate.snapshot.revision
        ):
            raise RecoveryRunCorruptState(run_id)
        return aggregate

    @staticmethod
    def _replace_locked(
        connection: sqlite3.Connection,
        current: RecoveryRunAggregate,
        replacement: RecoveryRunAggregate,
    ) -> None:
        event = replacement.events[-1]
        cursor = connection.execute(
            "UPDATE recovery_run_aggregates SET revision = ?, payload = ? WHERE run_id = ? AND revision = ?",
            (
                replacement.snapshot.revision,
                canonical_json_bytes(replacement),
                replacement.snapshot.request.run_id,
                current.snapshot.revision,
            ),
        )
        if cursor.rowcount != 1:
            raise RecoveryRunConflict(replacement.snapshot.request.run_id)
        connection.execute(
            "INSERT INTO recovery_run_events (run_id, cursor, payload) VALUES (?, ?, ?)",
            (
                event.run_id,
                event.cursor,
                canonical_json_bytes(event),
            ),
        )

    async def create(
        self,
        request: RecoveryRunRequest,
        chain: RecoveryChain,
        *,
        created_at: datetime,
    ) -> tuple[RecoveryRunSnapshot, bool]:
        aggregate = create_recovery_run_aggregate(request, chain, created_at=created_at)
        try:
            with self._write() as connection:
                current = connection.execute(
                    "SELECT payload FROM recovery_run_aggregates WHERE run_id = ?",
                    (request.run_id,),
                ).fetchone()
                if current is not None:
                    existing = self._decode(current["payload"], request.run_id)
                    if (
                        existing.snapshot.request != request
                        or existing.snapshot.chain != chain
                    ):
                        raise RecoveryRunConflict(request.run_id)
                    return existing.snapshot, False
                connection.execute(
                    "INSERT INTO recovery_run_aggregates (run_id, request_sha256, revision, payload) VALUES (?, ?, ?, ?)",
                    (
                        request.run_id,
                        aggregate.snapshot.request_sha256,
                        aggregate.snapshot.revision,
                        canonical_json_bytes(aggregate),
                    ),
                )
                connection.executemany(
                    "INSERT INTO recovery_run_events (run_id, cursor, payload) VALUES (?, ?, ?)",
                    tuple(
                        (event.run_id, event.cursor, canonical_json_bytes(event))
                        for event in aggregate.events
                    ),
                )
            return aggregate.snapshot, True
        except RecoveryRunStoreError:
            raise
        except sqlite3.DatabaseError as error:
            raise RecoveryRunStoreUnavailable from error

    async def get(self, run_id: str) -> RecoveryRunSnapshot:
        try:
            with self._connect() as connection:
                return self._load_locked(connection, run_id).snapshot
        except RecoveryRunStoreError:
            raise
        except sqlite3.DatabaseError as error:
            raise RecoveryRunStoreUnavailable from error

    async def events(self, run_id: str, *, after: int = 0) -> RecoveryRunEventSnapshot:
        try:
            with self._connect() as connection:
                aggregate = self._load_locked(connection, run_id)
            if type(after) is not int or not 0 <= after <= len(aggregate.events):
                raise RecoveryRunConflict(run_id)
            return RecoveryRunEventSnapshot(
                schema_version=RECOVERY_RUN_EVENT_SNAPSHOT_VERSION,
                run_id=run_id,
                cursor=len(aggregate.events),
                terminal=is_terminal_recovery_run(aggregate.snapshot.lifecycle),
                events=aggregate.events[after:],
            )
        except RecoveryRunStoreError:
            raise
        except sqlite3.DatabaseError as error:
            raise RecoveryRunStoreUnavailable from error

    async def append(
        self,
        run_id: str,
        *,
        expected_revision: int,
        event_type: RecoveryRunEventType,
        payload: RecoveryRunEventPayload,
        occurred_at: datetime,
    ) -> RecoveryRunSnapshot:
        try:
            with self._write() as connection:
                current = self._load_locked(connection, run_id)
                if current.snapshot.revision != expected_revision:
                    raise RecoveryRunConflict(run_id)
                replacement = append_recovery_event(
                    current,
                    event_type=event_type,
                    payload=payload,
                    occurred_at=occurred_at,
                )
                self._replace_locked(connection, current, replacement)
            return replacement.snapshot
        except RecoveryRunStoreError:
            raise
        except sqlite3.DatabaseError as error:
            raise RecoveryRunStoreUnavailable from error

    async def claim_launch(
        self,
        run_id: str,
        *,
        launch_permit_id: str,
        claim_id: str,
        action_request_sha256: str,
        claimed_at: datetime,
    ) -> RecoveryLaunchPermit:
        try:
            with self._write() as connection:
                current = self._load_locked(connection, run_id)
                replacement, permit = claim_recovery_launch(
                    current,
                    launch_permit_id=launch_permit_id,
                    claim_id=claim_id,
                    action_request_sha256=action_request_sha256,
                    claimed_at=claimed_at,
                )
                self._replace_locked(connection, current, replacement)
            return permit
        except RecoveryRunStoreError:
            raise
        except sqlite3.DatabaseError as error:
            raise RecoveryRunStoreUnavailable from error

    async def complete_launch(
        self,
        run_id: str,
        *,
        launch_permit_id: str,
        claim_id: str,
        outcome: RecoveryDispatchOutcome,
        completed_at: datetime,
    ) -> RecoveryLaunchPermit:
        try:
            with self._write() as connection:
                current = self._load_locked(connection, run_id)
                replacement, permit = complete_recovery_launch(
                    current,
                    launch_permit_id=launch_permit_id,
                    claim_id=claim_id,
                    outcome=outcome,
                    completed_at=completed_at,
                )
                self._replace_locked(connection, current, replacement)
            return permit
        except RecoveryRunStoreError:
            raise
        except sqlite3.DatabaseError as error:
            raise RecoveryRunStoreUnavailable from error


__all__ = [
    "RECOVERY_RUN_AGGREGATE_VERSION",
    "RECOVERY_RUN_EVENT_SNAPSHOT_VERSION",
    "InMemoryRecoveryRunStore",
    "RecoveryLaunchClaimDenied",
    "RecoveryRunAggregate",
    "RecoveryRunConflict",
    "RecoveryRunCorruptState",
    "RecoveryRunEventSnapshot",
    "RecoveryRunNotFound",
    "RecoveryRunStore",
    "RecoveryRunStoreError",
    "RecoveryRunStoreUnavailable",
    "SqliteRecoveryRunStore",
    "append_recovery_event",
    "apply_recovery_event",
    "claim_recovery_launch",
    "complete_recovery_launch",
    "create_recovery_run_aggregate",
    "is_terminal_recovery_run",
]
