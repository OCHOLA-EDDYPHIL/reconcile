"""Bounded Firestore persistence for recovery checkpoints and immutable events."""

from __future__ import annotations

import asyncio
import hashlib
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime
from typing import Literal, Protocol

from pydantic import Field, model_validator

from reconcile.contracts import (
    MAX_RECOVERY_RUN_EVENTS,
    ActionPermitState,
    RecoveryChain,
    RecoveryDispatchOutcome,
    RecoveryDispatchReceipt,
    RecoveryLaunchPermit,
    RecoveryLaunchPermitState,
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
from reconcile.contracts.base import (
    Sha256Digest,
    StrictModel,
    canonical_json_value_bytes,
)
from reconcile.hosted.firestore_cas import (
    FIRESTORE_CAS_PAYLOAD_BYTE_CEILING,
    FirestoreCasCollection,
    FirestoreCasConflict,
    FirestoreCasDocument,
    FirestoreCasOutcomeUnknown,
    FirestoreCasSnapshot,
    build_firestore_cas_document,
    new_firestore_cas_mutation_id,
)
from reconcile.persistence.recovery_runs import (
    RECOVERY_RUN_AGGREGATE_VERSION,
    RECOVERY_RUN_EVENT_SNAPSHOT_VERSION,
    RecoveryLaunchClaimDenied,
    RecoveryRunAggregate,
    RecoveryRunConflict,
    RecoveryRunCorruptState,
    RecoveryRunEventSnapshot,
    RecoveryRunEventTooLarge,
    RecoveryRunNotFound,
    RecoveryRunStoreUnavailable,
    _append_decoded_recovery_event,
    apply_recovery_event,
    claim_recovery_launch,
    complete_recovery_launch,
    create_recovery_run_aggregate,
    is_terminal_recovery_run,
)

FIRESTORE_RECOVERY_RUN_STATE_VERSION = "reconcile/firestore-recovery-state/v2"
FIRESTORE_RECOVERY_EVENT_RECORD_VERSION = "reconcile/firestore-recovery-event-record/v2"
FIRESTORE_RECOVERY_EVENT_BYTE_CEILING = FIRESTORE_CAS_PAYLOAD_BYTE_CEILING - 4_096
FIRESTORE_RECOVERY_EVENT_LIMIT = MAX_RECOVERY_RUN_EVENTS
FIRESTORE_RECOVERY_EVENT_RETENTION = "run-lifetime-no-truncation"

_FIRESTORE_RECOVERY_RUN_STATE_V1_VERSION = "reconcile/firestore-recovery-state/v1"
_FIRESTORE_RECOVERY_EVENT_RECORD_V1_VERSION = (
    "reconcile/firestore-recovery-event-record/v1"
)
_LEGACY_GENESIS_JOURNAL_SHA256 = "0" * 64
_JOURNAL_V2_GENESIS_DOMAIN = b"reconcile/firestore-recovery-journal/genesis/v2\0"
_JOURNAL_V2_LINK_DOMAIN = b"reconcile/firestore-recovery-journal/link/v2\0"
_MAX_CAS_ATTEMPTS = 64
_MAX_EVENT_READ_CONCURRENCY = 32
_MAX_MIGRATION_BATCH = 500


def _journal_genesis_sha256(request: RecoveryRunRequest) -> str:
    return hashlib.sha256(
        _JOURNAL_V2_GENESIS_DOMAIN + canonical_json_bytes(request)
    ).hexdigest()


def _next_journal_sha256(previous: str, event: RecoveryRunEvent) -> str:
    return hashlib.sha256(
        _JOURNAL_V2_LINK_DOMAIN + bytes.fromhex(previous) + canonical_json_bytes(event)
    ).hexdigest()


def _legacy_next_journal_sha256(previous: str, event: RecoveryRunEvent) -> str:
    return hashlib.sha256(
        bytes.fromhex(previous) + canonical_json_bytes(event)
    ).hexdigest()


class _FirestoreRecoveryRunState(StrictModel):
    schema_version: Literal[FIRESTORE_RECOVERY_RUN_STATE_VERSION]
    request: RecoveryRunRequest
    request_sha256: Sha256Digest
    event_record_version: Literal[FIRESTORE_RECOVERY_EVENT_RECORD_VERSION]
    event_cursor: int = Field(ge=2, le=FIRESTORE_RECOVERY_EVENT_LIMIT)
    revision: int = Field(ge=1, le=FIRESTORE_RECOVERY_EVENT_LIMIT - 1)
    journal_sha256: Sha256Digest

    @model_validator(mode="after")
    def validate_cursor(self) -> _FirestoreRecoveryRunState:
        if (
            self.revision != self.event_cursor - 1
            or self.request_sha256 != canonical_sha256(self.request)
        ):
            raise ValueError("recovery state checkpoint binding does not match")
        return self


class _FirestoreRecoveryRunStateV1(StrictModel):
    schema_version: Literal[_FIRESTORE_RECOVERY_RUN_STATE_V1_VERSION]
    snapshot: RecoveryRunSnapshot
    journal_sha256: Sha256Digest


class _FirestoreRecoveryEventRecordV1(StrictModel):
    schema_version: Literal[_FIRESTORE_RECOVERY_EVENT_RECORD_V1_VERSION]
    event: RecoveryRunEvent
    previous_journal_sha256: Sha256Digest
    journal_sha256: Sha256Digest

    @model_validator(mode="after")
    def validate_journal_link(self) -> _FirestoreRecoveryEventRecordV1:
        if self.journal_sha256 != _legacy_next_journal_sha256(
            self.previous_journal_sha256,
            self.event,
        ):
            raise ValueError("recovery event journal link does not match")
        return self


class _FirestoreRecoveryEventRecord(StrictModel):
    schema_version: Literal[FIRESTORE_RECOVERY_EVENT_RECORD_VERSION]
    event: RecoveryRunEvent
    previous_journal_sha256: Sha256Digest
    journal_sha256: Sha256Digest

    @model_validator(mode="after")
    def validate_journal_link(self) -> _FirestoreRecoveryEventRecord:
        if self.journal_sha256 != _next_journal_sha256(
            self.previous_journal_sha256,
            self.event,
        ):
            raise ValueError("recovery event journal link does not match")
        return self


@dataclass(frozen=True, slots=True)
class _DecodedRecoveryDocument:
    state: _FirestoreRecoveryRunState | None = None
    previous_state: _FirestoreRecoveryRunStateV1 | None = None
    legacy_aggregate: RecoveryRunAggregate | None = None


@dataclass(frozen=True, slots=True)
class _LoadedRecoveryRun:
    snapshot: FirestoreCasSnapshot
    aggregate: RecoveryRunAggregate
    source: Literal["compact", "split-v1", "legacy"]


class _FirestoreCasStore(Protocol):
    async def read(
        self,
        collection: FirestoreCasCollection,
        logical_id: str,
    ) -> FirestoreCasSnapshot | None: ...

    async def create_many(
        self,
        documents: tuple[FirestoreCasDocument, ...],
    ) -> tuple[FirestoreCasSnapshot, ...]: ...

    async def update_and_create_many(
        self,
        current: FirestoreCasSnapshot,
        replacement: FirestoreCasDocument,
        created: tuple[FirestoreCasDocument, ...],
    ) -> tuple[FirestoreCasSnapshot, ...]: ...

    async def rewrite_recovery_run(
        self,
        current: FirestoreCasSnapshot,
        replacement: FirestoreCasDocument,
    ) -> FirestoreCasSnapshot: ...


def _legacy_event_logical_id(run_id: str, cursor: int) -> str:
    run_digest = hashlib.sha256(run_id.encode()).hexdigest()
    return f"recovery-event-{run_digest}-{cursor:03d}"


def _event_logical_id(run_id: str, cursor: int) -> str:
    run_digest = hashlib.sha256(run_id.encode()).hexdigest()
    return f"recovery-event-v2-{run_digest}-{cursor:03d}"


def _journal_records(
    request: RecoveryRunRequest,
    events: tuple[RecoveryRunEvent, ...],
) -> tuple[_FirestoreRecoveryEventRecord, ...]:
    previous = _journal_genesis_sha256(request)
    records: list[_FirestoreRecoveryEventRecord] = []
    for event in events:
        current = _next_journal_sha256(previous, event)
        records.append(
            _FirestoreRecoveryEventRecord(
                schema_version=FIRESTORE_RECOVERY_EVENT_RECORD_VERSION,
                event=event,
                previous_journal_sha256=previous,
                journal_sha256=current,
            )
        )
        previous = current
    return tuple(records)


def _legacy_journal_records(
    events: tuple[RecoveryRunEvent, ...],
) -> tuple[_FirestoreRecoveryEventRecordV1, ...]:
    previous = _LEGACY_GENESIS_JOURNAL_SHA256
    records: list[_FirestoreRecoveryEventRecordV1] = []
    for event in events:
        current = _legacy_next_journal_sha256(previous, event)
        records.append(
            _FirestoreRecoveryEventRecordV1(
                schema_version=_FIRESTORE_RECOVERY_EVENT_RECORD_V1_VERSION,
                event=event,
                previous_journal_sha256=previous,
                journal_sha256=current,
            )
        )
        previous = current
    return tuple(records)


def _state(aggregate: RecoveryRunAggregate) -> _FirestoreRecoveryRunState:
    request = aggregate.snapshot.request
    records = _journal_records(request, aggregate.events)
    return _FirestoreRecoveryRunState(
        schema_version=FIRESTORE_RECOVERY_RUN_STATE_VERSION,
        request=request,
        request_sha256=canonical_sha256(request),
        event_record_version=FIRESTORE_RECOVERY_EVENT_RECORD_VERSION,
        event_cursor=aggregate.snapshot.event_cursor,
        revision=aggregate.snapshot.revision,
        journal_sha256=records[-1].journal_sha256,
    )


def _state_document(aggregate: RecoveryRunAggregate) -> FirestoreCasDocument:
    state = _state(aggregate)
    return build_firestore_cas_document(
        collection=FirestoreCasCollection.RECOVERY_RUN,
        logical_id=aggregate.snapshot.request.run_id,
        revision=aggregate.snapshot.revision,
        mutation_id=new_firestore_cas_mutation_id(),
        canonical_payload=canonical_json_value_bytes(state.model_dump(mode="json")),
    )


def _event_document(record: _FirestoreRecoveryEventRecord) -> FirestoreCasDocument:
    if len(canonical_json_bytes(record.event)) > FIRESTORE_RECOVERY_EVENT_BYTE_CEILING:
        raise RecoveryRunEventTooLarge
    payload = canonical_json_value_bytes(record.model_dump(mode="json"))
    if len(payload) > FIRESTORE_CAS_PAYLOAD_BYTE_CEILING:
        raise RecoveryRunEventTooLarge
    return build_firestore_cas_document(
        collection=FirestoreCasCollection.RECOVERY_RUN_EVENT,
        logical_id=_event_logical_id(record.event.run_id, record.event.cursor),
        revision=record.event.cursor,
        mutation_id=f"mutation-{hashlib.sha256(payload).hexdigest()}",
        canonical_payload=payload,
    )


def _legacy_event_document(
    record: _FirestoreRecoveryEventRecordV1,
) -> FirestoreCasDocument:
    payload = canonical_json_value_bytes(record.model_dump(mode="json"))
    return build_firestore_cas_document(
        collection=FirestoreCasCollection.RECOVERY_RUN_EVENT,
        logical_id=_legacy_event_logical_id(
            record.event.run_id,
            record.event.cursor,
        ),
        revision=record.event.cursor,
        mutation_id=f"mutation-{hashlib.sha256(payload).hexdigest()}",
        canonical_payload=payload,
    )


def _decode(snapshot: FirestoreCasSnapshot) -> _DecodedRecoveryDocument:
    try:
        if (
            type(snapshot) is not FirestoreCasSnapshot
            or snapshot.collection is not FirestoreCasCollection.RECOVERY_RUN
            or snapshot.document.kind is not FirestoreCasCollection.RECOVERY_RUN
        ):
            raise ValueError
        try:
            state = decode_contract(
                snapshot.document.payload_bytes,
                _FirestoreRecoveryRunState,
            )
        except Exception:
            try:
                previous_state = decode_contract(
                    snapshot.document.payload_bytes,
                    _FirestoreRecoveryRunStateV1,
                )
            except Exception:
                aggregate = decode_contract(
                    snapshot.document.payload_bytes,
                    RecoveryRunAggregate,
                )
                if (
                    snapshot.document.logical_id != aggregate.snapshot.request.run_id
                    or snapshot.document.revision != aggregate.snapshot.revision
                ):
                    raise ValueError from None
                return _DecodedRecoveryDocument(legacy_aggregate=aggregate)
            if (
                snapshot.document.logical_id != previous_state.snapshot.request.run_id
                or snapshot.document.revision != previous_state.snapshot.revision
            ):
                raise ValueError from None
            return _DecodedRecoveryDocument(previous_state=previous_state)
        if (
            snapshot.document.logical_id != state.request.run_id
            or snapshot.document.revision != state.revision
        ):
            raise ValueError
        return _DecodedRecoveryDocument(state=state)
    except Exception as error:
        run_id = getattr(snapshot.document, "logical_id", None)
        raise RecoveryRunCorruptState(run_id) from error


def _decode_event(
    snapshot: FirestoreCasSnapshot,
    *,
    run_id: str,
    cursor: int,
    legacy: bool,
) -> _FirestoreRecoveryEventRecord | _FirestoreRecoveryEventRecordV1:
    try:
        logical_id = (
            _legacy_event_logical_id(run_id, cursor)
            if legacy
            else _event_logical_id(run_id, cursor)
        )
        if (
            type(snapshot) is not FirestoreCasSnapshot
            or snapshot.collection is not FirestoreCasCollection.RECOVERY_RUN_EVENT
            or snapshot.document.kind is not FirestoreCasCollection.RECOVERY_RUN_EVENT
            or snapshot.document.logical_id != logical_id
            or snapshot.document.revision != cursor
        ):
            raise ValueError
        record = decode_contract(
            snapshot.document.payload_bytes,
            (
                _FirestoreRecoveryEventRecordV1
                if legacy
                else _FirestoreRecoveryEventRecord
            ),
        )
        if record.event.run_id != run_id or record.event.cursor != cursor:
            raise ValueError
        return record
    except Exception as error:
        raise RecoveryRunCorruptState(run_id) from error


def _same_event_document(
    current: FirestoreCasDocument,
    expected: FirestoreCasDocument,
) -> bool:
    """Compare immutable event content without coupling migration attempt identity."""

    return (
        current.schema_version == expected.schema_version
        and current.kind is expected.kind
        and current.logical_id == expected.logical_id
        and current.revision == expected.revision
        and current.canonical_payload == expected.canonical_payload
        and current.payload_sha256 == expected.payload_sha256
    )


def _matching_dispatch_receipts(
    snapshot: RecoveryRunSnapshot,
    *,
    authority_id: str,
    claim_id: str | None,
) -> tuple[RecoveryDispatchReceipt, ...]:
    if claim_id is None:
        return ()
    return tuple(
        receipt
        for receipt in snapshot.dispatch_receipts
        if receipt.authority_id == authority_id and receipt.claim_id == claim_id
    )


def _required_authority_event_capacity(snapshot: RecoveryRunSnapshot) -> int:
    """Return journal slots that active authority transitions must retain."""

    progress = {node.node_id: node.state for node in snapshot.nodes}
    required = 0
    launch = snapshot.launch_permit
    if launch is not None:
        receipts = _matching_dispatch_receipts(
            snapshot,
            authority_id=launch.launch_permit_id,
            claim_id=launch.claim_id,
        )
        provider_receipt = any(receipt.provider_contact for receipt in receipts)
        observer_receipt = any(not receipt.provider_contact for receipt in receipts)
        if launch.state is RecoveryLaunchPermitState.ISSUED:
            if progress.get(launch.node_id) is RecoveryNodeState.WAITING:
                required += 1
            required += 3
        elif launch.state is RecoveryLaunchPermitState.CLAIMED:
            required += int(not provider_receipt) + 1
        launch_progress = progress.get(launch.node_id)
        if snapshot.lifecycle is RecoveryRunLifecycle.RUNNING and launch_progress in {
            RecoveryNodeState.WAITING,
            RecoveryNodeState.DISPATCH_PENDING,
            RecoveryNodeState.DISPATCH_CLAIMED,
        }:
            required += 1
            required += int(not observer_receipt)

    for permit in snapshot.action_permits:
        receipts = _matching_dispatch_receipts(
            snapshot,
            authority_id=permit.permit_id,
            claim_id=permit.claim_id,
        )
        if permit.state is ActionPermitState.ISSUED:
            if progress.get(permit.source_node_id) is RecoveryNodeState.VERIFIED:
                required += 1
            required += 3
        elif permit.state is ActionPermitState.CLAIMED:
            required += int(not receipts) + 1
        if snapshot.lifecycle is RecoveryRunLifecycle.RUNNING and permit.state in {
            ActionPermitState.ISSUED,
            ActionPermitState.CLAIMED,
            ActionPermitState.COMPLETED,
        }:
            source_state = progress.get(permit.source_node_id)
            target_state = progress.get(permit.target_node_id)
            unsettled_source = source_state in {
                RecoveryNodeState.VERIFIED,
                RecoveryNodeState.PERMITTED,
                RecoveryNodeState.DISPATCH_CLAIMED,
            }
            if permit.source_node_id == permit.target_node_id:
                required += int(unsettled_source)
            else:
                required += int(unsettled_source)
                required += int(target_state is RecoveryNodeState.WAITING)
    return required


def _assert_authority_event_capacity(snapshot: RecoveryRunSnapshot) -> None:
    if (
        snapshot.event_cursor + _required_authority_event_capacity(snapshot)
        > FIRESTORE_RECOVERY_EVENT_LIMIT
    ):
        raise RecoveryRunConflict(snapshot.request.run_id)


class FirestoreRecoveryRunStore:
    """Persist compact CAS checkpoints and append-only event records."""

    def __init__(self, cas_store: _FirestoreCasStore) -> None:
        if any(
            not callable(getattr(cas_store, name, None))
            for name in (
                "create_many",
                "read",
                "rewrite_recovery_run",
                "update_and_create_many",
            )
        ):
            raise TypeError("Firestore recovery store requires atomic CAS operations")
        self._cas = cas_store

    async def _read_event_snapshots(
        self,
        run_id: str,
        cursors: tuple[int, ...],
        *,
        legacy: bool,
    ) -> tuple[FirestoreCasSnapshot | None, ...]:
        snapshots: list[FirestoreCasSnapshot | None] = []
        for start in range(0, len(cursors), _MAX_EVENT_READ_CONCURRENCY):
            selected = cursors[start : start + _MAX_EVENT_READ_CONCURRENCY]
            try:
                snapshots.extend(
                    await asyncio.gather(
                        *(
                            self._cas.read(
                                FirestoreCasCollection.RECOVERY_RUN_EVENT,
                                (
                                    _legacy_event_logical_id(run_id, event_cursor)
                                    if legacy
                                    else _event_logical_id(run_id, event_cursor)
                                ),
                            )
                            for event_cursor in selected
                        )
                    )
                )
            except asyncio.CancelledError:
                raise
            except Exception:
                raise RecoveryRunStoreUnavailable from None
        return tuple(snapshots)

    async def _read_event_records(
        self,
        run_id: str,
        cursor: int,
        *,
        legacy: bool,
    ) -> tuple[
        _FirestoreRecoveryEventRecord | _FirestoreRecoveryEventRecordV1,
        ...,
    ]:
        cursors = tuple(range(1, cursor + 1))
        snapshots = await self._read_event_snapshots(run_id, cursors, legacy=legacy)
        if any(snapshot is None for snapshot in snapshots):
            raise RecoveryRunCorruptState(run_id)
        return tuple(
            _decode_event(
                snapshot,
                run_id=run_id,
                cursor=event_cursor,
                legacy=legacy,
            )
            for snapshot, event_cursor in zip(snapshots, cursors, strict=True)
            if snapshot is not None
        )

    async def _reconstruct(
        self,
        run_id: str,
        state: _FirestoreRecoveryRunState | _FirestoreRecoveryRunStateV1,
    ) -> RecoveryRunAggregate:
        if type(state) is _FirestoreRecoveryRunState:
            request = state.request
            event_cursor = state.event_cursor
            expected_snapshot = None
            legacy = False
            genesis = _journal_genesis_sha256(request)
        elif type(state) is _FirestoreRecoveryRunStateV1:
            request = state.snapshot.request
            event_cursor = state.snapshot.event_cursor
            expected_snapshot = state.snapshot
            legacy = True
            genesis = _LEGACY_GENESIS_JOURNAL_SHA256
        else:  # pragma: no cover - closed internal union
            raise RecoveryRunCorruptState(run_id)
        records = await self._read_event_records(
            run_id,
            event_cursor,
            legacy=legacy,
        )
        previous = genesis
        for record in records:
            if record.previous_journal_sha256 != previous:
                raise RecoveryRunCorruptState(run_id)
            previous = record.journal_sha256
        if previous != state.journal_sha256:
            raise RecoveryRunCorruptState(run_id)
        try:
            events = tuple(record.event for record in records)
            chain = events[1].payload.chain
            if chain is None:
                raise ValueError
            initial = create_recovery_run_aggregate(
                request,
                chain,
                created_at=events[0].occurred_at,
            )
            if events[:2] != initial.events:
                raise ValueError
            projected = initial.snapshot
            for event in events[2:]:
                projected = apply_recovery_event(projected, event)
            aggregate = RecoveryRunAggregate(
                schema_version=RECOVERY_RUN_AGGREGATE_VERSION,
                snapshot=projected,
                events=events,
            )
            if (
                aggregate.snapshot.event_cursor != event_cursor
                or aggregate.snapshot.revision != event_cursor - 1
                or (
                    type(state) is _FirestoreRecoveryRunState
                    and aggregate.snapshot.revision != state.revision
                )
                or (
                    expected_snapshot is not None
                    and aggregate.snapshot != expected_snapshot
                )
            ):
                raise ValueError
        except Exception as error:
            raise RecoveryRunCorruptState(run_id) from error
        return aggregate

    async def _read(self, run_id: str) -> _LoadedRecoveryRun:
        try:
            snapshot = await self._cas.read(FirestoreCasCollection.RECOVERY_RUN, run_id)
        except asyncio.CancelledError:
            raise
        except FirestoreCasOutcomeUnknown:
            raise RecoveryRunStoreUnavailable from None
        except Exception:
            raise RecoveryRunStoreUnavailable from None
        if snapshot is None:
            raise RecoveryRunNotFound(run_id)
        if snapshot.document.logical_id != run_id:
            raise RecoveryRunCorruptState(run_id)
        decoded = _decode(snapshot)
        if decoded.legacy_aggregate is not None:
            aggregate = decoded.legacy_aggregate
            source: Literal["compact", "split-v1", "legacy"] = "legacy"
        elif decoded.previous_state is not None:
            aggregate = await self._reconstruct(run_id, decoded.previous_state)
            source = "split-v1"
        elif decoded.state is not None:
            aggregate = await self._reconstruct(run_id, decoded.state)
            source = "compact"
        else:
            raise RecoveryRunCorruptState(run_id)
        _assert_authority_event_capacity(aggregate.snapshot)
        return _LoadedRecoveryRun(
            snapshot=snapshot,
            aggregate=aggregate,
            source=source,
        )

    async def create(
        self,
        request: RecoveryRunRequest,
        chain: RecoveryChain,
        *,
        created_at: datetime,
    ) -> tuple[RecoveryRunSnapshot, bool]:
        aggregate = create_recovery_run_aggregate(request, chain, created_at=created_at)
        records = _journal_records(request, aggregate.events)
        documents = (
            _state_document(aggregate),
            *(_event_document(record) for record in records),
        )
        try:
            written = await self._cas.create_many(documents)
        except asyncio.CancelledError:
            raise
        except FirestoreCasConflict:
            try:
                existing = (await self._read(request.run_id)).aggregate
            except RecoveryRunNotFound:
                raise RecoveryRunStoreUnavailable from None
            if existing.snapshot.request != request or existing.snapshot.chain != chain:
                raise RecoveryRunConflict(request.run_id) from None
            return existing.snapshot, False
        except Exception:
            raise RecoveryRunStoreUnavailable from None
        if len(written) != len(documents) or any(
            snapshot.document != document
            for snapshot, document in zip(written, documents, strict=True)
        ):
            raise RecoveryRunCorruptState(request.run_id)
        return aggregate.snapshot, True

    async def get(self, run_id: str) -> RecoveryRunSnapshot:
        return (await self._read(run_id)).aggregate.snapshot

    async def events(self, run_id: str, *, after: int = 0) -> RecoveryRunEventSnapshot:
        aggregate = (await self._read(run_id)).aggregate
        if type(after) is not int or not 0 <= after <= len(aggregate.events):
            raise RecoveryRunConflict(run_id)
        return RecoveryRunEventSnapshot(
            schema_version=RECOVERY_RUN_EVENT_SNAPSHOT_VERSION,
            run_id=run_id,
            cursor=len(aggregate.events),
            terminal=is_terminal_recovery_run(aggregate.snapshot.lifecycle),
            events=aggregate.events[after:],
        )

    async def _ensure_migration_events(
        self,
        run_id: str,
        records: tuple[_FirestoreRecoveryEventRecord, ...],
    ) -> None:
        documents = tuple(_event_document(record) for record in records)
        for start in range(0, len(documents), _MAX_MIGRATION_BATCH):
            selected = documents[start : start + _MAX_MIGRATION_BATCH]
            cursors = tuple(document.revision for document in selected)
            for _attempt in range(_MAX_CAS_ATTEMPTS):
                current = await self._read_event_snapshots(
                    run_id,
                    cursors,
                    legacy=False,
                )
                for snapshot, expected in zip(current, selected, strict=True):
                    if snapshot is not None and not _same_event_document(
                        snapshot.document,
                        expected,
                    ):
                        raise RecoveryRunCorruptState(run_id)
                missing = tuple(
                    expected
                    for snapshot, expected in zip(current, selected, strict=True)
                    if snapshot is None
                )
                if not missing:
                    break
                try:
                    written = await self._cas.create_many(missing)
                except asyncio.CancelledError:
                    raise
                except FirestoreCasConflict:
                    continue
                except Exception:
                    raise RecoveryRunStoreUnavailable from None
                if len(written) != len(missing) or any(
                    snapshot.document != document
                    for snapshot, document in zip(written, missing, strict=True)
                ):
                    raise RecoveryRunCorruptState(run_id)
                break
            else:
                raise RecoveryRunStoreUnavailable

    async def _migrate(self, loaded: _LoadedRecoveryRun) -> bool:
        run_id = loaded.aggregate.snapshot.request.run_id
        records = _journal_records(
            loaded.aggregate.snapshot.request,
            loaded.aggregate.events,
        )
        await self._ensure_migration_events(run_id, records)
        document = _state_document(loaded.aggregate)
        try:
            written = await self._cas.rewrite_recovery_run(loaded.snapshot, document)
        except asyncio.CancelledError:
            raise
        except FirestoreCasConflict:
            return False
        except Exception:
            raise RecoveryRunStoreUnavailable from None
        if written.document != document:
            raise RecoveryRunCorruptState(run_id)
        return True

    async def _mutate(
        self,
        run_id: str,
        mutation: Callable[[RecoveryRunAggregate], RecoveryRunAggregate],
    ) -> RecoveryRunAggregate:
        for _attempt in range(_MAX_CAS_ATTEMPTS):
            loaded = await self._read(run_id)
            aggregate = loaded.aggregate
            if loaded.source != "compact":
                await self._migrate(loaded)
                continue
            if aggregate.snapshot.event_cursor >= FIRESTORE_RECOVERY_EVENT_LIMIT:
                raise RecoveryRunConflict(run_id)
            replacement = mutation(aggregate)
            if (
                replacement.events[:-1] != aggregate.events
                or replacement.snapshot.revision != aggregate.snapshot.revision + 1
                or replacement.snapshot.event_cursor
                != aggregate.snapshot.event_cursor + 1
            ):
                raise RecoveryRunCorruptState(run_id)
            _assert_authority_event_capacity(replacement.snapshot)
            records = _journal_records(
                replacement.snapshot.request,
                replacement.events,
            )
            created = (_event_document(records[-1]),)
            document = _state_document(replacement)
            try:
                written = await self._cas.update_and_create_many(
                    loaded.snapshot,
                    document,
                    created,
                )
            except asyncio.CancelledError:
                raise
            except FirestoreCasConflict:
                continue
            except Exception:
                raise RecoveryRunStoreUnavailable from None
            if len(written) != len(created) + 1 or written[0].document != document:
                raise RecoveryRunCorruptState(run_id)
            return replacement
        raise RecoveryRunStoreUnavailable

    async def append(
        self,
        run_id: str,
        *,
        expected_revision: int,
        event_type: RecoveryRunEventType,
        payload: RecoveryRunEventPayload,
        occurred_at: datetime,
    ) -> RecoveryRunSnapshot:
        def mutate(aggregate: RecoveryRunAggregate) -> RecoveryRunAggregate:
            if aggregate.snapshot.revision != expected_revision:
                raise RecoveryRunConflict(run_id)
            return _append_decoded_recovery_event(
                aggregate,
                event_type=event_type,
                payload=payload,
                occurred_at=occurred_at,
            )

        return (await self._mutate(run_id, mutate)).snapshot

    async def claim_launch(
        self,
        run_id: str,
        *,
        launch_permit_id: str,
        claim_id: str,
        action_request_sha256: str,
        claimed_at: datetime,
    ) -> RecoveryLaunchPermit:
        claimed: RecoveryLaunchPermit | None = None

        def mutate(aggregate: RecoveryRunAggregate) -> RecoveryRunAggregate:
            nonlocal claimed
            replacement, claimed = claim_recovery_launch(
                aggregate,
                launch_permit_id=launch_permit_id,
                claim_id=claim_id,
                action_request_sha256=action_request_sha256,
                claimed_at=claimed_at,
            )
            return replacement

        await self._mutate(run_id, mutate)
        if claimed is None:
            raise RecoveryLaunchClaimDenied(run_id)
        return claimed

    async def complete_launch(
        self,
        run_id: str,
        *,
        launch_permit_id: str,
        claim_id: str,
        outcome: RecoveryDispatchOutcome,
        completed_at: datetime,
    ) -> RecoveryLaunchPermit:
        completed: RecoveryLaunchPermit | None = None

        def mutate(aggregate: RecoveryRunAggregate) -> RecoveryRunAggregate:
            nonlocal completed
            replacement, completed = complete_recovery_launch(
                aggregate,
                launch_permit_id=launch_permit_id,
                claim_id=claim_id,
                outcome=outcome,
                completed_at=completed_at,
            )
            return replacement

        await self._mutate(run_id, mutate)
        if completed is None:
            raise RecoveryLaunchClaimDenied(run_id)
        return completed


__all__ = [
    "FIRESTORE_RECOVERY_EVENT_BYTE_CEILING",
    "FIRESTORE_RECOVERY_EVENT_LIMIT",
    "FIRESTORE_RECOVERY_EVENT_RECORD_VERSION",
    "FIRESTORE_RECOVERY_EVENT_RETENTION",
    "FIRESTORE_RECOVERY_RUN_STATE_VERSION",
    "FirestoreRecoveryRunStore",
]
