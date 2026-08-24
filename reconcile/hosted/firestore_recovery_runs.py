"""Firestore CAS persistence for the separate recovery-run aggregate."""

from __future__ import annotations

import asyncio
from collections.abc import Callable
from datetime import datetime
from typing import Protocol

from reconcile.contracts import (
    RecoveryChain,
    RecoveryDispatchOutcome,
    RecoveryLaunchPermit,
    RecoveryRunEventPayload,
    RecoveryRunEventType,
    RecoveryRunRequest,
    RecoveryRunSnapshot,
    decode_contract,
)
from reconcile.hosted.firestore_cas import (
    FirestoreCasCollection,
    FirestoreCasConflict,
    FirestoreCasDocument,
    FirestoreCasOutcomeUnknown,
    FirestoreCasSnapshot,
    build_firestore_cas_document,
    new_firestore_cas_mutation_id,
)
from reconcile.persistence.recovery_runs import (
    RECOVERY_RUN_EVENT_SNAPSHOT_VERSION,
    RecoveryLaunchClaimDenied,
    RecoveryRunAggregate,
    RecoveryRunConflict,
    RecoveryRunCorruptState,
    RecoveryRunEventSnapshot,
    RecoveryRunNotFound,
    RecoveryRunStoreUnavailable,
    _append_decoded_recovery_event,
    _canonical_verified_recovery_aggregate_bytes,
    _RecoveryRunAggregateCache,
    claim_recovery_launch,
    complete_recovery_launch,
    create_recovery_run_aggregate,
    is_terminal_recovery_run,
)

_MAX_CAS_ATTEMPTS = 64


class _FirestoreCasStore(Protocol):
    async def read(
        self,
        collection: FirestoreCasCollection,
        logical_id: str,
    ) -> FirestoreCasSnapshot | None: ...

    async def create(
        self,
        document: FirestoreCasDocument,
    ) -> FirestoreCasSnapshot: ...

    async def update(
        self,
        current: FirestoreCasSnapshot,
        replacement: FirestoreCasDocument,
    ) -> FirestoreCasSnapshot: ...


def _document(aggregate: RecoveryRunAggregate) -> FirestoreCasDocument:
    return build_firestore_cas_document(
        collection=FirestoreCasCollection.RECOVERY_RUN,
        logical_id=aggregate.snapshot.request.run_id,
        revision=aggregate.snapshot.revision,
        mutation_id=new_firestore_cas_mutation_id(),
        canonical_payload=_canonical_verified_recovery_aggregate_bytes(aggregate),
    )


def _decode(snapshot: FirestoreCasSnapshot) -> RecoveryRunAggregate:
    try:
        if (
            type(snapshot) is not FirestoreCasSnapshot
            or snapshot.collection is not FirestoreCasCollection.RECOVERY_RUN
            or snapshot.document.kind is not FirestoreCasCollection.RECOVERY_RUN
        ):
            raise ValueError
        aggregate = decode_contract(
            snapshot.document.payload_bytes,
            RecoveryRunAggregate,
        )
        if (
            snapshot.document.logical_id != aggregate.snapshot.request.run_id
            or snapshot.document.revision != aggregate.snapshot.revision
        ):
            raise ValueError
        return aggregate
    except Exception as error:
        run_id = getattr(snapshot.document, "logical_id", None)
        raise RecoveryRunCorruptState(run_id) from error


class FirestoreRecoveryRunStore:
    """Persist each bounded aggregate with provider-enforced compare-and-swap."""

    def __init__(self, cas_store: _FirestoreCasStore) -> None:
        if any(
            not callable(getattr(cas_store, name, None))
            for name in ("create", "read", "update")
        ):
            raise TypeError("Firestore recovery store requires a CAS store")
        self._cas = cas_store
        self._aggregate_cache = _RecoveryRunAggregateCache()

    @staticmethod
    def _cache_identity(snapshot: FirestoreCasSnapshot) -> tuple[str | int, ...]:
        document = snapshot.document
        return (
            snapshot.collection.value,
            snapshot.document_key,
            document.schema_version,
            document.kind.value,
            document.logical_id,
            document.revision,
            document.mutation_id,
            document.payload_sha256,
            snapshot.update_time.isoformat(),
        )

    def _cache_verified(
        self,
        run_id: str,
        snapshot: FirestoreCasSnapshot,
        aggregate: RecoveryRunAggregate,
    ) -> None:
        if (
            snapshot.document.logical_id != run_id
            or aggregate.snapshot.request.run_id != run_id
        ):
            raise RecoveryRunCorruptState(run_id)
        self._aggregate_cache.put(
            run_id,
            identity=self._cache_identity(snapshot),
            payload=snapshot.document.payload_bytes,
            aggregate=aggregate,
        )

    async def _read(
        self,
        run_id: str,
    ) -> tuple[FirestoreCasSnapshot, RecoveryRunAggregate]:
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
        cached = self._aggregate_cache.get(
            run_id,
            identity=self._cache_identity(snapshot),
            payload=snapshot.document.payload_bytes,
        )
        if cached is not None:
            return snapshot, cached
        aggregate = _decode(snapshot)
        self._cache_verified(run_id, snapshot, aggregate)
        return snapshot, aggregate

    async def create(
        self,
        request: RecoveryRunRequest,
        chain: RecoveryChain,
        *,
        created_at: datetime,
    ) -> tuple[RecoveryRunSnapshot, bool]:
        aggregate = create_recovery_run_aggregate(request, chain, created_at=created_at)
        document = _document(aggregate)
        try:
            written = await self._cas.create(document)
        except asyncio.CancelledError:
            raise
        except FirestoreCasConflict:
            _snapshot, existing = await self._read(request.run_id)
            if existing.snapshot.request != request or existing.snapshot.chain != chain:
                raise RecoveryRunConflict(request.run_id) from None
            return existing.snapshot, False
        except Exception:
            raise RecoveryRunStoreUnavailable from None
        if written.document != document:
            raise RecoveryRunCorruptState(request.run_id)
        self._cache_verified(request.run_id, written, aggregate)
        return aggregate.snapshot, True

    async def get(self, run_id: str) -> RecoveryRunSnapshot:
        _snapshot, aggregate = await self._read(run_id)
        return aggregate.snapshot

    async def events(self, run_id: str, *, after: int = 0) -> RecoveryRunEventSnapshot:
        _snapshot, aggregate = await self._read(run_id)
        if type(after) is not int or not 0 <= after <= len(aggregate.events):
            raise RecoveryRunConflict(run_id)
        return RecoveryRunEventSnapshot(
            schema_version=RECOVERY_RUN_EVENT_SNAPSHOT_VERSION,
            run_id=run_id,
            cursor=len(aggregate.events),
            terminal=is_terminal_recovery_run(aggregate.snapshot.lifecycle),
            events=aggregate.events[after:],
        )

    async def _mutate(
        self,
        run_id: str,
        mutation: Callable[[RecoveryRunAggregate], RecoveryRunAggregate],
    ) -> RecoveryRunAggregate:
        for _attempt in range(_MAX_CAS_ATTEMPTS):
            snapshot, aggregate = await self._read(run_id)
            replacement = mutation(aggregate)
            document = _document(replacement)
            try:
                written = await self._cas.update(snapshot, document)
            except asyncio.CancelledError:
                raise
            except FirestoreCasConflict:
                continue
            except Exception:
                raise RecoveryRunStoreUnavailable from None
            if written.document != document:
                raise RecoveryRunCorruptState(run_id)
            self._cache_verified(run_id, written, replacement)
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


__all__ = ["FirestoreRecoveryRunStore"]
