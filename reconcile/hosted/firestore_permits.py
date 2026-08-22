"""Single-document Firestore CAS authority for one action permit."""

from __future__ import annotations

import asyncio
from collections.abc import Callable
from datetime import datetime
from typing import Literal, Protocol

from pydantic import model_validator

from reconcile.contracts import ActionPermit, ActionPermitState, canonical_json_bytes
from reconcile.contracts.base import StrictModel
from reconcile.contracts.codec import decode_contract
from reconcile.hosted.firestore_cas import (
    FirestoreCasCollection,
    FirestoreCasConflict,
    FirestoreCasDocument,
    FirestoreCasOutcomeUnknown,
    FirestoreCasSnapshot,
    build_firestore_cas_document,
    new_firestore_cas_mutation_id,
)
from reconcile.persistence.permits import (
    PermitAuditEvent,
    PermitClaimDenied,
    PermitClaimRequest,
    PermitCompletionDenied,
    PermitCompletionRequest,
    PermitConflict,
    PermitCorruptState,
    PermitMutation,
    PermitNotFound,
    PermitStoreError,
    PermitStoreOutcomeUnknown,
    PermitStoreUnavailable,
    evaluate_permit_claim,
    evaluate_permit_completion,
    issued_audit_event,
    same_action_permit_authority,
    validate_action_permit_identity,
    validate_permit_audit_history,
)

FIRESTORE_ACTION_PERMIT_AGGREGATE_VERSION = (
    "reconcile/firestore-action-permit-aggregate/v1"
)
_MAX_CAS_ATTEMPTS = 64


class FirestoreActionPermitAggregate(StrictModel):
    schema_version: Literal[FIRESTORE_ACTION_PERMIT_AGGREGATE_VERSION]
    permit: ActionPermit
    audit_events: tuple[PermitAuditEvent, ...]

    @model_validator(mode="after")
    def validate_history(self) -> FirestoreActionPermitAggregate:
        validate_permit_audit_history(self.permit, self.audit_events)
        return self


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


def _aggregate_document(
    aggregate: FirestoreActionPermitAggregate,
    *,
    revision: int,
) -> FirestoreCasDocument:
    return build_firestore_cas_document(
        collection=FirestoreCasCollection.ACTION_PERMIT,
        logical_id=aggregate.permit.permit_id,
        revision=revision,
        mutation_id=new_firestore_cas_mutation_id(),
        canonical_payload=canonical_json_bytes(aggregate),
    )


def _decode_aggregate(
    snapshot: FirestoreCasSnapshot,
) -> FirestoreActionPermitAggregate:
    try:
        if (
            type(snapshot) is not FirestoreCasSnapshot
            or snapshot.collection is not FirestoreCasCollection.ACTION_PERMIT
            or snapshot.document.kind is not FirestoreCasCollection.ACTION_PERMIT
        ):
            raise ValueError("snapshot collection is invalid")
        aggregate = decode_contract(
            snapshot.document.payload_bytes,
            FirestoreActionPermitAggregate,
        )
        validate_action_permit_identity(aggregate.permit)
        if snapshot.document.logical_id != aggregate.permit.permit_id:
            raise ValueError("snapshot logical identity is invalid")
        if snapshot.document.revision != len(aggregate.audit_events) - 1:
            raise ValueError("snapshot revision does not match permit audit history")
        return aggregate
    except PermitStoreError:
        raise
    except Exception as error:
        permit_id = getattr(snapshot.document, "logical_id", None)
        raise PermitCorruptState(permit_id) from error


class FirestoreActionPermitStore:
    """Persist exact permit transitions with provider-enforced CAS preconditions."""

    def __init__(self, cas_store: _FirestoreCasStore) -> None:
        if any(
            not callable(getattr(cas_store, name, None))
            for name in ("create", "read", "update")
        ):
            raise TypeError("Firestore permit store requires a CAS store")
        self._cas_store = cas_store

    async def _read(
        self,
        permit_id: str,
    ) -> tuple[FirestoreCasSnapshot, FirestoreActionPermitAggregate]:
        try:
            snapshot = await self._cas_store.read(
                FirestoreCasCollection.ACTION_PERMIT,
                permit_id,
            )
        except asyncio.CancelledError:
            raise
        except FirestoreCasOutcomeUnknown:
            raise PermitStoreOutcomeUnknown from None
        except Exception:
            raise PermitStoreUnavailable from None
        if snapshot is None:
            raise PermitNotFound(permit_id)
        return snapshot, _decode_aggregate(snapshot)

    async def issue_permit(self, permit: ActionPermit) -> ActionPermit:
        if type(permit) is not ActionPermit or (
            permit.state is not ActionPermitState.ISSUED
        ):
            raise TypeError("an exact issued action permit is required")
        try:
            validate_action_permit_identity(permit)
        except (TypeError, ValueError) as error:
            raise PermitConflict(permit.permit_id) from error
        aggregate = FirestoreActionPermitAggregate(
            schema_version=FIRESTORE_ACTION_PERMIT_AGGREGATE_VERSION,
            permit=permit,
            audit_events=(issued_audit_event(permit),),
        )
        document = _aggregate_document(aggregate, revision=0)
        try:
            written = await self._cas_store.create(document)
        except asyncio.CancelledError:
            raise
        except FirestoreCasConflict:
            try:
                _snapshot, existing = await self._read(permit.permit_id)
            except PermitStoreError:
                raise PermitConflict(permit.permit_id) from None
            if not same_action_permit_authority(existing.permit, permit):
                raise PermitConflict(permit.permit_id) from None
            return existing.permit
        except FirestoreCasOutcomeUnknown:
            raise PermitStoreOutcomeUnknown from None
        except Exception:
            raise PermitStoreUnavailable from None
        if written.document != document or _decode_aggregate(written) != aggregate:
            raise PermitCorruptState(permit.permit_id)
        return permit

    async def get_permit(self, permit_id: str) -> ActionPermit:
        _snapshot, aggregate = await self._read(permit_id)
        return aggregate.permit

    async def permit_audit_events(
        self,
        permit_id: str,
    ) -> tuple[PermitAuditEvent, ...]:
        _snapshot, aggregate = await self._read(permit_id)
        return aggregate.audit_events

    async def _mutate(
        self,
        permit_id: str,
        mutation_factory: Callable[
            [ActionPermit, int, datetime],
            PermitMutation,
        ],
    ) -> PermitMutation:
        for _attempt in range(_MAX_CAS_ATTEMPTS):
            snapshot, aggregate = await self._read(permit_id)
            mutation = mutation_factory(
                aggregate.permit,
                len(aggregate.audit_events) + 1,
                aggregate.audit_events[-1].occurred_at,
            )
            replacement = FirestoreActionPermitAggregate(
                schema_version=FIRESTORE_ACTION_PERMIT_AGGREGATE_VERSION,
                permit=mutation.permit,
                audit_events=(*aggregate.audit_events, mutation.event),
            )
            document = _aggregate_document(
                replacement,
                revision=snapshot.document.revision + 1,
            )
            try:
                written = await self._cas_store.update(snapshot, document)
            except asyncio.CancelledError:
                raise
            except FirestoreCasConflict:
                continue
            except FirestoreCasOutcomeUnknown:
                raise PermitStoreOutcomeUnknown from None
            except Exception:
                raise PermitStoreUnavailable from None
            if (
                written.document != document
                or _decode_aggregate(written) != replacement
            ):
                raise PermitCorruptState(permit_id)
            return mutation
        raise PermitStoreUnavailable

    async def claim_permit(self, request: PermitClaimRequest) -> ActionPermit:
        if type(request) is not PermitClaimRequest:
            raise TypeError("permit claim request must be exact")
        mutation = await self._mutate(
            request.permit_id,
            lambda permit, sequence, audit_not_before: evaluate_permit_claim(
                permit,
                request,
                audit_sequence=sequence,
                audit_not_before=audit_not_before,
            ),
        )
        if mutation.denial_reason is not None:
            raise PermitClaimDenied(request.permit_id, mutation.denial_reason)
        return mutation.permit

    async def complete_permit(
        self,
        request: PermitCompletionRequest,
    ) -> ActionPermit:
        if type(request) is not PermitCompletionRequest:
            raise TypeError("permit completion request must be exact")
        mutation = await self._mutate(
            request.permit_id,
            lambda permit, sequence, audit_not_before: evaluate_permit_completion(
                permit,
                request,
                audit_sequence=sequence,
                audit_not_before=audit_not_before,
            ),
        )
        if mutation.denial_reason is not None:
            raise PermitCompletionDenied(request.permit_id, mutation.denial_reason)
        return mutation.permit


__all__ = [
    "FIRESTORE_ACTION_PERMIT_AGGREGATE_VERSION",
    "FirestoreActionPermitAggregate",
    "FirestoreActionPermitStore",
]
