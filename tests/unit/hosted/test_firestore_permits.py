"""Firestore CAS single-use permit behavior."""

from __future__ import annotations

import asyncio
from datetime import timedelta

import pytest

from reconcile.contracts import (
    ActionPermit,
    ActionPermitState,
    PermitCompletionOutcome,
)
from reconcile.controller.permits import PermitAuthority
from reconcile.hosted.firestore_cas import (
    FirestoreCasCollection,
    FirestoreCasConflict,
    FirestoreCasDocument,
    FirestoreCasOutcomeUnknown,
    FirestoreCasSnapshot,
    firestore_cas_document_key,
)
from reconcile.hosted.firestore_permits import FirestoreActionPermitStore
from reconcile.persistence.permits import (
    PermitAuditKind,
    PermitClaimDenied,
    PermitDenialReason,
    PermitStoreOutcomeUnknown,
)
from tests._permit_support import make_permit_certificate
from tests.contract._factories import NOW

pytestmark = pytest.mark.unit


class _MemoryCas:
    def __init__(self) -> None:
        self._lock = asyncio.Lock()
        self._documents: dict[str, FirestoreCasSnapshot] = {}
        self._ticks = 0
        self.fail_next_update_unknown = False

    async def read(
        self,
        collection: FirestoreCasCollection,
        logical_id: str,
    ) -> FirestoreCasSnapshot | None:
        assert collection is FirestoreCasCollection.ACTION_PERMIT
        async with self._lock:
            return self._documents.get(logical_id)

    def _snapshot(self, document: FirestoreCasDocument) -> FirestoreCasSnapshot:
        self._ticks += 1
        return FirestoreCasSnapshot(
            collection=document.kind,
            document_key=firestore_cas_document_key(
                document.kind,
                document.logical_id,
            ),
            document=document,
            update_time=NOW + timedelta(microseconds=self._ticks),
        )

    async def create(
        self,
        document: FirestoreCasDocument,
    ) -> FirestoreCasSnapshot:
        async with self._lock:
            if document.logical_id in self._documents:
                raise FirestoreCasConflict
            snapshot = self._snapshot(document)
            self._documents[document.logical_id] = snapshot
            return snapshot

    async def update(
        self,
        current: FirestoreCasSnapshot,
        replacement: FirestoreCasDocument,
    ) -> FirestoreCasSnapshot:
        async with self._lock:
            if self.fail_next_update_unknown:
                self.fail_next_update_unknown = False
                raise FirestoreCasOutcomeUnknown
            stored = self._documents.get(replacement.logical_id)
            if stored is None or stored.update_time != current.update_time:
                raise FirestoreCasConflict
            snapshot = self._snapshot(replacement)
            self._documents[replacement.logical_id] = snapshot
            return snapshot


def test_firestore_thirty_two_concurrent_claims_have_exactly_one_winner() -> None:
    async def scenario() -> None:
        certificate, arguments, precondition = make_permit_certificate()
        store = FirestoreActionPermitStore(_MemoryCas())
        permit = await PermitAuthority(
            store,
            clock=lambda: NOW + timedelta(seconds=6),
        ).issue_permit(certificate)
        assert permit is not None

        async def claim(index: int) -> ActionPermit:
            authority = PermitAuthority(
                store,
                clock=lambda: NOW + timedelta(seconds=7),
                claim_id_factory=lambda: f"claim-{index:02d}",
            )
            return await authority.claim_for_dispatch(
                permit_id=permit.permit_id,
                certificate=certificate,
                tool_name=permit.tool_name,
                tool_version=permit.tool_version,
                arguments=arguments,
                target=certificate.target,
                precondition=precondition,
            )

        results = await asyncio.gather(
            *(claim(index) for index in range(32)),
            return_exceptions=True,
        )
        winners = [item for item in results if type(item) is ActionPermit]
        denials = [item for item in results if isinstance(item, PermitClaimDenied)]
        assert len(winners) == 1
        assert len(denials) == 31
        assert {item.reason for item in denials} == {PermitDenialReason.ALREADY_CLAIMED}
        events = await store.permit_audit_events(permit.permit_id)
        assert events[0].kind is PermitAuditKind.ISSUED
        assert sum(event.kind is PermitAuditKind.CLAIMED for event in events) == 1
        assert sum(event.kind is PermitAuditKind.BLOCKED for event in events) == 31

        completed = await PermitAuthority(
            store,
            clock=lambda: NOW + timedelta(seconds=8),
        ).complete_dispatch(winners[0], PermitCompletionOutcome.SUCCEEDED)
        assert completed.state is ActionPermitState.COMPLETED
        assert completed.completion_outcome is PermitCompletionOutcome.SUCCEEDED
        assert (await store.permit_audit_events(permit.permit_id))[-1].kind is (
            PermitAuditKind.COMPLETED
        )

    asyncio.run(scenario())


def test_firestore_claim_outcome_unknown_never_returns_dispatch_authority() -> None:
    async def scenario() -> None:
        certificate, arguments, precondition = make_permit_certificate()
        cas = _MemoryCas()
        store = FirestoreActionPermitStore(cas)
        permit = await PermitAuthority(
            store,
            clock=lambda: NOW + timedelta(seconds=6),
        ).issue_permit(certificate)
        assert permit is not None
        cas.fail_next_update_unknown = True
        authority = PermitAuthority(
            store,
            clock=lambda: NOW + timedelta(seconds=7),
            claim_id_factory=lambda: "claim-unknown",
        )
        with pytest.raises(PermitStoreOutcomeUnknown):
            await authority.claim_for_dispatch(
                permit_id=permit.permit_id,
                certificate=certificate,
                tool_name=permit.tool_name,
                tool_version=permit.tool_version,
                arguments=arguments,
                target=certificate.target,
                precondition=precondition,
            )
        assert (await store.get_permit(permit.permit_id)).state is (
            ActionPermitState.ISSUED
        )
        assert [
            event.kind for event in await store.permit_audit_events(permit.permit_id)
        ] == [PermitAuditKind.ISSUED]

    asyncio.run(scenario())
