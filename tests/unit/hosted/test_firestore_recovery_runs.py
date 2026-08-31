"""Recovery aggregates use Firestore compare-and-swap rather than local locks."""

from __future__ import annotations

import asyncio
import json
from datetime import timedelta

import pytest

import reconcile.hosted.firestore_recovery_runs as recovery_run_module
from reconcile.contracts import (
    RECOVERY_DISPATCH_RECEIPT_VERSION,
    RECOVERY_RUN_EVENT_VERSION,
    ActionPermit,
    ActionPermitState,
    Classification,
    InvestigationReport,
    PermitCompletionOutcome,
    RecoveryDispatchOutcome,
    RecoveryDispatchReceipt,
    RecoveryHypothesisDisposition,
    RecoveryNodeProgress,
    RecoveryNodeState,
    RecoveryReceiptOutcome,
    RecoveryRunEvent,
    RecoveryRunEventPayload,
    RecoveryRunEventType,
    RecoveryRunLifecycle,
    RecoveryRunPolicy,
    canonical_json_bytes,
    canonical_sha256,
)
from reconcile.contracts.base import canonical_json_value_bytes
from reconcile.hosted.firestore_cas import (
    FIRESTORE_CAS_PAYLOAD_BYTE_CEILING,
    FirestoreCasCollection,
    FirestoreCasSnapshot,
    build_firestore_cas_document,
)
from reconcile.hosted.firestore_recovery_runs import FirestoreRecoveryRunStore
from reconcile.persistence import (
    RecoveryRunConflict,
    RecoveryRunCorruptState,
    RecoveryRunEventTooLarge,
)
from reconcile.persistence.recovery_runs import (
    _append_decoded_recovery_event,
    _canonical_verified_recovery_aggregate_bytes,
    create_recovery_run_aggregate,
)
from tests.contract._factories import (
    NOW,
    make_recovery_examples,
    make_recovery_run_examples,
    make_report,
)
from tests.unit.hosted.test_firestore_cas import _Client, _store

pytestmark = pytest.mark.unit

_CURRENT_STATE_FIELDS = {
    "event_cursor",
    "event_record_version",
    "journal_sha256",
    "request",
    "request_sha256",
    "revision",
    "schema_version",
}


def _running_aggregate_at_cursor(request, chain, cursor):
    aggregate = create_recovery_run_aggregate(request, chain, created_at=NOW)
    aggregate = _append_decoded_recovery_event(
        aggregate,
        event_type=RecoveryRunEventType.LIFECYCLE,
        payload=RecoveryRunEventPayload(lifecycle=RecoveryRunLifecycle.RUNNING),
        occurred_at=NOW,
    )
    filler = RecoveryRunEventPayload(
        hypothesis_disposition=RecoveryHypothesisDisposition.MODEL_UNAVAILABLE,
        note="fixed fallback selected",
    )
    while aggregate.snapshot.event_cursor < cursor:
        aggregate = _append_decoded_recovery_event(
            aggregate,
            event_type=RecoveryRunEventType.HYPOTHESIS,
            payload=filler,
            occurred_at=NOW,
        )
    return aggregate


async def _seed_current_aggregate(cas, aggregate) -> None:
    records = recovery_run_module._journal_records(
        aggregate.snapshot.request,
        aggregate.events,
    )
    documents = tuple(recovery_run_module._event_document(item) for item in records)
    for start in range(0, len(documents), 500):
        await cas.create_many(documents[start : start + 500])
    await cas.create(recovery_run_module._state_document(aggregate))


async def _assert_unrelated_append_is_rejected(store, snapshot) -> None:
    with pytest.raises(RecoveryRunConflict):
        await store.append(
            snapshot.request.run_id,
            expected_revision=snapshot.revision,
            event_type=RecoveryRunEventType.HYPOTHESIS,
            payload=RecoveryRunEventPayload(
                hypothesis_disposition=(
                    RecoveryHypothesisDisposition.MODEL_UNAVAILABLE
                ),
                note="fixed fallback selected",
            ),
            occurred_at=snapshot.updated_at,
        )
    assert await store.get(snapshot.request.run_id) == snapshot


def test_action_authority_capacity_covers_claim_contact_and_node_settlement() -> None:
    _request, _event, _launch, initial, _scope = make_recovery_run_examples()
    _chain, _hypothesis, _certificate, _witness, issued = make_recovery_examples()
    source, target = initial.chain.nodes
    running = initial.model_copy(
        update={
            "lifecycle": RecoveryRunLifecycle.RUNNING,
            "nodes": (
                RecoveryNodeProgress(
                    node_id=source.node_id,
                    state=RecoveryNodeState.VERIFIED,
                    attempt=1,
                ),
                RecoveryNodeProgress(
                    node_id=target.node_id,
                    state=RecoveryNodeState.WAITING,
                    attempt=0,
                ),
            ),
            "active_node_id": source.node_id,
            "action_permits": (issued,),
        }
    )
    claimed = ActionPermit.model_validate(
        issued.model_copy(
            update={
                "state": ActionPermitState.CLAIMED,
                "revision": 1,
                "claim_id": "claim-action-capacity",
                "claimed_at": NOW + timedelta(seconds=6),
            }
        )
    )
    permitted = running.model_copy(
        update={
            "nodes": (
                RecoveryNodeProgress(
                    node_id=source.node_id,
                    state=RecoveryNodeState.PERMITTED,
                    attempt=1,
                ),
                running.nodes[1],
            ),
        }
    )
    claimed_snapshot = permitted.model_copy(update={"action_permits": (claimed,)})
    receipt = RecoveryDispatchReceipt(
        schema_version=RECOVERY_DISPATCH_RECEIPT_VERSION,
        receipt_id="dispatch-action-capacity",
        run_id=initial.request.run_id,
        release_id=str(target.semantic_action.semantic_arguments["release_id"]),
        node_id=target.node_id,
        semantic_action_sha256=target.semantic_action.semantic_action_sha256,
        action_request_sha256="a" * 64,
        authority_id=claimed.permit_id,
        claim_id=claimed.claim_id or "",
        attempt=1,
        provider_contact=True,
        outcome=RecoveryReceiptOutcome.PROVIDER_CONTACTED,
        recorded_at=NOW + timedelta(seconds=6),
    )
    contacted = claimed_snapshot.model_copy(update={"dispatch_receipts": (receipt,)})
    completed = ActionPermit.model_validate(
        claimed.model_copy(
            update={
                "state": ActionPermitState.COMPLETED,
                "revision": 2,
                "completed_at": NOW + timedelta(seconds=7),
                "completion_outcome": PermitCompletionOutcome.SUCCEEDED,
            }
        )
    )
    completed_snapshot = contacted.model_copy(update={"action_permits": (completed,)})
    target_settled = completed_snapshot.model_copy(
        update={
            "nodes": (
                completed_snapshot.nodes[0],
                RecoveryNodeProgress(
                    node_id=target.node_id,
                    state=RecoveryNodeState.RECONCILING,
                    attempt=1,
                ),
            )
        }
    )
    fully_settled = target_settled.model_copy(
        update={
            "nodes": (
                RecoveryNodeProgress(
                    node_id=source.node_id,
                    state=RecoveryNodeState.COMPLETED,
                    attempt=1,
                ),
                target_settled.nodes[1],
            )
        }
    )

    assert tuple(
        recovery_run_module._required_authority_event_capacity(snapshot)
        for snapshot in (
            running,
            permitted,
            claimed_snapshot,
            contacted,
            completed_snapshot,
            target_settled,
            fully_settled,
        )
    ) == (6, 5, 4, 3, 2, 1, 0)


def test_firestore_recovery_store_preserves_cas_revision_and_event_order() -> None:
    request, _event, _launch, expected, _scope = make_recovery_run_examples()

    async def exercise() -> None:
        client = _Client()
        cas, _factory = _store(client)
        store = FirestoreRecoveryRunStore(cas)
        created, was_created = await store.create(
            request,
            expected.chain,
            created_at=NOW,
        )
        assert was_created is True
        updated = await store.append(
            request.run_id,
            expected_revision=created.revision,
            event_type=RecoveryRunEventType.LIFECYCLE,
            payload=RecoveryRunEventPayload(lifecycle=RecoveryRunLifecycle.RUNNING),
            occurred_at=NOW + timedelta(seconds=1),
        )
        with pytest.raises(RecoveryRunConflict):
            await store.append(
                request.run_id,
                expected_revision=created.revision,
                event_type=RecoveryRunEventType.LIFECYCLE,
                payload=RecoveryRunEventPayload(
                    lifecycle=RecoveryRunLifecycle.CANCELLED
                ),
                occurred_at=NOW + timedelta(seconds=2),
            )
        events = await store.events(request.run_id)
        assert updated.revision == 2
        assert tuple(event.cursor for event in events.events) == (1, 2, 3)
        documents = tuple(item[0] for item in client.documents.values())
        state_documents = tuple(
            item
            for item in documents
            if item["kind"] == FirestoreCasCollection.RECOVERY_RUN.value
        )
        event_documents = tuple(
            item
            for item in documents
            if item["kind"] == FirestoreCasCollection.RECOVERY_RUN_EVENT.value
        )
        assert len(state_documents) == 1
        assert len(event_documents) == 3
        state_payload = json.loads(state_documents[0]["canonical_payload"])
        assert set(state_payload) == _CURRENT_STATE_FIELDS
        assert "events" not in state_payload
        assert tuple(
            json.loads(item["canonical_payload"])["event"]["cursor"]
            for item in event_documents
        ) == (1, 2, 3)

    asyncio.run(exercise())


def test_concurrent_append_commits_one_canonical_transition() -> None:
    request, _event, _launch, expected, _scope = make_recovery_run_examples()

    async def exercise() -> None:
        cas, _factory = _store(_Client())
        first = FirestoreRecoveryRunStore(cas)
        second = FirestoreRecoveryRunStore(cas)
        created, _was_created = await first.create(
            request,
            expected.chain,
            created_at=NOW,
        )
        results = await asyncio.gather(
            first.append(
                request.run_id,
                expected_revision=created.revision,
                event_type=RecoveryRunEventType.LIFECYCLE,
                payload=RecoveryRunEventPayload(lifecycle=RecoveryRunLifecycle.RUNNING),
                occurred_at=NOW + timedelta(seconds=1),
            ),
            second.append(
                request.run_id,
                expected_revision=created.revision,
                event_type=RecoveryRunEventType.LIFECYCLE,
                payload=RecoveryRunEventPayload(lifecycle=RecoveryRunLifecycle.RUNNING),
                occurred_at=NOW + timedelta(seconds=1),
            ),
            return_exceptions=True,
        )

        assert sum(type(item) is not RecoveryRunConflict for item in results) == 1
        assert sum(type(item) is RecoveryRunConflict for item in results) == 1
        events = await FirestoreRecoveryRunStore(cas).events(request.run_id)
        assert tuple(event.cursor for event in events.events) == (1, 2, 3)

    asyncio.run(exercise())


def test_concurrent_legacy_migration_commits_one_canonical_transition() -> None:
    request, _event, _launch, expected, _scope = make_recovery_run_examples()

    async def exercise() -> None:
        client = _Client()
        cas, _factory = _store(client)
        aggregate = create_recovery_run_aggregate(
            request,
            expected.chain,
            created_at=NOW,
        )
        await cas.create(
            build_firestore_cas_document(
                collection=FirestoreCasCollection.RECOVERY_RUN,
                logical_id=request.run_id,
                revision=aggregate.snapshot.revision,
                mutation_id="mutation-concurrent-legacy",
                canonical_payload=_canonical_verified_recovery_aggregate_bytes(
                    aggregate
                ),
            )
        )
        first = FirestoreRecoveryRunStore(cas)
        second = FirestoreRecoveryRunStore(cas)

        results = await asyncio.gather(
            first.append(
                request.run_id,
                expected_revision=aggregate.snapshot.revision,
                event_type=RecoveryRunEventType.LIFECYCLE,
                payload=RecoveryRunEventPayload(lifecycle=RecoveryRunLifecycle.RUNNING),
                occurred_at=NOW + timedelta(seconds=1),
            ),
            second.append(
                request.run_id,
                expected_revision=aggregate.snapshot.revision,
                event_type=RecoveryRunEventType.LIFECYCLE,
                payload=RecoveryRunEventPayload(lifecycle=RecoveryRunLifecycle.RUNNING),
                occurred_at=NOW + timedelta(seconds=1),
            ),
            return_exceptions=True,
        )

        assert sum(type(item) is not RecoveryRunConflict for item in results) == 1
        assert sum(type(item) is RecoveryRunConflict for item in results) == 1
        events = await FirestoreRecoveryRunStore(cas).events(request.run_id)
        assert tuple(event.cursor for event in events.events) == (1, 2, 3)

    asyncio.run(exercise())


def test_event_limit_fails_before_state_or_journal_changes(monkeypatch) -> None:
    request, _event, _launch, expected, _scope = make_recovery_run_examples()

    async def exercise() -> None:
        client = _Client()
        cas, _factory = _store(client)
        store = FirestoreRecoveryRunStore(cas)
        created, _was_created = await store.create(
            request,
            expected.chain,
            created_at=NOW,
        )
        before = dict(client.documents)
        monkeypatch.setattr(recovery_run_module, "FIRESTORE_RECOVERY_EVENT_LIMIT", 2)

        with pytest.raises(RecoveryRunConflict):
            await store.append(
                request.run_id,
                expected_revision=created.revision,
                event_type=RecoveryRunEventType.LIFECYCLE,
                payload=RecoveryRunEventPayload(lifecycle=RecoveryRunLifecycle.RUNNING),
                occurred_at=NOW + timedelta(seconds=1),
            )

        assert client.documents == before

    asyncio.run(exercise())


def test_launch_authority_reserves_cursor_509_through_acceptance_settlement() -> None:
    request, _event, launch, expected, _scope = make_recovery_run_examples()

    async def exercise() -> None:
        client = _Client()
        cas, _factory = _store(client)
        aggregate = _running_aggregate_at_cursor(request, expected.chain, 505)
        await _seed_current_aggregate(cas, aggregate)
        store = FirestoreRecoveryRunStore(cas)

        issued = await store.append(
            request.run_id,
            expected_revision=aggregate.snapshot.revision,
            event_type=RecoveryRunEventType.LAUNCH_PERMIT,
            payload=RecoveryRunEventPayload(launch_permit=launch),
            occurred_at=NOW,
        )
        pending = await store.append(
            request.run_id,
            expected_revision=issued.revision,
            event_type=RecoveryRunEventType.NODE,
            payload=RecoveryRunEventPayload(
                node=RecoveryNodeProgress(
                    node_id=launch.node_id,
                    state=RecoveryNodeState.DISPATCH_PENDING,
                    attempt=1,
                )
            ),
            occurred_at=NOW,
        )
        claimed = await store.claim_launch(
            request.run_id,
            launch_permit_id=launch.launch_permit_id,
            claim_id="claim-capacity-boundary",
            action_request_sha256=launch.action_request_sha256,
            claimed_at=NOW,
        )
        claimed_snapshot = await store.get(request.run_id)
        provider_receipt = RecoveryDispatchReceipt(
            schema_version=RECOVERY_DISPATCH_RECEIPT_VERSION,
            receipt_id="dispatch-capacity-provider",
            run_id=request.run_id,
            release_id=str(
                expected.chain.nodes[0].semantic_action.semantic_arguments["release_id"]
            ),
            node_id=launch.node_id,
            semantic_action_sha256=launch.semantic_action_sha256,
            action_request_sha256=launch.action_request_sha256,
            authority_id=launch.launch_permit_id,
            claim_id=claimed.claim_id or "",
            attempt=1,
            provider_contact=True,
            outcome=RecoveryReceiptOutcome.PROVIDER_CONTACTED,
            recorded_at=NOW,
        )
        contacted = await store.append(
            request.run_id,
            expected_revision=claimed_snapshot.revision,
            event_type=RecoveryRunEventType.DISPATCH_RECEIPT,
            payload=RecoveryRunEventPayload(dispatch_receipt=provider_receipt),
            occurred_at=NOW,
        )
        assert recovery_run_module._required_authority_event_capacity(contacted) == 3
        await _assert_unrelated_append_is_rejected(store, contacted)
        completed = await store.complete_launch(
            request.run_id,
            launch_permit_id=launch.launch_permit_id,
            claim_id=claimed.claim_id or "",
            outcome=RecoveryDispatchOutcome.SUCCEEDED,
            completed_at=NOW,
        )
        completed_snapshot = await store.get(request.run_id)
        assert (
            recovery_run_module._required_authority_event_capacity(completed_snapshot)
            == 2
        )
        await _assert_unrelated_append_is_rejected(store, completed_snapshot)
        observer_receipt = provider_receipt.model_copy(
            update={
                "receipt_id": "dispatch-capacity-acceptance-observer",
                "provider_contact": False,
                "outcome": RecoveryReceiptOutcome.REJECTED_BEFORE_PROVIDER_CONTACT,
            }
        )
        observed = await store.append(
            request.run_id,
            expected_revision=completed_snapshot.revision,
            event_type=RecoveryRunEventType.DISPATCH_RECEIPT,
            payload=RecoveryRunEventPayload(dispatch_receipt=observer_receipt),
            occurred_at=NOW,
        )
        assert recovery_run_module._required_authority_event_capacity(observed) == 1
        observed_while_claimed = observed.model_copy(
            update={
                "nodes": (
                    RecoveryNodeProgress(
                        node_id=launch.node_id,
                        state=RecoveryNodeState.DISPATCH_CLAIMED,
                        attempt=1,
                    ),
                    *observed.nodes[1:],
                )
            }
        )
        assert (
            recovery_run_module._required_authority_event_capacity(
                observed_while_claimed
            )
            == 1
        )
        await _assert_unrelated_append_is_rejected(store, observed)
        settled = await store.append(
            request.run_id,
            expected_revision=observed.revision,
            event_type=RecoveryRunEventType.NODE,
            payload=RecoveryRunEventPayload(
                node=RecoveryNodeProgress(
                    node_id=launch.node_id,
                    state=RecoveryNodeState.RECONCILING,
                    attempt=1,
                )
            ),
            occurred_at=NOW,
        )
        assert recovery_run_module._required_authority_event_capacity(settled) == 0
        await _assert_unrelated_append_is_rejected(store, settled)

        assert (
            issued.event_cursor,
            pending.event_cursor,
            claimed_snapshot.event_cursor,
            contacted.event_cursor,
            completed_snapshot.event_cursor,
            observed.event_cursor,
            settled.event_cursor,
            (await store.get(request.run_id)).launch_permit,
        ) == (506, 507, 508, 509, 510, 511, 512, completed)
        assert tuple(
            recovery_run_module._required_authority_event_capacity(snapshot)
            for snapshot in (
                issued,
                pending,
                claimed_snapshot,
                contacted,
                completed_snapshot,
                observed,
                settled,
            )
        ) == (6, 5, 4, 3, 2, 1, 0)
        assert settled.dispatch_receipts == (provider_receipt, observer_receipt)

    asyncio.run(exercise())


def test_launch_permit_is_rejected_before_it_can_overrun_reserved_capacity() -> None:
    request, _event, launch, expected, _scope = make_recovery_run_examples()

    async def exercise() -> None:
        client = _Client()
        cas, _factory = _store(client)
        aggregate = _running_aggregate_at_cursor(request, expected.chain, 506)
        await _seed_current_aggregate(cas, aggregate)
        store = FirestoreRecoveryRunStore(cas)
        before = dict(client.documents)

        with pytest.raises(RecoveryRunConflict):
            await store.append(
                request.run_id,
                expected_revision=aggregate.snapshot.revision,
                event_type=RecoveryRunEventType.LAUNCH_PERMIT,
                payload=RecoveryRunEventPayload(launch_permit=launch),
                occurred_at=NOW,
            )

        assert client.documents == before
        assert (await store.get(request.run_id)).event_cursor == 506

    asyncio.run(exercise())


def test_valid_event_over_ceiling_uses_recovery_store_error(monkeypatch) -> None:
    request, _event, _launch, expected, _scope = make_recovery_run_examples()

    async def exercise() -> None:
        client = _Client()
        cas, _factory = _store(client)
        store = FirestoreRecoveryRunStore(cas)
        created, _was_created = await store.create(
            request,
            expected.chain,
            created_at=NOW,
        )
        event = RecoveryRunEvent(
            schema_version=RECOVERY_RUN_EVENT_VERSION,
            run_id=request.run_id,
            cursor=3,
            type=RecoveryRunEventType.LIFECYCLE,
            occurred_at=NOW,
            payload=RecoveryRunEventPayload(lifecycle=RecoveryRunLifecycle.RUNNING),
        )
        monkeypatch.setattr(
            recovery_run_module,
            "FIRESTORE_RECOVERY_EVENT_BYTE_CEILING",
            len(canonical_json_bytes(event)) - 1,
        )
        before = dict(client.documents)

        with pytest.raises(
            RecoveryRunEventTooLarge,
            match="durable byte limit",
        ):
            await store.append(
                request.run_id,
                expected_revision=created.revision,
                event_type=event.type,
                payload=event.payload,
                occurred_at=event.occurred_at,
            )

        assert client.documents == before

    asyncio.run(exercise())


def test_firestore_reads_revalidate_external_writes_tampering_and_restart() -> None:
    request, _event, _launch, expected, _scope = make_recovery_run_examples()
    client = _Client()
    cas, _factory = _store(client)

    async def exercise() -> None:
        store = FirestoreRecoveryRunStore(cas)
        created, was_created = await store.create(
            request,
            expected.chain,
            created_at=NOW,
        )
        assert was_created is True
        created.chain.nodes[0].semantic_action.semantic_arguments["release_id"] = (
            "caller-mutation"
        )
        reread = await store.get(request.run_id)
        assert reread == expected
        reread.chain.nodes[0].semantic_action.semantic_arguments["release_id"] = (
            "second-caller-mutation"
        )
        assert await store.get(request.run_id) == expected

        reopened = FirestoreRecoveryRunStore(cas)
        assert await reopened.get(request.run_id) == expected
        assert await reopened.get(request.run_id) == expected

        updated = await reopened.append(
            request.run_id,
            expected_revision=expected.revision,
            event_type=RecoveryRunEventType.LIFECYCLE,
            payload=RecoveryRunEventPayload(lifecycle=RecoveryRunLifecycle.RUNNING),
            occurred_at=NOW + timedelta(seconds=1),
        )
        assert await store.get(request.run_id) == updated
        assert await store.get(request.run_id) == updated

        path, (data, _update_time) = next(iter(client.documents.items()))
        state = json.loads(data["canonical_payload"])
        state["journal_sha256"] = "f" * 64
        document = build_firestore_cas_document(
            collection=FirestoreCasCollection.RECOVERY_RUN,
            logical_id=request.run_id,
            revision=data["revision"],
            mutation_id="mutation-externally-tampered",
            canonical_payload=canonical_json_value_bytes(state),
        )
        client.documents[path] = (document.model_dump(mode="json"), client.clock)
        client.clock += timedelta(microseconds=1)

        with pytest.raises(RecoveryRunCorruptState):
            await store.get(request.run_id)

    asyncio.run(exercise())


def test_current_journal_genesis_rejects_a_rehashed_request_rewrite() -> None:
    request, _event, _launch, expected, _scope = make_recovery_run_examples()

    async def exercise() -> None:
        client = _Client()
        cas, _factory = _store(client)
        store = FirestoreRecoveryRunStore(cas)
        await store.create(request, expected.chain, created_at=NOW)
        path, (data, _update_time) = next(
            item
            for item in client.documents.items()
            if item[1][0]["kind"] == FirestoreCasCollection.RECOVERY_RUN.value
        )
        state = json.loads(data["canonical_payload"])
        changed_request = request.model_copy(update={"policy": RecoveryRunPolicy.FIXED})
        state["request"] = changed_request.model_dump(mode="json")
        state["request_sha256"] = canonical_sha256(changed_request)
        rewritten = build_firestore_cas_document(
            collection=FirestoreCasCollection.RECOVERY_RUN,
            logical_id=request.run_id,
            revision=data["revision"],
            mutation_id="mutation-rehashed-request-rewrite",
            canonical_payload=canonical_json_value_bytes(state),
        )
        client.documents[path] = (rewritten.model_dump(mode="json"), client.clock)
        client.clock += timedelta(microseconds=1)

        with pytest.raises(RecoveryRunCorruptState):
            await store.get(request.run_id)

    asyncio.run(exercise())


def test_missing_event_is_rejected_before_launch_authority_can_be_claimed() -> None:
    request, _event, launch, expected, _scope = make_recovery_run_examples()

    async def exercise() -> None:
        client = _Client()
        cas, _factory = _store(client)
        store = FirestoreRecoveryRunStore(cas)
        current, _was_created = await store.create(
            request,
            expected.chain,
            created_at=NOW,
        )
        current = await store.append(
            request.run_id,
            expected_revision=current.revision,
            event_type=RecoveryRunEventType.LIFECYCLE,
            payload=RecoveryRunEventPayload(lifecycle=RecoveryRunLifecycle.RUNNING),
            occurred_at=NOW + timedelta(seconds=1),
        )
        await store.append(
            request.run_id,
            expected_revision=current.revision,
            event_type=RecoveryRunEventType.LAUNCH_PERMIT,
            payload=RecoveryRunEventPayload(launch_permit=launch),
            occurred_at=NOW + timedelta(seconds=2),
        )
        event_path = next(
            path
            for path, (data, _timestamp) in client.documents.items()
            if data["kind"] == FirestoreCasCollection.RECOVERY_RUN_EVENT.value
        )
        del client.documents[event_path]
        before = dict(client.documents)

        with pytest.raises(RecoveryRunCorruptState):
            await store.claim_launch(
                request.run_id,
                launch_permit_id=launch.launch_permit_id,
                claim_id="claim-after-journal-loss",
                action_request_sha256=launch.action_request_sha256,
                claimed_at=NOW + timedelta(seconds=3),
            )

        assert client.documents == before

    asyncio.run(exercise())


def test_firestore_store_rejects_tampered_successful_cas_response() -> None:
    request, _event, _launch, expected, _scope = make_recovery_run_examples()

    async def exercise() -> None:
        cas, _factory = _store(_Client())

        class TamperedResponseCas:
            async def read(self, collection, logical_id):
                return await cas.read(collection, logical_id)

            async def create_many(self, documents):
                return await cas.create_many(documents)

            async def rewrite_recovery_run(self, current, replacement):
                return await cas.rewrite_recovery_run(current, replacement)

            async def update_and_create_many(self, current, replacement, created):
                written = await cas.update_and_create_many(
                    current,
                    replacement,
                    created,
                )
                state = written[0]
                changed = build_firestore_cas_document(
                    collection=state.collection,
                    logical_id=state.document.logical_id,
                    revision=state.document.revision,
                    mutation_id="mutation-tampered-return",
                    canonical_payload=state.document.payload_bytes,
                )
                return (
                    FirestoreCasSnapshot(
                        collection=state.collection,
                        document_key=state.document_key,
                        document=changed,
                        update_time=state.update_time,
                    ),
                    *written[1:],
                )

        store = FirestoreRecoveryRunStore(TamperedResponseCas())
        created, _was_created = await store.create(
            request,
            expected.chain,
            created_at=NOW,
        )
        with pytest.raises(RecoveryRunCorruptState):
            await store.append(
                request.run_id,
                expected_revision=created.revision,
                event_type=RecoveryRunEventType.LIFECYCLE,
                payload=RecoveryRunEventPayload(lifecycle=RecoveryRunLifecycle.RUNNING),
                occurred_at=NOW + timedelta(seconds=1),
            )

        durable = await store.get(request.run_id)
        assert durable.lifecycle is RecoveryRunLifecycle.RUNNING

    asyncio.run(exercise())


def test_legacy_aggregate_is_read_and_atomically_migrated_on_next_append() -> None:
    request, _event, _launch, expected, _scope = make_recovery_run_examples()

    async def exercise() -> None:
        client = _Client()
        cas, _factory = _store(client)
        aggregate = create_recovery_run_aggregate(
            request,
            expected.chain,
            created_at=NOW,
        )
        legacy = build_firestore_cas_document(
            collection=FirestoreCasCollection.RECOVERY_RUN,
            logical_id=request.run_id,
            revision=expected.revision,
            mutation_id="mutation-legacy",
            canonical_payload=_canonical_verified_recovery_aggregate_bytes(aggregate),
        )
        await cas.create(legacy)
        store = FirestoreRecoveryRunStore(cas)

        assert await store.get(request.run_id) == expected
        updated = await store.append(
            request.run_id,
            expected_revision=expected.revision,
            event_type=RecoveryRunEventType.LIFECYCLE,
            payload=RecoveryRunEventPayload(lifecycle=RecoveryRunLifecycle.RUNNING),
            occurred_at=NOW + timedelta(seconds=1),
        )

        assert updated.revision == expected.revision + 1
        state_payloads = tuple(
            json.loads(data["canonical_payload"])
            for data, _timestamp in client.documents.values()
            if data["kind"] == FirestoreCasCollection.RECOVERY_RUN.value
        )
        assert len(state_payloads) == 1
        assert set(state_payloads[0]) == _CURRENT_STATE_FIELDS
        assert "events" not in state_payloads[0]
        assert (
            sum(
                data["kind"] == FirestoreCasCollection.RECOVERY_RUN_EVENT.value
                for data, _timestamp in client.documents.values()
            )
            == len(aggregate.events) + 1
        )
        assert await FirestoreRecoveryRunStore(cas).get(request.run_id) == updated

    asyncio.run(exercise())


def test_previous_split_state_is_reconstructed_and_migrated() -> None:
    request, _event, _launch, expected, _scope = make_recovery_run_examples()

    async def exercise() -> None:
        aggregate = create_recovery_run_aggregate(
            request,
            expected.chain,
            created_at=NOW,
        )
        records = recovery_run_module._legacy_journal_records(aggregate.events)
        previous_state = recovery_run_module._FirestoreRecoveryRunStateV1(
            schema_version="reconcile/firestore-recovery-state/v1",
            snapshot=aggregate.snapshot,
            journal_sha256=records[-1].journal_sha256,
        )
        state_document = build_firestore_cas_document(
            collection=FirestoreCasCollection.RECOVERY_RUN,
            logical_id=request.run_id,
            revision=aggregate.snapshot.revision,
            mutation_id="mutation-split-v1",
            canonical_payload=canonical_json_value_bytes(
                previous_state.model_dump(mode="json")
            ),
        )
        client = _Client()
        cas, _factory = _store(client)
        await cas.create_many(
            (
                state_document,
                *(
                    recovery_run_module._legacy_event_document(record)
                    for record in records
                ),
            )
        )
        store = FirestoreRecoveryRunStore(cas)

        assert await store.get(request.run_id) == expected
        updated = await store.append(
            request.run_id,
            expected_revision=expected.revision,
            event_type=RecoveryRunEventType.LIFECYCLE,
            payload=RecoveryRunEventPayload(lifecycle=RecoveryRunLifecycle.RUNNING),
            occurred_at=NOW + timedelta(seconds=1),
        )

        state_payload = next(
            json.loads(data["canonical_payload"])
            for data, _timestamp in client.documents.values()
            if data["kind"] == FirestoreCasCollection.RECOVERY_RUN.value
        )
        assert state_payload["schema_version"] == (
            recovery_run_module.FIRESTORE_RECOVERY_RUN_STATE_VERSION
        )
        assert updated.event_cursor == 3

    asyncio.run(exercise())


def test_compact_state_stays_bounded_as_large_event_projections_grow() -> None:
    request, _event, _launch, expected, _scope = make_recovery_run_examples()
    report_payload = make_report(Classification.COMMITTED).model_dump(mode="python")
    report_payload["limitations"] = tuple("x" * 4096 for _index in range(64))
    report = InvestigationReport.model_validate(report_payload)

    async def exercise() -> None:
        client = _Client()
        cas, _factory = _store(client)
        store = FirestoreRecoveryRunStore(cas)
        current, _was_created = await store.create(
            request,
            expected.chain,
            created_at=NOW,
        )
        for index in range(4):
            current = await store.append(
                request.run_id,
                expected_revision=current.revision,
                event_type=RecoveryRunEventType.EVIDENCE,
                payload=RecoveryRunEventPayload(report=report),
                occurred_at=NOW + timedelta(seconds=index + 1),
            )

        state_payload = next(
            data["canonical_payload"]
            for data, _timestamp in client.documents.values()
            if data["kind"] == FirestoreCasCollection.RECOVERY_RUN.value
        )
        event_payloads = tuple(
            data["canonical_payload"]
            for data, _timestamp in client.documents.values()
            if data["kind"] == FirestoreCasCollection.RECOVERY_RUN_EVENT.value
        )
        assert len(state_payload.encode()) < FIRESTORE_CAS_PAYLOAD_BYTE_CEILING
        assert all(
            len(payload.encode()) < FIRESTORE_CAS_PAYLOAD_BYTE_CEILING
            for payload in event_payloads
        )
        assert len(event_payloads) == 6
        assert await FirestoreRecoveryRunStore(cas).get(request.run_id) == current

    asyncio.run(exercise())


@pytest.mark.parametrize("event_count", (499, 512))
def test_large_legacy_journal_migrates_before_applying_the_next_transition(
    event_count: int,
) -> None:
    request, _event, _launch, expected, _scope = make_recovery_run_examples()
    payload = RecoveryRunEventPayload(
        hypothesis_disposition=RecoveryHypothesisDisposition.MODEL_UNAVAILABLE,
        note="fixed fallback selected",
    )

    async def exercise() -> None:
        aggregate = create_recovery_run_aggregate(
            request,
            expected.chain,
            created_at=NOW,
        )
        while len(aggregate.events) < event_count:
            aggregate = _append_decoded_recovery_event(
                aggregate,
                event_type=RecoveryRunEventType.HYPOTHESIS,
                payload=payload,
                occurred_at=NOW,
            )
        legacy_payload = _canonical_verified_recovery_aggregate_bytes(aggregate)
        assert len(legacy_payload) < FIRESTORE_CAS_PAYLOAD_BYTE_CEILING

        client = _Client()
        cas, _factory = _store(client)
        await cas.create(
            build_firestore_cas_document(
                collection=FirestoreCasCollection.RECOVERY_RUN,
                logical_id=request.run_id,
                revision=aggregate.snapshot.revision,
                mutation_id="mutation-large-legacy",
                canonical_payload=legacy_payload,
            )
        )
        store = FirestoreRecoveryRunStore(cas)

        if event_count == 512:
            with pytest.raises(RecoveryRunConflict):
                await store.append(
                    request.run_id,
                    expected_revision=aggregate.snapshot.revision,
                    event_type=RecoveryRunEventType.HYPOTHESIS,
                    payload=payload,
                    occurred_at=NOW,
                )
            expected_cursor = event_count
        else:
            updated = await store.append(
                request.run_id,
                expected_revision=aggregate.snapshot.revision,
                event_type=RecoveryRunEventType.HYPOTHESIS,
                payload=payload,
                occurred_at=NOW,
            )
            expected_cursor = event_count + 1
            assert updated.event_cursor == expected_cursor

        state_payload = next(
            json.loads(data["canonical_payload"])
            for data, _timestamp in client.documents.values()
            if data["kind"] == FirestoreCasCollection.RECOVERY_RUN.value
        )
        event_documents = tuple(
            data
            for data, _timestamp in client.documents.values()
            if data["kind"] == FirestoreCasCollection.RECOVERY_RUN_EVENT.value
        )
        assert set(state_payload) == _CURRENT_STATE_FIELDS
        assert len(event_documents) == expected_cursor
        assert (
            await FirestoreRecoveryRunStore(cas).get(request.run_id)
        ).event_cursor == expected_cursor

    asyncio.run(exercise())
