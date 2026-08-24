"""Recovery aggregates use Firestore compare-and-swap rather than local locks."""

from __future__ import annotations

import asyncio
import json
from datetime import timedelta

import pytest

import reconcile.hosted.firestore_recovery_runs as recovery_run_module
from reconcile.contracts import (
    RecoveryRunEventPayload,
    RecoveryRunEventType,
    RecoveryRunLifecycle,
)
from reconcile.contracts.base import canonical_json_value_bytes
from reconcile.hosted.firestore_cas import (
    FirestoreCasCollection,
    FirestoreCasSnapshot,
    build_firestore_cas_document,
)
from reconcile.hosted.firestore_recovery_runs import FirestoreRecoveryRunStore
from reconcile.persistence import RecoveryRunConflict, RecoveryRunCorruptState
from tests.contract._factories import NOW, make_recovery_run_examples
from tests.unit.hosted.test_firestore_cas import _Client, _store

pytestmark = pytest.mark.unit


def test_firestore_recovery_store_preserves_cas_revision_and_event_order() -> None:
    request, _event, _launch, expected, _scope = make_recovery_run_examples()

    async def exercise() -> None:
        cas, _factory = _store(_Client())
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

    asyncio.run(exercise())


def test_firestore_cache_revalidates_external_writes_tampering_and_restart(
    monkeypatch,
) -> None:
    request, _event, _launch, expected, _scope = make_recovery_run_examples()
    client = _Client()
    cas, _factory = _store(client)
    decoded_payloads: list[bytes] = []
    decode = recovery_run_module._decode

    def counted_decode(snapshot):
        decoded_payloads.append(snapshot.document.payload_bytes)
        return decode(snapshot)

    monkeypatch.setattr(recovery_run_module, "_decode", counted_decode)

    async def exercise() -> None:
        store = FirestoreRecoveryRunStore(cas)
        created, was_created = await store.create(
            request,
            expected.chain,
            created_at=NOW,
        )
        assert was_created is True
        assert decoded_payloads == []
        created.chain.nodes[0].semantic_action.semantic_arguments["release_id"] = (
            "caller-mutation"
        )
        cached = await store.get(request.run_id)
        assert cached == expected
        cached.chain.nodes[0].semantic_action.semantic_arguments["release_id"] = (
            "second-caller-mutation"
        )
        assert await store.get(request.run_id) == expected
        assert decoded_payloads == []

        reopened = FirestoreRecoveryRunStore(cas)
        assert await reopened.get(request.run_id) == expected
        assert len(decoded_payloads) == 1
        assert await reopened.get(request.run_id) == expected
        assert len(decoded_payloads) == 1

        updated = await reopened.append(
            request.run_id,
            expected_revision=expected.revision,
            event_type=RecoveryRunEventType.LIFECYCLE,
            payload=RecoveryRunEventPayload(lifecycle=RecoveryRunLifecycle.RUNNING),
            occurred_at=NOW + timedelta(seconds=1),
        )
        assert len(decoded_payloads) == 1
        assert await store.get(request.run_id) == updated
        assert len(decoded_payloads) == 2
        assert await store.get(request.run_id) == updated
        assert len(decoded_payloads) == 2

        path, (data, _update_time) = next(iter(client.documents.items()))
        aggregate = json.loads(data["canonical_payload"])
        aggregate["events"] = aggregate["events"][:-1]
        document = build_firestore_cas_document(
            collection=FirestoreCasCollection.RECOVERY_RUN,
            logical_id=request.run_id,
            revision=data["revision"],
            mutation_id="mutation-externally-tampered",
            canonical_payload=canonical_json_value_bytes(aggregate),
        )
        client.documents[path] = (document.model_dump(mode="json"), client.clock)
        client.clock += timedelta(microseconds=1)

        with pytest.raises(RecoveryRunCorruptState):
            await store.get(request.run_id)
        assert len(decoded_payloads) == 3

    asyncio.run(exercise())


def test_firestore_cache_rejects_tampered_successful_cas_response() -> None:
    request, _event, _launch, expected, _scope = make_recovery_run_examples()

    async def exercise() -> None:
        cas, _factory = _store(_Client())

        class TamperedResponseCas:
            async def read(self, collection, logical_id):
                return await cas.read(collection, logical_id)

            async def create(self, document):
                return await cas.create(document)

            async def update(self, current, replacement):
                written = await cas.update(current, replacement)
                changed = build_firestore_cas_document(
                    collection=written.collection,
                    logical_id=written.document.logical_id,
                    revision=written.document.revision,
                    mutation_id="mutation-tampered-return",
                    canonical_payload=written.document.payload_bytes,
                )
                return FirestoreCasSnapshot(
                    collection=written.collection,
                    document_key=written.document_key,
                    document=changed,
                    update_time=written.update_time,
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
