"""Recovery aggregates use Firestore compare-and-swap rather than local locks."""

from __future__ import annotations

import asyncio
from datetime import timedelta

import pytest

from reconcile.contracts import (
    RecoveryRunEventPayload,
    RecoveryRunEventType,
    RecoveryRunLifecycle,
)
from reconcile.hosted.firestore_recovery_runs import FirestoreRecoveryRunStore
from reconcile.persistence import RecoveryRunConflict
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
