"""Final Firestore action hashing and ambiguous-create behavior."""

from __future__ import annotations

import asyncio

from reconcile.contracts import (
    RECOVERY_ACTION_SCOPE_VERSION,
    PermitAction,
    RecoveryActionScope,
    RecoveryAuthorityKind,
    RecoveryDispatchOutcome,
)
from reconcile.hosted.firestore_release_action import (
    FIRESTORE_RELEASE_ACTION_REQUEST_VERSION,
    FirestoreReleaseActionRequest,
    _create_release_record,
    firestore_release_action_request_payload,
    firestore_release_action_request_sha256,
)
from tests.unit.hosted.test_firestore_release import _Client, _record, _target


def _request() -> FirestoreReleaseActionRequest:
    scope = RecoveryActionScope(
        schema_version=RECOVERY_ACTION_SCOPE_VERSION,
        authority_kind=RecoveryAuthorityKind.ACTION_PERMIT,
        run_id="release-run-7",
        source_node_id="promote",
        target_node_id="record",
        semantic_action_sha256="b" * 64,
        action_request_sha256="0" * 64,
        authority_id="permit-release-7",
        authority_sha256="c" * 64,
        claim_id="claim-release-7",
        permit_action=PermitAction.CONTINUE,
        certificate_id="certificate-release-7",
        certificate_sha256="d" * 64,
    )
    request = FirestoreReleaseActionRequest(
        schema_version=FIRESTORE_RELEASE_ACTION_REQUEST_VERSION,
        request_id="request-release-7",
        action="record",
        cloud_run_revision="reconcile-canary-r-0123456789abcdef",
        payload_sha256="a" * 64,
        release_id="release-7",
        suppress_before_dispatch=False,
        scope=scope,
    )
    return request.model_copy(
        update={
            "scope": scope.model_copy(
                update={
                    "action_request_sha256": (
                        firestore_release_action_request_sha256(request)
                    )
                }
            )
        }
    )


def test_firestore_action_hash_is_exactly_the_prepared_provider_payload() -> None:
    request = _request()

    assert firestore_release_action_request_payload(request) == {
        "action": "record",
        "cloud_run_revision": "reconcile-canary-r-0123456789abcdef",
        "payload_sha256": "a" * 64,
        "release_id": "release-7",
        "suppress_before_dispatch": False,
    }
    assert request.scope.action_request_sha256 == (
        firestore_release_action_request_sha256(request)
    )


def test_action_rereads_after_the_target_cannot_resolve_a_lost_create_ack() -> None:
    client = _Client()
    reference = client.document("releases", "release-7")
    original_get = reference.get
    post_create_read_failures = 0

    async def lost_ack_create(data, **_kwargs):
        nonlocal post_create_read_failures
        reference.data = dict(data)
        reference.update_time = _record().created_at
        post_create_read_failures = 1
        raise RuntimeError("lost acknowledgement")

    async def fail_first_post_create_read(**kwargs):
        nonlocal post_create_read_failures
        if post_create_read_failures:
            post_create_read_failures -= 1
            raise RuntimeError("transient read failure")
        return await original_get(**kwargs)

    reference.create = lost_ack_create
    reference.get = fail_first_post_create_read

    outcome = asyncio.run(_create_release_record(_target(client), _record()))

    assert outcome is RecoveryDispatchOutcome.SUCCEEDED
    assert post_create_read_failures == 0
