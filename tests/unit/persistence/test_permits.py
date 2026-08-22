"""SQLite single-use permit authority behavior."""

from __future__ import annotations

import asyncio
import sqlite3
from datetime import timedelta

import pytest

from reconcile.contracts import (
    ActionPermit,
    ActionPermitState,
    PermitCompletionOutcome,
    canonical_sha256,
)
from reconcile.controller.permits import PermitAuthority, action_permit_from_certificate
from reconcile.persistence.permits import (
    PERMIT_CLAIM_REQUEST_VERSION,
    PERMIT_COMPLETION_REQUEST_VERSION,
    PermitAuditKind,
    PermitClaimDenied,
    PermitClaimRequest,
    PermitCompletionDenied,
    PermitCompletionRequest,
    PermitCorruptState,
    PermitDenialReason,
)
from reconcile.persistence.sqlite_runtime import SqliteDurableRuntimeStore
from tests._permit_support import NOW, make_permit_certificate

pytestmark = pytest.mark.unit


def _store(tmp_path, name: str = "runtime.sqlite3") -> SqliteDurableRuntimeStore:
    return SqliteDurableRuntimeStore(tmp_path / name)


def _claim_request(permit: ActionPermit) -> PermitClaimRequest:
    return PermitClaimRequest(
        schema_version=PERMIT_CLAIM_REQUEST_VERSION,
        permit_id=permit.permit_id,
        claim_id="claim-exact",
        issued_permit_sha256=canonical_sha256(permit),
        certificate_id=permit.certificate_id,
        certificate_sha256=permit.certificate_sha256,
        chain_id=permit.chain_id,
        source_node_id=permit.source_node_id,
        target_node_id=permit.target_node_id,
        semantic_action_sha256=permit.semantic_action_sha256,
        action_profile_version=permit.action_profile_version,
        action_policy_version=permit.action_policy_version,
        tool_name=permit.tool_name,
        tool_version=permit.tool_version,
        arguments_sha256=permit.arguments_sha256,
        target_sha256=permit.target_sha256,
        precondition_sha256=permit.precondition_sha256,
        requested_at=NOW + timedelta(seconds=7),
    )


def test_certificate_derives_one_stable_exact_permit_and_no_transition_issues_none(
    tmp_path,
) -> None:
    async def scenario() -> None:
        certificate, _semantic_action, _arguments, _precondition = (
            make_permit_certificate()
        )
        first = action_permit_from_certificate(certificate)
        second = action_permit_from_certificate(certificate)
        assert first == second
        assert first is not None
        assert first.action_profile_version == "promote-cloud-run-traffic-profile-v1"

        store = _store(tmp_path)
        authority = PermitAuthority(
            store,
            clock=lambda: NOW + timedelta(seconds=6),
        )
        assert await authority.issue_permit(certificate) == first
        assert await authority.issue_permit(certificate) == first
        assert len(await store.permit_audit_events(first.permit_id)) == 1
        no_transition = certificate.model_copy(update={"transition": None})
        assert await authority.issue_permit(no_transition) is None

    asyncio.run(scenario())


def test_sqlite_thirty_two_concurrent_claims_have_exactly_one_winner(
    tmp_path,
) -> None:
    async def scenario() -> None:
        certificate, semantic_action, arguments, precondition = (
            make_permit_certificate()
        )
        store = _store(tmp_path)
        issuer = PermitAuthority(
            store,
            clock=lambda: NOW + timedelta(seconds=6),
        )
        permit = await issuer.issue_permit(certificate)
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
                semantic_action=semantic_action,
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
        assert (await store.get_permit(permit.permit_id)).state is (
            ActionPermitState.CLAIMED
        )
        events = await store.permit_audit_events(permit.permit_id)
        assert events[0].kind is PermitAuditKind.ISSUED
        assert sum(event.kind is PermitAuditKind.CLAIMED for event in events) == 1
        assert sum(event.kind is PermitAuditKind.BLOCKED for event in events) == 31

    asyncio.run(scenario())


@pytest.mark.parametrize(
    ("outcome", "audit_kind"),
    (
        (PermitCompletionOutcome.SUCCEEDED, PermitAuditKind.COMPLETED),
        (PermitCompletionOutcome.REJECTED, PermitAuditKind.REJECTED),
        (PermitCompletionOutcome.OUTCOME_UNKNOWN, PermitAuditKind.OUTCOME_UNKNOWN),
    ),
)
def test_sqlite_completion_is_terminal_and_audited(
    tmp_path,
    outcome: PermitCompletionOutcome,
    audit_kind: PermitAuditKind,
) -> None:
    async def scenario() -> None:
        certificate, semantic_action, arguments, precondition = (
            make_permit_certificate()
        )
        store = _store(tmp_path, f"{outcome.value}.sqlite3")
        issuer = PermitAuthority(
            store,
            clock=lambda: NOW + timedelta(seconds=6),
        )
        permit = await issuer.issue_permit(certificate)
        assert permit is not None
        claimer = PermitAuthority(
            store,
            clock=lambda: NOW + timedelta(seconds=7),
            claim_id_factory=lambda: "claim-terminal",
        )
        claimed = await claimer.claim_for_dispatch(
            permit_id=permit.permit_id,
            certificate=certificate,
            semantic_action=semantic_action,
            tool_name=permit.tool_name,
            tool_version=permit.tool_version,
            arguments=arguments,
            target=certificate.target,
            precondition=precondition,
        )
        completer = PermitAuthority(
            store,
            clock=lambda: NOW + timedelta(seconds=8),
        )
        completed = await completer.complete_dispatch(claimed, outcome)
        assert completed.state is ActionPermitState.COMPLETED
        assert completed.completion_outcome is outcome
        assert (await store.permit_audit_events(permit.permit_id))[-1].kind is (
            audit_kind
        )

        replay_authority = PermitAuthority(
            store,
            clock=lambda: NOW + timedelta(seconds=9),
            claim_id_factory=lambda: "claim-terminal-replay",
        )
        with pytest.raises(PermitClaimDenied) as replay:
            await replay_authority.claim_for_dispatch(
                permit_id=permit.permit_id,
                certificate=certificate,
                semantic_action=semantic_action,
                tool_name=permit.tool_name,
                tool_version=permit.tool_version,
                arguments=arguments,
                target=certificate.target,
                precondition=precondition,
            )
        assert replay.value.reason is PermitDenialReason.ALREADY_COMPLETED

    asyncio.run(scenario())


def test_regressed_clocks_never_regress_audit_timestamps(tmp_path) -> None:
    async def scenario() -> None:
        certificate, semantic_action, arguments, precondition = (
            make_permit_certificate()
        )
        store = _store(tmp_path)
        permit = await PermitAuthority(
            store,
            clock=lambda: NOW + timedelta(seconds=6),
        ).issue_permit(certificate)
        assert permit is not None
        claimed = await PermitAuthority(
            store,
            clock=lambda: NOW + timedelta(seconds=7),
            claim_id_factory=lambda: "claim-monotonic",
        ).claim_for_dispatch(
            permit_id=permit.permit_id,
            certificate=certificate,
            semantic_action=semantic_action,
            tool_name=permit.tool_name,
            tool_version=permit.tool_version,
            arguments=arguments,
            target=certificate.target,
            precondition=precondition,
        )

        regressed_claim = PermitClaimRequest.model_validate(
            _claim_request(permit).model_copy(
                update={
                    "claim_id": "claim-regressed",
                    "requested_at": NOW + timedelta(seconds=6),
                }
            )
        )
        with pytest.raises(PermitClaimDenied) as claim_denied:
            await store.claim_permit(regressed_claim)
        assert claim_denied.value.reason is PermitDenialReason.NON_MONOTONIC_TIME

        regressed_completion = PermitCompletionRequest(
            schema_version=PERMIT_COMPLETION_REQUEST_VERSION,
            permit_id=claimed.permit_id,
            claim_id=claimed.claim_id,
            claimed_permit_sha256=canonical_sha256(claimed),
            outcome=PermitCompletionOutcome.SUCCEEDED,
            completed_at=NOW + timedelta(seconds=6),
        )
        with pytest.raises(PermitCompletionDenied) as completion_denied:
            await store.complete_permit(regressed_completion)
        assert completion_denied.value.reason is (PermitDenialReason.NON_MONOTONIC_TIME)

        events = await store.permit_audit_events(permit.permit_id)
        occurred_at = [event.occurred_at for event in events]
        assert occurred_at == sorted(occurred_at)
        assert occurred_at[-2:] == [
            NOW + timedelta(seconds=7),
            NOW + timedelta(seconds=7),
        ]
        assert (await store.get_permit(permit.permit_id)).state is (
            ActionPermitState.CLAIMED
        )

    asyncio.run(scenario())


def test_expired_and_modified_permits_fail_closed_with_audit(tmp_path) -> None:
    async def scenario() -> None:
        certificate, semantic_action, arguments, precondition = (
            make_permit_certificate()
        )

        expired_store = _store(tmp_path, "expired.sqlite3")
        issued = action_permit_from_certificate(certificate)
        assert issued is not None
        await expired_store.issue_permit(issued)
        expired_authority = PermitAuthority(
            expired_store,
            clock=lambda: certificate.expires_at,
            claim_id_factory=lambda: "claim-expired",
        )
        with pytest.raises(PermitClaimDenied) as expired:
            await expired_authority.claim_for_dispatch(
                permit_id=issued.permit_id,
                certificate=certificate,
                semantic_action=semantic_action,
                tool_name=issued.tool_name,
                tool_version=issued.tool_version,
                arguments=arguments,
                target=certificate.target,
                precondition=precondition,
            )
        assert expired.value.reason is PermitDenialReason.EXPIRED
        assert (await expired_store.get_permit(issued.permit_id)).state is (
            ActionPermitState.EXPIRED
        )
        assert (await expired_store.permit_audit_events(issued.permit_id))[-1].kind is (
            PermitAuditKind.EXPIRED
        )

        modified_store = _store(tmp_path, "modified.sqlite3")
        modified = ActionPermit.model_validate(
            issued.model_copy(update={"action_policy_version": "modified-policy-v1"})
        )
        await modified_store.issue_permit(modified)
        modified_authority = PermitAuthority(
            modified_store,
            clock=lambda: NOW + timedelta(seconds=7),
            claim_id_factory=lambda: "claim-modified",
        )
        with pytest.raises(PermitClaimDenied) as mismatch:
            await modified_authority.claim_for_dispatch(
                permit_id=issued.permit_id,
                certificate=certificate,
                semantic_action=semantic_action,
                tool_name=issued.tool_name,
                tool_version=issued.tool_version,
                arguments=arguments,
                target=certificate.target,
                precondition=precondition,
            )
        assert mismatch.value.reason is PermitDenialReason.BINDING_MISMATCH
        assert (await modified_store.permit_audit_events(issued.permit_id))[
            -1
        ].kind is (PermitAuditKind.BLOCKED)

    asyncio.run(scenario())


@pytest.mark.parametrize(
    ("field", "replacement"),
    (
        ("issued_permit_sha256", "0" * 64),
        ("certificate_id", "certificate-other"),
        ("certificate_sha256", "1" * 64),
        ("chain_id", "chain-other"),
        ("source_node_id", "source-other"),
        ("target_node_id", "target-other"),
        ("semantic_action_sha256", "2" * 64),
        ("action_profile_version", "profile-other"),
        ("action_policy_version", "policy-other"),
        ("tool_name", "tool-other"),
        ("tool_version", "2.0.0"),
        ("arguments_sha256", "3" * 64),
        ("target_sha256", "4" * 64),
        ("precondition_sha256", "5" * 64),
    ),
)
def test_every_dispatch_binding_must_match_before_claim(
    tmp_path,
    field: str,
    replacement: str,
) -> None:
    async def scenario() -> None:
        certificate, _semantic_action, _arguments, _precondition = (
            make_permit_certificate()
        )
        permit = action_permit_from_certificate(certificate)
        assert permit is not None
        store = _store(tmp_path)
        await store.issue_permit(permit)
        request = PermitClaimRequest.model_validate(
            _claim_request(permit).model_copy(update={field: replacement})
        )

        with pytest.raises(PermitClaimDenied) as denied:
            await store.claim_permit(request)
        assert denied.value.reason is PermitDenialReason.BINDING_MISMATCH
        assert (await store.get_permit(permit.permit_id)).state is (
            ActionPermitState.ISSUED
        )
        assert (await store.permit_audit_events(permit.permit_id))[-1].kind is (
            PermitAuditKind.BLOCKED
        )

    asyncio.run(scenario())


def test_claim_survives_process_boundary_and_corruption_fails_closed(tmp_path) -> None:
    async def scenario() -> None:
        certificate, semantic_action, arguments, precondition = (
            make_permit_certificate()
        )
        database = tmp_path / "runtime.sqlite3"
        store = SqliteDurableRuntimeStore(database)
        issuer = PermitAuthority(
            store,
            clock=lambda: NOW + timedelta(seconds=6),
        )
        permit = await issuer.issue_permit(certificate)
        assert permit is not None
        first_process = PermitAuthority(
            store,
            clock=lambda: NOW + timedelta(seconds=7),
            claim_id_factory=lambda: "claim-before-crash",
        )
        await first_process.claim_for_dispatch(
            permit_id=permit.permit_id,
            certificate=certificate,
            semantic_action=semantic_action,
            tool_name=permit.tool_name,
            tool_version=permit.tool_version,
            arguments=arguments,
            target=certificate.target,
            precondition=precondition,
        )

        restarted = SqliteDurableRuntimeStore(database)
        second_process = PermitAuthority(
            restarted,
            clock=lambda: NOW + timedelta(seconds=8),
            claim_id_factory=lambda: "claim-after-crash",
        )
        with pytest.raises(PermitClaimDenied) as replay:
            await second_process.claim_for_dispatch(
                permit_id=permit.permit_id,
                certificate=certificate,
                semantic_action=semantic_action,
                tool_name=permit.tool_name,
                tool_version=permit.tool_version,
                arguments=arguments,
                target=certificate.target,
                precondition=precondition,
            )
        assert replay.value.reason is PermitDenialReason.ALREADY_CLAIMED

        with sqlite3.connect(database) as connection:
            connection.execute(
                "UPDATE action_permits SET state = 'ISSUED' WHERE permit_id = ?",
                (permit.permit_id,),
            )
        with pytest.raises(PermitCorruptState):
            await restarted.get_permit(permit.permit_id)

    asyncio.run(scenario())
