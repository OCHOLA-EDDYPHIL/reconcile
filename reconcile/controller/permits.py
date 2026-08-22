"""Controller-owned issuance and dispatch binding for single-use permits."""

from __future__ import annotations

import hashlib
from collections.abc import Callable, Mapping
from datetime import UTC, datetime
from uuid import uuid4

from pydantic import JsonValue

from reconcile.contracts import (
    ACTION_PERMIT_VERSION,
    ActionPermit,
    ActionPermitState,
    PermitAction,
    PermitCompletionOutcome,
    SemanticActionIdentity,
    TargetBinding,
    VerifiedCertificate,
    canonical_json_bytes,
    canonical_sha256,
    decode_contract,
)
from reconcile.contracts.base import canonical_json_value_bytes
from reconcile.evidence.recovery_rules import (
    CREATE_FIRESTORE_RELEASE_RECORD_PROFILE_VERSION,
    PROMOTE_CLOUD_RUN_TRAFFIC_PROFILE_VERSION,
    RECOVERY_ACTION_PROFILES,
    STAGE_CLOUD_RUN_REVISION_PROFILE_VERSION,
    validate_recovery_dispatch,
)
from reconcile.persistence.permits import (
    PERMIT_CLAIM_REQUEST_VERSION,
    PERMIT_COMPLETION_REQUEST_VERSION,
    ActionPermitStore,
    PermitClaimRequest,
    PermitCompletionRequest,
    action_permit_id,
    same_action_permit_authority,
)

_ALLOWED_TRANSITIONS = {
    (STAGE_CLOUD_RUN_REVISION_PROFILE_VERSION, PermitAction.CONTINUE): (
        PROMOTE_CLOUD_RUN_TRAFFIC_PROFILE_VERSION
    ),
    (PROMOTE_CLOUD_RUN_TRAFFIC_PROFILE_VERSION, PermitAction.CONTINUE): (
        CREATE_FIRESTORE_RELEASE_RECORD_PROFILE_VERSION
    ),
    (CREATE_FIRESTORE_RELEASE_RECORD_PROFILE_VERSION, PermitAction.RETRY): (
        CREATE_FIRESTORE_RELEASE_RECORD_PROFILE_VERSION
    ),
}


class PermitAuthorityError(ValueError):
    """A certificate or dispatch binding is outside the sealed permit policy."""


def _aware_utc(value: datetime) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise PermitAuthorityError("permit authority clock must be timezone-aware")
    return value.astimezone(UTC)


def _certificate(value: VerifiedCertificate) -> VerifiedCertificate:
    if type(value) is not VerifiedCertificate:
        raise TypeError("verified certificate must be exact")
    try:
        return decode_contract(canonical_json_bytes(value), VerifiedCertificate)
    except Exception as error:
        raise PermitAuthorityError("verified certificate is invalid") from error


def _semantic_action(value: SemanticActionIdentity) -> SemanticActionIdentity:
    if type(value) is not SemanticActionIdentity:
        raise TypeError("dispatch semantic action must be exact")
    try:
        return SemanticActionIdentity.model_validate_json(canonical_json_bytes(value))
    except Exception as error:
        raise PermitAuthorityError("dispatch semantic action is invalid") from error


def _target_profile_version(certificate: VerifiedCertificate) -> str:
    transition = certificate.transition
    if transition is None:
        raise PermitAuthorityError("certificate does not authorize a transition")
    expected = _ALLOWED_TRANSITIONS.get(
        (certificate.action_profile_version, transition.action)
    )
    if expected is None:
        raise PermitAuthorityError("certificate transition is outside permit policy")
    profiles = tuple(
        profile
        for profile in RECOVERY_ACTION_PROFILES
        if profile.profile_version == expected
        and profile.tool_name == transition.tool_name
        and profile.tool_version == transition.tool_version
    )
    if len(profiles) != 1:
        raise PermitAuthorityError("certificate transition profile is not exact")
    return profiles[0].profile_version


def action_permit_from_certificate(
    certificate: VerifiedCertificate,
) -> ActionPermit | None:
    """Derive the sole permitted action identity from a verified transition."""

    trusted = _certificate(certificate)
    transition = trusted.transition
    if transition is None:
        return None
    profile_version = _target_profile_version(trusted)
    return ActionPermit(
        schema_version=ACTION_PERMIT_VERSION,
        permit_id=action_permit_id(trusted.certificate_id, transition),
        certificate_id=trusted.certificate_id,
        certificate_sha256=canonical_sha256(trusted),
        chain_id=trusted.chain_id,
        source_node_id=transition.source_node_id,
        target_node_id=transition.target_node_id,
        semantic_action_sha256=transition.semantic_action_sha256,
        action=transition.action,
        action_profile_version=profile_version,
        action_policy_version=trusted.action_policy_version,
        tool_name=transition.tool_name,
        tool_version=transition.tool_version,
        arguments_sha256=transition.arguments_sha256,
        target_sha256=transition.target_sha256,
        precondition_sha256=transition.precondition_sha256,
        issued_at=trusted.issued_at,
        expires_at=trusted.expires_at,
        max_uses=1,
        state=ActionPermitState.ISSUED,
        revision=0,
    )


def dispatch_arguments_sha256(arguments: Mapping[str, JsonValue]) -> str:
    if not isinstance(arguments, Mapping):
        raise TypeError("dispatch arguments must be a mapping")
    return hashlib.sha256(canonical_json_value_bytes(dict(arguments))).hexdigest()


def dispatch_precondition_sha256(precondition: Mapping[str, JsonValue]) -> str:
    if not isinstance(precondition, Mapping):
        raise TypeError("dispatch precondition must be a mapping")
    return hashlib.sha256(canonical_json_value_bytes(dict(precondition))).hexdigest()


class PermitAuthority:
    """Issue and consume permits through one controller-owned store."""

    def __init__(
        self,
        store: ActionPermitStore,
        *,
        clock: Callable[[], datetime] | None = None,
        claim_id_factory: Callable[[], str] | None = None,
    ) -> None:
        if not isinstance(store, ActionPermitStore):
            raise TypeError("permit authority requires an action permit store")
        if clock is not None and not callable(clock):
            raise TypeError("permit authority clock must be callable")
        if claim_id_factory is not None and not callable(claim_id_factory):
            raise TypeError("permit claim identifier factory must be callable")
        self._store = store
        self._clock = clock or (lambda: datetime.now(UTC))
        self._claim_id_factory = claim_id_factory or (lambda: f"claim-{uuid4().hex}")

    def _now(self) -> datetime:
        return _aware_utc(self._clock())

    async def issue_permit(
        self,
        certificate: VerifiedCertificate,
    ) -> ActionPermit | None:
        permit = action_permit_from_certificate(certificate)
        if permit is None:
            return None
        now = self._now()
        if now < permit.issued_at or now >= permit.expires_at:
            raise PermitAuthorityError(
                "certificate is outside its permit issuance interval"
            )
        stored = await self._store.issue_permit(permit)
        try:
            valid = type(stored) is ActionPermit and same_action_permit_authority(
                stored,
                permit,
            )
        except (TypeError, ValueError):
            valid = False
        if not valid:
            raise PermitAuthorityError("permit store returned another authority")
        return stored

    async def claim_for_dispatch(
        self,
        *,
        permit_id: str,
        certificate: VerifiedCertificate,
        semantic_action: SemanticActionIdentity,
        tool_name: str,
        tool_version: str,
        arguments: Mapping[str, JsonValue],
        target: TargetBinding,
        precondition: Mapping[str, JsonValue],
    ) -> ActionPermit:
        trusted = _certificate(certificate)
        expected = action_permit_from_certificate(trusted)
        if expected is None:
            raise PermitAuthorityError("certificate does not authorize dispatch")
        if permit_id != expected.permit_id:
            raise PermitAuthorityError("permit identifier does not match certificate")
        persisted = await self._store.get_permit(permit_id)
        try:
            persisted_matches = type(
                persisted
            ) is ActionPermit and same_action_permit_authority(persisted, expected)
        except (TypeError, ValueError):
            persisted_matches = False
        if not persisted_matches:
            raise PermitAuthorityError(
                "durable permit does not match the certificate authority"
            )
        trusted_action = _semantic_action(semantic_action)
        try:
            isolated_arguments = dict(arguments)
            isolated_precondition = dict(precondition)
            profile = validate_recovery_dispatch(
                trusted_action,
                tool_name=tool_name,
                tool_version=tool_version,
                arguments=isolated_arguments,
                target=target,
                precondition=isolated_precondition,
            )
        except (TypeError, ValueError) as error:
            raise PermitAuthorityError(
                "dispatch does not match a sealed recovery action"
            ) from error
        arguments_sha256 = dispatch_arguments_sha256(isolated_arguments)
        precondition_sha256 = dispatch_precondition_sha256(isolated_precondition)
        if (
            profile.profile_version != expected.action_profile_version
            or trusted_action.semantic_action_sha256 != expected.semantic_action_sha256
            or arguments_sha256 != expected.arguments_sha256
            or canonical_sha256(target) != expected.target_sha256
            or precondition_sha256 != expected.precondition_sha256
        ):
            raise PermitAuthorityError(
                "dispatch does not match the certified transition"
            )
        claim_id = self._claim_id_factory()
        requested_at = self._now()
        request = PermitClaimRequest(
            schema_version=PERMIT_CLAIM_REQUEST_VERSION,
            permit_id=permit_id,
            claim_id=claim_id,
            issued_permit_sha256=canonical_sha256(persisted),
            certificate_id=persisted.certificate_id,
            certificate_sha256=persisted.certificate_sha256,
            chain_id=persisted.chain_id,
            source_node_id=persisted.source_node_id,
            target_node_id=persisted.target_node_id,
            semantic_action_sha256=persisted.semantic_action_sha256,
            action_profile_version=persisted.action_profile_version,
            action_policy_version=persisted.action_policy_version,
            tool_name=tool_name,
            tool_version=tool_version,
            arguments_sha256=arguments_sha256,
            target_sha256=canonical_sha256(target),
            precondition_sha256=precondition_sha256,
            requested_at=requested_at,
        )
        claimed = await self._store.claim_permit(request)
        expected_claimed = ActionPermit.model_validate(
            persisted.model_copy(
                update={
                    "state": ActionPermitState.CLAIMED,
                    "revision": 1,
                    "claim_id": claim_id,
                    "claimed_at": requested_at,
                }
            )
        )
        if type(claimed) is not ActionPermit or claimed != expected_claimed:
            raise PermitAuthorityError("permit store returned an invalid claim")
        checked_at = self._now()
        if checked_at < requested_at or checked_at >= claimed.expires_at:
            raise PermitAuthorityError(
                "durably claimed permit requires outcome reconciliation"
            )
        return claimed

    async def complete_dispatch(
        self,
        claimed: ActionPermit,
        outcome: PermitCompletionOutcome,
    ) -> ActionPermit:
        if (
            type(claimed) is not ActionPermit
            or claimed.state is not ActionPermitState.CLAIMED
            or claimed.claim_id is None
        ):
            raise PermitAuthorityError("an exact claimed permit is required")
        if type(outcome) is not PermitCompletionOutcome:
            raise TypeError("permit completion outcome must be exact")
        completed_at = self._now()
        request = PermitCompletionRequest(
            schema_version=PERMIT_COMPLETION_REQUEST_VERSION,
            permit_id=claimed.permit_id,
            claim_id=claimed.claim_id,
            claimed_permit_sha256=canonical_sha256(claimed),
            outcome=outcome,
            completed_at=completed_at,
        )
        completed = await self._store.complete_permit(request)
        expected_completed = ActionPermit.model_validate(
            claimed.model_copy(
                update={
                    "state": ActionPermitState.COMPLETED,
                    "revision": 2,
                    "completed_at": completed_at,
                    "completion_outcome": outcome,
                }
            )
        )
        if type(completed) is not ActionPermit or completed != expected_completed:
            raise PermitAuthorityError("permit store returned an invalid completion")
        return completed


__all__ = [
    "PermitAuthority",
    "PermitAuthorityError",
    "action_permit_from_certificate",
    "dispatch_arguments_sha256",
    "dispatch_precondition_sha256",
]
