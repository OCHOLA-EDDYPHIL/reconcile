"""Durable single-use permit transitions and persistence protocol."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum
from typing import Literal, Protocol, runtime_checkable

from pydantic import Field, model_validator

from reconcile.contracts import (
    ActionPermit,
    ActionPermitState,
    PermitCompletionOutcome,
    canonical_sha256,
)
from reconcile.contracts.base import (
    AwareDatetime,
    Identifier,
    Sha256Digest,
    StrictModel,
)

PERMIT_AUDIT_EVENT_VERSION = "reconcile/permit-audit-event/v1"
PERMIT_CLAIM_REQUEST_VERSION = "reconcile/permit-claim-request/v1"
PERMIT_COMPLETION_REQUEST_VERSION = "reconcile/permit-completion-request/v1"


class PermitAuditKind(StrEnum):
    ISSUED = "ISSUED"
    BLOCKED = "BLOCKED"
    CLAIMED = "CLAIMED"
    COMPLETED = "COMPLETED"
    REJECTED = "REJECTED"
    EXPIRED = "EXPIRED"
    OUTCOME_UNKNOWN = "OUTCOME_UNKNOWN"


class PermitDenialReason(StrEnum):
    BINDING_MISMATCH = "BINDING_MISMATCH"
    NOT_YET_VALID = "NOT_YET_VALID"
    EXPIRED = "EXPIRED"
    ALREADY_CLAIMED = "ALREADY_CLAIMED"
    ALREADY_COMPLETED = "ALREADY_COMPLETED"


class PermitAuditEvent(StrictModel):
    schema_version: Literal[PERMIT_AUDIT_EVENT_VERSION]
    event_id: Identifier
    permit_id: Identifier
    sequence: int = Field(ge=1, le=2**63 - 1)
    kind: PermitAuditKind
    permit_revision: int = Field(ge=0, le=2**63 - 1)
    permit_sha256: Sha256Digest
    occurred_at: AwareDatetime
    claim_id: Identifier | None = None
    denial_reason: PermitDenialReason | None = None
    completion_outcome: PermitCompletionOutcome | None = None

    @model_validator(mode="after")
    def validate_kind(self) -> PermitAuditEvent:
        if self.kind is PermitAuditKind.ISSUED:
            valid = (
                self.permit_revision == 0
                and self.claim_id is None
                and self.denial_reason is None
                and self.completion_outcome is None
            )
        elif self.kind is PermitAuditKind.BLOCKED:
            valid = (
                self.claim_id is not None
                and self.denial_reason is not None
                and self.denial_reason is not PermitDenialReason.EXPIRED
                and self.completion_outcome is None
            )
        elif self.kind is PermitAuditKind.CLAIMED:
            valid = (
                self.permit_revision == 1
                and self.claim_id is not None
                and self.denial_reason is None
                and self.completion_outcome is None
            )
        elif self.kind is PermitAuditKind.EXPIRED:
            valid = (
                self.permit_revision == 1
                and self.claim_id is not None
                and self.denial_reason is PermitDenialReason.EXPIRED
                and self.completion_outcome is None
            )
        else:
            expected = {
                PermitAuditKind.COMPLETED: PermitCompletionOutcome.SUCCEEDED,
                PermitAuditKind.REJECTED: PermitCompletionOutcome.REJECTED,
                PermitAuditKind.OUTCOME_UNKNOWN: (
                    PermitCompletionOutcome.OUTCOME_UNKNOWN
                ),
            }[self.kind]
            valid = (
                self.permit_revision == 2
                and self.claim_id is not None
                and self.denial_reason is None
                and self.completion_outcome is expected
            )
        if not valid:
            raise ValueError("permit audit fields do not match the event kind")
        return self


class PermitClaimRequest(StrictModel):
    schema_version: Literal[PERMIT_CLAIM_REQUEST_VERSION]
    permit_id: Identifier
    claim_id: Identifier
    issued_permit_sha256: Sha256Digest
    certificate_id: Identifier
    certificate_sha256: Sha256Digest
    chain_id: Identifier
    source_node_id: Identifier
    target_node_id: Identifier
    semantic_action_sha256: Sha256Digest
    action_profile_version: Identifier
    action_policy_version: Identifier
    tool_name: Identifier
    tool_version: Identifier
    arguments_sha256: Sha256Digest
    target_sha256: Sha256Digest
    precondition_sha256: Sha256Digest
    requested_at: AwareDatetime


class PermitCompletionRequest(StrictModel):
    schema_version: Literal[PERMIT_COMPLETION_REQUEST_VERSION]
    permit_id: Identifier
    claim_id: Identifier
    claimed_permit_sha256: Sha256Digest
    outcome: PermitCompletionOutcome
    completed_at: AwareDatetime


class PermitStoreError(RuntimeError):
    """Base class for sanitized permit persistence failures."""


class PermitNotFound(PermitStoreError):
    def __init__(self, permit_id: str) -> None:
        self.permit_id = permit_id
        super().__init__("action permit was not found")


class PermitConflict(PermitStoreError):
    def __init__(self, permit_id: str) -> None:
        self.permit_id = permit_id
        super().__init__("action permit conflicts with durable state")


class PermitCorruptState(PermitStoreError):
    def __init__(self, permit_id: str | None = None) -> None:
        self.permit_id = permit_id
        super().__init__("action permit durable state is corrupt")


class PermitStoreUnavailable(PermitStoreError):
    def __init__(self) -> None:
        super().__init__("action permit store is unavailable")


class PermitStoreOutcomeUnknown(PermitStoreError):
    def __init__(self) -> None:
        super().__init__("action permit store outcome is unknown")


class PermitClaimDenied(PermitStoreError):
    def __init__(self, permit_id: str, reason: PermitDenialReason) -> None:
        self.permit_id = permit_id
        self.reason = reason
        super().__init__(f"action permit claim denied: {reason.value.lower()}")


class PermitCompletionDenied(PermitStoreError):
    def __init__(self, permit_id: str, reason: PermitDenialReason) -> None:
        self.permit_id = permit_id
        self.reason = reason
        super().__init__(f"action permit completion denied: {reason.value.lower()}")


@runtime_checkable
class ActionPermitStore(Protocol):
    async def issue_permit(self, permit: ActionPermit) -> ActionPermit: ...

    async def get_permit(self, permit_id: str) -> ActionPermit: ...

    async def claim_permit(self, request: PermitClaimRequest) -> ActionPermit: ...

    async def complete_permit(
        self,
        request: PermitCompletionRequest,
    ) -> ActionPermit: ...

    async def permit_audit_events(
        self,
        permit_id: str,
    ) -> tuple[PermitAuditEvent, ...]: ...


@dataclass(frozen=True, slots=True)
class PermitMutation:
    permit: ActionPermit
    event: PermitAuditEvent
    denial_reason: PermitDenialReason | None = None


def _event(
    permit: ActionPermit,
    *,
    sequence: int,
    kind: PermitAuditKind,
    occurred_at: datetime,
    claim_id: str | None = None,
    denial_reason: PermitDenialReason | None = None,
    completion_outcome: PermitCompletionOutcome | None = None,
) -> PermitAuditEvent:
    return PermitAuditEvent(
        schema_version=PERMIT_AUDIT_EVENT_VERSION,
        event_id=f"permit-audit-{sequence}",
        permit_id=permit.permit_id,
        sequence=sequence,
        kind=kind,
        permit_revision=permit.revision,
        permit_sha256=canonical_sha256(permit),
        occurred_at=occurred_at,
        claim_id=claim_id,
        denial_reason=denial_reason,
        completion_outcome=completion_outcome,
    )


def issued_audit_event(permit: ActionPermit) -> PermitAuditEvent:
    if type(permit) is not ActionPermit or permit.state is not ActionPermitState.ISSUED:
        raise TypeError("an exact issued action permit is required")
    return _event(
        permit,
        sequence=1,
        kind=PermitAuditKind.ISSUED,
        occurred_at=permit.issued_at,
    )


def validate_permit_audit_history(
    permit: ActionPermit,
    events: tuple[PermitAuditEvent, ...],
) -> None:
    """Validate that append-only events reproduce the current permit lifecycle."""

    if type(permit) is not ActionPermit or type(events) is not tuple:
        raise TypeError("exact permit audit history inputs are required")
    issued = ActionPermit.model_validate(
        permit.model_copy(
            update={
                "state": ActionPermitState.ISSUED,
                "revision": 0,
                "claim_id": None,
                "claimed_at": None,
                "completed_at": None,
                "completion_outcome": None,
                "expired_at": None,
            }
        )
    )
    if not events or events[0] != issued_audit_event(issued):
        raise ValueError("permit audit history does not begin at issuance")
    current = issued
    for sequence, event in enumerate(events, 1):
        if (
            type(event) is not PermitAuditEvent
            or event.permit_id != permit.permit_id
            or event.sequence != sequence
            or event.event_id != f"permit-audit-{sequence}"
        ):
            raise ValueError("permit audit sequence is invalid")
        if sequence == 1:
            continue
        if event.kind is PermitAuditKind.BLOCKED:
            replacement = current
        elif (
            event.kind is PermitAuditKind.CLAIMED
            and current.state is ActionPermitState.ISSUED
            and event.claim_id is not None
        ):
            replacement = ActionPermit.model_validate(
                current.model_copy(
                    update={
                        "state": ActionPermitState.CLAIMED,
                        "revision": 1,
                        "claim_id": event.claim_id,
                        "claimed_at": event.occurred_at,
                    }
                )
            )
        elif (
            event.kind is PermitAuditKind.EXPIRED
            and current.state is ActionPermitState.ISSUED
        ):
            replacement = ActionPermit.model_validate(
                current.model_copy(
                    update={
                        "state": ActionPermitState.EXPIRED,
                        "revision": 1,
                        "expired_at": event.occurred_at,
                    }
                )
            )
        elif (
            event.kind
            in {
                PermitAuditKind.COMPLETED,
                PermitAuditKind.REJECTED,
                PermitAuditKind.OUTCOME_UNKNOWN,
            }
            and current.state is ActionPermitState.CLAIMED
            and event.claim_id == current.claim_id
            and event.completion_outcome is not None
        ):
            replacement = ActionPermit.model_validate(
                current.model_copy(
                    update={
                        "state": ActionPermitState.COMPLETED,
                        "revision": 2,
                        "completed_at": event.occurred_at,
                        "completion_outcome": event.completion_outcome,
                    }
                )
            )
        else:
            raise ValueError("permit audit transition is invalid")
        if (
            event.permit_revision != replacement.revision
            or event.permit_sha256 != canonical_sha256(replacement)
        ):
            raise ValueError("permit audit does not bind its state revision")
        current = replacement
    if current != permit:
        raise ValueError("permit audit history does not reproduce durable state")


def _claim_bindings(permit: ActionPermit, request: PermitClaimRequest) -> bool:
    return (
        request.permit_id == permit.permit_id
        and request.issued_permit_sha256 == canonical_sha256(permit)
        and request.certificate_id == permit.certificate_id
        and request.certificate_sha256 == permit.certificate_sha256
        and request.chain_id == permit.chain_id
        and request.source_node_id == permit.source_node_id
        and request.target_node_id == permit.target_node_id
        and request.semantic_action_sha256 == permit.semantic_action_sha256
        and request.action_profile_version == permit.action_profile_version
        and request.action_policy_version == permit.action_policy_version
        and request.tool_name == permit.tool_name
        and request.tool_version == permit.tool_version
        and request.arguments_sha256 == permit.arguments_sha256
        and request.target_sha256 == permit.target_sha256
        and request.precondition_sha256 == permit.precondition_sha256
    )


def evaluate_permit_claim(
    permit: ActionPermit,
    request: PermitClaimRequest,
    *,
    audit_sequence: int,
) -> PermitMutation:
    """Apply one claim attempt without performing persistence I/O."""

    if type(permit) is not ActionPermit or type(request) is not PermitClaimRequest:
        raise TypeError("exact permit claim inputs are required")
    if request.requested_at < permit.issued_at:
        reason = PermitDenialReason.NOT_YET_VALID
    elif permit.state is ActionPermitState.ISSUED and (
        request.requested_at >= permit.expires_at
    ):
        expired = ActionPermit.model_validate(
            permit.model_copy(
                update={
                    "state": ActionPermitState.EXPIRED,
                    "revision": 1,
                    "expired_at": request.requested_at,
                }
            )
        )
        return PermitMutation(
            permit=expired,
            event=_event(
                expired,
                sequence=audit_sequence,
                kind=PermitAuditKind.EXPIRED,
                occurred_at=request.requested_at,
                claim_id=request.claim_id,
                denial_reason=PermitDenialReason.EXPIRED,
            ),
            denial_reason=PermitDenialReason.EXPIRED,
        )
    elif permit.state is ActionPermitState.CLAIMED:
        reason = PermitDenialReason.ALREADY_CLAIMED
    elif permit.state in {ActionPermitState.COMPLETED, ActionPermitState.EXPIRED}:
        reason = PermitDenialReason.ALREADY_COMPLETED
    elif not _claim_bindings(permit, request):
        reason = PermitDenialReason.BINDING_MISMATCH
    else:
        claimed = ActionPermit.model_validate(
            permit.model_copy(
                update={
                    "state": ActionPermitState.CLAIMED,
                    "revision": 1,
                    "claim_id": request.claim_id,
                    "claimed_at": request.requested_at,
                }
            )
        )
        return PermitMutation(
            permit=claimed,
            event=_event(
                claimed,
                sequence=audit_sequence,
                kind=PermitAuditKind.CLAIMED,
                occurred_at=request.requested_at,
                claim_id=request.claim_id,
            ),
        )

    return PermitMutation(
        permit=permit,
        event=_event(
            permit,
            sequence=audit_sequence,
            kind=PermitAuditKind.BLOCKED,
            occurred_at=request.requested_at,
            claim_id=request.claim_id,
            denial_reason=reason,
        ),
        denial_reason=reason,
    )


def evaluate_permit_completion(
    permit: ActionPermit,
    request: PermitCompletionRequest,
    *,
    audit_sequence: int,
) -> PermitMutation:
    """Apply one terminal completion without performing persistence I/O."""

    if type(permit) is not ActionPermit or type(request) is not PermitCompletionRequest:
        raise TypeError("exact permit completion inputs are required")
    exact_claim = (
        request.permit_id == permit.permit_id
        and request.claim_id == permit.claim_id
        and request.claimed_permit_sha256 == canonical_sha256(permit)
        and permit.claimed_at is not None
        and request.completed_at >= permit.claimed_at
    )
    if permit.state is ActionPermitState.CLAIMED and exact_claim:
        completed = ActionPermit.model_validate(
            permit.model_copy(
                update={
                    "state": ActionPermitState.COMPLETED,
                    "revision": 2,
                    "completed_at": request.completed_at,
                    "completion_outcome": request.outcome,
                }
            )
        )
        kind = {
            PermitCompletionOutcome.SUCCEEDED: PermitAuditKind.COMPLETED,
            PermitCompletionOutcome.REJECTED: PermitAuditKind.REJECTED,
            PermitCompletionOutcome.OUTCOME_UNKNOWN: (PermitAuditKind.OUTCOME_UNKNOWN),
        }[request.outcome]
        return PermitMutation(
            permit=completed,
            event=_event(
                completed,
                sequence=audit_sequence,
                kind=kind,
                occurred_at=request.completed_at,
                claim_id=request.claim_id,
                completion_outcome=request.outcome,
            ),
        )

    reason = (
        PermitDenialReason.ALREADY_COMPLETED
        if permit.state in {ActionPermitState.COMPLETED, ActionPermitState.EXPIRED}
        else PermitDenialReason.BINDING_MISMATCH
    )
    return PermitMutation(
        permit=permit,
        event=_event(
            permit,
            sequence=audit_sequence,
            kind=PermitAuditKind.BLOCKED,
            occurred_at=request.completed_at,
            claim_id=request.claim_id,
            denial_reason=reason,
        ),
        denial_reason=reason,
    )


__all__ = [
    "PERMIT_AUDIT_EVENT_VERSION",
    "PERMIT_CLAIM_REQUEST_VERSION",
    "PERMIT_COMPLETION_REQUEST_VERSION",
    "ActionPermitStore",
    "PermitAuditEvent",
    "PermitAuditKind",
    "PermitClaimDenied",
    "PermitClaimRequest",
    "PermitCompletionDenied",
    "PermitCompletionRequest",
    "PermitConflict",
    "PermitCorruptState",
    "PermitDenialReason",
    "PermitMutation",
    "PermitNotFound",
    "PermitStoreError",
    "PermitStoreOutcomeUnknown",
    "PermitStoreUnavailable",
    "evaluate_permit_claim",
    "evaluate_permit_completion",
    "issued_audit_event",
    "validate_permit_audit_history",
]
