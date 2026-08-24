"""Permit-gated hosted mutation boundary for the final Firestore release record."""

from __future__ import annotations

import asyncio
import hashlib
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from http import HTTPStatus
from typing import Literal

from fastapi import FastAPI, Request
from fastapi.responses import Response

from reconcile.adapters.firestore_release import build_firestore_release_target
from reconcile.contracts import (
    RECOVERY_DISPATCH_RECEIPT_VERSION,
    ActionPermit,
    ActionPermitState,
    PermitAction,
    PermitCompletionOutcome,
    RecoveryActionScope,
    RecoveryAuthorityKind,
    RecoveryDecision,
    RecoveryDispatchOutcome,
    RecoveryNodeState,
    RecoveryReceiptOutcome,
    RecoveryRunEventPayload,
    RecoveryRunEventType,
    RecoveryRunLifecycle,
    canonical_sha256,
)
from reconcile.contracts import RecoveryDispatchReceipt as DurableDispatchReceipt
from reconcile.contracts.base import (
    Identifier,
    Sha256Digest,
    StrictModel,
    canonical_json_value_bytes,
)
from reconcile.contracts.codec import canonical_json_bytes, decode_contract
from reconcile.controller.permits import PermitAuthority, action_permit_from_certificate
from reconcile.hosted.firestore_release import (
    FIRESTORE_RELEASE_RECORD_VERSION,
    FirestoreReleaseConflict,
    FirestoreReleaseCorruptRecord,
    FirestoreReleaseOutcomeUnknown,
    FirestoreReleaseProviderUnavailable,
    FirestoreReleaseRecord,
    FirestoreReleaseSnapshot,
    GoogleFirestoreReleaseTarget,
    firestore_release_document_path,
)
from reconcile.hosted.identity import VerifiedCaller
from reconcile.persistence.permits import (
    same_action_permit_authority,
    same_action_permit_state,
)
from reconcile.persistence.recovery_runs import RecoveryRunConflict, RecoveryRunStore

FIRESTORE_RELEASE_ACTION_PATH = "/internal/v1/firestore-release/actions"
FIRESTORE_RELEASE_ACTION_REQUEST_VERSION = (
    "reconcile/firestore-release-action-request/v1"
)
FIRESTORE_RELEASE_ACTION_RESPONSE_VERSION = (
    "reconcile/firestore-release-action-response/v1"
)

_MAX_ACTION_REQUEST_BYTES = 4_096


class FirestoreReleaseActionRequest(StrictModel):
    """Exact prepared record action plus its single-use recovery authority."""

    schema_version: Literal[FIRESTORE_RELEASE_ACTION_REQUEST_VERSION]
    request_id: Identifier
    action: Literal["record"] = "record"
    cloud_run_revision: Identifier
    payload_sha256: Sha256Digest
    release_id: Identifier
    suppress_before_dispatch: bool
    scope: RecoveryActionScope


class FirestoreReleaseActionResponse(StrictModel):
    """Small acknowledgement bound to the completed durable permit."""

    schema_version: Literal[FIRESTORE_RELEASE_ACTION_RESPONSE_VERSION]
    request_id: Identifier
    outcome: RecoveryDispatchOutcome
    authority_id: Identifier
    authority_sha256: Sha256Digest


def firestore_release_action_request_payload(
    request: FirestoreReleaseActionRequest,
) -> dict[str, object]:
    """Return the exact provider request prepared by the recovery workflow."""

    if type(request) is not FirestoreReleaseActionRequest:
        raise TypeError("Firestore release payload requires an exact request")
    return {
        "action": request.action,
        "cloud_run_revision": request.cloud_run_revision,
        "payload_sha256": request.payload_sha256,
        "release_id": request.release_id,
        "suppress_before_dispatch": request.suppress_before_dispatch,
    }


def firestore_release_action_request_sha256(
    request: FirestoreReleaseActionRequest,
) -> str:
    return hashlib.sha256(
        canonical_json_value_bytes(firestore_release_action_request_payload(request))
    ).hexdigest()


@dataclass(frozen=True, slots=True)
class FirestoreReleaseDispatchLease:
    request_sha256: str
    permit: ActionPermit

    def __post_init__(self) -> None:
        if (
            len(self.request_sha256) != 64
            or type(self.permit) is not ActionPermit
            or self.permit.state is not ActionPermitState.CLAIMED
            or self.permit.claim_id is None
        ):
            raise ValueError("Firestore release dispatch lease is invalid")


class RecoveryFirestoreReleaseActionAuthorizer:
    """Validate and atomically claim the exact final-action permit."""

    def __init__(
        self,
        *,
        recovery_store: RecoveryRunStore,
        permit_authority: PermitAuthority,
        target: GoogleFirestoreReleaseTarget,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        if not isinstance(recovery_store, RecoveryRunStore):
            raise TypeError("Firestore release authority requires a recovery store")
        if type(permit_authority) is not PermitAuthority:
            raise TypeError("Firestore release authority requires a permit authority")
        if type(target) is not GoogleFirestoreReleaseTarget:
            raise TypeError("Firestore release authority requires an exact target")
        self._store = recovery_store
        self._permit_authority = permit_authority
        self._target = target
        self._clock = clock or (lambda: datetime.now(UTC))

    @property
    def target(self) -> GoogleFirestoreReleaseTarget:
        return self._target

    def _now(self) -> datetime:
        value = self._clock()
        if (
            not isinstance(value, datetime)
            or value.tzinfo is None
            or value.utcoffset() is None
        ):
            raise PermissionError("Firestore release authority clock is invalid")
        return value.astimezone(UTC)

    async def _mirror_action_permit(
        self,
        run_id: str,
        permit: ActionPermit,
    ) -> None:
        for _attempt in range(8):
            snapshot = await self._store.get(run_id)
            matches = tuple(
                item
                for item in snapshot.action_permits
                if item.permit_id == permit.permit_id
            )
            if len(matches) != 1:
                raise PermissionError(
                    "Firestore release permit projection is unavailable"
                )
            try:
                if same_action_permit_state(matches[0], permit):
                    return
            except (TypeError, ValueError):
                raise PermissionError(
                    "Firestore release permit projection changed"
                ) from None
            try:
                await self._store.append(
                    run_id,
                    expected_revision=snapshot.revision,
                    event_type=RecoveryRunEventType.ACTION_PERMIT,
                    payload=RecoveryRunEventPayload(action_permit=permit),
                    occurred_at=max(self._now(), snapshot.updated_at),
                )
                return
            except RecoveryRunConflict:
                continue
        raise PermissionError("Firestore release permit projection is contended")

    @staticmethod
    def _node(snapshot: object, node_id: str):
        nodes = getattr(getattr(snapshot, "chain", None), "nodes", ())
        matches = tuple(node for node in nodes if node.node_id == node_id)
        if len(matches) != 1:
            raise PermissionError("Firestore release node is unavailable")
        return matches[0]

    async def claim(
        self,
        request: FirestoreReleaseActionRequest,
    ) -> FirestoreReleaseDispatchLease:
        if (
            type(request) is not FirestoreReleaseActionRequest
            or type(request.scope) is not RecoveryActionScope
            or request.scope.authority_kind is not RecoveryAuthorityKind.ACTION_PERMIT
        ):
            raise PermissionError("an action permit is required for Firestore release")
        scope = request.scope
        if (
            firestore_release_action_request_sha256(request)
            != scope.action_request_sha256
        ):
            raise PermissionError("Firestore release request changed")

        snapshot = await self._store.get(scope.run_id)
        if snapshot.lifecycle is not RecoveryRunLifecycle.RUNNING:
            raise PermissionError("Firestore recovery run is not active")
        node = self._node(snapshot, scope.target_node_id)
        expected_target = build_firestore_release_target(
            project=self._target.project_id,
            database=self._target.database_id,
            document=firestore_release_document_path(request.release_id),
        )
        action = node.semantic_action
        if (
            action.semantic_action_sha256 != scope.semantic_action_sha256
            or action.target != expected_target
            or action.semantic_arguments
            != {
                "release_id": request.release_id,
                "payload_sha256": request.payload_sha256,
            }
        ):
            raise PermissionError("Firestore release semantic action changed")

        promotion_nodes = tuple(
            item for item in snapshot.chain.nodes if item.node_id == "promote"
        )
        if (
            len(promotion_nodes) != 1
            or promotion_nodes[0].semantic_action.semantic_arguments.get("revision")
            != request.cloud_run_revision
        ):
            raise PermissionError("Firestore release revision changed")

        certificate_matches = tuple(
            item
            for item in snapshot.certificates
            if item.certificate_id == scope.certificate_id
            and canonical_sha256(item) == scope.certificate_sha256
        )
        if not certificate_matches or any(
            item != certificate_matches[0] for item in certificate_matches[1:]
        ):
            raise PermissionError("Firestore certificate authority is unavailable")
        certificate = certificate_matches[0]
        expected = action_permit_from_certificate(certificate)
        progress = {item.node_id: item for item in snapshot.nodes}
        source_progress = (
            None if expected is None else progress.get(expected.source_node_id)
        )
        target_progress = (
            None if expected is None else progress.get(expected.target_node_id)
        )
        projected_permits = (
            ()
            if expected is None
            else tuple(
                item
                for item in snapshot.action_permits
                if item.permit_id == expected.permit_id
            )
        )
        projected = projected_permits[0] if len(projected_permits) == 1 else None
        try:
            projected_matches = projected is not None and same_action_permit_authority(
                projected,
                expected,
            )
        except (TypeError, ValueError):
            projected_matches = False
        durable = (
            None
            if expected is None
            else await self._permit_authority.get_permit(expected.permit_id)
        )
        try:
            durable_matches = (
                durable is not None
                and projected is not None
                and same_action_permit_authority(durable, expected)
                and same_action_permit_state(durable, projected)
            )
        except (TypeError, ValueError):
            durable_matches = False
        expected_decision = (
            None
            if expected is None
            else (
                RecoveryDecision.RETRY
                if expected.action is PermitAction.RETRY
                else RecoveryDecision.CONTINUE
            )
        )
        target_state_matches = bool(
            target_progress is not None
            and (
                target_progress.state is RecoveryNodeState.PERMITTED
                if expected is not None and expected.action is PermitAction.RETRY
                else target_progress.state is RecoveryNodeState.WAITING
            )
        )
        if (
            expected is None
            or expected.permit_id != scope.authority_id
            or expected.target_node_id != node.node_id
            or expected.source_node_id != scope.source_node_id
            or expected.target_node_id != scope.target_node_id
            or expected.semantic_action_sha256 != scope.semantic_action_sha256
            or expected.action is not scope.permit_action
            or projected is None
            or projected.state is not ActionPermitState.ISSUED
            or not projected_matches
            or durable is None
            or durable.state is not ActionPermitState.ISSUED
            or canonical_sha256(durable) != scope.authority_sha256
            or not durable_matches
            or snapshot.active_node_id != expected.source_node_id
            or source_progress is None
            or source_progress.state is not RecoveryNodeState.PERMITTED
            or not target_state_matches
            or snapshot.decision is not expected_decision
        ):
            raise PermissionError("Firestore action permit changed")

        claimed = await self._permit_authority.claim_for_dispatch(
            permit_id=scope.authority_id,
            certificate=certificate,
            semantic_action=action,
            tool_name=action.tool_name,
            tool_version=action.tool_version,
            arguments=action.semantic_arguments,
            target=action.target,
            precondition={"exists": False},
            claim_id=scope.claim_id,
        )
        await self._mirror_action_permit(scope.run_id, claimed)
        latest = await self._store.get(scope.run_id)
        if latest.lifecycle is not RecoveryRunLifecycle.RUNNING:
            raise PermissionError("Firestore recovery run changed during permit claim")
        return FirestoreReleaseDispatchLease(
            request_sha256=canonical_sha256(request),
            permit=claimed,
        )

    async def should_suppress(
        self,
        request: FirestoreReleaseActionRequest,
        lease: FirestoreReleaseDispatchLease,
    ) -> bool:
        if (
            type(request) is not FirestoreReleaseActionRequest
            or type(lease) is not FirestoreReleaseDispatchLease
            or lease.request_sha256 != canonical_sha256(request)
        ):
            raise PermissionError("Firestore release lease changed")
        if not request.suppress_before_dispatch:
            return False
        snapshot = await self._store.get(request.scope.run_id)
        return not any(
            receipt.node_id == request.scope.target_node_id
            and not receipt.provider_contact
            for receipt in snapshot.dispatch_receipts
        )

    async def record_receipt(
        self,
        request: FirestoreReleaseActionRequest,
        lease: FirestoreReleaseDispatchLease,
        *,
        provider_contact: bool,
    ) -> DurableDispatchReceipt:
        if (
            type(request) is not FirestoreReleaseActionRequest
            or type(lease) is not FirestoreReleaseDispatchLease
            or lease.request_sha256 != canonical_sha256(request)
        ):
            raise PermissionError("Firestore release receipt authority changed")
        snapshot = await self._store.get(request.scope.run_id)
        receipt = DurableDispatchReceipt(
            schema_version=RECOVERY_DISPATCH_RECEIPT_VERSION,
            receipt_id=(
                "dispatch-"
                + hashlib.sha256(
                    f"{lease.permit.permit_id}\0{lease.permit.claim_id}".encode()
                ).hexdigest()[:32]
            ),
            run_id=request.scope.run_id,
            release_id=request.release_id,
            node_id=request.scope.target_node_id,
            semantic_action_sha256=request.scope.semantic_action_sha256,
            action_request_sha256=request.scope.action_request_sha256,
            authority_id=lease.permit.permit_id,
            claim_id=lease.permit.claim_id or "",
            attempt=2 if lease.permit.action is PermitAction.RETRY else 1,
            provider_contact=provider_contact,
            outcome=(
                RecoveryReceiptOutcome.PROVIDER_CONTACTED
                if provider_contact
                else RecoveryReceiptOutcome.SUPPRESSED_BEFORE_DISPATCH
            ),
            recorded_at=max(self._now(), snapshot.updated_at),
        )
        for _attempt in range(8):
            snapshot = await self._store.get(request.scope.run_id)
            try:
                await self._store.append(
                    request.scope.run_id,
                    expected_revision=snapshot.revision,
                    event_type=RecoveryRunEventType.DISPATCH_RECEIPT,
                    payload=RecoveryRunEventPayload(dispatch_receipt=receipt),
                    occurred_at=max(receipt.recorded_at, snapshot.updated_at),
                )
                return receipt
            except RecoveryRunConflict:
                continue
        raise PermissionError("Firestore release receipt is contended")

    async def complete(
        self,
        request: FirestoreReleaseActionRequest,
        lease: FirestoreReleaseDispatchLease,
        outcome: RecoveryDispatchOutcome,
    ) -> ActionPermit:
        if (
            type(request) is not FirestoreReleaseActionRequest
            or type(lease) is not FirestoreReleaseDispatchLease
            or type(outcome) is not RecoveryDispatchOutcome
            or lease.request_sha256 != canonical_sha256(request)
        ):
            raise TypeError("exact Firestore release completion inputs are required")
        completed = await self._permit_authority.complete_dispatch(
            lease.permit,
            PermitCompletionOutcome(outcome.value),
        )
        await self._mirror_action_permit(request.scope.run_id, completed)
        return completed


def _error(*, code: str, status: HTTPStatus) -> Response:
    return Response(
        content=f'{{"code":"{code}"}}'.encode("ascii"),
        status_code=status,
        media_type="application/json",
        headers={"Cache-Control": "no-store"},
    )


async def _read_request(request: Request) -> FirestoreReleaseActionRequest:
    if request.url.query:
        raise ValueError
    if request.headers.get("content-type", "").split(";", 1)[0].strip().lower() != (
        "application/json"
    ):
        raise ValueError
    content_length = request.headers.get("content-length")
    if content_length is not None:
        try:
            declared = int(content_length)
        except ValueError as error:
            raise ValueError from error
        if not 1 <= declared <= _MAX_ACTION_REQUEST_BYTES:
            raise ValueError
    body = bytearray()
    async for chunk in request.stream():
        body.extend(chunk)
        if len(body) > _MAX_ACTION_REQUEST_BYTES:
            raise ValueError
    if not body:
        raise ValueError
    decoded = decode_contract(bytes(body), FirestoreReleaseActionRequest)
    if canonical_json_bytes(decoded) != bytes(body):
        raise ValueError
    return decoded


async def _finish_before_cancellation[T](operation: Awaitable[T]) -> T:
    task = asyncio.create_task(operation)
    interrupted: asyncio.CancelledError | None = None
    while not task.done():
        try:
            await asyncio.shield(task)
        except asyncio.CancelledError as error:
            interrupted = error
    result = task.result()
    if interrupted is not None:
        raise interrupted
    return result


async def _finalize(
    authorizer: RecoveryFirestoreReleaseActionAuthorizer,
    request: FirestoreReleaseActionRequest,
    lease: FirestoreReleaseDispatchLease,
    *,
    provider_contact: bool,
    outcome: RecoveryDispatchOutcome,
) -> ActionPermit:
    try:
        await authorizer.record_receipt(
            request,
            lease,
            provider_contact=provider_contact,
        )
    except BaseException:
        await authorizer.complete(request, lease, outcome)
        raise
    return await authorizer.complete(request, lease, outcome)


async def _create_release_record(
    target: GoogleFirestoreReleaseTarget,
    record: FirestoreReleaseRecord,
) -> RecoveryDispatchOutcome:
    try:
        result = await target.create(record)
        if type(result) is not FirestoreReleaseSnapshot or result.record != record:
            return RecoveryDispatchOutcome.OUTCOME_UNKNOWN
        return RecoveryDispatchOutcome.SUCCEEDED
    except FirestoreReleaseConflict:
        return RecoveryDispatchOutcome.REJECTED
    except (
        FirestoreReleaseCorruptRecord,
        FirestoreReleaseOutcomeUnknown,
        FirestoreReleaseProviderUnavailable,
    ):
        try:
            current = await target.read(record.release_id)
        except Exception:
            return RecoveryDispatchOutcome.OUTCOME_UNKNOWN
        if current is not None and current.record == record:
            return RecoveryDispatchOutcome.SUCCEEDED
        return (
            RecoveryDispatchOutcome.REJECTED
            if current is not None
            else RecoveryDispatchOutcome.OUTCOME_UNKNOWN
        )
    except asyncio.CancelledError:
        raise
    except Exception:
        return RecoveryDispatchOutcome.OUTCOME_UNKNOWN


def install_firestore_release_action_route(
    application: FastAPI,
    *,
    target: GoogleFirestoreReleaseTarget,
    authorizer: RecoveryFirestoreReleaseActionAuthorizer,
    expected_caller_email: str,
) -> None:
    """Install the authenticated, permit-only final mutation endpoint."""

    if not isinstance(application, FastAPI):
        raise TypeError("Firestore release route requires a FastAPI application")
    if type(target) is not GoogleFirestoreReleaseTarget:
        raise TypeError("Firestore release route requires an exact target")
    if type(authorizer) is not RecoveryFirestoreReleaseActionAuthorizer:
        raise TypeError("Firestore release route requires an exact authorizer")
    if authorizer.target is not target:
        raise ValueError("Firestore release route and authority targets differ")
    if type(expected_caller_email) is not str or not expected_caller_email:
        raise TypeError("Firestore release route requires an expected caller")

    async def invoke(request: Request) -> Response:
        try:
            action = await _read_request(request)
        except (TypeError, ValueError):
            return _error(code="invalid-contract", status=HTTPStatus.BAD_REQUEST)
        caller = getattr(request.state, "verified_caller", None)
        if type(caller) is not VerifiedCaller or caller.email != expected_caller_email:
            return _error(code="operation-denied", status=HTTPStatus.FORBIDDEN)
        try:
            lease = await authorizer.claim(action)
            if (
                type(lease) is not FirestoreReleaseDispatchLease
                or lease.request_sha256 != canonical_sha256(action)
            ):
                raise PermissionError
        except asyncio.CancelledError:
            raise
        except Exception:
            return _error(code="operation-denied", status=HTTPStatus.FORBIDDEN)

        record = FirestoreReleaseRecord(
            schema_version=FIRESTORE_RELEASE_RECORD_VERSION,
            release_id=action.release_id,
            cloud_run_revision=action.cloud_run_revision,
            payload_sha256=action.payload_sha256,
            semantic_action_sha256=action.scope.semantic_action_sha256,
            created_at=authorizer._now(),
        )
        provider_contact = False
        try:
            suppress = await authorizer.should_suppress(action, lease)
            if suppress:
                outcome = RecoveryDispatchOutcome.OUTCOME_UNKNOWN
            else:
                provider_contact = True
                outcome = await _create_release_record(target, record)
        except asyncio.CancelledError:
            await _finish_before_cancellation(
                _finalize(
                    authorizer,
                    action,
                    lease,
                    provider_contact=provider_contact,
                    outcome=RecoveryDispatchOutcome.OUTCOME_UNKNOWN,
                )
            )
            raise
        except Exception:
            outcome = RecoveryDispatchOutcome.OUTCOME_UNKNOWN

        try:
            completed = await _finish_before_cancellation(
                _finalize(
                    authorizer,
                    action,
                    lease,
                    provider_contact=provider_contact,
                    outcome=outcome,
                )
            )
        except Exception:
            return _error(
                code="operation-unavailable",
                status=HTTPStatus.SERVICE_UNAVAILABLE,
            )

        response = FirestoreReleaseActionResponse(
            schema_version=FIRESTORE_RELEASE_ACTION_RESPONSE_VERSION,
            request_id=action.request_id,
            outcome=outcome,
            authority_id=completed.permit_id,
            authority_sha256=canonical_sha256(completed),
        )
        return Response(
            content=canonical_json_bytes(response),
            status_code=HTTPStatus.OK,
            media_type="application/json",
            headers={"Cache-Control": "no-store"},
        )

    application.add_api_route(
        FIRESTORE_RELEASE_ACTION_PATH,
        invoke,
        methods=["POST"],
        response_model=None,
    )


__all__ = [
    "FIRESTORE_RELEASE_ACTION_PATH",
    "FIRESTORE_RELEASE_ACTION_REQUEST_VERSION",
    "FIRESTORE_RELEASE_ACTION_RESPONSE_VERSION",
    "FirestoreReleaseActionRequest",
    "FirestoreReleaseActionResponse",
    "FirestoreReleaseDispatchLease",
    "RecoveryFirestoreReleaseActionAuthorizer",
    "firestore_release_action_request_payload",
    "firestore_release_action_request_sha256",
    "install_firestore_release_action_route",
]
