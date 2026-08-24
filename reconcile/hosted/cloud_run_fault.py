"""Authenticated and single-use-authorized Cloud Run canary mutations.

Caller identity is only the first gate. Recovery requests carry a proof-scoped,
single-use authority; the provider-relevant request is hashed independently from
transport metadata and checked again at this final mutation boundary. The hosted
runtime installs a closed authorizer until the durable permit integration supplies
this boundary. Legacy scenario scopes remain available only to the isolated demo
compatibility path and cannot authorize a recovery run.
"""

from __future__ import annotations

import asyncio
import hashlib
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from http import HTTPStatus
from typing import Literal, Protocol

from fastapi import FastAPI, Request
from fastapi.responses import Response
from pydantic import JsonValue, model_validator
from starlette.types import Receive, Scope, Send

from reconcile.contracts.base import (
    AwareDatetime,
    Identifier,
    NonEmptyText,
    StrictModel,
    canonical_json_value_bytes,
)
from reconcile.contracts.codec import (
    canonical_json_bytes,
    canonical_sha256,
    decode_contract,
)
from reconcile.contracts.recovery import (
    ActionPermit,
    ActionPermitState,
    PermitAction,
    PermitCompletionOutcome,
)
from reconcile.contracts.recovery_run import (
    RecoveryActionScope,
    RecoveryAuthorityKind,
    RecoveryDecision,
    RecoveryDispatchOutcome,
    RecoveryLaunchPermit,
    RecoveryNodeState,
    RecoveryRunEventPayload,
    RecoveryRunEventType,
    RecoveryRunFault,
    RecoveryRunLifecycle,
    RecoveryRunSnapshot,
)
from reconcile.contracts.recovery_scenario import (
    RECOVERY_DISPATCH_RECEIPT_VERSION,
    RecoveryReceiptOutcome,
)
from reconcile.contracts.recovery_scenario import (
    RecoveryDispatchReceipt as DurableDispatchReceipt,
)
from reconcile.controller.permits import PermitAuthority, action_permit_from_certificate
from reconcile.evidence.recovery_rules import CLOUD_RUN_SERVICE_TARGET_KIND
from reconcile.hosted.cloud_run_canary import (
    CloudRunAcceptanceAmbiguity,
    CloudRunAcceptedOperation,
    CloudRunCanaryAction,
    CloudRunCanaryError,
    CloudRunCanaryErrorCode,
    CloudRunCanaryFaultProxy,
    CloudRunCanaryTarget,
    CloudRunFaultMode,
)
from reconcile.hosted.identity import VerifiedCaller
from reconcile.hosted.workflow import HostedOperationScope, HostedWorkflowOperation
from reconcile.persistence.permits import (
    PermitNotFound,
    same_action_permit_authority,
    same_action_permit_state,
)
from reconcile.persistence.recovery_runs import RecoveryRunConflict, RecoveryRunStore

CLOUD_RUN_CANARY_ACTION_PATH = "/internal/v1/cloud-run-canary/actions"
CLOUD_RUN_CANARY_ACTION_REQUEST_VERSION = "reconcile/cloud-run-canary-action-request/v1"
CLOUD_RUN_CANARY_ACTION_RESPONSE_VERSION = (
    "reconcile/cloud-run-canary-action-response/v1"
)

_MAX_ACTION_REQUEST_BYTES = 4_096


class CloudRunCanaryActionRequest(StrictModel):
    schema_version: Literal[CLOUD_RUN_CANARY_ACTION_REQUEST_VERSION]
    request_id: Identifier
    action: CloudRunCanaryAction
    fault_mode: CloudRunFaultMode
    operation_id: Identifier | None = None
    release_id: str | None = None
    image_digest: str | None = None
    configuration_sha256: str | None = None
    revision: str | None = None
    service_etag: str | None = None
    scope: HostedOperationScope | RecoveryActionScope

    @model_validator(mode="after")
    def validate_action_fields(self) -> CloudRunCanaryActionRequest:
        populated = {
            name
            for name in (
                "operation_id",
                "release_id",
                "image_digest",
                "configuration_sha256",
                "revision",
                "service_etag",
            )
            if getattr(self, name) is not None
        }
        expected = {
            CloudRunCanaryAction.STAGE: {
                "operation_id",
                "release_id",
                "image_digest",
                "configuration_sha256",
            },
            CloudRunCanaryAction.PROMOTE: {
                "release_id",
                "revision",
                "service_etag",
            },
            CloudRunCanaryAction.RESET: set(),
        }[self.action]
        if populated != expected:
            raise ValueError("canary action fields are incomplete or mixed")
        for name in populated:
            value = getattr(self, name)
            if (
                type(value) is not str
                or not value
                or len(value) > 512
                or any(
                    ord(character) < 32 or ord(character) == 127 for character in value
                )
            ):
                raise ValueError("canary action field is invalid")
        if type(self.scope) is HostedOperationScope:
            expected_operation = (
                HostedWorkflowOperation.CLEANUP
                if self.action is CloudRunCanaryAction.RESET
                else HostedWorkflowOperation.EXECUTE_FAULT
            )
            if self.scope.operation is not expected_operation:
                raise ValueError("canary action does not match its authorized scope")
            if (
                self.action is CloudRunCanaryAction.STAGE
                and self.operation_id != self.scope.operation_id
            ):
                raise ValueError("canary action operation identity changed")
        return self


class CloudRunCanaryActionResponse(StrictModel):
    schema_version: Literal[CLOUD_RUN_CANARY_ACTION_RESPONSE_VERSION]
    request_id: Identifier
    accepted: Literal[True]
    operation_name: NonEmptyText
    revision: Identifier
    accepted_at: AwareDatetime
    service_etag: NonEmptyText


@dataclass(frozen=True, slots=True)
class CloudRunCanaryDispatchLease:
    request_sha256: str
    authority_id: str
    claim_id: str
    launch_permit: RecoveryLaunchPermit | None = None
    action_permit: ActionPermit | None = None

    def __post_init__(self) -> None:
        if (self.launch_permit is None) == (self.action_permit is None):
            raise ValueError("canary dispatch lease requires one authority record")


class CloudRunCanaryActionAuthorizer(Protocol):
    async def claim(
        self,
        request: CloudRunCanaryActionRequest,
    ) -> CloudRunCanaryDispatchLease: ...

    async def complete(
        self,
        lease: CloudRunCanaryDispatchLease,
        outcome: RecoveryDispatchOutcome,
    ) -> RecoveryLaunchPermit | ActionPermit: ...

    async def record_receipt(
        self,
        request: CloudRunCanaryActionRequest,
        lease: CloudRunCanaryDispatchLease,
    ) -> DurableDispatchReceipt: ...


class LegacyCloudRunCanaryActionAuthorizer(Protocol):
    """Compatibility boundary for pre-recovery scenario authorization."""

    async def __call__(self, request: CloudRunCanaryActionRequest) -> None: ...


class ClosedCloudRunCanaryActionAuthorizer:
    """Fail closed until an atomic, single-use permit claim owns dispatch."""

    async def claim(
        self,
        request: CloudRunCanaryActionRequest,
    ) -> CloudRunCanaryDispatchLease:
        if type(request) is not CloudRunCanaryActionRequest:
            raise TypeError("canary action authority requires an exact request")
        raise PermissionError("canary permit integration is not installed")

    async def complete(
        self,
        lease: CloudRunCanaryDispatchLease,
        outcome: RecoveryDispatchOutcome,
    ) -> RecoveryLaunchPermit | ActionPermit:
        del lease, outcome
        raise PermissionError("canary permit integration is not installed")

    async def record_receipt(
        self,
        request: CloudRunCanaryActionRequest,
        lease: CloudRunCanaryDispatchLease,
    ) -> DurableDispatchReceipt:
        del request, lease
        raise PermissionError("canary permit integration is not installed")


def cloud_run_action_request_payload(
    request: CloudRunCanaryActionRequest,
) -> dict[str, JsonValue]:
    """Return provider-relevant fields without transport or authority metadata."""
    if type(request) is not CloudRunCanaryActionRequest:
        raise TypeError("canary request payload requires an exact request")
    common: dict[str, JsonValue] = {
        "action": request.action.value,
        "fault_mode": request.fault_mode.value,
    }
    if request.action is CloudRunCanaryAction.STAGE:
        return {
            **common,
            "configuration_sha256": request.configuration_sha256,
            "image_digest": request.image_digest,
            "operation_id": request.operation_id,
            "release_id": request.release_id,
        }
    if request.action is CloudRunCanaryAction.PROMOTE:
        return {
            **common,
            "release_id": request.release_id,
            "revision": request.revision,
            "service_etag": request.service_etag,
        }
    return common


def cloud_run_action_request_sha256(request: CloudRunCanaryActionRequest) -> str:
    """Hash the provider-relevant request without transport or authority fields."""

    return hashlib.sha256(
        canonical_json_value_bytes(cloud_run_action_request_payload(request))
    ).hexdigest()


class RecoveryCloudRunCanaryActionAuthorizer:
    """Claim launch or certificate authority atomically before Cloud Run contact."""

    def __init__(
        self,
        *,
        recovery_store: RecoveryRunStore,
        permit_authority: PermitAuthority,
        target: CloudRunCanaryTarget,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        if not isinstance(recovery_store, RecoveryRunStore):
            raise TypeError("canary recovery authority requires a recovery store")
        if type(permit_authority) is not PermitAuthority:
            raise TypeError("canary recovery authority requires a permit authority")
        if type(target) is not CloudRunCanaryTarget:
            raise TypeError("canary recovery authority requires an exact target")
        self._store = recovery_store
        self._permit_authority = permit_authority
        self._target = target
        self._clock = clock or (lambda: datetime.now(UTC))

    @property
    def target(self) -> CloudRunCanaryTarget:
        return self._target

    def _now(self) -> datetime:
        value = self._clock()
        if (
            not isinstance(value, datetime)
            or value.tzinfo is None
            or value.utcoffset() is None
        ):
            raise PermissionError("canary recovery clock is invalid")
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
                raise PermissionError("canary action permit projection is unavailable")
            try:
                if same_action_permit_state(matches[0], permit):
                    return
            except (TypeError, ValueError):
                raise PermissionError(
                    "canary action permit projection changed"
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
        raise PermissionError("canary action permit projection is contended")

    @staticmethod
    def _node(snapshot: RecoveryRunSnapshot, node_id: str):
        chain = snapshot.chain
        matches = tuple(node for node in chain.nodes if node.node_id == node_id)
        if len(matches) != 1:
            raise PermissionError("canary recovery node is unavailable")
        return matches[0]

    async def claim(
        self,
        request: CloudRunCanaryActionRequest,
    ) -> CloudRunCanaryDispatchLease:
        if (
            type(request) is not CloudRunCanaryActionRequest
            or type(request.scope) is not RecoveryActionScope
        ):
            raise PermissionError("legacy canary scopes cannot authorize recovery")
        scope = request.scope
        if cloud_run_action_request_sha256(request) != scope.action_request_sha256:
            raise PermissionError("canary request does not match recovery authority")
        snapshot = await self._store.get(scope.run_id)
        if snapshot.lifecycle is not RecoveryRunLifecycle.RUNNING:
            raise PermissionError("canary recovery run is not active")
        node = self._node(snapshot, scope.target_node_id)
        target = node.semantic_action.target
        if (
            node.semantic_action.semantic_action_sha256 != scope.semantic_action_sha256
            or target.target_kind != CLOUD_RUN_SERVICE_TARGET_KIND
            or target.scope
            != {
                "project": self._target.project,
                "location": self._target.location,
            }
            or target.resource != {"service": self._target.service}
        ):
            raise PermissionError("canary semantic action changed")
        progress = {item.node_id: item for item in snapshot.nodes}
        expected_fault_mode = (
            CloudRunFaultMode.DROP_AFTER_ACCEPT
            if request.action is CloudRunCanaryAction.STAGE
            and snapshot.request.fault is RecoveryRunFault.DROP_AFTER_ACCEPT
            else CloudRunFaultMode.PASS_THROUGH
        )
        if request.fault_mode is not expected_fault_mode:
            raise PermissionError("canary recovery fault mode changed")

        if scope.authority_kind is RecoveryAuthorityKind.LAUNCH_PERMIT:
            launch = snapshot.launch_permit
            if (
                request.action is not CloudRunCanaryAction.STAGE
                or launch is None
                or launch.node_id != node.node_id
                or launch.launch_permit_id != scope.authority_id
                or canonical_sha256(launch) != scope.authority_sha256
                or request.operation_id != node.envelope.operation_id
                or node.depends_on
                or snapshot.active_node_id != node.node_id
                or progress[node.node_id].state
                is not RecoveryNodeState.DISPATCH_PENDING
            ):
                raise PermissionError("canary launch authority changed")
            arguments = node.semantic_action.semantic_arguments
            if (
                arguments.get("release_id") != request.release_id
                or arguments.get("image_digest") != request.image_digest
                or arguments.get("configuration_sha256") != request.configuration_sha256
            ):
                raise PermissionError("canary launch arguments changed")
            claimed = await self._store.claim_launch(
                scope.run_id,
                launch_permit_id=scope.authority_id,
                claim_id=scope.claim_id,
                action_request_sha256=scope.action_request_sha256,
                claimed_at=self._now(),
            )
            return CloudRunCanaryDispatchLease(
                request_sha256=canonical_sha256(request),
                authority_id=scope.authority_id,
                claim_id=scope.claim_id,
                launch_permit=claimed,
            )

        if request.action is not CloudRunCanaryAction.PROMOTE:
            raise PermissionError("canary permit action is unsupported")
        certificate_matches = tuple(
            item
            for item in snapshot.certificates
            if item.certificate_id == scope.certificate_id
            and canonical_sha256(item) == scope.certificate_sha256
        )
        if not certificate_matches:
            raise PermissionError("canary certificate authority is unavailable")
        certificate = certificate_matches[0]
        if any(item != certificate for item in certificate_matches[1:]):
            raise PermissionError("canary certificate authority is ambiguous")
        expected = action_permit_from_certificate(certificate)
        source_progress = (
            None if expected is None else progress.get(expected.source_node_id)
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
                projected, expected
            )
        except (TypeError, ValueError):
            projected_matches = False
        try:
            durable = (
                None
                if expected is None
                else await self._permit_authority.get_permit(scope.authority_id)
            )
        except PermitNotFound:
            raise PermissionError("canary action permit is unavailable") from None
        try:
            durable_matches = (
                durable is not None
                and projected is not None
                and same_action_permit_authority(durable, expected)
                and same_action_permit_state(durable, projected)
            )
        except (TypeError, ValueError):
            durable_matches = False
        if (
            expected is None
            or expected.permit_id != scope.authority_id
            or projected is None
            or projected.state is not ActionPermitState.ISSUED
            or not projected_matches
            or durable is None
            or durable.state is not ActionPermitState.ISSUED
            or canonical_sha256(durable) != scope.authority_sha256
            or not durable_matches
            or expected.action is not scope.permit_action
            or expected.source_node_id != scope.source_node_id
            or expected.target_node_id != node.node_id
            or expected.semantic_action_sha256 != scope.semantic_action_sha256
            or snapshot.active_node_id != expected.source_node_id
            or source_progress is None
            or source_progress.state is not RecoveryNodeState.PERMITTED
            or progress[node.node_id].state is not RecoveryNodeState.WAITING
            or snapshot.decision is not RecoveryDecision.CONTINUE
        ):
            raise PermissionError("canary action permit changed")
        arguments = node.semantic_action.semantic_arguments
        if (
            arguments.get("release_id") != request.release_id
            or arguments.get("revision") != request.revision
            or arguments.get("percent") != 100
            or type(request.service_etag) is not str
        ):
            raise PermissionError("canary promotion arguments changed")
        claimed = await self._permit_authority.claim_for_dispatch(
            permit_id=scope.authority_id,
            certificate=certificate,
            semantic_action=node.semantic_action,
            tool_name=node.semantic_action.tool_name,
            tool_version=node.semantic_action.tool_version,
            arguments=node.semantic_action.semantic_arguments,
            target=node.semantic_action.target,
            precondition={"service_etag": request.service_etag},
            claim_id=scope.claim_id,
        )
        latest = await self._store.get(scope.run_id)
        if latest.lifecycle is not RecoveryRunLifecycle.RUNNING:
            await self._mirror_action_permit(scope.run_id, claimed)
            raise PermissionError("canary recovery run changed during permit claim")
        return CloudRunCanaryDispatchLease(
            request_sha256=canonical_sha256(request),
            authority_id=scope.authority_id,
            claim_id=scope.claim_id,
            action_permit=claimed,
        )

    async def complete(
        self,
        lease: CloudRunCanaryDispatchLease,
        outcome: RecoveryDispatchOutcome,
    ) -> RecoveryLaunchPermit | ActionPermit:
        if (
            type(lease) is not CloudRunCanaryDispatchLease
            or type(outcome) is not RecoveryDispatchOutcome
        ):
            raise TypeError("exact canary completion inputs are required")
        if lease.launch_permit is not None:
            return await self._store.complete_launch(
                lease.launch_permit.run_id,
                launch_permit_id=lease.authority_id,
                claim_id=lease.claim_id,
                outcome=outcome,
                completed_at=self._now(),
            )
        claimed = lease.action_permit
        if claimed is None or claimed.state is not ActionPermitState.CLAIMED:
            raise PermissionError("canary permit claim is unavailable")
        permit_outcome = PermitCompletionOutcome(outcome.value)
        return await self._permit_authority.complete_dispatch(claimed, permit_outcome)

    async def record_receipt(
        self,
        request: CloudRunCanaryActionRequest,
        lease: CloudRunCanaryDispatchLease,
    ) -> DurableDispatchReceipt:
        if (
            type(request) is not CloudRunCanaryActionRequest
            or type(lease) is not CloudRunCanaryDispatchLease
            or type(request.scope) is not RecoveryActionScope
            or lease.request_sha256 != canonical_sha256(request)
        ):
            raise PermissionError("canary dispatch receipt authority changed")
        if lease.action_permit is not None:
            await self._mirror_action_permit(
                request.scope.run_id,
                lease.action_permit,
            )
        snapshot = await self._store.get(request.scope.run_id)
        action_permit = lease.action_permit
        receipt = DurableDispatchReceipt(
            schema_version=RECOVERY_DISPATCH_RECEIPT_VERSION,
            receipt_id=(
                "dispatch-"
                + hashlib.sha256(
                    f"{lease.authority_id}\0{lease.claim_id}".encode()
                ).hexdigest()[:32]
            ),
            run_id=request.scope.run_id,
            release_id=str(request.release_id),
            node_id=request.scope.target_node_id,
            semantic_action_sha256=request.scope.semantic_action_sha256,
            action_request_sha256=request.scope.action_request_sha256,
            authority_id=lease.authority_id,
            claim_id=lease.claim_id,
            attempt=(
                2
                if action_permit is not None
                and action_permit.action is PermitAction.RETRY
                else 1
            ),
            provider_contact=True,
            outcome=RecoveryReceiptOutcome.PROVIDER_CONTACTED,
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
        raise PermissionError("canary dispatch receipt is contended")


def cloud_run_release_id(scope: HostedOperationScope) -> str:
    """Derive the stable provider label from a durable authorized investigation."""

    if type(scope) is not HostedOperationScope:
        raise TypeError("canary release identity requires an exact operation scope")
    suffix = hashlib.sha256(scope.investigation_id.encode("utf-8")).hexdigest()[:16]
    return f"release-{suffix}"


class _DisconnectAfterAcceptance(Response):
    """Start an HTTP response, then close it without an acknowledgement body."""

    def __init__(self) -> None:
        super().__init__(
            status_code=HTTPStatus.OK,
            media_type="application/json",
            headers={"Cache-Control": "no-store"},
        )
        self.raw_headers = [
            (name, b"1") if name == b"content-length" else (name, value)
            for name, value in self.raw_headers
        ]

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        await send(
            {
                "type": "http.response.start",
                "status": self.status_code,
                "headers": self.raw_headers,
            }
        )
        raise CloudRunAcceptanceAmbiguity


def _error(*, code: str, status: HTTPStatus) -> Response:
    return Response(
        content=f'{{"code":"{code}"}}'.encode("ascii"),
        status_code=int(status),
        media_type="application/json",
        headers={"Cache-Control": "no-store"},
    )


async def _read_request(request: Request) -> CloudRunCanaryActionRequest:
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
    decoded = decode_contract(bytes(body), CloudRunCanaryActionRequest)
    if canonical_json_bytes(decoded) != bytes(body):
        raise ValueError
    return decoded


def _field(value: str | None) -> str:
    if type(value) is not str:
        raise TypeError("validated action field is unavailable")
    return value


def _invoke(
    proxy: CloudRunCanaryFaultProxy,
    request: CloudRunCanaryActionRequest,
) -> CloudRunAcceptedOperation:
    if request.action is CloudRunCanaryAction.STAGE:
        return proxy.stage_revision(
            mode=request.fault_mode,
            operation_id=_field(request.operation_id),
            release_id=_field(request.release_id),
            image_digest=_field(request.image_digest),
            configuration_sha256=_field(request.configuration_sha256),
        )
    if request.action is CloudRunCanaryAction.PROMOTE:
        return proxy.promote_revision(
            mode=request.fault_mode,
            release_id=_field(request.release_id),
            revision=_field(request.revision),
            service_etag=_field(request.service_etag),
        )
    return proxy.reset(mode=request.fault_mode)


async def _finish_before_cancellation[T](operation: Awaitable[T]) -> T:
    """Finish one claimed-authority transition before propagating cancellation."""

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


async def _finalize_recovery_dispatch(
    authorizer: CloudRunCanaryActionAuthorizer,
    request: CloudRunCanaryActionRequest,
    lease: CloudRunCanaryDispatchLease,
    outcome: RecoveryDispatchOutcome,
) -> RecoveryLaunchPermit | ActionPermit:
    """Persist provider contact before consuming the claimed authority."""

    try:
        await authorizer.record_receipt(request, lease)
    except Exception:
        await authorizer.complete(lease, outcome)
        raise
    return await authorizer.complete(lease, outcome)


def install_cloud_run_canary_fault_route(
    application: FastAPI,
    *,
    proxy: CloudRunCanaryFaultProxy,
    action_authorizer: (
        CloudRunCanaryActionAuthorizer | LegacyCloudRunCanaryActionAuthorizer
    ),
    expected_caller_email: str,
    expected_image_digest: str,
    expected_configuration_sha256: str,
) -> None:
    """Install the one authenticated mutation endpoint on the fault proxy app."""

    if not isinstance(application, FastAPI):
        raise TypeError("canary fault route requires a FastAPI application")
    if type(proxy) is not CloudRunCanaryFaultProxy:
        raise TypeError("canary fault route requires the exact fault proxy")
    modern_authorizer = all(
        callable(getattr(action_authorizer, name, None))
        for name in ("claim", "record_receipt", "complete")
    )
    if not modern_authorizer and not callable(action_authorizer):
        raise TypeError("canary fault route requires an action authorizer")
    if (
        type(action_authorizer) is RecoveryCloudRunCanaryActionAuthorizer
        and action_authorizer.target != proxy.target
    ):
        raise ValueError("canary fault proxy and recovery authority targets differ")
    if type(expected_caller_email) is not str or not expected_caller_email:
        raise TypeError("canary fault route requires an expected caller")
    if (
        type(expected_image_digest) is not str
        or type(expected_configuration_sha256) is not str
    ):
        raise TypeError("canary fault route requires immutable candidate identity")

    async def invoke(request: Request) -> Response:
        try:
            action = await _read_request(request)
        except (TypeError, ValueError):
            return _error(code="invalid-contract", status=HTTPStatus.BAD_REQUEST)
        caller = getattr(request.state, "verified_caller", None)
        if type(caller) is not VerifiedCaller or caller.email != expected_caller_email:
            return _error(code="operation-denied", status=HTTPStatus.FORBIDDEN)
        if (
            type(action.scope) is HostedOperationScope
            and action.action is not CloudRunCanaryAction.RESET
            and action.release_id != cloud_run_release_id(action.scope)
        ) or (
            action.action is CloudRunCanaryAction.STAGE
            and (
                action.image_digest != expected_image_digest
                or action.configuration_sha256 != expected_configuration_sha256
            )
        ):
            return _error(code="operation-denied", status=HTTPStatus.FORBIDDEN)
        lease: CloudRunCanaryDispatchLease | None = None
        try:
            if type(action.scope) is RecoveryActionScope:
                if not modern_authorizer:
                    raise PermissionError
                lease = await action_authorizer.claim(action)  # type: ignore[union-attr]
                if (
                    type(lease) is not CloudRunCanaryDispatchLease
                    or lease.request_sha256 != canonical_sha256(action)
                ):
                    raise PermissionError
            else:
                if not callable(action_authorizer):
                    raise PermissionError
                await action_authorizer(action)
        except asyncio.CancelledError:
            raise
        except Exception:
            return _error(code="operation-denied", status=HTTPStatus.FORBIDDEN)
        try:
            receipt = await asyncio.to_thread(_invoke, proxy, action)
        except CloudRunAcceptanceAmbiguity:
            if lease is not None:
                try:
                    await _finish_before_cancellation(
                        _finalize_recovery_dispatch(
                            action_authorizer,  # type: ignore[arg-type]
                            action,
                            lease,
                            RecoveryDispatchOutcome.OUTCOME_UNKNOWN,
                        )
                    )
                except Exception:
                    return _error(
                        code="operation-unavailable",
                        status=HTTPStatus.SERVICE_UNAVAILABLE,
                    )
            return _DisconnectAfterAcceptance()
        except CloudRunCanaryError as error:
            if lease is not None:
                try:
                    await _finish_before_cancellation(
                        _finalize_recovery_dispatch(
                            action_authorizer,  # type: ignore[arg-type]
                            action,
                            lease,
                            RecoveryDispatchOutcome.REJECTED,
                        )
                    )
                except Exception:
                    return _error(
                        code="operation-unavailable",
                        status=HTTPStatus.SERVICE_UNAVAILABLE,
                    )
            status = {
                CloudRunCanaryErrorCode.PERMISSION_DENIED: HTTPStatus.FORBIDDEN,
                CloudRunCanaryErrorCode.INVALID_CONFIGURATION: HTTPStatus.BAD_REQUEST,
                CloudRunCanaryErrorCode.STALE_ETAG: HTTPStatus.CONFLICT,
                CloudRunCanaryErrorCode.REVISION_NOT_FOUND: HTTPStatus.CONFLICT,
                CloudRunCanaryErrorCode.AMBIGUOUS_REVISION: HTTPStatus.CONFLICT,
                CloudRunCanaryErrorCode.REVISION_NOT_READY: HTTPStatus.CONFLICT,
            }.get(error.code, HTTPStatus.SERVICE_UNAVAILABLE)
            return _error(code=error.code.value, status=status)
        except asyncio.CancelledError:
            # The provider thread cannot be stopped. Close claimed authority as
            # outcome-unknown before propagating cancellation so the run can
            # restart in reconciliation and can never redispatch this request.
            if lease is not None:
                try:
                    await _finish_before_cancellation(
                        _finalize_recovery_dispatch(
                            action_authorizer,  # type: ignore[arg-type]
                            action,
                            lease,
                            RecoveryDispatchOutcome.OUTCOME_UNKNOWN,
                        )
                    )
                except Exception:
                    pass
            raise
        except Exception:
            if lease is not None:
                try:
                    await _finish_before_cancellation(
                        _finalize_recovery_dispatch(
                            action_authorizer,  # type: ignore[arg-type]
                            action,
                            lease,
                            RecoveryDispatchOutcome.OUTCOME_UNKNOWN,
                        )
                    )
                except Exception:
                    pass
            return _error(
                code="operation-unavailable",
                status=HTTPStatus.SERVICE_UNAVAILABLE,
            )
        if lease is not None:
            try:
                await _finish_before_cancellation(
                    _finalize_recovery_dispatch(
                        action_authorizer,  # type: ignore[arg-type]
                        action,
                        lease,
                        RecoveryDispatchOutcome.SUCCEEDED,
                    )
                )
            except Exception:
                return _error(
                    code="operation-unavailable",
                    status=HTTPStatus.SERVICE_UNAVAILABLE,
                )
        response = CloudRunCanaryActionResponse(
            schema_version=CLOUD_RUN_CANARY_ACTION_RESPONSE_VERSION,
            request_id=action.request_id,
            accepted=True,
            operation_name=receipt.operation_name,
            revision=receipt.revision,
            accepted_at=receipt.accepted_at,
            service_etag=receipt.service_etag,
        )
        return Response(
            content=canonical_json_bytes(response),
            status_code=HTTPStatus.OK,
            media_type="application/json",
            headers={"Cache-Control": "no-store"},
        )

    application.add_api_route(
        CLOUD_RUN_CANARY_ACTION_PATH,
        invoke,
        methods=["POST"],
        response_model=None,
    )


__all__ = [
    "CLOUD_RUN_CANARY_ACTION_PATH",
    "CLOUD_RUN_CANARY_ACTION_REQUEST_VERSION",
    "CLOUD_RUN_CANARY_ACTION_RESPONSE_VERSION",
    "ClosedCloudRunCanaryActionAuthorizer",
    "CloudRunCanaryActionAuthorizer",
    "CloudRunCanaryActionRequest",
    "CloudRunCanaryActionResponse",
    "CloudRunCanaryDispatchLease",
    "RecoveryCloudRunCanaryActionAuthorizer",
    "cloud_run_action_request_payload",
    "cloud_run_action_request_sha256",
    "cloud_run_release_id",
    "install_cloud_run_canary_fault_route",
]
