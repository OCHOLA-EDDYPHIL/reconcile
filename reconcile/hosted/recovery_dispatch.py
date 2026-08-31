"""No-local-claim HTTP dispatch for hosted recovery actions."""

from __future__ import annotations

import asyncio
import hashlib
from http import HTTPStatus
from typing import Protocol

from reconcile.contracts import (
    ActionPermitState,
    RecoveryActionScope,
    RecoveryAuthorityKind,
    RecoveryDispatchOutcome,
    RecoveryLaunchPermitState,
    RecoveryPreparedAction,
    canonical_sha256,
)
from reconcile.contracts.codec import canonical_json_bytes, decode_contract
from reconcile.controller.permits import PermitAuthority
from reconcile.hosted.cloud_run_canary import CloudRunCanaryAction, CloudRunFaultMode
from reconcile.hosted.cloud_run_fault import (
    CLOUD_RUN_CANARY_ACTION_PATH,
    CLOUD_RUN_CANARY_ACTION_REQUEST_VERSION,
    CloudRunCanaryActionRequest,
    CloudRunCanaryActionResponse,
    cloud_run_action_request_sha256,
)
from reconcile.hosted.firestore_release_action import (
    FIRESTORE_RELEASE_ACTION_PATH,
    FIRESTORE_RELEASE_ACTION_REQUEST_VERSION,
    FirestoreReleaseActionRequest,
    FirestoreReleaseActionResponse,
    firestore_release_action_request_sha256,
)
from reconcile.hosted.transport import (
    HostedHttpResponse,
    HostedHttpTransport,
    HostedRequestError,
    HostedTransportError,
)
from reconcile.persistence.recovery_runs import RecoveryRunStore
from reconcile.recovery_agents import RecoveryDispatchReceipt


class HostedRecoveryDispatchError(RuntimeError):
    """The remote mutation boundary did not establish a terminal authority state."""

    def __init__(self) -> None:
        super().__init__("hosted recovery dispatch is unavailable")


def _request_id(prepared: RecoveryPreparedAction, scope: RecoveryActionScope) -> str:
    digest = hashlib.sha256(
        canonical_json_bytes(prepared) + b"\0" + canonical_json_bytes(scope)
    ).hexdigest()[:32]
    return f"recovery-action-{digest}"


class HostedRecoveryDispatchObserver(Protocol):
    """Optional observer invoked after a cloud action reaches durable finality."""

    async def after_cloud_dispatch(
        self,
        prepared: RecoveryPreparedAction,
        scope: RecoveryActionScope,
        request: CloudRunCanaryActionRequest,
    ) -> None: ...


class HostedRecoveryDispatchGateway:
    """Forward authority without claiming it; the mutation service claims once."""

    def __init__(
        self,
        *,
        fault_proxy_url: str,
        fault_proxy_audience: str,
        transport: HostedHttpTransport,
        recovery_store: RecoveryRunStore,
        permit_authority: PermitAuthority,
        observer: HostedRecoveryDispatchObserver | None = None,
    ) -> None:
        if (
            type(fault_proxy_url) is not str
            or not fault_proxy_url.startswith("https://")
            or fault_proxy_url.endswith("/")
            or type(fault_proxy_audience) is not str
            or not fault_proxy_audience
        ):
            raise ValueError("hosted recovery mutation destination is invalid")
        if type(transport) is not HostedHttpTransport:
            raise TypeError("hosted recovery dispatch requires exact transport")
        if not isinstance(recovery_store, RecoveryRunStore):
            raise TypeError("hosted recovery dispatch requires a recovery store")
        if type(permit_authority) is not PermitAuthority:
            raise TypeError("hosted recovery dispatch requires a permit authority")
        if observer is not None and not callable(
            getattr(observer, "after_cloud_dispatch", None)
        ):
            raise TypeError("hosted recovery dispatch observer is invalid")
        self._cloud_endpoint = f"{fault_proxy_url}{CLOUD_RUN_CANARY_ACTION_PATH}"
        self._firestore_endpoint = f"{fault_proxy_url}{FIRESTORE_RELEASE_ACTION_PATH}"
        self._audience = fault_proxy_audience
        self._transport = transport
        self._store = recovery_store
        self._permit_authority = permit_authority
        self._observer = observer

    @staticmethod
    def _cloud_request(
        prepared: RecoveryPreparedAction,
        scope: RecoveryActionScope,
    ) -> CloudRunCanaryActionRequest:
        payload = prepared.request_payload
        try:
            request = CloudRunCanaryActionRequest(
                schema_version=CLOUD_RUN_CANARY_ACTION_REQUEST_VERSION,
                request_id=_request_id(prepared, scope),
                action=CloudRunCanaryAction(str(payload["action"])),
                fault_mode=CloudRunFaultMode(str(payload["fault_mode"])),
                operation_id=(
                    str(payload["operation_id"]) if "operation_id" in payload else None
                ),
                release_id=str(payload["release_id"]),
                image_digest=(
                    str(payload["image_digest"]) if "image_digest" in payload else None
                ),
                configuration_sha256=(
                    str(payload["configuration_sha256"])
                    if "configuration_sha256" in payload
                    else None
                ),
                revision=(str(payload["revision"]) if "revision" in payload else None),
                service_etag=(
                    str(payload["service_etag"]) if "service_etag" in payload else None
                ),
                scope=scope,
            )
        except Exception:
            raise HostedRecoveryDispatchError from None
        if (
            cloud_run_action_request_sha256(request) != prepared.action_request_sha256
            or request.scope != scope
        ):
            raise HostedRecoveryDispatchError from None
        return request

    @staticmethod
    def _firestore_request(
        prepared: RecoveryPreparedAction,
        scope: RecoveryActionScope,
    ) -> FirestoreReleaseActionRequest:
        payload = prepared.request_payload
        try:
            request = FirestoreReleaseActionRequest(
                schema_version=FIRESTORE_RELEASE_ACTION_REQUEST_VERSION,
                request_id=_request_id(prepared, scope),
                action=str(payload["action"]),
                cloud_run_revision=str(payload["cloud_run_revision"]),
                payload_sha256=str(payload["payload_sha256"]),
                release_id=str(payload["release_id"]),
                suppress_before_dispatch=payload["suppress_before_dispatch"],
                scope=scope,
            )
        except Exception:
            raise HostedRecoveryDispatchError from None
        if (
            firestore_release_action_request_sha256(request)
            != prepared.action_request_sha256
            or request.scope != scope
        ):
            raise HostedRecoveryDispatchError from None
        return request

    async def _call(
        self,
        *,
        endpoint: str,
        content: bytes,
    ) -> HostedHttpResponse | None:
        try:
            return await self._transport.request(
                "POST",
                endpoint,
                audience=self._audience,
                content=content,
            )
        except asyncio.CancelledError:
            raise
        except (HostedRequestError, HostedTransportError):
            return None

    async def _durable_receipt(
        self,
        scope: RecoveryActionScope,
    ) -> RecoveryDispatchReceipt:
        try:
            if scope.authority_kind is RecoveryAuthorityKind.LAUNCH_PERMIT:
                permit = (await self._store.get(scope.run_id)).launch_permit
                if (
                    permit is None
                    or permit.launch_permit_id != scope.authority_id
                    or permit.claim_id != scope.claim_id
                    or permit.state is not RecoveryLaunchPermitState.COMPLETED
                    or permit.outcome is None
                ):
                    raise ValueError
                return RecoveryDispatchReceipt(
                    outcome=permit.outcome,
                    launch_permit=permit,
                )
            permit = await self._permit_authority.get_permit(scope.authority_id)
            if (
                permit.permit_id != scope.authority_id
                or permit.claim_id != scope.claim_id
                or permit.state is not ActionPermitState.COMPLETED
                or permit.completion_outcome is None
            ):
                raise ValueError
            return RecoveryDispatchReceipt(
                outcome=RecoveryDispatchOutcome(permit.completion_outcome.value),
                action_permit=permit,
            )
        except asyncio.CancelledError:
            raise
        except Exception:
            raise HostedRecoveryDispatchError from None

    @staticmethod
    def _validate_cloud_response(
        response: HostedHttpResponse | None,
        request: CloudRunCanaryActionRequest,
    ) -> None:
        if response is None or response.status_code != HTTPStatus.OK:
            return
        try:
            decoded = decode_contract(response.content, CloudRunCanaryActionResponse)
            if (
                response.content != canonical_json_bytes(decoded)
                or decoded.request_id != request.request_id
            ):
                raise ValueError
        except Exception:
            raise HostedRecoveryDispatchError from None

    @staticmethod
    def _validate_firestore_response(
        response: HostedHttpResponse | None,
        request: FirestoreReleaseActionRequest,
        receipt: RecoveryDispatchReceipt,
    ) -> None:
        if response is None or response.status_code != HTTPStatus.OK:
            return
        try:
            decoded = decode_contract(
                response.content,
                FirestoreReleaseActionResponse,
            )
            permit = receipt.action_permit
            if (
                response.content != canonical_json_bytes(decoded)
                or decoded.request_id != request.request_id
                or permit is None
                or decoded.outcome is not receipt.outcome
                or decoded.authority_id != permit.permit_id
                or decoded.authority_sha256 != canonical_sha256(permit)
            ):
                raise ValueError
        except Exception:
            raise HostedRecoveryDispatchError from None

    async def dispatch(
        self,
        prepared: RecoveryPreparedAction,
        scope: RecoveryActionScope,
    ) -> RecoveryDispatchReceipt:
        if (
            type(prepared) is not RecoveryPreparedAction
            or type(scope) is not RecoveryActionScope
            or prepared.authority_kind is not scope.authority_kind
            or prepared.run_id != scope.run_id
            or prepared.source_node_id != scope.source_node_id
            or prepared.target_node_id != scope.target_node_id
            or prepared.semantic_action_sha256 != scope.semantic_action_sha256
            or prepared.action_request_sha256 != scope.action_request_sha256
            or prepared.permit_action is not scope.permit_action
            or prepared.certificate_id != scope.certificate_id
            or prepared.certificate_sha256 != scope.certificate_sha256
        ):
            raise TypeError("hosted recovery dispatch requires exact bound inputs")

        if prepared.target_node_id in {"stage", "promote"}:
            request = self._cloud_request(prepared, scope)
            response = await self._call(
                endpoint=self._cloud_endpoint,
                content=canonical_json_bytes(request),
            )
            receipt = await self._durable_receipt(scope)
            self._validate_cloud_response(response, request)
            if self._observer is not None:
                try:
                    await self._observer.after_cloud_dispatch(prepared, scope, request)
                except asyncio.CancelledError:
                    raise
                except Exception:
                    raise HostedRecoveryDispatchError from None
            return receipt
        if prepared.target_node_id == "record":
            request = self._firestore_request(prepared, scope)
            response = await self._call(
                endpoint=self._firestore_endpoint,
                content=canonical_json_bytes(request),
            )
            receipt = await self._durable_receipt(scope)
            self._validate_firestore_response(response, request, receipt)
            return receipt
        raise HostedRecoveryDispatchError from None


__all__ = [
    "HostedRecoveryDispatchError",
    "HostedRecoveryDispatchGateway",
    "HostedRecoveryDispatchObserver",
]
