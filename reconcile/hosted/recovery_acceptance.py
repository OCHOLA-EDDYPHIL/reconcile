"""Explicit acceptance-only observers for hosted recovery dispatch."""

from __future__ import annotations

import asyncio
import hashlib
import re
from datetime import UTC, datetime
from http import HTTPStatus

from reconcile.contracts import (
    RECOVERY_DISPATCH_RECEIPT_VERSION,
    RecoveryActionScope,
    RecoveryAuthorityKind,
    RecoveryPreparedAction,
    RecoveryReceiptOutcome,
    RecoveryRunEventPayload,
    RecoveryRunEventType,
    RecoveryRunFault,
)
from reconcile.contracts import RecoveryDispatchReceipt as DurableDispatchReceipt
from reconcile.contracts.codec import canonical_json_bytes
from reconcile.hosted.cloud_run_fault import (
    CLOUD_RUN_CANARY_ACTION_PATH,
    CloudRunCanaryActionRequest,
)
from reconcile.hosted.transport import HostedHttpTransport
from reconcile.persistence.recovery_runs import RecoveryRunConflict, RecoveryRunStore

_ACCEPTANCE_RUN_ID = re.compile(r"p5r-(?:fixed|adaptive)-[0-9a-f]{32}")
_PARTIAL_READ_ACCEPTANCE_RUN_ID = re.compile(r"p5w-fixed-[0-9a-f]{32}")
_OPERATION_DENIED = b'{"code":"operation-denied"}'


class HostedRecoveryAcceptanceObserver:
    """Exercise a consumed-authority replay only for sealed acceptance run IDs."""

    def __init__(
        self,
        *,
        fault_proxy_url: str,
        fault_proxy_audience: str,
        transport: HostedHttpTransport,
        recovery_store: RecoveryRunStore,
    ) -> None:
        if (
            type(fault_proxy_url) is not str
            or not fault_proxy_url.startswith("https://")
            or fault_proxy_url.endswith("/")
            or type(fault_proxy_audience) is not str
            or not fault_proxy_audience
        ):
            raise ValueError("hosted recovery acceptance destination is invalid")
        if type(transport) is not HostedHttpTransport:
            raise TypeError("hosted recovery acceptance requires exact transport")
        if not isinstance(recovery_store, RecoveryRunStore):
            raise TypeError("hosted recovery acceptance requires a recovery store")
        self._cloud_endpoint = f"{fault_proxy_url}{CLOUD_RUN_CANARY_ACTION_PATH}"
        self._audience = fault_proxy_audience
        self._transport = transport
        self._store = recovery_store

    async def after_cloud_dispatch(
        self,
        prepared: RecoveryPreparedAction,
        scope: RecoveryActionScope,
        request: CloudRunCanaryActionRequest,
    ) -> None:
        if (
            prepared.target_node_id != "stage"
            or scope.authority_kind is not RecoveryAuthorityKind.LAUNCH_PERMIT
        ):
            return
        snapshot = await self._store.get(scope.run_id)
        acceptance_replay = _ACCEPTANCE_RUN_ID.fullmatch(
            scope.run_id
        ) is not None and snapshot.request.fault in {
            RecoveryRunFault.DROP_AFTER_ACCEPT,
            RecoveryRunFault.NO_FAULT,
        }
        partial_read_replay = (
            _PARTIAL_READ_ACCEPTANCE_RUN_ID.fullmatch(scope.run_id) is not None
            and snapshot.request.fault
            is RecoveryRunFault.ACCEPTANCE_DROP_AFTER_ACCEPT_PARTIAL_READ_OUTAGE
        )
        if not (acceptance_replay or partial_read_replay):
            return
        receipt_id = (
            "dispatch-denial-"
            + hashlib.sha256(
                f"{scope.authority_id}\0{scope.claim_id}\0replay".encode()
            ).hexdigest()[:32]
        )
        existing = tuple(
            receipt
            for receipt in snapshot.dispatch_receipts
            if receipt.receipt_id == receipt_id
        )
        if existing:
            if len(existing) != 1:
                raise ValueError("acceptance replay receipt is not unique")
            expected = DurableDispatchReceipt(
                schema_version=RECOVERY_DISPATCH_RECEIPT_VERSION,
                receipt_id=receipt_id,
                run_id=scope.run_id,
                release_id=str(prepared.arguments["release_id"]),
                node_id=scope.target_node_id,
                semantic_action_sha256=scope.semantic_action_sha256,
                action_request_sha256=scope.action_request_sha256,
                authority_id=scope.authority_id,
                claim_id=scope.claim_id,
                attempt=1,
                provider_contact=False,
                outcome=RecoveryReceiptOutcome.REJECTED_BEFORE_PROVIDER_CONTACT,
                recorded_at=existing[0].recorded_at,
            )
            if existing[0] != expected:
                raise ValueError("acceptance replay receipt changed")
            return
        response = await self._transport.request(
            "POST",
            self._cloud_endpoint,
            audience=self._audience,
            content=canonical_json_bytes(request),
        )
        if (
            response is None
            or response.status_code != HTTPStatus.FORBIDDEN
            or response.content != _OPERATION_DENIED
        ):
            raise ValueError("consumed authority replay was not denied")
        recorded_at = max(datetime.now(UTC), snapshot.updated_at)
        denial = DurableDispatchReceipt(
            schema_version=RECOVERY_DISPATCH_RECEIPT_VERSION,
            receipt_id=receipt_id,
            run_id=scope.run_id,
            release_id=str(prepared.arguments["release_id"]),
            node_id=scope.target_node_id,
            semantic_action_sha256=scope.semantic_action_sha256,
            action_request_sha256=scope.action_request_sha256,
            authority_id=scope.authority_id,
            claim_id=scope.claim_id,
            attempt=1,
            provider_contact=False,
            outcome=RecoveryReceiptOutcome.REJECTED_BEFORE_PROVIDER_CONTACT,
            recorded_at=recorded_at,
        )
        for _attempt in range(8):
            snapshot = await self._store.get(scope.run_id)
            try:
                await self._store.append(
                    scope.run_id,
                    expected_revision=snapshot.revision,
                    event_type=RecoveryRunEventType.DISPATCH_RECEIPT,
                    payload=RecoveryRunEventPayload(dispatch_receipt=denial),
                    occurred_at=max(recorded_at, snapshot.updated_at),
                )
                return
            except RecoveryRunConflict:
                continue
            except asyncio.CancelledError:
                raise
        raise RuntimeError("acceptance replay receipt could not be recorded")


__all__ = ["HostedRecoveryAcceptanceObserver"]
