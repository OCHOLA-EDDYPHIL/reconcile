"""Exact authenticated wire adapters for request-scoped hosted workflow calls."""

from __future__ import annotations

import asyncio
from collections.abc import Callable
from datetime import UTC, datetime
from http import HTTPStatus
from typing import Literal, Protocol

from reconcile.contracts.base import (
    Identifier,
    Sha256Digest,
    StrictModel,
    canonical_json_value_bytes,
)
from reconcile.contracts.codec import canonical_sha256, decode_contract
from reconcile.contracts.recovery_run import (
    RecoveryRunFault,
    RecoveryRunPolicy,
    RecoveryRunRequest,
    RecoveryRunSnapshot,
)
from reconcile.contracts.report import InvestigationReport
from reconcile.hosted.apps import InternalOperationConflict, InternalOperationDenied
from reconcile.hosted.config import Component, HostedConfig
from reconcile.hosted.contracts import (
    INTERNAL_OPERATION_REQUEST_VERSION,
    INTERNAL_OPERATION_RESPONSE_VERSION,
    InternalOperation,
    InternalOperationRequest,
    InternalOperationResponse,
    canonical_internal_json_bytes,
)
from reconcile.hosted.firestore_scenarios import FirestoreScenarioOperationAuthority
from reconcile.hosted.identity import VerifiedCaller
from reconcile.hosted.transport import (
    HostedHttpResponse,
    HostedHttpTransport,
    HostedRequestError,
    HostedTransportError,
)
from reconcile.hosted.workflow import (
    HOSTED_INVESTIGATION_RESULT_VERSION,
    HostedInvestigationResult,
    HostedOperationReceipt,
    HostedOperationScope,
    HostedWorkflowGateway,
    HostedWorkflowOperation,
)
from reconcile.persistence.durable import (
    CleanupStatus,
    DurableRunState,
    DurableRuntimeStore,
)
from reconcile.persistence.recovery_runs import (
    RecoveryRunConflict,
    RecoveryRunEventSnapshot,
    RecoveryRunStore,
    RecoveryRunStoreUnavailable,
    is_terminal_recovery_run,
)
from reconcile.persistence.scenarios import (
    ScenarioInvestigationState,
    ScenarioMutationState,
)
from reconcile.recovery_workflow import RecoveryRunLaunchResult

HOSTED_INVESTIGATION_RECEIPT_VERSION = "reconcile/hosted-investigation-receipt/v1"
HOSTED_RECOVERY_RECEIPT_VERSION = "reconcile/hosted-recovery-receipt/v1"

_CONTROLLER_PATH = "/internal/v1/investigations"
_RECOVERY_PATH = "/internal/v1/recovery-runs"
_FAULT_PATH = "/internal/v1/faults"
_CLEANUP_PATH = "/internal/v1/cleanup"


class HostedInvestigationReceipt(StrictModel):
    """Small controller response whose report remains in runtime Firestore."""

    schema_version: Literal["reconcile/hosted-investigation-receipt/v1"]
    scope_sha256: Sha256Digest
    report_sha256: Sha256Digest


class HostedRecoveryReceipt(StrictModel):
    """Minimal recovery response whose snapshot remains in runtime Firestore."""

    schema_version: Literal["reconcile/hosted-recovery-receipt/v1"]
    run_id: Identifier
    request_sha256: Sha256Digest
    snapshot_sha256: Sha256Digest
    created: bool


class HostedWorkflowGatewayError(RuntimeError):
    """A sanitized internal dependency failure."""

    def __init__(self) -> None:
        super().__init__("hosted workflow dependency is unavailable")


class HostedRecoveryGatewayError(RecoveryRunStoreUnavailable):
    """A sanitized hosted recovery transport or verification failure."""

    def __init__(self) -> None:
        super().__init__("hosted recovery dependency is unavailable")


class HostedReportLoader(Protocol):
    async def load_report(self, investigation_id: str) -> InvestigationReport: ...


class HostedOperationDispatcher(Protocol):
    async def __call__(
        self,
        scope: HostedOperationScope,
    ) -> HostedOperationReceipt: ...


class HostedInvestigationDispatcher(Protocol):
    async def __call__(
        self,
        scope: HostedOperationScope,
    ) -> HostedInvestigationResult: ...


class HostedRecoveryService(Protocol):
    async def launch_and_wait_result(
        self,
        request: RecoveryRunRequest,
    ) -> RecoveryRunLaunchResult: ...

    async def aclose(self) -> None: ...


class HostedOperationScopeAuthorizer(Protocol):
    async def __call__(self, scope: HostedOperationScope) -> None: ...


class _ScenarioAuthorityStore(Protocol):
    async def operation_authority(
        self,
        investigation_id: str,
    ) -> FirestoreScenarioOperationAuthority: ...


def _aware_utc(value: datetime) -> datetime:
    if (
        not isinstance(value, datetime)
        or value.tzinfo is None
        or value.utcoffset() is None
    ):
        raise ValueError("hosted authority clock must be timezone-aware")
    return value.astimezone(UTC)


class FirestoreHostedOperationScopeAuthorizer:
    """Authorize one scope from current read-only Firestore scenario authority."""

    def __init__(
        self,
        store: _ScenarioAuthorityStore,
        *,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        if not callable(getattr(store, "operation_authority", None)):
            raise TypeError("hosted scope authorizer requires scenario authority")
        if clock is not None and not callable(clock):
            raise TypeError("hosted scope authorizer clock must be callable")
        self._store = store
        self._clock = clock or (lambda: datetime.now(UTC))

    async def __call__(self, scope: HostedOperationScope) -> None:
        if type(scope) is not HostedOperationScope:
            raise InternalOperationDenied from None
        try:
            authority = await self._store.operation_authority(scope.investigation_id)
        except asyncio.CancelledError:
            raise
        except Exception:
            raise InternalOperationDenied from None
        try:
            if type(authority) is not FirestoreScenarioOperationAuthority:
                raise ValueError
            work = authority.work
            request = work.scenario_request
            lease = authority.current_lease
            now = _aware_utc(self._clock())
            expected_envelope_sha256 = (
                work.prepared_envelope_sha256
                if scope.operation is HostedWorkflowOperation.EXECUTE_FAULT
                else work.envelope_sha256
            )
            if (
                lease is None
                or authority.lease_fence != scope.lease_fence
                or lease.fence != scope.lease_fence
                or lease.investigation_id != scope.investigation_id
                or now < lease.renewed_at
                or lease.expired(now)
                or work.launch_request.launch_id != scope.launch_id
                or work.launch_sha256 != scope.launch_sha256
                or work.scenario_request_sha256 != scope.scenario_request_sha256
                or request.investigation_id != scope.investigation_id
                or request.operation_id != scope.operation_id
                or request.invocation_id != scope.invocation_id
                or request.function_call_id != scope.function_call_id
                or expected_envelope_sha256 != scope.envelope_sha256
                or work.cleanup_manifest_sha256 != scope.cleanup_manifest_sha256
                or not self._operation_state_matches(scope, authority)
            ):
                raise ValueError
        except (TypeError, ValueError):
            raise InternalOperationDenied from None

    @staticmethod
    def _operation_state_matches(
        scope: HostedOperationScope,
        authority: FirestoreScenarioOperationAuthority,
    ) -> bool:
        work = authority.work
        if scope.operation is HostedWorkflowOperation.EXECUTE_FAULT:
            return (
                work.mutation_state is ScenarioMutationState.STARTED
                and work.scenario_result is None
                and work.investigation_state is ScenarioInvestigationState.NOT_STARTED
                and work.cleanup_status is CleanupStatus.NOT_REQUESTED
            )
        if scope.operation is HostedWorkflowOperation.INVESTIGATE:
            return (
                work.mutation_state is ScenarioMutationState.RECORDED
                and work.scenario_result is not None
                and work.investigation_state is ScenarioInvestigationState.STARTED
                and work.workflow_result is None
                and work.cleanup_status is CleanupStatus.NOT_REQUESTED
            )
        return (
            scope.operation is HostedWorkflowOperation.CLEANUP
            and work.mutation_state is ScenarioMutationState.RECORDED
            and work.scenario_result is not None
            and work.investigation_state is ScenarioInvestigationState.RECORDED
            and work.workflow_result is not None
            and work.cleanup_status is CleanupStatus.PENDING
        )


class DurableRuntimeReportLoader:
    """Read one exact terminal report without enumerating runtime state."""

    def __init__(self, store: DurableRuntimeStore) -> None:
        if any(
            not callable(getattr(store, name, None))
            for name in ("get_run", "snapshot_events")
        ):
            raise TypeError("hosted report loader requires a durable runtime store")
        self._store = store

    async def load_report(self, investigation_id: str) -> InvestigationReport:
        run = await self._store.get_run(investigation_id)
        report = run.established_report
        if run.state is not DurableRunState.TERMINAL or report is None:
            raise HostedWorkflowGatewayError from None
        return decode_contract(
            canonical_json_value_bytes(report.model_dump(mode="json")),
            InvestigationReport,
        )


def _internal_operation(operation: HostedWorkflowOperation) -> InternalOperation:
    return {
        HostedWorkflowOperation.EXECUTE_FAULT: InternalOperation.EXECUTE_FAULT,
        HostedWorkflowOperation.INVESTIGATE: InternalOperation.INVESTIGATE,
        HostedWorkflowOperation.CLEANUP: InternalOperation.CLEANUP,
    }[operation]


def _request(scope: HostedOperationScope) -> InternalOperationRequest:
    operation = _internal_operation(scope.operation)
    return InternalOperationRequest(
        schema_version=INTERNAL_OPERATION_REQUEST_VERSION,
        request_id=f"hosted-{operation.value}-{scope.sha256[:32]}",
        operation=operation,
        payload=scope.model_dump(mode="json"),
    )


def _recovery_request(request: RecoveryRunRequest) -> InternalOperationRequest:
    request_sha256 = canonical_sha256(request)
    return InternalOperationRequest(
        schema_version=INTERNAL_OPERATION_REQUEST_VERSION,
        request_id=f"hosted-recover-{request_sha256[:32]}",
        operation=InternalOperation.RECOVER,
        payload=request.model_dump(mode="json"),
    )


def _decode_recovery_request(
    request: InternalOperationRequest,
) -> RecoveryRunRequest:
    if request.operation is not InternalOperation.RECOVER:
        raise ValueError("hosted recovery does not match its route")
    recovery = RecoveryRunRequest.model_validate_json(
        canonical_json_value_bytes(request.payload)
    )
    if request.payload != recovery.model_dump(mode="json"):
        raise ValueError("hosted recovery request is not exact")
    return recovery


def _decode_scope(
    request: InternalOperationRequest,
    operation: HostedWorkflowOperation,
) -> HostedOperationScope:
    if request.operation is not _internal_operation(operation):
        raise ValueError("hosted operation does not match its route")
    scope = HostedOperationScope.model_validate_json(
        canonical_json_value_bytes(request.payload)
    )
    if scope.operation is not operation or request.payload != scope.model_dump(
        mode="json"
    ):
        raise ValueError("hosted operation scope is not exact")
    return scope


def _response(
    request: InternalOperationRequest,
    payload: dict[str, object],
) -> InternalOperationResponse:
    return InternalOperationResponse(
        schema_version=INTERNAL_OPERATION_RESPONSE_VERSION,
        request_id=request.request_id,
        operation=request.operation,
        accepted=True,
        payload=payload,  # type: ignore[arg-type]
    )


def _validated_caller(caller: VerifiedCaller, expected_email: str) -> None:
    if type(caller) is not VerifiedCaller or caller.email != expected_email:
        raise InternalOperationDenied from None


class HostedOperationHandler:
    """Adapt one fault or cleanup dispatcher to the exact internal route."""

    def __init__(
        self,
        *,
        operation: HostedWorkflowOperation,
        expected_caller_email: str,
        authorizer: HostedOperationScopeAuthorizer,
        dispatcher: HostedOperationDispatcher,
    ) -> None:
        if operation not in {
            HostedWorkflowOperation.EXECUTE_FAULT,
            HostedWorkflowOperation.CLEANUP,
        }:
            raise ValueError("hosted operation handler is not a fault route")
        if type(expected_caller_email) is not str or not expected_caller_email:
            raise ValueError("hosted operation caller is invalid")
        if not callable(dispatcher):
            raise TypeError("hosted operation dispatcher must be callable")
        if not callable(authorizer):
            raise TypeError("hosted operation authorizer must be callable")
        self._operation = operation
        self._expected_caller_email = expected_caller_email
        self._authorizer = authorizer
        self._dispatcher = dispatcher

    async def __call__(
        self,
        caller: VerifiedCaller,
        request: InternalOperationRequest,
    ) -> InternalOperationResponse:
        _validated_caller(caller, self._expected_caller_email)
        scope = _decode_scope(request, self._operation)
        await self._authorizer(scope)
        receipt = await self._dispatcher(scope)
        if (
            type(receipt) is not HostedOperationReceipt
            or receipt.operation is not self._operation
            or receipt.scope_sha256 != scope.sha256
        ):
            raise HostedWorkflowGatewayError from None
        return _response(request, receipt.model_dump(mode="json"))


class HostedInvestigationHandler:
    """Adapt one controller dispatcher while retaining its report in Firestore."""

    def __init__(
        self,
        *,
        expected_caller_email: str,
        authorizer: HostedOperationScopeAuthorizer,
        dispatcher: HostedInvestigationDispatcher,
    ) -> None:
        if type(expected_caller_email) is not str or not expected_caller_email:
            raise ValueError("hosted investigation caller is invalid")
        if not callable(dispatcher):
            raise TypeError("hosted investigation dispatcher must be callable")
        if not callable(authorizer):
            raise TypeError("hosted investigation authorizer must be callable")
        self._expected_caller_email = expected_caller_email
        self._authorizer = authorizer
        self._dispatcher = dispatcher

    async def __call__(
        self,
        caller: VerifiedCaller,
        request: InternalOperationRequest,
    ) -> InternalOperationResponse:
        _validated_caller(caller, self._expected_caller_email)
        scope = _decode_scope(request, HostedWorkflowOperation.INVESTIGATE)
        await self._authorizer(scope)
        result = await self._dispatcher(scope)
        if (
            type(result) is not HostedInvestigationResult
            or result.scope_sha256 != scope.sha256
            or result.report.investigation_id != scope.investigation_id
            or result.report.envelope_sha256 != scope.envelope_sha256
        ):
            raise HostedWorkflowGatewayError from None
        receipt = HostedInvestigationReceipt(
            schema_version=HOSTED_INVESTIGATION_RECEIPT_VERSION,
            scope_sha256=scope.sha256,
            report_sha256=canonical_sha256(result.report),
        )
        return _response(request, receipt.model_dump(mode="json"))


class HostedRecoveryHandler:
    """Join one controller-owned recovery and return only durable identity."""

    def __init__(
        self,
        *,
        expected_caller_email: str,
        service: HostedRecoveryService,
        operating_profile: Literal["evidence", "production"] = "evidence",
        acceptance_partial_read_outage_enabled: bool = False,
    ) -> None:
        if type(expected_caller_email) is not str or not expected_caller_email:
            raise ValueError("hosted recovery caller is invalid")
        if not callable(getattr(service, "launch_and_wait_result", None)):
            raise TypeError("hosted recovery service is invalid")
        if type(acceptance_partial_read_outage_enabled) is not bool:
            raise TypeError("partial-read acceptance state must be boolean")
        if operating_profile not in {"evidence", "production"}:
            raise ValueError("hosted recovery operating profile is invalid")
        self._expected_caller_email = expected_caller_email
        self._service = service
        self._operating_profile = operating_profile
        self._acceptance_partial_read_outage_enabled = (
            acceptance_partial_read_outage_enabled
        )

    async def __call__(
        self,
        caller: VerifiedCaller,
        request: InternalOperationRequest,
    ) -> InternalOperationResponse:
        _validated_caller(caller, self._expected_caller_email)
        recovery = _decode_recovery_request(request)
        if recovery.policy not in {
            RecoveryRunPolicy.FIXED,
            RecoveryRunPolicy.ADAPTIVE,
        }:
            raise HostedRecoveryGatewayError from None
        if (
            self._operating_profile == "production"
            and recovery.fault is not RecoveryRunFault.NO_FAULT
        ):
            raise HostedRecoveryGatewayError from None
        if (
            recovery.fault
            is RecoveryRunFault.ACCEPTANCE_DROP_AFTER_ACCEPT_PARTIAL_READ_OUTAGE
            and not self._acceptance_partial_read_outage_enabled
        ):
            raise HostedRecoveryGatewayError from None
        try:
            result = await self._service.launch_and_wait_result(recovery)
        except asyncio.CancelledError:
            raise
        except RecoveryRunConflict:
            raise InternalOperationConflict from None
        try:
            if type(result) is not RecoveryRunLaunchResult:
                raise TypeError
            snapshot = result.snapshot
            if (
                type(snapshot) is not RecoveryRunSnapshot
                or snapshot.request != recovery
                or snapshot.request_sha256 != canonical_sha256(recovery)
                or not is_terminal_recovery_run(snapshot.lifecycle)
                or type(result.created) is not bool
            ):
                raise ValueError
            receipt = HostedRecoveryReceipt(
                schema_version=HOSTED_RECOVERY_RECEIPT_VERSION,
                run_id=recovery.run_id,
                request_sha256=canonical_sha256(recovery),
                snapshot_sha256=canonical_sha256(snapshot),
                created=result.created,
            )
            return _response(request, receipt.model_dump(mode="json"))
        except (TypeError, ValueError):
            raise HostedRecoveryGatewayError from None

    async def aclose(self) -> None:
        closer = getattr(self._service, "aclose", None)
        if callable(closer):
            await closer()


class HostedHttpWorkflowGateway(HostedWorkflowGateway):
    """Make exactly one authenticated HTTP call for each parent transition."""

    def __init__(
        self,
        config: HostedConfig,
        transport: HostedHttpTransport,
        report_loader: HostedReportLoader,
    ) -> None:
        if type(config) is not HostedConfig or config.component is not Component.API:
            raise ValueError("hosted workflow gateway requires API configuration")
        if type(transport) is not HostedHttpTransport:
            raise TypeError("hosted workflow gateway requires exact transport")
        if not callable(getattr(report_loader, "load_report", None)):
            raise TypeError("hosted workflow gateway requires a report loader")
        required = (
            config.controller_url,
            config.controller_audience,
            config.fault_proxy_url,
            config.fault_proxy_audience,
        )
        if any(type(value) is not str or not value for value in required):
            raise ValueError("hosted workflow destinations are incomplete")
        self._controller_endpoint = f"{config.controller_url}{_CONTROLLER_PATH}"
        self._controller_audience = config.controller_audience
        self._fault_endpoint = f"{config.fault_proxy_url}{_FAULT_PATH}"
        self._cleanup_endpoint = f"{config.fault_proxy_url}{_CLEANUP_PATH}"
        self._fault_audience = config.fault_proxy_audience
        self._transport = transport
        self._report_loader = report_loader

    async def _call(
        self,
        scope: HostedOperationScope,
        *,
        endpoint: str,
        audience: str,
    ) -> tuple[InternalOperationRequest, InternalOperationResponse]:
        request = _request(scope)
        try:
            response = await self._transport.request(
                "POST",
                endpoint,
                audience=audience,
                content=canonical_internal_json_bytes(request),
            )
        except asyncio.CancelledError:
            raise
        except (HostedRequestError, HostedTransportError):
            raise HostedWorkflowGatewayError from None
        decoded = self._decode_response(response, request)
        return request, decoded

    @staticmethod
    def _decode_response(
        response: HostedHttpResponse,
        request: InternalOperationRequest,
    ) -> InternalOperationResponse:
        try:
            if type(response) is not HostedHttpResponse:
                raise TypeError
            if response.status_code != HTTPStatus.OK:
                raise ValueError
            decoded = decode_contract(response.content, InternalOperationResponse)
            if (
                response.content != canonical_internal_json_bytes(decoded)
                or decoded.request_id != request.request_id
                or decoded.operation is not request.operation
                or decoded.accepted is not True
            ):
                raise ValueError
            return decoded
        except (TypeError, ValueError):
            raise HostedWorkflowGatewayError from None

    async def execute_fault(
        self,
        scope: HostedOperationScope,
    ) -> HostedOperationReceipt:
        if scope.operation is not HostedWorkflowOperation.EXECUTE_FAULT:
            raise HostedWorkflowGatewayError from None
        _, response = await self._call(
            scope,
            endpoint=self._fault_endpoint,
            audience=self._fault_audience,
        )
        return self._receipt(response, scope)

    async def cleanup(
        self,
        scope: HostedOperationScope,
    ) -> HostedOperationReceipt:
        if scope.operation is not HostedWorkflowOperation.CLEANUP:
            raise HostedWorkflowGatewayError from None
        _, response = await self._call(
            scope,
            endpoint=self._cleanup_endpoint,
            audience=self._fault_audience,
        )
        return self._receipt(response, scope)

    @staticmethod
    def _receipt(
        response: InternalOperationResponse,
        scope: HostedOperationScope,
    ) -> HostedOperationReceipt:
        try:
            receipt = HostedOperationReceipt.model_validate_json(
                canonical_json_value_bytes(response.payload)
            )
            if (
                response.payload != receipt.model_dump(mode="json")
                or receipt.operation is not scope.operation
                or receipt.scope_sha256 != scope.sha256
            ):
                raise ValueError
            return receipt
        except (TypeError, ValueError):
            raise HostedWorkflowGatewayError from None

    async def investigate(
        self,
        scope: HostedOperationScope,
    ) -> HostedInvestigationResult:
        if scope.operation is not HostedWorkflowOperation.INVESTIGATE:
            raise HostedWorkflowGatewayError from None
        _, response = await self._call(
            scope,
            endpoint=self._controller_endpoint,
            audience=self._controller_audience,
        )
        try:
            receipt = HostedInvestigationReceipt.model_validate_json(
                canonical_json_value_bytes(response.payload)
            )
            if (
                response.payload != receipt.model_dump(mode="json")
                or receipt.scope_sha256 != scope.sha256
            ):
                raise ValueError
            report = await self._report_loader.load_report(scope.investigation_id)
            if (
                type(report) is not InvestigationReport
                or report.investigation_id != scope.investigation_id
                or report.envelope_sha256 != scope.envelope_sha256
                or canonical_sha256(report) != receipt.report_sha256
            ):
                raise ValueError
            return HostedInvestigationResult(
                schema_version=HOSTED_INVESTIGATION_RESULT_VERSION,
                scope_sha256=scope.sha256,
                report=report,
            )
        except asyncio.CancelledError:
            raise
        except HostedWorkflowGatewayError:
            raise
        except Exception:
            raise HostedWorkflowGatewayError from None


class HostedRecoveryRunGateway:
    """Call the controller, then verify its minimal receipt against Firestore."""

    def __init__(
        self,
        config: HostedConfig,
        transport: HostedHttpTransport,
        store: RecoveryRunStore,
        *,
        poll_interval_seconds: float = 0.01,
        acceptance_partial_read_outage_enabled: bool = False,
    ) -> None:
        if type(config) is not HostedConfig or config.component is not Component.API:
            raise ValueError("hosted recovery gateway requires API configuration")
        if type(transport) is not HostedHttpTransport:
            raise TypeError("hosted recovery gateway requires exact transport")
        if not isinstance(store, RecoveryRunStore):
            raise TypeError("hosted recovery gateway requires a recovery store")
        if (
            type(config.controller_url) is not str
            or not config.controller_url
            or type(config.controller_audience) is not str
            or not config.controller_audience
        ):
            raise ValueError("hosted recovery controller destination is incomplete")
        if (
            not isinstance(poll_interval_seconds, (int, float))
            or isinstance(poll_interval_seconds, bool)
            or poll_interval_seconds <= 0
        ):
            raise ValueError("hosted recovery poll interval is invalid")
        if type(acceptance_partial_read_outage_enabled) is not bool:
            raise TypeError("partial-read acceptance state must be boolean")
        self._endpoint = f"{config.controller_url}{_RECOVERY_PATH}"
        self._audience = config.controller_audience
        self._transport = transport
        self._store = store
        self._poll = float(poll_interval_seconds)
        self._operating_profile = config.operating_profile
        self._acceptance_partial_read_outage_enabled = (
            acceptance_partial_read_outage_enabled
        )

    async def launch(
        self,
        request: RecoveryRunRequest,
    ) -> RecoveryRunLaunchResult:
        return await self.launch_and_wait_result(request)

    async def launch_and_wait_result(
        self,
        recovery: RecoveryRunRequest,
    ) -> RecoveryRunLaunchResult:
        if type(recovery) is not RecoveryRunRequest:
            raise TypeError("hosted recovery launch requires an exact request")
        if (
            self._operating_profile == "production"
            and recovery.fault is not RecoveryRunFault.NO_FAULT
        ):
            raise HostedRecoveryGatewayError from None
        if (
            recovery.fault
            is RecoveryRunFault.ACCEPTANCE_DROP_AFTER_ACCEPT_PARTIAL_READ_OUTAGE
            and not self._acceptance_partial_read_outage_enabled
        ):
            raise HostedRecoveryGatewayError from None
        request = _recovery_request(recovery)
        try:
            response = await self._transport.request(
                "POST",
                self._endpoint,
                audience=self._audience,
                content=canonical_internal_json_bytes(request),
            )
            if (
                type(response) is HostedHttpResponse
                and response.status_code == HTTPStatus.CONFLICT
            ):
                raise RecoveryRunConflict(recovery.run_id)
            decoded = HostedHttpWorkflowGateway._decode_response(response, request)
            receipt = HostedRecoveryReceipt.model_validate_json(
                canonical_json_value_bytes(decoded.payload)
            )
            snapshot = await self._store.get(recovery.run_id)
            if (
                decoded.payload != receipt.model_dump(mode="json")
                or receipt.run_id != recovery.run_id
                or receipt.request_sha256 != canonical_sha256(recovery)
                or type(receipt.created) is not bool
                or type(snapshot) is not RecoveryRunSnapshot
                or snapshot.request != recovery
                or snapshot.request_sha256 != receipt.request_sha256
                or canonical_sha256(snapshot) != receipt.snapshot_sha256
                or not is_terminal_recovery_run(snapshot.lifecycle)
            ):
                raise ValueError
            return RecoveryRunLaunchResult(
                snapshot=snapshot,
                created=receipt.created,
            )
        except asyncio.CancelledError:
            raise
        except RecoveryRunConflict:
            raise
        except Exception:
            raise HostedRecoveryGatewayError from None

    async def get(self, run_id: str) -> RecoveryRunSnapshot:
        return await self._store.get(run_id)

    async def snapshot(
        self,
        run_id: str,
        *,
        after: int = 0,
    ) -> RecoveryRunEventSnapshot:
        return await self._store.events(run_id, after=after)

    async def wait_for_events(
        self,
        run_id: str,
        *,
        after: int = 0,
        cancellation_event: asyncio.Event | None = None,
    ) -> RecoveryRunEventSnapshot:
        while True:
            snapshot = await self.snapshot(run_id, after=after)
            if snapshot.events or snapshot.terminal:
                return snapshot
            if cancellation_event is not None and cancellation_event.is_set():
                return snapshot
            await asyncio.sleep(self._poll)

    async def aclose(self) -> None:
        return None


__all__ = [
    "HOSTED_INVESTIGATION_RECEIPT_VERSION",
    "HOSTED_RECOVERY_RECEIPT_VERSION",
    "DurableRuntimeReportLoader",
    "FirestoreHostedOperationScopeAuthorizer",
    "HostedHttpWorkflowGateway",
    "HostedInvestigationDispatcher",
    "HostedInvestigationHandler",
    "HostedInvestigationReceipt",
    "HostedOperationDispatcher",
    "HostedOperationHandler",
    "HostedOperationScopeAuthorizer",
    "HostedRecoveryGatewayError",
    "HostedRecoveryHandler",
    "HostedRecoveryReceipt",
    "HostedRecoveryRunGateway",
    "HostedRecoveryService",
    "HostedReportLoader",
    "HostedWorkflowGatewayError",
]
