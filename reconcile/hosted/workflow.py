"""Request-scoped hosted scenario orchestration over durable Firestore authority."""

from __future__ import annotations

import asyncio
import hashlib
from collections.abc import Callable
from contextlib import asynccontextmanager
from datetime import UTC, datetime
from enum import StrEnum
from typing import Literal, Protocol
from uuid import uuid4

from pydantic import Field, model_validator

from reconcile.contracts.base import Identifier, Sha256Digest, StrictModel
from reconcile.contracts.codec import canonical_json_bytes, canonical_sha256
from reconcile.contracts.common import AmbiguityKind, AmbiguousExecution
from reconcile.contracts.envelope import ExecutionEnvelope
from reconcile.contracts.operational import (
    SCENARIO_OPERATIONAL_STATUS_VERSION,
    ScenarioOperationalCleanupState,
    ScenarioOperationalInvestigationState,
    ScenarioOperationalMutationState,
    ScenarioOperationalRecoveryState,
    ScenarioOperationalStatus,
)
from reconcile.contracts.operator import (
    ScenarioLaunchRequest,
    ScenarioRunEvent,
    ScenarioRunSnapshot,
)
from reconcile.contracts.report import InvestigationReport, InvestigationStatus
from reconcile.contracts.scenario import (
    SCENARIO_FAULT_TRACE_VERSION,
    SCENARIO_RUN_RESULT_VERSION,
    ScenarioCallerObservation,
    ScenarioFaultAction,
    ScenarioFaultPoint,
    ScenarioFaultTrace,
    ScenarioFixtureRef,
    ScenarioRunRequest,
    ScenarioRunResult,
    ScenarioTraceEvent,
    ScenarioTransportEvent,
    ScenarioWorkerTermination,
)
from reconcile.persistence.durable import CleanupStatus
from reconcile.persistence.scenarios import (
    CreateScenarioWorkResult,
    ScenarioInvestigationState,
    ScenarioLeaseToken,
    ScenarioMutationState,
    ScenarioStore,
    ScenarioWorkItem,
)
from reconcile.progress import EnvelopeProgress, ProgressCallback
from reconcile.scenarios.service import (
    ScenarioMode,
    ScenarioName,
    ScenarioWorkflowError,
    ScenarioWorkflowErrorCategory,
    _envelope_summary,
    _request,
)

HOSTED_SCENARIO_PREPARATION_VERSION = "reconcile/hosted-scenario-preparation/v1"
HOSTED_OPERATION_SCOPE_VERSION = "reconcile/hosted-operation-scope/v1"
HOSTED_OPERATION_RECEIPT_VERSION = "reconcile/hosted-operation-receipt/v1"
HOSTED_INVESTIGATION_RESULT_VERSION = "reconcile/hosted-investigation-result/v1"

_HEARTBEAT_SECONDS = 5.0
_RENEWAL_WINDOW_SECONDS = 20.0


def _aware_utc(value: datetime) -> datetime:
    if (
        not isinstance(value, datetime)
        or value.tzinfo is None
        or value.utcoffset() is None
    ):
        raise ValueError("hosted workflow timestamps must be timezone-aware")
    return value.astimezone(UTC)


class HostedWorkflowOperation(StrEnum):
    EXECUTE_FAULT = "execute-fault"
    INVESTIGATE = "investigate"
    CLEANUP = "cleanup"


class HostedScenarioPreparation(StrictModel):
    """Canonical envelope and bounded cleanup scope sealed before dispatch."""

    schema_version: Literal["reconcile/hosted-scenario-preparation/v1"]
    namespace_id: Identifier
    execution_envelope: ExecutionEnvelope
    cleanup_resource_ids: tuple[str, ...] = Field(min_length=1, max_length=8)

    @model_validator(mode="after")
    def validate_preparation(self) -> HostedScenarioPreparation:
        if type(self.execution_envelope) is not ExecutionEnvelope:
            raise ValueError("hosted preparation requires an exact envelope")
        if any(
            type(item) is not str or not 1 <= len(item) <= 256
            for item in self.cleanup_resource_ids
        ) or len(self.cleanup_resource_ids) != len(set(self.cleanup_resource_ids)):
            raise ValueError("hosted cleanup resource identities must be unique")
        return self

    @property
    def envelope_bytes(self) -> bytes:
        return canonical_json_bytes(self.execution_envelope)  # type: ignore[arg-type]

    @property
    def envelope_sha256(self) -> str:
        return hashlib.sha256(self.envelope_bytes).hexdigest()

    @property
    def cleanup_manifest_sha256(self) -> str:
        from reconcile.contracts.base import canonical_json_value_bytes

        return hashlib.sha256(
            canonical_json_value_bytes(
                {"resource_ids": list(self.cleanup_resource_ids)}
            )
        ).hexdigest()


class HostedOperationScope(StrictModel):
    """Exact identifier, digest, and fence set sent to one internal operation."""

    schema_version: Literal["reconcile/hosted-operation-scope/v1"]
    operation: HostedWorkflowOperation
    launch_id: Identifier
    launch_sha256: Sha256Digest
    scenario_request_sha256: Sha256Digest
    investigation_id: Identifier
    operation_id: Identifier
    invocation_id: Identifier
    function_call_id: Identifier
    envelope_sha256: Sha256Digest
    cleanup_manifest_sha256: Sha256Digest
    lease_fence: int = Field(ge=1, le=2**63 - 1)

    @property
    def sha256(self) -> str:
        return canonical_sha256(self)


class HostedOperationReceipt(StrictModel):
    """Small response identity for mutation or cleanup; never target evidence."""

    schema_version: Literal["reconcile/hosted-operation-receipt/v1"]
    operation: HostedWorkflowOperation
    scope_sha256: Sha256Digest
    started_at: datetime
    completed_at: datetime

    @model_validator(mode="after")
    def validate_times(self) -> HostedOperationReceipt:
        started = _aware_utc(self.started_at)
        completed = _aware_utc(self.completed_at)
        if completed < started:
            raise ValueError("hosted operation completion precedes its start")
        return self


class HostedInvestigationResult(StrictModel):
    """Controller result bound to the exact request scope."""

    schema_version: Literal["reconcile/hosted-investigation-result/v1"]
    scope_sha256: Sha256Digest
    report: InvestigationReport


class HostedScenarioPreparer(Protocol):
    def __call__(
        self,
        request: ScenarioRunRequest,
        *,
        invoked_at: datetime,
    ) -> HostedScenarioPreparation: ...


class HostedWorkflowGateway(Protocol):
    """Authenticated component calls; implementations may load results by digest."""

    async def execute_fault(
        self,
        scope: HostedOperationScope,
    ) -> HostedOperationReceipt: ...

    async def investigate(
        self,
        scope: HostedOperationScope,
    ) -> HostedInvestigationResult: ...

    async def cleanup(
        self,
        scope: HostedOperationScope,
    ) -> HostedOperationReceipt: ...


class _RequestAuthority:
    def __init__(
        self,
        store: ScenarioStore,
        token: ScenarioLeaseToken,
        clock: Callable[[], datetime],
    ) -> None:
        self.store = store
        self.token = token
        self.clock = clock
        self._lock = asyncio.Lock()
        self._released = False

    @asynccontextmanager
    async def hold(self):
        async with self._lock:
            if self._released:
                raise RuntimeError("hosted workflow authority was released")
            now = max(_aware_utc(self.clock()), self.token.renewed_at)
            if now >= self.token.expires_at:
                raise RuntimeError("hosted workflow authority expired")
            if (self.token.expires_at - now).total_seconds() <= (
                _RENEWAL_WINDOW_SECONDS
            ):
                self.token = await self.store.renew_scenario_lease(
                    self.token,
                    now=now,
                )
            yield self.token

    async def heartbeat(self, stopped: asyncio.Event) -> None:
        while not stopped.is_set():
            try:
                await asyncio.wait_for(stopped.wait(), timeout=_HEARTBEAT_SECONDS)
            except TimeoutError:
                async with self.hold():
                    pass

    async def release(self) -> None:
        async with self._lock:
            if self._released:
                return
            now = max(_aware_utc(self.clock()), self.token.renewed_at)
            await self.store.release_scenario_lease(self.token, now=now)
            self._released = True


def _strategy_sha256(scenario: ScenarioName, mode: ScenarioMode) -> str:
    from reconcile.contracts.base import canonical_json_value_bytes

    return hashlib.sha256(
        canonical_json_value_bytes(
            {
                "mode": mode.value,
                "scenario": scenario.value,
                "version": "hosted-request-scoped-strategy-v1",
            }
        )
    ).hexdigest()


def _workspace_id(investigation_id: str) -> str:
    digest = hashlib.sha256(investigation_id.encode("utf-8")).hexdigest()
    return f"hosted-scope-{digest[:32]}"


def _scenario(value: object) -> ScenarioName:
    try:
        return ScenarioName(value.value)  # type: ignore[union-attr]
    except (AttributeError, ValueError):
        raise ValueError("hosted workflow scenario is unsupported") from None


def _mode(value: object) -> ScenarioMode:
    try:
        return ScenarioMode(value.value)  # type: ignore[union-attr]
    except (AttributeError, ValueError):
        raise ValueError("hosted workflow mode is unsupported") from None


def _workflow_failure(
    scenario: ScenarioName,
    category: ScenarioWorkflowErrorCategory = (
        ScenarioWorkflowErrorCategory.SCENARIO_EXECUTION_FAILED
    ),
) -> ScenarioWorkflowError:
    return ScenarioWorkflowError(category, scenario=scenario)


class HostedScenarioWorkflow:
    """Own exactly one launch for exactly one API request, then release it."""

    def __init__(
        self,
        store: ScenarioStore,
        preparer: HostedScenarioPreparer,
        gateway: HostedWorkflowGateway,
        *,
        semantic_config_sha256: str,
        runtime_provenance_sha256: str,
        provider_available: bool,
        owner_id: str = "hosted-api",
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        if not isinstance(store, ScenarioStore):
            raise TypeError("hosted workflow requires a complete scenario store")
        if not callable(preparer):
            raise TypeError("hosted workflow requires a deterministic preparer")
        if any(
            not callable(getattr(gateway, name, None))
            for name in ("execute_fault", "investigate", "cleanup")
        ):
            raise TypeError("hosted workflow gateway is incomplete")
        for value, label in (
            (semantic_config_sha256, "semantic configuration"),
            (runtime_provenance_sha256, "runtime provenance"),
        ):
            if (
                type(value) is not str
                or len(value) != 64
                or any(character not in "0123456789abcdef" for character in value)
            ):
                raise ValueError(f"hosted {label} must be a SHA-256 digest")
        if type(provider_available) is not bool:
            raise TypeError("hosted provider availability must be boolean")
        if (
            type(owner_id) is not str
            or not owner_id
            or len(owner_id) > 64
            or not owner_id.replace("-", "").isalnum()
        ):
            raise ValueError("hosted workflow owner identity is invalid")
        self._store = store
        self._preparer = preparer
        self._gateway = gateway
        self._semantic_config_sha256 = semantic_config_sha256
        self._runtime_provenance_sha256 = runtime_provenance_sha256
        self._provider_available = provider_available
        self._owner_id = owner_id
        self._clock = clock or (lambda: datetime.now(UTC))

    @property
    def provider_available(self) -> bool:
        return self._provider_available

    def _now(self, *, not_before: datetime | None = None) -> datetime:
        now = _aware_utc(self._clock())
        return now if not_before is None else max(now, _aware_utc(not_before))

    async def bind_launch(
        self,
        launch: ScenarioLaunchRequest,
        *,
        snapshot: ScenarioRunSnapshot,
        accepted_event: ScenarioRunEvent,
    ) -> CreateScenarioWorkResult:
        if type(launch) is not ScenarioLaunchRequest:
            raise TypeError("hosted launch must be exact")
        scenario = _scenario(launch.scenario)
        mode = _mode(launch.mode)
        if mode is ScenarioMode.COMPARE:
            raise ValueError("hosted comparison is not an accepted Phase 5 mode")
        request = _request(scenario, launch.launch_id)
        if (
            snapshot.investigation_id != request.investigation_id
            or accepted_event.investigation_id != request.investigation_id
            or snapshot.event_cursor != 1
            or accepted_event.cursor != 1
        ):
            raise ValueError("hosted launch projection identity is invalid")
        return await self._store.create_work(
            launch,
            request,
            strategy_sha256=_strategy_sha256(scenario, mode),
            semantic_config_sha256=self._semantic_config_sha256,
            runtime_provenance_sha256=self._runtime_provenance_sha256,
            workspace_id=_workspace_id(request.investigation_id),
            invoked_at=snapshot.accepted_at,
            snapshot=snapshot,
            accepted_event=accepted_event,
            created_at=snapshot.accepted_at,
        )

    def _validate_work(
        self,
        work: ScenarioWorkItem,
        scenario: ScenarioName,
        mode: ScenarioMode,
    ) -> None:
        if (
            work.strategy_sha256 != _strategy_sha256(scenario, mode)
            or work.semantic_config_sha256 != self._semantic_config_sha256
            or work.runtime_provenance_sha256 != self._runtime_provenance_sha256
            or work.workspace_id
            != _workspace_id(work.scenario_request.investigation_id)
        ):
            raise _workflow_failure(scenario)

    async def get_operational_status(
        self,
        investigation_id: str,
    ) -> ScenarioOperationalStatus:
        work = await self._store.get_work(investigation_id)
        scenario = _scenario(work.launch_request.scenario)
        self._validate_work(work, scenario, _mode(work.launch_request.mode))
        return ScenarioOperationalStatus(
            schema_version=SCENARIO_OPERATIONAL_STATUS_VERSION,
            launch_id=work.launch_request.launch_id,
            investigation_id=work.scenario_request.investigation_id,
            scenario=work.launch_request.scenario,
            mode=work.launch_request.mode,
            revision=work.revision,
            mutation_state=ScenarioOperationalMutationState(work.mutation_state.value),
            investigation_state=ScenarioOperationalInvestigationState(
                work.investigation_state.value
            ),
            cleanup_state=ScenarioOperationalCleanupState(work.cleanup_status.value),
            recovery_state=(
                ScenarioOperationalRecoveryState.HUMAN_ESCALATION_REQUIRED
                if work.investigation_state
                is ScenarioInvestigationState.ESCALATION_REQUIRED
                else ScenarioOperationalRecoveryState.NOT_ESCALATED
            ),
            updated_at=work.updated_at,
        )

    async def audit_terminal_projection(self, investigation_id: str) -> None:
        work = await self._store.get_work(investigation_id)
        projection = await self._store.snapshot_projection(investigation_id)
        if not projection.terminal or (
            work.investigation_state
            not in {
                ScenarioInvestigationState.RECORDED,
                ScenarioInvestigationState.ESCALATION_REQUIRED,
            }
        ):
            raise RuntimeError("hosted terminal projection contradicts authority")

    def _scope(
        self,
        work: ScenarioWorkItem,
        token: ScenarioLeaseToken,
        operation: HostedWorkflowOperation,
    ) -> HostedOperationScope:
        envelope_sha256 = (
            work.prepared_envelope_sha256
            if operation is HostedWorkflowOperation.EXECUTE_FAULT
            else work.envelope_sha256
        )
        if (
            envelope_sha256 is None
            or work.cleanup_manifest_sha256 is None
            or work.scenario_request.function_call_id is None
        ):
            raise RuntimeError("hosted operation scope is incomplete")
        request = work.scenario_request
        return HostedOperationScope(
            schema_version=HOSTED_OPERATION_SCOPE_VERSION,
            operation=operation,
            launch_id=work.launch_request.launch_id,
            launch_sha256=work.launch_sha256,
            scenario_request_sha256=work.scenario_request_sha256,
            investigation_id=request.investigation_id,
            operation_id=request.operation_id,
            invocation_id=request.invocation_id,
            function_call_id=request.function_call_id,
            envelope_sha256=envelope_sha256,
            cleanup_manifest_sha256=work.cleanup_manifest_sha256,
            lease_fence=token.fence,
        )

    @staticmethod
    def _validate_receipt(
        receipt: object,
        scope: HostedOperationScope,
    ) -> HostedOperationReceipt:
        if (
            type(receipt) is not HostedOperationReceipt
            or receipt.operation is not scope.operation
            or receipt.scope_sha256 != scope.sha256
        ):
            raise RuntimeError("hosted operation receipt is invalid")
        return receipt

    @staticmethod
    def _mutation_result(
        work: ScenarioWorkItem,
        preparation: HostedScenarioPreparation,
        receipt: HostedOperationReceipt,
    ) -> ScenarioRunResult:
        request = work.scenario_request
        if (
            request.fault.point is not ScenarioFaultPoint.POST_COMMIT
            or request.fault.action is not ScenarioFaultAction.INTERRUPT_PROCESS
        ):
            raise ValueError("hosted mutation requires the frozen ambiguity profile")
        started_at = _aware_utc(receipt.started_at)
        completed_at = _aware_utc(receipt.completed_at)
        events = (
            ScenarioTransportEvent.RUN_STARTED,
            ScenarioTransportEvent.DISPATCH_STARTED,
            ScenarioTransportEvent.PRE_COMMIT_REACHED,
            ScenarioTransportEvent.POST_COMMIT_REACHED,
            ScenarioTransportEvent.WORKER_INTERRUPTED,
            ScenarioTransportEvent.RUN_COMPLETED,
        )
        timestamps = (
            started_at,
            started_at,
            started_at,
            completed_at,
            completed_at,
            completed_at,
        )
        trace = ScenarioFaultTrace(
            schema_version=SCENARIO_FAULT_TRACE_VERSION,
            scenario=request.scenario,
            run_id=request.run_id,
            investigation_id=request.investigation_id,
            operation_id=request.operation_id,
            invocation_id=request.invocation_id,
            function_call_id=request.function_call_id,
            configured_fault=request.fault,
            events=tuple(
                ScenarioTraceEvent(
                    sequence=index,
                    event=event,
                    occurred_at=occurred_at,
                )
                for index, (event, occurred_at) in enumerate(
                    zip(events, timestamps, strict=True),
                    1,
                )
            ),
            caller_observation=ScenarioCallerObservation.NO_RESPONSE,
            worker_termination=ScenarioWorkerTermination.SIGNALED,
            signal=9,
            applied_delay_ms=0,
            started_at=started_at,
            completed_at=completed_at,
        )
        envelope = preparation.execution_envelope.model_copy(  # type: ignore[union-attr]
            update={
                "ambiguity": AmbiguousExecution(
                    kind=AmbiguityKind.PROCESS_INTERRUPTED,
                    observed_at=completed_at,
                    detail=(
                        "The bounded hosted fault boundary completed its target "
                        "dispatch without delivering the original tool response."
                    ),
                )
            }
        )
        return ScenarioRunResult(
            schema_version=SCENARIO_RUN_RESULT_VERSION,
            request_sha256=work.scenario_request_sha256,
            scenario=request.scenario,
            run_id=request.run_id,
            investigation_id=request.investigation_id,
            operation_id=request.operation_id,
            invocation_id=request.invocation_id,
            function_call_id=request.function_call_id,
            fixture=ScenarioFixtureRef(
                namespace_id=preparation.namespace_id,
                cleanup_manifest_sha256=preparation.cleanup_manifest_sha256,
            ),
            trace=trace,
            execution_envelope=envelope,
        )

    async def _record_cleanup_failure(
        self,
        authority: _RequestAuthority,
        failure_code: str,
    ) -> ScenarioWorkItem:
        async with authority.hold() as token:
            return await self._store.record_scenario_cleanup(
                token,
                CleanupStatus.FAILED,
                occurred_at=self._now(),
                failure_code=failure_code,
            )

    async def _require_escalation(
        self,
        authority: _RequestAuthority,
        failure_code: str,
    ) -> None:
        async with authority.hold() as token:
            await self._store.require_scenario_escalation(
                token,
                failure_code,
                occurred_at=self._now(),
            )

    async def _cleanup(
        self,
        work: ScenarioWorkItem,
        authority: _RequestAuthority,
        scenario: ScenarioName,
    ) -> None:
        if work.cleanup_status in {CleanupStatus.SUCCEEDED, CleanupStatus.FAILED}:
            return
        if work.cleanup_status is CleanupStatus.PENDING:
            await self._record_cleanup_failure(authority, "cleanup-outcome-unknown")
            return
        async with authority.hold() as token:
            work = await self._store.record_scenario_cleanup(
                token,
                CleanupStatus.PENDING,
                occurred_at=self._now(not_before=work.updated_at),
            )
            scope = self._scope(work, token, HostedWorkflowOperation.CLEANUP)
        try:
            receipt = await self._gateway.cleanup(scope)
            self._validate_receipt(receipt, scope)
        except asyncio.CancelledError:
            try:
                await asyncio.shield(
                    self._record_cleanup_failure(
                        authority,
                        "cleanup-outcome-unknown",
                    )
                )
            finally:
                raise
        except Exception:
            await self._record_cleanup_failure(authority, "cleanup-failed")
            return
        async with authority.hold() as token:
            await self._store.record_scenario_cleanup(
                token,
                CleanupStatus.SUCCEEDED,
                occurred_at=self._now(not_before=receipt.completed_at),
            )

    async def _run_owned(
        self,
        work: ScenarioWorkItem,
        authority: _RequestAuthority,
        scenario: ScenarioName,
        mode: ScenarioMode,
        progress_callback: ProgressCallback | None,
    ) -> InvestigationReport:
        self._validate_work(work, scenario, mode)
        if work.investigation_state is ScenarioInvestigationState.ESCALATION_REQUIRED:
            raise _workflow_failure(scenario)
        if work.workflow_result is not None:
            if type(work.workflow_result) is not InvestigationReport:
                raise _workflow_failure(scenario)
            await self._cleanup(work, authority, scenario)
            return work.workflow_result
        if work.mutation_state is ScenarioMutationState.STARTED:
            async with authority.hold() as token:
                await self._store.require_scenario_escalation(
                    token,
                    "mutation-outcome-unknown",
                    occurred_at=self._now(not_before=work.updated_at),
                )
            raise _workflow_failure(scenario)

        preparation: HostedScenarioPreparation | None = None
        if work.mutation_state is ScenarioMutationState.NOT_STARTED:
            try:
                preparation = self._preparer(
                    work.scenario_request,
                    invoked_at=work.invoked_at,
                )
                if type(preparation) is not HostedScenarioPreparation:
                    raise RuntimeError("hosted scenario preparation is invalid")
                envelope = preparation.execution_envelope
                request = work.scenario_request
                invocation = envelope.context.invocation
                if (
                    envelope.investigation_id != request.investigation_id
                    or envelope.operation_id != request.operation_id
                    or invocation.invocation_id != request.invocation_id
                    or invocation.function_call_id != request.function_call_id
                ):
                    raise RuntimeError("hosted scenario preparation identity changed")
            except asyncio.CancelledError:
                raise
            except Exception:
                await self._require_escalation(authority, "preparation-failed")
                raise _workflow_failure(scenario) from None
            try:
                async with authority.hold() as token:
                    work = await self._store.record_mutation_started(
                        token,
                        prepared_envelope=envelope,
                        prepared_envelope_sha256=preparation.envelope_sha256,
                        cleanup_manifest_sha256=preparation.cleanup_manifest_sha256,
                        occurred_at=self._now(not_before=work.updated_at),
                    )
                    scope = self._scope(
                        work,
                        token,
                        HostedWorkflowOperation.EXECUTE_FAULT,
                    )
                receipt = self._validate_receipt(
                    await self._gateway.execute_fault(scope),
                    scope,
                )
                result = self._mutation_result(work, preparation, receipt)
                async with authority.hold() as token:
                    work = await self._store.record_mutation_result(
                        token,
                        result,
                        prepared_envelope_bytes=preparation.envelope_bytes,
                        occurred_at=self._now(not_before=receipt.completed_at),
                    )
            except asyncio.CancelledError:
                await asyncio.shield(
                    self._require_escalation(
                        authority,
                        "mutation-outcome-unknown",
                    )
                )
                raise
            except Exception:
                await self._require_escalation(
                    authority,
                    "mutation-outcome-unknown",
                )
                raise _workflow_failure(scenario) from None

        result = work.scenario_result
        if result is None or result.execution_envelope is None:
            raise _workflow_failure(scenario)
        envelope = result.execution_envelope
        if progress_callback is not None:
            await progress_callback(
                EnvelopeProgress(
                    occurred_at=self._now(not_before=work.updated_at),
                    investigation_id=work.scenario_request.investigation_id,
                    summary=_envelope_summary(envelope),
                )
            )
        if work.investigation_state is ScenarioInvestigationState.NOT_STARTED:
            async with authority.hold() as token:
                work = await self._store.mark_investigation_started(
                    token,
                    occurred_at=self._now(not_before=work.updated_at),
                )
        if work.investigation_state is not ScenarioInvestigationState.STARTED:
            raise _workflow_failure(scenario)
        async with authority.hold() as token:
            scope = self._scope(work, token, HostedWorkflowOperation.INVESTIGATE)
        try:
            investigated = await self._gateway.investigate(scope)
            if (
                type(investigated) is not HostedInvestigationResult
                or investigated.scope_sha256 != scope.sha256
            ):
                raise RuntimeError("hosted investigation result is invalid")
            report = investigated.report
            if (
                report.status is not InvestigationStatus.COMPLETED
                or report.investigation_id != work.scenario_request.investigation_id
                or report.envelope_sha256 != work.envelope_sha256
                or report.classification is None
            ):
                raise RuntimeError("hosted investigation report is invalid")
            async with authority.hold() as token:
                work = await self._store.record_workflow_result(
                    token,
                    report,
                    occurred_at=self._now(not_before=report.updated_at),
                )
        except asyncio.CancelledError:
            raise
        except Exception:
            await self._require_escalation(
                authority,
                "investigation-failed",
            )
            raise _workflow_failure(scenario) from None
        await self._cleanup(work, authority, scenario)
        return report

    async def __call__(
        self,
        scenario: ScenarioName,
        mode: ScenarioMode,
        *,
        vertex_config: object | None,
        run_id: str,
        progress_callback: ProgressCallback | None,
        cancellation_event: asyncio.Event | None,
    ) -> InvestigationReport:
        del vertex_config
        if type(scenario) is not ScenarioName or type(mode) is not ScenarioMode:
            raise _workflow_failure(
                ScenarioName.STORAGE,
                ScenarioWorkflowErrorCategory.INVALID_CONFIGURATION,
            )
        request = _request(scenario, run_id)
        if cancellation_event is not None and cancellation_event.is_set():
            raise asyncio.CancelledError
        work = await self._store.get_work(request.investigation_id)
        owner_material = f"{self._owner_id}:{uuid4().hex}".encode()
        owner = f"hosted-{hashlib.sha256(owner_material).hexdigest()[:32]}"
        try:
            token = await self._store.acquire_scenario_lease(
                request.investigation_id,
                owner,
                now=self._now(),
            )
        except asyncio.CancelledError:
            raise
        except Exception:
            raise _workflow_failure(scenario) from None
        authority = _RequestAuthority(self._store, token, self._clock)
        stopped = asyncio.Event()
        heartbeat = asyncio.create_task(
            authority.heartbeat(stopped),
            name=f"reconcile-hosted-heartbeat-{request.investigation_id}",
        )
        try:
            work = await self._store.get_work(request.investigation_id)
            return await self._run_owned(
                work,
                authority,
                scenario,
                mode,
                progress_callback,
            )
        finally:
            stopped.set()
            heartbeat.cancel()
            await asyncio.gather(heartbeat, return_exceptions=True)
            release = asyncio.create_task(authority.release())
            interrupted = False
            while True:
                try:
                    await asyncio.shield(release)
                    break
                except asyncio.CancelledError:
                    if release.done():
                        await release
                        raise
                    interrupted = True
            if interrupted:
                raise asyncio.CancelledError


__all__ = [
    "HOSTED_INVESTIGATION_RESULT_VERSION",
    "HOSTED_OPERATION_RECEIPT_VERSION",
    "HOSTED_OPERATION_SCOPE_VERSION",
    "HOSTED_SCENARIO_PREPARATION_VERSION",
    "HostedInvestigationResult",
    "HostedOperationReceipt",
    "HostedOperationScope",
    "HostedScenarioPreparation",
    "HostedScenarioPreparer",
    "HostedScenarioWorkflow",
    "HostedWorkflowGateway",
    "HostedWorkflowOperation",
]
