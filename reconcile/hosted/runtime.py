"""Production assembly for the bounded four-component hosted prototype."""

from __future__ import annotations

import asyncio
import inspect
from collections.abc import Callable, Mapping
from contextlib import suppress
from datetime import UTC, datetime
from http import HTTPStatus
from typing import Protocol

from reconcile.adapters.sandbox_order import (
    SANDBOX_ORDER_CLOUD_PROFILE,
    build_sandbox_order_target,
)
from reconcile.adaptive import AdvisoryPlanner, AdvisoryPlannerMetadata
from reconcile.adk_planner import (
    ADK_PLANNER_PROMPT_SHA256,
    ADK_PLANNER_PROMPT_VERSION,
    AdkGeminiPlanner,
    VertexAdcPlannerConfig,
)
from reconcile.contracts.base import canonical_json_value_bytes
from reconcile.contracts.codec import (
    canonical_json_bytes,
    canonical_sha256,
    decode_contract,
)
from reconcile.contracts.envelope import ExecutionEnvelope
from reconcile.contracts.recovery_run import RecoveryRunRequest
from reconcile.contracts.report import InvestigationStatus
from reconcile.controller.permits import PermitAuthority
from reconcile.durable_application import (
    DurableExecutionContext,
    DurableExecutionOutcome,
    DurableExecutionStrategy,
    DurableInvestigationApplicationService,
)
from reconcile.durable_planner import DurableAdvisoryPlanner
from reconcile.hosted.apps import InternalOperationHandler, create_component_app
from reconcile.hosted.cloud_run_canary import (
    CloudRunCanaryActionAdapter,
    CloudRunCanaryFaultProxy,
    CloudRunCanaryReader,
    CloudRunCanaryTarget,
)
from reconcile.hosted.cloud_run_fault import RecoveryCloudRunCanaryActionAuthorizer
from reconcile.hosted.config import Component, HostedConfig
from reconcile.hosted.contracts import (
    INTERNAL_OPERATION_REQUEST_VERSION,
    InternalOperation,
    InternalOperationRequest,
    InternalOperationResponse,
    canonical_internal_json_bytes,
)
from reconcile.hosted.firestore_business import (
    GoogleFirestoreBusinessCleanupTarget,
    GoogleFirestoreBusinessMutationTarget,
    GoogleFirestoreBusinessReadTarget,
    build_google_firestore_business_targets,
)
from reconcile.hosted.firestore_cas import GoogleFirestoreCasStore
from reconcile.hosted.firestore_permits import FirestoreActionPermitStore
from reconcile.hosted.firestore_provider_ledger import FirestoreHostedProviderLedger
from reconcile.hosted.firestore_recovery_runs import FirestoreRecoveryRunStore
from reconcile.hosted.firestore_release import GoogleFirestoreReleaseTarget
from reconcile.hosted.firestore_release_action import (
    RecoveryFirestoreReleaseActionAuthorizer,
)
from reconcile.hosted.firestore_runtime import FirestoreDurableRuntimeStore
from reconcile.hosted.firestore_scenarios import (
    FirestoreScenarioOperationAuthority,
    FirestoreScenarioStore,
)
from reconcile.hosted.operations import (
    DurableRuntimeReportLoader,
    FirestoreHostedOperationScopeAuthorizer,
    HostedHttpWorkflowGateway,
    HostedInvestigationHandler,
    HostedOperationHandler,
    HostedRecoveryHandler,
    HostedRecoveryRunGateway,
    HostedWorkflowGatewayError,
)
from reconcile.hosted.planner import HostedGeminiPlanner
from reconcile.hosted.provider import (
    HOSTED_CANDIDATE_IDENTITY_VERSION,
    HostedCandidateIdentity,
)
from reconcile.hosted.recovery_dispatch import HostedRecoveryDispatchGateway
from reconcile.hosted.sandbox import (
    FirestoreSandboxEvidenceReader,
    HostedSandboxEvidenceTarget,
)
from reconcile.hosted.sandbox_mutation import (
    GoogleFirestoreSandboxCleanupTarget,
    GoogleFirestoreSandboxMutationTarget,
    build_google_firestore_sandbox_targets,
)
from reconcile.hosted.scenario_material import (
    DeterministicHostedScenarioPreparer,
    HostedFirestoreBusinessMaterial,
    HostedSandboxOrderMaterial,
    HostedScenarioMaterial,
    HostedStorageMaterial,
    build_hosted_scenario_material,
)
from reconcile.hosted.storage import (
    CloudStorageCleanupTarget,
    CloudStorageMutationTarget,
    CloudStorageReadTarget,
)
from reconcile.hosted.transport import (
    HostedHttpResponse,
    HostedHttpTransport,
    HostedRequestError,
    HostedTransportError,
)
from reconcile.hosted.workflow import (
    HOSTED_INVESTIGATION_RESULT_VERSION,
    HOSTED_OPERATION_RECEIPT_VERSION,
    HostedInvestigationResult,
    HostedOperationReceipt,
    HostedOperationScope,
    HostedScenarioWorkflow,
    HostedWorkflowOperation,
)
from reconcile.operator import OperatorApplicationService
from reconcile.persistence.scenarios import ScenarioWorkItem
from reconcile.recovery_agents import RecoveryAgent
from reconcile.recovery_scenario import (
    ReleaseChainSettings,
    build_release_chain_workflow,
)
from reconcile.recovery_workflow import (
    RecoveryRunApplicationService,
    RecoveryRunLaunchResult,
)
from reconcile.scenarios.firestore_business import (
    execute_cloud_firestore_business_baseline,
)
from reconcile.scenarios.local_order import HiddenOrderOutcome
from reconcile.scenarios.sandbox_order import (
    SANDBOX_ORDER_CONDITIONAL_POLICY,
    SandboxOrderInvestigationClock,
    execute_hosted_sandbox_order_fixed,
    execute_sandbox_order_conditional,
)
from reconcile.scenarios.service import (
    ScenarioMode,
    adaptive_result_requires_explicit_unknown,
    adaptive_result_requires_fixed_fallback,
    mark_bounded_hybrid_advisory,
    mark_bounded_hybrid_deterministic_fixed,
    mark_bounded_hybrid_explicit_unknown,
    mark_bounded_hybrid_fixed_fallback,
    mark_bounded_hybrid_preplanner_unknown,
    mark_bounded_hybrid_provider_cleanup_failure,
)
from reconcile.scenarios.storage import execute_cloud_storage_baseline

_SANDBOX_MUTATION_PATH = "/internal/v1/mutations"
_SANDBOX_CLEANUP_PATH = "/internal/v1/cleanup"
_PLANNER_ESTIMATED_COST_MICROUNITS = 1
_HOSTED_PROVIDER_TIMEOUT_SECONDS = 3.0
_HOSTED_RECOVERY_PROVIDER_TIMEOUT_SECONDS = 25.0

if (
    _HOSTED_PROVIDER_TIMEOUT_SECONDS * 1_000
    >= SANDBOX_ORDER_CONDITIONAL_POLICY.planner_timeout_ms
):
    raise RuntimeError("hosted provider timeout must precede planner timeout")


def _required(value: str | None, label: str) -> str:
    if type(value) is not str or not value:
        raise ValueError(f"hosted {label} is unavailable")
    return value


def _now() -> datetime:
    return datetime.now(UTC)


def build_hosted_candidate(config: HostedConfig) -> HostedCandidateIdentity:
    """Construct the same immutable candidate identity in every component."""

    if type(config) is not HostedConfig:
        raise TypeError("hosted candidate requires exact configuration")
    location = config.vertex_location or "us"
    model = config.vertex_model or "gemini-3.5-flash"
    prompt_version = config.vertex_prompt_version or ADK_PLANNER_PROMPT_VERSION
    prompt_sha256 = config.vertex_prompt_sha256 or ADK_PLANNER_PROMPT_SHA256
    count_attempts = config.vertex_max_count_tokens_attempts or 1
    generation_attempts = config.vertex_max_generation_attempts or 1
    maximum_input = config.vertex_max_input_tokens or 12_000
    maximum_output = config.vertex_max_output_tokens or 4_096
    thinking = config.vertex_thinking_level or "MINIMAL"
    candidate = HostedCandidateIdentity(
        schema_version=HOSTED_CANDIDATE_IDENTITY_VERSION,
        source_revision=config.source_revision,
        image_digest=config.image_digest,
        infrastructure_revision=config.infra_revision,
        semantic_config_sha256=config.semantic_config_sha256,
        project_id=config.project_id,
        vertex_location=location,
        configured_model=model,
        prompt_version=prompt_version,
        prompt_sha256=prompt_sha256,
        maximum_input_tokens=maximum_input,  # type: ignore[arg-type]
        maximum_output_tokens=maximum_output,  # type: ignore[arg-type]
        thinking_level=thinking,  # type: ignore[arg-type]
        maximum_count_tokens_attempts=count_attempts,  # type: ignore[arg-type]
        maximum_generation_attempts=generation_attempts,  # type: ignore[arg-type]
    )
    if (
        candidate.vertex_location != "us"
        or candidate.configured_model != "gemini-3.5-flash"
        or candidate.prompt_version != ADK_PLANNER_PROMPT_VERSION
        or candidate.prompt_sha256 != ADK_PLANNER_PROMPT_SHA256
    ):
        raise ValueError("hosted candidate planner identity drifted")
    return candidate


async def _owned_thread[Result](operation: Callable[[], Result]) -> Result:
    task = asyncio.create_task(asyncio.to_thread(operation))
    interrupted = False
    while True:
        try:
            await asyncio.shield(task)
            break
        except asyncio.CancelledError:
            if task.done():
                with suppress(asyncio.CancelledError):
                    task.exception()
                raise
            interrupted = True
    if interrupted:
        with suppress(asyncio.CancelledError):
            task.exception()
        raise asyncio.CancelledError
    return task.result()


def _operation_request(scope: HostedOperationScope) -> InternalOperationRequest:
    operation = {
        HostedWorkflowOperation.EXECUTE_FAULT: InternalOperation.EXECUTE_FAULT,
        HostedWorkflowOperation.CLEANUP: InternalOperation.CLEANUP,
    }.get(scope.operation)
    if operation is None:
        raise HostedWorkflowGatewayError from None
    return InternalOperationRequest(
        schema_version=INTERNAL_OPERATION_REQUEST_VERSION,
        request_id=f"hosted-{operation.value}-{scope.sha256[:32]}",
        operation=operation,
        payload=scope.model_dump(mode="json"),
    )


class HostedSandboxOperationGateway:
    """Forward only the sealed operation scope from fault proxy to sandbox."""

    def __init__(
        self,
        *,
        sandbox_url: str,
        sandbox_audience: str,
        transport: HostedHttpTransport,
    ) -> None:
        if type(transport) is not HostedHttpTransport:
            raise TypeError("sandbox operation gateway requires exact transport")
        self._sandbox_url = _required(sandbox_url, "sandbox URL")
        self._sandbox_audience = _required(sandbox_audience, "sandbox audience")
        self._transport = transport

    async def _call(self, scope: HostedOperationScope) -> HostedOperationReceipt:
        request = _operation_request(scope)
        path = (
            _SANDBOX_MUTATION_PATH
            if scope.operation is HostedWorkflowOperation.EXECUTE_FAULT
            else _SANDBOX_CLEANUP_PATH
        )
        try:
            response = await self._transport.request(
                "POST",
                f"{self._sandbox_url}{path}",
                audience=self._sandbox_audience,
                content=canonical_internal_json_bytes(request),
            )
            decoded = self._decode_response(response, request)
            receipt = HostedOperationReceipt.model_validate_json(
                canonical_json_value_bytes(decoded.payload)
            )
            if (
                decoded.payload != receipt.model_dump(mode="json")
                or receipt.operation is not scope.operation
                or receipt.scope_sha256 != scope.sha256
            ):
                raise ValueError
            return receipt
        except asyncio.CancelledError:
            raise
        except (HostedRequestError, HostedTransportError, TypeError, ValueError):
            raise HostedWorkflowGatewayError from None

    @staticmethod
    def _decode_response(
        response: HostedHttpResponse,
        request: InternalOperationRequest,
    ) -> InternalOperationResponse:
        if (
            type(response) is not HostedHttpResponse
            or response.status_code != HTTPStatus.OK
        ):
            raise ValueError("sandbox response is unavailable")
        decoded = decode_contract(response.content, InternalOperationResponse)
        if (
            response.content != canonical_internal_json_bytes(decoded)
            or decoded.request_id != request.request_id
            or decoded.operation is not request.operation
            or decoded.accepted is not True
        ):
            raise ValueError("sandbox response identity changed")
        return decoded

    async def execute_fault(
        self, scope: HostedOperationScope
    ) -> HostedOperationReceipt:
        if scope.operation is not HostedWorkflowOperation.EXECUTE_FAULT:
            raise HostedWorkflowGatewayError from None
        return await self._call(scope)

    async def cleanup(self, scope: HostedOperationScope) -> HostedOperationReceipt:
        if scope.operation is not HostedWorkflowOperation.CLEANUP:
            raise HostedWorkflowGatewayError from None
        return await self._call(scope)


class _ScenarioAuthorityStore(Protocol):
    async def operation_authority(
        self,
        investigation_id: str,
    ) -> FirestoreScenarioOperationAuthority: ...


async def _sealed_material(
    store: _ScenarioAuthorityStore,
    candidate: HostedCandidateIdentity,
    scope: HostedOperationScope,
    *,
    target_bucket: str,
) -> tuple[ScenarioWorkItem, HostedScenarioMaterial]:
    authority = await store.operation_authority(scope.investigation_id)
    if (
        type(authority) is not FirestoreScenarioOperationAuthority
        or authority.candidate != candidate
        or authority.work.runtime_provenance_sha256 != candidate.sha256
        or authority.work.semantic_config_sha256 != candidate.semantic_config_sha256
    ):
        raise ValueError("hosted scenario candidate authority changed")
    work = authority.work
    material = build_hosted_scenario_material(
        work.scenario_request,
        invoked_at=work.invoked_at,
        target_bucket=target_bucket,
    )
    preparation = material.preparation
    if (
        authority.prepared_envelope != preparation.execution_envelope
        or work.prepared_envelope_sha256 != preparation.envelope_sha256
        or work.cleanup_manifest_sha256 != preparation.cleanup_manifest_sha256
        or scope.cleanup_manifest_sha256 != preparation.cleanup_manifest_sha256
    ):
        raise ValueError("hosted scenario material authority changed")
    return work, material


class HostedFaultProxyDispatcher:
    """Dispatch exact fixed mutations and cleanup from recomputed authority."""

    def __init__(
        self,
        *,
        store: _ScenarioAuthorityStore,
        candidate: HostedCandidateIdentity,
        target_bucket: str,
        storage_mutation: CloudStorageMutationTarget,
        storage_cleanup: CloudStorageCleanupTarget,
        firestore_mutation: GoogleFirestoreBusinessMutationTarget,
        firestore_cleanup: GoogleFirestoreBusinessCleanupTarget,
        sandbox_gateway: HostedSandboxOperationGateway,
        clock: Callable[[], datetime] = _now,
    ) -> None:
        self._store = store
        self._candidate = candidate
        self._target_bucket = target_bucket
        self._storage_mutation = storage_mutation
        self._storage_cleanup = storage_cleanup
        self._firestore_mutation = firestore_mutation
        self._firestore_cleanup = firestore_cleanup
        self._sandbox_gateway = sandbox_gateway
        self._clock = clock

    async def __call__(self, scope: HostedOperationScope) -> HostedOperationReceipt:
        work, material = await _sealed_material(
            self._store,
            self._candidate,
            scope,
            target_bucket=self._target_bucket,
        )
        started_at = self._clock()
        if scope.operation is HostedWorkflowOperation.EXECUTE_FAULT:
            await self._execute_fault(work, material, scope)
        elif scope.operation is HostedWorkflowOperation.CLEANUP:
            await self._cleanup(work, material, scope)
        else:
            raise ValueError("fault proxy operation is unsupported")
        completed_at = max(started_at, self._clock())
        return HostedOperationReceipt(
            schema_version=HOSTED_OPERATION_RECEIPT_VERSION,
            operation=scope.operation,
            scope_sha256=scope.sha256,
            started_at=started_at,
            completed_at=completed_at,
        )

    async def _execute_fault(
        self,
        work: ScenarioWorkItem,
        material: HostedScenarioMaterial,
        scope: HostedOperationScope,
    ) -> None:
        if isinstance(material, HostedStorageMaterial):
            operation = material.operation
            await _owned_thread(
                lambda: self._storage_mutation.commit_object(
                    operation_id=work.scenario_request.operation_id,
                    bucket=self._target_bucket,
                    name=operation.object_name,
                    content=operation.content,
                    correlation=operation.correlation,
                )
            )
            return
        if isinstance(material, HostedFirestoreBusinessMaterial):
            operation = material.operation
            await self._firestore_mutation.commit_business_operation(
                namespace_id=operation.namespace_id,
                operation_id=operation.operation_id,
                manifest_collection=operation.manifest_collection,
                manifest_document_id=operation.manifest_document_id,
                documents=operation.documents,
                selected_effect_ids=operation.selected_effect_ids,
                correlation=operation.correlation,
            )
            return
        if not isinstance(material, HostedSandboxOrderMaterial):
            raise TypeError("hosted fault material is unsupported")
        await self._sandbox_gateway.execute_fault(scope)

    async def _cleanup(
        self,
        work: ScenarioWorkItem,
        material: HostedScenarioMaterial,
        scope: HostedOperationScope,
    ) -> None:
        if isinstance(material, HostedStorageMaterial):
            operation = material.operation

            def clean_storage() -> None:
                self._storage_cleanup.delete_owned(
                    bucket=self._target_bucket,
                    name=operation.object_name,
                    operation_id=work.scenario_request.operation_id,
                )
                if (
                    self._storage_cleanup.count_owned(
                        bucket=self._target_bucket,
                        name=operation.object_name,
                        operation_id=work.scenario_request.operation_id,
                    )
                    != 0
                ):
                    raise RuntimeError("storage cleanup did not establish absence")

            await _owned_thread(clean_storage)
            return
        if isinstance(material, HostedFirestoreBusinessMaterial):
            operation = material.operation
            coordinates = tuple(item.coordinate for item in operation.documents)
            await self._firestore_cleanup.delete_owned(
                namespace_id=operation.namespace_id,
                operation_id=operation.operation_id,
                manifest_collection=operation.manifest_collection,
                manifest_document_id=operation.manifest_document_id,
                document_coordinates=coordinates,
            )
            remaining = await self._firestore_cleanup.count_owned(
                namespace_id=operation.namespace_id,
                operation_id=operation.operation_id,
                manifest_collection=operation.manifest_collection,
                manifest_document_id=operation.manifest_document_id,
                document_coordinates=coordinates,
            )
            if remaining != 0:
                raise RuntimeError("Firestore cleanup did not establish absence")
            return
        if not isinstance(material, HostedSandboxOrderMaterial):
            raise TypeError("hosted cleanup material is unsupported")
        await self._sandbox_gateway.cleanup(scope)


class HostedSandboxDispatcher:
    """Independently reauthorize and execute sandbox-owned target operations."""

    def __init__(
        self,
        *,
        store: _ScenarioAuthorityStore,
        candidate: HostedCandidateIdentity,
        target_bucket: str,
        mutation: GoogleFirestoreSandboxMutationTarget,
        cleanup: GoogleFirestoreSandboxCleanupTarget,
        clock: Callable[[], datetime] = _now,
    ) -> None:
        self._store = store
        self._candidate = candidate
        self._target_bucket = target_bucket
        self._mutation = mutation
        self._cleanup_target = cleanup
        self._clock = clock

    async def __call__(self, scope: HostedOperationScope) -> HostedOperationReceipt:
        _, material = await _sealed_material(
            self._store,
            self._candidate,
            scope,
            target_bucket=self._target_bucket,
        )
        if not isinstance(material, HostedSandboxOrderMaterial):
            raise ValueError("sandbox operation is outside the sandbox scenario")
        operation = material.operation
        started_at = self._clock()
        if scope.operation is HostedWorkflowOperation.EXECUTE_FAULT:
            await self._mutation.submit_order(
                sandbox_id=operation.sandbox_id,
                owner_token=operation.owner_token,
                item_code=operation.item_code,
                quantity=operation.quantity,
            )
        elif scope.operation is HostedWorkflowOperation.CLEANUP:
            await self._cleanup_target.delete_owned(
                sandbox_id=operation.sandbox_id,
                owner_token=operation.owner_token,
                item_code=operation.item_code,
                quantity=operation.quantity,
            )
            if (
                await self._cleanup_target.count_owned(
                    sandbox_id=operation.sandbox_id,
                    owner_token=operation.owner_token,
                    item_code=operation.item_code,
                    quantity=operation.quantity,
                )
                != 0
            ):
                raise RuntimeError("sandbox cleanup did not establish absence")
        else:
            raise ValueError("sandbox operation is unsupported")
        return HostedOperationReceipt(
            schema_version=HOSTED_OPERATION_RECEIPT_VERSION,
            operation=scope.operation,
            scope_sha256=scope.sha256,
            started_at=started_at,
            completed_at=max(started_at, self._clock()),
        )


class HostedFixedExecutor:
    """Run only exact deterministic cloud connectors for all fixed routes."""

    def __init__(
        self,
        *,
        storage_reader: CloudStorageReadTarget,
        firestore_reader: GoogleFirestoreBusinessReadTarget,
        sandbox_url: str,
        sandbox_audience: str,
        transport: HostedHttpTransport,
    ) -> None:
        self._storage_reader = storage_reader
        self._firestore_reader = firestore_reader
        self._sandbox_url = sandbox_url
        self._sandbox_audience = sandbox_audience
        self._transport = transport

    def _sandbox_reader(
        self, envelope: ExecutionEnvelope
    ) -> HostedSandboxEvidenceTarget:
        sandbox_id = envelope.target.scope.get("sandbox_id")
        if type(sandbox_id) is not str:
            raise ValueError("sandbox envelope identity is invalid")
        expected_target = build_sandbox_order_target(
            sandbox_id=sandbox_id,
            profile=SANDBOX_ORDER_CLOUD_PROFILE,
        )
        if canonical_json_bytes(envelope.target) != canonical_json_bytes(
            expected_target
        ):
            raise ValueError("sandbox envelope scope is not exact")
        return HostedSandboxEvidenceTarget(
            sandbox_url=self._sandbox_url,
            sandbox_audience=self._sandbox_audience,
            sandbox_id=sandbox_id,
            transport=self._transport,
        )

    async def __call__(
        self,
        envelope: ExecutionEnvelope,
        *,
        revision: int,
        cancellation_event: asyncio.Event,
        runtime: DurableExecutionContext,
    ) -> DurableExecutionOutcome:
        if envelope.target.target_kind == "storage.object":
            result = await execute_cloud_storage_baseline(
                envelope,
                self._storage_reader,
                revision=revision,
                cancellation_event=cancellation_event,
                durability_observer=runtime,
            )
        elif envelope.target.target_kind == "business.documents":
            result = await execute_cloud_firestore_business_baseline(
                envelope,
                self._firestore_reader,
                revision=revision,
                cancellation_event=cancellation_event,
                durability_observer=runtime,
            )
        elif envelope.target.target_kind == "sandbox.order":
            result = await execute_hosted_sandbox_order_fixed(
                envelope,
                self._sandbox_reader(envelope),
                revision=revision,
                cancellation_event=cancellation_event,
                durability_observer=runtime,
            )
        else:
            raise ValueError("hosted fixed target is unsupported")
        report = mark_bounded_hybrid_deterministic_fixed(result.report)
        return await runtime.complete(report)


async def _close_planner(planner: AdvisoryPlanner) -> bool:
    try:
        closer = getattr(planner, "aclose", None)
        if callable(closer):
            result = closer()
            if inspect.isawaitable(result):
                await result
        return True
    except asyncio.CancelledError:
        raise
    except Exception:
        return False


class HostedHybridExecutor:
    """Allow one sandbox-only advisory planning turn with fixed-or-UNKNOWN fallback."""

    def __init__(
        self,
        *,
        fixed: HostedFixedExecutor,
        planner_factory: Callable[[], AdvisoryPlanner],
        clock: SandboxOrderInvestigationClock | None = None,
    ) -> None:
        self._fixed = fixed
        self._planner_factory = planner_factory
        self._clock = clock

    async def _fixed_fallback(
        self,
        envelope: ExecutionEnvelope,
        *,
        revision: int,
        cancellation_event: asyncio.Event,
        runtime: DurableExecutionContext,
        planner_invoked: bool,
        provider_cleanup_failed: bool = False,
    ) -> DurableExecutionOutcome:
        result = await execute_hosted_sandbox_order_fixed(
            envelope,
            self._fixed._sandbox_reader(envelope),
            revision=revision,
            cancellation_event=cancellation_event,
            durability_observer=runtime,
            clock=self._clock,
        )
        report = mark_bounded_hybrid_fixed_fallback(
            result.report,
            planner_invoked=planner_invoked,
            provider_cleanup_failed=provider_cleanup_failed,
        )
        return await runtime.complete(report)

    async def __call__(
        self,
        envelope: ExecutionEnvelope,
        *,
        revision: int,
        cancellation_event: asyncio.Event,
        runtime: DurableExecutionContext,
    ) -> DurableExecutionOutcome:
        if envelope.target.target_kind != "sandbox.order":
            raise ValueError("hosted hybrid planning is sandbox-only")
        sandbox_reader = self._fixed._sandbox_reader(envelope)
        planner: AdvisoryPlanner | None = None
        try:
            planner = self._planner_factory()
            if type(planner.metadata) is not AdvisoryPlannerMetadata or not callable(
                planner.plan
            ):
                raise TypeError("hosted planner protocol is unavailable")
        except asyncio.CancelledError:
            raise
        except Exception:
            cleanup_failed = planner is not None and not await _close_planner(planner)
            return await self._fixed_fallback(
                envelope,
                revision=revision,
                cancellation_event=cancellation_event,
                runtime=runtime,
                planner_invoked=False,
                provider_cleanup_failed=cleanup_failed,
            )

        durable_planner = DurableAdvisoryPlanner(
            planner,
            runtime,
            estimated_cost_microunits=_PLANNER_ESTIMATED_COST_MICROUNITS,
            minimum_remaining_ms=int(_HOSTED_PROVIDER_TIMEOUT_SECONDS * 1_000),
        )
        close_failed = False
        try:
            result = await execute_sandbox_order_conditional(
                envelope,
                sandbox_reader,
                durable_planner,
                revision=revision,
                cancellation_event=cancellation_event,
                durability_observer=runtime,
                clock=self._clock,
            )
        finally:
            close_failed = not await _close_planner(planner)
        maximum_elapsed = envelope.context.evidence_budget.max_elapsed_ms
        if adaptive_result_requires_fixed_fallback(
            result,
            max_elapsed_ms=maximum_elapsed,
        ):
            return await self._fixed_fallback(
                envelope,
                revision=revision,
                cancellation_event=cancellation_event,
                runtime=runtime,
                planner_invoked=True,
                provider_cleanup_failed=close_failed,
            )
        if adaptive_result_requires_explicit_unknown(
            result,
            max_elapsed_ms=maximum_elapsed,
        ):
            if (
                durable_planner.predispatch_refused
                or result.model_invocation_count == 0
            ):
                report = mark_bounded_hybrid_preplanner_unknown(result.report)
                if close_failed:
                    report = mark_bounded_hybrid_provider_cleanup_failure(report)
            else:
                report = mark_bounded_hybrid_explicit_unknown(
                    result.report,
                    provider_cleanup_failed=close_failed,
                )
        elif result.model_invocation_count == 0:
            report = mark_bounded_hybrid_preplanner_unknown(result.report)
            if close_failed:
                report = mark_bounded_hybrid_provider_cleanup_failure(report)
        else:
            report = mark_bounded_hybrid_advisory(
                result.report,
                provider_cleanup_failed=close_failed,
            )
        return await runtime.complete(report)


class HostedControllerDispatcher:
    """Select only the frozen fixed or sandbox-hybrid durable execution lane."""

    def __init__(
        self,
        *,
        store: _ScenarioAuthorityStore,
        candidate: HostedCandidateIdentity,
        target_bucket: str,
        runtime_store: FirestoreDurableRuntimeStore,
        fixed_executor: HostedFixedExecutor,
        hybrid_executor: HostedHybridExecutor,
    ) -> None:
        self._store = store
        self._candidate = candidate
        self._target_bucket = target_bucket
        self._fixed = DurableInvestigationApplicationService(
            runtime_store,
            fixed_executor,
            strategy=DurableExecutionStrategy.FIXED,
            owner_id="hosted-controller-fixed",
            semantic_config_sha256=candidate.semantic_config_sha256,
            max_provider_calls=0,
            max_estimated_cost_microunits=0,
        )
        self._hybrid = DurableInvestigationApplicationService(
            runtime_store,
            hybrid_executor,
            strategy=DurableExecutionStrategy.ADAPTIVE,
            owner_id="hosted-controller-hybrid",
            semantic_config_sha256=candidate.semantic_config_sha256,
            max_provider_calls=1,
            max_estimated_cost_microunits=_PLANNER_ESTIMATED_COST_MICROUNITS,
        )

    async def __call__(self, scope: HostedOperationScope) -> HostedInvestigationResult:
        work, material = await _sealed_material(
            self._store,
            self._candidate,
            scope,
            target_bucket=self._target_bucket,
        )
        result = work.scenario_result
        if result is None or result.execution_envelope is None:
            raise ValueError("hosted investigation envelope is unavailable")
        expected = material.preparation.execution_envelope.model_copy(
            update={"ambiguity": result.execution_envelope.ambiguity}
        )
        envelope = result.execution_envelope
        if (
            canonical_json_bytes(envelope) != canonical_json_bytes(expected)
            or canonical_sha256(envelope) != scope.envelope_sha256
        ):
            raise ValueError("hosted investigation envelope authority changed")
        mode = ScenarioMode(work.launch_request.mode.value)
        if mode is ScenarioMode.COMPARE:
            raise ValueError("hosted comparison is not accepted")
        service = (
            self._hybrid
            if mode is ScenarioMode.ADAPTIVE
            and isinstance(material, HostedSandboxOrderMaterial)
            else self._fixed
        )
        creation = await service.create_and_wait_result(
            envelope,
            started_at=work.updated_at,
        )
        report = creation.report
        if (
            report.status is not InvestigationStatus.COMPLETED
            or report.investigation_id != scope.investigation_id
            or report.envelope_sha256 != scope.envelope_sha256
        ):
            raise ValueError("hosted investigation did not establish a report")
        return HostedInvestigationResult(
            schema_version=HOSTED_INVESTIGATION_RESULT_VERSION,
            scope_sha256=scope.sha256,
            report=report,
        )


def _cas(config: HostedConfig) -> GoogleFirestoreCasStore:
    return GoogleFirestoreCasStore(
        project_id=config.project_id,
        database_id=_required(config.runtime_database, "runtime database"),
    )


def _canary_target(config: HostedConfig) -> CloudRunCanaryTarget:
    location = _required(config.canary_location, "canary location")
    return CloudRunCanaryTarget(
        project=config.project_id,
        location=location,
        service=_required(config.canary_service, "canary service"),
        image_repository=(
            f"{location}-docker.pkg.dev/{config.project_id}/reconcile-p5/reconcile"
        ),
        baseline_revision=_required(
            config.canary_baseline_revision,
            "canary baseline revision",
        ),
        health_audience=_required(config.canary_audience, "canary audience"),
    )


def _release_chain_settings(
    config: HostedConfig,
    candidate: HostedCandidateIdentity,
) -> tuple[ReleaseChainSettings, datetime, int]:
    release_id = _required(config.recovery_release_id, "recovery release ID")
    payload_sha256 = _required(
        config.recovery_payload_sha256,
        "recovery payload digest",
    )
    invoked_at = config.recovery_definition_created_at
    timeout = config.recovery_execution_timeout_seconds
    if release_id != f"p5-release-{config.source_revision[:24]}":
        raise ValueError("hosted recovery release identity drifted")
    if payload_sha256 != candidate.sha256:
        raise ValueError("hosted recovery payload identity drifted")
    if (
        type(invoked_at) is not datetime
        or invoked_at.tzinfo is None
        or invoked_at.utcoffset() is None
        or invoked_at.utcoffset().total_seconds() != 0
    ):
        raise ValueError("hosted recovery definition timestamp is invalid")
    if type(timeout) is not int or timeout != 240:
        raise ValueError("hosted recovery execution timeout drifted")
    settings = ReleaseChainSettings(
        project=config.project_id,
        location=_required(config.canary_location, "canary location"),
        service=_required(config.canary_service, "canary service"),
        release_id=release_id,
        image_digest=config.image_digest,
        configuration_sha256=config.semantic_config_sha256,
        payload_sha256=payload_sha256,
        database=_required(config.target_database, "target database"),
    )
    return settings, invoked_at.astimezone(UTC), timeout


class _LazyRecoveryRunService:
    """Construct the provider-backed recovery service on its first request."""

    def __init__(
        self,
        factory: Callable[[], RecoveryRunApplicationService],
    ) -> None:
        if not callable(factory):
            raise TypeError("recovery service factory is invalid")
        self._factory = factory
        self._service: RecoveryRunApplicationService | None = None
        self._lock = asyncio.Lock()
        self._closed = False

    async def _get(self) -> RecoveryRunApplicationService:
        async with self._lock:
            if self._closed:
                raise RuntimeError("recovery service is closed")
            service = self._service
            if service is None:
                service = self._factory()
                if not callable(getattr(service, "launch_and_wait_result", None)):
                    raise TypeError(
                        "recovery service factory returned an invalid service"
                    )
                self._service = service
            return service

    async def launch_and_wait_result(
        self,
        request: RecoveryRunRequest,
    ) -> RecoveryRunLaunchResult:
        service = await self._get()
        return await service.launch_and_wait_result(request)

    async def aclose(self) -> None:
        async with self._lock:
            if self._closed:
                return
            self._closed = True
            service = self._service
            self._service = None
        if service is not None:
            await service.aclose()


def _handlers(
    *entries: tuple[InternalOperation, InternalOperationHandler],
) -> Mapping[InternalOperation, InternalOperationHandler]:
    return dict(entries)


def create_runtime_component_app(
    config: HostedConfig,
    *,
    transport: HostedHttpTransport | None = None,
):
    """Assemble one exact component without eager ADC, network, or provider I/O."""

    if type(config) is not HostedConfig:
        raise TypeError("hosted runtime requires exact configuration")
    candidate = build_hosted_candidate(config)
    cas = _cas(config)
    scenario_store = FirestoreScenarioStore(cas, candidate)
    selected_transport = transport or HostedHttpTransport(
        request_timeout_seconds=(265.0 if config.component is Component.API else None),
        total_timeout_seconds=(270.0 if config.component is Component.API else None),
    )

    if config.component is Component.API:
        target_bucket = _required(config.target_bucket, "target bucket")
        runtime_store = FirestoreDurableRuntimeStore(
            project_id=config.project_id,
            cas_store=cas,
        )
        gateway = HostedHttpWorkflowGateway(
            config,
            selected_transport,
            DurableRuntimeReportLoader(runtime_store),
        )
        workflow = HostedScenarioWorkflow(
            scenario_store,
            DeterministicHostedScenarioPreparer(target_bucket=target_bucket),
            gateway,
            semantic_config_sha256=candidate.semantic_config_sha256,
            runtime_provenance_sha256=candidate.sha256,
            provider_available=True,
        )
        operator = OperatorApplicationService(
            runner=workflow,
            projection_store=scenario_store,
        )
        recovery = HostedRecoveryRunGateway(
            config,
            selected_transport,
            FirestoreRecoveryRunStore(cas),
        )
        return create_component_app(
            config,
            transport=selected_transport,
            operator_service=operator,
            recovery_service=recovery,
        )

    authorizer = FirestoreHostedOperationScopeAuthorizer(scenario_store)
    if config.component is Component.CONTROLLER:
        target_bucket = _required(config.target_bucket, "target bucket")
        firestore_targets = build_google_firestore_business_targets(
            project_id=config.project_id,
            database_id=_required(config.target_database, "target database"),
        )
        storage_reader = CloudStorageReadTarget(
            project_id=config.project_id,
            bucket_name=target_bucket,
        )
        fixed = HostedFixedExecutor(
            storage_reader=storage_reader,
            firestore_reader=firestore_targets.read,
            sandbox_url=_required(config.sandbox_url, "sandbox URL"),
            sandbox_audience=_required(config.sandbox_audience, "sandbox audience"),
            transport=selected_transport,
        )
        runtime_store = FirestoreDurableRuntimeStore(
            project_id=config.project_id,
            cas_store=cas,
        )
        provider_ledger = FirestoreHostedProviderLedger(cas)
        recovery_store = FirestoreRecoveryRunStore(cas)
        permit_authority = PermitAuthority(FirestoreActionPermitStore(cas))

        def planner_factory(
            timeout_seconds: float = _HOSTED_PROVIDER_TIMEOUT_SECONDS,
        ) -> AdvisoryPlanner:
            planner = AdkGeminiPlanner.from_vertex_adc_guarded(
                VertexAdcPlannerConfig(
                    project=candidate.project_id,
                    location=candidate.vertex_location,
                    model=candidate.configured_model,
                    timeout_seconds=timeout_seconds,
                    max_output_tokens=candidate.maximum_output_tokens,
                    prompt_version=candidate.prompt_version,
                )
            )
            return HostedGeminiPlanner(planner, candidate, provider_ledger)

        dispatcher = HostedControllerDispatcher(
            store=scenario_store,
            candidate=candidate,
            target_bucket=target_bucket,
            runtime_store=runtime_store,
            fixed_executor=fixed,
            hybrid_executor=HostedHybridExecutor(
                fixed=fixed,
                planner_factory=planner_factory,
            ),
        )
        handler = HostedInvestigationHandler(
            expected_caller_email=config.allowed_caller_emails[0],
            authorizer=authorizer,
            dispatcher=dispatcher,
        )
        recovery_settings, recovery_invoked_at, recovery_timeout = (
            _release_chain_settings(config, candidate)
        )
        recovery_cloud_reader = CloudRunCanaryReader(target=_canary_target(config))
        recovery_firestore = GoogleFirestoreReleaseTarget(
            project_id=config.project_id,
            database_id=_required(config.target_database, "target database"),
        )
        recovery_dispatch = HostedRecoveryDispatchGateway(
            fault_proxy_url=_required(config.fault_proxy_url, "fault proxy URL"),
            fault_proxy_audience=_required(
                config.fault_proxy_audience,
                "fault proxy audience",
            ),
            transport=selected_transport,
            recovery_store=recovery_store,
            permit_authority=permit_authority,
        )

        def recovery_service_factory() -> RecoveryRunApplicationService:
            workflow = build_release_chain_workflow(
                settings=recovery_settings,
                invoked_at=recovery_invoked_at,
                store=recovery_store,
                permit_authority=permit_authority,
                recovery_agent=RecoveryAgent(
                    planner_factory(_HOSTED_RECOVERY_PROVIDER_TIMEOUT_SECONDS)
                ),
                cloud_action=None,
                cloud_reader=recovery_cloud_reader,
                firestore=recovery_firestore,
                dispatch_gateway=recovery_dispatch,
            )
            return RecoveryRunApplicationService(
                workflow,
                recovery_store,
                execution_timeout_seconds=recovery_timeout,
            )

        recovery_service = _LazyRecoveryRunService(recovery_service_factory)
        return create_component_app(
            config,
            transport=selected_transport,
            internal_operation_handlers=_handlers(
                (InternalOperation.INVESTIGATE, handler),
                (
                    InternalOperation.RECOVER,
                    HostedRecoveryHandler(
                        expected_caller_email=config.allowed_caller_emails[0],
                        service=recovery_service,
                    ),
                ),
            ),
        )

    if config.component is Component.FAULT_PROXY:
        target_bucket = _required(config.target_bucket, "target bucket")
        canary_target = _canary_target(config)
        storage_mutation = CloudStorageMutationTarget(
            project_id=config.project_id,
            bucket_name=target_bucket,
        )
        storage_cleanup = CloudStorageCleanupTarget(
            project_id=config.project_id,
            bucket_name=target_bucket,
        )
        firestore_targets = build_google_firestore_business_targets(
            project_id=config.project_id,
            database_id=_required(config.target_database, "target database"),
        )
        dispatcher = HostedFaultProxyDispatcher(
            store=scenario_store,
            candidate=candidate,
            target_bucket=target_bucket,
            storage_mutation=storage_mutation,
            storage_cleanup=storage_cleanup,
            firestore_mutation=firestore_targets.mutation,
            firestore_cleanup=firestore_targets.cleanup,
            sandbox_gateway=HostedSandboxOperationGateway(
                sandbox_url=_required(config.sandbox_url, "sandbox URL"),
                sandbox_audience=_required(
                    config.sandbox_audience,
                    "sandbox audience",
                ),
                transport=selected_transport,
            ),
        )
        caller = config.allowed_caller_emails[0]
        recovery_store = FirestoreRecoveryRunStore(cas)
        permit_authority = PermitAuthority(FirestoreActionPermitStore(cas))
        canary_proxy = CloudRunCanaryFaultProxy(
            CloudRunCanaryActionAdapter(target=canary_target)
        )
        release_target = GoogleFirestoreReleaseTarget(
            project_id=config.project_id,
            database_id=_required(config.target_database, "target database"),
        )
        return create_component_app(
            config,
            transport=selected_transport,
            cloud_run_canary_fault_proxy=canary_proxy,
            cloud_run_canary_action_authorizer=RecoveryCloudRunCanaryActionAuthorizer(
                recovery_store=recovery_store,
                permit_authority=permit_authority,
                target=canary_target,
            ),
            firestore_release_target=release_target,
            firestore_release_action_authorizer=(
                RecoveryFirestoreReleaseActionAuthorizer(
                    recovery_store=recovery_store,
                    permit_authority=permit_authority,
                    target=release_target,
                )
            ),
            recovery_action_caller_email=_required(
                config.recovery_action_caller_email,
                "recovery action caller",
            ),
            internal_operation_handlers=_handlers(
                (
                    InternalOperation.EXECUTE_FAULT,
                    HostedOperationHandler(
                        operation=HostedWorkflowOperation.EXECUTE_FAULT,
                        expected_caller_email=caller,
                        authorizer=authorizer,
                        dispatcher=dispatcher,
                    ),
                ),
                (
                    InternalOperation.CLEANUP,
                    HostedOperationHandler(
                        operation=HostedWorkflowOperation.CLEANUP,
                        expected_caller_email=caller,
                        authorizer=authorizer,
                        dispatcher=dispatcher,
                    ),
                ),
            ),
        )

    target_database = _required(config.target_database, "target database")
    sandbox_targets = build_google_firestore_sandbox_targets(
        project_id=config.project_id,
        database_id=target_database,
        hidden_outcome=HiddenOrderOutcome.COMMIT,
    )
    target_bucket = f"{config.project_id}-p5-target"
    dispatcher = HostedSandboxDispatcher(
        store=scenario_store,
        candidate=candidate,
        target_bucket=target_bucket,
        mutation=sandbox_targets.mutation,
        cleanup=sandbox_targets.cleanup,
    )
    _required(config.sandbox_read_caller_email, "sandbox read caller")
    mutation_caller = _required(
        config.sandbox_mutation_caller_email,
        "sandbox mutation caller",
    )
    return create_component_app(
        config,
        transport=selected_transport,
        sandbox_evidence_reader=FirestoreSandboxEvidenceReader(
            project_id=config.project_id,
            database_id=target_database,
        ),
        internal_operation_handlers=_handlers(
            (
                InternalOperation.EXECUTE_FAULT,
                HostedOperationHandler(
                    operation=HostedWorkflowOperation.EXECUTE_FAULT,
                    expected_caller_email=mutation_caller,
                    authorizer=authorizer,
                    dispatcher=dispatcher,
                ),
            ),
            (
                InternalOperation.CLEANUP,
                HostedOperationHandler(
                    operation=HostedWorkflowOperation.CLEANUP,
                    expected_caller_email=mutation_caller,
                    authorizer=authorizer,
                    dispatcher=dispatcher,
                ),
            ),
        ),
    )


__all__ = [
    "HostedControllerDispatcher",
    "HostedFaultProxyDispatcher",
    "HostedFixedExecutor",
    "HostedHybridExecutor",
    "HostedSandboxDispatcher",
    "HostedSandboxOperationGateway",
    "build_hosted_candidate",
    "create_runtime_component_app",
]
