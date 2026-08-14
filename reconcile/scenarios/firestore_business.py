"""Local business-operation scenario with fixed and adaptive investigations."""

from __future__ import annotations

import asyncio
import hashlib
import time
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import Protocol

from pydantic import JsonValue

from reconcile.adapters.firestore_business import (
    FIRESTORE_BUSINESS_AUTHORITY_POLICY_VERSION,
    FIRESTORE_BUSINESS_CAPABILITY_NAME,
    FIRESTORE_BUSINESS_CAPABILITY_VERSION,
    FIRESTORE_BUSINESS_CLASSIFICATION_POLICY_VERSION,
    build_firestore_business_capability_registration,
    build_firestore_business_rule_registration,
    build_firestore_business_target,
)
from reconcile.adaptive import (
    AdaptiveInvestigationPolicy,
    AdaptiveInvestigationResult,
    AdvisoryPlanner,
    execute_adaptive_investigation,
)
from reconcile.baseline import (
    FixedBaselineResult,
    FixedProbePlan,
    FixedProbeStep,
    execute_fixed_plan,
    run_fixed_plan,
)
from reconcile.contracts import (
    EXECUTION_ENVELOPE_VERSION,
    EXPECTED_EFFECT_VERSION,
    PROBE_REQUEST_VERSION,
    AmbiguityKind,
    AmbiguousExecution,
    CapabilityRef,
    Classification,
    EnvelopeContext,
    EvidenceBudget,
    ExecutionEnvelope,
    ExpectedEffect,
    FreshnessPolicy,
    InvestigationReport,
    OriginalInvocation,
    PolicyReferences,
    ProbeRequest,
    ScenarioRef,
    canonical_json_bytes,
    decode_contract,
)
from reconcile.contracts.base import canonical_json_value_bytes
from reconcile.controller import CapabilityRegistry
from reconcile.evidence import TargetRuleRegistry
from reconcile.progress import ProgressEmitter
from reconcile.scenarios.adk_mutation import run_adk_mutation
from reconcile.scenarios.local_firestore import (
    BusinessDocumentCoordinate,
    BusinessDocumentWrite,
    LocalFirestoreCleanupTarget,
    LocalFirestoreMutationTarget,
    LocalFirestoreReadTarget,
)
from reconcile.scenarios.runner import (
    MutationBoundary,
    PreparedScenario,
    ScenarioCleanupManifest,
    ScenarioCleanupOutcome,
    ScenarioMutationResponse,
    ScenarioPlan,
    ScenarioPreparation,
)

FIRESTORE_BUSINESS_SCENARIO = ScenarioRef(
    name="firestore-business-operation",
    version="1.0.0",
)
FIRESTORE_BUSINESS_EFFECT_IDS = (
    "primary-request",
    "audit-record",
    "processing-index",
)
FIRESTORE_BUSINESS_ACTION_POLICY_VERSION = "action-v1"
FIRESTORE_BUSINESS_TOOL_NAME = "execute_business_operation"
FIRESTORE_BUSINESS_TOOL_VERSION = "1.0.0"

FIRESTORE_BUSINESS_FIXED_PROBE_PLAN = FixedProbePlan(
    name="firestore-business-fixed-baseline",
    version="1.0.0",
    steps=(
        FixedProbeStep(
            request=ProbeRequest(
                schema_version=PROBE_REQUEST_VERSION,
                capability_name=FIRESTORE_BUSINESS_CAPABILITY_NAME,
                capability_version=FIRESTORE_BUSINESS_CAPABILITY_VERSION,
                relevant_effect_ids=FIRESTORE_BUSINESS_EFFECT_IDS,
                arguments={},
                rationale=(
                    "Read the target-native manifest and all exact business "
                    "documents from one local snapshot."
                ),
            )
        ),
    ),
    sufficient_classifications=(
        Classification.COMMITTED,
        Classification.NOT_COMMITTED,
        Classification.PARTIAL,
    ),
)

FIRESTORE_BUSINESS_ADAPTIVE_POLICY = AdaptiveInvestigationPolicy(
    name="firestore-business-adaptive-investigation",
    version="1.0.0",
    sufficient_classifications=(
        Classification.COMMITTED,
        Classification.NOT_COMMITTED,
        Classification.PARTIAL,
    ),
    required_capabilities=(
        CapabilityRef(
            name=FIRESTORE_BUSINESS_CAPABILITY_NAME,
            version=FIRESTORE_BUSINESS_CAPABILITY_VERSION,
        ),
    ),
    max_turns=1,
    planner_timeout_ms=4_000,
    include_explanation=True,
)

_FIRESTORE_BUSINESS_LIMITATIONS = (
    (
        "A PARTIAL result means a partial multi-step business operation; no "
        "atomic transaction is represented."
    ),
    "Evidence comes from the local SQLite Firestore-shaped semantic target.",
)

_MANIFEST_COLLECTION = "operation-manifests"
_MAX_AGE_SECONDS = 60
_CLOCK_SKEW_SECONDS = 2


class BusinessInvestigationClock(Protocol):
    """Wall and monotonic time needed by one fixed investigation."""

    def monotonic(self) -> float:
        """Return monotonic seconds."""

    def now(self) -> datetime:
        """Return an aware wall-clock timestamp."""


class _SystemInvestigationClock:
    def monotonic(self) -> float:
        return time.monotonic()

    def now(self) -> datetime:
        return datetime.now(UTC)


def _aware_utc(value: datetime) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("business scenario timestamps must include a UTC offset")
    return value.astimezone(UTC)


def _business_request_id(plan: ScenarioPlan) -> str:
    material = {
        "namespace_id": plan.namespace_id,
        "operation_id": plan.identifiers.operation_id,
        "run_id": plan.identifiers.run_id,
    }
    digest = hashlib.sha256(canonical_json_value_bytes(material)).hexdigest()
    return f"business-request-{digest[:24]}"


def _correlation(plan: ScenarioPlan) -> dict[str, str]:
    return {
        "business_request_id": _business_request_id(plan),
        "operation_id": plan.identifiers.operation_id,
        "run_id": plan.identifiers.run_id,
    }


def _document_writes(plan: ScenarioPlan) -> tuple[BusinessDocumentWrite, ...]:
    business_request_id = _business_request_id(plan)
    definitions = (
        ("primary-request", "requests", business_request_id),
        ("audit-record", "audit-records", f"audit-{business_request_id}"),
        (
            "processing-index",
            "processing-indexes",
            f"processing-{business_request_id}",
        ),
    )
    return tuple(
        BusinessDocumentWrite(
            effect_id=effect_id,
            collection_name=collection_name,
            document_id=document_id,
            content=canonical_json_value_bytes(
                {
                    "business_request_id": business_request_id,
                    "effect_id": effect_id,
                    "operation_id": plan.identifiers.operation_id,
                    "run_id": plan.identifiers.run_id,
                }
            ),
        )
        for effect_id, collection_name, document_id in definitions
    )


def _coordinates(plan: ScenarioPlan) -> tuple[BusinessDocumentCoordinate, ...]:
    return tuple(document.coordinate for document in _document_writes(plan))


def _manifest_document_id(plan: ScenarioPlan) -> str:
    return f"operation-{plan.identifiers.operation_id}"


def _selected_effect_ids(plan: ScenarioPlan) -> tuple[str, ...]:
    mask = plan.seed & 0b111
    return tuple(
        effect_id
        for index, effect_id in enumerate(FIRESTORE_BUSINESS_EFFECT_IDS)
        if mask & (1 << index)
    )


def _mutation_arguments(plan: ScenarioPlan) -> dict[str, JsonValue]:
    return {
        "business_request_id": _business_request_id(plan),
        "operation_id": plan.identifiers.operation_id,
        "run_id": plan.identifiers.run_id,
    }


def _cleanup_resource_ids(plan: ScenarioPlan) -> tuple[str, ...]:
    manifest = (
        f"business-manifest:{plan.namespace_id}/"
        f"{_MANIFEST_COLLECTION}/{_manifest_document_id(plan)}"
    )
    documents = tuple(
        f"business-document:{plan.namespace_id}/"
        f"{coordinate.collection_name}/{coordinate.document_id}"
        for coordinate in _coordinates(plan)
    )
    return (manifest, *documents)


class FirestoreBusinessScenarioDefinition:
    """Three separately committed local business effects through Google ADK."""

    scenario = FIRESTORE_BUSINESS_SCENARIO

    def __init__(
        self,
        database_path: str | Path,
        *,
        selected_effect_ids: tuple[str, ...] | None = None,
        invoked_at: datetime | None = None,
        target_clock: Callable[[], datetime] | None = None,
    ) -> None:
        if selected_effect_ids is not None:
            if (
                type(selected_effect_ids) is not tuple
                or not selected_effect_ids
                or len(selected_effect_ids) != len(set(selected_effect_ids))
                or not set(selected_effect_ids) <= set(FIRESTORE_BUSINESS_EFFECT_IDS)
            ):
                raise ValueError(
                    "selected business effects must be a nonempty unique subset"
                )
            selected_effect_ids = tuple(
                effect_id
                for effect_id in FIRESTORE_BUSINESS_EFFECT_IDS
                if effect_id in selected_effect_ids
            )
        self._mutation_target = LocalFirestoreMutationTarget(
            database_path,
            clock=target_clock,
        )
        self._read_target = LocalFirestoreReadTarget(database_path)
        self._cleanup_target = LocalFirestoreCleanupTarget(database_path)
        self._selected_effect_ids = selected_effect_ids
        self._invoked_at = _aware_utc(invoked_at or datetime.now(UTC))

    def investigate(
        self,
        envelope: ExecutionEnvelope,
        *,
        clock: BusinessInvestigationClock | None = None,
        revision: int = 1,
    ) -> InvestigationReport:
        """Run fixed evidence acquisition without exposing the manifest handle."""

        return self.baseline(
            envelope,
            clock=clock,
            revision=revision,
        ).report

    def baseline(
        self,
        envelope: ExecutionEnvelope,
        *,
        clock: BusinessInvestigationClock | None = None,
        revision: int = 1,
    ) -> FixedBaselineResult:
        """Run the canonical fixed baseline without exposing the read handle."""

        return run_firestore_business_baseline(
            envelope,
            self._read_target,
            clock=clock,
            revision=revision,
        )

    async def adaptive(
        self,
        envelope: ExecutionEnvelope,
        planner: AdvisoryPlanner,
        *,
        clock: BusinessInvestigationClock | None = None,
        revision: int = 1,
        cancellation_event: asyncio.Event | None = None,
        progress_emitter: ProgressEmitter | None = None,
    ) -> AdaptiveInvestigationResult:
        """Run the canonical bounded adaptive business investigation."""

        return await execute_firestore_business_adaptive(
            envelope,
            self._read_target,
            planner,
            clock=clock,
            revision=revision,
            cancellation_event=cancellation_event,
            progress_emitter=progress_emitter,
        )

    def prepare(self, plan: ScenarioPlan) -> ScenarioPreparation:
        identifiers = plan.identifiers
        if identifiers.function_call_id is None:
            raise ValueError(
                "the business ADK scenario requires a function-call identifier"
            )
        documents = _document_writes(plan)
        coordinates = tuple(document.coordinate for document in documents)
        correlation = _correlation(plan)
        arguments = _mutation_arguments(plan)
        target = build_firestore_business_target(
            namespace_id=plan.namespace_id,
            manifest_collection=_MANIFEST_COLLECTION,
            manifest_document_id=_manifest_document_id(plan),
            document_coordinates=coordinates,
        )
        expected_effects = tuple(
            ExpectedEffect(
                schema_version=EXPECTED_EFFECT_VERSION,
                effect_id=document.effect_id,
                commit_scope=document.effect_id,
                predicate={
                    "collection_name": document.collection_name,
                    "document_id": document.document_id,
                    "content_sha256": document.content_sha256,
                    "correlation": correlation,
                },
                description=(
                    "This separately committed business-step document exists with "
                    "the exact operation correlation."
                ),
            )
            for document in documents
        )
        envelope = ExecutionEnvelope(
            schema_version=EXECUTION_ENVELOPE_VERSION,
            investigation_id=identifiers.investigation_id,
            operation_id=identifiers.operation_id,
            target=target,
            invoked_at=self._invoked_at,
            ambiguity=AmbiguousExecution(
                kind=AmbiguityKind.OTHER,
                observed_at=self._invoked_at,
                detail="Sealed local business-operation scenario envelope template.",
            ),
            expected_effects=expected_effects,
            context=EnvelopeContext(
                invocation=OriginalInvocation(
                    invocation_id=identifiers.invocation_id,
                    function_call_id=identifiers.function_call_id,
                    tool_name=FIRESTORE_BUSINESS_TOOL_NAME,
                    tool_version=FIRESTORE_BUSINESS_TOOL_VERSION,
                    arguments=arguments,
                    arguments_sha256=hashlib.sha256(
                        canonical_json_value_bytes(arguments)
                    ).hexdigest(),
                ),
                enabled_capabilities=(
                    CapabilityRef(
                        name=FIRESTORE_BUSINESS_CAPABILITY_NAME,
                        version=FIRESTORE_BUSINESS_CAPABILITY_VERSION,
                    ),
                ),
                correlation_fields=correlation,
                evidence_budget=EvidenceBudget(
                    max_probes=1,
                    max_elapsed_ms=5_000,
                    max_total_result_bytes=32_768,
                    max_cost_units=1,
                ),
                freshness=FreshnessPolicy(
                    max_age_seconds=_MAX_AGE_SECONDS,
                    clock_skew_seconds=_CLOCK_SKEW_SECONDS,
                ),
                policies=PolicyReferences(
                    authority=FIRESTORE_BUSINESS_AUTHORITY_POLICY_VERSION,
                    classification=FIRESTORE_BUSINESS_CLASSIFICATION_POLICY_VERSION,
                    action=FIRESTORE_BUSINESS_ACTION_POLICY_VERSION,
                ),
            ),
        )
        return ScenarioPreparation(
            execution_envelope=envelope,
            cleanup_manifest=ScenarioCleanupManifest(
                resource_ids=_cleanup_resource_ids(plan)
            ),
        )

    def setup(self, prepared: PreparedScenario) -> None:
        self._mutation_target.initialize()

    def mutate(
        self,
        boundary: MutationBoundary,
        prepared: PreparedScenario,
    ) -> ScenarioMutationResponse:
        envelope = decode_contract(
            prepared.execution_envelope_bytes,
            ExecutionEnvelope,
        )
        expected_arguments = _mutation_arguments(prepared.plan)
        if canonical_json_value_bytes(envelope.context.invocation.arguments) != (
            canonical_json_value_bytes(expected_arguments)
        ):
            raise ValueError("sealed business mutation arguments changed")
        function_call_id = prepared.plan.identifiers.function_call_id
        if function_call_id is None:
            raise ValueError(
                "the business ADK scenario requires a function-call identifier"
            )
        documents = _document_writes(prepared.plan)
        selected_effect_ids = self._selected_effect_ids or _selected_effect_ids(
            prepared.plan
        )
        correlation = _correlation(prepared.plan)

        def execute_business_operation(
            business_request_id: str,
            operation_id: str,
            run_id: str,
        ) -> None:
            received = {
                "business_request_id": business_request_id,
                "operation_id": operation_id,
                "run_id": run_id,
            }
            if canonical_json_value_bytes(received) != canonical_json_value_bytes(
                expected_arguments
            ):
                raise ValueError("ADK changed the business mutation arguments")
            boundary.before_commit()
            self._mutation_target.commit_business_operation(
                namespace_id=prepared.plan.namespace_id,
                operation_id=prepared.plan.identifiers.operation_id,
                manifest_collection=_MANIFEST_COLLECTION,
                manifest_document_id=_manifest_document_id(prepared.plan),
                documents=documents,
                selected_effect_ids=selected_effect_ids,
                correlation=correlation,
            )
            boundary.after_commit()

        public_response = run_adk_mutation(
            execute_business_operation,
            arguments=expected_arguments,
            public_response={
                "accepted": True,
                "operation_id": prepared.plan.identifiers.operation_id,
            },
            function_call_id=function_call_id,
            invocation_id=prepared.plan.identifiers.invocation_id,
        )
        return ScenarioMutationResponse(is_error=False, payload=public_response)

    def remaining(self, prepared: PreparedScenario) -> int | None:
        return self._cleanup_target.count_owned(
            namespace_id=prepared.plan.namespace_id,
            operation_id=prepared.plan.identifiers.operation_id,
            manifest_collection=_MANIFEST_COLLECTION,
            manifest_document_id=_manifest_document_id(prepared.plan),
            document_coordinates=_coordinates(prepared.plan),
        )

    def cleanup(self, prepared: PreparedScenario) -> ScenarioCleanupOutcome:
        deletion = self._cleanup_target.delete_owned(
            namespace_id=prepared.plan.namespace_id,
            operation_id=prepared.plan.identifiers.operation_id,
            manifest_collection=_MANIFEST_COLLECTION,
            manifest_document_id=_manifest_document_id(prepared.plan),
            document_coordinates=_coordinates(prepared.plan),
        )
        declared_ids = _cleanup_resource_ids(prepared.plan)
        removed_by_coordinate = {
            (coordinate.collection_name, coordinate.document_id)
            for coordinate in deletion.removed_documents
        }
        removed: list[str] = []
        if deletion.manifest_removed:
            removed.append(declared_ids[0])
        for resource_id, coordinate in zip(
            declared_ids[1:],
            _coordinates(prepared.plan),
            strict=True,
        ):
            if (coordinate.collection_name, coordinate.document_id) in (
                removed_by_coordinate
            ):
                removed.append(resource_id)
        return ScenarioCleanupOutcome(removed_resource_ids=tuple(removed))


def _firestore_business_registries(
    envelope: ExecutionEnvelope,
    read_target: LocalFirestoreReadTarget,
    *,
    clock: BusinessInvestigationClock,
) -> tuple[CapabilityRegistry, TargetRuleRegistry]:
    capabilities = CapabilityRegistry()
    capabilities.register(
        build_firestore_business_capability_registration(
            read_target=read_target,
            target=envelope.target,
            clock=clock.now,
        )
    )
    rules = TargetRuleRegistry()
    rules.register(build_firestore_business_rule_registration())
    return capabilities, rules


async def execute_firestore_business_baseline(
    envelope: ExecutionEnvelope,
    read_target: LocalFirestoreReadTarget,
    *,
    clock: BusinessInvestigationClock | None = None,
    revision: int = 1,
    cancellation_event: asyncio.Event | None = None,
    progress_emitter: ProgressEmitter | None = None,
) -> FixedBaselineResult:
    """Execute the canonical one-read business-document baseline."""

    envelope = decode_contract(canonical_json_bytes(envelope), ExecutionEnvelope)
    if type(read_target) is not LocalFirestoreReadTarget:
        raise TypeError(
            "the business investigation requires the restricted read target"
        )
    selected_clock = clock or _SystemInvestigationClock()
    capabilities, rules = _firestore_business_registries(
        envelope,
        read_target,
        clock=selected_clock,
    )
    return await execute_fixed_plan(
        envelope,
        capabilities,
        rules,
        FIRESTORE_BUSINESS_FIXED_PROBE_PLAN,
        clock=selected_clock,
        revision=revision,
        cancellation_event=cancellation_event,
        progress_emitter=progress_emitter,
        additional_limitations=_FIRESTORE_BUSINESS_LIMITATIONS,
    )


async def execute_firestore_business_adaptive(
    envelope: ExecutionEnvelope,
    read_target: LocalFirestoreReadTarget,
    planner: AdvisoryPlanner,
    *,
    clock: BusinessInvestigationClock | None = None,
    revision: int = 1,
    cancellation_event: asyncio.Event | None = None,
    progress_emitter: ProgressEmitter | None = None,
) -> AdaptiveInvestigationResult:
    """Execute the canonical advisory business-document investigation."""

    envelope = decode_contract(canonical_json_bytes(envelope), ExecutionEnvelope)
    if type(read_target) is not LocalFirestoreReadTarget:
        raise TypeError(
            "the business investigation requires the restricted read target"
        )
    selected_clock = clock or _SystemInvestigationClock()
    capabilities, rules = _firestore_business_registries(
        envelope,
        read_target,
        clock=selected_clock,
    )
    return await execute_adaptive_investigation(
        envelope,
        capabilities,
        rules,
        planner,
        FIRESTORE_BUSINESS_ADAPTIVE_POLICY,
        clock=selected_clock,
        revision=revision,
        cancellation_event=cancellation_event,
        progress_emitter=progress_emitter,
        additional_limitations=_FIRESTORE_BUSINESS_LIMITATIONS,
    )


def run_firestore_business_baseline(
    envelope: ExecutionEnvelope,
    read_target: LocalFirestoreReadTarget,
    *,
    clock: BusinessInvestigationClock | None = None,
    revision: int = 1,
) -> FixedBaselineResult:
    """Synchronously execute the canonical business-document baseline."""

    envelope = decode_contract(canonical_json_bytes(envelope), ExecutionEnvelope)
    if type(read_target) is not LocalFirestoreReadTarget:
        raise TypeError(
            "the business investigation requires the restricted read target"
        )
    selected_clock = clock or _SystemInvestigationClock()
    capabilities, rules = _firestore_business_registries(
        envelope,
        read_target,
        clock=selected_clock,
    )
    return run_fixed_plan(
        envelope,
        capabilities,
        rules,
        FIRESTORE_BUSINESS_FIXED_PROBE_PLAN,
        clock=selected_clock,
        revision=revision,
        additional_limitations=_FIRESTORE_BUSINESS_LIMITATIONS,
    )


async def investigate_firestore_business(
    envelope: ExecutionEnvelope,
    read_target: LocalFirestoreReadTarget,
    *,
    clock: BusinessInvestigationClock | None = None,
    revision: int = 1,
) -> InvestigationReport:
    """Run the one-probe fixed local business-document evidence path."""

    return (
        await execute_firestore_business_baseline(
            envelope,
            read_target,
            clock=clock,
            revision=revision,
        )
    ).report


def run_firestore_business_investigation(
    envelope: ExecutionEnvelope,
    read_target: LocalFirestoreReadTarget,
    *,
    clock: BusinessInvestigationClock | None = None,
    revision: int = 1,
) -> InvestigationReport:
    """Synchronously execute the fixed local business-document evidence path."""

    return run_firestore_business_baseline(
        envelope,
        read_target,
        clock=clock,
        revision=revision,
    ).report


__all__ = [
    "FIRESTORE_BUSINESS_ACTION_POLICY_VERSION",
    "FIRESTORE_BUSINESS_ADAPTIVE_POLICY",
    "FIRESTORE_BUSINESS_EFFECT_IDS",
    "FIRESTORE_BUSINESS_FIXED_PROBE_PLAN",
    "FIRESTORE_BUSINESS_SCENARIO",
    "FIRESTORE_BUSINESS_TOOL_NAME",
    "FIRESTORE_BUSINESS_TOOL_VERSION",
    "BusinessInvestigationClock",
    "FirestoreBusinessScenarioDefinition",
    "execute_firestore_business_adaptive",
    "execute_firestore_business_baseline",
    "investigate_firestore_business",
    "run_firestore_business_baseline",
    "run_firestore_business_investigation",
]
