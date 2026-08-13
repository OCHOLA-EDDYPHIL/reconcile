"""Local Storage ambiguity scenario and its fixed evidence investigation."""

from __future__ import annotations

import asyncio
import hashlib
import time
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import Protocol

from pydantic import JsonValue

from reconcile.adapters.storage import (
    STORAGE_AUTHORITY_POLICY_VERSION,
    STORAGE_CAPABILITY_NAME,
    STORAGE_CAPABILITY_VERSION,
    STORAGE_CLASSIFICATION_POLICY_VERSION,
    build_storage_capability_registration,
    build_storage_rule_registration,
    build_storage_target,
)
from reconcile.contracts import (
    EXECUTION_ENVELOPE_VERSION,
    EXPECTED_EFFECT_VERSION,
    PROBE_REQUEST_VERSION,
    AmbiguityKind,
    AmbiguousExecution,
    CapabilityRef,
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
from reconcile.controller import CapabilityRegistry, ProbeController
from reconcile.evidence import EvidenceEngine, ProbeRun, TargetRuleRegistry
from reconcile.scenarios.adk_mutation import run_adk_mutation
from reconcile.scenarios.local_storage import (
    LocalStorageCleanupTarget,
    LocalStorageMutationTarget,
    LocalStorageReadTarget,
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

STORAGE_SCENARIO = ScenarioRef(name="storage-object", version="1.0.0")
STORAGE_EFFECT_ID = "storage-object-created"
STORAGE_ACTION_POLICY_VERSION = "action-v1"
STORAGE_TOOL_NAME = "create_storage_object"
STORAGE_TOOL_VERSION = "1.0.0"

_MAX_AGE_SECONDS = 60
_CLOCK_SKEW_SECONDS = 2


class InvestigationClock(Protocol):
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
        raise ValueError("storage scenario timestamps must include a UTC offset")
    return value.astimezone(UTC)


def _material(plan: ScenarioPlan) -> tuple[str, bytes, dict[str, str]]:
    identifiers = plan.identifiers
    object_name = f"runs/{plan.namespace_id}/object.json"
    content = canonical_json_value_bytes(
        {
            "operation_id": identifiers.operation_id,
            "run_id": identifiers.run_id,
            "seed": plan.seed,
        }
    )
    correlation = {
        "invocation_id": identifiers.invocation_id,
        "operation_id": identifiers.operation_id,
        "run_id": identifiers.run_id,
    }
    return object_name, content, correlation


def _mutation_arguments(
    *,
    bucket_name: str,
    object_name: str,
    content: bytes,
    correlation: dict[str, str],
) -> dict[str, JsonValue]:
    return {
        "bucket_name": bucket_name,
        "object_name": object_name,
        "content_sha256": hashlib.sha256(content).hexdigest(),
        "size_bytes": len(content),
        "correlation": dict(correlation),
    }


class StorageScenarioDefinition:
    """One isolated create-only object mutation through the actual ADK runner."""

    scenario = STORAGE_SCENARIO

    def __init__(
        self,
        database_path: str | Path,
        *,
        bucket_name: str = "reconcile-local-scenarios",
        invoked_at: datetime | None = None,
        target_clock: Callable[[], datetime] | None = None,
    ) -> None:
        self._mutation_target = LocalStorageMutationTarget(
            database_path,
            clock=target_clock,
        )
        self._read_target = LocalStorageReadTarget(database_path)
        self._cleanup_target = LocalStorageCleanupTarget(database_path)
        probe_target = build_storage_target(
            bucket_name=bucket_name,
            object_name="constructor-validation/object.json",
        )
        self._bucket_name = str(probe_target.scope["bucket_name"])
        self._invoked_at = _aware_utc(invoked_at or datetime.now(UTC))

    def investigate(
        self,
        envelope: ExecutionEnvelope,
        *,
        clock: InvestigationClock | None = None,
        revision: int = 1,
    ) -> InvestigationReport:
        """Run fixed evidence acquisition without exposing the receipt read handle."""

        return run_storage_investigation(
            envelope,
            self._read_target,
            clock=clock,
            revision=revision,
        )

    def prepare(self, plan: ScenarioPlan) -> ScenarioPreparation:
        identifiers = plan.identifiers
        if identifiers.function_call_id is None:
            raise ValueError(
                "the Storage ADK scenario requires a function-call identifier"
            )
        object_name, content, correlation = _material(plan)
        arguments = _mutation_arguments(
            bucket_name=self._bucket_name,
            object_name=object_name,
            content=content,
            correlation=correlation,
        )
        target = build_storage_target(
            bucket_name=self._bucket_name,
            object_name=object_name,
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
                detail="Sealed local Storage scenario envelope template.",
            ),
            expected_effects=(
                ExpectedEffect(
                    schema_version=EXPECTED_EFFECT_VERSION,
                    effect_id=STORAGE_EFFECT_ID,
                    commit_scope="object-create",
                    predicate={
                        "content_sha256": arguments["content_sha256"],
                        "size_bytes": arguments["size_bytes"],
                        "correlation": arguments["correlation"],
                    },
                    description=(
                        "The exact correlated object generation exists in the local "
                        "SQLite Storage-shaped target."
                    ),
                ),
            ),
            context=EnvelopeContext(
                invocation=OriginalInvocation(
                    invocation_id=identifiers.invocation_id,
                    function_call_id=identifiers.function_call_id,
                    tool_name=STORAGE_TOOL_NAME,
                    tool_version=STORAGE_TOOL_VERSION,
                    arguments=arguments,
                    arguments_sha256=hashlib.sha256(
                        canonical_json_value_bytes(arguments)
                    ).hexdigest(),
                ),
                enabled_capabilities=(
                    CapabilityRef(
                        name=STORAGE_CAPABILITY_NAME,
                        version=STORAGE_CAPABILITY_VERSION,
                    ),
                ),
                correlation_fields=correlation,
                evidence_budget=EvidenceBudget(
                    max_probes=1,
                    max_elapsed_ms=5_000,
                    max_total_result_bytes=16_384,
                    max_cost_units=1,
                ),
                freshness=FreshnessPolicy(
                    max_age_seconds=_MAX_AGE_SECONDS,
                    clock_skew_seconds=_CLOCK_SKEW_SECONDS,
                ),
                policies=PolicyReferences(
                    authority=STORAGE_AUTHORITY_POLICY_VERSION,
                    classification=STORAGE_CLASSIFICATION_POLICY_VERSION,
                    action=STORAGE_ACTION_POLICY_VERSION,
                ),
            ),
        )
        return ScenarioPreparation(
            execution_envelope=envelope,
            cleanup_manifest=ScenarioCleanupManifest(
                resource_ids=(
                    f"storage-object:{self._bucket_name}/{object_name}",
                    f"storage-receipt:{identifiers.operation_id}",
                )
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
        object_name, content, correlation = _material(prepared.plan)
        expected_arguments = _mutation_arguments(
            bucket_name=self._bucket_name,
            object_name=object_name,
            content=content,
            correlation=correlation,
        )
        if canonical_json_value_bytes(envelope.context.invocation.arguments) != (
            canonical_json_value_bytes(expected_arguments)
        ):
            raise ValueError("sealed Storage mutation arguments changed")
        function_call_id = prepared.plan.identifiers.function_call_id
        if function_call_id is None:
            raise ValueError(
                "the Storage ADK scenario requires a function-call identifier"
            )

        def create_storage_object(
            bucket_name: str,
            object_name: str,
            content_sha256: str,
            size_bytes: int,
            correlation: dict[str, str],
        ) -> None:
            received = {
                "bucket_name": bucket_name,
                "object_name": object_name,
                "content_sha256": content_sha256,
                "size_bytes": size_bytes,
                "correlation": correlation,
            }
            if canonical_json_value_bytes(received) != canonical_json_value_bytes(
                expected_arguments
            ):
                raise ValueError("ADK changed the Storage mutation arguments")
            boundary.before_commit()
            self._mutation_target.commit_object(
                operation_id=prepared.plan.identifiers.operation_id,
                bucket=self._bucket_name,
                name=object_name,
                content=content,
                correlation=correlation,
            )
            boundary.after_commit()

        public_response = run_adk_mutation(
            create_storage_object,
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
        object_name, _, _ = _material(prepared.plan)
        return self._cleanup_target.count_owned(
            bucket=self._bucket_name,
            name=object_name,
            operation_id=prepared.plan.identifiers.operation_id,
        )

    def cleanup(self, prepared: PreparedScenario) -> ScenarioCleanupOutcome:
        object_name, _, _ = _material(prepared.plan)
        deletion = self._cleanup_target.delete_owned(
            bucket=self._bucket_name,
            name=object_name,
            operation_id=prepared.plan.identifiers.operation_id,
        )
        removed: list[str] = []
        if deletion.object_removed:
            removed.append(f"storage-object:{self._bucket_name}/{object_name}")
        if deletion.receipt_removed:
            removed.append(f"storage-receipt:{prepared.plan.identifiers.operation_id}")
        return ScenarioCleanupOutcome(removed_resource_ids=tuple(removed))


async def investigate_storage(
    envelope: ExecutionEnvelope,
    read_target: LocalStorageReadTarget,
    *,
    clock: InvestigationClock | None = None,
    revision: int = 1,
) -> InvestigationReport:
    """Run the one-probe fixed local Storage evidence path."""

    envelope = decode_contract(canonical_json_bytes(envelope), ExecutionEnvelope)
    if type(read_target) is not LocalStorageReadTarget:
        raise TypeError("the Storage investigation requires the restricted read target")
    selected_clock = clock or _SystemInvestigationClock()

    capabilities = CapabilityRegistry()
    capabilities.register(
        build_storage_capability_registration(
            read_target=read_target,
            target=envelope.target,
            clock=selected_clock.now,
        )
    )
    rules = TargetRuleRegistry()
    rules.register(build_storage_rule_registration())

    request = ProbeRequest(
        schema_version=PROBE_REQUEST_VERSION,
        capability_name=STORAGE_CAPABILITY_NAME,
        capability_version=STORAGE_CAPABILITY_VERSION,
        relevant_effect_ids=tuple(
            effect.effect_id for effect in envelope.expected_effects
        ),
        arguments={},
        rationale="Read the exact local object metadata and its immutable receipt.",
    )
    controller = ProbeController(envelope, capabilities, clock=selected_clock)
    engine = EvidenceEngine(envelope, rules)
    execution = await controller.execute(request)
    engine.process(ProbeRun(request=request, execution=execution))
    updated_at = selected_clock.now()
    return engine.report(
        controller.audit_trail,
        created_at=envelope.ambiguity.observed_at,
        updated_at=updated_at,
        revision=revision,
    )


def run_storage_investigation(
    envelope: ExecutionEnvelope,
    read_target: LocalStorageReadTarget,
    *,
    clock: InvestigationClock | None = None,
    revision: int = 1,
) -> InvestigationReport:
    """Synchronously execute the fixed local Storage evidence path."""

    try:
        asyncio.get_running_loop()
    except RuntimeError:
        pass
    else:
        raise RuntimeError(
            "run_storage_investigation cannot run inside an active event loop"
        )
    return asyncio.run(
        investigate_storage(
            envelope,
            read_target,
            clock=clock,
            revision=revision,
        )
    )


__all__ = [
    "STORAGE_ACTION_POLICY_VERSION",
    "STORAGE_EFFECT_ID",
    "STORAGE_SCENARIO",
    "STORAGE_TOOL_NAME",
    "STORAGE_TOOL_VERSION",
    "InvestigationClock",
    "StorageScenarioDefinition",
    "investigate_storage",
    "run_storage_investigation",
]
