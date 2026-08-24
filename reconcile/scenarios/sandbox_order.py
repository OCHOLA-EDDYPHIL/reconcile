"""Local sandbox-order ambiguity scenario with deliberately weak evidence."""

from __future__ import annotations

import asyncio
import hashlib
import time
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Protocol

from pydantic import JsonValue

from reconcile.adapters.sandbox_order import (
    SANDBOX_ORDER_AGGREGATE_CAPABILITY_NAME,
    SANDBOX_ORDER_AUTHORITY_POLICY_VERSION,
    SANDBOX_ORDER_CAPABILITY_VERSION,
    SANDBOX_ORDER_CLASSIFICATION_POLICY_VERSION,
    SANDBOX_ORDER_CLOUD_PROFILE,
    SANDBOX_ORDER_INGRESS_CAPABILITY_NAME,
    SANDBOX_ORDER_LOCAL_PROFILE,
    SandboxOrderAdapterProfile,
    build_sandbox_order_aggregate_capability_registration,
    build_sandbox_order_aggregate_rule_registration,
    build_sandbox_order_ingress_capability_registration,
    build_sandbox_order_ingress_rule_registration,
    build_sandbox_order_target,
)
from reconcile.adaptive import (
    AdaptiveInvestigationPolicy,
    AdaptiveInvestigationResult,
    AdvisoryPlanner,
    execute_adaptive_investigation,
    execute_conditional_adaptive_investigation,
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
from reconcile.controller import CapabilityRegistry, ProbeDurabilityObserver
from reconcile.evidence import TargetRuleRegistry
from reconcile.progress import ProgressEmitter
from reconcile.scenarios.adk_mutation import run_adk_mutation
from reconcile.scenarios.local_order import (
    HiddenOrderOutcome,
    LocalOrderCleanupTarget,
    LocalOrderMutationTarget,
    LocalOrderReadTarget,
    SandboxOrderReadPort,
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

SANDBOX_ORDER_SCENARIO = ScenarioRef(name="sandbox-order-unknown", version="1.0.0")
SANDBOX_ORDER_EFFECT_ID = "order-accepted"
SANDBOX_ORDER_ACTION_POLICY_VERSION = "action-v1"
SANDBOX_ORDER_TOOL_NAME = "submit_sandbox_order"
SANDBOX_ORDER_TOOL_VERSION = "1.0.0"
SANDBOX_ORDER_ITEM_CODE = "widget-blue"
SANDBOX_ORDER_QUANTITY = 2
SANDBOX_ORDER_INGRESS_FIRST = (
    SANDBOX_ORDER_INGRESS_CAPABILITY_NAME,
    SANDBOX_ORDER_AGGREGATE_CAPABILITY_NAME,
)
SANDBOX_ORDER_AGGREGATE_FIRST = (
    SANDBOX_ORDER_AGGREGATE_CAPABILITY_NAME,
    SANDBOX_ORDER_INGRESS_CAPABILITY_NAME,
)

SANDBOX_ORDER_ADAPTIVE_POLICY = AdaptiveInvestigationPolicy(
    name="sandbox-order-adaptive-investigation",
    version="1.0.0",
    sufficient_classifications=(
        Classification.COMMITTED,
        Classification.NOT_COMMITTED,
    ),
    max_turns=4,
    planner_timeout_ms=4_000,
    include_explanation=True,
)

SANDBOX_ORDER_CONDITIONAL_POLICY = AdaptiveInvestigationPolicy(
    name="sandbox-order-conditional-investigation",
    version="1.0.0",
    sufficient_classifications=(
        Classification.COMMITTED,
        Classification.NOT_COMMITTED,
    ),
    max_turns=1,
    planner_timeout_ms=35_000,
    include_explanation=False,
)

_MAX_AGE_SECONDS = 60
_CLOCK_SKEW_SECONDS = 2

_SANDBOX_ORDER_LIMITATIONS = (
    (
        "The local sandbox exposes no authoritative order-status lookup or "
        "durable unique order correlation."
    ),
    (
        "Ingress logs and coarse aggregate counts are weak, non-discriminating "
        "observations and cannot establish order commitment."
    ),
    (
        "A human operator may escalate the indeterminate result; deterministic "
        "action gates deny automatic retry and compensation."
    ),
    (
        "Evidence comes only from a local SQLite sandbox and does not establish "
        "third-party API, network, latency, or hosted isolation behavior."
    ),
)

_HOSTED_SANDBOX_ORDER_LIMITATIONS = (
    (
        "The hosted sandbox exposes no authoritative order-status lookup or "
        "durable unique order correlation."
    ),
    (
        "Ingress logs and coarse aggregate counts are weak, non-discriminating "
        "observations and cannot establish order commitment."
    ),
    (
        "A human operator may escalate the indeterminate result; deterministic "
        "action gates deny automatic retry and compensation."
    ),
    (
        "The controller performs only the allowlisted authenticated weak reads; "
        "the sandbox route cannot expose private order state."
    ),
)

type SandboxOrderProbeOrder = tuple[str, str]


class SandboxOrderInvestigationClock(Protocol):
    """Wall and monotonic time needed by one bounded investigation."""

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
        raise ValueError("sandbox-order timestamps must include a UTC offset")
    return value.astimezone(UTC)


def _mutation_arguments() -> dict[str, JsonValue]:
    return {
        "item_code": SANDBOX_ORDER_ITEM_CODE,
        "quantity": SANDBOX_ORDER_QUANTITY,
    }


def _owner_token(plan: ScenarioPlan) -> str:
    material = {
        "namespace_id": plan.namespace_id,
        "operation_id": plan.identifiers.operation_id,
    }
    digest = hashlib.sha256(canonical_json_value_bytes(material)).hexdigest()
    return f"sandbox-owner-{digest[:32]}"


@dataclass(frozen=True, slots=True)
class SandboxOrderOperationMaterial:
    """Private mutation coordinates derived only behind sandbox authority."""

    sandbox_id: str
    owner_token: str
    item_code: str
    quantity: int


def build_sandbox_order_operation_material(
    plan: ScenarioPlan,
) -> SandboxOrderOperationMaterial:
    """Derive the exact sandbox mutation without placing its owner on the wire."""

    if type(plan) is not ScenarioPlan:
        raise TypeError("sandbox material requires an exact scenario plan")
    return SandboxOrderOperationMaterial(
        sandbox_id=plan.namespace_id,
        owner_token=_owner_token(plan),
        item_code=SANDBOX_ORDER_ITEM_CODE,
        quantity=SANDBOX_ORDER_QUANTITY,
    )


def _cleanup_resource_ids(plan: ScenarioPlan) -> tuple[str, ...]:
    owner_token = _owner_token(plan)
    prefix = f"sandbox-order:{plan.namespace_id}/{owner_token}"
    return (
        f"{prefix}/order",
        f"{prefix}/ingress",
        f"{prefix}/receipt",
    )


def build_hosted_sandbox_order_scenario_preparation(
    plan: ScenarioPlan,
    *,
    invoked_at: datetime,
) -> ScenarioPreparation:
    """Build the sealed hosted weak-evidence envelope and exact cleanup scope."""

    if type(plan) is not ScenarioPlan:
        raise TypeError("sandbox preparation requires an exact scenario plan")
    identifiers = plan.identifiers
    if identifiers.function_call_id is None:
        raise ValueError(
            "the sandbox-order ADK scenario requires a function-call identifier"
        )
    material = build_sandbox_order_operation_material(plan)
    arguments = _mutation_arguments()
    target = build_sandbox_order_target(
        sandbox_id=material.sandbox_id,
        profile=SANDBOX_ORDER_CLOUD_PROFILE,
    )
    timestamp = _aware_utc(invoked_at)
    envelope = ExecutionEnvelope(
        schema_version=EXECUTION_ENVELOPE_VERSION,
        investigation_id=identifiers.investigation_id,
        operation_id=identifiers.operation_id,
        target=target,
        invoked_at=timestamp,
        ambiguity=AmbiguousExecution(
            kind=AmbiguityKind.OTHER,
            observed_at=timestamp,
            detail="Sealed hosted sandbox-order scenario envelope template.",
        ),
        expected_effects=(
            ExpectedEffect(
                schema_version=EXPECTED_EFFECT_VERSION,
                effect_id=SANDBOX_ORDER_EFFECT_ID,
                commit_scope="sandbox-order",
                predicate={
                    "item_code": SANDBOX_ORDER_ITEM_CODE,
                    "quantity": SANDBOX_ORDER_QUANTITY,
                },
                description=(
                    "The sandbox accepted the requested order as one private "
                    "business effect."
                ),
            ),
        ),
        context=EnvelopeContext(
            invocation=OriginalInvocation(
                invocation_id=identifiers.invocation_id,
                function_call_id=identifiers.function_call_id,
                tool_name=SANDBOX_ORDER_TOOL_NAME,
                tool_version=SANDBOX_ORDER_TOOL_VERSION,
                arguments=arguments,
                arguments_sha256=hashlib.sha256(
                    canonical_json_value_bytes(arguments)
                ).hexdigest(),
            ),
            enabled_capabilities=(
                CapabilityRef(
                    name=SANDBOX_ORDER_INGRESS_CAPABILITY_NAME,
                    version=SANDBOX_ORDER_CAPABILITY_VERSION,
                ),
                CapabilityRef(
                    name=SANDBOX_ORDER_AGGREGATE_CAPABILITY_NAME,
                    version=SANDBOX_ORDER_CAPABILITY_VERSION,
                ),
            ),
            correlation_fields={},
            evidence_budget=EvidenceBudget(
                max_probes=2,
                max_elapsed_ms=40_000,
                max_total_result_bytes=8_192,
                max_cost_units=2,
            ),
            freshness=FreshnessPolicy(
                max_age_seconds=_MAX_AGE_SECONDS,
                clock_skew_seconds=_CLOCK_SKEW_SECONDS,
            ),
            policies=PolicyReferences(
                authority=SANDBOX_ORDER_CLOUD_PROFILE.authority_policy_version,
                classification=SANDBOX_ORDER_CLASSIFICATION_POLICY_VERSION,
                action=SANDBOX_ORDER_ACTION_POLICY_VERSION,
            ),
        ),
    )
    prefix = f"reconcile-sandbox-observations/{material.sandbox_id}/weak-observations"
    return ScenarioPreparation(
        execution_envelope=envelope,
        cleanup_manifest=ScenarioCleanupManifest(
            resource_ids=(
                f"reconcile-sandbox-private-state/{material.sandbox_id}",
                f"{prefix}/ingress",
                f"{prefix}/aggregate",
            )
        ),
    )


def _validated_probe_order(
    probe_order: SandboxOrderProbeOrder,
) -> SandboxOrderProbeOrder:
    if type(probe_order) is not tuple or probe_order not in {
        SANDBOX_ORDER_INGRESS_FIRST,
        SANDBOX_ORDER_AGGREGATE_FIRST,
    }:
        raise ValueError("sandbox-order investigation requires a permitted probe order")
    return probe_order


class SandboxOrderScenarioDefinition:
    """One ambiguous local order mutation through the offline ADK runner."""

    scenario = SANDBOX_ORDER_SCENARIO

    def __init__(
        self,
        private_database_path: str | Path,
        observation_database_path: str | Path,
        *,
        hidden_outcome: HiddenOrderOutcome,
        invoked_at: datetime | None = None,
        target_clock: Callable[[], datetime] | None = None,
    ) -> None:
        self._mutation_target = LocalOrderMutationTarget(
            private_database_path,
            observation_database_path,
            hidden_outcome=hidden_outcome,
            clock=target_clock,
        )
        self._read_target = LocalOrderReadTarget(observation_database_path)
        self._cleanup_target = LocalOrderCleanupTarget(
            private_database_path,
            observation_database_path,
        )
        self._invoked_at = _aware_utc(invoked_at or datetime.now(UTC))

    def investigate(
        self,
        envelope: ExecutionEnvelope,
        *,
        probe_order: SandboxOrderProbeOrder = SANDBOX_ORDER_INGRESS_FIRST,
        clock: SandboxOrderInvestigationClock | None = None,
        revision: int = 1,
    ) -> InvestigationReport:
        """Run bounded weak reads without exposing the private order store."""

        return self.baseline(
            envelope,
            probe_order=probe_order,
            clock=clock,
            revision=revision,
        ).report

    def baseline(
        self,
        envelope: ExecutionEnvelope,
        *,
        probe_order: SandboxOrderProbeOrder = SANDBOX_ORDER_INGRESS_FIRST,
        clock: SandboxOrderInvestigationClock | None = None,
        revision: int = 1,
    ) -> FixedBaselineResult:
        """Run a permitted fixed baseline without exposing private order state."""

        return run_sandbox_order_baseline(
            envelope,
            self._read_target,
            probe_order=probe_order,
            clock=clock,
            revision=revision,
        )

    async def adaptive(
        self,
        envelope: ExecutionEnvelope,
        planner: AdvisoryPlanner,
        *,
        clock: SandboxOrderInvestigationClock | None = None,
        revision: int = 1,
        cancellation_event: asyncio.Event | None = None,
        progress_emitter: ProgressEmitter | None = None,
        durability_observer: ProbeDurabilityObserver | None = None,
    ) -> AdaptiveInvestigationResult:
        """Run the canonical bounded adaptive sandbox-order investigation."""

        return await execute_sandbox_order_adaptive(
            envelope,
            self._read_target,
            planner,
            clock=clock,
            revision=revision,
            cancellation_event=cancellation_event,
            progress_emitter=progress_emitter,
            durability_observer=durability_observer,
        )

    def prepare(self, plan: ScenarioPlan) -> ScenarioPreparation:
        identifiers = plan.identifiers
        if identifiers.function_call_id is None:
            raise ValueError(
                "the sandbox-order ADK scenario requires a function-call identifier"
            )
        arguments = _mutation_arguments()
        target = build_sandbox_order_target(sandbox_id=plan.namespace_id)
        envelope = ExecutionEnvelope(
            schema_version=EXECUTION_ENVELOPE_VERSION,
            investigation_id=identifiers.investigation_id,
            operation_id=identifiers.operation_id,
            target=target,
            invoked_at=self._invoked_at,
            ambiguity=AmbiguousExecution(
                kind=AmbiguityKind.OTHER,
                observed_at=self._invoked_at,
                detail="Sealed local sandbox-order scenario envelope template.",
            ),
            expected_effects=(
                ExpectedEffect(
                    schema_version=EXPECTED_EFFECT_VERSION,
                    effect_id=SANDBOX_ORDER_EFFECT_ID,
                    commit_scope="sandbox-order",
                    predicate={
                        "item_code": SANDBOX_ORDER_ITEM_CODE,
                        "quantity": SANDBOX_ORDER_QUANTITY,
                    },
                    description=(
                        "The sandbox accepted the requested order as one private "
                        "business effect."
                    ),
                ),
            ),
            context=EnvelopeContext(
                invocation=OriginalInvocation(
                    invocation_id=identifiers.invocation_id,
                    function_call_id=identifiers.function_call_id,
                    tool_name=SANDBOX_ORDER_TOOL_NAME,
                    tool_version=SANDBOX_ORDER_TOOL_VERSION,
                    arguments=arguments,
                    arguments_sha256=hashlib.sha256(
                        canonical_json_value_bytes(arguments)
                    ).hexdigest(),
                ),
                enabled_capabilities=(
                    CapabilityRef(
                        name=SANDBOX_ORDER_INGRESS_CAPABILITY_NAME,
                        version=SANDBOX_ORDER_CAPABILITY_VERSION,
                    ),
                    CapabilityRef(
                        name=SANDBOX_ORDER_AGGREGATE_CAPABILITY_NAME,
                        version=SANDBOX_ORDER_CAPABILITY_VERSION,
                    ),
                ),
                correlation_fields={},
                evidence_budget=EvidenceBudget(
                    max_probes=2,
                    max_elapsed_ms=40_000,
                    max_total_result_bytes=8_192,
                    max_cost_units=2,
                ),
                freshness=FreshnessPolicy(
                    max_age_seconds=_MAX_AGE_SECONDS,
                    clock_skew_seconds=_CLOCK_SKEW_SECONDS,
                ),
                policies=PolicyReferences(
                    authority=SANDBOX_ORDER_AUTHORITY_POLICY_VERSION,
                    classification=SANDBOX_ORDER_CLASSIFICATION_POLICY_VERSION,
                    action=SANDBOX_ORDER_ACTION_POLICY_VERSION,
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
        expected_arguments = _mutation_arguments()
        if canonical_json_value_bytes(envelope.context.invocation.arguments) != (
            canonical_json_value_bytes(expected_arguments)
        ):
            raise ValueError("sealed sandbox-order mutation arguments changed")
        function_call_id = prepared.plan.identifiers.function_call_id
        if function_call_id is None:
            raise ValueError(
                "the sandbox-order ADK scenario requires a function-call identifier"
            )
        owner_token = _owner_token(prepared.plan)

        def submit_sandbox_order(item_code: str, quantity: int) -> None:
            received = {"item_code": item_code, "quantity": quantity}
            if canonical_json_value_bytes(received) != canonical_json_value_bytes(
                expected_arguments
            ):
                raise ValueError("ADK changed the sandbox-order mutation arguments")
            boundary.before_commit()
            self._mutation_target.submit_order(
                owner_token=owner_token,
                item_code=item_code,
                quantity=quantity,
            )
            boundary.after_commit()

        public_response = run_adk_mutation(
            submit_sandbox_order,
            arguments=expected_arguments,
            public_response={"accepted": True},
            function_call_id=function_call_id,
            invocation_id=prepared.plan.identifiers.invocation_id,
        )
        return ScenarioMutationResponse(is_error=False, payload=public_response)

    def remaining(self, prepared: PreparedScenario) -> int | None:
        return self._cleanup_target.count_owned(owner_token=_owner_token(prepared.plan))

    def cleanup(self, prepared: PreparedScenario) -> ScenarioCleanupOutcome:
        deletion = self._cleanup_target.delete_owned(
            owner_token=_owner_token(prepared.plan)
        )
        declared = _cleanup_resource_ids(prepared.plan)
        removed: list[str] = []
        if deletion.order_removed:
            removed.append(declared[0])
        if deletion.ingress_removed:
            removed.append(declared[1])
        if deletion.receipt_removed:
            removed.append(declared[2])
        return ScenarioCleanupOutcome(removed_resource_ids=tuple(removed))


def _probe_request(
    capability_name: str,
) -> ProbeRequest:
    rationale = {
        SANDBOX_ORDER_INGRESS_CAPABILITY_NAME: (
            "Read the generic sandbox ingress observation without order correlation."
        ),
        SANDBOX_ORDER_AGGREGATE_CAPABILITY_NAME: (
            "Read the coarse sandbox order-count band without order identity."
        ),
    }[capability_name]
    return ProbeRequest(
        schema_version=PROBE_REQUEST_VERSION,
        capability_name=capability_name,
        capability_version=SANDBOX_ORDER_CAPABILITY_VERSION,
        relevant_effect_ids=(SANDBOX_ORDER_EFFECT_ID,),
        arguments={},
        rationale=rationale,
    )


SANDBOX_ORDER_FIXED_PROBE_PLAN = FixedProbePlan(
    name="sandbox-order-fixed-baseline",
    version="1.0.0",
    steps=tuple(
        FixedProbeStep(
            request=_probe_request(capability_name),
            required=False,
        )
        for capability_name in SANDBOX_ORDER_INGRESS_FIRST
    ),
)

_SANDBOX_ORDER_AGGREGATE_FIRST_PLAN = FixedProbePlan(
    name="sandbox-order-fixed-baseline",
    version="1.0.0-aggregate-first",
    steps=tuple(
        FixedProbeStep(
            request=_probe_request(capability_name),
            required=False,
        )
        for capability_name in SANDBOX_ORDER_AGGREGATE_FIRST
    ),
)


def _sandbox_order_plan(
    probe_order: SandboxOrderProbeOrder,
) -> FixedProbePlan:
    probe_order = _validated_probe_order(probe_order)
    if probe_order == SANDBOX_ORDER_INGRESS_FIRST:
        return SANDBOX_ORDER_FIXED_PROBE_PLAN
    return _SANDBOX_ORDER_AGGREGATE_FIRST_PLAN


def _sandbox_order_registries(
    envelope: ExecutionEnvelope,
    read_target: SandboxOrderReadPort,
    *,
    clock: SandboxOrderInvestigationClock,
    profile: SandboxOrderAdapterProfile = SANDBOX_ORDER_LOCAL_PROFILE,
) -> tuple[CapabilityRegistry, TargetRuleRegistry]:
    capabilities = CapabilityRegistry()
    capabilities.register(
        build_sandbox_order_ingress_capability_registration(
            read_target=read_target,
            target=envelope.target,
            clock=clock.now,
            profile=profile,
        )
    )
    capabilities.register(
        build_sandbox_order_aggregate_capability_registration(
            read_target=read_target,
            target=envelope.target,
            clock=clock.now,
            profile=profile,
        )
    )
    rules = TargetRuleRegistry()
    rules.register(build_sandbox_order_ingress_rule_registration(profile=profile))
    rules.register(build_sandbox_order_aggregate_rule_registration(profile=profile))
    return capabilities, rules


def _conditional_profile(
    read_target: SandboxOrderReadPort,
) -> SandboxOrderAdapterProfile:
    if type(read_target) is LocalOrderReadTarget:
        return SANDBOX_ORDER_LOCAL_PROFILE
    from reconcile.hosted.sandbox import HostedSandboxEvidenceTarget

    if type(read_target) is HostedSandboxEvidenceTarget:
        return SANDBOX_ORDER_CLOUD_PROFILE
    raise TypeError(
        "the conditional sandbox-order investigation requires a sealed read target"
    )


async def execute_sandbox_order_baseline(
    envelope: ExecutionEnvelope,
    read_target: LocalOrderReadTarget,
    *,
    probe_order: SandboxOrderProbeOrder = SANDBOX_ORDER_INGRESS_FIRST,
    clock: SandboxOrderInvestigationClock | None = None,
    revision: int = 1,
    cancellation_event: asyncio.Event | None = None,
    progress_emitter: ProgressEmitter | None = None,
    durability_observer: ProbeDurabilityObserver | None = None,
    elapsed_offset_ms: int = 0,
) -> FixedBaselineResult:
    """Execute a permitted two-read weak-evidence baseline."""

    envelope = decode_contract(canonical_json_bytes(envelope), ExecutionEnvelope)
    if type(read_target) is not LocalOrderReadTarget:
        raise TypeError(
            "the sandbox-order investigation requires the restricted read target"
        )
    plan = _sandbox_order_plan(probe_order)
    selected_clock = clock or _SystemInvestigationClock()
    capabilities, rules = _sandbox_order_registries(
        envelope,
        read_target,
        clock=selected_clock,
    )
    return await execute_fixed_plan(
        envelope,
        capabilities,
        rules,
        plan,
        clock=selected_clock,
        revision=revision,
        cancellation_event=cancellation_event,
        progress_emitter=progress_emitter,
        additional_limitations=_SANDBOX_ORDER_LIMITATIONS,
        durability_observer=durability_observer,
        elapsed_offset_ms=elapsed_offset_ms,
    )


async def execute_hosted_sandbox_order_fixed(
    envelope: ExecutionEnvelope,
    read_target: SandboxOrderReadPort,
    *,
    probe_order: SandboxOrderProbeOrder = SANDBOX_ORDER_INGRESS_FIRST,
    clock: SandboxOrderInvestigationClock | None = None,
    revision: int = 1,
    cancellation_event: asyncio.Event | None = None,
    progress_emitter: ProgressEmitter | None = None,
    durability_observer: ProbeDurabilityObserver | None = None,
    elapsed_offset_ms: int = 0,
) -> FixedBaselineResult:
    """Execute the deterministic hosted two-read weak-evidence path."""

    from reconcile.hosted.sandbox import HostedSandboxEvidenceTarget

    envelope = decode_contract(canonical_json_bytes(envelope), ExecutionEnvelope)
    if type(read_target) is not HostedSandboxEvidenceTarget:
        raise TypeError("the hosted sandbox investigation requires the sealed reader")
    plan = _sandbox_order_plan(probe_order)
    selected_clock = clock or _SystemInvestigationClock()
    capabilities, rules = _sandbox_order_registries(
        envelope,
        read_target,
        clock=selected_clock,
        profile=SANDBOX_ORDER_CLOUD_PROFILE,
    )
    return await execute_fixed_plan(
        envelope,
        capabilities,
        rules,
        plan,
        clock=selected_clock,
        revision=revision,
        cancellation_event=cancellation_event,
        progress_emitter=progress_emitter,
        additional_limitations=_HOSTED_SANDBOX_ORDER_LIMITATIONS,
        durability_observer=durability_observer,
        elapsed_offset_ms=elapsed_offset_ms,
    )


async def execute_sandbox_order_adaptive(
    envelope: ExecutionEnvelope,
    read_target: LocalOrderReadTarget,
    planner: AdvisoryPlanner,
    *,
    clock: SandboxOrderInvestigationClock | None = None,
    revision: int = 1,
    cancellation_event: asyncio.Event | None = None,
    progress_emitter: ProgressEmitter | None = None,
    durability_observer: ProbeDurabilityObserver | None = None,
) -> AdaptiveInvestigationResult:
    """Execute the canonical advisory sandbox-order investigation."""

    envelope = decode_contract(canonical_json_bytes(envelope), ExecutionEnvelope)
    if type(read_target) is not LocalOrderReadTarget:
        raise TypeError(
            "the sandbox-order investigation requires the restricted read target"
        )
    selected_clock = clock or _SystemInvestigationClock()
    capabilities, rules = _sandbox_order_registries(
        envelope,
        read_target,
        clock=selected_clock,
    )
    return await execute_adaptive_investigation(
        envelope,
        capabilities,
        rules,
        planner,
        SANDBOX_ORDER_ADAPTIVE_POLICY,
        clock=selected_clock,
        revision=revision,
        cancellation_event=cancellation_event,
        progress_emitter=progress_emitter,
        additional_limitations=_SANDBOX_ORDER_LIMITATIONS,
        durability_observer=durability_observer,
    )


async def execute_sandbox_order_conditional(
    envelope: ExecutionEnvelope,
    read_target: SandboxOrderReadPort,
    planner: AdvisoryPlanner,
    *,
    clock: SandboxOrderInvestigationClock | None = None,
    revision: int = 1,
    cancellation_event: asyncio.Event | None = None,
    progress_emitter: ProgressEmitter | None = None,
    durability_observer: ProbeDurabilityObserver | None = None,
) -> AdaptiveInvestigationResult:
    """Read ingress first, then allow one advisory aggregate-read selection."""

    envelope = decode_contract(canonical_json_bytes(envelope), ExecutionEnvelope)
    profile = _conditional_profile(read_target)
    selected_clock = clock or _SystemInvestigationClock()
    capabilities, rules = _sandbox_order_registries(
        envelope,
        read_target,
        clock=selected_clock,
        profile=profile,
    )
    return await execute_conditional_adaptive_investigation(
        envelope,
        capabilities,
        rules,
        planner,
        SANDBOX_ORDER_CONDITIONAL_POLICY,
        _probe_request(SANDBOX_ORDER_INGRESS_CAPABILITY_NAME),
        clock=selected_clock,
        revision=revision,
        cancellation_event=cancellation_event,
        progress_emitter=progress_emitter,
        additional_limitations=(
            _SANDBOX_ORDER_LIMITATIONS
            if profile is SANDBOX_ORDER_LOCAL_PROFILE
            else _HOSTED_SANDBOX_ORDER_LIMITATIONS
        ),
        durability_observer=durability_observer,
    )


def run_sandbox_order_baseline(
    envelope: ExecutionEnvelope,
    read_target: LocalOrderReadTarget,
    *,
    probe_order: SandboxOrderProbeOrder = SANDBOX_ORDER_INGRESS_FIRST,
    clock: SandboxOrderInvestigationClock | None = None,
    revision: int = 1,
) -> FixedBaselineResult:
    """Synchronously execute a permitted weak-evidence baseline."""

    envelope = decode_contract(canonical_json_bytes(envelope), ExecutionEnvelope)
    if type(read_target) is not LocalOrderReadTarget:
        raise TypeError(
            "the sandbox-order investigation requires the restricted read target"
        )
    plan = _sandbox_order_plan(probe_order)
    selected_clock = clock or _SystemInvestigationClock()
    capabilities, rules = _sandbox_order_registries(
        envelope,
        read_target,
        clock=selected_clock,
    )
    return run_fixed_plan(
        envelope,
        capabilities,
        rules,
        plan,
        clock=selected_clock,
        revision=revision,
        additional_limitations=_SANDBOX_ORDER_LIMITATIONS,
    )


async def investigate_sandbox_order(
    envelope: ExecutionEnvelope,
    read_target: LocalOrderReadTarget,
    *,
    probe_order: SandboxOrderProbeOrder = SANDBOX_ORDER_INGRESS_FIRST,
    clock: SandboxOrderInvestigationClock | None = None,
    revision: int = 1,
) -> InvestigationReport:
    """Run both permitted weak reads through deterministic product boundaries."""

    return (
        await execute_sandbox_order_baseline(
            envelope,
            read_target,
            probe_order=probe_order,
            clock=clock,
            revision=revision,
        )
    ).report


def run_sandbox_order_investigation(
    envelope: ExecutionEnvelope,
    read_target: LocalOrderReadTarget,
    *,
    probe_order: SandboxOrderProbeOrder = SANDBOX_ORDER_INGRESS_FIRST,
    clock: SandboxOrderInvestigationClock | None = None,
    revision: int = 1,
) -> InvestigationReport:
    """Synchronously execute the bounded local sandbox-order investigation."""

    return run_sandbox_order_baseline(
        envelope,
        read_target,
        probe_order=probe_order,
        clock=clock,
        revision=revision,
    ).report


__all__ = [
    "SANDBOX_ORDER_ACTION_POLICY_VERSION",
    "SANDBOX_ORDER_ADAPTIVE_POLICY",
    "SANDBOX_ORDER_AGGREGATE_FIRST",
    "SANDBOX_ORDER_CONDITIONAL_POLICY",
    "SANDBOX_ORDER_EFFECT_ID",
    "SANDBOX_ORDER_FIXED_PROBE_PLAN",
    "SANDBOX_ORDER_INGRESS_FIRST",
    "SANDBOX_ORDER_ITEM_CODE",
    "SANDBOX_ORDER_QUANTITY",
    "SANDBOX_ORDER_SCENARIO",
    "SANDBOX_ORDER_TOOL_NAME",
    "SANDBOX_ORDER_TOOL_VERSION",
    "SandboxOrderInvestigationClock",
    "SandboxOrderOperationMaterial",
    "SandboxOrderProbeOrder",
    "SandboxOrderScenarioDefinition",
    "build_hosted_sandbox_order_scenario_preparation",
    "build_sandbox_order_operation_material",
    "execute_hosted_sandbox_order_fixed",
    "execute_sandbox_order_adaptive",
    "execute_sandbox_order_baseline",
    "execute_sandbox_order_conditional",
    "investigate_sandbox_order",
    "run_sandbox_order_baseline",
    "run_sandbox_order_investigation",
]
