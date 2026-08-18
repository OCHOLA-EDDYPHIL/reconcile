"""Isolated orchestration for the canonical local scenario suite."""

from __future__ import annotations

import asyncio
import hashlib
import inspect
import re
import tempfile
import time
import uuid
import warnings
from collections.abc import Callable
from contextlib import suppress
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path
from typing import Protocol

from reconcile.adaptive import (
    AdaptiveInvestigationResult,
    AdaptiveStopReason,
    AdvisoryPlanner,
    AdvisoryPlannerMetadata,
    ProposalDisposition,
)
from reconcile.adk_planner import AdkGeminiPlanner, VertexAdcPlannerConfig
from reconcile.baseline import FixedBaselineResult
from reconcile.contracts import (
    BOUNDED_HYBRID_ROUTE_POLICY_VERSION,
    EXECUTION_ENVELOPE_SUMMARY_VERSION,
    INVESTIGATION_COMPARISON_RECORD_VERSION,
    SCENARIO_RUN_REQUEST_VERSION,
    AdaptivePlannerPhase,
    Classification,
    ComparisonModelUsage,
    ComparisonModelUsageStatus,
    ComparisonRun,
    ComparisonStrategyKind,
    EnvelopeEffectSummary,
    ExecutionEnvelope,
    ExecutionEnvelopeSummary,
    ExplanationCompleteness,
    InvestigationComparisonRecord,
    InvestigationReport,
    PreregisteredExpectedClassification,
    ScenarioCleanupDisposition,
    ScenarioFaultAction,
    ScenarioFaultInstruction,
    ScenarioFaultPoint,
    ScenarioHybridOutcome,
    ScenarioHybridRoute,
    ScenarioRef,
    ScenarioRouteProvenance,
    ScenarioRunRequest,
    canonical_json_bytes,
    canonical_sha256,
    decode_contract,
)
from reconcile.contracts.base import canonical_json_value_bytes
from reconcile.controller import ProbeDurabilityObserver
from reconcile.progress import (
    EnvelopeProgress,
    ProgressCallback,
    ProgressDeliveryError,
    ProgressDispatcher,
    ProgressEmitter,
)
from reconcile.scenarios.firestore_business import (
    FIRESTORE_BUSINESS_SCENARIO,
    FirestoreBusinessScenarioDefinition,
    execute_firestore_business_baseline,
)
from reconcile.scenarios.local_firestore import LocalFirestoreReadTarget
from reconcile.scenarios.local_order import (
    HiddenOrderOutcome,
    LocalOrderHarness,
    LocalOrderReadTarget,
)
from reconcile.scenarios.local_storage import LocalStorageReadTarget
from reconcile.scenarios.runner import ScenarioRunner
from reconcile.scenarios.sandbox_order import (
    SANDBOX_ORDER_ITEM_CODE,
    SANDBOX_ORDER_QUANTITY,
    SANDBOX_ORDER_SCENARIO,
    SandboxOrderScenarioDefinition,
    execute_sandbox_order_baseline,
)
from reconcile.scenarios.storage import (
    STORAGE_SCENARIO,
    StorageScenarioDefinition,
    execute_storage_baseline,
)
from reconcile.security import contains_sensitive_material

_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]*$")
_MAX_RUN_ID_LENGTH = 128


def _utc_now() -> datetime:
    return datetime.now(UTC)


class ScenarioName(StrEnum):
    """Stable command names for the three canonical local scenarios."""

    STORAGE = "storage"
    FIRESTORE_BUSINESS = "firestore-business"
    SANDBOX_ORDER = "sandbox-order"


class ScenarioMode(StrEnum):
    """Supported investigation strategies for local scenario execution."""

    FIXED = "fixed"
    ADAPTIVE = "adaptive"
    COMPARE = "compare"


SCENARIO_SUITE = (
    ScenarioName.STORAGE,
    ScenarioName.FIRESTORE_BUSINESS,
    ScenarioName.SANDBOX_ORDER,
)

BOUNDED_HYBRID_FIXED_PROVENANCE = (
    f"Bounded hybrid route policy {BOUNDED_HYBRID_ROUTE_POLICY_VERSION} selected "
    "the deterministic fixed connector; no advisory planner was invoked."
)
BOUNDED_HYBRID_ADVISORY_PROVENANCE = (
    f"Bounded hybrid route policy {BOUNDED_HYBRID_ROUTE_POLICY_VERSION} selected "
    "allowlisted read-only advisory evidence planning; deterministic code retained "
    "evidence, classification, and action authority."
)
BOUNDED_HYBRID_FALLBACK_PROVENANCE = (
    f"Bounded hybrid route policy {BOUNDED_HYBRID_ROUTE_POLICY_VERSION} selected "
    "the deterministic fixed fallback because advisory planning was not safely "
    "available."
)
BOUNDED_HYBRID_PLANNER_INVOKED_PROVENANCE = (
    f"Bounded hybrid route policy {BOUNDED_HYBRID_ROUTE_POLICY_VERSION} invoked "
    "the advisory planner before reaching this deterministic outcome."
)
BOUNDED_HYBRID_EXPLICIT_UNKNOWN_PROVENANCE = (
    f"Bounded hybrid route policy {BOUNDED_HYBRID_ROUTE_POLICY_VERSION} retained "
    "explicit UNKNOWN after advisory failure because a fresh fixed plan would "
    "exceed or replay the target-read budget."
)
BOUNDED_HYBRID_PREPLANNER_UNKNOWN_PROVENANCE = (
    f"Bounded hybrid route policy {BOUNDED_HYBRID_ROUTE_POLICY_VERSION} retained "
    "explicit UNKNOWN before advisory dispatch because the deterministic bootstrap "
    "read could not safely support a planning turn; no planner or fresh fixed replay "
    "was invoked."
)
BOUNDED_HYBRID_PROVIDER_CLEANUP_PROVENANCE = (
    "Advisory provider cleanup failed after the deterministic result was "
    "established; the sanitized failure did not change classification or action "
    "authority."
)

_PROVIDER_FAILURE_STOP_REASONS = frozenset(
    {
        AdaptiveStopReason.PLANNER_UNAVAILABLE,
        AdaptiveStopReason.PLANNER_TIMEOUT,
        AdaptiveStopReason.PLANNER_SCHEMA_INVALID,
    }
)


def bounded_hybrid_route_for(scenario: ScenarioName) -> ScenarioHybridRoute:
    """Resolve the frozen bounded-hybrid route for one canonical scenario."""

    if type(scenario) is not ScenarioName:
        raise TypeError("bounded hybrid routing requires an exact scenario")
    if scenario in {ScenarioName.STORAGE, ScenarioName.FIRESTORE_BUSINESS}:
        return ScenarioHybridRoute.FIXED_AUTHORITATIVE
    return ScenarioHybridRoute.PLANNER_HETEROGENEOUS


def adaptive_result_has_provider_failure(
    result: AdaptiveInvestigationResult,
) -> bool:
    """Return whether evidence acquisition stopped on a provider failure."""

    if type(result) is not AdaptiveInvestigationResult:
        raise TypeError("hybrid fallback requires an exact adaptive result")
    return result.stop_reason in _PROVIDER_FAILURE_STOP_REASONS


def adaptive_result_requires_fixed_fallback(
    result: AdaptiveInvestigationResult,
    *,
    max_elapsed_ms: int,
) -> bool:
    """Return whether a sanitized advisory provider failure requires fallback."""

    if type(max_elapsed_ms) is not int or max_elapsed_ms < 1:
        raise ValueError("hybrid fallback elapsed budget must be positive")
    return adaptive_result_has_provider_failure(result) and (
        result.attempted_probe_count == 0
        and result.probe_count_used == 0
        and not result.report.probe_audit
        and result.total_elapsed_ms < max_elapsed_ms
    )


def adaptive_result_requires_explicit_unknown(
    result: AdaptiveInvestigationResult,
    *,
    max_elapsed_ms: int,
) -> bool:
    """Return whether provider failure must stop without a fresh fixed replay."""

    if not adaptive_result_has_provider_failure(result):
        return False
    if adaptive_result_requires_fixed_fallback(
        result,
        max_elapsed_ms=max_elapsed_ms,
    ):
        return False
    if result.report.classification is not Classification.UNKNOWN:
        raise ValueError(
            "provider failure cannot relabel an established classification"
        )
    return True


def _mark_bounded_hybrid_route(
    report: InvestigationReport,
    provenance: str,
) -> InvestigationReport:
    if type(report) is not InvestigationReport:
        raise TypeError("hybrid route provenance requires an exact report")
    sealed = decode_contract(canonical_json_bytes(report), InvestigationReport)
    if provenance in sealed.limitations:
        return sealed
    payload = sealed.model_dump(mode="python")
    payload["limitations"] = (*sealed.limitations, provenance)
    return InvestigationReport.model_validate(payload)


def mark_bounded_hybrid_deterministic_fixed(
    report: InvestigationReport,
) -> InvestigationReport:
    """Attach stable provenance to an authoritative deterministic fixed route."""

    return _mark_bounded_hybrid_route(report, BOUNDED_HYBRID_FIXED_PROVENANCE)


def mark_bounded_hybrid_advisory(
    report: InvestigationReport,
    *,
    provider_cleanup_failed: bool = False,
) -> InvestigationReport:
    """Attach stable provenance to bounded advisory evidence planning."""

    marked = _mark_bounded_hybrid_route(report, BOUNDED_HYBRID_ADVISORY_PROVENANCE)
    marked = _mark_bounded_hybrid_route(
        marked,
        BOUNDED_HYBRID_PLANNER_INVOKED_PROVENANCE,
    )
    if provider_cleanup_failed:
        marked = _mark_bounded_hybrid_route(
            marked,
            BOUNDED_HYBRID_PROVIDER_CLEANUP_PROVENANCE,
        )
    return marked


def mark_bounded_hybrid_fixed_fallback(
    report: InvestigationReport,
    *,
    planner_invoked: bool = False,
    provider_cleanup_failed: bool = False,
) -> InvestigationReport:
    """Attach stable provenance to a deterministic fixed fallback route."""

    marked = _mark_bounded_hybrid_route(report, BOUNDED_HYBRID_FALLBACK_PROVENANCE)
    if planner_invoked:
        marked = _mark_bounded_hybrid_route(
            marked,
            BOUNDED_HYBRID_PLANNER_INVOKED_PROVENANCE,
        )
    if provider_cleanup_failed:
        marked = _mark_bounded_hybrid_route(
            marked,
            BOUNDED_HYBRID_PROVIDER_CLEANUP_PROVENANCE,
        )
    return marked


def mark_bounded_hybrid_explicit_unknown(
    report: InvestigationReport,
    *,
    provider_cleanup_failed: bool = False,
) -> InvestigationReport:
    """Attach provenance to a provider failure that cannot replay fixed reads."""

    if report.classification is not Classification.UNKNOWN:
        raise ValueError("explicit hybrid fallback requires UNKNOWN classification")
    marked = _mark_bounded_hybrid_route(
        report,
        BOUNDED_HYBRID_EXPLICIT_UNKNOWN_PROVENANCE,
    )
    marked = _mark_bounded_hybrid_route(
        marked,
        BOUNDED_HYBRID_PLANNER_INVOKED_PROVENANCE,
    )
    if provider_cleanup_failed:
        marked = _mark_bounded_hybrid_route(
            marked,
            BOUNDED_HYBRID_PROVIDER_CLEANUP_PROVENANCE,
        )
    return marked


def mark_bounded_hybrid_preplanner_unknown(
    report: InvestigationReport,
) -> InvestigationReport:
    """Attach truthful provenance when the bootstrap stops before planning."""

    if report.classification is not Classification.UNKNOWN:
        raise ValueError("pre-planner hybrid stop requires UNKNOWN classification")
    return _mark_bounded_hybrid_route(
        report,
        BOUNDED_HYBRID_PREPLANNER_UNKNOWN_PROVENANCE,
    )


def mark_bounded_hybrid_provider_cleanup_failure(
    report: InvestigationReport,
) -> InvestigationReport:
    """Retain a sanitized cleanup failure without changing the established result."""

    return _mark_bounded_hybrid_route(
        report,
        BOUNDED_HYBRID_PROVIDER_CLEANUP_PROVENANCE,
    )


def is_bounded_hybrid_fixed_fallback(report: InvestigationReport) -> bool:
    """Return whether a report carries exact bounded-hybrid fallback provenance."""

    if type(report) is not InvestigationReport:
        raise TypeError("hybrid fallback inspection requires an exact report")
    return BOUNDED_HYBRID_FALLBACK_PROVENANCE in report.limitations


def is_bounded_hybrid_explicit_unknown(report: InvestigationReport) -> bool:
    """Return whether a bounded hybrid path retained UNKNOWN without replay."""

    if type(report) is not InvestigationReport:
        raise TypeError("hybrid UNKNOWN inspection requires an exact report")
    return bool(
        {
            BOUNDED_HYBRID_EXPLICIT_UNKNOWN_PROVENANCE,
            BOUNDED_HYBRID_PREPLANNER_UNKNOWN_PROVENANCE,
        }.intersection(report.limitations)
    )


def bounded_hybrid_route_provenance(
    report: InvestigationReport,
) -> ScenarioRouteProvenance | None:
    """Project static route markers into a sanitized public provenance record."""

    if type(report) is not InvestigationReport:
        raise TypeError("hybrid route projection requires an exact report")
    limitations = frozenset(report.limitations)
    primary = tuple(
        marker
        for marker in (
            BOUNDED_HYBRID_FIXED_PROVENANCE,
            BOUNDED_HYBRID_ADVISORY_PROVENANCE,
            BOUNDED_HYBRID_FALLBACK_PROVENANCE,
            BOUNDED_HYBRID_EXPLICIT_UNKNOWN_PROVENANCE,
            BOUNDED_HYBRID_PREPLANNER_UNKNOWN_PROVENANCE,
        )
        if marker in limitations
    )
    if not primary:
        return None
    if len(primary) != 1:
        raise ValueError("hybrid report contains conflicting route provenance")
    planner_invoked = BOUNDED_HYBRID_PLANNER_INVOKED_PROVENANCE in limitations
    cleanup_failed = BOUNDED_HYBRID_PROVIDER_CLEANUP_PROVENANCE in limitations
    if primary[0] == BOUNDED_HYBRID_FIXED_PROVENANCE:
        route = ScenarioHybridRoute.FIXED_AUTHORITATIVE
        outcome = ScenarioHybridOutcome.FIXED_AUTHORITATIVE
        fixed_invoked = True
        provider_failure = False
    elif primary[0] == BOUNDED_HYBRID_ADVISORY_PROVENANCE:
        route = ScenarioHybridRoute.PLANNER_HETEROGENEOUS
        outcome = ScenarioHybridOutcome.PLANNER_EVIDENCE
        fixed_invoked = False
        provider_failure = False
    elif primary[0] == BOUNDED_HYBRID_FALLBACK_PROVENANCE:
        route = ScenarioHybridRoute.PLANNER_HETEROGENEOUS
        outcome = ScenarioHybridOutcome.FIXED_FALLBACK
        fixed_invoked = True
        provider_failure = True
    elif primary[0] == BOUNDED_HYBRID_EXPLICIT_UNKNOWN_PROVENANCE:
        route = ScenarioHybridRoute.PLANNER_HETEROGENEOUS
        outcome = ScenarioHybridOutcome.EXPLICIT_UNKNOWN
        fixed_invoked = False
        provider_failure = True
    else:
        route = ScenarioHybridRoute.PLANNER_HETEROGENEOUS
        outcome = ScenarioHybridOutcome.EXPLICIT_UNKNOWN
        fixed_invoked = False
        provider_failure = False
    return ScenarioRouteProvenance(
        policy_version=BOUNDED_HYBRID_ROUTE_POLICY_VERSION,
        route=route,
        outcome=outcome,
        planner_invoked=planner_invoked,
        fixed_connector_invoked=fixed_invoked,
        provider_failure=provider_failure,
        provider_cleanup_failure=cleanup_failed,
    )


class ScenarioWorkflowErrorCategory(StrEnum):
    """Sanitized failure categories safe for an interface boundary."""

    INVALID_CONFIGURATION = "invalid_configuration"
    SCENARIO_EXECUTION_FAILED = "scenario_execution_failed"
    PROVIDER_FAILED = "provider_failed"
    CLEANUP_FAILED = "cleanup_failed"
    COMPARISON_UNREPRESENTABLE = "comparison_unrepresentable"


class ScenarioWorkflowError(RuntimeError):
    """A scenario failure without target, provider, or credential detail."""

    def __init__(
        self,
        category: ScenarioWorkflowErrorCategory,
        *,
        scenario: ScenarioName | None = None,
    ) -> None:
        if type(category) is not ScenarioWorkflowErrorCategory:
            raise TypeError("scenario workflow error category must be exact")
        if scenario is not None and type(scenario) is not ScenarioName:
            raise TypeError("scenario workflow error identity must be exact")
        self.category = category
        self.scenario = scenario
        super().__init__(category.value)


class _InvestigableScenario(Protocol):
    scenario: ScenarioRef

    async def adaptive(
        self,
        envelope: ExecutionEnvelope,
        planner: AdvisoryPlanner,
        *,
        revision: int = 1,
        cancellation_event: asyncio.Event | None = None,
        progress_emitter: ProgressEmitter | None = None,
        durability_observer: ProbeDurabilityObserver | None = None,
    ) -> AdaptiveInvestigationResult: ...


type AdvisoryPlannerFactory = Callable[[ScenarioName], AdvisoryPlanner]
type ScenarioWorkflowResult = InvestigationReport | InvestigationComparisonRecord


@dataclass(frozen=True, slots=True)
class _Recipe:
    scenario_ref: ScenarioRef
    seed: int
    expected_classification: Classification
    short_name: str


_RECIPES = {
    ScenarioName.STORAGE: _Recipe(
        scenario_ref=STORAGE_SCENARIO,
        seed=39,
        expected_classification=Classification.COMMITTED,
        short_name="storage",
    ),
    ScenarioName.FIRESTORE_BUSINESS: _Recipe(
        scenario_ref=FIRESTORE_BUSINESS_SCENARIO,
        seed=0b011,
        expected_classification=Classification.PARTIAL,
        short_name="firestore",
    ),
    ScenarioName.SANDBOX_ORDER: _Recipe(
        scenario_ref=SANDBOX_ORDER_SCENARIO,
        seed=41,
        expected_classification=Classification.UNKNOWN,
        short_name="sandbox",
    ),
}


def _workflow_error(
    category: ScenarioWorkflowErrorCategory,
    scenario: ScenarioName | None = None,
) -> ScenarioWorkflowError:
    return ScenarioWorkflowError(category, scenario=scenario)


def _validate_selection(scenario: ScenarioName, mode: ScenarioMode) -> None:
    if type(scenario) is not ScenarioName or type(mode) is not ScenarioMode:
        raise _workflow_error(ScenarioWorkflowErrorCategory.INVALID_CONFIGURATION)


def _validated_run_id(run_id: str | None) -> str:
    if run_id is None:
        return f"run-{uuid.uuid4().hex}"
    if (
        type(run_id) is not str
        or not 1 <= len(run_id) <= _MAX_RUN_ID_LENGTH
        or _IDENTIFIER.fullmatch(run_id) is None
        or contains_sensitive_material(run_id)
    ):
        raise _workflow_error(ScenarioWorkflowErrorCategory.INVALID_CONFIGURATION)
    return run_id


def _validated_workspace(workspace: str | Path | None) -> Path | None:
    if workspace is None:
        return None
    if not isinstance(workspace, (str, Path)):
        raise _workflow_error(ScenarioWorkflowErrorCategory.INVALID_CONFIGURATION)
    path = Path(workspace)
    try:
        resolved = path.resolve(strict=True)
    except OSError:
        raise _workflow_error(
            ScenarioWorkflowErrorCategory.INVALID_CONFIGURATION
        ) from None
    if not resolved.is_dir():
        raise _workflow_error(ScenarioWorkflowErrorCategory.INVALID_CONFIGURATION)
    return resolved


def _validate_provider_selection(
    mode: ScenarioMode,
    *,
    vertex_config: VertexAdcPlannerConfig | None,
    planner: AdvisoryPlanner | None,
    planner_factory: AdvisoryPlannerFactory | None,
) -> None:
    selected = sum(
        value is not None for value in (vertex_config, planner, planner_factory)
    )
    if mode is ScenarioMode.FIXED:
        if selected:
            raise _workflow_error(ScenarioWorkflowErrorCategory.INVALID_CONFIGURATION)
        return
    if selected > 1 or (mode is ScenarioMode.COMPARE and selected != 1):
        raise _workflow_error(ScenarioWorkflowErrorCategory.INVALID_CONFIGURATION)
    if vertex_config is not None:
        if type(vertex_config) is not VertexAdcPlannerConfig:
            raise _workflow_error(ScenarioWorkflowErrorCategory.INVALID_CONFIGURATION)
        if vertex_config.credentials is not None:
            raise _workflow_error(ScenarioWorkflowErrorCategory.INVALID_CONFIGURATION)
    if planner_factory is not None and not callable(planner_factory):
        raise _workflow_error(ScenarioWorkflowErrorCategory.INVALID_CONFIGURATION)


def _planner_protocol_available(planner: AdvisoryPlanner) -> bool:
    try:
        metadata = planner.metadata
        plan = planner.plan
    except Exception:
        return False
    return type(metadata) is AdvisoryPlannerMetadata and callable(plan)


def _request(scenario: ScenarioName, run_id: str) -> ScenarioRunRequest:
    recipe = _RECIPES[scenario]
    digest = hashlib.sha256(
        canonical_json_value_bytes({"run_id": run_id, "scenario": scenario.value})
    ).hexdigest()[:24]
    return ScenarioRunRequest(
        schema_version=SCENARIO_RUN_REQUEST_VERSION,
        scenario=recipe.scenario_ref,
        run_id=run_id,
        investigation_id=f"investigation-{recipe.short_name}-{digest}",
        operation_id=f"operation-{recipe.short_name}-{digest}",
        invocation_id=f"invocation-{recipe.short_name}-{digest}",
        function_call_id=f"function-call-{recipe.short_name}-{digest}",
        seed=recipe.seed,
        fault=ScenarioFaultInstruction(
            point=ScenarioFaultPoint.POST_COMMIT,
            action=ScenarioFaultAction.INTERRUPT_PROCESS,
        ),
    )


def scenario_investigation_id(scenario: ScenarioName, run_id: str) -> str:
    """Derive the canonical public identity for one validated scenario run."""

    if type(scenario) is not ScenarioName:
        raise _workflow_error(ScenarioWorkflowErrorCategory.INVALID_CONFIGURATION)
    return _request(scenario, _validated_run_id(run_id)).investigation_id


def _envelope_summary(envelope: ExecutionEnvelope) -> ExecutionEnvelopeSummary:
    return ExecutionEnvelopeSummary(
        schema_version=EXECUTION_ENVELOPE_SUMMARY_VERSION,
        investigation_id=envelope.investigation_id,
        envelope_sha256=canonical_sha256(envelope),
        target_kind=envelope.target.target_kind,
        invoked_at=envelope.invoked_at,
        ambiguity_kind=envelope.ambiguity.kind,
        ambiguity_observed_at=envelope.ambiguity.observed_at,
        expected_effects=tuple(
            EnvelopeEffectSummary(
                effect_id=effect.effect_id,
                commit_scope=effect.commit_scope,
            )
            for effect in envelope.expected_effects
        ),
        enabled_capabilities=envelope.context.enabled_capabilities,
        evidence_budget=envelope.context.evidence_budget,
    )


async def _join_owned_thread[Result](
    operation: Callable[[], Result],
) -> tuple[asyncio.Task[Result], bool]:
    task = asyncio.create_task(asyncio.to_thread(operation))
    try:
        await asyncio.shield(task)
    except asyncio.CancelledError:
        while not task.done():
            try:
                await asyncio.shield(task)
            except asyncio.CancelledError:
                continue
            except BaseException:
                break
        return task, True
    return task, False


async def _owned_thread[Result](operation: Callable[[], Result]) -> Result:
    """Join owned synchronous work before propagating task cancellation."""

    task, cancelled = await _join_owned_thread(operation)
    if cancelled:
        with suppress(asyncio.CancelledError):
            task.exception()
        raise asyncio.CancelledError
    return task.result()


def _definition(
    scenario: ScenarioName,
    workspace: Path,
    *,
    invoked_at: datetime,
    seed_sandbox: bool = True,
) -> _InvestigableScenario:
    if scenario is ScenarioName.STORAGE:
        return StorageScenarioDefinition(
            workspace / "storage.sqlite3",
            invoked_at=invoked_at,
            target_clock=_utc_now,
        )
    if scenario is ScenarioName.FIRESTORE_BUSINESS:
        return FirestoreBusinessScenarioDefinition(
            workspace / "firestore.sqlite3",
            invoked_at=invoked_at,
            target_clock=_utc_now,
        )

    private_path = workspace / "sandbox-private.sqlite3"
    observation_path = workspace / "sandbox-observations.sqlite3"
    if seed_sandbox:
        _seed_sandbox_fixture(workspace)
    return SandboxOrderScenarioDefinition(
        private_path,
        observation_path,
        hidden_outcome=HiddenOrderOutcome.COMMIT,
        invoked_at=invoked_at,
        target_clock=_utc_now,
    )


def _seed_sandbox_fixture(workspace: Path) -> None:
    LocalOrderHarness(
        workspace / "sandbox-private.sqlite3",
        workspace / "sandbox-observations.sqlite3",
        clock=_utc_now,
    ).seed_duplicate_looking_order(
        item_code=SANDBOX_ORDER_ITEM_CODE,
        quantity=SANDBOX_ORDER_QUANTITY,
    )


def _expectation(scenario: ScenarioName) -> PreregisteredExpectedClassification:
    recipe = _RECIPES[scenario]
    registration_id = f"expectation-{recipe.short_name}-post-commit-v1"
    metadata = {
        "expected_classification": recipe.expected_classification.value,
        "recipe": "post-commit-interruption-v1",
        "scenario": recipe.scenario_ref.model_dump(mode="json"),
    }
    return PreregisteredExpectedClassification(
        registration_id=registration_id,
        metadata_sha256=hashlib.sha256(
            canonical_json_value_bytes(metadata)
        ).hexdigest(),
        expected_classification=recipe.expected_classification,
    )


def _explanation_completeness(
    report: InvestigationReport,
) -> ExplanationCompleteness:
    citations = (
        ()
        if report.advisory_explanation is None
        else report.advisory_explanation.cited_evidence_ids
    )
    retained = {item.evidence_id for item in report.evidence}
    valid = sum(item in retained for item in citations)
    missing = len(citations) - valid
    return ExplanationCompleteness(
        required_evidence_citation_count=len(citations),
        valid_evidence_citation_count=valid,
        missing_evidence_citation_count=missing,
        complete=missing == 0,
    )


def _fixed_comparison_run(
    scenario: ScenarioName,
    envelope_sha256: str,
    expectation: PreregisteredExpectedClassification,
    result: FixedBaselineResult,
) -> ComparisonRun:
    return ComparisonRun(
        scenario=_RECIPES[scenario].scenario_ref,
        envelope_sha256=envelope_sha256,
        strategy_kind=ComparisonStrategyKind.FIXED,
        strategy_version=f"{result.plan_name}:{result.plan_version}",
        plan_sha256=result.plan_sha256,
        report_sha256=canonical_sha256(result.report),
        classification=result.classification,
        matches_preregistered_expectation=(
            result.classification is expectation.expected_classification
        ),
        planned_probe_count=result.planned_probe_count,
        executed_probe_count=result.attempted_probe_count,
        controller_cost_units_used=result.cost_units_used,
        controller_result_bytes_acquired=result.result_bytes_acquired,
        total_elapsed_ms=result.total_elapsed_ms,
        time_to_sufficient_evidence_ms=result.time_to_sufficient_evidence_ms,
        stop_reason=result.stop_reason.value,
        unsupported_probe_count=result.unsupported_probe_count,
        unnecessary_probe_count=result.redundant_probe_count,
        duplicate_probe_count=result.duplicate_probe_count,
        explanation_completeness=_explanation_completeness(result.report),
        model_usage=ComparisonModelUsage(
            status=ComparisonModelUsageStatus.NOT_APPLICABLE,
            model_call_count=0,
            input_token_count=0,
            output_token_count=0,
            total_token_count=0,
        ),
    )


def _adaptive_model_usage(
    scenario: ScenarioName,
    result: AdaptiveInvestigationResult,
) -> ComparisonModelUsage:
    if result.model_invocation_count == 0:
        raise _workflow_error(
            ScenarioWorkflowErrorCategory.COMPARISON_UNREPRESENTABLE,
            scenario,
        )
    counts = (
        result.model_prompt_tokens,
        result.model_output_tokens,
        result.model_total_tokens,
    )
    status = (
        ComparisonModelUsageStatus.MEASURED
        if all(value is not None for value in counts)
        else ComparisonModelUsageStatus.UNAVAILABLE
    )
    return ComparisonModelUsage(
        status=status,
        provider_name=result.provider_name,
        model_name=result.configured_model,
        model_call_count=result.model_invocation_count,
        input_token_count=result.model_prompt_tokens,
        output_token_count=result.model_output_tokens,
        total_token_count=result.model_total_tokens,
    )


def _adaptive_comparison_run(
    scenario: ScenarioName,
    envelope_sha256: str,
    expectation: PreregisteredExpectedClassification,
    result: AdaptiveInvestigationResult,
) -> ComparisonRun:
    selected_probes = sum(
        proposal.disposition is ProposalDisposition.SELECTED
        for turn in result.turns
        if turn.phase is AdaptivePlannerPhase.ACQUIRE_EVIDENCE
        for proposal in turn.proposals
    )
    if (
        result.attempted_probe_count > selected_probes
        or result.explanation_valid is not True
    ):
        raise _workflow_error(
            ScenarioWorkflowErrorCategory.COMPARISON_UNREPRESENTABLE,
            scenario,
        )
    try:
        return ComparisonRun(
            scenario=_RECIPES[scenario].scenario_ref,
            envelope_sha256=envelope_sha256,
            strategy_kind=ComparisonStrategyKind.ADAPTIVE,
            strategy_version=f"{result.policy_name}:{result.policy_version}",
            plan_sha256=result.policy_sha256,
            report_sha256=canonical_sha256(result.report),
            classification=result.classification,
            matches_preregistered_expectation=(
                result.classification is expectation.expected_classification
            ),
            planned_probe_count=selected_probes,
            executed_probe_count=result.attempted_probe_count,
            controller_cost_units_used=result.cost_units_used,
            controller_result_bytes_acquired=result.result_bytes_acquired,
            total_elapsed_ms=result.total_elapsed_ms,
            time_to_sufficient_evidence_ms=(result.time_to_sufficient_evidence_ms),
            stop_reason=result.stop_reason.value,
            unsupported_probe_count=0,
            unnecessary_probe_count=result.redundant_probe_count,
            duplicate_probe_count=0,
            explanation_completeness=_explanation_completeness(result.report),
            model_usage=_adaptive_model_usage(scenario, result),
        )
    except ScenarioWorkflowError:
        raise
    except (TypeError, ValueError):
        raise _workflow_error(
            ScenarioWorkflowErrorCategory.COMPARISON_UNREPRESENTABLE,
            scenario,
        ) from None


async def _fixed_investigation(
    scenario: ScenarioName,
    workspace: Path,
    envelope: ExecutionEnvelope,
    *,
    cancellation_event: asyncio.Event | None,
    progress_emitter: ProgressEmitter | None,
    revision: int = 1,
    durability_observer: ProbeDurabilityObserver | None = None,
    elapsed_offset_ms: int = 0,
) -> FixedBaselineResult:
    if scenario is ScenarioName.STORAGE:
        return await execute_storage_baseline(
            envelope,
            LocalStorageReadTarget(workspace / "storage.sqlite3"),
            cancellation_event=cancellation_event,
            progress_emitter=progress_emitter,
            revision=revision,
            durability_observer=durability_observer,
        )
    if scenario is ScenarioName.FIRESTORE_BUSINESS:
        return await execute_firestore_business_baseline(
            envelope,
            LocalFirestoreReadTarget(workspace / "firestore.sqlite3"),
            cancellation_event=cancellation_event,
            progress_emitter=progress_emitter,
            revision=revision,
            durability_observer=durability_observer,
        )
    return await execute_sandbox_order_baseline(
        envelope,
        LocalOrderReadTarget(workspace / "sandbox-observations.sqlite3"),
        cancellation_event=cancellation_event,
        progress_emitter=progress_emitter,
        revision=revision,
        durability_observer=durability_observer,
        elapsed_offset_ms=elapsed_offset_ms,
    )


async def _investigate(
    scenario: ScenarioName,
    mode: ScenarioMode,
    definition: _InvestigableScenario,
    envelope: ExecutionEnvelope,
    planner: AdvisoryPlanner | None,
    expectation: PreregisteredExpectedClassification,
    *,
    workspace: Path,
    run_digest: str,
    cancellation_event: asyncio.Event | None,
    progress_emitter: ProgressEmitter | None,
    revision: int = 1,
    durability_observer: ProbeDurabilityObserver | None = None,
) -> ScenarioWorkflowResult:
    sealed_envelope = canonical_json_bytes(envelope)

    async def fixed_report(
        *,
        hybrid_route: ScenarioHybridRoute | None = None,
        planner_invoked: bool = False,
        elapsed_offset_ms: int = 0,
    ) -> InvestigationReport:
        fixed_envelope = decode_contract(sealed_envelope, ExecutionEnvelope)
        report = (
            await _fixed_investigation(
                scenario,
                workspace,
                fixed_envelope,
                cancellation_event=cancellation_event,
                progress_emitter=progress_emitter,
                revision=revision,
                durability_observer=durability_observer,
                elapsed_offset_ms=elapsed_offset_ms,
            )
        ).report
        if hybrid_route is ScenarioHybridRoute.FIXED_AUTHORITATIVE:
            return mark_bounded_hybrid_deterministic_fixed(report)
        if hybrid_route is ScenarioHybridRoute.PLANNER_HETEROGENEOUS:
            return mark_bounded_hybrid_fixed_fallback(
                report,
                planner_invoked=planner_invoked,
            )
        return report

    if mode is ScenarioMode.FIXED:
        return await fixed_report()
    if mode is ScenarioMode.ADAPTIVE:
        route = bounded_hybrid_route_for(scenario)
        if route is ScenarioHybridRoute.FIXED_AUTHORITATIVE:
            return await fixed_report(hybrid_route=route)
        if planner is None or not _planner_protocol_available(planner):
            return await fixed_report(hybrid_route=route)
        adaptive_envelope = decode_contract(sealed_envelope, ExecutionEnvelope)
        adaptive_started_monotonic = time.monotonic()
        adaptive = await definition.adaptive(
            adaptive_envelope,
            planner,
            cancellation_event=cancellation_event,
            progress_emitter=progress_emitter,
            revision=revision,
            durability_observer=durability_observer,
        )
        max_elapsed_ms = adaptive_envelope.context.evidence_budget.max_elapsed_ms
        aggregate_elapsed_ms = max(
            adaptive.total_elapsed_ms,
            int((time.monotonic() - adaptive_started_monotonic) * 1_000),
        )
        if (
            adaptive_result_requires_fixed_fallback(
                adaptive,
                max_elapsed_ms=max_elapsed_ms,
            )
            and aggregate_elapsed_ms < max_elapsed_ms
        ):
            return await fixed_report(
                hybrid_route=route,
                planner_invoked=bool(adaptive.turns),
                elapsed_offset_ms=aggregate_elapsed_ms,
            )
        if adaptive_result_has_provider_failure(adaptive):
            return mark_bounded_hybrid_explicit_unknown(adaptive.report)
        return mark_bounded_hybrid_advisory(adaptive.report)

    if planner is None:
        raise _workflow_error(
            ScenarioWorkflowErrorCategory.INVALID_CONFIGURATION,
            scenario,
        )

    fixed_envelope = decode_contract(sealed_envelope, ExecutionEnvelope)
    fixed = await _fixed_investigation(
        scenario,
        workspace,
        fixed_envelope,
        cancellation_event=cancellation_event,
        progress_emitter=progress_emitter,
        revision=revision,
        durability_observer=durability_observer,
    )
    adaptive_envelope = decode_contract(sealed_envelope, ExecutionEnvelope)
    adaptive = await definition.adaptive(
        adaptive_envelope,
        planner,
        cancellation_event=cancellation_event,
        progress_emitter=progress_emitter,
        revision=revision,
        durability_observer=durability_observer,
    )
    envelope_sha256 = canonical_sha256(fixed_envelope)
    try:
        return InvestigationComparisonRecord(
            schema_version=INVESTIGATION_COMPARISON_RECORD_VERSION,
            comparison_id=f"comparison-{_RECIPES[scenario].short_name}-{run_digest}",
            case_id=f"case-{_RECIPES[scenario].short_name}-{run_digest}",
            scenario=_RECIPES[scenario].scenario_ref,
            envelope_sha256=envelope_sha256,
            preregistered_expectation=expectation,
            baseline=_fixed_comparison_run(
                scenario,
                envelope_sha256,
                expectation,
                fixed,
            ),
            adaptive=_adaptive_comparison_run(
                scenario,
                envelope_sha256,
                expectation,
                adaptive,
            ),
        )
    except ScenarioWorkflowError:
        raise
    except (TypeError, ValueError):
        raise _workflow_error(
            ScenarioWorkflowErrorCategory.COMPARISON_UNREPRESENTABLE,
            scenario,
        ) from None


async def _run_in_workspace(
    scenario: ScenarioName,
    mode: ScenarioMode,
    planner: AdvisoryPlanner | None,
    workspace: Path,
    run_id: str,
    *,
    cancellation_event: asyncio.Event | None,
    progress_callback: ProgressCallback | None,
) -> ScenarioWorkflowResult:
    request = _request(scenario, run_id)
    expectation = _expectation(scenario)
    definition = _definition(
        scenario,
        workspace,
        invoked_at=datetime.now(UTC),
    )
    runner = ScenarioRunner()
    scenario_result = None
    dispatcher = (
        None if progress_callback is None else ProgressDispatcher(progress_callback)
    )
    progress_emitter = None if dispatcher is None else dispatcher.emit

    def execute_scenario():
        with warnings.catch_warnings():
            warnings.filterwarnings(
                "ignore",
                message=(
                    r"\[EXPERIMENTAL\] feature "
                    r"FeatureName\.JSON_SCHEMA_FOR_FUNC_DECL is enabled\."
                ),
                category=UserWarning,
                module=r"google\.adk\.models\.llm_request",
            )
            return runner.run(request, definition)

    try:
        scenario_result = await _owned_thread(execute_scenario)
        envelope = scenario_result.execution_envelope
        if envelope is None:
            raise _workflow_error(
                ScenarioWorkflowErrorCategory.SCENARIO_EXECUTION_FAILED,
                scenario,
            )
        sealed_envelope = canonical_json_bytes(envelope)
        if progress_emitter is not None:
            progress_emitter(
                EnvelopeProgress(
                    occurred_at=datetime.now(UTC),
                    investigation_id=envelope.investigation_id,
                    summary=_envelope_summary(envelope),
                )
            )
        run_digest = hashlib.sha256(
            canonical_json_value_bytes({"run_id": run_id, "scenario": scenario.value})
        ).hexdigest()[:20]
        result = await _investigate(
            scenario,
            mode,
            definition,
            envelope,
            planner,
            expectation,
            workspace=workspace,
            run_digest=run_digest,
            cancellation_event=cancellation_event,
            progress_emitter=progress_emitter,
        )
        if canonical_json_bytes(envelope) != sealed_envelope:
            raise _workflow_error(
                ScenarioWorkflowErrorCategory.SCENARIO_EXECUTION_FAILED,
                scenario,
            )
        if dispatcher is not None:
            await dispatcher.finish()
        return result
    except asyncio.CancelledError:
        if dispatcher is not None:
            await dispatcher.abort()
        raise
    except Exception:
        if dispatcher is not None:
            try:
                await dispatcher.finish()
            except (ProgressDeliveryError, asyncio.CancelledError):
                pass
        raise
    finally:

        def cleanup_scenario():
            if scenario_result is None:
                cleanup_request = runner.build_cleanup_request_for_attempt(
                    request,
                    definition,
                )
            else:
                cleanup_request = runner.build_cleanup_request(
                    request,
                    scenario_result,
                )
            return runner.cleanup(cleanup_request, definition)

        try:
            cleanup_task, cleanup_cancelled = await _join_owned_thread(cleanup_scenario)
            cleanup = cleanup_task.result()
        except Exception:
            raise _workflow_error(
                ScenarioWorkflowErrorCategory.CLEANUP_FAILED,
                scenario,
            ) from None
        if (
            cleanup.disposition
            not in {
                ScenarioCleanupDisposition.CLEANED,
                ScenarioCleanupDisposition.ALREADY_CLEAN,
            }
            or cleanup.remaining_count != 0
        ):
            raise _workflow_error(
                ScenarioWorkflowErrorCategory.CLEANUP_FAILED,
                scenario,
            )
        if cleanup_cancelled:
            raise asyncio.CancelledError


async def _run_isolated(
    scenario: ScenarioName,
    mode: ScenarioMode,
    planner: AdvisoryPlanner | None,
    *,
    workspace_parent: Path | None,
    run_id: str,
    cancellation_event: asyncio.Event | None = None,
    progress_callback: ProgressCallback | None = None,
) -> ScenarioWorkflowResult:
    try:
        temporary = tempfile.TemporaryDirectory(
            prefix=f"reconcile-{scenario.value}-",
            dir=workspace_parent,
        )
    except OSError:
        raise _workflow_error(
            ScenarioWorkflowErrorCategory.SCENARIO_EXECUTION_FAILED,
            scenario,
        ) from None
    try:
        try:
            return await _run_in_workspace(
                scenario,
                mode,
                planner,
                Path(temporary.name),
                run_id,
                cancellation_event=cancellation_event,
                progress_callback=progress_callback,
            )
        except (
            ProgressDeliveryError,
            ScenarioWorkflowError,
            asyncio.CancelledError,
        ):
            raise
        except Exception:
            raise _workflow_error(
                ScenarioWorkflowErrorCategory.SCENARIO_EXECUTION_FAILED,
                scenario,
            ) from None
    finally:
        try:
            temporary.cleanup()
        except OSError:
            raise _workflow_error(
                ScenarioWorkflowErrorCategory.CLEANUP_FAILED,
                scenario,
            ) from None


async def _close_factory_planner(
    planner: AdvisoryPlanner,
    scenario: ScenarioName,
) -> None:
    try:
        closer = getattr(planner, "aclose", None)
        if not callable(closer):
            return
        result = closer()
        if inspect.isawaitable(result):
            await result
    except Exception:
        raise _workflow_error(
            ScenarioWorkflowErrorCategory.PROVIDER_FAILED,
            scenario,
        ) from None


async def _run_with_factory(
    scenario: ScenarioName,
    mode: ScenarioMode,
    planner_factory: AdvisoryPlannerFactory,
    *,
    workspace_parent: Path | None,
    run_id: str,
    cancellation_event: asyncio.Event | None = None,
    progress_callback: ProgressCallback | None = None,
) -> ScenarioWorkflowResult:
    if (
        mode is ScenarioMode.ADAPTIVE
        and bounded_hybrid_route_for(scenario)
        is ScenarioHybridRoute.FIXED_AUTHORITATIVE
    ):
        return await _run_isolated(
            scenario,
            mode,
            None,
            workspace_parent=workspace_parent,
            run_id=run_id,
            cancellation_event=cancellation_event,
            progress_callback=progress_callback,
        )
    try:
        planner = planner_factory(scenario)
    except Exception:
        if mode is ScenarioMode.ADAPTIVE:
            return await _run_isolated(
                scenario,
                mode,
                None,
                workspace_parent=workspace_parent,
                run_id=run_id,
                cancellation_event=cancellation_event,
                progress_callback=progress_callback,
            )
        raise _workflow_error(
            ScenarioWorkflowErrorCategory.PROVIDER_FAILED,
            scenario,
        ) from None
    try:
        result = await _run_isolated(
            scenario,
            mode,
            planner,
            workspace_parent=workspace_parent,
            run_id=run_id,
            cancellation_event=cancellation_event,
            progress_callback=progress_callback,
        )
    except BaseException:
        with suppress(ScenarioWorkflowError):
            await _close_factory_planner(planner, scenario)
        raise
    try:
        await _close_factory_planner(planner, scenario)
    except ScenarioWorkflowError:
        if mode is ScenarioMode.ADAPTIVE:
            return mark_bounded_hybrid_provider_cleanup_failure(result)
        raise
    return result


async def run_one(
    scenario: ScenarioName,
    mode: ScenarioMode = ScenarioMode.FIXED,
    *,
    vertex_config: VertexAdcPlannerConfig | None = None,
    planner: AdvisoryPlanner | None = None,
    planner_factory: AdvisoryPlannerFactory | None = None,
    workspace: str | Path | None = None,
    run_id: str | None = None,
    cancellation_event: asyncio.Event | None = None,
    progress_callback: ProgressCallback | None = None,
) -> ScenarioWorkflowResult:
    """Run one isolated canonical scenario and return only its public result."""

    _validate_selection(scenario, mode)
    _validate_provider_selection(
        mode,
        vertex_config=vertex_config,
        planner=planner,
        planner_factory=planner_factory,
    )
    if cancellation_event is not None and type(cancellation_event) is not asyncio.Event:
        raise _workflow_error(ScenarioWorkflowErrorCategory.INVALID_CONFIGURATION)
    if progress_callback is not None and not callable(progress_callback):
        raise _workflow_error(ScenarioWorkflowErrorCategory.INVALID_CONFIGURATION)
    selected_run_id = _validated_run_id(run_id)
    workspace_parent = _validated_workspace(workspace)
    if mode is ScenarioMode.FIXED:
        return await _run_isolated(
            scenario,
            mode,
            None,
            workspace_parent=workspace_parent,
            run_id=selected_run_id,
            cancellation_event=cancellation_event,
            progress_callback=progress_callback,
        )
    if (
        mode is ScenarioMode.ADAPTIVE
        and bounded_hybrid_route_for(scenario)
        is ScenarioHybridRoute.FIXED_AUTHORITATIVE
    ):
        return await _run_isolated(
            scenario,
            mode,
            None,
            workspace_parent=workspace_parent,
            run_id=selected_run_id,
            cancellation_event=cancellation_event,
            progress_callback=progress_callback,
        )
    if planner is not None:
        return await _run_isolated(
            scenario,
            mode,
            planner,
            workspace_parent=workspace_parent,
            run_id=selected_run_id,
            cancellation_event=cancellation_event,
            progress_callback=progress_callback,
        )
    if planner_factory is not None:
        return await _run_with_factory(
            scenario,
            mode,
            planner_factory,
            workspace_parent=workspace_parent,
            run_id=selected_run_id,
            cancellation_event=cancellation_event,
            progress_callback=progress_callback,
        )
    if vertex_config is None:
        if mode is ScenarioMode.ADAPTIVE:
            return await _run_isolated(
                scenario,
                mode,
                None,
                workspace_parent=workspace_parent,
                run_id=selected_run_id,
                cancellation_event=cancellation_event,
                progress_callback=progress_callback,
            )
        raise _workflow_error(
            ScenarioWorkflowErrorCategory.INVALID_CONFIGURATION, scenario
        )
    try:
        provider = AdkGeminiPlanner.from_vertex_adc(vertex_config)
    except Exception:
        if mode is ScenarioMode.ADAPTIVE:
            return await _run_isolated(
                scenario,
                mode,
                None,
                workspace_parent=workspace_parent,
                run_id=selected_run_id,
                cancellation_event=cancellation_event,
                progress_callback=progress_callback,
            )
        raise _workflow_error(
            ScenarioWorkflowErrorCategory.PROVIDER_FAILED,
            scenario,
        ) from None
    try:
        result = await _run_isolated(
            scenario,
            mode,
            provider,
            workspace_parent=workspace_parent,
            run_id=selected_run_id,
            cancellation_event=cancellation_event,
            progress_callback=progress_callback,
        )
    except (
        ProgressDeliveryError,
        ScenarioWorkflowError,
        asyncio.CancelledError,
    ):
        with suppress(ScenarioWorkflowError):
            await _close_factory_planner(provider, scenario)
        raise
    except Exception:
        with suppress(ScenarioWorkflowError):
            await _close_factory_planner(provider, scenario)
        raise _workflow_error(
            ScenarioWorkflowErrorCategory.PROVIDER_FAILED,
            scenario,
        ) from None
    try:
        await _close_factory_planner(provider, scenario)
    except ScenarioWorkflowError:
        if mode is ScenarioMode.ADAPTIVE:
            return mark_bounded_hybrid_provider_cleanup_failure(result)
        raise
    return result


async def run_suite(
    mode: ScenarioMode = ScenarioMode.FIXED,
    *,
    vertex_config: VertexAdcPlannerConfig | None = None,
    planner: AdvisoryPlanner | None = None,
    planner_factory: AdvisoryPlannerFactory | None = None,
    workspace: str | Path | None = None,
    run_id: str | None = None,
) -> tuple[ScenarioWorkflowResult, ...]:
    """Run the complete suite in its frozen storage, business, sandbox order."""

    if type(mode) is not ScenarioMode:
        raise _workflow_error(ScenarioWorkflowErrorCategory.INVALID_CONFIGURATION)
    _validate_provider_selection(
        mode,
        vertex_config=vertex_config,
        planner=planner,
        planner_factory=planner_factory,
    )
    selected_run_id = _validated_run_id(run_id)
    workspace_parent = _validated_workspace(workspace)

    if (
        mode is ScenarioMode.FIXED
        or planner is not None
        or (
            mode is ScenarioMode.ADAPTIVE
            and planner_factory is None
            and vertex_config is None
        )
    ):
        active_planner = planner
        return tuple(
            [
                await _run_isolated(
                    scenario,
                    mode,
                    active_planner,
                    workspace_parent=workspace_parent,
                    run_id=selected_run_id,
                )
                for scenario in SCENARIO_SUITE
            ]
        )
    if planner_factory is not None:
        return tuple(
            [
                await _run_with_factory(
                    scenario,
                    mode,
                    planner_factory,
                    workspace_parent=workspace_parent,
                    run_id=selected_run_id,
                )
                for scenario in SCENARIO_SUITE
            ]
        )
    if vertex_config is None:
        raise _workflow_error(ScenarioWorkflowErrorCategory.INVALID_CONFIGURATION)
    try:
        provider = AdkGeminiPlanner.from_vertex_adc(vertex_config)
    except Exception:
        if mode is ScenarioMode.ADAPTIVE:
            return tuple(
                [
                    await _run_isolated(
                        scenario,
                        mode,
                        None,
                        workspace_parent=workspace_parent,
                        run_id=selected_run_id,
                    )
                    for scenario in SCENARIO_SUITE
                ]
            )
        raise _workflow_error(ScenarioWorkflowErrorCategory.PROVIDER_FAILED) from None
    try:
        results = tuple(
            [
                await _run_isolated(
                    scenario,
                    mode,
                    provider,
                    workspace_parent=workspace_parent,
                    run_id=selected_run_id,
                )
                for scenario in SCENARIO_SUITE
            ]
        )
    except (ScenarioWorkflowError, asyncio.CancelledError):
        with suppress(ScenarioWorkflowError):
            await _close_factory_planner(provider, ScenarioName.SANDBOX_ORDER)
        raise
    except Exception:
        with suppress(ScenarioWorkflowError):
            await _close_factory_planner(provider, ScenarioName.SANDBOX_ORDER)
        raise _workflow_error(ScenarioWorkflowErrorCategory.PROVIDER_FAILED) from None
    try:
        await _close_factory_planner(provider, ScenarioName.SANDBOX_ORDER)
    except ScenarioWorkflowError:
        if mode is not ScenarioMode.ADAPTIVE:
            raise
        return tuple(
            mark_bounded_hybrid_provider_cleanup_failure(result)
            if scenario is ScenarioName.SANDBOX_ORDER
            else result
            for scenario, result in zip(SCENARIO_SUITE, results, strict=True)
        )
    return results


__all__ = [
    "BOUNDED_HYBRID_ADVISORY_PROVENANCE",
    "BOUNDED_HYBRID_EXPLICIT_UNKNOWN_PROVENANCE",
    "BOUNDED_HYBRID_FALLBACK_PROVENANCE",
    "BOUNDED_HYBRID_FIXED_PROVENANCE",
    "BOUNDED_HYBRID_PLANNER_INVOKED_PROVENANCE",
    "BOUNDED_HYBRID_PREPLANNER_UNKNOWN_PROVENANCE",
    "BOUNDED_HYBRID_PROVIDER_CLEANUP_PROVENANCE",
    "BOUNDED_HYBRID_ROUTE_POLICY_VERSION",
    "SCENARIO_SUITE",
    "AdvisoryPlannerFactory",
    "ScenarioMode",
    "ScenarioName",
    "ScenarioWorkflowError",
    "ScenarioWorkflowErrorCategory",
    "ScenarioWorkflowResult",
    "adaptive_result_has_provider_failure",
    "adaptive_result_requires_explicit_unknown",
    "adaptive_result_requires_fixed_fallback",
    "bounded_hybrid_route_for",
    "bounded_hybrid_route_provenance",
    "is_bounded_hybrid_explicit_unknown",
    "is_bounded_hybrid_fixed_fallback",
    "mark_bounded_hybrid_advisory",
    "mark_bounded_hybrid_deterministic_fixed",
    "mark_bounded_hybrid_explicit_unknown",
    "mark_bounded_hybrid_fixed_fallback",
    "mark_bounded_hybrid_preplanner_unknown",
    "mark_bounded_hybrid_provider_cleanup_failure",
    "run_one",
    "run_suite",
    "scenario_investigation_id",
]
