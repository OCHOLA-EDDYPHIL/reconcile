"""Opt-in Vertex AI acceptance for one bounded adaptive Storage turn."""

from __future__ import annotations

import asyncio
import os
import subprocess
from datetime import UTC, datetime
from pathlib import Path

import pytest
from google.oauth2.credentials import Credentials

from reconcile.adapters.storage import (
    STORAGE_CAPABILITY_NAME,
    STORAGE_CAPABILITY_VERSION,
    build_storage_capability_registration,
    build_storage_rule_registration,
)
from reconcile.adaptive import (
    AdaptiveInvestigationPolicy,
    AdaptiveStopReason,
    ProposalDisposition,
    execute_adaptive_investigation,
)
from reconcile.adk_planner import (
    AdkGeminiPlanner,
    GuardedDispatchContext,
    VertexAdcPlannerConfig,
)
from reconcile.contracts import (
    SCENARIO_RUN_REQUEST_VERSION,
    AdaptivePlannerPhase,
    CapabilityRef,
    Classification,
    ScenarioFaultAction,
    ScenarioFaultInstruction,
    ScenarioFaultPoint,
    ScenarioRunRequest,
    canonical_json_bytes,
)
from reconcile.controller import CapabilityRegistry
from reconcile.evidence import TargetRuleRegistry
from reconcile.scenarios.local_storage import LocalStorageReadTarget
from reconcile.scenarios.runner import ScenarioRunner
from reconcile.scenarios.storage import STORAGE_SCENARIO, StorageScenarioDefinition
from tests._clocks import ConstantClock

pytestmark = pytest.mark.acceptance

_REAL_GEMINI_ENABLED = os.environ.get("RECONCILE_REAL_GEMINI") == "1"


def _required_environment(name: str) -> str:
    value = os.environ.get(name)
    if value is None or not value.strip():
        pytest.fail(f"{name} is required for the opt-in provider acceptance")
    return value.strip()


def _gcloud_credentials() -> Credentials:
    try:
        completed = subprocess.run(
            ("gcloud", "auth", "print-access-token", "--quiet"),
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            timeout=15,
        )
    except (OSError, subprocess.TimeoutExpired):
        pytest.fail(
            "gcloud could not mint a short-lived access token",
            pytrace=False,
        )
    if completed.returncode != 0:
        pytest.fail(
            "gcloud could not mint a short-lived access token",
            pytrace=False,
        )
    try:
        token = completed.stdout.strip().decode("ascii")
    except UnicodeDecodeError:
        pytest.fail("gcloud returned an invalid access token", pytrace=False)
    if not token or any(character.isspace() for character in token):
        pytest.fail("gcloud returned an invalid access token", pytrace=False)
    credentials = Credentials(token)
    del token, completed
    return credentials


@pytest.mark.skipif(
    not _REAL_GEMINI_ENABLED,
    reason="set RECONCILE_REAL_GEMINI=1 to run the real provider acceptance",
)
def test_one_real_gemini_turn_commits_only_through_deterministic_storage_evidence(
    tmp_path: Path,
) -> None:
    project = _required_environment("RECONCILE_VERTEX_PROJECT")
    location = _required_environment("RECONCILE_VERTEX_LOCATION")
    model = _required_environment("RECONCILE_VERTEX_MODEL")
    if location != "us":
        pytest.fail("RECONCILE_VERTEX_LOCATION must be us", pytrace=False)
    if model != "gemini-3.5-flash":
        pytest.fail(
            "RECONCILE_VERTEX_MODEL must be gemini-3.5-flash",
            pytrace=False,
        )

    invoked_at = datetime.now(UTC)
    database_path = tmp_path / "real-gemini-storage.sqlite3"
    definition = StorageScenarioDefinition(
        database_path,
        invoked_at=invoked_at,
        target_clock=ConstantClock(invoked_at),
    )
    scenario_result = ScenarioRunner().run(
        ScenarioRunRequest(
            schema_version=SCENARIO_RUN_REQUEST_VERSION,
            scenario=STORAGE_SCENARIO,
            run_id="run-real-gemini-storage",
            investigation_id="investigation-real-gemini-storage",
            operation_id="operation-real-gemini-storage",
            invocation_id="invocation-real-gemini-storage",
            function_call_id="function-call-real-gemini-storage",
            seed=39,
            fault=ScenarioFaultInstruction(
                point=ScenarioFaultPoint.POST_COMMIT,
                action=ScenarioFaultAction.INTERRUPT_PROCESS,
            ),
        ),
        definition,
    )
    envelope = scenario_result.execution_envelope
    assert envelope is not None
    budget = envelope.context.evidence_budget.model_copy(
        update={"max_elapsed_ms": 60_000}
    )
    context = envelope.context.model_copy(update={"evidence_budget": budget})
    envelope = envelope.model_copy(update={"context": context})
    sealed_envelope = canonical_json_bytes(envelope)

    read_target = LocalStorageReadTarget(database_path)
    capabilities = CapabilityRegistry()
    capabilities.register(
        build_storage_capability_registration(
            read_target=read_target,
            target=envelope.target,
            clock=lambda: datetime.now(UTC),
        )
    )
    rules = TargetRuleRegistry()
    rules.register(build_storage_rule_registration())
    policy = AdaptiveInvestigationPolicy(
        name="storage-real-gemini-acceptance",
        version="1.0.0",
        sufficient_classifications=(Classification.COMMITTED,),
        required_capabilities=(
            CapabilityRef(
                name=STORAGE_CAPABILITY_NAME,
                version=STORAGE_CAPABILITY_VERSION,
            ),
        ),
        max_turns=1,
        planner_timeout_ms=30_000,
        include_explanation=False,
    )
    credentials = _gcloud_credentials()
    config = VertexAdcPlannerConfig(
        project=project,
        location=location,
        model=model,
        timeout_seconds=25,
        max_output_tokens=4_096,
        credentials=credentials,
    )
    assert (
        config.timeout_seconds * 1_000
        < policy.planner_timeout_ms
        < envelope.context.evidence_budget.max_elapsed_ms
    )

    dispatch_count = 0

    async def dispatch(context: GuardedDispatchContext):
        nonlocal dispatch_count
        dispatch_count += 1
        await context.count_tokens()
        return await context.generate_content()

    async def investigate(planner_config: VertexAdcPlannerConfig):
        async with AdkGeminiPlanner.from_vertex_adc_guarded(planner_config) as planner:
            planner.bind_guarded_dispatch_hook(dispatch)
            try:
                result = await execute_adaptive_investigation(
                    envelope,
                    capabilities,
                    rules,
                    planner,
                    policy,
                )
            finally:
                consumed = planner.clear_guarded_dispatch_hook(dispatch)
            return result, consumed

    result, consumed = asyncio.run(investigate(config))
    del credentials, config
    fixed_report = definition.investigate(envelope)

    assert canonical_json_bytes(envelope) == sealed_envelope
    assert consumed is True
    assert dispatch_count == 1
    assert result.model_invocation_count == 1
    assert result.acquisition_turn_count == 1
    assert len(result.turns) == 1
    assert result.turns[0].phase is AdaptivePlannerPhase.ACQUIRE_EVIDENCE
    assert result.turns[0].failure is None
    assert result.explanation_valid is None
    assert result.report.advisory_explanation is None
    assert result.model_prompt_tokens is not None
    assert result.model_prompt_tokens > 0
    assert result.model_output_tokens is not None
    assert result.model_output_tokens > 0
    assert result.model_total_tokens == (
        result.model_prompt_tokens + result.model_output_tokens
    )

    selected = tuple(
        proposal
        for turn in result.turns
        for proposal in turn.proposals
        if proposal.disposition is ProposalDisposition.SELECTED
    )
    assert len(selected) == 1
    assert selected[0].capability_name == STORAGE_CAPABILITY_NAME
    assert selected[0].capability_version == STORAGE_CAPABILITY_VERSION
    assert result.unsupported_proposal_count == 0
    assert result.invalid_proposal_count == 0
    assert result.duplicate_proposal_count == 0
    assert result.attempted_probe_count == 1
    assert result.probe_count_used == 1

    assert result.stop_reason is AdaptiveStopReason.SUFFICIENT_EVIDENCE
    assert result.classification is Classification.COMMITTED
    assert result.report.action_gate == fixed_report.action_gate
