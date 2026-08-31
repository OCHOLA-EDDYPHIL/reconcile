"""Bounded recovery baselines, conditional comparison, and local smoke execution."""

from __future__ import annotations

import asyncio
import hashlib
from pathlib import Path

from reconcile.contracts import (
    RECOVERY_UTILITY_REPORT_VERSION,
    RecoveryRetryBaselineKind,
    RecoveryRetryBaselineResult,
    RecoveryRetryPrecondition,
    RecoveryUtilityConclusion,
    RecoveryUtilityEffects,
    RecoveryUtilityExecutionBasis,
    RecoveryUtilityLaneResult,
    RecoveryUtilityPolicy,
    RecoveryUtilityReport,
    RecoveryUtilitySelectionCondition,
    RecoveryUtilitySmokeResult,
    RecoveryUtilityVerificationMode,
    canonical_sha256,
)
from reconcile.contracts.base import canonical_json_value_bytes
from reconcile.contracts.recovery_qualification import (
    RECOVERY_QUALIFICATION_CONTROLLER_VERSION,
    RECOVERY_QUALIFICATION_DECISION_POLICY_VERSION,
    RECOVERY_QUALIFICATION_PERMIT_POLICY_VERSION,
    RecoveryQualificationPolicy,
)
from reconcile.hosted.cloud_run_canary import (
    CloudRunAcceptanceAmbiguity,
    CloudRunCanaryError,
    CloudRunCanaryErrorCode,
    CloudRunFaultMode,
)
from reconcile.recovery_qualification_execution import (
    _UTILITY_FIXED_SELECTION_MODE,
    _UTILITY_OBSERVATION_SELECTION_MODE,
    RecoveryQualificationProofExecution,
    build_recovery_qualification_definition,
    execute_recovery_qualification_proof_lane,
    execute_recovery_qualification_smoke,
)
from reconcile.recovery_qualification_fixtures import (
    RecoveryQualificationFixture,
    build_recovery_qualification_fixtures,
)
from reconcile.recovery_qualification_provider import (
    build_recovery_qualification_foundation,
    build_recovery_qualification_provider,
)
from reconcile.recovery_scenario import recovery_utility_comparison_policy_descriptor


def _sha256(value: object) -> str:
    return hashlib.sha256(canonical_json_value_bytes(value)).hexdigest()  # type: ignore[arg-type]


def recovery_utility_fixture() -> RecoveryQualificationFixture:
    """Select the frozen committed stage-drop case used by the short path."""

    return next(
        fixture
        for fixture in build_recovery_qualification_fixtures()
        if fixture.archetype.archetype_id == "stage-drop-committed"
    )


async def _retry_baseline(
    fixture: RecoveryQualificationFixture,
    *,
    state_directory: Path,
    baseline: RecoveryRetryBaselineKind,
    sealed_inputs_sha256: str,
    expected_initial_service_etag: str,
) -> RecoveryRetryBaselineResult:
    foundation = build_recovery_qualification_foundation(
        fixture,
        state_directory=state_directory,
    )
    provider = foundation.provider
    operation_id = provider.settings.stage_operation_id
    retry_operation_id = (
        f"{operation_id}-retry"
        if baseline is RecoveryRetryBaselineKind.NAIVE_NEW_IDENTITY
        else operation_id
    )
    initial_etag = None
    if baseline is RecoveryRetryBaselineKind.STABLE_IDENTITY_PRECONDITION:
        initial_service = await asyncio.to_thread(
            provider.cloud_reader.read_service,
            release_id=provider.settings.release_id,
            revision=provider.cloud_reader.target.baseline_revision,
        )
        initial_etag = initial_service.service_etag
        if initial_etag != expected_initial_service_etag:
            raise AssertionError("stable retry precondition drifted from sealed inputs")
    common = {
        "release_id": provider.settings.release_id,
        "image_digest": provider.settings.image_digest,
        "configuration_sha256": provider.settings.configuration_sha256,
    }
    initial_outcome = None
    try:
        await asyncio.to_thread(
            provider.cloud_fault_proxy.stage_revision,
            mode=CloudRunFaultMode.DROP_AFTER_ACCEPT,
            operation_id=operation_id,
            expected_service_etag=(
                initial_etag
                if baseline is RecoveryRetryBaselineKind.STABLE_IDENTITY_PRECONDITION
                else None
            ),
            **common,
        )
    except CloudRunAcceptanceAmbiguity:
        initial_outcome = "ACKNOWLEDGEMENT_LOST"
    else:  # pragma: no cover - guarded by the explicit provider fault
        raise AssertionError("retry baseline did not lose its first acknowledgement")
    if initial_outcome is None:  # pragma: no cover - guarded by the branch above
        raise AssertionError("retry baseline lacks an observed acknowledgement loss")

    retry_outcome = "ACCEPTED"
    try:
        await asyncio.to_thread(
            provider.cloud_fault_proxy.stage_revision,
            mode=CloudRunFaultMode.PASS_THROUGH,
            operation_id=retry_operation_id,
            expected_service_etag=(
                initial_etag
                if baseline is RecoveryRetryBaselineKind.STABLE_IDENTITY_PRECONDITION
                else None
            ),
            **common,
        )
    except CloudRunCanaryError as error:
        if (
            baseline is not RecoveryRetryBaselineKind.STABLE_IDENTITY_PRECONDITION
            or error.code is not CloudRunCanaryErrorCode.STALE_ETAG
        ):
            raise
        retry_outcome = "PRECONDITION_REJECTED"

    revisions = await asyncio.to_thread(
        provider.cloud_reader.list_release_revisions,
        release_id=provider.settings.release_id,
        image_digest=provider.settings.image_digest,
        configuration_sha256=provider.settings.configuration_sha256,
    )
    return RecoveryRetryBaselineResult(
        baseline=baseline,
        sealed_inputs_sha256=sealed_inputs_sha256,
        initial_operation_id=operation_id,
        retry_operation_id=retry_operation_id,
        retry_identity_stable=operation_id == retry_operation_id,
        provider_precondition=(
            RecoveryRetryPrecondition.CLOUD_RUN_SERVICE_ETAG
            if baseline is RecoveryRetryBaselineKind.STABLE_IDENTITY_PRECONDITION
            else RecoveryRetryPrecondition.NONE
        ),
        provider_precondition_sha256=(
            _sha256({"cloud_run_service_etag": initial_etag})
            if initial_etag is not None
            else None
        ),
        initial_outcome=initial_outcome,
        retry_outcome=retry_outcome,
        stage_attempt_count=2,
        provider_read_contact_count=provider.counters.provider_read_contact_count,
        provider_mutation_contact_count=provider.counters.stage_calls,
        accepted_stage_mutation_count=provider.counters.stage_accepts,
        distinct_revision_count=len(revisions),
        chain_completed=False,
        deterministic_authority_used=False,
    )


def _comparison_digests(
    fixture: RecoveryQualificationFixture,
) -> dict[str, str]:
    provider = build_recovery_qualification_provider(fixture)
    definition = build_recovery_qualification_definition(provider)
    initial_provider = provider.snapshot()
    case_value = {
        "archetype": fixture.archetype.model_dump(mode="json"),
        "case_id": fixture.case_id,
        "initial_provider_generation": fixture.initial_provider_generation,
        "initial_provider_state": {
            "service_etag": initial_provider.service_etag,
            "service_generation": initial_provider.service_generation,
            "staged_revision_exists": initial_provider.staged_revision_exists,
            "staged_traffic_percent": initial_provider.staged_traffic_percent,
        },
        "observations": [
            {
                "authoritative": item.authoritative,
                "evidence_id": item.evidence_id,
                "fact_key": item.fact_key,
                "fact_value": item.fact_value,
                "fresh": item.fresh,
            }
            for item in fixture.observations
        ],
        "seed": fixture.seed,
        "storage_backend": fixture.storage_backend.value,
    }
    envelope_hashes = {
        node_id: canonical_sha256(envelope)
        for node_id, envelope in definition.envelopes.items()
    }
    capability_hashes = {
        node_id: [canonical_sha256(item) for item in capabilities]
        for node_id, capabilities in definition.capabilities.items()
    }
    budgets = {
        node_id: envelope.context.evidence_budget.model_dump(mode="json")
        for node_id, envelope in definition.envelopes.items()
    }
    verifier_policy = {
        "controller": RECOVERY_QUALIFICATION_CONTROLLER_VERSION,
        "decision": RECOVERY_QUALIFICATION_DECISION_POLICY_VERSION,
        "permit": RECOVERY_QUALIFICATION_PERMIT_POLICY_VERSION,
    }
    authority_path = {
        "classifier": "deterministic-evidence-verifier",
        "permit_issuer": "deterministic-permit-authority",
        "mutation_dispatch": "permit-guarded-rollout-agent",
        "planner_role": "advisory-probe-selection-only",
    }
    comparison_policy = recovery_utility_comparison_policy_descriptor()
    return {
        "case": _sha256(case_value),
        "sealed_inputs": _sha256(
            {
                "case": case_value,
                "chain": canonical_sha256(definition.chain),
                "envelopes": envelope_hashes,
            }
        ),
        "capabilities": _sha256(capability_hashes),
        "budgets": _sha256(budgets),
        "verifier": _sha256(verifier_policy),
        "authority": _sha256(authority_path),
        "comparison_policy": _sha256(comparison_policy),
        "initial_service_etag": initial_provider.service_etag,
    }


def _lane(
    execution: RecoveryQualificationProofExecution,
    *,
    policy: RecoveryUtilityPolicy,
    digests: dict[str, str],
) -> RecoveryUtilityLaneResult:
    if execution.selection_condition is None:
        raise AssertionError("recovery utility lane did not record its selection rule")
    conditionally_skipped_capabilities = tuple(
        capability
        for capability in ("cloud-run-revision-health",)
        if capability not in execution.probe_capabilities
    )
    return RecoveryUtilityLaneResult(
        policy=policy,
        case_sha256=digests["case"],
        sealed_inputs_sha256=digests["sealed_inputs"],
        capability_catalog_sha256=digests["capabilities"],
        budget_catalog_sha256=digests["budgets"],
        verifier_policy_sha256=digests["verifier"],
        authority_path_sha256=digests["authority"],
        comparison_policy_sha256=digests["comparison_policy"],
        selection_condition=RecoveryUtilitySelectionCondition(
            execution.selection_condition
        ),
        verification_mode=(
            RecoveryUtilityVerificationMode.FIXED_BATCH_THEN_VERIFY
            if policy is RecoveryUtilityPolicy.FIXED
            else RecoveryUtilityVerificationMode.INCREMENTAL_AFTER_EACH_PROBE
        ),
        probe_capabilities=execution.probe_capabilities,
        conditionally_skipped_capabilities=conditionally_skipped_capabilities,
        probe_count=execution.probe_count,
        simulated_controller_ticks_to_sufficient_evidence=(
            execution.time_to_sufficient_evidence_ms
        ),
        provider_contacts=execution.provider_mutations,
        provider_read_contact_count=execution.provider_read_contact_count,
        provider_contact_count=execution.provider_contact_count,
        model_usage=execution.model_usage,
        initial_classification=execution.initial_classification,
        deterministic_decision=execution.deterministic_decision,
        deterministic_artifact_kind=execution.artifact_kind,
        permit_action=execution.permit_action,
        effects=RecoveryUtilityEffects(
            revisions_created=execution.stage_accepts,
            promotions_accepted=execution.promote_accepts,
            release_records_created=execution.record_commits,
        ),
        model_can_classify=False,
        model_can_issue_authority=False,
        model_can_contact_mutation_provider=False,
    )


async def execute_recovery_utility(
    *,
    state_directory: str | Path,
) -> RecoveryUtilityReport:
    """Run the bounded local comparison against isolated deterministic providers."""

    root = Path(state_directory)
    fixture = recovery_utility_fixture()
    digests = _comparison_digests(fixture)
    naive, stable = await asyncio.gather(
        _retry_baseline(
            fixture,
            state_directory=root / "baseline-naive",
            baseline=RecoveryRetryBaselineKind.NAIVE_NEW_IDENTITY,
            sealed_inputs_sha256=digests["sealed_inputs"],
            expected_initial_service_etag=digests["initial_service_etag"],
        ),
        _retry_baseline(
            fixture,
            state_directory=root / "baseline-stable",
            baseline=RecoveryRetryBaselineKind.STABLE_IDENTITY_PRECONDITION,
            sealed_inputs_sha256=digests["sealed_inputs"],
            expected_initial_service_etag=digests["initial_service_etag"],
        ),
    )
    fixed = await execute_recovery_qualification_proof_lane(
        fixture,
        policy=RecoveryQualificationPolicy.FIXED,
        state_directory=root / "fixed",
        restart=False,
        _include_safety_replays=False,
        _utility_selection_mode=_UTILITY_FIXED_SELECTION_MODE,
    )
    adaptive = await execute_recovery_qualification_proof_lane(
        fixture,
        policy=RecoveryQualificationPolicy.ADAPTIVE,
        state_directory=root / "adaptive",
        restart=False,
        _include_safety_replays=False,
        _utility_selection_mode=_UTILITY_OBSERVATION_SELECTION_MODE,
    )
    smoke = await execute_recovery_qualification_smoke(
        fixture,
        state_directory=root / "smoke",
    )
    observed_at = build_recovery_qualification_provider(fixture).observed_at
    return RecoveryUtilityReport(
        schema_version=RECOVERY_UTILITY_REPORT_VERSION,
        report_id=f"recovery-utility-{digests['case'][:24]}",
        case_id=fixture.case_id,
        baselines=(naive, stable),
        fixed=_lane(
            fixed,
            policy=RecoveryUtilityPolicy.FIXED,
            digests=digests,
        ),
        adaptive=_lane(
            adaptive,
            policy=RecoveryUtilityPolicy.ADAPTIVE,
            digests=digests,
        ),
        smoke=RecoveryUtilitySmokeResult(
            shared_recovery_core=True,
            fault=smoke.fault,
            initial_launch_permit_state=smoke.initial_launch_permit_state,
            initial_outcome=smoke.initial_outcome,
            initial_provider_contact_receipt_count=(
                smoke.initial_provider_contact_receipt_count
            ),
            initial_classification=smoke.initial_classification,
            deterministic_action=smoke.permit_action,
            terminal_chain_completed=smoke.terminal_chain_completed,
            provider_contacts=smoke.provider_mutations,
            provider_read_contact_count=smoke.provider_read_contact_count,
            provider_contact_count=smoke.provider_contact_count,
            effects=RecoveryUtilityEffects(
                revisions_created=smoke.stage_accepts,
                promotions_accepted=smoke.promote_accepts,
                release_records_created=smoke.record_commits,
            ),
            replay_denied=smoke.replay_denied,
            replay_provider_read_contact_delta=(
                smoke.replay_provider_read_contact_delta
            ),
            replay_provider_mutation_contact_delta=(
                smoke.replay_provider_mutation_contact_delta
            ),
            replay_provider_contact_delta=smoke.replay_provider_contact_delta,
            model_usage=smoke.model_usage,
        ),
        execution_basis=RecoveryUtilityExecutionBasis.DETERMINISTIC_LOCAL_SCRIPTED,
        conclusion=RecoveryUtilityConclusion.MEASUREMENTS_ONLY,
        observed_at=observed_at,
    )


__all__ = ["execute_recovery_utility", "recovery_utility_fixture"]
