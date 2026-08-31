"""Bounded recovery utility execution through the shared production core."""

from __future__ import annotations

import asyncio
import hashlib
import json

import pytest
from pydantic import ValidationError
from typer.testing import CliRunner

import reconcile.interfaces.cli as cli_module
from reconcile.cli import app
from reconcile.contracts import (
    Classification,
    PermitAction,
    RecoveryDispatchOutcome,
    RecoveryLaunchPermitState,
    RecoveryRetryBaselineKind,
    RecoveryRunFault,
    RecoveryUtilityConclusion,
    RecoveryUtilityExecutionBasis,
    RecoveryUtilityPolicy,
    RecoveryUtilityReport,
    RecoveryUtilitySelectionCondition,
    RecoveryUtilityVerificationMode,
    canonical_json_bytes,
)
from reconcile.contracts.base import canonical_json_value_bytes
from reconcile.contracts.recovery_qualification import (
    RecoveryQualificationModelUsageStatus,
)
from reconcile.hosted.cloud_run_canary import CloudRunCanaryFaultProxy
from reconcile.recovery_qualification_execution import (
    execute_recovery_qualification_smoke,
)
from reconcile.recovery_scenario import (
    RECOVERY_FIXED_STAGE_PROBE_SEQUENCE,
    recovery_utility_comparison_policy_descriptor,
)
from reconcile.recovery_utility import (
    execute_recovery_utility,
    recovery_utility_fixture,
)

pytestmark = pytest.mark.integration


@pytest.fixture(scope="module")
def utility_report(tmp_path_factory: pytest.TempPathFactory) -> RecoveryUtilityReport:
    return asyncio.run(
        execute_recovery_utility(
            state_directory=tmp_path_factory.mktemp("recovery-utility")
        )
    )


def test_recovery_utility_records_fair_baselines_and_shared_authority(
    utility_report: RecoveryUtilityReport,
) -> None:
    naive, stable = utility_report.baselines

    assert naive.baseline is RecoveryRetryBaselineKind.NAIVE_NEW_IDENTITY
    assert naive.initial_operation_id != naive.retry_operation_id
    assert naive.accepted_stage_mutation_count == 2
    assert naive.distinct_revision_count == 2
    assert naive.provider_precondition_sha256 is None
    assert stable.baseline is RecoveryRetryBaselineKind.STABLE_IDENTITY_PRECONDITION
    assert stable.initial_operation_id == stable.retry_operation_id
    assert stable.accepted_stage_mutation_count == 1
    assert stable.distinct_revision_count == 1
    assert stable.provider_precondition_sha256 is not None
    assert naive.provider_read_contact_count == 3
    assert stable.provider_read_contact_count == 4
    assert naive.sealed_inputs_sha256 == stable.sealed_inputs_sha256

    fixed = utility_report.fixed
    adaptive = utility_report.adaptive
    assert fixed.policy is RecoveryUtilityPolicy.FIXED
    assert adaptive.policy is RecoveryUtilityPolicy.ADAPTIVE
    assert fixed.sealed_inputs_sha256 == adaptive.sealed_inputs_sha256
    assert fixed.sealed_inputs_sha256 == naive.sealed_inputs_sha256
    assert fixed.capability_catalog_sha256 == adaptive.capability_catalog_sha256
    assert fixed.budget_catalog_sha256 == adaptive.budget_catalog_sha256
    assert fixed.verifier_policy_sha256 == adaptive.verifier_policy_sha256
    assert fixed.authority_path_sha256 == adaptive.authority_path_sha256
    assert fixed.comparison_policy_sha256 == adaptive.comparison_policy_sha256
    assert (
        fixed.comparison_policy_sha256
        == hashlib.sha256(
            canonical_json_value_bytes(recovery_utility_comparison_policy_descriptor())
        ).hexdigest()
    )
    assert RECOVERY_FIXED_STAGE_PROBE_SEQUENCE == (
        "cloud-run-service-get",
        "cloud-run-revision-get",
        "cloud-run-revision-health",
    )
    comparison_policy = recovery_utility_comparison_policy_descriptor()
    assert comparison_policy["fixed"]["verification_mode"] == (
        "fixed-batch-then-verify"
    )
    assert comparison_policy["fixed"]["conditional_reread"]["capability"] == (
        "cloud-run-service-get"
    )
    assert comparison_policy["adaptive"]["verification_mode"] == (
        "incremental-after-each-probe"
    )
    assert fixed.probe_capabilities == (
        "cloud-run-service-get",
        "cloud-run-revision-get",
        "cloud-run-revision-health",
    )
    assert adaptive.probe_capabilities == (
        "cloud-run-service-get",
        "cloud-run-revision-get",
    )
    assert fixed.conditionally_skipped_capabilities == ()
    assert adaptive.conditionally_skipped_capabilities == ("cloud-run-revision-health",)
    assert fixed.probe_count == 3
    assert adaptive.probe_count == 2
    assert fixed.selection_condition is RecoveryUtilitySelectionCondition.FIXED_ORDER
    assert (
        adaptive.selection_condition
        is RecoveryUtilitySelectionCondition.SERVICE_STATE_REQUIRES_REVISION
    )
    assert (
        fixed.verification_mode
        is RecoveryUtilityVerificationMode.FIXED_BATCH_THEN_VERIFY
    )
    assert (
        adaptive.verification_mode
        is RecoveryUtilityVerificationMode.INCREMENTAL_AFTER_EACH_PROBE
    )
    assert fixed.provider_contact_count >= fixed.probe_count + 3
    assert adaptive.provider_contact_count >= adaptive.probe_count + 3
    assert fixed.provider_contact_count == (
        fixed.provider_read_contact_count + fixed.provider_contacts.outbound_call_count
    )
    assert adaptive.provider_contact_count == (
        adaptive.provider_read_contact_count
        + adaptive.provider_contacts.outbound_call_count
    )
    assert fixed.initial_classification is Classification.UNKNOWN
    assert adaptive.initial_classification is Classification.UNKNOWN
    assert fixed.permit_action is adaptive.permit_action is PermitAction.CONTINUE
    assert (
        fixed.model_usage.status is RecoveryQualificationModelUsageStatus.NOT_APPLICABLE
    )
    assert fixed.model_usage.model_call_count == 0
    assert adaptive.model_usage.status is RecoveryQualificationModelUsageStatus.SCRIPTED
    assert adaptive.model_usage.model_call_count == 3
    assert not adaptive.model_can_classify
    assert not adaptive.model_can_issue_authority
    assert not adaptive.model_can_contact_mutation_provider
    assert (
        utility_report.execution_basis
        is RecoveryUtilityExecutionBasis.DETERMINISTIC_LOCAL_SCRIPTED
    )
    assert utility_report.conclusion is RecoveryUtilityConclusion.MEASUREMENTS_ONLY


def test_recovery_utility_smoke_denies_exact_replay_before_provider_contact(
    utility_report: RecoveryUtilityReport,
) -> None:
    smoke = utility_report.smoke

    assert smoke.shared_recovery_core
    assert smoke.fault is RecoveryRunFault.DROP_AFTER_ACCEPT
    assert smoke.initial_launch_permit_state is RecoveryLaunchPermitState.COMPLETED
    assert smoke.initial_outcome is RecoveryDispatchOutcome.OUTCOME_UNKNOWN
    assert smoke.initial_provider_contact_receipt_count == 1
    assert smoke.initial_classification is Classification.UNKNOWN
    assert smoke.deterministic_action is PermitAction.CONTINUE
    assert smoke.terminal_chain_completed
    assert smoke.effects.revisions_created == 1
    assert smoke.effects.promotions_accepted == 1
    assert smoke.effects.release_records_created == 1
    assert smoke.provider_read_contact_count == 7
    assert smoke.provider_contacts.outbound_call_count == 3
    assert smoke.provider_contact_count == 10
    assert smoke.replay_denied
    assert smoke.replay_provider_read_contact_delta == 0
    assert smoke.replay_provider_mutation_contact_delta == 0
    assert smoke.replay_provider_contact_delta == 0
    assert smoke.model_usage.status is RecoveryQualificationModelUsageStatus.SCRIPTED
    assert smoke.model_usage.model_call_count == 3


def test_recovery_utility_smoke_requires_the_observed_unknown_launch_outcome(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path,
) -> None:
    monkeypatch.setattr(
        CloudRunCanaryFaultProxy,
        "_after_accept",
        staticmethod(lambda receipt, _mode: receipt),
    )

    with pytest.raises(AssertionError, match="unknown launch outcome"):
        asyncio.run(
            execute_recovery_qualification_smoke(
                recovery_utility_fixture(),
                state_directory=tmp_path,
            )
        )


def test_recovery_utility_contract_rejects_comparison_and_authority_drift(
    utility_report: RecoveryUtilityReport,
) -> None:
    payload = utility_report.model_dump(mode="python")
    payload["adaptive"]["sealed_inputs_sha256"] = "0" * 64
    with pytest.raises(ValidationError, match="share sealed inputs"):
        RecoveryUtilityReport.model_validate(payload)

    payload = utility_report.model_dump(mode="python")
    payload["adaptive"]["model_can_classify"] = True
    with pytest.raises(ValidationError):
        RecoveryUtilityReport.model_validate(payload)

    payload = utility_report.model_dump(mode="python")
    payload["adaptive_superiority_claim"] = True
    with pytest.raises(ValidationError, match="Extra inputs are not permitted"):
        RecoveryUtilityReport.model_validate(payload)

    payload = utility_report.model_dump(mode="python")
    payload["execution_basis"] = "wall-clock-live-provider"
    with pytest.raises(ValidationError):
        RecoveryUtilityReport.model_validate(payload)


def test_recovery_smoke_cli_emits_the_versioned_report(
    monkeypatch: pytest.MonkeyPatch,
    utility_report: RecoveryUtilityReport,
) -> None:
    async def execute_stub(*, state_directory: str) -> RecoveryUtilityReport:
        assert state_directory
        return utility_report

    monkeypatch.setattr(cli_module, "execute_recovery_utility", execute_stub)

    result = CliRunner().invoke(app, ["recovery", "smoke", "--output", "json"])

    assert result.exit_code == 0
    assert json.loads(result.stdout_bytes) == json.loads(
        canonical_json_bytes(utility_report)
    )


def test_recovery_smoke_cli_discloses_policy_cadence_and_usage(
    monkeypatch: pytest.MonkeyPatch,
    utility_report: RecoveryUtilityReport,
) -> None:
    async def execute_stub(*, state_directory: str) -> RecoveryUtilityReport:
        assert state_directory
        return utility_report

    monkeypatch.setattr(cli_module, "execute_recovery_utility", execute_stub)

    result = CliRunner().invoke(app, ["recovery", "smoke"])

    assert result.exit_code == 0
    assert "Fixed verification: fixed-batch-then-verify" in result.stdout
    assert "Adaptive verification: incremental-after-each-probe" in result.stdout
    assert "Smoke provider contacts: 10" in result.stdout
    assert "Smoke scripted model calls: 3" in result.stdout
    assert "Smoke terminal effects: 1/1/1" in result.stdout
    assert "Conclusion: MEASUREMENTS_ONLY" in result.stdout
