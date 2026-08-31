"""Additive contracts for bounded recovery utility demonstrations."""

from __future__ import annotations

from enum import StrEnum
from typing import Literal

from pydantic import Field, model_validator

from reconcile.contracts.base import (
    AwareDatetime,
    Identifier,
    Sha256Digest,
    StrictModel,
)
from reconcile.contracts.common import Classification
from reconcile.contracts.recovery import PermitAction
from reconcile.contracts.recovery_qualification import (
    RecoveryQualificationArtifactKind,
    RecoveryQualificationModelUsage,
    RecoveryQualificationModelUsageStatus,
    RecoveryQualificationProviderMutations,
)
from reconcile.contracts.recovery_run import (
    RecoveryDecision,
    RecoveryDispatchOutcome,
    RecoveryLaunchPermitState,
    RecoveryRunFault,
)

RECOVERY_UTILITY_REPORT_VERSION = "reconcile/recovery-utility-report/v2"


class RecoveryRetryBaselineKind(StrEnum):
    NAIVE_NEW_IDENTITY = "naive-new-identity"
    STABLE_IDENTITY_PRECONDITION = "stable-identity-precondition"


class RecoveryRetryPrecondition(StrEnum):
    NONE = "none"
    CLOUD_RUN_SERVICE_ETAG = "cloud-run-service-etag"


class RecoveryUtilityPolicy(StrEnum):
    FIXED = "fixed"
    ADAPTIVE = "adaptive"


class RecoveryUtilityConclusion(StrEnum):
    MEASUREMENTS_ONLY = "MEASUREMENTS_ONLY"


class RecoveryUtilityExecutionBasis(StrEnum):
    DETERMINISTIC_LOCAL_SCRIPTED = "deterministic-local-scripted"


class RecoveryUtilitySelectionCondition(StrEnum):
    FIXED_ORDER = "fixed-order"
    SERVICE_STATE_REQUIRES_REVISION = (
        "service-traffic-established-revision-readiness-unverified"
    )


class RecoveryUtilityVerificationMode(StrEnum):
    FIXED_BATCH_THEN_VERIFY = "fixed-batch-then-verify"
    INCREMENTAL_AFTER_EACH_PROBE = "incremental-after-each-probe"


class RecoveryUtilityEffects(StrictModel):
    revisions_created: int = Field(ge=0, le=16)
    promotions_accepted: int = Field(ge=0, le=16)
    release_records_created: int = Field(ge=0, le=16)


class RecoveryRetryBaselineResult(StrictModel):
    baseline: RecoveryRetryBaselineKind
    sealed_inputs_sha256: Sha256Digest
    initial_operation_id: Identifier
    retry_operation_id: Identifier
    retry_identity_stable: bool
    provider_precondition: RecoveryRetryPrecondition
    provider_precondition_sha256: Sha256Digest | None
    initial_outcome: Literal["ACKNOWLEDGEMENT_LOST"]
    retry_outcome: Literal["ACCEPTED", "PRECONDITION_REJECTED"]
    stage_attempt_count: Literal[2]
    provider_read_contact_count: int = Field(ge=0, le=16)
    provider_mutation_contact_count: int = Field(ge=0, le=16)
    accepted_stage_mutation_count: int = Field(ge=0, le=16)
    distinct_revision_count: int = Field(ge=0, le=16)
    chain_completed: bool
    deterministic_authority_used: Literal[False]

    @model_validator(mode="after")
    def validate_baseline(self) -> RecoveryRetryBaselineResult:
        if self.baseline is RecoveryRetryBaselineKind.NAIVE_NEW_IDENTITY:
            valid = (
                self.initial_operation_id != self.retry_operation_id
                and not self.retry_identity_stable
                and self.provider_precondition is RecoveryRetryPrecondition.NONE
                and self.provider_precondition_sha256 is None
                and self.retry_outcome == "ACCEPTED"
                and self.provider_read_contact_count == 3
                and self.provider_mutation_contact_count == 2
                and self.accepted_stage_mutation_count == 2
                and self.distinct_revision_count == 2
                and not self.chain_completed
            )
        else:
            valid = (
                self.initial_operation_id == self.retry_operation_id
                and self.retry_identity_stable
                and self.provider_precondition
                is RecoveryRetryPrecondition.CLOUD_RUN_SERVICE_ETAG
                and self.provider_precondition_sha256 is not None
                and self.retry_outcome == "PRECONDITION_REJECTED"
                and self.provider_read_contact_count == 4
                and self.provider_mutation_contact_count == 1
                and self.accepted_stage_mutation_count == 1
                and self.distinct_revision_count == 1
                and not self.chain_completed
            )
        if not valid:
            raise ValueError("retry baseline fields do not match the declared contract")
        return self


class RecoveryUtilityLaneResult(StrictModel):
    policy: RecoveryUtilityPolicy
    case_sha256: Sha256Digest
    sealed_inputs_sha256: Sha256Digest
    capability_catalog_sha256: Sha256Digest
    budget_catalog_sha256: Sha256Digest
    verifier_policy_sha256: Sha256Digest
    authority_path_sha256: Sha256Digest
    comparison_policy_sha256: Sha256Digest
    selection_condition: RecoveryUtilitySelectionCondition
    verification_mode: RecoveryUtilityVerificationMode
    probe_capabilities: tuple[Identifier, ...] = Field(min_length=1, max_length=64)
    conditionally_skipped_capabilities: tuple[Identifier, ...] = Field(max_length=64)
    probe_count: int = Field(ge=1, le=64)
    simulated_controller_ticks_to_sufficient_evidence: int = Field(
        ge=0,
        le=2**63 - 1,
    )
    provider_contacts: RecoveryQualificationProviderMutations
    provider_read_contact_count: int = Field(ge=0, le=2**63 - 1)
    provider_contact_count: int = Field(ge=1, le=2**63 - 1)
    model_usage: RecoveryQualificationModelUsage
    initial_classification: Literal[Classification.UNKNOWN]
    deterministic_decision: RecoveryDecision
    deterministic_artifact_kind: RecoveryQualificationArtifactKind
    permit_action: PermitAction | None
    effects: RecoveryUtilityEffects
    model_can_classify: Literal[False]
    model_can_issue_authority: Literal[False]
    model_can_contact_mutation_provider: Literal[False]

    @model_validator(mode="after")
    def validate_lane(self) -> RecoveryUtilityLaneResult:
        if self.probe_count != len(self.probe_capabilities):
            raise ValueError("probe count must match the recorded capability sequence")
        if self.provider_contact_count != (
            self.provider_read_contact_count
            + self.provider_contacts.outbound_call_count
        ):
            raise ValueError("provider contact count omits an observed operation")
        if self.policy is RecoveryUtilityPolicy.FIXED:
            if (
                self.model_usage.status
                is not RecoveryQualificationModelUsageStatus.NOT_APPLICABLE
            ):
                raise ValueError("fixed recovery lane cannot report model usage")
            if (
                self.selection_condition
                is not RecoveryUtilitySelectionCondition.FIXED_ORDER
            ):
                raise ValueError("fixed recovery lane changed its selection rule")
            if (
                self.verification_mode
                is not RecoveryUtilityVerificationMode.FIXED_BATCH_THEN_VERIFY
            ):
                raise ValueError("fixed recovery lane changed its verification mode")
        elif self.model_usage.status not in {
            RecoveryQualificationModelUsageStatus.SCRIPTED,
            RecoveryQualificationModelUsageStatus.MEASURED,
            RecoveryQualificationModelUsageStatus.UNAVAILABLE,
        }:
            raise ValueError("adaptive recovery lane requires explicit model status")
        elif (
            self.selection_condition
            is not RecoveryUtilitySelectionCondition.SERVICE_STATE_REQUIRES_REVISION
        ):
            raise ValueError("adaptive recovery lane lacks its observed condition")
        elif (
            self.verification_mode
            is not RecoveryUtilityVerificationMode.INCREMENTAL_AFTER_EACH_PROBE
        ):
            raise ValueError("adaptive recovery lane changed its verification mode")
        if (
            self.deterministic_decision is not RecoveryDecision.CONTINUE
            or self.permit_action is not PermitAction.CONTINUE
            or self.deterministic_artifact_kind
            is not RecoveryQualificationArtifactKind.VERIFIED_CERTIFICATE
        ):
            raise ValueError(
                "conditional recovery lane changed deterministic authority"
            )
        if self.effects != RecoveryUtilityEffects(
            revisions_created=1,
            promotions_accepted=1,
            release_records_created=1,
        ):
            raise ValueError("conditional recovery lane changed exact provider effects")
        return self


class RecoveryUtilitySmokeResult(StrictModel):
    shared_recovery_core: Literal[True]
    fault: Literal[RecoveryRunFault.DROP_AFTER_ACCEPT]
    initial_launch_permit_state: Literal[RecoveryLaunchPermitState.COMPLETED]
    initial_outcome: Literal[RecoveryDispatchOutcome.OUTCOME_UNKNOWN]
    initial_provider_contact_receipt_count: Literal[1]
    initial_classification: Literal[Classification.UNKNOWN]
    deterministic_action: Literal[PermitAction.CONTINUE]
    terminal_chain_completed: Literal[True]
    provider_contacts: RecoveryQualificationProviderMutations
    provider_read_contact_count: int = Field(ge=0, le=2**63 - 1)
    provider_contact_count: int = Field(ge=1, le=2**63 - 1)
    effects: RecoveryUtilityEffects
    replay_denied: Literal[True]
    replay_provider_read_contact_delta: Literal[0]
    replay_provider_mutation_contact_delta: Literal[0]
    replay_provider_contact_delta: Literal[0]
    model_usage: RecoveryQualificationModelUsage

    @model_validator(mode="after")
    def validate_smoke(self) -> RecoveryUtilitySmokeResult:
        if self.effects != RecoveryUtilityEffects(
            revisions_created=1,
            promotions_accepted=1,
            release_records_created=1,
        ):
            raise ValueError("smoke execution did not retain exact provider effects")
        if (
            self.model_usage.status
            is not RecoveryQualificationModelUsageStatus.SCRIPTED
            or self.model_usage.model_call_count < 1
        ):
            raise ValueError("smoke execution did not report scripted planner usage")
        if self.provider_contact_count != (
            self.provider_read_contact_count
            + self.provider_contacts.outbound_call_count
        ):
            raise ValueError("smoke provider contact count omits an observed operation")
        return self


class RecoveryUtilityReport(StrictModel):
    schema_version: Literal[RECOVERY_UTILITY_REPORT_VERSION]
    report_id: Identifier
    case_id: Identifier
    baselines: tuple[RecoveryRetryBaselineResult, RecoveryRetryBaselineResult] = Field(
        min_length=2,
        max_length=2,
    )
    fixed: RecoveryUtilityLaneResult
    adaptive: RecoveryUtilityLaneResult
    smoke: RecoveryUtilitySmokeResult
    execution_basis: Literal[RecoveryUtilityExecutionBasis.DETERMINISTIC_LOCAL_SCRIPTED]
    conclusion: Literal[RecoveryUtilityConclusion.MEASUREMENTS_ONLY]
    observed_at: AwareDatetime

    @model_validator(mode="after")
    def validate_report(self) -> RecoveryUtilityReport:
        if tuple(item.baseline for item in self.baselines) != (
            RecoveryRetryBaselineKind.NAIVE_NEW_IDENTITY,
            RecoveryRetryBaselineKind.STABLE_IDENTITY_PRECONDITION,
        ):
            raise ValueError("recovery baselines must retain their canonical order")
        if (
            self.fixed.policy is not RecoveryUtilityPolicy.FIXED
            or self.adaptive.policy is not RecoveryUtilityPolicy.ADAPTIVE
        ):
            raise ValueError("recovery comparison lanes changed identity")
        shared_fields = (
            "case_sha256",
            "sealed_inputs_sha256",
            "capability_catalog_sha256",
            "budget_catalog_sha256",
            "verifier_policy_sha256",
            "authority_path_sha256",
            "comparison_policy_sha256",
        )
        if any(
            getattr(self.fixed, field) != getattr(self.adaptive, field)
            for field in shared_fields
        ):
            raise ValueError("fixed and adaptive lanes do not share sealed inputs")
        if any(
            baseline.sealed_inputs_sha256 != self.fixed.sealed_inputs_sha256
            for baseline in self.baselines
        ):
            raise ValueError("retry baselines do not share the sealed inputs")
        if (
            self.fixed.deterministic_decision
            is not self.adaptive.deterministic_decision
            or self.fixed.permit_action is not self.adaptive.permit_action
            or self.fixed.effects != self.adaptive.effects
        ):
            raise ValueError("fixed and adaptive deterministic outcomes diverged")
        return self


__all__ = [
    "RECOVERY_UTILITY_REPORT_VERSION",
    "RecoveryRetryBaselineKind",
    "RecoveryRetryBaselineResult",
    "RecoveryRetryPrecondition",
    "RecoveryUtilityConclusion",
    "RecoveryUtilityEffects",
    "RecoveryUtilityExecutionBasis",
    "RecoveryUtilityLaneResult",
    "RecoveryUtilityPolicy",
    "RecoveryUtilityReport",
    "RecoveryUtilitySelectionCondition",
    "RecoveryUtilitySmokeResult",
    "RecoveryUtilityVerificationMode",
]
