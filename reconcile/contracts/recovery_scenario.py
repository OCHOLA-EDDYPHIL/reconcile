"""Judge-readable contracts for the four-policy recovery release scenario."""

from __future__ import annotations

from enum import StrEnum
from typing import Literal

from pydantic import Field, model_validator

from reconcile.contracts.base import (
    AwareDatetime,
    Identifier,
    SanitizedText,
    Sha256Digest,
    StrictModel,
)

RECOVERY_DISPATCH_RECEIPT_VERSION = "reconcile/recovery-dispatch-receipt/v1"
RECOVERY_POLICY_RESULT_VERSION = "reconcile/recovery-policy-result/v1"
RECOVERY_POLICY_COMPARISON_VERSION = "reconcile/recovery-policy-comparison/v1"
RECOVERY_RESET_RESULT_VERSION = "reconcile/recovery-reset-result/v1"


class RecoveryReceiptOutcome(StrEnum):
    """What the trusted dispatcher knew before or after provider contact."""

    PROVIDER_CONTACTED = "PROVIDER_CONTACTED"
    SUPPRESSED_BEFORE_DISPATCH = "SUPPRESSED_BEFORE_DISPATCH"
    REJECTED_BEFORE_PROVIDER_CONTACT = "REJECTED_BEFORE_PROVIDER_CONTACT"


class RecoveryDispatchReceipt(StrictModel):
    """Durable dispatcher fact bound to one claimed-authority attempt."""

    schema_version: Literal[RECOVERY_DISPATCH_RECEIPT_VERSION]
    receipt_id: Identifier
    run_id: Identifier
    release_id: Identifier
    node_id: Identifier
    semantic_action_sha256: Sha256Digest
    action_request_sha256: Sha256Digest
    authority_id: Identifier
    claim_id: Identifier
    attempt: int = Field(ge=1, le=2)
    provider_contact: bool
    outcome: RecoveryReceiptOutcome
    recorded_at: AwareDatetime

    @model_validator(mode="after")
    def validate_contact(self) -> RecoveryDispatchReceipt:
        contacted = self.outcome is RecoveryReceiptOutcome.PROVIDER_CONTACTED
        if self.provider_contact is not contacted:
            raise ValueError("dispatch receipt outcome and provider contact disagree")
        return self


class RecoveryMutationCounters(StrictModel):
    revisions_created: int = Field(ge=0, le=16)
    promotions_accepted: int = Field(ge=0, le=16)
    release_records_created: int = Field(ge=0, le=16)
    provider_contacts: int = Field(ge=0, le=64)
    continue_permits_issued: int = Field(ge=0, le=16)
    retry_permits_issued: int = Field(ge=0, le=2)
    retry_permits_consumed: int = Field(ge=0, le=2)
    action_permits_consumed: int = Field(ge=0, le=16)

    @model_validator(mode="after")
    def validate_permits(self) -> RecoveryMutationCounters:
        if (
            self.retry_permits_consumed > self.retry_permits_issued
            or self.action_permits_consumed
            > self.continue_permits_issued + self.retry_permits_issued
            or self.retry_permits_consumed > self.action_permits_consumed
        ):
            raise ValueError("consumed permits exceed issued authority")
        return self


class RecoveryCloudRunObservation(StrictModel):
    baseline_revision: Identifier
    intended_revision: Identifier
    release_revisions: tuple[Identifier, ...] = Field(max_length=16)
    serving_revision: Identifier
    serving_percent: int = Field(ge=0, le=100)
    observed_service_etag_sha256: Sha256Digest

    @model_validator(mode="after")
    def validate_revisions(self) -> RecoveryCloudRunObservation:
        if len(self.release_revisions) != len(set(self.release_revisions)):
            raise ValueError("release revision inventory must be unique")
        return self


class RecoveryFirestoreObservation(StrictModel):
    release_id: Identifier
    document_path: SanitizedText
    payload_sha256: Sha256Digest | None = None
    semantic_action_sha256: Sha256Digest | None = None
    exists: bool
    cloud_run_revision: Identifier | None = None

    @model_validator(mode="after")
    def validate_record(self) -> RecoveryFirestoreObservation:
        observed_identity = (
            self.cloud_run_revision,
            self.payload_sha256,
            self.semantic_action_sha256,
        )
        if self.exists != all(value is not None for value in observed_identity) or (
            not self.exists and any(value is not None for value in observed_identity)
        ):
            raise ValueError("release-record existence and observed identity disagree")
        return self


class RecoveryTimelineEntry(StrictModel):
    sequence: int = Field(ge=1, le=256)
    node_id: Identifier
    event: Identifier
    detail: SanitizedText


class RecoveryPolicyResult(StrictModel):
    schema_version: Literal[RECOVERY_POLICY_RESULT_VERSION]
    run_id: Identifier
    policy: Literal["blind-retry", "blind-abort", "fixed", "adaptive"]
    fault: Literal["drop-after-accept", "suppress-before-dispatch"]
    target_sha256: Sha256Digest
    input_intent_sha256: Sha256Digest
    fault_boundary_sha256: Sha256Digest
    observation_catalog_sha256: Sha256Digest
    chain_completed: bool
    terminal_disposition: Literal["COMPLETED", "ABORTED", "ESCALATED"]
    counters: RecoveryMutationCounters
    cloud_run: RecoveryCloudRunObservation
    firestore: RecoveryFirestoreObservation
    dispatch_receipts: tuple[RecoveryDispatchReceipt, ...] = Field(max_length=16)
    timeline: tuple[RecoveryTimelineEntry, ...] = Field(min_length=1, max_length=256)
    certificate_sha256s: tuple[Sha256Digest, ...] = Field(max_length=32)
    witness_sha256s: tuple[Sha256Digest, ...] = Field(max_length=32)

    @model_validator(mode="after")
    def validate_result(self) -> RecoveryPolicyResult:
        if tuple(item.sequence for item in self.timeline) != tuple(
            range(1, len(self.timeline) + 1)
        ):
            raise ValueError("recovery timeline must be contiguous")
        receipt_ids = tuple(item.receipt_id for item in self.dispatch_receipts)
        if len(receipt_ids) != len(set(receipt_ids)):
            raise ValueError("dispatch receipt identifiers must be unique")
        if any(
            item.run_id != self.run_id or item.release_id != self.firestore.release_id
            for item in self.dispatch_receipts
        ):
            raise ValueError("dispatch receipts changed run or release identity")
        if self.chain_completed != (self.terminal_disposition == "COMPLETED"):
            raise ValueError("chain completion and terminal disposition disagree")
        if self.chain_completed and not (
            self.cloud_run.serving_percent == 100 and self.firestore.exists
        ):
            raise ValueError("completed release chain lacks its terminal effects")
        proof_policy = self.policy in {"fixed", "adaptive"}
        permit_counts = self.counters
        if not proof_policy and (
            self.dispatch_receipts
            or self.certificate_sha256s
            or self.witness_sha256s
            or permit_counts.continue_permits_issued
            or permit_counts.retry_permits_issued
            or permit_counts.retry_permits_consumed
            or permit_counts.action_permits_consumed
        ):
            raise ValueError("blind baseline acquired proof or mutation authority")
        if proof_policy and not (self.certificate_sha256s or self.witness_sha256s):
            raise ValueError("proof policy lacks a certificate or ambiguity witness")
        if proof_policy and self.chain_completed:
            if (
                self.cloud_run.release_revisions != (self.cloud_run.intended_revision,)
                or self.cloud_run.serving_revision != self.cloud_run.intended_revision
                or self.firestore.cloud_run_revision != self.cloud_run.intended_revision
                or permit_counts.revisions_created != 1
                or permit_counts.promotions_accepted != 1
                or permit_counts.release_records_created != 1
                or permit_counts.continue_permits_issued != 2
                or permit_counts.action_permits_consumed
                != 2 + permit_counts.retry_permits_consumed
            ):
                raise ValueError("proof policy did not produce the exact release chain")
            expected_retries = int(self.fault == "suppress-before-dispatch")
            if (
                permit_counts.retry_permits_issued != expected_retries
                or permit_counts.retry_permits_consumed != expected_retries
            ):
                raise ValueError("proof policy retry authority changed")
            suppressed = tuple(
                receipt
                for receipt in self.dispatch_receipts
                if receipt.outcome is RecoveryReceiptOutcome.SUPPRESSED_BEFORE_DISPATCH
            )
            if len(suppressed) != expected_retries:
                raise ValueError("proof policy suppression receipt changed")
        if (
            self.policy == "blind-retry"
            and self.fault == "drop-after-accept"
            and (
                permit_counts.revisions_created < 2
                or len(self.cloud_run.release_revisions) < 2
            )
        ):
            raise ValueError("blind retry did not expose its duplicate revision")
        if (
            self.policy == "blind-abort"
            and self.fault == "drop-after-accept"
            and (
                self.chain_completed
                or permit_counts.promotions_accepted
                or permit_counts.release_records_created
                or self.cloud_run.intended_revision
                not in self.cloud_run.release_revisions
            )
        ):
            raise ValueError("blind abort did not expose its incomplete release")
        return self


class RecoveryPolicyComparison(StrictModel):
    schema_version: Literal[RECOVERY_POLICY_COMPARISON_VERSION]
    comparison_id: Identifier
    release_id: Identifier
    fault: Literal["drop-after-accept", "suppress-before-dispatch"]
    target_sha256: Sha256Digest
    input_intent_sha256: Sha256Digest
    fault_boundary_sha256: Sha256Digest
    observation_catalog_sha256: Sha256Digest
    lanes: tuple[RecoveryPolicyResult, ...] = Field(min_length=4, max_length=4)
    reset_results: tuple[RecoveryResetResult, ...] = Field(min_length=4, max_length=4)
    created_at: AwareDatetime

    @model_validator(mode="after")
    def validate_comparison(self) -> RecoveryPolicyComparison:
        expected_order = ("blind-retry", "blind-abort", "fixed", "adaptive")
        if tuple(lane.policy for lane in self.lanes) != expected_order:
            raise ValueError("comparison requires the four policies in canonical order")
        if len({lane.run_id for lane in self.lanes}) != len(self.lanes):
            raise ValueError("comparison lanes must use isolated run identities")
        if any(
            lane.fault != self.fault or lane.firestore.release_id != self.release_id
            for lane in self.lanes
        ):
            raise ValueError("comparison lanes changed the fault or release identity")
        common = (
            self.target_sha256,
            self.input_intent_sha256,
            self.fault_boundary_sha256,
            self.observation_catalog_sha256,
        )
        if any(
            (
                lane.target_sha256,
                lane.input_intent_sha256,
                lane.fault_boundary_sha256,
                lane.observation_catalog_sha256,
            )
            != common
            for lane in self.lanes
        ):
            raise ValueError("comparison lanes do not share the sealed experiment")
        if any(reset.release_id != self.release_id for reset in self.reset_results):
            raise ValueError("comparison reset changed release identity")
        return self


class RecoveryResetResult(StrictModel):
    schema_version: Literal[RECOVERY_RESET_RESULT_VERSION]
    release_id: Identifier
    baseline_revision: Identifier
    serving_revision: Identifier
    serving_percent: int = Field(ge=0, le=100)
    release_record_absent: bool
    release_revisions_before: tuple[Identifier, ...] = Field(max_length=16)
    release_revisions_after: tuple[Identifier, ...] = Field(max_length=16)
    reset_operation_name_sha256: Sha256Digest
    verified_at: AwareDatetime

    @model_validator(mode="after")
    def validate_reset(self) -> RecoveryResetResult:
        if (
            self.serving_revision != self.baseline_revision
            or self.serving_percent != 100
            or not self.release_record_absent
        ):
            raise ValueError("reset did not restore the exact safe baseline")
        if not set(self.release_revisions_before) <= set(self.release_revisions_after):
            raise ValueError("reset must report immutable revision inventory honestly")
        return self


RecoveryPolicyComparison.model_rebuild()


__all__ = [
    "RECOVERY_DISPATCH_RECEIPT_VERSION",
    "RECOVERY_POLICY_COMPARISON_VERSION",
    "RECOVERY_POLICY_RESULT_VERSION",
    "RECOVERY_RESET_RESULT_VERSION",
    "RecoveryCloudRunObservation",
    "RecoveryDispatchReceipt",
    "RecoveryFirestoreObservation",
    "RecoveryMutationCounters",
    "RecoveryPolicyComparison",
    "RecoveryPolicyResult",
    "RecoveryReceiptOutcome",
    "RecoveryResetResult",
    "RecoveryTimelineEntry",
]
