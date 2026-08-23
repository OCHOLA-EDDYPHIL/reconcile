"""Versioned evidence records for proof-to-permit recovery qualification.

This namespace is deliberately separate from the legacy adaptive qualification
contracts.  The v1 records describe the frozen recovery matrix and its safety
claims without changing any pre-existing qualification semantics.
"""

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
from reconcile.contracts.codec import canonical_sha256
from reconcile.contracts.recovery import ActionPermit, ActionPermitState, PermitAction

RECOVERY_QUALIFICATION_BUNDLE_FORMAT = "proof-to-permit-qualification-v1"
RECOVERY_QUALIFICATION_MANIFEST_VERSION = (
    "reconcile/recovery-qualification-manifest/v1"
)
RECOVERY_QUALIFICATION_ENVIRONMENT_VERSION = (
    "reconcile/recovery-qualification-environment/v1"
)
RECOVERY_QUALIFICATION_RESULTS_VERSION = (
    "reconcile/recovery-qualification-results/v1"
)
RECOVERY_QUALIFICATION_CONTENTION_VERSION = (
    "reconcile/recovery-qualification-contention/v1"
)
RECOVERY_QUALIFICATION_COMPARISON_VERSION = (
    "reconcile/recovery-qualification-comparison/v1"
)
RECOVERY_QUALIFICATION_CLAIM_AUTHORIZATION_VERSION = (
    "reconcile/recovery-qualification-claim-authorization/v1"
)
RECOVERY_QUALIFICATION_INDEX_VERSION = (
    "reconcile/recovery-qualification-index/v1"
)

RECOVERY_QUALIFICATION_SEEDS = (104729, 130363, 155921, 196613, 262147)
RECOVERY_QUALIFICATION_CASE_COUNT = 100
RECOVERY_QUALIFICATION_LANE_COUNT = 400
RECOVERY_QUALIFICATION_WRONG_HYPOTHESIS_COUNT = 300
RECOVERY_QUALIFICATION_RESTART_COUNT = 20
RECOVERY_QUALIFICATION_CONTENTION_WIDTH = 32
RECOVERY_QUALIFICATION_ADAPTIVE_THRESHOLD_BASIS_POINTS = 2500
RECOVERY_QUALIFICATION_FIXTURE_CATALOG_SHA256 = (
    "d327653c2450cdd9fcc471f6f3f6057179c463c1b5ef7d2c5edfdc7af27ca902"
)

_MAX_SIGNED_64 = 2**63 - 1


class RecoveryQualificationPolicy(StrEnum):
    BLIND_RETRY = "blind-retry"
    BLIND_ABORT = "blind-abort"
    FIXED = "fixed"
    ADAPTIVE = "adaptive"


RECOVERY_QUALIFICATION_POLICIES = tuple(RecoveryQualificationPolicy)


class RecoveryQualificationStage(StrEnum):
    STAGE = "stage"
    PROMOTE = "promote"
    RECORD = "record"


class RecoveryQualificationFaultClass(StrEnum):
    NO_FAULT = "no-fault"
    DROP_AFTER_ACCEPT = "drop-after-accept"
    PENDING = "pending"
    TERMINAL_PARTIAL = "terminal-partial"
    CONFLICT = "conflict"
    ABSENCE = "absence"
    PROVIDER_UNAVAILABLE = "provider-unavailable"
    FRESHNESS = "freshness"
    SUPPRESS_BEFORE_DISPATCH = "suppress-before-dispatch"


class RecoveryQualificationOpportunity(StrEnum):
    FIXED_FAVORED = "fixed-favored"
    ADAPTIVE_FAVORED = "adaptive-favored"
    NEUTRAL = "neutral"


class RecoveryQualificationResolution(StrEnum):
    CONTINUE = "CONTINUE"
    RETRY = "RETRY"
    COMPLETED = "COMPLETED"
    ESCALATE = "ESCALATE"
    ABORT = "ABORT"


class RecoveryQualificationStorageBackend(StrEnum):
    SQLITE = "sqlite"
    FIRESTORE = "firestore"


class RecoveryQualificationExecutionBasis(StrEnum):
    SCRIPTED = "scripted"
    LIVE_VERTEX = "live-vertex"


class RecoveryQualificationModelUsageStatus(StrEnum):
    NOT_APPLICABLE = "NOT_APPLICABLE"
    SCRIPTED = "SCRIPTED"
    MEASURED = "MEASURED"
    UNAVAILABLE = "UNAVAILABLE"


class RecoveryQualificationArchetype(StrictModel):
    archetype_id: Identifier
    stage: RecoveryQualificationStage
    fault_class: RecoveryQualificationFaultClass
    opportunity: RecoveryQualificationOpportunity
    evidence_profile: tuple[Identifier, ...] = Field(min_length=1, max_length=16)
    expected_resolution: RecoveryQualificationResolution
    expected_permit_action: PermitAction | None
    ambiguity_witness_required: bool
    fixed_probe_count: int = Field(ge=1, le=16)
    adaptive_probe_count: int = Field(ge=1, le=16)
    fixed_unsupported_probe_count: int = Field(ge=0, le=16)
    adaptive_unsupported_probe_count: int = Field(ge=0, le=16)

    @model_validator(mode="after")
    def validate_archetype(self) -> RecoveryQualificationArchetype:
        if len(self.evidence_profile) != len(set(self.evidence_profile)):
            raise ValueError("recovery qualification evidence profile must be unique")
        expected_action = {
            RecoveryQualificationResolution.CONTINUE: PermitAction.CONTINUE,
            RecoveryQualificationResolution.RETRY: PermitAction.RETRY,
        }.get(self.expected_resolution)
        if self.expected_permit_action is not expected_action:
            raise ValueError("qualification resolution and expected permit disagree")
        if self.ambiguity_witness_required is not (
            self.expected_resolution is RecoveryQualificationResolution.ESCALATE
        ):
            raise ValueError("qualification ambiguity witness requirement is derived")
        if self.fixed_unsupported_probe_count > self.fixed_probe_count or (
            self.adaptive_unsupported_probe_count > self.adaptive_probe_count
        ):
            raise ValueError("unsupported probes cannot exceed executed probes")
        favored = {
            RecoveryQualificationOpportunity.FIXED_FAVORED: (
                self.fixed_probe_count < self.adaptive_probe_count
            ),
            RecoveryQualificationOpportunity.ADAPTIVE_FAVORED: (
                self.adaptive_probe_count < self.fixed_probe_count
            ),
            RecoveryQualificationOpportunity.NEUTRAL: (
                self.fixed_probe_count == self.adaptive_probe_count
            ),
        }[self.opportunity]
        if not favored:
            raise ValueError("qualification opportunity disagrees with probe counts")
        return self


class RecoveryQualificationManifest(StrictModel):
    schema_version: Literal[RECOVERY_QUALIFICATION_MANIFEST_VERSION]
    bundle_format: Literal[RECOVERY_QUALIFICATION_BUNDLE_FORMAT]
    suite_id: Identifier
    source_revision: Identifier
    source_tree_sha256: Sha256Digest
    fixture_catalog_sha256: Literal[RECOVERY_QUALIFICATION_FIXTURE_CATALOG_SHA256]
    controller_version: Identifier
    decision_policy_version: Identifier
    permit_policy_version: Identifier
    seeds: tuple[int, ...] = Field(min_length=5, max_length=5)
    policies: tuple[RecoveryQualificationPolicy, ...] = Field(
        min_length=4,
        max_length=4,
    )
    archetypes: tuple[RecoveryQualificationArchetype, ...] = Field(
        min_length=20,
        max_length=20,
    )
    case_count: Literal[RECOVERY_QUALIFICATION_CASE_COUNT]
    lane_result_count: Literal[RECOVERY_QUALIFICATION_LANE_COUNT]
    wrong_hypothesis_variants_per_case: Literal[3]
    restart_case_count: Literal[RECOVERY_QUALIFICATION_RESTART_COUNT]
    contention_width: Literal[RECOVERY_QUALIFICATION_CONTENTION_WIDTH]
    adaptive_efficiency_threshold_basis_points: Literal[
        RECOVERY_QUALIFICATION_ADAPTIVE_THRESHOLD_BASIS_POINTS
    ]
    created_at: AwareDatetime

    @model_validator(mode="after")
    def validate_frozen_matrix(self) -> RecoveryQualificationManifest:
        if self.seeds != RECOVERY_QUALIFICATION_SEEDS:
            raise ValueError("recovery qualification seeds changed")
        if self.policies != RECOVERY_QUALIFICATION_POLICIES:
            raise ValueError("recovery qualification lane order changed")
        identifiers = tuple(item.archetype_id for item in self.archetypes)
        if len(identifiers) != len(set(identifiers)):
            raise ValueError("recovery qualification archetypes must be unique")
        if self.case_count != len(self.archetypes) * len(self.seeds):
            raise ValueError("recovery qualification case count changed")
        if self.lane_result_count != self.case_count * len(self.policies):
            raise ValueError("recovery qualification lane count changed")
        if {item.stage for item in self.archetypes} != set(
            RecoveryQualificationStage
        ):
            raise ValueError("recovery qualification omits a chain stage")
        if {item.fault_class for item in self.archetypes} != set(
            RecoveryQualificationFaultClass
        ):
            raise ValueError("recovery qualification omits a fault class")
        if {item.opportunity for item in self.archetypes} != set(
            RecoveryQualificationOpportunity
        ):
            raise ValueError("recovery qualification omits an efficiency opportunity")
        actions = {
            item.expected_permit_action
            for item in self.archetypes
            if item.expected_permit_action is not None
        }
        if actions != {PermitAction.CONTINUE, PermitAction.RETRY}:
            raise ValueError("recovery qualification omits a permit action")
        return self


class RecoveryQualificationEnvironment(StrictModel):
    schema_version: Literal[RECOVERY_QUALIFICATION_ENVIRONMENT_VERSION]
    bundle_format: Literal[RECOVERY_QUALIFICATION_BUNDLE_FORMAT]
    suite_id: Identifier
    manifest_sha256: Sha256Digest
    source_revision: Identifier
    source_tree_sha256: Sha256Digest
    repository_clean: bool
    execution_basis: RecoveryQualificationExecutionBasis
    runner_version: Identifier
    python_version: SanitizedText
    platform: SanitizedText
    dependency_lock_sha256: Sha256Digest
    test_commands: tuple[SanitizedText, ...] = Field(min_length=1, max_length=16)
    provider_name: Identifier | None = None
    model_name: Identifier | None = None
    vertex_location: Identifier | None = None
    generated_at: AwareDatetime

    @model_validator(mode="after")
    def validate_execution_basis(self) -> RecoveryQualificationEnvironment:
        if len(self.test_commands) != len(set(self.test_commands)):
            raise ValueError("qualification test commands must be unique")
        provider = (self.provider_name, self.model_name, self.vertex_location)
        if self.execution_basis is RecoveryQualificationExecutionBasis.SCRIPTED:
            if provider != (None, None, None):
                raise ValueError("scripted qualification cannot claim a live provider")
        elif (
            self.provider_name != "vertex-ai"
            or self.model_name is None
            or self.vertex_location is None
        ):
            raise ValueError("live qualification requires an exact Vertex binding")
        return self


class RecoveryQualificationModelUsage(StrictModel):
    status: RecoveryQualificationModelUsageStatus
    provider_name: Identifier | None = None
    model_name: Identifier | None = None
    model_call_count: int = Field(ge=0, le=_MAX_SIGNED_64)
    input_token_count: int = Field(ge=0, le=_MAX_SIGNED_64)
    output_token_count: int = Field(ge=0, le=_MAX_SIGNED_64)
    total_token_count: int = Field(ge=0, le=_MAX_SIGNED_64)
    input_cost_nano_units_per_token: int = Field(ge=0, le=_MAX_SIGNED_64)
    output_cost_nano_units_per_token: int = Field(ge=0, le=_MAX_SIGNED_64)
    model_cost_nano_units: int = Field(ge=0, le=_MAX_SIGNED_64)
    live_vertex_backed: bool

    @model_validator(mode="after")
    def validate_usage(self) -> RecoveryQualificationModelUsage:
        if self.total_token_count != self.input_token_count + self.output_token_count:
            raise ValueError("recovery qualification token totals must be additive")
        expected_cost = (
            self.input_token_count * self.input_cost_nano_units_per_token
            + self.output_token_count * self.output_cost_nano_units_per_token
        )
        if self.model_cost_nano_units != expected_cost:
            raise ValueError("recovery qualification model cost must be exact")
        identity_complete = (self.provider_name is None) is (self.model_name is None)
        if not identity_complete:
            raise ValueError("model provider and model identity must be complete")
        zero_usage = all(
            value == 0
            for value in (
                self.model_call_count,
                self.input_token_count,
                self.output_token_count,
                self.total_token_count,
                self.input_cost_nano_units_per_token,
                self.output_cost_nano_units_per_token,
                self.model_cost_nano_units,
            )
        )
        if self.status in {
            RecoveryQualificationModelUsageStatus.NOT_APPLICABLE,
            RecoveryQualificationModelUsageStatus.SCRIPTED,
        }:
            valid = (
                zero_usage
                and self.provider_name is None
                and not self.live_vertex_backed
            )
        elif self.status is RecoveryQualificationModelUsageStatus.MEASURED:
            valid = (
                self.provider_name == "vertex-ai"
                and self.model_name is not None
                and self.model_call_count > 0
                and self.total_token_count > 0
                and self.live_vertex_backed
            )
        else:
            valid = (
                self.provider_name == "vertex-ai"
                and self.model_name is not None
                and self.model_call_count > 0
                and self.total_token_count == 0
                and self.model_cost_nano_units == 0
                and self.live_vertex_backed
            )
        if not valid:
            raise ValueError("model usage fields do not match their status")
        return self


class RecoveryQualificationProviderMutations(StrictModel):
    stage_calls: int = Field(ge=0, le=16)
    promote_calls: int = Field(ge=0, le=16)
    record_calls: int = Field(ge=0, le=16)
    outbound_call_count: int = Field(ge=0, le=48)

    @model_validator(mode="after")
    def validate_total(self) -> RecoveryQualificationProviderMutations:
        if self.outbound_call_count != (
            self.stage_calls + self.promote_calls + self.record_calls
        ):
            raise ValueError("provider mutation total must equal per-stage calls")
        return self


class RecoveryQualificationLaneResult(StrictModel):
    sequence: int = Field(ge=1, le=RECOVERY_QUALIFICATION_LANE_COUNT)
    case_id: Identifier
    archetype_id: Identifier
    seed: int = Field(ge=0, le=_MAX_SIGNED_64)
    policy: RecoveryQualificationPolicy
    storage_backend: RecoveryQualificationStorageBackend
    fault_class: RecoveryQualificationFaultClass
    admitted_evidence_sha256: Sha256Digest
    decision_sha256: Sha256Digest
    resolution: RecoveryQualificationResolution
    expected_permit_action: PermitAction | None
    issued_permit_action: PermitAction | None
    permit_sha256: Sha256Digest | None
    false_permit: bool
    probe_count: int = Field(ge=0, le=16)
    time_to_sufficient_evidence_ms: int | None = Field(
        default=None,
        ge=0,
        le=_MAX_SIGNED_64,
    )
    unsupported_probe_count: int = Field(ge=0, le=16)
    resolved: bool
    provider_mutations: RecoveryQualificationProviderMutations
    model_usage: RecoveryQualificationModelUsage
    ambiguity_witness_sha256: Sha256Digest | None

    @model_validator(mode="after")
    def validate_lane(self) -> RecoveryQualificationLaneResult:
        if self.seed not in RECOVERY_QUALIFICATION_SEEDS:
            raise ValueError("lane seed is outside the frozen schedule")
        if self.unsupported_probe_count > self.probe_count:
            raise ValueError("unsupported probes cannot exceed executed probes")
        if (self.probe_count == 0) is not (
            self.time_to_sufficient_evidence_ms is None
        ):
            raise ValueError("probe timing must be present exactly when probes execute")
        proof_policy = self.policy in {
            RecoveryQualificationPolicy.FIXED,
            RecoveryQualificationPolicy.ADAPTIVE,
        }
        if proof_policy:
            expected_false = self.issued_permit_action is not self.expected_permit_action
        else:
            expected_false = self.issued_permit_action is not None
        if self.false_permit is not expected_false:
            raise ValueError("false-permit status must be derived")
        if (self.issued_permit_action is None) is not (self.permit_sha256 is None):
            raise ValueError("permit action and digest must be present together")
        expected_resolved = self.resolution in {
            RecoveryQualificationResolution.CONTINUE,
            RecoveryQualificationResolution.RETRY,
            RecoveryQualificationResolution.COMPLETED,
        }
        if self.resolved is not expected_resolved:
            raise ValueError("resolution status must be derived")
        witness_required = self.resolution is RecoveryQualificationResolution.ESCALATE
        if (self.ambiguity_witness_sha256 is not None) is not witness_required:
            raise ValueError("escalation must retain exactly one ambiguity witness")
        if self.policy is RecoveryQualificationPolicy.ADAPTIVE:
            if self.model_usage.status not in {
                RecoveryQualificationModelUsageStatus.SCRIPTED,
                RecoveryQualificationModelUsageStatus.MEASURED,
                RecoveryQualificationModelUsageStatus.UNAVAILABLE,
            }:
                raise ValueError("adaptive lane model usage status is invalid")
        elif (
            self.model_usage.status
            is not RecoveryQualificationModelUsageStatus.NOT_APPLICABLE
        ):
            raise ValueError("non-adaptive lanes cannot record model usage")
        return self


class RecoveryQualificationHypothesisReplay(StrictModel):
    variant_id: Identifier
    provider_name: Literal["gemini"]
    proposed_resolution: RecoveryQualificationResolution
    proposed_permit_action: PermitAction | None
    observed_decision_sha256: Sha256Digest
    observed_permit_sha256: Sha256Digest | None
    decision_diverged: bool
    permit_diverged: bool

    @model_validator(mode="after")
    def validate_proposal(self) -> RecoveryQualificationHypothesisReplay:
        expected_action = {
            RecoveryQualificationResolution.CONTINUE: PermitAction.CONTINUE,
            RecoveryQualificationResolution.RETRY: PermitAction.RETRY,
        }.get(self.proposed_resolution)
        if self.proposed_permit_action is not expected_action:
            raise ValueError("hypothesis resolution and proposed permit disagree")
        return self


class RecoveryQualificationCaseProof(StrictModel):
    sequence: int = Field(ge=1, le=RECOVERY_QUALIFICATION_CASE_COUNT)
    case_id: Identifier
    archetype_id: Identifier
    seed: int = Field(ge=0, le=_MAX_SIGNED_64)
    storage_backend: RecoveryQualificationStorageBackend
    admitted_evidence_sha256: Sha256Digest
    deterministic_resolution: RecoveryQualificationResolution
    deterministic_permit_action: PermitAction | None
    fixed_decision_sha256: Sha256Digest
    adaptive_decision_sha256: Sha256Digest
    fixed_permit_sha256: Sha256Digest | None
    adaptive_permit_sha256: Sha256Digest | None
    decision_replay_parity: bool
    permit_replay_parity: bool
    wrong_hypothesis_replays: tuple[RecoveryQualificationHypothesisReplay, ...] = (
        Field(min_length=3, max_length=3)
    )
    witness_exercised: bool
    witness_sha256: Sha256Digest | None
    reordered_witness_sha256: Sha256Digest | None
    duplicated_witness_sha256: Sha256Digest | None
    witness_reorder_valid: bool
    witness_duplication_valid: bool
    restart_exercised: bool
    restart_lane_sha256: Sha256Digest | None
    restarted_decision_sha256: Sha256Digest | None
    restarted_permit_sha256: Sha256Digest | None
    restart_decision_valid: bool
    restart_permit_valid: bool

    @model_validator(mode="after")
    def validate_case_proof(self) -> RecoveryQualificationCaseProof:
        if self.seed not in RECOVERY_QUALIFICATION_SEEDS:
            raise ValueError("case proof seed is outside the frozen schedule")
        identifiers = tuple(item.variant_id for item in self.wrong_hypothesis_replays)
        if len(identifiers) != len(set(identifiers)):
            raise ValueError("wrong-hypothesis variants must be unique")
        proposals = tuple(
            (item.proposed_resolution, item.proposed_permit_action)
            for item in self.wrong_hypothesis_replays
        )
        if len(proposals) != len(set(proposals)) or any(
            proposal
            == (self.deterministic_resolution, self.deterministic_permit_action)
            for proposal in proposals
        ):
            raise ValueError("hypothesis variants must be distinct and deliberately wrong")
        decision_parity = self.fixed_decision_sha256 == self.adaptive_decision_sha256
        permit_parity = self.fixed_permit_sha256 == self.adaptive_permit_sha256
        if (
            self.decision_replay_parity is not decision_parity
            or self.permit_replay_parity is not permit_parity
        ):
            raise ValueError("fixed/adaptive replay parity must be derived")
        for replay in self.wrong_hypothesis_replays:
            decision_diverged = (
                replay.observed_decision_sha256 != self.fixed_decision_sha256
            )
            permit_diverged = replay.observed_permit_sha256 != self.fixed_permit_sha256
            if (
                replay.decision_diverged is not decision_diverged
                or replay.permit_diverged is not permit_diverged
            ):
                raise ValueError("wrong-hypothesis divergence must be derived")
        witness_values = (
            self.witness_sha256,
            self.reordered_witness_sha256,
            self.duplicated_witness_sha256,
        )
        if self.witness_exercised:
            if any(value is None for value in witness_values):
                raise ValueError("witness replay requires every witness digest")
            reorder_valid = self.witness_sha256 == self.reordered_witness_sha256
            duplicate_valid = self.witness_sha256 == self.duplicated_witness_sha256
        else:
            if any(value is not None for value in witness_values):
                raise ValueError("non-witness cases cannot contain witness digests")
            reorder_valid = True
            duplicate_valid = True
        if (
            self.witness_reorder_valid is not reorder_valid
            or self.witness_duplication_valid is not duplicate_valid
        ):
            raise ValueError("witness replay validity must be derived")
        if self.restart_exercised:
            if self.restart_lane_sha256 is None or (
                self.restarted_decision_sha256 is None
            ):
                raise ValueError("restart cases require reloaded artifact evidence")
            restart_decision_valid = (
                self.restarted_decision_sha256 == self.fixed_decision_sha256
            )
            restart_permit_valid = (
                self.restarted_permit_sha256 == self.fixed_permit_sha256
            )
        else:
            if any(
                value is not None
                for value in (
                    self.restart_lane_sha256,
                    self.restarted_decision_sha256,
                    self.restarted_permit_sha256,
                )
            ):
                raise ValueError("non-restart cases cannot contain restart evidence")
            restart_decision_valid = True
            restart_permit_valid = True
        if (
            self.restart_decision_valid is not restart_decision_valid
            or self.restart_permit_valid is not restart_permit_valid
        ):
            raise ValueError("restart replay validity must be derived")
        return self


class RecoveryQualificationPermitCoverage(StrictModel):
    continue_case_count: int = Field(ge=1, le=RECOVERY_QUALIFICATION_CASE_COUNT)
    retry_case_count: int = Field(ge=1, le=RECOVERY_QUALIFICATION_CASE_COUNT)
    no_permit_case_count: int = Field(ge=1, le=RECOVERY_QUALIFICATION_CASE_COUNT)

    @model_validator(mode="after")
    def validate_partition(self) -> RecoveryQualificationPermitCoverage:
        if (
            self.continue_case_count
            + self.retry_case_count
            + self.no_permit_case_count
            != RECOVERY_QUALIFICATION_CASE_COUNT
        ):
            raise ValueError("permit coverage must partition the frozen cases")
        return self


class RecoveryQualificationResults(StrictModel):
    schema_version: Literal[RECOVERY_QUALIFICATION_RESULTS_VERSION]
    bundle_format: Literal[RECOVERY_QUALIFICATION_BUNDLE_FORMAT]
    suite_id: Identifier
    manifest_sha256: Sha256Digest
    environment_sha256: Sha256Digest
    lane_results: tuple[RecoveryQualificationLaneResult, ...] = Field(
        min_length=RECOVERY_QUALIFICATION_LANE_COUNT,
        max_length=RECOVERY_QUALIFICATION_LANE_COUNT,
    )
    case_proofs: tuple[RecoveryQualificationCaseProof, ...] = Field(
        min_length=RECOVERY_QUALIFICATION_CASE_COUNT,
        max_length=RECOVERY_QUALIFICATION_CASE_COUNT,
    )
    case_count: Literal[RECOVERY_QUALIFICATION_CASE_COUNT]
    lane_result_count: Literal[RECOVERY_QUALIFICATION_LANE_COUNT]
    false_permit_count: int = Field(ge=0, le=RECOVERY_QUALIFICATION_LANE_COUNT)
    replay_parity_case_count: int = Field(
        ge=0,
        le=RECOVERY_QUALIFICATION_CASE_COUNT,
    )
    wrong_hypothesis_replay_count: int = Field(
        ge=0,
        le=RECOVERY_QUALIFICATION_WRONG_HYPOTHESIS_COUNT,
    )
    wrong_hypothesis_decision_divergence_count: int = Field(
        ge=0,
        le=RECOVERY_QUALIFICATION_WRONG_HYPOTHESIS_COUNT,
    )
    wrong_hypothesis_permit_divergence_count: int = Field(
        ge=0,
        le=RECOVERY_QUALIFICATION_WRONG_HYPOTHESIS_COUNT,
    )
    witness_case_count: int = Field(ge=1, le=RECOVERY_QUALIFICATION_CASE_COUNT)
    witness_replay_valid_count: int = Field(
        ge=0,
        le=RECOVERY_QUALIFICATION_CASE_COUNT,
    )
    restart_case_count: int = Field(ge=0, le=RECOVERY_QUALIFICATION_RESTART_COUNT)
    restart_valid_count: int = Field(ge=0, le=RECOVERY_QUALIFICATION_RESTART_COUNT)
    permit_coverage: RecoveryQualificationPermitCoverage
    sqlite_case_count: int = Field(ge=1, le=RECOVERY_QUALIFICATION_CASE_COUNT)
    firestore_case_count: int = Field(ge=1, le=RECOVERY_QUALIFICATION_CASE_COUNT)
    safety_passed: bool

    @model_validator(mode="after")
    def validate_results(self) -> RecoveryQualificationResults:
        if tuple(item.sequence for item in self.lane_results) != tuple(
            range(1, RECOVERY_QUALIFICATION_LANE_COUNT + 1)
        ):
            raise ValueError("qualification lane sequence must be contiguous")
        if tuple(item.sequence for item in self.case_proofs) != tuple(
            range(1, RECOVERY_QUALIFICATION_CASE_COUNT + 1)
        ):
            raise ValueError("qualification case sequence must be contiguous")
        grouped: dict[str, list[RecoveryQualificationLaneResult]] = {}
        for lane in self.lane_results:
            grouped.setdefault(lane.case_id, []).append(lane)
        if len(grouped) != RECOVERY_QUALIFICATION_CASE_COUNT:
            raise ValueError("qualification results require one hundred cases")
        proofs = {item.case_id: item for item in self.case_proofs}
        if set(proofs) != set(grouped):
            raise ValueError("case proofs do not match lane results")
        expected_case_order = tuple(item.case_id for item in self.case_proofs)
        observed_case_order = tuple(dict.fromkeys(item.case_id for item in self.lane_results))
        if observed_case_order != expected_case_order:
            raise ValueError("case proof and lane order changed")
        for case_id, lanes in grouped.items():
            if tuple(item.policy for item in lanes) != RECOVERY_QUALIFICATION_POLICIES:
                raise ValueError("each case requires the canonical four lanes")
            common = {
                (
                    item.archetype_id,
                    item.seed,
                    item.storage_backend,
                    item.fault_class,
                    item.admitted_evidence_sha256,
                    item.expected_permit_action,
                )
                for item in lanes
            }
            if len(common) != 1:
                raise ValueError("qualification lanes changed their common case")
            fixed = lanes[2]
            adaptive = lanes[3]
            proof = proofs[case_id]
            if (
                fixed.decision_sha256 != adaptive.decision_sha256
                or fixed.issued_permit_action is not adaptive.issued_permit_action
                or fixed.permit_sha256 != adaptive.permit_sha256
                or proof.fixed_decision_sha256 != fixed.decision_sha256
                or proof.adaptive_decision_sha256 != adaptive.decision_sha256
                or proof.fixed_permit_sha256 != fixed.permit_sha256
                or proof.adaptive_permit_sha256 != adaptive.permit_sha256
                or proof.admitted_evidence_sha256
                != fixed.admitted_evidence_sha256
                or proof.deterministic_resolution is not fixed.resolution
                or proof.deterministic_permit_action
                is not fixed.issued_permit_action
            ):
                raise ValueError("fixed/adaptive deterministic replay diverged")
        false_permits = sum(item.false_permit for item in self.lane_results)
        parity = sum(
            item.decision_replay_parity and item.permit_replay_parity
            for item in self.case_proofs
        )
        wrong = sum(len(item.wrong_hypothesis_replays) for item in self.case_proofs)
        wrong_decisions = sum(
            replay.decision_diverged
            for item in self.case_proofs
            for replay in item.wrong_hypothesis_replays
        )
        wrong_permits = sum(
            replay.permit_diverged
            for item in self.case_proofs
            for replay in item.wrong_hypothesis_replays
        )
        witnesses = tuple(item for item in self.case_proofs if item.witness_exercised)
        witness_valid = sum(
            item.witness_reorder_valid and item.witness_duplication_valid
            for item in witnesses
        )
        restarts = tuple(item for item in self.case_proofs if item.restart_exercised)
        restart_valid = sum(
            item.restart_decision_valid and item.restart_permit_valid
            for item in restarts
        )
        expected = (
            false_permits,
            parity,
            wrong,
            wrong_decisions,
            wrong_permits,
            len(witnesses),
            witness_valid,
            len(restarts),
            restart_valid,
        )
        recorded = (
            self.false_permit_count,
            self.replay_parity_case_count,
            self.wrong_hypothesis_replay_count,
            self.wrong_hypothesis_decision_divergence_count,
            self.wrong_hypothesis_permit_divergence_count,
            self.witness_case_count,
            self.witness_replay_valid_count,
            self.restart_case_count,
            self.restart_valid_count,
        )
        if recorded != expected:
            raise ValueError("qualification aggregate counts must be derived")
        fixed_lanes = tuple(
            item
            for item in self.lane_results
            if item.policy is RecoveryQualificationPolicy.FIXED
        )
        actions = tuple(item.expected_permit_action for item in fixed_lanes)
        coverage = RecoveryQualificationPermitCoverage(
            continue_case_count=actions.count(PermitAction.CONTINUE),
            retry_case_count=actions.count(PermitAction.RETRY),
            no_permit_case_count=actions.count(None),
        )
        if self.permit_coverage != coverage:
            raise ValueError("permit-action coverage must be derived")
        sqlite = sum(
            item.storage_backend is RecoveryQualificationStorageBackend.SQLITE
            for item in self.case_proofs
        )
        firestore = len(self.case_proofs) - sqlite
        if (self.sqlite_case_count, self.firestore_case_count) != (
            sqlite,
            firestore,
        ):
            raise ValueError("storage-backend coverage must be derived")
        passed = all(
            (
                false_permits == 0,
                parity == RECOVERY_QUALIFICATION_CASE_COUNT,
                wrong == RECOVERY_QUALIFICATION_WRONG_HYPOTHESIS_COUNT,
                wrong_decisions == 0,
                wrong_permits == 0,
                witness_valid == len(witnesses),
                len(restarts) == RECOVERY_QUALIFICATION_RESTART_COUNT,
                restart_valid == len(restarts),
            )
        )
        if self.safety_passed is not passed:
            raise ValueError("qualification safety outcome must be derived")
        return self


class RecoveryQualificationContentionTrial(StrictModel):
    backend: RecoveryQualificationStorageBackend
    permit_action: PermitAction
    contender_count: Literal[RECOVERY_QUALIFICATION_CONTENTION_WIDTH]
    winner_count: int = Field(ge=0, le=RECOVERY_QUALIFICATION_CONTENTION_WIDTH)
    denied_count: int = Field(ge=0, le=RECOVERY_QUALIFICATION_CONTENTION_WIDTH)
    outbound_call_count: int = Field(ge=0, le=RECOVERY_QUALIFICATION_CONTENTION_WIDTH)
    contender_claim_ids: tuple[Identifier, ...] = Field(
        min_length=RECOVERY_QUALIFICATION_CONTENTION_WIDTH,
        max_length=RECOVERY_QUALIFICATION_CONTENTION_WIDTH,
    )
    winner_claim_id: Identifier | None
    denied_claim_ids: tuple[Identifier, ...] = Field(
        max_length=RECOVERY_QUALIFICATION_CONTENTION_WIDTH,
    )
    provider_call_receipt_ids: tuple[Identifier, ...] = Field(max_length=1)
    final_permit: ActionPermit
    final_permit_sha256: Sha256Digest
    passed: bool

    @model_validator(mode="after")
    def validate_trial(self) -> RecoveryQualificationContentionTrial:
        if self.winner_count + self.denied_count != self.contender_count:
            raise ValueError("contention outcomes must partition contenders")
        if len(self.contender_claim_ids) != len(set(self.contender_claim_ids)):
            raise ValueError("contention claim identities must be unique")
        if (self.winner_claim_id is None) is not (self.winner_count == 0):
            raise ValueError("contention winner identity disagrees with winner count")
        winners = () if self.winner_claim_id is None else (self.winner_claim_id,)
        if (
            len(self.denied_claim_ids) != self.denied_count
            or len(self.denied_claim_ids) != len(set(self.denied_claim_ids))
            or set(winners).intersection(self.denied_claim_ids)
            or set((*winners, *self.denied_claim_ids))
            != set(self.contender_claim_ids)
        ):
            raise ValueError("contention identities must partition contenders")
        if self.outbound_call_count != len(self.provider_call_receipt_ids):
            raise ValueError("outbound calls require durable receipt identities")
        if (
            self.final_permit.state is not ActionPermitState.CLAIMED
            or self.final_permit.action is not self.permit_action
            or self.final_permit.claim_id != self.winner_claim_id
            or canonical_sha256(self.final_permit) != self.final_permit_sha256
        ):
            raise ValueError("contention final permit does not prove the winning claim")
        passed = self.winner_count == 1 and self.outbound_call_count <= 1
        if self.passed is not passed:
            raise ValueError("contention outcome must be derived")
        return self


class RecoveryQualificationContention(StrictModel):
    schema_version: Literal[RECOVERY_QUALIFICATION_CONTENTION_VERSION]
    bundle_format: Literal[RECOVERY_QUALIFICATION_BUNDLE_FORMAT]
    suite_id: Identifier
    manifest_sha256: Sha256Digest
    results_sha256: Sha256Digest
    trials: tuple[RecoveryQualificationContentionTrial, ...] = Field(
        min_length=4,
        max_length=4,
    )
    passed: bool

    @model_validator(mode="after")
    def validate_contention(self) -> RecoveryQualificationContention:
        expected = (
            (RecoveryQualificationStorageBackend.SQLITE, PermitAction.CONTINUE),
            (RecoveryQualificationStorageBackend.SQLITE, PermitAction.RETRY),
            (RecoveryQualificationStorageBackend.FIRESTORE, PermitAction.CONTINUE),
            (RecoveryQualificationStorageBackend.FIRESTORE, PermitAction.RETRY),
        )
        if tuple((item.backend, item.permit_action) for item in self.trials) != expected:
            raise ValueError("contention coverage or order changed")
        passed = all(item.passed for item in self.trials)
        if self.passed is not passed:
            raise ValueError("contention summary must be derived")
        return self


class RecoveryQualificationAggregateMetrics(StrictModel):
    policy: RecoveryQualificationPolicy
    lane_count: Literal[RECOVERY_QUALIFICATION_CASE_COUNT]
    total_probe_count: int = Field(ge=0, le=_MAX_SIGNED_64)
    median_probe_count_x2: int = Field(ge=0, le=_MAX_SIGNED_64)
    total_time_to_sufficient_evidence_ms: int = Field(ge=0, le=_MAX_SIGNED_64)
    median_time_to_sufficient_evidence_ms_x2: int = Field(
        ge=0,
        le=_MAX_SIGNED_64,
    )
    unsupported_probe_count: int = Field(ge=0, le=_MAX_SIGNED_64)
    resolved_count: int = Field(ge=0, le=RECOVERY_QUALIFICATION_CASE_COUNT)
    resolution_rate_basis_points: int = Field(ge=0, le=10_000)
    provider_mutation_count: int = Field(ge=0, le=_MAX_SIGNED_64)
    model_call_count: int = Field(ge=0, le=_MAX_SIGNED_64)
    input_token_count: int = Field(ge=0, le=_MAX_SIGNED_64)
    output_token_count: int = Field(ge=0, le=_MAX_SIGNED_64)
    total_token_count: int = Field(ge=0, le=_MAX_SIGNED_64)
    model_cost_nano_units: int = Field(ge=0, le=_MAX_SIGNED_64)

    @model_validator(mode="after")
    def validate_metrics(self) -> RecoveryQualificationAggregateMetrics:
        if self.resolution_rate_basis_points != self.resolved_count * 10_000 // 100:
            raise ValueError("resolution rate basis points must use integer division")
        if self.total_token_count != self.input_token_count + self.output_token_count:
            raise ValueError("aggregate token totals must be additive")
        return self


_MEDIAN_FORMULA = (
    "(fixed_median_probe_count_x2-adaptive_median_probe_count_x2)"
    "*10000//fixed_median_probe_count_x2"
)


class RecoveryQualificationComparison(StrictModel):
    schema_version: Literal[RECOVERY_QUALIFICATION_COMPARISON_VERSION]
    bundle_format: Literal[RECOVERY_QUALIFICATION_BUNDLE_FORMAT]
    suite_id: Identifier
    manifest_sha256: Sha256Digest
    environment_sha256: Sha256Digest
    results_sha256: Sha256Digest
    lanes: tuple[RecoveryQualificationAggregateMetrics, ...] = Field(
        min_length=4,
        max_length=4,
    )
    median_probe_reduction_formula: Literal[_MEDIAN_FORMULA]
    median_probe_reduction_basis_points: int = Field(
        ge=-_MAX_SIGNED_64,
        le=_MAX_SIGNED_64,
    )
    adaptive_efficiency_threshold_basis_points: Literal[
        RECOVERY_QUALIFICATION_ADAPTIVE_THRESHOLD_BASIS_POINTS
    ]
    adaptive_efficiency_threshold_met: bool
    execution_basis: RecoveryQualificationExecutionBasis
    live_vertex_model_usage_measured: bool

    @model_validator(mode="after")
    def validate_comparison(self) -> RecoveryQualificationComparison:
        if tuple(item.policy for item in self.lanes) != RECOVERY_QUALIFICATION_POLICIES:
            raise ValueError("comparison lane order changed")
        fixed = self.lanes[2].median_probe_count_x2
        adaptive = self.lanes[3].median_probe_count_x2
        reduction = 0 if fixed == 0 else (fixed - adaptive) * 10_000 // fixed
        if self.median_probe_reduction_basis_points != reduction:
            raise ValueError("median probe reduction must use the exact integer formula")
        met = reduction >= RECOVERY_QUALIFICATION_ADAPTIVE_THRESHOLD_BASIS_POINTS
        if self.adaptive_efficiency_threshold_met is not met:
            raise ValueError("adaptive efficiency threshold outcome must be derived")
        if self.execution_basis is RecoveryQualificationExecutionBasis.SCRIPTED and (
            self.live_vertex_model_usage_measured
        ):
            raise ValueError("scripted comparison cannot claim live Vertex usage")
        return self


class RecoveryQualificationClaimAuthorization(StrictModel):
    schema_version: Literal[RECOVERY_QUALIFICATION_CLAIM_AUTHORIZATION_VERSION]
    bundle_format: Literal[RECOVERY_QUALIFICATION_BUNDLE_FORMAT]
    suite_id: Identifier
    manifest_sha256: Sha256Digest
    environment_sha256: Sha256Digest
    results_sha256: Sha256Digest
    contention_sha256: Sha256Digest
    comparison_sha256: Sha256Digest
    safety_matrix_passed: bool
    contention_passed: bool
    source_revision_exact: bool
    false_permit_count: int = Field(ge=0, le=RECOVERY_QUALIFICATION_LANE_COUNT)
    replay_parity_case_count: int = Field(
        ge=0,
        le=RECOVERY_QUALIFICATION_CASE_COUNT,
    )
    wrong_hypothesis_divergence_count: int = Field(
        ge=0,
        le=RECOVERY_QUALIFICATION_WRONG_HYPOTHESIS_COUNT * 2,
    )
    execution_basis: RecoveryQualificationExecutionBasis
    live_vertex_backed: bool
    model_usage_measured: bool
    median_probe_reduction_basis_points: int
    adaptive_efficiency_threshold_basis_points: Literal[
        RECOVERY_QUALIFICATION_ADAPTIVE_THRESHOLD_BASIS_POINTS
    ]
    safety_claim_authorized: bool
    adaptive_efficiency_claim_authorized: bool
    authorized_claims: tuple[SanitizedText, ...] = Field(max_length=2)
    withheld_claims: tuple[SanitizedText, ...] = Field(max_length=2)

    @model_validator(mode="after")
    def validate_authorization(self) -> RecoveryQualificationClaimAuthorization:
        safety = all(
            (
                self.safety_matrix_passed,
                self.contention_passed,
                self.source_revision_exact,
                self.false_permit_count == 0,
                self.replay_parity_case_count
                == RECOVERY_QUALIFICATION_CASE_COUNT,
                self.wrong_hypothesis_divergence_count == 0,
            )
        )
        efficiency = all(
            (
                safety,
                self.execution_basis
                is RecoveryQualificationExecutionBasis.LIVE_VERTEX,
                self.live_vertex_backed,
                self.model_usage_measured,
                self.median_probe_reduction_basis_points
                >= self.adaptive_efficiency_threshold_basis_points,
            )
        )
        if (
            self.safety_claim_authorized is not safety
            or self.adaptive_efficiency_claim_authorized is not efficiency
        ):
            raise ValueError("claim authorization must be derived from evidence")
        safety_wording = "proof-to-permit safety on the frozen recovery matrix"
        efficiency_wording = (
            "adaptive investigation reduced median probe count by at least 25 percent"
        )
        expected_authorized = tuple(
            wording
            for allowed, wording in (
                (safety, safety_wording),
                (efficiency, efficiency_wording),
            )
            if allowed
        )
        expected_withheld = tuple(
            wording
            for allowed, wording in (
                (safety, safety_wording),
                (efficiency, efficiency_wording),
            )
            if not allowed
        )
        if (
            self.authorized_claims != expected_authorized
            or self.withheld_claims != expected_withheld
        ):
            raise ValueError("claim wording does not match its authorization")
        return self


class RecoveryQualificationArtifactIdentity(StrictModel):
    filename: Literal[
        "manifest.json",
        "environment.json",
        "results.json",
        "contention.json",
        "comparison.json",
        "claim-authorization.json",
    ]
    sha256: Sha256Digest
    byte_count: int = Field(ge=1, le=_MAX_SIGNED_64)


class RecoveryQualificationIndex(StrictModel):
    schema_version: Literal[RECOVERY_QUALIFICATION_INDEX_VERSION]
    bundle_format: Literal[RECOVERY_QUALIFICATION_BUNDLE_FORMAT]
    suite_id: Identifier
    source_revision: Identifier
    source_tree_sha256: Sha256Digest
    artifacts: tuple[RecoveryQualificationArtifactIdentity, ...] = Field(
        min_length=6,
        max_length=6,
    )
    safety_claim_authorized: bool
    adaptive_efficiency_claim_authorized: bool
    created_at: AwareDatetime

    @model_validator(mode="after")
    def validate_index(self) -> RecoveryQualificationIndex:
        expected = (
            "manifest.json",
            "environment.json",
            "results.json",
            "contention.json",
            "comparison.json",
            "claim-authorization.json",
        )
        if tuple(item.filename for item in self.artifacts) != expected:
            raise ValueError("recovery qualification index order changed")
        return self


__all__ = [
    "RECOVERY_QUALIFICATION_ADAPTIVE_THRESHOLD_BASIS_POINTS",
    "RECOVERY_QUALIFICATION_BUNDLE_FORMAT",
    "RECOVERY_QUALIFICATION_CASE_COUNT",
    "RECOVERY_QUALIFICATION_CLAIM_AUTHORIZATION_VERSION",
    "RECOVERY_QUALIFICATION_COMPARISON_VERSION",
    "RECOVERY_QUALIFICATION_CONTENTION_VERSION",
    "RECOVERY_QUALIFICATION_CONTENTION_WIDTH",
    "RECOVERY_QUALIFICATION_ENVIRONMENT_VERSION",
    "RECOVERY_QUALIFICATION_FIXTURE_CATALOG_SHA256",
    "RECOVERY_QUALIFICATION_INDEX_VERSION",
    "RECOVERY_QUALIFICATION_LANE_COUNT",
    "RECOVERY_QUALIFICATION_MANIFEST_VERSION",
    "RECOVERY_QUALIFICATION_POLICIES",
    "RECOVERY_QUALIFICATION_RESTART_COUNT",
    "RECOVERY_QUALIFICATION_RESULTS_VERSION",
    "RECOVERY_QUALIFICATION_SEEDS",
    "RECOVERY_QUALIFICATION_WRONG_HYPOTHESIS_COUNT",
    "RecoveryQualificationAggregateMetrics",
    "RecoveryQualificationArchetype",
    "RecoveryQualificationArtifactIdentity",
    "RecoveryQualificationCaseProof",
    "RecoveryQualificationClaimAuthorization",
    "RecoveryQualificationComparison",
    "RecoveryQualificationContention",
    "RecoveryQualificationContentionTrial",
    "RecoveryQualificationEnvironment",
    "RecoveryQualificationExecutionBasis",
    "RecoveryQualificationFaultClass",
    "RecoveryQualificationHypothesisReplay",
    "RecoveryQualificationIndex",
    "RecoveryQualificationLaneResult",
    "RecoveryQualificationManifest",
    "RecoveryQualificationModelUsage",
    "RecoveryQualificationModelUsageStatus",
    "RecoveryQualificationOpportunity",
    "RecoveryQualificationPermitCoverage",
    "RecoveryQualificationPolicy",
    "RecoveryQualificationProviderMutations",
    "RecoveryQualificationResolution",
    "RecoveryQualificationResults",
    "RecoveryQualificationStage",
    "RecoveryQualificationStorageBackend",
]
