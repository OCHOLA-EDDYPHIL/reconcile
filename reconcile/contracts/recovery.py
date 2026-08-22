"""Contracts for proof-scoped recovery and single-use action authority."""

from __future__ import annotations

import hashlib
from enum import StrEnum
from typing import Literal

from pydantic import Field, model_validator

from reconcile.contracts.base import (
    ArgumentsObject,
    AwareDatetime,
    Identifier,
    SanitizedText,
    Sha256Digest,
    StrictModel,
    canonical_json_value_bytes,
    reject_sensitive_keys,
    reject_sensitive_values,
)
from reconcile.contracts.codec import canonical_sha256
from reconcile.contracts.common import Classification, TargetBinding
from reconcile.contracts.envelope import ProbeRequest
from reconcile.contracts.evidence import EffectAssertionState

RECOVERY_CHAIN_VERSION = "reconcile/recovery-chain/v1"
GEMINI_HYPOTHESIS_VERSION = "reconcile/gemini-hypothesis/v1"
VERIFIED_CERTIFICATE_VERSION = "reconcile/verified-certificate/v1"
AMBIGUITY_WITNESS_VERSION = "reconcile/ambiguity-witness/v1"
ACTION_PERMIT_VERSION = "reconcile/action-permit/v1"


def _require_unique(values: tuple[object, ...], label: str) -> None:
    if len(values) != len(set(values)):
        raise ValueError(f"{label} must be unique")


def semantic_action_sha256(
    *,
    key_version: str,
    tool_name: str,
    tool_version: str,
    semantic_arguments: ArgumentsObject,
    target: TargetBinding,
    expected_effect_sha256s: tuple[str, ...],
    action_profile_version: str,
) -> str:
    """Hash only trusted semantic fields, excluding dispatch-local identifiers."""

    value = {
        "action_profile_version": action_profile_version,
        "expected_effect_sha256s": list(expected_effect_sha256s),
        "key_version": key_version,
        "semantic_arguments": semantic_arguments,
        "target": target.model_dump(mode="json"),
        "tool_name": tool_name,
        "tool_version": tool_version,
    }
    return hashlib.sha256(canonical_json_value_bytes(value)).hexdigest()


class PermitAction(StrEnum):
    CONTINUE = "CONTINUE"
    RETRY = "RETRY"


class ActionPermitState(StrEnum):
    ISSUED = "ISSUED"
    CLAIMED = "CLAIMED"
    COMPLETED = "COMPLETED"
    EXPIRED = "EXPIRED"


class PermitCompletionOutcome(StrEnum):
    SUCCEEDED = "SUCCEEDED"
    REJECTED = "REJECTED"
    OUTCOME_UNKNOWN = "OUTCOME_UNKNOWN"


class ExecutionEnvelopeReference(StrictModel):
    investigation_id: Identifier
    operation_id: Identifier
    envelope_sha256: Sha256Digest


class SemanticActionIdentity(StrictModel):
    key_version: Identifier
    tool_name: Identifier
    tool_version: Identifier
    semantic_arguments: ArgumentsObject = Field(default_factory=dict)
    target: TargetBinding
    expected_effect_sha256s: tuple[Sha256Digest, ...] = Field(
        min_length=1,
        max_length=64,
    )
    action_profile_version: Identifier
    semantic_action_sha256: Sha256Digest

    @model_validator(mode="after")
    def validate_identity(self) -> SemanticActionIdentity:
        reject_sensitive_keys(self.semantic_arguments)
        reject_sensitive_values(self.semantic_arguments)
        _require_unique(
            self.expected_effect_sha256s,
            "semantic action effect digests",
        )
        expected = semantic_action_sha256(
            key_version=self.key_version,
            tool_name=self.tool_name,
            tool_version=self.tool_version,
            semantic_arguments=self.semantic_arguments,
            target=self.target,
            expected_effect_sha256s=self.expected_effect_sha256s,
            action_profile_version=self.action_profile_version,
        )
        if expected != self.semantic_action_sha256:
            raise ValueError("semantic action digest does not match its trusted fields")
        return self


class RecoveryActionNode(StrictModel):
    node_id: Identifier
    chain_profile_version: Identifier
    semantic_action: SemanticActionIdentity
    depends_on: tuple[Identifier, ...] = Field(default_factory=tuple, max_length=32)
    envelope: ExecutionEnvelopeReference

    @model_validator(mode="after")
    def validate_dependencies(self) -> RecoveryActionNode:
        _require_unique(self.depends_on, "node dependencies")
        if self.node_id in self.depends_on:
            raise ValueError("a recovery node cannot depend on itself")
        return self


class RecoveryChain(StrictModel):
    schema_version: Literal[RECOVERY_CHAIN_VERSION]
    chain_id: Identifier
    chain_profile_version: Identifier
    nodes: tuple[RecoveryActionNode, ...] = Field(min_length=1, max_length=32)
    created_at: AwareDatetime

    @model_validator(mode="after")
    def validate_graph(self) -> RecoveryChain:
        node_ids = tuple(node.node_id for node in self.nodes)
        _require_unique(node_ids, "recovery node identifiers")
        semantic_keys = tuple(
            node.semantic_action.semantic_action_sha256 for node in self.nodes
        )
        _require_unique(semantic_keys, "recovery semantic action keys")
        envelope_refs = tuple(
            (
                node.envelope.investigation_id,
                node.envelope.operation_id,
                node.envelope.envelope_sha256,
            )
            for node in self.nodes
        )
        _require_unique(envelope_refs, "recovery envelope references")
        if any(
            node.chain_profile_version != self.chain_profile_version
            for node in self.nodes
        ):
            raise ValueError("node chain profile versions must match the chain")

        known = set(node_ids)
        if any(
            dependency not in known
            for node in self.nodes
            for dependency in node.depends_on
        ):
            raise ValueError("recovery node references a missing dependency")

        dependencies = {node.node_id: set(node.depends_on) for node in self.nodes}
        visiting: set[str] = set()
        visited: set[str] = set()

        def visit(node_id: str) -> None:
            if node_id in visiting:
                raise ValueError("recovery chain must be acyclic")
            if node_id in visited:
                return
            visiting.add(node_id)
            for dependency in dependencies[node_id]:
                visit(dependency)
            visiting.remove(node_id)
            visited.add(node_id)

        for node_id in node_ids:
            visit(node_id)
        return self


class HypothesizedEffect(StrictModel):
    effect_id: Identifier
    state: EffectAssertionState
    cited_evidence_ids: tuple[Identifier, ...] = Field(
        default_factory=tuple,
        max_length=64,
    )

    @model_validator(mode="after")
    def validate_citations(self) -> HypothesizedEffect:
        _require_unique(self.cited_evidence_ids, "effect hypothesis citations")
        return self


class PossibleHistory(StrictModel):
    history_id: Identifier
    classification: Classification
    effect_states: tuple[HypothesizedEffect, ...] = Field(
        min_length=1,
        max_length=64,
    )
    compatible_evidence_ids: tuple[Identifier, ...] = Field(
        default_factory=tuple,
        max_length=64,
    )
    summary: SanitizedText

    @model_validator(mode="after")
    def validate_history(self) -> PossibleHistory:
        _require_unique(
            tuple(effect.effect_id for effect in self.effect_states),
            "history effect identifiers",
        )
        _require_unique(
            self.compatible_evidence_ids,
            "history evidence identifiers",
        )
        return self


class HypothesisMissingEvidence(StrictModel):
    effect_ids: tuple[Identifier, ...] = Field(min_length=1, max_length=64)
    reason: SanitizedText

    @model_validator(mode="after")
    def validate_effects(self) -> HypothesisMissingEvidence:
        _require_unique(self.effect_ids, "missing-evidence effect identifiers")
        return self


class ProposedTransition(StrictModel):
    action: PermitAction
    source_node_id: Identifier
    target_node_id: Identifier
    rationale: SanitizedText

    @model_validator(mode="after")
    def validate_target(self) -> ProposedTransition:
        if (
            self.action is PermitAction.RETRY
            and self.target_node_id != self.source_node_id
        ):
            raise ValueError("a retry proposal must target its source node")
        if (
            self.action is PermitAction.CONTINUE
            and self.target_node_id == self.source_node_id
        ):
            raise ValueError("a continuation proposal must target a successor node")
        return self


class GeminiHypothesis(StrictModel):
    schema_version: Literal[GEMINI_HYPOTHESIS_VERSION]
    hypothesis_id: Identifier
    chain_id: Identifier
    node_id: Identifier
    semantic_action_sha256: Sha256Digest
    report_sha256: Sha256Digest
    proposed_classification: Classification
    effect_hypotheses: tuple[HypothesizedEffect, ...] = Field(
        min_length=1,
        max_length=64,
    )
    cited_evidence_ids: tuple[Identifier, ...] = Field(
        default_factory=tuple,
        max_length=64,
    )
    confidence_basis_points: int = Field(ge=0, le=10_000)
    alternative_histories: tuple[PossibleHistory, ...] = Field(
        default_factory=tuple,
        max_length=8,
    )
    missing_evidence: tuple[HypothesisMissingEvidence, ...] = Field(
        default_factory=tuple,
        max_length=64,
    )
    proposed_probe: ProbeRequest | None = None
    proposed_transition: ProposedTransition | None = None
    explanation: SanitizedText
    created_at: AwareDatetime

    @model_validator(mode="after")
    def validate_hypothesis(self) -> GeminiHypothesis:
        _require_unique(
            tuple(effect.effect_id for effect in self.effect_hypotheses),
            "hypothesis effect identifiers",
        )
        _require_unique(self.cited_evidence_ids, "hypothesis evidence citations")
        _require_unique(
            tuple(history.history_id for history in self.alternative_histories),
            "alternative history identifiers",
        )
        _require_unique(
            tuple(
                effect_id
                for missing in self.missing_evidence
                for effect_id in missing.effect_ids
            ),
            "missing-evidence effect identifiers",
        )
        if self.proposed_probe is not None and self.proposed_transition is not None:
            raise ValueError(
                "a hypothesis may propose one probe or one action, not both"
            )
        cited = set(self.cited_evidence_ids)
        referenced = {
            evidence_id
            for effect in self.effect_hypotheses
            for evidence_id in effect.cited_evidence_ids
        }
        referenced.update(
            evidence_id
            for history in self.alternative_histories
            for evidence_id in history.compatible_evidence_ids
        )
        if not referenced <= cited:
            raise ValueError("hypothesis details cite undeclared evidence")
        if not cited and not self.missing_evidence:
            raise ValueError(
                "a hypothesis requires evidence citations or missing evidence"
            )
        if (
            self.proposed_transition is not None
            and self.proposed_transition.source_node_id != self.node_id
        ):
            raise ValueError("a proposed transition must start at the bound node")
        known_effects = {effect.effect_id for effect in self.effect_hypotheses}
        if (
            self.proposed_probe is not None
            and not set(self.proposed_probe.relevant_effect_ids) <= known_effects
        ):
            raise ValueError("a proposed probe references an unknown effect")
        return self


class RecoveryEvidenceBinding(StrictModel):
    evidence_id: Identifier
    evidence_sha256: Sha256Digest
    raw_observation_sha256: Sha256Digest
    valid_until: AwareDatetime


class CertifiedTransition(StrictModel):
    action: PermitAction
    source_node_id: Identifier
    target_node_id: Identifier
    semantic_action_sha256: Sha256Digest
    tool_name: Identifier
    tool_version: Identifier
    arguments_sha256: Sha256Digest
    target_sha256: Sha256Digest
    precondition_sha256: Sha256Digest

    @model_validator(mode="after")
    def validate_target(self) -> CertifiedTransition:
        if (
            self.action is PermitAction.RETRY
            and self.target_node_id != self.source_node_id
        ):
            raise ValueError("a retry transition must target its source node")
        if (
            self.action is PermitAction.CONTINUE
            and self.target_node_id == self.source_node_id
        ):
            raise ValueError("a continuation transition must target a successor node")
        return self


class VerifiedCertificate(StrictModel):
    schema_version: Literal[VERIFIED_CERTIFICATE_VERSION]
    certificate_id: Identifier
    chain_id: Identifier
    node_id: Identifier
    semantic_action_sha256: Sha256Digest
    chain_sha256: Sha256Digest
    node_sha256: Sha256Digest
    envelope_sha256: Sha256Digest
    report_sha256: Sha256Digest
    proof_sha256: Sha256Digest
    target: TargetBinding
    target_sha256: Sha256Digest
    evidence: tuple[RecoveryEvidenceBinding, ...] = Field(
        min_length=1,
        max_length=64,
    )
    authority_satisfied: Literal[True]
    correlation_satisfied: Literal[True]
    freshness_satisfied: Literal[True]
    authority_policy_version: Identifier
    correlation_policy_version: Identifier
    freshness_policy_version: Identifier
    classification_policy_version: Identifier
    action_policy_version: Identifier
    action_profile_version: Identifier
    verifier_version: Identifier
    classification: Classification
    transition: CertifiedTransition | None
    issued_at: AwareDatetime
    expires_at: AwareDatetime

    @model_validator(mode="after")
    def validate_certificate(self) -> VerifiedCertificate:
        if self.target_sha256 != canonical_sha256(self.target):
            raise ValueError("certificate target digest does not match its target")
        if self.expires_at <= self.issued_at:
            raise ValueError("certificate validity interval must be nonempty")
        _require_unique(
            tuple(binding.evidence_id for binding in self.evidence),
            "certificate evidence identifiers",
        )
        _require_unique(
            tuple(binding.evidence_sha256 for binding in self.evidence),
            "certificate evidence digests",
        )
        if self.evidence and self.expires_at > min(
            binding.valid_until for binding in self.evidence
        ):
            raise ValueError("certificate outlives supporting evidence")
        if self.classification is Classification.UNKNOWN:
            raise ValueError("UNKNOWN requires an ambiguity witness")
        if self.transition is not None:
            if self.transition.source_node_id != self.node_id:
                raise ValueError("certificate transition must start at the bound node")
            expected = {
                Classification.COMMITTED: PermitAction.CONTINUE,
                Classification.NOT_COMMITTED: PermitAction.RETRY,
            }.get(self.classification)
            if expected is None or self.transition.action is not expected:
                raise ValueError("classification cannot authorize this transition")
        return self


class DiscriminatingObservation(StrictModel):
    observation_id: Identifier
    description: SanitizedText
    capability_name: Identifier | None = None
    capability_version: Identifier | None = None
    relevant_effect_ids: tuple[Identifier, ...] = Field(
        default_factory=tuple,
        max_length=64,
    )
    distinguishes_history_ids: tuple[Identifier, ...] = Field(
        min_length=2,
        max_length=8,
    )

    @model_validator(mode="after")
    def validate_observation(self) -> DiscriminatingObservation:
        if (self.capability_name is None) is not (self.capability_version is None):
            raise ValueError("discriminating capability identity must be complete")
        _require_unique(self.relevant_effect_ids, "discriminating effect identifiers")
        _require_unique(
            self.distinguishes_history_ids,
            "distinguished history identifiers",
        )
        return self


class AmbiguityWitness(StrictModel):
    schema_version: Literal[AMBIGUITY_WITNESS_VERSION]
    witness_id: Identifier
    chain_id: Identifier
    node_id: Identifier
    semantic_action_sha256: Sha256Digest
    chain_sha256: Sha256Digest
    node_sha256: Sha256Digest
    envelope_sha256: Sha256Digest
    report_sha256: Sha256Digest
    proof_sha256: Sha256Digest
    target: TargetBinding
    target_sha256: Sha256Digest
    evidence: tuple[RecoveryEvidenceBinding, ...] = Field(
        default_factory=tuple,
        max_length=64,
    )
    possible_histories: tuple[PossibleHistory, ...] = Field(min_length=2, max_length=8)
    discriminating_observations: tuple[DiscriminatingObservation, ...] = Field(
        min_length=1,
        max_length=8,
    )
    conflicting_evidence_ids: tuple[Identifier, ...] = Field(
        default_factory=tuple,
        max_length=64,
    )
    verifier_version: Identifier
    created_at: AwareDatetime

    @model_validator(mode="after")
    def validate_witness(self) -> AmbiguityWitness:
        if self.target_sha256 != canonical_sha256(self.target):
            raise ValueError("witness target digest does not match its target")
        evidence_ids = tuple(binding.evidence_id for binding in self.evidence)
        _require_unique(evidence_ids, "witness evidence identifiers")
        history_ids = tuple(history.history_id for history in self.possible_histories)
        _require_unique(history_ids, "possible history identifiers")
        signatures = tuple(
            (
                history.classification,
                tuple(
                    (effect.effect_id, effect.state) for effect in history.effect_states
                ),
            )
            for history in self.possible_histories
        )
        _require_unique(signatures, "possible history outcomes")
        known_evidence = set(evidence_ids)
        if any(
            not set(history.compatible_evidence_ids) <= known_evidence
            for history in self.possible_histories
        ):
            raise ValueError("possible history references unknown evidence")
        if not set(self.conflicting_evidence_ids) <= known_evidence:
            raise ValueError("conflict set references unknown evidence")
        _require_unique(
            self.conflicting_evidence_ids, "conflicting evidence identifiers"
        )
        known_histories = set(history_ids)
        for observation in self.discriminating_observations:
            if not set(observation.distinguishes_history_ids) <= known_histories:
                raise ValueError(
                    "discriminating observation references unknown history"
                )
        return self


class ActionPermit(StrictModel):
    schema_version: Literal[ACTION_PERMIT_VERSION]
    permit_id: Identifier
    certificate_id: Identifier
    certificate_sha256: Sha256Digest
    chain_id: Identifier
    source_node_id: Identifier
    target_node_id: Identifier
    semantic_action_sha256: Sha256Digest
    action: PermitAction
    action_profile_version: Identifier
    action_policy_version: Identifier
    tool_name: Identifier
    tool_version: Identifier
    arguments_sha256: Sha256Digest
    target_sha256: Sha256Digest
    precondition_sha256: Sha256Digest
    issued_at: AwareDatetime
    expires_at: AwareDatetime
    max_uses: Literal[1]
    state: ActionPermitState
    revision: int = Field(ge=0, le=2**63 - 1)
    claim_id: Identifier | None = None
    claimed_at: AwareDatetime | None = None
    completed_at: AwareDatetime | None = None
    completion_outcome: PermitCompletionOutcome | None = None
    expired_at: AwareDatetime | None = None

    @model_validator(mode="after")
    def validate_lifecycle(self) -> ActionPermit:
        if self.expires_at <= self.issued_at:
            raise ValueError("permit validity interval must be nonempty")
        if (
            self.action is PermitAction.RETRY
            and self.target_node_id != self.source_node_id
        ):
            raise ValueError("a retry permit must target its source node")
        if (
            self.action is PermitAction.CONTINUE
            and self.target_node_id == self.source_node_id
        ):
            raise ValueError("a continuation permit must target a successor node")

        claim_fields = (self.claim_id, self.claimed_at)
        completion_fields = (self.completed_at, self.completion_outcome)
        if self.state is ActionPermitState.ISSUED:
            valid = (
                self.revision == 0
                and all(item is None for item in claim_fields + completion_fields)
                and self.expired_at is None
            )
        elif self.state is ActionPermitState.CLAIMED:
            valid = (
                self.revision == 1
                and all(item is not None for item in claim_fields)
                and all(item is None for item in completion_fields)
                and self.expired_at is None
            )
        elif self.state is ActionPermitState.COMPLETED:
            valid = (
                self.revision == 2
                and all(item is not None for item in claim_fields + completion_fields)
                and self.expired_at is None
            )
        else:
            valid = (
                self.revision == 1
                and all(item is None for item in claim_fields + completion_fields)
                and self.expired_at is not None
            )
        if not valid:
            raise ValueError("permit fields do not match its lifecycle state")
        if self.claimed_at is not None and not (
            self.issued_at <= self.claimed_at < self.expires_at
        ):
            raise ValueError("permit claim must occur inside its validity interval")
        if (
            self.completed_at is not None
            and self.claimed_at is not None
            and self.completed_at < self.claimed_at
        ):
            raise ValueError("permit completion cannot precede its claim")
        if self.expired_at is not None and self.expired_at < self.expires_at:
            raise ValueError("permit cannot expire before its validity ends")
        return self


__all__ = [
    "ACTION_PERMIT_VERSION",
    "AMBIGUITY_WITNESS_VERSION",
    "GEMINI_HYPOTHESIS_VERSION",
    "RECOVERY_CHAIN_VERSION",
    "VERIFIED_CERTIFICATE_VERSION",
    "ActionPermit",
    "ActionPermitState",
    "AmbiguityWitness",
    "CertifiedTransition",
    "DiscriminatingObservation",
    "ExecutionEnvelopeReference",
    "GeminiHypothesis",
    "HypothesisMissingEvidence",
    "HypothesizedEffect",
    "PermitAction",
    "PermitCompletionOutcome",
    "PossibleHistory",
    "ProposedTransition",
    "RecoveryActionNode",
    "RecoveryChain",
    "RecoveryEvidenceBinding",
    "SemanticActionIdentity",
    "VerifiedCertificate",
    "semantic_action_sha256",
]
