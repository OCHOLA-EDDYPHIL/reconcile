"""Public contracts for one durable proof-to-permit recovery run."""

from __future__ import annotations

import hashlib
from enum import StrEnum
from typing import Literal

from pydantic import ConfigDict, Field, model_validator

from reconcile.contracts.base import (
    ArgumentsObject,
    AwareDatetime,
    Identifier,
    NonEmptySmallJsonObject,
    SanitizedText,
    Sha256Digest,
    StrictModel,
    canonical_json_value_bytes,
    reject_sensitive_keys,
    reject_sensitive_values,
)
from reconcile.contracts.codec import canonical_sha256
from reconcile.contracts.common import Classification, TargetBinding
from reconcile.contracts.recovery import (
    ActionPermit,
    AmbiguityWitness,
    GeminiHypothesis,
    PermitAction,
    RecoveryChain,
    VerifiedCertificate,
)
from reconcile.contracts.report import InvestigationReport

RECOVERY_RUN_REQUEST_VERSION = "reconcile/recovery-run-request/v1"
RECOVERY_RUN_SNAPSHOT_VERSION = "reconcile/recovery-run-snapshot/v1"
RECOVERY_RUN_EVENT_VERSION = "reconcile/recovery-run-event/v1"
RECOVERY_LAUNCH_PERMIT_VERSION = "reconcile/recovery-launch-permit/v1"
RECOVERY_PREPARED_ACTION_VERSION = "reconcile/recovery-prepared-action/v1"
RECOVERY_ACTION_SCOPE_VERSION = "reconcile/recovery-action-scope/v2"

MAX_RECOVERY_RUN_EVENTS = 512


class RecoveryRunPolicy(StrEnum):
    BLIND_RETRY = "blind-retry"
    BLIND_ABORT = "blind-abort"
    FIXED = "fixed"
    ADAPTIVE = "adaptive"


class RecoveryRunFault(StrEnum):
    DROP_AFTER_ACCEPT = "drop-after-accept"
    SUPPRESS_BEFORE_DISPATCH = "suppress-before-dispatch"


class RecoveryRunLifecycle(StrEnum):
    ACCEPTED = "ACCEPTED"
    RUNNING = "RUNNING"
    COMPLETED = "COMPLETED"
    ESCALATED = "ESCALATED"
    FAILED = "FAILED"
    CANCELLED = "CANCELLED"


class RecoveryNodeState(StrEnum):
    WAITING = "WAITING"
    DISPATCH_PENDING = "DISPATCH_PENDING"
    DISPATCH_CLAIMED = "DISPATCH_CLAIMED"
    RECONCILING = "RECONCILING"
    VERIFIED = "VERIFIED"
    PERMITTED = "PERMITTED"
    COMPLETED = "COMPLETED"
    ESCALATED = "ESCALATED"


class RecoveryDecision(StrEnum):
    CONTINUE = "CONTINUE"
    RETRY = "RETRY"
    OBSERVE = "OBSERVE"
    ESCALATE = "ESCALATE"


class RecoveryHypothesisDisposition(StrEnum):
    SELECTED = "SELECTED"
    NO_PROBE = "NO_PROBE"
    DUPLICATE_PROBE = "DUPLICATE_PROBE"
    BUDGET_EXHAUSTED = "BUDGET_EXHAUSTED"
    UNSUPPORTED_PROBE = "UNSUPPORTED_PROBE"
    UNSUPPORTED_ACTION = "UNSUPPORTED_ACTION"
    INVALID_BINDING = "INVALID_BINDING"
    MODEL_UNAVAILABLE = "MODEL_UNAVAILABLE"
    MODEL_TIMEOUT = "MODEL_TIMEOUT"
    MALFORMED_MODEL_OUTPUT = "MALFORMED_MODEL_OUTPUT"
    FIXED_FALLBACK = "FIXED_FALLBACK"


class RecoveryRunFailureCategory(StrEnum):
    CANCELLED = "cancelled"
    INVALID_DEFINITION = "invalid_definition"
    MODEL_UNAVAILABLE = "model_unavailable"
    EVIDENCE_UNAVAILABLE = "evidence_unavailable"
    DISPATCH_UNAVAILABLE = "dispatch_unavailable"
    DURABLE_STATE_UNAVAILABLE = "durable_state_unavailable"
    INTERNAL_FAILURE = "internal_failure"


class RecoveryLaunchPermitState(StrEnum):
    ISSUED = "ISSUED"
    CLAIMED = "CLAIMED"
    COMPLETED = "COMPLETED"


class RecoveryDispatchOutcome(StrEnum):
    SUCCEEDED = "SUCCEEDED"
    REJECTED = "REJECTED"
    OUTCOME_UNKNOWN = "OUTCOME_UNKNOWN"


class RecoveryAuthorityKind(StrEnum):
    LAUNCH_PERMIT = "LAUNCH_PERMIT"
    ACTION_PERMIT = "ACTION_PERMIT"


class RecoveryRunRequest(StrictModel):
    schema_version: Literal[RECOVERY_RUN_REQUEST_VERSION]
    run_id: Identifier
    scenario: Literal["cloud-run-rollout"] = "cloud-run-rollout"
    policy: RecoveryRunPolicy
    fault: RecoveryRunFault


class RecoveryNodeProgress(StrictModel):
    node_id: Identifier
    state: RecoveryNodeState
    attempt: int = Field(ge=0, le=2)


class RecoveryLaunchPermit(StrictModel):
    """One-shot authority for the first mutation, before a certificate exists."""

    schema_version: Literal[RECOVERY_LAUNCH_PERMIT_VERSION]
    launch_permit_id: Identifier
    run_id: Identifier
    node_id: Identifier
    semantic_action_sha256: Sha256Digest
    action_request_sha256: Sha256Digest
    issued_at: AwareDatetime
    state: RecoveryLaunchPermitState
    revision: int = Field(ge=0, le=2)
    claim_id: Identifier | None = None
    claimed_at: AwareDatetime | None = None
    completed_at: AwareDatetime | None = None
    outcome: RecoveryDispatchOutcome | None = None

    @model_validator(mode="after")
    def validate_lifecycle(self) -> RecoveryLaunchPermit:
        if self.state is RecoveryLaunchPermitState.ISSUED:
            valid = (
                self.revision == 0
                and self.claim_id is None
                and self.claimed_at is None
                and self.completed_at is None
                and self.outcome is None
            )
        elif self.state is RecoveryLaunchPermitState.CLAIMED:
            valid = (
                self.revision == 1
                and self.claim_id is not None
                and self.claimed_at is not None
                and self.completed_at is None
                and self.outcome is None
            )
        else:
            valid = (
                self.revision == 2
                and self.claim_id is not None
                and self.claimed_at is not None
                and self.completed_at is not None
                and self.outcome is not None
                and self.completed_at >= self.claimed_at
            )
        if not valid:
            raise ValueError("launch permit fields do not match lifecycle state")
        return self


class RecoveryPreparedAction(StrictModel):
    """Exact secret-free mutation material prepared from certified evidence."""

    schema_version: Literal[RECOVERY_PREPARED_ACTION_VERSION]
    authority_kind: RecoveryAuthorityKind
    run_id: Identifier
    chain_id: Identifier
    source_node_id: Identifier
    target_node_id: Identifier
    semantic_action_sha256: Sha256Digest
    tool_name: Identifier
    tool_version: Identifier
    arguments: ArgumentsObject
    arguments_sha256: Sha256Digest
    target: TargetBinding
    target_sha256: Sha256Digest
    precondition: NonEmptySmallJsonObject
    precondition_sha256: Sha256Digest
    request_payload: NonEmptySmallJsonObject
    action_request_sha256: Sha256Digest
    permit_action: PermitAction | None = None
    report_sha256: Sha256Digest | None = None
    certificate_id: Identifier | None = None
    certificate_sha256: Sha256Digest | None = None

    @model_validator(mode="after")
    def validate_bindings(self) -> RecoveryPreparedAction:
        for value in (self.arguments, self.precondition, self.request_payload):
            reject_sensitive_keys(value)
            reject_sensitive_values(value)
        digests = (
            (
                self.arguments_sha256,
                hashlib.sha256(canonical_json_value_bytes(self.arguments)).hexdigest(),
            ),
            (self.target_sha256, canonical_sha256(self.target)),
            (
                self.precondition_sha256,
                hashlib.sha256(
                    canonical_json_value_bytes(self.precondition)
                ).hexdigest(),
            ),
            (
                self.action_request_sha256,
                hashlib.sha256(
                    canonical_json_value_bytes(self.request_payload)
                ).hexdigest(),
            ),
        )
        if any(actual != expected for actual, expected in digests):
            raise ValueError("prepared recovery action digest does not match its value")

        proof_fields = (
            self.report_sha256,
            self.certificate_id,
            self.certificate_sha256,
        )
        if self.authority_kind is RecoveryAuthorityKind.LAUNCH_PERMIT:
            valid = (
                self.source_node_id == self.target_node_id
                and self.permit_action is None
                and all(value is None for value in proof_fields)
            )
        else:
            valid = (
                self.permit_action is not None
                and all(value is not None for value in proof_fields)
                and (
                    (
                        self.permit_action is PermitAction.RETRY
                        and self.source_node_id == self.target_node_id
                    )
                    or (
                        self.permit_action is PermitAction.CONTINUE
                        and self.source_node_id != self.target_node_id
                    )
                )
            )
        if not valid:
            raise ValueError("prepared recovery action authority is inconsistent")
        return self


class RecoveryActionScope(StrictModel):
    """Recovery-specific dispatch identity carried to the mutation boundary."""

    schema_version: Literal[RECOVERY_ACTION_SCOPE_VERSION]
    authority_kind: RecoveryAuthorityKind
    run_id: Identifier
    source_node_id: Identifier
    target_node_id: Identifier
    semantic_action_sha256: Sha256Digest
    action_request_sha256: Sha256Digest
    authority_id: Identifier
    authority_sha256: Sha256Digest
    claim_id: Identifier
    permit_action: PermitAction | None = None
    certificate_id: Identifier | None = None
    certificate_sha256: Sha256Digest | None = None

    @model_validator(mode="after")
    def validate_authority(self) -> RecoveryActionScope:
        certificate_fields = (self.certificate_id, self.certificate_sha256)
        if self.authority_kind is RecoveryAuthorityKind.LAUNCH_PERMIT:
            valid = (
                self.source_node_id == self.target_node_id
                and self.permit_action is None
                and all(value is None for value in certificate_fields)
            )
        else:
            valid = (
                self.permit_action is not None
                and all(value is not None for value in certificate_fields)
                and (
                    (
                        self.permit_action is PermitAction.RETRY
                        and self.source_node_id == self.target_node_id
                    )
                    or (
                        self.permit_action is PermitAction.CONTINUE
                        and self.source_node_id != self.target_node_id
                    )
                )
            )
        if not valid:
            raise ValueError("recovery action scope authority fields are inconsistent")
        return self


class RecoveryRunEventType(StrEnum):
    LIFECYCLE = "LIFECYCLE"
    CHAIN = "CHAIN"
    NODE = "NODE"
    HYPOTHESIS = "HYPOTHESIS"
    EVIDENCE = "EVIDENCE"
    DECISION = "DECISION"
    LAUNCH_PERMIT = "LAUNCH_PERMIT"
    ACTION_PERMIT = "ACTION_PERMIT"


class RecoveryRunEventPayload(StrictModel):
    lifecycle: RecoveryRunLifecycle | None = None
    failure_category: RecoveryRunFailureCategory | None = None
    chain: RecoveryChain | None = None
    node: RecoveryNodeProgress | None = None
    hypothesis: GeminiHypothesis | None = None
    hypothesis_disposition: RecoveryHypothesisDisposition | None = None
    report: InvestigationReport | None = None
    decision: RecoveryDecision | None = None
    certificate: VerifiedCertificate | None = None
    witness: AmbiguityWitness | None = None
    launch_permit: RecoveryLaunchPermit | None = None
    action_permit: ActionPermit | None = None
    note: SanitizedText | None = None


class RecoveryRunEvent(StrictModel):
    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        revalidate_instances="always",
        strict=True,
    )

    schema_version: Literal[RECOVERY_RUN_EVENT_VERSION]
    run_id: Identifier
    cursor: int = Field(ge=1, le=MAX_RECOVERY_RUN_EVENTS)
    type: RecoveryRunEventType
    occurred_at: AwareDatetime
    payload: RecoveryRunEventPayload

    @model_validator(mode="after")
    def validate_payload(self) -> RecoveryRunEvent:
        fields = {
            name
            for name in RecoveryRunEventPayload.model_fields
            if getattr(self.payload, name) is not None
        }
        expected = {
            RecoveryRunEventType.LIFECYCLE: {"lifecycle"},
            RecoveryRunEventType.CHAIN: {"chain"},
            RecoveryRunEventType.NODE: {"node"},
            RecoveryRunEventType.HYPOTHESIS: {
                "hypothesis_disposition",
                "note",
            },
            RecoveryRunEventType.EVIDENCE: {"report"},
            RecoveryRunEventType.DECISION: {"decision"},
            RecoveryRunEventType.LAUNCH_PERMIT: {"launch_permit"},
            RecoveryRunEventType.ACTION_PERMIT: {"action_permit"},
        }[self.type]
        if self.type is RecoveryRunEventType.LIFECYCLE:
            failed = self.payload.lifecycle in {
                RecoveryRunLifecycle.FAILED,
                RecoveryRunLifecycle.CANCELLED,
            }
            if failed != (self.payload.failure_category is not None):
                raise ValueError("failed lifecycle events require one failure category")
            if failed:
                expected.add("failure_category")
        elif self.type is RecoveryRunEventType.HYPOTHESIS:
            requires_hypothesis = self.payload.hypothesis_disposition in {
                RecoveryHypothesisDisposition.SELECTED,
                RecoveryHypothesisDisposition.NO_PROBE,
                RecoveryHypothesisDisposition.DUPLICATE_PROBE,
                RecoveryHypothesisDisposition.BUDGET_EXHAUSTED,
                RecoveryHypothesisDisposition.UNSUPPORTED_PROBE,
                RecoveryHypothesisDisposition.UNSUPPORTED_ACTION,
                RecoveryHypothesisDisposition.INVALID_BINDING,
            }
            if requires_hypothesis != (self.payload.hypothesis is not None):
                raise ValueError(
                    "hypothesis disposition does not match its model artifact"
                )
            if requires_hypothesis:
                expected.add("hypothesis")
        elif self.type is RecoveryRunEventType.DECISION:
            artifacts = (
                self.payload.certificate is not None,
                self.payload.witness is not None,
            )
            if sum(artifacts) != 1:
                raise ValueError("a recovery decision requires one proof artifact")
            if self.payload.certificate is not None:
                certificate = self.payload.certificate
                transition = certificate.transition
                if transition is not None:
                    valid_decisions = {
                        RecoveryDecision.CONTINUE
                        if transition.action is PermitAction.CONTINUE
                        else RecoveryDecision.RETRY
                    }
                else:
                    valid_decisions = {
                        Classification.COMMITTED: {
                            RecoveryDecision.CONTINUE,
                            RecoveryDecision.ESCALATE,
                        },
                        Classification.NOT_COMMITTED: {
                            RecoveryDecision.ESCALATE,
                        },
                        Classification.PARTIAL: {RecoveryDecision.ESCALATE},
                        Classification.PENDING: {
                            RecoveryDecision.OBSERVE,
                            RecoveryDecision.ESCALATE,
                        },
                    }[certificate.classification]
                if self.payload.decision not in valid_decisions:
                    raise ValueError(
                        "certificate does not support the recovery decision"
                    )
            elif self.payload.decision is not RecoveryDecision.ESCALATE:
                raise ValueError("an ambiguity witness requires escalation")
            expected.add("certificate" if artifacts[0] else "witness")
        if fields != expected:
            raise ValueError("recovery event type does not match its payload")
        return self


class RecoveryRunSnapshot(StrictModel):
    schema_version: Literal[RECOVERY_RUN_SNAPSHOT_VERSION]
    request: RecoveryRunRequest
    request_sha256: Sha256Digest
    lifecycle: RecoveryRunLifecycle
    event_cursor: int = Field(ge=1, le=MAX_RECOVERY_RUN_EVENTS)
    revision: int = Field(ge=0, le=MAX_RECOVERY_RUN_EVENTS - 1)
    chain: RecoveryChain
    chain_sha256: Sha256Digest
    active_node_id: Identifier | None = None
    nodes: tuple[RecoveryNodeProgress, ...] = Field(min_length=1, max_length=32)
    hypotheses: tuple[GeminiHypothesis, ...] = Field(
        default_factory=tuple, max_length=64
    )
    reports: tuple[InvestigationReport, ...] = Field(
        default_factory=tuple, max_length=64
    )
    certificates: tuple[VerifiedCertificate, ...] = Field(
        default_factory=tuple,
        max_length=32,
    )
    witnesses: tuple[AmbiguityWitness, ...] = Field(
        default_factory=tuple, max_length=32
    )
    launch_permit: RecoveryLaunchPermit | None = None
    action_permits: tuple[ActionPermit, ...] = Field(
        default_factory=tuple, max_length=32
    )
    decision: RecoveryDecision | None = None
    failure_category: RecoveryRunFailureCategory | None = None
    created_at: AwareDatetime
    updated_at: AwareDatetime

    @model_validator(mode="after")
    def validate_snapshot(self) -> RecoveryRunSnapshot:
        if self.request_sha256 != canonical_sha256(self.request):
            raise ValueError("recovery request digest does not match")
        if self.chain_sha256 != canonical_sha256(self.chain):
            raise ValueError("recovery chain digest does not match")
        if self.revision != self.event_cursor - 1:
            raise ValueError("recovery revision must follow the event cursor")
        node_ids = tuple(node.node_id for node in self.nodes)
        chain_node_ids = tuple(node.node_id for node in self.chain.nodes)
        chain_nodes = {node.node_id: node for node in self.chain.nodes}
        if node_ids != chain_node_ids:
            raise ValueError("recovery node progress must match the declared chain")
        if self.active_node_id is not None and self.active_node_id not in node_ids:
            raise ValueError("active recovery node is not declared")
        if self.updated_at < self.created_at:
            raise ValueError("recovery update cannot precede creation")
        terminal = self.lifecycle in {
            RecoveryRunLifecycle.COMPLETED,
            RecoveryRunLifecycle.ESCALATED,
            RecoveryRunLifecycle.FAILED,
            RecoveryRunLifecycle.CANCELLED,
        }
        if terminal and self.decision is None and self.failure_category is None:
            raise ValueError("terminal recovery state requires a disposition")
        if self.failure_category is not None and self.lifecycle not in {
            RecoveryRunLifecycle.FAILED,
            RecoveryRunLifecycle.CANCELLED,
        }:
            raise ValueError("failure category requires a failed recovery state")
        if self.launch_permit is not None:
            first = self.chain.nodes[0]
            if (
                self.launch_permit.run_id != self.request.run_id
                or self.launch_permit.node_id != first.node_id
                or self.launch_permit.semantic_action_sha256
                != first.semantic_action.semantic_action_sha256
            ):
                raise ValueError("launch permit is not bound to the first chain node")
        if any(
            permit.chain_id != self.chain.chain_id
            or permit.source_node_id not in chain_node_ids
            or permit.target_node_id not in chain_node_ids
            for permit in self.action_permits
        ):
            raise ValueError("action permit is not bound to this recovery chain")
        report_sha256s = {canonical_sha256(report) for report in self.reports}
        for artifact in (*self.certificates, *self.witnesses, *self.hypotheses):
            if (
                artifact.chain_id != self.chain.chain_id
                or artifact.node_id not in chain_node_ids
                or artifact.report_sha256 not in report_sha256s
                or artifact.semantic_action_sha256
                != chain_nodes[artifact.node_id].semantic_action.semantic_action_sha256
            ):
                raise ValueError("recovery artifact is not bound to this chain")
        for artifact in (*self.certificates, *self.witnesses):
            node = chain_nodes[artifact.node_id]
            if (
                artifact.chain_sha256 != self.chain_sha256
                or artifact.node_sha256 != canonical_sha256(node)
                or artifact.envelope_sha256 != node.envelope.envelope_sha256
                or artifact.target != node.semantic_action.target
            ):
                raise ValueError("recovery proof binding changed")
        for permit in self.action_permits:
            bound = False
            for certificate in self.certificates:
                transition = certificate.transition
                if (
                    certificate.certificate_id == permit.certificate_id
                    and transition is not None
                    and permit.chain_id == certificate.chain_id
                    and permit.source_node_id == transition.source_node_id
                    and permit.target_node_id == transition.target_node_id
                    and permit.semantic_action_sha256
                    == transition.semantic_action_sha256
                    and permit.action is transition.action
                    and permit.action_policy_version
                    == certificate.action_policy_version
                    and permit.tool_name == transition.tool_name
                    and permit.tool_version == transition.tool_version
                    and permit.arguments_sha256 == transition.arguments_sha256
                    and permit.target_sha256 == transition.target_sha256
                    and permit.precondition_sha256 == transition.precondition_sha256
                    and permit.expires_at == certificate.expires_at
                ):
                    bound = True
                    break
            if not bound:
                raise ValueError("action permit is not bound to its certificate")
        if self.lifecycle is RecoveryRunLifecycle.COMPLETED and any(
            node.state is not RecoveryNodeState.COMPLETED for node in self.nodes
        ):
            raise ValueError("completed recovery requires every node to complete")
        if self.lifecycle is RecoveryRunLifecycle.ESCALATED and not (
            self.witnesses
            or any(certificate.transition is None for certificate in self.certificates)
        ):
            raise ValueError("escalated recovery requires a non-authorizing proof")
        return self


__all__ = [
    "MAX_RECOVERY_RUN_EVENTS",
    "RECOVERY_ACTION_SCOPE_VERSION",
    "RECOVERY_LAUNCH_PERMIT_VERSION",
    "RECOVERY_PREPARED_ACTION_VERSION",
    "RECOVERY_RUN_EVENT_VERSION",
    "RECOVERY_RUN_REQUEST_VERSION",
    "RECOVERY_RUN_SNAPSHOT_VERSION",
    "RecoveryActionScope",
    "RecoveryAuthorityKind",
    "RecoveryDecision",
    "RecoveryDispatchOutcome",
    "RecoveryHypothesisDisposition",
    "RecoveryLaunchPermit",
    "RecoveryLaunchPermitState",
    "RecoveryNodeProgress",
    "RecoveryNodeState",
    "RecoveryPreparedAction",
    "RecoveryRunEvent",
    "RecoveryRunEventPayload",
    "RecoveryRunEventType",
    "RecoveryRunFailureCategory",
    "RecoveryRunFault",
    "RecoveryRunLifecycle",
    "RecoveryRunPolicy",
    "RecoveryRunRequest",
    "RecoveryRunSnapshot",
]
