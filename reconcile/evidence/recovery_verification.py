"""Deterministic certificates and ambiguity witnesses for recovery actions."""

from __future__ import annotations

import hashlib
from datetime import UTC, datetime

from reconcile.contracts import (
    AMBIGUITY_WITNESS_VERSION,
    VERIFIED_CERTIFICATE_VERSION,
    AmbiguityWitness,
    CertifiedTransition,
    Classification,
    ContractError,
    DiscriminatingObservation,
    EffectAssertionState,
    EvidenceAuthority,
    EvidenceDisposition,
    EvidenceReason,
    ExecutionEnvelope,
    HypothesizedEffect,
    InvestigationReport,
    InvestigationStatus,
    NormalizedEvidence,
    OperationStatus,
    PermitAction,
    PossibleHistory,
    RecoveryActionNode,
    RecoveryChain,
    RecoveryEvidenceBinding,
    VerifiedCertificate,
    canonical_json_bytes,
    canonical_sha256,
    decode_contract,
)
from reconcile.contracts.base import canonical_json_value_bytes
from reconcile.controller import ControllerAuditRecord, ProbeStopReason
from reconcile.evidence.classification import CoreEvaluation
from reconcile.evidence.recovery_rules import (
    CREATE_FIRESTORE_RELEASE_RECORD_PROFILE_VERSION,
    FIRESTORE_RECORD_EFFECT_SCOPE,
    PROMOTE_CLOUD_RUN_TRAFFIC_PROFILE_VERSION,
    PROMOTION_TRAFFIC_EFFECT_SCOPE,
    RECOVERY_CAPABILITY_VERSION,
    STAGE_CLOUD_RUN_REVISION_PROFILE_VERSION,
    STAGE_READINESS_EFFECT_SCOPE,
    STAGE_REVISION_EFFECT_SCOPE,
    STAGE_TRAFFIC_EFFECT_SCOPE,
    RecoveryActionProfile,
    RecoveryRuleViolation,
    recovery_precondition_sha256,
    resolve_recovery_action_profile,
    validate_recovery_proof,
)

RECOVERY_VERIFIER_VERSION = "recovery-verifier-v1"
RECOVERY_CHAIN_PROFILE_VERSION = "cloud-run-release-chain-v1"
RECOVERY_CORRELATION_POLICY_VERSION = "exact-envelope-correlation-v1"
RECOVERY_FRESHNESS_POLICY_VERSION = "envelope-freshness-window-v1"

RecoveryVerificationResult = VerifiedCertificate | AmbiguityWitness

_SUCCESSOR_PROFILE = {
    STAGE_CLOUD_RUN_REVISION_PROFILE_VERSION: (
        PROMOTE_CLOUD_RUN_TRAFFIC_PROFILE_VERSION
    ),
    PROMOTE_CLOUD_RUN_TRAFFIC_PROFILE_VERSION: (
        CREATE_FIRESTORE_RELEASE_RECORD_PROFILE_VERSION
    ),
    CREATE_FIRESTORE_RELEASE_RECORD_PROFILE_VERSION: None,
}

_CHAIN_PROFILE_ORDER = (
    STAGE_CLOUD_RUN_REVISION_PROFILE_VERSION,
    PROMOTE_CLOUD_RUN_TRAFFIC_PROFILE_VERSION,
    CREATE_FIRESTORE_RELEASE_RECORD_PROFILE_VERSION,
)
_STAGE_REVISION_CAPABILITIES = {
    ("cloud-run-revision-get", RECOVERY_CAPABILITY_VERSION),
    ("cloud-run-revision-health", RECOVERY_CAPABILITY_VERSION),
}


class RecoveryVerificationError(ValueError):
    """Trusted recovery inputs do not form one coherent verification request."""


def _rehydrate[Contract](value: Contract, model_type: type[Contract]) -> Contract:
    if type(value) is not model_type:
        raise TypeError(f"{model_type.__name__} input must be exact")
    try:
        return decode_contract(canonical_json_bytes(value), model_type)
    except ContractError as error:
        raise RecoveryVerificationError(
            f"{model_type.__name__} input failed contract validation"
        ) from error


def _validate_time(
    verified_at: datetime,
    *,
    chain: RecoveryChain,
    envelope: ExecutionEnvelope,
    report: InvestigationReport,
) -> datetime:
    if verified_at.tzinfo is None or verified_at.utcoffset() is None:
        raise RecoveryVerificationError("verification time must include a UTC offset")
    verified_at = verified_at.astimezone(UTC)
    if envelope.ambiguity.observed_at < envelope.invoked_at:
        raise RecoveryVerificationError(
            "ambiguous outcome precedes the bound invocation"
        )
    if report.created_at < envelope.ambiguity.observed_at:
        raise RecoveryVerificationError(
            "report creation precedes the ambiguous outcome"
        )
    if report.updated_at < envelope.ambiguity.observed_at:
        raise RecoveryVerificationError(
            "report completion precedes the ambiguous outcome"
        )
    if any(
        record.started_at < report.created_at or record.completed_at > report.updated_at
        for record in report.probe_audit
    ):
        raise RecoveryVerificationError(
            "probe audit timestamps fall outside the report interval"
        )
    if any(
        item.provenance.retrieved_at > report.updated_at for item in report.evidence
    ):
        raise RecoveryVerificationError(
            "evidence retrieval occurs after the report update"
        )

    required_predecessors = [
        chain.created_at,
        envelope.invoked_at,
        envelope.ambiguity.observed_at,
        report.created_at,
        report.updated_at,
    ]
    required_predecessors.extend(record.completed_at for record in report.probe_audit)
    for item in report.evidence:
        required_predecessors.extend(
            (
                item.freshness.valid_from,
                item.observed_at,
                item.provenance.retrieved_at,
            )
        )
    if verified_at < max(required_predecessors):
        raise RecoveryVerificationError("verification time precedes its trusted inputs")
    return verified_at


def _validate_chain(
    chain: RecoveryChain,
) -> dict[str, tuple[RecoveryActionNode, RecoveryActionProfile]]:
    if chain.chain_profile_version != RECOVERY_CHAIN_PROFILE_VERSION:
        raise RecoveryVerificationError("recovery chain profile is unsupported")
    if len(chain.nodes) != len(_CHAIN_PROFILE_ORDER):
        raise RecoveryVerificationError(
            "recovery chain must contain exactly stage, promote, and record nodes"
        )

    by_profile: dict[str, tuple[RecoveryActionNode, RecoveryActionProfile]] = {}
    for node in chain.nodes:
        try:
            profile = resolve_recovery_action_profile(node.semantic_action)
        except (TypeError, RecoveryRuleViolation) as error:
            raise RecoveryVerificationError(str(error)) from error
        if profile.profile_version in by_profile:
            raise RecoveryVerificationError(
                "recovery chain contains a duplicate action profile"
            )
        by_profile[profile.profile_version] = (node, profile)

    if set(by_profile) != set(_CHAIN_PROFILE_ORDER):
        raise RecoveryVerificationError(
            "recovery chain must contain exactly stage, promote, and record nodes"
        )

    stage, _ = by_profile[STAGE_CLOUD_RUN_REVISION_PROFILE_VERSION]
    promote, _ = by_profile[PROMOTE_CLOUD_RUN_TRAFFIC_PROFILE_VERSION]
    record, _ = by_profile[CREATE_FIRESTORE_RELEASE_RECORD_PROFILE_VERSION]
    if (
        stage.depends_on
        or promote.depends_on != (stage.node_id,)
        or record.depends_on != (promote.node_id,)
    ):
        raise RecoveryVerificationError(
            "recovery chain must be the exact stage-to-promote-to-record topology"
        )

    stage_action = stage.semantic_action
    promote_action = promote.semantic_action
    record_action = record.semantic_action
    stage_release = stage_action.semantic_arguments["release_id"]
    if (
        promote_action.target != stage_action.target
        or promote_action.semantic_arguments["release_id"] != stage_release
    ):
        raise RecoveryVerificationError(
            "stage and promotion must bind the same Cloud Run service and release"
        )
    if (
        record_action.target.scope["project"] != stage_action.target.scope["project"]
        or record_action.semantic_arguments["release_id"] != stage_release
        or record_action.target.resource["document"] != f"releases/{stage_release}"
    ):
        raise RecoveryVerificationError(
            "release record must bind the Cloud Run project and exact release document"
        )
    return by_profile


def _find_node(chain: RecoveryChain, node_id: str) -> RecoveryActionNode:
    matches = tuple(node for node in chain.nodes if node.node_id == node_id)
    if len(matches) != 1:
        raise RecoveryVerificationError("recovery node is not present exactly once")
    return matches[0]


def _validate_node_binding(
    chain: RecoveryChain,
    node: RecoveryActionNode,
    envelope: ExecutionEnvelope,
) -> RecoveryActionProfile:
    if (
        node.envelope.investigation_id != envelope.investigation_id
        or node.envelope.operation_id != envelope.operation_id
        or node.envelope.envelope_sha256 != canonical_sha256(envelope)
    ):
        raise RecoveryVerificationError("recovery node references another envelope")

    action = node.semantic_action
    invocation = envelope.context.invocation
    expected_effect_sha256s = tuple(
        canonical_sha256(effect) for effect in envelope.expected_effects
    )
    if (
        action.key_version != "semantic-action-v1"
        or action.tool_name != invocation.tool_name
        or action.tool_version != invocation.tool_version
        or action.semantic_arguments != invocation.arguments
        or action.target != envelope.target
        or action.expected_effect_sha256s != expected_effect_sha256s
    ):
        raise RecoveryVerificationError(
            "recovery semantic action does not match the execution envelope"
        )
    try:
        profile = resolve_recovery_action_profile(action)
    except (TypeError, RecoveryRuleViolation) as error:
        raise RecoveryVerificationError(str(error)) from error
    if (
        envelope.context.correlation_fields.get("release_id")
        != action.semantic_arguments["release_id"]
    ):
        raise RecoveryVerificationError(
            "envelope release correlation does not match the semantic action"
        )
    return profile


def _audit_record_sha256(report_record: object) -> str:
    values = report_record.model_dump(mode="python", exclude={"evidence_ids"})
    values["sequence"] = values.pop("probe_sequence")
    values["stop_reason"] = ProbeStopReason(values["stop_reason"])
    return canonical_sha256(ControllerAuditRecord.model_validate(values))


def _validate_report(
    envelope: ExecutionEnvelope,
    report: InvestigationReport,
    evaluation: CoreEvaluation,
) -> None:
    if report.status is not InvestigationStatus.COMPLETED:
        raise RecoveryVerificationError("recovery requires a completed report")
    if (
        report.investigation_id != envelope.investigation_id
        or report.envelope_sha256 != canonical_sha256(envelope)
        or evaluation.envelope_sha256 != report.envelope_sha256
    ):
        raise RecoveryVerificationError(
            "report and evaluation envelope binding differs"
        )
    if (
        report.evidence != evaluation.evidence
        or report.evidence_decisions != evaluation.decisions
        or report.proof != evaluation.proof
        or report.classification is not evaluation.classification
        or report.action_gate != evaluation.action_gates
        or report.missing_evidence != evaluation.missing_evidence
    ):
        raise RecoveryVerificationError(
            "report does not reproduce the sealed deterministic evaluation"
        )
    if len(report.probe_audit) != len(evaluation.attempts):
        raise RecoveryVerificationError("report omits deterministic probe audit")
    for record, attempt in zip(report.probe_audit, evaluation.attempts, strict=True):
        if (
            record.probe_sequence != attempt.probe_sequence
            or _audit_record_sha256(record) != attempt.controller_audit_sha256
            or record.evidence_ids != (attempt.decision.evidence_id,)
        ):
            raise RecoveryVerificationError(
                "report probe audit does not match the sealed evaluation"
            )


def _admitted_evidence(
    envelope: ExecutionEnvelope,
    evaluation: CoreEvaluation,
) -> tuple[NormalizedEvidence, ...]:
    admitted_ids = {
        decision.evidence_id
        for decision in evaluation.decisions
        if decision.disposition is EvidenceDisposition.ADMITTED
    }
    if admitted_ids != set(evaluation.proof.admitted_evidence_ids):
        raise RecoveryVerificationError("proof admitted-evidence identity drifted")
    expected_correlation = envelope.context.correlation_fields
    enabled_capabilities = {
        (capability.name, capability.version)
        for capability in envelope.context.enabled_capabilities
    }
    admitted = tuple(
        sorted(
            (
                evidence
                for evidence in evaluation.evidence
                if evidence.evidence_id in admitted_ids
            ),
            key=lambda evidence: evidence.evidence_id,
        )
    )
    if {item.evidence_id for item in admitted} != admitted_ids:
        raise RecoveryVerificationError("admitted evidence is missing from evaluation")
    for evidence in admitted:
        if (
            evidence.target != envelope.target
            or evidence.authority is not EvidenceAuthority.TARGET_STATE
            or (evidence.capability_name, evidence.capability_version)
            not in enabled_capabilities
            or evidence.authority_policy_version != envelope.context.policies.authority
            or any(
                evidence.correlation.get(name) != value
                for name, value in expected_correlation.items()
            )
        ):
            raise RecoveryVerificationError(
                "admitted evidence escaped target, policy, or correlation binding"
            )
    return admitted


def _supporting_evidence(
    evaluation: CoreEvaluation,
    admitted: tuple[NormalizedEvidence, ...],
) -> tuple[NormalizedEvidence, ...]:
    evidence_by_id = {item.evidence_id: item for item in admitted}
    identifiers = {
        evidence_id
        for finding in evaluation.proof.effect_findings
        for evidence_id in finding.evidence_ids
    }
    if evaluation.proof.operation_status is not None:
        identifiers.update(
            evidence.evidence_id
            for evidence in admitted
            if evidence.operation_status is evaluation.proof.operation_status
        )
    if not identifiers <= set(evidence_by_id):
        raise RecoveryVerificationError("proof cites evidence that was not admitted")
    return tuple(evidence_by_id[evidence_id] for evidence_id in sorted(identifiers))


def _bindings(
    evidence: tuple[NormalizedEvidence, ...],
) -> tuple[RecoveryEvidenceBinding, ...]:
    return tuple(
        RecoveryEvidenceBinding(
            evidence_id=item.evidence_id,
            evidence_sha256=canonical_sha256(item),
            raw_observation_sha256=item.raw_observation.sha256,
            valid_until=item.freshness.valid_until,
        )
        for item in evidence
    )


def _arguments_sha256(node: RecoveryActionNode) -> str:
    return hashlib.sha256(
        canonical_json_value_bytes(node.semantic_action.semantic_arguments)
    ).hexdigest()


def _successor(
    chain: RecoveryChain,
    node: RecoveryActionNode,
    profile: RecoveryActionProfile,
) -> tuple[RecoveryActionNode, RecoveryActionProfile] | None:
    expected_profile = _SUCCESSOR_PROFILE[profile.profile_version]
    if expected_profile is None:
        return None
    successors = tuple(
        candidate
        for candidate in chain.nodes
        if candidate.depends_on == (node.node_id,)
    )
    if len(successors) != 1:
        return None
    candidate = successors[0]
    try:
        candidate_profile = resolve_recovery_action_profile(candidate.semantic_action)
    except (TypeError, RecoveryRuleViolation):
        return None
    if candidate_profile.profile_version != expected_profile:
        return None
    return candidate, candidate_profile


def _continue_transition(
    chain: RecoveryChain,
    node: RecoveryActionNode,
    profile: RecoveryActionProfile,
    evidence: tuple[NormalizedEvidence, ...],
    successor_envelope: ExecutionEnvelope | None,
) -> CertifiedTransition | None:
    successor = _successor(chain, node, profile)
    if successor is None:
        return None
    target_node, target_profile = successor
    if successor_envelope is None:
        return None
    validated_profile = _validate_node_binding(chain, target_node, successor_envelope)
    if validated_profile.profile_version != target_profile.profile_version:
        raise RecoveryVerificationError(
            "successor envelope resolves to another action profile"
        )
    if profile.profile_version == STAGE_CLOUD_RUN_REVISION_PROFILE_VERSION:
        revisions = {
            item.correlation["revision"]
            for item in evidence
            if (item.capability_name, item.capability_version)
            in _STAGE_REVISION_CAPABILITIES
            and "revision" in item.correlation
        }
        if revisions != {target_node.semantic_action.semantic_arguments["revision"]}:
            return None
    try:
        precondition_sha256 = recovery_precondition_sha256(target_profile, evidence)
    except RecoveryRuleViolation:
        return None
    action = target_node.semantic_action
    return CertifiedTransition(
        action=PermitAction.CONTINUE,
        source_node_id=node.node_id,
        target_node_id=target_node.node_id,
        semantic_action_sha256=action.semantic_action_sha256,
        tool_name=action.tool_name,
        tool_version=action.tool_version,
        arguments_sha256=_arguments_sha256(target_node),
        target_sha256=canonical_sha256(action.target),
        precondition_sha256=precondition_sha256,
    )


def _retry_transition(
    node: RecoveryActionNode,
    profile: RecoveryActionProfile,
    evaluation: CoreEvaluation,
    evidence: tuple[NormalizedEvidence, ...],
) -> CertifiedTransition | None:
    if not profile.retry_allowed:
        return None
    decisions = {item.evidence_id: item for item in evaluation.decisions}
    positive = tuple(
        item
        for item in evidence
        if item.operation_status is OperationStatus.TERMINAL_NOT_COMMITTED
        and decisions[item.evidence_id].reason
        is EvidenceReason.AUTHORITATIVE_AFFIRMATIVE_NON_EXECUTION
    )
    if not positive:
        return None
    try:
        precondition_sha256 = recovery_precondition_sha256(
            profile,
            positive,
            retry=True,
        )
    except RecoveryRuleViolation:
        return None
    action = node.semantic_action
    return CertifiedTransition(
        action=PermitAction.RETRY,
        source_node_id=node.node_id,
        target_node_id=node.node_id,
        semantic_action_sha256=action.semantic_action_sha256,
        tool_name=action.tool_name,
        tool_version=action.tool_version,
        arguments_sha256=_arguments_sha256(node),
        target_sha256=canonical_sha256(action.target),
        precondition_sha256=precondition_sha256,
    )


def _artifact_identifier(
    prefix: str,
    *,
    chain: RecoveryChain,
    node: RecoveryActionNode,
    report: InvestigationReport,
    verified_at: datetime,
) -> str:
    digest = hashlib.sha256(
        canonical_json_value_bytes(
            {
                "chain_sha256": canonical_sha256(chain),
                "node_sha256": canonical_sha256(node),
                "report_sha256": canonical_sha256(report),
                "verified_at": verified_at.isoformat(),
                "verifier_version": RECOVERY_VERIFIER_VERSION,
            }
        )
    ).hexdigest()
    return f"{prefix}-{digest[:32]}"


def _history_classification(
    states: tuple[EffectAssertionState, ...],
) -> Classification:
    if all(state is EffectAssertionState.ESTABLISHED for state in states):
        return Classification.COMMITTED
    if all(state is EffectAssertionState.NOT_ESTABLISHED for state in states):
        return Classification.NOT_COMMITTED
    if any(state is EffectAssertionState.ESTABLISHED for state in states) and any(
        state is EffectAssertionState.NOT_ESTABLISHED for state in states
    ):
        return Classification.PARTIAL
    return Classification.UNKNOWN


def _evidence_compatible_with_history(
    evidence: NormalizedEvidence,
    states: dict[str, EffectAssertionState],
    classification: Classification,
) -> bool:
    for assertion in evidence.effect_assertions:
        if (
            assertion.effect_id in states
            and assertion.state is not EffectAssertionState.UNVERIFIED
            and assertion.state is not states[assertion.effect_id]
        ):
            return False
    status = evidence.operation_status
    if status is OperationStatus.TERMINAL_NOT_COMMITTED:
        return classification is Classification.NOT_COMMITTED
    if status is OperationStatus.TERMINAL_COMMITTED:
        return classification in {Classification.COMMITTED, Classification.PARTIAL}
    if status in {OperationStatus.ACTIVE, OperationStatus.UNRESOLVED}:
        return classification in {Classification.PENDING, Classification.UNKNOWN}
    return True


def _history(
    *,
    history_id: str,
    assignment: EffectAssertionState,
    evaluation: CoreEvaluation,
    evidence: tuple[NormalizedEvidence, ...],
    preserve_findings: bool,
    classification_override: Classification | None = None,
) -> PossibleHistory:
    states = {
        finding.effect_id: (
            assignment
            if not preserve_findings or finding.state is EffectAssertionState.UNVERIFIED
            else finding.state
        )
        for finding in evaluation.proof.effect_findings
    }
    classification = classification_override or _history_classification(
        tuple(states.values())
    )
    compatible = tuple(
        item.evidence_id
        for item in evidence
        if _evidence_compatible_with_history(item, states, classification)
    )
    compatible_set = set(compatible)
    effects = tuple(
        HypothesizedEffect(
            effect_id=finding.effect_id,
            state=states[finding.effect_id],
            cited_evidence_ids=tuple(
                sorted(
                    item.evidence_id
                    for item in evidence
                    if item.evidence_id in compatible_set
                    and any(
                        assertion.effect_id == finding.effect_id
                        and assertion.state is states[finding.effect_id]
                        for assertion in item.effect_assertions
                    )
                )
            ),
        )
        for finding in evaluation.proof.effect_findings
    )
    summary = {
        EffectAssertionState.ESTABLISHED: (
            "The unresolved effects occurred before acknowledgement was lost."
        ),
        EffectAssertionState.NOT_ESTABLISHED: (
            "The unresolved effects did not occur before acknowledgement was lost."
        ),
        EffectAssertionState.UNVERIFIED: (
            "The operation remains active and the effects are not yet settled."
        ),
    }[assignment]
    return PossibleHistory(
        history_id=history_id,
        classification=classification,
        effect_states=effects,
        compatible_evidence_ids=compatible,
        summary=summary,
    )


def _minimal_conflict(
    evaluation: CoreEvaluation,
    evidence: tuple[NormalizedEvidence, ...],
) -> tuple[str, ...]:
    pairs: set[tuple[str, str]] = set()
    for finding in evaluation.proof.effect_findings:
        established = sorted(
            item.evidence_id
            for item in evidence
            if any(
                assertion.effect_id == finding.effect_id
                and assertion.state is EffectAssertionState.ESTABLISHED
                for assertion in item.effect_assertions
            )
        )
        absent = sorted(
            item.evidence_id
            for item in evidence
            if any(
                assertion.effect_id == finding.effect_id
                and assertion.state is EffectAssertionState.NOT_ESTABLISHED
                for assertion in item.effect_assertions
            )
        )
        pairs.update(
            tuple(sorted((left, right))) for left in established for right in absent
        )

    status_ids: dict[OperationStatus, list[str]] = {
        status: sorted(
            item.evidence_id for item in evidence if item.operation_status is status
        )
        for status in OperationStatus
    }
    incompatible = (
        (OperationStatus.TERMINAL_COMMITTED, OperationStatus.TERMINAL_NOT_COMMITTED),
        (OperationStatus.TERMINAL_NOT_COMMITTED, OperationStatus.ACTIVE),
        (OperationStatus.TERMINAL_NOT_COMMITTED, OperationStatus.UNRESOLVED),
    )
    if not all(
        finding.state is EffectAssertionState.ESTABLISHED
        for finding in evaluation.proof.effect_findings
    ):
        incompatible += (
            (OperationStatus.TERMINAL_COMMITTED, OperationStatus.ACTIVE),
            (OperationStatus.TERMINAL_COMMITTED, OperationStatus.UNRESOLVED),
        )
    for left_status, right_status in incompatible:
        pairs.update(
            tuple(sorted((left, right)))
            for left in status_ids[left_status]
            for right in status_ids[right_status]
        )
    established_ids = sorted(
        item.evidence_id
        for item in evidence
        if any(
            assertion.state is EffectAssertionState.ESTABLISHED
            for assertion in item.effect_assertions
        )
    )
    pairs.update(
        tuple(sorted((left, right)))
        for left in established_ids
        for right in status_ids[OperationStatus.TERMINAL_NOT_COMMITTED]
    )
    if not pairs:
        return ()
    return min(pairs)


def _status_conflict_histories(
    *,
    conflict_ids: tuple[str, ...],
    evaluation: CoreEvaluation,
    evidence: tuple[NormalizedEvidence, ...],
) -> tuple[PossibleHistory, PossibleHistory] | None:
    if len(conflict_ids) != 2:
        return None
    by_id = {item.evidence_id: item for item in evidence}
    pair = tuple(by_id[evidence_id] for evidence_id in conflict_ids)
    if any(
        assertion.state is not EffectAssertionState.UNVERIFIED
        for item in pair
        for assertion in item.effect_assertions
    ):
        return None

    status_history = {
        OperationStatus.TERMINAL_COMMITTED: (
            EffectAssertionState.ESTABLISHED,
            Classification.COMMITTED,
        ),
        OperationStatus.TERMINAL_NOT_COMMITTED: (
            EffectAssertionState.NOT_ESTABLISHED,
            Classification.NOT_COMMITTED,
        ),
        OperationStatus.ACTIVE: (
            EffectAssertionState.UNVERIFIED,
            Classification.PENDING,
        ),
        OperationStatus.UNRESOLVED: (
            EffectAssertionState.UNVERIFIED,
            Classification.PENDING,
        ),
    }
    if any(item.operation_status not in status_history for item in pair):
        return None

    histories = tuple(
        _history(
            history_id=f"status-{item.operation_status.value.lower()}",
            assignment=status_history[item.operation_status][0],
            evaluation=evaluation,
            evidence=evidence,
            preserve_findings=False,
            classification_override=status_history[item.operation_status][1],
        )
        for item in pair
    )
    signatures = {
        (
            history.classification,
            tuple((effect.effect_id, effect.state) for effect in history.effect_states),
        )
        for history in histories
    }
    if len(signatures) != 2:
        return None
    return histories[0], histories[1]


def _discriminating_observations(
    *,
    profile: RecoveryActionProfile,
    envelope: ExecutionEnvelope,
    unresolved_effect_ids: tuple[str, ...],
    history_ids: tuple[str, ...],
) -> tuple[DiscriminatingObservation, ...]:
    unresolved = set(unresolved_effect_ids)
    effects_by_scope = {
        effect.commit_scope: effect.effect_id
        for effect in envelope.expected_effects
        if effect.effect_id in unresolved
    }
    if profile.profile_version == STAGE_CLOUD_RUN_REVISION_PROFILE_VERSION:
        requirements = (
            (
                STAGE_REVISION_EFFECT_SCOPE,
                "cloud-run-revision-get",
                "Read the exact labelled revision and verify its image and configuration.",
            ),
            (
                STAGE_READINESS_EFFECT_SCOPE,
                "cloud-run-revision-health",
                "Read health from the exact staged revision.",
            ),
            (
                STAGE_TRAFFIC_EFFECT_SCOPE,
                "cloud-run-service-get",
                "Read settled service traffic for the exact staged revision.",
            ),
        )
    elif profile.profile_version == PROMOTE_CLOUD_RUN_TRAFFIC_PROFILE_VERSION:
        requirements = (
            (
                PROMOTION_TRAFFIC_EFFECT_SCOPE,
                "cloud-run-service-get",
                "Read settled service traffic for the exact promoted revision.",
            ),
        )
    else:
        requirements = (
            (
                FIRESTORE_RECORD_EFFECT_SCOPE,
                "firestore-release-record-get",
                "Read the exact release document; matching existence proves commit.",
            ),
            (
                FIRESTORE_RECORD_EFFECT_SCOPE,
                "reconcile-dispatch-receipt-get",
                "Read a positive pre-provider dispatch receipt to prove non-execution.",
            ),
        )

    result = tuple(
        DiscriminatingObservation(
            observation_id=f"observe-{capability_name}",
            description=description,
            capability_name=capability_name,
            capability_version=RECOVERY_CAPABILITY_VERSION,
            relevant_effect_ids=(effects_by_scope[scope],),
            distinguishes_history_ids=history_ids,
        )
        for scope, capability_name, description in requirements
        if scope in effects_by_scope
    )
    if result:
        return result
    return (
        DiscriminatingObservation(
            observation_id="validate-expected-effect-profile",
            description=(
                "Validate the declared expected-effect profile before acquiring "
                "provider evidence."
            ),
            relevant_effect_ids=unresolved_effect_ids,
            distinguishes_history_ids=history_ids,
        ),
    )


def _witness(
    *,
    chain: RecoveryChain,
    node: RecoveryActionNode,
    envelope: ExecutionEnvelope,
    report: InvestigationReport,
    evaluation: CoreEvaluation,
    profile: RecoveryActionProfile,
    evidence: tuple[NormalizedEvidence, ...],
    verified_at: datetime,
    preserve_findings: bool,
) -> AmbiguityWitness:
    preserve_findings = preserve_findings and any(
        finding.state is EffectAssertionState.UNVERIFIED
        for finding in evaluation.proof.effect_findings
    )
    conflict_ids = (
        _minimal_conflict(evaluation, evidence)
        if evaluation.proof.conflicting_authority
        else ()
    )
    if evaluation.proof.conflicting_authority and len(conflict_ids) != 2:
        raise RecoveryVerificationError(
            "conflicting authority has no minimal contradictory evidence pair"
        )
    histories = (
        _status_conflict_histories(
            conflict_ids=conflict_ids,
            evaluation=evaluation,
            evidence=evidence,
        )
        if conflict_ids
        else None
    ) or (
        _history(
            history_id="effects-occurred",
            assignment=EffectAssertionState.ESTABLISHED,
            evaluation=evaluation,
            evidence=evidence,
            preserve_findings=preserve_findings,
        ),
        _history(
            history_id="effects-not-occurred",
            assignment=EffectAssertionState.NOT_ESTABLISHED,
            evaluation=evaluation,
            evidence=evidence,
            preserve_findings=preserve_findings,
        ),
    )
    unresolved = tuple(
        finding.effect_id
        for finding in evaluation.proof.effect_findings
        if finding.state is EffectAssertionState.UNVERIFIED
    ) or tuple(finding.effect_id for finding in evaluation.proof.effect_findings)
    history_ids = tuple(history.history_id for history in histories)
    return AmbiguityWitness(
        schema_version=AMBIGUITY_WITNESS_VERSION,
        witness_id=_artifact_identifier(
            "witness",
            chain=chain,
            node=node,
            report=report,
            verified_at=verified_at,
        ),
        chain_id=chain.chain_id,
        node_id=node.node_id,
        semantic_action_sha256=node.semantic_action.semantic_action_sha256,
        chain_sha256=canonical_sha256(chain),
        node_sha256=canonical_sha256(node),
        envelope_sha256=canonical_sha256(envelope),
        report_sha256=canonical_sha256(report),
        proof_sha256=canonical_sha256(evaluation.proof),
        target=node.semantic_action.target,
        target_sha256=canonical_sha256(node.semantic_action.target),
        evidence=_bindings(evidence),
        possible_histories=histories,
        discriminating_observations=_discriminating_observations(
            profile=profile,
            envelope=envelope,
            unresolved_effect_ids=unresolved,
            history_ids=history_ids,
        ),
        conflicting_evidence_ids=conflict_ids,
        verifier_version=RECOVERY_VERIFIER_VERSION,
        created_at=verified_at,
    )


def verify_recovery(
    *,
    chain: RecoveryChain,
    node_id: str,
    envelope: ExecutionEnvelope,
    report: InvestigationReport,
    evaluation: CoreEvaluation,
    verified_at: datetime,
    successor_envelope: ExecutionEnvelope | None = None,
) -> RecoveryVerificationResult:
    """Produce deterministic proof authority without consulting model output."""

    chain = _rehydrate(chain, RecoveryChain)
    envelope = _rehydrate(envelope, ExecutionEnvelope)
    report = _rehydrate(report, InvestigationReport)
    if successor_envelope is not None:
        successor_envelope = _rehydrate(successor_envelope, ExecutionEnvelope)
    if type(evaluation) is not CoreEvaluation or not evaluation.is_engine_output():
        raise TypeError("recovery verification accepts only sealed core evaluations")
    _validate_chain(chain)
    node = _find_node(chain, node_id)
    profile = _validate_node_binding(chain, node, envelope)
    _validate_report(envelope, report, evaluation)
    verified_at = _validate_time(
        verified_at,
        chain=chain,
        envelope=envelope,
        report=report,
    )
    admitted = _admitted_evidence(envelope, evaluation)
    supporting = _supporting_evidence(evaluation, admitted)
    # Validate the complete admitted history. The certificate's report/proof
    # digests bind that history, while direct evidence bindings remain the
    # decisive support whose freshness bounds the authorization.
    relevant = admitted

    try:
        validate_recovery_proof(
            profile,
            node.semantic_action,
            envelope.expected_effects,
            evaluation.classification,
            relevant,
        )
        profile_evidence_valid = True
    except RecoveryRuleViolation:
        profile_evidence_valid = False

    stale_support = any(
        not item.freshness.valid_from <= verified_at < item.freshness.valid_until
        for item in supporting
    )
    if (
        evaluation.classification is Classification.UNKNOWN
        or evaluation.proof.conflicting_authority
        or not supporting
        or not profile_evidence_valid
        or stale_support
    ):
        return _witness(
            chain=chain,
            node=node,
            envelope=envelope,
            report=report,
            evaluation=evaluation,
            profile=profile,
            evidence=relevant,
            verified_at=verified_at,
            preserve_findings=profile_evidence_valid and not stale_support,
        )

    transition: CertifiedTransition | None = None
    if evaluation.classification is Classification.COMMITTED:
        transition = _continue_transition(
            chain,
            node,
            profile,
            supporting,
            successor_envelope,
        )
    elif evaluation.classification is Classification.NOT_COMMITTED:
        transition = _retry_transition(node, profile, evaluation, supporting)

    expires_at = min(item.freshness.valid_until for item in supporting)
    return VerifiedCertificate(
        schema_version=VERIFIED_CERTIFICATE_VERSION,
        certificate_id=_artifact_identifier(
            "certificate",
            chain=chain,
            node=node,
            report=report,
            verified_at=verified_at,
        ),
        chain_id=chain.chain_id,
        node_id=node.node_id,
        semantic_action_sha256=node.semantic_action.semantic_action_sha256,
        chain_sha256=canonical_sha256(chain),
        node_sha256=canonical_sha256(node),
        envelope_sha256=canonical_sha256(envelope),
        report_sha256=canonical_sha256(report),
        proof_sha256=canonical_sha256(evaluation.proof),
        target=node.semantic_action.target,
        target_sha256=canonical_sha256(node.semantic_action.target),
        evidence=_bindings(supporting),
        authority_satisfied=True,
        correlation_satisfied=True,
        freshness_satisfied=True,
        authority_policy_version=envelope.context.policies.authority,
        correlation_policy_version=RECOVERY_CORRELATION_POLICY_VERSION,
        freshness_policy_version=RECOVERY_FRESHNESS_POLICY_VERSION,
        classification_policy_version=envelope.context.policies.classification,
        action_policy_version=envelope.context.policies.action,
        action_profile_version=profile.profile_version,
        verifier_version=RECOVERY_VERIFIER_VERSION,
        classification=evaluation.classification,
        transition=transition,
        issued_at=verified_at,
        expires_at=expires_at,
    )


__all__ = [
    "RECOVERY_CHAIN_PROFILE_VERSION",
    "RECOVERY_CORRELATION_POLICY_VERSION",
    "RECOVERY_FRESHNESS_POLICY_VERSION",
    "RECOVERY_VERIFIER_VERSION",
    "RecoveryVerificationError",
    "RecoveryVerificationResult",
    "verify_recovery",
]
