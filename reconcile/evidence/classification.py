"""Deterministic proof, five-state classification, and action policy."""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass
from threading import RLock
from weakref import WeakSet

from reconcile.contracts import (
    ACTION_GATE_RESULT_VERSION,
    ActionGateReason,
    ActionGateResult,
    Classification,
    DeterministicProof,
    EffectAssertionState,
    EffectFinding,
    EvidenceAuthority,
    EvidenceDecision,
    EvidenceDisposition,
    EvidenceReason,
    ExecutionEnvelope,
    MissingEvidence,
    NormalizedEvidence,
    OperationStatus,
    RequestedAction,
    canonical_json_bytes,
    canonical_sha256,
    decode_contract,
)
from reconcile.controller import ControllerAuditRecord
from reconcile.evidence.admission import EvidenceAttempt

_EVALUATION_SEAL = object()
_EVALUATION_LOCK = RLock()
_VALID_EVALUATIONS: WeakSet[CoreEvaluation] = WeakSet()


@dataclass(frozen=True, slots=True, init=False, eq=False, weakref_slot=True)
class CoreEvaluation:
    envelope_sha256: str
    attempts: tuple[EvidenceAttempt, ...]
    _evidence_bytes: tuple[bytes, ...]
    decisions: tuple[EvidenceDecision, ...]
    proof: DeterministicProof
    classification: Classification
    action_gates: tuple[ActionGateResult, ...]
    missing_evidence: tuple[MissingEvidence, ...]

    def __init__(
        self,
        *,
        envelope_sha256: str,
        attempts: tuple[EvidenceAttempt, ...],
        evidence: tuple[NormalizedEvidence, ...],
        decisions: tuple[EvidenceDecision, ...],
        proof: DeterministicProof,
        classification: Classification,
        action_gates: tuple[ActionGateResult, ...],
        missing_evidence: tuple[MissingEvidence, ...],
        _seal: object,
    ) -> None:
        if _seal is not _EVALUATION_SEAL:
            raise TypeError("core evaluations are created only by the classifier")
        object.__setattr__(self, "envelope_sha256", envelope_sha256)
        object.__setattr__(self, "attempts", attempts)
        object.__setattr__(
            self,
            "_evidence_bytes",
            tuple(canonical_json_bytes(item) for item in evidence),
        )
        object.__setattr__(self, "decisions", decisions)
        object.__setattr__(self, "proof", proof)
        object.__setattr__(self, "classification", classification)
        object.__setattr__(self, "action_gates", action_gates)
        object.__setattr__(self, "missing_evidence", missing_evidence)
        with _EVALUATION_LOCK:
            _VALID_EVALUATIONS.add(self)

    @property
    def evidence(self) -> tuple[NormalizedEvidence, ...]:
        return tuple(
            decode_contract(payload, NormalizedEvidence)
            for payload in self._evidence_bytes
        )

    def is_engine_output(self) -> bool:
        with _EVALUATION_LOCK:
            return self in _VALID_EVALUATIONS


def _deduplicate_attempts(
    attempts: tuple[EvidenceAttempt, ...],
) -> tuple[EvidenceAttempt, ...]:
    first_by_source_request_and_raw: dict[
        tuple[str, str, str, str, str | None, str],
        str,
    ] = {}
    result: list[EvidenceAttempt] = []
    for attempt in attempts:
        if attempt.raw_sha256 is None or attempt.evidence is None:
            result.append(attempt)
            continue
        evidence = attempt.evidence
        if evidence is None:
            raise RuntimeError("evidence attempt changed during deduplication")
        first_id = first_by_source_request_and_raw.setdefault(
            (
                evidence.capability_name,
                evidence.capability_version,
                evidence.provenance.source,
                evidence.provenance.adapter_version,
                attempt.request_sha256,
                attempt.raw_sha256,
            ),
            attempt.decision.evidence_id,
        )
        if first_id == attempt.decision.evidence_id:
            result.append(attempt)
            continue
        result.append(attempt.reject_duplicate())
    return tuple(result)


def _action_gates(
    classification: Classification,
    *,
    classification_policy_version: str,
    action_policy_version: str,
) -> tuple[ActionGateResult, ...]:
    continue_reasons = {
        Classification.COMMITTED: ActionGateReason.ALL_EFFECTS_ESTABLISHED,
        Classification.NOT_COMMITTED: ActionGateReason.OPERATION_NOT_COMMITTED,
        Classification.PARTIAL: ActionGateReason.INCOMPLETE_EFFECT_SET,
        Classification.PENDING: ActionGateReason.OPERATION_ACTIVE,
        Classification.UNKNOWN: ActionGateReason.INSUFFICIENT_AUTHORITATIVE_EVIDENCE,
    }
    retry_reasons = {
        Classification.COMMITTED: ActionGateReason.DUPLICATE_EFFECT_RISK,
        Classification.NOT_COMMITTED: ActionGateReason.EXPLICIT_RETRY_POLICY_REQUIRED,
        Classification.PARTIAL: ActionGateReason.DUPLICATE_EFFECT_RISK,
        Classification.PENDING: ActionGateReason.OPERATION_ACTIVE,
        Classification.UNKNOWN: ActionGateReason.AMBIGUOUS_DUPLICATE_RISK,
    }
    definitions: list[tuple[RequestedAction, bool, ActionGateReason]] = [
        (
            RequestedAction.CONTINUE,
            classification is Classification.COMMITTED,
            continue_reasons[classification],
        ),
        (RequestedAction.RETRY, False, retry_reasons[classification]),
        (
            RequestedAction.COMPENSATE,
            False,
            ActionGateReason.COMPENSATION_OUT_OF_SCOPE_V1,
        ),
    ]
    escalation_allowed, escalation_reason = {
        Classification.COMMITTED: (
            False,
            ActionGateReason.ALL_EFFECTS_ESTABLISHED,
        ),
        Classification.NOT_COMMITTED: (
            True,
            ActionGateReason.OPERATOR_REVIEW_AVAILABLE,
        ),
        Classification.PARTIAL: (
            True,
            ActionGateReason.OPERATOR_INTERVENTION_REQUIRED,
        ),
        Classification.PENDING: (
            True,
            ActionGateReason.OPERATOR_INTERVENTION_REQUIRED,
        ),
        Classification.UNKNOWN: (
            True,
            ActionGateReason.OPERATOR_INTERVENTION_REQUIRED,
        ),
    }[classification]
    definitions.append(
        (RequestedAction.ESCALATE, escalation_allowed, escalation_reason)
    )
    definitions.append(
        (RequestedAction.OBSERVE, True, ActionGateReason.READ_ONLY_FOLLOW_UP)
    )
    return tuple(
        ActionGateResult(
            schema_version=ACTION_GATE_RESULT_VERSION,
            requested_action=action,
            allowed=allowed,
            reason=reason,
            classification=classification,
            classification_policy_version=classification_policy_version,
            action_policy_version=action_policy_version,
            escalation_required=classification is not Classification.COMMITTED,
        )
        for action, allowed, reason in definitions
    )


def evaluate_evidence(
    envelope: ExecutionEnvelope,
    attempts: tuple[EvidenceAttempt, ...],
    audit_trail: tuple[ControllerAuditRecord, ...],
) -> CoreEvaluation:
    """Recheck pipeline output and derive the only authoritative core result."""

    envelope = decode_contract(canonical_json_bytes(envelope), ExecutionEnvelope)
    envelope_sha256 = canonical_sha256(envelope)
    if any(type(attempt) is not EvidenceAttempt for attempt in attempts):
        raise TypeError("classification accepts only pipeline evidence attempts")
    if any(not attempt.is_pipeline_output() for attempt in attempts):
        raise TypeError("classification accepts only sealed pipeline output")
    if any(attempt.envelope_sha256 != envelope_sha256 for attempt in attempts):
        raise ValueError("evidence attempt belongs to a different envelope")
    attempts = tuple(
        sorted(
            attempts, key=lambda item: (item.probe_sequence, item.decision.evidence_id)
        )
    )
    sequences = [attempt.probe_sequence for attempt in attempts]
    if len(sequences) != len(set(sequences)):
        raise ValueError("one evidence attempt is allowed per probe sequence")
    decision_ids = [attempt.decision.evidence_id for attempt in attempts]
    if len(decision_ids) != len(set(decision_ids)):
        raise ValueError("evidence attempt identifiers must be unique")
    if any(type(record) is not ControllerAuditRecord for record in audit_trail):
        raise TypeError("classification accepts only controller audit records")
    audit_trail = tuple(sorted(audit_trail, key=lambda record: record.sequence))
    if sequences != list(range(1, len(sequences) + 1)):
        raise ValueError("controller audit sequence must be contiguous")
    if sequences != [record.sequence for record in audit_trail]:
        raise ValueError("every controller audit record requires one evidence attempt")
    if any(
        attempt.controller_audit_sha256 != canonical_sha256(record)
        for attempt, record in zip(attempts, audit_trail, strict=True)
    ):
        raise ValueError("evidence attempt audit does not match the controller")
    attempts = _deduplicate_attempts(attempts)

    enabled = {
        (reference.name, reference.version)
        for reference in envelope.context.enabled_capabilities
    }
    admitted_attempts: list[EvidenceAttempt] = []
    for attempt in attempts:
        evidence = attempt.evidence
        if (
            evidence is None
            or attempt.decision.disposition is not EvidenceDisposition.ADMITTED
        ):
            continue
        if (
            evidence.authority is not EvidenceAuthority.TARGET_STATE
            or canonical_json_bytes(evidence.target)
            != canonical_json_bytes(envelope.target)
            or (evidence.capability_name, evidence.capability_version) not in enabled
            or evidence.authority_policy_version != envelope.context.policies.authority
            or any(
                key not in evidence.correlation or evidence.correlation[key] != expected
                for key, expected in envelope.context.correlation_fields.items()
            )
        ):
            raise ValueError("admitted evidence escaped deterministic admission")
        admitted_attempts.append(attempt)

    expected_effects = tuple(envelope.expected_effects)
    assertions: dict[str, list[tuple[EffectAssertionState, str]]] = defaultdict(list)
    statuses: list[tuple[OperationStatus, str]] = []
    for attempt in admitted_attempts:
        evidence = attempt.evidence
        if evidence is None:
            raise RuntimeError("admitted attempt omitted normalized evidence")
        for assertion in evidence.effect_assertions:
            assertions[assertion.effect_id].append(
                (assertion.state, evidence.evidence_id)
            )
        if evidence.operation_status is not None:
            statuses.append((evidence.operation_status, evidence.evidence_id))

    conflicting = False
    findings: list[EffectFinding] = []
    established_effects: set[str] = set()
    not_established_effects: set[str] = set()
    for effect in expected_effects:
        values = assertions.get(effect.effect_id, [])
        states = {state for state, _ in values}
        if {
            EffectAssertionState.ESTABLISHED,
            EffectAssertionState.NOT_ESTABLISHED,
        } <= states:
            conflicting = True
            state = EffectAssertionState.UNVERIFIED
        elif EffectAssertionState.ESTABLISHED in states:
            state = EffectAssertionState.ESTABLISHED
            established_effects.add(effect.effect_id)
        elif EffectAssertionState.NOT_ESTABLISHED in states:
            state = EffectAssertionState.NOT_ESTABLISHED
            not_established_effects.add(effect.effect_id)
        else:
            state = EffectAssertionState.UNVERIFIED
        evidence_ids = tuple(
            sorted(
                {
                    evidence_id
                    for assertion_state, evidence_id in values
                    if assertion_state is not EffectAssertionState.UNVERIFIED
                }
            )
        )
        findings.append(
            EffectFinding(
                effect_id=effect.effect_id,
                commit_scope=effect.commit_scope,
                state=state,
                evidence_ids=evidence_ids,
            )
        )

    status_values = {status for status, _ in statuses}
    terminal_not_committed = OperationStatus.TERMINAL_NOT_COMMITTED in status_values
    if (
        OperationStatus.TERMINAL_COMMITTED in status_values and terminal_not_committed
    ) or (
        terminal_not_committed
        and status_values
        & {
            OperationStatus.ACTIVE,
            OperationStatus.UNRESOLVED,
        }
    ):
        conflicting = True
    if terminal_not_committed and established_effects:
        conflicting = True

    all_established = len(established_effects) == len(expected_effects)
    if (
        OperationStatus.TERMINAL_COMMITTED in status_values
        and status_values
        & {
            OperationStatus.ACTIVE,
            OperationStatus.UNRESOLVED,
        }
        and not all_established
    ):
        conflicting = True

    if conflicting:
        operation_status = None
    elif OperationStatus.TERMINAL_COMMITTED in status_values:
        operation_status = OperationStatus.TERMINAL_COMMITTED
    elif OperationStatus.ACTIVE in status_values:
        operation_status = OperationStatus.ACTIVE
    elif OperationStatus.UNRESOLVED in status_values:
        operation_status = OperationStatus.UNRESOLVED
    elif terminal_not_committed:
        operation_status = OperationStatus.TERMINAL_NOT_COMMITTED
    else:
        operation_status = None

    active = bool(status_values & {OperationStatus.ACTIVE, OperationStatus.UNRESOLVED})
    effects_by_scope: dict[str, set[str]] = defaultdict(set)
    for effect in expected_effects:
        effects_by_scope[effect.commit_scope].add(effect.effect_id)
    fully_established_scopes = {
        scope
        for scope, effect_ids in effects_by_scope.items()
        if effect_ids <= established_effects
    }
    fully_not_established_scopes = {
        scope
        for scope, effect_ids in effects_by_scope.items()
        if effect_ids <= not_established_effects
    }

    if conflicting:
        classification = Classification.UNKNOWN
    elif all_established:
        classification = Classification.COMMITTED
    elif active:
        classification = Classification.PENDING
    elif (
        len(effects_by_scope) >= 2
        and 0 < len(fully_established_scopes) < len(effects_by_scope)
        and fully_established_scopes | fully_not_established_scopes
        == set(effects_by_scope)
    ):
        classification = Classification.PARTIAL
    elif terminal_not_committed and not established_effects:
        classification = Classification.NOT_COMMITTED
    else:
        classification = Classification.UNKNOWN

    admitted_ids = tuple(attempt.decision.evidence_id for attempt in admitted_attempts)
    proof = DeterministicProof(
        effect_findings=tuple(findings),
        operation_status=operation_status,
        conflicting_authority=conflicting,
        admitted_evidence_ids=admitted_ids,
    )

    unresolved = tuple(
        finding.effect_id
        for finding in findings
        if finding.state is not EffectAssertionState.ESTABLISHED
    )
    if classification in {Classification.COMMITTED, Classification.NOT_COMMITTED}:
        missing = ()
    else:
        if conflicting:
            reason = EvidenceReason.CONFLICTING_AUTHORITY.value
        elif classification is Classification.PENDING:
            reason = "authoritative-terminal-proof-required"
        elif classification is Classification.PARTIAL:
            reason = "authoritative-effect-proof-required"
        else:
            reported_reasons = sorted(
                {
                    attempt.decision.reason.value
                    for attempt in attempts
                    if attempt.decision.disposition is not EvidenceDisposition.ADMITTED
                }
            )
            reason = (
                reported_reasons[0]
                if reported_reasons
                else "authoritative-effect-proof-required"
            )
        missing = (MissingEvidence(effect_ids=unresolved, reason=reason),)

    policies = envelope.context.policies
    gates = _action_gates(
        classification,
        classification_policy_version=policies.classification,
        action_policy_version=policies.action,
    )
    evidence = tuple(
        attempt.evidence for attempt in attempts if attempt.evidence is not None
    )
    decisions = tuple(attempt.decision for attempt in attempts)
    return CoreEvaluation(
        envelope_sha256=envelope_sha256,
        attempts=attempts,
        evidence=evidence,
        decisions=decisions,
        proof=proof,
        classification=classification,
        action_gates=gates,
        missing_evidence=missing,
        _seal=_EVALUATION_SEAL,
    )


__all__ = [
    "CoreEvaluation",
    "evaluate_evidence",
]
