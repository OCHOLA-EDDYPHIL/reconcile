"""Deterministic normalization and admission of bounded probe observations."""

from __future__ import annotations

import hashlib
import inspect
from dataclasses import dataclass, field
from datetime import UTC, timedelta
from threading import RLock
from weakref import WeakSet

from reconcile.contracts import (
    EVIDENCE_DECISION_VERSION,
    NORMALIZED_EVIDENCE_VERSION,
    EvidenceAuthority,
    EvidenceDecision,
    EvidenceDisposition,
    EvidenceProvenance,
    EvidenceReason,
    ExecutionEnvelope,
    FreshnessWindow,
    NormalizedEvidence,
    ProbeOutcome,
    ProbeRequest,
    RawObservationReference,
    canonical_json_bytes,
    canonical_sha256,
    decode_contract,
)
from reconcile.contracts.base import canonical_json_value_bytes
from reconcile.controller import (
    ProbeExecution,
    ProbeObservation,
    ProbeStopReason,
    probe_request_sha256,
)
from reconcile.evidence.rules import (
    RuleInput,
    RuleObservation,
    RuleRejected,
    RuleVerdict,
    TargetRuleRegistry,
)


@dataclass(frozen=True, slots=True, init=False)
class ProbeRun:
    _request_bytes: bytes = field(repr=False)
    execution: ProbeExecution

    def __init__(self, *, request: ProbeRequest, execution: ProbeExecution) -> None:
        if type(execution) is not ProbeExecution:
            raise TypeError("probe execution must be exact")
        if not execution.is_controller_output():
            raise TypeError("probe execution must come from the controller")
        object.__setattr__(self, "_request_bytes", canonical_json_bytes(request))
        object.__setattr__(self, "execution", execution)

    @property
    def request(self) -> ProbeRequest:
        return decode_contract(self._request_bytes, ProbeRequest)


_ATTEMPT_SEAL = object()
_ATTEMPT_LOCK = RLock()
_VALID_ATTEMPTS: WeakSet[EvidenceAttempt] = WeakSet()


@dataclass(frozen=True, slots=True, init=False, eq=False, weakref_slot=True)
class EvidenceAttempt:
    envelope_sha256: str
    controller_audit_sha256: str
    request_sha256: str | None
    probe_sequence: int
    raw_sha256: str | None
    _evidence_bytes: bytes | None = field(repr=False)
    _decision_bytes: bytes = field(repr=False)

    def __init__(
        self,
        *,
        envelope_sha256: str,
        controller_audit_sha256: str,
        request_sha256: str | None,
        probe_sequence: int,
        raw_sha256: str | None,
        evidence: NormalizedEvidence | None,
        decision: EvidenceDecision,
        _seal: object,
    ) -> None:
        if _seal is not _ATTEMPT_SEAL:
            raise TypeError("evidence attempts are created only by the pipeline")
        if probe_sequence < 1:
            raise ValueError("evidence attempt sequence must be positive")
        decision_bytes = canonical_json_bytes(decision)
        validated_decision = decode_contract(decision_bytes, EvidenceDecision)
        evidence_bytes = (
            canonical_json_bytes(evidence) if evidence is not None else None
        )
        validated_evidence = (
            decode_contract(evidence_bytes, NormalizedEvidence)
            if evidence_bytes is not None
            else None
        )
        if (
            validated_evidence is not None
            and validated_evidence.evidence_id != validated_decision.evidence_id
        ):
            raise ValueError("evidence attempt identifiers must agree")
        object.__setattr__(self, "envelope_sha256", envelope_sha256)
        object.__setattr__(
            self,
            "controller_audit_sha256",
            controller_audit_sha256,
        )
        object.__setattr__(self, "request_sha256", request_sha256)
        object.__setattr__(self, "probe_sequence", probe_sequence)
        object.__setattr__(self, "raw_sha256", raw_sha256)
        object.__setattr__(self, "_evidence_bytes", evidence_bytes)
        object.__setattr__(self, "_decision_bytes", decision_bytes)
        with _ATTEMPT_LOCK:
            _VALID_ATTEMPTS.add(self)

    @property
    def evidence(self) -> NormalizedEvidence | None:
        if self._evidence_bytes is None:
            return None
        return decode_contract(self._evidence_bytes, NormalizedEvidence)

    @property
    def decision(self) -> EvidenceDecision:
        return decode_contract(self._decision_bytes, EvidenceDecision)

    def reject_duplicate(self) -> EvidenceAttempt:
        """Return the only permitted conservative decision replacement."""

        if not self.is_pipeline_output():
            raise TypeError("duplicate rejection accepts only pipeline output")
        return EvidenceAttempt(
            envelope_sha256=self.envelope_sha256,
            controller_audit_sha256=self.controller_audit_sha256,
            request_sha256=self.request_sha256,
            probe_sequence=self.probe_sequence,
            raw_sha256=self.raw_sha256,
            evidence=self.evidence,
            decision=EvidenceDecision(
                schema_version=EVIDENCE_DECISION_VERSION,
                evidence_id=self.decision.evidence_id,
                disposition=EvidenceDisposition.REJECTED,
                reason=EvidenceReason.DUPLICATE_CANDIDATES,
            ),
            _seal=_ATTEMPT_SEAL,
        )

    def is_pipeline_output(self) -> bool:
        with _ATTEMPT_LOCK:
            return self in _VALID_ATTEMPTS


_FAILED_PROBE_REASONS = {
    ProbeOutcome.TIMED_OUT: EvidenceReason.PROBE_TIMEOUT,
    ProbeOutcome.MALFORMED: EvidenceReason.MALFORMED_OBSERVATION,
    ProbeOutcome.BUDGET_EXHAUSTED: EvidenceReason.BUDGET_EXHAUSTED,
}


class EvidencePipeline:
    """One investigation's exact target-rule and common admission boundary."""

    def __init__(
        self,
        envelope: ExecutionEnvelope,
        registry: TargetRuleRegistry,
    ) -> None:
        self._envelope_bytes = canonical_json_bytes(envelope)
        self._envelope = decode_contract(self._envelope_bytes, ExecutionEnvelope)
        self._envelope_sha256 = canonical_sha256(self._envelope)
        registry.freeze()
        self._registry = registry
        self._target_sha256 = hashlib.sha256(
            canonical_json_bytes(self._envelope.target)
        ).hexdigest()
        self._effect_ids = {
            effect.effect_id for effect in self._envelope.expected_effects
        }
        self._next_sequence = 1
        self._controller_session: object | None = None

    def _evidence_id(
        self,
        *,
        sequence: int,
        request_sha256: str | None,
        raw_sha256: str | None,
        outcome: ProbeOutcome,
    ) -> str:
        material = {
            "investigation_id": self._envelope.investigation_id,
            "outcome": outcome.value,
            "probe_sequence": sequence,
            "raw_sha256": raw_sha256,
            "request_sha256": request_sha256,
            "target_sha256": self._target_sha256,
        }
        digest = hashlib.sha256(canonical_json_value_bytes(material)).hexdigest()
        return f"evidence:{digest}"

    @staticmethod
    def _decision(
        evidence_id: str,
        disposition: EvidenceDisposition,
        reason: EvidenceReason,
    ) -> EvidenceDecision:
        return EvidenceDecision(
            schema_version=EVIDENCE_DECISION_VERSION,
            evidence_id=evidence_id,
            disposition=disposition,
            reason=reason,
        )

    def _rejected_attempt(
        self,
        *,
        sequence: int,
        request_sha256: str | None,
        raw_sha256: str | None,
        outcome: ProbeOutcome,
        reason: EvidenceReason,
        controller_audit_sha256: str,
        evidence: NormalizedEvidence | None = None,
    ) -> EvidenceAttempt:
        evidence_id = self._evidence_id(
            sequence=sequence,
            request_sha256=request_sha256,
            raw_sha256=raw_sha256,
            outcome=outcome,
        )
        if evidence is not None and evidence.evidence_id != evidence_id:
            raise ValueError("normalized evidence identifier is not deterministic")
        return EvidenceAttempt(
            envelope_sha256=self._envelope_sha256,
            controller_audit_sha256=controller_audit_sha256,
            request_sha256=request_sha256,
            probe_sequence=sequence,
            raw_sha256=raw_sha256,
            evidence=evidence,
            decision=self._decision(
                evidence_id,
                EvidenceDisposition.REJECTED,
                reason,
            ),
            _seal=_ATTEMPT_SEAL,
        )

    def normalize(
        self,
        run: ProbeRun,
    ) -> EvidenceAttempt:
        if type(run) is not ProbeRun:
            raise TypeError("probe run must be exact")
        request = run.request
        execution = run.execution
        audit = execution.audit
        if audit.sequence != self._next_sequence:
            raise ValueError("probe runs must be normalized in contiguous order")
        self._next_sequence += 1
        controller_session = execution._session_token()
        if self._controller_session is None:
            self._controller_session = controller_session
        same_controller_session = self._controller_session is controller_session
        retrieved_at = audit.completed_at.astimezone(UTC)
        controller_audit_sha256 = canonical_sha256(audit)
        expected_request_sha256 = probe_request_sha256(request)
        integrity_valid = (
            execution.envelope_sha256 == self._envelope_sha256
            and same_controller_session
            and audit.target_sha256 == self._target_sha256
            and audit.request_sha256 in {None, expected_request_sha256}
            and (
                audit.capability_name is None
                or audit.capability_name == request.capability_name
            )
            and (
                audit.capability_version is None
                or audit.capability_version == request.capability_version
            )
        )
        if not integrity_valid:
            return self._rejected_attempt(
                sequence=audit.sequence,
                request_sha256=audit.request_sha256,
                raw_sha256=None,
                outcome=audit.outcome,
                reason=EvidenceReason.MALFORMED_OBSERVATION,
                controller_audit_sha256=controller_audit_sha256,
            )

        if audit.outcome is not ProbeOutcome.COMPLETED:
            reason = _FAILED_PROBE_REASONS.get(
                audit.outcome,
                EvidenceReason.UNVERIFIABLE_AUTHORITY,
            )
            if audit.stop_reason is ProbeStopReason.RESULT_TOO_LARGE:
                reason = EvidenceReason.RESULT_TOO_LARGE
            return self._rejected_attempt(
                sequence=audit.sequence,
                request_sha256=audit.request_sha256,
                raw_sha256=None,
                outcome=audit.outcome,
                reason=reason,
                controller_audit_sha256=controller_audit_sha256,
            )

        observation = execution.observation
        if observation is None:
            return self._rejected_attempt(
                sequence=audit.sequence,
                request_sha256=audit.request_sha256,
                raw_sha256=None,
                outcome=audit.outcome,
                reason=EvidenceReason.MALFORMED_OBSERVATION,
                controller_audit_sha256=controller_audit_sha256,
            )
        raw_sha256 = hashlib.sha256(observation.canonical_json).hexdigest()
        try:
            parsed_observation = ProbeObservation.model_validate_json(
                observation.canonical_json
            )
            canonical_observation = canonical_json_bytes(parsed_observation)
        except (TypeError, ValueError):
            canonical_observation = b""
        if (
            raw_sha256 != observation.sha256
            or observation.byte_count != len(observation.canonical_json)
            or canonical_observation != observation.canonical_json
            or audit.result_sha256 != observation.sha256
            or audit.result_byte_count != observation.byte_count
            or audit.capability_name != request.capability_name
            or audit.capability_version != request.capability_version
            or audit.request_sha256 != expected_request_sha256
        ):
            return self._rejected_attempt(
                sequence=audit.sequence,
                request_sha256=audit.request_sha256,
                raw_sha256=raw_sha256,
                outcome=audit.outcome,
                reason=EvidenceReason.MALFORMED_OBSERVATION,
                controller_audit_sha256=controller_audit_sha256,
            )

        evidence_id = self._evidence_id(
            sequence=audit.sequence,
            request_sha256=audit.request_sha256,
            raw_sha256=raw_sha256,
            outcome=audit.outcome,
        )
        policies = self._envelope.context.policies
        key = (
            self._envelope.target.target_kind,
            request.capability_name,
            request.capability_version,
            policies.authority,
            policies.classification,
        )
        registration = self._registry.resolve(key)
        if registration is None:
            return self._rejected_attempt(
                sequence=audit.sequence,
                request_sha256=audit.request_sha256,
                raw_sha256=raw_sha256,
                outcome=audit.outcome,
                reason=EvidenceReason.UNSUPPORTED_CAPABILITY,
                controller_audit_sha256=controller_audit_sha256,
            )

        try:
            rule_result = registration.normalizer(
                RuleInput(
                    envelope=self._envelope,
                    request=request,
                    observation=observation.canonical_json,
                    retrieved_at=retrieved_at,
                )
            )
            if inspect.isawaitable(rule_result):
                raise TypeError("target rule returned an awaitable")
            rule_result = RuleObservation.model_validate(rule_result)
        except RuleRejected as error:
            return self._rejected_attempt(
                sequence=audit.sequence,
                request_sha256=audit.request_sha256,
                raw_sha256=raw_sha256,
                outcome=audit.outcome,
                reason=error.reason,
                controller_audit_sha256=controller_audit_sha256,
            )
        except Exception:
            return self._rejected_attempt(
                sequence=audit.sequence,
                request_sha256=audit.request_sha256,
                raw_sha256=raw_sha256,
                outcome=audit.outcome,
                reason=EvidenceReason.MALFORMED_OBSERVATION,
                controller_audit_sha256=controller_audit_sha256,
            )

        descriptor = registration.descriptor
        try:
            skew = timedelta(
                seconds=self._envelope.context.freshness.clock_skew_seconds
            )
            max_age = timedelta(
                seconds=self._envelope.context.freshness.max_age_seconds
            )
            freshness_horizon = max_age + skew
            freshness = FreshnessWindow(
                valid_from=rule_result.observed_at - skew,
                valid_until=rule_result.observed_at + freshness_horizon,
            )
        except (OverflowError, ValueError):
            return self._rejected_attempt(
                sequence=audit.sequence,
                request_sha256=audit.request_sha256,
                raw_sha256=raw_sha256,
                outcome=audit.outcome,
                reason=EvidenceReason.CLOCK_AMBIGUITY,
                controller_audit_sha256=controller_audit_sha256,
            )
        authority = {
            RuleVerdict.AUTHORITATIVE_EFFECTS: EvidenceAuthority.TARGET_STATE,
            RuleVerdict.AUTHORITATIVE_NON_EXECUTION: EvidenceAuthority.TARGET_STATE,
            RuleVerdict.AUTHORITATIVE_PENDING: EvidenceAuthority.TARGET_STATE,
            RuleVerdict.SUPPLEMENTARY: EvidenceAuthority.SUPPLEMENTARY,
            RuleVerdict.ABSENCE_ONLY: EvidenceAuthority.WEAK,
        }[rule_result.verdict]
        try:
            normalized = NormalizedEvidence(
                schema_version=NORMALIZED_EVIDENCE_VERSION,
                evidence_id=evidence_id,
                capability_name=request.capability_name,
                capability_version=request.capability_version,
                target=rule_result.target,
                provenance=EvidenceProvenance(
                    source=descriptor.source,
                    source_record=rule_result.source_record,
                    adapter_version=descriptor.adapter_version,
                    retrieved_at=retrieved_at,
                ),
                observed_at=rule_result.observed_at,
                freshness=freshness,
                correlation=rule_result.correlation,
                authority=authority,
                authority_policy_version=descriptor.authority_policy_version,
                effect_assertions=rule_result.effect_assertions,
                operation_status=rule_result.operation_status,
                raw_observation=RawObservationReference(
                    sha256=raw_sha256,
                    reference=f"observation:{raw_sha256}",
                    byte_count=observation.byte_count,
                ),
            )
        except (TypeError, ValueError):
            return self._rejected_attempt(
                sequence=audit.sequence,
                request_sha256=audit.request_sha256,
                raw_sha256=raw_sha256,
                outcome=audit.outcome,
                reason=EvidenceReason.MALFORMED_OBSERVATION,
                controller_audit_sha256=controller_audit_sha256,
            )

        target_matches = canonical_json_bytes(
            normalized.target
        ) == canonical_json_bytes(self._envelope.target)
        if not target_matches:
            return self._rejected_attempt(
                sequence=audit.sequence,
                request_sha256=audit.request_sha256,
                raw_sha256=raw_sha256,
                outcome=audit.outcome,
                reason=EvidenceReason.SCOPE_MISMATCH,
                controller_audit_sha256=controller_audit_sha256,
                evidence=normalized,
            )
        authoritative = authority is EvidenceAuthority.TARGET_STATE
        if authoritative and rule_result.operation_id != self._envelope.operation_id:
            return self._rejected_attempt(
                sequence=audit.sequence,
                request_sha256=audit.request_sha256,
                raw_sha256=raw_sha256,
                outcome=audit.outcome,
                reason=EvidenceReason.CORRELATION_MISMATCH,
                controller_audit_sha256=controller_audit_sha256,
                evidence=normalized,
            )
        if any(
            key not in normalized.correlation
            or canonical_json_value_bytes(normalized.correlation[key])
            != canonical_json_value_bytes(expected)
            for key, expected in self._envelope.context.correlation_fields.items()
        ):
            return self._rejected_attempt(
                sequence=audit.sequence,
                request_sha256=audit.request_sha256,
                raw_sha256=raw_sha256,
                outcome=audit.outcome,
                reason=EvidenceReason.CORRELATION_MISMATCH,
                controller_audit_sha256=controller_audit_sha256,
                evidence=normalized,
            )
        asserted_effect_ids = {
            assertion.effect_id for assertion in normalized.effect_assertions
        }
        if (
            not asserted_effect_ids <= self._effect_ids
            or not asserted_effect_ids <= set(request.relevant_effect_ids)
        ):
            return self._rejected_attempt(
                sequence=audit.sequence,
                request_sha256=audit.request_sha256,
                raw_sha256=raw_sha256,
                outcome=audit.outcome,
                reason=EvidenceReason.EXPECTED_EFFECT_MISMATCH,
                controller_audit_sha256=controller_audit_sha256,
                evidence=normalized,
            )
        if (
            normalized.observed_at > retrieved_at
            and normalized.observed_at - retrieved_at > skew
        ):
            return self._rejected_attempt(
                sequence=audit.sequence,
                request_sha256=audit.request_sha256,
                raw_sha256=raw_sha256,
                outcome=audit.outcome,
                reason=EvidenceReason.CLOCK_AMBIGUITY,
                controller_audit_sha256=controller_audit_sha256,
                evidence=normalized,
            )
        if (
            normalized.observed_at < self._envelope.invoked_at
            and self._envelope.invoked_at - normalized.observed_at > skew
        ) or retrieved_at - normalized.observed_at > freshness_horizon:
            return self._rejected_attempt(
                sequence=audit.sequence,
                request_sha256=audit.request_sha256,
                raw_sha256=raw_sha256,
                outcome=audit.outcome,
                reason=EvidenceReason.STALE_OBSERVATION,
                controller_audit_sha256=controller_audit_sha256,
                evidence=normalized,
            )

        disposition, reason = {
            RuleVerdict.AUTHORITATIVE_EFFECTS: (
                EvidenceDisposition.ADMITTED,
                EvidenceReason.AUTHORITATIVE_EXACT_CORRELATION,
            ),
            RuleVerdict.AUTHORITATIVE_NON_EXECUTION: (
                EvidenceDisposition.ADMITTED,
                EvidenceReason.AUTHORITATIVE_AFFIRMATIVE_NON_EXECUTION,
            ),
            RuleVerdict.AUTHORITATIVE_PENDING: (
                EvidenceDisposition.ADMITTED,
                EvidenceReason.AUTHORITATIVE_ACTIVE_STATUS,
            ),
            RuleVerdict.SUPPLEMENTARY: (
                EvidenceDisposition.WEAK,
                EvidenceReason.NON_AUTHORITATIVE_LOG_ONLY,
            ),
            RuleVerdict.ABSENCE_ONLY: (
                EvidenceDisposition.WEAK,
                EvidenceReason.NOT_FOUND_ABSENCE_ONLY,
            ),
        }[rule_result.verdict]
        return EvidenceAttempt(
            envelope_sha256=self._envelope_sha256,
            controller_audit_sha256=controller_audit_sha256,
            request_sha256=audit.request_sha256,
            probe_sequence=audit.sequence,
            raw_sha256=raw_sha256,
            evidence=normalized,
            decision=self._decision(evidence_id, disposition, reason),
            _seal=_ATTEMPT_SEAL,
        )


__all__ = [
    "EvidenceAttempt",
    "EvidencePipeline",
    "ProbeRun",
]
