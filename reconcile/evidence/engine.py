"""Single deterministic path from probe executions to a completed report."""

from __future__ import annotations

from datetime import datetime

from reconcile.contracts import (
    AdvisoryExplanation,
    ExecutionEnvelope,
    InvestigationReport,
    canonical_json_bytes,
    decode_contract,
)
from reconcile.controller import ControllerAuditRecord
from reconcile.evidence.admission import EvidenceAttempt, EvidencePipeline, ProbeRun
from reconcile.evidence.classification import CoreEvaluation, evaluate_evidence
from reconcile.evidence.reporting import build_report
from reconcile.evidence.rules import TargetRuleRegistry


class EvidenceEngine:
    """Own one investigation's target-rule outputs and deterministic result."""

    def __init__(
        self,
        envelope: ExecutionEnvelope,
        registry: TargetRuleRegistry,
    ) -> None:
        self._envelope_bytes = canonical_json_bytes(envelope)
        self._envelope = decode_contract(self._envelope_bytes, ExecutionEnvelope)
        self._pipeline = EvidencePipeline(self._envelope, registry)
        self._attempts: dict[int, EvidenceAttempt] = {}

    @property
    def attempts(self) -> tuple[EvidenceAttempt, ...]:
        return tuple(self._attempts[key] for key in sorted(self._attempts))

    def process(
        self,
        run: ProbeRun,
    ) -> EvidenceAttempt:
        attempt = self._pipeline.normalize(run)
        if attempt.probe_sequence in self._attempts:
            raise ValueError("probe sequence already has an evidence attempt")
        self._attempts[attempt.probe_sequence] = attempt
        return attempt

    def evaluate(
        self,
        audit_trail: tuple[ControllerAuditRecord, ...],
    ) -> CoreEvaluation:
        return evaluate_evidence(self._envelope, self.attempts, audit_trail)

    def report(
        self,
        audit_trail: tuple[ControllerAuditRecord, ...],
        *,
        created_at: datetime,
        updated_at: datetime,
        revision: int,
        advisory_explanation: AdvisoryExplanation | None = None,
    ) -> InvestigationReport:
        return build_report(
            self._envelope,
            audit_trail,
            self.evaluate(audit_trail),
            created_at=created_at,
            updated_at=updated_at,
            revision=revision,
            advisory_explanation=advisory_explanation,
        )


__all__ = ["EvidenceEngine"]
