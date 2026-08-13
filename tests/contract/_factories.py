"""Deterministic public-contract examples used by contract and codec tests."""

from __future__ import annotations

import hashlib
from datetime import UTC, datetime, timedelta

from reconcile.contracts import (
    ACTION_GATE_RESULT_VERSION,
    EVIDENCE_DECISION_VERSION,
    EXECUTION_ENVELOPE_VERSION,
    EXPECTED_EFFECT_VERSION,
    INVESTIGATION_REPORT_VERSION,
    NORMALIZED_EVIDENCE_VERSION,
    OBSERVATION_CAPABILITY_VERSION,
    PROBE_REQUEST_VERSION,
    ActionGateReason,
    ActionGateResult,
    AdvisoryExplanation,
    AmbiguityKind,
    AmbiguousExecution,
    CapabilityRef,
    Classification,
    DeterministicProof,
    EffectAssertion,
    EffectAssertionState,
    EffectFinding,
    EnvelopeContext,
    EvidenceAuthority,
    EvidenceBudget,
    EvidenceDecision,
    EvidenceDisposition,
    EvidenceProvenance,
    EvidenceReason,
    ExecutionEnvelope,
    ExpectedEffect,
    FreshnessPolicy,
    FreshnessWindow,
    InvestigationReport,
    InvestigationStatus,
    MissingEvidence,
    NormalizedEvidence,
    ObservationCapability,
    OperationStatus,
    OriginalInvocation,
    PolicyReferences,
    ProbeAuditRecord,
    ProbeOutcome,
    ProbeRequest,
    RawObservationReference,
    RequestedAction,
    TargetBinding,
    TargetConstraint,
    canonical_json_bytes,
    canonical_sha256,
)
from reconcile.contracts.base import canonical_json_value_bytes

NOW = datetime(2026, 8, 13, 12, 0, tzinfo=UTC)


def make_target() -> TargetBinding:
    return TargetBinding(
        target_kind="gcs.object",
        scope={"project_id": "demo-project", "bucket_name": "demo-bucket"},
        resource={"object_name": "receipts/order-7.json"},
    )


def make_effects(*, same_scope: bool = False) -> tuple[ExpectedEffect, ...]:
    second_scope = "write" if same_scope else "audit"
    return (
        ExpectedEffect(
            schema_version=EXPECTED_EFFECT_VERSION,
            effect_id="business-record",
            commit_scope="write",
            predicate={"field": "order_id", "equals": "order-7"},
            description="The business record exists with the correlated order identifier.",
        ),
        ExpectedEffect(
            schema_version=EXPECTED_EFFECT_VERSION,
            effect_id="audit-record",
            commit_scope=second_scope,
            predicate={"field": "audit_id", "equals": "audit-7"},
            description="The audit record exists with the correlated audit identifier.",
        ),
    )


def make_envelope(*, same_scope: bool = False) -> ExecutionEnvelope:
    arguments = {"order_id": "order-7", "quantity": 2}
    invocation = OriginalInvocation(
        invocation_id="invoke-7",
        function_call_id="call-7",
        tool_name="create-order",
        tool_version="1.0.0",
        arguments=arguments,
        arguments_sha256=hashlib.sha256(
            canonical_json_value_bytes(arguments)
        ).hexdigest(),
    )
    return ExecutionEnvelope(
        schema_version=EXECUTION_ENVELOPE_VERSION,
        investigation_id="investigation-7",
        operation_id="operation-7",
        target=make_target(),
        invoked_at=NOW,
        ambiguity=AmbiguousExecution(
            kind=AmbiguityKind.MISSING_TOOL_RESULT,
            observed_at=NOW + timedelta(seconds=2),
            detail="The mutation result was not delivered to the caller.",
        ),
        expected_effects=make_effects(same_scope=same_scope),
        context=EnvelopeContext(
            invocation=invocation,
            enabled_capabilities=(
                CapabilityRef(name="gcs-object-readback", version="1.0.0"),
            ),
            correlation_fields={"order_id": "order-7"},
            evidence_budget=EvidenceBudget(
                max_probes=3,
                max_elapsed_ms=5_000,
                max_total_result_bytes=65_536,
                max_cost_units=3,
            ),
            freshness=FreshnessPolicy(max_age_seconds=60, clock_skew_seconds=5),
            policies=PolicyReferences(
                authority="authority-gcs-v1",
                classification="classification-v1",
                action="action-v1",
            ),
        ),
    )


def make_capability() -> ObservationCapability:
    return ObservationCapability(
        schema_version=OBSERVATION_CAPABILITY_VERSION,
        name="gcs-object-readback",
        version="1.0.0",
        read_only=True,
        argument_schema={
            "$schema": "https://json-schema.org/draft/2020-12/schema",
            "type": "object",
            "properties": {"order_id": {"type": "string", "minLength": 1}},
            "required": ["order_id"],
            "additionalProperties": False,
        },
        allowed_targets=(
            TargetConstraint(
                target_kind="gcs.object",
                scope={"project_id": "demo-project", "bucket_name": "demo-bucket"},
            ),
        ),
        timeout_ms=2_000,
        result_byte_ceiling=65_536,
        cost_units=1,
    )


def make_probe() -> ProbeRequest:
    return ProbeRequest(
        schema_version=PROBE_REQUEST_VERSION,
        capability_name="gcs-object-readback",
        capability_version="1.0.0",
        relevant_effect_ids=("business-record", "audit-record"),
        arguments={"order_id": "order-7"},
        rationale="Read the bound target to determine which expected effects exist.",
    )


def make_evidence(
    classification: Classification,
) -> tuple[NormalizedEvidence, EvidenceDecision]:
    states = {
        Classification.COMMITTED: (
            EffectAssertionState.ESTABLISHED,
            EffectAssertionState.ESTABLISHED,
            OperationStatus.TERMINAL_COMMITTED,
        ),
        Classification.NOT_COMMITTED: (
            EffectAssertionState.NOT_ESTABLISHED,
            EffectAssertionState.NOT_ESTABLISHED,
            OperationStatus.TERMINAL_NOT_COMMITTED,
        ),
        Classification.PARTIAL: (
            EffectAssertionState.ESTABLISHED,
            EffectAssertionState.NOT_ESTABLISHED,
            OperationStatus.TERMINAL_COMMITTED,
        ),
        Classification.PENDING: (
            EffectAssertionState.ESTABLISHED,
            EffectAssertionState.NOT_ESTABLISHED,
            OperationStatus.ACTIVE,
        ),
        Classification.UNKNOWN: (
            EffectAssertionState.UNVERIFIED,
            EffectAssertionState.UNVERIFIED,
            None,
        ),
    }
    business, audit, operation_status = states[classification]
    weak = classification is Classification.UNKNOWN
    evidence = NormalizedEvidence(
        schema_version=NORMALIZED_EVIDENCE_VERSION,
        evidence_id="evidence-7",
        capability_name="gcs-object-readback",
        capability_version="1.0.0",
        target=make_target(),
        provenance=EvidenceProvenance(
            source="gcs-json-api",
            source_record="generation-1700000000000000",
            adapter_version="1.0.0",
            retrieved_at=NOW + timedelta(seconds=4),
        ),
        observed_at=NOW + timedelta(seconds=3),
        freshness=FreshnessWindow(
            valid_from=NOW - timedelta(seconds=30),
            valid_until=NOW + timedelta(seconds=30),
        ),
        correlation={"order_id": "order-7"},
        authority=(
            EvidenceAuthority.SUPPLEMENTARY if weak else EvidenceAuthority.TARGET_STATE
        ),
        authority_policy_version="authority-gcs-v1",
        effect_assertions=(
            EffectAssertion(effect_id="business-record", state=business),
            EffectAssertion(effect_id="audit-record", state=audit),
        ),
        operation_status=operation_status,
        raw_observation=RawObservationReference(
            sha256="7" * 64,
            reference="observation:evidence-7",
            byte_count=512,
        ),
    )
    decision = EvidenceDecision(
        schema_version=EVIDENCE_DECISION_VERSION,
        evidence_id=evidence.evidence_id,
        disposition=(
            EvidenceDisposition.WEAK if weak else EvidenceDisposition.ADMITTED
        ),
        reason=(
            EvidenceReason.NON_AUTHORITATIVE_LOG_ONLY
            if weak
            else {
                Classification.COMMITTED: (
                    EvidenceReason.AUTHORITATIVE_EXACT_CORRELATION
                ),
                Classification.NOT_COMMITTED: (
                    EvidenceReason.AUTHORITATIVE_AFFIRMATIVE_NON_EXECUTION
                ),
                Classification.PARTIAL: (
                    EvidenceReason.AUTHORITATIVE_EXACT_CORRELATION
                ),
                Classification.PENDING: EvidenceReason.AUTHORITATIVE_ACTIVE_STATUS,
            }[classification]
        ),
    )
    return evidence, decision


def _gates(classification: Classification) -> tuple[ActionGateResult, ...]:
    definitions = {
        Classification.COMMITTED: (
            (RequestedAction.CONTINUE, True, ActionGateReason.ALL_EFFECTS_ESTABLISHED),
            (RequestedAction.RETRY, False, ActionGateReason.DUPLICATE_EFFECT_RISK),
            (
                RequestedAction.COMPENSATE,
                False,
                ActionGateReason.COMPENSATION_OUT_OF_SCOPE_V1,
            ),
            (
                RequestedAction.ESCALATE,
                False,
                ActionGateReason.ALL_EFFECTS_ESTABLISHED,
            ),
            (RequestedAction.OBSERVE, True, ActionGateReason.READ_ONLY_FOLLOW_UP),
        ),
        Classification.NOT_COMMITTED: (
            (
                RequestedAction.CONTINUE,
                False,
                ActionGateReason.OPERATION_NOT_COMMITTED,
            ),
            (
                RequestedAction.RETRY,
                False,
                ActionGateReason.EXPLICIT_RETRY_POLICY_REQUIRED,
            ),
            (
                RequestedAction.COMPENSATE,
                False,
                ActionGateReason.COMPENSATION_OUT_OF_SCOPE_V1,
            ),
            (
                RequestedAction.ESCALATE,
                True,
                ActionGateReason.OPERATOR_REVIEW_AVAILABLE,
            ),
            (RequestedAction.OBSERVE, True, ActionGateReason.READ_ONLY_FOLLOW_UP),
        ),
        Classification.PARTIAL: (
            (RequestedAction.CONTINUE, False, ActionGateReason.INCOMPLETE_EFFECT_SET),
            (RequestedAction.RETRY, False, ActionGateReason.DUPLICATE_EFFECT_RISK),
            (
                RequestedAction.COMPENSATE,
                False,
                ActionGateReason.COMPENSATION_OUT_OF_SCOPE_V1,
            ),
            (
                RequestedAction.ESCALATE,
                True,
                ActionGateReason.OPERATOR_INTERVENTION_REQUIRED,
            ),
            (RequestedAction.OBSERVE, True, ActionGateReason.READ_ONLY_FOLLOW_UP),
        ),
        Classification.PENDING: (
            (RequestedAction.CONTINUE, False, ActionGateReason.OPERATION_ACTIVE),
            (RequestedAction.RETRY, False, ActionGateReason.OPERATION_ACTIVE),
            (
                RequestedAction.COMPENSATE,
                False,
                ActionGateReason.COMPENSATION_OUT_OF_SCOPE_V1,
            ),
            (
                RequestedAction.ESCALATE,
                True,
                ActionGateReason.OPERATOR_INTERVENTION_REQUIRED,
            ),
            (RequestedAction.OBSERVE, True, ActionGateReason.READ_ONLY_FOLLOW_UP),
        ),
        Classification.UNKNOWN: (
            (
                RequestedAction.CONTINUE,
                False,
                ActionGateReason.INSUFFICIENT_AUTHORITATIVE_EVIDENCE,
            ),
            (
                RequestedAction.RETRY,
                False,
                ActionGateReason.AMBIGUOUS_DUPLICATE_RISK,
            ),
            (
                RequestedAction.COMPENSATE,
                False,
                ActionGateReason.COMPENSATION_OUT_OF_SCOPE_V1,
            ),
            (
                RequestedAction.ESCALATE,
                True,
                ActionGateReason.OPERATOR_INTERVENTION_REQUIRED,
            ),
            (RequestedAction.OBSERVE, True, ActionGateReason.READ_ONLY_FOLLOW_UP),
        ),
    }
    return tuple(
        ActionGateResult(
            schema_version=ACTION_GATE_RESULT_VERSION,
            requested_action=action,
            allowed=allowed,
            reason=reason,
            classification=classification,
            classification_policy_version="classification-v1",
            action_policy_version="action-v1",
            escalation_required=classification is not Classification.COMMITTED,
        )
        for action, allowed, reason in definitions[classification]
    )


def make_report(classification: Classification) -> InvestigationReport:
    envelope = make_envelope()
    probe = make_probe()
    evidence, decision = make_evidence(classification)
    admitted_ids = (
        (evidence.evidence_id,)
        if decision.disposition is EvidenceDisposition.ADMITTED
        else ()
    )
    findings = tuple(
        EffectFinding(
            effect_id=assertion.effect_id,
            commit_scope=envelope.expected_effects[index].commit_scope,
            state=assertion.state,
            evidence_ids=admitted_ids,
        )
        for index, assertion in enumerate(evidence.effect_assertions)
    )
    missing = ()
    if classification in {
        Classification.PARTIAL,
        Classification.PENDING,
        Classification.UNKNOWN,
    }:
        missing = (
            MissingEvidence(
                effect_ids=(
                    ("business-record", "audit-record")
                    if classification is Classification.UNKNOWN
                    else ("audit-record",)
                ),
                reason=(
                    "authoritative-effect-proof-required"
                    if classification is Classification.PARTIAL
                    else (
                        "non_authoritative_log_only"
                        if classification is Classification.UNKNOWN
                        else "authoritative-terminal-proof-required"
                    )
                ),
            ),
        )
    return InvestigationReport(
        schema_version=INVESTIGATION_REPORT_VERSION,
        investigation_id=envelope.investigation_id,
        envelope_sha256=canonical_sha256(envelope),
        status=InvestigationStatus.COMPLETED,
        probe_audit=(
            ProbeAuditRecord(
                probe_sequence=1,
                capability_name=probe.capability_name,
                capability_version=probe.capability_version,
                request_sha256=hashlib.sha256(
                    canonical_json_value_bytes(
                        {
                            "arguments": probe.arguments,
                            "capability_name": probe.capability_name,
                            "capability_version": probe.capability_version,
                            "relevant_effect_ids": sorted(probe.relevant_effect_ids),
                        }
                    )
                ).hexdigest(),
                target_sha256=canonical_sha256(envelope.target),
                outcome=ProbeOutcome.COMPLETED,
                stop_reason="probe_completed",
                started_at=NOW + timedelta(seconds=2),
                completed_at=NOW + timedelta(seconds=4),
                session_elapsed_ms=2_000,
                probe_count_used=1,
                cost_units_used=1,
                result_bytes_acquired=512,
                result_sha256=evidence.raw_observation.sha256,
                result_byte_count=evidence.raw_observation.byte_count,
                evidence_ids=(evidence.evidence_id,),
            ),
        ),
        evidence=(evidence,),
        evidence_decisions=(decision,),
        proof=DeterministicProof(
            effect_findings=findings,
            operation_status=evidence.operation_status,
            admitted_evidence_ids=admitted_ids,
        ),
        classification=classification,
        action_gate=_gates(classification),
        missing_evidence=missing,
        limitations=("No mutation was retried or compensated.",),
        advisory_explanation=AdvisoryExplanation(
            text="The explanation cites only retained evidence.",
            cited_evidence_ids=(evidence.evidence_id,),
        ),
        created_at=NOW,
        updated_at=NOW + timedelta(seconds=5),
        revision=1,
    )


def public_examples() -> tuple[object, ...]:
    envelope = make_envelope()
    capability = make_capability()
    probe = make_probe()
    evidence, decision = make_evidence(Classification.COMMITTED)
    return (
        envelope.expected_effects[0],
        envelope,
        capability,
        probe,
        evidence,
        decision,
        make_report(Classification.COMMITTED).action_gate[0],
        make_report(Classification.COMMITTED),
    )


def canonical_example_bytes(classification: Classification) -> bytes:
    return canonical_json_bytes(make_report(classification))
