"""Deterministic public-contract examples used by contract and codec tests."""

from __future__ import annotations

import hashlib
from datetime import UTC, datetime, timedelta

from reconcile.contracts import (
    ACTION_GATE_RESULT_VERSION,
    ACTION_PERMIT_VERSION,
    ADAPTIVE_PLANNER_INPUT_VERSION,
    ADAPTIVE_PLANNER_OUTPUT_VERSION,
    AMBIGUITY_WITNESS_VERSION,
    ERROR_VERSION,
    EVIDENCE_DECISION_VERSION,
    EXECUTION_ENVELOPE_VERSION,
    EXPECTED_EFFECT_VERSION,
    GEMINI_HYPOTHESIS_VERSION,
    INVESTIGATION_COMPARISON_RECORD_VERSION,
    INVESTIGATION_EVENT_VERSION,
    INVESTIGATION_REPORT_VERSION,
    NORMALIZED_EVIDENCE_VERSION,
    OBSERVATION_CAPABILITY_VERSION,
    PROBE_REQUEST_VERSION,
    RECOVERY_ACTION_SCOPE_VERSION,
    RECOVERY_CHAIN_VERSION,
    RECOVERY_DISPATCH_RECEIPT_VERSION,
    RECOVERY_LAUNCH_PERMIT_VERSION,
    RECOVERY_POLICY_COMPARISON_VERSION,
    RECOVERY_POLICY_RESULT_VERSION,
    RECOVERY_RESET_RESULT_VERSION,
    RECOVERY_RUN_EVENT_VERSION,
    RECOVERY_RUN_REQUEST_VERSION,
    RECOVERY_RUN_SNAPSHOT_VERSION,
    SCENARIO_CLEANUP_REQUEST_VERSION,
    SCENARIO_CLEANUP_RESULT_VERSION,
    SCENARIO_FAULT_TRACE_VERSION,
    SCENARIO_RUN_REQUEST_VERSION,
    SCENARIO_RUN_RESULT_VERSION,
    VERIFIED_CERTIFICATE_VERSION,
    ActionGateEventPayload,
    ActionGateReason,
    ActionGateResult,
    ActionPermit,
    ActionPermitState,
    AdaptivePlannerInput,
    AdaptivePlannerOutput,
    AdaptivePlannerPhase,
    AdvisoryExplanation,
    AmbiguityKind,
    AmbiguityWitness,
    AmbiguousExecution,
    ApiError,
    ApiErrorCode,
    CapabilityRef,
    CertifiedTransition,
    Classification,
    ClassificationEventPayload,
    ComparisonModelUsage,
    ComparisonModelUsageStatus,
    ComparisonRun,
    ComparisonStrategyKind,
    DeterministicProof,
    DiscriminatingObservation,
    EffectAssertion,
    EffectAssertionState,
    EffectFinding,
    EnvelopeContext,
    EvidenceAuthority,
    EvidenceBudget,
    EvidenceDecision,
    EvidenceDecisionEventPayload,
    EvidenceDisposition,
    EvidenceProvenance,
    EvidenceReason,
    ExecutionEnvelope,
    ExecutionEnvelopeReference,
    ExpectedEffect,
    ExplanationCompleteness,
    FreshnessPolicy,
    FreshnessWindow,
    GeminiHypothesis,
    HypothesizedEffect,
    InvestigationComparisonRecord,
    InvestigationEvent,
    InvestigationEventType,
    InvestigationReport,
    InvestigationStatus,
    LifecycleEventPayload,
    MissingEvidence,
    NormalizedEvidence,
    ObservationCapability,
    OperationStatus,
    OriginalInvocation,
    PermitAction,
    PlannerAcquisitionAdvice,
    PlannerAdmittedEvidence,
    PlannerCapability,
    PlannerCitationRefs,
    PlannerExplanation,
    PlannerMissingEvidence,
    PlannerMissingEvidenceNote,
    PlannerRejectedEvidence,
    PlannerRemainingBudget,
    PlannerStopAdvice,
    PlannerVersionMetadata,
    PlannerWeakEvidence,
    PolicyReferences,
    PossibleHistory,
    PreregisteredExpectedClassification,
    ProbeAuditRecord,
    ProbeEventPayload,
    ProbeOutcome,
    ProbeRequest,
    ProposedTransition,
    QualificationCaseResult,
    QualificationDisposition,
    QualificationLaneOrder,
    QualificationProviderSettings,
    QualificationResultSet,
    QualificationSuiteManifest,
    QualificationSummary,
    RawObservationReference,
    RecoveryActionNode,
    RecoveryActionScope,
    RecoveryAuthorityKind,
    RecoveryChain,
    RecoveryCloudRunObservation,
    RecoveryDispatchReceipt,
    RecoveryEvidenceBinding,
    RecoveryFirestoreObservation,
    RecoveryLaunchPermit,
    RecoveryLaunchPermitState,
    RecoveryMutationCounters,
    RecoveryNodeProgress,
    RecoveryNodeState,
    RecoveryPolicyComparison,
    RecoveryPolicyResult,
    RecoveryReceiptOutcome,
    RecoveryResetResult,
    RecoveryRunEvent,
    RecoveryRunEventPayload,
    RecoveryRunEventType,
    RecoveryRunFault,
    RecoveryRunLifecycle,
    RecoveryRunPolicy,
    RecoveryRunRequest,
    RecoveryRunSnapshot,
    RecoveryTimelineEntry,
    RequestedAction,
    ScenarioCallerObservation,
    ScenarioCleanupDisposition,
    ScenarioCleanupRequest,
    ScenarioCleanupResult,
    ScenarioFaultAction,
    ScenarioFaultInstruction,
    ScenarioFaultPoint,
    ScenarioFaultTrace,
    ScenarioFixtureRef,
    ScenarioRef,
    ScenarioRunRequest,
    ScenarioRunResult,
    ScenarioTraceEvent,
    ScenarioTransportEvent,
    ScenarioWorkerTermination,
    SemanticActionIdentity,
    TargetBinding,
    TargetConstraint,
    VerifiedCertificate,
    canonical_json_bytes,
    canonical_sha256,
    semantic_action_sha256,
)
from reconcile.contracts.base import canonical_json_value_bytes
from reconcile.qualification import (
    build_failed_result,
    build_qualification_manifest,
    build_result_set,
    derive_disposition,
    summarize_qualification,
)

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


def make_scenario_request() -> ScenarioRunRequest:
    return ScenarioRunRequest(
        schema_version=SCENARIO_RUN_REQUEST_VERSION,
        scenario=ScenarioRef(name="storage-object", version="1.0.0"),
        run_id="run-7",
        investigation_id="investigation-7",
        operation_id="operation-7",
        invocation_id="invoke-7",
        function_call_id="call-7",
        seed=7,
        fault=ScenarioFaultInstruction(
            point=ScenarioFaultPoint.POST_RESPONSE,
            action=ScenarioFaultAction.DROP_RESPONSE,
        ),
    )


def make_scenario_trace() -> ScenarioFaultTrace:
    request = make_scenario_request()
    return ScenarioFaultTrace(
        schema_version=SCENARIO_FAULT_TRACE_VERSION,
        scenario=request.scenario,
        run_id=request.run_id,
        investigation_id=request.investigation_id,
        operation_id=request.operation_id,
        invocation_id=request.invocation_id,
        function_call_id=request.function_call_id,
        configured_fault=request.fault,
        events=(
            ScenarioTraceEvent(
                sequence=1,
                event=ScenarioTransportEvent.RUN_STARTED,
                occurred_at=NOW,
            ),
            ScenarioTraceEvent(
                sequence=2,
                event=ScenarioTransportEvent.DISPATCH_STARTED,
                occurred_at=NOW + timedelta(milliseconds=1),
            ),
            ScenarioTraceEvent(
                sequence=3,
                event=ScenarioTransportEvent.PRE_COMMIT_REACHED,
                occurred_at=NOW + timedelta(milliseconds=2),
            ),
            ScenarioTraceEvent(
                sequence=4,
                event=ScenarioTransportEvent.POST_COMMIT_REACHED,
                occurred_at=NOW + timedelta(milliseconds=3),
            ),
            ScenarioTraceEvent(
                sequence=5,
                event=ScenarioTransportEvent.RESPONSE_AVAILABLE,
                occurred_at=NOW + timedelta(milliseconds=4),
            ),
            ScenarioTraceEvent(
                sequence=6,
                event=ScenarioTransportEvent.RESPONSE_DROPPED,
                occurred_at=NOW + timedelta(milliseconds=5),
            ),
            ScenarioTraceEvent(
                sequence=7,
                event=ScenarioTransportEvent.RUN_COMPLETED,
                occurred_at=NOW + timedelta(milliseconds=6),
            ),
        ),
        caller_observation=ScenarioCallerObservation.NO_RESPONSE,
        worker_termination=ScenarioWorkerTermination.EXITED,
        exit_code=0,
        applied_delay_ms=0,
        response_sha256="a" * 64,
        response_byte_count=128,
        started_at=NOW,
        completed_at=NOW + timedelta(milliseconds=6),
    )


def make_scenario_result() -> ScenarioRunResult:
    request = make_scenario_request()
    trace = make_scenario_trace()
    base = make_envelope()
    envelope = ExecutionEnvelope(
        schema_version=EXECUTION_ENVELOPE_VERSION,
        investigation_id=request.investigation_id,
        operation_id=request.operation_id,
        target=base.target,
        invoked_at=base.invoked_at,
        ambiguity=AmbiguousExecution(
            kind=AmbiguityKind.MISSING_TOOL_RESULT,
            observed_at=NOW + timedelta(milliseconds=5),
            detail="The mutation result was not delivered to the caller.",
        ),
        expected_effects=base.expected_effects,
        context=EnvelopeContext(
            invocation=base.context.invocation,
            enabled_capabilities=base.context.enabled_capabilities,
            correlation_fields=base.context.correlation_fields,
            evidence_budget=base.context.evidence_budget,
            freshness=base.context.freshness,
            policies=base.context.policies,
        ),
    )
    return ScenarioRunResult(
        schema_version=SCENARIO_RUN_RESULT_VERSION,
        request_sha256=canonical_sha256(request),
        scenario=request.scenario,
        run_id=request.run_id,
        investigation_id=envelope.investigation_id,
        operation_id=envelope.operation_id,
        invocation_id=base.context.invocation.invocation_id,
        function_call_id=base.context.invocation.function_call_id,
        fixture=ScenarioFixtureRef(
            namespace_id="scenario-run-7",
            cleanup_manifest_sha256="c" * 64,
        ),
        trace=trace,
        execution_envelope=envelope,
    )


def make_cleanup_request() -> ScenarioCleanupRequest:
    request = make_scenario_request()
    fixture = make_scenario_result().fixture
    return ScenarioCleanupRequest(
        schema_version=SCENARIO_CLEANUP_REQUEST_VERSION,
        scenario=request.scenario,
        run_id=request.run_id,
        investigation_id=request.investigation_id,
        operation_id=request.operation_id,
        invocation_id=request.invocation_id,
        function_call_id=request.function_call_id,
        seed=request.seed,
        namespace_id=fixture.namespace_id,
        cleanup_manifest_sha256=fixture.cleanup_manifest_sha256,
    )


def make_cleanup_result() -> ScenarioCleanupResult:
    request = make_cleanup_request()
    return ScenarioCleanupResult(
        schema_version=SCENARIO_CLEANUP_RESULT_VERSION,
        cleanup_request_sha256=canonical_sha256(request),
        run_id=request.run_id,
        namespace_id=request.namespace_id,
        cleanup_manifest_sha256=request.cleanup_manifest_sha256,
        disposition=ScenarioCleanupDisposition.CLEANED,
        removed_count=1,
        remaining_count=0,
        started_at=NOW + timedelta(seconds=6),
        completed_at=NOW + timedelta(seconds=7),
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


def make_api_error(
    code: ApiErrorCode = ApiErrorCode.INVALID_CONTRACT,
) -> ApiError:
    details = (
        {"investigation_id": "investigation-7"}
        if code
        in {
            ApiErrorCode.INVESTIGATION_NOT_FOUND,
            ApiErrorCode.DUPLICATE_INVESTIGATION_ID,
        }
        else {}
    )
    return ApiError(
        schema_version=ERROR_VERSION,
        code=code,
        message="The request could not be completed.",
        details=details,
    )


def make_investigation_event(
    event_type: InvestigationEventType = InvestigationEventType.LIFECYCLE,
    *,
    sequence: int = 1,
) -> InvestigationEvent:
    report = make_report(Classification.COMMITTED)
    payloads = {
        InvestigationEventType.LIFECYCLE: LifecycleEventPayload(
            status=InvestigationStatus.COMPLETED,
        ),
        InvestigationEventType.PROBE: ProbeEventPayload(
            probe_audit=report.probe_audit[0],
        ),
        InvestigationEventType.EVIDENCE_DECISION: EvidenceDecisionEventPayload(
            decision=report.evidence_decisions[0],
        ),
        InvestigationEventType.CLASSIFICATION: ClassificationEventPayload(
            classification=Classification.COMMITTED,
        ),
        InvestigationEventType.ACTION_GATE: ActionGateEventPayload(
            action_gate=report.action_gate[0],
        ),
    }
    return InvestigationEvent(
        schema_version=INVESTIGATION_EVENT_VERSION,
        investigation_id=report.investigation_id,
        sequence=sequence,
        type=event_type,
        occurred_at=report.updated_at,
        payload=payloads[event_type],
    )


def make_comparison_record(
    *,
    include_adaptive: bool = False,
) -> InvestigationComparisonRecord:
    scenario = ScenarioRef(name="storage-object", version="1.0.0")
    envelope_sha256 = canonical_sha256(make_envelope())
    expectation = PreregisteredExpectedClassification(
        registration_id="expectation-storage-committed-v1",
        metadata_sha256="f" * 64,
        expected_classification=Classification.COMMITTED,
    )
    complete_explanation = ExplanationCompleteness(
        required_evidence_citation_count=1,
        valid_evidence_citation_count=1,
        missing_evidence_citation_count=0,
        complete=True,
    )
    baseline = ComparisonRun(
        scenario=scenario,
        envelope_sha256=envelope_sha256,
        strategy_kind=ComparisonStrategyKind.FIXED,
        strategy_version="fixed-storage-v1",
        plan_sha256="a" * 64,
        report_sha256="b" * 64,
        classification=Classification.COMMITTED,
        matches_preregistered_expectation=True,
        planned_probe_count=1,
        executed_probe_count=1,
        controller_cost_units_used=1,
        controller_result_bytes_acquired=512,
        total_elapsed_ms=20,
        time_to_sufficient_evidence_ms=15,
        stop_reason="sufficient_evidence",
        unsupported_probe_count=0,
        unnecessary_probe_count=0,
        duplicate_probe_count=0,
        explanation_completeness=complete_explanation,
        model_usage=ComparisonModelUsage(
            status=ComparisonModelUsageStatus.NOT_APPLICABLE,
            model_call_count=0,
            input_token_count=0,
            output_token_count=0,
            total_token_count=0,
        ),
    )
    adaptive = None
    if include_adaptive:
        adaptive = ComparisonRun(
            scenario=scenario,
            envelope_sha256=envelope_sha256,
            strategy_kind=ComparisonStrategyKind.ADAPTIVE,
            strategy_version="adaptive-planner-v1",
            plan_sha256="c" * 64,
            report_sha256="d" * 64,
            classification=Classification.COMMITTED,
            matches_preregistered_expectation=True,
            planned_probe_count=2,
            executed_probe_count=1,
            controller_cost_units_used=1,
            controller_result_bytes_acquired=512,
            total_elapsed_ms=35,
            time_to_sufficient_evidence_ms=25,
            stop_reason="sufficient_evidence",
            unsupported_probe_count=0,
            unnecessary_probe_count=0,
            duplicate_probe_count=0,
            explanation_completeness=complete_explanation,
            model_usage=ComparisonModelUsage(
                status=ComparisonModelUsageStatus.MEASURED,
                provider_name="google",
                model_name="gemini-2.5-flash",
                model_call_count=1,
                input_token_count=100,
                output_token_count=20,
                total_token_count=120,
            ),
        )
    return InvestigationComparisonRecord(
        schema_version=INVESTIGATION_COMPARISON_RECORD_VERSION,
        comparison_id="comparison-storage-7",
        case_id="case-storage-committed-7",
        scenario=scenario,
        envelope_sha256=envelope_sha256,
        preregistered_expectation=expectation,
        baseline=baseline,
        adaptive=adaptive,
    )


def make_planner_input() -> AdaptivePlannerInput:
    envelope = make_envelope()
    capability = make_capability()
    return AdaptivePlannerInput(
        schema_version=ADAPTIVE_PLANNER_INPUT_VERSION,
        phase=AdaptivePlannerPhase.ACQUIRE_EVIDENCE,
        envelope=envelope,
        capabilities=(
            PlannerCapability(
                name=capability.name,
                version=capability.version,
                description="Read exact target state through the bound adapter.",
                read_only=True,
                argument_schema=dict(capability.argument_schema),
                cost_units=capability.cost_units,
                remaining_invocations=2,
            ),
        ),
        admitted_evidence=(
            PlannerAdmittedEvidence(
                evidence_id="evidence-admitted-7",
                capability_name=capability.name,
                capability_version=capability.version,
                reason=EvidenceReason.AUTHORITATIVE_EXACT_CORRELATION,
                effect_assertions=(
                    EffectAssertion(
                        effect_id="business-record",
                        state=EffectAssertionState.ESTABLISHED,
                    ),
                ),
                operation_status=None,
            ),
        ),
        weak_evidence=(
            PlannerWeakEvidence(
                evidence_id="evidence-weak-7",
                capability_name=capability.name,
                capability_version=capability.version,
                reason=EvidenceReason.NON_AUTHORITATIVE_LOG_ONLY,
                relevant_effect_ids=("audit-record",),
            ),
        ),
        rejected_evidence=(
            PlannerRejectedEvidence(
                evidence_id="evidence-rejected-7",
                capability_name=capability.name,
                capability_version=capability.version,
                reason=EvidenceReason.CORRELATION_MISMATCH,
                relevant_effect_ids=("audit-record",),
            ),
        ),
        missing_evidence=(
            PlannerMissingEvidence(
                effect_id="audit-record",
                reason="insufficient_authoritative_evidence",
            ),
        ),
        prior_executable_request_hashes=("e" * 64,),
        remaining_budget=PlannerRemainingBudget(
            probes=2,
            elapsed_ms=3_000,
            result_bytes=32_768,
            cost_units=2,
            deadline_at=NOW + timedelta(seconds=5),
        ),
        versions=PlannerVersionMetadata(
            provider_name="google",
            model_name="gemini-2.5-flash",
            adk_version="1.11.0",
            genai_version="1.29.0",
            prompt_version="adaptive-planner-v1",
            capability_catalog_version="capability-catalog-v1",
            authority_policy_version=envelope.context.policies.authority,
            classification_policy_version=envelope.context.policies.classification,
            action_policy_version=envelope.context.policies.action,
            input_schema_version=ADAPTIVE_PLANNER_INPUT_VERSION,
            output_schema_version=ADAPTIVE_PLANNER_OUTPUT_VERSION,
        ),
    )


def make_planner_output() -> AdaptivePlannerOutput:
    return AdaptivePlannerOutput(
        schema_version=ADAPTIVE_PLANNER_OUTPUT_VERSION,
        probe_proposals=(make_probe(),),
        acquisition_advice=PlannerAcquisitionAdvice(
            summary="Acquire one exact target-state observation for the missing effect.",
        ),
        stop_advice=PlannerStopAdvice(
            recommend_stop=False,
            reason="Authoritative evidence for one expected effect remains missing.",
        ),
        missing_evidence_notes=(
            PlannerMissingEvidenceNote(
                effect_ids=("audit-record",),
                note="No admitted observation establishes the audit effect.",
            ),
        ),
        explanation=PlannerExplanation(
            summary="The available evidence leaves one expected effect unresolved.",
            admitted_evidence="One admitted observation establishes the business effect.",
            weak_evidence="Weak evidence does not establish the audit effect.",
            rejected_evidence="A rejected observation failed exact correlation.",
            missing_evidence="The audit effect still needs authoritative evidence.",
            citations=PlannerCitationRefs(
                admitted_evidence_ids=("evidence-admitted-7",),
                weak_evidence_ids=("evidence-weak-7",),
                rejected_evidence_ids=("evidence-rejected-7",),
                missing_effect_ids=("audit-record",),
            ),
        ),
    )


def make_recovery_examples() -> tuple[
    RecoveryChain,
    GeminiHypothesis,
    VerifiedCertificate,
    AmbiguityWitness,
    ActionPermit,
]:
    envelope = make_envelope()
    second_envelope = envelope.model_copy(
        update={
            "investigation_id": "investigation-promote-7",
            "operation_id": "operation-promote-7",
        }
    )

    def action_identity(
        *,
        tool_name: str,
        arguments: dict[str, object],
        bound_envelope: ExecutionEnvelope,
    ) -> SemanticActionIdentity:
        effect_hashes = tuple(
            canonical_sha256(effect) for effect in bound_envelope.expected_effects
        )
        digest = semantic_action_sha256(
            key_version="semantic-action-v1",
            tool_name=tool_name,
            tool_version="1.0.0",
            semantic_arguments=arguments,  # type: ignore[arg-type]
            target=bound_envelope.target,
            expected_effect_sha256s=effect_hashes,
            action_profile_version=f"{tool_name}-profile-v1",
        )
        return SemanticActionIdentity(
            key_version="semantic-action-v1",
            tool_name=tool_name,
            tool_version="1.0.0",
            semantic_arguments=arguments,  # type: ignore[arg-type]
            target=bound_envelope.target,
            expected_effect_sha256s=effect_hashes,
            action_profile_version=f"{tool_name}-profile-v1",
            semantic_action_sha256=digest,
        )

    stage = RecoveryActionNode(
        node_id="stage-revision",
        chain_profile_version="cloud-run-release-chain-v1",
        semantic_action=action_identity(
            tool_name="stage-cloud-run-revision",
            arguments={"image_digest": "sha256:" + "a" * 64, "release_id": "r-7"},
            bound_envelope=envelope,
        ),
        envelope=ExecutionEnvelopeReference(
            investigation_id=envelope.investigation_id,
            operation_id=envelope.operation_id,
            envelope_sha256=canonical_sha256(envelope),
        ),
    )
    promote = RecoveryActionNode(
        node_id="promote-traffic",
        chain_profile_version="cloud-run-release-chain-v1",
        semantic_action=action_identity(
            tool_name="promote-cloud-run-traffic",
            arguments={"percent": 100, "release_id": "r-7"},
            bound_envelope=second_envelope,
        ),
        depends_on=(stage.node_id,),
        envelope=ExecutionEnvelopeReference(
            investigation_id=second_envelope.investigation_id,
            operation_id=second_envelope.operation_id,
            envelope_sha256=canonical_sha256(second_envelope),
        ),
    )
    chain = RecoveryChain(
        schema_version=RECOVERY_CHAIN_VERSION,
        chain_id="release-chain-7",
        chain_profile_version="cloud-run-release-chain-v1",
        nodes=(stage, promote),
        created_at=NOW,
    )

    report = make_report(Classification.COMMITTED)
    evidence = report.evidence[0]
    established = tuple(
        HypothesizedEffect(
            effect_id=finding.effect_id,
            state=finding.state,
            cited_evidence_ids=(evidence.evidence_id,),
        )
        for finding in report.proof.effect_findings  # type: ignore[union-attr]
    )
    committed_history = PossibleHistory(
        history_id="provider-accepted",
        classification=Classification.COMMITTED,
        effect_states=established,
        compatible_evidence_ids=(evidence.evidence_id,),
        summary="The provider accepted and completed the staged revision.",
    )
    hypothesis = GeminiHypothesis(
        schema_version=GEMINI_HYPOTHESIS_VERSION,
        hypothesis_id="hypothesis-7",
        chain_id=chain.chain_id,
        node_id=stage.node_id,
        semantic_action_sha256=stage.semantic_action.semantic_action_sha256,
        report_sha256=canonical_sha256(report),
        proposed_classification=Classification.COMMITTED,
        effect_hypotheses=established,
        cited_evidence_ids=(evidence.evidence_id,),
        confidence_basis_points=8_500,
        alternative_histories=(committed_history,),
        proposed_transition=ProposedTransition(
            action=PermitAction.CONTINUE,
            source_node_id=stage.node_id,
            target_node_id=promote.node_id,
            rationale="Continue only after deterministic verification.",
        ),
        explanation="Provider evidence suggests that the staged revision committed.",
        created_at=NOW + timedelta(seconds=5),
    )

    binding = RecoveryEvidenceBinding(
        evidence_id=evidence.evidence_id,
        evidence_sha256=canonical_sha256(evidence),
        raw_observation_sha256=evidence.raw_observation.sha256,
        valid_until=evidence.freshness.valid_until,
    )
    transition = CertifiedTransition(
        action=PermitAction.CONTINUE,
        source_node_id=stage.node_id,
        target_node_id=promote.node_id,
        semantic_action_sha256=promote.semantic_action.semantic_action_sha256,
        tool_name=promote.semantic_action.tool_name,
        tool_version=promote.semantic_action.tool_version,
        arguments_sha256=hashlib.sha256(
            canonical_json_value_bytes(promote.semantic_action.semantic_arguments)
        ).hexdigest(),
        target_sha256=canonical_sha256(promote.semantic_action.target),
        precondition_sha256="b" * 64,
    )
    certificate = VerifiedCertificate(
        schema_version=VERIFIED_CERTIFICATE_VERSION,
        certificate_id="certificate-7",
        chain_id=chain.chain_id,
        node_id=stage.node_id,
        semantic_action_sha256=stage.semantic_action.semantic_action_sha256,
        chain_sha256=canonical_sha256(chain),
        node_sha256=canonical_sha256(stage),
        envelope_sha256=stage.envelope.envelope_sha256,
        report_sha256=canonical_sha256(report),
        proof_sha256=canonical_sha256(report.proof),  # type: ignore[arg-type]
        target=stage.semantic_action.target,
        target_sha256=canonical_sha256(stage.semantic_action.target),
        evidence=(binding,),
        authority_satisfied=True,
        correlation_satisfied=True,
        freshness_satisfied=True,
        authority_policy_version="authority-v1",
        correlation_policy_version="correlation-v1",
        freshness_policy_version="freshness-v1",
        classification_policy_version="classification-v1",
        action_policy_version="action-v1",
        action_profile_version=stage.semantic_action.action_profile_version,
        verifier_version="recovery-verifier-v1",
        classification=Classification.COMMITTED,
        transition=transition,
        issued_at=NOW + timedelta(seconds=5),
        expires_at=NOW + timedelta(seconds=20),
    )

    absent_history = PossibleHistory(
        history_id="provider-not-dispatched",
        classification=Classification.NOT_COMMITTED,
        effect_states=tuple(
            HypothesizedEffect(
                effect_id=effect.effect_id,
                state=EffectAssertionState.NOT_ESTABLISHED,
            )
            for effect in envelope.expected_effects
        ),
        compatible_evidence_ids=(evidence.evidence_id,),
        summary="The request never crossed the provider boundary.",
    )
    witness = AmbiguityWitness(
        schema_version=AMBIGUITY_WITNESS_VERSION,
        witness_id="witness-7",
        chain_id=chain.chain_id,
        node_id=stage.node_id,
        semantic_action_sha256=stage.semantic_action.semantic_action_sha256,
        chain_sha256=canonical_sha256(chain),
        node_sha256=canonical_sha256(stage),
        envelope_sha256=stage.envelope.envelope_sha256,
        report_sha256=canonical_sha256(report),
        proof_sha256=canonical_sha256(report.proof),  # type: ignore[arg-type]
        target=stage.semantic_action.target,
        target_sha256=canonical_sha256(stage.semantic_action.target),
        evidence=(binding,),
        possible_histories=(committed_history, absent_history),
        discriminating_observations=(
            DiscriminatingObservation(
                observation_id="read-exact-revision",
                description="Read the exact candidate revision from Cloud Run.",
                capability_name="cloud-run-revision-get",
                capability_version="1.0.0",
                relevant_effect_ids=("business-record", "audit-record"),
                distinguishes_history_ids=(
                    committed_history.history_id,
                    absent_history.history_id,
                ),
            ),
        ),
        verifier_version="recovery-verifier-v1",
        created_at=NOW + timedelta(seconds=5),
    )
    permit = ActionPermit(
        schema_version=ACTION_PERMIT_VERSION,
        permit_id="permit-7",
        certificate_id=certificate.certificate_id,
        certificate_sha256=canonical_sha256(certificate),
        chain_id=chain.chain_id,
        source_node_id=transition.source_node_id,
        target_node_id=transition.target_node_id,
        semantic_action_sha256=transition.semantic_action_sha256,
        action=transition.action,
        action_profile_version=promote.semantic_action.action_profile_version,
        action_policy_version=certificate.action_policy_version,
        tool_name=transition.tool_name,
        tool_version=transition.tool_version,
        arguments_sha256=transition.arguments_sha256,
        target_sha256=transition.target_sha256,
        precondition_sha256=transition.precondition_sha256,
        issued_at=certificate.issued_at,
        expires_at=certificate.expires_at,
        max_uses=1,
        state=ActionPermitState.ISSUED,
        revision=0,
    )
    return chain, hypothesis, certificate, witness, permit


def make_qualification_examples() -> tuple[
    QualificationSuiteManifest,
    QualificationCaseResult,
    QualificationResultSet,
    QualificationSummary,
    QualificationDisposition,
]:
    provider = QualificationProviderSettings(
        provider_name="google-vertex-ai",
        model_name="gemini-3.5-flash",
        model_revision="ga-2026-08",
        location="global",
        prompt_version="adaptive-planner-v3",
        adk_version="2.6.3",
        genai_version="2.18.0",
        timeout_ms=30_000,
        max_output_tokens=2_048,
        temperature_milli=0,
        billing_currency="USD",
        input_cost_nano_units_per_token=1_500,
        output_cost_nano_units_per_token=9_000,
    )
    manifest = build_qualification_manifest(
        source_revision="f" * 64,
        registered_at=NOW,
        provider=provider,
        repetition_count=1,
    )
    result = build_failed_result(
        manifest,
        execution_id="qualification-example-failure",
        case_id=manifest.cases[0].case_id,
        repetition=1,
        lane_order=QualificationLaneOrder.FIXED_FIRST,
        failure_category="provider-timeout",
    )
    result_set = build_result_set(manifest, (result,))
    summary = summarize_qualification(manifest, result_set, evaluated_at=NOW)
    disposition = derive_disposition(
        manifest,
        result_set,
        summary,
        decided_at=NOW,
    )
    return manifest, result, result_set, summary, disposition


def make_recovery_run_examples() -> tuple[
    RecoveryRunRequest,
    RecoveryRunEvent,
    RecoveryLaunchPermit,
    RecoveryRunSnapshot,
    RecoveryActionScope,
]:
    chain, _hypothesis, certificate, _witness, permit = make_recovery_examples()
    request = RecoveryRunRequest(
        schema_version=RECOVERY_RUN_REQUEST_VERSION,
        run_id="recovery-run-7",
        scenario="cloud-run-rollout",
        policy=RecoveryRunPolicy.ADAPTIVE,
        fault=RecoveryRunFault.DROP_AFTER_ACCEPT,
    )
    event = RecoveryRunEvent(
        schema_version=RECOVERY_RUN_EVENT_VERSION,
        run_id=request.run_id,
        cursor=1,
        type=RecoveryRunEventType.LIFECYCLE,
        occurred_at=NOW,
        payload=RecoveryRunEventPayload(lifecycle=RecoveryRunLifecycle.ACCEPTED),
    )
    first_node = chain.nodes[0]
    launch = RecoveryLaunchPermit(
        schema_version=RECOVERY_LAUNCH_PERMIT_VERSION,
        launch_permit_id="launch-permit-7",
        run_id=request.run_id,
        node_id=first_node.node_id,
        semantic_action_sha256=first_node.semantic_action.semantic_action_sha256,
        action_request_sha256="d" * 64,
        issued_at=NOW,
        state=RecoveryLaunchPermitState.ISSUED,
        revision=0,
    )
    snapshot = RecoveryRunSnapshot(
        schema_version=RECOVERY_RUN_SNAPSHOT_VERSION,
        request=request,
        request_sha256=canonical_sha256(request),
        lifecycle=RecoveryRunLifecycle.ACCEPTED,
        event_cursor=2,
        revision=1,
        chain=chain,
        chain_sha256=canonical_sha256(chain),
        nodes=tuple(
            RecoveryNodeProgress(
                node_id=node.node_id,
                state=RecoveryNodeState.WAITING,
                attempt=0,
            )
            for node in chain.nodes
        ),
        created_at=NOW,
        updated_at=NOW,
    )
    scope = RecoveryActionScope(
        schema_version=RECOVERY_ACTION_SCOPE_VERSION,
        authority_kind=RecoveryAuthorityKind.ACTION_PERMIT,
        run_id=request.run_id,
        source_node_id=permit.source_node_id,
        target_node_id=permit.target_node_id,
        semantic_action_sha256=permit.semantic_action_sha256,
        action_request_sha256="e" * 64,
        authority_id=permit.permit_id,
        authority_sha256=canonical_sha256(permit),
        claim_id="claim-7",
        permit_action=permit.action,
        certificate_id=certificate.certificate_id,
        certificate_sha256=canonical_sha256(certificate),
    )
    return request, event, launch, snapshot, scope


def make_recovery_scenario_examples() -> tuple[
    RecoveryDispatchReceipt,
    RecoveryPolicyComparison,
]:
    common = {
        "target_sha256": "1" * 64,
        "input_intent_sha256": "2" * 64,
        "fault_boundary_sha256": "3" * 64,
        "observation_catalog_sha256": "4" * 64,
    }
    receipt = RecoveryDispatchReceipt(
        schema_version=RECOVERY_DISPATCH_RECEIPT_VERSION,
        receipt_id="dispatch-receipt-7",
        run_id="adaptive-run-7",
        release_id="release-7",
        node_id="record",
        semantic_action_sha256="5" * 64,
        action_request_sha256="6" * 64,
        authority_id="permit-7",
        claim_id="claim-7",
        attempt=1,
        provider_contact=False,
        outcome=RecoveryReceiptOutcome.SUPPRESSED_BEFORE_DISPATCH,
        recorded_at=NOW,
    )
    lanes = tuple(
        RecoveryPolicyResult(
            schema_version=RECOVERY_POLICY_RESULT_VERSION,
            run_id=f"{policy}-run-7",
            policy=policy,
            fault="drop-after-accept",
            **common,
            chain_completed=policy != "blind-abort",
            terminal_disposition=(
                "ABORTED" if policy == "blind-abort" else "COMPLETED"
            ),
            counters=RecoveryMutationCounters(
                revisions_created=2 if policy == "blind-retry" else 1,
                promotions_accepted=0 if policy == "blind-abort" else 1,
                release_records_created=0 if policy == "blind-abort" else 1,
                provider_contacts=(
                    4
                    if policy == "blind-retry"
                    else 1
                    if policy == "blind-abort"
                    else 3
                ),
                continue_permits_issued=2 if policy in {"fixed", "adaptive"} else 0,
                retry_permits_issued=0,
                retry_permits_consumed=0,
                action_permits_consumed=2 if policy in {"fixed", "adaptive"} else 0,
            ),
            cloud_run=RecoveryCloudRunObservation(
                baseline_revision="canary-baseline",
                intended_revision="canary-release-a",
                release_revisions=(
                    ("canary-release-a", "canary-release-b")
                    if policy == "blind-retry"
                    else ("canary-release-a",)
                ),
                serving_revision=(
                    "canary-baseline"
                    if policy == "blind-abort"
                    else "canary-release-b"
                    if policy == "blind-retry"
                    else "canary-release-a"
                ),
                serving_percent=100,
                observed_service_etag_sha256="7" * 64,
            ),
            firestore=RecoveryFirestoreObservation(
                release_id="release-7",
                document_path="releases/release-7",
                payload_sha256=None if policy == "blind-abort" else "8" * 64,
                semantic_action_sha256=(None if policy == "blind-abort" else "9" * 64),
                exists=policy != "blind-abort",
                cloud_run_revision=(
                    None
                    if policy == "blind-abort"
                    else "canary-release-b"
                    if policy == "blind-retry"
                    else "canary-release-a"
                ),
            ),
            dispatch_receipts=(),
            timeline=(
                RecoveryTimelineEntry(
                    sequence=1,
                    node_id="stage",
                    event="policy-finished",
                    detail="The isolated policy lane reached its recorded outcome.",
                ),
            ),
            certificate_sha256s=(
                ("9" * 64,) if policy in {"fixed", "adaptive"} else ()
            ),
            witness_sha256s=(),
        )
        for policy in ("blind-retry", "blind-abort", "fixed", "adaptive")
    )
    resets = tuple(
        RecoveryResetResult(
            schema_version=RECOVERY_RESET_RESULT_VERSION,
            release_id="release-7",
            baseline_revision="canary-baseline",
            serving_revision="canary-baseline",
            serving_percent=100,
            release_record_absent=True,
            release_revisions_before=("canary-release-a",),
            release_revisions_after=("canary-release-a",),
            reset_operation_name_sha256=str(index) * 64,
            verified_at=NOW,
        )
        for index in range(1, 5)
    )
    comparison = RecoveryPolicyComparison(
        schema_version=RECOVERY_POLICY_COMPARISON_VERSION,
        comparison_id="comparison-7",
        release_id="release-7",
        fault="drop-after-accept",
        **common,
        lanes=lanes,
        reset_results=resets,
        created_at=NOW,
    )
    return receipt, comparison


def public_examples() -> tuple[object, ...]:
    envelope = make_envelope()
    capability = make_capability()
    probe = make_probe()
    evidence, decision = make_evidence(Classification.COMMITTED)
    qualification = make_qualification_examples()
    return (
        envelope.expected_effects[0],
        envelope,
        capability,
        probe,
        evidence,
        decision,
        make_report(Classification.COMMITTED).action_gate[0],
        make_report(Classification.COMMITTED),
        make_scenario_request(),
        make_scenario_trace(),
        make_scenario_result(),
        make_cleanup_request(),
        make_cleanup_result(),
        make_comparison_record(),
        make_planner_input(),
        make_planner_output(),
        make_api_error(),
        make_investigation_event(),
        *qualification,
        *make_recovery_examples(),
        *make_recovery_run_examples(),
        *make_recovery_scenario_examples(),
    )


def canonical_example_bytes(classification: Classification) -> bytes:
    return canonical_json_bytes(make_report(classification))
