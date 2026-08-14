import ast
from datetime import timedelta
from pathlib import Path

import pytest

from reconcile.contracts import (
    EVIDENCE_DECISION_VERSION,
    EXECUTION_ENVELOPE_SUMMARY_VERSION,
    SCENARIO_RUN_EVENT_VERSION,
    SCENARIO_RUN_SNAPSHOT_VERSION,
    AdaptivePlannerPhase,
    AdvisoryTurnEventPayload,
    AdvisoryTurnStatus,
    AdvisoryTurnSummary,
    Classification,
    ComparisonStrategyKind,
    EnvelopeEffectSummary,
    EvidenceDecision,
    EvidenceDisposition,
    EvidenceReason,
    ExecutionEnvelope,
    ExecutionEnvelopeSummary,
    InvestigationReport,
    OperatorEvidenceDecisionEventPayload,
    ProbeOutcome,
    ProbeRequestDisposition,
    ProbeRequestEventPayload,
    ProbeResultEventPayload,
    SanitizedComparisonRun,
    SanitizedDeterministicProof,
    SanitizedEffectFinding,
    SanitizedEvidenceSummary,
    SanitizedInvestigationComparison,
    SanitizedInvestigationReport,
    SanitizedMissingEvidence,
    SanitizedProbeAuditRecord,
    SanitizedProbeRequest,
    SanitizedProbeResult,
    ScenarioLaunchName,
    ScenarioRunEvent,
    ScenarioRunEventType,
    ScenarioRunFailureCategory,
    ScenarioRunLifecycle,
    ScenarioRunMode,
    ScenarioRunResultKind,
    ScenarioRunSnapshot,
    TerminalStateEventPayload,
    TerminalStateSummary,
    canonical_json_bytes,
    canonical_sha256,
)
from reconcile.interfaces.tui_state import (
    ConnectionPhase,
    OperatorViewState,
    ViewStateProtocolError,
    ViewStateProtocolErrorCode,
)
from tests.contract._factories import (
    NOW,
    make_comparison_record,
    make_envelope,
    make_report,
)

pytestmark = pytest.mark.unit

_INVESTIGATION_ID = "investigation-7"


def _envelope(investigation_id: str = _INVESTIGATION_ID) -> ExecutionEnvelope:
    payload = make_envelope().model_dump(mode="python")
    payload["investigation_id"] = investigation_id
    return ExecutionEnvelope.model_validate(payload)


def _summary(
    investigation_id: str = _INVESTIGATION_ID,
) -> ExecutionEnvelopeSummary:
    envelope = _envelope(investigation_id)
    return ExecutionEnvelopeSummary(
        schema_version=EXECUTION_ENVELOPE_SUMMARY_VERSION,
        investigation_id=investigation_id,
        envelope_sha256=canonical_sha256(envelope),
        target_kind=envelope.target.target_kind,
        invoked_at=envelope.invoked_at,
        ambiguity_kind=envelope.ambiguity.kind,
        ambiguity_observed_at=envelope.ambiguity.observed_at,
        expected_effects=tuple(
            EnvelopeEffectSummary(
                effect_id=item.effect_id,
                commit_scope=item.commit_scope,
            )
            for item in envelope.expected_effects
        ),
        enabled_capabilities=envelope.context.enabled_capabilities,
        evidence_budget=envelope.context.evidence_budget,
    )


def _sanitized_report(
    classification: Classification,
) -> SanitizedInvestigationReport:
    payload = make_report(classification).model_dump(mode="python")
    payload["investigation_id"] = _INVESTIGATION_ID
    payload["envelope_sha256"] = _summary().envelope_sha256
    report = InvestigationReport.model_validate(payload)
    decisions = {item.evidence_id: item for item in report.evidence_decisions}
    proof = report.proof
    return SanitizedInvestigationReport(
        investigation_id=report.investigation_id,
        envelope_sha256=report.envelope_sha256,
        status=report.status,
        probe_audit=tuple(
            SanitizedProbeAuditRecord(
                probe_sequence=item.probe_sequence,
                capability_name=item.capability_name,
                capability_version=item.capability_version,
                request_sha256=item.request_sha256,
                outcome=item.outcome,
                stop_reason=item.stop_reason,
                started_at=item.started_at,
                completed_at=item.completed_at,
                session_elapsed_ms=item.session_elapsed_ms,
                probe_count_used=item.probe_count_used,
                cost_units_used=item.cost_units_used,
                result_bytes_acquired=item.result_bytes_acquired,
                result_sha256=item.result_sha256,
                result_byte_count=item.result_byte_count,
                evidence_ids=item.evidence_ids,
            )
            for item in report.probe_audit
        ),
        evidence=tuple(
            SanitizedEvidenceSummary(
                evidence_id=item.evidence_id,
                capability_name=item.capability_name,
                capability_version=item.capability_version,
                disposition=decisions[item.evidence_id].disposition,
                reason=decisions[item.evidence_id].reason,
                authority=item.authority,
                effect_assertions=item.effect_assertions,
                operation_status=item.operation_status,
            )
            for item in report.evidence
        ),
        proof=(
            None
            if proof is None
            else SanitizedDeterministicProof(
                effect_findings=tuple(
                    SanitizedEffectFinding(
                        effect_id=item.effect_id,
                        commit_scope=item.commit_scope,
                        state=item.state,
                        evidence_ids=item.evidence_ids,
                    )
                    for item in proof.effect_findings
                ),
                operation_status=proof.operation_status,
                conflicting_authority=proof.conflicting_authority,
                admitted_evidence_ids=proof.admitted_evidence_ids,
            )
        ),
        classification=report.classification,
        action_gate=report.action_gate,
        missing_evidence=tuple(
            SanitizedMissingEvidence(
                effect_ids=item.effect_ids,
                reason=item.reason,
            )
            for item in report.missing_evidence
        ),
        advisory_cited_evidence_ids=(
            ()
            if report.advisory_explanation is None
            else report.advisory_explanation.cited_evidence_ids
        ),
        created_at=report.created_at,
        updated_at=report.updated_at,
        revision=report.revision,
    )


def _sanitized_comparison_run(run) -> SanitizedComparisonRun:
    return SanitizedComparisonRun(
        strategy_kind=run.strategy_kind,
        strategy_version=run.strategy_version,
        plan_sha256=run.plan_sha256,
        report_sha256=run.report_sha256,
        classification=run.classification,
        planned_probe_count=run.planned_probe_count,
        executed_probe_count=run.executed_probe_count,
        controller_cost_units_used=run.controller_cost_units_used,
        controller_result_bytes_acquired=run.controller_result_bytes_acquired,
        total_elapsed_ms=run.total_elapsed_ms,
        time_to_sufficient_evidence_ms=run.time_to_sufficient_evidence_ms,
        stop_reason=run.stop_reason,
        unsupported_probe_count=run.unsupported_probe_count,
        unnecessary_probe_count=run.unnecessary_probe_count,
        duplicate_probe_count=run.duplicate_probe_count,
        explanation_completeness=run.explanation_completeness,
        model_usage=run.model_usage,
    )


def _active_snapshot(
    *,
    investigation_id: str = _INVESTIGATION_ID,
    mode: ScenarioRunMode = ScenarioRunMode.FIXED,
    event_cursor: int = 0,
) -> ScenarioRunSnapshot:
    return ScenarioRunSnapshot(
        schema_version=SCENARIO_RUN_SNAPSHOT_VERSION,
        launch_id="launch-7",
        investigation_id=investigation_id,
        scenario=ScenarioLaunchName.STORAGE,
        mode=mode,
        lifecycle=ScenarioRunLifecycle.RUNNING,
        event_cursor=event_cursor,
        envelope_summary=_summary(investigation_id),
        report=None,
        comparison=None,
        failure_category=None,
        accepted_at=NOW,
        updated_at=NOW + timedelta(seconds=1),
    )


def _completed_report_snapshot(
    classification: Classification,
    *,
    event_cursor: int = 0,
) -> ScenarioRunSnapshot:
    report = _sanitized_report(classification)
    return ScenarioRunSnapshot(
        schema_version=SCENARIO_RUN_SNAPSHOT_VERSION,
        launch_id="launch-7",
        investigation_id=_INVESTIGATION_ID,
        scenario=ScenarioLaunchName.STORAGE,
        mode=ScenarioRunMode.FIXED,
        lifecycle=ScenarioRunLifecycle.COMPLETED,
        event_cursor=event_cursor,
        envelope_summary=_summary(),
        report=report,
        comparison=None,
        failure_category=None,
        accepted_at=NOW,
        updated_at=NOW + timedelta(seconds=6),
    )


def _completed_comparison_snapshot() -> ScenarioRunSnapshot:
    source = make_comparison_record(include_adaptive=True)
    assert source.adaptive is not None
    comparison = SanitizedInvestigationComparison(
        comparison_id=source.comparison_id,
        envelope_sha256=source.envelope_sha256,
        baseline=_sanitized_comparison_run(source.baseline),
        adaptive=_sanitized_comparison_run(source.adaptive),
    )
    return ScenarioRunSnapshot(
        schema_version=SCENARIO_RUN_SNAPSHOT_VERSION,
        launch_id="launch-7",
        investigation_id=_INVESTIGATION_ID,
        scenario=ScenarioLaunchName.STORAGE,
        mode=ScenarioRunMode.COMPARE,
        lifecycle=ScenarioRunLifecycle.COMPLETED,
        event_cursor=0,
        envelope_summary=_summary(),
        report=None,
        comparison=comparison,
        failure_category=None,
        accepted_at=NOW,
        updated_at=NOW + timedelta(seconds=6),
    )


def _failed_snapshot(
    *,
    mode: ScenarioRunMode = ScenarioRunMode.ADAPTIVE,
) -> ScenarioRunSnapshot:
    return ScenarioRunSnapshot(
        schema_version=SCENARIO_RUN_SNAPSHOT_VERSION,
        launch_id="launch-7",
        investigation_id=_INVESTIGATION_ID,
        scenario=ScenarioLaunchName.STORAGE,
        mode=mode,
        lifecycle=ScenarioRunLifecycle.FAILED,
        event_cursor=1,
        envelope_summary=None,
        report=None,
        comparison=None,
        failure_category=ScenarioRunFailureCategory.MODEL_UNAVAILABLE,
        accepted_at=NOW,
        updated_at=NOW + timedelta(seconds=1),
    )


def _event(
    cursor: int,
    event_type: ScenarioRunEventType,
    payload,
    *,
    investigation_id: str = _INVESTIGATION_ID,
) -> ScenarioRunEvent:
    return ScenarioRunEvent(
        schema_version=SCENARIO_RUN_EVENT_VERSION,
        investigation_id=investigation_id,
        cursor=cursor,
        type=event_type,
        occurred_at=NOW + timedelta(seconds=cursor),
        payload=payload,
    )


def _terminal_event(
    classification: Classification = Classification.UNKNOWN,
) -> ScenarioRunEvent:
    return _event(
        1,
        ScenarioRunEventType.TERMINAL,
        TerminalStateEventPayload(
            terminal=TerminalStateSummary(
                lifecycle=ScenarioRunLifecycle.COMPLETED,
                result_kind=ScenarioRunResultKind.REPORT,
                classification=classification,
                action_gate_allowed_count=2,
                action_gate_denied_count=3,
                missing_evidence_count=1,
                escalation_required=True,
                failure_category=None,
            )
        ),
    )


def test_state_reset_and_connection_changes_preserve_no_stale_projection() -> None:
    state = OperatorViewState.empty()
    assert state.connection_phase is ConnectionPhase.IDLE

    state = state.apply_snapshot(_active_snapshot()).set_connection(
        ConnectionPhase.LIVE
    )
    reset = state.reset()

    assert reset.connection_phase is ConnectionPhase.CONNECTING
    assert reset.snapshot is None
    assert reset.event_bytes_by_cursor == ()
    assert reset.render_connection() == ("API CONNECTION: CONNECTING",)


def test_ingestion_is_contiguous_idempotent_and_exact() -> None:
    state = OperatorViewState.empty().apply_snapshot(_active_snapshot(event_cursor=2))
    first = _terminal_event()
    second = first.model_copy(
        update={
            "cursor": 2,
            "occurred_at": first.occurred_at + timedelta(seconds=1),
        }
    )

    state = state.ingest(first).ingest(second)

    assert state.last_cursor == 2
    assert state.timeline_complete is True
    assert state.event_bytes_by_cursor == (
        (1, canonical_json_bytes(first)),
        (2, canonical_json_bytes(second)),
    )
    assert state.event_at(1) == first
    assert state.event_at(3) is None
    assert state.ingest(second) is state

    divergent = second.model_copy(
        update={"occurred_at": second.occurred_at + timedelta(seconds=1)}
    )
    with pytest.raises(ViewStateProtocolError) as duplicate_error:
        state.ingest(divergent)
    assert duplicate_error.value.code is (
        ViewStateProtocolErrorCode.DIVERGENT_DUPLICATE
    )

    gap = second.model_copy(update={"cursor": 4})
    with pytest.raises(ViewStateProtocolError) as gap_error:
        state.ingest(gap)
    assert gap_error.value.code is ViewStateProtocolErrorCode.EVENT_GAP

    foreign = _event(
        3,
        ScenarioRunEventType.TERMINAL,
        second.payload,
        investigation_id="investigation-other",
    )
    with pytest.raises(ViewStateProtocolError) as identity_error:
        state.ingest(foreign)
    assert identity_error.value.code is ViewStateProtocolErrorCode.EVENT_IDENTITY


def test_snapshot_is_authoritative_for_deterministic_state() -> None:
    active = _active_snapshot(event_cursor=0)
    state = OperatorViewState.empty().apply_snapshot(active).ingest(_terminal_event())

    assert state.render_deterministic() == ("DETERMINISTIC DECISION: PENDING",)
    assert state.render_actions() == ("ACTION PERMISSION: PENDING",)
    assert state.render_missing() == ("MISSING EVIDENCE: DECISION PENDING",)

    terminal = state.apply_snapshot(
        _completed_report_snapshot(Classification.UNKNOWN, event_cursor=1)
    )
    assert terminal.render_deterministic()[0] == (
        "DETERMINISTIC CLASSIFICATION: UNKNOWN"
    )
    assert terminal.render_actions()[0].startswith("ACTION CONTINUE: DENIED")
    assert terminal.render_missing()[0].startswith("MISSING EVIDENCE: effects=")

    with pytest.raises(ViewStateProtocolError) as identity_error:
        terminal.apply_snapshot(
            _active_snapshot(investigation_id="investigation-other", event_cursor=1)
        )
    assert identity_error.value.code is (ViewStateProtocolErrorCode.SNAPSHOT_IDENTITY)

    with pytest.raises(ViewStateProtocolError) as regression_error:
        terminal.apply_snapshot(_active_snapshot(event_cursor=0))
    assert regression_error.value.code is (
        ViewStateProtocolErrorCode.SNAPSHOT_CURSOR_REGRESSION
    )


def test_snapshot_progression_rejects_cursor_terminal_and_content_regression() -> None:
    active = OperatorViewState.empty().apply_snapshot(_active_snapshot(event_cursor=7))
    with pytest.raises(ViewStateProtocolError) as cursor_error:
        active.apply_snapshot(_active_snapshot(event_cursor=3))
    assert cursor_error.value.code is (
        ViewStateProtocolErrorCode.SNAPSHOT_CURSOR_REGRESSION
    )

    completed_snapshot = _completed_report_snapshot(
        Classification.COMMITTED,
        event_cursor=7,
    )
    completed = OperatorViewState.empty().apply_snapshot(completed_snapshot)
    with pytest.raises(ViewStateProtocolError) as lifecycle_error:
        completed.apply_snapshot(_active_snapshot(event_cursor=8))
    assert lifecycle_error.value.code is (
        ViewStateProtocolErrorCode.SNAPSHOT_LIFECYCLE_REGRESSION
    )

    divergent = completed_snapshot.model_copy(
        update={"updated_at": completed_snapshot.updated_at + timedelta(seconds=1)}
    )
    with pytest.raises(ViewStateProtocolError) as divergence_error:
        completed.apply_snapshot(divergent)
    assert divergence_error.value.code is ViewStateProtocolErrorCode.SNAPSHOT_DIVERGENCE


@pytest.mark.parametrize(
    ("classification", "evidence_marker", "missing_marker"),
    (
        (Classification.COMMITTED, "TARGET EVIDENCE ADMITTED", "NONE"),
        (Classification.UNKNOWN, "TARGET EVIDENCE WEAK", "effects="),
    ),
)
def test_fixed_report_sections_have_plain_non_color_semantics(
    classification: Classification,
    evidence_marker: str,
    missing_marker: str,
) -> None:
    state = (
        OperatorViewState.empty()
        .apply_snapshot(_completed_report_snapshot(classification))
        .set_connection(ConnectionPhase.LIVE)
    )
    rendered = state.render_sections()
    plain = "\n".join(
        line
        for section in (
            rendered.connection,
            rendered.outcome,
            rendered.transport,
            rendered.envelope,
            rendered.advisory,
            rendered.evidence,
            rendered.deterministic,
            rendered.actions,
            rendered.missing,
        )
        for line in section
    )

    assert "API CONNECTION: LIVE" in plain
    assert "MUTATION TRANSPORT: MISSING_TOOL_RESULT" in plain
    assert "EXPECTED EFFECT: business-record" in plain
    assert "ADVISORY: NOT USED - FIXED STRATEGY" in plain
    assert evidence_marker in plain
    assert f"DETERMINISTIC CLASSIFICATION: {classification.value}" in plain
    assert "ACTION PERMISSION: ALLOWED=" in plain
    assert "ACTION CONTINUE:" in plain
    assert "ACTION RETRY: DENIED" in plain
    assert f"MISSING EVIDENCE: {missing_marker}" in plain
    assert "\x1b" not in plain


def test_timeline_distinguishes_advisory_requests_results_and_evidence() -> None:
    request_sha256 = "a" * 64
    common_request = {
        "advisory_turn_sequence": 1,
        "capability_name": "gcs-object-readback",
        "capability_version": "1.0.0",
        "request_sha256": request_sha256,
        "relevant_effect_ids": ("business-record",),
    }
    events = (
        _event(
            1,
            ScenarioRunEventType.ADVISORY_TURN,
            AdvisoryTurnEventPayload(
                turn=AdvisoryTurnSummary(
                    turn_sequence=1,
                    phase=AdaptivePlannerPhase.ACQUIRE_EVIDENCE,
                    status=AdvisoryTurnStatus.COMPLETED,
                    input_sha256="b" * 64,
                    output_sha256="c" * 64,
                    proposal_count=2,
                    selected_proposal_count=1,
                    failure_category=None,
                )
            ),
        ),
        _event(
            2,
            ScenarioRunEventType.PROBE_REQUEST,
            ProbeRequestEventPayload(
                strategy=ComparisonStrategyKind.ADAPTIVE,
                request=SanitizedProbeRequest(
                    request_sequence=1,
                    proposal_sequence=1,
                    disposition=ProbeRequestDisposition.SELECTED,
                    **common_request,
                ),
            ),
        ),
        _event(
            3,
            ScenarioRunEventType.PROBE_REQUEST,
            ProbeRequestEventPayload(
                strategy=ComparisonStrategyKind.ADAPTIVE,
                request=SanitizedProbeRequest(
                    request_sequence=2,
                    proposal_sequence=2,
                    disposition=ProbeRequestDisposition.UNSUPPORTED_CAPABILITY,
                    **common_request,
                ),
            ),
        ),
        _event(
            4,
            ScenarioRunEventType.PROBE_RESULT,
            ProbeResultEventPayload(
                strategy=ComparisonStrategyKind.ADAPTIVE,
                probe=SanitizedProbeResult(
                    probe_sequence=1,
                    capability_name="gcs-object-readback",
                    capability_version="1.0.0",
                    request_sha256=request_sha256,
                    outcome=ProbeOutcome.COMPLETED,
                    stop_reason="probe_completed",
                    result_sha256="d" * 64,
                    result_byte_count=2,
                    evidence_ids=("evidence-admitted",),
                ),
            ),
        ),
        _event(
            5,
            ScenarioRunEventType.EVIDENCE_DECISION,
            OperatorEvidenceDecisionEventPayload(
                strategy=ComparisonStrategyKind.ADAPTIVE,
                decision=EvidenceDecision(
                    schema_version=EVIDENCE_DECISION_VERSION,
                    evidence_id="evidence-admitted",
                    disposition=EvidenceDisposition.ADMITTED,
                    reason=EvidenceReason.AUTHORITATIVE_EXACT_CORRELATION,
                ),
            ),
        ),
        _event(
            6,
            ScenarioRunEventType.EVIDENCE_DECISION,
            OperatorEvidenceDecisionEventPayload(
                strategy=ComparisonStrategyKind.ADAPTIVE,
                decision=EvidenceDecision(
                    schema_version=EVIDENCE_DECISION_VERSION,
                    evidence_id="evidence-weak",
                    disposition=EvidenceDisposition.WEAK,
                    reason=EvidenceReason.NON_AUTHORITATIVE_LOG_ONLY,
                ),
            ),
        ),
        _event(
            7,
            ScenarioRunEventType.EVIDENCE_DECISION,
            OperatorEvidenceDecisionEventPayload(
                strategy=ComparisonStrategyKind.ADAPTIVE,
                decision=EvidenceDecision(
                    schema_version=EVIDENCE_DECISION_VERSION,
                    evidence_id="evidence-rejected",
                    disposition=EvidenceDisposition.REJECTED,
                    reason=EvidenceReason.STALE_OBSERVATION,
                ),
            ),
        ),
    )
    state = OperatorViewState.empty().apply_snapshot(
        _active_snapshot(mode=ScenarioRunMode.ADAPTIVE, event_cursor=len(events))
    )
    for event in events:
        state = state.ingest(event)

    plain = "\n".join(state.render_timeline())
    assert "ADVISORY TURN" in plain
    assert "PROBE REQUEST SELECTED" in plain
    assert "PROBE REQUEST DENIED" in plain
    assert "UNSUPPORTED_CAPABILITY" in plain
    assert "PROBE RESULT" in plain
    assert "EVIDENCE ADMITTED" in plain
    assert "EVIDENCE WEAK" in plain
    assert "EVIDENCE REJECTED" in plain


def test_comparison_renders_fixed_then_adaptive_without_overall_decision() -> None:
    state = OperatorViewState.empty().apply_snapshot(_completed_comparison_snapshot())

    comparison = state.render_comparison()
    lane_lines = tuple(
        line for line in comparison if line.startswith("COMPARISON LANE")
    )
    plain = "\n".join(comparison)

    assert lane_lines == (
        "COMPARISON LANE: FIXED",
        "COMPARISON LANE: ADAPTIVE",
    )
    assert "COMPARISON: NEUTRAL FIXED AND ADAPTIVE LANES" in plain
    assert "COMPARISON MODEL USAGE: status=NOT_APPLICABLE" in plain
    assert "COMPARISON MODEL USAGE: status=MEASURED" in plain
    assert state.render_deterministic() == (
        "DETERMINISTIC DECISION: NO OVERALL CLASSIFICATION - NEUTRAL COMPARISON",
    )
    assert state.render_actions() == (
        "ACTION PERMISSION: NOT APPLICABLE - NEUTRAL COMPARISON",
    )
    for disallowed in ("winner", "better", "best", "superior", "recommended"):
        assert disallowed not in plain.lower()


def test_provider_failure_is_not_rendered_as_unknown() -> None:
    state = OperatorViewState.empty().apply_snapshot(_failed_snapshot())
    plain = "\n".join(
        (
            *state.render_advisory(),
            *state.render_deterministic(),
            *state.render_actions(),
        )
    )

    assert "MODEL_UNAVAILABLE" in plain
    assert "RUN FAILED" in plain
    assert "UNKNOWN" not in plain


def test_tui_state_has_no_privileged_product_imports() -> None:
    source_path = (
        Path(__file__).parents[2] / "reconcile" / "interfaces" / "tui_state.py"
    )
    tree = ast.parse(source_path.read_text(encoding="utf-8"))
    imported = {
        alias.name
        for node in ast.walk(tree)
        if isinstance(node, ast.Import)
        for alias in node.names
    }
    imported.update(
        node.module
        for node in ast.walk(tree)
        if isinstance(node, ast.ImportFrom) and node.module is not None
    )
    forbidden = (
        "reconcile.operator",
        "reconcile.scenarios",
        "reconcile.controller",
        "reconcile.evidence",
        "reconcile.adapters",
        "reconcile.persistence",
        "reconcile.application",
    )

    assert not any(
        module == prefix or module.startswith(f"{prefix}.")
        for module in imported
        for prefix in forbidden
    )
