"""Sanitized operator contracts and their cross-field invariants."""

from __future__ import annotations

import json
from collections.abc import Iterable

import pytest
from jsonschema import Draft202012Validator
from pydantic import BaseModel, ValidationError

from reconcile.contracts import (
    EXECUTION_ENVELOPE_SUMMARY_VERSION,
    MAX_SCENARIO_RUN_EVENTS,
    SCENARIO_LAUNCH_REQUEST_VERSION,
    SCENARIO_RUN_EVENT_VERSION,
    SCENARIO_RUN_SNAPSHOT_VERSION,
    AdaptivePlannerPhase,
    AdvisoryTurnEventPayload,
    AdvisoryTurnStatus,
    AdvisoryTurnSummary,
    Classification,
    ComparisonRun,
    ComparisonStrategyKind,
    EnvelopeEffectSummary,
    EnvelopeSummaryEventPayload,
    EvidenceDisposition,
    ExecutionEnvelopeSummary,
    OperatorEvidenceDecisionEventPayload,
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
    ScenarioLaunchRequest,
    ScenarioLifecycleEventPayload,
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
    decode_contract,
)
from tests.contract._factories import (
    NOW,
    make_comparison_record,
    make_envelope,
    make_report,
)

pytestmark = pytest.mark.contract


def _payload(model: BaseModel) -> dict[str, object]:
    return json.loads(canonical_json_bytes(model))


def _make_summary() -> ExecutionEnvelopeSummary:
    envelope = make_envelope()
    return ExecutionEnvelopeSummary(
        schema_version=EXECUTION_ENVELOPE_SUMMARY_VERSION,
        investigation_id=envelope.investigation_id,
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


def _make_sanitized_report(
    classification: Classification = Classification.COMMITTED,
) -> SanitizedInvestigationReport:
    report = make_report(classification)
    evidence_by_id = {item.evidence_id: item for item in report.evidence}
    evidence = tuple(
        SanitizedEvidenceSummary(
            evidence_id=decision.evidence_id,
            capability_name=(
                evidence_by_id[decision.evidence_id].capability_name
                if decision.evidence_id in evidence_by_id
                else None
            ),
            capability_version=(
                evidence_by_id[decision.evidence_id].capability_version
                if decision.evidence_id in evidence_by_id
                else None
            ),
            disposition=decision.disposition,
            reason=decision.reason,
            authority=(
                evidence_by_id[decision.evidence_id].authority
                if decision.evidence_id in evidence_by_id
                else None
            ),
            effect_assertions=(
                evidence_by_id[decision.evidence_id].effect_assertions
                if decision.evidence_id in evidence_by_id
                else ()
            ),
            operation_status=(
                evidence_by_id[decision.evidence_id].operation_status
                if decision.evidence_id in evidence_by_id
                else None
            ),
        )
        for decision in report.evidence_decisions
    )
    proof = report.proof
    assert proof is not None
    sanitized_proof = SanitizedDeterministicProof(
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
        evidence=evidence,
        proof=sanitized_proof,
        classification=report.classification,
        action_gate=report.action_gate,
        missing_evidence=tuple(
            SanitizedMissingEvidence(effect_ids=item.effect_ids, reason=item.reason)
            for item in report.missing_evidence
        ),
        advisory_cited_evidence_ids=(
            report.advisory_explanation.cited_evidence_ids
            if report.advisory_explanation is not None
            else ()
        ),
        created_at=report.created_at,
        updated_at=report.updated_at,
        revision=report.revision,
    )


def _project_comparison_run(run: ComparisonRun) -> SanitizedComparisonRun:
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


def _make_sanitized_comparison() -> SanitizedInvestigationComparison:
    source = make_comparison_record(include_adaptive=True)
    assert source.adaptive is not None
    return SanitizedInvestigationComparison(
        comparison_id=source.comparison_id,
        envelope_sha256=source.envelope_sha256,
        baseline=_project_comparison_run(source.baseline),
        adaptive=_project_comparison_run(source.adaptive),
    )


def _make_snapshot(
    *,
    mode: ScenarioRunMode = ScenarioRunMode.FIXED,
) -> ScenarioRunSnapshot:
    summary = _make_summary()
    report = _make_sanitized_report() if mode is not ScenarioRunMode.COMPARE else None
    comparison = (
        _make_sanitized_comparison() if mode is ScenarioRunMode.COMPARE else None
    )
    if comparison is not None:
        summary = summary.model_copy(
            update={"envelope_sha256": comparison.envelope_sha256}
        )
    return ScenarioRunSnapshot(
        schema_version=SCENARIO_RUN_SNAPSHOT_VERSION,
        launch_id="launch-7",
        investigation_id=summary.investigation_id,
        scenario=ScenarioLaunchName.STORAGE,
        mode=mode,
        lifecycle=ScenarioRunLifecycle.COMPLETED,
        event_cursor=7,
        envelope_summary=summary,
        report=report,
        comparison=comparison,
        failure_category=None,
        accepted_at=NOW,
        updated_at=NOW.replace(second=10),
    )


def _make_probe_result() -> SanitizedProbeResult:
    item = _make_sanitized_report().probe_audit[0]
    return SanitizedProbeResult(
        probe_sequence=item.probe_sequence,
        capability_name=item.capability_name,
        capability_version=item.capability_version,
        request_sha256=item.request_sha256,
        outcome=item.outcome,
        stop_reason=item.stop_reason,
        result_sha256=item.result_sha256,
        result_byte_count=item.result_byte_count,
        evidence_ids=item.evidence_ids,
    )


def _make_event(event_type: ScenarioRunEventType) -> ScenarioRunEvent:
    summary = _make_summary()
    report = _make_sanitized_report()
    allowed = sum(gate.allowed for gate in report.action_gate)
    payloads = {
        ScenarioRunEventType.LIFECYCLE: ScenarioLifecycleEventPayload(
            lifecycle=ScenarioRunLifecycle.RUNNING,
        ),
        ScenarioRunEventType.ENVELOPE_SUMMARY: EnvelopeSummaryEventPayload(
            summary=summary,
        ),
        ScenarioRunEventType.ADVISORY_TURN: AdvisoryTurnEventPayload(
            turn=AdvisoryTurnSummary(
                turn_sequence=1,
                phase=AdaptivePlannerPhase.ACQUIRE_EVIDENCE,
                status=AdvisoryTurnStatus.COMPLETED,
                input_sha256="1" * 64,
                output_sha256="2" * 64,
                proposal_count=1,
                selected_proposal_count=1,
                failure_category=None,
            ),
        ),
        ScenarioRunEventType.PROBE_REQUEST: ProbeRequestEventPayload(
            strategy=ComparisonStrategyKind.FIXED,
            request=SanitizedProbeRequest(
                request_sequence=1,
                capability_name="gcs-object-readback",
                capability_version="1.0.0",
                request_sha256="3" * 64,
                relevant_effect_ids=("business-record",),
                disposition=ProbeRequestDisposition.SELECTED,
            ),
        ),
        ScenarioRunEventType.PROBE_RESULT: ProbeResultEventPayload(
            strategy=ComparisonStrategyKind.FIXED,
            probe=_make_probe_result(),
        ),
        ScenarioRunEventType.EVIDENCE_DECISION: (
            OperatorEvidenceDecisionEventPayload(
                strategy=ComparisonStrategyKind.FIXED,
                decision=make_report(Classification.COMMITTED).evidence_decisions[0],
            )
        ),
        ScenarioRunEventType.TERMINAL: TerminalStateEventPayload(
            terminal=TerminalStateSummary(
                lifecycle=ScenarioRunLifecycle.COMPLETED,
                result_kind=ScenarioRunResultKind.REPORT,
                classification=Classification.COMMITTED,
                action_gate_allowed_count=allowed,
                action_gate_denied_count=len(report.action_gate) - allowed,
                missing_evidence_count=0,
                escalation_required=False,
                failure_category=None,
            ),
        ),
    }
    return ScenarioRunEvent(
        schema_version=SCENARIO_RUN_EVENT_VERSION,
        investigation_id=summary.investigation_id,
        cursor=tuple(ScenarioRunEventType).index(event_type) + 1,
        type=event_type,
        occurred_at=NOW,
        payload=payloads[event_type],
    )


@pytest.mark.parametrize(
    ("contract", "model_type"),
    (
        (_make_summary(), ExecutionEnvelopeSummary),
        (
            ScenarioLaunchRequest(
                schema_version=SCENARIO_LAUNCH_REQUEST_VERSION,
                launch_id="launch-7",
                scenario=ScenarioLaunchName.STORAGE,
            ),
            ScenarioLaunchRequest,
        ),
        (_make_snapshot(), ScenarioRunSnapshot),
        (_make_event(ScenarioRunEventType.TERMINAL), ScenarioRunEvent),
    ),
)
def test_operator_contracts_have_canonical_round_trips(
    contract: BaseModel,
    model_type: type[BaseModel],
) -> None:
    encoded = canonical_json_bytes(contract)
    decoded = decode_contract(encoded, model_type)

    assert decoded == contract
    assert canonical_json_bytes(decoded) == encoded


def test_launch_is_bounded_to_the_three_scenarios_and_three_modes() -> None:
    assert tuple(item.value for item in ScenarioLaunchName) == (
        "storage",
        "firestore-business",
        "sandbox-order",
    )
    assert tuple(item.value for item in ScenarioRunMode) == (
        "fixed",
        "adaptive",
        "compare",
    )
    launch = ScenarioLaunchRequest(
        schema_version=SCENARIO_LAUNCH_REQUEST_VERSION,
        launch_id="launch-7",
        scenario=ScenarioLaunchName.STORAGE,
    )
    assert launch.mode is ScenarioRunMode.FIXED


@pytest.mark.parametrize(
    "field",
    ("investigation_id", "target", "arguments", "correlation", "seed"),
)
def test_launch_rejects_server_owned_or_sensitive_fields(field: str) -> None:
    payload = {
        "schema_version": SCENARIO_LAUNCH_REQUEST_VERSION,
        "launch_id": "launch-7",
        "scenario": "storage",
        "mode": "fixed",
        field: {},
    }

    with pytest.raises(ValidationError):
        ScenarioLaunchRequest.model_validate_json(json.dumps(payload))


def test_envelope_summary_omits_target_coordinates_and_execution_content() -> None:
    payload = _payload(_make_summary())

    assert set(payload) == {
        "schema_version",
        "investigation_id",
        "envelope_sha256",
        "target_kind",
        "invoked_at",
        "ambiguity_kind",
        "ambiguity_observed_at",
        "expected_effects",
        "enabled_capabilities",
        "evidence_budget",
    }
    encoded = canonical_json_bytes(_make_summary()).decode()
    for prohibited in (
        '"scope"',
        '"resource"',
        '"arguments"',
        '"predicate"',
        '"description"',
        '"correlation_fields"',
        '"detail"',
    ):
        assert prohibited not in encoded


def test_snapshot_report_projection_omits_raw_evidence_and_free_text() -> None:
    report = _payload(_make_sanitized_report(Classification.UNKNOWN))
    encoded = json.dumps(report, sort_keys=True)

    assert report["classification"] == "UNKNOWN"
    assert report["missing_evidence"]
    assert report["evidence"][0]["disposition"] == "WEAK"  # type: ignore[index]
    for prohibited in (
        '"target"',
        '"scope"',
        '"resource"',
        '"arguments"',
        '"predicate"',
        '"description"',
        '"correlation"',
        '"source_record"',
        '"reference"',
        '"text"',
    ):
        assert prohibited not in encoded


def test_comparison_projection_removes_preregistered_hidden_truth() -> None:
    payload = _payload(_make_snapshot(mode=ScenarioRunMode.COMPARE))
    encoded = json.dumps(payload, sort_keys=True)

    assert '"expected_classification"' not in encoded
    assert '"matches_preregistered_expectation"' not in encoded
    assert '"preregistered_expectation"' not in encoded
    assert '"case_id"' not in encoded
    assert payload["comparison"]["baseline"]["strategy_kind"] == "FIXED"  # type: ignore[index]
    assert payload["comparison"]["adaptive"]["strategy_kind"] == "ADAPTIVE"  # type: ignore[index]


@pytest.mark.parametrize("event_type", tuple(ScenarioRunEventType))
def test_every_operator_event_has_a_canonical_round_trip(
    event_type: ScenarioRunEventType,
) -> None:
    event = _make_event(event_type)
    encoded = canonical_json_bytes(event)

    assert decode_contract(encoded, ScenarioRunEvent) == event
    Draft202012Validator(ScenarioRunEvent.model_json_schema()).validate(
        json.loads(encoded)
    )


@pytest.mark.parametrize(
    ("event_type", "payload_type"),
    tuple(
        (event_type, payload_type)
        for event_type in ScenarioRunEventType
        for payload_type in ScenarioRunEventType
        if event_type is not payload_type
    ),
)
def test_event_type_must_match_payload_at_runtime_and_in_schema(
    event_type: ScenarioRunEventType,
    payload_type: ScenarioRunEventType,
) -> None:
    payload = _payload(_make_event(payload_type))
    payload["type"] = event_type.value

    with pytest.raises(ValidationError, match="type does not match"):
        ScenarioRunEvent.model_validate_json(json.dumps(payload))
    assert list(
        Draft202012Validator(ScenarioRunEvent.model_json_schema()).iter_errors(payload)
    )


def test_event_wire_contains_no_unbounded_or_privileged_payload_fields() -> None:
    events = tuple(_make_event(event_type) for event_type in ScenarioRunEventType)
    encoded = b"\n".join(canonical_json_bytes(event) for event in events).decode()

    for prohibited in (
        '"scope"',
        '"resource"',
        '"arguments"',
        '"predicate"',
        '"description"',
        '"correlation"',
        '"exception"',
        '"credentials"',
        '"cleanup"',
        '"expected_classification"',
    ):
        assert prohibited not in encoded


@pytest.mark.parametrize("cursor", (0, MAX_SCENARIO_RUN_EVENTS + 1))
def test_event_cursor_is_positive_and_bounded(cursor: int) -> None:
    payload = _payload(_make_event(ScenarioRunEventType.LIFECYCLE))
    payload["cursor"] = cursor

    with pytest.raises(ValidationError):
        ScenarioRunEvent.model_validate_json(json.dumps(payload))


def test_journal_and_individual_proposal_counts_cover_the_bounded_run() -> None:
    assert MAX_SCENARIO_RUN_EVENTS == 1024
    request = SanitizedProbeRequest(
        request_sequence=584,
        advisory_turn_sequence=65,
        proposal_sequence=8,
        capability_name="gcs-object-readback",
        capability_version="1.0.0",
        request_sha256="3" * 64,
        relevant_effect_ids=("business-record",),
        disposition=ProbeRequestDisposition.DEFERRED,
    )
    assert request.proposal_sequence == 8

    for change in (
        {"request_sequence": 585},
        {"proposal_sequence": None},
        {"advisory_turn_sequence": None},
    ):
        with pytest.raises(ValidationError):
            type(request).model_validate(request.model_copy(update=change))


def test_snapshot_lifecycle_owns_result_and_failure_presence() -> None:
    completed = _payload(_make_snapshot())

    completed["lifecycle"] = "FAILED"
    completed["failure_category"] = "model_unavailable"
    with pytest.raises(ValidationError, match="failure category"):
        ScenarioRunSnapshot.model_validate_json(json.dumps(completed))

    failed = ScenarioRunSnapshot(
        schema_version=SCENARIO_RUN_SNAPSHOT_VERSION,
        launch_id="launch-7",
        investigation_id="investigation-7",
        scenario=ScenarioLaunchName.STORAGE,
        mode=ScenarioRunMode.ADAPTIVE,
        lifecycle=ScenarioRunLifecycle.FAILED,
        event_cursor=2,
        envelope_summary=None,
        report=None,
        comparison=None,
        failure_category=ScenarioRunFailureCategory.MODEL_UNAVAILABLE,
        accepted_at=NOW,
        updated_at=NOW,
    )
    assert failed.failure_category is ScenarioRunFailureCategory.MODEL_UNAVAILABLE

    accepted = _payload(failed)
    accepted["lifecycle"] = "ACCEPTED"
    with pytest.raises(ValidationError, match="accepted snapshots"):
        ScenarioRunSnapshot.model_validate_json(json.dumps(accepted))


def test_snapshot_rejects_cross_investigation_and_envelope_results() -> None:
    payload = _payload(_make_snapshot())
    payload["report"]["investigation_id"] = "other-investigation"  # type: ignore[index]

    with pytest.raises(ValidationError, match="investigation"):
        ScenarioRunSnapshot.model_validate_json(json.dumps(payload))

    payload = _payload(_make_snapshot())
    payload["report"]["envelope_sha256"] = "0" * 64  # type: ignore[index]
    with pytest.raises(ValidationError, match="envelope"):
        ScenarioRunSnapshot.model_validate_json(json.dumps(payload))


def test_completed_comparison_requires_both_neutral_lanes() -> None:
    payload = _payload(_make_snapshot(mode=ScenarioRunMode.COMPARE))
    payload["comparison"]["adaptive"] = None  # type: ignore[index]

    with pytest.raises(ValidationError, match="both lanes"):
        ScenarioRunSnapshot.model_validate_json(json.dumps(payload))


@pytest.mark.parametrize("classification", tuple(Classification))
def test_report_projection_preserves_every_deterministic_classification(
    classification: Classification,
) -> None:
    report = _make_sanitized_report(classification)

    assert report.classification is classification
    assert (
        decode_contract(
            canonical_json_bytes(
                ScenarioRunSnapshot(
                    schema_version=SCENARIO_RUN_SNAPSHOT_VERSION,
                    launch_id="launch-7",
                    investigation_id=report.investigation_id,
                    scenario=ScenarioLaunchName.STORAGE,
                    mode=ScenarioRunMode.FIXED,
                    lifecycle=ScenarioRunLifecycle.COMPLETED,
                    event_cursor=7,
                    envelope_summary=_make_summary(),
                    report=report,
                    comparison=None,
                    failure_category=None,
                    accepted_at=NOW,
                    updated_at=report.updated_at,
                )
            ),
            ScenarioRunSnapshot,
        ).report
        == report
    )


def test_sanitized_report_preserves_deterministic_authority_invariants() -> None:
    payload = _payload(_make_sanitized_report())
    payload["action_gate"][0]["classification"] = "UNKNOWN"  # type: ignore[index]

    with pytest.raises(ValidationError):
        SanitizedInvestigationReport.model_validate_json(json.dumps(payload))

    committed = _payload(_make_sanitized_report(Classification.COMMITTED))
    unknown = _payload(_make_sanitized_report(Classification.UNKNOWN))
    committed["classification"] = "UNKNOWN"
    committed["action_gate"] = unknown["action_gate"]
    committed["missing_evidence"] = unknown["missing_evidence"]
    with pytest.raises(ValidationError, match="deterministic proof"):
        SanitizedInvestigationReport.model_validate_json(json.dumps(committed))

    payload = _payload(_make_sanitized_report())
    payload["proof"]["admitted_evidence_ids"] = []  # type: ignore[index]
    with pytest.raises(ValidationError, match="admitted evidence"):
        SanitizedInvestigationReport.model_validate_json(json.dumps(payload))


def test_evidence_disposition_cannot_fabricate_authority() -> None:
    payload = _payload(_make_sanitized_report())
    item = payload["evidence"][0]  # type: ignore[index]
    item["disposition"] = EvidenceDisposition.REJECTED.value  # type: ignore[index]

    with pytest.raises(ValidationError, match="disposition"):
        SanitizedInvestigationReport.model_validate_json(json.dumps(payload))


def test_terminal_state_cannot_turn_comparison_into_one_classification() -> None:
    terminal = TerminalStateSummary(
        lifecycle=ScenarioRunLifecycle.COMPLETED,
        result_kind=ScenarioRunResultKind.COMPARISON,
        classification=None,
        action_gate_allowed_count=0,
        action_gate_denied_count=0,
        missing_evidence_count=0,
        escalation_required=None,
        failure_category=None,
    )
    payload = _payload(terminal)
    payload["classification"] = "COMMITTED"

    with pytest.raises(ValidationError, match="neutral"):
        TerminalStateSummary.model_validate_json(json.dumps(payload))


@pytest.mark.parametrize(
    "lifecycle",
    (
        ScenarioRunLifecycle.COMPLETED,
        ScenarioRunLifecycle.FAILED,
        ScenarioRunLifecycle.CANCELLED,
    ),
)
def test_terminal_lifecycle_requires_the_terminal_event_contract(
    lifecycle: ScenarioRunLifecycle,
) -> None:
    with pytest.raises(ValidationError):
        ScenarioLifecycleEventPayload(lifecycle=lifecycle)


def test_all_four_operator_schemas_are_strict_and_exactly_versioned() -> None:
    models: Iterable[type[BaseModel]] = (
        ExecutionEnvelopeSummary,
        ScenarioLaunchRequest,
        ScenarioRunSnapshot,
        ScenarioRunEvent,
    )
    expected_versions = (
        EXECUTION_ENVELOPE_SUMMARY_VERSION,
        SCENARIO_LAUNCH_REQUEST_VERSION,
        SCENARIO_RUN_SNAPSHOT_VERSION,
        SCENARIO_RUN_EVENT_VERSION,
    )

    for model, expected_version in zip(models, expected_versions, strict=True):
        schema = model.model_json_schema()
        assert schema["additionalProperties"] is False
        assert schema["properties"]["schema_version"]["const"] == expected_version
        assert "schema_version" in schema["required"]
