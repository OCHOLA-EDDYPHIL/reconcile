"""Focused tests for the bounded Phase 5 remote acceptance harness."""

from __future__ import annotations

import asyncio
import hashlib
import json
import os
import stat
import subprocess
from datetime import UTC, datetime, timedelta
from pathlib import Path

import httpx
import pytest

import reconcile.phase5_hosted_acceptance as acceptance_module
from reconcile.adapters.firestore_business import (
    FIRESTORE_BUSINESS_CAPABILITY_NAME,
    FIRESTORE_BUSINESS_TARGET_KIND,
)
from reconcile.adapters.sandbox_order import SANDBOX_ORDER_TARGET_KIND
from reconcile.adapters.storage import STORAGE_CAPABILITY_NAME, STORAGE_TARGET_KIND
from reconcile.contracts import (
    BOUNDED_HYBRID_ROUTE_POLICY_VERSION,
    EXECUTION_ENVELOPE_SUMMARY_VERSION,
    SCENARIO_LAUNCH_REQUEST_VERSION,
    SCENARIO_OPERATIONAL_STATUS_VERSION,
    SCENARIO_RUN_EVENT_VERSION,
    SCENARIO_RUN_SNAPSHOT_VERSION,
    AdaptivePlannerPhase,
    AdvisoryTurnEventPayload,
    AdvisoryTurnFailureCategory,
    AdvisoryTurnStatus,
    AdvisoryTurnSummary,
    AmbiguityKind,
    CapabilityRef,
    Classification,
    ComparisonStrategyKind,
    EffectAssertion,
    EffectAssertionState,
    EnvelopeEffectSummary,
    EvidenceAuthority,
    EvidenceBudget,
    EvidenceDisposition,
    EvidenceReason,
    ExecutionEnvelopeSummary,
    InvestigationStatus,
    OperationStatus,
    ProbeOutcome,
    ProbeRequestDisposition,
    ProbeRequestEventPayload,
    SanitizedDeterministicProof,
    SanitizedEffectFinding,
    SanitizedEvidenceSummary,
    SanitizedInvestigationReport,
    SanitizedMissingEvidence,
    SanitizedProbeAuditRecord,
    SanitizedProbeRequest,
    ScenarioHybridOutcome,
    ScenarioHybridRoute,
    ScenarioLaunchName,
    ScenarioLaunchRequest,
    ScenarioLifecycleEventPayload,
    ScenarioOperationalCleanupState,
    ScenarioOperationalInvestigationState,
    ScenarioOperationalMutationState,
    ScenarioOperationalRecoveryState,
    ScenarioOperationalStatus,
    ScenarioRouteProvenance,
    ScenarioRunEvent,
    ScenarioRunEventType,
    ScenarioRunLifecycle,
    ScenarioRunMode,
    ScenarioRunResultKind,
    ScenarioRunSnapshot,
    TerminalStateEventPayload,
    TerminalStateSummary,
    canonical_json_bytes,
)
from reconcile.evidence.classification import _action_gates
from reconcile.interfaces.operator_api_client import ScenarioLaunchResult
from reconcile.phase5_hosted_acceptance import (
    PHASE5_HOSTED_ACCEPTANCE_VERSION,
    AcceptanceLimitation,
    AcceptanceMode,
    CandidateIdentity,
    CloudRunAcceptanceBackend,
    CursorResumeObservation,
    DenialLayer,
    DenialObservation,
    DuplicateRequestObservation,
    GcloudReadOnlyInspector,
    HostedAcceptanceError,
    HostedAcceptanceRecord,
    InterfaceParityObservation,
    LifecycleDiagnostics,
    ScenarioAcceptanceObservation,
    ServiceComponent,
    ServiceDeploymentObservation,
    _validate_firestore_public_report,
    _validate_provider_scenario,
    _validate_sandbox_unknown_public_report,
    build_candidate_identity,
    read_acceptance_record,
    read_provider_record,
    run_hosted_acceptance,
    run_provider_acceptance,
)
from reconcile.scenarios.firestore_business import FIRESTORE_BUSINESS_EFFECT_IDS
from reconcile.scenarios.sandbox_order import (
    SANDBOX_ORDER_AGGREGATE_CAPABILITY_NAME,
    SANDBOX_ORDER_EFFECT_ID,
    SANDBOX_ORDER_INGRESS_CAPABILITY_NAME,
)
from reconcile.scenarios.storage import STORAGE_EFFECT_ID

pytestmark = pytest.mark.unit

NOW = datetime(2026, 8, 18, 12, tzinfo=UTC)
SHA_A = "a" * 64
SHA_B = "b" * 64
SHA_C = "c" * 64
IMAGE = f"sha256:{SHA_B}"
SOURCE = "1" * 40
PROJECT = "reconcile-dev-260813-14fa6d"


def _candidate() -> CandidateIdentity:
    return build_candidate_identity(
        source_revision=SOURCE,
        image_digest=IMAGE,
        infrastructure_revision=SHA_A,
        semantic_config_sha256=SHA_C,
    )


def _route(
    outcome: ScenarioHybridOutcome,
) -> ScenarioRouteProvenance:
    if outcome is ScenarioHybridOutcome.FIXED_AUTHORITATIVE:
        return ScenarioRouteProvenance(
            policy_version=BOUNDED_HYBRID_ROUTE_POLICY_VERSION,
            route=ScenarioHybridRoute.FIXED_AUTHORITATIVE,
            outcome=outcome,
            planner_invoked=False,
            fixed_connector_invoked=True,
            provider_failure=False,
            provider_cleanup_failure=False,
        )
    if outcome is ScenarioHybridOutcome.FIXED_FALLBACK:
        return ScenarioRouteProvenance(
            policy_version=BOUNDED_HYBRID_ROUTE_POLICY_VERSION,
            route=ScenarioHybridRoute.PLANNER_HETEROGENEOUS,
            outcome=outcome,
            planner_invoked=False,
            fixed_connector_invoked=True,
            provider_failure=True,
            provider_cleanup_failure=False,
        )
    if outcome is ScenarioHybridOutcome.EXPLICIT_UNKNOWN:
        return ScenarioRouteProvenance(
            policy_version=BOUNDED_HYBRID_ROUTE_POLICY_VERSION,
            route=ScenarioHybridRoute.PLANNER_HETEROGENEOUS,
            outcome=outcome,
            planner_invoked=True,
            fixed_connector_invoked=False,
            provider_failure=True,
            provider_cleanup_failure=False,
        )
    return ScenarioRouteProvenance(
        policy_version=BOUNDED_HYBRID_ROUTE_POLICY_VERSION,
        route=ScenarioHybridRoute.PLANNER_HETEROGENEOUS,
        outcome=outcome,
        planner_invoked=True,
        fixed_connector_invoked=False,
        provider_failure=False,
        provider_cleanup_failure=False,
    )


def _report(
    classification: Classification,
    route: ScenarioRouteProvenance,
    *,
    capabilities: tuple[str, ...],
    effects: tuple[tuple[str, str, EffectAssertionState], ...],
    operation_status: OperationStatus | None,
    audit_counters: tuple[tuple[int, int, int], ...] | None = None,
    proof_commit_scopes: tuple[str, ...] | None = None,
) -> SanitizedInvestigationReport:
    if audit_counters is not None and len(audit_counters) != len(capabilities):
        raise ValueError("test audit counters do not match capabilities")
    if proof_commit_scopes is not None and len(proof_commit_scopes) != len(effects):
        raise ValueError("test proof scopes do not match effects")
    audits = tuple(
        SanitizedProbeAuditRecord(
            probe_sequence=index,
            capability_name=capability,
            capability_version="1.0.0",
            request_sha256=str(index) * 64,
            outcome=ProbeOutcome.COMPLETED,
            stop_reason="completed",
            started_at=NOW + timedelta(milliseconds=index),
            completed_at=NOW + timedelta(milliseconds=index + 1),
            session_elapsed_ms=index,
            probe_count_used=(
                index if audit_counters is None else audit_counters[index - 1][0]
            ),
            cost_units_used=(
                index if audit_counters is None else audit_counters[index - 1][1]
            ),
            result_bytes_acquired=(
                64 * index if audit_counters is None else audit_counters[index - 1][2]
            ),
            result_sha256=str(index + 3) * 64,
            result_byte_count=64,
            evidence_ids=(f"evidence-{index}",),
        )
        for index, capability in enumerate(capabilities, 1)
    )
    definitive = classification in {Classification.COMMITTED, Classification.PARTIAL}
    evidence = tuple(
        SanitizedEvidenceSummary(
            evidence_id=f"evidence-{index}",
            capability_name=capability,
            capability_version="1.0.0",
            disposition=(
                EvidenceDisposition.ADMITTED if definitive else EvidenceDisposition.WEAK
            ),
            reason=(
                EvidenceReason.AUTHORITATIVE_EXACT_CORRELATION
                if definitive
                else EvidenceReason.NON_AUTHORITATIVE_LOG_ONLY
            ),
            authority=(
                EvidenceAuthority.TARGET_STATE
                if definitive
                else EvidenceAuthority.SUPPLEMENTARY
            ),
            effect_assertions=tuple(
                EffectAssertion(effect_id=effect_id, state=state)
                for effect_id, _commit_scope, state in effects
            ),
            operation_status=operation_status,
        )
        for index, capability in enumerate(capabilities, 1)
    )
    citation = tuple(f"evidence-{index}" for index in range(1, len(evidence) + 1))
    proof = SanitizedDeterministicProof(
        effect_findings=tuple(
            SanitizedEffectFinding(
                effect_id=effect_id,
                commit_scope=(
                    commit_scope
                    if proof_commit_scopes is None
                    else proof_commit_scopes[index]
                ),
                state=state,
                evidence_ids=citation if definitive else (),
            )
            for index, (effect_id, commit_scope, state) in enumerate(effects)
        ),
        operation_status=operation_status,
        conflicting_authority=False,
        admitted_evidence_ids=citation if definitive else (),
    )
    missing = ()
    if classification is Classification.PARTIAL:
        missing = (
            SanitizedMissingEvidence(
                effect_ids=(FIRESTORE_BUSINESS_EFFECT_IDS[2],),
                reason="authoritative-effect-proof-required",
            ),
        )
    elif classification is Classification.UNKNOWN:
        missing = (
            SanitizedMissingEvidence(
                effect_ids=(SANDBOX_ORDER_EFFECT_ID,),
                reason=EvidenceReason.NON_AUTHORITATIVE_LOG_ONLY.value,
            ),
        )
    return SanitizedInvestigationReport(
        investigation_id="placeholder",
        envelope_sha256=SHA_A,
        status=InvestigationStatus.COMPLETED,
        probe_audit=audits,
        evidence=evidence,
        proof=proof,
        classification=classification,
        action_gate=_action_gates(
            classification,
            classification_policy_version="classification-v1",
            action_policy_version="action-v1",
        ),
        missing_evidence=missing,
        advisory_cited_evidence_ids=(),
        route_provenance=route,
        created_at=NOW,
        updated_at=NOW + timedelta(seconds=1),
        revision=1,
    )


def _summary(
    investigation_id: str,
    *,
    target_kind: str,
    capabilities: tuple[str, ...],
    effects: tuple[tuple[str, str, EffectAssertionState], ...],
) -> ExecutionEnvelopeSummary:
    return ExecutionEnvelopeSummary(
        schema_version=EXECUTION_ENVELOPE_SUMMARY_VERSION,
        investigation_id=investigation_id,
        envelope_sha256=SHA_A,
        target_kind=target_kind,
        invoked_at=NOW,
        ambiguity_kind=AmbiguityKind.PROCESS_INTERRUPTED,
        ambiguity_observed_at=NOW,
        expected_effects=tuple(
            EnvelopeEffectSummary(effect_id=effect_id, commit_scope=commit_scope)
            for effect_id, commit_scope, _state in effects
        ),
        enabled_capabilities=tuple(
            CapabilityRef(name=name, version="1.0.0") for name in capabilities
        ),
        evidence_budget=EvidenceBudget(
            max_probes=2,
            max_elapsed_ms=5_000,
            max_total_result_bytes=8_192,
            max_cost_units=2,
        ),
    )


def _observation(
    request,
    purpose: str,
    classification: Classification,
    route: ScenarioRouteProvenance,
    *,
    capabilities: tuple[str, ...] | None = None,
    audit_counters: tuple[tuple[int, int, int], ...] | None = None,
    proof_commit_scopes: tuple[str, ...] | None = None,
    provider_event_shape: str = "valid",
) -> ScenarioAcceptanceObservation:
    investigation_id = f"investigation-{request.launch_id}"
    if request.scenario is ScenarioLaunchName.STORAGE:
        target_kind = STORAGE_TARGET_KIND
        selected_capabilities = (STORAGE_CAPABILITY_NAME,)
        effects = (
            (
                STORAGE_EFFECT_ID,
                "object-create",
                EffectAssertionState.ESTABLISHED,
            ),
        )
        operation_status = OperationStatus.TERMINAL_COMMITTED
    elif request.scenario is ScenarioLaunchName.FIRESTORE_BUSINESS:
        target_kind = FIRESTORE_BUSINESS_TARGET_KIND
        selected_capabilities = (FIRESTORE_BUSINESS_CAPABILITY_NAME,)
        effects = (
            (
                FIRESTORE_BUSINESS_EFFECT_IDS[0],
                FIRESTORE_BUSINESS_EFFECT_IDS[0],
                EffectAssertionState.ESTABLISHED,
            ),
            (
                FIRESTORE_BUSINESS_EFFECT_IDS[1],
                FIRESTORE_BUSINESS_EFFECT_IDS[1],
                EffectAssertionState.ESTABLISHED,
            ),
            (
                FIRESTORE_BUSINESS_EFFECT_IDS[2],
                FIRESTORE_BUSINESS_EFFECT_IDS[2],
                EffectAssertionState.NOT_ESTABLISHED,
            ),
        )
        operation_status = OperationStatus.TERMINAL_COMMITTED
    else:
        target_kind = SANDBOX_ORDER_TARGET_KIND
        selected_capabilities = (
            SANDBOX_ORDER_INGRESS_CAPABILITY_NAME,
            SANDBOX_ORDER_AGGREGATE_CAPABILITY_NAME,
        )
        effects = (
            (
                SANDBOX_ORDER_EFFECT_ID,
                "sandbox-order",
                EffectAssertionState.UNVERIFIED,
            ),
        )
        operation_status = None
    selected_capabilities = capabilities or selected_capabilities
    report = _report(
        classification,
        route,
        capabilities=selected_capabilities,
        effects=effects,
        operation_status=operation_status,
        audit_counters=audit_counters,
        proof_commit_scopes=proof_commit_scopes,
    ).model_copy(update={"investigation_id": investigation_id})
    summary = _summary(
        investigation_id,
        target_kind=target_kind,
        capabilities=(
            (
                SANDBOX_ORDER_INGRESS_CAPABILITY_NAME,
                SANDBOX_ORDER_AGGREGATE_CAPABILITY_NAME,
            )
            if request.scenario is ScenarioLaunchName.SANDBOX_ORDER
            else selected_capabilities
        ),
        effects=effects,
    )
    terminal = TerminalStateSummary(
        lifecycle=ScenarioRunLifecycle.COMPLETED,
        result_kind=ScenarioRunResultKind.REPORT,
        classification=classification,
        action_gate_allowed_count=sum(item.allowed for item in report.action_gate),
        action_gate_denied_count=sum(not item.allowed for item in report.action_gate),
        missing_evidence_count=len(report.missing_evidence),
        escalation_required=classification is not Classification.COMMITTED,
        failure_category=None,
        route_provenance=route,
    )
    event_list = [
        ScenarioRunEvent(
            schema_version=SCENARIO_RUN_EVENT_VERSION,
            investigation_id=investigation_id,
            cursor=1,
            type=ScenarioRunEventType.LIFECYCLE,
            occurred_at=NOW,
            payload=ScenarioLifecycleEventPayload(
                lifecycle=ScenarioRunLifecycle.ACCEPTED
            ),
        ),
        ScenarioRunEvent(
            schema_version=SCENARIO_RUN_EVENT_VERSION,
            investigation_id=investigation_id,
            cursor=2,
            type=ScenarioRunEventType.LIFECYCLE,
            occurred_at=NOW + timedelta(milliseconds=1),
            payload=ScenarioLifecycleEventPayload(
                lifecycle=ScenarioRunLifecycle.RUNNING
            ),
        ),
    ]
    if purpose == "provider-sandbox-adaptive":
        if provider_event_shape not in {"valid", "none", "planner-no-selection"}:
            raise ValueError("unsupported provider test event shape")
        if provider_event_shape != "none" and route.outcome in {
            ScenarioHybridOutcome.PLANNER_EVIDENCE,
            ScenarioHybridOutcome.EXPLICIT_UNKNOWN,
        }:
            started = AdvisoryTurnSummary(
                turn_sequence=1,
                phase=AdaptivePlannerPhase.ACQUIRE_EVIDENCE,
                status=AdvisoryTurnStatus.STARTED,
                input_sha256=SHA_B,
                output_sha256=None,
                proposal_count=0,
                selected_proposal_count=0,
                failure_category=None,
            )
            event_list.append(
                ScenarioRunEvent(
                    schema_version=SCENARIO_RUN_EVENT_VERSION,
                    investigation_id=investigation_id,
                    cursor=len(event_list) + 1,
                    type=ScenarioRunEventType.ADVISORY_TURN,
                    occurred_at=NOW + timedelta(milliseconds=len(event_list) + 1),
                    payload=AdvisoryTurnEventPayload(turn=started),
                )
            )
            planner_selected = (
                route.outcome is ScenarioHybridOutcome.PLANNER_EVIDENCE
                and provider_event_shape == "valid"
            )
            terminal_turn = AdvisoryTurnSummary(
                turn_sequence=1,
                phase=AdaptivePlannerPhase.ACQUIRE_EVIDENCE,
                status=(
                    AdvisoryTurnStatus.COMPLETED
                    if route.outcome is ScenarioHybridOutcome.PLANNER_EVIDENCE
                    else AdvisoryTurnStatus.FAILED
                ),
                input_sha256=SHA_B,
                output_sha256=(
                    SHA_C
                    if route.outcome is ScenarioHybridOutcome.PLANNER_EVIDENCE
                    else None
                ),
                proposal_count=1 if planner_selected else 0,
                selected_proposal_count=1 if planner_selected else 0,
                failure_category=(
                    None
                    if route.outcome is ScenarioHybridOutcome.PLANNER_EVIDENCE
                    else AdvisoryTurnFailureCategory.UNAVAILABLE
                ),
            )
            event_list.append(
                ScenarioRunEvent(
                    schema_version=SCENARIO_RUN_EVENT_VERSION,
                    investigation_id=investigation_id,
                    cursor=len(event_list) + 1,
                    type=ScenarioRunEventType.ADVISORY_TURN,
                    occurred_at=NOW + timedelta(milliseconds=len(event_list) + 1),
                    payload=AdvisoryTurnEventPayload(turn=terminal_turn),
                )
            )
            if planner_selected:
                aggregate_audit = report.probe_audit[1]
                if aggregate_audit.request_sha256 is None:
                    raise AssertionError("provider fixture lost aggregate request")
                event_list.append(
                    ScenarioRunEvent(
                        schema_version=SCENARIO_RUN_EVENT_VERSION,
                        investigation_id=investigation_id,
                        cursor=len(event_list) + 1,
                        type=ScenarioRunEventType.PROBE_REQUEST,
                        occurred_at=NOW + timedelta(milliseconds=len(event_list) + 1),
                        payload=ProbeRequestEventPayload(
                            strategy=ComparisonStrategyKind.ADAPTIVE,
                            request=SanitizedProbeRequest(
                                request_sequence=1,
                                advisory_turn_sequence=1,
                                proposal_sequence=1,
                                capability_name=(
                                    SANDBOX_ORDER_AGGREGATE_CAPABILITY_NAME
                                ),
                                capability_version="1.0.0",
                                request_sha256=aggregate_audit.request_sha256,
                                relevant_effect_ids=(SANDBOX_ORDER_EFFECT_ID,),
                                disposition=ProbeRequestDisposition.SELECTED,
                            ),
                        ),
                    )
                )
        elif (
            provider_event_shape != "none"
            and route.outcome is ScenarioHybridOutcome.FIXED_FALLBACK
        ):
            for index, audit in enumerate(report.probe_audit, start=1):
                if (
                    audit.capability_name is None
                    or audit.capability_version is None
                    or audit.request_sha256 is None
                ):
                    raise AssertionError("fallback fixture lost probe identity")
                event_list.append(
                    ScenarioRunEvent(
                        schema_version=SCENARIO_RUN_EVENT_VERSION,
                        investigation_id=investigation_id,
                        cursor=len(event_list) + 1,
                        type=ScenarioRunEventType.PROBE_REQUEST,
                        occurred_at=NOW + timedelta(milliseconds=len(event_list) + 1),
                        payload=ProbeRequestEventPayload(
                            strategy=ComparisonStrategyKind.FIXED,
                            request=SanitizedProbeRequest(
                                request_sequence=index,
                                advisory_turn_sequence=None,
                                proposal_sequence=None,
                                capability_name=audit.capability_name,
                                capability_version=audit.capability_version,
                                request_sha256=audit.request_sha256,
                                relevant_effect_ids=(SANDBOX_ORDER_EFFECT_ID,),
                                disposition=ProbeRequestDisposition.SELECTED,
                            ),
                        ),
                    )
                )
    event_list.append(
        ScenarioRunEvent(
            schema_version=SCENARIO_RUN_EVENT_VERSION,
            investigation_id=investigation_id,
            cursor=len(event_list) + 1,
            type=ScenarioRunEventType.TERMINAL,
            occurred_at=NOW + timedelta(seconds=2),
            payload=TerminalStateEventPayload(terminal=terminal),
        )
    )
    events = tuple(event_list)
    snapshot = ScenarioRunSnapshot(
        schema_version=SCENARIO_RUN_SNAPSHOT_VERSION,
        launch_id=request.launch_id,
        investigation_id=investigation_id,
        scenario=request.scenario,
        mode=request.mode,
        lifecycle=ScenarioRunLifecycle.COMPLETED,
        event_cursor=len(events),
        envelope_summary=summary,
        report=report,
        comparison=None,
        failure_category=None,
        accepted_at=NOW,
        updated_at=NOW + timedelta(seconds=2),
    )
    status = ScenarioOperationalStatus(
        schema_version=SCENARIO_OPERATIONAL_STATUS_VERSION,
        launch_id=request.launch_id,
        investigation_id=investigation_id,
        scenario=request.scenario,
        mode=request.mode,
        revision=7,
        mutation_state=ScenarioOperationalMutationState.RECORDED,
        investigation_state=ScenarioOperationalInvestigationState.RECORDED,
        cleanup_state=ScenarioOperationalCleanupState.SUCCEEDED,
        recovery_state=ScenarioOperationalRecoveryState.NOT_ESCALATED,
        updated_at=NOW + timedelta(seconds=3),
    )
    snapshot_sha = hashlib.sha256(canonical_json_bytes(snapshot)).hexdigest()
    events_sha = hashlib.sha256(
        json.dumps(
            [item.model_dump(mode="json") for item in events],
            separators=(",", ":"),
            sort_keys=True,
        ).encode()
    ).hexdigest()
    return ScenarioAcceptanceObservation(
        purpose=purpose,
        request=request,
        launch_created=True,
        snapshot=snapshot,
        events=events,
        operational_status=status,
        replay_created=False,
        replay_snapshot_sha256=snapshot_sha,
        snapshot_sha256=snapshot_sha,
        events_sha256=events_sha,
        operational_status_sha256=hashlib.sha256(
            canonical_json_bytes(status)
        ).hexdigest(),
    )


def _deployments(
    candidate: CandidateIdentity,
) -> tuple[ServiceDeploymentObservation, ...]:
    accounts = {
        ServiceComponent.API: f"rec-p5-api@{PROJECT}.iam.gserviceaccount.com",
        ServiceComponent.CONTROLLER: (
            f"rec-p5-controller@{PROJECT}.iam.gserviceaccount.com"
        ),
        ServiceComponent.FAULT_PROXY: f"rec-p5-fault@{PROJECT}.iam.gserviceaccount.com",
        ServiceComponent.SANDBOX: f"rec-p5-sandbox@{PROJECT}.iam.gserviceaccount.com",
    }
    names = {
        ServiceComponent.API: "reconcile-p5-api",
        ServiceComponent.CONTROLLER: "reconcile-p5-controller",
        ServiceComponent.FAULT_PROXY: "reconcile-p5-fault-proxy",
        ServiceComponent.SANDBOX: "reconcile-p5-sandbox",
    }
    audiences = {
        ServiceComponent.API: f"https://reconcile.invalid/phase5/{PROJECT}/api",
        ServiceComponent.CONTROLLER: (
            f"https://reconcile.invalid/phase5/{PROJECT}/controller"
        ),
        ServiceComponent.FAULT_PROXY: (
            f"https://reconcile.invalid/phase5/{PROJECT}/fault-proxy"
        ),
        ServiceComponent.SANDBOX: (
            f"https://reconcile.invalid/phase5/{PROJECT}/sandbox"
        ),
    }
    image = f"us-central1-docker.pkg.dev/{PROJECT}/reconcile-p5/reconcile@{IMAGE}"
    return tuple(
        ServiceDeploymentObservation(
            component=component,
            service_name=names[component],
            uri=f"https://{names[component]}.example.test",
            custom_audience=audiences[component],
            generation=1,
            observed_generation=1,
            ready=True,
            latest_created_revision=f"{names[component]}-00001",
            latest_ready_revision=f"{names[component]}-00001",
            serving_revision=f"{names[component]}-00001",
            traffic_percent=100,
            revision_generation=1,
            revision_observed_generation=1,
            revision_ready=True,
            invoker_iam_disabled=False,
            api_invoker_iam_sha256=(
                _api_invoker_iam_sha256() if component is ServiceComponent.API else None
            ),
            image_reference=image,
            service_account_email=accounts[component],
            source_revision=candidate.source_revision,
            image_digest=candidate.image_digest,
            infrastructure_revision=candidate.infrastructure_revision,
            semantic_config_sha256=candidate.semantic_config_sha256,
            environment_sha256=SHA_A,
            describe_sha256=SHA_B,
            revision_describe_sha256=SHA_C,
            observed_at=NOW,
        )
        for component in ServiceComponent
    )


class _Backend:
    def __init__(self) -> None:
        self.calls: list[tuple[str, object]] = []

    async def deployments(self, candidate):
        self.calls.append(("deployments", candidate))
        return _deployments(candidate)

    async def scenario(self, request, *, purpose: str):
        self.calls.append(("scenario", (request.scenario, request.mode)))
        if purpose == "provider-sandbox-adaptive":
            return _observation(
                request,
                purpose,
                Classification.UNKNOWN,
                _route(ScenarioHybridOutcome.PLANNER_EVIDENCE),
                capabilities=(
                    SANDBOX_ORDER_INGRESS_CAPABILITY_NAME,
                    SANDBOX_ORDER_AGGREGATE_CAPABILITY_NAME,
                ),
            )
        classification = {
            ScenarioLaunchName.STORAGE: Classification.COMMITTED,
            ScenarioLaunchName.FIRESTORE_BUSINESS: Classification.PARTIAL,
            ScenarioLaunchName.SANDBOX_ORDER: Classification.UNKNOWN,
        }[request.scenario]
        return _observation(
            request,
            purpose,
            classification,
            _route(ScenarioHybridOutcome.FIXED_AUTHORITATIVE),
        )

    async def concurrent_replay(self, scenario):
        self.calls.append(("concurrent", scenario.request.launch_id))
        return DuplicateRequestObservation(
            launch_id=scenario.request.launch_id,
            concurrent_replay_count=2,
            snapshot_sha256=scenario.snapshot_sha256,
            conflict_observed=True,
        )

    async def cursor_resume(self, scenario):
        self.calls.append(("resume", scenario.snapshot.investigation_id))
        resumed_events_sha256 = hashlib.sha256(
            json.dumps(
                [item.model_dump(mode="json") for item in scenario.events[1:]],
                separators=(",", ":"),
                sort_keys=True,
            ).encode()
        ).hexdigest()
        return CursorResumeObservation(
            investigation_id=scenario.snapshot.investigation_id,
            disconnected_after_cursor=1,
            resumed_first_cursor=2,
            final_cursor=3,
            resumed_events_sha256=resumed_events_sha256,
        )

    async def interface_parity(self, scenario):
        self.calls.append(("parity", scenario.snapshot.investigation_id))
        return InterfaceParityObservation(
            investigation_id=scenario.snapshot.investigation_id,
            api_snapshot_sha256=scenario.snapshot_sha256,
            cli_snapshot_sha256=scenario.snapshot_sha256,
            tui_snapshot_sha256=scenario.snapshot_sha256,
            all_equal=True,
        )

    async def denials(self):
        self.calls.append(("denials", True))
        return (
            DenialObservation(
                layer=DenialLayer.PLATFORM,
                status_code=403,
                response_sha256=SHA_A,
                response_kind="platform-non-json",
            ),
            DenialObservation(
                layer=DenialLayer.APPLICATION,
                status_code=401,
                response_sha256=SHA_B,
                response_kind="application-canonical-json",
                canonical_code="unauthorized",
            ),
        )

    async def diagnostics(self):
        self.calls.append(("diagnostics", True))
        return LifecycleDiagnostics(
            available=False,
            entry_count=0,
            payload_sha256=hashlib.sha256(b"").hexdigest(),
            revision_names=(),
            observed_at=NOW,
        )


def _state_root(tmp_path: Path) -> Path:
    root = tmp_path / "state"
    root.mkdir(mode=0o700)
    return root


def test_provider_seals_one_canonical_owner_only_record(tmp_path: Path) -> None:
    candidate = _candidate()
    backend = _Backend()
    root = _state_root(tmp_path)
    moments = iter((NOW, NOW + timedelta(seconds=10)))

    binding = asyncio.run(
        run_provider_acceptance(
            candidate,
            state_root=root,
            backend=backend,
            clock=lambda: next(moments),
        )
    )

    path = Path(binding.path)
    assert binding.mode is AcceptanceMode.PROVIDER
    assert stat.S_IMODE(path.stat().st_mode) == 0o400
    assert path.stat().st_nlink == 1
    payload = path.read_bytes()
    assert hashlib.sha256(payload).hexdigest() == binding.file_sha256
    record, observed_binding = read_provider_record(root, candidate)
    assert canonical_json_bytes(record) == payload
    assert observed_binding == binding
    assert record.scenario.request.mode is ScenarioRunMode.ADAPTIVE
    assert record.scenario.snapshot.report is not None
    assert record.scenario.snapshot.report.classification is Classification.UNKNOWN
    assert record.limitations[-1] is (
        AcceptanceLimitation.LIFECYCLE_DIAGNOSTICS_UNAVAILABLE
    )
    assert [item[0] for item in backend.calls] == [
        "deployments",
        "scenario",
        "diagnostics",
    ]
    second_backend = _Backend()
    with pytest.raises(HostedAcceptanceError, match="ACCEPTANCE_RECORD_EXISTS"):
        asyncio.run(
            run_provider_acceptance(
                candidate,
                state_root=root,
                backend=second_backend,
                clock=lambda: NOW,
            )
        )
    assert second_backend.calls == []


def test_provider_fixed_fallback_proves_no_planner_invocation(tmp_path: Path) -> None:
    class FallbackBackend(_Backend):
        def __init__(self, *, planner_invoked: bool) -> None:
            super().__init__()
            self.planner_invoked = planner_invoked

        async def scenario(self, request, *, purpose: str):
            self.calls.append(("scenario", (request.scenario, request.mode)))
            route = ScenarioRouteProvenance(
                policy_version=BOUNDED_HYBRID_ROUTE_POLICY_VERSION,
                route=ScenarioHybridRoute.PLANNER_HETEROGENEOUS,
                outcome=ScenarioHybridOutcome.FIXED_FALLBACK,
                planner_invoked=self.planner_invoked,
                fixed_connector_invoked=True,
                provider_failure=True,
                provider_cleanup_failure=False,
            )
            return _observation(
                request,
                purpose,
                Classification.UNKNOWN,
                route,
                capabilities=(
                    SANDBOX_ORDER_INGRESS_CAPABILITY_NAME,
                    SANDBOX_ORDER_AGGREGATE_CAPABILITY_NAME,
                ),
            )

    candidate = _candidate()
    accepted_root = tmp_path / "accepted"
    accepted_root.mkdir(mode=0o700)
    asyncio.run(
        run_provider_acceptance(
            candidate,
            state_root=accepted_root,
            backend=FallbackBackend(planner_invoked=False),
            clock=lambda: NOW,
        )
    )
    record, _binding = read_provider_record(accepted_root, candidate)
    route = record.scenario.snapshot.report.route_provenance
    assert route is not None
    assert route.outcome is ScenarioHybridOutcome.FIXED_FALLBACK
    assert not route.planner_invoked

    rejected_root = tmp_path / "rejected"
    rejected_root.mkdir(mode=0o700)
    with pytest.raises(ValueError, match="fixed fallback provenance changed"):
        asyncio.run(
            run_provider_acceptance(
                candidate,
                state_root=rejected_root,
                backend=FallbackBackend(planner_invoked=True),
                clock=lambda: NOW,
            )
        )


@pytest.mark.parametrize(
    ("outcome", "capabilities", "event_shape", "message"),
    (
        (
            ScenarioHybridOutcome.PLANNER_EVIDENCE,
            (
                SANDBOX_ORDER_INGRESS_CAPABILITY_NAME,
                SANDBOX_ORDER_AGGREGATE_CAPABILITY_NAME,
            ),
            "none",
            "provider advisory event provenance changed",
        ),
        (
            ScenarioHybridOutcome.PLANNER_EVIDENCE,
            (
                SANDBOX_ORDER_INGRESS_CAPABILITY_NAME,
                SANDBOX_ORDER_AGGREGATE_CAPABILITY_NAME,
            ),
            "planner-no-selection",
            "planner did not select one heterogeneous probe",
        ),
        (
            ScenarioHybridOutcome.FIXED_FALLBACK,
            (
                SANDBOX_ORDER_INGRESS_CAPABILITY_NAME,
                SANDBOX_ORDER_AGGREGATE_CAPABILITY_NAME,
            ),
            "none",
            "fixed fallback event provenance changed",
        ),
        (
            ScenarioHybridOutcome.EXPLICIT_UNKNOWN,
            (SANDBOX_ORDER_INGRESS_CAPABILITY_NAME,),
            "none",
            "provider advisory event provenance changed",
        ),
    ),
)
def test_provider_route_requires_outcome_specific_event_provenance(
    outcome: ScenarioHybridOutcome,
    capabilities: tuple[str, ...],
    event_shape: str,
    message: str,
) -> None:
    request = ScenarioLaunchRequest(
        schema_version=SCENARIO_LAUNCH_REQUEST_VERSION,
        launch_id="provider-event-provenance",
        scenario=ScenarioLaunchName.SANDBOX_ORDER,
        mode=ScenarioRunMode.ADAPTIVE,
    )
    scenario = _observation(
        request,
        "provider-sandbox-adaptive",
        Classification.UNKNOWN,
        _route(outcome),
        capabilities=capabilities,
        provider_event_shape=event_shape,
    )

    with pytest.raises(ValueError, match=message):
        _validate_provider_scenario(scenario)


def test_provider_explicit_unknown_binds_failed_advisory_after_bootstrap() -> None:
    request = ScenarioLaunchRequest(
        schema_version=SCENARIO_LAUNCH_REQUEST_VERSION,
        launch_id="provider-explicit-unknown",
        scenario=ScenarioLaunchName.SANDBOX_ORDER,
        mode=ScenarioRunMode.ADAPTIVE,
    )
    scenario = _observation(
        request,
        "provider-sandbox-adaptive",
        Classification.UNKNOWN,
        _route(ScenarioHybridOutcome.EXPLICIT_UNKNOWN),
        capabilities=(SANDBOX_ORDER_INGRESS_CAPABILITY_NAME,),
    )

    _validate_provider_scenario(scenario)


def test_provider_explicit_unknown_accepts_predispatch_budget_stop() -> None:
    request = ScenarioLaunchRequest(
        schema_version=SCENARIO_LAUNCH_REQUEST_VERSION,
        launch_id="provider-predispatch-unknown",
        scenario=ScenarioLaunchName.SANDBOX_ORDER,
        mode=ScenarioRunMode.ADAPTIVE,
    )
    route = ScenarioRouteProvenance(
        policy_version=BOUNDED_HYBRID_ROUTE_POLICY_VERSION,
        route=ScenarioHybridRoute.PLANNER_HETEROGENEOUS,
        outcome=ScenarioHybridOutcome.EXPLICIT_UNKNOWN,
        planner_invoked=False,
        fixed_connector_invoked=False,
        provider_failure=False,
        provider_cleanup_failure=False,
    )
    scenario = _observation(
        request,
        "provider-sandbox-adaptive",
        Classification.UNKNOWN,
        route,
        capabilities=(SANDBOX_ORDER_INGRESS_CAPABILITY_NAME,),
    )

    _validate_provider_scenario(scenario)


def test_firestore_proof_requires_exact_effect_commit_scopes() -> None:
    request = ScenarioLaunchRequest(
        schema_version=SCENARIO_LAUNCH_REQUEST_VERSION,
        launch_id="firestore-proof-scope",
        scenario=ScenarioLaunchName.FIRESTORE_BUSINESS,
        mode=ScenarioRunMode.ADAPTIVE,
    )
    scenario = _observation(
        request,
        "hosted-firestore-multi-effect",
        Classification.PARTIAL,
        _route(ScenarioHybridOutcome.FIXED_AUTHORITATIVE),
        proof_commit_scopes=(
            "wrong-scope",
            FIRESTORE_BUSINESS_EFFECT_IDS[1],
            FIRESTORE_BUSINESS_EFFECT_IDS[2],
        ),
    )

    with pytest.raises(ValueError, match="Firestore selected-effect proof changed"):
        _validate_firestore_public_report(scenario)


def test_sandbox_fixed_evidence_rejects_duplicate_or_out_of_order_probes() -> None:
    request = ScenarioLaunchRequest(
        schema_version=SCENARIO_LAUNCH_REQUEST_VERSION,
        launch_id="sandbox-duplicate-probe",
        scenario=ScenarioLaunchName.SANDBOX_ORDER,
        mode=ScenarioRunMode.FIXED,
    )
    scenario = _observation(
        request,
        "hosted-sandbox-fixed-weak",
        Classification.UNKNOWN,
        _route(ScenarioHybridOutcome.FIXED_AUTHORITATIVE),
        capabilities=(
            SANDBOX_ORDER_INGRESS_CAPABILITY_NAME,
            SANDBOX_ORDER_AGGREGATE_CAPABILITY_NAME,
            SANDBOX_ORDER_INGRESS_CAPABILITY_NAME,
        ),
    )

    with pytest.raises(ValueError, match="sandbox weak-evidence public shape changed"):
        _validate_sandbox_unknown_public_report(scenario, require_both_probes=True)


@pytest.mark.parametrize(
    "audit_counters",
    (
        ((1, 1, 64), (1, 2, 128)),
        ((1, 1, 64), (2, 1, 128)),
        ((1, 1, 64), (2, 2, 64)),
    ),
)
def test_sandbox_fixed_evidence_requires_exact_cumulative_budget_counters(
    audit_counters: tuple[tuple[int, int, int], ...],
) -> None:
    request = ScenarioLaunchRequest(
        schema_version=SCENARIO_LAUNCH_REQUEST_VERSION,
        launch_id="sandbox-budget-counters",
        scenario=ScenarioLaunchName.SANDBOX_ORDER,
        mode=ScenarioRunMode.FIXED,
    )
    scenario = _observation(
        request,
        "hosted-sandbox-fixed-weak",
        Classification.UNKNOWN,
        _route(ScenarioHybridOutcome.FIXED_AUTHORITATIVE),
        audit_counters=audit_counters,
    )

    with pytest.raises(ValueError, match="sandbox probe budget counters changed"):
        _validate_sandbox_unknown_public_report(scenario, require_both_probes=True)


@pytest.mark.parametrize(
    "tamper",
    ("missing", "mode", "symlink", "hardlink", "wrong-record"),
)
def test_acceptance_reader_rejects_missing_or_mutable_record_artifacts(
    tmp_path: Path,
    tamper: str,
) -> None:
    candidate = _candidate()
    root = _state_root(tmp_path)
    binding = asyncio.run(
        run_provider_acceptance(
            candidate,
            state_root=root,
            backend=_Backend(),
            clock=lambda: NOW,
        )
    )
    path = Path(binding.path)
    if tamper == "missing":
        path.unlink()
    elif tamper == "mode":
        path.chmod(0o600)
    elif tamper == "symlink":
        saved = path.with_suffix(".saved")
        path.rename(saved)
        path.symlink_to(saved)
    elif tamper == "hardlink":
        os.link(path, path.with_suffix(".linked"))
    else:
        path.chmod(0o600)
        path.write_bytes(b"{}")
        path.chmod(0o400)

    with pytest.raises(
        HostedAcceptanceError,
        match=r"PROVIDER_RECORD_(?:UNAVAILABLE|INVALID)|ACCEPTANCE_RECORD_INVALID",
    ):
        read_acceptance_record(root, candidate, AcceptanceMode.PROVIDER)


def test_hosted_revalidates_provider_and_never_launches_another_adaptive_sandbox(
    tmp_path: Path,
) -> None:
    candidate = _candidate()
    root = _state_root(tmp_path)
    asyncio.run(
        run_provider_acceptance(
            candidate,
            state_root=root,
            backend=_Backend(),
            clock=lambda: NOW,
        )
    )
    backend = _Backend()

    binding = asyncio.run(
        run_hosted_acceptance(
            candidate,
            state_root=root,
            backend=backend,
            clock=lambda: NOW + timedelta(minutes=1),
        )
    )

    payload = Path(binding.path).read_bytes()
    record = HostedAcceptanceRecord.model_validate_json(payload)
    observed, observed_binding = read_acceptance_record(
        root,
        candidate,
        AcceptanceMode.HOSTED,
    )
    assert record.schema_version == PHASE5_HOSTED_ACCEPTANCE_VERSION
    assert observed == record
    assert observed_binding == binding
    assert record.provider_artifact.mode is AcceptanceMode.PROVIDER
    scenario_calls = [value for name, value in backend.calls if name == "scenario"]
    assert scenario_calls == [
        (ScenarioLaunchName.STORAGE, ScenarioRunMode.ADAPTIVE),
        (ScenarioLaunchName.FIRESTORE_BUSINESS, ScenarioRunMode.ADAPTIVE),
        (ScenarioLaunchName.SANDBOX_ORDER, ScenarioRunMode.FIXED),
    ]
    assert tuple(item.control for item in record.exact_main_test_substitutions) == (
        "controller-restart",
        "provider-timeout",
        "provider-construction-failure",
        "cleanup-failure",
        "negative-evidence-injection",
        "budget-exhaustion",
        "cloud-run-cold-start",
    )
    assert AcceptanceLimitation.INFLIGHT_CONTROLLER_RESTART_NOT_FORCED in (
        record.limitations
    )
    assert AcceptanceLimitation.NEGATIVE_EVIDENCE_INJECTION_NOT_EXPOSED in (
        record.limitations
    )
    assert AcceptanceLimitation.BUDGET_EXHAUSTION_NOT_FORCED in record.limitations
    assert AcceptanceLimitation.CLOUD_RUN_COLD_START_NOT_FORCED in record.limitations


def test_hosted_reader_rejects_a_rehashed_provider_chain_substitution(
    tmp_path: Path,
) -> None:
    candidate = _candidate()
    root = _state_root(tmp_path)
    asyncio.run(
        run_provider_acceptance(
            candidate,
            state_root=root,
            backend=_Backend(),
            clock=lambda: NOW,
        )
    )
    hosted_binding = asyncio.run(
        run_hosted_acceptance(
            candidate,
            state_root=root,
            backend=_Backend(),
            clock=lambda: NOW + timedelta(minutes=1),
        )
    )
    path = Path(hosted_binding.path)
    value = json.loads(path.read_bytes())
    value["provider_artifact"]["file_sha256"] = "d" * 64
    record_body = {key: item for key, item in value.items() if key != "record_sha256"}
    value["record_sha256"] = hashlib.sha256(
        json.dumps(record_body, separators=(",", ":"), sort_keys=True).encode()
    ).hexdigest()
    payload = json.dumps(value, separators=(",", ":"), sort_keys=True).encode()
    path.chmod(0o600)
    path.write_bytes(payload)
    path.chmod(0o400)

    with pytest.raises(HostedAcceptanceError, match="HOSTED_PROVIDER_CHAIN_INVALID"):
        read_acceptance_record(root, candidate, AcceptanceMode.HOSTED)


def test_hosted_rejects_missing_or_candidate_mismatched_provider_record(
    tmp_path: Path,
) -> None:
    root = _state_root(tmp_path)
    candidate = _candidate()
    with pytest.raises(HostedAcceptanceError, match="PROVIDER_RECORD_UNAVAILABLE"):
        asyncio.run(
            run_hosted_acceptance(
                candidate,
                state_root=root,
                backend=_Backend(),
            )
        )

    asyncio.run(
        run_provider_acceptance(
            candidate,
            state_root=root,
            backend=_Backend(),
            clock=lambda: NOW,
        )
    )
    changed = build_candidate_identity(
        source_revision="2" * 40,
        image_digest=IMAGE,
        infrastructure_revision=SHA_A,
        semantic_config_sha256=SHA_C,
    )
    with pytest.raises(HostedAcceptanceError, match="PROVIDER_RECORD_UNAVAILABLE"):
        asyncio.run(
            run_hosted_acceptance(
                changed,
                state_root=root,
                backend=_Backend(),
            )
        )


def _description(component: str, account: str) -> bytes:
    service = f"reconcile-p5-{component}"
    if component == "fault-proxy":
        service = "reconcile-p5-fault-proxy"
    image = f"us-central1-docker.pkg.dev/{PROJECT}/reconcile-p5/reconcile@{IMAGE}"
    audience = f"https://reconcile.invalid/phase5/{PROJECT}/{component}"
    environment = {
        "GOOGLE_CLOUD_PROJECT": PROJECT,
        "RECONCILE_AUTH_AUDIENCE": audience,
        "RECONCILE_COMPONENT": component,
        "RECONCILE_SOURCE_REVISION": SOURCE,
        "RECONCILE_IMAGE_DIGEST": IMAGE,
        "RECONCILE_INFRA_REVISION": SHA_A,
        "RECONCILE_RUNTIME_DATABASE": "reconcile-p5-runtime",
        "RECONCILE_SEMANTIC_CONFIG_SHA256": SHA_C,
    }
    if component == "api":
        environment.update(
            {
                "RECONCILE_ALLOWED_CALLER_EMAILS": (
                    f"rec-p5-apply@{PROJECT}.iam.gserviceaccount.com"
                ),
                "RECONCILE_CONTROLLER_AUDIENCE": (
                    f"https://reconcile.invalid/phase5/{PROJECT}/controller"
                ),
                "RECONCILE_CONTROLLER_URL": (
                    "https://reconcile-p5-controller.example.test"
                ),
                "RECONCILE_FAULT_PROXY_AUDIENCE": (
                    f"https://reconcile.invalid/phase5/{PROJECT}/fault-proxy"
                ),
                "RECONCILE_FAULT_PROXY_URL": (
                    "https://reconcile-p5-fault-proxy.example.test"
                ),
                "RECONCILE_TARGET_BUCKET": f"{PROJECT}-p5-target",
            }
        )
    elif component == "controller":
        environment.update(
            {
                "RECONCILE_ALLOWED_CALLER_EMAILS": (
                    f"rec-p5-api@{PROJECT}.iam.gserviceaccount.com"
                ),
                "RECONCILE_SANDBOX_AUDIENCE": (
                    f"https://reconcile.invalid/phase5/{PROJECT}/sandbox"
                ),
                "RECONCILE_SANDBOX_URL": ("https://reconcile-p5-sandbox.example.test"),
                "RECONCILE_TARGET_BUCKET": f"{PROJECT}-p5-target",
                "RECONCILE_TARGET_DATABASE": "reconcile-p5-target",
                "RECONCILE_VERTEX_LOCATION": "us",
                "RECONCILE_VERTEX_MAX_COUNT_TOKENS_ATTEMPTS": "1",
                "RECONCILE_VERTEX_MAX_GENERATION_ATTEMPTS": "1",
                "RECONCILE_VERTEX_MAX_INPUT_TOKENS": "12000",
                "RECONCILE_VERTEX_MAX_OUTPUT_TOKENS": "1024",
                "RECONCILE_VERTEX_MODEL": "gemini-3.5-flash",
                "RECONCILE_VERTEX_PROMPT_SHA256": (
                    "a18ac5bbd22570562acc6dfbc49437a82f0db6a265a4de737c1371b6ef2ca2d3"
                ),
                "RECONCILE_VERTEX_PROMPT_VERSION": "adaptive-planner-v3",
                "RECONCILE_VERTEX_THINKING_LEVEL": "MINIMAL",
            }
        )
    elif component == "fault-proxy":
        environment.update(
            {
                "RECONCILE_ALLOWED_CALLER_EMAILS": (
                    f"rec-p5-api@{PROJECT}.iam.gserviceaccount.com"
                ),
                "RECONCILE_SANDBOX_AUDIENCE": (
                    f"https://reconcile.invalid/phase5/{PROJECT}/sandbox"
                ),
                "RECONCILE_SANDBOX_URL": ("https://reconcile-p5-sandbox.example.test"),
                "RECONCILE_TARGET_BUCKET": f"{PROJECT}-p5-target",
                "RECONCILE_TARGET_DATABASE": "reconcile-p5-target",
            }
        )
    else:
        environment.update(
            {
                "RECONCILE_SANDBOX_MUTATION_CALLER_EMAIL": (
                    f"rec-p5-fault@{PROJECT}.iam.gserviceaccount.com"
                ),
                "RECONCILE_SANDBOX_READ_CALLER_EMAIL": (
                    f"rec-p5-controller@{PROJECT}.iam.gserviceaccount.com"
                ),
                "RECONCILE_TARGET_DATABASE": "reconcile-p5-sandbox",
            }
        )
    return json.dumps(
        {
            "metadata": {
                "annotations": {
                    "run.googleapis.com/custom-audiences": json.dumps([audience]),
                    "run.googleapis.com/invoker-iam-disabled": "false",
                },
                "generation": 7,
                "name": service,
            },
            "spec": {
                "template": {
                    "spec": {
                        "containers": [
                            {
                                "env": [
                                    {"name": name, "value": value}
                                    for name, value in sorted(environment.items())
                                ],
                                "image": image,
                            }
                        ],
                        "serviceAccountName": account,
                    }
                }
            },
            "status": {
                "conditions": [{"status": "True", "type": "Ready"}],
                "latestCreatedRevisionName": f"{service}-00007",
                "latestReadyRevisionName": f"{service}-00007",
                "observedGeneration": 7,
                "traffic": [{"percent": 100, "revisionName": f"{service}-00007"}],
                "url": f"https://{service}.example.test",
            },
        },
        separators=(",", ":"),
        sort_keys=True,
    ).encode()


def _revision_description(component: str, account: str) -> bytes:
    service_value = json.loads(_description(component, account))
    service = service_value["metadata"]["name"]
    return json.dumps(
        {
            "metadata": {
                "generation": 1,
                "name": f"{service}-00007",
            },
            "spec": service_value["spec"]["template"]["spec"],
            "status": {
                "conditions": [{"status": "True", "type": "Ready"}],
                "observedGeneration": 1,
            },
        },
        separators=(",", ":"),
        sort_keys=True,
    ).encode()


def _api_invoker_iam_policy() -> bytes:
    return json.dumps(
        {
            "bindings": [
                {
                    "members": [
                        f"serviceAccount:rec-p5-apply@{PROJECT}.iam.gserviceaccount.com"
                    ],
                    "role": "roles/run.invoker",
                }
            ],
            "etag": "sanitized-test-etag",
            "version": 1,
        },
        separators=(",", ":"),
        sort_keys=True,
    ).encode()


def _api_invoker_iam_sha256() -> str:
    return hashlib.sha256(
        json.dumps(
            {
                "members": [
                    f"serviceAccount:rec-p5-apply@{PROJECT}.iam.gserviceaccount.com"
                ],
                "role": "roles/run.invoker",
            },
            separators=(",", ":"),
            sort_keys=True,
        ).encode()
    ).hexdigest()


def test_gcloud_inspector_uses_only_exact_read_only_commands(tmp_path: Path) -> None:
    calls: list[tuple[tuple[str, ...], Path, dict[str, str], int]] = []
    accounts = {
        "reconcile-p5-api": f"rec-p5-api@{PROJECT}.iam.gserviceaccount.com",
        "reconcile-p5-controller": (
            f"rec-p5-controller@{PROJECT}.iam.gserviceaccount.com"
        ),
        "reconcile-p5-fault-proxy": f"rec-p5-fault@{PROJECT}.iam.gserviceaccount.com",
        "reconcile-p5-sandbox": f"rec-p5-sandbox@{PROJECT}.iam.gserviceaccount.com",
    }

    def runner(argv, cwd, environment, timeout):
        calls.append((argv, cwd, dict(environment), timeout))
        if argv[1:4] == ("run", "services", "describe"):
            service = argv[4]
            component = service.removeprefix("reconcile-p5-")
            return subprocess.CompletedProcess(
                argv,
                0,
                _description(component, accounts[service]),
                b"",
            )
        if argv[1:4] == ("run", "revisions", "describe"):
            service = argv[4].removesuffix("-00007")
            component = service.removeprefix("reconcile-p5-")
            return subprocess.CompletedProcess(
                argv,
                0,
                _revision_description(component, accounts[service]),
                b"",
            )
        if argv[1:4] == ("run", "services", "get-iam-policy"):
            return subprocess.CompletedProcess(argv, 0, _api_invoker_iam_policy(), b"")
        assert argv[1:3] == ("logging", "read")
        logs = [
            {
                "resource": {"labels": {"revision_name": "reconcile-p5-api-00007"}},
                "timestamp": "2026-08-18T12:00:00Z",
            }
        ]
        return subprocess.CompletedProcess(
            argv,
            0,
            json.dumps(logs).encode(),
            b"",
        )

    inspector = GcloudReadOnlyInspector(
        command_runner=runner,
        environ={"HOME": str(tmp_path)},
        clock=lambda: NOW,
    )
    deployments = inspector.inspect_deployments(_candidate())
    diagnostics = inspector.lifecycle_diagnostics()

    assert tuple(item.component for item in deployments) == tuple(ServiceComponent)
    assert all(
        item.generation == item.observed_generation == 7
        and item.ready
        and item.latest_created_revision
        == item.latest_ready_revision
        == item.serving_revision
        and item.revision_generation == item.revision_observed_generation == 1
        and item.revision_ready
        and not item.invoker_iam_disabled
        for item in deployments
    )
    assert deployments[0].api_invoker_iam_sha256 == _api_invoker_iam_sha256()
    assert all(item.api_invoker_iam_sha256 is None for item in deployments[1:])
    assert diagnostics.available
    assert diagnostics.diagnostic_only
    assert diagnostics.revision_names == ("reconcile-p5-api-00007",)
    assert len(calls) == 10
    command_kinds = tuple(item[0][1:4] for item in calls)
    assert command_kinds.count(("run", "services", "describe")) == 4
    assert command_kinds.count(("run", "revisions", "describe")) == 4
    assert command_kinds.count(("run", "services", "get-iam-policy")) == 1
    assert sum(item[0][1:3] == ("logging", "read") for item in calls) == 1
    assert all(item[0][0] == "/usr/bin/gcloud" for item in calls)
    assert all("--quiet" in item[0] and "--format=json" in item[0] for item in calls)
    assert all(
        "--impersonate-service-account="
        "rec-p5-apply@reconcile-dev-260813-14fa6d.iam.gserviceaccount.com" in item[0]
        for item in calls
    )
    assert all(item[2]["HOME"] == str(tmp_path) for item in calls)
    assert all(
        forbidden not in " ".join(item[0])
        for forbidden in (
            " delete ",
            " update ",
            " deploy ",
            " add-iam-policy ",
            " remove-iam-policy ",
            " set-iam-policy ",
        )
        for item in calls
    )


@pytest.mark.parametrize("drift", ("extra-environment", "cross-service-url"))
def test_gcloud_inspector_rejects_full_environment_drift(
    tmp_path: Path,
    drift: str,
) -> None:
    accounts = {
        "reconcile-p5-api": f"rec-p5-api@{PROJECT}.iam.gserviceaccount.com",
        "reconcile-p5-controller": (
            f"rec-p5-controller@{PROJECT}.iam.gserviceaccount.com"
        ),
        "reconcile-p5-fault-proxy": f"rec-p5-fault@{PROJECT}.iam.gserviceaccount.com",
        "reconcile-p5-sandbox": f"rec-p5-sandbox@{PROJECT}.iam.gserviceaccount.com",
    }

    def runner(argv, _cwd, _environment, _timeout):
        if argv[1:4] == ("run", "services", "describe"):
            service = argv[4]
            component = service.removeprefix("reconcile-p5-")
            payload = _description(component, accounts[service])
            return subprocess.CompletedProcess(argv, 0, payload, b"")
        if argv[1:4] == ("run", "services", "get-iam-policy"):
            return subprocess.CompletedProcess(argv, 0, _api_invoker_iam_policy(), b"")
        assert argv[1:4] == ("run", "revisions", "describe")
        service = argv[4].removesuffix("-00007")
        component = service.removeprefix("reconcile-p5-")
        value = json.loads(_revision_description(component, accounts[service]))
        if service == "reconcile-p5-api":
            environment = value["spec"]["containers"][0]["env"]
            if drift == "extra-environment":
                environment.append(
                    {"name": "UNAPPROVED_SECRET_REF", "value": "not-a-secret"}
                )
            else:
                next(
                    item
                    for item in environment
                    if item["name"] == "RECONCILE_CONTROLLER_URL"
                )["value"] = "https://reconcile-p5-sandbox.example.test"
        return subprocess.CompletedProcess(
            argv,
            0,
            json.dumps(value, separators=(",", ":"), sort_keys=True).encode(),
            b"",
        )

    inspector = GcloudReadOnlyInspector(
        command_runner=runner,
        environ={"HOME": str(tmp_path)},
        clock=lambda: NOW,
    )

    with pytest.raises(HostedAcceptanceError, match="DEPLOYMENT_IDENTITY_MISMATCH"):
        inspector.inspect_deployments(_candidate())


@pytest.mark.parametrize(
    ("drift", "error_code"),
    (
        ("unobserved-generation", "DEPLOYMENT_NOT_READY"),
        ("service-not-ready", "DEPLOYMENT_NOT_READY"),
        ("newer-created-revision", "DEPLOYMENT_NOT_READY"),
        ("split-traffic", "DEPLOYMENT_TRAFFIC_INVALID"),
        ("invoker-iam-disabled", "DEPLOYMENT_INVOKER_IAM_DISABLED"),
    ),
)
def test_gcloud_inspector_requires_current_ready_single_revision_and_iam_check(
    tmp_path: Path,
    drift: str,
    error_code: str,
) -> None:
    accounts = {
        "reconcile-p5-api": f"rec-p5-api@{PROJECT}.iam.gserviceaccount.com",
        "reconcile-p5-controller": (
            f"rec-p5-controller@{PROJECT}.iam.gserviceaccount.com"
        ),
        "reconcile-p5-fault-proxy": f"rec-p5-fault@{PROJECT}.iam.gserviceaccount.com",
        "reconcile-p5-sandbox": f"rec-p5-sandbox@{PROJECT}.iam.gserviceaccount.com",
    }

    def runner(argv, _cwd, _environment, _timeout):
        if argv[1:4] == ("run", "services", "describe"):
            service = argv[4]
            component = service.removeprefix("reconcile-p5-")
            value = json.loads(_description(component, accounts[service]))
            if service == "reconcile-p5-api":
                if drift == "unobserved-generation":
                    value["status"]["observedGeneration"] = 6
                elif drift == "service-not-ready":
                    value["status"]["conditions"][0]["status"] = "False"
                elif drift == "newer-created-revision":
                    value["status"]["latestCreatedRevisionName"] = (
                        "reconcile-p5-api-00008"
                    )
                elif drift == "split-traffic":
                    value["status"]["traffic"] = [
                        {
                            "percent": 50,
                            "revisionName": "reconcile-p5-api-00007",
                        },
                        {
                            "percent": 50,
                            "revisionName": "reconcile-p5-api-00006",
                        },
                    ]
                else:
                    value["metadata"]["annotations"][
                        "run.googleapis.com/invoker-iam-disabled"
                    ] = "true"
            return subprocess.CompletedProcess(
                argv,
                0,
                json.dumps(value, separators=(",", ":"), sort_keys=True).encode(),
                b"",
            )
        if argv[1:4] == ("run", "revisions", "describe"):
            service = argv[4].removesuffix("-00007")
            component = service.removeprefix("reconcile-p5-")
            return subprocess.CompletedProcess(
                argv,
                0,
                _revision_description(component, accounts[service]),
                b"",
            )
        assert argv[1:4] == ("run", "services", "get-iam-policy")
        return subprocess.CompletedProcess(argv, 0, _api_invoker_iam_policy(), b"")

    inspector = GcloudReadOnlyInspector(
        command_runner=runner,
        environ={"HOME": str(tmp_path)},
        clock=lambda: NOW,
    )

    with pytest.raises(HostedAcceptanceError, match=error_code):
        inspector.inspect_deployments(_candidate())


def test_gcloud_inspector_rejects_public_api_invoker_policy(tmp_path: Path) -> None:
    accounts = {
        "reconcile-p5-api": f"rec-p5-api@{PROJECT}.iam.gserviceaccount.com",
        "reconcile-p5-controller": (
            f"rec-p5-controller@{PROJECT}.iam.gserviceaccount.com"
        ),
        "reconcile-p5-fault-proxy": f"rec-p5-fault@{PROJECT}.iam.gserviceaccount.com",
        "reconcile-p5-sandbox": f"rec-p5-sandbox@{PROJECT}.iam.gserviceaccount.com",
    }

    def runner(argv, _cwd, _environment, _timeout):
        if argv[1:4] == ("run", "services", "describe"):
            service = argv[4]
            component = service.removeprefix("reconcile-p5-")
            payload = _description(component, accounts[service])
        elif argv[1:4] == ("run", "revisions", "describe"):
            service = argv[4].removesuffix("-00007")
            component = service.removeprefix("reconcile-p5-")
            payload = _revision_description(component, accounts[service])
        else:
            assert argv[1:4] == ("run", "services", "get-iam-policy")
            payload = (
                b'{"bindings":[{"members":["allUsers"],"role":"roles/run.invoker"}]}'
            )
        return subprocess.CompletedProcess(argv, 0, payload, b"")

    inspector = GcloudReadOnlyInspector(
        command_runner=runner,
        environ={"HOME": str(tmp_path)},
        clock=lambda: NOW,
    )

    with pytest.raises(HostedAcceptanceError, match="API_INVOKER_IAM_MISMATCH"):
        inspector.inspect_deployments(_candidate())


def test_gcloud_inspector_rejects_unready_serving_revision(tmp_path: Path) -> None:
    accounts = {
        "reconcile-p5-api": f"rec-p5-api@{PROJECT}.iam.gserviceaccount.com",
        "reconcile-p5-controller": (
            f"rec-p5-controller@{PROJECT}.iam.gserviceaccount.com"
        ),
        "reconcile-p5-fault-proxy": f"rec-p5-fault@{PROJECT}.iam.gserviceaccount.com",
        "reconcile-p5-sandbox": f"rec-p5-sandbox@{PROJECT}.iam.gserviceaccount.com",
    }

    def runner(argv, _cwd, _environment, _timeout):
        if argv[1:4] == ("run", "services", "describe"):
            service = argv[4]
            component = service.removeprefix("reconcile-p5-")
            payload = _description(component, accounts[service])
        elif argv[1:4] == ("run", "revisions", "describe"):
            service = argv[4].removesuffix("-00007")
            component = service.removeprefix("reconcile-p5-")
            value = json.loads(_revision_description(component, accounts[service]))
            if service == "reconcile-p5-api":
                value["status"]["conditions"][0]["status"] = "False"
            payload = json.dumps(
                value,
                separators=(",", ":"),
                sort_keys=True,
            ).encode()
        else:
            assert argv[1:4] == ("run", "services", "get-iam-policy")
            payload = _api_invoker_iam_policy()
        return subprocess.CompletedProcess(argv, 0, payload, b"")

    inspector = GcloudReadOnlyInspector(
        command_runner=runner,
        environ={"HOME": str(tmp_path)},
        clock=lambda: NOW,
    )

    with pytest.raises(HostedAcceptanceError, match="DEPLOYMENT_NOT_READY"):
        inspector.inspect_deployments(_candidate())


def test_gcloud_service_failure_is_mandatory_but_log_failure_is_diagnostic(
    tmp_path: Path,
) -> None:
    calls: list[tuple[str, ...]] = []

    def runner(argv, _cwd, _environment, _timeout):
        calls.append(argv)
        raise OSError

    inspector = GcloudReadOnlyInspector(
        command_runner=runner,
        environ={"HOME": str(tmp_path)},
        clock=lambda: NOW,
    )

    with pytest.raises(HostedAcceptanceError, match="READ_ONLY_COMMAND_FAILED"):
        inspector.inspect_deployments(_candidate())
    diagnostics = inspector.lifecycle_diagnostics()

    assert not diagnostics.available
    assert diagnostics.payload_sha256 == hashlib.sha256(b"").hexdigest()
    assert len(calls) == 2
    assert all("--quiet" in argv for argv in calls)
    assert all(
        "--impersonate-service-account="
        "rec-p5-apply@reconcile-dev-260813-14fa6d.iam.gserviceaccount.com" in argv
        for argv in calls
    )


def test_cli_snapshot_imports_only_from_the_bound_snapshot(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    request = ScenarioLaunchRequest(
        schema_version=SCENARIO_LAUNCH_REQUEST_VERSION,
        launch_id="phase5-cli-source-binding",
        scenario=ScenarioLaunchName.STORAGE,
        mode=ScenarioRunMode.ADAPTIVE,
    )
    expected = _observation(
        request,
        "hosted-storage-authoritative",
        Classification.COMMITTED,
        _route(ScenarioHybridOutcome.FIXED_AUTHORITATIVE),
    ).snapshot
    source = tmp_path / "source"
    package = source / "reconcile"
    package.mkdir(parents=True)
    (package / "__init__.py").write_text("", encoding="utf-8")
    payload = canonical_json_bytes(expected) + b"\n"
    (package / "__main__.py").write_text(
        "import pathlib,sys\n"
        "assert sys.flags.no_site == 1\n"
        f"assert pathlib.Path(__file__).resolve().is_relative_to({str(source)!r})\n"
        f"sys.stdout.buffer.write({payload!r})\n",
        encoding="utf-8",
    )
    dependencies = tmp_path / "python-dependencies"
    dependencies.mkdir()
    live = tmp_path / "mutable-live" / "reconcile"
    live.mkdir(parents=True)
    (live / "__init__.py").write_text("", encoding="utf-8")
    (live / "__main__.py").write_text(
        "raise RuntimeError('mutable-live-sentinel-imported')\n",
        encoding="utf-8",
    )
    monkeypatch.setattr(acceptance_module, "_REPO_ROOT", source)
    calls: list[tuple[tuple[str, ...], Path, dict[str, str], int]] = []

    def runner(
        argv: tuple[str, ...],
        cwd: Path,
        environment: dict[str, str],
        timeout: int,
    ) -> subprocess.CompletedProcess[bytes]:
        calls.append((argv, cwd, dict(environment), timeout))
        return subprocess.run(
            argv,
            cwd=cwd,
            env=environment,
            capture_output=True,
            check=False,
            timeout=timeout,
        )

    backend = CloudRunAcceptanceBackend(
        _candidate(),
        command_runner=runner,
        environ={
            "HOME": str(tmp_path),
            "PYTHONPATH": f"{source}:{dependencies}",
        },
    )
    backend._api_uri = "https://api.example.test"

    observed = backend._cli_snapshot(expected.investigation_id)

    assert observed == expected
    assert len(calls) == 1
    argv, cwd, environment, timeout = calls[0]
    assert argv[:4] == (acceptance_module.sys.executable, "-P", "-S", "-m")
    assert cwd == source
    assert environment["PYTHONPATH"] == f"{source}:{dependencies}"
    assert str(live.parent) not in environment["PYTHONPATH"]
    assert timeout == 120


def test_remote_scenario_waits_for_terminal_events_before_final_snapshot(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    candidate = _candidate()
    request = ScenarioLaunchRequest(
        schema_version=SCENARIO_LAUNCH_REQUEST_VERSION,
        launch_id="phase5-remote-sequencing",
        scenario=ScenarioLaunchName.STORAGE,
        mode=ScenarioRunMode.ADAPTIVE,
    )
    expected = _observation(
        request,
        "hosted-storage-authoritative",
        Classification.COMMITTED,
        _route(ScenarioHybridOutcome.FIXED_AUTHORITATIVE),
    )

    class Client:
        def __init__(self) -> None:
            self.calls: list[str] = []
            self.launch_count = 0

        async def __aenter__(self):
            return self

        async def __aexit__(self, *_args):
            return None

        async def launch(self, _request):
            self.calls.append("launch")
            self.launch_count += 1
            return ScenarioLaunchResult(
                created=self.launch_count == 1,
                snapshot=expected.snapshot,
            )

        def events(self, _investigation_id, *, after):
            self.calls.append(f"events:{after}")

            async def generate():
                for event in expected.events:
                    yield event

            return generate()

        async def get_snapshot(self, _investigation_id):
            self.calls.append("snapshot")
            return expected.snapshot

        async def get_operational_status(self, _investigation_id):
            self.calls.append("status")
            return expected.operational_status

    client = Client()
    backend = CloudRunAcceptanceBackend(
        candidate,
        identity_supplier=lambda _audience: "unused",
        environ={"HOME": str(Path.home())},
    )
    monkeypatch.setattr(backend, "_client", lambda: client)

    observed = asyncio.run(
        backend.scenario(request, purpose="hosted-storage-authoritative")
    )

    assert observed.snapshot == expected.snapshot
    assert client.calls == ["launch", "events:0", "snapshot", "status", "launch"]


def test_remote_denials_distinguish_platform_from_application_json(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if "x-serverless-authorization" not in request.headers:
            return httpx.Response(
                403,
                headers={"content-type": "text/html; charset=UTF-8"},
                content=b"platform permission denied",
            )
        return httpx.Response(
            401,
            headers={"content-type": "application/json"},
            content=b'{"code":"unauthorized"}',
        )

    async_client = httpx.AsyncClient

    def client_factory(**kwargs):
        return async_client(transport=httpx.MockTransport(handler), **kwargs)

    monkeypatch.setattr(httpx, "AsyncClient", client_factory)
    backend = CloudRunAcceptanceBackend(
        _candidate(),
        identity_supplier=lambda audience: (
            "api-token" if audience.endswith("/api") else "wrong-token"
        ),
        environ={"HOME": str(Path.home())},
    )
    backend._api_uri = "https://reconcile-p5-api.example.test"

    platform, application = asyncio.run(backend.denials())

    assert platform.response_kind == "platform-non-json"
    assert platform.canonical_code is None
    assert application.response_kind == "application-canonical-json"
    assert application.canonical_code == "unauthorized"


@pytest.mark.parametrize(
    ("content_type", "body"),
    (
        ("application/json", b'{"error":"forbidden"}'),
        ("text/html", b'{"code":"unauthorized"}'),
    ),
)
def test_remote_denials_reject_application_shaped_platform_response(
    monkeypatch: pytest.MonkeyPatch,
    content_type: str,
    body: bytes,
) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if "x-serverless-authorization" not in request.headers:
            return httpx.Response(
                403,
                headers={"content-type": content_type},
                content=body,
            )
        return httpx.Response(
            401,
            headers={"content-type": "application/json"},
            content=b'{"code":"unauthorized"}',
        )

    async_client = httpx.AsyncClient

    def client_factory(**kwargs):
        return async_client(transport=httpx.MockTransport(handler), **kwargs)

    monkeypatch.setattr(httpx, "AsyncClient", client_factory)
    backend = CloudRunAcceptanceBackend(
        _candidate(),
        identity_supplier=lambda audience: (
            "api-token" if audience.endswith("/api") else "wrong-token"
        ),
        environ={"HOME": str(Path.home())},
    )
    backend._api_uri = "https://reconcile-p5-api.example.test"

    with pytest.raises(HostedAcceptanceError, match="PLATFORM_DENIAL_CHANGED"):
        asyncio.run(backend.denials())
