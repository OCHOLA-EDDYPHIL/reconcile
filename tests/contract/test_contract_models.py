"""Cross-field invariants for the frozen v1 public contracts."""

from __future__ import annotations

import ast
import hashlib
import json
from pathlib import Path

import pytest
from pydantic import ValidationError

from reconcile.contracts import (
    ACTION_GATE_RESULT_VERSION,
    EVIDENCE_DECISION_VERSION,
    PROBE_REQUEST_VERSION,
    ActionGateReason,
    ActionGateResult,
    AdvisoryExplanation,
    Classification,
    EvidenceDecision,
    EvidenceDisposition,
    EvidenceReason,
    ExecutionEnvelope,
    InvestigationReport,
    NormalizedEvidence,
    ProbeAuditRecord,
    ProbeRequest,
    RawObservationReference,
    RequestedAction,
    TargetBinding,
    canonical_json_bytes,
)
from reconcile.contracts.base import canonical_json_value_bytes
from tests.contract._factories import (
    make_capability,
    make_effects,
    make_envelope,
    make_evidence,
    make_report,
)

pytestmark = pytest.mark.contract


def _payload(model: object) -> dict[str, object]:
    return json.loads(canonical_json_bytes(model))  # type: ignore[arg-type]


def _append_admitted_evidence_copy(
    payload: dict[str, object],
    *,
    updates: dict[str, object],
) -> None:
    second_evidence = json.loads(json.dumps(payload["evidence"][0]))  # type: ignore[index]
    second_evidence["evidence_id"] = "evidence-8"
    second_evidence.update(updates)
    payload["evidence"].append(second_evidence)  # type: ignore[union-attr]

    second_decision = json.loads(json.dumps(payload["evidence_decisions"][0]))  # type: ignore[index]
    second_decision["evidence_id"] = "evidence-8"
    payload["evidence_decisions"].append(second_decision)  # type: ignore[union-attr]

    second_audit = json.loads(json.dumps(payload["probe_audit"][0]))  # type: ignore[index]
    second_audit["probe_sequence"] = 2
    second_audit["evidence_ids"] = ["evidence-8"]
    payload["probe_audit"].append(second_audit)  # type: ignore[union-attr]
    payload["proof"]["admitted_evidence_ids"].append("evidence-8")  # type: ignore[index,union-attr]
    for finding in payload["proof"]["effect_findings"]:  # type: ignore[index,union-attr]
        finding["evidence_ids"].append("evidence-8")


def test_envelope_preserves_invocation_policies_budget_and_stable_ids() -> None:
    envelope = make_envelope()

    assert envelope.context.invocation.invocation_id == "invoke-7"
    assert envelope.context.invocation.arguments_sha256
    assert envelope.context.policies.classification == "classification-v1"
    assert envelope.context.evidence_budget.max_probes == 3
    assert [effect.effect_id for effect in envelope.expected_effects] == [
        "business-record",
        "audit-record",
    ]


def test_same_and_separate_commit_scopes_are_representable() -> None:
    separate = make_effects()
    atomic = make_effects(same_scope=True)

    assert separate[0].commit_scope != separate[1].commit_scope
    assert atomic[0].commit_scope == atomic[1].commit_scope


def test_duplicate_effect_identifiers_are_rejected() -> None:
    payload = _payload(make_envelope())
    payload["expected_effects"][1]["effect_id"] = "business-record"  # type: ignore[index]

    with pytest.raises(ValidationError):
        ExecutionEnvelope.model_validate_json(json.dumps(payload))


@pytest.mark.parametrize("missing", ("investigation_id", "operation_id"))
def test_envelope_rejects_missing_stable_identifiers(missing: str) -> None:
    payload = _payload(make_envelope())
    payload.pop(missing)

    with pytest.raises(ValidationError):
        ExecutionEnvelope.model_validate_json(json.dumps(payload))


def test_invocation_digest_must_match_canonical_arguments() -> None:
    payload = _payload(make_envelope())
    payload["context"]["invocation"]["arguments"]["quantity"] = 3  # type: ignore[index]

    with pytest.raises(ValidationError):
        ExecutionEnvelope.model_validate_json(json.dumps(payload))


@pytest.mark.parametrize(
    "sensitive_key",
    ("access_token", "apiKey", "password", "authorization", "private_key"),
)
def test_envelope_context_rejects_credential_shaped_arguments(
    sensitive_key: str,
) -> None:
    payload = _payload(make_envelope())
    arguments = {sensitive_key: "visible-secret"}
    payload["context"]["invocation"]["arguments"] = arguments  # type: ignore[index]
    payload["context"]["invocation"]["arguments_sha256"] = hashlib.sha256(  # type: ignore[index]
        canonical_json_value_bytes(arguments)
    ).hexdigest()

    with pytest.raises(ValidationError):
        ExecutionEnvelope.model_validate_json(json.dumps(payload))


def test_capability_is_read_only_has_valid_schema_and_exact_allowed_scope() -> None:
    capability = make_capability()

    assert capability.read_only is True
    assert capability.allowed_targets[0].scope["bucket_name"] == "demo-bucket"

    for change in (
        {"read_only": False},
        {"argument_schema": {"type": "object", "additionalProperties": False}},
        {
            "argument_schema": {
                "$schema": "https://json-schema.org/draft/2020-12/schema",
                "type": "object",
                "properties": {"count": {"type": "not-a-json-schema-type"}},
                "additionalProperties": False,
            }
        },
        {
            "argument_schema": {
                "$schema": "https://json-schema.org/draft/2020-12/schema",
                "type": "object",
                "properties": {"order_id": {"$ref": "https://example.test/id"}},
                "additionalProperties": False,
            }
        },
    ):
        payload = _payload(capability)
        payload.update(change)
        with pytest.raises(ValidationError):
            type(capability).model_validate_json(json.dumps(payload))


@pytest.mark.parametrize(
    "coordinate",
    (
        "project_id",
        "bucketName",
        "document_path",
        "api_endpoint",
        "access_token",
        "password",
        "api_key",
        "authorization",
    ),
)
def test_probe_request_cannot_carry_target_coordinates(coordinate: str) -> None:
    with pytest.raises(ValidationError):
        ProbeRequest(
            schema_version=PROBE_REQUEST_VERSION,
            capability_name="readback",
            capability_version="1.0.0",
            relevant_effect_ids=("effect-1",),
            arguments={coordinate: "redirected"},
            rationale="Attempt a redirected read.",
        )


def test_probe_request_rejects_top_level_target_binding() -> None:
    payload = {
        "schema_version": PROBE_REQUEST_VERSION,
        "capability_name": "readback",
        "capability_version": "1.0.0",
        "relevant_effect_ids": ["effect-1"],
        "arguments": {},
        "rationale": "Read only.",
        "target": {"project": "other"},
    }

    with pytest.raises(ValidationError):
        ProbeRequest.model_validate_json(json.dumps(payload))


@pytest.mark.parametrize(
    ("path", "value"),
    [
        (("context", "invocation", "arguments", "note"), "Bearer hidden-value"),
        (("context", "correlation_fields", "request_id"), "token=hidden-value"),
        (("target", "resource", "label"), "eyJabcdefgh.ijklmnop.qrstuvwx"),
        (
            ("expected_effects", 0, "description"),
            "-----BEGIN PRIVATE KEY-----\nmaterial\n-----END PRIVATE KEY-----",
        ),
    ],
)
def test_execution_envelope_rejects_secret_signatures_in_innocuous_fields(
    path: tuple[str | int, ...],
    value: str,
) -> None:
    payload = _payload(make_envelope())
    current: object = payload
    for key in path[:-1]:
        current = current[key]  # type: ignore[index]
    current[path[-1]] = value  # type: ignore[index]
    if path[-2:] == ("arguments", "note"):
        arguments = payload["context"]["invocation"]["arguments"]
        payload["context"]["invocation"]["arguments_sha256"] = hashlib.sha256(
            canonical_json_value_bytes(arguments)
        ).hexdigest()

    with pytest.raises(ValidationError, match="secret-bearing values"):
        ExecutionEnvelope.model_validate_json(json.dumps(payload))


def test_raw_observation_reference_is_opaque_not_a_credentialed_url() -> None:
    with pytest.raises(ValidationError):
        RawObservationReference(
            sha256="a" * 64,
            reference="https://example.test/read?access_token=secret",
            byte_count=1,
        )


def test_probe_audit_retains_hashes_and_counters_without_planner_content() -> None:
    report = make_report(Classification.COMMITTED)
    audit = _payload(report)["probe_audit"][0]  # type: ignore[index]

    assert "request" not in audit
    assert "rationale" not in audit
    assert "arguments" not in audit
    assert audit["request_sha256"]
    assert audit["target_sha256"]
    assert audit["result_sha256"]
    assert audit["probe_count_used"] == 1


def test_completed_probe_audit_requires_a_result_digest_and_byte_count() -> None:
    audit = _payload(make_report(Classification.COMMITTED))["probe_audit"][0]  # type: ignore[index]
    audit.pop("result_sha256")

    with pytest.raises(ValidationError, match="request, capability, and result"):
        ProbeAuditRecord.model_validate_json(json.dumps(audit))


def test_completed_probe_audit_requires_request_identity() -> None:
    audit = _payload(make_report(Classification.COMMITTED))["probe_audit"][0]  # type: ignore[index]
    audit["request_sha256"] = None

    with pytest.raises(ValidationError, match="request, capability, and result"):
        ProbeAuditRecord.model_validate_json(json.dumps(audit))


def test_noncompleted_probe_audit_cannot_promote_a_result_digest() -> None:
    audit = _payload(make_report(Classification.COMMITTED))["probe_audit"][0]  # type: ignore[index]
    audit["outcome"] = "TIMED_OUT"

    with pytest.raises(ValidationError, match="cannot become an evidence digest"):
        ProbeAuditRecord.model_validate_json(json.dumps(audit))


def test_evidence_correlation_rejects_sensitive_fields() -> None:
    evidence, _ = make_evidence(Classification.COMMITTED)
    payload = _payload(evidence)
    payload["correlation"] = {"access_token": "visible-secret"}

    with pytest.raises(ValidationError, match="secret-bearing fields"):
        NormalizedEvidence.model_validate_json(json.dumps(payload))


@pytest.mark.parametrize(
    "observed_at",
    ("2026-08-13T11:59:29Z", "2026-08-13T12:00:31Z"),
)
def test_observation_must_fall_inside_its_freshness_window(
    observed_at: str,
) -> None:
    evidence, _ = make_evidence(Classification.COMMITTED)
    payload = _payload(evidence)
    payload["observed_at"] = observed_at

    with pytest.raises(ValidationError, match="inside its freshness window"):
        NormalizedEvidence.model_validate_json(json.dumps(payload))


@pytest.mark.parametrize("authority", ("SUPPLEMENTARY", "WEAK"))
def test_non_target_evidence_cannot_claim_definitive_state(authority: str) -> None:
    evidence, _ = make_evidence(Classification.COMMITTED)
    payload = _payload(evidence)
    payload["authority"] = authority

    with pytest.raises(ValidationError, match="non-target evidence"):
        NormalizedEvidence.model_validate_json(json.dumps(payload))


def test_terminal_nonexecution_cannot_coexist_with_established_effects() -> None:
    evidence, _ = make_evidence(Classification.NOT_COMMITTED)
    payload = _payload(evidence)
    payload["effect_assertions"][0]["state"] = "ESTABLISHED"  # type: ignore[index]

    with pytest.raises(ValidationError, match="terminal non-execution"):
        NormalizedEvidence.model_validate_json(json.dumps(payload))


def test_probe_budget_cannot_exceed_report_proof_capacity() -> None:
    payload = _payload(make_envelope())
    payload["context"]["evidence_budget"]["max_probes"] = 65  # type: ignore[index]

    with pytest.raises(ValidationError):
        ExecutionEnvelope.model_validate_json(json.dumps(payload))


@pytest.mark.parametrize(
    ("target_kind", "scope", "resource"),
    (
        (
            "gcs.object",
            {"project_id": "demo", "bucket_name": "receipts"},
            {"object_name": "order-7.json"},
        ),
        (
            "firestore.document",
            {"project_id": "demo", "database_id": "reconcile"},
            {"document_name": "orders/order-7"},
        ),
        (
            "sandbox.order",
            {"environment": "demo"},
            {"order_id": "order-7"},
        ),
    ),
)
def test_required_target_scenarios_are_provider_neutral(
    target_kind: str,
    scope: dict[str, str],
    resource: dict[str, str],
) -> None:
    target = TargetBinding(target_kind=target_kind, scope=scope, resource=resource)

    assert target.target_kind == target_kind


def test_rejected_probe_attempt_can_be_retained_without_fabricated_evidence() -> None:
    report = make_report(Classification.UNKNOWN)
    payload = _payload(report)
    payload["evidence"] = []
    payload["evidence_decisions"] = [
        {
            "schema_version": EVIDENCE_DECISION_VERSION,
            "evidence_id": "attempt-timeout-1",
            "disposition": "REJECTED",
            "reason": "probe_timeout",
        }
    ]
    payload["probe_audit"][0]["evidence_ids"] = ["attempt-timeout-1"]  # type: ignore[index]
    payload["proof"]["effect_findings"][0]["evidence_ids"] = []  # type: ignore[index]
    payload["proof"]["effect_findings"][1]["evidence_ids"] = []  # type: ignore[index]
    payload["proof"]["admitted_evidence_ids"] = []  # type: ignore[index]
    payload["missing_evidence"][0]["reason"] = "probe_timeout"  # type: ignore[index]
    payload["advisory_explanation"] = None

    retained = InvestigationReport.model_validate_json(json.dumps(payload))

    assert retained.evidence == ()
    assert retained.evidence_decisions[0].reason is EvidenceReason.PROBE_TIMEOUT


@pytest.mark.parametrize(
    "reason",
    (
        EvidenceReason.UNSUPPORTED_CAPABILITY,
        EvidenceReason.MALFORMED_OBSERVATION,
        EvidenceReason.BUDGET_EXHAUSTED,
        EvidenceReason.PROBE_TIMEOUT,
        EvidenceReason.RESULT_TOO_LARGE,
        EvidenceReason.UNVERIFIABLE_AUTHORITY,
    ),
)
def test_failed_probe_reasons_need_no_fabricated_observation(
    reason: EvidenceReason,
) -> None:
    report = make_report(Classification.UNKNOWN)
    payload = _payload(report)
    payload["evidence"] = []
    payload["evidence_decisions"] = [
        {
            "schema_version": EVIDENCE_DECISION_VERSION,
            "evidence_id": "attempt-1",
            "disposition": "REJECTED",
            "reason": reason.value,
        }
    ]
    payload["probe_audit"][0]["evidence_ids"] = ["attempt-1"]  # type: ignore[index]
    payload["proof"]["effect_findings"][0]["evidence_ids"] = []  # type: ignore[index]
    payload["proof"]["effect_findings"][1]["evidence_ids"] = []  # type: ignore[index]
    payload["proof"]["admitted_evidence_ids"] = []  # type: ignore[index]
    payload["missing_evidence"][0]["reason"] = reason.value  # type: ignore[index]
    payload["advisory_explanation"] = None

    assert InvestigationReport.model_validate_json(json.dumps(payload))


@pytest.mark.parametrize(
    "reason",
    (
        EvidenceReason.STALE_OBSERVATION,
        EvidenceReason.CLOCK_AMBIGUITY,
        EvidenceReason.SCOPE_MISMATCH,
        EvidenceReason.CONFLICTING_AUTHORITY,
        EvidenceReason.CORRELATION_MISMATCH,
        EvidenceReason.DUPLICATE_CANDIDATES,
        EvidenceReason.EXPECTED_EFFECT_MISMATCH,
    ),
)
def test_rejected_observation_edges_remain_reportable(reason: EvidenceReason) -> None:
    report = make_report(Classification.UNKNOWN)
    payload = _payload(report)
    payload["evidence_decisions"][0].update(  # type: ignore[index]
        {"disposition": "REJECTED", "reason": reason.value}
    )
    payload["proof"]["conflicting_authority"] = False  # type: ignore[index]
    payload["missing_evidence"][0]["reason"] = reason.value  # type: ignore[index]
    payload["advisory_explanation"] = None

    retained = InvestigationReport.model_validate_json(json.dumps(payload))

    assert retained.evidence[0].evidence_id == "evidence-7"
    assert retained.evidence_decisions[0].reason is reason


def test_rejected_scope_mismatch_retains_the_observed_target_and_raw_digest() -> None:
    payload = _payload(make_report(Classification.UNKNOWN))
    payload["evidence"][0]["target"]["resource"] = {  # type: ignore[index]
        "object_name": "receipts/order-8.json"
    }
    payload["evidence_decisions"][0].update(  # type: ignore[index]
        {"disposition": "REJECTED", "reason": "scope_mismatch"}
    )
    payload["missing_evidence"][0]["reason"] = "scope_mismatch"  # type: ignore[index]
    payload["advisory_explanation"] = None

    retained = InvestigationReport.model_validate_json(json.dumps(payload))

    assert (
        retained.evidence[0].target.resource["object_name"] == "receipts/order-8.json"
    )
    assert retained.evidence[0].raw_observation.sha256 == "7" * 64


def test_non_rejected_decision_requires_normalized_evidence() -> None:
    report = make_report(Classification.UNKNOWN)
    payload = _payload(report)
    payload["evidence"] = []

    with pytest.raises(ValidationError):
        InvestigationReport.model_validate_json(json.dumps(payload))


def test_weak_evidence_may_support_explanation_but_not_proof() -> None:
    report = make_report(Classification.UNKNOWN)
    assert report.advisory_explanation == AdvisoryExplanation(
        text="The explanation cites only retained evidence.",
        cited_evidence_ids=("evidence-7",),
    )

    payload = _payload(report)
    payload["proof"]["admitted_evidence_ids"] = ["evidence-7"]  # type: ignore[index]
    with pytest.raises(ValidationError):
        InvestigationReport.model_validate_json(json.dumps(payload))


def test_weak_evidence_reason_must_match_its_authority() -> None:
    payload = _payload(make_report(Classification.UNKNOWN))
    payload["evidence_decisions"][0]["reason"] = "not_found_absence_only"  # type: ignore[index]

    with pytest.raises(ValidationError, match="weak evidence reason"):
        InvestigationReport.model_validate_json(json.dumps(payload))


@pytest.mark.parametrize(
    ("classification", "reason"),
    (
        (Classification.COMMITTED, "authoritative_active_status"),
        (Classification.PENDING, "authoritative_exact_correlation"),
        (
            Classification.NOT_COMMITTED,
            "authoritative_exact_correlation",
        ),
    ),
)
def test_admitted_decision_reason_must_match_evidence_semantics(
    classification: Classification,
    reason: str,
) -> None:
    payload = _payload(make_report(classification))
    payload["evidence_decisions"][0]["reason"] = reason  # type: ignore[index]

    with pytest.raises(ValidationError, match="reason does not match"):
        InvestigationReport.model_validate_json(json.dumps(payload))


@pytest.mark.parametrize(
    ("audit_field", "replacement", "message"),
    (
        ("capability_name", "different-capability", "capability"),
        ("target_sha256", "a" * 64, "target"),
        ("result_sha256", "b" * 64, "raw observation"),
        ("result_byte_count", 513, "raw observation"),
    ),
)
def test_normalized_evidence_is_linked_to_its_probe_audit(
    audit_field: str,
    replacement: object,
    message: str,
) -> None:
    payload = _payload(make_report(Classification.COMMITTED))
    payload["probe_audit"][0][audit_field] = replacement  # type: ignore[index]

    with pytest.raises(ValidationError, match=message):
        InvestigationReport.model_validate_json(json.dumps(payload))


def test_evidence_retrieval_time_is_bound_to_probe_completion() -> None:
    payload = _payload(make_report(Classification.COMMITTED))
    payload["evidence"][0]["provenance"]["retrieved_at"] = (  # type: ignore[index]
        "2026-08-13T12:00:05Z"
    )

    with pytest.raises(ValidationError, match="retrieval time"):
        InvestigationReport.model_validate_json(json.dumps(payload))


def test_effect_finding_citation_must_support_the_claimed_state() -> None:
    payload = _payload(make_report(Classification.COMMITTED))
    payload["evidence"][0]["effect_assertions"][0]["state"] = (  # type: ignore[index]
        "NOT_ESTABLISHED"
    )

    with pytest.raises(ValidationError, match="aggregate admitted evidence"):
        InvestigationReport.model_validate_json(json.dumps(payload))


def test_definitive_effect_finding_requires_an_admitted_citation() -> None:
    payload = _payload(make_report(Classification.COMMITTED))
    payload["proof"]["effect_findings"][0]["evidence_ids"] = []  # type: ignore[index]

    with pytest.raises(ValidationError, match="require evidence"):
        InvestigationReport.model_validate_json(json.dumps(payload))


def test_admitted_evidence_uses_one_authority_policy() -> None:
    payload = _payload(make_report(Classification.COMMITTED))
    _append_admitted_evidence_copy(
        payload,
        updates={"authority_policy_version": "authority-gcs-v2"},
    )

    with pytest.raises(ValidationError, match="authority policies"):
        InvestigationReport.model_validate_json(json.dumps(payload))


def test_admitted_evidence_may_retain_different_extra_correlation_fields() -> None:
    payload = _payload(make_report(Classification.COMMITTED))
    _append_admitted_evidence_copy(
        payload,
        updates={
            "correlation": {
                "order_id": "order-7",
                "trusted_generation": "1700000000000001",
            }
        },
    )

    retained = InvestigationReport.model_validate_json(json.dumps(payload))

    assert len(retained.proof.admitted_evidence_ids) == 2  # type: ignore[union-attr]


@pytest.mark.parametrize(
    ("action", "classification", "reason"),
    (
        (
            RequestedAction.COMPENSATE,
            Classification.UNKNOWN,
            ActionGateReason.COMPENSATION_OUT_OF_SCOPE_V1,
        ),
        (
            RequestedAction.RETRY,
            Classification.NOT_COMMITTED,
            ActionGateReason.EXPLICIT_RETRY_POLICY_REQUIRED,
        ),
        (
            RequestedAction.CONTINUE,
            Classification.PARTIAL,
            ActionGateReason.INCOMPLETE_EFFECT_SET,
        ),
    ),
)
def test_unsafe_v1_action_gate_outcomes_are_unrepresentable(
    action: RequestedAction,
    classification: Classification,
    reason: ActionGateReason,
) -> None:
    with pytest.raises(ValidationError):
        ActionGateResult(
            schema_version=ACTION_GATE_RESULT_VERSION,
            requested_action=action,
            allowed=True,
            reason=reason,
            classification=classification,
            classification_policy_version="classification-v1",
            action_policy_version="action-v1",
            escalation_required=True,
        )


def test_action_gate_escalation_requirement_is_classification_bound() -> None:
    with pytest.raises(ValidationError):
        ActionGateResult(
            schema_version=ACTION_GATE_RESULT_VERSION,
            requested_action=RequestedAction.OBSERVE,
            allowed=True,
            reason=ActionGateReason.READ_ONLY_FOLLOW_UP,
            classification=Classification.COMMITTED,
            classification_policy_version="classification-v1",
            action_policy_version="action-v1",
            escalation_required=True,
        )


@pytest.mark.parametrize("classification", tuple(Classification))
def test_every_state_has_one_deterministic_gate_for_every_action(
    classification: Classification,
) -> None:
    report = make_report(classification)
    by_action = {gate.requested_action: gate for gate in report.action_gate}

    assert set(by_action) == set(RequestedAction)
    assert [gate.requested_action for gate in report.action_gate] == list(
        RequestedAction
    )
    assert all(
        gate.escalation_required is (classification is not Classification.COMMITTED)
        for gate in report.action_gate
    )
    if classification is Classification.NOT_COMMITTED:
        assert (
            by_action[RequestedAction.CONTINUE].reason
            is ActionGateReason.OPERATION_NOT_COMMITTED
        )


def test_action_gate_policy_versions_cannot_diverge_within_one_report() -> None:
    payload = _payload(make_report(Classification.COMMITTED))
    payload["action_gate"][1]["action_policy_version"] = "action-v2"  # type: ignore[index]

    with pytest.raises(ValidationError, match="one policy version pair"):
        InvestigationReport.model_validate_json(json.dumps(payload))


def test_report_rejects_incomplete_or_reordered_action_gate_sets() -> None:
    incomplete = _payload(make_report(Classification.COMMITTED))
    incomplete["action_gate"] = incomplete["action_gate"][:1]  # type: ignore[index]
    reordered = _payload(make_report(Classification.COMMITTED))
    reordered["action_gate"][0], reordered["action_gate"][1] = (  # type: ignore[index]
        reordered["action_gate"][1],
        reordered["action_gate"][0],
    )

    with pytest.raises(ValidationError):
        InvestigationReport.model_validate_json(json.dumps(incomplete))
    with pytest.raises(ValidationError, match="every v1 requested action"):
        InvestigationReport.model_validate_json(json.dumps(reordered))


def test_advisory_explanation_requires_an_evidence_citation() -> None:
    with pytest.raises(ValidationError):
        AdvisoryExplanation(
            text="The model made an uncited claim.",
            cited_evidence_ids=(),
        )


@pytest.mark.parametrize("classification", tuple(Classification))
def test_each_state_factory_satisfies_its_proof_prerequisites(
    classification: Classification,
) -> None:
    retained = InvestigationReport.model_validate_json(
        json.dumps(_payload(make_report(classification)))
    )

    assert retained.classification is classification


def test_committed_requires_complete_effect_proof() -> None:
    payload = _payload(make_report(Classification.COMMITTED))
    payload["proof"]["effect_findings"][1].update(  # type: ignore[index]
        {"state": "UNVERIFIED", "evidence_ids": []}
    )

    with pytest.raises(ValidationError, match="aggregate admitted evidence"):
        InvestigationReport.model_validate_json(json.dumps(payload))


def test_not_committed_requires_affirmative_terminal_nonexecution() -> None:
    payload = _payload(make_report(Classification.NOT_COMMITTED))
    payload["proof"]["operation_status"] = None  # type: ignore[index]

    with pytest.raises(ValidationError, match="operation status does not match"):
        InvestigationReport.model_validate_json(json.dumps(payload))


def test_partial_cannot_split_one_atomic_commit_scope() -> None:
    payload = _payload(make_report(Classification.PARTIAL))
    payload["proof"]["effect_findings"][1]["commit_scope"] = "write"  # type: ignore[index]

    with pytest.raises(ValidationError, match="atomic commit scope"):
        InvestigationReport.model_validate_json(json.dumps(payload))


def test_pending_requires_an_authoritative_unresolved_status() -> None:
    payload = _payload(make_report(Classification.PENDING))
    payload["proof"]["operation_status"] = None  # type: ignore[index]

    with pytest.raises(ValidationError, match="operation status does not match"):
        InvestigationReport.model_validate_json(json.dumps(payload))


@pytest.mark.parametrize(
    "classification",
    (Classification.PARTIAL, Classification.PENDING, Classification.UNKNOWN),
)
def test_non_definitive_report_requires_exact_missing_effects(
    classification: Classification,
) -> None:
    payload = _payload(make_report(classification))
    payload["missing_evidence"] = []

    with pytest.raises(ValidationError, match="require missing evidence"):
        InvestigationReport.model_validate_json(json.dumps(payload))


@pytest.mark.parametrize(
    "classification",
    (Classification.COMMITTED, Classification.NOT_COMMITTED),
)
def test_definitive_report_cannot_claim_missing_evidence(
    classification: Classification,
) -> None:
    payload = _payload(make_report(classification))
    payload["missing_evidence"] = [
        {"effect_ids": [], "reason": "invented-missing-proof"}
    ]

    with pytest.raises(ValidationError, match="cannot list missing evidence"):
        InvestigationReport.model_validate_json(json.dumps(payload))


def test_unknown_cannot_mask_a_definitive_committed_proof() -> None:
    payload = _payload(make_report(Classification.COMMITTED))
    payload["classification"] = "UNKNOWN"
    payload["action_gate"] = _payload(make_report(Classification.UNKNOWN))[
        "action_gate"
    ]
    payload["missing_evidence"] = [{"effect_ids": [], "reason": "invented-ambiguity"}]

    with pytest.raises(ValidationError, match="deterministic proof precedence"):
        InvestigationReport.model_validate_json(json.dumps(payload))


def test_unknown_missing_reason_is_derived_from_evidence_decisions() -> None:
    payload = _payload(make_report(Classification.UNKNOWN))
    payload["missing_evidence"][0]["reason"] = "invented-ambiguity"  # type: ignore[index]

    with pytest.raises(ValidationError, match="reason does not match"):
        InvestigationReport.model_validate_json(json.dumps(payload))


def test_conflicting_authority_cannot_claim_a_definitive_state() -> None:
    payload = _payload(make_report(Classification.COMMITTED))
    payload["proof"]["conflicting_authority"] = True  # type: ignore[index]

    with pytest.raises(ValidationError, match="conflict flag does not match"):
        InvestigationReport.model_validate_json(json.dumps(payload))


def test_aggregate_conflict_does_not_reject_individually_admitted_evidence() -> None:
    payload = _payload(make_report(Classification.COMMITTED))
    _append_admitted_evidence_copy(
        payload,
        updates={
            "effect_assertions": [
                {"effect_id": "business-record", "state": "NOT_ESTABLISHED"},
                {"effect_id": "audit-record", "state": "NOT_ESTABLISHED"},
            ],
            "operation_status": "TERMINAL_NOT_COMMITTED",
        },
    )
    payload["evidence_decisions"][1]["reason"] = (  # type: ignore[index]
        "authoritative_affirmative_non_execution"
    )
    for finding in payload["proof"]["effect_findings"]:  # type: ignore[index]
        finding["state"] = "UNVERIFIED"
    payload["proof"]["conflicting_authority"] = True  # type: ignore[index]
    payload["proof"]["operation_status"] = None  # type: ignore[index]
    payload["classification"] = "UNKNOWN"
    payload["action_gate"] = _payload(make_report(Classification.UNKNOWN))[
        "action_gate"
    ]
    payload["missing_evidence"] = [
        {
            "effect_ids": ["business-record", "audit-record"],
            "reason": "conflicting_authority",
        }
    ]

    retained = InvestigationReport.model_validate_json(json.dumps(payload))

    assert retained.proof.conflicting_authority is True  # type: ignore[union-attr]
    assert retained.evidence_decisions[0].disposition is EvidenceDisposition.ADMITTED


@pytest.mark.parametrize(
    ("path", "identifier"),
    (
        (("proof", "effect_findings", 0, "evidence_ids"), "evidence-7"),
        (("missing_evidence", 0, "effect_ids"), "audit-record"),
        (("advisory_explanation", "cited_evidence_ids"), "evidence-7"),
    ),
)
def test_duplicate_report_reference_identifiers_fail_atomically(
    path: tuple[object, ...],
    identifier: str,
) -> None:
    payload = _payload(make_report(Classification.UNKNOWN))
    value: object = payload
    for part in path[:-1]:
        value = value[part]  # type: ignore[index]
    final = path[-1]
    value[final] = [identifier, identifier]  # type: ignore[index]

    with pytest.raises(ValidationError, match="must be unique"):
        InvestigationReport.model_validate_json(json.dumps(payload))


def test_evidence_decision_reason_catalog_is_disposition_safe() -> None:
    with pytest.raises(ValidationError):
        EvidenceDecision(
            schema_version=EVIDENCE_DECISION_VERSION,
            evidence_id="evidence-1",
            disposition=EvidenceDisposition.ADMITTED,
            reason=EvidenceReason.STALE_OBSERVATION,
        )


def test_frozen_evidence_reason_catalog_is_complete() -> None:
    assert {reason.value for reason in EvidenceReason} == {
        "authoritative_exact_correlation",
        "authoritative_affirmative_non_execution",
        "authoritative_active_status",
        "non_authoritative_log_only",
        "not_found_absence_only",
        "stale_observation",
        "correlation_mismatch",
        "scope_mismatch",
        "unsupported_capability",
        "malformed_observation",
        "unverifiable_authority",
        "conflicting_authority",
        "budget_exhausted",
        "probe_timeout",
        "result_too_large",
        "duplicate_candidates",
        "clock_ambiguity",
        "expected_effect_mismatch",
    }


def test_frozen_action_gate_reason_catalog_is_complete() -> None:
    assert {reason.value for reason in ActionGateReason} == {
        "all_effects_established",
        "operation_not_committed",
        "duplicate_effect_risk",
        "compensation_out_of_scope_v1",
        "explicit_retry_policy_required",
        "operator_review_available",
        "incomplete_effect_set",
        "operator_intervention_required",
        "operation_active",
        "read_only_follow_up",
        "insufficient_authoritative_evidence",
        "ambiguous_duplicate_risk",
    }


def test_domain_and_firestore_boundary_import_no_provider_sdk_types() -> None:
    paths = [
        *Path("reconcile/contracts").glob("*.py"),
        *Path("reconcile/evidence").glob("*.py"),
        Path("reconcile/adapters/firestore_repository.py"),
    ]
    for path in paths:
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        imports = [
            node.module
            for node in ast.walk(tree)
            if isinstance(node, ast.ImportFrom) and node.module is not None
        ]
        imports.extend(
            alias.name
            for node in ast.walk(tree)
            if isinstance(node, ast.Import)
            for alias in node.names
        )
        assert not any(
            module == "google" or module.startswith("google.") for module in imports
        ), path
