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
    make_report,
)

pytestmark = pytest.mark.contract


def _payload(model: object) -> dict[str, object]:
    return json.loads(canonical_json_bytes(model))  # type: ignore[arg-type]


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


def test_raw_observation_reference_is_opaque_not_a_credentialed_url() -> None:
    with pytest.raises(ValidationError):
        RawObservationReference(
            sha256="a" * 64,
            reference="https://example.test/read?access_token=secret",
            byte_count=1,
        )


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
    payload["advisory_explanation"]["cited_evidence_ids"] = []  # type: ignore[index]

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
    payload["advisory_explanation"]["cited_evidence_ids"] = []  # type: ignore[index]

    assert InvestigationReport.model_validate_json(json.dumps(payload))


@pytest.mark.parametrize(
    "reason",
    (
        EvidenceReason.STALE_OBSERVATION,
        EvidenceReason.CLOCK_AMBIGUITY,
        EvidenceReason.SCOPE_MISMATCH,
        EvidenceReason.CONFLICTING_AUTHORITY,
    ),
)
def test_rejected_observation_edges_remain_reportable(reason: EvidenceReason) -> None:
    report = make_report(Classification.UNKNOWN)
    payload = _payload(report)
    payload["evidence_decisions"][0].update(  # type: ignore[index]
        {"disposition": "REJECTED", "reason": reason.value}
    )
    payload["proof"]["conflicting_authority"] = (  # type: ignore[index]
        reason is EvidenceReason.CONFLICTING_AUTHORITY
    )
    payload["advisory_explanation"]["cited_evidence_ids"] = []  # type: ignore[index]

    retained = InvestigationReport.model_validate_json(json.dumps(payload))

    assert retained.evidence[0].evidence_id == "evidence-7"
    assert retained.evidence_decisions[0].reason is reason


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
