"""Profile-valid fixtures for single-use permit tests."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from pydantic import JsonValue

from reconcile.contracts import (
    EXPECTED_EFFECT_VERSION,
    VERIFIED_CERTIFICATE_VERSION,
    CertifiedTransition,
    Classification,
    ExpectedEffect,
    PermitAction,
    RecoveryEvidenceBinding,
    SemanticActionIdentity,
    TargetBinding,
    VerifiedCertificate,
    canonical_sha256,
    semantic_action_sha256,
)
from reconcile.controller.permits import (
    dispatch_arguments_sha256,
    dispatch_precondition_sha256,
)
from reconcile.evidence.recovery_rules import (
    CLOUD_RUN_SERVICE_TARGET_KIND,
    PROMOTE_CLOUD_RUN_TRAFFIC_PROFILE_VERSION,
    PROMOTION_TRAFFIC_EFFECT_SCOPE,
    RECOVERY_TOOL_VERSION,
    STAGE_CLOUD_RUN_REVISION_PROFILE_VERSION,
)

NOW = datetime(2026, 8, 22, 12, 0, tzinfo=UTC)


def make_permit_certificate() -> tuple[
    VerifiedCertificate,
    SemanticActionIdentity,
    dict[str, JsonValue],
    dict[str, JsonValue],
]:
    """Build the exact stage-certificate → promote-action verifier shape."""

    target = TargetBinding(
        target_kind=CLOUD_RUN_SERVICE_TARGET_KIND,
        scope={"project": "demo-project", "location": "us-central1"},
        resource={"service": "reconcile-canary"},
    )
    arguments: dict[str, JsonValue] = {
        "release_id": "release-7",
        "revision": "reconcile-canary-release-7",
        "percent": 100,
    }
    effect = ExpectedEffect(
        schema_version=EXPECTED_EFFECT_VERSION,
        effect_id="promote-traffic",
        commit_scope=PROMOTION_TRAFFIC_EFFECT_SCOPE,
        predicate={
            "release_id": "release-7",
            "revision": "reconcile-canary-release-7",
            "percent": 100,
        },
        description="Route all traffic to the exact verified revision.",
    )
    semantic_digest = semantic_action_sha256(
        key_version="semantic-action-v1",
        tool_name="promote-cloud-run-traffic",
        tool_version=RECOVERY_TOOL_VERSION,
        semantic_arguments=arguments,
        target=target,
        expected_effect_sha256s=(canonical_sha256(effect),),
        action_profile_version=PROMOTE_CLOUD_RUN_TRAFFIC_PROFILE_VERSION,
    )
    semantic_action = SemanticActionIdentity(
        key_version="semantic-action-v1",
        tool_name="promote-cloud-run-traffic",
        tool_version=RECOVERY_TOOL_VERSION,
        semantic_arguments=arguments,
        target=target,
        expected_effect_sha256s=(canonical_sha256(effect),),
        action_profile_version=PROMOTE_CLOUD_RUN_TRAFFIC_PROFILE_VERSION,
        semantic_action_sha256=semantic_digest,
    )
    precondition: dict[str, JsonValue] = {"service_etag": "etag-release-7"}
    transition = CertifiedTransition(
        action=PermitAction.CONTINUE,
        source_node_id="stage",
        target_node_id="promote",
        semantic_action_sha256=semantic_action.semantic_action_sha256,
        tool_name=semantic_action.tool_name,
        tool_version=semantic_action.tool_version,
        arguments_sha256=dispatch_arguments_sha256(arguments),
        target_sha256=canonical_sha256(target),
        precondition_sha256=dispatch_precondition_sha256(precondition),
    )
    certificate = VerifiedCertificate(
        schema_version=VERIFIED_CERTIFICATE_VERSION,
        certificate_id="certificate-stage-release-7",
        chain_id="release-chain-7",
        node_id="stage",
        semantic_action_sha256="1" * 64,
        chain_sha256="2" * 64,
        node_sha256="3" * 64,
        envelope_sha256="4" * 64,
        report_sha256="5" * 64,
        proof_sha256="6" * 64,
        target=target,
        target_sha256=canonical_sha256(target),
        evidence=(
            RecoveryEvidenceBinding(
                evidence_id="stage-service-evidence",
                evidence_sha256="7" * 64,
                raw_observation_sha256="8" * 64,
                valid_until=NOW + timedelta(seconds=30),
            ),
        ),
        authority_satisfied=True,
        correlation_satisfied=True,
        freshness_satisfied=True,
        authority_policy_version="recovery-authority-v1",
        correlation_policy_version="exact-envelope-correlation-v1",
        freshness_policy_version="envelope-freshness-window-v1",
        classification_policy_version="recovery-classification-v1",
        action_policy_version="recovery-action-v1",
        action_profile_version=STAGE_CLOUD_RUN_REVISION_PROFILE_VERSION,
        verifier_version="recovery-verifier-v1",
        classification=Classification.COMMITTED,
        transition=transition,
        issued_at=NOW + timedelta(seconds=5),
        expires_at=NOW + timedelta(seconds=20),
    )
    return certificate, semantic_action, arguments, precondition


def make_permit_certificate_presentation_variant(
    certificate: VerifiedCertificate,
) -> VerifiedCertificate:
    """Change audit-only fields while preserving the certificate authority ID."""

    if type(certificate) is not VerifiedCertificate:
        raise TypeError("verified certificate must be exact")
    return VerifiedCertificate.model_validate(
        certificate.model_copy(
            update={
                "report_sha256": "9" * 64,
                "issued_at": certificate.issued_at + timedelta(seconds=1),
            }
        )
    )
