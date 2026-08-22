"""Adversarial regressions for recovery-certificate authority semantics."""

from __future__ import annotations

from datetime import datetime, timedelta

import pytest

from reconcile.contracts import (
    AdvisoryExplanation,
    AmbiguityWitness,
    Classification,
    EffectAssertionState,
    OperationStatus,
    VerifiedCertificate,
    canonical_sha256,
)
from reconcile.controller import ProbeObservation
from reconcile.evidence import RuleInput, RuleObservation, RuleVerdict, verify_recovery
from reconcile.evidence.recovery_rules import (
    STAGE_CLOUD_RUN_REVISION_PROFILE,
    STAGE_CLOUD_RUN_REVISION_PROFILE_VERSION,
    STAGE_READINESS_EFFECT_SCOPE,
    STAGE_REVISION_EFFECT_SCOPE,
    STAGE_TRAFFIC_EFFECT_SCOPE,
    RecoveryRuleViolation,
    validate_recovery_proof,
)
from tests.unit.evidence import test_recovery_provider_rules as provider_fixtures
from tests.unit.evidence import test_recovery_verification as fixtures

pytestmark = pytest.mark.unit

_BASE_NORMALIZER = fixtures._RecoveryNormalizer
_REVISION_A = "reconcile-canary-release-a"
_REVISION_B = "reconcile-canary-release-b"


def _stage_committed_run():
    chain, envelopes = fixtures._chain()
    envelope = envelopes["stage"]
    run = fixtures._run_pipeline(
        envelope,
        (
            (
                "cloud-run-service-get",
                "committed",
                fixtures.NOW + timedelta(seconds=2),
                "etag-stage-7",
            ),
            (
                "cloud-run-revision-get",
                "committed",
                fixtures.NOW + timedelta(seconds=3),
                None,
            ),
            (
                "cloud-run-revision-health",
                "committed",
                fixtures.NOW + timedelta(seconds=4),
                None,
            ),
        ),
    )
    evaluation, report = run.evaluation_and_report()
    return chain, envelopes, envelope, run, evaluation, report


def _verify_stage(
    *,
    chain,
    envelopes,
    envelope,
    evaluation,
    report,
    include_successor: bool = False,
    verified_at: datetime = fixtures.VERIFIED_AT,
):
    return verify_recovery(
        chain=chain,
        node_id="stage",
        envelope=envelope,
        report=report,
        evaluation=evaluation,
        verified_at=verified_at,
        successor_envelope=envelopes["promote"] if include_successor else None,
    )


def _validated_rule_copy(
    observation: RuleObservation,
    **updates: object,
) -> RuleObservation:
    payload = observation.model_dump(mode="python")
    payload.update(updates)
    return RuleObservation.model_validate(payload)


def _payload_kind(rule_input: RuleInput) -> str:
    observation = ProbeObservation.model_validate_json(rule_input.observation)
    return str(observation.payload["kind"])


class _CrossRevisionPartialNormalizer:
    def __init__(self) -> None:
        self._base = _BASE_NORMALIZER()

    def __call__(self, rule_input: RuleInput) -> RuleObservation:
        result = self._base(rule_input)
        if _payload_kind(rule_input) != "partial":
            return result
        correlation = dict(result.correlation)
        capability = rule_input.request.capability_name
        if capability == "cloud-run-service-get":
            correlation["revision"] = _REVISION_A
            return _validated_rule_copy(result, correlation=correlation)
        if capability == "cloud-run-revision-get":
            correlation["revision"] = _REVISION_B
            service_prefix = (
                "projects/demo-project/locations/us-central1/services/reconcile-canary"
            )
            return _validated_rule_copy(
                result,
                correlation=correlation,
                source_record=f"{service_prefix}/revisions/{_REVISION_B}",
            )
        return result


class _FailedOperationNormalizer:
    def __init__(self) -> None:
        self._base = _BASE_NORMALIZER()

    def __call__(self, rule_input: RuleInput) -> RuleObservation:
        result = self._base(rule_input)
        if (
            rule_input.request.capability_name != "cloud-run-operation-get"
            or _payload_kind(rule_input) != "failed"
        ):
            return result
        correlation = dict(result.correlation)
        correlation["operation_state"] = "FAILED"
        return _validated_rule_copy(
            result,
            correlation=correlation,
            operation_status=OperationStatus.UNRESOLVED,
            verdict=RuleVerdict.AUTHORITATIVE_PENDING,
        )


def test_model_advisory_does_not_change_certificate_authority_id() -> None:
    chain, envelopes, envelope, run, evaluation, _ = _stage_committed_run()
    cited = (evaluation.proof.admitted_evidence_ids[0],)

    def report(text: str):
        return run.engine.report(
            run.audit_trail,
            created_at=fixtures.NOW + timedelta(seconds=1),
            updated_at=fixtures.NOW + timedelta(seconds=5),
            revision=1,
            advisory_explanation=AdvisoryExplanation(
                text=text,
                cited_evidence_ids=cited,
            ),
        )

    first = _verify_stage(
        chain=chain,
        envelopes=envelopes,
        envelope=envelope,
        evaluation=evaluation,
        report=report("Gemini explanation A."),
        include_successor=True,
    )
    second = _verify_stage(
        chain=chain,
        envelopes=envelopes,
        envelope=envelope,
        evaluation=evaluation,
        report=report("Gemini explanation B."),
        include_successor=True,
    )

    assert isinstance(first, VerifiedCertificate)
    assert isinstance(second, VerifiedCertificate)
    assert first.report_sha256 != second.report_sha256
    assert first.certificate_id == second.certificate_id
    assert first.transition == second.transition


def test_replayed_probe_and_later_verification_preserve_authority_id(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    chain, envelopes, envelope, _, evaluation, report = _stage_committed_run()
    first = _verify_stage(
        chain=chain,
        envelopes=envelopes,
        envelope=envelope,
        evaluation=evaluation,
        report=report,
        include_successor=True,
    )
    later = _verify_stage(
        chain=chain,
        envelopes=envelopes,
        envelope=envelope,
        evaluation=evaluation,
        report=report,
        include_successor=True,
        verified_at=fixtures.VERIFIED_AT + timedelta(seconds=1),
    )

    class _ReplayFirstObservation:
        def __init__(self, observations: tuple[ProbeObservation, ...]) -> None:
            assert len(observations) == 4
            self._observations = [*observations[:3], observations[0]]

        async def __call__(self, _: object) -> ProbeObservation:
            return self._observations.pop(0)

    monkeypatch.setattr(fixtures, "_QueueHandler", _ReplayFirstObservation)
    replayed_run = fixtures._run_pipeline(
        envelope,
        (
            (
                "cloud-run-service-get",
                "committed",
                fixtures.NOW + timedelta(seconds=2),
                "etag-stage-7",
            ),
            (
                "cloud-run-revision-get",
                "committed",
                fixtures.NOW + timedelta(seconds=3),
                None,
            ),
            (
                "cloud-run-revision-health",
                "committed",
                fixtures.NOW + timedelta(seconds=4),
                None,
            ),
            (
                "cloud-run-service-get",
                "committed",
                fixtures.NOW + timedelta(seconds=5),
                "ignored-by-replay",
            ),
        ),
    )
    replayed_evaluation, replayed_report = replayed_run.evaluation_and_report()
    replayed = _verify_stage(
        chain=chain,
        envelopes=envelopes,
        envelope=envelope,
        evaluation=replayed_evaluation,
        report=replayed_report,
        include_successor=True,
    )

    assert isinstance(first, VerifiedCertificate)
    assert isinstance(later, VerifiedCertificate)
    assert isinstance(replayed, VerifiedCertificate)
    assert later.issued_at != first.issued_at
    assert replayed.report_sha256 != first.report_sha256
    assert replayed_evaluation.proof == evaluation.proof
    assert len(replayed_evaluation.evidence) == len(evaluation.evidence) + 1
    assert replayed_evaluation.decisions[-1].reason.value == "duplicate_candidates"
    assert first.certificate_id == later.certificate_id == replayed.certificate_id


def test_transition_presence_changes_certificate_authority_id() -> None:
    chain, envelopes, envelope, _, evaluation, report = _stage_committed_run()

    proof_only = _verify_stage(
        chain=chain,
        envelopes=envelopes,
        envelope=envelope,
        evaluation=evaluation,
        report=report,
    )
    continuation = _verify_stage(
        chain=chain,
        envelopes=envelopes,
        envelope=envelope,
        evaluation=evaluation,
        report=report,
        include_successor=True,
    )

    assert isinstance(proof_only, VerifiedCertificate)
    assert isinstance(continuation, VerifiedCertificate)
    assert proof_only.transition is None
    assert continuation.transition is not None
    assert proof_only.certificate_id != continuation.certificate_id


def test_partial_cross_revision_evidence_becomes_exact_conflict_witness(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        fixtures,
        "_RecoveryNormalizer",
        _CrossRevisionPartialNormalizer,
    )
    chain, envelopes = fixtures._chain()
    envelope = envelopes["stage"]
    run = fixtures._run_pipeline(
        envelope,
        (
            (
                "cloud-run-service-get",
                "partial",
                fixtures.NOW + timedelta(seconds=2),
                "etag-stage-7",
            ),
            (
                "cloud-run-revision-get",
                "partial",
                fixtures.NOW + timedelta(seconds=3),
                None,
            ),
        ),
    )
    evaluation, report = run.evaluation_and_report()
    assert evaluation.classification is Classification.PARTIAL

    artifact = _verify_stage(
        chain=chain,
        envelopes=envelopes,
        envelope=envelope,
        evaluation=evaluation,
        report=report,
    )
    service_id = next(
        item.evidence_id
        for item in evaluation.evidence
        if item.capability_name == "cloud-run-service-get"
    )
    revision_id = next(
        item.evidence_id
        for item in evaluation.evidence
        if item.capability_name == "cloud-run-revision-get"
    )

    assert isinstance(artifact, AmbiguityWitness)
    assert artifact.conflicting_evidence_ids == tuple(sorted((service_id, revision_id)))
    assert {item.capability_name for item in artifact.discriminating_observations} == {
        "cloud-run-service-get",
        "cloud-run-revision-get",
    }


def test_partial_revision_creation_requires_exact_revision_read() -> None:
    action, effects = provider_fixtures._action(
        STAGE_CLOUD_RUN_REVISION_PROFILE_VERSION
    )
    operation = provider_fixtures._evidence(
        action,
        evidence_id="successful-operation-without-revision-read",
        capability="cloud-run-operation-get",
        correlation=provider_fixtures._operation_values(state="SUCCEEDED"),
        assertions=provider_fixtures._assertions(
            effects,
            (STAGE_REVISION_EFFECT_SCOPE,),
        ),
        operation_status=OperationStatus.TERMINAL_COMMITTED,
    )
    service = provider_fixtures._evidence(
        action,
        evidence_id="nonzero-traffic-service",
        capability="cloud-run-service-get",
        correlation=provider_fixtures._service_values(percent="100"),
        assertions=provider_fixtures._assertions(
            effects,
            (STAGE_TRAFFIC_EFFECT_SCOPE,),
            EffectAssertionState.NOT_ESTABLISHED,
        ),
    )
    unhealthy_values = provider_fixtures._health_values()
    unhealthy_values["health_status"] = "UNHEALTHY"
    health = provider_fixtures._evidence(
        action,
        evidence_id="unhealthy-revision",
        capability="cloud-run-revision-health",
        correlation=unhealthy_values,
        assertions=provider_fixtures._assertions(
            effects,
            (STAGE_READINESS_EFFECT_SCOPE,),
            EffectAssertionState.NOT_ESTABLISHED,
        ),
    )

    with pytest.raises(RecoveryRuleViolation, match="exact revision read"):
        validate_recovery_proof(
            STAGE_CLOUD_RUN_REVISION_PROFILE,
            action,
            effects,
            Classification.PARTIAL,
            (operation, service, health),
        )


def test_terminal_failed_operation_does_not_hide_complete_partial_proof(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(fixtures, "_RecoveryNormalizer", _FailedOperationNormalizer)
    chain, envelopes = fixtures._chain()
    envelope = envelopes["stage"]
    run = fixtures._run_pipeline(
        envelope,
        (
            (
                "cloud-run-operation-get",
                "pending",
                fixtures.NOW + timedelta(seconds=2),
                None,
            ),
            (
                "cloud-run-service-get",
                "committed",
                fixtures.NOW + timedelta(seconds=3),
                "etag-stage-7",
            ),
            (
                "cloud-run-revision-get",
                "partial",
                fixtures.NOW + timedelta(seconds=4),
                None,
            ),
            (
                "cloud-run-operation-get",
                "failed",
                fixtures.NOW + timedelta(seconds=5),
                None,
            ),
        ),
    )
    evaluation = run.engine.evaluate(run.audit_trail)

    assert evaluation.classification is Classification.PARTIAL
    assert evaluation.proof.operation_status is OperationStatus.UNRESOLVED
    report = run.engine.report(
        run.audit_trail,
        created_at=fixtures.NOW + timedelta(seconds=1),
        updated_at=fixtures.NOW + timedelta(seconds=6),
        revision=1,
    )
    artifact = _verify_stage(
        chain=chain,
        envelopes=envelopes,
        envelope=envelope,
        evaluation=evaluation,
        report=report,
    )

    assert isinstance(artifact, VerifiedCertificate)
    assert artifact.classification is Classification.PARTIAL
    assert artifact.transition is None


def test_service_snapshot_conflict_has_exact_ids_and_honest_histories() -> None:
    chain, envelopes = fixtures._chain()
    envelope = envelopes["stage"]
    run = fixtures._run_pipeline(
        envelope,
        (
            (
                "cloud-run-service-get",
                "committed",
                fixtures.NOW + timedelta(seconds=2),
                "etag-a",
            ),
            (
                "cloud-run-service-get",
                "committed",
                fixtures.NOW + timedelta(seconds=3),
                "etag-b",
            ),
            (
                "cloud-run-revision-get",
                "committed",
                fixtures.NOW + timedelta(seconds=3),
                None,
            ),
            (
                "cloud-run-revision-health",
                "committed",
                fixtures.NOW + timedelta(seconds=4),
                None,
            ),
        ),
    )
    evaluation, report = run.evaluation_and_report()
    artifact = _verify_stage(
        chain=chain,
        envelopes=envelopes,
        envelope=envelope,
        evaluation=evaluation,
        report=report,
    )

    assert isinstance(artifact, AmbiguityWitness)
    service_ids = {
        item.evidence_id
        for item in evaluation.evidence
        if item.capability_name == "cloud-run-service-get"
    }
    non_conflict_ids = {
        item.evidence_id
        for item in evaluation.evidence
        if item.capability_name != "cloud-run-service-get"
    }
    assert artifact.conflicting_evidence_ids == tuple(sorted(service_ids))

    histories = artifact.possible_histories
    assert len(histories) == 2
    assert {history.classification for history in histories} == {
        Classification.COMMITTED
    }
    assert (
        len(
            {
                tuple(
                    (effect.effect_id, effect.state) for effect in history.effect_states
                )
                for history in histories
            }
        )
        == 1
    )
    assert len({history.compatible_evidence_ids for history in histories}) == 2
    assert all(
        non_conflict_ids <= set(history.compatible_evidence_ids)
        for history in histories
    )
    assert all(
        len(service_ids & set(history.compatible_evidence_ids)) == 1
        for history in histories
    )
    assert {item.capability_name for item in artifact.discriminating_observations} == {
        "cloud-run-service-get"
    }


def test_terminal_operation_regression_names_exact_conflict_pair() -> None:
    chain, envelopes = fixtures._chain()
    envelope = envelopes["stage"]
    run = fixtures._run_pipeline(
        envelope,
        (
            (
                "cloud-run-service-get",
                "committed",
                fixtures.NOW + timedelta(seconds=2),
                "etag-stage-7",
            ),
            (
                "cloud-run-revision-get",
                "committed",
                fixtures.NOW + timedelta(seconds=2),
                None,
            ),
            (
                "cloud-run-revision-health",
                "committed",
                fixtures.NOW + timedelta(seconds=2),
                None,
            ),
            (
                "cloud-run-operation-get",
                "operation-succeeded",
                fixtures.NOW + timedelta(seconds=3),
                None,
            ),
            (
                "cloud-run-operation-get",
                "pending",
                fixtures.NOW + timedelta(seconds=4),
                None,
            ),
        ),
    )
    evaluation, report = run.evaluation_and_report()
    assert evaluation.classification is Classification.COMMITTED
    assert not evaluation.proof.conflicting_authority

    artifact = _verify_stage(
        chain=chain,
        envelopes=envelopes,
        envelope=envelope,
        evaluation=evaluation,
        report=report,
    )
    operation_ids = {
        item.evidence_id
        for item in evaluation.evidence
        if item.capability_name == "cloud-run-operation-get"
    }

    assert isinstance(artifact, AmbiguityWitness)
    assert artifact.conflicting_evidence_ids == tuple(sorted(operation_ids))
    assert artifact.proof_sha256 == canonical_sha256(evaluation.proof)
    assert {item.capability_name for item in artifact.discriminating_observations} == {
        "cloud-run-operation-get"
    }


def test_histories_are_internally_consistent_across_independent_conflicts() -> None:
    chain, envelopes = fixtures._chain()
    envelope = envelopes["stage"]
    run = fixtures._run_pipeline(
        envelope,
        (
            (
                "cloud-run-revision-get",
                "partial",
                fixtures.NOW + timedelta(seconds=2),
                None,
            ),
            (
                "cloud-run-revision-health",
                "committed",
                fixtures.NOW + timedelta(seconds=3),
                None,
            ),
            (
                "cloud-run-service-get",
                "committed",
                fixtures.NOW + timedelta(seconds=4),
                "etag-a",
            ),
            (
                "cloud-run-service-get",
                "committed",
                fixtures.NOW + timedelta(seconds=5),
                "etag-b",
            ),
        ),
    )
    evaluation, report = run.evaluation_and_report()
    artifact = _verify_stage(
        chain=chain,
        envelopes=envelopes,
        envelope=envelope,
        evaluation=evaluation,
        report=report,
    )

    assert isinstance(artifact, AmbiguityWitness)
    service_ids = tuple(
        sorted(
            item.evidence_id
            for item in evaluation.evidence
            if item.capability_name == "cloud-run-service-get"
        )
    )
    readiness_ids = tuple(
        sorted(
            item.evidence_id
            for item in evaluation.evidence
            if item.capability_name
            in {"cloud-run-revision-get", "cloud-run-revision-health"}
        )
    )
    for history in artifact.possible_histories:
        compatible = set(history.compatible_evidence_ids)
        assert not set(service_ids) <= compatible
        assert not set(readiness_ids) <= compatible
        if EffectAssertionState.UNVERIFIED in {
            effect.state for effect in history.effect_states
        }:
            assert history.classification is not Classification.PARTIAL
