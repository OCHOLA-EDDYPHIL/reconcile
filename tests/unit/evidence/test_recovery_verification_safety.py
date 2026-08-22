"""Safety invariants for the fixed Cloud Run-to-Firestore recovery chain."""

from __future__ import annotations

from datetime import timedelta

import pytest

from reconcile.contracts import (
    EXECUTION_ENVELOPE_VERSION,
    AmbiguityWitness,
    Classification,
    ExecutionEnvelope,
    ExecutionEnvelopeReference,
    InvestigationReport,
    OperationStatus,
    RecoveryActionNode,
    RecoveryChain,
    SemanticActionIdentity,
    TargetBinding,
    canonical_sha256,
    semantic_action_sha256,
)
from reconcile.evidence import (
    PROMOTE_CLOUD_RUN_TRAFFIC_PROFILE_VERSION,
    STAGE_CLOUD_RUN_REVISION_PROFILE_VERSION,
    CoreEvaluation,
    RecoveryVerificationError,
    RuleInput,
    RuleObservation,
    RuleVerdict,
    resolve_recovery_action_profile,
    verify_recovery,
)
from reconcile.evidence import recovery_verification as recovery_verifier
from tests.unit.evidence import test_recovery_provider_rules as provider_fixtures
from tests.unit.evidence import test_recovery_verification as fixtures

pytestmark = pytest.mark.unit


def _replace_action(
    node: RecoveryActionNode,
    *,
    arguments: dict[str, object] | None = None,
    target: TargetBinding | None = None,
) -> RecoveryActionNode:
    current = node.semantic_action
    next_arguments = current.semantic_arguments if arguments is None else arguments
    next_target = current.target if target is None else target
    digest = semantic_action_sha256(
        key_version=current.key_version,
        tool_name=current.tool_name,
        tool_version=current.tool_version,
        semantic_arguments=next_arguments,
        target=next_target,
        expected_effect_sha256s=current.expected_effect_sha256s,
        action_profile_version=current.action_profile_version,
    )
    action = SemanticActionIdentity(
        key_version=current.key_version,
        tool_name=current.tool_name,
        tool_version=current.tool_version,
        semantic_arguments=next_arguments,
        target=next_target,
        expected_effect_sha256s=current.expected_effect_sha256s,
        action_profile_version=current.action_profile_version,
        semantic_action_sha256=digest,
    )
    return node.model_copy(update={"semantic_action": action})


def _replace_nodes(
    chain: RecoveryChain,
    replacements: dict[str, RecoveryActionNode],
) -> RecoveryChain:
    return RecoveryChain(
        schema_version=chain.schema_version,
        chain_id=chain.chain_id,
        chain_profile_version=chain.chain_profile_version,
        nodes=tuple(replacements.get(node.node_id, node) for node in chain.nodes),
        created_at=chain.created_at,
    )


def _stage_case() -> tuple[
    RecoveryChain,
    ExecutionEnvelope,
    CoreEvaluation,
    InvestigationReport,
]:
    chain, envelopes = fixtures._chain()
    envelope = envelopes["stage"]
    run = fixtures._run_pipeline(
        envelope,
        (
            (
                "cloud-run-service-get",
                "committed",
                fixtures.NOW + timedelta(seconds=3),
                "etag-stage-7",
            ),
        ),
    )
    evaluation, report = run.evaluation_and_report()
    return chain, envelope, evaluation, report


def _verify_stage(
    chain: RecoveryChain,
    envelope: ExecutionEnvelope,
    evaluation: CoreEvaluation,
    report: InvestigationReport,
) -> recovery_verifier.RecoveryVerificationResult:
    return verify_recovery(
        chain=chain,
        node_id="stage",
        envelope=envelope,
        report=report,
        evaluation=evaluation,
        verified_at=fixtures.VERIFIED_AT,
    )


@pytest.mark.parametrize("shape", ("missing-record", "wrong-edge"))
def test_verifier_rejects_any_non_exact_three_node_chain(shape: str) -> None:
    chain, envelope, evaluation, report = _stage_case()
    if shape == "missing-record":
        changed = RecoveryChain(
            schema_version=chain.schema_version,
            chain_id=chain.chain_id,
            chain_profile_version=chain.chain_profile_version,
            nodes=chain.nodes[:2],
            created_at=chain.created_at,
        )
    else:
        record = chain.nodes[2].model_copy(update={"depends_on": ("stage",)})
        changed = _replace_nodes(chain, {"record": record})

    with pytest.raises(RecoveryVerificationError, match=r"exact|exactly"):
        _verify_stage(changed, envelope, evaluation, report)


@pytest.mark.parametrize(
    "mutation",
    ("promote-release", "promote-service", "record-project", "record-document"),
)
def test_chain_actions_are_bound_to_one_service_project_and_release(
    mutation: str,
) -> None:
    chain, envelope, evaluation, report = _stage_case()
    promote = chain.nodes[1]
    record = chain.nodes[2]
    if mutation == "promote-release":
        arguments = dict(promote.semantic_action.semantic_arguments)
        arguments["release_id"] = "release-8"
        replacement = _replace_action(promote, arguments=arguments)
        changed = _replace_nodes(chain, {"promote": replacement})
    elif mutation == "promote-service":
        target = promote.semantic_action.target.model_copy(
            update={"resource": {"service": "another-canary"}}
        )
        replacement = _replace_action(promote, target=target)
        changed = _replace_nodes(chain, {"promote": replacement})
    elif mutation == "record-project":
        target = record.semantic_action.target.model_copy(
            update={"scope": {"project": "another-project", "database": "release-db"}}
        )
        replacement = _replace_action(record, target=target)
        changed = _replace_nodes(chain, {"record": replacement})
    else:
        target = record.semantic_action.target.model_copy(
            update={"resource": {"document": "releases/release-8"}}
        )
        replacement = _replace_action(record, target=target)
        changed = _replace_nodes(chain, {"record": replacement})

    with pytest.raises(RecoveryVerificationError, match=r"service|release record"):
        _verify_stage(changed, envelope, evaluation, report)


def test_envelope_release_correlation_must_equal_its_action_argument() -> None:
    chain, envelopes = fixtures._chain()
    original = envelopes["stage"]
    payload = original.model_dump(mode="python")
    payload["context"]["correlation_fields"] = {"release_id": "release-8"}
    envelope = ExecutionEnvelope.model_validate(payload)
    assert envelope.schema_version == EXECUTION_ENVELOPE_VERSION

    stage = chain.nodes[0].model_copy(
        update={
            "envelope": ExecutionEnvelopeReference(
                investigation_id=envelope.investigation_id,
                operation_id=envelope.operation_id,
                envelope_sha256=canonical_sha256(envelope),
            )
        }
    )
    chain = _replace_nodes(chain, {"stage": stage})
    run = fixtures._run_pipeline(
        envelope,
        (
            (
                "cloud-run-service-get",
                "committed",
                fixtures.NOW + timedelta(seconds=3),
                "etag-stage-7",
            ),
        ),
    )
    evaluation, report = run.evaluation_and_report()

    with pytest.raises(RecoveryVerificationError, match="release correlation"):
        _verify_stage(chain, envelope, evaluation, report)


def test_stage_continuation_binds_the_exact_observed_revision() -> None:
    chain, envelope, _, _ = _stage_case()
    stage = chain.nodes[0]
    profile = resolve_recovery_action_profile(stage.semantic_action)
    assert profile.profile_version == STAGE_CLOUD_RUN_REVISION_PROFILE_VERSION
    promote = chain.nodes[1]
    assert (
        promote.semantic_action.action_profile_version
        == PROMOTE_CLOUD_RUN_TRAFFIC_PROFILE_VERSION
    )
    intended = promote.semantic_action.semantic_arguments["revision"]

    service_values = provider_fixtures._service_values(revision=str(intended))
    service = provider_fixtures._evidence(
        stage.semantic_action,
        evidence_id="service-proof",
        capability="cloud-run-service-get",
        correlation=service_values,
    )

    def revision_evidence(revision: str):
        correlation = provider_fixtures._revision_values()
        correlation["revision"] = revision
        return provider_fixtures._evidence(
            stage.semantic_action,
            evidence_id=f"revision-{revision}",
            capability="cloud-run-revision-get",
            correlation=correlation,
        )

    matching = recovery_verifier._continue_transition(
        chain,
        stage,
        profile,
        (service, revision_evidence(str(intended))),
        fixtures._chain()[1]["promote"],
    )
    omitted = recovery_verifier._continue_transition(
        chain,
        stage,
        profile,
        (service, revision_evidence(str(intended))),
        None,
    )
    mismatched = recovery_verifier._continue_transition(
        chain,
        stage,
        profile,
        (service, revision_evidence("other-revision")),
        fixtures._chain()[1]["promote"],
    )

    assert matching is not None
    assert matching.target_node_id == promote.node_id
    assert omitted is None
    assert mismatched is None
    assert envelope.target == stage.semantic_action.target

    with pytest.raises(RecoveryVerificationError, match="another envelope"):
        recovery_verifier._continue_transition(
            chain,
            stage,
            profile,
            (service, revision_evidence(str(intended))),
            fixtures._chain()[1]["record"],
        )


def test_verification_time_follows_all_observation_and_audit_times() -> None:
    chain, envelope, evaluation, report = _stage_case()
    del evaluation
    issued_at = recovery_verifier._validate_time(
        fixtures.VERIFIED_AT,
        chain=chain,
        envelope=envelope,
        report=report,
    )

    assert issued_at == fixtures.VERIFIED_AT
    assert all(
        issued_at
        >= max(
            item.freshness.valid_from,
            item.observed_at,
            item.provenance.retrieved_at,
        )
        for item in report.evidence
    )
    assert all(issued_at >= record.completed_at for record in report.probe_audit)


def test_report_update_must_enclose_probe_completion() -> None:
    chain, envelope, evaluation, report = _stage_case()
    payload = report.model_dump(mode="python")
    payload["updated_at"] = fixtures.NOW + timedelta(seconds=3)
    incoherent = InvestigationReport.model_validate(payload)

    with pytest.raises(RecoveryVerificationError, match="probe audit timestamps"):
        _verify_stage(chain, envelope, evaluation, incoherent)


def test_ambiguity_cannot_predate_the_bound_invocation() -> None:
    chain, envelopes = fixtures._chain()
    original = envelopes["stage"]
    payload = original.model_dump(mode="python")
    payload["ambiguity"]["observed_at"] = fixtures.NOW - timedelta(seconds=1)
    envelope = ExecutionEnvelope.model_validate(payload)
    stage = chain.nodes[0].model_copy(
        update={
            "envelope": ExecutionEnvelopeReference(
                investigation_id=envelope.investigation_id,
                operation_id=envelope.operation_id,
                envelope_sha256=canonical_sha256(envelope),
            )
        }
    )
    chain = _replace_nodes(chain, {"stage": stage})
    run = fixtures._run_pipeline(
        envelope,
        (
            (
                "cloud-run-operation-get",
                "pending",
                fixtures.NOW + timedelta(seconds=3),
                None,
            ),
        ),
    )
    evaluation, report = run.evaluation_and_report()

    with pytest.raises(RecoveryVerificationError, match=r"precedes.*invocation"):
        verify_recovery(
            chain=chain,
            node_id="stage",
            envelope=envelope,
            report=report,
            evaluation=evaluation,
            verified_at=fixtures.VERIFIED_AT,
        )


class _StatusOnlyNormalizer:
    def __call__(self, rule_input: RuleInput) -> RuleObservation:
        observation = fixtures.ProbeObservation.model_validate_json(
            rule_input.observation
        )
        kind = observation.payload["kind"]
        if kind == "status-not-committed":
            status = OperationStatus.TERMINAL_NOT_COMMITTED
            verdict = RuleVerdict.AUTHORITATIVE_NON_EXECUTION
            assertions = ()
        elif kind == "status-active":
            status = OperationStatus.ACTIVE
            verdict = RuleVerdict.AUTHORITATIVE_PENDING
            assertions = ()
        elif kind == "effects-established":
            status = None
            verdict = RuleVerdict.AUTHORITATIVE_EFFECTS
            assertions = tuple(
                fixtures.EffectAssertion(
                    effect_id=effect.effect_id,
                    state=fixtures.EffectAssertionState.ESTABLISHED,
                )
                for effect in rule_input.envelope.expected_effects
            )
        else:  # pragma: no cover - the test inventory is closed
            raise ValueError("unsupported status fixture")
        envelope = rule_input.envelope
        return RuleObservation(
            target=envelope.target,
            source_record=str(observation.payload["record"]),
            observed_at=observation.observed_at,
            operation_id=envelope.operation_id,
            correlation=dict(envelope.context.correlation_fields),
            effect_assertions=assertions,
            operation_status=status,
            verdict=verdict,
        )


def test_status_only_conflict_has_two_ids_and_distinct_histories(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(fixtures, "_RecoveryNormalizer", _StatusOnlyNormalizer)
    chain, envelopes = fixtures._chain()
    envelope = envelopes["stage"]
    run = fixtures._run_pipeline(
        envelope,
        (
            (
                "cloud-run-operation-get",
                "status-not-committed",
                fixtures.NOW + timedelta(seconds=2),
                None,
            ),
            (
                "cloud-run-operation-get",
                "status-active",
                fixtures.NOW + timedelta(seconds=3),
                None,
            ),
        ),
    )
    evaluation, report = run.evaluation_and_report()
    artifact = verify_recovery(
        chain=chain,
        node_id="stage",
        envelope=envelope,
        report=report,
        evaluation=evaluation,
        verified_at=fixtures.VERIFIED_AT,
    )

    assert isinstance(artifact, AmbiguityWitness)
    assert len(artifact.conflicting_evidence_ids) == 2
    assert len(artifact.possible_histories) == 2
    signatures = {
        (
            history.classification,
            tuple((effect.effect_id, effect.state) for effect in history.effect_states),
        )
        for history in artifact.possible_histories
    }
    assert len(signatures) == 2
    assert {history.classification for history in artifact.possible_histories} == {
        Classification.NOT_COMMITTED,
        Classification.PENDING,
    }


def test_established_effect_and_status_only_nonexecution_return_conflict_witness(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(fixtures, "_RecoveryNormalizer", _StatusOnlyNormalizer)
    chain, envelopes = fixtures._chain()
    envelope = envelopes["stage"]
    run = fixtures._run_pipeline(
        envelope,
        (
            (
                "cloud-run-service-get",
                "effects-established",
                fixtures.NOW + timedelta(seconds=2),
                None,
            ),
            (
                "cloud-run-operation-get",
                "status-not-committed",
                fixtures.NOW + timedelta(seconds=3),
                None,
            ),
        ),
    )
    evaluation, report = run.evaluation_and_report()

    artifact = verify_recovery(
        chain=chain,
        node_id="stage",
        envelope=envelope,
        report=report,
        evaluation=evaluation,
        verified_at=fixtures.VERIFIED_AT,
    )

    assert isinstance(artifact, AmbiguityWitness)
    assert len(artifact.conflicting_evidence_ids) == 2
    assert len(artifact.possible_histories) == 2
