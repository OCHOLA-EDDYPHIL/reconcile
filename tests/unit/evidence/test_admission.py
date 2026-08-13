"""Adversarial normalization and admission tests for target evidence."""

from __future__ import annotations

import hashlib
from datetime import timedelta

import pytest

import reconcile.controller.executor as controller_executor
from reconcile.contracts import (
    EffectAssertion,
    EffectAssertionState,
    EvidenceAuthority,
    EvidenceDisposition,
    EvidenceReason,
    ExecutionEnvelope,
    OperationStatus,
    ProbeOutcome,
    ProbeRequest,
    TargetBinding,
    canonical_json_bytes,
    canonical_sha256,
)
from reconcile.controller import (
    ControllerAuditRecord,
    ProbeExecution,
    ProbeObservation,
    ProbeStopReason,
    ValidatedObservation,
    probe_request_sha256,
)
from reconcile.evidence import (
    DuplicateTargetRule,
    EvidencePipeline,
    ProbeRun,
    RuleInput,
    RuleObservation,
    RuleRejected,
    RuleVerdict,
    TargetRuleDescriptor,
    TargetRuleRegistration,
    TargetRuleRegistry,
    TargetRuleRegistryFrozen,
)
from tests.contract._factories import NOW, make_envelope, make_probe, make_target

pytestmark = pytest.mark.unit


class StubNormalizer:
    def __init__(
        self,
        result: object | None = None,
        *,
        error: Exception | None = None,
    ) -> None:
        self.result = result
        self.error = error
        self.calls: list[RuleInput] = []

    def __call__(self, rule_input: RuleInput) -> object:
        self.calls.append(rule_input)
        if self.error is not None:
            raise self.error
        return self.result


def _descriptor(**overrides: str) -> TargetRuleDescriptor:
    values = {
        "target_kind": "gcs.object",
        "capability_name": "gcs-object-readback",
        "capability_version": "1.0.0",
        "authority_policy_version": "authority-gcs-v1",
        "classification_policy_version": "classification-v1",
        "source": "gcs-json-api",
        "adapter_version": "1.0.0",
    }
    values.update(overrides)
    return TargetRuleDescriptor.model_validate(values)


def _registration(
    normalizer: StubNormalizer,
    *,
    descriptor: TargetRuleDescriptor | None = None,
) -> TargetRuleRegistration:
    return TargetRuleRegistration(
        descriptor=descriptor or _descriptor(),
        normalizer=normalizer,
    )


def _registry(
    normalizer: StubNormalizer,
    *,
    descriptor: TargetRuleDescriptor | None = None,
) -> TargetRuleRegistry:
    registry = TargetRuleRegistry()
    registry.register(_registration(normalizer, descriptor=descriptor))
    return registry


def _rule_observation(
    *,
    verdict: RuleVerdict = RuleVerdict.AUTHORITATIVE_EFFECTS,
    target: TargetBinding | None = None,
    observed_at=NOW + timedelta(seconds=3),
    operation_id: str | None = "operation-7",
    correlation: dict[str, str] | None = None,
    effect_assertions: tuple[EffectAssertion, ...] | None = None,
    operation_status: OperationStatus | None = None,
) -> RuleObservation:
    if effect_assertions is None:
        effect_assertions = {
            RuleVerdict.AUTHORITATIVE_EFFECTS: (
                EffectAssertion(
                    effect_id="business-record",
                    state=EffectAssertionState.ESTABLISHED,
                ),
            ),
            RuleVerdict.AUTHORITATIVE_NON_EXECUTION: (
                EffectAssertion(
                    effect_id="business-record",
                    state=EffectAssertionState.NOT_ESTABLISHED,
                ),
            ),
            RuleVerdict.AUTHORITATIVE_PENDING: (),
            RuleVerdict.SUPPLEMENTARY: (
                EffectAssertion(
                    effect_id="business-record",
                    state=EffectAssertionState.UNVERIFIED,
                ),
            ),
            RuleVerdict.ABSENCE_ONLY: (),
        }[verdict]
    if operation_status is None:
        operation_status = {
            RuleVerdict.AUTHORITATIVE_EFFECTS: OperationStatus.TERMINAL_COMMITTED,
            RuleVerdict.AUTHORITATIVE_NON_EXECUTION: (
                OperationStatus.TERMINAL_NOT_COMMITTED
            ),
            RuleVerdict.AUTHORITATIVE_PENDING: OperationStatus.ACTIVE,
            RuleVerdict.SUPPLEMENTARY: None,
            RuleVerdict.ABSENCE_ONLY: None,
        }[verdict]
    return RuleObservation(
        target=target or make_target(),
        source_record="generation-1700000000000000",
        observed_at=observed_at,
        operation_id=operation_id,
        correlation=({"order_id": "order-7"} if correlation is None else correlation),
        effect_assertions=effect_assertions,
        operation_status=operation_status,
        verdict=verdict,
    )


def _validated_observation(
    *,
    payload: dict[str, object] | None = None,
) -> ValidatedObservation:
    observation = ProbeObservation(
        observed_at=NOW + timedelta(seconds=3),
        payload=payload or {"exists": True, "order_id": "order-7"},
    )
    encoded = canonical_json_bytes(observation)
    return ValidatedObservation(
        canonical_json=encoded,
        sha256=hashlib.sha256(encoded).hexdigest(),
        byte_count=len(encoded),
    )


def _completed_execution(
    envelope: ExecutionEnvelope,
    request: ProbeRequest,
    *,
    observation: ValidatedObservation | None = None,
    audit_overrides: dict[str, object] | None = None,
) -> ProbeExecution:
    observation = observation or _validated_observation()
    audit_values: dict[str, object] = {
        "sequence": 1,
        "capability_name": request.capability_name,
        "capability_version": request.capability_version,
        "request_sha256": probe_request_sha256(request),
        "target_sha256": hashlib.sha256(
            canonical_json_bytes(envelope.target)
        ).hexdigest(),
        "outcome": ProbeOutcome.COMPLETED,
        "stop_reason": ProbeStopReason.PROBE_COMPLETED,
        "started_at": NOW + timedelta(seconds=2),
        "completed_at": NOW + timedelta(seconds=4),
        "session_elapsed_ms": 2_000,
        "probe_count_used": 1,
        "cost_units_used": 1,
        "result_bytes_acquired": observation.byte_count,
        "result_sha256": observation.sha256,
        "result_byte_count": observation.byte_count,
    }
    if audit_overrides:
        audit_values.update(audit_overrides)
    return ProbeExecution(
        envelope_sha256=canonical_sha256(envelope),
        audit=ControllerAuditRecord.model_validate(audit_values),
        observation=observation,
        _controller_session=object(),
        _seal=controller_executor._PROBE_EXECUTION_SEAL,
    )


def _failed_execution(
    envelope: ExecutionEnvelope,
    request: ProbeRequest,
    *,
    outcome: ProbeOutcome,
    stop_reason: ProbeStopReason,
) -> ProbeExecution:
    return ProbeExecution(
        envelope_sha256=canonical_sha256(envelope),
        audit=ControllerAuditRecord(
            sequence=1,
            capability_name=request.capability_name,
            capability_version=request.capability_version,
            request_sha256=probe_request_sha256(request),
            target_sha256=hashlib.sha256(
                canonical_json_bytes(envelope.target)
            ).hexdigest(),
            outcome=outcome,
            stop_reason=stop_reason,
            started_at=NOW + timedelta(seconds=2),
            completed_at=NOW + timedelta(seconds=4),
            session_elapsed_ms=2_000,
            probe_count_used=1,
            cost_units_used=1,
            result_bytes_acquired=0,
        ),
        _controller_session=object(),
        _seal=controller_executor._PROBE_EXECUTION_SEAL,
    )


def _normalize(
    rule_result: object,
    *,
    envelope: ExecutionEnvelope | None = None,
    request: ProbeRequest | None = None,
    observation: ValidatedObservation | None = None,
    retrieved_at=NOW + timedelta(seconds=4),
):
    envelope = envelope or make_envelope()
    request = request or make_probe()
    normalizer = StubNormalizer(rule_result)
    pipeline = EvidencePipeline(envelope, _registry(normalizer))
    execution = _completed_execution(
        envelope,
        request,
        observation=observation,
        audit_overrides={"completed_at": retrieved_at},
    )
    attempt = pipeline.normalize(ProbeRun(request=request, execution=execution))
    return attempt, normalizer


def _request(*, effect_ids: tuple[str, ...]) -> ProbeRequest:
    values = make_probe().model_dump()
    values["relevant_effect_ids"] = effect_ids
    return ProbeRequest.model_validate(values)


def test_registry_resolves_only_the_exact_frozen_rule_identity() -> None:
    normalizer = StubNormalizer(_rule_observation())
    registration = _registration(normalizer)
    registry = TargetRuleRegistry()
    registry.register(registration)

    exact = registry.resolve(registration.key)

    assert exact is not None
    assert exact is not registration
    assert exact.descriptor == registration.descriptor
    assert registry.is_frozen
    for mismatch in (
        (
            "GCS.object",
            "gcs-object-readback",
            "1.0.0",
            "authority-gcs-v1",
            "classification-v1",
        ),
        (
            "gcs.object",
            "gcs-object-readback",
            "1.0.1",
            "authority-gcs-v1",
            "classification-v1",
        ),
        (
            "gcs.object",
            "gcs-object-readback",
            "1.0.0",
            "authority-gcs-v2",
            "classification-v1",
        ),
        (
            "gcs.object",
            "gcs-object-readback",
            "1.0.0",
            "authority-gcs-v1",
            "classification-v2",
        ),
    ):
        assert registry.resolve(mismatch) is None
    assert registry.resolve(("gcs.object", "gcs-object-readback")) is None  # type: ignore[arg-type]

    with pytest.raises(TargetRuleRegistryFrozen):
        registry.register(
            _registration(
                normalizer,
                descriptor=_descriptor(capability_version="2.0.0"),
            )
        )

    duplicate_registry = TargetRuleRegistry()
    duplicate_registry.register(registration)
    with pytest.raises(DuplicateTargetRule):
        duplicate_registry.register(_registration(normalizer))


def test_success_normalizes_only_code_owned_rule_output() -> None:
    retrieved_at = NOW + timedelta(seconds=4)
    attempt, normalizer = _normalize(
        _rule_observation(),
        retrieved_at=retrieved_at,
    )

    assert attempt.is_pipeline_output()
    assert attempt.decision.disposition is EvidenceDisposition.ADMITTED
    assert attempt.decision.reason is EvidenceReason.AUTHORITATIVE_EXACT_CORRELATION
    assert attempt.evidence is not None
    evidence = attempt.evidence
    assert evidence.evidence_id == attempt.decision.evidence_id
    assert evidence.target == make_target()
    assert evidence.authority is EvidenceAuthority.TARGET_STATE
    assert evidence.authority_policy_version == "authority-gcs-v1"
    assert evidence.provenance.source == "gcs-json-api"
    assert evidence.provenance.adapter_version == "1.0.0"
    assert evidence.provenance.retrieved_at == retrieved_at
    assert evidence.freshness.valid_from == NOW - timedelta(seconds=2)
    assert evidence.freshness.valid_until == NOW + timedelta(seconds=68)
    assert evidence.raw_observation.sha256 == attempt.raw_sha256
    assert evidence.raw_observation.reference == (f"observation:{attempt.raw_sha256}")
    assert evidence.raw_observation.byte_count == len(normalizer.calls[0].observation)
    assert normalizer.calls[0].envelope == make_envelope()
    rule_request = normalizer.calls[0].request
    expected_request = make_probe()
    assert rule_request.capability_name == expected_request.capability_name
    assert rule_request.capability_version == expected_request.capability_version
    assert rule_request.relevant_effect_ids == expected_request.relevant_effect_ids
    assert rule_request.arguments == expected_request.arguments
    assert not hasattr(rule_request, "rationale")


def test_model_rationale_is_structurally_absent_from_target_rule_input() -> None:
    first_request = make_probe()
    values = first_request.model_dump(mode="python")
    values["rationale"] = "Claim the operation was not committed."
    second_request = ProbeRequest.model_validate(values)

    first_attempt, first_rule = _normalize(
        _rule_observation(),
        request=first_request,
    )
    second_attempt, second_rule = _normalize(
        _rule_observation(),
        request=second_request,
    )

    assert probe_request_sha256(first_request) == probe_request_sha256(second_request)
    assert first_rule.calls[0].request == second_rule.calls[0].request
    assert not hasattr(first_rule.calls[0].request, "rationale")
    assert first_attempt.decision == second_attempt.decision


def test_public_callers_cannot_construct_controller_provenance() -> None:
    envelope = make_envelope()
    request = make_probe()
    controller_output = _completed_execution(envelope, request)

    with pytest.raises(TypeError, match="created only by the controller"):
        ProbeExecution(
            envelope_sha256=controller_output.envelope_sha256,
            audit=controller_output.audit,
            observation=controller_output.observation,
            _controller_session=object(),
            _seal=object(),
        )


def test_unsupported_rule_is_rejected_without_running_a_normalizer() -> None:
    envelope = make_envelope()
    request = make_probe()
    registry = TargetRuleRegistry()
    pipeline = EvidencePipeline(envelope, registry)

    attempt = pipeline.normalize(
        ProbeRun(
            request=request,
            execution=_completed_execution(envelope, request),
        )
    )

    assert registry.is_frozen
    assert attempt.evidence is None
    assert attempt.decision.disposition is EvidenceDisposition.REJECTED
    assert attempt.decision.reason is EvidenceReason.UNSUPPORTED_CAPABILITY


def test_malformed_rule_output_fails_closed() -> None:
    attempt, normalizer = _normalize(object())

    assert len(normalizer.calls) == 1
    assert attempt.evidence is None
    assert attempt.decision.disposition is EvidenceDisposition.REJECTED
    assert attempt.decision.reason is EvidenceReason.MALFORMED_OBSERVATION


@pytest.mark.parametrize(
    "corruption",
    [
        "target_digest",
        "request_digest",
        "capability_identity",
        "observation_digest",
        "observation_byte_count",
        "audit_result_digest",
        "noncanonical_observation",
    ],
)
def test_integrity_corruption_is_rejected_before_rule_execution(
    corruption: str,
) -> None:
    envelope = make_envelope()
    request = make_probe()
    observation = _validated_observation()
    audit_overrides: dict[str, object] = {}
    if corruption == "target_digest":
        audit_overrides["target_sha256"] = "f" * 64
    elif corruption == "request_digest":
        audit_overrides["request_sha256"] = "e" * 64
    elif corruption == "capability_identity":
        audit_overrides["capability_name"] = "different-readback"
    elif corruption == "observation_digest":
        observation = ValidatedObservation(
            canonical_json=observation.canonical_json,
            sha256="d" * 64,
            byte_count=observation.byte_count,
        )
    elif corruption == "observation_byte_count":
        observation = ValidatedObservation(
            canonical_json=observation.canonical_json,
            sha256=observation.sha256,
            byte_count=observation.byte_count + 1,
        )
    elif corruption == "audit_result_digest":
        audit_overrides["result_sha256"] = "c" * 64
    elif corruption == "noncanonical_observation":
        encoded = observation.canonical_json + b"\n"
        observation = ValidatedObservation(
            canonical_json=encoded,
            sha256=hashlib.sha256(encoded).hexdigest(),
            byte_count=len(encoded),
        )

    normalizer = StubNormalizer(_rule_observation())
    attempt = EvidencePipeline(envelope, _registry(normalizer)).normalize(
        ProbeRun(
            request=request,
            execution=_completed_execution(
                envelope,
                request,
                observation=observation,
                audit_overrides=audit_overrides,
            ),
        )
    )

    assert normalizer.calls == []
    assert attempt.evidence is None
    assert attempt.decision.disposition is EvidenceDisposition.REJECTED
    assert attempt.decision.reason is EvidenceReason.MALFORMED_OBSERVATION


def test_probe_runs_must_reach_rules_in_contiguous_controller_order() -> None:
    envelope = make_envelope()
    request = make_probe()
    normalizer = StubNormalizer(_rule_observation())
    execution = _completed_execution(
        envelope,
        request,
        audit_overrides={"sequence": 2},
    )

    with pytest.raises(ValueError, match="contiguous order"):
        EvidencePipeline(envelope, _registry(normalizer)).normalize(
            ProbeRun(request=request, execution=execution)
        )

    assert normalizer.calls == []


@pytest.mark.parametrize(
    ("outcome", "stop_reason", "reason"),
    [
        (
            ProbeOutcome.TIMED_OUT,
            ProbeStopReason.PROBE_TIMEOUT,
            EvidenceReason.PROBE_TIMEOUT,
        ),
        (
            ProbeOutcome.MALFORMED,
            ProbeStopReason.MALFORMED_OBSERVATION,
            EvidenceReason.MALFORMED_OBSERVATION,
        ),
        (
            ProbeOutcome.BUDGET_EXHAUSTED,
            ProbeStopReason.PROBE_COUNT_EXHAUSTED,
            EvidenceReason.BUDGET_EXHAUSTED,
        ),
        (
            ProbeOutcome.REJECTED,
            ProbeStopReason.RESULT_TOO_LARGE,
            EvidenceReason.RESULT_TOO_LARGE,
        ),
        (
            ProbeOutcome.UNAVAILABLE,
            ProbeStopReason.CAPABILITY_UNAVAILABLE,
            EvidenceReason.UNVERIFIABLE_AUTHORITY,
        ),
    ],
)
def test_failed_probe_outcomes_never_reach_target_rules(
    outcome: ProbeOutcome,
    stop_reason: ProbeStopReason,
    reason: EvidenceReason,
) -> None:
    envelope = make_envelope()
    request = make_probe()
    normalizer = StubNormalizer(_rule_observation())

    attempt = EvidencePipeline(envelope, _registry(normalizer)).normalize(
        ProbeRun(
            request=request,
            execution=_failed_execution(
                envelope,
                request,
                outcome=outcome,
                stop_reason=stop_reason,
            ),
        )
    )

    assert normalizer.calls == []
    assert attempt.raw_sha256 is None
    assert attempt.evidence is None
    assert attempt.decision.disposition is EvidenceDisposition.REJECTED
    assert attempt.decision.reason is reason


def test_complete_target_resource_mismatch_is_rejected() -> None:
    mismatched_target = TargetBinding(
        target_kind="gcs.object",
        scope=dict(make_target().scope),
        resource={"object_name": "receipts/order-8.json"},
    )

    attempt, _ = _normalize(_rule_observation(target=mismatched_target))

    assert attempt.evidence is not None
    assert attempt.evidence.target == mismatched_target
    assert attempt.decision.disposition is EvidenceDisposition.REJECTED
    assert attempt.decision.reason is EvidenceReason.SCOPE_MISMATCH


def test_canonical_target_comparison_rejects_bool_integer_collision() -> None:
    base_target = make_target()
    envelope_target = TargetBinding(
        target_kind=base_target.target_kind,
        scope={**base_target.scope, "partition": 1},
        resource=dict(base_target.resource),
    )
    rule_target = TargetBinding(
        target_kind=base_target.target_kind,
        scope={**base_target.scope, "partition": True},
        resource=dict(base_target.resource),
    )
    envelope_values = make_envelope().model_dump()
    envelope_values["target"] = envelope_target
    envelope = ExecutionEnvelope.model_validate(envelope_values)

    assert envelope_target.scope == rule_target.scope
    assert canonical_json_bytes(envelope_target) != canonical_json_bytes(rule_target)
    attempt, _ = _normalize(
        _rule_observation(target=rule_target),
        envelope=envelope,
    )

    assert attempt.evidence is not None
    assert attempt.decision.disposition is EvidenceDisposition.REJECTED
    assert attempt.decision.reason is EvidenceReason.SCOPE_MISMATCH


def test_authoritative_operation_must_match_the_envelope() -> None:
    attempt, _ = _normalize(_rule_observation(operation_id="operation-8"))

    assert attempt.evidence is not None
    assert attempt.decision.disposition is EvidenceDisposition.REJECTED
    assert attempt.decision.reason is EvidenceReason.CORRELATION_MISMATCH


@pytest.mark.parametrize(
    "correlation",
    [{}, {"order_id": "order-8"}],
)
def test_required_correlation_must_be_present_and_exact(
    correlation: dict[str, str],
) -> None:
    attempt, _ = _normalize(_rule_observation(correlation=correlation))

    assert attempt.evidence is not None
    assert attempt.decision.disposition is EvidenceDisposition.REJECTED
    assert attempt.decision.reason is EvidenceReason.CORRELATION_MISMATCH


def test_asserted_effect_must_exist_in_the_envelope() -> None:
    assertion = EffectAssertion(
        effect_id="unplanned-record",
        state=EffectAssertionState.ESTABLISHED,
    )

    attempt, _ = _normalize(_rule_observation(effect_assertions=(assertion,)))

    assert attempt.evidence is not None
    assert attempt.decision.disposition is EvidenceDisposition.REJECTED
    assert attempt.decision.reason is EvidenceReason.EXPECTED_EFFECT_MISMATCH


def test_asserted_effect_must_be_relevant_to_the_probe() -> None:
    assertion = EffectAssertion(
        effect_id="audit-record",
        state=EffectAssertionState.ESTABLISHED,
    )
    request = _request(effect_ids=("business-record",))

    attempt, _ = _normalize(
        _rule_observation(effect_assertions=(assertion,)),
        request=request,
    )

    assert attempt.evidence is not None
    assert attempt.decision.disposition is EvidenceDisposition.REJECTED
    assert attempt.decision.reason is EvidenceReason.EXPECTED_EFFECT_MISMATCH


@pytest.mark.parametrize(
    ("observed_at", "retrieved_at", "disposition", "reason"),
    [
        (
            NOW + timedelta(seconds=9),
            NOW + timedelta(seconds=4),
            EvidenceDisposition.ADMITTED,
            EvidenceReason.AUTHORITATIVE_EXACT_CORRELATION,
        ),
        (
            NOW + timedelta(seconds=9, microseconds=1),
            NOW + timedelta(seconds=4),
            EvidenceDisposition.REJECTED,
            EvidenceReason.CLOCK_AMBIGUITY,
        ),
        (
            NOW - timedelta(seconds=5),
            NOW + timedelta(seconds=4),
            EvidenceDisposition.ADMITTED,
            EvidenceReason.AUTHORITATIVE_EXACT_CORRELATION,
        ),
        (
            NOW - timedelta(seconds=5, microseconds=1),
            NOW + timedelta(seconds=4),
            EvidenceDisposition.REJECTED,
            EvidenceReason.STALE_OBSERVATION,
        ),
        (
            NOW,
            NOW + timedelta(seconds=65),
            EvidenceDisposition.ADMITTED,
            EvidenceReason.AUTHORITATIVE_EXACT_CORRELATION,
        ),
        (
            NOW,
            NOW + timedelta(seconds=65, microseconds=1),
            EvidenceDisposition.REJECTED,
            EvidenceReason.STALE_OBSERVATION,
        ),
    ],
)
def test_freshness_and_clock_skew_boundaries_are_exact(
    observed_at,
    retrieved_at,
    disposition: EvidenceDisposition,
    reason: EvidenceReason,
) -> None:
    attempt, _ = _normalize(
        _rule_observation(observed_at=observed_at),
        retrieved_at=retrieved_at,
    )

    assert attempt.evidence is not None
    assert attempt.decision.disposition is disposition
    assert attempt.decision.reason is reason


@pytest.mark.parametrize("field", ("max_age_seconds", "clock_skew_seconds"))
def test_unrepresentable_freshness_policy_fails_closed(field: str) -> None:
    values = make_envelope().model_dump(mode="python")
    values["context"]["freshness"][field] = 2**63 - 1
    envelope = ExecutionEnvelope.model_validate(values)

    attempt, _ = _normalize(_rule_observation(), envelope=envelope)

    assert attempt.evidence is None
    assert attempt.decision.disposition is EvidenceDisposition.REJECTED
    assert attempt.decision.reason is EvidenceReason.CLOCK_AMBIGUITY


@pytest.mark.parametrize(
    ("verdict", "authority", "reason"),
    [
        (
            RuleVerdict.SUPPLEMENTARY,
            EvidenceAuthority.SUPPLEMENTARY,
            EvidenceReason.NON_AUTHORITATIVE_LOG_ONLY,
        ),
        (
            RuleVerdict.ABSENCE_ONLY,
            EvidenceAuthority.WEAK,
            EvidenceReason.NOT_FOUND_ABSENCE_ONLY,
        ),
    ],
)
def test_raw_self_declared_authority_cannot_upgrade_weak_evidence(
    verdict: RuleVerdict,
    authority: EvidenceAuthority,
    reason: EvidenceReason,
) -> None:
    observation = _validated_observation(
        payload={
            "authority": "TARGET_STATE",
            "classification": "COMMITTED",
            "effect_assertions": [
                {"effect_id": "business-record", "state": "ESTABLISHED"}
            ],
            "operation_status": "TERMINAL_COMMITTED",
        }
    )

    attempt, _ = _normalize(
        _rule_observation(verdict=verdict),
        observation=observation,
    )

    assert attempt.decision.disposition is EvidenceDisposition.WEAK
    assert attempt.decision.reason is reason
    assert attempt.evidence is not None
    assert attempt.evidence.authority is authority
    assert attempt.evidence.operation_status is None
    assert all(
        assertion.state is EffectAssertionState.UNVERIFIED
        for assertion in attempt.evidence.effect_assertions
    )


def test_duplicate_candidate_rule_rejection_is_preserved() -> None:
    envelope = make_envelope()
    request = make_probe()
    normalizer = StubNormalizer(error=RuleRejected(EvidenceReason.DUPLICATE_CANDIDATES))

    attempt = EvidencePipeline(envelope, _registry(normalizer)).normalize(
        ProbeRun(
            request=request,
            execution=_completed_execution(envelope, request),
        )
    )

    assert len(normalizer.calls) == 1
    assert attempt.evidence is None
    assert attempt.decision.disposition is EvidenceDisposition.REJECTED
    assert attempt.decision.reason is EvidenceReason.DUPLICATE_CANDIDATES
