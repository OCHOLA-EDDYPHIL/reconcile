"""Deterministic evidence classification and safe report assembly."""

from __future__ import annotations

import asyncio
import json
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

import pytest

from reconcile.contracts import (
    OBSERVATION_CAPABILITY_VERSION,
    AdvisoryExplanation,
    Classification,
    EffectAssertion,
    EffectAssertionState,
    EvidenceDisposition,
    EvidenceReason,
    ExecutionEnvelope,
    InvestigationReport,
    ObservationCapability,
    OperationStatus,
    ProbeRequest,
    RequestedAction,
    canonical_json_bytes,
    decode_contract,
)
from reconcile.controller import (
    BoundProbe,
    CapabilityRegistration,
    CapabilityRegistry,
    CapabilitySemantics,
    ControllerAuditRecord,
    ProbeController,
    ProbeObservation,
)
from reconcile.evidence import (
    CoreEvaluation,
    EvidenceEngine,
    ProbeRun,
    RuleInput,
    RuleObservation,
    RuleVerdict,
    TargetRuleDescriptor,
    TargetRuleRegistration,
    TargetRuleRegistry,
    evaluate_evidence,
)
from reconcile.persistence import (
    InMemoryInvestigationRepository,
    new_investigation_record,
)
from tests.contract._factories import make_capability, make_envelope, make_probe

pytestmark = pytest.mark.unit

NOW = datetime(2026, 8, 13, 12, 0, tzinfo=UTC)
ALL_EFFECTS = ("business-record", "audit-record")
RAW_REQUEST_MARKER = "RAW-REQUEST-MARKER-MUST-NOT-ENTER-REPORT"


class _FixedClock:
    def monotonic(self) -> float:
        return 0.0

    def now(self) -> datetime:
        return NOW + timedelta(seconds=4)


class _QueueHandler:
    def __init__(self, observations: tuple[ProbeObservation, ...]) -> None:
        self._observations = list(observations)

    async def __call__(self, probe: BoundProbe) -> ProbeObservation:
        assert probe.relevant_effect_ids == ALL_EFFECTS
        return self._observations.pop(0)


class _FixedNormalizer:
    """Translate a closed test payload into provider-neutral rule assertions."""

    def __call__(self, rule_input: RuleInput) -> RuleObservation:
        observation = ProbeObservation.model_validate_json(rule_input.observation)
        kind = observation.payload.get("kind")
        raw_effects = observation.payload.get("effects")
        source_record = observation.payload.get("record")
        if (
            not isinstance(kind, str)
            or not isinstance(raw_effects, list)
            or any(not isinstance(item, str) for item in raw_effects)
            or not isinstance(source_record, str)
        ):
            raise ValueError("test observation is outside the fixed rule profile")

        definitions = {
            "effects": (
                EffectAssertionState.ESTABLISHED,
                OperationStatus.TERMINAL_COMMITTED,
                RuleVerdict.AUTHORITATIVE_EFFECTS,
            ),
            "partial": (
                None,
                OperationStatus.TERMINAL_COMMITTED,
                RuleVerdict.AUTHORITATIVE_EFFECTS,
            ),
            "pending": (
                EffectAssertionState.ESTABLISHED,
                OperationStatus.ACTIVE,
                RuleVerdict.AUTHORITATIVE_PENDING,
            ),
            "nonexecution": (
                EffectAssertionState.NOT_ESTABLISHED,
                OperationStatus.TERMINAL_NOT_COMMITTED,
                RuleVerdict.AUTHORITATIVE_NON_EXECUTION,
            ),
            "supplementary": (
                EffectAssertionState.UNVERIFIED,
                None,
                RuleVerdict.SUPPLEMENTARY,
            ),
            "absence": (
                EffectAssertionState.UNVERIFIED,
                None,
                RuleVerdict.ABSENCE_ONLY,
            ),
        }
        try:
            assertion_state, operation_status, verdict = definitions[kind]
        except KeyError as error:
            raise ValueError("unknown fixed rule observation") from error

        envelope = rule_input.envelope
        authoritative = verdict in {
            RuleVerdict.AUTHORITATIVE_EFFECTS,
            RuleVerdict.AUTHORITATIVE_NON_EXECUTION,
            RuleVerdict.AUTHORITATIVE_PENDING,
        }
        return RuleObservation(
            target=envelope.target,
            source_record=source_record,
            observed_at=observation.observed_at,
            operation_id=envelope.operation_id if authoritative else None,
            correlation=dict(envelope.context.correlation_fields),
            effect_assertions=tuple(
                EffectAssertion(
                    effect_id=effect_id,
                    state=(
                        EffectAssertionState.ESTABLISHED
                        if kind == "partial" and effect_id == "business-record"
                        else (
                            EffectAssertionState.NOT_ESTABLISHED
                            if kind == "partial"
                            else assertion_state
                        )
                    ),
                )
                for effect_id in raw_effects
            ),
            operation_status=operation_status,
            verdict=verdict,
        )


@dataclass(frozen=True, slots=True)
class _RunResult:
    envelope: ExecutionEnvelope
    engine: EvidenceEngine
    audit_trail: tuple[ControllerAuditRecord, ...]

    def evaluate(self) -> CoreEvaluation:
        return self.engine.evaluate(self.audit_trail)


def _observation(
    kind: str,
    effects: tuple[str, ...],
    *,
    record: str = "record-1",
    observed_at: datetime = NOW + timedelta(seconds=3),
) -> ProbeObservation:
    return ProbeObservation(
        observed_at=observed_at,
        payload={"kind": kind, "effects": list(effects), "record": record},
    )


def _capability() -> ObservationCapability:
    base = make_capability()
    return ObservationCapability(
        schema_version=OBSERVATION_CAPABILITY_VERSION,
        name=base.name,
        version=base.version,
        read_only=True,
        argument_schema={
            "$schema": "https://json-schema.org/draft/2020-12/schema",
            "type": "object",
            "properties": {
                "order_id": {
                    "type": "string",
                    "minLength": 1,
                    "maxLength": 128,
                }
            },
            "required": ["order_id"],
            "additionalProperties": False,
        },
        allowed_targets=base.allowed_targets,
        timeout_ms=base.timeout_ms,
        result_byte_ceiling=base.result_byte_ceiling,
        cost_units=base.cost_units,
    )


def _capability_registry(handler: _QueueHandler) -> CapabilityRegistry:
    registry = CapabilityRegistry()
    registry.register(
        CapabilityRegistration(
            capability=_capability(),
            semantics=CapabilitySemantics.READ_ONLY,
            enabled=True,
            argument_byte_ceiling=4_096,
            max_invocations=3,
            handler=handler,
        )
    )
    return registry


def _rule_registry() -> TargetRuleRegistry:
    registry = TargetRuleRegistry()
    registry.register(
        TargetRuleRegistration(
            descriptor=TargetRuleDescriptor(
                target_kind="gcs.object",
                capability_name="gcs-object-readback",
                capability_version="1.0.0",
                authority_policy_version="authority-gcs-v1",
                classification_policy_version="classification-v1",
                source="fixed-test-rule",
                adapter_version="1.0.0",
            ),
            normalizer=_FixedNormalizer(),
        )
    )
    return registry


def _request(*, rationale: str = "Read the fixed target state.") -> ProbeRequest:
    base = make_probe()
    return ProbeRequest(
        schema_version=base.schema_version,
        capability_name=base.capability_name,
        capability_version=base.capability_version,
        relevant_effect_ids=base.relevant_effect_ids,
        arguments=base.arguments,
        rationale=rationale,
    )


def _run_pipeline(
    envelope: ExecutionEnvelope,
    observations: tuple[ProbeObservation, ...],
    *,
    rationale: str = "Read the fixed target state.",
) -> _RunResult:
    async def scenario() -> _RunResult:
        handler = _QueueHandler(observations)
        controller = ProbeController(
            envelope,
            _capability_registry(handler),
            clock=_FixedClock(),
        )
        engine = EvidenceEngine(envelope, _rule_registry())
        request = _request(rationale=rationale)
        for _ in observations:
            execution = await controller.execute(request)
            engine.process(ProbeRun(request=request, execution=execution))
        return _RunResult(
            envelope=envelope,
            engine=engine,
            audit_trail=controller.audit_trail,
        )

    return asyncio.run(scenario())


@pytest.mark.parametrize(
    ("observation", "expected", "missing_reason"),
    (
        (_observation("effects", ALL_EFFECTS), Classification.COMMITTED, None),
        (
            _observation("nonexecution", ALL_EFFECTS),
            Classification.NOT_COMMITTED,
            None,
        ),
        (
            _observation("partial", ALL_EFFECTS),
            Classification.PARTIAL,
            "authoritative-effect-proof-required",
        ),
        (
            _observation("pending", ("business-record",)),
            Classification.PENDING,
            "authoritative-terminal-proof-required",
        ),
        (
            _observation("supplementary", ALL_EFFECTS),
            Classification.UNKNOWN,
            "non_authoritative_log_only",
        ),
    ),
    ids=("committed", "not-committed", "partial", "pending", "unknown"),
)
def test_five_states_have_complete_fail_closed_action_gates(
    observation: ProbeObservation,
    expected: Classification,
    missing_reason: str | None,
) -> None:
    run = _run_pipeline(make_envelope(), (observation,))
    evaluation = run.evaluate()
    report = run.engine.report(
        run.audit_trail,
        created_at=NOW,
        updated_at=NOW + timedelta(seconds=5),
        revision=1,
    )

    assert evaluation.classification is expected
    assert report.classification is expected
    assert report.proof == evaluation.proof
    assert (
        report.missing_evidence[0].reason if report.missing_evidence else None
    ) == missing_reason
    gates = {gate.requested_action: gate for gate in evaluation.action_gates}
    assert set(gates) == set(RequestedAction)
    assert [gate.requested_action for gate in evaluation.action_gates] == list(
        RequestedAction
    )
    assert gates[RequestedAction.CONTINUE].allowed is (
        expected is Classification.COMMITTED
    )
    assert gates[RequestedAction.RETRY].allowed is False
    assert gates[RequestedAction.COMPENSATE].allowed is False
    assert gates[RequestedAction.OBSERVE].allowed is True
    assert gates[RequestedAction.ESCALATE].allowed is (
        expected is not Classification.COMMITTED
    )


@pytest.mark.parametrize(
    ("same_scope", "expected"),
    (
        (False, Classification.PARTIAL),
        (True, Classification.UNKNOWN),
    ),
    ids=("separate-commit-scopes", "one-atomic-commit-scope"),
)
def test_subset_is_partial_only_across_separate_commit_scopes(
    same_scope: bool,
    expected: Classification,
) -> None:
    run = _run_pipeline(
        make_envelope(same_scope=same_scope),
        (_observation("partial", ALL_EFFECTS),),
    )

    assert run.evaluate().classification is expected


def test_unobserved_effects_preserve_unknown_instead_of_claiming_partial() -> None:
    evaluation = _run_pipeline(
        make_envelope(),
        (_observation("effects", ("business-record",)),),
    ).evaluate()

    assert evaluation.classification is Classification.UNKNOWN
    assert [finding.state for finding in evaluation.proof.effect_findings] == [
        EffectAssertionState.ESTABLISHED,
        EffectAssertionState.UNVERIFIED,
    ]


@pytest.mark.parametrize(
    ("effects", "expected"),
    (
        (("business-record",), Classification.PENDING),
        (ALL_EFFECTS, Classification.COMMITTED),
    ),
    ids=("active-subset", "active-complete"),
)
def test_complete_effect_proof_precedes_active_status(
    effects: tuple[str, ...],
    expected: Classification,
) -> None:
    evaluation = _run_pipeline(
        make_envelope(),
        (_observation("pending", effects),),
    ).evaluate()

    assert evaluation.classification is expected
    assert evaluation.proof.operation_status is OperationStatus.ACTIVE


def test_terminal_committed_subset_conflicting_with_active_is_unknown() -> None:
    run = _run_pipeline(
        make_envelope(),
        (
            _observation("effects", ("business-record",), record="terminal"),
            _observation("pending", (), record="active"),
        ),
    )

    evaluation = run.evaluate()
    report = run.engine.report(
        run.audit_trail,
        created_at=NOW,
        updated_at=NOW + timedelta(seconds=5),
        revision=1,
    )

    assert evaluation.classification is Classification.UNKNOWN
    assert evaluation.proof.conflicting_authority is True
    assert evaluation.proof.operation_status is None
    assert report.classification is Classification.UNKNOWN


def test_terminal_nonexecution_conflicting_with_an_effect_is_unknown() -> None:
    run = _run_pipeline(
        make_envelope(),
        (
            _observation("nonexecution", ALL_EFFECTS, record="negative"),
            _observation(
                "effects",
                ("business-record",),
                record="positive",
            ),
        ),
    )

    evaluation = run.evaluate()
    assert evaluation.classification is Classification.UNKNOWN
    assert evaluation.proof.conflicting_authority is True
    assert evaluation.proof.operation_status is None
    assert evaluation.missing_evidence[0].reason == "conflicting_authority"

    report = run.engine.report(
        run.audit_trail,
        created_at=NOW,
        updated_at=NOW + timedelta(seconds=5),
        revision=1,
    )
    assert report.classification is Classification.UNKNOWN
    assert report.proof == evaluation.proof


def test_weak_and_stale_observations_do_not_contribute_to_proof() -> None:
    run = _run_pipeline(
        make_envelope(),
        (
            _observation("supplementary", ALL_EFFECTS, record="log-only"),
            _observation(
                "effects",
                ALL_EFFECTS,
                record="stale-target-read",
                observed_at=NOW - timedelta(seconds=10),
            ),
        ),
    )

    evaluation = run.evaluate()
    assert evaluation.classification is Classification.UNKNOWN
    assert evaluation.proof.admitted_evidence_ids == ()
    assert {decision.reason for decision in evaluation.decisions} == {
        EvidenceReason.NON_AUTHORITATIVE_LOG_ONLY,
        EvidenceReason.STALE_OBSERVATION,
    }
    assert {decision.disposition for decision in evaluation.decisions} == {
        EvidenceDisposition.WEAK,
        EvidenceDisposition.REJECTED,
    }


def test_input_permutation_has_identical_proof_decisions_and_gates() -> None:
    run = _run_pipeline(
        make_envelope(),
        (
            _observation("effects", ("business-record",), record="business"),
            _observation("effects", ("audit-record",), record="audit"),
        ),
    )

    forward = evaluate_evidence(run.envelope, run.engine.attempts, run.audit_trail)
    reverse = evaluate_evidence(
        run.envelope,
        tuple(reversed(run.engine.attempts)),
        tuple(reversed(run.audit_trail)),
    )

    assert forward.classification is Classification.COMMITTED
    assert forward.attempts == reverse.attempts
    assert canonical_json_bytes(forward.proof) == canonical_json_bytes(reverse.proof)
    assert forward.decisions == reverse.decisions
    assert forward.action_gates == reverse.action_gates
    assert forward.missing_evidence == reverse.missing_evidence


def test_duplicate_raw_observation_is_rejected_without_amplifying_proof() -> None:
    duplicate = _observation("effects", ALL_EFFECTS)
    evaluation = _run_pipeline(
        make_envelope(),
        (duplicate, duplicate),
    ).evaluate()

    assert evaluation.classification is Classification.COMMITTED
    assert len(evaluation.proof.admitted_evidence_ids) == 1
    assert [decision.disposition for decision in evaluation.decisions] == [
        EvidenceDisposition.ADMITTED,
        EvidenceDisposition.REJECTED,
    ]
    assert evaluation.decisions[1].reason is EvidenceReason.DUPLICATE_CANDIDATES


def test_rejected_attempt_cannot_be_promoted_or_resealed_by_a_caller() -> None:
    run = _run_pipeline(
        make_envelope(),
        (
            _observation(
                "effects",
                ALL_EFFECTS,
                observed_at=NOW - timedelta(seconds=10),
            ),
        ),
    )
    attempt = run.engine.attempts[0]

    assert attempt.decision.disposition is EvidenceDisposition.REJECTED
    assert attempt.decision.reason is EvidenceReason.STALE_OBSERVATION
    assert not hasattr(attempt, "with_decision")
    assert not hasattr(attempt, "_seal")
    assert run.evaluate().classification is Classification.UNKNOWN


def test_pipeline_attempt_is_bound_to_its_exact_execution_envelope() -> None:
    run = _run_pipeline(
        make_envelope(),
        (_observation("effects", ALL_EFFECTS),),
    )
    other_values = run.envelope.model_dump(mode="python")
    other_values["investigation_id"] = "investigation-replay"
    other_envelope = ExecutionEnvelope.model_validate(other_values)

    with pytest.raises(ValueError, match="different envelope"):
        evaluate_evidence(other_envelope, run.engine.attempts, run.audit_trail)


def test_real_controller_output_cannot_replay_across_operations() -> None:
    async def scenario() -> tuple[EvidenceDisposition, Classification, bool]:
        source_envelope = make_envelope()
        values = source_envelope.model_dump(mode="python")
        values["investigation_id"] = "investigation-replay"
        values["operation_id"] = "operation-replay"
        other_envelope = ExecutionEnvelope.model_validate(values)
        handler = _QueueHandler((_observation("effects", ALL_EFFECTS),))
        controller = ProbeController(
            source_envelope,
            _capability_registry(handler),
            clock=_FixedClock(),
        )
        request = _request()
        execution = await controller.execute(request)
        engine = EvidenceEngine(other_envelope, _rule_registry())
        attempt = engine.process(ProbeRun(request=request, execution=execution))
        evaluation = engine.evaluate(controller.audit_trail)
        continue_gate = next(
            gate
            for gate in evaluation.action_gates
            if gate.requested_action is RequestedAction.CONTINUE
        )
        return (
            attempt.decision.disposition,
            evaluation.classification,
            continue_gate.allowed,
        )

    disposition, classification, continue_allowed = asyncio.run(scenario())

    assert disposition is EvidenceDisposition.REJECTED
    assert classification is Classification.UNKNOWN
    assert continue_allowed is False


def test_controller_sessions_cannot_be_spliced_into_one_investigation() -> None:
    async def scenario() -> tuple[CoreEvaluation, tuple[ControllerAuditRecord, ...]]:
        envelope = make_envelope()
        first_controller = ProbeController(
            envelope,
            _capability_registry(
                _QueueHandler(
                    (_observation("effects", ("business-record",), record="first"),)
                )
            ),
            clock=_FixedClock(),
        )
        second_controller = ProbeController(
            envelope,
            _capability_registry(
                _QueueHandler(
                    (
                        _observation("nonexecution", ALL_EFFECTS, record="omitted"),
                        _observation("effects", ("audit-record",), record="second"),
                    )
                )
            ),
            clock=_FixedClock(),
        )
        request = _request()
        first = await first_controller.execute(request)
        await second_controller.execute(request)
        second = await second_controller.execute(request)
        engine = EvidenceEngine(envelope, _rule_registry())
        engine.process(ProbeRun(request=request, execution=first))
        rejected = engine.process(ProbeRun(request=request, execution=second))
        audits = (first_controller.audit_trail[0], second_controller.audit_trail[1])
        evaluation = engine.evaluate(audits)
        assert rejected.decision.reason is EvidenceReason.MALFORMED_OBSERVATION
        return evaluation, audits

    evaluation, audits = asyncio.run(scenario())

    assert [record.sequence for record in audits] == [1, 2]
    assert evaluation.classification is Classification.UNKNOWN
    assert [decision.disposition for decision in evaluation.decisions] == [
        EvidenceDisposition.ADMITTED,
        EvidenceDisposition.REJECTED,
    ]
    assert not next(
        gate
        for gate in evaluation.action_gates
        if gate.requested_action is RequestedAction.CONTINUE
    ).allowed


def test_report_rejects_a_substituted_controller_audit_record() -> None:
    run = _run_pipeline(
        make_envelope(),
        (_observation("effects", ALL_EFFECTS),),
    )
    audit_values = run.audit_trail[0].model_dump(mode="python")
    audit_values["request_sha256"] = "f" * 64
    substituted = ControllerAuditRecord.model_validate(audit_values)

    with pytest.raises(ValueError, match="audit does not match"):
        run.engine.report(
            (substituted,),
            created_at=NOW,
            updated_at=NOW + timedelta(seconds=5),
            revision=1,
        )


def test_report_rejects_an_audit_record_omitted_from_evidence_processing() -> None:
    run = _run_pipeline(
        make_envelope(),
        (_observation("effects", ALL_EFFECTS),),
    )
    extra_values = run.audit_trail[0].model_dump(mode="python")
    extra_values["sequence"] = 2
    extra = ControllerAuditRecord.model_validate(extra_values)

    with pytest.raises(ValueError, match="every controller audit"):
        run.engine.report(
            (*run.audit_trail, extra),
            created_at=NOW,
            updated_at=NOW + timedelta(seconds=5),
            revision=1,
        )


def test_action_gates_require_the_complete_controller_audit_trail() -> None:
    run = _run_pipeline(
        make_envelope(),
        (
            _observation("effects", ALL_EFFECTS, record="positive"),
            _observation("nonexecution", ALL_EFFECTS, record="negative"),
        ),
    )

    with pytest.raises(ValueError, match="every controller audit"):
        run.engine.evaluate(run.audit_trail[:1])


def test_core_evaluation_does_not_expose_its_constructor_seal() -> None:
    evaluation = _run_pipeline(
        make_envelope(),
        (_observation("effects", ALL_EFFECTS),),
    ).evaluate()

    assert evaluation.is_engine_output()
    assert not hasattr(evaluation, "_seal")


def test_mutating_an_evaluation_copy_cannot_change_the_sealed_report() -> None:
    run = _run_pipeline(
        make_envelope(),
        (_observation("effects", ALL_EFFECTS),),
    )
    evaluation = run.evaluate()
    exposed = evaluation.evidence[0]
    exposed.correlation["order_id"] = "wrong-order"
    exposed.target.resource["object_name"] = "wrong-object.json"

    report = run.engine.report(
        run.audit_trail,
        created_at=NOW,
        updated_at=NOW + timedelta(seconds=5),
        revision=1,
    )

    assert report.classification is Classification.COMMITTED
    assert report.evidence[0].correlation["order_id"] == "order-7"
    assert report.evidence[0].target.resource["object_name"] == (
        "receipts/order-7.json"
    )


def _build_committed_report(
    run: _RunResult,
    evaluation: CoreEvaluation,
    advisory: AdvisoryExplanation | None,
) -> InvestigationReport:
    return run.engine.report(
        run.audit_trail,
        created_at=NOW,
        updated_at=NOW + timedelta(seconds=5),
        revision=1,
        advisory_explanation=advisory,
    )


def test_advisory_cannot_override_core_and_invalid_citations_are_dropped() -> None:
    run = _run_pipeline(
        make_envelope(),
        (_observation("effects", ALL_EFFECTS),),
    )
    evaluation = run.evaluate()
    evidence_id = evaluation.proof.admitted_evidence_ids[0]

    contradictory = AdvisoryExplanation(
        text="The operation was definitely not committed.",
        cited_evidence_ids=(evidence_id,),
    )
    report = _build_committed_report(run, evaluation, contradictory)
    invalid = _build_committed_report(
        run,
        evaluation,
        AdvisoryExplanation(
            text="This citation was invented.",
            cited_evidence_ids=("evidence:does-not-exist",),
        ),
    )

    assert report.classification is Classification.COMMITTED
    assert report.proof == evaluation.proof
    assert report.advisory_explanation == contradictory
    assert invalid.classification is Classification.COMMITTED
    assert invalid.advisory_explanation is None


def test_advisory_secrets_are_redacted_before_report_persistence() -> None:
    run = _run_pipeline(
        make_envelope(),
        (_observation("effects", ALL_EFFECTS),),
    )
    evaluation = run.evaluate()
    evidence_id = evaluation.proof.admitted_evidence_ids[0]
    marker = "must-not-cross-boundary"

    report = _build_committed_report(
        run,
        evaluation,
        AdvisoryExplanation(
            text=f"provider token={marker}",
            cited_evidence_ids=(evidence_id,),
        ),
    )

    encoded = canonical_json_bytes(report)
    assert marker.encode() not in encoded
    assert b"[REDACTED]" in encoded
    assert report.classification is Classification.COMMITTED


def test_report_audit_is_safe_canonical_and_persists_exactly() -> None:
    run = _run_pipeline(
        make_envelope(),
        (_observation("effects", ALL_EFFECTS),),
        rationale=RAW_REQUEST_MARKER,
    )
    evaluation = run.evaluate()
    report = _build_committed_report(run, evaluation, None)

    encoded = canonical_json_bytes(report)
    payload = json.loads(encoded)
    assert RAW_REQUEST_MARKER.encode() not in encoded
    assert b'"rationale"' not in encoded
    assert b'"arguments"' not in encoded
    assert b'"payload"' not in encoded
    assert payload["probe_audit"][0]["request_sha256"]
    assert set(payload["probe_audit"][0]) == {
        "capability_name",
        "capability_version",
        "completed_at",
        "cost_units_used",
        "evidence_ids",
        "outcome",
        "probe_count_used",
        "probe_sequence",
        "request_sha256",
        "result_byte_count",
        "result_bytes_acquired",
        "result_sha256",
        "session_elapsed_ms",
        "started_at",
        "stop_reason",
        "target_sha256",
    }
    roundtrip = decode_contract(encoded, InvestigationReport)
    assert canonical_json_bytes(roundtrip) == encoded

    async def persist() -> InvestigationReport:
        repository = InMemoryInvestigationRepository()
        initial = new_investigation_record(run.envelope, created_at=NOW)
        await repository.create(initial)
        await repository.replace_report(
            run.envelope.investigation_id,
            0,
            report,
        )
        stored = await repository.get(run.envelope.investigation_id)
        return stored.report

    stored_report = asyncio.run(persist())
    assert canonical_json_bytes(stored_report) == encoded
