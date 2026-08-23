"""Frozen recovery qualification matrix and authority-boundary tests."""

from __future__ import annotations

import asyncio
from dataclasses import replace
from datetime import UTC, datetime

import pytest

import reconcile.recovery_qualification as recovery_qualification_module
from reconcile.contracts import (
    PermitAction,
    RecoveryHypothesisDisposition,
    RecoveryRunFault,
)
from reconcile.contracts.recovery_qualification import (
    RECOVERY_QUALIFICATION_SEEDS,
    RecoveryQualificationExecutionBasis,
    RecoveryQualificationFaultClass,
    RecoveryQualificationHypothesisWrongnessKind,
    RecoveryQualificationOpportunity,
    RecoveryQualificationPolicy,
    RecoveryQualificationResolution,
    RecoveryQualificationStage,
    RecoveryQualificationWitnessReplayKind,
)
from reconcile.recovery_qualification import (
    RecoveryQualificationError,
    _execute_qualification_cases,
    build_recovery_qualification_environment,
    build_recovery_qualification_manifest,
    compare_recovery_qualification,
    recovery_qualification_adaptive_threshold_met,
    recovery_qualification_median_reduction_basis_points,
    replay_recovery_qualification_fixture,
    run_recovery_qualification,
)
from reconcile.recovery_qualification_execution import (
    _fault,
    _RecordingEvidenceSource,
    _run_to_qualification_dispatch_boundary,
    execute_recovery_qualification_proof_lane,
)
from reconcile.recovery_qualification_fixtures import (
    RECOVERY_QUALIFICATION_ARCHETYPES,
    build_recovery_qualification_fixtures,
)
from reconcile.recovery_qualification_provider import (
    build_recovery_qualification_provider,
    recovery_qualification_provider_scenario,
)
from tests.contract._factories import make_recovery_qualification_examples

NOW = datetime(2026, 8, 23, tzinfo=UTC)


def _manifest():
    return build_recovery_qualification_manifest(
        source_revision="d403db32b7507a8e04008d34484e8ba8a51bc657",
        source_tree_sha256="a" * 64,
        created_at=NOW,
    )


def _environment(manifest, *, live: bool = False):
    return build_recovery_qualification_environment(
        manifest,
        repository_clean=True,
        dependency_lock_sha256="b" * 64,
        generated_at=NOW,
        execution_basis=(
            RecoveryQualificationExecutionBasis.LIVE_VERTEX
            if live
            else RecoveryQualificationExecutionBasis.SCRIPTED
        ),
        provider_name="google-vertex-ai" if live else None,
        provider_project="qualification-project" if live else None,
        model_name="gemini-2.5-flash" if live else None,
        reported_model_revision="gemini-2.5-flash-001" if live else None,
        vertex_location="us-central1" if live else None,
        python_version="3.12.13",
        platform_name="qualification-test",
    )


@pytest.fixture(scope="module")
def qualification_matrix():
    manifest, environment, results, *_ = make_recovery_qualification_examples()
    return manifest, environment, results


def test_frozen_matrix_has_exact_schedule_and_required_coverage() -> None:
    fixtures = build_recovery_qualification_fixtures()

    assert len(RECOVERY_QUALIFICATION_ARCHETYPES) == 20
    assert RECOVERY_QUALIFICATION_SEEDS == (104729, 130363, 155921, 196613, 262147)
    assert len(fixtures) == 100
    assert len({item.case_id for item in fixtures}) == 100
    assert {item.archetype.stage for item in fixtures} == set(
        RecoveryQualificationStage
    )
    assert {item.archetype.fault_class for item in fixtures} == set(
        RecoveryQualificationFaultClass
    )
    assert {item.archetype.opportunity for item in fixtures} == set(
        RecoveryQualificationOpportunity
    )
    assert {
        item.archetype.expected_permit_action
        for item in fixtures
        if item.archetype.expected_permit_action is not None
    } == {PermitAction.CONTINUE, PermitAction.RETRY}
    neutral_no_fault = {
        item.archetype.archetype_id
        for item in fixtures
        if item.archetype.fault_class is RecoveryQualificationFaultClass.NO_FAULT
        and item.archetype.opportunity is RecoveryQualificationOpportunity.NEUTRAL
    }
    assert neutral_no_fault == {"promote-committed"}


def test_each_archetype_varies_provider_precondition_state_across_seeds() -> None:
    fixtures = build_recovery_qualification_fixtures()
    generations_by_archetype: dict[str, set[int]] = {}
    for fixture in fixtures:
        scenario = recovery_qualification_provider_scenario(fixture)
        provider = build_recovery_qualification_provider(fixture)
        assert (
            scenario.initial_service_generation == fixture.initial_provider_generation
        )
        generations_by_archetype.setdefault(
            fixture.archetype.archetype_id,
            set(),
        ).add(provider.snapshot().service_generation)

    assert len(fixtures) == 100
    assert all(
        values == {1, 2, 3, 4, 5} for values in generations_by_archetype.values()
    )


def test_only_explicit_fault_boundaries_use_production_fault_toggles() -> None:
    fixtures = build_recovery_qualification_fixtures()

    by_archetype = {
        fixture.archetype.archetype_id: fixture
        for fixture in fixtures
        if fixture.seed == RECOVERY_QUALIFICATION_SEEDS[0]
    }
    assert _fault(by_archetype["stage-drop-committed"]) is (
        RecoveryRunFault.DROP_AFTER_ACCEPT
    )
    assert _fault(by_archetype["record-predispatch-retry"]) is (
        RecoveryRunFault.SUPPRESS_BEFORE_DISPATCH
    )
    assert _fault(by_archetype["promote-committed"]) is RecoveryRunFault.NO_FAULT
    assert _fault(by_archetype["stage-unavailable"]) is RecoveryRunFault.NO_FAULT
    assert _fault(by_archetype["record-outcome-unknown"]) is (RecoveryRunFault.NO_FAULT)


@pytest.mark.parametrize(
    ("archetype_id", "policy", "expected_probe_count"),
    (
        ("stage-terminal-partial", RecoveryQualificationPolicy.ADAPTIVE, 2),
        ("stage-conflict", RecoveryQualificationPolicy.ADAPTIVE, 5),
        ("record-predispatch-retry", RecoveryQualificationPolicy.FIXED, 2),
        ("record-predispatch-retry", RecoveryQualificationPolicy.ADAPTIVE, 2),
    ),
)
def test_preregistered_probe_metrics_end_at_the_selected_proof(
    tmp_path,
    archetype_id: str,
    policy: RecoveryQualificationPolicy,
    expected_probe_count: int,
) -> None:
    fixture = next(
        item
        for item in build_recovery_qualification_fixtures()
        if item.archetype.archetype_id == archetype_id
        and item.seed == RECOVERY_QUALIFICATION_SEEDS[0]
    )

    result = asyncio.run(
        execute_recovery_qualification_proof_lane(
            fixture,
            policy=policy,
            state_directory=tmp_path / archetype_id,
            restart=False,
            _include_safety_replays=False,
        )
    )

    assert result.probe_count == expected_probe_count
    assert result.time_to_sufficient_evidence_ms == expected_probe_count * 8
    assert result.demonstrated_evidence_profile == fixture.archetype.evidence_profile
    if archetype_id == "record-predispatch-retry":
        assert result.provider_mutations.record_calls == 1


def test_proof_measurement_lookup_fails_closed_for_an_unknown_report() -> None:
    source = _RecordingEvidenceSource(
        object(),  # type: ignore[arg-type]
        "stage",
        repeat_target_primary=False,
        target_replay_state=None,
    )

    with pytest.raises(ValueError, match="no acquisition measurement"):
        source.measurement_for_report("a" * 64)


def test_record_crash_replay_does_not_claim_unreceipted_provider_contact(
    tmp_path,
) -> None:
    fixture = next(
        item
        for item in build_recovery_qualification_fixtures()
        if item.archetype.archetype_id == "record-outcome-unknown"
        and item.seed == RECOVERY_QUALIFICATION_SEEDS[0]
    )

    result = asyncio.run(
        execute_recovery_qualification_proof_lane(
            fixture,
            policy=RecoveryQualificationPolicy.FIXED,
            state_directory=tmp_path / fixture.case_id,
            restart=True,
            _include_safety_replays=False,
        )
    )

    assert "record-provider-contacted" not in result.demonstrated_evidence_profile
    assert result.restarted_snapshot_sha256 is not None


@pytest.mark.parametrize(
    ("archetype_id", "expected_kind"),
    (
        (
            "stage-conflict",
            RecoveryQualificationWitnessReplayKind.EVIDENCE_DUPLICATION,
        ),
        (
            "stage-absence",
            RecoveryQualificationWitnessReplayKind.ZERO_EVIDENCE_REPLAY,
        ),
    ),
)
def test_witness_replay_distinguishes_admitted_from_zero_evidence(
    tmp_path,
    archetype_id: str,
    expected_kind: RecoveryQualificationWitnessReplayKind,
) -> None:
    fixture = next(
        item
        for item in build_recovery_qualification_fixtures()
        if item.archetype.archetype_id == archetype_id
    )

    result = asyncio.run(
        execute_recovery_qualification_proof_lane(
            fixture,
            policy=RecoveryQualificationPolicy.FIXED,
            state_directory=tmp_path / archetype_id,
            restart=False,
        )
    )

    assert result.witness_replay_kind is expected_kind
    assert result.replayed_witness_semantic_sha256 == result.witness_semantic_sha256
    assert all(item.hypothesis_sha256 for item in result.wrong_hypotheses)
    assert {item.disposition for item in result.wrong_hypotheses} <= {
        RecoveryHypothesisDisposition.SELECTED,
        RecoveryHypothesisDisposition.NO_PROBE,
    }
    assert tuple(item.wrongness_kind for item in result.wrong_hypotheses) == tuple(
        RecoveryQualificationHypothesisWrongnessKind
    )


def test_wrong_hypothesis_replay_uses_certificate_case_clock(tmp_path) -> None:
    fixture = build_recovery_qualification_fixtures()[0]

    result = asyncio.run(
        execute_recovery_qualification_proof_lane(
            fixture,
            policy=RecoveryQualificationPolicy.FIXED,
            state_directory=tmp_path / fixture.case_id,
            restart=False,
        )
    )

    assert result.permit_sha256 is not None
    assert len(result.wrong_hypotheses) == len(
        RecoveryQualificationHypothesisWrongnessKind
    )
    assert all(
        replay.permit_sha256 == result.permit_sha256
        for replay in result.wrong_hypotheses
    )


def test_external_cancellation_is_not_treated_as_a_qualification_boundary() -> None:
    async def exercise() -> None:
        entered = asyncio.Event()

        class BlockingWorkflow:
            async def run(self, _run_id):
                entered.set()
                await asyncio.Event().wait()

        task = asyncio.create_task(
            _run_to_qualification_dispatch_boundary(
                BlockingWorkflow(),  # type: ignore[arg-type]
                "externally-cancelled-run",
            )
        )
        await entered.wait()
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task

    asyncio.run(exercise())


def test_matrix_execution_is_sequential_and_preserves_canonical_lane_order(
    tmp_path,
    monkeypatch,
) -> None:
    fixtures = build_recovery_qualification_fixtures()[:2]
    calls: list[tuple[str, RecoveryQualificationPolicy]] = []
    active = 0
    max_active = 0

    async def record(fixture, policy):
        nonlocal active, max_active
        active += 1
        max_active = max(max_active, active)
        calls.append((fixture.case_id, policy))
        await asyncio.sleep(0)
        active -= 1
        return object()

    async def blind(fixture, *, policy):
        return await record(fixture, policy)

    async def proof(fixture, *, policy, state_directory, restart):
        assert state_directory == tmp_path / fixture.case_id / policy.value
        assert restart is (
            policy is RecoveryQualificationPolicy.FIXED
            and fixture.seed == RECOVERY_QUALIFICATION_SEEDS[0]
        )
        return await record(fixture, policy)

    monkeypatch.setattr(
        recovery_qualification_module,
        "execute_recovery_qualification_blind_lane",
        blind,
    )
    monkeypatch.setattr(
        recovery_qualification_module,
        "execute_recovery_qualification_proof_lane",
        proof,
    )

    executions = asyncio.run(
        _execute_qualification_cases(fixtures, state_root=tmp_path)
    )

    assert tuple(item.fixture for item in executions) == fixtures
    assert max_active == 1
    assert calls == [
        (fixture.case_id, policy)
        for fixture in fixtures
        for policy in (
            RecoveryQualificationPolicy.BLIND_RETRY,
            RecoveryQualificationPolicy.BLIND_ABORT,
            RecoveryQualificationPolicy.FIXED,
            RecoveryQualificationPolicy.ADAPTIVE,
        )
    ]


def test_matrix_contract_records_four_hundred_lanes_and_all_safety_replays(
    qualification_matrix,
) -> None:
    _manifest_value, environment, results = qualification_matrix

    assert results.case_count == 100
    assert results.lane_result_count == 400
    assert results.false_permit_count == 0
    assert results.replay_parity_case_count == 100
    assert results.wrong_hypothesis_replay_count == 300
    assert results.wrong_hypothesis_decision_divergence_count == 0
    assert results.wrong_hypothesis_permit_divergence_count == 0
    assert results.witness_replay_valid_count == results.witness_case_count == 55
    assert results.witness_evidence_duplication_case_count > 0
    assert results.witness_zero_evidence_replay_case_count > 0
    assert (
        results.witness_evidence_duplication_case_count
        + results.witness_zero_evidence_replay_case_count
        == results.witness_case_count
    )
    assert results.non_authorizing_certificate_case_count == 15
    assert results.restart_valid_count == results.restart_case_count == 20
    assert (results.sqlite_case_count, results.firestore_case_count) == (50, 50)
    assert results.safety_passed is True
    assert "python -m pytest -q" in environment.test_commands


def test_same_id_fixture_content_cannot_drift_from_frozen_catalog() -> None:
    manifest = _manifest()
    environment = _environment(manifest)
    fixtures = list(build_recovery_qualification_fixtures())
    original = fixtures[0]
    payload = original.archetype.model_dump(mode="python")
    payload.update(
        {
            "expected_resolution": RecoveryQualificationResolution.RETRY,
            "expected_permit_action": PermitAction.RETRY,
        }
    )
    fixtures[0] = replace(
        original,
        archetype=type(original.archetype).model_validate(payload),
    )

    with pytest.raises(RecoveryQualificationError, match="schedule changed"):
        run_recovery_qualification(manifest, environment, fixtures=tuple(fixtures))


def test_hypotheses_and_evidence_order_cannot_change_deterministic_authority() -> None:
    fixture = build_recovery_qualification_fixtures()[0]
    baseline = replay_recovery_qualification_fixture(fixture)

    wrong = replay_recovery_qualification_fixture(
        fixture,
        hypothesis={"resolution": "RETRY", "action": "RETRY"},
    )
    reordered = replay_recovery_qualification_fixture(
        fixture,
        observations=tuple(reversed(fixture.observations)),
    )
    duplicated = replay_recovery_qualification_fixture(
        fixture,
        observations=(
            *fixture.observations,
            replace(fixture.observations[0], evidence_id="duplicate-evidence-id"),
        ),
    )

    assert wrong == baseline
    assert reordered == baseline
    assert duplicated == baseline


def test_median_probe_reduction_uses_exact_even_sample_integer_formula() -> None:
    assert recovery_qualification_median_reduction_basis_points((2, 3), (1, 2)) == 4000
    assert recovery_qualification_median_reduction_basis_points((2, 3), (3, 4)) == -4000
    assert recovery_qualification_median_reduction_basis_points((0, 0), (0, 0)) == 0


def test_adaptive_efficiency_gate_includes_exact_25_percent_boundary() -> None:
    assert recovery_qualification_adaptive_threshold_met(2500) is True
    assert recovery_qualification_adaptive_threshold_met(2499) is False


def test_scripted_comparison_records_zero_model_cost_and_cannot_authorize_value(
    qualification_matrix,
) -> None:
    manifest, environment, results = qualification_matrix

    comparison = compare_recovery_qualification(manifest, environment, results)

    assert comparison.live_vertex_model_usage_measured is False
    assert comparison.lanes[3].model_call_count > 0
    assert comparison.lanes[3].model_cost_nano_units == 0


def test_scripted_runner_rejects_self_attested_live_vertex_usage() -> None:
    manifest = _manifest()
    environment = _environment(manifest, live=True)

    with pytest.raises(RecoveryQualificationError, match="cannot produce live Vertex"):
        run_recovery_qualification(manifest, environment)
