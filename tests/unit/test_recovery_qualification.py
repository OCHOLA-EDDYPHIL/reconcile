"""Frozen recovery qualification matrix and authority-boundary tests."""

from __future__ import annotations

import asyncio
from dataclasses import replace
from datetime import UTC, datetime

import pytest

from reconcile.contracts import (
    PermitAction,
    RecoveryHypothesisDisposition,
    RecoveryRunFault,
)
from reconcile.contracts.recovery_qualification import (
    RECOVERY_QUALIFICATION_SEEDS,
    RecoveryQualificationExecutionBasis,
    RecoveryQualificationFaultClass,
    RecoveryQualificationOpportunity,
    RecoveryQualificationPolicy,
    RecoveryQualificationResolution,
    RecoveryQualificationStage,
    RecoveryQualificationWitnessReplayKind,
)
from reconcile.recovery_qualification import (
    RecoveryQualificationError,
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
        provider_name="vertex-ai" if live else None,
        model_name="gemini-2.5-flash" if live else None,
        vertex_location="us-central1" if live else None,
        python_version="3.12.13",
        platform_name="qualification-test",
    )


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
    assert {item.disposition for item in result.wrong_hypotheses} == {
        RecoveryHypothesisDisposition.UNSUPPORTED_PROBE
    }


def test_matrix_records_four_hundred_lanes_and_all_safety_replays() -> None:
    manifest = _manifest()
    environment = _environment(manifest)

    results = run_recovery_qualification(manifest, environment)

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


def test_scripted_comparison_records_zero_model_cost_and_cannot_authorize_value() -> (
    None
):
    manifest = _manifest()
    environment = _environment(manifest)
    results = run_recovery_qualification(manifest, environment)

    comparison = compare_recovery_qualification(manifest, environment, results)

    assert comparison.live_vertex_model_usage_measured is False
    assert comparison.lanes[3].model_call_count > 0
    assert comparison.lanes[3].model_cost_nano_units == 0


def test_scripted_runner_rejects_self_attested_live_vertex_usage() -> None:
    manifest = _manifest()
    environment = _environment(manifest, live=True)

    with pytest.raises(RecoveryQualificationError, match="cannot produce live Vertex"):
        run_recovery_qualification(manifest, environment)
