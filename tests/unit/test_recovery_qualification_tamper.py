"""Focused tamper checks for recovery qualification claim evidence."""

from __future__ import annotations

import asyncio
import hashlib
import subprocess
from datetime import timedelta
from pathlib import Path

import pytest

import reconcile.recovery_qualification as recovery_qualification_module
from reconcile.contracts import (
    Classification,
    ContractError,
    EffectAssertion,
    EffectAssertionState,
    PlannerMissingEvidence,
    canonical_json_bytes,
    canonical_sha256,
)
from reconcile.contracts.base import canonical_json_value_bytes
from reconcile.contracts.recovery_qualification import (
    RecoveryQualificationContention,
    RecoveryQualificationExecutionBasis,
    RecoveryQualificationModelUsage,
    RecoveryQualificationModelUsageStatus,
    RecoveryQualificationPolicy,
    RecoveryQualificationResults,
)
from reconcile.recovery_qualification import (
    RecoveryQualificationBundle,
    RecoveryQualificationError,
    authorize_recovery_qualification_claims,
    build_recovery_qualification_bundle,
    build_recovery_qualification_environment,
    compare_recovery_qualification,
    export_recovery_qualification_bundle,
    recovery_qualification_adaptive_threshold_met,
    verify_recovery_qualification_bundle,
)
from reconcile.recovery_qualification_execution import (
    _OBSERVED_SELECTION_CONDITION,
    _UNMATCHED_SELECTION_CONDITION,
    _UTILITY_OBSERVATION_SELECTION_MODE,
    _evidence_semantics,
    _ScriptedPlanner,
)
from tests.contract._factories import (
    make_evidence,
    make_planner_input,
    make_recovery_qualification_examples,
)


def _replace_tuple_item(values, index, replacement):
    updated = list(values)
    updated[index] = replacement
    return tuple(updated)


def _install_fast_bundle_execution(monkeypatch) -> None:
    async def fake_results(manifest, environment):
        template = make_recovery_qualification_examples()[2]
        return RecoveryQualificationResults.model_validate(
            template.model_copy(
                update={
                    "manifest_sha256": canonical_sha256(manifest),
                    "environment_sha256": canonical_sha256(environment),
                }
            ).model_dump(mode="python")
        )

    async def fake_contention(
        manifest,
        results,
        *,
        environment=None,
        working_directory=None,
    ):
        del environment, working_directory
        template = make_recovery_qualification_examples()[3]
        return RecoveryQualificationContention.model_validate(
            template.model_copy(
                update={
                    "manifest_sha256": canonical_sha256(manifest),
                    "results_sha256": canonical_sha256(results),
                }
            ).model_dump(mode="python")
        )

    monkeypatch.setattr(
        recovery_qualification_module,
        "_run_recovery_qualification_async",
        fake_results,
    )
    monkeypatch.setattr(
        recovery_qualification_module,
        "run_recovery_qualification_contention",
        fake_contention,
    )


def _install_example_source(tmp_path, monkeypatch) -> Path:
    manifest, environment, *_ = make_recovery_qualification_examples()
    repository = tmp_path / "example-source"
    repository.mkdir()
    (repository / "uv.lock").write_text("version = 1\n", encoding="utf-8")
    measured = (
        repository,
        manifest.source_revision,
        manifest.source_tree_sha256,
        environment.repository_clean,
        environment.dependency_lock_sha256,
    )
    monkeypatch.setattr(
        recovery_qualification_module,
        "_measured_recovery_qualification_source",
        lambda _repository: measured,
    )
    return repository


def _committed_source_repository(tmp_path: Path, *, track_lock: bool = True) -> Path:
    repository = tmp_path / "committed-source"
    repository.mkdir(parents=True)
    (repository / "uv.lock").write_text("version = 1\n", encoding="utf-8")
    (repository / "tracked.py").write_text("VALUE = 1\n", encoding="utf-8")
    subprocess.run(("git", "init", "-q"), cwd=repository, check=True)
    paths = ("uv.lock", "tracked.py") if track_lock else ("tracked.py",)
    subprocess.run(("git", "add", "--", *paths), cwd=repository, check=True)
    subprocess.run(
        (
            "git",
            "-c",
            "user.name=RECONCILE Qualification",
            "-c",
            "user.email=qualification@example.invalid",
            "commit",
            "-qm",
            "qualification source",
        ),
        cwd=repository,
        check=True,
    )
    return repository.resolve()


def test_evidence_semantics_are_strict_json_values() -> None:
    evidence, _decision = make_evidence(Classification.COMMITTED)
    semantics = _evidence_semantics(evidence)

    assert canonical_json_value_bytes(semantics)
    assert all(type(item) is dict for item in semantics["effect_assertions"])


def test_source_measurement_rejects_a_git_subdirectory(tmp_path) -> None:
    repository = _committed_source_repository(tmp_path)
    subdirectory = repository / "nested"
    subdirectory.mkdir()

    with pytest.raises(RecoveryQualificationError, match="Git top-level"):
        recovery_qualification_module.recovery_qualification_source_state(subdirectory)


def test_source_measurement_detects_assume_unchanged_content(tmp_path) -> None:
    repository = _committed_source_repository(tmp_path)
    _revision, original_tree, original_clean = (
        recovery_qualification_module.recovery_qualification_source_state(repository)
    )
    subprocess.run(
        ("git", "update-index", "--assume-unchanged", "tracked.py"),
        cwd=repository,
        check=True,
    )
    (repository / "tracked.py").write_text("VALUE = 2\n", encoding="utf-8")
    assert (
        subprocess.run(
            ("git", "status", "--porcelain"),
            cwd=repository,
            check=True,
            capture_output=True,
        ).stdout
        == b""
    )

    _revision, changed_tree, changed_clean = (
        recovery_qualification_module.recovery_qualification_source_state(repository)
    )

    assert original_clean is True
    assert changed_clean is False
    assert changed_tree != original_tree


@pytest.mark.parametrize("mutation", ("addition", "modification"))
def test_source_measurement_rejects_staged_index_drift(tmp_path, mutation) -> None:
    repository = _committed_source_repository(tmp_path)
    if mutation == "addition":
        path = repository / "injected.py"
        path.write_text("INJECTED = True\n", encoding="utf-8")
    else:
        path = repository / "tracked.py"
        path.write_text("VALUE = 2\n", encoding="utf-8")
    subprocess.run(("git", "add", "--", path.name), cwd=repository, check=True)

    with pytest.raises(RecoveryQualificationError, match="index must exactly match"):
        recovery_qualification_module.recovery_qualification_source_state(repository)


def test_measured_source_requires_the_executing_tree_and_tracked_lock(
    tmp_path,
    monkeypatch,
) -> None:
    repository = _committed_source_repository(tmp_path / "tracked")
    with pytest.raises(RecoveryQualificationError, match="measured repository"):
        recovery_qualification_module._measured_recovery_qualification_source(
            repository
        )

    untracked_lock_repository = _committed_source_repository(
        tmp_path / "untracked",
        track_lock=False,
    )
    monkeypatch.setattr(
        recovery_qualification_module,
        "_recovery_qualification_executing_repository",
        lambda: untracked_lock_repository,
    )
    with pytest.raises(RecoveryQualificationError, match=r"checked-in uv\.lock"):
        recovery_qualification_module._measured_recovery_qualification_source(
            untracked_lock_repository
        )


def test_scripted_planner_never_cites_rejected_evidence() -> None:
    planner_input = make_planner_input()
    turn = asyncio.run(_ScriptedPlanner().plan(planner_input))

    assert turn.output is not None
    citations = turn.output.explanation.citations
    assert citations.rejected_evidence_ids == ()
    assert set(citations.admitted_evidence_ids) <= {
        item.evidence_id for item in planner_input.admitted_evidence
    }
    assert set(citations.weak_evidence_ids) <= {
        item.evidence_id for item in planner_input.weak_evidence
    }


def test_scripted_record_planner_stops_after_one_receipt_probe() -> None:
    planner = _ScriptedPlanner()
    planner_input = make_planner_input()
    invocation = planner_input.envelope.context.invocation.model_copy(
        update={"tool_name": "create-firestore-release-record"}
    )
    context = planner_input.envelope.context.model_copy(
        update={"invocation": invocation}
    )
    envelope = planner_input.envelope.model_copy(update={"context": context})
    first_input = planner_input.model_copy(
        update={"envelope": envelope, "prior_executable_request_hashes": ()}
    )
    second_input = planner_input.model_copy(
        update={
            "envelope": envelope,
            "prior_executable_request_hashes": ("e" * 64,),
        }
    )

    first = asyncio.run(planner.plan(first_input))
    second = asyncio.run(planner.plan(second_input))

    assert first.output is not None
    assert tuple(item.capability_name for item in first.output.probe_proposals) == (
        "reconcile-dispatch-receipt-get",
    )
    assert second.output is not None
    assert second.output.probe_proposals == ()
    assert second.output.stop_advice.recommend_stop is True


def test_recovery_utility_selector_changes_with_observed_service_state() -> None:
    planner_input = make_planner_input()
    invocation = planner_input.envelope.context.invocation.model_copy(
        update={"tool_name": "stage-cloud-run-revision"}
    )
    context = planner_input.envelope.context.model_copy(
        update={"invocation": invocation}
    )
    envelope = planner_input.envelope.model_copy(update={"context": context})
    service_evidence = planner_input.admitted_evidence[0].model_copy(
        update={
            "capability_name": "cloud-run-service-get",
            "effect_assertions": (
                EffectAssertion(
                    effect_id="stage-revision",
                    state=EffectAssertionState.UNVERIFIED,
                ),
                EffectAssertion(
                    effect_id="stage-readiness",
                    state=EffectAssertionState.UNVERIFIED,
                ),
                EffectAssertion(
                    effect_id="stage-traffic",
                    state=EffectAssertionState.ESTABLISHED,
                ),
            ),
        }
    )
    conditioned = planner_input.model_copy(
        update={
            "envelope": envelope,
            "admitted_evidence": (service_evidence,),
            "weak_evidence": (),
            "rejected_evidence": (),
            "missing_evidence": (
                PlannerMissingEvidence(
                    effect_id="stage-revision",
                    reason="insufficient_authoritative_evidence",
                ),
                PlannerMissingEvidence(
                    effect_id="stage-readiness",
                    reason="insufficient_authoritative_evidence",
                ),
            ),
            "prior_executable_request_hashes": (),
        }
    )
    changed_assertions = tuple(
        assertion.model_copy(update={"state": EffectAssertionState.NOT_ESTABLISHED})
        if assertion.effect_id == "stage-traffic"
        else assertion
        for assertion in service_evidence.effect_assertions
    )
    changed = conditioned.model_copy(
        update={
            "admitted_evidence": (
                service_evidence.model_copy(
                    update={"effect_assertions": changed_assertions}
                ),
            )
        }
    )

    observed_planner = _ScriptedPlanner(
        utility_selection_mode=_UTILITY_OBSERVATION_SELECTION_MODE
    )
    changed_planner = _ScriptedPlanner(
        utility_selection_mode=_UTILITY_OBSERVATION_SELECTION_MODE
    )
    observed_capability = observed_planner._normal_capability(conditioned)
    changed_capability = changed_planner._normal_capability(changed)

    assert observed_capability == "cloud-run-revision-get"
    assert changed_capability == "cloud-run-revision-health"
    assert (
        observed_planner.selection_conditions_by_tool["stage-cloud-run-revision"]
        == _OBSERVED_SELECTION_CONDITION
    )
    assert (
        changed_planner.selection_conditions_by_tool["stage-cloud-run-revision"]
        == _UNMATCHED_SELECTION_CONDITION
    )


@pytest.mark.parametrize("mutation", ("missing", "tampered"))
def test_comparison_rejects_demonstrated_evidence_profile_drift(mutation: str) -> None:
    manifest, environment, results, *_ = make_recovery_qualification_examples()
    lane = results.lane_results[2]
    if mutation == "missing":
        profile = lane.demonstrated_evidence_profile[1:]
    else:
        profile = (
            "tampered-provider-fact",
            *lane.demonstrated_evidence_profile[1:],
        )
    tampered_lane = lane.model_copy(update={"demonstrated_evidence_profile": profile})
    tampered_results = results.model_copy(
        update={
            "lane_results": _replace_tuple_item(
                results.lane_results,
                2,
                tampered_lane,
            )
        }
    )

    with pytest.raises(
        RecoveryQualificationError,
        match="results contradict the frozen manifest",
    ):
        compare_recovery_qualification(manifest, environment, tampered_results)


@pytest.mark.parametrize(
    "mutation",
    ("completion_outcome", "receipt_identity"),
)
def test_authorization_rejects_contention_identity_drift(
    mutation: str,
    tmp_path,
    monkeypatch,
) -> None:
    repository = _install_example_source(tmp_path, monkeypatch)
    manifest, environment, results, contention, comparison, *_ = (
        make_recovery_qualification_examples()
    )
    trial = contention.trials[0]
    if mutation == "receipt_identity":
        tampered_trial = trial.model_copy(
            update={"provider_call_receipt_ids": (f"provider-call-receipt-{'f' * 32}",)}
        )
    else:
        tampered_permit = trial.final_permit.model_copy(
            update={"completion_outcome": None}
        )
        tampered_trial = trial.model_copy(
            update={
                "final_permit": tampered_permit,
            }
        )
    tampered_contention = contention.model_copy(
        update={
            "trials": _replace_tuple_item(
                contention.trials,
                0,
                tampered_trial,
            )
        }
    )

    with pytest.raises((RecoveryQualificationError, ContractError)):
        authorize_recovery_qualification_claims(
            manifest,
            environment,
            results,
            tampered_contention,
            comparison,
            source_repository=repository,
        )


def test_authorization_rejects_invalid_claimed_permit_revision(
    tmp_path,
    monkeypatch,
) -> None:
    repository = _install_example_source(tmp_path, monkeypatch)
    manifest, environment, results, contention, comparison, *_ = (
        make_recovery_qualification_examples()
    )
    trial = contention.trials[0]
    tampered_permit = trial.final_permit.model_copy(
        update={"revision": trial.final_permit.revision + 1}
    )
    tampered_trial = trial.model_copy(update={"final_permit": tampered_permit})
    tampered_contention = contention.model_copy(
        update={
            "trials": _replace_tuple_item(
                contention.trials,
                0,
                tampered_trial,
            )
        }
    )

    with pytest.raises(ContractError, match="canonical encoding failed"):
        authorize_recovery_qualification_claims(
            manifest,
            environment,
            results,
            tampered_contention,
            comparison,
            source_repository=repository,
        )


def test_bundle_runner_derives_source_and_reproduces_seeded_bytes(
    tmp_path,
    monkeypatch,
) -> None:
    _install_fast_bundle_execution(monkeypatch)
    repository = tmp_path / "source"
    repository.mkdir()
    lock = b"version = 1\n"
    (repository / "uv.lock").write_bytes(lock)
    source_state = (
        repository.resolve(),
        "d" * 40,
        "e" * 64,
        True,
        hashlib.sha256(lock).hexdigest(),
    )
    monkeypatch.setattr(
        recovery_qualification_module,
        "_measured_recovery_qualification_source",
        lambda _repository: source_state,
    )

    first = asyncio.run(
        build_recovery_qualification_bundle(source_repository=repository)
    )
    second = asyncio.run(
        build_recovery_qualification_bundle(source_repository=repository)
    )

    assert first.manifest.source_revision == source_state[1]
    assert first.manifest.source_tree_sha256 == source_state[2]
    assert first.environment.repository_clean is True
    assert first.environment.dependency_lock_sha256 == hashlib.sha256(lock).hexdigest()
    for field in (
        "manifest",
        "environment",
        "results",
        "contention",
        "comparison",
        "claim_authorization",
    ):
        assert canonical_json_bytes(getattr(first, field)) == canonical_json_bytes(
            getattr(second, field)
        )


def test_bundle_runner_rejects_source_change_during_execution(
    tmp_path,
    monkeypatch,
) -> None:
    _install_fast_bundle_execution(monkeypatch)
    repository = tmp_path / "source"
    repository.mkdir()
    (repository / "uv.lock").write_text("version = 1\n", encoding="utf-8")
    states = iter(
        (
            (
                repository.resolve(),
                "d" * 40,
                "e" * 64,
                True,
                hashlib.sha256(b"version = 1\n").hexdigest(),
            ),
            (
                repository.resolve(),
                "d" * 40,
                "f" * 64,
                False,
                hashlib.sha256(b"version = 1\n").hexdigest(),
            ),
        )
    )
    monkeypatch.setattr(
        recovery_qualification_module,
        "_measured_recovery_qualification_source",
        lambda _repository: next(states),
    )

    with pytest.raises(RecoveryQualificationError, match="source changed"):
        asyncio.run(build_recovery_qualification_bundle(source_repository=repository))


def test_authorization_recomputes_comparison_from_results(
    tmp_path,
    monkeypatch,
) -> None:
    repository = _install_example_source(tmp_path, monkeypatch)
    manifest, environment, results, contention, comparison, *_ = (
        make_recovery_qualification_examples()
    )
    lane = comparison.lanes[2]
    tampered_lane = lane.model_copy(
        update={"total_probe_count": lane.total_probe_count + 1}
    )
    tampered_comparison = comparison.model_copy(
        update={
            "lanes": _replace_tuple_item(comparison.lanes, 2, tampered_lane),
        }
    )

    with pytest.raises(
        RecoveryQualificationError,
        match="comparison does not reproduce its results",
    ):
        authorize_recovery_qualification_claims(
            manifest,
            environment,
            results,
            contention,
            tampered_comparison,
            source_repository=repository,
        )


def test_public_claim_boundaries_require_a_measured_repository(tmp_path) -> None:
    manifest, environment, results, contention, comparison, claims, _index = (
        make_recovery_qualification_examples()
    )
    bundle = RecoveryQualificationBundle(
        manifest=manifest,
        environment=environment,
        results=results,
        contention=contention,
        comparison=comparison,
        claim_authorization=claims,
    )

    with pytest.raises(TypeError, match="source_repository"):
        authorize_recovery_qualification_claims(  # type: ignore[call-arg]
            manifest,
            environment,
            results,
            contention,
            comparison,
        )
    with pytest.raises(TypeError, match="source_repository"):
        export_recovery_qualification_bundle(  # type: ignore[call-arg]
            tmp_path / "omitted-source",
            bundle,
        )
    with pytest.raises(TypeError, match="source_repository"):
        verify_recovery_qualification_bundle(  # type: ignore[call-arg]
            tmp_path / "omitted-source"
        )


def test_fabricated_source_identity_cannot_authorize_or_export(tmp_path) -> None:
    manifest, environment, results, contention, comparison, claims, _index = (
        make_recovery_qualification_examples()
    )
    bundle = RecoveryQualificationBundle(
        manifest=manifest,
        environment=environment,
        results=results,
        contention=contention,
        comparison=comparison,
        claim_authorization=claims,
    )
    repository = Path(__file__).parents[2]

    with pytest.raises(RecoveryQualificationError, match="measured source"):
        authorize_recovery_qualification_claims(
            manifest,
            environment,
            results,
            contention,
            comparison,
            source_repository=repository,
        )
    destination = tmp_path / "forged-source"
    with pytest.raises(RecoveryQualificationError, match="measured source"):
        export_recovery_qualification_bundle(
            destination,
            bundle,
            source_repository=repository,
        )
    assert not destination.exists()


def test_self_attested_live_measurement_cannot_authorize_efficiency(
    tmp_path,
    monkeypatch,
) -> None:
    repository = _install_example_source(tmp_path, monkeypatch)
    manifest, scripted_environment, template, template_contention, *_ = (
        make_recovery_qualification_examples()
    )
    scripted_comparison = compare_recovery_qualification(
        manifest,
        scripted_environment,
        template,
    )
    scripted_claims = authorize_recovery_qualification_claims(
        manifest,
        scripted_environment,
        template,
        template_contention,
        scripted_comparison,
        source_repository=repository,
    )
    assert scripted_claims.adaptive_efficiency_claim_authorized is False

    environment = build_recovery_qualification_environment(
        manifest,
        repository_clean=True,
        dependency_lock_sha256=scripted_environment.dependency_lock_sha256,
        generated_at=scripted_environment.generated_at,
        execution_basis=RecoveryQualificationExecutionBasis.LIVE_VERTEX,
        provider_name="google-vertex-ai",
        provider_project="qualification-project",
        model_name="gemini-2.5-flash",
        reported_model_revision="gemini-2.5-flash-001",
        vertex_location="us-central1",
        python_version=scripted_environment.python_version,
        platform_name=scripted_environment.platform,
    )
    measured_usage = RecoveryQualificationModelUsage(
        status=RecoveryQualificationModelUsageStatus.MEASURED,
        provider_name="google-vertex-ai",
        model_name="gemini-2.5-flash",
        model_call_count=1,
        input_token_count=10,
        output_token_count=5,
        total_token_count=15,
        input_cost_nano_units_per_token=2,
        output_cost_nano_units_per_token=3,
        model_cost_nano_units=35,
        live_vertex_backed=True,
    )
    lanes = tuple(
        lane.model_copy(update={"model_usage": measured_usage})
        if lane.policy is RecoveryQualificationPolicy.ADAPTIVE
        else lane
        for lane in template.lane_results
    )
    results = RecoveryQualificationResults.model_validate(
        template.model_copy(
            update={
                "environment_sha256": canonical_sha256(environment),
                "lane_results": lanes,
            }
        ).model_dump(mode="python")
    )
    contention = RecoveryQualificationContention.model_validate(
        template_contention.model_copy(
            update={"results_sha256": canonical_sha256(results)}
        ).model_dump(mode="python")
    )
    comparison = compare_recovery_qualification(manifest, environment, results)
    claims = authorize_recovery_qualification_claims(
        manifest,
        environment,
        results,
        contention,
        comparison,
        source_repository=repository,
    )

    assert comparison.live_vertex_model_usage_measured is False
    assert claims.live_vertex_backed is False
    assert claims.model_usage_measured is False
    assert claims.adaptive_efficiency_claim_authorized is False


def test_efficiency_threshold_is_exact_but_unverified_evidence_is_denied() -> None:
    assert recovery_qualification_adaptive_threshold_met(2499) is False
    assert recovery_qualification_adaptive_threshold_met(2500) is True


def test_bundle_verification_binds_index_creation_time(tmp_path, monkeypatch) -> None:
    repository = _install_example_source(tmp_path, monkeypatch)
    manifest, environment, results, contention, comparison, claims, _index = (
        make_recovery_qualification_examples()
    )
    bundle = RecoveryQualificationBundle(
        manifest=manifest,
        environment=environment,
        results=results,
        contention=contention,
        comparison=comparison,
        claim_authorization=claims,
    )
    destination = tmp_path / "qualification"
    index = export_recovery_qualification_bundle(
        destination,
        bundle,
        source_repository=repository,
    )
    tampered_index = index.model_copy(
        update={"created_at": index.created_at + timedelta(seconds=1)}
    )
    (destination / "index.json").write_bytes(canonical_json_bytes(tampered_index))

    with pytest.raises(
        RecoveryQualificationError,
        match="bundle binding changed",
    ):
        verify_recovery_qualification_bundle(
            destination,
            source_repository=repository,
        )


def test_bundle_verification_remeasures_source(tmp_path, monkeypatch) -> None:
    repository = _install_example_source(tmp_path, monkeypatch)
    manifest, environment, results, contention, comparison, claims, _index = (
        make_recovery_qualification_examples()
    )
    bundle = RecoveryQualificationBundle(
        manifest=manifest,
        environment=environment,
        results=results,
        contention=contention,
        comparison=comparison,
        claim_authorization=claims,
    )
    destination = tmp_path / "qualification"
    export_recovery_qualification_bundle(
        destination,
        bundle,
        source_repository=repository,
    )
    monkeypatch.setattr(
        recovery_qualification_module,
        "_measured_recovery_qualification_source",
        lambda _repository: (
            repository,
            manifest.source_revision,
            "f" * 64,
            True,
            environment.dependency_lock_sha256,
        ),
    )

    with pytest.raises(RecoveryQualificationError, match="measured source"):
        verify_recovery_qualification_bundle(
            destination,
            source_repository=repository,
        )
