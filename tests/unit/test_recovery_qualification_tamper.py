"""Focused tamper checks for recovery qualification claim evidence."""

from __future__ import annotations

import asyncio
import hashlib
from datetime import timedelta

import pytest

import reconcile.recovery_qualification as recovery_qualification_module
from reconcile.contracts import (
    Classification,
    ContractError,
    canonical_json_bytes,
    canonical_sha256,
)
from reconcile.contracts.base import canonical_json_value_bytes
from reconcile.contracts.recovery_qualification import (
    RecoveryQualificationContention,
    RecoveryQualificationResults,
)
from reconcile.recovery_qualification import (
    RecoveryQualificationBundle,
    RecoveryQualificationError,
    authorize_recovery_qualification_claims,
    build_recovery_qualification_bundle,
    compare_recovery_qualification,
    export_recovery_qualification_bundle,
    verify_recovery_qualification_bundle,
)
from reconcile.recovery_qualification_execution import (
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

    async def fake_contention(manifest, results, *, working_directory=None):
        del working_directory
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


def test_evidence_semantics_are_strict_json_values() -> None:
    evidence, _decision = make_evidence(Classification.COMMITTED)
    semantics = _evidence_semantics(evidence)

    assert canonical_json_value_bytes(semantics)
    assert all(type(item) is dict for item in semantics["effect_assertions"])


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
def test_authorization_rejects_contention_identity_drift(mutation: str) -> None:
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
        )


def test_authorization_rejects_invalid_claimed_permit_revision() -> None:
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
    source_state = ("d" * 40, "e" * 64, True)
    monkeypatch.setattr(
        recovery_qualification_module,
        "recovery_qualification_source_state",
        lambda _repository: source_state,
    )

    first = asyncio.run(
        build_recovery_qualification_bundle(source_repository=repository)
    )
    second = asyncio.run(
        build_recovery_qualification_bundle(source_repository=repository)
    )

    assert first.manifest.source_revision == source_state[0]
    assert first.manifest.source_tree_sha256 == source_state[1]
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
            ("d" * 40, "e" * 64, True),
            ("d" * 40, "f" * 64, False),
        )
    )
    monkeypatch.setattr(
        recovery_qualification_module,
        "recovery_qualification_source_state",
        lambda _repository: next(states),
    )

    with pytest.raises(RecoveryQualificationError, match="source changed"):
        asyncio.run(build_recovery_qualification_bundle(source_repository=repository))


def test_authorization_recomputes_comparison_from_results() -> None:
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
        )


def test_bundle_verification_binds_index_creation_time(tmp_path) -> None:
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
    index = export_recovery_qualification_bundle(destination, bundle)
    tampered_index = index.model_copy(
        update={"created_at": index.created_at + timedelta(seconds=1)}
    )
    (destination / "index.json").write_bytes(canonical_json_bytes(tampered_index))

    with pytest.raises(
        RecoveryQualificationError,
        match="bundle binding changed",
    ):
        verify_recovery_qualification_bundle(destination)
