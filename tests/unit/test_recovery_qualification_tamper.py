"""Focused tamper checks for recovery qualification claim evidence."""

from __future__ import annotations

from datetime import timedelta

import pytest

from reconcile.contracts import ContractError, canonical_json_bytes, canonical_sha256
from reconcile.recovery_qualification import (
    RecoveryQualificationBundle,
    RecoveryQualificationError,
    authorize_recovery_qualification_claims,
    compare_recovery_qualification,
    export_recovery_qualification_bundle,
    verify_recovery_qualification_bundle,
)
from tests.contract._factories import make_recovery_qualification_examples


def _replace_tuple_item(values, index, replacement):
    updated = list(values)
    updated[index] = replacement
    return tuple(updated)


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
    ("claimed_at", "receipt_identity"),
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
            update={"claimed_at": trial.final_permit.claimed_at + timedelta(seconds=1)}
        )
        tampered_trial = trial.model_copy(
            update={
                "final_permit": tampered_permit,
                "final_permit_sha256": canonical_sha256(tampered_permit),
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

    with pytest.raises(
        RecoveryQualificationError,
        match="contention trial contradicts the protocol",
    ):
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
