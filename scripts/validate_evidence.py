#!/usr/bin/env python3
"""Validate and present a versioned sanitized evidence bundle."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from datetime import datetime
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
DEFAULT_EVIDENCE = ROOT / "evidence" / "v0.2.0" / "proof-to-permit.json"

SOURCE_REVISION = "4d626bb67739ca51c7569124724ea5d7ac8f5c0e"
IMAGE_DIGEST = "sha256:160471416779de06923cf5addb622206c3a5281b1858a2e2a111077218a423ef"
CANDIDATE_SHA256 = "297dbd7b5fe72db91e45ff06d1200313ca4ab448ffa57b26ac6a30d8762638fa"
RUN_ID = "p5r-adaptive-b166ba368d1cbc3e9ab57dee61b3dd74"
PROVIDER_PROJECTION_SHA256 = (
    "27118dde742d01eadb93778996964f55702ccc12238f6fb5795542f4ca31e480"
)
LIVE_CORROBORATION_SHA256 = (
    "408525043d82b0ee69404038e90358d82c7a531d35cbcfc169729ac5791fbcc9"
)
CLEANUP_VERIFICATION_SHA256 = (
    "34c4bd615f99b650baeca3e91736759c135c0fc172d1753ac1513d58afd71bcc"
)
LIVE_CAPTURED_AT = "2026-08-28T17:18:31Z"
CLEANUP_CAPTURED_AT = "2026-08-28T17:28:09Z"
EVENT_COUNT = 49
MODEL = "gemini-3.5-flash"

SHA256 = re.compile(r"^[0-9a-f]{64}$")
REVISION = re.compile(r"^[0-9a-f]{40}$")
RUN_IDENTIFIER = re.compile(r"^p5r-adaptive-[0-9a-f]{32}$")
HYPOTHESIS_IDENTIFIER = re.compile(r"^hypothesis-[0-9a-f]{32}$")
RELEASE_REVISION = re.compile(r"^reconcile-p5-canary-r-[0-9a-f]{16}$")
BASELINE_REVISION = re.compile(r"^reconcile-p5-canary-b-[0-9a-f]{16}$")
RFC3339_UTC = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")


class EvidenceError(ValueError):
    """The checked-in evidence violates its public acceptance contract."""


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise EvidenceError(message)


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise EvidenceError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _reject_nonfinite(value: str) -> None:
    raise EvidenceError(f"non-standard JSON number: {value}")


def _read_json(path: Path) -> tuple[dict[str, Any], bytes]:
    try:
        raw = path.read_bytes()
    except OSError as error:
        raise EvidenceError(f"cannot read {path.name}: {error}") from error

    _require(
        not raw.startswith(b"\xef\xbb\xbf"), f"{path.name}: UTF-8 BOM is forbidden"
    )
    try:
        text = raw.decode("utf-8", errors="strict")
        payload = json.loads(
            text,
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=_reject_nonfinite,
        )
    except (UnicodeDecodeError, json.JSONDecodeError, EvidenceError) as error:
        raise EvidenceError(f"{path.name}: invalid strict JSON: {error}") from error
    _require(type(payload) is dict, f"{path.name}: root must be an object")
    return payload, raw


def _object(value: Any, keys: set[str], label: str) -> dict[str, Any]:
    _require(type(value) is dict, f"{label} must be an object")
    actual = set(value)
    _require(
        actual == keys,
        f"{label} fields changed; missing={sorted(keys - actual)}, "
        f"unexpected={sorted(actual - keys)}",
    )
    return value


def _exact_values(value: Any, expected: dict[str, Any], label: str) -> dict[str, Any]:
    actual = _object(value, set(expected), label)
    for key, expected_value in expected.items():
        actual_value = actual[key]
        _require(
            type(actual_value) is type(expected_value)
            and actual_value == expected_value,
            f"{label}.{key} changed",
        )
    return actual


def _sha256(value: Any, label: str) -> None:
    _require(type(value) is str and SHA256.fullmatch(value) is not None, label)


def _timestamp(value: Any, label: str) -> datetime:
    _require(type(value) is str and RFC3339_UTC.fullmatch(value) is not None, label)
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as error:
        raise EvidenceError(label) from error


def _validate_claims(payload: dict[str, Any]) -> None:
    _exact_values(
        payload,
        {
            "adaptive_efficiency_claim_authorized": False,
            "authorized_safety_claim": (
                "proof-to-permit safety on the frozen recovery matrix"
            ),
            "live_cloud_is_a_policy_comparison": False,
            "live_endpoint_exists": False,
        },
        "claim boundary",
    )


def _validate_baseline(payload: dict[str, Any]) -> None:
    baseline = _object(
        payload,
        {
            "execution_basis",
            "fault",
            "qualification_source_revision",
            "results_sha256",
            "comparison_sha256",
            "claim_authorization_sha256",
            "representative_case",
            "policies",
            "matrix",
        },
        "scripted baseline",
    )
    _exact_values(
        {key: baseline[key] for key in baseline if key not in {"policies", "matrix"}},
        {
            "execution_basis": "accepted scripted provider-shaped qualification",
            "fault": "drop-after-accept",
            "qualification_source_revision": (
                "e9e83e077a333c460c0755a25754c9aa23a7d79a"
            ),
            "results_sha256": (
                "8334e278ac5f29d307c416cd3762908573ccb746c7918b20ebe11808edff9b7b"
            ),
            "comparison_sha256": (
                "3c4fcc53adabd4f2101be23b8ce0eca2b09b60ba735a0e584bc8eb13cac4f322"
            ),
            "claim_authorization_sha256": (
                "4e76c4e4013a479275c12b6d33e51120475533fd8d1e21fe7a5536c8343f3541"
            ),
            "representative_case": "rq-01-stage-drop-committed-104729",
        },
        "scripted baseline metadata",
    )

    policies = _object(
        baseline["policies"],
        {"blind_retry", "blind_abort", "fixed", "adaptive"},
        "scripted baseline policies",
    )
    expected_policies = {
        "blind_retry": (True, 4, 2, 1, 1),
        "blind_abort": (False, 1, 1, 0, 0),
        "fixed": (True, 3, 1, 1, 1),
        "adaptive": (True, 3, 1, 1, 1),
    }
    for name, values in expected_policies.items():
        _exact_values(
            policies[name],
            {
                "chain_completed": values[0],
                "provider_contacts": values[1],
                "revisions_created": values[2],
                "promotions_accepted": values[3],
                "release_records_created": values[4],
            },
            f"scripted baseline policy {name}",
        )

    matrix = _exact_values(
        baseline["matrix"],
        {
            "case_count": 100,
            "lane_count": 400,
            "false_permit_count": 0,
            "decision_and_permit_parity_cases": 100,
            "wrong_hypothesis_replays": 300,
            "wrong_hypothesis_decision_divergence": 0,
            "wrong_hypothesis_permit_divergence": 0,
            "fixed_total_probes": 370,
            "adaptive_total_probes": 325,
            "fixed_median_probes": 2.5,
            "adaptive_median_probes": 2.0,
            "median_probe_reduction_percent": 20,
            "preregistered_efficiency_threshold_percent": 25,
        },
        "scripted baseline matrix",
    )
    _require(
        matrix["median_probe_reduction_percent"]
        < matrix["preregistered_efficiency_threshold_percent"],
        "adaptive efficiency threshold unexpectedly passed",
    )


def _validate_provider(payload: dict[str, Any]) -> None:
    provider = _object(
        payload,
        {
            "acceptance",
            "candidate",
            "effects",
            "gemini",
            "initial_pass",
            "permits",
            "replay",
            "reset",
            "run_id",
            "schema_version",
            "settled_pass",
            "status",
        },
        "provider evidence record",
    )
    _require(
        provider["schema_version"] == "reconcile/provider-proof/v1",
        "provider evidence record schema changed",
    )
    _require(
        provider["status"] == "PASS",
        "provider evidence record status is not PASS",
    )
    _require(provider["run_id"] == RUN_ID, "provider run ID changed")
    _require(RUN_IDENTIFIER.fullmatch(provider["run_id"]) is not None, "invalid run ID")

    acceptance = _exact_values(
        provider["acceptance"],
        {
            "event_count": EVENT_COUNT,
            "events_sha256": (
                "c41b6b5701e50e46867d87c7d6993595797b92bf2316517347f770189aaf39ec"
            ),
            "provider_file_sha256": (
                "c46bba695d6ea11b91af1605cbdcaaacefed4bc317229563a26ebd7c21c82b87"
            ),
            "provider_record_sha256": (
                "5ccd883dde676a9ee049e14200fcfeabfd1f5d1fd6fbea94141fe68ced71983c"
            ),
            "snapshot_reread_stable": True,
            "snapshot_sha256": (
                "929f2d6175ac079080c4bf10369e291a43f7c3afe3f3d0d52e43faf3f4ef397b"
            ),
        },
        "provider acceptance",
    )
    for key in (
        "events_sha256",
        "provider_file_sha256",
        "provider_record_sha256",
        "snapshot_sha256",
    ):
        _sha256(acceptance[key], f"provider acceptance.{key} is not SHA-256")

    candidate = _exact_values(
        provider["candidate"],
        {
            "candidate_sha256": CANDIDATE_SHA256,
            "image_digest": IMAGE_DIGEST,
            "source_revision": SOURCE_REVISION,
        },
        "provider candidate",
    )
    _require(
        REVISION.fullmatch(candidate["source_revision"]) is not None,
        "provider source revision is invalid",
    )
    _sha256(candidate["candidate_sha256"], "provider candidate hash is invalid")
    _require(
        candidate["image_digest"].startswith("sha256:")
        and SHA256.fullmatch(candidate["image_digest"][7:]) is not None,
        "provider image digest is invalid",
    )

    effects = _exact_values(
        provider["effects"],
        {
            "continue_permits_consumed": 2,
            "continue_permits_issued": 2,
            "promotions": 1,
            "release_records": 1,
            "retry_permits_consumed": 0,
            "retry_permits_issued": 0,
            "revisions": 1,
        },
        "provider effects",
    )
    gemini = _exact_values(
        provider["gemini"],
        {
            "bound_to_hypothesis": True,
            "configured_model": MODEL,
            "count_attempts": 1,
            "generation_attempts": 1,
            "hypothesis_count": 1,
            "hypothesis_id": "hypothesis-e61163ea829f43d1593b6a9df2454f7c",
            "ledger_revision": 4,
            "ledger_state": "finalized",
            "planner_outcome": "planner-succeeded",
            "provider_ledger_absent_before": True,
            "reported_model": MODEL,
        },
        "provider Gemini evidence",
    )
    _require(
        HYPOTHESIS_IDENTIFIER.fullmatch(gemini["hypothesis_id"]) is not None,
        "provider hypothesis ID is invalid",
    )

    initial = _exact_values(
        provider["initial_pass"],
        {
            "acknowledgement_lost": True,
            "action_permits_issued": 0,
            "classification": "UNKNOWN",
            "continue_allowed": False,
            "continue_denial": "insufficient_authoritative_evidence",
            "dispatch_outcome": "OUTCOME_UNKNOWN",
            "report_sha256": (
                "623428317e4d8fb9c64b6e023be85861d6a7df68917853c06168b33e87826fb2"
            ),
            "retry_allowed": False,
            "retry_denial": "ambiguous_duplicate_risk",
        },
        "provider initial pass",
    )
    _sha256(initial["report_sha256"], "provider initial report hash is invalid")

    permits = provider["permits"]
    _require(type(permits) is list and len(permits) == 2, "permit chain changed")
    expected_permits = (
        {
            "certificate_sha256": (
                "4a009e5d75a2663615fb96c8e7913232604a5fb829626546a8e01809983fb1c2"
            ),
            "classification": "COMMITTED",
            "completion_outcome": "SUCCEEDED",
            "max_uses": 1,
            "state": "COMPLETED",
            "transition": "stage-to-promote",
        },
        {
            "certificate_sha256": (
                "0e229bd29c975e770a566fc8ddeeaa76fa3080f1f3e910478504b5df88406b83"
            ),
            "classification": "COMMITTED",
            "completion_outcome": "SUCCEEDED",
            "max_uses": 1,
            "state": "COMPLETED",
            "transition": "promote-to-record",
        },
    )
    for index, expected in enumerate(expected_permits):
        permit = _exact_values(permits[index], expected, f"provider permit {index + 1}")
        _sha256(permit["certificate_sha256"], "permit certificate hash is invalid")

    replay = _exact_values(
        provider["replay"],
        {
            "outcome": "REJECTED_BEFORE_PROVIDER_CONTACT",
            "provider_contact": False,
            "provider_contact_delta": 0,
            "snapshot_unchanged": True,
            "whole_request_created": False,
        },
        "provider replay",
    )
    reset = _exact_values(
        provider["reset"],
        {
            "baseline_revision": "reconcile-p5-canary-b-be77779d39439565",
            "release_record_absent": True,
            "release_revisions_after": ["reconcile-p5-canary-r-4a955e5169d2b921"],
            "release_revisions_before": ["reconcile-p5-canary-r-4a955e5169d2b921"],
            "reset_operation_sha256": (
                "e97b746d9b6d95284309e71477aee9d53f395c6405c61e9f99828afcdfa83849"
            ),
            "serving_percent": 100,
            "serving_revision": "reconcile-p5-canary-b-be77779d39439565",
        },
        "provider reset",
    )
    _sha256(reset["reset_operation_sha256"], "reset operation hash is invalid")
    _require(
        BASELINE_REVISION.fullmatch(reset["baseline_revision"]) is not None,
        "reset baseline revision is invalid",
    )
    _require(
        reset["serving_revision"] == reset["baseline_revision"],
        "reset did not restore the baseline revision",
    )

    settled = _exact_values(
        provider["settled_pass"],
        {
            "classification": "COMMITTED",
            "correlated_revision": "reconcile-p5-canary-r-4a955e5169d2b921",
            "correlated_revision_count": 1,
            "report_sha256": (
                "8ab3424685103abbe61529a1e5c08eb245378386a31a489ba05d7412c0f8f1cb"
            ),
            "serving_revision": "reconcile-p5-canary-r-4a955e5169d2b921",
            "traffic_percent": 100,
        },
        "provider settled pass",
    )
    _sha256(settled["report_sha256"], "provider settled report hash is invalid")
    _require(
        RELEASE_REVISION.fullmatch(settled["correlated_revision"]) is not None,
        "settled release revision is invalid",
    )
    _require(
        settled["correlated_revision"] == settled["serving_revision"],
        "settled correlated and serving revisions differ",
    )
    expected_revisions = [settled["correlated_revision"]]
    _require(
        reset["release_revisions_before"] == expected_revisions
        and reset["release_revisions_after"] == expected_revisions,
        "reset release-revision inventory changed",
    )
    _require(
        effects["continue_permits_issued"]
        == effects["continue_permits_consumed"]
        == len(permits),
        "permit issue/consume counts are incoherent",
    )
    _require(
        effects["revisions"] == settled["correlated_revision_count"]
        and effects["promotions"] == 1
        and effects["release_records"] == 1,
        "provider effect counts are incoherent",
    )
    _require(
        replay["provider_contact_delta"] == 0 and replay["snapshot_unchanged"],
        "replay invariants changed",
    )


def _validate_corroboration(
    payload: dict[str, Any], provider: dict[str, Any], provider_raw: bytes
) -> datetime:
    live = _object(
        payload,
        {
            "schema_version",
            "captured_at",
            "status",
            "source_revision",
            "run_id",
            "provider_acceptance_evidence_sha256",
            "provider_projection_sha256",
            "cloud_run",
            "firestore",
            "gemini",
        },
        "live corroboration",
    )
    _require(
        live["schema_version"] == "reconcile/live-corroboration/v1",
        "live corroboration schema changed",
    )
    _require(live["status"] == "PASS", "live corroboration status is not PASS")
    captured_at = _timestamp(live["captured_at"], "invalid live capture timestamp")
    _require(live["captured_at"] == LIVE_CAPTURED_AT, "live capture time changed")
    _require(live["source_revision"] == SOURCE_REVISION, "live source changed")
    _require(live["run_id"] == RUN_ID, "live run ID changed")
    _require(
        live["provider_acceptance_evidence_sha256"]
        == "313dcf99995138fcba9764c2a91814add929cc6c2c7b02ce7b72c27047ab20a4",
        "provider acceptance evidence hash changed",
    )
    projection_sha256 = hashlib.sha256(provider_raw).hexdigest()
    _require(
        projection_sha256 == PROVIDER_PROJECTION_SHA256,
        "provider-proof.json exact-byte digest changed",
    )
    _require(
        live["provider_projection_sha256"] == projection_sha256,
        "live corroboration does not hash the checked-in provider projection bytes",
    )

    _exact_values(
        live["cloud_run"],
        {
            "service_count": 5,
            "ready_count": 5,
            "revision_bound_count": 5,
            "log_entry_count": 143,
            "run_correlated_log_entry_count": 11,
            "log_service_stream_count": 6,
            "log_revision_stream_count": 7,
        },
        "live Cloud Run corroboration",
    )
    firestore = _exact_values(
        live["firestore"],
        {
            "native_database_count": 3,
            "durable_recovery_snapshot_reread": True,
            "durable_recovery_event_count": EVENT_COUNT,
        },
        "live Firestore corroboration",
    )
    _require(
        firestore["durable_recovery_event_count"]
        == provider["acceptance"]["event_count"],
        "provider and Firestore event counts differ",
    )

    live_gemini = _exact_values(
        live["gemini"],
        {
            "configured_model": MODEL,
            "reported_model": MODEL,
            "count_attempts": 1,
            "generation_attempts": 1,
            "planner_outcome": "planner-succeeded",
        },
        "live Gemini corroboration",
    )
    for key in live_gemini:
        _require(
            live_gemini[key] == provider["gemini"][key],
            f"provider and live Gemini {key} differ",
        )
    return captured_at


def _validate_cleanup(
    payload: dict[str, Any],
    live_captured_at: datetime,
    live_raw: bytes,
) -> None:
    cleanup = _object(
        payload,
        {
            "schema_version",
            "captured_at",
            "status",
            "source_revision",
            "run_id",
            "provider_projection_sha256",
            "live_corroboration_sha256",
            "teardown_evidence",
            "inventory",
            "service_account_audit",
        },
        "cleanup verification",
    )
    _require(
        cleanup["schema_version"] == "reconcile/cleanup-verification/v1",
        "cleanup verification schema changed",
    )
    _require(cleanup["status"] == "PASS", "cleanup verification status is not PASS")
    cleanup_captured_at = _timestamp(
        cleanup["captured_at"], "invalid cleanup capture timestamp"
    )
    _require(
        cleanup["captured_at"] == CLEANUP_CAPTURED_AT,
        "cleanup capture time changed",
    )
    _require(
        cleanup_captured_at > live_captured_at,
        "cleanup verification must follow live corroboration",
    )
    _require(cleanup["source_revision"] == SOURCE_REVISION, "cleanup source changed")
    _require(cleanup["run_id"] == RUN_ID, "cleanup run ID changed")
    _require(
        cleanup["provider_projection_sha256"] == PROVIDER_PROJECTION_SHA256,
        "cleanup does not bind the provider projection",
    )
    _require(
        hashlib.sha256(live_raw).hexdigest() == LIVE_CORROBORATION_SHA256,
        "live-corroboration.json exact-byte digest changed",
    )
    _require(
        cleanup["live_corroboration_sha256"] == LIVE_CORROBORATION_SHA256,
        "cleanup does not bind the live corroboration bytes",
    )

    teardown = _exact_values(
        cleanup["teardown_evidence"],
        {
            "runtime_sha256": (
                "04e7d549d19925f03e9eb22ac2b892a00766c4f495ec6d5b40ff814de993d810"
            ),
            "foundation_sha256": (
                "8c7dba1f646c64c19b5ecc41becd8f7a531768179a6aa1c1324483a4b050deb1"
            ),
            "state_protection_sha256": (
                "88b72d6497bf7b4da1759e3c068beba45e9cbf05b035d9d9a9595118ec518f27"
            ),
            "bootstrap_sha256": (
                "429f42331c07eab2559848e8f2c0082a8cc032fd2fa2ce18f6f5aa8dfe7814a6"
            ),
        },
        "cleanup teardown evidence",
    )
    for key, value in teardown.items():
        _sha256(value, f"cleanup teardown {key} is not SHA-256")

    inventory = _exact_values(
        cleanup["inventory"],
        {
            "cloud_run_services": 0,
            "cloud_run_jobs": 0,
            "artifact_repositories": 0,
            "firestore_databases": 0,
            "storage_buckets": 0,
            "phase5_named_service_accounts": 0,
            "custom_roles": 0,
            "phase5_project_iam_members": 0,
            "phase5_budgets": 0,
        },
        "cleanup inventory",
    )
    _require(all(value == 0 for value in inventory.values()), "cleanup is incomplete")

    audit = _exact_values(
        cleanup["service_account_audit"],
        {
            "created_during_run_window": 6,
            "deleted_without_error_during_run_window": 6,
            "remaining_default_compute_accounts": 1,
            "remaining_phase5_named_accounts": 0,
        },
        "cleanup service-account audit",
    )
    _require(
        audit["created_during_run_window"]
        == audit["deleted_without_error_during_run_window"],
        "created and deleted service-account counts differ",
    )


def load_and_validate(path: Path) -> dict[str, Any]:
    """Load and cross-check the four-file offline evidence bundle."""

    index, _ = _read_json(path)
    if index.get("schema_version") == "reconcile/public-evidence/v1":
        try:
            from reconcile.public_evidence import (
                PublicEvidenceError,
                load_public_evidence,
                public_bundle_dict,
            )
        except ImportError as error:
            raise EvidenceError("public evidence validator is unavailable") from error
        try:
            return public_bundle_dict(load_public_evidence(path.resolve()))
        except PublicEvidenceError as error:
            raise EvidenceError(error.code) from error
    _object(
        index,
        {"schema_version", "claim_boundary", "scripted_baseline", "live_gate"},
        "evidence index",
    )
    _require(
        index["schema_version"] == "reconcile/demo-proof/v2",
        "unsupported evidence index schema",
    )
    _validate_claims(index["claim_boundary"])
    _validate_baseline(index["scripted_baseline"])

    references = _exact_values(
        index["live_gate"],
        {
            "execution_basis": "direct live Google Cloud candidate",
            "provider_proof": "provider-proof.json",
            "provider_proof_sha256": PROVIDER_PROJECTION_SHA256,
            "live_corroboration": "live-corroboration.json",
            "live_corroboration_sha256": LIVE_CORROBORATION_SHA256,
            "cleanup_verification": "cleanup-verification.json",
            "cleanup_verification_sha256": CLEANUP_VERIFICATION_SHA256,
        },
        "live evidence references",
    )
    provider, provider_raw = _read_json(path.parent / references["provider_proof"])
    live, live_raw = _read_json(path.parent / references["live_corroboration"])
    cleanup, cleanup_raw = _read_json(path.parent / references["cleanup_verification"])

    for label, raw, expected in (
        (
            "provider evidence record",
            provider_raw,
            references["provider_proof_sha256"],
        ),
        ("live corroboration", live_raw, references["live_corroboration_sha256"]),
        (
            "cleanup verification",
            cleanup_raw,
            references["cleanup_verification_sha256"],
        ),
    ):
        _require(
            hashlib.sha256(raw).hexdigest() == expected,
            f"evidence index does not bind the {label} bytes",
        )

    _validate_provider(provider)
    live_captured_at = _validate_corroboration(live, provider, provider_raw)
    _validate_cleanup(cleanup, live_captured_at, live_raw)

    return {
        **index,
        "provider_proof": provider,
        "live_corroboration": live,
        "cleanup_verification": cleanup,
    }


def summary(payload: dict[str, Any]) -> dict[str, Any]:
    if payload["schema_version"] == "reconcile/public-evidence/v1":
        provider = payload["provider_proof"]
        adaptive = provider["adaptive_recovery"]
        ambiguity = payload["live_corroboration"]["ambiguity_proof"]
        return {
            "claim": payload["claim_boundary"]["authorized_safety_claim"],
            "live_gate": {
                "adaptive": {
                    "chain_completed": adaptive["chain_completed"],
                    "effects": adaptive["effects"],
                    "replay": adaptive["replay"],
                },
                "ambiguity": {
                    "classification": ambiguity["classification"],
                    "lifecycle": ambiguity["lifecycle"],
                    "histories": list(ambiguity["history_ids"]),
                    "effects": ambiguity["effects"],
                    "certificate_count": ambiguity["certificate_count"],
                    "action_permit_count": ambiguity["action_permit_count"],
                },
                "source_revision": provider["candidate"]["source_revision"],
            },
            "status": "PASS",
        }
    baseline = payload["scripted_baseline"]
    provider = payload["provider_proof"]
    return {
        "claim": payload["claim_boundary"]["authorized_safety_claim"],
        "scripted_baseline": {
            name: {
                "chain_completed": lane["chain_completed"],
                "revisions": lane["revisions_created"],
                "promotions": lane["promotions_accepted"],
                "records": lane["release_records_created"],
            }
            for name, lane in baseline["policies"].items()
        },
        "live_gate": {
            "event_count": provider["acceptance"]["event_count"],
            "initial": provider["initial_pass"]["classification"],
            "settled": provider["settled_pass"]["classification"],
            "effects": "1 revision / 1 promotion / 1 Firestore record",
            "replay": provider["replay"]["outcome"],
            "run_id": provider["run_id"],
            "source_revision": provider["candidate"]["source_revision"],
        },
        "status": "PASS",
    }


def _print_human(payload: dict[str, Any]) -> None:
    if payload["schema_version"] == "reconcile/public-evidence/v1":
        provider = payload["provider_proof"]
        adaptive = provider["adaptive_recovery"]
        ambiguity = payload["live_corroboration"]["ambiguity_proof"]
        print("Reconcile - offline evidence validation")
        print("Gemini investigates. Deterministic evidence decides.\n")
        print("Recorded adaptive recovery")
        print(
            "  effects      -> "
            f"{adaptive['effects']['revisions']} revision / "
            f"{adaptive['effects']['promotions']} promotion / "
            f"{adaptive['effects']['release_records']} release record"
        )
        print("  replay       -> rejected before provider contact; contact delta 0")
        print("\nRecorded partial-read outage")
        print("  result       -> UNKNOWN / ESCALATED; no action permit")
        print("  histories    -> " + " / ".join(ambiguity["history_ids"]))
        print("  effects      -> 1 staged revision / 0 promotions / 0 records")
        print("  cleanup      -> zero retained operational resources")
        print("\nRESULT: PASS")
        return
    baseline = payload["scripted_baseline"]["policies"]
    provider = payload["provider_proof"]
    print("Reconcile — offline evidence validation")
    print("Gemini investigates. Deterministic evidence decides.\n")
    print("Accepted scripted baseline | fault: drop-after-accept")
    print("  blind retry  -> 2 revisions, 1 promotion, 1 record (duplicate revision)")
    print(
        "  blind abort  -> 1 staged revision, 0 promotions, 0 records "
        "(incomplete chain)"
    )
    _require(baseline["blind_retry"]["revisions_created"] == 2, "baseline drift")
    print("\nRecorded direct live-cloud evidence")
    print(
        "  pass 1       -> UNKNOWN; CONTINUE denied; RETRY denied; "
        "0 recovery-action permits"
    )
    print(
        f"  pass 2       -> COMMITTED; exact revision "
        f"{provider['settled_pass']['correlated_revision']}"
    )
    print("  authority    -> hash-bound certificates; two max_uses=1 permits")
    print("  evidence     -> 49 durable events; provider/corroboration hashes linked")
    print("  effects      -> 1 revision / 1 promotion / 1 Firestore record")
    print("  replay       -> rejected before provider contact; contact delta 0")
    print("  cleanup      -> zero retained operational resources")
    print("\nClaim boundary")
    print("  Safety on the frozen matrix: authorized")
    print("  Adaptive efficiency/superiority: not authorized")
    print("  Live endpoint: none; the recorded environment was cleaned up")
    print("\nRESULT: PASS")


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Validate and present the sanitized offline evidence bundle."
    )
    parser.add_argument("--evidence", type=Path, default=DEFAULT_EVIDENCE)
    parser.add_argument("--json", action="store_true", help="emit the compact result")
    arguments = parser.parse_args()
    try:
        payload = load_and_validate(arguments.evidence.resolve())
    except EvidenceError as error:
        print(f"FAIL: {error}", file=sys.stderr)
        return 1
    if arguments.json:
        print(json.dumps(summary(payload), indent=2, sort_keys=True))
    else:
        _print_human(payload)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
