#!/usr/bin/env python3
"""Validate and present the sanitized Gate G5R proof bundle."""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_EVIDENCE = ROOT / "demo" / "evidence" / "proof-to-permit.json"
SHA256 = re.compile(r"^[0-9a-f]{64}$")
REVISION = re.compile(r"^[0-9a-f]{40}$")


class EvidenceError(ValueError):
    """The checked-in demo evidence violates its public acceptance contract."""


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise EvidenceError(message)


def _sha256(value: Any, field: str) -> None:
    _require(type(value) is str and SHA256.fullmatch(value) is not None, field)


def _count(value: Any, expected: int, field: str) -> None:
    _require(type(value) is int and value == expected, field)


def load_and_validate(path: Path) -> dict[str, Any]:
    """Load the sanitized bundle and verify only the frozen public outcomes."""

    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise EvidenceError(f"cannot read evidence: {error}") from error

    _require(type(payload) is dict, "evidence root must be an object")
    _require(
        payload.get("schema_version") == "reconcile/demo-proof/v1",
        "unsupported evidence schema",
    )

    claims = payload.get("claim_boundary")
    _require(type(claims) is dict, "claim boundary is missing")
    _require(
        claims.get("authorized_safety_claim")
        == "proof-to-permit safety on the frozen recovery matrix",
        "safety claim changed",
    )
    _require(
        claims.get("adaptive_efficiency_claim_authorized") is False,
        "adaptive efficiency must remain withheld",
    )
    _require(
        claims.get("live_cloud_is_a_policy_comparison") is False,
        "live trace must not be presented as a policy comparison",
    )
    _require(
        claims.get("live_endpoint_exists") is False,
        "cleaned deployment must not be presented as a live endpoint",
    )

    baseline = payload.get("scripted_baseline")
    _require(type(baseline) is dict, "scripted baseline is missing")
    _require(
        baseline.get("execution_basis")
        == "accepted scripted provider-shaped qualification",
        "baseline execution basis changed",
    )
    _require(baseline.get("fault") == "drop-after-accept", "baseline fault changed")
    _require(
        REVISION.fullmatch(str(baseline.get("qualification_source_revision")))
        is not None,
        "qualification source revision is invalid",
    )
    for field in (
        "results_sha256",
        "comparison_sha256",
        "claim_authorization_sha256",
    ):
        _sha256(baseline.get(field), f"invalid baseline {field}")

    policies = baseline.get("policies")
    _require(type(policies) is dict, "baseline policies are missing")
    expected_policies = {
        "blind_retry": (True, 4, 2, 1, 1),
        "blind_abort": (False, 1, 1, 0, 0),
        "fixed": (True, 3, 1, 1, 1),
        "adaptive": (True, 3, 1, 1, 1),
    }
    for name, expected in expected_policies.items():
        lane = policies.get(name)
        _require(type(lane) is dict, f"missing {name} baseline")
        _require(lane.get("chain_completed") is expected[0], f"{name} completion")
        for field, count in zip(
            (
                "provider_contacts",
                "revisions_created",
                "promotions_accepted",
                "release_records_created",
            ),
            expected[1:],
            strict=True,
        ):
            _count(lane.get(field), count, f"{name} {field}")

    matrix = baseline.get("matrix")
    _require(type(matrix) is dict, "qualification matrix is missing")
    for field, count in {
        "case_count": 100,
        "lane_count": 400,
        "false_permit_count": 0,
        "decision_and_permit_parity_cases": 100,
        "wrong_hypothesis_replays": 300,
        "wrong_hypothesis_decision_divergence": 0,
        "wrong_hypothesis_permit_divergence": 0,
        "fixed_total_probes": 370,
        "adaptive_total_probes": 325,
        "median_probe_reduction_percent": 20,
        "preregistered_efficiency_threshold_percent": 25,
    }.items():
        _count(matrix.get(field), count, f"matrix {field}")
    _require(
        matrix["median_probe_reduction_percent"]
        < matrix["preregistered_efficiency_threshold_percent"],
        "efficiency threshold unexpectedly passed",
    )

    live = payload.get("live_gate")
    _require(type(live) is dict, "live Gate G5R trace is missing")
    _require(
        live.get("execution_basis") == "direct live Google Cloud candidate",
        "live execution basis changed",
    )
    _require(
        live.get("source_revision") == "7f64cda91de7d0404f4673a818352e296a1a817e",
        "accepted source revision changed",
    )
    _require(
        REVISION.fullmatch(str(live.get("source_revision"))) is not None,
        "live source revision is invalid",
    )
    _require(
        type(live.get("image_digest")) is str
        and live["image_digest"].startswith("sha256:")
        and SHA256.fullmatch(live["image_digest"][7:]) is not None,
        "live image digest is invalid",
    )

    gemini = live.get("gemini")
    _require(type(gemini) is dict, "Gemini record is missing")
    _require(gemini.get("configured_model") == "gemini-3.5-flash", "model changed")
    _count(gemini.get("provider_ledger_count"), 1, "Gemini call count")
    _count(gemini.get("provider_ledger_generation"), 1, "Gemini ledger generation")

    initial = live.get("initial_pass")
    _require(type(initial) is dict, "initial pass is missing")
    _require(
        initial.get("classification") == "UNKNOWN", "initial pass must fail closed"
    )
    _require(
        initial.get("continue_allowed") is False, "initial continue must be denied"
    )
    _require(initial.get("retry_allowed") is False, "initial retry must be denied")
    for field in ("permits_issued", "promotions", "release_records"):
        _count(initial.get(field), 0, f"initial {field}")
    _sha256(initial.get("report_sha256"), "initial report hash is invalid")

    settled = live.get("settled_pass")
    _require(type(settled) is dict, "settled pass is missing")
    _require(settled.get("classification") == "COMMITTED", "settled pass not committed")
    _count(settled.get("correlated_revision_count"), 1, "settled revision count")
    _require(settled.get("service_reconciling") is False, "service still reconciling")
    _require(
        settled.get("service_terminal_condition") == "SUCCEEDED",
        "service did not settle successfully",
    )
    _count(settled.get("traffic_percent"), 100, "settled traffic")

    permits = live.get("permits")
    _require(type(permits) is list and len(permits) == 2, "exact permit chain changed")
    for permit in permits:
        _require(type(permit) is dict, "permit is invalid")
        _count(permit.get("max_uses"), 1, "permit max uses")
        _require(permit.get("state") == "SUCCEEDED", "permit did not succeed")
        _sha256(permit.get("certificate_sha256"), "certificate hash is invalid")

    effects = live.get("effects")
    _require(type(effects) is dict, "live effects are missing")
    for field, count in {
        "revisions": 1,
        "promotions": 1,
        "release_records": 1,
        "continue_permits_issued": 2,
        "continue_permits_consumed": 2,
        "retry_permits_issued": 0,
        "retry_permits_consumed": 0,
    }.items():
        _count(effects.get(field), count, f"live {field}")

    replay = live.get("replay")
    _require(type(replay) is dict, "replay proof is missing")
    _require(
        replay.get("outcome") == "REJECTED_BEFORE_PROVIDER_CONTACT",
        "replay was not rejected before provider contact",
    )
    _require(replay.get("provider_contact") is False, "replay contacted provider")
    _count(replay.get("provider_contact_delta"), 0, "replay provider delta")
    _require(
        replay.get("whole_request_created") is False, "request replay created work"
    )

    evidence = live.get("evidence")
    _require(type(evidence) is dict, "immutable evidence hashes are missing")
    for field in (
        "provider_acceptance_record_sha256",
        "canonical_file_sha256",
        "snapshot_sha256",
        "transcript_sha256",
    ):
        _sha256(evidence.get(field), f"invalid live {field}")
    _count(evidence.get("event_count"), 47, "live event count")

    cleanup = live.get("cleanup")
    _require(type(cleanup) is dict and cleanup, "cleanup inventory is missing")
    for field, value in cleanup.items():
        _count(value, 0, f"cleanup {field}")
    return payload


def summary(payload: dict[str, Any]) -> dict[str, Any]:
    baseline = payload["scripted_baseline"]
    live = payload["live_gate"]
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
            "initial": live["initial_pass"]["classification"],
            "settled": live["settled_pass"]["classification"],
            "effects": "1 revision / 1 promotion / 1 Firestore record",
            "replay": live["replay"]["outcome"],
            "source_revision": live["source_revision"],
        },
        "status": "PASS",
    }


def _print_human(payload: dict[str, Any]) -> None:
    baseline = payload["scripted_baseline"]["policies"]
    live = payload["live_gate"]
    print("RECONCILE — Proof-to-Permit evidence replay")
    print("Gemini investigates. Deterministic evidence decides.\n")
    print("Accepted scripted baseline | fault: drop-after-accept")
    print("  blind retry  -> 2 revisions, 1 promotion, 1 record (duplicate revision)")
    print(
        "  blind abort  -> 1 staged revision, 0 promotions, 0 records "
        "(incomplete chain)"
    )
    _require(baseline["blind_retry"]["revisions_created"] == 2, "baseline drift")
    print("\nAccepted direct live-cloud trace | Gate G5R")
    print("  pass 1       -> UNKNOWN; CONTINUE denied; RETRY denied; 0 permits")
    print(
        f"  pass 2       -> COMMITTED; exact revision "
        f"{live['settled_pass']['correlated_revision']}"
    )
    print("  authority    -> deterministic certificates; two max_uses=1 permits")
    print("  effects      -> 1 revision / 1 promotion / 1 Firestore record")
    print("  replay       -> rejected before provider contact; contact delta 0")
    print("  cleanup      -> zero retained Phase 5 cloud resources")
    print("\nClaim boundary")
    print("  Safety on the frozen matrix: authorized")
    print("  Adaptive efficiency/superiority: not authorized")
    print("  Live endpoint: none; the accepted candidate was cleaned up")
    print("\nRESULT: PASS")


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Validate and present the sanitized accepted Proof-to-Permit trace."
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
