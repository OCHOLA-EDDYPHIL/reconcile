from __future__ import annotations

from copy import deepcopy
import json
import os
from pathlib import Path
import re
import shutil
import stat
import tempfile
import unittest

from lazarus.benchmark import HELDOUT_COVERAGE
from lazarus.compiler import compile_case
from lazarus.locking import canonical_json_bytes, canonical_sha256, file_sha256
from lazarus.recovery import run_recovery
from lazarus.suite import (
    ATTESTATION_SCHEMA_VERSION,
    CALIBRATION_INDEX_SCHEMA_VERSION,
    MANIFEST_NAME,
    SuiteError,
    aggregate_attestation,
    create_sealing_key,
    decrypt_oracles,
    generate_fresh_suite,
    seal_oracles,
    validate_calibration_index,
    validate_public_suite,
)


_FIXED_SEED = bytes(range(32))
_RESERVED = {
    "abstention_required",
    "acceptable_matches",
    "coverage",
    "decision_changing_blockers",
    "negative_control",
    "oracle_id",
    "recovery_expectation",
    "required_probe",
}


class FreshSuiteTests(unittest.TestCase):
    def test_requires_verified_calibration_index_and_unused_destination(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.assertEqual(
                validate_calibration_index(_calibration_index()),
                _calibration_index(),
            )
            with self.assertRaises(TypeError):
                generate_fresh_suite(
                    root / "suite",
                    calibration_complete=True,
                    seed=_FIXED_SEED,
                )
            failed = _calibration_index()
            failed["passed"] = False
            with self.assertRaisesRegex(SuiteError, "passing calibration"):
                generate_fresh_suite(
                    root / "failed",
                    calibration_index=failed,
                    seed=_FIXED_SEED,
                )
            tampered = _calibration_index()
            tampered["results"]["value"]["case_count"] = 5
            with self.assertRaisesRegex(SuiteError, "digest does not match"):
                generate_fresh_suite(
                    root / "tampered",
                    calibration_index=tampered,
                    seed=_FIXED_SEED,
                )
            wrong_algorithm = _calibration_index()
            wrong_algorithm["capture_index"]["algorithm"] = "sha512"
            with self.assertRaisesRegex(SuiteError, "algorithm is invalid"):
                validate_calibration_index(wrong_algorithm)
            contradictory_score = _calibration_index()
            contradictory_score["score"]["value"]["passed"] = False
            contradictory_score["score"]["digest"] = canonical_sha256(
                contradictory_score["score"]["value"]
            )
            with self.assertRaisesRegex(SuiteError, "score must record a passing"):
                validate_calibration_index(contradictory_score)
            (root / "existing").mkdir()
            with self.assertRaises(SuiteError):
                generate_fresh_suite(
                    root / "existing",
                    calibration_index=_calibration_index(),
                    seed=_FIXED_SEED,
                )
            with self.assertRaises(SuiteError):
                generate_fresh_suite(
                    root / "short-seed",
                    calibration_index=_calibration_index(),
                    seed=b"short",
                )

    def test_generates_public_manifest_and_aggregate_attestation_only(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            result = generate_fresh_suite(
                Path(temporary) / "suite",
                calibration_index=_calibration_index(),
                seed=_FIXED_SEED,
            )
            self.assertEqual(
                validate_public_suite(
                    result.root,
                    calibration_index=_calibration_index(),
                ),
                result.manifest,
            )
            self.assertEqual(
                result.manifest["calibration_index_sha256"],
                canonical_sha256(_calibration_index()),
            )
            other_calibration = _calibration_index()
            other_calibration["score"]["value"]["score_digest"] = "e" * 64
            other_calibration["score"]["digest"] = canonical_sha256(
                other_calibration["score"]["value"]
            )
            with self.assertRaisesRegex(SuiteError, "commitment does not match"):
                validate_public_suite(
                    result.root,
                    calibration_index=other_calibration,
                )
            self.assertEqual(
                result.attestation,
                {
                    "schema_version": ATTESTATION_SCHEMA_VERSION,
                    "case_count": 12,
                    "blocker_case_count": 8,
                    "negative_control_count": 4,
                    "registered_coverage_count": 12,
                    "one_to_one_coverage": True,
                    "no_reserved_field_leakage": True,
                },
            )
            case_ids = result.manifest["case_ids"]
            self.assertEqual(case_ids, sorted(case_ids))
            self.assertEqual(len(case_ids), 12)
            self.assertEqual(len(case_ids), len(set(case_ids)))
            self.assertTrue(
                all(re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]*", item) for item in case_ids)
            )
            self.assertEqual(set(result.oracles), set(case_ids))
            self.assertEqual(
                {oracle["coverage"][0] for oracle in result.oracles.values()},
                set(HELDOUT_COVERAGE),
            )
            self.assertEqual(
                sum(oracle["negative_control"] for oracle in result.oracles.values()),
                4,
            )
            self.assertTrue(
                all(len(digest) == 64 for digest in result.manifest["files"].values())
            )
            self.assertFalse(
                any(
                    "oracle" in {part.casefold() for part in Path(relative).parts}
                    for relative in result.manifest["files"]
                )
            )
            self.assertFalse(any((result.root / "heldout").glob("*/oracle")))
            self.assertFalse(_reserved_keys(result.manifest))
            for path in result.root.rglob("*.json"):
                value = json.loads(path.read_text(encoding="utf-8"))
                self.assertFalse(_reserved_keys(value), path)
            representation = repr(result)
            self.assertNotIn("direct_destructive_target", representation)
            self.assertNotIn("decision_changing_blockers", representation)

    def test_fixed_seed_is_reproducible_and_fresh_seed_changes_identity(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            first = generate_fresh_suite(
                root / "first",
                calibration_index=_calibration_index(),
                seed=_FIXED_SEED,
            )
            second = generate_fresh_suite(
                root / "second",
                calibration_index=_calibration_index(),
                seed=_FIXED_SEED,
            )
            different = generate_fresh_suite(
                root / "different",
                calibration_index=_calibration_index(),
                seed=b"different-fixed-test-seed-value!",
            )
            self.assertEqual(first.manifest, second.manifest)
            self.assertEqual(first.oracles, second.oracles)
            self.assertNotEqual(
                first.manifest["suite_digest"], different.manifest["suite_digest"]
            )
            self.assertNotEqual(first.manifest["case_ids"], different.manifest["case_ids"])

    def test_generated_cases_compile_and_recovery_matches_custodied_oracles(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            result = generate_fresh_suite(
                Path(temporary) / "suite",
                calibration_index=_calibration_index(),
                seed=_FIXED_SEED,
            )
            semantic_scenarios = {"semantic_alias", "nuanced_intent"}
            for case_id, oracle in result.oracles.items():
                case_dir = result.root / "heldout" / case_id
                case = json.loads((case_dir / "case.json").read_text(encoding="utf-8"))
                recovery = run_recovery(case_dir, case["recovery"])
                actual_recovery = {
                    section: recovery[section]["status"]
                    for section in ("restore", "canary", "rpo", "rto", "cleanup")
                }
                self.assertEqual(actual_recovery, oracle["recovery_expectation"])

                packet = compile_case(case_dir, "a1", allow_heldout=True)
                codes = {blocker["code"] for blocker in packet["blockers"]}
                scenario = oracle["coverage"][0]
                if oracle["negative_control"]:
                    self.assertEqual(codes, set(), scenario)
                elif scenario in semantic_scenarios:
                    self.assertNotIn("SEMANTIC_CONFIRMATION_REQUIRED", codes)
                else:
                    expected = {
                        match
                        for blocker in oracle["decision_changing_blockers"]
                        for match in blocker["acceptable_matches"]
                        if isinstance(match, str)
                    }
                    self.assertTrue(expected.issubset(codes), (scenario, expected, codes))

    def test_public_validation_detects_digest_and_reserved_field_tampering(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            first = generate_fresh_suite(
                root / "digest",
                calibration_index=_calibration_index(),
                seed=_FIXED_SEED,
            )
            artifact = next(first.root.glob("heldout/*/inputs/plan.json"))
            artifact.write_bytes(artifact.read_bytes() + b" ")
            with self.assertRaisesRegex(SuiteError, "digest mismatch"):
                validate_public_suite(first.root)

            second = generate_fresh_suite(
                root / "reserved",
                calibration_index=_calibration_index(),
                seed=b"reserved-field-test-seed-value!",
            )
            artifact = next(second.root.glob("heldout/*/inputs/plan.json"))
            value = json.loads(artifact.read_text(encoding="utf-8"))
            value["coverage"] = ["must-not-be-public"]
            artifact.write_bytes(canonical_json_bytes(value) + b"\n")
            manifest_path = second.root / MANIFEST_NAME
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            relative = artifact.relative_to(second.root).as_posix()
            manifest["files"][relative] = file_sha256(artifact)
            core = {key: item for key, item in manifest.items() if key != "suite_digest"}
            manifest["suite_digest"] = canonical_sha256(core)
            manifest_path.write_bytes(canonical_json_bytes(manifest) + b"\n")
            with self.assertRaisesRegex(SuiteError, "reserved oracle fields"):
                validate_public_suite(second.root)

    def test_attestation_rejects_oracle_inventory_or_coverage_changes(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            result = generate_fresh_suite(
                Path(temporary) / "suite",
                calibration_index=_calibration_index(),
                seed=_FIXED_SEED,
            )
            missing = deepcopy(result.oracles)
            missing.pop(next(iter(missing)))
            with self.assertRaises(SuiteError):
                aggregate_attestation(
                    result.root,
                    missing,
                    calibration_index=_calibration_index(),
                )

            duplicate = deepcopy(result.oracles)
            identifiers = list(duplicate)
            duplicate[identifiers[0]]["coverage"] = list(
                duplicate[identifiers[1]]["coverage"]
            )
            with self.assertRaises(SuiteError):
                aggregate_attestation(
                    result.root,
                    duplicate,
                    calibration_index=_calibration_index(),
                )


@unittest.skipUnless(shutil.which("gpg"), "gpg is required for custody tests")
class OracleCustodyTests(unittest.TestCase):
    def test_aes256_round_trip_uses_mode_600_key_and_no_plaintext_file(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            result = generate_fresh_suite(
                root / "suite",
                calibration_index=_calibration_index(),
                seed=_FIXED_SEED,
            )
            key = create_sealing_key(root / "custody.key")
            self.assertEqual(stat.S_IMODE(key.stat().st_mode), 0o600)
            sealed = seal_oracles(result.oracles, key, root / "oracles.gpg")
            self.assertEqual(stat.S_IMODE(sealed.stat().st_mode), 0o600)
            ciphertext = sealed.read_bytes()
            self.assertNotIn(b"decision_changing_blockers", ciphertext)
            self.assertNotIn(b"direct_destructive_target", ciphertext)
            self.assertEqual(decrypt_oracles(sealed, key), result.oracles)
            self.assertFalse(any(root.rglob("oracle.json")))

    def test_rejects_wrong_key_insecure_key_mode_and_overwrite(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            result = generate_fresh_suite(
                root / "suite",
                calibration_index=_calibration_index(),
                seed=_FIXED_SEED,
            )
            key = create_sealing_key(root / "key")
            wrong_key = create_sealing_key(root / "wrong-key")
            sealed = seal_oracles(result.oracles, key, root / "oracles.gpg")
            with self.assertRaises(SuiteError):
                decrypt_oracles(sealed, wrong_key)
            with self.assertRaises(SuiteError):
                seal_oracles(result.oracles, key, sealed)

            os.chmod(key, 0o640)
            with self.assertRaisesRegex(SuiteError, "mode must be 600"):
                decrypt_oracles(sealed, key)


def _calibration_index() -> dict[str, object]:
    values = {
        "calibration_lock": {
            "schema_version": "lazarus.calibration-lock/v1",
            "lock_digest": "a" * 64,
        },
        "capture_index": {
            "schema_version": "lazarus.calibration-captures/v1",
            "case_count": 4,
            "completed": True,
            "index_digest": "b" * 64,
        },
        "results": {
            "schema_version": "lazarus.calibration-results/v1",
            "case_count": 4,
            "completed": True,
            "results_digest": "c" * 64,
        },
        "score": {
            "schema_version": "lazarus.calibration-score/v1",
            "passed": True,
            "score_digest": "d" * 64,
        },
    }
    return {
        "schema_version": CALIBRATION_INDEX_SCHEMA_VERSION,
        "passed": True,
        **{
            name: {
                "algorithm": "sha256",
                "digest": canonical_sha256(value),
                "value": value,
            }
            for name, value in values.items()
        },
    }


def _reserved_keys(value: object) -> set[str]:
    if isinstance(value, dict):
        found = set(value).intersection(_RESERVED)
        for item in value.values():
            found.update(_reserved_keys(item))
        return found
    if isinstance(value, list):
        found: set[str] = set()
        for item in value:
            found.update(_reserved_keys(item))
        return found
    return set()


if __name__ == "__main__":
    unittest.main()
