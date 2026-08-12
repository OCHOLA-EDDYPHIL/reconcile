from __future__ import annotations

from copy import deepcopy
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

from lazarus.execution import (
    ExecutionError,
    InventoryError,
    MODEL_ARMS,
    build_digest_chain_record,
    build_execution_plan,
    expected_execution_paths,
    sha256_bytes,
    sha256_json,
    validate_execution_inventory,
    validate_execution_plan,
    verify_digest_chain_record,
    write_immutable_bytes,
    write_score_receipt,
)
from lazarus.locking import (
    CALIBRATION_LOCK_SCHEMA_VERSION,
    CALIBRATION_LOCK_SECTIONS,
    LOCK_V2_SCHEMA_VERSION,
    LockVerificationError,
    LockingError,
    build_calibration_lock_manifest,
    build_lock_manifest_v2,
    canonical_sha256,
    validate_model_settings,
    verify_calibration_lock_manifest,
    verify_lock_manifest,
)


CASE_IDS = tuple(f"sealed-{index:02d}" for index in range(1, 13))
GEMINI_SETTINGS = {
    "provider": "gemini-developer-api",
    "api_version": "v1beta",
    "endpoint": (
        "https://generativelanguage.googleapis.com/v1beta/models/"
        "gemini-3.5-flash:generateContent"
    ),
    "model": "gemini-3.5-flash",
    "catalog_model_version": "3.5-flash-05-2026",
    "resolved_model_version": "gemini-3.5-flash",
    "parameters": {
        "temperature": 1.0,
        "top_p": 1.0,
        "max_output_tokens": 8192,
        "candidate_count": 1,
        "response_mime_type": "application/json",
        "response_schema_sha256": "b" * 64,
    },
    "thinking": {"level": "MEDIUM", "include_thoughts": False},
    "request": {
        "store": False,
        "service_tier": "standard",
        "timeout_seconds": 120,
        "safety_settings": "provider-default",
        "tools": [],
    },
    "retry": {"max_attempts": 1, "backoff_seconds": 0},
}


def _calibration_plan() -> dict:
    inputs = []
    for sequence in range(1, 5):
        case_id = f"cal-{sequence:02d}"
        execution_id = f"calibration-{sequence:03d}"
        base = f"calibration/{execution_id}"
        inputs.append(
            {
                "execution_id": execution_id,
                "sequence": sequence,
                "invocation_id": f"calibration-invocation-{sequence:03d}",
                "case_id": case_id,
                "arm": "b-replay",
                "run_id": "calibration",
                "input_path": f"calibration-inputs/{case_id}.json",
                "request_path": f"{base}/request.json",
                "raw_response_path": f"{base}/raw-response.json",
                "capture_path": f"{base}/capture.json",
            }
        )
    return {
        "schema_version": "lazarus.calibration-capture-plan/v1",
        "inputs": inputs,
    }


def _bound(value: dict) -> dict:
    return {
        "algorithm": "sha256",
        "digest": canonical_sha256(value),
        "value": deepcopy(value),
    }


def _calibration_index(calibration_lock: dict) -> dict:
    return {
        "schema_version": "lazarus.calibration-index/v2",
        "passed": True,
        "calibration_lock": _bound(calibration_lock),
        "capture_index": _bound({"schema_version": "capture-index/v1", "count": 4}),
        "results": _bound({"schema_version": "results/v1", "count": 4}),
        "score": _bound({"schema_version": "score/v1", "passed": True}),
    }


class ExecutionPlanTests(unittest.TestCase):
    def test_fixed_plan_has_registered_counts_and_cyclic_model_order(self) -> None:
        plan = build_execution_plan(CASE_IDS)
        self.assertEqual(validate_execution_plan(plan), plan)
        self.assertEqual(len(plan["prepared_inputs"]), 60)
        self.assertEqual(len(plan["evaluations"]), 204)
        self.assertEqual(len(plan["recovery"]), 120)

        deterministic = [
            entry for entry in plan["evaluations"] if entry["invocation_id"] is None
        ]
        model = [
            entry for entry in plan["evaluations"] if entry["invocation_id"] is not None
        ]
        self.assertEqual(len(deterministic), 24)
        self.assertEqual({entry["arm"] for entry in deterministic}, {"a1", "a1-rules"})
        self.assertNotIn("a0", {entry["arm"] for entry in plan["evaluations"]})
        self.assertEqual(len(model), 180)
        self.assertEqual(
            [entry["arm"] for entry in model[: len(MODEL_ARMS)]],
            list(MODEL_ARMS),
        )
        self.assertEqual(
            [entry["arm"] for entry in model[len(MODEL_ARMS) : 2 * len(MODEL_ARMS)]],
            [*MODEL_ARMS[1:], MODEL_ARMS[0]],
        )
        second_run = len(CASE_IDS) * len(MODEL_ARMS)
        self.assertEqual(
            [entry["arm"] for entry in model[second_run : second_run + len(MODEL_ARMS)]],
            [*MODEL_ARMS[1:], MODEL_ARMS[0]],
        )
        self.assertEqual(
            len({entry["execution_id"] for entry in plan["evaluations"]}),
            204,
        )
        self.assertEqual(len({entry["invocation_id"] for entry in model}), 180)
        self.assertTrue(
            all(
                sum(entry["state"] == state for entry in plan["recovery"]) == 20
                for state in {entry["state"] for entry in plan["recovery"]}
            )
        )

    def test_plan_rejects_reordering_and_case_count_changes(self) -> None:
        with self.assertRaises(ExecutionError):
            build_execution_plan(tuple(reversed(CASE_IDS)))
        changed = build_execution_plan(CASE_IDS)
        changed["evaluations"][24]["run_id"] = "selected-afterward"
        with self.assertRaises(ExecutionError):
            validate_execution_plan(changed)


class ImmutableArtifactTests(unittest.TestCase):
    def test_immutable_write_and_score_receipt_refuse_overwrite(self) -> None:
        plan = build_execution_plan(CASE_IDS)
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            artifact = root / "artifact.bin"
            write_immutable_bytes(artifact, b"first")
            with self.assertRaises(ExecutionError):
                write_immutable_bytes(artifact, b"second")
            self.assertEqual(artifact.read_bytes(), b"first")

            score = {"schema_version": "synthetic-score/v1", "technical_pass": False}
            write_score_receipt(
                root,
                plan,
                lock_digest="c" * 64,
                inventory_digest="d" * 64,
                score=score,
            )
            with self.assertRaises(ExecutionError):
                write_score_receipt(
                    root,
                    plan,
                    lock_digest="c" * 64,
                    inventory_digest="d" * 64,
                    score=score,
                )

    def test_digest_chain_binds_all_four_artifacts(self) -> None:
        plan = build_execution_plan(CASE_IDS)
        evaluation = next(
            entry for entry in plan["evaluations"] if entry["invocation_id"] is not None
        )
        payloads = {
            "request_path": b"request",
            "raw_response_path": b"response",
            "result_path": b"result",
        }
        payloads["capture_path"] = (
            json.dumps(
                {
                    "schema_version": "lazarus.model-capture/v2",
                    "request_sha256": sha256_bytes(payloads["request_path"]),
                    "raw_response_sha256": sha256_bytes(
                        payloads["raw_response_path"]
                    ),
                },
                separators=(",", ":"),
                sort_keys=True,
            ).encode("utf-8")
            + b"\n"
        )
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for field, payload in payloads.items():
                path = root / evaluation[field]
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(payload)
            record = build_digest_chain_record(
                evaluation,
                request_bytes=payloads["request_path"],
                raw_response_bytes=payloads["raw_response_path"],
                capture_bytes=payloads["capture_path"],
                result_bytes=payloads["result_path"],
            )
            verify_digest_chain_record(record, evaluation, root)
            (root / evaluation["raw_response_path"]).write_bytes(b"changed")
            with self.assertRaises(ExecutionError):
                verify_digest_chain_record(record, evaluation, root)


class InventoryTests(unittest.TestCase):
    def test_inventory_rejects_missing_extra_and_alias_files(self) -> None:
        plan = build_execution_plan(CASE_IDS)
        paths = expected_execution_paths(plan)
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            with self.assertRaises(InventoryError):
                validate_execution_inventory(root, plan)
            for relative in paths:
                path = root / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(relative.encode("utf-8"))
            inventory = validate_execution_inventory(root, plan)
            self.assertEqual(set(inventory), set(paths))

            extra = root / "unplanned.json"
            extra.write_text("{}", encoding="utf-8")
            with self.assertRaises(InventoryError):
                validate_execution_inventory(root, plan)
            extra.unlink()

            first, second = (root / paths[0], root / paths[1])
            second.unlink()
            try:
                os.link(first, second)
            except OSError:
                self.skipTest("hard links are unavailable")
            with self.assertRaises(InventoryError):
                validate_execution_inventory(root, plan)


class CalibrationLockTests(unittest.TestCase):
    def test_calibration_lock_binds_repository_plan_and_external_inputs(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            repository = root / "repository"
            execution = root / "execution"
            repository.mkdir()
            execution.mkdir()
            _initialize_repository(repository)
            plan = _calibration_plan()
            prepared = []
            for entry in plan["inputs"]:
                path = execution / entry["input_path"]
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(entry["case_id"], encoding="utf-8")
                prepared.append(path)

            manifest = build_calibration_lock_manifest(
                repository,
                execution_root=execution,
                fixtures=[repository / "fixtures.json"],
                oracles=[repository / "oracle.json"],
                schemas=[repository / "schema.json"],
                prompts=[repository / "prompt.txt"],
                evaluator=[repository / "evaluator.py"],
                prepared_inputs=prepared,
                model_settings=GEMINI_SETTINGS,
                calibration_plan=plan,
            )
            self.assertEqual(
                manifest["schema_version"], CALIBRATION_LOCK_SCHEMA_VERSION
            )
            self.assertEqual(set(manifest["sections"]), set(CALIBRATION_LOCK_SECTIONS))
            self.assertEqual(
                set(manifest["sections"]["prepared_inputs"]["files"]),
                {entry["input_path"] for entry in plan["inputs"]},
            )
            self.assertEqual(
                set(manifest["sections"]["fixtures"]["files"]),
                {"fixtures.json"},
            )
            verify_calibration_lock_manifest(
                manifest,
                repository,
                execution_root=execution,
                model_settings=GEMINI_SETTINGS,
                calibration_plan=plan,
            )

            prepared[0].write_text("changed", encoding="utf-8")
            with self.assertRaises(LockVerificationError):
                verify_calibration_lock_manifest(
                    manifest,
                    repository,
                    execution_root=execution,
                )
            prepared[0].write_text("cal-01", encoding="utf-8")

            (repository / "fixtures.json").write_text('{"changed":true}\n', encoding="utf-8")
            subprocess.run(
                ("git", "-C", str(repository), "add", "fixtures.json"),
                check=True,
                capture_output=True,
            )
            subprocess.run(
                ("git", "-C", str(repository), "commit", "-qm", "change fixture"),
                check=True,
                capture_output=True,
            )
            with self.assertRaises(LockVerificationError):
                verify_calibration_lock_manifest(
                    manifest,
                    repository,
                    execution_root=execution,
                )

    def test_calibration_lock_rejects_plan_mutation(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            _initialize_repository(root)
            plan = _calibration_plan()
            plan["inputs"][0]["case_id"] = "cal-99"
            with self.assertRaises(LockingError):
                build_calibration_lock_manifest(
                    root,
                    fixtures=[root / "fixtures.json"],
                    oracles=[root / "oracle.json"],
                    schemas=[root / "schema.json"],
                    prompts=[root / "prompt.txt"],
                    evaluator=[root / "evaluator.py"],
                    prepared_inputs=[root / "fixtures.json"],
                    model_settings=GEMINI_SETTINGS,
                    calibration_plan=plan,
                )


class LockV2Tests(unittest.TestCase):
    def test_exact_gemini_settings_reject_extras_and_behavior_changes(self) -> None:
        self.assertEqual(validate_model_settings(GEMINI_SETTINGS), GEMINI_SETTINGS)
        extra = deepcopy(GEMINI_SETTINGS)
        extra["seed"] = 7
        with self.assertRaises(LockingError):
            validate_model_settings(extra)
        retry = deepcopy(GEMINI_SETTINGS)
        retry["retry"]["max_attempts"] = 2
        with self.assertRaises(LockingError):
            validate_model_settings(retry)
        tools = deepcopy(GEMINI_SETTINGS)
        tools["request"]["tools"] = [{"function_declarations": []}]
        with self.assertRaises(LockingError):
            validate_model_settings(tools)
        noncanonical_types = deepcopy(GEMINI_SETTINGS)
        noncanonical_types["request"]["store"] = 0
        noncanonical_types["retry"]["max_attempts"] = 1.0
        with self.assertRaises(LockingError):
            validate_model_settings(noncanonical_types)

    def test_lock_v2_binds_git_state_plan_inputs_and_sealed_oracle(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            repository = root / "repository"
            execution = root / "execution"
            repository.mkdir()
            execution.mkdir()
            _initialize_repository(repository)
            calibration_plan = _calibration_plan()
            calibration_prepared = []
            for entry in calibration_plan["inputs"]:
                path = execution / entry["input_path"]
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(entry["case_id"], encoding="utf-8")
                calibration_prepared.append(path)
            calibration_lock = build_calibration_lock_manifest(
                repository,
                execution_root=execution,
                fixtures=[repository / "fixtures.json"],
                oracles=[repository / "oracle.json"],
                schemas=[repository / "schema.json"],
                prompts=[repository / "prompt.txt"],
                evaluator=[repository / "evaluator.py"],
                prepared_inputs=calibration_prepared,
                model_settings=GEMINI_SETTINGS,
                calibration_plan=calibration_plan,
            )
            calibration_index = _calibration_index(calibration_lock)
            suite_manifest = {
                "schema_version": "suite-manifest/v1",
                "calibration_index_sha256": canonical_sha256(calibration_index),
                "case_count": 12,
            }
            plan = build_execution_plan(CASE_IDS)
            prepared: list[Path] = []
            for entry in plan["prepared_inputs"]:
                path = execution / entry["path"]
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(entry["input_id"], encoding="utf-8")
                prepared.append(path)
            manifest = build_lock_manifest_v2(
                repository,
                execution_root=execution,
                fixtures=[repository / "fixtures.json"],
                schemas=[repository / "schema.json"],
                prompts=[repository / "prompt.txt"],
                evaluator=[repository / "evaluator.py"],
                prepared_inputs=prepared,
                model_settings=GEMINI_SETTINGS,
                execution_plan=plan,
                calibration_index=calibration_index,
                suite_manifest=suite_manifest,
                suite_attestation={"schema_version": "suite-attestation/v1", "valid": True},
                sealed_oracle_digest="a" * 64,
            )
            self.assertEqual(manifest["schema_version"], LOCK_V2_SCHEMA_VERSION)
            verify_lock_manifest(
                manifest,
                repository,
                execution_root=execution,
                model_settings=GEMINI_SETTINGS,
                execution_plan=plan,
                sealed_oracle_digest="a" * 64,
            )

            broken_link = deepcopy(manifest)
            broken_link["suite_manifest"]["value"][
                "calibration_index_sha256"
            ] = "0" * 64
            broken_link["suite_manifest"]["digest"] = canonical_sha256(
                broken_link["suite_manifest"]["value"]
            )
            with self.assertRaises(LockVerificationError):
                verify_lock_manifest(
                    broken_link,
                    repository,
                    execution_root=execution,
                )

            wrong_repository_index = deepcopy(calibration_index)
            embedded_lock = wrong_repository_index["calibration_lock"]["value"]
            embedded_lock["repository"]["head_sha"] = "0" * 40
            wrong_repository_index["calibration_lock"]["digest"] = canonical_sha256(
                embedded_lock
            )
            wrong_repository_suite = deepcopy(suite_manifest)
            wrong_repository_suite["calibration_index_sha256"] = canonical_sha256(
                wrong_repository_index
            )
            with self.assertRaises(LockingError):
                build_lock_manifest_v2(
                    repository,
                    execution_root=execution,
                    fixtures=[repository / "fixtures.json"],
                    schemas=[repository / "schema.json"],
                    prompts=[repository / "prompt.txt"],
                    evaluator=[repository / "evaluator.py"],
                    prepared_inputs=prepared,
                    model_settings=GEMINI_SETTINGS,
                    execution_plan=plan,
                    calibration_index=wrong_repository_index,
                    suite_manifest=wrong_repository_suite,
                    suite_attestation={"status": "attested"},
                    sealed_oracle_digest="a" * 64,
                )

            wrong_prepared = prepared.copy()
            replacement = execution / "prepared-inputs" / "replacement.json"
            replacement.write_text("{}\n", encoding="utf-8")
            wrong_prepared[0] = replacement
            with self.assertRaises(LockingError):
                build_lock_manifest_v2(
                    repository,
                    execution_root=execution,
                    fixtures=[repository / "fixtures.json"],
                    schemas=[repository / "schema.json"],
                    prompts=[repository / "prompt.txt"],
                    evaluator=[repository / "evaluator.py"],
                    prepared_inputs=wrong_prepared,
                    model_settings=GEMINI_SETTINGS,
                    execution_plan=plan,
                    calibration_index=calibration_index,
                    suite_manifest=suite_manifest,
                    suite_attestation={"status": "attested"},
                    sealed_oracle_digest="a" * 64,
                )

            changed = deepcopy(manifest)
            changed["unexpected"] = True
            with self.assertRaises(LockVerificationError):
                verify_lock_manifest(
                    changed,
                    repository,
                    execution_root=execution,
                )

            (repository / "evaluator.py").write_text("VALUE = 2\n", encoding="utf-8")
            with self.assertRaises(LockVerificationError):
                verify_lock_manifest(
                    manifest,
                    repository,
                    execution_root=execution,
                )


def _initialize_repository(root: Path) -> None:
    files = {
        "fixtures.json": "{}\n",
        "oracle.json": "{}\n",
        "schema.json": "{}\n",
        "prompt.txt": "bounded prompt\n",
        "evaluator.py": "VALUE = 1\n",
    }
    for relative, content in files.items():
        (root / relative).write_text(content, encoding="utf-8")
    commands = (
        ("init", "-q"),
        ("config", "user.name", "Lazarus Test"),
        ("config", "user.email", "test@example.invalid"),
        ("add", "."),
        ("commit", "-qm", "fixture"),
    )
    for arguments in commands:
        subprocess.run(
            ("git", "-C", str(root), *arguments),
            check=True,
            capture_output=True,
        )


if __name__ == "__main__":
    unittest.main()
