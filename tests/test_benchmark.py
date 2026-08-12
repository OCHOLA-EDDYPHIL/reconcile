from __future__ import annotations

from copy import deepcopy
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from lazarus.benchmark import (
    ABLATION_ARMS,
    BenchmarkCase,
    BenchmarkError,
    _abstained,
    _behavior_deviations,
    _concept_thresholds,
    _prediction_matches,
    _relation_failures,
    _recovery_repeatability,
    _recovery_state_coverage,
    _score_run,
    _validate_compiler_packet,
    _validate_record_context,
    _validate_v2_capture_execution,
    build_model_input,
    discover_cases,
    freeze_benchmark,
    load_case,
    load_oracle,
    load_persisted_result,
    persist_raw_result,
    score_persisted_results,
    validate_model_capture,
    validate_suite,
    verify_benchmark_lock,
)
from lazarus.locking import (
    LockVerificationError,
    LockingError,
    canonical_sha256,
    file_sha256,
)
from lazarus.compiler import compile_case
from lazarus.execution import build_execution_plan
from lazarus.recovery import load_recovery_matrix_inputs


REPOSITORY = Path(__file__).resolve().parents[1]
FIXTURES = REPOSITORY / "fixtures"
MODEL_SETTINGS = {
    "provider": "local-replay",
    "model": "bounded-resolver-v1",
    "parameters": {
        "temperature": 0,
        "top_p": 1,
        "max_output_tokens": 1024,
    },
    "retry": {
        "max_attempts": 1,
        "backoff_seconds": 0,
    },
}
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
        "response_schema_sha256": "a" * 64,
    },
    "thinking": {"level": "MINIMAL", "include_thoughts": False},
    "request": {
        "store": False,
        "service_tier": "standard",
        "timeout_seconds": 120,
        "minimum_interval_seconds": 16,
        "safety_settings": "provider-default",
        "tools": [],
    },
    "retry": {"max_attempts": 1, "backoff_seconds": 0},
}


class BenchmarkFixtureTests(unittest.TestCase):
    def test_suite_has_separate_oracles_and_required_balance(self) -> None:
        self.assertEqual(
            validate_suite(FIXTURES),
            {
                "calibration": 4,
                "heldout": 12,
                "heldout_blockers": 8,
                "heldout_negative_controls": 4,
            },
        )
        cases = [load_case(path) for path in discover_cases(FIXTURES)]
        self.assertEqual(len(cases), 16)
        expected_ids = {f"cal-{index:02d}" for index in range(1, 5)} | {
            f"eval-n{index:02d}" for index in range(1, 13)
        }
        self.assertEqual({case.case_id for case in cases}, expected_ids)
        for case in cases:
            self.assertNotIn(case.oracle_path.resolve(), set(case.artifacts.values()))
            self.assertTrue(case.oracle_path.is_file())
            self.assertEqual(load_oracle(case.directory)["case_id"], case.case_id)
    def test_model_inputs_do_not_contain_oracle_fields(self) -> None:
        forbidden = {"negative_control", "decision_changing_blockers", "oracle_id", "coverage"}
        for case_path in discover_cases(FIXTURES):
            case = load_case(case_path)
            self.assertTrue(forbidden.isdisjoint(_keys(case.definition)))
            for artifact in case.artifacts.values():
                if artifact.suffix == ".json":
                    value = json.loads(artifact.read_text(encoding="utf-8"))
                    self.assertTrue(forbidden.isdisjoint(_keys(value)))


class LockingTests(unittest.TestCase):
    def test_canonical_hash_ignores_json_member_order(self) -> None:
        self.assertEqual(
            canonical_sha256({"b": [2, 3], "a": 1}),
            canonical_sha256({"a": 1, "b": [2, 3]}),
        )

    def test_lock_hashes_exact_json_bytes_and_all_evaluator_modules(self) -> None:
        manifest = freeze_benchmark(FIXTURES, model_settings=MODEL_SETTINGS)
        with tempfile.TemporaryDirectory() as temporary:
            source = Path(temporary) / "value.json"
            source.write_text('{"a":1}\n', encoding="utf-8")
            compact = file_sha256(source)
            source.write_text('{ "a": 1 }\n', encoding="utf-8")
            self.assertNotEqual(compact, file_sha256(source))
        evaluator = manifest["sections"]["evaluator"]["files"]
        expected_modules = {
            path.relative_to(REPOSITORY).as_posix()
            for path in (REPOSITORY / "lazarus").glob("*.py")
        }
        self.assertTrue(expected_modules.issubset(evaluator))
        self.assertIn("pyproject.toml", evaluator)

    def test_freeze_requires_complete_model_settings(self) -> None:
        incomplete = deepcopy(MODEL_SETTINGS)
        del incomplete["retry"]["max_attempts"]
        with self.assertRaises(LockingError):
            freeze_benchmark(FIXTURES, model_settings=incomplete)

    def test_freeze_and_verify_every_protocol_section(self) -> None:
        manifest = freeze_benchmark(FIXTURES, model_settings=MODEL_SETTINGS)
        self.assertEqual(
            set(manifest["sections"]),
            {"fixtures", "oracles", "schemas", "prompts", "evaluator"},
        )
        self.assertTrue(all(section["files"] for section in manifest["sections"].values()))
        verify_benchmark_lock(manifest, FIXTURES, model_settings=MODEL_SETTINGS)

        changed = deepcopy(manifest)
        first_path = next(iter(changed["sections"]["fixtures"]["files"]))
        changed["sections"]["fixtures"]["files"][first_path] = "0" * 64
        with self.assertRaises(LockVerificationError):
            verify_benchmark_lock(changed, FIXTURES, model_settings=MODEL_SETTINGS)


class RawResultTests(unittest.TestCase):
    def test_raw_result_is_immutable_and_digest_checked(self) -> None:
        packet = {"case_id": "synthetic-01", "arm": "a1", "blockers": []}
        raw = _raw_result("synthetic-01", "a1", "baseline", packet)
        with tempfile.TemporaryDirectory() as temporary:
            destination = Path(temporary)
            path = persist_raw_result(destination, raw)
            self.assertEqual(load_persisted_result(path), raw)
            with self.assertRaises(BenchmarkError):
                persist_raw_result(destination, raw)

            envelope = json.loads(path.read_text(encoding="utf-8"))
            envelope["result"]["output"]["packet"]["blockers"] = [
                {"code": "ALTERED", "decision_effect": "block"}
            ]
            path.write_text(json.dumps(envelope), encoding="utf-8")
            with self.assertRaises(BenchmarkError):
                load_persisted_result(path)

    def test_oracle_matching_never_credits_an_arbitrary_blocker(self) -> None:
        expected = {"acceptable_matches": ["EXPECTED_BLOCKER"]}
        self.assertFalse(
            _prediction_matches(
                expected,
                {"code": "UNRELATED_BLOCKER", "decision_effect": "block"},
                None,
            )
        )

    def test_persisted_packet_must_reproduce_the_locked_compiler(self) -> None:
        case = load_case(FIXTURES / "calibration" / "case-02")
        packet = compile_case(case.directory, "a1")
        record = _raw_result(case.case_id, "a1", "baseline", packet)
        _validate_compiler_packet(record, case, semantic_output=None)
        record["output"]["packet"]["blockers"].append(
            {
                "blocker_id": "fabricated",
                "code": "FABRICATED",
                "message": "Not produced by the compiler.",
                "evidence_refs": ["ticket"],
                "decision_effect": "block",
            }
        )
        with self.assertRaises(BenchmarkError):
            _validate_compiler_packet(record, case, semantic_output=None)

    def test_persisted_capture_v2_preserves_invalid_semantic_unavailability(self) -> None:
        case = load_case(FIXTURES / "calibration" / "case-01")
        arm = "b-replay"
        run_id = "run-01"
        lock_digest = "b" * 64
        input_digest = hashlib.sha256(
            build_model_input(case, arm, FIXTURES / "protocol" / "prompts")
        ).hexdigest()
        capture = _v2_capture(
            case_id=case.case_id,
            arm=arm,
            run_id=run_id,
            lock_digest=lock_digest,
            input_digest=input_digest,
            response_text="not valid semantic JSON",
        )
        record = {
            "schema_version": "lazarus.raw-result/v1",
            "case_id": case.case_id,
            "arm": arm,
            "run_id": run_id,
            "started_at": capture["started_at"],
            "completed_at": capture["completed_at"],
            "protocol_lock_digest": lock_digest,
            "model_settings": deepcopy(GEMINI_SETTINGS),
            "model_settings_digest": canonical_sha256(GEMINI_SETTINGS),
            "output": {
                "packet": compile_case(
                    case.directory,
                    arm,
                    semantic=None,
                    allow_heldout=True,
                ),
                "capture": capture,
            },
        }

        with tempfile.TemporaryDirectory() as temporary:
            persisted = persist_raw_result(temporary, record)
            loaded = load_persisted_result(persisted)
        _validate_record_context(
            loaded,
            case,
            GEMINI_SETTINGS,
            FIXTURES / "protocol" / "prompts",
        )

        loaded["output"]["packet"]["semantic_status"] = "available"
        loaded["output"]["packet"]["semantic"] = {
            "admitted": [],
            "rejected": [],
            "abstained": False,
            "requested_evidence": [],
        }
        with self.assertRaisesRegex(
            BenchmarkError,
            "invalid captured response must preserve semantic unavailability",
        ):
            _validate_record_context(
                loaded,
                case,
                GEMINI_SETTINGS,
                FIXTURES / "protocol" / "prompts",
            )

    def test_capture_v2_binds_settings_response_and_locked_execution_identity(self) -> None:
        case_ids = tuple(f"synthetic-{index:02d}" for index in range(1, 13))
        plan = build_execution_plan(case_ids)
        evaluation = next(
            entry
            for entry in plan["evaluations"]
            if entry["case_id"] == case_ids[0]
            and entry["arm"] == "b-replay"
            and entry["run_id"] == "run-01"
        )
        lock = {
            "schema_version": "lazarus.benchmark-lock/v2",
            "execution_plan": {
                "digest": canonical_sha256(plan),
                "value": plan,
            },
            "sealed_oracle": {"algorithm": "sha256", "digest": "a" * 64},
        }
        capture = _v2_capture(
            case_id=evaluation["case_id"],
            arm=evaluation["arm"],
            run_id=evaluation["run_id"],
            lock_digest=canonical_sha256(lock),
            input_digest="c" * 64,
            execution=evaluation,
            execution_plan_digest=canonical_sha256(plan),
            sealed_oracle_digest="a" * 64,
        )
        record = {
            "case_id": evaluation["case_id"],
            "arm": evaluation["arm"],
            "run_id": evaluation["run_id"],
            "output": {"capture": capture},
        }

        self.assertEqual(
            validate_model_capture(
                capture,
                model_settings=GEMINI_SETTINGS,
                arm=evaluation["arm"],
            ),
            capture,
        )
        _validate_v2_capture_execution(record, lock)

        settings_mismatch = deepcopy(capture)
        settings_mismatch["provider"] = "other-provider"
        with self.assertRaises(BenchmarkError):
            validate_model_capture(
                settings_mismatch,
                model_settings=GEMINI_SETTINGS,
                arm=evaluation["arm"],
            )
        response_mismatch = deepcopy(capture)
        response_mismatch["response_text"] = "altered"
        with self.assertRaises(BenchmarkError):
            validate_model_capture(
                response_mismatch,
                model_settings=GEMINI_SETTINGS,
                arm=evaluation["arm"],
            )
        identity_mismatch = deepcopy(record)
        identity_mismatch["output"]["capture"]["sequence"] += 1
        with self.assertRaises(BenchmarkError):
            _validate_v2_capture_execution(identity_mismatch, lock)


class SyntheticScoringTests(unittest.TestCase):
    def test_admitted_candidate_requires_endpoint_support_from_its_citations(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            cases_by_path, _oracles = _synthetic_cases(Path(temporary))
            case = next(iter(cases_by_path.values()))
            proposal = _proposal(case, "owner", "owner_candidate")
            proposal["subject"] = "uncited-resource"
            record = _raw_result(
                case.case_id,
                "b-replay",
                "concept",
                _packet(case, "b-replay", [], [proposal]),
            )

            self.assertEqual(_relation_failures(record, case), (1, 0))

    def test_companion_blockers_are_enumerated_one_to_one(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            cases_by_path, _oracles = _synthetic_cases(Path(temporary))
            case = next(iter(cases_by_path.values()))
            record = _raw_result(
                case.case_id,
                "a1",
                "baseline",
                _packet(case, "a1", ["PRIMARY", "COMPANION"], []),
            )
            oracle = {
                "negative_control": False,
                "decision_changing_blockers": [
                    {
                        "oracle_id": "primary",
                        "decision_changing": True,
                        "acceptable_matches": ["PRIMARY"],
                    },
                    {
                        "oracle_id": "companion",
                        "decision_changing": True,
                        "acceptable_matches": ["COMPANION"],
                    },
                ],
                "abstention_required": False,
                "required_probe": None,
                "coverage": ["direct_destructive_target"],
                "recovery_expectation": {
                    "restore": "pass",
                    "canary": "pass",
                    "rpo": "pass",
                    "rto": "pass",
                    "cleanup": "pass",
                },
            }

            score = _score_run(
                {case.case_id: case},
                {case.case_id: oracle},
                {case.case_id: record},
                {},
                arm="a1",
            )

        self.assertEqual(score["true_positive"], 2)
        self.assertEqual(score["false_positive"], 0)
        self.assertEqual(score["precision"], 1.0)

    def test_model_input_binds_the_semantic_output_contract(self) -> None:
        case = load_case(FIXTURES / "calibration" / "case-01")
        request = json.loads(
            build_model_input(
                case,
                "b-replay",
                FIXTURES / "protocol" / "prompts",
            )
        )
        schema_text = request["semantic_output_schema"]

        self.assertEqual(
            json.loads(schema_text)["properties"]["schema_version"]["const"],
            "lazarus.semantic-proposal/v1",
        )
        self.assertEqual(
            request["semantic_output_schema_sha256"],
            hashlib.sha256(schema_text.encode("utf-8")).hexdigest(),
        )

    def test_invalid_semantic_object_is_not_a_correct_abstention(self) -> None:
        packet = {
            "semantic_status": "unavailable",
            "semantic": {
                "admitted": [],
                "rejected": [],
                "abstained": True,
                "requested_evidence": ["valid semantic response"],
            },
        }
        response_text = "{}"
        record = {
            "output": {
                "packet": packet,
                "capture": {
                    "response_text": response_text,
                    "tool_calls": [],
                },
            }
        }

        self.assertFalse(_abstained(record))
        self.assertEqual(
            _behavior_deviations(record, {"coverage": []}),
            1,
        )

    def test_capture_v2_tool_parts_are_behavior_deviations(self) -> None:
        record = {
            "output": {
                "packet": {
                    "semantic_status": "available",
                    "semantic": {"admitted": [], "rejected": []},
                },
                "capture": {
                    "schema_version": "lazarus.model-capture/v2",
                    "response_text": "{}",
                    "tool_parts": [{"functionCall": {"name": "forbidden"}}],
                    "finish_reason": "STOP",
                },
            }
        }

        self.assertEqual(_behavior_deviations(record, {"coverage": []}), 1)

    def test_capture_v2_requires_normal_model_completion(self) -> None:
        record = {
            "output": {
                "packet": {
                    "semantic_status": "available",
                    "semantic": {"admitted": [], "rejected": []},
                },
                "capture": {
                    "schema_version": "lazarus.model-capture/v2",
                    "response_text": "{}",
                    "tool_parts": [],
                    "finish_reason": "MAX_TOKENS",
                },
            }
        }

        self.assertEqual(_behavior_deviations(record, {"coverage": []}), 1)

    def test_no_incident_ablation_removes_incident_input_before_generation(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            cases, _oracles = _synthetic_cases(Path(temporary))
            case = next(iter(cases.values()))
            incident_path = case.directory / "incident.txt"
            incident_path.write_text("Historical context only.", encoding="utf-8")
            definition = deepcopy(case.definition)
            definition["artifacts"].append(
                {
                    "artifact_id": "incident",
                    "kind": "incident",
                    "path": "incident.txt",
                    "authority": "advisory_context",
                }
            )
            with_incident = BenchmarkCase(
                case.directory,
                definition,
                {**case.artifacts, "incident": incident_path},
            )
            prompt_root = FIXTURES / "protocol" / "prompts"
            full = json.loads(build_model_input(with_incident, "b-replay", prompt_root))
            ablated = json.loads(
                build_model_input(with_incident, "b-replay-no-incident", prompt_root)
            )

        self.assertIn(
            "incident",
            {item["artifact_id"] for item in full["untrusted_artifacts"]},
        )
        self.assertNotIn(
            "incident",
            {item["artifact_id"] for item in ablated["untrusted_artifacts"]},
        )

    def test_concept_score_uses_one_result_per_arm_and_recovery_state(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            cases, oracles = _synthetic_cases(root)
            manifest = {"schema_version": "synthetic-lock/v1", "nonce": "unit-test"}
            lock_digest = canonical_sha256(manifest)
            result_root = root / "results"

            a1_paths: list[Path] = []
            rules_paths: list[Path] = []
            b_paths: list[Path] = []
            for index, case in enumerate(cases.values(), start=1):
                baseline_codes = [f"BASELINE_{index:02d}"] if index <= 6 else []
                a1_packet = _packet(case, "a1", baseline_codes, [])
                rules_packet = _packet(case, "a1-rules", baseline_codes, [])
                a1_paths.append(
                    persist_raw_result(
                        result_root,
                        _raw_result(
                            case.case_id,
                            "a1",
                            "baseline",
                            a1_packet,
                            lock_digest=lock_digest,
                        ),
                    )
                )
                rules_paths.append(
                    persist_raw_result(
                        result_root,
                        _raw_result(
                            case.case_id,
                            "a1-rules",
                            "rules",
                            rules_packet,
                            lock_digest=lock_digest,
                        ),
                    )
                )
                coverage = oracles[case.directory]["coverage"][0]
                b_paths.append(
                    persist_raw_result(
                        result_root,
                        _model_raw_result(
                            case,
                            "b-replay",
                            "concept",
                            baseline_codes,
                            coverage,
                            lock_digest,
                        ),
                    )
                )

            case_paths = tuple(cases)

            def synthetic_case(path: Path) -> BenchmarkCase:
                return cases[Path(path)]

            def synthetic_oracle(path: Path) -> dict[str, object]:
                return oracles[Path(path)]

            with (
                mock.patch("lazarus.benchmark.verify_benchmark_lock"),
                mock.patch("lazarus.benchmark.discover_cases", return_value=case_paths),
                mock.patch("lazarus.benchmark.load_case", side_effect=synthetic_case),
                mock.patch("lazarus.benchmark.load_oracle", side_effect=synthetic_oracle),
                mock.patch("lazarus.benchmark._validate_compiler_packet"),
            ):
                score = score_persisted_results(
                    FIXTURES,
                    lock_manifest=manifest,
                    a1_results=a1_paths,
                    a1_rules_results=rules_paths,
                    b_results=b_paths,
                    model_settings=MODEL_SETTINGS,
                    recovery_state_coverage=_state_coverage_evidence(lock_digest),
                )

            self.assertEqual(
                set(score),
                {
                    "schema_version",
                    "case_count",
                    "a1",
                    "a1_rules",
                    "b",
                    "recovery_state_coverage",
                    "thresholds",
                    "concept_pass",
                },
            )
            self.assertEqual(score["schema_version"], "lazarus.concept-score/v1")
            self.assertEqual(score["a1"]["recall"], 0.75)
            self.assertEqual(score["a1_rules"]["recall"], 0.75)
            self.assertEqual(score["b"]["recall"], 1.0)
            self.assertEqual(score["b"]["precision"], 1.0)
            self.assertEqual(score["b"]["unique_beyond_a1"], 2)
            self.assertTrue(score["concept_pass"])
            self.assertTrue(score["recovery_state_coverage"]["passed"])
            self.assertTrue(score["thresholds"]["generic_rules_do_not_reproduce"])

    def test_concept_thresholds_use_only_the_registered_checks(self) -> None:
        a1 = {
            "recall": 0.5,
            "false_positive": 1,
            "recovery_correct": 12,
            "recovery_expected": 12,
        }
        a1_rules = {
            "recovery_correct": 12,
            "recovery_expected": 12,
        }
        b = {
            "recall": 0.5001,
            "false_positive": 1,
            "unique_beyond_a1": 1,
            "negative_control_false_blockers": 0,
            "unsupported_relations": 0,
            "invalid_citations": 0,
            "behavior_deviations": 0,
            "recovery_correct": 12,
            "recovery_expected": 12,
        }

        thresholds = _concept_thresholds(
            a1,
            a1_rules,
            b,
            generic_rules_reproduce=False,
            recovery_state_coverage=True,
        )

        self.assertEqual(
            set(thresholds),
            {
                "recall_improvement",
                "unique_blockers",
                "false_positive_control",
                "negative_controls",
                "supported_relations",
                "valid_citations",
                "behavior_deviations",
                "generic_rules_do_not_reproduce",
                "recovery_expectations",
                "recovery_state_coverage",
            },
        )
        self.assertTrue(all(thresholds.values()))

    def test_recovery_state_coverage_requires_one_exact_run_per_state(self) -> None:
        lock_digest = "a" * 64
        evidence = _state_coverage_evidence(lock_digest)
        self.assertTrue(
            _recovery_state_coverage(
                evidence,
                protocol_lock_digest=lock_digest,
                fixtures_root=FIXTURES,
            )["passed"]
        )

        evidence["states"]["fresh"]["runs"] = []
        self.assertFalse(
            _recovery_state_coverage(
                evidence,
                protocol_lock_digest=lock_digest,
                fixtures_root=FIXTURES,
            )["passed"]
        )

        wrong_repeat = _state_coverage_evidence(lock_digest)
        wrong_repeat["repeat"] = 20
        with self.assertRaises(BenchmarkError):
            _recovery_state_coverage(
                wrong_repeat,
                protocol_lock_digest=lock_digest,
                fixtures_root=FIXTURES,
            )

    def test_repeatability_ignores_self_attested_summary_fields(self) -> None:
        lock_digest = "a" * 64
        evidence = _repeatability_evidence(lock_digest)
        evidence["states"]["fresh"]["runs"] = evidence["states"]["fresh"]["runs"][:19]
        self.assertFalse(
            _recovery_repeatability(
                evidence,
                protocol_lock_digest=lock_digest,
                fixtures_root=FIXTURES,
            )["passed"]
        )


def _synthetic_cases(
    root: Path,
) -> tuple[dict[Path, BenchmarkCase], dict[Path, dict[str, object]]]:
    coverage = (
        "direct_destructive_target",
        "exact_dependency",
        "generation_mismatch",
        "stale_recovery",
        "canary_invariant",
        "rto_breach",
        "semantic_alias",
        "nuanced_intent",
        "similar_names",
        "retired_dependency",
        "fresh_proof",
        "embedded_hostile_instruction",
    )
    cases: dict[Path, BenchmarkCase] = {}
    oracles: dict[Path, dict[str, object]] = {}
    for index, scenario in enumerate(coverage, start=1):
        directory = root / f"case-{index:02d}"
        directory.mkdir()
        text = f"Synthetic evidence for {scenario}."
        artifact = directory / "ticket.txt"
        artifact.write_text(text, encoding="utf-8")
        (directory / "dump.sql").write_text(
            "PRAGMA user_version = 1; CREATE TABLE sample(id INTEGER PRIMARY KEY);",
            encoding="utf-8",
        )
        case_id = f"synthetic-{index:02d}"
        definition = {
            "schema_version": "lazarus.case/v1",
            "case_id": case_id,
            "split": "heldout",
            "artifacts": [
                {
                    "artifact_id": "ticket",
                    "kind": "change_ticket_text",
                    "path": "ticket.txt",
                    "authority": "declared_context",
                }
            ],
            "recovery": {
                "dump_path": "dump.sql",
                "backup_created_at": "2026-08-12T11:59:30Z",
                "reference_time": "2026-08-12T12:00:00Z",
                "rpo_seconds": 60,
                "rto_ms": 100,
                "minimum_delay_ms": 0,
                "expected_schema_version": 1,
                "required_tables": ["sample"],
                "assertions": [],
            },
            "policy": {
                "reference_time": "2026-08-12T12:00:00Z",
                "max_evidence_age_seconds": 3600,
                "allowed_probe_ids": ["verify_recovery_scope"],
                "required_owner_fields": ["owner", "recovery_owner"],
                "human_decision_required": True,
            },
        }
        case = BenchmarkCase(directory, definition, {"ticket": artifact})
        cases[directory] = case
        blockers: list[dict[str, object]] = []
        negative = index > 8
        if index <= 6:
            blockers = [
                {
                    "oracle_id": f"oracle-{index:02d}",
                    "decision_changing": True,
                    "acceptable_matches": [f"BASELINE_{index:02d}"],
                }
            ]
        elif scenario == "semantic_alias":
            blockers = [
                {
                    "oracle_id": "oracle-alias",
                    "decision_changing": True,
                    "acceptable_matches": ["SEMANTIC_CONFIRMATION_REQUIRED"],
                    "required_relation_types": ["resource_alias_candidate"],
                }
            ]
        elif scenario == "nuanced_intent":
            blockers = [
                {
                    "oracle_id": "oracle-intent",
                    "decision_changing": True,
                    "acceptable_matches": ["SEMANTIC_CONFIRMATION_REQUIRED"],
                    "required_relation_types": ["intent_effect_contradiction"],
                    "requires_abstention": True,
                }
            ]
        oracles[directory] = {
            "schema_version": "lazarus.oracle/v1",
            "case_id": case_id,
            "negative_control": negative,
            "decision_changing_blockers": blockers,
            "advisory_findings": [],
            "coverage": [scenario],
            "abstention_required": scenario == "nuanced_intent",
            "required_probe": "verify_recovery_scope" if scenario == "semantic_alias" else None,
            "recovery_expectation": {
                "restore": "pass",
                "canary": "pass",
                "rpo": "pass",
                "rto": "pass",
                "cleanup": "pass",
            },
        }
    return cases, oracles


def _packet(
    case: BenchmarkCase,
    arm: str,
    blocker_codes: list[str],
    proposals: list[dict[str, object]],
    *,
    abstained: bool = False,
) -> dict[str, object]:
    semantic = {
        "admitted": proposals,
        "rejected": [],
        "abstained": abstained,
        "requested_evidence": ["clarify intended effect"] if abstained else [],
    }
    blockers: list[dict[str, object]] = []
    for code in blocker_codes:
        refs = ["ticket"]
        if code == "SEMANTIC_CONFIRMATION_REQUIRED":
            refs = [
                str(proposal["proposal_id"])
                for proposal in proposals
                if proposal.get("relation_type") != "probe_selection"
            ]
            if abstained:
                refs.append("semantic:abstention")
        blockers.append(
            {
                "blocker_id": f"blocker-{case.case_id}-{len(blockers) + 1}",
                "code": code,
                "message": f"Synthetic {code} evidence.",
                "evidence_refs": refs,
                "decision_effect": "block",
            }
        )
    semantic_requested = arm.startswith("b")
    if not semantic_requested:
        semantic = {
            "admitted": [],
            "rejected": [],
            "abstained": False,
            "requested_evidence": [],
        }
    if blockers:
        human_state = (
            "needs_confirmation"
            if all(item["code"] == "SEMANTIC_CONFIRMATION_REQUIRED" for item in blockers)
            else "blocked"
        )
    elif proposals:
        human_state = "needs_confirmation"
    else:
        human_state = "ready_for_human_decision"
    return {
        "schema_version": "lazarus.evidence-packet/v1",
        "case_id": case.case_id,
        "arm": arm,
        "facts": [],
        "derivations": [],
        "semantic": semantic,
        "advisory": [],
        "unknowns": ([{"code": "SEMANTIC_EVIDENCE_INCOMPLETE"}] if abstained else []),
        "blockers": blockers,
        "recovery": _recovery_result("fresh"),
        "human_decision_state": human_state,
        "semantic_status": "available" if semantic_requested else "not_requested",
    }


def _model_raw_result(
    case: BenchmarkCase,
    arm: str,
    run: str,
    baseline_codes: list[str],
    coverage: str,
    lock_digest: str,
) -> dict[str, object]:
    proposals: list[dict[str, object]] = []
    abstained = False
    if coverage == "semantic_alias" and arm != "b-replay-no-alias":
        proposals.append(_proposal(case, "alias", "resource_alias_candidate"))
        if arm != "b-replay-no-probe":
            proposals.append(_proposal(case, "probe", "probe_selection"))
    if coverage == "nuanced_intent" and arm != "b-replay-no-intent":
        proposals.append(_proposal(case, "intent", "intent_effect_contradiction"))
        abstained = True
    blocker_codes = list(baseline_codes)
    if any(item["relation_type"] != "probe_selection" for item in proposals):
        blocker_codes.append("SEMANTIC_CONFIRMATION_REQUIRED")
    packet = _packet(
        case,
        arm,
        blocker_codes,
        proposals,
        abstained=abstained,
    )
    semantic_response = {
        "schema_version": "lazarus.semantic-proposal/v1",
        "case_id": case.case_id,
        "proposals": [
            {key: value for key, value in proposal.items() if key != "evidence_class"}
            for proposal in proposals
        ],
        "abstained": abstained,
        "requested_evidence": ["clarify intended effect"] if abstained else [],
    }
    response_text = json.dumps(
        semantic_response,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    )
    capture = {
        "schema_version": "lazarus.model-capture/v1",
        "invocation_id": f"{arm}-{run}-{case.case_id}",
        "arm": arm,
        "started_at": "2026-08-12T12:00:00Z",
        "completed_at": "2026-08-12T12:00:01Z",
        "model_settings_digest": canonical_sha256(MODEL_SETTINGS),
        "prompt_sha256": hashlib.sha256(
            build_model_input(case, arm, FIXTURES / "protocol" / "prompts")
        ).hexdigest(),
        "response_text": response_text,
        "response_sha256": hashlib.sha256(response_text.encode("utf-8")).hexdigest(),
        "tool_calls": [],
    }
    return _raw_result(
        case.case_id,
        arm,
        run,
        packet,
        model=True,
        capture=capture,
        lock_digest=lock_digest,
    )


def _proposal(
    case: BenchmarkCase,
    suffix: str,
    relation_type: str,
) -> dict[str, object]:
    raw = case.artifacts["ticket"].read_bytes()
    text = raw.decode("utf-8")
    proposal: dict[str, object] = {
        "proposal_id": f"proposal-{suffix}-{case.case_id}",
        "relation_type": relation_type,
        "subject": "Synthetic evidence",
        "object": text.removeprefix("Synthetic evidence for ").rstrip("."),
        "citations": [
            {
                "artifact_id": "ticket",
                "digest": hashlib.sha256(raw).hexdigest(),
                "start": 0,
                "end": len(text),
                "quote": text,
            }
        ],
        "evidence_class": (
            "semantic_proposal"
            if relation_type == "probe_selection"
            else "candidate_inference"
        ),
    }
    if relation_type == "probe_selection":
        proposal["probe_id"] = "verify_recovery_scope"
    return proposal


def _v2_capture(
    *,
    case_id: str,
    arm: str,
    run_id: str,
    lock_digest: str,
    input_digest: str,
    response_text: str = "{}",
    execution: dict[str, object] | None = None,
    execution_plan_digest: str = "d" * 64,
    sealed_oracle_digest: str | None = None,
) -> dict[str, object]:
    selected = execution or {
        "execution_id": "evaluation-025",
        "sequence": 25,
        "invocation_id": "invocation-001",
        "request_path": "evaluations/evaluation-025/request.json",
        "raw_response_path": "evaluations/evaluation-025/raw-response.json",
        "capture_path": "evaluations/evaluation-025/capture.json",
    }
    return {
        "schema_version": "lazarus.model-capture/v2",
        "execution_id": selected["execution_id"],
        "sequence": selected["sequence"],
        "invocation_id": selected["invocation_id"],
        "case_id": case_id,
        "arm": arm,
        "run_id": run_id,
        "started_at": "2026-08-12T12:00:00Z",
        "completed_at": "2026-08-12T12:00:01Z",
        "http_status": 200,
        "provider": GEMINI_SETTINGS["provider"],
        "endpoint": GEMINI_SETTINGS["endpoint"],
        "model": GEMINI_SETTINGS["model"],
        "resolved_model_version": GEMINI_SETTINGS["resolved_model_version"],
        "model_version": GEMINI_SETTINGS["resolved_model_version"],
        "response_id": "response-001",
        "lock_sha256": lock_digest,
        "model_settings_sha256": canonical_sha256(GEMINI_SETTINGS),
        "execution_plan_sha256": execution_plan_digest,
        "sealed_oracle_sha256": sealed_oracle_digest,
        "input_path": f"prepared-inputs/{arm}/{case_id}.json",
        "input_sha256": input_digest,
        "request_path": selected["request_path"],
        "request_sha256": "e" * 64,
        "raw_response_path": selected["raw_response_path"],
        "raw_response_sha256": "f" * 64,
        "capture_path": selected["capture_path"],
        "candidate_index": 0,
        "candidate_role": "model",
        "finish_reason": "STOP",
        "text_parts": [response_text],
        "parts": [{"text": response_text}],
        "tool_parts": [],
        "safety_ratings": [],
        "usage_metadata": {"totalTokenCount": 1},
        "prompt_feedback": {},
        "model_status": {},
        "response_text": response_text,
        "response_text_sha256": hashlib.sha256(response_text.encode("utf-8")).hexdigest(),
    }


def _raw_result(
    case_id: str,
    arm: str,
    run_id: str,
    packet: dict[str, object],
    *,
    model: bool = False,
    capture: dict[str, object] | None = None,
    lock_digest: str | None = None,
) -> dict[str, object]:
    result: dict[str, object] = {
        "schema_version": "lazarus.raw-result/v1",
        "case_id": case_id,
        "arm": arm,
        "run_id": run_id,
        "started_at": "2026-08-12T12:00:00Z",
        "completed_at": "2026-08-12T12:00:01Z",
        "output": {"packet": packet},
    }
    if lock_digest is not None:
        result["protocol_lock_digest"] = lock_digest
    if model:
        assert capture is not None
        result["model_settings"] = deepcopy(MODEL_SETTINGS)
        result["model_settings_digest"] = canonical_sha256(MODEL_SETTINGS)
        result["output"]["capture"] = capture
    return result


def _repeatability_evidence(lock_digest: str) -> dict[str, object]:
    inputs = load_recovery_matrix_inputs(FIXTURES)
    states: dict[str, object] = {}
    for state in ("fresh", "schema", "invariant", "stale", "rto", "cleanup"):
        metadata = inputs["states"][state]
        runs: list[dict[str, object]] = []
        for index in range(1, 21):
            result = deepcopy(_recovery_result(state))
            runs.append(
                {
                    "schema_version": "lazarus.recovery-run-envelope/v1",
                    "case_id": metadata["case_id"],
                    "state": state,
                    "run_id": f"{state}-{index:02d}",
                    "started_at": "2026-08-12T12:00:00Z",
                    "completed_at": "2026-08-12T12:00:01Z",
                    "protocol_lock_digest": lock_digest,
                    "fixture_digest": metadata["fixture_digest"],
                    "result_sha256": canonical_sha256(result),
                    "result": result,
                }
            )
        states[state] = {
            "fixture_digest": metadata["fixture_digest"],
            "expected_signature": deepcopy(metadata["expected_signature"]),
            "runs": runs,
        }
    return {
        "schema_version": "lazarus.recovery-repeatability/v1",
        "protocol_lock_digest": lock_digest,
        "matrix_sha256": inputs["matrix_sha256"],
        "repeat": 20,
        "states": states,
    }


def _state_coverage_evidence(lock_digest: str) -> dict[str, object]:
    evidence = _repeatability_evidence(lock_digest)
    evidence["schema_version"] = "lazarus.recovery-state-coverage/v1"
    evidence["repeat"] = 1
    for state in evidence["states"].values():
        state["runs"] = state["runs"][:1]
    return evidence


def _recovery_result(state: str) -> dict[str, object]:
    checks = [
        {"check_id": "integrity", "check_type": "integrity", "status": "pass"},
        {
            "check_id": "schema",
            "check_type": "schema",
            "status": "fail" if state == "schema" else "pass",
        },
        {
            "check_id": "required-query",
            "check_type": "required_query",
            "status": "pass",
        },
        {
            "check_id": "invariant",
            "check_type": "business_invariant",
            "status": "fail" if state == "invariant" else "pass",
        },
    ]
    canary_status = "fail" if state in {"schema", "invariant"} else "pass"
    rpo_status = "fail" if state == "stale" else "pass"
    rto_status = (
        "unknown"
        if state in {"schema", "invariant"}
        else "fail" if state == "rto" else "pass"
    )
    cleanup_status = "fail" if state == "cleanup" else "pass"
    statuses = ("pass", canary_status, rpo_status, rto_status, cleanup_status)
    classification = "fail" if "fail" in statuses else "unknown" if "unknown" in statuses else "pass"
    rto_elapsed = 200 if state == "rto" else 1
    return {
        "restore": {"status": "pass", "elapsed_ms": 1},
        "canary": {"status": canary_status, "checks": checks},
        "rpo": {
            "status": rpo_status,
            "age_seconds": 120 if state == "stale" else 30,
            "objective_seconds": 60,
        },
        "rto": {
            "status": rto_status,
            "elapsed_ms": rto_elapsed,
            "objective_ms": 100,
        },
        "cleanup": {"status": cleanup_status},
        "classification": classification,
        "timing": {
            "clock": "monotonic_ns",
            "rto_started_ns": 1_000_000_000,
            "restore_started_ns": 1_000_000_000,
            "restore_completed_ns": 1_001_000_000,
            "rto_completed_ns": 1_000_000_000 + rto_elapsed * 1_000_000,
        },
    }


def _keys(value: object) -> set[str]:
    if isinstance(value, dict):
        return set(value) | {key for item in value.values() for key in _keys(item)}
    if isinstance(value, list):
        return {key for item in value for key in _keys(item)}
    return set()


if __name__ == "__main__":
    unittest.main()
