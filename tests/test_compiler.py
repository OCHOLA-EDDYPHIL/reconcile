from __future__ import annotations

import json
from pathlib import Path
import shutil
import tempfile
import unittest
from unittest import mock

from lazarus.compiler import B_ARM_DISABLED_RELATIONS, compile_case, normalize_operations
from lazarus.protocol import artifact_digest


class CompilerTests(unittest.TestCase):
    def test_ablation_policy_matches_replay_enforcement(self) -> None:
        policy_path = (
            Path(__file__).resolve().parents[1]
            / "fixtures"
            / "protocol"
            / "prompts"
            / "ablation-policy.json"
        )
        policy = json.loads(policy_path.read_text(encoding="utf-8"))
        self.assertEqual(
            {
                arm: frozenset(value["disabled_relation_types"])
                for arm, value in policy["arms"].items()
            },
            B_ARM_DISABLED_RELATIONS,
        )

    def test_normalizes_replacement_as_destructive(self) -> None:
        operations = normalize_operations(
            {
                "resource_changes": [
                    {
                        "address": "google_sql_database_instance.primary",
                        "type": "google_sql_database_instance",
                        "provider_name": "registry.terraform.io/hashicorp/google",
                        "change": {
                            "actions": ["delete", "create"],
                            "before": {
                                "name": "ledger-primary",
                                "project": "core",
                                "environment": "production",
                                "generation": "g7",
                            },
                            "after": {},
                        },
                    }
                ]
            }
        )
        self.assertEqual(operations[0]["effect"], "replace")
        self.assertTrue(operations[0]["destructive"])

    def test_structured_intent_and_missing_owner_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            artifacts = root / "artifacts"
            artifacts.mkdir()
            (artifacts / "plan.json").write_text(
                json.dumps(
                    {
                        "resource_changes": [
                            {
                                "address": "google_sql_database_instance.primary",
                                "type": "google_sql_database_instance",
                                "provider_name": "google",
                                "change": {
                                    "actions": ["delete", "create"],
                                    "before": {
                                        "name": "ledger-primary",
                                        "project": "core",
                                        "environment": "production",
                                        "generation": "g7",
                                    },
                                    "after": {},
                                },
                            }
                        ]
                    }
                ),
                encoding="utf-8",
            )
            (artifacts / "ticket.json").write_text(
                json.dumps({"intended_environment": "staging", "intended_effect": "resize"}),
                encoding="utf-8",
            )
            (artifacts / "ownership.json").write_text(json.dumps({"resources": []}), encoding="utf-8")
            (artifacts / "manifest.json").write_text(json.dumps({"services": []}), encoding="utf-8")
            (artifacts / "ledger.json").write_text(json.dumps({"records": []}), encoding="utf-8")
            (artifacts / "database.sql").write_text(
                "PRAGMA user_version = 1; CREATE TABLE accounts (id INTEGER PRIMARY KEY, balance INTEGER NOT NULL); INSERT INTO accounts VALUES (1, 0);",
                encoding="utf-8",
            )
            case = {
                "schema_version": "lazarus.case/v1",
                "case_id": "case-neutral",
                "split": "calibration",
                "artifacts": [
                    {"artifact_id": "plan", "kind": "terraform_plan", "path": "artifacts/plan.json", "authority": "structured_fact"},
                    {"artifact_id": "ticket", "kind": "change_ticket", "path": "artifacts/ticket.json", "authority": "declared_context"},
                    {"artifact_id": "ownership", "kind": "ownership", "path": "artifacts/ownership.json", "authority": "structured_fact"},
                    {"artifact_id": "manifest", "kind": "service_manifest", "path": "artifacts/manifest.json", "authority": "structured_fact"},
                    {"artifact_id": "ledger", "kind": "recovery_ledger", "path": "artifacts/ledger.json", "authority": "structured_fact"},
                ],
                "recovery": {
                    "dump_path": "artifacts/database.sql",
                    "backup_created_at": "2026-08-12T11:55:00Z",
                    "reference_time": "2026-08-12T12:00:00Z",
                    "rpo_seconds": 3600,
                    "rto_ms": 60000,
                    "minimum_delay_ms": 0,
                    "expected_schema_version": 1,
                    "required_tables": ["accounts"],
                    "assertions": [
                        {
                            "assertion_id": "nonnegative-balances",
                            "sql": "SELECT COUNT(*) FROM accounts WHERE balance < 0",
                            "expected": 0,
                        }
                    ],
                },
                "policy": {
                    "reference_time": "2026-08-12T12:00:00Z",
                    "max_evidence_age_seconds": 86400,
                    "allowed_probe_ids": [
                        "verify_resource_generation",
                        "verify_recovery_scope",
                        "verify_owner_record",
                        "run_application_canary",
                    ],
                    "required_owner_fields": ["owner", "recovery_owner"],
                    "human_decision_required": True,
                },
            }
            (root / "case.json").write_text(json.dumps(case), encoding="utf-8")
            packet = compile_case(root, "a0")
            codes = {blocker["code"] for blocker in packet["blockers"]}
            self.assertIn("DESTRUCTIVE_INTENT_MISMATCH", codes)
            self.assertIn("REQUIRED_EVIDENCE_UNKNOWN", codes)
            self.assertEqual(packet["human_decision_state"], "blocked")

    def test_b_replay_abstention_requires_human_confirmation(self) -> None:
        case_dir = Path(__file__).resolve().parents[1] / "fixtures" / "calibration" / "case-03"
        semantic = {
            "schema_version": "lazarus.semantic-proposal/v1",
            "case_id": "cal-03",
            "proposals": [],
            "abstained": True,
            "requested_evidence": ["the intended audit-store generation"],
        }

        packet = compile_case(case_dir, "b-replay", semantic=semantic)

        self.assertIn(
            "SEMANTIC_CONFIRMATION_REQUIRED",
            {blocker["code"] for blocker in packet["blockers"]},
        )
        self.assertIn(
            "SEMANTIC_EVIDENCE_INCOMPLETE",
            {unknown["code"] for unknown in packet["unknowns"]},
        )
        self.assertEqual(packet["human_decision_state"], "needs_confirmation")

    def test_b_replay_does_not_inherit_fixed_generic_rules(self) -> None:
        case_dir = Path(__file__).resolve().parents[1] / "fixtures" / "calibration" / "case-03"
        semantic = {
            "schema_version": "lazarus.semantic-proposal/v1",
            "case_id": "cal-03",
            "proposals": [],
            "abstained": True,
            "requested_evidence": ["the intended audit-store generation"],
        }

        with mock.patch("lazarus.compiler._generic_rule_checks") as generic_rules:
            compile_case(case_dir, "b-replay", semantic=semantic)
            generic_rules.assert_not_called()
            compile_case(case_dir, "a1-rules")
            generic_rules.assert_called_once()

    def test_a1_reconciles_visible_fuzzy_ownership_without_weakening_a0(self) -> None:
        case_dir = Path(__file__).resolve().parents[1] / "fixtures" / "calibration" / "case-02"

        a0 = compile_case(case_dir, "a0")
        a1 = compile_case(case_dir, "a1")

        self.assertIn(
            "REQUIRED_EVIDENCE_UNKNOWN",
            {blocker["code"] for blocker in a0["blockers"]},
        )
        self.assertNotIn(
            "REQUIRED_EVIDENCE_UNKNOWN",
            {blocker["code"] for blocker in a1["blockers"]},
        )
        self.assertEqual(a1["human_decision_state"], "ready_for_human_decision")

    def test_missing_destructive_target_scope_fails_closed(self) -> None:
        source = Path(__file__).resolve().parents[1] / "fixtures" / "calibration" / "case-02"
        with tempfile.TemporaryDirectory() as temporary:
            case_dir = Path(temporary) / "case"
            shutil.copytree(source, case_dir)
            plan_path = case_dir / "inputs" / "plan.json"
            plan = json.loads(plan_path.read_text(encoding="utf-8"))
            before = plan["resource_changes"][0]["change"]["before"]
            for field in ("project", "environment", "generation"):
                before.pop(field)
            plan_path.write_text(json.dumps(plan), encoding="utf-8")

            packet = compile_case(case_dir, "a1")

        self.assertIn(
            "DESTRUCTIVE_TARGET_SCOPE_INCOMPLETE",
            {unknown["code"] for unknown in packet["unknowns"]},
        )
        self.assertIn(
            "REQUIRED_EVIDENCE_UNKNOWN",
            {blocker["code"] for blocker in packet["blockers"]},
        )
        self.assertEqual(packet["human_decision_state"], "blocked")

    def test_unzoned_recovery_timestamp_fails_closed(self) -> None:
        source = Path(__file__).resolve().parents[1] / "fixtures" / "calibration" / "case-04"
        with tempfile.TemporaryDirectory() as temporary:
            case_dir = Path(temporary) / "case"
            shutil.copytree(source, case_dir)
            manifest_path = case_dir / "inputs" / "manifest.json"
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            manifest["services"][0]["dependencies"][0]["resource_ref"] = "inventory-main"
            manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
            ledger_path = case_dir / "inputs" / "ledger.json"
            ledger = {
                "records": [
                    {
                        "resource_ref": "inventory-main",
                        "project": "core-platform",
                        "environment": "production",
                        "generation": "gen-6",
                        "tested_at": "2026-08-12T11:59:00",
                        "application_canary": True,
                    }
                ]
            }
            ledger_path.write_text(json.dumps(ledger), encoding="utf-8")

            packet = compile_case(case_dir, "a1")

        self.assertIn(
            "RECOVERY_TIMESTAMP_INVALID",
            {unknown["code"] for unknown in packet["unknowns"]},
        )
        self.assertIn(
            "REQUIRED_EVIDENCE_UNKNOWN",
            {blocker["code"] for blocker in packet["blockers"]},
        )

    def test_semantic_alias_blocks_only_with_a_structured_dependency_consequence(self) -> None:
        case_dir = Path(__file__).resolve().parents[1] / "fixtures" / "calibration" / "case-04"
        runbook = (case_dir / "inputs" / "runbook.txt").read_text(encoding="utf-8")

        def response(subject: str, object_: str) -> dict[str, object]:
            return {
                "schema_version": "lazarus.semantic-proposal/v1",
                "case_id": "cal-04",
                "proposals": [
                    {
                        "proposal_id": "alias-candidate",
                        "relation_type": "resource_alias_candidate",
                        "subject": subject,
                        "object": object_,
                        "citations": [
                            {
                                "artifact_id": "runbook",
                                "digest": artifact_digest(runbook),
                                "start": 0,
                                "end": len(runbook),
                                "quote": runbook,
                            }
                        ],
                    }
                ],
                "abstained": False,
                "requested_evidence": [],
            }

        consequential = compile_case(
            case_dir,
            "b-replay",
            semantic=response("inventory-main", "stock store"),
        )
        diagnostic_only = compile_case(
            case_dir,
            "b-replay",
            semantic=response("unrelated-a", "unrelated-b"),
        )

        self.assertIn(
            "SEMANTIC_CONFIRMATION_REQUIRED",
            {blocker["code"] for blocker in consequential["blockers"]},
        )
        self.assertNotIn(
            "SEMANTIC_CONFIRMATION_REQUIRED",
            {blocker["code"] for blocker in diagnostic_only["blockers"]},
        )

    def test_a1_does_not_combine_stale_proof_with_a_failing_fresh_canary(self) -> None:
        source = Path(__file__).resolve().parents[1] / "fixtures" / "calibration" / "case-04"
        with tempfile.TemporaryDirectory() as temporary:
            case_dir = Path(temporary) / "case"
            shutil.copytree(source, case_dir)
            manifest_path = case_dir / "inputs" / "manifest.json"
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            manifest["services"][0]["dependencies"][0]["resource_ref"] = "inventory-main"
            manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
            ledger_path = case_dir / "inputs" / "ledger.json"
            scope = {
                "resource_ref": "inventory-main",
                "project": "core-platform",
                "environment": "production",
                "generation": "gen-6",
            }
            ledger_path.write_text(
                json.dumps(
                    {
                        "records": [
                            {
                                **scope,
                                "tested_at": "2026-08-10T12:00:00Z",
                                "application_canary": True,
                            },
                            {
                                **scope,
                                "tested_at": "2026-08-12T11:59:00Z",
                                "application_canary": False,
                            },
                        ]
                    }
                ),
                encoding="utf-8",
            )

            packet = compile_case(case_dir, "a1")

        codes = {blocker["code"] for blocker in packet["blockers"]}
        self.assertIn("RECOVERY_EVIDENCE_STALE", codes)
        self.assertIn("DEPENDENCY_RECOVERY_EVIDENCE_MISSING", codes)


if __name__ == "__main__":
    unittest.main()
