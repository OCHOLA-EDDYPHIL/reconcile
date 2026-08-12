from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest import mock

from lazarus.recovery import run_recovery, run_recovery_matrix


FIXTURES = Path(__file__).resolve().parents[1] / "fixtures"


class RecoveryHarnessTests(unittest.TestCase):
    def setUp(self) -> None:
        self.case_directory = tempfile.TemporaryDirectory()
        self.case_path = Path(self.case_directory.name)

    def tearDown(self) -> None:
        self.case_directory.cleanup()

    def _write_dump(
        self,
        name: str = "backup.sql",
        *,
        include_ledger: bool = True,
        negative_balance: bool = False,
    ) -> str:
        second_balance = -25 if negative_balance else 25
        ledger_sql = ""
        if include_ledger:
            ledger_sql = """
CREATE TABLE ledger (
    id INTEGER PRIMARY KEY,
    account_id INTEGER NOT NULL REFERENCES accounts(id),
    amount INTEGER NOT NULL
);
INSERT INTO ledger(id, account_id, amount) VALUES (1, 1, 100);
INSERT INTO ledger(id, account_id, amount) VALUES (2, 2, 25);
"""
        dump = f"""
PRAGMA foreign_keys = ON;
PRAGMA user_version = 3;
CREATE TABLE accounts (
    id INTEGER PRIMARY KEY,
    owner TEXT NOT NULL,
    balance INTEGER NOT NULL
);
INSERT INTO accounts(id, owner, balance) VALUES (1, 'Ada', 100);
INSERT INTO accounts(id, owner, balance) VALUES (2, 'Lin', {second_balance});
{ledger_sql}
"""
        (self.case_path / name).write_text(dump, encoding="utf-8")
        return name

    def _config(self, dump_path: str, **overrides: object) -> dict[str, object]:
        config: dict[str, object] = {
            "dump_path": dump_path,
            "backup_created_at": "2026-08-12T11:59:30Z",
            "reference_time": "2026-08-12T12:00:00+00:00",
            "rpo_seconds": 60,
            "rto_ms": 60_000,
            "minimum_delay_ms": 0,
            "expected_schema_version": 3,
            "required_tables": ["accounts", "ledger"],
            "assertions": [
                {
                    "assertion_id": "account_count",
                    "sql": "SELECT COUNT(*) FROM accounts",
                    "expected": 2,
                },
                {
                    "assertion_id": "nonnegative_balances",
                    "sql": "SELECT COUNT(*) FROM accounts WHERE balance < 0",
                    "expected": 0,
                },
                {
                    "assertion_id": "ledger_total",
                    "sql": "SELECT SUM(amount) FROM ledger",
                    "expected": 125,
                },
            ],
        }
        config.update(overrides)
        return config

    @staticmethod
    def _check(result: dict[str, object], check_id: str) -> dict[str, object]:
        canary = result["canary"]
        assert isinstance(canary, dict)
        checks = canary["checks"]
        assert isinstance(checks, list)
        return next(check for check in checks if check["check_id"] == check_id)

    @staticmethod
    def _signature(result: dict[str, object]) -> tuple[object, ...]:
        return (
            result["classification"],
            result["restore"]["status"],
            result["canary"]["status"],
            result["rpo"]["status"],
            result["rto"]["status"],
            result["cleanup"]["status"],
        )

    def test_fresh_restore_passes_every_component(self) -> None:
        config = self._config(self._write_dump())

        result = run_recovery(self.case_path, config)

        self.assertEqual("pass", result["classification"])
        for component in ("restore", "canary", "rpo", "rto", "cleanup"):
            self.assertEqual("pass", result[component]["status"])
        self.assertEqual(30, result["rpo"]["age_seconds"])
        self.assertEqual(60, result["rpo"]["objective_seconds"])
        self.assertTrue(
            all(
                check["status"] == "pass"
                for check in result["canary"]["checks"]
            )
        )

    def test_missing_required_schema_fails_canary(self) -> None:
        dump_path = self._write_dump(include_ledger=False)
        config = self._config(
            dump_path,
            assertions=[
                {
                    "assertion_id": "account_count",
                    "sql": "SELECT COUNT(*) FROM accounts",
                    "expected": 2,
                }
            ],
        )

        result = run_recovery(self.case_path, config)

        self.assertEqual("pass", result["restore"]["status"])
        self.assertEqual("fail", result["canary"]["status"])
        self.assertEqual("fail", self._check(result, "schema")["status"])
        self.assertEqual("fail", result["classification"])

    def test_business_invariant_failure_is_not_a_restore_failure(self) -> None:
        config = self._config(self._write_dump(negative_balance=True))

        result = run_recovery(self.case_path, config)

        self.assertEqual("pass", result["restore"]["status"])
        self.assertEqual("fail", result["canary"]["status"])
        invariant = self._check(result, "nonnegative_balances:invariant")
        self.assertEqual("fail", invariant["status"])
        self.assertEqual(0, invariant["expected"])
        self.assertEqual(1, invariant["actual"])
        self.assertEqual("fail", result["classification"])

    def test_stale_backup_fails_rpo(self) -> None:
        config = self._config(
            self._write_dump(),
            backup_created_at="2026-08-12T11:57:59Z",
            rpo_seconds=120,
        )

        result = run_recovery(self.case_path, config)

        self.assertEqual("fail", result["rpo"]["status"])
        self.assertEqual(121, result["rpo"]["age_seconds"])
        self.assertEqual("fail", result["classification"])

    def test_controlled_delay_produces_rto_breach(self) -> None:
        config = self._config(
            self._write_dump(), minimum_delay_ms=10, rto_ms=1
        )

        result = run_recovery(self.case_path, config)

        self.assertEqual("pass", result["restore"]["status"])
        self.assertEqual("pass", result["canary"]["status"])
        self.assertEqual("fail", result["rto"]["status"])
        self.assertGreaterEqual(result["rto"]["elapsed_ms"], 10)
        self.assertEqual("fail", result["classification"])

    def test_injected_cleanup_failure_fails_and_fallback_removes_directory(self) -> None:
        config = self._config(
            self._write_dump(), simulate_cleanup_failure=True
        )
        real_temporary_directory = tempfile.TemporaryDirectory
        created_paths: list[Path] = []

        def record_directory(
            *args: object, **kwargs: object
        ) -> tempfile.TemporaryDirectory[str]:
            directory = real_temporary_directory(*args, **kwargs)
            created_paths.append(Path(directory.name))
            return directory

        with mock.patch(
            "lazarus.recovery.tempfile.TemporaryDirectory",
            side_effect=record_directory,
        ):
            result = run_recovery(self.case_path, config)

        self.assertEqual("fail", result["cleanup"]["status"])
        self.assertEqual("fail", result["classification"])
        self.assertEqual(1, len(created_paths))
        self.assertFalse(created_paths[0].exists())

    def test_missing_rpo_input_stays_unknown(self) -> None:
        config = self._config(self._write_dump())
        del config["reference_time"]

        result = run_recovery(self.case_path, config)

        self.assertEqual("unknown", result["rpo"]["status"])
        self.assertEqual("unknown", result["classification"])

    def test_missing_dump_stays_unknown_and_cleanup_still_passes(self) -> None:
        config = self._config("absent.sql")

        result = run_recovery(self.case_path, config)

        self.assertEqual("unknown", result["restore"]["status"])
        self.assertEqual("unknown", result["canary"]["status"])
        self.assertEqual("unknown", result["rto"]["status"])
        self.assertEqual("pass", result["cleanup"]["status"])
        self.assertEqual("unknown", result["classification"])

    def test_state_classifications_repeat_twenty_times(self) -> None:
        lock_digest = "a" * 64
        bundle = run_recovery_matrix(
            FIXTURES,
            protocol_lock_digest=lock_digest,
        )

        self.assertEqual(bundle["repeat"], 20)
        self.assertEqual(bundle["protocol_lock_digest"], lock_digest)
        for state, evidence in bundle["states"].items():
            with self.subTest(state=state):
                runs = evidence["runs"]
                self.assertEqual(len(runs), 20)
                expected = tuple(
                    evidence["expected_signature"][field]
                    for field in (
                        "classification",
                        "restore",
                        "canary",
                        "rpo",
                        "rto",
                        "cleanup",
                    )
                )
                self.assertEqual(
                    {self._signature(run["result"]) for run in runs},
                    {expected},
                )
                self.assertTrue(
                    all(run["protocol_lock_digest"] == lock_digest for run in runs)
                )


if __name__ == "__main__":
    unittest.main()
