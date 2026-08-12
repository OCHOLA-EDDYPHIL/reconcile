from __future__ import annotations

import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from lazarus.benchmark import _recovery_repeatability, freeze_benchmark
from lazarus.locking import canonical_sha256
from lazarus.cli import main


FIXTURES = Path(__file__).resolve().parents[1] / "fixtures"
MODEL_SETTINGS = {
    "provider": "local-replay",
    "model": "bounded-resolver-v1",
    "parameters": {
        "temperature": 0,
        "top_p": 1,
        "max_output_tokens": 1024,
    },
    "retry": {"max_attempts": 1, "backoff_seconds": 0},
}


class CliTests(unittest.TestCase):
    def test_direct_commands_refuse_heldout_without_executing_it(self) -> None:
        heldout = {
            "schema_version": "lazarus.case/v1",
            "case_id": "opaque-case",
            "split": "heldout",
        }
        with (
            mock.patch("lazarus.cli.load_case", return_value=(heldout, {})),
            mock.patch("lazarus.cli.compile_case") as compile_mock,
            mock.patch("lazarus.cli.run_recovery") as recovery_mock,
        ):
            self.assertEqual(main(["compile", "/opaque", "--arm", "a1"]), 2)
            self.assertEqual(main(["restore", "/opaque"]), 2)
            compile_mock.assert_not_called()
            recovery_mock.assert_not_called()

    def test_validates_suite_and_calibration_case(self) -> None:
        self.assertEqual(main(["validate", str(FIXTURES), "--suite"]), 0)
        self.assertEqual(
            main(["validate", str(FIXTURES / "calibration" / "case-01")]),
            0,
        )

    def test_compiles_calibration_packet_without_overwrite(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "packet.json"
            arguments = [
                "compile",
                str(FIXTURES / "calibration" / "case-01"),
                "--arm",
                "a1-rules",
                "--output",
                str(output),
            ]
            self.assertEqual(main(arguments), 0)
            packet = json.loads(output.read_text(encoding="utf-8"))
            self.assertEqual(packet["schema_version"], "lazarus.evidence-packet/v1")
            self.assertEqual(main(arguments), 2)

    def test_restore_repeatability_uses_visible_case(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "recovery.json"
            self.assertEqual(
                main(
                    [
                        "restore",
                        str(FIXTURES / "calibration" / "case-01"),
                        "--repeat",
                        "2",
                        "--output",
                        str(output),
                    ]
                ),
                0,
            )
            result = json.loads(output.read_text(encoding="utf-8"))
            self.assertEqual(result["schema_version"], "lazarus.recovery-case-run/v1")
            self.assertTrue(result["passed"])
            self.assertEqual(result["identical"], 2)

    def test_repeatability_command_produces_locked_six_state_bundle(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            lock = root / "lock.json"
            settings = root / "settings.json"
            output = root / "repeatability.json"
            settings.write_text(json.dumps(MODEL_SETTINGS), encoding="utf-8")
            freeze_benchmark(
                FIXTURES,
                model_settings=MODEL_SETTINGS,
                destination=lock,
            )

            self.assertEqual(
                main(
                    [
                        "repeatability",
                        str(FIXTURES),
                        "--lock",
                        str(lock),
                        "--model-settings",
                        str(settings),
                        "--repository-root",
                        str(Path(__file__).resolve().parents[1]),
                        "--output",
                        str(output),
                    ]
                ),
                0,
            )

            bundle = json.loads(output.read_text(encoding="utf-8"))
            self.assertEqual(bundle["repeat"], 20)
            self.assertEqual(
                set(bundle["states"]),
                {"fresh", "schema", "invariant", "stale", "rto", "cleanup"},
            )
            self.assertTrue(
                all(len(state["runs"]) == 20 for state in bundle["states"].values())
            )
            lock_digest = canonical_sha256(
                json.loads(lock.read_text(encoding="utf-8"))
            )
            self.assertTrue(
                _recovery_repeatability(
                    bundle,
                    protocol_lock_digest=lock_digest,
                    fixtures_root=FIXTURES,
                )["passed"]
            )

    def test_renders_only_a_registered_visible_model_input(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "input.json"
            self.assertEqual(
                main(
                    [
                        "render-input",
                        str(FIXTURES),
                        str(FIXTURES / "calibration" / "case-01"),
                        "--arm",
                        "b-replay",
                        "--output",
                        str(output),
                    ]
                ),
                0,
            )
            value = json.loads(output.read_text(encoding="utf-8"))
            self.assertEqual(value["schema_version"], "lazarus.model-input/v1")
            self.assertEqual(value["case"]["case_id"], "cal-01")


if __name__ == "__main__":
    unittest.main()
