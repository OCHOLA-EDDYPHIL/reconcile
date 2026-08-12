from __future__ import annotations

import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from lazarus.benchmark import build_model_input, load_case
from lazarus.falsification import (
    EXPECTED_GENERATION_CALLS,
    FalsificationError,
    build_registered_model_settings,
    read_api_key,
    run_registered_falsification,
)
from lazarus.gemini import RequestPacer, build_generate_content_request
from lazarus.locking import canonical_json_bytes, canonical_sha256


REPOSITORY = Path(__file__).resolve().parents[1]


class _Response:
    status = 200

    def __init__(self, payload: bytes):
        self._payload = payload

    def read(self) -> bytes:
        return self._payload

    def close(self) -> None:
        return None


class _EmptySemanticTransport:
    def __init__(self, *, complete: bool = True) -> None:
        self.calls = 0
        self.complete = complete

    def __call__(self, request, timeout: float) -> _Response:
        self.calls += 1
        self.assert_timeout = timeout
        request_body = json.loads(request.data)
        model_input = json.loads(request_body["contents"][0]["parts"][0]["text"])
        case_id = model_input["case"]["case_id"]
        semantic = {
            "schema_version": "lazarus.semantic-proposal/v1",
            "case_id": case_id,
            "proposals": [],
            "abstained": False,
            "requested_evidence": [],
        }
        response_text = canonical_json_bytes(semantic).decode("utf-8")
        payload = {
            "responseId": f"calibration-response-{self.calls}",
            "modelVersion": "gemini-3.6-flash",
            "candidates": [
                {
                    "index": 0,
                    "finishReason": "STOP" if self.complete else "MAX_TOKENS",
                    "content": {
                        "role": "model",
                        "parts": [
                            {"text": response_text if self.complete else "{"}
                        ],
                    },
                    "safetyRatings": [],
                }
            ],
            "usageMetadata": {
                "promptTokenCount": 1,
                "candidatesTokenCount": 1,
                "totalTokenCount": 2,
            },
        }
        return _Response(canonical_json_bytes(payload))


def _virtual_pacer() -> tuple[RequestPacer, list[float]]:
    monotonic_time = [0.0]
    sleeps: list[float] = []

    def sleep(seconds: float) -> None:
        sleeps.append(seconds)
        monotonic_time[0] += seconds

    return (
        RequestPacer(
            16,
            monotonic=lambda: monotonic_time[0],
            sleeper=sleep,
        ),
        sleeps,
    )


class SettingsTests(unittest.TestCase):
    def test_registered_settings_match_the_exact_rendered_request_schema(self) -> None:
        settings = build_registered_model_settings(REPOSITORY)
        case = load_case(REPOSITORY / "fixtures" / "calibration" / "case-01")
        model_input = build_model_input(
            case,
            "b-replay",
            REPOSITORY / "fixtures" / "protocol" / "prompts",
        )
        request = json.loads(build_generate_content_request(model_input))
        self.assertEqual(
            canonical_sha256(request["generationConfig"]["responseJsonSchema"]),
            settings["parameters"]["response_schema_sha256"],
        )
        self.assertEqual(
            request["generationConfig"]["thinkingConfig"],
            {"thinkingLevel": "MINIMAL", "includeThoughts": False},
        )
        self.assertEqual(
            settings["thinking"],
            {"level": "MINIMAL", "include_thoughts": False},
        )
        self.assertEqual(settings["request"]["minimum_interval_seconds"], 16)
        self.assertEqual(settings["retry"], {"max_attempts": 1, "backoff_seconds": 0})
        self.assertEqual(EXPECTED_GENERATION_CALLS, 16)

    def test_api_key_reader_never_accepts_multiline_or_symlink_input(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            key = root / "key"
            key.write_text("test-token\n", encoding="utf-8")
            self.assertEqual(read_api_key(key), "test-token")
            key.write_text("two tokens\nare invalid\n", encoding="utf-8")
            with self.assertRaises(FalsificationError):
                read_api_key(key)
            key.write_text("test-token\n", encoding="utf-8")
            link = root / "link"
            link.symlink_to(key)
            with self.assertRaises(FalsificationError):
                read_api_key(link)


class CalibrationBoundaryTests(unittest.TestCase):
    def test_incomplete_calibration_never_generates_a_heldout_suite(self) -> None:
        transport = _EmptySemanticTransport(complete=False)
        pacer, sleeps = _virtual_pacer()
        repository_state = {
            "head_sha": "1" * 40,
            "tree_sha": "2" * 40,
            "tracked_clean": True,
        }
        with tempfile.TemporaryDirectory(dir=REPOSITORY) as temporary:
            run_root = Path(temporary) / "run"
            with (
                mock.patch("lazarus.falsification._verify_repository"),
                mock.patch(
                    "lazarus.locking._repository_state",
                    return_value=repository_state,
                ),
                mock.patch(
                    "lazarus.falsification._git_state",
                    return_value=repository_state,
                ),
            ):
                outcome = run_registered_falsification(
                    REPOSITORY,
                    run_root,
                    api_key="test-key",
                    transport=transport,
                    pacer=pacer,
                    require_exact_main=False,
                )
            self.assertEqual(transport.calls, 4)
            self.assertEqual(transport.assert_timeout, 120)
            self.assertEqual(outcome.summary["generation_calls"], 4)
            self.assertEqual(outcome.summary["disposition"], "calibration_failed")
            self.assertEqual(sleeps, [16.0] * 3)
            self.assertFalse((run_root / "runtime" / "public-suite").exists())
            self.assertEqual(
                len(list((run_root / "calibration-run" / "calibration").glob("*/raw-response.json"))),
                4,
            )

    def test_valid_transport_reaches_the_concept_score_without_model_gain(self) -> None:
        transport = _EmptySemanticTransport()
        pacer, sleeps = _virtual_pacer()
        repository_state = {
            "head_sha": "1" * 40,
            "tree_sha": "2" * 40,
            "tracked_clean": True,
        }
        with tempfile.TemporaryDirectory(dir=REPOSITORY) as temporary:
            run_root = Path(temporary) / "run"
            with (
                mock.patch("lazarus.falsification._verify_repository"),
                mock.patch(
                    "lazarus.locking._repository_state",
                    return_value=repository_state,
                ),
                mock.patch(
                    "lazarus.falsification._git_state",
                    return_value=repository_state,
                ),
            ):
                outcome = run_registered_falsification(
                    REPOSITORY,
                    run_root,
                    api_key="test-key",
                    transport=transport,
                    pacer=pacer,
                    require_exact_main=False,
                )
            self.assertEqual(transport.calls, EXPECTED_GENERATION_CALLS)
            self.assertEqual(outcome.summary["generation_calls"], EXPECTED_GENERATION_CALLS)
            self.assertEqual(outcome.summary["disposition"], "concept_fail")
            self.assertEqual(sleeps, [16.0] * (EXPECTED_GENERATION_CALLS - 1))
            self.assertTrue((run_root / "control" / "benchmark-lock.json").is_file())
            self.assertEqual(
                len(list((run_root / "execution" / "evaluations").glob("*/raw-response.json"))),
                12,
            )


if __name__ == "__main__":
    unittest.main()
