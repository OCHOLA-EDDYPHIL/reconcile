from __future__ import annotations

import hashlib
import importlib.util
import json
import shutil
from pathlib import Path
from typing import Any

import pytest

ROOT = Path(__file__).resolve().parents[2]
EVIDENCE_SOURCE = ROOT / "demo" / "evidence"
REPLAY_PATH = ROOT / "scripts" / "replay_gate_g5r.py"

SPEC = importlib.util.spec_from_file_location("replay_gate_g5r", REPLAY_PATH)
assert SPEC is not None and SPEC.loader is not None
REPLAY = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(REPLAY)


@pytest.fixture
def evidence_path(tmp_path: Path) -> Path:
    target = tmp_path / "evidence"
    shutil.copytree(EVIDENCE_SOURCE, target)
    return target / "proof-to-permit.json"


def _rewrite(path: Path, key_path: tuple[str | int, ...], value: Any) -> None:
    payload = json.loads(path.read_text(encoding="utf-8"))
    cursor = payload
    for key in key_path[:-1]:
        cursor = cursor[key]
    cursor[key_path[-1]] = value
    path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")


def test_final_candidate_bundle_is_coherent() -> None:
    payload = REPLAY.load_and_validate(EVIDENCE_SOURCE / "proof-to-permit.json")

    provider = payload["provider_proof"]
    assert provider["candidate"]["source_revision"] == REPLAY.SOURCE_REVISION
    assert provider["run_id"] == REPLAY.RUN_ID
    assert provider["acceptance"]["event_count"] == 49
    assert (
        payload["live_corroboration"]["firestore"]["durable_recovery_event_count"]
        == provider["acceptance"]["event_count"]
    )
    assert payload["cleanup_verification"]["status"] == "PASS"

    provider_bytes = (EVIDENCE_SOURCE / "provider-proof.json").read_bytes()
    assert (
        hashlib.sha256(provider_bytes).hexdigest()
        == payload["live_corroboration"]["provider_projection_sha256"]
    )
    index_text = (EVIDENCE_SOURCE / "proof-to-permit.json").read_text(encoding="utf-8")
    assert "generated_from" not in index_text
    assert "https://" not in index_text


@pytest.mark.parametrize(
    ("filename", "key_path", "replacement"),
    [
        (
            "provider-proof.json",
            ("candidate", "source_revision"),
            "0" * 40,
        ),
        ("provider-proof.json", ("run_id",), "p5r-adaptive-" + "0" * 32),
        ("provider-proof.json", ("effects", "revisions"), 2),
        ("provider-proof.json", ("permits", 0, "max_uses"), 2),
        ("provider-proof.json", ("replay", "provider_contact"), True),
        (
            "live-corroboration.json",
            ("firestore", "durable_recovery_event_count"),
            48,
        ),
        (
            "live-corroboration.json",
            ("gemini", "reported_model"),
            "gemini-tampered",
        ),
        (
            "live-corroboration.json",
            ("provider_projection_sha256",),
            "0" * 64,
        ),
        (
            "live-corroboration.json",
            ("source_revision",),
            "0" * 40,
        ),
        (
            "live-corroboration.json",
            ("captured_at",),
            "2099-01-01T00:00:00Z",
        ),
        (
            "cleanup-verification.json",
            ("run_id",),
            "p5r-adaptive-" + "0" * 32,
        ),
        (
            "cleanup-verification.json",
            ("live_corroboration_sha256",),
            "0" * 64,
        ),
        (
            "cleanup-verification.json",
            ("captured_at",),
            "2099-01-02T00:00:00Z",
        ),
        (
            "cleanup-verification.json",
            ("inventory", "cloud_run_services"),
            1,
        ),
    ],
)
def test_candidate_or_cross_file_tampering_is_rejected(
    evidence_path: Path,
    filename: str,
    key_path: tuple[str | int, ...],
    replacement: Any,
) -> None:
    _rewrite(evidence_path.parent / filename, key_path, replacement)

    with pytest.raises(REPLAY.EvidenceError):
        REPLAY.load_and_validate(evidence_path)


def test_provider_projection_hash_covers_exact_bytes(evidence_path: Path) -> None:
    provider_path = evidence_path.parent / "provider-proof.json"
    provider_path.write_bytes(provider_path.read_bytes() + b" ")

    with pytest.raises(REPLAY.EvidenceError, match="provider proof bytes"):
        REPLAY.load_and_validate(evidence_path)


def test_manifest_digest_tampering_is_rejected(evidence_path: Path) -> None:
    _rewrite(evidence_path, ("live_gate", "cleanup_verification_sha256"), "0" * 64)

    with pytest.raises(REPLAY.EvidenceError):
        REPLAY.load_and_validate(evidence_path)


def test_unexpected_generated_from_metadata_is_rejected(evidence_path: Path) -> None:
    _rewrite(evidence_path, ("generated_from",), {"source": "private-placeholder"})

    with pytest.raises(REPLAY.EvidenceError, match="evidence index fields changed"):
        REPLAY.load_and_validate(evidence_path)


def test_duplicate_json_key_is_rejected(evidence_path: Path) -> None:
    live_path = evidence_path.parent / "live-corroboration.json"
    text = live_path.read_text(encoding="utf-8")
    live_path.write_text(
        text.replace(
            '  "status": "PASS",',
            '  "status": "PASS",\n  "status": "PASS",',
            1,
        ),
        encoding="utf-8",
    )

    with pytest.raises(REPLAY.EvidenceError, match="duplicate JSON key"):
        REPLAY.load_and_validate(evidence_path)


def test_nonfinite_json_number_is_rejected(evidence_path: Path) -> None:
    live_path = evidence_path.parent / "live-corroboration.json"
    text = live_path.read_text(encoding="utf-8")
    live_path.write_text(
        text.replace('"service_count": 5', '"service_count": NaN', 1),
        encoding="utf-8",
    )

    with pytest.raises(REPLAY.EvidenceError, match="non-standard JSON number"):
        REPLAY.load_and_validate(evidence_path)


@pytest.mark.parametrize("prefix", [b"\xef\xbb\xbf", b"\xff"])
def test_noncanonical_encoding_is_rejected(evidence_path: Path, prefix: bytes) -> None:
    cleanup_path = evidence_path.parent / "cleanup-verification.json"
    cleanup_path.write_bytes(prefix + cleanup_path.read_bytes())

    with pytest.raises(REPLAY.EvidenceError, match=r"strict JSON|BOM"):
        REPLAY.load_and_validate(evidence_path)
