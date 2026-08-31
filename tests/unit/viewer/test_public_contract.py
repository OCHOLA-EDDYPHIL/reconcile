from __future__ import annotations

import copy
import hashlib
import json

import pytest

from tests.unit.viewer.conftest import EVIDENCE_ROOT, VIEWER_SOURCE_REVISION
from viewer.export import _build_snapshot
from viewer.public_contract import (
    PublicContractError,
    canonical_json_bytes,
    decode_snapshot,
    render_html,
    validate_snapshot,
)

pytestmark = pytest.mark.unit


def _recompute_projection(snapshot: dict[str, object]) -> None:
    base = {key: value for key, value in snapshot.items() if key != "projection_sha256"}
    snapshot["projection_sha256"] = hashlib.sha256(
        canonical_json_bytes(base)
    ).hexdigest()


def test_snapshot_is_canonical_closed_and_self_bound() -> None:
    snapshot = _build_snapshot(EVIDENCE_ROOT, VIEWER_SOURCE_REVISION)
    payload = canonical_json_bytes(snapshot)

    assert decode_snapshot(payload) == snapshot
    with pytest.raises(PublicContractError, match="SNAPSHOT_INVALID"):
        decode_snapshot(payload + b" ")
    duplicate = payload.replace(
        b'{"advisory_planning":',
        b'{"advisory_planning":{},"advisory_planning":',
        1,
    )
    with pytest.raises(PublicContractError, match="SNAPSHOT_INVALID"):
        decode_snapshot(duplicate)


def test_snapshot_rejects_extra_run_data_after_projection_recomputation() -> None:
    snapshot = _build_snapshot(EVIDENCE_ROOT, VIEWER_SOURCE_REVISION)
    changed = copy.deepcopy(snapshot)
    changed["run_id"] = "not-part-of-the-public-contract"
    _recompute_projection(changed)

    with pytest.raises(PublicContractError, match="SNAPSHOT_INVALID"):
        validate_snapshot(changed)


def test_current_snapshot_rejects_inferred_legacy_fields() -> None:
    snapshot = _build_snapshot(EVIDENCE_ROOT, VIEWER_SOURCE_REVISION)
    changed = copy.deepcopy(snapshot)
    changed["recovery"]["initial_classification"] = "UNKNOWN"
    _recompute_projection(changed)

    with pytest.raises(PublicContractError, match="SNAPSHOT_RECOVERY_INVALID"):
        validate_snapshot(changed)


def test_legacy_snapshot_schema_cannot_describe_current_evidence() -> None:
    legacy = _build_snapshot(EVIDENCE_ROOT.parent / "v0.1.0", VIEWER_SOURCE_REVISION)
    legacy["evidence"]["manifest_schema_version"] = "reconcile/public-evidence/v1"
    _recompute_projection(legacy)

    with pytest.raises(PublicContractError, match="SNAPSHOT_INVALID"):
        validate_snapshot(legacy)


def test_current_html_renders_only_recorded_recovery_and_advisory_facts() -> None:
    snapshot = _build_snapshot(EVIDENCE_ROOT, VIEWER_SOURCE_REVISION)

    page = render_html(snapshot)

    for expected in (
        b"Recorded recovery",
        b"OUTCOME_UNKNOWN",
        b"COMPLETED",
        b"Continue permits issued: 2",
        b"Action permits consumed: 2",
        b"Rejected before provider contact: true",
        b"Provider contact delta: 0",
        b"Recorded authority: read-only-probe-planning-only",
    ):
        assert expected in page
    for unsupported in (
        b"Initial result",
        b"Settled result",
        b"single-use",
        b"bound to hypothesis",
    ):
        assert unsupported not in page


def test_viewer_source_contains_no_embedded_evidence_identity() -> None:
    provider = json.loads((EVIDENCE_ROOT / "provider-proof.json").read_bytes())
    forbidden = (
        provider["candidate"]["candidate_sha256"],
        provider["candidate"]["source_revision"],
        provider["candidate"]["image_digest"],
    )
    source = "\n".join(
        path.read_text(encoding="utf-8")
        for path in (
            EVIDENCE_ROOT.parents[1] / "viewer" / "export.py",
            EVIDENCE_ROOT.parents[1] / "viewer" / "public_contract.py",
            EVIDENCE_ROOT.parents[1] / "viewer" / "server.py",
        )
    )

    assert all(value not in source for value in forbidden)
