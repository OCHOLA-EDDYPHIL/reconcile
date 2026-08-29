from __future__ import annotations

import hashlib
import json
import shutil
import stat
import subprocess
from pathlib import Path

import pytest

from tests.unit.viewer.conftest import EVIDENCE_ROOT, ROOT, VIEWER_SOURCE_REVISION
from viewer.export import (
    ViewerExportError,
    _build_snapshot,
    _verified_viewer_source,
    export_bundle,
    stage_build_context,
)
from viewer.public_contract import decode_snapshot
from viewer.server import load_bundle

pytestmark = pytest.mark.unit


def test_versioned_evidence_projects_distinct_source_identities() -> None:
    snapshot = _build_snapshot(EVIDENCE_ROOT, VIEWER_SOURCE_REVISION)
    provider = json.loads((EVIDENCE_ROOT / "provider-proof.json").read_bytes())

    assert snapshot["viewer_source_revision"] == VIEWER_SOURCE_REVISION
    assert (
        snapshot["evidence_source_revision"] == provider["candidate"]["source_revision"]
    )
    assert snapshot["viewer_source_revision"] != snapshot["evidence_source_revision"]
    assert snapshot["evidence_version"] == "v0.1.0"
    assert snapshot["recovery"]["initial_classification"] == "UNKNOWN"
    assert snapshot["recovery"]["initial_action_permits_issued"] == 0
    assert snapshot["recovery"]["all_permits_single_use"] is True
    assert snapshot["recovery"]["replay_contacted_provider"] is False


def test_export_writes_one_closed_immutable_bundle(
    tmp_path: Path,
    viewer_bundle: Path,
) -> None:
    assert {path.name for path in viewer_bundle.iterdir()} == {
        "bundle-manifest.json",
        "index.html",
        "snapshot.json",
    }
    assert stat.S_IMODE(viewer_bundle.stat().st_mode) == 0o700
    assert all(
        stat.S_IMODE(path.stat().st_mode) == 0o400 for path in viewer_bundle.iterdir()
    )
    responses = load_bundle(viewer_bundle)
    assert set(responses) == {
        "/",
        "/index.html",
        "/snapshot.json",
        "/bundle-manifest.json",
        "/health",
    }
    snapshot = decode_snapshot(responses["/snapshot.json"][0])
    assert snapshot["viewer_source_revision"] == VIEWER_SOURCE_REVISION

    with pytest.raises(ViewerExportError, match="OUTPUT_DIRECTORY_INVALID"):
        export_bundle(EVIDENCE_ROOT, viewer_bundle)


def test_export_rejects_changed_or_extra_evidence(tmp_path: Path) -> None:
    copied = tmp_path / "v0.1.0"
    shutil.copytree(EVIDENCE_ROOT, copied)
    provider_path = copied / "provider-proof.json"
    provider = json.loads(provider_path.read_bytes())
    provider["effects"]["revisions"] += 1
    provider_path.write_text(json.dumps(provider), encoding="utf-8")

    with pytest.raises(ViewerExportError, match="EVIDENCE_CONTRACT_INVALID"):
        _build_snapshot(copied, VIEWER_SOURCE_REVISION)

    shutil.rmtree(copied)
    shutil.copytree(EVIDENCE_ROOT, copied)
    (copied / "unexpected.json").write_text("{}", encoding="utf-8")
    with pytest.raises(ViewerExportError, match="EVIDENCE_DIRECTORY_INVALID"):
        _build_snapshot(copied, VIEWER_SOURCE_REVISION)


def test_projection_binds_exact_versioned_evidence_bytes() -> None:
    snapshot = _build_snapshot(EVIDENCE_ROOT, VIEWER_SOURCE_REVISION)

    assert (
        snapshot["evidence"]["manifest_sha256"]
        == hashlib.sha256(
            (EVIDENCE_ROOT / "proof-to-permit.json").read_bytes()
        ).hexdigest()
    )
    assert (
        snapshot["evidence"]["provider_proof_sha256"]
        == hashlib.sha256(
            (EVIDENCE_ROOT / "provider-proof.json").read_bytes()
        ).hexdigest()
    )


def test_export_rejects_generated_bundle_inside_repository(
    verified_viewer_source: None,
) -> None:
    output = ROOT / "viewer" / "bundle"

    with pytest.raises(ViewerExportError, match="OUTPUT_MUST_BE_OUTSIDE_REPOSITORY"):
        export_bundle(EVIDENCE_ROOT, output)
    assert not output.exists()


def test_viewer_source_must_be_clean_exact_main(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repository = tmp_path / "repository"
    viewer = repository / "viewer"
    viewer.mkdir(parents=True)
    for name in ("Dockerfile", "public_contract.py", "server.py"):
        (viewer / name).write_bytes((ROOT / "viewer" / name).read_bytes())
    subprocess.run(("git", "init", "--initial-branch=main"), cwd=repository, check=True)
    subprocess.run(("git", "config", "user.name", "Test"), cwd=repository, check=True)
    subprocess.run(
        ("git", "config", "user.email", "test@example.com"),
        cwd=repository,
        check=True,
    )
    subprocess.run(("git", "add", "viewer"), cwd=repository, check=True)
    subprocess.run(("git", "commit", "-m", "viewer"), cwd=repository, check=True)
    revision = subprocess.run(
        ("git", "rev-parse", "HEAD"),
        cwd=repository,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    subprocess.run(
        ("git", "update-ref", "refs/remotes/origin/main", revision),
        cwd=repository,
        check=True,
    )
    monkeypatch.setattr("viewer.export._REPOSITORY_ROOT", repository)
    monkeypatch.setattr("viewer.export._VIEWER_ROOT", viewer)

    observed_revision, sources = _verified_viewer_source(revision)

    assert observed_revision == revision
    assert set(sources) == {"Dockerfile", "public_contract.py", "server.py"}
    (viewer / "server.py").write_text("changed", encoding="utf-8")
    with pytest.raises(ViewerExportError, match="VIEWER_SOURCE_NOT_EXACT_MAIN"):
        _verified_viewer_source(revision)


def test_external_build_context_contains_only_runtime_and_validated_bundle(
    tmp_path: Path,
    viewer_bundle: Path,
) -> None:
    context = tmp_path / "viewer-context"

    stage_build_context(viewer_bundle, context)

    assert {str(path.relative_to(context)) for path in context.rglob("*")} == {
        "Dockerfile",
        "public_contract.py",
        "server.py",
        "bundle",
        "bundle/index.html",
        "bundle/snapshot.json",
        "bundle/bundle-manifest.json",
    }
    assert (context / "Dockerfile").read_bytes() == (
        ROOT / "viewer" / "Dockerfile"
    ).read_bytes()
    with pytest.raises(ViewerExportError, match="BUILD_CONTEXT_DIRECTORY_INVALID"):
        stage_build_context(viewer_bundle, context)
