from __future__ import annotations

from pathlib import Path

import pytest

from viewer import export as viewer_export

ROOT = Path(__file__).parents[3]
EVIDENCE_ROOT = ROOT / "evidence" / "v0.1.0"
VIEWER_SOURCE_REVISION = "a" * 40


@pytest.fixture
def verified_viewer_source(monkeypatch: pytest.MonkeyPatch) -> None:
    source_payloads = {
        name: (ROOT / "viewer" / name).read_bytes()
        for name in viewer_export._BUILD_CONTEXT_FILES
    }
    monkeypatch.setattr(
        viewer_export,
        "_verified_viewer_source",
        lambda expected_revision=None: (
            VIEWER_SOURCE_REVISION,
            source_payloads,
        ),
    )


@pytest.fixture
def viewer_bundle(tmp_path: Path, verified_viewer_source: None) -> Path:
    output = tmp_path / "bundle"
    viewer_export.export_bundle(EVIDENCE_ROOT, output)
    return output
