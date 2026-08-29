from __future__ import annotations

import ast
from pathlib import Path

import pytest

pytestmark = pytest.mark.unit

ROOT = Path(__file__).parents[3]
VIEWER = ROOT / "viewer"


def test_viewer_image_has_separate_source_identities_and_readonly_runtime() -> None:
    dockerfile = (VIEWER / "Dockerfile").read_text(encoding="utf-8")

    assert "python:3.12.13-slim-bookworm@sha256:" in dockerfile
    assert 'test "${#VIEWER_SOURCE_REVISION}" -eq 40' in dockerfile
    assert 'test "${#EVIDENCE_SOURCE_REVISION}" -eq 40' in dockerfile
    assert 'test "${#SNAPSHOT_SHA256}" -eq 64' in dockerfile
    assert "sha256sum --check --strict" in dockerfile
    assert "RECONCILE_VIEWER_SOURCE_REVISION=${VIEWER_SOURCE_REVISION}" in dockerfile
    assert (
        "RECONCILE_EVIDENCE_SOURCE_REVISION=${EVIDENCE_SOURCE_REVISION}" in dockerfile
    )
    assert "USER 65532:65532" in dockerfile
    assert 'ENTRYPOINT ["python", "/app/server.py"]' in dockerfile


def test_docker_context_allows_only_code_and_three_public_files() -> None:
    entries = set((VIEWER / ".dockerignore").read_text(encoding="utf-8").splitlines())

    assert entries == {
        "**",
        "!Dockerfile",
        "!server.py",
        "!public_contract.py",
        "!bundle/",
        "!bundle/index.html",
        "!bundle/snapshot.json",
        "!bundle/bundle-manifest.json",
    }


@pytest.mark.parametrize("name", ("public_contract.py", "server.py"))
def test_runtime_modules_import_only_the_standard_library_or_each_other(
    name: str,
) -> None:
    tree = ast.parse((VIEWER / name).read_text(encoding="utf-8"))
    roots: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            roots.update(item.name.split(".", 1)[0] for item in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            roots.add(node.module.split(".", 1)[0])

    assert roots <= {
        "__future__",
        "collections",
        "hashlib",
        "html",
        "http",
        "json",
        "os",
        "pathlib",
        "public_contract",
        "re",
        "stat",
        "typing",
        "urllib",
    }
