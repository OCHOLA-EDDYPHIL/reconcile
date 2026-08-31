#!/usr/bin/env python3
"""Build a checksum-bound release directory from checked repository bytes."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if __package__:
    from .validate_evidence import EvidenceError, load_and_validate
else:
    from validate_evidence import EvidenceError, load_and_validate

RELEASE_VERSION = "v0.1.1"
EVIDENCE_ROOT = ROOT / "evidence" / RELEASE_VERSION
CHECKSUM_NAME = f"reconcile-{RELEASE_VERSION}-SHA256SUMS.txt"
SOURCE_MANIFEST_NAME = f"reconcile-{RELEASE_VERSION}-SOURCE.json"
SOURCE_REPOSITORY = "https://github.com/OCHOLA-EDDYPHIL/reconcile"
SOURCE_REVISION = re.compile(r"^[0-9a-f]{40}$")
RELEASE_TAG = re.compile(r"^v[0-9]+[.][0-9]+[.][0-9]+$")
ASSETS = (
    (ROOT / "docs" / "architecture.png", "architecture.png"),
    (ROOT / "docs" / "deployment.png", "deployment.png"),
    (EVIDENCE_ROOT / "cleanup-verification.json", "cleanup-verification.json"),
    (EVIDENCE_ROOT / "live-corroboration.json", "live-corroboration.json"),
    (EVIDENCE_ROOT / "proof-to-permit.json", "proof-to-permit.json"),
    (EVIDENCE_ROOT / "provider-proof.json", "provider-proof.json"),
)
IMPLEMENTATION_SOURCES = (
    ROOT / "scripts" / "build_public_release.py",
    ROOT / "scripts" / "validate_evidence.py",
)


class ReleaseBuildError(RuntimeError):
    """The requested release directory is unsafe or inconsistent."""


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(128 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _project_version(source_revision: str) -> str:
    try:
        document = tomllib.loads(
            _committed_bytes(source_revision, ROOT / "pyproject.toml").decode("utf-8")
        )
    except (UnicodeError, tomllib.TOMLDecodeError) as error:
        raise ReleaseBuildError("project metadata is invalid") from error
    value = document.get("project", {}).get("version")
    if not isinstance(value, str):
        raise ReleaseBuildError("project version is missing")
    return f"v{value}"


def _resolve_git_ref(reference: str) -> str:
    try:
        completed = subprocess.run(
            ("git", "rev-parse", "--verify", f"{reference}^{{commit}}"),
            cwd=ROOT,
            check=True,
            capture_output=True,
            text=True,
        )
    except subprocess.SubprocessError as error:
        raise ReleaseBuildError("source revision is not a repository commit") from error
    resolved = completed.stdout.strip()
    if SOURCE_REVISION.fullmatch(resolved) is None:
        raise ReleaseBuildError("source revision did not resolve to a full commit hash")
    return resolved


def _resolve_source_revision(revision: str) -> str:
    if revision != "HEAD" and SOURCE_REVISION.fullmatch(revision) is None:
        raise ReleaseBuildError("source revision must be HEAD or a full commit hash")
    return _resolve_git_ref(revision)


def _committed_bytes(source_revision: str, source: Path) -> bytes:
    relative = source.relative_to(ROOT).as_posix()
    try:
        return subprocess.run(
            ("git", "show", f"{source_revision}:{relative}"),
            cwd=ROOT,
            check=True,
            capture_output=True,
        ).stdout
    except subprocess.SubprocessError as error:
        raise ReleaseBuildError(
            f"release source is absent from source revision: {relative}"
        ) from error


def _verify_loaded_implementation(source_revision: str) -> None:
    for source in IMPLEMENTATION_SOURCES:
        if _committed_bytes(source_revision, source) != source.read_bytes():
            relative = source.relative_to(ROOT).as_posix()
            raise ReleaseBuildError(
                f"release source differs from source revision: {relative}"
            )


def _verify_required_tag(required_tag: str, source_revision: str) -> None:
    if RELEASE_TAG.fullmatch(required_tag) is None or required_tag != RELEASE_VERSION:
        raise ReleaseBuildError("required tag must equal the release version")
    if _resolve_git_ref(f"refs/tags/{required_tag}") != source_revision:
        raise ReleaseBuildError("release tag does not identify the source revision")


def _validate_evidence_bytes(asset_bytes: dict[str, bytes]) -> None:
    with tempfile.TemporaryDirectory(prefix="reconcile-release-evidence-") as directory:
        evidence_root = Path(directory) / RELEASE_VERSION
        evidence_root.mkdir()
        for source, name in ASSETS:
            if source.parent == EVIDENCE_ROOT:
                (evidence_root / name).write_bytes(asset_bytes[name])
        try:
            load_and_validate(evidence_root / "proof-to-permit.json")
        except EvidenceError as error:
            raise ReleaseBuildError("current evidence is invalid") from error


def build_release(
    output: Path,
    *,
    source_revision: str = "HEAD",
    required_tag: str | None = None,
) -> tuple[Path, ...]:
    """Create one immutable release directory without changing source files."""

    output = output.resolve()
    if output == ROOT or ROOT in output.parents:
        raise ReleaseBuildError("release output must be outside the repository")
    if output.exists() or output.is_symlink():
        raise ReleaseBuildError("release output must not already exist")
    if not output.parent.is_dir():
        raise ReleaseBuildError("release output parent must exist")

    resolved_revision = _resolve_source_revision(source_revision)
    if _project_version(resolved_revision) != RELEASE_VERSION:
        raise ReleaseBuildError("project and release versions differ")
    _verify_loaded_implementation(resolved_revision)
    if required_tag is not None:
        _verify_required_tag(required_tag, resolved_revision)
    asset_bytes = {
        name: _committed_bytes(resolved_revision, source) for source, name in ASSETS
    }
    _validate_evidence_bytes(asset_bytes)

    temporary = Path(tempfile.mkdtemp(prefix=".reconcile-release-", dir=output.parent))
    try:
        copied: list[Path] = []
        for _, name in ASSETS:
            destination = temporary / name
            destination.write_bytes(asset_bytes[name])
            destination.chmod(stat.S_IRUSR | stat.S_IRGRP | stat.S_IROTH)
            copied.append(destination)

        source_manifest = temporary / SOURCE_MANIFEST_NAME
        source_manifest.write_text(
            json.dumps(
                {
                    "assets": [
                        {"name": path.name, "sha256": _sha256(path)} for path in copied
                    ],
                    "package_status": (
                        "tagged-release" if required_tag is not None else "candidate"
                    ),
                    "release_version": RELEASE_VERSION,
                    "schema_version": "reconcile/public-release-source/v1",
                    "source_repository": SOURCE_REPOSITORY,
                    "source_revision": resolved_revision,
                    "source_tag": required_tag,
                },
                sort_keys=True,
                separators=(",", ":"),
            )
            + "\n",
            encoding="utf-8",
        )
        source_manifest.chmod(stat.S_IRUSR | stat.S_IRGRP | stat.S_IROTH)
        copied.append(source_manifest)

        checksums = temporary / CHECKSUM_NAME
        checksums.write_text(
            "".join(f"{_sha256(path)}  {path.name}\n" for path in copied),
            encoding="utf-8",
        )
        checksums.chmod(stat.S_IRUSR | stat.S_IRGRP | stat.S_IROTH)
        temporary.chmod(stat.S_IRWXU)
        temporary.rename(output)
    except Exception:
        shutil.rmtree(temporary)
        raise
    return (
        *tuple(output / name for _, name in ASSETS),
        output / SOURCE_MANIFEST_NAME,
        output / CHECKSUM_NAME,
    )


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Build the current public evidence release asset set."
    )
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument(
        "--source-revision",
        default="HEAD",
        help="repository commit whose exact asset bytes are being packaged",
    )
    parser.add_argument(
        "--require-tag",
        help="require this release-version tag to identify the source commit",
    )
    arguments = parser.parse_args()
    try:
        assets = build_release(
            arguments.output,
            source_revision=arguments.source_revision,
            required_tag=arguments.require_tag,
        )
    except (OSError, ReleaseBuildError) as error:
        print(f"FAIL: {error}", file=sys.stderr)
        return 1
    print(f"Reconcile {RELEASE_VERSION} release package: PASS")
    print(f"  assets: {len(assets)}")
    print(f"  output: {assets[0].parent}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
