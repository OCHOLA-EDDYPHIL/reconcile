from __future__ import annotations

import hashlib
import json
import stat
from pathlib import Path

import pytest

from scripts import build_public_release as release

pytestmark = pytest.mark.unit


def test_release_package_copies_exact_current_evidence_and_diagrams(
    tmp_path: Path,
) -> None:
    output = tmp_path / release.RELEASE_VERSION

    assets = release.build_release(output)

    expected_names = {name for _, name in release.ASSETS} | {
        release.SOURCE_MANIFEST_NAME,
        release.CHECKSUM_NAME,
    }
    assert {path.name for path in assets} == expected_names
    assert {path.name for path in output.iterdir()} == expected_names
    assert stat.S_IMODE(output.stat().st_mode) == 0o700
    assert all(stat.S_IMODE(path.stat().st_mode) == 0o444 for path in assets)
    for source, name in release.ASSETS:
        assert (output / name).read_bytes() == source.read_bytes()

    source_manifest = json.loads(
        (output / release.SOURCE_MANIFEST_NAME).read_text(encoding="utf-8")
    )
    assert source_manifest == {
        "assets": [
            {
                "name": name,
                "sha256": hashlib.sha256((output / name).read_bytes()).hexdigest(),
            }
            for _, name in release.ASSETS
        ],
        "package_status": "candidate",
        "release_version": release.RELEASE_VERSION,
        "schema_version": "reconcile/public-release-source/v1",
        "source_repository": release.SOURCE_REPOSITORY,
        "source_revision": release._resolve_source_revision("HEAD"),
        "source_tag": None,
    }

    checksum_lines = (
        (output / release.CHECKSUM_NAME).read_text(encoding="utf-8").splitlines()
    )
    assert checksum_lines == [
        f"{hashlib.sha256((output / name).read_bytes()).hexdigest()}  {name}"
        for name in [
            *(name for _, name in release.ASSETS),
            release.SOURCE_MANIFEST_NAME,
        ]
    ]


def test_release_package_refuses_overwrite_or_repository_output(
    tmp_path: Path,
) -> None:
    output = tmp_path / "release"
    output.mkdir()
    with pytest.raises(release.ReleaseBuildError, match="must not already exist"):
        release.build_release(output)

    with pytest.raises(release.ReleaseBuildError, match="outside the repository"):
        release.build_release(release.ROOT / "dist" / release.RELEASE_VERSION)


def test_release_package_requires_a_repository_source_revision(tmp_path: Path) -> None:
    with pytest.raises(release.ReleaseBuildError, match="repository commit"):
        release.build_release(
            tmp_path / "release",
            source_revision="0" * 40,
        )
