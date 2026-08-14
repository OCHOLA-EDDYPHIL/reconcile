from __future__ import annotations

from pathlib import Path

import pytest

import reconcile.runtime_provenance as provenance_module
from reconcile.runtime_provenance import (
    RuntimeProvenanceError,
    build_runtime_provenance,
    runtime_provenance_material,
)

pytestmark = pytest.mark.unit

_CONFIG = "a" * 64


class _ExecutorOne:
    async def __call__(self, envelope, **kwargs):
        return envelope, kwargs


class _ExecutorTwo:
    async def __call__(self, envelope, **kwargs):
        return kwargs, envelope


class _CleanupOne:
    async def __call__(self, envelope, report):
        return envelope, report


class _CleanupTwo:
    async def __call__(self, envelope, report):
        return report, envelope


def _fixture_project(tmp_path: Path) -> tuple[Path, Path]:
    project = tmp_path / "private-secret-project"
    package = project / "reconcile"
    package.mkdir(parents=True)
    (package / "__init__.py").write_text("TOKEN = 'fixture-secret'\n")
    (package / "worker.py").write_text("VALUE = 1\n")
    (project / "pyproject.toml").write_text(
        """
[project]
name = "fixture"
version = "1.0.0"
dependencies = ["fixture-dependency==1.0.0"]
""".strip()
        + "\n"
    )
    (project / "uv.lock").write_text("version = 1\nfixture-secret-lock = true\n")
    return project, package


def _build(
    project: Path,
    package: Path,
    *,
    executor=None,
    cleanup=None,
    config: str = _CONFIG,
):
    return build_runtime_provenance(
        executor=_ExecutorOne() if executor is None else executor,
        cleanup=cleanup,
        strategy="FIXED",
        max_provider_calls=2,
        max_estimated_cost_microunits=100,
        semantic_config_sha256=config,
        package_root=package,
        project_root=project,
    )


def test_same_runtime_identity_replays_exactly(tmp_path: Path, monkeypatch) -> None:
    project, package = _fixture_project(tmp_path)
    monkeypatch.setattr(provenance_module.metadata, "version", lambda _name: "1.0.0")

    first = _build(project, package, cleanup=_CleanupOne())
    second = _build(project, package, cleanup=_CleanupOne())

    assert first == second
    assert first.sha256 == second.sha256


def test_executor_cleanup_and_semantic_config_drift_change_identity(
    tmp_path: Path,
    monkeypatch,
) -> None:
    project, package = _fixture_project(tmp_path)
    monkeypatch.setattr(provenance_module.metadata, "version", lambda _name: "1.0.0")
    baseline = _build(project, package, cleanup=_CleanupOne())

    assert (
        _build(
            project,
            package,
            executor=_ExecutorTwo(),
            cleanup=_CleanupOne(),
        ).sha256
        != baseline.sha256
    )
    assert _build(project, package, cleanup=_CleanupTwo()).sha256 != baseline.sha256
    assert (
        _build(
            project,
            package,
            cleanup=_CleanupOne(),
            config="b" * 64,
        ).sha256
        != baseline.sha256
    )


def test_source_lock_declaration_and_installed_dependency_drift_are_bound(
    tmp_path: Path,
    monkeypatch,
) -> None:
    project, package = _fixture_project(tmp_path)
    installed_version = "1.0.0"

    def version(_name: str) -> str:
        return installed_version

    monkeypatch.setattr(provenance_module.metadata, "version", version)
    baseline = _build(project, package)

    (package / "worker.py").write_text("VALUE = 2\n")
    assert _build(project, package).sha256 != baseline.sha256
    (package / "worker.py").write_text("VALUE = 1\n")

    (project / "uv.lock").write_text("version = 2\n")
    assert _build(project, package).sha256 != baseline.sha256
    (project / "uv.lock").write_text("version = 1\nfixture-secret-lock = true\n")

    pyproject = project / "pyproject.toml"
    pyproject.write_text(pyproject.read_text().replace('1.0.0"]', '1.0.1"]'))
    assert _build(project, package).sha256 != baseline.sha256
    pyproject.write_text(pyproject.read_text().replace('1.0.1"]', '1.0.0"]'))

    installed_version = "1.0.1"
    assert _build(project, package).sha256 != baseline.sha256


def test_identity_material_never_exposes_source_paths_or_contents(
    tmp_path: Path,
    monkeypatch,
) -> None:
    project, package = _fixture_project(tmp_path)
    monkeypatch.setattr(provenance_module.metadata, "version", lambda _name: "1.0.0")

    material = runtime_provenance_material(_build(project, package))

    assert str(tmp_path).encode() not in material
    assert b"private-secret-project" not in material
    assert b"fixture-secret" not in material
    assert b"worker.py" not in material


@pytest.mark.parametrize(
    ("executor", "package_exists", "project_exists", "config"),
    (
        (len, True, True, _CONFIG),
        (_ExecutorOne(), False, True, _CONFIG),
        (_ExecutorOne(), True, False, _CONFIG),
        (_ExecutorOne(), True, True, "not-a-digest"),
    ),
)
def test_missing_or_unresolvable_required_identity_fails_closed(
    tmp_path: Path,
    monkeypatch,
    executor,
    package_exists: bool,
    project_exists: bool,
    config: str,
) -> None:
    project, package = _fixture_project(tmp_path)
    monkeypatch.setattr(provenance_module.metadata, "version", lambda _name: "1.0.0")
    if not package_exists:
        package = project / "missing-package"
    if not project_exists:
        project = tmp_path / "missing-project"

    with pytest.raises(RuntimeProvenanceError):
        _build(project, package, executor=executor, config=config)
