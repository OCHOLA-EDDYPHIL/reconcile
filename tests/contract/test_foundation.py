import ast
import tomllib
from importlib import import_module
from importlib.metadata import entry_points
from pathlib import Path

import pytest

pytestmark = pytest.mark.contract


def test_package_boundaries_are_importable() -> None:
    for module in (
        "reconcile.adapters",
        "reconcile.contracts",
        "reconcile.controller",
        "reconcile.interfaces",
    ):
        assert import_module(module)


def test_supported_python_and_entry_points_are_explicit() -> None:
    project = tomllib.loads(Path("pyproject.toml").read_text(encoding="utf-8"))

    assert project["project"]["requires-python"] == ">=3.12,<3.13"
    assert project["project"]["scripts"] == {
        "reconcile": "reconcile.cli:main",
        "reconcile-api": "reconcile.interfaces.api:main",
        "reconcile-tui": "reconcile.interfaces.tui:main",
    }


def test_installed_console_scripts_match_the_project_contract() -> None:
    scripts = {
        point.name: point.value
        for point in entry_points(group="console_scripts")
        if point.name.startswith("reconcile")
    }

    assert scripts == {
        "reconcile": "reconcile.cli:main",
        "reconcile-api": "reconcile.interfaces.api:main",
        "reconcile-tui": "reconcile.interfaces.tui:main",
    }


def test_dependency_and_secret_policy_is_machine_readable() -> None:
    project = tomllib.loads(Path("pyproject.toml").read_text(encoding="utf-8"))
    policy = project["tool"]["reconcile"]["dependency-policy"]

    assert policy["python"] == "3.12.13"
    assert policy["check"] == "uv lock --check"
    assert policy["install"] == "uv sync --locked --all-groups"
    assert policy["upgrade"] == (
        "edit one exact pin; uv lock --upgrade-package <name>; review uv.lock diff"
    )
    assert "never repository files" in policy["secrets"]


def test_core_layers_do_not_depend_on_interfaces_or_interface_frameworks() -> None:
    forbidden = ("fastapi", "reconcile.interfaces", "textual", "typer", "uvicorn")
    for layer in ("adapters", "contracts", "controller"):
        for path in (Path("reconcile") / layer).rglob("*.py"):
            tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
            imported = []
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    imported.extend(alias.name for alias in node.names)
                elif isinstance(node, ast.ImportFrom) and node.module:
                    imported.append(node.module)
            assert not any(
                module == blocked or module.startswith(f"{blocked}.")
                for module in imported
                for blocked in forbidden
            ), path
