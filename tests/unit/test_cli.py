import pytest
from typer.testing import CliRunner

from reconcile.cli import app, main

pytestmark = pytest.mark.unit


def test_empty_invocation_remains_successful() -> None:
    result = CliRunner().invoke(app, [])

    assert result.exit_code == 0
    assert main([]) == 0


def test_help_identifies_the_stable_command() -> None:
    result = CliRunner().invoke(app, ["--help"])

    assert result.exit_code == 0
    assert "RECONCILE automation interface" in result.stdout
