"""Typer automation shell."""

from __future__ import annotations

import typer

app = typer.Typer(
    add_completion=False,
    invoke_without_command=True,
    no_args_is_help=False,
    help="RECONCILE automation interface.",
)


@app.callback()
def root() -> None:
    """RECONCILE automation interface."""


def main(argv: list[str] | None = None) -> int:
    """Run the command while preserving a process-style return code."""

    try:
        app(args=argv, prog_name="reconcile")
    except SystemExit as error:
        return int(error.code or 0)
    return 0
