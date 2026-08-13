"""Textual terminal shell."""

from typing import ClassVar

from textual.app import App, ComposeResult
from textual.widgets import Footer, Header, Static


class ReconcileApp(App[None]):
    """Credential-free RECONCILE terminal shell."""

    BINDINGS: ClassVar = [("q", "quit", "Quit")]

    def compose(self) -> ComposeResult:
        yield Header()
        yield Static("RECONCILE", id="product-title")
        yield Footer()


def main() -> None:
    """Run the terminal shell."""

    ReconcileApp().run()
