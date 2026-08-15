import asyncio

import pytest
from textual.widgets import Static

from reconcile.interfaces import tui

pytestmark = pytest.mark.acceptance


def test_terminal_shell_starts_headlessly() -> None:
    async def start() -> None:
        app = tui.ReconcileApp()

        async with app.run_test() as pilot:
            await pilot.pause()
            assert app.query_one("#product-title", Static)
            assert "OPERATIONAL STATUS: PENDING" in str(
                app.query_one("#operations-panel", Static).content
            )

    asyncio.run(start())


def test_terminal_entry_point_runs_the_app(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[bool] = []

    def run(_: tui.ReconcileApp) -> None:
        calls.append(True)

    monkeypatch.setattr(tui.ReconcileApp, "run", run)

    tui.main()

    assert calls == [True]
