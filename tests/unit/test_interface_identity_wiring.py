from __future__ import annotations

import asyncio
from collections.abc import Callable
from typing import Any

import pytest
from textual.widgets import Static

from reconcile.interfaces import cli, tui
from reconcile.interfaces.api_client import InvalidRequestError
from reconcile.interfaces.google_identity import GoogleIdentityTokenError

pytestmark = pytest.mark.unit

_API_URL = "https://api.example.test"
_AUDIENCE = "https://reconcile.invalid/phase5/operator"


class _FakeOperatorClient:
    def __init__(
        self,
        base_url: str,
        **options: object,
    ) -> None:
        self.base_url = base_url
        self.options = options
        self.closed = False

    async def aclose(self) -> None:
        self.closed = True


def _client_factory(
    observed: list[_FakeOperatorClient],
) -> Callable[..., _FakeOperatorClient]:
    def build(base_url: str, **options: object) -> _FakeOperatorClient:
        client = _FakeOperatorClient(base_url, **options)
        observed.append(client)
        return client

    return build


@pytest.mark.parametrize("module", (cli, tui))
def test_plain_operator_client_is_retained_when_no_audience_is_explicit(
    monkeypatch: pytest.MonkeyPatch,
    module: Any,
) -> None:
    observed: list[_FakeOperatorClient] = []
    monkeypatch.setattr(module, "operator_client_identity", lambda: None)
    monkeypatch.setattr(module, "OperatorApiClient", _client_factory(observed))

    client = module._operator_client(_API_URL)

    assert client is observed[0]
    assert observed[0].base_url == _API_URL
    assert observed[0].options == {}


@pytest.mark.parametrize("module", (cli, tui))
def test_explicit_audience_wires_the_exact_supplier_and_audience(
    monkeypatch: pytest.MonkeyPatch,
    module: Any,
) -> None:
    observed: list[_FakeOperatorClient] = []

    def supplier(audience: str) -> str:
        raise AssertionError(f"supplier must remain lazy for {audience}")

    monkeypatch.setattr(
        module,
        "operator_client_identity",
        lambda: (supplier, _AUDIENCE),
    )
    monkeypatch.setattr(module, "OperatorApiClient", _client_factory(observed))

    client = module._operator_client(_API_URL)

    assert client is observed[0]
    assert observed[0].base_url == _API_URL
    assert observed[0].options == {
        "identity_audience": _AUDIENCE,
        "identity_token_supplier": supplier,
    }


def test_cli_sanitizes_identity_configuration_failure_as_invalid_request(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def invalid_identity() -> None:
        raise GoogleIdentityTokenError("credential=do-not-render")

    monkeypatch.setattr(cli, "operator_client_identity", invalid_identity)
    monkeypatch.setattr(
        cli,
        "OperatorApiClient",
        lambda *_args, **_kwargs: pytest.fail("client must not be constructed"),
    )

    with pytest.raises(InvalidRequestError) as raised:
        cli._operator_client(_API_URL)

    assert "do-not-render" not in str(raised.value)


def test_tui_mount_sanitizes_identity_configuration_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def invalid_identity() -> None:
        raise GoogleIdentityTokenError("credential=do-not-render")

    monkeypatch.setattr(tui, "operator_client_identity", invalid_identity)
    monkeypatch.setattr(
        tui,
        "OperatorApiClient",
        lambda *_args, **_kwargs: pytest.fail("client must not be constructed"),
    )

    async def exercise() -> None:
        app = tui.ReconcileApp(api_base_url=_API_URL)
        async with app.run_test() as pilot:
            await pilot.pause()
            message = str(app.query_one("#operator-message", Static).content)
            assert message == (
                "[REFUSED] Local Google identity configuration is invalid."
            )
            assert "do-not-render" not in message
            assert app._client is None

    asyncio.run(exercise())


def test_tui_mount_constructs_the_authenticated_client(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    observed: list[_FakeOperatorClient] = []

    def supplier(_audience: str) -> str:
        return "unused-token"

    monkeypatch.setattr(
        tui,
        "operator_client_identity",
        lambda: (supplier, _AUDIENCE),
    )
    monkeypatch.setattr(tui, "OperatorApiClient", _client_factory(observed))

    async def exercise() -> None:
        app = tui.ReconcileApp(api_base_url=_API_URL)
        async with app.run_test() as pilot:
            await pilot.pause()
            assert app._client is observed[0]
            assert observed[0].base_url == _API_URL
            assert observed[0].options == {
                "identity_audience": _AUDIENCE,
                "identity_token_supplier": supplier,
            }
        assert observed[0].closed is True

    asyncio.run(exercise())


def test_tui_injected_client_bypasses_local_identity_construction(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    injected = _FakeOperatorClient(_API_URL)
    monkeypatch.setattr(
        tui,
        "operator_client_identity",
        lambda: pytest.fail("injected clients must bypass local identity"),
    )

    async def exercise() -> None:
        app = tui.ReconcileApp(client=injected)
        async with app.run_test() as pilot:
            await pilot.pause()
            assert app._client is injected
        assert injected.closed is True

    asyncio.run(exercise())
