"""Startup checks for the one-image hosted component dispatcher."""

from __future__ import annotations

import pytest

import reconcile.hosted.__main__ as hosted_main
from reconcile.hosted.config import Component, HostedConfig

pytestmark = pytest.mark.unit


def test_main_binds_selected_component_to_injected_port(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = HostedConfig(
        component=Component.API,
        port=9123,
        project_id="example-project-id",
        auth_audience=("https://reconcile.invalid/phase5/example-project-id/api"),
        allowed_caller_emails=(
            "rec-p5-operator@example-project-id.iam.gserviceaccount.com",
        ),
        source_revision="a" * 40,
        image_digest=f"sha256:{'b' * 64}",
        infra_revision="c" * 64,
        semantic_config_sha256="d" * 64,
    )
    application = object()
    observed: dict[str, object] = {}

    monkeypatch.setattr(hosted_main, "load_config", lambda: config)
    monkeypatch.setattr(
        hosted_main,
        "create_runtime_component_app",
        lambda selected: application if selected is config else None,
    )

    def run(selected: object, **options: object) -> None:
        observed["application"] = selected
        observed.update(options)

    monkeypatch.setattr(hosted_main.uvicorn, "run", run)

    hosted_main.main()

    assert observed == {
        "application": application,
        "host": "0.0.0.0",
        "port": 9123,
        "proxy_headers": False,
        "forwarded_allow_ips": "",
        "server_header": False,
    }
