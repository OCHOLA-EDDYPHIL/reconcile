"""Run one hosted RECONCILE component from strict environment configuration."""

from __future__ import annotations

import uvicorn

from reconcile.hosted.apps import create_component_app
from reconcile.hosted.config import load_config


def main() -> None:
    """Bind the selected Cloud Run component to its injected port."""

    config = load_config()
    application = create_component_app(config)
    uvicorn.run(
        application,
        host="0.0.0.0",
        port=config.port,
        proxy_headers=False,
        forwarded_allow_ips="",
        server_header=False,
    )


if __name__ == "__main__":
    main()
