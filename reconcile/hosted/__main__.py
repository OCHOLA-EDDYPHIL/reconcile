"""Run one hosted RECONCILE component from strict environment configuration."""

from __future__ import annotations

import uvicorn

from reconcile.hosted.config import load_config
from reconcile.hosted.runtime import create_runtime_component_app


def main() -> None:
    """Bind the selected Cloud Run component to its injected port."""

    config = load_config()
    application = create_runtime_component_app(config)
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
