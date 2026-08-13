import json
import socket
import time
from threading import Thread
from urllib.error import URLError
from urllib.request import urlopen

import pytest
import uvicorn

from reconcile.interfaces import api

pytestmark = pytest.mark.integration


def test_health_shell_starts_without_credentials() -> None:
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    port = listener.getsockname()[1]
    server = uvicorn.Server(
        uvicorn.Config(api.app, lifespan="off", log_level="critical")
    )
    thread = Thread(target=server.run, kwargs={"sockets": [listener]})
    thread.start()
    deadline = time.monotonic() + 5

    try:
        while True:
            try:
                with urlopen(f"http://127.0.0.1:{port}/health", timeout=1) as response:
                    assert response.status == 200
                    assert json.load(response) == {"status": "ok"}
                    break
            except URLError:
                if time.monotonic() >= deadline:
                    raise
                time.sleep(0.01)
    finally:
        server.should_exit = True
        thread.join(timeout=5)
        listener.close()

    assert not thread.is_alive()


def test_api_entry_point_binds_only_to_loopback(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[tuple[object, str, int]] = []

    def run(application: object, *, host: str, port: int) -> None:
        calls.append((application, host, port))

    monkeypatch.setattr(api.uvicorn, "run", run)

    api.main()

    assert calls == [(api.app, "127.0.0.1", 8000)]
