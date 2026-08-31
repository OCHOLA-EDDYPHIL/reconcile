from __future__ import annotations

import http.client
import socket
import threading

import pytest

from tests.unit.viewer.conftest import VIEWER_SOURCE_REVISION
from viewer.public_contract import decode_snapshot, sha256_hex
from viewer.server import (
    BundleError,
    ViewerHandler,
    ViewerHTTPServer,
    _validate_runtime_identity,
    load_bundle,
    main,
)

pytestmark = pytest.mark.unit


@pytest.fixture
def viewer(viewer_bundle):
    ViewerHandler.responses_by_path = load_bundle(viewer_bundle)
    server = ViewerHTTPServer(("127.0.0.1", 0), ViewerHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server.server_address[1]
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def _request(port: int, method: str, path: str, **kwargs):
    connection = http.client.HTTPConnection("127.0.0.1", port, timeout=2)
    connection.request(method, path, **kwargs)
    response = connection.getresponse()
    payload = response.read()
    headers = dict(response.getheaders())
    connection.close()
    return response.status, headers, payload


def _raw_status(port: int, request: bytes) -> tuple[int, bytes]:
    with socket.create_connection(("127.0.0.1", port), timeout=2) as connection:
        connection.sendall(request)
        response = b""
        while True:
            chunk = connection.recv(65_536)
            if not chunk:
                break
            response += chunk
    status_line = response.split(b"\r\n", 1)[0]
    return int(status_line.split(b" ")[1]), response


def test_closed_routes_emit_security_headers(viewer: int) -> None:
    status, headers, payload = _request(viewer, "GET", "/")

    assert status == 200
    assert b"Recorded evidence - not a live operation" in payload
    assert b"Viewer and evidence identities were verified" in payload
    snapshot = decode_snapshot(_request(viewer, "GET", "/snapshot.json")[2])
    hidden_identifiers = (
        snapshot["viewer_source_revision"],
        snapshot["evidence_source_revision"],
        snapshot["evidence"]["image_digest"],
        snapshot["evidence"]["manifest_sha256"],
        snapshot["projection_sha256"],
    )
    assert all(value.encode() not in payload for value in hidden_identifiers)
    assert headers["Cache-Control"] == "no-store, max-age=0, must-revalidate"
    assert headers["Content-Security-Policy"].startswith("default-src 'none'")
    assert headers["Permissions-Policy"] == ("camera=(), microphone=(), geolocation=()")
    assert headers["X-Frame-Options"] == "DENY"
    assert headers["Server"] == "Reconcile"


def test_head_health_manifest_and_etag_are_read_only(viewer: int) -> None:
    status, headers, payload = _request(viewer, "HEAD", "/snapshot.json")
    assert status == 200
    assert payload == b""
    etag = headers["ETag"]

    status, headers, payload = _request(
        viewer,
        "GET",
        "/snapshot.json",
        headers={"If-None-Match": etag},
    )
    assert status == 304
    assert payload == b""

    assert _request(viewer, "GET", "/bundle-manifest.json")[0] == 200
    status, headers, payload = _request(viewer, "GET", "/health")
    assert status == 200
    assert headers["Content-Type"] == "application/json; charset=utf-8"
    assert payload.startswith(b'{"snapshot_sha256":"')


@pytest.mark.parametrize(
    ("method", "path", "expected"),
    (
        ("GET", "/?key=value", 400),
        ("GET", "/missing", 404),
        ("POST", "/", 405),
        ("PUT", "/", 405),
        ("PATCH", "/", 405),
        ("DELETE", "/", 405),
        ("OPTIONS", "/", 405),
    ),
)
def test_route_and_method_matrix(
    viewer: int,
    method: str,
    path: str,
    expected: int,
) -> None:
    status, headers, payload = _request(viewer, method, path)

    assert status == expected
    assert payload == b""
    if status == 405:
        assert headers["Allow"] == "GET, HEAD"


def test_ambiguous_http_framing_is_rejected(viewer: int) -> None:
    status, response = _raw_status(
        viewer,
        b"GET / HTTP/1.1\r\nHost: first\r\nHost: second\r\n\r\n",
    )

    assert status == 400
    assert b"Connection: close\r\n" in response


def test_runtime_identity_matches_viewer_and_evidence_sources(
    viewer_bundle,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    responses = load_bundle(viewer_bundle)
    snapshot_payload = responses["/snapshot.json"][0]
    snapshot = decode_snapshot(snapshot_payload)
    monkeypatch.setenv("RECONCILE_SNAPSHOT_SHA256", sha256_hex(snapshot_payload))
    monkeypatch.setenv(
        "RECONCILE_VIEWER_SOURCE_REVISION", snapshot["viewer_source_revision"]
    )
    monkeypatch.setenv(
        "RECONCILE_EVIDENCE_SOURCE_REVISION", snapshot["evidence_source_revision"]
    )

    _validate_runtime_identity(responses)
    monkeypatch.setenv("RECONCILE_VIEWER_SOURCE_REVISION", "b" * 40)
    with pytest.raises(BundleError, match="viewer source"):
        _validate_runtime_identity(responses)


def test_main_requires_all_runtime_identity_fields(
    viewer_bundle,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("RECONCILE_VIEWER_BUNDLE", str(viewer_bundle))
    monkeypatch.delenv("RECONCILE_SNAPSHOT_SHA256", raising=False)
    monkeypatch.setenv("RECONCILE_VIEWER_SOURCE_REVISION", VIEWER_SOURCE_REVISION)
    monkeypatch.setenv("RECONCILE_EVIDENCE_SOURCE_REVISION", "b" * 40)

    with pytest.raises(BundleError, match="runtime identity is missing"):
        main()
