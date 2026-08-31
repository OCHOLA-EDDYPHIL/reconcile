"""Serve one immutable, read-only public evidence bundle."""

from __future__ import annotations

import os
import stat
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from typing import ClassVar
from urllib.parse import urlsplit

if __package__:
    from .public_contract import (
        MAX_HTML_BYTES,
        MAX_MANIFEST_BYTES,
        MAX_SNAPSHOT_BYTES,
        PublicContractError,
        canonical_json_bytes,
        decode_manifest,
        decode_snapshot,
        read_bounded_regular_at,
        render_html,
        sha256_hex,
    )
else:
    from public_contract import (  # type: ignore[import-not-found]
        MAX_HTML_BYTES,
        MAX_MANIFEST_BYTES,
        MAX_SNAPSHOT_BYTES,
        PublicContractError,
        canonical_json_bytes,
        decode_manifest,
        decode_snapshot,
        read_bounded_regular_at,
        render_html,
        sha256_hex,
    )

_BUNDLE_FILES = frozenset({"bundle-manifest.json", "index.html", "snapshot.json"})
_CACHE_CONTROL = "no-store, max-age=0, must-revalidate"
_SOCKET_TIMEOUT_SECONDS = 5.0


class BundleError(RuntimeError):
    """Signal that the immutable viewer bundle is invalid."""


def load_bundle(root: Path) -> dict[str, tuple[bytes, str]]:
    """Load exactly three descriptor-read files and verify their full contract."""

    if not isinstance(root, Path):
        raise BundleError("bundle directory is invalid")
    flags = os.O_RDONLY | os.O_CLOEXEC | os.O_DIRECTORY | os.O_NOFOLLOW
    try:
        descriptor = os.open(root, flags)
    except OSError as error:
        raise BundleError("bundle directory is invalid") from error
    try:
        metadata = os.fstat(descriptor)
        entries = os.listdir(descriptor)
        if (
            not stat.S_ISDIR(metadata.st_mode)
            or len(entries) != len(_BUNDLE_FILES)
            or set(entries) != _BUNDLE_FILES
        ):
            raise BundleError("bundle directory is invalid")
        manifest_payload = read_bounded_regular_at(
            descriptor,
            "bundle-manifest.json",
            MAX_MANIFEST_BYTES,
        )
        snapshot_payload = read_bounded_regular_at(
            descriptor,
            "snapshot.json",
            MAX_SNAPSHOT_BYTES,
        )
        html_payload = read_bounded_regular_at(
            descriptor,
            "index.html",
            MAX_HTML_BYTES,
        )
    except BundleError:
        raise
    except (OSError, PublicContractError) as error:
        raise BundleError("bundle file is invalid") from error
    finally:
        os.close(descriptor)

    try:
        snapshot = decode_snapshot(snapshot_payload)
        if render_html(snapshot) != html_payload:
            raise BundleError("bundle HTML is invalid")
        decode_manifest(manifest_payload, snapshot, snapshot_payload, html_payload)
    except BundleError:
        raise
    except PublicContractError as error:
        raise BundleError("bundle contract is invalid") from error

    health = canonical_json_bytes(
        {
            "snapshot_sha256": sha256_hex(snapshot_payload),
            "status": "ok",
        }
    )
    return {
        "/": (html_payload, "text/html; charset=utf-8"),
        "/index.html": (html_payload, "text/html; charset=utf-8"),
        "/snapshot.json": (snapshot_payload, "application/json; charset=utf-8"),
        "/bundle-manifest.json": (
            manifest_payload,
            "application/json; charset=utf-8",
        ),
        "/health": (health, "application/json; charset=utf-8"),
    }


class ViewerHandler(BaseHTTPRequestHandler):
    """Serve a closed route set without any mutation surface."""

    protocol_version = "HTTP/1.1"
    server_version = "Reconcile"
    sys_version = ""
    responses_by_path: ClassVar[dict[str, tuple[bytes, str]]]

    def log_message(self, format: str, *args: object) -> None:
        del format, args

    def version_string(self) -> str:
        return self.server_version

    def __getattr__(self, name: str) -> object:
        if name.startswith("do_"):
            return self._method_not_allowed
        raise AttributeError(name)

    def handle_expect_100(self) -> bool:
        self._empty(417)
        return False

    def _security_headers(self) -> None:
        self.send_header(
            "Content-Security-Policy",
            "default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; "
            "form-action 'none'; frame-ancestors 'none'",
        )
        self.send_header("Cross-Origin-Opener-Policy", "same-origin")
        self.send_header("Cross-Origin-Resource-Policy", "same-origin")
        self.send_header(
            "Permissions-Policy", "camera=(), microphone=(), geolocation=()"
        )
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Strict-Transport-Security", "max-age=31536000")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("X-Robots-Tag", "noindex, nofollow, noarchive")
        self.send_header("Cache-Control", _CACHE_CONTROL)
        self.send_header("Pragma", "no-cache")

    def _empty(self, status: int, *, allow: bool = False) -> None:
        self.send_response(status)
        if allow:
            self.send_header("Allow", "GET, HEAD")
        self._security_headers()
        self.send_header("Content-Length", "0")
        self.send_header("Connection", "close")
        self.end_headers()
        self.close_connection = True

    def _request_headers_are_valid(self) -> bool:
        hosts = self.headers.get_all("Host", failobj=[])
        if self.request_version == "HTTP/1.1" and (
            len(hosts) != 1 or not hosts[0].strip()
        ):
            return False
        lengths = self.headers.get_all("Content-Length", failobj=[])
        transfers = self.headers.get_all("Transfer-Encoding", failobj=[])
        return transfers == [] and lengths in ([], ["0"])

    def _serve(self, *, head: bool) -> None:
        if not self._request_headers_are_valid():
            self._empty(400)
            return
        try:
            parsed = urlsplit(self.path)
        except ValueError:
            self._empty(400)
            return
        if parsed.scheme or parsed.netloc or "?" in self.path or "#" in self.path:
            self._empty(400)
            return
        response = self.responses_by_path.get(parsed.path)
        if response is None:
            self._empty(404)
            return
        payload, content_type = response
        etag = f'"sha256:{sha256_hex(payload)}"'
        if self.headers.get("If-None-Match") == etag:
            self.send_response(304)
            self._security_headers()
            self.send_header("ETag", etag)
            self.send_header("Content-Length", "0")
            self.send_header("Connection", "close")
            self.end_headers()
            self.close_connection = True
            return
        self.send_response(200)
        self._security_headers()
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(payload)))
        self.send_header("ETag", etag)
        self.send_header("Connection", "close")
        self.end_headers()
        if not head:
            self.wfile.write(payload)
        self.close_connection = True

    def _method_not_allowed(self) -> None:
        self._empty(405, allow=True)

    def do_GET(self) -> None:
        self._serve(head=False)

    def do_HEAD(self) -> None:
        self._serve(head=True)


class ViewerHTTPServer(HTTPServer):
    """Single-request server with a deadline on every accepted socket."""

    request_queue_size = 64

    def get_request(self):
        connection, address = super().get_request()
        connection.settimeout(_SOCKET_TIMEOUT_SECONDS)
        return connection, address


def _port() -> int:
    try:
        value = int(os.environ.get("PORT", "8080"))
    except ValueError as error:
        raise BundleError("PORT is invalid") from error
    if value < 1 or value > 65_535:
        raise BundleError("PORT is invalid")
    return value


def _validate_runtime_identity(
    responses_by_path: dict[str, tuple[bytes, str]],
) -> None:
    """Require deployment identity to match both loaded source identities."""

    expected_snapshot = os.environ.get("RECONCILE_SNAPSHOT_SHA256")
    expected_viewer_source = os.environ.get("RECONCILE_VIEWER_SOURCE_REVISION")
    expected_evidence_source = os.environ.get("RECONCILE_EVIDENCE_SOURCE_REVISION")
    if (
        expected_snapshot is None
        or expected_viewer_source is None
        or expected_evidence_source is None
    ):
        raise BundleError("runtime identity is missing")

    snapshot_payload = responses_by_path["/snapshot.json"][0]
    if sha256_hex(snapshot_payload) != expected_snapshot:
        raise BundleError("runtime snapshot identity does not match")
    try:
        snapshot = decode_snapshot(snapshot_payload)
    except PublicContractError as error:
        raise BundleError("runtime snapshot identity is invalid") from error
    if snapshot["viewer_source_revision"] != expected_viewer_source:
        raise BundleError("runtime viewer source identity does not match")
    if snapshot["evidence_source_revision"] != expected_evidence_source:
        raise BundleError("runtime evidence source identity does not match")


def main() -> int:
    bundle_root = Path(os.environ.get("RECONCILE_VIEWER_BUNDLE", "/app/bundle"))
    responses_by_path = load_bundle(bundle_root)
    _validate_runtime_identity(responses_by_path)
    ViewerHandler.responses_by_path = responses_by_path
    server = ViewerHTTPServer(("0.0.0.0", _port()), ViewerHandler)
    server.serve_forever()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())


__all__ = [
    "BundleError",
    "ViewerHTTPServer",
    "ViewerHandler",
    "load_bundle",
    "main",
]
