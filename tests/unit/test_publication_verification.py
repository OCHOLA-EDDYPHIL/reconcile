from __future__ import annotations

import hashlib
import json
import urllib.error
from dataclasses import replace
from pathlib import Path
from typing import Any

import pytest

from scripts import build_public_release as release
from scripts import verify_publication as publication
from viewer.export import _build_snapshot, write_bundle
from viewer.public_contract import sha256_hex

pytestmark = pytest.mark.unit

ROOT = Path(__file__).parents[2]
EVIDENCE_ROOT = ROOT / "evidence" / release.RELEASE_VERSION


class _RawResponse:
    def __init__(
        self,
        body: bytes,
        *,
        url: str = "https://example.test/value",
        status: int = 200,
    ) -> None:
        self.status = status
        self.headers = {"Content-Length": str(len(body))}
        self._body = body
        self._url = url
        self.closed = False

    def read(self, amount: int) -> bytes:
        return self._body[:amount]

    def geturl(self) -> str:
        return self._url

    def close(self) -> None:
        self.closed = True


def test_bounded_http_client_retries_only_within_its_budget() -> None:
    attempts = 0
    delays: list[float] = []
    response = _RawResponse(b"ok")

    def opener(_request: object, *, timeout: float) -> _RawResponse:
        nonlocal attempts
        assert timeout == 2
        attempts += 1
        if attempts < 3:
            raise urllib.error.URLError("transient")
        return response

    client = publication.BoundedHttpClient(
        attempts=3,
        timeout_seconds=2,
        initial_delay_seconds=0.1,
        opener=opener,
        sleeper=delays.append,
    )

    observed = client.request(
        "https://example.test/value",
        maximum_bytes=2,
    )

    assert observed.body == b"ok"
    assert attempts == 3
    assert delays == [0.1, 0.2]
    assert response.closed


def _tagged_release(tmp_path: Path) -> tuple[Path, dict[str, bytes], dict[str, Any]]:
    output = tmp_path / "release"
    release.build_release(output)
    manifest_path = output / release.SOURCE_MANIFEST_NAME
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["package_status"] = "tagged-release"
    manifest["project_version"] = release.RELEASE_VERSION
    manifest["source_tag"] = release.RELEASE_VERSION
    manifest_path.chmod(0o600)
    manifest_path.write_text(
        json.dumps(manifest, sort_keys=True, separators=(",", ":")) + "\n",
        encoding="utf-8",
    )
    checksum_names = [
        *(binding["name"] for binding in manifest["assets"]),
        release.SOURCE_MANIFEST_NAME,
    ]
    checksum_path = output / release.CHECKSUM_NAME
    checksum_path.chmod(0o600)
    checksum_path.write_text(
        "".join(
            f"{hashlib.sha256((output / name).read_bytes()).hexdigest()}  {name}\n"
            for name in checksum_names
        ),
        encoding="ascii",
    )
    return output, {path.name: path.read_bytes() for path in output.iterdir()}, manifest


def _security_headers(**extra: str) -> dict[str, str]:
    return {**publication._SECURITY_HEADERS, **extra}


class _PublicationClient:
    def __init__(
        self,
        release_payloads: dict[str, bytes],
        manifest: dict[str, Any],
        bundle: Path,
    ) -> None:
        self.release_payloads = release_payloads
        self.manifest = manifest
        self.bundle = bundle
        self.viewer_base = publication.DEFAULT_VIEWER_URL
        self.slug = "OCHOLA-EDDYPHIL/reconcile"
        self.release_api = (
            f"{publication.GITHUB_API_ROOT}/repos/{self.slug}/releases/tags/"
            f"{release.RELEASE_VERSION}"
        )
        self.tag_api = (
            f"{publication.GITHUB_API_ROOT}/repos/{self.slug}/git/ref/tags/"
            f"{release.RELEASE_VERSION}"
        )

    @staticmethod
    def _response(
        status: int,
        url: str,
        body: bytes,
        headers: dict[str, str] | None = None,
    ) -> publication.HttpResponse:
        return publication.HttpResponse(status, url, headers or {}, body)

    def _github_release(self) -> publication.HttpResponse:
        assets = []
        for name, payload in self.release_payloads.items():
            assets.append(
                {
                    "browser_download_url": (
                        f"{release.SOURCE_REPOSITORY}/releases/download/"
                        f"{release.RELEASE_VERSION}/{name}"
                    ),
                    "name": name,
                    "size": len(payload),
                    "state": "uploaded",
                }
            )
        metadata = {
            "assets": assets,
            "draft": False,
            "html_url": (
                f"{release.SOURCE_REPOSITORY}/releases/tag/{release.RELEASE_VERSION}"
            ),
            "prerelease": False,
            "published_at": "2026-08-31T00:00:00Z",
            "tag_name": release.RELEASE_VERSION,
        }
        return self._response(
            200,
            self.release_api,
            json.dumps(metadata).encode(),
        )

    def _viewer_response(
        self,
        url: str,
        *,
        method: str,
        request_headers: dict[str, str],
    ) -> publication.HttpResponse:
        path = url.removeprefix(self.viewer_base)
        files = {
            "/": ("index.html", "text/html; charset=utf-8"),
            "/index.html": ("index.html", "text/html; charset=utf-8"),
            "/snapshot.json": (
                "snapshot.json",
                "application/json; charset=utf-8",
            ),
            "/bundle-manifest.json": (
                "bundle-manifest.json",
                "application/json; charset=utf-8",
            ),
        }
        if method not in {"GET", "HEAD"}:
            return self._response(
                405,
                url,
                b"",
                _security_headers(**{"allow": "GET, HEAD", "content-length": "0"}),
            )
        if path == "/missing":
            return self._response(
                404,
                url,
                b"",
                _security_headers(**{"content-length": "0"}),
            )
        if path == "/snapshot.json?unexpected=1":
            return self._response(
                400,
                url,
                b"",
                _security_headers(**{"content-length": "0"}),
            )
        if path == "/health":
            snapshot = (self.bundle / "snapshot.json").read_bytes()
            payload = (
                json.dumps(
                    {"snapshot_sha256": sha256_hex(snapshot), "status": "ok"},
                    sort_keys=True,
                    separators=(",", ":"),
                ).encode()
                + b"\n"
            )
            content_type = "application/json; charset=utf-8"
        else:
            filename, content_type = files[path]
            payload = (self.bundle / filename).read_bytes()
        etag = f'"sha256:{sha256_hex(payload)}"'
        headers = _security_headers(
            **{
                "content-length": str(len(payload)),
                "content-type": content_type,
                "etag": etag,
            }
        )
        if request_headers.get("If-None-Match") == etag:
            return self._response(
                304,
                url,
                b"",
                _security_headers(**{"content-length": "0", "etag": etag}),
            )
        return self._response(200, url, b"" if method == "HEAD" else payload, headers)

    def request(
        self,
        url: str,
        *,
        method: str = "GET",
        maximum_bytes: int,
        headers: dict[str, str] | None = None,
        accepted_statuses: frozenset[int] = frozenset({200}),
    ) -> publication.HttpResponse:
        del maximum_bytes, accepted_statuses
        if url == self.release_api:
            return self._github_release()
        if url == self.tag_api:
            body = json.dumps(
                {
                    "object": {
                        "sha": self.manifest["source_revision"],
                        "type": "commit",
                    }
                }
            ).encode()
            return self._response(200, url, body)
        release_prefix = (
            f"{release.SOURCE_REPOSITORY}/releases/download/{release.RELEASE_VERSION}/"
        )
        if url.startswith(release_prefix):
            return self._response(
                200,
                url,
                self.release_payloads[url.removeprefix(release_prefix)],
            )
        if url.startswith(self.viewer_base):
            return self._viewer_response(
                url,
                method=method,
                request_headers=headers or {},
            )
        raise AssertionError(f"unexpected URL: {url}")


def _publication_fixture(
    tmp_path: Path,
) -> tuple[Path, _PublicationClient]:
    directory, payloads, manifest = _tagged_release(tmp_path)
    snapshot = _build_snapshot(EVIDENCE_ROOT, manifest["source_revision"])
    bundle = tmp_path / "bundle"
    write_bundle(snapshot, bundle)
    return directory, _PublicationClient(payloads, manifest, bundle)


def test_publication_verifier_binds_release_and_viewer(tmp_path: Path) -> None:
    directory, client = _publication_fixture(tmp_path)

    summary = publication.verify_publication(directory, client=client)

    assert summary == publication.VerificationSummary(
        release_assets=len(client.release_payloads),
        viewer_routes=9,
        mutation_methods=5,
    )


def test_publication_verifier_rejects_changed_downloaded_asset(tmp_path: Path) -> None:
    directory, client = _publication_fixture(tmp_path)
    client.release_payloads["architecture.png"] += b"changed"

    with pytest.raises(
        publication.PublicationVerificationError,
        match=r"asset metadata differs: architecture[.]png",
    ):
        publication.verify_publication(directory, client=client)


def test_viewer_verifier_rejects_missing_security_header(tmp_path: Path) -> None:
    directory, client = _publication_fixture(tmp_path)
    identity, _ = publication._load_local_release(
        directory,
        version=release.RELEASE_VERSION,
    )
    original = client._viewer_response

    def without_frame_header(
        url: str,
        *,
        method: str,
        request_headers: dict[str, str],
    ) -> publication.HttpResponse:
        response = original(url, method=method, request_headers=request_headers)
        if url == publication.DEFAULT_VIEWER_URL + "/":
            headers = dict(response.headers)
            headers.pop("x-frame-options")
            return replace(response, headers=headers)
        return response

    client._viewer_response = without_frame_header  # type: ignore[method-assign]

    with pytest.raises(
        publication.PublicationVerificationError,
        match="security header differs: x-frame-options",
    ):
        publication.verify_viewer(
            client,
            identity,
            viewer_url=publication.DEFAULT_VIEWER_URL,
        )
