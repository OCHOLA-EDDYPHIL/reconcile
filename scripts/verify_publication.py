#!/usr/bin/env python3
"""Verify one published release and its retained read-only evidence viewer."""

from __future__ import annotations

import argparse
import hashlib
import http.client
import json
import re
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

if __package__:
    from .build_public_release import (
        CHECKSUM_NAME,
        RELEASE_VERSION,
        SOURCE_MANIFEST_NAME,
        SOURCE_REPOSITORY,
    )
    from .validate_evidence import EvidenceError, load_and_validate
else:
    from build_public_release import (  # type: ignore[import-not-found]
        CHECKSUM_NAME,
        RELEASE_VERSION,
        SOURCE_MANIFEST_NAME,
        SOURCE_REPOSITORY,
    )
    from validate_evidence import (  # type: ignore[import-not-found]
        EvidenceError,
        load_and_validate,
    )

from viewer.export import ViewerExportError, _build_snapshot
from viewer.public_contract import (
    SNAPSHOT_VERSION,
    PublicContractError,
    canonical_json_bytes,
    decode_manifest,
    decode_snapshot,
    render_html,
    sha256_hex,
)

DEFAULT_VIEWER_URL = "https://reconcile-evidence-g6fwwrme5a-uc.a.run.app"
GITHUB_API_ROOT = "https://api.github.com"
MAX_METADATA_BYTES = 1_048_576
MAX_ASSET_BYTES = 16 * 1_048_576
MAX_VIEWER_BYTES = 131_072
_TRANSIENT_HTTP_STATUSES = frozenset({408, 425, 429, 500, 502, 503, 504})
_SOURCE_REVISION = re.compile(r"^[0-9a-f]{40}$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_VERSION = re.compile(r"^v[0-9]+[.][0-9]+[.][0-9]+$")
_RFC3339_UTC = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")
_ASSET_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,199}$")
_CHECKSUM_LINE = re.compile(r"^([0-9a-f]{64})  ([A-Za-z0-9][A-Za-z0-9._-]{0,199})$")
_SECURITY_HEADERS = {
    "cache-control": "no-store, max-age=0, must-revalidate",
    "content-security-policy": (
        "default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; "
        "form-action 'none'; frame-ancestors 'none'"
    ),
    "cross-origin-opener-policy": "same-origin",
    "cross-origin-resource-policy": "same-origin",
    "permissions-policy": "camera=(), microphone=(), geolocation=()",
    "pragma": "no-cache",
    "referrer-policy": "no-referrer",
    "strict-transport-security": "max-age=31536000",
    "x-content-type-options": "nosniff",
    "x-frame-options": "DENY",
    "x-robots-tag": "noindex, nofollow, noarchive",
}


class PublicationVerificationError(RuntimeError):
    """The published bytes or public HTTP surface violate their contract."""


@dataclass(frozen=True)
class HttpResponse:
    """One bounded HTTP response after redirect handling."""

    status: int
    url: str
    headers: Mapping[str, str]
    body: bytes


@dataclass(frozen=True)
class ReleaseIdentity:
    """Bindings shared by the release assets and retained viewer."""

    version: str
    source_revision: str
    evidence_source_revision: str
    evidence_sha256: Mapping[str, str]
    expected_snapshot: bytes
    asset_names: tuple[str, ...]


@dataclass(frozen=True)
class VerificationSummary:
    """Counts from a complete online publication verification."""

    release_assets: int
    viewer_routes: int
    mutation_methods: int


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise PublicationVerificationError(message)


def _normalized_headers(headers: Any) -> dict[str, str]:
    normalized: dict[str, str] = {}
    singular = {*_SECURITY_HEADERS, "allow", "content-length", "content-type", "etag"}
    for name, value in headers.items():
        key = str(name).casefold()
        observed = str(value).strip()
        if key in normalized:
            _require(key not in singular, f"duplicate HTTP header: {key}")
            normalized[key] = f"{normalized[key]}, {observed}"
        else:
            normalized[key] = observed
    return normalized


class BoundedHttpClient:
    """Perform bounded requests with retries limited to transient failures."""

    def __init__(
        self,
        *,
        attempts: int = 4,
        timeout_seconds: float = 10.0,
        initial_delay_seconds: float = 0.25,
        opener: Callable[..., Any] = urllib.request.urlopen,
        sleeper: Callable[[float], None] = time.sleep,
    ) -> None:
        if (
            type(attempts) is not int
            or not 1 <= attempts <= 8
            or not 0 < timeout_seconds <= 60
            or not 0 <= initial_delay_seconds <= 5
        ):
            raise PublicationVerificationError("HTTP retry policy is invalid")
        self._attempts = attempts
        self._timeout_seconds = timeout_seconds
        self._initial_delay_seconds = initial_delay_seconds
        self._opener = opener
        self._sleeper = sleeper

    def _wait(self, attempt: int) -> None:
        self._sleeper(min(self._initial_delay_seconds * (2**attempt), 5.0))

    def request(
        self,
        url: str,
        *,
        method: str = "GET",
        maximum_bytes: int,
        headers: Mapping[str, str] | None = None,
        accepted_statuses: frozenset[int] = frozenset({200}),
    ) -> HttpResponse:
        """Return one response or fail after a bounded transient retry sequence."""

        _require(
            type(maximum_bytes) is int and 0 <= maximum_bytes <= MAX_ASSET_BYTES,
            "HTTP response bound is invalid",
        )
        request_headers = {
            "Accept": "application/octet-stream",
            "Accept-Encoding": "identity",
            "User-Agent": "Reconcile-publication-verifier/1",
            **dict(headers or {}),
        }
        data = b"" if method not in {"GET", "HEAD"} else None
        request = urllib.request.Request(
            url,
            data=data,
            headers=request_headers,
            method=method,
        )
        last_error: BaseException | None = None
        for attempt in range(self._attempts):
            response: Any | None = None
            try:
                response = self._opener(request, timeout=self._timeout_seconds)
            except urllib.error.HTTPError as error:
                if error.code in _TRANSIENT_HTTP_STATUSES:
                    last_error = error
                    error.close()
                    if attempt + 1 < self._attempts:
                        self._wait(attempt)
                        continue
                    break
                response = error
            except OSError as error:
                last_error = error
                if attempt + 1 < self._attempts:
                    self._wait(attempt)
                    continue
                break

            try:
                try:
                    status = int(response.status)
                    response_headers = _normalized_headers(response.headers)
                    length_header = response_headers.get("content-length")
                    if length_header is not None:
                        try:
                            declared_length = int(length_header)
                        except ValueError as error:
                            raise PublicationVerificationError(
                                "HTTP Content-Length is invalid"
                            ) from error
                        _require(
                            0 <= declared_length <= maximum_bytes,
                            "HTTP response exceeds its byte bound",
                        )
                    body = response.read(maximum_bytes + 1)
                    _require(
                        len(body) <= maximum_bytes,
                        "HTTP response exceeds its byte bound",
                    )
                    if method != "HEAD" and length_header is not None:
                        _require(
                            len(body) == declared_length,
                            "HTTP response length does not match its header",
                        )
                    final_url = response.geturl()
                except (OSError, http.client.HTTPException) as error:
                    last_error = error
                    if attempt + 1 < self._attempts:
                        self._wait(attempt)
                        continue
                    break
            finally:
                response.close()
            _require(status in accepted_statuses, f"unexpected HTTP status {status}")
            return HttpResponse(status, final_url, response_headers, body)

        raise PublicationVerificationError(
            "HTTP request failed after bounded retries"
        ) from last_error


def _reject_constant(value: str) -> None:
    raise ValueError(f"non-finite JSON number: {value}")


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _json_object(payload: bytes, label: str) -> dict[str, Any]:
    try:
        value = json.loads(
            payload.decode("utf-8", errors="strict"),
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=_reject_constant,
        )
    except (UnicodeError, ValueError) as error:
        raise PublicationVerificationError(f"{label} is not strict JSON") from error
    _require(type(value) is dict, f"{label} must be a JSON object")
    return value


def _keys(value: object, expected: frozenset[str], label: str) -> dict[str, Any]:
    _require(type(value) is dict, f"{label} must be an object")
    result = value
    _require(set(result) == expected, f"{label} fields changed")
    return result


def _sha256(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _validate_source_manifest(
    payload: bytes,
    *,
    version: str,
) -> tuple[dict[str, Any], tuple[str, ...]]:
    manifest = _keys(
        _json_object(payload, "release source manifest"),
        frozenset(
            {
                "assets",
                "package_status",
                "project_version",
                "release_version",
                "schema_version",
                "source_repository",
                "source_revision",
                "source_tag",
            }
        ),
        "release source manifest",
    )
    _require(
        canonical_json_bytes(manifest) == payload,
        "release source manifest is not canonical JSON",
    )
    _require(
        manifest["schema_version"] == "reconcile/public-release-source/v2"
        and manifest["package_status"] == "tagged-release"
        and manifest["project_version"] == version
        and manifest["release_version"] == version
        and manifest["source_repository"] == SOURCE_REPOSITORY
        and manifest["source_tag"] == version
        and type(manifest["source_revision"]) is str
        and _SOURCE_REVISION.fullmatch(manifest["source_revision"]) is not None,
        "release source identity is invalid",
    )
    assets = manifest["assets"]
    _require(
        type(assets) is list and bool(assets), "release asset bindings are invalid"
    )
    names: list[str] = []
    for index, item in enumerate(assets):
        binding = _keys(
            item,
            frozenset({"name", "sha256"}),
            f"release asset binding {index}",
        )
        name = binding["name"]
        digest = binding["sha256"]
        _require(
            type(name) is str
            and _ASSET_NAME.fullmatch(name) is not None
            and name not in {SOURCE_MANIFEST_NAME, CHECKSUM_NAME}
            and name not in names
            and type(digest) is str
            and _SHA256.fullmatch(digest) is not None,
            f"release asset binding {index} is invalid",
        )
        names.append(name)
    return manifest, tuple(names)


def _validate_release_payloads(
    payloads: Mapping[str, bytes],
    *,
    version: str,
) -> tuple[dict[str, Any], tuple[str, ...]]:
    _require(
        SOURCE_MANIFEST_NAME in payloads and CHECKSUM_NAME in payloads,
        "release provenance assets are missing",
    )
    manifest, asset_names = _validate_source_manifest(
        payloads[SOURCE_MANIFEST_NAME],
        version=version,
    )
    expected_names = (*asset_names, SOURCE_MANIFEST_NAME, CHECKSUM_NAME)
    _require(
        set(payloads) == set(expected_names),
        "release asset inventory differs from the source manifest",
    )
    for binding in manifest["assets"]:
        _require(
            _sha256(payloads[binding["name"]]) == binding["sha256"],
            f"release asset digest differs: {binding['name']}",
        )
    try:
        checksum_text = payloads[CHECKSUM_NAME].decode("ascii", errors="strict")
    except UnicodeError as error:
        raise PublicationVerificationError("release checksums are not ASCII") from error
    _require(
        checksum_text.endswith("\n") and "\r" not in checksum_text,
        "release checksum framing is invalid",
    )
    checksum_names: list[str] = []
    for line in checksum_text.splitlines():
        match = _CHECKSUM_LINE.fullmatch(line)
        _require(match is not None, "release checksum line is invalid")
        digest, name = match.groups()
        _require(name not in checksum_names, "release checksum name is duplicated")
        _require(name in payloads, "release checksum names an unknown asset")
        _require(_sha256(payloads[name]) == digest, f"release checksum differs: {name}")
        checksum_names.append(name)
    _require(
        tuple(checksum_names) == (*asset_names, SOURCE_MANIFEST_NAME),
        "release checksum inventory or order is invalid",
    )
    return manifest, expected_names


def _validate_evidence_payloads(
    payloads: Mapping[str, bytes],
    *,
    version: str,
) -> str:
    evidence_names = (
        "proof-to-permit.json",
        "provider-proof.json",
        "live-corroboration.json",
        "cleanup-verification.json",
    )
    _require(
        all(name in payloads for name in evidence_names),
        "release evidence inventory is incomplete",
    )
    try:
        with tempfile.TemporaryDirectory(
            prefix="reconcile-publication-evidence-"
        ) as temporary:
            evidence_root = Path(temporary) / version
            evidence_root.mkdir(mode=0o700)
            for name in evidence_names:
                (evidence_root / name).write_bytes(payloads[name])
            evidence = load_and_validate(evidence_root / "proof-to-permit.json")
        candidate = evidence["provider_proof"]["candidate"]
        evidence_source_revision = candidate["source_revision"]
    except (EvidenceError, KeyError, TypeError, OSError) as error:
        raise PublicationVerificationError("release evidence is invalid") from error
    _require(
        type(evidence_source_revision) is str
        and _SOURCE_REVISION.fullmatch(evidence_source_revision) is not None,
        "release evidence source identity is invalid",
    )
    return evidence_source_revision


def _expected_snapshot_payload(
    payloads: Mapping[str, bytes],
    *,
    version: str,
    viewer_source_revision: str,
) -> bytes:
    evidence_names = (
        "proof-to-permit.json",
        "provider-proof.json",
        "live-corroboration.json",
        "cleanup-verification.json",
    )
    try:
        with tempfile.TemporaryDirectory(
            prefix="reconcile-publication-projection-"
        ) as temporary:
            evidence_root = Path(temporary) / version
            evidence_root.mkdir(mode=0o700)
            for name in evidence_names:
                (evidence_root / name).write_bytes(payloads[name])
            return canonical_json_bytes(
                _build_snapshot(evidence_root, viewer_source_revision)
            )
    except (
        KeyError,
        OSError,
        PublicContractError,
        ValueError,
        ViewerExportError,
    ) as error:
        raise PublicationVerificationError(
            "release evidence projection is invalid"
        ) from error


def _load_local_release(
    directory: Path, *, version: str
) -> tuple[ReleaseIdentity, dict[str, bytes]]:
    _require(isinstance(directory, Path), "release directory is invalid")
    try:
        entries = tuple(directory.iterdir())
    except OSError as error:
        raise PublicationVerificationError("release directory is unreadable") from error
    _require(
        bool(entries)
        and all(path.is_file() and not path.is_symlink() for path in entries),
        "release directory inventory is invalid",
    )
    try:
        payloads = {path.name: path.read_bytes() for path in entries}
    except OSError as error:
        raise PublicationVerificationError("release asset is unreadable") from error
    _require(
        all(len(payload) <= MAX_ASSET_BYTES for payload in payloads.values()),
        "local release asset exceeds its byte bound",
    )
    manifest, expected_names = _validate_release_payloads(payloads, version=version)
    evidence_source_revision = _validate_evidence_payloads(payloads, version=version)
    evidence_names = (
        "proof-to-permit.json",
        "provider-proof.json",
        "live-corroboration.json",
        "cleanup-verification.json",
    )
    _require(
        all(name in payloads for name in evidence_names),
        "release evidence inventory is incomplete",
    )
    identity = ReleaseIdentity(
        version=version,
        source_revision=manifest["source_revision"],
        evidence_source_revision=evidence_source_revision,
        evidence_sha256={name: _sha256(payloads[name]) for name in evidence_names},
        expected_snapshot=_expected_snapshot_payload(
            payloads,
            version=version,
            viewer_source_revision=manifest["source_revision"],
        ),
        asset_names=expected_names,
    )
    return identity, payloads


def _repository_slug() -> str:
    prefix = "https://github.com/"
    _require(SOURCE_REPOSITORY.startswith(prefix), "source repository is invalid")
    slug = SOURCE_REPOSITORY.removeprefix(prefix)
    _require(
        slug.count("/") == 1 and all(part for part in slug.split("/")),
        "source repository is invalid",
    )
    return slug


def _github_json(client: BoundedHttpClient, url: str, label: str) -> dict[str, Any]:
    response = client.request(
        url,
        maximum_bytes=MAX_METADATA_BYTES,
        headers={"Accept": "application/vnd.github+json"},
    )
    _require(response.url == url, f"{label} unexpectedly redirected")
    return _json_object(response.body, label)


def _verify_github_tag(
    client: BoundedHttpClient,
    *,
    slug: str,
    version: str,
    source_revision: str,
) -> None:
    encoded_tag = urllib.parse.quote(version, safe="")
    ref_url = f"{GITHUB_API_ROOT}/repos/{slug}/git/ref/tags/{encoded_tag}"
    ref = _github_json(client, ref_url, "GitHub tag reference")
    target = ref.get("object")
    _require(type(target) is dict, "GitHub tag target is invalid")
    target_type = target.get("type")
    target_sha = target.get("sha")
    if target_type == "tag" and type(target_sha) is str:
        tag_url = f"{GITHUB_API_ROOT}/repos/{slug}/git/tags/{target_sha}"
        tag = _github_json(client, tag_url, "GitHub annotated tag")
        target = tag.get("object")
        _require(
            tag.get("tag") == version and type(target) is dict,
            "GitHub annotated tag identity is invalid",
        )
        target_type = target.get("type")
        target_sha = target.get("sha")
    _require(
        target_type == "commit" and target_sha == source_revision,
        "GitHub tag does not identify the release source revision",
    )


def verify_github_release(
    client: BoundedHttpClient,
    identity: ReleaseIdentity,
    expected_payloads: Mapping[str, bytes],
) -> int:
    """Verify release metadata, tag identity, and every downloaded asset byte."""

    slug = _repository_slug()
    encoded_tag = urllib.parse.quote(identity.version, safe="")
    release_api = f"{GITHUB_API_ROOT}/repos/{slug}/releases/tags/{encoded_tag}"
    metadata = _github_json(client, release_api, "GitHub release metadata")
    _require(
        metadata.get("tag_name") == identity.version
        and metadata.get("draft") is False
        and metadata.get("prerelease") is False
        and type(metadata.get("published_at")) is str
        and _RFC3339_UTC.fullmatch(metadata["published_at"]) is not None
        and metadata.get("html_url")
        == f"{SOURCE_REPOSITORY}/releases/tag/{identity.version}",
        "GitHub release metadata is invalid",
    )
    assets = metadata.get("assets")
    _require(type(assets) is list, "GitHub release asset metadata is invalid")
    remote_assets: dict[str, dict[str, Any]] = {}
    for item in assets:
        _require(type(item) is dict, "GitHub release asset metadata is invalid")
        name = item.get("name")
        _require(
            type(name) is str and name not in remote_assets,
            "GitHub release asset names are invalid",
        )
        remote_assets[name] = item
    _require(
        set(remote_assets) == set(identity.asset_names),
        "GitHub release asset inventory differs",
    )
    downloaded: dict[str, bytes] = {}
    for name in identity.asset_names:
        item = remote_assets[name]
        expected = expected_payloads[name]
        expected_url = (
            f"{SOURCE_REPOSITORY}/releases/download/{identity.version}/"
            f"{urllib.parse.quote(name, safe='')}"
        )
        _require(
            item.get("state") == "uploaded"
            and item.get("size") == len(expected)
            and item.get("browser_download_url") == expected_url,
            f"GitHub release asset metadata differs: {name}",
        )
        response = client.request(expected_url, maximum_bytes=len(expected))
        final = urllib.parse.urlsplit(response.url)
        _require(
            final.scheme == "https"
            and (
                final.netloc == "github.com"
                or final.netloc.endswith(".githubusercontent.com")
            )
            and response.body == expected,
            f"GitHub release asset bytes differ: {name}",
        )
        downloaded[name] = response.body
    _validate_release_payloads(downloaded, version=identity.version)
    _require(
        _validate_evidence_payloads(downloaded, version=identity.version)
        == identity.evidence_source_revision,
        "downloaded evidence source identity differs",
    )
    _verify_github_tag(
        client,
        slug=slug,
        version=identity.version,
        source_revision=identity.source_revision,
    )
    return len(downloaded)


def _viewer_url(base_url: str, path: str) -> str:
    parsed = urllib.parse.urlsplit(base_url)
    _require(
        parsed.scheme == "https"
        and bool(parsed.netloc)
        and parsed.path in {"", "/"}
        and not parsed.query
        and not parsed.fragment,
        "viewer URL is invalid",
    )
    return base_url.rstrip("/") + path


def _verify_security_headers(response: HttpResponse) -> None:
    for name, expected in _SECURITY_HEADERS.items():
        _require(
            response.headers.get(name) == expected,
            f"viewer security header differs: {name}",
        )


def _verify_viewer_response(
    response: HttpResponse,
    *,
    expected_url: str,
    expected_status: int,
    expected_body: bytes | None = None,
    expected_content_type: str | None = None,
) -> None:
    _require(response.url == expected_url, "viewer request unexpectedly redirected")
    _require(response.status == expected_status, "viewer status differs")
    _verify_security_headers(response)
    if expected_body is not None:
        _require(response.body == expected_body, "viewer response body differs")
    if expected_content_type is not None:
        _require(
            response.headers.get("content-type") == expected_content_type,
            "viewer content type differs",
        )


def _verify_entity_headers(response: HttpResponse, payload: bytes) -> None:
    _require(
        response.headers.get("etag") == f'"sha256:{sha256_hex(payload)}"'
        and response.headers.get("content-length") == str(len(payload)),
        "viewer entity headers differ",
    )


def verify_viewer(
    client: BoundedHttpClient,
    identity: ReleaseIdentity,
    *,
    viewer_url: str,
) -> tuple[int, int]:
    """Verify the retained viewer bytes, identities, routes, and mutation refusal."""

    responses: dict[str, HttpResponse] = {}
    content_types = {
        "/": "text/html; charset=utf-8",
        "/index.html": "text/html; charset=utf-8",
        "/snapshot.json": "application/json; charset=utf-8",
        "/bundle-manifest.json": "application/json; charset=utf-8",
        "/health": "application/json; charset=utf-8",
    }
    for path, content_type in content_types.items():
        url = _viewer_url(viewer_url, path)
        response = client.request(url, maximum_bytes=MAX_VIEWER_BYTES)
        _verify_viewer_response(
            response,
            expected_url=url,
            expected_status=200,
            expected_content_type=content_type,
        )
        _verify_entity_headers(response, response.body)
        responses[path] = response

    snapshot_payload = responses["/snapshot.json"].body
    html_payload = responses["/"].body
    manifest_payload = responses["/bundle-manifest.json"].body
    try:
        _require(
            snapshot_payload == identity.expected_snapshot,
            "viewer snapshot differs from the released evidence projection",
        )
        snapshot = decode_snapshot(snapshot_payload)
        _require(
            snapshot["schema_version"] == SNAPSHOT_VERSION,
            "viewer snapshot schema is not current",
        )
        _require(render_html(snapshot) == html_payload, "viewer HTML is not derived")
        decode_manifest(manifest_payload, snapshot, snapshot_payload, html_payload)
    except (KeyError, PublicContractError) as error:
        raise PublicationVerificationError(
            "viewer bundle contract is invalid"
        ) from error
    _require(
        responses["/index.html"].body == html_payload,
        "viewer HTML routes differ",
    )
    _require(
        snapshot["evidence_version"] == identity.version
        and snapshot["viewer_source_revision"] == identity.source_revision
        and snapshot["evidence_source_revision"] == identity.evidence_source_revision,
        "viewer release or source identity differs",
    )
    evidence = snapshot["evidence"]
    expected_evidence_hashes = {
        "manifest_sha256": identity.evidence_sha256["proof-to-permit.json"],
        "provider_proof_sha256": identity.evidence_sha256["provider-proof.json"],
        "live_corroboration_sha256": identity.evidence_sha256[
            "live-corroboration.json"
        ],
        "cleanup_verification_sha256": identity.evidence_sha256[
            "cleanup-verification.json"
        ],
    }
    _require(
        all(
            evidence.get(name) == digest
            for name, digest in expected_evidence_hashes.items()
        ),
        "viewer evidence hashes differ from the release",
    )
    expected_health = canonical_json_bytes(
        {"snapshot_sha256": sha256_hex(snapshot_payload), "status": "ok"}
    )
    _require(
        responses["/health"].body == expected_health,
        "viewer health identity differs",
    )

    head_url = _viewer_url(viewer_url, "/snapshot.json")
    head = client.request(
        head_url,
        method="HEAD",
        maximum_bytes=MAX_VIEWER_BYTES,
    )
    _verify_viewer_response(
        head,
        expected_url=head_url,
        expected_status=200,
        expected_body=b"",
        expected_content_type="application/json; charset=utf-8",
    )
    _require(
        head.headers.get("etag") == responses["/snapshot.json"].headers.get("etag")
        and head.headers.get("content-length") == str(len(snapshot_payload)),
        "viewer HEAD identity differs",
    )
    conditional = client.request(
        head_url,
        maximum_bytes=0,
        headers={"If-None-Match": head.headers["etag"]},
        accepted_statuses=frozenset({304}),
    )
    _verify_viewer_response(
        conditional,
        expected_url=head_url,
        expected_status=304,
        expected_body=b"",
    )
    _require(
        conditional.headers.get("etag") == head.headers.get("etag")
        and conditional.headers.get("content-length") == "0",
        "viewer conditional response identity differs",
    )

    error_routes = (("/missing", 404), ("/snapshot.json?unexpected=1", 400))
    for path, status in error_routes:
        url = _viewer_url(viewer_url, path)
        response = client.request(
            url,
            maximum_bytes=0,
            accepted_statuses=frozenset({status}),
        )
        _verify_viewer_response(
            response,
            expected_url=url,
            expected_status=status,
            expected_body=b"",
        )

    mutation_methods = ("POST", "PUT", "PATCH", "DELETE", "OPTIONS")
    root_url = _viewer_url(viewer_url, "/")
    for method in mutation_methods:
        response = client.request(
            root_url,
            method=method,
            maximum_bytes=0,
            accepted_statuses=frozenset({405}),
        )
        _verify_viewer_response(
            response,
            expected_url=root_url,
            expected_status=405,
            expected_body=b"",
        )
        _require(
            response.headers.get("allow") == "GET, HEAD",
            "viewer mutation refusal Allow header differs",
        )
    return len(content_types) + 1 + 1 + len(error_routes), len(mutation_methods)


def verify_publication(
    release_directory: Path,
    *,
    version: str = RELEASE_VERSION,
    viewer_url: str = DEFAULT_VIEWER_URL,
    client: BoundedHttpClient | None = None,
) -> VerificationSummary:
    """Verify one exact release and the retained viewer that projects it."""

    _require(_VERSION.fullmatch(version) is not None, "release version is invalid")
    _require(
        version == RELEASE_VERSION,
        "release version must equal the configured package version",
    )
    identity, payloads = _load_local_release(release_directory, version=version)
    active_client = client or BoundedHttpClient()
    release_assets = verify_github_release(active_client, identity, payloads)
    viewer_routes, mutation_methods = verify_viewer(
        active_client,
        identity,
        viewer_url=viewer_url,
    )
    return VerificationSummary(release_assets, viewer_routes, mutation_methods)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Verify a published release and its retained evidence viewer."
    )
    parser.add_argument("--release-directory", required=True, type=Path)
    parser.add_argument("--version", default=RELEASE_VERSION)
    parser.add_argument("--viewer-url", default=DEFAULT_VIEWER_URL)
    parser.add_argument("--attempts", default=4, type=int)
    parser.add_argument("--timeout-seconds", default=10.0, type=float)
    arguments = parser.parse_args()
    try:
        summary = verify_publication(
            arguments.release_directory.resolve(),
            version=arguments.version,
            viewer_url=arguments.viewer_url,
            client=BoundedHttpClient(
                attempts=arguments.attempts,
                timeout_seconds=arguments.timeout_seconds,
            ),
        )
    except (
        EvidenceError,
        OSError,
        PublicationVerificationError,
        PublicContractError,
        UnicodeError,
        ValueError,
    ) as error:
        print(f"FAIL: {error}", file=sys.stderr)
        return 1
    print("Reconcile publication: PASS")
    print(f"  release assets: {summary.release_assets} exact download(s)")
    print(f"  viewer routes: {summary.viewer_routes} checked")
    print(f"  mutation methods: {summary.mutation_methods} rejected")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())


__all__ = [
    "DEFAULT_VIEWER_URL",
    "BoundedHttpClient",
    "HttpResponse",
    "PublicationVerificationError",
    "ReleaseIdentity",
    "VerificationSummary",
    "verify_github_release",
    "verify_publication",
    "verify_viewer",
]
