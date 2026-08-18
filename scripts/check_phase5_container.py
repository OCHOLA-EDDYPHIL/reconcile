from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import stat
import subprocess
import tarfile
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any
from uuid import uuid4

_ROOT = Path(__file__).parents[1]
_DOCKERFILE = _ROOT / "Dockerfile"
_DOCKERIGNORE = _ROOT / ".dockerignore"
_PROJECT = "reconcile-dev-260813-14fa6d"
_REGION = "us-central1"
_SOURCE_REVISION = re.compile(r"[0-9a-f]{40}")
_IMAGE_DIGEST = re.compile(r"sha256:[0-9a-f]{64}")
_ARCHIVE_SHA256 = re.compile(r"[0-9a-f]{64}")
_MAX_ARTIFACT_BYTES = 4 * 1_073_741_824
_PYTHON_MANIFEST = (
    "python:3.12.13-slim-bookworm@"
    "sha256:6e13e65c55e33adf203d77ee371cf8bf5d81bd4902ef07565721f46bf44917af"
)
_UV_MANIFEST = (
    "ghcr.io/astral-sh/uv@"
    "sha256:dfd1e6972e100ca2fbf1f391effc3dd4aa57f319bf03c3e321e0a3f3341ed5af"
)
_BUILDX_IMAGE = (
    "docker/buildx-bin@"
    "sha256:5142d4e80b699fe7be8c9d196c776704f7128ded6dd24cb56cbd0231b1e9f232"
)
_BUILDX_BINARY_SHA256 = (
    "d41ece72044243b4f58b343441ae37446d9c29a7d6b5e11c61847bbcf8f7dfda"
)
_BUILDX_BINARY_SIZE = 65_265_826
_BUILDX_VERSION = (
    "github.com/docker/buildx v0.35.0 a319e5b15052cf6557ceb666eb8ff6e32380b782"
)
_BUILDKIT_IMAGE = (
    "moby/buildkit@"
    "sha256:72bda77240181301a0d5ee57d39fa58e4aabd7eff26f81bbf108088caf810f05"
)
_BUILDKIT_VERSION = "v0.25.2"
_PROMPT_VERSION = "adaptive-planner-v3"
_PROMPT_SHA256 = "a18ac5bbd22570562acc6dfbc49437a82f0db6a265a4de737c1371b6ef2ca2d3"
_ENTRYPOINT = ["/opt/reconcile/bin/python", "-m", "reconcile.hosted"]
_DOCKERIGNORE_LINES = (
    "**",
    "!.dockerignore",
    "!Dockerfile",
    "!pyproject.toml",
    "!uv.lock",
    "!reconcile/",
    "!reconcile/**",
    "reconcile/**/__pycache__/",
    "reconcile/**/*.pyc",
    "reconcile/**/*.pyo",
)
_OCI_INDEX = "application/vnd.oci.image.index.v1+json"
_OCI_MANIFEST = "application/vnd.oci.image.manifest.v1+json"
_OCI_CONFIG = "application/vnd.oci.image.config.v1+json"
_OCI_REFERENCE_ANNOTATION = "org.opencontainers.image.ref.name"
_OCI_LAYERS = frozenset(
    {
        "application/vnd.oci.image.layer.v1.tar",
        "application/vnd.oci.image.layer.v1.tar+gzip",
    }
)
_CREDENTIAL_ENVIRONMENT = frozenset(
    {
        "AWS_ACCESS_KEY_ID",
        "AWS_SECRET_ACCESS_KEY",
        "AZURE_CLIENT_SECRET",
        "CLOUDSDK_CONFIG",
        "DOCKER_AUTH_CONFIG",
        "DOCKER_CONFIG",
        "GOOGLE_APPLICATION_CREDENTIALS",
    }
)


class ContainerGateError(RuntimeError):
    """A sanitized immutable-container verification failure."""


@dataclass(frozen=True, slots=True)
class OciImage:
    manifest_digest: str
    config_digest: str
    source_tag: str | None
    archive_sha256: str
    config: dict[str, Any]


@dataclass(frozen=True, slots=True)
class GateResult:
    status: str
    reason: str
    image_digest: str | None = None
    archive_sha256: str | None = None
    config_digest: str | None = None
    source_tag: str | None = None

    def canonical_json(self) -> str:
        return json.dumps(
            {
                "schema_version": "reconcile/phase5-container-gate/v1",
                "status": self.status,
                "reason": self.reason,
                "image_digest": self.image_digest,
                "archive_sha256": self.archive_sha256,
                "config_digest": self.config_digest,
                "source_tag": self.source_tag,
            },
            sort_keys=True,
            separators=(",", ":"),
        )


def _fail(message: str) -> None:
    raise ContainerGateError(message) from None


def _read_exact(path: Path, maximum_bytes: int = 2_000_000) -> str:
    if path.is_symlink() or not path.is_file():
        _fail(f"{path.name} is not an exact regular file")
    payload = path.read_bytes()
    if not payload or len(payload) > maximum_bytes:
        _fail(f"{path.name} has an invalid size")
    try:
        return payload.decode("utf-8")
    except UnicodeDecodeError:
        _fail(f"{path.name} is not UTF-8")


def verify_static_contract(source_root: Path | None = None) -> None:
    root = _ROOT if source_root is None else source_root
    dockerfile = _read_exact(root / "Dockerfile")
    dockerignore = _read_exact(root / ".dockerignore", 4_096)
    if tuple(dockerignore.splitlines()) != _DOCKERIGNORE_LINES:
        _fail(".dockerignore is not the closed build-context allowlist")
    required = (
        f"ARG PYTHON_IMAGE={_PYTHON_MANIFEST}",
        f"ARG UV_IMAGE={_UV_MANIFEST}",
        "COPY pyproject.toml uv.lock ./",
        "COPY reconcile ./reconcile",
        "uv sync --locked --no-dev --no-editable",
        'cache="$metadata/uv_cache.json"',
        'rm "$cache"',
        "COPY --from=builder --chown=65532:65532 /opt/reconcile /opt/reconcile",
        "USER 65532:65532",
        'ENTRYPOINT ["/opt/reconcile/bin/python", "-m", "reconcile.hosted"]',
    )
    if any(item not in dockerfile for item in required):
        _fail("Dockerfile does not retain the immutable runtime contract")
    disallowed = (
        "COPY . ",
        "COPY ./ ",
        "ADD ",
        "USER root",
        "docker login",
        "docker push",
        "gcloud ",
        "GOOGLE_APPLICATION_CREDENTIALS",
    )
    if any(item.casefold() in dockerfile.casefold() for item in disallowed):
        _fail("Dockerfile contains a forbidden build or credential path")
    for path in (root / "pyproject.toml", root / "uv.lock", root / "reconcile"):
        if path.is_symlink():
            _fail("container context contains a symbolic-link root")
    for path in (root / "reconcile").rglob("*"):
        if path.is_symlink():
            _fail("container context contains a symbolic link")


def _minimal_environment(
    docker_config: Path,
    *,
    docker_host: str | None = None,
) -> dict[str, str]:
    environment = {
        "DOCKER_CONFIG": str(docker_config),
        "HOME": str(docker_config.parent),
        "PATH": os.environ.get("PATH", "/usr/local/bin:/usr/bin:/bin"),
    }
    if docker_host is not None:
        if not docker_host.startswith("unix:///") or any(
            ord(character) < 0x21 for character in docker_host
        ):
            _fail("explicit Docker host is invalid")
        environment["DOCKER_HOST"] = docker_host
        return environment
    for name in ("DOCKER_HOST", "DOCKER_TLS_VERIFY", "DOCKER_CERT_PATH"):
        value = os.environ.get(name)
        if value:
            environment[name] = value
    return environment


def _run(
    command: list[str],
    *,
    environment: dict[str, str],
    timeout: float = 900,
    expected: frozenset[int] = frozenset({0}),
) -> subprocess.CompletedProcess[str]:
    if not command or Path(command[0]).name not in {"docker", "docker-29.6.2"}:
        _fail("container gate attempted a non-Docker process")
    rendered = " ".join(command).casefold()
    if any(item in rendered for item in (" login", " push", "--push")):
        _fail("container gate attempted a registry mutation")
    try:
        result = subprocess.run(
            command,
            check=False,
            capture_output=True,
            env=environment,
            text=True,
            timeout=timeout,
        )
    except (OSError, subprocess.SubprocessError):
        _fail("container command could not be completed")
    if result.returncode not in expected:
        _fail("container command failed")
    return result


def _docker_capability(
    docker: str,
    environment: dict[str, str],
    *,
    require_daemon: bool = False,
) -> GateResult | None:
    daemon = _run(
        [
            docker,
            "version",
            "--format",
            ("{{.Client.Version}}|{{.Server.Version}}|{{.Server.Os}}|{{.Server.Arch}}"),
        ],
        environment=environment,
        timeout=15,
        expected=frozenset(range(256)),
    )
    if daemon.returncode != 0 or not daemon.stdout.strip():
        if require_daemon:
            _fail("Docker daemon is required")
        return GateResult(status="skipped", reason="docker-daemon-unavailable")
    fields = daemon.stdout.strip().split("|")
    if fields != ["29.6.2", "29.6.2", "linux", "amd64"]:
        _fail("Docker client and Linux amd64 daemon 29.6.2 are required")
    return None


def _hash_file(path: Path) -> str:
    digest = hashlib.sha256()
    try:
        with path.open("rb") as source:
            while chunk := source.read(1024 * 1024):
                digest.update(chunk)
    except OSError:
        _fail("Buildx plugin could not be verified")
    return digest.hexdigest()


def _bootstrap_buildx(
    docker: str,
    environment: dict[str, str],
    docker_config: Path,
) -> None:
    plugin_directory = docker_config / "cli-plugins"
    plugin_directory.mkdir(mode=0o700)
    plugin = plugin_directory / "docker-buildx"
    bootstrap = f"reconcile-buildx-bootstrap-{uuid4().hex[:16]}"
    created = False
    try:
        _run(
            [
                docker,
                "create",
                "--name",
                bootstrap,
                "--platform",
                "linux/amd64",
                _BUILDX_IMAGE,
                "/buildx",
                "version",
            ],
            environment=environment,
            timeout=120,
        )
        created = True
        _run(
            [docker, "cp", f"{bootstrap}:/buildx", str(plugin)],
            environment=environment,
            timeout=60,
        )
    finally:
        removed = _run(
            [docker, "rm", "--force", bootstrap],
            environment=environment,
            timeout=30,
            expected=frozenset(range(256)),
        )
        if created and removed.returncode != 0:
            _fail("Buildx bootstrap container could not be removed")
    if (
        plugin.is_symlink()
        or not plugin.is_file()
        or plugin.stat().st_size != _BUILDX_BINARY_SIZE
        or _hash_file(plugin) != _BUILDX_BINARY_SHA256
    ):
        _fail("Buildx plugin does not match the pinned amd64 binary")
    plugin.chmod(0o700)
    version = _run(
        [docker, "buildx", "version"],
        environment=environment,
        timeout=15,
        expected=frozenset(range(256)),
    )
    if version.returncode != 0 or version.stdout.strip() != _BUILDX_VERSION:
        _fail("Buildx plugin does not match the pinned version")


def _remove_builder(
    docker: str,
    environment: dict[str, str],
    builder: str,
) -> None:
    removed = _run(
        [docker, "buildx", "rm", "--force", builder],
        environment=environment,
        timeout=120,
        expected=frozenset(range(256)),
    )
    if removed.returncode != 0:
        _fail("isolated BuildKit builder could not be removed")


def _create_builder(
    docker: str,
    environment: dict[str, str],
) -> str:
    builder = f"reconcile-phase5-{uuid4().hex[:16]}"
    created = False
    try:
        _run(
            [
                docker,
                "buildx",
                "create",
                "--name",
                builder,
                "--driver",
                "docker-container",
                "--driver-opt",
                f"image={_BUILDKIT_IMAGE}",
            ],
            environment=environment,
            timeout=120,
        )
        created = True
        inspected = _run(
            [docker, "buildx", "inspect", builder, "--bootstrap"],
            environment=environment,
            timeout=180,
        )
        required = (
            re.search(r"(?m)^Driver:\s+docker-container\s*$", inspected.stdout),
            re.search(r"(?m)^Status:\s+running\s*$", inspected.stdout),
            re.search(
                rf"(?m)^BuildKit version:\s+{re.escape(_BUILDKIT_VERSION)}\s*$",
                inspected.stdout,
            ),
            f'image="{_BUILDKIT_IMAGE}"' in inspected.stdout,
            "linux/amd64" in inspected.stdout,
        )
        if not all(required):
            _fail("isolated BuildKit builder did not match the pinned contract")
        container = f"buildx_buildkit_{builder}0"
        runtime = _run(
            [
                docker,
                "inspect",
                container,
                "--format",
                (
                    "{{.Config.Image}}|{{json .Mounts}}|"
                    "{{.HostConfig.NetworkMode}}|{{.HostConfig.Privileged}}"
                ),
            ],
            environment=environment,
            timeout=15,
        )
        fields = runtime.stdout.strip().split("|", 3)
        if len(fields) != 4:
            _fail("isolated BuildKit runtime could not be verified")
        try:
            mounts = json.loads(fields[1])
        except json.JSONDecodeError:
            _fail("isolated BuildKit mounts could not be verified")
        if (
            fields[0] != _BUILDKIT_IMAGE
            or fields[2] != "bridge"
            or fields[3] != "true"
            or not isinstance(mounts, list)
            or len(mounts) != 1
            or mounts[0].get("Type") != "volume"
            or mounts[0].get("Destination") != "/var/lib/buildkit"
        ):
            _fail("isolated BuildKit runtime exposed an unexpected host resource")
        return builder
    except BaseException:
        if created:
            _remove_builder(docker, environment, builder)
        raise


def _canonical_json(payload: bytes, label: str) -> dict[str, Any]:
    try:
        decoded = json.loads(payload)
    except (UnicodeDecodeError, json.JSONDecodeError):
        _fail(f"{label} is not canonical JSON")
    if not isinstance(decoded, dict):
        _fail(f"{label} is not a JSON object")
    encoded = json.dumps(
        decoded,
        sort_keys=True,
        separators=(",", ":"),
    ).encode()
    if json.loads(encoded) != decoded:
        _fail(f"{label} did not round-trip")
    return decoded


def _normalized_member(name: str) -> str:
    candidate = name.removeprefix("./")
    path = PurePosixPath(candidate)
    if not candidate or path.is_absolute() or ".." in path.parts:
        _fail("OCI archive contains an unsafe path")
    return path.as_posix()


def _members(archive: tarfile.TarFile) -> dict[str, tarfile.TarInfo]:
    indexed: dict[str, tarfile.TarInfo] = {}
    for member in archive.getmembers():
        name = _normalized_member(member.name)
        if name in indexed:
            _fail("OCI archive contains a duplicate path")
        indexed[name] = member
    return indexed


def _read_member(
    archive: tarfile.TarFile,
    members: dict[str, tarfile.TarInfo],
    name: str,
    *,
    maximum_bytes: int = 2_000_000,
) -> bytes:
    member = members.get(name)
    if member is None or not member.isfile() or member.size > maximum_bytes:
        _fail("OCI archive is incomplete")
    source = archive.extractfile(member)
    if source is None:
        _fail("OCI archive member could not be read")
    payload = source.read(maximum_bytes + 1)
    if len(payload) != member.size:
        _fail("OCI archive member size is inconsistent")
    return payload


def _descriptor(
    value: object,
    *,
    expected_media_types: frozenset[str],
) -> tuple[str, int, str]:
    if not isinstance(value, dict):
        _fail("OCI descriptor is invalid")
    media_type = value.get("mediaType")
    digest = value.get("digest")
    size = value.get("size")
    if (
        media_type not in expected_media_types
        or not isinstance(digest, str)
        or _IMAGE_DIGEST.fullmatch(digest) is None
        or type(size) is not int
        or size < 1
    ):
        _fail("OCI descriptor is invalid")
    return digest, size, media_type


def _verify_blob(
    archive: tarfile.TarFile,
    members: dict[str, tarfile.TarInfo],
    digest: str,
    size: int,
) -> tarfile.TarInfo:
    algorithm, value = digest.split(":", 1)
    member = members.get(f"blobs/{algorithm}/{value}")
    if member is None or not member.isfile() or member.size != size:
        _fail("OCI blob is absent or has the wrong size")
    source = archive.extractfile(member)
    if source is None:
        _fail("OCI blob could not be read")
    computed = hashlib.sha256()
    while chunk := source.read(1024 * 1024):
        computed.update(chunk)
    if computed.hexdigest() != value:
        _fail("OCI blob digest does not match")
    return member


def _forbidden_layer_path(name: str) -> bool:
    path = PurePosixPath(name.casefold())
    parts = path.parts
    basename = path.name
    if any(part in {".git", ".terraform"} for part in parts):
        return True
    if basename == ".env" or basename.startswith(".env."):
        return True
    if basename.endswith((".tfstate", ".tfplan", ".tfvars", ".tfvars.json")):
        return True
    if parts[:3] in {
        ("root", ".config", "gcloud"),
        ("root", ".docker", "config.json"),
    }:
        return True
    return bool(parts and parts[0] == "artifacts") or (
        len(parts) > 1
        and parts[0] in {"app", "src", "workspace"}
        and parts[1] == "artifacts"
    )


def _inspect_layer(
    archive: tarfile.TarFile,
    member: tarfile.TarInfo,
) -> None:
    source = archive.extractfile(member)
    if source is None:
        _fail("OCI layer could not be read")
    try:
        with tarfile.open(fileobj=source, mode="r|*") as layer:
            for item in layer:
                name = _normalized_member(item.name)
                if _forbidden_layer_path(name):
                    _fail("OCI image contains a forbidden repository artifact")
    except tarfile.TarError:
        _fail("OCI layer is not a supported tar stream")


def _verify_config(config: dict[str, Any], source_revision: str) -> None:
    runtime = config.get("config")
    if (
        config.get("architecture") != "amd64"
        or config.get("os") != "linux"
        or not isinstance(runtime, dict)
        or runtime.get("User") != "65532:65532"
        or runtime.get("Entrypoint") != _ENTRYPOINT
        or runtime.get("Cmd") not in (None, [])
        or runtime.get("WorkingDir") != "/app"
    ):
        _fail("OCI runtime configuration is not the pinned nonroot contract")
    labels = runtime.get("Labels")
    if (
        not isinstance(labels, dict)
        or labels.get("org.opencontainers.image.revision") != source_revision
    ):
        _fail("OCI source revision label is absent or drifted")
    environment = runtime.get("Env") or []
    if not isinstance(environment, list) or any(
        not isinstance(item, str) or "=" not in item for item in environment
    ):
        _fail("OCI environment is invalid")
    names = {item.split("=", 1)[0] for item in environment}
    if names & _CREDENTIAL_ENVIRONMENT or any(
        name.endswith(("_PASSWORD", "_SECRET", "_TOKEN")) for name in names
    ):
        _fail("OCI environment contains a credential-bearing name")


def _archive_sha256(path: Path) -> str:
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    except OSError:
        _fail("OCI archive could not be read")
    try:
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_size < 1
            or before.st_size > _MAX_ARTIFACT_BYTES
        ):
            _fail("OCI archive has an invalid size or type")
        digest = hashlib.sha256()
        observed = 0
        while chunk := os.read(descriptor, 1_048_576):
            observed += len(chunk)
            if observed > _MAX_ARTIFACT_BYTES:
                _fail("OCI archive exceeds the artifact limit")
            digest.update(chunk)
        after = os.fstat(descriptor)
        identity_before = (
            before.st_dev,
            before.st_ino,
            before.st_size,
            before.st_mtime_ns,
            before.st_ctime_ns,
        )
        identity_after = (
            after.st_dev,
            after.st_ino,
            after.st_size,
            after.st_mtime_ns,
            after.st_ctime_ns,
        )
        if observed != before.st_size or identity_after != identity_before:
            _fail("OCI archive changed while it was read")
        return digest.hexdigest()
    finally:
        os.close(descriptor)


def verify_oci_archive(
    path: Path,
    source_revision: str,
    *,
    expected_source_tag: str | None = None,
) -> OciImage:
    if _SOURCE_REVISION.fullmatch(source_revision) is None:
        _fail("source revision is invalid")
    if path.is_symlink() or not path.is_file():
        _fail("OCI archive is not an exact regular file")
    try:
        with tarfile.open(path, mode="r:*") as archive:
            members = _members(archive)
            layout = _canonical_json(
                _read_member(archive, members, "oci-layout"),
                "OCI layout",
            )
            if layout != {"imageLayoutVersion": "1.0.0"}:
                _fail("OCI layout version is not exact")
            index = _canonical_json(
                _read_member(archive, members, "index.json"),
                "OCI index",
            )
            manifests = index.get("manifests")
            if (
                index.get("schemaVersion") != 2
                or index.get("mediaType") not in (None, _OCI_INDEX)
                or not isinstance(manifests, list)
                or len(manifests) != 1
            ):
                _fail("OCI index does not contain one image")
            manifest_digest, manifest_size, _ = _descriptor(
                manifests[0], expected_media_types=frozenset({_OCI_MANIFEST})
            )
            manifest_descriptor = manifests[0]
            annotations = (
                manifest_descriptor.get("annotations")
                if isinstance(manifest_descriptor, dict)
                else None
            )
            source_tag = (
                annotations.get(_OCI_REFERENCE_ANNOTATION)
                if isinstance(annotations, dict)
                else None
            )
            if source_tag is not None and not isinstance(source_tag, str):
                _fail("OCI source tag annotation is invalid")
            if expected_source_tag is not None and source_tag != expected_source_tag:
                _fail("OCI source tag annotation does not match")
            manifest_member = _verify_blob(
                archive,
                members,
                manifest_digest,
                manifest_size,
            )
            manifest_payload = _read_member(
                archive,
                members,
                _normalized_member(manifest_member.name),
            )
            manifest = _canonical_json(manifest_payload, "OCI manifest")
            layers = manifest.get("layers")
            if (
                manifest.get("schemaVersion") != 2
                or manifest.get("mediaType") not in (None, _OCI_MANIFEST)
                or not isinstance(layers, list)
                or not layers
            ):
                _fail("OCI manifest is invalid")
            config_digest, config_size, _ = _descriptor(
                manifest.get("config"), expected_media_types=frozenset({_OCI_CONFIG})
            )
            config_member = _verify_blob(
                archive,
                members,
                config_digest,
                config_size,
            )
            config = _canonical_json(
                _read_member(
                    archive,
                    members,
                    _normalized_member(config_member.name),
                ),
                "OCI config",
            )
            _verify_config(config, source_revision)
            for value in layers:
                digest, size, _ = _descriptor(
                    value,
                    expected_media_types=_OCI_LAYERS,
                )
                layer_member = _verify_blob(archive, members, digest, size)
                _inspect_layer(archive, layer_member)
    except tarfile.TarError:
        _fail("OCI archive is not a supported tar file")
    return OciImage(
        manifest_digest=manifest_digest,
        config_digest=config_digest,
        source_tag=source_tag,
        archive_sha256=_archive_sha256(path),
        config=config,
    )


def _git_value(arguments: list[str]) -> str:
    try:
        result = subprocess.run(
            ["git", *arguments],
            cwd=_ROOT,
            check=True,
            capture_output=True,
            env={"PATH": os.environ.get("PATH", "/usr/bin:/bin")},
            text=True,
            timeout=15,
        )
    except (OSError, subprocess.SubprocessError):
        _fail("Git source identity could not be read")
    return result.stdout.strip()


def _source_identity(selected_revision: str | None) -> tuple[str, int]:
    revision = _git_value(["rev-parse", "HEAD"])
    if _SOURCE_REVISION.fullmatch(revision) is None or (
        selected_revision is not None and selected_revision != revision
    ):
        _fail("source revision does not match HEAD")
    if _git_value(["status", "--porcelain", "--untracked-files=all"]):
        _fail("container build requires a clean source tree")
    epoch = _git_value(["show", "-s", "--format=%ct", revision])
    if not epoch.isascii() or not epoch.isdecimal() or int(epoch) < 1:
        _fail("source revision timestamp is invalid")
    return revision, int(epoch)


def _image_source_tag(source_revision: str) -> str:
    if _SOURCE_REVISION.fullmatch(source_revision) is None:
        _fail("source revision is invalid")
    return (
        f"{_REGION}-docker.pkg.dev/{_PROJECT}/reconcile-p5/"
        f"reconcile:git-{source_revision}"
    )


def _validate_artifact_destination(destination: Path) -> Path:
    candidate = Path(destination)
    if not candidate.is_absolute():
        _fail("artifact destination must be an absolute canonical path")
    try:
        canonical = candidate.resolve(strict=False)
    except OSError:
        _fail("artifact destination could not be resolved")
    if canonical != candidate:
        _fail("artifact destination must be an absolute canonical path")
    try:
        parent = os.lstat(candidate.parent)
    except OSError:
        _fail("artifact destination parent is unavailable")
    if (
        not stat.S_ISDIR(parent.st_mode)
        or stat.S_ISLNK(parent.st_mode)
        or parent.st_uid != os.getuid()
        or stat.S_IMODE(parent.st_mode) != 0o700
    ):
        _fail("artifact destination parent is not private")
    try:
        os.lstat(candidate)
    except FileNotFoundError:
        return candidate
    except OSError:
        _fail("artifact destination could not be inspected")
    _fail("artifact destination already exists")


def _same_oci_image(observed: OciImage, expected: OciImage) -> bool:
    return (
        _IMAGE_DIGEST.fullmatch(observed.manifest_digest) is not None
        and _IMAGE_DIGEST.fullmatch(observed.config_digest) is not None
        and _ARCHIVE_SHA256.fullmatch(observed.archive_sha256) is not None
        and observed.manifest_digest == expected.manifest_digest
        and observed.config_digest == expected.config_digest
        and observed.source_tag == expected.source_tag
        and observed.archive_sha256 == expected.archive_sha256
    )


def _seal_verified_archive(
    source: Path,
    destination: Path,
    *,
    source_revision: str,
    expected: OciImage,
) -> OciImage:
    target = _validate_artifact_destination(destination)
    if expected.source_tag != _image_source_tag(source_revision):
        _fail("verified OCI source tag is not the operator source tag")

    parent_descriptor = -1
    source_descriptor = -1
    staging_descriptor = -1
    staging_name = f".reconcile-oci-{uuid4().hex}.tmp"
    staging_present = False
    published = False
    published_inode: tuple[int, int] | None = None
    succeeded = False
    try:
        parent_descriptor = os.open(
            target.parent,
            os.O_RDONLY | os.O_CLOEXEC | os.O_DIRECTORY | os.O_NOFOLLOW,
        )
        parent = os.fstat(parent_descriptor)
        if (
            not stat.S_ISDIR(parent.st_mode)
            or parent.st_uid != os.getuid()
            or stat.S_IMODE(parent.st_mode) != 0o700
        ):
            _fail("artifact destination parent is not private")
        try:
            os.stat(
                target.name,
                dir_fd=parent_descriptor,
                follow_symlinks=False,
            )
        except FileNotFoundError:
            pass
        else:
            _fail("artifact destination already exists")

        source_descriptor = os.open(
            source,
            os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW,
        )
        source_metadata = os.fstat(source_descriptor)
        if (
            not stat.S_ISREG(source_metadata.st_mode)
            or source_metadata.st_size < 1
            or source_metadata.st_size > _MAX_ARTIFACT_BYTES
        ):
            _fail("verified OCI archive has an invalid size or type")
        staging_descriptor = os.open(
            staging_name,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW,
            0o600,
            dir_fd=parent_descriptor,
        )
        staging_present = True
        copied = 0
        digest = hashlib.sha256()
        while chunk := os.read(source_descriptor, 1_048_576):
            copied += len(chunk)
            if copied > _MAX_ARTIFACT_BYTES:
                _fail("verified OCI archive exceeds the artifact limit")
            digest.update(chunk)
            view = memoryview(chunk)
            while view:
                written = os.write(staging_descriptor, view)
                if written < 1:
                    _fail("verified OCI archive could not be copied")
                view = view[written:]
        if (
            copied != source_metadata.st_size
            or digest.hexdigest() != expected.archive_sha256
        ):
            _fail("verified OCI archive changed before preservation")
        os.fsync(staging_descriptor)
        os.fchmod(staging_descriptor, 0o400)
        os.fsync(staging_descriptor)
        staged_metadata = os.fstat(staging_descriptor)
        if (
            not stat.S_ISREG(staged_metadata.st_mode)
            or staged_metadata.st_uid != os.getuid()
            or stat.S_IMODE(staged_metadata.st_mode) != 0o400
            or staged_metadata.st_nlink != 1
            or staged_metadata.st_size != copied
        ):
            _fail("staged OCI artifact is not sealed")
        published_inode = (staged_metadata.st_dev, staged_metadata.st_ino)
        os.close(staging_descriptor)
        staging_descriptor = -1
        os.close(source_descriptor)
        source_descriptor = -1

        staged_path = target.parent / staging_name
        staged_image = verify_oci_archive(
            staged_path,
            source_revision,
            expected_source_tag=expected.source_tag,
        )
        if not _same_oci_image(staged_image, expected):
            _fail("staged OCI artifact identity drifted")

        try:
            os.link(
                staging_name,
                target.name,
                src_dir_fd=parent_descriptor,
                dst_dir_fd=parent_descriptor,
                follow_symlinks=False,
            )
        except FileExistsError:
            _fail("artifact destination already exists")
        published = True
        os.unlink(staging_name, dir_fd=parent_descriptor)
        staging_present = False
        final_metadata = os.stat(
            target.name,
            dir_fd=parent_descriptor,
            follow_symlinks=False,
        )
        if (
            not stat.S_ISREG(final_metadata.st_mode)
            or final_metadata.st_uid != os.getuid()
            or stat.S_IMODE(final_metadata.st_mode) != 0o400
            or final_metadata.st_nlink != 1
            or (final_metadata.st_dev, final_metadata.st_ino) != published_inode
        ):
            _fail("published OCI artifact is not sealed")
        os.fsync(parent_descriptor)
        final_image = verify_oci_archive(
            target,
            source_revision,
            expected_source_tag=expected.source_tag,
        )
        if not _same_oci_image(final_image, expected):
            _fail("published OCI artifact identity drifted")
        succeeded = True
        return final_image
    except ContainerGateError:
        raise
    except OSError:
        _fail("OCI artifact could not be sealed")
    finally:
        if staging_descriptor >= 0:
            os.close(staging_descriptor)
        if source_descriptor >= 0:
            os.close(source_descriptor)
        if parent_descriptor >= 0:
            if staging_present:
                try:
                    os.unlink(staging_name, dir_fd=parent_descriptor)
                except OSError:
                    pass
            if published and not succeeded and published_inode is not None:
                try:
                    metadata = os.stat(
                        target.name,
                        dir_fd=parent_descriptor,
                        follow_symlinks=False,
                    )
                    if (metadata.st_dev, metadata.st_ino) == published_inode:
                        os.unlink(target.name, dir_fd=parent_descriptor)
                        os.fsync(parent_descriptor)
                except OSError:
                    pass
            os.close(parent_descriptor)


def _build_archive(
    docker: str,
    environment: dict[str, str],
    *,
    builder: str,
    destination: Path,
    metadata: Path,
    image_tag: str,
    source_revision: str,
    source_date_epoch: int,
    source_root: Path = _ROOT,
) -> None:
    _run(
        [
            docker,
            "buildx",
            "build",
            "--builder",
            builder,
            "--no-cache",
            "--platform",
            "linux/amd64",
            "--provenance=false",
            "--sbom=false",
            "--build-arg",
            f"SOURCE_REVISION={source_revision}",
            "--build-arg",
            f"SOURCE_DATE_EPOCH={source_date_epoch}",
            "--tag",
            image_tag,
            "--metadata-file",
            str(metadata),
            "--output",
            f"type=oci,rewrite-timestamp=true,dest={destination}",
            str(source_root),
        ],
        environment=environment,
    )


def _approved_audiences() -> dict[str, str]:
    return {
        component: f"https://reconcile.invalid/phase5/{_PROJECT}/{component}"
        for component in ("api", "controller", "fault-proxy", "sandbox")
    }


def component_environment(
    component: str,
    *,
    source_revision: str,
    image_digest: str,
) -> dict[str, str]:
    audiences = _approved_audiences()
    common = {
        "GOOGLE_CLOUD_PROJECT": _PROJECT,
        "PORT": "8080",
        "RECONCILE_AUTH_AUDIENCE": audiences[component],
        "RECONCILE_COMPONENT": component,
        "RECONCILE_IMAGE_DIGEST": image_digest,
        "RECONCILE_INFRA_REVISION": "1" * 64,
        "RECONCILE_SEMANTIC_CONFIG_SHA256": "2" * 64,
        "RECONCILE_SOURCE_REVISION": source_revision,
    }
    if component == "api":
        specific = {
            "RECONCILE_ALLOWED_CALLER_EMAILS": (
                f"rec-p5-apply@{_PROJECT}.iam.gserviceaccount.com"
            ),
            "RECONCILE_CONTROLLER_AUDIENCE": audiences["controller"],
            "RECONCILE_CONTROLLER_URL": "https://controller.example.test",
            "RECONCILE_FAULT_PROXY_AUDIENCE": audiences["fault-proxy"],
            "RECONCILE_FAULT_PROXY_URL": "https://fault-proxy.example.test",
            "RECONCILE_RUNTIME_DATABASE": "reconcile-p5-runtime",
            "RECONCILE_TARGET_BUCKET": f"{_PROJECT}-p5-target",
        }
    elif component == "controller":
        specific = {
            "RECONCILE_ALLOWED_CALLER_EMAILS": (
                f"rec-p5-api@{_PROJECT}.iam.gserviceaccount.com"
            ),
            "RECONCILE_RUNTIME_DATABASE": "reconcile-p5-runtime",
            "RECONCILE_SANDBOX_AUDIENCE": audiences["sandbox"],
            "RECONCILE_SANDBOX_URL": "https://sandbox.example.test",
            "RECONCILE_TARGET_BUCKET": f"{_PROJECT}-p5-target",
            "RECONCILE_TARGET_DATABASE": "reconcile-p5-target",
            "RECONCILE_VERTEX_LOCATION": "us",
            "RECONCILE_VERTEX_MAX_COUNT_TOKENS_ATTEMPTS": "1",
            "RECONCILE_VERTEX_MAX_GENERATION_ATTEMPTS": "1",
            "RECONCILE_VERTEX_MAX_INPUT_TOKENS": "12000",
            "RECONCILE_VERTEX_MAX_OUTPUT_TOKENS": "1024",
            "RECONCILE_VERTEX_MODEL": "gemini-3.5-flash",
            "RECONCILE_VERTEX_PROMPT_SHA256": _PROMPT_SHA256,
            "RECONCILE_VERTEX_PROMPT_VERSION": _PROMPT_VERSION,
            "RECONCILE_VERTEX_THINKING_LEVEL": "MINIMAL",
        }
    elif component == "fault-proxy":
        specific = {
            "RECONCILE_ALLOWED_CALLER_EMAILS": (
                f"rec-p5-api@{_PROJECT}.iam.gserviceaccount.com"
            ),
            "RECONCILE_RUNTIME_DATABASE": "reconcile-p5-runtime",
            "RECONCILE_SANDBOX_AUDIENCE": audiences["sandbox"],
            "RECONCILE_SANDBOX_URL": "https://sandbox.example.test",
            "RECONCILE_TARGET_BUCKET": f"{_PROJECT}-p5-target",
            "RECONCILE_TARGET_DATABASE": "reconcile-p5-target",
        }
    elif component == "sandbox":
        specific = {
            "RECONCILE_SANDBOX_MUTATION_CALLER_EMAIL": (
                f"rec-p5-fault@{_PROJECT}.iam.gserviceaccount.com"
            ),
            "RECONCILE_SANDBOX_READ_CALLER_EMAIL": (
                f"rec-p5-controller@{_PROJECT}.iam.gserviceaccount.com"
            ),
            "RECONCILE_RUNTIME_DATABASE": "reconcile-p5-runtime",
            "RECONCILE_TARGET_DATABASE": "reconcile-p5-sandbox",
        }
    else:
        _fail("container smoke component is unsupported")
    return {**common, **specific}


def _smoke_component(
    docker: str,
    environment: dict[str, str],
    *,
    image_tag: str,
    component: str,
    source_revision: str,
    image_digest: str,
) -> str:
    name = f"reconcile-phase5-{component.replace('-', '')}-{uuid4().hex[:12]}"
    component_env = component_environment(
        component,
        source_revision=source_revision,
        image_digest=image_digest,
    )
    command = [
        docker,
        "run",
        "--detach",
        "--name",
        name,
        "--network",
        "none",
        "--read-only",
        "--tmpfs",
        "/tmp:rw,noexec,nosuid,nodev,size=64m",
        "--cap-drop",
        "ALL",
        "--security-opt",
        "no-new-privileges",
        "--pids-limit",
        "128",
        "--memory",
        "768m",
        "--cpus",
        "1",
    ]
    for key, value in sorted(component_env.items()):
        command.extend(("--env", f"{key}={value}"))
    command.append(image_tag)
    try:
        _run(command, environment=environment, timeout=60)
        probe = (
            "import sys,urllib.request;"
            "response=urllib.request.urlopen("
            "'http://127.0.0.1:8080/health',timeout=2);"
            "payload=response.read();"
            'sys.exit(0 if response.status==200 and payload==b\'{"status":"ok"}\' else 1)'
        )
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline:
            result = _run(
                [docker, "exec", name, "/opt/reconcile/bin/python", "-c", probe],
                environment=environment,
                timeout=5,
                expected=frozenset(range(256)),
            )
            if result.returncode == 0:
                return name
            time.sleep(0.25)
        _fail("hosted component did not become healthy")
    except BaseException:
        _run(
            [docker, "rm", "--force", name],
            environment=environment,
            timeout=30,
            expected=frozenset(range(256)),
        )
        raise


def run_gate(
    selected_revision: str | None = None,
    *,
    require_daemon: bool = False,
    artifact_output: Path | None = None,
    docker_executable: Path | None = None,
    docker_host: str | None = None,
    source_root: Path | None = None,
    source_date_epoch: int | None = None,
) -> GateResult:
    build_root = _ROOT if source_root is None else source_root
    if source_root is not None:
        if (
            not source_root.is_absolute()
            or source_root.resolve(strict=False) != source_root
            or source_root.is_symlink()
            or not source_root.is_dir()
            or selected_revision is None
            or _SOURCE_REVISION.fullmatch(selected_revision) is None
            or type(source_date_epoch) is not int
            or source_date_epoch < 1
        ):
            _fail("explicit source identity is invalid")
    elif source_date_epoch is not None:
        _fail("source date epoch requires an explicit source root")
    if source_root is None:
        verify_static_contract()
    else:
        verify_static_contract(build_root)
    artifact_destination = (
        _validate_artifact_destination(artifact_output)
        if artifact_output is not None
        else None
    )
    if docker_executable is None:
        docker = shutil.which("docker")
        if docker is None:
            _fail("Docker CLI is required")
    else:
        if (
            not docker_executable.is_absolute()
            or docker_executable.resolve(strict=False) != docker_executable
            or docker_executable.is_symlink()
            or not docker_executable.is_file()
        ):
            _fail("explicit Docker CLI is invalid")
        docker = str(docker_executable)
    with tempfile.TemporaryDirectory(prefix="reconcile-container-gate-") as temporary:
        root = Path(temporary)
        docker_config = root / "docker-config"
        docker_config.mkdir(mode=0o700)
        environment = _minimal_environment(docker_config, docker_host=docker_host)
        capability = _docker_capability(
            docker,
            environment,
            require_daemon=require_daemon or artifact_destination is not None,
        )
        if capability is not None:
            return capability
        if source_root is None:
            source_revision, epoch = _source_identity(selected_revision)
        else:
            source_revision = selected_revision
            epoch = source_date_epoch
            if source_revision is None or epoch is None:  # validated above
                _fail("explicit source identity is invalid")
        image_tag = (
            _image_source_tag(source_revision)
            if artifact_destination is not None
            else f"reconcile-phase5-verification:{source_revision}"
        )
        existing = _run(
            [docker, "image", "inspect", image_tag],
            environment=environment,
            timeout=15,
            expected=frozenset(range(256)),
        )
        if existing.returncode == 0:
            _fail("deterministic local image tag is already in use")
        _bootstrap_buildx(docker, environment, docker_config)
        builder = _create_builder(docker, environment)
        archives = (root / "first.oci.tar", root / "second.oci.tar")
        images: list[OciImage] = []
        containers: list[str] = []
        loaded = False
        try:
            for index, archive in enumerate(archives, start=1):
                build_arguments: dict[str, Any] = {
                    "builder": builder,
                    "destination": archive,
                    "metadata": root / f"metadata-{index}.json",
                    "image_tag": image_tag,
                    "source_revision": source_revision,
                    "source_date_epoch": epoch,
                }
                if source_root is not None:
                    build_arguments["source_root"] = build_root
                _build_archive(docker, environment, **build_arguments)
                images.append(
                    verify_oci_archive(
                        archive,
                        source_revision,
                        expected_source_tag=(
                            image_tag if artifact_destination is not None else None
                        ),
                    )
                )
            if not _same_oci_image(images[0], images[1]):
                _fail("two clean builds produced different OCI artifacts")
            _run(
                [docker, "load", "--input", str(archives[0])],
                environment=environment,
                timeout=180,
            )
            loaded = True
            for component in ("api", "controller", "fault-proxy", "sandbox"):
                name = _smoke_component(
                    docker,
                    environment,
                    image_tag=image_tag,
                    component=component,
                    source_revision=source_revision,
                    image_digest=images[0].manifest_digest,
                )
                containers.append(name)
                _run(
                    [docker, "rm", "--force", name],
                    environment=environment,
                    timeout=30,
                )
                containers.remove(name)
        finally:
            for name in containers:
                _run(
                    [docker, "rm", "--force", name],
                    environment=environment,
                    timeout=30,
                    expected=frozenset(range(256)),
                )
            if loaded:
                _run(
                    [docker, "image", "rm", image_tag],
                    environment=environment,
                    timeout=60,
                )
            _remove_builder(docker, environment, builder)
        sealed_image = (
            _seal_verified_archive(
                archives[0],
                artifact_destination,
                source_revision=source_revision,
                expected=images[0],
            )
            if artifact_destination is not None
            else None
        )
        return GateResult(
            status="passed",
            reason="reproducible-offline-container-verified",
            image_digest=images[0].manifest_digest,
            archive_sha256=(
                sealed_image.archive_sha256 if sealed_image is not None else None
            ),
            config_digest=(
                sealed_image.config_digest if sealed_image is not None else None
            ),
            source_tag=sealed_image.source_tag if sealed_image is not None else None,
        )


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--source-revision")
    parser.add_argument("--static-only", action="store_true")
    parser.add_argument("--require-daemon", action="store_true")
    parser.add_argument("--artifact-output", type=Path)
    parser.add_argument("--docker-executable", type=Path)
    parser.add_argument("--docker-host")
    parser.add_argument("--source-root", type=Path)
    parser.add_argument("--source-date-epoch", type=int)
    return parser.parse_args()


def main() -> int:
    arguments = _parse_args()
    try:
        if arguments.static_only and arguments.artifact_output is not None:
            _fail("artifact output is incompatible with static-only mode")
        if arguments.static_only:
            verify_static_contract(arguments.source_root)
            result = GateResult(status="passed", reason="static-contract-verified")
        else:
            result = run_gate(
                arguments.source_revision,
                require_daemon=arguments.require_daemon,
                artifact_output=arguments.artifact_output,
                docker_executable=arguments.docker_executable,
                docker_host=arguments.docker_host,
                source_root=arguments.source_root,
                source_date_epoch=arguments.source_date_epoch,
            )
    except ContainerGateError as error:
        print(
            GateResult(status="failed", reason=str(error)).canonical_json(),
            flush=True,
        )
        return 1
    print(result.canonical_json(), flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
