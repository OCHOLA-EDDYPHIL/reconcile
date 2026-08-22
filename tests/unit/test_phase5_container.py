from __future__ import annotations

import hashlib
import io
import json
import os
import stat
import subprocess
import tarfile
from pathlib import Path
from typing import Any

import pytest

from reconcile.hosted.config import load_config
from scripts import check_phase5_container as container

pytestmark = pytest.mark.unit

_REVISION = "a" * 40
_SOURCE_TAG = container._image_source_tag(_REVISION)
_OCI_SOURCE_TAG = container._oci_source_tag(_REVISION)


def _canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def _layer(name: str = "opt/reconcile/application.py") -> bytes:
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode="w:gz") as archive:
        payload = b"safe"
        member = tarfile.TarInfo(name)
        member.size = len(payload)
        member.mtime = 1
        archive.addfile(member, io.BytesIO(payload))
    return output.getvalue()


def _descriptor(payload: bytes, media_type: str) -> dict[str, object]:
    return {
        "mediaType": media_type,
        "digest": f"sha256:{hashlib.sha256(payload).hexdigest()}",
        "size": len(payload),
    }


def _archive(
    path: Path,
    *,
    layer_name: str = "opt/reconcile/application.py",
    user: str = "65532:65532",
    environment: list[str] | None = None,
    source_tag: str = _OCI_SOURCE_TAG,
) -> str:
    config = _canonical(
        {
            "architecture": "amd64",
            "os": "linux",
            "config": {
                "Cmd": None,
                "Entrypoint": container._ENTRYPOINT,
                "Env": environment or ["HOME=/tmp"],
                "Labels": {"org.opencontainers.image.revision": _REVISION},
                "User": user,
                "WorkingDir": "/app",
            },
        }
    )
    layer = _layer(layer_name)
    manifest = _canonical(
        {
            "schemaVersion": 2,
            "mediaType": container._OCI_MANIFEST,
            "config": _descriptor(config, container._OCI_CONFIG),
            "layers": [
                _descriptor(
                    layer,
                    "application/vnd.oci.image.layer.v1.tar+gzip",
                )
            ],
        }
    )
    manifest_descriptor = _descriptor(manifest, container._OCI_MANIFEST)
    manifest_descriptor["annotations"] = {
        container._OCI_REFERENCE_ANNOTATION: source_tag
    }
    index = _canonical(
        {
            "schemaVersion": 2,
            "mediaType": container._OCI_INDEX,
            "manifests": [manifest_descriptor],
        }
    )
    files = {
        "oci-layout": _canonical({"imageLayoutVersion": "1.0.0"}),
        "index.json": index,
        f"blobs/sha256/{hashlib.sha256(config).hexdigest()}": config,
        f"blobs/sha256/{hashlib.sha256(layer).hexdigest()}": layer,
        f"blobs/sha256/{hashlib.sha256(manifest).hexdigest()}": manifest,
    }
    with tarfile.open(path, mode="w") as archive:
        for name, payload in files.items():
            member = tarfile.TarInfo(name)
            member.size = len(payload)
            member.mtime = 1
            archive.addfile(member, io.BytesIO(payload))
    return str(manifest_descriptor["digest"])


def test_static_container_contract_is_closed_and_nonroot() -> None:
    container.verify_static_contract()

    dockerfile = container._DOCKERFILE.read_text(encoding="utf-8")
    dockerignore = container._DOCKERIGNORE.read_text(encoding="utf-8")
    assert container._PYTHON_MANIFEST in dockerfile
    assert container._UV_MANIFEST in dockerfile
    assert "USER 65532:65532" in dockerfile
    assert tuple(dockerignore.splitlines()) == container._DOCKERIGNORE_LINES
    assert "artifacts" not in dockerignore


def test_exact_oci_archive_is_verified_without_extraction(tmp_path: Path) -> None:
    path = tmp_path / "image.oci.tar"
    expected = _archive(path)

    image = container.verify_oci_archive(
        path,
        _REVISION,
        expected_source_tag=_OCI_SOURCE_TAG,
    )

    assert image.manifest_digest == expected
    assert image.config_digest.startswith("sha256:")
    assert image.source_tag == _OCI_SOURCE_TAG
    assert image.archive_sha256 == hashlib.sha256(path.read_bytes()).hexdigest()
    assert image.config["config"]["User"] == "65532:65532"


@pytest.mark.parametrize(
    ("updates", "message"),
    (
        ({"user": "0:0"}, "nonroot contract"),
        (
            {"environment": ["GOOGLE_APPLICATION_CREDENTIALS=/private/key.json"]},
            "credential-bearing",
        ),
        ({"layer_name": "app/.env.production"}, "forbidden repository artifact"),
        (
            {"layer_name": "artifacts/final-holdout.json"},
            "forbidden repository artifact",
        ),
        ({"layer_name": "workspace/runtime.tfstate"}, "forbidden repository artifact"),
    ),
)
def test_oci_archive_rejects_root_credentials_and_repository_artifacts(
    tmp_path: Path,
    updates: dict[str, Any],
    message: str,
) -> None:
    path = tmp_path / "image.oci.tar"
    _archive(path, **updates)

    with pytest.raises(container.ContainerGateError, match=message):
        container.verify_oci_archive(path, _REVISION)


def test_oci_archive_rejects_a_tampered_blob(tmp_path: Path) -> None:
    path = tmp_path / "image.oci.tar"
    _archive(path)
    replacement = tmp_path / "tampered.oci.tar"
    with (
        tarfile.open(path, mode="r") as source,
        tarfile.open(replacement, mode="w") as target,
    ):
        changed = False
        for member in source.getmembers():
            extracted = source.extractfile(member)
            payload = b"" if extracted is None else extracted.read()
            if member.name.startswith("blobs/sha256/") and not changed:
                payload = payload + b"tampered"
                member.size = len(payload)
                changed = True
            target.addfile(member, io.BytesIO(payload) if member.isfile() else None)

    with pytest.raises(container.ContainerGateError, match=r"wrong size|digest"):
        container.verify_oci_archive(replacement, _REVISION)


def test_daemon_absence_is_the_only_default_skip(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    calls: list[list[str]] = []

    def unavailable(
        command: list[str], **_: object
    ) -> subprocess.CompletedProcess[str]:
        calls.append(command)
        return subprocess.CompletedProcess(command, 1, "", "unavailable")

    monkeypatch.setattr(container, "_run", unavailable)
    result = container._docker_capability(
        "/usr/bin/docker",
        container._minimal_environment(tmp_path),
    )

    assert result == container.GateResult(
        status="skipped",
        reason="docker-daemon-unavailable",
    )
    assert calls == [
        [
            "/usr/bin/docker",
            "version",
            "--format",
            ("{{.Client.Version}}|{{.Server.Version}}|{{.Server.Os}}|{{.Server.Arch}}"),
        ]
    ]


def test_required_daemon_fails_instead_of_skipping(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    monkeypatch.setattr(
        container,
        "_run",
        lambda *_args, **_kwargs: subprocess.CompletedProcess([], 1, "", "missing"),
    )

    with pytest.raises(container.ContainerGateError, match="Docker daemon is required"):
        container._docker_capability(
            "/usr/bin/docker",
            container._minimal_environment(tmp_path),
            require_daemon=True,
        )


def test_pinned_operator_docker_client_name_is_allowed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    observed: list[list[str]] = []

    def completed(command: list[str], **_: object) -> subprocess.CompletedProcess[str]:
        observed.append(command)
        return subprocess.CompletedProcess(command, 0, "", "")

    monkeypatch.setattr(container.subprocess, "run", completed)
    command = ["/usr/local/libexec/reconcile/docker-29.6.2", "version"]

    result = container._run(command, environment={})

    assert result.returncode == 0
    assert observed == [command]


def test_explicit_docker_host_does_not_inherit_ambient_endpoint(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    monkeypatch.setenv("DOCKER_HOST", "tcp://ambient.invalid:2375")
    selected = "unix:///var/lib/reconcile-phase5-operator/run/docker.sock"

    environment = container._minimal_environment(
        tmp_path,
        docker_host=selected,
    )

    assert environment["DOCKER_HOST"] == selected
    assert "DOCKER_TLS_VERIFY" not in environment
    assert "DOCKER_CERT_PATH" not in environment


def test_docker_version_drift_fails_instead_of_skipping(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    monkeypatch.setattr(
        container,
        "_run",
        lambda *_args, **_kwargs: subprocess.CompletedProcess(
            [], 0, "29.1.3|29.1.3|linux|amd64\n", ""
        ),
    )

    with pytest.raises(
        container.ContainerGateError,
        match=r"Docker client and Linux amd64 daemon 29[.]6[.]2",
    ):
        container._docker_capability(
            "/usr/bin/docker",
            container._minimal_environment(tmp_path),
        )


def test_buildx_bootstrap_uses_exact_amd64_image_and_binary(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    payload = b"exact-buildx"
    observed: list[list[str]] = []

    def emulate(command: list[str], **_: object) -> subprocess.CompletedProcess[str]:
        observed.append(command)
        if command[1] == "cp":
            Path(command[-1]).write_bytes(payload)
        stdout = (
            container._BUILDX_VERSION if command[1:3] == ["buildx", "version"] else ""
        )
        return subprocess.CompletedProcess(command, 0, stdout, "")

    monkeypatch.setattr(container, "_run", emulate)
    monkeypatch.setattr(container, "_BUILDX_BINARY_SIZE", len(payload))
    monkeypatch.setattr(
        container,
        "_BUILDX_BINARY_SHA256",
        hashlib.sha256(payload).hexdigest(),
    )

    container._bootstrap_buildx("/usr/bin/docker", {}, tmp_path)

    create = next(command for command in observed if command[1] == "create")
    assert container._BUILDX_IMAGE in create
    assert ["--platform", "linux/amd64"] == create[4:6]
    assert observed[-1][1:3] == ["buildx", "version"]


def test_isolated_builder_is_pinned_and_has_no_host_bind(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    observed: list[list[str]] = []

    def emulate(command: list[str], **_: object) -> subprocess.CompletedProcess[str]:
        observed.append(command)
        if command[1:3] == ["buildx", "inspect"]:
            stdout = (
                "Driver: docker-container\n"
                "Status: running\n"
                f"BuildKit version: {container._BUILDKIT_VERSION}\n"
                f'Driver Options: image="{container._BUILDKIT_IMAGE}"\n'
                "Platforms: linux/amd64\n"
            )
        elif command[1] == "inspect":
            mounts = json.dumps(
                [{"Type": "volume", "Destination": "/var/lib/buildkit"}]
            )
            stdout = f"{container._BUILDKIT_IMAGE}|{mounts}|bridge|true\n"
        else:
            stdout = ""
        return subprocess.CompletedProcess(command, 0, stdout, "")

    monkeypatch.setattr(container, "_run", emulate)

    builder = container._create_builder("/usr/bin/docker", {})

    assert builder.startswith("reconcile-phase5-")
    create = next(
        command for command in observed if command[1:3] == ["buildx", "create"]
    )
    assert ["--driver", "docker-container"] == create[5:7]
    assert f"image={container._BUILDKIT_IMAGE}" in create


def test_isolated_builder_rejects_a_host_socket_bind(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    observed: list[list[str]] = []

    def emulate(command: list[str], **_: object) -> subprocess.CompletedProcess[str]:
        observed.append(command)
        if command[1:3] == ["buildx", "inspect"]:
            stdout = (
                "Driver: docker-container\n"
                "Status: running\n"
                f"BuildKit version: {container._BUILDKIT_VERSION}\n"
                f'Driver Options: image="{container._BUILDKIT_IMAGE}"\n'
                "Platforms: linux/amd64\n"
            )
        elif command[1] == "inspect":
            mounts = json.dumps(
                [
                    {
                        "Type": "bind",
                        "Destination": "/var/run/docker.sock",
                    }
                ]
            )
            stdout = f"{container._BUILDKIT_IMAGE}|{mounts}|bridge|true\n"
        else:
            stdout = ""
        return subprocess.CompletedProcess(command, 0, stdout, "")

    monkeypatch.setattr(container, "_run", emulate)

    with pytest.raises(container.ContainerGateError, match="host resource"):
        container._create_builder("/usr/bin/docker", {})

    assert any(command[1:4] == ["buildx", "rm", "--force"] for command in observed)


def test_build_command_is_oci_only_and_never_pushes(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    observed: list[str] = []

    def record(command: list[str], **_: object) -> subprocess.CompletedProcess[str]:
        observed.extend(command)
        return subprocess.CompletedProcess(command, 0, "", "")

    monkeypatch.setattr(container, "_run", record)
    container._build_archive(
        "/usr/bin/docker",
        {},
        builder="reconcile-phase5-test",
        destination=tmp_path / "image.oci.tar",
        metadata=tmp_path / "metadata.json",
        image_tag="reconcile-phase5-verification:test",
        source_revision=_REVISION,
        source_date_epoch=1,
    )

    assert observed[:3] == ["/usr/bin/docker", "buildx", "build"]
    assert observed[3:5] == ["--builder", "reconcile-phase5-test"]
    assert "--provenance=false" in observed
    assert "--sbom=false" in observed
    assert any(
        item.startswith("type=oci,rewrite-timestamp=true,dest=") for item in observed
    )
    assert not {"--push", "push", "login"} & set(observed)


@pytest.mark.parametrize("component", ("api", "controller", "fault-proxy", "sandbox"))
def test_smoke_environment_loads_each_exact_component(component: str) -> None:
    environment = container.component_environment(
        component,
        source_revision=_REVISION,
        image_digest=f"sha256:{'b' * 64}",
    )

    config = load_config(environment)

    assert config.component.value == component
    assert "GOOGLE_APPLICATION_CREDENTIALS" not in environment
    assert "CLOUDSDK_CONFIG" not in environment
    if component == "fault-proxy":
        assert config.canary_location == "us-central1"
        assert config.canary_service == "reconcile-p5-canary"
        assert (
            config.canary_baseline_revision
            == (environment["RECONCILE_CANARY_BASELINE_REVISION"])
        )


def _mock_gate_runtime(
    monkeypatch: pytest.MonkeyPatch,
    *,
    fail_component: str | None = None,
) -> tuple[list[Path], list[str], list[bool]]:
    built: list[Path] = []
    smoke_tags: list[str] = []
    daemon_requirements: list[bool] = []

    monkeypatch.setattr(container, "verify_static_contract", lambda: None)
    monkeypatch.setattr(container.shutil, "which", lambda _: "/usr/bin/docker")

    def capability(
        _docker: str,
        _environment: dict[str, str],
        *,
        require_daemon: bool = False,
    ) -> container.GateResult | None:
        daemon_requirements.append(require_daemon)
        return None

    monkeypatch.setattr(container, "_docker_capability", capability)
    monkeypatch.setattr(container, "_source_identity", lambda _: (_REVISION, 1))
    monkeypatch.setattr(container, "_bootstrap_buildx", lambda *_args: None)
    monkeypatch.setattr(container, "_create_builder", lambda *_args: "builder")
    monkeypatch.setattr(container, "_remove_builder", lambda *_args: None)

    def build(
        _docker: str,
        _environment: dict[str, str],
        *,
        builder: str,
        destination: Path,
        metadata: Path,
        image_tag: str,
        source_revision: str,
        source_date_epoch: int,
    ) -> None:
        del builder, metadata, source_date_epoch
        assert source_revision == _REVISION
        built.append(destination)
        _archive(destination, source_tag=image_tag.rsplit(":", 1)[-1])

    monkeypatch.setattr(container, "_build_archive", build)

    def run(command: list[str], **_: object) -> subprocess.CompletedProcess[str]:
        return subprocess.CompletedProcess(
            command,
            1 if command[1:3] == ["image", "inspect"] else 0,
            "",
            "",
        )

    monkeypatch.setattr(container, "_run", run)

    def smoke(
        _docker: str,
        _environment: dict[str, str],
        *,
        image_tag: str,
        component: str,
        source_revision: str,
        image_digest: str,
    ) -> str:
        assert source_revision == _REVISION
        assert image_digest.startswith("sha256:")
        smoke_tags.append(image_tag)
        if component == fail_component:
            raise container.ContainerGateError("simulated smoke failure")
        return f"smoke-{component}"

    monkeypatch.setattr(container, "_smoke_component", smoke)
    return built, smoke_tags, daemon_requirements


def test_artifact_mode_seals_the_exact_smoked_archive_and_reports_identity(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    parent = tmp_path / "private"
    parent.mkdir(mode=0o700)
    parent.chmod(0o700)
    destination = parent / "reconcile.oci.tar"
    built, smoke_tags, daemon_requirements = _mock_gate_runtime(monkeypatch)

    result = container.run_gate(artifact_output=destination)

    assert result.status == "passed"
    assert result.image_digest is not None
    assert result.config_digest is not None
    assert result.source_tag == _SOURCE_TAG
    assert result.archive_sha256 == hashlib.sha256(destination.read_bytes()).hexdigest()
    assert smoke_tags == [_SOURCE_TAG] * 4
    assert daemon_requirements == [True]
    assert stat.S_IMODE(destination.stat().st_mode) == 0o400
    assert destination.stat().st_nlink == 1
    assert destination.stat().st_uid == os.getuid()
    assert built and all(not path.exists() for path in built)
    rendered = result.canonical_json()
    assert str(destination) not in rendered
    assert json.loads(rendered)["archive_sha256"] == result.archive_sha256


def test_default_gate_remains_ephemeral(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    built, smoke_tags, daemon_requirements = _mock_gate_runtime(monkeypatch)

    result = container.run_gate()

    assert result.status == "passed"
    assert result.archive_sha256 is None
    assert result.config_digest is None
    assert result.source_tag is None
    assert smoke_tags == [f"reconcile-phase5-verification:{_REVISION}"] * 4
    assert daemon_requirements == [False]
    assert built and all(not path.exists() for path in built)


def test_build_archive_uses_only_the_explicit_snapshot_context(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    observed: list[list[str]] = []

    def run(command, *, environment, **_values):
        assert environment == {"CLEAN": "1"}
        observed.append(command)
        return subprocess.CompletedProcess(command, 0, "", "")

    monkeypatch.setattr(container, "_run", run)
    source = tmp_path / "private-source"
    container._build_archive(
        "/usr/bin/docker",
        {"CLEAN": "1"},
        builder="builder",
        destination=tmp_path / "image.tar",
        metadata=tmp_path / "metadata.json",
        image_tag="reconcile:test",
        source_revision="a" * 40,
        source_date_epoch=1,
        source_root=source,
    )

    assert observed[0][-1] == str(source)
    assert str(container._ROOT) not in observed[0]


def test_artifact_is_not_preserved_before_every_smoke_passes(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    parent = tmp_path / "private"
    parent.mkdir(mode=0o700)
    parent.chmod(0o700)
    destination = parent / "reconcile.oci.tar"
    _, smoke_tags, _ = _mock_gate_runtime(
        monkeypatch,
        fail_component="sandbox",
    )

    with pytest.raises(container.ContainerGateError, match="simulated smoke failure"):
        container.run_gate(artifact_output=destination)

    assert smoke_tags == [_SOURCE_TAG] * 4
    assert not destination.exists()
    assert list(parent.iterdir()) == []


@pytest.mark.parametrize(
    "candidate_kind",
    ("relative", "noncanonical", "missing-parent", "public-parent"),
)
def test_artifact_destination_requires_an_exact_private_parent(
    tmp_path: Path,
    candidate_kind: str,
) -> None:
    private = tmp_path / "private"
    private.mkdir(mode=0o700)
    private.chmod(0o700)
    if candidate_kind == "relative":
        candidate = Path("reconcile.oci.tar")
    elif candidate_kind == "noncanonical":
        candidate = private / ".." / "private" / "reconcile.oci.tar"
    elif candidate_kind == "missing-parent":
        candidate = tmp_path / "missing" / "reconcile.oci.tar"
    else:
        private.chmod(0o755)
        candidate = private / "reconcile.oci.tar"

    with pytest.raises(container.ContainerGateError):
        container._validate_artifact_destination(candidate)


def test_artifact_destination_parent_must_belong_to_the_operator_user(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    parent = tmp_path / "private"
    parent.mkdir(mode=0o700)
    parent.chmod(0o700)
    real_uid = os.getuid()
    monkeypatch.setattr(container.os, "getuid", lambda: real_uid + 1)

    with pytest.raises(container.ContainerGateError, match="not private"):
        container._validate_artifact_destination(parent / "reconcile.oci.tar")


@pytest.mark.parametrize("existing_kind", ("file", "symlink"))
def test_artifact_destination_refuses_existing_or_symlink_paths(
    tmp_path: Path,
    existing_kind: str,
) -> None:
    parent = tmp_path / "private"
    parent.mkdir(mode=0o700)
    parent.chmod(0o700)
    destination = parent / "reconcile.oci.tar"
    if existing_kind == "file":
        destination.write_bytes(b"do not overwrite")
    else:
        destination.symlink_to(parent / "absent")

    with pytest.raises(container.ContainerGateError):
        container._validate_artifact_destination(destination)


def test_source_tamper_is_rejected_without_publishing(
    tmp_path: Path,
) -> None:
    source = tmp_path / "source.oci.tar"
    _archive(source)
    expected = container.verify_oci_archive(
        source,
        _REVISION,
        expected_source_tag=_OCI_SOURCE_TAG,
    )
    source.write_bytes(source.read_bytes() + b"tamper")
    parent = tmp_path / "private"
    parent.mkdir(mode=0o700)
    parent.chmod(0o700)
    destination = parent / "reconcile.oci.tar"

    with pytest.raises(container.ContainerGateError, match="changed before"):
        container._seal_verified_archive(
            source,
            destination,
            source_revision=_REVISION,
            expected=expected,
        )

    assert not destination.exists()
    assert list(parent.iterdir()) == []


def test_post_staging_tamper_is_caught_by_final_reverification(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    source = tmp_path / "source.oci.tar"
    _archive(source)
    expected = container.verify_oci_archive(
        source,
        _REVISION,
        expected_source_tag=_OCI_SOURCE_TAG,
    )
    parent = tmp_path / "private"
    parent.mkdir(mode=0o700)
    parent.chmod(0o700)
    destination = parent / "reconcile.oci.tar"
    verify = container.verify_oci_archive

    def tampering_verify(
        path: Path, *args: object, **kwargs: object
    ) -> container.OciImage:
        observed = verify(path, *args, **kwargs)  # type: ignore[arg-type]
        if path.name.startswith(".reconcile-oci-"):
            path.chmod(0o600)
            path.write_bytes(path.read_bytes() + b"tamper-after-staging-check")
            path.chmod(0o400)
        return observed

    monkeypatch.setattr(container, "verify_oci_archive", tampering_verify)

    with pytest.raises(container.ContainerGateError, match="identity drifted"):
        container._seal_verified_archive(
            source,
            destination,
            source_revision=_REVISION,
            expected=expected,
        )

    assert not destination.exists()
    assert list(parent.iterdir()) == []
