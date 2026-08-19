from __future__ import annotations

import base64
import gzip
import hashlib
import io
import json
import os
import shutil
import stat
import subprocess
import tarfile
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest

from reconcile import phase5_operator as operator

pytestmark = pytest.mark.unit

_NOW = datetime(2026, 8, 18, 6, 0, tzinfo=UTC)
_SOURCE = "a" * 40
_REPO_ROOT = Path(__file__).parents[2].resolve()


def _draft(image_digest: str = f"sha256:{'c' * 64}") -> operator.Phase5ManifestDraft:
    return operator.Phase5ManifestDraft(
        schema_version="reconcile/phase5-operator-draft/v1",
        source_revision=_SOURCE,
        image_digest=image_digest,
        created_at=_NOW,
        work_deadline=_NOW + timedelta(hours=8),
        approval_expires_at=_NOW + timedelta(hours=10),
    )


def _project_dependency_payloads(repo_root: Path) -> tuple[bytes, bytes]:
    payload = (repo_root / "reconcile" / "phase5_operator.py").read_bytes()
    encoded_digest = base64.urlsafe_b64encode(hashlib.sha256(payload).digest()).rstrip(
        b"="
    )
    record = (
        b"reconcile/phase5_operator.py,sha256="
        + encoded_digest
        + f",{len(payload)}\n".encode()
    )
    return payload, record


def _write_oci_archive(
    path: Path,
    *,
    layer_entries: tuple[tuple[str, str, bytes | str | None], ...] | None = None,
    project_root: Path | None = None,
    include_layer: bool = True,
    gzip_layer: bool = False,
    truncate_gzip: bool = False,
    invalid_deflate: bool = False,
    layer_repeat: int = 1,
) -> str:
    config = b'{"architecture":"amd64","os":"linux"}'
    config_hexadecimal = hashlib.sha256(config).hexdigest()
    default_entries: tuple[tuple[str, str, bytes | str | None], ...] = (
        *(
            (name, "directory", None)
            for name in (
                "opt",
                "opt/reconcile",
                "opt/reconcile/lib",
                "opt/reconcile/lib/python3.12",
                "opt/reconcile/lib/python3.12/site-packages",
                *(
                    "opt/reconcile/lib/python3.12/site-packages/" + package
                    for package in ("grpc", "pydantic_core", "textual")
                ),
            )
        ),
        *(
            (
                f"opt/reconcile/lib/python3.12/site-packages/{package}/__init__.py",
                "file",
                f'PACKAGE = "{package}"\n'.encode(),
            )
            for package in ("grpc", "pydantic_core", "textual")
        ),
    )
    if project_root is not None:
        operator_payload, record_payload = _project_dependency_payloads(project_root)
        site_packages = "opt/reconcile/lib/python3.12/site-packages"
        default_entries = (
            *default_entries,
            (f"{site_packages}/reconcile", "directory", None),
            (f"{site_packages}/reconcile-0.1.0.dist-info", "directory", None),
            (
                f"{site_packages}/reconcile/phase5_operator.py",
                "file",
                operator_payload,
            ),
            (
                f"{site_packages}/reconcile-0.1.0.dist-info/RECORD",
                "file",
                record_payload,
            ),
        )
    selected_entries = default_entries if layer_entries is None else layer_entries
    layer_buffer = io.BytesIO()
    with tarfile.open(fileobj=layer_buffer, mode="w") as layer:
        for name, kind, payload in selected_entries:
            member = tarfile.TarInfo(name)
            member.mode = 0o755 if kind == "directory" else 0o644
            if kind == "directory":
                member.type = tarfile.DIRTYPE
                layer.addfile(member)
            elif kind == "file" and isinstance(payload, bytes):
                member.size = len(payload)
                layer.addfile(member, io.BytesIO(payload))
            elif kind in {"symlink", "hardlink"} and isinstance(payload, str):
                member.type = tarfile.SYMTYPE if kind == "symlink" else tarfile.LNKTYPE
                member.linkname = payload
                layer.addfile(member)
            elif kind == "fifo" and payload is None:
                member.type = tarfile.FIFOTYPE
                layer.addfile(member)
            elif kind in {"character", "block"} and payload is None:
                member.type = (
                    tarfile.CHRTYPE if kind == "character" else tarfile.BLKTYPE
                )
                member.devmajor = 1
                member.devminor = 1
                layer.addfile(member)
            elif kind == "sparse" and isinstance(payload, bytes):
                member.type = tarfile.GNUTYPE_SPARSE
                member.size = len(payload)
                member.sparse = [(0, len(payload))]
                layer.addfile(member, io.BytesIO(payload))
            else:
                raise AssertionError((name, kind, payload))
    uncompressed_layer = layer_buffer.getvalue()
    layer_payload = (
        gzip.compress(uncompressed_layer, mtime=0) if gzip_layer else uncompressed_layer
    )
    if truncate_gzip:
        assert gzip_layer
        layer_payload = layer_payload[:-8]
    if invalid_deflate:
        assert gzip_layer
        layer_payload = layer_payload[:10] + b"\x07" + layer_payload[11:]
    layer_hexadecimal = hashlib.sha256(layer_payload).hexdigest()
    layer_descriptor = {
        "digest": f"sha256:{layer_hexadecimal}",
        "mediaType": (
            "application/vnd.oci.image.layer.v1.tar+gzip"
            if gzip_layer
            else "application/vnd.oci.image.layer.v1.tar"
        ),
        "size": len(layer_payload),
    }
    layers = [layer_descriptor] * layer_repeat if include_layer else []
    manifest = json.dumps(
        {
            "config": {
                "digest": f"sha256:{config_hexadecimal}",
                "mediaType": "application/vnd.oci.image.config.v1+json",
                "size": len(config),
            },
            "layers": layers,
            "schemaVersion": 2,
        },
        separators=(",", ":"),
        sort_keys=True,
    ).encode()
    hexadecimal = hashlib.sha256(manifest).hexdigest()
    digest = f"sha256:{hexadecimal}"
    index = json.dumps(
        {
            "manifests": [
                {
                    "annotations": {
                        "org.opencontainers.image.ref.name": (f"git-{_SOURCE}")
                    },
                    "digest": digest,
                    "mediaType": "application/vnd.oci.image.manifest.v1+json",
                    "size": len(manifest),
                }
            ],
            "schemaVersion": 2,
        },
        separators=(",", ":"),
        sort_keys=True,
    ).encode()
    with tarfile.open(path, "w") as bundle:
        archive_entries = [
            ("index.json", index),
            (f"blobs/sha256/{hexadecimal}", manifest),
            (f"blobs/sha256/{config_hexadecimal}", config),
        ]
        if include_layer:
            archive_entries.append((f"blobs/sha256/{layer_hexadecimal}", layer_payload))
        for name, payload in archive_entries:
            member = tarfile.TarInfo(name)
            member.mode = 0o400
            member.size = len(payload)
            bundle.addfile(member, io.BytesIO(payload))
    path.chmod(0o400)
    return digest


def _runtime_values(repo_root: Path, image_digest: str) -> set[str]:
    semantic = operator._capture_semantic_sources(repo_root)
    stacks = operator._capture_terraform_stacks(repo_root)
    infrastructure = operator._hash_value(
        [item.model_dump(mode="json") for item in stacks]
    )
    prompt_version, prompt_sha = operator._planner_prompt_identity(repo_root)
    immutable_reference = (
        "us-central1-docker.pkg.dev/reconcile-dev-260813-14fa6d/"
        f"reconcile-p5/reconcile@{image_digest}"
    )
    return {
        _SOURCE,
        image_digest,
        immutable_reference,
        infrastructure,
        semantic.sha256,
        prompt_version,
        prompt_sha,
    }


def _plan_json(filename: str, runtime_values: set[str]) -> bytes:
    action = (
        "delete"
        if "destroy" in filename or filename == "bootstrap-disable-protection"
        else "create"
    )
    iam_value = {
        "member": (
            "serviceAccount:fixture@reconcile-dev-260813-14fa6d.iam.gserviceaccount.com"
        ),
        "name": None,
        "project": "reconcile-dev-260813-14fa6d",
        "role": "roles/viewer",
    }
    bucket_value = {
        "id": None,
        "name": f"fixture-{filename}",
        "project": "reconcile-dev-260813-14fa6d",
    }

    def change(value: dict[str, object], unknown: dict[str, bool]) -> dict[str, object]:
        if action == "delete":
            return {
                "actions": [action],
                "after": None,
                "before": value,
                "reconcile_before_unknown": unknown,
            }
        return {
            "actions": [action],
            "after": value,
            "after_unknown": unknown,
            "before": None,
        }

    return json.dumps(
        {
            "resource_changes": [
                {
                    "address": f'google_project_iam_member.fixture["{filename}"]',
                    "change": change(iam_value, {"name": True}),
                    "provider_name": "registry.terraform.io/hashicorp/google",
                    "type": "google_project_iam_member",
                },
                {
                    "address": f'google_storage_bucket.fixture["{filename}"]',
                    "change": change(bucket_value, {"id": True}),
                    "provider_name": "registry.terraform.io/hashicorp/google",
                    "type": "google_storage_bucket",
                },
            ],
            "terraform_version": "1.15.8",
            "variables": {
                f"identity_{index}": {"value": value}
                for index, value in enumerate(sorted(runtime_values))
            },
        },
        separators=(",", ":"),
        sort_keys=True,
    ).encode()


def _live_teardown_plan(qualification: dict[str, Any]) -> dict[str, Any]:
    rendered = json.loads(json.dumps(qualification))
    for resource in rendered["resource_changes"]:
        change = resource["change"]
        unknown = change.pop("reconcile_before_unknown", None)
        change.pop("reconcile_before_sensitive", None)
        before = change.get("before")
        if isinstance(before, dict) and isinstance(unknown, dict):
            for key, mask in unknown.items():
                if mask is True:
                    before[key] = f"provider-computed-{key}"
    return rendered


def _write_dependency_tree(root: Path) -> None:
    root.mkdir(mode=0o700)
    for package in ("grpc", "pydantic_core", "textual"):
        directory = root / package
        directory.mkdir(mode=0o700)
        module = directory / "__init__.py"
        module.write_text(f'PACKAGE = "{package}"\n', encoding="utf-8")
        module.chmod(0o400)
        directory.chmod(0o500)
    root.chmod(0o500)


def _write_project_dependency_files(root: Path, repo_root: Path) -> None:
    payload, record_payload = _project_dependency_payloads(repo_root)
    root.chmod(0o700)
    package = root / "reconcile"
    metadata = root / "reconcile-0.1.0.dist-info"
    package.mkdir(mode=0o700)
    metadata.mkdir(mode=0o700)
    operator_file = package / "phase5_operator.py"
    operator_file.write_bytes(payload)
    operator_file.chmod(0o400)
    record = metadata / "RECORD"
    record.write_bytes(record_payload)
    record.chmod(0o400)
    package.chmod(0o500)
    metadata.chmod(0o500)
    root.chmod(0o500)


def _dependency_artifact(
    tmp_path: Path,
    *,
    layer_entries: tuple[tuple[str, str, bytes | str | None], ...] | None = None,
    include_layer: bool = True,
    gzip_layer: bool = False,
    truncate_gzip: bool = False,
    invalid_deflate: bool = False,
    layer_repeat: int = 1,
) -> tuple[operator.Phase5StateStore, operator.ImageArtifactBinding]:
    state = operator.Phase5StateStore(tmp_path / "state")
    archive = state.root / "images" / "reconcile.oci.tar"
    digest = _write_oci_archive(
        archive,
        layer_entries=layer_entries,
        include_layer=include_layer,
        gzip_layer=gzip_layer,
        truncate_gzip=truncate_gzip,
        invalid_deflate=invalid_deflate,
        layer_repeat=layer_repeat,
    )
    artifact = operator._capture_image_artifact(
        state_root=state.root,
        source_revision=_SOURCE,
        expected_digest=digest,
    )
    return state, artifact


def _prepare_artifacts(
    state: operator.Phase5StateStore,
    *,
    repo_root: Path,
) -> operator.Phase5ManifestDraft:
    plans = state.root / "plans"
    images = state.root / "images"
    terraform_config = state.root / "terraform.rc"
    terraform_config.write_bytes(b"")
    terraform_config.chmod(0o400)
    dependency_root = state.root / "python-dependencies"
    _write_dependency_tree(dependency_root)
    _write_project_dependency_files(dependency_root, repo_root)
    image_digest = _write_oci_archive(
        images / "reconcile.oci.tar",
        project_root=repo_root,
    )
    runtime_values = _runtime_values(repo_root, image_digest)
    for _, stem in operator._PLAN_FILES.values():
        qualification = plans / f"{stem}.tfplan.json"
        qualification.write_bytes(
            _plan_json(
                stem,
                runtime_values if stem.startswith("runtime-") else set(),
            )
        )
        qualification.chmod(0o400)
        plan_value = json.loads(qualification.read_bytes())
        variables = {
            name: item["value"] for name, item in plan_value["variables"].items()
        }
        variable_path = plans / f"{stem}.tfvars.json"
        variable_path.write_bytes(
            json.dumps(variables, separators=(",", ":"), sort_keys=True).encode()
        )
        variable_path.chmod(0o400)
    return _draft(image_digest)


def _execution_input_paths(repo_root: Path) -> tuple[Path, ...]:
    paths = [repo_root / name for name in operator._EXECUTION_ROOT_FILES]
    paths.extend(repo_root / name for name in operator._EXECUTION_SCRIPTS)
    for tree in (repo_root / "reconcile", repo_root / "infra"):
        paths.extend(
            path
            for path in tree.rglob("*")
            if path.is_file()
            and not path.is_symlink()
            and "__pycache__" not in path.parts
            and ".terraform" not in path.parts
            and path.suffix not in {".pyc", ".pyo"}
        )
    return tuple(sorted(set(paths)))


def _install_execution_source(
    state: operator.Phase5StateStore,
    repo_root: Path,
) -> Path:
    source = state.root / "source"
    source.mkdir(mode=0o700)
    for path in _execution_input_paths(repo_root):
        relative = path.relative_to(repo_root)
        destination = source / relative
        destination.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        shutil.copy2(path, destination)
        executable = bool(path.stat().st_mode & stat.S_IXUSR)
        destination.chmod(0o500 if executable else 0o400)
    directories = sorted(
        (path for path in source.rglob("*") if path.is_dir()),
        key=lambda path: len(path.parts),
        reverse=True,
    )
    for directory in directories:
        directory.chmod(0o500)
    source.chmod(0o500)
    return source


def _snapshot_tree(source_root: Path) -> tuple[tuple[str, str, str], ...]:
    entries: list[tuple[str, str, str]] = []
    for path in sorted(item for item in source_root.rglob("*") if item.is_file()):
        payload = path.read_bytes()
        mode = "100755" if path.stat().st_mode & stat.S_IXUSR else "100644"
        entries.append(
            (
                path.relative_to(source_root).as_posix(),
                mode,
                operator._git_blob_object_id(payload),
            )
        )
    return tuple(entries)


def _test_execution_binding(source_root: Path) -> operator.ExecutionSourceBinding:
    files = tuple(
        operator.ExecutionSourceFileBinding(
            path=path,
            git_mode=mode,
            git_object_id=object_id,
            byte_count=len((source_root / path).read_bytes()),
            sha256=hashlib.sha256((source_root / path).read_bytes()).hexdigest(),
        )
        for path, mode, object_id in _snapshot_tree(source_root)
    )
    aggregate = {
        "source_revision": _SOURCE,
        "source_date_epoch": 1_787_032_800,
        "files": [item.model_dump(mode="json") for item in files],
    }
    return operator.ExecutionSourceBinding(
        root=str(source_root),
        source_revision=_SOURCE,
        source_date_epoch=1_787_032_800,
        files=files,
        sha256=operator._hash_value(aggregate),
    )


def _rewrite_snapshot_file(source_root: Path, relative: str, payload: bytes) -> None:
    path = source_root / relative
    parents: list[Path] = []
    parent = path.parent
    while parent != source_root.parent:
        parents.append(parent)
        parent = parent.parent
    for directory in reversed(parents):
        directory.chmod(0o700)
    path.chmod(0o600)
    path.write_bytes(payload)
    path.chmod(0o400)
    for directory in parents:
        directory.chmod(0o500)


def _records(
    tmp_path: Path,
    *,
    repo_root: Path = _REPO_ROOT,
) -> tuple[
    operator.Phase5StateStore,
    operator.Phase5ApprovalManifest,
    operator.Phase5Approval,
    _Runner,
]:
    state = operator.Phase5StateStore(tmp_path / "state")
    source_root = _install_execution_source(state, repo_root)
    draft = _prepare_artifacts(state, repo_root=source_root)
    runner = _Runner(source_root=source_root)
    manifest = operator.build_manifest(
        draft,
        state_root=state.root,
        repo_root=repo_root,
        runner=runner,
    )
    state.write_manifest(manifest)
    approval = operator.build_approval(
        manifest,
        approved_by="user:eddyphilochola13@gmail.com",
        approved_at=_NOW + timedelta(minutes=1),
    )
    state.write_approval(approval)
    runner.calls.clear()
    runner.cwds.clear()
    runner.environments.clear()
    return state, manifest, approval, runner


def _legacy_image_id_manifest(
    manifest: operator.Phase5ApprovalManifest,
) -> operator.Phase5ApprovalManifest:
    values = {
        name: getattr(manifest, name)
        for name in type(manifest).model_fields
        if name != "record_sha256"
    }
    values["commands"] = operator._fixed_commands(
        manifest.source_revision,
        manifest.image_digest,
        manifest.infrastructure_revision,
        manifest.semantic_config_sha256,
        state_root=Path(manifest.operator_state_root),
        image_archive=Path(manifest.image_artifact.archive_path),
        image_identity_format="--format={{.Id}}",
    )
    return operator._seal(operator.Phase5ApprovalManifest, **values)


class _Runner:
    def __init__(
        self,
        *,
        action_result: object | None = None,
        wrong_branch: bool = False,
        wrong_remote: bool = False,
        action_error: Exception | None = None,
        rendered_plan_drift: bool = False,
        tamper_execution_on_show: bool = False,
        image_id: str | None = None,
        remote_digest: str | None = None,
        source_root: Path | None = None,
    ) -> None:
        self.action_result = action_result or subprocess.CompletedProcess(
            ["fixed"], 0, b"ok", b""
        )
        self.wrong_branch = wrong_branch
        self.wrong_remote = wrong_remote
        self.action_error = action_error
        self.rendered_plan_drift = rendered_plan_drift
        self.tamper_execution_on_show = tamper_execution_on_show
        self.image_id = image_id
        self.remote_digest = remote_digest
        self.source_root = source_root
        self.source_tree = _snapshot_tree(source_root) if source_root else None
        self.calls: list[tuple[str, ...]] = []
        self.cwds: list[Path] = []
        self.environments: list[dict[str, str]] = []

    def __call__(
        self,
        argv: tuple[str, ...],
        *,
        cwd: Path,
        environment: dict[str, str] | Any,
        timeout_seconds: int,
    ) -> object:
        del timeout_seconds
        self.calls.append(argv)
        self.cwds.append(cwd)
        self.environments.append(dict(environment))
        if argv[0] == "/usr/bin/git":
            if argv[1:] == ("--version",):
                output = b"git version 2.43.0\n"
            elif argv[1:] == ("branch", "--show-current"):
                output = b"topic\n" if self.wrong_branch else b"main\n"
            elif argv[1:] == ("rev-parse", "--show-object-format"):
                output = b"sha1\n"
            elif argv[1:3] == ("rev-parse", "--verify"):
                output = f"{_SOURCE}\n".encode()
            elif argv[1:4] == ("show", "-s", "--format=%ct"):
                output = b"1787032800\n"
            elif argv[1:5] == ("ls-tree", "-r", "-z", "--full-tree"):
                assert self.source_tree is not None
                output = b"".join(
                    f"{mode} blob {object_id}\t{path}\0".encode()
                    for path, mode, object_id in self.source_tree
                )
            elif argv[1:3] == ("cat-file", "blob"):
                assert self.source_root is not None
                object_id = argv[3]
                path = next(
                    path
                    for path, _, candidate in self.source_tree or ()
                    if candidate == object_id
                )
                output = (self.source_root / path).read_bytes()
            elif argv[1] == "status":
                output = b""
            elif argv[1:] == ("remote", "get-url", "origin"):
                output = b"git@github.com:OCHOLA-EDDYPHIL/reconcile.git\n"
            elif argv[1:3] == ("ls-remote", "--exit-code"):
                revision = "f" * 40 if self.wrong_remote else _SOURCE
                output = f"{revision}\trefs/heads/main\n".encode()
            else:  # pragma: no cover - the closed git inventory is asserted below
                raise AssertionError(argv)
            return subprocess.CompletedProcess(list(argv), 0, output, b"")
        if argv == (operator._TERRAFORM, "version", "-json"):
            return subprocess.CompletedProcess(
                list(argv), 0, b'{"terraform_version":"1.15.8"}', b""
            )
        if (
            argv[0] == operator._TERRAFORM
            and argv[1].startswith("-chdir=")
            and argv[2:4] == ("show", "-json")
        ):
            execution = Path(argv[4])
            qualification = (
                execution.parent.parent / "plans" / f"{execution.stem}.tfplan.json"
            )
            payload = json.loads(qualification.read_bytes())
            if self.rendered_plan_drift:
                payload["resource_changes"][0]["change"]["actions"] = ["update"]
            output = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode()
            if self.tamper_execution_on_show:
                execution.chmod(0o600)
                execution.write_bytes(execution.read_bytes() + b"tampered")
                execution.chmod(0o400)
            return subprocess.CompletedProcess(list(argv), 0, output, b"")
        if argv[:3] == (operator._DOCKER, "version", "--format"):
            return subprocess.CompletedProcess(
                list(argv), 0, b"29.6.2|29.6.2|linux|amd64\n", b""
            )
        if argv[:4] == (
            operator._DOCKER,
            "image",
            "inspect",
            "--format={{.Descriptor.digest}}",
        ):
            output = f"{self.image_id}\n".encode() if self.image_id else b"ok"
            return subprocess.CompletedProcess(list(argv), 0, output, b"")
        if argv[:3] == ("/usr/bin/gcloud", "auth", "configure-docker"):
            config = Path(environment["DOCKER_CONFIG"]) / "config.json"
            config.write_text(
                json.dumps({"credHelpers": {"us-central1-docker.pkg.dev": "gcloud"}}),
                encoding="utf-8",
            )
            config.chmod(0o600)
            return subprocess.CompletedProcess(list(argv), 0, b"configured\n", b"")
        if argv == ("/usr/bin/gcloud", "version", "--format=json"):
            return subprocess.CompletedProcess(
                list(argv), 0, b'{"Google Cloud SDK":"580.0.0"}', b""
            )
        if argv[:5] == (
            "/usr/bin/gcloud",
            "artifacts",
            "docker",
            "images",
            "describe",
        ):
            output = f"{self.remote_digest}\n".encode() if self.remote_digest else b"ok"
            return subprocess.CompletedProcess(list(argv), 0, output, b"")
        if argv[:4] == (operator._PYTHON, "-P", "-S", "-c"):
            return subprocess.CompletedProcess(list(argv), 0, b"", b"")
        if self.action_error is not None:
            raise self.action_error
        if argv[0] == operator._TERRAFORM and "plan" in argv:
            output = next(
                item.removeprefix("-out=") for item in argv if item.startswith("-out=")
            )
            Path(output).write_bytes(b"execution-plan")
        return self.action_result

    def bind_source(self, source_root: Path) -> _Runner:
        self.source_root = source_root
        self.source_tree = _snapshot_tree(source_root)
        return self


def _mutating_calls(runner: _Runner) -> list[tuple[str, ...]]:
    return [
        call
        for call in runner.calls
        if call[0] != "/usr/bin/git"
        and not (
            call[0] == operator._TERRAFORM
            and len(call) > 1
            and (
                call[1] == "version"
                or (
                    len(call) > 2
                    and call[1].startswith("-chdir=")
                    and call[2] == "show"
                )
            )
        )
        and call != ("/usr/bin/gcloud", "version", "--format=json")
        and call[:4] != (operator._PYTHON, "-P", "-S", "-c")
    ]


def _admit_bootstrap(
    tmp_path: Path,
    *,
    runner: _Runner | None = None,
) -> tuple[
    operator.Phase5StateStore,
    operator.Phase5ApprovalManifest,
    operator.Phase5Approval,
    operator.Phase5Admission,
]:
    state, manifest, approval, prepared_runner = _records(tmp_path)
    selected_runner = runner or prepared_runner
    admission = operator.authorize_action(
        action=operator.Phase5Action.BOOTSTRAP_APPLY,
        manifest=manifest,
        approval=approval,
        state=state,
        repo_root=_REPO_ROOT,
        now=_NOW + timedelta(minutes=2),
        runner=selected_runner,
    )
    return state, manifest, approval, admission


def _record_action(
    state: operator.Phase5StateStore,
    manifest: operator.Phase5ApprovalManifest,
    approval: operator.Phase5Approval,
    action: operator.Phase5Action,
    *,
    at: datetime,
    result: object,
) -> operator.Phase5ActionEvidenceBinding:
    admission = state.admit(
        manifest=manifest,
        approval=approval,
        action=action,
        admitted_at=at,
    )
    outcome = operator._build_outcome(
        admission,
        result,
        finished_at=at + timedelta(seconds=1),
    )
    evidence = operator._seal(
        operator.Phase5Evidence,
        schema_version="reconcile/phase5-operator/v1",
        record_type="evidence",
        manifest_sha256=manifest.record_sha256,
        approval_sha256=approval.record_sha256,
        admission_sha256=admission.record_sha256,
        outcome_sha256=outcome.record_sha256,
        action=action,
        status=outcome.status,
        observed_at=outcome.finished_at,
    )
    state.complete(admission=admission, outcome=outcome, evidence=evidence)
    return operator.Phase5ActionEvidenceBinding(
        action=action,
        admission_sha256=admission.record_sha256,
        outcome_sha256=outcome.record_sha256,
        evidence_sha256=evidence.record_sha256,
        status=outcome.status,
    )


def _terminal_image_predecessor(
    tmp_path: Path,
) -> tuple[
    operator.Phase5StateStore,
    operator.Phase5ApprovalManifest,
    operator.Phase5Approval,
]:
    tmp_path.mkdir()
    state, manifest, approval, _ = _records(tmp_path)
    success = subprocess.CompletedProcess(["fixed"], 0, b"", b"")
    _record_action(
        state,
        manifest,
        approval,
        operator.Phase5Action.BOOTSTRAP_APPLY,
        at=_NOW + timedelta(minutes=2),
        result=success,
    )
    _record_action(
        state,
        manifest,
        approval,
        operator.Phase5Action.FOUNDATION_APPLY,
        at=_NOW + timedelta(minutes=3),
        result=success,
    )
    _record_action(
        state,
        manifest,
        approval,
        operator.Phase5Action.IMAGE_PUSH,
        at=_NOW + timedelta(minutes=4),
        result=object(),
    )
    bootstrap_state = state.root / "state" / "bootstrap.tfstate"
    bootstrap_state.write_bytes(b'{"lineage":"phase5","serial":1}')
    bootstrap_state.chmod(0o600)
    return state, manifest, approval


def _continuation_successor(
    tmp_path: Path,
) -> tuple[
    Path,
    operator.Phase5StateStore,
    operator.Phase5ApprovalManifest,
    operator.Phase5Approval,
    _Runner,
]:
    repo_root = _copy_repo_inputs(tmp_path / "successor-repo")
    operator_source = repo_root / "reconcile" / "phase5_operator.py"
    operator_source.write_bytes(operator_source.read_bytes() + b"\n")
    successor_root = tmp_path / "successor"
    successor_root.mkdir()
    state, manifest, approval, runner = _records(
        successor_root,
        repo_root=repo_root,
    )
    return repo_root, state, manifest, approval, runner


def test_manifest_freezes_exact_identity_limits_estimates_and_commands(
    tmp_path: Path,
) -> None:
    _, manifest, _, _ = _records(tmp_path)

    assert manifest.image_reference.endswith(f"@{manifest.image_digest}")
    assert manifest.image_artifact.manifest_digest == manifest.image_digest
    assert len(manifest.terraform_stacks) == 3
    assert len(manifest.terraform_plans) == 7
    assert manifest.semantic_config_sha256 == manifest.semantic_sources.sha256
    assert manifest.count_tokens_attempt_limit == 1
    assert manifest.billed_generation_limit == 1
    assert manifest.authorization_estimate_usd == "3.892942"
    assert manifest.contingency_authorization_estimate_usd == "4.866178"
    assert manifest.estimate_kind == "authorization-estimate-not-hard-cap"
    assert manifest.work_deadline - manifest.created_at == timedelta(hours=8)
    assert {item.action for item in manifest.commands} == set(operator.Phase5Action)
    assert all(
        command and command[0] not in {"sh", "bash"}
        for item in manifest.commands
        for command in item.commands
    )
    assert all(
        "-c" not in command[:2]
        for item in manifest.commands
        for command in item.commands
    )
    provider = manifest.command_for(operator.Phase5Action.PROVIDER_ACCEPTANCE)
    assert {item.name: item.value for item in provider.environment} == {
        "PYTHONPATH": (
            f"{Path(manifest.operator_state_root) / 'source'}:"
            f"{Path(manifest.operator_state_root) / 'python-dependencies'}"
        ),
        "RECONCILE_API_AUDIENCE": (
            "https://reconcile.invalid/phase5/reconcile-dev-260813-14fa6d/api"
        ),
    }
    assert provider.commands[0][4:6] == (
        "scripts.check_phase5_hosted_acceptance",
        "provider",
    )
    assert provider.commands[0][:4] == (operator._PYTHON, "-P", "-S", "-m")
    assert manifest.python_interpreter == operator._PYTHON
    assert manifest.python_interpreter_sha256 == operator._PYTHON_SHA256
    assert manifest.terraform_executable == operator._TERRAFORM
    assert manifest.terraform_binary_sha256 == operator._TERRAFORM_SHA256
    assert manifest.terraform_cli_config_path == str(
        Path(manifest.operator_state_root) / "terraform.rc"
    )
    assert manifest.terraform_cli_config_sha256 == operator._EMPTY_SHA256
    assert manifest.python_dependencies.root == str(
        Path(manifest.operator_state_root) / "python-dependencies"
    )
    assert manifest.execution_source.root == str(
        Path(manifest.operator_state_root) / "source"
    )
    assert "scripts/phase5_operator.py" in {
        item.path for item in manifest.execution_source.files
    }
    api = next(
        item for item in manifest.authenticated_exposure if item.service == "api"
    )
    assert api.allowed_callers == (
        "serviceAccount:rec-p5-apply@"
        "reconcile-dev-260813-14fa6d.iam.gserviceaccount.com",
    )
    assert manifest.gcloud_version == "580.0.0"
    image_push = manifest.command_for(operator.Phase5Action.IMAGE_PUSH)
    assert image_push.commands[2][3] == "--format={{.Descriptor.digest}}"
    bootstrap = manifest.command_for(operator.Phase5Action.BOOTSTRAP_APPLY)
    assert bootstrap.commands[0] == (
        "/usr/bin/gcloud",
        "services",
        "enable",
        "cloudresourcemanager.googleapis.com",
        "--project=reconcile-dev-260813-14fa6d",
        "--account=eddyphilochola13@gmail.com",
        "--quiet",
    )
    assert "init" in bootstrap.commands[1]
    assert "plan" in bootstrap.commands[2]
    assert bootstrap.commands[3][:4] == (
        operator._TERRAFORM,
        "-chdir=infra/bootstrap",
        "show",
        "-json",
    )
    assert "apply" in bootstrap.commands[4]
    terraform_stacks = {
        operator.Phase5Action.BOOTSTRAP_APPLY: "infra/bootstrap",
        operator.Phase5Action.FOUNDATION_APPLY: "infra/environments/dev/foundation",
        operator.Phase5Action.RUNTIME_APPLY: "infra/environments/dev/runtime",
        operator.Phase5Action.RUNTIME_TEARDOWN: "infra/environments/dev/runtime",
        operator.Phase5Action.FOUNDATION_TEARDOWN: (
            "infra/environments/dev/foundation"
        ),
        operator.Phase5Action.STATE_PROTECTION_CHANGE: "infra/bootstrap",
        operator.Phase5Action.BOOTSTRAP_TEARDOWN: "infra/bootstrap",
    }
    for action, directory in terraform_stacks.items():
        descriptor = manifest.command_for(action)
        show = next(command for command in descriptor.commands if "show" in command)
        assert show[:4] == (
            operator._TERRAFORM,
            f"-chdir={directory}",
            "show",
            "-json",
        )
    image = manifest.command_for(operator.Phase5Action.IMAGE_PUSH)
    assert {item.name: item.value for item in image.environment} == {
        "CLOUDSDK_AUTH_IMPERSONATE_SERVICE_ACCOUNT": (
            "rec-p5-apply@reconcile-dev-260813-14fa6d.iam.gserviceaccount.com"
        ),
        "DOCKER_CONFIG": str(Path(manifest.operator_state_root) / "docker"),
        "DOCKER_HOST": operator._DOCKER_HOST,
    }
    assert image.commands[0] == (
        "/usr/bin/gcloud",
        "auth",
        "configure-docker",
        "us-central1-docker.pkg.dev",
        (
            "--impersonate-service-account=rec-p5-apply@"
            "reconcile-dev-260813-14fa6d.iam.gserviceaccount.com"
        ),
        "--quiet",
    )
    assert image.commands[1][0] == operator._DOCKER


def test_legacy_image_id_manifest_is_limited_to_the_exact_allowlist(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _, manifest, _, _ = _records(tmp_path)

    with pytest.raises(ValueError, match="command inventory differs"):
        _legacy_image_id_manifest(manifest)

    monkeypatch.setattr(
        operator,
        "_LEGACY_IMAGE_ID_SOURCE_REVISIONS",
        frozenset({_SOURCE}),
    )
    legacy = _legacy_image_id_manifest(manifest)

    assert (
        legacy.command_for(operator.Phase5Action.IMAGE_PUSH).commands[2][3]
        == "--format={{.Id}}"
    )
    assert (
        manifest.command_for(operator.Phase5Action.IMAGE_PUSH).commands[2][3]
        == "--format={{.Descriptor.digest}}"
    )


def test_legacy_manifest_is_read_only_even_when_allowlisted(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    state, manifest, _, runner = _records(tmp_path)
    monkeypatch.setattr(
        operator,
        "_LEGACY_IMAGE_ID_SOURCE_REVISIONS",
        frozenset({_SOURCE}),
    )
    legacy = _legacy_image_id_manifest(manifest)
    approval = operator.build_approval(
        legacy,
        approved_by="user:eddyphilochola13@gmail.com",
        approved_at=_NOW + timedelta(minutes=1),
    )

    with pytest.raises(operator.OperatorError, match="LEGACY_MANIFEST_READ_ONLY"):
        operator.authorize_action(
            action=operator.Phase5Action.RUNTIME_TEARDOWN,
            manifest=legacy,
            approval=approval,
            state=state,
            repo_root=_REPO_ROOT,
            now=_NOW + timedelta(minutes=2),
            runner=runner,
        )
    assert _mutating_calls(runner) == []


def test_execution_snapshot_is_closed_to_code_and_required_phase5_scripts(
    tmp_path: Path,
) -> None:
    _, manifest, _, _ = _records(tmp_path)
    paths = {item.path for item in manifest.execution_source.files}

    assert operator._EXECUTION_REQUIRED_PATHS <= paths
    assert "scripts/phase5_operator.py" in paths
    assert all(operator._execution_path_allowed(path) for path in paths)
    assert not any(
        path.split("/", 1)[0]
        in {"artifacts", "docs", "evidence", "qualification", "tests"}
        for path in paths
    )
    assert not any(
        "holdout" in part.casefold() for path in paths for part in path.split("/")
    )
    assert operator._execution_path_allowed("reconcile/evidence/engine.py")
    assert not operator._execution_path_allowed("evidence/consumed-v3.json")
    assert not operator._execution_path_allowed("qualification/final-holdout.json")


def test_materializer_reads_only_allowlisted_commit_blobs(tmp_path: Path) -> None:
    repository = tmp_path / "repository"
    repository.mkdir()
    state = operator.Phase5StateStore(tmp_path / "state")
    payloads = {
        path: f"exact:{path}\n".encode()
        for path in (
            *sorted(operator._EXECUTION_REQUIRED_PATHS),
            "reconcile/__init__.py",
            "infra/bootstrap/main.tf",
        )
    }
    entries = tuple(
        (path, "100644", operator._git_blob_object_id(payload))
        for path, payload in sorted(payloads.items())
    )
    by_object = {object_id: payloads[path] for path, _, object_id in entries}
    calls: list[tuple[str, ...]] = []

    def runner(argv, *, cwd, environment, timeout_seconds):
        assert cwd == repository
        assert "AMBIENT_SECRET" not in environment
        assert timeout_seconds in {15, 30}
        calls.append(argv)
        if argv[1:] == ("--version",):
            output = b"git version 2.43.0\n"
        elif argv[1:] == ("rev-parse", "--show-object-format"):
            output = b"sha1\n"
        elif argv[1:3] == ("rev-parse", "--verify"):
            output = f"{_SOURCE}\n".encode()
        elif argv[1:4] == ("show", "-s", "--format=%ct"):
            output = b"1787032800\n"
        elif argv[1:5] == ("ls-tree", "-r", "-z", "--full-tree"):
            output = b"".join(
                f"{mode} blob {object_id}\t{path}\0".encode()
                for path, mode, object_id in entries
            )
        elif argv[1:3] == ("cat-file", "blob"):
            output = by_object[argv[3]]
        else:  # pragma: no cover - closed Git inventory
            raise AssertionError(argv)
        return subprocess.CompletedProcess(argv, 0, output, b"")

    binding = operator._materialize_execution_source(
        state_root=state.root,
        repo_root=repository,
        source_revision=_SOURCE,
        runner=runner,
    )

    ls_tree = next(call for call in calls if call[1] == "ls-tree")
    assert ls_tree[7:] == operator._EXECUTION_GIT_PATHS
    assert {call[3] for call in calls if call[1:3] == ("cat-file", "blob")} == set(
        by_object
    )
    assert {item.path for item in binding.files} == set(payloads)
    assert stat.S_IMODE(Path(binding.root).stat().st_mode) == 0o500


def test_snapshot_tamper_and_closed_world_extra_block_before_mutation(
    tmp_path: Path,
) -> None:
    state, manifest, approval, runner = _records(tmp_path)
    source = Path(manifest.execution_source.root)
    source.chmod(0o700)
    extra = source / "unexpected.txt"
    extra.write_bytes(b"not approved")
    extra.chmod(0o400)
    source.chmod(0o500)

    with pytest.raises(
        operator.OperatorError, match="EXECUTION_SOURCE_CLOSED_WORLD_DRIFT"
    ):
        operator.authorize_action(
            action=operator.Phase5Action.BOOTSTRAP_APPLY,
            manifest=manifest,
            approval=approval,
            state=state,
            repo_root=_REPO_ROOT,
            now=_NOW + timedelta(minutes=2),
            runner=runner,
        )

    assert _mutating_calls(runner) == []


def test_snapshot_permissions_deny_direct_source_writes(tmp_path: Path) -> None:
    _, manifest, _, _ = _records(tmp_path)
    source = Path(manifest.execution_source.root)

    assert stat.S_IMODE(source.stat().st_mode) == 0o500
    with pytest.raises(PermissionError):
        (source / "pyproject.toml").open("wb")


def test_manifest_rejects_non_eight_hour_window() -> None:
    values = _draft().model_dump()
    values["work_deadline"] = _NOW + timedelta(hours=9)

    with pytest.raises(ValueError, match="exactly eight hours"):
        operator.Phase5ManifestDraft.model_validate(values)


@pytest.mark.parametrize("hours", (9, 11))
def test_manifest_rejects_shorter_or_longer_teardown_window(hours: int) -> None:
    values = _draft().model_dump()
    values["approval_expires_at"] = _NOW + timedelta(hours=hours)

    with pytest.raises(ValueError, match="exactly two hours"):
        operator.Phase5ManifestDraft.model_validate(values)


def test_source_and_infrastructure_revision_widths_are_not_interchangeable(
    tmp_path: Path,
) -> None:
    _, manifest, _, _ = _records(tmp_path)
    assert len(manifest.source_revision) == 40
    assert len(manifest.infrastructure_revision) == 64

    invalid_manifest = manifest.model_dump()
    invalid_manifest["infrastructure_revision"] = "b" * 40
    with pytest.raises(ValueError):
        operator.Phase5ApprovalManifest.model_validate(invalid_manifest)

    invalid_draft = _draft().model_dump()
    invalid_draft["source_revision"] = "a" * 64
    with pytest.raises(ValueError):
        operator.Phase5ManifestDraft.model_validate(invalid_draft)


def test_approval_requires_the_frozen_owner(tmp_path: Path) -> None:
    _, manifest, _, _ = _records(tmp_path)

    with pytest.raises(operator.OperatorError, match="APPROVER_NOT_OWNER"):
        operator.build_approval(
            manifest,
            approved_by="user:someone-else@example.com",
            approved_at=_NOW + timedelta(minutes=1),
        )


def test_state_records_are_canonical_private_and_immutable(tmp_path: Path) -> None:
    state, manifest, _, _ = _records(tmp_path)
    manifest_path = state.root / f"manifest-{manifest.record_sha256}.json"

    assert stat.S_IMODE(state.root.stat().st_mode) == 0o700
    assert stat.S_IMODE(manifest_path.stat().st_mode) == 0o400
    raw = manifest_path.read_bytes()
    assert (
        raw
        == json.dumps(
            json.loads(raw),
            allow_nan=False,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode()
    )
    with pytest.raises(operator.OperatorError, match="IMMUTABLE_RECORD_EXISTS"):
        state.write_manifest(manifest)


def test_state_record_hardlink_substitution_is_rejected(tmp_path: Path) -> None:
    state, manifest, _, _ = _records(tmp_path)
    manifest_path = state.root / f"manifest-{manifest.record_sha256}.json"
    os.link(manifest_path, state.root / "unexpected-hardlink.json")

    with pytest.raises(operator.OperatorError, match="RECORD_NOT_PRIVATE"):
        state.load_manifest(manifest.record_sha256)


def test_state_rejects_nonprivate_directory(tmp_path: Path) -> None:
    root = tmp_path / "state"
    root.mkdir(mode=0o700)
    root.chmod(0o755)

    with pytest.raises(operator.OperatorError, match="STATE_DIRECTORY_NOT_PRIVATE"):
        operator.Phase5StateStore(root)


def test_continuation_carries_only_verified_successes_without_replaying_them(
    tmp_path: Path,
) -> None:
    predecessor, predecessor_manifest, predecessor_approval = (
        _terminal_image_predecessor(tmp_path / "predecessor")
    )
    repo_root, successor, manifest, approval, runner = _continuation_successor(tmp_path)
    predecessor_snapshot = {
        path.relative_to(predecessor.root).as_posix(): (
            path.read_bytes(),
            stat.S_IMODE(path.stat().st_mode),
            path.stat().st_ino,
        )
        for path in predecessor.root.rglob("*")
        if path.is_file()
    }

    continuation = operator.prepare_phase5_continuation(
        predecessor_state_root=predecessor.root,
        predecessor_manifest_sha256=predecessor_manifest.record_sha256,
        predecessor_approval_sha256=predecessor_approval.record_sha256,
        successor_state_root=successor.root,
        successor_manifest_sha256=manifest.record_sha256,
        successor_approval_sha256=approval.record_sha256,
        repo_root=repo_root,
        prepared_at=_NOW + timedelta(minutes=2),
        runner=runner,
    )

    assert tuple(item.action for item in continuation.carried_successes) == (
        operator.Phase5Action.BOOTSTRAP_APPLY,
        operator.Phase5Action.FOUNDATION_APPLY,
    )
    assert continuation.terminal_action.action is operator.Phase5Action.IMAGE_PUSH
    assert continuation.terminal_action.status is operator.OutcomeStatus.UNKNOWN
    source_state = predecessor.root / "state" / "bootstrap.tfstate"
    copied_state = successor.root / "state" / "bootstrap.tfstate"
    assert source_state.read_bytes() == copied_state.read_bytes()
    assert source_state.stat().st_ino != copied_state.stat().st_ino
    assert stat.S_IMODE(copied_state.stat().st_mode) == 0o600
    assert predecessor_snapshot == {
        path.relative_to(predecessor.root).as_posix(): (
            path.read_bytes(),
            stat.S_IMODE(path.stat().st_mode),
            path.stat().st_ino,
        )
        for path in predecessor.root.rglob("*")
        if path.is_file()
    }

    with pytest.raises(operator.OperatorError, match="ACTION_ALREADY_ATTEMPTED"):
        successor.admit(
            manifest=manifest,
            approval=approval,
            action=operator.Phase5Action.BOOTSTRAP_APPLY,
            admitted_at=_NOW + timedelta(minutes=3),
        )
    image_admission = successor.admit(
        manifest=manifest,
        approval=approval,
        action=operator.Phase5Action.IMAGE_PUSH,
        admitted_at=_NOW + timedelta(minutes=4),
    )
    assert image_admission.action is operator.Phase5Action.IMAGE_PUSH


def test_continuation_rejects_unsuccessful_predecessor_action(
    tmp_path: Path,
) -> None:
    (tmp_path / "predecessor").mkdir()
    predecessor, predecessor_manifest, predecessor_approval, _ = _records(
        tmp_path / "predecessor"
    )
    success = subprocess.CompletedProcess(["fixed"], 0, b"", b"")
    failure = subprocess.CompletedProcess(["fixed"], 1, b"", b"")
    _record_action(
        predecessor,
        predecessor_manifest,
        predecessor_approval,
        operator.Phase5Action.BOOTSTRAP_APPLY,
        at=_NOW + timedelta(minutes=2),
        result=success,
    )
    _record_action(
        predecessor,
        predecessor_manifest,
        predecessor_approval,
        operator.Phase5Action.FOUNDATION_APPLY,
        at=_NOW + timedelta(minutes=3),
        result=failure,
    )
    bootstrap_state = predecessor.root / "state" / "bootstrap.tfstate"
    bootstrap_state.write_bytes(b'{"serial":1}')
    bootstrap_state.chmod(0o600)
    repo_root, successor, manifest, approval, runner = _continuation_successor(tmp_path)

    with pytest.raises(
        operator.OperatorError,
        match="CONTINUATION_PREDECESSOR_HISTORY_INVALID",
    ):
        operator.prepare_phase5_continuation(
            predecessor_state_root=predecessor.root,
            predecessor_manifest_sha256=predecessor_manifest.record_sha256,
            predecessor_approval_sha256=predecessor_approval.record_sha256,
            successor_state_root=successor.root,
            successor_manifest_sha256=manifest.record_sha256,
            successor_approval_sha256=approval.record_sha256,
            repo_root=repo_root,
            prepared_at=_NOW + timedelta(minutes=2),
            runner=runner,
        )
    assert not (successor.root / "state" / "bootstrap.tfstate").exists()


def test_continuation_rejects_bound_drift(tmp_path: Path) -> None:
    (tmp_path / "predecessor").mkdir()
    _, predecessor, _, _ = _records(tmp_path / "predecessor")
    _, _, successor, _, _ = _continuation_successor(tmp_path)
    drifted = successor.model_copy(update={"infrastructure_revision": "f" * 64})

    with pytest.raises(operator.OperatorError, match="CONTINUATION_BOUND_DRIFT"):
        operator._validate_continuation_bounds(predecessor, drifted)


def test_continuation_rejects_additional_dependency_drift(tmp_path: Path) -> None:
    (tmp_path / "predecessor").mkdir()
    _, predecessor, _, _ = _records(tmp_path / "predecessor")
    _, successor_state, successor, _, _ = _continuation_successor(tmp_path)
    dependency = Path(successor.python_dependencies.root) / "grpc" / "__init__.py"
    dependency.chmod(0o600)
    dependency.write_bytes(b'PACKAGE = "changed"\n')
    dependency.chmod(0o400)
    recaptured = operator._capture_python_dependencies(
        state_root=successor_state.root,
        image_artifact=successor.image_artifact,
        python_lock_sha256=successor.python_lock_sha256,
    )
    drifted = successor.model_copy(update={"python_dependencies": recaptured})

    with pytest.raises(
        operator.OperatorError,
        match="CONTINUATION_DEPENDENCY_DRIFT",
    ):
        operator._validate_continuation_bounds(predecessor, drifted)


def test_continuation_state_tamper_blocks_next_admission(tmp_path: Path) -> None:
    predecessor, predecessor_manifest, predecessor_approval = (
        _terminal_image_predecessor(tmp_path / "predecessor")
    )
    repo_root, successor, manifest, approval, runner = _continuation_successor(tmp_path)
    operator.prepare_phase5_continuation(
        predecessor_state_root=predecessor.root,
        predecessor_manifest_sha256=predecessor_manifest.record_sha256,
        predecessor_approval_sha256=predecessor_approval.record_sha256,
        successor_state_root=successor.root,
        successor_manifest_sha256=manifest.record_sha256,
        successor_approval_sha256=approval.record_sha256,
        repo_root=repo_root,
        prepared_at=_NOW + timedelta(minutes=2),
        runner=runner,
    )
    predecessor_state = predecessor.root / "state" / "bootstrap.tfstate"
    predecessor_state.write_bytes(predecessor_state.read_bytes() + b"tamper")
    predecessor_state.chmod(0o600)

    with pytest.raises(
        operator.OperatorError,
        match="CONTINUATION_BOOTSTRAP_STATE_DRIFT",
    ):
        successor.admit(
            manifest=manifest,
            approval=approval,
            action=operator.Phase5Action.IMAGE_PUSH,
            admitted_at=_NOW + timedelta(minutes=3),
        )


def test_continuation_rejects_bootstrap_state_destination_collision(
    tmp_path: Path,
) -> None:
    predecessor, predecessor_manifest, predecessor_approval = (
        _terminal_image_predecessor(tmp_path / "predecessor")
    )
    repo_root, successor, manifest, approval, runner = _continuation_successor(tmp_path)
    collision = successor.root / "state" / "bootstrap.tfstate"
    collision.write_bytes(b"preexisting")
    collision.chmod(0o600)

    with pytest.raises(
        operator.OperatorError,
        match="CONTINUATION_BOOTSTRAP_STATE_EXISTS",
    ):
        operator.prepare_phase5_continuation(
            predecessor_state_root=predecessor.root,
            predecessor_manifest_sha256=predecessor_manifest.record_sha256,
            predecessor_approval_sha256=predecessor_approval.record_sha256,
            successor_state_root=successor.root,
            successor_manifest_sha256=manifest.record_sha256,
            successor_approval_sha256=approval.record_sha256,
            repo_root=repo_root,
            prepared_at=_NOW + timedelta(minutes=2),
            runner=runner,
        )


def test_default_cli_is_read_only_inspection(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capfd: pytest.CaptureFixture[str]
) -> None:
    root = tmp_path / "not-created"
    monkeypatch.setenv("XDG_STATE_HOME", str(root))

    assert operator.main([]) == 0

    output = json.loads(capfd.readouterr().out)
    assert output["status"] == "UNINITIALIZED"
    assert not root.exists()


def test_no_cloud_preparation_builds_complete_private_manifest_inputs(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def fake_container(**values: Any) -> tuple[str, str]:
        assert values["source_revision"] == _SOURCE
        assert values["source_root"] == tmp_path / "state" / "source"
        assert values["source_date_epoch"] == 1_787_032_800
        artifact_output = values["artifact_output"]
        digest = _write_oci_archive(artifact_output)
        return digest, operator._image_source_tag(_SOURCE)

    def fake_terraform(**values: Any) -> None:
        assert values["provider_mirror"] is None
        source_root = values["source_root"]
        runtime_identity = values["runtime_identity"]
        assert source_root == tmp_path / "state" / "source"
        artifact_output = values["state_root"] / "plans"
        required = set(runtime_identity.values()) | {
            (
                "us-central1-docker.pkg.dev/reconcile-dev-260813-14fa6d/"
                f"reconcile-p5/reconcile@{runtime_identity['image_digest']}"
            )
        }
        for _, stem in operator._PLAN_FILES.values():
            qualification = artifact_output / f"{stem}.tfplan.json"
            qualification.write_bytes(_plan_json(stem, required))
            qualification.chmod(0o400)
            values = json.loads(qualification.read_bytes())["variables"]
            variables = artifact_output / f"{stem}.tfvars.json"
            variables.write_bytes(
                json.dumps(
                    {name: item["value"] for name, item in values.items()},
                    separators=(",", ":"),
                    sort_keys=True,
                ).encode()
            )
            variables.chmod(0o400)

    def fake_dependencies(**values: Any) -> operator.PythonDependencyBinding:
        _write_dependency_tree(values["state_root"] / "python-dependencies")
        return operator._capture_python_dependencies(
            state_root=values["state_root"],
            image_artifact=values["image_artifact"],
            python_lock_sha256=values["python_lock_sha256"],
        )

    monkeypatch.setattr(operator, "_verify_exact_main_identity", lambda *_, **__: None)
    monkeypatch.setattr(operator, "_prepare_container_from_snapshot", fake_container)
    monkeypatch.setattr(operator, "_prepare_terraform_from_snapshot", fake_terraform)
    monkeypatch.setattr(operator, "_materialize_python_dependencies", fake_dependencies)
    monkeypatch.setattr(
        operator, "_verify_python_dependency_runtime", lambda *_, **__: None
    )
    monkeypatch.setattr(operator, "_verify_terraform_binary", lambda *_, **__: None)
    monkeypatch.setattr(operator, "_verify_docker_binary", lambda *_: None)

    def fake_materialize(**values: Any) -> operator.ExecutionSourceBinding:
        state = operator.Phase5StateStore(values["state_root"])
        source = _install_execution_source(state, values["repo_root"])
        return _test_execution_binding(source)

    monkeypatch.setattr(operator, "_materialize_execution_source", fake_materialize)

    draft, draft_path = operator.prepare_phase5_artifacts(
        state_root=tmp_path / "state",
        repo_root=_REPO_ROOT,
        source_revision=_SOURCE,
        created_at=_NOW,
        provider_mirror=None,
    )

    assert draft.work_deadline == _NOW + timedelta(hours=8)
    assert draft.approval_expires_at == _NOW + timedelta(hours=10)
    assert stat.S_IMODE(draft_path.stat().st_mode) == 0o600
    assert len(tuple((tmp_path / "state" / "plans").iterdir())) == 14
    assert (
        stat.S_IMODE(
            (tmp_path / "state" / "images" / "reconcile.oci.tar").stat().st_mode
        )
        == 0o400
    )


@pytest.mark.parametrize(
    ("relative", "directory"),
    (
        ("execution/stale.tfplan", False),
        ("state/bootstrap.tfstate", False),
        ("docker/config.json", False),
        ("terraform-data/bootstrap/stale", False),
        ("draft.json", False),
        ("manifest-stale.json", False),
        (".operator.lock", False),
        ("source", True),
    ),
)
def test_preparation_rejects_every_reused_state_contaminant(
    tmp_path: Path,
    relative: str,
    directory: bool,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(operator, "_verify_exact_main_identity", lambda *_, **__: None)
    state = operator.Phase5StateStore(tmp_path / "state")
    path = state.root / relative
    if directory:
        path.mkdir(mode=0o700)
    else:
        path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        path.write_bytes(b"stale")

    with pytest.raises(operator.OperatorError, match="PREPARATION_STATE_NOT_EMPTY"):
        operator.prepare_phase5_artifacts(
            state_root=state.root,
            repo_root=_REPO_ROOT,
            source_revision=_SOURCE,
            created_at=_NOW,
            provider_mirror=None,
        )


@pytest.mark.parametrize(
    "name",
    (
        "opt/reconcile/lib/python3.12/site-packages/bidi-\u202e.py",
        "opt/reconcile/lib/python3.12/site-packages/cafe\u0301.py",
        "opt/reconcile/lib/python3.12/site-packages/space name.py",
    ),
)
def test_dependency_extractor_rejects_non_ascii_or_noncanonical_paths(
    tmp_path: Path,
    name: str,
) -> None:
    state, artifact = _dependency_artifact(
        tmp_path,
        layer_entries=((name, "file", b"payload"),),
    )

    with pytest.raises(operator.OperatorError, match="OCI_IMAGE_INVALID"):
        operator._materialize_python_dependencies(
            state_root=state.root,
            image_artifact=artifact,
            python_lock_sha256="a" * 64,
        )


def test_dependency_extractor_ignores_safe_utf8_path_outside_dependency_prefix(
    tmp_path: Path,
) -> None:
    prefix = "opt/reconcile/lib/python3.12/site-packages"
    state, artifact = _dependency_artifact(
        tmp_path,
        layer_entries=(
            (
                "etc/ssl/certs/NetLock_Arany_=Class_Gold=_F\u0151tan\u00fas\u00edtv\u00e1ny.pem",
                "symlink",
                "/usr/share/ca-certificates/mozilla/NetLock.pem",
            ),
            *(
                (name, "directory", None)
                for name in (
                    "opt",
                    "opt/reconcile",
                    "opt/reconcile/lib",
                    "opt/reconcile/lib/python3.12",
                    prefix,
                )
            ),
            (f"{prefix}/module.py", "file", b"payload"),
        ),
    )

    binding = operator._materialize_python_dependencies(
        state_root=state.root,
        image_artifact=artifact,
        python_lock_sha256="a" * 64,
    )

    assert binding.file_count == 1
    assert (Path(binding.root) / "module.py").read_bytes() == b"payload"


@pytest.mark.parametrize(
    "name",
    (
        "/opt/reconcile/lib/python3.12/site-packages/absolute.py",
        "opt/reconcile/lib/python3.12/site-packages/../traversal.py",
        "opt\\reconcile\\lib\\python3.12\\site-packages\\backslash.py",
        "././opt/reconcile/lib/python3.12/site-packages/alias.py",
    ),
)
def test_dependency_extractor_rejects_absolute_traversal_and_alias_paths(
    tmp_path: Path,
    name: str,
) -> None:
    state, artifact = _dependency_artifact(
        tmp_path,
        layer_entries=((name, "file", b"payload"),),
    )

    with pytest.raises(operator.OperatorError, match="OCI_IMAGE_INVALID"):
        operator._materialize_python_dependencies(
            state_root=state.root,
            image_artifact=artifact,
            python_lock_sha256="a" * 64,
        )


def test_dependency_extractor_rejects_excessive_depth_without_temp_remnants(
    tmp_path: Path,
) -> None:
    prefix = "opt/reconcile/lib/python3.12/site-packages"
    deep = "/".join((prefix, *("n" for _ in range(1_100)), "module.py"))
    state, artifact = _dependency_artifact(
        tmp_path,
        layer_entries=((deep, "file", b"payload"),),
    )

    with pytest.raises(operator.OperatorError, match="OCI_IMAGE_INVALID"):
        operator._materialize_python_dependencies(
            state_root=state.root,
            image_artifact=artifact,
            python_lock_sha256="a" * 64,
        )
    assert not any(
        path.name.startswith((".python-dependencies-", ".python-dependency-layers-"))
        for path in state.root.iterdir()
    )


def test_dependency_extractor_rejects_duplicate_canonical_aliases(
    tmp_path: Path,
) -> None:
    canonical = "opt/reconcile/lib/python3.12/site-packages/module.py"
    state, artifact = _dependency_artifact(
        tmp_path,
        layer_entries=(
            (canonical, "file", b"one"),
            (f"./{canonical}", "file", b"two"),
        ),
    )

    with pytest.raises(
        operator.OperatorError,
        match="PYTHON_DEPENDENCY_CLOSURE_INVALID",
    ):
        operator._materialize_python_dependencies(
            state_root=state.root,
            image_artifact=artifact,
            python_lock_sha256="a" * 64,
        )


@pytest.mark.parametrize(
    "name",
    (
        "opt/reconcile/lib/python3.12/.wh.site-packages",
        ("opt/reconcile/lib/python3.12/site-packages/package/.wh.module.py"),
        ("opt/reconcile/lib/python3.12/site-packages/package/.wh..wh..opq"),
    ),
)
def test_dependency_extractor_rejects_ancestor_descendant_and_opaque_whiteouts(
    tmp_path: Path,
    name: str,
) -> None:
    state, artifact = _dependency_artifact(
        tmp_path,
        layer_entries=((name, "file", b""),),
    )

    with pytest.raises(
        operator.OperatorError,
        match="PYTHON_DEPENDENCY_CLOSURE_INVALID",
    ):
        operator._materialize_python_dependencies(
            state_root=state.root,
            image_artifact=artifact,
            python_lock_sha256="a" * 64,
        )


@pytest.mark.parametrize(
    ("name", "kind", "payload"),
    (
        ("opt", "file", b"not-a-directory"),
        (
            "opt/reconcile/lib",
            "hardlink",
            "somewhere-else",
        ),
        (
            "opt/reconcile/lib/python3.12/site-packages",
            "symlink",
            "somewhere-else",
        ),
        (
            "opt/reconcile/lib/python3.12/site-packages",
            "fifo",
            None,
        ),
    ),
)
def test_dependency_extractor_requires_directory_ancestors_and_prefix(
    tmp_path: Path,
    name: str,
    kind: str,
    payload: bytes | str | None,
) -> None:
    state, artifact = _dependency_artifact(
        tmp_path,
        layer_entries=((name, kind, payload),),
    )

    with pytest.raises(
        operator.OperatorError,
        match="PYTHON_DEPENDENCY_CLOSURE_INVALID",
    ):
        operator._materialize_python_dependencies(
            state_root=state.root,
            image_artifact=artifact,
            python_lock_sha256="a" * 64,
        )


@pytest.mark.parametrize(
    "kind",
    ("symlink", "hardlink", "fifo", "character", "block", "sparse"),
)
def test_dependency_extractor_rejects_links_and_special_files(
    tmp_path: Path,
    kind: str,
) -> None:
    payload: bytes | str | None
    if kind in {"symlink", "hardlink"}:
        payload = "target"
    elif kind == "sparse":
        payload = b"x"
    else:
        payload = None
    state, artifact = _dependency_artifact(
        tmp_path,
        layer_entries=(
            (
                "opt/reconcile/lib/python3.12/site-packages/unsafe",
                kind,
                payload,
            ),
        ),
    )

    with pytest.raises(
        operator.OperatorError,
        match="PYTHON_DEPENDENCY_CLOSURE_INVALID",
    ):
        operator._materialize_python_dependencies(
            state_root=state.root,
            image_artifact=artifact,
            python_lock_sha256="a" * 64,
        )


def test_dependency_extractor_rejects_a_second_contributing_layer(
    tmp_path: Path,
) -> None:
    state, artifact = _dependency_artifact(tmp_path, layer_repeat=2)

    with pytest.raises(
        operator.OperatorError,
        match="PYTHON_DEPENDENCY_CLOSURE_INVALID",
    ):
        operator._materialize_python_dependencies(
            state_root=state.root,
            image_artifact=artifact,
            python_lock_sha256="a" * 64,
        )


def test_dependency_extractor_bounds_streamed_layer_members(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    entries = tuple((f"irrelevant/{index}", "file", b"x") for index in range(3))
    state, artifact = _dependency_artifact(tmp_path, layer_entries=entries)
    monkeypatch.setattr(operator, "_MAX_OCI_LAYER_MEMBERS", 2)

    with pytest.raises(operator.OperatorError, match="OCI_IMAGE_INVALID"):
        operator._materialize_python_dependencies(
            state_root=state.root,
            image_artifact=artifact,
            python_lock_sha256="a" * 64,
        )


def test_dependency_extractor_counts_implicit_and_empty_directories(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    prefix = "opt/reconcile/lib/python3.12/site-packages"
    state, artifact = _dependency_artifact(
        tmp_path,
        layer_entries=(
            (f"{prefix}/one", "directory", None),
            (f"{prefix}/two", "directory", None),
            (f"{prefix}/one/module.py", "file", b"x"),
        ),
    )
    monkeypatch.setattr(operator, "_MAX_PYTHON_DEPENDENCY_ENTRIES", 2)

    with pytest.raises(
        operator.OperatorError,
        match="PYTHON_DEPENDENCY_CLOSURE_TOO_LARGE",
    ):
        operator._materialize_python_dependencies(
            state_root=state.root,
            image_artifact=artifact,
            python_lock_sha256="a" * 64,
        )


def test_dependency_extractor_bounds_declared_uncompressed_bytes(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    state, artifact = _dependency_artifact(
        tmp_path,
        layer_entries=(("irrelevant/payload", "file", b"xx"),),
    )
    monkeypatch.setattr(operator, "_MAX_OCI_LAYER_UNCOMPRESSED_BYTES", 1)

    with pytest.raises(operator.OperatorError, match="OCI_IMAGE_INVALID"):
        operator._materialize_python_dependencies(
            state_root=state.root,
            image_artifact=artifact,
            python_lock_sha256="a" * 64,
        )


def test_dependency_extractor_bounds_gzip_expansion_before_scanning(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    state, artifact = _dependency_artifact(tmp_path, gzip_layer=True)
    monkeypatch.setattr(operator, "_MAX_OCI_LAYER_TAR_BYTES", 1_024)

    with pytest.raises(operator.OperatorError, match="OCI_IMAGE_INVALID"):
        operator._materialize_python_dependencies(
            state_root=state.root,
            image_artifact=artifact,
            python_lock_sha256="a" * 64,
        )


@pytest.mark.parametrize(
    "mutation",
    ("truncate_gzip", "invalid_deflate"),
)
def test_dependency_extractor_sanitizes_malformed_gzip_failures(
    tmp_path: Path,
    mutation: str,
) -> None:
    state, artifact = _dependency_artifact(
        tmp_path,
        gzip_layer=True,
        truncate_gzip=mutation == "truncate_gzip",
        invalid_deflate=mutation == "invalid_deflate",
    )

    with pytest.raises(
        operator.OperatorError,
        match="PYTHON_DEPENDENCY_CLOSURE_INVALID",
    ):
        operator._materialize_python_dependencies(
            state_root=state.root,
            image_artifact=artifact,
            python_lock_sha256="a" * 64,
        )


@pytest.mark.parametrize(
    ("constant", "limit", "entries"),
    (
        ("_MAX_OCI_IMAGE_LAYERS", 1, (("irrelevant/a", "file", b"x"),)),
        (
            "_MAX_OCI_AGGREGATE_UNCOMPRESSED_BYTES",
            3,
            (("irrelevant/a", "file", b"xx"),),
        ),
        (
            "_MAX_OCI_AGGREGATE_MEMBERS",
            3,
            (
                ("irrelevant/a", "file", b"x"),
                ("irrelevant/b", "file", b"x"),
            ),
        ),
    ),
)
def test_dependency_extractor_bounds_aggregate_layers(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    constant: str,
    limit: int,
    entries: tuple[tuple[str, str, bytes], ...],
) -> None:
    state, artifact = _dependency_artifact(
        tmp_path,
        layer_entries=entries,
        layer_repeat=2,
    )
    monkeypatch.setattr(operator, constant, limit)

    with pytest.raises(operator.OperatorError, match="OCI_IMAGE_INVALID"):
        operator._materialize_python_dependencies(
            state_root=state.root,
            image_artifact=artifact,
            python_lock_sha256="a" * 64,
        )


def test_oci_outer_archive_stream_index_rejects_duplicates_and_overflow(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    state = operator.Phase5StateStore(tmp_path / "state")
    archive = state.root / "images" / "reconcile.oci.tar"
    digest = _write_oci_archive(archive)
    archive.chmod(0o600)
    with tarfile.open(archive, mode="a") as bundle:
        duplicate = tarfile.TarInfo("index.json")
        duplicate.size = 2
        bundle.addfile(duplicate, io.BytesIO(b"{}"))
    archive.chmod(0o400)

    with pytest.raises(operator.OperatorError, match="OCI_IMAGE_INVALID"):
        operator._capture_image_artifact(
            state_root=state.root,
            source_revision=_SOURCE,
            expected_digest=digest,
        )

    second = tmp_path / "second"
    second.mkdir()
    second_state = operator.Phase5StateStore(second / "state")
    second_archive = second_state.root / "images" / "reconcile.oci.tar"
    second_digest = _write_oci_archive(second_archive)
    monkeypatch.setattr(operator, "_MAX_OCI_ARCHIVE_MEMBERS", 3)
    with pytest.raises(operator.OperatorError, match="OCI_IMAGE_INVALID"):
        operator._capture_image_artifact(
            state_root=second_state.root,
            source_revision=_SOURCE,
            expected_digest=second_digest,
        )


def test_seal_rejects_manual_dependency_tree_when_image_has_no_layer(
    tmp_path: Path,
) -> None:
    state, artifact = _dependency_artifact(tmp_path, include_layer=False)
    _write_dependency_tree(state.root / "python-dependencies")
    source = tmp_path / "source"
    source.mkdir()

    with pytest.raises(operator.OperatorError, match="OCI_IMAGE_INVALID"):
        operator._verify_python_dependency_derivation(
            state_root=state.root,
            source_root=source,
            image_artifact=artifact,
            python_lock_sha256="a" * 64,
            runner=_Runner(),
        )


def test_seal_rederivation_rejects_post_prepare_dependency_tamper(
    tmp_path: Path,
) -> None:
    state, artifact = _dependency_artifact(tmp_path)
    binding = operator._materialize_python_dependencies(
        state_root=state.root,
        image_artifact=artifact,
        python_lock_sha256="a" * 64,
    )
    tampered = Path(binding.root) / "grpc" / "__init__.py"
    tampered.chmod(0o600)
    tampered.write_bytes(b"tampered but manually blessed")
    tampered.chmod(0o400)
    source = tmp_path / "source"
    source.mkdir()

    with pytest.raises(
        operator.OperatorError,
        match="PYTHON_DEPENDENCY_PROVENANCE_INVALID",
    ):
        operator._verify_python_dependency_derivation(
            state_root=state.root,
            source_root=source,
            image_artifact=artifact,
            python_lock_sha256="a" * 64,
            runner=_Runner(),
        )
    assert not any(
        path.name.startswith(".python-dependencies-derived-")
        for path in state.root.iterdir()
    )


def test_dependency_runtime_probe_uses_only_root_python_snapshot_and_sealed_deps(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    state, artifact = _dependency_artifact(tmp_path)
    _write_dependency_tree(state.root / "python-dependencies")
    binding = operator._capture_python_dependencies(
        state_root=state.root,
        image_artifact=artifact,
        python_lock_sha256="a" * 64,
    )
    source = tmp_path / "source"
    package = source / "reconcile"
    package.mkdir(parents=True)
    (package / "__init__.py").write_text("", encoding="utf-8")
    calls: list[tuple[tuple[str, ...], Path, dict[str, str], int]] = []

    def runner(
        argv: tuple[str, ...],
        *,
        cwd: Path,
        environment: dict[str, str] | Any,
        timeout_seconds: int,
    ) -> subprocess.CompletedProcess[bytes]:
        calls.append((argv, cwd, dict(environment), timeout_seconds))
        return subprocess.run(
            argv,
            cwd=cwd,
            env=dict(environment),
            capture_output=True,
            check=False,
            timeout=timeout_seconds,
        )

    monkeypatch.setenv("VIRTUAL_ENV", str(tmp_path / "mutable-venv"))
    monkeypatch.setenv("PYTHONPATH", str(tmp_path / "mutable-live"))
    operator._verify_python_dependency_runtime(
        source_root=source,
        binding=binding,
        runner=runner,
    )

    assert len(calls) == 1
    argv, cwd, environment, timeout = calls[0]
    assert argv[:4] == (operator._PYTHON, "-P", "-S", "-c")
    assert "sys.flags.no_site==1" in argv[4]
    assert argv[-2:] == (str(source), binding.root)
    assert cwd == source
    assert environment["PYTHONPATH"] == f"{source}:{binding.root}"
    assert "VIRTUAL_ENV" not in environment
    assert "mutable" not in environment["PYTHONPATH"]
    assert timeout == 30


def test_dependency_runtime_probe_fails_closed_on_import_or_abi_failure(
    tmp_path: Path,
) -> None:
    state, artifact = _dependency_artifact(tmp_path)
    _write_dependency_tree(state.root / "python-dependencies")
    binding = operator._capture_python_dependencies(
        state_root=state.root,
        image_artifact=artifact,
        python_lock_sha256="a" * 64,
    )
    source = tmp_path / "source"
    source.mkdir()

    def runner(*_args: Any, **_kwargs: Any) -> subprocess.CompletedProcess[bytes]:
        return subprocess.CompletedProcess(["probe"], 1, b"", b"import failed")

    with pytest.raises(
        operator.OperatorError,
        match="PYTHON_DEPENDENCY_RUNTIME_INVALID",
    ):
        operator._verify_python_dependency_runtime(
            source_root=source,
            binding=binding,
            runner=runner,
        )


def test_snapshot_checkers_use_pinned_python_and_reverify_before_terraform(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = tmp_path / "source"
    source.mkdir()
    state = operator.Phase5StateStore(tmp_path / "state")
    operator._write_immutable_empty_file(
        state.root / "terraform.rc",
        failure="TEST_WRITE_FAILED",
    )
    events: list[str] = []
    calls: list[tuple[tuple[str, ...], Path, dict[str, str], int]] = []

    def verify_python() -> None:
        events.append("python")

    def verify_terraform(
        root: Path,
        _runner: Any,
        *,
        cli_config: Path,
        timeout_seconds: int = 15,
    ) -> None:
        assert root == source
        assert cli_config == state.root / "terraform.rc"
        assert timeout_seconds == 15
        events.append("terraform")

    def runner(
        argv: tuple[str, ...],
        *,
        cwd: Path,
        environment: dict[str, str] | Any,
        timeout_seconds: int,
    ) -> subprocess.CompletedProcess[bytes]:
        events.append("runner")
        calls.append((argv, cwd, dict(environment), timeout_seconds))
        output = b""
        if "scripts.check_phase5_container" in argv:
            output = json.dumps(
                {
                    "image_digest": f"sha256:{'b' * 64}",
                    "source_tag": operator._image_source_tag(_SOURCE),
                    "status": "passed",
                },
                separators=(",", ":"),
                sort_keys=True,
            ).encode()
        return subprocess.CompletedProcess(list(argv), 0, output, b"")

    monkeypatch.setattr(operator, "_verify_python_interpreter", verify_python)
    monkeypatch.setattr(operator, "_verify_terraform_binary", verify_terraform)
    runtime_identity = {
        "image_digest": f"sha256:{'b' * 64}",
        "infrastructure_revision": "c" * 64,
        "semantic_config_sha256": "d" * 64,
        "source_revision": _SOURCE,
        "vertex_prompt_sha256": "e" * 64,
        "vertex_prompt_version": "phase5-test",
    }

    operator._prepare_container_from_snapshot(
        source_root=source,
        source_revision=_SOURCE,
        source_date_epoch=1_787_032_800,
        artifact_output=state.root / "images" / "reconcile.oci.tar",
        runner=runner,
    )
    operator._prepare_terraform_from_snapshot(
        source_root=source,
        state_root=state.root,
        provider_mirror=None,
        runtime_identity=runtime_identity,
        runner=runner,
    )

    assert events == ["python", "runner", "python", "terraform", "runner"]
    container_argv, container_cwd, container_environment, container_timeout = calls[0]
    assert container_argv[:5] == (
        operator._PYTHON,
        "-P",
        "-S",
        "-m",
        "scripts.check_phase5_container",
    )
    assert container_cwd == source
    assert container_environment["PYTHONPATH"] == str(source)
    assert container_timeout == 7_200

    argv, cwd, environment, timeout = calls[1]
    assert argv[:5] == (
        operator._PYTHON,
        "-P",
        "-S",
        "-m",
        "scripts.check_phase5_terraform_plans",
    )
    assert cwd == source
    assert environment["PYTHONPATH"] == str(source)
    assert environment["TF_CLI_CONFIG_FILE"] == str(state.root / "terraform.rc")
    assert timeout == 7_200


def test_terraform_verifier_binds_root_binary_hash_and_empty_cli_config(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = tmp_path / "source"
    source.mkdir()
    cli_config = tmp_path / "terraform.rc"
    cli_config.write_bytes(b"")
    cli_config.chmod(0o400)
    binary_checks: list[tuple[Path, str, str]] = []
    calls: list[tuple[tuple[str, ...], dict[str, str], int]] = []

    def verify_binary(path: Path, digest: str, failure: str) -> None:
        binary_checks.append((path, digest, failure))

    def runner(
        argv: tuple[str, ...],
        *,
        cwd: Path,
        environment: dict[str, str] | Any,
        timeout_seconds: int,
    ) -> subprocess.CompletedProcess[bytes]:
        assert cwd == source
        calls.append((argv, dict(environment), timeout_seconds))
        return subprocess.CompletedProcess(
            list(argv), 0, b'{"terraform_version":"1.15.8"}', b""
        )

    monkeypatch.setattr(operator, "_verify_root_owned_binary", verify_binary)
    monkeypatch.setenv("TF_CLI_CONFIG_FILE", str(tmp_path / "ambient.rc"))
    operator._verify_terraform_binary(
        source,
        runner,
        cli_config=cli_config,
        timeout_seconds=5,
    )

    assert binary_checks == [
        (
            Path(operator._TERRAFORM),
            operator._TERRAFORM_SHA256,
            "TERRAFORM_BINARY_DRIFT",
        )
    ]
    argv, environment, timeout = calls[0]
    assert argv == (operator._TERRAFORM, "version", "-json")
    assert environment["TF_CLI_CONFIG_FILE"] == str(cli_config)
    assert str(tmp_path / "ambient.rc") not in environment.values()
    assert timeout == 5


def test_exact_main_drift_blocks_before_admission(tmp_path: Path) -> None:
    state, manifest, approval, _ = _records(tmp_path)

    with pytest.raises(operator.OperatorError, match="EXACT_MAIN_CHECK_FAILED"):
        operator.authorize_action(
            action=operator.Phase5Action.BOOTSTRAP_APPLY,
            manifest=manifest,
            approval=approval,
            state=state,
            repo_root=_REPO_ROOT,
            now=_NOW + timedelta(minutes=2),
            runner=_Runner(wrong_branch=True),
        )

    assert state.inspect()["unfinished_admission_sha256"] is None


def test_remote_main_drift_blocks_before_any_mutating_command(tmp_path: Path) -> None:
    state, manifest, approval, _ = _records(tmp_path)
    runner = _Runner(wrong_remote=True)

    with pytest.raises(operator.OperatorError, match="EXACT_MAIN_CHECK_FAILED"):
        operator.authorize_action(
            action=operator.Phase5Action.BOOTSTRAP_APPLY,
            manifest=manifest,
            approval=approval,
            state=state,
            repo_root=_REPO_ROOT,
            now=_NOW + timedelta(minutes=2),
            runner=runner,
        )

    assert _mutating_calls(runner) == []


def test_immutable_plan_byte_drift_blocks_before_mutation(tmp_path: Path) -> None:
    state, manifest, approval, runner = _records(tmp_path)
    plan = state.root / "plans" / "bootstrap-create.tfplan.json"
    plan.chmod(0o600)
    plan.write_bytes(b"tampered immutable plan")
    plan.chmod(0o400)

    with pytest.raises(operator.OperatorError, match="TERRAFORM_VARIABLES_INVALID"):
        operator.authorize_action(
            action=operator.Phase5Action.BOOTSTRAP_APPLY,
            manifest=manifest,
            approval=approval,
            state=state,
            repo_root=_REPO_ROOT,
            now=_NOW + timedelta(minutes=2),
            runner=runner,
        )

    assert _mutating_calls(runner) == []


def test_normalized_plan_and_iam_graph_drift_blocks_before_mutation(
    tmp_path: Path,
) -> None:
    state, manifest, approval, runner = _records(tmp_path)
    rendered = state.root / "plans" / "foundation-create.tfplan.json"
    rendered.chmod(0o600)
    payload = json.loads(rendered.read_bytes())
    payload["resource_changes"][0]["change"]["after"]["role"] = "roles/owner"
    rendered.write_text(json.dumps(payload), encoding="utf-8")
    rendered.chmod(0o400)

    with pytest.raises(operator.OperatorError, match="APPROVED_ARTIFACT_DRIFT"):
        operator.authorize_action(
            action=operator.Phase5Action.BOOTSTRAP_APPLY,
            manifest=manifest,
            approval=approval,
            state=state,
            repo_root=_REPO_ROOT,
            now=_NOW + timedelta(minutes=2),
            runner=runner,
        )

    assert _mutating_calls(runner) == []


@pytest.mark.parametrize(
    "action",
    (
        operator.Phase5Action.RUNTIME_TEARDOWN,
        operator.Phase5Action.FOUNDATION_TEARDOWN,
        operator.Phase5Action.STATE_PROTECTION_CHANGE,
        operator.Phase5Action.BOOTSTRAP_TEARDOWN,
    ),
)
def test_teardown_verifier_accepts_only_safe_live_subsets_and_empty_plans(
    tmp_path: Path,
    action: operator.Phase5Action,
) -> None:
    _, manifest, _, _ = _records(tmp_path)
    binding = manifest.terraform_plan_for(action)
    assert binding is not None
    qualification = _live_teardown_plan(
        json.loads(Path(binding.qualification_path).read_bytes())
    )

    subset = dict(qualification)
    subset["resource_changes"] = qualification["resource_changes"][:1]
    operator._verify_rendered_plan(
        json.dumps(subset, separators=(",", ":"), sort_keys=True).encode(),
        binding,
    )
    empty = dict(qualification)
    empty["resource_changes"] = []
    operator._verify_rendered_plan(
        json.dumps(empty, separators=(",", ":"), sort_keys=True).encode(),
        binding,
    )


@pytest.mark.parametrize("drift", ("extra", "action", "iam", "non-iam"))
def test_teardown_verifier_rejects_additions_action_and_attribute_drift(
    tmp_path: Path,
    drift: str,
) -> None:
    _, manifest, _, _ = _records(tmp_path)
    binding = manifest.terraform_plan_for(operator.Phase5Action.RUNTIME_TEARDOWN)
    assert binding is not None
    rendered = _live_teardown_plan(
        json.loads(Path(binding.qualification_path).read_bytes())
    )
    if drift == "extra":
        extra = json.loads(json.dumps(rendered["resource_changes"][1]))
        extra["address"] = "google_storage_bucket.unapproved"
        rendered["resource_changes"].append(extra)
    elif drift == "action":
        rendered["resource_changes"][0]["change"]["actions"] = ["create"]
    elif drift == "iam":
        rendered["resource_changes"][0]["change"]["before"]["role"] = "roles/owner"
    else:
        bucket = rendered["resource_changes"][1]["change"]
        attributes = bucket.get("before") or bucket.get("after")
        assert isinstance(attributes, dict)
        attributes["name"] = "different-unapproved-cloud-object"

    with pytest.raises(operator.OperatorError, match="EXECUTION_PLAN_DRIFT"):
        operator._verify_rendered_plan(
            json.dumps(rendered, separators=(",", ":"), sort_keys=True).encode(),
            binding,
        )


def test_teardown_verifier_tolerates_only_approved_provider_computed_fields(
    tmp_path: Path,
) -> None:
    _, manifest, _, _ = _records(tmp_path)
    binding = manifest.terraform_plan_for(operator.Phase5Action.RUNTIME_TEARDOWN)
    assert binding is not None
    rendered = _live_teardown_plan(
        json.loads(Path(binding.qualification_path).read_bytes())
    )
    rendered["resource_changes"][0]["change"]["before"]["name"] = (
        "different-provider-computed-iam-name"
    )
    rendered["resource_changes"][1]["change"]["before"]["id"] = (
        "different-provider-computed-bucket-id"
    )

    operator._verify_rendered_plan(
        json.dumps(rendered, separators=(",", ":"), sort_keys=True).encode(),
        binding,
    )


@pytest.mark.parametrize(
    ("mutation", "reason"),
    (
        ("malformed-sensitive", "TERRAFORM_PLAN_INVALID"),
        ("sensitive", "TERRAFORM_PLAN_INVALID"),
        ("delete-after-unknown", "TERRAFORM_PLAN_INVALID"),
        ("live-custom-unknown", "EXECUTION_PLAN_DRIFT"),
    ),
)
def test_teardown_verifier_rejects_malformed_sensitive_or_live_unknown_masks(
    tmp_path: Path,
    mutation: str,
    reason: str,
) -> None:
    _, manifest, _, _ = _records(tmp_path)
    binding = manifest.terraform_plan_for(operator.Phase5Action.RUNTIME_TEARDOWN)
    assert binding is not None
    rendered = _live_teardown_plan(
        json.loads(Path(binding.qualification_path).read_bytes())
    )
    change = rendered["resource_changes"][0]["change"]
    if mutation == "malformed-sensitive":
        change["before_sensitive"] = {"role": "not-a-mask"}
    elif mutation == "sensitive":
        change["before_sensitive"] = {"role": True}
    elif mutation == "delete-after-unknown":
        change["after_unknown"] = {"name": True}
    else:
        change["reconcile_before_unknown"] = {"unreported": True}

    with pytest.raises(operator.OperatorError, match=reason):
        operator._verify_rendered_plan(
            json.dumps(rendered, separators=(",", ":"), sort_keys=True).encode(),
            binding,
        )


def test_create_verifier_remains_exact_and_state_protection_cannot_apply(
    tmp_path: Path,
) -> None:
    _, manifest, _, _ = _records(tmp_path)
    create = manifest.terraform_plan_for(operator.Phase5Action.BOOTSTRAP_APPLY)
    assert create is not None
    rendered = json.loads(Path(create.qualification_path).read_bytes())
    rendered["resource_changes"] = rendered["resource_changes"][:1]
    with pytest.raises(operator.OperatorError, match="EXECUTION_PLAN_DRIFT"):
        operator._verify_rendered_plan(
            json.dumps(rendered, separators=(",", ":"), sort_keys=True).encode(),
            create,
        )

    rendered = json.loads(Path(create.qualification_path).read_bytes())
    bucket = rendered["resource_changes"][1]["change"]["after"]
    bucket["name"] = "different-unapproved-cloud-object"
    with pytest.raises(operator.OperatorError, match="EXECUTION_PLAN_DRIFT"):
        operator._verify_rendered_plan(
            json.dumps(rendered, separators=(",", ":"), sort_keys=True).encode(),
            create,
        )

    protection = manifest.command_for(operator.Phase5Action.STATE_PROTECTION_CHANGE)
    assert len(protection.commands) == 3
    assert "-destroy" in protection.commands[1]
    assert all("apply" not in command for command in protection.commands)


def test_oci_archive_drift_blocks_before_mutation(tmp_path: Path) -> None:
    state, manifest, approval, runner = _records(tmp_path)
    archive = state.root / "images" / "reconcile.oci.tar"
    archive.chmod(0o600)
    archive.write_bytes(archive.read_bytes() + b"tamper")
    archive.chmod(0o400)

    with pytest.raises(operator.OperatorError, match="APPROVED_ARTIFACT_DRIFT"):
        operator.authorize_action(
            action=operator.Phase5Action.BOOTSTRAP_APPLY,
            manifest=manifest,
            approval=approval,
            state=state,
            repo_root=_REPO_ROOT,
            now=_NOW + timedelta(minutes=2),
            runner=runner,
        )

    assert _mutating_calls(runner) == []


def test_preexisting_acceptance_artifact_blocks_before_command(
    tmp_path: Path,
) -> None:
    state, manifest, approval, runner = _records(tmp_path)
    path = operator._expected_acceptance_artifact_path(
        manifest=manifest,
        state_root=state.root,
        action=operator.Phase5Action.PROVIDER_ACCEPTANCE,
    )
    path.parent.mkdir(mode=0o700)
    path.write_bytes(b"preexisting")
    path.chmod(0o400)

    with pytest.raises(
        operator.OperatorError, match="ACCEPTANCE_ARTIFACT_ALREADY_EXISTS"
    ):
        operator.authorize_action(
            action=operator.Phase5Action.PROVIDER_ACCEPTANCE,
            manifest=manifest,
            approval=approval,
            state=state,
            repo_root=_REPO_ROOT,
            now=_NOW + timedelta(minutes=2),
            runner=runner,
        )

    assert ("/usr/bin/gcloud", "version", "--format=json") in runner.calls
    assert _mutating_calls(runner) == []


def test_acceptance_artifact_binding_is_mapped_into_operator_evidence(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from reconcile import phase5_hosted_acceptance as acceptance

    state, manifest, _, _ = _records(tmp_path)
    candidate = operator._acceptance_candidate(manifest)
    path = operator._expected_acceptance_artifact_path(
        manifest=manifest,
        state_root=state.root,
        action=operator.Phase5Action.PROVIDER_ACCEPTANCE,
    )
    record_sha256 = "d" * 64
    binding = acceptance.AcceptanceArtifactBinding(
        schema_version=acceptance.PHASE5_ACCEPTANCE_ARTIFACT_VERSION,
        mode=acceptance.AcceptanceMode.PROVIDER,
        path=str(path),
        record_sha256=record_sha256,
        file_sha256="e" * 64,
        byte_count=123,
    )

    class _Record:
        def __init__(self) -> None:
            self.candidate = candidate
            self.record_sha256 = record_sha256

    monkeypatch.setattr(
        acceptance,
        "read_acceptance_record",
        lambda *_args: (_Record(), binding),
    )

    observed = operator._capture_acceptance_artifact(
        manifest=manifest,
        state_root=state.root,
        action=operator.Phase5Action.PROVIDER_ACCEPTANCE,
    )

    assert observed == {
        "acceptance_mode": "provider",
        "acceptance_artifact_path": str(path),
        "acceptance_record_sha256": record_sha256,
        "acceptance_file_sha256": "e" * 64,
        "acceptance_byte_count": 123,
    }


def test_successful_acceptance_evidence_cannot_omit_artifact_binding() -> None:
    with pytest.raises(ValueError, match="requires one exact artifact"):
        operator._seal(
            operator.Phase5Evidence,
            schema_version="reconcile/phase5-operator/v1",
            record_type="evidence",
            manifest_sha256="a" * 64,
            approval_sha256="b" * 64,
            admission_sha256="c" * 64,
            outcome_sha256="d" * 64,
            action=operator.Phase5Action.PROVIDER_ACCEPTANCE,
            status=operator.OutcomeStatus.SUCCEEDED,
            observed_at=_NOW,
        )


def _copy_repo_inputs(destination: Path) -> Path:
    destination.mkdir()
    shutil.copytree(_REPO_ROOT / "reconcile", destination / "reconcile")
    shutil.copytree(_REPO_ROOT / "infra", destination / "infra")
    (destination / "scripts").mkdir()
    for relative in operator._EXECUTION_ROOT_FILES | operator._EXECUTION_SCRIPTS:
        source = _REPO_ROOT / relative
        target = destination / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, target)
    return destination


def test_mutable_worktree_drift_does_not_change_approved_execution_source(
    tmp_path: Path,
) -> None:
    repo_root = _copy_repo_inputs(tmp_path / "repo")
    operator_root = tmp_path / "operator"
    operator_root.mkdir()
    state, manifest, approval, runner = _records(operator_root, repo_root=repo_root)
    planner = repo_root / "reconcile" / "adk_planner.py"
    planner.write_text(planner.read_text(encoding="utf-8") + "\n", encoding="utf-8")

    admission = operator.authorize_action(
        action=operator.Phase5Action.BOOTSTRAP_APPLY,
        manifest=manifest,
        approval=approval,
        state=state,
        repo_root=repo_root,
        now=_NOW + timedelta(minutes=2),
        runner=runner,
    )

    assert admission.source_revision == manifest.source_revision
    assert _mutating_calls(runner) == []


def test_execution_snapshot_drift_blocks_before_mutation(tmp_path: Path) -> None:
    repo_root = _copy_repo_inputs(tmp_path / "repo")
    operator_root = tmp_path / "operator"
    operator_root.mkdir()
    state, manifest, approval, runner = _records(operator_root, repo_root=repo_root)
    source_root = Path(manifest.execution_source.root)
    lock = source_root / "infra" / "bootstrap" / ".terraform.lock.hcl"
    _rewrite_snapshot_file(
        source_root,
        "infra/bootstrap/.terraform.lock.hcl",
        lock.read_bytes().replace(b"7.44.0", b"7.45.0"),
    )

    with pytest.raises(operator.OperatorError, match="EXECUTION_SOURCE_COMMIT_DRIFT"):
        operator.authorize_action(
            action=operator.Phase5Action.BOOTSTRAP_APPLY,
            manifest=manifest,
            approval=approval,
            state=state,
            repo_root=repo_root,
            now=_NOW + timedelta(minutes=2),
            runner=runner,
        )

    assert _mutating_calls(runner) == []


def test_unfinished_admission_blocks_every_later_action(tmp_path: Path) -> None:
    state, manifest, approval, admission = _admit_bootstrap(tmp_path)

    with pytest.raises(operator.OperatorError, match="UNFINISHED_ADMISSION"):
        operator.authorize_action(
            action=operator.Phase5Action.RUNTIME_TEARDOWN,
            manifest=manifest,
            approval=approval,
            state=state,
            repo_root=_REPO_ROOT,
            now=_NOW + timedelta(minutes=3),
            runner=_Runner(source_root=Path(manifest.execution_source.root)),
        )

    assert state.inspect()["unfinished_admission_sha256"] == admission.record_sha256


def test_work_deadline_switches_to_teardown_only(tmp_path: Path) -> None:
    state, manifest, approval, runner = _records(tmp_path)
    teardown_time = manifest.work_deadline + timedelta(seconds=1)

    with pytest.raises(operator.OperatorError, match="TEARDOWN_ONLY_WINDOW"):
        operator.authorize_action(
            action=operator.Phase5Action.BOOTSTRAP_APPLY,
            manifest=manifest,
            approval=approval,
            state=state,
            repo_root=_REPO_ROOT,
            now=teardown_time,
            runner=runner,
        )

    admission = operator.authorize_action(
        action=operator.Phase5Action.RUNTIME_TEARDOWN,
        manifest=manifest,
        approval=approval,
        state=state,
        repo_root=_REPO_ROOT,
        now=teardown_time,
        runner=runner,
    )
    assert admission.action is operator.Phase5Action.RUNTIME_TEARDOWN


@pytest.mark.parametrize(
    "action",
    tuple(action for action in operator.Phase5Action if not action.is_teardown),
)
def test_any_teardown_attempt_permanently_blocks_non_teardown_actions(
    action: operator.Phase5Action,
) -> None:
    with pytest.raises(operator.OperatorError, match="TERMINAL_TEARDOWN_STARTED"):
        operator._validate_action_sequence(
            action,
            {operator.Phase5Action.RUNTIME_TEARDOWN},
            {
                operator.Phase5Action.BOOTSTRAP_APPLY,
                operator.Phase5Action.FOUNDATION_APPLY,
                operator.Phase5Action.IMAGE_PUSH,
            },
        )


def test_approval_expiry_blocks_teardown(tmp_path: Path) -> None:
    state, manifest, approval, _ = _records(tmp_path)

    with pytest.raises(operator.OperatorError, match="APPROVAL_EXPIRED"):
        operator.authorize_action(
            action=operator.Phase5Action.RUNTIME_TEARDOWN,
            manifest=manifest,
            approval=approval,
            state=state,
            repo_root=_REPO_ROOT,
            now=manifest.approval_expires_at,
            runner=_Runner(source_root=Path(manifest.execution_source.root)),
        )


@pytest.mark.parametrize(
    ("action", "deadline_field"),
    (
        (operator.Phase5Action.BOOTSTRAP_APPLY, "work_deadline"),
        (operator.Phase5Action.RUNTIME_TEARDOWN, "approval_expires_at"),
    ),
)
def test_command_cannot_finish_successfully_after_its_execution_deadline(
    tmp_path: Path,
    action: operator.Phase5Action,
    deadline_field: str,
) -> None:
    _, manifest, _, base_runner = _records(tmp_path)
    deadline = getattr(manifest, deadline_field)
    current = deadline - timedelta(seconds=5)
    observed_timeouts: list[int] = []

    def advancing_runner(
        argv: tuple[str, ...],
        *,
        cwd: Path,
        environment: dict[str, str] | Any,
        timeout_seconds: int,
    ) -> object:
        nonlocal current
        observed_timeouts.append(timeout_seconds)
        result = base_runner(
            argv,
            cwd=cwd,
            environment=environment,
            timeout_seconds=timeout_seconds,
        )
        current = deadline + timedelta(seconds=1)
        return result

    result = operator._run_descriptor_once(
        manifest.command_for(action),
        repo_root=Path(manifest.execution_source.root),
        execution_source=manifest.execution_source,
        runner=advancing_runner,
        image_artifact=manifest.image_artifact,
        terraform_plan=manifest.terraform_plan_for(action),
        python_dependencies=manifest.python_dependencies,
        deadline=deadline,
        clock=lambda: current,
    )

    assert not isinstance(result, subprocess.CompletedProcess)
    assert observed_timeouts == [5]


def test_apply_rechecks_deadline_after_execution_plan_verification(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _, manifest, _, runner = _records(tmp_path)
    action = operator.Phase5Action.BOOTSTRAP_APPLY
    plan = manifest.terraform_plan_for(action)
    assert plan is not None
    deadline = manifest.work_deadline
    current = deadline - timedelta(seconds=5)
    verification_calls = 0
    original = operator._verify_execution_plan

    def verify(path: Path, expected: operator.ExecutionPlanIdentity) -> None:
        nonlocal current, verification_calls
        original(path, expected)
        verification_calls += 1
        if verification_calls == 2:
            current = deadline

    monkeypatch.setattr(operator, "_verify_execution_plan", verify)
    result = operator._run_descriptor_once(
        manifest.command_for(action),
        repo_root=Path(manifest.execution_source.root),
        execution_source=manifest.execution_source,
        runner=runner,
        image_artifact=manifest.image_artifact,
        terraform_plan=plan,
        python_dependencies=manifest.python_dependencies,
        deadline=deadline,
        clock=lambda: current,
    )

    assert not isinstance(result, subprocess.CompletedProcess)
    assert verification_calls == 2
    assert not any("apply" in command for command in runner.calls)


def test_apply_rechecks_deadline_after_immediate_source_verification(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _, manifest, _, runner = _records(tmp_path)
    action = operator.Phase5Action.BOOTSTRAP_APPLY
    deadline = manifest.work_deadline
    current = deadline - timedelta(seconds=5)
    source_checks = 0
    original = operator._verify_execution_source_binding

    def verify(binding: operator.ExecutionSourceBinding) -> None:
        nonlocal current, source_checks
        original(binding)
        source_checks += 1
        if source_checks == 5:
            current = deadline

    monkeypatch.setattr(operator, "_verify_execution_source_binding", verify)
    result = operator._run_descriptor_once(
        manifest.command_for(action),
        repo_root=Path(manifest.execution_source.root),
        execution_source=manifest.execution_source,
        runner=runner,
        image_artifact=manifest.image_artifact,
        terraform_plan=manifest.terraform_plan_for(action),
        python_dependencies=manifest.python_dependencies,
        deadline=deadline,
        clock=lambda: current,
    )

    assert not isinstance(result, subprocess.CompletedProcess)
    assert source_checks == 5
    assert not any("apply" in command for command in runner.calls)


def test_success_is_not_sealed_after_the_execution_deadline(tmp_path: Path) -> None:
    state, manifest, approval, runner = _records(tmp_path)
    deadline = manifest.work_deadline
    clock_calls = 0

    def boundary_clock() -> datetime:
        nonlocal clock_calls
        clock_calls += 1
        return deadline - timedelta(seconds=1) if clock_calls <= 8 else deadline

    evidence = operator.execute_action(
        action=operator.Phase5Action.BOOTSTRAP_APPLY,
        manifest=manifest,
        approval=approval,
        state=state,
        repo_root=_REPO_ROOT,
        now=_NOW + timedelta(minutes=2),
        runner=runner,
        clock=boundary_clock,
    )

    assert evidence.status is operator.OutcomeStatus.UNKNOWN
    assert clock_calls == 10


def test_execution_records_only_output_hashes(tmp_path: Path) -> None:
    state, manifest, approval, _ = _records(tmp_path)
    secret_output = b"password=must-not-be-persisted"
    runner = _Runner(
        action_result=subprocess.CompletedProcess(
            ["fixed"], 0, secret_output, b"private diagnostic"
        )
    ).bind_source(Path(manifest.execution_source.root))

    evidence = operator.execute_action(
        action=operator.Phase5Action.BOOTSTRAP_APPLY,
        manifest=manifest,
        approval=approval,
        state=state,
        repo_root=_REPO_ROOT,
        now=_NOW + timedelta(minutes=2),
        runner=runner,
        clock=lambda: _NOW + timedelta(minutes=3),
    )

    assert evidence.status is operator.OutcomeStatus.SUCCEEDED
    persisted = b"".join(path.read_bytes() for path in state.root.glob("*.json"))
    assert secret_output not in persisted
    assert b"private diagnostic" not in persisted
    assert len(_mutating_calls(runner)) == 4
    source = Path(manifest.execution_source.root)
    mutating_cwds = [
        cwd
        for call, cwd in zip(runner.calls, runner.cwds, strict=True)
        if call in _mutating_calls(runner)
    ]
    assert mutating_cwds == [source, source, source, source]


@pytest.mark.parametrize(
    "runner",
    (
        _Runner(rendered_plan_drift=True),
        _Runner(tamper_execution_on_show=True),
    ),
)
def test_action_time_plan_drift_prevents_apply(tmp_path: Path, runner: _Runner) -> None:
    state, manifest, approval, _ = _records(tmp_path)
    runner.bind_source(Path(manifest.execution_source.root))

    evidence = operator.execute_action(
        action=operator.Phase5Action.BOOTSTRAP_APPLY,
        manifest=manifest,
        approval=approval,
        state=state,
        repo_root=_REPO_ROOT,
        now=_NOW + timedelta(minutes=2),
        runner=runner,
        clock=lambda: _NOW + timedelta(minutes=3),
    )

    assert evidence.status is operator.OutcomeStatus.UNKNOWN
    assert any("plan" in call for call in runner.calls)
    assert any(
        call[0] == operator._TERRAFORM and call[2:4] == ("show", "-json")
        for call in runner.calls
    )
    assert (
        sum(
            call[:4]
            == (
                "/usr/bin/gcloud",
                "services",
                "enable",
                "cloudresourcemanager.googleapis.com",
            )
            for call in runner.calls
        )
        == 1
    )
    assert not any("apply" in call for call in runner.calls)


def test_cloud_resource_manager_enable_failure_prevents_terraform_apply(
    tmp_path: Path,
) -> None:
    _, manifest, _, base_runner = _records(tmp_path)
    enable = manifest.command_for(operator.Phase5Action.BOOTSTRAP_APPLY).commands[0]
    observed: list[tuple[str, ...]] = []

    def runner(
        argv: tuple[str, ...],
        *,
        cwd: Path,
        environment: dict[str, str] | Any,
        timeout_seconds: int,
    ) -> object:
        observed.append(argv)
        if argv == enable:
            return subprocess.CompletedProcess(list(argv), 1, b"", b"unavailable")
        return base_runner(
            argv,
            cwd=cwd,
            environment=environment,
            timeout_seconds=timeout_seconds,
        )

    result = operator._run_descriptor_once(
        manifest.command_for(operator.Phase5Action.BOOTSTRAP_APPLY),
        repo_root=Path(manifest.execution_source.root),
        execution_source=manifest.execution_source,
        runner=runner,
        image_artifact=manifest.image_artifact,
        terraform_plan=manifest.terraform_plan_for(
            operator.Phase5Action.BOOTSTRAP_APPLY
        ),
        python_dependencies=manifest.python_dependencies,
        deadline=manifest.work_deadline,
        clock=lambda: _NOW + timedelta(minutes=3),
    )

    assert isinstance(result, subprocess.CompletedProcess)
    assert result.returncode == 1
    assert enable in observed
    assert not any(call[0] == operator._TERRAFORM for call in observed)


def test_loaded_image_descriptor_mismatch_prevents_push(tmp_path: Path) -> None:
    _, manifest, _, _ = _records(tmp_path)
    assert manifest.image_artifact.config_digest != manifest.image_digest
    runner = _Runner(image_id=manifest.image_artifact.config_digest)

    result = operator._run_descriptor_once(
        manifest.command_for(operator.Phase5Action.IMAGE_PUSH),
        repo_root=Path(manifest.execution_source.root),
        execution_source=manifest.execution_source,
        runner=runner,
        image_artifact=manifest.image_artifact,
        terraform_plan=None,
        python_dependencies=manifest.python_dependencies,
        deadline=manifest.work_deadline,
        clock=lambda: _NOW + timedelta(minutes=3),
    )

    assert not isinstance(result, subprocess.CompletedProcess)
    assert not any(
        call[:3] == (operator._DOCKER, "image", "push") for call in runner.calls
    )


@pytest.mark.parametrize("failure", ("missing", "mode", "symlink", "shape"))
def test_docker_credential_config_is_exact_private_and_nonsensitive(
    tmp_path: Path,
    failure: str,
) -> None:
    directory = tmp_path / "docker"
    directory.mkdir(mode=0o700)
    path = directory / "config.json"
    if failure == "symlink":
        target = tmp_path / "outside.json"
        target.write_text("{}", encoding="utf-8")
        path.symlink_to(target)
    elif failure != "missing":
        payload = (
            {"auths": {"us-central1-docker.pkg.dev": {"auth": "secret"}}}
            if failure == "shape"
            else {"credHelpers": {"us-central1-docker.pkg.dev": "gcloud"}}
        )
        path.write_text(json.dumps(payload), encoding="utf-8")
        path.chmod(0o644 if failure == "mode" else 0o600)

    with pytest.raises(operator.OperatorError, match="DOCKER_CONFIG_INVALID"):
        operator._verify_docker_credential_config(directory)


def test_image_push_proves_source_tag_resolves_to_remote_manifest_digest(
    tmp_path: Path,
) -> None:
    _, manifest, _, _ = _records(tmp_path)
    runner = _Runner(
        image_id=manifest.image_artifact.manifest_digest,
        remote_digest=manifest.image_digest,
    )

    result = operator._run_descriptor_once(
        manifest.command_for(operator.Phase5Action.IMAGE_PUSH),
        repo_root=Path(manifest.execution_source.root),
        execution_source=manifest.execution_source,
        runner=runner,
        image_artifact=manifest.image_artifact,
        terraform_plan=None,
        python_dependencies=manifest.python_dependencies,
        deadline=manifest.work_deadline,
        clock=lambda: _NOW + timedelta(minutes=3),
    )

    assert isinstance(result, subprocess.CompletedProcess)
    assert result.returncode == 0
    remote = runner.calls[-1]
    assert remote == (
        "/usr/bin/gcloud",
        "artifacts",
        "docker",
        "images",
        "describe",
        manifest.image_artifact.source_tag,
        "--project=reconcile-dev-260813-14fa6d",
        (
            "--impersonate-service-account=rec-p5-apply@"
            "reconcile-dev-260813-14fa6d.iam.gserviceaccount.com"
        ),
        "--format=value(image_summary.digest)",
        "--quiet",
    )


def test_remote_manifest_mismatch_fails_post_push_proof(tmp_path: Path) -> None:
    _, manifest, _, _ = _records(tmp_path)
    runner = _Runner(
        image_id=manifest.image_artifact.manifest_digest,
        remote_digest=manifest.image_artifact.config_digest,
    )

    result = operator._run_descriptor_once(
        manifest.command_for(operator.Phase5Action.IMAGE_PUSH),
        repo_root=Path(manifest.execution_source.root),
        execution_source=manifest.execution_source,
        runner=runner,
        image_artifact=manifest.image_artifact,
        terraform_plan=None,
        python_dependencies=manifest.python_dependencies,
        deadline=manifest.work_deadline,
        clock=lambda: _NOW + timedelta(minutes=3),
    )

    assert not isinstance(result, subprocess.CompletedProcess)
    assert any(call[:3] == (operator._DOCKER, "image", "push") for call in runner.calls)


def test_subprocess_environment_does_not_inherit_ambient_values(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("AMBIENT_SECRET", "must-not-propagate")
    assert os.environ["AMBIENT_SECRET"] == "must-not-propagate"
    state, manifest, approval, runner = _records(tmp_path)

    operator.execute_action(
        action=operator.Phase5Action.BOOTSTRAP_APPLY,
        manifest=manifest,
        approval=approval,
        state=state,
        repo_root=_REPO_ROOT,
        now=_NOW + timedelta(minutes=2),
        runner=runner,
        clock=lambda: _NOW + timedelta(minutes=3),
    )

    assert runner.environments
    assert all("AMBIENT_SECRET" not in value for value in runner.environments)
    base_environment = {
        "CLOUDSDK_CORE_DISABLE_PROMPTS",
        "GIT_TERMINAL_PROMPT",
        "HOME",
        "LANG",
        "LC_ALL",
        "PATH",
        "PYTHONDONTWRITEBYTECODE",
        "PYTHONNOUSERSITE",
        "TF_IN_AUTOMATION",
        "TF_INPUT",
    }
    assert all(
        frozenset(value)
        in {
            frozenset(base_environment),
            frozenset(base_environment | {"PYTHONPATH"}),
            frozenset(base_environment | {"TF_CLI_CONFIG_FILE"}),
            frozenset(base_environment | {"TF_CLI_CONFIG_FILE", "TF_DATA_DIR"}),
        }
        for value in runner.environments
    )


@pytest.mark.parametrize(
    ("runner", "reason"),
    [
        (
            _Runner(action_error=RuntimeError("credential=do-not-record")),
            "EXECUTION_EXCEPTION",
        ),
        (_Runner(action_result=object()), "INVALID_EXECUTION_RESULT"),
    ],
)
def test_exception_or_invalid_result_is_sanitized_unknown_without_retry(
    tmp_path: Path, runner: _Runner, reason: str
) -> None:
    state, manifest, approval, _ = _records(tmp_path)
    runner.bind_source(Path(manifest.execution_source.root))

    evidence = operator.execute_action(
        action=operator.Phase5Action.BOOTSTRAP_APPLY,
        manifest=manifest,
        approval=approval,
        state=state,
        repo_root=_REPO_ROOT,
        now=_NOW + timedelta(minutes=2),
        runner=runner,
        clock=lambda: _NOW + timedelta(minutes=3),
    )

    assert evidence.status is operator.OutcomeStatus.UNKNOWN
    action_calls = _mutating_calls(runner)
    assert len(action_calls) == 1
    outcome_path = next(state.root.glob("outcome-*.json"))
    outcome = json.loads(outcome_path.read_bytes())
    assert outcome["reason"] == reason
    assert outcome["return_code"] is None
    assert outcome["stdout_bytes"] == outcome["stderr_bytes"] == 0
    assert b"do-not-record" not in outcome_path.read_bytes()
    with pytest.raises(operator.OperatorError, match="ACTION_ALREADY_ATTEMPTED"):
        operator.authorize_action(
            action=operator.Phase5Action.BOOTSTRAP_APPLY,
            manifest=manifest,
            approval=approval,
            state=state,
            repo_root=_REPO_ROOT,
            now=_NOW + timedelta(minutes=4),
            runner=_Runner(source_root=Path(manifest.execution_source.root)),
        )


def test_every_action_execution_path_calls_the_one_authorization_guard(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _, manifest, approval, _ = _records(tmp_path)
    observed: list[operator.Phase5Action] = []

    class _CompletionSink:
        def complete(self, **values: object) -> None:
            assert set(values) == {"admission", "outcome", "evidence"}

    def fake_authorize(**values: Any) -> operator.Phase5Admission:
        action = values["action"]
        observed.append(action)
        return operator._seal(
            operator.Phase5Admission,
            schema_version="reconcile/phase5-operator/v1",
            record_type="admission",
            manifest_sha256=manifest.record_sha256,
            approval_sha256=approval.record_sha256,
            action=action,
            command_descriptor_sha256=manifest.command_for(action).descriptor_sha256,
            source_revision=manifest.source_revision,
            admitted_at=_NOW + timedelta(minutes=2),
        )

    monkeypatch.setattr(operator, "authorize_action", fake_authorize)
    for action in operator.Phase5Action:
        operator.execute_action(
            action=action,
            manifest=manifest,
            approval=approval,
            state=_CompletionSink(),  # type: ignore[arg-type]
            repo_root=_REPO_ROOT,
            now=_NOW + timedelta(minutes=2),
            runner=_Runner(),
            clock=lambda: _NOW + timedelta(minutes=3),
        )

    assert observed == list(operator.Phase5Action)
