"""Strict external deployment identity and sealed backend bindings."""

from __future__ import annotations

import hashlib
import json
import os
import stat
from pathlib import Path
from typing import Annotated, Any, Literal

from pydantic import Field, StringConstraints, model_validator

from reconcile.contracts.base import Sha256Digest, StrictModel

_PROFILE_SCHEMA = "reconcile/deployment-profile/v1"
_MAX_PROFILE_BYTES = 16_384
_MAX_BACKEND_BYTES = 4_096
_REGION = "us-central1"

ProjectId = Annotated[
    str,
    StringConstraints(
        min_length=6,
        max_length=30,
        pattern=r"^[a-z][a-z0-9-]{4,28}[a-z0-9]$",
    ),
]
ProjectNumber = Annotated[
    str,
    StringConstraints(min_length=6, max_length=20, pattern=r"^[1-9][0-9]{5,19}$"),
]
BillingAccountId = Annotated[
    str,
    StringConstraints(pattern=r"^[0-9A-F]{6}-[0-9A-F]{6}-[0-9A-F]{6}$"),
]
OwnerAccount = Annotated[
    str,
    StringConstraints(
        min_length=3,
        max_length=254,
        pattern=(
            r"^[a-z0-9.!#$%&'*+/=?^_`{|}~-]+@"
            r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?"
            r"(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$"
        ),
    ),
]
SafePath = Annotated[
    str,
    StringConstraints(min_length=1, max_length=4096, pattern=r"^[^\x00-\x1f\x7f]+$"),
]


class DeploymentProfileError(RuntimeError):
    """A stable refusal that does not echo private profile values."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


class DeploymentProfile(StrictModel):
    """The complete environment-specific input accepted by deployment tooling."""

    schema_version: Literal["reconcile/deployment-profile/v1"]
    project_id: ProjectId
    project_number: ProjectNumber
    billing_account_id: BillingAccountId
    owner_account: OwnerAccount

    @model_validator(mode="after")
    def _reject_public_placeholders(self) -> DeploymentProfile:
        if (
            self.project_id == "example-project-id"
            or self.project_number == "000000000000"
            or self.billing_account_id == "000000-000000-000000"
            or self.owner_account.endswith(".invalid")
        ):
            raise ValueError("deployment profile contains a public placeholder")
        return self


class RuntimeServiceAccounts(StrictModel):
    api: str
    canary: str
    controller: str
    fault_proxy: str
    sandbox: str


class RuntimeAudiences(StrictModel):
    api: str
    canary: str
    controller: str
    fault_proxy: str
    sandbox: str


class DeploymentIdentity(StrictModel):
    """Deterministic, manifest-private expansion of one deployment profile."""

    deployment_profile_sha256: Sha256Digest
    project_id: ProjectId
    project_number: ProjectNumber
    billing_account_id: BillingAccountId
    owner_account: OwnerAccount
    owner_principal: str
    region: Literal["us-central1"]
    state_bucket_name: str
    target_bucket_name: str
    apply_service_account_email: str
    runtime_service_accounts: RuntimeServiceAccounts
    audiences: RuntimeAudiences

    @model_validator(mode="after")
    def _validate_derivation(self) -> DeploymentIdentity:
        expected = resolve_deployment_identity(
            DeploymentProfile(
                schema_version=_PROFILE_SCHEMA,
                project_id=self.project_id,
                project_number=self.project_number,
                billing_account_id=self.billing_account_id,
                owner_account=self.owner_account,
            )
        )
        if self != expected:
            raise ValueError("deployment identity is not derived from its profile")
        return self


class DeploymentProfileBinding(StrictModel):
    path: SafePath
    sha256: Sha256Digest
    byte_count: Annotated[int, Field(ge=1, le=_MAX_PROFILE_BYTES)]
    device: Annotated[int, Field(ge=0)]
    inode: Annotated[int, Field(ge=1)]
    identity: DeploymentIdentity

    @model_validator(mode="after")
    def _validate_digest(self) -> DeploymentProfileBinding:
        if self.sha256 != self.identity.deployment_profile_sha256:
            raise ValueError("profile file and deployment identity digests differ")
        return self


class TerraformBackendBinding(StrictModel):
    stack: Literal["bootstrap", "foundation", "runtime"]
    kind: Literal["local", "gcs"]
    path: SafePath
    sha256: Sha256Digest
    byte_count: Annotated[int, Field(ge=1, le=_MAX_BACKEND_BYTES)]
    device: Annotated[int, Field(ge=0)]
    inode: Annotated[int, Field(ge=1)]

    @model_validator(mode="after")
    def _validate_kind(self) -> TerraformBackendBinding:
        expected = "local" if self.stack == "bootstrap" else "gcs"
        if self.kind != expected:
            raise ValueError("backend kind does not match its stack")
        return self


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise DeploymentProfileError("DEPLOYMENT_PROFILE_DUPLICATE_KEY")
        value[key] = item
    return value


def canonical_profile_bytes(profile: DeploymentProfile) -> bytes:
    return json.dumps(
        profile.model_dump(mode="json"),
        allow_nan=False,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


def parse_deployment_profile(data: bytes) -> DeploymentProfile:
    try:
        text = data.decode("utf-8")
        value = json.loads(text, object_pairs_hook=_reject_duplicate_keys)
        if not isinstance(value, dict):
            raise DeploymentProfileError("DEPLOYMENT_PROFILE_NOT_OBJECT")
        return DeploymentProfile.model_validate(value, strict=True)
    except DeploymentProfileError:
        raise
    except (UnicodeError, ValueError, TypeError) as error:
        raise DeploymentProfileError("DEPLOYMENT_PROFILE_INVALID") from error


def resolve_deployment_identity(profile: DeploymentProfile) -> DeploymentIdentity:
    digest = hashlib.sha256(canonical_profile_bytes(profile)).hexdigest()
    project = profile.project_id
    service_accounts = RuntimeServiceAccounts(
        api=f"rec-p5-api@{project}.iam.gserviceaccount.com",
        canary=f"rec-p5-canary@{project}.iam.gserviceaccount.com",
        controller=f"rec-p5-controller@{project}.iam.gserviceaccount.com",
        fault_proxy=f"rec-p5-fault@{project}.iam.gserviceaccount.com",
        sandbox=f"rec-p5-sandbox@{project}.iam.gserviceaccount.com",
    )
    origin = f"https://reconcile.invalid/phase5/{project}"
    return DeploymentIdentity.model_construct(
        deployment_profile_sha256=digest,
        project_id=project,
        project_number=profile.project_number,
        billing_account_id=profile.billing_account_id,
        owner_account=profile.owner_account,
        owner_principal=f"user:{profile.owner_account}",
        region=_REGION,
        state_bucket_name=f"{project}-p5-state",
        target_bucket_name=f"{project}-p5-target",
        apply_service_account_email=(f"rec-p5-apply@{project}.iam.gserviceaccount.com"),
        runtime_service_accounts=service_accounts,
        audiences=RuntimeAudiences(
            api=f"{origin}/api",
            canary=f"{origin}/canary",
            controller=f"{origin}/controller",
            fault_proxy=f"{origin}/fault-proxy",
            sandbox=f"{origin}/sandbox",
        ),
    )


def _read_profile_file(path: Path, *, required_mode: int) -> bytes:
    flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        raise DeploymentProfileError("DEPLOYMENT_PROFILE_UNAVAILABLE") from error
    try:
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != os.getuid()
            or stat.S_IMODE(metadata.st_mode) != required_mode
            or metadata.st_nlink != 1
            or not 1 <= metadata.st_size <= _MAX_PROFILE_BYTES
        ):
            raise DeploymentProfileError("DEPLOYMENT_PROFILE_NOT_PRIVATE")
        chunks: list[bytes] = []
        remaining = _MAX_PROFILE_BYTES + 1
        while remaining > 0:
            chunk = os.read(descriptor, min(16_384, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        data = b"".join(chunks)
        if len(data) > _MAX_PROFILE_BYTES:
            raise DeploymentProfileError("DEPLOYMENT_PROFILE_TOO_LARGE")
        after = os.fstat(descriptor)
        if (
            after.st_dev != metadata.st_dev
            or after.st_ino != metadata.st_ino
            or after.st_size != metadata.st_size
        ):
            raise DeploymentProfileError("DEPLOYMENT_PROFILE_CHANGED")
        return data
    finally:
        os.close(descriptor)


def _read_sealed_backend_file(path: Path) -> tuple[bytes, os.stat_result]:
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    except OSError as error:
        raise DeploymentProfileError("TERRAFORM_BACKEND_BINDING_UNAVAILABLE") from error
    try:
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != os.getuid()
            or stat.S_IMODE(metadata.st_mode) != 0o400
            or metadata.st_nlink != 1
            or not 1 <= metadata.st_size <= _MAX_BACKEND_BYTES
        ):
            raise DeploymentProfileError("TERRAFORM_BACKEND_BINDING_DRIFT")
        chunks: list[bytes] = []
        remaining = _MAX_BACKEND_BYTES + 1
        while remaining > 0:
            chunk = os.read(descriptor, remaining)
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        data = b"".join(chunks)
        after = os.fstat(descriptor)
        if (
            len(data) != metadata.st_size
            or len(data) > _MAX_BACKEND_BYTES
            or (after.st_dev, after.st_ino, after.st_size, after.st_mode)
            != (metadata.st_dev, metadata.st_ino, metadata.st_size, metadata.st_mode)
            or after.st_uid != metadata.st_uid
            or after.st_nlink != metadata.st_nlink
        ):
            raise DeploymentProfileError("TERRAFORM_BACKEND_BINDING_DRIFT")
        return data, after
    finally:
        os.close(descriptor)


def load_external_deployment_profile(
    path: Path,
    *,
    repo_root: Path,
) -> DeploymentProfile:
    if not path.is_absolute():
        raise DeploymentProfileError("DEPLOYMENT_PROFILE_PATH_NOT_ABSOLUTE")
    try:
        canonical = path.resolve(strict=True)
        repository = repo_root.resolve(strict=True)
    except OSError as error:
        raise DeploymentProfileError("DEPLOYMENT_PROFILE_UNAVAILABLE") from error
    if (
        canonical != path
        or canonical == repository
        or canonical.is_relative_to(repository)
    ):
        raise DeploymentProfileError("DEPLOYMENT_PROFILE_PATH_NOT_EXTERNAL")
    return parse_deployment_profile(_read_profile_file(canonical, required_mode=0o600))


def load_sealed_deployment_profile_file(
    path: Path,
    *,
    repo_root: Path,
) -> DeploymentProfile:
    if not path.is_absolute():
        raise DeploymentProfileError("DEPLOYMENT_PROFILE_PATH_NOT_ABSOLUTE")
    try:
        canonical = path.resolve(strict=True)
        repository = repo_root.resolve(strict=True)
    except OSError as error:
        raise DeploymentProfileError("DEPLOYMENT_PROFILE_UNAVAILABLE") from error
    if (
        canonical != path
        or canonical == repository
        or canonical.is_relative_to(repository)
    ):
        raise DeploymentProfileError("DEPLOYMENT_PROFILE_PATH_NOT_EXTERNAL")
    data = _read_profile_file(canonical, required_mode=0o400)
    profile = parse_deployment_profile(data)
    if data != canonical_profile_bytes(profile):
        raise DeploymentProfileError("SEALED_DEPLOYMENT_PROFILE_DRIFT")
    return profile


def _write_sealed_file(path: Path, payload: bytes) -> os.stat_result:
    try:
        descriptor = os.open(
            path,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW,
            0o600,
        )
    except FileExistsError as error:
        raise DeploymentProfileError("SEALED_DEPLOYMENT_ARTIFACT_EXISTS") from error
    except OSError as error:
        raise DeploymentProfileError(
            "SEALED_DEPLOYMENT_ARTIFACT_WRITE_FAILED"
        ) from error
    try:
        view = memoryview(payload)
        while view:
            written = os.write(descriptor, view)
            if written < 1:
                raise DeploymentProfileError("SEALED_DEPLOYMENT_ARTIFACT_WRITE_FAILED")
            view = view[written:]
        os.fchmod(descriptor, 0o400)
        os.fsync(descriptor)
        return os.fstat(descriptor)
    finally:
        os.close(descriptor)


def seal_deployment_profile(
    profile: DeploymentProfile,
    *,
    state_root: Path,
) -> DeploymentProfileBinding:
    directory = state_root / "bindings"
    path = directory / "deployment-profile.json"
    payload = canonical_profile_bytes(profile)
    metadata = _write_sealed_file(path, payload)
    directory_fd = os.open(
        directory,
        os.O_RDONLY | os.O_CLOEXEC | os.O_DIRECTORY | os.O_NOFOLLOW,
    )
    try:
        os.fsync(directory_fd)
    finally:
        os.close(directory_fd)
    identity = resolve_deployment_identity(profile)
    return DeploymentProfileBinding(
        path=str(path),
        sha256=identity.deployment_profile_sha256,
        byte_count=len(payload),
        device=metadata.st_dev,
        inode=metadata.st_ino,
        identity=identity,
    )


def capture_sealed_deployment_profile(
    *,
    state_root: Path,
) -> DeploymentProfileBinding:
    path = state_root / "bindings" / "deployment-profile.json"
    data = _read_profile_file(path, required_mode=0o400)
    profile = parse_deployment_profile(data)
    canonical = canonical_profile_bytes(profile)
    if data != canonical:
        raise DeploymentProfileError("SEALED_DEPLOYMENT_PROFILE_DRIFT")
    metadata = os.stat(path, follow_symlinks=False)
    identity = resolve_deployment_identity(profile)
    return DeploymentProfileBinding(
        path=str(path),
        sha256=identity.deployment_profile_sha256,
        byte_count=len(data),
        device=metadata.st_dev,
        inode=metadata.st_ino,
        identity=identity,
    )


def verify_sealed_deployment_profile(
    binding: DeploymentProfileBinding,
) -> DeploymentProfile:
    path = Path(binding.path)
    if not path.is_absolute() or path.resolve(strict=True) != path:
        raise DeploymentProfileError("SEALED_DEPLOYMENT_PROFILE_PATH_INVALID")
    data = _read_profile_file(path, required_mode=0o400)
    metadata = os.stat(path, follow_symlinks=False)
    profile = parse_deployment_profile(data)
    digest = hashlib.sha256(canonical_profile_bytes(profile)).hexdigest()
    if (
        data != canonical_profile_bytes(profile)
        or digest != binding.sha256
        or len(data) != binding.byte_count
        or metadata.st_dev != binding.device
        or metadata.st_ino != binding.inode
        or resolve_deployment_identity(profile) != binding.identity
    ):
        raise DeploymentProfileError("SEALED_DEPLOYMENT_PROFILE_DRIFT")
    return profile


def backend_config_bytes(
    stack: Literal["bootstrap", "foundation", "runtime"],
    *,
    state_root: Path,
    identity: DeploymentIdentity,
) -> bytes:
    if stack == "bootstrap":
        value = f'path = "{state_root / "state" / "bootstrap.tfstate"}"\n'
    else:
        value = (
            f'bucket = "{identity.state_bucket_name}"\n'
            f'impersonate_service_account = "{identity.apply_service_account_email}"\n'
        )
    return value.encode("utf-8")


def seal_backend_configs(
    *,
    state_root: Path,
    identity: DeploymentIdentity,
) -> tuple[TerraformBackendBinding, ...]:
    directory = state_root / "bindings" / "backends"
    bindings: list[TerraformBackendBinding] = []
    for stack in ("bootstrap", "foundation", "runtime"):
        path = directory / f"{stack}.tfbackend"
        payload = backend_config_bytes(stack, state_root=state_root, identity=identity)
        metadata = _write_sealed_file(path, payload)
        bindings.append(
            TerraformBackendBinding(
                stack=stack,
                kind="local" if stack == "bootstrap" else "gcs",
                path=str(path),
                sha256=hashlib.sha256(payload).hexdigest(),
                byte_count=len(payload),
                device=metadata.st_dev,
                inode=metadata.st_ino,
            )
        )
    directory_fd = os.open(
        directory,
        os.O_RDONLY | os.O_CLOEXEC | os.O_DIRECTORY | os.O_NOFOLLOW,
    )
    try:
        os.fsync(directory_fd)
    finally:
        os.close(directory_fd)
    return tuple(bindings)


def capture_backend_configs(
    *,
    state_root: Path,
    identity: DeploymentIdentity,
) -> tuple[TerraformBackendBinding, ...]:
    bindings: list[TerraformBackendBinding] = []
    for stack in ("bootstrap", "foundation", "runtime"):
        path = state_root / "bindings" / "backends" / f"{stack}.tfbackend"
        data, metadata = _read_sealed_backend_file(path)
        expected = backend_config_bytes(
            stack,
            state_root=state_root,
            identity=identity,
        )
        binding = TerraformBackendBinding(
            stack=stack,
            kind="local" if stack == "bootstrap" else "gcs",
            path=str(path),
            sha256=hashlib.sha256(data).hexdigest(),
            byte_count=len(data),
            device=metadata.st_dev,
            inode=metadata.st_ino,
        )
        verify_backend_binding(binding, state_root=state_root, identity=identity)
        if data != expected:
            raise DeploymentProfileError("TERRAFORM_BACKEND_BINDING_DRIFT")
        bindings.append(binding)
    return tuple(bindings)


def verify_backend_binding(
    binding: TerraformBackendBinding,
    *,
    state_root: Path,
    identity: DeploymentIdentity,
) -> None:
    path = Path(binding.path)
    expected_path = state_root / "bindings" / "backends" / f"{binding.stack}.tfbackend"
    data, metadata = _read_sealed_backend_file(path)
    expected = backend_config_bytes(
        binding.stack,
        state_root=state_root,
        identity=identity,
    )
    if (
        path != expected_path
        or path.resolve(strict=True) != path
        or metadata.st_size != binding.byte_count
        or metadata.st_dev != binding.device
        or metadata.st_ino != binding.inode
        or data != expected
        or hashlib.sha256(data).hexdigest() != binding.sha256
    ):
        raise DeploymentProfileError("TERRAFORM_BACKEND_BINDING_DRIFT")


__all__ = [
    "DeploymentIdentity",
    "DeploymentProfile",
    "DeploymentProfileBinding",
    "DeploymentProfileError",
    "RuntimeAudiences",
    "RuntimeServiceAccounts",
    "TerraformBackendBinding",
    "backend_config_bytes",
    "canonical_profile_bytes",
    "capture_backend_configs",
    "capture_sealed_deployment_profile",
    "load_external_deployment_profile",
    "load_sealed_deployment_profile_file",
    "parse_deployment_profile",
    "resolve_deployment_identity",
    "seal_backend_configs",
    "seal_deployment_profile",
    "verify_backend_binding",
    "verify_sealed_deployment_profile",
]
