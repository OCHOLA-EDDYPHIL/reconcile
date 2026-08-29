"""Fail-closed Phase 5 approval, admission, and evidence tooling.

The default CLI operation is local inspection.  Explicit execution is admitted
only against an immutable manifest and approval, and every admitted command is
recorded before it is started.
"""

from __future__ import annotations

import argparse
import ast
import fcntl
import gzip
import hashlib
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import tarfile
import time
import zlib
from collections.abc import Callable, Iterator, Mapping, Sequence
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from pathlib import Path, PurePosixPath
from typing import Annotated, Any, Literal, Protocol
from uuid import uuid4

from pydantic import Field, JsonValue, StringConstraints, model_validator

from reconcile import phase5_hosted_acceptance as _acceptance
from reconcile.contracts.base import AwareDatetime, Sha256Digest, StrictModel
from reconcile.evidence.recovery_rules import deterministic_stage_revision

_SCHEMA = "reconcile/phase5-operator/v1"
_PROJECT_ID = "example-project-id"
_PROJECT_NUMBER = "000000000000"
_REGION = "us-central1"
_ORIGIN_URL = "git@github.com:OCHOLA-EDDYPHIL/reconcile.git"
_OWNER = "user:owner@example.invalid"
_OWNER_ACCOUNT = "owner@example.invalid"
_STATE_BUCKET = f"{_PROJECT_ID}-p5-state"
_EMPTY_STATE_BUCKET_CLEANUP_STDERR = (
    "Removing objects:\n"
    "ERROR: (gcloud.storage.rm) The following URLs matched no objects or files:\n"
    f"gs://{_STATE_BUCKET}/**\n"
).encode("ascii")
_OPERATOR_SERVICE_ACCOUNT = "rec-p5-apply@example-project-id.iam.gserviceaccount.com"
_OPERATOR_PRINCIPAL = f"serviceAccount:{_OPERATOR_SERVICE_ACCOUNT}"
_TERRAFORM_VERSION = "1.15.8"
_GCLOUD_VERSION = "580.0.0"
_GOOGLE_PROVIDER_SOURCE = "registry.terraform.io/hashicorp/google"
_GOOGLE_PROVIDER_VERSION = "7.44.0"
_TERRAFORM_BUILTIN_PROVIDER_SOURCE = "terraform.io/builtin/terraform"
_GEMINI_MODEL = "gemini-3.5-flash"
_VERTEX_LOCATION = "us"
_AUTHORIZATION_ESTIMATE = "3.892942"
_CONTINGENCY_AUTHORIZATION_ESTIMATE = "4.866178"
_WORK_WINDOW = timedelta(hours=8)
_TEARDOWN_WINDOW = timedelta(hours=2)
_MAX_RECORD_BYTES = 1_048_576
_MAX_OUTPUT_BYTES = 1_048_576
_MAX_PLAN_JSON_BYTES = 32 * 1_048_576
_MAX_ARTIFACT_BYTES = 4 * 1_073_741_824
_EMPTY_SHA256 = hashlib.sha256(b"").hexdigest()
_RECORD_NAME_PATTERN = re.compile(r"^[a-z0-9][a-z0-9-]{0,191}[.]json$")
_SHA256_PATTERN = re.compile(r"^[0-9a-f]{64}$")
_TERRAFORM = "/usr/local/libexec/reconcile/terraform-1.15.8"
_TERRAFORM_SHA256 = "8b6cb96cd46080ee1287baf646c70078715a99123b9b3a6ce2a7fe3892ec703a"
_DOCKER = "/usr/local/libexec/reconcile/docker-29.6.2"
_DOCKER_SHA256 = "dda0804fca9b37a16e688356049ddf51fdd4c1a435c0a41055ec81cdf121535a"
_DOCKER_HOST = "unix:///var/lib/reconcile-phase5-operator/run/docker.sock"
_DOCKER_CREDENTIAL_GCLOUD = "/usr/lib/google-cloud-sdk/bin/docker-credential-gcloud"
_DOCKER_CREDENTIAL_GCLOUD_SHA256 = (
    "12fe4830c186064fb2202a96058a3abd4abf8a8a17bafead45054a7068019179"
)
_GIT = "/usr/bin/git"
_GIT_SHA256 = "2a8c18fbf43da9f692d75474c72bea9dfd796c260b0f3dfe456376abc3bbd668"
_GIT_VERSION = "2.43.0"
_PYTHON = "/usr/local/libexec/reconcile/python-3.12.13/bin/python3.12"
_PYTHON_SHA256 = "021044895e95be79dc2f110367607e684119afbc8ce75f6f0eec94844e0acec7"
_PYTHON_VERSION = "3.12.13"
_OPERATOR_HOME = "/opt/reconcile"
_OCI_REFERENCE_ANNOTATION = "org.opencontainers.image.ref.name"
_LEGACY_IMAGE_ID_SOURCE_REVISIONS = frozenset(
    {"e7ccaab5268d31172b3a5efa5e754b0beb3b1a79"}
)
_LEGACY_STATE_BUCKET_CLEANUP_SOURCE_REVISIONS = frozenset(
    {
        "e7ccaab5268d31172b3a5efa5e754b0beb3b1a79",
        "bab63ed6ec64e068fb0734a436cce3626c5f18c3",
        "dd8713fcb892049a4c07824e7dcec46c3708c480",
    }
)
_LEGACY_BOOTSTRAP_PROTECTION_UPDATE_SOURCE_REVISIONS = frozenset(
    {"33954ba1f117ad49b01b0c7de7d2a8da025f2144"}
)
_OUTPUT_BUDGET_MIGRATION_PREDECESSOR_MANIFEST_SHA256 = (
    "06f5c2af8e26fe9b23944949270c8a9dc99ce09ba80636cbca1e34f7e9230f04"
)
_OUTPUT_BUDGET_MIGRATION_PREDECESSOR_SOURCE_REVISION = (
    "8b757de0d0087ea79c66714575949b0d0a1a9b03"
)
_OUTPUT_BUDGET_MIGRATION_PYTHON_PATHS = frozenset(
    {
        "reconcile/adk_planner.py",
        "reconcile/hosted/config.py",
        "reconcile/hosted/provider.py",
        "reconcile/hosted/runtime.py",
        "reconcile/phase5_hosted_acceptance.py",
        "reconcile/phase5_operator.py",
    }
)
_OUTPUT_BUDGET_MIGRATION_EXTERNAL_PATHS = frozenset(
    {
        "infra/environments/dev/runtime/cloud_run.tf",
        "infra/environments/dev/runtime/locals.tf",
        "scripts/check_phase5_container.py",
        "scripts/check_phase5_terraform_plans.py",
    }
)
_OUTPUT_BUDGET_MIGRATION_TERRAFORM_PATHS = frozenset(
    {
        "infra/environments/dev/runtime/cloud_run.tf",
        "infra/environments/dev/runtime/locals.tf",
    }
)
_PROJECT_DEPENDENCY_RECORD_PATH = "reconcile-0.1.0.dist-info/RECORD"

_EXECUTION_ROOT_FILES = frozenset(
    {".dockerignore", "Dockerfile", "pyproject.toml", "uv.lock"}
)
_EXECUTION_TREE_PREFIXES = ("reconcile/", "infra/")
_EXECUTION_SCRIPTS = frozenset(
    {
        "scripts/check_phase5_container.py",
        "scripts/check_phase5_hosted_acceptance.py",
        "scripts/check_phase5_terraform_plans.py",
        "scripts/phase5_operator.py",
    }
)
_EXECUTION_REQUIRED_PATHS = _EXECUTION_ROOT_FILES | _EXECUTION_SCRIPTS
_FORBIDDEN_TOP_LEVEL_SOURCE_ROOTS = frozenset(
    {"artifacts", "docs", "evidence", "qualification", "tests"}
)
_EXECUTION_GIT_PATHS = (
    ".dockerignore",
    "Dockerfile",
    "pyproject.toml",
    "uv.lock",
    "reconcile",
    "infra",
    *tuple(sorted(_EXECUTION_SCRIPTS)),
)
_MAX_EXECUTION_SOURCE_FILE_BYTES = 16 * 1_048_576
_MAX_EXECUTION_SOURCE_FILES = 4_096
_PYTHON_DEPENDENCY_PREFIX = PurePosixPath("opt/reconcile/lib/python3.12/site-packages")
_MAX_PYTHON_DEPENDENCY_FILES = 20_000
_MAX_PYTHON_DEPENDENCY_ENTRIES = 20_000
_MAX_PYTHON_DEPENDENCY_BYTES = 512 * 1_048_576
_MAX_OCI_LAYER_BLOB_BYTES = 512 * 1_048_576
_MAX_OCI_LAYER_TAR_BYTES = 640 * 1_048_576
_MAX_OCI_LAYER_UNCOMPRESSED_BYTES = 512 * 1_048_576
_MAX_OCI_LAYER_MEMBERS = 65_536
_MAX_OCI_ARCHIVE_MEMBERS = 256
_MAX_OCI_IMAGE_LAYERS = 32
_MAX_OCI_AGGREGATE_LAYER_BLOB_BYTES = 512 * 1_048_576
_MAX_OCI_AGGREGATE_UNCOMPRESSED_BYTES = 1_024 * 1_048_576
_MAX_OCI_AGGREGATE_TAR_BYTES = 1_024 * 1_048_576
_MAX_OCI_AGGREGATE_MEMBERS = 65_536
_MAX_OCI_PATH_COMPONENTS = 64

_STACK_ROOTS = {
    "bootstrap": "infra/bootstrap",
    "foundation": "infra/environments/dev/foundation",
    "runtime": "infra/environments/dev/runtime",
}
_FOUNDATION_INIT_COMMAND = (
    _TERRAFORM,
    f"-chdir={_STACK_ROOTS['foundation']}",
    "init",
    "-input=false",
    "-lockfile=readonly",
    "-no-color",
)
_FOUNDATION_INIT_RETRY_DELAYS_SECONDS = (5, 10, 20, 30, 45, 60, 60)
_PLAN_FILES = {
    "bootstrap-apply": ("bootstrap", "bootstrap-create"),
    "foundation-apply": ("foundation", "foundation-create"),
    "runtime-apply": ("runtime", "runtime-create"),
    "runtime-teardown": ("runtime", "runtime-destroy"),
    "foundation-teardown": ("foundation", "foundation-destroy"),
    "state-protection-change": (
        "bootstrap",
        "bootstrap-disable-protection",
    ),
    "bootstrap-teardown": ("bootstrap", "bootstrap-destroy"),
}

GitRevision = Annotated[str, StringConstraints(pattern=r"^[0-9a-f]{40}$")]
GitObjectId = Annotated[str, StringConstraints(pattern=r"^[0-9a-f]{40}$")]
ImageDigest = Annotated[str, StringConstraints(pattern=r"^sha256:[0-9a-f]{64}$")]
Principal = Annotated[
    str,
    StringConstraints(
        min_length=3,
        max_length=256,
        pattern=r"^(?:user|serviceAccount):[A-Za-z0-9._%+@-]+$",
    ),
]
SafeArgument = Annotated[
    str,
    StringConstraints(min_length=1, max_length=4096, pattern=r"^[^\x00-\x1f\x7f]+$"),
]
RecordName = Annotated[
    str, StringConstraints(pattern=r"^[a-z0-9][a-z0-9-]{0,191}[.]json$")
]


class OperatorError(RuntimeError):
    """A fixed, non-sensitive operator refusal."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


class Phase5Action(StrEnum):
    """The complete closed set of separately admitted Phase 5 actions."""

    BOOTSTRAP_APPLY = "bootstrap-apply"
    FOUNDATION_APPLY = "foundation-apply"
    IMAGE_PUSH = "image-push"
    RUNTIME_APPLY = "runtime-apply"
    PROVIDER_ACCEPTANCE = "provider-acceptance"
    HOSTED_ACCEPTANCE = "hosted-acceptance"
    RUNTIME_TEARDOWN = "runtime-teardown"
    FOUNDATION_TEARDOWN = "foundation-teardown"
    STATE_PROTECTION_CHANGE = "state-protection-change"
    BOOTSTRAP_TEARDOWN = "bootstrap-teardown"

    @property
    def is_teardown(self) -> bool:
        return self in {
            self.RUNTIME_TEARDOWN,
            self.FOUNDATION_TEARDOWN,
            self.STATE_PROTECTION_CHANGE,
            self.BOOTSTRAP_TEARDOWN,
        }


class OutcomeStatus(StrEnum):
    SUCCEEDED = "SUCCEEDED"
    FAILED = "FAILED"
    UNKNOWN = "UNKNOWN"


_INITIAL_CONTINUATION_ACTIONS = (
    Phase5Action.BOOTSTRAP_APPLY,
    Phase5Action.FOUNDATION_APPLY,
)
_TEARDOWN_CONTINUATION_ACTIONS = (
    Phase5Action.BOOTSTRAP_APPLY,
    Phase5Action.FOUNDATION_APPLY,
    Phase5Action.IMAGE_PUSH,
    Phase5Action.RUNTIME_APPLY,
    Phase5Action.PROVIDER_ACCEPTANCE,
    Phase5Action.HOSTED_ACCEPTANCE,
    Phase5Action.RUNTIME_TEARDOWN,
    Phase5Action.FOUNDATION_TEARDOWN,
)
_BOOTSTRAP_CONTINUATION_ACTIONS = (
    *_TEARDOWN_CONTINUATION_ACTIONS,
    Phase5Action.STATE_PROTECTION_CHANGE,
)


class OutcomeReason(StrEnum):
    COMMAND_SUCCEEDED = "COMMAND_SUCCEEDED"
    COMMAND_FAILED = "COMMAND_FAILED"
    EXECUTION_EXCEPTION = "EXECUTION_EXCEPTION"
    INVALID_EXECUTION_RESULT = "INVALID_EXECUTION_RESULT"


class ExposureBinding(StrictModel):
    service: Literal["api", "controller", "fault-proxy", "sandbox"]
    audience: SafeArgument
    allowed_callers: tuple[Principal, ...]


class EnvironmentBinding(StrictModel):
    name: Annotated[str, StringConstraints(pattern=r"^[A-Z][A-Z0-9_]{0,127}$")]
    value: SafeArgument

    @model_validator(mode="after")
    def _reject_secret_environment_names(self) -> EnvironmentBinding:
        tokens = set(self.name.casefold().split("_"))
        if tokens.intersection(
            {"authorization", "credential", "password", "secret", "token"}
        ):
            raise ValueError("secret-bearing environment names are forbidden")
        return self


class CommandDescriptor(StrictModel):
    action: Phase5Action
    commands: tuple[tuple[SafeArgument, ...], ...]
    environment: tuple[EnvironmentBinding, ...] = ()
    timeout_seconds: Annotated[int, Field(ge=1, le=14_400)]
    descriptor_sha256: Sha256Digest

    @model_validator(mode="after")
    def _validate_descriptor(self) -> CommandDescriptor:
        if (
            not self.commands
            or any(not command for command in self.commands)
            or not 1 <= self.timeout_seconds <= 14_400
        ):
            raise ValueError("command descriptor is outside fixed bounds")
        names = tuple(item.name for item in self.environment)
        if len(names) != len(set(names)):
            raise ValueError("environment names must be unique")
        shell_names = {
            "bash",
            "/bin/bash",
            "sh",
            "/bin/sh",
            "zsh",
            "/bin/zsh",
        }
        if any(command[0] in shell_names for command in self.commands):
            raise ValueError("shell command descriptors are forbidden")
        if self.descriptor_sha256 != _hash_model_without(self, "descriptor_sha256"):
            raise ValueError("command descriptor hash mismatch")
        return self


class ExecutionSourceFileBinding(StrictModel):
    path: SafeArgument
    git_mode: Literal["100644", "100755"]
    git_object_id: GitObjectId
    byte_count: Annotated[int, Field(ge=0, le=_MAX_EXECUTION_SOURCE_FILE_BYTES)]
    sha256: Sha256Digest

    @model_validator(mode="after")
    def _validate_path(self) -> ExecutionSourceFileBinding:
        if not _execution_path_allowed(self.path):
            raise ValueError("execution source path is outside the closed allowlist")
        return self


class ExecutionSourceBinding(StrictModel):
    root: SafeArgument
    source_revision: GitRevision
    source_date_epoch: Annotated[int, Field(ge=1, le=2**63 - 1)]
    files: tuple[ExecutionSourceFileBinding, ...] = Field(
        min_length=1,
        max_length=_MAX_EXECUTION_SOURCE_FILES,
    )
    sha256: Sha256Digest

    @model_validator(mode="after")
    def _validate_source(self) -> ExecutionSourceBinding:
        paths = tuple(item.path for item in self.files)
        if (
            paths != tuple(sorted(paths))
            or len(paths) != len(set(paths))
            or not _EXECUTION_REQUIRED_PATHS.issubset(paths)
        ):
            raise ValueError("execution source inventory is not closed-world")
        aggregate = {
            "source_revision": self.source_revision,
            "source_date_epoch": self.source_date_epoch,
            "files": [item.model_dump(mode="json") for item in self.files],
        }
        if self.sha256 != _hash_value(aggregate):
            raise ValueError("execution source aggregate hash mismatch")
        return self


class PythonDependencyBinding(StrictModel):
    root: SafeArgument
    source_image_digest: ImageDigest
    source_archive_sha256: Sha256Digest
    python_lock_sha256: Sha256Digest
    file_count: Annotated[int, Field(ge=1, le=_MAX_PYTHON_DEPENDENCY_FILES)]
    entry_count: Annotated[int, Field(ge=1, le=_MAX_PYTHON_DEPENDENCY_ENTRIES)]
    byte_count: Annotated[int, Field(ge=1, le=_MAX_PYTHON_DEPENDENCY_BYTES)]
    sha256: Sha256Digest


class SourceFileBinding(StrictModel):
    path: SafeArgument
    sha256: Sha256Digest


class SourceGroupBinding(StrictModel):
    name: SafeArgument
    files: tuple[SourceFileBinding, ...]
    sha256: Sha256Digest

    @model_validator(mode="after")
    def _validate_group(self) -> SourceGroupBinding:
        paths = tuple(item.path for item in self.files)
        if not paths or paths != tuple(sorted(paths)) or len(paths) != len(set(paths)):
            raise ValueError("source files must be nonempty, unique, and sorted")
        if self.sha256 != _hash_value(
            [item.model_dump(mode="json") for item in self.files]
        ):
            raise ValueError("source group hash mismatch")
        return self


class TerraformStackBinding(StrictModel):
    stack: Literal["bootstrap", "foundation", "runtime"]
    source_root: SafeArgument
    sources: SourceGroupBinding
    lock_sha256: Sha256Digest

    @model_validator(mode="after")
    def _validate_stack(self) -> TerraformStackBinding:
        expected_root = _STACK_ROOTS[self.stack]
        expected_lock = f"{expected_root}/.terraform.lock.hcl"
        hashes = {item.path: item.sha256 for item in self.sources.files}
        if (
            self.source_root != expected_root
            or self.sources.name != f"terraform-{self.stack}"
            or hashes.get(expected_lock) != self.lock_sha256
        ):
            raise ValueError("Terraform stack source binding mismatch")
        return self


class PlanResourceBinding(StrictModel):
    address: SafeArgument
    resource_type: SafeArgument
    provider_name: SafeArgument
    actions: tuple[SafeArgument, ...]
    before_sha256: Sha256Digest
    after_sha256: Sha256Digest
    before_projection: JsonValue
    before_unknown: JsonValue | None = None


class PlanIamBinding(StrictModel):
    address: SafeArgument
    resource_type: SafeArgument
    actions: tuple[SafeArgument, ...]
    role: SafeArgument | None
    member: SafeArgument | None
    after_sha256: Sha256Digest
    authority_projection: JsonValue
    authority_unknown: JsonValue | None = None


class TerraformPlanBinding(StrictModel):
    action: Phase5Action
    stack: Literal["bootstrap", "foundation", "runtime"]
    qualification_path: SafeArgument
    qualification_sha256: Sha256Digest
    variables_path: SafeArgument
    variables_sha256: Sha256Digest
    execution_plan_path: SafeArgument
    normalized_plan_sha256: Sha256Digest
    resource_inventory_sha256: Sha256Digest
    iam_inventory_sha256: Sha256Digest
    resources: tuple[PlanResourceBinding, ...]
    iam_edges: tuple[PlanIamBinding, ...]

    @model_validator(mode="after")
    def _validate_plan(self) -> TerraformPlanBinding:
        if self.action.value not in _PLAN_FILES:
            raise ValueError("action has no immutable Terraform plan")
        expected_stack, expected_stem = _PLAN_FILES[self.action.value]
        if (
            self.stack != expected_stack
            or Path(self.qualification_path).name != f"{expected_stem}.tfplan.json"
            or Path(self.variables_path).name != f"{expected_stem}.tfvars.json"
            or Path(self.execution_plan_path).name != f"{expected_stem}.tfplan"
        ):
            raise ValueError("Terraform plan artifacts do not match their action")
        if self.resources != tuple(
            sorted(self.resources, key=lambda item: item.address)
        ) or len({item.address for item in self.resources}) != len(self.resources):
            raise ValueError("resource inventory must be unique and sorted")
        if self.iam_edges != tuple(
            sorted(self.iam_edges, key=lambda item: item.address)
        ) or len({item.address for item in self.iam_edges}) != len(self.iam_edges):
            raise ValueError("IAM inventory must be unique and sorted")
        if self.resource_inventory_sha256 != _hash_value(
            [item.model_dump(mode="json") for item in self.resources]
        ):
            raise ValueError("resource inventory hash mismatch")
        if self.iam_inventory_sha256 != _hash_value(
            [item.model_dump(mode="json") for item in self.iam_edges]
        ):
            raise ValueError("IAM inventory hash mismatch")
        return self


class ImageArtifactBinding(StrictModel):
    archive_path: SafeArgument
    archive_sha256: Sha256Digest
    source_tag: SafeArgument
    manifest_digest: ImageDigest
    config_digest: ImageDigest
    immutable_reference: SafeArgument


class Phase5ManifestDraft(StrictModel):
    """Canonical, secret-free input used to seal one exact manifest."""

    schema_version: Literal["reconcile/phase5-operator-draft/v1"]
    source_revision: GitRevision
    image_digest: ImageDigest
    created_at: AwareDatetime
    work_deadline: AwareDatetime
    approval_expires_at: AwareDatetime

    @model_validator(mode="after")
    def _validate_window(self) -> Phase5ManifestDraft:
        if self.work_deadline - self.created_at != _WORK_WINDOW:
            raise ValueError("the work deadline must be exactly eight hours")
        if self.approval_expires_at - self.work_deadline != _TEARDOWN_WINDOW:
            raise ValueError("the teardown-only window must be exactly two hours")
        return self


class _HasRecordHash(StrictModel):
    record_sha256: Sha256Digest

    @model_validator(mode="after")
    def _validate_record_hash(self) -> _HasRecordHash:
        if self.record_sha256 != _hash_model_without(self, "record_sha256"):
            raise ValueError("record hash mismatch")
        return self


class Phase5ApprovalManifest(_HasRecordHash):
    schema_version: Literal["reconcile/phase5-operator/v1"] = _SCHEMA
    record_type: Literal["approval-manifest"] = "approval-manifest"
    source_revision: GitRevision
    origin_url: Literal["git@github.com:OCHOLA-EDDYPHIL/reconcile.git"]
    operator_state_root: SafeArgument
    execution_source: ExecutionSourceBinding
    python_dependencies: PythonDependencyBinding
    infrastructure_revision: Sha256Digest
    terraform_stacks: tuple[TerraformStackBinding, ...]
    terraform_plans: tuple[TerraformPlanBinding, ...]
    semantic_sources: SourceGroupBinding
    python_project_sha256: Sha256Digest
    python_lock_sha256: Sha256Digest
    image_digest: ImageDigest
    image_reference: SafeArgument
    image_artifact: ImageArtifactBinding
    semantic_config_sha256: Sha256Digest
    prompt_sha256: Sha256Digest
    prompt_version: SafeArgument
    resource_inventory_sha256: Sha256Digest
    iam_inventory_sha256: Sha256Digest
    plan_inventory_sha256: Sha256Digest
    project_id: Literal["example-project-id"]
    project_number: Literal["000000000000"]
    region: Literal["us-central1"]
    authenticated_exposure: tuple[ExposureBinding, ...]
    terraform_version: Literal["1.15.8"]
    terraform_executable: Literal["/usr/local/libexec/reconcile/terraform-1.15.8"]
    terraform_binary_sha256: Literal[
        "8b6cb96cd46080ee1287baf646c70078715a99123b9b3a6ce2a7fe3892ec703a"
    ]
    terraform_cli_config_path: SafeArgument
    terraform_cli_config_sha256: Literal[
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    ]
    gcloud_version: Literal["580.0.0"]
    git_version: Literal["2.43.0"]
    git_binary_sha256: Literal[
        "2a8c18fbf43da9f692d75474c72bea9dfd796c260b0f3dfe456376abc3bbd668"
    ]
    python_version: Literal["3.12.13"]
    python_interpreter: Literal[
        "/usr/local/libexec/reconcile/python-3.12.13/bin/python3.12"
    ]
    python_interpreter_sha256: Literal[
        "021044895e95be79dc2f110367607e684119afbc8ce75f6f0eec94844e0acec7"
    ]
    docker_client_sha256: Literal[
        "dda0804fca9b37a16e688356049ddf51fdd4c1a435c0a41055ec81cdf121535a"
    ]
    docker_credential_gcloud_sha256: Literal[
        "12fe4830c186064fb2202a96058a3abd4abf8a8a17bafead45054a7068019179"
    ]
    provider_source: Literal["registry.terraform.io/hashicorp/google"]
    provider_version: Literal["7.44.0"]
    gemini_model: Literal["gemini-3.5-flash"]
    vertex_location: Literal["us"]
    count_tokens_attempt_limit: Literal[1]
    billed_generation_limit: Literal[1]
    input_token_limit: Literal[12000]
    output_token_limit: Literal[1024, 4096]
    thinking_level: Literal["MINIMAL"]
    authorization_estimate_usd: Literal["3.892942"]
    contingency_authorization_estimate_usd: Literal["4.866178"]
    estimate_kind: Literal["authorization-estimate-not-hard-cap"]
    created_at: AwareDatetime
    work_deadline: AwareDatetime
    approval_expires_at: AwareDatetime
    commands: tuple[CommandDescriptor, ...]

    @model_validator(mode="after")
    def _validate_manifest(self) -> Phase5ApprovalManifest:
        if self.work_deadline - self.created_at != _WORK_WINDOW:
            raise ValueError("the work deadline must be exactly eight hours")
        if self.approval_expires_at - self.work_deadline != _TEARDOWN_WINDOW:
            raise ValueError("the teardown-only window must be exactly two hours")
        expected_image = (
            f"{self.region}-docker.pkg.dev/{self.project_id}/reconcile-p5/"
            f"reconcile@{self.image_digest}"
        )
        if self.image_reference != expected_image:
            raise ValueError("image reference is not the one immutable digest")
        if self.authenticated_exposure != _fixed_exposure():
            raise ValueError("authenticated exposure differs from the fixed graph")
        if self.semantic_config_sha256 != self.semantic_sources.sha256:
            raise ValueError("semantic configuration source hash mismatch")
        if self.terraform_stacks != tuple(
            sorted(self.terraform_stacks, key=lambda item: item.stack)
        ) or {item.stack for item in self.terraform_stacks} != set(_STACK_ROOTS):
            raise ValueError("Terraform stack inventory is not closed-world")
        if self.infrastructure_revision != _hash_value(
            [item.model_dump(mode="json") for item in self.terraform_stacks]
        ):
            raise ValueError("infrastructure revision hash mismatch")
        plan_actions = tuple(item.action for item in self.terraform_plans)
        expected_plan_actions = {Phase5Action(value) for value in _PLAN_FILES}
        if (
            len(plan_actions) != len(set(plan_actions))
            or set(plan_actions) != expected_plan_actions
        ):
            raise ValueError("Terraform plan inventory is not closed-world")
        state_root = _canonical_absolute_path(
            Path(self.operator_state_root), require_exists=False
        )
        if (
            self.execution_source.root != str(state_root / "source")
            or self.execution_source.source_revision != self.source_revision
        ):
            raise ValueError("execution source binding is outside the approved state")
        if (
            self.python_dependencies.root != str(state_root / "python-dependencies")
            or self.python_dependencies.source_image_digest != self.image_digest
            or self.python_dependencies.source_archive_sha256
            != self.image_artifact.archive_sha256
            or self.python_dependencies.python_lock_sha256 != self.python_lock_sha256
        ):
            raise ValueError("Python dependency binding is outside the approved state")
        if (
            self.terraform_cli_config_path != str(state_root / "terraform.rc")
            or self.terraform_cli_config_sha256 != _EMPTY_SHA256
        ):
            raise ValueError("Terraform CLI configuration is outside approved state")
        for plan in self.terraform_plans:
            _, stem = _PLAN_FILES[plan.action.value]
            if (
                plan.qualification_path
                != str(state_root / "plans" / f"{stem}.tfplan.json")
                or plan.variables_path
                != str(state_root / "plans" / f"{stem}.tfvars.json")
                or plan.execution_plan_path
                != str(state_root / "execution" / f"{stem}.tfplan")
            ):
                raise ValueError("Terraform plan is outside the approved state root")
        if self.plan_inventory_sha256 != _plan_inventory_hash(self.terraform_plans):
            raise ValueError("plan inventory aggregate hash mismatch")
        if self.resource_inventory_sha256 != _resource_inventory_hash(
            self.terraform_plans
        ):
            raise ValueError("resource inventory aggregate hash mismatch")
        if self.iam_inventory_sha256 != _iam_inventory_hash(self.terraform_plans):
            raise ValueError("IAM inventory aggregate hash mismatch")
        expected_archive = state_root / "images" / "reconcile.oci.tar"
        expected_tag = _image_source_tag(self.source_revision)
        if (
            self.image_artifact.archive_path != str(expected_archive)
            or self.image_artifact.source_tag != expected_tag
            or self.image_artifact.manifest_digest != self.image_digest
            or self.image_artifact.immutable_reference != self.image_reference
        ):
            raise ValueError("OCI image artifact binding mismatch")
        actions = tuple(item.action for item in self.commands)
        if len(actions) != len(set(actions)) or set(actions) != set(Phase5Action):
            raise ValueError("command inventory is not closed-world")
        runtime_source_sha256, runtime_variables_sha256 = _runtime_acceptance_hashes(
            self.terraform_stacks,
            self.terraform_plans,
        )
        expected_commands = _fixed_commands(
            self.source_revision,
            self.image_digest,
            self.infrastructure_revision,
            self.semantic_config_sha256,
            runtime_source_sha256=runtime_source_sha256,
            runtime_variables_sha256=runtime_variables_sha256,
            state_root=state_root,
            image_archive=expected_archive,
        )
        accepted_commands = [expected_commands]
        if self.source_revision in _LEGACY_STATE_BUCKET_CLEANUP_SOURCE_REVISIONS:
            accepted_commands.append(
                _fixed_commands(
                    self.source_revision,
                    self.image_digest,
                    self.infrastructure_revision,
                    self.semantic_config_sha256,
                    runtime_source_sha256=runtime_source_sha256,
                    runtime_variables_sha256=runtime_variables_sha256,
                    state_root=state_root,
                    image_archive=expected_archive,
                    include_state_bucket_cleanup=False,
                    include_bootstrap_protection_update=False,
                )
            )
        if self.source_revision in _LEGACY_BOOTSTRAP_PROTECTION_UPDATE_SOURCE_REVISIONS:
            accepted_commands.append(
                _fixed_commands(
                    self.source_revision,
                    self.image_digest,
                    self.infrastructure_revision,
                    self.semantic_config_sha256,
                    runtime_source_sha256=runtime_source_sha256,
                    runtime_variables_sha256=runtime_variables_sha256,
                    state_root=state_root,
                    image_archive=expected_archive,
                    include_bootstrap_protection_update=False,
                )
            )
        if self.source_revision in _LEGACY_IMAGE_ID_SOURCE_REVISIONS:
            accepted_commands.append(
                _fixed_commands(
                    self.source_revision,
                    self.image_digest,
                    self.infrastructure_revision,
                    self.semantic_config_sha256,
                    runtime_source_sha256=runtime_source_sha256,
                    runtime_variables_sha256=runtime_variables_sha256,
                    state_root=state_root,
                    image_archive=expected_archive,
                    image_identity_format="--format={{.Id}}",
                )
            )
            if self.source_revision in _LEGACY_STATE_BUCKET_CLEANUP_SOURCE_REVISIONS:
                accepted_commands.append(
                    _fixed_commands(
                        self.source_revision,
                        self.image_digest,
                        self.infrastructure_revision,
                        self.semantic_config_sha256,
                        runtime_source_sha256=runtime_source_sha256,
                        runtime_variables_sha256=runtime_variables_sha256,
                        state_root=state_root,
                        image_archive=expected_archive,
                        image_identity_format="--format={{.Id}}",
                        include_state_bucket_cleanup=False,
                        include_bootstrap_protection_update=False,
                    )
                )
        if self.commands not in accepted_commands:
            raise ValueError("command inventory differs from fixed descriptors")
        return self

    def command_for(self, action: Phase5Action) -> CommandDescriptor:
        for descriptor in self.commands:
            if descriptor.action is action:
                return descriptor
        raise OperatorError("COMMAND_NOT_IN_MANIFEST")

    def terraform_plan_for(self, action: Phase5Action) -> TerraformPlanBinding | None:
        for plan in self.terraform_plans:
            if plan.action is action:
                return plan
        return None


class Phase5Approval(_HasRecordHash):
    schema_version: Literal["reconcile/phase5-operator/v1"] = _SCHEMA
    record_type: Literal["approval"] = "approval"
    manifest_sha256: Sha256Digest
    decision: Literal["APPROVE_EXACT_MANIFEST"]
    approved_by: Literal["user:owner@example.invalid"]
    approved_at: AwareDatetime
    work_deadline: AwareDatetime
    approval_expires_at: AwareDatetime
    authorization_estimate_usd: Literal["3.892942"]
    contingency_authorization_estimate_usd: Literal["4.866178"]
    estimate_kind: Literal["authorization-estimate-not-hard-cap"]


class Phase5Admission(_HasRecordHash):
    schema_version: Literal["reconcile/phase5-operator/v1"] = _SCHEMA
    record_type: Literal["admission"] = "admission"
    manifest_sha256: Sha256Digest
    approval_sha256: Sha256Digest
    action: Phase5Action
    command_descriptor_sha256: Sha256Digest
    source_revision: GitRevision
    admitted_at: AwareDatetime


class Phase5Outcome(_HasRecordHash):
    schema_version: Literal["reconcile/phase5-operator/v1"] = _SCHEMA
    record_type: Literal["outcome"] = "outcome"
    admission_sha256: Sha256Digest
    status: OutcomeStatus
    reason: OutcomeReason
    return_code: Annotated[int, Field(ge=-255, le=255)] | None
    stdout_sha256: Sha256Digest
    stdout_bytes: Annotated[int, Field(ge=0, le=_MAX_OUTPUT_BYTES)]
    stderr_sha256: Sha256Digest
    stderr_bytes: Annotated[int, Field(ge=0, le=_MAX_OUTPUT_BYTES)]
    finished_at: AwareDatetime

    @model_validator(mode="after")
    def _validate_status_shape(self) -> Phase5Outcome:
        if self.status is OutcomeStatus.SUCCEEDED and (
            self.reason is not OutcomeReason.COMMAND_SUCCEEDED or self.return_code != 0
        ):
            raise ValueError("successful outcome shape mismatch")
        if self.status is OutcomeStatus.FAILED and (
            self.reason is not OutcomeReason.COMMAND_FAILED
            or self.return_code in {None, 0}
        ):
            raise ValueError("failed outcome shape mismatch")
        if self.status is OutcomeStatus.UNKNOWN and (
            self.reason
            not in {
                OutcomeReason.EXECUTION_EXCEPTION,
                OutcomeReason.INVALID_EXECUTION_RESULT,
            }
            or self.return_code is not None
            or self.stdout_sha256 != _EMPTY_SHA256
            or self.stdout_bytes != 0
            or self.stderr_sha256 != _EMPTY_SHA256
            or self.stderr_bytes != 0
        ):
            raise ValueError("unknown outcome must be sanitized")
        return self


class Phase5Evidence(_HasRecordHash):
    schema_version: Literal["reconcile/phase5-operator/v1"] = _SCHEMA
    record_type: Literal["evidence"] = "evidence"
    manifest_sha256: Sha256Digest
    approval_sha256: Sha256Digest
    admission_sha256: Sha256Digest
    outcome_sha256: Sha256Digest
    action: Phase5Action
    status: OutcomeStatus
    observed_at: AwareDatetime
    acceptance_mode: Literal["provider", "hosted"] | None = None
    acceptance_artifact_path: SafeArgument | None = None
    acceptance_record_sha256: Sha256Digest | None = None
    acceptance_file_sha256: Sha256Digest | None = None
    acceptance_byte_count: Annotated[int, Field(ge=1, le=_MAX_RECORD_BYTES)] | None = (
        None
    )

    @model_validator(mode="after")
    def _validate_acceptance_artifact(self) -> Phase5Evidence:
        values = (
            self.acceptance_mode,
            self.acceptance_artifact_path,
            self.acceptance_record_sha256,
            self.acceptance_file_sha256,
            self.acceptance_byte_count,
        )
        acceptance_action = self.action in {
            Phase5Action.PROVIDER_ACCEPTANCE,
            Phase5Action.HOSTED_ACCEPTANCE,
        }
        if acceptance_action and self.status is OutcomeStatus.SUCCEEDED:
            expected_mode = (
                "provider"
                if self.action is Phase5Action.PROVIDER_ACCEPTANCE
                else "hosted"
            )
            if (
                any(value is None for value in values)
                or self.acceptance_mode != expected_mode
            ):
                raise ValueError(
                    "successful acceptance evidence requires one exact artifact"
                )
        elif any(value is not None for value in values):
            raise ValueError("non-success evidence cannot bind an acceptance artifact")
        return self


class Phase5ActionEvidenceBinding(StrictModel):
    action: Phase5Action
    admission_sha256: Sha256Digest
    outcome_sha256: Sha256Digest
    evidence_sha256: Sha256Digest
    status: OutcomeStatus


class Phase5Continuation(_HasRecordHash):
    schema_version: Literal["reconcile/phase5-operator/v1"] = _SCHEMA
    record_type: Literal["continuation"] = "continuation"
    successor_manifest_sha256: Sha256Digest
    successor_approval_sha256: Sha256Digest
    predecessor_state_root: SafeArgument
    predecessor_manifest_sha256: Sha256Digest
    predecessor_approval_sha256: Sha256Digest
    carried_successes: tuple[Phase5ActionEvidenceBinding, ...] = Field(
        min_length=2,
        max_length=9,
    )
    terminal_action: Phase5ActionEvidenceBinding
    bootstrap_state_sha256: Sha256Digest
    bootstrap_state_byte_count: Annotated[int, Field(ge=1, le=_MAX_ARTIFACT_BYTES)]
    prepared_at: AwareDatetime

    @model_validator(mode="after")
    def _validate_continuation_shape(self) -> Phase5Continuation:
        carried_actions = tuple(item.action for item in self.carried_successes)
        valid_shape = (
            (
                carried_actions == _INITIAL_CONTINUATION_ACTIONS
                and self.terminal_action.action is Phase5Action.IMAGE_PUSH
                and self.terminal_action.status is OutcomeStatus.UNKNOWN
            )
            or (
                carried_actions == _INITIAL_CONTINUATION_ACTIONS
                and self.terminal_action.action is Phase5Action.PROVIDER_ACCEPTANCE
                and self.terminal_action.status is OutcomeStatus.FAILED
            )
            or (
                carried_actions == _TEARDOWN_CONTINUATION_ACTIONS
                and self.terminal_action.action is Phase5Action.STATE_PROTECTION_CHANGE
                and self.terminal_action.status is OutcomeStatus.UNKNOWN
            )
            or (
                carried_actions == _BOOTSTRAP_CONTINUATION_ACTIONS
                and self.terminal_action.action is Phase5Action.BOOTSTRAP_TEARDOWN
                and self.terminal_action.status is OutcomeStatus.FAILED
            )
        )
        if not valid_shape or any(
            item.status is not OutcomeStatus.SUCCEEDED
            for item in self.carried_successes
        ):
            raise ValueError("continuation may carry only successful prerequisites")
        return self


class CommandRunner(Protocol):
    def __call__(
        self,
        argv: tuple[str, ...],
        *,
        cwd: Path,
        environment: Mapping[str, str],
        timeout_seconds: int,
    ) -> object: ...


def _canonical_model_bytes(model: StrictModel) -> bytes:
    return json.dumps(
        model.model_dump(mode="json"),
        allow_nan=False,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


def _canonical_value_bytes(value: Any) -> bytes:
    return json.dumps(
        value,
        allow_nan=False,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


def _hash_value(value: Any) -> str:
    return hashlib.sha256(_canonical_value_bytes(value)).hexdigest()


def _hash_model_without(model: StrictModel, field: str) -> str:
    value = model.model_dump(mode="json", exclude={field})
    payload = json.dumps(
        value,
        allow_nan=False,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def _seal[ModelT: StrictModel](model_type: type[ModelT], **values: Any) -> ModelT:
    payload = dict(values)
    provisional = model_type.model_construct(
        **payload,
        record_sha256="0" * 64,
    )
    payload["record_sha256"] = _hash_model_without(provisional, "record_sha256")
    return model_type.model_validate(payload)


def _seal_descriptor(
    *,
    action: Phase5Action,
    commands: tuple[tuple[str, ...], ...],
    environment: tuple[EnvironmentBinding, ...] = (),
    timeout_seconds: int,
) -> CommandDescriptor:
    payload: dict[str, Any] = {
        "action": action,
        "commands": commands,
        "environment": environment,
        "timeout_seconds": timeout_seconds,
    }
    draft = CommandDescriptor.model_construct(**payload, descriptor_sha256="0" * 64)
    payload["descriptor_sha256"] = _hash_model_without(draft, "descriptor_sha256")
    return CommandDescriptor.model_validate(payload)


def _fixed_exposure() -> tuple[ExposureBinding, ...]:
    service_accounts = {
        component: (
            f"serviceAccount:rec-p5-{component.replace('_', '-')}@"
            f"{_PROJECT_ID}.iam.gserviceaccount.com"
        )
        for component in ("api", "controller", "fault", "sandbox")
    }
    return (
        ExposureBinding(
            service="api",
            audience=f"https://reconcile.invalid/phase5/{_PROJECT_ID}/api",
            allowed_callers=(_OPERATOR_PRINCIPAL,),
        ),
        ExposureBinding(
            service="controller",
            audience=(f"https://reconcile.invalid/phase5/{_PROJECT_ID}/controller"),
            allowed_callers=(service_accounts["api"],),
        ),
        ExposureBinding(
            service="fault-proxy",
            audience=(f"https://reconcile.invalid/phase5/{_PROJECT_ID}/fault-proxy"),
            allowed_callers=(service_accounts["api"],),
        ),
        ExposureBinding(
            service="sandbox",
            audience=f"https://reconcile.invalid/phase5/{_PROJECT_ID}/sandbox",
            allowed_callers=(
                service_accounts["controller"],
                service_accounts["fault"],
            ),
        ),
    )


def _image_source_tag(source_revision: str) -> str:
    return (
        f"{_REGION}-docker.pkg.dev/{_PROJECT_ID}/reconcile-p5/"
        f"reconcile:git-{source_revision}"
    )


def _oci_source_tag(source_revision: str) -> str:
    return f"git-{source_revision}"


def _plan_inventory_hash(plans: tuple[TerraformPlanBinding, ...]) -> str:
    return _hash_value(
        [
            {
                "action": item.action.value,
                "stack": item.stack,
                "qualification_path": item.qualification_path,
                "qualification_sha256": item.qualification_sha256,
                "variables_path": item.variables_path,
                "variables_sha256": item.variables_sha256,
                "execution_plan_path": item.execution_plan_path,
                "normalized_plan_sha256": item.normalized_plan_sha256,
            }
            for item in sorted(plans, key=lambda value: value.action.value)
        ]
    )


def _resource_inventory_hash(plans: tuple[TerraformPlanBinding, ...]) -> str:
    return _hash_value(
        [
            {
                "action": plan.action.value,
                "resources": [item.model_dump(mode="json") for item in plan.resources],
            }
            for plan in sorted(plans, key=lambda value: value.action.value)
        ]
    )


def _iam_inventory_hash(plans: tuple[TerraformPlanBinding, ...]) -> str:
    return _hash_value(
        [
            {
                "action": plan.action.value,
                "iam_edges": [item.model_dump(mode="json") for item in plan.iam_edges],
            }
            for plan in sorted(plans, key=lambda value: value.action.value)
        ]
    )


def _runtime_acceptance_hashes(
    stacks: tuple[TerraformStackBinding, ...],
    plans: tuple[TerraformPlanBinding, ...],
) -> tuple[str, str]:
    runtime_stacks = tuple(item for item in stacks if item.stack == "runtime")
    runtime_apply_plans = tuple(
        item for item in plans if item.action is Phase5Action.RUNTIME_APPLY
    )
    if len(runtime_stacks) != 1 or len(runtime_apply_plans) != 1:
        raise ValueError("hosted acceptance runtime bindings are incomplete")
    return (
        runtime_stacks[0].sources.sha256,
        runtime_apply_plans[0].variables_sha256,
    )


def fixed_command_descriptors(
    draft: Phase5ManifestDraft,
    *,
    state_root: Path,
    infrastructure_revision: str,
    semantic_config_sha256: str,
    runtime_source_sha256: str,
    runtime_variables_sha256: str,
) -> tuple[CommandDescriptor, ...]:
    """Build the closed, shell-free argv inventory bound into a manifest."""

    root = _canonical_absolute_path(state_root, require_exists=False)
    return _fixed_commands(
        draft.source_revision,
        draft.image_digest,
        infrastructure_revision,
        semantic_config_sha256,
        runtime_source_sha256=runtime_source_sha256,
        runtime_variables_sha256=runtime_variables_sha256,
        state_root=root,
        image_archive=root / "images" / "reconcile.oci.tar",
    )


def _fixed_commands(
    source_revision: str,
    image_digest: str,
    infrastructure_revision: str,
    semantic_config_sha256: str,
    *,
    runtime_source_sha256: str,
    runtime_variables_sha256: str,
    state_root: Path,
    image_archive: Path,
    image_identity_format: Literal[
        "--format={{.Descriptor.digest}}",
        "--format={{.Id}}",
    ] = "--format={{.Descriptor.digest}}",
    include_state_bucket_cleanup: bool = True,
    include_bootstrap_protection_update: bool = True,
) -> tuple[CommandDescriptor, ...]:
    root = _canonical_absolute_path(state_root, require_exists=False)
    plan_root = root / "plans"
    execution_root = root / "execution"
    data_root = root / "terraform-data"
    source_root = root / "source"
    dependency_root = root / "python-dependencies"
    terraform_cli_config = root / "terraform.rc"
    image_tag = _image_source_tag(source_revision)

    def terraform_action(action: Phase5Action) -> CommandDescriptor:
        stack, stem = _PLAN_FILES[action.value]
        directory = _STACK_ROOTS[stack]
        variables = plan_root / f"{stem}.tfvars.json"
        execution_plan = execution_root / f"{stem}.tfplan"
        protection_execution_plan = (
            execution_root / "bootstrap-final-protection-update.tfplan"
        )
        init = [
            _TERRAFORM,
            f"-chdir={directory}",
            "init",
            "-input=false",
            "-lockfile=readonly",
            "-no-color",
        ]
        if stack == "bootstrap":
            init.append(f"-backend-config=path={root / 'state' / 'bootstrap.tfstate'}")
        plan = [
            _TERRAFORM,
            f"-chdir={directory}",
            "plan",
            "-input=false",
            "-lock=true",
            "-no-color",
            f"-out={execution_plan}",
            f"-var-file={variables}",
        ]
        if action in {
            Phase5Action.RUNTIME_TEARDOWN,
            Phase5Action.FOUNDATION_TEARDOWN,
            Phase5Action.STATE_PROTECTION_CHANGE,
            Phase5Action.BOOTSTRAP_TEARDOWN,
        }:
            plan.append("-destroy")
        commands: tuple[tuple[str, ...], ...] = ()
        if action is Phase5Action.BOOTSTRAP_APPLY:
            commands += (
                (
                    "/usr/bin/gcloud",
                    "services",
                    "enable",
                    "cloudresourcemanager.googleapis.com",
                    f"--project={_PROJECT_ID}",
                    f"--account={_OWNER_ACCOUNT}",
                    "--quiet",
                ),
            )
        if action is Phase5Action.BOOTSTRAP_TEARDOWN and include_state_bucket_cleanup:
            commands += (_state_bucket_cleanup_command(),)
        commands += (tuple(init),)
        if (
            action is Phase5Action.BOOTSTRAP_TEARDOWN
            and include_bootstrap_protection_update
        ):
            commands += (
                (
                    _TERRAFORM,
                    f"-chdir={directory}",
                    "plan",
                    "-input=false",
                    "-lock=true",
                    "-no-color",
                    f"-out={protection_execution_plan}",
                    f"-var-file={variables}",
                    "-target=google_storage_bucket.terraform_state",
                ),
                (
                    _TERRAFORM,
                    f"-chdir={directory}",
                    "show",
                    "-json",
                    str(protection_execution_plan),
                ),
                (
                    _TERRAFORM,
                    f"-chdir={directory}",
                    "apply",
                    "-input=false",
                    "-no-color",
                    str(protection_execution_plan),
                ),
            )
        commands += (
            tuple(plan),
            (
                _TERRAFORM,
                f"-chdir={directory}",
                "show",
                "-json",
                str(execution_plan),
            ),
        )
        if action is not Phase5Action.STATE_PROTECTION_CHANGE:
            commands += (
                (
                    _TERRAFORM,
                    f"-chdir={directory}",
                    "apply",
                    "-input=false",
                    "-no-color",
                    str(execution_plan),
                ),
            )
        return _seal_descriptor(
            action=action,
            commands=commands,
            environment=(
                EnvironmentBinding(name="TF_DATA_DIR", value=str(data_root / stack)),
                EnvironmentBinding(
                    name="TF_CLI_CONFIG_FILE", value=str(terraform_cli_config)
                ),
            ),
            timeout_seconds=3_600,
        )

    return (
        terraform_action(Phase5Action.BOOTSTRAP_APPLY),
        terraform_action(Phase5Action.FOUNDATION_APPLY),
        _seal_descriptor(
            action=Phase5Action.IMAGE_PUSH,
            commands=(
                (
                    "/usr/bin/gcloud",
                    "auth",
                    "configure-docker",
                    f"{_REGION}-docker.pkg.dev",
                    f"--impersonate-service-account={_OPERATOR_SERVICE_ACCOUNT}",
                    "--quiet",
                ),
                (_DOCKER, "image", "load", "--input", str(image_archive)),
                (
                    _DOCKER,
                    "image",
                    "inspect",
                    image_identity_format,
                    image_tag,
                ),
                (_DOCKER, "image", "push", image_tag),
                (
                    "/usr/bin/gcloud",
                    "artifacts",
                    "docker",
                    "images",
                    "describe",
                    image_tag,
                    f"--project={_PROJECT_ID}",
                    f"--impersonate-service-account={_OPERATOR_SERVICE_ACCOUNT}",
                    "--format=value(image_summary.digest)",
                    "--quiet",
                ),
            ),
            environment=(
                EnvironmentBinding(
                    name="CLOUDSDK_AUTH_IMPERSONATE_SERVICE_ACCOUNT",
                    value=_OPERATOR_SERVICE_ACCOUNT,
                ),
                EnvironmentBinding(name="DOCKER_CONFIG", value=str(root / "docker")),
                EnvironmentBinding(name="DOCKER_HOST", value=_DOCKER_HOST),
            ),
            timeout_seconds=1_800,
        ),
        terraform_action(Phase5Action.RUNTIME_APPLY),
        _seal_descriptor(
            action=Phase5Action.PROVIDER_ACCEPTANCE,
            commands=(
                (
                    _PYTHON,
                    "-P",
                    "-S",
                    "-m",
                    "scripts.check_phase5_hosted_acceptance",
                    "provider",
                    "--state-root",
                    str(root),
                    "--source-revision",
                    source_revision,
                    "--image-digest",
                    image_digest,
                    "--infrastructure-revision",
                    infrastructure_revision,
                    "--semantic-config-sha256",
                    semantic_config_sha256,
                    "--runtime-source-sha256",
                    runtime_source_sha256,
                    "--runtime-variables-sha256",
                    runtime_variables_sha256,
                ),
            ),
            environment=(
                EnvironmentBinding(
                    name="RECONCILE_API_AUDIENCE",
                    value=f"https://reconcile.invalid/phase5/{_PROJECT_ID}/api",
                ),
                EnvironmentBinding(
                    name="PYTHONPATH",
                    value=f"{source_root}:{dependency_root}",
                ),
            ),
            timeout_seconds=3_600,
        ),
        _seal_descriptor(
            action=Phase5Action.HOSTED_ACCEPTANCE,
            commands=(
                (
                    _PYTHON,
                    "-P",
                    "-S",
                    "-m",
                    "scripts.check_phase5_hosted_acceptance",
                    "hosted",
                    "--state-root",
                    str(root),
                    "--source-revision",
                    source_revision,
                    "--image-digest",
                    image_digest,
                    "--infrastructure-revision",
                    infrastructure_revision,
                    "--semantic-config-sha256",
                    semantic_config_sha256,
                    "--runtime-source-sha256",
                    runtime_source_sha256,
                    "--runtime-variables-sha256",
                    runtime_variables_sha256,
                ),
            ),
            environment=(
                EnvironmentBinding(
                    name="RECONCILE_API_AUDIENCE",
                    value=f"https://reconcile.invalid/phase5/{_PROJECT_ID}/api",
                ),
                EnvironmentBinding(
                    name="PYTHONPATH",
                    value=f"{source_root}:{dependency_root}",
                ),
            ),
            timeout_seconds=14_400,
        ),
        terraform_action(Phase5Action.RUNTIME_TEARDOWN),
        terraform_action(Phase5Action.FOUNDATION_TEARDOWN),
        terraform_action(Phase5Action.STATE_PROTECTION_CHANGE),
        terraform_action(Phase5Action.BOOTSTRAP_TEARDOWN),
    )


def _state_bucket_cleanup_command() -> tuple[str, ...]:
    return (
        "/usr/bin/gcloud",
        "storage",
        "rm",
        "--all-versions",
        f"gs://{_STATE_BUCKET}/**",
        f"--project={_PROJECT_ID}",
        f"--account={_OWNER_ACCOUNT}",
        "--quiet",
    )


def _minimal_subprocess_environment(
    extra: tuple[EnvironmentBinding, ...] = (),
) -> dict[str, str]:
    environment = {
        "CLOUDSDK_CORE_DISABLE_PROMPTS": "1",
        "GIT_TERMINAL_PROMPT": "0",
        "HOME": _OPERATOR_HOME,
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "PATH": f"{_OPERATOR_HOME}/.local/bin:/usr/bin:/bin",
        "PYTHONDONTWRITEBYTECODE": "1",
        "PYTHONNOUSERSITE": "1",
        "TF_IN_AUTOMATION": "1",
        "TF_INPUT": "0",
    }
    environment.update({item.name: item.value for item in extra})
    return environment


def _read_bounded_file(
    path: Path,
    *,
    maximum: int,
    immutable: bool,
) -> bytes:
    canonical = _canonical_absolute_path(path, require_exists=True)
    try:
        descriptor = os.open(canonical, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    except OSError as error:
        raise OperatorError("ARTIFACT_READ_FAILED") from error
    try:
        metadata = os.fstat(descriptor)
        expected_mode = 0o400 if immutable else None
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != os.getuid()
            or metadata.st_size > maximum
            or (
                expected_mode is not None
                and stat.S_IMODE(metadata.st_mode) != expected_mode
            )
            or (immutable and metadata.st_nlink != 1)
        ):
            raise OperatorError("ARTIFACT_NOT_IMMUTABLE")
        chunks: list[bytes] = []
        remaining = maximum + 1
        while remaining > 0:
            chunk = os.read(descriptor, min(1_048_576, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        data = b"".join(chunks)
        if len(data) > maximum:
            raise OperatorError("ARTIFACT_TOO_LARGE")
        return data
    finally:
        os.close(descriptor)


def _immutable_file_sha256(path: Path) -> str:
    canonical = _canonical_absolute_path(path, require_exists=True)
    try:
        descriptor = os.open(canonical, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    except OSError as error:
        raise OperatorError("ARTIFACT_READ_FAILED") from error
    try:
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != os.getuid()
            or stat.S_IMODE(metadata.st_mode) != 0o400
            or metadata.st_nlink != 1
            or metadata.st_size > _MAX_ARTIFACT_BYTES
        ):
            raise OperatorError("ARTIFACT_NOT_IMMUTABLE")
        digest = hashlib.sha256()
        remaining = _MAX_ARTIFACT_BYTES + 1
        while remaining > 0:
            chunk = os.read(descriptor, min(1_048_576, remaining))
            if not chunk:
                break
            digest.update(chunk)
            remaining -= len(chunk)
        if remaining <= 0 and os.read(descriptor, 1):
            raise OperatorError("ARTIFACT_TOO_LARGE")
        return digest.hexdigest()
    finally:
        os.close(descriptor)


def _verify_artifact_directory(path: Path) -> None:
    canonical = _canonical_absolute_path(path, require_exists=True)
    try:
        metadata = os.lstat(canonical)
    except OSError as error:
        raise OperatorError("ARTIFACT_DIRECTORY_UNAVAILABLE") from error
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or stat.S_ISLNK(metadata.st_mode)
        or metadata.st_uid != os.getuid()
        or stat.S_IMODE(metadata.st_mode) != 0o700
    ):
        raise OperatorError("ARTIFACT_DIRECTORY_NOT_PRIVATE")


def _verify_immutable_empty_file(path: Path, *, failure: str) -> None:
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    except OSError as error:
        raise OperatorError(failure) from error
    try:
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != os.getuid()
            or stat.S_IMODE(metadata.st_mode) != 0o400
            or metadata.st_nlink != 1
            or metadata.st_size != 0
        ):
            raise OperatorError(failure)
    finally:
        os.close(descriptor)


def _write_immutable_empty_file(path: Path, *, failure: str) -> None:
    _verify_artifact_directory(path.parent)
    try:
        descriptor = os.open(
            path,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW,
            0o600,
        )
    except OSError as error:
        raise OperatorError(failure) from error
    try:
        os.fchmod(descriptor, 0o400)
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    directory = os.open(
        path.parent,
        os.O_RDONLY | os.O_CLOEXEC | os.O_DIRECTORY | os.O_NOFOLLOW,
    )
    try:
        os.fsync(directory)
    finally:
        os.close(directory)
    _verify_immutable_empty_file(path, failure=failure)


def _source_file_binding(repo_root: Path, path: Path) -> SourceFileBinding:
    root = _canonical_absolute_path(repo_root, require_exists=True)
    canonical = _canonical_absolute_path(path, require_exists=True)
    try:
        relative = canonical.relative_to(root).as_posix()
    except ValueError as error:
        raise OperatorError("SOURCE_OUTSIDE_REPOSITORY") from error
    data = _read_bounded_file(canonical, maximum=8 * 1_048_576, immutable=False)
    return SourceFileBinding(path=relative, sha256=hashlib.sha256(data).hexdigest())


def _source_group(
    repo_root: Path,
    *,
    name: str,
    paths: Sequence[Path],
) -> SourceGroupBinding:
    files = tuple(
        sorted(
            (_source_file_binding(repo_root, path) for path in paths),
            key=lambda item: item.path,
        )
    )
    if not files:
        raise OperatorError("SOURCE_GROUP_EMPTY")
    return SourceGroupBinding(
        name=name,
        files=files,
        sha256=_hash_value([item.model_dump(mode="json") for item in files]),
    )


def _capture_semantic_sources(repo_root: Path) -> SourceGroupBinding:
    source_root = repo_root / "reconcile"
    paths = tuple(path for path in source_root.rglob("*.py") if path.is_file())
    return _source_group(repo_root, name="reconcile-python", paths=paths)


def _stack_paths(repo_root: Path, stack: str) -> tuple[Path, ...]:
    root = repo_root / _STACK_ROOTS[stack]
    paths = tuple(sorted((*root.glob("*.tf"), root / ".terraform.lock.hcl")))
    if any(not path.is_file() or path.is_symlink() for path in paths):
        raise OperatorError("TERRAFORM_SOURCE_INVALID")
    forbidden = tuple(
        path
        for path in root.iterdir()
        if path.is_file()
        and (
            path.name.endswith(".tf.json")
            or ".tfvars" in path.name
            or path.name == "override.tf"
            or path.name.endswith("_override.tf")
        )
    )
    if forbidden:
        raise OperatorError("TERRAFORM_SOURCE_INVALID")
    return paths


def _validate_terraform_source_pins(repo_root: Path, stack: str) -> None:
    root = repo_root / _STACK_ROOTS[stack]
    versions = _read_bounded_file(
        root / "versions.tf", maximum=65_536, immutable=False
    ).decode("utf-8")
    lock = _read_bounded_file(
        root / ".terraform.lock.hcl", maximum=1_048_576, immutable=False
    ).decode("utf-8")
    expected_versions = (
        versions.count('required_version = "= 1.15.8"') == 1
        and versions.count('source  = "hashicorp/google"') == 1
        and versions.count('version = "= 7.44.0"') == 1
    )
    provider_header = f'provider "{_GOOGLE_PROVIDER_SOURCE}"'
    expected_lock = (
        lock.count(provider_header) == 1
        and lock.count('version     = "7.44.0"') == 1
        and lock.count('constraints = "7.44.0"') == 1
    )
    if not expected_versions or not expected_lock:
        raise OperatorError("TERRAFORM_PIN_DRIFT")


def _capture_terraform_stacks(
    repo_root: Path,
) -> tuple[TerraformStackBinding, ...]:
    bindings: list[TerraformStackBinding] = []
    for stack in sorted(_STACK_ROOTS):
        _validate_terraform_source_pins(repo_root, stack)
        sources = _source_group(
            repo_root,
            name=f"terraform-{stack}",
            paths=_stack_paths(repo_root, stack),
        )
        lock_path = f"{_STACK_ROOTS[stack]}/.terraform.lock.hcl"
        lock_sha256 = next(
            item.sha256 for item in sources.files if item.path == lock_path
        )
        bindings.append(
            TerraformStackBinding(
                stack=stack,
                source_root=_STACK_ROOTS[stack],
                sources=sources,
                lock_sha256=lock_sha256,
            )
        )
    return tuple(bindings)


def _planner_prompt_identity(repo_root: Path) -> tuple[str, str]:
    data = _read_bounded_file(
        repo_root / "reconcile" / "adk_planner.py",
        maximum=2 * 1_048_576,
        immutable=False,
    )
    try:
        tree = ast.parse(data.decode("utf-8"))
    except (UnicodeError, SyntaxError) as error:
        raise OperatorError("PLANNER_PROMPT_UNREADABLE") from error
    values: dict[str, str] = {}
    for node in tree.body:
        if not isinstance(node, ast.Assign) or len(node.targets) != 1:
            continue
        target = node.targets[0]
        if (
            isinstance(target, ast.Name)
            and target.id in {"ADK_PLANNER_PROMPT_VERSION", "_PLANNER_INSTRUCTION"}
            and isinstance(node.value, ast.Constant)
            and isinstance(node.value.value, str)
        ):
            values[target.id] = node.value.value
    if set(values) != {"ADK_PLANNER_PROMPT_VERSION", "_PLANNER_INSTRUCTION"}:
        raise OperatorError("PLANNER_PROMPT_UNREADABLE")
    return (
        values["ADK_PLANNER_PROMPT_VERSION"],
        hashlib.sha256(values["_PLANNER_INSTRUCTION"].encode("utf-8")).hexdigest(),
    )


def _validated_runner_bytes(
    result: object,
    *,
    maximum: int,
    failure: str,
) -> bytes:
    if (
        not isinstance(result, subprocess.CompletedProcess)
        or type(result.returncode) is not int
        or result.returncode != 0
        or type(result.stdout) is not bytes
        or type(result.stderr) is not bytes
        or len(result.stdout) > maximum
        or len(result.stderr) > 65_536
    ):
        raise OperatorError(failure)
    return result.stdout


def _verify_terraform_binary(
    repo_root: Path,
    runner: CommandRunner,
    *,
    cli_config: Path,
    timeout_seconds: int = 15,
) -> None:
    if not 1 <= timeout_seconds <= 15:
        raise OperatorError("TERRAFORM_BINARY_DRIFT")
    _verify_root_owned_binary(
        Path(_TERRAFORM),
        _TERRAFORM_SHA256,
        "TERRAFORM_BINARY_DRIFT",
    )
    _verify_immutable_empty_file(cli_config, failure="TERRAFORM_CLI_CONFIG_DRIFT")
    try:
        output = _validated_runner_bytes(
            runner(
                (_TERRAFORM, "version", "-json"),
                cwd=repo_root,
                environment=_minimal_subprocess_environment(
                    (
                        EnvironmentBinding(
                            name="TF_CLI_CONFIG_FILE", value=str(cli_config)
                        ),
                    )
                ),
                timeout_seconds=timeout_seconds,
            ),
            maximum=65_536,
            failure="TERRAFORM_BINARY_DRIFT",
        )
        value = json.loads(output, object_pairs_hook=_reject_duplicate_keys)
    except OperatorError:
        raise
    except (ValueError, TypeError) as error:
        raise OperatorError("TERRAFORM_BINARY_DRIFT") from error
    if (
        not isinstance(value, dict)
        or value.get("terraform_version") != _TERRAFORM_VERSION
    ):
        raise OperatorError("TERRAFORM_BINARY_DRIFT")


def _verify_root_owned_binary(path: Path, expected_sha256: str, failure: str) -> None:
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    except OSError as error:
        raise OperatorError(failure) from error
    try:
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != 0
            or stat.S_IMODE(metadata.st_mode) & 0o022
            or not stat.S_IMODE(metadata.st_mode) & 0o111
            or metadata.st_size > 128 * 1_048_576
        ):
            raise OperatorError(failure)
        digest = hashlib.sha256()
        while chunk := os.read(descriptor, 1_048_576):
            digest.update(chunk)
        if digest.hexdigest() != expected_sha256:
            raise OperatorError(failure)
    finally:
        os.close(descriptor)


def _execution_path_allowed(value: str) -> bool:
    try:
        path = PurePosixPath(value)
    except (TypeError, ValueError):
        return False
    if (
        not value
        or len(value) > 4_096
        or any(ord(character) < 0x20 or ord(character) == 0x7F for character in value)
        or path.is_absolute()
        or path.as_posix() != value
        or value.startswith("./")
        or any(part in {"", ".", ".."} for part in path.parts)
        or path.parts[0].casefold() in _FORBIDDEN_TOP_LEVEL_SOURCE_ROOTS
        or any("holdout" in part.casefold() for part in path.parts)
    ):
        return False
    return (
        value in _EXECUTION_ROOT_FILES
        or value in _EXECUTION_SCRIPTS
        or any(value.startswith(prefix) for prefix in _EXECUTION_TREE_PREFIXES)
    )


def _verify_python_interpreter() -> None:
    _verify_root_owned_binary(
        Path(_PYTHON),
        _PYTHON_SHA256,
        "PYTHON_INTERPRETER_DRIFT",
    )


def _verify_git_binary(repo_root: Path, runner: CommandRunner) -> None:
    _verify_root_owned_binary(Path(_GIT), _GIT_SHA256, "GIT_BINARY_DRIFT")
    try:
        output = _validated_runner_bytes(
            runner(
                (_GIT, "--version"),
                cwd=repo_root,
                environment=_minimal_subprocess_environment(),
                timeout_seconds=15,
            ),
            maximum=1_024,
            failure="GIT_BINARY_DRIFT",
        )
    except OperatorError:
        raise
    except Exception as error:
        raise OperatorError("GIT_BINARY_DRIFT") from error
    if output != f"git version {_GIT_VERSION}\n".encode("ascii"):
        raise OperatorError("GIT_BINARY_DRIFT")


def _git_blob_object_id(payload: bytes) -> str:
    header = f"blob {len(payload)}\0".encode("ascii")
    return hashlib.sha1(header + payload, usedforsecurity=False).hexdigest()


def _git_execution_tree(
    repo_root: Path,
    source_revision: str,
    runner: CommandRunner,
) -> tuple[int, tuple[tuple[str, str, str], ...]]:
    root = _canonical_absolute_path(repo_root, require_exists=True)
    if re.fullmatch(r"[0-9a-f]{40}", source_revision) is None:
        raise OperatorError("SOURCE_REVISION_INVALID")
    _verify_git_binary(root, runner)
    environment = _minimal_subprocess_environment()

    def checked(argv: tuple[str, ...], maximum: int = 1_048_576) -> bytes:
        try:
            return _validated_runner_bytes(
                runner(
                    argv,
                    cwd=root,
                    environment=environment,
                    timeout_seconds=30,
                ),
                maximum=maximum,
                failure="EXECUTION_SOURCE_GIT_FAILED",
            )
        except OperatorError:
            raise
        except Exception as error:
            raise OperatorError("EXECUTION_SOURCE_GIT_FAILED") from error

    if checked((_GIT, "rev-parse", "--show-object-format"), 64) != b"sha1\n":
        raise OperatorError("EXECUTION_SOURCE_OBJECT_FORMAT_UNSUPPORTED")
    if checked(
        (_GIT, "rev-parse", "--verify", f"{source_revision}^{{commit}}"), 128
    ) != f"{source_revision}\n".encode("ascii"):
        raise OperatorError("EXECUTION_SOURCE_COMMIT_DRIFT")
    timestamp = checked(
        (_GIT, "show", "-s", "--format=%ct", source_revision), 128
    ).strip()
    if not timestamp.isascii() or not timestamp.isdigit() or int(timestamp) < 1:
        raise OperatorError("EXECUTION_SOURCE_TIMESTAMP_INVALID")
    payload = checked(
        (
            _GIT,
            "ls-tree",
            "-r",
            "-z",
            "--full-tree",
            source_revision,
            "--",
            *_EXECUTION_GIT_PATHS,
        ),
        8 * 1_048_576,
    )
    entries: list[tuple[str, str, str]] = []
    for record in payload.split(b"\0"):
        if not record:
            continue
        try:
            header, raw_path = record.split(b"\t", 1)
            mode, kind, object_id = header.decode("ascii").split(" ", 2)
            path = raw_path.decode("utf-8")
        except (UnicodeError, ValueError) as error:
            raise OperatorError("EXECUTION_SOURCE_TREE_INVALID") from error
        if (
            mode not in {"100644", "100755"}
            or kind != "blob"
            or re.fullmatch(r"[0-9a-f]{40}", object_id) is None
            or not _execution_path_allowed(path)
        ):
            raise OperatorError("EXECUTION_SOURCE_TREE_INVALID")
        entries.append((path, mode, object_id))
    entries.sort(key=lambda item: item[0])
    paths = tuple(item[0] for item in entries)
    if (
        not entries
        or len(entries) > _MAX_EXECUTION_SOURCE_FILES
        or len(paths) != len(set(paths))
        or not _EXECUTION_REQUIRED_PATHS.issubset(paths)
    ):
        raise OperatorError("EXECUTION_SOURCE_TREE_INCOMPLETE")
    return int(timestamp), tuple(entries)


def _read_execution_source_file(path: Path, git_mode: str) -> bytes:
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    except OSError as error:
        raise OperatorError("EXECUTION_SOURCE_INVALID") from error
    try:
        metadata = os.fstat(descriptor)
        expected_mode = 0o500 if git_mode == "100755" else 0o400
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != os.getuid()
            or stat.S_IMODE(metadata.st_mode) != expected_mode
            or metadata.st_nlink != 1
            or metadata.st_size > _MAX_EXECUTION_SOURCE_FILE_BYTES
        ):
            raise OperatorError("EXECUTION_SOURCE_INVALID")
        chunks: list[bytes] = []
        observed = 0
        while chunk := os.read(descriptor, 1_048_576):
            observed += len(chunk)
            if observed > _MAX_EXECUTION_SOURCE_FILE_BYTES:
                raise OperatorError("EXECUTION_SOURCE_INVALID")
            chunks.append(chunk)
        after = os.fstat(descriptor)
        if observed != metadata.st_size or (
            after.st_dev,
            after.st_ino,
            after.st_size,
            after.st_mtime_ns,
            after.st_ctime_ns,
            after.st_mode,
            after.st_uid,
            after.st_nlink,
        ) != (
            metadata.st_dev,
            metadata.st_ino,
            metadata.st_size,
            metadata.st_mtime_ns,
            metadata.st_ctime_ns,
            metadata.st_mode,
            metadata.st_uid,
            metadata.st_nlink,
        ):
            raise OperatorError("EXECUTION_SOURCE_CHANGED_DURING_READ")
        return b"".join(chunks)
    finally:
        os.close(descriptor)


def _capture_execution_source(
    *,
    state_root: Path,
    repo_root: Path,
    source_revision: str,
    runner: CommandRunner,
) -> ExecutionSourceBinding:
    state = _canonical_absolute_path(state_root, require_exists=True)
    source = _canonical_absolute_path(state / "source", require_exists=True)
    try:
        source_metadata = os.lstat(source)
    except OSError as error:
        raise OperatorError("EXECUTION_SOURCE_INVALID") from error
    if (
        not stat.S_ISDIR(source_metadata.st_mode)
        or stat.S_ISLNK(source_metadata.st_mode)
        or source_metadata.st_uid != os.getuid()
        or stat.S_IMODE(source_metadata.st_mode) != 0o500
    ):
        raise OperatorError("EXECUTION_SOURCE_INVALID")
    epoch, tree_entries = _git_execution_tree(repo_root, source_revision, runner)
    expected = {path: (mode, object_id) for path, mode, object_id in tree_entries}
    expected_directories: set[str] = set()
    for path in expected:
        parent = PurePosixPath(path).parent
        while parent != PurePosixPath("."):
            expected_directories.add(parent.as_posix())
            parent = parent.parent
    actual_files: set[str] = set()
    actual_directories: set[str] = set()
    try:
        for directory, names, filenames in os.walk(source, followlinks=False):
            current = Path(directory)
            relative_directory = current.relative_to(source).as_posix()
            if relative_directory != ".":
                actual_directories.add(relative_directory)
            metadata = os.lstat(current)
            if (
                not stat.S_ISDIR(metadata.st_mode)
                or stat.S_ISLNK(metadata.st_mode)
                or metadata.st_uid != os.getuid()
                or stat.S_IMODE(metadata.st_mode) != 0o500
            ):
                raise OperatorError("EXECUTION_SOURCE_INVALID")
            for name in names:
                child = current / name
                child_metadata = os.lstat(child)
                if stat.S_ISLNK(child_metadata.st_mode):
                    raise OperatorError("EXECUTION_SOURCE_INVALID")
            for name in filenames:
                relative = (current / name).relative_to(source).as_posix()
                actual_files.add(relative)
    except OperatorError:
        raise
    except OSError as error:
        raise OperatorError("EXECUTION_SOURCE_INVALID") from error
    if actual_files != set(expected) or actual_directories != expected_directories:
        raise OperatorError("EXECUTION_SOURCE_CLOSED_WORLD_DRIFT")
    files: list[ExecutionSourceFileBinding] = []
    for path, mode, object_id in tree_entries:
        payload = _read_execution_source_file(source / path, mode)
        if _git_blob_object_id(payload) != object_id:
            raise OperatorError("EXECUTION_SOURCE_COMMIT_DRIFT")
        files.append(
            ExecutionSourceFileBinding(
                path=path,
                git_mode=mode,
                git_object_id=object_id,
                byte_count=len(payload),
                sha256=hashlib.sha256(payload).hexdigest(),
            )
        )
    aggregate = {
        "source_revision": source_revision,
        "source_date_epoch": epoch,
        "files": [item.model_dump(mode="json") for item in files],
    }
    return ExecutionSourceBinding(
        root=str(source),
        source_revision=source_revision,
        source_date_epoch=epoch,
        files=tuple(files),
        sha256=_hash_value(aggregate),
    )


def _verify_execution_source_binding(binding: ExecutionSourceBinding) -> None:
    source = _canonical_absolute_path(Path(binding.root), require_exists=True)
    expected = {item.path: item for item in binding.files}
    expected_directories: set[str] = set()
    for path in expected:
        parent = PurePosixPath(path).parent
        while parent != PurePosixPath("."):
            expected_directories.add(parent.as_posix())
            parent = parent.parent
    actual_files: set[str] = set()
    actual_directories: set[str] = set()
    try:
        for directory, names, filenames in os.walk(source, followlinks=False):
            current = Path(directory)
            relative_directory = current.relative_to(source).as_posix()
            if relative_directory != ".":
                actual_directories.add(relative_directory)
            metadata = os.lstat(current)
            if (
                not stat.S_ISDIR(metadata.st_mode)
                or stat.S_ISLNK(metadata.st_mode)
                or metadata.st_uid != os.getuid()
                or stat.S_IMODE(metadata.st_mode) != 0o500
            ):
                raise OperatorError("EXECUTION_SOURCE_INVALID")
            for name in names:
                if stat.S_ISLNK(os.lstat(current / name).st_mode):
                    raise OperatorError("EXECUTION_SOURCE_INVALID")
            actual_files.update(
                (current / name).relative_to(source).as_posix() for name in filenames
            )
    except OperatorError:
        raise
    except OSError as error:
        raise OperatorError("EXECUTION_SOURCE_INVALID") from error
    if actual_files != set(expected) or actual_directories != expected_directories:
        raise OperatorError("EXECUTION_SOURCE_CLOSED_WORLD_DRIFT")
    for path, item in expected.items():
        payload = _read_execution_source_file(source / path, item.git_mode)
        if (
            len(payload) != item.byte_count
            or hashlib.sha256(payload).hexdigest() != item.sha256
            or _git_blob_object_id(payload) != item.git_object_id
        ):
            raise OperatorError("EXECUTION_SOURCE_BINDING_DRIFT")


def _write_execution_source_file(path: Path, payload: bytes, git_mode: str) -> None:
    try:
        descriptor = os.open(
            path,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW,
            0o600,
        )
    except OSError as error:
        raise OperatorError("EXECUTION_SOURCE_WRITE_FAILED") from error
    try:
        offset = 0
        while offset < len(payload):
            written = os.write(descriptor, payload[offset:])
            if written < 1:
                raise OperatorError("EXECUTION_SOURCE_WRITE_FAILED")
            offset += written
        os.fchmod(descriptor, 0o500 if git_mode == "100755" else 0o400)
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _materialize_execution_source(
    *,
    state_root: Path,
    repo_root: Path,
    source_revision: str,
    runner: CommandRunner,
) -> ExecutionSourceBinding:
    state = _canonical_absolute_path(state_root, require_exists=True)
    _verify_artifact_directory(state)
    destination = state / "source"
    if destination.exists() or destination.is_symlink():
        raise OperatorError("EXECUTION_SOURCE_ALREADY_EXISTS")
    epoch, entries = _git_execution_tree(repo_root, source_revision, runner)
    del epoch
    staging = state / f".source-staging-{uuid4().hex}"
    try:
        staging.mkdir(mode=0o700)
        environment = _minimal_subprocess_environment()
        for path, mode, object_id in entries:
            target = staging / path
            target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            try:
                payload = _validated_runner_bytes(
                    runner(
                        (_GIT, "cat-file", "blob", object_id),
                        cwd=repo_root,
                        environment=environment,
                        timeout_seconds=30,
                    ),
                    maximum=_MAX_EXECUTION_SOURCE_FILE_BYTES,
                    failure="EXECUTION_SOURCE_GIT_FAILED",
                )
            except OperatorError:
                raise
            except Exception as error:
                raise OperatorError("EXECUTION_SOURCE_GIT_FAILED") from error
            if _git_blob_object_id(payload) != object_id:
                raise OperatorError("EXECUTION_SOURCE_BLOB_DRIFT")
            _write_execution_source_file(target, payload, mode)
        directories = sorted(
            (path for path in staging.rglob("*") if path.is_dir()),
            key=lambda path: len(path.parts),
            reverse=True,
        )
        for directory_path in directories:
            directory_path.chmod(0o500)
        staging.chmod(0o500)
        os.rename(staging, destination)
        directory = os.open(
            state,
            os.O_RDONLY | os.O_CLOEXEC | os.O_DIRECTORY | os.O_NOFOLLOW,
        )
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    except OperatorError:
        if staging.exists():
            staging.chmod(0o700)
            for directory_path in staging.rglob("*"):
                if directory_path.is_dir():
                    directory_path.chmod(0o700)
            shutil.rmtree(staging)
        raise
    except OSError as error:
        if staging.exists():
            staging.chmod(0o700)
            for directory_path in staging.rglob("*"):
                if directory_path.is_dir():
                    directory_path.chmod(0o700)
            shutil.rmtree(staging)
        raise OperatorError("EXECUTION_SOURCE_WRITE_FAILED") from error
    return _capture_execution_source(
        state_root=state,
        repo_root=repo_root,
        source_revision=source_revision,
        runner=runner,
    )


def _verify_docker_socket() -> None:
    path = Path(_DOCKER_HOST.removeprefix("unix://"))
    try:
        metadata = os.lstat(path)
    except OSError as error:
        raise OperatorError("DOCKER_SOCKET_DRIFT") from error
    if (
        not stat.S_ISSOCK(metadata.st_mode)
        or metadata.st_uid != 0
        or metadata.st_gid != 114
        or stat.S_IMODE(metadata.st_mode) != 0o660
    ):
        raise OperatorError("DOCKER_SOCKET_DRIFT")


def _verify_docker_binary(repo_root: Path, runner: CommandRunner) -> None:
    _verify_root_owned_binary(Path(_DOCKER), _DOCKER_SHA256, "DOCKER_BINARY_DRIFT")
    _verify_docker_socket()
    command = (
        _DOCKER,
        "version",
        "--format",
        "{{.Client.Version}}|{{.Server.Version}}|{{.Server.Os}}|{{.Server.Arch}}",
    )
    try:
        output = _validated_runner_bytes(
            runner(
                command,
                cwd=repo_root,
                environment=_minimal_subprocess_environment(
                    (EnvironmentBinding(name="DOCKER_HOST", value=_DOCKER_HOST),)
                ),
                timeout_seconds=15,
            ),
            maximum=1_024,
            failure="DOCKER_BINARY_DRIFT",
        )
    except OperatorError:
        raise
    except Exception as error:
        raise OperatorError("DOCKER_BINARY_DRIFT") from error
    if output != b"29.6.2|29.6.2|linux|amd64\n":
        raise OperatorError("DOCKER_BINARY_DRIFT")


def _verify_gcloud_binary(repo_root: Path, runner: CommandRunner) -> None:
    _verify_root_owned_binary(
        Path(_DOCKER_CREDENTIAL_GCLOUD),
        _DOCKER_CREDENTIAL_GCLOUD_SHA256,
        "GCLOUD_CREDENTIAL_HELPER_DRIFT",
    )
    command = ("/usr/bin/gcloud", "version", "--format=json")
    try:
        output = _validated_runner_bytes(
            runner(
                command,
                cwd=repo_root,
                environment=_minimal_subprocess_environment(),
                timeout_seconds=15,
            ),
            maximum=65_536,
            failure="GCLOUD_BINARY_DRIFT",
        )
        value = json.loads(output, object_pairs_hook=_reject_duplicate_keys)
    except OperatorError:
        raise
    except Exception as error:
        raise OperatorError("GCLOUD_BINARY_DRIFT") from error
    if not isinstance(value, dict) or value.get("Google Cloud SDK") != _GCLOUD_VERSION:
        raise OperatorError("GCLOUD_BINARY_DRIFT")


def _parse_plan_json(
    data: bytes,
    *,
    allow_empty: bool = False,
) -> tuple[
    bytes,
    tuple[PlanResourceBinding, ...],
    tuple[PlanIamBinding, ...],
    set[str],
    dict[str, Any],
]:
    def reject_constant(_: str) -> None:
        raise ValueError("non-finite JSON number")

    try:
        value = json.loads(
            data,
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=reject_constant,
        )
    except OperatorError:
        raise
    except (UnicodeError, ValueError, TypeError) as error:
        raise OperatorError("TERRAFORM_PLAN_INVALID") from error
    if (
        not isinstance(value, dict)
        or value.get("terraform_version") != _TERRAFORM_VERSION
    ):
        raise OperatorError("TERRAFORM_PLAN_INVALID")
    variables = value.get("variables")
    changes = value.get("resource_changes")
    if allow_empty and changes is None:
        changes = []
    if (
        not isinstance(variables, dict)
        or any(
            not isinstance(name, str)
            or not isinstance(item, dict)
            or set(item) != {"value"}
            for name, item in variables.items()
        )
        or not isinstance(changes, list)
        or (not changes and not allow_empty)
    ):
        raise OperatorError("TERRAFORM_PLAN_INVALID")
    resources: list[PlanResourceBinding] = []
    iam_edges: list[PlanIamBinding] = []
    for raw in changes:
        if not isinstance(raw, dict):
            raise OperatorError("TERRAFORM_PLAN_INVALID")
        change = raw.get("change")
        actions = change.get("actions") if isinstance(change, dict) else None
        address = raw.get("address")
        resource_type = raw.get("type")
        provider_name = raw.get("provider_name")
        if (
            not isinstance(address, str)
            or not isinstance(resource_type, str)
            or not isinstance(provider_name, str)
            or not isinstance(actions, list)
            or not actions
            or any(not isinstance(item, str) for item in actions)
            or any(
                item not in {"create", "delete", "no-op", "read", "update"}
                for item in actions
            )
            or not (
                provider_name == _GOOGLE_PROVIDER_SOURCE
                or (
                    resource_type == "terraform_data"
                    and provider_name == _TERRAFORM_BUILTIN_PROVIDER_SOURCE
                )
            )
        ):
            raise OperatorError("TERRAFORM_PLAN_INVALID")
        before_unknown = change.get("reconcile_before_unknown")
        before_sensitive = change.get("before_sensitive")
        after_sensitive = change.get("after_sensitive")
        approved_before_sensitive = change.get("reconcile_before_sensitive")
        live_after_unknown = change.get("after_unknown")
        if before_unknown is not None and not _unknown_mask_valid_for_value(
            change.get("before"),
            before_unknown,
        ):
            raise OperatorError("TERRAFORM_PLAN_INVALID")
        sensitivity_masks = (
            before_sensitive,
            after_sensitive,
            approved_before_sensitive,
        )
        if any(
            value is not None
            and (not _valid_unknown_mask(value) or _mask_contains_true(value))
            for value in sensitivity_masks
        ):
            raise OperatorError("TERRAFORM_PLAN_INVALID")
        if live_after_unknown is not None and not _valid_unknown_mask(
            live_after_unknown
        ):
            raise OperatorError("TERRAFORM_PLAN_INVALID")
        if (
            actions != ["delete"]
            and live_after_unknown is not None
            and not (
                _unknown_mask_valid_for_value(
                    change.get("after"),
                    live_after_unknown,
                )
            )
        ):
            raise OperatorError("TERRAFORM_PLAN_INVALID")
        if actions == ["delete"] and (
            change.get("after") is not None or _mask_contains_true(live_after_unknown)
        ):
            raise OperatorError("TERRAFORM_PLAN_INVALID")
        resource = PlanResourceBinding(
            address=address,
            resource_type=resource_type,
            provider_name=provider_name,
            actions=tuple(actions),
            before_sha256=_hash_value(change.get("before")),
            after_sha256=_hash_value(change.get("after")),
            before_projection=change.get("before"),
            before_unknown=before_unknown,
        )
        resources.append(resource)
        if "_iam_" in resource_type:
            after = change.get("after")
            before = change.get("before")
            identity = after if isinstance(after, dict) else before
            if not isinstance(identity, dict):
                raise OperatorError("TERRAFORM_PLAN_INVALID")
            role = identity.get("role")
            member = identity.get("member")
            if role is not None and not isinstance(role, str):
                raise OperatorError("TERRAFORM_PLAN_INVALID")
            if member is not None and not isinstance(member, str):
                raise OperatorError("TERRAFORM_PLAN_INVALID")
            authority_keys = (
                "billing_account_id",
                "bucket",
                "condition",
                "location",
                "member",
                "project",
                "role",
                "service_account_id",
            )
            iam_identity: dict[str, JsonValue] = {
                key: identity[key] for key in authority_keys if key in identity
            }
            identity_unknown = (
                live_after_unknown if isinstance(after, dict) else before_unknown
            )
            iam_unknown: JsonValue | None = None
            if isinstance(identity_unknown, dict):
                iam_unknown = {
                    key: identity_unknown[key]
                    for key in authority_keys
                    if key in identity_unknown
                }
                if not iam_unknown:
                    iam_unknown = None
            if iam_unknown is not None and not _unknown_mask_valid_for_value(
                iam_identity,
                iam_unknown,
            ):
                raise OperatorError("TERRAFORM_PLAN_INVALID")
            iam_edges.append(
                PlanIamBinding(
                    address=address,
                    resource_type=resource_type,
                    actions=tuple(actions),
                    role=role,
                    member=member,
                    after_sha256=_hash_value(iam_identity),
                    authority_projection=iam_identity,
                    authority_unknown=iam_unknown,
                )
            )

    strings: set[str] = set()

    def collect(item: Any) -> None:
        if isinstance(item, str):
            strings.add(item)
        elif isinstance(item, list):
            for child in item:
                collect(child)
        elif isinstance(item, dict):
            for child in item.values():
                collect(child)

    collect(value)
    sorted_resources = tuple(sorted(resources, key=lambda item: item.address))
    sorted_iam = tuple(sorted(iam_edges, key=lambda item: item.address))
    projection = {
        "terraform_version": _TERRAFORM_VERSION,
        "variables": variables,
        "resources": [item.model_dump(mode="json") for item in sorted_resources],
        "iam_edges": [item.model_dump(mode="json") for item in sorted_iam],
    }
    rendered_variables = {name: item["value"] for name, item in variables.items()}
    return (
        _canonical_value_bytes(projection),
        sorted_resources,
        sorted_iam,
        strings,
        rendered_variables,
    )


def _capture_plan(
    *,
    action: Phase5Action,
    state_root: Path,
    required_runtime_values: set[str],
) -> TerraformPlanBinding:
    stack, stem = _PLAN_FILES[action.value]
    qualification_path = state_root / "plans" / f"{stem}.tfplan.json"
    variables_path = state_root / "plans" / f"{stem}.tfvars.json"
    execution_plan_path = state_root / "execution" / f"{stem}.tfplan"
    qualification = _read_bounded_file(
        qualification_path,
        maximum=_MAX_PLAN_JSON_BYTES,
        immutable=True,
    )
    variables = _read_bounded_file(
        variables_path,
        maximum=1_048_576,
        immutable=True,
    )
    try:
        variable_value = json.loads(
            variables,
            object_pairs_hook=_reject_duplicate_keys,
        )
    except OperatorError:
        raise
    except (UnicodeError, ValueError, TypeError) as error:
        raise OperatorError("TERRAFORM_VARIABLES_INVALID") from error
    if not isinstance(variable_value, dict) or variables != _canonical_value_bytes(
        variable_value
    ):
        raise OperatorError("TERRAFORM_VARIABLES_INVALID")
    try:
        qualification_value = json.loads(
            qualification,
            object_pairs_hook=_reject_duplicate_keys,
        )
        planned_variables = qualification_value.get("variables")
        if not isinstance(planned_variables, dict):
            raise OperatorError("TERRAFORM_VARIABLES_INVALID")
        rendered_variables = {
            name: item["value"]
            for name, item in planned_variables.items()
            if isinstance(name, str)
            and isinstance(item, dict)
            and set(item) == {"value"}
        }
    except OperatorError:
        raise
    except (KeyError, TypeError, ValueError) as error:
        raise OperatorError("TERRAFORM_VARIABLES_INVALID") from error
    if (
        len(rendered_variables) != len(planned_variables)
        or rendered_variables != variable_value
    ):
        raise OperatorError("TERRAFORM_VARIABLES_INVALID")
    normalized, resources, iam_edges, strings, _ = _parse_plan_json(qualification)
    variable_strings: set[str] = set()

    def collect(item: Any) -> None:
        if isinstance(item, str):
            variable_strings.add(item)
        elif isinstance(item, list):
            for child in item:
                collect(child)
        elif isinstance(item, dict):
            for child in item.values():
                collect(child)

    collect(variable_value)
    if action is Phase5Action.RUNTIME_APPLY and not required_runtime_values.issubset(
        strings | variable_strings
    ):
        raise OperatorError("RUNTIME_PLAN_IDENTITY_DRIFT")
    return TerraformPlanBinding(
        action=action,
        stack=stack,
        qualification_path=str(qualification_path),
        qualification_sha256=hashlib.sha256(qualification).hexdigest(),
        variables_path=str(variables_path),
        variables_sha256=hashlib.sha256(variables).hexdigest(),
        execution_plan_path=str(execution_plan_path),
        normalized_plan_sha256=hashlib.sha256(normalized).hexdigest(),
        resource_inventory_sha256=_hash_value(
            [item.model_dump(mode="json") for item in resources]
        ),
        iam_inventory_sha256=_hash_value(
            [item.model_dump(mode="json") for item in iam_edges]
        ),
        resources=resources,
        iam_edges=iam_edges,
    )


def _capture_image_artifact(
    *,
    state_root: Path,
    source_revision: str,
    expected_digest: str,
) -> ImageArtifactBinding:
    archive = state_root / "images" / "reconcile.oci.tar"
    archive_sha256 = _immutable_file_sha256(archive)
    try:
        with tarfile.open(archive, mode="r:*") as bundle:
            archive_index = _index_oci_archive(bundle)
            index = json.loads(
                _read_oci_archive_member(
                    bundle,
                    archive_index,
                    "index.json",
                    maximum=1_048_576,
                ),
                object_pairs_hook=_reject_duplicate_keys,
            )
            manifests = index.get("manifests") if isinstance(index, dict) else None
            if not isinstance(manifests, list) or len(manifests) != 1:
                raise OperatorError("OCI_IMAGE_INVALID")
            descriptor = manifests[0]
            digest = descriptor.get("digest") if isinstance(descriptor, dict) else None
            annotations = (
                descriptor.get("annotations") if isinstance(descriptor, dict) else None
            )
            source_tag = _oci_source_tag(source_revision)
            if (
                digest != expected_digest
                or not isinstance(annotations, dict)
                or annotations.get(_OCI_REFERENCE_ANNOTATION) != source_tag
            ):
                raise OperatorError("OCI_IMAGE_IDENTITY_DRIFT")
            algorithm, hexadecimal = expected_digest.split(":", 1)
            manifest_bytes = _read_oci_archive_member(
                bundle,
                archive_index,
                f"blobs/{algorithm}/{hexadecimal}",
                maximum=8 * 1_048_576,
            )
            if hashlib.sha256(manifest_bytes).hexdigest() != hexadecimal:
                raise OperatorError("OCI_IMAGE_IDENTITY_DRIFT")
            manifest = json.loads(
                manifest_bytes, object_pairs_hook=_reject_duplicate_keys
            )
            config = manifest.get("config") if isinstance(manifest, dict) else None
            config_digest = config.get("digest") if isinstance(config, dict) else None
            if (
                not isinstance(config_digest, str)
                or re.fullmatch(r"sha256:[0-9a-f]{64}", config_digest) is None
            ):
                raise OperatorError("OCI_IMAGE_INVALID")
            config_hexadecimal = config_digest.removeprefix("sha256:")
            config_bytes = _read_oci_archive_member(
                bundle,
                archive_index,
                f"blobs/sha256/{config_hexadecimal}",
                maximum=8 * 1_048_576,
            )
            if hashlib.sha256(config_bytes).hexdigest() != config_hexadecimal:
                raise OperatorError("OCI_IMAGE_IDENTITY_DRIFT")
    except OperatorError:
        raise
    except (
        EOFError,
        OSError,
        KeyError,
        ValueError,
        tarfile.TarError,
        zlib.error,
    ) as error:
        raise OperatorError("OCI_IMAGE_INVALID") from error
    immutable_reference = (
        f"{_REGION}-docker.pkg.dev/{_PROJECT_ID}/reconcile-p5/"
        f"reconcile@{expected_digest}"
    )
    return ImageArtifactBinding(
        archive_path=str(archive),
        archive_sha256=archive_sha256,
        source_tag=_image_source_tag(source_revision),
        manifest_digest=expected_digest,
        config_digest=config_digest,
        immutable_reference=immutable_reference,
    )


def _dependency_inventory_details(
    root: Path,
) -> tuple[int, int, int, str, tuple[dict[str, Any], ...]]:
    canonical = _canonical_absolute_path(root, require_exists=True)
    try:
        root_metadata = os.lstat(canonical)
    except OSError as error:
        raise OperatorError("PYTHON_DEPENDENCY_CLOSURE_INVALID") from error
    if (
        not stat.S_ISDIR(root_metadata.st_mode)
        or stat.S_ISLNK(root_metadata.st_mode)
        or root_metadata.st_uid != os.getuid()
        or stat.S_IMODE(root_metadata.st_mode) != 0o500
    ):
        raise OperatorError("PYTHON_DEPENDENCY_CLOSURE_INVALID")
    inventory: list[dict[str, Any]] = []
    byte_count = 0
    file_count = 0
    entry_count = 0
    try:
        for directory, names, filenames in os.walk(canonical, followlinks=False):
            current = Path(directory)
            directory_metadata = os.lstat(current)
            if (
                not stat.S_ISDIR(directory_metadata.st_mode)
                or stat.S_ISLNK(directory_metadata.st_mode)
                or directory_metadata.st_uid != os.getuid()
                or stat.S_IMODE(directory_metadata.st_mode) != 0o500
            ):
                raise OperatorError("PYTHON_DEPENDENCY_CLOSURE_INVALID")
            relative_directory = current.relative_to(canonical).as_posix()
            if relative_directory != ".":
                entry_count += 1
                if entry_count > _MAX_PYTHON_DEPENDENCY_ENTRIES:
                    raise OperatorError("PYTHON_DEPENDENCY_CLOSURE_TOO_LARGE")
                inventory.append(
                    {
                        "path": relative_directory,
                        "kind": "directory",
                    }
                )
            for name in names:
                child = current / name
                child_metadata = os.lstat(child)
                if not stat.S_ISDIR(child_metadata.st_mode) or stat.S_ISLNK(
                    child_metadata.st_mode
                ):
                    raise OperatorError("PYTHON_DEPENDENCY_CLOSURE_INVALID")
            for name in filenames:
                path = current / name
                relative = path.relative_to(canonical).as_posix()
                try:
                    descriptor = os.open(
                        path,
                        os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW,
                    )
                except OSError as error:
                    raise OperatorError("PYTHON_DEPENDENCY_CLOSURE_INVALID") from error
                try:
                    before = os.fstat(descriptor)
                    if (
                        not stat.S_ISREG(before.st_mode)
                        or before.st_uid != os.getuid()
                        or stat.S_IMODE(before.st_mode) != 0o400
                        or before.st_nlink != 1
                        or before.st_size > _MAX_EXECUTION_SOURCE_FILE_BYTES
                    ):
                        raise OperatorError("PYTHON_DEPENDENCY_CLOSURE_INVALID")
                    digest = hashlib.sha256()
                    observed = 0
                    while chunk := os.read(descriptor, 1_048_576):
                        observed += len(chunk)
                        if observed > _MAX_EXECUTION_SOURCE_FILE_BYTES:
                            raise OperatorError("PYTHON_DEPENDENCY_CLOSURE_INVALID")
                        digest.update(chunk)
                    after = os.fstat(descriptor)
                    if observed != before.st_size or (
                        after.st_dev,
                        after.st_ino,
                        after.st_size,
                        after.st_mtime_ns,
                        after.st_ctime_ns,
                        after.st_mode,
                        after.st_uid,
                        after.st_nlink,
                    ) != (
                        before.st_dev,
                        before.st_ino,
                        before.st_size,
                        before.st_mtime_ns,
                        before.st_ctime_ns,
                        before.st_mode,
                        before.st_uid,
                        before.st_nlink,
                    ):
                        raise OperatorError(
                            "PYTHON_DEPENDENCY_CLOSURE_CHANGED_DURING_READ"
                        )
                finally:
                    os.close(descriptor)
                byte_count += observed
                file_count += 1
                entry_count += 1
                inventory.append(
                    {
                        "path": relative,
                        "kind": "file",
                        "byte_count": observed,
                        "sha256": digest.hexdigest(),
                    }
                )
                if (
                    file_count > _MAX_PYTHON_DEPENDENCY_FILES
                    or entry_count > _MAX_PYTHON_DEPENDENCY_ENTRIES
                    or byte_count > _MAX_PYTHON_DEPENDENCY_BYTES
                ):
                    raise OperatorError("PYTHON_DEPENDENCY_CLOSURE_TOO_LARGE")
    except OperatorError:
        raise
    except OSError as error:
        raise OperatorError("PYTHON_DEPENDENCY_CLOSURE_INVALID") from error
    inventory.sort(key=lambda item: item["path"])
    if file_count < 1:
        raise OperatorError("PYTHON_DEPENDENCY_CLOSURE_EMPTY")
    return (
        file_count,
        entry_count,
        byte_count,
        _hash_value(inventory),
        tuple(inventory),
    )


def _dependency_inventory(root: Path) -> tuple[int, int, int, str]:
    file_count, entry_count, byte_count, aggregate, _ = _dependency_inventory_details(
        root
    )
    return file_count, entry_count, byte_count, aggregate


def _capture_python_dependencies(
    *,
    state_root: Path,
    image_artifact: ImageArtifactBinding,
    python_lock_sha256: str,
    dependency_root: Path | None = None,
) -> PythonDependencyBinding:
    root = dependency_root or state_root / "python-dependencies"
    file_count, entry_count, byte_count, aggregate = _dependency_inventory(root)
    return PythonDependencyBinding(
        root=str(root),
        source_image_digest=image_artifact.manifest_digest,
        source_archive_sha256=image_artifact.archive_sha256,
        python_lock_sha256=python_lock_sha256,
        file_count=file_count,
        entry_count=entry_count,
        byte_count=byte_count,
        sha256=aggregate,
    )


def _verify_python_dependency_binding(binding: PythonDependencyBinding) -> None:
    observed = _dependency_inventory(Path(binding.root))
    if observed != (
        binding.file_count,
        binding.entry_count,
        binding.byte_count,
        binding.sha256,
    ):
        raise OperatorError("PYTHON_DEPENDENCY_CLOSURE_DRIFT")


def _verify_python_dependency_runtime(
    *,
    source_root: Path,
    binding: PythonDependencyBinding,
    runner: CommandRunner,
) -> None:
    _verify_python_interpreter()
    _verify_python_dependency_binding(binding)
    dependency_root = Path(binding.root)
    if ":" in str(source_root) or ":" in str(dependency_root):
        raise OperatorError("PYTHON_IMPORT_PATH_INVALID")
    probe = (
        "import pathlib,sys;"
        "import grpc,pydantic_core,reconcile,textual;"
        "source=pathlib.Path(sys.argv[1]).resolve();"
        "deps=pathlib.Path(sys.argv[2]).resolve();"
        "paths=[pathlib.Path(module.__file__).resolve() "
        "for module in (grpc,pydantic_core,textual)];"
        "reconcile_path=pathlib.Path(reconcile.__file__).resolve();"
        "ok=(sys.flags.no_site==1 and reconcile_path.is_relative_to(source) "
        "and all(path.is_relative_to(deps) for path in paths));"
        "raise SystemExit(0 if ok else 1)"
    )
    environment = _minimal_subprocess_environment(
        (
            EnvironmentBinding(
                name="PYTHONPATH", value=f"{source_root}:{dependency_root}"
            ),
        )
    )
    try:
        result = runner(
            (_PYTHON, "-P", "-S", "-c", probe, str(source_root), str(dependency_root)),
            cwd=source_root,
            environment=environment,
            timeout_seconds=30,
        )
        output = _validated_runner_bytes(
            result,
            maximum=1_024,
            failure="PYTHON_DEPENDENCY_RUNTIME_INVALID",
        )
    except OperatorError:
        raise
    except Exception as error:
        raise OperatorError("PYTHON_DEPENDENCY_RUNTIME_INVALID") from error
    if output:
        raise OperatorError("PYTHON_DEPENDENCY_RUNTIME_INVALID")


def _index_oci_archive(archive: tarfile.TarFile) -> dict[str, tarfile.TarInfo]:
    members: dict[str, tarfile.TarInfo] = {}
    for member in archive:
        if len(members) >= _MAX_OCI_ARCHIVE_MEMBERS:
            raise OperatorError("OCI_IMAGE_INVALID")
        raw_name = (
            member.name[:-1]
            if member.isdir() and member.name.endswith("/")
            else member.name
        )
        path = _canonical_oci_path(raw_name).as_posix()
        if path in members or not (member.isfile() or member.isdir()):
            raise OperatorError("OCI_IMAGE_INVALID")
        members[path] = member
    return members


def _read_oci_archive_member(
    archive: tarfile.TarFile,
    members: Mapping[str, tarfile.TarInfo],
    name: str,
    *,
    maximum: int,
) -> bytes:
    member = members.get(name)
    if (
        member is None
        or not member.isfile()
        or type(member.size) is not int
        or member.size < 0
        or member.size > maximum
    ):
        raise OperatorError("OCI_IMAGE_INVALID")
    source = archive.extractfile(member)
    if source is None:
        raise OperatorError("OCI_IMAGE_INVALID")
    payload = source.read(maximum + 1)
    if len(payload) != member.size:
        raise OperatorError("OCI_IMAGE_INVALID")
    return payload


def _canonical_oci_path(
    value: str,
    *,
    allow_non_ascii: bool = False,
) -> PurePosixPath:
    raw = value[2:] if value.startswith("./") else value
    try:
        raw.encode("utf-8", errors="strict")
        path = PurePosixPath(raw)
    except (UnicodeError, ValueError) as error:
        raise OperatorError("OCI_IMAGE_INVALID") from error
    invalid_character = (
        any(not character.isprintable() or character.isspace() for character in raw)
        if allow_non_ascii
        else any(not 0x21 <= ord(character) <= 0x7E for character in raw)
    )
    if (
        not raw
        or len(raw) > 4096
        or raw.startswith("./")
        or "\\" in raw
        or invalid_character
        or path.is_absolute()
        or path.as_posix() != raw
        or len(path.parts) > _MAX_OCI_PATH_COMPONENTS
        or any(part in {"", ".", ".."} for part in path.parts)
    ):
        raise OperatorError("OCI_IMAGE_INVALID")
    return path


def _whiteout_affects_python_dependencies(path: PurePosixPath) -> bool:
    name = path.name
    if not name.startswith(".wh."):
        return False
    parent = path.parent
    if name == ".wh..wh..opq":
        target = parent
    else:
        target = parent / name.removeprefix(".wh.")
    prefix = _PYTHON_DEPENDENCY_PREFIX
    return target == prefix or target in prefix.parents or prefix in target.parents


def _materialize_python_dependencies(
    *,
    state_root: Path,
    image_artifact: ImageArtifactBinding,
    python_lock_sha256: str,
    destination_name: str = "python-dependencies",
) -> PythonDependencyBinding:
    state = _canonical_absolute_path(state_root, require_exists=True)
    _verify_artifact_directory(state)
    if (
        destination_name != "python-dependencies"
        and re.fullmatch(
            r"[.]python-dependencies-derived-[0-9a-f]{32}", destination_name
        )
        is None
    ):
        raise OperatorError("PYTHON_DEPENDENCY_DESTINATION_INVALID")
    destination = state / destination_name
    if destination.exists() or destination.is_symlink():
        raise OperatorError("PYTHON_DEPENDENCY_CLOSURE_ALREADY_EXISTS")
    staging = state / f".python-dependencies-{uuid4().hex}"
    scratch = state / f".python-dependency-layers-{uuid4().hex}"
    archive_path = Path(image_artifact.archive_path)
    if _immutable_file_sha256(archive_path) != image_artifact.archive_sha256:
        raise OperatorError("OCI_IMAGE_IDENTITY_DRIFT")
    total_files = 0
    total_bytes = 0
    contributing_layer: int | None = None
    dependency_paths: set[str] = set()
    dependency_entries: set[str] = set()
    try:
        staging.mkdir(mode=0o700)
        scratch.mkdir(mode=0o700)
        with tarfile.open(archive_path, mode="r:*") as archive:
            archive_index = _index_oci_archive(archive)
            index = json.loads(
                _read_oci_archive_member(
                    archive,
                    archive_index,
                    "index.json",
                    maximum=1_048_576,
                ),
                object_pairs_hook=_reject_duplicate_keys,
            )
            manifests = index.get("manifests") if isinstance(index, dict) else None
            if not isinstance(manifests, list) or len(manifests) != 1:
                raise OperatorError("OCI_IMAGE_INVALID")
            descriptor = manifests[0]
            manifest_digest = (
                descriptor.get("digest") if isinstance(descriptor, dict) else None
            )
            manifest_size = (
                descriptor.get("size") if isinstance(descriptor, dict) else None
            )
            if (
                manifest_digest != image_artifact.manifest_digest
                or type(manifest_size) is not int
                or manifest_size < 1
                or manifest_size > 8 * 1_048_576
            ):
                raise OperatorError("OCI_IMAGE_INVALID")
            hexadecimal = manifest_digest.removeprefix("sha256:")
            manifest_payload = _read_oci_archive_member(
                archive,
                archive_index,
                f"blobs/sha256/{hexadecimal}",
                maximum=8 * 1_048_576,
            )
            if (
                len(manifest_payload) != manifest_size
                or hashlib.sha256(manifest_payload).hexdigest() != hexadecimal
            ):
                raise OperatorError("OCI_IMAGE_IDENTITY_DRIFT")
            manifest = json.loads(
                manifest_payload,
                object_pairs_hook=_reject_duplicate_keys,
            )
            layers = manifest.get("layers") if isinstance(manifest, dict) else None
            if (
                not isinstance(layers, list)
                or not layers
                or len(layers) > _MAX_OCI_IMAGE_LAYERS
            ):
                raise OperatorError("OCI_IMAGE_INVALID")
            aggregate_blob_bytes = 0
            for layer in layers:
                size = layer.get("size") if isinstance(layer, dict) else None
                if type(size) is not int or size < 1:
                    raise OperatorError("OCI_IMAGE_INVALID")
                aggregate_blob_bytes += size
                if aggregate_blob_bytes > _MAX_OCI_AGGREGATE_LAYER_BLOB_BYTES:
                    raise OperatorError("OCI_IMAGE_INVALID")
            aggregate_uncompressed_bytes = 0
            aggregate_tar_bytes = 0
            aggregate_member_count = 0
            for index_value, layer in enumerate(layers):
                digest = layer.get("digest") if isinstance(layer, dict) else None
                size = layer.get("size") if isinstance(layer, dict) else None
                media_type = layer.get("mediaType") if isinstance(layer, dict) else None
                if (
                    not isinstance(digest, str)
                    or re.fullmatch(r"sha256:[0-9a-f]{64}", digest) is None
                    or type(size) is not int
                    or size < 1
                    or size > _MAX_OCI_LAYER_BLOB_BYTES
                    or media_type
                    not in {
                        "application/vnd.oci.image.layer.v1.tar",
                        "application/vnd.oci.image.layer.v1.tar+gzip",
                    }
                ):
                    raise OperatorError("OCI_IMAGE_INVALID")
                layer_hexadecimal = digest.removeprefix("sha256:")
                member_name = f"blobs/sha256/{layer_hexadecimal}"
                layer_member = archive_index.get(member_name)
                if (
                    layer_member is None
                    or not layer_member.isfile()
                    or layer_member.size != size
                ):
                    raise OperatorError("OCI_IMAGE_INVALID")
                layer_source = archive.extractfile(layer_member)
                if layer_source is None:
                    raise OperatorError("OCI_IMAGE_INVALID")
                layer_path = scratch / f"layer-{index_value}.tar"
                digest_value = hashlib.sha256()
                copied = 0
                with layer_path.open("xb") as layer_output:
                    while chunk := layer_source.read(1_048_576):
                        copied += len(chunk)
                        if copied > _MAX_OCI_LAYER_BLOB_BYTES:
                            raise OperatorError("OCI_IMAGE_INVALID")
                        digest_value.update(chunk)
                        layer_output.write(chunk)
                if copied != size or digest_value.hexdigest() != layer_hexadecimal:
                    raise OperatorError("OCI_IMAGE_IDENTITY_DRIFT")
                expanded_path: Path | None = None
                tar_path = layer_path
                if media_type.endswith("+gzip"):
                    expanded_path = scratch / f"layer-{index_value}-expanded.tar"
                    expanded = 0
                    with gzip.open(layer_path, mode="rb") as compressed_source:
                        with expanded_path.open("xb") as expanded_output:
                            while chunk := compressed_source.read(1_048_576):
                                expanded += len(chunk)
                                if (
                                    expanded > _MAX_OCI_LAYER_TAR_BYTES
                                    or aggregate_tar_bytes + expanded
                                    > _MAX_OCI_AGGREGATE_TAR_BYTES
                                ):
                                    raise OperatorError("OCI_IMAGE_INVALID")
                                expanded_output.write(chunk)
                    tar_path = expanded_path
                elif layer_path.stat().st_size > _MAX_OCI_LAYER_TAR_BYTES:
                    raise OperatorError("OCI_IMAGE_INVALID")
                aggregate_tar_bytes += tar_path.stat().st_size
                if aggregate_tar_bytes > _MAX_OCI_AGGREGATE_TAR_BYTES:
                    raise OperatorError("OCI_IMAGE_INVALID")
                with tarfile.open(tar_path, mode="r:") as layer_archive:
                    layer_members: list[tarfile.TarInfo] = []
                    declared_bytes = 0
                    for item in layer_archive:
                        if len(layer_members) >= _MAX_OCI_LAYER_MEMBERS:
                            raise OperatorError("OCI_IMAGE_INVALID")
                        if type(item.size) is not int or item.size < 0:
                            raise OperatorError("OCI_IMAGE_INVALID")
                        declared_bytes += item.size
                        if declared_bytes > _MAX_OCI_LAYER_UNCOMPRESSED_BYTES:
                            raise OperatorError("OCI_IMAGE_INVALID")
                        layer_members.append(item)
                    aggregate_member_count += len(layer_members)
                    if aggregate_member_count > _MAX_OCI_AGGREGATE_MEMBERS:
                        raise OperatorError("OCI_IMAGE_INVALID")
                    aggregate_uncompressed_bytes += declared_bytes
                    if (
                        aggregate_uncompressed_bytes
                        > _MAX_OCI_AGGREGATE_UNCOMPRESSED_BYTES
                    ):
                        raise OperatorError("OCI_IMAGE_INVALID")
                    for item in layer_members:
                        contains_non_ascii = any(
                            ord(character) > 0x7E for character in item.name
                        )
                        path = _canonical_oci_path(
                            item.name,
                            allow_non_ascii=contains_non_ascii,
                        )
                        if contains_non_ascii:
                            if (
                                path == _PYTHON_DEPENDENCY_PREFIX
                                or path in _PYTHON_DEPENDENCY_PREFIX.parents
                                or _PYTHON_DEPENDENCY_PREFIX in path.parents
                            ):
                                raise OperatorError("OCI_IMAGE_INVALID")
                            continue
                        if _whiteout_affects_python_dependencies(path):
                            raise OperatorError("PYTHON_DEPENDENCY_CLOSURE_INVALID")
                        if (
                            path == _PYTHON_DEPENDENCY_PREFIX
                            or path in _PYTHON_DEPENDENCY_PREFIX.parents
                        ) and not item.isdir():
                            raise OperatorError("PYTHON_DEPENDENCY_CLOSURE_INVALID")
                        try:
                            relative = path.relative_to(_PYTHON_DEPENDENCY_PREFIX)
                        except ValueError:
                            continue
                        if relative == PurePosixPath("."):
                            continue
                        if contributing_layer not in {None, index_value}:
                            raise OperatorError("PYTHON_DEPENDENCY_CLOSURE_INVALID")
                        contributing_layer = index_value
                        normalized = relative.as_posix()
                        if normalized in dependency_paths:
                            raise OperatorError("PYTHON_DEPENDENCY_CLOSURE_INVALID")
                        dependency_paths.add(normalized)
                        for depth in range(1, len(relative.parts) + 1):
                            dependency_entries.add(
                                PurePosixPath(*relative.parts[:depth]).as_posix()
                            )
                        if len(dependency_entries) > _MAX_PYTHON_DEPENDENCY_ENTRIES:
                            raise OperatorError("PYTHON_DEPENDENCY_CLOSURE_TOO_LARGE")
                        target = staging.joinpath(*relative.parts)
                        if item.isdir():
                            if target.exists() and not target.is_dir():
                                raise OperatorError("PYTHON_DEPENDENCY_CLOSURE_INVALID")
                            target.mkdir(mode=0o700, parents=True, exist_ok=True)
                            continue
                        if (
                            not item.isreg()
                            or bool(getattr(item, "sparse", None))
                            or item.size > _MAX_EXECUTION_SOURCE_FILE_BYTES
                        ):
                            raise OperatorError("PYTHON_DEPENDENCY_CLOSURE_INVALID")
                        if target.exists() or target.is_symlink():
                            raise OperatorError("PYTHON_DEPENDENCY_CLOSURE_INVALID")
                        target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
                        extracted = layer_archive.extractfile(item)
                        if extracted is None:
                            raise OperatorError("PYTHON_DEPENDENCY_CLOSURE_INVALID")
                        descriptor_fd = os.open(
                            target,
                            os.O_WRONLY
                            | os.O_CREAT
                            | os.O_EXCL
                            | os.O_CLOEXEC
                            | os.O_NOFOLLOW,
                            0o600,
                        )
                        try:
                            observed = 0
                            while chunk := extracted.read(1_048_576):
                                observed += len(chunk)
                                if observed > item.size:
                                    raise OperatorError(
                                        "PYTHON_DEPENDENCY_CLOSURE_INVALID"
                                    )
                                view = memoryview(chunk)
                                while view:
                                    written = os.write(descriptor_fd, view)
                                    if written < 1:
                                        raise OperatorError(
                                            "PYTHON_DEPENDENCY_CLOSURE_INVALID"
                                        )
                                    view = view[written:]
                            if observed != item.size:
                                raise OperatorError("PYTHON_DEPENDENCY_CLOSURE_INVALID")
                            os.fchmod(descriptor_fd, 0o400)
                            os.fsync(descriptor_fd)
                        finally:
                            os.close(descriptor_fd)
                        total_files += 1
                        total_bytes += item.size
                        if (
                            total_files > _MAX_PYTHON_DEPENDENCY_FILES
                            or total_bytes > _MAX_PYTHON_DEPENDENCY_BYTES
                        ):
                            raise OperatorError("PYTHON_DEPENDENCY_CLOSURE_TOO_LARGE")
                if expanded_path is not None:
                    expanded_path.unlink()
                layer_path.unlink()
        scratch.rmdir()
        if total_files < 1 or total_bytes < 1:
            raise OperatorError("PYTHON_DEPENDENCY_CLOSURE_EMPTY")
        directories = sorted(
            (path for path in staging.rglob("*") if path.is_dir()),
            key=lambda path: len(path.parts),
            reverse=True,
        )
        for directory_path in directories:
            directory_path.chmod(0o500)
        staging.chmod(0o500)
        os.rename(staging, destination)
        directory = os.open(
            state,
            os.O_RDONLY | os.O_CLOEXEC | os.O_DIRECTORY | os.O_NOFOLLOW,
        )
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    except OperatorError:
        if scratch.exists():
            shutil.rmtree(scratch)
        if staging.exists():
            for path in staging.rglob("*"):
                if path.is_dir():
                    path.chmod(0o700)
                elif path.is_file():
                    path.chmod(0o600)
            staging.chmod(0o700)
            shutil.rmtree(staging)
        raise
    except (
        EOFError,
        OSError,
        RecursionError,
        ValueError,
        TypeError,
        tarfile.TarError,
        zlib.error,
    ) as error:
        if scratch.exists():
            shutil.rmtree(scratch)
        if staging.exists():
            for path in staging.rglob("*"):
                if path.is_dir():
                    path.chmod(0o700)
                elif path.is_file():
                    path.chmod(0o600)
            staging.chmod(0o700)
            shutil.rmtree(staging)
        raise OperatorError("PYTHON_DEPENDENCY_CLOSURE_INVALID") from error
    if _immutable_file_sha256(archive_path) != image_artifact.archive_sha256:
        raise OperatorError("OCI_IMAGE_IDENTITY_DRIFT")
    return _capture_python_dependencies(
        state_root=state,
        image_artifact=image_artifact,
        python_lock_sha256=python_lock_sha256,
        dependency_root=destination,
    )


def _remove_python_dependency_tree(root: Path) -> None:
    try:
        metadata = os.lstat(root)
        if not stat.S_ISDIR(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
            raise OperatorError("PYTHON_DEPENDENCY_CLOSURE_INVALID")
        paths = sorted(
            root.rglob("*"),
            key=lambda path: len(path.parts),
            reverse=True,
        )
        for path in paths:
            metadata = os.lstat(path)
            if stat.S_ISDIR(metadata.st_mode) and not stat.S_ISLNK(metadata.st_mode):
                path.chmod(0o700)
            elif stat.S_ISREG(metadata.st_mode) and not stat.S_ISLNK(metadata.st_mode):
                path.chmod(0o600)
            else:
                raise OperatorError("PYTHON_DEPENDENCY_CLOSURE_INVALID")
        root.chmod(0o700)
        shutil.rmtree(root)
    except OperatorError:
        raise
    except OSError as error:
        raise OperatorError("PYTHON_DEPENDENCY_CLOSURE_INVALID") from error


def _verify_python_dependency_derivation(
    *,
    state_root: Path,
    source_root: Path,
    image_artifact: ImageArtifactBinding,
    python_lock_sha256: str,
    runner: CommandRunner,
) -> PythonDependencyBinding:
    approved = _capture_python_dependencies(
        state_root=state_root,
        image_artifact=image_artifact,
        python_lock_sha256=python_lock_sha256,
    )
    destination_name = f".python-dependencies-derived-{uuid4().hex}"
    derived_root = state_root / destination_name
    try:
        derived = _materialize_python_dependencies(
            state_root=state_root,
            image_artifact=image_artifact,
            python_lock_sha256=python_lock_sha256,
            destination_name=destination_name,
        )
        approved_identity = approved.model_dump(mode="json", exclude={"root"})
        derived_identity = derived.model_dump(mode="json", exclude={"root"})
        if derived_identity != approved_identity:
            raise OperatorError("PYTHON_DEPENDENCY_PROVENANCE_INVALID")
        _verify_python_dependency_runtime(
            source_root=source_root,
            binding=derived,
            runner=runner,
        )
    finally:
        if derived_root.exists() or derived_root.is_symlink():
            _remove_python_dependency_tree(derived_root)
    return approved


def _capture_artifact_bindings(
    draft: Phase5ManifestDraft,
    *,
    state_root: Path,
    repo_root: Path,
    runner: CommandRunner,
) -> dict[str, Any]:
    repository = _canonical_absolute_path(repo_root, require_exists=True)
    state = _canonical_absolute_path(state_root, require_exists=True)
    for relative in (
        "docker",
        "execution",
        "images",
        "plans",
        "state",
        "terraform-data",
        "terraform-data/bootstrap",
        "terraform-data/foundation",
        "terraform-data/runtime",
    ):
        _verify_artifact_directory(state / relative)
    execution_source = _capture_execution_source(
        state_root=state,
        repo_root=repository,
        source_revision=draft.source_revision,
        runner=runner,
    )
    root = Path(execution_source.root)
    terraform_cli_config = state / "terraform.rc"
    _verify_immutable_empty_file(
        terraform_cli_config,
        failure="TERRAFORM_CLI_CONFIG_DRIFT",
    )
    _verify_python_interpreter()
    semantic_sources = _capture_semantic_sources(root)
    terraform_stacks = _capture_terraform_stacks(root)
    infrastructure_revision = _hash_value(
        [item.model_dump(mode="json") for item in terraform_stacks]
    )
    prompt_version, prompt_sha256 = _planner_prompt_identity(root)
    project_binding = _source_file_binding(root, root / "pyproject.toml")
    lock_binding = _source_file_binding(root, root / "uv.lock")
    image_artifact = _capture_image_artifact(
        state_root=state,
        source_revision=draft.source_revision,
        expected_digest=draft.image_digest,
    )
    python_dependencies = _verify_python_dependency_derivation(
        state_root=state,
        source_root=root,
        image_artifact=image_artifact,
        python_lock_sha256=lock_binding.sha256,
        runner=runner,
    )
    _verify_terraform_binary(
        root,
        runner,
        cli_config=state / "terraform.rc",
    )
    required_runtime_values = {
        draft.source_revision,
        draft.image_digest,
        image_artifact.immutable_reference,
        infrastructure_revision,
        semantic_sources.sha256,
        prompt_version,
        prompt_sha256,
        _canonical_utc_timestamp(draft.created_at),
    }
    plans = tuple(
        sorted(
            (
                _capture_plan(
                    action=Phase5Action(action),
                    state_root=state,
                    required_runtime_values=required_runtime_values,
                )
                for action in _PLAN_FILES
            ),
            key=lambda item: item.action.value,
        )
    )
    return {
        "operator_state_root": str(state),
        "execution_source": execution_source,
        "python_dependencies": python_dependencies,
        "terraform_cli_config_path": str(terraform_cli_config),
        "terraform_cli_config_sha256": _EMPTY_SHA256,
        "infrastructure_revision": infrastructure_revision,
        "terraform_stacks": terraform_stacks,
        "terraform_plans": plans,
        "semantic_sources": semantic_sources,
        "python_project_sha256": project_binding.sha256,
        "python_lock_sha256": lock_binding.sha256,
        "image_artifact": image_artifact,
        "semantic_config_sha256": semantic_sources.sha256,
        "prompt_sha256": prompt_sha256,
        "prompt_version": prompt_version,
        "resource_inventory_sha256": _resource_inventory_hash(plans),
        "iam_inventory_sha256": _iam_inventory_hash(plans),
        "plan_inventory_sha256": _plan_inventory_hash(plans),
    }


def build_manifest(
    draft: Phase5ManifestDraft,
    *,
    state_root: Path,
    repo_root: Path,
    runner: CommandRunner,
) -> Phase5ApprovalManifest:
    artifacts = _capture_artifact_bindings(
        draft,
        state_root=state_root,
        repo_root=repo_root,
        runner=runner,
    )
    image_reference = (
        f"{_REGION}-docker.pkg.dev/{_PROJECT_ID}/reconcile-p5/"
        f"reconcile@{draft.image_digest}"
    )
    runtime_source_sha256, runtime_variables_sha256 = _runtime_acceptance_hashes(
        artifacts["terraform_stacks"],
        artifacts["terraform_plans"],
    )
    return _seal(
        Phase5ApprovalManifest,
        schema_version=_SCHEMA,
        record_type="approval-manifest",
        source_revision=draft.source_revision,
        origin_url=_ORIGIN_URL,
        **artifacts,
        image_digest=draft.image_digest,
        image_reference=image_reference,
        project_id=_PROJECT_ID,
        project_number=_PROJECT_NUMBER,
        region=_REGION,
        authenticated_exposure=_fixed_exposure(),
        terraform_version=_TERRAFORM_VERSION,
        terraform_executable=_TERRAFORM,
        terraform_binary_sha256=_TERRAFORM_SHA256,
        gcloud_version=_GCLOUD_VERSION,
        git_version=_GIT_VERSION,
        git_binary_sha256=_GIT_SHA256,
        python_version=_PYTHON_VERSION,
        python_interpreter=_PYTHON,
        python_interpreter_sha256=_PYTHON_SHA256,
        docker_client_sha256=_DOCKER_SHA256,
        docker_credential_gcloud_sha256=_DOCKER_CREDENTIAL_GCLOUD_SHA256,
        provider_source=_GOOGLE_PROVIDER_SOURCE,
        provider_version=_GOOGLE_PROVIDER_VERSION,
        gemini_model=_GEMINI_MODEL,
        vertex_location=_VERTEX_LOCATION,
        count_tokens_attempt_limit=1,
        billed_generation_limit=1,
        input_token_limit=12_000,
        output_token_limit=4_096,
        thinking_level="MINIMAL",
        authorization_estimate_usd=_AUTHORIZATION_ESTIMATE,
        contingency_authorization_estimate_usd=(_CONTINGENCY_AUTHORIZATION_ESTIMATE),
        estimate_kind="authorization-estimate-not-hard-cap",
        created_at=draft.created_at,
        work_deadline=draft.work_deadline,
        approval_expires_at=draft.approval_expires_at,
        commands=_fixed_commands(
            draft.source_revision,
            draft.image_digest,
            artifacts["infrastructure_revision"],
            artifacts["semantic_config_sha256"],
            runtime_source_sha256=runtime_source_sha256,
            runtime_variables_sha256=runtime_variables_sha256,
            state_root=state_root,
            image_archive=Path(artifacts["image_artifact"].archive_path),
        ),
    )


def _write_private_draft(path: Path, draft: Phase5ManifestDraft) -> None:
    canonical = _canonical_absolute_path(path, require_exists=False)
    _verify_artifact_directory(canonical.parent)
    data = _canonical_model_bytes(draft)
    try:
        descriptor = os.open(
            canonical,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW,
            0o600,
        )
    except FileExistsError as error:
        raise OperatorError("DRAFT_ALREADY_EXISTS") from error
    except OSError as error:
        raise OperatorError("DRAFT_WRITE_FAILED") from error
    try:
        offset = 0
        while offset < len(data):
            written = os.write(descriptor, data[offset:])
            if written < 1:
                raise OperatorError("DRAFT_WRITE_FAILED")
            offset += written
        os.fchmod(descriptor, 0o600)
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    directory = os.open(
        canonical.parent,
        os.O_RDONLY | os.O_CLOEXEC | os.O_DIRECTORY | os.O_NOFOLLOW,
    )
    try:
        os.fsync(directory)
    finally:
        os.close(directory)


def _verify_preparation_state_empty(state: Phase5StateStore) -> None:
    expected_root = {
        "docker",
        "execution",
        "images",
        "plans",
        "state",
        "terraform-data",
    }
    expected_terraform_data = {"bootstrap", "foundation", "runtime"}
    try:
        if {path.name for path in state.root.iterdir()} != expected_root:
            raise OperatorError("PREPARATION_STATE_NOT_EMPTY")
        terraform_data = state.root / "terraform-data"
        if {path.name for path in terraform_data.iterdir()} != expected_terraform_data:
            raise OperatorError("PREPARATION_STATE_NOT_EMPTY")
        leaves = (
            state.root / "docker",
            state.root / "execution",
            state.root / "images",
            state.root / "plans",
            state.root / "state",
            *(terraform_data / name for name in sorted(expected_terraform_data)),
        )
        if any(any(path.iterdir()) for path in leaves):
            raise OperatorError("PREPARATION_STATE_NOT_EMPTY")
    except OperatorError:
        raise
    except OSError as error:
        raise OperatorError("PREPARATION_STATE_NOT_EMPTY") from error


def _prepare_container_from_snapshot(
    *,
    source_root: Path,
    source_revision: str,
    source_date_epoch: int,
    artifact_output: Path,
    runner: CommandRunner,
) -> tuple[str, str]:
    _verify_python_interpreter()
    command = (
        _PYTHON,
        "-P",
        "-S",
        "-m",
        "scripts.check_phase5_container",
        "--source-revision",
        source_revision,
        "--require-daemon",
        "--artifact-output",
        str(artifact_output),
        "--docker-executable",
        _DOCKER,
        "--docker-host",
        _DOCKER_HOST,
        "--source-root",
        str(source_root),
        "--source-date-epoch",
        str(source_date_epoch),
    )
    try:
        output = _validated_runner_bytes(
            runner(
                command,
                cwd=source_root,
                environment=_minimal_subprocess_environment(
                    (EnvironmentBinding(name="PYTHONPATH", value=str(source_root)),)
                ),
                timeout_seconds=7_200,
            ),
            maximum=65_536,
            failure="CONTAINER_PREPARATION_FAILED",
        )
        value = json.loads(output, object_pairs_hook=_reject_duplicate_keys)
    except OperatorError:
        raise
    except (TypeError, ValueError) as error:
        raise OperatorError("CONTAINER_PREPARATION_FAILED") from error
    image_digest = value.get("image_digest") if isinstance(value, dict) else None
    source_tag = value.get("source_tag") if isinstance(value, dict) else None
    if (
        not isinstance(value, dict)
        or value.get("status") != "passed"
        or not isinstance(image_digest, str)
        or re.fullmatch(r"sha256:[0-9a-f]{64}", image_digest) is None
        or source_tag != _image_source_tag(source_revision)
    ):
        raise OperatorError("CONTAINER_PREPARATION_FAILED")
    return image_digest, source_tag


def _prepare_terraform_from_snapshot(
    *,
    source_root: Path,
    state_root: Path,
    provider_mirror: Path | None,
    runtime_identity: Mapping[str, str],
    runner: CommandRunner,
) -> None:
    cli_config = state_root / "terraform.rc"
    _verify_python_interpreter()
    _verify_terraform_binary(source_root, runner, cli_config=cli_config)
    command = [
        _PYTHON,
        "-P",
        "-S",
        "-m",
        "scripts.check_phase5_terraform_plans",
        "--terraform",
        _TERRAFORM,
        "--artifact-output",
        str(state_root / "plans"),
    ]
    if provider_mirror is not None:
        command.extend(("--provider-mirror", str(provider_mirror)))
    for name in (
        "image_digest",
        "infrastructure_revision",
        "recovery_definition_created_at",
        "semantic_config_sha256",
        "source_revision",
        "vertex_prompt_sha256",
        "vertex_prompt_version",
    ):
        command.extend((f"--{name.replace('_', '-')}", runtime_identity[name]))
    try:
        _validated_runner_bytes(
            runner(
                tuple(command),
                cwd=source_root,
                environment=_minimal_subprocess_environment(
                    (
                        EnvironmentBinding(name="PYTHONPATH", value=str(source_root)),
                        EnvironmentBinding(
                            name="TF_CLI_CONFIG_FILE", value=str(cli_config)
                        ),
                    )
                ),
                timeout_seconds=7_200,
            ),
            maximum=65_536,
            failure="TERRAFORM_PREPARATION_FAILED",
        )
    except OperatorError:
        raise
    except Exception as error:
        raise OperatorError("TERRAFORM_PREPARATION_FAILED") from error


def prepare_phase5_artifacts(
    *,
    state_root: Path,
    repo_root: Path,
    source_revision: str,
    created_at: datetime,
    provider_mirror: Path | None,
) -> tuple[Phase5ManifestDraft, Path]:
    """Prepare the complete private, no-cloud input set for manifest sealing."""

    root = _canonical_absolute_path(repo_root, require_exists=True)
    if root != Path(__file__).parents[1].resolve():
        raise OperatorError("PREPARATION_REPOSITORY_MISMATCH")
    if re.fullmatch(r"[0-9a-f]{40}", source_revision) is None:
        raise OperatorError("SOURCE_REVISION_INVALID")
    _verify_exact_main_identity(
        source_revision,
        _ORIGIN_URL,
        repo_root=root,
        runner=_default_runner,
    )
    state = Phase5StateStore(state_root)
    _verify_preparation_state_empty(state)
    _write_immutable_empty_file(
        state.root / "terraform.rc",
        failure="TERRAFORM_CLI_CONFIG_WRITE_FAILED",
    )

    execution_source = _materialize_execution_source(
        state_root=state.root,
        repo_root=root,
        source_revision=source_revision,
        runner=_default_runner,
    )
    source_root = Path(execution_source.root)

    _verify_docker_binary(source_root, _default_runner)
    image_path = state.root / "images" / "reconcile.oci.tar"
    image_digest, _ = _prepare_container_from_snapshot(
        source_root=source_root,
        source_revision=source_revision,
        source_date_epoch=execution_source.source_date_epoch,
        artifact_output=image_path,
        runner=_default_runner,
    )
    _immutable_file_sha256(image_path)
    prepared_image = _capture_image_artifact(
        state_root=state.root,
        source_revision=source_revision,
        expected_digest=image_digest,
    )
    lock_binding = _source_file_binding(
        source_root,
        source_root / "uv.lock",
    )
    python_dependencies = _materialize_python_dependencies(
        state_root=state.root,
        image_artifact=prepared_image,
        python_lock_sha256=lock_binding.sha256,
    )
    _verify_python_dependency_runtime(
        source_root=source_root,
        binding=python_dependencies,
        runner=_default_runner,
    )

    semantic_sources = _capture_semantic_sources(source_root)
    terraform_stacks = _capture_terraform_stacks(source_root)
    infrastructure_revision = _hash_value(
        [item.model_dump(mode="json") for item in terraform_stacks]
    )
    prompt_version, prompt_sha256 = _planner_prompt_identity(source_root)
    _verify_terraform_binary(
        source_root,
        _default_runner,
        cli_config=state.root / "terraform.rc",
    )
    moment = _utc(created_at)
    runtime_identity = {
        "image_digest": image_digest,
        "infrastructure_revision": infrastructure_revision,
        "recovery_definition_created_at": _canonical_utc_timestamp(moment),
        "semantic_config_sha256": semantic_sources.sha256,
        "source_revision": source_revision,
        "vertex_prompt_sha256": prompt_sha256,
        "vertex_prompt_version": prompt_version,
    }
    _prepare_terraform_from_snapshot(
        source_root=source_root,
        state_root=state.root,
        provider_mirror=provider_mirror,
        runtime_identity=runtime_identity,
        runner=_default_runner,
    )

    draft = Phase5ManifestDraft(
        schema_version="reconcile/phase5-operator-draft/v1",
        source_revision=source_revision,
        image_digest=image_digest,
        created_at=moment,
        work_deadline=moment + _WORK_WINDOW,
        approval_expires_at=moment + _WORK_WINDOW + _TEARDOWN_WINDOW,
    )
    draft_path = state.root / "draft.json"
    _write_private_draft(draft_path, draft)
    return draft, draft_path


def build_approval(
    manifest: Phase5ApprovalManifest,
    *,
    approved_by: str,
    approved_at: datetime,
) -> Phase5Approval:
    approved_at = _utc(approved_at)
    if approved_by != _OWNER:
        raise OperatorError("APPROVER_NOT_OWNER")
    if approved_at < manifest.created_at or approved_at >= manifest.work_deadline:
        raise OperatorError("APPROVAL_OUTSIDE_WORK_WINDOW")
    return _seal(
        Phase5Approval,
        schema_version=_SCHEMA,
        record_type="approval",
        manifest_sha256=manifest.record_sha256,
        decision="APPROVE_EXACT_MANIFEST",
        approved_by=approved_by,
        approved_at=approved_at,
        work_deadline=manifest.work_deadline,
        approval_expires_at=manifest.approval_expires_at,
        authorization_estimate_usd=manifest.authorization_estimate_usd,
        contingency_authorization_estimate_usd=(
            manifest.contingency_authorization_estimate_usd
        ),
        estimate_kind=manifest.estimate_kind,
    )


def _utc(value: datetime) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise OperatorError("TIMESTAMP_MUST_BE_AWARE")
    return value.astimezone(UTC)


def _canonical_utc_timestamp(value: datetime) -> str:
    moment = _utc(value)
    timespec = "microseconds" if moment.microsecond else "seconds"
    return moment.isoformat(timespec=timespec).replace("+00:00", "Z")


def _canonical_absolute_path(path: Path, *, require_exists: bool) -> Path:
    if not path.is_absolute() or ":" in str(path):
        raise OperatorError("PATH_NOT_ABSOLUTE")
    try:
        resolved = path.resolve(strict=require_exists)
    except OSError as error:
        raise OperatorError("PATH_UNAVAILABLE") from error
    if resolved != path:
        raise OperatorError("PATH_NOT_CANONICAL")
    return resolved


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise OperatorError("DUPLICATE_JSON_KEY")
        result[key] = value
    return result


def _validate_digest(value: str) -> str:
    if _SHA256_PATTERN.fullmatch(value) is None:
        raise OperatorError("INVALID_SHA256")
    return value


def _validate_record_name(value: str) -> str:
    if _RECORD_NAME_PATTERN.fullmatch(value) is None:
        raise OperatorError("INVALID_RECORD_NAME")
    return value


def _parse_canonical_model[ModelT: StrictModel](
    data: bytes, model_type: type[ModelT]
) -> ModelT:
    try:
        data.decode("utf-8")
        value = json.loads(data, object_pairs_hook=_reject_duplicate_keys)
        if not isinstance(value, dict):
            raise OperatorError("RECORD_NOT_OBJECT")
        model = model_type.model_validate_json(data, strict=True)
    except OperatorError:
        raise
    except (UnicodeError, ValueError, TypeError) as error:
        raise OperatorError("INVALID_RECORD") from error
    if data != _canonical_model_bytes(model):
        raise OperatorError("NONCANONICAL_RECORD")
    return model


class Phase5StateStore:
    """Private, append-only filesystem store for the operator record chain."""

    def __init__(self, root: Path, *, create: bool = True) -> None:
        self.root = _canonical_absolute_path(root, require_exists=False)
        if create:
            self._ensure_root()
            self._ensure_layout()
        elif self.root.exists():
            self._verify_root()

    @property
    def exists(self) -> bool:
        return self.root.exists()

    def _ensure_root(self) -> None:
        try:
            os.mkdir(self.root, mode=0o700)
        except FileExistsError:
            pass
        except OSError as error:
            raise OperatorError("STATE_DIRECTORY_UNAVAILABLE") from error
        self._verify_root()

    def _verify_root(self) -> None:
        try:
            metadata = os.lstat(self.root)
        except OSError as error:
            raise OperatorError("STATE_DIRECTORY_UNAVAILABLE") from error
        if (
            not stat.S_ISDIR(metadata.st_mode)
            or stat.S_ISLNK(metadata.st_mode)
            or metadata.st_uid != os.getuid()
            or stat.S_IMODE(metadata.st_mode) != 0o700
        ):
            raise OperatorError("STATE_DIRECTORY_NOT_PRIVATE")

    def _ensure_layout(self) -> None:
        for relative in (
            "docker",
            "execution",
            "images",
            "plans",
            "state",
            "terraform-data",
            "terraform-data/bootstrap",
            "terraform-data/foundation",
            "terraform-data/runtime",
        ):
            path = self.root / relative
            try:
                path.mkdir(mode=0o700)
            except FileExistsError:
                pass
            except OSError as error:
                raise OperatorError("STATE_LAYOUT_UNAVAILABLE") from error
            _verify_artifact_directory(path)

    def _open_directory(self) -> int:
        self._verify_root()
        flags = os.O_RDONLY | os.O_CLOEXEC | os.O_DIRECTORY | os.O_NOFOLLOW
        try:
            return os.open(self.root, flags)
        except OSError as error:
            raise OperatorError("STATE_DIRECTORY_UNAVAILABLE") from error

    @contextmanager
    def _locked(self) -> Iterator[int]:
        directory = self._open_directory()
        lock_flags = os.O_RDWR | os.O_CLOEXEC | os.O_NOFOLLOW
        created = False
        try:
            try:
                lock_fd = os.open(
                    ".operator.lock",
                    lock_flags | os.O_CREAT | os.O_EXCL,
                    0o600,
                    dir_fd=directory,
                )
                created = True
            except FileExistsError:
                lock_fd = os.open(".operator.lock", lock_flags, dir_fd=directory)
            metadata = os.fstat(lock_fd)
            if (
                not stat.S_ISREG(metadata.st_mode)
                or metadata.st_uid != os.getuid()
                or stat.S_IMODE(metadata.st_mode) != 0o600
            ):
                raise OperatorError("STATE_LOCK_NOT_PRIVATE")
            if created:
                os.fsync(lock_fd)
                os.fsync(directory)
            try:
                fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError as error:
                raise OperatorError("STATE_LOCKED") from error
            yield directory
        except OSError as error:
            raise OperatorError("STATE_LOCK_UNAVAILABLE") from error
        finally:
            if "lock_fd" in locals():
                os.close(lock_fd)
            os.close(directory)

    @staticmethod
    def _write(directory: int, name: RecordName, model: StrictModel) -> None:
        _validate_record_name(name)
        data = _canonical_model_bytes(model)
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW
        try:
            descriptor = os.open(name, flags, 0o600, dir_fd=directory)
        except FileExistsError as error:
            raise OperatorError("IMMUTABLE_RECORD_EXISTS") from error
        except OSError as error:
            raise OperatorError("RECORD_WRITE_FAILED") from error
        try:
            offset = 0
            while offset < len(data):
                written = os.write(descriptor, data[offset:])
                if written <= 0:
                    raise OperatorError("RECORD_WRITE_FAILED")
                offset += written
            os.fchmod(descriptor, 0o400)
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        os.fsync(directory)

    @staticmethod
    def _read[ModelT: StrictModel](
        directory: int,
        name: RecordName,
        model_type: type[ModelT],
    ) -> ModelT:
        _validate_record_name(name)
        flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW
        try:
            descriptor = os.open(name, flags, dir_fd=directory)
        except FileNotFoundError as error:
            raise OperatorError("RECORD_NOT_FOUND") from error
        except OSError as error:
            raise OperatorError("RECORD_READ_FAILED") from error
        try:
            metadata = os.fstat(descriptor)
            if (
                not stat.S_ISREG(metadata.st_mode)
                or metadata.st_uid != os.getuid()
                or stat.S_IMODE(metadata.st_mode) != 0o400
                or metadata.st_nlink != 1
                or metadata.st_size > _MAX_RECORD_BYTES
            ):
                raise OperatorError("RECORD_NOT_PRIVATE")
            chunks: list[bytes] = []
            remaining = _MAX_RECORD_BYTES + 1
            while remaining > 0:
                chunk = os.read(descriptor, min(65_536, remaining))
                if not chunk:
                    break
                chunks.append(chunk)
                remaining -= len(chunk)
            data = b"".join(chunks)
            if len(data) > _MAX_RECORD_BYTES:
                raise OperatorError("RECORD_TOO_LARGE")
        finally:
            os.close(descriptor)
        return _parse_canonical_model(data, model_type)

    @staticmethod
    def _names(directory: int, prefix: str) -> tuple[str, ...]:
        try:
            values = os.listdir(directory)
        except OSError as error:
            raise OperatorError("STATE_LIST_FAILED") from error
        return tuple(
            sorted(
                value
                for value in values
                if value.startswith(prefix) and value.endswith(".json")
            )
        )

    def write_manifest(self, manifest: Phase5ApprovalManifest) -> None:
        with self._locked() as directory:
            self._write(
                directory,
                f"manifest-{manifest.record_sha256}.json",
                manifest,
            )

    def write_approval(self, approval: Phase5Approval) -> None:
        with self._locked() as directory:
            manifest = self._read(
                directory,
                f"manifest-{approval.manifest_sha256}.json",
                Phase5ApprovalManifest,
            )
            _validate_approval_binding(manifest, approval)
            self._write(
                directory,
                f"approval-{approval.record_sha256}.json",
                approval,
            )

    def write_continuation(self, continuation: Phase5Continuation) -> None:
        with self._locked() as directory:
            manifest = self._read(
                directory,
                f"manifest-{continuation.successor_manifest_sha256}.json",
                Phase5ApprovalManifest,
            )
            approval = self._read(
                directory,
                f"approval-{continuation.successor_approval_sha256}.json",
                Phase5Approval,
            )
            if self._names(directory, "continuation-"):
                raise OperatorError("CONTINUATION_ALREADY_EXISTS")
            attempted, successful = self._direct_action_history(
                directory,
                manifest.record_sha256,
            )
            if attempted or successful:
                raise OperatorError("CONTINUATION_SUCCESSOR_NOT_FRESH")
            _verify_continuation_record(
                continuation,
                successor_manifest=manifest,
                successor_approval=approval,
                successor_state_root=self.root,
            )
            self._write(
                directory,
                f"continuation-{continuation.record_sha256}.json",
                continuation,
            )

    def load_manifest(self, digest: str) -> Phase5ApprovalManifest:
        digest = _validate_digest(digest)
        with self._locked() as directory:
            return self._read(
                directory,
                f"manifest-{digest}.json",
                Phase5ApprovalManifest,
            )

    def load_approval(self, digest: str) -> Phase5Approval:
        digest = _validate_digest(digest)
        with self._locked() as directory:
            return self._read(
                directory,
                f"approval-{digest}.json",
                Phase5Approval,
            )

    def inspect(self) -> dict[str, Any]:
        if not self.exists:
            return {
                "schema_version": _SCHEMA,
                "status": "UNINITIALIZED",
                "manifest_sha256": None,
                "approval_sha256": None,
                "unfinished_admission_sha256": None,
            }
        with self._locked() as directory:
            manifests = [
                self._read(directory, name, Phase5ApprovalManifest)
                for name in self._names(directory, "manifest-")
            ]
            approvals = [
                self._read(directory, name, Phase5Approval)
                for name in self._names(directory, "approval-")
            ]
            unfinished = self._unfinished(directory)
            latest_manifest = max(
                manifests,
                key=lambda item: (item.created_at, item.record_sha256),
                default=None,
            )
            latest_approval = max(
                approvals,
                key=lambda item: (item.approved_at, item.record_sha256),
                default=None,
            )
            return {
                "schema_version": _SCHEMA,
                "status": "BLOCKED" if unfinished else "INSPECT_ONLY",
                "manifest_sha256": (
                    latest_manifest.record_sha256 if latest_manifest else None
                ),
                "approval_sha256": (
                    latest_approval.record_sha256 if latest_approval else None
                ),
                "unfinished_admission_sha256": (
                    unfinished.record_sha256 if unfinished else None
                ),
            }

    def _unfinished(self, directory: int) -> Phase5Admission | None:
        for name in self._names(directory, "admission-"):
            admission = self._read(directory, name, Phase5Admission)
            outcome_name = f"outcome-{admission.record_sha256}.json"
            evidence_name = f"evidence-{admission.record_sha256}.json"
            names = set(os.listdir(directory))
            if outcome_name not in names or evidence_name not in names:
                return admission
            outcome = self._read(directory, outcome_name, Phase5Outcome)
            evidence = self._read(directory, evidence_name, Phase5Evidence)
            _validate_completion_chain(admission, outcome, evidence)
        return None

    def _direct_action_history(
        self,
        directory: int,
        manifest_sha256: str,
    ) -> tuple[set[Phase5Action], set[Phase5Action]]:
        attempted: set[Phase5Action] = set()
        successful: set[Phase5Action] = set()
        for name in self._names(directory, "admission-"):
            admission = self._read(directory, name, Phase5Admission)
            if admission.manifest_sha256 != manifest_sha256:
                continue
            try:
                outcome = self._read(
                    directory,
                    f"outcome-{admission.record_sha256}.json",
                    Phase5Outcome,
                )
                evidence = self._read(
                    directory,
                    f"evidence-{admission.record_sha256}.json",
                    Phase5Evidence,
                )
            except OperatorError as error:
                if error.code == "RECORD_NOT_FOUND":
                    continue
                raise
            _validate_completion_chain(admission, outcome, evidence)
            attempted.add(admission.action)
            if outcome.status is OutcomeStatus.SUCCEEDED:
                successful.add(admission.action)
        return attempted, successful

    def _action_binding(
        self,
        directory: int,
        manifest_sha256: str,
        action: Phase5Action,
    ) -> Phase5ActionEvidenceBinding:
        matches = tuple(
            admission
            for name in self._names(directory, "admission-")
            if (
                (
                    admission := self._read(directory, name, Phase5Admission)
                ).manifest_sha256
                == manifest_sha256
                and admission.action is action
            )
        )
        if len(matches) != 1:
            raise OperatorError("CONTINUATION_ACTION_CHAIN_INVALID")
        admission = matches[0]
        outcome = self._read(
            directory,
            f"outcome-{admission.record_sha256}.json",
            Phase5Outcome,
        )
        evidence = self._read(
            directory,
            f"evidence-{admission.record_sha256}.json",
            Phase5Evidence,
        )
        _validate_completion_chain(admission, outcome, evidence)
        return Phase5ActionEvidenceBinding(
            action=action,
            admission_sha256=admission.record_sha256,
            outcome_sha256=outcome.record_sha256,
            evidence_sha256=evidence.record_sha256,
            status=outcome.status,
        )

    def continuation_source(
        self,
        *,
        manifest_sha256: str,
        approval_sha256: str,
    ) -> tuple[
        Phase5ApprovalManifest,
        Phase5Approval,
        tuple[Phase5ActionEvidenceBinding, ...],
        Phase5ActionEvidenceBinding,
    ]:
        with self._locked() as directory:
            manifest = self._read(
                directory,
                f"manifest-{_validate_digest(manifest_sha256)}.json",
                Phase5ApprovalManifest,
            )
            approval = self._read(
                directory,
                f"approval-{_validate_digest(approval_sha256)}.json",
                Phase5Approval,
            )
            _validate_approval_binding(manifest, approval)
            if self._unfinished(directory) is not None:
                raise OperatorError("CONTINUATION_PREDECESSOR_UNFINISHED")
            continuation_names = self._names(directory, "continuation-")
            if len(continuation_names) > 1:
                raise OperatorError("CONTINUATION_RECORD_SET_INVALID")
            continuations = tuple(
                self._read(directory, name, Phase5Continuation)
                for name in continuation_names
            )
            if continuations and (
                continuations[0].successor_manifest_sha256 != manifest.record_sha256
            ):
                raise OperatorError("CONTINUATION_RECORD_SET_INVALID")
            direct_attempted, direct_successful = self._direct_action_history(
                directory,
                manifest.record_sha256,
            )
            if not continuations:
                image_attempted = {
                    *_INITIAL_CONTINUATION_ACTIONS,
                    Phase5Action.IMAGE_PUSH,
                }
                provider_attempted = {
                    *image_attempted,
                    Phase5Action.RUNTIME_APPLY,
                    Phase5Action.PROVIDER_ACCEPTANCE,
                }
                provider_successful = {
                    *image_attempted,
                    Phase5Action.RUNTIME_APPLY,
                }
                if direct_attempted == image_attempted and direct_successful == set(
                    _INITIAL_CONTINUATION_ACTIONS
                ):
                    terminal_action = Phase5Action.IMAGE_PUSH
                elif (
                    direct_attempted == provider_attempted
                    and direct_successful == provider_successful
                ):
                    terminal_action = Phase5Action.PROVIDER_ACCEPTANCE
                else:
                    raise OperatorError("CONTINUATION_PREDECESSOR_HISTORY_INVALID")
                carried = tuple(
                    self._action_binding(directory, manifest.record_sha256, action)
                    for action in _INITIAL_CONTINUATION_ACTIONS
                )
                terminal = self._action_binding(
                    directory,
                    manifest.record_sha256,
                    terminal_action,
                )
            else:
                prior = continuations[0]
                prior_actions = tuple(item.action for item in prior.carried_successes)
                preserve_prior_carried = False
                if (
                    prior_actions == _INITIAL_CONTINUATION_ACTIONS
                    and prior.terminal_action.action is Phase5Action.IMAGE_PUSH
                    and prior.terminal_action.status is OutcomeStatus.UNKNOWN
                ):
                    direct_carried_actions = _TEARDOWN_CONTINUATION_ACTIONS[
                        len(_INITIAL_CONTINUATION_ACTIONS) :
                    ]
                    terminal_action = Phase5Action.STATE_PROTECTION_CHANGE
                elif (
                    prior_actions == _INITIAL_CONTINUATION_ACTIONS
                    and prior.terminal_action.action is Phase5Action.PROVIDER_ACCEPTANCE
                    and prior.terminal_action.status is OutcomeStatus.FAILED
                ):
                    direct_carried_actions = (
                        Phase5Action.IMAGE_PUSH,
                        Phase5Action.RUNTIME_APPLY,
                    )
                    terminal_action = Phase5Action.PROVIDER_ACCEPTANCE
                    preserve_prior_carried = True
                elif (
                    prior_actions == _TEARDOWN_CONTINUATION_ACTIONS
                    and prior.terminal_action.action
                    is Phase5Action.STATE_PROTECTION_CHANGE
                    and prior.terminal_action.status is OutcomeStatus.UNKNOWN
                ):
                    direct_carried_actions = (Phase5Action.STATE_PROTECTION_CHANGE,)
                    terminal_action = Phase5Action.BOOTSTRAP_TEARDOWN
                elif (
                    prior_actions == _BOOTSTRAP_CONTINUATION_ACTIONS
                    and prior.terminal_action.action is Phase5Action.BOOTSTRAP_TEARDOWN
                    and prior.terminal_action.status is OutcomeStatus.FAILED
                ):
                    direct_carried_actions = ()
                    terminal_action = Phase5Action.BOOTSTRAP_TEARDOWN
                else:
                    raise OperatorError("CONTINUATION_PREDECESSOR_HISTORY_INVALID")
                expected_attempted = {
                    *direct_carried_actions,
                    terminal_action,
                }
                if direct_attempted != expected_attempted or direct_successful != set(
                    direct_carried_actions
                ):
                    raise OperatorError("CONTINUATION_PREDECESSOR_HISTORY_INVALID")
                terminal = self._action_binding(
                    directory,
                    manifest.record_sha256,
                    terminal_action,
                )
                allow_evolved_bootstrap_state = (
                    terminal_action is Phase5Action.BOOTSTRAP_TEARDOWN
                    and terminal.status is OutcomeStatus.FAILED
                )
                _verify_continuation_record(
                    prior,
                    successor_manifest=manifest,
                    successor_approval=approval,
                    successor_state_root=self.root,
                    allow_evolved_successor_bootstrap_state=(
                        allow_evolved_bootstrap_state
                    ),
                )
                carried = (
                    *prior.carried_successes,
                    *(
                        self._action_binding(
                            directory,
                            manifest.record_sha256,
                            action,
                        )
                        for action in (
                            () if preserve_prior_carried else direct_carried_actions
                        )
                    ),
                )
            if (
                any(item.status is not OutcomeStatus.SUCCEEDED for item in carried)
                or (
                    terminal.action is Phase5Action.BOOTSTRAP_TEARDOWN
                    and terminal.status is not OutcomeStatus.FAILED
                )
                or (
                    terminal.action is Phase5Action.PROVIDER_ACCEPTANCE
                    and terminal.status is not OutcomeStatus.FAILED
                )
                or (
                    terminal.action
                    not in {
                        Phase5Action.BOOTSTRAP_TEARDOWN,
                        Phase5Action.PROVIDER_ACCEPTANCE,
                    }
                    and terminal.status is not OutcomeStatus.UNKNOWN
                )
            ):
                raise OperatorError("CONTINUATION_PREDECESSOR_HISTORY_INVALID")
            return manifest, approval, carried, terminal

    def _action_history(
        self,
        directory: int,
        manifest_sha256: str,
    ) -> tuple[set[Phase5Action], set[Phase5Action]]:
        attempted, successful = self._direct_action_history(
            directory,
            manifest_sha256,
        )
        continuations = tuple(
            continuation
            for name in self._names(directory, "continuation-")
            if (
                continuation := self._read(directory, name, Phase5Continuation)
            ).successor_manifest_sha256
            == manifest_sha256
        )
        if len(continuations) > 1:
            raise OperatorError("CONTINUATION_RECORD_SET_INVALID")
        if continuations:
            continuation = continuations[0]
            manifest = self._read(
                directory,
                f"manifest-{manifest_sha256}.json",
                Phase5ApprovalManifest,
            )
            approval = self._read(
                directory,
                f"approval-{continuation.successor_approval_sha256}.json",
                Phase5Approval,
            )
            _verify_continuation_record(
                continuation,
                successor_manifest=manifest,
                successor_approval=approval,
                successor_state_root=self.root,
            )
            carried = {item.action for item in continuation.carried_successes}
            attempted.update(carried)
            successful.update(carried)
        return attempted, successful

    def admit(
        self,
        *,
        manifest: Phase5ApprovalManifest,
        approval: Phase5Approval,
        action: Phase5Action,
        admitted_at: datetime,
    ) -> Phase5Admission:
        with self._locked() as directory:
            stored_manifest = self._read(
                directory,
                f"manifest-{manifest.record_sha256}.json",
                Phase5ApprovalManifest,
            )
            stored_approval = self._read(
                directory,
                f"approval-{approval.record_sha256}.json",
                Phase5Approval,
            )
            if stored_manifest != manifest or stored_approval != approval:
                raise OperatorError("STORED_RECORD_MISMATCH")
            if self._unfinished(directory) is not None:
                raise OperatorError("UNFINISHED_ADMISSION")
            attempted, successful = self._action_history(
                directory,
                manifest.record_sha256,
            )
            _validate_action_sequence(action, attempted, successful)
            descriptor = manifest.command_for(action)
            admission = _seal(
                Phase5Admission,
                schema_version=_SCHEMA,
                record_type="admission",
                manifest_sha256=manifest.record_sha256,
                approval_sha256=approval.record_sha256,
                action=action,
                command_descriptor_sha256=descriptor.descriptor_sha256,
                source_revision=manifest.source_revision,
                admitted_at=_utc(admitted_at),
            )
            self._write(
                directory,
                f"admission-{admission.record_sha256}.json",
                admission,
            )
            return admission

    def complete(
        self,
        *,
        admission: Phase5Admission,
        outcome: Phase5Outcome,
        evidence: Phase5Evidence,
    ) -> None:
        _validate_completion_chain(admission, outcome, evidence)
        with self._locked() as directory:
            stored = self._read(
                directory,
                f"admission-{admission.record_sha256}.json",
                Phase5Admission,
            )
            if stored != admission:
                raise OperatorError("STORED_RECORD_MISMATCH")
            self._write(
                directory,
                f"outcome-{admission.record_sha256}.json",
                outcome,
            )
            self._write(
                directory,
                f"evidence-{admission.record_sha256}.json",
                evidence,
            )


def _bootstrap_state_identity(path: Path) -> tuple[str, int, int, int]:
    try:
        canonical = _canonical_absolute_path(path, require_exists=True)
        descriptor = os.open(
            canonical,
            os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW,
        )
    except (OSError, OperatorError) as error:
        raise OperatorError("CONTINUATION_BOOTSTRAP_STATE_INVALID") from error
    try:
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_uid != os.getuid()
            or stat.S_IMODE(before.st_mode) != 0o600
            or before.st_nlink != 1
            or before.st_size < 1
            or before.st_size > _MAX_ARTIFACT_BYTES
        ):
            raise OperatorError("CONTINUATION_BOOTSTRAP_STATE_INVALID")
        digest = hashlib.sha256()
        observed = 0
        while chunk := os.read(descriptor, 1_048_576):
            observed += len(chunk)
            if observed > _MAX_ARTIFACT_BYTES:
                raise OperatorError("CONTINUATION_BOOTSTRAP_STATE_INVALID")
            digest.update(chunk)
        after = os.fstat(descriptor)
        if (
            observed != before.st_size
            or (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)
            != (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
            or stat.S_IMODE(after.st_mode) != 0o600
            or after.st_nlink != 1
        ):
            raise OperatorError("CONTINUATION_BOOTSTRAP_STATE_INVALID")
        return digest.hexdigest(), observed, after.st_dev, after.st_ino
    except OSError as error:
        raise OperatorError("CONTINUATION_BOOTSTRAP_STATE_INVALID") from error
    finally:
        os.close(descriptor)


def _copy_bootstrap_state(source: Path, destination: Path) -> tuple[str, int]:
    expected_digest, expected_size, _, _ = _bootstrap_state_identity(source)
    _verify_artifact_directory(destination.parent)
    source_descriptor: int | None = None
    destination_descriptor: int | None = None
    try:
        source_descriptor = os.open(
            source,
            os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW,
        )
        before = os.fstat(source_descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_uid != os.getuid()
            or stat.S_IMODE(before.st_mode) != 0o600
            or before.st_nlink != 1
            or before.st_size != expected_size
        ):
            raise OperatorError("CONTINUATION_BOOTSTRAP_STATE_INVALID")
        destination_descriptor = os.open(
            destination,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW,
            0o600,
        )
        digest = hashlib.sha256()
        observed = 0
        while chunk := os.read(source_descriptor, 1_048_576):
            observed += len(chunk)
            if observed > _MAX_ARTIFACT_BYTES:
                raise OperatorError("CONTINUATION_BOOTSTRAP_STATE_INVALID")
            digest.update(chunk)
            offset = 0
            while offset < len(chunk):
                written = os.write(destination_descriptor, chunk[offset:])
                if written < 1:
                    raise OperatorError("CONTINUATION_BOOTSTRAP_STATE_COPY_FAILED")
                offset += written
        after = os.fstat(source_descriptor)
        if (
            observed != expected_size
            or digest.hexdigest() != expected_digest
            or (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)
            != (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
            or after.st_nlink != 1
        ):
            raise OperatorError("CONTINUATION_BOOTSTRAP_STATE_INVALID")
        os.fchmod(destination_descriptor, 0o600)
        os.fsync(destination_descriptor)
    except FileExistsError as error:
        raise OperatorError("CONTINUATION_BOOTSTRAP_STATE_EXISTS") from error
    except OperatorError:
        raise
    except OSError as error:
        raise OperatorError("CONTINUATION_BOOTSTRAP_STATE_COPY_FAILED") from error
    finally:
        if source_descriptor is not None:
            os.close(source_descriptor)
        if destination_descriptor is not None:
            os.close(destination_descriptor)
    directory = os.open(
        destination.parent,
        os.O_RDONLY | os.O_CLOEXEC | os.O_DIRECTORY | os.O_NOFOLLOW,
    )
    try:
        os.fsync(directory)
    finally:
        os.close(directory)
    copied_digest, copied_size, _, _ = _bootstrap_state_identity(destination)
    if (copied_digest, copied_size) != (expected_digest, expected_size):
        raise OperatorError("CONTINUATION_BOOTSTRAP_STATE_COPY_FAILED")
    return copied_digest, copied_size


def _plan_continuation_identity(plan: TerraformPlanBinding) -> dict[str, Any]:
    return plan.model_dump(
        mode="json",
        exclude={"qualification_path", "variables_path", "execution_plan_path"},
    )


def _source_changes(
    predecessor: SourceGroupBinding | ExecutionSourceBinding,
    successor: SourceGroupBinding | ExecutionSourceBinding,
) -> set[str]:
    predecessor_files = {item.path: item for item in predecessor.files}
    successor_files = {item.path: item for item in successor.files}
    if set(predecessor_files) != set(successor_files):
        raise OperatorError("CONTINUATION_SOURCE_SCOPE_DRIFT")
    return {
        path
        for path in predecessor_files
        if predecessor_files[path] != successor_files[path]
    }


def _validate_project_dependency_drift(
    predecessor: Phase5ApprovalManifest,
    successor: Phase5ApprovalManifest,
    source_changes: set[str],
) -> None:
    observed: list[tuple[dict[str, Any], ...]] = []
    for manifest in (predecessor, successor):
        binding = manifest.python_dependencies
        details = _dependency_inventory_details(Path(binding.root))
        if details[:4] != (
            binding.file_count,
            binding.entry_count,
            binding.byte_count,
            binding.sha256,
        ):
            raise OperatorError("CONTINUATION_DEPENDENCY_DRIFT")
        observed.append(details[4])

    predecessor_entries = {item["path"]: item for item in observed[0]}
    successor_entries = {item["path"]: item for item in observed[1]}
    if set(predecessor_entries) != set(successor_entries):
        raise OperatorError("CONTINUATION_DEPENDENCY_DRIFT")
    changed = {
        path
        for path in predecessor_entries
        if predecessor_entries[path] != successor_entries[path]
    }
    expected_changes = source_changes | {_PROJECT_DEPENDENCY_RECORD_PATH}
    if changed != expected_changes:
        raise OperatorError("CONTINUATION_DEPENDENCY_DRIFT")

    for manifest, entries in zip(
        (predecessor, successor),
        (predecessor_entries, successor_entries),
        strict=True,
    ):
        sources = {item.path: item for item in manifest.execution_source.files}
        for path in source_changes:
            source = sources.get(path)
            dependency = entries.get(path)
            if source is None or dependency != {
                "path": path,
                "kind": "file",
                "byte_count": source.byte_count,
                "sha256": source.sha256,
            }:
                raise OperatorError("CONTINUATION_DEPENDENCY_DRIFT")


def _validate_continuation_bounds(
    predecessor: Phase5ApprovalManifest,
    successor: Phase5ApprovalManifest,
    terminal_action: Phase5ActionEvidenceBinding | None = None,
) -> None:
    output_budget_migration = (
        predecessor.record_sha256
        == _OUTPUT_BUDGET_MIGRATION_PREDECESSOR_MANIFEST_SHA256
        and predecessor.source_revision
        == _OUTPUT_BUDGET_MIGRATION_PREDECESSOR_SOURCE_REVISION
        and predecessor.output_token_limit == 1_024
        and successor.output_token_limit == 4_096
        and terminal_action is not None
        and terminal_action.action is Phase5Action.PROVIDER_ACCEPTANCE
        and terminal_action.status is OutcomeStatus.FAILED
    )
    fixed_fields = (
        "origin_url",
        "project_id",
        "project_number",
        "region",
        "authenticated_exposure",
        "terraform_version",
        "terraform_executable",
        "terraform_binary_sha256",
        "terraform_cli_config_sha256",
        "gcloud_version",
        "git_version",
        "git_binary_sha256",
        "python_version",
        "python_interpreter",
        "python_interpreter_sha256",
        "docker_client_sha256",
        "docker_credential_gcloud_sha256",
        "provider_source",
        "provider_version",
        "gemini_model",
        "vertex_location",
        "count_tokens_attempt_limit",
        "billed_generation_limit",
        "input_token_limit",
        "thinking_level",
        "authorization_estimate_usd",
        "contingency_authorization_estimate_usd",
        "estimate_kind",
        "python_project_sha256",
        "python_lock_sha256",
        "prompt_sha256",
        "prompt_version",
    )
    if not output_budget_migration:
        fixed_fields += (
            "output_token_limit",
            "infrastructure_revision",
            "terraform_stacks",
        )
    if any(
        getattr(predecessor, field) != getattr(successor, field)
        for field in fixed_fields
    ):
        raise OperatorError("CONTINUATION_BOUND_DRIFT")
    execution_changes = _source_changes(
        predecessor.execution_source,
        successor.execution_source,
    )
    semantic_changes = _source_changes(
        predecessor.semantic_sources,
        successor.semantic_sources,
    )
    if output_budget_migration:
        if (
            semantic_changes != _OUTPUT_BUDGET_MIGRATION_PYTHON_PATHS
            or execution_changes
            != (
                _OUTPUT_BUDGET_MIGRATION_PYTHON_PATHS
                | _OUTPUT_BUDGET_MIGRATION_EXTERNAL_PATHS
            )
        ):
            raise OperatorError("CONTINUATION_SOURCE_SCOPE_DRIFT")
        predecessor_stacks = {item.stack: item for item in predecessor.terraform_stacks}
        successor_stacks = {item.stack: item for item in successor.terraform_stacks}
        if (
            predecessor_stacks.keys() != successor_stacks.keys()
            or predecessor_stacks["bootstrap"] != successor_stacks["bootstrap"]
            or predecessor_stacks["foundation"] != successor_stacks["foundation"]
        ):
            raise OperatorError("CONTINUATION_BOUND_DRIFT")
        predecessor_runtime = predecessor_stacks["runtime"]
        successor_runtime = successor_stacks["runtime"]
        if (
            predecessor_runtime.stack != successor_runtime.stack
            or predecessor_runtime.source_root != successor_runtime.source_root
            or predecessor_runtime.lock_sha256 != successor_runtime.lock_sha256
            or _source_changes(
                predecessor_runtime.sources,
                successor_runtime.sources,
            )
            != _OUTPUT_BUDGET_MIGRATION_TERRAFORM_PATHS
        ):
            raise OperatorError("CONTINUATION_BOUND_DRIFT")
    elif (
        not execution_changes
        or execution_changes != semantic_changes
        or any(
            not path.startswith("reconcile/") or not path.endswith(".py")
            for path in execution_changes
        )
    ):
        raise OperatorError("CONTINUATION_SOURCE_SCOPE_DRIFT")
    _validate_project_dependency_drift(
        predecessor,
        successor,
        semantic_changes,
    )
    for action in (
        Phase5Action.BOOTSTRAP_APPLY,
        Phase5Action.FOUNDATION_APPLY,
        Phase5Action.FOUNDATION_TEARDOWN,
        Phase5Action.STATE_PROTECTION_CHANGE,
        Phase5Action.BOOTSTRAP_TEARDOWN,
    ):
        predecessor_plan = predecessor.terraform_plan_for(action)
        successor_plan = successor.terraform_plan_for(action)
        if (
            predecessor_plan is None
            or successor_plan is None
            or _plan_continuation_identity(predecessor_plan)
            != _plan_continuation_identity(successor_plan)
        ):
            raise OperatorError("CONTINUATION_INFRASTRUCTURE_PLAN_DRIFT")


def _verify_continuation_record(
    continuation: Phase5Continuation,
    *,
    successor_manifest: Phase5ApprovalManifest,
    successor_approval: Phase5Approval,
    successor_state_root: Path,
    allow_evolved_successor_bootstrap_state: bool = False,
) -> None:
    _validate_approval_binding(successor_manifest, successor_approval)
    successor_root = _canonical_absolute_path(
        successor_state_root,
        require_exists=True,
    )
    predecessor_root = _canonical_absolute_path(
        Path(continuation.predecessor_state_root),
        require_exists=True,
    )
    if (
        predecessor_root == successor_root
        or successor_manifest.operator_state_root != str(successor_root)
        or continuation.successor_manifest_sha256 != successor_manifest.record_sha256
        or continuation.successor_approval_sha256 != successor_approval.record_sha256
        or continuation.prepared_at < successor_approval.approved_at
        or continuation.prepared_at >= successor_approval.work_deadline
    ):
        raise OperatorError("CONTINUATION_SUCCESSOR_BINDING_INVALID")
    predecessor_state = Phase5StateStore(predecessor_root, create=False)
    (
        predecessor_manifest,
        predecessor_approval,
        carried,
        terminal,
    ) = predecessor_state.continuation_source(
        manifest_sha256=continuation.predecessor_manifest_sha256,
        approval_sha256=continuation.predecessor_approval_sha256,
    )
    if (
        predecessor_manifest.record_sha256 != continuation.predecessor_manifest_sha256
        or predecessor_approval.record_sha256
        != continuation.predecessor_approval_sha256
        or carried != continuation.carried_successes
        or terminal != continuation.terminal_action
    ):
        raise OperatorError("CONTINUATION_PREDECESSOR_BINDING_INVALID")
    _validate_continuation_bounds(
        predecessor_manifest,
        successor_manifest,
        terminal,
    )
    predecessor_identity = _bootstrap_state_identity(
        predecessor_root / "state" / "bootstrap.tfstate"
    )
    successor_identity = _bootstrap_state_identity(
        successor_root / "state" / "bootstrap.tfstate"
    )
    expected = (
        continuation.bootstrap_state_sha256,
        continuation.bootstrap_state_byte_count,
    )
    if predecessor_identity[:2] != expected:
        raise OperatorError("CONTINUATION_BOOTSTRAP_STATE_DRIFT")
    if (
        not allow_evolved_successor_bootstrap_state
        and successor_identity[:2] != expected
    ):
        raise OperatorError("CONTINUATION_BOOTSTRAP_STATE_DRIFT")
    if predecessor_identity[2:] == successor_identity[2:]:
        raise OperatorError("CONTINUATION_BOOTSTRAP_STATE_NOT_INDEPENDENT")


def prepare_phase5_continuation(
    *,
    predecessor_state_root: Path,
    predecessor_manifest_sha256: str,
    predecessor_approval_sha256: str,
    successor_state_root: Path,
    successor_manifest_sha256: str,
    successor_approval_sha256: str,
    repo_root: Path,
    prepared_at: datetime,
    runner: CommandRunner | None = None,
) -> Phase5Continuation:
    selected_runner = _default_runner if runner is None else runner
    predecessor_state = Phase5StateStore(predecessor_state_root, create=False)
    successor_state = Phase5StateStore(successor_state_root)
    if predecessor_state.root == successor_state.root:
        raise OperatorError("CONTINUATION_STATE_ROOT_REUSED")
    successor_manifest = successor_state.load_manifest(successor_manifest_sha256)
    successor_approval = successor_state.load_approval(successor_approval_sha256)
    _validate_approval_binding(successor_manifest, successor_approval)
    moment = _utc(prepared_at)
    if (
        moment < successor_approval.approved_at
        or moment >= successor_approval.work_deadline
    ):
        raise OperatorError("CONTINUATION_OUTSIDE_WORK_WINDOW")
    _verify_exact_main(
        successor_manifest,
        repo_root=repo_root,
        runner=selected_runner,
    )
    (
        predecessor_manifest,
        predecessor_approval,
        carried,
        terminal,
    ) = predecessor_state.continuation_source(
        manifest_sha256=predecessor_manifest_sha256,
        approval_sha256=predecessor_approval_sha256,
    )
    _validate_continuation_bounds(
        predecessor_manifest,
        successor_manifest,
        terminal,
    )
    source_state = predecessor_state.root / "state" / "bootstrap.tfstate"
    source_digest, source_size, _, _ = _bootstrap_state_identity(source_state)
    continuation = _seal(
        Phase5Continuation,
        schema_version=_SCHEMA,
        record_type="continuation",
        successor_manifest_sha256=successor_manifest.record_sha256,
        successor_approval_sha256=successor_approval.record_sha256,
        predecessor_state_root=str(predecessor_state.root),
        predecessor_manifest_sha256=predecessor_manifest.record_sha256,
        predecessor_approval_sha256=predecessor_approval.record_sha256,
        carried_successes=carried,
        terminal_action=terminal,
        bootstrap_state_sha256=source_digest,
        bootstrap_state_byte_count=source_size,
        prepared_at=moment,
    )
    destination_state = successor_state.root / "state" / "bootstrap.tfstate"
    copied = _copy_bootstrap_state(source_state, destination_state)
    if copied != (source_digest, source_size):
        raise OperatorError("CONTINUATION_BOOTSTRAP_STATE_COPY_FAILED")
    successor_state.write_continuation(continuation)
    return continuation


def _validate_approval_binding(
    manifest: Phase5ApprovalManifest,
    approval: Phase5Approval,
) -> None:
    if (
        approval.manifest_sha256 != manifest.record_sha256
        or approval.work_deadline != manifest.work_deadline
        or approval.approval_expires_at != manifest.approval_expires_at
        or approval.authorization_estimate_usd != manifest.authorization_estimate_usd
        or approval.contingency_authorization_estimate_usd
        != manifest.contingency_authorization_estimate_usd
        or approval.estimate_kind != manifest.estimate_kind
        or approval.approved_at < manifest.created_at
        or approval.approved_at >= manifest.work_deadline
    ):
        raise OperatorError("APPROVAL_MANIFEST_MISMATCH")


def _validate_completion_chain(
    admission: Phase5Admission,
    outcome: Phase5Outcome,
    evidence: Phase5Evidence,
) -> None:
    if (
        outcome.admission_sha256 != admission.record_sha256
        or evidence.admission_sha256 != admission.record_sha256
        or evidence.manifest_sha256 != admission.manifest_sha256
        or evidence.approval_sha256 != admission.approval_sha256
        or evidence.outcome_sha256 != outcome.record_sha256
        or evidence.action is not admission.action
        or evidence.status is not outcome.status
        or outcome.finished_at < admission.admitted_at
        or evidence.observed_at != outcome.finished_at
    ):
        raise OperatorError("EVIDENCE_CHAIN_MISMATCH")


_PREREQUISITES: dict[Phase5Action, Phase5Action] = {
    Phase5Action.FOUNDATION_APPLY: Phase5Action.BOOTSTRAP_APPLY,
    Phase5Action.IMAGE_PUSH: Phase5Action.FOUNDATION_APPLY,
    Phase5Action.RUNTIME_APPLY: Phase5Action.IMAGE_PUSH,
    Phase5Action.PROVIDER_ACCEPTANCE: Phase5Action.RUNTIME_APPLY,
    Phase5Action.HOSTED_ACCEPTANCE: Phase5Action.PROVIDER_ACCEPTANCE,
    Phase5Action.FOUNDATION_TEARDOWN: Phase5Action.RUNTIME_TEARDOWN,
    Phase5Action.STATE_PROTECTION_CHANGE: Phase5Action.FOUNDATION_TEARDOWN,
    Phase5Action.BOOTSTRAP_TEARDOWN: Phase5Action.STATE_PROTECTION_CHANGE,
}


def _validate_action_sequence(
    action: Phase5Action,
    attempted: set[Phase5Action],
    successful: set[Phase5Action],
) -> None:
    if action in attempted:
        raise OperatorError("ACTION_ALREADY_ATTEMPTED")
    if not action.is_teardown and any(item.is_teardown for item in attempted):
        raise OperatorError("TERMINAL_TEARDOWN_STARTED")
    prerequisite = _PREREQUISITES.get(action)
    if prerequisite is not None and prerequisite not in successful:
        raise OperatorError("ACTION_PREREQUISITE_NOT_SUCCEEDED")


def _default_runner(
    argv: tuple[str, ...],
    *,
    cwd: Path,
    environment: Mapping[str, str],
    timeout_seconds: int,
) -> object:
    return subprocess.run(
        list(argv),
        cwd=str(cwd),
        env=dict(environment),
        timeout=timeout_seconds,
        check=False,
        capture_output=True,
        shell=False,
        umask=0o077,
    )


def _checked_output(result: object, *, maximum: int = 4096) -> bytes:
    if (
        not isinstance(result, subprocess.CompletedProcess)
        or type(result.returncode) is not int
        or type(result.stdout) is not bytes
        or type(result.stderr) is not bytes
        or len(result.stdout) > maximum
        or len(result.stderr) > maximum
        or result.returncode != 0
    ):
        raise OperatorError("GIT_CHECK_FAILED")
    return result.stdout


def _verify_exact_main_identity(
    source_revision: str,
    origin_url: str,
    *,
    repo_root: Path,
    runner: CommandRunner,
) -> None:
    root = _canonical_absolute_path(repo_root, require_exists=True)
    if re.fullmatch(r"[0-9a-f]{40}", source_revision) is None:
        raise OperatorError("SOURCE_REVISION_INVALID")
    _verify_git_binary(root, runner)
    commands = (
        (("/usr/bin/git", "branch", "--show-current"), b"main\n"),
        (
            ("/usr/bin/git", "rev-parse", "--verify", "HEAD"),
            f"{source_revision}\n".encode(),
        ),
        (
            ("/usr/bin/git", "rev-parse", "--verify", "origin/main"),
            f"{source_revision}\n".encode(),
        ),
        (
            (
                "/usr/bin/git",
                "status",
                "--porcelain=v1",
                "--untracked-files=all",
            ),
            b"",
        ),
        (
            ("/usr/bin/git", "remote", "get-url", "origin"),
            f"{origin_url}\n".encode(),
        ),
        (
            (
                "/usr/bin/git",
                "ls-remote",
                "--exit-code",
                "origin",
                "refs/heads/main",
            ),
            f"{source_revision}\trefs/heads/main\n".encode(),
        ),
    )
    environment = _minimal_subprocess_environment()
    for argv, expected in commands:
        try:
            output = _checked_output(
                runner(
                    argv,
                    cwd=root,
                    environment=environment,
                    timeout_seconds=15,
                )
            )
        except OperatorError:
            raise
        except Exception as error:
            raise OperatorError("GIT_CHECK_FAILED") from error
        if output != expected:
            raise OperatorError("EXACT_MAIN_CHECK_FAILED")


def _verify_exact_main(
    manifest: Phase5ApprovalManifest,
    *,
    repo_root: Path,
    runner: CommandRunner,
) -> None:
    _verify_exact_main_identity(
        manifest.source_revision,
        manifest.origin_url,
        repo_root=repo_root,
        runner=runner,
    )


def _verify_approved_artifacts(
    manifest: Phase5ApprovalManifest,
    *,
    action: Phase5Action,
    state: Phase5StateStore,
    repo_root: Path,
    runner: CommandRunner,
) -> None:
    if str(state.root) != manifest.operator_state_root:
        raise OperatorError("OPERATOR_STATE_ROOT_DRIFT")
    draft = Phase5ManifestDraft(
        schema_version="reconcile/phase5-operator-draft/v1",
        source_revision=manifest.source_revision,
        image_digest=manifest.image_digest,
        created_at=manifest.created_at,
        work_deadline=manifest.work_deadline,
        approval_expires_at=manifest.approval_expires_at,
    )
    try:
        observed = _capture_artifact_bindings(
            draft,
            state_root=state.root,
            repo_root=repo_root,
            runner=runner,
        )
    except OperatorError:
        raise
    except Exception as error:
        raise OperatorError("ARTIFACT_VERIFICATION_FAILED") from error
    expected = {
        "operator_state_root": manifest.operator_state_root,
        "execution_source": manifest.execution_source,
        "python_dependencies": manifest.python_dependencies,
        "terraform_cli_config_path": manifest.terraform_cli_config_path,
        "terraform_cli_config_sha256": manifest.terraform_cli_config_sha256,
        "infrastructure_revision": manifest.infrastructure_revision,
        "terraform_stacks": manifest.terraform_stacks,
        "terraform_plans": manifest.terraform_plans,
        "semantic_sources": manifest.semantic_sources,
        "python_project_sha256": manifest.python_project_sha256,
        "python_lock_sha256": manifest.python_lock_sha256,
        "image_artifact": manifest.image_artifact,
        "semantic_config_sha256": manifest.semantic_config_sha256,
        "prompt_sha256": manifest.prompt_sha256,
        "prompt_version": manifest.prompt_version,
        "resource_inventory_sha256": manifest.resource_inventory_sha256,
        "iam_inventory_sha256": manifest.iam_inventory_sha256,
        "plan_inventory_sha256": manifest.plan_inventory_sha256,
    }
    if observed != expected:
        raise OperatorError("APPROVED_ARTIFACT_DRIFT")
    plan = manifest.terraform_plan_for(action)
    if plan is not None:
        execution_paths = [Path(plan.execution_plan_path)]
        if action is Phase5Action.BOOTSTRAP_TEARDOWN:
            execution_paths.append(
                Path(plan.execution_plan_path).with_name(
                    "bootstrap-final-protection-update.tfplan"
                )
            )
        for execution_path in execution_paths:
            try:
                os.lstat(execution_path)
            except FileNotFoundError:
                pass
            except OSError as error:
                raise OperatorError("EXECUTION_PLAN_PATH_INVALID") from error
            else:
                raise OperatorError("EXECUTION_PLAN_ALREADY_EXISTS")
    if action in {
        Phase5Action.BOOTSTRAP_APPLY,
        Phase5Action.BOOTSTRAP_TEARDOWN,
        Phase5Action.IMAGE_PUSH,
    }:
        _verify_gcloud_binary(repo_root, runner)
    if action is Phase5Action.IMAGE_PUSH:
        docker_directory = state.root / "docker"
        try:
            if any(docker_directory.iterdir()):
                raise OperatorError("DOCKER_CONFIG_NOT_EMPTY")
        except OSError as error:
            raise OperatorError("DOCKER_CONFIG_INVALID") from error
        _verify_docker_binary(repo_root, runner)
    if action in {
        Phase5Action.PROVIDER_ACCEPTANCE,
        Phase5Action.HOSTED_ACCEPTANCE,
    }:
        _verify_gcloud_binary(repo_root, runner)
        expected = _expected_acceptance_artifact_path(
            manifest=manifest,
            state_root=state.root,
            action=action,
        )
        try:
            os.lstat(expected)
        except FileNotFoundError:
            pass
        except OSError as error:
            raise OperatorError("ACCEPTANCE_ARTIFACT_PATH_INVALID") from error
        else:
            raise OperatorError("ACCEPTANCE_ARTIFACT_ALREADY_EXISTS")


def authorize_action(
    *,
    action: Phase5Action,
    manifest: Phase5ApprovalManifest,
    approval: Phase5Approval,
    state: Phase5StateStore,
    repo_root: Path,
    now: datetime,
    runner: CommandRunner = _default_runner,
) -> Phase5Admission:
    """Perform the sole admission guard and persist admission before execution."""

    moment = _utc(now)
    if manifest.source_revision in _LEGACY_IMAGE_ID_SOURCE_REVISIONS:
        raise OperatorError("LEGACY_MANIFEST_READ_ONLY")
    _validate_approval_binding(manifest, approval)
    if moment < approval.approved_at:
        raise OperatorError("APPROVAL_NOT_YET_ACTIVE")
    if moment >= approval.approval_expires_at:
        raise OperatorError("APPROVAL_EXPIRED")
    if moment >= approval.work_deadline and not action.is_teardown:
        raise OperatorError("TEARDOWN_ONLY_WINDOW")
    _verify_exact_main(manifest, repo_root=repo_root, runner=runner)
    _verify_approved_artifacts(
        manifest,
        action=action,
        state=state,
        repo_root=repo_root,
        runner=runner,
    )
    return state.admit(
        manifest=manifest,
        approval=approval,
        action=action,
        admitted_at=moment,
    )


def _build_outcome(
    admission: Phase5Admission,
    result: object,
    *,
    finished_at: datetime,
) -> Phase5Outcome:
    if (
        not isinstance(result, subprocess.CompletedProcess)
        or type(result.returncode) is not int
        or type(result.stdout) is not bytes
        or type(result.stderr) is not bytes
        or len(result.stdout) > _MAX_OUTPUT_BYTES
        or len(result.stderr) > _MAX_OUTPUT_BYTES
    ):
        status = OutcomeStatus.UNKNOWN
        reason = OutcomeReason.INVALID_EXECUTION_RESULT
        return_code = None
        stdout = b""
        stderr = b""
    else:
        status = (
            OutcomeStatus.SUCCEEDED if result.returncode == 0 else OutcomeStatus.FAILED
        )
        reason = (
            OutcomeReason.COMMAND_SUCCEEDED
            if result.returncode == 0
            else OutcomeReason.COMMAND_FAILED
        )
        return_code = result.returncode
        stdout = result.stdout
        stderr = result.stderr
    return _seal(
        Phase5Outcome,
        schema_version=_SCHEMA,
        record_type="outcome",
        admission_sha256=admission.record_sha256,
        status=status,
        reason=reason,
        return_code=return_code,
        stdout_sha256=hashlib.sha256(stdout).hexdigest(),
        stdout_bytes=len(stdout),
        stderr_sha256=hashlib.sha256(stderr).hexdigest(),
        stderr_bytes=len(stderr),
        finished_at=_utc(finished_at),
    )


def _unknown_exception_outcome(
    admission: Phase5Admission,
    *,
    finished_at: datetime,
) -> Phase5Outcome:
    return _seal(
        Phase5Outcome,
        schema_version=_SCHEMA,
        record_type="outcome",
        admission_sha256=admission.record_sha256,
        status=OutcomeStatus.UNKNOWN,
        reason=OutcomeReason.EXECUTION_EXCEPTION,
        return_code=None,
        stdout_sha256=_EMPTY_SHA256,
        stdout_bytes=0,
        stderr_sha256=_EMPTY_SHA256,
        stderr_bytes=0,
        finished_at=_utc(finished_at),
    )


ExecutionPlanIdentity = tuple[int, int, int, str]


def _verify_docker_credential_config(directory: Path) -> None:
    _verify_artifact_directory(directory)
    path = directory / "config.json"
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    except OSError as error:
        raise OperatorError("DOCKER_CONFIG_INVALID") from error
    try:
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != os.getuid()
            or metadata.st_nlink != 1
            or stat.S_IMODE(metadata.st_mode) != 0o600
            or metadata.st_size > 65_536
        ):
            raise OperatorError("DOCKER_CONFIG_INVALID")
        chunks: list[bytes] = []
        remaining = 65_537
        while remaining > 0:
            chunk = os.read(descriptor, remaining)
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        data = b"".join(chunks)
        if len(data) != metadata.st_size:
            raise OperatorError("DOCKER_CONFIG_INVALID")
    finally:
        os.close(descriptor)
    try:
        value = json.loads(data, object_pairs_hook=_reject_duplicate_keys)
    except OperatorError:
        raise
    except (UnicodeError, ValueError, TypeError) as error:
        raise OperatorError("DOCKER_CONFIG_INVALID") from error
    if value != {"credHelpers": {f"{_REGION}-docker.pkg.dev": "gcloud"}}:
        raise OperatorError("DOCKER_CONFIG_INVALID")


def _acceptance_candidate(manifest: Phase5ApprovalManifest) -> object:
    try:
        return _acceptance.build_candidate_identity(
            source_revision=manifest.source_revision,
            image_digest=manifest.image_digest,
            infrastructure_revision=manifest.infrastructure_revision,
            semantic_config_sha256=manifest.semantic_config_sha256,
        )
    except (TypeError, ValueError) as error:
        raise OperatorError("ACCEPTANCE_CANDIDATE_INVALID") from error


def _expected_acceptance_artifact_path(
    *,
    manifest: Phase5ApprovalManifest,
    state_root: Path,
    action: Phase5Action,
) -> Path:
    candidate = _acceptance_candidate(manifest)
    digest = getattr(candidate, "candidate_sha256", None)
    if not isinstance(digest, str) or _SHA256_PATTERN.fullmatch(digest) is None:
        raise OperatorError("ACCEPTANCE_CANDIDATE_INVALID")
    if action is Phase5Action.PROVIDER_ACCEPTANCE:
        mode = "provider"
    elif action is Phase5Action.HOSTED_ACCEPTANCE:
        mode = "hosted"
    else:
        raise OperatorError("ACCEPTANCE_ACTION_INVALID")
    return state_root / "acceptance" / f"{mode}-{digest}.json"


def _capture_acceptance_artifact(
    *,
    manifest: Phase5ApprovalManifest,
    state_root: Path,
    action: Phase5Action,
) -> dict[str, Any]:
    candidate = _acceptance_candidate(manifest)
    mode = (
        _acceptance.AcceptanceMode.PROVIDER
        if action is Phase5Action.PROVIDER_ACCEPTANCE
        else _acceptance.AcceptanceMode.HOSTED
    )
    expected_path = _expected_acceptance_artifact_path(
        manifest=manifest,
        state_root=state_root,
        action=action,
    )
    try:
        record, binding = _acceptance.read_acceptance_record(
            state_root, candidate, mode
        )
    except Exception as error:
        raise OperatorError("ACCEPTANCE_ARTIFACT_INVALID") from error
    record_candidate = getattr(record, "candidate", None)
    if (
        record_candidate != candidate
        or binding.mode is not mode
        or binding.path != str(expected_path)
        or getattr(record, "record_sha256", None) != binding.record_sha256
    ):
        raise OperatorError("ACCEPTANCE_ARTIFACT_INVALID")
    return {
        "acceptance_mode": mode.value,
        "acceptance_artifact_path": binding.path,
        "acceptance_record_sha256": binding.record_sha256,
        "acceptance_file_sha256": binding.file_sha256,
        "acceptance_byte_count": binding.byte_count,
    }


def _seal_execution_plan(path: Path) -> ExecutionPlanIdentity:
    _verify_artifact_directory(path.parent)
    canonical = _canonical_absolute_path(path, require_exists=True)
    try:
        descriptor = os.open(
            canonical,
            os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW,
        )
    except OSError as error:
        raise OperatorError("EXECUTION_PLAN_INVALID") from error
    try:
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_uid != os.getuid()
            or before.st_nlink != 1
            or before.st_size < 1
            or before.st_size > _MAX_ARTIFACT_BYTES
        ):
            raise OperatorError("EXECUTION_PLAN_INVALID")
        os.fchmod(descriptor, 0o400)
        os.fsync(descriptor)
        os.lseek(descriptor, 0, os.SEEK_SET)
        digest = hashlib.sha256()
        observed = 0
        while chunk := os.read(descriptor, 1_048_576):
            observed += len(chunk)
            if observed > _MAX_ARTIFACT_BYTES:
                raise OperatorError("EXECUTION_PLAN_INVALID")
            digest.update(chunk)
        after = os.fstat(descriptor)
        if (
            observed != before.st_size
            or not stat.S_ISREG(after.st_mode)
            or after.st_uid != os.getuid()
            or stat.S_IMODE(after.st_mode) != 0o400
            or after.st_nlink != 1
            or after.st_size != before.st_size
            or (after.st_dev, after.st_ino) != (before.st_dev, before.st_ino)
        ):
            raise OperatorError("EXECUTION_PLAN_INVALID")
        return after.st_dev, after.st_ino, after.st_size, digest.hexdigest()
    except OSError as error:
        raise OperatorError("EXECUTION_PLAN_INVALID") from error
    finally:
        os.close(descriptor)


def _verify_execution_plan(
    path: Path,
    expected: ExecutionPlanIdentity,
) -> None:
    canonical = _canonical_absolute_path(path, require_exists=True)
    observed_digest = _immutable_file_sha256(canonical)
    try:
        metadata = os.stat(canonical, follow_symlinks=False)
    except OSError as error:
        raise OperatorError("EXECUTION_PLAN_DRIFT") from error
    observed = (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_size,
        observed_digest,
    )
    if observed != expected:
        raise OperatorError("EXECUTION_PLAN_DRIFT")


_MISSING = object()


def _valid_unknown_mask(value: JsonValue, *, depth: int = 0) -> bool:
    if depth > 64:
        return False
    if type(value) is bool:
        return True
    if isinstance(value, dict):
        return all(
            isinstance(key, str) and _valid_unknown_mask(child, depth=depth + 1)
            for key, child in value.items()
        )
    if isinstance(value, list):
        return all(_valid_unknown_mask(child, depth=depth + 1) for child in value)
    return False


def _unknown_mask_valid_for_value(
    expected: JsonValue | object,
    mask: JsonValue,
    *,
    depth: int = 0,
) -> bool:
    if depth > 64 or not _valid_unknown_mask(mask, depth=depth):
        return False
    if mask is True:
        return expected is _MISSING or expected is None
    if mask is False:
        return expected is not _MISSING
    if isinstance(mask, dict):
        if not isinstance(expected, dict):
            return False
        return all(
            _unknown_mask_valid_for_value(
                expected.get(key, _MISSING),
                child,
                depth=depth + 1,
            )
            for key, child in mask.items()
        )
    if isinstance(mask, list):
        return (
            isinstance(expected, list)
            and len(mask) == len(expected)
            and all(
                _unknown_mask_valid_for_value(
                    expected_value,
                    child,
                    depth=depth + 1,
                )
                for expected_value, child in zip(expected, mask, strict=True)
            )
        )
    return False


def _mask_contains_true(value: JsonValue | None) -> bool:
    if value is True:
        return True
    if isinstance(value, dict):
        return any(_mask_contains_true(child) for child in value.values())
    if isinstance(value, list):
        return any(_mask_contains_true(child) for child in value)
    return False


def _matches_approved_before(
    actual: JsonValue,
    expected: JsonValue,
    unknown: JsonValue | None,
    *,
    depth: int = 0,
) -> bool:
    if depth > 64:
        return False
    if unknown is True:
        return True
    if unknown is None or unknown is False:
        if _canonical_value_bytes(actual) == _canonical_value_bytes(expected):
            return True
        if expected is None:
            return (
                actual is False
                or (isinstance(actual, str) and not actual)
                or (isinstance(actual, list) and not actual)
                or (isinstance(actual, dict) and not actual)
            )
        if isinstance(actual, dict) and isinstance(expected, dict):
            return set(actual) == set(expected) and all(
                _matches_approved_before(
                    actual[key],
                    expected_value,
                    None,
                    depth=depth + 1,
                )
                for key, expected_value in expected.items()
            )
        if isinstance(actual, list) and isinstance(expected, list):
            return len(actual) == len(expected) and all(
                _matches_approved_before(
                    actual_value,
                    expected_value,
                    None,
                    depth=depth + 1,
                )
                for actual_value, expected_value in zip(actual, expected, strict=True)
            )
        return False
    if isinstance(unknown, dict):
        if not isinstance(actual, dict) or not isinstance(expected, dict):
            return False
        if set(actual) - (set(expected) | set(unknown)):
            return False
        for key, expected_value in expected.items():
            child_unknown = unknown.get(key)
            if key not in actual:
                if child_unknown is True:
                    continue
                return False
            if not _matches_approved_before(
                actual[key],
                expected_value,
                child_unknown,
                depth=depth + 1,
            ):
                return False
        return all(
            key in expected
            or _matches_approved_before(
                actual[key],
                None,
                mask,
                depth=depth + 1,
            )
            for key, mask in unknown.items()
            if key in actual
        )
    if isinstance(unknown, list):
        if (
            not isinstance(actual, list)
            or not isinstance(expected, list)
            or len(actual) != len(expected)
            or len(unknown) != len(expected)
        ):
            return False
        return all(
            _matches_approved_before(
                actual_value,
                expected_value,
                mask,
                depth=depth + 1,
            )
            for actual_value, expected_value, mask in zip(
                actual, expected, unknown, strict=True
            )
        )
    return False


def _matches_approved_teardown_resource(
    actual: JsonValue,
    expected: JsonValue,
    unknown: JsonValue | None,
    *,
    resource_type: str,
    action: Phase5Action | None = None,
) -> bool:
    normalized = _normalize_observed_teardown_resource(
        actual,
        expected,
        resource_type=resource_type,
        action=action,
    )
    if _matches_approved_before(normalized, expected, unknown):
        return True
    if (
        resource_type != "google_cloud_run_v2_service_iam_member"
        or not isinstance(normalized, dict)
        or not isinstance(expected, dict)
    ):
        return False
    expected_project = expected.get("project")
    expected_location = expected.get("location")
    expected_name = expected.get("name")
    if not all(
        isinstance(item, str) and item and "/" not in item
        for item in (expected_project, expected_location, expected_name)
    ):
        return False
    canonical_name = (
        f"projects/{expected_project}/locations/{expected_location}/services/"
        f"{expected_name}"
    )
    if normalized.get("name") != canonical_name:
        return False
    canonicalized = dict(normalized)
    canonicalized["name"] = expected_name
    return _matches_approved_before(canonicalized, expected, unknown)


def _normalize_observed_teardown_resource(
    actual: JsonValue,
    expected: JsonValue,
    *,
    resource_type: str,
    action: Phase5Action | None = None,
) -> JsonValue:
    if not isinstance(actual, dict) or not isinstance(expected, dict):
        return actual
    normalized = json.loads(_canonical_value_bytes(actual))
    if not isinstance(normalized, dict):  # pragma: no cover - canonical object above
        return actual

    if resource_type == "google_artifact_registry_repository":
        policies = normalized.get("cleanup_policies")
        expected_policies = expected.get("cleanup_policies")
        if isinstance(policies, list) and isinstance(expected_policies, list):
            for policy, expected_policy in zip(
                policies, expected_policies, strict=True
            ):
                if not isinstance(policy, dict) or not isinstance(
                    expected_policy, dict
                ):
                    continue
                conditions = policy.get("condition")
                expected_conditions = expected_policy.get("condition")
                if (
                    isinstance(conditions, list)
                    and isinstance(expected_conditions, list)
                    and len(conditions) == len(expected_conditions) == 1
                    and isinstance(conditions[0], dict)
                    and isinstance(expected_conditions[0], dict)
                    and conditions[0].get("older_than") == "86400s"
                    and expected_conditions[0].get("older_than") == "1d"
                ):
                    conditions[0]["older_than"] = "1d"

    if resource_type == "google_artifact_registry_repository_iam_member":
        project = expected.get("project")
        location = expected.get("location")
        repository = expected.get("repository")
        if all(
            isinstance(item, str) and item and "/" not in item
            for item in (project, location, repository)
        ):
            canonical_repository = (
                f"projects/{project}/locations/{location}/repositories/{repository}"
            )
            if normalized.get("repository") == canonical_repository:
                normalized["repository"] = repository

    if (
        resource_type == "google_cloud_run_v2_service"
        and action is Phase5Action.RUNTIME_TEARDOWN
        and expected.get("name") == "reconcile-p5-canary"
    ):
        expected_templates = expected.get("template")
        observed_templates = normalized.get("template")
        if (
            isinstance(expected_templates, list)
            and isinstance(observed_templates, list)
            and len(expected_templates) == len(observed_templates) == 1
            and isinstance(expected_templates[0], dict)
            and isinstance(observed_templates[0], dict)
        ):
            expected_template = expected_templates[0]
            observed_template = observed_templates[0]
            expected_containers = expected_template.get("containers")
            observed_containers = observed_template.get("containers")
            expected_labels = expected_template.get("labels")
            observed_labels = observed_template.get("labels")
            if (
                isinstance(expected_containers, list)
                and isinstance(observed_containers, list)
                and len(expected_containers) == len(observed_containers) == 1
                and isinstance(expected_containers[0], dict)
                and isinstance(observed_containers[0], dict)
                and isinstance(expected_labels, dict)
                and isinstance(observed_labels, dict)
            ):
                expected_environment = expected_containers[0].get("env")
                observed_environment = observed_containers[0].get("env")
                if isinstance(expected_environment, list) and isinstance(
                    observed_environment, list
                ):
                    expected_by_name = {
                        item.get("name"): item
                        for item in expected_environment
                        if isinstance(item, dict) and isinstance(item.get("name"), str)
                    }
                    observed_by_name = {
                        item.get("name"): item
                        for item in observed_environment
                        if isinstance(item, dict) and isinstance(item.get("name"), str)
                    }
                    source = expected_by_name.get("RECONCILE_SOURCE_REVISION")
                    expected_release = expected_by_name.get(
                        "RECONCILE_CANARY_RELEASE_ID"
                    )
                    observed_release = observed_by_name.get(
                        "RECONCILE_CANARY_RELEASE_ID"
                    )
                    source_revision = (
                        source.get("value") if isinstance(source, dict) else None
                    )
                    release_id = (
                        f"p5-release-{source_revision[:24]}"
                        if isinstance(source_revision, str)
                        and re.fullmatch(r"[0-9a-f]{40}", source_revision)
                        else None
                    )
                    staged_revision = (
                        deterministic_stage_revision(
                            service="reconcile-p5-canary",
                            release_id=release_id,
                        )
                        if release_id is not None
                        else None
                    )
                    if (
                        len(expected_by_name) == len(expected_environment)
                        and len(observed_by_name) == len(observed_environment)
                        and isinstance(expected_release, dict)
                        and isinstance(observed_release, dict)
                        and expected_release.get("value") == "baseline"
                        and observed_release.get("value") == release_id
                        and expected_labels.get("reconcile-release") == "baseline"
                        and observed_labels.get("reconcile-release") == release_id
                        and observed_template.get("revision") == staged_revision
                    ):
                        observed_release["value"] = "baseline"
                        observed_labels["reconcile-release"] = "baseline"
                        observed_template["revision"] = expected_template.get(
                            "revision"
                        )

    if resource_type == "google_billing_budget":
        amounts = normalized.get("amount")
        expected_amounts = expected.get("amount")
        if (
            isinstance(amounts, list)
            and isinstance(expected_amounts, list)
            and len(amounts) == len(expected_amounts) == 1
            and isinstance(amounts[0], dict)
            and isinstance(expected_amounts[0], dict)
        ):
            if (
                amounts[0].get("last_period_amount") is False
                and expected_amounts[0].get("last_period_amount") is None
            ):
                amounts[0]["last_period_amount"] = None
            specified = amounts[0].get("specified_amount")
            expected_specified = expected_amounts[0].get("specified_amount")
            if (
                isinstance(specified, list)
                and isinstance(expected_specified, list)
                and len(specified) == len(expected_specified) == 1
                and isinstance(specified[0], dict)
                and isinstance(expected_specified[0], dict)
                and type(specified[0].get("nanos")) is int
                and specified[0].get("nanos") == 0
                and expected_specified[0].get("nanos") is None
            ):
                specified[0]["nanos"] = None
        filters = normalized.get("budget_filter")
        expected_filters = expected.get("budget_filter")
        if (
            isinstance(filters, list)
            and isinstance(expected_filters, list)
            and len(filters) == len(expected_filters) == 1
            and isinstance(filters[0], dict)
            and isinstance(expected_filters[0], dict)
            and filters[0].get("calendar_period") == "MONTH"
            and expected_filters[0].get("calendar_period") is None
        ):
            filters[0]["calendar_period"] = None

    if resource_type == "google_storage_bucket":
        if (
            normalized.get("hierarchical_namespace") == [{"enabled": False}]
            and expected.get("hierarchical_namespace") == []
        ):
            normalized["hierarchical_namespace"] = []
        if action in {
            Phase5Action.STATE_PROTECTION_CHANGE,
            Phase5Action.BOOTSTRAP_TEARDOWN,
        }:
            for field in (
                "default_event_based_hold",
                "enable_object_retention",
                "requester_pays",
            ):
                if normalized.get(field) is False and expected.get(field) is None:
                    normalized[field] = None
            if (
                normalized.get("force_destroy") is False
                and normalized.get("deletion_policy") == "PREVENT"
                and expected.get("force_destroy") is True
                and expected.get("deletion_policy") == "DELETE"
            ):
                normalized["force_destroy"] = True
                normalized["deletion_policy"] = "DELETE"

    if resource_type == "google_storage_bucket_iam_member":
        bucket = normalized.get("bucket")
        expected_bucket = expected.get("bucket")
        if isinstance(expected_bucket, str) and bucket == f"b/{expected_bucket}":
            normalized["bucket"] = expected_bucket

    return normalized  # type: ignore[return-value]


def _plan_changes_by_address(data: bytes) -> dict[str, dict[str, Any]]:
    def reject_constant(_: str) -> None:
        raise ValueError("non-finite JSON number")

    try:
        value = json.loads(
            data,
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=reject_constant,
        )
    except OperatorError:
        raise
    except (UnicodeError, ValueError, TypeError) as error:
        raise OperatorError("TERRAFORM_PLAN_INVALID") from error
    changes = value.get("resource_changes") if isinstance(value, dict) else None
    if not isinstance(changes, list):
        raise OperatorError("TERRAFORM_PLAN_INVALID")
    result: dict[str, dict[str, Any]] = {}
    for item in changes:
        address = item.get("address") if isinstance(item, dict) else None
        change = item.get("change") if isinstance(item, dict) else None
        if (
            not isinstance(address, str)
            or not isinstance(change, dict)
            or address in result
        ):
            raise OperatorError("TERRAFORM_PLAN_INVALID")
        result[address] = change
    return result


def _verify_runtime_update_plan(
    rendered: bytes,
    expected: TerraformPlanBinding,
    resources: tuple[PlanResourceBinding, ...],
    iam_edges: tuple[PlanIamBinding, ...],
    variables: dict[str, Any],
) -> None:
    qualification = _read_bounded_file(
        Path(expected.qualification_path),
        maximum=_MAX_PLAN_JSON_BYTES,
        immutable=True,
    )
    if hashlib.sha256(qualification).hexdigest() != expected.qualification_sha256:
        raise OperatorError("EXECUTION_PLAN_DRIFT")
    (
        approved_normalized,
        approved_resources,
        approved_iam_edges,
        _,
        _,
    ) = _parse_plan_json(qualification)
    if (
        hashlib.sha256(approved_normalized).hexdigest()
        != expected.normalized_plan_sha256
        or approved_resources != expected.resources
        or approved_iam_edges != expected.iam_edges
        or hashlib.sha256(_canonical_value_bytes(variables)).hexdigest()
        != expected.variables_sha256
    ):
        raise OperatorError("EXECUTION_PLAN_DRIFT")

    approved_by_address = {item.address: item for item in expected.resources}
    approved_iam_by_address = {item.address: item for item in expected.iam_edges}
    live_iam_by_address = {item.address: item for item in iam_edges}
    approved_changes = _plan_changes_by_address(qualification)
    live_changes = _plan_changes_by_address(rendered)
    reprovisioned_addresses = {
        "google_cloud_run_v2_service.canary",
        "google_cloud_run_v2_service_iam_member.canary_invoker",
        "google_cloud_run_v2_service_iam_member.canary_mutator",
        "google_cloud_run_v2_service_iam_member.canary_reader",
        "terraform_data.canary_baseline",
    }
    if (
        set(live_changes) != set(approved_changes)
        or {item.address for item in resources} != set(approved_by_address)
        or set(live_iam_by_address) != set(approved_iam_by_address)
        or any(item.actions != ("create",) for item in expected.resources)
    ):
        raise OperatorError("EXECUTION_PLAN_DRIFT")

    service_updates = 0
    for item in resources:
        approved = approved_by_address[item.address]
        approved_change = approved_changes[item.address]
        live_change = live_changes[item.address]
        live_after_unknown = live_change.get("after_unknown")
        reprovisioned = item.address in reprovisioned_addresses
        iam_resource = item.address in approved_iam_by_address
        expected_actions = (
            ("delete", "create")
            if reprovisioned
            else (
                ("update",)
                if item.resource_type == "google_cloud_run_v2_service"
                else ("no-op",)
            )
        )
        if (
            item.resource_type != approved.resource_type
            or item.provider_name != approved.provider_name
            or item.before_projection is None
            or item.before_unknown is not None
            or item.actions != expected_actions
            or (
                reprovisioned
                and _canonical_value_bytes(live_after_unknown)
                != _canonical_value_bytes(approved_change.get("after_unknown"))
            )
            or (not reprovisioned and live_after_unknown not in (None, {}))
            or (
                not iam_resource
                and not _matches_approved_before(
                    live_change.get("after"),
                    approved_change.get("after"),
                    approved_change.get("after_unknown"),
                )
            )
            or (
                expected_actions == ("no-op",)
                and _canonical_value_bytes(live_change.get("before"))
                != _canonical_value_bytes(live_change.get("after"))
            )
        ):
            raise OperatorError("EXECUTION_PLAN_DRIFT")
        if item.resource_type == "google_cloud_run_v2_service":
            if not reprovisioned:
                service_updates += 1
            continue
        if not iam_resource and not reprovisioned:
            raise OperatorError("EXECUTION_PLAN_DRIFT")
        approved_iam = approved_iam_by_address.get(item.address)
        live_iam = live_iam_by_address.get(item.address)
        if not iam_resource:
            continue
        if approved_iam is None or live_iam is None:  # pragma: no cover - mapped above
            raise OperatorError("EXECUTION_PLAN_DRIFT")
        expected_authority_unknown = (
            approved_iam.authority_unknown if reprovisioned else None
        )
        if (
            live_iam.resource_type != approved_iam.resource_type
            or live_iam.actions != expected_actions
            or live_iam.role != approved_iam.role
            or live_iam.member != approved_iam.member
            or _canonical_value_bytes(live_iam.authority_unknown)
            != _canonical_value_bytes(expected_authority_unknown)
            or not _matches_approved_before(
                live_iam.authority_projection,
                approved_iam.authority_projection,
                approved_iam.authority_unknown,
            )
        ):
            raise OperatorError("EXECUTION_PLAN_DRIFT")
    if service_updates < 1:
        raise OperatorError("EXECUTION_PLAN_DRIFT")


def _verify_bootstrap_protection_update_plan(
    rendered: bytes,
    expected: TerraformPlanBinding,
) -> None:
    _, resources, iam_edges, _, variables = _parse_plan_json(rendered)
    approved_by_address = {item.address: item for item in expected.resources}
    bucket_address = "google_storage_bucket.terraform_state"
    service_addresses = {
        item.address
        for item in expected.resources
        if item.resource_type == "google_project_service"
        and item.address.startswith('google_project_service.bootstrap_required["')
    }
    expected_addresses = service_addresses | {bucket_address}
    live_by_address = {item.address: item for item in resources}
    live_changes = _plan_changes_by_address(rendered)
    if (
        expected.action is not Phase5Action.BOOTSTRAP_TEARDOWN
        or len(service_addresses) != 6
        or set(live_by_address) != expected_addresses
        or set(live_changes) != expected_addresses
        or iam_edges
        or hashlib.sha256(_canonical_value_bytes(variables)).hexdigest()
        != expected.variables_sha256
    ):
        raise OperatorError("EXECUTION_PLAN_DRIFT")

    for address in sorted(service_addresses):
        item = live_by_address[address]
        approved = approved_by_address[address]
        change = live_changes[address]
        before = change.get("before")
        after = change.get("after")
        if (
            approved.actions != ("delete",)
            or item.resource_type != approved.resource_type
            or item.provider_name != approved.provider_name
            or item.actions != ("no-op",)
            or item.before_unknown is not None
            or change.get("after_unknown") not in (None, {})
            or _canonical_value_bytes(before) != _canonical_value_bytes(after)
            or not _matches_approved_teardown_resource(
                before,
                approved.before_projection,
                approved.before_unknown,
                resource_type=item.resource_type,
                action=Phase5Action.BOOTSTRAP_TEARDOWN,
            )
        ):
            raise OperatorError("EXECUTION_PLAN_DRIFT")

    bucket = live_by_address[bucket_address]
    approved_bucket = approved_by_address[bucket_address]
    bucket_change = live_changes[bucket_address]
    before = bucket_change.get("before")
    after = bucket_change.get("after")
    if (
        approved_bucket.actions != ("delete",)
        or bucket.resource_type != "google_storage_bucket"
        or bucket.resource_type != approved_bucket.resource_type
        or bucket.provider_name != approved_bucket.provider_name
        or bucket.actions != ("update",)
        or bucket.before_unknown is not None
        or bucket_change.get("after_unknown") not in (None, {})
        or not isinstance(before, dict)
        or not isinstance(after, dict)
        or before.get("force_destroy") is not False
        or before.get("deletion_policy") != "PREVENT"
        or after.get("force_destroy") is not True
        or after.get("deletion_policy") != "DELETE"
        or not _matches_approved_teardown_resource(
            before,
            approved_bucket.before_projection,
            approved_bucket.before_unknown,
            resource_type=bucket.resource_type,
            action=Phase5Action.STATE_PROTECTION_CHANGE,
        )
        or not _matches_approved_teardown_resource(
            after,
            approved_bucket.before_projection,
            approved_bucket.before_unknown,
            resource_type=bucket.resource_type,
            action=Phase5Action.BOOTSTRAP_TEARDOWN,
        )
    ):
        raise OperatorError("EXECUTION_PLAN_DRIFT")


def _verify_rendered_plan(
    rendered: bytes,
    expected: TerraformPlanBinding,
) -> None:
    allow_subset = expected.action.is_teardown
    normalized, resources, iam_edges, _, variables = _parse_plan_json(
        rendered,
        allow_empty=allow_subset,
    )
    if allow_subset:
        expected_resources = {item.address: item for item in expected.resources}
        expected_iam = {item.address: item for item in expected.iam_edges}
        resource_addresses = tuple(item.address for item in resources)
        iam_addresses = tuple(item.address for item in iam_edges)
        resources_match = all(
            (
                (approved := expected_resources.get(item.address)) is not None
                and item.resource_type == approved.resource_type
                and item.provider_name == approved.provider_name
                and item.actions == ("delete",)
                and item.after_sha256 == approved.after_sha256
                and item.before_unknown is None
                and _matches_approved_teardown_resource(
                    item.before_projection,
                    approved.before_projection,
                    approved.before_unknown,
                    resource_type=item.resource_type,
                    action=expected.action,
                )
            )
            for item in resources
        )
        if (
            hashlib.sha256(_canonical_value_bytes(variables)).hexdigest()
            != expected.variables_sha256
            or any(item.actions != ("delete",) for item in expected.resources)
            or len(resource_addresses) != len(set(resource_addresses))
            or len(iam_addresses) != len(set(iam_addresses))
            or not resources_match
            or any(
                (approved := expected_iam.get(item.address)) is None
                or item.resource_type != approved.resource_type
                or item.actions != ("delete",)
                or item.role != approved.role
                or item.member != approved.member
                or item.authority_unknown is not None
                or not _matches_approved_teardown_resource(
                    item.authority_projection,
                    approved.authority_projection,
                    approved.authority_unknown,
                    resource_type=item.resource_type,
                    action=expected.action,
                )
                for item in iam_edges
            )
        ):
            raise OperatorError("EXECUTION_PLAN_DRIFT")
        return
    has_drift = (
        hashlib.sha256(normalized).hexdigest() != expected.normalized_plan_sha256
        or resources != expected.resources
        or iam_edges != expected.iam_edges
        or _hash_value([item.model_dump(mode="json") for item in resources])
        != expected.resource_inventory_sha256
        or _hash_value([item.model_dump(mode="json") for item in iam_edges])
        != expected.iam_inventory_sha256
    )
    if not has_drift:
        return
    if expected.action is Phase5Action.RUNTIME_APPLY:
        _verify_runtime_update_plan(
            rendered,
            expected,
            resources,
            iam_edges,
            variables,
        )
        return
    raise OperatorError("EXECUTION_PLAN_DRIFT")


def _run_descriptor_once(
    descriptor: CommandDescriptor,
    *,
    repo_root: Path,
    execution_source: ExecutionSourceBinding,
    runner: CommandRunner,
    image_artifact: ImageArtifactBinding,
    python_dependencies: PythonDependencyBinding | None,
    terraform_plan: TerraformPlanBinding | None,
    deadline: datetime,
    clock: Callable[[], datetime],
    sleeper: Callable[[float], None] = time.sleep,
) -> object:
    source_root = _canonical_absolute_path(
        Path(execution_source.root), require_exists=True
    )
    if _canonical_absolute_path(repo_root, require_exists=True) != source_root:
        raise OperatorError("EXECUTION_SOURCE_CWD_DRIFT")
    stdout_parts: list[bytes] = []
    stderr_parts: list[bytes] = []
    final_code = 0
    environment = _minimal_subprocess_environment(descriptor.environment)
    execution_identities: dict[Path, ExecutionPlanIdentity] = {}
    plan_stages: tuple[tuple[int, int, int, Path, bool], ...] = ()
    if terraform_plan is not None:
        if descriptor.action is Phase5Action.BOOTSTRAP_TEARDOWN:
            protection_path = Path(terraform_plan.execution_plan_path).with_name(
                "bootstrap-final-protection-update.tfplan"
            )
            plan_stages = (
                (2, 3, 4, protection_path, True),
                (5, 6, 7, Path(terraform_plan.execution_plan_path), False),
            )
        else:
            terraform_index_offset = (
                1 if descriptor.action is Phase5Action.BOOTSTRAP_APPLY else 0
            )
            plan_stages = (
                (
                    terraform_index_offset + 1,
                    terraform_index_offset + 2,
                    terraform_index_offset + 3,
                    Path(terraform_plan.execution_plan_path),
                    False,
                ),
            )
    plan_by_index = {stage[0]: stage for stage in plan_stages}
    show_by_index = {stage[1]: stage for stage in plan_stages}
    apply_by_index = {stage[2]: stage for stage in plan_stages}
    for index, command in enumerate(descriptor.commands):
        if (apply_stage := apply_by_index.get(index)) is not None:
            execution_path = apply_stage[3]
            execution_identity = execution_identities.get(execution_path)
            if execution_identity is None:
                return object()
            _verify_execution_plan(execution_path, execution_identity)
        retry_delays = (
            iter(_FOUNDATION_INIT_RETRY_DELAYS_SECONDS)
            if descriptor.action is Phase5Action.FOUNDATION_APPLY
            and index == 0
            and command == _FOUNDATION_INIT_COMMAND
            else iter(())
        )
        while True:
            remaining_seconds = int((_utc(deadline) - _utc(clock())).total_seconds())
            if remaining_seconds < 1:
                return object()
            _verify_execution_source_binding(execution_source)
            if command[0] == _TERRAFORM:
                cli_config = environment.get("TF_CLI_CONFIG_FILE")
                if cli_config is None:
                    return object()
                _verify_terraform_binary(
                    source_root,
                    runner,
                    cli_config=Path(cli_config),
                    timeout_seconds=min(15, remaining_seconds),
                )
            if descriptor.action in {
                Phase5Action.PROVIDER_ACCEPTANCE,
                Phase5Action.HOSTED_ACCEPTANCE,
            }:
                _verify_python_interpreter()
                if python_dependencies is None:
                    return object()
                _verify_python_dependency_binding(python_dependencies)
                expected_pythonpath = f"{source_root}:{python_dependencies.root}"
                if environment.get("PYTHONPATH") != expected_pythonpath:
                    return object()
            remaining_seconds = int((_utc(deadline) - _utc(clock())).total_seconds())
            if remaining_seconds < 1:
                return object()
            result = runner(
                command,
                cwd=source_root,
                environment=environment,
                timeout_seconds=min(descriptor.timeout_seconds, remaining_seconds),
            )
            if _utc(clock()) >= _utc(deadline):
                return object()
            if (
                not isinstance(result, subprocess.CompletedProcess)
                or type(result.returncode) is not int
                or type(result.stdout) is not bytes
                or type(result.stderr) is not bytes
                or len(result.stdout)
                > (
                    _MAX_PLAN_JSON_BYTES
                    if index in show_by_index
                    else _MAX_OUTPUT_BYTES
                )
                or len(result.stderr) > _MAX_OUTPUT_BYTES
            ):
                return object()
            recorded_stdout = result.stdout
            if index in show_by_index:
                recorded_stdout = (
                    hashlib.sha256(result.stdout).hexdigest().encode("ascii")
                )
            stdout_parts.append(
                len(recorded_stdout).to_bytes(8, "big") + recorded_stdout
            )
            stderr_parts.append(len(result.stderr).to_bytes(8, "big") + result.stderr)
            if (
                sum(map(len, stdout_parts)) > _MAX_OUTPUT_BYTES
                or sum(map(len, stderr_parts)) > _MAX_OUTPUT_BYTES
            ):
                return object()
            cleanup_already_empty = (
                descriptor.action is Phase5Action.BOOTSTRAP_TEARDOWN
                and index == 0
                and command == _state_bucket_cleanup_command()
                and result.returncode == 1
                and result.stdout == b""
                and result.stderr == _EMPTY_STATE_BUCKET_CLEANUP_STDERR
            )
            final_code = 0 if cleanup_already_empty else result.returncode
            if final_code == 0:
                break
            if final_code != 1:
                break
            try:
                retry_delay = next(retry_delays)
            except StopIteration:
                break
            remaining_seconds = int((_utc(deadline) - _utc(clock())).total_seconds())
            if remaining_seconds <= retry_delay:
                return object()
            sleeper(retry_delay)
        if final_code != 0:
            break
        if (plan_stage := plan_by_index.get(index)) is not None:
            execution_path = plan_stage[3]
            execution_identities[execution_path] = _seal_execution_plan(execution_path)
        if (show_stage := show_by_index.get(index)) is not None:
            execution_path = show_stage[3]
            execution_identity = execution_identities.get(execution_path)
            if execution_identity is None:
                return object()
            _verify_execution_plan(execution_path, execution_identity)
            if terraform_plan is None:  # pragma: no cover - stages require a plan
                return object()
            if show_stage[4]:
                _verify_bootstrap_protection_update_plan(
                    result.stdout,
                    terraform_plan,
                )
            else:
                _verify_rendered_plan(result.stdout, terraform_plan)
        if descriptor.action is Phase5Action.IMAGE_PUSH and index == 0:
            docker_config = next(
                (
                    item.value
                    for item in descriptor.environment
                    if item.name == "DOCKER_CONFIG"
                ),
                None,
            )
            if docker_config is None:
                return object()
            _verify_docker_credential_config(Path(docker_config))
        if (
            descriptor.action is Phase5Action.IMAGE_PUSH
            and index == 2
            and result.stdout != f"{image_artifact.manifest_digest}\n".encode()
        ):
            return object()
        if (
            descriptor.action is Phase5Action.IMAGE_PUSH
            and index == 4
            and result.stdout != f"{image_artifact.manifest_digest}\n".encode()
        ):
            return object()
    return subprocess.CompletedProcess(
        [list(item) for item in descriptor.commands],
        final_code,
        b"".join(stdout_parts),
        b"".join(stderr_parts),
    )


def execute_action(
    *,
    action: Phase5Action,
    manifest: Phase5ApprovalManifest,
    approval: Phase5Approval,
    state: Phase5StateStore,
    repo_root: Path,
    now: datetime,
    runner: CommandRunner = _default_runner,
    clock: Callable[[], datetime] = lambda: datetime.now(UTC),
) -> Phase5Evidence:
    """Authorize once, execute once without a shell, and seal sanitized evidence."""

    admission = authorize_action(
        action=action,
        manifest=manifest,
        approval=approval,
        state=state,
        repo_root=repo_root,
        now=now,
        runner=runner,
    )
    descriptor = manifest.command_for(action)
    deadline = (
        approval.approval_expires_at
        if action.is_teardown
        else min(approval.work_deadline, approval.approval_expires_at)
    )
    acceptance_artifact: dict[str, Any] = {}
    try:
        result = _run_descriptor_once(
            descriptor,
            repo_root=Path(manifest.execution_source.root),
            execution_source=manifest.execution_source,
            runner=runner,
            image_artifact=manifest.image_artifact,
            python_dependencies=manifest.python_dependencies,
            terraform_plan=manifest.terraform_plan_for(action),
            deadline=deadline,
            clock=clock,
        )
        if (
            action
            in {
                Phase5Action.PROVIDER_ACCEPTANCE,
                Phase5Action.HOSTED_ACCEPTANCE,
            }
            and isinstance(result, subprocess.CompletedProcess)
            and result.returncode == 0
        ):
            try:
                acceptance_artifact = _capture_acceptance_artifact(
                    manifest=manifest,
                    state_root=state.root,
                    action=action,
                )
            except OperatorError:
                result = object()
        finished_at = _utc(clock())
        if (
            isinstance(result, subprocess.CompletedProcess)
            and result.returncode == 0
            and finished_at >= _utc(deadline)
        ):
            result = object()
            acceptance_artifact = {}
        outcome = _build_outcome(admission, result, finished_at=finished_at)
    except Exception:
        outcome = _unknown_exception_outcome(admission, finished_at=clock())
    evidence = _seal(
        Phase5Evidence,
        schema_version=_SCHEMA,
        record_type="evidence",
        manifest_sha256=manifest.record_sha256,
        approval_sha256=approval.record_sha256,
        admission_sha256=admission.record_sha256,
        outcome_sha256=outcome.record_sha256,
        action=action,
        status=outcome.status,
        observed_at=outcome.finished_at,
        **acceptance_artifact,
    )
    state.complete(admission=admission, outcome=outcome, evidence=evidence)
    return evidence


def _read_private_canonical_file[ModelT: StrictModel](
    path: Path, model_type: type[ModelT]
) -> ModelT:
    canonical = _canonical_absolute_path(path, require_exists=True)
    flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW
    try:
        descriptor = os.open(canonical, flags)
    except OSError as error:
        raise OperatorError("INPUT_FILE_UNAVAILABLE") from error
    try:
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != os.getuid()
            or stat.S_IMODE(metadata.st_mode) != 0o600
            or metadata.st_size > _MAX_RECORD_BYTES
        ):
            raise OperatorError("INPUT_FILE_NOT_PRIVATE")
        data = os.read(descriptor, _MAX_RECORD_BYTES + 1)
        if len(data) > _MAX_RECORD_BYTES:
            raise OperatorError("INPUT_FILE_TOO_LARGE")
    finally:
        os.close(descriptor)
    return _parse_canonical_model(data, model_type)


def _parse_timestamp(value: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as error:
        raise argparse.ArgumentTypeError("timestamp must be ISO 8601") from error
    if parsed.tzinfo is None:
        raise argparse.ArgumentTypeError("timestamp must include an offset")
    return parsed.astimezone(UTC)


def _default_state_root() -> Path:
    base = os.environ.get("XDG_STATE_HOME")
    if base is None:
        return (Path.home() / ".local" / "state" / "reconcile" / "phase5").resolve()
    return (Path(base) / "reconcile" / "phase5").resolve()


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="phase5-operator")
    subcommands = parser.add_subparsers(dest="command", required=True)

    inspect_parser = subcommands.add_parser("inspect")
    inspect_parser.add_argument("--state-dir", type=Path, default=_default_state_root())

    seal_parser = subcommands.add_parser("seal-manifest")
    seal_parser.add_argument("--state-dir", type=Path, required=True)
    seal_parser.add_argument("--draft", type=Path, required=True)
    seal_parser.add_argument("--repo-root", type=Path, required=True)

    prepare_parser = subcommands.add_parser("prepare-artifacts")
    prepare_parser.add_argument("--state-dir", type=Path, required=True)
    prepare_parser.add_argument("--repo-root", type=Path, required=True)
    prepare_parser.add_argument("--source-revision", required=True)
    prepare_parser.add_argument("--created-at", type=_parse_timestamp, required=True)
    prepare_parser.add_argument("--provider-mirror", type=Path)

    approval_parser = subcommands.add_parser("record-approval")
    approval_parser.add_argument("--state-dir", type=Path, required=True)
    approval_parser.add_argument("--manifest-sha256", required=True)
    approval_parser.add_argument("--approved-by", required=True)
    approval_parser.add_argument("--approved-at", type=_parse_timestamp, required=True)

    continuation_parser = subcommands.add_parser("continue-manifest")
    continuation_parser.add_argument(
        "--predecessor-state-dir", type=Path, required=True
    )
    continuation_parser.add_argument("--predecessor-manifest-sha256", required=True)
    continuation_parser.add_argument("--predecessor-approval-sha256", required=True)
    continuation_parser.add_argument("--state-dir", type=Path, required=True)
    continuation_parser.add_argument("--manifest-sha256", required=True)
    continuation_parser.add_argument("--approval-sha256", required=True)
    continuation_parser.add_argument("--repo-root", type=Path, required=True)
    continuation_parser.add_argument(
        "--prepared-at", type=_parse_timestamp, required=True
    )

    run_parser = subcommands.add_parser("run")
    run_parser.add_argument("--state-dir", type=Path, required=True)
    run_parser.add_argument("--manifest-sha256", required=True)
    run_parser.add_argument("--approval-sha256", required=True)
    run_parser.add_argument(
        "--action", type=Phase5Action, choices=tuple(Phase5Action), required=True
    )
    run_parser.add_argument("--repo-root", type=Path, required=True)
    return parser


def _emit(value: Mapping[str, Any]) -> None:
    sys.stdout.buffer.write(
        json.dumps(
            dict(value),
            allow_nan=False,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
        + b"\n"
    )


def main(argv: Sequence[str] | None = None) -> int:
    arguments = list(sys.argv[1:] if argv is None else argv)
    if not arguments:
        arguments = ["inspect"]
    try:
        namespace = _parser().parse_args(arguments)
        if namespace.command == "inspect":
            state = Phase5StateStore(namespace.state_dir, create=False)
            _emit(state.inspect())
            return 0
        if namespace.command == "prepare-artifacts":
            draft, draft_path = prepare_phase5_artifacts(
                state_root=namespace.state_dir,
                repo_root=namespace.repo_root,
                source_revision=namespace.source_revision,
                created_at=namespace.created_at,
                provider_mirror=namespace.provider_mirror,
            )
            _emit(
                {
                    "schema_version": _SCHEMA,
                    "status": "ARTIFACTS_PREPARED",
                    "draft_path": str(draft_path),
                    "image_digest": draft.image_digest,
                    "created_at": draft.created_at.isoformat(),
                    "work_deadline": draft.work_deadline.isoformat(),
                    "approval_expires_at": draft.approval_expires_at.isoformat(),
                }
            )
            return 0
        if namespace.command == "seal-manifest":
            draft = _read_private_canonical_file(namespace.draft, Phase5ManifestDraft)
            state = Phase5StateStore(namespace.state_dir)
            manifest = build_manifest(
                draft,
                state_root=state.root,
                repo_root=namespace.repo_root,
                runner=_default_runner,
            )
            _verify_exact_main(
                manifest,
                repo_root=namespace.repo_root,
                runner=_default_runner,
            )
            state.write_manifest(manifest)
            _emit(
                {
                    "schema_version": _SCHEMA,
                    "status": "MANIFEST_SEALED",
                    "manifest_sha256": manifest.record_sha256,
                    "authorization_estimate_usd": (manifest.authorization_estimate_usd),
                    "contingency_authorization_estimate_usd": (
                        manifest.contingency_authorization_estimate_usd
                    ),
                    "estimate_kind": manifest.estimate_kind,
                    "work_deadline": manifest.work_deadline.isoformat(),
                    "approval_expires_at": (manifest.approval_expires_at.isoformat()),
                }
            )
            return 0
        if namespace.command == "record-approval":
            state = Phase5StateStore(namespace.state_dir)
            manifest = state.load_manifest(namespace.manifest_sha256)
            approval = build_approval(
                manifest,
                approved_by=namespace.approved_by,
                approved_at=namespace.approved_at,
            )
            state.write_approval(approval)
            _emit(
                {
                    "schema_version": _SCHEMA,
                    "status": "APPROVAL_RECORDED",
                    "manifest_sha256": manifest.record_sha256,
                    "approval_sha256": approval.record_sha256,
                }
            )
            return 0
        if namespace.command == "continue-manifest":
            continuation = prepare_phase5_continuation(
                predecessor_state_root=namespace.predecessor_state_dir,
                predecessor_manifest_sha256=(namespace.predecessor_manifest_sha256),
                predecessor_approval_sha256=(namespace.predecessor_approval_sha256),
                successor_state_root=namespace.state_dir,
                successor_manifest_sha256=namespace.manifest_sha256,
                successor_approval_sha256=namespace.approval_sha256,
                repo_root=namespace.repo_root,
                prepared_at=namespace.prepared_at,
            )
            _emit(
                {
                    "schema_version": _SCHEMA,
                    "status": "CONTINUATION_PREPARED",
                    "continuation_sha256": continuation.record_sha256,
                    "manifest_sha256": continuation.successor_manifest_sha256,
                    "carried_actions": [
                        item.action.value for item in continuation.carried_successes
                    ],
                }
            )
            return 0
        if namespace.command == "run":
            state = Phase5StateStore(namespace.state_dir)
            manifest = state.load_manifest(namespace.manifest_sha256)
            approval = state.load_approval(namespace.approval_sha256)
            evidence = execute_action(
                action=namespace.action,
                manifest=manifest,
                approval=approval,
                state=state,
                repo_root=namespace.repo_root,
                now=datetime.now(UTC),
            )
            _emit(
                {
                    "schema_version": _SCHEMA,
                    "status": evidence.status.value,
                    "action": evidence.action.value,
                    "evidence_sha256": evidence.record_sha256,
                }
            )
            return 0 if evidence.status is OutcomeStatus.SUCCEEDED else 2
        raise OperatorError("UNKNOWN_COMMAND")
    except OperatorError as error:
        _emit(
            {
                "schema_version": _SCHEMA,
                "status": "BLOCKED",
                "reason": error.code,
            }
        )
        return 2


__all__ = [
    "CommandDescriptor",
    "EnvironmentBinding",
    "ExecutionSourceBinding",
    "ExecutionSourceFileBinding",
    "OperatorError",
    "OutcomeReason",
    "OutcomeStatus",
    "Phase5Action",
    "Phase5Admission",
    "Phase5Approval",
    "Phase5ApprovalManifest",
    "Phase5Continuation",
    "Phase5Evidence",
    "Phase5ManifestDraft",
    "Phase5Outcome",
    "Phase5StateStore",
    "PythonDependencyBinding",
    "authorize_action",
    "build_approval",
    "build_manifest",
    "execute_action",
    "fixed_command_descriptors",
    "main",
    "prepare_phase5_continuation",
]
