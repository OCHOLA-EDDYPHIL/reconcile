"""Sanitized, versioned public evidence derived from hosted acceptance records."""

from __future__ import annotations

import hashlib
import json
import os
import stat
import subprocess
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import Annotated, Any, Literal

from pydantic import Field, StringConstraints, model_validator

from reconcile.contracts import (
    RecoveryDispatchOutcome,
    RecoveryReceiptOutcome,
    RecoveryRunFault,
    RecoveryRunLifecycle,
    RecoveryRunPolicy,
    canonical_json_bytes,
    decode_contract,
)
from reconcile.contracts.base import AwareDatetime, Sha256Digest, StrictModel
from reconcile.phase5_hosted_acceptance import (
    AcceptanceMode,
    HostedAcceptanceRecord,
    ProviderAcceptanceRecord,
)
from reconcile.phase5_operator import (
    OutcomeStatus,
    Phase5Action,
    Phase5Admission,
    Phase5ApprovalManifest,
    Phase5Evidence,
    Phase5Outcome,
)

PUBLIC_EVIDENCE_INDEX_VERSION = "reconcile/public-evidence/v1"
PUBLIC_PROVIDER_PROOF_VERSION = "reconcile/provider-proof/v2"
PUBLIC_LIVE_CORROBORATION_VERSION = "reconcile/live-corroboration/v2"
PUBLIC_CLEANUP_VERSION = "reconcile/cleanup-verification/v2"
POST_TEARDOWN_CAPTURE_VERSION = "reconcile/post-teardown-capture/v1"

PUBLIC_EVIDENCE_FILES = frozenset(
    {
        "proof-to-permit.json",
        "provider-proof.json",
        "live-corroboration.json",
        "cleanup-verification.json",
    }
)

_MAX_INPUT_BYTES = 8 * 1_048_576
_MAX_PUBLIC_FILE_BYTES = 256 * 1_024
_REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
_GCLOUD = "/usr/bin/gcloud"
_INVENTORY_KINDS = (
    "cloud-run-services",
    "cloud-run-jobs",
    "artifact-repositories",
    "firestore-databases",
    "storage-buckets",
    "phase5-named-service-accounts",
    "custom-roles",
    "phase5-project-iam-members",
    "phase5-budgets",
)

GitRevision = Annotated[
    str,
    StringConstraints(pattern=r"^[0-9a-f]{40}$"),
]
ImageDigest = Annotated[
    str,
    StringConstraints(pattern=r"^sha256:[0-9a-f]{64}$"),
]
PrivateIdentifier = Annotated[
    str,
    StringConstraints(min_length=1, max_length=2048, pattern=r"^[^\x00-\x1f\x7f]+$"),
]


class PublicEvidenceError(RuntimeError):
    """A stable refusal at the public evidence export boundary."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


class PostTeardownInventory(StrictModel):
    """Closed inventory that must be empty after the accepted teardown."""

    cloud_run_services: Literal[0]
    cloud_run_jobs: Literal[0]
    artifact_repositories: Literal[0]
    firestore_databases: Literal[0]
    storage_buckets: Literal[0]
    phase5_named_service_accounts: Literal[0]
    custom_roles: Literal[0]
    phase5_project_iam_members: Literal[0]
    phase5_budgets: Literal[0]


class TeardownActionBindings(StrictModel):
    """Digests of the four accepted teardown action records."""

    runtime_sha256: Sha256Digest
    foundation_sha256: Sha256Digest
    state_protection_sha256: Sha256Digest
    bootstrap_sha256: Sha256Digest


class PostTeardownCapture(StrictModel):
    """Strict, sanitized operator input captured after hosted teardown."""

    schema_version: Literal["reconcile/post-teardown-capture/v1"]
    status: Literal["PASS"]
    source_revision: GitRevision
    candidate_sha256: Sha256Digest
    captured_at: AwareDatetime
    teardown_actions: TeardownActionBindings
    inventory: PostTeardownInventory
    observations_sha256: Sha256Digest


class InventoryQueryObservation(StrictModel):
    """One fixed read-only gcloud query and its normalized matched resources."""

    kind: Literal[
        "cloud-run-services",
        "cloud-run-jobs",
        "artifact-repositories",
        "firestore-databases",
        "storage-buckets",
        "phase5-named-service-accounts",
        "custom-roles",
        "phase5-project-iam-members",
        "phase5-budgets",
    ]
    command_sha256: Sha256Digest
    response_sha256: Sha256Digest
    matched_resource_ids: tuple[PrivateIdentifier, ...] = Field(max_length=256)

    @model_validator(mode="after")
    def validate_resources(self) -> InventoryQueryObservation:
        if self.matched_resource_ids != tuple(sorted(set(self.matched_resource_ids))):
            raise ValueError("inventory resources must be unique and sorted")
        return self


class PostTeardownInventoryObservation(StrictModel):
    """Canonical private capture produced by fixed read-only gcloud queries."""

    schema_version: Literal["reconcile/post-teardown-inventory/v1"]
    operator_manifest_sha256: Sha256Digest
    source_revision: GitRevision
    image_digest: ImageDigest
    infrastructure_revision: Sha256Digest
    semantic_config_sha256: Sha256Digest
    deployment_profile_sha256: Sha256Digest
    project_id: Annotated[
        str,
        StringConstraints(pattern=r"^[a-z][a-z0-9-]{4,28}[a-z0-9]$"),
    ]
    region: Literal["us-central1"]
    billing_account_id: Annotated[
        str,
        StringConstraints(pattern=r"^[0-9A-F]{6}-[0-9A-F]{6}-[0-9A-F]{6}$"),
    ]
    captured_at: AwareDatetime
    queries: tuple[
        InventoryQueryObservation,
        InventoryQueryObservation,
        InventoryQueryObservation,
        InventoryQueryObservation,
        InventoryQueryObservation,
        InventoryQueryObservation,
        InventoryQueryObservation,
        InventoryQueryObservation,
        InventoryQueryObservation,
    ]

    @model_validator(mode="after")
    def validate_queries(self) -> PostTeardownInventoryObservation:
        if tuple(item.kind for item in self.queries) != _INVENTORY_KINDS:
            raise ValueError("post-teardown query inventory changed")
        expected = _inventory_commands(
            project_id=self.project_id,
            region=self.region,
            billing_account_id=self.billing_account_id,
        )
        if any(
            item.command_sha256 != _json_sha256(list(command))
            for item, (_, command) in zip(self.queries, expected, strict=True)
        ):
            raise ValueError("post-teardown query command changed")
        return self


class PublicCandidate(StrictModel):
    source_revision: GitRevision
    image_digest: ImageDigest
    candidate_sha256: Sha256Digest
    provider_acceptance_record_sha256: Sha256Digest
    provider_acceptance_file_sha256: Sha256Digest
    hosted_acceptance_record_sha256: Sha256Digest
    hosted_acceptance_file_sha256: Sha256Digest


class PublicReplayProof(StrictModel):
    snapshot_stable: Literal[True]
    rejected_before_provider_contact: Literal[True]
    provider_contact_delta: Literal[0]
    denial_count: Literal[1]


class PublicEffects(StrictModel):
    revisions: int = Field(ge=0, le=16)
    promotions: int = Field(ge=0, le=16)
    release_records: int = Field(ge=0, le=16)


class PublicAdaptiveRecovery(StrictModel):
    policy: Literal["adaptive"]
    fault: Literal["drop-after-accept"]
    acknowledgement_lost: Literal[True]
    launch_outcome: Literal["OUTCOME_UNKNOWN"]
    terminal_disposition: Literal["COMPLETED"]
    chain_completed: Literal[True]
    certificate_count: int = Field(ge=1, le=16)
    continue_permits_issued: int = Field(ge=1, le=16)
    action_permits_consumed: int = Field(ge=1, le=16)
    provider_contacts: int = Field(ge=1, le=32)
    effects: PublicEffects
    replay: PublicReplayProof

    @model_validator(mode="after")
    def validate_effects(self) -> PublicAdaptiveRecovery:
        if self.effects != PublicEffects(
            revisions=1,
            promotions=1,
            release_records=1,
        ):
            raise ValueError("adaptive recovery effects changed")
        return self


class PublicProviderProof(StrictModel):
    schema_version: Literal["reconcile/provider-proof/v2"]
    status: Literal["PASS"]
    candidate: PublicCandidate
    adaptive_recovery: PublicAdaptiveRecovery


class PublicAdvisoryPlanning(StrictModel):
    configured_model: Literal["gemini-3.5-flash"]
    reported_model: Annotated[
        str,
        StringConstraints(
            min_length=12,
            max_length=128,
            pattern=r"^gemini-3\.5-[A-Za-z0-9._-]+$",
        ),
    ]
    planner_outcome: Literal["planner-succeeded"]
    count_attempts: Literal[1]
    generation_attempts: Literal[1]
    authority: Literal["read-only-probe-planning-only"]


class PublicDeploymentProof(StrictModel):
    service_count: Literal[5]
    all_services_ready: Literal[True]
    source_revision_consistent: Literal[True]
    image_digest_consistent: Literal[True]


class PublicAmbiguityEffects(StrictModel):
    staged_revisions: Literal[1]
    promotions: Literal[0]
    release_records: Literal[0]


class PublicAmbiguityProof(StrictModel):
    policy: Literal["fixed"]
    fault: Literal["acceptance-drop-after-accept-partial-read-outage"]
    acknowledgement_lost: Literal[True]
    launch_outcome: Literal["OUTCOME_UNKNOWN"]
    classification: Literal["UNKNOWN"]
    lifecycle: Literal["ESCALATED"]
    decision: Literal["ESCALATE"]
    chain_completed: Literal[False]
    history_ids: tuple[Literal["effects-occurred"], Literal["effects-not-occurred"]]
    history_classifications: tuple[Literal["COMMITTED"], Literal["PARTIAL"]]
    history_evidence_counts: tuple[int, int]
    discriminating_observation_count: int = Field(ge=1, le=16)
    probe_outcomes: tuple[
        Literal["COMPLETED"], Literal["UNAVAILABLE"], Literal["UNAVAILABLE"]
    ]
    certificate_count: Literal[0]
    action_permit_count: Literal[0]
    provider_contacts: Literal[1]
    effects: PublicAmbiguityEffects
    replay: PublicReplayProof

    @model_validator(mode="after")
    def validate_history_evidence(self) -> PublicAmbiguityProof:
        if any(not 1 <= count <= 64 for count in self.history_evidence_counts):
            raise ValueError("ambiguity histories lack compatible evidence")
        return self


class PublicLiveCorroboration(StrictModel):
    schema_version: Literal["reconcile/live-corroboration/v2"]
    status: Literal["PASS"]
    source_revision: GitRevision
    candidate_sha256: Sha256Digest
    provider_proof_sha256: Sha256Digest
    provider_acceptance_completed_at: AwareDatetime
    hosted_acceptance_completed_at: AwareDatetime
    deployments: PublicDeploymentProof
    advisory_planning: PublicAdvisoryPlanning
    ambiguity_proof: PublicAmbiguityProof

    @model_validator(mode="after")
    def validate_times(self) -> PublicLiveCorroboration:
        if self.hosted_acceptance_completed_at < self.provider_acceptance_completed_at:
            raise ValueError("hosted acceptance predates provider acceptance")
        return self


class PublicCleanupVerification(StrictModel):
    schema_version: Literal["reconcile/cleanup-verification/v2"]
    status: Literal["PASS"]
    source_revision: GitRevision
    candidate_sha256: Sha256Digest
    captured_at: AwareDatetime
    post_teardown_capture_sha256: Sha256Digest
    observations_sha256: Sha256Digest
    teardown_actions: TeardownActionBindings
    inventory: PostTeardownInventory


class PublicClaimBoundary(StrictModel):
    authorized_safety_claim: Literal[
        "evidence-bound recovery on the recorded hosted acceptance"
    ]
    adaptive_efficiency_claim_authorized: Literal[False]
    live_cloud_is_a_policy_comparison: Literal[True]
    live_endpoint_exists: Literal[False]


class PublicFileBinding(StrictModel):
    path: Literal[
        "provider-proof.json",
        "live-corroboration.json",
        "cleanup-verification.json",
    ]
    sha256: Sha256Digest
    byte_count: int = Field(ge=1, le=_MAX_PUBLIC_FILE_BYTES)


class PublicInputBindings(StrictModel):
    provider_acceptance_record_sha256: Sha256Digest
    provider_acceptance_file_sha256: Sha256Digest
    hosted_acceptance_record_sha256: Sha256Digest
    hosted_acceptance_file_sha256: Sha256Digest
    post_teardown_capture_sha256: Sha256Digest


class PublicEvidenceIndex(StrictModel):
    schema_version: Literal["reconcile/public-evidence/v1"]
    status: Literal["PASS"]
    source_revision: GitRevision
    candidate_sha256: Sha256Digest
    claim_boundary: PublicClaimBoundary
    inputs: PublicInputBindings
    files: tuple[PublicFileBinding, PublicFileBinding, PublicFileBinding]

    @model_validator(mode="after")
    def validate_files(self) -> PublicEvidenceIndex:
        if tuple(item.path for item in self.files) != (
            "provider-proof.json",
            "live-corroboration.json",
            "cleanup-verification.json",
        ):
            raise ValueError("public evidence file order changed")
        return self


class PublicEvidenceBundle(StrictModel):
    index: PublicEvidenceIndex
    provider_proof: PublicProviderProof
    live_corroboration: PublicLiveCorroboration
    cleanup_verification: PublicCleanupVerification


def _file_sha256(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _json_sha256(value: object) -> str:
    return hashlib.sha256(
        json.dumps(
            value,
            allow_nan=False,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
    ).hexdigest()


def _inventory_commands(
    *,
    project_id: str,
    region: str,
    billing_account_id: str,
) -> tuple[tuple[str, tuple[str, ...]], ...]:
    project = f"--project={project_id}"
    location = f"--region={region}"
    output = "--format=json"
    quiet = "--quiet"
    return (
        (
            "cloud-run-services",
            (_GCLOUD, "run", "services", "list", project, location, output, quiet),
        ),
        (
            "cloud-run-jobs",
            (_GCLOUD, "run", "jobs", "list", project, location, output, quiet),
        ),
        (
            "artifact-repositories",
            (
                _GCLOUD,
                "artifacts",
                "repositories",
                "list",
                project,
                f"--location={region}",
                output,
                quiet,
            ),
        ),
        (
            "firestore-databases",
            (_GCLOUD, "firestore", "databases", "list", project, output, quiet),
        ),
        (
            "storage-buckets",
            (_GCLOUD, "storage", "buckets", "list", project, output, quiet),
        ),
        (
            "phase5-named-service-accounts",
            (
                _GCLOUD,
                "iam",
                "service-accounts",
                "list",
                project,
                output,
                quiet,
            ),
        ),
        (
            "custom-roles",
            (_GCLOUD, "iam", "roles", "list", project, output, quiet),
        ),
        (
            "phase5-project-iam-members",
            (
                _GCLOUD,
                "projects",
                "get-iam-policy",
                project_id,
                output,
                quiet,
            ),
        ),
        (
            "phase5-budgets",
            (
                _GCLOUD,
                "billing",
                "budgets",
                "list",
                f"--billing-account={billing_account_id}",
                output,
                quiet,
            ),
        ),
    )


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


def _reject_nonfinite(value: str) -> None:
    raise ValueError(value)


def _strict_json(payload: bytes) -> object:
    if not 1 <= len(payload) <= _MAX_INPUT_BYTES:
        raise PublicEvidenceError("INVENTORY_RESPONSE_INVALID")
    try:
        return json.loads(
            payload.decode("utf-8"),
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=_reject_nonfinite,
        )
    except (UnicodeError, ValueError) as error:
        raise PublicEvidenceError("INVENTORY_RESPONSE_INVALID") from error


def _nested_text(value: object, *path: str) -> str | None:
    current = value
    for key in path:
        if type(current) is not dict:
            return None
        current = current.get(key)
    return current if type(current) is str and current else None


def _list_items(value: object) -> list[dict[str, Any]]:
    if type(value) is not list or any(type(item) is not dict for item in value):
        raise PublicEvidenceError("INVENTORY_RESPONSE_INVALID")
    return value


def _matched_resource_ids(
    kind: str,
    value: object,
    *,
    project_id: str,
) -> tuple[str, ...]:
    resources: set[str] = set()
    if kind == "phase5-project-iam-members":
        if type(value) is not dict or type(value.get("bindings")) is not list:
            raise PublicEvidenceError("INVENTORY_RESPONSE_INVALID")
        for binding in value["bindings"]:
            if type(binding) is not dict:
                raise PublicEvidenceError("INVENTORY_RESPONSE_INVALID")
            role = binding.get("role")
            members = binding.get("members", [])
            if (
                type(role) is not str
                or type(members) is not list
                or any(type(member) is not str for member in members)
            ):
                raise PublicEvidenceError("INVENTORY_RESPONSE_INVALID")
            for member in members:
                if (
                    "rec-p5-" in member
                    or f"projects/{project_id}/roles/reconcileP5" in role
                ):
                    resources.add(f"{role}|{member}")
        return tuple(sorted(resources))

    items = _list_items(value)
    for item in items:
        if kind in {"cloud-run-services", "cloud-run-jobs"}:
            resource = _nested_text(item, "metadata", "name") or _nested_text(
                item, "name"
            )
        elif kind == "phase5-named-service-accounts":
            resource = _nested_text(item, "email")
            if resource is not None and not resource.startswith("rec-p5-"):
                resource = None
        elif kind == "custom-roles":
            resource = _nested_text(item, "name")
            if resource is not None and not resource.startswith(
                f"projects/{project_id}/roles/reconcileP5"
            ):
                resource = None
        elif kind == "phase5-budgets":
            display_name = _nested_text(item, "displayName") or _nested_text(
                item, "display_name"
            )
            resource = (
                _nested_text(item, "name")
                if display_name == "RECONCILE Phase 5 USD 5"
                else None
            )
        else:
            resource = _nested_text(item, "name") or _nested_text(item, "id")
        if resource is not None:
            resources.add(resource)
    return tuple(sorted(resources))


def _default_inventory_runner(argv: tuple[str, ...]) -> object:
    return subprocess.run(
        list(argv),
        check=False,
        capture_output=True,
        timeout=60,
    )


def _write_new_path(path: Path, payload: bytes) -> None:
    if (
        not path.is_absolute()
        or path == _REPOSITORY_ROOT
        or _REPOSITORY_ROOT in path.parents
    ):
        raise PublicEvidenceError("OUTPUT_MUST_BE_OUTSIDE_REPOSITORY")
    try:
        path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        descriptor = os.open(
            path,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW,
            0o400,
        )
    except OSError as error:
        raise PublicEvidenceError("OUTPUT_WRITE_FAILED") from error
    try:
        offset = 0
        while offset < len(payload):
            written = os.write(descriptor, payload[offset:])
            if written < 1:
                raise PublicEvidenceError("OUTPUT_WRITE_FAILED")
            offset += written
        os.fchmod(descriptor, 0o400)
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def capture_post_teardown_inventory(
    *,
    operator_manifest_sha256: str,
    source_revision: str,
    image_digest: str,
    infrastructure_revision: str,
    semantic_config_sha256: str,
    deployment_profile_sha256: str,
    project_id: str,
    region: str,
    billing_account_id: str,
    output: Path,
    runner: Callable[[tuple[str, ...]], object] = _default_inventory_runner,
    clock: Callable[[], datetime] = lambda: datetime.now(UTC),
) -> PostTeardownInventoryObservation:
    """Execute the fixed read-only inventory and seal its canonical observation."""

    queries: list[InventoryQueryObservation] = []
    for kind, command in _inventory_commands(
        project_id=project_id,
        region=region,
        billing_account_id=billing_account_id,
    ):
        try:
            result = runner(command)
        except Exception as error:
            raise PublicEvidenceError("INVENTORY_QUERY_FAILED") from error
        if (
            not isinstance(result, subprocess.CompletedProcess)
            or result.returncode != 0
            or type(result.stdout) is not bytes
            or len(result.stdout) > _MAX_INPUT_BYTES
        ):
            raise PublicEvidenceError("INVENTORY_QUERY_FAILED")
        response = _strict_json(result.stdout)
        queries.append(
            InventoryQueryObservation(
                kind=kind,
                command_sha256=_json_sha256(list(command)),
                response_sha256=_file_sha256(result.stdout),
                matched_resource_ids=_matched_resource_ids(
                    kind,
                    response,
                    project_id=project_id,
                ),
            )
        )
    try:
        observation = PostTeardownInventoryObservation(
            schema_version="reconcile/post-teardown-inventory/v1",
            operator_manifest_sha256=operator_manifest_sha256,
            source_revision=source_revision,
            image_digest=image_digest,
            infrastructure_revision=infrastructure_revision,
            semantic_config_sha256=semantic_config_sha256,
            deployment_profile_sha256=deployment_profile_sha256,
            project_id=project_id,
            region=region,
            billing_account_id=billing_account_id,
            captured_at=clock(),
            queries=tuple(queries),
        )
    except (TypeError, ValueError) as error:
        raise PublicEvidenceError("INVENTORY_CAPTURE_INVALID") from error
    _write_new_path(output, canonical_json_bytes(observation))
    return observation


def capture_post_teardown_inventory_from_manifest(
    *,
    manifest_path: Path,
    output: Path,
    runner: Callable[[tuple[str, ...]], object] = _default_inventory_runner,
    clock: Callable[[], datetime] = lambda: datetime.now(UTC),
) -> PostTeardownInventoryObservation:
    """Load one sealed operator manifest and capture its post-teardown inventory."""

    raw = _read_regular(
        manifest_path,
        code="OPERATOR_MANIFEST_INVALID",
        require_private_mode=True,
    )
    manifest = _decode_canonical(
        raw,
        Phase5ApprovalManifest,
        code="OPERATOR_MANIFEST_INVALID",
    )
    if (
        not isinstance(manifest, Phase5ApprovalManifest)
        or manifest.deployment_profile is None
    ):
        raise PublicEvidenceError("OPERATOR_MANIFEST_INVALID")
    identity = manifest.deployment_profile.identity
    return capture_post_teardown_inventory(
        operator_manifest_sha256=manifest.record_sha256,
        source_revision=manifest.source_revision,
        image_digest=manifest.image_digest,
        infrastructure_revision=manifest.infrastructure_revision,
        semantic_config_sha256=manifest.semantic_config_sha256,
        deployment_profile_sha256=identity.deployment_profile_sha256,
        project_id=identity.project_id,
        region=identity.region,
        billing_account_id=identity.billing_account_id,
        output=output,
        runner=runner,
        clock=clock,
    )


def _read_regular(path: Path, *, code: str, require_private_mode: bool) -> bytes:
    if not isinstance(path, Path) or not path.is_absolute():
        raise PublicEvidenceError(code)
    flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        raise PublicEvidenceError(code) from error
    try:
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_uid != os.getuid()
            or before.st_nlink != 1
            or not 1 <= before.st_size <= _MAX_INPUT_BYTES
            or (
                require_private_mode
                and stat.S_IMODE(before.st_mode) not in {0o400, 0o600}
            )
        ):
            raise PublicEvidenceError(code)
        chunks: list[bytes] = []
        remaining = before.st_size
        while remaining:
            chunk = os.read(descriptor, min(65_536, remaining))
            if not chunk:
                raise PublicEvidenceError(code)
            chunks.append(chunk)
            remaining -= len(chunk)
        if os.read(descriptor, 1):
            raise PublicEvidenceError(code)
        after = os.fstat(descriptor)
        if (
            before.st_dev,
            before.st_ino,
            before.st_size,
            before.st_mtime_ns,
        ) != (
            after.st_dev,
            after.st_ino,
            after.st_size,
            after.st_mtime_ns,
        ):
            raise PublicEvidenceError(code)
        return b"".join(chunks)
    finally:
        os.close(descriptor)


def _load_teardown_evidence(
    path: Path,
    expected_action: Phase5Action,
) -> tuple[Phase5Evidence, bytes]:
    raw = _read_regular(
        path,
        code="TEARDOWN_EVIDENCE_INVALID",
        require_private_mode=True,
    )
    evidence = _decode_canonical(
        raw,
        Phase5Evidence,
        code="TEARDOWN_EVIDENCE_INVALID",
    )
    if not isinstance(evidence, Phase5Evidence):
        raise PublicEvidenceError("TEARDOWN_EVIDENCE_INVALID")
    if (
        evidence.action is not expected_action
        or evidence.status is not OutcomeStatus.SUCCEEDED
        or path.name != f"evidence-{evidence.admission_sha256}.json"
    ):
        raise PublicEvidenceError("TEARDOWN_EVIDENCE_INVALID")

    admission_raw = _read_regular(
        path.parent / f"admission-{evidence.admission_sha256}.json",
        code="TEARDOWN_EVIDENCE_CHAIN_INVALID",
        require_private_mode=True,
    )
    outcome_raw = _read_regular(
        path.parent / f"outcome-{evidence.admission_sha256}.json",
        code="TEARDOWN_EVIDENCE_CHAIN_INVALID",
        require_private_mode=True,
    )
    admission = _decode_canonical(
        admission_raw,
        Phase5Admission,
        code="TEARDOWN_EVIDENCE_CHAIN_INVALID",
    )
    outcome = _decode_canonical(
        outcome_raw,
        Phase5Outcome,
        code="TEARDOWN_EVIDENCE_CHAIN_INVALID",
    )
    if (
        not isinstance(admission, Phase5Admission)
        or not isinstance(outcome, Phase5Outcome)
        or admission.action is not expected_action
        or admission.manifest_sha256 != evidence.manifest_sha256
        or admission.approval_sha256 != evidence.approval_sha256
        or outcome.admission_sha256 != admission.record_sha256
        or evidence.outcome_sha256 != outcome.record_sha256
        or evidence.observed_at != outcome.finished_at
        or outcome.status is not OutcomeStatus.SUCCEEDED
    ):
        raise PublicEvidenceError("TEARDOWN_EVIDENCE_CHAIN_INVALID")
    return evidence, raw


def _validated_teardown_capture(
    *,
    provider: ProviderAcceptanceRecord,
    hosted: HostedAcceptanceRecord,
    inventory_path: Path,
    teardown_evidence_paths: tuple[Path, Path, Path, Path],
) -> tuple[PostTeardownCapture, bytes]:
    expected_actions = (
        Phase5Action.RUNTIME_TEARDOWN,
        Phase5Action.FOUNDATION_TEARDOWN,
        Phase5Action.STATE_PROTECTION_CHANGE,
        Phase5Action.BOOTSTRAP_TEARDOWN,
    )
    loaded = tuple(
        _load_teardown_evidence(path, action)
        for path, action in zip(teardown_evidence_paths, expected_actions, strict=True)
    )
    evidence = tuple(item[0] for item in loaded)
    raw = tuple(item[1] for item in loaded)
    if (
        len({item.manifest_sha256 for item in evidence}) != 1
        or len({item.approval_sha256 for item in evidence}) != 1
        or tuple(item.observed_at for item in evidence)
        != tuple(sorted(item.observed_at for item in evidence))
        or evidence[0].observed_at < hosted.completed_at
    ):
        raise PublicEvidenceError("TEARDOWN_EVIDENCE_CHAIN_INVALID")

    inventory_raw = _read_regular(
        inventory_path,
        code="POST_TEARDOWN_INVENTORY_INVALID",
        require_private_mode=True,
    )
    inventory = _decode_canonical(
        inventory_raw,
        PostTeardownInventoryObservation,
        code="POST_TEARDOWN_INVENTORY_INVALID",
    )
    if not isinstance(inventory, PostTeardownInventoryObservation):
        raise PublicEvidenceError("POST_TEARDOWN_INVENTORY_INVALID")
    candidate = provider.candidate
    if inventory.operator_manifest_sha256 != evidence[0].manifest_sha256:
        raise PublicEvidenceError("POST_TEARDOWN_MANIFEST_MISMATCH")
    if (
        inventory.source_revision != candidate.source_revision
        or inventory.image_digest != candidate.image_digest
        or inventory.infrastructure_revision != candidate.infrastructure_revision
        or inventory.semantic_config_sha256 != candidate.semantic_config_sha256
        or inventory.deployment_profile_sha256 != candidate.deployment_profile_sha256
        or inventory.project_id != candidate.project_id
        or inventory.region != candidate.region
        or inventory.captured_at <= evidence[-1].observed_at
        or any(query.matched_resource_ids for query in inventory.queries)
    ):
        raise PublicEvidenceError("POST_TEARDOWN_INVENTORY_NOT_EMPTY")

    query_by_kind = {query.kind: query for query in inventory.queries}
    counts = {
        kind: len(query_by_kind[kind].matched_resource_ids) for kind in _INVENTORY_KINDS
    }
    capture = PostTeardownCapture(
        schema_version=POST_TEARDOWN_CAPTURE_VERSION,
        status="PASS",
        source_revision=candidate.source_revision,
        candidate_sha256=candidate.candidate_sha256,
        captured_at=inventory.captured_at,
        teardown_actions=TeardownActionBindings(
            runtime_sha256=_file_sha256(raw[0]),
            foundation_sha256=_file_sha256(raw[1]),
            state_protection_sha256=_file_sha256(raw[2]),
            bootstrap_sha256=_file_sha256(raw[3]),
        ),
        inventory=PostTeardownInventory(
            cloud_run_services=counts["cloud-run-services"],
            cloud_run_jobs=counts["cloud-run-jobs"],
            artifact_repositories=counts["artifact-repositories"],
            firestore_databases=counts["firestore-databases"],
            storage_buckets=counts["storage-buckets"],
            phase5_named_service_accounts=counts["phase5-named-service-accounts"],
            custom_roles=counts["custom-roles"],
            phase5_project_iam_members=counts["phase5-project-iam-members"],
            phase5_budgets=counts["phase5-budgets"],
        ),
        observations_sha256=_file_sha256(inventory_raw),
    )
    return capture, canonical_json_bytes(capture)


def _decode_canonical(
    payload: bytes,
    model: type[StrictModel],
    *,
    code: str,
) -> StrictModel:
    try:
        value = decode_contract(payload, model)
        if canonical_json_bytes(value) != payload:
            raise ValueError("noncanonical input")
    except (TypeError, ValueError) as error:
        raise PublicEvidenceError(code) from error
    return value


def _validate_acceptance_inputs(
    provider_path: Path,
    hosted_path: Path,
) -> tuple[
    ProviderAcceptanceRecord,
    HostedAcceptanceRecord,
    bytes,
    bytes,
]:
    provider_raw = _read_regular(
        provider_path,
        code="PROVIDER_ACCEPTANCE_INVALID",
        require_private_mode=True,
    )
    hosted_raw = _read_regular(
        hosted_path,
        code="HOSTED_ACCEPTANCE_INVALID",
        require_private_mode=True,
    )
    provider = _decode_canonical(
        provider_raw,
        ProviderAcceptanceRecord,
        code="PROVIDER_ACCEPTANCE_INVALID",
    )
    hosted = _decode_canonical(
        hosted_raw,
        HostedAcceptanceRecord,
        code="HOSTED_ACCEPTANCE_INVALID",
    )
    if not isinstance(provider, ProviderAcceptanceRecord):
        raise PublicEvidenceError("PROVIDER_ACCEPTANCE_INVALID")
    if not isinstance(hosted, HostedAcceptanceRecord):
        raise PublicEvidenceError("HOSTED_ACCEPTANCE_INVALID")
    provider_binding = hosted.provider_artifact
    expected_provider_path = Path(provider_binding.path)
    if (
        provider.candidate != hosted.candidate
        or provider.provider_ledger != hosted.provider_ledger
        or expected_provider_path != provider_path
        or provider_binding.mode is not AcceptanceMode.PROVIDER
        or provider_binding.record_sha256 != provider.record_sha256
        or provider_binding.file_sha256 != _file_sha256(provider_raw)
        or provider_binding.byte_count != len(provider_raw)
        or hosted.recovery_comparison.lanes[3] != provider.adaptive_recovery.result
        or hosted.recovery_comparison.reset_results[3]
        != provider.adaptive_recovery.reset
    ):
        raise PublicEvidenceError("ACCEPTANCE_CHAIN_INVALID")
    return provider, hosted, provider_raw, hosted_raw


def _project_provider(
    provider: ProviderAcceptanceRecord,
    hosted: HostedAcceptanceRecord,
    provider_raw: bytes,
    hosted_raw: bytes,
) -> PublicProviderProof:
    lane = provider.adaptive_recovery
    result = lane.result
    counters = result.counters
    rejected = tuple(
        receipt
        for receipt in result.dispatch_receipts
        if receipt.outcome is RecoveryReceiptOutcome.REJECTED_BEFORE_PROVIDER_CONTACT
    )
    if (
        result.policy != RecoveryRunPolicy.ADAPTIVE.value
        or result.fault != RecoveryRunFault.DROP_AFTER_ACCEPT.value
        or not lane.acknowledgement_lost
        or lane.launch_outcome is not RecoveryDispatchOutcome.OUTCOME_UNKNOWN
        or result.terminal_disposition != RecoveryRunLifecycle.COMPLETED.value
        or not result.chain_completed
        or not result.certificate_sha256s
        or counters.continue_permits_issued < 1
        or counters.action_permits_consumed < 1
        or (
            counters.revisions_created,
            counters.promotions_accepted,
            counters.release_records_created,
        )
        != (1, 1, 1)
        or lane.snapshot_sha256 != lane.replay_snapshot_sha256
        or lane.replay_provider_contact_delta != 0
        or lane.live_authority_replay_denial_count != 1
        or len(rejected) != 1
        or rejected[0].provider_contact
    ):
        raise PublicEvidenceError("ADAPTIVE_PROOF_INVALID")
    candidate = provider.candidate
    return PublicProviderProof(
        schema_version=PUBLIC_PROVIDER_PROOF_VERSION,
        status="PASS",
        candidate=PublicCandidate(
            source_revision=candidate.source_revision,
            image_digest=candidate.image_digest,
            candidate_sha256=candidate.candidate_sha256,
            provider_acceptance_record_sha256=provider.record_sha256,
            provider_acceptance_file_sha256=_file_sha256(provider_raw),
            hosted_acceptance_record_sha256=hosted.record_sha256,
            hosted_acceptance_file_sha256=_file_sha256(hosted_raw),
        ),
        adaptive_recovery=PublicAdaptiveRecovery(
            policy="adaptive",
            fault="drop-after-accept",
            acknowledgement_lost=True,
            launch_outcome="OUTCOME_UNKNOWN",
            terminal_disposition="COMPLETED",
            chain_completed=True,
            certificate_count=len(result.certificate_sha256s),
            continue_permits_issued=counters.continue_permits_issued,
            action_permits_consumed=counters.action_permits_consumed,
            provider_contacts=counters.provider_contacts,
            effects=PublicEffects(
                revisions=counters.revisions_created,
                promotions=counters.promotions_accepted,
                release_records=counters.release_records_created,
            ),
            replay=PublicReplayProof(
                snapshot_stable=True,
                rejected_before_provider_contact=True,
                provider_contact_delta=0,
                denial_count=1,
            ),
        ),
    )


def _project_live(
    provider: ProviderAcceptanceRecord,
    hosted: HostedAcceptanceRecord,
    provider_proof_raw: bytes,
) -> PublicLiveCorroboration:
    candidate = provider.candidate
    deployments = (*provider.deployments, *hosted.deployments)
    if any(
        not deployment.ready
        or deployment.source_revision != candidate.source_revision
        or deployment.image_digest != candidate.image_digest
        for deployment in deployments
    ):
        raise PublicEvidenceError("DEPLOYMENT_PROOF_INVALID")

    lane = hosted.recovery_lanes[-1]
    observation = lane.partial_read_outage
    if observation is None:
        raise PublicEvidenceError("AMBIGUITY_PROOF_MISSING")
    result = lane.result
    counters = result.counters
    histories = observation.witness.possible_histories
    history_evidence_counts = tuple(
        len(history.compatible_evidence_ids) for history in histories
    )
    if len(history_evidence_counts) != 2 or any(
        count < 1 for count in history_evidence_counts
    ):
        raise PublicEvidenceError("AMBIGUITY_PROOF_INVALID")
    return PublicLiveCorroboration(
        schema_version=PUBLIC_LIVE_CORROBORATION_VERSION,
        status="PASS",
        source_revision=candidate.source_revision,
        candidate_sha256=candidate.candidate_sha256,
        provider_proof_sha256=_file_sha256(provider_proof_raw),
        provider_acceptance_completed_at=provider.completed_at,
        hosted_acceptance_completed_at=hosted.completed_at,
        deployments=PublicDeploymentProof(
            service_count=len(hosted.deployments),
            all_services_ready=True,
            source_revision_consistent=True,
            image_digest_consistent=True,
        ),
        advisory_planning=PublicAdvisoryPlanning(
            configured_model=candidate.gemini_model,
            reported_model=provider.provider_ledger.reported_model,
            planner_outcome=provider.provider_ledger.planner_outcome,
            count_attempts=provider.provider_ledger.count_attempts,
            generation_attempts=provider.provider_ledger.generation_attempts,
            authority="read-only-probe-planning-only",
        ),
        ambiguity_proof=PublicAmbiguityProof(
            policy="fixed",
            fault="acceptance-drop-after-accept-partial-read-outage",
            acknowledgement_lost=True,
            launch_outcome="OUTCOME_UNKNOWN",
            classification=observation.classification.value,
            lifecycle=observation.lifecycle.value,
            decision=observation.decision.value,
            chain_completed=False,
            history_ids=(histories[0].history_id, histories[1].history_id),
            history_classifications=(
                histories[0].classification.value,
                histories[1].classification.value,
            ),
            history_evidence_counts=history_evidence_counts,
            discriminating_observation_count=len(
                observation.witness.discriminating_observations
            ),
            probe_outcomes=tuple(item.value for item in observation.probe_outcomes),
            certificate_count=observation.certificate_count,
            action_permit_count=observation.action_permit_count,
            provider_contacts=counters.provider_contacts,
            effects=PublicAmbiguityEffects(
                staged_revisions=counters.revisions_created,
                promotions=counters.promotions_accepted,
                release_records=counters.release_records_created,
            ),
            replay=PublicReplayProof(
                snapshot_stable=lane.snapshot_sha256 == lane.replay_snapshot_sha256,
                rejected_before_provider_contact=True,
                provider_contact_delta=lane.replay_provider_contact_delta,
                denial_count=lane.live_authority_replay_denial_count,
            ),
        ),
    )


def _project_cleanup(
    capture: PostTeardownCapture,
    capture_raw: bytes,
) -> PublicCleanupVerification:
    return PublicCleanupVerification(
        schema_version=PUBLIC_CLEANUP_VERSION,
        status="PASS",
        source_revision=capture.source_revision,
        candidate_sha256=capture.candidate_sha256,
        captured_at=capture.captured_at,
        post_teardown_capture_sha256=_file_sha256(capture_raw),
        observations_sha256=capture.observations_sha256,
        teardown_actions=capture.teardown_actions,
        inventory=capture.inventory,
    )


def _assert_sanitized(
    payloads: tuple[bytes, ...],
    provider: ProviderAcceptanceRecord,
    hosted: HostedAcceptanceRecord,
) -> None:
    private_values = {
        provider.candidate.project_id,
        provider.candidate.operator_service_account,
        provider.candidate.api_audience,
        provider.candidate.controller_audience,
        hosted.provider_artifact.path,
        *(deployment.uri for deployment in provider.deployments),
        *(deployment.uri for deployment in hosted.deployments),
        *(deployment.service_account_email for deployment in provider.deployments),
        *(deployment.service_account_email for deployment in hosted.deployments),
    }
    for value in private_values:
        encoded = value.encode("utf-8")
        if any(encoded in payload for payload in payloads):
            raise PublicEvidenceError("PUBLIC_PROJECTION_NOT_SANITIZED")


def _write_new_file(directory_descriptor: int, name: str, payload: bytes) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW
    try:
        descriptor = os.open(name, flags, 0o400, dir_fd=directory_descriptor)
    except OSError as error:
        raise PublicEvidenceError("OUTPUT_WRITE_FAILED") from error
    try:
        offset = 0
        while offset < len(payload):
            written = os.write(descriptor, payload[offset:])
            if written < 1:
                raise PublicEvidenceError("OUTPUT_WRITE_FAILED")
            offset += written
        os.fchmod(descriptor, 0o400)
        os.fsync(descriptor)
    except BaseException:
        try:
            os.close(descriptor)
        finally:
            try:
                os.unlink(name, dir_fd=directory_descriptor)
            except OSError:
                pass
        raise
    else:
        os.close(descriptor)


def export_public_evidence(
    *,
    provider_acceptance: Path,
    hosted_acceptance: Path,
    runtime_teardown_evidence: Path,
    foundation_teardown_evidence: Path,
    state_protection_evidence: Path,
    bootstrap_teardown_evidence: Path,
    post_teardown_inventory: Path,
    output: Path,
) -> PublicEvidenceBundle:
    """Validate exact private inputs and write one new sanitized four-file bundle."""

    if not all(
        isinstance(path, Path) and path.is_absolute()
        for path in (
            provider_acceptance,
            hosted_acceptance,
            runtime_teardown_evidence,
            foundation_teardown_evidence,
            state_protection_evidence,
            bootstrap_teardown_evidence,
            post_teardown_inventory,
            output,
        )
    ):
        raise PublicEvidenceError("EXPORT_ARGUMENT_INVALID")
    if output == _REPOSITORY_ROOT or _REPOSITORY_ROOT in output.parents:
        raise PublicEvidenceError("OUTPUT_MUST_BE_OUTSIDE_REPOSITORY")

    provider, hosted, provider_raw, hosted_raw = _validate_acceptance_inputs(
        provider_acceptance,
        hosted_acceptance,
    )
    capture, capture_raw = _validated_teardown_capture(
        provider=provider,
        hosted=hosted,
        inventory_path=post_teardown_inventory,
        teardown_evidence_paths=(
            runtime_teardown_evidence,
            foundation_teardown_evidence,
            state_protection_evidence,
            bootstrap_teardown_evidence,
        ),
    )
    provider_proof = _project_provider(provider, hosted, provider_raw, hosted_raw)
    provider_proof_raw = canonical_json_bytes(provider_proof)
    live = _project_live(provider, hosted, provider_proof_raw)
    live_raw = canonical_json_bytes(live)
    cleanup = _project_cleanup(capture, capture_raw)
    cleanup_raw = canonical_json_bytes(cleanup)
    projected = {
        "provider-proof.json": provider_proof_raw,
        "live-corroboration.json": live_raw,
        "cleanup-verification.json": cleanup_raw,
    }
    index = PublicEvidenceIndex(
        schema_version=PUBLIC_EVIDENCE_INDEX_VERSION,
        status="PASS",
        source_revision=provider.candidate.source_revision,
        candidate_sha256=provider.candidate.candidate_sha256,
        claim_boundary=PublicClaimBoundary(
            authorized_safety_claim=(
                "evidence-bound recovery on the recorded hosted acceptance"
            ),
            adaptive_efficiency_claim_authorized=False,
            live_cloud_is_a_policy_comparison=True,
            live_endpoint_exists=False,
        ),
        inputs=PublicInputBindings(
            provider_acceptance_record_sha256=provider.record_sha256,
            provider_acceptance_file_sha256=_file_sha256(provider_raw),
            hosted_acceptance_record_sha256=hosted.record_sha256,
            hosted_acceptance_file_sha256=_file_sha256(hosted_raw),
            post_teardown_capture_sha256=_file_sha256(capture_raw),
        ),
        files=tuple(
            PublicFileBinding(
                path=name,
                sha256=_file_sha256(payload),
                byte_count=len(payload),
            )
            for name, payload in projected.items()
        ),
    )
    index_raw = canonical_json_bytes(index)
    _assert_sanitized(
        (index_raw, provider_proof_raw, live_raw, cleanup_raw),
        provider,
        hosted,
    )

    try:
        output.mkdir(mode=0o700, parents=True, exist_ok=False)
        descriptor = os.open(
            output,
            os.O_RDONLY | os.O_CLOEXEC | os.O_DIRECTORY | os.O_NOFOLLOW,
        )
    except OSError as error:
        raise PublicEvidenceError("OUTPUT_DIRECTORY_INVALID") from error
    try:
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISDIR(metadata.st_mode)
            or metadata.st_uid != os.getuid()
            or stat.S_IMODE(metadata.st_mode) != 0o700
        ):
            raise PublicEvidenceError("OUTPUT_DIRECTORY_INVALID")
        _write_new_file(descriptor, "proof-to-permit.json", index_raw)
        for name, payload in projected.items():
            _write_new_file(descriptor, name, payload)
        os.fsync(descriptor)
    finally:
        os.close(descriptor)

    return PublicEvidenceBundle(
        index=index,
        provider_proof=provider_proof,
        live_corroboration=live,
        cleanup_verification=cleanup,
    )


def load_public_evidence(path: Path) -> PublicEvidenceBundle:
    """Load and cross-check one canonical v0.1.1-style public evidence bundle."""

    if not isinstance(path, Path) or not path.is_absolute():
        raise PublicEvidenceError("PUBLIC_EVIDENCE_INVALID")
    root = path.parent
    if path.name != "proof-to-permit.json":
        raise PublicEvidenceError("PUBLIC_EVIDENCE_INVALID")
    try:
        entries = set(os.listdir(root))
    except OSError as error:
        raise PublicEvidenceError("PUBLIC_EVIDENCE_INVALID") from error
    if entries != PUBLIC_EVIDENCE_FILES:
        raise PublicEvidenceError("PUBLIC_EVIDENCE_INVALID")

    raw = {
        name: _read_regular(
            root / name,
            code="PUBLIC_EVIDENCE_INVALID",
            require_private_mode=False,
        )
        for name in sorted(PUBLIC_EVIDENCE_FILES)
    }
    index = _decode_canonical(
        raw["proof-to-permit.json"],
        PublicEvidenceIndex,
        code="PUBLIC_EVIDENCE_INVALID",
    )
    provider = _decode_canonical(
        raw["provider-proof.json"],
        PublicProviderProof,
        code="PUBLIC_EVIDENCE_INVALID",
    )
    live = _decode_canonical(
        raw["live-corroboration.json"],
        PublicLiveCorroboration,
        code="PUBLIC_EVIDENCE_INVALID",
    )
    cleanup = _decode_canonical(
        raw["cleanup-verification.json"],
        PublicCleanupVerification,
        code="PUBLIC_EVIDENCE_INVALID",
    )
    if not isinstance(index, PublicEvidenceIndex):
        raise PublicEvidenceError("PUBLIC_EVIDENCE_INVALID")
    if not isinstance(provider, PublicProviderProof):
        raise PublicEvidenceError("PUBLIC_EVIDENCE_INVALID")
    if not isinstance(live, PublicLiveCorroboration):
        raise PublicEvidenceError("PUBLIC_EVIDENCE_INVALID")
    if not isinstance(cleanup, PublicCleanupVerification):
        raise PublicEvidenceError("PUBLIC_EVIDENCE_INVALID")

    expected_files = tuple(
        PublicFileBinding(
            path=name,
            sha256=_file_sha256(raw[name]),
            byte_count=len(raw[name]),
        )
        for name in (
            "provider-proof.json",
            "live-corroboration.json",
            "cleanup-verification.json",
        )
    )
    candidate = provider.candidate
    if (
        index.files != expected_files
        or index.source_revision != candidate.source_revision
        or index.candidate_sha256 != candidate.candidate_sha256
        or index.inputs.provider_acceptance_record_sha256
        != candidate.provider_acceptance_record_sha256
        or index.inputs.provider_acceptance_file_sha256
        != candidate.provider_acceptance_file_sha256
        or index.inputs.hosted_acceptance_record_sha256
        != candidate.hosted_acceptance_record_sha256
        or index.inputs.hosted_acceptance_file_sha256
        != candidate.hosted_acceptance_file_sha256
        or index.inputs.post_teardown_capture_sha256
        != cleanup.post_teardown_capture_sha256
        or live.source_revision != candidate.source_revision
        or live.candidate_sha256 != candidate.candidate_sha256
        or live.provider_proof_sha256 != _file_sha256(raw["provider-proof.json"])
        or cleanup.source_revision != candidate.source_revision
        or cleanup.candidate_sha256 != candidate.candidate_sha256
        or cleanup.captured_at <= live.hosted_acceptance_completed_at
    ):
        raise PublicEvidenceError("PUBLIC_EVIDENCE_BINDING_INVALID")
    return PublicEvidenceBundle(
        index=index,
        provider_proof=provider,
        live_corroboration=live,
        cleanup_verification=cleanup,
    )


def public_bundle_dict(bundle: PublicEvidenceBundle) -> dict[str, Any]:
    """Return the validator/viewer mapping used by both evidence versions."""

    return {
        **bundle.index.model_dump(mode="json"),
        "provider_proof": bundle.provider_proof.model_dump(mode="json"),
        "live_corroboration": bundle.live_corroboration.model_dump(mode="json"),
        "cleanup_verification": bundle.cleanup_verification.model_dump(mode="json"),
    }


def canonical_post_teardown_capture(value: dict[str, Any]) -> bytes:
    """Validate and canonically encode one post-teardown capture."""

    try:
        payload = json.dumps(
            value,
            allow_nan=False,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
        capture = decode_contract(payload, PostTeardownCapture)
        return canonical_json_bytes(capture)
    except (TypeError, ValueError) as error:
        raise PublicEvidenceError("POST_TEARDOWN_CAPTURE_INVALID") from error


def public_evidence_schema_version(payload: bytes) -> str | None:
    """Read only the schema discriminator from strict JSON bytes."""

    try:
        value = json.loads(payload.decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError):
        return None
    if type(value) is not dict:
        return None
    schema = value.get("schema_version")
    return schema if type(schema) is str else None


__all__ = [
    "POST_TEARDOWN_CAPTURE_VERSION",
    "PUBLIC_CLEANUP_VERSION",
    "PUBLIC_EVIDENCE_FILES",
    "PUBLIC_EVIDENCE_INDEX_VERSION",
    "PUBLIC_LIVE_CORROBORATION_VERSION",
    "PUBLIC_PROVIDER_PROOF_VERSION",
    "PostTeardownCapture",
    "PostTeardownInventory",
    "PublicEvidenceBundle",
    "PublicEvidenceError",
    "TeardownActionBindings",
    "canonical_post_teardown_capture",
    "export_public_evidence",
    "load_public_evidence",
    "public_bundle_dict",
    "public_evidence_schema_version",
]
