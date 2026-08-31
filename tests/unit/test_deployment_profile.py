from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from reconcile import phase5_operator as operator
from reconcile.deployment_profile import (
    DeploymentProfile,
    DeploymentProfileError,
    backend_config_bytes,
    canonical_profile_bytes,
    capture_backend_configs,
    capture_sealed_deployment_profile,
    load_external_deployment_profile,
    resolve_deployment_identity,
    seal_backend_configs,
    seal_deployment_profile,
    verify_backend_binding,
    verify_sealed_deployment_profile,
)
from reconcile.phase5_hosted_acceptance import (
    CandidateIdentity,
    build_candidate_identity,
)

pytestmark = pytest.mark.unit

_PROFILE = {
    "schema_version": "reconcile/deployment-profile/v1",
    "project_id": "reconcile-test-123456",
    "project_number": "123456789012",
    "billing_account_id": "ABCDEF-123456-ABCDEF",
    "owner_account": "owner@example.com",
}


def _profile_file(tmp_path: Path, value: object = _PROFILE) -> Path:
    path = tmp_path / "deployment.json"
    path.write_text(json.dumps(value, indent=2), encoding="utf-8")
    path.chmod(0o600)
    return path


def test_external_profile_is_strict_private_and_outside_repository(
    tmp_path: Path,
) -> None:
    path = _profile_file(tmp_path)

    profile = load_external_deployment_profile(path, repo_root=Path.cwd())

    assert profile == DeploymentProfile(**_PROFILE)

    path.chmod(0o644)
    with pytest.raises(DeploymentProfileError, match="DEPLOYMENT_PROFILE_NOT_PRIVATE"):
        load_external_deployment_profile(path, repo_root=Path.cwd())


@pytest.mark.parametrize(
    "payload,code",
    (
        (
            b'{"schema_version":"reconcile/deployment-profile/v1",'
            b'"project_id":"reconcile-test-123456",'
            b'"project_id":"reconcile-test-654321",'
            b'"project_number":"123456789012",'
            b'"billing_account_id":"ABCDEF-123456-ABCDEF",'
            b'"owner_account":"owner@example.com"}',
            "DEPLOYMENT_PROFILE_DUPLICATE_KEY",
        ),
        ({**_PROFILE, "unexpected": "value"}, "DEPLOYMENT_PROFILE_INVALID"),
        (
            {**_PROFILE, "project_id": "example-project-id"},
            "DEPLOYMENT_PROFILE_INVALID",
        ),
    ),
)
def test_external_profile_rejects_ambiguous_or_extra_values(
    tmp_path: Path,
    payload: bytes | dict[str, str],
    code: str,
) -> None:
    path = tmp_path / "deployment.json"
    path.write_bytes(
        payload if isinstance(payload, bytes) else json.dumps(payload).encode()
    )
    path.chmod(0o600)

    with pytest.raises(DeploymentProfileError, match=code):
        load_external_deployment_profile(path, repo_root=Path.cwd())


def test_profile_and_backend_files_are_canonical_derived_and_bound(
    tmp_path: Path,
) -> None:
    state = tmp_path / "state"
    (state / "bindings" / "backends").mkdir(parents=True)
    profile = load_external_deployment_profile(
        _profile_file(tmp_path),
        repo_root=Path.cwd(),
    )

    profile_binding = seal_deployment_profile(profile, state_root=state)
    backend_bindings = seal_backend_configs(
        state_root=state,
        identity=profile_binding.identity,
    )

    assert (state / "bindings" / "deployment-profile.json").read_bytes() == (
        json.dumps(_PROFILE, separators=(",", ":"), sort_keys=True).encode()
    )
    assert profile_binding.identity.state_bucket_name == (
        "reconcile-test-123456-p5-state"
    )
    assert profile_binding.identity.apply_service_account_email == (
        "rec-p5-apply@reconcile-test-123456.iam.gserviceaccount.com"
    )
    assert profile_binding.identity.operator_service_account_email == (
        "rec-p5-operator@reconcile-test-123456.iam.gserviceaccount.com"
    )
    assert profile_binding.identity.operating_profile == "evidence"
    assert verify_sealed_deployment_profile(profile_binding) == profile
    assert capture_sealed_deployment_profile(state_root=state) == profile_binding
    assert (
        capture_backend_configs(
            state_root=state,
            identity=profile_binding.identity,
        )
        == backend_bindings
    )
    assert (state / "bindings" / "backends" / "foundation.tfbackend").read_text(
        encoding="utf-8"
    ) == (
        'bucket = "reconcile-test-123456-p5-state"\n'
        "impersonate_service_account = "
        '"rec-p5-apply@reconcile-test-123456.iam.gserviceaccount.com"\n'
        'prefix = "phase5/foundation/evidence"\n'
    )

    backend = backend_bindings[1]
    backend_path = Path(backend.path)
    backend_path.chmod(0o600)
    backend_path.write_text('bucket = "different"\n', encoding="utf-8")
    backend_path.chmod(0o400)
    with pytest.raises(
        DeploymentProfileError,
        match="TERRAFORM_BACKEND_BINDING_DRIFT",
    ):
        verify_backend_binding(
            backend,
            state_root=state,
            identity=profile_binding.identity,
        )


def test_profile_path_must_be_absolute_external_and_not_a_symlink(
    tmp_path: Path,
) -> None:
    path = _profile_file(tmp_path)
    link = tmp_path / "deployment-link.json"
    link.symlink_to(path)

    with pytest.raises(
        DeploymentProfileError,
        match="DEPLOYMENT_PROFILE_PATH_NOT_ABSOLUTE",
    ):
        load_external_deployment_profile(Path("deployment.json"), repo_root=Path.cwd())
    with pytest.raises(
        DeploymentProfileError,
        match="DEPLOYMENT_PROFILE_PATH_NOT_EXTERNAL",
    ):
        load_external_deployment_profile(link, repo_root=Path.cwd())


def test_acceptance_candidate_binds_derived_identity_and_preserves_v1_hashing() -> None:
    identity = resolve_deployment_identity(DeploymentProfile(**_PROFILE))
    common = {
        "source_revision": "a" * 40,
        "image_digest": f"sha256:{'b' * 64}",
        "infrastructure_revision": "c" * 64,
        "semantic_config_sha256": "d" * 64,
    }

    candidate = build_candidate_identity(**common, deployment=identity)

    assert candidate.deployment_profile_sha256 == identity.deployment_profile_sha256
    assert candidate.project_id == identity.project_id
    assert candidate.operator_service_account == (
        identity.operator_service_account_email
    )
    assert candidate.deployment_service_account == identity.apply_service_account_email
    assert candidate.api_audience == identity.audiences.api
    assert CandidateIdentity.model_validate(candidate.model_dump()) == candidate

    legacy = build_candidate_identity(**common)
    legacy_payload = legacy.model_dump(mode="json", exclude={"candidate_sha256"})
    legacy_payload.pop("deployment_profile_sha256", None)
    expected = hashlib.sha256(
        json.dumps(
            legacy_payload,
            allow_nan=False,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
    ).hexdigest()
    assert legacy.deployment_profile_sha256 is None
    assert legacy.candidate_sha256 == expected


def test_production_profile_is_explicit_and_hash_distinct() -> None:
    evidence = DeploymentProfile(**_PROFILE)
    production_payload = {
        **_PROFILE,
        "schema_version": "reconcile/deployment-profile/v2",
        "operating_profile": "production",
        "notification_channel_ids": (
            "projects/reconcile-test-123456/notificationChannels/123456",
        ),
    }
    production = DeploymentProfile(**production_payload)

    evidence_identity = resolve_deployment_identity(evidence)
    production_identity = resolve_deployment_identity(production)

    assert production_identity.operating_profile == "production"
    assert production_identity.deployment_profile_sha256 != (
        evidence_identity.deployment_profile_sha256
    )
    assert b'"operating_profile":"production"' in (canonical_profile_bytes(production))
    assert production_identity.notification_channel_ids == (
        "projects/reconcile-test-123456/notificationChannels/123456",
    )
    assert backend_config_bytes(
        "runtime",
        state_root=Path("/tmp/operator-state"),
        identity=production_identity,
    ).endswith(b'prefix = "phase5/runtime/production"\n')


def test_production_profile_requires_project_scoped_notification_channels() -> None:
    payload = {
        **_PROFILE,
        "schema_version": "reconcile/deployment-profile/v2",
        "operating_profile": "production",
    }
    with pytest.raises(ValueError, match="require notification channels"):
        DeploymentProfile(**payload)
    with pytest.raises(ValueError, match="deployment project"):
        DeploymentProfile(
            **payload,
            notification_channel_ids=(
                "projects/another-project-123/notificationChannels/123456",
            ),
        )

    with pytest.raises(ValueError, match="evidence deployment profiles cannot"):
        DeploymentProfile(
            **(
                _PROFILE
                | {
                    "schema_version": "reconcile/deployment-profile/v2",
                    "operating_profile": "evidence",
                }
            ),
            notification_channel_ids=(
                "projects/reconcile-test-123456/notificationChannels/123456",
            ),
        )


def test_v1_profile_cannot_be_confused_with_production() -> None:
    with pytest.raises(ValueError, match="v1 deployment profiles"):
        DeploymentProfile(**_PROFILE, operating_profile="production")

    with pytest.raises(ValueError, match="require an operating profile"):
        DeploymentProfile(
            **{**_PROFILE, "schema_version": "reconcile/deployment-profile/v2"}
        )


def test_fixed_commands_bind_profile_and_each_backend(tmp_path: Path) -> None:
    state = tmp_path / "state"
    (state / "bindings" / "backends").mkdir(parents=True)
    profile = DeploymentProfile(**_PROFILE)
    profile_binding = seal_deployment_profile(profile, state_root=state)
    backends = seal_backend_configs(
        state_root=state,
        identity=profile_binding.identity,
    )

    commands = operator._fixed_commands(
        "a" * 40,
        f"sha256:{'b' * 64}",
        "c" * 64,
        "d" * 64,
        runtime_source_sha256="e" * 64,
        runtime_variables_sha256="f" * 64,
        state_root=state,
        image_archive=state / "images" / "reconcile.oci.tar",
        deployment=profile_binding.identity,
        terraform_backends=backends,
    )

    for descriptor in commands:
        for command in descriptor.commands:
            if len(command) >= 3 and command[2] == "init":
                stack = Path(command[1].removeprefix("-chdir=")).name
                backend = next(item for item in backends if item.stack == stack)
                assert f"-backend-config={backend.path}" in command
    for action in (
        operator.Phase5Action.PROVIDER_ACCEPTANCE,
        operator.Phase5Action.HOSTED_ACCEPTANCE,
    ):
        command = next(item for item in commands if item.action is action).commands[0]
        assert command[command.index("--deployment-profile") + 1] == (
            profile_binding.path
        )
