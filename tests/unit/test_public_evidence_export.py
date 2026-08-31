from __future__ import annotations

import asyncio
import json
import stat
import subprocess
import sys
from dataclasses import dataclass
from datetime import timedelta
from pathlib import Path

import pytest

from reconcile import phase5_operator as operator
from reconcile import public_evidence
from reconcile.contracts import canonical_json_bytes
from reconcile.deployment_profile import DeploymentProfile, resolve_deployment_identity
from reconcile.phase5_hosted_acceptance import (
    build_candidate_identity,
    run_hosted_acceptance,
    run_provider_acceptance,
)
from reconcile.public_evidence import (
    PUBLIC_EVIDENCE_FILES,
    PostTeardownInventoryObservation,
    PublicEvidenceError,
    canonical_post_teardown_capture,
    capture_post_teardown_inventory,
    export_public_evidence,
)
from scripts import capture_post_teardown_inventory as capture_inventory_cli
from scripts.validate_evidence import load_and_validate
from tests.unit import test_phase5_hosted_acceptance as acceptance_fixtures
from viewer.export import _build_snapshot

pytestmark = pytest.mark.unit
ROOT = Path(__file__).parents[2]
NOW = acceptance_fixtures.NOW


@dataclass(frozen=True)
class _Inputs:
    provider: Path
    hosted: Path
    inventory: Path
    teardown: tuple[Path, Path, Path, Path]


def _write_private(path: Path, payload: bytes) -> None:
    path.write_bytes(payload)
    path.chmod(0o400)


def _teardown_records(root: Path, source_revision: str) -> tuple[Path, ...]:
    root.mkdir(mode=0o700)
    paths: list[Path] = []
    actions = (
        operator.Phase5Action.RUNTIME_TEARDOWN,
        operator.Phase5Action.FOUNDATION_TEARDOWN,
        operator.Phase5Action.STATE_PROTECTION_CHANGE,
        operator.Phase5Action.BOOTSTRAP_TEARDOWN,
    )
    for index, action in enumerate(actions):
        admitted_at = NOW + timedelta(minutes=2, seconds=index * 2)
        admission = operator._seal(
            operator.Phase5Admission,
            schema_version="reconcile/phase5-operator/v1",
            record_type="admission",
            manifest_sha256="6" * 64,
            approval_sha256="7" * 64,
            action=action,
            command_descriptor_sha256="8" * 64,
            source_revision=source_revision,
            admitted_at=admitted_at,
        )
        outcome = operator._build_outcome(
            admission,
            subprocess.CompletedProcess(["fixed"], 0, b"", b""),
            finished_at=admitted_at + timedelta(seconds=1),
        )
        evidence = operator._seal(
            operator.Phase5Evidence,
            schema_version="reconcile/phase5-operator/v1",
            record_type="evidence",
            manifest_sha256=admission.manifest_sha256,
            approval_sha256=admission.approval_sha256,
            admission_sha256=admission.record_sha256,
            outcome_sha256=outcome.record_sha256,
            action=action,
            status=outcome.status,
            observed_at=outcome.finished_at,
        )
        _write_private(
            root / f"admission-{admission.record_sha256}.json",
            canonical_json_bytes(admission),
        )
        _write_private(
            root / f"outcome-{admission.record_sha256}.json",
            canonical_json_bytes(outcome),
        )
        evidence_path = root / f"evidence-{admission.record_sha256}.json"
        _write_private(evidence_path, canonical_json_bytes(evidence))
        paths.append(evidence_path)
    return tuple(paths)


def _empty_inventory_runner(command: tuple[str, ...]) -> object:
    payload = b'{"bindings":[]}' if "get-iam-policy" in command else b"[]"
    return subprocess.CompletedProcess(list(command), 0, payload, b"")


@pytest.mark.parametrize(
    ("kind", "resources", "expected"),
    (
        (
            "phase5-log-metrics",
            [
                {"name": "reconcile_p5_failed_run"},
                {"name": "unrelated_metric"},
            ],
            ("reconcile_p5_failed_run",),
        ),
        (
            "phase5-alert-policies",
            [
                {
                    "displayName": "Reconcile failed-run",
                    "name": "projects/example/alertPolicies/1",
                },
                {
                    "displayName": "Unrelated policy",
                    "name": "projects/example/alertPolicies/2",
                },
            ],
            ("projects/example/alertPolicies/1",),
        ),
        (
            "phase5-dashboards",
            [
                {
                    "displayName": "Reconcile Phase 5 operational signals",
                    "name": "projects/example/dashboards/1",
                },
                {
                    "displayName": "Unrelated dashboard",
                    "name": "projects/example/dashboards/2",
                },
            ],
            ("projects/example/dashboards/1",),
        ),
        (
            "phase5-project-org-policies",
            [
                {
                    "name": (
                        "projects/123456789012/policies/"
                        "iam.automaticIamGrantsForDefaultServiceAccounts"
                    )
                },
                {"name": "projects/123456789012/policies/other.constraint"},
            ],
            (
                "projects/123456789012/policies/"
                "iam.automaticIamGrantsForDefaultServiceAccounts",
            ),
        ),
    ),
)
def test_post_teardown_inventory_matches_operational_resources_only(
    kind: str,
    resources: list[dict[str, str]],
    expected: tuple[str, ...],
) -> None:
    assert (
        public_evidence._matched_resource_ids(
            kind,
            resources,
            project_id="reconcile-proof-123456",
        )
        == expected
    )


def test_post_teardown_capture_versions_are_strict_and_compatible() -> None:
    legacy_inventory = {
        "artifact_repositories": 0,
        "cloud_run_jobs": 0,
        "cloud_run_services": 0,
        "custom_roles": 0,
        "firestore_databases": 0,
        "phase5_budgets": 0,
        "phase5_named_service_accounts": 0,
        "phase5_project_iam_members": 0,
        "storage_buckets": 0,
    }
    legacy = {
        "schema_version": "reconcile/post-teardown-capture/v1",
        "status": "PASS",
        "source_revision": "a" * 40,
        "candidate_sha256": "b" * 64,
        "captured_at": "2026-08-31T12:00:00Z",
        "teardown_actions": {
            "runtime_sha256": "c" * 64,
            "foundation_sha256": "d" * 64,
            "state_protection_sha256": "e" * 64,
            "bootstrap_sha256": "f" * 64,
        },
        "inventory": legacy_inventory,
        "observations_sha256": "1" * 64,
    }
    expected_legacy = json.dumps(
        legacy,
        allow_nan=False,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode()

    assert canonical_post_teardown_capture(legacy) == expected_legacy

    current = json.loads(expected_legacy)
    current["schema_version"] = "reconcile/post-teardown-capture/v2"
    current["inventory"].update(
        {
            "phase5_alert_policies": 0,
            "phase5_dashboards": 0,
            "phase5_log_metrics": 0,
            "phase5_project_org_policies": 0,
        }
    )
    current_capture = json.loads(canonical_post_teardown_capture(current))
    assert current_capture["inventory"] == current["inventory"]

    incomplete = json.loads(expected_legacy)
    incomplete["schema_version"] = "reconcile/post-teardown-capture/v2"
    with pytest.raises(PublicEvidenceError, match="POST_TEARDOWN_CAPTURE_INVALID"):
        canonical_post_teardown_capture(incomplete)


@pytest.fixture(scope="module")
def accepted_inputs(
    tmp_path_factory: pytest.TempPathFactory,
) -> _Inputs:
    root = tmp_path_factory.mktemp("public-evidence-input")
    state_root = acceptance_fixtures._state_root(root)
    project = "reconcile-proof-123456"
    previous_project = acceptance_fixtures.PROJECT
    acceptance_fixtures.PROJECT = project
    try:
        profile = DeploymentProfile(
            schema_version="reconcile/deployment-profile/v1",
            project_id=project,
            project_number="123456789012",
            billing_account_id="ABCDEF-123456-ABCDEF",
            owner_account="owner@example.com",
        )
        candidate = build_candidate_identity(
            source_revision=acceptance_fixtures.SOURCE,
            image_digest=acceptance_fixtures.IMAGE,
            infrastructure_revision=acceptance_fixtures.SHA_A,
            semantic_config_sha256=acceptance_fixtures.SHA_C,
            deployment=resolve_deployment_identity(profile),
        )
        provider = asyncio.run(
            run_provider_acceptance(
                candidate,
                state_root=state_root,
                backend=acceptance_fixtures._Backend(),
                clock=lambda: NOW,
            )
        )
        hosted = asyncio.run(
            run_hosted_acceptance(
                candidate,
                state_root=state_root,
                backend=acceptance_fixtures._Backend(hosted=True),
                clock=lambda: NOW + timedelta(minutes=1),
            )
        )
        teardown = _teardown_records(
            root / "operator-records", candidate.source_revision
        )
        inventory = root / "post-teardown-inventory.json"
        capture_post_teardown_inventory(
            operator_manifest_sha256="6" * 64,
            source_revision=candidate.source_revision,
            image_digest=candidate.image_digest,
            infrastructure_revision=candidate.infrastructure_revision,
            semantic_config_sha256=candidate.semantic_config_sha256,
            deployment_profile_sha256=candidate.deployment_profile_sha256,
            project_id=candidate.project_id,
            region=candidate.region,
            billing_account_id=profile.billing_account_id,
            output=inventory,
            runner=_empty_inventory_runner,
            clock=lambda: NOW + timedelta(minutes=3),
        )
        yield _Inputs(
            provider=Path(provider.path),
            hosted=Path(hosted.path),
            inventory=inventory,
            teardown=teardown,
        )
    finally:
        acceptance_fixtures.PROJECT = previous_project


def test_export_projects_positive_and_ambiguity_proofs_without_private_identity(
    tmp_path: Path,
    accepted_inputs: _Inputs,
) -> None:
    provider_path = accepted_inputs.provider
    hosted_path = accepted_inputs.hosted
    output = tmp_path / "v0.2.0"

    export_public_evidence(
        provider_acceptance=provider_path,
        hosted_acceptance=hosted_path,
        runtime_teardown_evidence=accepted_inputs.teardown[0],
        foundation_teardown_evidence=accepted_inputs.teardown[1],
        state_protection_evidence=accepted_inputs.teardown[2],
        bootstrap_teardown_evidence=accepted_inputs.teardown[3],
        post_teardown_inventory=accepted_inputs.inventory,
        output=output,
    )
    payload = load_and_validate(output / "proof-to-permit.json")

    assert {path.name for path in output.iterdir()} == PUBLIC_EVIDENCE_FILES
    assert stat.S_IMODE(output.stat().st_mode) == 0o700
    assert all(stat.S_IMODE(path.stat().st_mode) == 0o400 for path in output.iterdir())
    cleanup = payload["cleanup_verification"]
    assert cleanup["schema_version"] == "reconcile/cleanup-verification/v3"
    assert cleanup["inventory"] == {
        "artifact_repositories": 0,
        "cloud_run_jobs": 0,
        "cloud_run_services": 0,
        "custom_roles": 0,
        "firestore_databases": 0,
        "phase5_alert_policies": 0,
        "phase5_budgets": 0,
        "phase5_dashboards": 0,
        "phase5_log_metrics": 0,
        "phase5_named_service_accounts": 0,
        "phase5_project_iam_members": 0,
        "phase5_project_org_policies": 0,
        "storage_buckets": 0,
    }
    adaptive = payload["provider_proof"]["adaptive_recovery"]
    assert adaptive["effects"] == {
        "revisions": 1,
        "promotions": 1,
        "release_records": 1,
    }
    assert adaptive["replay"] == {
        "snapshot_stable": True,
        "rejected_before_provider_contact": True,
        "provider_contact_delta": 0,
        "denial_count": 1,
    }
    ambiguity = payload["live_corroboration"]["ambiguity_proof"]
    assert ambiguity["classification"] == "UNKNOWN"
    assert ambiguity["lifecycle"] == "ESCALATED"
    assert ambiguity["history_ids"] == [
        "effects-occurred",
        "effects-not-occurred",
    ]
    assert ambiguity["history_classifications"] == ["COMMITTED", "PARTIAL"]
    hosted_input = json.loads(hosted_path.read_bytes())
    expected_classifications = [
        item["classification"]
        for item in hosted_input["recovery_lanes"][-1]["partial_read_outage"][
            "witness"
        ]["possible_histories"]
    ]
    assert ambiguity["history_classifications"] == expected_classifications
    assert ambiguity["history_evidence_counts"] == [1, 1]
    assert ambiguity["certificate_count"] == 0
    assert ambiguity["action_permit_count"] == 0
    assert ambiguity["effects"] == {
        "staged_revisions": 1,
        "promotions": 0,
        "release_records": 0,
    }

    provider_input = json.loads(provider_path.read_bytes())
    public_bytes = b"".join(path.read_bytes() for path in sorted(output.iterdir()))
    private_values = (
        provider_input["candidate"]["project_id"],
        provider_input["candidate"]["operator_service_account"],
        provider_input["candidate"]["api_audience"],
        hosted_input["provider_artifact"]["path"],
        *(item["uri"] for item in hosted_input["deployments"]),
    )
    assert all(value.encode() not in public_bytes for value in private_values)

    snapshot = _build_snapshot(output, "a" * 40)
    assert snapshot["recovery"]["replay"] == adaptive["replay"]
    assert (
        snapshot["recovery"]["action_permits_consumed"]
        == adaptive["action_permits_consumed"]
    )
    assert "all_permits_single_use" not in snapshot["recovery"]
    assert snapshot["ambiguity"]["history_ids"] == [
        "effects-occurred",
        "effects-not-occurred",
    ]


def test_export_rejects_inventory_bound_to_another_operator_manifest(
    tmp_path: Path,
    accepted_inputs: _Inputs,
) -> None:
    values = json.loads(accepted_inputs.inventory.read_bytes())
    values["operator_manifest_sha256"] = "5" * 64
    inventory = tmp_path / "wrong-manifest-inventory.json"
    _write_private(
        inventory,
        canonical_json_bytes(
            PostTeardownInventoryObservation.model_validate_json(
                json.dumps(values, allow_nan=False, separators=(",", ":"))
            )
        ),
    )

    with pytest.raises(PublicEvidenceError, match="POST_TEARDOWN_MANIFEST_MISMATCH"):
        export_public_evidence(
            provider_acceptance=accepted_inputs.provider,
            hosted_acceptance=accepted_inputs.hosted,
            runtime_teardown_evidence=accepted_inputs.teardown[0],
            foundation_teardown_evidence=accepted_inputs.teardown[1],
            state_protection_evidence=accepted_inputs.teardown[2],
            bootstrap_teardown_evidence=accepted_inputs.teardown[3],
            post_teardown_inventory=inventory,
            output=tmp_path / "rejected-manifest",
        )


def test_export_rejects_noncanonical_capture_and_existing_output(
    tmp_path: Path,
    accepted_inputs: _Inputs,
) -> None:
    provider_path = accepted_inputs.provider
    hosted_path = accepted_inputs.hosted
    noncanonical = tmp_path / "inventory.json"
    noncanonical.write_bytes(accepted_inputs.inventory.read_bytes() + b"\n")
    noncanonical.chmod(0o400)

    with pytest.raises(PublicEvidenceError, match="POST_TEARDOWN_INVENTORY_INVALID"):
        export_public_evidence(
            provider_acceptance=provider_path,
            hosted_acceptance=hosted_path,
            runtime_teardown_evidence=accepted_inputs.teardown[0],
            foundation_teardown_evidence=accepted_inputs.teardown[1],
            state_protection_evidence=accepted_inputs.teardown[2],
            bootstrap_teardown_evidence=accepted_inputs.teardown[3],
            post_teardown_inventory=noncanonical,
            output=tmp_path / "rejected",
        )

    output = tmp_path / "v0.2.0"
    export_public_evidence(
        provider_acceptance=provider_path,
        hosted_acceptance=hosted_path,
        runtime_teardown_evidence=accepted_inputs.teardown[0],
        foundation_teardown_evidence=accepted_inputs.teardown[1],
        state_protection_evidence=accepted_inputs.teardown[2],
        bootstrap_teardown_evidence=accepted_inputs.teardown[3],
        post_teardown_inventory=accepted_inputs.inventory,
        output=output,
    )
    with pytest.raises(PublicEvidenceError, match="OUTPUT_DIRECTORY_INVALID"):
        export_public_evidence(
            provider_acceptance=provider_path,
            hosted_acceptance=hosted_path,
            runtime_teardown_evidence=accepted_inputs.teardown[0],
            foundation_teardown_evidence=accepted_inputs.teardown[1],
            state_protection_evidence=accepted_inputs.teardown[2],
            bootstrap_teardown_evidence=accepted_inputs.teardown[3],
            post_teardown_inventory=accepted_inputs.inventory,
            output=output,
        )


def test_export_cli_accepts_only_explicit_absolute_inputs(
    tmp_path: Path,
    accepted_inputs: _Inputs,
) -> None:
    provider_path = accepted_inputs.provider
    hosted_path = accepted_inputs.hosted
    output = tmp_path / "v0.2.0"

    completed = subprocess.run(
        [
            sys.executable,
            "-m",
            "scripts.export_public_evidence",
            "--provider-acceptance",
            str(provider_path),
            "--hosted-acceptance",
            str(hosted_path),
            "--runtime-teardown-evidence",
            str(accepted_inputs.teardown[0]),
            "--foundation-teardown-evidence",
            str(accepted_inputs.teardown[1]),
            "--state-protection-evidence",
            str(accepted_inputs.teardown[2]),
            "--bootstrap-teardown-evidence",
            str(accepted_inputs.teardown[3]),
            "--post-teardown-inventory",
            str(accepted_inputs.inventory),
            "--output",
            str(output),
        ],
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
    )

    assert json.loads(completed.stdout)["schema_version"] == (
        "reconcile/public-evidence/v1"
    )
    assert {path.name for path in output.iterdir()} == PUBLIC_EVIDENCE_FILES

    validated = subprocess.run(
        [
            sys.executable,
            "-m",
            "scripts.validate_evidence",
            "--evidence",
            str(output / "proof-to-permit.json"),
            "--json",
        ],
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
    )
    summary = json.loads(validated.stdout)
    assert summary["status"] == "PASS"
    assert summary["live_gate"]["ambiguity"]["classification"] == "UNKNOWN"


def test_capture_cli_reports_empty_inventory_as_pass(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    accepted_inputs: _Inputs,
    tmp_path: Path,
) -> None:
    observation = PostTeardownInventoryObservation.model_validate_json(
        accepted_inputs.inventory.read_bytes(),
        strict=True,
    )
    assert observation.schema_version == "reconcile/post-teardown-inventory/v2"
    assert tuple(query.kind for query in observation.queries[-4:]) == (
        "phase5-log-metrics",
        "phase5-alert-policies",
        "phase5-dashboards",
        "phase5-project-org-policies",
    )
    monkeypatch.setattr(
        capture_inventory_cli,
        "capture_post_teardown_inventory_from_manifest",
        lambda **_kwargs: observation,
    )
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "capture_post_teardown_inventory.py",
            "--manifest",
            str(tmp_path / "manifest.json"),
            "--output",
            str(tmp_path / "inventory.json"),
        ],
    )

    assert capture_inventory_cli.main() == 0
    summary = json.loads(capsys.readouterr().out)
    assert summary["status"] == "PASS"
    assert summary["query_count"] == 13
    assert set(summary["matched_resource_counts"].values()) == {0}


def test_capture_cli_fails_visibly_when_resources_remain(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    accepted_inputs: _Inputs,
    tmp_path: Path,
) -> None:
    observation = PostTeardownInventoryObservation.model_validate_json(
        accepted_inputs.inventory.read_bytes(),
        strict=True,
    )
    first = observation.queries[0].model_copy(
        update={"matched_resource_ids": ("reconcile-p5-api",)}
    )
    nonempty = observation.model_copy(
        update={"queries": (first, *observation.queries[1:])}
    )
    monkeypatch.setattr(
        capture_inventory_cli,
        "capture_post_teardown_inventory_from_manifest",
        lambda **_kwargs: nonempty,
    )
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "capture_post_teardown_inventory.py",
            "--manifest",
            str(tmp_path / "manifest.json"),
            "--output",
            str(tmp_path / "inventory.json"),
        ],
    )

    assert capture_inventory_cli.main() == 2
    summary = json.loads(capsys.readouterr().out)
    assert summary["status"] == "RESOURCES_REMAIN"
    assert summary["matched_resource_counts"][first.kind] == 1
