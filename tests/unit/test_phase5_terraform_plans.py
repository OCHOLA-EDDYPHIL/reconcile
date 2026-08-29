from __future__ import annotations

import json
import shutil
import stat
import subprocess
from copy import deepcopy
from pathlib import Path
from typing import Any

import pytest

from reconcile.hosted.provider import (
    HOSTED_CANDIDATE_IDENTITY_VERSION,
    HostedCandidateIdentity,
)
from scripts import check_phase5_terraform_plans as plans

pytestmark = pytest.mark.unit


def test_recovery_payload_hash_is_the_canonical_hosted_candidate_identity() -> None:
    candidate = HostedCandidateIdentity(
        schema_version=HOSTED_CANDIDATE_IDENTITY_VERSION,
        source_revision=plans._SOURCE_REVISION,
        image_digest=plans._IMAGE_DIGEST,
        infrastructure_revision=plans._INFRASTRUCTURE_REVISION,
        semantic_config_sha256=plans._SEMANTIC_CONFIG_SHA256,
        project_id=plans._PROJECT,
        vertex_location="us",
        configured_model="gemini-3.5-flash",
        prompt_version=plans._VERTEX_PROMPT_VERSION,
        prompt_sha256=plans._VERTEX_PROMPT_SHA256,
        maximum_input_tokens=12_000,
        maximum_output_tokens=4_096,
        thinking_level="MINIMAL",
        maximum_count_tokens_attempts=1,
        maximum_generation_attempts=1,
    )

    assert plans._RECOVERY_PAYLOAD_SHA256 == candidate.sha256


def test_subprocess_failure_includes_bounded_diagnostics(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    omitted = "not-in-diagnostic"
    failure = subprocess.CompletedProcess(
        args=["terraform", "validate"],
        returncode=1,
        stdout=omitted + ("o" * 4_096),
        stderr=omitted + ("e" * 4_096),
    )
    monkeypatch.setattr(plans.subprocess, "run", lambda *args, **kwargs: failure)

    with pytest.raises(RuntimeError) as raised:
        plans._run(["terraform", "validate"], environment={})

    diagnostic = str(raised.value)
    assert omitted not in diagnostic
    assert "stdout='" + ("o" * 4_096) + "'" in diagnostic
    assert "stderr='" + ("e" * 4_096) + "'" in diagnostic


def _resource(address: str, after: dict[str, Any] | None = None) -> dict[str, Any]:
    return {
        "address": address,
        "change": {
            "actions": ["create"],
            "after": after or {},
            "after_sensitive": {},
        },
        "provider_name": (
            plans._TERRAFORM_PROVIDER
            if address.startswith("terraform_data.")
            else plans._PROVIDER
        ),
        "type": address.split(".", 1)[0],
    }


def _stack_resources(stack: plans._Stack) -> dict[str, dict[str, Any]]:
    return {address: _resource(address) for address in stack.addresses}


def _iam_resources(stack: plans._Stack) -> dict[str, dict[str, Any]]:
    resources = _stack_resources(stack)
    for address in set(resources) & set(plans._IAM_EXPECTED):
        expected = deepcopy(plans._IAM_EXPECTED[address])
        expression = expected.pop("condition_expression", None)
        if expression is not None:
            expected["condition"] = [{"expression": expression}]
        resources[address]["change"]["after"] = expected
    for address in set(resources) & set(plans._CUSTOM_ROLE_EXPECTED):
        resources[address]["change"]["after"] = deepcopy(
            plans._CUSTOM_ROLE_EXPECTED[address]
        )
    return resources


@pytest.mark.parametrize("stack", plans._STACKS, ids=lambda stack: stack.name)
def test_create_inventory_is_exact_and_create_only(stack: plans._Stack) -> None:
    resources = _stack_resources(stack)

    plans._verify_inventory(stack, resources)

    extra = deepcopy(resources)
    extra["google_project_iam_member.extra"] = _resource(
        "google_project_iam_member.extra"
    )
    with pytest.raises(ValueError, match="inventory mismatch"):
        plans._verify_inventory(stack, extra)

    changed = deepcopy(resources)
    first = next(iter(changed.values()))
    first["change"]["actions"] = ["update"]
    with pytest.raises(ValueError, match="not create-only"):
        plans._verify_inventory(stack, changed)


def test_resource_semantics_digest_binds_complete_before_and_after_values() -> None:
    resources = {
        "google_example.second": _resource("google_example.second", {"bounded": True}),
        "google_example.first": _resource("google_example.first", {"bounded": True}),
    }
    resources["google_example.first"]["change"]["before"] = None

    baseline = plans._resource_semantics_digest(resources)
    assert baseline == plans._resource_semantics_digest(
        dict(reversed(resources.items()))
    )

    changed_after = deepcopy(resources)
    changed_after["google_example.first"]["change"]["after"]["bounded"] = False
    assert plans._resource_semantics_digest(changed_after) != baseline

    changed_before = deepcopy(resources)
    changed_before["google_example.first"]["change"]["before"] = {"bounded": False}
    assert plans._resource_semantics_digest(changed_before) != baseline


@pytest.mark.parametrize("stack", plans._STACKS, ids=lambda stack: stack.name)
def test_expanded_iam_edges_are_closed_world(stack: plans._Stack) -> None:
    resources = _iam_resources(stack)

    plans._verify_iam(resources)

    extra = deepcopy(resources)
    extra["google_project_iam_member.extra"] = _resource(
        "google_project_iam_member.extra",
        {
            "member": plans._APPLY_MEMBER,
            "project": plans._PROJECT,
            "role": "roles/owner",
        },
    )
    with pytest.raises(ValueError, match="not closed-world"):
        plans._verify_iam(extra)

    if set(resources) & set(plans._IAM_EXPECTED):
        changed = deepcopy(resources)
        address = next(iter(set(changed) & set(plans._IAM_EXPECTED)))
        changed[address]["change"]["after"]["role"] = "roles/owner"
        with pytest.raises(ValueError, match="unexpected role"):
            plans._verify_iam(changed)


def test_runtime_revision_reader_inventory_is_exact() -> None:
    addresses = {
        address
        for address in plans._RUNTIME_ADDRESSES
        if address.startswith("google_project_iam_member.canary_revision_reader")
    }
    expected = {
        f'google_project_iam_member.canary_revision_reader["{component}"]': (
            f"serviceAccount:{plans._RUNTIME_EMAILS[component]}"
        )
        for component in ("controller", "fault_proxy")
    }

    assert addresses == set(expected)
    assert {
        address: plans._IAM_EXPECTED[address]["member"] for address in addresses
    } == expected


def _runtime_service_resources() -> dict[str, dict[str, Any]]:
    resources: dict[str, dict[str, Any]] = {
        "terraform_data.canary_baseline": _resource(
            "terraform_data.canary_baseline",
            {"triggers_replace": plans._CANARY_BASELINE_IDENTITY},
        )
    }
    for component, email in plans._RUNTIME_EMAILS.items():
        address = f"google_cloud_run_v2_service.{component}"
        container = {
            "env": [
                {"name": name, "value": value}
                for name, value in plans._RUNTIME_ENVIRONMENT[component].items()
            ],
            "image": plans._IMAGE_REFERENCE,
            "name": plans._SERVICE_CONTAINERS[component],
            "ports": [{"container_port": 8080, "name": "http1"}],
            "resources": [
                {
                    "cpu_idle": True,
                    "limits": {
                        "cpu": "1",
                        "memory": plans._SERVICE_MEMORY[component],
                    },
                    "startup_cpu_boost": False,
                }
            ],
        }
        template = {
            "containers": [container],
            "execution_environment": "EXECUTION_ENVIRONMENT_GEN2",
            "max_instance_request_concurrency": 1,
            "scaling": [{"max_instance_count": 1, "min_instance_count": 0}],
            "service_account": email,
            "timeout": plans._SERVICE_TIMEOUTS[component],
        }
        traffic = None
        if component == "canary":
            container.update(
                {
                    "args": ["-m", "reconcile.hosted.cloud_run_canary"],
                    "command": ["/opt/reconcile/bin/python"],
                }
            )
            template.update(
                {
                    "annotations": {
                        "reconcile.dev/configuration-sha256": (
                            plans._SEMANTIC_CONFIG_SHA256
                        )
                    },
                    "labels": {"reconcile-release": "baseline"},
                    "revision": plans._CANARY_BASELINE_REVISION,
                }
            )
            traffic = [
                {
                    "percent": 100,
                    "revision": plans._CANARY_BASELINE_REVISION,
                    "tag": None,
                    "type": "TRAFFIC_TARGET_ALLOCATION_TYPE_REVISION",
                }
            ]
        resources[address] = _resource(
            address,
            {
                "custom_audiences": [plans._AUDIENCES[component]],
                "deletion_policy": "DELETE",
                "deletion_protection": False,
                "ingress": "INGRESS_TRAFFIC_ALL",
                "invoker_iam_disabled": False,
                "labels": {
                    "app": "reconcile",
                    "component": component.replace("_", "-"),
                    "environment": "phase5",
                },
                "location": plans._REGION,
                "name": plans._SERVICE_NAMES[component],
                "project": plans._PROJECT,
                "template": [template],
                "traffic": traffic,
            },
        )
    return resources


def test_runtime_plan_requires_one_image_audiences_and_exact_environment() -> None:
    resources = _runtime_service_resources()

    plans._verify_cloud_run(resources)

    changed_audience = deepcopy(resources)
    changed_audience["google_cloud_run_v2_service.api"]["change"]["after"][
        "custom_audiences"
    ] = [plans._AUDIENCES["controller"]]
    with pytest.raises(ValueError, match="custom_audiences"):
        plans._verify_cloud_run(changed_audience)

    changed_image = deepcopy(resources)
    container = changed_image["google_cloud_run_v2_service.sandbox"]["change"]["after"][
        "template"
    ][0]["containers"][0]
    container["image"] = container["image"][:-1] + "1"
    with pytest.raises(ValueError, match="image"):
        plans._verify_cloud_run(changed_image)

    missing_environment = deepcopy(resources)
    missing_environment["google_cloud_run_v2_service.controller"]["change"]["after"][
        "template"
    ][0]["containers"][0]["env"].pop()
    with pytest.raises(ValueError, match="environment contract"):
        plans._verify_cloud_run(missing_environment)

    expensive = deepcopy(resources)
    expensive_container = expensive["google_cloud_run_v2_service.api"]["change"][
        "after"
    ]["template"][0]["containers"][0]
    expensive_container["resources"][0]["limits"] = {
        "cpu": "8",
        "memory": "32Gi",
    }
    with pytest.raises(ValueError, match="unexpected limits"):
        plans._verify_cloud_run(expensive)

    wrong_port = deepcopy(resources)
    wrong_port["google_cloud_run_v2_service.api"]["change"]["after"]["template"][0][
        "containers"
    ][0]["ports"][0]["container_port"] = 9999
    with pytest.raises(ValueError, match="unexpected ports"):
        plans._verify_cloud_run(wrong_port)

    unbounded_timeout = deepcopy(resources)
    unbounded_timeout["google_cloud_run_v2_service.api"]["change"]["after"]["template"][
        0
    ]["timeout"] = "3600s"
    with pytest.raises(ValueError, match="unexpected timeout"):
        plans._verify_cloud_run(unbounded_timeout)

    protected = deepcopy(resources)
    protected["google_cloud_run_v2_service.api"]["change"]["after"].update(
        {"deletion_policy": "PREVENT", "deletion_protection": True}
    )
    with pytest.raises(ValueError, match="unexpected deletion_policy"):
        plans._verify_cloud_run(protected)

    external_network = deepcopy(resources)
    external_network["google_cloud_run_v2_service.api"]["change"]["after"]["template"][
        0
    ]["vpc_access"] = [{"egress": "ALL_TRAFFIC"}]
    with pytest.raises(ValueError, match="unapproved vpc_access"):
        plans._verify_cloud_run(external_network)

    stale_canary = deepcopy(resources)
    stale_canary["google_cloud_run_v2_service.canary"]["change"]["after"]["traffic"][0][
        "revision"
    ] = "reconcile-p5-canary-unverified"
    with pytest.raises(ValueError, match="baseline canary traffic"):
        plans._verify_cloud_run(stale_canary)

    stale_trigger = deepcopy(resources)
    stale_trigger["terraform_data.canary_baseline"]["change"]["after"][
        "triggers_replace"
    ] = "f" * 64
    with pytest.raises(ValueError, match="replacement trigger"):
        plans._verify_cloud_run(stale_trigger)


def test_canary_two_plan_model_stabilizes_drift_and_rotates_new_baseline() -> None:
    initial = {
        "image_digest": plans._IMAGE_DIGEST,
        "infrastructure_revision": plans._INFRASTRUCTURE_REVISION,
        "semantic_config_sha256": plans._SEMANTIC_CONFIG_SHA256,
        "source_revision": plans._SOURCE_REVISION,
        "request_timeout_seconds": 60,
    }
    first = plans._canary_baseline_identity(**initial)
    post_stage_replan = plans._canary_baseline_identity(**initial)

    assert first == post_stage_replan == plans._CANARY_BASELINE_IDENTITY
    assert plans._CANARY_BASELINE_REVISION.endswith(first[:16])

    replacements = (
        {"image_digest": f"sha256:{'1' * 64}"},
        {"infrastructure_revision": "2" * 64},
        {"semantic_config_sha256": "3" * 64},
        {"source_revision": "4" * 40},
        {"request_timeout_seconds": 61},
    )
    rotated = {
        plans._canary_baseline_identity(**(initial | replacement))
        for replacement in replacements
    }
    assert len(rotated) == len(replacements)
    assert first not in rotated


def test_foundation_plan_requires_three_exact_database_boundaries() -> None:
    resources = {
        "google_artifact_registry_repository.runtime": _resource(
            "google_artifact_registry_repository.runtime",
            {
                "cleanup_policies": [
                    {
                        "action": "DELETE",
                        "condition": [
                            {
                                "newer_than": "",
                                "older_than": "1d",
                                "package_name_prefixes": ["reconcile"],
                                "tag_prefixes": [],
                                "tag_state": "UNTAGGED",
                                "version_name_prefixes": [],
                            }
                        ],
                        "id": "delete-old-untagged",
                        "most_recent_versions": [],
                    },
                    {
                        "action": "KEEP",
                        "condition": [],
                        "id": "keep-at-least-two-recent",
                        "most_recent_versions": [
                            {
                                "keep_count": 2,
                                "package_name_prefixes": ["reconcile"],
                            }
                        ],
                    },
                ],
                "cleanup_policy_dry_run": False,
                "deletion_policy": "DELETE",
                "description": "RECONCILE Phase 5 runtime images",
                "docker_config": [{"immutable_tags": True}],
                "format": "DOCKER",
                "labels": {
                    "app": "reconcile",
                    "component": "runtime-images",
                    "environment": "phase5",
                },
                "location": plans._REGION,
                "mode": "STANDARD_REPOSITORY",
                "project": plans._PROJECT,
                "repository_id": "reconcile-p5",
            },
        ),
        "google_billing_budget.phase5": _resource(
            "google_billing_budget.phase5",
            {
                "all_updates_rule": [],
                "amount": [
                    {
                        "last_period_amount": None,
                        "specified_amount": [
                            {"currency_code": "USD", "nanos": None, "units": "5"}
                        ],
                    }
                ],
                "billing_account": "000000-000000-000000",
                "budget_filter": [
                    {
                        "calendar_period": None,
                        "credit_types": None,
                        "credit_types_treatment": "EXCLUDE_ALL_CREDITS",
                        "custom_period": [],
                        "projects": [f"projects/{plans._PROJECT_NUMBER}"],
                        "resource_ancestors": None,
                        "subaccounts": None,
                    }
                ],
                "deletion_policy": "DELETE",
                "display_name": "RECONCILE Phase 5 USD 5",
                "ownership_scope": None,
                "threshold_rules": [
                    {"spend_basis": "CURRENT_SPEND", "threshold_percent": 0.5},
                    {"spend_basis": "CURRENT_SPEND", "threshold_percent": 0.8},
                    {"spend_basis": "CURRENT_SPEND", "threshold_percent": 1.0},
                    {"spend_basis": "FORECASTED_SPEND", "threshold_percent": 1.0},
                ],
            },
        ),
    }
    database_names = {
        "runtime": "reconcile-p5-runtime",
        "sandbox": plans._SANDBOX_DATABASE,
        "target": "reconcile-p5-target",
    }
    for key, name in database_names.items():
        address = f'google_firestore_database.phase5["{key}"]'
        resources[address] = _resource(
            address,
            {
                "app_engine_integration_mode": "DISABLED",
                "concurrency_mode": "OPTIMISTIC",
                "database_edition": "STANDARD",
                "delete_protection_state": "DELETE_PROTECTION_DISABLED",
                "deletion_policy": "DELETE",
                "location_id": plans._REGION,
                "name": name,
                "point_in_time_recovery_enablement": (
                    "POINT_IN_TIME_RECOVERY_DISABLED"
                ),
                "project": plans._PROJECT,
                "type": "FIRESTORE_NATIVE",
            },
        )

    plans._verify_foundation(resources)

    changed = deepcopy(resources)
    changed['google_firestore_database.phase5["sandbox"]']["change"]["after"][
        "name"
    ] = "reconcile-p5-target"
    with pytest.raises(ValueError, match="unexpected name"):
        plans._verify_foundation(changed)

    enterprise = deepcopy(resources)
    enterprise['google_firestore_database.phase5["runtime"]']["change"]["after"][
        "database_edition"
    ] = "ENTERPRISE"
    with pytest.raises(ValueError, match="unexpected database_edition"):
        plans._verify_foundation(enterprise)

    protected = deepcopy(resources)
    protected['google_firestore_database.phase5["runtime"]']["change"]["after"].update(
        {
            "delete_protection_state": "DELETE_PROTECTION_ENABLED",
            "deletion_policy": "ABANDON",
        }
    )
    with pytest.raises(ValueError, match="unexpected delete_protection_state"):
        plans._verify_foundation(protected)

    wrong_repository = deepcopy(resources)
    wrong_repository["google_artifact_registry_repository.runtime"]["change"]["after"][
        "repository_id"
    ] = "wrong-repository"
    with pytest.raises(ValueError, match="unexpected repository_id"):
        plans._verify_foundation(wrong_repository)

    unscoped_budget = deepcopy(resources)
    unscoped_budget["google_billing_budget.phase5"]["change"]["after"]["budget_filter"][
        0
    ]["projects"] = []
    with pytest.raises(ValueError, match="unexpected budget_filter"):
        plans._verify_foundation(unscoped_budget)


def test_operator_artifacts_cover_create_destroy_and_protection_paths(
    tmp_path: Path,
) -> None:
    destination = tmp_path / "plans"
    destination.mkdir(mode=0o700)

    def qualification(address: str, variables: dict[str, Any]) -> dict[str, Any]:
        return {
            "resource_changes": [
                {
                    "address": address,
                    "change": {
                        "actions": ["create"],
                        "after": {
                            "deletion_policy": "PREVENT",
                            "force_destroy": False,
                        },
                        "before": None,
                    },
                    "provider_name": plans._PROVIDER,
                    "type": address.split(".", 1)[0],
                }
            ],
            "terraform_version": "1.15.8",
            "variables": {name: {"value": value} for name, value in variables.items()},
        }

    create_plans = {
        "bootstrap": qualification(
            "google_storage_bucket.terraform_state",
            {"allow_state_bucket_destroy": False},
        ),
        "foundation": qualification("google_storage_bucket.target", {}),
        "runtime": qualification("google_cloud_run_v2_service.api", {}),
    }

    plans._write_operator_artifacts(destination, create_plans)

    artifacts = tuple(destination.iterdir())
    assert len(artifacts) == 14
    assert all(stat.S_IMODE(path.stat().st_mode) == 0o400 for path in artifacts)
    runtime_destroy = json.loads(
        (destination / "runtime-destroy.tfplan.json").read_bytes()
    )
    assert runtime_destroy["resource_changes"][0]["change"]["actions"] == ["delete"]
    protection = json.loads(
        (destination / "bootstrap-disable-protection.tfplan.json").read_bytes()
    )
    assert protection["variables"]["allow_state_bucket_destroy"]["value"] is True
    assert protection["resource_changes"][0]["change"]["actions"] == ["delete"]


@pytest.mark.parametrize(
    "value, message",
    [
        ({"password": "not-allowed"}, "secret-bearing value"),
        ({"member": "allUsers"}, "public principal"),
        ({"nested": [{"api_key": "not-allowed"}]}, "secret-bearing value"),
    ],
)
def test_plan_value_scan_rejects_secrets_and_public_principals(
    value: dict[str, Any], message: str
) -> None:
    with pytest.raises(ValueError, match=message):
        plans._walk(value)


def test_sensitive_plan_markers_are_detected() -> None:
    assert plans._contains_true({"template": [{"secret": True}]}) is True
    assert plans._contains_true({"template": [{"secret": False}]}) is False


@pytest.mark.parametrize("stack", plans._STACKS, ids=lambda stack: stack.name)
def test_plan_envelope_is_closed_world(stack: plans._Stack) -> None:
    plan = {
        "terraform_version": "1.15.8",
        "variables": {
            name: {"value": "safe"} for name in plans._VARIABLE_NAMES[stack.name]
        },
        "planned_values": {
            "outputs": {
                name: {"sensitive": False, "value": "safe"}
                for name in plans._OUTPUT_NAMES[stack.name]
            }
        },
        "output_changes": {
            name: {
                "after": "safe",
                "after_sensitive": False,
                "before": None,
                "before_sensitive": False,
            }
            for name in plans._OUTPUT_NAMES[stack.name]
        },
    }

    plans._verify_plan_envelope(stack, plan)

    extra_variable = deepcopy(plan)
    extra_variable["variables"]["password"] = {"value": "not-allowed"}
    with pytest.raises(ValueError, match="variable inventory"):
        plans._verify_plan_envelope(stack, extra_variable)

    extra_output = deepcopy(plan)
    extra_output["planned_values"]["outputs"]["leak"] = {
        "sensitive": False,
        "value": "not-allowed",
    }
    with pytest.raises(ValueError, match="output inventory"):
        plans._verify_plan_envelope(stack, extra_output)

    sensitive = deepcopy(plan)
    first_output = next(iter(plans._OUTPUT_NAMES[stack.name]))
    sensitive["output_changes"][first_output]["after_sensitive"] = True
    with pytest.raises(ValueError, match="sensitive output change"):
        plans._verify_plan_envelope(stack, sensitive)


def _temporary_stack(path: Path, source: str) -> plans._Stack:
    (path / "main.tf").write_text(source, encoding="utf-8")
    return plans._Stack("temporary", path, frozenset(), {})


def test_source_policy_allows_attributes_but_rejects_hidden_configuration(
    tmp_path: Path,
) -> None:
    stack = _temporary_stack(
        tmp_path,
        'resource "example" "value" {\n  action = "DELETE"\n}\n',
    )
    assert plans._validate_stack_source(stack) == (tmp_path / "main.tf",)

    (tmp_path / "extra.tf.json").write_text("{}", encoding="utf-8")
    with pytest.raises(ValueError, match="input file"):
        plans._validate_stack_source(stack)


@pytest.mark.parametrize(
    "source, message",
    [
        (
            '/* backend "gcs" { bucket = "expected" } */\n'
            'resource "example" "value" {}\n',
            "lexical content",
        ),
        ('data "google_client_config" "current" {}\n', "construct"),
        ('check "hidden" { assert { condition = true } }\n', "construct"),
        ("moved { from = one.old to = one.new }\n", "construct"),
        (
            'resource "example" "value" { value = file("/proc/self/environ") }\n',
            "filesystem function",
        ),
    ],
)
def test_source_policy_rejects_bypass_constructs(
    tmp_path: Path, source: str, message: str
) -> None:
    stack = _temporary_stack(tmp_path, source)
    with pytest.raises(ValueError, match=message):
        plans._validate_stack_source(stack)


@pytest.mark.parametrize(
    "name",
    [
        "secret",
        "client_secret",
        "secret_value",
        "credentials",
        "db_password",
        "access_token",
    ],
)
def test_source_policy_rejects_secret_bearing_local_keys(
    tmp_path: Path, name: str
) -> None:
    stack = _temporary_stack(tmp_path, f'locals {{ {name} = "not-allowed" }}\n')

    with pytest.raises(ValueError, match="secret-bearing source identifier"):
        plans._validate_stack_source(stack)


def test_copy_rewrites_only_the_verified_remote_backend(tmp_path: Path) -> None:
    for stack in plans._STACKS:
        destination = tmp_path / stack.name
        plans._copy_stack(stack, destination)
        if stack.name == "bootstrap":
            continue
        versions = (destination / "versions.tf").read_text(encoding="utf-8")
        provider = (destination / "providers.tf").read_text(encoding="utf-8")
        assert 'backend "local" {}' in versions
        assert 'backend "gcs"' not in versions
        assert "impersonate_service_account" not in provider


def test_copy_rewrites_private_working_files_from_read_only_source(
    tmp_path: Path,
) -> None:
    original = plans._STACKS[1]
    source = tmp_path / "source"
    shutil.copytree(original.source, source)
    source_files = tuple(path for path in source.iterdir() if path.is_file())
    for path in source_files:
        path.chmod(0o400)
    stack = plans._Stack(
        original.name,
        source,
        original.addresses,
        original.variables,
    )

    destination = tmp_path / "destination"
    plans._copy_stack(stack, destination)

    assert all(stat.S_IMODE(path.stat().st_mode) == 0o400 for path in source_files)
    assert all(
        stat.S_IMODE(path.stat().st_mode) == 0o600
        for path in destination.iterdir()
        if path.is_file()
    )
    assert 'backend "local" {}' in (destination / "versions.tf").read_text(
        encoding="utf-8"
    )


def test_copy_rejects_bootstrap_local_backend_path_drift(tmp_path: Path) -> None:
    source = tmp_path / "source"
    shutil.copytree(plans._STACKS[0].source, source)
    versions = source / "versions.tf"
    versions.write_text(
        versions.read_text(encoding="utf-8").replace(
            'path = "terraform.tfstate"', 'path = "drift.tfstate"'
        ),
        encoding="utf-8",
    )
    stack = plans._Stack("bootstrap", source, frozenset(), {})

    with pytest.raises(ValueError, match="local backend path drifted"):
        plans._copy_stack(stack, tmp_path / "destination")


def test_sandbox_is_read_only_offline_and_receives_a_minimal_environment(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("UNRELATED_SECRET", "not-forwarded")
    environment = plans._minimal_environment(network=False)
    command = plans._offline_command(["/bin/true"], tmp_path)

    assert "UNRELATED_SECRET" not in environment
    assert "GOOGLE_APPLICATION_CREDENTIALS" not in environment
    assert "--unshare-net" in command
    assert command[command.index("--ro-bind") + 1 : command.index("--ro-bind") + 3] == [
        "/",
        "/",
    ]
    assert ["--bind", str(tmp_path.parent), str(tmp_path.parent)] == command[
        command.index("--bind") : command.index("--bind") + 3
    ]
    assert ["--setenv", "TMPDIR", str(tmp_path.parent / "tmp")] == command[
        command.index("--setenv") : command.index("--setenv") + 3
    ]


def test_capable_bubblewrap_is_selected_without_docker(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(plans.shutil, "which", lambda name: f"/usr/bin/{name}")
    monkeypatch.setattr(plans, "_bubblewrap_usable", lambda _: True)
    monkeypatch.setattr(
        plans,
        "_run",
        lambda *args, **kwargs: pytest.fail("Docker must not be inspected"),
    )

    assert plans._select_offline_backend(tmp_path) == (
        "bubblewrap",
        Path("/usr/bin/bwrap"),
    )


def test_unusable_bubblewrap_selects_digest_pinned_docker(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    commands: list[list[str]] = []

    def locate(name: str) -> str:
        return f"/usr/bin/{name}"

    def record(command: list[str], **_: Any) -> subprocess.CompletedProcess[str]:
        commands.append(command)
        return subprocess.CompletedProcess(command, 0, "", "")

    monkeypatch.setattr(plans.shutil, "which", locate)
    monkeypatch.setattr(plans, "_bubblewrap_usable", lambda _: False)
    monkeypatch.setattr(plans, "_run", record)

    assert plans._select_offline_backend(tmp_path) == (
        "docker",
        Path("/usr/bin/docker"),
    )
    assert commands == [
        ["/usr/bin/docker", "image", "inspect", plans._OFFLINE_DOCKER_IMAGE]
    ]
    assert (tmp_path / "docker-config").stat().st_mode & 0o777 == 0o700


def test_docker_backend_pulls_only_the_missing_digest(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    commands: list[list[str]] = []

    def locate(name: str) -> str:
        return f"/usr/bin/{name}"

    def record(command: list[str], **_: Any) -> subprocess.CompletedProcess[str]:
        commands.append(command)
        return subprocess.CompletedProcess(
            command, 1 if len(commands) == 1 else 0, "", ""
        )

    monkeypatch.setattr(plans.shutil, "which", locate)
    monkeypatch.setattr(plans, "_bubblewrap_usable", lambda _: False)
    monkeypatch.setattr(plans, "_run", record)

    assert plans._select_offline_backend(tmp_path)[0] == "docker"
    assert commands == [
        ["/usr/bin/docker", "image", "inspect", plans._OFFLINE_DOCKER_IMAGE],
        ["/usr/bin/docker", "pull", plans._OFFLINE_DOCKER_IMAGE],
    ]


def test_offline_backend_fails_closed_when_no_isolator_exists(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(plans.shutil, "which", lambda _: None)

    with pytest.raises(RuntimeError, match="usable bwrap or a Docker daemon"):
        plans._select_offline_backend(tmp_path)


def test_docker_sandbox_is_networkless_read_only_and_closed_environment(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("DOCKER_HOST", "tcp://127.0.0.1:2375")
    monkeypatch.setenv("UNRELATED_SECRET", "not-forwarded")
    root = tmp_path / "plans"
    working = root / "runtime"
    working.mkdir(parents=True)
    terraform = tmp_path / "terraform"
    mirror = tmp_path / "provider-mirror"
    environment = plans._minimal_environment(network=False) | {
        "TF_CLI_CONFIG_FILE": str(root / "terraform.rc"),
        "TF_DATA_DIR": str(root / "runtime-data"),
    }

    command = plans._docker_offline_command(
        [str(terraform), f"-chdir={working}", "validate"],
        working,
        docker=Path("/usr/bin/docker"),
        environment=environment,
        read_only_paths=(mirror,),
    )

    assert command[:3] == ["/usr/bin/docker", "run", "--rm"]
    assert ["--network", "none"] == command[
        command.index("--network") : command.index("--network") + 2
    ]
    assert "--read-only" in command
    assert ["--cap-drop", "ALL"] == command[
        command.index("--cap-drop") : command.index("--cap-drop") + 2
    ]
    assert ["--security-opt", "no-new-privileges"] == command[
        command.index("--security-opt") : command.index("--security-opt") + 2
    ]
    assert ["--user", f"{plans.os.getuid()}:{plans.os.getgid()}"] == command[
        command.index("--user") : command.index("--user") + 2
    ]
    assert f"{root.resolve()}:{root.resolve()}:rw" in command
    assert f"{terraform.resolve()}:/reconcile-bin/terraform:ro" in command
    assert f"{mirror.resolve()}:{mirror.resolve()}:ro" in command
    assert command[-3:] == [
        "/reconcile-bin/terraform",
        f"-chdir={working}",
        "validate",
    ]
    assert plans._OFFLINE_DOCKER_IMAGE in command
    encoded_environment = [
        command[index + 1] for index, value in enumerate(command) if value == "--env"
    ]
    assert "DOCKER_HOST=tcp://127.0.0.1:2375" not in encoded_environment
    assert all("UNRELATED_SECRET" not in item for item in encoded_environment)

    outer_environment = plans._docker_environment(root)
    assert outer_environment["DOCKER_HOST"] == "tcp://127.0.0.1:2375"
    assert "UNRELATED_SECRET" not in outer_environment


def test_provider_mirror_uses_generated_fixed_configuration(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    commands: list[list[str]] = []

    def record(command: list[str], **_: Any) -> None:
        commands.append(command)

    monkeypatch.setattr(plans, "_run", record)
    monkeypatch.setattr(plans, "_verify_provider_mirror", lambda path: path)

    mirror = plans._create_provider_mirror(Path("/terraform"), tmp_path)
    source = (tmp_path / "mirror-configuration" / "versions.tf").read_text(
        encoding="utf-8"
    )

    assert mirror == tmp_path / "provider-mirror"
    assert 'source = "hashicorp/google"' in source
    assert 'version = "= 7.44.0"' in source
    assert commands == [
        [
            "/terraform",
            f"-chdir={tmp_path / 'mirror-configuration'}",
            "providers",
            "mirror",
            "-platform=linux_amd64",
            str(tmp_path / "provider-mirror"),
        ]
    ]
