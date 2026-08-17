from __future__ import annotations

import shutil
from copy import deepcopy
from pathlib import Path
from typing import Any

import pytest

from scripts import check_phase5_terraform_plans as plans

pytestmark = pytest.mark.unit


def _resource(address: str, after: dict[str, Any] | None = None) -> dict[str, Any]:
    return {
        "address": address,
        "change": {
            "actions": ["create"],
            "after": after or {},
            "after_sensitive": {},
        },
        "provider_name": plans._PROVIDER,
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
