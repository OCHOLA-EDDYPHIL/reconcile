from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

import pytest

pytestmark = pytest.mark.unit

_ROOT = Path(__file__).parents[2]
_INFRA = _ROOT / "infra"
_STACKS = (
    _INFRA / "bootstrap",
    _INFRA / "environments" / "dev" / "foundation",
    _INFRA / "environments" / "dev" / "runtime",
)
_CLOUD_RUN_SERVICES = {"api", "controller", "fault_proxy", "sandbox"}
_REQUIRED_SERVICES = {
    "aiplatform.googleapis.com",
    "artifactregistry.googleapis.com",
    "billingbudgets.googleapis.com",
    "cloudresourcemanager.googleapis.com",
    "firestore.googleapis.com",
    "iam.googleapis.com",
    "logging.googleapis.com",
    "run.googleapis.com",
    "serviceusage.googleapis.com",
    "storage.googleapis.com",
}
_ALLOWED_RESOURCE_TYPES = {
    "google_artifact_registry_repository",
    "google_billing_budget",
    "google_cloud_run_v2_service",
    "google_cloud_run_v2_service_iam_member",
    "google_firestore_database",
    "google_project_iam_member",
    "google_project_service",
    "google_service_account",
    "google_storage_bucket",
    "google_storage_bucket_iam_member",
}
_RESOURCE_HEADER = re.compile(
    r'(?m)^[ \t]*resource[ \t]+"([^"]+)"[ \t]+"([^"]+)"[ \t]*\{'
)


@dataclass(frozen=True, slots=True)
class _Resource:
    path: Path
    resource_type: str
    name: str
    body: str


def _terraform_files() -> tuple[Path, ...]:
    return tuple(sorted(_INFRA.rglob("*.tf")))


def _find_closing_brace(source: str, opening: int) -> int:
    depth = 0
    index = opening
    quote = False
    escaped = False
    line_comment = False
    block_comment = False
    while index < len(source):
        current = source[index]
        following = source[index + 1] if index + 1 < len(source) else ""
        if line_comment:
            if current == "\n":
                line_comment = False
        elif block_comment:
            if current == "*" and following == "/":
                block_comment = False
                index += 1
        elif quote:
            if escaped:
                escaped = False
            elif current == "\\":
                escaped = True
            elif current == '"':
                quote = False
        elif current == '"':
            quote = True
        elif current == "#" or (current == "/" and following == "/"):
            line_comment = True
            if current == "/":
                index += 1
        elif current == "/" and following == "*":
            block_comment = True
            index += 1
        elif current == "{":
            depth += 1
        elif current == "}":
            depth -= 1
            if depth == 0:
                return index
        index += 1
    raise AssertionError("unterminated Terraform block")


def _matching_blocks(
    path: Path, pattern: re.Pattern[str]
) -> tuple[tuple[str, ...], ...]:
    source = path.read_text(encoding="utf-8")
    blocks: list[tuple[str, ...]] = []
    for match in pattern.finditer(source):
        opening = match.end() - 1
        closing = _find_closing_brace(source, opening)
        blocks.append((*match.groups(), source[opening + 1 : closing]))
    return tuple(blocks)


def _resources() -> tuple[_Resource, ...]:
    return tuple(
        _Resource(path, resource_type, name, body)
        for path in _terraform_files()
        for resource_type, name, body in _matching_blocks(path, _RESOURCE_HEADER)
    )


def _named_block(path: Path, kind: str, name: str) -> str:
    pattern = re.compile(
        rf'(?m)^[ \t]*{re.escape(kind)}[ \t]+"{re.escape(name)}"[ \t]*\{{'
    )
    blocks = _matching_blocks(path, pattern)
    assert len(blocks) == 1
    return blocks[0][-1]


def _attribute(body: str, name: str) -> str:
    match = re.search(rf"(?m)^[ \t]*{re.escape(name)}[ \t]*=[ \t]*([^\n#]+)", body)
    assert match is not None, name
    return match.group(1).strip()


def test_three_stacks_have_separate_pinned_backends() -> None:
    files = _terraform_files()

    assert files
    assert {path.parent for path in files} == set(_STACKS)
    for stack in _STACKS:
        versions = (stack / "versions.tf").read_text(encoding="utf-8")
        assert 'required_version = "= 1.15.8"' in versions
        assert 'version = "= 7.44.0"' in versions

    bootstrap = (_STACKS[0] / "versions.tf").read_text(encoding="utf-8")
    foundation = (_STACKS[1] / "versions.tf").read_text(encoding="utf-8")
    runtime = (_STACKS[2] / "versions.tf").read_text(encoding="utf-8")
    assert re.findall(r'backend\s+"([^"]+)"', bootstrap) == ["local"]
    assert re.findall(r'backend\s+"([^"]+)"', foundation) == ["gcs"]
    assert re.findall(r'backend\s+"([^"]+)"', runtime) == ["gcs"]
    assert 'prefix = "phase5/foundation"' in foundation
    assert 'prefix = "phase5/runtime"' in runtime


def test_resources_and_apis_are_restricted_to_the_frozen_allowlists() -> None:
    resources = _resources()
    services_source = (_STACKS[1] / "locals.tf").read_text(encoding="utf-8")
    services = set(re.findall(r'"([a-z0-9.-]+[.]googleapis[.]com)"', services_source))

    assert {resource.resource_type for resource in resources} == (
        _ALLOWED_RESOURCE_TYPES
    )
    assert services == _REQUIRED_SERVICES

    project_services = [
        resource
        for resource in resources
        if resource.resource_type == "google_project_service"
    ]
    assert len(project_services) == 1
    assert _attribute(project_services[0].body, "disable_on_destroy") == "false"
    assert _attribute(project_services[0].body, "disable_dependent_services") == (
        "false"
    )


def test_public_principals_and_secret_values_are_absent() -> None:
    source = "\n".join(path.read_text(encoding="utf-8") for path in _terraform_files())
    lowered = source.lower()
    invokers = _named_block(
        _STACKS[2] / "variables.tf", "variable", "api_invoker_members"
    )
    run_resources = {
        resource.name: resource
        for resource in _resources()
        if resource.resource_type == "google_cloud_run_v2_service"
    }

    assert "allusers" not in lowered
    assert "allauthenticatedusers" not in lowered
    assert not tuple(_INFRA.rglob("*.tfvars"))
    assert "google_secret_manager_secret_version" not in lowered
    assert "-----begin private key-----" not in lowered
    assert (
        re.search(
            r"(?mi)^\s*(?:secret_data|plaintext|password|private_key|access_token|api_key)\s*=",
            source,
        )
        is None
    )
    assert '"user:eddyphilochola13@gmail.com"' in invokers
    assert "var.api_invoker_members == toset" in invokers
    assert set(run_resources) == _CLOUD_RUN_SERVICES
    for resource in run_resources.values():
        assert _attribute(resource.body, "invoker_iam_disabled") == "false"

    iam_resources = [
        resource
        for resource in _resources()
        if resource.resource_type.endswith("_iam_member")
    ]
    for resource in iam_resources:
        member = _attribute(resource.body, "member")
        if resource.name == "api_owner":
            assert member == "each.value"
        else:
            assert member.startswith('"serviceAccount:')


def test_cloud_run_images_are_digest_pinned_and_bounded() -> None:
    variables = _STACKS[2] / "variables.tf"
    image_variable = _named_block(variables, "variable", "image_references")
    run_resources = {
        resource.name: resource
        for resource in _resources()
        if resource.resource_type == "google_cloud_run_v2_service"
    }

    assert "reconcile@sha256:[0-9a-f]{64}$" in image_variable
    assert "length(toset(values(var.image_references))) <= 2" in image_variable
    assert set(run_resources) == _CLOUD_RUN_SERVICES
    for name, resource in run_resources.items():
        assert _attribute(resource.body, "image") == f"var.image_references.{name}"
        assert len(re.findall(r"(?m)^\s*image\s*=", resource.body)) == 1


def test_cloud_run_capacity_is_frozen_to_single_zero_minimum_instances() -> None:
    run_resources = [
        resource
        for resource in _resources()
        if resource.resource_type == "google_cloud_run_v2_service"
    ]

    assert {resource.name for resource in run_resources} == _CLOUD_RUN_SERVICES
    for resource in run_resources:
        assert _attribute(resource.body, "max_instance_request_concurrency") == "1"
        assert _attribute(resource.body, "min_instance_count") == "0"
        assert _attribute(resource.body, "max_instance_count") == "1"


def test_budget_is_fixed_to_five_us_dollars_without_credits() -> None:
    variables = _STACKS[1] / "variables.tf"
    budget_variable = _named_block(variables, "variable", "budget_amount_usd")
    budgets = [
        resource
        for resource in _resources()
        if resource.resource_type == "google_billing_budget"
    ]

    assert len(budgets) == 1
    budget = budgets[0]
    assert _attribute(budget_variable, "default") == "5"
    assert "var.budget_amount_usd == 5" in budget_variable
    assert _attribute(budget.body, "currency_code") == '"USD"'
    assert _attribute(budget.body, "units") == "tostring(var.budget_amount_usd)"
    assert _attribute(budget.body, "credit_types_treatment") == (
        '"EXCLUDE_ALL_CREDITS"'
    )


def test_only_the_disposable_target_bucket_has_destructive_defaults() -> None:
    buckets = {
        resource.name: resource
        for resource in _resources()
        if resource.resource_type == "google_storage_bucket"
    }
    destroy_variable = _named_block(
        _STACKS[0] / "variables.tf", "variable", "allow_state_bucket_destroy"
    )

    assert set(buckets) == {"target", "terraform_state"}
    assert _attribute(buckets["target"].body, "force_destroy") == "true"
    assert _attribute(buckets["target"].body, "retention_duration_seconds") == "0"
    assert _attribute(buckets["terraform_state"].body, "force_destroy") == (
        "var.allow_state_bucket_destroy"
    )
    assert _attribute(destroy_variable, "default") == "false"
    assert (
        _attribute(buckets["terraform_state"].body, "retention_duration_seconds") == "0"
    )


def test_every_project_level_database_role_is_resource_conditioned() -> None:
    database_roles = {
        resource.name: resource
        for resource in _resources()
        if resource.resource_type == "google_project_iam_member"
        and _attribute(resource.body, "role").startswith('"roles/datastore.')
    }
    expected_databases = {
        "runtime_database_user": "local.runtime_database_name",
        "target_database_user": "local.target_database_name",
        "target_database_viewer": "local.target_database_name",
    }

    assert set(database_roles) == set(expected_databases)
    for name, database in expected_databases.items():
        body = database_roles[name].body
        assert re.search(r"(?m)^\s*condition\s*\{", body) is not None
        assert f'/databases/${{{database}}}\\""' in _attribute(body, "expression")
