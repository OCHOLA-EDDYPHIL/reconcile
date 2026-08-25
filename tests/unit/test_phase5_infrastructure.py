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
_CLOUD_RUN_SERVICES = {"api", "canary", "controller", "fault_proxy", "sandbox"}
_BOOTSTRAP_SERVICES = {
    "cloudbilling.googleapis.com",
    "cloudresourcemanager.googleapis.com",
    "iam.googleapis.com",
    "iamcredentials.googleapis.com",
    "serviceusage.googleapis.com",
    "storage.googleapis.com",
}
_FOUNDATION_SERVICES = {
    "aiplatform.googleapis.com",
    "artifactregistry.googleapis.com",
    "billingbudgets.googleapis.com",
    "firestore.googleapis.com",
    "logging.googleapis.com",
    "run.googleapis.com",
}
_EXPECTED_RESOURCE_BLOCKS = {
    ("google_artifact_registry_repository", "runtime"),
    (
        "google_artifact_registry_repository_iam_member",
        "canary_mutator_image_reader",
    ),
    ("google_billing_account_iam_member", "phase5_apply"),
    ("google_billing_budget", "phase5"),
    ("google_cloud_run_v2_service", "api"),
    ("google_cloud_run_v2_service", "canary"),
    ("google_cloud_run_v2_service", "controller"),
    ("google_cloud_run_v2_service", "fault_proxy"),
    ("google_cloud_run_v2_service", "sandbox"),
    ("google_cloud_run_v2_service_iam_member", "api_operator"),
    ("google_cloud_run_v2_service_iam_member", "canary_mutator"),
    ("google_cloud_run_v2_service_iam_member", "canary_invoker"),
    ("google_cloud_run_v2_service_iam_member", "canary_reader"),
    ("google_cloud_run_v2_service_iam_member", "internal"),
    ("google_firestore_database", "phase5"),
    ("google_project_iam_member", "phase5_apply"),
    ("google_project_iam_member", "canary_operation_reader"),
    ("google_project_iam_member", "canary_revision_reader"),
    ("google_project_iam_member", "runtime_database_user"),
    ("google_project_iam_member", "runtime_database_viewer"),
    ("google_project_iam_member", "sandbox_database_user"),
    ("google_project_iam_member", "target_database_user"),
    ("google_project_iam_member", "target_database_viewer"),
    ("google_project_iam_member", "vertex_user"),
    ("google_project_iam_custom_role", "canary_operation_reader"),
    ("google_project_iam_custom_role", "canary_revision_reader"),
    ("google_project_iam_custom_role", "canary_mutator"),
    ("google_project_service", "bootstrap_required"),
    ("google_project_service", "required"),
    ("google_service_account", "phase5_apply"),
    ("google_service_account", "runtime"),
    ("google_service_account_iam_member", "apply_act_as"),
    ("google_service_account_iam_member", "canary_mutator_act_as"),
    ("google_service_account_iam_member", "owner_impersonation"),
    ("google_storage_bucket", "target"),
    ("google_storage_bucket", "terraform_state"),
    ("google_storage_bucket_iam_member", "target_mutator"),
    ("google_storage_bucket_iam_member", "target_viewer"),
    ("terraform_data", "canary_baseline"),
}
_APPLY_PROJECT_ROLES = {
    "roles/artifactregistry.admin",
    "roles/datastore.owner",
    "roles/iam.serviceAccountAdmin",
    "roles/logging.viewer",
    "roles/resourcemanager.projectIamAdmin",
    "roles/run.admin",
    "roles/serviceusage.serviceUsageAdmin",
    "roles/storage.admin",
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


def _compact(source: str) -> str:
    return " ".join(source.split())


def test_three_stacks_have_separate_pinned_backends() -> None:
    files = _terraform_files()

    assert files
    assert {path.parent for path in files} == set(_STACKS)
    for stack in _STACKS:
        terraform_blocks = _matching_blocks(
            stack / "versions.tf", re.compile(r"(?m)^\s*terraform\s*\{")
        )
        assert len(terraform_blocks) == 1
        assert _attribute(terraform_blocks[0][-1], "required_version") == ('"= 1.15.8"')
        assert _attribute(terraform_blocks[0][-1], "version") == '"= 7.44.0"'
        lock_blocks = _matching_blocks(
            stack / ".terraform.lock.hcl",
            re.compile(
                r'(?m)^\s*provider\s+"registry[.]terraform[.]io/hashicorp/google"\s*\{'
            ),
        )
        assert len(lock_blocks) == 1
        assert _attribute(lock_blocks[0][-1], "version") == '"7.44.0"'
        assert _attribute(lock_blocks[0][-1], "constraints") == '"7.44.0"'

    bootstrap_path = _STACKS[0] / "versions.tf"
    bootstrap = bootstrap_path.read_text(encoding="utf-8")
    foundation = (_STACKS[1] / "versions.tf").read_text(encoding="utf-8")
    runtime = (_STACKS[2] / "versions.tf").read_text(encoding="utf-8")
    assert re.findall(r'backend\s+"([^"]+)"', bootstrap) == ["local"]
    assert re.findall(r'backend\s+"([^"]+)"', foundation) == ["gcs"]
    assert re.findall(r'backend\s+"([^"]+)"', runtime) == ["gcs"]
    bootstrap_backend = _matching_blocks(
        bootstrap_path, re.compile(r'(?m)^\s*backend\s+"local"\s*\{')
    )
    assert len(bootstrap_backend) == 1
    assert set(re.findall(r"(?m)^\s*([a-z_]+)\s*=", bootstrap_backend[0][-1])) == {
        "path"
    }
    assert _attribute(bootstrap_backend[0][-1], "path") == '"terraform.tfstate"'
    for path, prefix in (
        (_STACKS[1] / "versions.tf", "phase5/foundation"),
        (_STACKS[2] / "versions.tf", "phase5/runtime"),
    ):
        backend = _matching_blocks(path, re.compile(r'(?m)^\s*backend\s+"gcs"\s*\{'))
        assert len(backend) == 1
        assignments = set(re.findall(r"(?m)^\s*([a-z_]+)\s*=", backend[0][-1]))
        assert assignments == {"bucket", "impersonate_service_account", "prefix"}
        assert _attribute(backend[0][-1], "bucket") == (
            '"reconcile-dev-260813-14fa6d-p5-state"'
        )
        assert _attribute(backend[0][-1], "prefix") == f'"{prefix}"'
        assert _attribute(backend[0][-1], "impersonate_service_account") == (
            '"rec-p5-apply@reconcile-dev-260813-14fa6d.iam.gserviceaccount.com"'
        )
    assert re.search(r'prefix\s*=\s*"phase5/foundation"', foundation) is not None
    assert re.search(r'prefix\s*=\s*"phase5/runtime"', runtime) is not None

    bootstrap_provider = _named_block(_STACKS[0] / "providers.tf", "provider", "google")
    assert set(re.findall(r"(?m)^\s*([a-z_]+)\s*=", bootstrap_provider)) == {
        "project",
        "region",
    }

    for stack in _STACKS[1:]:
        provider_path = stack / "providers.tf"
        provider_block = _named_block(provider_path, "provider", "google")
        assignments = set(re.findall(r"(?m)^\s*([a-z_]+)\s*=", provider_block))
        assert assignments == {"impersonate_service_account", "project", "region"}
        assert _attribute(provider_block, "impersonate_service_account") == (
            '"rec-p5-apply@reconcile-dev-260813-14fa6d.iam.gserviceaccount.com"'
        )


def test_resources_and_apis_are_restricted_to_the_frozen_allowlists() -> None:
    resources = _resources()
    bootstrap_services_source = (_STACKS[0] / "apis.tf").read_text(encoding="utf-8")
    foundation_services_source = (_STACKS[1] / "locals.tf").read_text(encoding="utf-8")
    bootstrap_services = set(
        re.findall(r'"([a-z0-9.-]+[.]googleapis[.]com)"', bootstrap_services_source)
    )
    foundation_services = set(
        re.findall(r'"([a-z0-9.-]+[.]googleapis[.]com)"', foundation_services_source)
    )

    assert {(resource.resource_type, resource.name) for resource in resources} == (
        _EXPECTED_RESOURCE_BLOCKS
    )
    assert len(resources) == len(_EXPECTED_RESOURCE_BLOCKS)
    assert bootstrap_services == _BOOTSTRAP_SERVICES
    assert foundation_services == _FOUNDATION_SERVICES
    assert bootstrap_services.isdisjoint(foundation_services)

    project_services = [
        resource
        for resource in resources
        if resource.resource_type == "google_project_service"
    ]
    assert len(project_services) == 2
    for project_service in project_services:
        assert _attribute(project_service.body, "disable_on_destroy") == "false"
        assert _attribute(project_service.body, "disable_dependent_services") == (
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
    assert not tuple(_INFRA.rglob("*.tf.json"))
    assert not tuple(_INFRA.rglob("*.tfvars*"))
    assert not any(path.is_symlink() for path in _terraform_files())
    assert "google_secret_manager_secret_version" not in lowered
    assert not any(marker in source for marker in ("#", "//", "/*", "*/", "<<"))
    assert re.search(r'(?m)^\s*(?:data|module)\s+"', source) is None
    assert re.search(r'(?m)^\s*provisioner\s+"', source) is None
    assert "-----begin private key-----" not in lowered
    assert (
        re.search(
            r"(?mi)^\s*(?:secret|secret_data|plaintext|password|private_key|access_token|api_key|credentials?)\s*=",
            source,
        )
        is None
    )
    assert (
        '"serviceAccount:rec-p5-apply@reconcile-dev-260813-14fa6d.iam.gserviceaccount.com"'
        in invokers
    )
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
        if resource.name == "api_operator":
            assert member == "each.value"
        elif resource.name == "owner_impersonation":
            assert member == "var.owner_principal"
        elif resource.name == "phase5_apply":
            assert member == "google_service_account.phase5_apply.member"
        else:
            assert member.startswith('"serviceAccount:')


def test_cloud_run_images_are_digest_pinned_and_bounded() -> None:
    variables = _STACKS[2] / "variables.tf"
    image_variable = _named_block(variables, "variable", "image_digest")
    locals_source = (_STACKS[2] / "locals.tf").read_text(encoding="utf-8")
    run_resources = {
        resource.name: resource
        for resource in _resources()
        if resource.resource_type == "google_cloud_run_v2_service"
    }

    assert "^sha256:[0-9a-f]{64}$" in image_variable
    assert "image_references" not in variables.read_text(encoding="utf-8")
    assert locals_source.count("reconcile-p5/reconcile@${var.image_digest}") == 1
    assert set(run_resources) == _CLOUD_RUN_SERVICES
    for resource in run_resources.values():
        assert _attribute(resource.body, "image") == "local.image_reference"
        assert len(re.findall(r"(?m)^\s*image\s*=", resource.body)) == 1


def test_cloud_run_audiences_and_candidate_environment_are_closed_world() -> None:
    run_resources = {
        resource.name: resource
        for resource in _resources()
        if resource.resource_type == "google_cloud_run_v2_service"
    }
    source = (_STACKS[2] / "cloud_run.tf").read_text(encoding="utf-8")
    locals_source = (_STACKS[2] / "locals.tf").read_text(encoding="utf-8")

    assert set(run_resources) == _CLOUD_RUN_SERVICES
    for name, resource in run_resources.items():
        assert _attribute(resource.body, "custom_audiences") == (
            f"[local.audiences.{name}]"
        )
    for name in (
        "GOOGLE_CLOUD_PROJECT",
        "RECONCILE_IMAGE_DIGEST",
        "RECONCILE_INFRA_REVISION",
        "RECONCILE_SEMANTIC_CONFIG_SHA256",
        "RECONCILE_SOURCE_REVISION",
    ):
        assert locals_source.count(f"{name}") == 1
    for name in (
        "RECONCILE_VERTEX_MAX_COUNT_TOKENS_ATTEMPTS",
        "RECONCILE_VERTEX_MAX_GENERATION_ATTEMPTS",
        "RECONCILE_VERTEX_MAX_INPUT_TOKENS",
        "RECONCILE_VERTEX_MAX_OUTPUT_TOKENS",
        "RECONCILE_VERTEX_PROMPT_SHA256",
        "RECONCILE_VERTEX_PROMPT_VERSION",
    ):
        assert source.count(name) == 1
    assert source.count("RECONCILE_TARGET_DATABASE") == 3
    assert source.count("local.sandbox_database_name") == 1
    assert source.count("local.target_database_name") == 2
    assert 'sandbox_database_name = "reconcile-p5-sandbox"' in locals_source


def test_runtime_commands_are_owned_by_the_pinned_images() -> None:
    source = (_STACKS[2] / "cloud_run.tf").read_text(encoding="utf-8")
    variables = (_STACKS[2] / "variables.tf").read_text(encoding="utf-8")
    resources = {
        resource.name: resource
        for resource in _resources()
        if resource.resource_type == "google_cloud_run_v2_service"
    }

    assert "container_args" not in variables
    assert len(re.findall(r"(?m)^\s*(?:args|command)\s*=", source)) == 2
    assert _attribute(resources["canary"].body, "command") == (
        '["/opt/reconcile/bin/python"]'
    )
    assert _attribute(resources["canary"].body, "args") == (
        '["-m", "reconcile.hosted.cloud_run_canary"]'
    )
    for name in _CLOUD_RUN_SERVICES - {"canary"}:
        assert re.search(r"(?m)^\s*(?:args|command)\s*=", resources[name].body) is None


def test_canary_runtime_drift_and_baseline_rotation_are_explicit() -> None:
    cloud_run = (_STACKS[2] / "cloud_run.tf").read_text(encoding="utf-8")
    locals_source = (_STACKS[2] / "locals.tf").read_text(encoding="utf-8")
    invocation_iam = (_STACKS[2] / "invocation_iam.tf").read_text(encoding="utf-8")
    resources = {
        (resource.resource_type, resource.name): resource for resource in _resources()
    }
    canary = resources[("google_cloud_run_v2_service", "canary")].body
    trigger = resources[("terraform_data", "canary_baseline")].body

    for template_input in (
        "var.image_digest",
        "var.infrastructure_revision",
        "var.project_id",
        "var.region",
        "var.request_timeout_seconds.canary",
        "var.semantic_config_sha256",
        "var.service_account_emails.canary",
        "var.source_revision",
    ):
        assert template_input in locals_source
    assert (
        'canary_baseline_revision = "reconcile-p5-canary-b-'
        '${substr(local.canary_baseline_identity, 0, 16)}"'
    ) in locals_source
    assert _attribute(trigger, "triggers_replace") == ("local.canary_baseline_identity")
    assert (
        len(
            re.findall(
                r"(?m)^\s*revision\s*=\s*local[.]canary_baseline_revision$",
                canary,
            )
        )
        == 2
    )
    assert "ignore_changes       = [template, traffic]" in canary
    assert "replace_triggered_by = [terraform_data.canary_baseline]" in canary
    assert (
        invocation_iam.count("replace_triggered_by = [terraform_data.canary_baseline]")
        == 3
    )
    assert (
        len(
            re.findall(
                r"RECONCILE_CANARY_BASELINE_REVISION\s*=\s*local[.]canary_baseline_revision",
                cloud_run,
            )
        )
        == 2
    )


def test_artifact_registry_uses_immutable_tags_without_claiming_a_maximum() -> None:
    repositories = [
        resource
        for resource in _resources()
        if resource.resource_type == "google_artifact_registry_repository"
    ]

    assert len(repositories) == 1
    repository = repositories[0]
    assert _attribute(repository.body, "immutable_tags") == "true"
    assert 'id     = "keep-at-least-two-recent"' in repository.body
    assert 'id     = "keep-two-recent"' not in repository.body


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


def test_firestore_database_inventory_separates_runtime_sandbox_and_target() -> None:
    databases = [
        resource
        for resource in _resources()
        if resource.resource_type == "google_firestore_database"
    ]
    foundation_locals = _compact((_STACKS[1] / "locals.tf").read_text(encoding="utf-8"))

    assert len(databases) == 1
    compact = _compact(databases[0].body)
    assert "runtime = local.runtime_database_name" in compact
    assert "sandbox = local.sandbox_database_name" in compact
    assert "target = local.target_database_name" in compact
    assert 'runtime_database_name = "reconcile-p5-runtime"' in foundation_locals
    assert 'sandbox_database_name = "reconcile-p5-sandbox"' in foundation_locals
    assert 'target_database_name = "reconcile-p5-target"' in foundation_locals


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
    assert _attribute(buckets["terraform_state"].body, "deletion_policy") == (
        'var.allow_state_bucket_destroy ? "DELETE" : "PREVENT"'
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
        "runtime_database_viewer": "local.runtime_database_name",
        "sandbox_database_user": "local.sandbox_database_name",
        "target_database_user": "local.target_database_name",
        "target_database_viewer": "local.target_database_name",
    }

    assert set(database_roles) == set(expected_databases)
    for name, database in expected_databases.items():
        body = database_roles[name].body
        assert re.search(r"(?m)^\s*condition\s*\{", body) is not None
        assert f'/databases/${{{database}}}\\""' in _attribute(body, "expression")


def test_apply_identity_and_runtime_iam_graph_are_closed_world() -> None:
    resources = _resources()
    project_iam = {
        resource.name: resource
        for resource in resources
        if resource.resource_type == "google_project_iam_member"
    }
    bucket_iam = {
        resource.name: resource
        for resource in resources
        if resource.resource_type == "google_storage_bucket_iam_member"
    }
    service_account_iam = {
        resource.name: resource
        for resource in resources
        if resource.resource_type == "google_service_account_iam_member"
    }
    run_iam = {
        resource.name: resource
        for resource in resources
        if resource.resource_type == "google_cloud_run_v2_service_iam_member"
    }
    artifact_iam = {
        resource.name: resource
        for resource in resources
        if resource.resource_type == "google_artifact_registry_repository_iam_member"
    }
    custom_roles = {
        resource.name: resource
        for resource in resources
        if resource.resource_type == "google_project_iam_custom_role"
    }

    assert set(project_iam) == {
        "phase5_apply",
        "canary_operation_reader",
        "canary_revision_reader",
        "runtime_database_user",
        "runtime_database_viewer",
        "sandbox_database_user",
        "target_database_user",
        "target_database_viewer",
        "vertex_user",
    }
    apply_source = (_STACKS[0] / "apply_identity.tf").read_text(encoding="utf-8")
    apply_locals = _matching_blocks(
        _STACKS[0] / "apply_identity.tf", re.compile(r"(?m)^locals\s*\{")
    )
    assert len(apply_locals) == 1
    assert set(re.findall(r'"(roles/[A-Za-z.]+)"', apply_locals[0][-1])) == (
        _APPLY_PROJECT_ROLES
    )
    assert _attribute(project_iam["phase5_apply"].body, "for_each") == (
        "local.apply_project_roles"
    )
    assert _attribute(project_iam["phase5_apply"].body, "role") == "each.value"
    assert _attribute(project_iam["phase5_apply"].body, "member") == (
        "google_service_account.phase5_apply.member"
    )
    assert "roles/owner" not in apply_source
    assert "roles/editor" not in apply_source

    expected_project_bindings = {
        "runtime_database_user": (
            '"roles/datastore.user"',
            '"serviceAccount:${google_service_account.runtime[each.value].email}"',
            'toset(["api", "controller", "fault_proxy"])',
        ),
        "runtime_database_viewer": (
            '"roles/datastore.viewer"',
            '"serviceAccount:${google_service_account.runtime[each.value].email}"',
            'toset(["sandbox"])',
        ),
        "sandbox_database_user": (
            '"roles/datastore.user"',
            '"serviceAccount:${google_service_account.runtime["sandbox"].email}"',
            None,
        ),
        "target_database_user": (
            '"roles/datastore.user"',
            '"serviceAccount:${google_service_account.runtime[each.value].email}"',
            'toset(["fault_proxy"])',
        ),
        "target_database_viewer": (
            '"roles/datastore.viewer"',
            '"serviceAccount:${google_service_account.runtime["controller"].email}"',
            None,
        ),
        "vertex_user": (
            '"roles/aiplatform.user"',
            '"serviceAccount:${google_service_account.runtime["controller"].email}"',
            None,
        ),
        "canary_operation_reader": (
            '"projects/${var.project_id}/roles/reconcileP5CanaryOperationReader"',
            '"serviceAccount:${var.service_account_emails.controller}"',
            None,
        ),
        "canary_revision_reader": (
            '"projects/${var.project_id}/roles/reconcileP5CanaryRevisionReader"',
            '"serviceAccount:${var.service_account_emails.fault_proxy}"',
            None,
        ),
    }
    for name, (role, member, for_each) in expected_project_bindings.items():
        body = project_iam[name].body
        assert _attribute(body, "role") == role
        assert _attribute(body, "member") == member
        if for_each is None:
            assert re.search(r"(?m)^\s*for_each\s*=", body) is None
        else:
            assert _attribute(body, "for_each") == for_each

    operation_reader = project_iam["canary_operation_reader"].body
    assert re.search(r"(?m)^\s*condition\s*\{", operation_reader) is None
    revision_reader_binding = project_iam["canary_revision_reader"].body
    assert re.search(r"(?m)^\s*condition\s*\{", revision_reader_binding) is None

    assert set(custom_roles) == {
        "canary_mutator",
        "canary_operation_reader",
        "canary_revision_reader",
    }
    operation_role = custom_roles["canary_operation_reader"].body
    assert _attribute(operation_role, "role_id") == (
        '"reconcileP5CanaryOperationReader"'
    )
    assert _attribute(operation_role, "permissions") == '["run.operations.get"]'
    assert _attribute(operation_role, "stage") == '"GA"'
    revision_role = custom_roles["canary_revision_reader"].body
    assert _attribute(revision_role, "role_id") == (
        '"reconcileP5CanaryRevisionReader"'
    )
    assert _attribute(revision_role, "permissions") == '["run.revisions.get"]'
    assert _attribute(revision_role, "stage") == '"GA"'
    mutator_role = custom_roles["canary_mutator"].body
    assert _attribute(mutator_role, "role_id") == '"reconcileP5CanaryMutator"'
    assert set(re.findall(r'"(run\.[a-z.]+)"', mutator_role)) == {
        "run.services.get",
        "run.services.update",
    }
    assert _attribute(mutator_role, "stage") == '"GA"'

    assert set(artifact_iam) == {"canary_mutator_image_reader"}
    image_reader = artifact_iam["canary_mutator_image_reader"].body
    assert _attribute(image_reader, "repository") == '"reconcile-p5"'
    assert _attribute(image_reader, "role") == '"roles/artifactregistry.reader"'
    assert _attribute(image_reader, "member") == (
        '"serviceAccount:${var.service_account_emails.fault_proxy}"'
    )

    assert set(bucket_iam) == {"target_mutator", "target_viewer"}
    expected_bucket_bindings = {
        "target_mutator": (
            '"roles/storage.objectUser"',
            '"serviceAccount:${google_service_account.runtime["fault_proxy"].email}"',
        ),
        "target_viewer": (
            '"roles/storage.objectViewer"',
            '"serviceAccount:${google_service_account.runtime["controller"].email}"',
        ),
    }
    for name, (role, member) in expected_bucket_bindings.items():
        body = bucket_iam[name].body
        assert _attribute(body, "bucket") == "google_storage_bucket.target.name"
        assert _attribute(body, "role") == role
        assert _attribute(body, "member") == member

    assert set(service_account_iam) == {
        "apply_act_as",
        "canary_mutator_act_as",
        "owner_impersonation",
    }
    owner = service_account_iam["owner_impersonation"].body
    assert _attribute(owner, "role") == '"roles/iam.serviceAccountTokenCreator"'
    assert _attribute(owner, "member") == "var.owner_principal"
    act_as = service_account_iam["apply_act_as"].body
    assert _attribute(act_as, "for_each") == "local.service_accounts"
    assert _attribute(act_as, "role") == '"roles/iam.serviceAccountUser"'
    assert _attribute(act_as, "member") == (
        '"serviceAccount:rec-p5-apply@reconcile-dev-260813-14fa6d.iam.gserviceaccount.com"'
    )
    canary_act_as = service_account_iam["canary_mutator_act_as"].body
    assert _attribute(canary_act_as, "service_account_id") == (
        '"projects/${var.project_id}/serviceAccounts/${var.service_account_emails.canary}"'
    )
    assert _attribute(canary_act_as, "role") == '"roles/iam.serviceAccountUser"'
    assert _attribute(canary_act_as, "member") == (
        '"serviceAccount:${var.service_account_emails.fault_proxy}"'
    )

    billing_iam = [
        resource
        for resource in resources
        if resource.resource_type == "google_billing_account_iam_member"
    ]
    assert len(billing_iam) == 1
    assert _attribute(billing_iam[0].body, "role") == '"roles/billing.costsManager"'
    assert _attribute(billing_iam[0].body, "member") == (
        "google_service_account.phase5_apply.member"
    )

    assert set(run_iam) == {
        "api_operator",
        "canary_invoker",
        "canary_mutator",
        "canary_reader",
        "internal",
    }
    api_operator = run_iam["api_operator"].body
    assert _attribute(api_operator, "for_each") == "var.api_invoker_members"
    assert _attribute(api_operator, "name") == "google_cloud_run_v2_service.api.name"
    assert _attribute(api_operator, "role") == '"roles/run.invoker"'
    assert _attribute(api_operator, "member") == "each.value"
    internal = run_iam["internal"].body
    assert _attribute(internal, "for_each") == "local.internal_invocations"
    assert _attribute(internal, "name") == "each.value.service"
    assert _attribute(internal, "role") == '"roles/run.invoker"'
    assert _attribute(internal, "member") == ('"serviceAccount:${each.value.member}"')
    assert _attribute(run_iam["canary_reader"].body, "role") == '"roles/run.viewer"'
    assert _attribute(run_iam["canary_reader"].body, "member") == (
        '"serviceAccount:${var.service_account_emails.controller}"'
    )
    assert _attribute(run_iam["canary_mutator"].body, "role") == (
        '"projects/${var.project_id}/roles/reconcileP5CanaryMutator"'
    )
    assert _attribute(run_iam["canary_mutator"].body, "member") == (
        '"serviceAccount:${var.service_account_emails.fault_proxy}"'
    )
    assert _attribute(run_iam["canary_invoker"].body, "role") == ('"roles/run.invoker"')
    assert _attribute(run_iam["canary_invoker"].body, "member") == (
        '"serviceAccount:${var.service_account_emails.controller}"'
    )

    invocation_locals = _matching_blocks(
        _STACKS[2] / "invocation_iam.tf", re.compile(r"(?m)^locals\s*\{")
    )
    assert len(invocation_locals) == 1
    expected_invocations = """
        internal_invocations = {
          api_to_controller = {
            service = google_cloud_run_v2_service.controller.name
            member  = var.service_account_emails.api
          }
          api_to_fault_proxy = {
            service = google_cloud_run_v2_service.fault_proxy.name
            member  = var.service_account_emails.api
          }
          controller_to_fault_proxy = {
            service = google_cloud_run_v2_service.fault_proxy.name
            member  = var.service_account_emails.controller
          }
          controller_to_sandbox = {
            service = google_cloud_run_v2_service.sandbox.name
            member  = var.service_account_emails.controller
          }
          fault_proxy_to_sandbox = {
            service = google_cloud_run_v2_service.sandbox.name
            member  = var.service_account_emails.fault_proxy
          }
        }
    """
    assert _compact(invocation_locals[0][-1]) == _compact(expected_invocations)


def test_every_label_capable_resource_has_phase5_labels() -> None:
    label_capable_types = {
        "google_artifact_registry_repository",
        "google_cloud_run_v2_service",
        "google_storage_bucket",
    }
    resources = [
        resource
        for resource in _resources()
        if resource.resource_type in label_capable_types
    ]

    assert len(resources) == 8
    for resource in resources:
        assert re.search(r"(?m)^\s*labels\s*=", resource.body) is not None


def test_outputs_are_closed_world_and_non_sensitive() -> None:
    expected = {
        _STACKS[0] / "outputs.tf": {
            "apply_service_account_email": (
                "value = google_service_account.phase5_apply.email"
            ),
            "state_bucket_name": ("value = google_storage_bucket.terraform_state.name"),
        },
        _STACKS[1] / "outputs.tf": {
            "artifact_repository_url": (
                'value = "${var.region}-docker.pkg.dev/${var.project_id}/'
                '${google_artifact_registry_repository.runtime.repository_id}"'
            ),
            "firestore_databases": (
                'value = { runtime = google_firestore_database.phase5["runtime"].name '
                'sandbox = google_firestore_database.phase5["sandbox"].name '
                'target = google_firestore_database.phase5["target"].name }'
            ),
            "service_account_emails": (
                "value = { for name, account in google_service_account.runtime : "
                "name => account.email }"
            ),
            "target_bucket_name": "value = google_storage_bucket.target.name",
        },
        _STACKS[2] / "outputs.tf": {
            "api_uri": "value = google_cloud_run_v2_service.api.uri",
            "canary_uri": "value = google_cloud_run_v2_service.canary.uri",
        },
    }

    for path, expected_outputs in expected.items():
        outputs = {
            name: body
            for name, body in _matching_blocks(
                path, re.compile(r'(?m)^\s*output\s+"([^"]+)"\s*\{')
            )
        }
        assert set(outputs) == set(expected_outputs)
        for name, body in outputs.items():
            assert _compact(body) == _compact(expected_outputs[name])
