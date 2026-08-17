from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any

_ROOT = Path(__file__).parents[1]
_PROJECT = "reconcile-dev-260813-14fa6d"
_PROJECT_NUMBER = "669727977920"
_REGION = "us-central1"
_STATE_BUCKET = f"{_PROJECT}-p5-state"
_TARGET_BUCKET = f"{_PROJECT}-p5-target"
_OWNER = "user:eddyphilochola13@gmail.com"
_APPLY_EMAIL = f"rec-p5-apply@{_PROJECT}.iam.gserviceaccount.com"
_APPLY_MEMBER = f"serviceAccount:{_APPLY_EMAIL}"
_PROVIDER = "registry.terraform.io/hashicorp/google"
_DIGEST = "0" * 64
_RUNTIME_EMAILS = {
    "api": f"rec-p5-api@{_PROJECT}.iam.gserviceaccount.com",
    "controller": f"rec-p5-controller@{_PROJECT}.iam.gserviceaccount.com",
    "fault_proxy": f"rec-p5-fault@{_PROJECT}.iam.gserviceaccount.com",
    "sandbox": f"rec-p5-sandbox@{_PROJECT}.iam.gserviceaccount.com",
}
_RUNTIME_ENVIRONMENT = {
    "api": {
        "GOOGLE_CLOUD_PROJECT": _PROJECT,
        "RECONCILE_COMPONENT": "api",
        "RECONCILE_CONTROLLER_URL": None,
        "RECONCILE_FAULT_PROXY_URL": None,
        "RECONCILE_RUNTIME_DATABASE": "reconcile-p5-runtime",
    },
    "controller": {
        "GOOGLE_CLOUD_PROJECT": _PROJECT,
        "RECONCILE_COMPONENT": "controller",
        "RECONCILE_RUNTIME_DATABASE": "reconcile-p5-runtime",
        "RECONCILE_SANDBOX_URL": None,
        "RECONCILE_TARGET_BUCKET": _TARGET_BUCKET,
        "RECONCILE_TARGET_DATABASE": "reconcile-p5-target",
        "RECONCILE_VERTEX_LOCATION": "us",
        "RECONCILE_VERTEX_MAX_CALLS": "1",
        "RECONCILE_VERTEX_MAX_INPUT_TOKENS": "12000",
        "RECONCILE_VERTEX_MAX_OUTPUT_TOKENS": "1024",
        "RECONCILE_VERTEX_MODEL": "gemini-3.5-flash",
        "RECONCILE_VERTEX_THINKING_LEVEL": "MINIMAL",
    },
    "fault_proxy": {
        "GOOGLE_CLOUD_PROJECT": _PROJECT,
        "RECONCILE_COMPONENT": "fault-proxy",
        "RECONCILE_SANDBOX_URL": None,
        "RECONCILE_TARGET_BUCKET": _TARGET_BUCKET,
        "RECONCILE_TARGET_DATABASE": "reconcile-p5-target",
    },
    "sandbox": {
        "GOOGLE_CLOUD_PROJECT": _PROJECT,
        "RECONCILE_COMPONENT": "sandbox",
        "RECONCILE_TARGET_DATABASE": "reconcile-p5-target",
    },
}
_APPLY_ROLES = {
    "roles/artifactregistry.admin",
    "roles/datastore.owner",
    "roles/iam.serviceAccountAdmin",
    "roles/resourcemanager.projectIamAdmin",
    "roles/run.admin",
    "roles/serviceusage.serviceUsageAdmin",
    "roles/storage.admin",
}
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
_SECRET_KEY = re.compile(
    r"(?:^|_)(?:secret|password|private_key|access_token|api_key|credentials?)(?:$|_)",
    re.IGNORECASE,
)


@dataclass(frozen=True, slots=True)
class _Stack:
    name: str
    source: Path
    addresses: frozenset[str]
    variables: dict[str, Any]


def _quoted(address: str, keys: set[str]) -> set[str]:
    return {f'{address}["{key}"]' for key in keys}


_BOOTSTRAP_ADDRESSES = frozenset(
    {
        "google_billing_account_iam_member.phase5_apply",
        "google_service_account.phase5_apply",
        "google_service_account_iam_member.owner_impersonation",
        "google_storage_bucket.terraform_state",
        *_quoted("google_project_iam_member.phase5_apply", _APPLY_ROLES),
        *_quoted("google_project_service.bootstrap_required", _BOOTSTRAP_SERVICES),
    }
)
_FOUNDATION_ADDRESSES = frozenset(
    {
        "google_artifact_registry_repository.runtime",
        "google_billing_budget.phase5",
        'google_firestore_database.phase5["runtime"]',
        'google_firestore_database.phase5["target"]',
        'google_project_iam_member.runtime_database_user["api"]',
        'google_project_iam_member.runtime_database_user["controller"]',
        'google_project_iam_member.target_database_user["fault_proxy"]',
        'google_project_iam_member.target_database_user["sandbox"]',
        "google_project_iam_member.target_database_viewer",
        "google_project_iam_member.vertex_user",
        "google_storage_bucket.target",
        "google_storage_bucket_iam_member.target_mutator",
        "google_storage_bucket_iam_member.target_viewer",
        *_quoted("google_project_service.required", _FOUNDATION_SERVICES),
        *_quoted("google_service_account.runtime", set(_RUNTIME_EMAILS)),
        *_quoted(
            "google_service_account_iam_member.apply_act_as", set(_RUNTIME_EMAILS)
        ),
    }
)
_RUNTIME_ADDRESSES = frozenset(
    {
        "google_cloud_run_v2_service.api",
        "google_cloud_run_v2_service.controller",
        "google_cloud_run_v2_service.fault_proxy",
        "google_cloud_run_v2_service.sandbox",
        f'google_cloud_run_v2_service_iam_member.api_owner["{_OWNER}"]',
        'google_cloud_run_v2_service_iam_member.internal["api_to_controller"]',
        'google_cloud_run_v2_service_iam_member.internal["api_to_fault_proxy"]',
        'google_cloud_run_v2_service_iam_member.internal["controller_to_sandbox"]',
        'google_cloud_run_v2_service_iam_member.internal["fault_proxy_to_sandbox"]',
    }
)
_STACKS = (
    _Stack("bootstrap", _ROOT / "infra" / "bootstrap", _BOOTSTRAP_ADDRESSES, {}),
    _Stack(
        "foundation",
        _ROOT / "infra" / "environments" / "dev" / "foundation",
        _FOUNDATION_ADDRESSES,
        {},
    ),
    _Stack(
        "runtime",
        _ROOT / "infra" / "environments" / "dev" / "runtime",
        _RUNTIME_ADDRESSES,
        {
            "api_invoker_members": [_OWNER],
            "image_references": {
                component: (
                    f"{_REGION}-docker.pkg.dev/{_PROJECT}/reconcile-p5/"
                    f"reconcile@sha256:{_DIGEST}"
                )
                for component in _RUNTIME_EMAILS
            },
            "service_account_emails": _RUNTIME_EMAILS,
        },
    ),
)
_VARIABLE_NAMES = {
    "bootstrap": {
        "allow_state_bucket_destroy",
        "billing_account_id",
        "owner_principal",
        "project_id",
        "region",
        "state_bucket_name",
    },
    "foundation": {
        "billing_account_id",
        "budget_amount_usd",
        "project_id",
        "project_number",
        "region",
    },
    "runtime": {
        "api_invoker_members",
        "image_references",
        "project_id",
        "region",
        "request_timeout_seconds",
        "service_account_emails",
        "vertex_location",
        "vertex_model",
    },
}
_OUTPUT_NAMES = {
    "bootstrap": {"apply_service_account_email", "state_bucket_name"},
    "foundation": {
        "artifact_repository_url",
        "firestore_databases",
        "service_account_emails",
        "target_bucket_name",
    },
    "runtime": {"api_uri"},
}


def _iam_expectations() -> dict[str, dict[str, Any]]:
    expected = {
        "google_billing_account_iam_member.phase5_apply": {
            "billing_account_id": "01029C-95939A-70E448",
            "member": _APPLY_MEMBER,
            "role": "roles/billing.costsManager",
        },
        "google_service_account_iam_member.owner_impersonation": {
            "member": _OWNER,
            "role": "roles/iam.serviceAccountTokenCreator",
            "service_account_id": (
                f"projects/{_PROJECT}/serviceAccounts/{_APPLY_EMAIL}"
            ),
        },
        'google_project_iam_member.runtime_database_user["api"]': {
            "member": f"serviceAccount:{_RUNTIME_EMAILS['api']}",
            "project": _PROJECT,
            "role": "roles/datastore.user",
            "condition_expression": (
                f'resource.name == "projects/{_PROJECT}/databases/reconcile-p5-runtime"'
            ),
        },
        'google_project_iam_member.runtime_database_user["controller"]': {
            "member": f"serviceAccount:{_RUNTIME_EMAILS['controller']}",
            "project": _PROJECT,
            "role": "roles/datastore.user",
            "condition_expression": (
                f'resource.name == "projects/{_PROJECT}/databases/reconcile-p5-runtime"'
            ),
        },
        "google_project_iam_member.target_database_viewer": {
            "member": f"serviceAccount:{_RUNTIME_EMAILS['controller']}",
            "project": _PROJECT,
            "role": "roles/datastore.viewer",
            "condition_expression": (
                f'resource.name == "projects/{_PROJECT}/databases/reconcile-p5-target"'
            ),
        },
        'google_project_iam_member.target_database_user["fault_proxy"]': {
            "member": f"serviceAccount:{_RUNTIME_EMAILS['fault_proxy']}",
            "project": _PROJECT,
            "role": "roles/datastore.user",
            "condition_expression": (
                f'resource.name == "projects/{_PROJECT}/databases/reconcile-p5-target"'
            ),
        },
        'google_project_iam_member.target_database_user["sandbox"]': {
            "member": f"serviceAccount:{_RUNTIME_EMAILS['sandbox']}",
            "project": _PROJECT,
            "role": "roles/datastore.user",
            "condition_expression": (
                f'resource.name == "projects/{_PROJECT}/databases/reconcile-p5-target"'
            ),
        },
        "google_project_iam_member.vertex_user": {
            "member": f"serviceAccount:{_RUNTIME_EMAILS['controller']}",
            "project": _PROJECT,
            "role": "roles/aiplatform.user",
        },
        "google_storage_bucket_iam_member.target_mutator": {
            "bucket": _TARGET_BUCKET,
            "member": f"serviceAccount:{_RUNTIME_EMAILS['fault_proxy']}",
            "role": "roles/storage.objectUser",
        },
        "google_storage_bucket_iam_member.target_viewer": {
            "bucket": _TARGET_BUCKET,
            "member": f"serviceAccount:{_RUNTIME_EMAILS['controller']}",
            "role": "roles/storage.objectViewer",
        },
        f'google_cloud_run_v2_service_iam_member.api_owner["{_OWNER}"]': {
            "location": _REGION,
            "member": _OWNER,
            "name": "reconcile-p5-api",
            "project": _PROJECT,
            "role": "roles/run.invoker",
        },
    }
    for role in _APPLY_ROLES:
        expected[f'google_project_iam_member.phase5_apply["{role}"]'] = {
            "member": _APPLY_MEMBER,
            "project": _PROJECT,
            "role": role,
        }
    for component, email in _RUNTIME_EMAILS.items():
        expected[f'google_service_account_iam_member.apply_act_as["{component}"]'] = {
            "member": _APPLY_MEMBER,
            "role": "roles/iam.serviceAccountUser",
            "service_account_id": f"projects/{_PROJECT}/serviceAccounts/{email}",
        }
    invocations = {
        "api_to_controller": ("controller", "api"),
        "api_to_fault_proxy": ("fault-proxy", "api"),
        "controller_to_sandbox": ("sandbox", "controller"),
        "fault_proxy_to_sandbox": ("sandbox", "fault_proxy"),
    }
    for edge, (service, caller) in invocations.items():
        expected[f'google_cloud_run_v2_service_iam_member.internal["{edge}"]'] = {
            "location": _REGION,
            "member": f"serviceAccount:{_RUNTIME_EMAILS[caller]}",
            "name": f"reconcile-p5-{service}",
            "project": _PROJECT,
            "role": "roles/run.invoker",
        }
    return expected


_IAM_EXPECTED = _iam_expectations()


def _fail(message: str) -> None:
    raise ValueError(message)


def _walk(value: Any, path: tuple[str, ...] = ()) -> None:
    if isinstance(value, dict):
        for key, child in value.items():
            if _SECRET_KEY.search(key) and child not in (None, "", [], {}):
                _fail(f"secret-bearing value at {'.'.join((*path, key))}")
            _walk(child, (*path, key))
    elif isinstance(value, list):
        for index, child in enumerate(value):
            _walk(child, (*path, str(index)))
    elif isinstance(value, str) and value.casefold() in {
        "allusers",
        "allauthenticatedusers",
    }:
        _fail(f"public principal at {'.'.join(path)}")


def _contains_true(value: Any) -> bool:
    if isinstance(value, dict):
        return any(_contains_true(child) for child in value.values())
    if isinstance(value, list):
        return any(_contains_true(child) for child in value)
    return value is True


def _resources(plan: dict[str, Any]) -> dict[str, dict[str, Any]]:
    resources = plan.get("resource_changes")
    if not isinstance(resources, list):
        _fail("plan has no resource_changes array")
    indexed: dict[str, dict[str, Any]] = {}
    for resource in resources:
        address = resource.get("address")
        if not isinstance(address, str) or address in indexed:
            _fail("plan has an invalid or duplicate resource address")
        indexed[address] = resource
    return indexed


def _verify_plan_envelope(stack: _Stack, plan: dict[str, Any]) -> None:
    if plan.get("terraform_version") != "1.15.8":
        _fail(f"{stack.name} plan used an unexpected Terraform version")
    variables = plan.get("variables")
    if not isinstance(variables, dict) or set(variables) != _VARIABLE_NAMES[stack.name]:
        _fail(f"{stack.name} variable inventory is not closed-world")
    _walk(variables, (stack.name, "variables"))

    planned_values = plan.get("planned_values")
    if not isinstance(planned_values, dict):
        _fail(f"{stack.name} has no planned_values object")
    outputs = planned_values.get("outputs") or {}
    output_changes = plan.get("output_changes") or {}
    expected_outputs = _OUTPUT_NAMES[stack.name]
    if set(outputs) != expected_outputs or set(output_changes) != expected_outputs:
        _fail(f"{stack.name} output inventory is not closed-world")
    for name, output in outputs.items():
        if output.get("sensitive") is not False:
            _fail(f"{stack.name}.{name} is a sensitive planned output")
        _walk(output.get("value"), (stack.name, "outputs", name))
    for name, output in output_changes.items():
        if _contains_true(output.get("before_sensitive")) or _contains_true(
            output.get("after_sensitive")
        ):
            _fail(f"{stack.name}.{name} has a sensitive output change")
        _walk(output.get("before"), (stack.name, "output_changes", name, "before"))
        _walk(output.get("after"), (stack.name, "output_changes", name, "after"))


def _verify_inventory(stack: _Stack, resources: dict[str, dict[str, Any]]) -> None:
    actual = set(resources)
    if actual != set(stack.addresses):
        missing = sorted(set(stack.addresses) - actual)
        extra = sorted(actual - set(stack.addresses))
        _fail(f"{stack.name} inventory mismatch; missing={missing}; extra={extra}")
    for address, resource in resources.items():
        actions = resource.get("change", {}).get("actions")
        if actions != ["create"]:
            _fail(f"{address} actions are {actions!r}, not create-only")
        if resource.get("provider_name") != _PROVIDER:
            _fail(f"{address} uses an unapproved provider")
        if resource.get("type") != address.split(".", 1)[0]:
            _fail(f"{address} has an inconsistent resource type")
        change = resource["change"]
        if _contains_true(change.get("after_sensitive", {})):
            _fail(f"{address} contains a sensitive planned value")
        _walk(change.get("after", {}), (address,))


def _verify_iam(resources: dict[str, dict[str, Any]]) -> None:
    actual_iam = {
        address
        for address, resource in resources.items()
        if resource["type"].endswith("_iam_member")
    }
    expected_iam = set(resources) & set(_IAM_EXPECTED)
    if actual_iam != expected_iam:
        _fail("IAM inventory is not closed-world")
    for address in actual_iam:
        after = resources[address]["change"]["after"]
        expected = _IAM_EXPECTED[address]
        for key, value in expected.items():
            if key == "condition_expression":
                conditions = after.get("condition")
                actual = (
                    conditions[0].get("expression")
                    if isinstance(conditions, list) and len(conditions) == 1
                    else None
                )
            else:
                actual = after.get(key)
            if actual != value:
                _fail(f"{address} has an unexpected {key}")


def _one_block(after: dict[str, Any], key: str, address: str) -> dict[str, Any]:
    value = after.get(key)
    if not isinstance(value, list) or len(value) != 1 or not isinstance(value[0], dict):
        _fail(f"{address} has an invalid {key} block")
    return value[0]


def _verify_cloud_run(resources: dict[str, dict[str, Any]]) -> None:
    if not any(
        resource["type"] == "google_cloud_run_v2_service"
        for resource in resources.values()
    ):
        return
    images: set[str] = set()
    for component in _RUNTIME_EMAILS:
        address = f"google_cloud_run_v2_service.{component}"
        after = resources[address]["change"]["after"]
        if after.get("project") != _PROJECT or after.get("location") != _REGION:
            _fail(f"{address} escaped the approved project or region")
        if after.get("invoker_iam_disabled") is not False:
            _fail(f"{address} disables invoker IAM")
        if after.get("ingress") != "INGRESS_TRAFFIC_ALL":
            _fail(f"{address} has unexpected ingress")
        template = _one_block(after, "template", address)
        if template.get("service_account") != _RUNTIME_EMAILS[component]:
            _fail(f"{address} has an unexpected runtime identity")
        if template.get("max_instance_request_concurrency") != 1:
            _fail(f"{address} has unexpected concurrency")
        scaling = _one_block(template, "scaling", address)
        if (
            scaling.get("min_instance_count") != 0
            or scaling.get("max_instance_count") != 1
        ):
            _fail(f"{address} has unbounded scaling")
        container = _one_block(template, "containers", address)
        image = container.get("image")
        pattern = (
            rf"^{re.escape(_REGION)}-docker[.]pkg[.]dev/{re.escape(_PROJECT)}/"
            rf"reconcile-p5/reconcile@sha256:[0-9a-f]{{64}}$"
        )
        if not isinstance(image, str) or re.fullmatch(pattern, image) is None:
            _fail(f"{address} has a mutable or external image")
        images.add(image)
        if container.get("args") not in (None, []) or container.get("command") not in (
            None,
            [],
        ):
            _fail(f"{address} overrides its image-owned command")
        environments = container.get("env") or []
        environment_by_name = {
            environment.get("name"): environment for environment in environments
        }
        if len(environment_by_name) != len(environments) or set(
            environment_by_name
        ) != set(_RUNTIME_ENVIRONMENT[component]):
            _fail(f"{address} has an unexpected environment contract")
        for name, environment in environment_by_name.items():
            name = environment.get("name")
            if not isinstance(name, str) or _SECRET_KEY.search(name):
                _fail(f"{address} has a secret-bearing environment name")
            expected_value = _RUNTIME_ENVIRONMENT[component][name]
            actual_value = environment.get("value")
            if expected_value is None:
                if actual_value is not None:
                    _fail(f"{address} has an unexpected computed endpoint")
            elif actual_value != expected_value:
                _fail(f"{address} has an unexpected environment value")
            if environment.get("value_source") not in (None, []):
                _fail(f"{address} has an undeclared environment value source")
    if len(images) > 2:
        _fail("runtime references more than two distinct image digests")


def _verify_storage(resources: dict[str, dict[str, Any]]) -> None:
    for address in {
        "google_storage_bucket.terraform_state",
        "google_storage_bucket.target",
    } & set(resources):
        after = resources[address]["change"]["after"]
        if after.get("uniform_bucket_level_access") is not True:
            _fail(f"{address} lacks uniform bucket-level access")
        if after.get("public_access_prevention") != "enforced":
            _fail(f"{address} lacks public access prevention")
    if "google_storage_bucket.terraform_state" in resources:
        after = resources["google_storage_bucket.terraform_state"]["change"]["after"]
        if (
            after.get("name") != _STATE_BUCKET
            or after.get("force_destroy") is not False
        ):
            _fail("state bucket is not fail-closed")
        if after.get("deletion_policy") != "PREVENT":
            _fail("state bucket deletion policy is not PREVENT")
    if "google_storage_bucket.target" in resources:
        after = resources["google_storage_bucket.target"]["change"]["after"]
        if (
            after.get("name") != _TARGET_BUCKET
            or after.get("force_destroy") is not True
        ):
            _fail("target bucket is not the approved disposable bucket")


def _verify_foundation(resources: dict[str, dict[str, Any]]) -> None:
    if "google_artifact_registry_repository.runtime" not in resources:
        return
    repository = resources["google_artifact_registry_repository.runtime"]["change"][
        "after"
    ]
    docker = _one_block(
        repository,
        "docker_config",
        "google_artifact_registry_repository.runtime",
    )
    if docker.get("immutable_tags") is not True:
        _fail("artifact tags are not immutable")
    budget = resources["google_billing_budget.phase5"]["change"]["after"]
    amount = _one_block(budget, "amount", "google_billing_budget.phase5")
    specified = _one_block(amount, "specified_amount", "google_billing_budget.phase5")
    if specified.get("currency_code") != "USD" or specified.get("units") != "5":
        _fail("billing budget is not exactly USD 5")


def verify_create_plan(stack: _Stack, plan: dict[str, Any]) -> str:
    _verify_plan_envelope(stack, plan)
    resources = _resources(plan)
    _verify_inventory(stack, resources)
    _verify_iam(resources)
    _verify_cloud_run(resources)
    _verify_storage(resources)
    _verify_foundation(resources)
    inventory = [
        (
            address,
            resource["type"],
            resource["provider_name"],
            resource["change"]["actions"],
        )
        for address, resource in sorted(resources.items())
    ]
    encoded = json.dumps(inventory, separators=(",", ":")).encode()
    return hashlib.sha256(encoded).hexdigest()


def _validate_stack_source(stack: _Stack) -> tuple[Path, ...]:
    sources = tuple(sorted(stack.source.glob("*.tf")))
    if not sources:
        _fail(f"{stack.name} contains no Terraform configuration")
    for source in sources:
        if source.is_symlink():
            _fail(f"{stack.name} contains a symbolic-link configuration")
        configuration = source.read_text(encoding="utf-8")
        if any(marker in configuration for marker in ("#", "//", "/*", "*/", "<<")):
            _fail(f"{stack.name} configuration contains unsupported lexical content")
        unquoted = re.sub(r'"(?:\\.|[^"\\])*"', '""', configuration)
        assigned_names = re.findall(
            r"(?<![A-Za-z0-9_])([A-Za-z_][A-Za-z0-9_]*)\s*=", unquoted
        )
        if any(_SECRET_KEY.search(name) for name in assigned_names):
            _fail(f"{stack.name} contains a secret-bearing source identifier")
        if re.search(
            r'(?m)^\s*(?:action|check|data|ephemeral|module|provisioner)\s+"',
            configuration,
        ) or re.search(
            r"(?m)^\s*(?:action_trigger|import|lifecycle|moved|postcondition|precondition|removed)\s*\{",
            configuration,
        ):
            _fail(f"{stack.name} contains an undeclared Terraform construct")
        if re.search(
            r"\b(?:file[a-z0-9_]*|fileset|pathexpand|templatefile)\s*\(",
            configuration,
        ):
            _fail(f"{stack.name} contains an undeclared filesystem function")
    forbidden = [
        path
        for path in stack.source.rglob("*")
        if path.is_file()
        and (
            path.name.endswith(".tf.json")
            or ".tfvars" in path.name
            or path.name == "override.tf"
            or path.name.endswith("_override.tf")
        )
    ]
    if forbidden:
        _fail(f"{stack.name} contains an undeclared Terraform input file")
    return sources


def _string_attribute(block: str, name: str) -> str:
    values = re.findall(rf'(?m)^\s*{re.escape(name)}\s*=\s*"([^"]+)"\s*$', block)
    if len(values) != 1:
        _fail(f"{name} is not a unique string attribute")
    return values[0]


def _copy_stack(stack: _Stack, destination: Path) -> None:
    destination.mkdir()
    for source in _validate_stack_source(stack):
        shutil.copy2(source, destination / source.name)
    shutil.copy2(stack.source / ".terraform.lock.hcl", destination)
    versions = destination / "versions.tf"
    source = versions.read_text(encoding="utf-8")
    if stack.name == "bootstrap":
        backend = re.compile(r'(?ms)^\s*backend "local" \{.*?^\s*\}')
        matches = backend.findall(source)
        if len(matches) != 1:
            _fail("bootstrap local backend block is not unique")
        block = matches[0]
        assignments = re.findall(r"(?m)^\s*([a-z_]+)\s*=", block)
        if (
            assignments != ["path"]
            or _string_attribute(block, "path") != "terraform.tfstate"
        ):
            _fail("bootstrap local backend path drifted")
        return
    backend = re.compile(r'(?ms)^\s*backend "gcs" \{.*?^\s*\}')
    matches = backend.findall(source)
    if len(matches) != 1:
        _fail(f"{stack.name} backend block is not unique")
    block = matches[0]
    attributes = {
        "bucket": _STATE_BUCKET,
        "prefix": f"phase5/{stack.name}",
        "impersonate_service_account": _APPLY_EMAIL,
    }
    if any(
        _string_attribute(block, name) != value for name, value in attributes.items()
    ):
        _fail(f"{stack.name} backend identity drifted")
    versions.write_text(backend.sub('\n  backend "local" {}', source), encoding="utf-8")
    provider = destination / "providers.tf"
    source = provider.read_text(encoding="utf-8")
    impersonation = f'  impersonate_service_account = "{_APPLY_EMAIL}"\n'
    if source.count(impersonation) != 1:
        _fail(f"{stack.name} provider identity drifted")
    provider.write_text(source.replace(impersonation, ""), encoding="utf-8")


def _run(
    command: list[str],
    *,
    environment: dict[str, str],
    expected: frozenset[int] = frozenset({0}),
) -> subprocess.CompletedProcess[str]:
    result = subprocess.run(
        command,
        check=False,
        capture_output=True,
        env=environment,
        text=True,
        timeout=120,
    )
    if result.returncode not in expected:
        raise RuntimeError(f"subprocess failed with exit code {result.returncode}")
    return result


def _offline_command(command: list[str], working_directory: Path) -> list[str]:
    bwrap = shutil.which("bwrap")
    if bwrap is None:
        raise RuntimeError("bwrap is required for network-isolated plans")
    return [
        bwrap,
        "--die-with-parent",
        "--new-session",
        "--unshare-net",
        "--ro-bind",
        "/",
        "/",
        "--bind",
        str(working_directory.parent),
        str(working_directory.parent),
        "--dev",
        "/dev",
        "--proc",
        "/proc",
        "--chdir",
        str(working_directory),
        *command,
    ]


def _minimal_environment(*, network: bool) -> dict[str, str]:
    environment = {
        "CHECKPOINT_DISABLE": "1",
        "LANG": os.environ.get("LANG", "C.UTF-8"),
        "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
        "TF_IN_AUTOMATION": "1",
        "TF_INPUT": "0",
    }
    if network:
        for key in (
            "ALL_PROXY",
            "HTTP_PROXY",
            "HTTPS_PROXY",
            "NO_PROXY",
            "SSL_CERT_DIR",
            "SSL_CERT_FILE",
            "all_proxy",
            "http_proxy",
            "https_proxy",
            "no_proxy",
        ):
            if key in os.environ:
                environment[key] = os.environ[key]
    return environment


def _verify_provider_mirror(provider_mirror: Path) -> Path:
    provider_mirror = provider_mirror.resolve()
    google_mirror = provider_mirror / "registry.terraform.io" / "hashicorp" / "google"
    if not google_mirror.is_dir() or not any(
        "7.44.0" in path.name for path in google_mirror.rglob("*")
    ):
        raise RuntimeError("the Google provider 7.44.0 mirror is unavailable")
    return provider_mirror


def _create_provider_mirror(terraform: Path, root: Path) -> Path:
    mirror_configuration = root / "mirror-configuration"
    mirror_configuration.mkdir()
    (mirror_configuration / "versions.tf").write_text(
        'terraform {\n  required_version = "= 1.15.8"\n'
        '  required_providers {\n    google = {\n      source = "hashicorp/google"\n'
        '      version = "= 7.44.0"\n    }\n  }\n}\n',
        encoding="utf-8",
    )
    shutil.copy2(
        _ROOT / "infra" / "bootstrap" / ".terraform.lock.hcl",
        mirror_configuration,
    )
    provider_mirror = root / "provider-mirror"
    _run(
        [
            str(terraform),
            f"-chdir={mirror_configuration}",
            "providers",
            "mirror",
            "-platform=linux_amd64",
            str(provider_mirror),
        ],
        environment=_minimal_environment(network=True),
    )
    return _verify_provider_mirror(provider_mirror)


def _offline_create(terraform: Path, provider_mirror: Path | None) -> None:
    for stack in _STACKS:
        _validate_stack_source(stack)
    runner_temporary = os.environ.get("RUNNER_TEMP")
    temporary_parent = Path(runner_temporary) if runner_temporary else None
    with tempfile.TemporaryDirectory(
        prefix="reconcile-phase5-plans-", dir=temporary_parent
    ) as temporary:
        root = Path(temporary)
        if provider_mirror is None:
            provider_mirror = _create_provider_mirror(terraform, root)
        else:
            provider_mirror = _verify_provider_mirror(provider_mirror)
        base_environment = _minimal_environment(network=False)
        base_environment.update(
            {
                "ALL_PROXY": "http://127.0.0.1:9",
                "GOOGLE_OAUTH_ACCESS_TOKEN": "offline-ci-token",
                "HTTP_PROXY": "http://127.0.0.1:9",
                "HTTPS_PROXY": "http://127.0.0.1:9",
                "NO_PROXY": "127.0.0.1,localhost",
                "TMPDIR": str(root / "tmp"),
            }
        )
        base_environment["CLOUDSDK_CONFIG"] = str(root / "empty-gcloud")
        (root / "empty-gcloud").mkdir()
        (root / "tmp").mkdir()
        cli_config = root / "terraform.rc"
        cli_config.write_text(
            "provider_installation {\n"
            "  filesystem_mirror {\n"
            f"    path    = {json.dumps(str(provider_mirror))}\n"
            f'    include = ["{_PROVIDER}"]\n'
            "  }\n"
            "}\n",
            encoding="utf-8",
        )
        base_environment["TF_CLI_CONFIG_FILE"] = str(cli_config)
        for stack in _STACKS:
            working = root / stack.name
            _copy_stack(stack, working)
            if stack.variables:
                (working / "terraform.tfvars.json").write_text(
                    json.dumps(stack.variables), encoding="utf-8"
                )
            environment = base_environment | {
                "TF_DATA_DIR": str(root / f"{stack.name}-data")
            }
            _run(
                _offline_command(
                    [
                        str(terraform),
                        f"-chdir={working}",
                        "init",
                        "-input=false",
                        "-lockfile=readonly",
                        "-no-color",
                    ],
                    working,
                ),
                environment=environment,
            )
            _run(
                _offline_command(
                    [
                        str(terraform),
                        f"-chdir={working}",
                        "validate",
                        "-no-color",
                    ],
                    working,
                ),
                environment=environment,
            )
            stack_version = _run(
                _offline_command(
                    [
                        str(terraform),
                        f"-chdir={working}",
                        "version",
                        "-json",
                    ],
                    working,
                ),
                environment=environment,
            )
            selections = json.loads(stack_version.stdout).get("provider_selections")
            if selections != {_PROVIDER: "7.44.0"}:
                _fail(f"{stack.name} selected an unexpected provider")
            plan_path = root / f"{stack.name}.tfplan"
            plan = _run(
                _offline_command(
                    [
                        str(terraform),
                        f"-chdir={working}",
                        "plan",
                        "-detailed-exitcode",
                        "-input=false",
                        "-lock=false",
                        "-no-color",
                        "-out",
                        str(plan_path),
                        "-refresh=false",
                    ],
                    working,
                ),
                environment=environment,
                expected=frozenset({2}),
            )
            if plan.stdout.count("Plan:") != 1:
                _fail(f"{stack.name} did not produce one create plan")
            rendered = _run(
                _offline_command(
                    [
                        str(terraform),
                        f"-chdir={working}",
                        "show",
                        "-json",
                        str(plan_path),
                    ],
                    working,
                ),
                environment=environment,
            )
            plan_path.unlink()
            digest = verify_create_plan(stack, json.loads(rendered.stdout))
            print(
                f"{stack.name}: {len(stack.addresses)} create-only resources; "
                f"inventory_sha256={digest}"
            )


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--provider-mirror", type=Path)
    parser.add_argument("--terraform", type=Path, default=Path("terraform"))
    return parser.parse_args()


def main() -> int:
    arguments = _parse_args()
    terraform = shutil.which(str(arguments.terraform))
    if terraform is None:
        raise RuntimeError("terraform executable was not found")
    provider_mirror = arguments.provider_mirror
    if provider_mirror is None:
        configured_mirror = os.environ.get("TF_PLUGIN_CACHE_DIR")
        provider_mirror = Path(configured_mirror) if configured_mirror else None
    executable = Path(terraform).resolve()
    version = _run(
        [str(executable), "version", "-json"],
        environment=_minimal_environment(network=False),
    )
    if json.loads(version.stdout).get("terraform_version") != "1.15.8":
        raise RuntimeError("terraform 1.15.8 is required")
    _offline_create(executable, provider_mirror)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
