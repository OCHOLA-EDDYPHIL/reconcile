from __future__ import annotations

import argparse
import copy
import hashlib
import json
import os
import re
import shutil
import stat
import subprocess
import tempfile
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from reconcile.deployment_profile import (
    DeploymentProfile,
    DeploymentProfileError,
    load_sealed_deployment_profile_file,
)

_ROOT = Path(__file__).parents[1]
_PROJECT = "example-project-id"
_PROJECT_NUMBER = "000000000000"
_REGION = "us-central1"
_STATE_BUCKET = f"{_PROJECT}-p5-state"
_TARGET_BUCKET = f"{_PROJECT}-p5-target"
_SANDBOX_DATABASE = "reconcile-p5-sandbox"
_OWNER = "user:owner@example.invalid"
_BILLING_ACCOUNT = "000000-000000-000000"
_APPLY_EMAIL = f"rec-p5-apply@{_PROJECT}.iam.gserviceaccount.com"
_APPLY_MEMBER = f"serviceAccount:{_APPLY_EMAIL}"
_OPERATOR_EMAIL = f"rec-p5-operator@{_PROJECT}.iam.gserviceaccount.com"
_OPERATOR_MEMBER = f"serviceAccount:{_OPERATOR_EMAIL}"
_NOTIFICATION_CHANNEL_IDS: tuple[str, ...] = ()
_PROVIDER = "registry.terraform.io/hashicorp/google"
_TERRAFORM_PROVIDER = "terraform.io/builtin/terraform"
_OFFLINE_DOCKER_IMAGE = (
    "python:3.12.13-slim-bookworm@"
    "sha256:6e13e65c55e33adf203d77ee371cf8bf5d81bd4902ef07565721f46bf44917af"
)
_DIGEST = "0" * 64
_IMAGE_DIGEST = f"sha256:{_DIGEST}"
_IMAGE_REFERENCE = (
    f"{_REGION}-docker.pkg.dev/{_PROJECT}/reconcile-p5/reconcile@{_IMAGE_DIGEST}"
)
_SOURCE_REVISION = "a" * 40
_INFRASTRUCTURE_REVISION = "b" * 64
_SEMANTIC_CONFIG_SHA256 = "c" * 64
_RECOVERY_DEFINITION_CREATED_AT = "2026-08-24T00:00:00Z"
_VERTEX_PROMPT_VERSION = "adaptive-planner-v3"
_VERTEX_PROMPT_SHA256 = (
    "a18ac5bbd22570562acc6dfbc49437a82f0db6a265a4de737c1371b6ef2ca2d3"
)
_RUNTIME_EMAILS = {
    "api": f"rec-p5-api@{_PROJECT}.iam.gserviceaccount.com",
    "canary": f"rec-p5-canary@{_PROJECT}.iam.gserviceaccount.com",
    "controller": f"rec-p5-controller@{_PROJECT}.iam.gserviceaccount.com",
    "fault_proxy": f"rec-p5-fault@{_PROJECT}.iam.gserviceaccount.com",
    "sandbox": f"rec-p5-sandbox@{_PROJECT}.iam.gserviceaccount.com",
}


def _canary_baseline_identity(
    *,
    image_digest: str,
    infrastructure_revision: str,
    semantic_config_sha256: str,
    source_revision: str,
    request_timeout_seconds: int = 60,
) -> str:
    encoded = json.dumps(
        {
            "image_digest": image_digest,
            "infrastructure_revision": infrastructure_revision,
            "project_id": _PROJECT,
            "region": _REGION,
            "request_timeout_seconds": request_timeout_seconds,
            "semantic_config_sha256": semantic_config_sha256,
            "service_account_email": _RUNTIME_EMAILS["canary"],
            "source_revision": source_revision,
        },
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _recovery_payload_sha256(
    *,
    image_digest: str,
    infrastructure_revision: str,
    semantic_config_sha256: str,
    source_revision: str,
    vertex_location: str = "us",
    vertex_model: str = "gemini-3.5-flash",
    vertex_prompt_sha256: str = _VERTEX_PROMPT_SHA256,
    vertex_prompt_version: str = _VERTEX_PROMPT_VERSION,
) -> str:
    encoded = json.dumps(
        {
            "configured_model": vertex_model,
            "image_digest": image_digest,
            "infrastructure_revision": infrastructure_revision,
            "maximum_count_tokens_attempts": 1,
            "maximum_generation_attempts": 1,
            "maximum_input_tokens": 12_000,
            "maximum_output_tokens": 4_096,
            "project_id": _PROJECT,
            "prompt_sha256": vertex_prompt_sha256,
            "prompt_version": vertex_prompt_version,
            "schema_version": "reconcile/hosted-candidate-identity/v1",
            "semantic_config_sha256": semantic_config_sha256,
            "source_revision": source_revision,
            "thinking_level": "MINIMAL",
            "vertex_location": vertex_location,
        },
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


_CANARY_BASELINE_IDENTITY = _canary_baseline_identity(
    image_digest=_IMAGE_DIGEST,
    infrastructure_revision=_INFRASTRUCTURE_REVISION,
    semantic_config_sha256=_SEMANTIC_CONFIG_SHA256,
    source_revision=_SOURCE_REVISION,
)
_CANARY_BASELINE_REVISION = f"reconcile-p5-canary-b-{_CANARY_BASELINE_IDENTITY[:16]}"
_RECOVERY_RELEASE_ID = f"p5-release-{_SOURCE_REVISION[:24]}"
_RECOVERY_PAYLOAD_SHA256 = _recovery_payload_sha256(
    image_digest=_IMAGE_DIGEST,
    infrastructure_revision=_INFRASTRUCTURE_REVISION,
    semantic_config_sha256=_SEMANTIC_CONFIG_SHA256,
    source_revision=_SOURCE_REVISION,
)
_SERVICE_NAMES = {
    "api": "reconcile-p5-api",
    "canary": "reconcile-p5-canary",
    "controller": "reconcile-p5-controller",
    "fault_proxy": "reconcile-p5-fault-proxy",
    "sandbox": "reconcile-p5-sandbox",
}
_SERVICE_CONTAINERS = {
    "api": "api",
    "canary": "canary",
    "controller": "controller",
    "fault_proxy": "fault-proxy",
    "sandbox": "sandbox",
}
_SERVICE_MEMORY = {
    "api": "512Mi",
    "canary": "512Mi",
    "controller": "1Gi",
    "fault_proxy": "512Mi",
    "sandbox": "512Mi",
}
_SERVICE_TIMEOUTS = {
    "api": "300s",
    "canary": "60s",
    "controller": "300s",
    "fault_proxy": "60s",
    "sandbox": "60s",
}
_AUDIENCES = {
    component: f"https://reconcile.invalid/phase5/{_PROJECT}/{component.replace('_', '-')}"
    for component in _RUNTIME_EMAILS
}
_COMMON_RUNTIME_ENVIRONMENT = {
    "GOOGLE_CLOUD_PROJECT": _PROJECT,
    "RECONCILE_IMAGE_DIGEST": _IMAGE_DIGEST,
    "RECONCILE_INFRA_REVISION": _INFRASTRUCTURE_REVISION,
    "RECONCILE_SEMANTIC_CONFIG_SHA256": _SEMANTIC_CONFIG_SHA256,
    "RECONCILE_SOURCE_REVISION": _SOURCE_REVISION,
    "RECONCILE_OPERATING_PROFILE": "evidence",
}
_RUNTIME_ENVIRONMENT = {
    "api": _COMMON_RUNTIME_ENVIRONMENT
    | {
        "RECONCILE_ACCEPTANCE_PARTIAL_READ_OUTAGE_ENABLED": "true",
        "RECONCILE_ALLOWED_CALLER_EMAILS": _OPERATOR_EMAIL,
        "RECONCILE_AUTH_AUDIENCE": _AUDIENCES["api"],
        "RECONCILE_COMPONENT": "api",
        "RECONCILE_CONTROLLER_AUDIENCE": _AUDIENCES["controller"],
        "RECONCILE_CONTROLLER_URL": None,
        "RECONCILE_FAULT_PROXY_AUDIENCE": _AUDIENCES["fault_proxy"],
        "RECONCILE_FAULT_PROXY_URL": None,
        "RECONCILE_RUNTIME_DATABASE": "reconcile-p5-runtime",
        "RECONCILE_TARGET_BUCKET": _TARGET_BUCKET,
    },
    "canary": _COMMON_RUNTIME_ENVIRONMENT
    | {
        "RECONCILE_CANARY_CONFIGURATION_SHA256": _SEMANTIC_CONFIG_SHA256,
        "RECONCILE_CANARY_RELEASE_ID": "baseline",
    },
    "controller": _COMMON_RUNTIME_ENVIRONMENT
    | {
        "RECONCILE_ACCEPTANCE_PARTIAL_READ_OUTAGE_ENABLED": "true",
        "RECONCILE_ALLOWED_CALLER_EMAILS": _RUNTIME_EMAILS["api"],
        "RECONCILE_AUTH_AUDIENCE": _AUDIENCES["controller"],
        "RECONCILE_CANARY_AUDIENCE": _AUDIENCES["canary"],
        "RECONCILE_CANARY_BASELINE_REVISION": _CANARY_BASELINE_REVISION,
        "RECONCILE_CANARY_LOCATION": _REGION,
        "RECONCILE_CANARY_SERVICE": "reconcile-p5-canary",
        "RECONCILE_COMPONENT": "controller",
        "RECONCILE_FAULT_PROXY_AUDIENCE": _AUDIENCES["fault_proxy"],
        "RECONCILE_FAULT_PROXY_URL": None,
        "RECONCILE_RECOVERY_DEFINITION_CREATED_AT": _RECOVERY_DEFINITION_CREATED_AT,
        "RECONCILE_RECOVERY_EXECUTION_TIMEOUT_SECONDS": "240",
        "RECONCILE_RECOVERY_PAYLOAD_SHA256": _RECOVERY_PAYLOAD_SHA256,
        "RECONCILE_RECOVERY_RELEASE_ID": _RECOVERY_RELEASE_ID,
        "RECONCILE_RUNTIME_DATABASE": "reconcile-p5-runtime",
        "RECONCILE_SANDBOX_AUDIENCE": _AUDIENCES["sandbox"],
        "RECONCILE_SANDBOX_URL": None,
        "RECONCILE_TARGET_BUCKET": _TARGET_BUCKET,
        "RECONCILE_TARGET_DATABASE": "reconcile-p5-target",
        "RECONCILE_VERTEX_LOCATION": "us",
        "RECONCILE_VERTEX_MAX_COUNT_TOKENS_ATTEMPTS": "1",
        "RECONCILE_VERTEX_MAX_GENERATION_ATTEMPTS": "1",
        "RECONCILE_VERTEX_MAX_INPUT_TOKENS": "12000",
        "RECONCILE_VERTEX_MAX_OUTPUT_TOKENS": "4096",
        "RECONCILE_VERTEX_MODEL": "gemini-3.5-flash",
        "RECONCILE_VERTEX_PROMPT_SHA256": _VERTEX_PROMPT_SHA256,
        "RECONCILE_VERTEX_PROMPT_VERSION": _VERTEX_PROMPT_VERSION,
        "RECONCILE_VERTEX_THINKING_LEVEL": "MINIMAL",
    },
    "fault_proxy": _COMMON_RUNTIME_ENVIRONMENT
    | {
        "RECONCILE_ACCEPTANCE_PARTIAL_READ_OUTAGE_ENABLED": "true",
        "RECONCILE_ALLOWED_CALLER_EMAILS": _RUNTIME_EMAILS["api"],
        "RECONCILE_AUTH_AUDIENCE": _AUDIENCES["fault_proxy"],
        "RECONCILE_CANARY_AUDIENCE": _AUDIENCES["canary"],
        "RECONCILE_CANARY_BASELINE_REVISION": _CANARY_BASELINE_REVISION,
        "RECONCILE_CANARY_LOCATION": _REGION,
        "RECONCILE_CANARY_SERVICE": "reconcile-p5-canary",
        "RECONCILE_COMPONENT": "fault-proxy",
        "RECONCILE_RECOVERY_ACTION_CALLER_EMAIL": _RUNTIME_EMAILS["controller"],
        "RECONCILE_RUNTIME_DATABASE": "reconcile-p5-runtime",
        "RECONCILE_SANDBOX_AUDIENCE": _AUDIENCES["sandbox"],
        "RECONCILE_SANDBOX_URL": None,
        "RECONCILE_TARGET_BUCKET": _TARGET_BUCKET,
        "RECONCILE_TARGET_DATABASE": "reconcile-p5-target",
    },
    "sandbox": _COMMON_RUNTIME_ENVIRONMENT
    | {
        "RECONCILE_AUTH_AUDIENCE": _AUDIENCES["sandbox"],
        "RECONCILE_COMPONENT": "sandbox",
        "RECONCILE_RUNTIME_DATABASE": "reconcile-p5-runtime",
        "RECONCILE_SANDBOX_MUTATION_CALLER_EMAIL": _RUNTIME_EMAILS["fault_proxy"],
        "RECONCILE_SANDBOX_READ_CALLER_EMAIL": _RUNTIME_EMAILS["controller"],
        "RECONCILE_TARGET_DATABASE": _SANDBOX_DATABASE,
    },
}
_APPLY_ROLES = {
    "roles/artifactregistry.admin",
    "roles/datastore.owner",
    "roles/iam.serviceAccountAdmin",
    "roles/logging.configWriter",
    "roles/logging.viewer",
    "roles/monitoring.editor",
    "roles/resourcemanager.projectIamAdmin",
    "roles/serviceusage.serviceUsageAdmin",
    "roles/storage.admin",
}
_BOOTSTRAP_SERVICES = {
    "cloudbilling.googleapis.com",
    "cloudresourcemanager.googleapis.com",
    "iam.googleapis.com",
    "iamcredentials.googleapis.com",
    "orgpolicy.googleapis.com",
    "serviceusage.googleapis.com",
    "storage.googleapis.com",
}
_FOUNDATION_SERVICES = {
    "aiplatform.googleapis.com",
    "artifactregistry.googleapis.com",
    "billingbudgets.googleapis.com",
    "firestore.googleapis.com",
    "logging.googleapis.com",
    "monitoring.googleapis.com",
    "run.googleapis.com",
}
_OPERATIONAL_SIGNALS = {
    "failed_run": "failed-run",
    "permit_denial": "permit-denial",
    "provider_unavailable": "provider-unavailable",
    "replay_denial": "replay-denial",
    "unresolved_ambiguity": "unresolved-ambiguity",
    "worker_failure": "worker-failure",
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
        "google_project_iam_custom_role.canary_mutator",
        "google_project_iam_custom_role.canary_operation_reader",
        "google_project_iam_custom_role.canary_revision_reader",
        "google_project_iam_custom_role.cloud_run_deployer",
        "google_service_account.phase5_apply",
        "google_service_account.phase5_operator",
        "google_project_default_service_accounts.phase5",
        "google_project_organization_policy.disable_automatic_default_service_account_grants",
        "google_project_iam_member.phase5_cloud_run_deployer",
        "google_service_account_iam_member.owner_impersonation",
        "google_service_account_iam_member.owner_operator_impersonation",
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
        'google_firestore_database.phase5["sandbox"]',
        'google_firestore_database.phase5["target"]',
        'google_project_iam_member.runtime_database_user["api"]',
        'google_project_iam_member.runtime_database_user["controller"]',
        'google_project_iam_member.runtime_database_user["fault_proxy"]',
        'google_project_iam_member.runtime_database_viewer["sandbox"]',
        'google_project_iam_member.target_database_user["fault_proxy"]',
        "google_project_iam_member.sandbox_database_user",
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
        "google_cloud_run_v2_service.canary",
        "google_cloud_run_v2_service.controller",
        "google_cloud_run_v2_service.fault_proxy",
        "google_cloud_run_v2_service.sandbox",
        "terraform_data.canary_baseline",
        f'google_cloud_run_v2_service_iam_member.api_operator["{_OPERATOR_MEMBER}"]',
        'google_cloud_run_v2_service_iam_member.internal["api_to_controller"]',
        'google_cloud_run_v2_service_iam_member.internal["api_to_fault_proxy"]',
        'google_cloud_run_v2_service_iam_member.internal["controller_to_fault_proxy"]',
        'google_cloud_run_v2_service_iam_member.internal["controller_to_sandbox"]',
        'google_cloud_run_v2_service_iam_member.internal["fault_proxy_to_sandbox"]',
        "google_cloud_run_v2_service_iam_member.canary_invoker",
        "google_cloud_run_v2_service_iam_member.canary_mutator",
        "google_cloud_run_v2_service_iam_member.canary_reader",
        "google_project_iam_member.canary_operation_reader",
        *_quoted(
            "google_project_iam_member.canary_revision_reader",
            {"controller", "fault_proxy"},
        ),
        "google_artifact_registry_repository_iam_member.canary_mutator_image_reader",
        "google_service_account_iam_member.canary_mutator_act_as",
        "google_monitoring_dashboard.operational",
        *_quoted(
            "google_logging_metric.operational_failure",
            set(_OPERATIONAL_SIGNALS),
        ),
        *_quoted(
            "google_monitoring_alert_policy.operational_failure",
            set(_OPERATIONAL_SIGNALS),
        ),
    }
)
_STACKS = (
    _Stack(
        "bootstrap",
        _ROOT / "infra" / "bootstrap",
        _BOOTSTRAP_ADDRESSES,
        {
            "billing_account_id": _BILLING_ACCOUNT,
            "owner_principal": _OWNER,
            "project_id": _PROJECT,
        },
    ),
    _Stack(
        "foundation",
        _ROOT / "infra" / "environments" / "dev" / "foundation",
        _FOUNDATION_ADDRESSES,
        {
            "billing_account_id": _BILLING_ACCOUNT,
            "operating_profile": "evidence",
            "project_id": _PROJECT,
            "project_number": _PROJECT_NUMBER,
        },
    ),
    _Stack(
        "runtime",
        _ROOT / "infra" / "environments" / "dev" / "runtime",
        _RUNTIME_ADDRESSES,
        {
            "acceptance_partial_read_outage_enabled": True,
            "apply_service_account_email": _APPLY_EMAIL,
            "image_digest": _IMAGE_DIGEST,
            "infrastructure_revision": _INFRASTRUCTURE_REVISION,
            "notification_channel_ids": [],
            "operating_profile": "evidence",
            "project_id": _PROJECT,
            "recovery_definition_created_at": _RECOVERY_DEFINITION_CREATED_AT,
            "semantic_config_sha256": _SEMANTIC_CONFIG_SHA256,
            "source_revision": _SOURCE_REVISION,
        },
    ),
)


def _configure_deployment(profile: DeploymentProfile) -> None:
    global _APPLY_EMAIL
    global _APPLY_MEMBER
    global _AUDIENCES
    global _BILLING_ACCOUNT
    global _CANARY_BASELINE_IDENTITY
    global _CANARY_BASELINE_REVISION
    global _COMMON_RUNTIME_ENVIRONMENT
    global _CUSTOM_ROLE_EXPECTED
    global _IMAGE_REFERENCE
    global _IAM_EXPECTED
    global _OPERATOR_MEMBER
    global _OPERATOR_EMAIL
    global _NOTIFICATION_CHANNEL_IDS
    global _OWNER
    global _PROJECT
    global _PROJECT_NUMBER
    global _FOUNDATION_ADDRESSES
    global _RECOVERY_PAYLOAD_SHA256
    global _RUNTIME_ADDRESSES
    global _RUNTIME_EMAILS
    global _RUNTIME_ENVIRONMENT
    global _STACKS
    global _STATE_BUCKET
    global _TARGET_BUCKET

    _PROJECT = profile.project_id
    _PROJECT_NUMBER = profile.project_number
    _BILLING_ACCOUNT = profile.billing_account_id
    _OWNER = f"user:{profile.owner_account}"
    _STATE_BUCKET = f"{_PROJECT}-p5-state"
    _TARGET_BUCKET = f"{_PROJECT}-p5-target"
    _APPLY_EMAIL = f"rec-p5-apply@{_PROJECT}.iam.gserviceaccount.com"
    _APPLY_MEMBER = f"serviceAccount:{_APPLY_EMAIL}"
    _OPERATOR_EMAIL = f"rec-p5-operator@{_PROJECT}.iam.gserviceaccount.com"
    _OPERATOR_MEMBER = f"serviceAccount:{_OPERATOR_EMAIL}"
    _NOTIFICATION_CHANNEL_IDS = profile.notification_channel_ids
    _IMAGE_REFERENCE = (
        f"{_REGION}-docker.pkg.dev/{_PROJECT}/reconcile-p5/reconcile@{_IMAGE_DIGEST}"
    )
    _RUNTIME_EMAILS = {
        "api": f"rec-p5-api@{_PROJECT}.iam.gserviceaccount.com",
        "canary": f"rec-p5-canary@{_PROJECT}.iam.gserviceaccount.com",
        "controller": f"rec-p5-controller@{_PROJECT}.iam.gserviceaccount.com",
        "fault_proxy": f"rec-p5-fault@{_PROJECT}.iam.gserviceaccount.com",
        "sandbox": f"rec-p5-sandbox@{_PROJECT}.iam.gserviceaccount.com",
    }
    _AUDIENCES = {
        component: (
            f"https://reconcile.invalid/phase5/{_PROJECT}/{component.replace('_', '-')}"
        )
        for component in _RUNTIME_EMAILS
    }
    _CANARY_BASELINE_IDENTITY = _canary_baseline_identity(
        image_digest=_IMAGE_DIGEST,
        infrastructure_revision=_INFRASTRUCTURE_REVISION,
        semantic_config_sha256=_SEMANTIC_CONFIG_SHA256,
        source_revision=_SOURCE_REVISION,
    )
    _CANARY_BASELINE_REVISION = (
        f"reconcile-p5-canary-b-{_CANARY_BASELINE_IDENTITY[:16]}"
    )
    _RECOVERY_PAYLOAD_SHA256 = _recovery_payload_sha256(
        image_digest=_IMAGE_DIGEST,
        infrastructure_revision=_INFRASTRUCTURE_REVISION,
        semantic_config_sha256=_SEMANTIC_CONFIG_SHA256,
        source_revision=_SOURCE_REVISION,
    )
    acceptance_partial_read_outage_enabled = profile.operating_profile == "evidence"
    acceptance_partial_read_outage_environment = (
        "true" if acceptance_partial_read_outage_enabled else "false"
    )
    _COMMON_RUNTIME_ENVIRONMENT = {
        "GOOGLE_CLOUD_PROJECT": _PROJECT,
        "RECONCILE_IMAGE_DIGEST": _IMAGE_DIGEST,
        "RECONCILE_INFRA_REVISION": _INFRASTRUCTURE_REVISION,
        "RECONCILE_SEMANTIC_CONFIG_SHA256": _SEMANTIC_CONFIG_SHA256,
        "RECONCILE_SOURCE_REVISION": _SOURCE_REVISION,
        "RECONCILE_OPERATING_PROFILE": profile.operating_profile,
    }
    _RUNTIME_ENVIRONMENT = {
        "api": _COMMON_RUNTIME_ENVIRONMENT
        | {
            "RECONCILE_ACCEPTANCE_PARTIAL_READ_OUTAGE_ENABLED": (
                acceptance_partial_read_outage_environment
            ),
            "RECONCILE_ALLOWED_CALLER_EMAILS": _OPERATOR_EMAIL,
            "RECONCILE_AUTH_AUDIENCE": _AUDIENCES["api"],
            "RECONCILE_COMPONENT": "api",
            "RECONCILE_CONTROLLER_AUDIENCE": _AUDIENCES["controller"],
            "RECONCILE_CONTROLLER_URL": None,
            "RECONCILE_FAULT_PROXY_AUDIENCE": _AUDIENCES["fault_proxy"],
            "RECONCILE_FAULT_PROXY_URL": None,
            "RECONCILE_RUNTIME_DATABASE": "reconcile-p5-runtime",
            "RECONCILE_TARGET_BUCKET": _TARGET_BUCKET,
        },
        "canary": _COMMON_RUNTIME_ENVIRONMENT
        | {
            "RECONCILE_CANARY_CONFIGURATION_SHA256": _SEMANTIC_CONFIG_SHA256,
            "RECONCILE_CANARY_RELEASE_ID": "baseline",
        },
        "controller": _COMMON_RUNTIME_ENVIRONMENT
        | {
            "RECONCILE_ACCEPTANCE_PARTIAL_READ_OUTAGE_ENABLED": (
                acceptance_partial_read_outage_environment
            ),
            "RECONCILE_ALLOWED_CALLER_EMAILS": _RUNTIME_EMAILS["api"],
            "RECONCILE_AUTH_AUDIENCE": _AUDIENCES["controller"],
            "RECONCILE_CANARY_AUDIENCE": _AUDIENCES["canary"],
            "RECONCILE_CANARY_BASELINE_REVISION": _CANARY_BASELINE_REVISION,
            "RECONCILE_CANARY_LOCATION": _REGION,
            "RECONCILE_CANARY_SERVICE": "reconcile-p5-canary",
            "RECONCILE_COMPONENT": "controller",
            "RECONCILE_FAULT_PROXY_AUDIENCE": _AUDIENCES["fault_proxy"],
            "RECONCILE_FAULT_PROXY_URL": None,
            "RECONCILE_RECOVERY_DEFINITION_CREATED_AT": (
                _RECOVERY_DEFINITION_CREATED_AT
            ),
            "RECONCILE_RECOVERY_EXECUTION_TIMEOUT_SECONDS": "240",
            "RECONCILE_RECOVERY_PAYLOAD_SHA256": _RECOVERY_PAYLOAD_SHA256,
            "RECONCILE_RECOVERY_RELEASE_ID": _RECOVERY_RELEASE_ID,
            "RECONCILE_RUNTIME_DATABASE": "reconcile-p5-runtime",
            "RECONCILE_SANDBOX_AUDIENCE": _AUDIENCES["sandbox"],
            "RECONCILE_SANDBOX_URL": None,
            "RECONCILE_TARGET_BUCKET": _TARGET_BUCKET,
            "RECONCILE_TARGET_DATABASE": "reconcile-p5-target",
            "RECONCILE_VERTEX_LOCATION": "us",
            "RECONCILE_VERTEX_MAX_COUNT_TOKENS_ATTEMPTS": "1",
            "RECONCILE_VERTEX_MAX_GENERATION_ATTEMPTS": "1",
            "RECONCILE_VERTEX_MAX_INPUT_TOKENS": "12000",
            "RECONCILE_VERTEX_MAX_OUTPUT_TOKENS": "4096",
            "RECONCILE_VERTEX_MODEL": "gemini-3.5-flash",
            "RECONCILE_VERTEX_PROMPT_SHA256": _VERTEX_PROMPT_SHA256,
            "RECONCILE_VERTEX_PROMPT_VERSION": _VERTEX_PROMPT_VERSION,
            "RECONCILE_VERTEX_THINKING_LEVEL": "MINIMAL",
        },
        "fault_proxy": _COMMON_RUNTIME_ENVIRONMENT
        | {
            "RECONCILE_ACCEPTANCE_PARTIAL_READ_OUTAGE_ENABLED": (
                acceptance_partial_read_outage_environment
            ),
            "RECONCILE_ALLOWED_CALLER_EMAILS": _RUNTIME_EMAILS["api"],
            "RECONCILE_AUTH_AUDIENCE": _AUDIENCES["fault_proxy"],
            "RECONCILE_CANARY_AUDIENCE": _AUDIENCES["canary"],
            "RECONCILE_CANARY_BASELINE_REVISION": _CANARY_BASELINE_REVISION,
            "RECONCILE_CANARY_LOCATION": _REGION,
            "RECONCILE_CANARY_SERVICE": "reconcile-p5-canary",
            "RECONCILE_COMPONENT": "fault-proxy",
            "RECONCILE_RECOVERY_ACTION_CALLER_EMAIL": (_RUNTIME_EMAILS["controller"]),
            "RECONCILE_RUNTIME_DATABASE": "reconcile-p5-runtime",
            "RECONCILE_SANDBOX_AUDIENCE": _AUDIENCES["sandbox"],
            "RECONCILE_SANDBOX_URL": None,
            "RECONCILE_TARGET_BUCKET": _TARGET_BUCKET,
            "RECONCILE_TARGET_DATABASE": "reconcile-p5-target",
        },
        "sandbox": _COMMON_RUNTIME_ENVIRONMENT
        | {
            "RECONCILE_AUTH_AUDIENCE": _AUDIENCES["sandbox"],
            "RECONCILE_COMPONENT": "sandbox",
            "RECONCILE_RUNTIME_DATABASE": "reconcile-p5-runtime",
            "RECONCILE_SANDBOX_MUTATION_CALLER_EMAIL": (_RUNTIME_EMAILS["fault_proxy"]),
            "RECONCILE_SANDBOX_READ_CALLER_EMAIL": _RUNTIME_EMAILS["controller"],
            "RECONCILE_TARGET_DATABASE": _SANDBOX_DATABASE,
        },
    }
    _RUNTIME_ADDRESSES = frozenset(
        address
        for address in _RUNTIME_ADDRESSES
        if not address.startswith(
            "google_cloud_run_v2_service_iam_member.api_operator["
        )
        and address != "terraform_data.runtime_production_guard[0]"
    ) | frozenset(
        {
            f'google_cloud_run_v2_service_iam_member.api_operator["{_OPERATOR_MEMBER}"]',
            *(
                {"terraform_data.runtime_production_guard[0]"}
                if profile.operating_profile == "production"
                else set()
            ),
        }
    )
    _FOUNDATION_ADDRESSES = frozenset(
        address
        for address in _FOUNDATION_ADDRESSES
        if address != "terraform_data.foundation_production_guard[0]"
    ) | frozenset(
        {"terraform_data.foundation_production_guard[0]"}
        if profile.operating_profile == "production"
        else set()
    )
    _STACKS = (
        _Stack(
            "bootstrap",
            _ROOT / "infra" / "bootstrap",
            _BOOTSTRAP_ADDRESSES,
            {
                "billing_account_id": _BILLING_ACCOUNT,
                "owner_principal": _OWNER,
                "project_id": _PROJECT,
            },
        ),
        _Stack(
            "foundation",
            _ROOT / "infra" / "environments" / "dev" / "foundation",
            _FOUNDATION_ADDRESSES,
            {
                "billing_account_id": _BILLING_ACCOUNT,
                "operating_profile": profile.operating_profile,
                "project_id": _PROJECT,
                "project_number": _PROJECT_NUMBER,
            },
        ),
        _Stack(
            "runtime",
            _ROOT / "infra" / "environments" / "dev" / "runtime",
            _RUNTIME_ADDRESSES,
            {
                "acceptance_partial_read_outage_enabled": (
                    acceptance_partial_read_outage_enabled
                ),
                "apply_service_account_email": _APPLY_EMAIL,
                "image_digest": _IMAGE_DIGEST,
                "infrastructure_revision": _INFRASTRUCTURE_REVISION,
                "notification_channel_ids": list(_NOTIFICATION_CHANNEL_IDS),
                "operating_profile": profile.operating_profile,
                "project_id": _PROJECT,
                "recovery_definition_created_at": (_RECOVERY_DEFINITION_CREATED_AT),
                "semantic_config_sha256": _SEMANTIC_CONFIG_SHA256,
                "source_revision": _SOURCE_REVISION,
            },
        ),
    )
    _IAM_EXPECTED = _iam_expectations()
    _CUSTOM_ROLE_EXPECTED = _custom_role_expectations()


_VARIABLE_NAMES = {
    "bootstrap": {
        "allow_state_bucket_destroy",
        "billing_account_id",
        "owner_principal",
        "project_id",
        "region",
    },
    "foundation": {
        "billing_account_id",
        "budget_amount_usd",
        "operating_profile",
        "project_id",
        "project_number",
        "region",
    },
    "runtime": {
        "acceptance_partial_read_outage_enabled",
        "apply_service_account_email",
        "image_digest",
        "infrastructure_revision",
        "notification_channel_ids",
        "operating_profile",
        "project_id",
        "region",
        "request_timeout_seconds",
        "recovery_definition_created_at",
        "semantic_config_sha256",
        "source_revision",
        "vertex_location",
        "vertex_model",
        "vertex_prompt_sha256",
        "vertex_prompt_version",
    },
}
_OUTPUT_NAMES = {
    "bootstrap": {
        "apply_service_account_email",
        "operator_service_account_email",
        "state_bucket_name",
    },
    "foundation": {
        "artifact_repository_url",
        "firestore_databases",
        "service_account_emails",
        "target_bucket_name",
    },
    "runtime": {"api_uri", "canary_uri"},
}


def _iam_expectations() -> dict[str, dict[str, Any]]:
    expected = {
        "google_billing_account_iam_member.phase5_apply": {
            "billing_account_id": _BILLING_ACCOUNT,
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
        "google_service_account_iam_member.owner_operator_impersonation": {
            "member": _OWNER,
            "role": "roles/iam.serviceAccountTokenCreator",
            "service_account_id": (
                f"projects/{_PROJECT}/serviceAccounts/{_OPERATOR_EMAIL}"
            ),
        },
        "google_project_iam_member.phase5_cloud_run_deployer": {
            "member": _APPLY_MEMBER,
            "project": _PROJECT,
            "role": f"projects/{_PROJECT}/roles/reconcileP5CloudRunDeployer",
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
        'google_project_iam_member.runtime_database_user["fault_proxy"]': {
            "member": f"serviceAccount:{_RUNTIME_EMAILS['fault_proxy']}",
            "project": _PROJECT,
            "role": "roles/datastore.user",
            "condition_expression": (
                f'resource.name == "projects/{_PROJECT}/databases/reconcile-p5-runtime"'
            ),
        },
        'google_project_iam_member.runtime_database_viewer["sandbox"]': {
            "member": f"serviceAccount:{_RUNTIME_EMAILS['sandbox']}",
            "project": _PROJECT,
            "role": "roles/datastore.viewer",
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
        "google_project_iam_member.sandbox_database_user": {
            "member": f"serviceAccount:{_RUNTIME_EMAILS['sandbox']}",
            "project": _PROJECT,
            "role": "roles/datastore.user",
            "condition_expression": (
                f'resource.name == "projects/{_PROJECT}/databases/{_SANDBOX_DATABASE}"'
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
        f'google_cloud_run_v2_service_iam_member.api_operator["{_OPERATOR_MEMBER}"]': {
            "location": _REGION,
            "member": _OPERATOR_MEMBER,
            "name": "reconcile-p5-api",
            "project": _PROJECT,
            "role": "roles/run.invoker",
        },
        "google_cloud_run_v2_service_iam_member.canary_reader": {
            "location": _REGION,
            "member": f"serviceAccount:{_RUNTIME_EMAILS['controller']}",
            "name": "reconcile-p5-canary",
            "project": _PROJECT,
            "role": "roles/run.viewer",
        },
        "google_cloud_run_v2_service_iam_member.canary_invoker": {
            "location": _REGION,
            "member": f"serviceAccount:{_RUNTIME_EMAILS['controller']}",
            "name": "reconcile-p5-canary",
            "project": _PROJECT,
            "role": "roles/run.invoker",
        },
        "google_cloud_run_v2_service_iam_member.canary_mutator": {
            "location": _REGION,
            "member": f"serviceAccount:{_RUNTIME_EMAILS['fault_proxy']}",
            "name": "reconcile-p5-canary",
            "project": _PROJECT,
            "role": f"projects/{_PROJECT}/roles/reconcileP5CanaryMutator",
        },
        "google_project_iam_member.canary_operation_reader": {
            "member": f"serviceAccount:{_RUNTIME_EMAILS['controller']}",
            "project": _PROJECT,
            "role": (f"projects/{_PROJECT}/roles/reconcileP5CanaryOperationReader"),
        },
        "google_artifact_registry_repository_iam_member.canary_mutator_image_reader": {
            "location": _REGION,
            "member": f"serviceAccount:{_RUNTIME_EMAILS['fault_proxy']}",
            "project": _PROJECT,
            "repository": "reconcile-p5",
            "role": "roles/artifactregistry.reader",
        },
        "google_service_account_iam_member.canary_mutator_act_as": {
            "member": f"serviceAccount:{_RUNTIME_EMAILS['fault_proxy']}",
            "role": "roles/iam.serviceAccountUser",
            "service_account_id": (
                f"projects/{_PROJECT}/serviceAccounts/{_RUNTIME_EMAILS['canary']}"
            ),
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
    for component in ("controller", "fault_proxy"):
        expected[f'google_project_iam_member.canary_revision_reader["{component}"]'] = {
            "member": f"serviceAccount:{_RUNTIME_EMAILS[component]}",
            "project": _PROJECT,
            "role": f"projects/{_PROJECT}/roles/reconcileP5CanaryRevisionReader",
        }
    invocations = {
        "api_to_controller": ("controller", "api"),
        "api_to_fault_proxy": ("fault-proxy", "api"),
        "controller_to_fault_proxy": ("fault-proxy", "controller"),
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


def _custom_role_expectations() -> dict[str, dict[str, Any]]:
    return {
        "google_project_iam_custom_role.canary_operation_reader": {
            "permissions": ["run.operations.get"],
            "project": _PROJECT,
            "role_id": "reconcileP5CanaryOperationReader",
            "stage": "GA",
        },
        "google_project_iam_custom_role.canary_mutator": {
            "permissions": [
                "run.services.get",
                "run.services.update",
            ],
            "project": _PROJECT,
            "role_id": "reconcileP5CanaryMutator",
            "stage": "GA",
        },
        "google_project_iam_custom_role.canary_revision_reader": {
            "permissions": ["run.revisions.get"],
            "project": _PROJECT,
            "role_id": "reconcileP5CanaryRevisionReader",
            "stage": "GA",
        },
        "google_project_iam_custom_role.cloud_run_deployer": {
            "permissions": [
                "run.locations.list",
                "run.operations.get",
                "run.operations.list",
                "run.services.create",
                "run.services.delete",
                "run.services.get",
                "run.services.getIamPolicy",
                "run.services.list",
                "run.services.setIamPolicy",
                "run.services.update",
            ],
            "project": _PROJECT,
            "role_id": "reconcileP5CloudRunDeployer",
            "stage": "GA",
        },
    }


_CUSTOM_ROLE_EXPECTED = _custom_role_expectations()


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
        expected_provider = (
            _TERRAFORM_PROVIDER
            if resource.get("type") == "terraform_data"
            else _PROVIDER
        )
        if resource.get("provider_name") != expected_provider:
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
    for address in set(resources) & set(_CUSTOM_ROLE_EXPECTED):
        _expect_fields(
            resources[address]["change"]["after"],
            _CUSTOM_ROLE_EXPECTED[address],
            address,
        )


def _verify_project_services(resources: dict[str, dict[str, Any]]) -> None:
    expected = {
        **{
            f'google_project_service.bootstrap_required["{service}"]': service
            for service in _BOOTSTRAP_SERVICES
        },
        **{
            f'google_project_service.required["{service}"]': service
            for service in _FOUNDATION_SERVICES
        },
    }
    for address, resource in resources.items():
        if resource["type"] != "google_project_service":
            continue
        service = expected.get(address)
        if service is None:
            _fail(f"{address} enables an unapproved service")
        _expect_fields(
            resource["change"]["after"],
            {
                "deletion_policy": "DELETE",
                "disable_dependent_services": False,
                "disable_on_destroy": False,
                "project": _PROJECT,
                "service": service,
            },
            address,
        )


def _verify_service_accounts(resources: dict[str, dict[str, Any]]) -> None:
    expected = {
        "google_service_account.phase5_apply": ("rec-p5-apply", _APPLY_EMAIL),
        "google_service_account.phase5_operator": (
            "rec-p5-operator",
            _OPERATOR_EMAIL,
        ),
        **{
            f'google_service_account.runtime["{component}"]': (
                email.split("@", 1)[0],
                email,
            )
            for component, email in _RUNTIME_EMAILS.items()
        },
    }
    for address, resource in resources.items():
        if resource["type"] != "google_service_account":
            continue
        identity = expected.get(address)
        if identity is None:
            _fail(f"{address} creates an unapproved service account")
        account_id, email = identity
        _expect_fields(
            resource["change"]["after"],
            {
                "account_id": account_id,
                "create_ignore_already_exists": None,
                "deletion_policy": "DELETE",
                "disabled": False,
                "email": email,
                "member": f"serviceAccount:{email}",
                "project": _PROJECT,
            },
            address,
        )
    default_accounts = resources.get("google_project_default_service_accounts.phase5")
    if default_accounts is not None:
        _expect_fields(
            default_accounts["change"]["after"],
            {
                "action": "DEPRIVILEGE",
                "project": _PROJECT,
                "restore_policy": "REVERT",
            },
            "google_project_default_service_accounts.phase5",
        )


def _verify_default_service_account_policy(
    resources: dict[str, dict[str, Any]],
) -> None:
    address = (
        "google_project_organization_policy."
        "disable_automatic_default_service_account_grants"
    )
    policy = resources.get(address)
    if policy is None:
        return
    after = policy["change"]["after"]
    _expect_fields(
        after,
        {
            "constraint": "iam.automaticIamGrantsForDefaultServiceAccounts",
            "project": _PROJECT,
        },
        address,
    )
    if _one_block(after, "boolean_policy", address) != {"enforced": True}:
        _fail(f"{address} does not enforce the automatic-grant constraint")
    _require_disabled_fields(after, ("list_policy", "restore_policy"), address)


def _verify_production_guard(
    stack: _Stack,
    resources: dict[str, dict[str, Any]],
    plan: dict[str, Any],
) -> None:
    if stack.name not in {"foundation", "runtime"}:
        return
    profile = _rendered_variables(plan).get("operating_profile")
    if profile not in {"evidence", "production"}:
        _fail(f"{stack.name} operating profile is invalid")
    address = f"terraform_data.{stack.name}_production_guard[0]"
    guard = resources.get(address)
    if profile == "evidence":
        if guard is not None:
            _fail(f"{stack.name} evidence plan contains a production guard")
        return
    if guard is None:
        _fail(f"{stack.name} production plan lacks its destruction guard")
    after = guard["change"]["after"]
    _expect_fields(
        after,
        {
            "input": {
                "operating_profile": "production",
                "project_id": _PROJECT,
                "stack": stack.name,
            },
            "triggers_replace": None,
        },
        address,
    )


def _one_block(after: dict[str, Any], key: str, address: str) -> dict[str, Any]:
    value = after.get(key)
    if not isinstance(value, list) or len(value) != 1 or not isinstance(value[0], dict):
        _fail(f"{address} has an invalid {key} block")
    return value[0]


def _expect_fields(
    actual: dict[str, Any], expected: dict[str, Any], address: str
) -> None:
    for key, value in expected.items():
        if actual.get(key) != value:
            _fail(f"{address} has an unexpected {key}")


def _is_disabled(value: Any) -> bool:
    return value is None or value is False or value == [] or value == {}


def _require_disabled_fields(
    actual: dict[str, Any], fields: tuple[str, ...], address: str
) -> None:
    for field in fields:
        if not _is_disabled(actual.get(field)):
            _fail(f"{address} enables unapproved {field}")


def _rendered_variables(plan: dict[str, Any]) -> dict[str, Any]:
    variables = plan.get("variables")
    if not isinstance(variables, dict):
        _fail("Terraform plan variables are absent")
    rendered = {
        name: item.get("value")
        for name, item in variables.items()
        if isinstance(name, str) and isinstance(item, dict) and set(item) == {"value"}
    }
    if len(rendered) != len(variables):
        _fail("Terraform plan variables are malformed")
    return rendered


def _verify_cloud_run(
    resources: dict[str, dict[str, Any]], plan: dict[str, Any] | None = None
) -> None:
    if not any(
        resource["type"] == "google_cloud_run_v2_service"
        for resource in resources.values()
    ):
        return
    variables = (
        _rendered_variables(plan)
        if plan is not None
        else {
            "image_digest": _IMAGE_DIGEST,
            "infrastructure_revision": _INFRASTRUCTURE_REVISION,
            "recovery_definition_created_at": _RECOVERY_DEFINITION_CREATED_AT,
            "semantic_config_sha256": _SEMANTIC_CONFIG_SHA256,
            "source_revision": _SOURCE_REVISION,
            "vertex_location": "us",
            "vertex_model": "gemini-3.5-flash",
            "vertex_prompt_sha256": _VERTEX_PROMPT_SHA256,
            "vertex_prompt_version": _VERTEX_PROMPT_VERSION,
        }
    )
    image_digest = variables.get("image_digest")
    operating_profile = variables.get("operating_profile", "evidence")
    if (
        not isinstance(image_digest, str)
        or re.fullmatch(r"sha256:[0-9a-f]{64}", image_digest) is None
    ):
        _fail("runtime image digest variable is invalid")
    if operating_profile not in {"evidence", "production"}:
        _fail("runtime operating profile is invalid")
    production_profile = operating_profile == "production"
    image_reference = (
        f"{_REGION}-docker.pkg.dev/{_PROJECT}/reconcile-p5/reconcile@{image_digest}"
    )
    runtime_environment = copy.deepcopy(_RUNTIME_ENVIRONMENT)
    dynamic_environment = {
        "RECONCILE_IMAGE_DIGEST": image_digest,
        "RECONCILE_INFRA_REVISION": variables.get("infrastructure_revision"),
        "RECONCILE_SEMANTIC_CONFIG_SHA256": variables.get("semantic_config_sha256"),
        "RECONCILE_SOURCE_REVISION": variables.get("source_revision"),
        "RECONCILE_OPERATING_PROFILE": operating_profile,
    }
    for environment in runtime_environment.values():
        environment.update(dynamic_environment)
    runtime_environment["controller"].update(
        {
            "RECONCILE_VERTEX_LOCATION": variables.get("vertex_location"),
            "RECONCILE_VERTEX_MODEL": variables.get("vertex_model"),
            "RECONCILE_VERTEX_PROMPT_SHA256": variables.get("vertex_prompt_sha256"),
            "RECONCILE_VERTEX_PROMPT_VERSION": variables.get("vertex_prompt_version"),
        }
    )
    runtime_environment["canary"]["RECONCILE_CANARY_CONFIGURATION_SHA256"] = (
        variables.get("semantic_config_sha256")
    )
    timeout_values = variables.get("request_timeout_seconds")
    timeout = timeout_values.get("canary") if isinstance(timeout_values, dict) else 60
    if not isinstance(timeout, int):
        _fail("canary timeout identity is invalid")
    baseline_identity = _canary_baseline_identity(
        image_digest=image_digest,
        infrastructure_revision=str(variables.get("infrastructure_revision")),
        semantic_config_sha256=str(variables.get("semantic_config_sha256")),
        source_revision=str(variables.get("source_revision")),
        request_timeout_seconds=timeout,
    )
    baseline_revision = f"reconcile-p5-canary-b-{baseline_identity[:16]}"
    recovery_definition_created_at = variables.get("recovery_definition_created_at")
    if not isinstance(recovery_definition_created_at, str):
        _fail("recovery definition timestamp is invalid")
    try:
        parsed_recovery_timestamp = datetime.fromisoformat(
            recovery_definition_created_at.replace("Z", "+00:00")
        ).astimezone(UTC)
    except ValueError:
        _fail("recovery definition timestamp is invalid")
    timespec = "microseconds" if parsed_recovery_timestamp.microsecond else "seconds"
    if (
        parsed_recovery_timestamp.isoformat(timespec=timespec).replace("+00:00", "Z")
        != recovery_definition_created_at
    ):
        _fail("recovery definition timestamp is not canonical")
    recovery_release_id = f"p5-release-{str(variables.get('source_revision'))[:24]}"
    recovery_payload_sha256 = _recovery_payload_sha256(
        image_digest=image_digest,
        infrastructure_revision=str(variables.get("infrastructure_revision")),
        semantic_config_sha256=str(variables.get("semantic_config_sha256")),
        source_revision=str(variables.get("source_revision")),
        vertex_location=str(variables.get("vertex_location")),
        vertex_model=str(variables.get("vertex_model")),
        vertex_prompt_sha256=str(variables.get("vertex_prompt_sha256")),
        vertex_prompt_version=str(variables.get("vertex_prompt_version")),
    )
    trigger = resources.get("terraform_data.canary_baseline")
    if (
        trigger is None
        or trigger["change"]["after"].get("triggers_replace") != baseline_identity
    ):
        _fail("canary baseline replacement trigger is not content-addressed")
    runtime_environment["fault_proxy"]["RECONCILE_CANARY_BASELINE_REVISION"] = (
        baseline_revision
    )
    runtime_environment["controller"].update(
        {
            "RECONCILE_CANARY_BASELINE_REVISION": baseline_revision,
            "RECONCILE_RECOVERY_DEFINITION_CREATED_AT": recovery_definition_created_at,
            "RECONCILE_RECOVERY_PAYLOAD_SHA256": recovery_payload_sha256,
            "RECONCILE_RECOVERY_RELEASE_ID": recovery_release_id,
        }
    )
    images: set[str] = set()
    for component in _RUNTIME_EMAILS:
        address = f"google_cloud_run_v2_service.{component}"
        after = resources[address]["change"]["after"]
        _expect_fields(
            after,
            {
                "custom_audiences": [_AUDIENCES[component]],
                "deletion_policy": "ABANDON" if production_profile else "DELETE",
                "deletion_protection": production_profile,
                "ingress": "INGRESS_TRAFFIC_ALL",
                "invoker_iam_disabled": False,
                "labels": {
                    "app": "reconcile",
                    "component": component.replace("_", "-"),
                    "environment": "phase5",
                    "operating_profile": operating_profile,
                },
                "location": _REGION,
                "name": _SERVICE_NAMES[component],
                "project": _PROJECT,
            },
            address,
        )
        _require_disabled_fields(
            after,
            (
                "annotations",
                "binary_authorization",
                "build_config",
                "default_uri_disabled",
                "iap_enabled",
                "multi_region_settings",
                "tags",
            ),
            address,
        )
        template = _one_block(after, "template", address)
        _expect_fields(
            template,
            {
                "execution_environment": "EXECUTION_ENVIRONMENT_GEN2",
                "max_instance_request_concurrency": (
                    8
                    if production_profile and component in {"api", "controller"}
                    else 1
                ),
                "service_account": _RUNTIME_EMAILS[component],
                "timeout": _SERVICE_TIMEOUTS[component],
            },
            f"{address}.template",
        )
        if component == "canary":
            _expect_fields(
                template,
                {
                    "annotations": {
                        "reconcile.dev/configuration-sha256": variables.get(
                            "semantic_config_sha256"
                        )
                    },
                    "labels": {"reconcile-release": "baseline"},
                    "revision": baseline_revision,
                },
                f"{address}.template",
            )
            _require_disabled_fields(
                template,
                (
                    "encryption_key",
                    "health_check_disabled",
                    "node_selector",
                    "session_affinity",
                    "volumes",
                    "vpc_access",
                ),
                f"{address}.template",
            )
        else:
            _require_disabled_fields(
                template,
                (
                    "annotations",
                    "encryption_key",
                    "health_check_disabled",
                    "labels",
                    "node_selector",
                    "revision",
                    "session_affinity",
                    "volumes",
                    "vpc_access",
                ),
                f"{address}.template",
            )
        scaling = _one_block(template, "scaling", address)
        expected_min = (
            1 if production_profile and component in {"api", "controller"} else 0
        )
        expected_max = (
            3 if production_profile and component in {"api", "controller"} else 1
        )
        if (
            scaling.get("min_instance_count") != expected_min
            or scaling.get("max_instance_count") != expected_max
        ):
            _fail(f"{address} has unbounded scaling")
        container = _one_block(template, "containers", address)
        image = container.get("image")
        pattern = (
            rf"^{re.escape(_REGION)}-docker[.]pkg[.]dev/{re.escape(_PROJECT)}/"
            rf"reconcile-p5/reconcile@sha256:[0-9a-f]{{64}}$"
        )
        if (
            not isinstance(image, str)
            or re.fullmatch(pattern, image) is None
            or image != image_reference
        ):
            _fail(f"{address} has a mutable or external image")
        images.add(image)
        if component == "canary":
            if container.get("command") != [
                "/opt/reconcile/bin/python"
            ] or container.get("args") != ["-m", "reconcile.hosted.cloud_run_canary"]:
                _fail(f"{address} does not use the sealed canary entrypoint")
        elif container.get("args") not in (None, []) or container.get(
            "command"
        ) not in (None, []):
            _fail(f"{address} overrides its image-owned command")
        _expect_fields(
            container,
            {
                "name": _SERVICE_CONTAINERS[component],
                "ports": [{"container_port": 8080, "name": "http1"}],
            },
            f"{address}.container",
        )
        _require_disabled_fields(
            container,
            (
                "base_image_uri",
                "depends_on",
                "liveness_probe",
                "readiness_probe",
                "sandbox_launcher",
                "volume_mounts",
                "working_dir",
            ),
            f"{address}.container",
        )
        container_resources = _one_block(container, "resources", address)
        _expect_fields(
            container_resources,
            {
                "cpu_idle": True,
                "limits": {"cpu": "1", "memory": _SERVICE_MEMORY[component]},
                "startup_cpu_boost": False,
            },
            f"{address}.container.resources",
        )
        environments = container.get("env") or []
        environment_by_name = {
            environment.get("name"): environment for environment in environments
        }
        if len(environment_by_name) != len(environments) or set(
            environment_by_name
        ) != set(runtime_environment[component]):
            _fail(f"{address} has an unexpected environment contract")
        for name, environment in environment_by_name.items():
            name = environment.get("name")
            if not isinstance(name, str) or _SECRET_KEY.search(name):
                _fail(f"{address} has a secret-bearing environment name")
            expected_value = runtime_environment[component][name]
            actual_value = environment.get("value")
            if expected_value is None:
                if actual_value is not None:
                    _fail(f"{address} has an unexpected computed endpoint")
            elif actual_value != expected_value:
                _fail(f"{address} has an unexpected environment value")
            if environment.get("value_source") not in (None, []):
                _fail(f"{address} has an undeclared environment value source")
        traffic = after.get("traffic")
        if component == "canary":
            if traffic != [
                {
                    "percent": 100,
                    "revision": baseline_revision,
                    "tag": None,
                    "type": "TRAFFIC_TARGET_ALLOCATION_TYPE_REVISION",
                }
            ]:
                _fail(f"{address} does not pin baseline canary traffic")
        elif not _is_disabled(traffic):
            _fail(f"{address} has an undeclared traffic override")
    if images != {image_reference}:
        _fail("runtime does not use exactly one approved image digest")


def _verify_storage(
    resources: dict[str, dict[str, Any]],
    plan: dict[str, Any] | None = None,
) -> None:
    variables = _rendered_variables(plan) if plan is not None else {}
    operating_profile = variables.get("operating_profile", "evidence")
    if operating_profile not in {"evidence", "production"}:
        _fail("storage operating profile is invalid")
    production_profile = operating_profile == "production"
    expected = {
        "google_storage_bucket.terraform_state": {
            "component": "terraform-state",
            "deletion_policy": "PREVENT",
            "force_destroy": False,
            "name": _STATE_BUCKET,
            "versioning": [{"enabled": True}],
        },
        "google_storage_bucket.target": {
            "component": "target",
            "deletion_policy": "PREVENT" if production_profile else "DELETE",
            "force_destroy": not production_profile,
            "name": _TARGET_BUCKET,
            "versioning": [{"enabled": production_profile}],
        },
    }
    for address in set(expected) & set(resources):
        after = resources[address]["change"]["after"]
        contract = expected[address]
        labels = {
            "app": "reconcile",
            "component": contract["component"],
            "environment": "phase5",
        }
        if address == "google_storage_bucket.target":
            labels["operating_profile"] = operating_profile
        _expect_fields(
            after,
            {
                "deletion_policy": contract["deletion_policy"],
                "force_destroy": contract["force_destroy"],
                "labels": labels,
                "location": "US-CENTRAL1",
                "name": contract["name"],
                "project": _PROJECT,
                "public_access_prevention": "enforced",
                "soft_delete_policy": [
                    {
                        "retention_duration_seconds": (
                            604_800
                            if production_profile
                            and address == "google_storage_bucket.target"
                            else 0
                        )
                    }
                ],
                "storage_class": "STANDARD",
                "uniform_bucket_level_access": True,
                "versioning": contract["versioning"],
            },
            address,
        )
        _require_disabled_fields(
            after,
            (
                "autoclass",
                "cors",
                "custom_placement_config",
                "default_event_based_hold",
                "enable_object_retention",
                "encryption",
                "hierarchical_namespace",
                "ip_filter",
                "lifecycle_rule",
                "logging",
                "requester_pays",
                "retention_policy",
            ),
            address,
        )


def _verify_foundation(
    resources: dict[str, dict[str, Any]],
    plan: dict[str, Any] | None = None,
) -> None:
    if "google_artifact_registry_repository.runtime" not in resources:
        return
    variables = _rendered_variables(plan) if plan is not None else {}
    operating_profile = variables.get("operating_profile", "evidence")
    if operating_profile not in {"evidence", "production"}:
        _fail("foundation operating profile is invalid")
    production_profile = operating_profile == "production"
    database_names = {
        'google_firestore_database.phase5["runtime"]': "reconcile-p5-runtime",
        'google_firestore_database.phase5["sandbox"]': _SANDBOX_DATABASE,
        'google_firestore_database.phase5["target"]': "reconcile-p5-target",
    }
    for address, name in database_names.items():
        database = resources[address]["change"]["after"]
        _expect_fields(
            database,
            {
                "app_engine_integration_mode": "DISABLED",
                "concurrency_mode": "OPTIMISTIC",
                "database_edition": "STANDARD",
                "delete_protection_state": (
                    "DELETE_PROTECTION_ENABLED"
                    if production_profile
                    else "DELETE_PROTECTION_DISABLED"
                ),
                "deletion_policy": "ABANDON" if production_profile else "DELETE",
                "location_id": _REGION,
                "name": name,
                "point_in_time_recovery_enablement": (
                    "POINT_IN_TIME_RECOVERY_ENABLED"
                    if production_profile
                    else "POINT_IN_TIME_RECOVERY_DISABLED"
                ),
                "project": _PROJECT,
                "type": "FIRESTORE_NATIVE",
            },
            address,
        )
        _require_disabled_fields(database, ("cmek_config", "tags"), address)
    repository = resources["google_artifact_registry_repository.runtime"]["change"][
        "after"
    ]
    repository_address = "google_artifact_registry_repository.runtime"
    _expect_fields(
        repository,
        {
            "cleanup_policy_dry_run": False,
            "deletion_policy": "DELETE",
            "description": "RECONCILE Phase 5 runtime images",
            "format": "DOCKER",
            "labels": {
                "app": "reconcile",
                "component": "runtime-images",
                "environment": "phase5",
                "operating_profile": operating_profile,
            },
            "location": _REGION,
            "mode": "STANDARD_REPOSITORY",
            "project": _PROJECT,
            "repository_id": "reconcile-p5",
        },
        repository_address,
    )
    _require_disabled_fields(
        repository,
        (
            "kms_key_name",
            "maven_config",
            "remote_repository_config",
            "virtual_repository_config",
        ),
        repository_address,
    )
    docker = _one_block(
        repository,
        "docker_config",
        repository_address,
    )
    if docker != {"immutable_tags": True}:
        _fail("artifact Docker configuration is not the approved immutable contract")
    cleanup_policies = repository.get("cleanup_policies")
    if not isinstance(cleanup_policies, list) or any(
        not isinstance(policy, dict) for policy in cleanup_policies
    ):
        _fail("artifact cleanup policies are malformed")
    cleanup_by_id = {policy.get("id"): policy for policy in cleanup_policies}
    expected_cleanup = {
        "delete-old-untagged": {
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
        "keep-at-least-two-recent": {
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
    }
    if len(cleanup_by_id) != len(cleanup_policies) or cleanup_by_id != expected_cleanup:
        _fail("artifact cleanup policies are not the approved bounded contract")
    budget = resources["google_billing_budget.phase5"]["change"]["after"]
    budget_address = "google_billing_budget.phase5"
    _expect_fields(
        budget,
        {
            "all_updates_rule": [],
            "billing_account": _BILLING_ACCOUNT,
            "budget_filter": [
                {
                    "calendar_period": None,
                    "credit_types": None,
                    "credit_types_treatment": "EXCLUDE_ALL_CREDITS",
                    "custom_period": [],
                    "projects": [f"projects/{_PROJECT_NUMBER}"],
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
        budget_address,
    )
    amount = _one_block(budget, "amount", "google_billing_budget.phase5")
    specified = _one_block(amount, "specified_amount", "google_billing_budget.phase5")
    if amount.get("last_period_amount") is not None or specified != {
        "currency_code": "USD",
        "nanos": None,
        "units": "5",
    }:
        _fail("billing budget is not exactly USD 5")


def _verify_observability(
    resources: dict[str, dict[str, Any]],
    plan: dict[str, Any] | None = None,
) -> None:
    if "google_monitoring_dashboard.operational" not in resources:
        return
    variables = _rendered_variables(plan) if plan is not None else {}
    operating_profile = variables.get("operating_profile", "evidence")
    notification_channels = variables.get("notification_channel_ids", [])
    if (
        not isinstance(notification_channels, list)
        or notification_channels != sorted(set(notification_channels))
        or any(
            not isinstance(channel, str)
            or re.fullmatch(
                rf"projects/{re.escape(_PROJECT)}/notificationChannels/[0-9]+",
                channel,
            )
            is None
            for channel in notification_channels
        )
        or (operating_profile == "production" and not notification_channels)
        or (operating_profile == "evidence" and bool(notification_channels))
    ):
        _fail("runtime notification channels are invalid")
    labels = {
        "app": "reconcile",
        "environment": "phase5",
        "operating_profile": operating_profile,
    }
    expected_filters: set[str] = set()
    for key, signal in _OPERATIONAL_SIGNALS.items():
        metric_address = f'google_logging_metric.operational_failure["{key}"]'
        metric = resources[metric_address]["change"]["after"]
        metric_name = f"reconcile_p5_{key}"
        log_filter = (
            'resource.type="cloud_run_revision" AND '
            'jsonPayload.schema_version="reconcile/operational-event/v2" AND '
            'jsonPayload.event="operational-signal" AND '
            f'jsonPayload.signal="{signal}"'
        )
        _expect_fields(
            metric,
            {
                "bucket_name": None,
                "bucket_options": [],
                "deletion_policy": "DELETE",
                "description": (
                    f"Count of bounded Reconcile {signal} operational signals."
                ),
                "disabled": False,
                "filter": log_filter,
                "label_extractors": None,
                "name": metric_name,
                "project": _PROJECT,
                "value_extractor": None,
            },
            metric_address,
        )
        descriptor = _one_block(metric, "metric_descriptor", metric_address)
        if descriptor != {
            "display_name": f"Reconcile {signal}",
            "labels": [],
            "metric_kind": "DELTA",
            "unit": "1",
            "value_type": "INT64",
        }:
            _fail(f"{metric_address} descriptor drifted")

        metric_filter = (
            'resource.type = "cloud_run_revision" AND '
            f'metric.type = "logging.googleapis.com/user/{metric_name}"'
        )
        expected_filters.add(metric_filter)
        policy_address = f'google_monitoring_alert_policy.operational_failure["{key}"]'
        policy = resources[policy_address]["change"]["after"]
        _expect_fields(
            policy,
            {
                "alert_strategy": [],
                "combiner": "OR",
                "deletion_policy": "DELETE",
                "display_name": f"Reconcile {signal}",
                "enabled": True,
                "notification_channels": (
                    notification_channels if operating_profile == "production" else []
                ),
                "project": _PROJECT,
                "severity": (
                    "ERROR" if key in {"failed_run", "worker_failure"} else "WARNING"
                ),
                "user_labels": labels,
            },
            policy_address,
        )
        condition = _one_block(policy, "conditions", policy_address)
        _expect_fields(
            condition,
            {"display_name": f"{signal} observed"},
            f"{policy_address}.conditions",
        )
        threshold = _one_block(
            condition,
            "condition_threshold",
            f"{policy_address}.conditions",
        )
        _expect_fields(
            threshold,
            {
                "comparison": "COMPARISON_GT",
                "duration": "0s",
                "filter": metric_filter,
                "threshold_value": 0,
                "trigger": [{"count": 1, "percent": None}],
            },
            f"{policy_address}.condition_threshold",
        )
        aggregation = _one_block(
            threshold,
            "aggregations",
            f"{policy_address}.condition_threshold",
        )
        _expect_fields(
            aggregation,
            {
                "alignment_period": "300s",
                "cross_series_reducer": "REDUCE_SUM",
                "group_by_fields": None,
                "per_series_aligner": "ALIGN_DELTA",
            },
            f"{policy_address}.aggregations",
        )
        documentation = _one_block(policy, "documentation", policy_address)
        _expect_fields(
            documentation,
            {
                "content": (
                    f"A bounded Reconcile {signal} signal was emitted by a hosted "
                    "runtime component. Correlate with correlation_id in Cloud Logging."
                ),
                "links": [],
                "mime_type": "text/markdown",
                "subject": None,
            },
            f"{policy_address}.documentation",
        )

    dashboard_address = "google_monitoring_dashboard.operational"
    dashboard = resources[dashboard_address]["change"]["after"]
    _expect_fields(
        dashboard,
        {"deletion_policy": "DELETE", "project": _PROJECT},
        dashboard_address,
    )
    try:
        definition = json.loads(dashboard.get("dashboard_json"))
        layout = definition["mosaicLayout"]
        tiles = layout["tiles"]
    except (KeyError, TypeError, ValueError):
        _fail("operational dashboard definition is malformed")
    if (
        definition.get("displayName") != "Reconcile Phase 5 operational signals"
        or definition.get("labels") != labels
        or layout.get("columns") != 12
        or not isinstance(tiles, list)
        or len(tiles) != len(_OPERATIONAL_SIGNALS)
    ):
        _fail("operational dashboard definition drifted")
    observed_filters: set[str] = set()
    observed_titles: set[str] = set()
    try:
        for tile in tiles:
            widget = tile["widget"]
            scorecard = widget["scorecard"]
            query = scorecard["timeSeriesQuery"]["timeSeriesFilter"]
            if (
                tile["width"] != 4
                or tile["height"] != 4
                or scorecard["sparkChartType"] != "SPARK_LINE"
                or query["aggregation"]
                != {
                    "alignmentPeriod": "300s",
                    "crossSeriesReducer": "REDUCE_SUM",
                    "perSeriesAligner": "ALIGN_DELTA",
                }
            ):
                _fail("operational dashboard tile drifted")
            observed_titles.add(widget["title"])
            observed_filters.add(query["filter"])
    except (KeyError, TypeError):
        _fail("operational dashboard tile is malformed")
    if observed_titles != set(_OPERATIONAL_SIGNALS.values()) or (
        observed_filters != expected_filters
    ):
        _fail("operational dashboard coverage drifted")


def _resource_semantics_digest(resources: dict[str, dict[str, Any]]) -> str:
    canonical_resources = [resources[address] for address in sorted(resources)]
    encoded = json.dumps(
        canonical_resources,
        allow_nan=False,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def verify_create_plan(stack: _Stack, plan: dict[str, Any]) -> str:
    _verify_plan_envelope(stack, plan)
    resources = _resources(plan)
    _verify_inventory(stack, resources)
    _verify_iam(resources)
    _verify_project_services(resources)
    _verify_service_accounts(resources)
    _verify_default_service_account_policy(resources)
    _verify_production_guard(stack, resources, plan)
    _verify_cloud_run(resources, plan)
    _verify_storage(resources, plan)
    _verify_foundation(resources, plan)
    _verify_observability(resources, plan)
    return _resource_semantics_digest(resources)


def _operator_stacks(
    runtime_identity: dict[str, Any] | None,
    source_root: Path | None = None,
) -> tuple[_Stack, ...]:
    root = _ROOT if source_root is None else source_root
    base_stacks = tuple(
        _Stack(
            name=stack.name,
            source=root / stack.source.relative_to(_ROOT),
            addresses=stack.addresses,
            variables=stack.variables,
        )
        for stack in _STACKS
    )
    if runtime_identity is None:
        return base_stacks
    required = {
        "image_digest",
        "infrastructure_revision",
        "recovery_definition_created_at",
        "semantic_config_sha256",
        "source_revision",
        "vertex_prompt_sha256",
        "vertex_prompt_version",
    }
    if set(runtime_identity) != required:
        _fail("operator runtime identity is incomplete")
    if (
        re.fullmatch(r"sha256:[0-9a-f]{64}", runtime_identity["image_digest"]) is None
        or re.fullmatch(r"[0-9a-f]{64}", runtime_identity["infrastructure_revision"])
        is None
        or not isinstance(runtime_identity["recovery_definition_created_at"], str)
        or re.fullmatch(
            r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:[.][0-9]{6})?Z",
            runtime_identity["recovery_definition_created_at"],
        )
        is None
        or re.fullmatch(r"[0-9a-f]{64}", runtime_identity["semantic_config_sha256"])
        is None
        or re.fullmatch(r"[0-9a-f]{40}", runtime_identity["source_revision"]) is None
        or re.fullmatch(r"[0-9a-f]{64}", runtime_identity["vertex_prompt_sha256"])
        is None
        or not isinstance(runtime_identity["vertex_prompt_version"], str)
        or not runtime_identity["vertex_prompt_version"]
    ):
        _fail("operator runtime identity is invalid")
    stacks: list[_Stack] = []
    for stack in base_stacks:
        if stack.name != "runtime":
            stacks.append(stack)
            continue
        stacks.append(
            _Stack(
                name=stack.name,
                source=stack.source,
                addresses=stack.addresses,
                variables=stack.variables | runtime_identity,
            )
        )
    return tuple(stacks)


def _operator_plan_projection(plan: dict[str, Any]) -> dict[str, Any]:
    resources = plan.get("resource_changes")
    if not isinstance(resources, list) or not resources:
        _fail("operator qualification plan has no resources")
    projected: list[dict[str, Any]] = []
    for resource in resources:
        if not isinstance(resource, dict) or not isinstance(
            resource.get("change"), dict
        ):
            _fail("operator qualification resource is malformed")
        change = resource["change"]
        projected.append(
            {
                "address": resource.get("address"),
                "change": {
                    "actions": change.get("actions"),
                    "after": change.get("after"),
                    "after_sensitive": change.get("after_sensitive"),
                    "after_unknown": change.get("after_unknown"),
                    "before": change.get("before"),
                    "before_sensitive": change.get("before_sensitive"),
                },
                "provider_name": resource.get("provider_name"),
                "type": resource.get("type"),
            }
        )
    return {
        "resource_changes": projected,
        "terraform_version": plan.get("terraform_version"),
        "variables": {
            name: {"value": value}
            for name, value in sorted(_rendered_variables(plan).items())
        },
    }


def _destroy_projection(
    create_plan: dict[str, Any],
    *,
    enable_state_bucket_destroy: bool = False,
) -> dict[str, Any]:
    projected = copy.deepcopy(create_plan)
    variables = _rendered_variables(projected)
    if enable_state_bucket_destroy:
        variables["allow_state_bucket_destroy"] = True
    projected["variables"] = {
        name: {"value": value} for name, value in sorted(variables.items())
    }
    for resource in projected["resource_changes"]:
        source_change = resource["change"]
        after = copy.deepcopy(source_change.get("after"))
        after_unknown = copy.deepcopy(source_change.get("after_unknown"))
        after_sensitive = copy.deepcopy(source_change.get("after_sensitive"))
        if (
            enable_state_bucket_destroy
            and resource["address"] == "google_storage_bucket.terraform_state"
        ):
            if not isinstance(after, dict):
                _fail("state bucket qualification value is malformed")
            after["deletion_policy"] = "DELETE"
            after["force_destroy"] = True
        resource["change"] = {
            "actions": ["delete"],
            "after": None,
            "before": after,
        }
        if after_unknown is not None:
            resource["change"]["reconcile_before_unknown"] = after_unknown
        if after_sensitive is not None:
            resource["change"]["reconcile_before_sensitive"] = after_sensitive
    return projected


def _state_protection_projection(create_plan: dict[str, Any]) -> dict[str, Any]:
    return _destroy_projection(create_plan, enable_state_bucket_destroy=True)


def _write_immutable_json(path: Path, value: object) -> None:
    payload = json.dumps(
        value,
        allow_nan=False,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    descriptor = os.open(
        path,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW,
        0o600,
    )
    try:
        view = memoryview(payload)
        while view:
            written = os.write(descriptor, view)
            if written < 1:
                raise RuntimeError("operator artifact write did not progress")
            view = view[written:]
        os.fsync(descriptor)
        os.fchmod(descriptor, 0o400)
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _write_operator_artifacts(
    destination: Path,
    create_plans: dict[str, dict[str, Any]],
) -> None:
    if not destination.is_absolute():
        _fail("operator artifact directory must be absolute")
    target = destination.resolve(strict=False)
    if target != destination.absolute():
        _fail("operator artifact directory must be canonical")
    if not target.exists():
        target.mkdir(mode=0o700)
    metadata = os.lstat(target)
    if (
        not target.is_dir()
        or target.is_symlink()
        or metadata.st_uid != os.getuid()
        or stat.S_IMODE(metadata.st_mode) != 0o700
        or any(target.iterdir())
    ):
        _fail("operator artifact directory must be empty and private")
    qualifications = {
        "bootstrap-create": create_plans["bootstrap"],
        "foundation-create": create_plans["foundation"],
        "runtime-create": create_plans["runtime"],
        "runtime-destroy": _destroy_projection(create_plans["runtime"]),
        "foundation-destroy": _destroy_projection(create_plans["foundation"]),
        "bootstrap-disable-protection": _state_protection_projection(
            create_plans["bootstrap"]
        ),
        "bootstrap-destroy": _destroy_projection(
            create_plans["bootstrap"], enable_state_bucket_destroy=True
        ),
    }
    for stem, qualification in qualifications.items():
        variables = _rendered_variables(qualification)
        _write_immutable_json(target / f"{stem}.tfplan.json", qualification)
        _write_immutable_json(target / f"{stem}.tfvars.json", variables)
    directory = os.open(
        target,
        os.O_RDONLY | os.O_CLOEXEC | os.O_DIRECTORY | os.O_NOFOLLOW,
    )
    try:
        os.fsync(directory)
    finally:
        os.close(directory)


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
            r"(?m)^\s*(?:action_trigger|import|moved|postcondition|precondition|removed)\s*\{",
            configuration,
        ):
            _fail(f"{stack.name} contains an undeclared Terraform construct")
        lifecycle_blocks = tuple(
            " ".join(item.split())
            for item in re.findall(r"(?ms)^\s*lifecycle\s*\{([^{}]*)\}", configuration)
        )
        if lifecycle_blocks:
            expected = (
                {
                    "ignore_changes = [template, traffic] "
                    "replace_triggered_by = [terraform_data.canary_baseline]": 1,
                }
                if stack.name == "runtime" and source.name == "cloud_run.tf"
                else {
                    "replace_triggered_by = [terraform_data.canary_baseline]": 3,
                }
                if stack.name == "runtime" and source.name == "invocation_iam.tf"
                else {"prevent_destroy = true": 1}
                if stack.name in {"foundation", "runtime"}
                and source.name == "profile_guard.tf"
                else {}
            )
            actual = {
                value: lifecycle_blocks.count(value) for value in set(lifecycle_blocks)
            }
            if actual != expected:
                _fail(f"{stack.name} contains an unapproved lifecycle block")
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
        copied = destination / source.name
        shutil.copy2(source, copied)
        copied.chmod(0o600)
    copied_lock = destination / ".terraform.lock.hcl"
    shutil.copy2(stack.source / ".terraform.lock.hcl", copied_lock)
    copied_lock.chmod(0o600)
    versions = destination / "versions.tf"
    source = versions.read_text(encoding="utf-8")
    if stack.name == "bootstrap":
        backend = re.compile(r'(?ms)^\s*backend "local" \{.*?^\s*\}')
        matches = backend.findall(source)
        if len(matches) != 1:
            _fail("bootstrap local backend block is not unique")
        block = matches[0]
        assignments = re.findall(r"(?m)^\s*([a-z_]+)\s*=", block)
        if assignments:
            _fail("bootstrap local backend path drifted")
        return
    backend = 'backend "gcs" {}'
    if source.count(backend) != 1:
        _fail(f"{stack.name} backend block is not unique")
    versions.write_text(source.replace(backend, 'backend "local" {}'), encoding="utf-8")
    provider = destination / "providers.tf"
    source = provider.read_text(encoding="utf-8")
    impersonation = (
        "  impersonate_service_account = var.apply_service_account_email\n"
        if stack.name == "runtime"
        else (
            '  impersonate_service_account = "rec-p5-apply@'
            '${var.project_id}.iam.gserviceaccount.com"\n'
        )
    )
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
        stdout = result.stdout.strip()[-4_096:] or "<empty>"
        stderr = result.stderr.strip()[-4_096:] or "<empty>"
        raise RuntimeError(
            f"subprocess failed with exit code {result.returncode}; "
            f"stdout={stdout!r}; stderr={stderr!r}"
        )
    return result


def _offline_command(
    command: list[str], working_directory: Path, *, bwrap: Path | None = None
) -> list[str]:
    resolved_bwrap = str(bwrap) if bwrap is not None else shutil.which("bwrap")
    if resolved_bwrap is None:
        raise RuntimeError("bwrap is unavailable for network-isolated plans")
    temporary_directory = working_directory.parent / "tmp"
    return [
        resolved_bwrap,
        "--die-with-parent",
        "--new-session",
        "--unshare-net",
        "--ro-bind",
        "/",
        "/",
        "--bind",
        str(working_directory.parent),
        str(working_directory.parent),
        "--setenv",
        "TMPDIR",
        str(temporary_directory),
        "--dev",
        "/dev",
        "--proc",
        "/proc",
        "--chdir",
        str(working_directory),
        *command,
    ]


def _bubblewrap_usable(bwrap: Path) -> bool:
    try:
        result = subprocess.run(
            [
                str(bwrap),
                "--die-with-parent",
                "--new-session",
                "--unshare-net",
                "--ro-bind",
                "/",
                "/",
                "--dev",
                "/dev",
                "--proc",
                "/proc",
                "/bin/true",
            ],
            check=False,
            capture_output=True,
            env=_minimal_environment(network=False),
            text=True,
            timeout=10,
        )
    except (OSError, subprocess.TimeoutExpired):
        return False
    return result.returncode == 0


def _docker_environment(root: Path) -> dict[str, str]:
    environment = _minimal_environment(network=False)
    docker_host = os.environ.get("DOCKER_HOST")
    if docker_host:
        environment["DOCKER_HOST"] = docker_host
    environment["DOCKER_CONFIG"] = str(root / "docker-config")
    environment["HOME"] = str(root)
    environment["NO_PROXY"] = "127.0.0.1,localhost"
    return environment


def _select_offline_backend(root: Path) -> tuple[str, Path]:
    bwrap = shutil.which("bwrap")
    if bwrap is not None and _bubblewrap_usable(Path(bwrap)):
        return "bubblewrap", Path(bwrap)

    docker = shutil.which("docker")
    if docker is None:
        raise RuntimeError(
            "network-isolated plans require usable bwrap or a Docker daemon"
        )
    (root / "docker-config").mkdir(mode=0o700)
    environment = _docker_environment(root)
    present = _run(
        [docker, "image", "inspect", _OFFLINE_DOCKER_IMAGE],
        environment=environment,
        expected=frozenset({0, 1}),
    )
    if present.returncode == 1:
        _run(
            [docker, "pull", _OFFLINE_DOCKER_IMAGE],
            environment=environment,
        )
    return "docker", Path(docker)


def _docker_offline_command(
    command: list[str],
    working_directory: Path,
    *,
    docker: Path,
    environment: dict[str, str],
    read_only_paths: tuple[Path, ...],
) -> list[str]:
    if not command:
        raise RuntimeError("offline command is empty")
    root = working_directory.parent.resolve()
    executable = Path(command[0]).resolve()
    container_executable = Path("/reconcile-bin") / executable.name
    invocation = [
        str(docker),
        "run",
        "--rm",
        "--network",
        "none",
        "--read-only",
        "--cap-drop",
        "ALL",
        "--security-opt",
        "no-new-privileges",
        "--pids-limit",
        "256",
        "--memory",
        "1536m",
        "--cpus",
        "1.0",
        "--user",
        f"{os.getuid()}:{os.getgid()}",
        "--volume",
        f"{root}:{root}:rw",
        "--volume",
        f"{executable}:{container_executable}:ro",
        "--workdir",
        str(working_directory.resolve()),
    ]
    for path in sorted({item.resolve() for item in read_only_paths}):
        invocation.extend(["--volume", f"{path}:{path}:ro"])
    for name, value in sorted(environment.items()):
        invocation.extend(["--env", f"{name}={value}"])
    return [
        *invocation,
        _OFFLINE_DOCKER_IMAGE,
        str(container_executable),
        *command[1:],
    ]


def _run_offline(
    command: list[str],
    *,
    working_directory: Path,
    environment: dict[str, str],
    backend: tuple[str, Path],
    read_only_paths: tuple[Path, ...],
    expected: frozenset[int] = frozenset({0}),
) -> subprocess.CompletedProcess[str]:
    kind, executable = backend
    if kind == "bubblewrap":
        invocation = _offline_command(
            command,
            working_directory,
            bwrap=executable,
        )
        host_environment = environment
    elif kind == "docker":
        invocation = _docker_offline_command(
            command,
            working_directory,
            docker=executable,
            environment=environment,
            read_only_paths=read_only_paths,
        )
        host_environment = _docker_environment(working_directory.parent)
    else:
        raise RuntimeError(f"unsupported offline backend: {kind}")
    return _run(invocation, environment=host_environment, expected=expected)


def _minimal_environment(*, network: bool) -> dict[str, str]:
    environment = {
        "CHECKPOINT_DISABLE": "1",
        "LANG": os.environ.get("LANG", "C.UTF-8"),
        "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
        "TF_IN_AUTOMATION": "1",
        "TF_INPUT": "0",
    }
    terraform_cli_config = os.environ.get("TF_CLI_CONFIG_FILE")
    if terraform_cli_config:
        environment["TF_CLI_CONFIG_FILE"] = terraform_cli_config
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


def _verify_production_transition_guards(
    terraform: Path,
    stack: _Stack,
    working: Path,
    *,
    environment: dict[str, str],
    backend: tuple[str, Path],
    read_only_paths: tuple[Path, ...],
) -> None:
    if (
        stack.name not in {"foundation", "runtime"}
        or stack.variables.get("operating_profile") != "production"
    ):
        return
    guard = f"terraform_data.{stack.name}_production_guard[0]"
    _run_offline(
        [
            str(terraform),
            f"-chdir={working}",
            "apply",
            "-auto-approve",
            "-input=false",
            "-lock=false",
            "-no-color",
            "-refresh=false",
            f"-target={guard}",
        ],
        working_directory=working,
        environment=environment,
        backend=backend,
        read_only_paths=read_only_paths,
    )
    destroy = _run_offline(
        [
            str(terraform),
            f"-chdir={working}",
            "plan",
            "-destroy",
            "-input=false",
            "-lock=false",
            "-no-color",
            "-refresh=false",
        ],
        working_directory=working,
        environment=environment,
        backend=backend,
        read_only_paths=read_only_paths,
        expected=frozenset({1}),
    )
    if "Instance cannot be destroyed" not in destroy.stdout + destroy.stderr:
        _fail(f"{stack.name} production destroy did not fail on its state guard")

    downgraded = dict(stack.variables)
    downgraded["operating_profile"] = "evidence"
    if stack.name == "runtime":
        downgraded["notification_channel_ids"] = []
    (working / "terraform.tfvars.json").write_text(
        json.dumps(downgraded),
        encoding="utf-8",
    )
    downgrade = _run_offline(
        [
            str(terraform),
            f"-chdir={working}",
            "plan",
            "-input=false",
            "-lock=false",
            "-no-color",
            "-refresh=false",
        ],
        working_directory=working,
        environment=environment,
        backend=backend,
        read_only_paths=read_only_paths,
        expected=frozenset({1}),
    )
    if "Instance cannot be destroyed" not in downgrade.stdout + downgrade.stderr:
        _fail(f"{stack.name} profile downgrade did not fail on its state guard")


def _verify_provider_mirror(provider_mirror: Path) -> Path:
    provider_mirror = provider_mirror.resolve()
    google_mirror = provider_mirror / "registry.terraform.io" / "hashicorp" / "google"
    if not google_mirror.is_dir() or not any(
        "7.44.0" in path.name for path in google_mirror.rglob("*")
    ):
        raise RuntimeError("the Google provider 7.44.0 mirror is unavailable")
    return provider_mirror


def _create_provider_mirror(
    terraform: Path,
    root: Path,
    source_root: Path | None = None,
) -> Path:
    mirror_configuration = root / "mirror-configuration"
    mirror_configuration.mkdir()
    (mirror_configuration / "versions.tf").write_text(
        'terraform {\n  required_version = "= 1.15.8"\n'
        '  required_providers {\n    google = {\n      source = "hashicorp/google"\n'
        '      version = "= 7.44.0"\n    }\n  }\n}\n',
        encoding="utf-8",
    )
    shutil.copy2(
        (source_root or _ROOT) / "infra" / "bootstrap" / ".terraform.lock.hcl",
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


def _offline_create(
    terraform: Path,
    provider_mirror: Path | None,
    *,
    artifact_output: Path | None = None,
    runtime_identity: dict[str, Any] | None = None,
    source_root: Path | None = None,
) -> None:
    stacks = _operator_stacks(runtime_identity, source_root)
    for stack in stacks:
        _validate_stack_source(stack)
    runner_temporary = os.environ.get("RUNNER_TEMP")
    temporary_parent = Path(runner_temporary) if runner_temporary else None
    with tempfile.TemporaryDirectory(
        prefix="reconcile-phase5-plans-", dir=temporary_parent
    ) as temporary:
        root = Path(temporary)
        if provider_mirror is None:
            provider_mirror = _create_provider_mirror(terraform, root, source_root)
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
        backend = _select_offline_backend(root)
        read_only_paths = (provider_mirror,)
        create_plans: dict[str, dict[str, Any]] = {}
        for stack in stacks:
            working = root / stack.name
            _copy_stack(stack, working)
            if stack.variables:
                (working / "terraform.tfvars.json").write_text(
                    json.dumps(stack.variables), encoding="utf-8"
                )
            environment = base_environment | {
                "TF_DATA_DIR": str(root / f"{stack.name}-data")
            }
            _run_offline(
                [
                    str(terraform),
                    f"-chdir={working}",
                    "init",
                    "-input=false",
                    "-lockfile=readonly",
                    "-no-color",
                ],
                working_directory=working,
                environment=environment,
                backend=backend,
                read_only_paths=read_only_paths,
            )
            _run_offline(
                [
                    str(terraform),
                    f"-chdir={working}",
                    "validate",
                    "-no-color",
                ],
                working_directory=working,
                environment=environment,
                backend=backend,
                read_only_paths=read_only_paths,
            )
            stack_version = _run_offline(
                [
                    str(terraform),
                    f"-chdir={working}",
                    "version",
                    "-json",
                ],
                working_directory=working,
                environment=environment,
                backend=backend,
                read_only_paths=read_only_paths,
            )
            selections = json.loads(stack_version.stdout).get("provider_selections")
            if selections != {_PROVIDER: "7.44.0"}:
                _fail(f"{stack.name} selected an unexpected provider")
            plan_path = root / f"{stack.name}.tfplan"
            plan = _run_offline(
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
                working_directory=working,
                environment=environment,
                backend=backend,
                read_only_paths=read_only_paths,
                expected=frozenset({2}),
            )
            if plan.stdout.count("Plan:") != 1:
                _fail(f"{stack.name} did not produce one create plan")
            rendered = _run_offline(
                [
                    str(terraform),
                    f"-chdir={working}",
                    "show",
                    "-json",
                    str(plan_path),
                ],
                working_directory=working,
                environment=environment,
                backend=backend,
                read_only_paths=read_only_paths,
            )
            plan_path.unlink()
            rendered_plan = json.loads(rendered.stdout)
            digest = verify_create_plan(stack, rendered_plan)
            create_plans[stack.name] = _operator_plan_projection(rendered_plan)
            _verify_production_transition_guards(
                terraform,
                stack,
                working,
                environment=environment,
                backend=backend,
                read_only_paths=read_only_paths,
            )
            print(
                f"{stack.name}: {len(stack.addresses)} create-only resources; "
                f"inventory_sha256={digest}"
            )
        if artifact_output is not None:
            _write_operator_artifacts(artifact_output, create_plans)


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--deployment-profile", type=Path, required=True)
    parser.add_argument("--provider-mirror", type=Path)
    parser.add_argument("--terraform", type=Path, default=Path("terraform"))
    parser.add_argument("--artifact-output", type=Path)
    parser.add_argument("--image-digest")
    parser.add_argument("--infrastructure-revision")
    parser.add_argument("--recovery-definition-created-at")
    parser.add_argument("--semantic-config-sha256")
    parser.add_argument("--source-revision")
    parser.add_argument("--vertex-prompt-sha256")
    parser.add_argument("--vertex-prompt-version")
    return parser.parse_args()


def main() -> int:
    arguments = _parse_args()
    try:
        deployment_profile = load_sealed_deployment_profile_file(
            arguments.deployment_profile,
            repo_root=_ROOT,
        )
    except DeploymentProfileError as error:
        raise RuntimeError(error.code) from error
    _configure_deployment(deployment_profile)
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
    identity_values = {
        "image_digest": arguments.image_digest,
        "infrastructure_revision": arguments.infrastructure_revision,
        "recovery_definition_created_at": arguments.recovery_definition_created_at,
        "semantic_config_sha256": arguments.semantic_config_sha256,
        "source_revision": arguments.source_revision,
        "vertex_prompt_sha256": arguments.vertex_prompt_sha256,
        "vertex_prompt_version": arguments.vertex_prompt_version,
    }
    supplied = {name for name, value in identity_values.items() if value is not None}
    if arguments.artifact_output is None:
        if supplied:
            raise RuntimeError("runtime identity requires --artifact-output")
        runtime_identity = None
    else:
        if supplied != set(identity_values):
            raise RuntimeError(
                "--artifact-output requires the complete runtime identity"
            )
        runtime_identity = identity_values
    _offline_create(
        executable,
        provider_mirror,
        artifact_output=arguments.artifact_output,
        runtime_identity=runtime_identity,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
