"""Bounded exact-candidate Phase 5 hosted acceptance records and runner."""

from __future__ import annotations

import asyncio
import hashlib
import json
import os
import re
import stat
import subprocess
import sys
from collections.abc import Callable, Mapping
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path
from typing import Annotated, Literal, Protocol
from urllib.parse import urlsplit

import httpx
from google.auth import default as google_auth_default
from google.auth import impersonated_credentials
from google.cloud import firestore_v1, run_v2
from pydantic import Field, StringConstraints, model_validator

from reconcile.adapters.firestore_business import (
    FIRESTORE_BUSINESS_CAPABILITY_NAME,
    FIRESTORE_BUSINESS_CAPABILITY_VERSION,
    FIRESTORE_BUSINESS_TARGET_KIND,
)
from reconcile.adapters.sandbox_order import (
    SANDBOX_ORDER_CAPABILITY_VERSION,
    SANDBOX_ORDER_TARGET_KIND,
)
from reconcile.adapters.storage import (
    STORAGE_CAPABILITY_NAME,
    STORAGE_CAPABILITY_VERSION,
    STORAGE_TARGET_KIND,
)
from reconcile.contracts import (
    RECOVERY_POLICY_COMPARISON_VERSION,
    RECOVERY_RUN_REQUEST_VERSION,
    SCENARIO_LAUNCH_REQUEST_VERSION,
    AdaptivePlannerPhase,
    AdvisoryTurnEventPayload,
    AdvisoryTurnStatus,
    Classification,
    ComparisonStrategyKind,
    EffectAssertionState,
    EvidenceAuthority,
    EvidenceDisposition,
    EvidenceReason,
    OperationStatus,
    ProbeOutcome,
    ProbeRequestDisposition,
    ProbeRequestEventPayload,
    RecoveryDispatchOutcome,
    RecoveryPolicyComparison,
    RecoveryPolicyResult,
    RecoveryReceiptOutcome,
    RecoveryResetResult,
    RecoveryRunFault,
    RecoveryRunLifecycle,
    RecoveryRunPolicy,
    RecoveryRunRequest,
    RecoveryRunSnapshot,
    ScenarioHybridOutcome,
    ScenarioHybridRoute,
    ScenarioLaunchName,
    ScenarioLaunchRequest,
    ScenarioOperationalCleanupState,
    ScenarioOperationalInvestigationState,
    ScenarioOperationalMutationState,
    ScenarioOperationalRecoveryState,
    ScenarioOperationalStatus,
    ScenarioRunEvent,
    ScenarioRunEventType,
    ScenarioRunLifecycle,
    ScenarioRunMode,
    ScenarioRunResultKind,
    ScenarioRunSnapshot,
    TerminalStateEventPayload,
    canonical_json_bytes,
    decode_contract,
)
from reconcile.contracts.base import (
    AwareDatetime,
    Identifier,
    Sha256Digest,
    StrictModel,
)
from reconcile.hosted.cloud_run_canary import (
    CloudRunCanaryActionAdapter,
    CloudRunCanaryFaultProxy,
    CloudRunCanaryReader,
    CloudRunCanaryTarget,
)
from reconcile.hosted.firestore_cas import (
    FIRESTORE_RUNTIME_DATABASE,
    GoogleFirestoreCasStore,
)
from reconcile.hosted.firestore_provider_ledger import (
    FirestoreHostedProviderLedger,
    HostedProviderLedgerObservation,
)
from reconcile.hosted.firestore_release import (
    FIRESTORE_RELEASE_DATABASE,
    GoogleFirestoreReleaseTarget,
)
from reconcile.hosted.provider import (
    HOSTED_CANDIDATE_IDENTITY_VERSION,
    HostedCandidateIdentity,
)
from reconcile.interfaces.api_client import (
    InvestigationConflictError,
    InvestigationNotFoundError,
)
from reconcile.interfaces.google_identity import GcloudIdentityTokenSupplier
from reconcile.interfaces.operator_api_client import (
    LaunchOutcomeUnknownError,
    OperatorApiClient,
)
from reconcile.persistence.recovery_runs import (
    RECOVERY_RUN_AGGREGATE_VERSION,
    RECOVERY_RUN_EVENT_SNAPSHOT_VERSION,
    RecoveryRunAggregate,
    RecoveryRunEventSnapshot,
)
from reconcile.recovery_agents import (
    recovery_hypothesis_id,
    recovery_hypothesis_id_from_hashes,
)
from reconcile.recovery_scenario import (
    BlindPolicyExecutor,
    RecoveryPolicyResultRecorder,
    ReleaseChainBlindMutator,
    ReleaseChainResetter,
    ReleaseChainSettings,
    recovery_experiment_binding,
)
from reconcile.scenarios.firestore_business import FIRESTORE_BUSINESS_EFFECT_IDS
from reconcile.scenarios.sandbox_order import (
    SANDBOX_ORDER_AGGREGATE_CAPABILITY_NAME,
    SANDBOX_ORDER_EFFECT_ID,
    SANDBOX_ORDER_INGRESS_CAPABILITY_NAME,
)
from reconcile.scenarios.storage import STORAGE_EFFECT_ID

PHASE5_HOSTED_ACCEPTANCE_VERSION = "reconcile/phase5-hosted-acceptance/v2"
PHASE5_ACCEPTANCE_ARTIFACT_VERSION = "reconcile/phase5-acceptance-artifact/v1"

_PROJECT_ID = "reconcile-dev-260813-14fa6d"
_REGION = "us-central1"
_API_AUDIENCE = f"https://reconcile.invalid/phase5/{_PROJECT_ID}/api"
_CANARY_AUDIENCE = f"https://reconcile.invalid/phase5/{_PROJECT_ID}/canary"
_CONTROLLER_AUDIENCE = f"https://reconcile.invalid/phase5/{_PROJECT_ID}/controller"
_FAULT_PROXY_AUDIENCE = f"https://reconcile.invalid/phase5/{_PROJECT_ID}/fault-proxy"
_SANDBOX_AUDIENCE = f"https://reconcile.invalid/phase5/{_PROJECT_ID}/sandbox"
_PROVIDER_SOURCE = "registry.terraform.io/hashicorp/google"
_PROVIDER_VERSION = "7.44.0"
_GEMINI_MODEL = "gemini-3.5-flash"
_PROMPT_VERSION = "adaptive-planner-v3"
_PROMPT_SHA256 = "a18ac5bbd22570562acc6dfbc49437a82f0db6a265a4de737c1371b6ef2ca2d3"
_GCLOUD = "/usr/bin/gcloud"
_TERRAFORM = "/usr/local/libexec/reconcile/terraform-1.15.8"
_TERRAFORM_SHA256 = "8b6cb96cd46080ee1287baf646c70078715a99123b9b3a6ce2a7fe3892ec703a"
_APPLY_SERVICE_ACCOUNT = (
    "rec-p5-apply@reconcile-dev-260813-14fa6d.iam.gserviceaccount.com"
)
_MAX_COMMAND_BYTES = 1_048_576
_MAX_TERRAFORM_PLAN_BYTES = 16 * 1_048_576
_MAX_RECORD_BYTES = 8 * 1_048_576
_MAX_LOG_ENTRIES = 100
_REPO_ROOT = Path(__file__).parents[1]

_CANARY_SERVICE = "reconcile-p5-canary"
_CANARY_SERVICE_ACCOUNT = f"rec-p5-canary@{_PROJECT_ID}.iam.gserviceaccount.com"
_CANARY_REPROVISION_ADDRESSES = (
    "google_cloud_run_v2_service.canary",
    "google_cloud_run_v2_service_iam_member.canary_invoker",
    "google_cloud_run_v2_service_iam_member.canary_mutator",
    "google_cloud_run_v2_service_iam_member.canary_reader",
)
_CANARY_REPROVISION_TYPES = {
    "google_cloud_run_v2_service.canary": "google_cloud_run_v2_service",
    "google_cloud_run_v2_service_iam_member.canary_invoker": (
        "google_cloud_run_v2_service_iam_member"
    ),
    "google_cloud_run_v2_service_iam_member.canary_mutator": (
        "google_cloud_run_v2_service_iam_member"
    ),
    "google_cloud_run_v2_service_iam_member.canary_reader": (
        "google_cloud_run_v2_service_iam_member"
    ),
}
_CANARY_REPROVISION_IAM = {
    "google_cloud_run_v2_service_iam_member.canary_invoker": (
        "roles/run.invoker",
        f"serviceAccount:rec-p5-controller@{_PROJECT_ID}.iam.gserviceaccount.com",
    ),
    "google_cloud_run_v2_service_iam_member.canary_mutator": (
        f"projects/{_PROJECT_ID}/roles/reconcileP5CanaryMutator",
        f"serviceAccount:rec-p5-fault@{_PROJECT_ID}.iam.gserviceaccount.com",
    ),
    "google_cloud_run_v2_service_iam_member.canary_reader": (
        "roles/run.viewer",
        f"serviceAccount:rec-p5-controller@{_PROJECT_ID}.iam.gserviceaccount.com",
    ),
}
_RUNTIME_SOURCE_FILES = (
    ".terraform.lock.hcl",
    "cloud_run.tf",
    "invocation_iam.tf",
    "locals.tf",
    "outputs.tf",
    "providers.tf",
    "variables.tf",
    "versions.tf",
)

ImageDigest = Annotated[
    str,
    StringConstraints(pattern=r"^sha256:[0-9a-f]{64}$"),
]
GitRevision = Annotated[
    str,
    StringConstraints(pattern=r"^[0-9a-f]{40}$"),
]
ServiceAccountEmail = Annotated[
    str,
    StringConstraints(
        min_length=3,
        max_length=254,
        pattern=r"^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+$",
    ),
]


class HostedAcceptanceError(RuntimeError):
    """One sanitized, stable hosted-acceptance refusal."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


class AcceptanceMode(StrEnum):
    PROVIDER = "provider"
    HOSTED = "hosted"


class ServiceComponent(StrEnum):
    API = "api"
    CANARY = "canary"
    CONTROLLER = "controller"
    FAULT_PROXY = "fault-proxy"
    SANDBOX = "sandbox"


class AcceptanceLimitation(StrEnum):
    INFLIGHT_CONTROLLER_RESTART_NOT_FORCED = "inflight-controller-restart-not-forced"
    PROVIDER_TIMEOUT_NOT_FORCED = "provider-timeout-not-forced"
    PROVIDER_CONSTRUCTION_FAILURE_NOT_FORCED = (
        "provider-construction-failure-not-forced"
    )
    TARGET_CLEANUP_FAILURE_NOT_FORCED = "target-cleanup-failure-not-forced"
    NEGATIVE_EVIDENCE_INJECTION_NOT_EXPOSED = "negative-evidence-injection-not-exposed"
    BUDGET_EXHAUSTION_NOT_FORCED = "budget-exhaustion-not-forced"
    CLOUD_RUN_COLD_START_NOT_FORCED = "cloud-run-cold-start-not-forced"
    PLATFORM_LOGS_DIAGNOSTIC_ONLY = "platform-logs-diagnostic-only"
    STORAGE_RAW_PROVIDER_FIELDS_NOT_PUBLIC = "storage-raw-provider-fields-not-public"
    SANDBOX_DISCARD_OUTCOME_NOT_LIVE = "sandbox-discard-outcome-not-live"
    LIFECYCLE_DIAGNOSTICS_UNAVAILABLE = "lifecycle-diagnostics-unavailable"


class CandidateIdentity(StrictModel):
    source_revision: GitRevision
    image_digest: ImageDigest
    infrastructure_revision: Sha256Digest
    semantic_config_sha256: Sha256Digest
    project_id: Literal["reconcile-dev-260813-14fa6d"] = _PROJECT_ID
    region: Literal["us-central1"] = _REGION
    operator_service_account: Literal[
        "rec-p5-apply@reconcile-dev-260813-14fa6d.iam.gserviceaccount.com"
    ] = _APPLY_SERVICE_ACCOUNT
    api_audience: Literal[
        "https://reconcile.invalid/phase5/reconcile-dev-260813-14fa6d/api"
    ] = _API_AUDIENCE
    controller_audience: Literal[
        "https://reconcile.invalid/phase5/reconcile-dev-260813-14fa6d/controller"
    ] = _CONTROLLER_AUDIENCE
    provider_source: Literal["registry.terraform.io/hashicorp/google"] = (
        _PROVIDER_SOURCE
    )
    provider_version: Literal["7.44.0"] = _PROVIDER_VERSION
    gemini_model: Literal["gemini-3.5-flash"] = _GEMINI_MODEL
    prompt_version: Literal["adaptive-planner-v3"] = _PROMPT_VERSION
    prompt_sha256: Literal[
        "a18ac5bbd22570562acc6dfbc49437a82f0db6a265a4de737c1371b6ef2ca2d3"
    ] = _PROMPT_SHA256
    count_tokens_attempt_limit: Literal[1] = 1
    billed_generation_limit: Literal[1] = 1
    input_token_limit: Literal[12000] = 12_000
    output_token_limit: Literal[1024] = 1_024
    candidate_sha256: Sha256Digest

    @model_validator(mode="after")
    def validate_identity(self) -> CandidateIdentity:
        expected = _model_hash(self, exclude={"candidate_sha256"})
        if self.candidate_sha256 != expected:
            raise ValueError("candidate identity hash mismatch")
        return self


class ServiceDeploymentObservation(StrictModel):
    component: ServiceComponent
    service_name: Identifier
    service_uid: Identifier
    uri: str
    custom_audience: str
    generation: int = Field(ge=1, le=2**63 - 1)
    observed_generation: int = Field(ge=1, le=2**63 - 1)
    ready: Literal[True]
    latest_created_revision: Identifier
    latest_ready_revision: Identifier
    serving_revision: Identifier
    traffic_percent: Literal[100]
    revision_generation: int = Field(ge=1, le=2**63 - 1)
    revision_observed_generation: int = Field(ge=1, le=2**63 - 1)
    revision_ready: Literal[True]
    invoker_iam_disabled: Literal[False]
    api_invoker_iam_sha256: Sha256Digest | None = None
    image_reference: ImageDigest | str
    service_account_email: ServiceAccountEmail
    source_revision: GitRevision
    image_digest: ImageDigest
    infrastructure_revision: Sha256Digest
    semantic_config_sha256: Sha256Digest
    environment_sha256: Sha256Digest
    describe_sha256: Sha256Digest
    revision_describe_sha256: Sha256Digest
    observed_at: AwareDatetime

    @model_validator(mode="after")
    def validate_observation(self) -> ServiceDeploymentObservation:
        _validated_https_origin(self.uri)
        expected_name = _SERVICE_NAMES[self.component]
        if self.service_name != expected_name:
            raise ValueError("service observation name mismatch")
        if self.service_account_email != _SERVICE_ACCOUNTS[self.component]:
            raise ValueError("service account observation mismatch")
        if self.custom_audience != _SERVICE_AUDIENCES[self.component]:
            raise ValueError("custom audience observation mismatch")
        if (
            self.observed_generation != self.generation
            or self.latest_created_revision != self.latest_ready_revision
            or self.serving_revision != self.latest_ready_revision
            or self.revision_observed_generation != self.revision_generation
        ):
            raise ValueError("serving revision observation is not current and ready")
        expected_invoker_iam_sha256 = (
            _expected_api_invoker_iam_sha256()
            if self.component is ServiceComponent.API
            else None
        )
        if self.api_invoker_iam_sha256 != expected_invoker_iam_sha256:
            raise ValueError("API invoker IAM observation is not exact")
        return self


class LifecycleDiagnostics(StrictModel):
    diagnostic_only: Literal[True] = True
    available: bool
    entry_count: int = Field(ge=0, le=_MAX_LOG_ENTRIES)
    payload_sha256: Sha256Digest
    revision_names: tuple[Identifier, ...] = Field(max_length=32)
    first_timestamp: AwareDatetime | None = None
    last_timestamp: AwareDatetime | None = None
    observed_at: AwareDatetime

    @model_validator(mode="after")
    def validate_diagnostics(self) -> LifecycleDiagnostics:
        if len(self.revision_names) != len(set(self.revision_names)):
            raise ValueError("diagnostic revisions must be unique")
        if self.available:
            if self.entry_count < 1 or (
                self.first_timestamp is None or self.last_timestamp is None
            ):
                raise ValueError("available diagnostics require bounded entries")
            if self.last_timestamp < self.first_timestamp:
                raise ValueError("diagnostic timestamps are not ordered")
        elif (
            self.entry_count != 0
            or self.revision_names
            or self.first_timestamp is not None
            or self.last_timestamp is not None
        ):
            raise ValueError("unavailable diagnostics cannot imply observations")
        if (
            not self.available
            and self.payload_sha256 != hashlib.sha256(b"").hexdigest()
        ):
            raise ValueError("unavailable diagnostics must bind the empty payload")
        return self


class ScenarioAcceptanceObservation(StrictModel):
    purpose: Identifier
    request: ScenarioLaunchRequest
    launch_created: bool
    snapshot: ScenarioRunSnapshot
    events: tuple[ScenarioRunEvent, ...] = Field(min_length=1, max_length=512)
    operational_status: ScenarioOperationalStatus
    replay_created: Literal[False]
    replay_snapshot_sha256: Sha256Digest
    snapshot_sha256: Sha256Digest
    events_sha256: Sha256Digest
    operational_status_sha256: Sha256Digest

    @model_validator(mode="after")
    def validate_scenario(self) -> ScenarioAcceptanceObservation:
        snapshot = self.snapshot
        if (
            not self.launch_created
            or snapshot.launch_id != self.request.launch_id
            or snapshot.scenario is not self.request.scenario
            or snapshot.mode is not self.request.mode
            or snapshot.lifecycle is not ScenarioRunLifecycle.COMPLETED
            or snapshot.report is None
            or snapshot.comparison is not None
            or snapshot.failure_category is not None
        ):
            raise ValueError("acceptance scenario is not a completed exact report")
        if self.snapshot_sha256 != _model_hash(snapshot):
            raise ValueError("acceptance snapshot hash mismatch")
        if self.replay_snapshot_sha256 != self.snapshot_sha256:
            raise ValueError("exact replay changed the terminal snapshot")
        if self.events_sha256 != _models_hash(self.events):
            raise ValueError("acceptance event hash mismatch")
        expected_cursors = tuple(range(1, len(self.events) + 1))
        if tuple(event.cursor for event in self.events) != expected_cursors:
            raise ValueError("acceptance event journal is not contiguous")
        if any(
            event.investigation_id != snapshot.investigation_id for event in self.events
        ):
            raise ValueError("acceptance event identity changed")
        final = self.events[-1]
        if (
            final.type is not ScenarioRunEventType.TERMINAL
            or final.cursor != snapshot.event_cursor
            or not isinstance(final.payload, TerminalStateEventPayload)
        ):
            raise ValueError("acceptance event journal is not terminal")
        terminal = final.payload.terminal
        if (
            terminal.lifecycle is not ScenarioRunLifecycle.COMPLETED
            or terminal.result_kind is not ScenarioRunResultKind.REPORT
            or terminal.classification is not snapshot.report.classification
            or terminal.failure_category is not None
            or terminal.route_provenance != snapshot.report.route_provenance
        ):
            raise ValueError("acceptance terminal event changed the public result")
        status = self.operational_status
        if (
            status.launch_id != snapshot.launch_id
            or status.investigation_id != snapshot.investigation_id
            or status.scenario is not snapshot.scenario
            or status.mode is not snapshot.mode
            or status.mutation_state is not ScenarioOperationalMutationState.RECORDED
            or status.investigation_state
            is not ScenarioOperationalInvestigationState.RECORDED
            or status.cleanup_state is not ScenarioOperationalCleanupState.SUCCEEDED
            or status.recovery_state
            is not ScenarioOperationalRecoveryState.NOT_ESCALATED
        ):
            raise ValueError("acceptance operational state is not cleanly terminal")
        if self.operational_status_sha256 != _model_hash(status):
            raise ValueError("acceptance operational status hash mismatch")
        return self


class CursorResumeObservation(StrictModel):
    investigation_id: Identifier
    disconnected_after_cursor: int = Field(ge=1, le=512)
    resumed_first_cursor: int = Field(ge=2, le=512)
    final_cursor: int = Field(ge=2, le=512)
    resumed_events_sha256: Sha256Digest

    @model_validator(mode="after")
    def validate_resume(self) -> CursorResumeObservation:
        if self.resumed_first_cursor != self.disconnected_after_cursor + 1:
            raise ValueError("resumed event cursor is not exclusive")
        if self.final_cursor < self.resumed_first_cursor:
            raise ValueError("resumed event range is reversed")
        return self


class InterfaceParityObservation(StrictModel):
    investigation_id: Identifier
    api_snapshot_sha256: Sha256Digest
    cli_snapshot_sha256: Sha256Digest
    tui_snapshot_sha256: Sha256Digest
    all_equal: Literal[True]

    @model_validator(mode="after")
    def validate_parity(self) -> InterfaceParityObservation:
        if (
            len(
                {
                    self.api_snapshot_sha256,
                    self.cli_snapshot_sha256,
                    self.tui_snapshot_sha256,
                }
            )
            != 1
        ):
            raise ValueError("remote operator interfaces disagree")
        return self


class DuplicateRequestObservation(StrictModel):
    launch_id: Identifier
    concurrent_replay_count: Literal[2]
    snapshot_sha256: Sha256Digest
    conflict_observed: Literal[True]


class DenialLayer(StrEnum):
    PLATFORM = "platform"
    APPLICATION = "application"


class DenialObservation(StrictModel):
    layer: DenialLayer
    status_code: int = Field(ge=400, le=499)
    response_sha256: Sha256Digest
    response_kind: Literal["platform-non-json", "application-canonical-json"]
    canonical_code: Identifier | None = None

    @model_validator(mode="after")
    def validate_denial(self) -> DenialObservation:
        if self.layer is DenialLayer.APPLICATION:
            if (
                self.status_code != 401
                or self.canonical_code != "unauthorized"
                or self.response_kind != "application-canonical-json"
            ):
                raise ValueError("application denial is not canonical")
        elif (
            self.status_code not in {401, 403}
            or self.canonical_code is not None
            or self.response_kind != "platform-non-json"
        ):
            raise ValueError("platform denial is not distinguishable")
        return self


class ExactMainTestSubstitution(StrictModel):
    control: Identifier
    live_exercised: Literal[False] = False
    proof_kind: Literal["exact-main-test"] = "exact-main-test"
    tests: tuple[str, ...] = Field(min_length=1, max_length=8)

    @model_validator(mode="after")
    def validate_tests(self) -> ExactMainTestSubstitution:
        if len(self.tests) != len(set(self.tests)) or any(
            not item.startswith("tests/") or "::test_" not in item or len(item) > 256
            for item in self.tests
        ):
            raise ValueError("exact-main substitution tests are not exact")
        return self


class ProviderAcceptanceRecord(StrictModel):
    schema_version: Literal["reconcile/phase5-hosted-acceptance/v2"]
    record_type: Literal["provider-acceptance"]
    candidate: CandidateIdentity
    deployments: tuple[ServiceDeploymentObservation, ...] = Field(
        min_length=5, max_length=5
    )
    provider_ledger_absent_before: Literal[True]
    adaptive_recovery: RecoveryLaneAcceptanceObservation
    provider_ledger: HostedProviderLedgerObservation
    diagnostics: LifecycleDiagnostics
    limitations: tuple[AcceptanceLimitation, ...]
    started_at: AwareDatetime
    completed_at: AwareDatetime
    record_sha256: Sha256Digest

    @model_validator(mode="after")
    def validate_record(self) -> ProviderAcceptanceRecord:
        _validate_record_common(
            self.candidate,
            self.deployments,
            self.started_at,
            self.completed_at,
        )
        _validate_recovery_lane(
            self.adaptive_recovery,
            candidate=self.candidate,
            policy=RecoveryRunPolicy.ADAPTIVE,
            fault=RecoveryRunFault.DROP_AFTER_ACCEPT,
            purpose="provider-adaptive-drop",
        )
        hosted_candidate = _hosted_candidate_identity(self.candidate)
        canary = next(
            item
            for item in self.deployments
            if item.component is ServiceComponent.CANARY
        )
        if (
            self.provider_ledger.candidate_sha256 != hosted_candidate.sha256
            or self.adaptive_recovery.reprovision.previous_service_uid
            != canary.service_uid
            or self.provider_ledger.dispatch.input_sha256
            != self.adaptive_recovery.hypothesis_input_sha256
            or self.provider_ledger.output_sha256
            != self.adaptive_recovery.hypothesis_output_sha256
            or self.adaptive_recovery.provider_hypothesis_count != 1
        ):
            raise ValueError("provider recovery and generation ledger are not bound")
        if self.limitations != _provider_limitations(self.diagnostics):
            raise ValueError("provider acceptance limitations changed")
        if self.record_sha256 != _model_hash(self, exclude={"record_sha256"}):
            raise ValueError("provider acceptance record hash mismatch")
        return self


class AcceptanceArtifactBinding(StrictModel):
    schema_version: Literal["reconcile/phase5-acceptance-artifact/v1"]
    mode: AcceptanceMode
    path: str
    record_sha256: Sha256Digest
    file_sha256: Sha256Digest
    byte_count: int = Field(ge=1, le=_MAX_RECORD_BYTES)


class HostedAcceptanceRecord(StrictModel):
    schema_version: Literal["reconcile/phase5-hosted-acceptance/v2"]
    record_type: Literal["hosted-acceptance"]
    candidate: CandidateIdentity
    provider_artifact: AcceptanceArtifactBinding
    deployments: tuple[ServiceDeploymentObservation, ...] = Field(
        min_length=5, max_length=5
    )
    scenarios: tuple[ScenarioAcceptanceObservation, ...] = Field(
        min_length=3, max_length=3
    )
    recovery_lanes: tuple[RecoveryLaneAcceptanceObservation, ...] = Field(
        min_length=5, max_length=5
    )
    recovery_comparison: RecoveryPolicyComparison
    provider_ledger: HostedProviderLedgerObservation
    duplicate_request: DuplicateRequestObservation
    cursor_resume: CursorResumeObservation
    interface_parity: InterfaceParityObservation
    denials: tuple[DenialObservation, ...] = Field(min_length=2, max_length=2)
    diagnostics: LifecycleDiagnostics
    exact_main_test_substitutions: tuple[ExactMainTestSubstitution, ...] = Field(
        min_length=8, max_length=8
    )
    limitations: tuple[AcceptanceLimitation, ...]
    started_at: AwareDatetime
    completed_at: AwareDatetime
    record_sha256: Sha256Digest

    @model_validator(mode="after")
    def validate_record(self) -> HostedAcceptanceRecord:
        _validate_record_common(
            self.candidate,
            self.deployments,
            self.started_at,
            self.completed_at,
        )
        if self.provider_artifact.mode is not AcceptanceMode.PROVIDER:
            raise ValueError("hosted acceptance does not bind provider acceptance")
        expected = {
            (ScenarioLaunchName.STORAGE, ScenarioRunMode.ADAPTIVE): (
                Classification.COMMITTED,
                "hosted-storage-authoritative",
                "storage-authoritative",
            ),
            (ScenarioLaunchName.FIRESTORE_BUSINESS, ScenarioRunMode.ADAPTIVE): (
                Classification.PARTIAL,
                "hosted-firestore-authoritative",
                "firestore-authoritative",
            ),
            (ScenarioLaunchName.SANDBOX_ORDER, ScenarioRunMode.FIXED): (
                Classification.UNKNOWN,
                "hosted-sandbox-fixed-unknown",
                "sandbox-fixed",
            ),
        }
        scenario_by_key: dict[
            tuple[ScenarioLaunchName, ScenarioRunMode],
            ScenarioAcceptanceObservation,
        ] = {}
        observed: set[tuple[ScenarioLaunchName, ScenarioRunMode]] = set()
        for scenario in self.scenarios:
            key = (scenario.request.scenario, scenario.request.mode)
            if key not in expected or key in observed:
                raise ValueError("hosted acceptance scenario matrix changed")
            observed.add(key)
            scenario_by_key[key] = scenario
            classification, purpose, label = expected[key]
            report = scenario.snapshot.report
            if (
                report is None
                or report.classification is not classification
                or scenario.purpose != purpose
                or scenario.request
                != _launch(
                    self.candidate,
                    label,
                    scenario.request.scenario,
                    scenario.request.mode,
                )
                or report.route_provenance is None
                or report.route_provenance.route
                is not ScenarioHybridRoute.FIXED_AUTHORITATIVE
                or report.route_provenance.outcome
                is not ScenarioHybridOutcome.FIXED_AUTHORITATIVE
                or report.route_provenance.planner_invoked
                or not report.route_provenance.fixed_connector_invoked
                or report.route_provenance.provider_failure
            ):
                raise ValueError("hosted fixed-authoritative result changed")
            if key[0] is ScenarioLaunchName.STORAGE:
                _validate_storage_public_report(scenario)
            elif key[0] is ScenarioLaunchName.FIRESTORE_BUSINESS:
                _validate_firestore_public_report(scenario)
            else:
                _validate_sandbox_unknown_public_report(
                    scenario,
                    require_both_probes=True,
                )
        if observed != set(expected):
            raise ValueError("hosted acceptance scenario matrix is incomplete")
        _validate_hosted_recovery_evidence(self)
        storage = scenario_by_key[
            (ScenarioLaunchName.STORAGE, ScenarioRunMode.ADAPTIVE)
        ]
        if (
            self.duplicate_request.launch_id != storage.request.launch_id
            or self.duplicate_request.snapshot_sha256 != storage.snapshot_sha256
            or self.cursor_resume.investigation_id != storage.snapshot.investigation_id
            or self.cursor_resume.final_cursor != storage.snapshot.event_cursor
            or self.cursor_resume.resumed_events_sha256
            != _models_hash(
                storage.events[self.cursor_resume.disconnected_after_cursor :]
            )
            or self.interface_parity.investigation_id
            != storage.snapshot.investigation_id
            or self.interface_parity.api_snapshot_sha256 != storage.snapshot_sha256
        ):
            raise ValueError("hosted transport observations changed candidate identity")
        if self.exact_main_test_substitutions != _exact_main_substitutions():
            raise ValueError("hosted substitution coverage changed")
        required = _hosted_limitations(self.diagnostics)
        if self.limitations != required:
            raise ValueError("hosted acceptance limitations changed")
        if tuple(item.layer for item in self.denials) != (
            DenialLayer.PLATFORM,
            DenialLayer.APPLICATION,
        ):
            raise ValueError("hosted denial matrix changed")
        if self.record_sha256 != _model_hash(self, exclude={"record_sha256"}):
            raise ValueError("hosted acceptance record hash mismatch")
        return self


class CanaryReprovisionBinding(StrictModel):
    """Approved hashes and private state root for one runtime reprovision."""

    state_root: str
    runtime_source_sha256: Sha256Digest
    runtime_variables_sha256: Sha256Digest

    @model_validator(mode="after")
    def validate_binding(self) -> CanaryReprovisionBinding:
        path = Path(self.state_root)
        if not path.is_absolute() or path != Path(os.path.abspath(path)):
            raise ValueError("canary reprovision state root must be canonical")
        return self


class CanaryReprovisionObservation(StrictModel):
    """Sanitized proof that one lane received a physically new clean canary."""

    previous_service_uid: Identifier
    service_uid: Identifier
    baseline_revision: Identifier
    revision_names: tuple[Identifier, ...] = Field(min_length=1, max_length=1)
    traffic_percent: Literal[100] = 100
    release_id: Identifier
    release_record_absent: Literal[True] = True
    changed_resource_addresses: tuple[str, ...] = Field(min_length=4, max_length=4)
    execution_plan_sha256: Sha256Digest
    normalized_plan_sha256: Sha256Digest
    observed_at: AwareDatetime

    @model_validator(mode="after")
    def validate_reprovision(self) -> CanaryReprovisionObservation:
        if (
            self.previous_service_uid == self.service_uid
            or self.revision_names != (self.baseline_revision,)
            or self.changed_resource_addresses != _CANARY_REPROVISION_ADDRESSES
        ):
            raise ValueError("canary was not physically reprovisioned to baseline")
        return self


class RecoveryLaneAcceptanceObservation(StrictModel):
    """One physically isolated policy lane and its sanitized API evidence."""

    purpose: Identifier
    reprovision: CanaryReprovisionObservation
    result: RecoveryPolicyResult
    reset: RecoveryResetResult
    acknowledgement_lost: bool
    launch_outcome: RecoveryDispatchOutcome | None = None
    launch_created: Literal[True] | None = None
    replay_created: Literal[False] | None = None
    request_sha256: Sha256Digest | None = None
    snapshot_sha256: Sha256Digest | None = None
    replay_snapshot_sha256: Sha256Digest | None = None
    events_sha256: Sha256Digest | None = None
    event_count: int = Field(ge=0, le=512)
    replay_provider_contact_delta: Literal[0] | None = None
    live_authority_replay_denial_count: int = Field(ge=0, le=1)
    provider_hypothesis_count: int = Field(ge=0, le=1)
    hypothesis_id: Identifier | None = None
    hypothesis_chain_sha256: Sha256Digest | None = None
    hypothesis_node_sha256: Sha256Digest | None = None
    hypothesis_input_sha256: Sha256Digest | None = None
    hypothesis_output_sha256: Sha256Digest | None = None

    @model_validator(mode="after")
    def validate_lane(self) -> RecoveryLaneAcceptanceObservation:
        if (
            self.reprovision.release_id != self.result.firestore.release_id
            or self.reprovision.baseline_revision
            != self.result.cloud_run.baseline_revision
            or self.reset.release_id != self.reprovision.release_id
            or self.reset.baseline_revision != self.reprovision.baseline_revision
            or self.reset.release_revisions_before
            != self.result.cloud_run.release_revisions
        ):
            raise ValueError("recovery lane changed its physical target")
        proof_policy = self.result.policy in {"fixed", "adaptive"}
        drop_after_accept = self.result.fault == "drop-after-accept"
        if self.acknowledgement_lost != drop_after_accept:
            raise ValueError("recovery lane fault was not observed at its boundary")
        api_fields = (
            self.launch_created,
            self.replay_created,
            self.request_sha256,
            self.snapshot_sha256,
            self.replay_snapshot_sha256,
            self.events_sha256,
            self.replay_provider_contact_delta,
        )
        hypothesis_fields = (
            self.hypothesis_id,
            self.hypothesis_chain_sha256,
            self.hypothesis_node_sha256,
            self.hypothesis_input_sha256,
            self.hypothesis_output_sha256,
        )
        replay_denials = tuple(
            receipt
            for receipt in self.result.dispatch_receipts
            if receipt.outcome
            is RecoveryReceiptOutcome.REJECTED_BEFORE_PROVIDER_CONTACT
        )
        expected_live_replay = proof_policy and self.result.fault in {
            RecoveryRunFault.DROP_AFTER_ACCEPT.value,
            RecoveryRunFault.NO_FAULT.value,
        }
        if (
            self.live_authority_replay_denial_count != len(replay_denials)
            or self.live_authority_replay_denial_count != int(expected_live_replay)
            or any(
                receipt.node_id != "stage"
                or receipt.provider_contact
                or receipt.attempt != 1
                for receipt in replay_denials
            )
        ):
            raise ValueError("live recovery authority replay evidence changed")
        if proof_policy:
            if (
                any(value is None for value in api_fields)
                or self.snapshot_sha256 != self.replay_snapshot_sha256
                or self.event_count < 1
                or not self.result.chain_completed
                or self.launch_outcome
                is not (
                    RecoveryDispatchOutcome.OUTCOME_UNKNOWN
                    if drop_after_accept
                    else RecoveryDispatchOutcome.SUCCEEDED
                )
            ):
                raise ValueError("proof lane lacks terminal hosted API evidence")
            adaptive = self.result.policy == "adaptive"
            if adaptive != (self.provider_hypothesis_count == 1) or adaptive != all(
                value is not None for value in hypothesis_fields
            ):
                raise ValueError("proof lane changed its Gemini hypothesis evidence")
            if adaptive and self.hypothesis_id != recovery_hypothesis_id_from_hashes(
                chain_sha256=self.hypothesis_chain_sha256,
                node_sha256=self.hypothesis_node_sha256,
                input_sha256=self.hypothesis_input_sha256,
                output_sha256=self.hypothesis_output_sha256,
            ):
                raise ValueError("adaptive hypothesis binding changed")
        elif (
            any(value is not None for value in api_fields)
            or self.launch_outcome is not None
            or self.event_count != 0
            or self.provider_hypothesis_count != 0
            or any(value is not None for value in hypothesis_fields)
        ):
            raise ValueError("blind lane acquired hosted proof artifacts")
        if self.result.policy == "blind-retry" and not self.result.chain_completed:
            raise ValueError("blind retry did not expose its completed duplicate chain")
        if self.result.fault == "suppress-before-dispatch":
            record_receipts = tuple(
                receipt
                for receipt in self.result.dispatch_receipts
                if receipt.node_id == "record"
            )
            if tuple(item.outcome for item in record_receipts) != (
                RecoveryReceiptOutcome.SUPPRESSED_BEFORE_DISPATCH,
                RecoveryReceiptOutcome.PROVIDER_CONTACTED,
            ) or tuple(item.attempt for item in record_receipts) != (1, 2):
                raise ValueError("suppressed dispatch retry evidence changed")
        return self


def _validate_recovery_lane(
    lane: RecoveryLaneAcceptanceObservation,
    *,
    candidate: CandidateIdentity,
    policy: RecoveryRunPolicy,
    fault: RecoveryRunFault,
    purpose: str,
) -> None:
    settings = _candidate_release_settings(candidate)
    binding = recovery_experiment_binding(settings, fault)
    if (
        lane.purpose != purpose
        or lane.result.policy != policy.value
        or lane.result.fault != fault.value
        or lane.result.target_sha256 != binding.target_sha256
        or lane.result.input_intent_sha256 != binding.input_intent_sha256
        or lane.result.fault_boundary_sha256 != binding.fault_boundary_sha256
        or lane.result.observation_catalog_sha256 != binding.observation_catalog_sha256
        or lane.result.run_id
        != _recovery_run_id(
            policy=policy,
            fault=fault,
            purpose=purpose,
            service_uid=lane.reprovision.service_uid,
            candidate_sha256=candidate.candidate_sha256,
        )
        or lane.result.cloud_run.intended_revision != settings.staged_revision
        or lane.result.firestore.release_id != settings.release_id
        or lane.result.firestore.expected_payload_sha256 != settings.payload_sha256
    ):
        raise ValueError("recovery acceptance lane identity changed")


def _validate_hosted_recovery_evidence(record: HostedAcceptanceRecord) -> None:
    expected = (
        (
            RecoveryRunPolicy.BLIND_RETRY,
            RecoveryRunFault.DROP_AFTER_ACCEPT,
            "hosted-blind-retry-drop",
        ),
        (
            RecoveryRunPolicy.BLIND_ABORT,
            RecoveryRunFault.DROP_AFTER_ACCEPT,
            "hosted-blind-abort-drop",
        ),
        (
            RecoveryRunPolicy.FIXED,
            RecoveryRunFault.DROP_AFTER_ACCEPT,
            "hosted-fixed-drop",
        ),
        (
            RecoveryRunPolicy.FIXED,
            RecoveryRunFault.NO_FAULT,
            "hosted-fixed-no-fault",
        ),
        (
            RecoveryRunPolicy.FIXED,
            RecoveryRunFault.SUPPRESS_BEFORE_DISPATCH,
            "hosted-fixed-suppress",
        ),
    )
    for lane, (policy, fault, purpose) in zip(
        record.recovery_lanes,
        expected,
        strict=True,
    ):
        _validate_recovery_lane(
            lane,
            candidate=record.candidate,
            policy=policy,
            fault=fault,
            purpose=purpose,
        )
    comparison = record.recovery_comparison
    drop_lanes = record.recovery_lanes[:3]
    canary = next(
        item for item in record.deployments if item.component is ServiceComponent.CANARY
    )
    common = comparison.lanes[0]
    if (
        comparison.schema_version != RECOVERY_POLICY_COMPARISON_VERSION
        or comparison.fault != RecoveryRunFault.DROP_AFTER_ACCEPT.value
        or comparison.lanes[:3] != tuple(item.result for item in drop_lanes)
        or comparison.reset_results[:3] != tuple(item.reset for item in drop_lanes)
        or comparison.lanes[3].policy != RecoveryRunPolicy.ADAPTIVE.value
        or record.provider_ledger.candidate_sha256
        != _hosted_candidate_identity(record.candidate).sha256
        or record.recovery_lanes[0].reprovision.previous_service_uid
        != canary.service_uid
        or any(
            (
                lane.result.target_sha256,
                lane.result.input_intent_sha256,
                lane.result.observation_catalog_sha256,
            )
            != (
                common.target_sha256,
                common.input_intent_sha256,
                common.observation_catalog_sha256,
            )
            for lane in record.recovery_lanes[3:]
        )
    ):
        raise ValueError("hosted recovery comparison changed accepted evidence")
    if any(
        current.reprovision.previous_service_uid != previous.reprovision.service_uid
        for previous, current in zip(
            record.recovery_lanes[:-1],
            record.recovery_lanes[1:],
            strict=True,
        )
    ):
        raise ValueError("hosted recovery reprovision chain changed")


ProviderAcceptanceRecord.model_rebuild()
HostedAcceptanceRecord.model_rebuild()


class RecoveryReleaseRecordReader(Protocol):
    async def read(self, release_id: str) -> object | None: ...


class CanaryReprovisionBackend(Protocol):
    async def reprovision(self) -> CanaryReprovisionObservation: ...


class HostedAcceptanceBackend(Protocol):
    async def deployments(
        self, candidate: CandidateIdentity
    ) -> tuple[ServiceDeploymentObservation, ...]: ...

    async def scenario(
        self,
        request: ScenarioLaunchRequest,
        *,
        purpose: str,
    ) -> ScenarioAcceptanceObservation: ...

    async def provider_ledger_absent(self) -> bool: ...

    async def recovery_lane(
        self,
        *,
        policy: RecoveryRunPolicy,
        fault: RecoveryRunFault,
        purpose: str,
    ) -> RecoveryLaneAcceptanceObservation: ...

    async def provider_ledger(self) -> HostedProviderLedgerObservation: ...

    async def concurrent_replay(
        self,
        scenario: ScenarioAcceptanceObservation,
    ) -> DuplicateRequestObservation: ...

    async def cursor_resume(
        self,
        scenario: ScenarioAcceptanceObservation,
    ) -> CursorResumeObservation: ...

    async def interface_parity(
        self,
        scenario: ScenarioAcceptanceObservation,
    ) -> InterfaceParityObservation: ...

    async def denials(self) -> tuple[DenialObservation, DenialObservation]: ...

    async def diagnostics(self) -> LifecycleDiagnostics: ...


type CommandRunner = Callable[
    [tuple[str, ...], Path, Mapping[str, str], int],
    object,
]


_SERVICE_NAMES = {
    ServiceComponent.API: "reconcile-p5-api",
    ServiceComponent.CANARY: "reconcile-p5-canary",
    ServiceComponent.CONTROLLER: "reconcile-p5-controller",
    ServiceComponent.FAULT_PROXY: "reconcile-p5-fault-proxy",
    ServiceComponent.SANDBOX: "reconcile-p5-sandbox",
}
_SERVICE_ACCOUNTS = {
    ServiceComponent.API: f"rec-p5-api@{_PROJECT_ID}.iam.gserviceaccount.com",
    ServiceComponent.CANARY: (f"rec-p5-canary@{_PROJECT_ID}.iam.gserviceaccount.com"),
    ServiceComponent.CONTROLLER: (
        f"rec-p5-controller@{_PROJECT_ID}.iam.gserviceaccount.com"
    ),
    ServiceComponent.FAULT_PROXY: (
        f"rec-p5-fault@{_PROJECT_ID}.iam.gserviceaccount.com"
    ),
    ServiceComponent.SANDBOX: (f"rec-p5-sandbox@{_PROJECT_ID}.iam.gserviceaccount.com"),
}
_SERVICE_AUDIENCES = {
    ServiceComponent.API: _API_AUDIENCE,
    ServiceComponent.CANARY: _CANARY_AUDIENCE,
    ServiceComponent.CONTROLLER: _CONTROLLER_AUDIENCE,
    ServiceComponent.FAULT_PROXY: _FAULT_PROXY_AUDIENCE,
    ServiceComponent.SANDBOX: _SANDBOX_AUDIENCE,
}


def _required_service_environment(
    component: ServiceComponent,
    candidate: CandidateIdentity,
    service_uris: Mapping[ServiceComponent, str],
    *,
    canary_baseline_revision: str | None,
    recovery_definition_created_at: str | None,
) -> dict[str, str]:
    if component is ServiceComponent.CANARY:
        return {
            "GOOGLE_CLOUD_PROJECT": _PROJECT_ID,
            "RECONCILE_CANARY_CONFIGURATION_SHA256": (candidate.semantic_config_sha256),
            "RECONCILE_CANARY_RELEASE_ID": "baseline",
            "RECONCILE_IMAGE_DIGEST": candidate.image_digest,
            "RECONCILE_INFRA_REVISION": candidate.infrastructure_revision,
            "RECONCILE_SEMANTIC_CONFIG_SHA256": candidate.semantic_config_sha256,
            "RECONCILE_SOURCE_REVISION": candidate.source_revision,
        }
    required = {
        "GOOGLE_CLOUD_PROJECT": _PROJECT_ID,
        "RECONCILE_AUTH_AUDIENCE": _SERVICE_AUDIENCES[component],
        "RECONCILE_COMPONENT": component.value,
        "RECONCILE_SOURCE_REVISION": candidate.source_revision,
        "RECONCILE_IMAGE_DIGEST": candidate.image_digest,
        "RECONCILE_INFRA_REVISION": candidate.infrastructure_revision,
        "RECONCILE_RUNTIME_DATABASE": "reconcile-p5-runtime",
        "RECONCILE_SEMANTIC_CONFIG_SHA256": candidate.semantic_config_sha256,
    }
    if component is ServiceComponent.API:
        required.update(
            {
                "RECONCILE_ALLOWED_CALLER_EMAILS": _APPLY_SERVICE_ACCOUNT,
                "RECONCILE_CONTROLLER_AUDIENCE": _CONTROLLER_AUDIENCE,
                "RECONCILE_CONTROLLER_URL": service_uris[ServiceComponent.CONTROLLER],
                "RECONCILE_FAULT_PROXY_AUDIENCE": _FAULT_PROXY_AUDIENCE,
                "RECONCILE_FAULT_PROXY_URL": service_uris[ServiceComponent.FAULT_PROXY],
                "RECONCILE_TARGET_BUCKET": f"{_PROJECT_ID}-p5-target",
            }
        )
    elif component is ServiceComponent.CONTROLLER:
        if canary_baseline_revision is None or recovery_definition_created_at is None:
            raise HostedAcceptanceError("DEPLOYMENT_EXPECTATION_INCOMPLETE")
        required.update(
            {
                "RECONCILE_ALLOWED_CALLER_EMAILS": _SERVICE_ACCOUNTS[
                    ServiceComponent.API
                ],
                "RECONCILE_CANARY_AUDIENCE": _CANARY_AUDIENCE,
                "RECONCILE_CANARY_BASELINE_REVISION": canary_baseline_revision,
                "RECONCILE_CANARY_LOCATION": candidate.region,
                "RECONCILE_CANARY_SERVICE": _CANARY_SERVICE,
                "RECONCILE_FAULT_PROXY_AUDIENCE": _FAULT_PROXY_AUDIENCE,
                "RECONCILE_FAULT_PROXY_URL": service_uris[ServiceComponent.FAULT_PROXY],
                "RECONCILE_RECOVERY_DEFINITION_CREATED_AT": (
                    recovery_definition_created_at
                ),
                "RECONCILE_RECOVERY_EXECUTION_TIMEOUT_SECONDS": "240",
                "RECONCILE_RECOVERY_PAYLOAD_SHA256": _hosted_candidate_identity(
                    candidate
                ).sha256,
                "RECONCILE_RECOVERY_RELEASE_ID": (
                    f"p5-release-{candidate.source_revision[:24]}"
                ),
                "RECONCILE_SANDBOX_AUDIENCE": _SANDBOX_AUDIENCE,
                "RECONCILE_SANDBOX_URL": service_uris[ServiceComponent.SANDBOX],
                "RECONCILE_TARGET_BUCKET": f"{_PROJECT_ID}-p5-target",
                "RECONCILE_TARGET_DATABASE": "reconcile-p5-target",
                "RECONCILE_VERTEX_LOCATION": "us",
                "RECONCILE_VERTEX_MAX_COUNT_TOKENS_ATTEMPTS": "1",
                "RECONCILE_VERTEX_MAX_GENERATION_ATTEMPTS": "1",
                "RECONCILE_VERTEX_MAX_INPUT_TOKENS": "12000",
                "RECONCILE_VERTEX_MAX_OUTPUT_TOKENS": "1024",
                "RECONCILE_VERTEX_MODEL": _GEMINI_MODEL,
                "RECONCILE_VERTEX_PROMPT_SHA256": _PROMPT_SHA256,
                "RECONCILE_VERTEX_PROMPT_VERSION": _PROMPT_VERSION,
                "RECONCILE_VERTEX_THINKING_LEVEL": "MINIMAL",
            }
        )
    elif component is ServiceComponent.FAULT_PROXY:
        if canary_baseline_revision is None:
            raise HostedAcceptanceError("DEPLOYMENT_EXPECTATION_INCOMPLETE")
        required.update(
            {
                "RECONCILE_ALLOWED_CALLER_EMAILS": _SERVICE_ACCOUNTS[
                    ServiceComponent.API
                ],
                "RECONCILE_CANARY_AUDIENCE": _CANARY_AUDIENCE,
                "RECONCILE_CANARY_BASELINE_REVISION": canary_baseline_revision,
                "RECONCILE_CANARY_LOCATION": candidate.region,
                "RECONCILE_CANARY_SERVICE": _CANARY_SERVICE,
                "RECONCILE_RECOVERY_ACTION_CALLER_EMAIL": _SERVICE_ACCOUNTS[
                    ServiceComponent.CONTROLLER
                ],
                "RECONCILE_SANDBOX_AUDIENCE": _SANDBOX_AUDIENCE,
                "RECONCILE_SANDBOX_URL": service_uris[ServiceComponent.SANDBOX],
                "RECONCILE_TARGET_BUCKET": f"{_PROJECT_ID}-p5-target",
                "RECONCILE_TARGET_DATABASE": "reconcile-p5-target",
            }
        )
    else:
        required.update(
            {
                "RECONCILE_SANDBOX_MUTATION_CALLER_EMAIL": _SERVICE_ACCOUNTS[
                    ServiceComponent.FAULT_PROXY
                ],
                "RECONCILE_SANDBOX_READ_CALLER_EMAIL": _SERVICE_ACCOUNTS[
                    ServiceComponent.CONTROLLER
                ],
                "RECONCILE_TARGET_DATABASE": "reconcile-p5-sandbox",
            }
        )
    return required


def build_candidate_identity(
    *,
    source_revision: str,
    image_digest: str,
    infrastructure_revision: str,
    semantic_config_sha256: str,
) -> CandidateIdentity:
    values = {
        "source_revision": source_revision,
        "image_digest": image_digest,
        "infrastructure_revision": infrastructure_revision,
        "semantic_config_sha256": semantic_config_sha256,
        "project_id": _PROJECT_ID,
        "region": _REGION,
        "operator_service_account": _APPLY_SERVICE_ACCOUNT,
        "api_audience": _API_AUDIENCE,
        "controller_audience": _CONTROLLER_AUDIENCE,
        "provider_source": _PROVIDER_SOURCE,
        "provider_version": _PROVIDER_VERSION,
        "gemini_model": _GEMINI_MODEL,
        "prompt_version": _PROMPT_VERSION,
        "prompt_sha256": _PROMPT_SHA256,
        "count_tokens_attempt_limit": 1,
        "billed_generation_limit": 1,
        "input_token_limit": 12_000,
        "output_token_limit": 1_024,
    }
    return CandidateIdentity(
        **values,  # type: ignore[arg-type]
        candidate_sha256=_json_hash(values),  # type: ignore[arg-type]
    )


def _hosted_candidate_identity(candidate: CandidateIdentity) -> HostedCandidateIdentity:
    if type(candidate) is not CandidateIdentity:
        raise TypeError("hosted candidate identity requires an exact candidate")
    return HostedCandidateIdentity(
        schema_version=HOSTED_CANDIDATE_IDENTITY_VERSION,
        source_revision=candidate.source_revision,
        image_digest=candidate.image_digest,
        infrastructure_revision=candidate.infrastructure_revision,
        semantic_config_sha256=candidate.semantic_config_sha256,
        project_id=candidate.project_id,
        vertex_location="us",
        configured_model=candidate.gemini_model,
        prompt_version=candidate.prompt_version,
        prompt_sha256=candidate.prompt_sha256,
        maximum_input_tokens=candidate.input_token_limit,
        maximum_output_tokens=candidate.output_token_limit,
        thinking_level="MINIMAL",
        maximum_count_tokens_attempts=candidate.count_tokens_attempt_limit,
        maximum_generation_attempts=candidate.billed_generation_limit,
    )


def _candidate_release_settings(candidate: CandidateIdentity) -> ReleaseChainSettings:
    if type(candidate) is not CandidateIdentity:
        raise TypeError("release settings require an exact candidate")
    return ReleaseChainSettings(
        project=candidate.project_id,
        location=candidate.region,
        service=_CANARY_SERVICE,
        release_id=f"p5-release-{candidate.source_revision[:24]}",
        image_digest=candidate.image_digest,
        configuration_sha256=candidate.semantic_config_sha256,
        payload_sha256=_hosted_candidate_identity(candidate).sha256,
        database=FIRESTORE_RELEASE_DATABASE,
    )


def _recovery_run_id(
    *,
    policy: RecoveryRunPolicy,
    fault: RecoveryRunFault,
    purpose: str,
    service_uid: str,
    candidate_sha256: str,
) -> str:
    suffix = _json_hash(
        {
            "candidate_sha256": candidate_sha256,
            "fault": fault.value,
            "policy": policy.value,
            "purpose": purpose,
            "service_uid": service_uid,
        }
    )[:32]
    return f"p5r-{policy.value}-{suffix}"


def _model_hash(model: StrictModel, *, exclude: set[str] | None = None) -> str:
    payload = model.model_dump(mode="json", exclude=exclude or set())
    return _json_hash(payload)


def _models_hash(models: tuple[StrictModel, ...]) -> str:
    return _json_hash([item.model_dump(mode="json") for item in models])


def _json_hash(value: object) -> str:
    payload = json.dumps(
        value,
        allow_nan=False,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def _expected_api_invoker_iam_sha256() -> str:
    return _json_hash(
        {
            "members": [f"serviceAccount:{_APPLY_SERVICE_ACCOUNT}"],
            "role": "roles/run.invoker",
        }
    )


def _validated_https_origin(value: object) -> str:
    if type(value) is not str or len(value) > 2_048:
        raise ValueError("service URI is invalid")
    split = urlsplit(value)
    if (
        split.scheme != "https"
        or not split.hostname
        or split.username is not None
        or split.password is not None
        or split.path not in {"", "/"}
        or split.query
        or split.fragment
    ):
        raise ValueError("service URI is not an HTTPS origin")
    return value.rstrip("/")


def _validate_record_common(
    candidate: CandidateIdentity,
    deployments: tuple[ServiceDeploymentObservation, ...],
    started_at: datetime,
    completed_at: datetime,
) -> None:
    if completed_at < started_at:
        raise ValueError("acceptance completion precedes start")
    if tuple(item.component for item in deployments) != tuple(ServiceComponent):
        raise ValueError("deployment observation set is not closed")
    expected_image = (
        f"{candidate.region}-docker.pkg.dev/{candidate.project_id}/reconcile-p5/"
        f"reconcile@{candidate.image_digest}"
    )
    for item in deployments:
        if (
            item.image_reference != expected_image
            or item.source_revision != candidate.source_revision
            or item.image_digest != candidate.image_digest
            or item.infrastructure_revision != candidate.infrastructure_revision
            or item.semantic_config_sha256 != candidate.semantic_config_sha256
        ):
            raise ValueError("deployment does not match the exact candidate")


def _validate_provider_scenario(scenario: ScenarioAcceptanceObservation) -> None:
    if (
        scenario.purpose != "provider-sandbox-adaptive"
        or scenario.request.scenario is not ScenarioLaunchName.SANDBOX_ORDER
        or scenario.request.mode is not ScenarioRunMode.ADAPTIVE
    ):
        raise ValueError("provider acceptance is not the one adaptive sandbox run")
    report = scenario.snapshot.report
    if report is None or report.classification is not Classification.UNKNOWN:
        raise ValueError("provider acceptance changed deterministic authority")
    _validate_sandbox_unknown_public_report(scenario, require_both_probes=False)
    route = report.route_provenance
    if (
        route is None
        or route.route is not ScenarioHybridRoute.PLANNER_HETEROGENEOUS
        or route.outcome
        not in {
            ScenarioHybridOutcome.PLANNER_EVIDENCE,
            ScenarioHybridOutcome.FIXED_FALLBACK,
            ScenarioHybridOutcome.EXPLICIT_UNKNOWN,
        }
    ):
        raise ValueError("provider acceptance route is not allowlisted")
    capabilities = tuple(item.capability_name for item in report.probe_audit)
    if not capabilities or capabilities[0] != SANDBOX_ORDER_INGRESS_CAPABILITY_NAME:
        raise ValueError("provider acceptance did not preserve ingress bootstrap")
    if len(capabilities) > 2 or (
        len(capabilities) == 2
        and capabilities[1] != SANDBOX_ORDER_AGGREGATE_CAPABILITY_NAME
    ):
        raise ValueError("provider acceptance exceeded conditional probe scope")
    if route.outcome is ScenarioHybridOutcome.PLANNER_EVIDENCE and (
        not route.planner_invoked
        or route.fixed_connector_invoked
        or route.provider_failure
    ):
        raise ValueError("planner evidence provenance changed")
    if route.outcome is ScenarioHybridOutcome.FIXED_FALLBACK and (
        route.planner_invoked
        or not route.fixed_connector_invoked
        or not route.provider_failure
    ):
        raise ValueError("fixed fallback provenance changed")
    if route.outcome is ScenarioHybridOutcome.EXPLICIT_UNKNOWN and (
        route.fixed_connector_invoked
        or route.planner_invoked is not route.provider_failure
    ):
        raise ValueError("explicit UNKNOWN provenance changed")
    _validate_provider_event_provenance(scenario, route.outcome)


def _validate_provider_event_provenance(
    scenario: ScenarioAcceptanceObservation,
    outcome: ScenarioHybridOutcome,
) -> None:
    report = scenario.snapshot.report
    if report is None:
        raise ValueError("provider acceptance report is absent")
    advisory_turns = tuple(
        event.payload.turn
        for event in scenario.events
        if isinstance(event.payload, AdvisoryTurnEventPayload)
    )
    request_events = tuple(
        event.payload
        for event in scenario.events
        if isinstance(event.payload, ProbeRequestEventPayload)
    )
    if tuple(item.request.request_sequence for item in request_events) != tuple(
        range(1, len(request_events) + 1)
    ):
        raise ValueError("provider acceptance request event sequence changed")
    adaptive_requests = tuple(
        item
        for item in request_events
        if item.strategy is ComparisonStrategyKind.ADAPTIVE
    )
    fixed_requests = tuple(
        item for item in request_events if item.strategy is ComparisonStrategyKind.FIXED
    )
    audit = report.probe_audit

    if outcome is ScenarioHybridOutcome.EXPLICIT_UNKNOWN:
        route = report.route_provenance
        if route is not None and not route.planner_invoked:
            if advisory_turns or adaptive_requests or fixed_requests or len(audit) != 1:
                raise ValueError("predispatch UNKNOWN event provenance changed")
            return

    if outcome is ScenarioHybridOutcome.FIXED_FALLBACK:
        if advisory_turns or adaptive_requests or len(fixed_requests) != 2:
            raise ValueError("fixed fallback event provenance changed")
        if len(audit) != 2:
            raise ValueError("fixed fallback probe provenance changed")
        for request_event, audit_item in zip(
            fixed_requests,
            audit,
            strict=True,
        ):
            request = request_event.request
            if (
                request.advisory_turn_sequence is not None
                or request.proposal_sequence is not None
                or request.disposition is not ProbeRequestDisposition.SELECTED
                or request.capability_name != audit_item.capability_name
                or request.capability_version != audit_item.capability_version
                or request.request_sha256 != audit_item.request_sha256
                or request.relevant_effect_ids != (SANDBOX_ORDER_EFFECT_ID,)
            ):
                raise ValueError("fixed fallback probe provenance changed")
        return

    if fixed_requests or len(advisory_turns) != 2:
        raise ValueError("provider advisory event provenance changed")
    started, terminal = advisory_turns
    if (
        started.turn_sequence != 1
        or started.phase is not AdaptivePlannerPhase.ACQUIRE_EVIDENCE
        or started.status is not AdvisoryTurnStatus.STARTED
        or terminal.turn_sequence != started.turn_sequence
        or terminal.phase is not started.phase
        or terminal.input_sha256 != started.input_sha256
    ):
        raise ValueError("provider advisory event provenance changed")

    if outcome is ScenarioHybridOutcome.EXPLICIT_UNKNOWN:
        if (
            terminal.status is not AdvisoryTurnStatus.FAILED
            or adaptive_requests
            or len(audit) != 1
        ):
            raise ValueError("explicit UNKNOWN event provenance changed")
        return

    if outcome is not ScenarioHybridOutcome.PLANNER_EVIDENCE:
        raise ValueError("provider acceptance event outcome changed")
    if terminal.status is not AdvisoryTurnStatus.COMPLETED or len(audit) != 2:
        raise ValueError("planner evidence event provenance changed")
    if (
        terminal.proposal_count != len(adaptive_requests)
        or terminal.selected_proposal_count
        != sum(
            item.request.disposition is ProbeRequestDisposition.SELECTED
            for item in adaptive_requests
        )
        or tuple(item.request.proposal_sequence for item in adaptive_requests)
        != tuple(range(1, len(adaptive_requests) + 1))
        or any(
            item.request.advisory_turn_sequence != terminal.turn_sequence
            for item in adaptive_requests
        )
    ):
        raise ValueError("planner proposal event provenance changed")
    selected = tuple(
        item.request
        for item in adaptive_requests
        if item.request.disposition is ProbeRequestDisposition.SELECTED
    )
    if len(selected) != 1:
        raise ValueError("planner did not select one heterogeneous probe")
    request = selected[0]
    aggregate_audit = audit[1]
    if (
        request.capability_name != SANDBOX_ORDER_AGGREGATE_CAPABILITY_NAME
        or request.capability_version != SANDBOX_ORDER_CAPABILITY_VERSION
        or request.request_sha256 != aggregate_audit.request_sha256
        or request.relevant_effect_ids != (SANDBOX_ORDER_EFFECT_ID,)
    ):
        raise ValueError("planner selected probe provenance changed")


def _validate_storage_public_report(
    scenario: ScenarioAcceptanceObservation,
) -> None:
    summary = scenario.snapshot.envelope_summary
    report = scenario.snapshot.report
    if report is None:
        raise ValueError("storage acceptance report is absent")
    if (
        summary.target_kind != STORAGE_TARGET_KIND
        or tuple(
            (item.effect_id, item.commit_scope) for item in summary.expected_effects
        )
        != ((STORAGE_EFFECT_ID, "object-create"),)
        or tuple((item.name, item.version) for item in summary.enabled_capabilities)
        != ((STORAGE_CAPABILITY_NAME, STORAGE_CAPABILITY_VERSION),)
        or len(report.probe_audit) != 1
        or len(report.evidence) != 1
        or report.missing_evidence
    ):
        raise ValueError("storage acceptance public shape changed")
    audit = report.probe_audit[0]
    evidence = report.evidence[0]
    proof = report.proof
    if (
        audit.capability_name != STORAGE_CAPABILITY_NAME
        or audit.capability_version != STORAGE_CAPABILITY_VERSION
        or audit.outcome is not ProbeOutcome.COMPLETED
        or audit.request_sha256 is None
        or audit.result_sha256 is None
        or audit.result_byte_count is None
        or audit.result_byte_count < 1
        or audit.evidence_ids != (evidence.evidence_id,)
        or evidence.capability_name != STORAGE_CAPABILITY_NAME
        or evidence.capability_version != STORAGE_CAPABILITY_VERSION
        or evidence.disposition is not EvidenceDisposition.ADMITTED
        or evidence.reason is not EvidenceReason.AUTHORITATIVE_EXACT_CORRELATION
        or evidence.authority is not EvidenceAuthority.TARGET_STATE
        or evidence.operation_status is not OperationStatus.TERMINAL_COMMITTED
        or tuple((item.effect_id, item.state) for item in evidence.effect_assertions)
        != ((STORAGE_EFFECT_ID, EffectAssertionState.ESTABLISHED),)
        or proof is None
        or proof.operation_status is not OperationStatus.TERMINAL_COMMITTED
        or proof.conflicting_authority
        or proof.admitted_evidence_ids != (evidence.evidence_id,)
        or tuple(
            (item.effect_id, item.commit_scope, item.state, item.evidence_ids)
            for item in proof.effect_findings
        )
        != (
            (
                STORAGE_EFFECT_ID,
                "object-create",
                EffectAssertionState.ESTABLISHED,
                (evidence.evidence_id,),
            ),
        )
    ):
        raise ValueError("storage exact generation evidence changed")


def _validate_firestore_public_report(
    scenario: ScenarioAcceptanceObservation,
) -> None:
    summary = scenario.snapshot.envelope_summary
    report = scenario.snapshot.report
    if report is None:
        raise ValueError("Firestore acceptance report is absent")
    expected_states = (
        (FIRESTORE_BUSINESS_EFFECT_IDS[0], EffectAssertionState.ESTABLISHED),
        (FIRESTORE_BUSINESS_EFFECT_IDS[1], EffectAssertionState.ESTABLISHED),
        (FIRESTORE_BUSINESS_EFFECT_IDS[2], EffectAssertionState.NOT_ESTABLISHED),
    )
    expected_findings = tuple(
        (effect_id, effect_id, state) for effect_id, state in expected_states
    )
    if (
        summary.target_kind != FIRESTORE_BUSINESS_TARGET_KIND
        or tuple(
            (item.effect_id, item.commit_scope) for item in summary.expected_effects
        )
        != tuple((item, item) for item in FIRESTORE_BUSINESS_EFFECT_IDS)
        or tuple((item.name, item.version) for item in summary.enabled_capabilities)
        != (
            (
                FIRESTORE_BUSINESS_CAPABILITY_NAME,
                FIRESTORE_BUSINESS_CAPABILITY_VERSION,
            ),
        )
        or len(report.probe_audit) != 1
        or len(report.evidence) != 1
        or len(report.missing_evidence) != 1
        or report.missing_evidence[0].effect_ids != (FIRESTORE_BUSINESS_EFFECT_IDS[2],)
        or report.missing_evidence[0].reason != "authoritative-effect-proof-required"
    ):
        raise ValueError("Firestore acceptance public shape changed")
    audit = report.probe_audit[0]
    evidence = report.evidence[0]
    proof = report.proof
    if (
        audit.capability_name != FIRESTORE_BUSINESS_CAPABILITY_NAME
        or audit.capability_version != FIRESTORE_BUSINESS_CAPABILITY_VERSION
        or audit.outcome is not ProbeOutcome.COMPLETED
        or audit.request_sha256 is None
        or audit.result_sha256 is None
        or audit.result_byte_count is None
        or audit.result_byte_count < 1
        or audit.evidence_ids != (evidence.evidence_id,)
        or evidence.capability_name != FIRESTORE_BUSINESS_CAPABILITY_NAME
        or evidence.capability_version != FIRESTORE_BUSINESS_CAPABILITY_VERSION
        or evidence.disposition is not EvidenceDisposition.ADMITTED
        or evidence.reason is not EvidenceReason.AUTHORITATIVE_EXACT_CORRELATION
        or evidence.authority is not EvidenceAuthority.TARGET_STATE
        or evidence.operation_status is not OperationStatus.TERMINAL_COMMITTED
        or tuple((item.effect_id, item.state) for item in evidence.effect_assertions)
        != expected_states
        or proof is None
        or proof.operation_status is not OperationStatus.TERMINAL_COMMITTED
        or proof.conflicting_authority
        or proof.admitted_evidence_ids != (evidence.evidence_id,)
        or tuple(
            (item.effect_id, item.commit_scope, item.state)
            for item in proof.effect_findings
        )
        != expected_findings
        or any(
            item.evidence_ids != (evidence.evidence_id,)
            for item in proof.effect_findings
        )
    ):
        raise ValueError("Firestore selected-effect proof changed")


def _validate_sandbox_unknown_public_report(
    scenario: ScenarioAcceptanceObservation,
    *,
    require_both_probes: bool,
) -> None:
    summary = scenario.snapshot.envelope_summary
    report = scenario.snapshot.report
    if report is None:
        raise ValueError("sandbox acceptance report is absent")
    expected_capabilities = (
        (SANDBOX_ORDER_INGRESS_CAPABILITY_NAME, SANDBOX_ORDER_CAPABILITY_VERSION),
        (SANDBOX_ORDER_AGGREGATE_CAPABILITY_NAME, SANDBOX_ORDER_CAPABILITY_VERSION),
    )
    audit_capabilities = tuple(
        (item.capability_name, item.capability_version) for item in report.probe_audit
    )
    if (
        summary.target_kind != SANDBOX_ORDER_TARGET_KIND
        or tuple(
            (item.effect_id, item.commit_scope) for item in summary.expected_effects
        )
        != ((SANDBOX_ORDER_EFFECT_ID, "sandbox-order"),)
        or tuple((item.name, item.version) for item in summary.enabled_capabilities)
        != expected_capabilities
        or not report.probe_audit
        or audit_capabilities
        not in (
            (expected_capabilities,)
            if require_both_probes
            else (expected_capabilities[:1], expected_capabilities)
        )
        or (
            summary.evidence_budget.max_probes,
            summary.evidence_budget.max_elapsed_ms,
            summary.evidence_budget.max_total_result_bytes,
            summary.evidence_budget.max_cost_units,
        )
        != (2, 5_000, 8_192, 2)
        or len(report.evidence) != len(report.probe_audit)
        or len(report.missing_evidence) != 1
        or report.missing_evidence[0].effect_ids != (SANDBOX_ORDER_EFFECT_ID,)
    ):
        raise ValueError("sandbox weak-evidence public shape changed")
    total_result_bytes = 0
    previous_elapsed_ms = 0
    for index, audit in enumerate(report.probe_audit, start=1):
        result_byte_count = audit.result_byte_count or 0
        total_result_bytes += result_byte_count
        if (
            audit.probe_sequence != index
            or audit.probe_count_used != index
            or audit.cost_units_used != index
            or audit.result_bytes_acquired != total_result_bytes
            or audit.session_elapsed_ms < previous_elapsed_ms
            or audit.session_elapsed_ms > summary.evidence_budget.max_elapsed_ms
            or total_result_bytes > summary.evidence_budget.max_total_result_bytes
        ):
            raise ValueError("sandbox probe budget counters changed")
        previous_elapsed_ms = audit.session_elapsed_ms
    if any(
        audit.outcome is not ProbeOutcome.COMPLETED
        or audit.request_sha256 is None
        or audit.result_sha256 is None
        or audit.result_byte_count is None
        or audit.result_byte_count < 1
        or audit.evidence_ids != (evidence.evidence_id,)
        or evidence.capability_name != audit.capability_name
        or evidence.capability_version != audit.capability_version
        for audit, evidence in zip(
            report.probe_audit,
            report.evidence,
            strict=True,
        )
    ) or any(
        evidence.disposition is not EvidenceDisposition.WEAK
        or evidence.reason
        not in {
            EvidenceReason.NON_AUTHORITATIVE_LOG_ONLY,
            EvidenceReason.NOT_FOUND_ABSENCE_ONLY,
        }
        or evidence.authority
        not in {EvidenceAuthority.SUPPLEMENTARY, EvidenceAuthority.WEAK}
        or evidence.operation_status is not None
        or tuple((item.effect_id, item.state) for item in evidence.effect_assertions)
        != ((SANDBOX_ORDER_EFFECT_ID, EffectAssertionState.UNVERIFIED),)
        for evidence in report.evidence
    ):
        raise ValueError("sandbox evidence is not exclusively weak")
    proof = report.proof
    if (
        proof is None
        or proof.operation_status is not None
        or proof.conflicting_authority
        or proof.admitted_evidence_ids
        or tuple(
            (item.effect_id, item.commit_scope, item.state, item.evidence_ids)
            for item in proof.effect_findings
        )
        != (
            (
                SANDBOX_ORDER_EFFECT_ID,
                "sandbox-order",
                EffectAssertionState.UNVERIFIED,
                (),
            ),
        )
    ):
        raise ValueError("sandbox UNKNOWN proof changed")


def _exact_main_substitutions() -> tuple[ExactMainTestSubstitution, ...]:
    return (
        ExactMainTestSubstitution(
            control="controller-restart",
            tests=(
                "tests/integration/test_hosted_firestore_workflow.py::test_started_mutation_restart_escalates_without_any_remote_call",
                "tests/integration/test_hosted_firestore_workflow.py::test_started_investigation_restart_only_investigates_then_cleans_up",
                "tests/integration/test_hosted_firestore_workflow.py::test_pending_cleanup_restart_marks_failed_without_losing_report",
            ),
        ),
        ExactMainTestSubstitution(
            control="provider-timeout",
            tests=(
                "tests/unit/hosted/test_planner.py::test_failure_edges_do_not_retry_or_release_candidate_attempts",
            ),
        ),
        ExactMainTestSubstitution(
            control="provider-construction-failure",
            tests=(
                "tests/integration/test_hosted_conditional_planning.py::test_hosted_runtime_predispatch_planner_failure_uses_fresh_fixed_path",
            ),
        ),
        ExactMainTestSubstitution(
            control="cleanup-failure",
            tests=(
                "tests/integration/test_storage_scenario.py::test_cleanup_failure_is_reported_separately_from_classification",
                "tests/integration/test_firestore_business_scenario.py::test_cleanup_failure_preserves_a_replacement_document",
                "tests/integration/test_sandbox_order_scenario.py::test_cleanup_failure_preserves_a_replacement_private_order",
            ),
        ),
        ExactMainTestSubstitution(
            control="negative-evidence-injection",
            tests=(
                "tests/integration/test_storage_scenario.py::test_negative_controls_remain_unknown",
                "tests/integration/test_firestore_business_scenario.py::test_inaccessible_composite_read_remains_unknown",
                "tests/integration/test_sandbox_order_scenario.py::test_malformed_weak_storage_fails_closed",
            ),
        ),
        ExactMainTestSubstitution(
            control="budget-exhaustion",
            tests=(
                "tests/unit/test_adaptive.py::test_conditional_exhausted_read_budget_skips_planner",
                "tests/integration/test_hosted_conditional_planning.py::test_hosted_runtime_bootstrap_failure_does_not_claim_planner_invocation",
                "tests/integration/test_sandbox_order_scenario.py::test_exhausted_probe_budget_preserves_unknown",
            ),
        ),
        ExactMainTestSubstitution(
            control="cloud-run-cold-start",
            tests=(
                "tests/unit/hosted/test_firestore_scenarios.py::test_projection_is_contiguous_coherent_and_available_after_restart",
                "tests/unit/hosted/test_firestore_provider_ledger.py::test_restart_never_reopens_any_persisted_state",
            ),
        ),
        ExactMainTestSubstitution(
            control="recovery-action-authority-non-replay-denials",
            tests=(
                "tests/unit/hosted/test_recovery_cloud_run_authority.py::test_recovery_authorizer_rejects_legacy_replayable_scope",
                "tests/unit/hosted/test_recovery_cloud_run_authority.py::test_missing_promotion_authority_is_rejected_before_claim",
                "tests/unit/hosted/test_recovery_cloud_run_authority.py::test_certificate_bound_promotion_rejects_tampering_before_claim",
                "tests/unit/hosted/test_recovery_cloud_run_authority.py::test_expired_promotion_permit_is_rejected_before_provider_authority",
            ),
        ),
    )


def _provider_limitations(
    diagnostics: LifecycleDiagnostics,
) -> tuple[AcceptanceLimitation, ...]:
    result = [
        AcceptanceLimitation.PROVIDER_TIMEOUT_NOT_FORCED,
        AcceptanceLimitation.PROVIDER_CONSTRUCTION_FAILURE_NOT_FORCED,
        AcceptanceLimitation.PLATFORM_LOGS_DIAGNOSTIC_ONLY,
    ]
    if not diagnostics.available:
        result.append(AcceptanceLimitation.LIFECYCLE_DIAGNOSTICS_UNAVAILABLE)
    return tuple(result)


def _hosted_limitations(
    diagnostics: LifecycleDiagnostics,
) -> tuple[AcceptanceLimitation, ...]:
    result = [
        AcceptanceLimitation.INFLIGHT_CONTROLLER_RESTART_NOT_FORCED,
        AcceptanceLimitation.PROVIDER_TIMEOUT_NOT_FORCED,
        AcceptanceLimitation.PROVIDER_CONSTRUCTION_FAILURE_NOT_FORCED,
        AcceptanceLimitation.TARGET_CLEANUP_FAILURE_NOT_FORCED,
        AcceptanceLimitation.NEGATIVE_EVIDENCE_INJECTION_NOT_EXPOSED,
        AcceptanceLimitation.BUDGET_EXHAUSTION_NOT_FORCED,
        AcceptanceLimitation.CLOUD_RUN_COLD_START_NOT_FORCED,
        AcceptanceLimitation.PLATFORM_LOGS_DIAGNOSTIC_ONLY,
        AcceptanceLimitation.STORAGE_RAW_PROVIDER_FIELDS_NOT_PUBLIC,
        AcceptanceLimitation.SANDBOX_DISCARD_OUTCOME_NOT_LIVE,
    ]
    if not diagnostics.available:
        result.append(AcceptanceLimitation.LIFECYCLE_DIAGNOSTICS_UNAVAILABLE)
    return tuple(result)


def _utc_now() -> datetime:
    return datetime.now(UTC)


def _launch_id(candidate: CandidateIdentity, label: str) -> str:
    return f"p5-{label}-{candidate.candidate_sha256[:24]}"


def _launch(
    candidate: CandidateIdentity,
    label: str,
    scenario: ScenarioLaunchName,
    mode: ScenarioRunMode,
) -> ScenarioLaunchRequest:
    return ScenarioLaunchRequest(
        schema_version=SCENARIO_LAUNCH_REQUEST_VERSION,
        launch_id=_launch_id(candidate, label),
        scenario=scenario,
        mode=mode,
    )


async def run_provider_acceptance(
    candidate: CandidateIdentity,
    *,
    state_root: Path,
    backend: HostedAcceptanceBackend,
    clock: Callable[[], datetime] = _utc_now,
) -> AcceptanceArtifactBinding:
    _require_record_absent(state_root, AcceptanceMode.PROVIDER, candidate)
    started_at = clock()
    deployments = await backend.deployments(candidate)
    if not await backend.provider_ledger_absent():
        raise HostedAcceptanceError("PROVIDER_LEDGER_ALREADY_CONSUMED")
    adaptive_recovery = await backend.recovery_lane(
        policy=RecoveryRunPolicy.ADAPTIVE,
        fault=RecoveryRunFault.DROP_AFTER_ACCEPT,
        purpose="provider-adaptive-drop",
    )
    provider_ledger = await backend.provider_ledger()
    diagnostics = await backend.diagnostics()
    values = {
        "schema_version": PHASE5_HOSTED_ACCEPTANCE_VERSION,
        "record_type": "provider-acceptance",
        "candidate": candidate,
        "deployments": deployments,
        "provider_ledger_absent_before": True,
        "adaptive_recovery": adaptive_recovery,
        "provider_ledger": provider_ledger,
        "diagnostics": diagnostics,
        "limitations": _provider_limitations(diagnostics),
        "started_at": started_at,
        "completed_at": clock(),
    }
    record = ProviderAcceptanceRecord(
        **values,  # type: ignore[arg-type]
        record_sha256=_values_hash(values),
    )
    return _write_record(state_root, AcceptanceMode.PROVIDER, candidate, record)


async def run_hosted_acceptance(
    candidate: CandidateIdentity,
    *,
    state_root: Path,
    backend: HostedAcceptanceBackend,
    clock: Callable[[], datetime] = _utc_now,
) -> AcceptanceArtifactBinding:
    _require_record_absent(state_root, AcceptanceMode.HOSTED, candidate)
    started_at = clock()
    provider, provider_binding = read_provider_record(state_root, candidate)
    deployments = await backend.deployments(candidate)
    requests = (
        (
            _launch(
                candidate,
                "storage-authoritative",
                ScenarioLaunchName.STORAGE,
                ScenarioRunMode.ADAPTIVE,
            ),
            "hosted-storage-authoritative",
        ),
        (
            _launch(
                candidate,
                "firestore-authoritative",
                ScenarioLaunchName.FIRESTORE_BUSINESS,
                ScenarioRunMode.ADAPTIVE,
            ),
            "hosted-firestore-authoritative",
        ),
        (
            _launch(
                candidate,
                "sandbox-fixed",
                ScenarioLaunchName.SANDBOX_ORDER,
                ScenarioRunMode.FIXED,
            ),
            "hosted-sandbox-fixed-unknown",
        ),
    )
    scenarios = tuple(
        [
            await backend.scenario(request, purpose=purpose)
            for request, purpose in requests
        ]
    )
    recovery_specs = (
        (
            RecoveryRunPolicy.BLIND_RETRY,
            RecoveryRunFault.DROP_AFTER_ACCEPT,
            "hosted-blind-retry-drop",
        ),
        (
            RecoveryRunPolicy.BLIND_ABORT,
            RecoveryRunFault.DROP_AFTER_ACCEPT,
            "hosted-blind-abort-drop",
        ),
        (
            RecoveryRunPolicy.FIXED,
            RecoveryRunFault.DROP_AFTER_ACCEPT,
            "hosted-fixed-drop",
        ),
        (
            RecoveryRunPolicy.FIXED,
            RecoveryRunFault.NO_FAULT,
            "hosted-fixed-no-fault",
        ),
        (
            RecoveryRunPolicy.FIXED,
            RecoveryRunFault.SUPPRESS_BEFORE_DISPATCH,
            "hosted-fixed-suppress",
        ),
    )
    recovery_lanes = tuple(
        [
            await backend.recovery_lane(
                policy=policy,
                fault=fault,
                purpose=purpose,
            )
            for policy, fault, purpose in recovery_specs
        ]
    )
    provider_ledger = await backend.provider_ledger()
    if provider_ledger != provider.provider_ledger:
        raise HostedAcceptanceError("PROVIDER_LEDGER_CHANGED")
    comparison_lanes = (
        *(lane.result for lane in recovery_lanes[:3]),
        provider.adaptive_recovery.result,
    )
    comparison_resets = (
        *(lane.reset for lane in recovery_lanes[:3]),
        provider.adaptive_recovery.reset,
    )
    common = provider.adaptive_recovery.result
    recovery_comparison = RecoveryPolicyComparison(
        schema_version=RECOVERY_POLICY_COMPARISON_VERSION,
        comparison_id=(
            "comparison-"
            + _json_hash(
                {
                    "candidate_sha256": candidate.candidate_sha256,
                    "run_ids": [lane.run_id for lane in comparison_lanes],
                }
            )[:32]
        ),
        release_id=common.firestore.release_id,
        fault=RecoveryRunFault.DROP_AFTER_ACCEPT.value,
        target_sha256=common.target_sha256,
        input_intent_sha256=common.input_intent_sha256,
        fault_boundary_sha256=common.fault_boundary_sha256,
        observation_catalog_sha256=common.observation_catalog_sha256,
        lanes=comparison_lanes,
        reset_results=comparison_resets,
        created_at=started_at,
    )
    storage = scenarios[0]
    duplicate = await backend.concurrent_replay(storage)
    resume = await backend.cursor_resume(storage)
    parity = await backend.interface_parity(storage)
    denials = await backend.denials()
    diagnostics = await backend.diagnostics()
    values = {
        "schema_version": PHASE5_HOSTED_ACCEPTANCE_VERSION,
        "record_type": "hosted-acceptance",
        "candidate": candidate,
        "provider_artifact": provider_binding,
        "deployments": deployments,
        "scenarios": scenarios,
        "recovery_lanes": recovery_lanes,
        "recovery_comparison": recovery_comparison,
        "provider_ledger": provider_ledger,
        "duplicate_request": duplicate,
        "cursor_resume": resume,
        "interface_parity": parity,
        "denials": denials,
        "diagnostics": diagnostics,
        "exact_main_test_substitutions": _exact_main_substitutions(),
        "limitations": _hosted_limitations(diagnostics),
        "started_at": started_at,
        "completed_at": clock(),
    }
    record = HostedAcceptanceRecord(
        **values,  # type: ignore[arg-type]
        record_sha256=_values_hash(values),
    )
    return _write_record(state_root, AcceptanceMode.HOSTED, candidate, record)


def _values_hash(values: Mapping[str, object]) -> str:
    projected: dict[str, object] = {}
    for key, value in values.items():
        if isinstance(value, StrictModel):
            projected[key] = value.model_dump(mode="json")
        elif isinstance(value, tuple):
            projected[key] = [
                item.model_dump(mode="json")
                if isinstance(item, StrictModel)
                else item.value
                if isinstance(item, StrEnum)
                else item
                for item in value
            ]
        elif isinstance(value, datetime):
            projected[key] = value.astimezone(UTC).isoformat().replace("+00:00", "Z")
        else:
            projected[key] = value
    return _json_hash(projected)


def _state_directory(state_root: Path) -> Path:
    if not isinstance(state_root, Path) or not state_root.is_absolute():
        raise HostedAcceptanceError("STATE_ROOT_INVALID")
    try:
        root = state_root.resolve(strict=True)
        metadata = root.stat()
    except OSError as error:
        raise HostedAcceptanceError("STATE_ROOT_INVALID") from error
    if (
        root != state_root
        or not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != os.getuid()
        or stat.S_IMODE(metadata.st_mode) & 0o077
    ):
        raise HostedAcceptanceError("STATE_ROOT_INVALID")
    directory = root / "acceptance"
    try:
        directory.mkdir(mode=0o700)
    except FileExistsError:
        pass
    except OSError as error:
        raise HostedAcceptanceError("ACCEPTANCE_DIRECTORY_INVALID") from error
    try:
        observed = directory.lstat()
    except OSError as error:
        raise HostedAcceptanceError("ACCEPTANCE_DIRECTORY_INVALID") from error
    if (
        not stat.S_ISDIR(observed.st_mode)
        or stat.S_ISLNK(observed.st_mode)
        or observed.st_uid != os.getuid()
        or stat.S_IMODE(observed.st_mode) != 0o700
    ):
        raise HostedAcceptanceError("ACCEPTANCE_DIRECTORY_INVALID")
    return directory


def _record_path(
    state_root: Path,
    mode: AcceptanceMode,
    candidate: CandidateIdentity,
) -> Path:
    return _state_directory(state_root) / (
        f"{mode.value}-{candidate.candidate_sha256}.json"
    )


def _require_record_absent(
    state_root: Path,
    mode: AcceptanceMode,
    candidate: CandidateIdentity,
) -> None:
    path = _record_path(state_root, mode, candidate)
    try:
        path.lstat()
    except FileNotFoundError:
        return
    except OSError as error:
        raise HostedAcceptanceError("ACCEPTANCE_DIRECTORY_INVALID") from error
    raise HostedAcceptanceError("ACCEPTANCE_RECORD_EXISTS")


def _write_record(
    state_root: Path,
    mode: AcceptanceMode,
    candidate: CandidateIdentity,
    record: ProviderAcceptanceRecord | HostedAcceptanceRecord,
) -> AcceptanceArtifactBinding:
    path = _record_path(state_root, mode, candidate)
    payload = canonical_json_bytes(record)
    if not 1 <= len(payload) <= _MAX_RECORD_BYTES:
        raise HostedAcceptanceError("ACCEPTANCE_RECORD_TOO_LARGE")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags, 0o400)
    except FileExistsError as error:
        raise HostedAcceptanceError("ACCEPTANCE_RECORD_EXISTS") from error
    except OSError as error:
        raise HostedAcceptanceError("ACCEPTANCE_RECORD_WRITE_FAILED") from error
    try:
        offset = 0
        while offset < len(payload):
            written = os.write(descriptor, payload[offset:])
            if written < 1:
                raise HostedAcceptanceError("ACCEPTANCE_RECORD_WRITE_FAILED")
            offset += written
        os.fchmod(descriptor, 0o400)
        os.fsync(descriptor)
    except BaseException:
        try:
            os.close(descriptor)
        finally:
            try:
                path.unlink()
            except OSError:
                pass
        raise
    else:
        os.close(descriptor)
    directory_descriptor = os.open(path.parent, os.O_RDONLY | os.O_CLOEXEC)
    try:
        os.fsync(directory_descriptor)
    finally:
        os.close(directory_descriptor)
    return AcceptanceArtifactBinding(
        schema_version=PHASE5_ACCEPTANCE_ARTIFACT_VERSION,
        mode=mode,
        path=str(path),
        record_sha256=record.record_sha256,
        file_sha256=hashlib.sha256(payload).hexdigest(),
        byte_count=len(payload),
    )


def _read_record_bytes(path: Path) -> bytes:
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    except OSError as error:
        raise HostedAcceptanceError("PROVIDER_RECORD_UNAVAILABLE") from error
    try:
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != os.getuid()
            or stat.S_IMODE(metadata.st_mode) != 0o400
            or metadata.st_nlink != 1
            or not 1 <= metadata.st_size <= _MAX_RECORD_BYTES
        ):
            raise HostedAcceptanceError("PROVIDER_RECORD_INVALID")
        chunks: list[bytes] = []
        remaining = _MAX_RECORD_BYTES + 1
        while remaining > 0:
            chunk = os.read(descriptor, min(1_048_576, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        payload = b"".join(chunks)
        if len(payload) != metadata.st_size:
            raise HostedAcceptanceError("PROVIDER_RECORD_INVALID")
        return payload
    finally:
        os.close(descriptor)


def read_acceptance_record(
    state_root: Path,
    candidate: CandidateIdentity,
    mode: AcceptanceMode,
) -> tuple[
    ProviderAcceptanceRecord | HostedAcceptanceRecord,
    AcceptanceArtifactBinding,
]:
    if type(mode) is not AcceptanceMode:
        raise HostedAcceptanceError("ACCEPTANCE_MODE_INVALID")
    path = _record_path(state_root, mode, candidate)
    payload = _read_record_bytes(path)
    record_type: type[ProviderAcceptanceRecord] | type[HostedAcceptanceRecord]
    if mode is AcceptanceMode.PROVIDER:
        record_type = ProviderAcceptanceRecord
    else:
        record_type = HostedAcceptanceRecord
    try:
        record = decode_contract(payload, record_type)
    except (TypeError, ValueError) as error:
        raise HostedAcceptanceError("ACCEPTANCE_RECORD_INVALID") from error
    if canonical_json_bytes(record) != payload or record.candidate != candidate:
        raise HostedAcceptanceError("ACCEPTANCE_RECORD_INVALID")
    binding = AcceptanceArtifactBinding(
        schema_version=PHASE5_ACCEPTANCE_ARTIFACT_VERSION,
        mode=mode,
        path=str(path),
        record_sha256=record.record_sha256,
        file_sha256=hashlib.sha256(payload).hexdigest(),
        byte_count=len(payload),
    )
    if isinstance(record, HostedAcceptanceRecord):
        provider, provider_binding = read_acceptance_record(
            state_root,
            candidate,
            AcceptanceMode.PROVIDER,
        )
        if (
            not isinstance(provider, ProviderAcceptanceRecord)
            or record.provider_artifact != provider_binding
            or record.provider_ledger != provider.provider_ledger
            or record.recovery_comparison.lanes[3] != provider.adaptive_recovery.result
            or record.recovery_comparison.reset_results[3]
            != provider.adaptive_recovery.reset
            or record.recovery_lanes[0].reprovision.previous_service_uid
            != provider.adaptive_recovery.reprovision.service_uid
            or len(
                {
                    provider.adaptive_recovery.reprovision.service_uid,
                    *(lane.reprovision.service_uid for lane in record.recovery_lanes),
                }
            )
            != 1 + len(record.recovery_lanes)
        ):
            raise HostedAcceptanceError("HOSTED_PROVIDER_CHAIN_INVALID")
    return record, binding


def read_provider_record(
    state_root: Path,
    candidate: CandidateIdentity,
) -> tuple[ProviderAcceptanceRecord, AcceptanceArtifactBinding]:
    try:
        record, binding = read_acceptance_record(
            state_root,
            candidate,
            AcceptanceMode.PROVIDER,
        )
    except HostedAcceptanceError as error:
        if error.code in {
            "ACCEPTANCE_RECORD_INVALID",
            "PROVIDER_RECORD_INVALID",
        }:
            raise HostedAcceptanceError("PROVIDER_RECORD_INVALID") from error
        raise
    if not isinstance(record, ProviderAcceptanceRecord):
        raise HostedAcceptanceError("PROVIDER_RECORD_INVALID")
    return record, binding


def _default_command_runner(
    argv: tuple[str, ...],
    cwd: Path,
    environment: Mapping[str, str],
    timeout_seconds: int,
) -> object:
    return subprocess.run(
        argv,
        cwd=cwd,
        env=dict(environment),
        check=False,
        capture_output=True,
        timeout=timeout_seconds,
    )


def _minimal_environment(source: Mapping[str, str]) -> dict[str, str]:
    home = Path(source.get("HOME", str(Path.home()))).resolve()
    if not home.is_absolute():
        raise HostedAcceptanceError("COMMAND_ENVIRONMENT_INVALID")
    result = {
        "CLOUDSDK_CORE_DISABLE_PROMPTS": "1",
        "HOME": str(home),
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "PATH": "/home/reconcile/.local/bin:/usr/bin:/bin",
        "PYTHONNOUSERSITE": "1",
    }
    configuration = source.get("CLOUDSDK_ACTIVE_CONFIG_NAME")
    if configuration is not None:
        if re.fullmatch(r"[a-z][a-z0-9-]{0,62}", configuration) is None:
            raise HostedAcceptanceError("COMMAND_ENVIRONMENT_INVALID")
        result["CLOUDSDK_ACTIVE_CONFIG_NAME"] = configuration
    return result


def _checked_command_bytes(result: object) -> bytes:
    if (
        not isinstance(result, subprocess.CompletedProcess)
        or result.returncode != 0
        or type(result.stdout) is not bytes
        or type(result.stderr) is not bytes
        or len(result.stdout) > _MAX_COMMAND_BYTES
        or len(result.stderr) > _MAX_COMMAND_BYTES
    ):
        raise HostedAcceptanceError("READ_ONLY_COMMAND_FAILED")
    return result.stdout


def _private_directory(path: Path, *, writable: bool) -> Path:
    try:
        resolved = path.resolve(strict=True)
        metadata = path.lstat()
    except OSError as error:
        raise HostedAcceptanceError("CANARY_REPROVISION_BINDING_INVALID") from error
    mode = stat.S_IMODE(metadata.st_mode)
    if (
        resolved != path
        or not stat.S_ISDIR(metadata.st_mode)
        or stat.S_ISLNK(metadata.st_mode)
        or metadata.st_uid != os.getuid()
        or mode & 0o077
        or (writable and not mode & stat.S_IWUSR)
    ):
        raise HostedAcceptanceError("CANARY_REPROVISION_BINDING_INVALID")
    return resolved


def _read_owner_file(
    path: Path,
    *,
    maximum: int,
    exact_mode: int | None,
    failure: str = "CANARY_REPROVISION_BINDING_INVALID",
) -> bytes:
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    except OSError as error:
        raise HostedAcceptanceError(failure) from error
    try:
        metadata = os.fstat(descriptor)
        mode = stat.S_IMODE(metadata.st_mode)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != os.getuid()
            or metadata.st_nlink != 1
            or metadata.st_size < 0
            or metadata.st_size > maximum
            or (exact_mode is not None and mode != exact_mode)
            or (exact_mode is None and mode & 0o022)
        ):
            raise HostedAcceptanceError(failure)
        chunks: list[bytes] = []
        remaining = maximum + 1
        while remaining > 0:
            chunk = os.read(descriptor, min(1_048_576, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        payload = b"".join(chunks)
        if len(payload) != metadata.st_size:
            raise HostedAcceptanceError(failure)
        return payload
    finally:
        os.close(descriptor)


def _reject_duplicate_json_pairs(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


def _json_object(payload: bytes, *, canonical: bool, failure: str) -> dict[str, object]:
    try:
        value = json.loads(payload, object_pairs_hook=_reject_duplicate_json_pairs)
        if type(value) is not dict:
            raise ValueError
        if (
            canonical
            and json.dumps(
                value,
                allow_nan=False,
                ensure_ascii=False,
                separators=(",", ":"),
                sort_keys=True,
            ).encode("utf-8")
            != payload
        ):
            raise ValueError
    except (TypeError, UnicodeError, ValueError) as error:
        raise HostedAcceptanceError(failure) from error
    return value


def _runtime_source_sha256(source_root: Path) -> str:
    runtime = source_root / "infra" / "environments" / "dev" / "runtime"
    _private_directory(source_root, writable=False)
    _private_directory(runtime, writable=False)
    try:
        names = tuple(sorted(item.name for item in runtime.iterdir()))
    except OSError as error:
        raise HostedAcceptanceError("CANARY_REPROVISION_BINDING_INVALID") from error
    if names != _RUNTIME_SOURCE_FILES:
        raise HostedAcceptanceError("CANARY_REPROVISION_BINDING_INVALID")
    values = []
    for name in names:
        payload = _read_owner_file(
            runtime / name,
            maximum=1_048_576,
            exact_mode=0o400,
        )
        values.append(
            {
                "path": f"infra/environments/dev/runtime/{name}",
                "sha256": hashlib.sha256(payload).hexdigest(),
            }
        )
    return _json_hash(values)


def _expected_canary_revision(
    candidate: CandidateIdentity,
    variables: Mapping[str, object],
) -> str:
    service_accounts = variables.get("service_account_emails")
    timeouts = variables.get("request_timeout_seconds")
    if type(service_accounts) is not dict or type(timeouts) is not dict:
        raise HostedAcceptanceError("CANARY_REPROVISION_INPUT_INVALID")
    if (
        variables.get("project_id") != candidate.project_id
        or variables.get("region") != candidate.region
        or variables.get("source_revision") != candidate.source_revision
        or variables.get("image_digest") != candidate.image_digest
        or variables.get("infrastructure_revision") != candidate.infrastructure_revision
        or variables.get("semantic_config_sha256") != candidate.semantic_config_sha256
        or service_accounts.get("canary") != _CANARY_SERVICE_ACCOUNT
        or type(timeouts.get("canary")) is not int
        or not 1 <= timeouts["canary"] <= 3_600
    ):
        raise HostedAcceptanceError("CANARY_REPROVISION_INPUT_INVALID")
    identity = {
        "image_digest": candidate.image_digest,
        "infrastructure_revision": candidate.infrastructure_revision,
        "project_id": candidate.project_id,
        "region": candidate.region,
        "request_timeout_seconds": timeouts["canary"],
        "semantic_config_sha256": candidate.semantic_config_sha256,
        "service_account_email": _CANARY_SERVICE_ACCOUNT,
        "source_revision": candidate.source_revision,
    }
    return f"{_CANARY_SERVICE}-b-{_json_hash(identity)[:16]}"


def _verify_runtime_backend(data_directory: Path) -> None:
    _private_directory(data_directory, writable=True)
    payload = _read_owner_file(
        data_directory / "terraform.tfstate",
        maximum=1_048_576,
        exact_mode=None,
    )
    value = _json_object(
        payload,
        canonical=False,
        failure="CANARY_REPROVISION_BACKEND_INVALID",
    )
    backend = value.get("backend")
    if type(backend) is not dict or backend.get("type") != "gcs":
        raise HostedAcceptanceError("CANARY_REPROVISION_BACKEND_INVALID")
    config = backend.get("config")
    if (
        type(config) is not dict
        or config.get("bucket") != f"{_PROJECT_ID}-p5-state"
        or config.get("prefix") != "phase5/runtime"
        or config.get("impersonate_service_account") != _APPLY_SERVICE_ACCOUNT
    ):
        raise HostedAcceptanceError("CANARY_REPROVISION_BACKEND_INVALID")


def _terraform_binary_sha256() -> str:
    path = Path(_TERRAFORM)
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    except OSError as error:
        raise HostedAcceptanceError("CANARY_REPROVISION_TERRAFORM_INVALID") from error
    digest = hashlib.sha256()
    try:
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid not in {0, os.getuid()}
            or metadata.st_nlink != 1
            or stat.S_IMODE(metadata.st_mode) & 0o022
            or metadata.st_size < 1
            or metadata.st_size > 256 * 1_048_576
        ):
            raise HostedAcceptanceError("CANARY_REPROVISION_TERRAFORM_INVALID")
        while True:
            chunk = os.read(descriptor, 1_048_576)
            if not chunk:
                break
            digest.update(chunk)
    finally:
        os.close(descriptor)
    return digest.hexdigest()


def _plan_mapping(value: object) -> dict[str, object]:
    if type(value) is not dict or any(type(key) is not str for key in value):
        raise HostedAcceptanceError("CANARY_REPROVISION_PLAN_INVALID")
    return value


def _is_canary_empty_collection_normalization(value: object) -> bool:
    """Accept only Cloud Run provider null-to-empty normalization drift."""

    resource = _plan_mapping(value)
    change = _plan_mapping(resource.get("change"))
    before = _plan_mapping(change.get("before"))
    after = _plan_mapping(change.get("after"))
    if (
        resource.get("address") != "google_cloud_run_v2_service.canary"
        or resource.get("mode") != "managed"
        or resource.get("type") != "google_cloud_run_v2_service"
        or resource.get("provider_name") != _PROVIDER_SOURCE
        or change.get("actions") != ["update"]
        or before == after
    ):
        return False

    normalized: list[dict[str, object]] = []
    for projection in (before, after):
        current = json.loads(json.dumps(projection))
        if current.get("annotations") is None:
            current["annotations"] = {}
        templates = current.get("template")
        if type(templates) is list and len(templates) == 1:
            containers = _plan_mapping(templates[0]).get("containers")
            if type(containers) is list and len(containers) == 1:
                container = _plan_mapping(containers[0])
                if container.get("depends_on") is None:
                    container["depends_on"] = []
        normalized.append(current)
    return normalized[0] == normalized[1]


def _validate_canary_reprovision_plan(
    payload: bytes,
    *,
    candidate: CandidateIdentity,
    variables: Mapping[str, object],
) -> None:
    plan = _json_object(
        payload,
        canonical=False,
        failure="CANARY_REPROVISION_PLAN_INVALID",
    )
    if plan.get("format_version") != "1.2" or plan.get("terraform_version") != "1.15.8":
        raise HostedAcceptanceError("CANARY_REPROVISION_PLAN_INVALID")
    resource_drift = plan.get("resource_drift")
    if (
        plan.get("deferred_changes") not in (None, [])
        or type(resource_drift) is not list
        or (
            resource_drift
            and (
                len(resource_drift) != 1
                or not _is_canary_empty_collection_normalization(resource_drift[0])
            )
        )
    ):
        raise HostedAcceptanceError("CANARY_REPROVISION_PLAN_WIDE")

    rendered = _plan_mapping(plan.get("variables"))
    rendered_values: dict[str, object] = {}
    for name, item in rendered.items():
        projected = _plan_mapping(item)
        if set(projected) != {"value"}:
            raise HostedAcceptanceError("CANARY_REPROVISION_PLAN_INVALID")
        rendered_values[name] = projected["value"]
    if rendered_values != dict(variables):
        raise HostedAcceptanceError("CANARY_REPROVISION_INPUT_CHANGED")

    changes = plan.get("resource_changes")
    if type(changes) is not list:
        raise HostedAcceptanceError("CANARY_REPROVISION_PLAN_INVALID")
    changed: dict[str, dict[str, object]] = {}
    for item in changes:
        resource = _plan_mapping(item)
        address = resource.get("address")
        change = _plan_mapping(resource.get("change"))
        actions = change.get("actions")
        if actions == ["no-op"]:
            continue
        if (
            type(address) is not str
            or address not in _CANARY_REPROVISION_ADDRESSES
            or address in changed
            or resource.get("mode") != "managed"
            or resource.get("type") != _CANARY_REPROVISION_TYPES[address]
            or resource.get("provider_name") != _PROVIDER_SOURCE
            or actions != ["delete", "create"]
            or resource.get("action_reason") != "replace_by_request"
        ):
            raise HostedAcceptanceError("CANARY_REPROVISION_PLAN_WIDE")
        before = _plan_mapping(change.get("before"))
        after = _plan_mapping(change.get("after"))
        for projection in (before, after):
            if (
                projection.get("project") != candidate.project_id
                or projection.get("location") != candidate.region
                or projection.get("name") != _CANARY_SERVICE
            ):
                raise HostedAcceptanceError("CANARY_REPROVISION_TARGET_CHANGED")
        if address in _CANARY_REPROVISION_IAM:
            role, member = _CANARY_REPROVISION_IAM[address]
            if any(
                projection.get("role") != role or projection.get("member") != member
                for projection in (before, after)
            ):
                raise HostedAcceptanceError("CANARY_REPROVISION_TARGET_CHANGED")
        changed[address] = resource
    if tuple(sorted(changed)) != tuple(sorted(_CANARY_REPROVISION_ADDRESSES)):
        raise HostedAcceptanceError("CANARY_REPROVISION_PLAN_INCOMPLETE")


class GcloudReadOnlyInspector:
    """Closed read-only Cloud Run and Cloud Logging observation boundary."""

    def __init__(
        self,
        *,
        command_runner: CommandRunner = _default_command_runner,
        environ: Mapping[str, str] | None = None,
        clock: Callable[[], datetime] = _utc_now,
        canary_baseline_revision: str | None = None,
        recovery_definition_created_at: str | None = None,
    ) -> None:
        self._runner = command_runner
        self._environment = _minimal_environment(
            os.environ if environ is None else environ
        )
        self._clock = clock
        self._canary_baseline_revision = canary_baseline_revision
        self._recovery_definition_created_at = recovery_definition_created_at

    def _run(self, argv: tuple[str, ...], *, timeout: int = 30) -> bytes:
        try:
            result = self._runner(
                argv, self._environment_home, self._environment, timeout
            )
        except (OSError, subprocess.SubprocessError) as error:
            raise HostedAcceptanceError("READ_ONLY_COMMAND_FAILED") from error
        return _checked_command_bytes(result)

    @property
    def _environment_home(self) -> Path:
        return Path(self._environment["HOME"])

    def inspect_deployments(
        self,
        candidate: CandidateIdentity,
    ) -> tuple[ServiceDeploymentObservation, ...]:
        service_payloads: dict[ServiceComponent, bytes] = {}
        for component in ServiceComponent:
            service = _SERVICE_NAMES[component]
            service_payloads[component] = self._run(
                (
                    _GCLOUD,
                    "run",
                    "services",
                    "describe",
                    service,
                    f"--project={candidate.project_id}",
                    f"--region={candidate.region}",
                    f"--impersonate-service-account={_APPLY_SERVICE_ACCOUNT}",
                    "--format=json",
                    "--quiet",
                )
            )
        serving_revisions = {
            component: _service_serving_revision(service_payloads[component])
            for component in ServiceComponent
        }
        revision_payloads: dict[ServiceComponent, bytes] = {}
        for component in ServiceComponent:
            revision_payloads[component] = self._run(
                (
                    _GCLOUD,
                    "run",
                    "revisions",
                    "describe",
                    serving_revisions[component],
                    f"--project={candidate.project_id}",
                    f"--region={candidate.region}",
                    f"--impersonate-service-account={_APPLY_SERVICE_ACCOUNT}",
                    "--format=json",
                    "--quiet",
                )
            )
        api_invoker_iam_sha256 = _normalize_api_invoker_iam_policy(
            self._run(
                (
                    _GCLOUD,
                    "run",
                    "services",
                    "get-iam-policy",
                    _SERVICE_NAMES[ServiceComponent.API],
                    f"--project={candidate.project_id}",
                    f"--region={candidate.region}",
                    f"--impersonate-service-account={_APPLY_SERVICE_ACCOUNT}",
                    "--format=json",
                    "--quiet",
                )
            )
        )
        service_uris = {
            component: _service_description_uri(payload)
            for component, payload in service_payloads.items()
        }
        return tuple(
            _normalize_service_description(
                service_payloads[component],
                revision_payload=revision_payloads[component],
                component=component,
                candidate=candidate,
                service_uris=service_uris,
                canary_baseline_revision=self._canary_baseline_revision,
                recovery_definition_created_at=(self._recovery_definition_created_at),
                api_invoker_iam_sha256=(
                    api_invoker_iam_sha256
                    if component is ServiceComponent.API
                    else None
                ),
                observed_at=self._clock(),
            )
            for component in ServiceComponent
        )

    def lifecycle_diagnostics(self) -> LifecycleDiagnostics:
        service_filter = " OR ".join(
            f'resource.labels.service_name="{name}"' for name in _SERVICE_NAMES.values()
        )
        argv = (
            _GCLOUD,
            "logging",
            "read",
            f'resource.type="cloud_run_revision" AND ({service_filter})',
            f"--project={_PROJECT_ID}",
            f"--impersonate-service-account={_APPLY_SERVICE_ACCOUNT}",
            "--freshness=1h",
            f"--limit={_MAX_LOG_ENTRIES}",
            "--order=asc",
            "--format=json",
            "--quiet",
        )
        try:
            payload = self._run(argv)
            return _normalize_log_diagnostics(payload, observed_at=self._clock())
        except (HostedAcceptanceError, TypeError, ValueError):
            return LifecycleDiagnostics(
                available=False,
                entry_count=0,
                payload_sha256=hashlib.sha256(b"").hexdigest(),
                revision_names=(),
                observed_at=self._clock(),
            )


def _decode_json_object(payload: bytes) -> dict[str, object]:
    try:
        value = json.loads(payload)
    except (UnicodeError, ValueError) as error:
        raise HostedAcceptanceError("READ_ONLY_RESPONSE_INVALID") from error
    if type(value) is not dict:
        raise HostedAcceptanceError("READ_ONLY_RESPONSE_INVALID")
    return value


def _mapping(value: object) -> dict[str, object]:
    if type(value) is not dict or any(type(key) is not str for key in value):
        raise HostedAcceptanceError("READ_ONLY_RESPONSE_INVALID")
    return value  # type: ignore[return-value]


def _sequence(value: object) -> list[object]:
    if type(value) is not list:
        raise HostedAcceptanceError("READ_ONLY_RESPONSE_INVALID")
    return value


def _text(value: object) -> str:
    if type(value) is not str or not value:
        raise HostedAcceptanceError("READ_ONLY_RESPONSE_INVALID")
    return value


def _integer(value: object) -> int:
    if type(value) is int:
        return value
    if type(value) is str and re.fullmatch(r"[1-9][0-9]*", value):
        return int(value)
    raise HostedAcceptanceError("READ_ONLY_RESPONSE_INVALID")


def _require_ready_condition(status: Mapping[str, object]) -> None:
    ready_conditions = []
    for item in _sequence(status.get("conditions")):
        condition = _mapping(item)
        if condition.get("type") == "Ready":
            ready_conditions.append(condition)
    if len(ready_conditions) != 1 or ready_conditions[0].get("status") != "True":
        raise HostedAcceptanceError("DEPLOYMENT_NOT_READY")


def _service_serving_revision(payload: bytes) -> str:
    value = _decode_json_object(payload)
    status = _mapping(value.get("status"))
    return _text(status.get("latestReadyRevisionName"))


def _invoker_iam_disabled(
    value: Mapping[str, object],
    annotations: Mapping[str, object],
) -> bool:
    observed: list[bool] = []
    direct = value.get("invokerIamDisabled")
    if direct is not None:
        if type(direct) is not bool:
            raise HostedAcceptanceError("DEPLOYMENT_DESCRIPTION_INVALID")
        observed.append(direct)
    annotation = annotations.get("run.googleapis.com/invoker-iam-disabled")
    if annotation is not None:
        if annotation == "true":
            observed.append(True)
        elif annotation == "false":
            observed.append(False)
        else:
            raise HostedAcceptanceError("DEPLOYMENT_DESCRIPTION_INVALID")
    if observed and any(item != observed[0] for item in observed[1:]):
        raise HostedAcceptanceError("DEPLOYMENT_DESCRIPTION_INVALID")
    return observed[0] if observed else False


def _normalize_api_invoker_iam_policy(payload: bytes) -> str:
    value = _decode_json_object(payload)
    bindings = _sequence(value.get("bindings"))
    if len(bindings) != 1:
        raise HostedAcceptanceError("API_INVOKER_IAM_MISMATCH")
    binding = _mapping(bindings[0])
    if set(binding) != {"members", "role"}:
        raise HostedAcceptanceError("API_INVOKER_IAM_MISMATCH")
    members = tuple(_text(item) for item in _sequence(binding.get("members")))
    expected_member = f"serviceAccount:{_APPLY_SERVICE_ACCOUNT}"
    if _text(binding.get("role")) != "roles/run.invoker" or members != (
        expected_member,
    ):
        raise HostedAcceptanceError("API_INVOKER_IAM_MISMATCH")
    return _expected_api_invoker_iam_sha256()


def _normalize_service_description(
    payload: bytes,
    *,
    revision_payload: bytes,
    component: ServiceComponent,
    candidate: CandidateIdentity,
    service_uris: Mapping[ServiceComponent, str],
    canary_baseline_revision: str | None,
    recovery_definition_created_at: str | None,
    api_invoker_iam_sha256: str | None,
    observed_at: datetime,
) -> ServiceDeploymentObservation:
    value = _decode_json_object(payload)
    metadata = _mapping(value.get("metadata"))
    annotations = _mapping(metadata.get("annotations"))
    status = _mapping(value.get("status"))
    generation = _integer(metadata.get("generation"))
    observed_generation = _integer(status.get("observedGeneration"))
    _require_ready_condition(status)
    latest_created_revision = _text(status.get("latestCreatedRevisionName"))
    revision = _text(status.get("latestReadyRevisionName"))
    if observed_generation != generation or latest_created_revision != revision:
        raise HostedAcceptanceError("DEPLOYMENT_NOT_READY")
    traffic = _sequence(status.get("traffic"))
    if len(traffic) != 1:
        raise HostedAcceptanceError("DEPLOYMENT_TRAFFIC_INVALID")
    traffic_item = _mapping(traffic[0])
    if (
        _integer(traffic_item.get("percent")) != 100
        or _text(traffic_item.get("revisionName")) != revision
    ):
        raise HostedAcceptanceError("DEPLOYMENT_TRAFFIC_INVALID")
    if _invoker_iam_disabled(value, annotations):
        raise HostedAcceptanceError("DEPLOYMENT_INVOKER_IAM_DISABLED")

    revision_value = _decode_json_object(revision_payload)
    revision_metadata = _mapping(revision_value.get("metadata"))
    revision_spec = _mapping(revision_value.get("spec"))
    revision_status = _mapping(revision_value.get("status"))
    if _text(revision_metadata.get("name")) != revision:
        raise HostedAcceptanceError("DEPLOYMENT_REVISION_MISMATCH")
    revision_generation = _integer(revision_metadata.get("generation"))
    revision_observed_generation = _integer(revision_status.get("observedGeneration"))
    _require_ready_condition(revision_status)
    if revision_observed_generation != revision_generation:
        raise HostedAcceptanceError("DEPLOYMENT_REVISION_NOT_READY")
    containers = _sequence(revision_spec.get("containers"))
    if len(containers) != 1:
        raise HostedAcceptanceError("DEPLOYMENT_DESCRIPTION_INVALID")
    container = _mapping(containers[0])
    env_values: dict[str, str] = {}
    for item in _sequence(container.get("env")):
        binding = _mapping(item)
        name = _text(binding.get("name"))
        if name in env_values or set(binding) != {"name", "value"}:
            raise HostedAcceptanceError("DEPLOYMENT_DESCRIPTION_INVALID")
        env_values[name] = _text(binding.get("value"))
    required_environment = _required_service_environment(
        component,
        candidate,
        service_uris,
        canary_baseline_revision=canary_baseline_revision,
        recovery_definition_created_at=recovery_definition_created_at,
    )
    if env_values != required_environment:
        raise HostedAcceptanceError("DEPLOYMENT_IDENTITY_MISMATCH")
    uri = _validated_https_origin(_text(status.get("url")))
    audience_annotation = _text(annotations.get("run.googleapis.com/custom-audiences"))
    try:
        custom_audiences = json.loads(audience_annotation)
    except (TypeError, ValueError) as error:
        raise HostedAcceptanceError("DEPLOYMENT_DESCRIPTION_INVALID") from error
    if custom_audiences != [_SERVICE_AUDIENCES[component]]:
        raise HostedAcceptanceError("DEPLOYMENT_IDENTITY_MISMATCH")
    expected_image = (
        f"{candidate.region}-docker.pkg.dev/{candidate.project_id}/reconcile-p5/"
        f"reconcile@{candidate.image_digest}"
    )
    image = _text(container.get("image"))
    if image != expected_image:
        raise HostedAcceptanceError("DEPLOYMENT_IDENTITY_MISMATCH")
    return ServiceDeploymentObservation(
        component=component,
        service_name=_text(metadata.get("name")),
        service_uid=_text(metadata.get("uid")),
        uri=uri,
        custom_audience=custom_audiences[0],
        generation=generation,
        observed_generation=observed_generation,
        ready=True,
        latest_created_revision=latest_created_revision,
        latest_ready_revision=revision,
        serving_revision=revision,
        traffic_percent=100,
        revision_generation=revision_generation,
        revision_observed_generation=revision_observed_generation,
        revision_ready=True,
        invoker_iam_disabled=False,
        api_invoker_iam_sha256=api_invoker_iam_sha256,
        image_reference=image,
        service_account_email=_text(revision_spec.get("serviceAccountName")),
        source_revision=candidate.source_revision,
        image_digest=candidate.image_digest,
        infrastructure_revision=candidate.infrastructure_revision,
        semantic_config_sha256=candidate.semantic_config_sha256,
        environment_sha256=_json_hash(env_values),
        describe_sha256=hashlib.sha256(payload).hexdigest(),
        revision_describe_sha256=hashlib.sha256(revision_payload).hexdigest(),
        observed_at=observed_at,
    )


def _service_description_uri(payload: bytes) -> str:
    value = _decode_json_object(payload)
    status = _mapping(value.get("status"))
    return _validated_https_origin(_text(status.get("url")))


def _parse_timestamp(value: object) -> datetime:
    text = _text(value)
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError as error:
        raise HostedAcceptanceError("READ_ONLY_RESPONSE_INVALID") from error
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise HostedAcceptanceError("READ_ONLY_RESPONSE_INVALID")
    return parsed.astimezone(UTC)


def _normalize_log_diagnostics(
    payload: bytes,
    *,
    observed_at: datetime,
) -> LifecycleDiagnostics:
    try:
        value = json.loads(payload)
    except (UnicodeError, ValueError) as error:
        raise HostedAcceptanceError("READ_ONLY_RESPONSE_INVALID") from error
    entries = _sequence(value)
    if not entries:
        raise HostedAcceptanceError("LIFECYCLE_DIAGNOSTICS_UNAVAILABLE")
    if len(entries) > _MAX_LOG_ENTRIES:
        raise HostedAcceptanceError("READ_ONLY_RESPONSE_INVALID")
    revisions: set[str] = set()
    timestamps: list[datetime] = []
    for item in entries:
        entry = _mapping(item)
        resource = _mapping(entry.get("resource"))
        labels = _mapping(resource.get("labels"))
        revision = labels.get("revision_name")
        if revision is not None:
            revisions.add(_text(revision))
        timestamps.append(_parse_timestamp(entry.get("timestamp")))
    canonical = json.dumps(
        value,
        allow_nan=False,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    return LifecycleDiagnostics(
        available=True,
        entry_count=len(entries),
        payload_sha256=hashlib.sha256(canonical).hexdigest(),
        revision_names=tuple(sorted(revisions)),
        first_timestamp=min(timestamps),
        last_timestamp=max(timestamps),
        observed_at=observed_at,
    )


class TerraformCanaryReprovisioner:
    """Replace only the isolated canary and prove a clean physical boundary."""

    def __init__(
        self,
        candidate: CandidateIdentity,
        *,
        binding: CanaryReprovisionBinding,
        release_id: str,
        release_reader: RecoveryReleaseRecordReader,
        command_runner: CommandRunner = _default_command_runner,
        environ: Mapping[str, str] | None = None,
        clock: Callable[[], datetime] = _utc_now,
    ) -> None:
        if type(candidate) is not CandidateIdentity:
            raise TypeError("canary reprovision requires an exact candidate")
        expected_release_id = f"p5-release-{candidate.source_revision[:24]}"
        if type(binding) is not CanaryReprovisionBinding:
            raise TypeError("canary reprovision requires an exact sealed binding")
        if release_id != expected_release_id:
            raise ValueError("canary reprovision release identity changed")
        if not callable(getattr(release_reader, "read", None)):
            raise TypeError("canary reprovision requires a release reader")
        if not callable(command_runner) or not callable(clock):
            raise TypeError("canary reprovision dependencies are invalid")
        self._candidate = candidate
        self._binding = binding
        self._release_id = release_id
        self._release_reader = release_reader
        self._runner = command_runner
        self._environment = _minimal_environment(
            os.environ if environ is None else environ
        )
        self._clock = clock

    @staticmethod
    def _command_output(
        result: object,
        *,
        maximum: int,
        failure: str,
    ) -> bytes:
        if (
            not isinstance(result, subprocess.CompletedProcess)
            or result.returncode != 0
            or type(result.stdout) is not bytes
            or type(result.stderr) is not bytes
            or len(result.stdout) > maximum
            or len(result.stderr) > _MAX_COMMAND_BYTES
        ):
            raise HostedAcceptanceError(failure)
        return result.stdout

    def _run(
        self,
        argv: tuple[str, ...],
        *,
        cwd: Path,
        environment: Mapping[str, str],
        timeout: int,
        maximum: int = _MAX_COMMAND_BYTES,
        failure: str = "CANARY_REPROVISION_COMMAND_FAILED",
    ) -> bytes:
        try:
            result = self._runner(argv, cwd, environment, timeout)
        except (OSError, subprocess.SubprocessError) as error:
            raise HostedAcceptanceError(failure) from error
        return self._command_output(result, maximum=maximum, failure=failure)

    def _sealed_paths(self) -> tuple[Path, Path, Path, Path, dict[str, object]]:
        root = _private_directory(Path(self._binding.state_root), writable=True)
        source = _private_directory(root / "source", writable=False)
        execution = _private_directory(root / "execution", writable=True)
        data = _private_directory(root / "terraform-data" / "runtime", writable=True)
        plans = _private_directory(root / "plans", writable=False)
        variables_path = plans / "runtime-create.tfvars.json"
        variables_payload = _read_owner_file(
            variables_path,
            maximum=1_048_576,
            exact_mode=0o400,
        )
        if (
            hashlib.sha256(variables_payload).hexdigest()
            != self._binding.runtime_variables_sha256
            or _runtime_source_sha256(source) != self._binding.runtime_source_sha256
        ):
            raise HostedAcceptanceError("CANARY_REPROVISION_BINDING_CHANGED")
        variables = _json_object(
            variables_payload,
            canonical=True,
            failure="CANARY_REPROVISION_INPUT_INVALID",
        )
        _expected_canary_revision(self._candidate, variables)
        cli_config = root / "terraform.rc"
        if _read_owner_file(
            cli_config,
            maximum=1,
            exact_mode=0o400,
        ):
            raise HostedAcceptanceError("CANARY_REPROVISION_BINDING_INVALID")
        _verify_runtime_backend(data)
        if _terraform_binary_sha256() != _TERRAFORM_SHA256:
            raise HostedAcceptanceError("CANARY_REPROVISION_TERRAFORM_INVALID")
        return source, execution, data, cli_config, variables

    def _terraform_environment(self, data: Path, cli_config: Path) -> dict[str, str]:
        environment = dict(self._environment)
        environment["TF_CLI_CONFIG_FILE"] = str(cli_config)
        environment["TF_DATA_DIR"] = str(data)
        return environment

    def _gcloud(self, source: Path, *arguments: str) -> bytes:
        return self._run(
            (
                _GCLOUD,
                *arguments,
                f"--project={self._candidate.project_id}",
                f"--region={self._candidate.region}",
                f"--impersonate-service-account={_APPLY_SERVICE_ACCOUNT}",
                "--format=json",
                "--quiet",
            ),
            cwd=source,
            environment=self._environment,
            timeout=30,
            failure="CANARY_REPROVISION_OBSERVATION_FAILED",
        )

    def _service_description(self, source: Path) -> bytes:
        return self._gcloud(
            source,
            "run",
            "services",
            "describe",
            _CANARY_SERVICE,
        )

    @staticmethod
    def _service_uid(payload: bytes) -> str:
        try:
            value = _decode_json_object(payload)
            metadata = _mapping(value.get("metadata"))
            if _text(metadata.get("name")) != _CANARY_SERVICE:
                raise HostedAcceptanceError("READ_ONLY_RESPONSE_INVALID")
            uid = _text(metadata.get("uid"))
            if (
                len(uid) > 128
                or re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:-]*", uid) is None
            ):
                raise HostedAcceptanceError("READ_ONLY_RESPONSE_INVALID")
            return uid
        except HostedAcceptanceError as error:
            raise HostedAcceptanceError(
                "CANARY_REPROVISION_OBSERVATION_FAILED"
            ) from error

    def _verify_clean_service(self, payload: bytes, baseline_revision: str) -> str:
        try:
            value = _decode_json_object(payload)
            metadata = _mapping(value.get("metadata"))
            status = _mapping(value.get("status"))
            if _text(metadata.get("name")) != _CANARY_SERVICE:
                raise HostedAcceptanceError("READ_ONLY_RESPONSE_INVALID")
            generation = _integer(metadata.get("generation"))
            if _integer(status.get("observedGeneration")) != generation:
                raise HostedAcceptanceError("DEPLOYMENT_NOT_READY")
            _require_ready_condition(status)
            if (
                _text(status.get("latestCreatedRevisionName")) != baseline_revision
                or _text(status.get("latestReadyRevisionName")) != baseline_revision
            ):
                raise HostedAcceptanceError("DEPLOYMENT_REVISION_MISMATCH")
            traffic = _sequence(status.get("traffic"))
            if len(traffic) != 1:
                raise HostedAcceptanceError("DEPLOYMENT_TRAFFIC_INVALID")
            target = _mapping(traffic[0])
            if (
                _text(target.get("revisionName")) != baseline_revision
                or _integer(target.get("percent")) != 100
            ):
                raise HostedAcceptanceError("DEPLOYMENT_TRAFFIC_INVALID")
            return self._service_uid(payload)
        except HostedAcceptanceError as error:
            raise HostedAcceptanceError("CANARY_REPROVISION_NOT_CLEAN") from error

    def _verify_clean_revisions(
        self,
        payload: bytes,
        baseline_revision: str,
    ) -> tuple[str, ...]:
        try:
            value = json.loads(payload, object_pairs_hook=_reject_duplicate_json_pairs)
            revisions = _sequence(value)
            if len(revisions) != 1:
                raise HostedAcceptanceError("READ_ONLY_RESPONSE_INVALID")
            revision = _mapping(revisions[0])
            metadata = _mapping(revision.get("metadata"))
            status = _mapping(revision.get("status"))
            spec = _mapping(revision.get("spec"))
            name = _text(metadata.get("name"))
            if (
                name != baseline_revision
                or metadata.get("deletionTimestamp") is not None
                or _integer(status.get("observedGeneration"))
                != _integer(metadata.get("generation"))
            ):
                raise HostedAcceptanceError("READ_ONLY_RESPONSE_INVALID")
            _require_ready_condition(status)
            labels = _mapping(metadata.get("labels"))
            annotations = _mapping(metadata.get("annotations"))
            containers = _sequence(spec.get("containers"))
            if len(containers) != 1:
                raise HostedAcceptanceError("READ_ONLY_RESPONSE_INVALID")
            container = _mapping(containers[0])
            expected_image = (
                f"{self._candidate.region}-docker.pkg.dev/"
                f"{self._candidate.project_id}/reconcile-p5/reconcile@"
                f"{self._candidate.image_digest}"
            )
            if (
                labels.get("reconcile-release") != "baseline"
                or annotations.get("reconcile.dev/configuration-sha256")
                != self._candidate.semantic_config_sha256
                or container.get("image") != expected_image
            ):
                raise HostedAcceptanceError("READ_ONLY_RESPONSE_INVALID")
            return (name,)
        except (TypeError, UnicodeError, ValueError, HostedAcceptanceError) as error:
            raise HostedAcceptanceError("CANARY_REPROVISION_NOT_CLEAN") from error

    @staticmethod
    def _seal_execution_plan(path: Path) -> str:
        try:
            descriptor = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
        except OSError as error:
            raise HostedAcceptanceError("CANARY_REPROVISION_PLAN_INVALID") from error
        digest = hashlib.sha256()
        try:
            metadata = os.fstat(descriptor)
            if (
                not stat.S_ISREG(metadata.st_mode)
                or metadata.st_uid != os.getuid()
                or metadata.st_nlink != 1
                or not 1 <= metadata.st_size <= _MAX_TERRAFORM_PLAN_BYTES
                or stat.S_IMODE(metadata.st_mode) & 0o022
            ):
                raise HostedAcceptanceError("CANARY_REPROVISION_PLAN_INVALID")
            os.fchmod(descriptor, 0o400)
            while True:
                chunk = os.read(descriptor, 1_048_576)
                if not chunk:
                    break
                digest.update(chunk)
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        return digest.hexdigest()

    def _execute(self) -> tuple[str, str, str, str, tuple[str, ...]]:
        source, execution, data, cli_config, variables = self._sealed_paths()
        environment = self._terraform_environment(data, cli_config)
        version = self._run(
            (_TERRAFORM, "version", "-json"),
            cwd=source,
            environment=environment,
            timeout=15,
            failure="CANARY_REPROVISION_TERRAFORM_INVALID",
        )
        if (
            _json_object(
                version,
                canonical=False,
                failure="CANARY_REPROVISION_TERRAFORM_INVALID",
            ).get("terraform_version")
            != "1.15.8"
        ):
            raise HostedAcceptanceError("CANARY_REPROVISION_TERRAFORM_INVALID")

        previous_uid = self._service_uid(self._service_description(source))
        baseline_revision = _expected_canary_revision(self._candidate, variables)
        root = Path(self._binding.state_root)
        variable_path = root / "plans" / "runtime-create.tfvars.json"
        plan_path = (
            execution / f"canary-reprovision-{self._candidate.candidate_sha256}.tfplan"
        )
        lock_path = execution / "canary-reprovision.lock"
        try:
            lock_descriptor = os.open(
                lock_path,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW,
                0o600,
            )
        except OSError as error:
            raise HostedAcceptanceError("CANARY_REPROVISION_BUSY") from error
        try:
            try:
                plan_path.lstat()
            except FileNotFoundError:
                pass
            except OSError as error:
                raise HostedAcceptanceError(
                    "CANARY_REPROVISION_PLAN_INVALID"
                ) from error
            else:
                raise HostedAcceptanceError("CANARY_REPROVISION_PLAN_INVALID")

            selector_arguments = tuple(
                argument
                for address in _CANARY_REPROVISION_ADDRESSES
                for argument in (f"-replace={address}", f"-target={address}")
            )
            self._run(
                (
                    _TERRAFORM,
                    "-chdir=infra/environments/dev/runtime",
                    "plan",
                    "-input=false",
                    "-lock=true",
                    "-lock-timeout=60s",
                    "-no-color",
                    f"-out={plan_path}",
                    f"-var-file={variable_path}",
                    *selector_arguments,
                ),
                cwd=source,
                environment=environment,
                timeout=1_800,
            )
            normalized = self._run(
                (
                    _TERRAFORM,
                    "-chdir=infra/environments/dev/runtime",
                    "show",
                    "-json",
                    str(plan_path),
                ),
                cwd=source,
                environment=environment,
                timeout=60,
                maximum=_MAX_TERRAFORM_PLAN_BYTES,
                failure="CANARY_REPROVISION_PLAN_INVALID",
            )
            _validate_canary_reprovision_plan(
                normalized,
                candidate=self._candidate,
                variables=variables,
            )
            plan_sha256 = self._seal_execution_plan(plan_path)
            if (
                hashlib.sha256(
                    _read_owner_file(
                        plan_path,
                        maximum=_MAX_TERRAFORM_PLAN_BYTES,
                        exact_mode=0o400,
                        failure="CANARY_REPROVISION_PLAN_INVALID",
                    )
                ).hexdigest()
                != plan_sha256
            ):
                raise HostedAcceptanceError("CANARY_REPROVISION_PLAN_CHANGED")
            self._run(
                (
                    _TERRAFORM,
                    "-chdir=infra/environments/dev/runtime",
                    "apply",
                    "-input=false",
                    "-no-color",
                    str(plan_path),
                ),
                cwd=source,
                environment=environment,
                timeout=1_800,
            )
            current_payload = self._service_description(source)
            current_uid = self._verify_clean_service(
                current_payload,
                baseline_revision,
            )
            revisions = self._verify_clean_revisions(
                self._gcloud(
                    source,
                    "run",
                    "revisions",
                    "list",
                    f"--service={_CANARY_SERVICE}",
                ),
                baseline_revision,
            )
            if current_uid == previous_uid:
                raise HostedAcceptanceError("CANARY_REPROVISION_UID_UNCHANGED")
            return (
                previous_uid,
                current_uid,
                plan_sha256,
                hashlib.sha256(normalized).hexdigest(),
                revisions,
            )
        finally:
            os.close(lock_descriptor)
            try:
                plan_path.unlink(missing_ok=True)
            finally:
                lock_path.unlink(missing_ok=True)

    async def reprovision(self) -> CanaryReprovisionObservation:
        """Apply one closed replacement plan and prove the resulting clean state."""

        operation = asyncio.create_task(asyncio.to_thread(self._execute))
        interrupted: asyncio.CancelledError | None = None
        while not operation.done():
            try:
                await asyncio.shield(operation)
            except asyncio.CancelledError as error:
                interrupted = error
        result = operation.result()
        if interrupted is not None:
            raise interrupted
        previous_uid, current_uid, plan_sha256, normalized_sha256, revisions = result
        try:
            release_record = await self._release_reader.read(self._release_id)
        except asyncio.CancelledError:
            raise
        except Exception as error:
            raise HostedAcceptanceError("CANARY_RELEASE_READ_FAILED") from error
        if release_record is not None:
            raise HostedAcceptanceError("CANARY_RELEASE_RECORD_PRESENT")
        try:
            observed_at = self._clock()
            if (
                not isinstance(observed_at, datetime)
                or observed_at.tzinfo is None
                or observed_at.utcoffset() is None
            ):
                raise ValueError
            return CanaryReprovisionObservation(
                previous_service_uid=previous_uid,
                service_uid=current_uid,
                baseline_revision=revisions[0],
                revision_names=revisions,
                release_id=self._release_id,
                changed_resource_addresses=_CANARY_REPROVISION_ADDRESSES,
                execution_plan_sha256=plan_sha256,
                normalized_plan_sha256=normalized_sha256,
                observed_at=observed_at,
            )
        except (TypeError, ValueError) as error:
            raise HostedAcceptanceError(
                "CANARY_REPROVISION_OBSERVATION_FAILED"
            ) from error


class CloudRunAcceptanceBackend:
    """Authenticated remote acceptance over the frozen public API only."""

    def __init__(
        self,
        candidate: CandidateIdentity,
        *,
        state_root: Path | None = None,
        runtime_source_sha256: str | None = None,
        runtime_variables_sha256: str | None = None,
        inspector: GcloudReadOnlyInspector | None = None,
        identity_supplier: GcloudIdentityTokenSupplier | None = None,
        credentials_factory: Callable[[], object] | None = None,
        command_runner: CommandRunner = _default_command_runner,
        environ: Mapping[str, str] | None = None,
    ) -> None:
        self._candidate = candidate
        recovery_values = (
            state_root,
            runtime_source_sha256,
            runtime_variables_sha256,
        )
        if any(value is not None for value in recovery_values) and not all(
            value is not None for value in recovery_values
        ):
            raise ValueError("hosted recovery binding is incomplete")
        self._recovery_binding = (
            None
            if state_root is None
            else CanaryReprovisionBinding(
                state_root=str(state_root),
                runtime_source_sha256=runtime_source_sha256,
                runtime_variables_sha256=runtime_variables_sha256,
            )
        )
        source = os.environ if environ is None else environ
        self._inspector = inspector
        self._identity_supplier = identity_supplier or GcloudIdentityTokenSupplier(
            source
        )
        self._command_runner = command_runner
        self._environment = _minimal_environment(source)
        self._bound_pythonpath = source.get("PYTHONPATH")
        self._api_uri: str | None = None
        self._credentials_factory = credentials_factory
        self._operator_credentials_value: object | None = None
        self._recovery_settings: ReleaseChainSettings | None = None
        self._recovery_invoked_at: datetime | None = None
        self._recovery_definition_created_at_text: str | None = None
        self._recovery_baseline_revision: str | None = None
        self._release_target_value: GoogleFirestoreReleaseTarget | None = None
        self._provider_ledger_value: FirestoreHostedProviderLedger | None = None
        self._reprovisioner_value: TerraformCanaryReprovisioner | None = None

    async def deployments(
        self,
        candidate: CandidateIdentity,
    ) -> tuple[ServiceDeploymentObservation, ...]:
        if candidate != self._candidate:
            raise HostedAcceptanceError("CANDIDATE_IDENTITY_CHANGED")
        inspector = self._inspector
        if inspector is None:
            self._load_recovery_configuration()
            inspector = GcloudReadOnlyInspector(
                command_runner=self._command_runner,
                environ=self._environment,
                canary_baseline_revision=self._recovery_baseline_revision,
                recovery_definition_created_at=(
                    self._recovery_definition_created_at_text
                ),
            )
            self._inspector = inspector
        deployments = await asyncio.to_thread(
            inspector.inspect_deployments,
            candidate,
        )
        self._api_uri = next(
            item.uri for item in deployments if item.component is ServiceComponent.API
        )
        return deployments

    def _client(self) -> OperatorApiClient:
        if self._api_uri is None:
            raise HostedAcceptanceError("DEPLOYMENT_NOT_INSPECTED")
        return OperatorApiClient(
            self._api_uri,
            identity_token_supplier=self._identity_supplier,
            identity_audience=_API_AUDIENCE,
        )

    async def scenario(
        self,
        request: ScenarioLaunchRequest,
        *,
        purpose: str,
    ) -> ScenarioAcceptanceObservation:
        async with self._client() as client:
            launched = await client.launch(request)
            if not launched.created:
                raise HostedAcceptanceError("ACCEPTANCE_LAUNCH_REPLAYED")
            investigation_id = launched.snapshot.investigation_id
            events = tuple(
                [
                    event
                    async for event in client.events(
                        investigation_id,
                        after=0,
                    )
                ]
            )
            current = await client.get_snapshot(investigation_id)
            status = await client.get_operational_status(investigation_id)
            replay = await client.launch(request)
        if replay.created or replay.snapshot != current:
            raise HostedAcceptanceError("EXACT_REPLAY_CHANGED")
        return ScenarioAcceptanceObservation(
            purpose=purpose,
            request=request,
            launch_created=launched.created,
            snapshot=current,
            events=events,
            operational_status=status,
            replay_created=False,
            replay_snapshot_sha256=_model_hash(replay.snapshot),
            snapshot_sha256=_model_hash(current),
            events_sha256=_models_hash(events),
            operational_status_sha256=_model_hash(status),
        )

    def _operator_credentials(self) -> object:
        existing = self._operator_credentials_value
        if existing is not None:
            return existing
        try:
            if self._credentials_factory is not None:
                credentials = self._credentials_factory()
            else:
                source, _project = google_auth_default(
                    scopes=("https://www.googleapis.com/auth/cloud-platform",)
                )
                credentials = impersonated_credentials.Credentials(
                    source_credentials=source,
                    target_principal=_APPLY_SERVICE_ACCOUNT,
                    target_scopes=("https://www.googleapis.com/auth/cloud-platform",),
                    lifetime=3_600,
                )
        except Exception as error:
            raise HostedAcceptanceError("OPERATOR_CREDENTIALS_UNAVAILABLE") from error
        self._operator_credentials_value = credentials
        return credentials

    def _load_recovery_configuration(
        self,
    ) -> tuple[ReleaseChainSettings, datetime]:
        settings = self._recovery_settings
        invoked_at = self._recovery_invoked_at
        if settings is not None and invoked_at is not None:
            return settings, invoked_at
        binding = self._recovery_binding
        if binding is None:
            raise HostedAcceptanceError("RECOVERY_ACCEPTANCE_BINDING_MISSING")
        root = _private_directory(Path(binding.state_root), writable=True)
        source = _private_directory(root / "source", writable=False)
        plans = _private_directory(root / "plans", writable=False)
        variables_payload = _read_owner_file(
            plans / "runtime-create.tfvars.json",
            maximum=1_048_576,
            exact_mode=0o400,
        )
        if (
            _runtime_source_sha256(source) != binding.runtime_source_sha256
            or hashlib.sha256(variables_payload).hexdigest()
            != binding.runtime_variables_sha256
        ):
            raise HostedAcceptanceError("RECOVERY_ACCEPTANCE_BINDING_CHANGED")
        variables = _json_object(
            variables_payload,
            canonical=True,
            failure="RECOVERY_ACCEPTANCE_INPUT_INVALID",
        )
        baseline_revision = _expected_canary_revision(self._candidate, variables)
        try:
            raw_invoked_at = variables["recovery_definition_created_at"]
        except KeyError as error:
            raise HostedAcceptanceError("RECOVERY_ACCEPTANCE_INPUT_INVALID") from error
        invoked_at = _parse_timestamp(raw_invoked_at)
        settings = _candidate_release_settings(self._candidate)
        self._recovery_settings = settings
        self._recovery_invoked_at = invoked_at
        self._recovery_definition_created_at_text = str(raw_invoked_at)
        self._recovery_baseline_revision = baseline_revision
        return settings, invoked_at

    def _firestore_client(self, database: str):
        return firestore_v1.AsyncClient(
            project=self._candidate.project_id,
            database=database,
            credentials=self._operator_credentials(),
        )

    def _release_target(self) -> GoogleFirestoreReleaseTarget:
        if self._release_target_value is None:
            self._release_target_value = GoogleFirestoreReleaseTarget(
                project_id=self._candidate.project_id,
                database_id=FIRESTORE_RELEASE_DATABASE,
                client_factory=lambda: self._firestore_client(
                    FIRESTORE_RELEASE_DATABASE
                ),
            )
        return self._release_target_value

    def _provider_ledger_boundary(self) -> FirestoreHostedProviderLedger:
        if self._provider_ledger_value is None:
            store = GoogleFirestoreCasStore(
                project_id=self._candidate.project_id,
                database_id=FIRESTORE_RUNTIME_DATABASE,
                client_factory=lambda: self._firestore_client(
                    FIRESTORE_RUNTIME_DATABASE
                ),
            )
            self._provider_ledger_value = FirestoreHostedProviderLedger(store)
        return self._provider_ledger_value

    def _reprovisioner(self) -> TerraformCanaryReprovisioner:
        if self._reprovisioner_value is not None:
            return self._reprovisioner_value
        settings, _invoked_at = self._load_recovery_configuration()
        binding = self._recovery_binding
        if binding is None:  # pragma: no cover - configuration loader guards this
            raise HostedAcceptanceError("RECOVERY_ACCEPTANCE_BINDING_MISSING")
        self._reprovisioner_value = TerraformCanaryReprovisioner(
            self._candidate,
            binding=binding,
            release_id=settings.release_id,
            release_reader=self._release_target(),
            command_runner=self._command_runner,
            environ=self._environment,
        )
        return self._reprovisioner_value

    def _canary_boundaries(
        self,
        baseline_revision: str,
    ) -> tuple[
        CloudRunCanaryActionAdapter,
        CloudRunCanaryFaultProxy,
        CloudRunCanaryReader,
    ]:
        target = CloudRunCanaryTarget(
            project=self._candidate.project_id,
            location=self._candidate.region,
            service=_CANARY_SERVICE,
            image_repository=(
                f"{self._candidate.region}-docker.pkg.dev/"
                f"{self._candidate.project_id}/reconcile-p5/reconcile"
            ),
            baseline_revision=baseline_revision,
            health_audience=_CANARY_AUDIENCE,
            timeout_seconds=5.0,
        )

        def services_factory():
            return run_v2.ServicesClient(credentials=self._operator_credentials())

        def revisions_factory():
            return run_v2.RevisionsClient(credentials=self._operator_credentials())

        action = CloudRunCanaryActionAdapter(
            target=target,
            services_factory=services_factory,
            revisions_factory=revisions_factory,
        )
        reader = CloudRunCanaryReader(
            target=target,
            services_factory=services_factory,
            revisions_factory=revisions_factory,
        )
        return action, CloudRunCanaryFaultProxy(action), reader

    async def provider_ledger_absent(self) -> bool:
        try:
            return await self._provider_ledger_boundary().is_absent(
                _hosted_candidate_identity(self._candidate)
            )
        except asyncio.CancelledError:
            raise
        except Exception as error:
            raise HostedAcceptanceError("PROVIDER_LEDGER_READ_FAILED") from error

    async def provider_ledger(self) -> HostedProviderLedgerObservation:
        try:
            return await self._provider_ledger_boundary().observe_finalized(
                _hosted_candidate_identity(self._candidate)
            )
        except asyncio.CancelledError:
            raise
        except Exception as error:
            raise HostedAcceptanceError("PROVIDER_LEDGER_READ_FAILED") from error

    async def recovery_lane(
        self,
        *,
        policy: RecoveryRunPolicy,
        fault: RecoveryRunFault,
        purpose: str,
    ) -> RecoveryLaneAcceptanceObservation:
        if type(policy) is not RecoveryRunPolicy or type(fault) is not RecoveryRunFault:
            raise TypeError("recovery acceptance policy and fault must be exact")
        if type(purpose) is not str or not purpose:
            raise ValueError("recovery acceptance purpose is invalid")
        settings, invoked_at = self._load_recovery_configuration()
        reprovision = await self._reprovisioner().reprovision()
        _action, fault_proxy, reader = self._canary_boundaries(
            reprovision.baseline_revision
        )
        firestore = self._release_target()
        recorder = RecoveryPolicyResultRecorder(
            settings=settings,
            baseline_revision=reprovision.baseline_revision,
            cloud_reader=reader,
            firestore=firestore,
        )
        baseline = await recorder.capture_baseline()
        binding = recovery_experiment_binding(settings, fault)
        run_id = _recovery_run_id(
            policy=policy,
            fault=fault,
            purpose=purpose,
            service_uid=reprovision.service_uid,
            candidate_sha256=self._candidate.candidate_sha256,
        )
        resetter = ReleaseChainResetter(
            settings=settings,
            cloud_action=fault_proxy,
            cloud_reader=reader,
            firestore=firestore,
            baseline_revision=reprovision.baseline_revision,
            max_observations=120,
            poll_interval_seconds=1,
        )
        result: RecoveryPolicyResult
        acknowledgement_lost = False
        launch_outcome: RecoveryDispatchOutcome | None = None
        launched_created: bool | None = None
        replay_created: bool | None = None
        request_sha256: str | None = None
        snapshot_sha256: str | None = None
        replay_snapshot_sha256: str | None = None
        events_sha256: str | None = None
        event_count = 0
        replay_provider_contact_delta: int | None = None
        live_authority_replay_denial_count = 0
        provider_hypothesis_count = 0
        hypothesis_id: str | None = None
        hypothesis_chain_sha256: str | None = None
        hypothesis_node_sha256: str | None = None
        hypothesis_input_sha256: str | None = None
        hypothesis_output_sha256: str | None = None
        terminal_owned = policy in {
            RecoveryRunPolicy.BLIND_RETRY,
            RecoveryRunPolicy.BLIND_ABORT,
        }
        try:
            if policy in {
                RecoveryRunPolicy.BLIND_RETRY,
                RecoveryRunPolicy.BLIND_ABORT,
            }:
                mutator = ReleaseChainBlindMutator(
                    settings=settings,
                    cloud_action=fault_proxy,
                    cloud_reader=reader,
                    firestore=firestore,
                    invoked_at=invoked_at,
                    max_settle_observations=240,
                    settle_poll_interval_seconds=1,
                )
                executor = BlindPolicyExecutor(mutator)
                if policy is RecoveryRunPolicy.BLIND_RETRY:
                    outcome = await executor.blind_retry(
                        operation_id=settings.stage_operation_id,
                        fault=fault,
                    )
                else:
                    outcome = await executor.blind_abort(
                        operation_id=settings.stage_operation_id,
                        fault=fault,
                    )
                result = await recorder.record_blind(
                    run_id=run_id,
                    policy=policy,
                    fault=fault,
                    binding=binding,
                    baseline=baseline,
                    outcome=outcome,
                )
                acknowledgement_lost = fault is RecoveryRunFault.DROP_AFTER_ACCEPT
            else:
                request = RecoveryRunRequest(
                    schema_version=RECOVERY_RUN_REQUEST_VERSION,
                    run_id=run_id,
                    scenario="cloud-run-rollout",
                    policy=policy,
                    fault=fault,
                )
                async with self._client() as client:
                    current = await self._launch_recovery_terminal(client, request)
                    terminal_owned = True
                    events = tuple(
                        [
                            event
                            async for event in client.recovery_events(
                                request.run_id,
                                after=0,
                            )
                        ]
                    )
                    reread = await client.get_recovery_snapshot(request.run_id)
                    contacts_before_replay = sum(
                        item.provider_contact for item in reread.dispatch_receipts
                    )
                    replay = await client.launch_recovery(request)
                    contacts_after_replay = sum(
                        item.provider_contact
                        for item in replay.snapshot.dispatch_receipts
                    )
                if (
                    reread != current
                    or replay.created
                    or replay.snapshot != current
                    or not events
                    or current.lifecycle
                    not in {
                        RecoveryRunLifecycle.COMPLETED,
                        RecoveryRunLifecycle.ESCALATED,
                    }
                ):
                    raise HostedAcceptanceError("RECOVERY_API_EVIDENCE_CHANGED")
                event_snapshot = RecoveryRunEventSnapshot(
                    schema_version=RECOVERY_RUN_EVENT_SNAPSHOT_VERSION,
                    run_id=request.run_id,
                    cursor=current.event_cursor,
                    terminal=True,
                    events=events,
                )
                RecoveryRunAggregate(
                    schema_version=RECOVERY_RUN_AGGREGATE_VERSION,
                    snapshot=current,
                    events=events,
                )
                if (
                    current.launch_permit is None
                    or current.launch_permit.outcome is None
                ):
                    raise HostedAcceptanceError("RECOVERY_LAUNCH_AUTHORITY_CHANGED")
                launch_outcome = current.launch_permit.outcome
                acknowledgement_lost = (
                    launch_outcome is RecoveryDispatchOutcome.OUTCOME_UNKNOWN
                )
                if policy is RecoveryRunPolicy.FIXED and current.hypotheses:
                    raise HostedAcceptanceError("FIXED_RECOVERY_USED_PROVIDER")
                result = await recorder.record_proof(
                    snapshot=current,
                    events=event_snapshot,
                    binding=binding,
                    baseline=baseline,
                )
                live_authority_replay_denial_count = sum(
                    receipt.outcome
                    is RecoveryReceiptOutcome.REJECTED_BEFORE_PROVIDER_CONTACT
                    for receipt in result.dispatch_receipts
                )
                launched_created = True
                replay_created = False
                request_sha256 = _model_hash(request)
                snapshot_sha256 = _model_hash(current)
                replay_snapshot_sha256 = _model_hash(replay.snapshot)
                events_sha256 = _models_hash(events)
                event_count = len(events)
                replay_provider_contact_delta = (
                    contacts_after_replay - contacts_before_replay
                )
                if replay_provider_contact_delta != 0:
                    raise HostedAcceptanceError("RECOVERY_REPLAY_CONTACTED_PROVIDER")
                if policy is RecoveryRunPolicy.ADAPTIVE:
                    ledger = await self.provider_ledger()
                    if len(current.hypotheses) != 1:
                        raise HostedAcceptanceError(
                            "RECOVERY_PROVIDER_HYPOTHESIS_CHANGED"
                        )
                    hypothesis = current.hypotheses[0]
                    node = next(
                        (
                            item
                            for item in current.chain.nodes
                            if item.node_id == hypothesis.node_id
                        ),
                        None,
                    )
                    if node is None:
                        raise HostedAcceptanceError(
                            "RECOVERY_PROVIDER_HYPOTHESIS_CHANGED"
                        )
                    expected_hypothesis_id = recovery_hypothesis_id(
                        chain=current.chain,
                        node=node,
                        input_sha256=ledger.dispatch.input_sha256,
                        output_sha256=ledger.output_sha256,
                    )
                    if hypothesis.hypothesis_id != expected_hypothesis_id:
                        raise HostedAcceptanceError(
                            "RECOVERY_PROVIDER_HYPOTHESIS_CHANGED"
                        )
                    provider_hypothesis_count = 1
                    hypothesis_id = hypothesis.hypothesis_id
                    hypothesis_chain_sha256 = _model_hash(current.chain)
                    hypothesis_node_sha256 = _model_hash(node)
                    hypothesis_input_sha256 = ledger.dispatch.input_sha256
                    hypothesis_output_sha256 = ledger.output_sha256
        finally:
            if terminal_owned:
                reset = await resetter.reset()
        return RecoveryLaneAcceptanceObservation(
            purpose=purpose,
            reprovision=reprovision,
            result=result,
            reset=reset,
            acknowledgement_lost=acknowledgement_lost,
            launch_outcome=launch_outcome,
            launch_created=launched_created,
            replay_created=replay_created,
            request_sha256=request_sha256,
            snapshot_sha256=snapshot_sha256,
            replay_snapshot_sha256=replay_snapshot_sha256,
            events_sha256=events_sha256,
            event_count=event_count,
            replay_provider_contact_delta=replay_provider_contact_delta,
            live_authority_replay_denial_count=(live_authority_replay_denial_count),
            provider_hypothesis_count=provider_hypothesis_count,
            hypothesis_id=hypothesis_id,
            hypothesis_chain_sha256=hypothesis_chain_sha256,
            hypothesis_node_sha256=hypothesis_node_sha256,
            hypothesis_input_sha256=hypothesis_input_sha256,
            hypothesis_output_sha256=hypothesis_output_sha256,
        )

    @staticmethod
    async def _launch_recovery_terminal(
        client: OperatorApiClient,
        request: RecoveryRunRequest,
    ) -> RecoveryRunSnapshot:
        snapshot: RecoveryRunSnapshot | None = None
        outcome_was_unknown = False
        for _attempt in range(3):
            try:
                launched = await client.launch_recovery(request)
            except LaunchOutcomeUnknownError:
                outcome_was_unknown = True
                try:
                    snapshot = await client.get_recovery_snapshot(request.run_id)
                except InvestigationNotFoundError:
                    continue
                break
            if not launched.created and not outcome_was_unknown:
                raise HostedAcceptanceError("RECOVERY_LAUNCH_REPLAYED")
            snapshot = launched.snapshot
            break
        if snapshot is None:
            raise HostedAcceptanceError("RECOVERY_LAUNCH_UNRESOLVED")
        if snapshot.lifecycle not in {
            RecoveryRunLifecycle.COMPLETED,
            RecoveryRunLifecycle.ESCALATED,
        }:
            async for _event in client.recovery_events(
                request.run_id,
                after=snapshot.event_cursor,
            ):
                pass
            snapshot = await client.get_recovery_snapshot(request.run_id)
        if snapshot.lifecycle not in {
            RecoveryRunLifecycle.COMPLETED,
            RecoveryRunLifecycle.ESCALATED,
        }:
            raise HostedAcceptanceError("RECOVERY_LAUNCH_UNRESOLVED")
        return snapshot

    async def concurrent_replay(
        self,
        scenario: ScenarioAcceptanceObservation,
    ) -> DuplicateRequestObservation:
        async def replay_once() -> ScenarioRunSnapshot:
            async with self._client() as client:
                result = await client.launch(scenario.request)
                if result.created:
                    raise HostedAcceptanceError("CONCURRENT_REPLAY_CREATED")
                return result.snapshot

        snapshots = await asyncio.gather(replay_once(), replay_once())
        if any(item != scenario.snapshot for item in snapshots):
            raise HostedAcceptanceError("CONCURRENT_REPLAY_CHANGED")
        conflicting_mode = (
            ScenarioRunMode.FIXED
            if scenario.request.mode is not ScenarioRunMode.FIXED
            else ScenarioRunMode.ADAPTIVE
        )
        conflict = scenario.request.model_copy(update={"mode": conflicting_mode})
        try:
            async with self._client() as client:
                await client.launch(conflict)
        except InvestigationConflictError:
            pass
        else:
            raise HostedAcceptanceError("DUPLICATE_CONFLICT_NOT_REJECTED")
        return DuplicateRequestObservation(
            launch_id=scenario.request.launch_id,
            concurrent_replay_count=2,
            snapshot_sha256=scenario.snapshot_sha256,
            conflict_observed=True,
        )

    async def cursor_resume(
        self,
        scenario: ScenarioAcceptanceObservation,
    ) -> CursorResumeObservation:
        cut = scenario.events[0].cursor
        async with self._client() as client:
            resumed = tuple(
                [
                    event
                    async for event in client.events(
                        scenario.snapshot.investigation_id,
                        after=cut,
                    )
                ]
            )
        expected = scenario.events[1:]
        if not resumed or resumed != expected:
            raise HostedAcceptanceError("CURSOR_RESUME_CHANGED")
        return CursorResumeObservation(
            investigation_id=scenario.snapshot.investigation_id,
            disconnected_after_cursor=cut,
            resumed_first_cursor=resumed[0].cursor,
            final_cursor=resumed[-1].cursor,
            resumed_events_sha256=_models_hash(resumed),
        )

    async def interface_parity(
        self,
        scenario: ScenarioAcceptanceObservation,
    ) -> InterfaceParityObservation:
        cli_snapshot = await asyncio.to_thread(
            self._cli_snapshot,
            scenario.snapshot.investigation_id,
        )
        tui_snapshot = await self._tui_snapshot(scenario.snapshot.investigation_id)
        if cli_snapshot != scenario.snapshot or tui_snapshot != scenario.snapshot:
            raise HostedAcceptanceError("REMOTE_INTERFACE_PARITY_CHANGED")
        digest = scenario.snapshot_sha256
        return InterfaceParityObservation(
            investigation_id=scenario.snapshot.investigation_id,
            api_snapshot_sha256=digest,
            cli_snapshot_sha256=_model_hash(cli_snapshot),
            tui_snapshot_sha256=_model_hash(tui_snapshot),
            all_equal=True,
        )

    def _cli_snapshot(self, investigation_id: str) -> ScenarioRunSnapshot:
        if self._api_uri is None:
            raise HostedAcceptanceError("DEPLOYMENT_NOT_INSPECTED")
        pythonpath = self._bound_pythonpath
        if not isinstance(pythonpath, str) or pythonpath.count(":") != 1:
            raise HostedAcceptanceError("CLI_IMPORT_PATH_INVALID")
        source_value, dependency_value = pythonpath.split(":", 1)
        try:
            source_root = Path(source_value).resolve(strict=True)
            dependency_root = Path(dependency_value).resolve(strict=True)
        except OSError as error:
            raise HostedAcceptanceError("CLI_IMPORT_PATH_INVALID") from error
        if (
            source_root != _REPO_ROOT.resolve(strict=True)
            or not dependency_root.is_dir()
            or dependency_root.is_symlink()
            or any(":" in value for value in (source_value, dependency_value))
        ):
            raise HostedAcceptanceError("CLI_IMPORT_PATH_INVALID")
        environment = dict(self._environment)
        environment["RECONCILE_API_AUDIENCE"] = _API_AUDIENCE
        environment["PYTHONDONTWRITEBYTECODE"] = "1"
        environment["PYTHONNOUSERSITE"] = "1"
        environment["PYTHONPATH"] = pythonpath
        argv = (
            sys.executable,
            "-P",
            "-S",
            "-m",
            "reconcile",
            "scenario",
            "watch",
            investigation_id,
            "--output",
            "json",
            "--after",
            "0",
            "--api-url",
            self._api_uri,
        )
        try:
            result = self._command_runner(argv, source_root, environment, 120)
        except (OSError, subprocess.SubprocessError) as error:
            raise HostedAcceptanceError("CLI_PARITY_FAILED") from error
        payload = _checked_command_bytes(result)
        if payload.endswith(b"\n"):
            payload = payload[:-1]
        try:
            snapshot = decode_contract(payload, ScenarioRunSnapshot)
        except (TypeError, ValueError) as error:
            raise HostedAcceptanceError("CLI_PARITY_FAILED") from error
        if canonical_json_bytes(snapshot) != payload:
            raise HostedAcceptanceError("CLI_PARITY_FAILED")
        return snapshot

    async def _tui_snapshot(self, investigation_id: str) -> ScenarioRunSnapshot:
        from textual.widgets import Input

        from reconcile.interfaces.tui import ReconcileApp

        app = ReconcileApp(client=self._client())
        async with app.run_test(size=(120, 40)) as pilot:
            app.query_one("#investigation-id", Input).value = investigation_id
            await pilot.click("#attach-button")
            await app.workers.wait_for_complete()
            await pilot.pause()
            snapshot = app.operator_view_state.snapshot
        if snapshot is None:
            raise HostedAcceptanceError("TUI_PARITY_FAILED")
        return snapshot

    async def denials(self) -> tuple[DenialObservation, DenialObservation]:
        if self._api_uri is None:
            raise HostedAcceptanceError("DEPLOYMENT_NOT_INSPECTED")
        path = "/api/v1/scenario-runs/phase5-denial-probe"
        async with httpx.AsyncClient(
            base_url=self._api_uri,
            trust_env=False,
            follow_redirects=False,
            timeout=10,
        ) as client:
            (
                platform_status,
                platform_body,
                platform_content_type,
            ) = await _bounded_denial_request(
                client,
                path,
            )
            api_token, wrong_token = await asyncio.gather(
                asyncio.to_thread(self._identity_supplier, _API_AUDIENCE),
                asyncio.to_thread(self._identity_supplier, _CONTROLLER_AUDIENCE),
            )
            (
                application_status,
                application_body,
                application_content_type,
            ) = await _bounded_denial_request(
                client,
                path,
                headers={
                    "Authorization": f"Bearer {wrong_token}",
                    "X-Serverless-Authorization": f"Bearer {api_token}",
                },
            )
        if (
            platform_status not in {401, 403}
            or _is_json_media_type(platform_content_type)
            or platform_body == b'{"code":"unauthorized"}'
        ):
            raise HostedAcceptanceError("PLATFORM_DENIAL_CHANGED")
        if (
            application_status != 401
            or not _is_json_media_type(application_content_type)
            or application_body != b'{"code":"unauthorized"}'
        ):
            raise HostedAcceptanceError("APPLICATION_DENIAL_CHANGED")
        return (
            DenialObservation(
                layer=DenialLayer.PLATFORM,
                status_code=platform_status,
                response_sha256=hashlib.sha256(platform_body).hexdigest(),
                response_kind="platform-non-json",
            ),
            DenialObservation(
                layer=DenialLayer.APPLICATION,
                status_code=application_status,
                response_sha256=hashlib.sha256(application_body).hexdigest(),
                response_kind="application-canonical-json",
                canonical_code="unauthorized",
            ),
        )

    async def diagnostics(self) -> LifecycleDiagnostics:
        inspector = self._inspector
        if inspector is None:
            raise HostedAcceptanceError("DEPLOYMENT_NOT_INSPECTED")
        return await asyncio.to_thread(inspector.lifecycle_diagnostics)


async def _bounded_denial_request(
    client: httpx.AsyncClient,
    path: str,
    *,
    headers: Mapping[str, str] | None = None,
) -> tuple[int, bytes, str]:
    body = bytearray()
    async with client.stream("GET", path, headers=headers) as response:
        content_type = response.headers.get("content-type", "")
        if len(content_type) > 256:
            raise HostedAcceptanceError("DENIAL_RESPONSE_INVALID")
        async for chunk in response.aiter_bytes():
            if len(body) + len(chunk) > _MAX_COMMAND_BYTES:
                raise HostedAcceptanceError("DENIAL_RESPONSE_TOO_LARGE")
            body.extend(chunk)
        return response.status_code, bytes(body), content_type


def _is_json_media_type(value: str) -> bool:
    media_type = value.partition(";")[0].strip().lower()
    return media_type == "application/json" or media_type.endswith("+json")


def load_artifact_binding(payload: bytes) -> AcceptanceArtifactBinding:
    try:
        binding = decode_contract(payload, AcceptanceArtifactBinding)
    except (TypeError, ValueError) as error:
        raise HostedAcceptanceError("ARTIFACT_BINDING_INVALID") from error
    if canonical_json_bytes(binding) != payload:
        raise HostedAcceptanceError("ARTIFACT_BINDING_INVALID")
    return binding


__all__ = [
    "PHASE5_ACCEPTANCE_ARTIFACT_VERSION",
    "PHASE5_HOSTED_ACCEPTANCE_VERSION",
    "AcceptanceArtifactBinding",
    "AcceptanceLimitation",
    "AcceptanceMode",
    "CanaryReprovisionBackend",
    "CanaryReprovisionBinding",
    "CanaryReprovisionObservation",
    "CandidateIdentity",
    "CloudRunAcceptanceBackend",
    "CursorResumeObservation",
    "DenialLayer",
    "DenialObservation",
    "DuplicateRequestObservation",
    "ExactMainTestSubstitution",
    "GcloudReadOnlyInspector",
    "HostedAcceptanceBackend",
    "HostedAcceptanceError",
    "HostedAcceptanceRecord",
    "InterfaceParityObservation",
    "LifecycleDiagnostics",
    "ProviderAcceptanceRecord",
    "RecoveryLaneAcceptanceObservation",
    "RecoveryReleaseRecordReader",
    "ScenarioAcceptanceObservation",
    "ServiceComponent",
    "ServiceDeploymentObservation",
    "TerraformCanaryReprovisioner",
    "build_candidate_identity",
    "load_artifact_binding",
    "read_acceptance_record",
    "read_provider_record",
    "run_hosted_acceptance",
    "run_provider_acceptance",
]
