"""Concrete Cloud Run-to-Firestore Proof-to-Permit release scenario.

This module owns the declared three-node chain, late request preparation, durable
dispatch receipts, deliberately unsafe baseline executors, deterministic reset
reporting, and canonical comparison export. Qualification sampling remains in the
separate qualification package.
"""

from __future__ import annotations

import asyncio
import hashlib
import inspect
import os
import secrets
import tempfile
import time
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Protocol

from reconcile.adapters.cloud_run import (
    CLOUD_RUN_HEALTH_CAPABILITY,
    CLOUD_RUN_OPERATION_CAPABILITY,
    CLOUD_RUN_REVISION_CAPABILITY,
    CLOUD_RUN_SERVICE_CAPABILITY,
    CloudRunProbeBinding,
    build_cloud_run_capability,
    build_cloud_run_capability_registration,
    build_cloud_run_rule_registration,
    build_cloud_run_target,
)
from reconcile.adapters.firestore_release import (
    DISPATCH_RECEIPT_CAPABILITY,
    FIRESTORE_RELEASE_CAPABILITY,
    FirestoreReleaseProbeBinding,
    build_firestore_release_capability,
    build_firestore_release_capability_registration,
    build_firestore_release_rule_registration,
    build_firestore_release_target,
)
from reconcile.contracts import (
    EXECUTION_ENVELOPE_VERSION,
    EXPECTED_EFFECT_VERSION,
    PROBE_REQUEST_VERSION,
    RECOVERY_CHAIN_VERSION,
    RECOVERY_DISPATCH_RECEIPT_VERSION,
    RECOVERY_POLICY_COMPARISON_VERSION,
    RECOVERY_POLICY_RESULT_VERSION,
    RECOVERY_PREPARED_ACTION_VERSION,
    RECOVERY_RESET_RESULT_VERSION,
    RECOVERY_RUN_REQUEST_VERSION,
    ActionPermit,
    ActionPermitState,
    AmbiguityKind,
    AmbiguousExecution,
    CapabilityRef,
    EnvelopeContext,
    EvidenceBudget,
    ExecutionEnvelope,
    ExecutionEnvelopeReference,
    ExpectedEffect,
    FreshnessPolicy,
    OriginalInvocation,
    PermitAction,
    PermitCompletionOutcome,
    PolicyReferences,
    ProbeRequest,
    RecoveryActionNode,
    RecoveryActionScope,
    RecoveryAuthorityKind,
    RecoveryChain,
    RecoveryCloudRunObservation,
    RecoveryDispatchOutcome,
    RecoveryFirestoreObservation,
    RecoveryLaunchPermitState,
    RecoveryMutationCounters,
    RecoveryPolicyComparison,
    RecoveryPolicyResult,
    RecoveryPreparedAction,
    RecoveryReceiptOutcome,
    RecoveryResetResult,
    RecoveryRunEvent,
    RecoveryRunEventPayload,
    RecoveryRunEventType,
    RecoveryRunFault,
    RecoveryRunLifecycle,
    RecoveryRunPolicy,
    RecoveryRunRequest,
    RecoveryRunSnapshot,
    RecoveryTimelineEntry,
    SemanticActionIdentity,
    VerifiedCertificate,
    canonical_sha256,
    semantic_action_sha256,
)
from reconcile.contracts import (
    RecoveryDispatchReceipt as DurableDispatchReceipt,
)
from reconcile.contracts.base import (
    canonical_json_value_bytes,
    reject_sensitive_keys,
    reject_sensitive_values,
)
from reconcile.controller import CapabilityRegistry, ControllerClock, ProbeController
from reconcile.controller.permits import PermitAuthority
from reconcile.evidence import EvidenceEngine, ProbeRun, TargetRuleRegistry
from reconcile.evidence.recovery_rules import (
    CREATE_FIRESTORE_RELEASE_RECORD_PROFILE_VERSION,
    FIRESTORE_RECORD_EFFECT_SCOPE,
    PROMOTE_CLOUD_RUN_TRAFFIC_PROFILE_VERSION,
    PROMOTION_TRAFFIC_EFFECT_SCOPE,
    RECOVERY_TOOL_VERSION,
    STAGE_CLOUD_RUN_REVISION_PROFILE_VERSION,
    STAGE_READINESS_EFFECT_SCOPE,
    STAGE_REVISION_EFFECT_SCOPE,
    STAGE_TRAFFIC_EFFECT_SCOPE,
    deterministic_stage_revision,
)
from reconcile.evidence.recovery_verification import RECOVERY_CHAIN_PROFILE_VERSION
from reconcile.hosted.cloud_run_canary import (
    CloudRunAcceptanceAmbiguity,
    CloudRunCanaryActionAdapter,
    CloudRunCanaryError,
    CloudRunCanaryErrorCode,
    CloudRunCanaryFaultProxy,
    CloudRunCanaryReader,
    CloudRunCanaryTarget,
    CloudRunFaultMode,
)
from reconcile.hosted.firestore_release import (
    FIRESTORE_RELEASE_DATABASE,
    FIRESTORE_RELEASE_RECORD_VERSION,
    FirestoreReleaseConflict,
    FirestoreReleaseOutcomeUnknown,
    FirestoreReleaseProviderUnavailable,
    FirestoreReleaseRecord,
    GoogleFirestoreReleaseTarget,
    firestore_release_document_path,
)
from reconcile.persistence.recovery_runs import (
    RecoveryRunEventSnapshot,
    RecoveryRunNotFound,
    RecoveryRunStore,
)
from reconcile.recovery_agents import RecoveryDispatchReceipt

RECOVERY_SCENARIO_VERSION = "release-chain-scenario-v1"
RECOVERY_AUTHORITY_POLICY_VERSION = "recovery-authority-v1"
RECOVERY_CLASSIFICATION_POLICY_VERSION = "recovery-classification-v1"
RECOVERY_ACTION_POLICY_VERSION = "recovery-action-v1"
RECOVERY_FRESHNESS_SECONDS = 60


class ReleaseChainError(RuntimeError):
    """Sanitized concrete-scenario failure."""


@dataclass(frozen=True, slots=True)
class ReleaseChainSettings:
    project: str
    location: str
    service: str
    release_id: str
    image_digest: str
    configuration_sha256: str
    payload_sha256: str
    database: str = FIRESTORE_RELEASE_DATABASE

    def __post_init__(self) -> None:
        # Reuse the sealed target and semantic profile validators below instead of
        # maintaining a second permissive syntax here.
        build_cloud_run_target(
            project=self.project,
            location=self.location,
            service=self.service,
        )
        build_firestore_release_target(
            project=self.project,
            database=self.database,
            document=firestore_release_document_path(self.release_id),
        )
        if (
            not self.image_digest.startswith("sha256:")
            or len(self.image_digest) != 71
            or any(
                character not in "0123456789abcdef"
                for character in self.image_digest[7:]
            )
            or len(self.configuration_sha256) != 64
            or any(
                character not in "0123456789abcdef"
                for character in self.configuration_sha256
            )
            or len(self.payload_sha256) != 64
            or any(
                character not in "0123456789abcdef" for character in self.payload_sha256
            )
        ):
            raise ValueError("release-chain immutable identity is invalid")

    @property
    def stage_operation_id(self) -> str:
        digest = hashlib.sha256(f"{self.release_id}\0stage".encode()).hexdigest()[:24]
        return f"release-stage-{digest}"

    def revision_for_operation(self, operation_id: str) -> str:
        if type(operation_id) is not str or not operation_id:
            raise ValueError("release-chain operation identity is invalid")
        suffix = hashlib.sha256(operation_id.encode("utf-8")).hexdigest()[:16]
        return f"{self.service}-r-{suffix}"

    @property
    def staged_revision(self) -> str:
        return deterministic_stage_revision(
            service=self.service,
            release_id=self.release_id,
        )


def _require_cloud_target(
    settings: ReleaseChainSettings,
    provider: object,
) -> CloudRunCanaryTarget:
    target = getattr(provider, "target", None)
    if type(target) is not CloudRunCanaryTarget or (
        target.project,
        target.location,
        target.service,
    ) != (settings.project, settings.location, settings.service):
        raise ValueError("Cloud Run provider target differs from release settings")
    return target


def _require_firestore_target(
    settings: ReleaseChainSettings,
    provider: object,
) -> None:
    if (
        getattr(provider, "project_id", None),
        getattr(provider, "database_id", None),
    ) != (settings.project, settings.database):
        raise ValueError("Firestore provider target differs from release settings")


def _effect(
    node_id: str,
    suffix: str,
    scope: str,
    predicate: dict[str, object],
) -> ExpectedEffect:
    return ExpectedEffect(
        schema_version=EXPECTED_EFFECT_VERSION,
        effect_id=f"{node_id}-{suffix}",
        commit_scope=scope,
        predicate=predicate,
        description=f"The provider proves {scope} for the exact release identity.",
    )


def _envelope(
    settings: ReleaseChainSettings,
    *,
    node_id: str,
    invoked_at: datetime,
) -> tuple[ExecutionEnvelope, str]:
    if node_id == "stage":
        profile = STAGE_CLOUD_RUN_REVISION_PROFILE_VERSION
        target = build_cloud_run_target(
            project=settings.project,
            location=settings.location,
            service=settings.service,
        )
        tool_name = "stage-cloud-run-revision"
        arguments = {
            "release_id": settings.release_id,
            "image_digest": settings.image_digest,
            "configuration_sha256": settings.configuration_sha256,
        }
        effects = (
            _effect(
                node_id,
                "revision",
                STAGE_REVISION_EFFECT_SCOPE,
                {**arguments, "revision": settings.staged_revision},
            ),
            _effect(
                node_id,
                "readiness",
                STAGE_READINESS_EFFECT_SCOPE,
                {
                    "release_id": settings.release_id,
                    "ready": True,
                    "revision": settings.staged_revision,
                },
            ),
            _effect(
                node_id,
                "traffic",
                STAGE_TRAFFIC_EFFECT_SCOPE,
                {
                    "release_id": settings.release_id,
                    "traffic_percent": 0,
                    "revision": settings.staged_revision,
                },
            ),
        )
        capability_names = (
            CLOUD_RUN_SERVICE_CAPABILITY,
            CLOUD_RUN_REVISION_CAPABILITY,
            CLOUD_RUN_OPERATION_CAPABILITY,
            CLOUD_RUN_HEALTH_CAPABILITY,
        )
        operation_id = settings.stage_operation_id
    elif node_id == "promote":
        profile = PROMOTE_CLOUD_RUN_TRAFFIC_PROFILE_VERSION
        target = build_cloud_run_target(
            project=settings.project,
            location=settings.location,
            service=settings.service,
        )
        tool_name = "promote-cloud-run-traffic"
        arguments = {
            "release_id": settings.release_id,
            "revision": settings.staged_revision,
            "percent": 100,
        }
        effects = (
            _effect(
                node_id,
                "traffic",
                PROMOTION_TRAFFIC_EFFECT_SCOPE,
                dict(arguments),
            ),
        )
        capability_names = (
            CLOUD_RUN_SERVICE_CAPABILITY,
            CLOUD_RUN_REVISION_CAPABILITY,
            CLOUD_RUN_OPERATION_CAPABILITY,
            CLOUD_RUN_HEALTH_CAPABILITY,
        )
        operation_id = f"release-promote-{hashlib.sha256(settings.release_id.encode()).hexdigest()[:24]}"
    elif node_id == "record":
        profile = CREATE_FIRESTORE_RELEASE_RECORD_PROFILE_VERSION
        target = build_firestore_release_target(
            project=settings.project,
            database=settings.database,
            document=firestore_release_document_path(settings.release_id),
        )
        tool_name = "create-firestore-release-record"
        arguments = {
            "release_id": settings.release_id,
            "payload_sha256": settings.payload_sha256,
        }
        effects = (
            _effect(
                node_id,
                "document",
                FIRESTORE_RECORD_EFFECT_SCOPE,
                {
                    **arguments,
                    "cloud_run_revision": settings.staged_revision,
                },
            ),
        )
        capability_names = (
            FIRESTORE_RELEASE_CAPABILITY,
            DISPATCH_RECEIPT_CAPABILITY,
        )
        operation_id = f"release-record-{hashlib.sha256(settings.release_id.encode()).hexdigest()[:24]}"
    else:
        raise ValueError("release chain node is unsupported")
    arguments_sha256 = hashlib.sha256(canonical_json_value_bytes(arguments)).hexdigest()
    envelope = ExecutionEnvelope(
        schema_version=EXECUTION_ENVELOPE_VERSION,
        investigation_id=f"recovery-{operation_id}",
        operation_id=operation_id,
        target=target,
        invoked_at=invoked_at,
        ambiguity=AmbiguousExecution(
            kind=AmbiguityKind.MISSING_TOOL_RESULT,
            observed_at=invoked_at,
            detail="The exact mutation acknowledgement may not reach the caller.",
        ),
        expected_effects=effects,
        context=EnvelopeContext(
            invocation=OriginalInvocation(
                invocation_id=f"invocation-{operation_id}",
                function_call_id=f"call-{operation_id}",
                tool_name=tool_name,
                tool_version=RECOVERY_TOOL_VERSION,
                arguments=arguments,
                arguments_sha256=arguments_sha256,
            ),
            enabled_capabilities=tuple(
                CapabilityRef(name=name, version="1.0.0") for name in capability_names
            ),
            correlation_fields={"release_id": settings.release_id},
            evidence_budget=EvidenceBudget(
                max_probes=8,
                max_elapsed_ms=30_000,
                max_total_result_bytes=1_000_000,
                max_cost_units=8,
            ),
            freshness=FreshnessPolicy(
                max_age_seconds=RECOVERY_FRESHNESS_SECONDS,
                clock_skew_seconds=2,
            ),
            policies=PolicyReferences(
                authority=RECOVERY_AUTHORITY_POLICY_VERSION,
                classification=RECOVERY_CLASSIFICATION_POLICY_VERSION,
                action=RECOVERY_ACTION_POLICY_VERSION,
            ),
        ),
    )
    return envelope, profile


def _semantic_action(
    envelope: ExecutionEnvelope,
    profile_version: str,
) -> SemanticActionIdentity:
    invocation = envelope.context.invocation
    effect_sha256s = tuple(
        canonical_sha256(effect) for effect in envelope.expected_effects
    )
    return SemanticActionIdentity(
        key_version="semantic-action-v1",
        tool_name=invocation.tool_name,
        tool_version=invocation.tool_version,
        semantic_arguments=invocation.arguments,
        target=envelope.target,
        expected_effect_sha256s=effect_sha256s,
        action_profile_version=profile_version,
        semantic_action_sha256=semantic_action_sha256(
            key_version="semantic-action-v1",
            tool_name=invocation.tool_name,
            tool_version=invocation.tool_version,
            semantic_arguments=invocation.arguments,
            target=envelope.target,
            expected_effect_sha256s=effect_sha256s,
            action_profile_version=profile_version,
        ),
    )


def build_release_chain_definition(
    settings: ReleaseChainSettings,
    *,
    invoked_at: datetime,
):
    """Build the stable semantic stage -> promote -> record chain."""

    from reconcile.recovery_workflow import RecoveryRunDefinition

    if invoked_at.tzinfo is None or invoked_at.utcoffset() is None:
        raise ValueError("release-chain invocation time must be aware")
    timestamp = invoked_at.astimezone(UTC)
    specifications = (
        ("stage", ()),
        ("promote", ("stage",)),
        ("record", ("promote",)),
    )
    envelopes: dict[str, ExecutionEnvelope] = {}
    nodes: list[RecoveryActionNode] = []
    capabilities: dict[str, tuple[object, ...]] = {}
    for node_id, dependencies in specifications:
        envelope, profile = _envelope(
            settings,
            node_id=node_id,
            invoked_at=timestamp,
        )
        action = _semantic_action(envelope, profile)
        envelopes[node_id] = envelope
        nodes.append(
            RecoveryActionNode(
                node_id=node_id,
                chain_profile_version=RECOVERY_CHAIN_PROFILE_VERSION,
                semantic_action=action,
                depends_on=dependencies,
                envelope=ExecutionEnvelopeReference(
                    investigation_id=envelope.investigation_id,
                    operation_id=envelope.operation_id,
                    envelope_sha256=canonical_sha256(envelope),
                ),
            )
        )
        capabilities[node_id] = tuple(
            (
                build_cloud_run_capability(
                    capability_name=reference.name,
                    target=envelope.target,
                )
                if node_id != "record"
                else build_firestore_release_capability(
                    capability_name=reference.name,
                    target=envelope.target,
                )
            )
            for reference in envelope.context.enabled_capabilities
        )
    chain_id = (
        f"release-chain-{hashlib.sha256(settings.release_id.encode()).hexdigest()[:24]}"
    )
    chain = RecoveryChain(
        schema_version=RECOVERY_CHAIN_VERSION,
        chain_id=chain_id,
        chain_profile_version=RECOVERY_CHAIN_PROFILE_VERSION,
        nodes=tuple(nodes),
        created_at=timestamp,
    )
    return RecoveryRunDefinition(
        chain=chain,
        envelopes=envelopes,
        capabilities=capabilities,  # type: ignore[arg-type]
    )


def build_release_chain_workflow(
    *,
    settings: ReleaseChainSettings,
    invoked_at: datetime,
    store: RecoveryRunStore,
    permit_authority: PermitAuthority,
    recovery_agent: object,
    cloud_action: object,
    cloud_reader: CloudRunCanaryReader,
    firestore: GoogleFirestoreReleaseTarget,
    clock: Callable[[], datetime] | None = None,
):
    """Assemble fixed/adaptive lanes over the exact same production boundaries."""

    from reconcile.recovery_agents import RecoveryAgent, RolloutAgent
    from reconcile.recovery_workflow import ProofToPermitWorkflow

    if type(recovery_agent) is not RecoveryAgent:
        raise TypeError("release workflow requires an exact RecoveryAgent")
    if _require_cloud_target(settings, cloud_action) != _require_cloud_target(
        settings, cloud_reader
    ):
        raise ValueError("Cloud Run action and evidence targets differ")
    _require_firestore_target(settings, firestore)
    definition = build_release_chain_definition(settings, invoked_at=invoked_at)
    evidence = ReleaseChainEvidenceSource(
        store=store,
        definition=definition,
        settings=settings,
        cloud_run=cloud_reader,
        firestore=firestore,
        clock=clock,
    )
    gateway = ReleaseChainDispatchGateway(
        settings=settings,
        store=store,
        permit_authority=permit_authority,
        cloud_run=cloud_action,  # type: ignore[arg-type]
        firestore=firestore,
        clock=clock,
    )
    return ProofToPermitWorkflow(
        store=store,
        definition_factory=lambda _request: definition,
        evidence_source=evidence,
        action_preparer=ReleaseChainActionPreparer(),
        recovery_agent=recovery_agent,
        rollout_agent=RolloutAgent(gateway),
        permit_authority=permit_authority,
        clock=clock,
    )


class ReleaseChainActionPreparer:
    """Prepare provider requests only after their exact proof artifact exists."""

    @staticmethod
    def _fresh_service_etag(
        report: object,
        certificate: VerifiedCertificate,
    ) -> str:
        from reconcile.contracts import InvestigationReport

        if type(report) is not InvestigationReport:
            raise ReleaseChainError("certificate-bound evidence report is unavailable")
        evidence_ids = {binding.evidence_id for binding in certificate.evidence}
        etags = {
            item.correlation["service_etag"]
            for item in report.evidence
            if item.evidence_id in evidence_ids
            and type(item.correlation.get("service_etag")) is str
        }
        if len(etags) != 1:
            raise ReleaseChainError("fresh service ETag is not uniquely certified")
        return etags.pop()

    def prepare(
        self,
        request: RecoveryRunRequest,
        chain: RecoveryChain,
        source_node: RecoveryActionNode,
        target_node: RecoveryActionNode,
        report: object | None,
        certificate: VerifiedCertificate | None,
    ) -> RecoveryPreparedAction:
        action = target_node.semantic_action
        arguments = action.semantic_arguments
        if target_node.node_id == "stage":
            precondition = {"none": True}
            payload = {
                "action": "stage",
                "configuration_sha256": arguments["configuration_sha256"],
                "fault_mode": (
                    CloudRunFaultMode.DROP_AFTER_ACCEPT.value
                    if request.fault is RecoveryRunFault.DROP_AFTER_ACCEPT
                    else CloudRunFaultMode.PASS_THROUGH.value
                ),
                "image_digest": arguments["image_digest"],
                "operation_id": target_node.envelope.operation_id,
                "release_id": arguments["release_id"],
            }
        elif target_node.node_id == "promote":
            if certificate is None or report is None:
                raise ReleaseChainError("promotion requires a fresh stage certificate")
            service_etag = self._fresh_service_etag(report, certificate)
            precondition = {"service_etag": service_etag}
            payload = {
                "action": "promote",
                "fault_mode": CloudRunFaultMode.PASS_THROUGH.value,
                "release_id": arguments["release_id"],
                "revision": arguments["revision"],
                "service_etag": service_etag,
            }
        elif target_node.node_id == "record":
            precondition = {"exists": False}
            payload = {
                "action": "record",
                "cloud_run_revision": next(
                    node.semantic_action.semantic_arguments["revision"]
                    for node in chain.nodes
                    if node.node_id == "promote"
                ),
                "payload_sha256": arguments["payload_sha256"],
                "release_id": arguments["release_id"],
                "suppress_before_dispatch": (
                    request.fault is RecoveryRunFault.SUPPRESS_BEFORE_DISPATCH
                ),
            }
        else:
            raise ReleaseChainError("release action is outside the declared chain")
        proof = certificate is not None
        payload_sha256 = hashlib.sha256(canonical_json_value_bytes(payload)).hexdigest()
        return RecoveryPreparedAction(
            schema_version=RECOVERY_PREPARED_ACTION_VERSION,
            authority_kind=(
                RecoveryAuthorityKind.ACTION_PERMIT
                if proof
                else RecoveryAuthorityKind.LAUNCH_PERMIT
            ),
            run_id=request.run_id,
            chain_id=chain.chain_id,
            source_node_id=source_node.node_id,
            target_node_id=target_node.node_id,
            semantic_action_sha256=action.semantic_action_sha256,
            tool_name=action.tool_name,
            tool_version=action.tool_version,
            arguments=arguments,
            arguments_sha256=hashlib.sha256(
                canonical_json_value_bytes(arguments)
            ).hexdigest(),
            target=action.target,
            target_sha256=canonical_sha256(action.target),
            precondition=precondition,
            precondition_sha256=hashlib.sha256(
                canonical_json_value_bytes(precondition)
            ).hexdigest(),
            request_payload=payload,
            action_request_sha256=payload_sha256,
            permit_action=(
                None if certificate is None else certificate.transition.action
            ),
            report_sha256=(None if certificate is None else certificate.report_sha256),
            certificate_id=(
                None if certificate is None else certificate.certificate_id
            ),
            certificate_sha256=(
                None if certificate is None else canonical_sha256(certificate)
            ),
        )


class RecoveryRunReceiptReader:
    """Expose only authoritative non-contact receipts to the evidence adapter."""

    def __init__(self, store: RecoveryRunStore) -> None:
        if not isinstance(store, RecoveryRunStore):
            raise TypeError("dispatch receipt reader requires a recovery store")
        self._store = store

    async def latest_dispatch_receipt(
        self,
        *,
        run_id: str,
        node_id: str,
        attempt: int,
        semantic_action_sha256: str,
    ) -> DurableDispatchReceipt | None:
        snapshot = await self._store.get(run_id)
        matches = tuple(
            receipt
            for receipt in snapshot.dispatch_receipts
            if receipt.node_id == node_id
            and receipt.attempt == attempt
            and receipt.semantic_action_sha256 == semantic_action_sha256
            and not receipt.provider_contact
        )
        return None if not matches else matches[-1]


@dataclass(slots=True)
class _EvidenceSession:
    controller: ProbeController
    engine: EvidenceEngine
    created_at: datetime
    executed_capabilities: set[str]


class ReleaseChainEvidenceSource:
    """Incrementally acquire real provider reads through the sealed rule path."""

    def __init__(
        self,
        *,
        store: RecoveryRunStore,
        definition: object,
        settings: ReleaseChainSettings,
        cloud_run: CloudRunCanaryReader,
        firestore: GoogleFirestoreReleaseTarget,
        clock: Callable[[], datetime] | None = None,
        controller_clock: ControllerClock | None = None,
    ) -> None:
        from reconcile.recovery_workflow import RecoveryRunDefinition

        if not isinstance(store, RecoveryRunStore):
            raise TypeError("release evidence requires a recovery store")
        if type(definition) is not RecoveryRunDefinition:
            raise TypeError("release evidence requires an exact definition")
        if type(settings) is not ReleaseChainSettings:
            raise TypeError("release evidence requires exact settings")
        if type(cloud_run) is not CloudRunCanaryReader:
            raise TypeError("release evidence requires the sealed Cloud Run reader")
        if type(firestore) is not GoogleFirestoreReleaseTarget:
            raise TypeError("release evidence requires the sealed Firestore target")
        _require_cloud_target(settings, cloud_run)
        _require_firestore_target(settings, firestore)
        self._store = store
        self._definition = definition
        self._settings = settings
        self._cloud_run = cloud_run
        self._firestore = firestore
        self._receipts = RecoveryRunReceiptReader(store)
        self._clock = clock or (lambda: datetime.now(UTC))
        self._controller_clock = controller_clock
        self._sessions: dict[tuple[str, str, int], _EvidenceSession] = {}

    def _now(self) -> datetime:
        value = self._clock()
        if value.tzinfo is None or value.utcoffset() is None:
            raise ReleaseChainError("release evidence clock is invalid")
        return value.astimezone(UTC)

    async def _session(
        self,
        run_id: str,
        node: RecoveryActionNode,
        envelope: ExecutionEnvelope,
        *,
        refresh: bool = False,
    ) -> _EvidenceSession:
        snapshot = await self._store.get(run_id)
        progress = next(item for item in snapshot.nodes if item.node_id == node.node_id)
        attempt = max(1, progress.attempt)
        key = (run_id, node.node_id, attempt)
        existing = self._sessions.get(key)
        if existing is not None and not refresh:
            return existing
        capabilities = CapabilityRegistry()
        rules = TargetRuleRegistry()
        if node.node_id in {"stage", "promote"}:
            binding = (
                CloudRunProbeBinding.for_stage(
                    release_id=self._settings.release_id,
                    image_digest=self._settings.image_digest,
                    configuration_sha256=self._settings.configuration_sha256,
                    expected_revision=self._settings.staged_revision,
                )
                if node.node_id == "stage"
                else CloudRunProbeBinding.for_promotion(
                    release_id=self._settings.release_id,
                    revision=self._settings.staged_revision,
                )
            )
            for reference in envelope.context.enabled_capabilities:
                capabilities.register(
                    build_cloud_run_capability_registration(
                        reader=self._cloud_run,
                        binding=binding,
                        capability_name=reference.name,
                        target=envelope.target,
                        clock=self._clock,
                    )
                )
                rules.register(
                    build_cloud_run_rule_registration(
                        capability_name=reference.name,
                        binding=binding,
                    )
                )
        else:
            binding = FirestoreReleaseProbeBinding(
                run_id=run_id,
                node_id=node.node_id,
                attempt=attempt,
                release_id=self._settings.release_id,
                cloud_run_revision=self._settings.staged_revision,
                payload_sha256=self._settings.payload_sha256,
                semantic_action_sha256=node.semantic_action.semantic_action_sha256,
            )
            for reference in envelope.context.enabled_capabilities:
                capabilities.register(
                    build_firestore_release_capability_registration(
                        target=self._firestore,
                        receipts=self._receipts,
                        binding=binding,
                        capability_name=reference.name,
                        action_target=envelope.target,
                        clock=self._clock,
                    )
                )
                rules.register(
                    build_firestore_release_rule_registration(
                        capability_name=reference.name,
                        binding=binding,
                    )
                )
        session = _EvidenceSession(
            controller=ProbeController(
                envelope,
                capabilities,
                clock=self._controller_clock or _WallClock(self._clock),
            ),
            engine=EvidenceEngine(envelope, rules),
            created_at=self._now(),
            executed_capabilities=set(),
        )
        self._sessions[key] = session
        return session

    async def _execute(
        self,
        session: _EvidenceSession,
        envelope: ExecutionEnvelope,
        capability_name: str,
    ) -> None:
        request = ProbeRequest(
            schema_version=PROBE_REQUEST_VERSION,
            capability_name=capability_name,
            capability_version="1.0.0",
            relevant_effect_ids=tuple(
                effect.effect_id for effect in envelope.expected_effects
            ),
            arguments={},
            rationale="Read exact target-bound provider state for recovery.",
        )
        execution = await session.controller.execute(request)
        session.engine.process(ProbeRun(request=request, execution=execution))
        session.executed_capabilities.add(capability_name)

    def _state(
        self,
        session: _EvidenceSession,
        envelope: ExecutionEnvelope,
    ):
        from reconcile.recovery_workflow import RecoveryEvidenceState

        updated_at = self._now()
        audit = session.controller.audit_trail
        evaluation = session.engine.evaluate(audit)
        report = session.engine.report(
            audit,
            created_at=session.created_at,
            updated_at=max(updated_at, session.created_at),
            revision=max(1, len(audit)),
        )
        return RecoveryEvidenceState(envelope, report, evaluation)

    async def current(
        self,
        run_id: str,
        node: RecoveryActionNode,
        envelope: ExecutionEnvelope,
    ):
        # `current` begins a new bounded observation round.  Reusing a completed
        # round here would turn PENDING into a permanent cached state.
        session = await self._session(run_id, node, envelope, refresh=True)
        primary = (
            CLOUD_RUN_SERVICE_CAPABILITY
            if node.node_id in {"stage", "promote"}
            else FIRESTORE_RELEASE_CAPABILITY
        )
        if primary not in session.executed_capabilities:
            await self._execute(session, envelope, primary)
        return self._state(session, envelope)

    async def probe(
        self,
        run_id: str,
        node: RecoveryActionNode,
        envelope: ExecutionEnvelope,
        request: object,
    ):
        if type(request) is not ProbeRequest:
            raise TypeError("release evidence probe must be exact")
        session = await self._session(run_id, node, envelope)
        execution = await session.controller.execute(request)
        session.engine.process(ProbeRun(request=request, execution=execution))
        session.executed_capabilities.add(request.capability_name)
        return self._state(session, envelope)

    async def fixed(
        self,
        run_id: str,
        node: RecoveryActionNode,
        envelope: ExecutionEnvelope,
    ):
        session = await self._session(run_id, node, envelope)
        sequence = {
            "stage": (
                CLOUD_RUN_SERVICE_CAPABILITY,
                CLOUD_RUN_REVISION_CAPABILITY,
                CLOUD_RUN_HEALTH_CAPABILITY,
            ),
            "promote": (CLOUD_RUN_SERVICE_CAPABILITY,),
            "record": (
                FIRESTORE_RELEASE_CAPABILITY,
                DISPATCH_RECEIPT_CAPABILITY,
            ),
        }[node.node_id]
        for capability_name in sequence:
            if capability_name not in session.executed_capabilities:
                await self._execute(session, envelope, capability_name)
        return self._state(session, envelope)


class _CloudMutationPort(Protocol):
    def stage_revision(self, **kwargs: object) -> object: ...

    def promote_revision(self, **kwargs: object) -> object: ...


class _ReleaseMutationPort(Protocol):
    async def create(self, record: FirestoreReleaseRecord) -> object: ...


async def _invoke_provider(call: Callable[..., object], **kwargs: object) -> object:
    """Keep synchronous Google clients off the orchestration event loop."""

    value = await asyncio.to_thread(call, **kwargs)
    return await value if inspect.isawaitable(value) else value


class ReleaseChainDispatchGateway:
    """Claim authority, enforce durable suppression, and receipt provider contact."""

    def __init__(
        self,
        *,
        settings: ReleaseChainSettings,
        store: RecoveryRunStore,
        permit_authority: PermitAuthority,
        cloud_run: _CloudMutationPort,
        firestore: _ReleaseMutationPort,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        if not isinstance(store, RecoveryRunStore):
            raise TypeError("release gateway requires a recovery store")
        if type(permit_authority) is not PermitAuthority:
            raise TypeError("release gateway requires an exact permit authority")
        if any(
            not callable(getattr(cloud_run, name, None))
            for name in ("stage_revision", "promote_revision")
        ) or not callable(getattr(firestore, "create", None)):
            raise TypeError("release gateway provider boundary is incomplete")
        if type(settings) is not ReleaseChainSettings:
            raise TypeError("release gateway requires exact release settings")
        _require_cloud_target(settings, cloud_run)
        _require_firestore_target(settings, firestore)
        self._settings = settings
        self._store = store
        self._authority = permit_authority
        self._cloud_run = cloud_run
        self._firestore = firestore
        self._clock = clock or (lambda: datetime.now(UTC))

    def _now(self, not_before: datetime) -> datetime:
        value = self._clock()
        if value.tzinfo is None or value.utcoffset() is None:
            raise ReleaseChainError("release gateway clock is invalid")
        return max(value.astimezone(UTC), not_before)

    async def _claim(
        self,
        prepared: RecoveryPreparedAction,
        scope: RecoveryActionScope,
    ):
        snapshot = await self._store.get(scope.run_id)
        if scope.authority_kind is RecoveryAuthorityKind.LAUNCH_PERMIT:
            return await self._store.claim_launch(
                scope.run_id,
                launch_permit_id=scope.authority_id,
                claim_id=scope.claim_id,
                action_request_sha256=scope.action_request_sha256,
                claimed_at=self._now(snapshot.updated_at),
            )
        certificate = next(
            (
                item
                for item in snapshot.certificates
                if item.certificate_id == scope.certificate_id
                and canonical_sha256(item) == scope.certificate_sha256
            ),
            None,
        )
        node = next(
            item
            for item in snapshot.chain.nodes
            if item.node_id == scope.target_node_id
        )
        if certificate is None:
            raise PermissionError("release certificate is unavailable")
        claimed = await self._authority.claim_for_dispatch(
            permit_id=scope.authority_id,
            certificate=certificate,
            semantic_action=node.semantic_action,
            tool_name=prepared.tool_name,
            tool_version=prepared.tool_version,
            arguments=prepared.arguments,
            target=prepared.target,
            precondition=prepared.precondition,
            claim_id=scope.claim_id,
        )
        snapshot = await self._store.get(scope.run_id)
        await self._store.append(
            scope.run_id,
            expected_revision=snapshot.revision,
            event_type=RecoveryRunEventType.ACTION_PERMIT,
            payload=RecoveryRunEventPayload(action_permit=claimed),
            occurred_at=self._now(snapshot.updated_at),
        )
        return claimed

    async def _record_receipt(
        self,
        prepared: RecoveryPreparedAction,
        scope: RecoveryActionScope,
        *,
        provider_contact: bool,
    ) -> DurableDispatchReceipt:
        snapshot = await self._store.get(scope.run_id)
        receipt = DurableDispatchReceipt(
            schema_version=RECOVERY_DISPATCH_RECEIPT_VERSION,
            receipt_id=(
                "dispatch-"
                + hashlib.sha256(
                    f"{scope.authority_id}\0{scope.claim_id}".encode()
                ).hexdigest()[:32]
            ),
            run_id=scope.run_id,
            release_id=str(prepared.arguments["release_id"]),
            node_id=scope.target_node_id,
            semantic_action_sha256=scope.semantic_action_sha256,
            action_request_sha256=scope.action_request_sha256,
            authority_id=scope.authority_id,
            claim_id=scope.claim_id,
            attempt=2 if scope.permit_action is PermitAction.RETRY else 1,
            provider_contact=provider_contact,
            outcome=(
                RecoveryReceiptOutcome.PROVIDER_CONTACTED
                if provider_contact
                else RecoveryReceiptOutcome.SUPPRESSED_BEFORE_DISPATCH
            ),
            recorded_at=self._now(snapshot.updated_at),
        )
        await self._store.append(
            scope.run_id,
            expected_revision=snapshot.revision,
            event_type=RecoveryRunEventType.DISPATCH_RECEIPT,
            payload=RecoveryRunEventPayload(dispatch_receipt=receipt),
            occurred_at=receipt.recorded_at,
        )
        return receipt

    async def _complete(
        self,
        claimed: object,
        scope: RecoveryActionScope,
        outcome: RecoveryDispatchOutcome,
    ) -> object:
        if scope.authority_kind is RecoveryAuthorityKind.LAUNCH_PERMIT:
            snapshot = await self._store.get(scope.run_id)
            return await self._store.complete_launch(
                scope.run_id,
                launch_permit_id=scope.authority_id,
                claim_id=scope.claim_id,
                outcome=outcome,
                completed_at=self._now(snapshot.updated_at),
            )
        return await self._authority.complete_dispatch(
            claimed,  # type: ignore[arg-type]
            PermitCompletionOutcome(outcome.value),
        )

    async def dispatch(
        self,
        prepared: RecoveryPreparedAction,
        scope: RecoveryActionScope,
    ) -> RecoveryDispatchReceipt:
        if (
            type(prepared) is not RecoveryPreparedAction
            or type(scope) is not RecoveryActionScope
        ):
            raise TypeError("release dispatch requires exact recovery authority")
        expected_target = (
            build_firestore_release_target(
                project=self._settings.project,
                database=self._settings.database,
                document=firestore_release_document_path(self._settings.release_id),
            )
            if prepared.target_node_id == "record"
            else build_cloud_run_target(
                project=self._settings.project,
                location=self._settings.location,
                service=self._settings.service,
            )
        )
        if (
            prepared.target != expected_target
            or prepared.arguments.get("release_id") != self._settings.release_id
        ):
            raise PermissionError("release dispatch provider target changed")
        stage_mode = (
            CloudRunFaultMode(str(prepared.request_payload["fault_mode"]))
            if prepared.target_node_id == "stage"
            else CloudRunFaultMode.PASS_THROUGH
        )
        if (
            prepared.target_node_id == "stage"
            and stage_mode is CloudRunFaultMode.DROP_AFTER_ACCEPT
            and type(self._cloud_run) is CloudRunCanaryActionAdapter
        ):
            raise ReleaseChainError(
                "drop-after-accept requires the explicit Cloud Run fault proxy"
            )
        claimed = await self._claim(prepared, scope)
        suppress = (
            prepared.target_node_id == "record"
            and prepared.request_payload.get("suppress_before_dispatch") is True
            and not any(
                receipt.node_id == "record" and not receipt.provider_contact
                for receipt in (await self._store.get(scope.run_id)).dispatch_receipts
            )
        )
        outcome = RecoveryDispatchOutcome.OUTCOME_UNKNOWN
        if suppress:
            await self._record_receipt(
                prepared,
                scope,
                provider_contact=False,
            )
        else:
            try:
                if prepared.target_node_id == "stage":
                    kwargs = {
                        "operation_id": str(prepared.request_payload["operation_id"]),
                        "release_id": str(prepared.request_payload["release_id"]),
                        "image_digest": str(prepared.request_payload["image_digest"]),
                        "configuration_sha256": str(
                            prepared.request_payload["configuration_sha256"]
                        ),
                    }
                    if type(self._cloud_run) is not CloudRunCanaryActionAdapter:
                        kwargs["mode"] = stage_mode
                    await _invoke_provider(
                        self._cloud_run.stage_revision,
                        **kwargs,
                    )
                elif prepared.target_node_id == "promote":
                    kwargs = {
                        "release_id": str(prepared.request_payload["release_id"]),
                        "revision": str(prepared.request_payload["revision"]),
                        "service_etag": str(prepared.request_payload["service_etag"]),
                    }
                    if type(self._cloud_run) is not CloudRunCanaryActionAdapter:
                        kwargs["mode"] = CloudRunFaultMode.PASS_THROUGH
                    await _invoke_provider(
                        self._cloud_run.promote_revision,
                        **kwargs,
                    )
                elif prepared.target_node_id == "record":
                    await self._firestore.create(
                        FirestoreReleaseRecord(
                            schema_version=FIRESTORE_RELEASE_RECORD_VERSION,
                            release_id=str(prepared.request_payload["release_id"]),
                            cloud_run_revision=str(
                                prepared.request_payload["cloud_run_revision"]
                            ),
                            payload_sha256=str(
                                prepared.request_payload["payload_sha256"]
                            ),
                            semantic_action_sha256=prepared.semantic_action_sha256,
                            created_at=self._now(
                                (await self._store.get(scope.run_id)).updated_at
                            ),
                        )
                    )
                else:
                    raise ReleaseChainError("release dispatch node is unsupported")
                outcome = RecoveryDispatchOutcome.SUCCEEDED
            except (
                CloudRunAcceptanceAmbiguity,
                FirestoreReleaseOutcomeUnknown,
                FirestoreReleaseProviderUnavailable,
            ):
                outcome = RecoveryDispatchOutcome.OUTCOME_UNKNOWN
            except FirestoreReleaseConflict:
                outcome = RecoveryDispatchOutcome.REJECTED
            except CloudRunCanaryError as error:
                outcome = (
                    RecoveryDispatchOutcome.OUTCOME_UNKNOWN
                    if error.code
                    in {
                        CloudRunCanaryErrorCode.ACCEPTANCE_AMBIGUOUS,
                        CloudRunCanaryErrorCode.PROVIDER_UNAVAILABLE,
                    }
                    else RecoveryDispatchOutcome.REJECTED
                )
            except asyncio.CancelledError:
                raise
            await self._record_receipt(
                prepared,
                scope,
                provider_contact=True,
            )
        completed = await self._complete(claimed, scope, outcome)
        return RecoveryDispatchReceipt(
            outcome=outcome,
            launch_permit=(
                completed
                if scope.authority_kind is RecoveryAuthorityKind.LAUNCH_PERMIT
                else None
            ),
            action_permit=(
                completed
                if scope.authority_kind is RecoveryAuthorityKind.ACTION_PERMIT
                else None
            ),
        )


class BlindReleaseMutator(Protocol):
    """Intentionally authority-free interface, isolated from RolloutAgent."""

    async def stage(self, *, operation_id: str, drop_after_accept: bool) -> None: ...

    async def promote(self) -> None: ...

    async def create_record(self, *, suppress_before_dispatch: bool) -> None: ...


class ReleaseChainBlindMutator:
    """Provider-backed mutation path with no proof or permit authority."""

    def __init__(
        self,
        *,
        settings: ReleaseChainSettings,
        cloud_action: object,
        cloud_reader: CloudRunCanaryReader,
        firestore: GoogleFirestoreReleaseTarget,
        invoked_at: datetime,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        if type(settings) is not ReleaseChainSettings:
            raise TypeError("blind mutator requires exact release settings")
        if type(cloud_reader) is not CloudRunCanaryReader:
            raise TypeError("blind mutator requires the sealed Cloud Run reader")
        if type(firestore) is not GoogleFirestoreReleaseTarget:
            raise TypeError("blind mutator requires the sealed Firestore target")
        action_target = _require_cloud_target(settings, cloud_action)
        if action_target != _require_cloud_target(settings, cloud_reader):
            raise ValueError("blind action and evidence targets differ")
        _require_firestore_target(settings, firestore)
        if invoked_at.tzinfo is None or invoked_at.utcoffset() is None:
            raise ValueError("blind mutator invocation time must be aware")
        self._settings = settings
        self._cloud_action = cloud_action
        self._cloud_reader = cloud_reader
        self._firestore = firestore
        self._clock = clock or (lambda: datetime.now(UTC))
        self._revision = settings.staged_revision
        self._record_action_sha256 = (
            build_release_chain_definition(
                settings,
                invoked_at=invoked_at,
            )
            .chain.nodes[-1]
            .semantic_action.semantic_action_sha256
        )

    def _now(self) -> datetime:
        value = self._clock()
        if value.tzinfo is None or value.utcoffset() is None:
            raise ReleaseChainError("blind mutator clock is invalid")
        return value.astimezone(UTC)

    async def stage(self, *, operation_id: str, drop_after_accept: bool) -> None:
        self._revision = self._settings.revision_for_operation(operation_id)
        if (
            drop_after_accept
            and type(self._cloud_action) is CloudRunCanaryActionAdapter
        ):
            raise ReleaseChainError(
                "drop-after-accept requires the explicit Cloud Run fault proxy"
            )
        kwargs: dict[str, object] = {
            "operation_id": operation_id,
            "release_id": self._settings.release_id,
            "image_digest": self._settings.image_digest,
            "configuration_sha256": self._settings.configuration_sha256,
        }
        if type(self._cloud_action) is not CloudRunCanaryActionAdapter:
            kwargs["mode"] = (
                CloudRunFaultMode.DROP_AFTER_ACCEPT
                if drop_after_accept
                else CloudRunFaultMode.PASS_THROUGH
            )
        await _invoke_provider(
            self._cloud_action.stage_revision,
            **kwargs,
        )

    async def promote(self) -> None:
        service = await asyncio.to_thread(
            self._cloud_reader.read_service,
            release_id=self._settings.release_id,
            revision=self._revision,
        )
        kwargs = {
            "release_id": self._settings.release_id,
            "revision": self._revision,
            "service_etag": service.service_etag,
        }
        if type(self._cloud_action) is not CloudRunCanaryActionAdapter:
            kwargs["mode"] = CloudRunFaultMode.PASS_THROUGH
        await _invoke_provider(self._cloud_action.promote_revision, **kwargs)

    async def create_record(self, *, suppress_before_dispatch: bool) -> None:
        if suppress_before_dispatch:
            raise ReleaseChainError("blind release-record dispatch was suppressed")
        await self._firestore.create(
            FirestoreReleaseRecord(
                schema_version=FIRESTORE_RELEASE_RECORD_VERSION,
                release_id=self._settings.release_id,
                cloud_run_revision=self._revision,
                payload_sha256=self._settings.payload_sha256,
                semantic_action_sha256=self._record_action_sha256,
                created_at=self._now(),
            )
        )


@dataclass(frozen=True, slots=True)
class BlindPolicyOutcome:
    """Authority-free baseline result, before provider observations are recorded."""

    chain_completed: bool
    provider_contacts: int
    timeline: tuple[RecoveryTimelineEntry, ...]


class BlindPolicyExecutor:
    """Minimal controls that demonstrate the two unsafe ambiguity defaults."""

    def __init__(self, mutator: BlindReleaseMutator) -> None:
        if any(
            not callable(getattr(mutator, name, None))
            for name in ("stage", "promote", "create_record")
        ):
            raise TypeError("blind baseline mutator is incomplete")
        self._mutator = mutator

    async def blind_retry(
        self,
        *,
        operation_id: str,
        fault: RecoveryRunFault = RecoveryRunFault.DROP_AFTER_ACCEPT,
    ) -> BlindPolicyOutcome:
        timeline: list[RecoveryTimelineEntry] = []
        provider_contacts = 1
        try:
            await self._mutator.stage(
                operation_id=operation_id,
                drop_after_accept=fault is RecoveryRunFault.DROP_AFTER_ACCEPT,
            )
        except Exception:
            timeline.append(
                RecoveryTimelineEntry(
                    sequence=len(timeline) + 1,
                    node_id="stage",
                    event="acknowledgement-lost",
                    detail="The baseline received no stage acknowledgement.",
                )
            )
            # This is the deliberately unsafe behavior under comparison.
            provider_contacts += 1
            await self._mutator.stage(
                operation_id=f"{operation_id}-retry",
                drop_after_accept=False,
            )
            timeline.append(
                RecoveryTimelineEntry(
                    sequence=len(timeline) + 1,
                    node_id="stage",
                    event="blind-retry",
                    detail="The baseline repeated the stage mutation without proof.",
                )
            )
        else:
            timeline.append(
                RecoveryTimelineEntry(
                    sequence=len(timeline) + 1,
                    node_id="stage",
                    event="acknowledged",
                    detail="The baseline received the stage acknowledgement.",
                )
            )
        provider_contacts += 1
        await self._mutator.promote()
        timeline.append(
            RecoveryTimelineEntry(
                sequence=len(timeline) + 1,
                node_id="promote",
                event="blind-continue",
                detail="The baseline promoted without proof-scoped authority.",
            )
        )
        try:
            await self._mutator.create_record(
                suppress_before_dispatch=(
                    fault is RecoveryRunFault.SUPPRESS_BEFORE_DISPATCH
                )
            )
        except Exception:
            timeline.append(
                RecoveryTimelineEntry(
                    sequence=len(timeline) + 1,
                    node_id="record",
                    event="dispatch-suppressed",
                    detail="The baseline observed a missing release-record response.",
                )
            )
            provider_contacts += 1
            await self._mutator.create_record(suppress_before_dispatch=False)
            timeline.append(
                RecoveryTimelineEntry(
                    sequence=len(timeline) + 1,
                    node_id="record",
                    event="blind-retry",
                    detail="The baseline repeated the release-record mutation.",
                )
            )
        else:
            provider_contacts += 1
            timeline.append(
                RecoveryTimelineEntry(
                    sequence=len(timeline) + 1,
                    node_id="record",
                    event="acknowledged",
                    detail="The baseline received the release-record acknowledgement.",
                )
            )
        return BlindPolicyOutcome(
            chain_completed=True,
            provider_contacts=provider_contacts,
            timeline=tuple(timeline),
        )

    async def blind_abort(
        self,
        *,
        operation_id: str,
        fault: RecoveryRunFault = RecoveryRunFault.DROP_AFTER_ACCEPT,
    ) -> BlindPolicyOutcome:
        timeline: list[RecoveryTimelineEntry] = []
        provider_contacts = 1
        try:
            await self._mutator.stage(
                operation_id=operation_id,
                drop_after_accept=fault is RecoveryRunFault.DROP_AFTER_ACCEPT,
            )
        except Exception:
            # This is intentionally incomplete and has no proof authority.
            return BlindPolicyOutcome(
                chain_completed=False,
                provider_contacts=provider_contacts,
                timeline=(
                    RecoveryTimelineEntry(
                        sequence=1,
                        node_id="stage",
                        event="blind-abort",
                        detail="The baseline aborted after a missing stage acknowledgement.",
                    ),
                ),
            )
        timeline.append(
            RecoveryTimelineEntry(
                sequence=1,
                node_id="stage",
                event="acknowledged",
                detail="The baseline received the stage acknowledgement.",
            )
        )
        provider_contacts += 1
        await self._mutator.promote()
        timeline.append(
            RecoveryTimelineEntry(
                sequence=2,
                node_id="promote",
                event="blind-continue",
                detail="The baseline promoted without proof-scoped authority.",
            )
        )
        try:
            await self._mutator.create_record(
                suppress_before_dispatch=(
                    fault is RecoveryRunFault.SUPPRESS_BEFORE_DISPATCH
                )
            )
        except Exception:
            timeline.append(
                RecoveryTimelineEntry(
                    sequence=3,
                    node_id="record",
                    event="blind-abort",
                    detail="The baseline aborted after a missing release-record response.",
                )
            )
            return BlindPolicyOutcome(
                chain_completed=False,
                provider_contacts=provider_contacts,
                timeline=tuple(timeline),
            )
        provider_contacts += 1
        timeline.append(
            RecoveryTimelineEntry(
                sequence=3,
                node_id="record",
                event="acknowledged",
                detail="The baseline received the release-record acknowledgement.",
            )
        )
        return BlindPolicyOutcome(
            chain_completed=True,
            provider_contacts=provider_contacts,
            timeline=tuple(timeline),
        )


@dataclass(frozen=True, slots=True)
class RecoveryExperimentBinding:
    target_sha256: str
    input_intent_sha256: str
    fault_boundary_sha256: str
    observation_catalog_sha256: str


def recovery_experiment_binding(
    settings: ReleaseChainSettings,
    fault: RecoveryRunFault,
) -> RecoveryExperimentBinding:
    """Seal the four common experiment dimensions before any policy executes."""

    if (
        type(settings) is not ReleaseChainSettings
        or type(fault) is not RecoveryRunFault
    ):
        raise TypeError("recovery experiment binding requires exact inputs")
    targets = {
        "cloud_run": build_cloud_run_target(
            project=settings.project,
            location=settings.location,
            service=settings.service,
        ).model_dump(mode="json"),
        "firestore": build_firestore_release_target(
            project=settings.project,
            database=settings.database,
            document=firestore_release_document_path(settings.release_id),
        ).model_dump(mode="json"),
    }
    intent = {
        "configuration_sha256": settings.configuration_sha256,
        "image_digest": settings.image_digest,
        "payload_sha256": settings.payload_sha256,
        "release_id": settings.release_id,
        "staged_revision": settings.staged_revision,
    }
    boundary = {
        "fault": fault.value,
        "point": (
            "cloud-run-stage-after-provider-accept"
            if fault is RecoveryRunFault.DROP_AFTER_ACCEPT
            else (
                "firestore-record-after-authority-claim-before-provider-contact"
                if fault is RecoveryRunFault.SUPPRESS_BEFORE_DISPATCH
                else "no-injected-fault"
            )
        ),
        "version": "recovery-fault-boundary-v1",
    }
    catalog = {
        "capabilities": [
            CLOUD_RUN_SERVICE_CAPABILITY,
            CLOUD_RUN_REVISION_CAPABILITY,
            CLOUD_RUN_OPERATION_CAPABILITY,
            CLOUD_RUN_HEALTH_CAPABILITY,
            FIRESTORE_RELEASE_CAPABILITY,
            DISPATCH_RECEIPT_CAPABILITY,
        ],
        "version": "recovery-observation-catalog-v1",
    }

    def digest(value: object) -> str:
        return hashlib.sha256(canonical_json_value_bytes(value)).hexdigest()

    return RecoveryExperimentBinding(
        target_sha256=digest(targets),
        input_intent_sha256=digest(intent),
        fault_boundary_sha256=digest(boundary),
        observation_catalog_sha256=digest(catalog),
    )


@dataclass(frozen=True, slots=True)
class RecoveryLaneBaseline:
    """Provider state captured before one isolated policy lane mutates."""

    release_revisions: tuple[str, ...]


class RecoveryPolicyResultRecorder:
    """Build one comparison lane from durable state and fresh provider reads."""

    def __init__(
        self,
        *,
        settings: ReleaseChainSettings,
        baseline_revision: str,
        cloud_reader: CloudRunCanaryReader,
        firestore: GoogleFirestoreReleaseTarget,
    ) -> None:
        if type(settings) is not ReleaseChainSettings:
            raise TypeError("policy recorder requires exact release settings")
        if type(cloud_reader) is not CloudRunCanaryReader:
            raise TypeError("policy recorder requires the sealed Cloud Run reader")
        if type(firestore) is not GoogleFirestoreReleaseTarget:
            raise TypeError("policy recorder requires the sealed Firestore target")
        if type(baseline_revision) is not str or not baseline_revision:
            raise ValueError("policy recorder baseline revision is invalid")
        target = _require_cloud_target(settings, cloud_reader)
        _require_firestore_target(settings, firestore)
        if baseline_revision != target.baseline_revision:
            raise ValueError("policy recorder baseline differs from the sealed target")
        self._settings = settings
        self._baseline_revision = baseline_revision
        self._cloud_reader = cloud_reader
        self._firestore = firestore

    async def capture_baseline(self) -> RecoveryLaneBaseline:
        revisions = await asyncio.to_thread(
            self._cloud_reader.list_release_revisions,
            release_id=self._settings.release_id,
            image_digest=self._settings.image_digest,
            configuration_sha256=self._settings.configuration_sha256,
        )
        service = await asyncio.to_thread(
            self._cloud_reader.read_service,
            release_id=self._settings.release_id,
            revision=self._baseline_revision,
        )
        record = await self._firestore.read(self._settings.release_id)
        if service.revision_traffic_percent != 100 or record is not None:
            raise ReleaseChainError("policy lane did not start from the safe baseline")
        if revisions:
            raise ReleaseChainError(
                "policy lane requires a freshly reprovisioned Cloud Run target"
            )
        return RecoveryLaneBaseline(release_revisions=())

    @staticmethod
    def _validate_binding(
        settings: ReleaseChainSettings,
        fault: RecoveryRunFault,
        binding: RecoveryExperimentBinding,
    ) -> None:
        if binding != recovery_experiment_binding(settings, fault):
            raise ReleaseChainError("policy result changed the sealed experiment")

    async def _observe_provider(
        self,
        baseline: RecoveryLaneBaseline,
    ) -> tuple[
        RecoveryCloudRunObservation, RecoveryFirestoreObservation, int, int, int
    ]:
        if type(baseline) is not RecoveryLaneBaseline:
            raise TypeError("policy result requires an exact baseline")
        revisions = await asyncio.to_thread(
            self._cloud_reader.list_release_revisions,
            release_id=self._settings.release_id,
            image_digest=self._settings.image_digest,
            configuration_sha256=self._settings.configuration_sha256,
        )
        candidates = tuple(dict.fromkeys((self._baseline_revision, *revisions)))
        services = tuple(
            await asyncio.gather(
                *(
                    asyncio.to_thread(
                        self._cloud_reader.read_service,
                        release_id=self._settings.release_id,
                        revision=revision,
                    )
                    for revision in candidates
                )
            )
        )
        serving = tuple(
            item for item in services if item.revision_traffic_percent == 100
        )
        if len(serving) != 1 or len({item.service_etag for item in services}) != 1:
            raise ReleaseChainError("policy result has ambiguous Cloud Run traffic")
        selected = serving[0]
        record = await self._firestore.read(self._settings.release_id)
        record_action = (
            build_release_chain_definition(
                self._settings,
                invoked_at=datetime(2000, 1, 1, tzinfo=UTC),
            )
            .chain.nodes[-1]
            .semantic_action
        )
        created_revisions = len(set(revisions).difference(baseline.release_revisions))
        promotion_count = int(selected.revision != self._baseline_revision)
        record_count = int(record is not None)
        cloud = RecoveryCloudRunObservation(
            baseline_revision=self._baseline_revision,
            intended_revision=self._settings.staged_revision,
            release_revisions=revisions,
            serving_revision=selected.revision,
            serving_percent=selected.revision_traffic_percent,
            observed_service_etag_sha256=hashlib.sha256(
                selected.service_etag.encode("utf-8")
            ).hexdigest(),
        )
        firestore = RecoveryFirestoreObservation(
            release_id=self._settings.release_id,
            document_path=firestore_release_document_path(self._settings.release_id),
            expected_payload_sha256=self._settings.payload_sha256,
            expected_semantic_action_sha256=record_action.semantic_action_sha256,
            payload_sha256=(None if record is None else record.record.payload_sha256),
            semantic_action_sha256=(
                None if record is None else record.record.semantic_action_sha256
            ),
            exists=record is not None,
            cloud_run_revision=(
                None if record is None else record.record.cloud_run_revision
            ),
        )
        return cloud, firestore, created_revisions, promotion_count, record_count

    @staticmethod
    def _authority_receipts(
        snapshot: RecoveryRunSnapshot,
        *,
        authority_id: str,
        claim_id: str | None,
    ) -> tuple[DurableDispatchReceipt, ...]:
        return tuple(
            receipt
            for receipt in snapshot.dispatch_receipts
            if receipt.authority_id == authority_id and receipt.claim_id == claim_id
        )

    @classmethod
    def _accepted_action_mutation(
        cls,
        snapshot: RecoveryRunSnapshot,
        *,
        target_node_id: str,
        observed_effect: bool,
    ) -> int:
        """Count an accepted mutation from durable authority, not ambient state."""

        permits = tuple(
            permit
            for permit in snapshot.action_permits
            if permit.target_node_id == target_node_id
        )

        def dispatch_receipts(
            permit: ActionPermit,
        ) -> tuple[DurableDispatchReceipt, ...]:
            return cls._authority_receipts(
                snapshot,
                authority_id=permit.permit_id,
                claim_id=permit.claim_id,
            )

        # The provider call precedes receipt persistence. A process can therefore
        # leave exact claimed authority and its exact effect without a receipt.
        return int(
            any(
                (
                    permit.state is ActionPermitState.COMPLETED
                    and (
                        permit.completion_outcome is PermitCompletionOutcome.SUCCEEDED
                        or (
                            permit.completion_outcome
                            is PermitCompletionOutcome.OUTCOME_UNKNOWN
                            and observed_effect
                            and any(
                                receipt.provider_contact
                                for receipt in dispatch_receipts(permit)
                            )
                        )
                    )
                )
                or (
                    permit.state is ActionPermitState.CLAIMED
                    and observed_effect
                    and (
                        not dispatch_receipts(permit)
                        or any(
                            receipt.provider_contact
                            for receipt in dispatch_receipts(permit)
                        )
                    )
                )
                for permit in permits
            )
        )

    @classmethod
    def _proof_mutation_counters(
        cls,
        snapshot: RecoveryRunSnapshot,
        cloud: RecoveryCloudRunObservation,
        firestore: RecoveryFirestoreObservation,
    ) -> tuple[int, int, int, int]:
        staged = cloud.intended_revision in cloud.release_revisions
        launch = snapshot.launch_permit
        launch_receipts = (
            ()
            if launch is None
            else cls._authority_receipts(
                snapshot,
                authority_id=launch.launch_permit_id,
                claim_id=launch.claim_id,
            )
        )
        launch_contacted = any(receipt.provider_contact for receipt in launch_receipts)
        # As with action permits, a claimed launch plus its exact effect spans the
        # unavoidable provider-return/receipt-persistence crash boundary.
        revisions_created = int(
            launch is not None
            and (
                (
                    launch.state is RecoveryLaunchPermitState.COMPLETED
                    and (
                        launch.outcome is RecoveryDispatchOutcome.SUCCEEDED
                        or (
                            launch.outcome is RecoveryDispatchOutcome.OUTCOME_UNKNOWN
                            and staged
                            and launch_contacted
                        )
                    )
                )
                or (
                    launch.state is RecoveryLaunchPermitState.CLAIMED
                    and staged
                    and (
                        not launch_receipts
                        or any(receipt.provider_contact for receipt in launch_receipts)
                    )
                )
            )
        )
        promoted = (
            cloud.serving_percent == 100
            and cloud.serving_revision == cloud.intended_revision
        )
        exact_record = (
            firestore.exists
            and firestore.cloud_run_revision == cloud.intended_revision
            and firestore.payload_sha256 == firestore.expected_payload_sha256
            and firestore.semantic_action_sha256
            == firestore.expected_semantic_action_sha256
        )
        promotions_accepted = cls._accepted_action_mutation(
            snapshot,
            target_node_id="promote",
            observed_effect=promoted,
        )
        release_records_created = cls._accepted_action_mutation(
            snapshot,
            target_node_id="record",
            observed_effect=exact_record,
        )
        observed_effects = {
            "stage": staged,
            "promote": promoted,
            "record": exact_record,
        }
        inferred_contacts = int(
            launch is not None
            and launch.state is RecoveryLaunchPermitState.CLAIMED
            and staged
            and not launch_receipts
        ) + sum(
            permit.state is ActionPermitState.CLAIMED
            and observed_effects.get(permit.target_node_id, False)
            and not cls._authority_receipts(
                snapshot,
                authority_id=permit.permit_id,
                claim_id=permit.claim_id,
            )
            for permit in snapshot.action_permits
        )
        provider_contacts = (
            sum(receipt.provider_contact for receipt in snapshot.dispatch_receipts)
            + inferred_contacts
        )
        return (
            revisions_created,
            promotions_accepted,
            release_records_created,
            provider_contacts,
        )

    @staticmethod
    def _event_node(event: RecoveryRunEvent) -> str:
        payload = event.payload
        for value in (
            payload.node,
            payload.dispatch_receipt,
            payload.launch_permit,
            payload.certificate,
            payload.witness,
            payload.hypothesis,
        ):
            node_id = getattr(value, "node_id", None)
            if type(node_id) is str and node_id:
                return node_id
        if payload.action_permit is not None:
            return payload.action_permit.source_node_id
        return "run"

    @classmethod
    def _timeline(
        cls,
        events: RecoveryRunEventSnapshot,
    ) -> tuple[RecoveryTimelineEntry, ...]:
        if len(events.events) > 256:
            raise ReleaseChainError("policy timeline exceeds the public bound")
        return tuple(
            RecoveryTimelineEntry(
                sequence=index,
                node_id=cls._event_node(event),
                event=event.type.value,
                detail="A durable recovery event advanced the isolated policy lane.",
            )
            for index, event in enumerate(events.events, start=1)
        )

    async def record_blind(
        self,
        *,
        run_id: str,
        policy: RecoveryRunPolicy,
        fault: RecoveryRunFault,
        binding: RecoveryExperimentBinding,
        baseline: RecoveryLaneBaseline,
        outcome: BlindPolicyOutcome,
    ) -> RecoveryPolicyResult:
        if (
            policy
            not in {
                RecoveryRunPolicy.BLIND_RETRY,
                RecoveryRunPolicy.BLIND_ABORT,
            }
            or type(outcome) is not BlindPolicyOutcome
        ):
            raise TypeError("blind result requires an isolated baseline outcome")
        self._validate_binding(self._settings, fault, binding)
        cloud, firestore, revisions, promotions, records = await self._observe_provider(
            baseline
        )
        chain_completed = outcome.chain_completed and (
            cloud.serving_percent == 100
            and cloud.serving_revision in cloud.release_revisions
            and firestore.exists
            and firestore.cloud_run_revision == cloud.serving_revision
            and firestore.payload_sha256 == firestore.expected_payload_sha256
            and firestore.semantic_action_sha256
            == firestore.expected_semantic_action_sha256
        )
        return RecoveryPolicyResult(
            schema_version=RECOVERY_POLICY_RESULT_VERSION,
            run_id=run_id,
            policy=policy.value,
            fault=fault.value,
            target_sha256=binding.target_sha256,
            input_intent_sha256=binding.input_intent_sha256,
            fault_boundary_sha256=binding.fault_boundary_sha256,
            observation_catalog_sha256=binding.observation_catalog_sha256,
            chain_completed=chain_completed,
            terminal_disposition=("COMPLETED" if chain_completed else "ABORTED"),
            counters=RecoveryMutationCounters(
                revisions_created=revisions,
                promotions_accepted=promotions,
                release_records_created=records,
                provider_contacts=outcome.provider_contacts,
                continue_permits_issued=0,
                retry_permits_issued=0,
                retry_permits_consumed=0,
                action_permits_consumed=0,
            ),
            cloud_run=cloud,
            firestore=firestore,
            dispatch_receipts=(),
            timeline=outcome.timeline,
            certificate_sha256s=(),
            witness_sha256s=(),
        )

    async def record_proof(
        self,
        *,
        snapshot: RecoveryRunSnapshot,
        events: RecoveryRunEventSnapshot,
        binding: RecoveryExperimentBinding,
        baseline: RecoveryLaneBaseline,
    ) -> RecoveryPolicyResult:
        if (
            type(snapshot) is not RecoveryRunSnapshot
            or type(events) is not RecoveryRunEventSnapshot
            or snapshot.request.policy
            not in {RecoveryRunPolicy.FIXED, RecoveryRunPolicy.ADAPTIVE}
            or snapshot.lifecycle
            not in {RecoveryRunLifecycle.COMPLETED, RecoveryRunLifecycle.ESCALATED}
            or events.run_id != snapshot.request.run_id
            or events.cursor != snapshot.event_cursor
        ):
            raise TypeError("proof result requires one terminal durable recovery run")
        fault = snapshot.request.fault
        self._validate_binding(self._settings, fault, binding)
        (
            cloud,
            firestore,
            _revisions,
            _promotions,
            _records,
        ) = await self._observe_provider(baseline)
        revisions, promotions, records, provider_contacts = (
            self._proof_mutation_counters(
                snapshot,
                cloud,
                firestore,
            )
        )
        permits = snapshot.action_permits
        retry_permits = tuple(
            permit for permit in permits if permit.action is PermitAction.RETRY
        )
        consumed = tuple(
            permit
            for permit in permits
            if permit.state in {ActionPermitState.CLAIMED, ActionPermitState.COMPLETED}
        )
        retry_consumed = tuple(
            permit
            for permit in retry_permits
            if permit.state in {ActionPermitState.CLAIMED, ActionPermitState.COMPLETED}
        )
        return RecoveryPolicyResult(
            schema_version=RECOVERY_POLICY_RESULT_VERSION,
            run_id=snapshot.request.run_id,
            policy=snapshot.request.policy.value,
            fault=fault.value,
            target_sha256=binding.target_sha256,
            input_intent_sha256=binding.input_intent_sha256,
            fault_boundary_sha256=binding.fault_boundary_sha256,
            observation_catalog_sha256=binding.observation_catalog_sha256,
            chain_completed=snapshot.lifecycle is RecoveryRunLifecycle.COMPLETED,
            terminal_disposition=(
                "COMPLETED"
                if snapshot.lifecycle is RecoveryRunLifecycle.COMPLETED
                else "ESCALATED"
            ),
            counters=RecoveryMutationCounters(
                revisions_created=revisions,
                promotions_accepted=promotions,
                release_records_created=records,
                provider_contacts=provider_contacts,
                continue_permits_issued=sum(
                    permit.action is PermitAction.CONTINUE for permit in permits
                ),
                retry_permits_issued=len(retry_permits),
                retry_permits_consumed=len(retry_consumed),
                action_permits_consumed=len(consumed),
            ),
            cloud_run=cloud,
            firestore=firestore,
            dispatch_receipts=snapshot.dispatch_receipts,
            timeline=self._timeline(events),
            certificate_sha256s=tuple(
                canonical_sha256(certificate) for certificate in snapshot.certificates
            ),
            witness_sha256s=tuple(
                canonical_sha256(witness) for witness in snapshot.witnesses
            ),
        )


@dataclass(frozen=True, slots=True)
class ReleaseChainLaneResources:
    """Fresh physical resources for one logically equivalent policy lane."""

    store: RecoveryRunStore
    permit_authority: PermitAuthority
    recovery_agent: object
    cloud_action: object
    cloud_reader: CloudRunCanaryReader
    firestore: GoogleFirestoreReleaseTarget
    baseline_revision: str


class ReleaseChainLaneFactory(Protocol):
    def __call__(
        self,
        *,
        policy: RecoveryRunPolicy,
        fault: RecoveryRunFault,
        binding: RecoveryExperimentBinding,
    ) -> ReleaseChainLaneResources | Awaitable[ReleaseChainLaneResources]: ...


class ReleaseChainPolicyLaneExecutor:
    """Execute real baseline or Proof-to-Permit lanes on fresh isolated state.

    Cloud Run revisions are immutable. A factory boundary is therefore mandatory:
    every lane receives an externally reprovisioned same-name canary while the
    constructor and recorder reject any drift in the logical target, input, fault,
    or observation catalog. Reset restores mutable effects and honestly retains
    immutable revision residue; automated reprovisioning belongs to issue #173.
    """

    def __init__(
        self,
        *,
        settings: ReleaseChainSettings,
        invoked_at: datetime,
        lane_factory: ReleaseChainLaneFactory,
        clock: Callable[[], datetime] | None = None,
        reset_observations: int = 60,
        reset_poll_interval_seconds: float = 0.5,
        sleep: Callable[[float], Awaitable[None]] = asyncio.sleep,
    ) -> None:
        if type(settings) is not ReleaseChainSettings:
            raise TypeError("policy lane executor requires exact release settings")
        if invoked_at.tzinfo is None or invoked_at.utcoffset() is None:
            raise ValueError("policy lane invocation time must be aware")
        if not callable(lane_factory) or not callable(clock or datetime.now):
            raise TypeError("policy lane executor factories must be callable")
        self._settings = settings
        self._invoked_at = invoked_at.astimezone(UTC)
        self._factory = lane_factory
        self._clock = clock or (lambda: datetime.now(UTC))
        self._reset_observations = reset_observations
        self._reset_poll_interval_seconds = reset_poll_interval_seconds
        self._sleep = sleep
        self._pending_resetter: ReleaseChainResetter | None = None
        self._retained_resources: list[ReleaseChainLaneResources] = []

    @staticmethod
    def _validate_resources(resources: object) -> ReleaseChainLaneResources:
        if type(resources) is not ReleaseChainLaneResources:
            raise TypeError("policy lane factory returned invalid resources")
        if not isinstance(resources.store, RecoveryRunStore):
            raise TypeError("policy lane requires a recovery store")
        if type(resources.permit_authority) is not PermitAuthority:
            raise TypeError("policy lane requires a permit authority")
        return resources

    def _run_id(
        self,
        policy: RecoveryRunPolicy,
        fault: RecoveryRunFault,
        binding: RecoveryExperimentBinding,
        *,
        execution_id: str | None = None,
    ) -> str:
        if execution_id is not None and (
            type(execution_id) is not str or not 1 <= len(execution_id) <= 128
        ):
            raise ValueError("policy lane execution identity is invalid")
        digest = hashlib.sha256(
            canonical_json_value_bytes(
                {
                    "execution_id": execution_id or self._invoked_at.isoformat(),
                    "fault": fault.value,
                    "input_intent_sha256": binding.input_intent_sha256,
                    "policy": policy.value,
                    "target_sha256": binding.target_sha256,
                }
            )
        ).hexdigest()[:24]
        return f"lane-{policy.value}-{digest}"

    async def execute(
        self,
        *,
        policy: str,
        fault: RecoveryRunFault,
        binding: RecoveryExperimentBinding,
        execution_id: str | None = None,
    ) -> RecoveryPolicyResult:
        if self._pending_resetter is not None:
            raise ReleaseChainError("previous policy lane has not been reset")
        try:
            selected_policy = RecoveryRunPolicy(policy)
        except (TypeError, ValueError):
            raise ValueError("policy lane is unsupported") from None
        if type(fault) is not RecoveryRunFault:
            raise TypeError("policy lane fault must be exact")
        RecoveryPolicyResultRecorder._validate_binding(
            self._settings,
            fault,
            binding,
        )
        resources_value = self._factory(
            policy=selected_policy,
            fault=fault,
            binding=binding,
        )
        if inspect.isawaitable(resources_value):
            resources_value = await resources_value
        resources = self._validate_resources(resources_value)
        resource_ids = {
            id(resources.store),
            id(resources.permit_authority),
            id(resources.recovery_agent),
            id(resources.cloud_action),
            id(resources.cloud_reader),
            id(resources.firestore),
        }
        if any(
            resource_ids
            & {
                id(existing.store),
                id(existing.permit_authority),
                id(existing.recovery_agent),
                id(existing.cloud_action),
                id(existing.cloud_reader),
                id(existing.firestore),
            }
            for existing in self._retained_resources
        ):
            raise ReleaseChainError("policy lanes must use fresh physical resources")
        self._retained_resources.append(resources)
        self._pending_resetter = ReleaseChainResetter(
            settings=self._settings,
            cloud_action=resources.cloud_action,
            cloud_reader=resources.cloud_reader,
            firestore=resources.firestore,
            baseline_revision=resources.baseline_revision,
            clock=self._clock,
            max_observations=self._reset_observations,
            poll_interval_seconds=self._reset_poll_interval_seconds,
            sleep=self._sleep,
        )
        recorder = RecoveryPolicyResultRecorder(
            settings=self._settings,
            baseline_revision=resources.baseline_revision,
            cloud_reader=resources.cloud_reader,
            firestore=resources.firestore,
        )
        run_id = self._run_id(
            selected_policy,
            fault,
            binding,
            execution_id=execution_id,
        )
        if selected_policy in {
            RecoveryRunPolicy.BLIND_RETRY,
            RecoveryRunPolicy.BLIND_ABORT,
        }:
            baseline = await recorder.capture_baseline()
            mutator = ReleaseChainBlindMutator(
                settings=self._settings,
                cloud_action=resources.cloud_action,
                cloud_reader=resources.cloud_reader,
                firestore=resources.firestore,
                invoked_at=self._invoked_at,
                clock=self._clock,
            )
            baseline_executor = BlindPolicyExecutor(mutator)
            outcome = (
                await baseline_executor.blind_retry(
                    operation_id=self._settings.stage_operation_id,
                    fault=fault,
                )
                if selected_policy is RecoveryRunPolicy.BLIND_RETRY
                else await baseline_executor.blind_abort(
                    operation_id=self._settings.stage_operation_id,
                    fault=fault,
                )
            )
            return await recorder.record_blind(
                run_id=run_id,
                policy=selected_policy,
                fault=fault,
                binding=binding,
                baseline=baseline,
                outcome=outcome,
            )

        request = RecoveryRunRequest(
            schema_version=RECOVERY_RUN_REQUEST_VERSION,
            run_id=run_id,
            scenario="cloud-run-rollout",
            policy=selected_policy,
            fault=fault,
        )
        workflow = build_release_chain_workflow(
            settings=self._settings,
            invoked_at=self._invoked_at,
            store=resources.store,
            permit_authority=resources.permit_authority,
            recovery_agent=resources.recovery_agent,
            cloud_action=resources.cloud_action,
            cloud_reader=resources.cloud_reader,
            firestore=resources.firestore,
            clock=self._clock,
        )
        definition = await workflow.definition(request)
        try:
            await resources.store.get(run_id)
        except RecoveryRunNotFound:
            baseline = await recorder.capture_baseline()
            _snapshot, created = await resources.store.create(
                request,
                definition.chain,
                created_at=self._invoked_at,
            )
            if not created:
                raise ReleaseChainError(
                    "policy lane was created concurrently"
                ) from None
        else:
            existing, created = await resources.store.create(
                request,
                definition.chain,
                created_at=self._invoked_at,
            )
            if created:
                raise ReleaseChainError("policy lane recovery state changed")
            if existing.lifecycle in {
                RecoveryRunLifecycle.COMPLETED,
                RecoveryRunLifecycle.ESCALATED,
                RecoveryRunLifecycle.FAILED,
                RecoveryRunLifecycle.CANCELLED,
            }:
                raise ReleaseChainError("terminal policy lane cannot be resumed")
            launch = existing.launch_permit
            progressed = bool(
                launch is not None
                and launch.state
                in {
                    RecoveryLaunchPermitState.CLAIMED,
                    RecoveryLaunchPermitState.COMPLETED,
                }
            )
            baseline = (
                RecoveryLaneBaseline(release_revisions=())
                if progressed
                else await recorder.capture_baseline()
            )
        snapshot = await workflow.run(run_id)
        events = await resources.store.events(run_id)
        return await recorder.record_proof(
            snapshot=snapshot,
            events=events,
            binding=binding,
            baseline=baseline,
        )

    async def reset(self) -> RecoveryResetResult:
        resetter = self._pending_resetter
        if resetter is None:
            raise ReleaseChainError("policy lane has no state to reset")
        result = await resetter.reset()
        self._pending_resetter = None
        return result


class RecoveryPolicyLaneExecutor(Protocol):
    async def execute(
        self,
        *,
        policy: str,
        fault: RecoveryRunFault,
        binding: RecoveryExperimentBinding,
        execution_id: str | None = None,
    ) -> RecoveryPolicyResult: ...


class RecoveryResetExecutor(Protocol):
    async def reset(self) -> RecoveryResetResult: ...


class RecoveryPolicyComparisonRunner:
    """Run isolated policy lanes under one sealed experiment and reset each lane."""

    _POLICIES = ("blind-retry", "blind-abort", "fixed", "adaptive")

    def __init__(
        self,
        *,
        settings: ReleaseChainSettings,
        lane_executor: RecoveryPolicyLaneExecutor,
        resetter: RecoveryResetExecutor,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        if not callable(getattr(lane_executor, "execute", None)):
            raise TypeError("comparison runner requires a lane executor")
        if not callable(getattr(resetter, "reset", None)):
            raise TypeError("comparison runner requires a reset executor")
        self._settings = settings
        self._lanes = lane_executor
        self._resetter = resetter
        self._clock = clock or (lambda: datetime.now(UTC))

    async def run(
        self,
        fault: RecoveryRunFault,
        *,
        execution_id: str | None = None,
    ) -> RecoveryPolicyComparison:
        if execution_id is None:
            execution_id = f"execution-{secrets.token_hex(16)}"
        elif type(execution_id) is not str or not 1 <= len(execution_id) <= 128:
            raise ValueError("comparison execution identity is invalid")
        binding = recovery_experiment_binding(self._settings, fault)
        lanes: list[RecoveryPolicyResult] = []
        resets: list[RecoveryResetResult] = []
        for policy in self._POLICIES:
            try:
                result = await self._lanes.execute(
                    policy=policy,
                    fault=fault,
                    binding=binding,
                    execution_id=execution_id,
                )
                if type(result) is not RecoveryPolicyResult or (
                    result.policy,
                    result.fault,
                    result.target_sha256,
                    result.input_intent_sha256,
                    result.fault_boundary_sha256,
                    result.observation_catalog_sha256,
                ) != (
                    policy,
                    fault.value,
                    binding.target_sha256,
                    binding.input_intent_sha256,
                    binding.fault_boundary_sha256,
                    binding.observation_catalog_sha256,
                ):
                    raise ReleaseChainError("policy lane changed its sealed experiment")
                lanes.append(result)
            finally:
                reset = await self._resetter.reset()
            if type(reset) is not RecoveryResetResult:
                raise ReleaseChainError("policy lane reset returned an invalid result")
            resets.append(reset)
        created_at = self._clock()
        if created_at.tzinfo is None or created_at.utcoffset() is None:
            raise ReleaseChainError("comparison clock is invalid")
        comparison_id = (
            "comparison-"
            + hashlib.sha256(
                canonical_json_value_bytes(
                    {
                        "fault": fault.value,
                        "input_intent_sha256": binding.input_intent_sha256,
                        "execution_id": execution_id,
                        "release_id": self._settings.release_id,
                        "run_ids": [lane.run_id for lane in lanes],
                        "target_sha256": binding.target_sha256,
                    }
                )
            ).hexdigest()[:32]
        )
        return RecoveryPolicyComparison(
            schema_version=RECOVERY_POLICY_COMPARISON_VERSION,
            comparison_id=comparison_id,
            release_id=self._settings.release_id,
            fault=fault.value,
            target_sha256=binding.target_sha256,
            input_intent_sha256=binding.input_intent_sha256,
            fault_boundary_sha256=binding.fault_boundary_sha256,
            observation_catalog_sha256=binding.observation_catalog_sha256,
            lanes=tuple(lanes),  # type: ignore[arg-type]
            reset_results=tuple(resets),  # type: ignore[arg-type]
            created_at=created_at.astimezone(UTC),
        )


class ReleaseChainResetter:
    """Reset exact mutable effects while reporting immutable revision residue."""

    def __init__(
        self,
        *,
        settings: ReleaseChainSettings,
        cloud_action: object,
        cloud_reader: CloudRunCanaryReader,
        firestore: GoogleFirestoreReleaseTarget,
        baseline_revision: str,
        clock: Callable[[], datetime] | None = None,
        max_observations: int = 60,
        poll_interval_seconds: float = 0.5,
        sleep: Callable[[float], Awaitable[None]] = asyncio.sleep,
    ) -> None:
        if not callable(getattr(cloud_action, "reset", None)):
            raise TypeError("release reset requires a Cloud Run reset boundary")
        if type(cloud_reader) is not CloudRunCanaryReader:
            raise TypeError("release reset requires the sealed Cloud Run reader")
        if type(firestore) is not GoogleFirestoreReleaseTarget:
            raise TypeError("release reset requires the sealed Firestore target")
        if type(settings) is not ReleaseChainSettings:
            raise TypeError("release reset requires exact release settings")
        if (
            type(max_observations) is not int
            or not 1 <= max_observations <= 120
            or type(poll_interval_seconds) not in {int, float}
            or not 0 <= float(poll_interval_seconds) <= 5
            or not callable(sleep)
        ):
            raise ValueError("release reset observation policy is invalid")
        action_target = _require_cloud_target(settings, cloud_action)
        reader_target = _require_cloud_target(settings, cloud_reader)
        _require_firestore_target(settings, firestore)
        if action_target != reader_target:
            raise ValueError("Cloud Run reset and evidence targets differ")
        if baseline_revision != action_target.baseline_revision:
            raise ValueError("release reset baseline differs from the sealed target")
        self._settings = settings
        self._cloud_action = cloud_action
        self._cloud_reader = cloud_reader
        self._firestore = firestore
        self._baseline = baseline_revision
        self._clock = clock or (lambda: datetime.now(UTC))
        self._max_observations = max_observations
        self._poll_interval_seconds = float(poll_interval_seconds)
        self._sleep = sleep

    async def _reset_cloud_run(self) -> object:
        if type(self._cloud_action) is CloudRunCanaryFaultProxy:
            return await _invoke_provider(
                self._cloud_action.reset,
                mode=CloudRunFaultMode.PASS_THROUGH,
            )
        if type(self._cloud_action) is CloudRunCanaryActionAdapter:
            return await _invoke_provider(self._cloud_action.reset)
        reset = getattr(self._cloud_action, "reset", None)
        if not callable(reset):  # pragma: no cover - constructor guards this
            raise ReleaseChainError("Cloud Run reset boundary is unavailable")
        try:
            accepts_mode = "mode" in inspect.signature(reset).parameters
        except (TypeError, ValueError):
            raise ReleaseChainError("Cloud Run reset boundary is invalid") from None
        return await _invoke_provider(
            reset,
            **({"mode": CloudRunFaultMode.PASS_THROUGH} if accepts_mode else {}),
        )

    async def _wait_for_baseline(
        self,
        *,
        previous_service_etag: str,
        previous_generation: int,
    ):
        latest = None
        for observation in range(self._max_observations):
            try:
                latest = await asyncio.to_thread(
                    self._cloud_reader.read_service,
                    release_id=self._settings.release_id,
                    revision=self._baseline,
                )
            except CloudRunCanaryError:
                latest = None
            if (
                latest is not None
                and latest.revision == self._baseline
                and latest.revision_traffic_percent == 100
                and not latest.reconciling
                and latest.terminal_condition == "SUCCEEDED"
                and latest.service_etag != previous_service_etag
                and latest.generation > previous_generation
                and latest.observed_generation >= latest.generation
            ):
                return latest
            if observation + 1 < self._max_observations:
                await self._sleep(self._poll_interval_seconds)
        raise ReleaseChainError("Cloud Run reset did not reach the safe baseline")

    async def reset(self) -> RecoveryResetResult:
        before = await asyncio.to_thread(
            self._cloud_reader.list_release_revisions,
            release_id=self._settings.release_id,
            image_digest=self._settings.image_digest,
            configuration_sha256=self._settings.configuration_sha256,
        )
        previous = await asyncio.to_thread(
            self._cloud_reader.read_service,
            release_id=self._settings.release_id,
            revision=self._baseline,
        )
        accepted = await self._reset_cloud_run()
        operation_name = getattr(accepted, "operation_name", None)
        accepted_revision = getattr(accepted, "revision", None)
        accepted_service_etag = getattr(accepted, "service_etag", None)
        accepted_at = getattr(accepted, "accepted_at", None)
        if (
            type(operation_name) is not str
            or not operation_name
            or accepted_revision != self._baseline
            or type(accepted_service_etag) is not str
            or not accepted_service_etag
            or accepted_service_etag != previous.service_etag
            or type(accepted_at) is not datetime
            or accepted_at.tzinfo is None
            or accepted_at.utcoffset() is None
        ):
            raise ReleaseChainError("Cloud Run reset acceptance is invalid")
        service = await self._wait_for_baseline(
            previous_service_etag=previous.service_etag,
            previous_generation=previous.generation,
        )
        record_action = (
            build_release_chain_definition(
                self._settings,
                invoked_at=datetime(2000, 1, 1, tzinfo=UTC),
            )
            .chain.nodes[-1]
            .semantic_action
        )
        await self._firestore.reset(
            release_id=self._settings.release_id,
            cloud_run_revisions=before,
            payload_sha256=self._settings.payload_sha256,
            semantic_action_sha256=record_action.semantic_action_sha256,
        )
        after = await asyncio.to_thread(
            self._cloud_reader.list_release_revisions,
            release_id=self._settings.release_id,
            image_digest=self._settings.image_digest,
            configuration_sha256=self._settings.configuration_sha256,
        )
        absent = await self._firestore.read(self._settings.release_id) is None
        verified_at = self._clock()
        if verified_at.tzinfo is None or verified_at.utcoffset() is None:
            raise ReleaseChainError("release reset clock is invalid")
        return RecoveryResetResult(
            schema_version=RECOVERY_RESET_RESULT_VERSION,
            release_id=self._settings.release_id,
            baseline_revision=self._baseline,
            serving_revision=service.revision,
            serving_percent=service.revision_traffic_percent,
            release_record_absent=absent,
            release_revisions_before=before,
            release_revisions_after=after,
            reset_operation_name_sha256=hashlib.sha256(
                operation_name.encode()
            ).hexdigest(),
            verified_at=verified_at.astimezone(UTC),
        )


def export_recovery_comparison(path: str | Path, comparison: object) -> str:
    """Write one canonical, secret-free comparison exactly once."""

    from reconcile.contracts import RecoveryPolicyComparison

    if type(comparison) is not RecoveryPolicyComparison:
        raise TypeError("recovery comparison export requires the public contract")
    target = Path(path)
    if not target.name or not target.parent.is_dir() or target.is_symlink():
        raise ValueError("recovery comparison export path is invalid")
    public_value = comparison.model_dump(mode="json")
    reject_sensitive_keys(public_value)
    reject_sensitive_values(public_value)
    payload = canonical_json_value_bytes(public_value)
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{target.name}.",
        suffix=".tmp",
        dir=target.parent,
    )
    temporary = Path(temporary_name)
    owned_identity: tuple[int, int] | None = None
    linked = False
    try:
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "wb") as output:
            descriptor = -1
            output.write(payload)
            output.flush()
            os.fsync(output.fileno())
        temporary_stat = temporary.stat(follow_symlinks=False)
        owned_identity = (temporary_stat.st_dev, temporary_stat.st_ino)
        os.link(temporary, target, follow_symlinks=False)
        linked = True
        directory = os.open(target.parent, os.O_RDONLY)
        try:
            os.fsync(directory)
            temporary.unlink()
            temporary = None
            os.fsync(directory)
        finally:
            os.close(directory)
    except BaseException:
        if linked:
            try:
                target_stat = target.stat(follow_symlinks=False)
                if owned_identity == (target_stat.st_dev, target_stat.st_ino):
                    target.unlink()
            except (FileNotFoundError, OSError):
                pass
        raise
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        if temporary is not None:
            try:
                temporary.unlink()
            except FileNotFoundError:
                pass
    return hashlib.sha256(payload).hexdigest()


class _WallClock:
    def __init__(self, now: Callable[[], datetime] | None = None) -> None:
        self._now = now or (lambda: datetime.now(UTC))

    def monotonic(self) -> float:
        return time.monotonic()

    def now(self) -> datetime:
        value = self._now()
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("recovery evidence clock is invalid")
        return value.astimezone(UTC)


__all__ = [
    "RECOVERY_SCENARIO_VERSION",
    "BlindPolicyExecutor",
    "BlindPolicyOutcome",
    "BlindReleaseMutator",
    "RecoveryExperimentBinding",
    "RecoveryLaneBaseline",
    "RecoveryPolicyComparisonRunner",
    "RecoveryPolicyLaneExecutor",
    "RecoveryPolicyResultRecorder",
    "RecoveryResetExecutor",
    "RecoveryRunReceiptReader",
    "ReleaseChainActionPreparer",
    "ReleaseChainBlindMutator",
    "ReleaseChainDispatchGateway",
    "ReleaseChainError",
    "ReleaseChainEvidenceSource",
    "ReleaseChainLaneFactory",
    "ReleaseChainLaneResources",
    "ReleaseChainPolicyLaneExecutor",
    "ReleaseChainResetter",
    "ReleaseChainSettings",
    "build_release_chain_definition",
    "build_release_chain_workflow",
    "export_recovery_comparison",
    "recovery_experiment_binding",
]
