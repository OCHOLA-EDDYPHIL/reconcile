"""Deterministic proof-to-certificate recovery behavior."""

from __future__ import annotations

import asyncio
import hashlib
import inspect
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

import pytest

from reconcile.contracts import (
    AMBIGUITY_WITNESS_VERSION,
    EXECUTION_ENVELOPE_VERSION,
    EXPECTED_EFFECT_VERSION,
    OBSERVATION_CAPABILITY_VERSION,
    PROBE_REQUEST_VERSION,
    RECOVERY_CHAIN_VERSION,
    AmbiguityKind,
    AmbiguousExecution,
    CapabilityRef,
    Classification,
    EffectAssertion,
    EffectAssertionState,
    EnvelopeContext,
    EvidenceBudget,
    ExecutionEnvelope,
    ExecutionEnvelopeReference,
    ExpectedEffect,
    FreshnessPolicy,
    InvestigationReport,
    ObservationCapability,
    OperationStatus,
    OriginalInvocation,
    PermitAction,
    PolicyReferences,
    ProbeRequest,
    RecoveryActionNode,
    RecoveryChain,
    SemanticActionIdentity,
    TargetBinding,
    VerifiedCertificate,
    canonical_sha256,
    semantic_action_sha256,
)
from reconcile.contracts.base import canonical_json_value_bytes
from reconcile.controller import (
    BoundProbe,
    CapabilityRegistration,
    CapabilityRegistry,
    CapabilitySemantics,
    ControllerAuditRecord,
    ProbeController,
    ProbeObservation,
)
from reconcile.evidence import (
    CLOUD_RUN_SERVICE_TARGET_KIND,
    CREATE_FIRESTORE_RELEASE_RECORD_PROFILE_VERSION,
    FIRESTORE_DOCUMENT_TARGET_KIND,
    PROMOTE_CLOUD_RUN_TRAFFIC_PROFILE_VERSION,
    RECOVERY_CHAIN_PROFILE_VERSION,
    RECOVERY_TOOL_VERSION,
    STAGE_CLOUD_RUN_REVISION_PROFILE_VERSION,
    CoreEvaluation,
    EvidenceEngine,
    ProbeRun,
    RecoveryVerificationError,
    RecoveryVerificationResult,
    RuleInput,
    RuleObservation,
    RuleVerdict,
    TargetRuleDescriptor,
    TargetRuleRegistration,
    TargetRuleRegistry,
    verify_recovery,
)
from reconcile.evidence.recovery_rules import (
    CLOUD_RUN_HEALTH_ADAPTER_VERSION,
    CLOUD_RUN_HEALTH_OBSERVATION_VERSION,
    CLOUD_RUN_HEALTH_SOURCE,
    CLOUD_RUN_OPERATION_OBSERVATION_VERSION,
    CLOUD_RUN_PROVIDER_ADAPTER_VERSION,
    CLOUD_RUN_PROVIDER_SOURCE,
    CLOUD_RUN_REVISION_OBSERVATION_VERSION,
    CLOUD_RUN_SERVICE_OBSERVATION_VERSION,
    DISPATCH_RECEIPT_ADAPTER_VERSION,
    DISPATCH_RECEIPT_OBSERVATION_VERSION,
    DISPATCH_RECEIPT_SOURCE,
    FIRESTORE_DOCUMENT_OBSERVATION_VERSION,
    FIRESTORE_PROVIDER_ADAPTER_VERSION,
    FIRESTORE_PROVIDER_SOURCE,
    FIRESTORE_RECORD_EFFECT_SCOPE,
    PROMOTION_TRAFFIC_EFFECT_SCOPE,
    STAGE_READINESS_EFFECT_SCOPE,
    STAGE_REVISION_EFFECT_SCOPE,
    STAGE_TRAFFIC_EFFECT_SCOPE,
)

pytestmark = pytest.mark.unit

NOW = datetime(2026, 8, 22, 12, 0, tzinfo=UTC)
VERIFIED_AT = NOW + timedelta(seconds=6)

_CLOUD_CAPABILITIES = (
    "cloud-run-service-get",
    "cloud-run-revision-get",
    "cloud-run-operation-get",
    "cloud-run-revision-health",
)
_FIRESTORE_CAPABILITIES = (
    "firestore-release-record-get",
    "reconcile-dispatch-receipt-get",
)

RELEASE_ID = "release-7"
REVISION = "reconcile-canary-release-7"
IMAGE_DIGEST = "sha256:" + "a" * 64
CONFIGURATION_SHA256 = "b" * 64
PAYLOAD_SHA256 = "c" * 64

_PROVENANCE = {
    "cloud-run-service-get": (
        CLOUD_RUN_PROVIDER_SOURCE,
        CLOUD_RUN_PROVIDER_ADAPTER_VERSION,
    ),
    "cloud-run-revision-get": (
        CLOUD_RUN_PROVIDER_SOURCE,
        CLOUD_RUN_PROVIDER_ADAPTER_VERSION,
    ),
    "cloud-run-operation-get": (
        CLOUD_RUN_PROVIDER_SOURCE,
        CLOUD_RUN_PROVIDER_ADAPTER_VERSION,
    ),
    "cloud-run-revision-health": (
        CLOUD_RUN_HEALTH_SOURCE,
        CLOUD_RUN_HEALTH_ADAPTER_VERSION,
    ),
    "firestore-release-record-get": (
        FIRESTORE_PROVIDER_SOURCE,
        FIRESTORE_PROVIDER_ADAPTER_VERSION,
    ),
    "reconcile-dispatch-receipt-get": (
        DISPATCH_RECEIPT_SOURCE,
        DISPATCH_RECEIPT_ADAPTER_VERSION,
    ),
}


class _FixedClock:
    def monotonic(self) -> float:
        return 0.0

    def now(self) -> datetime:
        return NOW + timedelta(seconds=4)


class _QueueHandler:
    def __init__(self, observations: tuple[ProbeObservation, ...]) -> None:
        self._observations = list(observations)

    async def __call__(self, _: BoundProbe) -> ProbeObservation:
        return self._observations.pop(0)


class _RecoveryNormalizer:
    def __call__(self, rule_input: RuleInput) -> RuleObservation:
        observation = ProbeObservation.model_validate_json(rule_input.observation)
        payload = observation.payload
        kind = payload.get("kind")
        if not isinstance(kind, str):
            raise ValueError("test observation kind is missing")
        envelope = rule_input.envelope
        capability = rule_input.request.capability_name
        arguments = envelope.context.invocation.arguments
        by_scope = {
            effect.commit_scope: effect.effect_id
            for effect in envelope.expected_effects
        }

        def assertions(
            *definitions: tuple[str, EffectAssertionState],
        ) -> tuple[EffectAssertion, ...]:
            return tuple(
                EffectAssertion(effect_id=by_scope[scope], state=state)
                for scope, state in definitions
            )

        release_id = str(arguments["release_id"])
        service_prefix = (
            f"projects/{envelope.target.scope['project']}/locations/"
            f"{envelope.target.scope['location']}/services/"
            f"{envelope.target.resource['service']}"
            if envelope.target.target_kind == CLOUD_RUN_SERVICE_TARGET_KIND
            else ""
        )
        status: OperationStatus | None = None
        operation_id: str | None = envelope.operation_id

        if capability == "cloud-run-service-get":
            promotion = (
                envelope.context.invocation.tool_name == "promote-cloud-run-traffic"
            )
            correlation = {
                "observation_schema": CLOUD_RUN_SERVICE_OBSERVATION_VERSION,
                "release_id": release_id,
                "revision": REVISION,
                "generation": "8",
                "observed_generation": "8",
                "reconciling": "false",
                "terminal_condition": "SUCCEEDED",
                "revision_traffic_percent": "100" if promotion else "0",
            }
            etag = payload.get("service_etag")
            if isinstance(etag, str):
                correlation["service_etag"] = etag
            if kind in {"committed", "partial"}:
                scope = (
                    PROMOTION_TRAFFIC_EFFECT_SCOPE
                    if promotion
                    else STAGE_TRAFFIC_EFFECT_SCOPE
                )
                states = assertions(
                    (scope, EffectAssertionState.ESTABLISHED),
                )
                verdict = RuleVerdict.AUTHORITATIVE_EFFECTS
            else:
                states = tuple(
                    EffectAssertion(
                        effect_id=effect.effect_id,
                        state=EffectAssertionState.UNVERIFIED,
                    )
                    for effect in envelope.expected_effects
                )
                verdict = RuleVerdict.ABSENCE_ONLY
                operation_id = None
            source_record = service_prefix
        elif capability == "cloud-run-revision-get":
            failed = kind == "partial"
            correlation = {
                "observation_schema": CLOUD_RUN_REVISION_OBSERVATION_VERSION,
                "release_id": release_id,
                "release_label": release_id,
                "revision": REVISION,
                "image_digest": str(arguments["image_digest"]),
                "configuration_sha256": str(arguments["configuration_sha256"]),
                "generation": "1",
                "observed_generation": "1",
                "reconciling": "false",
                "terminal_condition": "FAILED" if failed else "SUCCEEDED",
                "readiness": "NOT_READY" if failed else "READY",
            }
            if kind == "committed":
                states = assertions(
                    (STAGE_REVISION_EFFECT_SCOPE, EffectAssertionState.ESTABLISHED),
                    (STAGE_READINESS_EFFECT_SCOPE, EffectAssertionState.ESTABLISHED),
                )
                verdict = RuleVerdict.AUTHORITATIVE_EFFECTS
            elif kind == "partial":
                states = assertions(
                    (STAGE_REVISION_EFFECT_SCOPE, EffectAssertionState.ESTABLISHED),
                    (
                        STAGE_READINESS_EFFECT_SCOPE,
                        EffectAssertionState.NOT_ESTABLISHED,
                    ),
                )
                verdict = RuleVerdict.AUTHORITATIVE_EFFECTS
            else:
                states = tuple(
                    EffectAssertion(
                        effect_id=effect.effect_id,
                        state=EffectAssertionState.UNVERIFIED,
                    )
                    for effect in envelope.expected_effects
                )
                verdict = RuleVerdict.ABSENCE_ONLY
                operation_id = None
            source_record = f"{service_prefix}/revisions/{REVISION}"
        elif capability == "cloud-run-revision-health":
            correlation = {
                "observation_schema": CLOUD_RUN_HEALTH_OBSERVATION_VERSION,
                "release_id": release_id,
                "revision": REVISION,
                "health_status": "READY",
            }
            states = assertions(
                (STAGE_READINESS_EFFECT_SCOPE, EffectAssertionState.ESTABLISHED),
            )
            verdict = RuleVerdict.AUTHORITATIVE_EFFECTS
            source_record = f"{service_prefix}/revisions/{REVISION}/health"
        elif capability == "cloud-run-operation-get":
            operation_name = (
                "projects/demo-project/locations/us-central1/operations/release-7"
            )
            succeeded = kind == "operation-succeeded"
            correlation = {
                "observation_schema": CLOUD_RUN_OPERATION_OBSERVATION_VERSION,
                "release_id": release_id,
                "revision": REVISION,
                "operation_name": operation_name,
                "operation_state": "SUCCEEDED" if succeeded else "RUNNING",
            }
            if succeeded:
                scope = (
                    STAGE_REVISION_EFFECT_SCOPE
                    if envelope.context.invocation.tool_name
                    == "stage-cloud-run-revision"
                    else PROMOTION_TRAFFIC_EFFECT_SCOPE
                )
                states = assertions((scope, EffectAssertionState.ESTABLISHED))
                status = OperationStatus.TERMINAL_COMMITTED
                verdict = RuleVerdict.AUTHORITATIVE_EFFECTS
            else:
                states = ()
                status = OperationStatus.ACTIVE
                verdict = RuleVerdict.AUTHORITATIVE_PENDING
            source_record = operation_name
        elif capability == "firestore-release-record-get":
            correlation = {
                "observation_schema": FIRESTORE_DOCUMENT_OBSERVATION_VERSION,
                "release_id": release_id,
                "payload_sha256": str(arguments["payload_sha256"]),
                "exists": "true" if kind == "committed" else "false",
            }
            if kind == "committed":
                states = assertions(
                    (
                        FIRESTORE_RECORD_EFFECT_SCOPE,
                        EffectAssertionState.ESTABLISHED,
                    ),
                )
                verdict = RuleVerdict.AUTHORITATIVE_EFFECTS
            else:
                states = assertions(
                    (
                        FIRESTORE_RECORD_EFFECT_SCOPE,
                        EffectAssertionState.UNVERIFIED,
                    ),
                )
                verdict = RuleVerdict.ABSENCE_ONLY
                operation_id = None
            source_record = (
                f"projects/{envelope.target.scope['project']}/databases/"
                f"{envelope.target.scope['database']}/documents/"
                f"{envelope.target.resource['document']}"
            )
        elif capability == "reconcile-dispatch-receipt-get":
            correlation = {
                "observation_schema": DISPATCH_RECEIPT_OBSERVATION_VERSION,
                "release_id": release_id,
                "semantic_action_sha256": _action(
                    CREATE_FIRESTORE_RELEASE_RECORD_PROFILE_VERSION,
                    envelope,
                ).semantic_action_sha256,
                "receipt_id": "receipt-release-7",
                "provider_contact": "false",
                "outcome": "SUPPRESSED_BEFORE_DISPATCH",
            }
            states = assertions(
                (
                    FIRESTORE_RECORD_EFFECT_SCOPE,
                    EffectAssertionState.NOT_ESTABLISHED,
                ),
            )
            status = OperationStatus.TERMINAL_NOT_COMMITTED
            verdict = RuleVerdict.AUTHORITATIVE_NON_EXECUTION
            source_record = "dispatch-receipts/receipt-release-7"
        else:
            raise ValueError("unsupported test capability")
        return RuleObservation(
            target=envelope.target,
            source_record=source_record,
            observed_at=observation.observed_at,
            operation_id=operation_id,
            correlation=correlation,
            effect_assertions=states,
            operation_status=status,
            verdict=verdict,
        )


@dataclass(frozen=True, slots=True)
class _PipelineResult:
    envelope: ExecutionEnvelope
    engine: EvidenceEngine
    audit_trail: tuple[ControllerAuditRecord, ...]

    def evaluation_and_report(self) -> tuple[CoreEvaluation, InvestigationReport]:
        evaluation = self.engine.evaluate(self.audit_trail)
        report = self.engine.report(
            self.audit_trail,
            created_at=NOW + timedelta(seconds=1),
            updated_at=NOW + timedelta(seconds=5),
            revision=1,
        )
        return evaluation, report


def _target(profile_version: str) -> TargetBinding:
    if profile_version == CREATE_FIRESTORE_RELEASE_RECORD_PROFILE_VERSION:
        return TargetBinding(
            target_kind=FIRESTORE_DOCUMENT_TARGET_KIND,
            scope={"project": "demo-project", "database": "release-db"},
            resource={"document": "releases/release-7"},
        )
    return TargetBinding(
        target_kind=CLOUD_RUN_SERVICE_TARGET_KIND,
        scope={"project": "demo-project", "location": "us-central1"},
        resource={"service": "reconcile-canary"},
    )


def _tool_and_arguments(profile_version: str) -> tuple[str, dict[str, object]]:
    if profile_version == STAGE_CLOUD_RUN_REVISION_PROFILE_VERSION:
        return "stage-cloud-run-revision", {
            "release_id": RELEASE_ID,
            "image_digest": IMAGE_DIGEST,
            "configuration_sha256": CONFIGURATION_SHA256,
        }
    if profile_version == PROMOTE_CLOUD_RUN_TRAFFIC_PROFILE_VERSION:
        return "promote-cloud-run-traffic", {
            "release_id": RELEASE_ID,
            "revision": REVISION,
            "percent": 100,
        }
    return "create-firestore-release-record", {
        "release_id": RELEASE_ID,
        "payload_sha256": PAYLOAD_SHA256,
    }


def _envelope(
    profile_version: str,
    *,
    node_id: str,
    capability_names: tuple[str, ...] | None = None,
) -> ExecutionEnvelope:
    tool_name, arguments = _tool_and_arguments(profile_version)
    capabilities = capability_names or (
        _FIRESTORE_CAPABILITIES
        if profile_version == CREATE_FIRESTORE_RELEASE_RECORD_PROFILE_VERSION
        else _CLOUD_CAPABILITIES
    )
    if profile_version == STAGE_CLOUD_RUN_REVISION_PROFILE_VERSION:
        effect_definitions = (
            (
                "revision",
                STAGE_REVISION_EFFECT_SCOPE,
                {
                    "release_id": RELEASE_ID,
                    "image_digest": IMAGE_DIGEST,
                    "configuration_sha256": CONFIGURATION_SHA256,
                },
            ),
            (
                "readiness",
                STAGE_READINESS_EFFECT_SCOPE,
                {"release_id": RELEASE_ID, "ready": True},
            ),
            (
                "traffic",
                STAGE_TRAFFIC_EFFECT_SCOPE,
                {"release_id": RELEASE_ID, "traffic_percent": 0},
            ),
        )
    elif profile_version == PROMOTE_CLOUD_RUN_TRAFFIC_PROFILE_VERSION:
        effect_definitions = (
            (
                "traffic",
                PROMOTION_TRAFFIC_EFFECT_SCOPE,
                {"release_id": RELEASE_ID, "revision": REVISION, "percent": 100},
            ),
        )
    else:
        effect_definitions = (
            (
                "record",
                FIRESTORE_RECORD_EFFECT_SCOPE,
                {"release_id": RELEASE_ID, "payload_sha256": PAYLOAD_SHA256},
            ),
        )
    effects = tuple(
        ExpectedEffect(
            schema_version=EXPECTED_EFFECT_VERSION,
            effect_id=f"{node_id}-{suffix}",
            commit_scope=scope,
            predicate=predicate,
            description=f"The provider proves {scope}.",
        )
        for suffix, scope, predicate in effect_definitions
    )
    return ExecutionEnvelope(
        schema_version=EXECUTION_ENVELOPE_VERSION,
        investigation_id=f"investigation-{node_id}",
        operation_id=f"operation-{node_id}",
        target=_target(profile_version),
        invoked_at=NOW,
        ambiguity=AmbiguousExecution(
            kind=AmbiguityKind.MISSING_TOOL_RESULT,
            observed_at=NOW + timedelta(seconds=1),
            detail="The provider acknowledgement was not delivered.",
        ),
        expected_effects=effects,
        context=EnvelopeContext(
            invocation=OriginalInvocation(
                invocation_id=f"invocation-{node_id}",
                function_call_id=f"call-{node_id}",
                tool_name=tool_name,
                tool_version=RECOVERY_TOOL_VERSION,
                arguments=arguments,
                arguments_sha256=hashlib.sha256(
                    canonical_json_value_bytes(arguments)
                ).hexdigest(),
            ),
            enabled_capabilities=tuple(
                CapabilityRef(name=name, version="1.0.0") for name in capabilities
            ),
            correlation_fields={"release_id": "release-7"},
            evidence_budget=EvidenceBudget(
                max_probes=8,
                max_elapsed_ms=30_000,
                max_total_result_bytes=1_000_000,
                max_cost_units=8,
            ),
            freshness=FreshnessPolicy(max_age_seconds=60, clock_skew_seconds=2),
            policies=PolicyReferences(
                authority="recovery-authority-v1",
                classification="recovery-classification-v1",
                action="recovery-action-v1",
            ),
        ),
    )


def _action(
    profile_version: str, envelope: ExecutionEnvelope
) -> SemanticActionIdentity:
    invocation = envelope.context.invocation
    effect_hashes = tuple(canonical_sha256(item) for item in envelope.expected_effects)
    digest = semantic_action_sha256(
        key_version="semantic-action-v1",
        tool_name=invocation.tool_name,
        tool_version=invocation.tool_version,
        semantic_arguments=invocation.arguments,
        target=envelope.target,
        expected_effect_sha256s=effect_hashes,
        action_profile_version=profile_version,
    )
    return SemanticActionIdentity(
        key_version="semantic-action-v1",
        tool_name=invocation.tool_name,
        tool_version=invocation.tool_version,
        semantic_arguments=invocation.arguments,
        target=envelope.target,
        expected_effect_sha256s=effect_hashes,
        action_profile_version=profile_version,
        semantic_action_sha256=digest,
    )


def _chain() -> tuple[RecoveryChain, dict[str, ExecutionEnvelope]]:
    specifications = (
        (
            "stage",
            STAGE_CLOUD_RUN_REVISION_PROFILE_VERSION,
            (),
        ),
        (
            "promote",
            PROMOTE_CLOUD_RUN_TRAFFIC_PROFILE_VERSION,
            ("stage",),
        ),
        (
            "record",
            CREATE_FIRESTORE_RELEASE_RECORD_PROFILE_VERSION,
            ("promote",),
        ),
    )
    envelopes: dict[str, ExecutionEnvelope] = {}
    nodes: list[RecoveryActionNode] = []
    for node_id, profile_version, dependencies in specifications:
        envelope = _envelope(profile_version, node_id=node_id)
        envelopes[node_id] = envelope
        nodes.append(
            RecoveryActionNode(
                node_id=node_id,
                chain_profile_version=RECOVERY_CHAIN_PROFILE_VERSION,
                semantic_action=_action(profile_version, envelope),
                depends_on=dependencies,
                envelope=ExecutionEnvelopeReference(
                    investigation_id=envelope.investigation_id,
                    operation_id=envelope.operation_id,
                    envelope_sha256=canonical_sha256(envelope),
                ),
            )
        )
    return (
        RecoveryChain(
            schema_version=RECOVERY_CHAIN_VERSION,
            chain_id="release-chain-7",
            chain_profile_version=RECOVERY_CHAIN_PROFILE_VERSION,
            nodes=tuple(nodes),
            created_at=NOW,
        ),
        envelopes,
    )


def _capability(envelope: ExecutionEnvelope, name: str) -> ObservationCapability:
    return ObservationCapability(
        schema_version=OBSERVATION_CAPABILITY_VERSION,
        name=name,
        version="1.0.0",
        read_only=True,
        argument_schema={
            "$schema": "https://json-schema.org/draft/2020-12/schema",
            "type": "object",
            "properties": {},
            "required": [],
            "additionalProperties": False,
        },
        allowed_targets=(
            {
                "target_kind": envelope.target.target_kind,
                "scope": envelope.target.scope,
            },
        ),
        timeout_ms=2_000,
        result_byte_ceiling=65_536,
        cost_units=1,
    )


def _run_pipeline(
    envelope: ExecutionEnvelope,
    observations: tuple[tuple[str, str, datetime, str | None], ...],
) -> _PipelineResult:
    async def run() -> _PipelineResult:
        payloads = tuple(
            ProbeObservation(
                observed_at=observed_at,
                payload={
                    "kind": kind,
                    "record": f"record-{index}",
                    **(
                        {"service_etag": service_etag}
                        if service_etag is not None
                        else {}
                    ),
                },
            )
            for index, (_, kind, observed_at, service_etag) in enumerate(
                observations, start=1
            )
        )
        handler = _QueueHandler(payloads)
        capabilities = CapabilityRegistry()
        rules = TargetRuleRegistry()
        for name in dict.fromkeys(item[0] for item in observations):
            source, adapter_version = _PROVENANCE.get(
                name,
                ("recovery-test-provider", "1.0.0"),
            )
            capabilities.register(
                CapabilityRegistration(
                    capability=_capability(envelope, name),
                    semantics=CapabilitySemantics.READ_ONLY,
                    enabled=True,
                    argument_byte_ceiling=1_024,
                    max_invocations=8,
                    handler=handler,
                )
            )
            rules.register(
                TargetRuleRegistration(
                    descriptor=TargetRuleDescriptor(
                        target_kind=envelope.target.target_kind,
                        capability_name=name,
                        capability_version="1.0.0",
                        authority_policy_version=envelope.context.policies.authority,
                        classification_policy_version=(
                            envelope.context.policies.classification
                        ),
                        source=source,
                        adapter_version=adapter_version,
                    ),
                    normalizer=_RecoveryNormalizer(),
                )
            )
        controller = ProbeController(envelope, capabilities, clock=_FixedClock())
        engine = EvidenceEngine(envelope, rules)
        relevant_effect_ids = tuple(
            effect.effect_id for effect in envelope.expected_effects
        )
        for name, _, _, _ in observations:
            request = ProbeRequest(
                schema_version=PROBE_REQUEST_VERSION,
                capability_name=name,
                capability_version="1.0.0",
                relevant_effect_ids=relevant_effect_ids,
                arguments={},
                rationale="Read exact provider state for deterministic recovery.",
            )
            execution = await controller.execute(request)
            engine.process(ProbeRun(request=request, execution=execution))
        return _PipelineResult(envelope, engine, controller.audit_trail)

    return asyncio.run(run())


def _verify(
    *,
    node_id: str,
    kind: str,
    capability: str | None = None,
    service_etag: str | None = "etag-release-7",
    verified_at: datetime = VERIFIED_AT,
) -> tuple[
    RecoveryVerificationResult,
    CoreEvaluation,
    InvestigationReport,
    RecoveryChain,
    ExecutionEnvelope,
]:
    chain, envelopes = _chain()
    envelope = envelopes[node_id]
    if capability is not None:
        observations = ((capability, kind, NOW + timedelta(seconds=3), service_etag),)
    elif node_id == "stage" and kind == "committed":
        observations = (
            (
                "cloud-run-service-get",
                kind,
                NOW + timedelta(seconds=2),
                service_etag,
            ),
            (
                "cloud-run-revision-get",
                kind,
                NOW + timedelta(seconds=3),
                None,
            ),
            (
                "cloud-run-revision-health",
                kind,
                NOW + timedelta(seconds=4),
                None,
            ),
        )
    elif node_id == "stage" and kind == "partial":
        observations = (
            (
                "cloud-run-service-get",
                kind,
                NOW + timedelta(seconds=2),
                service_etag,
            ),
            (
                "cloud-run-revision-get",
                kind,
                NOW + timedelta(seconds=3),
                None,
            ),
        )
    elif node_id == "stage" and kind == "pending":
        observations = (
            (
                "cloud-run-operation-get",
                kind,
                NOW + timedelta(seconds=3),
                None,
            ),
        )
    elif node_id == "stage":
        observations = (
            (
                "cloud-run-revision-get",
                "absence",
                NOW + timedelta(seconds=3),
                None,
            ),
        )
    elif node_id == "record" and kind == "not-committed":
        observations = (
            (
                "reconcile-dispatch-receipt-get",
                kind,
                NOW + timedelta(seconds=3),
                None,
            ),
        )
    else:
        observations = (
            (
                "firestore-release-record-get"
                if node_id == "record"
                else "cloud-run-service-get",
                kind,
                NOW + timedelta(seconds=3),
                service_etag,
            ),
        )
    run = _run_pipeline(envelope, observations)
    evaluation, report = run.evaluation_and_report()
    artifact = verify_recovery(
        chain=chain,
        node_id=node_id,
        envelope=envelope,
        report=report,
        evaluation=evaluation,
        verified_at=verified_at,
        successor_envelope={
            "stage": envelopes["promote"],
            "promote": envelopes["record"],
        }.get(node_id),
    )
    return artifact, evaluation, report, chain, envelope


def test_committed_stage_certifies_exact_promotion_with_fresh_etag() -> None:
    artifact, _, _, chain, _ = _verify(
        node_id="stage",
        kind="committed",
        service_etag="etag-stage-7",
    )

    assert isinstance(artifact, VerifiedCertificate)
    assert artifact.classification is Classification.COMMITTED
    assert artifact.transition is not None
    assert artifact.transition.action is PermitAction.CONTINUE
    assert artifact.transition.source_node_id == "stage"
    assert artifact.transition.target_node_id == "promote"
    assert artifact.transition.semantic_action_sha256 == (
        chain.nodes[1].semantic_action.semantic_action_sha256
    )


def test_running_then_succeeded_operation_remains_certifiable() -> None:
    chain, envelopes = _chain()
    envelope = envelopes["stage"]
    run = _run_pipeline(
        envelope,
        (
            (
                "cloud-run-operation-get",
                "pending",
                NOW + timedelta(seconds=2),
                None,
            ),
            (
                "cloud-run-service-get",
                "committed",
                NOW + timedelta(seconds=2),
                "etag-stage-7",
            ),
            (
                "cloud-run-revision-get",
                "committed",
                NOW + timedelta(seconds=3),
                None,
            ),
            (
                "cloud-run-operation-get",
                "operation-succeeded",
                NOW + timedelta(seconds=4),
                None,
            ),
            (
                "cloud-run-revision-health",
                "committed",
                NOW + timedelta(seconds=4),
                None,
            ),
        ),
    )
    evaluation, report = run.evaluation_and_report()

    artifact = verify_recovery(
        chain=chain,
        node_id="stage",
        envelope=envelope,
        report=report,
        evaluation=evaluation,
        verified_at=VERIFIED_AT,
        successor_envelope=envelopes["promote"],
    )

    assert isinstance(artifact, VerifiedCertificate)
    assert artifact.classification is Classification.COMMITTED
    assert {binding.evidence_id for binding in artifact.evidence} == {
        evidence.evidence_id for evidence in evaluation.evidence
    }


def test_committed_promotion_certifies_firestore_record_creation() -> None:
    artifact, _, _, chain, _ = _verify(
        node_id="promote",
        kind="committed",
        service_etag="etag-promote-7",
    )

    assert isinstance(artifact, VerifiedCertificate)
    assert artifact.transition is not None
    assert artifact.transition.target_node_id == "record"
    assert artifact.transition.semantic_action_sha256 == (
        chain.nodes[2].semantic_action.semantic_action_sha256
    )


def test_committed_final_node_has_no_transition() -> None:
    artifact, *_ = _verify(node_id="record", kind="committed")

    assert isinstance(artifact, VerifiedCertificate)
    assert artifact.transition is None


def test_affirmative_firestore_non_dispatch_certifies_retry() -> None:
    artifact, *_ = _verify(node_id="record", kind="not-committed")

    assert isinstance(artifact, VerifiedCertificate)
    assert artifact.classification is Classification.NOT_COMMITTED
    assert artifact.transition is not None
    assert artifact.transition.action is PermitAction.RETRY
    assert artifact.transition.source_node_id == artifact.transition.target_node_id


def test_cloud_run_non_dispatch_does_not_authorize_retry() -> None:
    artifact, *_ = _verify(node_id="stage", kind="not-committed")

    assert artifact.schema_version == AMBIGUITY_WITNESS_VERSION


def test_committed_stage_without_service_etag_cannot_authorize_promotion() -> None:
    artifact, *_ = _verify(
        node_id="stage",
        kind="committed",
        service_etag=None,
    )

    assert artifact.schema_version == AMBIGUITY_WITNESS_VERSION


def test_conflicting_service_etags_cannot_authorize_promotion() -> None:
    chain, envelopes = _chain()
    envelope = envelopes["stage"]
    run = _run_pipeline(
        envelope,
        (
            (
                "cloud-run-service-get",
                "committed",
                NOW + timedelta(seconds=2),
                "etag-a",
            ),
            (
                "cloud-run-service-get",
                "committed",
                NOW + timedelta(seconds=3),
                "etag-b",
            ),
            (
                "cloud-run-revision-get",
                "committed",
                NOW + timedelta(seconds=3),
                None,
            ),
            (
                "cloud-run-revision-health",
                "committed",
                NOW + timedelta(seconds=4),
                None,
            ),
        ),
    )
    evaluation, report = run.evaluation_and_report()

    artifact = verify_recovery(
        chain=chain,
        node_id="stage",
        envelope=envelope,
        report=report,
        evaluation=evaluation,
        verified_at=VERIFIED_AT,
        successor_envelope=envelopes["promote"],
    )

    assert artifact.schema_version == AMBIGUITY_WITNESS_VERSION


def test_profile_disallowed_capability_produces_a_witness() -> None:
    chain, _ = _chain()
    envelope = _envelope(
        STAGE_CLOUD_RUN_REVISION_PROFILE_VERSION,
        node_id="stage",
        capability_names=("unexpected-provider-read",),
    )
    replacement = RecoveryActionNode(
        node_id="stage",
        chain_profile_version=RECOVERY_CHAIN_PROFILE_VERSION,
        semantic_action=_action(STAGE_CLOUD_RUN_REVISION_PROFILE_VERSION, envelope),
        envelope=ExecutionEnvelopeReference(
            investigation_id=envelope.investigation_id,
            operation_id=envelope.operation_id,
            envelope_sha256=canonical_sha256(envelope),
        ),
    )
    chain = RecoveryChain(
        schema_version=RECOVERY_CHAIN_VERSION,
        chain_id=chain.chain_id,
        chain_profile_version=chain.chain_profile_version,
        nodes=(replacement, *chain.nodes[1:]),
        created_at=chain.created_at,
    )
    run = _run_pipeline(
        envelope,
        (
            (
                "unexpected-provider-read",
                "committed",
                NOW + timedelta(seconds=3),
                "etag-7",
            ),
        ),
    )
    evaluation, report = run.evaluation_and_report()

    artifact = verify_recovery(
        chain=chain,
        node_id="stage",
        envelope=envelope,
        report=report,
        evaluation=evaluation,
        verified_at=VERIFIED_AT,
    )

    assert artifact.schema_version == AMBIGUITY_WITNESS_VERSION
    assert artifact.possible_histories[0] != artifact.possible_histories[1]


@pytest.mark.parametrize(
    ("kind", "classification"),
    (
        ("partial", Classification.PARTIAL),
        ("pending", Classification.PENDING),
    ),
)
def test_incomplete_or_active_effects_certify_no_mutation(
    kind: str, classification: Classification
) -> None:
    artifact, *_ = _verify(node_id="stage", kind=kind)

    assert isinstance(artifact, VerifiedCertificate)
    assert artifact.classification is classification
    assert artifact.transition is None


def test_absence_produces_two_histories_and_a_discriminating_probe() -> None:
    artifact, evaluation, *_ = _verify(
        node_id="stage",
        kind="absence",
        capability="cloud-run-revision-get",
    )

    assert artifact.schema_version == AMBIGUITY_WITNESS_VERSION
    assert evaluation.classification is Classification.UNKNOWN
    assert len(artifact.possible_histories) == 2
    assert {history.classification for history in artifact.possible_histories} == {
        Classification.COMMITTED,
        Classification.NOT_COMMITTED,
    }
    observation = artifact.discriminating_observations[0]
    assert observation.capability_name == "cloud-run-revision-get"
    assert set(observation.distinguishes_history_ids) == {
        history.history_id for history in artifact.possible_histories
    }
    by_capability = {
        item.capability_name: item.relevant_effect_ids
        for item in artifact.discriminating_observations
    }
    assert by_capability == {
        "cloud-run-revision-get": ("stage-revision",),
        "cloud-run-revision-health": ("stage-readiness",),
        "cloud-run-service-get": ("stage-traffic",),
    }


def test_provider_unavailability_produces_a_witness_without_authority() -> None:
    chain, envelopes = _chain()
    envelope = envelopes["stage"]
    run = _run_pipeline(envelope, ())
    evaluation, report = run.evaluation_and_report()

    artifact = verify_recovery(
        chain=chain,
        node_id="stage",
        envelope=envelope,
        report=report,
        evaluation=evaluation,
        verified_at=VERIFIED_AT,
        successor_envelope=envelopes["promote"],
    )

    assert artifact.schema_version == AMBIGUITY_WITNESS_VERSION
    assert artifact.evidence == ()


def test_cloud_run_absence_does_not_become_authoritative_conflict() -> None:
    chain, envelopes = _chain()
    envelope = envelopes["stage"]
    run = _run_pipeline(
        envelope,
        (
            (
                "cloud-run-service-get",
                "committed",
                NOW + timedelta(seconds=2),
                "etag-7",
            ),
            (
                "cloud-run-service-get",
                "not-committed",
                NOW + timedelta(seconds=3),
                "etag-7",
            ),
        ),
    )
    evaluation, report = run.evaluation_and_report()

    artifact = verify_recovery(
        chain=chain,
        node_id="stage",
        envelope=envelope,
        report=report,
        evaluation=evaluation,
        verified_at=VERIFIED_AT,
    )

    assert artifact.schema_version == AMBIGUITY_WITNESS_VERSION
    assert artifact.conflicting_evidence_ids == ()


def test_evidence_expiring_at_verification_time_cannot_certify() -> None:
    artifact, _, _, _, _ = _verify(
        node_id="stage",
        kind="committed",
        service_etag="etag-7",
        verified_at=NOW + timedelta(seconds=65),
    )

    assert artifact.schema_version == AMBIGUITY_WITNESS_VERSION


def test_certificate_expires_with_earliest_supporting_evidence() -> None:
    artifact, evaluation, *_ = _verify(
        node_id="stage",
        kind="committed",
        service_etag="etag-7",
    )

    assert isinstance(artifact, VerifiedCertificate)
    assert artifact.expires_at == min(
        item.freshness.valid_until for item in evaluation.evidence
    )


def test_wrong_chain_envelope_reference_is_rejected() -> None:
    artifact, evaluation, report, chain, envelope = _verify(
        node_id="stage",
        kind="committed",
        service_etag="etag-7",
    )
    assert isinstance(artifact, VerifiedCertificate)
    stage = chain.nodes[0]
    wrong_stage = stage.model_copy(
        update={
            "envelope": stage.envelope.model_copy(
                update={"operation_id": "operation-other"}
            )
        }
    )
    wrong_chain = chain.model_copy(update={"nodes": (wrong_stage, *chain.nodes[1:])})

    with pytest.raises(RecoveryVerificationError, match="another envelope"):
        verify_recovery(
            chain=wrong_chain,
            node_id="stage",
            envelope=envelope,
            report=report,
            evaluation=evaluation,
            verified_at=VERIFIED_AT,
        )


def test_report_deterministic_fields_must_match_the_sealed_evaluation() -> None:
    _, evaluation, _, chain, envelope = _verify(
        node_id="stage",
        kind="committed",
        service_etag="etag-7",
    )
    second = _run_pipeline(
        envelope,
        (
            (
                "cloud-run-service-get",
                "committed",
                NOW + timedelta(seconds=2),
                "etag-7",
            ),
        ),
    )
    _, changed = second.evaluation_and_report()

    with pytest.raises(RecoveryVerificationError, match="does not reproduce"):
        verify_recovery(
            chain=chain,
            node_id="stage",
            envelope=envelope,
            report=changed,
            evaluation=evaluation,
            verified_at=VERIFIED_AT,
        )


def test_forged_core_evaluation_is_rejected() -> None:
    _, _, report, chain, envelope = _verify(
        node_id="stage",
        kind="committed",
        service_etag="etag-7",
    )
    forged = object.__new__(CoreEvaluation)

    with pytest.raises(TypeError, match="sealed core evaluations"):
        verify_recovery(
            chain=chain,
            node_id="stage",
            envelope=envelope,
            report=report,
            evaluation=forged,
            verified_at=VERIFIED_AT,
        )


def test_verifier_is_deterministic_and_has_no_gemini_input() -> None:
    _, evaluation, report, chain, envelope = _verify(
        node_id="stage",
        kind="committed",
        service_etag="etag-7",
    )
    arguments = {
        "chain": chain,
        "node_id": "stage",
        "envelope": envelope,
        "report": report,
        "evaluation": evaluation,
        "verified_at": VERIFIED_AT,
    }

    assert "hypothesis" not in inspect.signature(verify_recovery).parameters
    assert verify_recovery(**arguments) == verify_recovery(**arguments)
