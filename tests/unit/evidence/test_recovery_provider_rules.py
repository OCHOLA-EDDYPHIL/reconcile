"""Provider-specific safety rules for proof-scoped recovery."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from itertools import permutations

import pytest

from reconcile.contracts import (
    EXPECTED_EFFECT_VERSION,
    NORMALIZED_EVIDENCE_VERSION,
    Classification,
    EffectAssertion,
    EffectAssertionState,
    EvidenceAuthority,
    EvidenceProvenance,
    ExpectedEffect,
    FreshnessWindow,
    NormalizedEvidence,
    OperationStatus,
    RawObservationReference,
    SemanticActionIdentity,
    TargetBinding,
    canonical_sha256,
    semantic_action_sha256,
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
    CLOUD_RUN_SERVICE_TARGET_KIND,
    CREATE_FIRESTORE_RELEASE_RECORD_PROFILE,
    CREATE_FIRESTORE_RELEASE_RECORD_PROFILE_VERSION,
    DISPATCH_RECEIPT_ADAPTER_VERSION,
    DISPATCH_RECEIPT_OBSERVATION_VERSION,
    DISPATCH_RECEIPT_SOURCE,
    FIRESTORE_DOCUMENT_OBSERVATION_VERSION,
    FIRESTORE_DOCUMENT_TARGET_KIND,
    FIRESTORE_PROVIDER_ADAPTER_VERSION,
    FIRESTORE_PROVIDER_SOURCE,
    FIRESTORE_RECORD_EFFECT_SCOPE,
    PROMOTE_CLOUD_RUN_TRAFFIC_PROFILE,
    PROMOTE_CLOUD_RUN_TRAFFIC_PROFILE_VERSION,
    PROMOTION_TRAFFIC_EFFECT_SCOPE,
    RECOVERY_TOOL_VERSION,
    STAGE_CLOUD_RUN_REVISION_PROFILE,
    STAGE_CLOUD_RUN_REVISION_PROFILE_VERSION,
    STAGE_READINESS_EFFECT_SCOPE,
    STAGE_REVISION_EFFECT_SCOPE,
    STAGE_TRAFFIC_EFFECT_SCOPE,
    RecoveryRuleViolation,
    validate_recovery_dispatch,
    validate_recovery_proof,
)

pytestmark = pytest.mark.unit

NOW = datetime(2026, 8, 22, 12, 0, tzinfo=UTC)
RELEASE_ID = "release-7"
REVISION = "reconcile-canary-r7-a1"
IMAGE_DIGEST = f"sha256:{'a' * 64}"
CONFIGURATION_SHA256 = "b" * 64
PAYLOAD_SHA256 = "c" * 64


def _target(profile_version: str) -> TargetBinding:
    if profile_version == CREATE_FIRESTORE_RELEASE_RECORD_PROFILE_VERSION:
        return TargetBinding(
            target_kind=FIRESTORE_DOCUMENT_TARGET_KIND,
            scope={"project": "demo-project", "database": "release-db"},
            resource={"document": f"releases/{RELEASE_ID}"},
        )
    return TargetBinding(
        target_kind=CLOUD_RUN_SERVICE_TARGET_KIND,
        scope={"project": "demo-project", "location": "us-central1"},
        resource={"service": "reconcile-canary"},
    )


def _effects(profile_version: str) -> tuple[ExpectedEffect, ...]:
    if profile_version == STAGE_CLOUD_RUN_REVISION_PROFILE_VERSION:
        definitions = (
            (
                "revision-created",
                STAGE_REVISION_EFFECT_SCOPE,
                {
                    "release_id": RELEASE_ID,
                    "image_digest": IMAGE_DIGEST,
                    "configuration_sha256": CONFIGURATION_SHA256,
                },
            ),
            (
                "revision-ready",
                STAGE_READINESS_EFFECT_SCOPE,
                {"release_id": RELEASE_ID, "ready": True},
            ),
            (
                "revision-zero-traffic",
                STAGE_TRAFFIC_EFFECT_SCOPE,
                {"release_id": RELEASE_ID, "traffic_percent": 0},
            ),
        )
    elif profile_version == PROMOTE_CLOUD_RUN_TRAFFIC_PROFILE_VERSION:
        definitions = (
            (
                "traffic-promoted",
                PROMOTION_TRAFFIC_EFFECT_SCOPE,
                {
                    "release_id": RELEASE_ID,
                    "revision": REVISION,
                    "percent": 100,
                },
            ),
        )
    else:
        definitions = (
            (
                "release-record-created",
                FIRESTORE_RECORD_EFFECT_SCOPE,
                {"release_id": RELEASE_ID, "payload_sha256": PAYLOAD_SHA256},
            ),
        )
    return tuple(
        ExpectedEffect(
            schema_version=EXPECTED_EFFECT_VERSION,
            effect_id=effect_id,
            commit_scope=scope,
            predicate=predicate,
            description=f"Provider proves {scope}.",
        )
        for effect_id, scope, predicate in definitions
    )


def _action(
    profile_version: str,
    effects: tuple[ExpectedEffect, ...] | None = None,
) -> tuple[SemanticActionIdentity, tuple[ExpectedEffect, ...]]:
    effects = effects or _effects(profile_version)
    if profile_version == STAGE_CLOUD_RUN_REVISION_PROFILE_VERSION:
        tool_name = "stage-cloud-run-revision"
        arguments: dict[str, object] = {
            "release_id": RELEASE_ID,
            "image_digest": IMAGE_DIGEST,
            "configuration_sha256": CONFIGURATION_SHA256,
        }
    elif profile_version == PROMOTE_CLOUD_RUN_TRAFFIC_PROFILE_VERSION:
        tool_name = "promote-cloud-run-traffic"
        arguments = {
            "release_id": RELEASE_ID,
            "revision": REVISION,
            "percent": 100,
        }
    else:
        tool_name = "create-firestore-release-record"
        arguments = {
            "release_id": RELEASE_ID,
            "payload_sha256": PAYLOAD_SHA256,
        }
    target = _target(profile_version)
    effect_hashes = tuple(canonical_sha256(item) for item in effects)
    digest = semantic_action_sha256(
        key_version="semantic-action-v1",
        tool_name=tool_name,
        tool_version=RECOVERY_TOOL_VERSION,
        semantic_arguments=arguments,
        target=target,
        expected_effect_sha256s=effect_hashes,
        action_profile_version=profile_version,
    )
    return (
        SemanticActionIdentity(
            key_version="semantic-action-v1",
            tool_name=tool_name,
            tool_version=RECOVERY_TOOL_VERSION,
            semantic_arguments=arguments,
            target=target,
            expected_effect_sha256s=effect_hashes,
            action_profile_version=profile_version,
            semantic_action_sha256=digest,
        ),
        effects,
    )


def test_recovery_dispatch_accepts_only_the_exact_profile_binding() -> None:
    action, _effects = _action(PROMOTE_CLOUD_RUN_TRAFFIC_PROFILE_VERSION)

    profile = validate_recovery_dispatch(
        action,
        tool_name=action.tool_name,
        tool_version=action.tool_version,
        arguments=dict(action.semantic_arguments),
        target=action.target,
        precondition={"service_etag": "etag-release-7"},
    )

    assert profile is PROMOTE_CLOUD_RUN_TRAFFIC_PROFILE


@pytest.mark.parametrize(
    ("case", "message"),
    (
        ("wrong-target", "identity"),
        ("missing-revision", "identity"),
        ("wrong-argument-type", "identity"),
        ("wrong-argument-value", "identity"),
        ("wrong-tool", "identity"),
        ("wrong-version", "identity"),
        ("missing-precondition", "precondition"),
        ("extra-precondition", "precondition"),
        ("wrong-precondition-type", "precondition"),
        ("empty-precondition-value", "precondition"),
    ),
)
def test_recovery_dispatch_rejects_adversarial_runtime_bindings(
    case: str,
    message: str,
) -> None:
    action, _effects = _action(PROMOTE_CLOUD_RUN_TRAFFIC_PROFILE_VERSION)
    tool_name = action.tool_name
    tool_version = action.tool_version
    arguments = dict(action.semantic_arguments)
    target = action.target
    precondition: dict[str, object] = {"service_etag": "etag-release-7"}

    if case == "wrong-target":
        target = TargetBinding.model_validate(
            target.model_copy(update={"resource": {"service": "other-service"}})
        )
    elif case == "missing-revision":
        arguments.pop("revision")
    elif case == "wrong-argument-type":
        arguments["percent"] = True
    elif case == "wrong-argument-value":
        arguments["percent"] = 99
    elif case == "wrong-tool":
        tool_name = "stage-cloud-run-revision"
    elif case == "wrong-version":
        tool_version = "2.0.0"
    elif case == "missing-precondition":
        precondition = {}
    elif case == "extra-precondition":
        precondition["unexpected"] = True
    elif case == "wrong-precondition-type":
        precondition["service_etag"] = 7
    elif case == "empty-precondition-value":
        precondition["service_etag"] = ""
    else:  # pragma: no cover - the parameter inventory is exhaustive
        raise AssertionError(case)

    with pytest.raises(RecoveryRuleViolation, match=message):
        validate_recovery_dispatch(
            action,
            tool_name=tool_name,
            tool_version=tool_version,
            arguments=arguments,
            target=target,
            precondition=precondition,
        )


def _source_record(
    action: SemanticActionIdentity, capability: str, values: dict[str, str]
) -> str:
    if action.target.target_kind == CLOUD_RUN_SERVICE_TARGET_KIND:
        prefix = (
            f"projects/{action.target.scope['project']}/locations/"
            f"{action.target.scope['location']}/services/"
            f"{action.target.resource['service']}"
        )
        if capability == "cloud-run-service-get":
            return prefix
        if capability == "cloud-run-operation-get":
            return values["operation_name"]
        suffix = f"{prefix}/revisions/{values['revision']}"
        return (
            f"{suffix}/health" if capability == "cloud-run-revision-health" else suffix
        )
    if capability == "reconcile-dispatch-receipt-get":
        return f"dispatch-receipts/{values['receipt_id']}"
    return (
        f"projects/{action.target.scope['project']}/databases/"
        f"{action.target.scope['database']}/documents/"
        f"{action.target.resource['document']}"
    )


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


def _evidence(
    action: SemanticActionIdentity,
    *,
    evidence_id: str,
    capability: str,
    correlation: dict[str, str],
    assertions: tuple[EffectAssertion, ...] = (),
    operation_status: OperationStatus | None = None,
    source: str | None = None,
    adapter_version: str | None = None,
    source_record: str | None = None,
) -> NormalizedEvidence:
    trusted_source, trusted_adapter = _PROVENANCE[capability]
    return NormalizedEvidence(
        schema_version=NORMALIZED_EVIDENCE_VERSION,
        evidence_id=evidence_id,
        capability_name=capability,
        capability_version="1.0.0",
        target=action.target,
        provenance=EvidenceProvenance(
            source=source or trusted_source,
            source_record=source_record
            or _source_record(action, capability, correlation),
            adapter_version=adapter_version or trusted_adapter,
            retrieved_at=NOW + timedelta(seconds=2),
        ),
        observed_at=NOW + timedelta(seconds=1),
        freshness=FreshnessWindow(
            valid_from=NOW,
            valid_until=NOW + timedelta(seconds=60),
        ),
        correlation=correlation,
        authority=EvidenceAuthority.TARGET_STATE,
        authority_policy_version="recovery-authority-v1",
        effect_assertions=assertions,
        operation_status=operation_status,
        raw_observation=RawObservationReference(
            sha256="d" * 64,
            reference=f"raw-{evidence_id}",
            byte_count=128,
        ),
    )


def _assertions(
    effects: tuple[ExpectedEffect, ...],
    scopes: tuple[str, ...],
    state: EffectAssertionState = EffectAssertionState.ESTABLISHED,
) -> tuple[EffectAssertion, ...]:
    by_scope = {item.commit_scope: item.effect_id for item in effects}
    return tuple(
        EffectAssertion(effect_id=by_scope[scope], state=state) for scope in scopes
    )


def _service_values(*, percent: str = "0", revision: str = REVISION) -> dict[str, str]:
    return {
        "observation_schema": CLOUD_RUN_SERVICE_OBSERVATION_VERSION,
        "release_id": RELEASE_ID,
        "revision": revision,
        "service_etag": "etag-r7-1",
        "generation": "8",
        "observed_generation": "8",
        "reconciling": "false",
        "terminal_condition": "SUCCEEDED",
        "revision_traffic_percent": percent,
    }


def _revision_values() -> dict[str, str]:
    return {
        "observation_schema": CLOUD_RUN_REVISION_OBSERVATION_VERSION,
        "release_id": RELEASE_ID,
        "release_label": RELEASE_ID,
        "revision": REVISION,
        "image_digest": IMAGE_DIGEST,
        "configuration_sha256": CONFIGURATION_SHA256,
        "generation": "1",
        "observed_generation": "1",
        "reconciling": "false",
        "terminal_condition": "SUCCEEDED",
        "readiness": "READY",
    }


def _health_values() -> dict[str, str]:
    return {
        "observation_schema": CLOUD_RUN_HEALTH_OBSERVATION_VERSION,
        "release_id": RELEASE_ID,
        "revision": REVISION,
        "health_status": "READY",
    }


def _operation_values(
    *,
    state: str,
    operation_name: str = (
        "projects/demo-project/locations/us-central1/operations/op-7"
    ),
) -> dict[str, str]:
    return {
        "observation_schema": CLOUD_RUN_OPERATION_OBSERVATION_VERSION,
        "release_id": RELEASE_ID,
        "revision": REVISION,
        "operation_name": operation_name,
        "operation_state": state,
    }


def _stage_proof() -> tuple[
    SemanticActionIdentity,
    tuple[ExpectedEffect, ...],
    tuple[NormalizedEvidence, ...],
]:
    action, effects = _action(STAGE_CLOUD_RUN_REVISION_PROFILE_VERSION)
    evidence = (
        _evidence(
            action,
            evidence_id="service-proof",
            capability="cloud-run-service-get",
            correlation=_service_values(),
            assertions=_assertions(effects, (STAGE_TRAFFIC_EFFECT_SCOPE,)),
        ),
        _evidence(
            action,
            evidence_id="revision-proof",
            capability="cloud-run-revision-get",
            correlation=_revision_values(),
            assertions=_assertions(
                effects,
                (STAGE_REVISION_EFFECT_SCOPE, STAGE_READINESS_EFFECT_SCOPE),
            ),
        ),
        _evidence(
            action,
            evidence_id="health-proof",
            capability="cloud-run-revision-health",
            correlation=_health_values(),
            assertions=_assertions(effects, (STAGE_READINESS_EFFECT_SCOPE,)),
        ),
    )
    return action, effects, evidence


def test_stage_commit_requires_collective_exact_provider_proof() -> None:
    action, effects, evidence = _stage_proof()

    validate_recovery_proof(
        STAGE_CLOUD_RUN_REVISION_PROFILE,
        action,
        effects,
        Classification.COMMITTED,
        evidence,
    )


def test_stage_proof_is_invariant_to_order_and_exact_duplicates() -> None:
    action, effects, evidence = _stage_proof()

    for ordered in permutations(evidence):
        validate_recovery_proof(
            STAGE_CLOUD_RUN_REVISION_PROFILE,
            action,
            effects,
            Classification.COMMITTED,
            ordered,
        )
    validate_recovery_proof(
        STAGE_CLOUD_RUN_REVISION_PROFILE,
        action,
        effects,
        Classification.COMMITTED,
        (*evidence, evidence[1]),
    )


@pytest.mark.parametrize(
    ("evidence_index", "updates"),
    (
        (0, {"service_etag": "etag-r7-2"}),
        (0, {"generation": "9", "observed_generation": "9"}),
        (1, {"generation": "2", "observed_generation": "2"}),
        (
            0,
            {
                "reconciling": "true",
                "terminal_condition": "NONE",
            },
        ),
    ),
)
def test_certifiable_proof_rejects_divergent_snapshots_of_same_resource(
    evidence_index: int,
    updates: dict[str, str],
) -> None:
    action, effects, evidence = _stage_proof()
    original = evidence[evidence_index]
    changed_values = {**original.correlation, **updates}
    changed = original.model_copy(
        update={
            "evidence_id": f"{original.evidence_id}-later",
            "correlation": changed_values,
            "effect_assertions": tuple(
                assertion.model_copy(update={"state": EffectAssertionState.UNVERIFIED})
                for assertion in original.effect_assertions
            ),
        }
    )

    with pytest.raises(RecoveryRuleViolation, match="inconsistent snapshots"):
        validate_recovery_proof(
            STAGE_CLOUD_RUN_REVISION_PROFILE,
            action,
            effects,
            Classification.COMMITTED,
            (*evidence, changed),
        )


def test_arbitrary_synthetic_normalizer_provenance_cannot_prove_stage() -> None:
    action, effects, evidence = _stage_proof()
    forged = evidence[1].model_copy(
        update={
            "provenance": evidence[1].provenance.model_copy(
                update={"source": "synthetic-test-provider"}
            )
        }
    )

    with pytest.raises(RecoveryRuleViolation, match="trusted provider adapter"):
        validate_recovery_proof(
            STAGE_CLOUD_RUN_REVISION_PROFILE,
            action,
            effects,
            Classification.COMMITTED,
            (evidence[0], forged, evidence[2]),
        )


@pytest.mark.parametrize(
    ("evidence_index", "field", "value", "message"),
    (
        (1, "release_label", "another-release", "release label"),
        (1, "image_digest", f"sha256:{'e' * 64}", "revision identity"),
        (1, "configuration_sha256", "f" * 64, "revision identity"),
        (1, "readiness", "NOT_READY", "typed provider observation"),
        (1, "observed_generation", "0", "typed provider observation"),
        (2, "health_status", "UNHEALTHY", "contradicts its typed observation"),
        (
            0,
            "revision_traffic_percent",
            "1",
            "contradicts its typed observation",
        ),
    ),
)
def test_stage_rejects_mismatched_or_unsettled_observations(
    evidence_index: int,
    field: str,
    value: str,
    message: str,
) -> None:
    action, effects, evidence = _stage_proof()
    changed_values = dict(evidence[evidence_index].correlation)
    changed_values[field] = value
    changed = evidence[evidence_index].model_copy(
        update={"correlation": changed_values}
    )
    candidate = tuple(
        changed if index == evidence_index else item
        for index, item in enumerate(evidence)
    )

    with pytest.raises(RecoveryRuleViolation, match=message):
        validate_recovery_proof(
            STAGE_CLOUD_RUN_REVISION_PROFILE,
            action,
            effects,
            Classification.COMMITTED,
            candidate,
        )


def test_stage_requires_successful_exact_revision_health() -> None:
    action, effects, evidence = _stage_proof()

    with pytest.raises(RecoveryRuleViolation, match="service, revision, and health"):
        validate_recovery_proof(
            STAGE_CLOUD_RUN_REVISION_PROFILE,
            action,
            effects,
            Classification.COMMITTED,
            evidence[:2],
        )


def test_stage_requires_sealed_expected_effect_predicates() -> None:
    effects = list(_effects(STAGE_CLOUD_RUN_REVISION_PROFILE_VERSION))
    effects[2] = effects[2].model_copy(
        update={"predicate": {"release_id": RELEASE_ID, "traffic_percent": 1}}
    )
    action, changed_effects = _action(
        STAGE_CLOUD_RUN_REVISION_PROFILE_VERSION,
        tuple(effects),
    )
    _, _, evidence = _stage_proof()
    rebound = tuple(
        item.model_copy(update={"target": action.target}) for item in evidence
    )

    with pytest.raises(RecoveryRuleViolation, match="expected-effect predicates"):
        validate_recovery_proof(
            STAGE_CLOUD_RUN_REVISION_PROFILE,
            action,
            changed_effects,
            Classification.COMMITTED,
            rebound,
        )


def test_promotion_commit_requires_settled_exact_100_percent_traffic() -> None:
    action, effects = _action(PROMOTE_CLOUD_RUN_TRAFFIC_PROFILE_VERSION)
    service = _evidence(
        action,
        evidence_id="promotion-service-proof",
        capability="cloud-run-service-get",
        correlation=_service_values(percent="100"),
        assertions=_assertions(effects, (PROMOTION_TRAFFIC_EFFECT_SCOPE,)),
    )

    validate_recovery_proof(
        PROMOTE_CLOUD_RUN_TRAFFIC_PROFILE,
        action,
        effects,
        Classification.COMMITTED,
        (service,),
    )


@pytest.mark.parametrize(
    ("field", "value"),
    (
        ("revision", "another-revision"),
        ("revision_traffic_percent", "99"),
        ("observed_generation", "7"),
        ("reconciling", "true"),
    ),
)
def test_promotion_rejects_wrong_or_unsettled_traffic(
    field: str,
    value: str,
) -> None:
    action, effects = _action(PROMOTE_CLOUD_RUN_TRAFFIC_PROFILE_VERSION)
    values = _service_values(percent="100")
    values[field] = value
    service = _evidence(
        action,
        evidence_id="promotion-service-proof",
        capability="cloud-run-service-get",
        correlation=values,
        assertions=_assertions(effects, (PROMOTION_TRAFFIC_EFFECT_SCOPE,)),
    )

    with pytest.raises(RecoveryRuleViolation):
        validate_recovery_proof(
            PROMOTE_CLOUD_RUN_TRAFFIC_PROFILE,
            action,
            effects,
            Classification.COMMITTED,
            (service,),
        )


def test_promotion_requires_typed_etag_evidence() -> None:
    action, effects = _action(PROMOTE_CLOUD_RUN_TRAFFIC_PROFILE_VERSION)
    values = _service_values(percent="100")
    values.pop("service_etag")
    service = _evidence(
        action,
        evidence_id="promotion-no-etag",
        capability="cloud-run-service-get",
        correlation=values,
        assertions=_assertions(effects, (PROMOTION_TRAFFIC_EFFECT_SCOPE,)),
    )

    with pytest.raises(RecoveryRuleViolation, match="typed provider observation"):
        validate_recovery_proof(
            PROMOTE_CLOUD_RUN_TRAFFIC_PROFILE,
            action,
            effects,
            Classification.COMMITTED,
            (service,),
        )


def test_cloud_run_operation_failure_cannot_prove_not_committed() -> None:
    action, effects = _action(STAGE_CLOUD_RUN_REVISION_PROFILE_VERSION)
    operation = _evidence(
        action,
        evidence_id="failed-operation",
        capability="cloud-run-operation-get",
        correlation=_operation_values(state="FAILED"),
        assertions=tuple(
            EffectAssertion(
                effect_id=item.effect_id,
                state=EffectAssertionState.UNVERIFIED,
            )
            for item in effects
        ),
        operation_status=OperationStatus.UNRESOLVED,
    )

    with pytest.raises(RecoveryRuleViolation, match="positive pre-provider receipt"):
        validate_recovery_proof(
            STAGE_CLOUD_RUN_REVISION_PROFILE,
            action,
            effects,
            Classification.NOT_COMMITTED,
            (operation,),
        )


@pytest.mark.parametrize(
    "operation_name",
    (
        "projects/foreign-project/locations/us-central1/operations/op-7",
        "projects/demo-project/locations/europe-west1/operations/op-7",
    ),
)
def test_cloud_run_operation_name_is_scoped_to_action_project_and_location(
    operation_name: str,
) -> None:
    action, effects = _action(STAGE_CLOUD_RUN_REVISION_PROFILE_VERSION)
    operation = _evidence(
        action,
        evidence_id="foreign-operation",
        capability="cloud-run-operation-get",
        correlation=_operation_values(
            state="RUNNING",
            operation_name=operation_name,
        ),
        assertions=_assertions(
            effects,
            (STAGE_REVISION_EFFECT_SCOPE,),
            EffectAssertionState.UNVERIFIED,
        ),
        operation_status=OperationStatus.ACTIVE,
        source_record=operation_name,
    )

    with pytest.raises(RecoveryRuleViolation, match="exact action project"):
        validate_recovery_proof(
            STAGE_CLOUD_RUN_REVISION_PROFILE,
            action,
            effects,
            Classification.UNKNOWN,
            (operation,),
        )


def test_cloud_run_operation_source_record_is_scoped_to_typed_operation() -> None:
    action, effects = _action(STAGE_CLOUD_RUN_REVISION_PROFILE_VERSION)
    operation = _evidence(
        action,
        evidence_id="foreign-operation-source-record",
        capability="cloud-run-operation-get",
        correlation=_operation_values(state="RUNNING"),
        assertions=_assertions(
            effects,
            (STAGE_REVISION_EFFECT_SCOPE,),
            EffectAssertionState.UNVERIFIED,
        ),
        operation_status=OperationStatus.ACTIVE,
        source_record=(
            "projects/foreign-project/locations/us-central1/operations/op-7"
        ),
    )

    with pytest.raises(RecoveryRuleViolation, match="exact action target"):
        validate_recovery_proof(
            STAGE_CLOUD_RUN_REVISION_PROFILE,
            action,
            effects,
            Classification.UNKNOWN,
            (operation,),
        )


def test_successful_stage_operation_can_support_collective_provider_proof() -> None:
    action, effects, evidence = _stage_proof()
    operation = _evidence(
        action,
        evidence_id="successful-stage-operation",
        capability="cloud-run-operation-get",
        correlation=_operation_values(state="SUCCEEDED"),
        assertions=_assertions(effects, (STAGE_REVISION_EFFECT_SCOPE,)),
        operation_status=OperationStatus.TERMINAL_COMMITTED,
    )

    validate_recovery_proof(
        STAGE_CLOUD_RUN_REVISION_PROFILE,
        action,
        effects,
        Classification.COMMITTED,
        (*evidence, operation),
    )

    with pytest.raises(RecoveryRuleViolation, match="every declared effect"):
        validate_recovery_proof(
            STAGE_CLOUD_RUN_REVISION_PROFILE,
            action,
            effects,
            Classification.COMMITTED,
            (operation,),
        )


def test_cloud_run_operation_polling_allows_running_then_succeeded() -> None:
    action, effects, evidence = _stage_proof()
    running = _evidence(
        action,
        evidence_id="running-stage-operation",
        capability="cloud-run-operation-get",
        correlation=_operation_values(state="RUNNING"),
        assertions=tuple(
            EffectAssertion(
                effect_id=item.effect_id,
                state=EffectAssertionState.UNVERIFIED,
            )
            for item in effects
        ),
        operation_status=OperationStatus.ACTIVE,
    ).model_copy(
        update={
            "observed_at": NOW + timedelta(seconds=1),
            "provenance": EvidenceProvenance(
                source=CLOUD_RUN_PROVIDER_SOURCE,
                source_record=_operation_values(state="RUNNING")["operation_name"],
                adapter_version=CLOUD_RUN_PROVIDER_ADAPTER_VERSION,
                retrieved_at=NOW + timedelta(seconds=2),
            ),
        }
    )
    succeeded = _evidence(
        action,
        evidence_id="succeeded-stage-operation",
        capability="cloud-run-operation-get",
        correlation=_operation_values(state="SUCCEEDED"),
        assertions=_assertions(effects, (STAGE_REVISION_EFFECT_SCOPE,)),
        operation_status=OperationStatus.TERMINAL_COMMITTED,
    ).model_copy(
        update={
            "observed_at": NOW + timedelta(seconds=3),
            "provenance": EvidenceProvenance(
                source=CLOUD_RUN_PROVIDER_SOURCE,
                source_record=_operation_values(state="SUCCEEDED")["operation_name"],
                adapter_version=CLOUD_RUN_PROVIDER_ADAPTER_VERSION,
                retrieved_at=NOW + timedelta(seconds=4),
            ),
        }
    )

    validate_recovery_proof(
        STAGE_CLOUD_RUN_REVISION_PROFILE,
        action,
        effects,
        Classification.COMMITTED,
        (*evidence, succeeded, running),
    )


@pytest.mark.parametrize(
    ("earlier_state", "earlier_status", "later_state", "later_status"),
    (
        (
            "SUCCEEDED",
            OperationStatus.TERMINAL_COMMITTED,
            "RUNNING",
            OperationStatus.ACTIVE,
        ),
        (
            "FAILED",
            OperationStatus.UNRESOLVED,
            "SUCCEEDED",
            OperationStatus.TERMINAL_COMMITTED,
        ),
    ),
)
def test_cloud_run_operation_polling_rejects_regression_or_terminal_disagreement(
    earlier_state: str,
    earlier_status: OperationStatus,
    later_state: str,
    later_status: OperationStatus,
) -> None:
    action, effects, evidence = _stage_proof()

    def operation(
        *, evidence_id: str, state: str, status: OperationStatus, observed_at: datetime
    ) -> NormalizedEvidence:
        assertions = (
            _assertions(effects, (STAGE_REVISION_EFFECT_SCOPE,))
            if state == "SUCCEEDED"
            else tuple(
                EffectAssertion(
                    effect_id=item.effect_id,
                    state=EffectAssertionState.UNVERIFIED,
                )
                for item in effects
            )
        )
        return _evidence(
            action,
            evidence_id=evidence_id,
            capability="cloud-run-operation-get",
            correlation=_operation_values(state=state),
            assertions=assertions,
            operation_status=status,
        ).model_copy(update={"observed_at": observed_at})

    earlier = operation(
        evidence_id="earlier-operation",
        state=earlier_state,
        status=earlier_status,
        observed_at=NOW + timedelta(seconds=1),
    )
    later = operation(
        evidence_id="later-operation",
        state=later_state,
        status=later_status,
        observed_at=NOW + timedelta(seconds=3),
    )

    with pytest.raises(RecoveryRuleViolation, match="regress or disagree"):
        validate_recovery_proof(
            STAGE_CLOUD_RUN_REVISION_PROFILE,
            action,
            effects,
            Classification.COMMITTED,
            (*evidence, earlier, later),
        )


def test_successful_promotion_operation_can_support_collective_provider_proof() -> None:
    action, effects = _action(PROMOTE_CLOUD_RUN_TRAFFIC_PROFILE_VERSION)
    service = _evidence(
        action,
        evidence_id="promotion-service-proof",
        capability="cloud-run-service-get",
        correlation=_service_values(percent="100"),
        assertions=_assertions(effects, (PROMOTION_TRAFFIC_EFFECT_SCOPE,)),
    )
    operation = _evidence(
        action,
        evidence_id="successful-promotion-operation",
        capability="cloud-run-operation-get",
        correlation=_operation_values(state="SUCCEEDED"),
        assertions=_assertions(effects, (PROMOTION_TRAFFIC_EFFECT_SCOPE,)),
        operation_status=OperationStatus.TERMINAL_COMMITTED,
    )

    validate_recovery_proof(
        PROMOTE_CLOUD_RUN_TRAFFIC_PROFILE,
        action,
        effects,
        Classification.COMMITTED,
        (service, operation),
    )

    with pytest.raises(RecoveryRuleViolation, match="promotion requires settled"):
        validate_recovery_proof(
            PROMOTE_CLOUD_RUN_TRAFFIC_PROFILE,
            action,
            effects,
            Classification.COMMITTED,
            (operation,),
        )


@pytest.mark.parametrize(
    ("operation_state", "operation_status"),
    (
        ("RUNNING", OperationStatus.ACTIVE),
        ("FAILED", OperationStatus.UNRESOLVED),
    ),
)
def test_non_successful_operations_cannot_establish_effects(
    operation_state: str,
    operation_status: OperationStatus,
) -> None:
    action, effects = _action(STAGE_CLOUD_RUN_REVISION_PROFILE_VERSION)
    operation = _evidence(
        action,
        evidence_id=f"{operation_state.lower()}-operation",
        capability="cloud-run-operation-get",
        correlation=_operation_values(state=operation_state),
        assertions=_assertions(effects, (STAGE_REVISION_EFFECT_SCOPE,)),
        operation_status=operation_status,
    )

    with pytest.raises(RecoveryRuleViolation, match="cannot establish effects"):
        validate_recovery_proof(
            STAGE_CLOUD_RUN_REVISION_PROFILE,
            action,
            effects,
            Classification.UNKNOWN,
            (operation,),
        )


def test_successful_operation_requires_at_least_one_established_effect() -> None:
    action, effects = _action(STAGE_CLOUD_RUN_REVISION_PROFILE_VERSION)
    operation = _evidence(
        action,
        evidence_id="successful-operation-without-proof",
        capability="cloud-run-operation-get",
        correlation=_operation_values(state="SUCCEEDED"),
        assertions=_assertions(
            effects,
            (STAGE_REVISION_EFFECT_SCOPE,),
            EffectAssertionState.UNVERIFIED,
        ),
        operation_status=OperationStatus.TERMINAL_COMMITTED,
    )

    with pytest.raises(RecoveryRuleViolation, match="must establish an effect"):
        validate_recovery_proof(
            STAGE_CLOUD_RUN_REVISION_PROFILE,
            action,
            effects,
            Classification.UNKNOWN,
            (operation,),
        )


def test_successful_operation_requires_terminal_committed_status() -> None:
    action, effects = _action(STAGE_CLOUD_RUN_REVISION_PROFILE_VERSION)
    operation = _evidence(
        action,
        evidence_id="successful-operation-active-status",
        capability="cloud-run-operation-get",
        correlation=_operation_values(state="SUCCEEDED"),
        assertions=_assertions(effects, (STAGE_REVISION_EFFECT_SCOPE,)),
        operation_status=OperationStatus.ACTIVE,
    )

    with pytest.raises(RecoveryRuleViolation, match="inconsistent proof semantics"):
        validate_recovery_proof(
            STAGE_CLOUD_RUN_REVISION_PROFILE,
            action,
            effects,
            Classification.UNKNOWN,
            (operation,),
        )


def test_successful_operation_cannot_assert_stage_readiness() -> None:
    action, effects = _action(STAGE_CLOUD_RUN_REVISION_PROFILE_VERSION)
    operation = _evidence(
        action,
        evidence_id="successful-operation-overclaim",
        capability="cloud-run-operation-get",
        correlation=_operation_values(state="SUCCEEDED"),
        assertions=_assertions(effects, (STAGE_READINESS_EFFECT_SCOPE,)),
        operation_status=OperationStatus.TERMINAL_COMMITTED,
    )

    with pytest.raises(RecoveryRuleViolation, match="outside its authority"):
        validate_recovery_proof(
            STAGE_CLOUD_RUN_REVISION_PROFILE,
            action,
            effects,
            Classification.UNKNOWN,
            (operation,),
        )


def _firestore_get(
    action: SemanticActionIdentity,
    effects: tuple[ExpectedEffect, ...],
    *,
    exists: str,
    cloud_run_revision: str = REVISION,
) -> NormalizedEvidence:
    return _evidence(
        action,
        evidence_id=f"firestore-exists-{exists}",
        capability="firestore-release-record-get",
        correlation={
            "observation_schema": FIRESTORE_DOCUMENT_OBSERVATION_VERSION,
            "release_id": RELEASE_ID,
            "cloud_run_revision": cloud_run_revision,
            "payload_sha256": PAYLOAD_SHA256,
            "semantic_action_sha256": action.semantic_action_sha256,
            "exists": exists,
        },
        assertions=_assertions(
            effects,
            (FIRESTORE_RECORD_EFFECT_SCOPE,),
            (
                EffectAssertionState.ESTABLISHED
                if exists == "true"
                else EffectAssertionState.UNVERIFIED
            ),
        ),
    )


def test_firestore_exact_document_can_prove_commit() -> None:
    action, effects = _action(CREATE_FIRESTORE_RELEASE_RECORD_PROFILE_VERSION)

    validate_recovery_proof(
        CREATE_FIRESTORE_RELEASE_RECORD_PROFILE,
        action,
        effects,
        Classification.COMMITTED,
        (_firestore_get(action, effects, exists="true"),),
    )


def test_firestore_enhanced_effect_rejects_a_record_for_another_revision() -> None:
    effects = tuple(
        effect.model_copy(
            update={
                "predicate": {
                    **effect.predicate,
                    "cloud_run_revision": REVISION,
                }
            }
        )
        for effect in _effects(CREATE_FIRESTORE_RELEASE_RECORD_PROFILE_VERSION)
    )
    action, effects = _action(
        CREATE_FIRESTORE_RELEASE_RECORD_PROFILE_VERSION,
        effects,
    )

    validate_recovery_proof(
        CREATE_FIRESTORE_RELEASE_RECORD_PROFILE,
        action,
        effects,
        Classification.COMMITTED,
        (_firestore_get(action, effects, exists="true"),),
    )
    with pytest.raises(RecoveryRuleViolation, match="intended Cloud Run revision"):
        validate_recovery_proof(
            CREATE_FIRESTORE_RELEASE_RECORD_PROFILE,
            action,
            effects,
            Classification.COMMITTED,
            (
                _firestore_get(
                    action,
                    effects,
                    exists="true",
                    cloud_run_revision="reconcile-canary-wrong",
                ),
            ),
        )


def test_firestore_get_not_found_remains_unknown_not_nonexecution_proof() -> None:
    action, effects = _action(CREATE_FIRESTORE_RELEASE_RECORD_PROFILE_VERSION)
    absence = _firestore_get(action, effects, exists="false")

    validate_recovery_proof(
        CREATE_FIRESTORE_RELEASE_RECORD_PROFILE,
        action,
        effects,
        Classification.UNKNOWN,
        (absence,),
    )
    with pytest.raises(RecoveryRuleViolation, match="positive pre-provider receipt"):
        validate_recovery_proof(
            CREATE_FIRESTORE_RELEASE_RECORD_PROFILE,
            action,
            effects,
            Classification.NOT_COMMITTED,
            (absence,),
        )


@pytest.mark.parametrize(
    "outcome",
    (
        "SUPPRESSED_BEFORE_DISPATCH",
        "AUTHORITATIVE_REJECTION_BEFORE_PROVIDER_CONTACT",
    ),
)
def test_firestore_retry_requires_typed_positive_dispatch_receipt(outcome: str) -> None:
    action, effects = _action(CREATE_FIRESTORE_RELEASE_RECORD_PROFILE_VERSION)
    receipt = _evidence(
        action,
        evidence_id=f"receipt-{outcome.lower()}",
        capability="reconcile-dispatch-receipt-get",
        correlation={
            "observation_schema": DISPATCH_RECEIPT_OBSERVATION_VERSION,
            "release_id": RELEASE_ID,
            "semantic_action_sha256": action.semantic_action_sha256,
            "receipt_id": "receipt-7",
            "provider_contact": "false",
            "outcome": outcome,
        },
        assertions=_assertions(
            effects,
            (FIRESTORE_RECORD_EFFECT_SCOPE,),
            EffectAssertionState.NOT_ESTABLISHED,
        ),
        operation_status=OperationStatus.TERMINAL_NOT_COMMITTED,
    )

    validate_recovery_proof(
        CREATE_FIRESTORE_RELEASE_RECORD_PROFILE,
        action,
        effects,
        Classification.NOT_COMMITTED,
        (receipt,),
    )


@pytest.mark.parametrize(
    ("field", "value"),
    (
        ("provider_contact", "true"),
        ("semantic_action_sha256", "e" * 64),
        ("release_id", "another-release"),
    ),
)
def test_firestore_receipt_rejects_replay_or_provider_contact(
    field: str,
    value: str,
) -> None:
    action, effects = _action(CREATE_FIRESTORE_RELEASE_RECORD_PROFILE_VERSION)
    values = {
        "observation_schema": DISPATCH_RECEIPT_OBSERVATION_VERSION,
        "release_id": RELEASE_ID,
        "semantic_action_sha256": action.semantic_action_sha256,
        "receipt_id": "receipt-7",
        "provider_contact": "false",
        "outcome": "SUPPRESSED_BEFORE_DISPATCH",
    }
    values[field] = value
    receipt = _evidence(
        action,
        evidence_id="receipt-replay-attempt",
        capability="reconcile-dispatch-receipt-get",
        correlation=values,
        assertions=_assertions(
            effects,
            (FIRESTORE_RECORD_EFFECT_SCOPE,),
            EffectAssertionState.NOT_ESTABLISHED,
        ),
        operation_status=OperationStatus.TERMINAL_NOT_COMMITTED,
    )

    with pytest.raises(RecoveryRuleViolation):
        validate_recovery_proof(
            CREATE_FIRESTORE_RELEASE_RECORD_PROFILE,
            action,
            effects,
            Classification.NOT_COMMITTED,
            (receipt,),
        )


def test_source_record_must_name_the_exact_target_resource() -> None:
    action, effects = _action(PROMOTE_CLOUD_RUN_TRAFFIC_PROFILE_VERSION)
    service = _evidence(
        action,
        evidence_id="wrong-service-record",
        capability="cloud-run-service-get",
        correlation=_service_values(percent="100"),
        assertions=_assertions(effects, (PROMOTION_TRAFFIC_EFFECT_SCOPE,)),
        source_record=(
            "projects/demo-project/locations/us-central1/services/another-service"
        ),
    )

    with pytest.raises(RecoveryRuleViolation, match="exact action target"):
        validate_recovery_proof(
            PROMOTE_CLOUD_RUN_TRAFFIC_PROFILE,
            action,
            effects,
            Classification.COMMITTED,
            (service,),
        )
