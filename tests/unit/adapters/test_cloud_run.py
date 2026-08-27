from __future__ import annotations

import hashlib
from datetime import UTC, datetime, timedelta

import pytest
from google.api_core import exceptions as api_exceptions
from google.cloud import run_v2
from google.longrunning import operations_pb2
from google.protobuf import any_pb2

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
from reconcile.contracts import (
    EXECUTION_ENVELOPE_VERSION,
    EXPECTED_EFFECT_VERSION,
    PROBE_REQUEST_VERSION,
    AmbiguityKind,
    AmbiguousExecution,
    CapabilityRef,
    EffectAssertionState,
    EnvelopeContext,
    EvidenceBudget,
    EvidenceReason,
    ExecutionEnvelope,
    ExpectedEffect,
    FreshnessPolicy,
    OperationStatus,
    OriginalInvocation,
    PolicyReferences,
    ProbeRequest,
    canonical_json_bytes,
)
from reconcile.contracts.base import canonical_json_value_bytes
from reconcile.controller import BoundProbe, CapabilitySemantics, ProbeObservation
from reconcile.evidence import RuleInput, RuleRejected, RuleVerdict
from reconcile.evidence.recovery_rules import (
    CLOUD_RUN_HEALTH_ADAPTER_VERSION,
    CLOUD_RUN_HEALTH_OBSERVATION_VERSION,
    CLOUD_RUN_HEALTH_SOURCE,
    CLOUD_RUN_OPERATION_OBSERVATION_VERSION,
    CLOUD_RUN_PROVIDER_ADAPTER_VERSION,
    CLOUD_RUN_PROVIDER_SOURCE,
    CLOUD_RUN_REVISION_OBSERVATION_VERSION,
    CLOUD_RUN_SERVICE_OBSERVATION_VERSION,
    PROMOTION_TRAFFIC_EFFECT_SCOPE,
    STAGE_READINESS_EFFECT_SCOPE,
    STAGE_REVISION_EFFECT_SCOPE,
    STAGE_TRAFFIC_EFFECT_SCOPE,
)
from reconcile.hosted.cloud_run_canary import (
    CloudRunCanaryReader,
    CloudRunCanaryTarget,
)

pytestmark = pytest.mark.unit

NOW = datetime(2026, 8, 22, 12, 0, tzinfo=UTC)
RELEASE = "release-7"
REVISION = "reconcile-canary-r-3997240d56d5ff06"
DIGEST = f"sha256:{'a' * 64}"
CONFIGURATION = "b" * 64
OPERATION = "projects/demo-project/locations/us-central1/operations/op-7"


def _target():
    return build_cloud_run_target(
        project="demo-project",
        location="us-central1",
        service="reconcile-canary",
    )


def _binding() -> CloudRunProbeBinding:
    return CloudRunProbeBinding.for_stage(
        release_id=RELEASE,
        image_digest=DIGEST,
        configuration_sha256=CONFIGURATION,
        expected_revision=REVISION,
    )


def _effects(stage: bool = True) -> tuple[ExpectedEffect, ...]:
    definitions = (
        (
            "revision-created",
            STAGE_REVISION_EFFECT_SCOPE,
            {
                "release_id": RELEASE,
                "image_digest": DIGEST,
                "configuration_sha256": CONFIGURATION,
                "revision": REVISION,
            },
        ),
        (
            "revision-ready",
            STAGE_READINESS_EFFECT_SCOPE,
            {"release_id": RELEASE, "ready": True, "revision": REVISION},
        ),
        (
            "revision-zero-traffic",
            STAGE_TRAFFIC_EFFECT_SCOPE,
            {
                "release_id": RELEASE,
                "traffic_percent": 0,
                "revision": REVISION,
            },
        ),
    )
    if not stage:
        definitions = (
            (
                "traffic-promoted",
                PROMOTION_TRAFFIC_EFFECT_SCOPE,
                {"release_id": RELEASE, "revision": REVISION, "percent": 100},
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


def _envelope(*, stage: bool = True) -> ExecutionEnvelope:
    effects = _effects(stage)
    arguments: dict[str, object]
    if stage:
        tool_name = "stage-cloud-run-revision"
        arguments = {
            "release_id": RELEASE,
            "image_digest": DIGEST,
            "configuration_sha256": CONFIGURATION,
        }
    else:
        tool_name = "promote-cloud-run-traffic"
        arguments = {"release_id": RELEASE, "revision": REVISION, "percent": 100}
    return ExecutionEnvelope(
        schema_version=EXECUTION_ENVELOPE_VERSION,
        investigation_id="investigation-7",
        operation_id="operation-7",
        target=_target(),
        invoked_at=NOW,
        ambiguity=AmbiguousExecution(
            kind=AmbiguityKind.MISSING_TOOL_RESULT,
            observed_at=NOW,
            detail="Provider acceptance was not delivered.",
        ),
        expected_effects=effects,
        context=EnvelopeContext(
            invocation=OriginalInvocation(
                invocation_id="invocation-7",
                function_call_id="call-7",
                tool_name=tool_name,
                tool_version="1.0.0",
                arguments=arguments,
                arguments_sha256=hashlib.sha256(
                    canonical_json_value_bytes(arguments)
                ).hexdigest(),
            ),
            enabled_capabilities=tuple(
                CapabilityRef(name=name, version="1.0.0")
                for name in (
                    CLOUD_RUN_SERVICE_CAPABILITY,
                    CLOUD_RUN_REVISION_CAPABILITY,
                    CLOUD_RUN_OPERATION_CAPABILITY,
                    CLOUD_RUN_HEALTH_CAPABILITY,
                )
            ),
            correlation_fields={"release_id": RELEASE},
            evidence_budget=EvidenceBudget(
                max_probes=8,
                max_elapsed_ms=30_000,
                max_total_result_bytes=65_536,
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


def _rule_input(
    *,
    capability: str,
    payload: dict[str, object],
    relevant_effect_ids: tuple[str, ...],
    envelope: ExecutionEnvelope | None = None,
    observed_at: datetime = NOW + timedelta(seconds=1),
) -> RuleInput:
    selected = envelope or _envelope()
    return RuleInput(
        envelope=selected,
        request=ProbeRequest(
            schema_version=PROBE_REQUEST_VERSION,
            capability_name=capability,
            capability_version="1.0.0",
            relevant_effect_ids=relevant_effect_ids,
            arguments={},
            rationale="Read exact provider state.",
        ),
        observation=canonical_json_bytes(
            ProbeObservation(observed_at=observed_at, payload=payload)
        ),
        retrieved_at=NOW + timedelta(seconds=2),
    )


def test_capability_inventory_is_read_only_empty_argument_and_exact_target() -> None:
    for name in (
        CLOUD_RUN_SERVICE_CAPABILITY,
        CLOUD_RUN_REVISION_CAPABILITY,
        CLOUD_RUN_OPERATION_CAPABILITY,
        CLOUD_RUN_HEALTH_CAPABILITY,
    ):
        capability = build_cloud_run_capability(
            capability_name=name,
            target=_target(),
        )
        assert capability.read_only is True
        assert capability.argument_schema["properties"] == {}
        assert capability.allowed_targets[0].scope == {
            "project": "demo-project",
            "location": "us-central1",
        }


def test_service_normalizer_emits_exact_provider_provenance_and_correlation() -> None:
    envelope = _envelope()
    effect_id = next(
        effect.effect_id
        for effect in envelope.expected_effects
        if effect.commit_scope == STAGE_TRAFFIC_EFFECT_SCOPE
    )
    payload = {
        "observation": {
            "observation_schema": CLOUD_RUN_SERVICE_OBSERVATION_VERSION,
            "release_id": RELEASE,
            "revision": REVISION,
            "service_etag": "etag-7",
            "generation": "8",
            "observed_generation": "8",
            "reconciling": "false",
            "terminal_condition": "SUCCEEDED",
            "revision_traffic_percent": "0",
        }
    }
    registration = build_cloud_run_rule_registration(
        capability_name=CLOUD_RUN_SERVICE_CAPABILITY,
        binding=_binding(),
    )

    result = registration.normalizer(
        _rule_input(
            capability=CLOUD_RUN_SERVICE_CAPABILITY,
            payload=payload,
            relevant_effect_ids=(effect_id,),
            envelope=envelope,
        )
    )

    assert registration.descriptor.source == CLOUD_RUN_PROVIDER_SOURCE
    assert registration.descriptor.adapter_version == CLOUD_RUN_PROVIDER_ADAPTER_VERSION
    assert result.target == envelope.target
    assert result.source_record.endswith("/services/reconcile-canary")
    assert result.observed_at == NOW + timedelta(seconds=1)
    assert result.operation_id == envelope.operation_id
    assert result.correlation == payload["observation"]
    assert result.effect_assertions[0].state is EffectAssertionState.ESTABLISHED
    assert result.verdict is RuleVerdict.AUTHORITATIVE_EFFECTS


def test_revision_failure_is_mixed_effect_evidence_not_non_execution() -> None:
    envelope = _envelope()
    effect_ids = tuple(
        effect.effect_id
        for effect in envelope.expected_effects
        if effect.commit_scope
        in {STAGE_REVISION_EFFECT_SCOPE, STAGE_READINESS_EFFECT_SCOPE}
    )
    result = build_cloud_run_rule_registration(
        capability_name=CLOUD_RUN_REVISION_CAPABILITY,
        binding=_binding(),
    ).normalizer(
        _rule_input(
            capability=CLOUD_RUN_REVISION_CAPABILITY,
            relevant_effect_ids=effect_ids,
            payload={
                "observation": {
                    "observation_schema": CLOUD_RUN_REVISION_OBSERVATION_VERSION,
                    "release_id": RELEASE,
                    "release_label": RELEASE,
                    "revision": REVISION,
                    "image_digest": DIGEST,
                    "configuration_sha256": CONFIGURATION,
                    "generation": "1",
                    "observed_generation": "1",
                    "reconciling": "false",
                    "terminal_condition": "FAILED",
                    "readiness": "NOT_READY",
                }
            },
            envelope=envelope,
        )
    )

    assert {item.state for item in result.effect_assertions} == {
        EffectAssertionState.ESTABLISHED,
        EffectAssertionState.NOT_ESTABLISHED,
    }
    assert result.operation_status is None
    assert result.verdict is RuleVerdict.AUTHORITATIVE_EFFECTS


def test_reconciling_revision_is_authoritative_pending_without_operation_name() -> None:
    envelope = _envelope()
    effect_ids = tuple(
        effect.effect_id
        for effect in envelope.expected_effects
        if effect.commit_scope
        in {STAGE_REVISION_EFFECT_SCOPE, STAGE_READINESS_EFFECT_SCOPE}
    )

    result = build_cloud_run_rule_registration(
        capability_name=CLOUD_RUN_REVISION_CAPABILITY,
        binding=_binding(),
    ).normalizer(
        _rule_input(
            capability=CLOUD_RUN_REVISION_CAPABILITY,
            relevant_effect_ids=effect_ids,
            payload={
                "observation": {
                    "observation_schema": CLOUD_RUN_REVISION_OBSERVATION_VERSION,
                    "release_id": RELEASE,
                    "release_label": RELEASE,
                    "revision": REVISION,
                    "image_digest": DIGEST,
                    "configuration_sha256": CONFIGURATION,
                    "generation": "1",
                    "observed_generation": "0",
                    "reconciling": "true",
                    "terminal_condition": "NONE",
                    "readiness": "UNKNOWN",
                }
            },
            envelope=envelope,
        )
    )

    assert result.verdict is RuleVerdict.AUTHORITATIVE_PENDING
    assert result.operation_status is OperationStatus.ACTIVE
    assert tuple(item.state for item in result.effect_assertions) == (
        EffectAssertionState.ESTABLISHED,
        EffectAssertionState.UNVERIFIED,
    )


def test_failed_operation_stays_unresolved_and_never_proves_non_execution() -> None:
    envelope = _envelope()
    effect_id = envelope.expected_effects[0].effect_id
    binding = CloudRunProbeBinding.for_stage(
        release_id=RELEASE,
        image_digest=DIGEST,
        configuration_sha256=CONFIGURATION,
        operation_name=OPERATION,
        operation_revision=REVISION,
    )
    result = build_cloud_run_rule_registration(
        capability_name=CLOUD_RUN_OPERATION_CAPABILITY,
        binding=binding,
    ).normalizer(
        _rule_input(
            capability=CLOUD_RUN_OPERATION_CAPABILITY,
            relevant_effect_ids=(effect_id,),
            envelope=envelope,
            payload={
                "observation": {
                    "observation_schema": CLOUD_RUN_OPERATION_OBSERVATION_VERSION,
                    "release_id": RELEASE,
                    "revision": REVISION,
                    "operation_name": OPERATION,
                    "operation_state": "FAILED",
                }
            },
        )
    )

    assert result.verdict is RuleVerdict.AUTHORITATIVE_PENDING
    assert result.operation_status.value == "UNRESOLVED"
    assert result.effect_assertions[0].state is EffectAssertionState.UNVERIFIED


def test_successful_operation_is_weak_when_requested_effect_is_outside_its_authority() -> (
    None
):
    envelope = _envelope()
    readiness = next(
        effect.effect_id
        for effect in envelope.expected_effects
        if effect.commit_scope == STAGE_READINESS_EFFECT_SCOPE
    )
    binding = CloudRunProbeBinding.for_stage(
        release_id=RELEASE,
        image_digest=DIGEST,
        configuration_sha256=CONFIGURATION,
        operation_name=OPERATION,
        operation_revision=REVISION,
    )
    result = build_cloud_run_rule_registration(
        capability_name=CLOUD_RUN_OPERATION_CAPABILITY,
        binding=binding,
    ).normalizer(
        _rule_input(
            capability=CLOUD_RUN_OPERATION_CAPABILITY,
            relevant_effect_ids=(readiness,),
            envelope=envelope,
            payload={
                "observation": {
                    "observation_schema": CLOUD_RUN_OPERATION_OBSERVATION_VERSION,
                    "release_id": RELEASE,
                    "revision": REVISION,
                    "operation_name": OPERATION,
                    "operation_state": "SUCCEEDED",
                }
            },
        )
    )

    assert result.verdict is RuleVerdict.ABSENCE_ONLY
    assert result.operation_status is None
    assert result.effect_assertions[0].state is EffectAssertionState.UNVERIFIED


def test_expected_revision_read_does_not_wait_for_list_visibility() -> None:
    class Services:
        pass

    class Revisions:
        def list_revisions(self, **_: object) -> tuple[()]:
            raise AssertionError("an exact expected revision must be read directly")

        def get_revision(self, **kwargs: object) -> run_v2.Revision:
            request = kwargs["request"]
            assert request.name.endswith(f"/revisions/{REVISION}")
            return run_v2.Revision(
                name=request.name,
                service="reconcile-canary",
                generation=1,
                observed_generation=1,
                labels={"reconcile-release": RELEASE},
                annotations={"reconcile.dev/configuration-sha256": CONFIGURATION},
                containers=(
                    run_v2.Container(
                        image=(
                            "us-central1-docker.pkg.dev/demo-project/"
                            f"reconcile-p5/reconcile@{DIGEST}"
                        )
                    ),
                ),
                conditions=(
                    run_v2.Condition(
                        type_="Ready",
                        state=run_v2.Condition.State.CONDITION_SUCCEEDED,
                    ),
                ),
            )

    target = CloudRunCanaryTarget(
        project="demo-project",
        location="us-central1",
        service="reconcile-canary",
        image_repository=(
            "us-central1-docker.pkg.dev/demo-project/reconcile-p5/reconcile"
        ),
        baseline_revision="reconcile-canary-baseline",
        health_audience="https://canary.example.test",
    )
    reader = CloudRunCanaryReader(
        target=target,
        services_factory=Services,
        revisions_factory=Revisions,
        clock=lambda: NOW + timedelta(seconds=1),
    )
    registration = build_cloud_run_capability_registration(
        reader=reader,
        binding=_binding(),
        capability_name=CLOUD_RUN_REVISION_CAPABILITY,
        target=_target(),
        clock=lambda: NOW + timedelta(seconds=1),
    )
    assert registration.semantics is CapabilitySemantics.READ_ONLY
    assert registration.handler is not None
    envelope = _envelope()
    probe = BoundProbe(
        investigation_id=envelope.investigation_id,
        operation_id=envelope.operation_id,
        capability_name=CLOUD_RUN_REVISION_CAPABILITY,
        capability_version="1.0.0",
        target=envelope.target,
        relevant_effect_ids=(envelope.expected_effects[0].effect_id,),
        arguments={},
        timeout_ms=5_000,
        result_byte_ceiling=8_192,
    )

    import asyncio

    raw = asyncio.run(registration.handler(probe))
    assert raw.payload["observation"]["revision"] == REVISION
    result = build_cloud_run_rule_registration(
        capability_name=CLOUD_RUN_REVISION_CAPABILITY,
        binding=_binding(),
    ).normalizer(
        _rule_input(
            capability=CLOUD_RUN_REVISION_CAPABILITY,
            relevant_effect_ids=(envelope.expected_effects[0].effect_id,),
            envelope=envelope,
            payload=raw.payload,
        )
    )
    assert result.verdict is RuleVerdict.AUTHORITATIVE_EFFECTS
    assert result.operation_id == envelope.operation_id


def test_missing_expected_revision_remains_authoritative_absence() -> None:
    class Services:
        def get_service(self, **_: object) -> run_v2.Service:
            return run_v2.Service(
                name=(
                    "projects/demo-project/locations/us-central1/services/"
                    "reconcile-canary"
                )
            )

    class Revisions:
        def list_revisions(self, **_: object) -> tuple[()]:
            raise AssertionError("an exact expected revision must be read directly")

        def get_revision(self, **_: object) -> run_v2.Revision:
            raise api_exceptions.NotFound("revision is absent")

    target = CloudRunCanaryTarget(
        project="demo-project",
        location="us-central1",
        service="reconcile-canary",
        image_repository=(
            "us-central1-docker.pkg.dev/demo-project/reconcile-p5/reconcile"
        ),
        baseline_revision="reconcile-canary-baseline",
        health_audience="https://canary.example.test",
    )
    registration = build_cloud_run_capability_registration(
        reader=CloudRunCanaryReader(
            target=target,
            services_factory=Services,
            revisions_factory=Revisions,
            clock=lambda: NOW + timedelta(seconds=1),
        ),
        binding=_binding(),
        capability_name=CLOUD_RUN_REVISION_CAPABILITY,
        target=_target(),
        clock=lambda: NOW + timedelta(seconds=1),
    )
    envelope = _envelope()
    probe = BoundProbe(
        investigation_id=envelope.investigation_id,
        operation_id=envelope.operation_id,
        capability_name=CLOUD_RUN_REVISION_CAPABILITY,
        capability_version="1.0.0",
        target=envelope.target,
        relevant_effect_ids=(envelope.expected_effects[0].effect_id,),
        arguments={},
        timeout_ms=1,
        result_byte_ceiling=8_192,
    )

    import asyncio

    assert registration.handler is not None
    raw = asyncio.run(registration.handler(probe))
    assert raw.payload == {"observation": None}
    result = build_cloud_run_rule_registration(
        capability_name=CLOUD_RUN_REVISION_CAPABILITY,
        binding=_binding(),
    ).normalizer(
        _rule_input(
            capability=CLOUD_RUN_REVISION_CAPABILITY,
            relevant_effect_ids=(envelope.expected_effects[0].effect_id,),
            envelope=envelope,
            payload=raw.payload,
        )
    )
    assert result.verdict is RuleVerdict.ABSENCE_ONLY


def test_expected_revision_waits_while_service_status_references_it() -> None:
    class Services:
        def get_service(self, **_: object) -> run_v2.Service:
            return run_v2.Service(
                name=(
                    "projects/demo-project/locations/us-central1/services/"
                    "reconcile-canary"
                ),
                traffic_statuses=(
                    run_v2.TrafficTargetStatus(
                        revision=REVISION,
                        percent=0,
                    ),
                ),
            )

    class Revisions:
        calls = 0

        def get_revision(self, **kwargs: object) -> run_v2.Revision:
            self.calls += 1
            if self.calls == 1:
                raise api_exceptions.NotFound("revision is becoming visible")
            if self.calls == 2:
                raise api_exceptions.ServiceUnavailable("revision is settling")
            request = kwargs["request"]
            return run_v2.Revision(
                name=request.name,
                service="reconcile-canary",
                generation=1,
                observed_generation=0 if self.calls == 3 else 1,
                labels={"reconcile-release": RELEASE},
                annotations={"reconcile.dev/configuration-sha256": CONFIGURATION},
                containers=(
                    run_v2.Container(
                        image=(
                            "us-central1-docker.pkg.dev/demo-project/"
                            f"reconcile-p5/reconcile@{DIGEST}"
                        )
                    ),
                ),
                conditions=(
                    run_v2.Condition(
                        type_="Ready",
                        state=(
                            run_v2.Condition.State.CONDITION_RECONCILING
                            if self.calls == 3
                            else run_v2.Condition.State.CONDITION_SUCCEEDED
                        ),
                    ),
                ),
                reconciling=self.calls == 3,
            )

    revisions = Revisions()
    target = CloudRunCanaryTarget(
        project="demo-project",
        location="us-central1",
        service="reconcile-canary",
        image_repository=(
            "us-central1-docker.pkg.dev/demo-project/reconcile-p5/reconcile"
        ),
        baseline_revision="reconcile-canary-baseline",
        health_audience="https://canary.example.test",
    )
    registration = build_cloud_run_capability_registration(
        reader=CloudRunCanaryReader(
            target=target,
            services_factory=Services,
            revisions_factory=lambda: revisions,
            clock=lambda: NOW + timedelta(seconds=1),
        ),
        binding=_binding(),
        capability_name=CLOUD_RUN_REVISION_CAPABILITY,
        target=_target(),
        clock=lambda: NOW + timedelta(seconds=1),
    )
    envelope = _envelope()
    probe = BoundProbe(
        investigation_id=envelope.investigation_id,
        operation_id=envelope.operation_id,
        capability_name=CLOUD_RUN_REVISION_CAPABILITY,
        capability_version="1.0.0",
        target=envelope.target,
        relevant_effect_ids=tuple(
            effect.effect_id for effect in envelope.expected_effects
        ),
        arguments={},
        timeout_ms=2_000,
        result_byte_ceiling=8_192,
    )

    import asyncio

    assert registration.handler is not None
    raw = asyncio.run(registration.handler(probe))
    assert revisions.calls == 4
    result = build_cloud_run_rule_registration(
        capability_name=CLOUD_RUN_REVISION_CAPABILITY,
        binding=_binding(),
    ).normalizer(
        _rule_input(
            capability=CLOUD_RUN_REVISION_CAPABILITY,
            relevant_effect_ids=probe.relevant_effect_ids,
            envelope=envelope,
            payload=raw.payload,
        )
    )
    states = {
        effect.effect_id: assertion.state
        for effect, assertion in zip(
            envelope.expected_effects,
            result.effect_assertions,
            strict=True,
        )
    }
    assert states["revision-created"] is EffectAssertionState.ESTABLISHED
    assert states["revision-ready"] is EffectAssertionState.ESTABLISHED
    assert states["revision-zero-traffic"] is EffectAssertionState.UNVERIFIED
    assert result.verdict is RuleVerdict.AUTHORITATIVE_EFFECTS


def test_service_read_waits_for_authoritative_settlement() -> None:
    class Services:
        calls = 0

        def get_service(self, **kwargs: object) -> run_v2.Service:
            self.calls += 1
            request = kwargs["request"]
            settling = self.calls == 1
            return run_v2.Service(
                name=request.name,
                etag=f"etag-{self.calls}",
                generation=2,
                observed_generation=1 if settling else 2,
                reconciling=settling,
                conditions=(
                    run_v2.Condition(
                        type_="Ready",
                        state=(
                            run_v2.Condition.State.CONDITION_RECONCILING
                            if settling
                            else run_v2.Condition.State.CONDITION_SUCCEEDED
                        ),
                    ),
                ),
                traffic_statuses=(
                    run_v2.TrafficTargetStatus(revision=REVISION, percent=0),
                ),
            )

    class Revisions:
        pass

    services = Services()
    target = CloudRunCanaryTarget(
        project="demo-project",
        location="us-central1",
        service="reconcile-canary",
        image_repository=(
            "us-central1-docker.pkg.dev/demo-project/reconcile-p5/reconcile"
        ),
        baseline_revision="reconcile-canary-baseline",
        health_audience="https://canary.example.test",
    )
    registration = build_cloud_run_capability_registration(
        reader=CloudRunCanaryReader(
            target=target,
            services_factory=lambda: services,
            revisions_factory=Revisions,
            clock=lambda: NOW + timedelta(seconds=1),
            revision_settle_delay_seconds=0.01,
        ),
        binding=_binding(),
        capability_name=CLOUD_RUN_SERVICE_CAPABILITY,
        target=_target(),
        clock=lambda: NOW + timedelta(seconds=1),
    )
    envelope = _envelope()
    probe = BoundProbe(
        investigation_id=envelope.investigation_id,
        operation_id=envelope.operation_id,
        capability_name=CLOUD_RUN_SERVICE_CAPABILITY,
        capability_version="1.0.0",
        target=envelope.target,
        relevant_effect_ids=tuple(
            effect.effect_id for effect in envelope.expected_effects
        ),
        arguments={},
        timeout_ms=1_000,
        result_byte_ceiling=8_192,
    )

    import asyncio

    assert registration.handler is not None
    raw = asyncio.run(registration.handler(probe))

    assert services.calls == 2
    assert raw.payload["observation"]["reconciling"] == "false"
    assert raw.payload["observation"]["terminal_condition"] == "SUCCEEDED"
    assert raw.payload["observation"]["revision_traffic_percent"] == "0"


def test_known_operation_polling_does_not_wait_for_revision_list_visibility() -> None:
    class Services:
        def get_operation(self, **_: object):
            service = run_v2.Service(
                name=(
                    "projects/demo-project/locations/us-central1/services/"
                    "reconcile-canary"
                ),
                template=run_v2.RevisionTemplate(
                    revision=REVISION,
                    labels={"reconcile-release": RELEASE},
                    annotations={"reconcile.dev/configuration-sha256": CONFIGURATION},
                    containers=(
                        run_v2.Container(
                            image=(
                                "us-central1-docker.pkg.dev/demo-project/"
                                f"reconcile-p5/reconcile@{DIGEST}"
                            )
                        ),
                    ),
                ),
                traffic=(
                    run_v2.TrafficTarget(
                        revision="reconcile-canary-baseline", percent=100
                    ),
                    run_v2.TrafficTarget(
                        revision=REVISION,
                        percent=0,
                        tag=(
                            "verify-"
                            f"{hashlib.sha256(RELEASE.encode()).hexdigest()[:12]}"
                        ),
                    ),
                ),
            )
            metadata = any_pb2.Any()
            metadata.Pack(run_v2.Service.pb(service))
            return operations_pb2.Operation(
                name=OPERATION,
                done=False,
                metadata=metadata,
            )

    class Revisions:
        def list_revisions(self, **_: object):
            raise AssertionError("known operation polling must not discover revisions")

    target = CloudRunCanaryTarget(
        project="demo-project",
        location="us-central1",
        service="reconcile-canary",
        image_repository=(
            "us-central1-docker.pkg.dev/demo-project/reconcile-p5/reconcile"
        ),
        baseline_revision="reconcile-canary-baseline",
        health_audience="https://canary.example.test",
    )
    reader = CloudRunCanaryReader(
        target=target,
        services_factory=Services,
        revisions_factory=Revisions,
        clock=lambda: NOW + timedelta(seconds=1),
    )
    binding = CloudRunProbeBinding.for_stage(
        release_id=RELEASE,
        image_digest=DIGEST,
        configuration_sha256=CONFIGURATION,
        operation_name=OPERATION,
        operation_revision=REVISION,
    )
    registration = build_cloud_run_capability_registration(
        reader=reader,
        binding=binding,
        capability_name=CLOUD_RUN_OPERATION_CAPABILITY,
        target=_target(),
    )
    envelope = _envelope()
    probe = BoundProbe(
        investigation_id=envelope.investigation_id,
        operation_id=envelope.operation_id,
        capability_name=CLOUD_RUN_OPERATION_CAPABILITY,
        capability_version="1.0.0",
        target=envelope.target,
        relevant_effect_ids=(envelope.expected_effects[0].effect_id,),
        arguments={},
        timeout_ms=5_000,
        result_byte_ceiling=8_192,
    )

    import asyncio

    assert registration.handler is not None
    raw = asyncio.run(registration.handler(probe))

    assert raw.payload["observation"]["operation_state"] == "RUNNING"
    assert raw.payload["observation"]["revision"] == REVISION


def test_health_provenance_is_distinct_and_stale_observations_are_rejected() -> None:
    registration = build_cloud_run_rule_registration(
        capability_name=CLOUD_RUN_HEALTH_CAPABILITY,
        binding=_binding(),
    )
    assert registration.descriptor.source == CLOUD_RUN_HEALTH_SOURCE
    assert registration.descriptor.adapter_version == CLOUD_RUN_HEALTH_ADAPTER_VERSION

    envelope = _envelope()
    readiness = next(
        effect.effect_id
        for effect in envelope.expected_effects
        if effect.commit_scope == STAGE_READINESS_EFFECT_SCOPE
    )
    with pytest.raises(RuleRejected) as raised:
        registration.normalizer(
            _rule_input(
                capability=CLOUD_RUN_HEALTH_CAPABILITY,
                relevant_effect_ids=(readiness,),
                envelope=envelope,
                observed_at=NOW - timedelta(minutes=5),
                payload={
                    "observation": {
                        "observation_schema": CLOUD_RUN_HEALTH_OBSERVATION_VERSION,
                        "release_id": RELEASE,
                        "revision": REVISION,
                        "health_status": "READY",
                    }
                },
            )
        )
    assert raised.value.reason is EvidenceReason.UNVERIFIABLE_AUTHORITY


def test_unhealthy_health_observation_refutes_stage_readiness() -> None:
    envelope = _envelope()
    readiness = next(
        effect.effect_id
        for effect in envelope.expected_effects
        if effect.commit_scope == STAGE_READINESS_EFFECT_SCOPE
    )
    result = build_cloud_run_rule_registration(
        capability_name=CLOUD_RUN_HEALTH_CAPABILITY,
        binding=_binding(),
    ).normalizer(
        _rule_input(
            capability=CLOUD_RUN_HEALTH_CAPABILITY,
            relevant_effect_ids=(readiness,),
            envelope=envelope,
            payload={
                "observation": {
                    "observation_schema": CLOUD_RUN_HEALTH_OBSERVATION_VERSION,
                    "release_id": RELEASE,
                    "revision": REVISION,
                    "health_status": "UNHEALTHY",
                }
            },
        )
    )

    assert result.effect_assertions[0].state is (EffectAssertionState.NOT_ESTABLISHED)
    assert result.verdict is RuleVerdict.AUTHORITATIVE_EFFECTS
