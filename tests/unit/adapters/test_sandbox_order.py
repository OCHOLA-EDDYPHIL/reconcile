"""Weak sandbox-order observation normalization."""

from __future__ import annotations

import asyncio
import hashlib
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from reconcile.adapters.sandbox_order import (
    SANDBOX_ORDER_AGGREGATE_CAPABILITY_NAME,
    SANDBOX_ORDER_AGGREGATE_SOURCE,
    SANDBOX_ORDER_AUTHORITY_POLICY_VERSION,
    SANDBOX_ORDER_CAPABILITY_VERSION,
    SANDBOX_ORDER_CLASSIFICATION_POLICY_VERSION,
    SANDBOX_ORDER_CLOUD_PROFILE,
    SANDBOX_ORDER_ENVIRONMENT,
    SANDBOX_ORDER_INGRESS_CAPABILITY_NAME,
    SANDBOX_ORDER_INGRESS_SOURCE,
    SANDBOX_ORDER_TARGET_KIND,
    SandboxOrderAggregateNormalizer,
    SandboxOrderIngressNormalizer,
    build_sandbox_order_aggregate_capability,
    build_sandbox_order_aggregate_capability_registration,
    build_sandbox_order_aggregate_rule_registration,
    build_sandbox_order_ingress_capability,
    build_sandbox_order_ingress_capability_registration,
    build_sandbox_order_ingress_rule_registration,
    build_sandbox_order_target,
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
    OriginalInvocation,
    PolicyReferences,
    ProbeRequest,
    TargetBinding,
    canonical_json_bytes,
)
from reconcile.contracts.base import canonical_json_value_bytes
from reconcile.controller import (
    BoundProbe,
    CapabilitySemantics,
    CapabilityUnavailable,
    ProbeObservation,
)
from reconcile.evidence import RuleInput, RuleRejected, RuleVerdict
from reconcile.hosted.sandbox import HostedSandboxEvidenceTarget
from reconcile.hosted.transport import HostedHttpTransport
from reconcile.scenarios.local_order import (
    HiddenOrderOutcome,
    LocalOrderError,
    LocalOrderHarness,
    LocalOrderMutationTarget,
    LocalOrderReadTarget,
    WeakOrderCountBand,
)

pytestmark = pytest.mark.unit

_NOW = datetime(2026, 8, 13, 22, 0, tzinfo=UTC)
_SANDBOX_ID = "order-sandbox-7"
_OPERATION_ID = "operation-order-7"
_EFFECT_ID = "order-accepted"
_ITEM_CODE = "widget-blue"
_QUANTITY = 2


def _target() -> TargetBinding:
    return build_sandbox_order_target(sandbox_id=_SANDBOX_ID)


def _envelope(
    *,
    target: TargetBinding | None = None,
    correlation_fields: dict[str, str] | None = None,
    invoked_at: datetime | None = None,
) -> ExecutionEnvelope:
    arguments = {"item_code": _ITEM_CODE, "quantity": _QUANTITY}
    return ExecutionEnvelope(
        schema_version=EXECUTION_ENVELOPE_VERSION,
        investigation_id="investigation-order-7",
        operation_id=_OPERATION_ID,
        target=target or _target(),
        invoked_at=invoked_at or (_NOW - timedelta(seconds=1)),
        ambiguity=AmbiguousExecution(
            kind=AmbiguityKind.PROCESS_INTERRUPTED,
            observed_at=_NOW + timedelta(seconds=1),
            detail="The local sandbox order call returned no result.",
        ),
        expected_effects=(
            ExpectedEffect(
                schema_version=EXPECTED_EFFECT_VERSION,
                effect_id=_EFFECT_ID,
                commit_scope="sandbox-order",
                predicate={"item_code": _ITEM_CODE, "quantity": _QUANTITY},
                description="The sandbox accepted the requested order.",
            ),
        ),
        context=EnvelopeContext(
            invocation=OriginalInvocation(
                invocation_id="invocation-order-7",
                function_call_id="function-call-order-7",
                tool_name="submit-sandbox-order",
                tool_version="1.0.0",
                arguments=arguments,
                arguments_sha256=hashlib.sha256(
                    canonical_json_value_bytes(arguments)
                ).hexdigest(),
            ),
            enabled_capabilities=(
                CapabilityRef(
                    name=SANDBOX_ORDER_INGRESS_CAPABILITY_NAME,
                    version=SANDBOX_ORDER_CAPABILITY_VERSION,
                ),
                CapabilityRef(
                    name=SANDBOX_ORDER_AGGREGATE_CAPABILITY_NAME,
                    version=SANDBOX_ORDER_CAPABILITY_VERSION,
                ),
            ),
            correlation_fields=(
                {} if correlation_fields is None else correlation_fields
            ),
            evidence_budget=EvidenceBudget(
                max_probes=2,
                max_elapsed_ms=2_000,
                max_total_result_bytes=8_192,
                max_cost_units=2,
            ),
            freshness=FreshnessPolicy(
                max_age_seconds=60,
                clock_skew_seconds=2,
            ),
            policies=PolicyReferences(
                authority=SANDBOX_ORDER_AUTHORITY_POLICY_VERSION,
                classification=SANDBOX_ORDER_CLASSIFICATION_POLICY_VERSION,
                action="action-v1",
            ),
        ),
    )


def _request(
    capability_name: str,
    *,
    relevant_effect_ids: tuple[str, ...] = (_EFFECT_ID,),
    arguments: dict[str, object] | None = None,
) -> ProbeRequest:
    return ProbeRequest(
        schema_version=PROBE_REQUEST_VERSION,
        capability_name=capability_name,
        capability_version=SANDBOX_ORDER_CAPABILITY_VERSION,
        relevant_effect_ids=relevant_effect_ids,
        arguments={} if arguments is None else arguments,
        rationale="Read one deliberately weak sandbox observation.",
    )


def _probe(capability_name: str, *, target: TargetBinding | None = None) -> BoundProbe:
    selected_target = target or _target()
    capability = (
        build_sandbox_order_ingress_capability(selected_target)
        if capability_name == SANDBOX_ORDER_INGRESS_CAPABILITY_NAME
        else build_sandbox_order_aggregate_capability(selected_target)
    )
    return BoundProbe(
        investigation_id="investigation-order-7",
        operation_id=_OPERATION_ID,
        capability_name=capability_name,
        capability_version=SANDBOX_ORDER_CAPABILITY_VERSION,
        target=selected_target,
        relevant_effect_ids=(_EFFECT_ID,),
        arguments={},
        timeout_ms=capability.timeout_ms,
        result_byte_ceiling=capability.result_byte_ceiling,
    )


def _rule_input(
    *,
    capability_name: str,
    observation: ProbeObservation,
    envelope: ExecutionEnvelope | None = None,
    request: ProbeRequest | None = None,
    retrieved_at: datetime | None = None,
) -> RuleInput:
    return RuleInput(
        envelope=envelope or _envelope(),
        request=request or _request(capability_name),
        observation=canonical_json_bytes(observation),
        retrieved_at=(
            observation.observed_at + timedelta(milliseconds=1)
            if retrieved_at is None
            else retrieved_at
        ),
    )


def _ingress_observation(
    *,
    ingress: dict[str, object] | None,
    read_at: datetime = _NOW + timedelta(seconds=1),
) -> ProbeObservation:
    return ProbeObservation(observed_at=read_at, payload={"ingress": ingress})


def _aggregate_observation(
    *,
    aggregate: dict[str, object] | None,
    read_at: datetime = _NOW + timedelta(seconds=1),
) -> ProbeObservation:
    return ProbeObservation(observed_at=read_at, payload={"aggregate": aggregate})


def _assert_weak_result(result: object, verdict: RuleVerdict) -> None:
    assert result.verdict is verdict  # type: ignore[attr-defined]
    assert result.operation_id is None  # type: ignore[attr-defined]
    assert result.operation_status is None  # type: ignore[attr-defined]
    assert result.correlation == {}  # type: ignore[attr-defined]
    assert [item.state for item in result.effect_assertions] == [  # type: ignore[attr-defined]
        EffectAssertionState.UNVERIFIED
    ]


def _sandbox_paths(tmp_path: Path, name: str) -> tuple[Path, Path]:
    return (
        tmp_path / f"{name}-private.sqlite3",
        tmp_path / f"{name}-observations.sqlite3",
    )


def _seed_sandbox(
    tmp_path: Path,
    *,
    name: str,
    outcome: HiddenOrderOutcome,
) -> LocalOrderReadTarget:
    private_path, observation_path = _sandbox_paths(tmp_path, name)
    harness = LocalOrderHarness(
        private_path,
        observation_path,
        clock=lambda: _NOW,
    )
    harness.seed_duplicate_looking_order(
        item_code=_ITEM_CODE,
        quantity=_QUANTITY,
    )
    LocalOrderMutationTarget(
        private_path,
        observation_path,
        hidden_outcome=outcome,
        clock=lambda: _NOW + timedelta(seconds=1),
    ).submit_order(
        owner_token=f"private-owner-{name}",
        item_code=_ITEM_CODE,
        quantity=_QUANTITY,
    )
    return LocalOrderReadTarget(observation_path)


def test_capabilities_are_empty_argument_read_only_and_locally_bound(
    tmp_path: Path,
) -> None:
    target = _target()
    read_target = LocalOrderReadTarget(tmp_path / "observations.sqlite3")
    ingress = build_sandbox_order_ingress_capability_registration(
        read_target=read_target,
        target=target,
        clock=lambda: _NOW,
    )
    aggregate = build_sandbox_order_aggregate_capability_registration(
        read_target=read_target,
        target=target,
        clock=lambda: _NOW,
    )

    assert target.target_kind == SANDBOX_ORDER_TARGET_KIND
    assert target.scope == {
        "environment": SANDBOX_ORDER_ENVIRONMENT,
        "sandbox_id": _SANDBOX_ID,
    }
    assert target.resource == {"observation_set": "weak-order-observations"}
    for registration in (ingress, aggregate):
        assert registration.capability.argument_schema["properties"] == {}
        assert registration.capability.argument_schema["additionalProperties"] is False
        assert registration.semantics is CapabilitySemantics.READ_ONLY
        assert registration.max_invocations == 1
    assert ingress.handler is not None
    assert aggregate.handler is not None
    assert asyncio.run(
        ingress.handler(_probe(SANDBOX_ORDER_INGRESS_CAPABILITY_NAME))
    ).payload == {"ingress": None}
    assert asyncio.run(
        aggregate.handler(_probe(SANDBOX_ORDER_AGGREGATE_CAPABILITY_NAME))
    ).payload == {"aggregate": None}
    assert build_sandbox_order_ingress_rule_registration().descriptor.source == (
        SANDBOX_ORDER_INGRESS_SOURCE
    )
    assert build_sandbox_order_aggregate_rule_registration().descriptor.source == (
        SANDBOX_ORDER_AGGREGATE_SOURCE
    )


def test_capability_registration_accepts_only_the_observation_read_handle(
    tmp_path: Path,
) -> None:
    private_path, observation_path = _sandbox_paths(tmp_path, "restricted")
    mutation = LocalOrderMutationTarget(
        private_path,
        observation_path,
        hidden_outcome=HiddenOrderOutcome.COMMIT,
    )

    with pytest.raises(TypeError, match="restricted read target"):
        build_sandbox_order_ingress_capability_registration(
            read_target=mutation,  # type: ignore[arg-type]
            target=_target(),
        )


def test_cloud_profile_accepts_only_the_sealed_hosted_read_target() -> None:
    class ForgedReadPort:
        async def read_ingress_observation(self):
            return None

        async def read_aggregate_observation(self):
            return None

    target = build_sandbox_order_target(
        sandbox_id=_SANDBOX_ID,
        profile=SANDBOX_ORDER_CLOUD_PROFILE,
    )
    with pytest.raises(TypeError, match="sealed hosted read target"):
        build_sandbox_order_ingress_capability_registration(
            read_target=ForgedReadPort(),
            target=target,
            profile=SANDBOX_ORDER_CLOUD_PROFILE,
        )

    hosted = HostedSandboxEvidenceTarget(
        sandbox_url="https://sandbox.example.test",
        sandbox_audience="https://sandbox.example.test",
        sandbox_id=_SANDBOX_ID,
        transport=HostedHttpTransport(lambda _audience: "header.payload.signature"),
    )
    registration = build_sandbox_order_ingress_capability_registration(
        read_target=hosted,
        target=target,
        profile=SANDBOX_ORDER_CLOUD_PROFILE,
    )
    rule = build_sandbox_order_ingress_rule_registration(
        profile=SANDBOX_ORDER_CLOUD_PROFILE,
    )

    assert registration.capability.timeout_ms == SANDBOX_ORDER_CLOUD_PROFILE.timeout_ms
    assert rule.descriptor.authority_policy_version == (
        SANDBOX_ORDER_CLOUD_PROFILE.authority_policy_version
    )
    assert rule.descriptor.source == SANDBOX_ORDER_CLOUD_PROFILE.ingress_source


@pytest.mark.parametrize(
    ("outcome", "capability_name"),
    (
        (HiddenOrderOutcome.COMMIT, SANDBOX_ORDER_INGRESS_CAPABILITY_NAME),
        (HiddenOrderOutcome.DISCARD, SANDBOX_ORDER_INGRESS_CAPABILITY_NAME),
        (HiddenOrderOutcome.COMMIT, SANDBOX_ORDER_AGGREGATE_CAPABILITY_NAME),
        (HiddenOrderOutcome.DISCARD, SANDBOX_ORDER_AGGREGATE_CAPABILITY_NAME),
    ),
)
def test_actual_observations_are_supplementary_for_both_hidden_outcomes(
    tmp_path: Path,
    outcome: HiddenOrderOutcome,
    capability_name: str,
) -> None:
    read_target = _seed_sandbox(
        tmp_path,
        name=f"{outcome.value.lower()}-{capability_name}",
        outcome=outcome,
    )
    if capability_name == SANDBOX_ORDER_INGRESS_CAPABILITY_NAME:
        registration = build_sandbox_order_ingress_capability_registration(
            read_target=read_target,
            target=_target(),
            clock=lambda: _NOW + timedelta(seconds=2),
        )
        normalizer = SandboxOrderIngressNormalizer()
    else:
        registration = build_sandbox_order_aggregate_capability_registration(
            read_target=read_target,
            target=_target(),
            clock=lambda: _NOW + timedelta(seconds=2),
        )
        normalizer = SandboxOrderAggregateNormalizer()
    handler = registration.handler
    assert handler is not None
    observation = asyncio.run(handler(_probe(capability_name)))

    result = normalizer(
        _rule_input(capability_name=capability_name, observation=observation)
    )

    _assert_weak_result(result, RuleVerdict.SUPPLEMENTARY)
    encoded = canonical_json_bytes(observation)
    assert _OPERATION_ID.encode() not in encoded
    assert _ITEM_CODE.encode() not in encoded
    assert b"private-owner" not in encoded
    assert b"COMMIT" not in encoded
    assert b"DISCARD" not in encoded


def test_hidden_commit_and_discard_are_byte_identical_through_both_adapters(
    tmp_path: Path,
) -> None:
    commit = _seed_sandbox(
        tmp_path,
        name="paired-commit",
        outcome=HiddenOrderOutcome.COMMIT,
    )
    discard = _seed_sandbox(
        tmp_path,
        name="paired-discard",
        outcome=HiddenOrderOutcome.DISCARD,
    )
    outputs: dict[tuple[HiddenOrderOutcome, str], bytes] = {}
    for outcome, read_target in (
        (HiddenOrderOutcome.COMMIT, commit),
        (HiddenOrderOutcome.DISCARD, discard),
    ):
        registrations = (
            build_sandbox_order_ingress_capability_registration(
                read_target=read_target,
                target=_target(),
                clock=lambda: _NOW + timedelta(seconds=2),
            ),
            build_sandbox_order_aggregate_capability_registration(
                read_target=read_target,
                target=_target(),
                clock=lambda: _NOW + timedelta(seconds=2),
            ),
        )
        for registration in registrations:
            capability_name = registration.capability.name
            handler = registration.handler
            assert handler is not None
            outputs[(outcome, capability_name)] = canonical_json_bytes(
                asyncio.run(handler(_probe(capability_name)))
            )

    for capability_name in (
        SANDBOX_ORDER_INGRESS_CAPABILITY_NAME,
        SANDBOX_ORDER_AGGREGATE_CAPABILITY_NAME,
    ):
        assert (
            outputs[(HiddenOrderOutcome.COMMIT, capability_name)]
            == outputs[(HiddenOrderOutcome.DISCARD, capability_name)]
        )


def test_present_and_missing_ingress_remain_weak() -> None:
    present = SandboxOrderIngressNormalizer()(
        _rule_input(
            capability_name=SANDBOX_ORDER_INGRESS_CAPABILITY_NAME,
            observation=_ingress_observation(
                ingress={
                    "event_kind": "REQUEST_SEEN",
                    "observed_at": _NOW.isoformat(),
                }
            ),
        )
    )
    missing = SandboxOrderIngressNormalizer()(
        _rule_input(
            capability_name=SANDBOX_ORDER_INGRESS_CAPABILITY_NAME,
            observation=_ingress_observation(ingress=None),
        )
    )

    _assert_weak_result(present, RuleVerdict.SUPPLEMENTARY)
    _assert_weak_result(missing, RuleVerdict.ABSENCE_ONLY)


@pytest.mark.parametrize("count_band", tuple(WeakOrderCountBand))
def test_every_existing_aggregate_band_is_supplementary(
    count_band: WeakOrderCountBand,
) -> None:
    result = SandboxOrderAggregateNormalizer()(
        _rule_input(
            capability_name=SANDBOX_ORDER_AGGREGATE_CAPABILITY_NAME,
            observation=_aggregate_observation(
                aggregate={
                    "count_band": count_band.value,
                    "observed_at": _NOW.isoformat(),
                }
            ),
        )
    )

    _assert_weak_result(result, RuleVerdict.SUPPLEMENTARY)


def test_missing_aggregate_is_absence_only() -> None:
    result = SandboxOrderAggregateNormalizer()(
        _rule_input(
            capability_name=SANDBOX_ORDER_AGGREGATE_CAPABILITY_NAME,
            observation=_aggregate_observation(aggregate=None),
        )
    )

    _assert_weak_result(result, RuleVerdict.ABSENCE_ONLY)


@pytest.mark.parametrize("delay_seconds", (0, 1, 20, 45))
def test_read_latency_variation_never_upgrades_weak_evidence(
    delay_seconds: int,
) -> None:
    read_at = _NOW + timedelta(seconds=delay_seconds)
    observation = _aggregate_observation(
        aggregate={
            "count_band": WeakOrderCountBand.ONE_OR_MORE.value,
            "observed_at": _NOW.isoformat(),
        },
        read_at=read_at,
    )

    result = SandboxOrderAggregateNormalizer()(
        _rule_input(
            capability_name=SANDBOX_ORDER_AGGREGATE_CAPABILITY_NAME,
            observation=observation,
            retrieved_at=read_at + timedelta(milliseconds=1),
        )
    )

    _assert_weak_result(result, RuleVerdict.SUPPLEMENTARY)


@pytest.mark.parametrize(
    ("normalizer", "capability_name", "payload"),
    (
        (
            SandboxOrderIngressNormalizer(),
            SANDBOX_ORDER_INGRESS_CAPABILITY_NAME,
            {
                "ingress": {
                    "event_kind": "ORDER_COMMITTED",
                    "observed_at": _NOW.isoformat(),
                }
            },
        ),
        (
            SandboxOrderIngressNormalizer(),
            SANDBOX_ORDER_INGRESS_CAPABILITY_NAME,
            {
                "ingress": {
                    "event_kind": "REQUEST_SEEN",
                    "observed_at": _NOW.isoformat(),
                    "operation_id": _OPERATION_ID,
                }
            },
        ),
        (
            SandboxOrderAggregateNormalizer(),
            SANDBOX_ORDER_AGGREGATE_CAPABILITY_NAME,
            {
                "aggregate": {
                    "count_band": "EXACTLY_ONE",
                    "observed_at": _NOW.isoformat(),
                }
            },
        ),
        (
            SandboxOrderAggregateNormalizer(),
            SANDBOX_ORDER_AGGREGATE_CAPABILITY_NAME,
            {
                "aggregate": {
                    "count_band": "ONE_OR_MORE",
                    "observed_at": _NOW.isoformat(),
                    "hidden_outcome": "COMMIT",
                }
            },
        ),
    ),
)
def test_malformed_or_correlating_observations_are_rejected(
    normalizer: object,
    capability_name: str,
    payload: dict[str, object],
) -> None:
    observation = ProbeObservation(
        observed_at=_NOW + timedelta(seconds=1),
        payload=payload,
    )

    with pytest.raises(RuleRejected) as raised:
        normalizer(  # type: ignore[operator]
            _rule_input(capability_name=capability_name, observation=observation)
        )
    assert raised.value.reason is EvidenceReason.MALFORMED_OBSERVATION


@pytest.mark.parametrize(
    ("capability_name", "method_name"),
    (
        (SANDBOX_ORDER_INGRESS_CAPABILITY_NAME, "read_ingress"),
        (SANDBOX_ORDER_AGGREGATE_CAPABILITY_NAME, "read_aggregate"),
    ),
)
def test_unavailable_reads_return_no_observation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capability_name: str,
    method_name: str,
) -> None:
    read_target = LocalOrderReadTarget(tmp_path / "observations.sqlite3")

    def unavailable(_target: LocalOrderReadTarget) -> object:
        raise LocalOrderError("observation store unavailable")

    monkeypatch.setattr(LocalOrderReadTarget, method_name, unavailable)
    registration = (
        build_sandbox_order_ingress_capability_registration(
            read_target=read_target,
            target=_target(),
        )
        if capability_name == SANDBOX_ORDER_INGRESS_CAPABILITY_NAME
        else build_sandbox_order_aggregate_capability_registration(
            read_target=read_target,
            target=_target(),
        )
    )
    handler = registration.handler
    assert handler is not None

    with pytest.raises(CapabilityUnavailable):
        asyncio.run(handler(_probe(capability_name)))


def test_wrong_target_or_claimed_correlation_is_rejected(tmp_path: Path) -> None:
    read_target = LocalOrderReadTarget(tmp_path / "observations.sqlite3")
    registration = build_sandbox_order_ingress_capability_registration(
        read_target=read_target,
        target=_target(),
        clock=lambda: _NOW,
    )
    changed_target = build_sandbox_order_target(sandbox_id="other-sandbox")
    handler = registration.handler
    assert handler is not None
    with pytest.raises(CapabilityUnavailable):
        asyncio.run(
            handler(
                BoundProbe(
                    investigation_id="investigation-order-7",
                    operation_id=_OPERATION_ID,
                    capability_name=SANDBOX_ORDER_INGRESS_CAPABILITY_NAME,
                    capability_version=SANDBOX_ORDER_CAPABILITY_VERSION,
                    target=changed_target,
                    relevant_effect_ids=(_EFFECT_ID,),
                    arguments={},
                    timeout_ms=2_000,
                    result_byte_ceiling=4_096,
                )
            )
        )

    observation = _ingress_observation(
        ingress={
            "event_kind": "REQUEST_SEEN",
            "observed_at": _NOW.isoformat(),
        }
    )
    with pytest.raises(RuleRejected) as raised:
        SandboxOrderIngressNormalizer()(
            _rule_input(
                capability_name=SANDBOX_ORDER_INGRESS_CAPABILITY_NAME,
                observation=observation,
                envelope=_envelope(
                    correlation_fields={"request_id": "unsupported-request-7"}
                ),
            )
        )
    assert raised.value.reason is EvidenceReason.UNVERIFIABLE_AUTHORITY


def test_target_shape_and_effect_scope_are_exact() -> None:
    target_payload = _target().model_dump(mode="python")
    target_payload["resource"]["observation_set"] = "private-orders"
    wrong_resource = TargetBinding.model_validate(target_payload)
    with pytest.raises(ValueError, match="resource is not exact"):
        build_sandbox_order_ingress_capability(wrong_resource)

    observation = _ingress_observation(ingress=None)
    with pytest.raises(RuleRejected) as raised:
        SandboxOrderIngressNormalizer()(
            _rule_input(
                capability_name=SANDBOX_ORDER_INGRESS_CAPABILITY_NAME,
                observation=observation,
                request=_request(
                    SANDBOX_ORDER_INGRESS_CAPABILITY_NAME,
                    relevant_effect_ids=("unrelated-effect",),
                ),
            )
        )
    assert raised.value.reason is EvidenceReason.EXPECTED_EFFECT_MISMATCH


def test_stale_or_future_weak_observation_is_rejected_without_inference() -> None:
    for observed_at in (
        _NOW - timedelta(minutes=5),
        _NOW + timedelta(minutes=5),
    ):
        observation = _ingress_observation(
            ingress={
                "event_kind": "REQUEST_SEEN",
                "observed_at": observed_at.isoformat(),
            }
        )
        with pytest.raises(RuleRejected) as raised:
            SandboxOrderIngressNormalizer()(
                _rule_input(
                    capability_name=SANDBOX_ORDER_INGRESS_CAPABILITY_NAME,
                    observation=observation,
                )
            )
        assert raised.value.reason is EvidenceReason.UNVERIFIABLE_AUTHORITY


def test_request_identity_and_empty_arguments_are_required() -> None:
    observation = _aggregate_observation(aggregate=None)
    with pytest.raises(RuleRejected) as raised:
        SandboxOrderAggregateNormalizer()(
            _rule_input(
                capability_name=SANDBOX_ORDER_AGGREGATE_CAPABILITY_NAME,
                observation=observation,
                request=_request(
                    SANDBOX_ORDER_AGGREGATE_CAPABILITY_NAME,
                    arguments={"order_id": _OPERATION_ID},
                ),
            )
        )
    assert raised.value.reason is EvidenceReason.MALFORMED_OBSERVATION
