"""Local Storage metadata adapter and deterministic normalization."""

from __future__ import annotations

import asyncio
import hashlib
import inspect
import json
from copy import deepcopy
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from reconcile.adapters.storage import (
    STORAGE_AUTHORITY_POLICY_VERSION,
    STORAGE_CAPABILITY_NAME,
    STORAGE_CAPABILITY_VERSION,
    STORAGE_CLASSIFICATION_POLICY_VERSION,
    STORAGE_ENVIRONMENT,
    STORAGE_SOURCE,
    STORAGE_TARGET_KIND,
    StorageReadbackNormalizer,
    build_storage_capability,
    build_storage_capability_registration,
    build_storage_rule_registration,
    build_storage_target,
)
from reconcile.contracts import (
    EXECUTION_ENVELOPE_VERSION,
    EXPECTED_EFFECT_VERSION,
    PROBE_REQUEST_VERSION,
    AmbiguityKind,
    AmbiguousExecution,
    CapabilityRef,
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
from reconcile.scenarios.local_storage import (
    LocalStorageHarness,
    LocalStorageReadTarget,
)

pytestmark = pytest.mark.unit

_BUCKET = "scenario-bucket"
_OBJECT = "runs/run-7/result.json"
_OPERATION = "operation-7"
_EFFECT = "storage-object-created"
_CONTENT = b'{"result":"created"}'
_CONTENT_SHA256 = hashlib.sha256(_CONTENT).hexdigest()
_CORRELATION = {"request_id": "request-7"}
_NOW = datetime(2026, 8, 13, 18, 0, tzinfo=UTC)


def _envelope(
    *,
    predicate: dict[str, object] | None = None,
    target: TargetBinding | None = None,
    correlation_fields: dict[str, str] | None = None,
) -> ExecutionEnvelope:
    target = target or build_storage_target(
        bucket_name=_BUCKET,
        object_name=_OBJECT,
    )
    arguments = {
        "bucket_name": _BUCKET,
        "object_name": _OBJECT,
        "content_sha256": _CONTENT_SHA256,
        "size_bytes": len(_CONTENT),
        "request_id": _CORRELATION["request_id"],
    }
    return ExecutionEnvelope(
        schema_version=EXECUTION_ENVELOPE_VERSION,
        investigation_id="investigation-7",
        operation_id=_OPERATION,
        target=target,
        invoked_at=_NOW - timedelta(seconds=1),
        ambiguity=AmbiguousExecution(
            kind=AmbiguityKind.MISSING_TOOL_RESULT,
            observed_at=_NOW + timedelta(seconds=1),
            detail="The local Storage mutation response was not delivered.",
        ),
        expected_effects=(
            ExpectedEffect(
                schema_version=EXPECTED_EFFECT_VERSION,
                effect_id=_EFFECT,
                commit_scope="object-create",
                predicate=(
                    {
                        "content_sha256": _CONTENT_SHA256,
                        "size_bytes": len(_CONTENT),
                        "correlation": _CORRELATION,
                    }
                    if predicate is None
                    else predicate
                ),
                description="The exact correlated object generation exists.",
            ),
        ),
        context=EnvelopeContext(
            invocation=OriginalInvocation(
                invocation_id="invocation-7",
                function_call_id="call-7",
                tool_name="storage-object-create",
                tool_version="1.0.0",
                arguments=arguments,
                arguments_sha256=hashlib.sha256(
                    canonical_json_value_bytes(arguments)
                ).hexdigest(),
            ),
            enabled_capabilities=(
                CapabilityRef(
                    name=STORAGE_CAPABILITY_NAME,
                    version=STORAGE_CAPABILITY_VERSION,
                ),
            ),
            correlation_fields=(
                _CORRELATION if correlation_fields is None else correlation_fields
            ),
            evidence_budget=EvidenceBudget(
                max_probes=1,
                max_elapsed_ms=2_000,
                max_total_result_bytes=16_384,
                max_cost_units=1,
            ),
            freshness=FreshnessPolicy(
                max_age_seconds=30,
                clock_skew_seconds=1,
            ),
            policies=PolicyReferences(
                authority=STORAGE_AUTHORITY_POLICY_VERSION,
                classification=STORAGE_CLASSIFICATION_POLICY_VERSION,
                action="action-v1",
            ),
        ),
    )


def _request(*, arguments: dict[str, object] | None = None) -> ProbeRequest:
    return ProbeRequest(
        schema_version=PROBE_REQUEST_VERSION,
        capability_name=STORAGE_CAPABILITY_NAME,
        capability_version=STORAGE_CAPABILITY_VERSION,
        relevant_effect_ids=(_EFFECT,),
        arguments={} if arguments is None else arguments,
        rationale="Read only the bound object's metadata and immutable receipt.",
    )


@dataclass(frozen=True, slots=True)
class _Case:
    harness: LocalStorageHarness
    envelope: ExecutionEnvelope
    request: ProbeRequest
    registration: object
    probe: BoundProbe
    observation: ProbeObservation


def _observe(registration: object, probe: BoundProbe) -> ProbeObservation:
    handler = registration.handler  # type: ignore[attr-defined]
    assert handler is not None
    return asyncio.run(handler(probe))


def _case(tmp_path: Path) -> _Case:
    database_path = tmp_path / "storage.sqlite3"
    harness = LocalStorageHarness(database_path)
    harness.create_object_with_receipt(
        operation_id=_OPERATION,
        bucket=_BUCKET,
        name=_OBJECT,
        content=_CONTENT,
        correlation=_CORRELATION,
        observed_at=_NOW,
    )
    envelope = _envelope()
    registration = build_storage_capability_registration(
        read_target=LocalStorageReadTarget(database_path),
        target=envelope.target,
        clock=lambda: _NOW + timedelta(seconds=1),
    )
    capability = registration.capability
    probe = BoundProbe(
        investigation_id=envelope.investigation_id,
        operation_id=envelope.operation_id,
        capability_name=STORAGE_CAPABILITY_NAME,
        capability_version=STORAGE_CAPABILITY_VERSION,
        target=envelope.target,
        relevant_effect_ids=(_EFFECT,),
        arguments={},
        timeout_ms=capability.timeout_ms,
        result_byte_ceiling=capability.result_byte_ceiling,
    )
    return _Case(
        harness=harness,
        envelope=envelope,
        request=_request(),
        registration=registration,
        probe=probe,
        observation=_observe(registration, probe),
    )


def _rule_input(
    case: _Case,
    *,
    observation: ProbeObservation | None = None,
    envelope: ExecutionEnvelope | None = None,
    request: ProbeRequest | None = None,
    retrieved_at: datetime | None = None,
) -> RuleInput:
    observation = observation or case.observation
    return RuleInput(
        envelope=envelope or case.envelope,
        request=request or case.request,
        observation=canonical_json_bytes(observation),
        retrieved_at=(
            observation.observed_at + timedelta(milliseconds=1)
            if retrieved_at is None
            else retrieved_at
        ),
    )


def _mutate_observation(
    observation: ProbeObservation,
    *,
    section: str,
    field_name: str,
    value: object = None,
    delete: bool = False,
) -> ProbeObservation:
    payload = observation.model_dump(mode="python")
    raw_payload = payload["payload"]
    assert isinstance(raw_payload, dict)
    section_payload = raw_payload[section]
    assert isinstance(section_payload, dict)
    if delete:
        section_payload.pop(field_name)
    else:
        section_payload[field_name] = value
    return ProbeObservation.model_validate(payload)


def _replace_predicate(
    envelope: ExecutionEnvelope,
    predicate: dict[str, object],
) -> ExecutionEnvelope:
    payload = envelope.model_dump(mode="python")
    payload["expected_effects"][0]["predicate"] = predicate
    return ExecutionEnvelope.model_validate(payload)


def _assert_rejected(
    case: _Case,
    reason: EvidenceReason,
    *,
    observation: ProbeObservation | None = None,
    envelope: ExecutionEnvelope | None = None,
    request: ProbeRequest | None = None,
    retrieved_at: datetime | None = None,
) -> None:
    with pytest.raises(RuleRejected) as raised:
        StorageReadbackNormalizer()(
            _rule_input(
                case,
                observation=observation,
                envelope=envelope,
                request=request,
                retrieved_at=retrieved_at,
            )
        )
    assert raised.value.reason is reason


def test_capability_is_empty_argument_read_only_and_exactly_scope_bound(
    tmp_path: Path,
) -> None:
    case = _case(tmp_path)
    target = case.envelope.target
    capability = build_storage_capability(target)
    registration = case.registration

    assert target.target_kind == STORAGE_TARGET_KIND
    assert target.scope == {
        "bucket_name": _BUCKET,
        "environment": STORAGE_ENVIRONMENT,
    }
    assert target.resource == {"object_name": _OBJECT}
    assert capability.argument_schema["properties"] == {}
    assert capability.argument_schema["required"] == []
    assert capability.argument_schema["additionalProperties"] is False
    assert capability.allowed_targets[0].scope == target.scope
    assert registration.semantics is CapabilitySemantics.READ_ONLY  # type: ignore[attr-defined]
    assert registration.max_invocations == 1  # type: ignore[attr-defined]
    assert inspect.iscoroutinefunction(type(registration.handler).__call__)  # type: ignore[attr-defined]
    payload = case.observation.payload
    assert "content" not in payload
    assert set(payload) == {"object_metadata", "receipt"}


def test_unbound_project_label_cannot_expand_the_authority_scope() -> None:
    target = TargetBinding(
        target_kind=STORAGE_TARGET_KIND,
        scope={
            "bucket_name": _BUCKET,
            "environment": STORAGE_ENVIRONMENT,
            "project_id": "unbound-project",
        },
        resource={"object_name": _OBJECT},
    )

    with pytest.raises(ValueError, match="scope is not exact"):
        build_storage_capability(target)


def test_handler_rejects_any_target_other_than_its_bound_target(tmp_path: Path) -> None:
    case = _case(tmp_path)
    other_target = build_storage_target(
        bucket_name=_BUCKET,
        object_name="runs/other/result.json",
    )
    payload = case.probe.model_dump(mode="python")
    payload["target"] = other_target
    other_probe = BoundProbe.model_validate(payload)
    handler = case.registration.handler  # type: ignore[attr-defined]
    assert handler is not None

    with pytest.raises(CapabilityUnavailable):
        asyncio.run(handler(other_probe))


def test_exact_readback_establishes_only_the_requested_effect(tmp_path: Path) -> None:
    case = _case(tmp_path)

    result = StorageReadbackNormalizer()(_rule_input(case))

    assert result.target == case.envelope.target
    assert result.verdict is RuleVerdict.AUTHORITATIVE_EFFECTS
    assert result.operation_status is OperationStatus.TERMINAL_COMMITTED
    assert result.operation_id == _OPERATION
    assert result.correlation == _CORRELATION
    assert [
        (item.effect_id, item.state.value) for item in result.effect_assertions
    ] == [(_EFFECT, "ESTABLISHED")]
    assert result.source_record == "object-generation-1"
    descriptor = build_storage_rule_registration().descriptor
    assert descriptor.source == STORAGE_SOURCE
    serialized = json.dumps(result.model_dump(mode="json"), sort_keys=True)
    receipt = case.observation.payload["receipt"]
    assert isinstance(receipt, dict)
    assert "receipt" not in serialized
    assert "correlation_sha256" not in serialized
    assert receipt["correlation_sha256"] not in serialized


@pytest.mark.parametrize(
    ("section", "field_name", "value"),
    (
        ("object_metadata", "bucket_name", "wrong-bucket"),
        ("object_metadata", "object_name", "wrong-object"),
        ("object_metadata", "generation", 2),
        ("object_metadata", "content_sha256", "f" * 64),
        ("object_metadata", "size_bytes", len(_CONTENT) + 1),
        ("object_metadata", "correlation", {"request_id": "wrong-request"}),
        ("receipt", "operation_id", "operation-other"),
        ("receipt", "bucket_name", "wrong-bucket"),
        ("receipt", "object_name", "wrong-object"),
        ("receipt", "generation", 2),
        ("receipt", "content_sha256", "f" * 64),
        ("receipt", "size_bytes", len(_CONTENT) + 1),
        ("receipt", "correlation_sha256", "f" * 64),
    ),
)
def test_any_wrong_object_or_receipt_binding_is_unverifiable(
    tmp_path: Path,
    section: str,
    field_name: str,
    value: object,
) -> None:
    case = _case(tmp_path)
    observation = _mutate_observation(
        case.observation,
        section=section,
        field_name=field_name,
        value=value,
    )

    _assert_rejected(
        case,
        EvidenceReason.UNVERIFIABLE_AUTHORITY,
        observation=observation,
    )


@pytest.mark.parametrize(
    ("field_name", "value"),
    (
        ("content_sha256", "e" * 64),
        ("size_bytes", len(_CONTENT) + 1),
        ("correlation", {"request_id": "request-other"}),
    ),
)
def test_consistent_readback_must_match_every_expected_predicate_field(
    tmp_path: Path,
    field_name: str,
    value: object,
) -> None:
    case = _case(tmp_path)
    predicate = deepcopy(case.envelope.expected_effects[0].predicate)
    predicate[field_name] = value

    _assert_rejected(
        case,
        EvidenceReason.EXPECTED_EFFECT_MISMATCH,
        envelope=_replace_predicate(case.envelope, predicate),
    )


@pytest.mark.parametrize(
    "missing_field",
    ("content_sha256", "size_bytes", "correlation"),
)
def test_expected_predicate_must_have_the_exact_closed_shape(
    tmp_path: Path,
    missing_field: str,
) -> None:
    case = _case(tmp_path)
    predicate = deepcopy(case.envelope.expected_effects[0].predicate)
    predicate.pop(missing_field)

    _assert_rejected(
        case,
        EvidenceReason.EXPECTED_EFFECT_MISMATCH,
        envelope=_replace_predicate(case.envelope, predicate),
    )


def test_envelope_correlation_must_equal_the_expected_metadata(tmp_path: Path) -> None:
    case = _case(tmp_path)
    payload = case.envelope.model_dump(mode="python")
    payload["context"]["correlation_fields"] = {"request_id": "request-other"}
    mismatched = ExecutionEnvelope.model_validate(payload)

    _assert_rejected(
        case,
        EvidenceReason.EXPECTED_EFFECT_MISMATCH,
        envelope=mismatched,
    )


@pytest.mark.parametrize(
    ("section", "missing_field"),
    (
        ("object_metadata", "bucket_name"),
        ("object_metadata", "object_name"),
        ("object_metadata", "generation"),
        ("object_metadata", "content_sha256"),
        ("object_metadata", "size_bytes"),
        ("object_metadata", "correlation"),
        ("object_metadata", "observed_at"),
        ("receipt", "operation_id"),
        ("receipt", "bucket_name"),
        ("receipt", "object_name"),
        ("receipt", "generation"),
        ("receipt", "content_sha256"),
        ("receipt", "size_bytes"),
        ("receipt", "correlation_sha256"),
        ("receipt", "observed_at"),
    ),
)
def test_missing_readback_fields_are_malformed_not_authoritative(
    tmp_path: Path,
    section: str,
    missing_field: str,
) -> None:
    case = _case(tmp_path)
    observation = _mutate_observation(
        case.observation,
        section=section,
        field_name=missing_field,
        delete=True,
    )

    _assert_rejected(
        case,
        EvidenceReason.MALFORMED_OBSERVATION,
        observation=observation,
    )


@pytest.mark.parametrize("missing", ("object", "receipt", "both"))
def test_missing_records_are_weak_and_never_prove_non_execution(
    tmp_path: Path,
    missing: str,
) -> None:
    case = _case(tmp_path)
    if missing in {"object", "both"}:
        assert case.harness.harness_delete_object(bucket=_BUCKET, name=_OBJECT)
    if missing in {"receipt", "both"}:
        assert case.harness.harness_delete_receipt(operation_id=_OPERATION)
    observation = _observe(case.registration, case.probe)

    result = StorageReadbackNormalizer()(_rule_input(case, observation=observation))

    assert result.verdict is RuleVerdict.ABSENCE_ONLY
    assert result.operation_status is None
    assert result.operation_id is None
    assert all(item.state.value == "UNVERIFIED" for item in result.effect_assertions)


def test_overwrite_cannot_satisfy_the_immutable_generation_receipt(
    tmp_path: Path,
) -> None:
    case = _case(tmp_path)
    case.harness.overwrite_object(
        bucket=_BUCKET,
        name=_OBJECT,
        content=b"replacement",
        correlation=_CORRELATION,
        observed_at=_NOW + timedelta(seconds=1),
    )
    observation = _observe(case.registration, case.probe)

    _assert_rejected(
        case,
        EvidenceReason.UNVERIFIABLE_AUTHORITY,
        observation=observation,
    )


def test_corrupted_generation_receipt_is_never_authoritative(tmp_path: Path) -> None:
    case = _case(tmp_path)
    case.harness.harness_corrupt_receipt(
        operation_id=_OPERATION,
        generation=99,
    )
    observation = _observe(case.registration, case.probe)

    _assert_rejected(
        case,
        EvidenceReason.UNVERIFIABLE_AUTHORITY,
        observation=observation,
    )


def test_stale_target_or_read_timestamp_is_unverifiable(tmp_path: Path) -> None:
    case = _case(tmp_path)
    stale = _NOW - timedelta(minutes=2)
    case.harness.harness_corrupt_object_metadata(
        bucket=_BUCKET,
        name=_OBJECT,
        observed_at=stale,
    )
    case.harness.harness_corrupt_receipt(
        operation_id=_OPERATION,
        observed_at=stale,
    )
    stale_target = _observe(case.registration, case.probe)
    _assert_rejected(
        case,
        EvidenceReason.UNVERIFIABLE_AUTHORITY,
        observation=stale_target,
    )

    payload = case.observation.model_dump(mode="python")
    payload["observed_at"] = stale
    stale_read = ProbeObservation.model_validate(payload)
    _assert_rejected(
        case,
        EvidenceReason.UNVERIFIABLE_AUTHORITY,
        observation=stale_read,
        retrieved_at=_NOW + timedelta(seconds=1),
    )


def test_normalizer_rejects_nonempty_probe_arguments(tmp_path: Path) -> None:
    case = _case(tmp_path)
    request = _request(arguments={"unexpected": "value"})

    _assert_rejected(
        case,
        EvidenceReason.MALFORMED_OBSERVATION,
        request=request,
    )
