"""Composite local business-document evidence normalization."""

from __future__ import annotations

import asyncio
import hashlib
from copy import deepcopy
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from reconcile.adapters.firestore_business import (
    FIRESTORE_BUSINESS_AUTHORITY_POLICY_VERSION,
    FIRESTORE_BUSINESS_CAPABILITY_NAME,
    FIRESTORE_BUSINESS_CAPABILITY_VERSION,
    FIRESTORE_BUSINESS_CLASSIFICATION_POLICY_VERSION,
    FIRESTORE_BUSINESS_CLOUD_AUTHORITY_POLICY_VERSION,
    FIRESTORE_BUSINESS_CLOUD_ENVIRONMENT,
    FIRESTORE_BUSINESS_CLOUD_PROFILE,
    FIRESTORE_BUSINESS_CLOUD_SOURCE,
    FIRESTORE_BUSINESS_ENVIRONMENT,
    FIRESTORE_BUSINESS_SOURCE,
    FIRESTORE_BUSINESS_TARGET_KIND,
    FirestoreBusinessReadbackNormalizer,
    build_firestore_business_capability,
    build_firestore_business_capability_registration,
    build_firestore_business_rule_registration,
    build_firestore_business_target,
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
from reconcile.hosted.firestore_business import build_google_firestore_business_targets
from reconcile.scenarios.local_firestore import (
    BusinessDocumentCoordinate,
    BusinessDocumentWrite,
    BusinessOperationReadback,
    LocalFirestoreMutationTarget,
    LocalFirestoreReadTarget,
    expected_effect_declarations_sha256,
)

pytestmark = pytest.mark.unit

_NOW = datetime(2026, 8, 13, 20, 0, tzinfo=UTC)
_NAMESPACE = "scenario-business-7"
_OPERATION = "operation-business-7"
_MANIFEST_COLLECTION = "operations"
_MANIFEST_DOCUMENT = _OPERATION
_CORRELATION = {
    "business_request_id": "request-7",
    "operation_id": _OPERATION,
    "run_id": "run-7",
}
_DECLARATIONS = (
    (
        "primary-request",
        "requests",
        "request-7",
        hashlib.sha256(b"primary-content").hexdigest(),
    ),
    (
        "audit-record",
        "audit",
        "audit-7",
        hashlib.sha256(b"audit-content").hexdigest(),
    ),
    (
        "processing-index",
        "processing",
        "processing-7",
        hashlib.sha256(b"processing-content").hexdigest(),
    ),
)
_EFFECT_IDS = tuple(item[0] for item in _DECLARATIONS)
_COORDINATES = tuple(
    BusinessDocumentCoordinate(
        effect_id=effect_id,
        collection_name=collection_name,
        document_id=document_id,
    )
    for effect_id, collection_name, document_id, _ in _DECLARATIONS
)


def _target() -> TargetBinding:
    return build_firestore_business_target(
        namespace_id=_NAMESPACE,
        manifest_collection=_MANIFEST_COLLECTION,
        manifest_document_id=_MANIFEST_DOCUMENT,
        document_coordinates=_COORDINATES,
    )


def _envelope() -> ExecutionEnvelope:
    arguments = {
        "business_request_id": _CORRELATION["business_request_id"],
        "operation_id": _OPERATION,
    }
    return ExecutionEnvelope(
        schema_version=EXECUTION_ENVELOPE_VERSION,
        investigation_id="investigation-business-7",
        operation_id=_OPERATION,
        target=_target(),
        invoked_at=_NOW - timedelta(seconds=1),
        ambiguity=AmbiguousExecution(
            kind=AmbiguityKind.PROCESS_INTERRUPTED,
            observed_at=_NOW + timedelta(seconds=1),
            detail="The local multi-step business operation returned no result.",
        ),
        expected_effects=tuple(
            ExpectedEffect(
                schema_version=EXPECTED_EFFECT_VERSION,
                effect_id=effect_id,
                commit_scope=f"business-step-{index}",
                predicate={
                    "collection_name": collection_name,
                    "document_id": document_id,
                    "content_sha256": content_sha256,
                    "correlation": _CORRELATION,
                },
                description="One separately committed business document effect.",
            )
            for index, (
                effect_id,
                collection_name,
                document_id,
                content_sha256,
            ) in enumerate(_DECLARATIONS, start=1)
        ),
        context=EnvelopeContext(
            invocation=OriginalInvocation(
                invocation_id="invocation-business-7",
                function_call_id="function-call-business-7",
                tool_name="create-business-operation",
                tool_version="1.0.0",
                arguments=arguments,
                arguments_sha256=hashlib.sha256(
                    canonical_json_value_bytes(arguments)
                ).hexdigest(),
            ),
            enabled_capabilities=(
                CapabilityRef(
                    name=FIRESTORE_BUSINESS_CAPABILITY_NAME,
                    version=FIRESTORE_BUSINESS_CAPABILITY_VERSION,
                ),
            ),
            correlation_fields=_CORRELATION,
            evidence_budget=EvidenceBudget(
                max_probes=1,
                max_elapsed_ms=2_000,
                max_total_result_bytes=32_768,
                max_cost_units=1,
            ),
            freshness=FreshnessPolicy(
                max_age_seconds=60,
                clock_skew_seconds=2,
            ),
            policies=PolicyReferences(
                authority=FIRESTORE_BUSINESS_AUTHORITY_POLICY_VERSION,
                classification=FIRESTORE_BUSINESS_CLASSIFICATION_POLICY_VERSION,
                action="action-v1",
            ),
        ),
    )


def _request(
    *,
    relevant_effect_ids: tuple[str, ...] = _EFFECT_IDS,
    arguments: dict[str, object] | None = None,
) -> ProbeRequest:
    return ProbeRequest(
        schema_version=PROBE_REQUEST_VERSION,
        capability_name=FIRESTORE_BUSINESS_CAPABILITY_NAME,
        capability_version=FIRESTORE_BUSINESS_CAPABILITY_VERSION,
        relevant_effect_ids=relevant_effect_ids,
        arguments={} if arguments is None else arguments,
        rationale="Read the operation manifest and three exact business documents.",
    )


def _manifest(
    established: tuple[str, ...],
    *,
    status: str = "TERMINAL_COMMITTED",
    not_established: tuple[str, ...] | None = None,
) -> dict[str, object]:
    if not_established is None:
        not_established = tuple(
            effect_id for effect_id in _EFFECT_IDS if effect_id not in established
        )
    effect_revisions = {
        effect_id: index for index, effect_id in enumerate(established, start=1)
    }
    return {
        "namespace_id": _NAMESPACE,
        "operation_id": _OPERATION,
        "manifest_collection": _MANIFEST_COLLECTION,
        "manifest_document_id": _MANIFEST_DOCUMENT,
        "status": status,
        "revision": max(1, len(established)),
        "expected_effect_ids": list(_EFFECT_IDS),
        "expected_effects_sha256": expected_effect_declarations_sha256(_DECLARATIONS),
        "established_effect_ids": list(established),
        "not_established_effect_ids": list(not_established),
        "effect_revisions": effect_revisions,
        "correlation": _CORRELATION,
        "observed_at": _NOW.isoformat(),
    }


def _documents(
    established: tuple[str, ...],
) -> list[dict[str, object]]:
    declaration_by_id = {item[0]: item for item in _DECLARATIONS}
    return [
        {
            "effect_id": effect_id,
            "collection_name": declaration_by_id[effect_id][1],
            "document_id": declaration_by_id[effect_id][2],
            "operation_id": _OPERATION,
            "revision": index,
            "content_sha256": declaration_by_id[effect_id][3],
            "correlation": _CORRELATION,
            "observed_at": _NOW.isoformat(),
        }
        for index, effect_id in enumerate(established, start=1)
    ]


def _observation(
    established: tuple[str, ...],
    *,
    status: str = "TERMINAL_COMMITTED",
    not_established: tuple[str, ...] | None = None,
) -> ProbeObservation:
    return ProbeObservation(
        observed_at=_NOW + timedelta(seconds=1),
        payload={
            "manifest": _manifest(
                established,
                status=status,
                not_established=not_established,
            ),
            "documents": _documents(established),
        },
    )


def _rule_input(
    *,
    observation: ProbeObservation,
    envelope: ExecutionEnvelope | None = None,
    request: ProbeRequest | None = None,
    retrieved_at: datetime | None = None,
) -> RuleInput:
    return RuleInput(
        envelope=envelope or _envelope(),
        request=request or _request(),
        observation=canonical_json_bytes(observation),
        retrieved_at=(
            observation.observed_at + timedelta(milliseconds=1)
            if retrieved_at is None
            else retrieved_at
        ),
    )


def _replace_observation(
    observation: ProbeObservation,
    path: tuple[str | int, ...],
    value: object,
    *,
    delete: bool = False,
) -> ProbeObservation:
    payload = observation.model_dump(mode="python")
    cursor: object = payload["payload"]
    for part in path[:-1]:
        assert isinstance(cursor, (dict, list))
        cursor = cursor[part]  # type: ignore[index]
    assert isinstance(cursor, (dict, list))
    key = path[-1]
    if delete:
        assert isinstance(cursor, dict)
        cursor.pop(key)  # type: ignore[arg-type]
    else:
        cursor[key] = value  # type: ignore[index]
    return ProbeObservation.model_validate(payload)


def _assert_rejected(
    observation: ProbeObservation,
    reason: EvidenceReason,
    *,
    envelope: ExecutionEnvelope | None = None,
    request: ProbeRequest | None = None,
    retrieved_at: datetime | None = None,
) -> None:
    with pytest.raises(RuleRejected) as raised:
        FirestoreBusinessReadbackNormalizer()(
            _rule_input(
                observation=observation,
                envelope=envelope,
                request=request,
                retrieved_at=retrieved_at,
            )
        )
    assert raised.value.reason is reason


def test_capability_is_empty_argument_read_only_and_exactly_bound(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    target = _target()
    capability = build_firestore_business_capability(target)
    read_target = LocalFirestoreReadTarget(tmp_path / "business.sqlite3")
    calls: list[dict[str, object]] = []

    def read(
        _target: LocalFirestoreReadTarget,
        **kwargs: object,
    ) -> BusinessOperationReadback:
        calls.append(kwargs)
        return BusinessOperationReadback(manifest=None, documents=())

    monkeypatch.setattr(LocalFirestoreReadTarget, "read", read)
    registration = build_firestore_business_capability_registration(
        read_target=read_target,
        target=target,
        clock=lambda: _NOW,
    )
    probe = BoundProbe(
        investigation_id="investigation-business-7",
        operation_id=_OPERATION,
        capability_name=FIRESTORE_BUSINESS_CAPABILITY_NAME,
        capability_version=FIRESTORE_BUSINESS_CAPABILITY_VERSION,
        target=target,
        relevant_effect_ids=_EFFECT_IDS,
        arguments={},
        timeout_ms=capability.timeout_ms,
        result_byte_ceiling=capability.result_byte_ceiling,
    )

    handler = registration.handler
    assert handler is not None
    result = asyncio.run(handler(probe))

    assert target.target_kind == FIRESTORE_BUSINESS_TARGET_KIND
    assert target.scope == {
        "environment": FIRESTORE_BUSINESS_ENVIRONMENT,
        "namespace_id": _NAMESPACE,
    }
    assert capability.argument_schema["properties"] == {}
    assert capability.argument_schema["additionalProperties"] is False
    assert registration.semantics is CapabilitySemantics.READ_ONLY
    assert registration.max_invocations == 1
    assert result.payload == {"manifest": None, "documents": []}
    assert calls == [
        {
            "namespace_id": _NAMESPACE,
            "operation_id": _OPERATION,
            "manifest_collection": _MANIFEST_COLLECTION,
            "manifest_document_id": _MANIFEST_DOCUMENT,
            "document_coordinates": _COORDINATES,
        }
    ]
    descriptor = build_firestore_business_rule_registration().descriptor
    assert descriptor.source == FIRESTORE_BUSINESS_SOURCE


def test_cloud_profile_accepts_only_the_sealed_cloud_read_target() -> None:
    class CloudReadPort:
        async def read_business_operation(
            self,
            **kwargs: object,
        ) -> BusinessOperationReadback:
            assert kwargs["namespace_id"] == _NAMESPACE
            return BusinessOperationReadback(manifest=None, documents=())

    target = build_firestore_business_target(
        namespace_id=_NAMESPACE,
        manifest_collection=_MANIFEST_COLLECTION,
        manifest_document_id=_MANIFEST_DOCUMENT,
        document_coordinates=_COORDINATES,
        profile=FIRESTORE_BUSINESS_CLOUD_PROFILE,
    )
    with pytest.raises(TypeError, match="sealed read target"):
        build_firestore_business_capability_registration(
            read_target=CloudReadPort(),
            target=target,
            clock=lambda: _NOW,
            profile=FIRESTORE_BUSINESS_CLOUD_PROFILE,
        )
    cloud_targets = build_google_firestore_business_targets(
        project_id="example-project-id",
        client_factory=lambda: object(),  # type: ignore[arg-type]
        server_timestamp_factory=object,
    )
    registration = build_firestore_business_capability_registration(
        read_target=cloud_targets.read,
        target=target,
        clock=lambda: _NOW,
        profile=FIRESTORE_BUSINESS_CLOUD_PROFILE,
    )
    assert registration.handler is not None
    descriptor = build_firestore_business_rule_registration(
        FIRESTORE_BUSINESS_CLOUD_PROFILE
    ).descriptor

    assert target.scope["environment"] == FIRESTORE_BUSINESS_CLOUD_ENVIRONMENT
    assert registration.capability.timeout_ms == 5_000
    assert (
        descriptor.authority_policy_version
        == FIRESTORE_BUSINESS_CLOUD_AUTHORITY_POLICY_VERSION
    )
    assert descriptor.source == FIRESTORE_BUSINESS_CLOUD_SOURCE
    _assert_rejected(
        _observation((_EFFECT_IDS[0],)),
        EvidenceReason.UNVERIFIABLE_AUTHORITY,
        envelope=_envelope().model_copy(update={"target": target}),
    )


def test_handler_rejects_changed_target_or_incomplete_effect_request(
    tmp_path: Path,
) -> None:
    target = _target()
    registration = build_firestore_business_capability_registration(
        read_target=LocalFirestoreReadTarget(tmp_path / "business.sqlite3"),
        target=target,
        clock=lambda: _NOW,
    )
    capability = registration.capability
    probe = BoundProbe(
        investigation_id="investigation-business-7",
        operation_id=_OPERATION,
        capability_name=FIRESTORE_BUSINESS_CAPABILITY_NAME,
        capability_version=FIRESTORE_BUSINESS_CAPABILITY_VERSION,
        target=target,
        relevant_effect_ids=_EFFECT_IDS[:-1],
        arguments={},
        timeout_ms=capability.timeout_ms,
        result_byte_ceiling=capability.result_byte_ceiling,
    )
    handler = registration.handler
    assert handler is not None

    with pytest.raises(CapabilityUnavailable):
        asyncio.run(handler(probe))


def test_actual_snapshot_readback_normalizes_a_terminal_subset(
    tmp_path: Path,
) -> None:
    database_path = tmp_path / "business.sqlite3"
    mutation = LocalFirestoreMutationTarget(database_path, clock=lambda: _NOW)
    documents = tuple(
        BusinessDocumentWrite(
            effect_id=effect_id,
            collection_name=collection_name,
            document_id=document_id,
            content={
                "primary-request": b"primary-content",
                "audit-record": b"audit-content",
                "processing-index": b"processing-content",
            }[effect_id],
        )
        for effect_id, collection_name, document_id, _ in _DECLARATIONS
    )
    mutation.commit_business_operation(
        namespace_id=_NAMESPACE,
        operation_id=_OPERATION,
        manifest_collection=_MANIFEST_COLLECTION,
        manifest_document_id=_MANIFEST_DOCUMENT,
        documents=documents,
        selected_effect_ids=(_EFFECT_IDS[0], _EFFECT_IDS[2]),
        correlation=_CORRELATION,
    )
    target = _target()
    registration = build_firestore_business_capability_registration(
        read_target=LocalFirestoreReadTarget(database_path),
        target=target,
        clock=lambda: _NOW + timedelta(seconds=1),
    )
    capability = registration.capability
    probe = BoundProbe(
        investigation_id="investigation-business-7",
        operation_id=_OPERATION,
        capability_name=FIRESTORE_BUSINESS_CAPABILITY_NAME,
        capability_version=FIRESTORE_BUSINESS_CAPABILITY_VERSION,
        target=target,
        relevant_effect_ids=_EFFECT_IDS,
        arguments={},
        timeout_ms=capability.timeout_ms,
        result_byte_ceiling=capability.result_byte_ceiling,
    )
    handler = registration.handler
    assert handler is not None

    observation = asyncio.run(handler(probe))
    result = FirestoreBusinessReadbackNormalizer()(_rule_input(observation=observation))

    assert result.verdict is RuleVerdict.AUTHORITATIVE_EFFECTS
    assert result.operation_status is OperationStatus.TERMINAL_COMMITTED
    assert [item.state.value for item in result.effect_assertions] == [
        "ESTABLISHED",
        "NOT_ESTABLISHED",
        "ESTABLISHED",
    ]
    assert b'"content":' not in canonical_json_bytes(observation)


@pytest.mark.parametrize("mask", range(8))
def test_every_terminal_effect_subset_emits_complete_authoritative_assertions(
    mask: int,
) -> None:
    established = tuple(
        effect_id for index, effect_id in enumerate(_EFFECT_IDS) if mask & (1 << index)
    )
    if not established:
        status = "TERMINAL_NOT_COMMITTED"
        verdict = RuleVerdict.AUTHORITATIVE_NON_EXECUTION
        operation_status = OperationStatus.TERMINAL_NOT_COMMITTED
    else:
        status = "TERMINAL_COMMITTED"
        verdict = RuleVerdict.AUTHORITATIVE_EFFECTS
        operation_status = OperationStatus.TERMINAL_COMMITTED

    result = FirestoreBusinessReadbackNormalizer()(
        _rule_input(
            observation=_observation(established, status=status),
        )
    )

    assert result.verdict is verdict
    assert result.operation_status is operation_status
    assert result.operation_id == _OPERATION
    assert result.correlation == _CORRELATION
    assert {item.effect_id: item.state.value for item in result.effect_assertions} == {
        effect_id: ("ESTABLISHED" if effect_id in established else "NOT_ESTABLISHED")
        for effect_id in _EFFECT_IDS
    }


@pytest.mark.parametrize(
    "established",
    ((), (_EFFECT_IDS[0],), (_EFFECT_IDS[0], _EFFECT_IDS[2])),
)
def test_active_manifest_is_pending_without_inferred_absence(
    established: tuple[str, ...],
) -> None:
    result = FirestoreBusinessReadbackNormalizer()(
        _rule_input(
            observation=_observation(
                established,
                status="ACTIVE",
                not_established=(),
            )
        )
    )

    assert result.verdict is RuleVerdict.AUTHORITATIVE_PENDING
    assert result.operation_status is OperationStatus.ACTIVE
    assert {item.effect_id: item.state.value for item in result.effect_assertions} == {
        effect_id: ("ESTABLISHED" if effect_id in established else "UNVERIFIED")
        for effect_id in _EFFECT_IDS
    }


def test_missing_operation_is_weak_and_never_proves_non_execution() -> None:
    observation = ProbeObservation(
        observed_at=_NOW + timedelta(seconds=1),
        payload={"manifest": None, "documents": []},
    )

    result = FirestoreBusinessReadbackNormalizer()(_rule_input(observation=observation))

    assert result.verdict is RuleVerdict.ABSENCE_ONLY
    assert result.operation_status is None
    assert result.operation_id is None
    assert all(
        assertion.state.value == "UNVERIFIED" for assertion in result.effect_assertions
    )


@pytest.mark.parametrize(
    ("path", "value", "reason"),
    (
        (
            ("manifest", "namespace_id"),
            "wrong-namespace",
            EvidenceReason.UNVERIFIABLE_AUTHORITY,
        ),
        (
            ("manifest", "operation_id"),
            "wrong-operation",
            EvidenceReason.UNVERIFIABLE_AUTHORITY,
        ),
        (
            ("manifest", "manifest_collection"),
            "wrong-collection",
            EvidenceReason.UNVERIFIABLE_AUTHORITY,
        ),
        (
            ("manifest", "manifest_document_id"),
            "wrong-document",
            EvidenceReason.UNVERIFIABLE_AUTHORITY,
        ),
        (
            ("manifest", "expected_effect_ids"),
            list(_EFFECT_IDS[::-1]),
            EvidenceReason.EXPECTED_EFFECT_MISMATCH,
        ),
        (
            ("manifest", "expected_effects_sha256"),
            "f" * 64,
            EvidenceReason.EXPECTED_EFFECT_MISMATCH,
        ),
        (
            ("manifest", "correlation"),
            {**_CORRELATION, "run_id": "wrong"},
            EvidenceReason.EXPECTED_EFFECT_MISMATCH,
        ),
        (
            ("documents", 0, "collection_name"),
            "wrong-collection",
            EvidenceReason.UNVERIFIABLE_AUTHORITY,
        ),
        (
            ("documents", 0, "document_id"),
            "wrong-document",
            EvidenceReason.UNVERIFIABLE_AUTHORITY,
        ),
        (
            ("documents", 0, "operation_id"),
            "wrong-operation",
            EvidenceReason.UNVERIFIABLE_AUTHORITY,
        ),
        (
            ("documents", 0, "content_sha256"),
            "e" * 64,
            EvidenceReason.UNVERIFIABLE_AUTHORITY,
        ),
        (
            ("documents", 0, "correlation"),
            {**_CORRELATION, "run_id": "wrong"},
            EvidenceReason.UNVERIFIABLE_AUTHORITY,
        ),
    ),
)
def test_wrong_identity_digest_or_correlation_is_rejected(
    path: tuple[str | int, ...],
    value: object,
    reason: EvidenceReason,
) -> None:
    observation = _replace_observation(
        _observation((_EFFECT_IDS[0],)),
        path,
        value,
    )

    _assert_rejected(observation, reason)


@pytest.mark.parametrize(
    ("established", "status", "not_established", "path", "value"),
    (
        ((_EFFECT_IDS[0],), "TERMINAL_COMMITTED", (_EFFECT_IDS[1],), (), None),
        (
            (_EFFECT_IDS[0],),
            "TERMINAL_COMMITTED",
            (_EFFECT_IDS[0], _EFFECT_IDS[1], _EFFECT_IDS[2]),
            (),
            None,
        ),
        ((), "TERMINAL_COMMITTED", _EFFECT_IDS, (), None),
        (
            (_EFFECT_IDS[0],),
            "TERMINAL_NOT_COMMITTED",
            (_EFFECT_IDS[1], _EFFECT_IDS[2]),
            (),
            None,
        ),
        ((_EFFECT_IDS[0],), "ACTIVE", (_EFFECT_IDS[1],), (), None),
        (_EFFECT_IDS, "ACTIVE", (), (), None),
        (
            (_EFFECT_IDS[0],),
            "TERMINAL_COMMITTED",
            (_EFFECT_IDS[1], _EFFECT_IDS[2]),
            ("manifest", "effect_revisions"),
            {},
        ),
        (
            (_EFFECT_IDS[0],),
            "TERMINAL_COMMITTED",
            (_EFFECT_IDS[1], _EFFECT_IDS[2]),
            ("manifest", "revision"),
            2,
        ),
    ),
)
def test_invalid_partition_status_or_revision_is_rejected(
    established: tuple[str, ...],
    status: str,
    not_established: tuple[str, ...],
    path: tuple[str | int, ...],
    value: object,
) -> None:
    observation = _observation(
        established,
        status=status,
        not_established=not_established,
    )
    if path:
        observation = _replace_observation(observation, path, value)

    _assert_rejected(observation, EvidenceReason.UNVERIFIABLE_AUTHORITY)


def test_duplicate_unrelated_missing_or_contradictory_documents_are_rejected() -> None:
    base = _observation((_EFFECT_IDS[0],))
    payload = base.model_dump(mode="python")
    documents = payload["payload"]["documents"]
    assert isinstance(documents, list)

    duplicate_payload = deepcopy(payload)
    duplicate_documents = duplicate_payload["payload"]["documents"]
    assert isinstance(duplicate_documents, list)
    duplicate_documents.append(deepcopy(duplicate_documents[0]))
    _assert_rejected(
        ProbeObservation.model_validate(duplicate_payload),
        EvidenceReason.DUPLICATE_CANDIDATES,
    )

    unrelated_payload = deepcopy(payload)
    unrelated_documents = unrelated_payload["payload"]["documents"]
    assert isinstance(unrelated_documents, list)
    unrelated = deepcopy(unrelated_documents[0])
    unrelated["effect_id"] = "unrelated-effect"
    unrelated["collection_name"] = "unrelated"
    unrelated["document_id"] = "unrelated-7"
    unrelated_documents.append(unrelated)
    _assert_rejected(
        ProbeObservation.model_validate(unrelated_payload),
        EvidenceReason.UNVERIFIABLE_AUTHORITY,
    )

    missing_payload = deepcopy(payload)
    missing_payload["payload"]["documents"] = []
    _assert_rejected(
        ProbeObservation.model_validate(missing_payload),
        EvidenceReason.UNVERIFIABLE_AUTHORITY,
    )

    contradictory_payload = deepcopy(payload)
    contradictory_documents = contradictory_payload["payload"]["documents"]
    assert isinstance(contradictory_documents, list)
    declaration = _DECLARATIONS[1]
    contradictory_documents.append(
        {
            "effect_id": declaration[0],
            "collection_name": declaration[1],
            "document_id": declaration[2],
            "operation_id": _OPERATION,
            "revision": 2,
            "content_sha256": declaration[3],
            "correlation": _CORRELATION,
            "observed_at": _NOW.isoformat(),
        }
    )
    _assert_rejected(
        ProbeObservation.model_validate(contradictory_payload),
        EvidenceReason.UNVERIFIABLE_AUTHORITY,
    )


def test_documents_without_a_manifest_are_inconsistent_not_negative_proof() -> None:
    observation = _observation((_EFFECT_IDS[0],))
    observation = _replace_observation(observation, ("manifest",), None)

    _assert_rejected(observation, EvidenceReason.UNVERIFIABLE_AUTHORITY)


@pytest.mark.parametrize(
    ("path", "timestamp"),
    (
        (("manifest", "observed_at"), _NOW - timedelta(minutes=5)),
        (("documents", 0, "observed_at"), _NOW - timedelta(minutes=5)),
        (("documents", 0, "observed_at"), _NOW + timedelta(minutes=5)),
    ),
)
def test_stale_or_future_target_timestamps_are_rejected(
    path: tuple[str | int, ...],
    timestamp: datetime,
) -> None:
    observation = _replace_observation(
        _observation((_EFFECT_IDS[0],)),
        path,
        timestamp.isoformat(),
    )

    _assert_rejected(observation, EvidenceReason.UNVERIFIABLE_AUTHORITY)


def test_stale_read_timestamp_is_rejected() -> None:
    observation = _observation((_EFFECT_IDS[0],))
    payload = observation.model_dump(mode="python")
    payload["observed_at"] = _NOW - timedelta(minutes=5)
    stale = ProbeObservation.model_validate(payload)

    _assert_rejected(
        stale,
        EvidenceReason.UNVERIFIABLE_AUTHORITY,
        retrieved_at=_NOW + timedelta(seconds=2),
    )


@pytest.mark.parametrize(
    ("path", "delete"),
    (
        (("manifest", "revision"), True),
        (("documents", 0, "content_sha256"), True),
        (("manifest", "unexpected"), False),
        (("documents", 0, "unexpected"), False),
    ),
)
def test_malformed_or_extra_readback_fields_are_rejected(
    path: tuple[str | int, ...],
    delete: bool,
) -> None:
    observation = _replace_observation(
        _observation((_EFFECT_IDS[0],)),
        path,
        "unexpected",
        delete=delete,
    )

    _assert_rejected(observation, EvidenceReason.MALFORMED_OBSERVATION)


def test_request_must_cover_all_effects_with_empty_arguments() -> None:
    observation = _observation((_EFFECT_IDS[0],))
    _assert_rejected(
        observation,
        EvidenceReason.EXPECTED_EFFECT_MISMATCH,
        request=_request(relevant_effect_ids=_EFFECT_IDS[:-1]),
    )
    _assert_rejected(
        observation,
        EvidenceReason.MALFORMED_OBSERVATION,
        request=_request(arguments={"effect_id": _EFFECT_IDS[0]}),
    )


def test_envelope_requires_three_separate_exact_effect_declarations() -> None:
    observation = _observation((_EFFECT_IDS[0],))
    envelope_payload = _envelope().model_dump(mode="python")
    envelope_payload["expected_effects"][1]["commit_scope"] = envelope_payload[
        "expected_effects"
    ][0]["commit_scope"]
    repeated_scope = ExecutionEnvelope.model_validate(envelope_payload)
    _assert_rejected(
        observation,
        EvidenceReason.EXPECTED_EFFECT_MISMATCH,
        envelope=repeated_scope,
    )

    envelope_payload = _envelope().model_dump(mode="python")
    envelope_payload["expected_effects"][0]["predicate"].pop("document_id")
    incomplete = ExecutionEnvelope.model_validate(envelope_payload)
    _assert_rejected(
        observation,
        EvidenceReason.EXPECTED_EFFECT_MISMATCH,
        envelope=incomplete,
    )


def test_target_builder_rejects_duplicate_or_nonexact_coordinates() -> None:
    with pytest.raises(ValueError, match="coordinates must be unique"):
        build_firestore_business_target(
            namespace_id=_NAMESPACE,
            manifest_collection=_MANIFEST_COLLECTION,
            manifest_document_id=_MANIFEST_DOCUMENT,
            document_coordinates=(
                _COORDINATES[0],
                BusinessDocumentCoordinate(
                    effect_id=_COORDINATES[1].effect_id,
                    collection_name=_COORDINATES[0].collection_name,
                    document_id=_COORDINATES[0].document_id,
                ),
                _COORDINATES[2],
            ),
        )

    target_payload = _target().model_dump(mode="python")
    target_payload["resource"]["effect_documents"][0]["unexpected"] = True
    malformed = TargetBinding.model_validate(target_payload)
    with pytest.raises(ValueError, match="coordinates are malformed"):
        build_firestore_business_capability(malformed)
