"""End-to-end local three-effect business-operation reconciliation."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from reconcile.contracts import (
    SCENARIO_RUN_REQUEST_VERSION,
    AmbiguityKind,
    Classification,
    EffectAssertionState,
    EvidenceDisposition,
    OperationStatus,
    ScenarioCallerObservation,
    ScenarioCleanupDisposition,
    ScenarioFaultAction,
    ScenarioFaultInstruction,
    ScenarioFaultPoint,
    ScenarioRunRequest,
    ScenarioRunResult,
    ScenarioTransportEvent,
    ScenarioWorkerTermination,
    canonical_json_bytes,
)
from reconcile.scenarios.firestore_business import (
    FIRESTORE_BUSINESS_EFFECT_IDS,
    FIRESTORE_BUSINESS_SCENARIO,
    FirestoreBusinessScenarioDefinition,
)
from reconcile.scenarios.local_firestore import (
    BusinessDocumentCoordinate,
    BusinessDocumentWrite,
    BusinessOperationReadback,
    LocalFirestoreHarness,
    LocalFirestoreReadTarget,
)
from reconcile.scenarios.runner import ScenarioRunner

pytestmark = pytest.mark.integration

NOW = datetime(2026, 8, 13, 21, 0, tzinfo=UTC)


class _StepClock:
    def __init__(self, current: datetime) -> None:
        self._current = current
        self._monotonic = 100.0

    def now(self) -> datetime:
        result = self._current
        self._current += timedelta(milliseconds=1)
        return result

    def monotonic(self) -> float:
        self._monotonic += 0.001
        return self._monotonic


def _request(
    mask: int,
    *,
    suffix: str,
    fault_point: ScenarioFaultPoint = ScenarioFaultPoint.POST_COMMIT,
) -> ScenarioRunRequest:
    return ScenarioRunRequest(
        schema_version=SCENARIO_RUN_REQUEST_VERSION,
        scenario=FIRESTORE_BUSINESS_SCENARIO,
        run_id=f"run-business-{suffix}",
        investigation_id=f"investigation-business-{suffix}",
        operation_id=f"operation-business-{suffix}",
        invocation_id=f"invocation-business-{suffix}",
        function_call_id=f"function-call-business-{suffix}",
        seed=mask,
        fault=ScenarioFaultInstruction(
            point=fault_point,
            action=ScenarioFaultAction.INTERRUPT_PROCESS,
        ),
    )


def _run(
    tmp_path: Path,
    *,
    mask: int,
    suffix: str,
) -> tuple[
    ScenarioRunner,
    FirestoreBusinessScenarioDefinition,
    ScenarioRunRequest,
    ScenarioRunResult,
    LocalFirestoreHarness,
]:
    database_path = tmp_path / f"{suffix}.sqlite3"
    definition = FirestoreBusinessScenarioDefinition(
        database_path,
        invoked_at=NOW,
        target_clock=lambda: NOW,
    )
    runner = ScenarioRunner(clock=_StepClock(NOW + timedelta(seconds=1)))
    request = _request(mask, suffix=suffix)
    result = runner.run(request, definition)
    assert result.execution_envelope is not None
    return (
        runner,
        definition,
        request,
        result,
        LocalFirestoreHarness(
            database_path,
            clock=lambda: NOW + timedelta(seconds=3),
        ),
    )


def _report(
    definition: FirestoreBusinessScenarioDefinition,
    result: ScenarioRunResult,
):
    envelope = result.execution_envelope
    assert envelope is not None
    return definition.investigate(
        envelope,
        clock=_StepClock(NOW + timedelta(seconds=2)),
    )


def _expected_partition(mask: int) -> tuple[set[str], set[str]]:
    established = {
        effect_id
        for index, effect_id in enumerate(FIRESTORE_BUSINESS_EFFECT_IDS)
        if mask & (1 << index)
    }
    return established, set(FIRESTORE_BUSINESS_EFFECT_IDS) - established


def _coordinates(result: ScenarioRunResult) -> tuple[BusinessDocumentCoordinate, ...]:
    envelope = result.execution_envelope
    assert envelope is not None
    coordinates: list[BusinessDocumentCoordinate] = []
    for effect in envelope.expected_effects:
        collection_name = effect.predicate.get("collection_name")
        document_id = effect.predicate.get("document_id")
        assert isinstance(collection_name, str)
        assert isinstance(document_id, str)
        coordinates.append(
            BusinessDocumentCoordinate(
                effect_id=effect.effect_id,
                collection_name=collection_name,
                document_id=document_id,
            )
        )
    return tuple(coordinates)


def _readback(
    harness: LocalFirestoreHarness,
    result: ScenarioRunResult,
):
    envelope = result.execution_envelope
    assert envelope is not None
    namespace_id = envelope.target.scope.get("namespace_id")
    manifest_collection = envelope.target.resource.get("manifest_collection")
    manifest_document_id = envelope.target.resource.get("manifest_document_id")
    assert isinstance(namespace_id, str)
    assert isinstance(manifest_collection, str)
    assert isinstance(manifest_document_id, str)
    return harness.read(
        namespace_id=namespace_id,
        operation_id=result.operation_id,
        manifest_collection=manifest_collection,
        manifest_document_id=manifest_document_id,
        document_coordinates=_coordinates(result),
    )


def _assert_public_contract(result: ScenarioRunResult) -> None:
    envelope = result.execution_envelope
    assert envelope is not None
    assert (
        tuple(effect.effect_id for effect in envelope.expected_effects)
        == FIRESTORE_BUSINESS_EFFECT_IDS
    )
    assert set(envelope.context.correlation_fields) == {
        "business_request_id",
        "operation_id",
        "run_id",
    }
    assert envelope.context.correlation_fields["operation_id"] == result.operation_id
    for effect in envelope.expected_effects:
        assert set(effect.predicate) == {
            "collection_name",
            "document_id",
            "content_sha256",
            "correlation",
        }
        assert effect.predicate["correlation"] == envelope.context.correlation_fields
        assert "separately committed" in effect.description

    assert result.trace.caller_observation is ScenarioCallerObservation.NO_RESPONSE
    assert result.trace.worker_termination is ScenarioWorkerTermination.SIGNALED
    assert result.trace.events[-2].event is ScenarioTransportEvent.WORKER_INTERRUPTED
    assert ScenarioTransportEvent.POST_COMMIT_REACHED in {
        event.event for event in result.trace.events
    }
    assert ScenarioTransportEvent.RESPONSE_AVAILABLE not in {
        event.event for event in result.trace.events
    }
    assert result.trace.response_sha256 is None
    assert result.trace.response_byte_count is None
    assert envelope.ambiguity.kind is AmbiguityKind.PROCESS_INTERRUPTED

    public_bytes = canonical_json_bytes(envelope) + canonical_json_bytes(result.trace)
    for hidden_term in (
        b'"seed"',
        b"selected_effect",
        b"established_effect_ids",
        b"not_established_effect_ids",
        b"subset",
    ):
        assert hidden_term not in public_bytes


@pytest.mark.parametrize(
    "mask",
    range(8),
    ids=(
        "none",
        "primary",
        "audit",
        "primary-audit",
        "processing",
        "primary-processing",
        "audit-processing",
        "all",
    ),
)
def test_every_effect_mask_has_the_exact_deterministic_classification(
    tmp_path: Path,
    mask: int,
) -> None:
    _, definition, _, result, _ = _run(
        tmp_path,
        mask=mask,
        suffix=f"mask-{mask}",
    )
    _assert_public_contract(result)

    report = _report(definition, result)
    established, not_established = _expected_partition(mask)
    if mask == 0:
        expected_classification = Classification.NOT_COMMITTED
        expected_status = OperationStatus.TERMINAL_NOT_COMMITTED
    elif mask == 0b111:
        expected_classification = Classification.COMMITTED
        expected_status = OperationStatus.TERMINAL_COMMITTED
    else:
        expected_classification = Classification.PARTIAL
        expected_status = OperationStatus.TERMINAL_COMMITTED

    assert report.classification is expected_classification
    assert report.proof is not None
    assert report.proof.operation_status is expected_status
    states = {
        finding.effect_id: finding.state for finding in report.proof.effect_findings
    }
    assert set(states) == set(FIRESTORE_BUSINESS_EFFECT_IDS)
    assert {
        effect_id
        for effect_id, state in states.items()
        if state is EffectAssertionState.ESTABLISHED
    } == established
    assert {
        effect_id
        for effect_id, state in states.items()
        if state is EffectAssertionState.NOT_ESTABLISHED
    } == not_established
    if expected_classification is Classification.PARTIAL:
        assert len(report.missing_evidence) == 1
        assert report.missing_evidence[0].effect_ids == tuple(
            effect_id
            for effect_id in FIRESTORE_BUSINESS_EFFECT_IDS
            if effect_id in not_established
        )
        assert (
            report.missing_evidence[0].reason == "authoritative-effect-proof-required"
        )
    else:
        assert report.missing_evidence == ()
    assert report.evidence_decisions[0].disposition is EvidenceDisposition.ADMITTED

    limitations = " ".join(report.limitations)
    assert "PARTIAL result means a partial multi-step business operation" in limitations
    assert "no atomic transaction is represented." in limitations
    assert "local SQLite Firestore-shaped semantic target" in limitations


def test_precommit_interruption_remains_unknown(tmp_path: Path) -> None:
    database_path = tmp_path / "precommit.sqlite3"
    definition = FirestoreBusinessScenarioDefinition(
        database_path,
        invoked_at=NOW,
        target_clock=lambda: NOW,
    )
    runner = ScenarioRunner(clock=_StepClock(NOW + timedelta(seconds=1)))
    request = _request(
        0b111,
        suffix="precommit",
        fault_point=ScenarioFaultPoint.PRE_COMMIT,
    )

    result = runner.run(request, definition)
    assert result.execution_envelope is not None
    report = _report(definition, result)
    cleanup = runner.cleanup(runner.build_cleanup_request(request, result), definition)

    assert report.classification is Classification.UNKNOWN
    assert report.proof is not None
    assert {finding.state for finding in report.proof.effect_findings} == {
        EffectAssertionState.UNVERIFIED
    }
    assert report.missing_evidence[0].effect_ids == FIRESTORE_BUSINESS_EFFECT_IDS
    assert cleanup.disposition is ScenarioCleanupDisposition.ALREADY_CLEAN


def test_inaccessible_composite_read_remains_unknown(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _, definition, _, result, _ = _run(
        tmp_path,
        mask=0b111,
        suffix="inaccessible",
    )

    def denied(
        _read_target: LocalFirestoreReadTarget,
        **_coordinates: object,
    ) -> None:
        raise PermissionError("local composite read denied")

    monkeypatch.setattr(LocalFirestoreReadTarget, "read", denied)

    report = _report(definition, result)

    assert report.classification is Classification.UNKNOWN
    assert report.evidence_decisions[0].disposition is EvidenceDisposition.REJECTED
    assert report.missing_evidence[0].effect_ids == FIRESTORE_BUSINESS_EFFECT_IDS


def test_incomplete_terminal_read_fails_closed_until_all_visible(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _, definition, _, result, _ = _run(
        tmp_path,
        mask=0b011,
        suffix="eventual-visibility",
    )
    original_read = LocalFirestoreReadTarget.read
    read_count = 0

    def delayed_read(
        read_target: LocalFirestoreReadTarget,
        **coordinates: object,
    ) -> BusinessOperationReadback:
        nonlocal read_count
        readback = original_read(read_target, **coordinates)
        read_count += 1
        if read_count == 1:
            return BusinessOperationReadback(
                manifest=readback.manifest,
                documents=readback.documents[1:],
            )
        return readback

    monkeypatch.setattr(LocalFirestoreReadTarget, "read", delayed_read)

    incomplete = _report(definition, result)
    complete = _report(definition, result)

    assert incomplete.classification is Classification.UNKNOWN
    assert incomplete.evidence_decisions[0].disposition is EvidenceDisposition.REJECTED
    assert complete.classification is Classification.PARTIAL
    assert complete.evidence_decisions[0].disposition is EvidenceDisposition.ADMITTED
    assert complete.proof is not None
    assert {
        finding.effect_id
        for finding in complete.proof.effect_findings
        if finding.state is EffectAssertionState.ESTABLISHED
    } == set(FIRESTORE_BUSINESS_EFFECT_IDS[:2])


def test_cleanup_is_exact_and_does_not_change_the_completed_report(
    tmp_path: Path,
) -> None:
    runner, definition, request, result, harness = _run(
        tmp_path,
        mask=0b111,
        suffix="cleanup-success",
    )
    report = _report(definition, result)
    report_bytes = canonical_json_bytes(report)

    cleanup = runner.cleanup(runner.build_cleanup_request(request, result), definition)

    assert cleanup.disposition is ScenarioCleanupDisposition.CLEANED
    assert cleanup.removed_count == 4
    assert cleanup.remaining_count == 0
    assert canonical_json_bytes(report) == report_bytes
    readback = _readback(harness, result)
    assert readback.manifest is None
    assert readback.documents == ()


def test_cleanup_failure_preserves_a_replacement_document(
    tmp_path: Path,
) -> None:
    runner, definition, request, result, harness = _run(
        tmp_path,
        mask=0b111,
        suffix="cleanup-replacement",
    )
    report = _report(definition, result)
    envelope = result.execution_envelope
    assert envelope is not None
    coordinate = _coordinates(result)[0]
    namespace_id = envelope.target.scope.get("namespace_id")
    assert isinstance(namespace_id, str)
    replacement = harness.replace_document(
        namespace_id=namespace_id,
        operation_id=result.operation_id,
        document=BusinessDocumentWrite(
            effect_id=coordinate.effect_id,
            collection_name=coordinate.collection_name,
            document_id=coordinate.document_id,
            content=b"replacement-document-not-owned-by-the-manifest",
        ),
        correlation=envelope.context.correlation_fields,
    )

    cleanup = runner.cleanup(runner.build_cleanup_request(request, result), definition)

    assert report.classification is Classification.COMMITTED
    assert cleanup.disposition is ScenarioCleanupDisposition.FAILED
    assert cleanup.failure_code == "cleanup_verification_failed"
    readback = _readback(harness, result)
    assert readback.manifest is not None
    assert replacement in readback.documents
