"""End-to-end local Storage ambiguity and evidence behavior."""

from __future__ import annotations

import hashlib
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from reconcile.contracts import (
    SCENARIO_RUN_REQUEST_VERSION,
    AmbiguityKind,
    Classification,
    EvidenceDisposition,
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
from reconcile.scenarios.local_storage import (
    LocalStorageHarness,
    LocalStorageReadTarget,
)
from reconcile.scenarios.runner import ScenarioRunner
from reconcile.scenarios.storage import (
    STORAGE_EFFECT_ID,
    STORAGE_SCENARIO,
    StorageScenarioDefinition,
)
from tests._clocks import ConstantClock

pytestmark = pytest.mark.integration

NOW = datetime(2026, 8, 13, 19, 0, tzinfo=UTC)


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
    *,
    fault_point: ScenarioFaultPoint = ScenarioFaultPoint.POST_COMMIT,
    fault_action: ScenarioFaultAction = ScenarioFaultAction.INTERRUPT_PROCESS,
    suffix: str = "committed",
) -> ScenarioRunRequest:
    return ScenarioRunRequest(
        schema_version=SCENARIO_RUN_REQUEST_VERSION,
        scenario=STORAGE_SCENARIO,
        run_id=f"run-{suffix}",
        investigation_id=f"investigation-{suffix}",
        operation_id=f"operation-{suffix}",
        invocation_id=f"invocation-{suffix}",
        function_call_id=f"function-call-{suffix}",
        seed=39,
        fault=ScenarioFaultInstruction(
            point=fault_point,
            action=fault_action,
        ),
    )


def _committed_run(
    tmp_path: Path,
    *,
    suffix: str = "committed",
) -> tuple[
    ScenarioRunner,
    StorageScenarioDefinition,
    ScenarioRunRequest,
    ScenarioRunResult,
    LocalStorageHarness,
]:
    database_path = tmp_path / f"{suffix}.sqlite3"
    definition = StorageScenarioDefinition(
        database_path,
        invoked_at=NOW,
        target_clock=ConstantClock(NOW),
    )
    runner = ScenarioRunner(clock=_StepClock(NOW + timedelta(seconds=1)))
    request = _request(suffix=suffix)
    result = runner.run(request, definition)
    assert result.execution_envelope is not None
    return runner, definition, request, result, LocalStorageHarness(database_path)


def _coordinates(result: ScenarioRunResult) -> tuple[str, str]:
    envelope = result.execution_envelope
    assert envelope is not None
    return (
        str(envelope.target.scope["bucket_name"]),
        str(envelope.target.resource["object_name"]),
    )


def _report(definition: StorageScenarioDefinition, result: ScenarioRunResult):
    envelope = result.execution_envelope
    assert envelope is not None
    return definition.investigate(
        envelope,
        clock=_StepClock(NOW + timedelta(seconds=2)),
    )


def test_postcommit_interruption_is_committed_only_from_exact_target_readback(
    tmp_path: Path,
) -> None:
    runner, definition, request, result, _ = _committed_run(tmp_path)
    envelope = result.execution_envelope
    assert envelope is not None
    arguments = envelope.context.invocation.arguments
    effect = envelope.expected_effects[0]

    assert result.trace.caller_observation is ScenarioCallerObservation.NO_RESPONSE
    assert result.trace.worker_termination is ScenarioWorkerTermination.SIGNALED
    assert result.trace.events[-2].event is ScenarioTransportEvent.WORKER_INTERRUPTED
    assert ScenarioTransportEvent.RESPONSE_AVAILABLE not in {
        event.event for event in result.trace.events
    }
    assert envelope.ambiguity.kind is AmbiguityKind.PROCESS_INTERRUPTED
    assert envelope.target.target_kind == "storage.object"
    assert envelope.target.scope["environment"] == "local-sqlite"
    assert effect.effect_id == STORAGE_EFFECT_ID
    assert effect.predicate == {
        "content_sha256": arguments["content_sha256"],
        "size_bytes": arguments["size_bytes"],
        "correlation": arguments["correlation"],
    }

    report = _report(definition, result)

    assert report.classification is Classification.COMMITTED
    assert report.evidence_decisions[0].disposition is EvidenceDisposition.ADMITTED
    assert report.proof is not None
    assert report.proof.effect_findings[0].effect_id == STORAGE_EFFECT_ID
    assert report.proof.effect_findings[0].state.value == "ESTABLISHED"
    assert report.evidence[0].provenance.source == "local-storage-sqlite"
    assert report.evidence[0].provenance.source_record.startswith("object-generation-")

    sealed_public_inputs = canonical_json_bytes(envelope) + canonical_json_bytes(
        result.trace
    )
    assert b"receipt" not in sealed_public_inputs.lower()
    assert b'"generation":' not in canonical_json_bytes(envelope).lower()

    report_before_cleanup = canonical_json_bytes(report)
    cleanup_request = runner.build_cleanup_request(request, result)
    cleanup = runner.cleanup(cleanup_request, definition)

    assert cleanup.disposition is ScenarioCleanupDisposition.CLEANED
    assert cleanup.removed_count == 2
    assert cleanup.remaining_count == 0
    assert canonical_json_bytes(report) == report_before_cleanup


def test_precommit_interruption_never_becomes_noncommitment_claim(
    tmp_path: Path,
) -> None:
    definition = StorageScenarioDefinition(
        tmp_path / "precommit.sqlite3",
        invoked_at=NOW,
        target_clock=ConstantClock(NOW),
    )
    runner = ScenarioRunner(clock=_StepClock(NOW + timedelta(seconds=1)))
    request = _request(
        fault_point=ScenarioFaultPoint.PRE_COMMIT,
        fault_action=ScenarioFaultAction.INTERRUPT_PROCESS,
        suffix="precommit",
    )

    result = runner.run(request, definition)
    assert result.execution_envelope is not None
    report = _report(definition, result)
    cleanup = runner.cleanup(runner.build_cleanup_request(request, result), definition)

    assert report.classification is Classification.UNKNOWN
    assert report.evidence_decisions[0].disposition is not EvidenceDisposition.ADMITTED
    assert cleanup.disposition is ScenarioCleanupDisposition.ALREADY_CLEAN
    assert cleanup.remaining_count == 0


Mutation = Callable[[LocalStorageHarness, ScenarioRunResult], None]


def _wrong_receipt_bucket(
    harness: LocalStorageHarness,
    result: ScenarioRunResult,
) -> None:
    harness.harness_corrupt_receipt(
        operation_id=result.operation_id,
        bucket="wrong-bucket",
    )


def _wrong_receipt_object(
    harness: LocalStorageHarness,
    result: ScenarioRunResult,
) -> None:
    harness.harness_corrupt_receipt(
        operation_id=result.operation_id,
        name="wrong/object.json",
    )


def _wrong_generation(
    harness: LocalStorageHarness,
    result: ScenarioRunResult,
) -> None:
    harness.harness_corrupt_receipt(
        operation_id=result.operation_id,
        generation=9_999,
    )


def _wrong_receipt_digest(
    harness: LocalStorageHarness,
    result: ScenarioRunResult,
) -> None:
    harness.harness_corrupt_receipt(
        operation_id=result.operation_id,
        content_sha256="f" * 64,
    )


def _wrong_receipt_size(
    harness: LocalStorageHarness,
    result: ScenarioRunResult,
) -> None:
    harness.harness_corrupt_receipt(
        operation_id=result.operation_id,
        size=9_999,
    )


def _wrong_correlation(
    harness: LocalStorageHarness,
    result: ScenarioRunResult,
) -> None:
    harness.harness_corrupt_receipt(
        operation_id=result.operation_id,
        correlation_digest="e" * 64,
    )


def _overwrite_object(
    harness: LocalStorageHarness,
    result: ScenarioRunResult,
) -> None:
    bucket, name = _coordinates(result)
    harness.overwrite_object(
        bucket=bucket,
        name=name,
        content=b"replacement",
        correlation={"operation_id": result.operation_id},
        observed_at=NOW + timedelta(seconds=1),
    )


def _missing_metadata(
    harness: LocalStorageHarness,
    result: ScenarioRunResult,
) -> None:
    bucket, name = _coordinates(result)
    assert harness.harness_delete_object(bucket=bucket, name=name)


def _missing_receipt(
    harness: LocalStorageHarness,
    result: ScenarioRunResult,
) -> None:
    assert harness.harness_delete_receipt(operation_id=result.operation_id)


def _stale_metadata(
    harness: LocalStorageHarness,
    result: ScenarioRunResult,
) -> None:
    bucket, name = _coordinates(result)
    harness.harness_corrupt_object_metadata(
        bucket=bucket,
        name=name,
        observed_at=NOW - timedelta(minutes=5),
    )


@pytest.mark.parametrize(
    "mutation",
    (
        _wrong_receipt_bucket,
        _wrong_receipt_object,
        _wrong_generation,
        _wrong_receipt_digest,
        _wrong_receipt_size,
        _wrong_correlation,
        _overwrite_object,
        _missing_metadata,
        _missing_receipt,
        _stale_metadata,
    ),
    ids=(
        "wrong-bucket",
        "wrong-object",
        "wrong-generation",
        "wrong-digest",
        "wrong-size",
        "wrong-correlation",
        "overwritten-object",
        "missing-metadata",
        "missing-receipt",
        "stale-observation",
    ),
)
def test_negative_controls_remain_unknown(
    tmp_path: Path,
    mutation: Mutation,
) -> None:
    suffix = hashlib.sha256(mutation.__name__.encode()).hexdigest()[:12]
    _, definition, _, result, harness = _committed_run(tmp_path, suffix=suffix)
    mutation(harness, result)

    report = _report(definition, result)

    assert report.classification is Classification.UNKNOWN
    assert report.proof is not None
    assert report.proof.effect_findings[0].state.value == "UNVERIFIED"
    assert report.evidence_decisions[0].disposition is not EvidenceDisposition.ADMITTED


@pytest.mark.parametrize(
    "field_name",
    ("invocation_id", "operation_id", "run_id"),
)
def test_each_declared_correlation_field_has_a_negative_control_report(
    tmp_path: Path,
    field_name: str,
) -> None:
    _, definition, _, result, harness = _committed_run(
        tmp_path,
        suffix=f"correlation-{field_name}",
    )
    envelope = result.execution_envelope
    assert envelope is not None
    bucket, name = _coordinates(result)
    correlation = dict(envelope.context.correlation_fields)
    correlation[field_name] = "wrong-value"
    harness.harness_corrupt_object_metadata(
        bucket=bucket,
        name=name,
        correlation=correlation,
    )

    report = _report(definition, result)

    assert report.classification is Classification.UNKNOWN
    assert report.evidence_decisions[0].disposition is not EvidenceDisposition.ADMITTED


def test_inaccessible_readback_remains_unknown(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _, definition, _, result, _ = _committed_run(tmp_path, suffix="inaccessible")

    def denied(
        _read_target: LocalStorageReadTarget,
        *,
        bucket: str,
        name: str,
        operation_id: str,
    ) -> None:
        raise PermissionError(f"read denied for {bucket}/{name}/{operation_id}")

    monkeypatch.setattr(LocalStorageReadTarget, "read", denied)

    report = _report(definition, result)

    assert report.classification is Classification.UNKNOWN
    assert report.evidence_decisions[0].disposition is EvidenceDisposition.REJECTED


def test_target_records_commit_time_instead_of_constructor_time(
    tmp_path: Path,
) -> None:
    committed_at = NOW + timedelta(seconds=30)
    database_path = tmp_path / "delayed-commit.sqlite3"
    definition = StorageScenarioDefinition(
        database_path,
        invoked_at=NOW,
        target_clock=ConstantClock(committed_at),
    )
    runner = ScenarioRunner(clock=_StepClock(committed_at + timedelta(seconds=1)))
    request = _request(suffix="delayed-commit")

    result = runner.run(request, definition)
    assert result.execution_envelope is not None
    report = definition.investigate(
        result.execution_envelope,
        clock=_StepClock(committed_at + timedelta(seconds=2)),
    )

    assert report.classification is Classification.COMMITTED
    receipt = LocalStorageHarness(database_path).read_receipt(
        operation_id=result.operation_id
    )
    assert receipt is not None
    assert receipt.observed_at == committed_at


def test_cleanup_preserves_an_overwritten_generation(tmp_path: Path) -> None:
    runner, definition, request, result, harness = _committed_run(
        tmp_path,
        suffix="replacement-cleanup",
    )
    _overwrite_object(harness, result)
    bucket, name = _coordinates(result)
    replacement = harness.read_metadata(bucket=bucket, name=name)

    cleanup = runner.cleanup(runner.build_cleanup_request(request, result), definition)

    assert cleanup.disposition is ScenarioCleanupDisposition.FAILED
    assert cleanup.failure_code == "cleanup_failed"
    assert harness.read_metadata(bucket=bucket, name=name) == replacement


def test_cleanup_failure_is_reported_separately_from_classification(
    tmp_path: Path,
) -> None:
    runner, definition, request, result, harness = _committed_run(
        tmp_path,
        suffix="cleanup-failure",
    )
    report = _report(definition, result)
    harness.harness_corrupt_receipt(
        operation_id=result.operation_id,
        name="different/object.json",
    )

    cleanup = runner.cleanup(runner.build_cleanup_request(request, result), definition)

    assert report.classification is Classification.COMMITTED
    assert cleanup.disposition is ScenarioCleanupDisposition.FAILED
    assert cleanup.failure_code == "cleanup_failed"
