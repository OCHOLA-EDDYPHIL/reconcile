"""Executable lifecycle coverage for the single-use qualification protocol."""

from __future__ import annotations

import asyncio
import hashlib
import json
import subprocess
from dataclasses import replace
from datetime import UTC, datetime
from pathlib import Path

import pytest

import reconcile.qualification_protocol as qualification_protocol_module
from reconcile.adaptive import (
    AdvisoryPlannerMetadata,
    AdvisoryPlannerTurn,
    AdvisoryPlannerUsage,
    PlannerFailureKind,
    execute_adaptive_investigation,
)
from reconcile.adk_planner import (
    VertexAdcPlannerConfig,
    qualification_request_static_byte_counts,
)
from reconcile.baseline import execute_fixed_plan
from reconcile.contracts import (
    ADAPTIVE_PLANNER_INPUT_VERSION,
    ADAPTIVE_PLANNER_OUTPUT_VERSION,
    PROBE_REQUEST_VERSION,
    AdaptivePlannerInput,
    AdaptivePlannerOutput,
    AdaptivePlannerPhase,
    Classification,
    PlannerAcquisitionAdvice,
    PlannerCitationRefs,
    PlannerExplanation,
    PlannerMissingEvidenceNote,
    PlannerStopAdvice,
    ProbeRequest,
    canonical_json_bytes,
    canonical_sha256,
)
from reconcile.contracts.qualification import (
    QualificationArtifactIdentity,
    QualificationProviderSettings,
    QualificationSuiteManifest,
)
from reconcile.controller import (
    CapabilityRegistration,
    CapabilityRegistry,
    CapabilityUnavailable,
)
from reconcile.qualification_fixtures import (
    QualificationFinalFixtureAccess,
    QualificationFixtureRegistry,
    QualificationProtocolStage,
    _FinalFixtureSession,
    _issue_final_fixture_access,
)
from reconcile.qualification_protocol import (
    QUALIFICATION_ATTEMPT_START_VERSION,
    QualificationArtifactStore,
    QualificationAttemptOutcome,
    QualificationBoundStatus,
    QualificationBudgetExceeded,
    QualificationExecutionBasis,
    QualificationExecutionConsumed,
    QualificationModelUsageTotals,
    QualificationProtocolError,
    QualificationProtocolRunner,
    QualificationProviderAttemptStart,
    QualificationProviderDrift,
    QualificationProviderOperation,
    QualificationSourceState,
    QualificationV2CustodySource,
    _adaptive_normalized_run,
    _AttemptMeter,
    _empty_usage,
    _fixed_normalized_run,
    _provider_reservation,
    _reservation_exceeds_ceiling,
    build_protocol_manifest,
    build_vertex_qualification_planner,
    canonical_consumed_v2_custody,
    canonical_historical_attempt_ledger,
    canonical_prior_attempt_ledger,
    frozen_qualification_provider_settings,
    frozen_qualification_runtime_identity,
    qualification_runtime_identity,
    repository_source_state,
    source_revision_for_git_commit,
    validate_protocol_manifest,
)

pytestmark = pytest.mark.integration

NOW = datetime(2026, 8, 14, 12, 0, tzinfo=UTC)
HISTORICAL_GIT_COMMIT = "b6f17aa197b82740d04e9c54ee6baf6a12b7ade6"
HISTORICAL_SOURCE_REVISION = (
    "db97e18893f3cd6088cffe3901f05cb630480c7a32b3f09ddd72c030b138b334"
)


def _artifact_root(tmp_path: Path, name: str = "artifacts") -> Path:
    return tmp_path / name / "qualification-protocol-v3"


def _provider() -> QualificationProviderSettings:
    return frozen_qualification_provider_settings()


class _ScriptedPlanner:
    def __init__(
        self,
        provider: QualificationProviderSettings,
        *,
        failure: PlannerFailureKind | None = None,
        measured_failure: bool = False,
        failure_after_calls: int = 0,
    ) -> None:
        self._metadata = AdvisoryPlannerMetadata(
            provider_name=provider.provider_name,
            configured_model=provider.model_name,
            reported_model=None,
            adk_version=provider.adk_version,
            genai_version=provider.genai_version,
            prompt_version=provider.prompt_version,
            prompt_sha256=(
                "a18ac5bbd22570562acc6dfbc49437a82f0db6a265a4de737c1371b6ef2ca2d3"
            ),
            input_schema_version=ADAPTIVE_PLANNER_INPUT_VERSION,
            output_schema_version=ADAPTIVE_PLANNER_OUTPUT_VERSION,
        )
        self.failure = failure
        self.measured_failure = measured_failure
        self.failure_after_calls = failure_after_calls
        self.reported_model: str | None = f"{provider.model_name}-001"
        self.turn_prompt_sha256 = self._metadata.prompt_sha256
        self.calls: list[AdaptivePlannerInput] = []

    @property
    def metadata(self) -> AdvisoryPlannerMetadata:
        return self._metadata

    async def plan(self, planner_input: AdaptivePlannerInput) -> AdvisoryPlannerTurn:
        self.calls.append(planner_input)
        payload = canonical_json_bytes(planner_input)
        input_sha256 = hashlib.sha256(payload).hexdigest()
        if self.failure is not None and len(self.calls) > self.failure_after_calls:
            return AdvisoryPlannerTurn(
                output=None,
                failure=self.failure,
                metadata=self._metadata,
                input_sha256=input_sha256,
                output_sha256=None,
                usage=(
                    AdvisoryPlannerUsage(
                        prompt_tokens=100,
                        output_tokens=20,
                        total_tokens=120,
                    )
                    if self.measured_failure
                    else None
                ),
            )
        proposal = None
        if planner_input.phase is AdaptivePlannerPhase.ACQUIRE_EVIDENCE:
            remaining = tuple(
                item
                for item in planner_input.capabilities
                if item.remaining_invocations
            )
            authoritative = tuple(
                item for item in remaining if "authoritative" in item.name
            )
            selected = authoritative or remaining
            if selected:
                capability = selected[0]
                proposal = ProbeRequest(
                    schema_version=PROBE_REQUEST_VERSION,
                    capability_name=capability.name,
                    capability_version=capability.version,
                    relevant_effect_ids=tuple(
                        item.effect_id
                        for item in planner_input.envelope.expected_effects
                    ),
                    arguments={},
                    rationale="Use one bounded read-only qualification probe.",
                )
        admitted = tuple(item.evidence_id for item in planner_input.admitted_evidence)
        weak = tuple(item.evidence_id for item in planner_input.weak_evidence)
        rejected = tuple(item.evidence_id for item in planner_input.rejected_evidence)
        missing = tuple(item.effect_id for item in planner_input.missing_evidence)
        output = AdaptivePlannerOutput(
            schema_version=ADAPTIVE_PLANNER_OUTPUT_VERSION,
            probe_proposals=() if proposal is None else (proposal,),
            acquisition_advice=PlannerAcquisitionAdvice(
                summary="Use the next bounded read-only proposal."
            ),
            stop_advice=PlannerStopAdvice(
                recommend_stop=proposal is None,
                reason="Advisory stop guidance has no controller authority.",
            ),
            missing_evidence_notes=(
                ()
                if not missing
                else (
                    PlannerMissingEvidenceNote(
                        effect_ids=missing,
                        note="Authoritative evidence remains missing.",
                    ),
                )
            ),
            explanation=PlannerExplanation(
                summary="Cite every deterministic evidence category.",
                admitted_evidence="Authoritative evidence admitted."
                if admitted
                else None,
                weak_evidence="Weak evidence retained." if weak else None,
                rejected_evidence="Rejected evidence excluded." if rejected else None,
                missing_evidence="Expected effects remain missing."
                if missing
                else None,
                citations=PlannerCitationRefs(
                    admitted_evidence_ids=admitted,
                    weak_evidence_ids=weak,
                    rejected_evidence_ids=rejected,
                    missing_effect_ids=missing,
                ),
            ),
        )
        output_bytes = canonical_json_bytes(output)
        return AdvisoryPlannerTurn(
            output=output,
            failure=None,
            metadata=replace(
                self._metadata,
                reported_model=self.reported_model,
                prompt_sha256=self.turn_prompt_sha256,
            ),
            input_sha256=input_sha256,
            output_sha256=hashlib.sha256(output_bytes).hexdigest(),
            usage=AdvisoryPlannerUsage(
                prompt_tokens=100,
                output_tokens=20,
                total_tokens=120,
            ),
        )


def _source_repository(path: Path) -> str:
    path.mkdir()
    subprocess.run(("git", "init", "-q"), cwd=path, check=True)
    subprocess.run(
        ("git", "config", "user.email", "qualification@example.invalid"),
        cwd=path,
        check=True,
    )
    subprocess.run(
        ("git", "config", "user.name", "Qualification Test"),
        cwd=path,
        check=True,
    )
    (path / "source.txt").write_text("frozen\n", encoding="utf-8")
    subprocess.run(("git", "add", "source.txt"), cwd=path, check=True)
    subprocess.run(("git", "commit", "-qm", "frozen source"), cwd=path, check=True)
    git_commit = subprocess.run(
        ("git", "rev-parse", "HEAD"),
        cwd=path,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    return source_revision_for_git_commit(git_commit)


def _git_commit(path: Path) -> str:
    return subprocess.run(
        ("git", "rev-parse", "HEAD"),
        cwd=path,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()


def _manifest(
    stage: QualificationProtocolStage,
    source_revision: str = "1" * 64,
) -> QualificationSuiteManifest:
    return build_protocol_manifest(
        stage,
        source_revision=source_revision,
        registered_at=NOW,
        provider=_provider(),
    )


def _run_fixed(fixture) -> tuple[Classification, tuple[bytes, ...], str]:
    async def execute():
        state = await fixture.semantic_state_sha256()
        fixture.begin_lane("FIXED")
        result = await execute_fixed_plan(
            fixture.envelope,
            fixture.capabilities,
            fixture.rules,
            fixture.fixed_plan,
            clock=fixture.new_controller_clock(),
        )
        observations = fixture.end_lane("FIXED")
        assert await fixture.semantic_state_sha256() == state
        return (
            result.classification,
            tuple(item.canonical_json for item in observations),
            state,
        )

    return asyncio.run(execute())


def test_development_fixtures_are_real_read_only_and_match_frozen_truth(
    tmp_path: Path,
) -> None:
    manifest = _manifest(QualificationProtocolStage.DEVELOPMENT_1)
    registry = QualificationFixtureRegistry(
        QualificationProtocolStage.DEVELOPMENT_1,
        manifest.cases,
        workspace=tmp_path / "targets",
    )

    for case in manifest.cases:
        if case.expectation is None:
            continue
        fixture = registry.prepare(manifest, case, 1)
        classification, observations, _ = _run_fixed(fixture)
        fixture.cleanup()
        assert classification is case.expectation.expected_classification
        assert observations
        assert all(item.startswith(b'{"observed_at"') for item in observations)


def test_fixture_truth_and_observations_do_not_derive_from_expectation_metadata(
    tmp_path: Path,
) -> None:
    manifest = _manifest(QualificationProtocolStage.DEVELOPMENT_1)
    original_case = manifest.cases[0]
    assert original_case.expectation is not None
    changed_expectation = original_case.expectation.model_copy(
        update={
            "registration_id": "falsified-expectation-metadata",
            "metadata_sha256": "f" * 64,
        }
    )
    changed_case = original_case.model_copy(update={"expectation": changed_expectation})
    changed_manifest = manifest.model_copy(
        update={"cases": (changed_case, *manifest.cases[1:])}
    )
    original_registry = QualificationFixtureRegistry(
        QualificationProtocolStage.DEVELOPMENT_1,
        manifest.cases,
        workspace=tmp_path / "original",
    )
    changed_registry = QualificationFixtureRegistry(
        QualificationProtocolStage.DEVELOPMENT_1,
        changed_manifest.cases,
        workspace=tmp_path / "changed",
    )
    original_fixture = original_registry.prepare(manifest, original_case, 1)
    changed_fixture = changed_registry.prepare(changed_manifest, changed_case, 1)
    original_result = _run_fixed(original_fixture)
    changed_result = _run_fixed(changed_fixture)
    original_fixture.cleanup()
    changed_fixture.cleanup()

    assert original_result == changed_result

    wrong_expectation = changed_expectation.model_copy(
        update={"expected_classification": Classification.UNKNOWN}
    )
    wrong_case = original_case.model_copy(update={"expectation": wrong_expectation})
    with pytest.raises(ValueError, match="truth contradicts"):
        QualificationFixtureRegistry(
            QualificationProtocolStage.DEVELOPMENT_1,
            (wrong_case, *manifest.cases[1:]),
            workspace=tmp_path / "rejected",
        )


def test_development_cohorts_have_disjoint_real_state_and_catalogs(
    tmp_path: Path,
) -> None:
    first_manifest = _manifest(QualificationProtocolStage.DEVELOPMENT_1)
    second_manifest = _manifest(QualificationProtocolStage.DEVELOPMENT_2)
    first_registry = QualificationFixtureRegistry(
        QualificationProtocolStage.DEVELOPMENT_1,
        first_manifest.cases,
        workspace=tmp_path / "development-one",
    )
    second_registry = QualificationFixtureRegistry(
        QualificationProtocolStage.DEVELOPMENT_2,
        second_manifest.cases,
        workspace=tmp_path / "development-two",
    )

    for first_case, second_case in zip(
        first_manifest.cases, second_manifest.cases, strict=True
    ):
        first = first_registry.prepare(first_manifest, first_case, 1)
        second = second_registry.prepare(second_manifest, second_case, 1)
        first_state = asyncio.run(first.semantic_state_sha256())
        second_state = asyncio.run(second.semantic_state_sha256())
        assert first_state != second_state
        assert canonical_sha256(first.envelope) != canonical_sha256(second.envelope)
        assert first.catalog_sha256 != second.catalog_sha256
        first.cleanup()
        second.cleanup()

    assert not (tmp_path / "development-one").exists()
    assert not (tmp_path / "development-two").exists()


def test_fixture_controller_clock_prevents_stale_evidence_relabelling(
    tmp_path: Path,
) -> None:
    manifest = _manifest(QualificationProtocolStage.DEVELOPMENT_1)
    registry = QualificationFixtureRegistry(
        QualificationProtocolStage.DEVELOPMENT_1,
        manifest.cases,
        workspace=tmp_path / "stale",
    )
    case = manifest.cases[0]
    fixture = registry.prepare(manifest, case, 1)

    async def stale_result() -> Classification:
        fixture.begin_lane("FIXED")
        result = await execute_fixed_plan(
            fixture.envelope,
            fixture.capabilities,
            fixture.rules,
            fixture.fixed_plan,
        )
        fixture.end_lane("FIXED")
        return result.classification

    assert asyncio.run(stale_result()) is Classification.UNKNOWN
    fixture.cleanup()


def test_final_fixture_access_is_rejected_before_stage_start(tmp_path: Path) -> None:
    manifest = _manifest(QualificationProtocolStage.FINAL_HOLDOUT)
    workspace = tmp_path / "untouched-final"
    with pytest.raises(RuntimeError, match="created only by its store"):
        QualificationFixtureRegistry(
            QualificationProtocolStage.FINAL_HOLDOUT,
            manifest.cases,
            workspace=workspace,
        )
    assert not workspace.exists()


def test_repository_source_state_binds_raw_git_identity_to_sha256(
    tmp_path: Path,
) -> None:
    repository = tmp_path / "source"
    expected_revision = _source_repository(repository)
    state = repository_source_state(repository)

    assert state.clean
    assert state.git_commit == _git_commit(repository)
    assert len(state.git_commit) == 40
    assert state.source_revision == expected_revision
    assert state.source_revision == source_revision_for_git_commit(state.git_commit)


def test_two_development_cycles_are_single_use_and_leave_final_untouched(
    tmp_path: Path,
) -> None:
    repository = tmp_path / "source"
    source_revision = _source_repository(repository)
    artifact_root = _artifact_root(tmp_path)
    runner = QualificationProtocolRunner(artifact_root, repository=repository)
    provider = _provider()
    development_one = build_protocol_manifest(
        QualificationProtocolStage.DEVELOPMENT_1,
        source_revision=source_revision,
        registered_at=NOW,
        provider=provider,
    )
    first_planner = _ScriptedPlanner(provider)
    first = asyncio.run(
        runner.run(
            QualificationProtocolStage.DEVELOPMENT_1,
            development_one,
            first_planner,
            execution_basis=QualificationExecutionBasis.DETERMINISTIC_TEST,
        )
    )
    assert first.completion.protocol_valid
    assert not first.completion.provider_evidence_qualifying
    assert not first.completion.successful
    assert len(first.result_set.results) == 8
    assert first.protocol_summary.prior_attempt_usage.model_call_count == 4
    assert (
        first.protocol_summary.prior_attempt_usage.model_cost_nano_units == 51_859_500
    )
    assert all(
        not item.qualification_evidence_qualifying
        for item in canonical_historical_attempt_ledger().attempts
    )
    assert all(
        item.source_revision != development_one.source_revision
        for item in canonical_historical_attempt_ledger().attempts
    )
    assert first.protocol_summary.ceiling_usage.model_call_count == (
        first.attempt_ledger.totals.model_call_count + 4
    )
    assert first.protocol_summary.prior_attempt_usage == (
        canonical_prior_attempt_ledger().totals
    )
    assert first.completion.consumed_v2_custody is not None
    assert tuple(item.operation for item in first.attempt_ledger.attempts[:2]) == (
        QualificationProviderOperation.COUNT_TOKENS,
        QualificationProviderOperation.GENERATE,
    )
    assert first.attempt_ledger.attempts[0].outcome is (
        QualificationAttemptOutcome.TOKEN_COUNTED
    )
    assert first.attempt_ledger.attempts[1].execution_id == (
        "provider-model-revision-preflight"
    )
    assert first.attempt_ledger.attempts[1].outcome is (
        QualificationAttemptOutcome.MEASURED
    )
    retained = {
        (item.artifact_id, item.sha256) for item in first.completion.retained_artifacts
    }
    assert all(
        (item.artifact_id, item.sha256) in retained
        for item in (
            *first.attempt_ledger.attempt_starts,
            *first.attempt_ledger.attempt_finishes,
        )
    )
    binding_payload = json.loads(
        (
            artifact_root
            / QualificationProtocolStage.DEVELOPMENT_1.value
            / "provider-model-binding.json"
        ).read_bytes()
    )
    assert binding_payload["reported_model_revision"] == "gemini-3.5-flash-001"
    assert binding_payload["preflight_generation_attempt_id"] == (
        first.attempt_ledger.attempts[1].attempt_id
    )
    assert first_planner.calls
    assert all(
        item.request_byte_count
        <= frozen_qualification_runtime_identity().maximum_input_tokens_per_call
        for item in first.attempt_ledger.attempts
    )
    assert all(
        item.reserved_input_tokens == 12_000
        and item.reserved_output_tokens == 1_024
        and item.reserved_cost_nano_units == 27_216_000
        for item in first.attempt_ledger.attempts
        if item.operation is QualificationProviderOperation.GENERATE
    )
    assert (
        sum(
            item.outcome is QualificationAttemptOutcome.CONTROL_FAILURE
            for item in first.attempt_ledger.attempts
        )
        == 1
    )
    assert first.attempt_ledger.totals.reserved_usage_count == 1
    assert first.attempt_ledger.totals.unexpected_missing_usage_count == 0
    adaptive_metrics = first.protocol_summary.adaptive_metrics
    assert adaptive_metrics.planned_probe_count == (
        adaptive_metrics.selected_proposal_count
    )
    assert adaptive_metrics.acquisition_proposal_count == sum(
        (
            adaptive_metrics.selected_proposal_count,
            adaptive_metrics.deferred_proposal_count,
            adaptive_metrics.unsupported_proposal_count,
            adaptive_metrics.invalid_proposal_count,
            adaptive_metrics.duplicate_proposal_count,
            adaptive_metrics.unavailable_proposal_count,
            adaptive_metrics.budget_exceeded_proposal_count,
        )
    )

    with pytest.raises(QualificationExecutionConsumed):
        asyncio.run(
            runner.run(
                QualificationProtocolStage.DEVELOPMENT_1,
                development_one,
                _ScriptedPlanner(provider),
                execution_basis=QualificationExecutionBasis.DETERMINISTIC_TEST,
            )
        )

    development_two = build_protocol_manifest(
        QualificationProtocolStage.DEVELOPMENT_2,
        source_revision=source_revision,
        registered_at=NOW,
        provider=provider,
    )
    second = asyncio.run(
        runner.run(
            QualificationProtocolStage.DEVELOPMENT_2,
            development_two,
            _ScriptedPlanner(provider),
            execution_basis=QualificationExecutionBasis.DETERMINISTIC_TEST,
        )
    )
    assert second.completion.protocol_valid
    assert not second.completion.successful
    assert len(second.result_set.results) == 8
    assert second.protocol_summary.prior_attempt_usage == (
        first.protocol_summary.ceiling_usage
    )
    assert second.protocol_summary.ceiling_usage.model_call_count == (
        first.protocol_summary.ceiling_usage.model_call_count
        + second.attempt_ledger.totals.model_call_count
    )

    final_manifest = build_protocol_manifest(
        QualificationProtocolStage.FINAL_HOLDOUT,
        source_revision=source_revision,
        registered_at=NOW,
        provider=provider,
    )
    assert final_manifest.repetition_count == 5
    assert tuple(item.value for item in final_manifest.lane_orders) == (
        "FIXED_FIRST",
        "ADAPTIVE_FIRST",
        "FIXED_FIRST",
        "ADAPTIVE_FIRST",
        "FIXED_FIRST",
    )
    assert final_manifest.thresholds.minimum_fallback_case_successful_repetitions == 4
    planner_configuration_sha256 = runner._validate_planner(
        final_manifest,
        _ScriptedPlanner(provider),
        QualificationExecutionBasis.DETERMINISTIC_TEST,
    )
    with pytest.raises(QualificationProtocolError, match="did not pass"):
        runner._validate_prerequisites(
            QualificationProtocolStage.FINAL_HOLDOUT,
            final_manifest,
            QualificationExecutionBasis.LIVE_PROVIDER,
            canonical_sha256(planner_configuration_sha256),
            canonical_consumed_v2_custody(),
        )
    assert not (artifact_root / "final-holdout").exists()
    assert not (artifact_root / ".runtime-final-holdout").exists()

    receipts = sorted((artifact_root / "development-1").glob("*lane-1-receipt.json"))
    assert receipts
    first_order = json.loads(
        (
            artifact_root
            / "development-1"
            / ("execution-d101-storage-authoritative-fast-path-r1-lane-1-receipt.json")
        ).read_bytes()
    )
    second_order = json.loads(
        (
            artifact_root
            / "development-2"
            / ("execution-d201-storage-authoritative-fast-path-r1-lane-1-receipt.json")
        ).read_bytes()
    )
    assert first_order["strategy_kind"] == "FIXED"
    assert second_order["strategy_kind"] == "ADAPTIVE"
    assert not (artifact_root / ".runtime-development-1").exists()
    assert not (artifact_root / ".runtime-development-2").exists()
    for path in (artifact_root / "development-1").glob("*.json"):
        assert path.stat().st_mode & 0o777 == 0o400

    live_claim = second.completion.model_copy(
        update={
            "execution_basis": QualificationExecutionBasis.LIVE_PROVIDER,
            "provider_evidence_qualifying": True,
            "successful": second.completion.protocol_valid,
        }
    )
    completion_path = artifact_root / "development-2" / "execution-completion.json"
    completion_path.chmod(0o600)
    completion_path.write_bytes(canonical_json_bytes(live_claim))
    completion_path.chmod(0o400)
    with pytest.raises(QualificationProtocolError, match="requires consumed-v2"):
        QualificationArtifactStore(artifact_root).read_completion(
            QualificationProtocolStage.DEVELOPMENT_2
        )


@pytest.mark.parametrize("measured", (False, True))
def test_provider_failure_is_consumed_and_never_relabelled(
    tmp_path: Path,
    measured: bool,
) -> None:
    repository = tmp_path / "source"
    source_revision = _source_repository(repository)
    artifact_root = _artifact_root(tmp_path)
    manifest = build_protocol_manifest(
        QualificationProtocolStage.DEVELOPMENT_1,
        source_revision=source_revision,
        registered_at=NOW,
        provider=_provider(),
    )
    planner = _ScriptedPlanner(
        manifest.provider,
        failure=PlannerFailureKind.UNAVAILABLE,
        measured_failure=measured,
        failure_after_calls=1,
    )
    runner = QualificationProtocolRunner(artifact_root, repository=repository)
    outcome = asyncio.run(
        runner.run(
            QualificationProtocolStage.DEVELOPMENT_1,
            manifest,
            planner,
            execution_basis=QualificationExecutionBasis.DETERMINISTIC_TEST,
        )
    )

    assert not outcome.completion.successful
    assert len(outcome.result_set.results) == 1
    assert outcome.result_set.results[0].status.value == "INVALID"
    case_failures = tuple(
        item
        for item in outcome.attempt_ledger.attempts
        if item.execution_id != "provider-model-revision-preflight"
        and item.operation is QualificationProviderOperation.GENERATE
    )
    assert case_failures[0].outcome is QualificationAttemptOutcome.PROVIDER_FAILURE
    assert (
        case_failures[0].provider_failure_kind == PlannerFailureKind.UNAVAILABLE.value
    )
    assert case_failures[0].input_bound_status is (
        QualificationBoundStatus.WITHIN
        if measured
        else QualificationBoundStatus.UNKNOWN
    )
    assert case_failures[0].output_bound_status is (
        QualificationBoundStatus.WITHIN
        if measured
        else QualificationBoundStatus.UNKNOWN
    )
    assert outcome.protocol_summary.usage_incomplete is (not measured)
    with pytest.raises(QualificationExecutionConsumed):
        asyncio.run(
            runner.run(
                QualificationProtocolStage.DEVELOPMENT_1,
                manifest,
                _ScriptedPlanner(manifest.provider),
                execution_basis=QualificationExecutionBasis.DETERMINISTIC_TEST,
            )
        )


class _PostPreflightDriftPlanner(_ScriptedPlanner):
    def __init__(
        self,
        provider: QualificationProviderSettings,
        drift: str,
    ) -> None:
        super().__init__(provider)
        self.drift = drift

    async def plan(self, planner_input: AdaptivePlannerInput) -> AdvisoryPlannerTurn:
        turn = await super().plan(planner_input)
        if len(self.calls) == 1:
            return turn
        metadata = turn.metadata
        if self.drift == "reported_model":
            metadata = replace(
                metadata,
                reported_model=f"{metadata.configured_model}-002",
            )
        else:
            metadata = replace(metadata, prompt_sha256="b" * 64)
        return AdvisoryPlannerTurn(
            output=turn.output,
            failure=turn.failure,
            metadata=metadata,
            input_sha256=turn.input_sha256,
            output_sha256=turn.output_sha256,
            usage=turn.usage,
        )


@pytest.mark.parametrize("drift", ("reported_model", "prompt_sha256"))
def test_provider_identity_drift_is_retained_and_invalid(
    tmp_path: Path,
    drift: str,
) -> None:
    repository = tmp_path / "source"
    source_revision = _source_repository(repository)
    manifest = build_protocol_manifest(
        QualificationProtocolStage.DEVELOPMENT_1,
        source_revision=source_revision,
        registered_at=NOW,
        provider=_provider(),
    )
    planner = _PostPreflightDriftPlanner(manifest.provider, drift)
    runner = QualificationProtocolRunner(
        _artifact_root(tmp_path), repository=repository
    )

    outcome = asyncio.run(
        runner.run(
            QualificationProtocolStage.DEVELOPMENT_1,
            manifest,
            planner,
            execution_basis=QualificationExecutionBasis.DETERMINISTIC_TEST,
        )
    )

    assert not outcome.completion.protocol_valid
    assert any(
        item.outcome is QualificationAttemptOutcome.PROVIDER_DRIFT
        for item in outcome.attempt_ledger.attempts
    )
    assert outcome.result_set.results[0].status.value == "INVALID"


@pytest.mark.parametrize(
    "reported_model",
    ("gemini-3.5-flash", "gemini-3.5-flash-latest", "UNKNOWN", None),
)
def test_model_revision_preflight_rejects_alias_default_or_missing_identity(
    tmp_path: Path,
    reported_model: str | None,
) -> None:
    repository = tmp_path / "source"
    source_revision = _source_repository(repository)
    manifest = build_protocol_manifest(
        QualificationProtocolStage.DEVELOPMENT_1,
        source_revision=source_revision,
        registered_at=NOW,
        provider=_provider(),
    )
    planner = _ScriptedPlanner(manifest.provider)
    planner.reported_model = reported_model
    artifact_root = _artifact_root(tmp_path)
    runner = QualificationProtocolRunner(artifact_root, repository=repository)

    with pytest.raises(QualificationProviderDrift, match="preflight"):
        asyncio.run(
            runner.run(
                QualificationProtocolStage.DEVELOPMENT_1,
                manifest,
                planner,
                execution_basis=QualificationExecutionBasis.DETERMINISTIC_TEST,
            )
        )
    assert not (
        artifact_root
        / QualificationProtocolStage.DEVELOPMENT_1.value
        / "execution-start.json"
    ).exists()
    assert not (artifact_root / ".runtime-development-1").exists()


class _CancelledPlanner(_ScriptedPlanner):
    async def plan(self, planner_input: AdaptivePlannerInput) -> AdvisoryPlannerTurn:
        del planner_input
        raise asyncio.CancelledError


class _SourceDriftPlanner(_ScriptedPlanner):
    def __init__(self, provider: QualificationProviderSettings, source: Path) -> None:
        super().__init__(provider)
        self.source = source

    async def plan(self, planner_input: AdaptivePlannerInput) -> AdvisoryPlannerTurn:
        self.source.write_text("drifted\n", encoding="utf-8")
        return await super().plan(planner_input)


@pytest.mark.parametrize("interruption", ("cancel", "source-drift"))
def test_interruption_consumes_stage_and_purges_runtime(
    tmp_path: Path,
    interruption: str,
) -> None:
    repository = tmp_path / "source"
    source_revision = _source_repository(repository)
    artifact_root = _artifact_root(tmp_path)
    manifest = build_protocol_manifest(
        QualificationProtocolStage.DEVELOPMENT_1,
        source_revision=source_revision,
        registered_at=NOW,
        provider=_provider(),
    )
    planner: _ScriptedPlanner = (
        _CancelledPlanner(manifest.provider)
        if interruption == "cancel"
        else _SourceDriftPlanner(manifest.provider, repository / "source.txt")
    )
    runner = QualificationProtocolRunner(artifact_root, repository=repository)

    expected = (
        asyncio.CancelledError
        if interruption == "cancel"
        else QualificationProtocolError
    )
    with pytest.raises(expected):
        asyncio.run(
            runner.run(
                QualificationProtocolStage.DEVELOPMENT_1,
                manifest,
                planner,
                execution_basis=QualificationExecutionBasis.DETERMINISTIC_TEST,
            )
        )
    if interruption == "source-drift":
        (repository / "source.txt").write_text("frozen\n", encoding="utf-8")
    assert not (artifact_root / ".runtime-development-1").exists()
    with pytest.raises(QualificationExecutionConsumed):
        asyncio.run(
            runner.run(
                QualificationProtocolStage.DEVELOPMENT_1,
                manifest,
                _ScriptedPlanner(manifest.provider),
                execution_basis=QualificationExecutionBasis.DETERMINISTIC_TEST,
            )
        )


def test_manifest_freeze_and_planner_identity_fail_closed(tmp_path: Path) -> None:
    manifest = _manifest(QualificationProtocolStage.DEVELOPMENT_1)
    changed = manifest.model_copy(update={"controller_version": "changed"})
    with pytest.raises(QualificationProtocolError, match="not frozen"):
        validate_protocol_manifest(QualificationProtocolStage.DEVELOPMENT_1, changed)

    wrong_provider = manifest.provider.model_copy(update={"model_name": "other-model"})
    wrong_planner = _ScriptedPlanner(wrong_provider)
    repository = tmp_path / "source"
    source_revision = _source_repository(repository)
    bound = manifest.model_copy(update={"source_revision": source_revision})
    runner = QualificationProtocolRunner(
        _artifact_root(tmp_path), repository=repository
    )
    with pytest.raises(QualificationProviderDrift):
        asyncio.run(
            runner.run(
                QualificationProtocolStage.DEVELOPMENT_1,
                bound,
                wrong_planner,
                execution_basis=QualificationExecutionBasis.DETERMINISTIC_TEST,
            )
        )
    assert not (_artifact_root(tmp_path) / "development-1").exists()

    live_spoof_runner = QualificationProtocolRunner(
        _artifact_root(tmp_path, "live-spoof-artifacts"), repository=repository
    )
    with pytest.raises(QualificationProtocolError, match="custody source"):
        asyncio.run(
            live_spoof_runner.run(
                QualificationProtocolStage.DEVELOPMENT_1,
                bound,
                _ScriptedPlanner(bound.provider),
            )
        )
    assert not (
        live_spoof_runner.store.root / QualificationProtocolStage.DEVELOPMENT_1.value
    ).exists()
    with pytest.raises(QualificationProviderDrift, match="sealed Vertex"):
        live_spoof_runner._validate_planner(
            bound,
            _ScriptedPlanner(bound.provider),
            QualificationExecutionBasis.LIVE_PROVIDER,
        )
    assert not (tmp_path / "live-spoof-artifacts" / "development-1").exists()


def test_v3_protocol_identities_change_only_protocol_custody() -> None:
    manifests = {stage: _manifest(stage) for stage in QualificationProtocolStage}
    assert {stage: manifest.suite_id for stage, manifest in manifests.items()} == {
        QualificationProtocolStage.DEVELOPMENT_1: "adaptive-development-one-v3",
        QualificationProtocolStage.DEVELOPMENT_2: "adaptive-development-two-v3",
        QualificationProtocolStage.FINAL_HOLDOUT: "adaptive-fixed-qualification-v3",
    }
    assert all(
        manifest.controller_version == "qualification-controller-v3"
        for manifest in manifests.values()
    )
    protocol_versions = (
        qualification_protocol_module.QUALIFICATION_EXECUTION_START_VERSION,
        qualification_protocol_module.QUALIFICATION_RUNTIME_IDENTITY_VERSION,
        qualification_protocol_module.QUALIFICATION_MODEL_BINDING_VERSION,
        qualification_protocol_module.QUALIFICATION_OBSERVATION_BUNDLE_VERSION,
        qualification_protocol_module.QUALIFICATION_NORMALIZED_RUN_VERSION,
        qualification_protocol_module.QUALIFICATION_LANE_RECEIPT_VERSION,
        qualification_protocol_module.QUALIFICATION_FAILURE_RECORD_VERSION,
        qualification_protocol_module.QUALIFICATION_PARTIAL_PUBLICATION_VERSION,
        qualification_protocol_module.QUALIFICATION_ATTEMPT_START_VERSION,
        qualification_protocol_module.QUALIFICATION_ATTEMPT_VERSION,
        qualification_protocol_module.QUALIFICATION_ATTEMPT_LEDGER_VERSION,
        qualification_protocol_module.QUALIFICATION_COMBINED_PRIOR_ATTEMPT_LEDGER_VERSION,
        qualification_protocol_module.QUALIFICATION_CASE_EXECUTION_VERSION,
        qualification_protocol_module.QUALIFICATION_PROTOCOL_SUMMARY_VERSION,
        qualification_protocol_module.QUALIFICATION_EXECUTION_COMPLETION_VERSION,
    )
    assert all(version.endswith("/v3") for version in protocol_versions)
    assert (
        qualification_protocol_module.QUALIFICATION_PRIOR_ATTEMPT_LEDGER_VERSION
        == "reconcile/qualification-prior-attempt-ledger/v2"
    )
    assert (
        qualification_protocol_module.QUALIFICATION_HISTORICAL_ATTEMPT_LEDGER_VERSION
        == "reconcile/qualification-prior-attempt-ledger/v2"
    )
    historical = canonical_historical_attempt_ledger()
    assert qualification_protocol_module.canonical_sha256(historical) == (
        "eb4d3d2be8f0cc89e3bb2b09b264c75d4785b78e90e42a3be350a30f1092026d"
    )
    assert (
        qualification_protocol_module.QualificationPriorAttemptLedger.model_validate_json(
            canonical_json_bytes(historical)
        )
        == historical
    )


def test_artifacts_are_atomic_immutable_and_symlink_safe(tmp_path: Path) -> None:
    store = QualificationArtifactStore(_artifact_root(tmp_path))
    store.begin(QualificationProtocolStage.DEVELOPMENT_1)
    git_commit = "1" * 40
    payload = QualificationSourceState(
        source_revision=source_revision_for_git_commit(git_commit),
        git_commit=git_commit,
        clean=True,
    )
    identity = store.publish("source-state", payload)
    path = store.stage_path / "source-state.json"
    assert hashlib.sha256(path.read_bytes()).hexdigest() == identity.sha256
    assert path.stat().st_mode & 0o777 == 0o400
    with pytest.raises(QualificationExecutionConsumed):
        store.publish("source-state", payload)
    with pytest.raises(ValueError, match="secret-bearing"):
        store.publish_bytes("credential", b'{"api_key":"not-persisted"}')
    assert not (store.stage_path / "credential.json").exists()

    real = tmp_path / "real"
    real.mkdir()
    symlink = tmp_path / "linked"
    symlink.symlink_to(real, target_is_directory=True)
    with pytest.raises(QualificationProtocolError, match="symlink"):
        QualificationArtifactStore(symlink / "qualification-protocol-v3")


def test_v3_artifact_namespace_cannot_overlap_v2_custody(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repository = tmp_path / "source"
    _source_repository(repository)
    custody_stage = tmp_path / "legacy-stage"
    custody_stage.mkdir()
    custody_alias = tmp_path / "legacy-stage-alias"
    custody_alias.symlink_to(custody_stage, target_is_directory=True)
    launcher = tmp_path / "legacy-launcher.py"
    launcher.write_text("raise SystemExit(0)\n")
    monkeypatch.setattr(
        qualification_protocol_module,
        "load_consumed_v2_custody",
        lambda source: canonical_consumed_v2_custody(),
    )
    source = QualificationV2CustodySource(
        stage_directory=custody_alias,
        launcher_file=launcher,
    )
    artifact_root = custody_stage / "qualification-protocol-v3"
    with pytest.raises(QualificationProtocolError, match="must not overlap"):
        QualificationProtocolRunner(
            artifact_root,
            repository=repository,
            v2_custody_source=source,
        )
    assert not artifact_root.exists()

    other_custody_stage = tmp_path / "other-legacy-stage"
    other_custody_stage.mkdir()
    launcher_overlap_root = (
        tmp_path / "launcher-artifacts" / "qualification-protocol-v3"
    )
    launcher_overlap_root.mkdir(parents=True, mode=0o750)
    launcher_overlap_root.chmod(0o750)
    launcher_inside_root = launcher_overlap_root / "legacy-launcher.py"
    launcher_inside_root.write_text("raise SystemExit(0)\n")
    launcher_source = QualificationV2CustodySource(
        stage_directory=other_custody_stage,
        launcher_file=launcher_inside_root,
    )
    with pytest.raises(QualificationProtocolError, match="must not overlap"):
        QualificationProtocolRunner(
            launcher_overlap_root,
            repository=repository,
            v2_custody_source=launcher_source,
        )
    assert launcher_inside_root.read_text() == "raise SystemExit(0)\n"
    assert launcher_overlap_root.stat().st_mode & 0o777 == 0o750

    repository_alias = tmp_path / "source-alias"
    repository_alias.symlink_to(repository, target_is_directory=True)
    repository_artifact_root = repository / "qualification-protocol-v3"
    with pytest.raises(QualificationProtocolError, match="outside the source"):
        QualificationProtocolRunner(
            repository_artifact_root,
            repository=repository_alias,
        )
    assert not repository_artifact_root.exists()


@pytest.mark.parametrize("failure", ("temporary-unlink", "directory-fsync"))
def test_post_link_cleanup_or_durability_failure_is_never_resolved(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    failure: str,
) -> None:
    store = QualificationArtifactStore(_artifact_root(tmp_path, failure))
    store.begin(QualificationProtocolStage.DEVELOPMENT_1)
    payload = QualificationSourceState(
        source_revision=source_revision_for_git_commit("1" * 40),
        git_commit="1" * 40,
        clean=True,
    )
    if failure == "temporary-unlink":
        original_unlink = qualification_protocol_module.os.unlink

        def fail_temporary_unlink(path, *args, **kwargs):
            if str(path).endswith(".tmp"):
                raise OSError("injected temporary unlink failure")
            return original_unlink(path, *args, **kwargs)

        monkeypatch.setattr(
            qualification_protocol_module.os,
            "unlink",
            fail_temporary_unlink,
        )
    else:
        original_fsync = qualification_protocol_module.os.fsync

        def fail_directory_fsync(descriptor: int) -> None:
            if qualification_protocol_module.stat.S_ISDIR(
                qualification_protocol_module.os.fstat(descriptor).st_mode
            ):
                raise OSError("injected directory fsync failure")
            original_fsync(descriptor)

        monkeypatch.setattr(
            qualification_protocol_module.os,
            "fsync",
            fail_directory_fsync,
        )

    with pytest.raises(OSError):
        store.publish("post-link-artifact", payload)
    failed_path = store.stage_path / "post-link-artifact.json"
    assert not failed_path.exists() or failed_path.stat().st_mode & 0o777 != 0o400
    with pytest.raises(QualificationProtocolError, match="unresolved publication"):
        store.resolve_committed("post-link-artifact", payload)
    with pytest.raises(QualificationProtocolError, match="unresolved publication"):
        store.publish("must-not-complete", payload)
    assert not (store.stage_path / "execution-completion.json").exists()
    fresh = QualificationArtifactStore(store.root)
    with pytest.raises(QualificationProtocolError):
        fresh.read_completion(QualificationProtocolStage.DEVELOPMENT_1)


def test_one_shot_completion_durability_failure_poison_is_cross_process_visible(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = QualificationArtifactStore(_artifact_root(tmp_path, "one-shot-completion"))
    store.begin(QualificationProtocolStage.DEVELOPMENT_1)
    payload = QualificationSourceState(
        source_revision=source_revision_for_git_commit("1" * 40),
        git_commit="1" * 40,
        clean=True,
    )
    original_fsync = qualification_protocol_module.os.fsync
    failed = False

    def fail_one_directory_fsync(descriptor: int) -> None:
        nonlocal failed
        if not failed and qualification_protocol_module.stat.S_ISDIR(
            qualification_protocol_module.os.fstat(descriptor).st_mode
        ):
            failed = True
            raise OSError("injected one-shot directory fsync failure")
        original_fsync(descriptor)

    monkeypatch.setattr(
        qualification_protocol_module.os,
        "fsync",
        fail_one_directory_fsync,
    )
    with pytest.raises(OSError, match="one-shot"):
        store.publish("execution-completion", payload)
    assert failed
    with pytest.raises(QualificationProtocolError, match="unresolved publication"):
        store.resolve_committed("execution-completion", payload)
    with pytest.raises(QualificationProtocolError, match="unresolved publication"):
        store.publish("execution-completion", payload)

    fresh = QualificationArtifactStore(store.root)
    with pytest.raises(QualificationProtocolError):
        fresh.read_completion(QualificationProtocolStage.DEVELOPMENT_1)


def test_only_ambiguous_link_call_can_resolve_an_exact_commit(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = QualificationArtifactStore(_artifact_root(tmp_path, "ambiguous-link"))
    store.begin(QualificationProtocolStage.DEVELOPMENT_1)
    payload = QualificationSourceState(
        source_revision=source_revision_for_git_commit("1" * 40),
        git_commit="1" * 40,
        clean=True,
    )
    original_link = qualification_protocol_module.os.link
    raised = False

    def link_then_raise(*args, **kwargs):
        nonlocal raised
        original_link(*args, **kwargs)
        if not raised:
            raised = True
            raise OSError("injected ambiguous link return")

    monkeypatch.setattr(qualification_protocol_module.os, "link", link_then_raise)
    identity = store.publish("ambiguous-artifact", payload)
    assert raised
    assert identity == store.resolve_committed("ambiguous-artifact", payload)
    with pytest.raises(QualificationExecutionConsumed):
        store.publish("ambiguous-artifact", payload)


def test_historical_and_consumed_v2_custody_are_canonical_and_add_once() -> None:
    ledger = canonical_historical_attempt_ledger()

    assert tuple(item.attempt_id for item in ledger.attempts) == (
        "call_StJWb2dkWSLLVpHNOEaXeywn",
        "call_0q88mBIC82Av6mw2a8PlMEIb",
        "call_dlT8NpkWkVNx8XJDgrlyHGAo",
    )
    assert all(
        item.source_revision == HISTORICAL_SOURCE_REVISION for item in ledger.attempts
    )
    assert all(item.git_commit == HISTORICAL_GIT_COMMIT for item in ledger.attempts)
    assert tuple(item.outcome for item in ledger.attempts) == (
        QualificationAttemptOutcome.PROVIDER_FAILURE,
        QualificationAttemptOutcome.USAGE_UNAVAILABLE,
        QualificationAttemptOutcome.MEASURED,
    )
    assert ledger.attempts[0].failure_category == PlannerFailureKind.UNAVAILABLE.value
    assert all(item.reported_model is None for item in ledger.attempts)
    assert tuple(item.accounted_cost_nano_units for item in ledger.attempts) == (
        26_791_500,
        12_477_000,
        774_000,
    )
    assert ledger.totals.model_cost_nano_units == 40_042_500
    assert canonical_sha256(ledger) == (
        "eb4d3d2be8f0cc89e3bb2b09b264c75d4785b78e90e42a3be350a30f1092026d"
    )
    combined = canonical_prior_attempt_ledger()
    assert combined.historical_attempt_ledger == ledger
    assert combined.historical_attempt_ledger_sha256 == canonical_sha256(ledger)
    assert combined.totals.model_call_count == 4
    assert combined.totals.count_tokens_call_count == 1
    assert combined.totals.provider_request_count == 5
    assert combined.totals.input_token_count == 21_679
    assert combined.totals.output_token_count == 2_149
    assert combined.totals.model_cost_nano_units == 51_859_500
    assert combined.totals.reserved_usage_count == 3
    assert combined.totals.unexpected_missing_usage_count == 0


def test_runtime_identity_freezes_project_provider_versions_and_pricing() -> None:
    provider = _provider()
    config = VertexAdcPlannerConfig(
        project="reconcile-dev-260813-14fa6d",
        location="global",
        model="gemini-3.5-flash",
        timeout_seconds=30,
        max_output_tokens=1_024,
        prompt_version="adaptive-planner-v3",
    )
    planner = build_vertex_qualification_planner(provider, config)
    try:
        identity = qualification_runtime_identity(planner)
        assert identity == frozen_qualification_runtime_identity()
        assert canonical_sha256(identity) == (
            "ebcccd85ec30ce87fa88d478715865d5962392719b5f10a045374db9bb4a6a34"
        )
        assert identity.provider_project == "reconcile-dev-260813-14fa6d"
        assert identity.configured_model == "gemini-3.5-flash"
        assert identity.model_revision == "UNKNOWN"
        assert identity.input_cost_nano_units_per_token == 1_500
        assert identity.output_cost_nano_units_per_token == 9_000
        assert identity.input_schema_version == ADAPTIVE_PLANNER_INPUT_VERSION
        assert identity.output_schema_version == ADAPTIVE_PLANNER_OUTPUT_VERSION
        planner._model.client_kwargs["project"] = "mutated-project"
        with pytest.raises(QualificationProviderDrift, match="configuration drifted"):
            qualification_runtime_identity(planner)
        planner._model.client_kwargs["project"] = config.project
    finally:
        asyncio.run(planner.aclose())

    wrong_project = replace(config, project="different-project")
    with pytest.raises(QualificationProviderDrift):
        build_vertex_qualification_planner(provider, wrong_project)
    wrong_pricing = provider.model_copy(
        update={"input_cost_nano_units_per_token": 1_499}
    )
    with pytest.raises(QualificationProviderDrift, match="not frozen"):
        build_protocol_manifest(
            QualificationProtocolStage.DEVELOPMENT_1,
            source_revision="1" * 64,
            registered_at=NOW,
            provider=wrong_pricing,
        )


def test_deterministic_rejects_live_planner_and_failed_count_is_persisted(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repository = tmp_path / "source"
    source_revision = _source_repository(repository)
    manifest = build_protocol_manifest(
        QualificationProtocolStage.DEVELOPMENT_1,
        source_revision=source_revision,
        registered_at=NOW,
        provider=_provider(),
    )
    planner = build_vertex_qualification_planner(
        manifest.provider,
        VertexAdcPlannerConfig(
            project="reconcile-dev-260813-14fa6d",
            location="global",
            model="gemini-3.5-flash",
            timeout_seconds=30,
            max_output_tokens=1_024,
            prompt_version="adaptive-planner-v3",
        ),
    )
    count_calls = 0

    async def fail_count(**_kwargs: object) -> object:
        nonlocal count_calls
        count_calls += 1
        raise RuntimeError("sanitized count failure")

    raw_models = planner._model.api_client.aio.models._raw_models
    monkeypatch.setattr(raw_models, "count_tokens", fail_count)
    artifact_root = _artifact_root(tmp_path)
    runner = QualificationProtocolRunner(artifact_root, repository=repository)
    try:
        with pytest.raises(QualificationProviderDrift, match="deterministic"):
            asyncio.run(
                runner.run(
                    QualificationProtocolStage.DEVELOPMENT_1,
                    manifest,
                    planner,
                    execution_basis=QualificationExecutionBasis.DETERMINISTIC_TEST,
                )
            )
        assert count_calls == 0
        assert not (
            artifact_root / QualificationProtocolStage.DEVELOPMENT_1.value
        ).exists()

        direct_store = QualificationArtifactStore(_artifact_root(tmp_path, "direct"))
        direct_store.begin(QualificationProtocolStage.DEVELOPMENT_1)
        meter = _AttemptMeter(
            manifest,
            direct_store,
            [],
            prior_usage=canonical_prior_attempt_ledger().totals,
            execution_basis=QualificationExecutionBasis.LIVE_PROVIDER,
            runtime_identity=frozen_qualification_runtime_identity(),
            source_guard=lambda: None,
        )
        preflight = qualification_protocol_module._model_revision_preflight_input(
            planner.metadata,
            NOW,
        )
        metered = qualification_protocol_module._MeteredPlanner(
            planner,
            meter,
            execution_id="provider-model-revision-preflight",
            case_id="provider-model-revision-preflight",
            repetition=1,
            control_failure=False,
            preflight=True,
        )
        turn = asyncio.run(metered.plan(preflight))
        assert turn.failure is not None
    finally:
        asyncio.run(planner.aclose())

    stage_path = direct_store.stage_path
    attempt_paths = tuple(stage_path.glob("attempt-*.json"))
    assert count_calls == 1
    assert {path.name for path in attempt_paths} == {
        "attempt-001-count-tokens-start.json",
        "attempt-001-count-tokens-finish.json",
    }
    finish = json.loads(
        (stage_path / "attempt-001-count-tokens-finish.json").read_bytes()
    )
    assert finish["operation"] == QualificationProviderOperation.COUNT_TOKENS.value
    assert finish["outcome"] == QualificationAttemptOutcome.PROVIDER_FAILURE.value
    assert finish["accounted_input_tokens"] == 0
    assert finish["accounted_output_tokens"] == 0
    assert finish["accounted_cost_nano_units"] == 0
    assert not (stage_path / "execution-start.json").exists()


def test_provider_reservation_uses_context_bound_and_exact_global_ceilings(
    tmp_path: Path,
) -> None:
    runtime = frozen_qualification_runtime_identity()
    reservation = _provider_reservation(runtime, runtime.maximum_input_tokens_per_call)
    assert reservation.input_tokens == runtime.maximum_input_tokens_per_call
    assert reservation.output_tokens == runtime.max_output_tokens
    with pytest.raises(QualificationBudgetExceeded):
        _provider_reservation(runtime, runtime.maximum_input_tokens_per_call + 1)
    assert qualification_request_static_byte_counts() == (1_021, 1_901)
    assert (
        176 * reservation.cost_nano_units
        + canonical_prior_attempt_ledger().totals.model_cost_nano_units
        == 4_841_875_500
    )

    manifest = _manifest(QualificationProtocolStage.DEVELOPMENT_1)
    exact = QualificationModelUsageTotals(
        model_call_count=179,
        count_tokens_call_count=177,
        provider_request_count=356,
        input_token_count=0,
        output_token_count=0,
        total_token_count=0,
        model_cost_nano_units=(5_000_000_000 - reservation.cost_nano_units),
        reserved_usage_count=0,
        unexpected_missing_usage_count=0,
    )
    assert not _reservation_exceeds_ceiling(manifest, exact, reservation)
    assert _reservation_exceeds_ceiling(
        manifest,
        exact.model_copy(
            update={"model_cost_nano_units": (exact.model_cost_nano_units + 1)}
        ),
        reservation,
    )
    assert _reservation_exceeds_ceiling(
        manifest,
        exact.model_copy(
            update={
                "model_call_count": 180,
                "model_cost_nano_units": 0,
            }
        ),
        reservation,
    )

    store = QualificationArtifactStore(_artifact_root(tmp_path, "meter"))
    store.begin(QualificationProtocolStage.DEVELOPMENT_1)
    retained: list[QualificationArtifactIdentity] = []
    meter = _AttemptMeter(
        manifest,
        store,
        retained,
        prior_usage=_empty_usage(),
        execution_basis=QualificationExecutionBasis.DETERMINISTIC_TEST,
        runtime_identity=runtime,
        source_guard=lambda: None,
    )
    start = QualificationProviderAttemptStart(
        schema_version=QUALIFICATION_ATTEMPT_START_VERSION,
        attempt_id="attempt-001",
        sequence=1,
        dispatch_id="dispatch-001-overrun",
        execution_id="execution-overrun",
        case_id=manifest.cases[0].case_id,
        repetition=1,
        planner_phase=AdaptivePlannerPhase.ACQUIRE_EVIDENCE,
        operation=QualificationProviderOperation.GENERATE,
        execution_basis=QualificationExecutionBasis.DETERMINISTIC_TEST,
        planner_configuration_sha256=canonical_sha256(runtime),
        input_sha256="1" * 64,
        request_byte_count=1,
        sealed_generation_request_sha256="2" * 64,
        paired_count_attempt_id="attempt-000-count-tokens",
        reserved_provider_request_count=1,
        reserved_input_tokens=reservation.input_tokens,
        reserved_output_tokens=reservation.output_tokens,
        reserved_cost_nano_units=reservation.cost_nano_units,
        started_at=NOW,
    )
    metadata = _ScriptedPlanner(manifest.provider).metadata
    turn = AdvisoryPlannerTurn(
        output=None,
        failure=PlannerFailureKind.UNAVAILABLE,
        metadata=metadata,
        input_sha256=start.input_sha256,
        output_sha256=None,
        usage=AdvisoryPlannerUsage(
            prompt_tokens=reservation.input_tokens + 1,
            output_tokens=0,
            total_tokens=reservation.input_tokens + 1,
        ),
    )
    record = meter.complete_generation(start, metadata, turn=turn)
    assert record.outcome is QualificationAttemptOutcome.PROVIDER_FAILURE
    assert record.provider_failure_kind == PlannerFailureKind.UNAVAILABLE.value
    assert record.input_bound_status is QualificationBoundStatus.EXCEEDED
    assert record.output_bound_status is QualificationBoundStatus.WITHIN
    assert record.usage_measured


def test_post_provider_source_guard_preserves_measured_failure_accounting(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    manifest = _manifest(QualificationProtocolStage.DEVELOPMENT_1)
    runtime = frozen_qualification_runtime_identity()
    guard_checks = 0

    def source_guard() -> None:
        nonlocal guard_checks
        guard_checks += 1
        if guard_checks == 3:
            raise QualificationProtocolError(
                "qualification source changed after provider call"
            )

    store = QualificationArtifactStore(_artifact_root(tmp_path, "post-call-guard"))
    store.begin(QualificationProtocolStage.DEVELOPMENT_1)
    meter = _AttemptMeter(
        manifest,
        store,
        [],
        prior_usage=_empty_usage(),
        execution_basis=QualificationExecutionBasis.DETERMINISTIC_TEST,
        runtime_identity=runtime,
        source_guard=source_guard,
    )
    planner = _ScriptedPlanner(manifest.provider)

    async def measured_failure(
        planner_input: AdaptivePlannerInput,
    ) -> AdvisoryPlannerTurn:
        input_sha256 = hashlib.sha256(canonical_json_bytes(planner_input)).hexdigest()
        return AdvisoryPlannerTurn(
            output=None,
            failure=PlannerFailureKind.UNAVAILABLE,
            metadata=planner.metadata,
            input_sha256=input_sha256,
            output_sha256=None,
            usage=AdvisoryPlannerUsage(
                prompt_tokens=12_001,
                output_tokens=1_025,
                total_tokens=13_026,
            ),
        )

    monkeypatch.setattr(planner, "plan", measured_failure)
    metered_planner = qualification_protocol_module._MeteredPlanner(
        planner,
        meter,
        execution_id="provider-model-revision-preflight",
        case_id="provider-model-revision-preflight",
        repetition=1,
        control_failure=False,
        preflight=True,
    )
    planner_input = qualification_protocol_module._model_revision_preflight_input(
        planner.metadata, NOW
    )

    with pytest.raises(QualificationProtocolError, match="source changed"):
        asyncio.run(metered_planner.plan(planner_input))

    assert guard_checks == 3
    generation_records = tuple(
        record
        for record in meter.attempts
        if record.operation is QualificationProviderOperation.GENERATE
    )
    assert len(generation_records) == 1
    record = generation_records[0]
    assert record.outcome is QualificationAttemptOutcome.PROVIDER_FAILURE
    assert record.provider_failure_kind == PlannerFailureKind.UNAVAILABLE.value
    assert record.input_bound_status is QualificationBoundStatus.EXCEEDED
    assert record.output_bound_status is QualificationBoundStatus.EXCEEDED
    assert record.usage_measured
    assert record.accounted_input_tokens == 12_001
    assert record.accounted_output_tokens == 1_025
    assert meter._totals().unexpected_missing_usage_count == 0


@pytest.mark.parametrize(
    (
        "failure",
        "input_tokens",
        "output_tokens",
        "expected_outcome",
        "input_status",
        "output_status",
        "missing_usage",
    ),
    (
        (
            None,
            12_000,
            1_024,
            QualificationAttemptOutcome.MEASURED,
            QualificationBoundStatus.WITHIN,
            QualificationBoundStatus.WITHIN,
            False,
        ),
        (
            None,
            12_001,
            100,
            QualificationAttemptOutcome.RESERVATION_EXCEEDED,
            QualificationBoundStatus.EXCEEDED,
            QualificationBoundStatus.WITHIN,
            False,
        ),
        (
            None,
            100,
            1_025,
            QualificationAttemptOutcome.RESERVATION_EXCEEDED,
            QualificationBoundStatus.WITHIN,
            QualificationBoundStatus.EXCEEDED,
            False,
        ),
        (
            PlannerFailureKind.UNAVAILABLE,
            100,
            20,
            QualificationAttemptOutcome.PROVIDER_FAILURE,
            QualificationBoundStatus.WITHIN,
            QualificationBoundStatus.WITHIN,
            False,
        ),
        (
            PlannerFailureKind.UNAVAILABLE,
            12_001,
            20,
            QualificationAttemptOutcome.PROVIDER_FAILURE,
            QualificationBoundStatus.EXCEEDED,
            QualificationBoundStatus.WITHIN,
            False,
        ),
        (
            PlannerFailureKind.UNAVAILABLE,
            100,
            1_025,
            QualificationAttemptOutcome.PROVIDER_FAILURE,
            QualificationBoundStatus.WITHIN,
            QualificationBoundStatus.EXCEEDED,
            False,
        ),
        (
            PlannerFailureKind.UNAVAILABLE,
            12_001,
            1_025,
            QualificationAttemptOutcome.PROVIDER_FAILURE,
            QualificationBoundStatus.EXCEEDED,
            QualificationBoundStatus.EXCEEDED,
            False,
        ),
        (
            PlannerFailureKind.UNAVAILABLE,
            None,
            None,
            QualificationAttemptOutcome.PROVIDER_FAILURE,
            QualificationBoundStatus.UNKNOWN,
            QualificationBoundStatus.UNKNOWN,
            True,
        ),
        (
            None,
            None,
            None,
            QualificationAttemptOutcome.USAGE_UNAVAILABLE,
            QualificationBoundStatus.UNKNOWN,
            QualificationBoundStatus.UNKNOWN,
            True,
        ),
    ),
)
def test_generation_failure_bounds_and_usage_are_orthogonal(
    tmp_path: Path,
    failure: PlannerFailureKind | None,
    input_tokens: int | None,
    output_tokens: int | None,
    expected_outcome: QualificationAttemptOutcome,
    input_status: QualificationBoundStatus,
    output_status: QualificationBoundStatus,
    missing_usage: bool,
) -> None:
    manifest = _manifest(QualificationProtocolStage.DEVELOPMENT_1)
    runtime = frozen_qualification_runtime_identity()
    slug = f"{expected_outcome.value.lower()}-{input_tokens}-{output_tokens}"
    store = QualificationArtifactStore(_artifact_root(tmp_path, slug))
    store.begin(QualificationProtocolStage.DEVELOPMENT_1)
    meter = _AttemptMeter(
        manifest,
        store,
        [],
        prior_usage=_empty_usage(),
        execution_basis=QualificationExecutionBasis.DETERMINISTIC_TEST,
        runtime_identity=runtime,
        source_guard=lambda: None,
    )
    planner = _ScriptedPlanner(manifest.provider)
    planner_input = qualification_protocol_module._model_revision_preflight_input(
        planner.metadata, NOW
    )
    successful_turn = asyncio.run(planner.plan(planner_input))
    start = QualificationProviderAttemptStart(
        schema_version=QUALIFICATION_ATTEMPT_START_VERSION,
        attempt_id="attempt-001-generate",
        sequence=1,
        dispatch_id="dispatch-001-bounds",
        execution_id="provider-model-revision-preflight",
        case_id="provider-model-revision-preflight",
        repetition=1,
        planner_phase=AdaptivePlannerPhase.ACQUIRE_EVIDENCE,
        operation=QualificationProviderOperation.GENERATE,
        execution_basis=QualificationExecutionBasis.DETERMINISTIC_TEST,
        planner_configuration_sha256=canonical_sha256(runtime),
        input_sha256=successful_turn.input_sha256,
        request_byte_count=1,
        sealed_generation_request_sha256="2" * 64,
        paired_count_attempt_id="attempt-000-count-tokens",
        reserved_provider_request_count=1,
        reserved_input_tokens=12_000,
        reserved_output_tokens=1_024,
        reserved_cost_nano_units=27_216_000,
        started_at=NOW,
    )
    usage = (
        None
        if input_tokens is None or output_tokens is None
        else AdvisoryPlannerUsage(
            prompt_tokens=input_tokens,
            output_tokens=output_tokens,
            total_tokens=input_tokens + output_tokens,
        )
    )
    if failure is None and usage is not None:
        turn = AdvisoryPlannerTurn(
            output=successful_turn.output,
            failure=None,
            metadata=successful_turn.metadata,
            input_sha256=successful_turn.input_sha256,
            output_sha256=successful_turn.output_sha256,
            usage=usage,
        )
    elif failure is None:
        turn = None
    else:
        turn = AdvisoryPlannerTurn(
            output=None,
            failure=failure,
            metadata=planner.metadata,
            input_sha256=start.input_sha256,
            output_sha256=None,
            usage=usage,
        )
    record = meter.complete_generation(
        start,
        planner.metadata,
        turn=turn,
        preflight=True,
    )

    assert record.outcome is expected_outcome
    assert record.provider_failure_kind == (None if failure is None else failure.value)
    assert record.input_bound_status is input_status
    assert record.output_bound_status is output_status
    assert record.usage_measured is (usage is not None)
    assert record.accounting_basis.value == (
        "MEASURED"
        if expected_outcome is QualificationAttemptOutcome.MEASURED
        else "RESERVED"
    )
    assert record.accounted_input_tokens == (
        input_tokens
        if expected_outcome is QualificationAttemptOutcome.MEASURED
        else max(12_000, input_tokens or 0)
    )
    assert record.accounted_output_tokens == (
        output_tokens
        if expected_outcome is QualificationAttemptOutcome.MEASURED
        else max(1_024, output_tokens or 0)
    )
    assert meter._totals().unexpected_missing_usage_count == int(missing_usage)
    assert meter._totals().reserved_usage_count == int(
        expected_outcome is not QualificationAttemptOutcome.MEASURED
    )


def test_count_attempts_include_consumed_v2_at_the_exact_total_boundary(
    tmp_path: Path,
) -> None:
    manifest = _manifest(QualificationProtocolStage.DEVELOPMENT_1)
    historical = canonical_prior_attempt_ledger().totals
    store = QualificationArtifactStore(_artifact_root(tmp_path, "count-boundary"))
    store.begin(QualificationProtocolStage.DEVELOPMENT_1)
    meter = _AttemptMeter(
        manifest,
        store,
        [],
        prior_usage=historical,
        execution_basis=QualificationExecutionBasis.DETERMINISTIC_TEST,
        runtime_identity=frozen_qualification_runtime_identity(),
        source_guard=lambda: None,
    )
    metadata = _ScriptedPlanner(manifest.provider).metadata
    for sequence in range(1, 177):
        start = meter.reserve_count_tokens(
            execution_id=f"count-boundary-{sequence:03d}",
            case_id=manifest.cases[0].case_id,
            repetition=1,
            planner_phase=AdaptivePlannerPhase.ACQUIRE_EVIDENCE,
            input_sha256=f"{sequence:064x}",
            request_byte_count=1,
            sealed_generation_request_sha256=f"{sequence + 1:064x}",
            provider_request_sha256=f"{sequence + 2:064x}",
        )
        meter.complete_count_tokens(
            start,
            metadata,
            counted_input_tokens=1,
        )

    combined = qualification_protocol_module._add_usage(historical, meter._totals())
    assert combined.model_call_count == 4
    assert combined.count_tokens_call_count == 177
    assert combined.provider_request_count == 181
    assert combined.input_token_count == historical.input_token_count
    assert combined.output_token_count == historical.output_token_count
    assert combined.model_cost_nano_units == historical.model_cost_nano_units
    assert len(meter.attempts) == 176
    assert all(
        item.operation is QualificationProviderOperation.COUNT_TOKENS
        for item in meter.attempts
    )
    with pytest.raises(QualificationBudgetExceeded, match="ceiling"):
        meter.reserve_count_tokens(
            execution_id="count-boundary-177",
            case_id=manifest.cases[0].case_id,
            repetition=1,
            planner_phase=AdaptivePlannerPhase.ACQUIRE_EVIDENCE,
            input_sha256=f"{177:064x}",
            request_byte_count=1,
            sealed_generation_request_sha256=f"{178:064x}",
            provider_request_sha256=f"{179:064x}",
        )


def test_successful_attempts_bind_provider_and_preflight_ownership(
    tmp_path: Path,
) -> None:
    manifest = _manifest(QualificationProtocolStage.DEVELOPMENT_1)
    runtime = frozen_qualification_runtime_identity()
    store = QualificationArtifactStore(_artifact_root(tmp_path, "attempt-ownership"))
    store.begin(QualificationProtocolStage.DEVELOPMENT_1)
    meter = _AttemptMeter(
        manifest,
        store,
        [],
        prior_usage=_empty_usage(),
        execution_basis=QualificationExecutionBasis.DETERMINISTIC_TEST,
        runtime_identity=runtime,
        source_guard=lambda: None,
    )
    planner = _ScriptedPlanner(manifest.provider)
    planner_input = qualification_protocol_module._model_revision_preflight_input(
        planner.metadata, NOW
    )
    turn = asyncio.run(planner.plan(planner_input))
    input_bytes = canonical_json_bytes(planner_input)
    count_start = meter.reserve_count_tokens(
        execution_id="provider-model-revision-preflight",
        case_id="forged-preflight-owner",
        repetition=16,
        planner_phase=AdaptivePlannerPhase.EXPLAIN_EVIDENCE,
        input_sha256=turn.input_sha256,
        request_byte_count=len(input_bytes),
        sealed_generation_request_sha256="1" * 64,
        provider_request_sha256="2" * 64,
    )
    count_finish = meter.complete_count_tokens(
        count_start,
        planner.metadata,
        counted_input_tokens=100,
    )
    generation_start = meter.reserve_generation(count_attempt=count_finish)
    generation_finish = meter.complete_generation(
        generation_start,
        planner.metadata,
        turn=turn,
        preflight=True,
    )
    for record in (count_finish, generation_finish):
        forged = record.model_dump(mode="python")
        forged["provider_name"] = "forged-provider"
        forged["configured_model"] = "forged-model"
        with pytest.raises(ValueError, match="frozen provider identity"):
            qualification_protocol_module.QualificationProviderAttempt.model_validate(
                forged
            )
    with pytest.raises(ValueError, match="preflight attempt pair"):
        meter.ledger()


def test_count_tokens_is_provenance_not_generation_reservation(
    tmp_path: Path,
) -> None:
    manifest = _manifest(QualificationProtocolStage.DEVELOPMENT_1)
    runtime = frozen_qualification_runtime_identity()
    store = QualificationArtifactStore(_artifact_root(tmp_path, "count-provenance"))
    store.begin(QualificationProtocolStage.DEVELOPMENT_1)
    meter = _AttemptMeter(
        manifest,
        store,
        [],
        prior_usage=canonical_prior_attempt_ledger().totals,
        execution_basis=QualificationExecutionBasis.DETERMINISTIC_TEST,
        runtime_identity=runtime,
        source_guard=lambda: None,
    )
    planner = _ScriptedPlanner(manifest.provider)
    planner_input = qualification_protocol_module._model_revision_preflight_input(
        planner.metadata, NOW
    )
    turn = asyncio.run(planner.plan(planner_input))
    turn = AdvisoryPlannerTurn(
        output=turn.output,
        failure=None,
        metadata=turn.metadata,
        input_sha256=turn.input_sha256,
        output_sha256=turn.output_sha256,
        usage=AdvisoryPlannerUsage(
            prompt_tokens=1_734,
            output_tokens=1_007,
            total_tokens=2_741,
        ),
    )
    input_bytes = canonical_json_bytes(planner_input)
    count_start = meter.reserve_count_tokens(
        execution_id="provider-model-revision-preflight",
        case_id="provider-model-revision-preflight",
        repetition=1,
        planner_phase=AdaptivePlannerPhase.ACQUIRE_EVIDENCE,
        input_sha256=turn.input_sha256,
        request_byte_count=len(input_bytes),
        sealed_generation_request_sha256="1" * 64,
        provider_request_sha256="2" * 64,
    )
    count_finish = meter.complete_count_tokens(
        count_start,
        planner.metadata,
        counted_input_tokens=1_089,
    )
    generation_start = meter.reserve_generation(count_attempt=count_finish)
    generation_finish = meter.complete_generation(
        generation_start,
        planner.metadata,
        turn=turn,
        preflight=True,
    )

    assert count_finish.counted_input_tokens == 1_089
    assert generation_start.reserved_input_tokens == 12_000
    assert generation_start.reserved_output_tokens == 1_024
    assert generation_finish.outcome is QualificationAttemptOutcome.MEASURED
    assert generation_finish.accounting_basis.value == "MEASURED"
    assert generation_finish.accounted_input_tokens == 1_734
    assert generation_finish.accounted_output_tokens == 1_007
    assert generation_finish.input_bound_status is QualificationBoundStatus.WITHIN
    assert generation_finish.output_bound_status is QualificationBoundStatus.WITHIN
    assert meter.ledger().totals.unexpected_missing_usage_count == 0


def test_paired_dispatches_reach_every_frozen_provider_ceiling(
    tmp_path: Path,
) -> None:
    manifest = _manifest(QualificationProtocolStage.DEVELOPMENT_1)
    historical = canonical_prior_attempt_ledger().totals
    runtime = frozen_qualification_runtime_identity()
    store = QualificationArtifactStore(_artifact_root(tmp_path, "paired-boundary"))
    store.begin(QualificationProtocolStage.DEVELOPMENT_1)
    meter = _AttemptMeter(
        manifest,
        store,
        [],
        prior_usage=historical,
        execution_basis=QualificationExecutionBasis.DETERMINISTIC_TEST,
        runtime_identity=runtime,
        source_guard=lambda: None,
    )
    metadata = _ScriptedPlanner(manifest.provider).metadata
    for dispatch in range(1, 177):
        input_sha256 = f"{dispatch:064x}"
        count_start = meter.reserve_count_tokens(
            execution_id=f"paired-boundary-{dispatch:03d}",
            case_id=manifest.cases[0].case_id,
            repetition=1,
            planner_phase=AdaptivePlannerPhase.ACQUIRE_EVIDENCE,
            input_sha256=input_sha256,
            request_byte_count=1,
            sealed_generation_request_sha256=f"{dispatch + 1:064x}",
            provider_request_sha256=f"{dispatch + 2:064x}",
        )
        count_finish = meter.complete_count_tokens(
            count_start,
            metadata,
            counted_input_tokens=runtime.maximum_input_tokens_per_call,
        )
        generation_start = meter.reserve_generation(count_attempt=count_finish)
        meter.complete_generation(
            generation_start,
            metadata,
            turn=AdvisoryPlannerTurn(
                output=None,
                failure=PlannerFailureKind.UNAVAILABLE,
                metadata=metadata,
                input_sha256=input_sha256,
                output_sha256=None,
                usage=AdvisoryPlannerUsage(
                    prompt_tokens=runtime.maximum_input_tokens_per_call,
                    output_tokens=0,
                    total_tokens=runtime.maximum_input_tokens_per_call,
                ),
            ),
        )

    combined = qualification_protocol_module._add_usage(historical, meter._totals())
    assert combined.model_call_count == 180
    assert combined.count_tokens_call_count == 177
    assert combined.provider_request_count == 357
    assert combined.input_token_count == 2_133_679
    assert combined.output_token_count == 182_373
    assert combined.model_cost_nano_units == 4_841_875_500
    assert len(meter.attempts) == 352
    with pytest.raises(QualificationBudgetExceeded, match="ceiling"):
        meter.reserve_count_tokens(
            execution_id="paired-boundary-177",
            case_id=manifest.cases[0].case_id,
            repetition=1,
            planner_phase=AdaptivePlannerPhase.ACQUIRE_EVIDENCE,
            input_sha256=f"{177:064x}",
            request_byte_count=1,
            sealed_generation_request_sha256=f"{178:064x}",
            provider_request_sha256=f"{179:064x}",
        )


class _DelayedPlanner(_ScriptedPlanner):
    async def plan(self, planner_input: AdaptivePlannerInput) -> AdvisoryPlannerTurn:
        await asyncio.sleep(0.03)
        return await super().plan(planner_input)


def test_live_clock_includes_planner_delay_without_relabelling_evidence_time(
    tmp_path: Path,
) -> None:
    manifest = _manifest(QualificationProtocolStage.DEVELOPMENT_1)
    registry = QualificationFixtureRegistry(
        QualificationProtocolStage.DEVELOPMENT_1,
        manifest.cases,
        workspace=tmp_path / "real-elapsed",
        real_monotonic=True,
    )
    fixture = registry.prepare(manifest, manifest.cases[0], 1)

    async def execute():
        fixture.begin_lane("ADAPTIVE")
        result = await execute_adaptive_investigation(
            fixture.envelope,
            fixture.capabilities,
            fixture.rules,
            _DelayedPlanner(manifest.provider),
            fixture.adaptive_policy,
            clock=fixture.new_controller_clock(),
        )
        fixture.end_lane("ADAPTIVE")
        return result

    result = asyncio.run(execute())
    fixture.cleanup()
    assert result.total_elapsed_ms >= 25
    assert result.report.updated_at >= result.report.created_at


def test_unavailable_execution_is_neutral_to_unsupported_probe_savings(
    tmp_path: Path,
) -> None:
    manifest = _manifest(QualificationProtocolStage.DEVELOPMENT_1)
    registry = QualificationFixtureRegistry(
        QualificationProtocolStage.DEVELOPMENT_1,
        manifest.cases,
        workspace=tmp_path / "unavailable",
    )
    case = manifest.cases[0]
    fixture = registry.prepare(manifest, case, 1)

    async def unavailable(_probe):
        raise CapabilityUnavailable

    capabilities = CapabilityRegistry()
    for registration in fixture.capabilities.freeze():
        capabilities.register(
            CapabilityRegistration(
                capability=registration.capability,
                semantics=registration.semantics,
                enabled=registration.enabled,
                argument_byte_ceiling=registration.argument_byte_ceiling,
                max_invocations=registration.max_invocations,
                handler=unavailable,
            )
        )

    async def execute():
        fixture.begin_lane("FIXED")
        fixed = await execute_fixed_plan(
            fixture.envelope,
            capabilities,
            fixture.rules,
            fixture.fixed_plan,
            clock=fixture.new_controller_clock(),
        )
        fixture.end_lane("FIXED")
        fixture.begin_lane("ADAPTIVE")
        adaptive = await execute_adaptive_investigation(
            fixture.envelope,
            capabilities,
            fixture.rules,
            _ScriptedPlanner(manifest.provider),
            fixture.adaptive_policy,
            clock=fixture.new_controller_clock(),
        )
        fixture.end_lane("ADAPTIVE")
        return fixed, adaptive

    fixed_result, adaptive_result = asyncio.run(execute())
    fixture.cleanup()
    runtime_sha256 = canonical_sha256(frozen_qualification_runtime_identity())
    envelope_sha256 = canonical_sha256(fixture.envelope)
    fixed = _fixed_normalized_run(
        manifest,
        case,
        envelope_sha256,
        fixed_result,
        runtime_sha256,
    )
    adaptive = _adaptive_normalized_run(
        manifest,
        case,
        envelope_sha256,
        adaptive_result,
        runtime_sha256,
    )
    assert fixed.run.unsupported_probe_count == 0
    assert adaptive.run.unsupported_probe_count == 0
    assert fixed.unavailable_probe_count == 1
    assert adaptive.unavailable_probe_count == 1
    assert adaptive.proposal_facts.unsupported_proposal_count == 0


def test_partial_lane_failure_remains_reachable_and_readable(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repository = tmp_path / "source"
    source_revision = _source_repository(repository)
    artifact_root = _artifact_root(tmp_path)
    manifest = build_protocol_manifest(
        QualificationProtocolStage.DEVELOPMENT_1,
        source_revision=source_revision,
        registered_at=NOW,
        provider=_provider(),
    )
    runner = QualificationProtocolRunner(artifact_root, repository=repository)

    async def fail_lane(*_args, **_kwargs):
        raise RuntimeError("sanitized test failure")

    monkeypatch.setattr(
        qualification_protocol_module,
        "execute_adaptive_investigation",
        fail_lane,
    )
    outcome = asyncio.run(
        runner.run(
            QualificationProtocolStage.DEVELOPMENT_1,
            manifest,
            _ScriptedPlanner(manifest.provider),
            execution_basis=QualificationExecutionBasis.DETERMINISTIC_TEST,
        )
    )

    completion = runner.store.read_completion(QualificationProtocolStage.DEVELOPMENT_1)
    assert completion == outcome.completion
    assert outcome.result_set.results[0].status.value == "INVALID"
    case_payload = json.loads(
        (
            artifact_root
            / "development-1"
            / "execution-d101-storage-authoritative-fast-path-r1-case-execution.json"
        ).read_bytes()
    )
    assert case_payload["failure_record"] is not None
    assert len(case_payload["lane_receipts"]) == 2
    failure_receipt = json.loads(
        (
            artifact_root
            / "development-1"
            / "execution-d101-storage-authoritative-fast-path-r1-lane-2-receipt.json"
        ).read_bytes()
    )
    assert failure_receipt["normalized_run"] is None
    assert failure_receipt["failure_record"] is not None
    retained = {
        item["artifact_id"]
        for item in json.loads(
            (artifact_root / "development-1" / "execution-completion.json").read_bytes()
        )["retained_artifacts"]
    }
    assert failure_receipt["failure_record"]["artifact_id"] in retained
    assert case_payload["failure_record"]["artifact_id"] in retained


@pytest.mark.parametrize(
    ("interrupted_suffix", "protocol_run_retained"),
    (
        ("-fixed-protocol-run", False),
        ("-lane-1-receipt", True),
    ),
)
def test_lane_publication_interruption_retains_each_published_artifact(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    interrupted_suffix: str,
    protocol_run_retained: bool,
) -> None:
    repository = tmp_path / "source"
    source_revision = _source_repository(repository)
    artifact_root = _artifact_root(tmp_path)
    manifest = build_protocol_manifest(
        QualificationProtocolStage.DEVELOPMENT_1,
        source_revision=source_revision,
        registered_at=NOW,
        provider=_provider(),
    )
    runner = QualificationProtocolRunner(artifact_root, repository=repository)
    publish = runner.store.publish
    interrupted = False

    def interrupt_lane_publication(artifact_id, model):
        nonlocal interrupted
        if artifact_id.endswith(interrupted_suffix) and not interrupted:
            interrupted = True
            raise OSError("injected publication interruption")
        return publish(artifact_id, model)

    monkeypatch.setattr(runner.store, "publish", interrupt_lane_publication)
    outcome = asyncio.run(
        runner.run(
            QualificationProtocolStage.DEVELOPMENT_1,
            manifest,
            _ScriptedPlanner(manifest.provider),
            execution_basis=QualificationExecutionBasis.DETERMINISTIC_TEST,
        )
    )

    assert interrupted
    assert (
        runner.store.read_completion(QualificationProtocolStage.DEVELOPMENT_1)
        == outcome.completion
    )
    retained = {item.artifact_id for item in outcome.completion.retained_artifacts}
    stem = "execution-d101-storage-authoritative-fast-path-r1-fixed"
    assert f"{stem}-observations" in retained
    assert f"{stem}-run" in retained
    assert (f"{stem}-protocol-run" in retained) is protocol_run_retained
    case_payload = json.loads(
        (
            artifact_root
            / "development-1"
            / "execution-d101-storage-authoritative-fast-path-r1-case-execution.json"
        ).read_bytes()
    )
    assert case_payload["failure_record"] is not None
    case_failure = json.loads(
        (
            artifact_root
            / "development-1"
            / f"{case_payload['failure_record']['artifact_id']}.json"
        ).read_bytes()
    )
    assert case_failure["partial_publication"] is not None


def test_post_link_receipt_error_resolves_the_exact_durable_commit(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repository = tmp_path / "source"
    source_revision = _source_repository(repository)
    artifact_root = _artifact_root(tmp_path)
    manifest = build_protocol_manifest(
        QualificationProtocolStage.DEVELOPMENT_1,
        source_revision=source_revision,
        registered_at=NOW,
        provider=_provider(),
    )
    runner = QualificationProtocolRunner(artifact_root, repository=repository)
    publish = runner.store.publish
    interrupted = False

    def interrupt_after_receipt_commit(artifact_id, model):
        nonlocal interrupted
        identity = publish(artifact_id, model)
        if artifact_id.endswith("-lane-1-receipt") and not interrupted:
            interrupted = True
            raise OSError("injected post-link receipt error")
        return identity

    monkeypatch.setattr(runner.store, "publish", interrupt_after_receipt_commit)
    outcome = asyncio.run(
        runner.run(
            QualificationProtocolStage.DEVELOPMENT_1,
            manifest,
            _ScriptedPlanner(manifest.provider),
            execution_basis=QualificationExecutionBasis.DETERMINISTIC_TEST,
        )
    )

    assert interrupted
    assert (
        runner.store.read_completion(QualificationProtocolStage.DEVELOPMENT_1)
        == outcome.completion
    )
    assert all(
        item.status.value in {"COMPLETED", "CONTROL_PASSED"}
        for item in outcome.result_set.results
    )


def _delete_final_adaptive_attempt_pair(stage_path: Path, execution_id: str) -> None:
    ledger_path = stage_path / "attempt-ledger.json"
    ledger = (
        qualification_protocol_module.QualificationAttemptLedger.model_validate_json(
            ledger_path.read_bytes()
        )
    )
    target_indices = tuple(
        index
        for index, attempt in enumerate(ledger.attempts)
        if attempt.execution_id == execution_id
    )
    assert target_indices[-2:] == (len(ledger.attempts) - 2, len(ledger.attempts) - 1)
    assert tuple(ledger.attempts[index].operation for index in target_indices[-2:]) == (
        QualificationProviderOperation.COUNT_TOKENS,
        QualificationProviderOperation.GENERATE,
    )
    removed_starts = ledger.attempt_starts[-2:]
    removed_finishes = ledger.attempt_finishes[-2:]
    new_attempts = ledger.attempts[:-2]
    ledger_value = ledger.model_dump(mode="python")
    ledger_value.update(
        {
            "attempts": new_attempts,
            "attempt_starts": ledger.attempt_starts[:-2],
            "attempt_finishes": ledger.attempt_finishes[:-2],
            "totals": qualification_protocol_module._attempt_totals(new_attempts),
        }
    )
    changed_ledger = (
        qualification_protocol_module.QualificationAttemptLedger.model_validate(
            ledger_value
        )
    )

    def rewrite(artifact_id: str, model) -> QualificationArtifactIdentity:
        path = stage_path / f"{artifact_id}.json"
        payload = canonical_json_bytes(model)
        path.chmod(0o600)
        path.write_bytes(payload)
        path.chmod(0o400)
        return qualification_protocol_module.artifact_identity(artifact_id, payload)

    ledger_identity = rewrite("attempt-ledger", changed_ledger)
    protocol = (
        qualification_protocol_module.QualificationProtocolSummary.model_validate_json(
            (stage_path / "summary.json").read_bytes()
        )
    )
    ceiling = qualification_protocol_module._add_usage(
        changed_ledger.totals, protocol.prior_attempt_usage
    )
    usage_incomplete = changed_ledger.totals.unexpected_missing_usage_count > 0
    limit_exceeded = any(
        (
            ceiling.model_call_count > protocol.maximum_total_model_calls,
            ceiling.count_tokens_call_count > protocol.maximum_total_count_tokens_calls,
            ceiling.provider_request_count > protocol.maximum_total_provider_requests,
            ceiling.input_token_count > protocol.maximum_total_input_tokens,
            ceiling.output_token_count > protocol.maximum_total_output_tokens,
            ceiling.model_cost_nano_units
            > protocol.maximum_total_model_cost_nano_units,
        )
    )
    protocol_valid = (
        protocol.qualification_valid_for_value_evidence
        and not usage_incomplete
        and not limit_exceeded
    )
    protocol_value = protocol.model_dump(mode="python")
    protocol_value.update(
        {
            "attempt_ledger_sha256": ledger_identity.sha256,
            "qualification_attempt_usage": changed_ledger.totals,
            "ceiling_usage": ceiling,
            "usage_incomplete": usage_incomplete,
            "provider_limit_exceeded": limit_exceeded,
            "protocol_valid": protocol_valid,
            "successful": protocol_valid and protocol.provider_evidence_qualifying,
        }
    )
    changed_protocol = (
        qualification_protocol_module.QualificationProtocolSummary.model_validate(
            protocol_value
        )
    )
    protocol_identity = rewrite("summary", changed_protocol)

    completion_path = stage_path / "execution-completion.json"
    completion = qualification_protocol_module.QualificationExecutionCompletion.model_validate_json(
        completion_path.read_bytes()
    )
    removed_ids = {item.artifact_id for item in (*removed_starts, *removed_finishes)}
    retained = tuple(
        ledger_identity
        if item.artifact_id == "attempt-ledger"
        else protocol_identity
        if item.artifact_id == "summary"
        else item
        for item in completion.retained_artifacts
        if item.artifact_id not in removed_ids
    )
    completion_value = completion.model_dump(mode="python")
    completion_value.update(
        {
            "attempt_ledger": ledger_identity,
            "protocol_summary": protocol_identity,
            "protocol_valid": changed_protocol.protocol_valid,
            "successful": changed_protocol.successful,
            "retained_artifacts": retained,
        }
    )
    changed_completion = (
        qualification_protocol_module.QualificationExecutionCompletion.model_validate(
            completion_value
        )
    )
    rewrite("execution-completion", changed_completion)
    for identity in (*removed_starts, *removed_finishes):
        (stage_path / f"{identity.artifact_id}.json").unlink()


@pytest.mark.parametrize("retained_graph", ("invalid-receipt", "partial-wrapper"))
def test_reader_rejects_adaptive_usage_undercount_in_every_retained_graph(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    retained_graph: str,
) -> None:
    repository = tmp_path / "source"
    source_revision = _source_repository(repository)
    artifact_root = _artifact_root(tmp_path)
    manifest = build_protocol_manifest(
        QualificationProtocolStage.DEVELOPMENT_1,
        source_revision=source_revision,
        registered_at=NOW,
        provider=_provider(),
    )
    runner = QualificationProtocolRunner(artifact_root, repository=repository)
    if retained_graph == "invalid-receipt":
        planner = _ScriptedPlanner(
            manifest.provider,
            failure=PlannerFailureKind.UNAVAILABLE,
            measured_failure=True,
            failure_after_calls=1,
        )
    else:
        planner = _ScriptedPlanner(manifest.provider)
        publish = runner.store.publish
        interrupted = False

        def interrupt_adaptive_receipt(artifact_id, model):
            nonlocal interrupted
            if artifact_id.endswith("-lane-2-receipt") and not interrupted:
                interrupted = True
                raise OSError("injected adaptive receipt interruption")
            return publish(artifact_id, model)

        monkeypatch.setattr(runner.store, "publish", interrupt_adaptive_receipt)
    outcome = asyncio.run(
        runner.run(
            QualificationProtocolStage.DEVELOPMENT_1,
            manifest,
            planner,
            execution_basis=QualificationExecutionBasis.DETERMINISTIC_TEST,
        )
    )
    result = outcome.result_set.results[0]
    assert result.status.value == "INVALID"
    stage_path = artifact_root / QualificationProtocolStage.DEVELOPMENT_1.value
    run_path = stage_path / f"{result.execution_id}-adaptive-run.json"
    run = qualification_protocol_module.ComparisonRun.model_validate_json(
        run_path.read_bytes()
    )
    ledger = outcome.attempt_ledger
    generations = tuple(
        item
        for item in ledger.attempts
        if item.execution_id == result.execution_id
        and item.operation is QualificationProviderOperation.GENERATE
    )
    token_counts = tuple(
        item
        for item in ledger.attempts
        if item.execution_id == result.execution_id
        and item.operation is QualificationProviderOperation.COUNT_TOKENS
    )
    runtime_identity = frozen_qualification_runtime_identity()
    model_binding = (
        qualification_protocol_module.QualificationModelBinding.model_validate_json(
            (stage_path / "provider-model-binding.json").read_bytes()
        )
    )
    for update in (
        {"provider_name": "forged-provider"},
        {"model_name": "forged-model"},
        {
            "status": qualification_protocol_module.ComparisonModelUsageStatus.UNAVAILABLE,
            "input_token_count": None,
            "output_token_count": None,
            "total_token_count": None,
        },
    ):
        forged_usage = (
            qualification_protocol_module.ComparisonModelUsage.model_validate(
                {**run.model_usage.model_dump(mode="python"), **update}
            )
        )
        with pytest.raises(QualificationProtocolError, match="model usage changed"):
            qualification_protocol_module._validate_retained_adaptive_usage(
                forged_usage,
                generations,
                token_counts,
                runtime_identity,
                model_binding,
            )

    if retained_graph == "partial-wrapper":
        case_failure = json.loads(
            (stage_path / f"{result.execution_id}-case-failure.json").read_bytes()
        )
        partial = json.loads(
            (
                stage_path
                / f"{case_failure['partial_publication']['artifact_id']}.json"
            ).read_bytes()
        )
        assert partial["protocol_run"] is not None
        assert partial["strategy_kind"] == "ADAPTIVE"
    _delete_final_adaptive_attempt_pair(stage_path, result.execution_id)
    fresh = QualificationArtifactStore(artifact_root)
    with pytest.raises(QualificationProtocolError, match="model usage changed"):
        fresh.read_completion(QualificationProtocolStage.DEVELOPMENT_1)


def test_reader_recomputes_summaries_and_enumerates_stage_files(
    tmp_path: Path,
) -> None:
    repository = tmp_path / "source"
    source_revision = _source_repository(repository)
    artifact_root = _artifact_root(tmp_path)
    manifest = build_protocol_manifest(
        QualificationProtocolStage.DEVELOPMENT_1,
        source_revision=source_revision,
        registered_at=NOW,
        provider=_provider(),
    )
    runner = QualificationProtocolRunner(artifact_root, repository=repository)
    asyncio.run(
        runner.run(
            QualificationProtocolStage.DEVELOPMENT_1,
            manifest,
            _ScriptedPlanner(manifest.provider),
            execution_basis=QualificationExecutionBasis.DETERMINISTIC_TEST,
        )
    )
    stage_path = artifact_root / QualificationProtocolStage.DEVELOPMENT_1.value
    tracked_names = (
        "qualification-summary-v1.json",
        "summary.json",
        "disposition.json",
        ("execution-d101-storage-authoritative-fast-path-r1-lane-2-receipt.json"),
        ("execution-d101-storage-authoritative-fast-path-r1-case-execution.json"),
        "execution-completion.json",
    )
    originals = {name: (stage_path / name).read_bytes() for name in tracked_names}

    def rewrite(name: str, value: dict[str, object]) -> dict[str, object]:
        path = stage_path / name
        payload = qualification_protocol_module.canonical_json_value_bytes(value)
        path.chmod(0o600)
        path.write_bytes(payload)
        path.chmod(0o400)
        return {
            "artifact_id": name.removesuffix(".json"),
            "byte_count": len(payload),
            "sha256": hashlib.sha256(payload).hexdigest(),
        }

    def bind_completion(
        completion: dict[str, object],
        *identities: dict[str, object],
    ) -> None:
        retained = completion["retained_artifacts"]
        assert isinstance(retained, list)
        by_id = {identity["artifact_id"]: identity for identity in identities}
        for field in (
            "qualification_summary",
            "protocol_summary",
            "disposition",
        ):
            current = completion[field]
            assert isinstance(current, dict)
            replacement = by_id.get(current["artifact_id"])
            if replacement is not None:
                completion[field] = replacement
        completion["retained_artifacts"] = [
            by_id.get(item["artifact_id"], item) if isinstance(item, dict) else item
            for item in retained
        ]

    protocol = json.loads(originals["summary.json"])
    protocol["adaptive_metrics"]["total_elapsed_ms"] += 1
    protocol_identity = rewrite("summary.json", protocol)
    completion = json.loads(originals["execution-completion.json"])
    bind_completion(completion, protocol_identity)
    rewrite("execution-completion.json", completion)
    with pytest.raises(QualificationProtocolError, match="recomputed faithfully"):
        runner.store.read_completion(QualificationProtocolStage.DEVELOPMENT_1)

    for name in tracked_names:
        path = stage_path / name
        path.chmod(0o600)
        path.write_bytes(originals[name])
        path.chmod(0o400)

    summary = json.loads(originals["qualification-summary-v1.json"])
    summary["suite_median_probe_reduction"] += 1
    summary_identity = rewrite("qualification-summary-v1.json", summary)
    disposition = json.loads(originals["disposition.json"])
    disposition["summary_sha256"] = summary_identity["sha256"]
    disposition_identity = rewrite("disposition.json", disposition)
    protocol = json.loads(originals["summary.json"])
    protocol["qualification_summary"] = summary_identity
    protocol_identity = rewrite("summary.json", protocol)
    completion = json.loads(originals["execution-completion.json"])
    bind_completion(
        completion,
        summary_identity,
        protocol_identity,
        disposition_identity,
    )
    rewrite("execution-completion.json", completion)
    with pytest.raises(QualificationProtocolError, match="recomputed faithfully"):
        runner.store.read_completion(QualificationProtocolStage.DEVELOPMENT_1)

    for name in tracked_names:
        path = stage_path / name
        path.chmod(0o600)
        path.write_bytes(originals[name])
        path.chmod(0o400)
    receipt_name = (
        "execution-d101-storage-authoritative-fast-path-r1-lane-2-receipt.json"
    )
    case_name = "execution-d101-storage-authoritative-fast-path-r1-case-execution.json"
    receipt = json.loads(originals[receipt_name])
    receipt["action_gates_sha256"] = "f" * 64
    receipt_identity = rewrite(receipt_name, receipt)
    case_execution = json.loads(originals[case_name])
    case_execution["lane_receipts"][1] = receipt_identity
    case_identity = rewrite(case_name, case_execution)
    protocol = json.loads(originals["summary.json"])
    protocol["case_executions"][0] = case_identity
    protocol_identity = rewrite("summary.json", protocol)
    completion = json.loads(originals["execution-completion.json"])
    completion["case_executions"][0] = case_identity
    bind_completion(
        completion,
        receipt_identity,
        case_identity,
        protocol_identity,
    )
    rewrite("execution-completion.json", completion)
    with pytest.raises(QualificationProtocolError, match="validity was not recomputed"):
        runner.store.read_completion(QualificationProtocolStage.DEVELOPMENT_1)

    for name in tracked_names:
        path = stage_path / name
        path.chmod(0o600)
        path.write_bytes(originals[name])
        path.chmod(0o400)
    extra = stage_path / "unreachable-extra.json"
    extra.write_bytes(b"{}")
    extra.chmod(0o400)
    with pytest.raises(QualificationProtocolError, match="missing, extra, or mutable"):
        runner.store.read_completion(QualificationProtocolStage.DEVELOPMENT_1)


def test_final_access_revalidates_all_sealed_prerequisites_before_prepare(
    tmp_path: Path,
) -> None:
    manifest = _manifest(QualificationProtocolStage.FINAL_HOLDOUT)
    store_root = tmp_path / "sealed-final-access"
    stage_paths = {
        stage: store_root / stage.value for stage in QualificationProtocolStage
    }
    for path in stage_paths.values():
        path.mkdir(parents=True)
        path.chmod(0o700)

    def seal(
        stage: QualificationProtocolStage,
        artifact_id: str,
        value: dict[str, object],
    ) -> QualificationArtifactIdentity:
        payload = qualification_protocol_module.canonical_json_value_bytes(value)
        path = stage_paths[stage] / f"{artifact_id}.json"
        path.write_bytes(payload)
        path.chmod(0o400)
        return QualificationArtifactIdentity(
            artifact_id=artifact_id,
            sha256=hashlib.sha256(payload).hexdigest(),
            byte_count=len(payload),
        )

    def identity_value(
        identity: QualificationArtifactIdentity,
    ) -> dict[str, object]:
        return identity.model_dump(mode="json")

    runtime_payload: dict[str, object] = {
        "configured_model": manifest.provider.model_name,
        "runtime": "sealed-synthetic-runtime",
    }
    runtime_identities = {
        stage: seal(stage, "runtime-identity", runtime_payload)
        for stage in QualificationProtocolStage
    }
    assert len({item.sha256 for item in runtime_identities.values()}) == 1
    runtime_sha256 = runtime_identities[QualificationProtocolStage.FINAL_HOLDOUT].sha256
    concrete_revision = "gemini-3.5-flash-001"
    historical_sha256 = "4" * 64
    consumed_v2_sha256 = "5" * 64

    def binding_payload(suite_id: str, nonce: str) -> dict[str, object]:
        return {
            "configured_model": manifest.provider.model_name,
            "nonce": nonce,
            "reported_model_revision": concrete_revision,
            "runtime_identity_sha256": runtime_sha256,
            "suite_id": suite_id,
        }

    first_suite = "synthetic-development-one"
    second_suite = "synthetic-development-two"
    first_binding = seal(
        QualificationProtocolStage.DEVELOPMENT_1,
        "provider-model-binding",
        binding_payload(first_suite, "first"),
    )
    second_binding = seal(
        QualificationProtocolStage.DEVELOPMENT_2,
        "provider-model-binding",
        binding_payload(second_suite, "second"),
    )
    final_binding = seal(
        QualificationProtocolStage.FINAL_HOLDOUT,
        "provider-model-binding",
        binding_payload(manifest.suite_id, "final"),
    )
    assert len({first_binding.sha256, second_binding.sha256, final_binding.sha256}) == 3

    first_completion_payload: dict[str, object] = {
        "execution_basis": "LIVE_PROVIDER",
        "consumed_v2_custody_sha256": consumed_v2_sha256,
        "historical_attempt_ledger_sha256": historical_sha256,
        "model_binding": identity_value(first_binding),
        "planner_configuration_sha256": runtime_sha256,
        "prior_stage_completion_sha256": None,
        "provider_evidence_qualifying": True,
        "runtime_identity": identity_value(
            runtime_identities[QualificationProtocolStage.DEVELOPMENT_1]
        ),
        "source_revision": manifest.source_revision,
        "stage": QualificationProtocolStage.DEVELOPMENT_1.value,
        "successful": True,
        "suite_id": first_suite,
    }
    first_completion = seal(
        QualificationProtocolStage.DEVELOPMENT_1,
        "execution-completion",
        first_completion_payload,
    )
    second_completion = seal(
        QualificationProtocolStage.DEVELOPMENT_2,
        "execution-completion",
        {
            **first_completion_payload,
            "model_binding": identity_value(second_binding),
            "prior_stage_completion_sha256": first_completion.sha256,
            "runtime_identity": identity_value(
                runtime_identities[QualificationProtocolStage.DEVELOPMENT_2]
            ),
            "stage": QualificationProtocolStage.DEVELOPMENT_2.value,
            "suite_id": second_suite,
        },
    )
    manifest_payload = manifest.model_dump(mode="json")
    manifest_identity = seal(
        QualificationProtocolStage.FINAL_HOLDOUT,
        "manifest",
        manifest_payload,
    )
    start_identity = seal(
        QualificationProtocolStage.FINAL_HOLDOUT,
        "execution-start",
        {
            "consumed_v2_custody_sha256": consumed_v2_sha256,
            "execution_basis": "LIVE_PROVIDER",
            "historical_attempt_ledger_sha256": historical_sha256,
            "manifest_sha256": manifest_identity.sha256,
            "model_binding": identity_value(final_binding),
            "planner_configuration_sha256": runtime_sha256,
            "prior_stage_completion_sha256": second_completion.sha256,
            "runtime_identity": identity_value(
                runtime_identities[QualificationProtocolStage.FINAL_HOLDOUT]
            ),
            "source_revision": manifest.source_revision,
            "stage": QualificationProtocolStage.FINAL_HOLDOUT.value,
            "suite_id": manifest.suite_id,
        },
    )
    schedule = tuple(
        (case.case_id, repetition)
        for repetition in range(1, manifest.repetition_count + 1)
        for case in manifest.cases
    )
    access = _issue_final_fixture_access(
        stage_paths[QualificationProtocolStage.FINAL_HOLDOUT],
        start_identity,
        store_root,
        manifest_identity=manifest_identity,
        final_runtime_identity=runtime_identities[
            QualificationProtocolStage.FINAL_HOLDOUT
        ],
        final_model_binding_identity=final_binding,
        prerequisite_completion_identities=(
            first_completion,
            second_completion,
        ),
        prerequisite_model_binding_identities=(
            first_binding,
            second_binding,
        ),
        prerequisite_retained_artifacts=(
            (
                runtime_identities[QualificationProtocolStage.DEVELOPMENT_1],
                first_binding,
            ),
            (
                runtime_identities[QualificationProtocolStage.DEVELOPMENT_2],
                second_binding,
            ),
        ),
        source_revision=manifest.source_revision,
        runtime_identity_sha256=runtime_sha256,
        concrete_model_revision=concrete_revision,
        historical_attempt_ledger_sha256=historical_sha256,
        consumed_v2_custody_sha256=consumed_v2_sha256,
        schedule=schedule,
    )
    session = _FinalFixtureSession(access)
    workspace = tmp_path / "final-runtime"
    registry = QualificationFixtureRegistry._from_store(
        manifest.cases,
        workspace=workspace,
        session=session,
        real_monotonic=False,
    )
    first_case = manifest.cases[0]
    manifest_path = (
        stage_paths[QualificationProtocolStage.FINAL_HOLDOUT] / "manifest.json"
    )
    original_manifest = manifest_path.read_bytes()
    changed_manifest = dict(manifest_payload)
    changed_manifest["action_policy_version"] = "tampered-action-policy"
    manifest_path.chmod(0o600)
    manifest_path.write_bytes(
        qualification_protocol_module.canonical_json_value_bytes(changed_manifest)
    )
    manifest_path.chmod(0o400)
    with pytest.raises(RuntimeError, match="remain untouched"):
        registry.prepare(manifest, first_case, 1)
    assert session.next_index == 0
    assert not workspace.exists()

    manifest_path.chmod(0o600)
    manifest_path.write_bytes(original_manifest)
    manifest_path.chmod(0o400)
    first_runtime_path = (
        stage_paths[QualificationProtocolStage.DEVELOPMENT_1] / "runtime-identity.json"
    )
    first_runtime_bytes = first_runtime_path.read_bytes()
    first_runtime_path.chmod(0o600)
    first_runtime_path.write_bytes(b'{"runtime":"tampered"}')
    first_runtime_path.chmod(0o400)
    with pytest.raises(RuntimeError, match="remain untouched"):
        registry.prepare(manifest, first_case, 1)
    assert session.next_index == 0
    assert not workspace.exists()
    first_runtime_path.chmod(0o600)
    first_runtime_path.write_bytes(first_runtime_bytes)
    first_runtime_path.chmod(0o400)

    first_binding_path = (
        stage_paths[QualificationProtocolStage.DEVELOPMENT_1]
        / "provider-model-binding.json"
    )
    first_binding_bytes = first_binding_path.read_bytes()
    first_binding_path.unlink()
    with pytest.raises(RuntimeError, match="remain untouched"):
        registry.prepare(manifest, first_case, 1)
    assert session.next_index == 0
    assert not workspace.exists()

    first_binding_path.write_bytes(first_binding_bytes)
    first_binding_path.chmod(0o400)
    fixture = registry.prepare(manifest, first_case, 1)
    assert session.next_index == 1
    fixture.cleanup()
    registry.cleanup_workspace()


def test_final_access_rejects_forged_store_path_and_identity(tmp_path: Path) -> None:
    identity = QualificationArtifactIdentity(
        artifact_id="execution-start",
        sha256="0" * 64,
        byte_count=1,
    )
    with pytest.raises(TypeError, match="issued only"):
        QualificationFinalFixtureAccess(
            tmp_path / "final-holdout",
            identity,
            tmp_path,
            manifest_identity=identity.model_copy(update={"artifact_id": "manifest"}),
            final_runtime_identity=identity.model_copy(
                update={"artifact_id": "runtime-identity"}
            ),
            final_model_binding_identity=identity.model_copy(
                update={"artifact_id": "provider-model-binding"}
            ),
            prerequisite_completion_identities=(
                identity.model_copy(
                    update={"artifact_id": "execution-completion", "sha256": "5" * 64}
                ),
                identity.model_copy(
                    update={"artifact_id": "execution-completion", "sha256": "6" * 64}
                ),
            ),
            prerequisite_model_binding_identities=(
                identity.model_copy(
                    update={"artifact_id": "provider-model-binding", "sha256": "7" * 64}
                ),
                identity.model_copy(
                    update={"artifact_id": "provider-model-binding", "sha256": "8" * 64}
                ),
            ),
            prerequisite_retained_artifacts=((), ()),
            source_revision="1" * 64,
            runtime_identity_sha256="2" * 64,
            concrete_model_revision="gemini-3.5-flash-001",
            historical_attempt_ledger_sha256="4" * 64,
            consumed_v2_custody_sha256="5" * 64,
            schedule=(("case", 1),),
            _seal=object(),
        )

    manifest = _manifest(QualificationProtocolStage.FINAL_HOLDOUT)
    with pytest.raises(RuntimeError, match="created only by its store"):
        QualificationFixtureRegistry(
            QualificationProtocolStage.FINAL_HOLDOUT,
            manifest.cases,
            workspace=tmp_path / "direct-final-fixtures",
        )

    store = QualificationArtifactStore(_artifact_root(tmp_path, "forged"))
    store.begin(QualificationProtocolStage.FINAL_HOLDOUT)
    forged = store.publish(
        "execution-start",
        QualificationSourceState(
            source_revision=source_revision_for_git_commit("1" * 40),
            git_commit="1" * 40,
            clean=True,
        ),
    )
    with pytest.raises((ValueError, QualificationProtocolError)):
        store.create_fixture_registry(
            QualificationProtocolStage.FINAL_HOLDOUT,
            manifest,
            forged,
            workspace=tmp_path / "final-fixtures",
            real_monotonic=False,
        )
    assert not (tmp_path / "final-fixtures").exists()
