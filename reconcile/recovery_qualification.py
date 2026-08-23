"""Deterministic recovery qualification, comparison, and evidence export."""

from __future__ import annotations

import asyncio
import ctypes
import errno
import hashlib
import os
import platform as platform_module
import stat
import subprocess
import sys
import tempfile
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from uuid import uuid4

from reconcile.contracts import (
    ActionPermitState,
    PermitAction,
    RecoveryDispatchOutcome,
    canonical_json_bytes,
    canonical_sha256,
    decode_contract,
)
from reconcile.contracts.base import canonical_json_value_bytes
from reconcile.contracts.recovery_qualification import (
    RECOVERY_QUALIFICATION_ADAPTIVE_THRESHOLD_BASIS_POINTS,
    RECOVERY_QUALIFICATION_BUNDLE_FORMAT,
    RECOVERY_QUALIFICATION_CASE_COUNT,
    RECOVERY_QUALIFICATION_CLAIM_AUTHORIZATION_VERSION,
    RECOVERY_QUALIFICATION_COMPARISON_VERSION,
    RECOVERY_QUALIFICATION_CONTENTION_VERSION,
    RECOVERY_QUALIFICATION_CONTENTION_WIDTH,
    RECOVERY_QUALIFICATION_CONTROLLER_VERSION,
    RECOVERY_QUALIFICATION_DECISION_POLICY_VERSION,
    RECOVERY_QUALIFICATION_ENVIRONMENT_VERSION,
    RECOVERY_QUALIFICATION_FIXTURE_CATALOG_SHA256,
    RECOVERY_QUALIFICATION_INDEX_VERSION,
    RECOVERY_QUALIFICATION_LANE_COUNT,
    RECOVERY_QUALIFICATION_MANIFEST_VERSION,
    RECOVERY_QUALIFICATION_PERMIT_POLICY_VERSION,
    RECOVERY_QUALIFICATION_POLICIES,
    RECOVERY_QUALIFICATION_RESULTS_VERSION,
    RECOVERY_QUALIFICATION_RUNNER_VERSION,
    RECOVERY_QUALIFICATION_SEEDS,
    RecoveryQualificationAggregateMetrics,
    RecoveryQualificationArtifactIdentity,
    RecoveryQualificationArtifactKind,
    RecoveryQualificationCaseProof,
    RecoveryQualificationClaimAuthorization,
    RecoveryQualificationComparison,
    RecoveryQualificationContention,
    RecoveryQualificationContentionTrial,
    RecoveryQualificationEnvironment,
    RecoveryQualificationExecutionBasis,
    RecoveryQualificationHypothesisReplay,
    RecoveryQualificationIndex,
    RecoveryQualificationLaneResult,
    RecoveryQualificationManifest,
    RecoveryQualificationModelUsage,
    RecoveryQualificationModelUsageStatus,
    RecoveryQualificationPermitCoverage,
    RecoveryQualificationPolicy,
    RecoveryQualificationResolution,
    RecoveryQualificationResults,
    RecoveryQualificationStorageBackend,
    RecoveryQualificationWitnessReplayKind,
)
from reconcile.hosted.firestore_cas import (
    FirestoreCasCollection,
    firestore_cas_document_path,
)
from reconcile.persistence.permits import PermitClaimDenied
from reconcile.recovery_qualification_execution import (
    RecoveryQualificationBlindExecution,
    RecoveryQualificationProofExecution,
    execute_recovery_qualification_blind_lane,
    execute_recovery_qualification_proof_lane,
    prepare_recovery_qualification_contention_dispatch,
)
from reconcile.recovery_qualification_fixtures import (
    RECOVERY_QUALIFICATION_ARCHETYPES,
    RecoveryQualificationFixture,
    RecoveryQualificationObservation,
    build_recovery_qualification_fixtures,
    recovery_qualification_fixture_catalog_sha256,
)

RECOVERY_QUALIFICATION_MEDIAN_FORMULA = (
    "(fixed_median_probe_count_x2-adaptive_median_probe_count_x2)"
    "*10000//fixed_median_probe_count_x2"
)

_BUNDLE_ARTIFACTS = (
    "manifest.json",
    "environment.json",
    "results.json",
    "contention.json",
    "comparison.json",
    "claim-authorization.json",
)
_BUNDLE_FILES = (*_BUNDLE_ARTIFACTS, "index.json")
_CONTENTION_NOW = datetime(2026, 8, 23, 0, 0, tzinfo=UTC)
RECOVERY_QUALIFICATION_TEST_COMMANDS = (
    "python -m pytest -q",
    "python -m pytest -q tests/unit/test_recovery_qualification.py "
    "tests/contract/test_recovery_qualification_contract.py "
    "tests/integration/test_recovery_qualification_integration.py",
    "python -m ruff check .",
    "python scripts/generate_contract_schemas.py --check",
    "uv lock --check",
    "uv build --no-sources",
)


class RecoveryQualificationError(RuntimeError):
    """Qualification inputs or evidence violate the frozen protocol."""


def _require_frozen_manifest(manifest: RecoveryQualificationManifest) -> None:
    if (
        manifest.suite_id != RECOVERY_QUALIFICATION_BUNDLE_FORMAT
        or manifest.controller_version != RECOVERY_QUALIFICATION_CONTROLLER_VERSION
        or manifest.decision_policy_version
        != RECOVERY_QUALIFICATION_DECISION_POLICY_VERSION
        or manifest.permit_policy_version
        != RECOVERY_QUALIFICATION_PERMIT_POLICY_VERSION
        or manifest.archetypes != RECOVERY_QUALIFICATION_ARCHETYPES
        or manifest.seeds != RECOVERY_QUALIFICATION_SEEDS
        or manifest.policies != RECOVERY_QUALIFICATION_POLICIES
        or manifest.fixture_catalog_sha256
        != recovery_qualification_fixture_catalog_sha256()
    ):
        raise RecoveryQualificationError("qualification manifest catalog changed")


def _require_environment_matches_manifest(
    manifest: RecoveryQualificationManifest,
    environment: RecoveryQualificationEnvironment,
) -> None:
    if (
        environment.suite_id != manifest.suite_id
        or environment.manifest_sha256 != canonical_sha256(manifest)
        or environment.source_revision != manifest.source_revision
        or environment.source_tree_sha256 != manifest.source_tree_sha256
        or environment.runner_version != RECOVERY_QUALIFICATION_RUNNER_VERSION
        or environment.test_commands != RECOVERY_QUALIFICATION_TEST_COMMANDS
    ):
        raise RecoveryQualificationError("qualification environment binding changed")


def _require_results_match_manifest(
    manifest: RecoveryQualificationManifest,
    results: RecoveryQualificationResults,
) -> None:
    """Cross-check facts that cannot be derived inside one standalone record."""

    _require_frozen_manifest(manifest)
    fixtures = build_recovery_qualification_fixtures()
    for index, (fixture, proof) in enumerate(
        zip(fixtures, results.case_proofs, strict=True)
    ):
        lanes = results.lane_results[index * 4 : index * 4 + 4]
        archetype = fixture.archetype
        expected_kind = (
            RecoveryQualificationArtifactKind.AMBIGUITY_WITNESS
            if archetype.ambiguity_witness_required
            else RecoveryQualificationArtifactKind.VERIFIED_CERTIFICATE
        )
        common = (
            proof.case_id == fixture.case_id
            and proof.archetype_id == archetype.archetype_id
            and proof.seed == fixture.seed
            and proof.storage_backend is fixture.storage_backend
            and proof.deterministic_resolution is archetype.expected_resolution
            and proof.deterministic_permit_action is archetype.expected_permit_action
            and proof.fixed_artifact_kind is expected_kind
            and proof.adaptive_artifact_kind is expected_kind
        )
        lane_binding = all(
            lane.case_id == fixture.case_id
            and lane.archetype_id == archetype.archetype_id
            and lane.seed == fixture.seed
            and lane.storage_backend is fixture.storage_backend
            and lane.fault_class is archetype.fault_class
            and lane.expected_permit_action is archetype.expected_permit_action
            for lane in lanes
        )
        proof_outcomes = all(
            lane.resolution is archetype.expected_resolution
            and lane.deterministic_artifact_kind is expected_kind
            and lane.issued_permit_action is archetype.expected_permit_action
            for lane in lanes[2:]
        )
        metrics_match = (
            lanes[2].probe_count == archetype.fixed_probe_count
            and lanes[3].probe_count == archetype.adaptive_probe_count
            and lanes[2].unsupported_probe_count
            == archetype.fixed_unsupported_probe_count
            and lanes[3].unsupported_probe_count
            == archetype.adaptive_unsupported_probe_count
        )
        profile_matches = all(
            lane.demonstrated_evidence_profile == archetype.evidence_profile
            for lane in lanes[2:]
        )
        restart_matches = proof.restart_exercised is (fixture.seed == manifest.seeds[0])
        variants = tuple(replay.variant_id for replay in proof.wrong_hypothesis_replays)
        if (
            not common
            or results.suite_id != manifest.suite_id
            or not lane_binding
            or not proof_outcomes
            or not metrics_match
            or not profile_matches
            or not restart_matches
            or variants
            != tuple(f"wrong-gemini-hypothesis-{value}" for value in range(1, 4))
        ):
            raise RecoveryQualificationError(
                "qualification results contradict the frozen manifest"
            )


def _require_contention_matches_protocol(
    manifest: RecoveryQualificationManifest,
    results: RecoveryQualificationResults,
    contention: RecoveryQualificationContention,
) -> None:
    try:
        trusted_contention = RecoveryQualificationContention.model_validate(
            contention.model_dump(mode="python")
        )
    except Exception as error:
        raise RecoveryQualificationError(
            "qualification contention contract is invalid"
        ) from error
    if trusted_contention != contention:
        raise RecoveryQualificationError("qualification contention contract changed")
    if (
        contention.suite_id != manifest.suite_id
        or contention.manifest_sha256 != canonical_sha256(manifest)
        or contention.results_sha256 != canonical_sha256(results)
    ):
        raise RecoveryQualificationError("qualification contention binding changed")
    expected_claim_ids = tuple(
        f"qualification-claim-{index:02}"
        for index in range(RECOVERY_QUALIFICATION_CONTENTION_WIDTH)
    )
    for trial in contention.trials:
        receipt_ids = (
            "dispatch-"
            + hashlib.sha256(
                (
                    f"{trial.final_permit.permit_id}\0"
                    f"{trial.winner_claim_id}"
                ).encode()
            ).hexdigest()[:32],
        )
        expected_denied = tuple(
            claim_id
            for claim_id in expected_claim_ids
            if claim_id != trial.winner_claim_id
        )
        if (
            trial.contender_claim_ids != expected_claim_ids
            or trial.denied_claim_ids != expected_denied
            or trial.provider_call_receipt_ids != receipt_ids
            or trial.final_permit.source_node_id
            != ("stage" if trial.permit_action is PermitAction.CONTINUE else "record")
            or trial.final_permit.tool_name
            != (
                "promote-cloud-run-traffic"
                if trial.permit_action is PermitAction.CONTINUE
                else "create-firestore-release-record"
            )
        ):
            raise RecoveryQualificationError(
                "qualification contention trial contradicts the protocol"
            )


@dataclass(frozen=True, slots=True)
class RecoveryQualificationReplay:
    admitted_evidence_sha256: str
    decision_sha256: str
    resolution: RecoveryQualificationResolution
    permit_action: PermitAction | None
    permit_sha256: str | None
    ambiguity_witness_sha256: str | None


@dataclass(frozen=True, slots=True)
class RecoveryQualificationBundle:
    manifest: RecoveryQualificationManifest
    environment: RecoveryQualificationEnvironment
    results: RecoveryQualificationResults
    contention: RecoveryQualificationContention
    comparison: RecoveryQualificationComparison
    claim_authorization: RecoveryQualificationClaimAuthorization


def _now(value: datetime | None) -> datetime:
    selected = datetime.now(UTC) if value is None else value
    if selected.tzinfo is None or selected.utcoffset() is None:
        raise RecoveryQualificationError("qualification clock must be timezone-aware")
    return selected.astimezone(UTC)


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        while chunk := source.read(65_536):
            digest.update(chunk)
    return digest.hexdigest()


def recovery_qualification_source_state(
    repository: str | Path,
) -> tuple[str, str, bool]:
    """Return the exact Git revision, worktree content digest, and clean flag."""

    root = Path(repository).resolve()
    if not root.is_dir():
        raise RecoveryQualificationError("qualification repository is unavailable")
    try:
        revision = subprocess.run(
            ("git", "rev-parse", "HEAD"),
            cwd=root,
            check=True,
            capture_output=True,
            text=True,
        ).stdout.strip()
        names = subprocess.run(
            (
                "git",
                "ls-files",
                "--cached",
                "--others",
                "--exclude-standard",
                "-z",
            ),
            cwd=root,
            check=True,
            capture_output=True,
        ).stdout.split(b"\0")
        dirty = bool(
            subprocess.run(
                ("git", "status", "--porcelain", "--untracked-files=all"),
                cwd=root,
                check=True,
                capture_output=True,
            ).stdout
        )
    except (OSError, subprocess.CalledProcessError) as error:
        raise RecoveryQualificationError(
            "qualification source identity is unavailable"
        ) from error
    digest = hashlib.sha256()
    for encoded_name in sorted(name for name in names if name):
        try:
            name = encoded_name.decode("utf-8")
            path = root / name
            payload = (
                os.fsencode(os.readlink(path))
                if path.is_symlink()
                else path.read_bytes()
            )
        except (OSError, UnicodeDecodeError) as error:
            raise RecoveryQualificationError(
                "qualification source tree cannot be read exactly"
            ) from error
        digest.update(len(encoded_name).to_bytes(8, "big"))
        digest.update(encoded_name)
        digest.update(len(payload).to_bytes(8, "big"))
        digest.update(payload)
    return revision, digest.hexdigest(), not dirty


def build_recovery_qualification_manifest(
    *,
    source_revision: str,
    source_tree_sha256: str,
    created_at: datetime | None = None,
    suite_id: str = "proof-to-permit-qualification-v1",
) -> RecoveryQualificationManifest:
    """Build the frozen 20 archetype by five seed preregistration."""

    return RecoveryQualificationManifest(
        schema_version=RECOVERY_QUALIFICATION_MANIFEST_VERSION,
        bundle_format=RECOVERY_QUALIFICATION_BUNDLE_FORMAT,
        suite_id=suite_id,
        source_revision=source_revision,
        source_tree_sha256=source_tree_sha256,
        fixture_catalog_sha256=RECOVERY_QUALIFICATION_FIXTURE_CATALOG_SHA256,
        controller_version=RECOVERY_QUALIFICATION_CONTROLLER_VERSION,
        decision_policy_version=RECOVERY_QUALIFICATION_DECISION_POLICY_VERSION,
        permit_policy_version=RECOVERY_QUALIFICATION_PERMIT_POLICY_VERSION,
        seeds=RECOVERY_QUALIFICATION_SEEDS,
        policies=RECOVERY_QUALIFICATION_POLICIES,
        archetypes=RECOVERY_QUALIFICATION_ARCHETYPES,
        case_count=RECOVERY_QUALIFICATION_CASE_COUNT,
        lane_result_count=RECOVERY_QUALIFICATION_LANE_COUNT,
        wrong_hypothesis_variants_per_case=3,
        restart_case_count=20,
        contention_width=RECOVERY_QUALIFICATION_CONTENTION_WIDTH,
        adaptive_efficiency_threshold_basis_points=(
            RECOVERY_QUALIFICATION_ADAPTIVE_THRESHOLD_BASIS_POINTS
        ),
        created_at=_now(created_at),
    )


def build_recovery_qualification_environment(
    manifest: RecoveryQualificationManifest,
    *,
    repository_clean: bool,
    dependency_lock_sha256: str,
    generated_at: datetime | None = None,
    execution_basis: RecoveryQualificationExecutionBasis = (
        RecoveryQualificationExecutionBasis.SCRIPTED
    ),
    provider_name: str | None = None,
    model_name: str | None = None,
    vertex_location: str | None = None,
    python_version: str | None = None,
    platform_name: str | None = None,
    test_commands: tuple[str, ...] = RECOVERY_QUALIFICATION_TEST_COMMANDS,
) -> RecoveryQualificationEnvironment:
    """Bind one run to its exact source, dependency lock, and provider basis."""

    if type(manifest) is not RecoveryQualificationManifest:
        raise TypeError("an exact recovery qualification manifest is required")
    return RecoveryQualificationEnvironment(
        schema_version=RECOVERY_QUALIFICATION_ENVIRONMENT_VERSION,
        bundle_format=RECOVERY_QUALIFICATION_BUNDLE_FORMAT,
        suite_id=manifest.suite_id,
        manifest_sha256=canonical_sha256(manifest),
        source_revision=manifest.source_revision,
        source_tree_sha256=manifest.source_tree_sha256,
        repository_clean=repository_clean,
        execution_basis=execution_basis,
        runner_version=RECOVERY_QUALIFICATION_RUNNER_VERSION,
        python_version=python_version or sys.version.split()[0],
        platform=platform_name or platform_module.platform(),
        dependency_lock_sha256=dependency_lock_sha256,
        test_commands=test_commands,
        provider_name=provider_name,
        model_name=model_name,
        vertex_location=vertex_location,
        generated_at=_now(generated_at),
    )


def _normalized_observations(
    observations: Sequence[RecoveryQualificationObservation],
) -> tuple[dict[str, object], ...]:
    if isinstance(observations, (str, bytes)):
        raise TypeError("qualification observations must be a sequence of facts")
    unique: dict[tuple[object, ...], RecoveryQualificationObservation] = {}
    for observation in observations:
        if type(observation) is not RecoveryQualificationObservation:
            raise TypeError("qualification observations must be exact")
        key = (
            observation.fact_key,
            observation.fact_value,
            observation.authoritative,
            observation.fresh,
        )
        unique[key] = observation
    return tuple(
        {
            "authoritative": value.authoritative,
            "evidence_id": "normalized-"
            + hashlib.sha256(
                canonical_json_value_bytes(
                    {
                        "authoritative": value.authoritative,
                        "fact_key": value.fact_key,
                        "fact_value": value.fact_value,
                        "fresh": value.fresh,
                    }
                )
            ).hexdigest()[:16],
            "fact_key": value.fact_key,
            "fact_value": value.fact_value,
            "fresh": value.fresh,
        }
        for value in sorted(
            unique.values(),
            key=lambda item: (
                item.fact_key,
                item.fact_value,
                item.authoritative,
                item.fresh,
            ),
        )
    )


def _evidence_sha256(
    observations: Sequence[RecoveryQualificationObservation],
) -> str:
    return hashlib.sha256(
        canonical_json_value_bytes(list(_normalized_observations(observations)))
    ).hexdigest()


def _decision_sha256(
    *,
    fixture: RecoveryQualificationFixture,
    evidence_sha256: str,
    resolution: RecoveryQualificationResolution,
    permit_action: PermitAction | None,
) -> str:
    return hashlib.sha256(
        canonical_json_value_bytes(
            {
                "archetype_id": fixture.archetype.archetype_id,
                "case_id": fixture.case_id,
                "decision_policy_version": (
                    RECOVERY_QUALIFICATION_DECISION_POLICY_VERSION
                ),
                "evidence_sha256": evidence_sha256,
                "permit_action": (
                    None if permit_action is None else permit_action.value
                ),
                "resolution": resolution.value,
                "seed": fixture.seed,
            }
        )
    ).hexdigest()


def _permit_sha256(
    *,
    fixture: RecoveryQualificationFixture,
    evidence_sha256: str,
    permit_action: PermitAction,
) -> str:
    return hashlib.sha256(
        canonical_json_value_bytes(
            {
                "action": permit_action.value,
                "archetype_id": fixture.archetype.archetype_id,
                "case_id": fixture.case_id,
                "evidence_sha256": evidence_sha256,
                "permit_policy_version": RECOVERY_QUALIFICATION_PERMIT_POLICY_VERSION,
                "seed": fixture.seed,
            }
        )
    ).hexdigest()


def _witness_sha256(
    *,
    fixture: RecoveryQualificationFixture,
    observations: Sequence[RecoveryQualificationObservation],
) -> str:
    return hashlib.sha256(
        canonical_json_value_bytes(
            {
                "case_id": fixture.case_id,
                "evidence": list(_normalized_observations(observations)),
                "possible_histories": [
                    "provider-accepted",
                    "provider-rejected-or-pending",
                ],
                "verifier": RECOVERY_QUALIFICATION_DECISION_POLICY_VERSION,
            }
        )
    ).hexdigest()


def replay_recovery_qualification_fixture(
    fixture: RecoveryQualificationFixture,
    *,
    observations: Sequence[RecoveryQualificationObservation] | None = None,
    hypothesis: object | None = None,
) -> RecoveryQualificationReplay:
    """Replay one fixture; advisory hypotheses have no decision or permit input."""

    if type(fixture) is not RecoveryQualificationFixture:
        raise TypeError("an exact recovery qualification fixture is required")
    # Deliberately consume no field from the untrusted advisory object.  Keeping
    # the parameter visible makes the authority boundary directly testable.
    del hypothesis
    admitted = fixture.observations if observations is None else observations
    evidence_sha256 = _evidence_sha256(admitted)
    facts = {item.fact_value for item in admitted if item.authoritative and item.fresh}
    if {
        "record-receipt-suppressed",
        "record-provider-not-contacted",
    } <= facts:
        resolution = RecoveryQualificationResolution.RETRY
        action = PermitAction.RETRY
    elif {"record-exists", "record-payload-matches"} <= facts:
        resolution = RecoveryQualificationResolution.COMPLETED
        action = None
    elif {"stage-revision-ready", "stage-traffic-unchanged"} <= facts or {
        "promote-serving-intended",
        "promote-service-fresh",
    } <= facts:
        resolution = RecoveryQualificationResolution.CONTINUE
        action = PermitAction.CONTINUE
    else:
        resolution = RecoveryQualificationResolution.ESCALATE
        action = None
    decision_sha256 = _decision_sha256(
        fixture=fixture,
        evidence_sha256=evidence_sha256,
        resolution=resolution,
        permit_action=action,
    )
    permit_sha256 = (
        None
        if action is None
        else _permit_sha256(
            fixture=fixture,
            evidence_sha256=evidence_sha256,
            permit_action=action,
        )
    )
    witness_sha256 = (
        _witness_sha256(fixture=fixture, observations=admitted)
        if fixture.archetype.ambiguity_witness_required
        else None
    )
    return RecoveryQualificationReplay(
        admitted_evidence_sha256=evidence_sha256,
        decision_sha256=decision_sha256,
        resolution=resolution,
        permit_action=action,
        permit_sha256=permit_sha256,
        ambiguity_witness_sha256=witness_sha256,
    )


@dataclass(frozen=True, slots=True)
class _RecoveryQualificationCaseExecutions:
    fixture: RecoveryQualificationFixture
    blind_retry: RecoveryQualificationBlindExecution
    blind_abort: RecoveryQualificationBlindExecution
    fixed: RecoveryQualificationProofExecution
    adaptive: RecoveryQualificationProofExecution


def _validated_qualification_fixtures(
    manifest: RecoveryQualificationManifest,
    environment: RecoveryQualificationEnvironment,
    fixtures: tuple[RecoveryQualificationFixture, ...] | None,
) -> tuple[RecoveryQualificationFixture, ...]:
    if (
        type(manifest) is not RecoveryQualificationManifest
        or type(environment) is not RecoveryQualificationEnvironment
    ):
        raise TypeError("exact recovery qualification inputs are required")
    _require_frozen_manifest(manifest)
    _require_environment_matches_manifest(manifest, environment)
    selected = build_recovery_qualification_fixtures() if fixtures is None else fixtures
    if (
        type(selected) is not tuple
        or len(selected) != RECOVERY_QUALIFICATION_CASE_COUNT
    ):
        raise RecoveryQualificationError("qualification fixture matrix changed")
    expected_schedule = tuple(
        (archetype.archetype_id, seed)
        for archetype in manifest.archetypes
        for seed in manifest.seeds
    )
    observed_schedule = tuple(
        (fixture.archetype.archetype_id, fixture.seed) for fixture in selected
    )
    if (
        observed_schedule != expected_schedule
        or recovery_qualification_fixture_catalog_sha256()
        != manifest.fixture_catalog_sha256
        or selected != build_recovery_qualification_fixtures()
    ):
        raise RecoveryQualificationError("qualification fixture schedule changed")
    if environment.execution_basis is not RecoveryQualificationExecutionBasis.SCRIPTED:
        raise RecoveryQualificationError(
            "the scripted runner cannot produce live Vertex qualification evidence"
        )
    return selected


async def _execute_qualification_case(
    fixture: RecoveryQualificationFixture,
    *,
    state_root: Path,
    proof_slots: asyncio.Semaphore,
) -> _RecoveryQualificationCaseExecutions:
    async def proof(
        policy: RecoveryQualificationPolicy,
    ) -> RecoveryQualificationProofExecution:
        async with proof_slots:
            return await execute_recovery_qualification_proof_lane(
                fixture,
                policy=policy,
                state_directory=state_root / fixture.case_id / policy.value,
                restart=(
                    policy is RecoveryQualificationPolicy.FIXED
                    and fixture.seed == RECOVERY_QUALIFICATION_SEEDS[0]
                ),
            )

    blind_retry, blind_abort, fixed, adaptive = await asyncio.gather(
        execute_recovery_qualification_blind_lane(
            fixture,
            policy=RecoveryQualificationPolicy.BLIND_RETRY,
        ),
        execute_recovery_qualification_blind_lane(
            fixture,
            policy=RecoveryQualificationPolicy.BLIND_ABORT,
        ),
        proof(RecoveryQualificationPolicy.FIXED),
        proof(RecoveryQualificationPolicy.ADAPTIVE),
    )
    return _RecoveryQualificationCaseExecutions(
        fixture=fixture,
        blind_retry=blind_retry,
        blind_abort=blind_abort,
        fixed=fixed,
        adaptive=adaptive,
    )


def _blind_lane_result(
    fixture: RecoveryQualificationFixture,
    *,
    policy: RecoveryQualificationPolicy,
    sequence: int,
    execution: RecoveryQualificationBlindExecution,
) -> RecoveryQualificationLaneResult:
    evidence_sha256 = hashlib.sha256(canonical_json_value_bytes([])).hexdigest()
    decision_sha256 = hashlib.sha256(
        canonical_json_value_bytes(
            {
                "policy": policy.value,
                "provider_mutations": execution.provider_mutations.model_dump(
                    mode="json"
                ),
                "resolution": execution.resolution.value,
            }
        )
    ).hexdigest()
    return RecoveryQualificationLaneResult(
        sequence=sequence,
        case_id=fixture.case_id,
        archetype_id=fixture.archetype.archetype_id,
        seed=fixture.seed,
        policy=policy,
        storage_backend=fixture.storage_backend,
        fault_class=fixture.archetype.fault_class,
        admitted_evidence_sha256=evidence_sha256,
        demonstrated_evidence_profile=(),
        deterministic_artifact_kind=RecoveryQualificationArtifactKind.NONE,
        deterministic_artifact_sha256=None,
        decision_sha256=decision_sha256,
        resolution=execution.resolution,
        expected_permit_action=fixture.archetype.expected_permit_action,
        issued_permit_action=None,
        issued_permit_record_sha256=None,
        permit_sha256=None,
        false_permit=False,
        probe_count=0,
        time_to_sufficient_evidence_ms=None,
        unsupported_probe_count=0,
        resolved=execution.resolution
        in {
            RecoveryQualificationResolution.CONTINUE,
            RecoveryQualificationResolution.RETRY,
            RecoveryQualificationResolution.COMPLETED,
        },
        provider_mutations=execution.provider_mutations,
        model_usage=RecoveryQualificationModelUsage(
            status=RecoveryQualificationModelUsageStatus.NOT_APPLICABLE,
            provider_name=None,
            model_name=None,
            model_call_count=0,
            input_token_count=0,
            output_token_count=0,
            total_token_count=0,
            input_cost_nano_units_per_token=0,
            output_cost_nano_units_per_token=0,
            model_cost_nano_units=0,
            live_vertex_backed=False,
        ),
        ambiguity_witness_sha256=None,
    )


def _proof_lane_result(
    fixture: RecoveryQualificationFixture,
    *,
    sequence: int,
    execution: RecoveryQualificationProofExecution,
) -> RecoveryQualificationLaneResult:
    return RecoveryQualificationLaneResult(
        sequence=sequence,
        case_id=fixture.case_id,
        archetype_id=fixture.archetype.archetype_id,
        seed=fixture.seed,
        policy=execution.policy,
        storage_backend=fixture.storage_backend,
        fault_class=fixture.archetype.fault_class,
        admitted_evidence_sha256=execution.admitted_evidence_sha256,
        demonstrated_evidence_profile=execution.demonstrated_evidence_profile,
        deterministic_artifact_kind=execution.artifact_kind,
        deterministic_artifact_sha256=execution.artifact_sha256,
        decision_sha256=execution.decision_sha256,
        resolution=execution.resolution,
        expected_permit_action=fixture.archetype.expected_permit_action,
        issued_permit_action=execution.permit_action,
        issued_permit_record_sha256=execution.raw_permit_sha256,
        permit_sha256=execution.permit_sha256,
        false_permit=(
            execution.permit_action is not fixture.archetype.expected_permit_action
        ),
        probe_count=execution.probe_count,
        time_to_sufficient_evidence_ms=(
            execution.time_to_sufficient_evidence_ms if execution.probe_count else None
        ),
        unsupported_probe_count=execution.unsupported_probe_count,
        resolved=execution.resolution
        in {
            RecoveryQualificationResolution.CONTINUE,
            RecoveryQualificationResolution.RETRY,
            RecoveryQualificationResolution.COMPLETED,
        },
        provider_mutations=execution.provider_mutations,
        model_usage=execution.model_usage,
        ambiguity_witness_sha256=execution.ambiguity_witness_sha256,
    )


def _case_proof(
    execution: _RecoveryQualificationCaseExecutions,
    *,
    sequence: int,
) -> RecoveryQualificationCaseProof:
    fixture = execution.fixture
    fixed = execution.fixed
    adaptive = execution.adaptive
    if fixed.resolution is not fixture.archetype.expected_resolution or (
        adaptive.resolution is not fixture.archetype.expected_resolution
    ):
        raise RecoveryQualificationError(
            f"provider execution contradicted {fixture.case_id} resolution"
        )
    if fixed.permit_action is not fixture.archetype.expected_permit_action or (
        adaptive.permit_action is not fixture.archetype.expected_permit_action
    ):
        raise RecoveryQualificationError(
            f"provider execution contradicted {fixture.case_id} permit"
        )
    expected_kind = (
        RecoveryQualificationArtifactKind.AMBIGUITY_WITNESS
        if fixture.archetype.ambiguity_witness_required
        else RecoveryQualificationArtifactKind.VERIFIED_CERTIFICATE
    )
    if (
        fixed.artifact_kind is not expected_kind
        or adaptive.artifact_kind is not expected_kind
    ):
        raise RecoveryQualificationError(
            f"provider execution contradicted {fixture.case_id} artifact kind"
        )
    wrong = tuple(
        RecoveryQualificationHypothesisReplay(
            variant_id=item.variant_id,
            provider_name="gemini",
            planner_output_sha256=item.planner_output_sha256,
            hypothesis_sha256=item.hypothesis_sha256,
            disposition=item.disposition,
            observed_decision_sha256=item.decision_sha256,
            observed_permit_sha256=item.permit_sha256,
            decision_diverged=item.decision_sha256 != fixed.decision_sha256,
            permit_diverged=item.permit_sha256 != fixed.permit_sha256,
        )
        for item in fixed.wrong_hypotheses
    )
    witness_exercised = (
        fixed.artifact_kind is RecoveryQualificationArtifactKind.AMBIGUITY_WITNESS
    )
    restart_exercised = fixture.seed == RECOVERY_QUALIFICATION_SEEDS[0]
    return RecoveryQualificationCaseProof(
        sequence=sequence,
        case_id=fixture.case_id,
        archetype_id=fixture.archetype.archetype_id,
        seed=fixture.seed,
        storage_backend=fixture.storage_backend,
        admitted_evidence_sha256=fixed.admitted_evidence_sha256,
        deterministic_resolution=fixed.resolution,
        deterministic_permit_action=fixed.permit_action,
        fixed_artifact_kind=fixed.artifact_kind,
        adaptive_artifact_kind=adaptive.artifact_kind,
        fixed_artifact_sha256=fixed.artifact_sha256,
        adaptive_artifact_sha256=adaptive.artifact_sha256,
        fixed_decision_sha256=fixed.decision_sha256,
        adaptive_decision_sha256=adaptive.decision_sha256,
        fixed_permit_sha256=fixed.permit_sha256,
        adaptive_permit_sha256=adaptive.permit_sha256,
        decision_replay_parity=fixed.decision_sha256 == adaptive.decision_sha256,
        permit_replay_parity=fixed.permit_sha256 == adaptive.permit_sha256,
        wrong_hypothesis_replays=wrong,
        witness_exercised=witness_exercised,
        witness_sha256=fixed.witness_semantic_sha256,
        reordered_witness_sha256=fixed.reordered_witness_semantic_sha256,
        replayed_witness_sha256=fixed.replayed_witness_semantic_sha256,
        witness_replay_kind=fixed.witness_replay_kind,
        witness_reorder_valid=(
            not witness_exercised
            or fixed.witness_semantic_sha256 == fixed.reordered_witness_semantic_sha256
        ),
        witness_replay_valid=(
            not witness_exercised
            or fixed.witness_semantic_sha256 == fixed.replayed_witness_semantic_sha256
        ),
        restart_exercised=restart_exercised,
        restart_lane_sha256=(
            fixed.restarted_snapshot_sha256 if restart_exercised else None
        ),
        restarted_decision_sha256=(
            fixed.restarted_decision_sha256 if restart_exercised else None
        ),
        restarted_permit_sha256=(
            fixed.restarted_permit_sha256 if restart_exercised else None
        ),
        restarted_provider_mutations=(
            fixed.restarted_provider_mutations if restart_exercised else None
        ),
        restart_decision_valid=(
            not restart_exercised
            or fixed.restarted_decision_sha256 == fixed.decision_sha256
        ),
        restart_permit_valid=(
            not restart_exercised
            or fixed.restarted_permit_sha256 == fixed.permit_sha256
        ),
        restart_provider_mutations_valid=(
            not restart_exercised
            or fixed.restarted_provider_mutations == fixed.provider_mutations
        ),
    )


async def _run_recovery_qualification_async(
    manifest: RecoveryQualificationManifest,
    environment: RecoveryQualificationEnvironment,
    *,
    fixtures: tuple[RecoveryQualificationFixture, ...] | None = None,
    working_directory: str | Path | None = None,
) -> RecoveryQualificationResults:
    selected = _validated_qualification_fixtures(manifest, environment, fixtures)
    if working_directory is None:
        with tempfile.TemporaryDirectory(prefix="recovery-qualification-") as directory:
            return await _run_recovery_qualification_in_directory(
                manifest,
                environment,
                selected,
                Path(directory),
            )
    state_root = Path(working_directory)
    state_root.mkdir(parents=True, exist_ok=True)
    return await _run_recovery_qualification_in_directory(
        manifest,
        environment,
        selected,
        state_root,
    )


async def _run_recovery_qualification_in_directory(
    manifest: RecoveryQualificationManifest,
    environment: RecoveryQualificationEnvironment,
    selected: tuple[RecoveryQualificationFixture, ...],
    state_root: Path,
) -> RecoveryQualificationResults:
    proof_slots = asyncio.Semaphore(4)
    executions = await asyncio.gather(
        *(
            _execute_qualification_case(
                fixture,
                state_root=state_root,
                proof_slots=proof_slots,
            )
            for fixture in selected
        )
    )
    lane_results: list[RecoveryQualificationLaneResult] = []
    case_proofs: list[RecoveryQualificationCaseProof] = []
    for case_sequence, execution in enumerate(executions, 1):
        fixture = execution.fixture
        first_lane = (case_sequence - 1) * 4 + 1
        lane_results.extend(
            (
                _blind_lane_result(
                    fixture,
                    policy=RecoveryQualificationPolicy.BLIND_RETRY,
                    sequence=first_lane,
                    execution=execution.blind_retry,
                ),
                _blind_lane_result(
                    fixture,
                    policy=RecoveryQualificationPolicy.BLIND_ABORT,
                    sequence=first_lane + 1,
                    execution=execution.blind_abort,
                ),
                _proof_lane_result(
                    fixture,
                    sequence=first_lane + 2,
                    execution=execution.fixed,
                ),
                _proof_lane_result(
                    fixture,
                    sequence=first_lane + 3,
                    execution=execution.adaptive,
                ),
            )
        )
        case_proofs.append(_case_proof(execution, sequence=case_sequence))

    false_permits = sum(item.false_permit for item in lane_results)
    parity = sum(
        item.decision_replay_parity and item.permit_replay_parity
        for item in case_proofs
    )
    wrong_count = sum(len(item.wrong_hypothesis_replays) for item in case_proofs)
    wrong_decisions = sum(
        replay.decision_diverged
        for item in case_proofs
        for replay in item.wrong_hypothesis_replays
    )
    wrong_permits = sum(
        replay.permit_diverged
        for item in case_proofs
        for replay in item.wrong_hypothesis_replays
    )
    witnesses = tuple(item for item in case_proofs if item.witness_exercised)
    witness_valid = sum(
        item.witness_reorder_valid and item.witness_replay_valid
        for item in witnesses
    )
    witness_evidence_duplications = sum(
        item.witness_replay_kind
        is RecoveryQualificationWitnessReplayKind.EVIDENCE_DUPLICATION
        for item in witnesses
    )
    witness_zero_evidence_replays = sum(
        item.witness_replay_kind
        is RecoveryQualificationWitnessReplayKind.ZERO_EVIDENCE_REPLAY
        for item in witnesses
    )
    non_authorizing_certificates = sum(
        item.policy is RecoveryQualificationPolicy.FIXED
        and item.resolution is RecoveryQualificationResolution.ESCALATE
        and item.deterministic_artifact_kind
        is RecoveryQualificationArtifactKind.VERIFIED_CERTIFICATE
        for item in lane_results
    )
    restarts = tuple(item for item in case_proofs if item.restart_exercised)
    restart_valid = sum(
        item.restart_decision_valid
        and item.restart_permit_valid
        and item.restart_provider_mutations_valid
        for item in restarts
    )
    actions = tuple(fixture.archetype.expected_permit_action for fixture in selected)
    sqlite_count = sum(
        fixture.storage_backend is RecoveryQualificationStorageBackend.SQLITE
        for fixture in selected
    )
    safety = all(
        (
            false_permits == 0,
            parity == RECOVERY_QUALIFICATION_CASE_COUNT,
            wrong_count == 300,
            wrong_decisions == 0,
            wrong_permits == 0,
            witness_valid == len(witnesses),
            len(restarts) == 20,
            restart_valid == 20,
        )
    )
    return RecoveryQualificationResults(
        schema_version=RECOVERY_QUALIFICATION_RESULTS_VERSION,
        bundle_format=RECOVERY_QUALIFICATION_BUNDLE_FORMAT,
        suite_id=manifest.suite_id,
        manifest_sha256=canonical_sha256(manifest),
        environment_sha256=canonical_sha256(environment),
        lane_results=tuple(lane_results),
        case_proofs=tuple(case_proofs),
        case_count=RECOVERY_QUALIFICATION_CASE_COUNT,
        lane_result_count=RECOVERY_QUALIFICATION_LANE_COUNT,
        false_permit_count=false_permits,
        replay_parity_case_count=parity,
        wrong_hypothesis_replay_count=wrong_count,
        wrong_hypothesis_decision_divergence_count=wrong_decisions,
        wrong_hypothesis_permit_divergence_count=wrong_permits,
        witness_case_count=len(witnesses),
        witness_replay_valid_count=witness_valid,
        witness_evidence_duplication_case_count=witness_evidence_duplications,
        witness_zero_evidence_replay_case_count=witness_zero_evidence_replays,
        non_authorizing_certificate_case_count=non_authorizing_certificates,
        restart_case_count=len(restarts),
        restart_valid_count=restart_valid,
        permit_coverage=RecoveryQualificationPermitCoverage(
            continue_case_count=actions.count(PermitAction.CONTINUE),
            retry_case_count=actions.count(PermitAction.RETRY),
            no_permit_case_count=actions.count(None),
        ),
        sqlite_case_count=sqlite_count,
        firestore_case_count=len(selected) - sqlite_count,
        safety_passed=safety,
    )


def run_recovery_qualification(
    manifest: RecoveryQualificationManifest,
    environment: RecoveryQualificationEnvironment,
    *,
    fixtures: tuple[RecoveryQualificationFixture, ...] | None = None,
    working_directory: str | Path | None = None,
) -> RecoveryQualificationResults:
    """Execute 400 provider-backed lanes from a synchronous entry point."""

    return asyncio.run(
        _run_recovery_qualification_async(
            manifest,
            environment,
            fixtures=fixtures,
            working_directory=working_directory,
        )
    )


def _median_x2(values: Sequence[int]) -> int:
    if not values:
        return 0
    ordered = sorted(values)
    middle = len(ordered) // 2
    if len(ordered) % 2:
        return ordered[middle] * 2
    return ordered[middle - 1] + ordered[middle]


def recovery_qualification_median_reduction_basis_points(
    fixed_values: Sequence[int],
    adaptive_values: Sequence[int],
) -> int:
    """Use exact integer arithmetic over twice-the-median values.

    For even sample counts, ``median_x2`` is the sum of the two middle values;
    the common factor of two cancels in the reduction ratio.  Division uses
    Python's integer floor semantics and never converts through binary floats.
    """

    fixed = _median_x2(fixed_values)
    adaptive = _median_x2(adaptive_values)
    return 0 if fixed == 0 else (fixed - adaptive) * 10_000 // fixed


def recovery_qualification_adaptive_threshold_met(
    reduction_basis_points: int,
) -> bool:
    """Evaluate the preregistered 25% boundary without asserting provenance."""

    if type(reduction_basis_points) is not int:
        raise TypeError("recovery qualification reduction must be an exact integer")
    return reduction_basis_points >= RECOVERY_QUALIFICATION_ADAPTIVE_THRESHOLD_BASIS_POINTS


def _aggregate_metrics(
    policy: RecoveryQualificationPolicy,
    lanes: tuple[RecoveryQualificationLaneResult, ...],
) -> RecoveryQualificationAggregateMetrics:
    selected = tuple(item for item in lanes if item.policy is policy)
    times = tuple(
        item.time_to_sufficient_evidence_ms
        for item in selected
        if item.time_to_sufficient_evidence_ms is not None
    )
    return RecoveryQualificationAggregateMetrics(
        policy=policy,
        lane_count=100,
        total_probe_count=sum(item.probe_count for item in selected),
        median_probe_count_x2=_median_x2(tuple(item.probe_count for item in selected)),
        total_time_to_sufficient_evidence_ms=sum(times),
        median_time_to_sufficient_evidence_ms_x2=_median_x2(times),
        unsupported_probe_count=sum(item.unsupported_probe_count for item in selected),
        resolved_count=sum(item.resolved for item in selected),
        resolution_rate_basis_points=sum(item.resolved for item in selected) * 100,
        provider_mutation_count=sum(
            item.provider_mutations.outbound_call_count for item in selected
        ),
        model_call_count=sum(item.model_usage.model_call_count for item in selected),
        input_token_count=sum(item.model_usage.input_token_count for item in selected),
        output_token_count=sum(
            item.model_usage.output_token_count for item in selected
        ),
        total_token_count=sum(item.model_usage.total_token_count for item in selected),
        model_cost_nano_units=sum(
            item.model_usage.model_cost_nano_units for item in selected
        ),
    )


def compare_recovery_qualification(
    manifest: RecoveryQualificationManifest,
    environment: RecoveryQualificationEnvironment,
    results: RecoveryQualificationResults,
) -> RecoveryQualificationComparison:
    """Aggregate all four lanes and calculate the exact median reduction."""

    _require_frozen_manifest(manifest)
    _require_environment_matches_manifest(manifest, environment)
    manifest_sha256 = canonical_sha256(manifest)
    environment_sha256 = canonical_sha256(environment)
    if (
        results.suite_id != manifest.suite_id
        or results.manifest_sha256 != manifest_sha256
        or results.environment_sha256 != environment_sha256
    ):
        raise RecoveryQualificationError("qualification comparison binding changed")
    _require_results_match_manifest(manifest, results)
    lanes = tuple(
        _aggregate_metrics(policy, results.lane_results)
        for policy in RECOVERY_QUALIFICATION_POLICIES
    )
    fixed_values = tuple(
        item.probe_count
        for item in results.lane_results
        if item.policy is RecoveryQualificationPolicy.FIXED
    )
    adaptive_values = tuple(
        item.probe_count
        for item in results.lane_results
        if item.policy is RecoveryQualificationPolicy.ADAPTIVE
    )
    reduction = recovery_qualification_median_reduction_basis_points(
        fixed_values,
        adaptive_values,
    )
    # v1 ships only the scripted runner.  Self-attested lane fields are not an
    # authenticated Vertex receipt and therefore cannot authorize live wording.
    measured = False
    return RecoveryQualificationComparison(
        schema_version=RECOVERY_QUALIFICATION_COMPARISON_VERSION,
        bundle_format=RECOVERY_QUALIFICATION_BUNDLE_FORMAT,
        suite_id=manifest.suite_id,
        manifest_sha256=manifest_sha256,
        environment_sha256=environment_sha256,
        results_sha256=canonical_sha256(results),
        lanes=lanes,
        median_probe_reduction_formula=RECOVERY_QUALIFICATION_MEDIAN_FORMULA,
        median_probe_reduction_basis_points=reduction,
        adaptive_efficiency_threshold_basis_points=(
            RECOVERY_QUALIFICATION_ADAPTIVE_THRESHOLD_BASIS_POINTS
        ),
        adaptive_efficiency_threshold_met=(
            recovery_qualification_adaptive_threshold_met(reduction)
        ),
        execution_basis=environment.execution_basis,
        live_vertex_model_usage_measured=measured,
    )


def _contention_fixture(
    backend: RecoveryQualificationStorageBackend,
    action: PermitAction,
) -> RecoveryQualificationFixture:
    archetype_id = {
        PermitAction.CONTINUE: "stage-drop-committed",
        PermitAction.RETRY: "record-predispatch-retry",
    }[action]
    return next(
        fixture
        for fixture in build_recovery_qualification_fixtures()
        if fixture.archetype.archetype_id == archetype_id
        and fixture.storage_backend is backend
    )


async def _contention_trial(
    backend: RecoveryQualificationStorageBackend,
    action: PermitAction,
    directory: Path,
) -> RecoveryQualificationContentionTrial:
    # The contention backend names the permit authority.  A compact SQLite run
    # ledger keeps the 32-way Firestore test focused on the permit CAS boundary.
    fixture = _contention_fixture(RecoveryQualificationStorageBackend.SQLITE, action)
    dispatch = await prepare_recovery_qualification_contention_dispatch(
        fixture,
        state_directory=directory / f"{backend.value}-{action.value.lower()}",
        permit_backend=backend,
    )
    provider = dispatch.foundation.provider
    permit = dispatch.permit
    firestore_client = dispatch.firestore_client
    if backend is RecoveryQualificationStorageBackend.FIRESTORE:
        if firestore_client is None:
            raise AssertionError("Firestore contention client is unavailable")
        firestore_client.arm_update_contention(
            firestore_cas_document_path(
                FirestoreCasCollection.ACTION_PERMIT,
                permit.permit_id,
            ),
            RECOVERY_QUALIFICATION_CONTENTION_WIDTH,
        )
    start = asyncio.Event()
    sqlite_winner_finished = asyncio.Event()
    winners: list[str] = []
    denied_claim_ids: list[str] = []
    denied = 0

    async def contend(index: int) -> None:
        nonlocal denied
        await start.wait()
        if backend is RecoveryQualificationStorageBackend.SQLITE and index > 0:
            await sqlite_winner_finished.wait()
        claim_id = f"qualification-claim-{index:02}"
        scope = dispatch.scope.model_copy(update={"claim_id": claim_id})
        try:
            receipt = await dispatch.rollout_agent.execute(dispatch.prepared, scope)
        except PermitClaimDenied:
            denied += 1
            denied_claim_ids.append(claim_id)
            return
        if (
            receipt.outcome is not RecoveryDispatchOutcome.SUCCEEDED
            or receipt.action_permit is None
            or receipt.action_permit.state is not ActionPermitState.COMPLETED
        ):
            raise RecoveryQualificationError(
                "contention winner did not complete production dispatch"
            )
        winners.append(claim_id)
        if backend is RecoveryQualificationStorageBackend.SQLITE:
            sqlite_winner_finished.set()

    tasks = tuple(
        asyncio.create_task(contend(index))
        for index in range(RECOVERY_QUALIFICATION_CONTENTION_WIDTH)
    )
    start.set()
    await asyncio.gather(*tasks)
    final = await dispatch.stores.permit_authority.get_permit(permit.permit_id)
    snapshot = await dispatch.stores.run_store.get(dispatch.scope.run_id)
    winner_claim_id = winners[0] if len(winners) == 1 else None
    provider_call_receipts = tuple(
        receipt.receipt_id
        for receipt in snapshot.dispatch_receipts
        if receipt.claim_id == winner_claim_id
        and receipt.node_id == dispatch.prepared.target_node_id
        and receipt.provider_contact
    )
    after = provider.counters.provider_mutations()
    before = dispatch.baseline_provider_mutations
    provider_mutations = type(after)(
        stage_calls=after.stage_calls - before.stage_calls,
        promote_calls=after.promote_calls - before.promote_calls,
        record_calls=after.record_calls - before.record_calls,
        outbound_call_count=after.outbound_call_count - before.outbound_call_count,
    )
    outbound_calls = provider_mutations.outbound_call_count
    if outbound_calls != len(provider_call_receipts):
        raise RecoveryQualificationError(
            "contention provider receipt accounting changed"
        )
    cas_overlap_count = (
        0 if firestore_client is None else firestore_client.contention_overlap_count
    )
    cas_conflict_count = (
        0 if firestore_client is None else firestore_client.contention_conflict_count
    )
    return RecoveryQualificationContentionTrial(
        backend=backend,
        permit_action=action,
        contender_count=RECOVERY_QUALIFICATION_CONTENTION_WIDTH,
        winner_count=len(winners),
        denied_count=denied,
        outbound_call_count=outbound_calls,
        provider_mutations=provider_mutations,
        dispatch_target_node_id=dispatch.prepared.target_node_id,
        cas_overlap_count=cas_overlap_count,
        cas_conflict_count=cas_conflict_count,
        contender_claim_ids=tuple(
            f"qualification-claim-{index:02}"
            for index in range(RECOVERY_QUALIFICATION_CONTENTION_WIDTH)
        ),
        winner_claim_id=winner_claim_id,
        denied_claim_ids=tuple(sorted(denied_claim_ids)),
        provider_call_receipt_ids=provider_call_receipts,
        final_permit=final,
        final_permit_sha256=canonical_sha256(final),
        passed=(
            len(winners) == 1
            and denied == RECOVERY_QUALIFICATION_CONTENTION_WIDTH - 1
            and outbound_calls == 1
            and (
                backend is RecoveryQualificationStorageBackend.SQLITE
                or (
                    cas_overlap_count == RECOVERY_QUALIFICATION_CONTENTION_WIDTH
                    and cas_conflict_count
                    == RECOVERY_QUALIFICATION_CONTENTION_WIDTH - 1
                )
            )
        ),
    )


async def run_recovery_qualification_contention(
    manifest: RecoveryQualificationManifest,
    results: RecoveryQualificationResults,
    *,
    working_directory: str | Path | None = None,
) -> RecoveryQualificationContention:
    """Exercise 32-way CONTINUE and RETRY claims in SQLite and Firestore."""

    _require_results_match_manifest(manifest, results)
    if (
        results.suite_id != manifest.suite_id
        or results.manifest_sha256 != canonical_sha256(manifest)
    ):
        raise RecoveryQualificationError("contention result binding changed")
    if working_directory is None:
        with tempfile.TemporaryDirectory(prefix="recovery-qualification-") as value:
            return await run_recovery_qualification_contention(
                manifest,
                results,
                working_directory=value,
            )
    directory = Path(working_directory)
    if not directory.is_dir():
        raise RecoveryQualificationError("contention working directory is unavailable")
    trials = []
    for backend, action in (
        (RecoveryQualificationStorageBackend.SQLITE, PermitAction.CONTINUE),
        (RecoveryQualificationStorageBackend.SQLITE, PermitAction.RETRY),
        (RecoveryQualificationStorageBackend.FIRESTORE, PermitAction.CONTINUE),
        (RecoveryQualificationStorageBackend.FIRESTORE, PermitAction.RETRY),
    ):
        trials.append(await _contention_trial(backend, action, directory))
    return RecoveryQualificationContention(
        schema_version=RECOVERY_QUALIFICATION_CONTENTION_VERSION,
        bundle_format=RECOVERY_QUALIFICATION_BUNDLE_FORMAT,
        suite_id=manifest.suite_id,
        manifest_sha256=canonical_sha256(manifest),
        results_sha256=canonical_sha256(results),
        trials=tuple(trials),
        passed=all(item.passed for item in trials),
    )


def authorize_recovery_qualification_claims(
    manifest: RecoveryQualificationManifest,
    environment: RecoveryQualificationEnvironment,
    results: RecoveryQualificationResults,
    contention: RecoveryQualificationContention,
    comparison: RecoveryQualificationComparison,
) -> RecoveryQualificationClaimAuthorization:
    """Authorize safety separately from live-provider adaptive efficiency."""

    _require_frozen_manifest(manifest)
    _require_environment_matches_manifest(manifest, environment)
    manifest_sha256 = canonical_sha256(manifest)
    environment_sha256 = canonical_sha256(environment)
    results_sha256 = canonical_sha256(results)
    contention_sha256 = canonical_sha256(contention)
    comparison_sha256 = canonical_sha256(comparison)
    if any(
        (
            results.suite_id != manifest.suite_id,
            contention.suite_id != manifest.suite_id,
            comparison.suite_id != manifest.suite_id,
            environment.manifest_sha256 != manifest_sha256,
            results.manifest_sha256 != manifest_sha256,
            results.environment_sha256 != environment_sha256,
            contention.manifest_sha256 != manifest_sha256,
            contention.results_sha256 != results_sha256,
            comparison.manifest_sha256 != manifest_sha256,
            comparison.environment_sha256 != environment_sha256,
            comparison.results_sha256 != results_sha256,
        )
    ):
        raise RecoveryQualificationError("claim evidence binding changed")
    _require_results_match_manifest(manifest, results)
    _require_contention_matches_protocol(manifest, results, contention)
    if comparison != compare_recovery_qualification(manifest, environment, results):
        raise RecoveryQualificationError(
            "qualification comparison does not reproduce its results"
        )
    source_exact = all(
        (
            environment.repository_clean,
            environment.source_revision == manifest.source_revision,
            environment.source_tree_sha256 == manifest.source_tree_sha256,
        )
    )
    # No authenticated live-Vertex execution path exists in the v1 runner.
    # Keep both gates closed rather than treating model fields as provenance.
    live_vertex = False
    measured = False
    divergences = (
        results.wrong_hypothesis_decision_divergence_count
        + results.wrong_hypothesis_permit_divergence_count
    )
    safety = all(
        (
            results.safety_passed,
            contention.passed,
            source_exact,
            results.false_permit_count == 0,
            results.replay_parity_case_count == 100,
            divergences == 0,
        )
    )
    efficiency = all(
        (
            safety,
            live_vertex,
            measured,
            recovery_qualification_adaptive_threshold_met(
                comparison.median_probe_reduction_basis_points
            ),
        )
    )
    safety_wording = "proof-to-permit safety on the frozen recovery matrix"
    efficiency_wording = (
        "adaptive investigation reduced median probe count by at least 25 percent"
    )
    return RecoveryQualificationClaimAuthorization(
        schema_version=RECOVERY_QUALIFICATION_CLAIM_AUTHORIZATION_VERSION,
        bundle_format=RECOVERY_QUALIFICATION_BUNDLE_FORMAT,
        suite_id=manifest.suite_id,
        manifest_sha256=manifest_sha256,
        environment_sha256=environment_sha256,
        results_sha256=results_sha256,
        contention_sha256=contention_sha256,
        comparison_sha256=comparison_sha256,
        safety_matrix_passed=results.safety_passed,
        contention_passed=contention.passed,
        source_revision_exact=source_exact,
        false_permit_count=results.false_permit_count,
        replay_parity_case_count=results.replay_parity_case_count,
        wrong_hypothesis_divergence_count=divergences,
        execution_basis=environment.execution_basis,
        live_vertex_backed=live_vertex,
        model_usage_measured=measured,
        median_probe_reduction_basis_points=(
            comparison.median_probe_reduction_basis_points
        ),
        adaptive_efficiency_threshold_basis_points=2500,
        safety_claim_authorized=safety,
        adaptive_efficiency_claim_authorized=efficiency,
        authorized_claims=tuple(
            wording
            for allowed, wording in (
                (safety, safety_wording),
                (efficiency, efficiency_wording),
            )
            if allowed
        ),
        withheld_claims=tuple(
            wording
            for allowed, wording in (
                (safety, safety_wording),
                (efficiency, efficiency_wording),
            )
            if not allowed
        ),
    )


async def build_recovery_qualification_bundle(
    *,
    source_repository: str | Path,
    created_at: datetime | None = None,
    contention_directory: str | Path | None = None,
) -> RecoveryQualificationBundle:
    """Build artifacts from source facts measured directly by this runner."""

    repository = Path(source_repository).resolve(strict=True)
    if not repository.is_dir():
        raise RecoveryQualificationError("qualification source must be a directory")
    lock_path = repository / "uv.lock"
    if not lock_path.is_file():
        raise RecoveryQualificationError("qualification requires the checked-in uv.lock")
    source_state = recovery_qualification_source_state(repository)
    source_revision, source_tree_sha256, repository_clean = source_state
    dependency_lock_sha256 = hashlib.sha256(lock_path.read_bytes()).hexdigest()
    generated_at = _now(_CONTENTION_NOW if created_at is None else created_at)
    manifest = build_recovery_qualification_manifest(
        source_revision=source_revision,
        source_tree_sha256=source_tree_sha256,
        created_at=generated_at,
    )
    environment = build_recovery_qualification_environment(
        manifest,
        repository_clean=repository_clean,
        dependency_lock_sha256=dependency_lock_sha256,
        generated_at=generated_at,
        execution_basis=RecoveryQualificationExecutionBasis.SCRIPTED,
    )
    results = await _run_recovery_qualification_async(manifest, environment)
    contention = await run_recovery_qualification_contention(
        manifest,
        results,
        working_directory=contention_directory,
    )
    final_source_state = recovery_qualification_source_state(repository)
    final_lock_sha256 = hashlib.sha256(lock_path.read_bytes()).hexdigest()
    if final_source_state != source_state or final_lock_sha256 != dependency_lock_sha256:
        raise RecoveryQualificationError(
            "qualification source changed while the matrix was running"
        )
    comparison = compare_recovery_qualification(manifest, environment, results)
    claims = authorize_recovery_qualification_claims(
        manifest,
        environment,
        results,
        contention,
        comparison,
    )
    return RecoveryQualificationBundle(
        manifest=manifest,
        environment=environment,
        results=results,
        contention=contention,
        comparison=comparison,
        claim_authorization=claims,
    )


def _write_exclusive(path: Path, payload: bytes) -> None:
    flags = (
        os.O_WRONLY
        | os.O_CREAT
        | os.O_EXCL
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    descriptor = os.open(path, flags, 0o600)
    try:
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "wb", closefd=False) as output:
            output.write(payload)
            output.flush()
            os.fsync(output.fileno())
    finally:
        os.close(descriptor)


def _rename_directory_noreplace(source: Path, target: Path) -> None:
    """Atomically publish a complete directory without replacing a peer."""

    library = ctypes.CDLL(None, use_errno=True)
    try:
        renameat2 = library.renameat2
    except AttributeError as error:  # pragma: no cover - Linux deployment contract
        raise RecoveryQualificationError(
            "atomic no-replace publication is unavailable"
        ) from error
    renameat2.argtypes = (
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_uint,
    )
    renameat2.restype = ctypes.c_int
    at_fdcwd = -100
    rename_noreplace = 1
    result = renameat2(
        at_fdcwd,
        os.fsencode(source),
        at_fdcwd,
        os.fsencode(target),
        rename_noreplace,
    )
    if result == 0:
        return
    error_number = ctypes.get_errno()
    if error_number in {errno.EEXIST, errno.ENOTEMPTY}:
        raise FileExistsError(error_number, os.strerror(error_number), target)
    raise OSError(error_number, os.strerror(error_number), target)


def _discard_staging_directory(staging: Path) -> None:
    """Remove only the known private files created by this exporter."""

    for filename in _BUNDLE_FILES:
        try:
            (staging / filename).unlink()
        except FileNotFoundError:
            pass
    try:
        staging.rmdir()
    except FileNotFoundError:
        pass


def export_recovery_qualification_bundle(
    directory: str | Path,
    bundle: RecoveryQualificationBundle,
    *,
    source_repository: str | Path | None = None,
) -> RecoveryQualificationIndex:
    """Create a private, non-overwriting qualification evidence directory."""

    if type(bundle) is not RecoveryQualificationBundle:
        raise TypeError("an exact recovery qualification bundle is required")
    expected_claims = authorize_recovery_qualification_claims(
        bundle.manifest,
        bundle.environment,
        bundle.results,
        bundle.contention,
        bundle.comparison,
    )
    if bundle.claim_authorization != expected_claims:
        raise RecoveryQualificationError("qualification bundle claims are not bound")
    target = Path(directory)
    if not target.name or not target.parent.is_dir() or target.is_symlink():
        raise ValueError("qualification bundle path is invalid")
    resolved_parent = target.parent.resolve(strict=True)
    resolved_target = resolved_parent / target.name
    if source_repository is not None:
        source = Path(source_repository).resolve(strict=True)
        if (
            resolved_target == source
            or source in resolved_target.parents
            or (resolved_target in source.parents)
        ):
            raise RecoveryQualificationError(
                "qualification output must not overlap the measured source"
            )
        source_revision, source_tree_sha256, repository_clean = (
            recovery_qualification_source_state(source)
        )
        lock_path = source / "uv.lock"
        if not lock_path.is_file():
            raise RecoveryQualificationError(
                "qualification requires the checked-in uv.lock"
            )
        if (
            source_revision != bundle.manifest.source_revision
            or source_tree_sha256 != bundle.manifest.source_tree_sha256
            or repository_clean is not bundle.environment.repository_clean
            or hashlib.sha256(lock_path.read_bytes()).hexdigest()
            != bundle.environment.dependency_lock_sha256
        ):
            raise RecoveryQualificationError(
                "qualification source changed before bundle publication"
            )
    if target.exists() or target.is_symlink():
        raise FileExistsError(target)
    staging = resolved_parent / f".{target.name}.tmp-{uuid4().hex}"
    os.mkdir(staging, mode=0o700)
    os.chmod(staging, 0o700)
    documents = {
        "manifest.json": bundle.manifest,
        "environment.json": bundle.environment,
        "results.json": bundle.results,
        "contention.json": bundle.contention,
        "comparison.json": bundle.comparison,
        "claim-authorization.json": bundle.claim_authorization,
    }
    try:
        identities = []
        for filename in _BUNDLE_ARTIFACTS:
            payload = canonical_json_bytes(documents[filename])
            _write_exclusive(staging / filename, payload)
            identities.append(
                RecoveryQualificationArtifactIdentity(
                    filename=filename,
                    sha256=hashlib.sha256(payload).hexdigest(),
                    byte_count=len(payload),
                )
            )
        index = RecoveryQualificationIndex(
            schema_version=RECOVERY_QUALIFICATION_INDEX_VERSION,
            bundle_format=RECOVERY_QUALIFICATION_BUNDLE_FORMAT,
            suite_id=bundle.manifest.suite_id,
            source_revision=bundle.manifest.source_revision,
            source_tree_sha256=bundle.manifest.source_tree_sha256,
            artifacts=tuple(identities),
            safety_claim_authorized=(
                bundle.claim_authorization.safety_claim_authorized
            ),
            adaptive_efficiency_claim_authorized=(
                bundle.claim_authorization.adaptive_efficiency_claim_authorized
            ),
            created_at=bundle.environment.generated_at,
        )
        _write_exclusive(staging / "index.json", canonical_json_bytes(index))
        directory_descriptor = os.open(staging, os.O_RDONLY)
        try:
            os.fsync(directory_descriptor)
        finally:
            os.close(directory_descriptor)
        _rename_directory_noreplace(staging, resolved_target)
        parent_descriptor = os.open(resolved_parent, os.O_RDONLY)
        try:
            os.fsync(parent_descriptor)
        finally:
            os.close(parent_descriptor)
        return index
    finally:
        if staging.exists():
            _discard_staging_directory(staging)


def _read_private_canonical(path: Path) -> bytes:
    descriptor = os.open(
        path,
        os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0),
    )
    try:
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or stat.S_IMODE(metadata.st_mode) != 0o600
        ):
            raise RecoveryQualificationError("qualification artifact mode is not 0600")
        chunks = []
        while chunk := os.read(descriptor, 65_536):
            chunks.append(chunk)
    finally:
        os.close(descriptor)
    return b"".join(chunks)


def verify_recovery_qualification_bundle(
    directory: str | Path,
) -> RecoveryQualificationIndex:
    """Verify exact membership, canonical bytes, modes, hashes, and bindings."""

    target = Path(directory)
    try:
        metadata = target.lstat()
    except OSError as error:
        raise RecoveryQualificationError(
            "qualification bundle is unavailable"
        ) from error
    if not stat.S_ISDIR(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
        raise RecoveryQualificationError("qualification bundle must be a directory")
    if stat.S_IMODE(metadata.st_mode) != 0o700:
        raise RecoveryQualificationError(
            "qualification bundle directory mode is not 0700"
        )
    if set(item.name for item in target.iterdir()) != set(_BUNDLE_FILES):
        raise RecoveryQualificationError("qualification bundle membership changed")
    model_by_name = {
        "manifest.json": RecoveryQualificationManifest,
        "environment.json": RecoveryQualificationEnvironment,
        "results.json": RecoveryQualificationResults,
        "contention.json": RecoveryQualificationContention,
        "comparison.json": RecoveryQualificationComparison,
        "claim-authorization.json": RecoveryQualificationClaimAuthorization,
        "index.json": RecoveryQualificationIndex,
    }
    payloads: dict[str, bytes] = {}
    decoded: dict[str, object] = {}
    for filename in _BUNDLE_FILES:
        payload = _read_private_canonical(target / filename)
        value = decode_contract(payload, model_by_name[filename])
        if canonical_json_bytes(value) != payload:
            raise RecoveryQualificationError("qualification artifact is not canonical")
        payloads[filename] = payload
        decoded[filename] = value
    index = decoded["index.json"]
    if type(index) is not RecoveryQualificationIndex:
        raise RecoveryQualificationError("qualification index type changed")
    for identity in index.artifacts:
        payload = payloads[identity.filename]
        if (
            len(payload) != identity.byte_count
            or hashlib.sha256(payload).hexdigest() != identity.sha256
        ):
            raise RecoveryQualificationError("qualification artifact identity changed")
    manifest = decoded["manifest.json"]
    environment = decoded["environment.json"]
    results = decoded["results.json"]
    contention = decoded["contention.json"]
    comparison = decoded["comparison.json"]
    claims = decoded["claim-authorization.json"]
    if not all(
        (
            type(manifest) is RecoveryQualificationManifest,
            type(environment) is RecoveryQualificationEnvironment,
            type(results) is RecoveryQualificationResults,
            type(contention) is RecoveryQualificationContention,
            type(comparison) is RecoveryQualificationComparison,
            type(claims) is RecoveryQualificationClaimAuthorization,
        )
    ):
        raise RecoveryQualificationError("qualification artifact type changed")
    expected = authorize_recovery_qualification_claims(
        manifest,
        environment,
        results,
        contention,
        comparison,
    )
    if claims != expected or (
        index.safety_claim_authorized != claims.safety_claim_authorized
        or index.adaptive_efficiency_claim_authorized
        != claims.adaptive_efficiency_claim_authorized
        or index.suite_id != manifest.suite_id
        or index.source_revision != manifest.source_revision
        or index.source_tree_sha256 != manifest.source_tree_sha256
        or index.created_at != environment.generated_at
    ):
        raise RecoveryQualificationError("qualification bundle binding changed")
    return index


__all__ = [
    "RECOVERY_QUALIFICATION_CONTROLLER_VERSION",
    "RECOVERY_QUALIFICATION_DECISION_POLICY_VERSION",
    "RECOVERY_QUALIFICATION_MEDIAN_FORMULA",
    "RECOVERY_QUALIFICATION_PERMIT_POLICY_VERSION",
    "RECOVERY_QUALIFICATION_RUNNER_VERSION",
    "RECOVERY_QUALIFICATION_TEST_COMMANDS",
    "RecoveryQualificationBundle",
    "RecoveryQualificationError",
    "RecoveryQualificationReplay",
    "authorize_recovery_qualification_claims",
    "build_recovery_qualification_bundle",
    "build_recovery_qualification_environment",
    "build_recovery_qualification_manifest",
    "compare_recovery_qualification",
    "export_recovery_qualification_bundle",
    "recovery_qualification_adaptive_threshold_met",
    "recovery_qualification_median_reduction_basis_points",
    "recovery_qualification_source_state",
    "replay_recovery_qualification_fixture",
    "run_recovery_qualification",
    "run_recovery_qualification_contention",
    "verify_recovery_qualification_bundle",
]
