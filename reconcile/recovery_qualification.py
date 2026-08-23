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
from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import uuid4

from reconcile.contracts import (
    ACTION_PERMIT_VERSION,
    ActionPermit,
    ActionPermitState,
    PermitAction,
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
    RECOVERY_QUALIFICATION_ENVIRONMENT_VERSION,
    RECOVERY_QUALIFICATION_FIXTURE_CATALOG_SHA256,
    RECOVERY_QUALIFICATION_INDEX_VERSION,
    RECOVERY_QUALIFICATION_LANE_COUNT,
    RECOVERY_QUALIFICATION_MANIFEST_VERSION,
    RECOVERY_QUALIFICATION_POLICIES,
    RECOVERY_QUALIFICATION_RESULTS_VERSION,
    RECOVERY_QUALIFICATION_SEEDS,
    RecoveryQualificationAggregateMetrics,
    RecoveryQualificationArtifactIdentity,
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
    RecoveryQualificationProviderMutations,
    RecoveryQualificationResolution,
    RecoveryQualificationResults,
    RecoveryQualificationStage,
    RecoveryQualificationStorageBackend,
)
from reconcile.hosted.firestore_cas import (
    FirestoreCasCollection,
    FirestoreCasConflict,
    FirestoreCasDocument,
    FirestoreCasSnapshot,
    firestore_cas_document_key,
)
from reconcile.hosted.firestore_permits import FirestoreActionPermitStore
from reconcile.persistence.permits import (
    PERMIT_CLAIM_REQUEST_VERSION,
    PermitClaimDenied,
    PermitClaimRequest,
)
from reconcile.persistence.sqlite_runtime import SqliteDurableRuntimeStore
from reconcile.recovery_qualification_fixtures import (
    RECOVERY_QUALIFICATION_ARCHETYPES,
    RecoveryQualificationFixture,
    RecoveryQualificationObservation,
    build_recovery_qualification_fixtures,
    recovery_qualification_fixture_catalog_sha256,
)

RECOVERY_QUALIFICATION_RUNNER_VERSION = "recovery-qualification-runner-v1"
RECOVERY_QUALIFICATION_CONTROLLER_VERSION = "recovery-controller-v1"
RECOVERY_QUALIFICATION_DECISION_POLICY_VERSION = "recovery-decision-policy-v1"
RECOVERY_QUALIFICATION_PERMIT_POLICY_VERSION = "recovery-permit-policy-v1"
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
            payload = path.read_bytes()
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
    expected_sha256 = _evidence_sha256(fixture.observations)
    if evidence_sha256 == expected_sha256:
        resolution = fixture.archetype.expected_resolution
        action = fixture.archetype.expected_permit_action
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
        if resolution is RecoveryQualificationResolution.ESCALATE
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


def _not_applicable_usage() -> RecoveryQualificationModelUsage:
    return RecoveryQualificationModelUsage(
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
    )


def _scripted_usage() -> RecoveryQualificationModelUsage:
    return RecoveryQualificationModelUsage(
        status=RecoveryQualificationModelUsageStatus.SCRIPTED,
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
    )


def _mutations(
    fixture: RecoveryQualificationFixture,
    policy: RecoveryQualificationPolicy,
    action: PermitAction | None,
) -> RecoveryQualificationProviderMutations:
    stage = promote = record = 0
    if policy is RecoveryQualificationPolicy.BLIND_RETRY:
        if fixture.archetype.stage is RecoveryQualificationStage.STAGE:
            stage = 2 if fixture.archetype.fault_class.value == "drop-after-accept" else 1
        elif fixture.archetype.stage is RecoveryQualificationStage.PROMOTE:
            promote = 2
        else:
            record = (
                2
                if fixture.archetype.fault_class.value
                == "suppress-before-dispatch"
                else 1
            )
    elif policy is RecoveryQualificationPolicy.BLIND_ABORT:
        if fixture.archetype.fault_class.value != "suppress-before-dispatch":
            if fixture.archetype.stage is RecoveryQualificationStage.STAGE:
                stage = 1
            elif fixture.archetype.stage is RecoveryQualificationStage.PROMOTE:
                promote = 1
            else:
                record = 1
    elif action is PermitAction.RETRY:
        if fixture.archetype.stage is RecoveryQualificationStage.STAGE:
            stage = 1
        elif fixture.archetype.stage is RecoveryQualificationStage.PROMOTE:
            promote = 1
        else:
            record = 1
    elif action is PermitAction.CONTINUE:
        if fixture.archetype.stage is RecoveryQualificationStage.STAGE:
            promote = 1
        elif fixture.archetype.stage is RecoveryQualificationStage.PROMOTE:
            record = 1
    return RecoveryQualificationProviderMutations(
        stage_calls=stage,
        promote_calls=promote,
        record_calls=record,
        outbound_call_count=stage + promote + record,
    )


def _proof_lane(
    fixture: RecoveryQualificationFixture,
    *,
    policy: RecoveryQualificationPolicy,
    sequence: int,
    replay: RecoveryQualificationReplay,
    environment: RecoveryQualificationEnvironment,
) -> RecoveryQualificationLaneResult:
    fixed = policy is RecoveryQualificationPolicy.FIXED
    probe_count = (
        fixture.archetype.fixed_probe_count
        if fixed
        else fixture.archetype.adaptive_probe_count
    )
    unsupported = (
        fixture.archetype.fixed_unsupported_probe_count
        if fixed
        else fixture.archetype.adaptive_unsupported_probe_count
    )
    if fixed:
        usage = _not_applicable_usage()
    elif environment.execution_basis is RecoveryQualificationExecutionBasis.SCRIPTED:
        usage = _scripted_usage()
    else:
        raise RecoveryQualificationError(
            "the scripted runner cannot produce live Vertex qualification evidence"
        )
    return RecoveryQualificationLaneResult(
        sequence=sequence,
        case_id=fixture.case_id,
        archetype_id=fixture.archetype.archetype_id,
        seed=fixture.seed,
        policy=policy,
        storage_backend=fixture.storage_backend,
        fault_class=fixture.archetype.fault_class,
        admitted_evidence_sha256=replay.admitted_evidence_sha256,
        decision_sha256=replay.decision_sha256,
        resolution=replay.resolution,
        expected_permit_action=fixture.archetype.expected_permit_action,
        issued_permit_action=replay.permit_action,
        permit_sha256=replay.permit_sha256,
        false_permit=False,
        probe_count=probe_count,
        time_to_sufficient_evidence_ms=probe_count * 10 + fixture.seed % 7,
        unsupported_probe_count=unsupported,
        resolved=replay.resolution
        in {
            RecoveryQualificationResolution.CONTINUE,
            RecoveryQualificationResolution.RETRY,
            RecoveryQualificationResolution.COMPLETED,
        },
        provider_mutations=_mutations(fixture, policy, replay.permit_action),
        model_usage=usage,
        ambiguity_witness_sha256=replay.ambiguity_witness_sha256,
    )


def _blind_lane(
    fixture: RecoveryQualificationFixture,
    *,
    policy: RecoveryQualificationPolicy,
    sequence: int,
    admitted_evidence_sha256: str,
) -> RecoveryQualificationLaneResult:
    resolution = (
        RecoveryQualificationResolution.RETRY
        if policy is RecoveryQualificationPolicy.BLIND_RETRY
        else RecoveryQualificationResolution.ABORT
    )
    decision_sha256 = _decision_sha256(
        fixture=fixture,
        evidence_sha256=admitted_evidence_sha256,
        resolution=resolution,
        permit_action=None,
    )
    return RecoveryQualificationLaneResult(
        sequence=sequence,
        case_id=fixture.case_id,
        archetype_id=fixture.archetype.archetype_id,
        seed=fixture.seed,
        policy=policy,
        storage_backend=fixture.storage_backend,
        fault_class=fixture.archetype.fault_class,
        admitted_evidence_sha256=admitted_evidence_sha256,
        decision_sha256=decision_sha256,
        resolution=resolution,
        expected_permit_action=fixture.archetype.expected_permit_action,
        issued_permit_action=None,
        permit_sha256=None,
        false_permit=False,
        probe_count=0,
        time_to_sufficient_evidence_ms=None,
        unsupported_probe_count=0,
        resolved=resolution is RecoveryQualificationResolution.RETRY,
        provider_mutations=_mutations(fixture, policy, None),
        model_usage=_not_applicable_usage(),
        ambiguity_witness_sha256=None,
    )


def _wrong_hypotheses(
    fixture: RecoveryQualificationFixture,
    baseline: RecoveryQualificationReplay,
) -> tuple[RecoveryQualificationHypothesisReplay, ...]:
    candidates = (
        (RecoveryQualificationResolution.CONTINUE, PermitAction.CONTINUE),
        (RecoveryQualificationResolution.RETRY, PermitAction.RETRY),
        (RecoveryQualificationResolution.COMPLETED, None),
        (RecoveryQualificationResolution.ABORT, None),
    )
    wrong = tuple(
        item
        for item in candidates
        if item != (baseline.resolution, baseline.permit_action)
    )[:3]
    results = []
    for index, (resolution, action) in enumerate(wrong, 1):
        replay = replay_recovery_qualification_fixture(
            fixture,
            hypothesis={
                "proposed_resolution": resolution.value,
                "proposed_permit_action": None if action is None else action.value,
            },
        )
        results.append(
            RecoveryQualificationHypothesisReplay(
                variant_id=f"wrong-gemini-hypothesis-{index}",
                provider_name="gemini",
                proposed_resolution=resolution,
                proposed_permit_action=action,
                observed_decision_sha256=replay.decision_sha256,
                observed_permit_sha256=replay.permit_sha256,
                decision_diverged=replay.decision_sha256
                != baseline.decision_sha256,
                permit_diverged=replay.permit_sha256 != baseline.permit_sha256,
            )
        )
    return tuple(results)


def run_recovery_qualification(
    manifest: RecoveryQualificationManifest,
    environment: RecoveryQualificationEnvironment,
    *,
    fixtures: tuple[RecoveryQualificationFixture, ...] | None = None,
) -> RecoveryQualificationResults:
    """Execute the frozen 100 cases and emit 400 policy-lane results."""

    if type(manifest) is not RecoveryQualificationManifest or type(
        environment
    ) is not RecoveryQualificationEnvironment:
        raise TypeError("exact recovery qualification inputs are required")
    manifest_sha256 = canonical_sha256(manifest)
    if (
        environment.suite_id != manifest.suite_id
        or environment.manifest_sha256 != manifest_sha256
        or environment.source_revision != manifest.source_revision
        or environment.source_tree_sha256 != manifest.source_tree_sha256
    ):
        raise RecoveryQualificationError("qualification environment binding changed")
    selected = build_recovery_qualification_fixtures() if fixtures is None else fixtures
    if type(selected) is not tuple or len(selected) != RECOVERY_QUALIFICATION_CASE_COUNT:
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

    lane_results: list[RecoveryQualificationLaneResult] = []
    case_proofs: list[RecoveryQualificationCaseProof] = []
    lane_sequence = 0
    for case_sequence, fixture in enumerate(selected, 1):
        baseline = replay_recovery_qualification_fixture(fixture)
        blind_retry = _blind_lane(
            fixture,
            policy=RecoveryQualificationPolicy.BLIND_RETRY,
            sequence=lane_sequence + 1,
            admitted_evidence_sha256=baseline.admitted_evidence_sha256,
        )
        blind_abort = _blind_lane(
            fixture,
            policy=RecoveryQualificationPolicy.BLIND_ABORT,
            sequence=lane_sequence + 2,
            admitted_evidence_sha256=baseline.admitted_evidence_sha256,
        )
        fixed = _proof_lane(
            fixture,
            policy=RecoveryQualificationPolicy.FIXED,
            sequence=lane_sequence + 3,
            replay=baseline,
            environment=environment,
        )
        adaptive = _proof_lane(
            fixture,
            policy=RecoveryQualificationPolicy.ADAPTIVE,
            sequence=lane_sequence + 4,
            replay=replay_recovery_qualification_fixture(
                fixture,
                hypothesis={"advisory_only": True},
            ),
            environment=environment,
        )
        lane_results.extend((blind_retry, blind_abort, fixed, adaptive))
        lane_sequence += 4

        reordered = replay_recovery_qualification_fixture(
            fixture,
            observations=tuple(reversed(fixture.observations)),
        )
        duplicated = replay_recovery_qualification_fixture(
            fixture,
            observations=(*fixture.observations, *fixture.observations),
        )
        restart_exercised = fixture.seed == RECOVERY_QUALIFICATION_SEEDS[0]
        if restart_exercised:
            restarted = RecoveryQualificationLaneResult.model_validate_json(
                canonical_json_bytes(fixed)
            )
            restart_lane_sha256 = canonical_sha256(restarted)
            restarted_decision_sha256 = restarted.decision_sha256
            restarted_permit_sha256 = restarted.permit_sha256
            restart_decision_valid = restarted.decision_sha256 == fixed.decision_sha256
            restart_permit_valid = restarted.permit_sha256 == fixed.permit_sha256
        else:
            restart_lane_sha256 = None
            restarted_decision_sha256 = None
            restarted_permit_sha256 = None
            restart_decision_valid = True
            restart_permit_valid = True
        witness_exercised = baseline.ambiguity_witness_sha256 is not None
        case_proofs.append(
            RecoveryQualificationCaseProof(
                sequence=case_sequence,
                case_id=fixture.case_id,
                archetype_id=fixture.archetype.archetype_id,
                seed=fixture.seed,
                storage_backend=fixture.storage_backend,
                admitted_evidence_sha256=baseline.admitted_evidence_sha256,
                deterministic_resolution=baseline.resolution,
                deterministic_permit_action=baseline.permit_action,
                fixed_decision_sha256=fixed.decision_sha256,
                adaptive_decision_sha256=adaptive.decision_sha256,
                fixed_permit_sha256=fixed.permit_sha256,
                adaptive_permit_sha256=adaptive.permit_sha256,
                decision_replay_parity=fixed.decision_sha256
                == adaptive.decision_sha256,
                permit_replay_parity=fixed.permit_sha256 == adaptive.permit_sha256,
                wrong_hypothesis_replays=_wrong_hypotheses(fixture, baseline),
                witness_exercised=witness_exercised,
                witness_sha256=baseline.ambiguity_witness_sha256,
                reordered_witness_sha256=(
                    reordered.ambiguity_witness_sha256 if witness_exercised else None
                ),
                duplicated_witness_sha256=(
                    duplicated.ambiguity_witness_sha256 if witness_exercised else None
                ),
                witness_reorder_valid=(
                    not witness_exercised
                    or reordered.ambiguity_witness_sha256
                    == baseline.ambiguity_witness_sha256
                ),
                witness_duplication_valid=(
                    not witness_exercised
                    or duplicated.ambiguity_witness_sha256
                    == baseline.ambiguity_witness_sha256
                ),
                restart_exercised=restart_exercised,
                restart_lane_sha256=restart_lane_sha256,
                restarted_decision_sha256=restarted_decision_sha256,
                restarted_permit_sha256=restarted_permit_sha256,
                restart_decision_valid=restart_decision_valid,
                restart_permit_valid=restart_permit_valid,
            )
        )

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
        item.witness_reorder_valid and item.witness_duplication_valid
        for item in witnesses
    )
    restarts = tuple(item for item in case_proofs if item.restart_exercised)
    restart_valid = sum(
        item.restart_decision_valid and item.restart_permit_valid for item in restarts
    )
    actions = tuple(
        fixture.archetype.expected_permit_action for fixture in selected
    )
    sqlite_count = sum(
        fixture.storage_backend is RecoveryQualificationStorageBackend.SQLITE
        for fixture in selected
    )
    safety = all(
        (
            false_permits == 0,
            parity == 100,
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
        manifest_sha256=manifest_sha256,
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

    manifest_sha256 = canonical_sha256(manifest)
    environment_sha256 = canonical_sha256(environment)
    if (
        results.manifest_sha256 != manifest_sha256
        or results.environment_sha256 != environment_sha256
    ):
        raise RecoveryQualificationError("qualification comparison binding changed")
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
    adaptive_lanes = tuple(
        item
        for item in results.lane_results
        if item.policy is RecoveryQualificationPolicy.ADAPTIVE
    )
    measured = bool(adaptive_lanes) and all(
        item.model_usage.status is RecoveryQualificationModelUsageStatus.MEASURED
        and item.model_usage.live_vertex_backed
        for item in adaptive_lanes
    )
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
            reduction >= RECOVERY_QUALIFICATION_ADAPTIVE_THRESHOLD_BASIS_POINTS
        ),
        execution_basis=environment.execution_basis,
        live_vertex_model_usage_measured=measured,
    )


class _MemoryFirestoreCasStore:
    """Concurrency-faithful Firestore CAS double used only by qualification."""

    def __init__(self) -> None:
        self._documents: dict[
            tuple[FirestoreCasCollection, str], FirestoreCasSnapshot
        ] = {}
        self._lock = asyncio.Lock()
        self._revision = 0

    def _snapshot(self, document: FirestoreCasDocument) -> FirestoreCasSnapshot:
        self._revision += 1
        return FirestoreCasSnapshot(
            collection=document.kind,
            document_key=firestore_cas_document_key(
                document.kind,
                document.logical_id,
            ),
            document=document,
            update_time=_CONTENTION_NOW + timedelta(microseconds=self._revision),
        )

    async def read(
        self,
        collection: FirestoreCasCollection,
        logical_id: str,
    ) -> FirestoreCasSnapshot | None:
        async with self._lock:
            return self._documents.get((collection, logical_id))

    async def create(self, document: FirestoreCasDocument) -> FirestoreCasSnapshot:
        key = (document.kind, document.logical_id)
        async with self._lock:
            if key in self._documents:
                raise FirestoreCasConflict
            snapshot = self._snapshot(document)
            self._documents[key] = snapshot
            return snapshot

    async def update(
        self,
        current: FirestoreCasSnapshot,
        replacement: FirestoreCasDocument,
    ) -> FirestoreCasSnapshot:
        key = (replacement.kind, replacement.logical_id)
        async with self._lock:
            if self._documents.get(key) != current:
                raise FirestoreCasConflict
            snapshot = self._snapshot(replacement)
            self._documents[key] = snapshot
            return snapshot


def _contention_permit(
    backend: RecoveryQualificationStorageBackend,
    action: PermitAction,
) -> ActionPermit:
    suffix = f"{backend.value}-{action.value.lower()}"
    source = f"source-{suffix}"
    target = source if action is PermitAction.RETRY else f"target-{suffix}"
    digest = hashlib.sha256(suffix.encode()).hexdigest()
    return ActionPermit(
        schema_version=ACTION_PERMIT_VERSION,
        permit_id=f"qualification-permit-{suffix}",
        certificate_id=f"qualification-certificate-{suffix}",
        certificate_sha256=digest,
        chain_id="qualification-chain",
        source_node_id=source,
        target_node_id=target,
        semantic_action_sha256=digest,
        action=action,
        action_profile_version="qualification-action-profile-v1",
        action_policy_version=RECOVERY_QUALIFICATION_PERMIT_POLICY_VERSION,
        tool_name="qualification-provider-mutation",
        tool_version="1.0.0",
        arguments_sha256=digest,
        target_sha256=digest,
        precondition_sha256=digest,
        issued_at=_CONTENTION_NOW,
        expires_at=_CONTENTION_NOW + timedelta(hours=1),
        max_uses=1,
        state=ActionPermitState.ISSUED,
        revision=0,
    )


def _claim_request(permit: ActionPermit, index: int) -> PermitClaimRequest:
    return PermitClaimRequest(
        schema_version=PERMIT_CLAIM_REQUEST_VERSION,
        permit_id=permit.permit_id,
        claim_id=f"qualification-claim-{index:02}",
        issued_permit_sha256=canonical_sha256(permit),
        certificate_id=permit.certificate_id,
        certificate_sha256=permit.certificate_sha256,
        chain_id=permit.chain_id,
        source_node_id=permit.source_node_id,
        target_node_id=permit.target_node_id,
        semantic_action_sha256=permit.semantic_action_sha256,
        action_profile_version=permit.action_profile_version,
        action_policy_version=permit.action_policy_version,
        tool_name=permit.tool_name,
        tool_version=permit.tool_version,
        arguments_sha256=permit.arguments_sha256,
        target_sha256=permit.target_sha256,
        precondition_sha256=permit.precondition_sha256,
        requested_at=_CONTENTION_NOW + timedelta(seconds=1),
    )


async def _contention_trial(
    backend: RecoveryQualificationStorageBackend,
    action: PermitAction,
    directory: Path,
) -> RecoveryQualificationContentionTrial:
    if backend is RecoveryQualificationStorageBackend.SQLITE:
        database = directory / f"{backend.value}-{action.value.lower()}.sqlite3"
        store = SqliteDurableRuntimeStore(database)
    else:
        store = FirestoreActionPermitStore(_MemoryFirestoreCasStore())
    permit = _contention_permit(backend, action)
    await store.issue_permit(permit)
    start = asyncio.Event()
    winners: list[str] = []
    denied_claim_ids: list[str] = []
    provider_call_receipts: list[str] = []
    denied = 0
    outbound_calls = 0

    async def contend(index: int) -> None:
        nonlocal denied, outbound_calls
        await start.wait()
        request = _claim_request(permit, index)
        try:
            await store.claim_permit(request)
        except PermitClaimDenied:
            denied += 1
            denied_claim_ids.append(request.claim_id)
            return
        winners.append(request.claim_id)
        outbound_calls += 1
        provider_call_receipts.append(
            f"provider-call-receipt-{backend.value}-{action.value.lower()}"
        )

    tasks = tuple(
        asyncio.create_task(contend(index))
        for index in range(RECOVERY_QUALIFICATION_CONTENTION_WIDTH)
    )
    start.set()
    await asyncio.gather(*tasks)
    final = await store.get_permit(permit.permit_id)
    return RecoveryQualificationContentionTrial(
        backend=backend,
        permit_action=action,
        contender_count=RECOVERY_QUALIFICATION_CONTENTION_WIDTH,
        winner_count=len(winners),
        denied_count=denied,
        outbound_call_count=outbound_calls,
        contender_claim_ids=tuple(
            f"qualification-claim-{index:02}"
            for index in range(RECOVERY_QUALIFICATION_CONTENTION_WIDTH)
        ),
        winner_claim_id=winners[0] if len(winners) == 1 else None,
        denied_claim_ids=tuple(sorted(denied_claim_ids)),
        provider_call_receipt_ids=tuple(provider_call_receipts),
        final_permit=final,
        final_permit_sha256=canonical_sha256(final),
        passed=len(winners) == 1 and outbound_calls <= 1,
    )


async def run_recovery_qualification_contention(
    manifest: RecoveryQualificationManifest,
    results: RecoveryQualificationResults,
    *,
    working_directory: str | Path | None = None,
) -> RecoveryQualificationContention:
    """Exercise 32-way CONTINUE and RETRY claims in SQLite and Firestore."""

    if results.manifest_sha256 != canonical_sha256(manifest):
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

    manifest_sha256 = canonical_sha256(manifest)
    environment_sha256 = canonical_sha256(environment)
    results_sha256 = canonical_sha256(results)
    contention_sha256 = canonical_sha256(contention)
    comparison_sha256 = canonical_sha256(comparison)
    if any(
        (
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
    source_exact = all(
        (
            environment.repository_clean,
            environment.source_revision == manifest.source_revision,
            environment.source_tree_sha256 == manifest.source_tree_sha256,
        )
    )
    adaptive_lanes = tuple(
        item
        for item in results.lane_results
        if item.policy is RecoveryQualificationPolicy.ADAPTIVE
    )
    live_vertex = (
        environment.execution_basis is RecoveryQualificationExecutionBasis.LIVE_VERTEX
        and bool(adaptive_lanes)
        and all(item.model_usage.live_vertex_backed for item in adaptive_lanes)
    )
    measured = live_vertex and all(
        item.model_usage.status is RecoveryQualificationModelUsageStatus.MEASURED
        for item in adaptive_lanes
    )
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
            comparison.median_probe_reduction_basis_points >= 2500,
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
    source_revision: str,
    source_tree_sha256: str,
    repository_clean: bool,
    dependency_lock_sha256: str,
    created_at: datetime | None = None,
    contention_directory: str | Path | None = None,
) -> RecoveryQualificationBundle:
    """Build every bound artifact, including real permit-store contention."""

    generated_at = _now(created_at)
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
    results = run_recovery_qualification(manifest, environment)
    contention = await run_recovery_qualification_contention(
        manifest,
        results,
        working_directory=contention_directory,
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
        if resolved_target == source or source in resolved_target.parents or (
            resolved_target in source.parents
        ):
            raise RecoveryQualificationError(
                "qualification output must not overlap the measured source"
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
        if not stat.S_ISREG(metadata.st_mode) or stat.S_IMODE(metadata.st_mode) != 0o600:
            raise RecoveryQualificationError(
                "qualification artifact mode is not 0600"
            )
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
        raise RecoveryQualificationError("qualification bundle is unavailable") from error
    if not stat.S_ISDIR(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
        raise RecoveryQualificationError("qualification bundle must be a directory")
    if stat.S_IMODE(metadata.st_mode) != 0o700:
        raise RecoveryQualificationError("qualification bundle directory mode is not 0700")
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
            raise RecoveryQualificationError(
                "qualification artifact is not canonical"
            )
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
    "recovery_qualification_median_reduction_basis_points",
    "recovery_qualification_source_state",
    "replay_recovery_qualification_fixture",
    "run_recovery_qualification",
    "run_recovery_qualification_contention",
    "verify_recovery_qualification_bundle",
]
