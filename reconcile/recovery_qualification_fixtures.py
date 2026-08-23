"""Frozen, secret-free fixtures for recovery qualification v1."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass

from reconcile.contracts.base import canonical_json_value_bytes
from reconcile.contracts.recovery import PermitAction
from reconcile.contracts.recovery_qualification import (
    RECOVERY_QUALIFICATION_SEEDS,
    RecoveryQualificationArchetype,
    RecoveryQualificationFaultClass,
    RecoveryQualificationOpportunity,
    RecoveryQualificationResolution,
    RecoveryQualificationStage,
    RecoveryQualificationStorageBackend,
)


@dataclass(frozen=True, slots=True)
class RecoveryQualificationObservation:
    """One admitted deterministic fact; hypotheses never enter this boundary."""

    evidence_id: str
    fact_key: str
    fact_value: str
    authoritative: bool = True
    fresh: bool = True


@dataclass(frozen=True, slots=True)
class RecoveryQualificationFixture:
    case_id: str
    archetype: RecoveryQualificationArchetype
    seed: int
    storage_backend: RecoveryQualificationStorageBackend
    observations: tuple[RecoveryQualificationObservation, ...]


def _archetype(
    archetype_id: str,
    *,
    stage: RecoveryQualificationStage,
    fault: RecoveryQualificationFaultClass,
    opportunity: RecoveryQualificationOpportunity,
    evidence: tuple[str, ...],
    resolution: RecoveryQualificationResolution,
    action: PermitAction | None,
    fixed_probes: int,
    adaptive_probes: int,
    fixed_unsupported: int = 0,
    adaptive_unsupported: int = 0,
) -> RecoveryQualificationArchetype:
    return RecoveryQualificationArchetype(
        archetype_id=archetype_id,
        stage=stage,
        fault_class=fault,
        opportunity=opportunity,
        evidence_profile=evidence,
        expected_resolution=resolution,
        expected_permit_action=action,
        ambiguity_witness_required=(
            resolution is RecoveryQualificationResolution.ESCALATE
        ),
        fixed_probe_count=fixed_probes,
        adaptive_probe_count=adaptive_probes,
        fixed_unsupported_probe_count=fixed_unsupported,
        adaptive_unsupported_probe_count=adaptive_unsupported,
    )


# Five fixed-favored, ten adaptive-favored, and five neutral archetypes.  The
# order is part of the frozen matrix and is retained in every result artifact.
RECOVERY_QUALIFICATION_ARCHETYPES = (
    _archetype(
        "stage-drop-committed",
        stage=RecoveryQualificationStage.STAGE,
        fault=RecoveryQualificationFaultClass.DROP_AFTER_ACCEPT,
        opportunity=RecoveryQualificationOpportunity.ADAPTIVE_FAVORED,
        evidence=(
            "stage-revision-exists",
            "stage-revision-ready",
            "stage-health-ready",
            "stage-traffic-unchanged",
        ),
        resolution=RecoveryQualificationResolution.CONTINUE,
        action=PermitAction.CONTINUE,
        fixed_probes=3,
        adaptive_probes=1,
    ),
    _archetype(
        "stage-pending",
        stage=RecoveryQualificationStage.STAGE,
        fault=RecoveryQualificationFaultClass.PENDING,
        opportunity=RecoveryQualificationOpportunity.ADAPTIVE_FAVORED,
        evidence=("stage-operation-pending", "stage-revision-reconciling"),
        resolution=RecoveryQualificationResolution.ESCALATE,
        action=None,
        fixed_probes=3,
        adaptive_probes=1,
    ),
    _archetype(
        "stage-terminal-partial",
        stage=RecoveryQualificationStage.STAGE,
        fault=RecoveryQualificationFaultClass.TERMINAL_PARTIAL,
        opportunity=RecoveryQualificationOpportunity.ADAPTIVE_FAVORED,
        evidence=(
            "stage-operation-failed",
            "stage-revision-exists",
            "stage-health-unhealthy",
        ),
        resolution=RecoveryQualificationResolution.ESCALATE,
        action=None,
        fixed_probes=3,
        adaptive_probes=1,
    ),
    _archetype(
        "stage-conflict",
        stage=RecoveryQualificationStage.STAGE,
        fault=RecoveryQualificationFaultClass.CONFLICT,
        opportunity=RecoveryQualificationOpportunity.ADAPTIVE_FAVORED,
        evidence=("stage-ready-assertion", "stage-failed-assertion"),
        resolution=RecoveryQualificationResolution.ESCALATE,
        action=None,
        fixed_probes=3,
        adaptive_probes=1,
    ),
    _archetype(
        "stage-absence",
        stage=RecoveryQualificationStage.STAGE,
        fault=RecoveryQualificationFaultClass.ABSENCE,
        opportunity=RecoveryQualificationOpportunity.FIXED_FAVORED,
        evidence=("stage-revision-absent", "stage-inventory-fresh"),
        resolution=RecoveryQualificationResolution.RETRY,
        action=PermitAction.RETRY,
        fixed_probes=1,
        adaptive_probes=2,
    ),
    _archetype(
        "stage-unavailable",
        stage=RecoveryQualificationStage.STAGE,
        fault=RecoveryQualificationFaultClass.PROVIDER_UNAVAILABLE,
        opportunity=RecoveryQualificationOpportunity.ADAPTIVE_FAVORED,
        evidence=("stage-service-read-unavailable",),
        resolution=RecoveryQualificationResolution.ESCALATE,
        action=None,
        fixed_probes=3,
        adaptive_probes=1,
        fixed_unsupported=1,
        adaptive_unsupported=1,
    ),
    _archetype(
        "stage-fresh",
        stage=RecoveryQualificationStage.STAGE,
        fault=RecoveryQualificationFaultClass.FRESHNESS,
        opportunity=RecoveryQualificationOpportunity.FIXED_FAVORED,
        evidence=(
            "stage-revision-ready",
            "stage-health-ready",
            "stage-observation-fresh",
        ),
        resolution=RecoveryQualificationResolution.CONTINUE,
        action=PermitAction.CONTINUE,
        fixed_probes=1,
        adaptive_probes=2,
    ),
    _archetype(
        "stage-stale",
        stage=RecoveryQualificationStage.STAGE,
        fault=RecoveryQualificationFaultClass.FRESHNESS,
        opportunity=RecoveryQualificationOpportunity.ADAPTIVE_FAVORED,
        evidence=(
            "stage-revision-ready",
            "stage-health-ready",
            "stage-observation-stale",
        ),
        resolution=RecoveryQualificationResolution.ESCALATE,
        action=None,
        fixed_probes=3,
        adaptive_probes=1,
    ),
    _archetype(
        "promote-committed",
        stage=RecoveryQualificationStage.PROMOTE,
        fault=RecoveryQualificationFaultClass.NO_FAULT,
        opportunity=RecoveryQualificationOpportunity.FIXED_FAVORED,
        evidence=("promote-serving-intended", "promote-etag-fresh"),
        resolution=RecoveryQualificationResolution.CONTINUE,
        action=PermitAction.CONTINUE,
        fixed_probes=1,
        adaptive_probes=2,
    ),
    _archetype(
        "promote-pending",
        stage=RecoveryQualificationStage.PROMOTE,
        fault=RecoveryQualificationFaultClass.PENDING,
        opportunity=RecoveryQualificationOpportunity.ADAPTIVE_FAVORED,
        evidence=("promote-operation-pending", "promote-traffic-reconciling"),
        resolution=RecoveryQualificationResolution.ESCALATE,
        action=None,
        fixed_probes=3,
        adaptive_probes=1,
    ),
    _archetype(
        "promote-conflict",
        stage=RecoveryQualificationStage.PROMOTE,
        fault=RecoveryQualificationFaultClass.CONFLICT,
        opportunity=RecoveryQualificationOpportunity.ADAPTIVE_FAVORED,
        evidence=("promote-serving-intended", "promote-serving-baseline"),
        resolution=RecoveryQualificationResolution.ESCALATE,
        action=None,
        fixed_probes=3,
        adaptive_probes=1,
    ),
    _archetype(
        "promote-stale-precondition",
        stage=RecoveryQualificationStage.PROMOTE,
        fault=RecoveryQualificationFaultClass.FRESHNESS,
        opportunity=RecoveryQualificationOpportunity.NEUTRAL,
        evidence=("promote-etag-stale", "promote-service-fresh"),
        resolution=RecoveryQualificationResolution.ESCALATE,
        action=None,
        fixed_probes=2,
        adaptive_probes=2,
    ),
    _archetype(
        "promote-unavailable",
        stage=RecoveryQualificationStage.PROMOTE,
        fault=RecoveryQualificationFaultClass.PROVIDER_UNAVAILABLE,
        opportunity=RecoveryQualificationOpportunity.ADAPTIVE_FAVORED,
        evidence=("promote-service-read-unavailable",),
        resolution=RecoveryQualificationResolution.ESCALATE,
        action=None,
        fixed_probes=3,
        adaptive_probes=1,
        fixed_unsupported=1,
        adaptive_unsupported=1,
    ),
    _archetype(
        "record-predispatch-retry",
        stage=RecoveryQualificationStage.RECORD,
        fault=RecoveryQualificationFaultClass.SUPPRESS_BEFORE_DISPATCH,
        opportunity=RecoveryQualificationOpportunity.FIXED_FAVORED,
        evidence=("record-receipt-suppressed", "record-provider-not-contacted"),
        resolution=RecoveryQualificationResolution.RETRY,
        action=PermitAction.RETRY,
        fixed_probes=1,
        adaptive_probes=2,
    ),
    _archetype(
        "record-predispatch-unavailable",
        stage=RecoveryQualificationStage.RECORD,
        fault=RecoveryQualificationFaultClass.PROVIDER_UNAVAILABLE,
        opportunity=RecoveryQualificationOpportunity.NEUTRAL,
        evidence=("record-receipt-unavailable", "record-state-unknown"),
        resolution=RecoveryQualificationResolution.ESCALATE,
        action=None,
        fixed_probes=2,
        adaptive_probes=2,
        fixed_unsupported=1,
        adaptive_unsupported=1,
    ),
    _archetype(
        "record-predispatch-conflict",
        stage=RecoveryQualificationStage.RECORD,
        fault=RecoveryQualificationFaultClass.CONFLICT,
        opportunity=RecoveryQualificationOpportunity.NEUTRAL,
        evidence=("record-receipt-suppressed", "record-provider-contacted"),
        resolution=RecoveryQualificationResolution.ESCALATE,
        action=None,
        fixed_probes=2,
        adaptive_probes=2,
    ),
    _archetype(
        "record-committed",
        stage=RecoveryQualificationStage.RECORD,
        fault=RecoveryQualificationFaultClass.NO_FAULT,
        opportunity=RecoveryQualificationOpportunity.FIXED_FAVORED,
        evidence=("record-exists", "record-payload-matches"),
        resolution=RecoveryQualificationResolution.COMPLETED,
        action=None,
        fixed_probes=1,
        adaptive_probes=2,
    ),
    _archetype(
        "record-absence-without-receipt",
        stage=RecoveryQualificationStage.RECORD,
        fault=RecoveryQualificationFaultClass.ABSENCE,
        opportunity=RecoveryQualificationOpportunity.NEUTRAL,
        evidence=("record-absent", "record-dispatch-receipt-absent"),
        resolution=RecoveryQualificationResolution.ESCALATE,
        action=None,
        fixed_probes=2,
        adaptive_probes=2,
    ),
    _archetype(
        "record-pending",
        stage=RecoveryQualificationStage.RECORD,
        fault=RecoveryQualificationFaultClass.PENDING,
        opportunity=RecoveryQualificationOpportunity.NEUTRAL,
        evidence=("record-write-pending", "record-read-absent"),
        resolution=RecoveryQualificationResolution.ESCALATE,
        action=None,
        fixed_probes=2,
        adaptive_probes=2,
    ),
    _archetype(
        "cross-provider-adaptive",
        stage=RecoveryQualificationStage.STAGE,
        fault=RecoveryQualificationFaultClass.DROP_AFTER_ACCEPT,
        opportunity=RecoveryQualificationOpportunity.ADAPTIVE_FAVORED,
        evidence=(
            "cross-revision-ready",
            "cross-health-ready",
            "cross-traffic-unchanged",
            "cross-record-absent",
        ),
        resolution=RecoveryQualificationResolution.CONTINUE,
        action=PermitAction.CONTINUE,
        fixed_probes=3,
        adaptive_probes=1,
        fixed_unsupported=1,
    ),
)


def build_recovery_qualification_fixtures() -> tuple[
    RecoveryQualificationFixture, ...
]:
    """Materialize the exact 20 x 5 matrix with both persistence backends."""

    fixtures: list[RecoveryQualificationFixture] = []
    for archetype_index, archetype in enumerate(RECOVERY_QUALIFICATION_ARCHETYPES):
        for seed_index, seed in enumerate(RECOVERY_QUALIFICATION_SEEDS):
            backend = (
                RecoveryQualificationStorageBackend.SQLITE
                if (archetype_index + seed_index) % 2 == 0
                else RecoveryQualificationStorageBackend.FIRESTORE
            )
            case_id = f"rq-{archetype_index + 1:02}-{archetype.archetype_id}-{seed}"
            observations = tuple(
                RecoveryQualificationObservation(
                    evidence_id=f"evidence-{index + 1}-{seed}",
                    fact_key=f"fact-{index + 1}",
                    fact_value=value,
                    fresh=not value.endswith("-stale"),
                )
                for index, value in enumerate(archetype.evidence_profile)
            )
            fixtures.append(
                RecoveryQualificationFixture(
                    case_id=case_id,
                    archetype=archetype,
                    seed=seed,
                    storage_backend=backend,
                    observations=observations,
                )
            )
    return tuple(fixtures)


def recovery_qualification_fixture_catalog_sha256() -> str:
    """Hash every frozen archetype, seed, backend, and admitted observation."""

    fixtures = build_recovery_qualification_fixtures()
    value = [
        {
            "archetype": fixture.archetype.model_dump(mode="json"),
            "case_id": fixture.case_id,
            "observations": [
                {
                    "authoritative": item.authoritative,
                    "evidence_id": item.evidence_id,
                    "fact_key": item.fact_key,
                    "fact_value": item.fact_value,
                    "fresh": item.fresh,
                }
                for item in fixture.observations
            ],
            "seed": fixture.seed,
            "storage_backend": fixture.storage_backend.value,
        }
        for fixture in fixtures
    ]
    return hashlib.sha256(canonical_json_value_bytes(value)).hexdigest()


__all__ = [
    "RECOVERY_QUALIFICATION_ARCHETYPES",
    "RECOVERY_QUALIFICATION_SEEDS",
    "RecoveryQualificationFixture",
    "RecoveryQualificationObservation",
    "build_recovery_qualification_fixtures",
    "recovery_qualification_fixture_catalog_sha256",
]
