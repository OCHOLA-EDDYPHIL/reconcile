"""Real bounded read-only fixtures for adaptive qualification execution."""

from __future__ import annotations

import hashlib
import json
import os
import stat
import time
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field, replace
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from pathlib import Path

from reconcile.adapters.firestore_business import (
    build_firestore_business_capability_registration,
    build_firestore_business_rule_registration,
)
from reconcile.adapters.sandbox_order import (
    build_sandbox_order_aggregate_capability_registration,
    build_sandbox_order_aggregate_rule_registration,
    build_sandbox_order_ingress_capability_registration,
    build_sandbox_order_ingress_rule_registration,
)
from reconcile.adapters.storage import (
    build_storage_capability_registration,
    build_storage_rule_registration,
)
from reconcile.adaptive import AdaptiveInvestigationPolicy
from reconcile.baseline import FixedProbePlan, FixedProbeStep
from reconcile.contracts import (
    PROBE_REQUEST_VERSION,
    SCENARIO_RUN_REQUEST_VERSION,
    CapabilityRef,
    Classification,
    EnvelopeContext,
    ExecutionEnvelope,
    ObservationCapability,
    PolicyReferences,
    ProbeRequest,
    ScenarioCleanupDisposition,
    ScenarioFaultAction,
    ScenarioFaultInstruction,
    ScenarioFaultPoint,
    ScenarioRunRequest,
    canonical_json_bytes,
    decode_contract,
)
from reconcile.contracts.base import (
    canonical_json_value_bytes,
    reject_sensitive_values,
)
from reconcile.contracts.evidence import EffectAssertion, EffectAssertionState
from reconcile.contracts.qualification import (
    QualificationArtifactIdentity,
    QualificationCaseDefinition,
    QualificationSuiteManifest,
)
from reconcile.controller import (
    BoundProbe,
    CapabilityRegistration,
    CapabilityRegistry,
    ProbeObservation,
)
from reconcile.evidence import (
    RuleInput,
    RuleObservation,
    RuleVerdict,
    TargetRuleDescriptor,
    TargetRuleRegistration,
    TargetRuleRegistry,
)
from reconcile.scenarios.firestore_business import (
    FIRESTORE_BUSINESS_EFFECT_IDS,
    FirestoreBusinessScenarioDefinition,
)
from reconcile.scenarios.local_firestore import LocalFirestoreReadTarget
from reconcile.scenarios.local_order import HiddenOrderOutcome, LocalOrderReadTarget
from reconcile.scenarios.local_storage import LocalStorageReadTarget
from reconcile.scenarios.runner import ScenarioRunner
from reconcile.scenarios.sandbox_order import SandboxOrderScenarioDefinition
from reconcile.scenarios.storage import StorageScenarioDefinition

_CAPABILITY_VERSION = "1.0.0"
_FIXED_PLAN_NAME = "qualification-fixed-plan"
_ADAPTIVE_POLICY_NAME = "qualification-adaptive-policy"
_QUALIFICATION_VERSION = "1.0.0"
_WEAK_SOURCE = "qualification-real-read-weak-projection"
_WEAK_ADAPTER_VERSION = "1.0.0"
_FINAL_ACCESS_SEAL = object()


class QualificationProtocolStage(StrEnum):
    DEVELOPMENT_1 = "development-1"
    DEVELOPMENT_2 = "development-2"
    FINAL_HOLDOUT = "final-holdout"


class _CapabilityKind(StrEnum):
    AUTHORITATIVE = "AUTHORITATIVE"
    WEAK = "WEAK"


@dataclass(frozen=True, slots=True)
class _FixedClock:
    value: datetime

    def __call__(self) -> datetime:
        return self.value


class _StepClock:
    def __init__(self, value: datetime) -> None:
        self._value = value

    def now(self) -> datetime:
        value = self._value
        self._value += timedelta(milliseconds=1)
        return value


class _ControllerClock:
    def __init__(self, value: datetime) -> None:
        self._value = value
        self._monotonic = 1_000.0

    def now(self) -> datetime:
        value = self._value
        self._value += timedelta(milliseconds=1)
        return value

    def monotonic(self) -> float:
        value = self._monotonic
        self._monotonic += 0.001
        return value


class _LiveControllerClock(_ControllerClock):
    def monotonic(self) -> float:
        return time.monotonic()


@dataclass(frozen=True, slots=True)
class _CapabilityRecipe:
    name: str
    kind: _CapabilityKind
    source: str


@dataclass(frozen=True, slots=True)
class _FixtureRecipe:
    fixture_id: str
    cohort: QualificationProtocolStage
    classification: Classification | None
    capabilities: tuple[_CapabilityRecipe, ...]
    fixed_order: tuple[str, ...]
    selected_effect_ids: tuple[str, ...] | None = None
    sandbox_hidden_outcome: HiddenOrderOutcome = HiddenOrderOutcome.COMMIT


_FIXTURE_RECIPES = {
    "storage-authoritative-single-lookup": _FixtureRecipe(
        fixture_id="storage-authoritative-single-lookup",
        cohort=QualificationProtocolStage.FINAL_HOLDOUT,
        classification=Classification.COMMITTED,
        capabilities=(
            _CapabilityRecipe(
                "qualification-authoritative-fast-path",
                _CapabilityKind.AUTHORITATIVE,
                "storage",
            ),
        ),
        fixed_order=("qualification-authoritative-fast-path",),
    ),
    "firestore-canonical-conditional-partial": _FixtureRecipe(
        fixture_id="firestore-canonical-conditional-partial",
        cohort=QualificationProtocolStage.FINAL_HOLDOUT,
        classification=Classification.PARTIAL,
        capabilities=(
            _CapabilityRecipe(
                "qualification-weak-index", _CapabilityKind.WEAK, "firestore"
            ),
            _CapabilityRecipe(
                "qualification-authoritative-conditional",
                _CapabilityKind.AUTHORITATIVE,
                "firestore",
            ),
        ),
        fixed_order=(
            "qualification-weak-index",
            "qualification-authoritative-conditional",
        ),
    ),
    "sandbox-canonical-weak-only": _FixtureRecipe(
        fixture_id="sandbox-canonical-weak-only",
        cohort=QualificationProtocolStage.FINAL_HOLDOUT,
        classification=Classification.UNKNOWN,
        capabilities=(
            _CapabilityRecipe(
                "qualification-weak-ingress", _CapabilityKind.WEAK, "sandbox-ingress"
            ),
            _CapabilityRecipe(
                "qualification-weak-aggregate",
                _CapabilityKind.WEAK,
                "sandbox-aggregate",
            ),
        ),
        fixed_order=("qualification-weak-ingress", "qualification-weak-aggregate"),
    ),
    "storage-redundant-capability-catalog": _FixtureRecipe(
        fixture_id="storage-redundant-capability-catalog",
        cohort=QualificationProtocolStage.FINAL_HOLDOUT,
        classification=Classification.COMMITTED,
        capabilities=(
            _CapabilityRecipe(
                "qualification-weak-cache", _CapabilityKind.WEAK, "storage"
            ),
            _CapabilityRecipe(
                "qualification-authoritative-primary",
                _CapabilityKind.AUTHORITATIVE,
                "storage",
            ),
            _CapabilityRecipe(
                "qualification-authoritative-redundant",
                _CapabilityKind.AUTHORITATIVE,
                "storage",
            ),
        ),
        fixed_order=(
            "qualification-weak-cache",
            "qualification-authoritative-primary",
            "qualification-authoritative-redundant",
        ),
    ),
    "firestore-evidence-availability-conditional": _FixtureRecipe(
        fixture_id="firestore-evidence-availability-conditional",
        cohort=QualificationProtocolStage.FINAL_HOLDOUT,
        classification=Classification.PARTIAL,
        capabilities=(
            _CapabilityRecipe(
                "qualification-weak-index", _CapabilityKind.WEAK, "firestore"
            ),
            _CapabilityRecipe(
                "qualification-authoritative-conditional",
                _CapabilityKind.AUTHORITATIVE,
                "firestore",
            ),
        ),
        fixed_order=(
            "qualification-weak-index",
            "qualification-authoritative-conditional",
        ),
    ),
    "sandbox-provider-unavailable-control": _FixtureRecipe(
        fixture_id="sandbox-provider-unavailable-control",
        cohort=QualificationProtocolStage.FINAL_HOLDOUT,
        classification=None,
        capabilities=(
            _CapabilityRecipe(
                "qualification-weak-ingress", _CapabilityKind.WEAK, "sandbox-ingress"
            ),
            _CapabilityRecipe(
                "qualification-weak-aggregate",
                _CapabilityKind.WEAK,
                "sandbox-aggregate",
            ),
        ),
        fixed_order=("qualification-weak-ingress", "qualification-weak-aggregate"),
    ),
    "storage-equal-plan-control": _FixtureRecipe(
        fixture_id="storage-equal-plan-control",
        cohort=QualificationProtocolStage.FINAL_HOLDOUT,
        classification=Classification.COMMITTED,
        capabilities=(
            _CapabilityRecipe(
                "qualification-authoritative-equal",
                _CapabilityKind.AUTHORITATIVE,
                "storage",
            ),
        ),
        fixed_order=("qualification-authoritative-equal",),
    ),
    "firestore-authoritative-manifest-fast-path": _FixtureRecipe(
        fixture_id="firestore-authoritative-manifest-fast-path",
        cohort=QualificationProtocolStage.FINAL_HOLDOUT,
        classification=Classification.PARTIAL,
        capabilities=(
            _CapabilityRecipe(
                "qualification-authoritative-fast-path",
                _CapabilityKind.AUTHORITATIVE,
                "firestore",
            ),
        ),
        fixed_order=("qualification-authoritative-fast-path",),
        selected_effect_ids=FIRESTORE_BUSINESS_EFFECT_IDS[:2],
    ),
}


@dataclass(frozen=True, slots=True)
class QualificationRawObservation:
    sequence: int
    strategy: str
    capability_name: str
    canonical_json: bytes = field(repr=False)


class _ObservationJournal:
    def __init__(self) -> None:
        self._active_strategy: str | None = None
        self._records: dict[str, list[QualificationRawObservation]] = {}

    def begin(self, strategy: str) -> None:
        if self._active_strategy is not None:
            raise RuntimeError("qualification observation lane is already active")
        if strategy in self._records:
            raise RuntimeError("qualification observation lane cannot be replayed")
        self._active_strategy = strategy
        self._records[strategy] = []

    def end(self, strategy: str) -> tuple[QualificationRawObservation, ...]:
        if self._active_strategy != strategy:
            raise RuntimeError("qualification observation lane is not active")
        self._active_strategy = None
        return tuple(self._records[strategy])

    def record(self, capability_name: str, observation: ProbeObservation) -> None:
        strategy = self._active_strategy
        if strategy is None:
            raise RuntimeError("qualification observation escaped an active lane")
        reject_sensitive_values(observation.payload)
        records = self._records[strategy]
        records.append(
            QualificationRawObservation(
                sequence=len(records) + 1,
                strategy=strategy,
                capability_name=capability_name,
                canonical_json=canonical_json_bytes(observation),
            )
        )


def _read_sealed_canonical_object(
    path: Path,
    identity: QualificationArtifactIdentity,
) -> dict[str, object] | None:
    descriptor = -1
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or stat.S_IMODE(metadata.st_mode) != 0o400
        ):
            return None
        chunks: list[bytes] = []
        while chunk := os.read(descriptor, 65_536):
            chunks.append(chunk)
        payload = b"".join(chunks)
    except OSError:
        return None
    finally:
        if descriptor >= 0:
            os.close(descriptor)
    if (
        len(payload) != identity.byte_count
        or hashlib.sha256(payload).hexdigest() != identity.sha256
    ):
        return None
    try:
        decoded = json.loads(payload)
    except (UnicodeDecodeError, json.JSONDecodeError):
        return None
    if type(decoded) is not dict or canonical_json_value_bytes(decoded) != payload:
        return None
    return decoded


def _identity_record_matches(
    value: object,
    identity: QualificationArtifactIdentity,
) -> bool:
    return value == {
        "artifact_id": identity.artifact_id,
        "byte_count": identity.byte_count,
        "sha256": identity.sha256,
    }


def _identity_digest_matches(
    value: object,
    *,
    artifact_id: str,
    sha256: str,
) -> bool:
    return (
        type(value) is dict
        and value.get("artifact_id") == artifact_id
        and value.get("sha256") == sha256
        and type(value.get("byte_count")) is int
        and value["byte_count"] >= 0
        and set(value) == {"artifact_id", "byte_count", "sha256"}
    )


def _identity_matches(path: Path, identity: QualificationArtifactIdentity) -> bool:
    return _read_sealed_canonical_object(path, identity) is not None


def _sealed_completed_stage_matches(
    stage_path: Path,
    completion_identity: QualificationArtifactIdentity,
    retained_artifacts: tuple[QualificationArtifactIdentity, ...],
) -> bool:
    expected_names = {
        "execution-completion.json",
        *(f"{item.artifact_id}.json" for item in retained_artifacts),
    }
    try:
        stage_metadata = stage_path.stat(follow_symlinks=False)
        entries = tuple(os.scandir(stage_path))
    except OSError:
        return False
    if (
        not stat.S_ISDIR(stage_metadata.st_mode)
        or stat.S_IMODE(stage_metadata.st_mode) != 0o700
        or {item.name for item in entries} != expected_names
        or any(
            not item.is_file(follow_symlinks=False)
            or stat.S_IMODE(item.stat(follow_symlinks=False).st_mode) != 0o400
            for item in entries
        )
        or not _identity_matches(
            stage_path / "execution-completion.json", completion_identity
        )
    ):
        return False
    return all(
        _identity_matches(stage_path / f"{item.artifact_id}.json", item)
        for item in retained_artifacts
    )


def _sealed_schedule(
    manifest: dict[str, object],
) -> tuple[tuple[str, int], ...] | None:
    repetition_count = manifest.get("repetition_count")
    cases = manifest.get("cases")
    if (
        type(repetition_count) is not int
        or repetition_count < 1
        or type(cases) is not list
    ):
        return None
    case_ids = []
    for case in cases:
        if type(case) is not dict or type(case.get("case_id")) is not str:
            return None
        case_ids.append(case["case_id"])
    return tuple(
        (case_id, repetition)
        for repetition in range(1, repetition_count + 1)
        for case_id in case_ids
    )


def _final_access_bindings_match(access: QualificationFinalFixtureAccess) -> bool:
    if (
        access._seal is not _FINAL_ACCESS_SEAL
        or access.stage_path
        != access.store_root / QualificationProtocolStage.FINAL_HOLDOUT.value
        or access.start_identity.artifact_id != "execution-start"
        or access.manifest_identity.artifact_id != "manifest"
        or access.final_runtime_identity.artifact_id != "runtime-identity"
        or access.final_model_binding_identity.artifact_id != "provider-model-binding"
        or any(
            identity.artifact_id != "execution-completion"
            for identity in access.prerequisite_completion_identities
        )
        or any(
            identity.artifact_id != "provider-model-binding"
            for identity in access.prerequisite_model_binding_identities
        )
    ):
        return False

    final_path = access.stage_path
    first_path = access.store_root / QualificationProtocolStage.DEVELOPMENT_1.value
    second_path = access.store_root / QualificationProtocolStage.DEVELOPMENT_2.value
    manifest = _read_sealed_canonical_object(
        final_path / "manifest.json", access.manifest_identity
    )
    start = _read_sealed_canonical_object(
        final_path / "execution-start.json", access.start_identity
    )
    final_binding = _read_sealed_canonical_object(
        final_path / "provider-model-binding.json",
        access.final_model_binding_identity,
    )
    first = _read_sealed_canonical_object(
        first_path / "execution-completion.json",
        access.prerequisite_completion_identities[0],
    )
    second = _read_sealed_canonical_object(
        second_path / "execution-completion.json",
        access.prerequisite_completion_identities[1],
    )
    first_binding = _read_sealed_canonical_object(
        first_path / "provider-model-binding.json",
        access.prerequisite_model_binding_identities[0],
    )
    second_binding = _read_sealed_canonical_object(
        second_path / "provider-model-binding.json",
        access.prerequisite_model_binding_identities[1],
    )
    if any(
        item is None
        for item in (
            manifest,
            start,
            final_binding,
            first,
            second,
            first_binding,
            second_binding,
        )
    ):
        return False
    assert manifest is not None
    assert start is not None
    assert final_binding is not None
    assert first is not None
    assert second is not None
    assert first_binding is not None
    assert second_binding is not None

    completion_identities = access.prerequisite_completion_identities
    binding_identities = access.prerequisite_model_binding_identities
    configured_model = final_binding.get("configured_model")
    provider = manifest.get("provider")
    return (
        manifest.get("source_revision") == access.source_revision
        and _sealed_schedule(manifest) == access.schedule
        and type(provider) is dict
        and provider.get("model_name") == configured_model
        and start.get("stage") == QualificationProtocolStage.FINAL_HOLDOUT.value
        and start.get("suite_id") == manifest.get("suite_id")
        and start.get("manifest_sha256") == access.manifest_identity.sha256
        and start.get("source_revision") == access.source_revision
        and start.get("execution_basis") == "LIVE_PROVIDER"
        and start.get("planner_configuration_sha256") == access.runtime_identity_sha256
        and _identity_digest_matches(
            start.get("runtime_identity"),
            artifact_id="runtime-identity",
            sha256=access.runtime_identity_sha256,
        )
        and _identity_record_matches(
            start.get("model_binding"), access.final_model_binding_identity
        )
        and _identity_record_matches(
            start.get("runtime_identity"), access.final_runtime_identity
        )
        and _identity_matches(
            final_path / "runtime-identity.json", access.final_runtime_identity
        )
        and start.get("historical_attempt_ledger_sha256")
        == access.historical_attempt_ledger_sha256
        and start.get("consumed_v2_custody_sha256") == access.consumed_v2_custody_sha256
        and start.get("prior_stage_completion_sha256")
        == completion_identities[1].sha256
        and first.get("stage") == QualificationProtocolStage.DEVELOPMENT_1.value
        and second.get("stage") == QualificationProtocolStage.DEVELOPMENT_2.value
        and first.get("successful") is True
        and second.get("successful") is True
        and first.get("provider_evidence_qualifying") is True
        and second.get("provider_evidence_qualifying") is True
        and first.get("execution_basis") == "LIVE_PROVIDER"
        and second.get("execution_basis") == "LIVE_PROVIDER"
        and first.get("prior_stage_completion_sha256") is None
        and second.get("prior_stage_completion_sha256")
        == completion_identities[0].sha256
        and first.get("source_revision") == access.source_revision
        and second.get("source_revision") == access.source_revision
        and first.get("planner_configuration_sha256") == access.runtime_identity_sha256
        and second.get("planner_configuration_sha256") == access.runtime_identity_sha256
        and _identity_digest_matches(
            first.get("runtime_identity"),
            artifact_id="runtime-identity",
            sha256=access.runtime_identity_sha256,
        )
        and _identity_digest_matches(
            second.get("runtime_identity"),
            artifact_id="runtime-identity",
            sha256=access.runtime_identity_sha256,
        )
        and first.get("historical_attempt_ledger_sha256")
        == access.historical_attempt_ledger_sha256
        and second.get("historical_attempt_ledger_sha256")
        == access.historical_attempt_ledger_sha256
        and first.get("consumed_v2_custody_sha256") == access.consumed_v2_custody_sha256
        and second.get("consumed_v2_custody_sha256")
        == access.consumed_v2_custody_sha256
        and _identity_record_matches(first.get("model_binding"), binding_identities[0])
        and _identity_record_matches(second.get("model_binding"), binding_identities[1])
        and final_binding.get("suite_id") == manifest.get("suite_id")
        and first_binding.get("suite_id") == first.get("suite_id")
        and second_binding.get("suite_id") == second.get("suite_id")
        and final_binding.get("runtime_identity_sha256")
        == access.runtime_identity_sha256
        and first_binding.get("runtime_identity_sha256")
        == access.runtime_identity_sha256
        and second_binding.get("runtime_identity_sha256")
        == access.runtime_identity_sha256
        and type(configured_model) is str
        and first_binding.get("configured_model") == configured_model
        and second_binding.get("configured_model") == configured_model
        and type(access.concrete_model_revision) is str
        and bool(access.concrete_model_revision)
        and final_binding.get("reported_model_revision")
        == access.concrete_model_revision
        and first_binding.get("reported_model_revision")
        == access.concrete_model_revision
        and second_binding.get("reported_model_revision")
        == access.concrete_model_revision
        and access.concrete_model_revision != configured_model
        and _sealed_completed_stage_matches(
            first_path,
            completion_identities[0],
            access.prerequisite_retained_artifacts[0],
        )
        and _sealed_completed_stage_matches(
            second_path,
            completion_identities[1],
            access.prerequisite_retained_artifacts[1],
        )
    )


@dataclass(frozen=True, slots=True, init=False)
class QualificationFinalFixtureAccess:
    stage_path: Path
    start_identity: QualificationArtifactIdentity
    store_root: Path
    manifest_identity: QualificationArtifactIdentity
    final_runtime_identity: QualificationArtifactIdentity
    final_model_binding_identity: QualificationArtifactIdentity
    prerequisite_completion_identities: tuple[
        QualificationArtifactIdentity,
        QualificationArtifactIdentity,
    ]
    prerequisite_model_binding_identities: tuple[
        QualificationArtifactIdentity,
        QualificationArtifactIdentity,
    ]
    prerequisite_retained_artifacts: tuple[
        tuple[QualificationArtifactIdentity, ...],
        tuple[QualificationArtifactIdentity, ...],
    ]
    source_revision: str
    runtime_identity_sha256: str
    concrete_model_revision: str
    historical_attempt_ledger_sha256: str
    consumed_v2_custody_sha256: str
    schedule: tuple[tuple[str, int], ...]
    _seal: object = field(repr=False, compare=False)

    def __init__(
        self,
        stage_path: Path,
        start_identity: QualificationArtifactIdentity,
        store_root: Path,
        *,
        manifest_identity: QualificationArtifactIdentity,
        final_runtime_identity: QualificationArtifactIdentity,
        final_model_binding_identity: QualificationArtifactIdentity,
        prerequisite_completion_identities: tuple[
            QualificationArtifactIdentity,
            QualificationArtifactIdentity,
        ],
        prerequisite_model_binding_identities: tuple[
            QualificationArtifactIdentity,
            QualificationArtifactIdentity,
        ],
        prerequisite_retained_artifacts: tuple[
            tuple[QualificationArtifactIdentity, ...],
            tuple[QualificationArtifactIdentity, ...],
        ],
        source_revision: str,
        runtime_identity_sha256: str,
        concrete_model_revision: str,
        historical_attempt_ledger_sha256: str,
        consumed_v2_custody_sha256: str,
        schedule: tuple[tuple[str, int], ...],
        _seal: object,
    ) -> None:
        if _seal is not _FINAL_ACCESS_SEAL:
            raise TypeError("final fixture access is issued only after stage start")
        object.__setattr__(self, "stage_path", stage_path)
        object.__setattr__(self, "start_identity", start_identity)
        object.__setattr__(self, "store_root", store_root)
        object.__setattr__(self, "manifest_identity", manifest_identity)
        object.__setattr__(self, "final_runtime_identity", final_runtime_identity)
        object.__setattr__(
            self, "final_model_binding_identity", final_model_binding_identity
        )
        object.__setattr__(
            self,
            "prerequisite_completion_identities",
            prerequisite_completion_identities,
        )
        object.__setattr__(
            self,
            "prerequisite_model_binding_identities",
            prerequisite_model_binding_identities,
        )
        object.__setattr__(
            self,
            "prerequisite_retained_artifacts",
            prerequisite_retained_artifacts,
        )
        object.__setattr__(self, "source_revision", source_revision)
        object.__setattr__(self, "runtime_identity_sha256", runtime_identity_sha256)
        object.__setattr__(self, "concrete_model_revision", concrete_model_revision)
        object.__setattr__(
            self,
            "historical_attempt_ledger_sha256",
            historical_attempt_ledger_sha256,
        )
        object.__setattr__(
            self,
            "consumed_v2_custody_sha256",
            consumed_v2_custody_sha256,
        )
        object.__setattr__(self, "schedule", schedule)
        object.__setattr__(self, "_seal", _seal)


def _issue_final_fixture_access(
    stage_path: Path,
    start_identity: QualificationArtifactIdentity,
    store_root: Path,
    *,
    manifest_identity: QualificationArtifactIdentity,
    final_runtime_identity: QualificationArtifactIdentity,
    final_model_binding_identity: QualificationArtifactIdentity,
    prerequisite_completion_identities: tuple[
        QualificationArtifactIdentity,
        QualificationArtifactIdentity,
    ],
    prerequisite_model_binding_identities: tuple[
        QualificationArtifactIdentity,
        QualificationArtifactIdentity,
    ],
    prerequisite_retained_artifacts: tuple[
        tuple[QualificationArtifactIdentity, ...],
        tuple[QualificationArtifactIdentity, ...],
    ],
    source_revision: str,
    runtime_identity_sha256: str,
    concrete_model_revision: str,
    historical_attempt_ledger_sha256: str,
    consumed_v2_custody_sha256: str,
    schedule: tuple[tuple[str, int], ...],
) -> QualificationFinalFixtureAccess:
    path = Path(stage_path)
    root = Path(store_root)
    if path.name != QualificationProtocolStage.FINAL_HOLDOUT.value:
        raise ValueError(
            "final fixture authorization requires the consumed final stage"
        )
    if path != root / QualificationProtocolStage.FINAL_HOLDOUT.value:
        raise ValueError("final fixture authorization escaped its artifact store")
    access = QualificationFinalFixtureAccess(
        path,
        start_identity,
        root,
        manifest_identity=manifest_identity,
        final_runtime_identity=final_runtime_identity,
        final_model_binding_identity=final_model_binding_identity,
        prerequisite_completion_identities=prerequisite_completion_identities,
        prerequisite_model_binding_identities=(prerequisite_model_binding_identities),
        prerequisite_retained_artifacts=prerequisite_retained_artifacts,
        source_revision=source_revision,
        runtime_identity_sha256=runtime_identity_sha256,
        concrete_model_revision=concrete_model_revision,
        historical_attempt_ledger_sha256=historical_attempt_ledger_sha256,
        consumed_v2_custody_sha256=consumed_v2_custody_sha256,
        schedule=schedule,
        _seal=_FINAL_ACCESS_SEAL,
    )
    if not _final_access_bindings_match(access):
        raise ValueError(
            "final fixture authorization is not bound to sealed prerequisites"
        )
    return access


@dataclass(slots=True)
class _FinalFixtureSession:
    access: QualificationFinalFixtureAccess
    next_index: int = 0


@dataclass(frozen=True, slots=True)
class _JournaledHandler:
    source_name: str
    source_version: str
    destination_name: str
    handler: Callable[[BoundProbe], Awaitable[ProbeObservation]] = field(
        repr=False, compare=False
    )
    journal: _ObservationJournal = field(repr=False, compare=False)
    projection: Callable[[ProbeObservation], ProbeObservation] = field(
        repr=False, compare=False
    )

    async def __call__(self, probe: BoundProbe) -> ProbeObservation:
        translated = probe.model_copy(
            update={
                "capability_name": self.source_name,
                "capability_version": self.source_version,
            }
        )
        observation = self.projection(await self.handler(translated))
        self.journal.record(self.destination_name, observation)
        return observation


def _unchanged(observation: ProbeObservation) -> ProbeObservation:
    return observation


def _weak_storage(observation: ProbeObservation) -> ProbeObservation:
    payload = observation.payload
    return ProbeObservation(
        observed_at=observation.observed_at,
        payload={
            "object_observed": payload.get("object_metadata") is not None,
            "receipt_observed": payload.get("receipt") is not None,
        },
    )


def _weak_firestore(observation: ProbeObservation) -> ProbeObservation:
    payload = observation.payload
    documents = payload.get("documents")
    document_count = len(documents) if isinstance(documents, list) else 0
    return ProbeObservation(
        observed_at=observation.observed_at,
        payload={
            "manifest_observed": payload.get("manifest") is not None,
            "document_count_band": "NONE" if document_count == 0 else "SOME",
        },
    )


@dataclass(frozen=True, slots=True)
class _AliasNormalizer:
    source_name: str
    source_version: str
    normalizer: Callable[[RuleInput], RuleObservation] = field(
        repr=False, compare=False
    )

    def __call__(self, rule_input: RuleInput) -> RuleObservation:
        request = rule_input.request
        translated_request = ProbeRequest(
            schema_version=PROBE_REQUEST_VERSION,
            capability_name=self.source_name,
            capability_version=self.source_version,
            relevant_effect_ids=request.relevant_effect_ids,
            arguments=request.arguments,
            rationale="Normalize one frozen qualification observation.",
        )
        return self.normalizer(
            RuleInput(
                envelope=rule_input.envelope,
                request=translated_request,
                observation=rule_input.observation,
                retrieved_at=rule_input.retrieved_at,
            )
        )


@dataclass(frozen=True, slots=True)
class _WeakNormalizer:
    source_record: str

    def __call__(self, rule_input: RuleInput) -> RuleObservation:
        observation = ProbeObservation.model_validate_json(rule_input.observation)
        return RuleObservation(
            target=rule_input.envelope.target,
            source_record=self.source_record,
            observed_at=observation.observed_at,
            effect_assertions=tuple(
                EffectAssertion(
                    effect_id=effect_id,
                    state=EffectAssertionState.UNVERIFIED,
                )
                for effect_id in rule_input.request.relevant_effect_ids
            ),
            verdict=RuleVerdict.ABSENCE_ONLY,
        )


def _aliased_capability(
    registration: CapabilityRegistration,
    *,
    destination_name: str,
    journal: _ObservationJournal,
    weak_projection: Callable[[ProbeObservation], ProbeObservation] | None = None,
) -> CapabilityRegistration:
    capability = registration.capability
    handler = registration.handler
    if handler is None:
        raise ValueError("qualification source capability is not executable")
    return CapabilityRegistration(
        capability=ObservationCapability.model_validate(
            capability.model_dump(mode="python") | {"name": destination_name}
        ),
        semantics=registration.semantics,
        enabled=registration.enabled,
        argument_byte_ceiling=registration.argument_byte_ceiling,
        max_invocations=1,
        handler=_JournaledHandler(
            source_name=capability.name,
            source_version=capability.version,
            destination_name=destination_name,
            handler=handler,
            journal=journal,
            projection=weak_projection or _unchanged,
        ),
    )


def _aliased_rule(
    registration: TargetRuleRegistration,
    *,
    destination_name: str,
    manifest: QualificationSuiteManifest,
    weak: bool,
) -> TargetRuleRegistration:
    descriptor = registration.descriptor
    return TargetRuleRegistration(
        descriptor=TargetRuleDescriptor(
            target_kind=descriptor.target_kind,
            capability_name=destination_name,
            capability_version=descriptor.capability_version,
            authority_policy_version=manifest.authority_policy_version,
            classification_policy_version=manifest.classification_policy_version,
            source=_WEAK_SOURCE if weak else descriptor.source,
            adapter_version=(
                _WEAK_ADAPTER_VERSION if weak else descriptor.adapter_version
            ),
        ),
        normalizer=(
            _WeakNormalizer(f"qualification-{destination_name}")
            if weak
            else _AliasNormalizer(
                descriptor.capability_name,
                descriptor.capability_version,
                registration.normalizer,
            )
        ),
    )


@dataclass(frozen=True, slots=True)
class _SemanticStateReader:
    handlers: tuple[
        tuple[Callable[[BoundProbe], Awaitable[ProbeObservation]], BoundProbe], ...
    ] = field(repr=False, compare=False)
    private_paths: tuple[Path, ...] = field(default=(), repr=False, compare=False)

    async def sha256(self) -> str:
        payloads = []
        for handler, probe in self.handlers:
            observation = await handler(probe)
            payloads.append(observation.payload)
        private = []
        for path in self.private_paths:
            private.append(hashlib.sha256(path.read_bytes()).hexdigest())
        return hashlib.sha256(
            canonical_json_value_bytes(
                {"private": private, "product_visible": payloads}
            )
        ).hexdigest()


@dataclass(frozen=True, slots=True)
class PreparedQualificationFixture:
    case: QualificationCaseDefinition
    envelope: ExecutionEnvelope
    capabilities: CapabilityRegistry = field(repr=False, compare=False)
    rules: TargetRuleRegistry = field(repr=False, compare=False)
    fixed_plan: FixedProbePlan
    adaptive_policy: AdaptiveInvestigationPolicy
    catalog_sha256: str
    rules_sha256: str
    _journal: _ObservationJournal = field(repr=False, compare=False)
    _state_reader: _SemanticStateReader = field(repr=False, compare=False)
    _controller_time: datetime = field(repr=False, compare=False)
    _real_monotonic: bool = field(repr=False, compare=False)
    _cleanup: Callable[[], None] = field(repr=False, compare=False)

    def begin_lane(self, strategy: str) -> None:
        self._journal.begin(strategy)

    def end_lane(self, strategy: str) -> tuple[QualificationRawObservation, ...]:
        return self._journal.end(strategy)

    async def semantic_state_sha256(self) -> str:
        return await self._state_reader.sha256()

    def new_controller_clock(self) -> _ControllerClock:
        clock_type = _LiveControllerClock if self._real_monotonic else _ControllerClock
        return clock_type(self._controller_time)

    def cleanup(self) -> None:
        self._cleanup()


def _final_fixture_id(fixture_id: str) -> str:
    for prefix in ("dev1-", "dev2-"):
        if fixture_id.startswith(prefix):
            return fixture_id[len(prefix) :]
    return fixture_id


_DEVELOPMENT_FIRESTORE_EFFECTS = {
    QualificationProtocolStage.DEVELOPMENT_1: {
        "firestore-canonical-conditional-partial": (FIRESTORE_BUSINESS_EFFECT_IDS[0],),
        "firestore-evidence-availability-conditional": (
            FIRESTORE_BUSINESS_EFFECT_IDS[2],
        ),
        "firestore-authoritative-manifest-fast-path": (
            FIRESTORE_BUSINESS_EFFECT_IDS[1],
            FIRESTORE_BUSINESS_EFFECT_IDS[2],
        ),
    },
    QualificationProtocolStage.DEVELOPMENT_2: {
        "firestore-canonical-conditional-partial": (
            FIRESTORE_BUSINESS_EFFECT_IDS[1],
            FIRESTORE_BUSINESS_EFFECT_IDS[2],
        ),
        "firestore-evidence-availability-conditional": (
            FIRESTORE_BUSINESS_EFFECT_IDS[0],
            FIRESTORE_BUSINESS_EFFECT_IDS[2],
        ),
        "firestore-authoritative-manifest-fast-path": (
            FIRESTORE_BUSINESS_EFFECT_IDS[0],
            FIRESTORE_BUSINESS_EFFECT_IDS[1],
        ),
    },
}


def _recipe_for_stage(
    stage: QualificationProtocolStage,
    fixture_id: str,
) -> _FixtureRecipe | None:
    final_id = _final_fixture_id(fixture_id)
    base = _FIXTURE_RECIPES.get(final_id)
    if base is None:
        return None
    if stage is QualificationProtocolStage.FINAL_HOLDOUT:
        return base if fixture_id == final_id else None
    expected_prefix = (
        "dev1-" if stage is QualificationProtocolStage.DEVELOPMENT_1 else "dev2-"
    )
    if fixture_id != f"{expected_prefix}{final_id}":
        return None
    cohort_name = (
        "development-one"
        if stage is QualificationProtocolStage.DEVELOPMENT_1
        else "development-two"
    )
    capabilities = tuple(
        replace(item, name=item.name.replace("qualification-", f"{cohort_name}-"))
        for item in base.capabilities
    )
    renamed = {
        old.name: new.name
        for old, new in zip(base.capabilities, capabilities, strict=True)
    }
    selected = _DEVELOPMENT_FIRESTORE_EFFECTS[stage].get(final_id)
    hidden = (
        HiddenOrderOutcome.COMMIT
        if stage is QualificationProtocolStage.DEVELOPMENT_1
        else HiddenOrderOutcome.DISCARD
    )
    return _FixtureRecipe(
        fixture_id=fixture_id,
        cohort=stage,
        classification=base.classification,
        capabilities=capabilities,
        fixed_order=tuple(renamed[item] for item in base.fixed_order),
        selected_effect_ids=selected,
        sandbox_hidden_outcome=hidden,
    )


def _expectation(
    case_id: str,
    scenario_name: str,
    scenario_version: str,
    fixture_id: str,
    seed: int,
    classification: Classification,
):
    from reconcile.contracts import PreregisteredExpectedClassification

    material = {
        "case_id": case_id,
        "expected_classification": classification.value,
        "fixture_id": fixture_id,
        "scenario": {"name": scenario_name, "version": scenario_version},
        "seed": seed,
    }
    return PreregisteredExpectedClassification(
        registration_id=f"{case_id}-expectation",
        metadata_sha256=hashlib.sha256(
            canonical_json_value_bytes(material)
        ).hexdigest(),
        expected_classification=classification,
    )


def _development_cases(
    stage: QualificationProtocolStage,
    final_cases: tuple[QualificationCaseDefinition, ...],
) -> tuple[QualificationCaseDefinition, ...]:
    if stage is QualificationProtocolStage.FINAL_HOLDOUT:
        return final_cases
    cycle = 1 if stage is QualificationProtocolStage.DEVELOPMENT_1 else 2
    seed_offset = 10_001 if cycle == 1 else 20_002
    cases = []
    for index, case in enumerate(final_cases, start=1):
        case_id = f"d{cycle}{index:02d}-{case.case_id[4:]}"
        fixture_id = f"dev{cycle}-{case.fixture_id}"
        seed = case.seed + seed_offset
        expectation = None
        if case.expectation is not None:
            expectation = _expectation(
                case_id,
                case.scenario.name,
                case.scenario.version,
                fixture_id,
                seed,
                case.expectation.expected_classification,
            )
        cases.append(
            QualificationCaseDefinition(
                case_id=case_id,
                scenario=case.scenario,
                fixture_id=fixture_id,
                seed=seed,
                role=case.role,
                evidence_profile=case.evidence_profile,
                opportunity=case.opportunity,
                expectation=expectation,
                evidence_budget=case.evidence_budget,
            )
        )
    return tuple(cases)


def qualification_cases_for_stage(
    stage: QualificationProtocolStage,
    final_cases: tuple[QualificationCaseDefinition, ...],
) -> tuple[QualificationCaseDefinition, ...]:
    if type(stage) is not QualificationProtocolStage:
        raise TypeError("qualification stage must be exact")
    return _development_cases(stage, final_cases)


def _request(case: QualificationCaseDefinition, repetition: int) -> ScenarioRunRequest:
    suffix = f"{case.case_id}-r{repetition}"
    return ScenarioRunRequest(
        schema_version=SCENARIO_RUN_REQUEST_VERSION,
        scenario=case.scenario,
        run_id=f"run-{suffix}",
        investigation_id=f"investigation-{suffix}",
        operation_id=f"operation-{suffix}",
        invocation_id=f"invocation-{suffix}",
        function_call_id=f"function-{suffix}",
        seed=case.seed,
        fault=ScenarioFaultInstruction(
            point=ScenarioFaultPoint.POST_COMMIT,
            action=ScenarioFaultAction.INTERRUPT_PROCESS,
        ),
    )


@dataclass(frozen=True, slots=True)
class _MaterializedScenario:
    envelope: ExecutionEnvelope
    source_capabilities: dict[str, CapabilityRegistration] = field(
        repr=False, compare=False
    )
    source_rules: dict[str, TargetRuleRegistration] = field(repr=False, compare=False)
    state_reader: _SemanticStateReader = field(repr=False, compare=False)
    cleanup: Callable[[], None] = field(repr=False, compare=False)


def _bound_probe(
    envelope: ExecutionEnvelope,
    registration: CapabilityRegistration,
) -> BoundProbe:
    capability = registration.capability
    return BoundProbe(
        investigation_id=envelope.investigation_id,
        operation_id=envelope.operation_id,
        capability_name=capability.name,
        capability_version=capability.version,
        target=envelope.target,
        relevant_effect_ids=tuple(item.effect_id for item in envelope.expected_effects),
        arguments={},
        timeout_ms=capability.timeout_ms,
        result_byte_ceiling=capability.result_byte_ceiling,
    )


def _materialize_scenario(
    workspace: Path,
    case: QualificationCaseDefinition,
    repetition: int,
    recipe: _FixtureRecipe,
) -> _MaterializedScenario:
    workspace.mkdir(mode=0o700, parents=True, exist_ok=True)
    request = _request(case, repetition)
    stem = f"{case.fixture_id}-r{repetition}"
    base_time = datetime(2026, 1, 1, tzinfo=UTC) + timedelta(
        seconds=case.seed * 10 + repetition
    )
    target_clock = _FixedClock(base_time)
    observation_clock = _FixedClock(base_time + timedelta(seconds=2))
    runner = ScenarioRunner(clock=_StepClock(base_time + timedelta(seconds=1)))
    private_paths: tuple[Path, ...] = ()
    database_paths: tuple[Path, ...]
    if case.scenario.name == "storage-object":
        database_path = workspace / f"{stem}.sqlite3"
        database_paths = (database_path,)
        definition = StorageScenarioDefinition(
            database_path,
            invoked_at=base_time,
            target_clock=target_clock,
        )
        result = runner.run(request, definition)
        read_target = LocalStorageReadTarget(database_path)
        source_capabilities = {
            "storage": build_storage_capability_registration(
                read_target=read_target,
                target=result.execution_envelope.target,  # type: ignore[union-attr]
                clock=observation_clock,
            )
        }
        source_rules = {"storage": build_storage_rule_registration()}
    elif case.scenario.name == "firestore-business-operation":
        database_path = workspace / f"{stem}.sqlite3"
        database_paths = (database_path,)
        definition = FirestoreBusinessScenarioDefinition(
            database_path,
            selected_effect_ids=recipe.selected_effect_ids,
            invoked_at=base_time,
            target_clock=target_clock,
        )
        result = runner.run(request, definition)
        read_target = LocalFirestoreReadTarget(database_path)
        source_capabilities = {
            "firestore": build_firestore_business_capability_registration(
                read_target=read_target,
                target=result.execution_envelope.target,  # type: ignore[union-attr]
                clock=observation_clock,
            )
        }
        source_rules = {"firestore": build_firestore_business_rule_registration()}
    elif case.scenario.name == "sandbox-order-unknown":
        private_path = workspace / f"{stem}-private.sqlite3"
        observation_path = workspace / f"{stem}-observations.sqlite3"
        database_paths = (private_path, observation_path)
        definition = SandboxOrderScenarioDefinition(
            private_path,
            observation_path,
            hidden_outcome=recipe.sandbox_hidden_outcome,
            invoked_at=base_time,
            target_clock=target_clock,
        )
        result = runner.run(request, definition)
        read_target = LocalOrderReadTarget(observation_path)
        target = result.execution_envelope.target  # type: ignore[union-attr]
        source_capabilities = {
            "sandbox-ingress": build_sandbox_order_ingress_capability_registration(
                read_target=read_target,
                target=target,
                clock=observation_clock,
            ),
            "sandbox-aggregate": (
                build_sandbox_order_aggregate_capability_registration(
                    read_target=read_target,
                    target=target,
                    clock=observation_clock,
                )
            ),
        }
        source_rules = {
            "sandbox-ingress": build_sandbox_order_ingress_rule_registration(),
            "sandbox-aggregate": build_sandbox_order_aggregate_rule_registration(),
        }
        private_paths = (private_path,)
    else:
        raise ValueError("qualification case references an unsupported scenario")
    envelope = result.execution_envelope
    if envelope is None:
        raise RuntimeError("qualification scenario did not produce ambiguity")
    state_handlers = []
    for registration in source_capabilities.values():
        if registration.handler is None:
            raise RuntimeError("qualification state reader is unavailable")
        state_handlers.append(
            (registration.handler, _bound_probe(envelope, registration))
        )
    cleaned = False

    def cleanup() -> None:
        nonlocal cleaned
        if cleaned:
            raise RuntimeError("qualification fixture cleanup cannot be replayed")
        cleaned = True
        cleanup_request = runner.build_cleanup_request(request, result)
        cleanup_result = runner.cleanup(cleanup_request, definition)
        if cleanup_result.disposition not in {
            ScenarioCleanupDisposition.CLEANED,
            ScenarioCleanupDisposition.ALREADY_CLEAN,
        }:
            raise RuntimeError("qualification fixture cleanup failed")
        for database_path in database_paths:
            if database_path.parent != workspace:
                raise RuntimeError("qualification runtime path escaped its workspace")
            for suffix in ("", "-shm", "-wal"):
                candidate = Path(f"{database_path}{suffix}")
                try:
                    candidate.unlink()
                except FileNotFoundError:
                    pass
                if candidate.exists():
                    raise RuntimeError("qualification runtime database was retained")
        if any(workspace.iterdir()):
            raise RuntimeError("qualification fixture retained runtime files")
        workspace.rmdir()

    return _MaterializedScenario(
        envelope=envelope,
        source_capabilities=source_capabilities,
        source_rules=source_rules,
        state_reader=_SemanticStateReader(tuple(state_handlers), private_paths),
        cleanup=cleanup,
    )


class QualificationFixtureRegistry:
    def __init__(
        self,
        stage: QualificationProtocolStage,
        cases: tuple[QualificationCaseDefinition, ...],
        *,
        workspace: str | Path,
        real_monotonic: bool = False,
        _final_session: _FinalFixtureSession | None = None,
        _seal: object | None = None,
    ) -> None:
        self.stage = stage
        self._workspace = Path(workspace)
        if stage is QualificationProtocolStage.FINAL_HOLDOUT and (
            _seal is not _FINAL_ACCESS_SEAL or _final_session is None
        ):
            raise RuntimeError("final fixture registry is created only by its store")
        if stage is not QualificationProtocolStage.FINAL_HOLDOUT and (
            _final_session is not None or _seal is not None
        ):
            raise RuntimeError("development fixtures cannot carry final access")
        self._final_session = _final_session
        self._real_monotonic = real_monotonic
        self._cases = {case.fixture_id: case for case in cases}
        if len(self._cases) != len(cases):
            raise ValueError("qualification fixtures must be unique")
        for case in cases:
            recipe = _recipe_for_stage(stage, case.fixture_id)
            if recipe is None:
                raise ValueError("qualification fixture has no real scenario recipe")
            expected = (
                None
                if case.expectation is None
                else case.expectation.expected_classification
            )
            if recipe.classification is not expected:
                raise ValueError(
                    "qualification fixture truth contradicts preregistration"
                )

    @classmethod
    def _from_store(
        cls,
        cases: tuple[QualificationCaseDefinition, ...],
        *,
        workspace: str | Path,
        session: _FinalFixtureSession,
        real_monotonic: bool,
    ) -> QualificationFixtureRegistry:
        return cls(
            QualificationProtocolStage.FINAL_HOLDOUT,
            cases,
            workspace=workspace,
            real_monotonic=real_monotonic,
            _final_session=session,
            _seal=_FINAL_ACCESS_SEAL,
        )

    @property
    def fixture_ids(self) -> tuple[str, ...]:
        return tuple(sorted(self._cases))

    def cleanup_workspace(self) -> None:
        if not self._workspace.exists():
            return
        for path in self._workspace.iterdir():
            if (
                path.is_symlink()
                or not path.is_file()
                or not path.name.endswith((".sqlite3", ".sqlite3-shm", ".sqlite3-wal"))
            ):
                raise RuntimeError("qualification runtime workspace is unsafe to purge")
            path.unlink()
        if any(self._workspace.iterdir()):
            raise RuntimeError("qualification runtime workspace could not be purged")
        self._workspace.rmdir()

    def _validate_final_access(
        self,
        manifest: QualificationSuiteManifest,
        case: QualificationCaseDefinition,
        repetition: int,
    ) -> None:
        if self.stage is not QualificationProtocolStage.FINAL_HOLDOUT:
            return
        session = self._final_session
        access = None if session is None else session.access
        manifest_payload = canonical_json_bytes(manifest)
        if (
            access is None
            or access._seal is not _FINAL_ACCESS_SEAL
            or access.store_root / self.stage.value != access.stage_path
            or access.source_revision != manifest.source_revision
            or access.manifest_identity.artifact_id != "manifest"
            or len(manifest_payload) != access.manifest_identity.byte_count
            or hashlib.sha256(manifest_payload).hexdigest()
            != access.manifest_identity.sha256
            or not _final_access_bindings_match(access)
            or session.next_index >= len(access.schedule)
            or access.schedule[session.next_index] != (case.case_id, repetition)
        ):
            raise RuntimeError(
                "final fixtures remain untouched until final stage start"
            )
        session.next_index += 1

    def prepare(
        self,
        manifest: QualificationSuiteManifest,
        case: QualificationCaseDefinition,
        repetition: int,
    ) -> PreparedQualificationFixture:
        registered = self._cases.get(case.fixture_id)
        if (
            registered != case
            or case not in manifest.cases
            or not 1 <= repetition <= manifest.repetition_count
        ):
            raise ValueError("qualification fixture binding changed")
        recipe = _recipe_for_stage(self.stage, case.fixture_id)
        if recipe is None:
            raise ValueError("qualification fixture has no stage-specific recipe")
        self._validate_final_access(manifest, case, repetition)
        materialized = _materialize_scenario(self._workspace, case, repetition, recipe)
        source_context = materialized.envelope.context
        enabled = tuple(
            CapabilityRef(name=item.name, version=_CAPABILITY_VERSION)
            for item in recipe.capabilities
        )
        context = EnvelopeContext(
            invocation=source_context.invocation,
            enabled_capabilities=enabled,
            correlation_fields=source_context.correlation_fields,
            evidence_budget=case.evidence_budget,
            freshness=source_context.freshness,
            policies=PolicyReferences(
                authority=manifest.authority_policy_version,
                classification=manifest.classification_policy_version,
                action=manifest.action_policy_version,
            ),
        )
        envelope = decode_contract(
            canonical_json_bytes(
                materialized.envelope.model_copy(update={"context": context})
            ),
            ExecutionEnvelope,
        )
        journal = _ObservationJournal()
        capabilities = CapabilityRegistry()
        rules = TargetRuleRegistry()
        requests = {}
        for item in recipe.capabilities:
            source_capability = materialized.source_capabilities[item.source]
            source_rule = materialized.source_rules[item.source]
            weak_projection = None
            if item.kind is _CapabilityKind.WEAK:
                if item.source == "storage":
                    weak_projection = _weak_storage
                elif item.source == "firestore":
                    weak_projection = _weak_firestore
            aliased = _aliased_capability(
                source_capability,
                destination_name=item.name,
                journal=journal,
                weak_projection=weak_projection,
            )
            capabilities.register(aliased)
            rules.register(
                _aliased_rule(
                    source_rule,
                    destination_name=item.name,
                    manifest=manifest,
                    weak=item.kind is _CapabilityKind.WEAK
                    and item.source in {"storage", "firestore"},
                )
            )
            requests[item.name] = ProbeRequest(
                schema_version=PROBE_REQUEST_VERSION,
                capability_name=item.name,
                capability_version=_CAPABILITY_VERSION,
                relevant_effect_ids=tuple(
                    effect.effect_id for effect in envelope.expected_effects
                ),
                arguments={},
                rationale="Execute one frozen real read-only qualification probe.",
            )
        sufficient = (
            ()
            if recipe.classification in {None, Classification.UNKNOWN}
            else (recipe.classification,)
        )
        fixed_plan = FixedProbePlan(
            name=_FIXED_PLAN_NAME,
            version=_QUALIFICATION_VERSION,
            steps=tuple(
                FixedProbeStep(request=requests[name]) for name in recipe.fixed_order
            ),
            sufficient_classifications=sufficient,
        )
        adaptive_policy = AdaptiveInvestigationPolicy(
            name=_ADAPTIVE_POLICY_NAME,
            version=_QUALIFICATION_VERSION,
            sufficient_classifications=sufficient,
            max_turns=case.evidence_budget.max_probes,
            planner_timeout_ms=30_000,
            include_explanation=True,
        )
        capability_snapshots = capabilities.freeze()
        rule_snapshots = rules.freeze()
        catalog_material = [
            {
                "capability": item.capability.model_dump(mode="json"),
                "semantics": item.semantics.value,
                "enabled": item.enabled,
                "argument_byte_ceiling": item.argument_byte_ceiling,
                "max_invocations": item.max_invocations,
            }
            for item in capability_snapshots
        ]
        rule_material = [
            item.descriptor.model_dump(mode="json") for item in rule_snapshots
        ]
        return PreparedQualificationFixture(
            case=case,
            envelope=envelope,
            capabilities=capabilities,
            rules=rules,
            fixed_plan=fixed_plan,
            adaptive_policy=adaptive_policy,
            catalog_sha256=hashlib.sha256(
                canonical_json_value_bytes(catalog_material)
            ).hexdigest(),
            rules_sha256=hashlib.sha256(
                canonical_json_value_bytes(rule_material)
            ).hexdigest(),
            _journal=journal,
            _state_reader=materialized.state_reader,
            _controller_time=datetime(2026, 1, 1, tzinfo=UTC)
            + timedelta(seconds=case.seed * 10 + repetition + 3),
            _real_monotonic=self._real_monotonic,
            _cleanup=materialized.cleanup,
        )


__all__ = [
    "PreparedQualificationFixture",
    "QualificationFinalFixtureAccess",
    "QualificationFixtureRegistry",
    "QualificationProtocolStage",
    "QualificationRawObservation",
    "qualification_cases_for_stage",
]
