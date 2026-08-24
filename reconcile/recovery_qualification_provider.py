"""Deterministic provider and durable-store foundations for qualification runs.

The doubles in this module sit below the production Cloud Run and Firestore
adapters.  Qualification therefore exercises the same request construction,
provider-response validation, compare-and-swap, and error mapping used by the
hosted release-chain workflow without making external network calls.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import threading
from collections import deque
from collections.abc import Callable
from copy import deepcopy
from dataclasses import dataclass, replace
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from pathlib import Path
from typing import Any

from google.api_core import exceptions as api_exceptions
from google.cloud import run_v2
from google.protobuf import any_pb2

from reconcile.contracts import ActionPermitState
from reconcile.contracts.recovery_qualification import (
    RECOVERY_QUALIFICATION_SEEDS,
    RecoveryQualificationProviderMutations,
    RecoveryQualificationStorageBackend,
)
from reconcile.controller.permits import PermitAuthority
from reconcile.hosted.cloud_run_canary import (
    CLOUD_RUN_CANARY_HEALTH_VERSION,
    CloudRunCanaryAction,
    CloudRunCanaryActionAdapter,
    CloudRunCanaryFaultProxy,
    CloudRunCanaryReader,
    CloudRunCanaryTarget,
    CloudRunFaultMode,
)
from reconcile.hosted.firestore_cas import GoogleFirestoreCasStore
from reconcile.hosted.firestore_permits import FirestoreActionPermitStore
from reconcile.hosted.firestore_recovery_runs import FirestoreRecoveryRunStore
from reconcile.hosted.firestore_release import (
    FIRESTORE_RELEASE_RECORD_VERSION,
    FirestoreReleaseRecord,
    GoogleFirestoreReleaseTarget,
)
from reconcile.persistence.permits import ActionPermitStore
from reconcile.persistence.recovery_runs import RecoveryRunStore, SqliteRecoveryRunStore
from reconcile.persistence.sqlite_runtime import SqliteDurableRuntimeStore
from reconcile.recovery_qualification_fixtures import RecoveryQualificationFixture
from reconcile.recovery_scenario import ReleaseChainSettings

RECOVERY_QUALIFICATION_PROJECT = "qualification-project"
RECOVERY_QUALIFICATION_LOCATION = "us-central1"
RECOVERY_QUALIFICATION_SERVICE = "reconcile-canary"
RECOVERY_QUALIFICATION_BASELINE = "reconcile-canary-baseline"
RECOVERY_QUALIFICATION_SERVICE_URI = (
    "https://reconcile-canary-qualification-hash-uc.a.run.app"
)
RECOVERY_QUALIFICATION_PROVIDER_EPOCH = datetime(2026, 8, 23, tzinfo=UTC)


class RecoveryQualificationStageBehavior(StrEnum):
    """Provider state left by an accepted stage request."""

    COMMITTED = "committed"
    PENDING = "pending"
    TERMINAL_FAILED = "terminal-failed"
    CONFLICTING = "conflicting"
    ABSENT = "absent"


class RecoveryQualificationPromoteBehavior(StrEnum):
    """Provider state or precondition behavior for promotion."""

    COMMITTED = "committed"
    PENDING = "pending"
    CONFLICTING = "conflicting"
    STALE_PRECONDITION = "stale-precondition"


class RecoveryQualificationReleaseWriteBehavior(StrEnum):
    """SDK outcome for a Firestore release-record create."""

    COMMITTED = "committed"
    FAIL_BEFORE_COMMIT = "fail-before-commit"
    FAIL_AFTER_COMMIT = "fail-after-commit"
    CONFLICT = "conflict"


class UnsupportedRecoveryQualificationBehavior(RuntimeError):
    """The production provider has no faithful state for a fixture archetype."""


@dataclass(frozen=True, slots=True)
class RecoveryQualificationProviderScenario:
    """One deterministic script interpreted by the SDK-level doubles."""

    fault_mode: CloudRunFaultMode = CloudRunFaultMode.PASS_THROUGH
    stage_behavior: RecoveryQualificationStageBehavior = (
        RecoveryQualificationStageBehavior.COMMITTED
    )
    promote_behavior: RecoveryQualificationPromoteBehavior = (
        RecoveryQualificationPromoteBehavior.COMMITTED
    )
    cloud_reads_unavailable_after: CloudRunCanaryAction | None = None
    stale_cloud_observations: bool = False
    release_write_behavior: RecoveryQualificationReleaseWriteBehavior = (
        RecoveryQualificationReleaseWriteBehavior.COMMITTED
    )
    release_reads_unavailable: bool = False
    initial_service_generation: int = 1
    unsupported_reason: str | None = None


@dataclass(slots=True)
class RecoveryQualificationProviderCounters:
    """Observable call and accepted-mutation counts for one isolated lane."""

    stage_calls: int = 0
    promote_calls: int = 0
    record_calls: int = 0
    reset_calls: int = 0
    stage_accepts: int = 0
    promote_accepts: int = 0
    record_commits: int = 0
    reset_accepts: int = 0
    cloud_service_reads: int = 0
    cloud_revision_reads: int = 0
    cloud_revision_lists: int = 0
    cloud_operation_reads: int = 0
    cloud_health_reads: int = 0
    release_reads: int = 0
    release_deletes: int = 0
    cas_reads: int = 0
    cas_commits: int = 0
    cas_create_writes: int = 0
    cas_update_writes: int = 0

    @property
    def outbound_call_count(self) -> int:
        """Return qualification mutations, excluding cleanup reset calls."""

        return self.stage_calls + self.promote_calls + self.record_calls

    def provider_mutations(self) -> RecoveryQualificationProviderMutations:
        """Project the live counters into the public qualification contract."""

        return RecoveryQualificationProviderMutations(
            stage_calls=self.stage_calls,
            promote_calls=self.promote_calls,
            record_calls=self.record_calls,
            outbound_call_count=self.outbound_call_count,
        )


@dataclass(frozen=True, slots=True)
class RecoveryQualificationProviderSnapshot:
    """A lock-consistent, assertion-friendly view of provider-side effects."""

    archetype_id: str
    counters: RecoveryQualificationProviderCounters
    service_etag: str
    service_generation: int
    service_reconciling: bool
    staged_revision_exists: bool
    staged_revision_reconciling: bool | None
    staged_traffic_percent: int
    release_record_count: int


def _ready_condition() -> run_v2.Condition:
    return run_v2.Condition(
        type_="Ready",
        state=run_v2.Condition.State.CONDITION_SUCCEEDED,
    )


def _pending_condition() -> run_v2.Condition:
    return run_v2.Condition(
        type_="Ready",
        state=run_v2.Condition.State.CONDITION_RECONCILING,
    )


def _failed_condition() -> run_v2.Condition:
    return run_v2.Condition(
        type_="Ready",
        state=run_v2.Condition.State.CONDITION_FAILED,
    )


@dataclass(frozen=True, slots=True)
class _AcceptedOperation:
    name: str


@dataclass(frozen=True, slots=True)
class _OperationError:
    code: int = 0


@dataclass(frozen=True, slots=True)
class _CloudOperation:
    name: str
    metadata: any_pb2.Any
    response: any_pb2.Any
    done: bool
    error: _OperationError


def _packed_service(service: run_v2.Service) -> any_pb2.Any:
    value = any_pb2.Any()
    value.Pack(run_v2.Service.pb(run_v2.Service(service)))
    return value


class DeterministicCloudRunState:
    """Thread-safe in-memory Cloud Run state shared by action/read clients."""

    def __init__(
        self,
        *,
        settings: ReleaseChainSettings,
        scenario: RecoveryQualificationProviderScenario,
        counters: RecoveryQualificationProviderCounters,
    ) -> None:
        self.settings = settings
        self.scenario = scenario
        self.counters = counters
        if scenario.initial_service_generation < 1:
            raise ValueError("initial service generation must be positive")
        self.generation = scenario.initial_service_generation
        self.revision_read_count = 0
        self.service_read_count = 0
        self.pending_reset_reads = 0
        self.ready_on_revision_read: int | None = None
        self.health_ready = True
        self.revisions: dict[str, run_v2.Revision] = {}
        self.operations: dict[str, _CloudOperation] = {}
        self._pending_reset_traffic: tuple[run_v2.TrafficTargetStatus, ...] | None = (
            None
        )
        self._forced_unavailable = False
        self._promote_conflict_read_count = 0
        self._etag_invalidated = False
        self._crash_after_accept: set[CloudRunCanaryAction] = set()
        self._lock = threading.RLock()

        baseline = run_v2.Revision(
            name=self.revision_name(RECOVERY_QUALIFICATION_BASELINE),
            service=self.service_name,
            generation=1,
            observed_generation=1,
            containers=(
                run_v2.Container(
                    image=f"{self.image_repository}@{settings.image_digest}"
                ),
            ),
            conditions=(_ready_condition(),),
        )
        self.revisions[RECOVERY_QUALIFICATION_BASELINE] = baseline
        self.service = run_v2.Service(
            name=self.service_name,
            etag=f"etag-{self.generation}",
            generation=self.generation,
            observed_generation=self.generation,
            terminal_condition=_ready_condition(),
            reconciling=False,
            uri=RECOVERY_QUALIFICATION_SERVICE_URI,
            latest_ready_revision=RECOVERY_QUALIFICATION_BASELINE,
            template=run_v2.RevisionTemplate(
                containers=(
                    run_v2.Container(
                        image=f"{self.image_repository}@{settings.image_digest}"
                    ),
                )
            ),
            traffic_statuses=(
                run_v2.TrafficTargetStatus(
                    revision=RECOVERY_QUALIFICATION_BASELINE,
                    percent=100,
                ),
            ),
        )

    @property
    def service_name(self) -> str:
        return (
            f"projects/{self.settings.project}/locations/{self.settings.location}/"
            f"services/{self.settings.service}"
        )

    @property
    def image_repository(self) -> str:
        return (
            f"{self.settings.location}-docker.pkg.dev/{self.settings.project}/"
            "reconcile-p5/reconcile"
        )

    def revision_name(self, revision: str) -> str:
        return f"{self.service_name}/revisions/{revision}"

    def arm_crash_after_accept(self, action: CloudRunCanaryAction) -> None:
        """Raise cancellation once, after the selected provider update commits."""

        if type(action) is not CloudRunCanaryAction:
            raise TypeError("crash action must be exact")
        with self._lock:
            self._crash_after_accept.add(action)

    def force_reads_unavailable(self, enabled: bool = True) -> None:
        """Override all subsequent Cloud Run SDK reads for restart tests."""

        if type(enabled) is not bool:
            raise TypeError("provider availability flag must be exact")
        with self._lock:
            self._forced_unavailable = enabled

    def make_staged_revision_ready(self) -> None:
        """Converge a scripted pending stage without replacing its identity."""

        with self._lock:
            revision = self.revisions.get(self.settings.staged_revision)
            if revision is None:
                raise ValueError("staged revision is absent")
            revision.conditions = (_ready_condition(),)
            revision.reconciling = False
            revision.observed_generation = revision.generation
            self.health_ready = True

    def invalidate_service_etag(self) -> str:
        """Advance the provider ETag without changing traffic."""

        with self._lock:
            self.generation += 1
            self.service.generation = self.generation
            self.service.observed_generation = self.generation
            self.service.etag = f"etag-{self.generation}"
            return self.service.etag

    def provider_snapshot(
        self,
        *,
        archetype_id: str,
        release_record_count: int,
    ) -> RecoveryQualificationProviderSnapshot:
        """Capture Cloud Run state and counters under the provider lock."""

        with self._lock:
            staged = self.revisions.get(self.settings.staged_revision)
            traffic_percent = sum(
                int(item.percent)
                for item in self.service.traffic_statuses
                if item.revision == self.settings.staged_revision
            )
            return RecoveryQualificationProviderSnapshot(
                archetype_id=archetype_id,
                counters=deepcopy(self.counters),
                service_etag=self.service.etag,
                service_generation=self.service.generation,
                service_reconciling=self.service.reconciling,
                staged_revision_exists=staged is not None,
                staged_revision_reconciling=(
                    None if staged is None else staged.reconciling
                ),
                staged_traffic_percent=traffic_percent,
                release_record_count=release_record_count,
            )

    def _reads_unavailable(self) -> bool:
        if self._forced_unavailable:
            return True
        selected = self.scenario.cloud_reads_unavailable_after
        if selected is CloudRunCanaryAction.STAGE:
            return self.counters.stage_calls > 0
        if selected is CloudRunCanaryAction.PROMOTE:
            return self.counters.promote_calls > 0
        if selected is CloudRunCanaryAction.RESET:
            return self.counters.reset_calls > 0
        return False

    @staticmethod
    def _action_for(request: run_v2.UpdateServiceRequest) -> CloudRunCanaryAction:
        paths = tuple(request.update_mask.paths)
        if paths == ("template", "traffic"):
            return CloudRunCanaryAction.STAGE
        if paths != ("traffic",):
            raise api_exceptions.InvalidArgument("unsupported update mask")
        traffic = tuple(request.service.traffic)
        if (
            len(traffic) == 1
            and traffic[0].revision == RECOVERY_QUALIFICATION_BASELINE
            and traffic[0].percent == 100
        ):
            return CloudRunCanaryAction.RESET
        return CloudRunCanaryAction.PROMOTE

    @staticmethod
    def _traffic_statuses(
        traffic: object,
    ) -> tuple[run_v2.TrafficTargetStatus, ...]:
        values: list[run_v2.TrafficTargetStatus] = []
        for item in traffic:
            tag = str(getattr(item, "tag", ""))
            uri = (
                f"https://{tag}---"
                f"{RECOVERY_QUALIFICATION_SERVICE_URI.removeprefix('https://')}"
                if tag
                else ""
            )
            values.append(
                run_v2.TrafficTargetStatus(
                    revision=str(getattr(item, "revision", "")),
                    percent=int(getattr(item, "percent", 0)),
                    tag=tag,
                    uri=uri,
                )
            )
        return tuple(values)

    def _set_operation(
        self,
        *,
        operation_name: str,
        request_service: run_v2.Service,
        pending: bool,
        failed: bool,
    ) -> None:
        response = (
            any_pb2.Any() if failed or pending else _packed_service(request_service)
        )
        self.operations[operation_name] = _CloudOperation(
            name=operation_name,
            metadata=_packed_service(request_service),
            response=response,
            done=not pending,
            error=_OperationError(code=9 if failed else 0),
        )

    def _advance_service(self) -> None:
        self.generation += 1
        self.service.generation = self.generation
        self.service.observed_generation = self.generation
        self.service.etag = f"etag-{self.generation}"

    def _apply_stage(self, candidate: run_v2.Service) -> tuple[bool, bool]:
        behavior = self.scenario.stage_behavior
        if behavior is RecoveryQualificationStageBehavior.ABSENT:
            return False, False
        template = run_v2.RevisionTemplate(candidate.template)
        revision_name = template.revision
        pending = behavior is RecoveryQualificationStageBehavior.PENDING
        failed = behavior is RecoveryQualificationStageBehavior.TERMINAL_FAILED
        condition = (
            _pending_condition()
            if pending
            else _failed_condition()
            if failed
            else _ready_condition()
        )
        self.revisions[revision_name] = run_v2.Revision(
            name=self.revision_name(revision_name),
            service=self.service_name,
            generation=1,
            observed_generation=0 if pending else 1,
            labels=dict(template.labels),
            annotations=dict(template.annotations),
            containers=tuple(run_v2.Container(item) for item in template.containers),
            conditions=(condition,),
            reconciling=pending,
        )
        self.service.template = template
        if not pending and not failed:
            self.service.latest_ready_revision = revision_name
        self.service.traffic_statuses = self._traffic_statuses(candidate.traffic)
        self.service.reconciling = False
        self.service.terminal_condition = _ready_condition()
        self.health_ready = not (
            pending
            or failed
            or behavior is RecoveryQualificationStageBehavior.CONFLICTING
        )
        self._advance_service()
        return pending, failed

    def _apply_promote(self, candidate: run_v2.Service) -> tuple[bool, bool]:
        behavior = self.scenario.promote_behavior
        pending = behavior is RecoveryQualificationPromoteBehavior.PENDING
        if pending:
            self.service.reconciling = True
            self.service.terminal_condition = _pending_condition()
        else:
            self.service.traffic_statuses = self._traffic_statuses(candidate.traffic)
            self.service.reconciling = False
            self.service.terminal_condition = _ready_condition()
        self._advance_service()
        return pending, False

    def _apply_reset(self, candidate: run_v2.Service) -> tuple[bool, bool]:
        statuses = self._traffic_statuses(candidate.traffic)
        pending = self.pending_reset_reads > 0
        if pending:
            self._pending_reset_traffic = statuses
            self.service.reconciling = True
            self.service.terminal_condition = _pending_condition()
        else:
            self.service.traffic_statuses = statuses
            self.service.reconciling = False
            self.service.terminal_condition = _ready_condition()
        self._advance_service()
        return pending, False

    def update(self, request: run_v2.UpdateServiceRequest) -> _AcceptedOperation:
        """Apply one provider update atomically and return an SDK-shaped LRO."""

        action = self._action_for(request)
        with self._lock:
            if request.service.etag != self.service.etag:
                raise api_exceptions.FailedPrecondition("stale provider precondition")
            if action is CloudRunCanaryAction.STAGE:
                self.counters.stage_calls += 1
            elif action is CloudRunCanaryAction.PROMOTE:
                self.counters.promote_calls += 1
            else:
                self.counters.reset_calls += 1
            operation_number = (
                self.counters.stage_calls
                + self.counters.promote_calls
                + self.counters.reset_calls
            )
            operation_name = (
                f"projects/{self.settings.project}/locations/"
                f"{self.settings.location}/operations/op-{operation_number}"
            )
            candidate = run_v2.Service(request.service)
            if action is CloudRunCanaryAction.STAGE:
                pending, failed = self._apply_stage(candidate)
                accepted = (
                    self.scenario.stage_behavior
                    is not RecoveryQualificationStageBehavior.ABSENT
                )
                if accepted:
                    self.counters.stage_accepts += 1
                    self._set_operation(
                        operation_name=operation_name,
                        request_service=candidate,
                        pending=pending,
                        failed=failed,
                    )
            elif action is CloudRunCanaryAction.PROMOTE:
                pending, failed = self._apply_promote(candidate)
                self.counters.promote_accepts += 1
                self._set_operation(
                    operation_name=operation_name,
                    request_service=candidate,
                    pending=pending,
                    failed=failed,
                )
            else:
                pending, failed = self._apply_reset(candidate)
                self.counters.reset_accepts += 1
                self._set_operation(
                    operation_name=operation_name,
                    request_service=candidate,
                    pending=pending,
                    failed=failed,
                )
            if action in self._crash_after_accept:
                self._crash_after_accept.remove(action)
                raise asyncio.CancelledError
            return _AcceptedOperation(operation_name)

    def service_snapshot(self, *, evidence_read: bool) -> run_v2.Service:
        with self._lock:
            if self._reads_unavailable():
                raise api_exceptions.ServiceUnavailable("scripted unavailable")
            self.counters.cloud_service_reads += 1
            self.service_read_count += 1
            if (
                not evidence_read
                and self.scenario.promote_behavior
                is RecoveryQualificationPromoteBehavior.STALE_PRECONDITION
                and self.counters.stage_calls > 0
                and self.counters.promote_calls == 0
                and not self._etag_invalidated
            ):
                self.invalidate_service_etag()
                self._etag_invalidated = True
            if self._pending_reset_traffic is not None:
                self.pending_reset_reads -= 1
                if self.pending_reset_reads <= 0:
                    self.service.traffic_statuses = self._pending_reset_traffic
                    self._pending_reset_traffic = None
                    self.service.reconciling = False
                    self.service.terminal_condition = _ready_condition()
            if evidence_read and (
                (
                    self.scenario.promote_behavior
                    is RecoveryQualificationPromoteBehavior.CONFLICTING
                    and self.counters.promote_calls > 0
                )
                or (
                    self.scenario.stage_behavior
                    is RecoveryQualificationStageBehavior.CONFLICTING
                    and self.counters.stage_calls > 0
                )
            ):
                self._promote_conflict_read_count += 1
                # Both snapshots affirm the effect, but their provider ETags
                # disagree.  The admission path therefore retains both target-
                # authoritative reads while recovery proof validation rejects
                # the inconsistent same-resource history.
                snapshot = run_v2.Service(self.service)
                snapshot.etag = (
                    f"{self.service.etag}-conflict-"
                    f"{self._promote_conflict_read_count % 2}"
                )
                return snapshot
            return run_v2.Service(self.service)

    def revision_snapshot(self, revision: str) -> run_v2.Revision:
        with self._lock:
            if self._reads_unavailable():
                raise api_exceptions.ServiceUnavailable("scripted unavailable")
            self.counters.cloud_revision_reads += 1
            self.revision_read_count += 1
            if (
                self.ready_on_revision_read == self.revision_read_count
                and revision == self.settings.staged_revision
            ):
                self.make_staged_revision_ready()
            try:
                return run_v2.Revision(self.revisions[revision])
            except KeyError:
                raise api_exceptions.NotFound("scripted missing revision") from None

    def revision_inventory(self) -> tuple[run_v2.Revision, ...]:
        with self._lock:
            if self._reads_unavailable():
                raise api_exceptions.ServiceUnavailable("scripted unavailable")
            self.counters.cloud_revision_lists += 1
            return tuple(run_v2.Revision(item) for item in self.revisions.values())

    def operation_snapshot(self, name: str) -> _CloudOperation:
        with self._lock:
            if self._reads_unavailable():
                raise api_exceptions.ServiceUnavailable("scripted unavailable")
            self.counters.cloud_operation_reads += 1
            try:
                return self.operations[name]
            except KeyError:
                raise api_exceptions.NotFound("scripted missing operation") from None


class _CloudRunServicesClient:
    def __init__(
        self,
        state: DeterministicCloudRunState,
        *,
        evidence_read: bool,
    ) -> None:
        self._state = state
        self._evidence_read = evidence_read

    def get_service(self, **_kwargs: object) -> run_v2.Service:
        return self._state.service_snapshot(evidence_read=self._evidence_read)

    def update_service(self, **kwargs: object) -> _AcceptedOperation:
        request = kwargs.get("request")
        if not isinstance(request, run_v2.UpdateServiceRequest):
            raise api_exceptions.InvalidArgument("invalid update request")
        return self._state.update(request)

    def get_operation(self, **kwargs: object) -> _CloudOperation:
        request = kwargs.get("request")
        if not isinstance(request, dict) or type(request.get("name")) is not str:
            raise api_exceptions.InvalidArgument("invalid operation request")
        return self._state.operation_snapshot(request["name"])


class _CloudRunRevisionsClient:
    def __init__(self, state: DeterministicCloudRunState) -> None:
        self._state = state

    def list_revisions(self, **_kwargs: object) -> tuple[run_v2.Revision, ...]:
        return self._state.revision_inventory()

    def get_revision(self, **kwargs: object) -> run_v2.Revision:
        request = kwargs.get("request")
        name = getattr(request, "name", None)
        if type(name) is not str:
            raise api_exceptions.InvalidArgument("invalid revision request")
        return self._state.revision_snapshot(name.rsplit("/", 1)[-1])


class _CloudRunHealthClient:
    def __init__(
        self,
        state: DeterministicCloudRunState,
        counters: RecoveryQualificationProviderCounters,
    ) -> None:
        self._state = state
        self._counters = counters

    def get(self, **_kwargs: object) -> tuple[int, bytes]:
        with self._state._lock:
            if self._state._reads_unavailable():
                raise api_exceptions.ServiceUnavailable("scripted unavailable")
            self._counters.cloud_health_reads += 1
            if not self._state.health_ready:
                return 503, b"{}"
            return 200, json.dumps(
                {
                    "schema_version": CLOUD_RUN_CANARY_HEALTH_VERSION,
                    "release_id": self._state.settings.release_id,
                    "revision": self._state.settings.staged_revision,
                    "status": "READY",
                    "image_digest": self._state.settings.image_digest,
                    "configuration_sha256": (self._state.settings.configuration_sha256),
                },
                separators=(",", ":"),
                sort_keys=True,
            ).encode()


@dataclass(frozen=True, slots=True)
class _WriteOption:
    kind: str
    value: object


@dataclass(frozen=True, slots=True)
class _WriteResult:
    update_time: datetime


@dataclass(slots=True)
class _FirestoreSnapshot:
    reference: object
    exists: bool
    read_time: datetime
    update_time: datetime | None
    data: dict[str, Any] | None

    def to_dict(self) -> dict[str, Any] | None:
        return deepcopy(self.data)


class _ReleaseDocumentReference:
    def __init__(self, client: DeterministicFirestoreReleaseClient, path: str) -> None:
        self._client = client
        self.path = path

    async def get(self, **_kwargs: object) -> _FirestoreSnapshot:
        return self._client._get(self)

    async def create(
        self,
        document_data: dict[str, Any],
        **_kwargs: object,
    ) -> _WriteResult:
        return self._client._create(self, document_data)

    async def delete(
        self,
        option: object | None = None,
        **_kwargs: object,
    ) -> _WriteResult:
        return self._client._delete(self, option)


class DeterministicFirestoreReleaseClient:
    """Async Firestore document double beneath ``GoogleFirestoreReleaseTarget``."""

    def __init__(
        self,
        *,
        scenario: RecoveryQualificationProviderScenario,
        counters: RecoveryQualificationProviderCounters,
        clock: datetime,
    ) -> None:
        self.scenario = scenario
        self.counters = counters
        self._clock = clock
        self._documents: dict[str, tuple[dict[str, Any], datetime]] = {}
        self._forced_reads_unavailable = False
        self._crash_after_commit = False
        self._crash_after_attempt = False
        self._lock = threading.RLock()

    def document(self, *document_path: str) -> _ReleaseDocumentReference:
        return _ReleaseDocumentReference(self, "/".join(document_path))

    @staticmethod
    def write_option(**kwargs: object) -> _WriteOption:
        if set(kwargs) != {"last_update_time"}:
            raise ValueError("unsupported write option")
        return _WriteOption("last_update_time", kwargs["last_update_time"])

    def force_reads_unavailable(self, enabled: bool = True) -> None:
        if type(enabled) is not bool:
            raise TypeError("provider availability flag must be exact")
        with self._lock:
            self._forced_reads_unavailable = enabled

    def arm_crash_after_commit(self) -> None:
        """Interrupt one record write after the provider durably accepted it."""

        with self._lock:
            self._crash_after_commit = True

    def arm_crash_after_attempt(self) -> None:
        """Interrupt once after the provider has evaluated a create request."""

        with self._lock:
            self._crash_after_attempt = True

    @property
    def document_count(self) -> int:
        with self._lock:
            return len(self._documents)

    def seed(self, record: FirestoreReleaseRecord) -> None:
        """Install an exact provider record without counting an outbound mutation."""

        if type(record) is not FirestoreReleaseRecord:
            raise TypeError("release seed must be an exact record")
        with self._lock:
            path = f"releases/{record.release_id}"
            self._documents[path] = (
                record.model_dump(mode="python"),
                self._tick(),
            )

    def _tick(self) -> datetime:
        current = self._clock
        self._clock += timedelta(microseconds=1)
        return current

    def _get(self, reference: _ReleaseDocumentReference) -> _FirestoreSnapshot:
        with self._lock:
            self.counters.release_reads += 1
            if self.scenario.release_reads_unavailable or (
                self._forced_reads_unavailable
            ):
                raise api_exceptions.ServiceUnavailable("scripted unavailable")
            current = self._documents.get(reference.path)
            return _FirestoreSnapshot(
                reference=reference,
                exists=current is not None,
                read_time=self._clock,
                update_time=None if current is None else current[1],
                data=None if current is None else deepcopy(current[0]),
            )

    def _create(
        self,
        reference: _ReleaseDocumentReference,
        document_data: dict[str, Any],
    ) -> _WriteResult:
        with self._lock:
            self.counters.record_calls += 1
            behavior = self.scenario.release_write_behavior
            if behavior is RecoveryQualificationReleaseWriteBehavior.CONFLICT:
                if self._crash_after_attempt:
                    self._crash_after_attempt = False
                    raise asyncio.CancelledError
                raise api_exceptions.AlreadyExists("scripted conflict")
            if reference.path in self._documents:
                if self._crash_after_attempt:
                    self._crash_after_attempt = False
                    raise asyncio.CancelledError
                raise api_exceptions.AlreadyExists("scripted conflict")
            if behavior is RecoveryQualificationReleaseWriteBehavior.FAIL_BEFORE_COMMIT:
                if self._crash_after_attempt:
                    self._crash_after_attempt = False
                    raise asyncio.CancelledError
                raise api_exceptions.ServiceUnavailable("scripted ambiguous write")
            update_time = self._tick()
            self._documents[reference.path] = (deepcopy(document_data), update_time)
            self.counters.record_commits += 1
            if self._crash_after_attempt:
                self._crash_after_attempt = False
                raise asyncio.CancelledError
            if self._crash_after_commit:
                self._crash_after_commit = False
                raise asyncio.CancelledError
            if behavior is RecoveryQualificationReleaseWriteBehavior.FAIL_AFTER_COMMIT:
                raise api_exceptions.ServiceUnavailable("scripted dropped write ack")
            return _WriteResult(update_time)

    def _delete(
        self,
        reference: _ReleaseDocumentReference,
        option: object | None,
    ) -> _WriteResult:
        with self._lock:
            self.counters.release_deletes += 1
            current = self._documents.get(reference.path)
            if (
                current is None
                or type(option) is not _WriteOption
                or option.kind != "last_update_time"
                or option.value != current[1]
            ):
                raise api_exceptions.FailedPrecondition("scripted stale delete")
            del self._documents[reference.path]
            return _WriteResult(self._tick())


@dataclass(frozen=True, slots=True)
class _CasOperation:
    kind: str
    reference: _CasDocumentReference
    data: dict[str, Any]
    option: _WriteOption | None


class _CasDocumentReference:
    def __init__(self, client: DeterministicAsyncFirestoreCasClient, path: str) -> None:
        self._client = client
        self.path = path

    async def get(
        self,
        field_paths: object | None = None,
        transaction: object | None = None,
        retry: object | None = None,
        timeout: float | None = None,
        *,
        read_time: datetime | None = None,
    ) -> _FirestoreSnapshot:
        del field_paths, transaction, retry, timeout, read_time
        return self._client._get(self)


class _CasWriteBatch:
    def __init__(self, client: DeterministicAsyncFirestoreCasClient) -> None:
        self._client = client
        self._operations: list[_CasOperation] = []

    def create(
        self,
        reference: _CasDocumentReference,
        document_data: dict[str, Any],
    ) -> None:
        self._operations.append(
            _CasOperation("create", reference, deepcopy(document_data), None)
        )

    def update(
        self,
        reference: _CasDocumentReference,
        field_updates: dict[str, Any],
        option: object | None = None,
    ) -> None:
        selected = option if type(option) is _WriteOption else None
        self._operations.append(
            _CasOperation("update", reference, deepcopy(field_updates), selected)
        )

    async def commit(
        self,
        retry: object | None = None,
        timeout: float | None = None,
    ) -> list[_WriteResult]:
        del retry, timeout
        return await self._client._commit_async(tuple(self._operations))


class DeterministicAsyncFirestoreCasClient:
    """Atomic async SDK fake suitable for ``GoogleFirestoreCasStore``."""

    def __init__(
        self,
        *,
        counters: RecoveryQualificationProviderCounters | None = None,
        clock: datetime = RECOVERY_QUALIFICATION_PROVIDER_EPOCH,
    ) -> None:
        if clock.tzinfo is None or clock.utcoffset() is None:
            raise ValueError("Firestore CAS clock must be timezone-aware")
        self.counters = counters or RecoveryQualificationProviderCounters()
        self._clock = clock.astimezone(UTC)
        self._documents: dict[str, tuple[dict[str, Any], datetime]] = {}
        self._get_failures: deque[BaseException] = deque()
        self._commit_before_failures: deque[BaseException] = deque()
        self._commit_after_failures: deque[BaseException] = deque()
        self._lock = threading.RLock()
        self._contention_path: str | None = None
        self._contention_width = 0
        self._contention_arrivals: dict[str, asyncio.Event] = {}
        self._contention_order: tuple[str, ...] = ()
        self._contention_lock = asyncio.Lock()
        self._contention_overlap_count = 0
        self._contention_conflict_count = 0

    def document(self, *document_path: str) -> _CasDocumentReference:
        return _CasDocumentReference(self, "/".join(document_path))

    def batch(self) -> _CasWriteBatch:
        return _CasWriteBatch(self)

    @staticmethod
    def write_option(**kwargs: object) -> _WriteOption:
        if set(kwargs) != {"last_update_time"}:
            raise ValueError("unsupported write option")
        return _WriteOption("last_update_time", kwargs["last_update_time"])

    @property
    def document_count(self) -> int:
        with self._lock:
            return len(self._documents)

    def snapshot_documents(self) -> dict[str, dict[str, Any]]:
        """Return a defensive copy for qualification assertions only."""

        with self._lock:
            return {
                path: deepcopy(document)
                for path, (document, _update_time) in self._documents.items()
            }

    @property
    def contention_overlap_count(self) -> int:
        return self._contention_overlap_count

    @property
    def contention_conflict_count(self) -> int:
        return self._contention_conflict_count

    def arm_update_contention(self, document_path: str, width: int) -> None:
        """Synchronize one fake-only wave of CAS updates at the commit boundary."""

        if type(document_path) is not str or not document_path:
            raise TypeError("contention document path must be non-empty text")
        if type(width) is not int or width < 2:
            raise ValueError("contention width must be at least two")
        if self._contention_path is not None:
            raise RuntimeError("Firestore CAS contention barrier is already armed")
        self._contention_path = document_path
        self._contention_width = width
        self._contention_arrivals = {}
        self._contention_order = ()
        self._contention_lock = asyncio.Lock()
        self._contention_overlap_count = 0
        self._contention_conflict_count = 0

    def fail_next_read(self, error: BaseException | None = None) -> None:
        self._get_failures.append(
            error or api_exceptions.ServiceUnavailable("scripted CAS read failure")
        )

    def fail_next_commit(
        self,
        error: BaseException | None = None,
        *,
        after_write: bool = False,
    ) -> None:
        failure = error or api_exceptions.ServiceUnavailable(
            "scripted CAS commit failure"
        )
        target = (
            self._commit_after_failures if after_write else self._commit_before_failures
        )
        target.append(failure)

    def _tick(self) -> datetime:
        current = self._clock
        self._clock += timedelta(microseconds=1)
        return current

    def _get(self, reference: _CasDocumentReference) -> _FirestoreSnapshot:
        with self._lock:
            self.counters.cas_reads += 1
            if self._get_failures:
                raise self._get_failures.popleft()
            current = self._documents.get(reference.path)
            return _FirestoreSnapshot(
                reference=reference,
                exists=current is not None,
                read_time=self._clock,
                update_time=None if current is None else current[1],
                data=None if current is None else deepcopy(current[0]),
            )

    def _commit(
        self,
        operations: tuple[_CasOperation, ...],
    ) -> list[_WriteResult]:
        with self._lock:
            self.counters.cas_commits += 1
            if self._commit_before_failures:
                raise self._commit_before_failures.popleft()
            proposed = deepcopy(self._documents)
            update_time = self._tick()
            for operation in operations:
                current = proposed.get(operation.reference.path)
                if operation.kind == "create":
                    if current is not None:
                        raise api_exceptions.AlreadyExists("scripted CAS contention")
                    self.counters.cas_create_writes += 1
                elif (
                    current is None
                    or operation.option is None
                    or operation.option.kind != "last_update_time"
                    or operation.option.value != current[1]
                ):
                    raise api_exceptions.FailedPrecondition("scripted CAS contention")
                else:
                    self.counters.cas_update_writes += 1
                proposed[operation.reference.path] = (
                    deepcopy(operation.data),
                    update_time,
                )
            self._documents = proposed
            results = [_WriteResult(update_time) for _operation in operations]
            if self._commit_after_failures:
                raise self._commit_after_failures.popleft()
            return results

    @staticmethod
    def _claim_id_for_contention(
        operations: tuple[_CasOperation, ...],
        document_path: str,
    ) -> str | None:
        matches = tuple(
            operation
            for operation in operations
            if operation.kind == "update" and operation.reference.path == document_path
        )
        if len(matches) != 1:
            return None
        try:
            aggregate = json.loads(str(matches[0].data["canonical_payload"]))
            if aggregate["permit"]["state"] != ActionPermitState.CLAIMED.value:
                return None
            claim_id = aggregate["permit"]["claim_id"]
        except (KeyError, TypeError, ValueError, json.JSONDecodeError):
            return None
        return claim_id if type(claim_id) is str and claim_id else None

    async def _commit_async(
        self,
        operations: tuple[_CasOperation, ...],
    ) -> list[_WriteResult]:
        path = self._contention_path
        claim_id = (
            None if path is None else self._claim_id_for_contention(operations, path)
        )
        if path is None or claim_id is None:
            return self._commit(operations)

        async with self._contention_lock:
            if claim_id in self._contention_arrivals:
                raise RuntimeError("duplicate contention claim identifier")
            turn = asyncio.Event()
            self._contention_arrivals[claim_id] = turn
            if len(self._contention_arrivals) == self._contention_width:
                self._contention_overlap_count = len(self._contention_arrivals)
                self._contention_order = tuple(sorted(self._contention_arrivals))
                self._contention_arrivals[self._contention_order[0]].set()
        await turn.wait()

        try:
            return self._commit(operations)
        except api_exceptions.FailedPrecondition:
            self._contention_conflict_count += 1
            raise
        finally:
            async with self._contention_lock:
                index = self._contention_order.index(claim_id)
                if index == 0:
                    for waiting_claim_id in self._contention_order[1:]:
                        self._contention_arrivals[waiting_claim_id].set()
                    self._contention_path = None


@dataclass(frozen=True, slots=True)
class RecoveryQualificationProviderResources:
    """Production adapters wired to one isolated deterministic provider state."""

    fixture: RecoveryQualificationFixture | None
    archetype_id: str
    scenario: RecoveryQualificationProviderScenario
    settings: ReleaseChainSettings
    invoked_at: datetime
    observed_at: datetime
    clock: Callable[[], datetime]
    counters: RecoveryQualificationProviderCounters
    cloud_state: DeterministicCloudRunState
    cloud_adapter: CloudRunCanaryActionAdapter
    cloud_fault_proxy: CloudRunCanaryFaultProxy
    cloud_reader: CloudRunCanaryReader
    release_client: DeterministicFirestoreReleaseClient
    release_target: GoogleFirestoreReleaseTarget

    @property
    def cloud_action(self) -> CloudRunCanaryFaultProxy:
        """Return the production fault boundary expected by the chain gateway."""

        return self.cloud_fault_proxy

    @property
    def firestore(self) -> GoogleFirestoreReleaseTarget:
        """Return the production Firestore target expected by the chain workflow."""

        return self.release_target

    @property
    def supported(self) -> bool:
        return self.scenario.unsupported_reason is None

    @property
    def unsupported_reason(self) -> str | None:
        return self.scenario.unsupported_reason

    def require_supported(self) -> None:
        """Fail explicitly instead of silently approximating an unsupported state."""

        if self.unsupported_reason is not None:
            raise UnsupportedRecoveryQualificationBehavior(self.unsupported_reason)

    def snapshot(self) -> RecoveryQualificationProviderSnapshot:
        """Return a stable view of provider effects and outbound call counters."""

        return self.cloud_state.provider_snapshot(
            archetype_id=self.archetype_id,
            release_record_count=self.release_client.document_count,
        )

    def seed_release_record(
        self,
        *,
        semantic_action_sha256: str,
        conflicting: bool = False,
    ) -> FirestoreReleaseRecord:
        """Seed a matching or deliberately conflicting release target record."""

        if type(conflicting) is not bool:
            raise TypeError("release conflict flag must be exact")
        record = FirestoreReleaseRecord(
            schema_version=FIRESTORE_RELEASE_RECORD_VERSION,
            release_id=self.settings.release_id,
            cloud_run_revision=(
                RECOVERY_QUALIFICATION_BASELINE
                if conflicting
                else self.settings.staged_revision
            ),
            payload_sha256=(
                hashlib.sha256(
                    f"{self.settings.release_id}:conflict".encode()
                ).hexdigest()
                if conflicting
                else self.settings.payload_sha256
            ),
            semantic_action_sha256=semantic_action_sha256,
            created_at=self.observed_at,
        )
        self.release_client.seed(record)
        return record


@dataclass(frozen=True, slots=True)
class RecoveryQualificationStores:
    """One opened pair of production run and permit stores."""

    run_store: RecoveryRunStore
    permit_store: ActionPermitStore
    permit_authority: PermitAuthority
    cas_store: GoogleFirestoreCasStore | None


class _ClaimIdFactory:
    def __init__(self, case_id: str) -> None:
        self._prefix = hashlib.sha256(case_id.encode()).hexdigest()[:16]
        self._next = 0
        self._lock = threading.Lock()

    def __call__(self) -> str:
        with self._lock:
            self._next += 1
            return f"claim-{self._prefix}-{self._next:08d}"


class RecoveryQualificationStoreFactory:
    """Open or reopen durable stores while retaining their backing state."""

    def __init__(
        self,
        fixture: RecoveryQualificationFixture | None = None,
        *,
        state_directory: str | Path,
        clock: Callable[[], datetime],
        counters: RecoveryQualificationProviderCounters | None = None,
        project_id: str = RECOVERY_QUALIFICATION_PROJECT,
        storage_backend: RecoveryQualificationStorageBackend | None = None,
        case_id: str | None = None,
    ) -> None:
        if fixture is not None:
            if type(fixture) is not RecoveryQualificationFixture:
                raise TypeError("store factory requires an exact qualification fixture")
            if storage_backend is not None or case_id is not None:
                raise ValueError("fixture and explicit store identity cannot be mixed")
            storage_backend = fixture.storage_backend
            case_id = fixture.case_id
        if type(storage_backend) is not RecoveryQualificationStorageBackend:
            raise TypeError("store factory backend must be exact")
        if type(case_id) is not str or not case_id:
            raise TypeError("store factory case identifier must be non-empty text")
        if not callable(clock):
            raise TypeError("store factory clock must be callable")
        directory = Path(state_directory)
        if directory.exists() and not directory.is_dir():
            raise ValueError("qualification state directory must be a directory")
        self.fixture = fixture
        self.storage_backend = storage_backend
        self.case_id = case_id
        self.state_directory = directory
        self.project_id = project_id
        self.counters = counters or RecoveryQualificationProviderCounters()
        self._clock = clock
        self._claim_ids = _ClaimIdFactory(case_id)
        self._firestore_client = (
            DeterministicAsyncFirestoreCasClient(
                counters=self.counters,
                clock=clock(),
            )
            if storage_backend is RecoveryQualificationStorageBackend.FIRESTORE
            else None
        )

    @property
    def firestore_client(self) -> DeterministicAsyncFirestoreCasClient | None:
        return self._firestore_client

    def next_claim_id(self) -> str:
        """Return the deterministic claim identity shared by workflow dispatches."""

        return self._claim_ids()

    @property
    def sqlite_paths(self) -> tuple[Path, Path] | None:
        if self.storage_backend is not RecoveryQualificationStorageBackend.SQLITE:
            return None
        stem = self.case_id
        return (
            self.state_directory / f"{stem}-runs.sqlite3",
            self.state_directory / f"{stem}-permits.sqlite3",
        )

    def open(self) -> RecoveryQualificationStores:
        """Open fresh store objects over the same durable backing state."""

        backend = self.storage_backend
        if backend is RecoveryQualificationStorageBackend.SQLITE:
            self.state_directory.mkdir(parents=True, exist_ok=True)
            paths = self.sqlite_paths
            if paths is None:
                raise AssertionError("SQLite paths are unavailable")
            run_store: RecoveryRunStore = SqliteRecoveryRunStore(paths[0])
            permit_store: ActionPermitStore = SqliteDurableRuntimeStore(paths[1])
            cas_store = None
        elif backend is RecoveryQualificationStorageBackend.FIRESTORE:
            client = self._firestore_client
            if client is None:
                raise AssertionError("Firestore client is unavailable")
            cas_store = GoogleFirestoreCasStore(
                project_id=self.project_id,
                client_factory=lambda: client,
            )
            run_store = FirestoreRecoveryRunStore(cas_store)
            permit_store = FirestoreActionPermitStore(cas_store)
        else:
            raise ValueError("unsupported qualification storage backend")
        authority = PermitAuthority(
            permit_store,
            clock=self._clock,
            claim_id_factory=self._claim_ids,
        )
        return RecoveryQualificationStores(
            run_store=run_store,
            permit_store=permit_store,
            permit_authority=authority,
            cas_store=cas_store,
        )


@dataclass(frozen=True, slots=True)
class RecoveryQualificationFoundation:
    """Provider resources and a restart-safe durable-store factory."""

    provider: RecoveryQualificationProviderResources
    stores: RecoveryQualificationStoreFactory


_DEFAULT_SCENARIO = RecoveryQualificationProviderScenario()

_SCENARIOS: dict[str, RecoveryQualificationProviderScenario] = {
    "stage-drop-committed": RecoveryQualificationProviderScenario(
        fault_mode=CloudRunFaultMode.DROP_AFTER_ACCEPT,
    ),
    "stage-pending": RecoveryQualificationProviderScenario(
        stage_behavior=RecoveryQualificationStageBehavior.PENDING,
    ),
    "stage-terminal-partial": RecoveryQualificationProviderScenario(
        stage_behavior=RecoveryQualificationStageBehavior.TERMINAL_FAILED,
    ),
    "stage-conflict": RecoveryQualificationProviderScenario(
        stage_behavior=RecoveryQualificationStageBehavior.CONFLICTING,
    ),
    "stage-absence": RecoveryQualificationProviderScenario(
        stage_behavior=RecoveryQualificationStageBehavior.ABSENT,
    ),
    "stage-unavailable": RecoveryQualificationProviderScenario(
        cloud_reads_unavailable_after=CloudRunCanaryAction.STAGE,
    ),
    "stage-fresh": _DEFAULT_SCENARIO,
    "stage-stale": RecoveryQualificationProviderScenario(
        stale_cloud_observations=True,
    ),
    "promote-committed": _DEFAULT_SCENARIO,
    "promote-pending": RecoveryQualificationProviderScenario(
        promote_behavior=RecoveryQualificationPromoteBehavior.PENDING,
    ),
    "promote-conflict": RecoveryQualificationProviderScenario(
        promote_behavior=RecoveryQualificationPromoteBehavior.CONFLICTING,
    ),
    "promote-stale-precondition": RecoveryQualificationProviderScenario(
        promote_behavior=RecoveryQualificationPromoteBehavior.STALE_PRECONDITION,
    ),
    "promote-unavailable": RecoveryQualificationProviderScenario(
        cloud_reads_unavailable_after=CloudRunCanaryAction.PROMOTE,
    ),
    "record-predispatch-retry": _DEFAULT_SCENARIO,
    "record-predispatch-unavailable": RecoveryQualificationProviderScenario(
        release_write_behavior=(
            RecoveryQualificationReleaseWriteBehavior.FAIL_BEFORE_COMMIT
        ),
        release_reads_unavailable=True,
    ),
    "record-predispatch-conflict": RecoveryQualificationProviderScenario(
        release_write_behavior=RecoveryQualificationReleaseWriteBehavior.CONFLICT,
    ),
    "record-committed": _DEFAULT_SCENARIO,
    "record-absence-without-receipt": RecoveryQualificationProviderScenario(
        release_write_behavior=(
            RecoveryQualificationReleaseWriteBehavior.FAIL_BEFORE_COMMIT
        ),
    ),
    "record-outcome-unknown": RecoveryQualificationProviderScenario(
        release_write_behavior=(
            RecoveryQualificationReleaseWriteBehavior.FAIL_AFTER_COMMIT
        ),
        release_reads_unavailable=True,
    ),
    "cross-provider-adaptive": RecoveryQualificationProviderScenario(
        fault_mode=CloudRunFaultMode.DROP_AFTER_ACCEPT,
    ),
}


def qualification_provider_scenario_for(
    archetype_id: str,
) -> RecoveryQualificationProviderScenario:
    """Return the provider script for one exact frozen archetype identifier."""

    if type(archetype_id) is not str or not archetype_id:
        raise TypeError("provider archetype identifier must be non-empty text")
    try:
        return _SCENARIOS[archetype_id]
    except KeyError:
        raise UnsupportedRecoveryQualificationBehavior(
            f"qualification archetype has no provider script: {archetype_id}"
        ) from None


def recovery_qualification_provider_scenario(
    fixture: RecoveryQualificationFixture,
) -> RecoveryQualificationProviderScenario:
    """Return the exact provider script registered for a fixture archetype."""

    if type(fixture) is not RecoveryQualificationFixture:
        raise TypeError("provider scenario requires an exact qualification fixture")
    try:
        expected_generation = RECOVERY_QUALIFICATION_SEEDS.index(fixture.seed) + 1
    except ValueError:
        raise ValueError(
            "qualification fixture seed is outside the frozen schedule"
        ) from None
    if fixture.initial_provider_generation != expected_generation:
        raise ValueError("qualification fixture provider generation changed")
    return replace(
        qualification_provider_scenario_for(fixture.archetype.archetype_id),
        # This is provider-visible concurrency state, not identifier decoration:
        # each seed begins from a distinct ETag/generation precondition.
        initial_service_generation=fixture.initial_provider_generation,
    )


def _fixture_clock(fixture: RecoveryQualificationFixture) -> datetime:
    offset = int(hashlib.sha256(fixture.case_id.encode()).hexdigest()[:8], 16)
    return RECOVERY_QUALIFICATION_PROVIDER_EPOCH + timedelta(seconds=offset % 86_400)


def _settings(fixture: RecoveryQualificationFixture) -> ReleaseChainSettings:
    def digest(label: str) -> str:
        material = f"{fixture.case_id}\0{fixture.seed}\0{label}".encode()
        return hashlib.sha256(material).hexdigest()

    return ReleaseChainSettings(
        project=RECOVERY_QUALIFICATION_PROJECT,
        location=RECOVERY_QUALIFICATION_LOCATION,
        service=RECOVERY_QUALIFICATION_SERVICE,
        release_id=fixture.case_id,
        image_digest=f"sha256:{digest('image')}",
        configuration_sha256=digest("configuration"),
        payload_sha256=digest("payload"),
    )


def _clock_value(clock: Callable[[], datetime]) -> datetime:
    value = clock()
    if not isinstance(value, datetime) or value.tzinfo is None:
        raise ValueError("qualification provider clock must be timezone-aware")
    if value.utcoffset() is None:
        raise ValueError("qualification provider clock must be timezone-aware")
    return value.astimezone(UTC)


def _build_qualification_provider(
    *,
    settings: ReleaseChainSettings,
    archetype_id: str,
    clock: Callable[[], datetime],
    fixture: RecoveryQualificationFixture | None,
    invoked_at: datetime,
    scenario: RecoveryQualificationProviderScenario | None,
) -> RecoveryQualificationProviderResources:
    if type(settings) is not ReleaseChainSettings:
        raise TypeError("provider factory requires exact release-chain settings")
    if not callable(clock):
        raise TypeError("provider factory clock must be callable")
    selected = scenario or qualification_provider_scenario_for(archetype_id)
    if type(selected) is not RecoveryQualificationProviderScenario:
        raise TypeError("provider scenario must be exact")
    observed_at = _clock_value(clock)

    def reader_clock() -> datetime:
        value = _clock_value(clock)
        if selected.stale_cloud_observations:
            return value - timedelta(seconds=61)
        return value

    counters = RecoveryQualificationProviderCounters()
    state = DeterministicCloudRunState(
        settings=settings,
        scenario=selected,
        counters=counters,
    )
    target = CloudRunCanaryTarget(
        project=settings.project,
        location=settings.location,
        service=settings.service,
        image_repository=state.image_repository,
        baseline_revision=RECOVERY_QUALIFICATION_BASELINE,
        health_audience="https://canary.example.test",
    )
    action_services = _CloudRunServicesClient(state, evidence_read=False)
    evidence_services = _CloudRunServicesClient(state, evidence_read=True)
    action_revisions = _CloudRunRevisionsClient(state)
    evidence_revisions = _CloudRunRevisionsClient(state)
    adapter = CloudRunCanaryActionAdapter(
        target=target,
        services_factory=lambda: action_services,
        revisions_factory=lambda: action_revisions,
        clock=clock,
    )
    reader = CloudRunCanaryReader(
        target=target,
        services_factory=lambda: evidence_services,
        revisions_factory=lambda: evidence_revisions,
        health_client=_CloudRunHealthClient(state, counters),
        clock=reader_clock,
        revision_settle_delay_seconds=0.0,
    )
    release_client = DeterministicFirestoreReleaseClient(
        scenario=selected,
        counters=counters,
        clock=observed_at,
    )
    release_target = GoogleFirestoreReleaseTarget(
        project_id=settings.project,
        client_factory=lambda: release_client,
        clock=clock,
    )
    return RecoveryQualificationProviderResources(
        fixture=fixture,
        archetype_id=archetype_id,
        scenario=selected,
        settings=settings,
        invoked_at=invoked_at,
        observed_at=observed_at,
        clock=clock,
        counters=counters,
        cloud_state=state,
        cloud_adapter=adapter,
        cloud_fault_proxy=CloudRunCanaryFaultProxy(adapter),
        cloud_reader=reader,
        release_client=release_client,
        release_target=release_target,
    )


def build_qualification_provider(
    settings: ReleaseChainSettings,
    archetype_id: str,
    clock: Callable[[], datetime],
    *,
    scenario: RecoveryQualificationProviderScenario | None = None,
) -> RecoveryQualificationProviderResources:
    """Build the compact provider surface consumed by the qualification runner."""

    observed_at = _clock_value(clock)
    return _build_qualification_provider(
        settings=settings,
        archetype_id=archetype_id,
        clock=clock,
        fixture=None,
        invoked_at=observed_at,
        scenario=scenario,
    )


def build_recovery_qualification_provider(
    fixture: RecoveryQualificationFixture,
    *,
    invoked_at: datetime | None = None,
    scenario: RecoveryQualificationProviderScenario | None = None,
) -> RecoveryQualificationProviderResources:
    """Fixture convenience wrapper around :func:`build_qualification_provider`."""

    if type(fixture) is not RecoveryQualificationFixture:
        raise TypeError("provider factory requires an exact qualification fixture")
    started_at = _fixture_clock(fixture) if invoked_at is None else invoked_at
    if started_at.tzinfo is None or started_at.utcoffset() is None:
        raise ValueError("qualification provider clock must be timezone-aware")
    started_at = started_at.astimezone(UTC)
    workflow_now = started_at + timedelta(seconds=2)
    tick = 0
    tick_lock = threading.Lock()

    def clock() -> datetime:
        nonlocal tick
        with tick_lock:
            value = workflow_now + timedelta(milliseconds=tick)
            tick += 1
            return value

    return _build_qualification_provider(
        settings=_settings(fixture),
        archetype_id=fixture.archetype.archetype_id,
        clock=clock,
        fixture=fixture,
        invoked_at=started_at,
        scenario=(
            recovery_qualification_provider_scenario(fixture)
            if scenario is None
            else scenario
        ),
    )


def build_recovery_qualification_store_factory(
    fixture: RecoveryQualificationFixture,
    *,
    state_directory: str | Path,
    clock: Callable[[], datetime],
    counters: RecoveryQualificationProviderCounters | None = None,
) -> RecoveryQualificationStoreFactory:
    """Build a backend-selected, reopenable production-store factory."""

    return RecoveryQualificationStoreFactory(
        fixture,
        state_directory=state_directory,
        clock=clock,
        counters=counters,
    )


def build_qualification_store_factory(
    storage_backend: RecoveryQualificationStorageBackend,
    case_id: str,
    state_directory: str | Path,
    clock: Callable[[], datetime],
    *,
    counters: RecoveryQualificationProviderCounters | None = None,
) -> RecoveryQualificationStoreFactory:
    """Build the compact backend-selected factory used by the main runner."""

    return RecoveryQualificationStoreFactory(
        state_directory=state_directory,
        clock=clock,
        counters=counters,
        storage_backend=storage_backend,
        case_id=case_id,
    )


def build_qualification_firestore_store_factory(
    case_id: str,
    clock: Callable[[], datetime],
    *,
    counters: RecoveryQualificationProviderCounters | None = None,
    project_id: str = RECOVERY_QUALIFICATION_PROJECT,
) -> RecoveryQualificationStoreFactory:
    """Build a reopenable run/permit factory over ``GoogleFirestoreCasStore``."""

    return RecoveryQualificationStoreFactory(
        state_directory=Path.cwd(),
        clock=clock,
        counters=counters,
        project_id=project_id,
        storage_backend=RecoveryQualificationStorageBackend.FIRESTORE,
        case_id=case_id,
    )


def build_recovery_qualification_foundation(
    fixture: RecoveryQualificationFixture,
    *,
    state_directory: str | Path,
    invoked_at: datetime | None = None,
    scenario: RecoveryQualificationProviderScenario | None = None,
    permit_clock: Callable[[], datetime] | None = None,
) -> RecoveryQualificationFoundation:
    """Build provider adapters and restart-safe stores for one isolated lane."""

    provider = build_recovery_qualification_provider(
        fixture,
        invoked_at=invoked_at,
        scenario=scenario,
    )
    stores = build_recovery_qualification_store_factory(
        fixture,
        state_directory=state_directory,
        clock=provider.clock if permit_clock is None else permit_clock,
        counters=provider.counters,
    )
    return RecoveryQualificationFoundation(provider=provider, stores=stores)


__all__ = [
    "RECOVERY_QUALIFICATION_BASELINE",
    "RECOVERY_QUALIFICATION_LOCATION",
    "RECOVERY_QUALIFICATION_PROJECT",
    "RECOVERY_QUALIFICATION_PROVIDER_EPOCH",
    "RECOVERY_QUALIFICATION_SERVICE",
    "RECOVERY_QUALIFICATION_SERVICE_URI",
    "DeterministicAsyncFirestoreCasClient",
    "DeterministicCloudRunState",
    "DeterministicFirestoreReleaseClient",
    "RecoveryQualificationFoundation",
    "RecoveryQualificationPromoteBehavior",
    "RecoveryQualificationProviderCounters",
    "RecoveryQualificationProviderResources",
    "RecoveryQualificationProviderScenario",
    "RecoveryQualificationProviderSnapshot",
    "RecoveryQualificationReleaseWriteBehavior",
    "RecoveryQualificationStageBehavior",
    "RecoveryQualificationStoreFactory",
    "RecoveryQualificationStores",
    "UnsupportedRecoveryQualificationBehavior",
    "build_qualification_firestore_store_factory",
    "build_qualification_provider",
    "build_qualification_store_factory",
    "build_recovery_qualification_foundation",
    "build_recovery_qualification_provider",
    "build_recovery_qualification_store_factory",
    "qualification_provider_scenario_for",
    "recovery_qualification_provider_scenario",
]
