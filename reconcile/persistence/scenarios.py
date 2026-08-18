"""Private durable authority for the operator scenario lifecycle."""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Literal, Protocol, runtime_checkable

from pydantic import Field, model_validator

from reconcile.contracts.base import (
    AwareDatetime,
    Identifier,
    Sha256Digest,
    StrictModel,
)
from reconcile.contracts.codec import canonical_sha256
from reconcile.contracts.comparison import (
    ComparisonRun,
    InvestigationComparisonRecord,
)
from reconcile.contracts.envelope import ExecutionEnvelope
from reconcile.contracts.operator import (
    ScenarioLaunchRequest,
    ScenarioRunEvent,
    ScenarioRunMode,
    ScenarioRunSnapshot,
)
from reconcile.contracts.report import InvestigationReport, InvestigationStatus
from reconcile.contracts.scenario import ScenarioRunRequest, ScenarioRunResult
from reconcile.persistence.durable import CleanupStatus

SCENARIO_WORK_ITEM_VERSION = "reconcile/scenario-work-item/v1"
SCENARIO_LEASE_VERSION = "reconcile/scenario-lease/v1"


class ScenarioPersistenceError(RuntimeError):
    """Base class for private scenario persistence failures."""


class ScenarioWorkNotFound(ScenarioPersistenceError):
    def __init__(self, investigation_id: str) -> None:
        self.investigation_id = investigation_id
        super().__init__(f"scenario work item does not exist: {investigation_id}")


class ScenarioWorkConflict(ScenarioPersistenceError):
    def __init__(self, launch_id: str, investigation_id: str) -> None:
        self.launch_id = launch_id
        self.investigation_id = investigation_id
        super().__init__(f"scenario launch identity conflicts: {launch_id}")


class CorruptScenarioState(ScenarioPersistenceError):
    def __init__(self, investigation_id: str | None = None) -> None:
        self.investigation_id = investigation_id
        suffix = "" if investigation_id is None else f": {investigation_id}"
        super().__init__(f"scenario durable state is invalid{suffix}")


class ScenarioLeaseUnavailable(ScenarioPersistenceError):
    def __init__(self, investigation_id: str) -> None:
        self.investigation_id = investigation_id
        super().__init__(f"scenario work item already has an owner: {investigation_id}")


class StaleScenarioLease(ScenarioPersistenceError):
    def __init__(self, investigation_id: str) -> None:
        self.investigation_id = investigation_id
        super().__init__(f"scenario work item lease is stale: {investigation_id}")


class ScenarioStateConflict(ScenarioPersistenceError):
    def __init__(self, investigation_id: str, operation: str) -> None:
        self.investigation_id = investigation_id
        self.operation = operation
        super().__init__(
            f"scenario work item cannot perform {operation}: {investigation_id}"
        )


class ScenarioMutationState(StrEnum):
    """Whether mutation dispatch may still be attempted."""

    NOT_STARTED = "NOT_STARTED"
    STARTED = "STARTED"
    RECORDED = "RECORDED"


class ScenarioInvestigationState(StrEnum):
    """Durable state of the post-mutation investigation."""

    NOT_STARTED = "NOT_STARTED"
    STARTED = "STARTED"
    RECORDED = "RECORDED"
    ESCALATION_REQUIRED = "ESCALATION_REQUIRED"


class ScenarioLane(StrEnum):
    """Stable child-runtime lane identities."""

    FIXED = "FIXED"
    ADAPTIVE = "ADAPTIVE"


class ScenarioWorkItem(StrictModel):
    """Canonical parent record written before any scenario side effect."""

    schema_version: Literal[SCENARIO_WORK_ITEM_VERSION]
    launch_request: ScenarioLaunchRequest
    launch_sha256: Sha256Digest
    scenario_request: ScenarioRunRequest
    scenario_request_sha256: Sha256Digest
    strategy: ScenarioRunMode
    strategy_sha256: Sha256Digest
    semantic_config_sha256: Sha256Digest
    runtime_provenance_sha256: Sha256Digest
    workspace_id: Identifier
    invoked_at: AwareDatetime
    mutation_state: ScenarioMutationState
    prepared_envelope_sha256: Sha256Digest | None = None
    cleanup_manifest_sha256: Sha256Digest | None = None
    scenario_result: ScenarioRunResult | None = None
    envelope_sha256: Sha256Digest | None = None
    investigation_state: ScenarioInvestigationState
    workflow_result: InvestigationReport | InvestigationComparisonRecord | None = None
    cleanup_status: CleanupStatus = CleanupStatus.NOT_REQUESTED
    cleanup_failure_code: Identifier | None = None
    recovery_failure_code: Identifier | None = None
    snapshot: ScenarioRunSnapshot
    created_at: AwareDatetime
    updated_at: AwareDatetime
    revision: int = Field(ge=0, le=2**63 - 1)

    @model_validator(mode="after")
    def validate_authority(self) -> ScenarioWorkItem:
        launch = self.launch_request
        request = self.scenario_request
        if self.launch_sha256 != canonical_sha256(launch):
            raise ValueError("scenario launch digest does not match")
        if self.scenario_request_sha256 != canonical_sha256(request):
            raise ValueError("scenario request digest does not match")
        if launch.mode is not self.strategy:
            raise ValueError("scenario strategy does not match its launch")
        if (
            launch.launch_id != request.run_id
            or self.snapshot.launch_id != launch.launch_id
            or self.snapshot.investigation_id != request.investigation_id
            or self.snapshot.scenario is not launch.scenario
            or self.snapshot.mode is not launch.mode
        ):
            raise ValueError("scenario work identities do not match")
        if (
            self.snapshot.accepted_at != self.created_at
            or self.snapshot.updated_at < self.snapshot.accepted_at
            or self.updated_at < self.snapshot.updated_at
            or self.invoked_at < self.created_at
        ):
            raise ValueError("scenario work timestamps are not ordered")

        prepared = self.prepared_envelope_sha256 is not None
        if prepared is not (self.cleanup_manifest_sha256 is not None):
            raise ValueError("scenario preparation binding is incomplete")
        if (self.mutation_state is ScenarioMutationState.NOT_STARTED) is prepared:
            raise ValueError("mutation state and preparation binding disagree")
        recorded = self.mutation_state is ScenarioMutationState.RECORDED
        if recorded is not (self.scenario_result is not None):
            raise ValueError("recorded mutation must have exactly one result")
        if self.scenario_result is not None:
            result = self.scenario_result
            if (
                result.request_sha256 != self.scenario_request_sha256
                or result.investigation_id != request.investigation_id
                or result.scenario != request.scenario
                or result.run_id != request.run_id
                or result.operation_id != request.operation_id
                or result.invocation_id != request.invocation_id
                or result.function_call_id != request.function_call_id
                or result.fixture.cleanup_manifest_sha256
                != self.cleanup_manifest_sha256
            ):
                raise ValueError("scenario result does not match its work item")
            result_envelope_sha256 = (
                None
                if result.execution_envelope is None
                else canonical_sha256(result.execution_envelope)
            )
            if result_envelope_sha256 != self.envelope_sha256:
                raise ValueError("scenario envelope binding does not match")
        elif self.envelope_sha256 is not None:
            raise ValueError("scenario envelope cannot precede mutation result")

        investigated = self.workflow_result is not None
        if investigated is not (
            self.investigation_state is ScenarioInvestigationState.RECORDED
        ):
            raise ValueError("investigation result and state disagree")
        if self.investigation_state in {
            ScenarioInvestigationState.STARTED,
            ScenarioInvestigationState.RECORDED,
        } and (
            self.mutation_state is not ScenarioMutationState.RECORDED
            or self.envelope_sha256 is None
        ):
            raise ValueError("investigation cannot precede a recorded envelope")
        if self.workflow_result is not None:
            result = self.workflow_result
            comparison_mode = self.strategy is ScenarioRunMode.COMPARE
            if (
                result.envelope_sha256 != self.envelope_sha256
                or comparison_mode
                is not (type(result) is InvestigationComparisonRecord)
                or (
                    type(result) is InvestigationReport
                    and (
                        result.investigation_id != request.investigation_id
                        or result.status is not InvestigationStatus.COMPLETED
                    )
                )
                or (
                    type(result) is InvestigationComparisonRecord
                    and result.scenario != request.scenario
                )
            ):
                raise ValueError("workflow result does not match its envelope")
        escalation = (
            self.investigation_state is ScenarioInvestigationState.ESCALATION_REQUIRED
        )
        if escalation is not (self.recovery_failure_code is not None):
            raise ValueError("scenario escalation state and reason disagree")
        cleanup_failed = self.cleanup_status is CleanupStatus.FAILED
        if cleanup_failed is not (self.cleanup_failure_code is not None):
            raise ValueError("scenario cleanup state and reason disagree")
        if (
            self.workflow_result is None
            and self.cleanup_status is not CleanupStatus.NOT_REQUESTED
        ):
            raise ValueError("scenario cleanup cannot precede a workflow result")
        return self


class ScenarioLeaseToken(StrictModel):
    """Fenced ownership token for one parent scenario work item."""

    schema_version: Literal[SCENARIO_LEASE_VERSION]
    investigation_id: Identifier
    owner_id: Identifier
    fence: int = Field(ge=1, le=2**63 - 1)
    acquired_at: AwareDatetime
    renewed_at: AwareDatetime
    expires_at: AwareDatetime

    @model_validator(mode="after")
    def validate_times(self) -> ScenarioLeaseToken:
        if not self.acquired_at <= self.renewed_at < self.expires_at:
            raise ValueError("scenario lease timestamps are not ordered")
        return self

    def expired(self, now: datetime) -> bool:
        return now >= self.expires_at


class CreateScenarioWorkResult(StrictModel):
    work: ScenarioWorkItem
    created: bool


class ScenarioProjectionSnapshot(StrictModel):
    snapshot: ScenarioRunSnapshot
    events: tuple[ScenarioRunEvent, ...]
    cursor: int = Field(ge=0, le=2**63 - 1)
    terminal: bool


@runtime_checkable
class ScenarioStore(Protocol):
    async def create_work(
        self,
        launch_request: ScenarioLaunchRequest,
        scenario_request: ScenarioRunRequest,
        *,
        strategy_sha256: str,
        semantic_config_sha256: str,
        runtime_provenance_sha256: str,
        workspace_id: str,
        invoked_at: datetime,
        snapshot: ScenarioRunSnapshot,
        accepted_event: ScenarioRunEvent,
        created_at: datetime,
    ) -> CreateScenarioWorkResult: ...

    async def get_work(self, investigation_id: str) -> ScenarioWorkItem: ...

    async def list_work(self) -> tuple[ScenarioWorkItem, ...]: ...

    async def acquire_scenario_lease(
        self,
        investigation_id: str,
        owner_id: str,
        *,
        now: datetime,
    ) -> ScenarioLeaseToken: ...

    async def renew_scenario_lease(
        self,
        token: ScenarioLeaseToken,
        *,
        now: datetime,
    ) -> ScenarioLeaseToken: ...

    async def release_scenario_lease(
        self,
        token: ScenarioLeaseToken,
        *,
        now: datetime,
    ) -> None: ...

    async def record_mutation_started(
        self,
        token: ScenarioLeaseToken,
        *,
        prepared_envelope: ExecutionEnvelope | None = None,
        prepared_envelope_sha256: str,
        cleanup_manifest_sha256: str,
        occurred_at: datetime,
    ) -> ScenarioWorkItem: ...

    async def record_mutation_result(
        self,
        token: ScenarioLeaseToken,
        result: ScenarioRunResult,
        *,
        prepared_envelope_bytes: bytes,
        occurred_at: datetime,
    ) -> ScenarioWorkItem: ...

    async def mark_investigation_started(
        self,
        token: ScenarioLeaseToken,
        *,
        occurred_at: datetime,
    ) -> ScenarioWorkItem: ...

    async def record_workflow_result(
        self,
        token: ScenarioLeaseToken,
        result: InvestigationReport | InvestigationComparisonRecord,
        *,
        occurred_at: datetime,
    ) -> ScenarioWorkItem: ...

    async def require_scenario_escalation(
        self,
        token: ScenarioLeaseToken,
        failure_code: str,
        *,
        occurred_at: datetime,
    ) -> ScenarioWorkItem: ...

    async def record_scenario_cleanup(
        self,
        token: ScenarioLeaseToken,
        status: CleanupStatus,
        *,
        occurred_at: datetime,
        failure_code: str | None = None,
    ) -> ScenarioWorkItem: ...

    async def append_projection(
        self,
        snapshot: ScenarioRunSnapshot,
        event: ScenarioRunEvent,
        *,
        terminal: bool,
    ) -> ScenarioWorkItem: ...

    async def snapshot_projection(
        self,
        investigation_id: str,
        *,
        after: int = 0,
    ) -> ScenarioProjectionSnapshot: ...

    async def record_lane_result(
        self,
        token: ScenarioLeaseToken,
        lane: ScenarioLane,
        result: ComparisonRun,
        *,
        occurred_at: datetime,
    ) -> None: ...

    async def get_lane_result(
        self,
        investigation_id: str,
        lane: ScenarioLane,
    ) -> ComparisonRun | None: ...


__all__ = [
    "SCENARIO_LEASE_VERSION",
    "SCENARIO_WORK_ITEM_VERSION",
    "CorruptScenarioState",
    "CreateScenarioWorkResult",
    "ScenarioInvestigationState",
    "ScenarioLane",
    "ScenarioLeaseToken",
    "ScenarioLeaseUnavailable",
    "ScenarioMutationState",
    "ScenarioPersistenceError",
    "ScenarioProjectionSnapshot",
    "ScenarioStateConflict",
    "ScenarioStore",
    "ScenarioWorkConflict",
    "ScenarioWorkItem",
    "ScenarioWorkNotFound",
    "StaleScenarioLease",
]
