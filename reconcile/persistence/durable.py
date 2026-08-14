"""Provider-neutral durable runtime records and ownership boundaries."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta
from enum import StrEnum
from typing import Literal, Protocol

from pydantic import Field, field_validator, model_validator

from reconcile.contracts.api import InvestigationEvent
from reconcile.contracts.base import (
    AwareDatetime,
    Identifier,
    Sha256Digest,
    SmallJsonObject,
    StrictModel,
    reject_sensitive_keys,
)
from reconcile.contracts.codec import canonical_json_bytes, canonical_sha256
from reconcile.contracts.common import Classification
from reconcile.contracts.envelope import ExecutionEnvelope, ProbeRequest
from reconcile.contracts.report import (
    InvestigationReport,
    InvestigationStatus,
    ProbeOutcome,
    RequestedAction,
)
from reconcile.controller import (
    ControllerAuditRecord,
    ProbeObservation,
    probe_request_sha256,
)
from reconcile.persistence.events import EventJournalSnapshot
from reconcile.security import redact_boundary_value

DURABLE_RUN_VERSION = "reconcile/durable-run/v1"
DURABLE_LEASE_VERSION = "reconcile/durable-lease/v1"
PROBE_CHECKPOINT_VERSION = "reconcile/probe-checkpoint/v1"
PROBE_RESUME_PLAN_VERSION = "reconcile/probe-resume-plan/v1"
RUNTIME_TELEMETRY_VERSION = "reconcile/runtime-telemetry/v1"
COST_LEDGER_ENTRY_VERSION = "reconcile/cost-ledger-entry/v1"
COST_LEDGER_SNAPSHOT_VERSION = "reconcile/cost-ledger-snapshot/v1"

LEASE_DURATION = timedelta(seconds=30)
LEASE_RENEWAL_INTERVAL = timedelta(seconds=10)

_MAX_SIGNED_64 = 2**63 - 1


class DurableRuntimeError(Exception):
    """Base class for deterministic durable-runtime failures."""


class DurableRunNotFound(DurableRuntimeError):
    def __init__(self, investigation_id: str) -> None:
        self.investigation_id = investigation_id
        super().__init__(f"durable run does not exist: {investigation_id}")


class DurableRunConflict(DurableRuntimeError):
    def __init__(self, investigation_id: str) -> None:
        self.investigation_id = investigation_id
        super().__init__(
            f"durable run identity conflicts with its envelope: {investigation_id}"
        )


class DurableStateConflict(DurableRuntimeError):
    def __init__(self, investigation_id: str, operation: str) -> None:
        self.investigation_id = investigation_id
        self.operation = operation
        super().__init__(f"durable run cannot perform {operation}: {investigation_id}")


class CorruptDurableState(DurableRuntimeError):
    def __init__(self, investigation_id: str | None = None) -> None:
        self.investigation_id = investigation_id
        suffix = "" if investigation_id is None else f": {investigation_id}"
        super().__init__(f"durable runtime state is invalid{suffix}")


class UnsupportedDurableSchema(DurableRuntimeError):
    def __init__(self) -> None:
        super().__init__("durable runtime schema is unsupported")


class LeaseUnavailable(DurableRuntimeError):
    def __init__(self, investigation_id: str) -> None:
        self.investigation_id = investigation_id
        super().__init__(f"durable run already has an active owner: {investigation_id}")


class StaleLease(DurableRuntimeError):
    def __init__(self, investigation_id: str) -> None:
        self.investigation_id = investigation_id
        super().__init__(f"durable lease is stale or expired: {investigation_id}")


class LeaseRenewalTooEarly(DurableRuntimeError):
    def __init__(self, investigation_id: str) -> None:
        self.investigation_id = investigation_id
        super().__init__(f"durable lease renewal is not due: {investigation_id}")


class ProbeCheckpointConflict(DurableRuntimeError):
    def __init__(self, investigation_id: str, checkpoint_id: str) -> None:
        self.investigation_id = investigation_id
        self.checkpoint_id = checkpoint_id
        super().__init__(
            f"probe checkpoint conflicts with durable state: {checkpoint_id}"
        )


class UnsupportedRecoveryState(DurableRuntimeError):
    def __init__(self, investigation_id: str) -> None:
        self.investigation_id = investigation_id
        super().__init__(
            f"durable recovery requires human escalation: {investigation_id}"
        )


class BudgetExceeded(DurableRuntimeError):
    def __init__(self, investigation_id: str, dimension: str) -> None:
        self.investigation_id = investigation_id
        self.dimension = dimension
        super().__init__(f"durable runtime budget exhausted: {dimension}")


class DurableRunState(StrEnum):
    CREATED = "CREATED"
    ACTIVE = "ACTIVE"
    TERMINAL = "TERMINAL"
    ESCALATION_REQUIRED = "ESCALATION_REQUIRED"


class CleanupStatus(StrEnum):
    NOT_REQUESTED = "NOT_REQUESTED"
    PENDING = "PENDING"
    SUCCEEDED = "SUCCEEDED"
    FAILED = "FAILED"


class ProbeCheckpointState(StrEnum):
    STARTED = "STARTED"
    RECORDED = "RECORDED"


class ProbeReplaySafety(StrEnum):
    SAFE_READ = "SAFE_READ"
    UNSAFE = "UNSAFE"
    UNKNOWN = "UNKNOWN"


class ProbeResumeAction(StrEnum):
    REUSE_RECORDED = "REUSE_RECORDED"
    REPEAT_SAFE_READ = "REPEAT_SAFE_READ"
    ESCALATE = "ESCALATE"


class RuntimeTelemetryKind(StrEnum):
    RUN = "RUN"
    LEASE = "LEASE"
    PROBE = "PROBE"
    EVIDENCE_DECISION = "EVIDENCE_DECISION"
    CLASSIFIER = "CLASSIFIER"
    ACTION_GATE = "ACTION_GATE"
    CLEANUP = "CLEANUP"


def sanitize_runtime_telemetry_attributes(
    attributes: SmallJsonObject,
) -> SmallJsonObject:
    """Apply the repository telemetry boundary policy through one callable seam."""

    reject_sensitive_keys(attributes)
    sanitized = redact_boundary_value(attributes)
    if not isinstance(sanitized, dict):
        raise TypeError("telemetry attributes must remain a JSON object")
    return sanitized


class RuntimeLimits(StrictModel):
    max_provider_calls: int = Field(ge=0, le=_MAX_SIGNED_64)
    max_probe_count: int = Field(ge=1, le=_MAX_SIGNED_64)
    max_evidence_bytes: int = Field(ge=1, le=_MAX_SIGNED_64)
    max_controller_cost_units: int = Field(ge=1, le=_MAX_SIGNED_64)
    max_estimated_cost_microunits: int = Field(ge=0, le=_MAX_SIGNED_64)
    deadline_at: AwareDatetime


def runtime_limits_for(
    envelope: ExecutionEnvelope,
    *,
    started_at: datetime,
    max_provider_calls: int,
    max_estimated_cost_microunits: int,
) -> RuntimeLimits:
    """Derive runtime ceilings without widening the sealed evidence budget."""

    if type(envelope) is not ExecutionEnvelope:
        raise TypeError("runtime limits require an execution envelope")
    budget = envelope.context.evidence_budget
    return RuntimeLimits(
        max_provider_calls=max_provider_calls,
        max_probe_count=budget.max_probes,
        max_evidence_bytes=budget.max_total_result_bytes,
        max_controller_cost_units=budget.max_cost_units,
        max_estimated_cost_microunits=max_estimated_cost_microunits,
        deadline_at=started_at + timedelta(milliseconds=budget.max_elapsed_ms),
    )


class DurableRunRecord(StrictModel):
    schema_version: Literal[DURABLE_RUN_VERSION]
    investigation_id: Identifier
    envelope: ExecutionEnvelope
    envelope_sha256: Sha256Digest
    state: DurableRunState
    limits: RuntimeLimits
    created_at: AwareDatetime
    updated_at: AwareDatetime
    revision: int = Field(ge=0, le=_MAX_SIGNED_64)
    established_report: InvestigationReport | None = None
    cleanup_status: CleanupStatus = CleanupStatus.NOT_REQUESTED
    cleanup_failure_code: Identifier | None = None
    recovery_failure_code: Identifier | None = None

    @model_validator(mode="after")
    def validate_state(self) -> DurableRunRecord:
        if self.investigation_id != self.envelope.investigation_id:
            raise ValueError("durable run and envelope identifiers must match")
        if self.envelope_sha256 != canonical_sha256(self.envelope):
            raise ValueError("durable run envelope digest does not match")
        if self.updated_at < self.created_at:
            raise ValueError("durable run timestamps must be ordered")
        budget = self.envelope.context.evidence_budget
        if (
            self.limits.max_probe_count > budget.max_probes
            or self.limits.max_evidence_bytes > budget.max_total_result_bytes
            or self.limits.max_controller_cost_units > budget.max_cost_units
            or self.limits.deadline_at
            > self.created_at + timedelta(milliseconds=budget.max_elapsed_ms)
        ):
            raise ValueError("runtime limits cannot widen the envelope budget")

        terminal = self.established_report is not None
        if terminal is not (self.state is DurableRunState.TERMINAL):
            raise ValueError("terminal run state must match its established report")
        if self.established_report is not None:
            report = self.established_report
            if (
                report.investigation_id != self.investigation_id
                or report.envelope_sha256 != self.envelope_sha256
                or report.status is not InvestigationStatus.COMPLETED
                or report.classification is None
                or self.updated_at < report.updated_at
            ):
                raise ValueError("established report does not match the durable run")

        cleanup_failed = self.cleanup_status is CleanupStatus.FAILED
        if cleanup_failed is not (self.cleanup_failure_code is not None):
            raise ValueError("cleanup failure status and code must agree")
        escalation = self.state is DurableRunState.ESCALATION_REQUIRED
        if escalation is not (self.recovery_failure_code is not None):
            raise ValueError("recovery escalation state and code must agree")
        return self

    @property
    def classification(self) -> Classification | None:
        if self.established_report is None:
            return None
        return self.established_report.classification


@dataclass(frozen=True, slots=True)
class CreateDurableRunResult:
    run: DurableRunRecord
    created: bool


class LeaseToken(StrictModel):
    schema_version: Literal[DURABLE_LEASE_VERSION]
    investigation_id: Identifier
    owner_id: Identifier
    fence: int = Field(ge=1, le=_MAX_SIGNED_64)
    acquired_at: AwareDatetime
    renewed_at: AwareDatetime
    renew_after: AwareDatetime
    expires_at: AwareDatetime

    @model_validator(mode="after")
    def validate_lease_window(self) -> LeaseToken:
        if self.renewed_at < self.acquired_at:
            raise ValueError("lease renewal cannot precede acquisition")
        if self.renew_after != self.renewed_at + LEASE_RENEWAL_INTERVAL:
            raise ValueError("lease renewal interval is not supported")
        if self.expires_at != self.renewed_at + LEASE_DURATION:
            raise ValueError("lease duration is not supported")
        return self

    def renewal_due(self, now: datetime) -> bool:
        return self.renew_after <= now < self.expires_at

    def expired(self, now: datetime) -> bool:
        return now >= self.expires_at


class ProbeCheckpoint(StrictModel):
    schema_version: Literal[PROBE_CHECKPOINT_VERSION]
    investigation_id: Identifier
    checkpoint_id: Identifier
    step_sequence: int = Field(ge=1, le=_MAX_SIGNED_64)
    request: ProbeRequest
    request_sha256: Sha256Digest
    replay_safety: ProbeReplaySafety
    state: ProbeCheckpointState
    started_at: AwareDatetime
    recorded_at: AwareDatetime | None = None
    audit: ControllerAuditRecord | None = None
    observation: ProbeObservation | None = None

    @model_validator(mode="after")
    def validate_checkpoint(self) -> ProbeCheckpoint:
        if self.request_sha256 != probe_request_sha256(self.request):
            raise ValueError("checkpoint request digest does not match")
        recorded = self.state is ProbeCheckpointState.RECORDED
        if recorded is not (self.recorded_at is not None and self.audit is not None):
            raise ValueError("recorded checkpoint fields are incomplete")
        if not recorded and (
            self.recorded_at is not None or self.observation is not None
        ):
            raise ValueError("started checkpoint cannot contain a result")
        if self.audit is None:
            return self
        if self.recorded_at is None or self.recorded_at < self.audit.completed_at:
            raise ValueError("checkpoint recording cannot precede probe completion")
        if self.audit.started_at < self.started_at:
            raise ValueError("probe execution cannot precede its durable checkpoint")
        if (
            self.audit.sequence != self.step_sequence
            or self.audit.request_sha256 != self.request_sha256
            or self.audit.capability_name != self.request.capability_name
            or self.audit.capability_version != self.request.capability_version
        ):
            raise ValueError("checkpoint audit does not match its request")
        completed = self.audit.outcome is ProbeOutcome.COMPLETED
        if completed is not (self.observation is not None):
            raise ValueError("completed checkpoint requires one raw observation")
        if self.observation is not None:
            payload = canonical_json_bytes(self.observation)
            if self.audit.result_sha256 != canonical_sha256(
                self.observation
            ) or self.audit.result_byte_count != len(payload):
                raise ValueError("checkpoint observation does not match its audit")
        return self


class ProbeResumeDecision(StrictModel):
    checkpoint_id: Identifier
    step_sequence: int = Field(ge=1, le=_MAX_SIGNED_64)
    action: ProbeResumeAction
    request_sha256: Sha256Digest


class ProbeResumePlan(StrictModel):
    schema_version: Literal[PROBE_RESUME_PLAN_VERSION]
    investigation_id: Identifier
    decisions: tuple[ProbeResumeDecision, ...]
    requires_escalation: bool

    @model_validator(mode="after")
    def validate_decisions(self) -> ProbeResumePlan:
        sequences = tuple(item.step_sequence for item in self.decisions)
        if sequences != tuple(range(1, len(sequences) + 1)):
            raise ValueError("resume decisions must be contiguous")
        escalates = any(
            item.action is ProbeResumeAction.ESCALATE for item in self.decisions
        )
        if self.requires_escalation is not escalates:
            raise ValueError("resume escalation flag does not match decisions")
        return self


def build_probe_resume_plan(
    investigation_id: str,
    checkpoints: tuple[ProbeCheckpoint, ...],
    *,
    repeat_safe_reads: bool = True,
) -> ProbeResumePlan:
    """Reuse recorded outcomes and repeat only unfinished trusted reads."""

    if tuple(item.step_sequence for item in checkpoints) != tuple(
        range(1, len(checkpoints) + 1)
    ):
        raise UnsupportedRecoveryState(investigation_id)
    decisions = tuple(
        ProbeResumeDecision(
            checkpoint_id=item.checkpoint_id,
            step_sequence=item.step_sequence,
            action=(
                ProbeResumeAction.REUSE_RECORDED
                if item.state is ProbeCheckpointState.RECORDED
                else (
                    ProbeResumeAction.REPEAT_SAFE_READ
                    if repeat_safe_reads
                    and item.replay_safety is ProbeReplaySafety.SAFE_READ
                    else ProbeResumeAction.ESCALATE
                )
            ),
            request_sha256=item.request_sha256,
        )
        for item in checkpoints
    )
    return ProbeResumePlan(
        schema_version=PROBE_RESUME_PLAN_VERSION,
        investigation_id=investigation_id,
        decisions=decisions,
        requires_escalation=any(
            item.action is ProbeResumeAction.ESCALATE for item in decisions
        ),
    )


class RuntimeTelemetryRecord(StrictModel):
    schema_version: Literal[RUNTIME_TELEMETRY_VERSION]
    investigation_id: Identifier
    telemetry_id: Identifier
    sequence: int = Field(ge=1, le=_MAX_SIGNED_64)
    kind: RuntimeTelemetryKind
    occurred_at: AwareDatetime
    trace_id: Identifier
    span_id: Identifier
    parent_span_id: Identifier | None = None
    outcome: Identifier
    probe_sequence: int | None = Field(default=None, ge=1, le=_MAX_SIGNED_64)
    evidence_id: Identifier | None = None
    classification: Classification | None = None
    requested_action: RequestedAction | None = None
    attributes: SmallJsonObject = Field(default_factory=dict)

    @field_validator("attributes")
    @classmethod
    def sanitize_attributes(cls, value: SmallJsonObject) -> SmallJsonObject:
        return sanitize_runtime_telemetry_attributes(value)

    @model_validator(mode="after")
    def validate_shape(self) -> RuntimeTelemetryRecord:
        if self.kind is RuntimeTelemetryKind.PROBE and self.probe_sequence is None:
            raise ValueError("probe telemetry requires a probe sequence")
        if (
            self.kind is RuntimeTelemetryKind.EVIDENCE_DECISION
            and self.evidence_id is None
        ):
            raise ValueError("evidence telemetry requires an evidence identifier")
        if (
            self.kind
            in {RuntimeTelemetryKind.CLASSIFIER, RuntimeTelemetryKind.ACTION_GATE}
            and self.classification is None
        ):
            raise ValueError("decision telemetry requires a classification")
        if (
            self.kind is RuntimeTelemetryKind.ACTION_GATE
            and self.requested_action is None
        ):
            raise ValueError("gate telemetry requires a requested action")
        return self


class RuntimeCostDelta(StrictModel):
    provider_calls: int = Field(default=0, ge=0, le=_MAX_SIGNED_64)
    probe_count: int = Field(default=0, ge=0, le=_MAX_SIGNED_64)
    evidence_bytes: int = Field(default=0, ge=0, le=_MAX_SIGNED_64)
    controller_cost_units: int = Field(default=0, ge=0, le=_MAX_SIGNED_64)
    estimated_cost_microunits: int = Field(default=0, ge=0, le=_MAX_SIGNED_64)

    @model_validator(mode="after")
    def require_charge(self) -> RuntimeCostDelta:
        if not any(
            (
                self.provider_calls,
                self.probe_count,
                self.evidence_bytes,
                self.controller_cost_units,
                self.estimated_cost_microunits,
            )
        ):
            raise ValueError("cost ledger entry must charge at least one dimension")
        return self


class CostLedgerEntry(StrictModel):
    schema_version: Literal[COST_LEDGER_ENTRY_VERSION]
    investigation_id: Identifier
    entry_id: Identifier
    sequence: int = Field(ge=1, le=_MAX_SIGNED_64)
    category: Identifier
    occurred_at: AwareDatetime
    delta: RuntimeCostDelta


class CostLedgerSnapshot(StrictModel):
    schema_version: Literal[COST_LEDGER_SNAPSHOT_VERSION]
    investigation_id: Identifier
    entry_count: int = Field(ge=0, le=_MAX_SIGNED_64)
    provider_calls: int = Field(ge=0, le=_MAX_SIGNED_64)
    probe_count: int = Field(ge=0, le=_MAX_SIGNED_64)
    evidence_bytes: int = Field(ge=0, le=_MAX_SIGNED_64)
    controller_cost_units: int = Field(ge=0, le=_MAX_SIGNED_64)
    estimated_cost_microunits: int = Field(ge=0, le=_MAX_SIGNED_64)
    limits: RuntimeLimits

    @model_validator(mode="after")
    def validate_totals(self) -> CostLedgerSnapshot:
        if (
            self.provider_calls > self.limits.max_provider_calls
            or self.probe_count > self.limits.max_probe_count
            or self.evidence_bytes > self.limits.max_evidence_bytes
            or self.controller_cost_units > self.limits.max_controller_cost_units
            or self.estimated_cost_microunits
            > self.limits.max_estimated_cost_microunits
        ):
            raise ValueError("cost ledger totals exceed the durable limits")
        return self


class DurableRuntimeStore(Protocol):
    async def create_run(
        self,
        envelope: ExecutionEnvelope,
        *,
        created_at: datetime,
        limits: RuntimeLimits,
    ) -> CreateDurableRunResult: ...

    async def get_run(self, investigation_id: str) -> DurableRunRecord: ...

    async def acquire_lease(
        self,
        investigation_id: str,
        owner_id: str,
        *,
        now: datetime,
    ) -> LeaseToken: ...

    async def renew_lease(
        self,
        lease: LeaseToken,
        *,
        now: datetime,
    ) -> LeaseToken: ...

    async def release_lease(
        self,
        lease: LeaseToken,
        *,
        now: datetime,
    ) -> None: ...

    async def mark_active(
        self,
        lease: LeaseToken,
        *,
        occurred_at: datetime,
    ) -> DurableRunRecord: ...

    async def require_escalation(
        self,
        lease: LeaseToken,
        *,
        failure_code: str,
        occurred_at: datetime,
    ) -> DurableRunRecord: ...

    async def start_probe(
        self,
        lease: LeaseToken,
        *,
        checkpoint_id: str,
        step_sequence: int,
        request: ProbeRequest,
        replay_safety: ProbeReplaySafety,
        started_at: datetime,
    ) -> ProbeCheckpoint: ...

    async def record_probe(
        self,
        lease: LeaseToken,
        checkpoint_id: str,
        *,
        audit: ControllerAuditRecord,
        observation: ProbeObservation | None,
        recorded_at: datetime,
    ) -> ProbeCheckpoint: ...

    async def resume_plan(
        self,
        investigation_id: str,
        *,
        now: datetime,
    ) -> ProbeResumePlan: ...

    async def append_event(
        self,
        lease: LeaseToken,
        event: InvestigationEvent,
        *,
        now: datetime,
    ) -> InvestigationEvent: ...

    async def snapshot_events(
        self,
        investigation_id: str,
        *,
        after: int = 0,
    ) -> EventJournalSnapshot: ...

    async def establish_report(
        self,
        lease: LeaseToken,
        report: InvestigationReport,
        *,
        occurred_at: datetime,
    ) -> DurableRunRecord: ...

    async def record_cleanup(
        self,
        lease: LeaseToken,
        status: CleanupStatus,
        *,
        occurred_at: datetime,
        failure_code: str | None = None,
    ) -> DurableRunRecord: ...

    async def append_telemetry(
        self,
        lease: LeaseToken,
        record: RuntimeTelemetryRecord,
        *,
        now: datetime,
    ) -> RuntimeTelemetryRecord: ...

    async def telemetry_records(
        self,
        investigation_id: str,
    ) -> tuple[RuntimeTelemetryRecord, ...]: ...

    async def charge(
        self,
        lease: LeaseToken,
        *,
        entry_id: str,
        category: str,
        occurred_at: datetime,
        delta: RuntimeCostDelta,
    ) -> CostLedgerSnapshot: ...

    async def cost_snapshot(self, investigation_id: str) -> CostLedgerSnapshot: ...


__all__ = [
    "COST_LEDGER_ENTRY_VERSION",
    "COST_LEDGER_SNAPSHOT_VERSION",
    "DURABLE_LEASE_VERSION",
    "DURABLE_RUN_VERSION",
    "LEASE_DURATION",
    "LEASE_RENEWAL_INTERVAL",
    "PROBE_CHECKPOINT_VERSION",
    "PROBE_RESUME_PLAN_VERSION",
    "RUNTIME_TELEMETRY_VERSION",
    "BudgetExceeded",
    "CleanupStatus",
    "CorruptDurableState",
    "CostLedgerEntry",
    "CostLedgerSnapshot",
    "CreateDurableRunResult",
    "DurableRunConflict",
    "DurableRunNotFound",
    "DurableRunRecord",
    "DurableRunState",
    "DurableRuntimeError",
    "DurableRuntimeStore",
    "DurableStateConflict",
    "LeaseRenewalTooEarly",
    "LeaseToken",
    "LeaseUnavailable",
    "ProbeCheckpoint",
    "ProbeCheckpointConflict",
    "ProbeCheckpointState",
    "ProbeReplaySafety",
    "ProbeResumeAction",
    "ProbeResumeDecision",
    "ProbeResumePlan",
    "RuntimeCostDelta",
    "RuntimeLimits",
    "RuntimeTelemetryKind",
    "RuntimeTelemetryRecord",
    "StaleLease",
    "UnsupportedDurableSchema",
    "UnsupportedRecoveryState",
    "build_probe_resume_plan",
    "runtime_limits_for",
    "sanitize_runtime_telemetry_attributes",
]
