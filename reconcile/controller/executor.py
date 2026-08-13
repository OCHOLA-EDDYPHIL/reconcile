"""Deterministic execution of fixed, trusted, read-only observation handlers."""

from __future__ import annotations

import asyncio
import hashlib
import inspect
import json
import re
import time
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from typing import Protocol

from jsonschema import Draft202012Validator, validators
from pydantic import Field, model_validator

from reconcile.contracts.base import (
    AwareDatetime,
    Identifier,
    Sha256Digest,
    StrictModel,
    canonical_json_value_bytes,
)
from reconcile.contracts.codec import (
    ContractError,
    canonical_json_bytes,
    decode_contract,
)
from reconcile.contracts.envelope import ExecutionEnvelope, ProbeRequest
from reconcile.contracts.report import ProbeOutcome
from reconcile.controller.capabilities import (
    BoundProbe,
    CapabilityRegistry,
    CapabilitySemantics,
    CapabilityUnavailable,
    ObservationHandler,
    ProbeObservation,
)


class ProbeStopReason(StrEnum):
    PROBE_COMPLETED = "probe_completed"
    INVALID_REQUEST = "invalid_request"
    UNKNOWN_CAPABILITY = "unknown_capability"
    CAPABILITY_DISABLED = "capability_disabled"
    CAPABILITY_NOT_ENABLED = "capability_not_enabled"
    CAPABILITY_MUTATING = "capability_mutating"
    CAPABILITY_SEMANTICS_AMBIGUOUS = "capability_semantics_ambiguous"
    TARGET_KIND_MISMATCH = "target_kind_mismatch"
    TARGET_SCOPE_MISMATCH = "target_scope_mismatch"
    INVALID_EFFECT_REFERENCE = "invalid_effect_reference"
    INVALID_ARGUMENTS = "invalid_arguments"
    ARGUMENTS_TOO_LARGE = "arguments_too_large"
    TARGET_PARAMETER_INJECTION = "target_parameter_injection"
    CORRELATION_MISMATCH = "correlation_mismatch"
    PROBE_COUNT_EXHAUSTED = "probe_count_exhausted"
    CAPABILITY_PROBE_LIMIT_EXHAUSTED = "capability_probe_limit_exhausted"
    COST_BUDGET_EXHAUSTED = "cost_budget_exhausted"
    ELAPSED_BUDGET_EXHAUSTED = "elapsed_budget_exhausted"
    TOTAL_RESULT_BYTES_EXHAUSTED = "total_result_bytes_exhausted"
    RESULT_TOO_LARGE = "result_too_large"
    PROBE_TIMEOUT = "probe_timeout"
    PROBE_CANCELLED = "probe_cancelled"
    CAPABILITY_UNAVAILABLE = "capability_unavailable"
    MALFORMED_OBSERVATION = "malformed_observation"


_TERMINAL_REASONS = frozenset(
    {
        ProbeStopReason.PROBE_CANCELLED,
        ProbeStopReason.PROBE_COUNT_EXHAUSTED,
        ProbeStopReason.ELAPSED_BUDGET_EXHAUSTED,
        ProbeStopReason.TOTAL_RESULT_BYTES_EXHAUSTED,
        ProbeStopReason.PROBE_TIMEOUT,
    }
)


def _is_strict_integer(_checker: object, instance: object) -> bool:
    return type(instance) is int


def _is_strict_number(_checker: object, instance: object) -> bool:
    return type(instance) in {int, float}


_STRICT_TYPE_CHECKER = Draft202012Validator.TYPE_CHECKER.redefine_many(
    {
        "integer": _is_strict_integer,
        "number": _is_strict_number,
    }
)
_StrictDraft202012Validator = validators.extend(
    Draft202012Validator,
    type_checker=_STRICT_TYPE_CHECKER,
)


class ControllerClock(Protocol):
    def monotonic(self) -> float:
        """Return monotonic seconds."""

    def now(self) -> datetime:
        """Return an aware wall-clock timestamp for audit records."""


class _SystemClock:
    def monotonic(self) -> float:
        return time.monotonic()

    def now(self) -> datetime:
        return datetime.now(UTC)


class ControllerAuditRecord(StrictModel):
    sequence: int = Field(ge=1, le=2**63 - 1)
    capability_name: Identifier | None = None
    capability_version: Identifier | None = None
    request_sha256: Sha256Digest | None = None
    target_sha256: Sha256Digest
    outcome: ProbeOutcome
    stop_reason: ProbeStopReason
    started_at: AwareDatetime
    completed_at: AwareDatetime
    session_elapsed_ms: int = Field(ge=0, le=2**63 - 1)
    probe_count_used: int = Field(ge=0, le=2**63 - 1)
    cost_units_used: int = Field(ge=0, le=2**63 - 1)
    result_bytes_acquired: int = Field(ge=0, le=2**63 - 1)
    result_sha256: Sha256Digest | None = None
    result_byte_count: int | None = Field(default=None, ge=0, le=2**63 - 1)

    @model_validator(mode="after")
    def validate_timestamps(self) -> ControllerAuditRecord:
        if self.completed_at < self.started_at:
            raise ValueError("audit completion cannot precede its start")
        if self.outcome is ProbeOutcome.COMPLETED:
            if self.result_sha256 is None or self.result_byte_count is None:
                raise ValueError(
                    "completed probes require a result digest and byte count"
                )
        elif self.result_sha256 is not None:
            raise ValueError("rejected probe output cannot become an evidence digest")
        return self


@dataclass(frozen=True, slots=True)
class ValidatedObservation:
    canonical_json: bytes
    sha256: str
    byte_count: int


@dataclass(frozen=True, slots=True)
class ProbeExecution:
    audit: ControllerAuditRecord
    observation: ValidatedObservation | None = None

    def __post_init__(self) -> None:
        completed = self.audit.outcome is ProbeOutcome.COMPLETED
        if completed != (self.observation is not None):
            raise ValueError("only completed probes may return an observation")


class _InvocationState(StrEnum):
    COMPLETED = "COMPLETED"
    CANCELLED = "CANCELLED"
    TIMED_OUT = "TIMED_OUT"
    UNAVAILABLE = "UNAVAILABLE"
    MALFORMED = "MALFORMED"


_TARGET_VALUE_PREFIXES = (
    "buckets/",
    "databases/",
    "documents/",
    "gs://",
    "http://",
    "https://",
    "projects/",
)
_URI_SCHEME = re.compile(r"^[a-z][a-z0-9+.-]*://", re.IGNORECASE)


def _contains_target_coordinate_value(value: object) -> bool:
    if isinstance(value, str):
        lowered = value.strip().lower()
        return lowered.startswith(_TARGET_VALUE_PREFIXES) or bool(
            _URI_SCHEME.match(lowered)
        )
    if isinstance(value, list):
        return any(_contains_target_coordinate_value(item) for item in value)
    if isinstance(value, dict):
        return any(_contains_target_coordinate_value(item) for item in value.values())
    return False


def _consume_task_result(task: asyncio.Task[object]) -> None:
    if task.cancelled():
        return
    try:
        task.exception()
    except Exception:
        pass


def _discard_task(task: asyncio.Task[object]) -> None:
    if not task.done():
        task.cancel()
    task.add_done_callback(_consume_task_result)


class ProbeController:
    """One investigation's serialized, bounded read-only probe session."""

    def __init__(
        self,
        envelope: ExecutionEnvelope,
        registry: CapabilityRegistry,
        *,
        clock: ControllerClock | None = None,
    ) -> None:
        envelope_payload = canonical_json_bytes(envelope)
        self._envelope = decode_contract(envelope_payload, ExecutionEnvelope)
        registry.freeze()
        self._registry = registry
        self._clock = clock or _SystemClock()
        self._started_monotonic = self._clock.monotonic()
        self._deadline_monotonic = (
            self._started_monotonic
            + self._envelope.context.evidence_budget.max_elapsed_ms / 1000
        )
        self._target_sha256 = hashlib.sha256(
            canonical_json_bytes(self._envelope.target)
        ).hexdigest()
        self._enabled_capabilities = {
            (reference.name, reference.version)
            for reference in self._envelope.context.enabled_capabilities
        }
        self._effect_ids = {
            effect.effect_id for effect in self._envelope.expected_effects
        }
        self._lock = asyncio.Lock()
        self._cancelled = asyncio.Event()
        self._sequence = 0
        self._probe_count_used = 0
        self._cost_units_used = 0
        self._result_bytes_acquired = 0
        self._capability_invocations: dict[tuple[str, str], int] = {}
        self._audit: list[ControllerAuditRecord] = []
        self._terminal_execution: ProbeExecution | None = None

    @property
    def audit_trail(self) -> tuple[ControllerAuditRecord, ...]:
        return tuple(self._audit)

    def cancel(self) -> None:
        """Permanently cancel this investigation's remaining probe work."""

        self._cancelled.set()

    def _session_elapsed_ms(self) -> int:
        elapsed = max(0.0, self._clock.monotonic() - self._started_monotonic)
        return min(int(elapsed * 1000), 2**63 - 1)

    def _deadline_reached(self) -> bool:
        return self._clock.monotonic() >= self._deadline_monotonic

    def _request_fingerprint(self, request: ProbeRequest) -> str:
        identity = {
            "arguments": request.arguments,
            "capability_name": request.capability_name,
            "capability_version": request.capability_version,
            "relevant_effect_ids": sorted(request.relevant_effect_ids),
        }
        return hashlib.sha256(canonical_json_value_bytes(identity)).hexdigest()

    def _finish(
        self,
        *,
        sequence: int,
        started_at: datetime,
        outcome: ProbeOutcome,
        reason: ProbeStopReason,
        capability_name: str | None,
        capability_version: str | None,
        request_sha256: str | None,
        observation: ValidatedObservation | None = None,
        rejected_result_bytes: int | None = None,
    ) -> ProbeExecution:
        completed_at = max(self._clock.now(), started_at)
        audit = ControllerAuditRecord(
            sequence=sequence,
            capability_name=capability_name,
            capability_version=capability_version,
            request_sha256=request_sha256,
            target_sha256=self._target_sha256,
            outcome=outcome,
            stop_reason=reason,
            started_at=started_at,
            completed_at=completed_at,
            session_elapsed_ms=self._session_elapsed_ms(),
            probe_count_used=self._probe_count_used,
            cost_units_used=self._cost_units_used,
            result_bytes_acquired=self._result_bytes_acquired,
            result_sha256=observation.sha256 if observation is not None else None,
            result_byte_count=(
                observation.byte_count
                if observation is not None
                else rejected_result_bytes
            ),
        )
        self._audit.append(audit)
        execution = ProbeExecution(audit=audit, observation=observation)
        if reason in _TERMINAL_REASONS:
            self._terminal_execution = execution
        return execution

    async def execute(self, request: ProbeRequest) -> ProbeExecution:
        """Validate and invoke at most one fixed read handler without retrying it."""

        async with self._lock:
            if self._terminal_execution is not None:
                return self._terminal_execution
            self._sequence += 1
            sequence = self._sequence
            started_at = self._clock.now()
            capability_name: str | None = None
            capability_version: str | None = None
            requested_capability_name: str | None = None
            requested_capability_version: str | None = None
            request_sha256: str | None = None

            if self._cancelled.is_set():
                return self._finish(
                    sequence=sequence,
                    started_at=started_at,
                    outcome=ProbeOutcome.CANCELLED,
                    reason=ProbeStopReason.PROBE_CANCELLED,
                    capability_name=None,
                    capability_version=None,
                    request_sha256=None,
                )

            budget = self._envelope.context.evidence_budget
            if self._probe_count_used >= budget.max_probes:
                return self._finish(
                    sequence=sequence,
                    started_at=started_at,
                    outcome=ProbeOutcome.BUDGET_EXHAUSTED,
                    reason=ProbeStopReason.PROBE_COUNT_EXHAUSTED,
                    capability_name=None,
                    capability_version=None,
                    request_sha256=None,
                )
            self._probe_count_used += 1

            try:
                if not isinstance(request, ProbeRequest):
                    raise TypeError("request is not a ProbeRequest")
                request = decode_contract(canonical_json_bytes(request), ProbeRequest)
                requested_capability_name = request.capability_name
                requested_capability_version = request.capability_version
                request_sha256 = self._request_fingerprint(request)
            except (ContractError, TypeError, ValueError):
                return self._finish(
                    sequence=sequence,
                    started_at=started_at,
                    outcome=ProbeOutcome.REJECTED,
                    reason=ProbeStopReason.INVALID_REQUEST,
                    capability_name=None,
                    capability_version=None,
                    request_sha256=None,
                )

            if self._deadline_reached():
                return self._finish(
                    sequence=sequence,
                    started_at=started_at,
                    outcome=ProbeOutcome.BUDGET_EXHAUSTED,
                    reason=ProbeStopReason.ELAPSED_BUDGET_EXHAUSTED,
                    capability_name=capability_name,
                    capability_version=capability_version,
                    request_sha256=request_sha256,
                )

            registration = self._registry.resolve(
                requested_capability_name,
                requested_capability_version,
            )
            if registration is None:
                return self._finish(
                    sequence=sequence,
                    started_at=started_at,
                    outcome=ProbeOutcome.REJECTED,
                    reason=ProbeStopReason.UNKNOWN_CAPABILITY,
                    capability_name=capability_name,
                    capability_version=capability_version,
                    request_sha256=request_sha256,
                )
            capability_name, capability_version = registration.identity
            if not registration.enabled:
                return self._finish(
                    sequence=sequence,
                    started_at=started_at,
                    outcome=ProbeOutcome.REJECTED,
                    reason=ProbeStopReason.CAPABILITY_DISABLED,
                    capability_name=capability_name,
                    capability_version=capability_version,
                    request_sha256=request_sha256,
                )
            if registration.semantics is CapabilitySemantics.MUTATING:
                return self._finish(
                    sequence=sequence,
                    started_at=started_at,
                    outcome=ProbeOutcome.REJECTED,
                    reason=ProbeStopReason.CAPABILITY_MUTATING,
                    capability_name=capability_name,
                    capability_version=capability_version,
                    request_sha256=request_sha256,
                )
            if registration.semantics is CapabilitySemantics.AMBIGUOUS:
                return self._finish(
                    sequence=sequence,
                    started_at=started_at,
                    outcome=ProbeOutcome.REJECTED,
                    reason=ProbeStopReason.CAPABILITY_SEMANTICS_AMBIGUOUS,
                    capability_name=capability_name,
                    capability_version=capability_version,
                    request_sha256=request_sha256,
                )
            if (
                capability_name,
                capability_version,
            ) not in self._enabled_capabilities:
                return self._finish(
                    sequence=sequence,
                    started_at=started_at,
                    outcome=ProbeOutcome.REJECTED,
                    reason=ProbeStopReason.CAPABILITY_NOT_ENABLED,
                    capability_name=capability_name,
                    capability_version=capability_version,
                    request_sha256=request_sha256,
                )

            matching_kind = tuple(
                constraint
                for constraint in registration.capability.allowed_targets
                if constraint.target_kind == self._envelope.target.target_kind
            )
            if not matching_kind:
                return self._finish(
                    sequence=sequence,
                    started_at=started_at,
                    outcome=ProbeOutcome.REJECTED,
                    reason=ProbeStopReason.TARGET_KIND_MISMATCH,
                    capability_name=capability_name,
                    capability_version=capability_version,
                    request_sha256=request_sha256,
                )
            target_scope = canonical_json_value_bytes(self._envelope.target.scope)
            if not any(
                canonical_json_value_bytes(constraint.scope) == target_scope
                for constraint in matching_kind
            ):
                return self._finish(
                    sequence=sequence,
                    started_at=started_at,
                    outcome=ProbeOutcome.REJECTED,
                    reason=ProbeStopReason.TARGET_SCOPE_MISMATCH,
                    capability_name=capability_name,
                    capability_version=capability_version,
                    request_sha256=request_sha256,
                )
            if not set(request.relevant_effect_ids) <= self._effect_ids:
                return self._finish(
                    sequence=sequence,
                    started_at=started_at,
                    outcome=ProbeOutcome.REJECTED,
                    reason=ProbeStopReason.INVALID_EFFECT_REFERENCE,
                    capability_name=capability_name,
                    capability_version=capability_version,
                    request_sha256=request_sha256,
                )

            arguments_payload = canonical_json_value_bytes(request.arguments)
            if len(arguments_payload) > registration.argument_byte_ceiling:
                return self._finish(
                    sequence=sequence,
                    started_at=started_at,
                    outcome=ProbeOutcome.REJECTED,
                    reason=ProbeStopReason.ARGUMENTS_TOO_LARGE,
                    capability_name=capability_name,
                    capability_version=capability_version,
                    request_sha256=request_sha256,
                )
            validator = _StrictDraft202012Validator(
                registration.capability.argument_schema
            )
            if not validator.is_valid(request.arguments):
                return self._finish(
                    sequence=sequence,
                    started_at=started_at,
                    outcome=ProbeOutcome.REJECTED,
                    reason=ProbeStopReason.INVALID_ARGUMENTS,
                    capability_name=capability_name,
                    capability_version=capability_version,
                    request_sha256=request_sha256,
                )
            if _contains_target_coordinate_value(request.arguments):
                return self._finish(
                    sequence=sequence,
                    started_at=started_at,
                    outcome=ProbeOutcome.REJECTED,
                    reason=ProbeStopReason.TARGET_PARAMETER_INJECTION,
                    capability_name=capability_name,
                    capability_version=capability_version,
                    request_sha256=request_sha256,
                )
            for (
                key,
                expected_value,
            ) in self._envelope.context.correlation_fields.items():
                if key in request.arguments and canonical_json_value_bytes(
                    request.arguments[key]
                ) != canonical_json_value_bytes(expected_value):
                    return self._finish(
                        sequence=sequence,
                        started_at=started_at,
                        outcome=ProbeOutcome.REJECTED,
                        reason=ProbeStopReason.CORRELATION_MISMATCH,
                        capability_name=capability_name,
                        capability_version=capability_version,
                        request_sha256=request_sha256,
                    )
            identity = (capability_name, capability_version)
            invocation_count = self._capability_invocations.get(identity, 0)
            if invocation_count >= registration.max_invocations:
                return self._finish(
                    sequence=sequence,
                    started_at=started_at,
                    outcome=ProbeOutcome.BUDGET_EXHAUSTED,
                    reason=ProbeStopReason.CAPABILITY_PROBE_LIMIT_EXHAUSTED,
                    capability_name=capability_name,
                    capability_version=capability_version,
                    request_sha256=request_sha256,
                )
            if (
                self._cost_units_used + registration.capability.cost_units
                > budget.max_cost_units
            ):
                return self._finish(
                    sequence=sequence,
                    started_at=started_at,
                    outcome=ProbeOutcome.BUDGET_EXHAUSTED,
                    reason=ProbeStopReason.COST_BUDGET_EXHAUSTED,
                    capability_name=capability_name,
                    capability_version=capability_version,
                    request_sha256=request_sha256,
                )
            if self._result_bytes_acquired >= budget.max_total_result_bytes:
                return self._finish(
                    sequence=sequence,
                    started_at=started_at,
                    outcome=ProbeOutcome.BUDGET_EXHAUSTED,
                    reason=ProbeStopReason.TOTAL_RESULT_BYTES_EXHAUSTED,
                    capability_name=capability_name,
                    capability_version=capability_version,
                    request_sha256=request_sha256,
                )

            handler = registration.handler
            if handler is None:
                return self._finish(
                    sequence=sequence,
                    started_at=started_at,
                    outcome=ProbeOutcome.UNAVAILABLE,
                    reason=ProbeStopReason.CAPABILITY_UNAVAILABLE,
                    capability_name=capability_name,
                    capability_version=capability_version,
                    request_sha256=request_sha256,
                )

            dispatch_started = self._clock.monotonic()
            capability_deadline = (
                dispatch_started + registration.capability.timeout_ms / 1000
            )
            invocation_deadline = min(
                self._deadline_monotonic,
                capability_deadline,
            )
            timeout_seconds = invocation_deadline - dispatch_started
            if timeout_seconds <= 0:
                return self._finish(
                    sequence=sequence,
                    started_at=started_at,
                    outcome=ProbeOutcome.BUDGET_EXHAUSTED,
                    reason=ProbeStopReason.ELAPSED_BUDGET_EXHAUSTED,
                    capability_name=capability_name,
                    capability_version=capability_version,
                    request_sha256=request_sha256,
                )
            elapsed_limited = self._deadline_monotonic <= capability_deadline
            timeout_ms = max(1, int(timeout_seconds * 1000))
            bound_probe = BoundProbe(
                investigation_id=self._envelope.investigation_id,
                operation_id=self._envelope.operation_id,
                capability_name=capability_name,
                capability_version=capability_version,
                target=type(self._envelope.target).model_validate_json(
                    canonical_json_bytes(self._envelope.target)
                ),
                relevant_effect_ids=request.relevant_effect_ids,
                arguments=json.loads(arguments_payload),
                timeout_ms=timeout_ms,
                result_byte_ceiling=registration.capability.result_byte_ceiling,
            )
            timeout_seconds = invocation_deadline - self._clock.monotonic()
            if timeout_seconds <= 0:
                return self._finish(
                    sequence=sequence,
                    started_at=started_at,
                    outcome=(
                        ProbeOutcome.BUDGET_EXHAUSTED
                        if elapsed_limited
                        else ProbeOutcome.TIMED_OUT
                    ),
                    reason=(
                        ProbeStopReason.ELAPSED_BUDGET_EXHAUSTED
                        if elapsed_limited
                        else ProbeStopReason.PROBE_TIMEOUT
                    ),
                    capability_name=capability_name,
                    capability_version=capability_version,
                    request_sha256=request_sha256,
                )

            self._capability_invocations[identity] = invocation_count + 1
            self._cost_units_used += registration.capability.cost_units
            try:
                invocation_state, raw_observation = await self._invoke_once(
                    handler,
                    bound_probe,
                    timeout_seconds,
                )
            except asyncio.CancelledError:
                self._finish(
                    sequence=sequence,
                    started_at=started_at,
                    outcome=ProbeOutcome.CANCELLED,
                    reason=ProbeStopReason.PROBE_CANCELLED,
                    capability_name=capability_name,
                    capability_version=capability_version,
                    request_sha256=request_sha256,
                )
                raise

            if invocation_state is _InvocationState.CANCELLED:
                return self._finish(
                    sequence=sequence,
                    started_at=started_at,
                    outcome=ProbeOutcome.CANCELLED,
                    reason=ProbeStopReason.PROBE_CANCELLED,
                    capability_name=capability_name,
                    capability_version=capability_version,
                    request_sha256=request_sha256,
                )
            if invocation_state is _InvocationState.TIMED_OUT:
                return self._finish(
                    sequence=sequence,
                    started_at=started_at,
                    outcome=(
                        ProbeOutcome.BUDGET_EXHAUSTED
                        if elapsed_limited
                        else ProbeOutcome.TIMED_OUT
                    ),
                    reason=(
                        ProbeStopReason.ELAPSED_BUDGET_EXHAUSTED
                        if elapsed_limited
                        else ProbeStopReason.PROBE_TIMEOUT
                    ),
                    capability_name=capability_name,
                    capability_version=capability_version,
                    request_sha256=request_sha256,
                )
            if invocation_state is _InvocationState.UNAVAILABLE:
                return self._finish(
                    sequence=sequence,
                    started_at=started_at,
                    outcome=ProbeOutcome.UNAVAILABLE,
                    reason=ProbeStopReason.CAPABILITY_UNAVAILABLE,
                    capability_name=capability_name,
                    capability_version=capability_version,
                    request_sha256=request_sha256,
                )
            if invocation_state is _InvocationState.MALFORMED:
                return self._finish(
                    sequence=sequence,
                    started_at=started_at,
                    outcome=ProbeOutcome.MALFORMED,
                    reason=ProbeStopReason.MALFORMED_OBSERVATION,
                    capability_name=capability_name,
                    capability_version=capability_version,
                    request_sha256=request_sha256,
                )

            if self._clock.monotonic() >= invocation_deadline:
                return self._finish(
                    sequence=sequence,
                    started_at=started_at,
                    outcome=(
                        ProbeOutcome.BUDGET_EXHAUSTED
                        if elapsed_limited
                        else ProbeOutcome.TIMED_OUT
                    ),
                    reason=(
                        ProbeStopReason.ELAPSED_BUDGET_EXHAUSTED
                        if elapsed_limited
                        else ProbeStopReason.PROBE_TIMEOUT
                    ),
                    capability_name=capability_name,
                    capability_version=capability_version,
                    request_sha256=request_sha256,
                )

            if raw_observation is None:
                raise RuntimeError("completed invocation omitted its observation")
            if self._deadline_reached():
                return self._finish(
                    sequence=sequence,
                    started_at=started_at,
                    outcome=ProbeOutcome.BUDGET_EXHAUSTED,
                    reason=ProbeStopReason.ELAPSED_BUDGET_EXHAUSTED,
                    capability_name=capability_name,
                    capability_version=capability_version,
                    request_sha256=request_sha256,
                )
            try:
                observation_payload = canonical_json_bytes(raw_observation)
                ProbeObservation.model_validate_json(observation_payload)
            except (ContractError, TypeError, ValueError):
                return self._finish(
                    sequence=sequence,
                    started_at=started_at,
                    outcome=ProbeOutcome.MALFORMED,
                    reason=ProbeStopReason.MALFORMED_OBSERVATION,
                    capability_name=capability_name,
                    capability_version=capability_version,
                    request_sha256=request_sha256,
                )

            byte_count = len(observation_payload)
            self._result_bytes_acquired = min(
                self._result_bytes_acquired + byte_count,
                2**63 - 1,
            )
            if self._deadline_reached():
                return self._finish(
                    sequence=sequence,
                    started_at=started_at,
                    outcome=ProbeOutcome.BUDGET_EXHAUSTED,
                    reason=ProbeStopReason.ELAPSED_BUDGET_EXHAUSTED,
                    capability_name=capability_name,
                    capability_version=capability_version,
                    request_sha256=request_sha256,
                    rejected_result_bytes=byte_count,
                )
            if byte_count > registration.capability.result_byte_ceiling:
                return self._finish(
                    sequence=sequence,
                    started_at=started_at,
                    outcome=ProbeOutcome.BUDGET_EXHAUSTED,
                    reason=ProbeStopReason.RESULT_TOO_LARGE,
                    capability_name=capability_name,
                    capability_version=capability_version,
                    request_sha256=request_sha256,
                    rejected_result_bytes=byte_count,
                )
            if self._result_bytes_acquired > budget.max_total_result_bytes:
                return self._finish(
                    sequence=sequence,
                    started_at=started_at,
                    outcome=ProbeOutcome.BUDGET_EXHAUSTED,
                    reason=ProbeStopReason.TOTAL_RESULT_BYTES_EXHAUSTED,
                    capability_name=capability_name,
                    capability_version=capability_version,
                    request_sha256=request_sha256,
                    rejected_result_bytes=byte_count,
                )

            validated = ValidatedObservation(
                canonical_json=observation_payload,
                sha256=hashlib.sha256(observation_payload).hexdigest(),
                byte_count=byte_count,
            )
            return self._finish(
                sequence=sequence,
                started_at=started_at,
                outcome=ProbeOutcome.COMPLETED,
                reason=ProbeStopReason.PROBE_COMPLETED,
                capability_name=capability_name,
                capability_version=capability_version,
                request_sha256=request_sha256,
                observation=validated,
            )

    async def _invoke_once(
        self,
        handler: ObservationHandler,
        probe: BoundProbe,
        timeout_seconds: float,
    ) -> tuple[_InvocationState, ProbeObservation | None]:
        async def call_handler() -> ProbeObservation:
            result = handler(probe)
            if not inspect.isawaitable(result):
                raise TypeError("observation handler is not asynchronous")
            return await result

        handler_task = asyncio.create_task(call_handler())
        cancellation_task = asyncio.create_task(self._cancelled.wait())
        try:
            done, _ = await asyncio.wait(
                {handler_task, cancellation_task},
                timeout=timeout_seconds,
                return_when=asyncio.FIRST_COMPLETED,
            )
        except asyncio.CancelledError:
            _discard_task(handler_task)
            _discard_task(cancellation_task)
            raise

        if not done:
            _discard_task(handler_task)
            _discard_task(cancellation_task)
            return _InvocationState.TIMED_OUT, None
        if cancellation_task in done:
            _discard_task(handler_task)
            _discard_task(cancellation_task)
            return _InvocationState.CANCELLED, None

        _discard_task(cancellation_task)
        try:
            observation = handler_task.result()
        except asyncio.CancelledError:
            return _InvocationState.CANCELLED, None
        except CapabilityUnavailable:
            return _InvocationState.UNAVAILABLE, None
        except (ContractError, TypeError, ValueError):
            return _InvocationState.MALFORMED, None
        except Exception:
            return _InvocationState.UNAVAILABLE, None
        if not isinstance(observation, ProbeObservation):
            return _InvocationState.MALFORMED, None
        return _InvocationState.COMPLETED, observation


__all__ = [
    "ControllerAuditRecord",
    "ControllerClock",
    "ProbeController",
    "ProbeExecution",
    "ProbeStopReason",
    "ValidatedObservation",
]
