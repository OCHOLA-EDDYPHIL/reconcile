"""Frozen versioned API error and investigation-event contracts."""

from __future__ import annotations

from enum import StrEnum
from typing import Literal

from pydantic import ConfigDict, Field, model_validator

from reconcile.contracts.base import (
    AwareDatetime,
    Identifier,
    ShortText,
    SmallJsonObject,
    StrictModel,
    reject_sensitive_keys,
)
from reconcile.contracts.common import Classification
from reconcile.contracts.evidence import EvidenceDecision
from reconcile.contracts.report import (
    ActionGateResult,
    InvestigationStatus,
    ProbeAuditRecord,
)

ERROR_VERSION = "reconcile/error/v1"
INVESTIGATION_EVENT_VERSION = "reconcile/investigation-event/v1"

MAX_INVESTIGATION_EVENTS = 137

_INTERNAL_ERROR_DETAIL_KEYS = frozenset(
    {"exception", "stack", "stacktrace", "traceback"}
)


def _reject_internal_error_details(value: object) -> None:
    if isinstance(value, dict):
        for key, item in value.items():
            normalized = "".join(
                character for character in key.lower() if character.isalnum()
            )
            if normalized in _INTERNAL_ERROR_DETAIL_KEYS:
                raise ValueError("internal failure material is not allowed")
            _reject_internal_error_details(item)
    elif isinstance(value, list):
        for item in value:
            _reject_internal_error_details(item)


class ApiErrorCode(StrEnum):
    INVALID_CONTRACT = "invalid_contract"
    UNSUPPORTED_CONTRACT_VERSION = "unsupported_contract_version"
    INVESTIGATION_NOT_FOUND = "investigation_not_found"
    DUPLICATE_INVESTIGATION_ID = "duplicate_investigation_id"
    DEPENDENCY_UNAVAILABLE = "dependency_unavailable"
    INTERNAL_FAILURE = "internal_failure"


class ApiError(StrictModel):
    schema_version: Literal[ERROR_VERSION]
    code: ApiErrorCode
    message: ShortText
    details: SmallJsonObject

    @model_validator(mode="after")
    def validate_details(self) -> ApiError:
        reject_sensitive_keys(self.details)
        _reject_internal_error_details(self.details)
        return self


class InvestigationEventType(StrEnum):
    LIFECYCLE = "LIFECYCLE"
    PROBE = "PROBE"
    EVIDENCE_DECISION = "EVIDENCE_DECISION"
    CLASSIFICATION = "CLASSIFICATION"
    ACTION_GATE = "ACTION_GATE"


class LifecycleEventPayload(StrictModel):
    status: InvestigationStatus


class ProbeEventPayload(StrictModel):
    probe_audit: ProbeAuditRecord


class EvidenceDecisionEventPayload(StrictModel):
    decision: EvidenceDecision


class ClassificationEventPayload(StrictModel):
    classification: Classification


class ActionGateEventPayload(StrictModel):
    action_gate: ActionGateResult


type InvestigationEventPayload = (
    LifecycleEventPayload
    | ProbeEventPayload
    | EvidenceDecisionEventPayload
    | ClassificationEventPayload
    | ActionGateEventPayload
)


class InvestigationEvent(StrictModel):
    model_config = ConfigDict(
        json_schema_extra={
            "allOf": [
                {
                    "if": {
                        "properties": {"type": {"const": event_type.value}},
                        "required": ["type"],
                    },
                    "then": {"properties": {"payload": {"required": [payload_field]}}},
                }
                for event_type, payload_field in (
                    (InvestigationEventType.LIFECYCLE, "status"),
                    (InvestigationEventType.PROBE, "probe_audit"),
                    (InvestigationEventType.EVIDENCE_DECISION, "decision"),
                    (InvestigationEventType.CLASSIFICATION, "classification"),
                    (InvestigationEventType.ACTION_GATE, "action_gate"),
                )
            ]
        }
    )

    schema_version: Literal[INVESTIGATION_EVENT_VERSION]
    investigation_id: Identifier
    sequence: int = Field(ge=1, le=MAX_INVESTIGATION_EVENTS)
    type: InvestigationEventType
    occurred_at: AwareDatetime
    payload: InvestigationEventPayload

    @model_validator(mode="after")
    def validate_event(self) -> InvestigationEvent:
        expected_payload = {
            InvestigationEventType.LIFECYCLE: LifecycleEventPayload,
            InvestigationEventType.PROBE: ProbeEventPayload,
            InvestigationEventType.EVIDENCE_DECISION: EvidenceDecisionEventPayload,
            InvestigationEventType.CLASSIFICATION: ClassificationEventPayload,
            InvestigationEventType.ACTION_GATE: ActionGateEventPayload,
        }[self.type]
        if not isinstance(self.payload, expected_payload):
            raise ValueError("event type does not match its payload")
        return self
