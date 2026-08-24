"""Strict internal wire contracts for hosted component calls."""

from __future__ import annotations

from enum import StrEnum
from typing import Annotated, Literal

from pydantic import AfterValidator, Field, JsonValue

from reconcile.contracts.base import (
    Identifier,
    StrictModel,
    canonical_json_value_bytes,
    reject_sensitive_keys,
    reject_sensitive_values,
)
from reconcile.contracts.codec import canonical_json_bytes

INTERNAL_OPERATION_REQUEST_VERSION = "reconcile/internal-operation-request/v1"
INTERNAL_OPERATION_RESPONSE_VERSION = "reconcile/internal-operation-response/v1"
MAX_INTERNAL_PAYLOAD_BYTES = 16_384


class InternalOperation(StrEnum):
    INVESTIGATE = "investigate"
    EXECUTE_FAULT = "execute-fault"
    READ_EVIDENCE = "read-evidence"
    CLEANUP = "cleanup"
    RECOVER = "recover"


def _validate_payload(value: dict[str, JsonValue]) -> dict[str, JsonValue]:
    reject_sensitive_keys(value)
    reject_sensitive_values(value)
    if len(canonical_json_value_bytes(value)) > MAX_INTERNAL_PAYLOAD_BYTES:
        raise ValueError("internal payload exceeds its byte limit")
    return value


type InternalPayload = Annotated[
    dict[str, JsonValue],
    Field(max_length=16),
    AfterValidator(_validate_payload),
]


class InternalOperationRequest(StrictModel):
    schema_version: Literal[INTERNAL_OPERATION_REQUEST_VERSION]
    request_id: Identifier
    operation: InternalOperation
    payload: InternalPayload


class InternalOperationResponse(StrictModel):
    schema_version: Literal[INTERNAL_OPERATION_RESPONSE_VERSION]
    request_id: Identifier
    operation: InternalOperation
    accepted: bool
    payload: InternalPayload


def canonical_internal_json_bytes(
    contract: InternalOperationRequest | InternalOperationResponse,
) -> bytes:
    """Encode an exact internal contract as canonical JSON."""

    if type(contract) not in {InternalOperationRequest, InternalOperationResponse}:
        raise TypeError("an exact internal operation contract is required")
    return canonical_json_bytes(contract)


__all__ = [
    "INTERNAL_OPERATION_REQUEST_VERSION",
    "INTERNAL_OPERATION_RESPONSE_VERSION",
    "MAX_INTERNAL_PAYLOAD_BYTES",
    "InternalOperation",
    "InternalOperationRequest",
    "InternalOperationResponse",
    "canonical_internal_json_bytes",
]
