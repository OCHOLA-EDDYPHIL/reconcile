"""Focused tests for strict hosted internal contracts."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from reconcile.hosted.contracts import (
    INTERNAL_OPERATION_REQUEST_VERSION,
    INTERNAL_OPERATION_RESPONSE_VERSION,
    MAX_INTERNAL_PAYLOAD_BYTES,
    InternalOperation,
    InternalOperationRequest,
    InternalOperationResponse,
    canonical_internal_json_bytes,
)

pytestmark = pytest.mark.unit


def _request(**updates: object) -> InternalOperationRequest:
    values: dict[str, object] = {
        "schema_version": INTERNAL_OPERATION_REQUEST_VERSION,
        "request_id": "request-7",
        "operation": InternalOperation.READ_EVIDENCE,
        "payload": {"z": 2, "a": "bounded"},
    }
    values.update(updates)
    return InternalOperationRequest(**values)  # type: ignore[arg-type]


def _response(**updates: object) -> InternalOperationResponse:
    values: dict[str, object] = {
        "schema_version": INTERNAL_OPERATION_RESPONSE_VERSION,
        "request_id": "request-7",
        "operation": InternalOperation.READ_EVIDENCE,
        "accepted": True,
        "payload": {"state": "observed"},
    }
    values.update(updates)
    return InternalOperationResponse(**values)  # type: ignore[arg-type]


def test_internal_operations_are_exact_and_bounded() -> None:
    assert tuple(InternalOperation) == (
        InternalOperation.INVESTIGATE,
        InternalOperation.EXECUTE_FAULT,
        InternalOperation.READ_EVIDENCE,
        InternalOperation.CLEANUP,
        InternalOperation.RECOVER,
    )
    assert MAX_INTERNAL_PAYLOAD_BYTES == 16_384


def test_request_and_response_have_canonical_wire_encodings() -> None:
    assert canonical_internal_json_bytes(_request()) == (
        b'{"operation":"read-evidence","payload":{"a":"bounded","z":2},'
        b'"request_id":"request-7","schema_version":'
        b'"reconcile/internal-operation-request/v1"}'
    )
    assert canonical_internal_json_bytes(_response()) == (
        b'{"accepted":true,"operation":"read-evidence","payload":'
        b'{"state":"observed"},"request_id":"request-7",'
        b'"schema_version":"reconcile/internal-operation-response/v1"}'
    )


@pytest.mark.parametrize(
    "updates",
    (
        {"extra": "field"},
        {"request_id": 7},
        {"operation": "arbitrary"},
        {"schema_version": "reconcile/internal-operation-request/v2"},
    ),
)
def test_request_rejects_unknown_coerced_or_unsupported_fields(
    updates: dict[str, object],
) -> None:
    with pytest.raises(ValidationError):
        _request(**updates)


@pytest.mark.parametrize(
    "updates",
    (
        {"extra": "field"},
        {"accepted": 1},
        {"operation": "arbitrary"},
        {"schema_version": "reconcile/internal-operation-response/v2"},
    ),
)
def test_response_rejects_unknown_coerced_or_unsupported_fields(
    updates: dict[str, object],
) -> None:
    with pytest.raises(ValidationError):
        _response(**updates)


@pytest.mark.parametrize(
    "payload",
    (
        {"authorization": "value"},
        {"nested": {"access_token": "value"}},
        {"safe": "Bearer private-marker-123456"},
    ),
)
def test_internal_payloads_reject_auth_token_and_secret_material(
    payload: dict[str, object],
) -> None:
    with pytest.raises(ValidationError, match="secret-bearing"):
        _request(payload=payload)

    with pytest.raises(ValidationError, match="secret-bearing"):
        _response(payload=payload)


def test_internal_payload_has_a_canonical_byte_limit() -> None:
    with pytest.raises(ValidationError, match="byte limit"):
        _request(payload={"value": "x" * MAX_INTERNAL_PAYLOAD_BYTES})


def test_internal_payload_rejects_too_many_top_level_fields() -> None:
    payload = {f"field-{index}": index for index in range(17)}

    with pytest.raises(ValidationError):
        _request(payload=payload)


def test_canonical_encoder_requires_an_exact_internal_contract() -> None:
    class RequestSubclass(InternalOperationRequest):
        pass

    with pytest.raises(TypeError, match="exact internal operation contract"):
        canonical_internal_json_bytes(
            RequestSubclass(
                schema_version=INTERNAL_OPERATION_REQUEST_VERSION,
                request_id="request-7",
                operation=InternalOperation.CLEANUP,
                payload={},
            )
        )
