"""Authenticated and scenario-authorized Cloud Run canary mutations.

Caller identity is only the first gate.  Every request also carries the existing
fenced hosted operation scope, which is checked against durable scenario state.
Release identity and immutable deployment inputs are then bound to that scope and
the running candidate before any provider mutation.  The hosted runtime installs a
closed authorizer until the single-use permit dispatcher supplies this boundary;
caller identity and a replayable scenario lease are intentionally insufficient.
"""

from __future__ import annotations

import asyncio
import hashlib
from http import HTTPStatus
from typing import Literal, Protocol

from fastapi import FastAPI, Request
from fastapi.responses import Response
from pydantic import model_validator
from starlette.types import Receive, Scope, Send

from reconcile.contracts.base import (
    AwareDatetime,
    Identifier,
    NonEmptyText,
    StrictModel,
)
from reconcile.contracts.codec import canonical_json_bytes, decode_contract
from reconcile.hosted.cloud_run_canary import (
    CloudRunAcceptanceAmbiguity,
    CloudRunAcceptedOperation,
    CloudRunCanaryAction,
    CloudRunCanaryError,
    CloudRunCanaryErrorCode,
    CloudRunCanaryFaultProxy,
    CloudRunFaultMode,
)
from reconcile.hosted.identity import VerifiedCaller
from reconcile.hosted.workflow import HostedOperationScope, HostedWorkflowOperation

CLOUD_RUN_CANARY_ACTION_PATH = "/internal/v1/cloud-run-canary/actions"
CLOUD_RUN_CANARY_ACTION_REQUEST_VERSION = "reconcile/cloud-run-canary-action-request/v1"
CLOUD_RUN_CANARY_ACTION_RESPONSE_VERSION = (
    "reconcile/cloud-run-canary-action-response/v1"
)

_MAX_ACTION_REQUEST_BYTES = 4_096


class CloudRunCanaryActionRequest(StrictModel):
    schema_version: Literal[CLOUD_RUN_CANARY_ACTION_REQUEST_VERSION]
    request_id: Identifier
    action: CloudRunCanaryAction
    fault_mode: CloudRunFaultMode
    operation_id: Identifier | None = None
    release_id: str | None = None
    image_digest: str | None = None
    configuration_sha256: str | None = None
    revision: str | None = None
    service_etag: str | None = None
    scope: HostedOperationScope

    @model_validator(mode="after")
    def validate_action_fields(self) -> CloudRunCanaryActionRequest:
        populated = {
            name
            for name in (
                "operation_id",
                "release_id",
                "image_digest",
                "configuration_sha256",
                "revision",
                "service_etag",
            )
            if getattr(self, name) is not None
        }
        expected = {
            CloudRunCanaryAction.STAGE: {
                "operation_id",
                "release_id",
                "image_digest",
                "configuration_sha256",
            },
            CloudRunCanaryAction.PROMOTE: {
                "release_id",
                "revision",
                "service_etag",
            },
            CloudRunCanaryAction.RESET: set(),
        }[self.action]
        if populated != expected:
            raise ValueError("canary action fields are incomplete or mixed")
        for name in populated:
            value = getattr(self, name)
            if (
                type(value) is not str
                or not value
                or len(value) > 512
                or any(
                    ord(character) < 32 or ord(character) == 127 for character in value
                )
            ):
                raise ValueError("canary action field is invalid")
        expected_operation = (
            HostedWorkflowOperation.CLEANUP
            if self.action is CloudRunCanaryAction.RESET
            else HostedWorkflowOperation.EXECUTE_FAULT
        )
        if self.scope.operation is not expected_operation:
            raise ValueError("canary action does not match its authorized scope")
        if (
            self.action is CloudRunCanaryAction.STAGE
            and self.operation_id != self.scope.operation_id
        ):
            raise ValueError("canary action operation identity changed")
        return self


class CloudRunCanaryActionResponse(StrictModel):
    schema_version: Literal[CLOUD_RUN_CANARY_ACTION_RESPONSE_VERSION]
    request_id: Identifier
    accepted: Literal[True]
    operation_name: NonEmptyText
    revision: Identifier
    accepted_at: AwareDatetime
    service_etag: NonEmptyText


class CloudRunCanaryActionAuthorizer(Protocol):
    async def __call__(self, request: CloudRunCanaryActionRequest) -> None: ...


class ClosedCloudRunCanaryActionAuthorizer:
    """Fail closed until an atomic, single-use permit claim owns dispatch."""

    async def __call__(self, request: CloudRunCanaryActionRequest) -> None:
        if type(request) is not CloudRunCanaryActionRequest:
            raise TypeError("canary action authority requires an exact request")
        raise PermissionError("canary permit integration is not installed")


def cloud_run_release_id(scope: HostedOperationScope) -> str:
    """Derive the stable provider label from a durable authorized investigation."""

    if type(scope) is not HostedOperationScope:
        raise TypeError("canary release identity requires an exact operation scope")
    suffix = hashlib.sha256(scope.investigation_id.encode("utf-8")).hexdigest()[:16]
    return f"release-{suffix}"


class _DisconnectAfterAcceptance(Response):
    """Start an HTTP response, then close it without an acknowledgement body."""

    def __init__(self) -> None:
        super().__init__(
            status_code=HTTPStatus.OK,
            media_type="application/json",
            headers={"Cache-Control": "no-store"},
        )
        self.raw_headers = [
            (name, b"1") if name == b"content-length" else (name, value)
            for name, value in self.raw_headers
        ]

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        await send(
            {
                "type": "http.response.start",
                "status": self.status_code,
                "headers": self.raw_headers,
            }
        )
        raise CloudRunAcceptanceAmbiguity


def _error(*, code: str, status: HTTPStatus) -> Response:
    return Response(
        content=f'{{"code":"{code}"}}'.encode("ascii"),
        status_code=status,
        media_type="application/json",
        headers={"Cache-Control": "no-store"},
    )


async def _read_request(request: Request) -> CloudRunCanaryActionRequest:
    if request.url.query:
        raise ValueError
    if request.headers.get("content-type", "").split(";", 1)[0].strip().lower() != (
        "application/json"
    ):
        raise ValueError
    content_length = request.headers.get("content-length")
    if content_length is not None:
        try:
            declared = int(content_length)
        except ValueError as error:
            raise ValueError from error
        if not 1 <= declared <= _MAX_ACTION_REQUEST_BYTES:
            raise ValueError
    body = bytearray()
    async for chunk in request.stream():
        body.extend(chunk)
        if len(body) > _MAX_ACTION_REQUEST_BYTES:
            raise ValueError
    if not body:
        raise ValueError
    decoded = decode_contract(bytes(body), CloudRunCanaryActionRequest)
    if canonical_json_bytes(decoded) != bytes(body):
        raise ValueError
    return decoded


def _field(value: str | None) -> str:
    if type(value) is not str:
        raise TypeError("validated action field is unavailable")
    return value


def _invoke(
    proxy: CloudRunCanaryFaultProxy,
    request: CloudRunCanaryActionRequest,
) -> CloudRunAcceptedOperation:
    if request.action is CloudRunCanaryAction.STAGE:
        return proxy.stage_revision(
            mode=request.fault_mode,
            operation_id=_field(request.operation_id),
            release_id=_field(request.release_id),
            image_digest=_field(request.image_digest),
            configuration_sha256=_field(request.configuration_sha256),
        )
    if request.action is CloudRunCanaryAction.PROMOTE:
        return proxy.promote_revision(
            mode=request.fault_mode,
            release_id=_field(request.release_id),
            revision=_field(request.revision),
            service_etag=_field(request.service_etag),
        )
    return proxy.reset(mode=request.fault_mode)


def install_cloud_run_canary_fault_route(
    application: FastAPI,
    *,
    proxy: CloudRunCanaryFaultProxy,
    action_authorizer: CloudRunCanaryActionAuthorizer,
    expected_caller_email: str,
    expected_image_digest: str,
    expected_configuration_sha256: str,
) -> None:
    """Install the one authenticated mutation endpoint on the fault proxy app."""

    if not isinstance(application, FastAPI):
        raise TypeError("canary fault route requires a FastAPI application")
    if type(proxy) is not CloudRunCanaryFaultProxy:
        raise TypeError("canary fault route requires the exact fault proxy")
    if not callable(action_authorizer):
        raise TypeError("canary fault route requires an action authorizer")
    if type(expected_caller_email) is not str or not expected_caller_email:
        raise TypeError("canary fault route requires an expected caller")
    if (
        type(expected_image_digest) is not str
        or type(expected_configuration_sha256) is not str
    ):
        raise TypeError("canary fault route requires immutable candidate identity")

    async def invoke(request: Request) -> Response:
        try:
            action = await _read_request(request)
        except (TypeError, ValueError):
            return _error(code="invalid-contract", status=HTTPStatus.BAD_REQUEST)
        caller = getattr(request.state, "verified_caller", None)
        if type(caller) is not VerifiedCaller or caller.email != expected_caller_email:
            return _error(code="operation-denied", status=HTTPStatus.FORBIDDEN)
        if (
            action.action is not CloudRunCanaryAction.RESET
            and action.release_id != cloud_run_release_id(action.scope)
        ) or (
            action.action is CloudRunCanaryAction.STAGE
            and (
                action.image_digest != expected_image_digest
                or action.configuration_sha256 != expected_configuration_sha256
            )
        ):
            return _error(code="operation-denied", status=HTTPStatus.FORBIDDEN)
        try:
            await action_authorizer(action)
        except asyncio.CancelledError:
            raise
        except Exception:
            return _error(code="operation-denied", status=HTTPStatus.FORBIDDEN)
        try:
            receipt = await asyncio.to_thread(_invoke, proxy, action)
        except CloudRunAcceptanceAmbiguity:
            return _DisconnectAfterAcceptance()
        except CloudRunCanaryError as error:
            status = {
                CloudRunCanaryErrorCode.PERMISSION_DENIED: HTTPStatus.FORBIDDEN,
                CloudRunCanaryErrorCode.INVALID_CONFIGURATION: HTTPStatus.BAD_REQUEST,
                CloudRunCanaryErrorCode.STALE_ETAG: HTTPStatus.CONFLICT,
                CloudRunCanaryErrorCode.REVISION_NOT_FOUND: HTTPStatus.CONFLICT,
                CloudRunCanaryErrorCode.AMBIGUOUS_REVISION: HTTPStatus.CONFLICT,
                CloudRunCanaryErrorCode.REVISION_NOT_READY: HTTPStatus.CONFLICT,
            }.get(error.code, HTTPStatus.SERVICE_UNAVAILABLE)
            return _error(code=error.code.value, status=status)
        response = CloudRunCanaryActionResponse(
            schema_version=CLOUD_RUN_CANARY_ACTION_RESPONSE_VERSION,
            request_id=action.request_id,
            accepted=True,
            operation_name=receipt.operation_name,
            revision=receipt.revision,
            accepted_at=receipt.accepted_at,
            service_etag=receipt.service_etag,
        )
        return Response(
            content=canonical_json_bytes(response),
            status_code=HTTPStatus.OK,
            media_type="application/json",
            headers={"Cache-Control": "no-store"},
        )

    application.add_api_route(
        CLOUD_RUN_CANARY_ACTION_PATH,
        invoke,
        methods=["POST"],
        response_model=None,
    )


__all__ = [
    "CLOUD_RUN_CANARY_ACTION_PATH",
    "CLOUD_RUN_CANARY_ACTION_REQUEST_VERSION",
    "CLOUD_RUN_CANARY_ACTION_RESPONSE_VERSION",
    "ClosedCloudRunCanaryActionAuthorizer",
    "CloudRunCanaryActionAuthorizer",
    "CloudRunCanaryActionRequest",
    "CloudRunCanaryActionResponse",
    "cloud_run_release_id",
    "install_cloud_run_canary_fault_route",
]
