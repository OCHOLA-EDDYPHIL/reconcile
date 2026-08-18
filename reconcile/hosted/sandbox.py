"""Restricted Firestore reads for hosted sandbox weak observations."""

from __future__ import annotations

import asyncio
import hashlib
import re
from collections.abc import AsyncIterator, Callable
from datetime import UTC, datetime
from enum import StrEnum
from http import HTTPStatus
from typing import Any, Literal, Never, Protocol
from urllib.parse import urlsplit

from pydantic import ValidationError

from reconcile.contracts.base import (
    AwareDatetime,
    Identifier,
    StrictModel,
    canonical_json_value_bytes,
)
from reconcile.contracts.codec import decode_contract
from reconcile.hosted.contracts import (
    INTERNAL_OPERATION_REQUEST_VERSION,
    InternalOperation,
    InternalOperationRequest,
    InternalOperationResponse,
    canonical_internal_json_bytes,
)
from reconcile.hosted.transport import (
    HostedHttpResponse,
    HostedHttpTransport,
    HostedRequestError,
    HostedTransportError,
)
from reconcile.scenarios.local_order import (
    WeakIngressObservation,
    WeakOrderAggregateObservation,
    WeakOrderCountBand,
)

SANDBOX_INGRESS_SCHEMA_VERSION = "reconcile/sandbox-ingress-observation/v1"
SANDBOX_AGGREGATE_SCHEMA_VERSION = "reconcile/sandbox-aggregate-observation/v1"
SANDBOX_FIRESTORE_TIMEOUT_SECONDS = 5.0
SANDBOX_TARGET_DATABASE_ID = "reconcile-p5-target"

_ROOT_COLLECTION = "reconcile-sandbox-observations"
_OBSERVATION_COLLECTION = "weak-observations"
_EVIDENCE_PATH = "/internal/v1/evidence"
_PROJECT_PATTERN = re.compile(r"[a-z][a-z0-9-]{4,28}[a-z0-9]")
_HOST_PATTERN = re.compile(
    r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?"
    r"(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+"
)
_INGRESS_FIELDS = (
    "event_kind",
    "observed_at",
    "sandbox_id",
    "schema_version",
)
_AGGREGATE_FIELDS = (
    "count_band",
    "observed_at",
    "sandbox_id",
    "schema_version",
)

type SandboxObservationKind = Literal["ingress", "aggregate"]


class SandboxEvidenceFailure(StrEnum):
    """Stable weak-observation failure codes."""

    CREDENTIALS_UNAVAILABLE = "credentials-unavailable"
    DEPENDENCY_UNAVAILABLE = "dependency-unavailable"
    MALFORMED_RESPONSE = "malformed-response"
    TIMEOUT = "timeout"
    UNAVAILABLE = "unavailable"


class SandboxEvidenceError(RuntimeError):
    """Sanitized weak-observation boundary failure."""

    def __init__(self, code: SandboxEvidenceFailure) -> None:
        if type(code) is not SandboxEvidenceFailure:
            raise TypeError("a sandbox evidence failure code is required")
        self.code = code
        super().__init__(code.value)


class SandboxEvidenceRequest(StrictModel):
    """One exact weak observation selected for one bounded sandbox."""

    sandbox_id: Identifier
    observation: SandboxObservationKind


class SandboxIngressObservation(StrictModel):
    event_kind: Literal["REQUEST_SEEN"]
    observed_at: AwareDatetime


class SandboxAggregateObservation(StrictModel):
    count_band: Literal["ZERO", "ONE_OR_MORE"]
    observed_at: AwareDatetime


class SandboxIngressEvidence(StrictModel):
    ingress: SandboxIngressObservation | None


class SandboxAggregateEvidence(StrictModel):
    aggregate: SandboxAggregateObservation | None


type SandboxEvidence = SandboxIngressEvidence | SandboxAggregateEvidence


class SandboxEvidenceReader(Protocol):
    async def read_evidence(
        self,
        request: SandboxEvidenceRequest,
    ) -> SandboxEvidence: ...


class _StoredIngressObservation(StrictModel):
    schema_version: Literal["reconcile/sandbox-ingress-observation/v1"]
    sandbox_id: Identifier
    event_kind: Literal["REQUEST_SEEN"]
    observed_at: AwareDatetime


class _StoredAggregateObservation(StrictModel):
    schema_version: Literal["reconcile/sandbox-aggregate-observation/v1"]
    sandbox_id: Identifier
    count_band: Literal["ZERO", "ONE_OR_MORE"]
    observed_at: AwareDatetime


class _DocumentReferencePort(Protocol):
    path: str


class _DocumentSnapshotPort(Protocol):
    reference: _DocumentReferencePort
    exists: bool
    read_time: object
    update_time: object | None

    def to_dict(self) -> dict[str, Any] | None: ...


class AsyncSandboxFirestoreClientPort(Protocol):
    def document(self, *document_path: str) -> _DocumentReferencePort: ...

    def get_all(
        self,
        references: list[_DocumentReferencePort],
        field_paths: object | None = None,
        transaction: object | None = None,
        retry: object | None = None,
        timeout: float | None = None,
        *,
        read_time: datetime | None = None,
    ) -> AsyncIterator[_DocumentSnapshotPort]: ...


type SandboxFirestoreClientFactory = Callable[[], AsyncSandboxFirestoreClientPort]


def _hosted_origin(value: object) -> str:
    if type(value) is not str or not 1 <= len(value) <= 2_048:
        raise ValueError("hosted sandbox origin is invalid")
    try:
        parsed = urlsplit(value)
        port = parsed.port
    except ValueError as error:
        raise ValueError("hosted sandbox origin is invalid") from error
    if (
        parsed.scheme != "https"
        or parsed.username is not None
        or parsed.password is not None
        or parsed.hostname is None
        or parsed.hostname != parsed.hostname.lower()
        or _HOST_PATTERN.fullmatch(parsed.hostname) is None
        or port is not None
        or parsed.path
        or parsed.query
        or parsed.fragment
        or value != f"https://{parsed.hostname}"
    ):
        raise ValueError("hosted sandbox origin is invalid")
    return value


def _hosted_audience(value: object) -> str:
    if type(value) is not str or not 1 <= len(value) <= 2_048:
        raise ValueError("hosted sandbox audience is invalid")
    try:
        encoded = value.encode("ascii")
    except UnicodeEncodeError as error:
        raise ValueError("hosted sandbox audience is invalid") from error
    if any(byte < 33 or byte == 127 for byte in encoded):
        raise ValueError("hosted sandbox audience is invalid")
    return value


def _sandbox_request(
    *,
    sandbox_id: str,
    observation: SandboxObservationKind,
) -> tuple[SandboxEvidenceRequest, InternalOperationRequest]:
    selection = SandboxEvidenceRequest(
        sandbox_id=sandbox_id,
        observation=observation,
    )
    payload = selection.model_dump(mode="json")
    request_digest = hashlib.sha256(canonical_json_value_bytes(payload)).hexdigest()
    request = InternalOperationRequest(
        schema_version=INTERNAL_OPERATION_REQUEST_VERSION,
        request_id=f"sandbox-evidence-{observation}-{request_digest[:32]}",
        operation=InternalOperation.READ_EVIDENCE,
        payload=payload,
    )
    return selection, request


def _malformed_hosted_response() -> Never:
    raise SandboxEvidenceError(SandboxEvidenceFailure.MALFORMED_RESPONSE) from None


def _decode_hosted_evidence(
    response: HostedHttpResponse,
    *,
    selection: SandboxEvidenceRequest,
    request: InternalOperationRequest,
) -> SandboxEvidence:
    if type(response) is not HostedHttpResponse:
        _malformed_hosted_response()
    if response.status_code != HTTPStatus.OK:
        raise SandboxEvidenceError(SandboxEvidenceFailure.UNAVAILABLE) from None
    if type(response.content) is not bytes:
        _malformed_hosted_response()
    try:
        decoded = decode_contract(response.content, InternalOperationResponse)
        if response.content != canonical_internal_json_bytes(decoded):
            _malformed_hosted_response()
        if (
            decoded.request_id != request.request_id
            or decoded.operation is not InternalOperation.READ_EVIDENCE
            or decoded.accepted is not True
        ):
            _malformed_hosted_response()
        payload_bytes = canonical_json_value_bytes(decoded.payload)
        if selection.observation == "ingress":
            evidence: SandboxEvidence = SandboxIngressEvidence.model_validate_json(
                payload_bytes
            )
        else:
            evidence = SandboxAggregateEvidence.model_validate_json(payload_bytes)
        if decoded.payload != sandbox_evidence_payload(selection, evidence):
            _malformed_hosted_response()
        return evidence
    except SandboxEvidenceError:
        raise
    except (TypeError, ValueError):
        _malformed_hosted_response()


class HostedSandboxEvidenceTarget:
    """Read one weak observation through the authenticated sandbox boundary."""

    def __init__(
        self,
        *,
        sandbox_url: str,
        sandbox_audience: str,
        sandbox_id: str,
        transport: HostedHttpTransport,
    ) -> None:
        if type(transport) is not HostedHttpTransport:
            raise TypeError("hosted sandbox target requires the exact transport")
        try:
            _sandbox_request(sandbox_id=sandbox_id, observation="ingress")
        except (TypeError, ValueError) as error:
            raise ValueError("hosted sandbox identity is invalid") from error
        self._endpoint = f"{_hosted_origin(sandbox_url)}{_EVIDENCE_PATH}"
        self._audience = _hosted_audience(sandbox_audience)
        self._sandbox_id = sandbox_id
        self._transport = transport

    async def _read(self, observation: SandboxObservationKind) -> SandboxEvidence:
        selection, request = _sandbox_request(
            sandbox_id=self._sandbox_id,
            observation=observation,
        )
        try:
            response = await self._transport.request(
                "POST",
                self._endpoint,
                audience=self._audience,
                content=canonical_internal_json_bytes(request),
            )
        except (HostedRequestError, HostedTransportError):
            raise SandboxEvidenceError(SandboxEvidenceFailure.UNAVAILABLE) from None
        return _decode_hosted_evidence(
            response,
            selection=selection,
            request=request,
        )

    async def read_ingress_observation(self) -> WeakIngressObservation | None:
        evidence = await self._read("ingress")
        if type(evidence) is not SandboxIngressEvidence:
            _malformed_hosted_response()
        ingress = evidence.ingress
        if ingress is None:
            return None
        try:
            return WeakIngressObservation(
                event_kind=ingress.event_kind,
                observed_at=ingress.observed_at,
            )
        except (TypeError, ValueError):
            _malformed_hosted_response()

    async def read_aggregate_observation(
        self,
    ) -> WeakOrderAggregateObservation | None:
        evidence = await self._read("aggregate")
        if type(evidence) is not SandboxAggregateEvidence:
            _malformed_hosted_response()
        aggregate = evidence.aggregate
        if aggregate is None:
            return None
        try:
            return WeakOrderAggregateObservation(
                count_band=WeakOrderCountBand(aggregate.count_band),
                observed_at=aggregate.observed_at,
            )
        except (TypeError, ValueError):
            _malformed_hosted_response()


def _default_client_factory(
    project_id: str,
    database_id: str,
) -> SandboxFirestoreClientFactory:
    def create() -> AsyncSandboxFirestoreClientPort:
        from google.cloud import firestore_v1

        return firestore_v1.AsyncClient(
            project=project_id,
            database=database_id,
        )

    return create


def _provider_timestamp(value: object) -> datetime:
    if not isinstance(value, datetime) or value.tzinfo is None:
        raise ValueError("provider timestamp is not timezone-aware")
    if value.utcoffset() is None:
        raise ValueError("provider timestamp is not timezone-aware")
    return value.astimezone(UTC)


def _raise_provider_failure(error: Exception) -> None:
    if isinstance(error, SandboxEvidenceError):
        raise SandboxEvidenceError(error.code) from None
    if isinstance(error, TimeoutError):
        raise SandboxEvidenceError(SandboxEvidenceFailure.TIMEOUT) from None
    try:
        from google.api_core import exceptions as api_exceptions
        from google.auth import exceptions as auth_exceptions
    except ImportError:
        raise SandboxEvidenceError(
            SandboxEvidenceFailure.DEPENDENCY_UNAVAILABLE
        ) from None
    if isinstance(error, auth_exceptions.DefaultCredentialsError):
        code = SandboxEvidenceFailure.CREDENTIALS_UNAVAILABLE
    elif isinstance(error, api_exceptions.DeadlineExceeded):
        code = SandboxEvidenceFailure.TIMEOUT
    else:
        code = SandboxEvidenceFailure.UNAVAILABLE
    raise SandboxEvidenceError(code) from None


def _canonical_evidence_payload(
    request: SandboxEvidenceRequest,
    evidence: SandboxEvidence,
) -> dict[str, object]:
    if request.observation == "ingress":
        if type(evidence) is not SandboxIngressEvidence:
            raise TypeError("sandbox evidence kind does not match its request")
        ingress = evidence.ingress
        return {
            "ingress": (
                None
                if ingress is None
                else {
                    "event_kind": ingress.event_kind,
                    "observed_at": ingress.observed_at.isoformat(),
                }
            )
        }
    if type(evidence) is not SandboxAggregateEvidence:
        raise TypeError("sandbox evidence kind does not match its request")
    aggregate = evidence.aggregate
    return {
        "aggregate": (
            None
            if aggregate is None
            else {
                "count_band": aggregate.count_band,
                "observed_at": aggregate.observed_at.isoformat(),
            }
        )
    }


def sandbox_evidence_payload(
    request: SandboxEvidenceRequest,
    evidence: SandboxEvidence,
) -> dict[str, object]:
    """Return only the selected product-visible weak observation."""

    if type(request) is not SandboxEvidenceRequest:
        raise TypeError("an exact sandbox evidence request is required")
    return _canonical_evidence_payload(request, evidence)


class FirestoreSandboxEvidenceReader:
    """Read one projected weak observation from one deterministic document."""

    def __init__(
        self,
        *,
        project_id: str,
        database_id: str,
        timeout_seconds: float = SANDBOX_FIRESTORE_TIMEOUT_SECONDS,
        client_factory: SandboxFirestoreClientFactory | None = None,
    ) -> None:
        if (
            type(project_id) is not str
            or _PROJECT_PATTERN.fullmatch(project_id) is None
        ):
            raise ValueError("sandbox Firestore project identifier is invalid")
        if database_id != SANDBOX_TARGET_DATABASE_ID:
            raise ValueError("sandbox Firestore database identifier is invalid")
        if (
            type(timeout_seconds) not in {int, float}
            or float(timeout_seconds) != SANDBOX_FIRESTORE_TIMEOUT_SECONDS
        ):
            raise ValueError("sandbox Firestore timeout must use the fixed value")
        factory = client_factory or _default_client_factory(project_id, database_id)
        if not callable(factory):
            raise TypeError("sandbox Firestore client factory must be callable")
        self._project_id = project_id
        self._database_id = database_id
        self._timeout_seconds = float(timeout_seconds)
        self._client_factory = factory
        self._client: AsyncSandboxFirestoreClientPort | None = None
        self._client_lock = asyncio.Lock()

    async def _get_client(self) -> AsyncSandboxFirestoreClientPort:
        if self._client is not None:
            return self._client
        async with self._client_lock:
            if self._client is None:
                try:
                    client = self._client_factory()
                except ImportError:
                    raise SandboxEvidenceError(
                        SandboxEvidenceFailure.DEPENDENCY_UNAVAILABLE
                    ) from None
                except Exception as error:
                    _raise_provider_failure(error)
                if any(
                    not callable(getattr(client, name, None))
                    for name in ("document", "get_all")
                ):
                    raise SandboxEvidenceError(
                        SandboxEvidenceFailure.UNAVAILABLE
                    ) from None
                self._client = client
            return self._client

    @staticmethod
    def _reference(
        client: AsyncSandboxFirestoreClientPort,
        request: SandboxEvidenceRequest,
    ) -> _DocumentReferencePort:
        segments = (
            _ROOT_COLLECTION,
            request.sandbox_id,
            _OBSERVATION_COLLECTION,
            request.observation,
        )
        expected_path = "/".join(segments)
        try:
            reference = client.document(*segments)
            actual_path = reference.path
        except Exception as error:
            _raise_provider_failure(error)
        if actual_path != expected_path:
            raise SandboxEvidenceError(
                SandboxEvidenceFailure.MALFORMED_RESPONSE
            ) from None
        return reference

    async def _snapshot(
        self,
        *,
        client: AsyncSandboxFirestoreClientPort,
        reference: _DocumentReferencePort,
        field_paths: tuple[str, ...],
    ) -> _DocumentSnapshotPort:
        snapshots: list[_DocumentSnapshotPort] = []
        try:
            async with asyncio.timeout(self._timeout_seconds):
                iterator = client.get_all(
                    [reference],
                    field_paths=field_paths,
                    transaction=None,
                    retry=None,
                    timeout=self._timeout_seconds,
                    read_time=None,
                )
                async for snapshot in iterator:
                    if len(snapshots) == 1:
                        raise SandboxEvidenceError(
                            SandboxEvidenceFailure.MALFORMED_RESPONSE
                        )
                    snapshots.append(snapshot)
        except SandboxEvidenceError:
            raise
        except (AttributeError, TypeError, ValueError):
            raise SandboxEvidenceError(
                SandboxEvidenceFailure.MALFORMED_RESPONSE
            ) from None
        except Exception as error:
            _raise_provider_failure(error)
        if len(snapshots) != 1:
            raise SandboxEvidenceError(
                SandboxEvidenceFailure.MALFORMED_RESPONSE
            ) from None
        snapshot = snapshots[0]
        try:
            if snapshot.reference.path != reference.path:
                raise ValueError("provider returned a different document")
            if type(snapshot.exists) is not bool:
                raise TypeError("provider returned an invalid existence marker")
            _provider_timestamp(snapshot.read_time)
            if snapshot.exists:
                _provider_timestamp(snapshot.update_time)
            elif snapshot.update_time is not None:
                raise ValueError("missing provider document has an update time")
        except (AttributeError, TypeError, ValueError):
            raise SandboxEvidenceError(
                SandboxEvidenceFailure.MALFORMED_RESPONSE
            ) from None
        return snapshot

    @staticmethod
    def _document_data(snapshot: _DocumentSnapshotPort) -> dict[str, Any] | None:
        try:
            data = snapshot.to_dict()
        except Exception as error:
            _raise_provider_failure(error)
        if snapshot.exists:
            if type(data) is not dict:
                raise SandboxEvidenceError(
                    SandboxEvidenceFailure.MALFORMED_RESPONSE
                ) from None
            return data
        if data is not None:
            raise SandboxEvidenceError(
                SandboxEvidenceFailure.MALFORMED_RESPONSE
            ) from None
        return None

    async def read_evidence(
        self,
        request: SandboxEvidenceRequest,
    ) -> SandboxEvidence:
        if type(request) is not SandboxEvidenceRequest:
            raise TypeError("an exact sandbox evidence request is required")
        client = await self._get_client()
        reference = self._reference(client, request)
        field_paths = (
            _INGRESS_FIELDS if request.observation == "ingress" else _AGGREGATE_FIELDS
        )
        snapshot = await self._snapshot(
            client=client,
            reference=reference,
            field_paths=field_paths,
        )
        data = self._document_data(snapshot)
        if data is None:
            if request.observation == "ingress":
                return SandboxIngressEvidence(ingress=None)
            return SandboxAggregateEvidence(aggregate=None)
        try:
            if request.observation == "ingress":
                stored = _StoredIngressObservation.model_validate(data)
                if stored.sandbox_id != request.sandbox_id:
                    raise ValueError("stored sandbox identity does not match")
                return SandboxIngressEvidence(
                    ingress=SandboxIngressObservation(
                        event_kind=stored.event_kind,
                        observed_at=stored.observed_at,
                    )
                )
            stored_aggregate = _StoredAggregateObservation.model_validate(data)
            if stored_aggregate.sandbox_id != request.sandbox_id:
                raise ValueError("stored sandbox identity does not match")
            return SandboxAggregateEvidence(
                aggregate=SandboxAggregateObservation(
                    count_band=stored_aggregate.count_band,
                    observed_at=stored_aggregate.observed_at,
                )
            )
        except (TypeError, ValueError, ValidationError):
            raise SandboxEvidenceError(
                SandboxEvidenceFailure.MALFORMED_RESPONSE
            ) from None


__all__ = [
    "SANDBOX_AGGREGATE_SCHEMA_VERSION",
    "SANDBOX_FIRESTORE_TIMEOUT_SECONDS",
    "SANDBOX_INGRESS_SCHEMA_VERSION",
    "SANDBOX_TARGET_DATABASE_ID",
    "AsyncSandboxFirestoreClientPort",
    "FirestoreSandboxEvidenceReader",
    "HostedSandboxEvidenceTarget",
    "SandboxAggregateEvidence",
    "SandboxAggregateObservation",
    "SandboxEvidence",
    "SandboxEvidenceError",
    "SandboxEvidenceFailure",
    "SandboxEvidenceReader",
    "SandboxEvidenceRequest",
    "SandboxIngressEvidence",
    "SandboxIngressObservation",
    "SandboxObservationKind",
    "sandbox_evidence_payload",
]
