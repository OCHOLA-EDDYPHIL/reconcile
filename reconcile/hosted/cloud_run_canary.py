"""Isolated Cloud Run canary mutations and exact provider read surfaces.

The action adapter intentionally returns as soon as Cloud Run accepts an update.  It
never waits for the long-running operation, which makes the acceptance boundary
available to the fault harness without pretending that acceptance means commit.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import threading
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any, Protocol
from urllib.parse import urlsplit

from google.api_core import exceptions as api_exceptions
from google.cloud import run_v2
from google.protobuf import any_pb2, field_mask_pb2

CLOUD_RUN_CANARY_HEALTH_VERSION = "reconcile/cloud-run-canary-health/v1"
CLOUD_RUN_RELEASE_LABEL = "reconcile-release"
CLOUD_RUN_CONFIGURATION_ANNOTATION = "reconcile.dev/configuration-sha256"
CLOUD_RUN_RELEASE_ENV = "RECONCILE_CANARY_RELEASE_ID"
CLOUD_RUN_CONFIGURATION_ENV = "RECONCILE_CANARY_CONFIGURATION_SHA256"
CLOUD_RUN_IMAGE_DIGEST_ENV = "RECONCILE_IMAGE_DIGEST"
CLOUD_RUN_CANARY_MODULE = "reconcile.hosted.cloud_run_canary"

_IMAGE_DIGEST = re.compile(r"sha256:[0-9a-f]{64}")
_SHA256 = re.compile(r"[0-9a-f]{64}")
_PROJECT = re.compile(r"[a-z][a-z0-9-]{4,28}[a-z0-9]")
_LOCATION = re.compile(r"[a-z][a-z0-9-]{0,62}")
_SERVICE = re.compile(r"[a-z][a-z0-9-]{0,47}")
_REVISION = re.compile(r"[a-z][a-z0-9-]{0,62}")
_RELEASE = re.compile(r"[a-z][a-z0-9_-]{0,62}")
_TIMEOUT_SECONDS = 5.0
_HEALTH_BODY_CEILING = 4_096


class CloudRunCanaryErrorCode(StrEnum):
    INVALID_CONFIGURATION = "invalid_configuration"
    PROVIDER_UNAVAILABLE = "provider_unavailable"
    PERMISSION_DENIED = "permission_denied"
    STALE_ETAG = "stale_etag"
    REVISION_NOT_FOUND = "revision_not_found"
    AMBIGUOUS_REVISION = "ambiguous_revision"
    REVISION_NOT_READY = "revision_not_ready"
    HEALTH_FAILED = "health_failed"
    ACCEPTANCE_AMBIGUOUS = "acceptance_ambiguous"


class CloudRunCanaryError(RuntimeError):
    """A sanitized canary boundary error with no provider response attached."""

    def __init__(self, code: CloudRunCanaryErrorCode) -> None:
        self.code = code
        super().__init__(f"cloud run canary {code.value}")


class CloudRunAcceptanceAmbiguity(CloudRunCanaryError):
    """Cloud Run accepted an update but its operation response was dropped."""

    def __init__(self) -> None:
        super().__init__(CloudRunCanaryErrorCode.ACCEPTANCE_AMBIGUOUS)


class CloudRunRevisionAmbiguous(CloudRunCanaryError):
    def __init__(self) -> None:
        super().__init__(CloudRunCanaryErrorCode.AMBIGUOUS_REVISION)


class CloudRunFaultMode(StrEnum):
    PASS_THROUGH = "pass-through"
    DROP_AFTER_ACCEPT = "drop-after-accept"


class CloudRunCanaryAction(StrEnum):
    STAGE = "stage"
    PROMOTE = "promote"
    RESET = "reset"


@dataclass(frozen=True, slots=True)
class CloudRunCanaryTarget:
    project: str
    location: str
    service: str
    image_repository: str
    baseline_revision: str
    health_audience: str
    timeout_seconds: float = _TIMEOUT_SECONDS

    def __post_init__(self) -> None:
        valid = (
            _PROJECT.fullmatch(self.project) is not None
            and _LOCATION.fullmatch(self.location) is not None
            and _SERVICE.fullmatch(self.service) is not None
            and _REVISION.fullmatch(self.baseline_revision) is not None
            and self.baseline_revision.startswith(f"{self.service}-")
            and self.image_repository
            == (f"{self.location}-docker.pkg.dev/{self.project}/reconcile-p5/reconcile")
            and _valid_audience(self.health_audience)
            and type(self.timeout_seconds) is float
            and 0.1 <= self.timeout_seconds <= 30.0
        )
        if not valid:
            raise CloudRunCanaryError(CloudRunCanaryErrorCode.INVALID_CONFIGURATION)

    @property
    def service_name(self) -> str:
        return (
            f"projects/{self.project}/locations/{self.location}/services/{self.service}"
        )

    @property
    def revisions_parent(self) -> str:
        return self.service_name

    def revision_name(self, revision: str) -> str:
        selected = _revision(revision)
        return f"{self.service_name}/revisions/{selected}"


@dataclass(frozen=True, slots=True)
class CloudRunAcceptedOperation:
    operation_name: str
    revision: str
    accepted_at: datetime
    service_etag: str


@dataclass(frozen=True, slots=True)
class CloudRunServiceSnapshot:
    release_id: str
    revision: str
    service_etag: str
    generation: int
    observed_generation: int
    reconciling: bool
    terminal_condition: str
    revision_traffic_percent: int
    observed_at: datetime


@dataclass(frozen=True, slots=True)
class CloudRunRevisionSnapshot:
    release_id: str
    release_label: str
    revision: str
    image_digest: str
    configuration_sha256: str
    generation: int
    observed_generation: int
    reconciling: bool
    terminal_condition: str
    readiness: str
    observed_at: datetime


@dataclass(frozen=True, slots=True)
class CloudRunOperationSnapshot:
    release_id: str
    revision: str
    operation_name: str
    operation_state: str
    observed_at: datetime


@dataclass(frozen=True, slots=True)
class CloudRunHealthSnapshot:
    release_id: str
    revision: str
    health_status: str
    observed_at: datetime


class _ServicesClient(Protocol):
    def get_service(self, *, request: object, retry: object, timeout: float) -> Any: ...

    def update_service(
        self, *, request: object, retry: object, timeout: float
    ) -> Any: ...

    def get_operation(
        self, *, request: object, retry: object, timeout: float
    ) -> Any: ...


class _RevisionsClient(Protocol):
    def get_revision(
        self, *, request: object, retry: object, timeout: float
    ) -> Any: ...

    def list_revisions(
        self, *, request: object, retry: object, timeout: float
    ) -> Any: ...


class RevisionHealthClient(Protocol):
    def get(self, *, url: str, audience: str, timeout: float) -> tuple[int, bytes]: ...


type ServicesClientFactory = Callable[[], _ServicesClient]
type RevisionsClientFactory = Callable[[], _RevisionsClient]
type Clock = Callable[[], datetime]


def _services_client_factory() -> _ServicesClient:
    return run_v2.ServicesClient()


def _revisions_client_factory() -> _RevisionsClient:
    return run_v2.RevisionsClient()


def _now() -> datetime:
    return datetime.now(UTC)


def _valid_audience(value: object) -> bool:
    if type(value) is not str or not 1 <= len(value) <= 2_048:
        return False
    if any(character in value for character in ("\\", "@", "?", "#", "%")):
        return False
    try:
        parsed = urlsplit(value)
        port = parsed.port
    except Exception:
        return False
    return bool(
        parsed.scheme == "https"
        and parsed.hostname
        and parsed.username is None
        and parsed.password is None
        and parsed.query == ""
        and parsed.fragment == ""
        and (port is None or 1 <= port <= 65_535)
        and (not parsed.path or parsed.path.startswith("/"))
        and "//" not in parsed.path
    )


def _revision(value: object) -> str:
    if type(value) is not str:
        raise CloudRunCanaryError(CloudRunCanaryErrorCode.INVALID_CONFIGURATION)
    selected = value.rsplit("/", 1)[-1]
    if _REVISION.fullmatch(selected) is None:
        raise CloudRunCanaryError(CloudRunCanaryErrorCode.INVALID_CONFIGURATION)
    return selected


def _release(value: object) -> str:
    if type(value) is not str or _RELEASE.fullmatch(value) is None:
        raise CloudRunCanaryError(CloudRunCanaryErrorCode.INVALID_CONFIGURATION)
    return value


def _digest(value: object) -> str:
    if type(value) is not str or _IMAGE_DIGEST.fullmatch(value) is None:
        raise CloudRunCanaryError(CloudRunCanaryErrorCode.INVALID_CONFIGURATION)
    return value


def _configuration(value: object) -> str:
    if type(value) is not str or _SHA256.fullmatch(value) is None:
        raise CloudRunCanaryError(CloudRunCanaryErrorCode.INVALID_CONFIGURATION)
    return value


def _aware_utc(value: datetime) -> datetime:
    if not isinstance(value, datetime) or value.tzinfo is None:
        raise CloudRunCanaryError(CloudRunCanaryErrorCode.PROVIDER_UNAVAILABLE)
    if value.utcoffset() is None:
        raise CloudRunCanaryError(CloudRunCanaryErrorCode.PROVIDER_UNAVAILABLE)
    return value.astimezone(UTC)


def _map_provider_error(error: Exception) -> CloudRunCanaryError:
    if isinstance(error, api_exceptions.PermissionDenied):
        return CloudRunCanaryError(CloudRunCanaryErrorCode.PERMISSION_DENIED)
    if isinstance(error, (api_exceptions.Aborted, api_exceptions.FailedPrecondition)):
        return CloudRunCanaryError(CloudRunCanaryErrorCode.STALE_ETAG)
    if isinstance(error, api_exceptions.NotFound):
        return CloudRunCanaryError(CloudRunCanaryErrorCode.REVISION_NOT_FOUND)
    return CloudRunCanaryError(CloudRunCanaryErrorCode.PROVIDER_UNAVAILABLE)


def _terminal_condition(resource: object) -> tuple[bool, str, str]:
    condition = getattr(resource, "terminal_condition", None)
    if not int(getattr(condition, "state", 0) or 0):
        condition = next(
            (
                item
                for item in getattr(resource, "conditions", ())
                if getattr(item, "type_", "") == "Ready"
            ),
            None,
        )
    state = int(getattr(condition, "state", 0) or 0)
    reconciling = bool(getattr(resource, "reconciling", False)) or state in {
        int(run_v2.Condition.State.STATE_UNSPECIFIED),
        int(run_v2.Condition.State.CONDITION_PENDING),
        int(run_v2.Condition.State.CONDITION_RECONCILING),
    }
    if reconciling:
        return True, "NONE", "UNKNOWN"
    if state == int(run_v2.Condition.State.CONDITION_SUCCEEDED):
        return False, "SUCCEEDED", "READY"
    if state == int(run_v2.Condition.State.CONDITION_FAILED):
        return False, "FAILED", "NOT_READY"
    raise CloudRunCanaryError(CloudRunCanaryErrorCode.PROVIDER_UNAVAILABLE)


def _operation_name(operation: object, target: CloudRunCanaryTarget) -> str:
    candidates = (
        getattr(operation, "name", None),
        getattr(getattr(operation, "operation", None), "name", None),
        getattr(getattr(operation, "_operation", None), "name", None),
    )
    prefix = f"projects/{target.project}/locations/{target.location}/operations/"
    for candidate in candidates:
        if (
            type(candidate) is str
            and candidate.startswith(prefix)
            and len(candidate) > len(prefix)
            and "/" not in candidate[len(prefix) :]
        ):
            return candidate
    raise CloudRunCanaryError(CloudRunCanaryErrorCode.PROVIDER_UNAVAILABLE)


def _revision_for_attempt(service: str, operation_id: str) -> str:
    if type(operation_id) is not str or not 1 <= len(operation_id) <= 128:
        raise CloudRunCanaryError(CloudRunCanaryErrorCode.INVALID_CONFIGURATION)
    digest = hashlib.sha256(operation_id.encode("utf-8")).hexdigest()[:16]
    return _revision(f"{service}-r-{digest}")


def _tag_for_release(release_id: str) -> str:
    suffix = hashlib.sha256(release_id.encode("utf-8")).hexdigest()[:12]
    return f"verify-{suffix}"


def _tagged_revision_origin(
    service: object,
    *,
    target: CloudRunCanaryTarget,
    release_id: str,
) -> str:
    """Derive the sole allowed tagged origin from the exact provider Service URI."""

    value = getattr(service, "uri", None)
    if type(value) is not str:
        raise CloudRunCanaryError(CloudRunCanaryErrorCode.PROVIDER_UNAVAILABLE)
    try:
        parsed = urlsplit(value)
        hostname = parsed.hostname
        port = parsed.port
    except Exception:
        raise CloudRunCanaryError(
            CloudRunCanaryErrorCode.PROVIDER_UNAVAILABLE
        ) from None
    if (
        parsed.scheme != "https"
        or hostname is None
        or hostname != hostname.lower()
        or not hostname.endswith(".run.app")
        or not hostname.startswith(f"{target.service}-")
        or "---" in hostname
        or parsed.username is not None
        or parsed.password is not None
        or port is not None
        or parsed.path not in {"", "/"}
        or parsed.query
        or parsed.fragment
    ):
        raise CloudRunCanaryError(CloudRunCanaryErrorCode.PROVIDER_UNAVAILABLE)
    tagged_hostname = f"{_tag_for_release(release_id)}---{hostname}"
    if len(tagged_hostname) > 253:
        raise CloudRunCanaryError(CloudRunCanaryErrorCode.PROVIDER_UNAVAILABLE)
    return f"https://{tagged_hostname}"


def _same_revision(value: object, expected: str) -> bool:
    try:
        return _revision(value) == expected
    except CloudRunCanaryError:
        return False


def _operation_service(value: object) -> run_v2.Service:
    """Unpack only the provider-declared Cloud Run Service LRO resource."""

    if not isinstance(value, any_pb2.Any):
        raise CloudRunCanaryError(CloudRunCanaryErrorCode.PROVIDER_UNAVAILABLE)
    message = run_v2.Service.pb()()
    if not value.Is(message.DESCRIPTOR) or not value.Unpack(message):
        raise CloudRunCanaryError(CloudRunCanaryErrorCode.PROVIDER_UNAVAILABLE)
    return run_v2.Service.wrap(message)


def _validate_operation_resource(
    service: run_v2.Service,
    *,
    target: CloudRunCanaryTarget,
    action: CloudRunCanaryAction,
    release_id: str,
    revision: str,
    image_digest: str | None,
    configuration_sha256: str | None,
) -> None:
    """Bind one provider LRO to the exact accepted canary mutation."""

    if service.name != target.service_name:
        raise CloudRunCanaryError(CloudRunCanaryErrorCode.PROVIDER_UNAVAILABLE)
    traffic = tuple(service.traffic)
    selected = tuple(
        item for item in traffic if _same_revision(item.revision, revision)
    )
    if action is CloudRunCanaryAction.STAGE:
        if image_digest is None or configuration_sha256 is None:
            raise CloudRunCanaryError(CloudRunCanaryErrorCode.INVALID_CONFIGURATION)
        template = service.template
        containers = tuple(template.containers)
        others = tuple(
            item for item in traffic if not _same_revision(item.revision, revision)
        )
        valid = (
            template.revision == revision
            and dict(template.labels).get(CLOUD_RUN_RELEASE_LABEL) == release_id
            and dict(template.annotations).get(CLOUD_RUN_CONFIGURATION_ANNOTATION)
            == configuration_sha256
            and len(containers) == 1
            and containers[0].image == f"{target.image_repository}@{image_digest}"
            and len(selected) == 1
            and selected[0].percent == 0
            and selected[0].tag == _tag_for_release(release_id)
            and len(others) == 1
            and others[0].percent == 100
            and bool(others[0].revision)
        )
    elif action is CloudRunCanaryAction.PROMOTE:
        valid = (
            image_digest is None
            and configuration_sha256 is None
            and len(traffic) == 1
            and len(selected) == 1
            and selected[0].percent == 100
            and selected[0].tag == _tag_for_release(release_id)
        )
    else:
        raise CloudRunCanaryError(CloudRunCanaryErrorCode.INVALID_CONFIGURATION)
    if not valid:
        raise CloudRunCanaryError(CloudRunCanaryErrorCode.PROVIDER_UNAVAILABLE)


def _serving_revision(service: object) -> str:
    serving = {
        _revision(getattr(status, "revision", ""))
        for status in getattr(service, "traffic_statuses", ())
        if int(getattr(status, "percent", 0)) == 100 and getattr(status, "revision", "")
    }
    if len(serving) != 1:
        raise CloudRunCanaryError(CloudRunCanaryErrorCode.PROVIDER_UNAVAILABLE)
    return next(iter(serving))


def _set_canary_environment(
    template: run_v2.RevisionTemplate,
    *,
    release_id: str,
    image_digest: str,
    configuration_sha256: str,
) -> None:
    if len(template.containers) != 1:
        raise CloudRunCanaryError(CloudRunCanaryErrorCode.INVALID_CONFIGURATION)
    container = template.containers[0]
    values = {
        CLOUD_RUN_RELEASE_ENV: release_id,
        CLOUD_RUN_CONFIGURATION_ENV: configuration_sha256,
        CLOUD_RUN_IMAGE_DIGEST_ENV: image_digest,
    }
    seen: set[str] = set()
    for environment in container.env:
        if environment.name in values:
            if environment.name in seen:
                raise CloudRunCanaryError(CloudRunCanaryErrorCode.INVALID_CONFIGURATION)
            environment.value = values[environment.name]
            seen.add(environment.name)
    for name in sorted(set(values) - seen):
        container.env.append(run_v2.EnvVar(name=name, value=values[name]))


class _GoogleRevisionHealthClient:
    """One no-retry identity-token request to an exact tagged revision URL."""

    def get(self, *, url: str, audience: str, timeout: float) -> tuple[int, bytes]:
        try:
            import httpx
            from google.auth.transport.requests import Request
            from google.oauth2 import id_token

            request = Request()
            request.session.trust_env = False
            request.session.max_redirects = 0

            def bounded_request(
                request_url: str,
                method: str = "GET",
                body: bytes | None = None,
                headers: dict[str, str] | None = None,
                **kwargs: Any,
            ) -> Any:
                kwargs.pop("timeout", None)
                return request(
                    request_url,
                    method=method,
                    body=body,
                    headers=headers,
                    timeout=timeout,
                    **kwargs,
                )

            try:
                token = id_token.fetch_id_token(bounded_request, audience)
            finally:
                request.session.close()
            with httpx.Client(
                follow_redirects=False,
                timeout=timeout,
                trust_env=False,
            ) as client:
                response = client.get(
                    url,
                    headers={"Authorization": f"Bearer {token}"},
                )
                content = bytes(response.content)
                if len(content) > _HEALTH_BODY_CEILING:
                    raise ValueError
                return int(response.status_code), content
        except Exception:
            raise CloudRunCanaryError(
                CloudRunCanaryErrorCode.PROVIDER_UNAVAILABLE
            ) from None


class _ClientBoundary:
    def __init__(
        self,
        *,
        target: CloudRunCanaryTarget,
        services_factory: ServicesClientFactory | None,
        revisions_factory: RevisionsClientFactory | None,
        clock: Clock | None,
    ) -> None:
        if type(target) is not CloudRunCanaryTarget:
            raise TypeError("Cloud Run canary target must be exact")
        self._target = target
        self._services_factory = services_factory or _services_client_factory
        self._revisions_factory = revisions_factory or _revisions_client_factory
        self._clock = clock or _now
        self._services: _ServicesClient | None = None
        self._revisions: _RevisionsClient | None = None
        self._client_lock = threading.Lock()

    @property
    def target(self) -> CloudRunCanaryTarget:
        return self._target

    def _services_client(self) -> _ServicesClient:
        if self._services is None:
            with self._client_lock:
                if self._services is None:
                    try:
                        self._services = self._services_factory()
                    except Exception as error:
                        raise _map_provider_error(error) from None
        return self._services

    def _revisions_client(self) -> _RevisionsClient:
        if self._revisions is None:
            with self._client_lock:
                if self._revisions is None:
                    try:
                        self._revisions = self._revisions_factory()
                    except Exception as error:
                        raise _map_provider_error(error) from None
        return self._revisions

    def _observed_at(self) -> datetime:
        return _aware_utc(self._clock())

    def _get_service(self) -> Any:
        try:
            service = self._services_client().get_service(
                request=run_v2.GetServiceRequest(name=self._target.service_name),
                retry=None,
                timeout=self._target.timeout_seconds,
            )
        except CloudRunCanaryError:
            raise
        except Exception as error:
            raise _map_provider_error(error) from None
        if getattr(service, "name", None) != self._target.service_name:
            raise CloudRunCanaryError(CloudRunCanaryErrorCode.PROVIDER_UNAVAILABLE)
        return service

    def _get_revision(self, revision: str) -> Any:
        expected_name = self._target.revision_name(revision)
        try:
            candidate = self._revisions_client().get_revision(
                request=run_v2.GetRevisionRequest(name=expected_name),
                retry=None,
                timeout=self._target.timeout_seconds,
            )
        except CloudRunCanaryError:
            raise
        except Exception as error:
            raise _map_provider_error(error) from None
        if (
            getattr(candidate, "name", None) != expected_name
            or getattr(candidate, "service", None) != self._target.service_name
        ):
            raise CloudRunCanaryError(CloudRunCanaryErrorCode.PROVIDER_UNAVAILABLE)
        return candidate


class CloudRunCanaryActionAdapter(_ClientBoundary):
    """Perform the three allowlisted canary updates with fresh ETags."""

    def __init__(
        self,
        *,
        target: CloudRunCanaryTarget,
        services_factory: ServicesClientFactory | None = None,
        revisions_factory: RevisionsClientFactory | None = None,
        clock: Clock | None = None,
    ) -> None:
        super().__init__(
            target=target,
            services_factory=services_factory,
            revisions_factory=revisions_factory,
            clock=clock,
        )

    def _update(
        self,
        *,
        service: run_v2.Service,
        paths: tuple[str, ...],
        revision: str,
    ) -> CloudRunAcceptedOperation:
        request = run_v2.UpdateServiceRequest(
            service=service,
            update_mask=field_mask_pb2.FieldMask(paths=list(paths)),
            allow_missing=False,
        )
        try:
            operation = self._services_client().update_service(
                request=request,
                retry=None,
                timeout=self._target.timeout_seconds,
            )
        except CloudRunCanaryError:
            raise
        except Exception as error:
            raise _map_provider_error(error) from None
        return CloudRunAcceptedOperation(
            operation_name=_operation_name(operation, self._target),
            revision=revision,
            accepted_at=self._observed_at(),
            service_etag=service.etag,
        )

    def stage_revision(
        self,
        *,
        operation_id: str,
        release_id: str,
        image_digest: str,
        configuration_sha256: str,
    ) -> CloudRunAcceptedOperation:
        """Create one immutable revision while pinning all serving traffic."""

        release = _release(release_id)
        digest = _digest(image_digest)
        configuration = _configuration(configuration_sha256)
        revision = _revision_for_attempt(self._target.service, operation_id)
        current = self._get_service()
        current_ready = _serving_revision(current)
        if current_ready == revision:
            raise CloudRunCanaryError(CloudRunCanaryErrorCode.INVALID_CONFIGURATION)
        etag = getattr(current, "etag", None)
        if type(etag) is not str or not etag:
            raise CloudRunCanaryError(CloudRunCanaryErrorCode.PROVIDER_UNAVAILABLE)

        template = run_v2.RevisionTemplate(current.template)
        template.revision = revision
        template.labels[CLOUD_RUN_RELEASE_LABEL] = release
        template.annotations[CLOUD_RUN_CONFIGURATION_ANNOTATION] = configuration
        if len(template.containers) != 1:
            raise CloudRunCanaryError(CloudRunCanaryErrorCode.INVALID_CONFIGURATION)
        template.containers[0].image = f"{self._target.image_repository}@{digest}"
        _set_canary_environment(
            template,
            release_id=release,
            image_digest=digest,
            configuration_sha256=configuration,
        )
        service = run_v2.Service(
            name=self._target.service_name,
            etag=etag,
            template=template,
            traffic=(
                run_v2.TrafficTarget(
                    type_=run_v2.TrafficTargetAllocationType.TRAFFIC_TARGET_ALLOCATION_TYPE_REVISION,
                    revision=current_ready,
                    percent=100,
                ),
                run_v2.TrafficTarget(
                    type_=run_v2.TrafficTargetAllocationType.TRAFFIC_TARGET_ALLOCATION_TYPE_REVISION,
                    revision=revision,
                    percent=0,
                    tag=_tag_for_release(release),
                ),
            ),
        )
        return self._update(
            service=service,
            paths=("template", "traffic"),
            revision=revision,
        )

    def promote_revision(
        self,
        *,
        release_id: str,
        revision: str,
        service_etag: str,
    ) -> CloudRunAcceptedOperation:
        """Promote only the exact ready revision under a freshly re-read ETag."""

        release = _release(release_id)
        selected = _revision(revision)
        if type(service_etag) is not str or not service_etag:
            raise CloudRunCanaryError(CloudRunCanaryErrorCode.STALE_ETAG)
        current = self._get_service()
        current_etag = getattr(current, "etag", None)
        if current_etag != service_etag:
            raise CloudRunCanaryError(CloudRunCanaryErrorCode.STALE_ETAG)
        candidate = self._get_revision(selected)
        labels = dict(getattr(candidate, "labels", {}))
        _, terminal, readiness = _terminal_condition(candidate)
        if (
            labels.get(CLOUD_RUN_RELEASE_LABEL) != release
            or terminal != "SUCCEEDED"
            or readiness != "READY"
        ):
            raise CloudRunCanaryError(CloudRunCanaryErrorCode.REVISION_NOT_READY)
        service = run_v2.Service(
            name=self._target.service_name,
            etag=current_etag,
            traffic=(
                run_v2.TrafficTarget(
                    type_=run_v2.TrafficTargetAllocationType.TRAFFIC_TARGET_ALLOCATION_TYPE_REVISION,
                    revision=selected,
                    percent=100,
                    tag=_tag_for_release(release),
                ),
            ),
        )
        return self._update(
            service=service,
            paths=("traffic",),
            revision=selected,
        )

    def reset(self) -> CloudRunAcceptedOperation:
        """Pin the dedicated canary back to its one Terraform-owned baseline."""

        current = self._get_service()
        baseline = self._get_revision(self._target.baseline_revision)
        _, terminal, readiness = _terminal_condition(baseline)
        if terminal != "SUCCEEDED" or readiness != "READY":
            raise CloudRunCanaryError(CloudRunCanaryErrorCode.REVISION_NOT_READY)
        etag = getattr(current, "etag", None)
        if type(etag) is not str or not etag:
            raise CloudRunCanaryError(CloudRunCanaryErrorCode.PROVIDER_UNAVAILABLE)
        service = run_v2.Service(
            name=self._target.service_name,
            etag=etag,
            traffic=(
                run_v2.TrafficTarget(
                    type_=run_v2.TrafficTargetAllocationType.TRAFFIC_TARGET_ALLOCATION_TYPE_REVISION,
                    revision=self._target.baseline_revision,
                    percent=100,
                ),
            ),
        )
        return self._update(
            service=service,
            paths=("traffic",),
            revision=self._target.baseline_revision,
        )


class CloudRunCanaryFaultProxy:
    """Apply the explicit lost-ack fault only after provider acceptance."""

    def __init__(self, action_adapter: CloudRunCanaryActionAdapter) -> None:
        if type(action_adapter) is not CloudRunCanaryActionAdapter:
            raise TypeError("fault proxy requires the sealed canary action adapter")
        self._adapter = action_adapter

    @property
    def target(self) -> CloudRunCanaryTarget:
        return self._adapter.target

    @staticmethod
    def _after_accept(
        receipt: CloudRunAcceptedOperation,
        mode: CloudRunFaultMode,
    ) -> CloudRunAcceptedOperation:
        if type(mode) is not CloudRunFaultMode:
            raise TypeError("Cloud Run fault mode must be exact")
        if mode is CloudRunFaultMode.DROP_AFTER_ACCEPT:
            # Deliberately do not put the operation name on the exception.  The
            # caller must recover from provider state rather than hidden fixture state.
            raise CloudRunAcceptanceAmbiguity
        return receipt

    def stage_revision(
        self,
        *,
        mode: CloudRunFaultMode,
        operation_id: str,
        release_id: str,
        image_digest: str,
        configuration_sha256: str,
    ) -> CloudRunAcceptedOperation:
        receipt = self._adapter.stage_revision(
            operation_id=operation_id,
            release_id=release_id,
            image_digest=image_digest,
            configuration_sha256=configuration_sha256,
        )
        return self._after_accept(receipt, mode)

    def promote_revision(
        self,
        *,
        mode: CloudRunFaultMode,
        release_id: str,
        revision: str,
        service_etag: str,
    ) -> CloudRunAcceptedOperation:
        receipt = self._adapter.promote_revision(
            release_id=release_id,
            revision=revision,
            service_etag=service_etag,
        )
        return self._after_accept(receipt, mode)

    def reset(self, *, mode: CloudRunFaultMode) -> CloudRunAcceptedOperation:
        receipt = self._adapter.reset()
        return self._after_accept(receipt, mode)


class CloudRunCanaryReader(_ClientBoundary):
    """Read exact Service, Revision, Operation, and tagged health resources."""

    def __init__(
        self,
        *,
        target: CloudRunCanaryTarget,
        services_factory: ServicesClientFactory | None = None,
        revisions_factory: RevisionsClientFactory | None = None,
        health_client: RevisionHealthClient | None = None,
        clock: Clock | None = None,
    ) -> None:
        super().__init__(
            target=target,
            services_factory=services_factory,
            revisions_factory=revisions_factory,
            clock=clock,
        )
        self._health_client = health_client or _GoogleRevisionHealthClient()

    def discover_revision(
        self,
        *,
        release_id: str,
        image_digest: str,
        configuration_sha256: str,
    ) -> str | None:
        """Return the sole exact release-labelled revision, never a best match."""

        release = _release(release_id)
        digest = _digest(image_digest)
        configuration = _configuration(configuration_sha256)
        try:
            revisions = self._revisions_client().list_revisions(
                request=run_v2.ListRevisionsRequest(
                    parent=self._target.revisions_parent
                ),
                retry=None,
                timeout=self._target.timeout_seconds,
            )
            matches = []
            for candidate in revisions:
                name = getattr(candidate, "name", None)
                if (
                    type(name) is not str
                    or not name.startswith(f"{self._target.service_name}/revisions/")
                    or getattr(candidate, "service", None) != self._target.service_name
                ):
                    raise CloudRunCanaryError(
                        CloudRunCanaryErrorCode.PROVIDER_UNAVAILABLE
                    )
                labels = dict(getattr(candidate, "labels", {}))
                annotations = dict(getattr(candidate, "annotations", {}))
                containers = tuple(getattr(candidate, "containers", ()))
                if len(containers) != 1:
                    continue
                image = getattr(containers[0], "image", "")
                if (
                    labels.get(CLOUD_RUN_RELEASE_LABEL) == release
                    and annotations.get(CLOUD_RUN_CONFIGURATION_ANNOTATION)
                    == configuration
                    and image == f"{self._target.image_repository}@{digest}"
                    and not getattr(candidate, "delete_time", None)
                ):
                    matches.append(_revision(getattr(candidate, "name", None)))
        except CloudRunCanaryError:
            raise
        except Exception as error:
            raise _map_provider_error(error) from None
        unique = sorted(set(matches))
        if not unique:
            return None
        if len(unique) != 1:
            raise CloudRunRevisionAmbiguous
        return unique[0]

    def read_service(
        self, *, release_id: str, revision: str
    ) -> CloudRunServiceSnapshot:
        release = _release(release_id)
        selected = _revision(revision)
        service = self._get_service()
        reconciling, terminal, _ = _terminal_condition(service)
        etag = getattr(service, "etag", None)
        generation = getattr(service, "generation", None)
        observed = getattr(service, "observed_generation", None)
        if (
            type(etag) is not str
            or not etag
            or type(generation) is not int
            or generation < 1
            or type(observed) is not int
            or observed < 0
        ):
            raise CloudRunCanaryError(CloudRunCanaryErrorCode.PROVIDER_UNAVAILABLE)
        percent = sum(
            int(getattr(status, "percent", 0))
            for status in getattr(service, "traffic_statuses", ())
            if _same_revision(getattr(status, "revision", ""), selected)
        )
        if not 0 <= percent <= 100:
            raise CloudRunCanaryError(CloudRunCanaryErrorCode.PROVIDER_UNAVAILABLE)
        return CloudRunServiceSnapshot(
            release_id=release,
            revision=selected,
            service_etag=etag,
            generation=generation,
            observed_generation=observed,
            reconciling=reconciling,
            terminal_condition=terminal,
            revision_traffic_percent=percent,
            observed_at=self._observed_at(),
        )

    def read_revision(
        self,
        *,
        release_id: str,
        revision: str,
    ) -> CloudRunRevisionSnapshot:
        release = _release(release_id)
        selected = _revision(revision)
        candidate = self._get_revision(selected)
        labels = dict(getattr(candidate, "labels", {}))
        annotations = dict(getattr(candidate, "annotations", {}))
        containers = tuple(getattr(candidate, "containers", ()))
        generation = getattr(candidate, "generation", None)
        observed = getattr(candidate, "observed_generation", None)
        if len(containers) != 1 or type(generation) is not int or generation < 1:
            raise CloudRunCanaryError(CloudRunCanaryErrorCode.PROVIDER_UNAVAILABLE)
        if type(observed) is not int or observed < 0:
            raise CloudRunCanaryError(CloudRunCanaryErrorCode.PROVIDER_UNAVAILABLE)
        image = getattr(containers[0], "image", "")
        prefix = f"{self._target.image_repository}@"
        if type(image) is not str or not image.startswith(prefix):
            raise CloudRunCanaryError(CloudRunCanaryErrorCode.PROVIDER_UNAVAILABLE)
        digest = _digest(image.removeprefix(prefix))
        configuration = _configuration(
            annotations.get(CLOUD_RUN_CONFIGURATION_ANNOTATION)
        )
        label = _release(labels.get(CLOUD_RUN_RELEASE_LABEL))
        reconciling, terminal, readiness = _terminal_condition(candidate)
        return CloudRunRevisionSnapshot(
            release_id=release,
            release_label=label,
            revision=selected,
            image_digest=digest,
            configuration_sha256=configuration,
            generation=generation,
            observed_generation=observed,
            reconciling=reconciling,
            terminal_condition=terminal,
            readiness=readiness,
            observed_at=self._observed_at(),
        )

    def read_operation(
        self,
        *,
        action: CloudRunCanaryAction,
        release_id: str,
        revision: str,
        operation_name: str | None,
        image_digest: str | None = None,
        configuration_sha256: str | None = None,
    ) -> CloudRunOperationSnapshot | None:
        if type(action) is not CloudRunCanaryAction:
            raise CloudRunCanaryError(CloudRunCanaryErrorCode.INVALID_CONFIGURATION)
        release = _release(release_id)
        selected = _revision(revision)
        digest = _digest(image_digest) if image_digest is not None else None
        configuration = (
            _configuration(configuration_sha256)
            if configuration_sha256 is not None
            else None
        )
        if (action is CloudRunCanaryAction.STAGE) != (
            digest is not None and configuration is not None
        ):
            raise CloudRunCanaryError(CloudRunCanaryErrorCode.INVALID_CONFIGURATION)
        if operation_name is None:
            return None
        prefix = (
            f"projects/{self._target.project}/locations/{self._target.location}/"
            "operations/"
        )
        if (
            type(operation_name) is not str
            or not operation_name.startswith(prefix)
            or not operation_name[len(prefix) :]
            or "/" in operation_name[len(prefix) :]
        ):
            raise CloudRunCanaryError(CloudRunCanaryErrorCode.INVALID_CONFIGURATION)
        try:
            operation = self._services_client().get_operation(
                request={"name": operation_name},
                retry=None,
                timeout=self._target.timeout_seconds,
            )
        except Exception as error:
            raise _map_provider_error(error) from None
        if getattr(operation, "name", None) != operation_name:
            raise CloudRunCanaryError(CloudRunCanaryErrorCode.PROVIDER_UNAVAILABLE)
        _validate_operation_resource(
            _operation_service(getattr(operation, "metadata", None)),
            target=self._target,
            action=action,
            release_id=release,
            revision=selected,
            image_digest=digest,
            configuration_sha256=configuration,
        )
        if not bool(getattr(operation, "done", False)):
            state = "RUNNING"
        else:
            error = getattr(operation, "error", None)
            state = "FAILED" if int(getattr(error, "code", 0) or 0) else "SUCCEEDED"
            if state == "SUCCEEDED":
                _validate_operation_resource(
                    _operation_service(getattr(operation, "response", None)),
                    target=self._target,
                    action=action,
                    release_id=release,
                    revision=selected,
                    image_digest=digest,
                    configuration_sha256=configuration,
                )
        return CloudRunOperationSnapshot(
            release_id=release,
            revision=selected,
            operation_name=operation_name,
            operation_state=state,
            observed_at=self._observed_at(),
        )

    def read_health(
        self,
        *,
        release_id: str,
        revision: str,
    ) -> CloudRunHealthSnapshot:
        release = _release(release_id)
        selected = _revision(revision)
        service = self._get_service()
        expected_tag = _tag_for_release(release)
        expected_origin = _tagged_revision_origin(
            service,
            target=self._target,
            release_id=release,
        )
        candidates = {
            getattr(status, "uri", "")
            for status in getattr(service, "traffic_statuses", ())
            if _same_revision(getattr(status, "revision", ""), selected)
            and getattr(status, "tag", "") == expected_tag
            and getattr(status, "uri", "") == expected_origin
        }
        if candidates != {expected_origin}:
            raise CloudRunCanaryError(CloudRunCanaryErrorCode.PROVIDER_UNAVAILABLE)
        try:
            status_code, body = self._health_client.get(
                url=f"{expected_origin}/health",
                audience=self._target.health_audience,
                timeout=self._target.timeout_seconds,
            )
        except CloudRunCanaryError:
            raise
        except Exception:
            raise CloudRunCanaryError(
                CloudRunCanaryErrorCode.PROVIDER_UNAVAILABLE
            ) from None
        if status_code in {401, 403}:
            raise CloudRunCanaryError(CloudRunCanaryErrorCode.PERMISSION_DENIED)
        if status_code == 404:
            raise CloudRunCanaryError(CloudRunCanaryErrorCode.PROVIDER_UNAVAILABLE)
        health_status = "UNHEALTHY"
        if status_code == 200 and len(body) <= _HEALTH_BODY_CEILING:
            try:
                payload = json.loads(body)
            except Exception:
                payload = None
            if (
                isinstance(payload, dict)
                and set(payload)
                == {
                    "configuration_sha256",
                    "image_digest",
                    "release_id",
                    "revision",
                    "schema_version",
                    "status",
                }
                and payload.get("schema_version") == CLOUD_RUN_CANARY_HEALTH_VERSION
                and payload.get("release_id") == release
                and payload.get("revision") == selected
                and payload.get("status") == "READY"
                and _IMAGE_DIGEST.fullmatch(str(payload.get("image_digest")))
                and _SHA256.fullmatch(str(payload.get("configuration_sha256")))
            ):
                health_status = "READY"
        return CloudRunHealthSnapshot(
            release_id=release,
            revision=selected,
            health_status=health_status,
            observed_at=self._observed_at(),
        )


@dataclass(frozen=True, slots=True)
class CloudRunCanaryHealthConfig:
    port: int
    release_id: str
    revision: str
    image_digest: str
    configuration_sha256: str


def load_cloud_run_canary_health_config(
    source: Mapping[str, str] | None = None,
) -> CloudRunCanaryHealthConfig:
    environment = os.environ if source is None else source
    try:
        port_text = environment["PORT"]
        port = int(port_text)
        if str(port) != port_text or not 1 <= port <= 65_535:
            raise ValueError
        release = _release(environment[CLOUD_RUN_RELEASE_ENV])
        revision = _revision(environment["K_REVISION"])
        digest = _digest(environment[CLOUD_RUN_IMAGE_DIGEST_ENV])
        configuration = _configuration(environment[CLOUD_RUN_CONFIGURATION_ENV])
    except CloudRunCanaryError:
        raise
    except Exception:
        raise CloudRunCanaryError(
            CloudRunCanaryErrorCode.INVALID_CONFIGURATION
        ) from None
    return CloudRunCanaryHealthConfig(
        port=port,
        release_id=release,
        revision=revision,
        image_digest=digest,
        configuration_sha256=configuration,
    )


def create_cloud_run_canary_health_app(config: CloudRunCanaryHealthConfig) -> Any:
    if type(config) is not CloudRunCanaryHealthConfig:
        raise TypeError("canary health configuration must be exact")
    from fastapi import FastAPI

    application = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)

    @application.get("/health")
    async def health() -> dict[str, str]:
        return {
            "schema_version": CLOUD_RUN_CANARY_HEALTH_VERSION,
            "status": "READY",
            "release_id": config.release_id,
            "revision": config.revision,
            "image_digest": config.image_digest,
            "configuration_sha256": config.configuration_sha256,
        }

    return application


def main() -> None:
    import uvicorn

    config = load_cloud_run_canary_health_config()
    uvicorn.run(
        create_cloud_run_canary_health_app(config),
        host="0.0.0.0",
        port=config.port,
        proxy_headers=False,
        forwarded_allow_ips="",
        server_header=False,
    )


if __name__ == "__main__":
    main()


__all__ = [
    "CLOUD_RUN_CANARY_HEALTH_VERSION",
    "CLOUD_RUN_CANARY_MODULE",
    "CLOUD_RUN_CONFIGURATION_ANNOTATION",
    "CLOUD_RUN_RELEASE_LABEL",
    "CloudRunAcceptanceAmbiguity",
    "CloudRunAcceptedOperation",
    "CloudRunCanaryAction",
    "CloudRunCanaryActionAdapter",
    "CloudRunCanaryError",
    "CloudRunCanaryErrorCode",
    "CloudRunCanaryFaultProxy",
    "CloudRunCanaryHealthConfig",
    "CloudRunCanaryReader",
    "CloudRunCanaryTarget",
    "CloudRunFaultMode",
    "CloudRunHealthSnapshot",
    "CloudRunOperationSnapshot",
    "CloudRunRevisionAmbiguous",
    "CloudRunRevisionSnapshot",
    "CloudRunServiceSnapshot",
    "create_cloud_run_canary_health_app",
    "load_cloud_run_canary_health_config",
    "main",
]
