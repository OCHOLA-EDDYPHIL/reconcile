from __future__ import annotations

import hashlib
from datetime import UTC, datetime

import pytest
from fastapi.testclient import TestClient
from google.api_core import exceptions as api_exceptions
from google.cloud import run_v2
from google.longrunning import operations_pb2
from google.protobuf import any_pb2

from reconcile.hosted.cloud_run_canary import (
    CLOUD_RUN_CANARY_HEALTH_VERSION,
    CLOUD_RUN_CONFIGURATION_ANNOTATION,
    CLOUD_RUN_RELEASE_LABEL,
    CloudRunAcceptanceAmbiguity,
    CloudRunCanaryAction,
    CloudRunCanaryActionAdapter,
    CloudRunCanaryError,
    CloudRunCanaryErrorCode,
    CloudRunCanaryFaultProxy,
    CloudRunCanaryHealthConfig,
    CloudRunCanaryReader,
    CloudRunCanaryTarget,
    CloudRunFaultMode,
    CloudRunRevisionAmbiguous,
    create_cloud_run_canary_health_app,
)

pytestmark = pytest.mark.unit

NOW = datetime(2026, 8, 22, 12, 0, tzinfo=UTC)
PROJECT = "demo-project"
LOCATION = "us-central1"
SERVICE = "reconcile-canary"
BASELINE = "reconcile-canary-baseline"
REVISION = "reconcile-canary-r-0123456789abcdef"
RELEASE = "release-7"
DIGEST = f"sha256:{'a' * 64}"
CONFIGURATION = "b" * 64
OPERATION = f"projects/{PROJECT}/locations/{LOCATION}/operations/op-7"
TAG = f"verify-{hashlib.sha256(RELEASE.encode()).hexdigest()[:12]}"
SERVICE_URI = "https://reconcile-canary-demo-hash-uc.a.run.app"


def _target() -> CloudRunCanaryTarget:
    return CloudRunCanaryTarget(
        project=PROJECT,
        location=LOCATION,
        service=SERVICE,
        image_repository=(
            f"{LOCATION}-docker.pkg.dev/{PROJECT}/reconcile-p5/reconcile"
        ),
        baseline_revision=BASELINE,
        health_audience="https://canary.example.test",
    )


def _ready_condition() -> run_v2.Condition:
    return run_v2.Condition(
        type_="Ready",
        state=run_v2.Condition.State.CONDITION_SUCCEEDED,
    )


def _service(
    *,
    etag: str = "etag-7",
    serving_revision: str = BASELINE,
    extra_statuses: tuple[run_v2.TrafficTargetStatus, ...] = (),
) -> run_v2.Service:
    return run_v2.Service(
        name=_target().service_name,
        etag=etag,
        generation=8,
        observed_generation=8,
        terminal_condition=_ready_condition(),
        reconciling=False,
        uri=SERVICE_URI,
        latest_ready_revision=serving_revision,
        template=run_v2.RevisionTemplate(
            containers=(
                run_v2.Container(
                    image=f"{_target().image_repository}@{DIGEST}",
                    env=(run_v2.EnvVar(name="EXISTING", value="preserved"),),
                ),
            )
        ),
        traffic_statuses=(
            run_v2.TrafficTargetStatus(
                type_=run_v2.TrafficTargetAllocationType.TRAFFIC_TARGET_ALLOCATION_TYPE_REVISION,
                revision=serving_revision,
                percent=100,
            ),
            *extra_statuses,
        ),
    )


def _revision(
    name: str = REVISION,
    *,
    release: str = RELEASE,
    digest: str = DIGEST,
    configuration: str = CONFIGURATION,
    ready: bool = True,
) -> run_v2.Revision:
    return run_v2.Revision(
        name=_target().revision_name(name),
        service=SERVICE,
        generation=1,
        observed_generation=1,
        labels={CLOUD_RUN_RELEASE_LABEL: release},
        annotations={CLOUD_RUN_CONFIGURATION_ANNOTATION: configuration},
        containers=(run_v2.Container(image=f"{_target().image_repository}@{digest}"),),
        reconciling=False,
        conditions=(
            run_v2.Condition(
                type_="Ready",
                state=(
                    run_v2.Condition.State.CONDITION_SUCCEEDED
                    if ready
                    else run_v2.Condition.State.CONDITION_FAILED
                ),
            ),
        ),
    )


class _AcceptedOperation:
    name = OPERATION

    def __init__(self) -> None:
        self.result_called = False

    def result(self) -> object:
        self.result_called = True
        raise AssertionError("the acceptance boundary must not poll")


class _Services:
    def __init__(self, service: run_v2.Service | Exception) -> None:
        self.service = service
        self.operation = _AcceptedOperation()
        self.updates: list[run_v2.UpdateServiceRequest] = []
        self.operation_response: object = _provider_operation()

    def get_service(self, **_: object) -> run_v2.Service:
        if isinstance(self.service, Exception):
            raise self.service
        return run_v2.Service(self.service)

    def update_service(self, **kwargs: object) -> _AcceptedOperation:
        self.updates.append(kwargs["request"])  # type: ignore[arg-type]
        return self.operation

    def get_operation(self, **_: object) -> object:
        return self.operation_response


class _Revisions:
    def __init__(self, revisions: tuple[run_v2.Revision, ...]) -> None:
        self.revisions = revisions
        self.gets: list[str] = []

    def list_revisions(self, **_: object) -> tuple[run_v2.Revision, ...]:
        return self.revisions

    def get_revision(self, **kwargs: object) -> run_v2.Revision:
        request = kwargs["request"]
        self.gets.append(request.name)
        selected = request.name.rsplit("/", 1)[-1]
        for revision in self.revisions:
            if revision.name.rsplit("/", 1)[-1] == selected:
                return run_v2.Revision(revision)
        raise api_exceptions.NotFound("missing")


def _adapter(services: _Services, revisions: _Revisions) -> CloudRunCanaryActionAdapter:
    return CloudRunCanaryActionAdapter(
        target=_target(),
        services_factory=lambda: services,
        revisions_factory=lambda: revisions,
        clock=lambda: NOW,
    )


def _reader(
    services: _Services,
    revisions: _Revisions,
    *,
    health: object | None = None,
) -> CloudRunCanaryReader:
    return CloudRunCanaryReader(
        target=_target(),
        services_factory=lambda: services,
        revisions_factory=lambda: revisions,
        health_client=health,  # type: ignore[arg-type]
        clock=lambda: NOW,
    )


def _operation_service(
    *, name: str | None = None, revision: str = REVISION
) -> run_v2.Service:
    return run_v2.Service(
        name=name or _target().service_name,
        template=run_v2.RevisionTemplate(
            revision=revision,
            labels={CLOUD_RUN_RELEASE_LABEL: RELEASE},
            annotations={CLOUD_RUN_CONFIGURATION_ANNOTATION: CONFIGURATION},
            containers=(
                run_v2.Container(image=f"{_target().image_repository}@{DIGEST}"),
            ),
        ),
        traffic=(
            run_v2.TrafficTarget(revision=BASELINE, percent=100),
            run_v2.TrafficTarget(revision=revision, percent=0, tag=TAG),
        ),
    )


def _service_any(service: run_v2.Service) -> any_pb2.Any:
    packed = any_pb2.Any()
    packed.Pack(run_v2.Service.pb(service))
    return packed


def _promotion_operation_service() -> run_v2.Service:
    return run_v2.Service(
        name=_target().service_name,
        traffic=(run_v2.TrafficTarget(revision=REVISION, percent=100, tag=TAG),),
    )


def _provider_operation(
    *,
    done: bool = False,
    error_code: int = 0,
    service: run_v2.Service | None = None,
) -> operations_pb2.Operation:
    selected = service or _operation_service()
    operation = operations_pb2.Operation(
        name=OPERATION,
        done=done,
        metadata=_service_any(selected),
    )
    if done and error_code:
        operation.error.code = error_code
    elif done:
        operation.response.CopyFrom(_service_any(selected))
    return operation


def test_stage_accepts_without_polling_and_pins_existing_serving_revision() -> None:
    services = _Services(_service())
    adapter = _adapter(services, _Revisions(()))

    receipt = adapter.stage_revision(
        operation_id="operation-7",
        release_id=RELEASE,
        image_digest=DIGEST,
        configuration_sha256=CONFIGURATION,
    )

    assert receipt.operation_name == OPERATION
    assert services.operation.result_called is False
    assert len(services.updates) == 1
    request = services.updates[0]
    assert request.allow_missing is False
    assert tuple(request.update_mask.paths) == ("template", "traffic")
    assert request.service.etag == "etag-7"
    assert [(item.revision, item.percent) for item in request.service.traffic] == [
        (BASELINE, 100),
        (receipt.revision, 0),
    ]
    assert request.service.template.labels[CLOUD_RUN_RELEASE_LABEL] == RELEASE
    assert (
        request.service.template.annotations[CLOUD_RUN_CONFIGURATION_ANNOTATION]
        == CONFIGURATION
    )
    assert request.service.template.containers[0].image == (
        f"{_target().image_repository}@{DIGEST}"
    )


def test_drop_after_accept_hides_operation_but_preserves_provider_update() -> None:
    services = _Services(_service())
    proxy = CloudRunCanaryFaultProxy(_adapter(services, _Revisions(())))

    with pytest.raises(CloudRunAcceptanceAmbiguity) as raised:
        proxy.stage_revision(
            mode=CloudRunFaultMode.DROP_AFTER_ACCEPT,
            operation_id="operation-7",
            release_id=RELEASE,
            image_digest=DIGEST,
            configuration_sha256=CONFIGURATION,
        )

    assert len(services.updates) == 1
    assert OPERATION not in str(raised.value)
    assert services.operation.result_called is False


def test_promotion_requires_fresh_etag_and_exact_ready_release_revision() -> None:
    services = _Services(_service())
    revisions = _Revisions((_revision(),))
    adapter = _adapter(services, revisions)

    with pytest.raises(CloudRunCanaryError) as raised:
        adapter.promote_revision(
            release_id=RELEASE,
            revision=REVISION,
            service_etag="stale-etag",
        )
    assert raised.value.code is CloudRunCanaryErrorCode.STALE_ETAG
    assert not services.updates

    receipt = adapter.promote_revision(
        release_id=RELEASE,
        revision=REVISION,
        service_etag="etag-7",
    )
    request = services.updates[0]
    assert receipt.revision == REVISION
    assert request.allow_missing is False
    assert tuple(request.update_mask.paths) == ("traffic",)
    assert [(item.revision, item.percent) for item in request.service.traffic] == [
        (REVISION, 100)
    ]
    assert revisions.gets == [_target().revision_name(REVISION)]


def test_stage_discovery_is_exact_and_never_selects_unrelated_or_ambiguous() -> None:
    unrelated = _revision("reconcile-canary-unrelated", release="another-release")
    reader = _reader(_Services(_service()), _Revisions((unrelated,)))
    assert (
        reader.discover_revision(
            release_id=RELEASE,
            image_digest=DIGEST,
            configuration_sha256=CONFIGURATION,
        )
        is None
    )

    duplicate = _revision("reconcile-canary-r-fedcba9876543210")
    reader = _reader(_Services(_service()), _Revisions((_revision(), duplicate)))
    with pytest.raises(CloudRunRevisionAmbiguous):
        reader.discover_revision(
            release_id=RELEASE,
            image_digest=DIGEST,
            configuration_sha256=CONFIGURATION,
        )


def test_zero_traffic_latest_created_revision_is_still_referenced() -> None:
    service = _service()
    service.latest_created_revision = REVISION
    reader = _reader(_Services(service), _Revisions(()))

    assert reader.is_revision_referenced(revision=REVISION) is True


def test_operation_is_read_only_when_its_exact_name_is_known() -> None:
    services = _Services(_service())
    reader = _reader(services, _Revisions((_revision(),)))

    assert (
        reader.read_operation(
            action=CloudRunCanaryAction.STAGE,
            release_id=RELEASE,
            revision=REVISION,
            operation_name=None,
            image_digest=DIGEST,
            configuration_sha256=CONFIGURATION,
        )
        is None
    )
    running = reader.read_operation(
        action=CloudRunCanaryAction.STAGE,
        release_id=RELEASE,
        revision=REVISION,
        operation_name=OPERATION,
        image_digest=DIGEST,
        configuration_sha256=CONFIGURATION,
    )
    assert running is not None and running.operation_state == "RUNNING"
    services.operation_response = _provider_operation(done=True, error_code=9)
    failed = reader.read_operation(
        action=CloudRunCanaryAction.STAGE,
        release_id=RELEASE,
        revision=REVISION,
        operation_name=OPERATION,
        image_digest=DIGEST,
        configuration_sha256=CONFIGURATION,
    )
    assert failed is not None and failed.operation_state == "FAILED"

    services.operation_response = _provider_operation(done=True)
    succeeded = reader.read_operation(
        action=CloudRunCanaryAction.STAGE,
        release_id=RELEASE,
        revision=REVISION,
        operation_name=OPERATION,
        image_digest=DIGEST,
        configuration_sha256=CONFIGURATION,
    )
    assert succeeded is not None and succeeded.operation_state == "SUCCEEDED"

    for unrelated in (
        _operation_service(
            name=f"projects/{PROJECT}/locations/{LOCATION}/services/unrelated"
        ),
        _operation_service(revision="reconcile-canary-r-fedcba9876543210"),
    ):
        services.operation_response = _provider_operation(service=unrelated)
        with pytest.raises(CloudRunCanaryError) as raised:
            reader.read_operation(
                action=CloudRunCanaryAction.STAGE,
                release_id=RELEASE,
                revision=REVISION,
                operation_name=OPERATION,
                image_digest=DIGEST,
                configuration_sha256=CONFIGURATION,
            )
        assert raised.value.code is CloudRunCanaryErrorCode.PROVIDER_UNAVAILABLE


def test_promotion_operation_rejects_a_stage_lro_for_the_same_service() -> None:
    services = _Services(_service())
    reader = _reader(services, _Revisions((_revision(),)))

    with pytest.raises(CloudRunCanaryError) as raised:
        reader.read_operation(
            action=CloudRunCanaryAction.PROMOTE,
            release_id=RELEASE,
            revision=REVISION,
            operation_name=OPERATION,
        )
    assert raised.value.code is CloudRunCanaryErrorCode.PROVIDER_UNAVAILABLE

    services.operation_response = _provider_operation(
        done=True,
        service=_promotion_operation_service(),
    )
    succeeded = reader.read_operation(
        action=CloudRunCanaryAction.PROMOTE,
        release_id=RELEASE,
        revision=REVISION,
        operation_name=OPERATION,
    )
    assert succeeded is not None and succeeded.operation_state == "SUCCEEDED"


class _Health:
    def __init__(self, status: int, body: bytes) -> None:
        self.status = status
        self.body = body
        self.calls: list[tuple[str, str]] = []

    def get(self, *, url: str, audience: str, timeout: float) -> tuple[int, bytes]:
        assert timeout == 25.0
        self.calls.append((url, audience))
        return self.status, self.body


def test_health_read_is_bound_to_the_exact_tagged_revision() -> None:
    payload = (
        "{"
        f'"schema_version":"{CLOUD_RUN_CANARY_HEALTH_VERSION}",'
        '"status":"READY",'
        f'"release_id":"{RELEASE}",'
        f'"revision":"{REVISION}",'
        f'"image_digest":"{DIGEST}",'
        f'"configuration_sha256":"{CONFIGURATION}"'
        "}"
    ).encode()
    status = run_v2.TrafficTargetStatus(
        revision=REVISION,
        percent=0,
        tag=TAG,
        uri=f"https://{TAG}---reconcile-canary-demo-hash-uc.a.run.app",
    )
    health = _Health(200, payload)
    reader = _reader(
        _Services(_service(extra_statuses=(status,))),
        _Revisions((_revision(),)),
        health=health,
    )

    snapshot = reader.read_health(release_id=RELEASE, revision=REVISION)

    assert snapshot.health_status == "READY"
    assert health.calls == [
        (
            f"https://{TAG}---reconcile-canary-demo-hash-uc.a.run.app/health",
            "https://canary.example.test",
        )
    ]
    unhealthy = _reader(
        _Services(_service(extra_statuses=(status,))),
        _Revisions((_revision(),)),
        health=_Health(503, b"unavailable"),
    ).read_health(release_id=RELEASE, revision=REVISION)
    assert unhealthy.health_status == "UNHEALTHY"

    unrelated_health = _Health(200, payload)
    unrelated = run_v2.TrafficTargetStatus(
        revision=REVISION,
        percent=0,
        tag=TAG,
        uri="https://attacker.example.test",
    )
    with pytest.raises(CloudRunCanaryError) as raised:
        _reader(
            _Services(_service(extra_statuses=(unrelated,))),
            _Revisions((_revision(),)),
            health=unrelated_health,
        ).read_health(release_id=RELEASE, revision=REVISION)
    assert raised.value.code is CloudRunCanaryErrorCode.PROVIDER_UNAVAILABLE
    assert unrelated_health.calls == []


def test_reset_is_deterministic_and_permission_failures_are_sanitized() -> None:
    services = _Services(_service(serving_revision=REVISION))
    adapter = _adapter(services, _Revisions((_revision(BASELINE),)))

    receipt = adapter.reset()

    assert receipt.revision == BASELINE
    assert [
        (item.revision, item.percent) for item in services.updates[0].service.traffic
    ] == [(BASELINE, 100)]

    denied = _adapter(
        _Services(api_exceptions.PermissionDenied("provider detail")),
        _Revisions(()),
    )
    with pytest.raises(CloudRunCanaryError) as raised:
        denied.stage_revision(
            operation_id="operation-7",
            release_id=RELEASE,
            image_digest=DIGEST,
            configuration_sha256=CONFIGURATION,
        )
    assert raised.value.code is CloudRunCanaryErrorCode.PERMISSION_DENIED
    assert "provider detail" not in str(raised.value)

    outage = _reader(
        _Services(api_exceptions.ServiceUnavailable("provider detail")),
        _Revisions(()),
    )
    with pytest.raises(CloudRunCanaryError) as raised:
        outage.read_service(release_id=RELEASE, revision=REVISION)
    assert raised.value.code is CloudRunCanaryErrorCode.PROVIDER_UNAVAILABLE
    assert "provider detail" not in str(raised.value)


def test_provider_responses_with_wrong_resource_names_fail_closed() -> None:
    wrong_service = _service()
    wrong_service.name = (
        f"projects/{PROJECT}/locations/{LOCATION}/services/another-service"
    )
    reader = _reader(_Services(wrong_service), _Revisions((_revision(),)))
    with pytest.raises(CloudRunCanaryError) as raised:
        reader.read_service(release_id=RELEASE, revision=REVISION)
    assert raised.value.code is CloudRunCanaryErrorCode.PROVIDER_UNAVAILABLE

    wrong_revision = _revision()
    wrong_revision.service = (
        f"projects/{PROJECT}/locations/{LOCATION}/services/another-service"
    )
    reader = _reader(_Services(_service()), _Revisions((wrong_revision,)))
    with pytest.raises(CloudRunCanaryError) as raised:
        reader.discover_revision(
            release_id=RELEASE,
            image_digest=DIGEST,
            configuration_sha256=CONFIGURATION,
        )
    assert raised.value.code is CloudRunCanaryErrorCode.PROVIDER_UNAVAILABLE


def test_dedicated_health_app_exposes_only_immutable_revision_identity() -> None:
    application = create_cloud_run_canary_health_app(
        CloudRunCanaryHealthConfig(
            port=8080,
            release_id=RELEASE,
            revision=REVISION,
            image_digest=DIGEST,
            configuration_sha256=CONFIGURATION,
        )
    )

    response = TestClient(application).get("/health")

    assert response.status_code == 200
    assert response.json() == {
        "configuration_sha256": CONFIGURATION,
        "image_digest": DIGEST,
        "release_id": RELEASE,
        "revision": REVISION,
        "schema_version": CLOUD_RUN_CANARY_HEALTH_VERSION,
        "status": "READY",
    }
