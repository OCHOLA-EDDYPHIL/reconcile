"""HTTP and SSE coverage for the additive operator scenario API."""

from __future__ import annotations

import json
from collections import deque
from datetime import timedelta

import pytest
from fastapi.testclient import TestClient

from reconcile.contracts import (
    ERROR_VERSION,
    EXECUTION_ENVELOPE_SUMMARY_VERSION,
    SCENARIO_LAUNCH_REQUEST_VERSION,
    SCENARIO_OPERATIONAL_STATUS_VERSION,
    SCENARIO_RUN_EVENT_VERSION,
    SCENARIO_RUN_SNAPSHOT_VERSION,
    ApiError,
    ApiErrorCode,
    EnvelopeEffectSummary,
    EnvelopeSummaryEventPayload,
    ExecutionEnvelopeSummary,
    ScenarioLaunchName,
    ScenarioLaunchRequest,
    ScenarioLifecycleEventPayload,
    ScenarioOperationalCleanupState,
    ScenarioOperationalInvestigationState,
    ScenarioOperationalMutationState,
    ScenarioOperationalRecoveryState,
    ScenarioOperationalStatus,
    ScenarioRunEvent,
    ScenarioRunEventType,
    ScenarioRunFailureCategory,
    ScenarioRunLifecycle,
    ScenarioRunMode,
    ScenarioRunResultKind,
    ScenarioRunSnapshot,
    TerminalStateEventPayload,
    TerminalStateSummary,
    canonical_json_bytes,
    canonical_sha256,
    decode_contract,
)
from reconcile.interfaces import api as api_module
from reconcile.interfaces.api import create_app
from reconcile.operator import (
    InvalidScenarioEventCursor,
    LaunchScenarioResult,
    OperatorCapacityExceeded,
    OperatorServiceClosed,
    OperatorServiceUnavailable,
    ScenarioLaunchConflict,
    ScenarioRunEventSnapshot,
    ScenarioRunNotFound,
)
from tests.contract._factories import NOW, make_envelope

pytestmark = pytest.mark.integration

_LAUNCH_INVESTIGATION_ID = "investigation-storage-a7ea12fef230a5685c7cb63f"


def test_default_operator_service_uses_only_complete_server_vertex_config(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured = []

    class CapturingService:
        def __init__(self, *, vertex_config=None) -> None:
            captured.append(vertex_config)

    monkeypatch.setattr(
        "reconcile.operator.OperatorApplicationService",
        CapturingService,
    )
    names = (
        "RECONCILE_VERTEX_PROJECT",
        "RECONCILE_VERTEX_LOCATION",
        "RECONCILE_VERTEX_MODEL",
    )
    for name in names:
        monkeypatch.delenv(name, raising=False)

    api_module._build_default_operator_service()
    assert captured == [None]

    monkeypatch.setenv(names[0], "project-7")
    with pytest.raises(ValueError, match="configuration is incomplete"):
        api_module._build_default_operator_service()

    monkeypatch.setenv(names[1], "global")
    monkeypatch.setenv(names[2], "gemini-2.5-flash-lite")
    api_module._build_default_operator_service()

    config = captured[-1]
    assert config.project == "project-7"
    assert config.location == "global"
    assert config.model == "gemini-2.5-flash-lite"
    assert config.credentials is None


def _summary() -> ExecutionEnvelopeSummary:
    envelope = make_envelope()
    return ExecutionEnvelopeSummary(
        schema_version=EXECUTION_ENVELOPE_SUMMARY_VERSION,
        investigation_id=envelope.investigation_id,
        envelope_sha256=canonical_sha256(envelope),
        target_kind=envelope.target.target_kind,
        invoked_at=envelope.invoked_at,
        ambiguity_kind=envelope.ambiguity.kind,
        ambiguity_observed_at=envelope.ambiguity.observed_at,
        expected_effects=tuple(
            EnvelopeEffectSummary(
                effect_id=item.effect_id,
                commit_scope=item.commit_scope,
            )
            for item in envelope.expected_effects
        ),
        enabled_capabilities=envelope.context.enabled_capabilities,
        evidence_budget=envelope.context.evidence_budget,
    )


def _snapshot(
    lifecycle: ScenarioRunLifecycle = ScenarioRunLifecycle.ACCEPTED,
    *,
    summary: ExecutionEnvelopeSummary | None = None,
    cursor: int = 1,
) -> ScenarioRunSnapshot:
    failure = (
        ScenarioRunFailureCategory.MODEL_UNAVAILABLE
        if lifecycle is ScenarioRunLifecycle.FAILED
        else None
    )
    return ScenarioRunSnapshot(
        schema_version=SCENARIO_RUN_SNAPSHOT_VERSION,
        launch_id="launch-7",
        investigation_id="investigation-7",
        scenario=ScenarioLaunchName.STORAGE,
        mode=ScenarioRunMode.FIXED,
        lifecycle=lifecycle,
        event_cursor=cursor,
        envelope_summary=summary,
        report=None,
        comparison=None,
        failure_category=failure,
        accepted_at=NOW,
        updated_at=NOW + timedelta(milliseconds=cursor),
    )


def _event(
    cursor: int,
    event_type: ScenarioRunEventType,
    payload: object,
) -> ScenarioRunEvent:
    return ScenarioRunEvent(
        schema_version=SCENARIO_RUN_EVENT_VERSION,
        investigation_id="investigation-7",
        cursor=cursor,
        type=event_type,
        occurred_at=NOW + timedelta(milliseconds=cursor),
        payload=payload,  # type: ignore[arg-type]
    )


def _operational_status() -> ScenarioOperationalStatus:
    return ScenarioOperationalStatus(
        schema_version=SCENARIO_OPERATIONAL_STATUS_VERSION,
        launch_id="launch-7",
        investigation_id="investigation-7",
        scenario=ScenarioLaunchName.STORAGE,
        mode=ScenarioRunMode.FIXED,
        revision=7,
        mutation_state=ScenarioOperationalMutationState.RECORDED,
        investigation_state=ScenarioOperationalInvestigationState.RECORDED,
        cleanup_state=ScenarioOperationalCleanupState.SUCCEEDED,
        recovery_state=ScenarioOperationalRecoveryState.NOT_ESCALATED,
        updated_at=NOW + timedelta(seconds=7),
    )


def _terminal_events() -> tuple[ScenarioRunEvent, ...]:
    return (
        _event(
            1,
            ScenarioRunEventType.LIFECYCLE,
            ScenarioLifecycleEventPayload(lifecycle=ScenarioRunLifecycle.ACCEPTED),
        ),
        _event(
            2,
            ScenarioRunEventType.LIFECYCLE,
            ScenarioLifecycleEventPayload(lifecycle=ScenarioRunLifecycle.RUNNING),
        ),
        _event(
            3,
            ScenarioRunEventType.TERMINAL,
            TerminalStateEventPayload(
                terminal=TerminalStateSummary(
                    lifecycle=ScenarioRunLifecycle.FAILED,
                    result_kind=ScenarioRunResultKind.NONE,
                    classification=None,
                    action_gate_allowed_count=0,
                    action_gate_denied_count=0,
                    missing_evidence_count=0,
                    escalation_required=None,
                    failure_category=(ScenarioRunFailureCategory.MODEL_UNAVAILABLE),
                )
            ),
        ),
    )


class _FakeOperatorService:
    def __init__(self) -> None:
        self.current_snapshot: object = _snapshot()
        self.launch_snapshot: object = _snapshot().model_copy(
            update={"investigation_id": _LAUNCH_INVESTIGATION_ID}
        )
        self.launch_created = True
        self.launch_error: Exception | None = None
        self.get_error: Exception | None = None
        self.operational_status: object = _operational_status()
        self.operational_status_error: Exception | None = None
        self.summary = _summary()
        self.summary_error: Exception | None = None
        self.events = _terminal_events()
        self.snapshot_error: Exception | None = None
        self.snapshot_override: object | None = None
        self.wait_results: deque[object] = deque()
        self.snapshot_after_wait: object | None = None
        self.allow_max_cursor = False
        self.launches: list[ScenarioLaunchRequest] = []
        self.get_ids: list[str] = []
        self.operational_status_ids: list[str] = []
        self.summary_ids: list[str] = []
        self.snapshot_cursors: list[int] = []
        self.wait_cursors: list[int] = []
        self.cancellation_events: list[object] = []
        self.closed = False

    async def launch(self, request: ScenarioLaunchRequest) -> LaunchScenarioResult:
        self.launches.append(request)
        if self.launch_error is not None:
            raise self.launch_error
        return LaunchScenarioResult(
            snapshot=self.launch_snapshot,  # type: ignore[arg-type]
            created=self.launch_created,
        )

    async def get(self, investigation_id: str) -> ScenarioRunSnapshot:
        self.get_ids.append(investigation_id)
        if self.get_error is not None:
            raise self.get_error
        return self.current_snapshot  # type: ignore[return-value]

    async def get_operational_status(
        self,
        investigation_id: str,
    ) -> ScenarioOperationalStatus:
        self.operational_status_ids.append(investigation_id)
        if self.operational_status_error is not None:
            raise self.operational_status_error
        return self.operational_status  # type: ignore[return-value]

    async def get_envelope_summary(
        self,
        investigation_id: str,
    ) -> ExecutionEnvelopeSummary:
        self.summary_ids.append(investigation_id)
        if self.summary_error is not None:
            raise self.summary_error
        return self.summary

    async def snapshot(
        self,
        investigation_id: str,
        *,
        after: int = 0,
    ) -> ScenarioRunEventSnapshot:
        self.snapshot_cursors.append(after)
        if self.snapshot_error is not None:
            raise self.snapshot_error
        if self.snapshot_override is not None:
            return self.snapshot_override  # type: ignore[return-value]
        if self.allow_max_cursor and after == 1024:
            return ScenarioRunEventSnapshot(events=(), cursor=1024, terminal=True)
        if after > len(self.events):
            raise InvalidScenarioEventCursor(
                investigation_id,
                after,
                len(self.events),
            )
        return ScenarioRunEventSnapshot(
            events=self.events[after:],
            cursor=len(self.events),
            terminal=True,
        )

    async def wait_for_events(
        self,
        investigation_id: str,
        *,
        after: int = 0,
        cancellation_event: object | None = None,
    ) -> ScenarioRunEventSnapshot:
        del investigation_id
        self.wait_cursors.append(after)
        self.cancellation_events.append(cancellation_event)
        if not self.wait_results:
            raise AssertionError("unexpected operator event wait")
        result = self.wait_results.popleft()
        if self.snapshot_after_wait is not None:
            self.current_snapshot = self.snapshot_after_wait
        if isinstance(result, Exception):
            raise result
        return result  # type: ignore[return-value]

    async def aclose(self) -> None:
        self.closed = True


def _launch() -> ScenarioLaunchRequest:
    return ScenarioLaunchRequest(
        schema_version=SCENARIO_LAUNCH_REQUEST_VERSION,
        launch_id="launch-7",
        scenario=ScenarioLaunchName.STORAGE,
        mode=ScenarioRunMode.FIXED,
    )


def _error(response: object) -> ApiError:
    content = response.content  # type: ignore[attr-defined]
    error = decode_contract(content, ApiError)
    assert content == canonical_json_bytes(error)
    assert error.schema_version == ERROR_VERSION
    return error


def _parse_sse(response: object) -> tuple[ScenarioRunEvent, ...]:
    content = response.content  # type: ignore[attr-defined]
    records = tuple(item for item in content.split(b"\n\n") if item)
    events: list[ScenarioRunEvent] = []
    for record in records:
        fields = dict(line.split(b": ", 1) for line in record.splitlines())
        event = decode_contract(fields[b"data"], ScenarioRunEvent)
        assert fields[b"id"] == str(event.cursor).encode()
        assert fields[b"event"] == event.type.value.encode()
        assert fields[b"data"] == canonical_json_bytes(event)
        events.append(event)
    return tuple(events)


@pytest.mark.parametrize(
    ("created", "expected_status"),
    ((True, 202), (False, 200)),
)
def test_launch_returns_canonical_new_or_replayed_snapshot(
    created: bool,
    expected_status: int,
) -> None:
    service = _FakeOperatorService()
    service.launch_created = created
    launch = _launch()
    with TestClient(create_app(operator_service=service)) as client:
        response = client.post(
            "/api/v1/scenario-runs",
            content=canonical_json_bytes(launch),
            headers={"Content-Type": "application/json"},
        )

    snapshot = decode_contract(response.content, ScenarioRunSnapshot)
    assert response.status_code == expected_status
    assert response.content == canonical_json_bytes(snapshot)
    assert snapshot.launch_id == launch.launch_id
    assert snapshot.investigation_id == _LAUNCH_INVESTIGATION_ID
    assert snapshot.scenario is launch.scenario
    assert snapshot.mode is launch.mode
    assert service.launches == [launch]


def test_conflicting_launch_is_a_canonical_409() -> None:
    service = _FakeOperatorService()
    service.launch_error = ScenarioLaunchConflict(
        "launch-7",
        "investigation-7",
    )
    with TestClient(create_app(operator_service=service)) as client:
        response = client.post(
            "/api/v1/scenario-runs",
            content=canonical_json_bytes(_launch()),
            headers={"Content-Type": "application/json"},
        )

    error = _error(response)
    assert response.status_code == 409
    assert error.code is ApiErrorCode.DUPLICATE_INVESTIGATION_ID
    assert error.details == {"investigation_id": "investigation-7"}


@pytest.mark.parametrize(
    "update",
    (
        {"launch_id": "other-launch"},
        {"investigation_id": "other-investigation"},
        {"scenario": ScenarioLaunchName.FIRESTORE_BUSINESS},
        {"mode": ScenarioRunMode.ADAPTIVE},
    ),
)
def test_launch_response_must_retain_the_canonical_request_identity(
    update: dict[str, object],
) -> None:
    service = _FakeOperatorService()
    service.launch_snapshot = service.launch_snapshot.model_copy(update=update)  # type: ignore[union-attr]
    with TestClient(create_app(operator_service=service)) as client:
        response = client.post(
            "/api/v1/scenario-runs",
            content=canonical_json_bytes(_launch()),
            headers={"Content-Type": "application/json"},
        )

    assert response.status_code == 500
    assert _error(response).code is ApiErrorCode.INTERNAL_FAILURE


def test_operator_capacity_refusal_is_a_canonical_503() -> None:
    service = _FakeOperatorService()
    service.launch_error = OperatorCapacityExceeded()
    with TestClient(create_app(operator_service=service)) as client:
        response = client.post(
            "/api/v1/scenario-runs",
            content=canonical_json_bytes(_launch()),
            headers={"Content-Type": "application/json"},
        )

    assert response.status_code == 503
    assert _error(response).code is ApiErrorCode.DEPENDENCY_UNAVAILABLE


@pytest.mark.parametrize(
    ("change", "status", "code"),
    (
        ({"provider_config": {}}, 400, ApiErrorCode.INVALID_CONTRACT),
        (
            {"schema_version": "reconcile/scenario-launch-request/v2"},
            422,
            ApiErrorCode.UNSUPPORTED_CONTRACT_VERSION,
        ),
        ({"launch_id": "bad id"}, 400, ApiErrorCode.INVALID_CONTRACT),
    ),
)
def test_launch_strictly_rejects_invalid_contracts(
    change: dict[str, object],
    status: int,
    code: ApiErrorCode,
) -> None:
    service = _FakeOperatorService()
    payload = json.loads(canonical_json_bytes(_launch()))
    payload.update(change)
    with TestClient(create_app(operator_service=service)) as client:
        response = client.post("/api/v1/scenario-runs", json=payload)

    assert response.status_code == status
    assert _error(response).code is code
    assert service.launches == []


def test_launch_rejects_query_parameters_and_non_json_media() -> None:
    service = _FakeOperatorService()
    with TestClient(create_app(operator_service=service)) as client:
        query_response = client.post(
            "/api/v1/scenario-runs?provider=local",
            content=canonical_json_bytes(_launch()),
            headers={"Content-Type": "application/json"},
        )
        media_response = client.post(
            "/api/v1/scenario-runs",
            content=canonical_json_bytes(_launch()),
            headers={"Content-Type": "text/plain"},
        )

    assert query_response.status_code == 400
    assert media_response.status_code == 400
    assert service.launches == []


def test_get_scenario_run_is_canonical_and_path_bound() -> None:
    service = _FakeOperatorService()
    with TestClient(create_app(operator_service=service)) as client:
        response = client.get("/api/v1/scenario-runs/investigation-7")

    snapshot = decode_contract(response.content, ScenarioRunSnapshot)
    assert response.status_code == 200
    assert response.content == canonical_json_bytes(snapshot)
    assert service.get_ids == ["investigation-7"]


def test_missing_scenario_run_is_a_canonical_404() -> None:
    service = _FakeOperatorService()
    service.get_error = ScenarioRunNotFound("investigation-7")
    with TestClient(create_app(operator_service=service)) as client:
        response = client.get("/api/v1/scenario-runs/investigation-7")

    assert response.status_code == 404
    assert _error(response).code is ApiErrorCode.INVESTIGATION_NOT_FOUND


def test_scenario_snapshot_must_match_the_path_identity() -> None:
    service = _FakeOperatorService()
    service.current_snapshot = _snapshot().model_copy(
        update={"investigation_id": "other-investigation"}
    )
    with TestClient(create_app(operator_service=service)) as client:
        response = client.get("/api/v1/scenario-runs/investigation-7")

    assert response.status_code == 500
    assert _error(response).code is ApiErrorCode.INTERNAL_FAILURE


def test_get_operational_status_is_canonical_and_path_bound() -> None:
    service = _FakeOperatorService()
    with TestClient(create_app(operator_service=service)) as client:
        response = client.get(
            "/api/v2/scenario-runs/investigation-7/operational-status"
        )

    status = decode_contract(response.content, ScenarioOperationalStatus)
    assert response.status_code == 200
    assert response.content == canonical_json_bytes(status)
    assert status == _operational_status()
    assert service.operational_status_ids == ["investigation-7"]


@pytest.mark.parametrize(
    ("error", "expected_status", "expected_code"),
    (
        (
            ScenarioRunNotFound("investigation-7"),
            404,
            ApiErrorCode.INVESTIGATION_NOT_FOUND,
        ),
        (
            OperatorServiceUnavailable("investigation-7"),
            503,
            ApiErrorCode.DEPENDENCY_UNAVAILABLE,
        ),
    ),
)
def test_operational_status_normalizes_missing_or_unavailable_authority(
    error: Exception,
    expected_status: int,
    expected_code: ApiErrorCode,
) -> None:
    service = _FakeOperatorService()
    service.operational_status_error = error
    with TestClient(create_app(operator_service=service)) as client:
        response = client.get(
            "/api/v2/scenario-runs/investigation-7/operational-status"
        )

    assert response.status_code == expected_status
    assert _error(response).code is expected_code


@pytest.mark.parametrize(
    "replacement",
    (
        _operational_status().model_copy(
            update={"investigation_id": "other-investigation"}
        ),
        {"schema_version": SCENARIO_OPERATIONAL_STATUS_VERSION},
    ),
)
def test_operational_status_response_must_be_exact_and_path_bound(
    replacement: object,
) -> None:
    service = _FakeOperatorService()
    service.operational_status = replacement
    with TestClient(create_app(operator_service=service)) as client:
        response = client.get(
            "/api/v2/scenario-runs/investigation-7/operational-status"
        )

    assert response.status_code == 500
    assert _error(response).code is ApiErrorCode.INTERNAL_FAILURE


def test_operational_status_rejects_queries_and_invalid_identifiers() -> None:
    service = _FakeOperatorService()
    with TestClient(create_app(operator_service=service)) as client:
        query = client.get(
            "/api/v2/scenario-runs/investigation-7/operational-status?expand=true"
        )
        invalid = client.get("/api/v2/scenario-runs/bad%20identity/operational-status")

    assert query.status_code == 400
    assert invalid.status_code == 400
    assert service.operational_status_ids == []


def test_terminal_scenario_sse_is_ordered_canonical_and_complete() -> None:
    service = _FakeOperatorService()
    with TestClient(create_app(operator_service=service)) as client:
        response = client.get("/api/v1/scenario-runs/investigation-7/events")

    events = _parse_sse(response)
    assert response.status_code == 200
    assert response.headers["content-type"].startswith("text/event-stream")
    assert [event.cursor for event in events] == [1, 2, 3]


@pytest.mark.parametrize(
    "request_options",
    (
        {"params": {"after": "1"}},
        {"headers": {"Last-Event-ID": "1"}},
        {
            "params": {"after": "1"},
            "headers": {"Last-Event-ID": "1"},
        },
    ),
)
def test_scenario_sse_reconnect_is_exclusive(
    request_options: dict[str, object],
) -> None:
    service = _FakeOperatorService()
    with TestClient(create_app(operator_service=service)) as client:
        response = client.get(
            "/api/v1/scenario-runs/investigation-7/events",
            **request_options,
        )

    assert [event.cursor for event in _parse_sse(response)] == [2, 3]
    assert service.snapshot_cursors == [1]


@pytest.mark.parametrize(
    "request_options",
    (
        {"params": {"after": "010"}},
        {"params": {"after": "1025"}},
        {
            "params": {"after": "1"},
            "headers": {"Last-Event-ID": "2"},
        },
        {"params": [("after", "1"), ("after", "2")]},
        {"params": {"unknown": "1"}},
    ),
)
def test_invalid_scenario_resume_cursor_is_canonical_400(
    request_options: dict[str, object],
) -> None:
    service = _FakeOperatorService()
    with TestClient(create_app(operator_service=service)) as client:
        response = client.get(
            "/api/v1/scenario-runs/investigation-7/events",
            **request_options,
        )

    assert response.status_code == 400
    assert _error(response).code is ApiErrorCode.INVALID_CONTRACT


def test_scenario_sse_accepts_the_maximum_exclusive_cursor() -> None:
    service = _FakeOperatorService()
    service.allow_max_cursor = True
    with TestClient(create_app(operator_service=service)) as client:
        response = client.get("/api/v1/scenario-runs/investigation-7/events?after=1024")

    assert response.status_code == 200
    assert _parse_sse(response) == ()
    assert service.snapshot_cursors == [1024]


@pytest.mark.parametrize(
    "error",
    (
        ScenarioRunNotFound("investigation-7"),
        InvalidScenarioEventCursor("investigation-7", 2, 1),
    ),
)
def test_scenario_sse_errors_are_validated_before_headers(error: Exception) -> None:
    service = _FakeOperatorService()
    service.snapshot_error = error
    with TestClient(create_app(operator_service=service)) as client:
        response = client.get("/api/v1/scenario-runs/investigation-7/events")

    expected_status = 404 if isinstance(error, ScenarioRunNotFound) else 400
    assert response.status_code == expected_status
    assert response.headers["content-type"].startswith("application/json")
    _error(response)


def test_malformed_scenario_journal_is_rejected_before_sse_headers() -> None:
    service = _FakeOperatorService()
    service.snapshot_override = ScenarioRunEventSnapshot(
        events=(service.events[1],),
        cursor=3,
        terminal=True,
    )
    with TestClient(create_app(operator_service=service)) as client:
        response = client.get("/api/v1/scenario-runs/investigation-7/events")

    assert response.status_code == 500
    assert response.headers["content-type"].startswith("application/json")
    assert _error(response).code is ApiErrorCode.INTERNAL_FAILURE


@pytest.mark.parametrize("terminal", (False, True))
def test_scenario_terminal_flag_must_match_the_final_event(terminal: bool) -> None:
    service = _FakeOperatorService()
    events = service.events[:2] if terminal else service.events
    service.snapshot_override = ScenarioRunEventSnapshot(
        events=events,
        cursor=len(events),
        terminal=terminal,
    )
    with TestClient(create_app(operator_service=service)) as client:
        response = client.get("/api/v1/scenario-runs/investigation-7/events")

    assert response.status_code == 500
    assert response.headers["content-type"].startswith("application/json")
    assert _error(response).code is ApiErrorCode.INTERNAL_FAILURE


def test_scenario_journal_cannot_claim_terminal_before_its_accepted_event() -> None:
    service = _FakeOperatorService()
    service.snapshot_override = ScenarioRunEventSnapshot(
        events=(),
        cursor=0,
        terminal=True,
    )
    with TestClient(create_app(operator_service=service)) as client:
        response = client.get("/api/v1/scenario-runs/investigation-7/events")

    assert response.status_code == 500
    assert response.headers["content-type"].startswith("application/json")
    assert _error(response).code is ApiErrorCode.INTERNAL_FAILURE


def test_initial_scenario_journal_must_begin_with_accepted_lifecycle() -> None:
    service = _FakeOperatorService()
    terminal = service.events[-1].model_copy(update={"cursor": 1})
    service.snapshot_override = ScenarioRunEventSnapshot(
        events=(terminal,),
        cursor=1,
        terminal=True,
    )
    with TestClient(create_app(operator_service=service)) as client:
        response = client.get("/api/v1/scenario-runs/investigation-7/events")

    assert response.status_code == 500
    assert response.headers["content-type"].startswith("application/json")
    assert _error(response).code is ApiErrorCode.INTERNAL_FAILURE


def test_active_scenario_stream_waits_for_the_terminal_suffix() -> None:
    service = _FakeOperatorService()
    service.snapshot_override = ScenarioRunEventSnapshot(
        events=service.events[:1],
        cursor=1,
        terminal=False,
    )
    service.wait_results.append(
        ScenarioRunEventSnapshot(
            events=service.events[1:],
            cursor=3,
            terminal=True,
        )
    )
    with TestClient(create_app(operator_service=service)) as client:
        response = client.get("/api/v1/scenario-runs/investigation-7/events")

    assert [event.cursor for event in _parse_sse(response)] == [1, 2, 3]
    assert service.wait_cursors == [1]
    assert len(service.cancellation_events) == 1
    assert service.cancellation_events[0].is_set()  # type: ignore[union-attr]


def test_envelope_summary_response_is_canonical_and_sanitized() -> None:
    service = _FakeOperatorService()
    service.current_snapshot = _snapshot(
        ScenarioRunLifecycle.RUNNING,
        summary=service.summary,
        cursor=3,
    )
    with TestClient(create_app(operator_service=service)) as client:
        response = client.get("/api/v1/investigations/investigation-7/envelope-summary")

    summary = decode_contract(response.content, ExecutionEnvelopeSummary)
    assert response.status_code == 200
    assert response.content == canonical_json_bytes(summary)
    assert service.summary_ids == ["investigation-7"]
    assert b'"scope"' not in response.content
    assert b'"resource"' not in response.content
    assert b'"arguments"' not in response.content


def test_envelope_summary_waits_without_missing_the_journal_transition() -> None:
    service = _FakeOperatorService()
    service.current_snapshot = _snapshot(
        ScenarioRunLifecycle.RUNNING,
        cursor=2,
    )
    summary_event = _event(
        3,
        ScenarioRunEventType.ENVELOPE_SUMMARY,
        EnvelopeSummaryEventPayload(summary=service.summary),
    )
    service.wait_results.append(
        ScenarioRunEventSnapshot(
            events=(summary_event,),
            cursor=3,
            terminal=False,
        )
    )
    service.snapshot_after_wait = _snapshot(
        ScenarioRunLifecycle.RUNNING,
        summary=service.summary,
        cursor=3,
    )
    with TestClient(create_app(operator_service=service)) as client:
        response = client.get("/api/v1/investigations/investigation-7/envelope-summary")

    assert response.status_code == 200
    assert decode_contract(response.content, ExecutionEnvelopeSummary) == (
        service.summary
    )
    assert service.wait_cursors == [2]
    assert service.cancellation_events[0].is_set()  # type: ignore[union-attr]


def test_terminal_pre_envelope_failure_is_a_fixed_canonical_503() -> None:
    service = _FakeOperatorService()
    service.current_snapshot = _snapshot(
        ScenarioRunLifecycle.FAILED,
        cursor=2,
    )
    with TestClient(create_app(operator_service=service)) as client:
        response = client.get("/api/v1/investigations/investigation-7/envelope-summary")

    error = _error(response)
    assert response.status_code == 503
    assert error.code is ApiErrorCode.DEPENDENCY_UNAVAILABLE
    assert error.message == "A required dependency is unavailable."
    assert error.details == {"investigation_id": "investigation-7"}
    assert service.summary_ids == []


def test_envelope_wait_converts_terminal_pre_summary_transition_to_503() -> None:
    service = _FakeOperatorService()
    service.current_snapshot = _snapshot(
        ScenarioRunLifecycle.RUNNING,
        cursor=2,
    )
    terminal = _event(
        3,
        ScenarioRunEventType.TERMINAL,
        TerminalStateEventPayload(
            terminal=TerminalStateSummary(
                lifecycle=ScenarioRunLifecycle.FAILED,
                result_kind=ScenarioRunResultKind.NONE,
                classification=None,
                action_gate_allowed_count=0,
                action_gate_denied_count=0,
                missing_evidence_count=0,
                escalation_required=None,
                failure_category=ScenarioRunFailureCategory.MODEL_UNAVAILABLE,
            )
        ),
    )
    service.wait_results.append(
        ScenarioRunEventSnapshot(events=(terminal,), cursor=3, terminal=True)
    )
    service.snapshot_after_wait = _snapshot(
        ScenarioRunLifecycle.FAILED,
        cursor=3,
    )
    with TestClient(create_app(operator_service=service)) as client:
        response = client.get("/api/v1/investigations/investigation-7/envelope-summary")

    assert response.status_code == 503
    assert _error(response).code is ApiErrorCode.DEPENDENCY_UNAVAILABLE
    assert service.wait_cursors == [2]
    assert service.cancellation_events[0].is_set()  # type: ignore[union-attr]


def test_closed_operator_service_is_a_canonical_503() -> None:
    service = _FakeOperatorService()
    service.launch_error = OperatorServiceClosed()
    with TestClient(create_app(operator_service=service)) as client:
        response = client.post(
            "/api/v1/scenario-runs",
            content=canonical_json_bytes(_launch()),
            headers={"Content-Type": "application/json"},
        )

    assert response.status_code == 503
    assert _error(response).code is ApiErrorCode.DEPENDENCY_UNAVAILABLE


def test_operator_service_lifetime_is_owned_and_default_is_lazy(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    service = _FakeOperatorService()
    built: list[bool] = []

    def build() -> _FakeOperatorService:
        built.append(True)
        return service

    monkeypatch.setattr(
        "reconcile.interfaces.api._build_default_operator_service",
        build,
    )
    application = create_app()
    assert built == []

    with TestClient(application) as client:
        assert client.get("/health").status_code == 200
        assert built == [True]
        assert service.closed is False

    assert service.closed is True


def test_openapi_contains_only_the_additive_versioned_operator_routes() -> None:
    service = _FakeOperatorService()
    with TestClient(create_app(operator_service=service)) as client:
        document = client.get("/openapi.json").json()

    paths = document["paths"]
    assert "/api/v1/investigations" in paths
    assert "/api/v1/scenario-runs" in paths
    assert "/api/v1/scenario-runs/{investigation_id}" in paths
    assert "/api/v1/scenario-runs/{investigation_id}/events" in paths
    assert "/api/v2/scenario-runs/{investigation_id}/operational-status" in paths
    assert "/api/v1/investigations/{investigation_id}/envelope-summary" in paths


def test_default_operator_api_completes_the_fixed_storage_journey() -> None:
    launch = ScenarioLaunchRequest(
        schema_version=SCENARIO_LAUNCH_REQUEST_VERSION,
        launch_id="api-fixed-storage",
        scenario=ScenarioLaunchName.STORAGE,
        mode=ScenarioRunMode.FIXED,
    )
    with TestClient(create_app()) as client:
        created = client.post(
            "/api/v1/scenario-runs",
            content=canonical_json_bytes(launch),
            headers={"Content-Type": "application/json"},
        )
        accepted = decode_contract(created.content, ScenarioRunSnapshot)
        events_response = client.get(
            f"/api/v1/scenario-runs/{accepted.investigation_id}/events"
        )
        current_response = client.get(
            f"/api/v1/scenario-runs/{accepted.investigation_id}"
        )
        summary_response = client.get(
            f"/api/v1/investigations/{accepted.investigation_id}/envelope-summary"
        )

    current = decode_contract(current_response.content, ScenarioRunSnapshot)
    assert created.status_code == 202
    assert _parse_sse(events_response)[-1].type is ScenarioRunEventType.TERMINAL
    assert current.lifecycle is ScenarioRunLifecycle.COMPLETED
    assert current.report is not None
    assert summary_response.status_code == 200
    assert (
        decode_contract(
            summary_response.content,
            ExecutionEnvelopeSummary,
        )
        == current.envelope_summary
    )
