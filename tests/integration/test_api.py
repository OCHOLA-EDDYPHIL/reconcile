"""Independent HTTP and SSE client coverage for the frozen loopback API."""

from __future__ import annotations

import json
from collections import deque
from dataclasses import dataclass
from datetime import timedelta
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient

from reconcile.contracts import (
    ERROR_VERSION,
    INVESTIGATION_EVENT_VERSION,
    ActionGateEventPayload,
    ApiError,
    ApiErrorCode,
    Classification,
    ClassificationEventPayload,
    EvidenceDecisionEventPayload,
    ExecutionEnvelope,
    InvestigationEvent,
    InvestigationEventPayload,
    InvestigationEventType,
    InvestigationReport,
    InvestigationStatus,
    LifecycleEventPayload,
    ProbeEventPayload,
    canonical_json_bytes,
    decode_contract,
)
from reconcile.interfaces.api import create_app, main
from reconcile.persistence import (
    CorruptStoredRecord,
    DuplicateInvestigationId,
    EventJournalSnapshot,
    InvalidCursor,
    InvestigationNotFound,
    WriteOutcomeUnknown,
)
from tests.contract._factories import NOW, make_envelope, make_report

pytestmark = pytest.mark.integration


@dataclass(frozen=True, slots=True)
class _CreateResult:
    report: InvestigationReport
    created: bool


class _SentinelReport(InvestigationReport):
    sentinel_authority: str


class _SentinelEvent(InvestigationEvent):
    sentinel_secret: str


def _terminal_report(
    classification: Classification = Classification.COMMITTED,
) -> InvestigationReport:
    payload = json.loads(canonical_json_bytes(make_report(classification)))
    payload["revision"] = 2
    return InvestigationReport.model_validate_json(json.dumps(payload))


def _sentinel_report() -> _SentinelReport:
    payload = json.loads(canonical_json_bytes(_terminal_report()))
    payload["sentinel_authority"] = "must-not-cross-http"
    return _SentinelReport.model_validate_json(json.dumps(payload))


def _sentinel_event(event: InvestigationEvent) -> _SentinelEvent:
    payload = json.loads(canonical_json_bytes(event))
    payload["sentinel_secret"] = "must-not-cross-http"
    return _SentinelEvent.model_validate_json(json.dumps(payload))


def _event(
    sequence: int,
    event_type: InvestigationEventType,
    payload: InvestigationEventPayload,
) -> InvestigationEvent:
    return InvestigationEvent(
        schema_version=INVESTIGATION_EVENT_VERSION,
        investigation_id="investigation-7",
        sequence=sequence,
        type=event_type,
        occurred_at=NOW + timedelta(milliseconds=sequence),
        payload=payload,
    )


def _terminal_transcript() -> tuple[InvestigationEvent, ...]:
    report = _terminal_report()
    events = [
        _event(
            1,
            InvestigationEventType.LIFECYCLE,
            LifecycleEventPayload(status=InvestigationStatus.CREATED),
        ),
        _event(
            2,
            InvestigationEventType.LIFECYCLE,
            LifecycleEventPayload(status=InvestigationStatus.INVESTIGATING),
        ),
        _event(
            3,
            InvestigationEventType.PROBE,
            ProbeEventPayload(probe_audit=report.probe_audit[0]),
        ),
        _event(
            4,
            InvestigationEventType.EVIDENCE_DECISION,
            EvidenceDecisionEventPayload(decision=report.evidence_decisions[0]),
        ),
        _event(
            5,
            InvestigationEventType.CLASSIFICATION,
            ClassificationEventPayload(classification=Classification.COMMITTED),
        ),
    ]
    events.extend(
        _event(
            sequence,
            InvestigationEventType.ACTION_GATE,
            ActionGateEventPayload(action_gate=action_gate),
        )
        for sequence, action_gate in enumerate(report.action_gate, start=6)
    )
    events.append(
        _event(
            11,
            InvestigationEventType.LIFECYCLE,
            LifecycleEventPayload(status=InvestigationStatus.COMPLETED),
        )
    )
    return tuple(events)


class _FakeService:
    def __init__(self) -> None:
        self.report = _terminal_report()
        self.events = _terminal_transcript()
        self.created = True
        self.create_error: Exception | None = None
        self.get_error: Exception | None = None
        self.snapshot_error: Exception | None = None
        self.wait_results: deque[EventJournalSnapshot] = deque()
        self.create_envelopes: list[ExecutionEnvelope] = []
        self.wait_create_envelopes: list[ExecutionEnvelope] = []
        self.snapshot_cursors: list[int] = []
        self.wait_cursors: list[int] = []
        self.cancellation_events: list[Any] = []
        self.closed = False

    async def create(self, envelope: ExecutionEnvelope) -> _CreateResult:
        if self.create_error is not None:
            raise self.create_error
        self.create_envelopes.append(envelope)
        return _CreateResult(report=self.report, created=self.created)

    async def create_and_wait_result(
        self,
        envelope: ExecutionEnvelope,
    ) -> _CreateResult:
        self.wait_create_envelopes.append(envelope)
        return _CreateResult(report=self.report, created=self.created)

    async def get(self, investigation_id: str) -> InvestigationReport:
        if self.get_error is not None:
            raise self.get_error
        if investigation_id != self.report.investigation_id:
            raise InvestigationNotFound(investigation_id)
        return self.report

    async def snapshot(
        self,
        investigation_id: str,
        *,
        after: int = 0,
    ) -> EventJournalSnapshot:
        if self.snapshot_error is not None:
            raise self.snapshot_error
        if investigation_id != self.report.investigation_id:
            raise InvestigationNotFound(investigation_id)
        if after > len(self.events):
            raise InvalidCursor(investigation_id, after, len(self.events))
        self.snapshot_cursors.append(after)
        if self.wait_results:
            initial_cursor = 2
            if after > initial_cursor:
                raise InvalidCursor(investigation_id, after, initial_cursor)
            return EventJournalSnapshot(
                events=self.events[after:initial_cursor],
                cursor=initial_cursor,
                terminal=False,
            )
        return EventJournalSnapshot(
            events=self.events[after:],
            cursor=len(self.events),
            terminal=True,
        )

    async def wait_for_events(
        self,
        investigation_id: str,
        *,
        after: int = 0,
        cancellation_event: Any = None,
    ) -> EventJournalSnapshot:
        if investigation_id != self.report.investigation_id:
            raise InvestigationNotFound(investigation_id)
        self.wait_cursors.append(after)
        self.cancellation_events.append(cancellation_event)
        if not self.wait_results:
            raise RuntimeError("unexpected empty wait queue")
        return self.wait_results.popleft()

    async def aclose(self) -> None:
        self.closed = True


def _error(response: Any) -> ApiError:
    error = decode_contract(response.content, ApiError)
    assert canonical_json_bytes(error) == response.content
    assert error.schema_version == ERROR_VERSION
    assert set(json.loads(response.content)) == {
        "schema_version",
        "code",
        "message",
        "details",
    }
    return error


def _parse_sse(response: Any) -> tuple[InvestigationEvent, ...]:
    blocks = tuple(block for block in response.content.split(b"\n\n") if block)
    events: list[InvestigationEvent] = []
    for block in blocks:
        fields = dict(line.split(b": ", 1) for line in block.splitlines())
        event = decode_contract(fields[b"data"], InvestigationEvent)
        assert fields[b"id"].decode() == str(event.sequence)
        assert fields[b"event"].decode() == event.type.value
        assert canonical_json_bytes(event) == fields[b"data"]
        events.append(event)
    return tuple(events)


def test_health_is_available_without_starting_the_default_service() -> None:
    client = TestClient(create_app())
    try:
        response = client.get("/health")
    finally:
        client.close()

    assert response.status_code == 200
    assert response.content == b'{"status":"ok"}'


def test_create_accepts_exact_envelope_and_returns_canonical_report() -> None:
    service = _FakeService()
    envelope = make_envelope()
    with TestClient(create_app(service)) as client:
        response = client.post(
            "/api/v1/investigations",
            content=canonical_json_bytes(envelope),
            headers={"content-type": "application/json"},
        )

    assert response.status_code == 201
    assert response.content == canonical_json_bytes(service.report)
    assert service.create_envelopes == [envelope]
    assert service.closed


def test_exact_create_replay_is_http_200_with_the_existing_report() -> None:
    service = _FakeService()
    service.created = False
    with TestClient(create_app(service)) as client:
        response = client.post(
            "/api/v1/investigations",
            content=canonical_json_bytes(make_envelope()),
            headers={"content-type": "application/json"},
        )

    assert response.status_code == 200
    assert response.content == canonical_json_bytes(service.report)


def test_hosted_create_uses_the_request_scoped_terminal_waiter() -> None:
    class HostedService(_FakeService):
        async def start(self) -> None:
            raise AssertionError("hosted service must not enumerate startup work")

    service = HostedService()
    envelope = make_envelope()
    with TestClient(create_app(service, hosted=True)) as client:
        response = client.post(
            "/api/v1/investigations",
            content=canonical_json_bytes(envelope),
            headers={"content-type": "application/json"},
        )

    assert response.status_code == 201
    assert response.content == canonical_json_bytes(service.report)
    assert service.wait_create_envelopes == [envelope]
    assert service.create_envelopes == []


def test_default_service_requires_an_explicit_durable_database(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("RECONCILE_RUNTIME_DATABASE", raising=False)
    envelope = make_envelope()
    with TestClient(create_app()) as client:
        response = client.post(
            "/api/v1/investigations",
            content=canonical_json_bytes(envelope),
            headers={"content-type": "application/json"},
        )

    assert response.status_code == 503
    assert _error(response).code is ApiErrorCode.DEPENDENCY_UNAVAILABLE


def test_explicit_default_runtime_database_fails_closed_without_executor(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    database = tmp_path / "api-runtime.sqlite3"
    monkeypatch.setenv("RECONCILE_RUNTIME_DATABASE", str(database))
    monkeypatch.setenv("RECONCILE_SEMANTIC_CONFIG_SHA256", "a" * 64)
    envelope = make_envelope()

    with TestClient(create_app()) as client:
        assert client.get("/health").status_code == 200
        response = client.post(
            "/api/v1/investigations",
            content=canonical_json_bytes(envelope),
            headers={"content-type": "application/json"},
        )

    assert response.status_code == 503
    assert _error(response).code is ApiErrorCode.DEPENDENCY_UNAVAILABLE
    # The envelope-only service remains unavailable, while the real operator
    # now owns the shared private schema-v4 scenario authority.
    assert database.is_file()
    assert database.stat().st_mode & 0o077 == 0


def test_default_operator_rejects_workspace_symlink_without_chmod_target(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    database = tmp_path / "api-runtime.sqlite3"
    target = tmp_path / "workspace-target"
    target.mkdir(mode=0o755)
    target_mode = target.stat().st_mode & 0o777
    (tmp_path / "scenario-workspaces").symlink_to(
        target,
        target_is_directory=True,
    )
    monkeypatch.setenv("RECONCILE_RUNTIME_DATABASE", str(database))
    monkeypatch.setenv("RECONCILE_SEMANTIC_CONFIG_SHA256", "a" * 64)
    for name in (
        "RECONCILE_VERTEX_PROJECT",
        "RECONCILE_VERTEX_LOCATION",
        "RECONCILE_VERTEX_MODEL",
    ):
        monkeypatch.delenv(name, raising=False)

    with TestClient(create_app()) as client:
        assert client.get("/health").status_code == 200

    assert target.stat().st_mode & 0o777 == target_mode
    assert not database.exists()


def test_relative_default_runtime_path_is_rejected_without_creating_state(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    relative = Path("runtime-must-not-exist.sqlite3")
    monkeypatch.setenv("RECONCILE_RUNTIME_DATABASE", str(relative))

    with TestClient(create_app()) as client:
        response = client.post(
            "/api/v1/investigations",
            content=canonical_json_bytes(make_envelope()),
            headers={"content-type": "application/json"},
        )

    assert response.status_code == 503
    assert not relative.exists()


@pytest.mark.parametrize(
    ("payload", "expected_status", "expected_code"),
    (
        (b"not-json", 400, ApiErrorCode.INVALID_CONTRACT),
        (b"{}", 400, ApiErrorCode.INVALID_CONTRACT),
        (
            json.dumps(
                {
                    **json.loads(canonical_json_bytes(make_envelope())),
                    "schema_version": "reconcile/execution-envelope/v2",
                }
            ).encode(),
            422,
            ApiErrorCode.UNSUPPORTED_CONTRACT_VERSION,
        ),
    ),
)
def test_invalid_and_unsupported_envelopes_are_distinct(
    payload: bytes,
    expected_status: int,
    expected_code: ApiErrorCode,
) -> None:
    service = _FakeService()
    with TestClient(create_app(service)) as client:
        response = client.post(
            "/api/v1/investigations",
            content=payload,
            headers={"content-type": "application/json"},
        )

    assert response.status_code == expected_status
    assert _error(response).code is expected_code
    assert service.create_envelopes == []


def test_nested_unknown_contract_version_is_unsupported() -> None:
    payload = json.loads(canonical_json_bytes(make_envelope()))
    payload["expected_effects"][0]["schema_version"] = "reconcile/expected-effect/v2"
    service = _FakeService()
    with TestClient(create_app(service)) as client:
        response = client.post("/api/v1/investigations", json=payload)

    assert response.status_code == 422
    assert _error(response).code is ApiErrorCode.UNSUPPORTED_CONTRACT_VERSION


def test_superseded_create_wrapper_is_not_accepted() -> None:
    payload = {
        "schema_version": "reconcile/investigation-create-request/v1",
        "envelope": json.loads(canonical_json_bytes(make_envelope())),
    }
    service = _FakeService()
    with TestClient(create_app(service)) as client:
        response = client.post("/api/v1/investigations", json=payload)

    assert response.status_code == 422
    assert _error(response).code is ApiErrorCode.UNSUPPORTED_CONTRACT_VERSION
    assert service.create_envelopes == []


@pytest.mark.parametrize(
    ("body", "content_type"),
    (
        (b"{}", "text/plain"),
        (b"", "application/json"),
        (b" " * 1_048_577, "application/json"),
    ),
)
def test_create_body_is_content_typed_nonempty_and_bounded(
    body: bytes,
    content_type: str,
) -> None:
    service = _FakeService()
    with TestClient(create_app(service)) as client:
        response = client.post(
            "/api/v1/investigations",
            content=body,
            headers={"content-type": content_type},
        )

    assert response.status_code == 400
    assert _error(response).code is ApiErrorCode.INVALID_CONTRACT


def test_create_rejects_client_authored_classification() -> None:
    payload = json.loads(canonical_json_bytes(make_envelope()))
    payload["classification"] = "COMMITTED"
    service = _FakeService()
    with TestClient(create_app(service)) as client:
        response = client.post("/api/v1/investigations", json=payload)

    assert response.status_code == 400
    assert _error(response).code is ApiErrorCode.INVALID_CONTRACT


@pytest.mark.parametrize(
    ("error", "expected_status", "expected_code"),
    (
        (
            DuplicateInvestigationId("investigation-7"),
            409,
            ApiErrorCode.DUPLICATE_INVESTIGATION_ID,
        ),
        (
            WriteOutcomeUnknown("create", "investigation-7"),
            503,
            ApiErrorCode.DEPENDENCY_UNAVAILABLE,
        ),
        (
            CorruptStoredRecord("investigation-7"),
            500,
            ApiErrorCode.INTERNAL_FAILURE,
        ),
        (
            RuntimeError("private provider failure"),
            500,
            ApiErrorCode.INTERNAL_FAILURE,
        ),
    ),
)
def test_create_failures_use_frozen_errors_without_exception_text(
    error: Exception,
    expected_status: int,
    expected_code: ApiErrorCode,
) -> None:
    service = _FakeService()
    service.create_error = error
    with TestClient(create_app(service)) as client:
        response = client.post(
            "/api/v1/investigations",
            content=canonical_json_bytes(make_envelope()),
            headers={"content-type": "application/json"},
        )

    parsed = _error(response)
    assert response.status_code == expected_status
    assert parsed.code is expected_code
    assert str(error).encode() not in response.content
    assert parsed.details == {"investigation_id": "investigation-7"}


def test_malformed_create_result_is_a_stable_internal_failure() -> None:
    service = _FakeService()

    async def create(_envelope: ExecutionEnvelope) -> object:
        return object()

    service.create = create  # type: ignore[method-assign]
    with TestClient(create_app(service)) as client:
        response = client.post(
            "/api/v1/investigations",
            content=canonical_json_bytes(make_envelope()),
            headers={"content-type": "application/json"},
        )

    assert response.status_code == 500
    assert _error(response).code is ApiErrorCode.INTERNAL_FAILURE


def test_report_subclass_fields_cannot_cross_the_http_boundary() -> None:
    service = _FakeService()
    service.report = _sentinel_report()
    with TestClient(create_app(service)) as client:
        response = client.post(
            "/api/v1/investigations",
            content=canonical_json_bytes(make_envelope()),
            headers={"content-type": "application/json"},
        )

    assert response.status_code == 500
    assert _error(response).code is ApiErrorCode.INTERNAL_FAILURE
    assert b"sentinel" not in response.content
    assert b"must-not-cross-http" not in response.content


@pytest.mark.parametrize(
    "classification",
    (Classification.UNKNOWN, Classification.PENDING),
)
def test_product_classifications_are_http_200_report_data(
    classification: Classification,
) -> None:
    service = _FakeService()
    service.report = _terminal_report(classification)
    with TestClient(create_app(service)) as client:
        response = client.get("/api/v1/investigations/investigation-7")

    report = decode_contract(response.content, InvestigationReport)
    assert response.status_code == 200
    assert report.classification is classification
    assert response.content == canonical_json_bytes(report)


def test_missing_investigation_is_a_canonical_404() -> None:
    service = _FakeService()
    service.get_error = InvestigationNotFound("investigation-7")
    with TestClient(create_app(service)) as client:
        response = client.get("/api/v1/investigations/investigation-7")

    assert response.status_code == 404
    assert _error(response).code is ApiErrorCode.INVESTIGATION_NOT_FOUND


@pytest.mark.parametrize("path", ("bad id", "x" * 129, "token:private-marker"))
def test_invalid_path_identifier_is_rejected_before_service_access(path: str) -> None:
    service = _FakeService()
    with TestClient(create_app(service)) as client:
        response = client.get(f"/api/v1/investigations/{path}")

    assert response.status_code == 400
    assert _error(response).code is ApiErrorCode.INVALID_CONTRACT


def test_terminal_sse_replay_is_ordered_canonical_and_complete() -> None:
    service = _FakeService()
    with TestClient(create_app(service)) as client:
        response = client.get("/api/v1/investigations/investigation-7/events")

    events = _parse_sse(response)
    assert response.status_code == 200
    assert response.headers["content-type"].startswith("text/event-stream")
    assert [event.sequence for event in events] == list(range(1, 12))
    assert set(json.loads(canonical_json_bytes(events[0]))) == {
        "schema_version",
        "investigation_id",
        "sequence",
        "type",
        "occurred_at",
        "payload",
    }


@pytest.mark.parametrize(
    "request_options",
    (
        {"params": {"after": "5"}},
        {"headers": {"Last-Event-ID": "5"}},
        {
            "params": {"after": "5"},
            "headers": {"Last-Event-ID": "5"},
        },
    ),
)
def test_sse_resume_sequence_is_exclusive_without_gaps_or_duplicates(
    request_options: dict[str, object],
) -> None:
    service = _FakeService()
    with TestClient(create_app(service)) as client:
        response = client.get(
            "/api/v1/investigations/investigation-7/events",
            **request_options,
        )

    assert [event.sequence for event in _parse_sse(response)] == list(range(6, 12))
    assert service.snapshot_cursors == [5]


@pytest.mark.parametrize(
    "request_options",
    (
        {"params": {"after": "05"}},
        {"params": {"after": "12"}},
        {
            "params": {"after": "4"},
            "headers": {"Last-Event-ID": "5"},
        },
        {"params": [("after", "4"), ("after", "5")]},
        {"params": {"unknown": "1"}},
    ),
)
def test_invalid_resume_sequence_is_invalid_contract(
    request_options: dict[str, object],
) -> None:
    service = _FakeService()
    with TestClient(create_app(service)) as client:
        response = client.get(
            "/api/v1/investigations/investigation-7/events",
            **request_options,
        )

    assert response.status_code == 400
    assert _error(response).code is ApiErrorCode.INVALID_CONTRACT


def test_active_stream_waits_once_and_delivers_terminal_suffix_slowly() -> None:
    service = _FakeService()
    service.wait_results.append(
        EventJournalSnapshot(
            events=service.events[2:],
            cursor=len(service.events),
            terminal=True,
        )
    )
    with TestClient(create_app(service)) as client:
        with client.stream(
            "GET",
            "/api/v1/investigations/investigation-7/events",
        ) as response:
            chunks = tuple(response.iter_bytes(chunk_size=17))

    events = _parse_sse(type("Response", (), {"content": b"".join(chunks)})())
    assert [event.sequence for event in events] == list(range(1, 12))
    assert service.wait_cursors == [2]
    assert len(service.cancellation_events) == 1
    assert service.cancellation_events[0].is_set()


def test_missing_event_journal_is_reported_before_sse_headers_start() -> None:
    service = _FakeService()
    service.snapshot_error = InvestigationNotFound("investigation-7")
    with TestClient(create_app(service)) as client:
        response = client.get("/api/v1/investigations/investigation-7/events")

    assert response.status_code == 404
    assert response.headers["content-type"].startswith("application/json")
    assert _error(response).code is ApiErrorCode.INVESTIGATION_NOT_FOUND


def test_malformed_snapshot_is_stable_error_before_sse_headers() -> None:
    service = _FakeService()

    async def snapshot(
        _investigation_id: str,
        *,
        after: int = 0,
    ) -> EventJournalSnapshot:
        return EventJournalSnapshot(
            events=(object(),),  # type: ignore[arg-type]
            cursor=after + 1,
            terminal=False,
        )

    service.snapshot = snapshot  # type: ignore[method-assign]
    with TestClient(create_app(service)) as client:
        response = client.get("/api/v1/investigations/investigation-7/events")

    assert response.status_code == 500
    assert _error(response).code is ApiErrorCode.INTERNAL_FAILURE


def test_event_subclass_fields_cannot_cross_the_sse_boundary() -> None:
    service = _FakeService()
    service.events = (_sentinel_event(service.events[0]),)
    with TestClient(create_app(service)) as client:
        response = client.get("/api/v1/investigations/investigation-7/events")

    assert response.status_code == 500
    assert response.headers["content-type"].startswith("application/json")
    assert _error(response).code is ApiErrorCode.INTERNAL_FAILURE
    assert b"sentinel" not in response.content
    assert b"must-not-cross-http" not in response.content


def test_superseded_draft_routes_are_not_mounted() -> None:
    service = _FakeService()
    with TestClient(create_app(service)) as client:
        response = client.get("/v1/investigations/investigation-7")

    assert response.status_code == 404


def test_openapi_states_the_isolated_authentication_boundary() -> None:
    service = _FakeService()
    with TestClient(create_app(service)) as client:
        document = client.get("/openapi.json").json()

    description = document["info"]["description"]
    assert "Loopback-only" in description
    assert "single-tenant" in description
    assert "Authentication" in description
    assert "/api/v1/investigations" in document["paths"]
    assert "/v1/investigations" not in document["paths"]
    assert document.get("security") is None


def test_main_binds_only_to_loopback(monkeypatch: pytest.MonkeyPatch) -> None:
    captured: dict[str, object] = {}

    def run(application: object, *, host: str, port: int) -> None:
        captured.update(application=application, host=host, port=port)

    monkeypatch.setattr("reconcile.interfaces.api.uvicorn.run", run)

    main()

    assert captured["host"] == "127.0.0.1"
    assert captured["port"] == 8000
