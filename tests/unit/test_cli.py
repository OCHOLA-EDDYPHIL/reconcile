from __future__ import annotations

import stat
from collections.abc import AsyncIterator
from dataclasses import dataclass, field
from datetime import timedelta
from pathlib import Path

import pytest
from click.testing import Result
from typer.testing import CliRunner

import reconcile.cli as package_cli
import reconcile.interfaces.cli as cli_module
from reconcile.cli import app, main
from reconcile.cli_core import (
    canonical_json_output,
    render_human_event,
    render_human_report,
    render_human_status,
)
from reconcile.contracts import (
    EXECUTION_ENVELOPE_SUMMARY_VERSION,
    SCENARIO_LAUNCH_REQUEST_VERSION,
    SCENARIO_OPERATIONAL_STATUS_VERSION,
    SCENARIO_RUN_EVENT_VERSION,
    SCENARIO_RUN_SNAPSHOT_VERSION,
    Classification,
    EnvelopeEffectSummary,
    ExecutionEnvelope,
    ExecutionEnvelopeSummary,
    InvestigationEvent,
    InvestigationEventType,
    InvestigationReport,
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
    ScenarioRunLifecycle,
    ScenarioRunMode,
    ScenarioRunSnapshot,
    canonical_json_bytes,
    canonical_sha256,
)
from reconcile.interfaces.api_client import (
    InvalidRequestError,
    InvestigationConflictError,
    InvestigationNotFoundError,
    RemoteInternalError,
    RemoteProtocolError,
    ServiceUnavailableError,
    TransportError,
)
from reconcile.interfaces.operator_api_client import ScenarioLaunchResult
from reconcile.operator import sanitize_report
from reconcile.scenarios.service import ScenarioMode, ScenarioName
from tests.contract._factories import (
    NOW,
    make_envelope,
    make_investigation_event,
    make_report,
)

pytestmark = pytest.mark.unit

_RUNNER = CliRunner()


class _BrokenStdout:
    encoding = "utf-8"

    @property
    def buffer(self) -> _BrokenStdout:
        return self

    def write(self, _payload: object) -> int:
        raise BrokenPipeError

    def flush(self) -> None:
        raise BrokenPipeError

    def fileno(self) -> int:
        raise OSError

    def isatty(self) -> bool:
        return False


@dataclass(slots=True)
class _ClientState:
    report: InvestigationReport
    events: tuple[InvestigationEvent, ...] = ()
    create_failure: BaseException | None = None
    get_failure: BaseException | None = None
    events_failure: BaseException | None = None
    base_urls: list[str] = field(default_factory=list)
    creates: list[ExecutionEnvelope] = field(default_factory=list)
    gets: list[str] = field(default_factory=list)
    event_requests: list[tuple[str, int]] = field(default_factory=list)
    exits: int = 0


def _install_client(
    monkeypatch: pytest.MonkeyPatch,
    *,
    report: InvestigationReport | None = None,
    events: tuple[InvestigationEvent, ...] = (),
    create_failure: BaseException | None = None,
    get_failure: BaseException | None = None,
    events_failure: BaseException | None = None,
) -> _ClientState:
    state = _ClientState(
        report=report or make_report(Classification.COMMITTED),
        events=events,
        create_failure=create_failure,
        get_failure=get_failure,
        events_failure=events_failure,
    )

    class FakeInvestigationApiClient:
        def __init__(self, base_url: str) -> None:
            state.base_urls.append(base_url)

        def __enter__(self) -> FakeInvestigationApiClient:
            return self

        def __exit__(self, *_exc_info: object) -> None:
            state.exits += 1

        def create(self, envelope: ExecutionEnvelope) -> InvestigationReport:
            state.creates.append(envelope)
            if state.create_failure is not None:
                raise state.create_failure
            return state.report

        def get(self, investigation_id: str) -> InvestigationReport:
            state.gets.append(investigation_id)
            if state.get_failure is not None:
                raise state.get_failure
            return state.report

        def events(
            self,
            investigation_id: str,
            *,
            after: int = 0,
        ) -> tuple[InvestigationEvent, ...]:
            state.event_requests.append((investigation_id, after))
            if state.events_failure is not None:
                raise state.events_failure
            return state.events

    monkeypatch.setattr(
        cli_module,
        "InvestigationApiClient",
        FakeInvestigationApiClient,
    )
    return state


def _scenario_snapshot(
    classification: Classification = Classification.COMMITTED,
) -> ScenarioRunSnapshot:
    envelope = make_envelope()
    report = sanitize_report(make_report(classification))
    summary = ExecutionEnvelopeSummary(
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
    return ScenarioRunSnapshot(
        schema_version=SCENARIO_RUN_SNAPSHOT_VERSION,
        launch_id="launch-7",
        investigation_id=envelope.investigation_id,
        scenario=ScenarioLaunchName.STORAGE,
        mode=ScenarioRunMode.FIXED,
        lifecycle=ScenarioRunLifecycle.COMPLETED,
        event_cursor=3,
        envelope_summary=summary,
        report=report,
        comparison=None,
        failure_category=None,
        accepted_at=NOW,
        updated_at=NOW + timedelta(seconds=5),
    )


def _scenario_status(
    *,
    cleanup_state: ScenarioOperationalCleanupState = (
        ScenarioOperationalCleanupState.SUCCEEDED
    ),
    recovery_state: ScenarioOperationalRecoveryState = (
        ScenarioOperationalRecoveryState.NOT_ESCALATED
    ),
    investigation_id: str = "investigation-7",
) -> ScenarioOperationalStatus:
    investigation_state = (
        ScenarioOperationalInvestigationState.ESCALATION_REQUIRED
        if recovery_state is ScenarioOperationalRecoveryState.HUMAN_ESCALATION_REQUIRED
        else ScenarioOperationalInvestigationState.RECORDED
    )
    return ScenarioOperationalStatus(
        schema_version=SCENARIO_OPERATIONAL_STATUS_VERSION,
        launch_id="launch-7",
        investigation_id=investigation_id,
        scenario=ScenarioLaunchName.STORAGE,
        mode=ScenarioRunMode.FIXED,
        revision=9,
        mutation_state=ScenarioOperationalMutationState.RECORDED,
        investigation_state=investigation_state,
        cleanup_state=(
            ScenarioOperationalCleanupState.NOT_REQUESTED
            if investigation_state
            is ScenarioOperationalInvestigationState.ESCALATION_REQUIRED
            else cleanup_state
        ),
        recovery_state=recovery_state,
        updated_at=NOW + timedelta(seconds=5),
    )


def _scenario_event(cursor: int = 1) -> ScenarioRunEvent:
    return ScenarioRunEvent(
        schema_version=SCENARIO_RUN_EVENT_VERSION,
        investigation_id="investigation-7",
        cursor=cursor,
        type=ScenarioRunEventType.LIFECYCLE,
        occurred_at=NOW + timedelta(milliseconds=cursor),
        payload=ScenarioLifecycleEventPayload(lifecycle=ScenarioRunLifecycle.ACCEPTED),
    )


@dataclass(slots=True)
class _OperatorClientState:
    snapshot: ScenarioRunSnapshot
    status: ScenarioOperationalStatus
    events: tuple[ScenarioRunEvent, ...] = ()
    failure: BaseException | None = None
    status_failure: BaseException | None = None
    base_urls: list[str] = field(default_factory=list)
    launches: list[ScenarioLaunchRequest] = field(default_factory=list)
    status_requests: list[str] = field(default_factory=list)
    snapshot_requests: list[str] = field(default_factory=list)
    event_requests: list[tuple[str, int]] = field(default_factory=list)
    exits: int = 0


def _install_operator_client(
    monkeypatch: pytest.MonkeyPatch,
    *,
    snapshot: ScenarioRunSnapshot | None = None,
    status: ScenarioOperationalStatus | None = None,
    events: tuple[ScenarioRunEvent, ...] = (),
    failure: BaseException | None = None,
    status_failure: BaseException | None = None,
) -> _OperatorClientState:
    state = _OperatorClientState(
        snapshot=snapshot or _scenario_snapshot(),
        status=status or _scenario_status(),
        events=events,
        failure=failure,
        status_failure=status_failure,
    )

    class FakeOperatorApiClient:
        def __init__(self, base_url: str) -> None:
            state.base_urls.append(base_url)

        async def __aenter__(self) -> FakeOperatorApiClient:
            return self

        async def __aexit__(self, *_exc_info: object) -> None:
            state.exits += 1

        async def launch(
            self,
            request: ScenarioLaunchRequest,
        ) -> ScenarioLaunchResult:
            state.launches.append(request)
            if state.failure is not None:
                raise state.failure
            return ScenarioLaunchResult(created=True, snapshot=state.snapshot)

        async def get_snapshot(
            self,
            investigation_id: str,
        ) -> ScenarioRunSnapshot:
            state.snapshot_requests.append(investigation_id)
            if state.failure is not None:
                raise state.failure
            return state.snapshot

        async def get_operational_status(
            self,
            investigation_id: str,
        ) -> ScenarioOperationalStatus:
            state.status_requests.append(investigation_id)
            if state.status_failure is not None:
                raise state.status_failure
            if state.failure is not None:
                raise state.failure
            return state.status

        async def events(
            self,
            investigation_id: str,
            *,
            after: int = 0,
        ) -> AsyncIterator[ScenarioRunEvent]:
            state.event_requests.append((investigation_id, after))
            if state.failure is not None:
                raise state.failure
            for event in state.events:
                yield event

    monkeypatch.setattr(
        cli_module,
        "OperatorApiClient",
        FakeOperatorApiClient,
    )
    return state


def _assert_clean_success(result: Result, expected: bytes) -> None:
    assert result.exit_code == 0
    assert result.stdout_bytes == expected
    assert result.stderr_bytes == b""


def test_empty_invocation_and_package_main_remain_successful() -> None:
    result = _RUNNER.invoke(app, [])

    assert result.exit_code == 0
    assert result.stdout_bytes == b""
    assert result.stderr_bytes == b""
    assert main([]) == 0
    assert package_cli.app is cli_module.app
    assert package_cli.main is cli_module.main


def test_help_lists_the_stable_command_surface() -> None:
    result = _RUNNER.invoke(app, ["--help"])

    assert result.exit_code == 0
    assert result.stderr_bytes == b""
    assert "RECONCILE automation interface" in result.stdout
    for command in (
        "investigate",
        "get",
        "events",
        "status",
        "report",
        "watch",
        "scenario",
    ):
        assert command in result.stdout

    scenario_result = _RUNNER.invoke(app, ["scenario", "--help"])
    assert scenario_result.exit_code == 0
    for command in ("launch", "status", "events", "watch", "run", "suite"):
        assert command in scenario_result.stdout


def test_remote_scenario_launch_emits_exact_v1_snapshot(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    snapshot = _scenario_snapshot()
    state = _install_operator_client(monkeypatch, snapshot=snapshot)

    result = _RUNNER.invoke(
        app,
        [
            "scenario",
            "launch",
            "launch-7",
            "storage",
            "--mode",
            "fixed",
            "--output",
            "json",
            "--api-url",
            "http://127.0.0.1:9000",
        ],
    )

    _assert_clean_success(result, canonical_json_output(snapshot))
    assert state.base_urls == ["http://127.0.0.1:9000"]
    assert state.launches == [
        ScenarioLaunchRequest(
            schema_version=SCENARIO_LAUNCH_REQUEST_VERSION,
            launch_id="launch-7",
            scenario=ScenarioLaunchName.STORAGE,
            mode=ScenarioRunMode.FIXED,
        )
    ]
    assert state.exits == 1


def test_remote_scenario_status_emits_exact_v2_status(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    status = _scenario_status(cleanup_state=ScenarioOperationalCleanupState.FAILED)
    state = _install_operator_client(monkeypatch, status=status)

    result = _RUNNER.invoke(
        app,
        ["scenario", "status", "investigation-7", "--output", "json"],
    )

    _assert_clean_success(result, canonical_json_output(status))
    assert state.base_urls == ["http://127.0.0.1:8000"]
    assert state.status_requests == ["investigation-7"]
    assert state.snapshot_requests == []


def test_remote_scenario_status_human_surfaces_recovery_escalation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    status = _scenario_status(
        recovery_state=(ScenarioOperationalRecoveryState.HUMAN_ESCALATION_REQUIRED)
    )
    _install_operator_client(monkeypatch, status=status)

    result = _RUNNER.invoke(
        app,
        ["scenario", "status", "investigation-7", "--output", "human"],
    )

    assert result.exit_code == 0
    assert result.stderr_bytes == b""
    assert "Investigation: ESCALATION_REQUIRED\n" in result.stdout
    assert "Cleanup: NOT_REQUESTED\n" in result.stdout
    assert "Recovery: HUMAN_ESCALATION_REQUIRED\n" in result.stdout


def test_remote_scenario_events_preserve_exclusive_v1_cursor_and_jsonl(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    event = _scenario_event(cursor=5)
    state = _install_operator_client(monkeypatch, events=(event,))

    result = _RUNNER.invoke(
        app,
        [
            "scenario",
            "events",
            "investigation-7",
            "--after",
            "4",
            "--output",
            "jsonl",
        ],
    )

    _assert_clean_success(result, canonical_json_output(event))
    assert state.event_requests == [("investigation-7", 4)]
    assert state.status_requests == []
    assert state.snapshot_requests == []


def test_remote_scenario_watch_json_is_only_authoritative_v1_snapshot(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    snapshot = _scenario_snapshot(Classification.COMMITTED)
    status = _scenario_status(cleanup_state=ScenarioOperationalCleanupState.FAILED)
    state = _install_operator_client(
        monkeypatch,
        snapshot=snapshot,
        status=status,
        status_failure=RuntimeError("v2 must not be requested for JSON watch"),
    )

    result = _RUNNER.invoke(
        app,
        [
            "scenario",
            "watch",
            "investigation-7",
            "--after",
            "2",
            "--output",
            "json",
        ],
    )

    _assert_clean_success(result, canonical_json_output(snapshot))
    assert state.event_requests == [("investigation-7", 2)]
    assert state.status_requests == []
    assert state.snapshot_requests == ["investigation-7"]


def test_remote_scenario_watch_human_shows_operations_then_v1_outcome(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    snapshot = _scenario_snapshot(Classification.UNKNOWN)
    status = _scenario_status(cleanup_state=ScenarioOperationalCleanupState.FAILED)
    event = _scenario_event()
    _install_operator_client(
        monkeypatch,
        snapshot=snapshot,
        status=status,
        events=(event,),
    )

    result = _RUNNER.invoke(
        app,
        ["scenario", "watch", "investigation-7", "--output", "human"],
    )

    assert result.exit_code == 6
    assert result.stderr_bytes == b""
    assert "Cursor: 1\nType: LIFECYCLE\n" in result.stdout
    assert "Cleanup: FAILED\n" in result.stdout
    assert "Recovery: NOT_ESCALATED\n" in result.stdout
    assert "Lifecycle: COMPLETED\n" in result.stdout
    assert "Classification: UNKNOWN\n" in result.stdout
    assert result.stdout.index("Cleanup: FAILED") < result.stdout.index(
        "Classification: UNKNOWN"
    )


@pytest.mark.parametrize(
    ("status_failure", "classification", "exit_code"),
    (
        (ServiceUnavailableError(), Classification.COMMITTED, 0),
        (RemoteProtocolError(), Classification.UNKNOWN, 6),
        (TransportError(), Classification.NOT_COMMITTED, 0),
    ),
)
def test_remote_scenario_watch_v2_failure_never_suppresses_v1_result(
    monkeypatch: pytest.MonkeyPatch,
    status_failure: BaseException,
    classification: Classification,
    exit_code: int,
) -> None:
    snapshot = _scenario_snapshot(classification)
    state = _install_operator_client(
        monkeypatch,
        snapshot=snapshot,
        status_failure=status_failure,
    )

    result = _RUNNER.invoke(
        app,
        ["scenario", "watch", "investigation-7", "--output", "human"],
    )

    assert result.exit_code == exit_code
    assert result.stderr_bytes == b""
    assert "Operational status: unavailable\n" in result.stdout
    assert f"Classification: {classification.value}\n" in result.stdout
    assert state.snapshot_requests == ["investigation-7"]
    assert state.status_requests == ["investigation-7"]


def test_remote_scenario_watch_does_not_render_v2_identity_collision(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    snapshot = _scenario_snapshot()
    state = _install_operator_client(
        monkeypatch,
        snapshot=snapshot,
        status=_scenario_status(investigation_id="other-investigation"),
    )

    result = _RUNNER.invoke(
        app,
        ["scenario", "watch", "investigation-7", "--output", "human"],
    )

    assert result.exit_code == 0
    assert result.stderr_bytes == b""
    assert "Operational status: unavailable\n" in result.stdout
    assert "Classification: COMMITTED\n" in result.stdout
    assert "other-investigation" not in result.stdout
    assert state.status_requests == ["investigation-7"]


def test_remote_scenario_invalid_cursor_is_rejected_before_client_creation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    state = _install_operator_client(monkeypatch)

    result = _RUNNER.invoke(
        app,
        ["scenario", "events", "investigation-7", "--after", "1025"],
    )

    assert result.exit_code == 2
    assert state.base_urls == []


@pytest.mark.parametrize(
    ("failure", "exit_code", "message"),
    (
        (InvalidRequestError(), 2, "The input is invalid.\n"),
        (
            InvestigationNotFoundError(),
            3,
            "The requested investigation was not found.\n",
        ),
        (ServiceUnavailableError(), 5, "The service is unavailable.\n"),
        (RemoteProtocolError(), 5, "The service is unavailable.\n"),
        (TransportError(), 5, "The service is unavailable.\n"),
    ),
)
def test_remote_scenario_status_uses_stable_client_failure_mapping(
    monkeypatch: pytest.MonkeyPatch,
    failure: BaseException,
    exit_code: int,
    message: str,
) -> None:
    _install_operator_client(monkeypatch, failure=failure)

    result = _RUNNER.invoke(
        app,
        ["scenario", "status", "investigation-7", "--output", "json"],
    )

    assert result.exit_code == exit_code
    assert result.stdout_bytes == b""
    assert result.stderr_bytes == message.encode()


def test_main_returns_the_parser_exit_code() -> None:
    assert main(["--unknown-option"]) == 2


def test_investigate_stdin_emits_one_exact_canonical_report(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    envelope = make_envelope()
    report = make_report(Classification.COMMITTED)
    state = _install_client(monkeypatch, report=report)

    result = _RUNNER.invoke(
        app,
        [
            "investigate",
            "--input",
            "-",
            "--output",
            "json",
            "--api-url",
            "https://api.example.test",
        ],
        input=canonical_json_bytes(envelope),
    )

    _assert_clean_success(result, canonical_json_output(report))
    assert state.creates == [envelope]
    assert state.base_urls == ["https://api.example.test"]
    assert state.exits == 1


def test_get_emits_one_exact_canonical_report(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    report = make_report(Classification.COMMITTED)
    state = _install_client(monkeypatch, report=report)

    result = _RUNNER.invoke(app, ["get", "investigation-7", "--output", "json"])

    _assert_clean_success(result, canonical_json_output(report))
    assert state.gets == ["investigation-7"]


def test_events_emits_only_exact_canonical_jsonl(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    events = (
        make_investigation_event(InvestigationEventType.PROBE, sequence=5),
        make_investigation_event(InvestigationEventType.LIFECYCLE, sequence=6),
    )
    state = _install_client(monkeypatch, events=events)

    result = _RUNNER.invoke(
        app,
        [
            "events",
            "investigation-7",
            "--after",
            "4",
            "--output",
            "jsonl",
        ],
    )

    _assert_clean_success(
        result,
        b"".join(canonical_json_output(event) for event in events),
    )
    assert state.event_requests == [("investigation-7", 4)]


@pytest.mark.parametrize(
    ("command", "output", "expected"),
    (
        ("status", "human", "status-human"),
        ("status", "json", "json"),
        ("report", "human", "report-human"),
        ("report", "json", "json"),
    ),
)
def test_status_and_report_human_and_json_views(
    monkeypatch: pytest.MonkeyPatch,
    command: str,
    output: str,
    expected: str,
) -> None:
    report = make_report(Classification.COMMITTED)
    _install_client(monkeypatch, report=report)
    expected_bytes = {
        "status-human": render_human_status(report),
        "report-human": render_human_report(report),
        "json": canonical_json_output(report),
    }[expected]

    result = _RUNNER.invoke(
        app,
        [command, "investigation-7", "--output", output],
    )

    _assert_clean_success(result, expected_bytes)


def test_watch_human_emits_bounded_events_then_report(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    report = make_report(Classification.COMMITTED)
    event = make_investigation_event(InvestigationEventType.LIFECYCLE)
    state = _install_client(monkeypatch, report=report, events=(event,))

    result = _RUNNER.invoke(
        app,
        ["watch", "investigation-7", "--output", "human", "--after", "0"],
    )

    _assert_clean_success(
        result,
        render_human_event(event) + render_human_report(report),
    )
    assert state.event_requests == [("investigation-7", 0)]
    assert state.gets == ["investigation-7"]


def test_watch_json_suppresses_event_output_and_emits_only_the_report(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    report = make_report(Classification.COMMITTED)
    event = make_investigation_event(InvestigationEventType.LIFECYCLE)
    _install_client(monkeypatch, report=report, events=(event,))

    result = _RUNNER.invoke(
        app,
        ["watch", "investigation-7", "--output", "json"],
    )

    _assert_clean_success(result, canonical_json_output(report))


def test_unknown_retrieval_succeeds_but_watch_is_unresolved(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    report = make_report(Classification.UNKNOWN)
    _install_client(monkeypatch, report=report)

    retrieved = _RUNNER.invoke(
        app,
        ["get", "investigation-7", "--output", "json"],
    )
    watched = _RUNNER.invoke(
        app,
        ["watch", "investigation-7", "--output", "json"],
    )

    assert retrieved.exit_code == 0
    assert watched.exit_code == 6
    assert retrieved.stdout_bytes == canonical_json_output(report)
    assert watched.stdout_bytes == canonical_json_output(report)
    assert retrieved.stderr_bytes == b""
    assert watched.stderr_bytes == b""


def test_explicit_denied_action_returns_policy_refusal(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    report = make_report(Classification.COMMITTED)
    _install_client(monkeypatch, report=report)

    result = _RUNNER.invoke(
        app,
        [
            "watch",
            "investigation-7",
            "--output",
            "json",
            "--require-action",
            "retry",
        ],
    )

    assert result.exit_code == 7
    assert result.stdout_bytes == canonical_json_output(report)
    assert result.stderr_bytes == b""


@pytest.mark.parametrize(
    ("failure", "exit_code", "message"),
    (
        (InvalidRequestError(), 2, "The input is invalid.\n"),
        (
            InvestigationNotFoundError(),
            3,
            "The requested investigation was not found.\n",
        ),
        (
            InvestigationConflictError(),
            4,
            "The investigation identity conflicts with an existing envelope.\n",
        ),
        (ServiceUnavailableError(), 5, "The service is unavailable.\n"),
        (RemoteInternalError(), 5, "The service is unavailable.\n"),
        (RemoteProtocolError(), 5, "The service is unavailable.\n"),
        (TransportError(), 5, "The service is unavailable.\n"),
        (
            RuntimeError("private-failure-sentinel"),
            1,
            "The command could not be completed.\n",
        ),
    ),
)
def test_client_failures_have_stable_exits_and_safe_stderr(
    monkeypatch: pytest.MonkeyPatch,
    failure: BaseException,
    exit_code: int,
    message: str,
) -> None:
    _install_client(monkeypatch, get_failure=failure)

    result = _RUNNER.invoke(
        app,
        ["get", "investigation-7", "--output", "json"],
    )

    assert result.exit_code == exit_code
    assert result.stdout_bytes == b""
    assert result.stderr_bytes == message.encode()
    assert b"private-failure-sentinel" not in result.stdout_bytes
    assert b"private-failure-sentinel" not in result.stderr_bytes


def test_interrupted_watch_returns_130_without_diagnostics(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _install_client(monkeypatch, events_failure=KeyboardInterrupt())

    result = _RUNNER.invoke(app, ["watch", "investigation-7"])

    assert result.exit_code == 130
    assert result.stdout_bytes == b""
    assert result.stderr_bytes == b""


def test_invalid_contract_input_is_not_echoed_or_sent(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    state = _install_client(monkeypatch)
    invalid = '{"private-input-sentinel":"value"}'

    result = _RUNNER.invoke(
        app,
        ["investigate", "--input", "-", "--output", "json"],
        input=invalid,
    )

    assert result.exit_code == 2
    assert result.stdout_bytes == b""
    assert result.stderr_bytes == b"The input is invalid.\n"
    assert b"private-input-sentinel" not in result.stderr_bytes
    assert state.base_urls == []
    assert state.creates == []


def test_invalid_required_action_is_usage_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    state = _install_client(monkeypatch)

    result = _RUNNER.invoke(
        app,
        ["report", "investigation-7", "--require-action", "not-an-action"],
    )

    assert result.exit_code == 2
    assert result.stdout_bytes == b""
    assert result.stderr_bytes == b"The input is invalid.\n"
    assert state.base_urls == []


def test_report_export_is_atomic_private_and_silent(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    report = make_report(Classification.COMMITTED)
    _install_client(monkeypatch, report=report)
    destination = tmp_path / "report.json"

    result = _RUNNER.invoke(
        app,
        ["report", "investigation-7", "--destination", str(destination)],
    )

    assert result.exit_code == 0
    assert result.stdout_bytes == b""
    assert result.stderr_bytes == b""
    assert destination.read_bytes() == canonical_json_bytes(report)
    assert stat.S_IMODE(destination.stat().st_mode) == 0o600
    assert list(tmp_path.glob(".reconcile-export-*")) == []

    repeated = _RUNNER.invoke(
        app,
        ["report", "investigation-7", "--destination", str(destination)],
    )
    assert repeated.exit_code == 2
    assert repeated.stdout_bytes == b""
    assert repeated.stderr_bytes == b"The input is invalid.\n"
    assert destination.read_bytes() == canonical_json_bytes(report)


def test_fixed_scenario_run_routes_exact_options_and_json(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    report = make_report(Classification.COMMITTED)
    calls: list[tuple[tuple[object, ...], dict[str, object]]] = []

    async def fake_run_one(*args: object, **kwargs: object) -> InvestigationReport:
        calls.append((args, kwargs))
        return report

    monkeypatch.setattr(cli_module, "run_one", fake_run_one)

    result = _RUNNER.invoke(
        app,
        [
            "scenario",
            "run",
            "storage",
            "--local",
            "--mode",
            "fixed",
            "--output",
            "json",
            "--run-id",
            "fixed-run",
            "--workspace",
            str(tmp_path),
        ],
    )

    _assert_clean_success(result, canonical_json_output(report))
    assert calls == [
        (
            (ScenarioName.STORAGE, ScenarioMode.FIXED),
            {
                "vertex_config": None,
                "workspace": str(tmp_path),
                "run_id": "fixed-run",
            },
        )
    ]


def test_fixed_scenario_suite_emits_ordered_jsonl_and_unresolved_exit(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    results = (
        make_report(Classification.COMMITTED),
        make_report(Classification.PARTIAL),
        make_report(Classification.UNKNOWN),
    )
    calls: list[tuple[tuple[object, ...], dict[str, object]]] = []

    async def fake_run_suite(
        *args: object,
        **kwargs: object,
    ) -> tuple[InvestigationReport, ...]:
        calls.append((args, kwargs))
        return results

    monkeypatch.setattr(cli_module, "run_suite", fake_run_suite)

    result = _RUNNER.invoke(
        app,
        [
            "scenario",
            "suite",
            "--local",
            "--mode",
            "fixed",
            "--output",
            "jsonl",
            "--run-id",
            "fixed-suite",
            "--workspace",
            str(tmp_path),
        ],
    )

    assert result.exit_code == 6
    assert result.stdout_bytes == b"".join(
        canonical_json_output(report) for report in results
    )
    assert result.stderr_bytes == b""
    assert calls == [
        (
            (ScenarioMode.FIXED,),
            {
                "vertex_config": None,
                "workspace": str(tmp_path),
                "run_id": "fixed-suite",
            },
        )
    ]


def test_broken_output_pipe_preserves_the_waited_product_exit(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    results = (
        make_report(Classification.COMMITTED),
        make_report(Classification.PARTIAL),
        make_report(Classification.UNKNOWN),
    )

    async def fake_run_suite(
        *_args: object,
        **_kwargs: object,
    ) -> tuple[InvestigationReport, ...]:
        return results

    monkeypatch.setattr(cli_module, "run_suite", fake_run_suite)
    monkeypatch.setattr(cli_module.sys, "stdout", _BrokenStdout())

    assert (
        main(
            [
                "scenario",
                "suite",
                "--local",
                "--mode",
                "fixed",
                "--output",
                "jsonl",
            ]
        )
        == 6
    )


def test_adaptive_scenario_requires_explicit_provider_configuration(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    for name in (
        "RECONCILE_VERTEX_PROJECT",
        "RECONCILE_VERTEX_LOCATION",
        "RECONCILE_VERTEX_MODEL",
    ):
        monkeypatch.delenv(name, raising=False)

    async def forbidden_run_one(
        *_args: object, **_kwargs: object
    ) -> InvestigationReport:
        pytest.fail("scenario execution must not start")

    monkeypatch.setattr(cli_module, "run_one", forbidden_run_one)

    result = _RUNNER.invoke(
        app,
        ["scenario", "run", "storage", "--local", "--mode", "adaptive"],
    )

    assert result.exit_code == 2
    assert result.stdout_bytes == b""
    assert result.stderr_bytes == b"The input is invalid.\n"


def test_scenario_requires_explicit_local_acknowledgement(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def forbidden_run_one(
        *_args: object, **_kwargs: object
    ) -> InvestigationReport:
        pytest.fail("scenario execution must not start")

    monkeypatch.setattr(cli_module, "run_one", forbidden_run_one)

    result = _RUNNER.invoke(app, ["scenario", "run", "storage"])

    assert result.exit_code == 2
    assert result.stdout_bytes == b""
    assert result.stderr_bytes == b"The input is invalid.\n"
