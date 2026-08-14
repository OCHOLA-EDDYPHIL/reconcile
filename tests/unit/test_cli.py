from __future__ import annotations

import stat
from dataclasses import dataclass, field
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
    Classification,
    ExecutionEnvelope,
    InvestigationEvent,
    InvestigationEventType,
    InvestigationReport,
    canonical_json_bytes,
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
from reconcile.scenarios.service import ScenarioMode, ScenarioName
from tests.contract._factories import (
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
