"""Automation-first command line boundary for RECONCILE."""

from __future__ import annotations

import asyncio
import os
import sys
from enum import StrEnum
from typing import Annotated

import typer

from reconcile.adk_planner import VertexAdcPlannerConfig
from reconcile.cli_core import (
    CliCoreError,
    ExitCode,
    FailureCategory,
    canonical_json_output,
    export_report,
    load_exact_input,
    public_failure,
    render_human_event,
    render_human_report,
    render_human_status,
    waited_report_exit_code,
)
from reconcile.contracts import (
    MAX_SCENARIO_RUN_EVENTS,
    SCENARIO_LAUNCH_REQUEST_VERSION,
    Classification,
    ContractError,
    ExecutionEnvelope,
    InvestigationComparisonRecord,
    InvestigationReport,
    RequestedAction,
    ScenarioLaunchName,
    ScenarioLaunchRequest,
    ScenarioOperationalStatus,
    ScenarioRunEvent,
    ScenarioRunLifecycle,
    ScenarioRunMode,
    ScenarioRunSnapshot,
    decode_contract,
)
from reconcile.interfaces.api_client import (
    InvalidRequestError,
    InvestigationApiClient,
    InvestigationApiClientError,
    InvestigationConflictError,
    InvestigationNotFoundError,
    RemoteInternalError,
    RemoteProtocolError,
    ServiceUnavailableError,
    TransportError,
)
from reconcile.interfaces.operator_api_client import OperatorApiClient
from reconcile.scenarios.service import (
    ScenarioMode,
    ScenarioName,
    ScenarioWorkflowError,
    ScenarioWorkflowErrorCategory,
    run_one,
    run_suite,
)

_DEFAULT_API_URL = "http://127.0.0.1:8000"
_OUTPUT_BROKEN = False
_API_URL_OPTION = typer.Option(
    "--api-url",
    envvar="RECONCILE_API_URL",
    help="Loopback HTTP or remote HTTPS API base URL.",
)


class StructuredOutput(StrEnum):
    HUMAN = "human"
    JSON = "json"


class EventOutput(StrEnum):
    HUMAN = "human"
    JSONL = "jsonl"


app = typer.Typer(
    name="reconcile",
    add_completion=False,
    invoke_without_command=True,
    no_args_is_help=False,
    help=(
        "RECONCILE automation interface. Exit codes: 0 success, 1 internal, "
        "2 invalid, 3 missing, 4 conflict, 5 service, 6 unresolved, "
        "7 policy refusal, 130 interrupted watch."
    ),
)
scenario_app = typer.Typer(
    add_completion=False,
    invoke_without_command=True,
    no_args_is_help=True,
    help="Operate canonical scenarios locally or through the API.",
)
app.add_typer(scenario_app, name="scenario")


@app.callback()
def root() -> None:
    """RECONCILE automation interface."""

    global _OUTPUT_BROKEN
    _OUTPUT_BROKEN = False


def _emit(payload: bytes) -> None:
    global _OUTPUT_BROKEN
    if _OUTPUT_BROKEN:
        return
    try:
        stream = sys.stdout.buffer
        stream.write(payload)
        stream.flush()
    except BrokenPipeError:
        _OUTPUT_BROKEN = True
        try:
            null_descriptor = os.open(os.devnull, os.O_WRONLY)
            try:
                os.dup2(null_descriptor, sys.stdout.fileno())
            finally:
                os.close(null_descriptor)
        except Exception:
            pass


def _fail(category: FailureCategory) -> None:
    failure = public_failure(category)
    typer.echo(failure.message, err=True)
    raise typer.Exit(code=failure.exit_code)


def _client_failure(error: Exception) -> None:
    if isinstance(error, InvalidRequestError):
        _fail(FailureCategory.INVALID_INPUT)
    if isinstance(error, InvestigationNotFoundError):
        _fail(FailureCategory.NOT_FOUND)
    if isinstance(error, InvestigationConflictError):
        _fail(FailureCategory.CONFLICT)
    if isinstance(
        error,
        (
            ServiceUnavailableError,
            RemoteInternalError,
            RemoteProtocolError,
            TransportError,
        ),
    ):
        _fail(FailureCategory.SERVICE_UNAVAILABLE)
    _fail(FailureCategory.INTERNAL_FAILURE)


def _scenario_failure(error: ScenarioWorkflowError) -> None:
    if error.category is ScenarioWorkflowErrorCategory.INVALID_CONFIGURATION:
        _fail(FailureCategory.INVALID_INPUT)
    if error.category in {
        ScenarioWorkflowErrorCategory.PROVIDER_FAILED,
        ScenarioWorkflowErrorCategory.SCENARIO_EXECUTION_FAILED,
        ScenarioWorkflowErrorCategory.CLEANUP_FAILED,
    }:
        _fail(FailureCategory.SERVICE_UNAVAILABLE)
    _fail(FailureCategory.INTERNAL_FAILURE)


def _parse_action(value: str | None) -> RequestedAction | None:
    if value is None:
        return None
    try:
        return RequestedAction(value.upper())
    except (AttributeError, ValueError):
        _fail(FailureCategory.INVALID_INPUT)


def _write_report(report: InvestigationReport, output: StructuredOutput) -> None:
    if output is StructuredOutput.JSON:
        _emit(canonical_json_output(report))
    else:
        _emit(render_human_report(report))


def _write_comparison(
    comparison: InvestigationComparisonRecord,
    output: StructuredOutput,
) -> None:
    if output is StructuredOutput.JSON:
        _emit(canonical_json_output(comparison))
        return
    adaptive = comparison.adaptive
    lines = (
        f"Comparison: {comparison.comparison_id}",
        f"Scenario: {comparison.scenario.name}@{comparison.scenario.version}",
        f"Expected: {comparison.preregistered_expectation.expected_classification.value}",
        f"Fixed classification: {comparison.baseline.classification.value}",
        f"Fixed probes: {comparison.baseline.executed_probe_count}",
        (
            "Adaptive classification: unavailable"
            if adaptive is None
            else f"Adaptive classification: {adaptive.classification.value}"
        ),
        (
            "Adaptive probes: unavailable"
            if adaptive is None
            else f"Adaptive probes: {adaptive.executed_probe_count}"
        ),
    )
    _emit(("\n".join(lines) + "\n").encode("utf-8"))


def _write_scenario_snapshot(
    snapshot: ScenarioRunSnapshot,
    output: StructuredOutput,
) -> None:
    if type(snapshot) is not ScenarioRunSnapshot:
        _fail(FailureCategory.INTERNAL_FAILURE)
    if output is StructuredOutput.JSON:
        _emit(canonical_json_output(snapshot))
        return
    lines = [
        f"Investigation: {snapshot.investigation_id}",
        f"Launch: {snapshot.launch_id}",
        f"Scenario: {snapshot.scenario.value}",
        f"Mode: {snapshot.mode.value}",
        f"Lifecycle: {snapshot.lifecycle.value}",
        f"Cursor: {snapshot.event_cursor}",
    ]
    if snapshot.report is not None:
        report = snapshot.report
        lines.extend(
            (
                f"Classification: {report.classification.value}",
                f"Missing evidence groups: {len(report.missing_evidence)}",
            )
        )
        if report.route_provenance is not None:
            route = report.route_provenance
            lines.extend(
                (
                    f"Hybrid route policy: {route.policy_version}",
                    f"Hybrid route: {route.route.value}",
                    f"Hybrid outcome: {route.outcome.value}",
                    f"Planner invoked: {str(route.planner_invoked).lower()}",
                    "Fixed connector invoked: "
                    f"{str(route.fixed_connector_invoked).lower()}",
                    "Provider cleanup failure: "
                    f"{str(route.provider_cleanup_failure).lower()}",
                )
            )
        lines.extend(
            f"Action {gate.requested_action.value}: "
            f"{'allowed' if gate.allowed else 'denied'}"
            for gate in report.action_gate
        )
    elif snapshot.comparison is not None:
        comparison = snapshot.comparison
        lines.extend(
            (
                f"Fixed classification: {comparison.baseline.classification.value}",
                (
                    "Adaptive classification: unavailable"
                    if comparison.adaptive is None
                    else (
                        "Adaptive classification: "
                        f"{comparison.adaptive.classification.value}"
                    )
                ),
            )
        )
    elif snapshot.failure_category is not None:
        lines.append(f"Failure: {snapshot.failure_category.value}")
    _emit(("\n".join(lines) + "\n").encode("utf-8"))


def _write_operational_status(
    status: ScenarioOperationalStatus,
    output: StructuredOutput,
) -> None:
    if type(status) is not ScenarioOperationalStatus:
        _fail(FailureCategory.INTERNAL_FAILURE)
    if output is StructuredOutput.JSON:
        _emit(canonical_json_output(status))
        return
    lines = (
        f"Operational investigation: {status.investigation_id}",
        f"Operational revision: {status.revision}",
        f"Mutation: {status.mutation_state.value}",
        f"Investigation: {status.investigation_state.value}",
        f"Cleanup: {status.cleanup_state.value}",
        f"Recovery: {status.recovery_state.value}",
        f"Operational updated: {status.updated_at.isoformat()}",
    )
    _emit(("\n".join(lines) + "\n").encode("utf-8"))


def _write_scenario_event(event: ScenarioRunEvent, output: EventOutput) -> None:
    if type(event) is not ScenarioRunEvent:
        _fail(FailureCategory.INTERNAL_FAILURE)
    if output is EventOutput.JSONL:
        _emit(canonical_json_output(event))
        return
    _emit(
        (
            f"Cursor: {event.cursor}\n"
            f"Type: {event.type.value}\n"
            f"Occurred: {event.occurred_at.isoformat()}\n"
        ).encode()
    )


def _validate_scenario_views(
    snapshot: ScenarioRunSnapshot,
    status: ScenarioOperationalStatus,
) -> None:
    if (
        type(snapshot) is not ScenarioRunSnapshot
        or type(status) is not ScenarioOperationalStatus
        or snapshot.investigation_id != status.investigation_id
        or snapshot.launch_id != status.launch_id
        or snapshot.scenario is not status.scenario
        or snapshot.mode is not status.mode
    ):
        raise RemoteProtocolError() from None


def _scenario_terminal_exit_code(snapshot: ScenarioRunSnapshot) -> ExitCode:
    if snapshot.lifecycle is ScenarioRunLifecycle.COMPLETED:
        if snapshot.report is not None:
            classification = snapshot.report.classification
            return (
                ExitCode.SUCCESS
                if classification
                in {Classification.COMMITTED, Classification.NOT_COMMITTED}
                else ExitCode.UNRESOLVED
            )
        if snapshot.comparison is not None:
            classifications = [snapshot.comparison.baseline.classification]
            if snapshot.comparison.adaptive is not None:
                classifications.append(snapshot.comparison.adaptive.classification)
            definitive = {Classification.COMMITTED, Classification.NOT_COMMITTED}
            return (
                ExitCode.SUCCESS
                if all(item in definitive for item in classifications)
                else ExitCode.UNRESOLVED
            )
        raise RemoteProtocolError() from None
    if snapshot.lifecycle in {
        ScenarioRunLifecycle.FAILED,
        ScenarioRunLifecycle.CANCELLED,
    }:
        return ExitCode.SERVICE_UNAVAILABLE
    raise RemoteProtocolError() from None


def _result_exit_code(
    result: InvestigationReport | InvestigationComparisonRecord,
) -> ExitCode:
    if type(result) is InvestigationReport:
        return waited_report_exit_code(result)
    if type(result) is InvestigationComparisonRecord:
        classifications = [result.baseline.classification]
        if result.adaptive is not None:
            classifications.append(result.adaptive.classification)
        definitive = {Classification.COMMITTED, Classification.NOT_COMMITTED}
        return (
            ExitCode.SUCCESS
            if all(item in definitive for item in classifications)
            else ExitCode.UNRESOLVED
        )
    _fail(FailureCategory.INTERNAL_FAILURE)


def _vertex_config(mode: ScenarioMode) -> VertexAdcPlannerConfig | None:
    if mode is ScenarioMode.FIXED:
        return None
    values = (
        os.environ.get("RECONCILE_VERTEX_PROJECT"),
        os.environ.get("RECONCILE_VERTEX_LOCATION"),
        os.environ.get("RECONCILE_VERTEX_MODEL"),
    )
    if all(value is None for value in values):
        if mode is ScenarioMode.ADAPTIVE:
            return None
        _fail(FailureCategory.INVALID_INPUT)
    if any(value is None or not value for value in values):
        _fail(FailureCategory.INVALID_INPUT)
    try:
        return VertexAdcPlannerConfig(
            project=values[0],  # type: ignore[arg-type]
            location=values[1],  # type: ignore[arg-type]
            model=values[2],  # type: ignore[arg-type]
            timeout_seconds=3.75,
            max_output_tokens=1_024,
        )
    except (TypeError, ValueError):
        _fail(FailureCategory.INVALID_INPUT)


@app.command("investigate")
def investigate(
    input_source: Annotated[
        str,
        typer.Option("--input", help="Versioned envelope file or '-' for stdin."),
    ],
    output: Annotated[StructuredOutput, typer.Option("--output")] = (
        StructuredOutput.HUMAN
    ),
    api_url: Annotated[str, _API_URL_OPTION] = _DEFAULT_API_URL,
) -> None:
    """Create one investigation from an exact versioned envelope."""

    try:
        envelope = decode_contract(load_exact_input(input_source), ExecutionEnvelope)
        with InvestigationApiClient(api_url) as client:
            report = client.create(envelope)
        if output is StructuredOutput.JSON:
            _emit(canonical_json_output(report))
        else:
            _emit(render_human_status(report))
    except typer.Exit:
        raise
    except CliCoreError as error:
        _fail(error.failure.category)
    except ContractError:
        _fail(FailureCategory.INVALID_INPUT)
    except Exception as error:
        _client_failure(error)


@app.command("get")
def get_investigation(
    investigation_id: str,
    output: Annotated[StructuredOutput, typer.Option("--output")] = (
        StructuredOutput.HUMAN
    ),
    api_url: Annotated[str, _API_URL_OPTION] = _DEFAULT_API_URL,
) -> None:
    """Retrieve one current investigation report."""

    try:
        with InvestigationApiClient(api_url) as client:
            report = client.get(investigation_id)
        _write_report(report, output)
    except typer.Exit:
        raise
    except CliCoreError as error:
        _fail(error.failure.category)
    except Exception as error:
        _client_failure(error)


@app.command("status")
def status(
    investigation_id: str,
    output: Annotated[StructuredOutput, typer.Option("--output")] = (
        StructuredOutput.HUMAN
    ),
    api_url: Annotated[str, _API_URL_OPTION] = _DEFAULT_API_URL,
) -> None:
    """Retrieve current lifecycle and deterministic state."""

    try:
        with InvestigationApiClient(api_url) as client:
            report = client.get(investigation_id)
        if output is StructuredOutput.JSON:
            _emit(canonical_json_output(report))
        else:
            _emit(render_human_status(report))
    except typer.Exit:
        raise
    except CliCoreError as error:
        _fail(error.failure.category)
    except Exception as error:
        _client_failure(error)


@app.command("events")
def events(
    investigation_id: str,
    output: Annotated[EventOutput, typer.Option("--output")] = EventOutput.HUMAN,
    after: Annotated[int, typer.Option("--after", min=0, max=137)] = 0,
    api_url: Annotated[str, _API_URL_OPTION] = _DEFAULT_API_URL,
) -> None:
    """Stream validated investigation events after an exclusive cursor."""

    try:
        with InvestigationApiClient(api_url) as client:
            for event in client.events(investigation_id, after=after):
                if output is EventOutput.JSONL:
                    _emit(canonical_json_output(event))
                else:
                    _emit(render_human_event(event))
    except typer.Exit:
        raise
    except KeyboardInterrupt:
        raise typer.Exit(code=ExitCode.INTERRUPTED) from None
    except CliCoreError as error:
        _fail(error.failure.category)
    except Exception as error:
        _client_failure(error)


@app.command("report")
def report(
    investigation_id: str,
    output: Annotated[StructuredOutput, typer.Option("--output")] = (
        StructuredOutput.HUMAN
    ),
    destination: Annotated[
        str | None,
        typer.Option("--destination", help="New file path, or '-' for stdout."),
    ] = None,
    require_action: Annotated[
        str | None,
        typer.Option("--require-action", help="Assert one deterministic action gate."),
    ] = None,
    api_url: Annotated[str, _API_URL_OPTION] = _DEFAULT_API_URL,
) -> None:
    """Inspect or atomically export one current report."""

    try:
        action = _parse_action(require_action)
        with InvestigationApiClient(api_url) as client:
            current = client.get(investigation_id)
        if destination is None:
            _write_report(current, output)
        elif destination == "-":
            _emit(canonical_json_output(current))
        else:
            export_report(current, destination)
        if action is not None:
            raise typer.Exit(
                code=waited_report_exit_code(current, require_action=action)
            )
    except typer.Exit:
        raise
    except CliCoreError as error:
        _fail(error.failure.category)
    except Exception as error:
        _client_failure(error)


@app.command("watch")
def watch(
    investigation_id: str,
    output: Annotated[StructuredOutput, typer.Option("--output")] = (
        StructuredOutput.HUMAN
    ),
    after: Annotated[int, typer.Option("--after", min=0, max=137)] = 0,
    require_action: Annotated[
        str | None,
        typer.Option("--require-action", help="Assert one deterministic action gate."),
    ] = None,
    api_url: Annotated[str, _API_URL_OPTION] = _DEFAULT_API_URL,
) -> None:
    """Resume events, confirm the terminal report, and return its product state."""

    try:
        action = _parse_action(require_action)
        with InvestigationApiClient(api_url) as client:
            for event in client.events(investigation_id, after=after):
                if output is StructuredOutput.HUMAN:
                    _emit(render_human_event(event))
            current = client.get(investigation_id)
        if output is StructuredOutput.JSON:
            _emit(canonical_json_output(current))
        else:
            _emit(render_human_report(current))
        raise typer.Exit(code=waited_report_exit_code(current, require_action=action))
    except typer.Exit:
        raise
    except KeyboardInterrupt:
        raise typer.Exit(code=ExitCode.INTERRUPTED) from None
    except CliCoreError as error:
        _fail(error.failure.category)
    except Exception as error:
        _client_failure(error)


def _require_local(local: bool) -> None:
    if not local:
        _fail(FailureCategory.INVALID_INPUT)


async def _remote_scenario_launch(
    *,
    api_url: str,
    request: ScenarioLaunchRequest,
) -> ScenarioRunSnapshot:
    async with OperatorApiClient(api_url) as client:
        launched = await client.launch(request)
    return launched.snapshot


@scenario_app.command("launch")
def scenario_launch(
    launch_id: str,
    scenario: ScenarioLaunchName,
    mode: Annotated[ScenarioRunMode, typer.Option("--mode")] = (ScenarioRunMode.FIXED),
    output: Annotated[StructuredOutput, typer.Option("--output")] = (
        StructuredOutput.HUMAN
    ),
    api_url: Annotated[str, _API_URL_OPTION] = _DEFAULT_API_URL,
) -> None:
    """Submit or exactly replay one durable remote scenario launch."""

    try:
        request = ScenarioLaunchRequest(
            schema_version=SCENARIO_LAUNCH_REQUEST_VERSION,
            launch_id=launch_id,
            scenario=scenario,
            mode=mode,
        )
        snapshot = asyncio.run(
            _remote_scenario_launch(api_url=api_url, request=request)
        )
        _write_scenario_snapshot(snapshot, output)
    except typer.Exit:
        raise
    except KeyboardInterrupt:
        raise typer.Exit(code=ExitCode.INTERRUPTED) from None
    except (ContractError, TypeError, ValueError):
        _fail(FailureCategory.INVALID_INPUT)
    except Exception as error:
        _client_failure(error)


async def _remote_scenario_status(
    *,
    api_url: str,
    investigation_id: str,
) -> ScenarioOperationalStatus:
    async with OperatorApiClient(api_url) as client:
        return await client.get_operational_status(investigation_id)


@scenario_app.command("status")
def scenario_status(
    investigation_id: str,
    output: Annotated[StructuredOutput, typer.Option("--output")] = (
        StructuredOutput.HUMAN
    ),
    api_url: Annotated[str, _API_URL_OPTION] = _DEFAULT_API_URL,
) -> None:
    """Retrieve remote mutation, investigation, cleanup, and recovery state."""

    try:
        status = asyncio.run(
            _remote_scenario_status(
                api_url=api_url,
                investigation_id=investigation_id,
            )
        )
        _write_operational_status(status, output)
    except typer.Exit:
        raise
    except KeyboardInterrupt:
        raise typer.Exit(code=ExitCode.INTERRUPTED) from None
    except Exception as error:
        _client_failure(error)


async def _remote_scenario_events(
    *,
    api_url: str,
    investigation_id: str,
    after: int,
    output: EventOutput,
) -> None:
    async with OperatorApiClient(api_url) as client:
        async for event in client.events(investigation_id, after=after):
            _write_scenario_event(event, output)


@scenario_app.command("events")
def scenario_events(
    investigation_id: str,
    output: Annotated[EventOutput, typer.Option("--output")] = EventOutput.HUMAN,
    after: Annotated[
        int,
        typer.Option("--after", min=0, max=MAX_SCENARIO_RUN_EVENTS),
    ] = 0,
    api_url: Annotated[str, _API_URL_OPTION] = _DEFAULT_API_URL,
) -> None:
    """Stream canonical v1 remote scenario events after an exclusive cursor."""

    try:
        asyncio.run(
            _remote_scenario_events(
                api_url=api_url,
                investigation_id=investigation_id,
                after=after,
                output=output,
            )
        )
    except typer.Exit:
        raise
    except KeyboardInterrupt:
        raise typer.Exit(code=ExitCode.INTERRUPTED) from None
    except Exception as error:
        _client_failure(error)


async def _remote_scenario_watch(
    *,
    api_url: str,
    investigation_id: str,
    after: int,
    output: StructuredOutput,
) -> tuple[ScenarioRunSnapshot, ScenarioOperationalStatus | None]:
    async with OperatorApiClient(api_url) as client:
        async for event in client.events(investigation_id, after=after):
            if output is StructuredOutput.HUMAN:
                _write_scenario_event(event, EventOutput.HUMAN)
        snapshot = await client.get_snapshot(investigation_id)
        status = None
        if output is StructuredOutput.HUMAN:
            try:
                status = await client.get_operational_status(investigation_id)
                _validate_scenario_views(snapshot, status)
            except InvestigationApiClientError:
                status = None
    return snapshot, status


@scenario_app.command("watch")
def scenario_watch(
    investigation_id: str,
    output: Annotated[StructuredOutput, typer.Option("--output")] = (
        StructuredOutput.HUMAN
    ),
    after: Annotated[
        int,
        typer.Option("--after", min=0, max=MAX_SCENARIO_RUN_EVENTS),
    ] = 0,
    api_url: Annotated[str, _API_URL_OPTION] = _DEFAULT_API_URL,
) -> None:
    """Resume v1 events and return the authoritative terminal v1 result."""

    try:
        snapshot, operational_status = asyncio.run(
            _remote_scenario_watch(
                api_url=api_url,
                investigation_id=investigation_id,
                after=after,
                output=output,
            )
        )
        if output is StructuredOutput.JSON:
            _write_scenario_snapshot(snapshot, output)
        else:
            if operational_status is None:
                _emit(b"Operational status: unavailable\n")
            else:
                _write_operational_status(operational_status, output)
            _write_scenario_snapshot(snapshot, output)
        raise typer.Exit(code=_scenario_terminal_exit_code(snapshot))
    except typer.Exit:
        raise
    except KeyboardInterrupt:
        raise typer.Exit(code=ExitCode.INTERRUPTED) from None
    except CliCoreError as error:
        _fail(error.failure.category)
    except Exception as error:
        _client_failure(error)


@scenario_app.command("run")
def scenario_run(
    scenario: ScenarioName,
    mode: Annotated[ScenarioMode, typer.Option("--mode")] = ScenarioMode.FIXED,
    output: Annotated[StructuredOutput, typer.Option("--output")] = (
        StructuredOutput.HUMAN
    ),
    local: Annotated[
        bool,
        typer.Option("--local", help="Acknowledge isolated one-shot local execution."),
    ] = False,
    run_id: Annotated[str | None, typer.Option("--run-id")] = None,
    workspace: Annotated[str | None, typer.Option("--workspace")] = None,
) -> None:
    """Run one canonical local scenario."""

    try:
        _require_local(local)
        result = asyncio.run(
            run_one(
                scenario,
                mode,
                vertex_config=_vertex_config(mode),
                workspace=workspace,
                run_id=run_id,
            )
        )
        if type(result) is InvestigationReport:
            _write_report(result, output)
        elif type(result) is InvestigationComparisonRecord:
            _write_comparison(result, output)
        else:
            _fail(FailureCategory.INTERNAL_FAILURE)
        raise typer.Exit(code=_result_exit_code(result))
    except typer.Exit:
        raise
    except KeyboardInterrupt:
        raise typer.Exit(code=ExitCode.INTERRUPTED) from None
    except CliCoreError as error:
        _fail(error.failure.category)
    except ScenarioWorkflowError as error:
        _scenario_failure(error)
    except Exception:
        _fail(FailureCategory.INTERNAL_FAILURE)


@scenario_app.command("suite")
def scenario_suite(
    mode: Annotated[ScenarioMode, typer.Option("--mode")] = ScenarioMode.FIXED,
    output: Annotated[EventOutput, typer.Option("--output")] = EventOutput.HUMAN,
    local: Annotated[
        bool,
        typer.Option("--local", help="Acknowledge isolated one-shot local execution."),
    ] = False,
    run_id: Annotated[str | None, typer.Option("--run-id")] = None,
    workspace: Annotated[str | None, typer.Option("--workspace")] = None,
) -> None:
    """Run the ordered three-scenario local suite."""

    try:
        _require_local(local)
        results = asyncio.run(
            run_suite(
                mode,
                vertex_config=_vertex_config(mode),
                workspace=workspace,
                run_id=run_id,
            )
        )
        exit_code = ExitCode.SUCCESS
        structured_output = (
            StructuredOutput.JSON
            if output is EventOutput.JSONL
            else StructuredOutput.HUMAN
        )
        for result in results:
            if type(result) is InvestigationReport:
                _write_report(result, structured_output)
            elif type(result) is InvestigationComparisonRecord:
                _write_comparison(result, structured_output)
            else:
                _fail(FailureCategory.INTERNAL_FAILURE)
            exit_code = max(exit_code, _result_exit_code(result))
        raise typer.Exit(code=exit_code)
    except typer.Exit:
        raise
    except KeyboardInterrupt:
        raise typer.Exit(code=ExitCode.INTERRUPTED) from None
    except CliCoreError as error:
        _fail(error.failure.category)
    except ScenarioWorkflowError as error:
        _scenario_failure(error)
    except Exception:
        _fail(FailureCategory.INTERNAL_FAILURE)


def main(argv: list[str] | None = None) -> int:
    """Run the command while preserving a process-style return code."""

    try:
        app(args=argv, prog_name="reconcile")
    except SystemExit as error:
        return int(error.code or 0)
    return 0


__all__ = ["EventOutput", "StructuredOutput", "app", "main"]
