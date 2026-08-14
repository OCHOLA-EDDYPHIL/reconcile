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
    Classification,
    ContractError,
    ExecutionEnvelope,
    InvestigationComparisonRecord,
    InvestigationReport,
    RequestedAction,
    decode_contract,
)
from reconcile.interfaces.api_client import (
    InvalidRequestError,
    InvestigationApiClient,
    InvestigationConflictError,
    InvestigationNotFoundError,
    RemoteInternalError,
    RemoteProtocolError,
    ServiceUnavailableError,
    TransportError,
)
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
    help="Run the isolated canonical local scenarios.",
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
