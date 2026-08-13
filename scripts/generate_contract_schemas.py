"""Generate the checked-in JSON Schema artifacts for public v1 contracts."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from pydantic import BaseModel

from reconcile.contracts import (
    ActionGateResult,
    EvidenceDecision,
    ExecutionEnvelope,
    ExpectedEffect,
    InvestigationReport,
    NormalizedEvidence,
    ObservationCapability,
    ProbeRequest,
    ScenarioCleanupRequest,
    ScenarioCleanupResult,
    ScenarioFaultTrace,
    ScenarioRunRequest,
    ScenarioRunResult,
)

SCHEMA_DIRECTORY = Path("schemas/v1")
PUBLIC_SCHEMAS: dict[str, type[BaseModel]] = {
    "action-gate-result": ActionGateResult,
    "evidence-decision": EvidenceDecision,
    "execution-envelope": ExecutionEnvelope,
    "expected-effect": ExpectedEffect,
    "investigation-report": InvestigationReport,
    "normalized-evidence": NormalizedEvidence,
    "observation-capability": ObservationCapability,
    "probe-request": ProbeRequest,
    "scenario-cleanup-request": ScenarioCleanupRequest,
    "scenario-cleanup-result": ScenarioCleanupResult,
    "scenario-fault-trace": ScenarioFaultTrace,
    "scenario-run-request": ScenarioRunRequest,
    "scenario-run-result": ScenarioRunResult,
}


def render_schema(model: type[BaseModel]) -> str:
    return (
        json.dumps(
            model.model_json_schema(mode="validation"),
            ensure_ascii=False,
            indent=2,
            sort_keys=True,
        )
        + "\n"
    )


def generated_artifacts() -> dict[Path, str]:
    return {
        SCHEMA_DIRECTORY / f"{name}.schema.json": render_schema(model)
        for name, model in PUBLIC_SCHEMAS.items()
    }


def check_artifacts() -> bool:
    return all(
        path.is_file() and path.read_text(encoding="utf-8") == contents
        for path, contents in generated_artifacts().items()
    )


def write_artifacts() -> None:
    SCHEMA_DIRECTORY.mkdir(parents=True, exist_ok=True)
    for path, contents in generated_artifacts().items():
        path.write_text(contents, encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true")
    arguments = parser.parse_args()
    if arguments.check:
        return 0 if check_artifacts() else 1
    write_artifacts()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
