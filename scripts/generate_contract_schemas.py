"""Generate the checked-in JSON Schema artifacts for public contracts."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from pydantic import BaseModel

from reconcile.contracts import (
    ActionGateResult,
    ActionPermit,
    AdaptivePlannerInput,
    AdaptivePlannerOutput,
    AmbiguityWitness,
    ApiError,
    EvidenceDecision,
    ExecutionEnvelope,
    ExpectedEffect,
    GeminiHypothesis,
    InvestigationComparisonRecord,
    InvestigationEvent,
    InvestigationReport,
    NormalizedEvidence,
    ObservationCapability,
    ProbeRequest,
    QualificationCaseResult,
    QualificationDisposition,
    QualificationResultSet,
    QualificationSuiteManifest,
    QualificationSummary,
    RecoveryActionScope,
    RecoveryChain,
    RecoveryLaunchPermit,
    RecoveryRunEvent,
    RecoveryRunRequest,
    RecoveryRunSnapshot,
    ScenarioCleanupRequest,
    ScenarioCleanupResult,
    ScenarioFaultTrace,
    ScenarioOperationalStatus,
    ScenarioRunRequest,
    ScenarioRunResult,
    VerifiedCertificate,
)

SCHEMA_DIRECTORY = Path("schemas/v1")
V2_SCHEMA_DIRECTORY = Path("schemas/v2")
PUBLIC_SCHEMAS: dict[str, type[BaseModel]] = {
    "action-permit": ActionPermit,
    "action-gate-result": ActionGateResult,
    "adaptive-planner-input": AdaptivePlannerInput,
    "adaptive-planner-output": AdaptivePlannerOutput,
    "ambiguity-witness": AmbiguityWitness,
    "error": ApiError,
    "evidence-decision": EvidenceDecision,
    "execution-envelope": ExecutionEnvelope,
    "expected-effect": ExpectedEffect,
    "gemini-hypothesis": GeminiHypothesis,
    "investigation-comparison-record": InvestigationComparisonRecord,
    "investigation-event": InvestigationEvent,
    "investigation-report": InvestigationReport,
    "normalized-evidence": NormalizedEvidence,
    "observation-capability": ObservationCapability,
    "probe-request": ProbeRequest,
    "qualification-case-result": QualificationCaseResult,
    "qualification-disposition": QualificationDisposition,
    "qualification-result-set": QualificationResultSet,
    "qualification-suite-manifest": QualificationSuiteManifest,
    "qualification-summary": QualificationSummary,
    "recovery-chain": RecoveryChain,
    "recovery-launch-permit": RecoveryLaunchPermit,
    "recovery-run-event": RecoveryRunEvent,
    "recovery-run-request": RecoveryRunRequest,
    "recovery-run-snapshot": RecoveryRunSnapshot,
    "scenario-cleanup-request": ScenarioCleanupRequest,
    "scenario-cleanup-result": ScenarioCleanupResult,
    "scenario-fault-trace": ScenarioFaultTrace,
    "scenario-run-request": ScenarioRunRequest,
    "scenario-run-result": ScenarioRunResult,
    "verified-certificate": VerifiedCertificate,
}
V2_PUBLIC_SCHEMAS: dict[str, type[BaseModel]] = {
    "recovery-action-scope": RecoveryActionScope,
    "scenario-operational-status": ScenarioOperationalStatus,
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
    v1 = {
        SCHEMA_DIRECTORY / f"{name}.schema.json": render_schema(model)
        for name, model in PUBLIC_SCHEMAS.items()
    }
    v2 = {
        V2_SCHEMA_DIRECTORY / f"{name}.schema.json": render_schema(model)
        for name, model in V2_PUBLIC_SCHEMAS.items()
    }
    return {**v1, **v2}


def check_artifacts() -> bool:
    return all(
        path.is_file() and path.read_text(encoding="utf-8") == contents
        for path, contents in generated_artifacts().items()
    )


def write_artifacts() -> None:
    for path, contents in generated_artifacts().items():
        path.parent.mkdir(parents=True, exist_ok=True)
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
