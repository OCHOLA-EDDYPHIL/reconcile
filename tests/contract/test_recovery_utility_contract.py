"""Public recovery utility v2 schema guarantees."""

from __future__ import annotations

import json

import pytest

from reconcile.contracts import (
    RECOVERY_POLICY_COMPARISON_VERSION,
    RECOVERY_QUALIFICATION_RESULTS_VERSION,
    RECOVERY_UTILITY_REPORT_VERSION,
    RecoveryPolicyComparison,
    RecoveryQualificationResults,
    RecoveryUtilityReport,
)
from scripts.generate_contract_schemas import V2_PUBLIC_SCHEMAS, generated_artifacts

pytestmark = pytest.mark.contract


def test_recovery_utility_has_an_additive_v2_schema() -> None:
    assert V2_PUBLIC_SCHEMAS["recovery-utility-report"] is RecoveryUtilityReport
    path = next(
        item
        for item in generated_artifacts()
        if item.as_posix() == "schemas/v2/recovery-utility-report.schema.json"
    )
    schema = json.loads(path.read_text(encoding="utf-8"))

    assert path.read_text(encoding="utf-8") == generated_artifacts()[path]
    assert schema["additionalProperties"] is False
    assert schema["properties"]["schema_version"]["const"] == (
        RECOVERY_UTILITY_REPORT_VERSION
    )
    assert schema["properties"]["execution_basis"]["const"] == (
        "deterministic-local-scripted"
    )
    lane = schema["$defs"]["RecoveryUtilityLaneResult"]["properties"]
    assert "comparison_policy_sha256" in lane
    assert "simulated_controller_ticks_to_sufficient_evidence" in lane
    assert "time_to_sufficient_evidence_ms" not in lane


def test_recovery_utility_does_not_change_accepted_v1_contracts() -> None:
    assert RECOVERY_POLICY_COMPARISON_VERSION.endswith("/v1")
    assert RECOVERY_QUALIFICATION_RESULTS_VERSION.endswith("/v1")
    assert "stable-identity-precondition" not in json.dumps(
        RecoveryPolicyComparison.model_json_schema()
    )
    assert "stable-identity-precondition" not in json.dumps(
        RecoveryQualificationResults.model_json_schema()
    )
