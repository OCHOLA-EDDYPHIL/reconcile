"""Strict public contract coverage for durable operational state."""

from __future__ import annotations

import json

import pytest
from jsonschema import Draft202012Validator
from pydantic import ValidationError

from reconcile.contracts import (
    SCENARIO_OPERATIONAL_STATUS_VERSION,
    RecoveryActionScope,
    RecoveryUtilityReport,
    ScenarioLaunchName,
    ScenarioOperationalCleanupState,
    ScenarioOperationalInvestigationState,
    ScenarioOperationalMutationState,
    ScenarioOperationalRecoveryState,
    ScenarioOperationalStatus,
    ScenarioRunMode,
    canonical_json_bytes,
    decode_contract,
)
from scripts.generate_contract_schemas import (
    PUBLIC_SCHEMAS,
    V2_PUBLIC_SCHEMAS,
    generated_artifacts,
)
from tests.contract._factories import NOW

pytestmark = pytest.mark.contract


def _status(**changes: object) -> ScenarioOperationalStatus:
    values: dict[str, object] = {
        "schema_version": SCENARIO_OPERATIONAL_STATUS_VERSION,
        "launch_id": "launch-7",
        "investigation_id": "investigation-7",
        "scenario": ScenarioLaunchName.STORAGE,
        "mode": ScenarioRunMode.FIXED,
        "revision": 7,
        "mutation_state": ScenarioOperationalMutationState.RECORDED,
        "investigation_state": ScenarioOperationalInvestigationState.RECORDED,
        "cleanup_state": ScenarioOperationalCleanupState.SUCCEEDED,
        "recovery_state": ScenarioOperationalRecoveryState.NOT_ESCALATED,
        "updated_at": NOW,
    }
    values.update(changes)
    return ScenarioOperationalStatus(**values)  # type: ignore[arg-type]


def test_operational_status_has_an_exact_canonical_v2_round_trip() -> None:
    status = _status()
    encoded = canonical_json_bytes(status)

    assert decode_contract(encoded, ScenarioOperationalStatus) == status
    assert canonical_json_bytes(
        decode_contract(encoded, ScenarioOperationalStatus)
    ) == (encoded)
    assert set(json.loads(encoded)) == {
        "schema_version",
        "launch_id",
        "investigation_id",
        "scenario",
        "mode",
        "revision",
        "mutation_state",
        "investigation_state",
        "cleanup_state",
        "recovery_state",
        "updated_at",
    }


def test_v2_schema_is_separate_regenerable_and_validates_the_contract() -> None:
    assert "scenario-operational-status" not in PUBLIC_SCHEMAS
    assert V2_PUBLIC_SCHEMAS == {
        "recovery-action-scope": RecoveryActionScope,
        "recovery-utility-report": RecoveryUtilityReport,
        "scenario-operational-status": ScenarioOperationalStatus,
    }
    path = next(
        item
        for item in generated_artifacts()
        if item.as_posix() == "schemas/v2/scenario-operational-status.schema.json"
    )
    schema = json.loads(path.read_text(encoding="utf-8"))

    assert path.read_text(encoding="utf-8") == generated_artifacts()[path]
    assert schema["additionalProperties"] is False
    assert schema["properties"]["schema_version"]["const"] == (
        SCENARIO_OPERATIONAL_STATUS_VERSION
    )
    Draft202012Validator(schema).validate(json.loads(canonical_json_bytes(_status())))


@pytest.mark.parametrize(
    "change",
    (
        {"recovery_state": ScenarioOperationalRecoveryState.HUMAN_ESCALATION_REQUIRED},
        {
            "investigation_state": (
                ScenarioOperationalInvestigationState.ESCALATION_REQUIRED
            )
        },
        {
            "mutation_state": ScenarioOperationalMutationState.STARTED,
            "investigation_state": ScenarioOperationalInvestigationState.STARTED,
            "cleanup_state": ScenarioOperationalCleanupState.NOT_REQUESTED,
        },
        {
            "mutation_state": ScenarioOperationalMutationState.STARTED,
            "investigation_state": ScenarioOperationalInvestigationState.RECORDED,
        },
        {
            "investigation_state": ScenarioOperationalInvestigationState.NOT_STARTED,
            "cleanup_state": ScenarioOperationalCleanupState.PENDING,
        },
        {
            "investigation_state": (
                ScenarioOperationalInvestigationState.ESCALATION_REQUIRED
            ),
            "cleanup_state": ScenarioOperationalCleanupState.FAILED,
            "recovery_state": (
                ScenarioOperationalRecoveryState.HUMAN_ESCALATION_REQUIRED
            ),
        },
    ),
)
def test_operational_status_rejects_incoherent_public_states(
    change: dict[str, object],
) -> None:
    with pytest.raises(ValidationError):
        _status(**change)


@pytest.mark.parametrize(
    "change",
    (
        {"provider_config": {}},
        {"schema_version": "reconcile/scenario-operational-status/v1"},
        {"revision": -1},
        {"workspace_id": "private-workspace"},
    ),
)
def test_operational_status_rejects_unknown_or_invalid_wire_values(
    change: dict[str, object],
) -> None:
    payload = json.loads(canonical_json_bytes(_status()))
    payload.update(change)

    with pytest.raises(ValidationError):
        ScenarioOperationalStatus.model_validate_json(json.dumps(payload))


def test_operational_status_exposes_no_private_authority_or_result_data() -> None:
    encoded = canonical_json_bytes(_status()).decode("utf-8")

    for forbidden in (
        "workspace",
        "coordinate",
        "observation",
        "evidence",
        "sha256",
        "lease",
        "failure_code",
        "report",
        "classification",
        "action_gate",
        "secret",
    ):
        assert forbidden not in encoded


@pytest.mark.parametrize(
    "change",
    (
        {
            "mutation_state": ScenarioOperationalMutationState.STARTED,
            "investigation_state": (
                ScenarioOperationalInvestigationState.ESCALATION_REQUIRED
            ),
            "cleanup_state": ScenarioOperationalCleanupState.NOT_REQUESTED,
            "recovery_state": (
                ScenarioOperationalRecoveryState.HUMAN_ESCALATION_REQUIRED
            ),
        },
        {
            "mutation_state": ScenarioOperationalMutationState.NOT_STARTED,
            "investigation_state": (
                ScenarioOperationalInvestigationState.ESCALATION_REQUIRED
            ),
            "cleanup_state": ScenarioOperationalCleanupState.NOT_REQUESTED,
            "recovery_state": (
                ScenarioOperationalRecoveryState.HUMAN_ESCALATION_REQUIRED
            ),
        },
        {
            "mutation_state": ScenarioOperationalMutationState.RECORDED,
            "investigation_state": ScenarioOperationalInvestigationState.NOT_STARTED,
            "cleanup_state": ScenarioOperationalCleanupState.NOT_REQUESTED,
        },
    ),
)
def test_operational_status_preserves_valid_recovery_boundaries(
    change: dict[str, object],
) -> None:
    assert _status(**change)
