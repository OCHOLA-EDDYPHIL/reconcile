"""Public operational state for durable scenario runs."""

from __future__ import annotations

from enum import StrEnum
from typing import Literal

from pydantic import Field, model_validator

from reconcile.contracts.base import AwareDatetime, Identifier, StrictModel
from reconcile.contracts.operator import ScenarioLaunchName, ScenarioRunMode

SCENARIO_OPERATIONAL_STATUS_VERSION = "reconcile/scenario-operational-status/v2"


class ScenarioOperationalMutationState(StrEnum):
    NOT_STARTED = "NOT_STARTED"
    STARTED = "STARTED"
    RECORDED = "RECORDED"


class ScenarioOperationalInvestigationState(StrEnum):
    NOT_STARTED = "NOT_STARTED"
    STARTED = "STARTED"
    RECORDED = "RECORDED"
    ESCALATION_REQUIRED = "ESCALATION_REQUIRED"


class ScenarioOperationalCleanupState(StrEnum):
    NOT_REQUESTED = "NOT_REQUESTED"
    PENDING = "PENDING"
    SUCCEEDED = "SUCCEEDED"
    FAILED = "FAILED"


class ScenarioOperationalRecoveryState(StrEnum):
    NOT_ESCALATED = "NOT_ESCALATED"
    HUMAN_ESCALATION_REQUIRED = "HUMAN_ESCALATION_REQUIRED"


class ScenarioOperationalStatus(StrictModel):
    schema_version: Literal[SCENARIO_OPERATIONAL_STATUS_VERSION]
    launch_id: Identifier
    investigation_id: Identifier
    scenario: ScenarioLaunchName
    mode: ScenarioRunMode
    revision: int = Field(ge=0, le=2**63 - 1)
    mutation_state: ScenarioOperationalMutationState
    investigation_state: ScenarioOperationalInvestigationState
    cleanup_state: ScenarioOperationalCleanupState
    recovery_state: ScenarioOperationalRecoveryState
    updated_at: AwareDatetime

    @model_validator(mode="after")
    def validate_recovery_state(self) -> ScenarioOperationalStatus:
        escalation = (
            self.investigation_state
            is ScenarioOperationalInvestigationState.ESCALATION_REQUIRED
        )
        required = (
            self.recovery_state
            is ScenarioOperationalRecoveryState.HUMAN_ESCALATION_REQUIRED
        )
        if escalation is not required:
            raise ValueError("operational recovery and investigation state disagree")
        if (
            self.investigation_state
            in {
                ScenarioOperationalInvestigationState.STARTED,
                ScenarioOperationalInvestigationState.RECORDED,
            }
            and self.mutation_state is not ScenarioOperationalMutationState.RECORDED
        ):
            raise ValueError("operational investigation cannot precede mutation result")
        if (
            self.cleanup_state is not ScenarioOperationalCleanupState.NOT_REQUESTED
            and self.investigation_state
            is not ScenarioOperationalInvestigationState.RECORDED
        ):
            raise ValueError("operational cleanup cannot precede investigation result")
        return self


__all__ = [
    "SCENARIO_OPERATIONAL_STATUS_VERSION",
    "ScenarioOperationalCleanupState",
    "ScenarioOperationalInvestigationState",
    "ScenarioOperationalMutationState",
    "ScenarioOperationalRecoveryState",
    "ScenarioOperationalStatus",
]
