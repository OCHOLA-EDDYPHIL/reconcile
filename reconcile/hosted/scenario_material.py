"""Pure hosted scenario material derived from sealed canonical requests."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime

from reconcile.contracts.codec import canonical_json_bytes, decode_contract
from reconcile.contracts.scenario import ScenarioRunRequest
from reconcile.hosted.workflow import (
    HOSTED_SCENARIO_PREPARATION_VERSION,
    HostedScenarioPreparation,
)
from reconcile.scenarios.firestore_business import (
    FIRESTORE_BUSINESS_SCENARIO,
    FirestoreBusinessOperationMaterial,
    build_firestore_business_operation_material,
    build_firestore_business_scenario_preparation,
)
from reconcile.scenarios.runner import build_scenario_plan
from reconcile.scenarios.sandbox_order import (
    SANDBOX_ORDER_SCENARIO,
    SandboxOrderOperationMaterial,
    build_hosted_sandbox_order_scenario_preparation,
    build_sandbox_order_operation_material,
)
from reconcile.scenarios.service import ScenarioName, _request
from reconcile.scenarios.storage import (
    STORAGE_SCENARIO,
    StorageOperationMaterial,
    build_storage_operation_material,
    build_storage_scenario_preparation,
)


@dataclass(frozen=True, slots=True)
class HostedStorageMaterial:
    preparation: HostedScenarioPreparation
    operation: StorageOperationMaterial


@dataclass(frozen=True, slots=True)
class HostedFirestoreBusinessMaterial:
    preparation: HostedScenarioPreparation
    operation: FirestoreBusinessOperationMaterial


@dataclass(frozen=True, slots=True)
class HostedSandboxOrderMaterial:
    preparation: HostedScenarioPreparation
    operation: SandboxOrderOperationMaterial


type HostedScenarioMaterial = (
    HostedStorageMaterial | HostedFirestoreBusinessMaterial | HostedSandboxOrderMaterial
)


def _scenario(request: ScenarioRunRequest) -> ScenarioName:
    by_ref = {
        STORAGE_SCENARIO: ScenarioName.STORAGE,
        FIRESTORE_BUSINESS_SCENARIO: ScenarioName.FIRESTORE_BUSINESS,
        SANDBOX_ORDER_SCENARIO: ScenarioName.SANDBOX_ORDER,
    }
    try:
        scenario = by_ref[request.scenario]
    except (KeyError, TypeError):
        raise ValueError("hosted scenario request is unsupported") from None
    if canonical_json_bytes(request) != canonical_json_bytes(
        _request(scenario, request.run_id)
    ):
        raise ValueError("hosted scenario request is not canonical")
    return scenario


def _hosted_preparation(
    namespace_id: str,
    preparation: object,
) -> HostedScenarioPreparation:
    try:
        execution_envelope = preparation.execution_envelope  # type: ignore[attr-defined]
        cleanup_manifest = preparation.cleanup_manifest  # type: ignore[attr-defined]
        resource_ids = cleanup_manifest.resource_ids
    except AttributeError:
        raise TypeError("hosted scenario preparation is incomplete") from None
    return HostedScenarioPreparation(
        schema_version=HOSTED_SCENARIO_PREPARATION_VERSION,
        namespace_id=namespace_id,
        execution_envelope=execution_envelope,
        cleanup_resource_ids=resource_ids,
    )


def build_hosted_scenario_material(
    request: ScenarioRunRequest,
    *,
    invoked_at: datetime,
    target_bucket: str,
) -> HostedScenarioMaterial:
    """Recompute one exact envelope and provider argument set without I/O."""

    request = decode_contract(canonical_json_bytes(request), ScenarioRunRequest)
    scenario = _scenario(request)
    plan = build_scenario_plan(request)
    if scenario is ScenarioName.STORAGE:
        operation = build_storage_operation_material(plan)
        preparation = build_storage_scenario_preparation(
            plan,
            bucket_name=target_bucket,
            invoked_at=invoked_at,
        )
        return HostedStorageMaterial(
            preparation=_hosted_preparation(plan.namespace_id, preparation),
            operation=operation,
        )
    if scenario is ScenarioName.FIRESTORE_BUSINESS:
        operation = build_firestore_business_operation_material(plan)
        preparation = build_firestore_business_scenario_preparation(
            plan,
            invoked_at=invoked_at,
        )
        return HostedFirestoreBusinessMaterial(
            preparation=_hosted_preparation(plan.namespace_id, preparation),
            operation=operation,
        )
    operation = build_sandbox_order_operation_material(plan)
    preparation = build_hosted_sandbox_order_scenario_preparation(
        plan,
        invoked_at=invoked_at,
    )
    return HostedSandboxOrderMaterial(
        preparation=_hosted_preparation(plan.namespace_id, preparation),
        operation=operation,
    )


class DeterministicHostedScenarioPreparer:
    """API-facing pure preparer with no credential or provider dependency."""

    def __init__(self, *, target_bucket: str) -> None:
        if type(target_bucket) is not str or not target_bucket:
            raise ValueError("hosted target bucket is required")
        self._target_bucket = target_bucket

    def __call__(
        self,
        request: ScenarioRunRequest,
        *,
        invoked_at: datetime,
    ) -> HostedScenarioPreparation:
        return build_hosted_scenario_material(
            request,
            invoked_at=invoked_at,
            target_bucket=self._target_bucket,
        ).preparation


__all__ = [
    "DeterministicHostedScenarioPreparer",
    "HostedFirestoreBusinessMaterial",
    "HostedSandboxOrderMaterial",
    "HostedScenarioMaterial",
    "HostedStorageMaterial",
    "build_hosted_scenario_material",
]
