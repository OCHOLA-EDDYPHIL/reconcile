from __future__ import annotations

import builtins
import os
import socket
import sqlite3
import subprocess
from dataclasses import asdict
from datetime import UTC, datetime
from pathlib import Path

import pytest

from reconcile.adapters.firestore_business import FIRESTORE_BUSINESS_CLOUD_PROFILE
from reconcile.adapters.sandbox_order import SANDBOX_ORDER_CLOUD_PROFILE
from reconcile.adapters.storage import CLOUD_STORAGE_PROFILE
from reconcile.contracts import (
    ScenarioFaultAction,
    ScenarioFaultInstruction,
    ScenarioFaultPoint,
    ScenarioRef,
    canonical_json_bytes,
)
from reconcile.contracts.base import canonical_json_value_bytes
from reconcile.hosted.scenario_material import (
    DeterministicHostedScenarioPreparer,
    HostedFirestoreBusinessMaterial,
    HostedSandboxOrderMaterial,
    HostedStorageMaterial,
    build_hosted_scenario_material,
)
from reconcile.scenarios.service import ScenarioName, _request

pytestmark = pytest.mark.unit

_RUN_ID = "hosted-material-7"
_TARGET_BUCKET = "reconcile-dev-260813-14fa6d-p5-target"
_INVOKED_AT = datetime(2026, 8, 18, 1, 2, 3, tzinfo=UTC)


def _material(scenario: ScenarioName):
    return build_hosted_scenario_material(
        _request(scenario, _RUN_ID),
        invoked_at=_INVOKED_AT,
        target_bucket=_TARGET_BUCKET,
    )


@pytest.mark.parametrize(
    (
        "scenario",
        "material_type",
        "profile",
        "expected_profile",
        "target_kind",
    ),
    (
        (
            ScenarioName.STORAGE,
            HostedStorageMaterial,
            CLOUD_STORAGE_PROFILE,
            {
                "environment": "google-cloud-storage",
                "authority_policy_version": "authority-cloud-storage-v1",
                "source": "google-cloud-storage-json-v1",
                "adapter_version": "1.0.0",
                "timeout_ms": 5_000,
            },
            "storage.object",
        ),
        (
            ScenarioName.FIRESTORE_BUSINESS,
            HostedFirestoreBusinessMaterial,
            FIRESTORE_BUSINESS_CLOUD_PROFILE,
            {
                "environment": "google-cloud-firestore",
                "authority_policy_version": (
                    "authority-cloud-firestore-business-documents-v1"
                ),
                "source": "google-cloud-firestore-v1",
                "adapter_version": "1.0.0",
                "timeout_ms": 5_000,
            },
            "business.documents",
        ),
        (
            ScenarioName.SANDBOX_ORDER,
            HostedSandboxOrderMaterial,
            SANDBOX_ORDER_CLOUD_PROFILE,
            {
                "environment": "google-cloud-firestore-sandbox",
                "authority_policy_version": ("authority-cloud-sandbox-order-weak-v1"),
                "adapter_version": "1.0.0",
                "ingress_source": "hosted-sandbox-order-weak-ingress",
                "aggregate_source": "hosted-sandbox-order-weak-aggregate",
                "timeout_ms": 5_000,
            },
            "sandbox.order",
        ),
    ),
)
def test_all_material_uses_the_exact_cloud_profile(
    scenario: ScenarioName,
    material_type: type,
    profile: object,
    expected_profile: dict[str, object],
    target_kind: str,
) -> None:
    material = _material(scenario)
    envelope = material.preparation.execution_envelope

    assert type(material) is material_type
    assert asdict(profile) == expected_profile  # type: ignore[arg-type]
    assert envelope.target.target_kind == target_kind
    assert envelope.target.scope["environment"] == expected_profile["environment"]
    assert (
        envelope.context.policies.authority
        == expected_profile["authority_policy_version"]
    )
    assert envelope.context.policies.classification == "classification-v1"
    assert envelope.context.policies.action == "action-v1"


@pytest.mark.parametrize("scenario", tuple(ScenarioName))
def test_preparer_and_material_builder_have_deterministic_parity(
    scenario: ScenarioName,
) -> None:
    request = _request(scenario, _RUN_ID)
    first = build_hosted_scenario_material(
        request,
        invoked_at=_INVOKED_AT,
        target_bucket=_TARGET_BUCKET,
    )
    second = build_hosted_scenario_material(
        request,
        invoked_at=_INVOKED_AT,
        target_bucket=_TARGET_BUCKET,
    )
    prepared = DeterministicHostedScenarioPreparer(target_bucket=_TARGET_BUCKET)(
        request,
        invoked_at=_INVOKED_AT,
    )

    assert first == second
    assert prepared == first.preparation
    assert canonical_json_bytes(prepared) == canonical_json_bytes(first.preparation)


def test_storage_material_has_exact_provider_coordinates_and_bytes() -> None:
    material = _material(ScenarioName.STORAGE)
    assert type(material) is HostedStorageMaterial
    operation = material.operation
    preparation = material.preparation
    namespace_id = "scenario-55019e0e87fc3be146b0087a9acde3e0"
    object_name = f"runs/{namespace_id}/object.json"
    operation_id = "operation-storage-4cfab3cbd649d533b3e0e4ac"
    correlation = {
        "invocation_id": "invocation-storage-4cfab3cbd649d533b3e0e4ac",
        "operation_id": operation_id,
        "run_id": _RUN_ID,
    }

    assert preparation.namespace_id == namespace_id
    assert operation.object_name == object_name
    assert operation.content == canonical_json_value_bytes(
        {"operation_id": operation_id, "run_id": _RUN_ID, "seed": 39}
    )
    assert operation.correlation == correlation
    assert preparation.execution_envelope.target.model_dump(mode="json") == {
        "target_kind": "storage.object",
        "scope": {
            "bucket_name": _TARGET_BUCKET,
            "environment": "google-cloud-storage",
        },
        "resource": {"object_name": object_name},
    }
    assert preparation.cleanup_resource_ids == (
        f"storage-object:{_TARGET_BUCKET}/{object_name}",
        f"storage-receipt:{operation_id}",
    )
    arguments = preparation.execution_envelope.context.invocation.arguments
    assert arguments == {
        "bucket_name": _TARGET_BUCKET,
        "content_sha256": "8f622d5f8bcee541acaed41d998b851ce0711f3b40abba7d442365fc049e9286",
        "correlation": correlation,
        "object_name": object_name,
        "size_bytes": 100,
    }


def test_firestore_material_has_exact_multi_effect_coordinates() -> None:
    material = _material(ScenarioName.FIRESTORE_BUSINESS)
    assert type(material) is HostedFirestoreBusinessMaterial
    operation = material.operation
    preparation = material.preparation
    namespace_id = "scenario-afbb854a7fab72b7497f33db399dbedf"
    operation_id = "operation-firestore-6c93db01bee88bb0a24f9ec8"
    business_request_id = "business-request-6e02c76e8b1b391d150b7e18"
    manifest_document_id = f"operation-{operation_id}"
    coordinates = (
        ("primary-request", "requests", business_request_id),
        ("audit-record", "audit-records", f"audit-{business_request_id}"),
        (
            "processing-index",
            "processing-indexes",
            f"processing-{business_request_id}",
        ),
    )
    correlation = {
        "business_request_id": business_request_id,
        "operation_id": operation_id,
        "run_id": _RUN_ID,
    }

    assert preparation.namespace_id == namespace_id
    assert operation.namespace_id == namespace_id
    assert operation.operation_id == operation_id
    assert operation.manifest_collection == "operation-manifests"
    assert operation.manifest_document_id == manifest_document_id
    assert operation.selected_effect_ids == ("primary-request", "audit-record")
    assert operation.correlation == correlation
    assert (
        tuple(
            (document.effect_id, document.collection_name, document.document_id)
            for document in operation.documents
        )
        == coordinates
    )
    for document in operation.documents:
        assert document.content == canonical_json_value_bytes(
            {
                "business_request_id": business_request_id,
                "effect_id": document.effect_id,
                "operation_id": operation_id,
                "run_id": _RUN_ID,
            }
        )
    assert preparation.execution_envelope.target.model_dump(mode="json") == {
        "target_kind": "business.documents",
        "scope": {
            "environment": "google-cloud-firestore",
            "namespace_id": namespace_id,
        },
        "resource": {
            "manifest_collection": "operation-manifests",
            "manifest_document_id": manifest_document_id,
            "effect_documents": [
                {
                    "effect_id": effect_id,
                    "collection_name": collection,
                    "document_id": document_id,
                }
                for effect_id, collection, document_id in coordinates
            ],
        },
    }
    assert preparation.cleanup_resource_ids == (
        f"business-manifest:{namespace_id}/operation-manifests/{manifest_document_id}",
        *(
            f"business-document:{namespace_id}/{collection}/{document_id}"
            for _, collection, document_id in coordinates
        ),
    )


def test_sandbox_material_keeps_private_owner_off_the_wire() -> None:
    material = _material(ScenarioName.SANDBOX_ORDER)
    assert type(material) is HostedSandboxOrderMaterial
    operation = material.operation
    preparation = material.preparation
    sandbox_id = "scenario-ff062c715a855a3828bd6a8b28146f16"
    owner_token = "sandbox-owner-7bdd36ae3ed67ae643d8979e03763f9d"

    assert preparation.namespace_id == sandbox_id
    assert asdict(operation) == {
        "sandbox_id": sandbox_id,
        "owner_token": owner_token,
        "item_code": "widget-blue",
        "quantity": 2,
    }
    assert preparation.execution_envelope.target.model_dump(mode="json") == {
        "target_kind": "sandbox.order",
        "scope": {
            "environment": "google-cloud-firestore-sandbox",
            "sandbox_id": sandbox_id,
        },
        "resource": {"observation_set": "weak-order-observations"},
    }
    assert preparation.cleanup_resource_ids == (
        f"reconcile-sandbox-private-state/{sandbox_id}",
        f"reconcile-sandbox-observations/{sandbox_id}/weak-observations/ingress",
        f"reconcile-sandbox-observations/{sandbox_id}/weak-observations/aggregate",
    )
    cleanup_wire = canonical_json_value_bytes(
        {"resource_ids": list(preparation.cleanup_resource_ids)}
    )
    for wire in (preparation.envelope_bytes, cleanup_wire):
        assert owner_token.encode() not in wire
        assert b"owner_token" not in wire


@pytest.mark.parametrize(
    ("update", "message"),
    (
        ({"operation_id": "operation-tampered"}, "not canonical"),
        ({"seed": 40}, "not canonical"),
        (
            {
                "fault": ScenarioFaultInstruction(
                    point=ScenarioFaultPoint.UNINTERRUPTED,
                    action=ScenarioFaultAction.NONE,
                )
            },
            "not canonical",
        ),
        (
            {"scenario": ScenarioRef(name="storage-object", version="2.0.0")},
            "unsupported",
        ),
    ),
)
def test_tampered_or_noncanonical_requests_are_rejected(
    update: dict[str, object],
    message: str,
) -> None:
    request = _request(ScenarioName.STORAGE, _RUN_ID).model_copy(update=update)

    with pytest.raises(ValueError, match=message):
        build_hosted_scenario_material(
            request,
            invoked_at=_INVOKED_AT,
            target_bucket=_TARGET_BUCKET,
        )


def test_material_construction_performs_no_file_process_database_or_network_io(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def deny_io(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("hosted scenario material attempted I/O")

    monkeypatch.setattr(builtins, "open", deny_io)
    monkeypatch.setattr(os, "open", deny_io)
    monkeypatch.setattr(Path, "open", deny_io)
    monkeypatch.setattr(socket, "socket", deny_io)
    monkeypatch.setattr(sqlite3, "connect", deny_io)
    monkeypatch.setattr(subprocess, "Popen", deny_io)

    for scenario in ScenarioName:
        assert _material(scenario).preparation.namespace_id.startswith("scenario-")
