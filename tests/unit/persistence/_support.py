"""Builders shared by persistence-boundary unit tests."""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from hashlib import sha256

from reconcile.contracts.codec import decode_contract
from reconcile.contracts.envelope import ExecutionEnvelope
from reconcile.contracts.report import (
    INVESTIGATION_REPORT_VERSION,
    InvestigationReport,
    InvestigationStatus,
)
from reconcile.persistence.models import InvestigationRecord, new_investigation_record

FIXED_TIME = datetime(2026, 8, 13, 12, 0, tzinfo=UTC)


def make_envelope(
    *,
    investigation_id: str = "investigation-1",
    operation_id: str = "operation-1",
) -> ExecutionEnvelope:
    invocation_arguments = {"content_sha256": "content-1"}
    value = {
        "schema_version": "reconcile/execution-envelope/v1",
        "investigation_id": investigation_id,
        "operation_id": operation_id,
        "target": {
            "target_kind": "gcs-object",
            "scope": {"project_id": "project-1", "bucket_name": "bucket-1"},
            "resource": {"object_name": "object-1"},
        },
        "invoked_at": "2026-08-13T11:59:58Z",
        "ambiguity": {
            "kind": "TIMEOUT",
            "observed_at": "2026-08-13T12:00:00Z",
            "detail": "response was not received",
        },
        "expected_effects": [
            {
                "schema_version": "reconcile/expected-effect/v1",
                "effect_id": "object-created",
                "commit_scope": "gcs-object-create",
                "predicate": {"generation_matches": "requested"},
                "description": "The requested object generation exists.",
            }
        ],
        "context": {
            "invocation": {
                "invocation_id": "invocation-1",
                "function_call_id": "function-call-1",
                "tool_name": "create-object",
                "tool_version": "v1",
                "arguments": invocation_arguments,
                "arguments_sha256": sha256(
                    json.dumps(
                        invocation_arguments,
                        ensure_ascii=False,
                        separators=(",", ":"),
                        sort_keys=True,
                    ).encode("utf-8")
                ).hexdigest(),
            },
            "enabled_capabilities": [{"name": "read-object-metadata", "version": "v1"}],
            "correlation_fields": {"request_id": "request-1"},
            "evidence_budget": {
                "max_probes": 3,
                "max_elapsed_ms": 10000,
                "max_total_result_bytes": 65536,
                "max_cost_units": 3,
            },
            "freshness": {"max_age_seconds": 300, "clock_skew_seconds": 5},
            "policies": {
                "authority": "authority-v1",
                "classification": "classification-v1",
                "action": "action-v1",
            },
        },
    }
    return decode_contract(json.dumps(value), ExecutionEnvelope)


def make_record(
    *,
    investigation_id: str = "investigation-1",
    operation_id: str = "operation-1",
    created_at: datetime = FIXED_TIME,
) -> InvestigationRecord:
    return new_investigation_record(
        make_envelope(
            investigation_id=investigation_id,
            operation_id=operation_id,
        ),
        created_at=created_at,
    )


def next_report(
    record: InvestigationRecord,
    *,
    seconds_later: int = 1,
) -> InvestigationReport:
    return InvestigationReport(
        schema_version=INVESTIGATION_REPORT_VERSION,
        investigation_id=record.investigation_id,
        envelope_sha256=record.envelope_sha256,
        status=InvestigationStatus.INVESTIGATING,
        created_at=record.report.created_at,
        updated_at=record.report.updated_at + timedelta(seconds=seconds_later),
        revision=record.revision + 1,
    )
