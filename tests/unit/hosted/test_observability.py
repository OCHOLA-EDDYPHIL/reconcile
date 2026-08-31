from __future__ import annotations

import io
import json
from datetime import UTC, datetime

import pytest
from pydantic import ValidationError

from reconcile.hosted.config import Component
from reconcile.hosted.observability import (
    OperationalSignal,
    component_observer,
    emit_operational_event,
)

pytestmark = pytest.mark.unit

_NOW = datetime(2026, 8, 31, 12, 0, tzinfo=UTC)


def test_operational_event_is_bounded_canonical_structured_json() -> None:
    output = io.StringIO()

    event = emit_operational_event(
        signal=OperationalSignal.WORKER_FAILURE,
        component=Component.CONTROLLER,
        correlation_id="run-123",
        occurred_at=_NOW,
        sink=lambda value: output.write(value.model_dump_json()),
    )

    assert event.severity == "ERROR"
    assert json.loads(output.getvalue()) == {
        "component": "controller",
        "correlation_id": "run-123",
        "event": "operational-signal",
        "event_id": event.event_id,
        "occurred_at": "2026-08-31T12:00:00Z",
        "schema_version": "reconcile/operational-event/v2",
        "severity": "ERROR",
        "signal": "worker-failure",
        "source_event_cursor": None,
        "source_event_sha256": None,
    }
    assert event.event_id.startswith("event-")


def test_observer_rejects_secret_shaped_correlation_without_emitting() -> None:
    observed = []
    observer = component_observer(Component.API, sink=observed.append)

    with pytest.raises(ValidationError):
        observer("provider-unavailable", "Bearer hdr.private.signature")

    assert observed == []


def test_observer_rejects_unrecognized_signal_without_emitting() -> None:
    observed = []
    observer = component_observer(Component.API, sink=observed.append)

    with pytest.raises(ValueError):
        observer("private-provider-error", "run-123")

    assert observed == []


def test_operational_event_requires_correlation_and_binds_source_identity() -> None:
    source_sha256 = "a" * 64
    first = emit_operational_event(
        signal=OperationalSignal.FAILED_RUN,
        component=Component.API,
        correlation_id="run-123",
        occurred_at=_NOW,
        source_event_cursor=7,
        source_event_sha256=source_sha256,
        sink=lambda _event: None,
    )
    replay = emit_operational_event(
        signal=OperationalSignal.FAILED_RUN,
        component=Component.API,
        correlation_id="run-123",
        occurred_at=_NOW,
        source_event_cursor=7,
        source_event_sha256=source_sha256,
        sink=lambda _event: None,
    )

    assert first.event_id == replay.event_id
    with pytest.raises(TypeError, match="missing 1 required keyword-only argument"):
        emit_operational_event(  # type: ignore[call-arg]
            signal=OperationalSignal.FAILED_RUN,
            component=Component.API,
            sink=lambda _event: None,
        )


def test_default_sink_uses_stable_cloud_logging_insert_identity(
    capsys: pytest.CaptureFixture[str],
) -> None:
    event = emit_operational_event(
        signal=OperationalSignal.PROVIDER_UNAVAILABLE,
        component=Component.API,
        correlation_id="request-123",
        occurred_at=_NOW,
    )

    payload = json.loads(capsys.readouterr().err)
    assert payload["event_id"] == event.event_id
    assert payload["logging.googleapis.com/insertId"] == event.event_id
    assert payload["timestamp"] == "2026-08-31T12:00:00Z"
