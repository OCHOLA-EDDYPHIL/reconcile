"""Deterministic, presentation-safe primitives for the command-line interface."""

from __future__ import annotations

import os
import stat
import sys
import tempfile
from collections.abc import Iterable
from dataclasses import dataclass
from enum import IntEnum, StrEnum
from pathlib import Path
from typing import BinaryIO

from pydantic import BaseModel

from reconcile.contracts import (
    ActionGateEventPayload,
    Classification,
    ClassificationEventPayload,
    EvidenceDecisionEventPayload,
    EvidenceDisposition,
    InvestigationEvent,
    InvestigationReport,
    LifecycleEventPayload,
    ProbeEventPayload,
    RequestedAction,
    canonical_json_bytes,
)

MAX_INPUT_BYTES = 1_048_576


class ExitCode(IntEnum):
    """Stable process outcomes for all RECONCILE commands."""

    SUCCESS = 0
    INTERNAL_FAILURE = 1
    INVALID_INPUT = 2
    NOT_FOUND = 3
    CONFLICT = 4
    SERVICE_UNAVAILABLE = 5
    UNRESOLVED = 6
    POLICY_REFUSAL = 7
    INTERRUPTED = 130


class FailureCategory(StrEnum):
    """Public failure categories that never contain internal detail."""

    INTERNAL_FAILURE = "internal_failure"
    INVALID_INPUT = "invalid_input"
    NOT_FOUND = "not_found"
    CONFLICT = "conflict"
    SERVICE_UNAVAILABLE = "service_unavailable"


_FAILURE_DETAILS: dict[FailureCategory, tuple[ExitCode, str]] = {
    FailureCategory.INTERNAL_FAILURE: (
        ExitCode.INTERNAL_FAILURE,
        "The command could not be completed.",
    ),
    FailureCategory.INVALID_INPUT: (
        ExitCode.INVALID_INPUT,
        "The input is invalid.",
    ),
    FailureCategory.NOT_FOUND: (
        ExitCode.NOT_FOUND,
        "The requested investigation was not found.",
    ),
    FailureCategory.CONFLICT: (
        ExitCode.CONFLICT,
        "The investigation identity conflicts with an existing envelope.",
    ),
    FailureCategory.SERVICE_UNAVAILABLE: (
        ExitCode.SERVICE_UNAVAILABLE,
        "The service is unavailable.",
    ),
}


@dataclass(frozen=True, slots=True, init=False)
class PublicFailure:
    """A fixed public failure response selected only by category."""

    category: FailureCategory
    exit_code: ExitCode
    message: str

    def __init__(self, category: FailureCategory) -> None:
        if type(category) is not FailureCategory:
            raise TypeError("category must be a FailureCategory")
        exit_code, message = _FAILURE_DETAILS[category]
        object.__setattr__(self, "category", category)
        object.__setattr__(self, "exit_code", exit_code)
        object.__setattr__(self, "message", message)


class CliCoreError(Exception):
    """A CLI-core error whose public representation is fixed and safe."""

    failure: PublicFailure

    def __init__(self, category: FailureCategory) -> None:
        self.failure = PublicFailure(category)
        super().__init__(self.failure.message)


def public_failure(category: FailureCategory) -> PublicFailure:
    """Return the fixed public response for a failure category."""

    return PublicFailure(category)


def load_exact_input(
    source: str | os.PathLike[str],
    *,
    stdin: BinaryIO | None = None,
) -> bytes:
    """Load one non-empty bounded payload from a regular file or ``-``."""

    try:
        source_text = os.fspath(source)
    except Exception:
        raise CliCoreError(FailureCategory.INVALID_INPUT) from None
    if type(source_text) is not str or not source_text:
        raise CliCoreError(FailureCategory.INVALID_INPUT)

    if source_text == "-":
        input_stream = sys.stdin.buffer if stdin is None else stdin
        return _read_bounded(input_stream)

    file_descriptor = -1
    try:
        initial = os.lstat(source_text)
        if stat.S_ISLNK(initial.st_mode) or not stat.S_ISREG(initial.st_mode):
            raise CliCoreError(FailureCategory.INVALID_INPUT)
        if initial.st_size > MAX_INPUT_BYTES:
            raise CliCoreError(FailureCategory.INVALID_INPUT)

        flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
        flags |= getattr(os, "O_NOFOLLOW", 0)
        file_descriptor = os.open(source_text, flags)
        opened = os.fstat(file_descriptor)
        if (
            not stat.S_ISREG(opened.st_mode)
            or opened.st_dev != initial.st_dev
            or opened.st_ino != initial.st_ino
        ):
            raise CliCoreError(FailureCategory.INVALID_INPUT)

        with os.fdopen(file_descriptor, "rb", closefd=True) as input_file:
            file_descriptor = -1
            return _read_bounded(input_file)
    except CliCoreError:
        raise
    except (OSError, ValueError):
        raise CliCoreError(FailureCategory.INVALID_INPUT) from None
    finally:
        if file_descriptor >= 0:
            try:
                os.close(file_descriptor)
            except OSError:
                pass


def canonical_json_output(contract: BaseModel) -> bytes:
    """Return one canonical JSON record terminated for stdout."""

    return canonical_json_bytes(contract) + b"\n"


def canonical_event_jsonl(events: Iterable[InvestigationEvent]) -> bytes:
    """Return validated events as one canonical JSON record per line."""

    records: list[bytes] = []
    for event in events:
        records.append(canonical_json_bytes(_validated_event(event)) + b"\n")
    return b"".join(records)


def render_human_status(report: InvestigationReport) -> bytes:
    """Render a bounded status view from explicitly selected fields."""

    report = _validated_report(report)
    classification = (
        report.classification.value
        if report.classification is not None
        else "UNAVAILABLE"
    )
    return _human_lines(
        (
            f"Investigation: {report.investigation_id}",
            f"Status: {report.status.value}",
            f"Classification: {classification}",
            f"Revision: {report.revision}",
        )
    )


def render_human_report(report: InvestigationReport) -> bytes:
    """Render a report summary without observations or advisory prose."""

    report = _validated_report(report)
    classification = (
        report.classification.value
        if report.classification is not None
        else "UNAVAILABLE"
    )
    disposition_counts = {
        disposition: sum(
            decision.disposition is disposition
            for decision in report.evidence_decisions
        )
        for disposition in EvidenceDisposition
    }
    lines = [
        f"Investigation: {report.investigation_id}",
        f"Status: {report.status.value}",
        f"Classification: {classification}",
        f"Revision: {report.revision}",
        f"Probes: {len(report.probe_audit)}",
        (
            "Evidence: "
            f"admitted={disposition_counts[EvidenceDisposition.ADMITTED]} "
            f"weak={disposition_counts[EvidenceDisposition.WEAK]} "
            f"rejected={disposition_counts[EvidenceDisposition.REJECTED]}"
        ),
        f"Missing evidence groups: {len(report.missing_evidence)}",
    ]
    lines.extend(
        f"Action {gate.requested_action.value}: "
        f"{'allowed' if gate.allowed else 'denied'}"
        for gate in report.action_gate
    )
    return _human_lines(lines)


def render_human_event(event: InvestigationEvent) -> bytes:
    """Render one event using only contract identifiers and enum values."""

    event = _validated_event(event)
    payload = event.payload
    fields = [f"Sequence: {event.sequence}", f"Type: {event.type.value}"]
    if type(payload) is LifecycleEventPayload:
        fields.append(f"Status: {payload.status.value}")
    elif type(payload) is ProbeEventPayload:
        fields.extend(
            (
                f"Probe: {payload.probe_audit.probe_sequence}",
                f"Outcome: {payload.probe_audit.outcome.value}",
            )
        )
    elif type(payload) is EvidenceDecisionEventPayload:
        fields.extend(
            (
                f"Evidence: {payload.decision.evidence_id}",
                f"Disposition: {payload.decision.disposition.value}",
                f"Reason: {payload.decision.reason.value}",
            )
        )
    elif type(payload) is ClassificationEventPayload:
        fields.append(f"Classification: {payload.classification.value}")
    elif type(payload) is ActionGateEventPayload:
        fields.extend(
            (
                f"Action: {payload.action_gate.requested_action.value}",
                f"Decision: {'allowed' if payload.action_gate.allowed else 'denied'}",
                f"Reason: {payload.action_gate.reason.value}",
            )
        )
    else:  # pragma: no cover - the contract validator makes this unreachable.
        raise CliCoreError(FailureCategory.INTERNAL_FAILURE)
    return _human_lines(fields)


def waited_report_exit_code(
    report: InvestigationReport,
    *,
    require_action: RequestedAction | None = None,
) -> ExitCode:
    """Map a waited report and optional policy requirement to an exit code."""

    report = _validated_report(report)
    if require_action is not None:
        if type(require_action) is not RequestedAction:
            raise CliCoreError(FailureCategory.INVALID_INPUT)
        matching_gate = next(
            (
                gate
                for gate in report.action_gate
                if gate.requested_action is require_action
            ),
            None,
        )
        if matching_gate is not None and not matching_gate.allowed:
            return ExitCode.POLICY_REFUSAL

    if report.classification in (
        Classification.COMMITTED,
        Classification.NOT_COMMITTED,
    ):
        return ExitCode.SUCCESS
    return ExitCode.UNRESOLVED


def export_report(
    report: InvestigationReport,
    destination: str | os.PathLike[str],
) -> None:
    """Atomically export canonical report JSON at mode 0600 without overwrite."""

    report = _validated_report(report)
    payload = canonical_json_bytes(report)
    try:
        destination_text = os.fspath(destination)
    except Exception:
        raise CliCoreError(FailureCategory.INVALID_INPUT) from None
    if type(destination_text) is not str or not destination_text:
        raise CliCoreError(FailureCategory.INVALID_INPUT)

    destination_path = Path(destination_text)
    parent = destination_path.parent
    temporary_name: str | None = None
    file_descriptor = -1
    destination_linked = False
    published = False
    try:
        try:
            os.lstat(destination_path)
        except FileNotFoundError:
            pass
        else:
            raise CliCoreError(FailureCategory.INVALID_INPUT)

        parent_status = os.lstat(parent)
        if stat.S_ISLNK(parent_status.st_mode) or not stat.S_ISDIR(
            parent_status.st_mode
        ):
            raise CliCoreError(FailureCategory.INVALID_INPUT)

        file_descriptor, temporary_name = tempfile.mkstemp(
            prefix=".reconcile-export-",
            dir=parent,
        )
        os.fchmod(file_descriptor, 0o600)
        remaining = memoryview(payload)
        while remaining:
            written = os.write(file_descriptor, remaining)
            if written <= 0:
                raise OSError("short write")
            remaining = remaining[written:]
        os.fsync(file_descriptor)
        expected_status = os.fstat(file_descriptor)
        source_status = os.lstat(temporary_name)
        if (source_status.st_dev, source_status.st_ino) != (
            expected_status.st_dev,
            expected_status.st_ino,
        ):
            raise OSError("temporary export identity changed")
        os.link(temporary_name, destination_path, follow_symlinks=False)
        destination_linked = True
        destination_status = os.lstat(destination_path)
        if (destination_status.st_dev, destination_status.st_ino) != (
            expected_status.st_dev,
            expected_status.st_ino,
        ):
            raise OSError("published export identity changed")
        published = True
        os.close(file_descriptor)
        file_descriptor = -1
    except CliCoreError:
        raise
    except Exception:
        raise CliCoreError(FailureCategory.INVALID_INPUT) from None
    finally:
        if file_descriptor >= 0:
            try:
                os.close(file_descriptor)
            except OSError:
                pass
        if destination_linked and not published:
            try:
                os.unlink(destination_path)
            except OSError:
                pass
        if temporary_name is not None:
            try:
                os.unlink(temporary_name)
            except OSError:
                if not published:
                    pass


def _read_bounded(stream: BinaryIO) -> bytes:
    payload = bytearray()
    try:
        while len(payload) <= MAX_INPUT_BYTES:
            chunk = stream.read(min(65_536, MAX_INPUT_BYTES + 1 - len(payload)))
            if type(chunk) is not bytes:
                raise CliCoreError(FailureCategory.INVALID_INPUT)
            if not chunk:
                break
            payload.extend(chunk)
    except CliCoreError:
        raise
    except Exception:
        raise CliCoreError(FailureCategory.INVALID_INPUT) from None
    if not payload or len(payload) > MAX_INPUT_BYTES:
        raise CliCoreError(FailureCategory.INVALID_INPUT)
    return bytes(payload)


def _validated_report(report: InvestigationReport) -> InvestigationReport:
    if type(report) is not InvestigationReport:
        raise CliCoreError(FailureCategory.INTERNAL_FAILURE)
    try:
        return InvestigationReport.model_validate(report)
    except (TypeError, ValueError):
        raise CliCoreError(FailureCategory.INTERNAL_FAILURE) from None


def _validated_event(event: InvestigationEvent) -> InvestigationEvent:
    if type(event) is not InvestigationEvent:
        raise CliCoreError(FailureCategory.INTERNAL_FAILURE)
    try:
        return InvestigationEvent.model_validate(event)
    except (TypeError, ValueError):
        raise CliCoreError(FailureCategory.INTERNAL_FAILURE) from None


def _human_lines(lines: Iterable[str]) -> bytes:
    return ("\n".join(lines) + "\n").encode("utf-8")


__all__ = [
    "MAX_INPUT_BYTES",
    "CliCoreError",
    "ExitCode",
    "FailureCategory",
    "PublicFailure",
    "canonical_event_jsonl",
    "canonical_json_output",
    "export_report",
    "load_exact_input",
    "public_failure",
    "render_human_event",
    "render_human_report",
    "render_human_status",
    "waited_report_exit_code",
]
