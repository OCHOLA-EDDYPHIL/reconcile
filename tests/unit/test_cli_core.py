from __future__ import annotations

import io
import json
import os
import stat
from pathlib import Path

import pytest

from reconcile.cli_core import (
    MAX_INPUT_BYTES,
    CliCoreError,
    ExitCode,
    FailureCategory,
    canonical_event_jsonl,
    canonical_json_output,
    export_report,
    load_exact_input,
    public_failure,
    render_human_event,
    render_human_report,
    render_human_status,
    waited_report_exit_code,
)
from reconcile.contracts import (
    Classification,
    InvestigationEventType,
    RequestedAction,
    canonical_json_bytes,
)
from tests.contract._factories import make_investigation_event, make_report


class _ShortReadStream(io.BytesIO):
    def read(self, size: int = -1) -> bytes:
        return super().read(min(size, 3))


class _FailingStream(io.BytesIO):
    def read(self, size: int = -1) -> bytes:
        raise RuntimeError("secret-stream-failure")


def test_exit_codes_are_stable() -> None:
    assert {member.name: member.value for member in ExitCode} == {
        "SUCCESS": 0,
        "INTERNAL_FAILURE": 1,
        "INVALID_INPUT": 2,
        "NOT_FOUND": 3,
        "CONFLICT": 4,
        "SERVICE_UNAVAILABLE": 5,
        "UNRESOLVED": 6,
        "POLICY_REFUSAL": 7,
        "INTERRUPTED": 130,
    }


@pytest.mark.parametrize(
    ("category", "exit_code", "message"),
    (
        (
            FailureCategory.INTERNAL_FAILURE,
            ExitCode.INTERNAL_FAILURE,
            "The command could not be completed.",
        ),
        (
            FailureCategory.INVALID_INPUT,
            ExitCode.INVALID_INPUT,
            "The input is invalid.",
        ),
        (
            FailureCategory.NOT_FOUND,
            ExitCode.NOT_FOUND,
            "The requested investigation was not found.",
        ),
        (
            FailureCategory.CONFLICT,
            ExitCode.CONFLICT,
            "The investigation identity conflicts with an existing envelope.",
        ),
        (
            FailureCategory.SERVICE_UNAVAILABLE,
            ExitCode.SERVICE_UNAVAILABLE,
            "The service is unavailable.",
        ),
    ),
)
def test_public_failures_are_fixed(
    category: FailureCategory,
    exit_code: ExitCode,
    message: str,
) -> None:
    failure = public_failure(category)

    assert failure.category is category
    assert failure.exit_code is exit_code
    assert failure.message == message


def test_load_exact_input_reads_bounded_stdin_without_echoing_it() -> None:
    payload = b"x" * MAX_INPUT_BYTES

    assert load_exact_input("-", stdin=io.BytesIO(payload)) == payload


def test_load_exact_input_collects_short_reads_until_eof() -> None:
    payload = b"complete-stream-payload"

    assert load_exact_input("-", stdin=_ShortReadStream(payload)) == payload


def test_load_exact_input_suppresses_unexpected_stream_failures() -> None:
    with pytest.raises(CliCoreError) as caught:
        load_exact_input("-", stdin=_FailingStream())

    assert str(caught.value) == "The input is invalid."
    assert "secret-stream-failure" not in repr(caught.value)


@pytest.mark.parametrize(
    "payload",
    (b"", b"x" * MAX_INPUT_BYTES + b"do-not-echo-this-secret"),
)
def test_load_exact_input_rejects_empty_or_oversized_stdin(payload: bytes) -> None:
    secret = "do-not-echo-this-secret"
    with pytest.raises(CliCoreError) as caught:
        load_exact_input("-", stdin=io.BytesIO(payload))

    assert caught.value.failure.category is FailureCategory.INVALID_INPUT
    assert secret not in str(caught.value)
    assert secret not in repr(caught.value)


def test_load_exact_input_reads_only_regular_files(tmp_path: Path) -> None:
    payload_path = tmp_path / "payload.json"
    payload_path.write_bytes(b'{"schema_version":"test/v1"}')

    assert load_exact_input(payload_path) == payload_path.read_bytes()

    directory = tmp_path / "directory"
    directory.mkdir()
    fifo = tmp_path / "fifo"
    os.mkfifo(fifo)
    symlink = tmp_path / "payload-link"
    symlink.symlink_to(payload_path)
    for rejected in (directory, fifo, symlink):
        with pytest.raises(CliCoreError) as caught:
            load_exact_input(rejected)
        assert caught.value.failure.category is FailureCategory.INVALID_INPUT


def test_load_exact_input_does_not_disclose_a_path_or_payload(tmp_path: Path) -> None:
    secret = "secret-input-4d9a7"
    missing = tmp_path / secret

    with pytest.raises(CliCoreError) as caught:
        load_exact_input(missing)

    assert str(caught.value) == "The input is invalid."
    assert secret not in repr(caught.value)


def test_canonical_json_output_is_bytes_with_one_record_terminator() -> None:
    report = make_report(Classification.COMMITTED)

    output = canonical_json_output(report)

    assert type(output) is bytes
    assert output == canonical_json_bytes(report) + b"\n"


def test_canonical_event_jsonl_emits_exact_canonical_records() -> None:
    events = (
        make_investigation_event(InvestigationEventType.LIFECYCLE, sequence=1),
        make_investigation_event(InvestigationEventType.CLASSIFICATION, sequence=2),
    )

    output = canonical_event_jsonl(events)

    assert type(output) is bytes
    assert output == b"".join(canonical_json_bytes(event) + b"\n" for event in events)
    assert [json.loads(line) for line in output.splitlines()] == [
        event.model_dump(mode="json") for event in events
    ]


def test_human_report_views_do_not_render_advisory_or_limitation_text() -> None:
    secret = "operator-secret-38de12"
    report = make_report(Classification.COMMITTED)
    assert report.advisory_explanation is not None
    report = report.model_copy(
        update={
            "advisory_explanation": report.advisory_explanation.model_copy(
                update={"text": secret}
            ),
            "limitations": (secret,),
        }
    )

    status_output = render_human_status(report)
    report_output = render_human_report(report)

    assert type(status_output) is bytes
    assert type(report_output) is bytes
    assert b"Status: COMPLETED" in status_output
    assert b"Classification: COMMITTED" in report_output
    assert b"Action CONTINUE: allowed" in report_output
    assert secret.encode() not in status_output
    assert secret.encode() not in report_output


@pytest.mark.parametrize("event_type", tuple(InvestigationEventType))
def test_human_event_renderer_uses_a_bounded_field_whitelist(
    event_type: InvestigationEventType,
) -> None:
    event = make_investigation_event(event_type)

    output = render_human_event(event)

    assert type(output) is bytes
    assert f"Type: {event_type.value}".encode() in output
    assert event.occurred_at.isoformat().encode() not in output
    assert b"result_sha256" not in output


@pytest.mark.parametrize(
    ("classification", "expected"),
    (
        (Classification.COMMITTED, ExitCode.SUCCESS),
        (Classification.NOT_COMMITTED, ExitCode.SUCCESS),
        (Classification.PARTIAL, ExitCode.UNRESOLVED),
        (Classification.PENDING, ExitCode.UNRESOLVED),
        (Classification.UNKNOWN, ExitCode.UNRESOLVED),
    ),
)
def test_waited_report_exit_code_maps_terminal_classifications(
    classification: Classification,
    expected: ExitCode,
) -> None:
    assert waited_report_exit_code(make_report(classification)) is expected


def test_waited_report_exit_code_enforces_an_explicit_action_requirement() -> None:
    committed = make_report(Classification.COMMITTED)
    unknown = make_report(Classification.UNKNOWN)

    assert (
        waited_report_exit_code(
            committed,
            require_action=RequestedAction.CONTINUE,
        )
        is ExitCode.SUCCESS
    )
    assert (
        waited_report_exit_code(
            committed,
            require_action=RequestedAction.RETRY,
        )
        is ExitCode.POLICY_REFUSAL
    )
    assert (
        waited_report_exit_code(
            unknown,
            require_action=RequestedAction.OBSERVE,
        )
        is ExitCode.UNRESOLVED
    )
    assert (
        waited_report_exit_code(
            unknown,
            require_action=RequestedAction.CONTINUE,
        )
        is ExitCode.POLICY_REFUSAL
    )


def test_export_report_is_canonical_atomic_and_private(tmp_path: Path) -> None:
    report = make_report(Classification.COMMITTED)
    destination = tmp_path / "report.json"

    export_report(report, destination)

    assert destination.read_bytes() == canonical_json_bytes(report)
    assert stat.S_IMODE(destination.stat().st_mode) == 0o600
    assert list(tmp_path.glob(".reconcile-export-*")) == []


def test_export_report_refuses_overwrite_and_symlink_targets(tmp_path: Path) -> None:
    report = make_report(Classification.COMMITTED)
    existing = tmp_path / "existing.json"
    existing.write_bytes(b"preserve-me")
    symlink = tmp_path / "report-link.json"
    symlink.symlink_to(existing)

    for destination in (existing, symlink):
        with pytest.raises(CliCoreError) as caught:
            export_report(report, destination)
        assert caught.value.failure.category is FailureCategory.INVALID_INPUT

    assert existing.read_bytes() == b"preserve-me"
    assert symlink.is_symlink()
    assert list(tmp_path.glob(".reconcile-export-*")) == []


def test_export_report_rejects_a_symlink_parent(tmp_path: Path) -> None:
    actual_parent = tmp_path / "actual"
    actual_parent.mkdir()
    linked_parent = tmp_path / "linked"
    linked_parent.symlink_to(actual_parent, target_is_directory=True)

    with pytest.raises(CliCoreError) as caught:
        export_report(
            make_report(Classification.COMMITTED),
            linked_parent / "report.json",
        )

    assert caught.value.failure.category is FailureCategory.INVALID_INPUT
    assert not (actual_parent / "report.json").exists()


@pytest.mark.parametrize("swap", ("source", "destination"))
def test_export_report_rejects_inode_swaps_during_publication(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    swap: str,
) -> None:
    destination = tmp_path / "report.json"
    original_link = os.link

    def swapped_link(
        source: str | os.PathLike[str],
        target: str | os.PathLike[str],
        *,
        src_dir_fd: int | None = None,
        dst_dir_fd: int | None = None,
        follow_symlinks: bool = True,
    ) -> None:
        if swap == "source":
            os.unlink(source)
            Path(source).write_bytes(b"untrusted-replacement")
        original_link(
            source,
            target,
            src_dir_fd=src_dir_fd,
            dst_dir_fd=dst_dir_fd,
            follow_symlinks=follow_symlinks,
        )
        if swap == "destination":
            os.unlink(target)
            Path(target).write_bytes(b"untrusted-replacement")

    monkeypatch.setattr(os, "link", swapped_link)

    with pytest.raises(CliCoreError) as caught:
        export_report(make_report(Classification.COMMITTED), destination)

    assert caught.value.failure.category is FailureCategory.INVALID_INPUT
    assert not destination.exists()
    assert list(tmp_path.glob(".reconcile-export-*")) == []
