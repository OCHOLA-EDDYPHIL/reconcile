from __future__ import annotations

import hashlib
from dataclasses import dataclass
from pathlib import Path

import pytest

import reconcile.qualification_v2_custody as qualification_v2_custody_module
from reconcile.contracts.base import canonical_json_value_bytes
from reconcile.qualification_v2_custody import (
    QualificationConsumedV2Custody,
    QualificationV2CustodySource,
    QualificationV2UsageTotals,
    _load_consumed_v2_custody,
    canonical_consumed_v2_custody,
)


@dataclass
class _SyntheticCustody:
    source: QualificationV2CustodySource
    expected: QualificationConsumedV2Custody
    documents: dict[str, dict[str, object]]
    paths: dict[str, Path]


def _json_bytes(value: object) -> bytes:
    return canonical_json_value_bytes(value)  # type: ignore[arg-type]


def _replace_file_identity(
    expected: QualificationConsumedV2Custody,
    field_name: str,
    raw: bytes,
) -> QualificationConsumedV2Custody:
    identity = getattr(expected, field_name)
    replacement = identity.model_copy(
        update={
            "sha256": hashlib.sha256(raw).hexdigest(),
            "byte_count": len(raw),
        }
    )
    return expected.model_copy(update={field_name: replacement})


def _write_read_only(path: Path, raw: bytes) -> None:
    path.write_bytes(raw)
    path.chmod(0o400)


def _synthetic_custody(tmp_path: Path) -> _SyntheticCustody:
    canonical = canonical_consumed_v2_custody()
    stage = tmp_path / "evidence" / "development-1"
    stage.mkdir(parents=True)
    stage.chmod(0o700)
    launcher = tmp_path / canonical.launcher.file_name
    launcher_raw = b"#!/usr/bin/env python3\nraise SystemExit(0)\n"
    launcher.write_bytes(launcher_raw)
    launcher.chmod(0o500)

    runtime: dict[str, object] = {
        "schema_version": "reconcile/qualification-runtime-identity/v2",
        "provider_name": "google-vertex-ai",
        "provider_project": "reconcile-dev-260813-14fa6d",
        "configured_model": "gemini-3.5-flash",
        "model_revision": "UNKNOWN",
        "location": "global",
        "max_output_tokens": 1_024,
        "maximum_input_tokens_per_call": 12_000,
        "input_cost_nano_units_per_token": 1_500,
        "output_cost_nano_units_per_token": 9_000,
    }
    runtime_sha = hashlib.sha256(_json_bytes(runtime)).hexdigest()
    common: dict[str, object] = {
        "dispatch_id": "dispatch-001-synthetic",
        "execution_id": "provider-model-revision-preflight",
        "case_id": "provider-model-revision-preflight",
        "repetition": 1,
        "planner_phase": "ACQUIRE_EVIDENCE",
        "execution_basis": "LIVE_PROVIDER",
        "planner_configuration_sha256": runtime_sha,
        "input_sha256": "1" * 64,
        "request_byte_count": 6_698,
        "sealed_generation_request_sha256": "2" * 64,
    }
    count_common: dict[str, object] = {
        **common,
        "attempt_id": "attempt-001-count-tokens",
        "sequence": 1,
        "operation": "COUNT_TOKENS",
        "provider_request_sha256": "3" * 64,
        "paired_count_attempt_id": None,
        "reserved_provider_request_count": 1,
        "reserved_input_tokens": 0,
        "reserved_output_tokens": 0,
        "reserved_cost_nano_units": 0,
    }
    count_start = {
        **count_common,
        "schema_version": "reconcile/qualification-attempt-start/v2",
    }
    count_finish = {
        **count_common,
        "schema_version": "reconcile/qualification-attempt/v2",
        "outcome": "TOKEN_COUNTED",
        "accounting_basis": "NON_BILLABLE",
        "usage_measured": False,
        "counted_input_tokens": 1_089,
        "accounted_input_tokens": 0,
        "accounted_output_tokens": 0,
        "accounted_cost_nano_units": 0,
        "provider_name": "google-vertex-ai",
        "configured_model": "gemini-3.5-flash",
    }
    generate_common: dict[str, object] = {
        **common,
        "attempt_id": "attempt-002-generate",
        "sequence": 2,
        "operation": "GENERATE",
        "provider_request_sha256": None,
        "paired_count_attempt_id": "attempt-001-count-tokens",
        "reserved_provider_request_count": 1,
        "reserved_input_tokens": 1_089,
        "reserved_output_tokens": 1_024,
        "reserved_cost_nano_units": 10_849_500,
    }
    generate_start = {
        **generate_common,
        "schema_version": "reconcile/qualification-attempt-start/v2",
    }
    generate_finish = {
        **generate_common,
        "schema_version": "reconcile/qualification-attempt/v2",
        "outcome": "RESERVATION_EXCEEDED",
        "accounting_basis": "RESERVED",
        "usage_measured": True,
        "failure_category": "reservation-exceeded",
        "measured_input_tokens": 1_734,
        "measured_output_tokens": 1_007,
        "accounted_input_tokens": 1_734,
        "accounted_output_tokens": 1_024,
        "accounted_cost_nano_units": 11_817_000,
        "provider_name": "google-vertex-ai",
        "configured_model": "gemini-3.5-flash",
    }
    historical_attempts = [
        {
            "accounting_basis": "RESERVED",
            "accounted_input_tokens": 11_717,
            "accounted_output_tokens": 1_024,
            "accounted_cost_nano_units": 26_791_500,
            "qualification_evidence_qualifying": False,
        },
        {
            "accounting_basis": "RESERVED",
            "accounted_input_tokens": 8_222,
            "accounted_output_tokens": 16,
            "accounted_cost_nano_units": 12_477_000,
            "qualification_evidence_qualifying": False,
        },
        {
            "accounting_basis": "MEASURED",
            "accounted_input_tokens": 6,
            "accounted_output_tokens": 85,
            "accounted_cost_nano_units": 774_000,
            "qualification_evidence_qualifying": False,
        },
    ]
    prior = {
        "schema_version": "reconcile/qualification-prior-attempt-ledger/v2",
        "attempts": historical_attempts,
        "totals": {
            "model_call_count": 3,
            "input_token_count": 19_945,
            "output_token_count": 1_125,
            "total_token_count": 21_070,
            "model_cost_nano_units": 40_042_500,
            "reserved_usage_count": 2,
            "unexpected_missing_usage_count": 0,
        },
    }
    manifest = {
        "schema_version": "reconcile/qualification-suite-manifest/v1",
        "source_revision": canonical.source_revision,
        "suite_id": canonical.suite_id,
        "provider": {
            "provider_name": "google-vertex-ai",
            "model_name": "gemini-3.5-flash",
            "model_revision": "UNKNOWN",
            "location": "global",
            "max_output_tokens": 1_024,
            "input_cost_nano_units_per_token": 1_500,
            "output_cost_nano_units_per_token": 9_000,
        },
    }
    documents: dict[str, dict[str, object]] = {
        "count_tokens_start": count_start,
        "count_tokens_finish": count_finish,
        "generate_start": generate_start,
        "generate_finish": generate_finish,
        "manifest": manifest,
        "prior_attempt_ledger": prior,
        "runtime_identity": runtime,
    }
    expected = canonical.model_copy(
        update={
            "stage_identifier": "evidence/development-1",
            "launcher": canonical.launcher.model_copy(
                update={
                    "sha256": hashlib.sha256(launcher_raw).hexdigest(),
                    "byte_count": len(launcher_raw),
                }
            ),
        }
    )
    paths: dict[str, Path] = {}
    for field_name, document in documents.items():
        identity = getattr(expected, field_name)
        raw = _json_bytes(document)
        path = stage / identity.file_name
        _write_read_only(path, raw)
        paths[field_name] = path
        expected = _replace_file_identity(expected, field_name, raw)
    return _SyntheticCustody(
        source=QualificationV2CustodySource(
            stage_directory=stage,
            launcher_file=launcher,
        ),
        expected=expected,
        documents=documents,
        paths=paths,
    )


def _rewrite_document(
    custody: _SyntheticCustody,
    field_name: str,
    document: dict[str, object],
    *,
    canonical: bool = True,
) -> None:
    raw = _json_bytes(document)
    if not canonical:
        raw += b"\n"
    path = custody.paths[field_name]
    path.chmod(0o600)
    path.write_bytes(raw)
    path.chmod(0o400)
    custody.documents[field_name] = document
    custody.expected = _replace_file_identity(custody.expected, field_name, raw)


def _all_strings(value: object) -> list[str]:
    if isinstance(value, str):
        return [value]
    if isinstance(value, dict):
        return [item for child in value.values() for item in _all_strings(child)]
    if isinstance(value, list):
        return [item for child in value for item in _all_strings(child)]
    return []


def test_canonical_consumed_v2_custody_freezes_production_constants() -> None:
    custody = canonical_consumed_v2_custody()

    assert custody.schema_version == "reconcile/qualification-consumed-v2-custody/v3"
    assert custody.git_commit == "724b9cdee313d4c6ba0c3cdf94edc4e8ae74e7e8"
    assert custody.source_revision == (
        "83ef813474c4d9d5dbf088dd082cdeea63ab262b0fbe0d951128f6da5e81b8bb"
    )
    assert custody.suite_id == "adaptive-development-one-v1"
    assert custody.qualification_evidence_qualifying is False
    assert custody.stage_identifier == (
        "issue-49-724b9cdee313d4c6ba0c3cdf94edc4e8ae74e7e8/development-1"
    )
    assert custody.stage_mode == 0o700
    assert (
        custody.launcher.file_name,
        custody.launcher.mode,
        custody.launcher.byte_count,
        custody.launcher.sha256,
    ) == (
        "run_issue49_724b9cd.py",
        0o500,
        5_339,
        "a8653134cd055a5b563f9d0e1c4dabae1947e10168392acd3f8451c172c34314",
    )
    assert {
        identity.file_name: (identity.mode, identity.byte_count, identity.sha256)
        for identity in custody.stage_files
    } == {
        "attempt-001-count-tokens-start.json": (
            0o400,
            961,
            "a6b92331e53d4543806052fc7bb0bb0aff19c7f0260ccdbb5e5dbf18e923043a",
        ),
        "attempt-001-count-tokens-finish.json": (
            0o400,
            1_385,
            "7d845542279927eb54be1b4526636ca4df44a23462800bd38c77e380c69a9543",
        ),
        "attempt-002-generate-start.json": (
            0o400,
            926,
            "17f349d7c96b8fc78a8bcb010e0d7e5e38ae677c806028eeee62b7b9f8128a90",
        ),
        "attempt-002-generate-finish.json": (
            0o400,
            1_383,
            "9cbba287e8136805926531038661b8f43d3dd1f047985368f426d9b70e7c1cb7",
        ),
        "manifest.json": (
            0o400,
            6_445,
            "d6fb9b4285b03c32bf3be365e12bda6217c8d83aca87a8e666708cbd03b085f5",
        ),
        "prior-attempt-ledger.json": (
            0o400,
            2_954,
            "eb4d3d2be8f0cc89e3bb2b09b264c75d4785b78e90e42a3be350a30f1092026d",
        ),
        "runtime-identity.json": (
            0o400,
            766,
            "5be6321b3848417cd005cb309a970909aae88cac7a3ce97a208c486e1517ee92",
        ),
    }
    assert custody.historical_totals == QualificationV2UsageTotals(
        model_call_count=3,
        count_tokens_call_count=0,
        provider_request_count=3,
        input_token_count=19_945,
        output_token_count=1_125,
        total_token_count=21_070,
        model_cost_nano_units=40_042_500,
        reserved_usage_count=2,
        unexpected_missing_usage_count=0,
    )
    assert custody.consumed_v2_totals == QualificationV2UsageTotals(
        model_call_count=1,
        count_tokens_call_count=1,
        provider_request_count=2,
        input_token_count=1_734,
        output_token_count=1_024,
        total_token_count=2_758,
        model_cost_nano_units=11_817_000,
        reserved_usage_count=1,
        unexpected_missing_usage_count=0,
    )
    assert custody.combined_totals == QualificationV2UsageTotals(
        model_call_count=4,
        count_tokens_call_count=1,
        provider_request_count=5,
        input_token_count=21_679,
        output_token_count=2_149,
        total_token_count=23_828,
        model_cost_nano_units=51_859_500,
        reserved_usage_count=3,
        unexpected_missing_usage_count=0,
    )
    assert not any(
        value.startswith("/") for value in _all_strings(custody.model_dump(mode="json"))
    )


def test_synthetic_custody_returns_supplied_authority(tmp_path: Path) -> None:
    custody = _synthetic_custody(tmp_path)

    loaded = _load_consumed_v2_custody(custody.source, custody.expected)

    assert loaded is custody.expected


@pytest.mark.parametrize("mutation", ["missing", "extra"])
def test_stage_requires_exact_file_set(tmp_path: Path, mutation: str) -> None:
    custody = _synthetic_custody(tmp_path)
    if mutation == "missing":
        custody.paths["manifest"].unlink()
    else:
        _write_read_only(custody.source.stage_directory / "extra.json", b"{}")

    with pytest.raises(RuntimeError, match="exact custody file set"):
        _load_consumed_v2_custody(custody.source, custody.expected)


def test_stage_file_set_is_revalidated_after_semantics(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    custody = _synthetic_custody(tmp_path)
    original_verify_semantics = qualification_v2_custody_module._verify_semantics

    def verify_then_insert_extra_file(
        documents: dict[str, object],
        expected: QualificationConsumedV2Custody,
    ) -> None:
        original_verify_semantics(documents, expected)
        _write_read_only(
            custody.source.stage_directory / "concurrent-extra.json",
            b"{}",
        )

    monkeypatch.setattr(
        qualification_v2_custody_module,
        "_verify_semantics",
        verify_then_insert_extra_file,
    )

    with pytest.raises(RuntimeError, match="exact custody file set"):
        _load_consumed_v2_custody(custody.source, custody.expected)


@pytest.mark.parametrize("target", ["stage-json", "launcher"])
def test_file_identity_is_revalidated_after_semantics(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    target: str,
) -> None:
    custody = _synthetic_custody(tmp_path)
    original_verify_semantics = qualification_v2_custody_module._verify_semantics
    if target == "stage-json":
        path = custody.paths["manifest"]
        mode = 0o400
    else:
        path = custody.source.launcher_file
        mode = 0o500

    def verify_then_mutate_same_name(
        documents: dict[str, object],
        expected: QualificationConsumedV2Custody,
    ) -> None:
        original_verify_semantics(documents, expected)
        raw = bytearray(path.read_bytes())
        raw[0] ^= 1
        path.chmod(0o600)
        path.write_bytes(raw)
        path.chmod(mode)

    monkeypatch.setattr(
        qualification_v2_custody_module,
        "_verify_semantics",
        verify_then_mutate_same_name,
    )

    with pytest.raises(RuntimeError, match="digest"):
        _load_consumed_v2_custody(custody.source, custody.expected)


def test_symlinked_stage_path_component_is_rejected(tmp_path: Path) -> None:
    custody = _synthetic_custody(tmp_path)
    stage = custody.source.stage_directory
    actual_stage = tmp_path / "actual-development-1"
    stage.rename(actual_stage)
    stage.symlink_to(actual_stage, target_is_directory=True)

    with pytest.raises(RuntimeError, match="symlinked directory"):
        _load_consumed_v2_custody(custody.source, custody.expected)


@pytest.mark.parametrize("target", ["stage", "json", "launcher"])
def test_modes_are_exact(tmp_path: Path, target: str) -> None:
    custody = _synthetic_custody(tmp_path)
    if target == "stage":
        custody.source.stage_directory.chmod(0o755)
    elif target == "json":
        custody.paths["runtime_identity"].chmod(0o600)
    else:
        custody.source.launcher_file.chmod(0o700)

    with pytest.raises(RuntimeError, match="mode"):
        _load_consumed_v2_custody(custody.source, custody.expected)


def test_stage_json_symlink_is_rejected(tmp_path: Path) -> None:
    custody = _synthetic_custody(tmp_path)
    path = custody.paths["runtime_identity"]
    target = tmp_path / "replacement-runtime-identity.json"
    _write_read_only(target, path.read_bytes())
    path.unlink()
    path.symlink_to(target)

    with pytest.raises(RuntimeError, match="unreadable"):
        _load_consumed_v2_custody(custody.source, custody.expected)


def test_launcher_symlink_is_rejected(tmp_path: Path) -> None:
    custody = _synthetic_custody(tmp_path)
    launcher = custody.source.launcher_file
    target = tmp_path / "replacement-launcher.py"
    target.write_bytes(launcher.read_bytes())
    target.chmod(0o500)
    launcher.unlink()
    launcher.symlink_to(target)

    with pytest.raises(RuntimeError, match="missing, symlinked, or unreadable"):
        _load_consumed_v2_custody(custody.source, custody.expected)


def test_same_size_digest_tampering_is_rejected(tmp_path: Path) -> None:
    custody = _synthetic_custody(tmp_path)
    path = custody.paths["manifest"]
    raw = bytearray(path.read_bytes())
    raw[0] ^= 1
    path.chmod(0o600)
    path.write_bytes(raw)
    path.chmod(0o400)

    with pytest.raises(RuntimeError, match="digest"):
        _load_consumed_v2_custody(custody.source, custody.expected)


@pytest.mark.parametrize("target", ["stage-json", "launcher"])
@pytest.mark.parametrize("size_change", ["oversized", "truncated"])
def test_frozen_byte_count_is_checked_before_reading(
    tmp_path: Path,
    target: str,
    size_change: str,
) -> None:
    custody = _synthetic_custody(tmp_path)
    if target == "stage-json":
        path = custody.paths["count_tokens_start"]
        mode = 0o400
    else:
        path = custody.source.launcher_file
        mode = 0o500
    raw = path.read_bytes()
    replacement = raw + b"x" if size_change == "oversized" else raw[:-1]
    path.chmod(0o600)
    path.write_bytes(replacement)
    path.chmod(mode)

    with pytest.raises(RuntimeError, match="byte count changed"):
        _load_consumed_v2_custody(custody.source, custody.expected)


def test_noncanonical_json_is_rejected_after_identity_matches(tmp_path: Path) -> None:
    custody = _synthetic_custody(tmp_path)
    _rewrite_document(
        custody,
        "manifest",
        custody.documents["manifest"],
        canonical=False,
    )

    with pytest.raises(RuntimeError, match="not canonical"):
        _load_consumed_v2_custody(custody.source, custody.expected)


def test_attempt_start_finish_pair_tampering_is_rejected(tmp_path: Path) -> None:
    custody = _synthetic_custody(tmp_path)
    finish = dict(custody.documents["generate_finish"])
    finish["paired_count_attempt_id"] = "attempt-other-count-tokens"
    _rewrite_document(custody, "generate_finish", finish)

    with pytest.raises(RuntimeError, match="do not pair"):
        _load_consumed_v2_custody(custody.source, custody.expected)


def test_historical_totals_tampering_is_rejected(tmp_path: Path) -> None:
    custody = _synthetic_custody(tmp_path)
    prior = dict(custody.documents["prior_attempt_ledger"])
    totals = dict(prior["totals"])  # type: ignore[arg-type]
    totals["input_token_count"] = 19_946
    prior["totals"] = totals
    _rewrite_document(custody, "prior_attempt_ledger", prior)

    with pytest.raises(RuntimeError, match="semantics changed"):
        _load_consumed_v2_custody(custody.source, custody.expected)
