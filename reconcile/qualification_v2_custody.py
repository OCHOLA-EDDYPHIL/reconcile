"""Independent custody boundary for the consumed qualification v2 evidence."""

from __future__ import annotations

import hashlib
import json
import os
import stat
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Literal

from pydantic import Field, model_validator

from reconcile.contracts.base import (
    Identifier,
    Sha256Digest,
    StrictModel,
    canonical_json_value_bytes,
    reject_sensitive_values,
)
from reconcile.security import is_sensitive_key

_CUSTODY_VERSION = "reconcile/qualification-consumed-v2-custody/v3"
_GIT_COMMIT = "724b9cdee313d4c6ba0c3cdf94edc4e8ae74e7e8"
_SOURCE_REVISION = "83ef813474c4d9d5dbf088dd082cdeea63ab262b0fbe0d951128f6da5e81b8bb"
_SUITE_ID = "adaptive-development-one-v1"
_STAGE_IDENTIFIER = "issue-49-724b9cdee313d4c6ba0c3cdf94edc4e8ae74e7e8/development-1"
_STAGE_MODE = 0o700
_JSON_MODE = 0o400
_LAUNCHER_MODE = 0o500
_MANIFEST_VERSION = "reconcile/qualification-suite-manifest/v1"
_PRIOR_LEDGER_VERSION = "reconcile/qualification-prior-attempt-ledger/v2"
_RUNTIME_IDENTITY_VERSION = "reconcile/qualification-runtime-identity/v2"


class QualificationV2CustodyError(RuntimeError):
    """Raised when consumed v2 evidence does not match frozen custody."""


@dataclass(frozen=True, slots=True)
class QualificationV2CustodySource:
    """Explicit filesystem locations whose contents may unlock custody."""

    stage_directory: Path
    launcher_file: Path

    def __post_init__(self) -> None:
        object.__setattr__(self, "stage_directory", Path(self.stage_directory))
        object.__setattr__(self, "launcher_file", Path(self.launcher_file))


class QualificationV2UsageTotals(StrictModel):
    """Frozen usage projection shared by historical and consumed evidence."""

    model_call_count: int = Field(ge=0)
    count_tokens_call_count: int = Field(ge=0)
    provider_request_count: int = Field(ge=0)
    input_token_count: int = Field(ge=0)
    output_token_count: int = Field(ge=0)
    total_token_count: int = Field(ge=0)
    model_cost_nano_units: int = Field(ge=0)
    reserved_usage_count: int = Field(ge=0)
    unexpected_missing_usage_count: int = Field(ge=0)

    @model_validator(mode="after")
    def _validate_totals(self) -> QualificationV2UsageTotals:
        if self.total_token_count != self.input_token_count + self.output_token_count:
            raise ValueError("total tokens must equal input plus output tokens")
        if self.provider_request_count != (
            self.model_call_count + self.count_tokens_call_count
        ):
            raise ValueError("provider requests must equal model and count calls")
        if self.reserved_usage_count > self.model_call_count:
            raise ValueError("reserved usage cannot exceed model calls")
        if self.unexpected_missing_usage_count > self.model_call_count:
            raise ValueError("missing usage cannot exceed model calls")
        return self


class _QualificationV2FileIdentity(StrictModel):
    file_name: str = Field(min_length=1, max_length=255)
    sha256: Sha256Digest
    byte_count: int = Field(gt=0)
    mode: Literal[256, 320]  # 0400 or 0500

    @model_validator(mode="after")
    def _validate_name(self) -> _QualificationV2FileIdentity:
        path = PurePosixPath(self.file_name)
        if (
            path.is_absolute()
            or len(path.parts) != 1
            or path.name != self.file_name
            or self.file_name in {".", ".."}
            or "\\" in self.file_name
        ):
            raise ValueError("custody file identities must use a basename")
        return self


class QualificationConsumedV2Custody(StrictModel):
    """Canonical nonqualifying custody retained from development attempt one."""

    schema_version: Literal["reconcile/qualification-consumed-v2-custody/v3"]
    git_commit: str = Field(pattern=r"^[0-9a-f]{40}$")
    source_revision: Sha256Digest
    suite_id: Identifier
    qualification_evidence_qualifying: Literal[False]
    stage_identifier: str = Field(min_length=1, max_length=255)
    stage_mode: Literal[448]  # 0700
    launcher: _QualificationV2FileIdentity
    count_tokens_start: _QualificationV2FileIdentity
    count_tokens_finish: _QualificationV2FileIdentity
    generate_start: _QualificationV2FileIdentity
    generate_finish: _QualificationV2FileIdentity
    manifest: _QualificationV2FileIdentity
    prior_attempt_ledger: _QualificationV2FileIdentity
    runtime_identity: _QualificationV2FileIdentity
    historical_totals: QualificationV2UsageTotals
    consumed_v2_totals: QualificationV2UsageTotals
    combined_totals: QualificationV2UsageTotals

    @model_validator(mode="after")
    def _validate_custody(self) -> QualificationConsumedV2Custody:
        stage = PurePosixPath(self.stage_identifier)
        if (
            stage.is_absolute()
            or stage.as_posix() != self.stage_identifier
            or any(part in {"", ".", ".."} for part in stage.parts)
            or "\\" in self.stage_identifier
        ):
            raise ValueError("stage identifier must be a normalized relative path")
        if self.source_revision != hashlib.sha256(self.git_commit.encode()).hexdigest():
            raise ValueError("source revision must bind the git commit")
        if self.launcher.mode != _LAUNCHER_MODE:
            raise ValueError("launcher custody must require mode 0500")
        identities = self.stage_files
        if any(identity.mode != _JSON_MODE for identity in identities):
            raise ValueError("stage JSON custody must require mode 0400")
        if len({identity.file_name for identity in identities}) != len(identities):
            raise ValueError("stage file identities must be unique")
        if self.combined_totals != _add_totals(
            self.historical_totals, self.consumed_v2_totals
        ):
            raise ValueError("combined totals must add historical and consumed totals")
        return self

    @property
    def stage_files(self) -> tuple[_QualificationV2FileIdentity, ...]:
        return (
            self.count_tokens_start,
            self.count_tokens_finish,
            self.generate_start,
            self.generate_finish,
            self.manifest,
            self.prior_attempt_ledger,
            self.runtime_identity,
        )


def _totals(
    *,
    model_calls: int,
    count_calls: int,
    input_tokens: int,
    output_tokens: int,
    cost: int,
    reserved: int,
    unexpected_missing: int,
) -> QualificationV2UsageTotals:
    return QualificationV2UsageTotals(
        model_call_count=model_calls,
        count_tokens_call_count=count_calls,
        provider_request_count=model_calls + count_calls,
        input_token_count=input_tokens,
        output_token_count=output_tokens,
        total_token_count=input_tokens + output_tokens,
        model_cost_nano_units=cost,
        reserved_usage_count=reserved,
        unexpected_missing_usage_count=unexpected_missing,
    )


def _add_totals(
    left: QualificationV2UsageTotals,
    right: QualificationV2UsageTotals,
) -> QualificationV2UsageTotals:
    return QualificationV2UsageTotals(
        **{
            field: getattr(left, field) + getattr(right, field)
            for field in QualificationV2UsageTotals.model_fields
        }
    )


def _identity(
    file_name: str, sha256: str, byte_count: int, mode: Literal[256, 320]
) -> _QualificationV2FileIdentity:
    return _QualificationV2FileIdentity(
        file_name=file_name,
        sha256=sha256,
        byte_count=byte_count,
        mode=mode,
    )


def canonical_consumed_v2_custody() -> QualificationConsumedV2Custody:
    """Return the in-code authority for the single consumed v2 evidence set."""

    historical = _totals(
        model_calls=3,
        count_calls=0,
        input_tokens=19_945,
        output_tokens=1_125,
        cost=40_042_500,
        reserved=2,
        unexpected_missing=0,
    )
    consumed = _totals(
        model_calls=1,
        count_calls=1,
        input_tokens=1_734,
        output_tokens=1_024,
        cost=11_817_000,
        reserved=1,
        unexpected_missing=0,
    )
    return QualificationConsumedV2Custody(
        schema_version=_CUSTODY_VERSION,
        git_commit=_GIT_COMMIT,
        source_revision=_SOURCE_REVISION,
        suite_id=_SUITE_ID,
        qualification_evidence_qualifying=False,
        stage_identifier=_STAGE_IDENTIFIER,
        stage_mode=_STAGE_MODE,
        launcher=_identity(
            "run_issue49_724b9cd.py",
            "a8653134cd055a5b563f9d0e1c4dabae1947e10168392acd3f8451c172c34314",
            5_339,
            _LAUNCHER_MODE,
        ),
        count_tokens_start=_identity(
            "attempt-001-count-tokens-start.json",
            "a6b92331e53d4543806052fc7bb0bb0aff19c7f0260ccdbb5e5dbf18e923043a",
            961,
            _JSON_MODE,
        ),
        count_tokens_finish=_identity(
            "attempt-001-count-tokens-finish.json",
            "7d845542279927eb54be1b4526636ca4df44a23462800bd38c77e380c69a9543",
            1_385,
            _JSON_MODE,
        ),
        generate_start=_identity(
            "attempt-002-generate-start.json",
            "17f349d7c96b8fc78a8bcb010e0d7e5e38ae677c806028eeee62b7b9f8128a90",
            926,
            _JSON_MODE,
        ),
        generate_finish=_identity(
            "attempt-002-generate-finish.json",
            "9cbba287e8136805926531038661b8f43d3dd1f047985368f426d9b70e7c1cb7",
            1_383,
            _JSON_MODE,
        ),
        manifest=_identity(
            "manifest.json",
            "d6fb9b4285b03c32bf3be365e12bda6217c8d83aca87a8e666708cbd03b085f5",
            6_445,
            _JSON_MODE,
        ),
        prior_attempt_ledger=_identity(
            "prior-attempt-ledger.json",
            "eb4d3d2be8f0cc89e3bb2b09b264c75d4785b78e90e42a3be350a30f1092026d",
            2_954,
            _JSON_MODE,
        ),
        runtime_identity=_identity(
            "runtime-identity.json",
            "5be6321b3848417cd005cb309a970909aae88cac7a3ce97a208c486e1517ee92",
            766,
            _JSON_MODE,
        ),
        historical_totals=historical,
        consumed_v2_totals=consumed,
        combined_totals=_add_totals(historical, consumed),
    )


def load_consumed_v2_custody(
    source: QualificationV2CustodySource,
) -> QualificationConsumedV2Custody:
    """Verify the production evidence and return only the in-code authority."""

    return _load_consumed_v2_custody(source, canonical_consumed_v2_custody())


def _load_consumed_v2_custody(
    source: QualificationV2CustodySource,
    expected: QualificationConsumedV2Custody,
) -> QualificationConsumedV2Custody:
    """Verify a source against supplied custody; intended for synthetic tests."""

    if not isinstance(source, QualificationV2CustodySource):
        raise TypeError("source must be QualificationV2CustodySource")
    if not isinstance(expected, QualificationConsumedV2Custody):
        raise TypeError("expected must be QualificationConsumedV2Custody")
    stage_suffix = tuple(PurePosixPath(expected.stage_identifier).parts)
    if tuple(Path(source.stage_directory).parts[-len(stage_suffix) :]) != stage_suffix:
        raise QualificationV2CustodyError("stage directory identity changed")
    if Path(source.launcher_file).name != expected.launcher.file_name:
        raise QualificationV2CustodyError("launcher file identity changed")

    stage_fd = _open_directory_without_symlinks(source.stage_directory)
    try:
        _require_mode(os.fstat(stage_fd), expected.stage_mode, "stage directory")
        expected_names = {identity.file_name for identity in expected.stage_files}
        _require_exact_stage_file_set(stage_fd, expected_names)
        documents = _read_verified_stage_documents(stage_fd, expected)
        _read_verified_launcher(source, expected)
        _verify_semantics(documents, expected)

        # Revalidate every byte and mode after semantic processing so a
        # same-name replacement or in-place mutation cannot pass the initial
        # snapshot and remain present when custody is accepted.
        _require_mode(os.fstat(stage_fd), expected.stage_mode, "stage directory")
        _require_exact_stage_file_set(stage_fd, expected_names)
        if _read_verified_stage_documents(stage_fd, expected) != documents:
            raise QualificationV2CustodyError("stage custody changed during validation")
        _read_verified_launcher(source, expected)
        _require_mode(os.fstat(stage_fd), expected.stage_mode, "stage directory")
        _require_exact_stage_file_set(stage_fd, expected_names)
    finally:
        os.close(stage_fd)
    return expected


def _require_exact_stage_file_set(stage_fd: int, expected_names: set[str]) -> None:
    if set(os.listdir(stage_fd)) != expected_names:
        raise QualificationV2CustodyError(
            "stage directory does not contain the exact custody file set"
        )


def _read_verified_stage_documents(
    stage_fd: int,
    expected: QualificationConsumedV2Custody,
) -> dict[str, object]:
    return {
        identity.file_name: _read_stage_json(stage_fd, identity)
        for identity in expected.stage_files
    }


def _read_verified_launcher(
    source: QualificationV2CustodySource,
    expected: QualificationConsumedV2Custody,
) -> None:
    launcher = _read_file_without_symlinks(
        source.launcher_file,
        expected.launcher.mode,
        expected.launcher.byte_count,
    )
    _verify_bytes(launcher, expected.launcher, "launcher")


def _open_directory_without_symlinks(path: Path) -> int:
    if ".." in Path(path).parts:
        raise QualificationV2CustodyError("custody paths may not traverse parents")
    absolute = os.path.abspath(os.fspath(path))
    parts = Path(absolute).parts
    if not parts or parts[0] != os.sep:
        raise QualificationV2CustodyError("custody path must resolve beneath root")
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
    descriptor = os.open(os.sep, flags)
    try:
        for part in parts[1:]:
            next_descriptor = os.open(part, flags, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = next_descriptor
        if not stat.S_ISDIR(os.fstat(descriptor).st_mode):
            raise QualificationV2CustodyError("custody directory is not regular")
        return descriptor
    except (OSError, QualificationV2CustodyError) as error:
        os.close(descriptor)
        if isinstance(error, QualificationV2CustodyError):
            raise
        raise QualificationV2CustodyError(
            "custody path contains a missing or symlinked directory"
        ) from error


def _read_file_without_symlinks(
    path: Path,
    expected_mode: int,
    expected_byte_count: int,
) -> bytes:
    if ".." in Path(path).parts:
        raise QualificationV2CustodyError("custody paths may not traverse parents")
    absolute = Path(os.path.abspath(os.fspath(path)))
    parent_fd = _open_directory_without_symlinks(absolute.parent)
    try:
        descriptor = os.open(
            absolute.name,
            os.O_RDONLY | os.O_NOFOLLOW,
            dir_fd=parent_fd,
        )
    except OSError as error:
        raise QualificationV2CustodyError(
            "custody file is missing, symlinked, or unreadable"
        ) from error
    finally:
        os.close(parent_fd)
    try:
        status = os.fstat(descriptor)
        if not stat.S_ISREG(status.st_mode):
            raise QualificationV2CustodyError("custody file is not regular")
        _require_mode(status, expected_mode, "custody file")
        _require_byte_count(status, expected_byte_count, "custody file")
        return _read_all(descriptor, expected_byte_count, "custody file")
    finally:
        os.close(descriptor)


def _read_stage_json(
    stage_fd: int,
    identity: _QualificationV2FileIdentity,
) -> object:
    try:
        descriptor = os.open(
            identity.file_name,
            os.O_RDONLY | os.O_NOFOLLOW,
            dir_fd=stage_fd,
        )
    except OSError as error:
        raise QualificationV2CustodyError(
            f"custody JSON {identity.file_name!r} is unreadable"
        ) from error
    try:
        status = os.fstat(descriptor)
        if not stat.S_ISREG(status.st_mode):
            raise QualificationV2CustodyError("custody JSON is not a regular file")
        _require_mode(status, identity.mode, "custody JSON")
        _require_byte_count(status, identity.byte_count, identity.file_name)
        raw = _read_all(descriptor, identity.byte_count, identity.file_name)
    finally:
        os.close(descriptor)
    _verify_bytes(raw, identity, identity.file_name)
    try:
        document = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise QualificationV2CustodyError("custody JSON is invalid") from error
    try:
        if raw != canonical_json_value_bytes(document):
            raise QualificationV2CustodyError("custody JSON is not canonical")
        _reject_artifact_secret_keys(document)
        reject_sensitive_values(document)
    except (TypeError, ValueError) as error:
        raise QualificationV2CustodyError(
            "custody JSON is noncanonical or secret-bearing"
        ) from error
    return document


def _read_all(descriptor: int, expected_byte_count: int, label: str) -> bytes:
    chunks: list[bytes] = []
    remaining = expected_byte_count + 1
    while remaining > 0 and (chunk := os.read(descriptor, min(65_536, remaining))):
        chunks.append(chunk)
        remaining -= len(chunk)
    raw = b"".join(chunks)
    if len(raw) > expected_byte_count:
        raise QualificationV2CustodyError(f"{label} byte count changed")
    return raw


def _require_mode(status: os.stat_result, expected: int, label: str) -> None:
    if stat.S_IMODE(status.st_mode) != expected:
        raise QualificationV2CustodyError(f"{label} mode does not match frozen custody")


def _require_byte_count(
    status: os.stat_result,
    expected: int,
    label: str,
) -> None:
    if status.st_size != expected:
        raise QualificationV2CustodyError(f"{label} byte count changed")


def _verify_bytes(
    raw: bytes,
    identity: _QualificationV2FileIdentity,
    label: str,
) -> None:
    if len(raw) != identity.byte_count:
        raise QualificationV2CustodyError(f"{label} byte count changed")
    if hashlib.sha256(raw).hexdigest() != identity.sha256:
        raise QualificationV2CustodyError(f"{label} digest changed")


def _reject_artifact_secret_keys(value: object) -> None:
    if isinstance(value, dict):
        for key, item in value.items():
            metric_key = isinstance(key, str) and key.endswith(
                ("_tokens", "_token_count", "_per_token")
            )
            if is_sensitive_key(key) and not metric_key:
                raise ValueError("secret-bearing fields are not allowed")
            _reject_artifact_secret_keys(item)
    elif isinstance(value, list):
        for item in value:
            _reject_artifact_secret_keys(item)


def _mapping(value: object, label: str) -> dict[str, object]:
    if not isinstance(value, dict) or not all(isinstance(key, str) for key in value):
        raise QualificationV2CustodyError(f"{label} must be a JSON object")
    return value


def _integer(mapping: dict[str, object], key: str) -> int:
    value = mapping.get(key)
    if type(value) is not int or value < 0:
        raise QualificationV2CustodyError(f"{key} must be a nonnegative integer")
    return value


def _require_equal(mapping: dict[str, object], **values: object) -> None:
    if any(
        type(mapping.get(key)) is not type(value) or mapping.get(key) != value
        for key, value in values.items()
    ):
        raise QualificationV2CustodyError("custody evidence semantics changed")


def _verify_semantics(
    documents: dict[str, object],
    expected: QualificationConsumedV2Custody,
) -> None:
    def document(identity: _QualificationV2FileIdentity) -> dict[str, object]:
        return _mapping(documents[identity.file_name], identity.file_name)

    manifest = document(expected.manifest)
    prior = document(expected.prior_attempt_ledger)
    runtime = document(expected.runtime_identity)
    count_start = document(expected.count_tokens_start)
    count_finish = document(expected.count_tokens_finish)
    generate_start = document(expected.generate_start)
    generate_finish = document(expected.generate_finish)

    _require_equal(
        manifest,
        schema_version=_MANIFEST_VERSION,
        source_revision=expected.source_revision,
        suite_id=expected.suite_id,
    )
    _require_equal(prior, schema_version=_PRIOR_LEDGER_VERSION)
    _require_equal(runtime, schema_version=_RUNTIME_IDENTITY_VERSION)
    if (
        expected.source_revision
        != hashlib.sha256(expected.git_commit.encode()).hexdigest()
    ):
        raise QualificationV2CustodyError("source revision does not bind commit")

    runtime_sha = expected.runtime_identity.sha256
    for attempt in (count_start, count_finish, generate_start, generate_finish):
        _require_equal(attempt, planner_configuration_sha256=runtime_sha)
    provider = _mapping(manifest.get("provider"), "manifest provider")
    _require_equal(
        provider,
        provider_name=runtime.get("provider_name"),
        model_name=runtime.get("configured_model"),
        model_revision=runtime.get("model_revision"),
        location=runtime.get("location"),
        max_output_tokens=runtime.get("max_output_tokens"),
        input_cost_nano_units_per_token=runtime.get("input_cost_nano_units_per_token"),
        output_cost_nano_units_per_token=runtime.get(
            "output_cost_nano_units_per_token"
        ),
    )
    for finish in (count_finish, generate_finish):
        _require_equal(
            finish,
            provider_name=runtime.get("provider_name"),
            configured_model=runtime.get("configured_model"),
        )
    _verify_attempt_pair(count_start, count_finish)
    _verify_attempt_pair(generate_start, generate_finish)
    _verify_consumed_pairing(count_start, count_finish, generate_start, generate_finish)

    historical = _derive_historical_totals(prior, runtime)
    consumed = _derive_consumed_totals(
        count_start, count_finish, generate_start, generate_finish, runtime
    )
    if historical != expected.historical_totals:
        raise QualificationV2CustodyError("historical usage totals changed")
    if consumed != expected.consumed_v2_totals:
        raise QualificationV2CustodyError("consumed v2 usage totals changed")
    if _add_totals(historical, consumed) != expected.combined_totals:
        raise QualificationV2CustodyError("combined usage totals changed")


_PAIR_FIELDS = (
    "attempt_id",
    "sequence",
    "dispatch_id",
    "execution_id",
    "case_id",
    "repetition",
    "planner_phase",
    "operation",
    "execution_basis",
    "planner_configuration_sha256",
    "input_sha256",
    "request_byte_count",
    "sealed_generation_request_sha256",
    "provider_request_sha256",
    "paired_count_attempt_id",
    "reserved_provider_request_count",
    "reserved_input_tokens",
    "reserved_output_tokens",
    "reserved_cost_nano_units",
)


def _verify_attempt_pair(start: dict[str, object], finish: dict[str, object]) -> None:
    _require_equal(start, schema_version="reconcile/qualification-attempt-start/v2")
    _require_equal(finish, schema_version="reconcile/qualification-attempt/v2")
    if any(
        field not in start
        or field not in finish
        or type(start[field]) is not type(finish[field])
        or start[field] != finish[field]
        for field in _PAIR_FIELDS
    ):
        raise QualificationV2CustodyError("attempt start and finish do not pair")


def _verify_consumed_pairing(
    count_start: dict[str, object],
    count_finish: dict[str, object],
    generate_start: dict[str, object],
    generate_finish: dict[str, object],
) -> None:
    _require_equal(
        count_start,
        sequence=1,
        operation="COUNT_TOKENS",
        execution_basis="LIVE_PROVIDER",
        paired_count_attempt_id=None,
        reserved_provider_request_count=1,
        reserved_input_tokens=0,
        reserved_output_tokens=0,
        reserved_cost_nano_units=0,
    )
    _require_equal(
        count_finish,
        outcome="TOKEN_COUNTED",
        accounting_basis="NON_BILLABLE",
        usage_measured=False,
        accounted_input_tokens=0,
        accounted_output_tokens=0,
        accounted_cost_nano_units=0,
    )
    counted_input = _integer(count_finish, "counted_input_tokens")
    _require_equal(
        generate_start,
        sequence=2,
        operation="GENERATE",
        execution_basis="LIVE_PROVIDER",
        paired_count_attempt_id=count_start.get("attempt_id"),
        reserved_provider_request_count=1,
        reserved_input_tokens=counted_input,
        reserved_output_tokens=1_024,
    )
    _require_equal(
        generate_finish,
        outcome="RESERVATION_EXCEEDED",
        accounting_basis="RESERVED",
        usage_measured=True,
        failure_category="reservation-exceeded",
    )
    shared = (
        "dispatch_id",
        "execution_id",
        "case_id",
        "repetition",
        "planner_phase",
        "execution_basis",
        "planner_configuration_sha256",
        "input_sha256",
        "request_byte_count",
        "sealed_generation_request_sha256",
    )
    if any(
        field not in count_start
        or field not in generate_start
        or type(count_start[field]) is not type(generate_start[field])
        or count_start[field] != generate_start[field]
        for field in shared
    ):
        raise QualificationV2CustodyError("count and generate attempts do not pair")


def _runtime_prices(runtime: dict[str, object]) -> tuple[int, int]:
    input_price = _integer(runtime, "input_cost_nano_units_per_token")
    output_price = _integer(runtime, "output_cost_nano_units_per_token")
    _require_equal(
        runtime,
        provider_name="google-vertex-ai",
        provider_project="example-project-id",
        configured_model="gemini-3.5-flash",
        model_revision="UNKNOWN",
        location="global",
        max_output_tokens=1_024,
        maximum_input_tokens_per_call=12_000,
    )
    if (input_price, output_price) != (1_500, 9_000):
        raise QualificationV2CustodyError("runtime prices changed")
    return input_price, output_price


def _derive_historical_totals(
    prior: dict[str, object], runtime: dict[str, object]
) -> QualificationV2UsageTotals:
    attempts_value = prior.get("attempts")
    if not isinstance(attempts_value, list) or len(attempts_value) != 3:
        raise QualificationV2CustodyError("historical attempt ledger changed")
    attempts = [_mapping(value, "historical attempt") for value in attempts_value]
    input_price, output_price = _runtime_prices(runtime)
    inputs = sum(_integer(attempt, "accounted_input_tokens") for attempt in attempts)
    outputs = sum(_integer(attempt, "accounted_output_tokens") for attempt in attempts)
    costs = sum(_integer(attempt, "accounted_cost_nano_units") for attempt in attempts)
    reserved = sum(
        attempt.get("accounting_basis") == "RESERVED" for attempt in attempts
    )
    if any(
        attempt.get("qualification_evidence_qualifying") is not False
        for attempt in attempts
    ):
        raise QualificationV2CustodyError("historical evidence became qualifying")
    if any(
        _integer(attempt, "accounted_cost_nano_units")
        != _integer(attempt, "accounted_input_tokens") * input_price
        + _integer(attempt, "accounted_output_tokens") * output_price
        for attempt in attempts
    ):
        raise QualificationV2CustodyError("historical cost arithmetic changed")
    totals = _mapping(prior.get("totals"), "historical totals")
    _require_equal(
        totals,
        model_call_count=3,
        input_token_count=inputs,
        output_token_count=outputs,
        total_token_count=inputs + outputs,
        model_cost_nano_units=costs,
        reserved_usage_count=reserved,
        unexpected_missing_usage_count=0,
    )
    return _totals(
        model_calls=3,
        count_calls=0,
        input_tokens=inputs,
        output_tokens=outputs,
        cost=costs,
        reserved=reserved,
        unexpected_missing=0,
    )


def _derive_consumed_totals(
    count_start: dict[str, object],
    count_finish: dict[str, object],
    generate_start: dict[str, object],
    generate_finish: dict[str, object],
    runtime: dict[str, object],
) -> QualificationV2UsageTotals:
    del count_start, generate_start
    input_price, output_price = _runtime_prices(runtime)
    input_tokens = _integer(generate_finish, "accounted_input_tokens")
    output_tokens = _integer(generate_finish, "accounted_output_tokens")
    cost = _integer(generate_finish, "accounted_cost_nano_units")
    reserved_input = _integer(generate_finish, "reserved_input_tokens")
    reserved_output = _integer(generate_finish, "reserved_output_tokens")
    reserved_cost = _integer(generate_finish, "reserved_cost_nano_units")
    measured_input = _integer(generate_finish, "measured_input_tokens")
    measured_output = _integer(generate_finish, "measured_output_tokens")
    if reserved_cost != reserved_input * input_price + reserved_output * output_price:
        raise QualificationV2CustodyError("consumed reservation arithmetic changed")
    if input_tokens != max(reserved_input, measured_input) or output_tokens != max(
        reserved_output, measured_output
    ):
        raise QualificationV2CustodyError("consumed accounting basis changed")
    if cost != input_tokens * input_price + output_tokens * output_price:
        raise QualificationV2CustodyError("consumed cost arithmetic changed")
    if _integer(count_finish, "accounted_cost_nano_units") != 0:
        raise QualificationV2CustodyError("count operation became billable")
    return _totals(
        model_calls=1,
        count_calls=1,
        input_tokens=input_tokens,
        output_tokens=output_tokens,
        cost=cost,
        reserved=int(generate_finish.get("accounting_basis") == "RESERVED"),
        unexpected_missing=int(generate_finish.get("usage_measured") is not True),
    )


__all__ = [
    "QualificationConsumedV2Custody",
    "QualificationV2CustodySource",
    "QualificationV2UsageTotals",
    "canonical_consumed_v2_custody",
    "load_consumed_v2_custody",
]
