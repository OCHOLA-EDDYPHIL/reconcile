from __future__ import annotations

from copy import deepcopy
import json
import os
import sqlite3
import tempfile
import time
from collections.abc import Mapping, Sequence
from datetime import datetime, timezone
from decimal import Decimal, InvalidOperation, ROUND_CEILING
from pathlib import Path
from typing import Any

from lazarus.locking import canonical_sha256, file_sha256


_MAXIMUM_CONTROLLED_DELAY_MS = Decimal("60000")
_UNKNOWN_CHECKS = (
    ("integrity", "integrity"),
    ("schema", "schema"),
    ("required_queries", "required_query"),
    ("business_invariants", "business_invariant"),
)
RECOVERY_MATRIX_STATES = (
    "fresh",
    "schema",
    "invariant",
    "stale",
    "rto",
    "cleanup",
)
_EXPECTED_MATRIX_SIGNATURES = {
    "fresh": ("pass", "pass", "pass", "pass", "pass", "pass"),
    "schema": ("fail", "pass", "fail", "pass", "unknown", "pass"),
    "invariant": ("fail", "pass", "fail", "pass", "unknown", "pass"),
    "stale": ("fail", "pass", "pass", "fail", "pass", "pass"),
    "rto": ("fail", "pass", "pass", "pass", "fail", "pass"),
    "cleanup": ("fail", "pass", "pass", "pass", "pass", "fail"),
}
_SIGNATURE_FIELDS = (
    "classification",
    "restore",
    "canary",
    "rpo",
    "rto",
    "cleanup",
)


class RecoveryMatrixError(ValueError):
    pass


def _local_database_authorizer(
    action: int,
    _arg1: str | None,
    _arg2: str | None,
    _database: str | None,
    _source: str | None,
) -> int:
    if action in (sqlite3.SQLITE_ATTACH, sqlite3.SQLITE_DETACH):
        return sqlite3.SQLITE_DENY
    return sqlite3.SQLITE_OK


def _unknown_canary() -> dict[str, Any]:
    return {
        "status": "unknown",
        "checks": [
            {"check_id": check_id, "check_type": check_type, "status": "unknown"}
            for check_id, check_type in _UNKNOWN_CHECKS
        ],
    }


def _nonnegative_decimal(value: object) -> Decimal | None:
    if isinstance(value, bool) or not isinstance(value, (int, float, Decimal)):
        return None
    try:
        number = Decimal(str(value))
    except (InvalidOperation, ValueError):
        return None
    if not number.is_finite() or number < 0:
        return None
    return number


def _display_number(value: Decimal | None) -> int | float | None:
    if value is None:
        return None
    integral = value.to_integral_value()
    if value == integral:
        return int(integral)
    return float(value)


def _elapsed_ms(started_ns: int, completed_ns: int) -> float:
    return round((completed_ns - started_ns) / 1_000_000, 3)


def _timestamp_seconds(value: object) -> Decimal | None:
    numeric = _nonnegative_decimal(value)
    if numeric is not None:
        return numeric
    if not isinstance(value, str) or not value.strip():
        return None

    timestamp = value.strip()
    if timestamp.endswith(("Z", "z")):
        timestamp = f"{timestamp[:-1]}+00:00"
    try:
        parsed = datetime.fromisoformat(timestamp)
    except ValueError:
        return None
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        return None

    utc_value = parsed.astimezone(timezone.utc)
    epoch = datetime(1970, 1, 1, tzinfo=timezone.utc)
    delta = utc_value - epoch
    return (
        Decimal(delta.days * 86_400 + delta.seconds)
        + Decimal(delta.microseconds) / Decimal(1_000_000)
    )


def _rpo_evidence(config: Mapping[str, Any]) -> dict[str, Any]:
    backup_time = _timestamp_seconds(config.get("backup_created_at"))
    reference_time = _timestamp_seconds(config.get("reference_time"))
    objective = _nonnegative_decimal(config.get("rpo_seconds"))
    age = None
    status = "unknown"

    if backup_time is not None and reference_time is not None:
        candidate_age = reference_time - backup_time
        if candidate_age >= 0:
            age = candidate_age
            if objective is not None:
                status = "pass" if age <= objective else "fail"

    return {
        "status": status,
        "age_seconds": _display_number(age),
        "objective_seconds": _display_number(objective),
    }


def _resolve_dump_path(case_dir: str | os.PathLike[str], dump_path: object) -> Path:
    if not isinstance(dump_path, str) or not dump_path.strip():
        raise ValueError("dump_path must be a non-empty relative path")
    relative_path = Path(dump_path)
    if relative_path.is_absolute():
        raise ValueError("dump_path must be relative")

    case_root = Path(case_dir).resolve(strict=True)
    resolved = (case_root / relative_path).resolve(strict=True)
    try:
        resolved.relative_to(case_root)
    except ValueError as error:
        raise ValueError("dump_path must stay inside case_dir") from error
    if not resolved.is_file():
        raise ValueError("dump_path must identify a file")
    return resolved


def _restore_database(
    case_dir: str | os.PathLike[str], config: Mapping[str, Any], database_path: Path
) -> tuple[dict[str, Any], int, int]:
    started = time.monotonic_ns()
    connection: sqlite3.Connection | None = None
    status = "fail"
    try:
        dump_path = _resolve_dump_path(case_dir, config.get("dump_path"))
        dump_sql = dump_path.read_text(encoding="utf-8")
        connection = sqlite3.connect(database_path)
        connection.set_authorizer(_local_database_authorizer)
        connection.execute("PRAGMA journal_mode = MEMORY")
        connection.execute("PRAGMA synchronous = OFF")
        connection.executescript(dump_sql)
        connection.commit()
        status = "pass"
    except (UnicodeError, sqlite3.Error):
        status = "fail"
    except (OSError, RuntimeError, TypeError, ValueError):
        status = "unknown"
    finally:
        if connection is not None:
            connection.close()

    completed = time.monotonic_ns()
    return (
        {"status": status, "elapsed_ms": _elapsed_ms(started, completed)},
        started,
        completed,
    )


def _schema_check(connection: sqlite3.Connection, config: Mapping[str, Any]) -> dict[str, Any]:
    expected_version = config.get("expected_schema_version")
    required_tables = config.get("required_tables")
    configuration_valid = (
        isinstance(expected_version, int)
        and not isinstance(expected_version, bool)
        and expected_version >= 0
        and isinstance(required_tables, Sequence)
        and not isinstance(required_tables, (str, bytes, bytearray))
        and all(isinstance(table, str) and bool(table) for table in required_tables)
        and len(set(required_tables)) == len(required_tables)
    )

    check: dict[str, Any] = {
        "check_id": "schema",
        "check_type": "schema",
        "status": "unknown",
    }
    try:
        actual_version = connection.execute("PRAGMA user_version").fetchone()[0]
        actual_tables = {
            row[0]
            for row in connection.execute(
                "SELECT name FROM sqlite_schema WHERE type = 'table'"
            ).fetchall()
        }
    except sqlite3.Error:
        check["status"] = "fail"
        return check

    if not configuration_valid:
        return check

    missing_tables = sorted(set(required_tables) - actual_tables)
    check["status"] = (
        "pass"
        if actual_version == expected_version and not missing_tables
        else "fail"
    )
    return check


def _integrity_check(connection: sqlite3.Connection) -> dict[str, str]:
    check = {
        "check_id": "integrity",
        "check_type": "integrity",
        "status": "fail",
    }
    try:
        integrity_rows = connection.execute("PRAGMA integrity_check").fetchall()
        foreign_key_rows = connection.execute("PRAGMA foreign_key_check").fetchall()
    except sqlite3.Error:
        return check
    if integrity_rows == [("ok",)] and not foreign_key_rows:
        check["status"] = "pass"
    return check


def _normalized_query_result(rows: list[tuple[Any, ...]]) -> Any:
    normalized_rows = [
        [
            {"hex": value.hex()} if isinstance(value, bytes) else value
            for value in row
        ]
        for row in rows
    ]
    if len(normalized_rows) == 1 and len(normalized_rows[0]) == 1:
        return normalized_rows[0][0]
    return normalized_rows


def _assertion_checks(
    connection: sqlite3.Connection, config: Mapping[str, Any]
) -> list[dict[str, Any]]:
    configured = config.get("assertions")
    if (
        not isinstance(configured, Sequence)
        or isinstance(configured, (str, bytes, bytearray))
        or not configured
    ):
        return [
            {
                "check_id": "required_queries",
                "check_type": "required_query",
                "status": "unknown",
            },
            {
                "check_id": "business_invariants",
                "check_type": "business_invariant",
                "status": "unknown",
            },
        ]

    checks: list[dict[str, Any]] = []
    seen_ids: set[str] = set()
    for index, assertion in enumerate(configured):
        fallback_id = f"assertion_{index}"
        assertion_id = fallback_id
        assertion_id_valid = False
        sql = None
        expected_present = False
        expected = None
        if isinstance(assertion, Mapping):
            candidate_id = assertion.get("assertion_id")
            if isinstance(candidate_id, str) and candidate_id:
                assertion_id = candidate_id
                assertion_id_valid = True
            sql = assertion.get("sql")
            expected_present = "expected" in assertion
            expected = assertion.get("expected")

        query_check: dict[str, Any] = {
            "check_id": f"{assertion_id}:query",
            "check_type": "required_query",
            "assertion_id": assertion_id,
            "status": "unknown",
        }
        invariant_check: dict[str, Any] = {
            "check_id": f"{assertion_id}:invariant",
            "check_type": "business_invariant",
            "assertion_id": assertion_id,
            "status": "unknown",
        }

        configuration_valid = (
            isinstance(assertion, Mapping)
            and assertion_id_valid
            and assertion_id not in seen_ids
            and isinstance(sql, str)
            and bool(sql.strip())
            and expected_present
        )
        seen_ids.add(assertion_id)
        if not configuration_valid:
            checks.extend((query_check, invariant_check))
            continue

        try:
            cursor = connection.execute(sql)
            if cursor.description is None:
                raise sqlite3.OperationalError("assertion did not return rows")
            actual = _normalized_query_result(cursor.fetchall())
        except sqlite3.Error:
            query_check["status"] = "fail"
            checks.extend((query_check, invariant_check))
            continue

        query_check["status"] = "pass"
        invariant_check["status"] = "pass" if actual == expected else "fail"
        invariant_check["expected"] = expected
        invariant_check["actual"] = actual
        checks.extend((query_check, invariant_check))

    return checks


def _run_canary(database_path: Path, config: Mapping[str, Any]) -> dict[str, Any]:
    checks: list[dict[str, Any]] = []
    connection: sqlite3.Connection | None = None
    try:
        connection = sqlite3.connect(f"{database_path.as_uri()}?mode=ro", uri=True)
        connection.set_authorizer(_local_database_authorizer)
        connection.execute("PRAGMA query_only = ON")
        checks.append(_integrity_check(connection))
        checks.append(_schema_check(connection, config))
        checks.extend(_assertion_checks(connection, config))
    except sqlite3.Error:
        failed_checks = _unknown_canary()["checks"]
        failed_checks[0]["status"] = "fail"
        return {
            "status": "fail",
            "checks": failed_checks,
        }
    finally:
        if connection is not None:
            connection.close()

    statuses = {check["status"] for check in checks}
    if "fail" in statuses:
        status = "fail"
    elif statuses == {"pass"}:
        status = "pass"
    else:
        status = "unknown"
    return {"status": status, "checks": checks}


def _minimum_delay_ns(config: Mapping[str, Any]) -> int | None:
    delay_ms = _nonnegative_decimal(config.get("minimum_delay_ms"))
    if delay_ms is None or delay_ms > _MAXIMUM_CONTROLLED_DELAY_MS:
        return None
    return int(
        (delay_ms * Decimal(1_000_000)).to_integral_value(rounding=ROUND_CEILING)
    )


def _wait_for_minimum_elapsed(started: int, delay_ns: int) -> None:
    target = started + delay_ns
    while True:
        remaining = target - time.monotonic_ns()
        if remaining <= 0:
            return
        time.sleep(remaining / 1_000_000_000)


def _rto_evidence(
    config: Mapping[str, Any],
    started: int,
    restore_status: str,
    canary_status: str,
) -> tuple[dict[str, Any], int]:
    objective = _nonnegative_decimal(config.get("rto_ms"))
    delay_ns = _minimum_delay_ns(config)
    if delay_ns is not None:
        _wait_for_minimum_elapsed(started, delay_ns)
    completed = time.monotonic_ns()
    elapsed_ms = _elapsed_ms(started, completed)

    status = "unknown"
    if (
        objective is not None
        and delay_ns is not None
        and restore_status == "pass"
        and canary_status == "pass"
    ):
        status = (
            "pass"
            if Decimal(str(elapsed_ms)) <= objective
            else "fail"
        )
    return (
        {
            "status": status,
            "elapsed_ms": elapsed_ms,
            "objective_ms": _display_number(objective),
        },
        completed,
    )


def _timing_evidence(
    rto_started_ns: int,
    restore_started_ns: int,
    restore_completed_ns: int,
    rto_completed_ns: int,
) -> dict[str, Any]:
    return {
        "clock": "monotonic_ns",
        "rto_started_ns": rto_started_ns,
        "restore_started_ns": restore_started_ns,
        "restore_completed_ns": restore_completed_ns,
        "rto_completed_ns": rto_completed_ns,
    }


def _cleanup_evidence(
    temporary_directory: tempfile.TemporaryDirectory[str], simulate_failure: object
) -> dict[str, str]:
    root = Path(temporary_directory.name)
    if not isinstance(simulate_failure, bool):
        status = "unknown"
    elif simulate_failure:
        status = "fail"
    else:
        try:
            temporary_directory.cleanup()
        except OSError:
            status = "fail"
        else:
            status = "pass" if not root.exists() else "fail"

    if root.exists():
        try:
            temporary_directory.cleanup()
        except OSError:
            pass
    if root.exists():
        status = "fail"
    return {"status": status}


def _classification(*statuses: str) -> str:
    if "fail" in statuses:
        return "fail"
    if all(status == "pass" for status in statuses):
        return "pass"
    return "unknown"


def run_recovery(
    case_dir: str | os.PathLike[str], recovery_config: Mapping[str, Any]
) -> dict[str, Any]:
    config: Mapping[str, Any]
    if isinstance(recovery_config, Mapping):
        config = recovery_config
    else:
        config = {}

    started = time.monotonic_ns()
    restore_started = started
    restore_completed = started
    rto_completed = started
    rpo = _rpo_evidence(config)
    restore: dict[str, Any] = {"status": "fail", "elapsed_ms": 0.0}
    canary = _unknown_canary()
    rto: dict[str, Any] = {
        "status": "unknown",
        "elapsed_ms": 0.0,
        "objective_ms": _display_number(_nonnegative_decimal(config.get("rto_ms"))),
    }
    cleanup = {"status": "fail"}

    try:
        temporary_directory = tempfile.TemporaryDirectory(prefix="lazarus-recovery-")
    except OSError:
        rto_completed = time.monotonic_ns()
        rto["elapsed_ms"] = _elapsed_ms(started, rto_completed)
        classification = _classification(
            restore["status"],
            canary["status"],
            rpo["status"],
            rto["status"],
            cleanup["status"],
        )
        return {
            "restore": restore,
            "canary": canary,
            "rpo": rpo,
            "rto": rto,
            "cleanup": cleanup,
            "classification": classification,
            "timing": _timing_evidence(
                started,
                restore_started,
                restore_completed,
                rto_completed,
            ),
        }

    database_path = Path(temporary_directory.name) / "restored.sqlite3"
    try:
        restore, restore_started, restore_completed = _restore_database(
            case_dir, config, database_path
        )
        if restore["status"] == "pass":
            canary = _run_canary(database_path, config)
        rto, rto_completed = _rto_evidence(
            config, started, restore["status"], canary["status"]
        )
    finally:
        cleanup = _cleanup_evidence(
            temporary_directory, config.get("simulate_cleanup_failure", False)
        )

    classification = _classification(
        restore["status"],
        canary["status"],
        rpo["status"],
        rto["status"],
        cleanup["status"],
    )
    return {
        "restore": restore,
        "canary": canary,
        "rpo": rpo,
        "rto": rto,
        "cleanup": cleanup,
        "classification": classification,
        "timing": _timing_evidence(
            started,
            restore_started,
            restore_completed,
            rto_completed,
        ),
    }


def load_recovery_matrix_inputs(
    fixtures_root: str | os.PathLike[str],
) -> dict[str, Any]:
    root = (Path(fixtures_root) / "recovery").resolve()
    matrix_path = root / "matrix.json"
    try:
        definition = json.loads(
            matrix_path.read_text(encoding="utf-8"),
            object_pairs_hook=_unique_json_object,
        )
    except (OSError, UnicodeError, ValueError) as exc:
        raise RecoveryMatrixError(f"cannot load recovery matrix: {exc}") from exc
    if not isinstance(definition, dict) or set(definition) != {
        "schema_version",
        "base_config",
        "states",
    }:
        raise RecoveryMatrixError("recovery matrix fields do not match the protocol")
    if definition.get("schema_version") != "lazarus.recovery-matrix/v1":
        raise RecoveryMatrixError("unsupported recovery matrix schema")
    base = definition.get("base_config")
    states = definition.get("states")
    if not isinstance(base, dict) or not isinstance(states, dict):
        raise RecoveryMatrixError("recovery matrix config and states must be objects")
    if set(states) != set(RECOVERY_MATRIX_STATES):
        raise RecoveryMatrixError("recovery matrix must define the six registered states")

    matrix_digest = file_sha256(matrix_path)
    normalized_states: dict[str, dict[str, Any]] = {}
    for state in RECOVERY_MATRIX_STATES:
        spec = states[state]
        if not isinstance(spec, dict) or set(spec) != {
            "overrides",
            "expected_signature",
        }:
            raise RecoveryMatrixError(f"recovery state {state} fields are invalid")
        overrides = spec.get("overrides")
        signature = spec.get("expected_signature")
        if not isinstance(overrides, dict) or not isinstance(signature, dict):
            raise RecoveryMatrixError(f"recovery state {state} is invalid")
        if set(signature) != set(_SIGNATURE_FIELDS):
            raise RecoveryMatrixError(f"recovery state {state} signature is incomplete")
        expected_values = tuple(signature[field] for field in _SIGNATURE_FIELDS)
        if expected_values != _EXPECTED_MATRIX_SIGNATURES[state]:
            raise RecoveryMatrixError(f"recovery state {state} signature is not registered")
        config = deepcopy(base)
        config.update(deepcopy(overrides))
        dump_path = config.get("dump_path")
        if not isinstance(dump_path, str) or not dump_path:
            raise RecoveryMatrixError(f"recovery state {state} has no dump path")
        candidate = root / dump_path
        if candidate.is_symlink():
            raise RecoveryMatrixError("recovery matrix dump paths cannot be symbolic links")
        try:
            resolved_dump = candidate.resolve(strict=True)
            resolved_dump.relative_to(root)
        except (OSError, ValueError) as exc:
            raise RecoveryMatrixError(
                f"recovery state {state} dump path is invalid"
            ) from exc
        if not resolved_dump.is_file():
            raise RecoveryMatrixError(f"recovery state {state} dump is not a file")
        fixture_digest = canonical_sha256(
            {
                "matrix_sha256": matrix_digest,
                "state": state,
                "config": config,
                "dump_sha256": file_sha256(resolved_dump),
            }
        )
        normalized_states[state] = {
            "case_id": f"recovery-{state}",
            "config": config,
            "expected_signature": deepcopy(signature),
            "fixture_digest": fixture_digest,
        }
    return {
        "root": root,
        "matrix_sha256": matrix_digest,
        "states": normalized_states,
    }


def run_recovery_matrix(
    fixtures_root: str | os.PathLike[str],
    *,
    protocol_lock_digest: str,
    repeat: int = 20,
) -> dict[str, Any]:
    from lazarus.protocol import validate_recovery_result

    if (
        not isinstance(protocol_lock_digest, str)
        or len(protocol_lock_digest) != 64
        or any(character not in "0123456789abcdef" for character in protocol_lock_digest)
    ):
        raise RecoveryMatrixError("protocol lock digest must be SHA-256")
    if isinstance(repeat, bool) or not isinstance(repeat, int) or repeat < 1:
        raise RecoveryMatrixError("recovery matrix repeat must be a positive integer")
    inputs = load_recovery_matrix_inputs(fixtures_root)
    bundled_states: dict[str, Any] = {}
    for state in RECOVERY_MATRIX_STATES:
        metadata = inputs["states"][state]
        runs: list[dict[str, Any]] = []
        for index in range(1, repeat + 1):
            started_at = _utc_now()
            result = run_recovery(inputs["root"], metadata["config"])
            completed_at = _utc_now()
            result = validate_recovery_result(result)
            if _result_signature(result) != _EXPECTED_MATRIX_SIGNATURES[state]:
                raise RecoveryMatrixError(
                    f"recovery state {state} produced an unexpected signature"
                )
            runs.append(
                {
                    "schema_version": "lazarus.recovery-run-envelope/v1",
                    "case_id": metadata["case_id"],
                    "state": state,
                    "run_id": f"{state}-{index:02d}",
                    "started_at": started_at,
                    "completed_at": completed_at,
                    "protocol_lock_digest": protocol_lock_digest,
                    "fixture_digest": metadata["fixture_digest"],
                    "result_sha256": canonical_sha256(result),
                    "result": result,
                }
            )
        bundled_states[state] = {
            "fixture_digest": metadata["fixture_digest"],
            "expected_signature": deepcopy(metadata["expected_signature"]),
            "runs": runs,
        }
    return {
        "schema_version": "lazarus.recovery-repeatability/v1",
        "protocol_lock_digest": protocol_lock_digest,
        "matrix_sha256": inputs["matrix_sha256"],
        "repeat": repeat,
        "states": bundled_states,
    }


def run_recovery_state_coverage(
    fixtures_root: str | os.PathLike[str],
    *,
    protocol_lock_digest: str,
) -> dict[str, Any]:
    coverage = run_recovery_matrix(
        fixtures_root,
        protocol_lock_digest=protocol_lock_digest,
        repeat=1,
    )
    coverage["schema_version"] = "lazarus.recovery-state-coverage/v1"
    return coverage


def _result_signature(result: Mapping[str, Any]) -> tuple[str, ...]:
    return (
        str(result.get("classification")),
        str(result.get("restore", {}).get("status")),
        str(result.get("canary", {}).get("status")),
        str(result.get("rpo", {}).get("status")),
        str(result.get("rto", {}).get("status")),
        str(result.get("cleanup", {}).get("status")),
    )


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _unique_json_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise ValueError(f"duplicate JSON object key: {key}")
        value[key] = item
    return value


__all__ = [
    "RECOVERY_MATRIX_STATES",
    "RecoveryMatrixError",
    "load_recovery_matrix_inputs",
    "run_recovery",
    "run_recovery_matrix",
    "run_recovery_state_coverage",
]
