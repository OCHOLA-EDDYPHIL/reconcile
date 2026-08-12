from __future__ import annotations

from collections.abc import Iterable, Mapping, Sequence
from copy import deepcopy
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
from typing import Any
from uuid import uuid4


EXECUTION_PLAN_SCHEMA_VERSION = "lazarus.execution-plan/v1"
DIGEST_CHAIN_SCHEMA_VERSION = "lazarus.digest-chain/v1"
SCORE_RECEIPT_SCHEMA_VERSION = "lazarus.score-receipt/v1"
MODEL_ARMS = (
    "b-replay",
    "b-replay-no-alias",
    "b-replay-no-intent",
    "b-replay-no-probe",
    "b-replay-no-incident",
)
DETERMINISTIC_ARMS = ("a1", "a1-rules")
RECOVERY_STATES = ("fresh", "schema", "invariant", "stale", "rto", "cleanup")
MODEL_RUN_IDS = ("run-01", "run-02", "run-03")
_SAFE_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]*$")
_DIGEST = re.compile(r"^[0-9a-f]{64}$")


class ExecutionError(ValueError):
    pass


class InventoryError(ExecutionError):
    def __init__(self, *, missing: Iterable[str] = (), extra: Iterable[str] = (), message: str | None = None):
        self.missing = tuple(sorted(set(missing)))
        self.extra = tuple(sorted(set(extra)))
        parts = []
        if message:
            parts.append(message)
        if self.missing:
            parts.append(f"missing={list(self.missing)}")
        if self.extra:
            parts.append(f"extra={list(self.extra)}")
        super().__init__("; ".join(parts) or "execution inventory mismatch")


def build_execution_plan(case_ids: Sequence[str]) -> dict[str, Any]:
    normalized_cases = _validate_case_ids(case_ids)
    evaluations: list[dict[str, Any]] = []
    sequence = 1

    for arm in DETERMINISTIC_ARMS:
        for case_id in normalized_cases:
            evaluations.append(
                _evaluation_entry(
                    sequence,
                    case_id=case_id,
                    arm=arm,
                    run_id="baseline",
                    invocation_id=None,
                )
            )
            sequence += 1

    model_sequence = 1
    for run_index, run_id in enumerate(MODEL_RUN_IDS):
        for case_index, case_id in enumerate(normalized_cases):
            offset = (run_index + case_index) % len(MODEL_ARMS)
            ordered_arms = MODEL_ARMS[offset:] + MODEL_ARMS[:offset]
            for arm in ordered_arms:
                evaluations.append(
                    _evaluation_entry(
                        sequence,
                        case_id=case_id,
                        arm=arm,
                        run_id=run_id,
                        invocation_id=f"invocation-{model_sequence:03d}",
                    )
                )
                sequence += 1
                model_sequence += 1

    recovery: list[dict[str, Any]] = []
    recovery_sequence = 1
    for state in RECOVERY_STATES:
        for repeat in range(1, 21):
            recovery.append(
                {
                    "recovery_id": f"recovery-{recovery_sequence:03d}",
                    "sequence": recovery_sequence,
                    "state": state,
                    "run_id": f"{state}-{repeat:02d}",
                    "result_path": f"recovery/{state}/{repeat:02d}.json",
                }
            )
            recovery_sequence += 1

    prepared_inputs = [
        {
            "input_id": f"input-{index:03d}",
            "case_id": case_id,
            "arm": arm,
            "path": f"prepared-inputs/{arm}/{case_id}.json",
        }
        for index, (case_id, arm) in enumerate(
            (
                (case_id, arm)
                for case_id in normalized_cases
                for arm in MODEL_ARMS
            ),
            start=1,
        )
    ]
    plan = {
        "schema_version": EXECUTION_PLAN_SCHEMA_VERSION,
        "case_ids": list(normalized_cases),
        "prepared_inputs": prepared_inputs,
        "evaluations": evaluations,
        "recovery": recovery,
        "score_receipt_path": "score/score.json",
    }
    _assert_json(plan)
    return plan


def validate_execution_plan(plan: Mapping[str, Any]) -> dict[str, Any]:
    if not isinstance(plan, Mapping):
        raise ExecutionError("execution plan must be an object")
    normalized = deepcopy(dict(plan))
    required = {
        "schema_version",
        "case_ids",
        "prepared_inputs",
        "evaluations",
        "recovery",
        "score_receipt_path",
    }
    if set(normalized) != required:
        raise ExecutionError("execution plan fields do not match the protocol")
    if normalized.get("schema_version") != EXECUTION_PLAN_SCHEMA_VERSION:
        raise ExecutionError("unsupported execution plan schema")
    cases = _validate_case_ids(normalized.get("case_ids"))
    expected = build_execution_plan(cases)
    if normalized != expected:
        raise ExecutionError("execution plan does not match the fixed protocol")
    _assert_json(normalized)
    return normalized


def expected_execution_paths(
    plan: Mapping[str, Any],
    *,
    include_score: bool = False,
    include_chains: bool = True,
) -> tuple[str, ...]:
    validated = validate_execution_plan(plan)
    paths = {entry["path"] for entry in validated["prepared_inputs"]}
    for entry in validated["evaluations"]:
        paths.add(entry["result_path"])
        if entry["invocation_id"] is not None:
            paths.update(
                {
                    entry["request_path"],
                    entry["raw_response_path"],
                    entry["capture_path"],
                }
            )
            if include_chains:
                paths.add(entry["chain_path"])
    paths.update(entry["result_path"] for entry in validated["recovery"])
    if include_score:
        paths.add(validated["score_receipt_path"])
    return tuple(sorted(paths))


def validate_execution_inventory(
    root: str | os.PathLike[str],
    plan: Mapping[str, Any],
    *,
    include_score: bool = False,
    include_chains: bool = True,
) -> dict[str, str]:
    base = Path(root)
    if base.is_symlink():
        raise InventoryError(message="execution root cannot be a symbolic link")
    if not base.is_dir():
        raise InventoryError(message="execution root must be a directory")
    expected = set(
        expected_execution_paths(
            plan,
            include_score=include_score,
            include_chains=include_chains,
        )
    )
    actual: dict[str, str] = {}
    file_identities: dict[tuple[int, int], str] = {}
    for directory, directory_names, file_names in os.walk(base, followlinks=False):
        current = Path(directory)
        for name in tuple(directory_names):
            candidate = current / name
            if candidate.is_symlink():
                raise InventoryError(message=f"execution inventory contains symbolic link: {candidate}")
        for name in file_names:
            path = current / name
            if path.is_symlink():
                raise InventoryError(message=f"execution inventory contains symbolic link: {path}")
            if not path.is_file():
                raise InventoryError(message=f"execution inventory contains a non-file: {path}")
            relative = path.relative_to(base).as_posix()
            if relative in actual:
                raise InventoryError(message=f"duplicate execution path: {relative}")
            stat = path.stat()
            identity = (stat.st_dev, stat.st_ino)
            if identity in file_identities:
                raise InventoryError(
                    message=(
                        "execution inventory aliases one file at multiple paths: "
                        f"{file_identities[identity]} and {relative}"
                    )
                )
            file_identities[identity] = relative
            actual[relative] = sha256_bytes(path.read_bytes())
    missing = expected - set(actual)
    extra = set(actual) - expected
    if missing or extra:
        raise InventoryError(missing=missing, extra=extra)
    return dict(sorted(actual.items()))


def write_immutable_bytes(path: str | os.PathLike[str], payload: bytes) -> Path:
    if not isinstance(payload, bytes):
        raise TypeError("immutable payload must be bytes")
    destination = Path(path)
    if destination.is_symlink() or any(parent.is_symlink() for parent in destination.parents):
        raise ExecutionError("immutable destination cannot be a symbolic link")
    destination.parent.mkdir(parents=True, exist_ok=True)
    temporary = destination.with_name(f".{destination.name}.{uuid4().hex}.tmp")
    descriptor: int | None = None
    try:
        descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, "wb") as stream:
            descriptor = None
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        try:
            os.link(temporary, destination)
        except FileExistsError:
            raise ExecutionError(f"refusing to overwrite {destination}") from None
        os.chmod(destination, 0o400)
        directory_descriptor = os.open(destination.parent, os.O_RDONLY)
        try:
            os.fsync(directory_descriptor)
        finally:
            os.close(directory_descriptor)
    finally:
        if descriptor is not None:
            os.close(descriptor)
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass
    return destination


def write_immutable_json(path: str | os.PathLike[str], value: Mapping[str, Any]) -> Path:
    if not isinstance(value, Mapping):
        raise TypeError("immutable JSON value must be an object")
    return write_immutable_bytes(path, _canonical_json_bytes(dict(value)) + b"\n")


def build_digest_chain_record(
    evaluation: Mapping[str, Any],
    *,
    request_bytes: bytes,
    raw_response_bytes: bytes,
    capture_bytes: bytes,
    result_bytes: bytes,
) -> dict[str, Any]:
    entry = _validate_model_evaluation(evaluation)
    links = {
        "request_sha256": sha256_bytes(request_bytes),
        "raw_response_sha256": sha256_bytes(raw_response_bytes),
        "capture_sha256": sha256_bytes(capture_bytes),
        "result_sha256": sha256_bytes(result_bytes),
    }
    return {
        "schema_version": DIGEST_CHAIN_SCHEMA_VERSION,
        "execution_id": entry["execution_id"],
        "invocation_id": entry["invocation_id"],
        **links,
        "chain_sha256": sha256_bytes(
            b"\0".join(bytes.fromhex(links[key]) for key in links)
        ),
    }


def verify_digest_chain_record(
    record: Mapping[str, Any],
    evaluation: Mapping[str, Any],
    root: str | os.PathLike[str],
) -> None:
    entry = _validate_model_evaluation(evaluation)
    required = {
        "schema_version",
        "execution_id",
        "invocation_id",
        "request_sha256",
        "raw_response_sha256",
        "capture_sha256",
        "result_sha256",
        "chain_sha256",
    }
    if not isinstance(record, Mapping) or set(record) != required:
        raise ExecutionError("digest chain fields do not match the protocol")
    if record.get("schema_version") != DIGEST_CHAIN_SCHEMA_VERSION:
        raise ExecutionError("unsupported digest chain schema")
    if record.get("execution_id") != entry["execution_id"] or record.get("invocation_id") != entry["invocation_id"]:
        raise ExecutionError("digest chain identity does not match the execution plan")
    base = Path(root)
    files = {
        "request_sha256": entry["request_path"],
        "raw_response_sha256": entry["raw_response_path"],
        "capture_sha256": entry["capture_path"],
        "result_sha256": entry["result_path"],
    }
    actual = {
        field: sha256_bytes(_safe_inventory_file(base, relative).read_bytes())
        for field, relative in files.items()
    }
    if any(record.get(field) != digest for field, digest in actual.items()):
        raise ExecutionError("digest chain file hash mismatch")
    expected_chain = sha256_bytes(
        b"\0".join(bytes.fromhex(actual[field]) for field in actual)
    )
    if record.get("chain_sha256") != expected_chain:
        raise ExecutionError("digest chain terminal hash mismatch")
    try:
        capture = json.loads(
            _safe_inventory_file(base, entry["capture_path"]).read_bytes(),
            object_pairs_hook=_unique_json_mapping,
        )
    except (UnicodeError, ValueError, json.JSONDecodeError) as exc:
        raise ExecutionError("digest chain capture is not strict JSON") from exc
    if (
        not isinstance(capture, Mapping)
        or capture.get("schema_version") != "lazarus.model-capture/v2"
        or capture.get("request_sha256") != actual["request_sha256"]
        or capture.get("raw_response_sha256") != actual["raw_response_sha256"]
    ):
        raise ExecutionError("capture provenance does not match the digest chain")


def write_score_receipt(
    execution_root: str | os.PathLike[str],
    plan: Mapping[str, Any],
    *,
    lock_digest: str,
    inventory_digest: str,
    score: Mapping[str, Any],
) -> Path:
    validated = validate_execution_plan(plan)
    for label, digest in (("lock", lock_digest), ("inventory", inventory_digest)):
        if not isinstance(digest, str) or _DIGEST.fullmatch(digest) is None:
            raise ExecutionError(f"{label} digest must be SHA-256")
    receipt = {
        "schema_version": SCORE_RECEIPT_SCHEMA_VERSION,
        "execution_plan_sha256": sha256_json(validated),
        "lock_sha256": lock_digest,
        "inventory_sha256": inventory_digest,
        "score_sha256": sha256_json(score),
        "score": deepcopy(dict(score)),
    }
    destination = Path(execution_root) / validated["score_receipt_path"]
    return write_immutable_json(destination, receipt)


def sha256_bytes(payload: bytes) -> str:
    if not isinstance(payload, bytes):
        raise TypeError("digest payload must be bytes")
    return hashlib.sha256(payload).hexdigest()


def sha256_json(value: Any) -> str:
    return sha256_bytes(_canonical_json_bytes(value))


def _evaluation_entry(
    sequence: int,
    *,
    case_id: str,
    arm: str,
    run_id: str,
    invocation_id: str | None,
) -> dict[str, Any]:
    execution_id = f"evaluation-{sequence:03d}"
    base = f"evaluations/{execution_id}"
    entry: dict[str, Any] = {
        "execution_id": execution_id,
        "sequence": sequence,
        "case_id": case_id,
        "arm": arm,
        "run_id": run_id,
        "invocation_id": invocation_id,
        "result_path": f"{base}/result.json",
        "request_path": None,
        "raw_response_path": None,
        "capture_path": None,
        "chain_path": None,
    }
    if invocation_id is not None:
        entry.update(
            {
                "request_path": f"{base}/request.json",
                "raw_response_path": f"{base}/raw-response.json",
                "capture_path": f"{base}/capture.json",
                "chain_path": f"{base}/chain.json",
            }
        )
    return entry


def _validate_model_evaluation(evaluation: Mapping[str, Any]) -> dict[str, Any]:
    required = {
        "execution_id",
        "sequence",
        "case_id",
        "arm",
        "run_id",
        "invocation_id",
        "result_path",
        "request_path",
        "raw_response_path",
        "capture_path",
        "chain_path",
    }
    if not isinstance(evaluation, Mapping) or set(evaluation) != required:
        raise ExecutionError("model evaluation fields do not match the protocol")
    if evaluation.get("arm") not in MODEL_ARMS:
        raise ExecutionError("digest chains require a model evaluation")
    entry = deepcopy(dict(evaluation))
    for field in ("execution_id", "case_id", "run_id", "invocation_id"):
        value = entry.get(field)
        if not isinstance(value, str) or _SAFE_IDENTIFIER.fullmatch(value) is None:
            raise ExecutionError(f"model evaluation has an invalid {field}")
    if type(entry.get("sequence")) is not int or entry["sequence"] <= 0:
        raise ExecutionError("model evaluation has an invalid sequence")
    paths = []
    for field in (
        "result_path",
        "request_path",
        "raw_response_path",
        "capture_path",
        "chain_path",
    ):
        value = entry.get(field)
        if not isinstance(value, str):
            raise ExecutionError(f"model evaluation has an invalid {field}")
        pure = PurePosixPath(value)
        if pure.is_absolute() or not pure.parts or ".." in pure.parts:
            raise ExecutionError(f"model evaluation has an invalid {field}")
        paths.append(value)
    if len(set(paths)) != len(paths):
        raise ExecutionError("model evaluation paths must be unique")
    return entry


def _validate_case_ids(case_ids: Any) -> tuple[str, ...]:
    if not isinstance(case_ids, Sequence) or isinstance(case_ids, (str, bytes, bytearray)):
        raise ExecutionError("execution plan case_ids must be an array")
    if len(case_ids) != 12:
        raise ExecutionError("execution plan requires exactly twelve heldout cases")
    if any(not isinstance(case_id, str) or _SAFE_IDENTIFIER.fullmatch(case_id) is None for case_id in case_ids):
        raise ExecutionError("execution plan case identifiers are invalid")
    if len(set(case_ids)) != len(case_ids):
        raise ExecutionError("execution plan case identifiers must be unique")
    if list(case_ids) != sorted(case_ids):
        raise ExecutionError("execution plan case identifiers must be sorted")
    return tuple(case_ids)


def _safe_inventory_file(base: Path, relative: str) -> Path:
    pure = PurePosixPath(relative)
    if pure.is_absolute() or not pure.parts or ".." in pure.parts:
        raise ExecutionError(f"invalid execution path: {relative}")
    candidate = base.joinpath(*pure.parts)
    if candidate.is_symlink() or any(
        parent != base and parent.is_symlink()
        for parent in candidate.parents
        if parent == base or base in parent.parents
    ):
        raise ExecutionError(f"execution path uses a symbolic link: {relative}")
    if not candidate.is_file():
        raise ExecutionError(f"execution file is unavailable: {relative}")
    try:
        candidate.resolve().relative_to(base.resolve())
    except ValueError as exc:
        raise ExecutionError(f"execution path escapes root: {relative}") from exc
    return candidate


def _assert_json(value: Any) -> None:
    _canonical_json_bytes(value)


def _canonical_json_bytes(value: Any) -> bytes:
    try:
        return json.dumps(
            value,
            allow_nan=False,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
    except (TypeError, ValueError, UnicodeEncodeError) as exc:
        raise ExecutionError(f"value is not canonical JSON: {exc}") from exc


def _unique_json_mapping(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise ValueError(f"duplicate JSON object key: {key}")
        value[key] = item
    return value


__all__ = [
    "DETERMINISTIC_ARMS",
    "DIGEST_CHAIN_SCHEMA_VERSION",
    "EXECUTION_PLAN_SCHEMA_VERSION",
    "ExecutionError",
    "InventoryError",
    "MODEL_ARMS",
    "MODEL_RUN_IDS",
    "RECOVERY_STATES",
    "SCORE_RECEIPT_SCHEMA_VERSION",
    "build_digest_chain_record",
    "build_execution_plan",
    "expected_execution_paths",
    "sha256_bytes",
    "sha256_json",
    "validate_execution_inventory",
    "validate_execution_plan",
    "verify_digest_chain_record",
    "write_immutable_bytes",
    "write_immutable_json",
    "write_score_receipt",
]
