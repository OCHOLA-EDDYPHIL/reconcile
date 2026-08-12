from __future__ import annotations

from collections.abc import Iterable, Mapping
from copy import deepcopy
import hashlib
import json
import math
import os
from pathlib import Path
from typing import Any
from uuid import uuid4


LOCK_SCHEMA_VERSION = "lazarus.benchmark-lock/v1"
LOCK_SECTIONS = ("fixtures", "oracles", "schemas", "prompts", "evaluator")
MODEL_PARAMETER_FIELDS = ("temperature", "top_p", "max_output_tokens")
RETRY_FIELDS = ("max_attempts", "backoff_seconds")


class LockingError(ValueError):
    pass


class LockVerificationError(LockingError):
    def __init__(self, mismatches: Iterable[str]):
        self.mismatches = tuple(mismatches)
        super().__init__("; ".join(self.mismatches))


def canonical_json_bytes(value: Any) -> bytes:
    _reject_non_finite(value)
    try:
        encoded = json.dumps(
            value,
            allow_nan=False,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        )
    except (TypeError, ValueError) as exc:
        raise LockingError(f"value is not canonical JSON: {exc}") from exc
    return encoded.encode("utf-8")


def canonical_sha256(value: Any) -> str:
    return hashlib.sha256(canonical_json_bytes(value)).hexdigest()


def file_sha256(path: str | os.PathLike[str]) -> str:
    source = Path(path)
    try:
        payload = source.read_bytes()
    except OSError as exc:
        raise LockingError(f"cannot hash {source}: {exc}") from exc
    return hashlib.sha256(payload).hexdigest()


def validate_model_settings(settings: Mapping[str, Any]) -> dict[str, Any]:
    if not isinstance(settings, Mapping):
        raise LockingError("model settings must be an object")
    normalized = deepcopy(dict(settings))
    for field in ("provider", "model"):
        if not isinstance(normalized.get(field), str) or not normalized[field].strip():
            raise LockingError(f"model settings require a non-empty {field}")

    parameters = normalized.get("parameters")
    if not isinstance(parameters, Mapping):
        raise LockingError("model settings require a parameters object")
    for field in MODEL_PARAMETER_FIELDS:
        if field not in parameters or isinstance(parameters[field], bool):
            raise LockingError(f"model parameters require {field}")
        if not isinstance(parameters[field], (int, float)):
            raise LockingError(f"model parameter {field} must be numeric")
        if isinstance(parameters[field], float) and not math.isfinite(parameters[field]):
            raise LockingError(f"model parameter {field} must be finite")
    if parameters["max_output_tokens"] <= 0 or int(parameters["max_output_tokens"]) != parameters["max_output_tokens"]:
        raise LockingError("max_output_tokens must be a positive integer")
    if not 0 <= parameters["temperature"] <= 2:
        raise LockingError("temperature must be between 0 and 2")
    if not 0 <= parameters["top_p"] <= 1:
        raise LockingError("top_p must be between 0 and 1")

    retry = normalized.get("retry")
    if not isinstance(retry, Mapping):
        raise LockingError("model settings require a retry object")
    for field in RETRY_FIELDS:
        if field not in retry or isinstance(retry[field], bool):
            raise LockingError(f"retry settings require {field}")
        if not isinstance(retry[field], (int, float)):
            raise LockingError(f"retry setting {field} must be numeric")
        if isinstance(retry[field], float) and not math.isfinite(retry[field]):
            raise LockingError(f"retry setting {field} must be finite")
        if retry[field] < 0:
            raise LockingError(f"retry setting {field} cannot be negative")
    if int(retry["max_attempts"]) != retry["max_attempts"] or retry["max_attempts"] < 1:
        raise LockingError("max_attempts must be a positive integer")

    canonical_json_bytes(normalized)
    return normalized


def build_lock_manifest(
    root: str | os.PathLike[str],
    *,
    fixtures: Iterable[str | os.PathLike[str]],
    oracles: Iterable[str | os.PathLike[str]],
    schemas: Iterable[str | os.PathLike[str]],
    prompts: Iterable[str | os.PathLike[str]],
    evaluator: Iterable[str | os.PathLike[str]],
    model_settings: Mapping[str, Any],
) -> dict[str, Any]:
    base = Path(root).resolve()
    settings = validate_model_settings(model_settings)
    supplied = {
        "fixtures": fixtures,
        "oracles": oracles,
        "schemas": schemas,
        "prompts": prompts,
        "evaluator": evaluator,
    }
    sections: dict[str, Any] = {}
    for name in LOCK_SECTIONS:
        entries = _file_entries(base, supplied[name])
        if not entries:
            raise LockingError(f"lock section {name} cannot be empty")
        sections[name] = {
            "digest": canonical_sha256(entries),
            "files": entries,
        }
    return {
        "schema_version": LOCK_SCHEMA_VERSION,
        "algorithm": "sha256",
        "sections": sections,
        "model_settings": {
            "digest": canonical_sha256(settings),
            "value": settings,
        },
    }


def verify_lock_manifest(
    manifest: Mapping[str, Any] | str | os.PathLike[str],
    root: str | os.PathLike[str],
    *,
    model_settings: Mapping[str, Any] | None = None,
) -> None:
    loaded = _read_manifest(manifest)
    base = Path(root).resolve()
    mismatches: list[str] = []
    if loaded.get("schema_version") != LOCK_SCHEMA_VERSION:
        mismatches.append("unsupported lock schema")
    if loaded.get("algorithm") != "sha256":
        mismatches.append("unsupported lock algorithm")

    sections = loaded.get("sections")
    if not isinstance(sections, Mapping):
        mismatches.append("lock sections are missing")
        sections = {}
    for section_name in LOCK_SECTIONS:
        section = sections.get(section_name)
        if not isinstance(section, Mapping):
            mismatches.append(f"lock section {section_name} is missing")
            continue
        expected_files = section.get("files")
        if not isinstance(expected_files, Mapping) or not expected_files:
            mismatches.append(f"lock section {section_name} has no files")
            continue
        actual_files: dict[str, str] = {}
        for relative, expected_digest in sorted(expected_files.items()):
            if not isinstance(relative, str) or not isinstance(expected_digest, str):
                mismatches.append(f"lock section {section_name} has an invalid entry")
                continue
            try:
                path = _resolve_locked_path(base, relative)
                actual_digest = file_sha256(path)
            except LockingError as exc:
                mismatches.append(str(exc))
                continue
            actual_files[relative] = actual_digest
            if actual_digest != expected_digest:
                mismatches.append(f"digest mismatch: {relative}")
        expected_section_digest = section.get("digest")
        if expected_section_digest != canonical_sha256(dict(sorted(expected_files.items()))):
            mismatches.append(f"section digest mismatch: {section_name}")
        if actual_files and canonical_sha256(actual_files) != expected_section_digest:
            marker = f"section content mismatch: {section_name}"
            if marker not in mismatches:
                mismatches.append(marker)

    settings_section = loaded.get("model_settings")
    if not isinstance(settings_section, Mapping):
        mismatches.append("model settings lock is missing")
    else:
        embedded = settings_section.get("value")
        try:
            validated_embedded = validate_model_settings(embedded)
        except LockingError as exc:
            mismatches.append(f"invalid locked model settings: {exc}")
        else:
            expected_digest = settings_section.get("digest")
            if canonical_sha256(validated_embedded) != expected_digest:
                mismatches.append("model settings digest mismatch")
            if model_settings is not None:
                try:
                    supplied_settings = validate_model_settings(model_settings)
                except LockingError as exc:
                    mismatches.append(f"invalid supplied model settings: {exc}")
                else:
                    if canonical_sha256(supplied_settings) != expected_digest:
                        mismatches.append("supplied model settings do not match the lock")

    if mismatches:
        raise LockVerificationError(dict.fromkeys(mismatches))


def write_lock_manifest(path: str | os.PathLike[str], manifest: Mapping[str, Any]) -> Path:
    destination = Path(path)
    payload = canonical_json_bytes(dict(manifest)) + b"\n"
    _atomic_create(destination, payload)
    return destination


def _reject_non_finite(value: Any) -> None:
    if isinstance(value, float) and not math.isfinite(value):
        raise LockingError("non-finite numbers are not canonical JSON")
    if isinstance(value, Mapping):
        for key, item in value.items():
            if not isinstance(key, str):
                raise LockingError("canonical JSON object keys must be strings")
            _reject_non_finite(item)
    elif isinstance(value, (list, tuple)):
        for item in value:
            _reject_non_finite(item)


def _file_entries(base: Path, paths: Iterable[str | os.PathLike[str]]) -> dict[str, str]:
    files: dict[str, str] = {}
    for supplied in paths:
        unresolved = Path(supplied)
        if not unresolved.is_absolute():
            unresolved = base / unresolved
        if unresolved.is_symlink():
            raise LockingError(f"locked paths cannot be symbolic links: {supplied}")
        candidate = unresolved.resolve()
        try:
            candidate.relative_to(base)
        except ValueError as exc:
            raise LockingError(f"locked path escapes root: {supplied}") from exc
        expanded = sorted(path for path in candidate.rglob("*") if path.is_file()) if candidate.is_dir() else [candidate]
        for path in expanded:
            if path.is_symlink():
                raise LockingError(f"locked paths cannot be symbolic links: {path}")
            try:
                path.resolve().relative_to(base)
            except ValueError as exc:
                raise LockingError(f"locked path escapes root: {path}") from exc
            if not path.is_file():
                raise LockingError(f"locked file does not exist: {path}")
            relative = path.relative_to(base).as_posix()
            if relative in files:
                raise LockingError(f"duplicate locked path: {relative}")
            files[relative] = file_sha256(path)
    return dict(sorted(files.items()))


def _resolve_locked_path(base: Path, relative: str) -> Path:
    if not relative or Path(relative).is_absolute():
        raise LockingError(f"invalid locked path: {relative}")
    path = (base / relative).resolve()
    try:
        path.relative_to(base)
    except ValueError as exc:
        raise LockingError(f"locked path escapes root: {relative}") from exc
    if not path.is_file():
        raise LockingError(f"locked file does not exist: {relative}")
    return path


def _read_manifest(manifest: Mapping[str, Any] | str | os.PathLike[str]) -> dict[str, Any]:
    if isinstance(manifest, Mapping):
        return deepcopy(dict(manifest))
    path = Path(manifest)
    try:
        loaded = json.loads(
            path.read_text(encoding="utf-8"),
            object_pairs_hook=_unique_json_object,
        )
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise LockingError(f"cannot read lock manifest {path}: {exc}") from exc
    if not isinstance(loaded, dict):
        raise LockingError("lock manifest must be an object")
    return loaded


def _unique_json_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise LockingError(f"duplicate JSON object key: {key}")
        value[key] = item
    return value


def _atomic_create(destination: Path, payload: bytes) -> None:
    destination.parent.mkdir(parents=True, exist_ok=True)
    temporary = destination.with_name(f".{destination.name}.{uuid4().hex}.tmp")
    try:
        descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        try:
            os.link(temporary, destination)
        except FileExistsError:
            raise LockingError(f"refusing to overwrite {destination}") from None
    finally:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass
