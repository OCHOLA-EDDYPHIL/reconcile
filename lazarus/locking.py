from __future__ import annotations

from collections.abc import Iterable, Mapping
from copy import deepcopy
import hashlib
import json
import math
import os
from pathlib import Path
import subprocess
from typing import Any
from uuid import uuid4

from lazarus.execution import validate_execution_plan


LOCK_SCHEMA_VERSION = "lazarus.benchmark-lock/v1"
LOCK_V2_SCHEMA_VERSION = "lazarus.benchmark-lock/v2"
CALIBRATION_LOCK_SCHEMA_VERSION = "lazarus.calibration-lock/v1"
CALIBRATION_PLAN_SCHEMA_VERSION = "lazarus.calibration-capture-plan/v1"
LOCK_SECTIONS = ("fixtures", "oracles", "schemas", "prompts", "evaluator")
LOCK_V2_SECTIONS = ("fixtures", "schemas", "prompts", "evaluator", "prepared_inputs")
CALIBRATION_LOCK_SECTIONS = (
    "fixtures",
    "oracles",
    "schemas",
    "prompts",
    "evaluator",
    "prepared_inputs",
)
MODEL_PARAMETER_FIELDS = ("temperature", "top_p", "max_output_tokens")
RETRY_FIELDS = ("max_attempts", "backoff_seconds")
GEMINI_MODEL_SETTINGS_FIELDS = {
    "provider",
    "api_version",
    "endpoint",
    "model",
    "catalog_model_version",
    "resolved_model_version",
    "parameters",
    "thinking",
    "request",
    "retry",
}
GEMINI_PARAMETER_FIELDS = {
    "max_output_tokens",
    "response_mime_type",
    "response_schema_sha256",
}


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


def validate_model_settings(
    settings: Mapping[str, Any], *, require_gemini: bool = False
) -> dict[str, Any]:
    if not isinstance(settings, Mapping):
        raise LockingError("model settings must be an object")
    normalized = deepcopy(dict(settings))
    if set(normalized) == GEMINI_MODEL_SETTINGS_FIELDS:
        return _validate_gemini_model_settings(normalized)
    if require_gemini:
        raise LockingError("lock v2 requires the exact Gemini REST settings shape")
    if set(normalized) != {"provider", "model", "parameters", "retry"}:
        raise LockingError("model settings fields do not match the replay protocol")
    for field in ("provider", "model"):
        if not isinstance(normalized.get(field), str) or not normalized[field].strip():
            raise LockingError(f"model settings require a non-empty {field}")

    parameters = normalized.get("parameters")
    if not isinstance(parameters, Mapping) or set(parameters) != set(MODEL_PARAMETER_FIELDS):
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
    if not isinstance(retry, Mapping) or set(retry) != set(RETRY_FIELDS):
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


def _validate_gemini_model_settings(settings: dict[str, Any]) -> dict[str, Any]:
    constants = {
        "provider": "gemini-developer-api",
        "api_version": "v1beta",
        "model": "gemini-3.6-flash",
        "catalog_model_version": "3.6-flash-07-2026",
        "resolved_model_version": "gemini-3.6-flash",
    }
    for field, expected in constants.items():
        if settings.get(field) != expected:
            raise LockingError(f"Gemini setting {field} must equal {expected}")
    endpoint = settings.get("endpoint")
    expected_endpoint = (
        "https://generativelanguage.googleapis.com/v1beta/"
        "models/gemini-3.6-flash:generateContent"
    )
    if endpoint != expected_endpoint:
        raise LockingError("Gemini endpoint does not match the locked callable resource")

    parameters = settings.get("parameters")
    if not isinstance(parameters, Mapping) or set(parameters) != GEMINI_PARAMETER_FIELDS:
        raise LockingError("Gemini parameter fields do not match the protocol")
    expected_parameters = {
        "max_output_tokens": 8192,
        "response_mime_type": "application/json",
    }
    for field, expected in expected_parameters.items():
        supplied = parameters.get(field)
        if (
            isinstance(supplied, bool)
            or supplied != expected
            or (isinstance(expected, float) and not isinstance(supplied, float))
            or (isinstance(expected, int) and not isinstance(supplied, int))
        ):
            raise LockingError(f"Gemini parameter {field} must equal {expected}")
    schema_digest = parameters.get("response_schema_sha256")
    if not isinstance(schema_digest, str) or len(schema_digest) != 64 or any(
        character not in "0123456789abcdef" for character in schema_digest
    ):
        raise LockingError("Gemini response schema digest must be SHA-256")

    thinking = settings.get("thinking")
    if not isinstance(thinking, Mapping) or set(thinking) != {
        "level",
        "include_thoughts",
    }:
        raise LockingError("Gemini thinking settings do not match the protocol")
    if thinking.get("level") != "MINIMAL" or thinking.get("include_thoughts") is not False:
        raise LockingError("Gemini thinking must be MINIMAL with thoughts excluded")
    request = settings.get("request")
    expected_request = {
        "store": False,
        "service_tier": "standard",
        "timeout_seconds": 120,
        "minimum_interval_seconds": 16,
        "safety_settings": "provider-default",
        "tools": [],
    }
    if (
        not isinstance(request, Mapping)
        or set(request) != set(expected_request)
        or request.get("store") is not False
        or request.get("service_tier") != "standard"
        or not isinstance(request.get("service_tier"), str)
        or type(request.get("timeout_seconds")) is not int
        or request.get("timeout_seconds") != 120
        or type(request.get("minimum_interval_seconds")) is not int
        or request.get("minimum_interval_seconds") != 16
        or request.get("safety_settings") != "provider-default"
        or not isinstance(request.get("safety_settings"), str)
        or not isinstance(request.get("tools"), list)
        or request.get("tools") != []
    ):
        raise LockingError("Gemini request settings do not match the protocol")
    retry = settings.get("retry")
    if not isinstance(retry, Mapping) or set(retry) != set(RETRY_FIELDS):
        raise LockingError("Gemini retry settings do not match the protocol")
    if type(retry.get("max_attempts")) is not int or retry.get("max_attempts") != 1:
        raise LockingError("Gemini execution permits exactly one attempt")
    if type(retry.get("backoff_seconds")) is not int or retry.get("backoff_seconds") != 0:
        raise LockingError("Gemini execution does not permit retry backoff")
    canonical_json_bytes(settings)
    return settings


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


def build_calibration_lock_manifest(
    repository_root: str | os.PathLike[str],
    *,
    fixtures: Iterable[str | os.PathLike[str]],
    oracles: Iterable[str | os.PathLike[str]],
    schemas: Iterable[str | os.PathLike[str]],
    prompts: Iterable[str | os.PathLike[str]],
    evaluator: Iterable[str | os.PathLike[str]],
    prepared_inputs: Iterable[str | os.PathLike[str]],
    model_settings: Mapping[str, Any],
    calibration_plan: Mapping[str, Any],
    execution_root: str | os.PathLike[str] | None = None,
) -> dict[str, Any]:
    repository_base = Path(repository_root).resolve()
    execution_base = (
        Path(execution_root).resolve()
        if execution_root is not None
        else repository_base
    )
    repository = _repository_state(repository_base, require_clean=True)
    settings = validate_model_settings(model_settings, require_gemini=True)
    plan = _validate_calibration_plan(calibration_plan)
    supplied = {
        "fixtures": fixtures,
        "oracles": oracles,
        "schemas": schemas,
        "prompts": prompts,
        "evaluator": evaluator,
    }
    sections: dict[str, Any] = {}
    for name, paths in supplied.items():
        entries = _file_entries(repository_base, paths)
        if not entries:
            raise LockingError(f"calibration lock section {name} cannot be empty")
        sections[name] = {
            "digest": canonical_sha256(entries),
            "files": entries,
        }
    prepared_entries = _file_entries(execution_base, prepared_inputs)
    expected_prepared_paths = {entry["input_path"] for entry in plan["inputs"]}
    if set(prepared_entries) != expected_prepared_paths:
        raise LockingError("calibration prepared input inventory does not match the plan")
    sections["prepared_inputs"] = {
        "digest": canonical_sha256(prepared_entries),
        "files": prepared_entries,
    }
    return {
        "schema_version": CALIBRATION_LOCK_SCHEMA_VERSION,
        "algorithm": "sha256",
        "repository": repository,
        "sections": sections,
        "model_settings": _bound_value(settings, "model settings"),
        "calibration_plan": _bound_value(plan, "calibration plan"),
    }


def build_lock_manifest_v2(
    repository_root: str | os.PathLike[str] | None = None,
    *,
    root: str | os.PathLike[str] | None = None,
    fixtures: Iterable[str | os.PathLike[str]],
    schemas: Iterable[str | os.PathLike[str]],
    prompts: Iterable[str | os.PathLike[str]],
    evaluator: Iterable[str | os.PathLike[str]],
    prepared_inputs: Iterable[str | os.PathLike[str]],
    model_settings: Mapping[str, Any],
    execution_plan: Mapping[str, Any],
    calibration_index: Mapping[str, Any],
    suite_manifest: Mapping[str, Any],
    suite_attestation: Mapping[str, Any],
    sealed_oracle_digest: str,
    execution_root: str | os.PathLike[str] | None = None,
) -> dict[str, Any]:
    repository_base = _select_repository_root(repository_root, root)
    execution_base = (
        Path(execution_root).resolve()
        if execution_root is not None
        else repository_base
    )
    repository = _repository_state(repository_base, require_clean=True)
    settings = validate_model_settings(model_settings, require_gemini=True)
    plan = validate_execution_plan(execution_plan)
    _validate_final_lock_links(
        repository,
        settings,
        calibration_index,
        suite_manifest,
    )
    bound_values = {
        "execution_plan": _bound_value(plan, "execution plan"),
        "calibration_index": _bound_value(calibration_index, "calibration index"),
        "suite_manifest": _bound_value(suite_manifest, "suite manifest"),
        "suite_attestation": _bound_value(suite_attestation, "suite attestation"),
    }
    _validate_digest(sealed_oracle_digest, "sealed oracle")
    supplied = {
        "fixtures": fixtures,
        "schemas": schemas,
        "prompts": prompts,
        "evaluator": evaluator,
        "prepared_inputs": prepared_inputs,
    }
    sections: dict[str, Any] = {}
    for name in LOCK_V2_SECTIONS:
        section_base = execution_base if name == "prepared_inputs" else repository_base
        entries = _file_entries(section_base, supplied[name])
        if not entries:
            raise LockingError(f"lock v2 section {name} cannot be empty")
        sections[name] = {
            "digest": canonical_sha256(entries),
            "files": entries,
        }
    expected_prepared_paths = {entry["path"] for entry in plan["prepared_inputs"]}
    if set(sections["prepared_inputs"]["files"]) != expected_prepared_paths:
        raise LockingError("prepared input inventory does not match the execution plan")
    return {
        "schema_version": LOCK_V2_SCHEMA_VERSION,
        "algorithm": "sha256",
        "repository": repository,
        "sections": sections,
        "model_settings": _bound_value(settings, "model settings"),
        **bound_values,
        "sealed_oracle": {
            "algorithm": "sha256",
            "digest": sealed_oracle_digest,
        },
    }


def verify_calibration_lock_manifest(
    manifest: Mapping[str, Any] | str | os.PathLike[str],
    repository_root: str | os.PathLike[str],
    *,
    execution_root: str | os.PathLike[str] | None = None,
    model_settings: Mapping[str, Any] | None = None,
    calibration_plan: Mapping[str, Any] | None = None,
) -> None:
    loaded = _read_manifest(manifest)
    repository_base = Path(repository_root).resolve()
    execution_base = (
        Path(execution_root).resolve()
        if execution_root is not None
        else repository_base
    )
    expected_fields = {
        "schema_version",
        "algorithm",
        "repository",
        "sections",
        "model_settings",
        "calibration_plan",
    }
    mismatches: list[str] = []
    if set(loaded) != expected_fields:
        mismatches.append("calibration lock fields do not match the protocol")
    if loaded.get("schema_version") != CALIBRATION_LOCK_SCHEMA_VERSION:
        mismatches.append("unsupported calibration lock schema")
    if loaded.get("algorithm") != "sha256":
        mismatches.append("unsupported lock algorithm")
    _verify_repository_binding(
        loaded.get("repository"), repository_base, mismatches
    )

    sections = loaded.get("sections")
    if not isinstance(sections, Mapping) or set(sections) != set(
        CALIBRATION_LOCK_SECTIONS
    ):
        mismatches.append("calibration lock sections do not match the protocol")
        sections = {}
    for name in CALIBRATION_LOCK_SECTIONS:
        section_base = execution_base if name == "prepared_inputs" else repository_base
        _verify_file_section(name, sections.get(name), section_base, mismatches)

    settings_value = _verify_bound_value(
        loaded.get("model_settings"), "model settings", mismatches
    )
    if settings_value is not None:
        try:
            validated_settings = validate_model_settings(
                settings_value, require_gemini=True
            )
        except LockingError as exc:
            mismatches.append(f"invalid locked model settings: {exc}")
        else:
            if model_settings is not None:
                try:
                    supplied_settings = validate_model_settings(
                        model_settings, require_gemini=True
                    )
                except LockingError as exc:
                    mismatches.append(f"invalid supplied model settings: {exc}")
                else:
                    if canonical_sha256(supplied_settings) != canonical_sha256(
                        validated_settings
                    ):
                        mismatches.append(
                            "supplied model settings do not match the calibration lock"
                        )

    locked_plan = _verify_bound_value(
        loaded.get("calibration_plan"), "calibration plan", mismatches
    )
    if locked_plan is not None:
        try:
            validated_plan = _validate_calibration_plan(locked_plan)
        except LockingError as exc:
            mismatches.append(f"invalid locked calibration plan: {exc}")
        else:
            prepared = sections.get("prepared_inputs")
            prepared_files = (
                prepared.get("files") if isinstance(prepared, Mapping) else None
            )
            expected_paths = {
                entry["input_path"] for entry in validated_plan["inputs"]
            }
            if isinstance(prepared_files, Mapping) and set(prepared_files) != expected_paths:
                mismatches.append(
                    "calibration prepared input inventory does not match the plan"
                )
            if calibration_plan is not None:
                try:
                    supplied_plan = _validate_calibration_plan(calibration_plan)
                except LockingError as exc:
                    mismatches.append(f"invalid supplied calibration plan: {exc}")
                else:
                    if canonical_sha256(supplied_plan) != canonical_sha256(
                        validated_plan
                    ):
                        mismatches.append(
                            "supplied calibration plan does not match the lock"
                        )

    if mismatches:
        raise LockVerificationError(dict.fromkeys(mismatches))


def verify_lock_manifest(
    manifest: Mapping[str, Any] | str | os.PathLike[str],
    repository_root: str | os.PathLike[str] | None = None,
    *,
    root: str | os.PathLike[str] | None = None,
    execution_root: str | os.PathLike[str] | None = None,
    model_settings: Mapping[str, Any] | None = None,
    execution_plan: Mapping[str, Any] | None = None,
    calibration_index: Mapping[str, Any] | None = None,
    suite_manifest: Mapping[str, Any] | None = None,
    suite_attestation: Mapping[str, Any] | None = None,
    sealed_oracle_digest: str | None = None,
) -> None:
    loaded = _read_manifest(manifest)
    repository_base = _select_repository_root(repository_root, root)
    if loaded.get("schema_version") == LOCK_V2_SCHEMA_VERSION:
        _verify_lock_manifest_v2(
            loaded,
            repository_base,
            execution_root=execution_root,
            model_settings=model_settings,
            execution_plan=execution_plan,
            calibration_index=calibration_index,
            suite_manifest=suite_manifest,
            suite_attestation=suite_attestation,
            sealed_oracle_digest=sealed_oracle_digest,
        )
        return
    base = repository_base
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


def _verify_lock_manifest_v2(
    loaded: Mapping[str, Any],
    repository_root: str | os.PathLike[str],
    *,
    execution_root: str | os.PathLike[str] | None,
    model_settings: Mapping[str, Any] | None,
    execution_plan: Mapping[str, Any] | None,
    calibration_index: Mapping[str, Any] | None,
    suite_manifest: Mapping[str, Any] | None,
    suite_attestation: Mapping[str, Any] | None,
    sealed_oracle_digest: str | None,
) -> None:
    expected_fields = {
        "schema_version",
        "algorithm",
        "repository",
        "sections",
        "model_settings",
        "execution_plan",
        "calibration_index",
        "suite_manifest",
        "suite_attestation",
        "sealed_oracle",
    }
    mismatches: list[str] = []
    if set(loaded) != expected_fields:
        mismatches.append("lock v2 fields do not match the protocol")
    if loaded.get("algorithm") != "sha256":
        mismatches.append("unsupported lock algorithm")
    repository_base = Path(repository_root).resolve()
    execution_base = (
        Path(execution_root).resolve()
        if execution_root is not None
        else repository_base
    )
    _verify_repository_binding(
        loaded.get("repository"), repository_base, mismatches
    )

    sections = loaded.get("sections")
    if not isinstance(sections, Mapping) or set(sections) != set(LOCK_V2_SECTIONS):
        mismatches.append("lock v2 sections do not match the protocol")
        sections = {}
    for name in LOCK_V2_SECTIONS:
        section_base = execution_base if name == "prepared_inputs" else repository_base
        _verify_file_section(name, sections.get(name), section_base, mismatches)

    settings_value = _verify_bound_value(
        loaded.get("model_settings"), "model settings", mismatches
    )
    if settings_value is not None:
        try:
            validated_settings = validate_model_settings(
                settings_value, require_gemini=True
            )
        except LockingError as exc:
            mismatches.append(f"invalid locked model settings: {exc}")
        else:
            if model_settings is not None:
                try:
                    supplied_settings = validate_model_settings(
                        model_settings, require_gemini=True
                    )
                except LockingError as exc:
                    mismatches.append(f"invalid supplied model settings: {exc}")
                else:
                    if canonical_sha256(supplied_settings) != canonical_sha256(
                        validated_settings
                    ):
                        mismatches.append("supplied model settings do not match the lock")

    locked_plan = _verify_bound_value(
        loaded.get("execution_plan"), "execution plan", mismatches
    )
    if locked_plan is not None:
        try:
            validated_plan = validate_execution_plan(locked_plan)
        except (TypeError, ValueError) as exc:
            mismatches.append(f"invalid locked execution plan: {exc}")
        else:
            prepared = sections.get("prepared_inputs")
            prepared_files = prepared.get("files") if isinstance(prepared, Mapping) else None
            expected_prepared_paths = {
                entry["path"] for entry in validated_plan["prepared_inputs"]
            }
            if isinstance(prepared_files, Mapping) and set(
                prepared_files
            ) != expected_prepared_paths:
                mismatches.append("prepared input inventory does not match the execution plan")
            if execution_plan is not None:
                try:
                    supplied_plan = validate_execution_plan(execution_plan)
                except (TypeError, ValueError) as exc:
                    mismatches.append(f"invalid supplied execution plan: {exc}")
                else:
                    if canonical_sha256(supplied_plan) != canonical_sha256(validated_plan):
                        mismatches.append("supplied execution plan does not match the lock")

    supplied_values = {
        "calibration_index": calibration_index,
        "suite_manifest": suite_manifest,
        "suite_attestation": suite_attestation,
    }
    labels = {
        "calibration_index": "calibration index",
        "suite_manifest": "suite manifest",
        "suite_attestation": "suite attestation",
    }
    locked_values: dict[str, dict[str, Any]] = {}
    for field, supplied in supplied_values.items():
        locked_value = _verify_bound_value(loaded.get(field), labels[field], mismatches)
        if locked_value is not None:
            locked_values[field] = locked_value
        if supplied is not None:
            try:
                supplied_bound = _bound_value(supplied, labels[field])
            except LockingError as exc:
                mismatches.append(str(exc))
            else:
                if locked_value is None or supplied_bound["digest"] != canonical_sha256(
                    locked_value
                ):
                    mismatches.append(f"supplied {labels[field]} does not match the lock")

    locked_calibration = locked_values.get("calibration_index")
    locked_suite = locked_values.get("suite_manifest")
    if locked_calibration is not None and locked_suite is not None:
        try:
            _validate_final_lock_links(
                loaded.get("repository"),
                settings_value if settings_value is not None else {},
                locked_calibration,
                locked_suite,
            )
        except LockingError as exc:
            mismatches.append(str(exc))

    sealed = loaded.get("sealed_oracle")
    if (
        not isinstance(sealed, Mapping)
        or set(sealed) != {"algorithm", "digest"}
        or sealed.get("algorithm") != "sha256"
    ):
        mismatches.append("sealed oracle commitment is invalid")
    else:
        try:
            _validate_digest(sealed.get("digest"), "sealed oracle")
        except LockingError as exc:
            mismatches.append(str(exc))
        if sealed_oracle_digest is not None and sealed.get("digest") != sealed_oracle_digest:
            mismatches.append("supplied sealed oracle digest does not match the lock")

    if mismatches:
        raise LockVerificationError(dict.fromkeys(mismatches))


def _validate_final_lock_links(
    repository: Mapping[str, Any],
    model_settings: Mapping[str, Any],
    calibration_index: Mapping[str, Any],
    suite_manifest: Mapping[str, Any],
) -> None:
    if not isinstance(calibration_index, Mapping):
        raise LockingError("calibration index must be an object")
    if not isinstance(suite_manifest, Mapping):
        raise LockingError("suite manifest must be an object")
    from lazarus.suite import SuiteError, validate_calibration_index

    try:
        calibration_index = validate_calibration_index(calibration_index)
    except (SuiteError, TypeError, ValueError) as exc:
        raise LockingError(
            f"calibration index does not match the protocol: {exc}"
        ) from exc
    calibration_digest = canonical_sha256(calibration_index)
    if suite_manifest.get("calibration_index_sha256") != calibration_digest:
        raise LockingError("suite manifest does not bind the calibration index")

    calibration_binding = calibration_index.get("calibration_lock")
    if (
        not isinstance(calibration_binding, Mapping)
        or set(calibration_binding) != {"algorithm", "digest", "value"}
        or calibration_binding.get("algorithm") != "sha256"
    ):
        raise LockingError("calibration index has an invalid calibration lock binding")
    calibration_lock = calibration_binding.get("value")
    if not isinstance(calibration_lock, Mapping):
        raise LockingError("calibration index has no embedded calibration lock")
    if calibration_binding.get("digest") != canonical_sha256(calibration_lock):
        raise LockingError("calibration index calibration lock digest mismatch")
    expected_lock_fields = {
        "schema_version",
        "algorithm",
        "repository",
        "sections",
        "model_settings",
        "calibration_plan",
    }
    if (
        set(calibration_lock) != expected_lock_fields
        or calibration_lock.get("schema_version") != CALIBRATION_LOCK_SCHEMA_VERSION
        or calibration_lock.get("algorithm") != "sha256"
    ):
        raise LockingError("embedded calibration lock does not match the protocol")
    embedded_repository = calibration_lock.get("repository")
    if not isinstance(repository, Mapping) or not isinstance(
        embedded_repository, Mapping
    ):
        raise LockingError("embedded calibration lock repository is invalid")
    if dict(embedded_repository) != dict(repository):
        raise LockingError("calibration and final locks bind different repositories")

    embedded_settings = calibration_lock.get("model_settings")
    if (
        not isinstance(embedded_settings, Mapping)
        or set(embedded_settings) != {"digest", "value"}
    ):
        raise LockingError("embedded calibration lock model settings are invalid")
    validated_final_settings = validate_model_settings(
        model_settings, require_gemini=True
    )
    validated_calibration_settings = validate_model_settings(
        embedded_settings.get("value"), require_gemini=True
    )
    calibration_settings_digest = canonical_sha256(
        validated_calibration_settings
    )
    if embedded_settings.get("digest") != calibration_settings_digest:
        raise LockingError("embedded calibration lock model settings digest mismatch")
    if canonical_sha256(validated_final_settings) != calibration_settings_digest:
        raise LockingError("calibration and final locks bind different model settings")


def _validate_calibration_plan(plan: Mapping[str, Any]) -> dict[str, Any]:
    if not isinstance(plan, Mapping):
        raise LockingError("calibration plan must be an object")
    normalized = deepcopy(dict(plan))
    expected_inputs: list[dict[str, Any]] = []
    for sequence in range(1, 5):
        case_id = f"cal-{sequence:02d}"
        execution_id = f"calibration-{sequence:03d}"
        base = f"calibration/{execution_id}"
        expected_inputs.append(
            {
                "execution_id": execution_id,
                "sequence": sequence,
                "invocation_id": f"calibration-invocation-{sequence:03d}",
                "case_id": case_id,
                "arm": "b-replay",
                "run_id": "calibration",
                "input_path": f"calibration-inputs/{case_id}.json",
                "request_path": f"{base}/request.json",
                "raw_response_path": f"{base}/raw-response.json",
                "capture_path": f"{base}/capture.json",
            }
        )
    expected = {
        "schema_version": CALIBRATION_PLAN_SCHEMA_VERSION,
        "inputs": expected_inputs,
    }
    if canonical_json_bytes(normalized) != canonical_json_bytes(expected):
        raise LockingError("calibration plan does not match the fixed protocol")
    return normalized


def _verify_repository_binding(
    locked: Any,
    repository_base: Path,
    mismatches: list[str],
) -> None:
    try:
        actual = _repository_state(repository_base, require_clean=True)
    except LockingError as exc:
        mismatches.append(str(exc))
        actual = None
    if (
        not isinstance(locked, Mapping)
        or set(locked) != {"head_sha", "tree_sha", "tracked_clean"}
        or locked.get("tracked_clean") is not True
    ):
        mismatches.append("locked repository state is invalid")
        return
    try:
        _validate_git_object_id(locked.get("head_sha"), "locked repository HEAD")
        _validate_git_object_id(locked.get("tree_sha"), "locked repository tree")
    except LockingError as exc:
        mismatches.append(str(exc))
        return
    if actual is not None and dict(locked) != actual:
        mismatches.append("repository HEAD, tree, or tracked state does not match the lock")


def _verify_file_section(
    name: str,
    section: Any,
    base: Path,
    mismatches: list[str],
) -> None:
    if not isinstance(section, Mapping) or set(section) != {"digest", "files"}:
        mismatches.append(f"lock section {name} is invalid")
        return
    expected_files = section.get("files")
    if not isinstance(expected_files, Mapping) or not expected_files:
        mismatches.append(f"lock section {name} has no files")
        return
    normalized_files: dict[str, str] = {}
    for relative, expected_digest in expected_files.items():
        if not isinstance(relative, str):
            mismatches.append(f"lock section {name} has an invalid path")
            continue
        try:
            _validate_digest(expected_digest, f"locked file {relative}")
            path = _resolve_locked_path(base, relative)
            actual_digest = file_sha256(path)
        except LockingError as exc:
            mismatches.append(str(exc))
            continue
        normalized_files[relative] = expected_digest
        if actual_digest != expected_digest:
            mismatches.append(f"digest mismatch: {relative}")
    if normalized_files and section.get("digest") != canonical_sha256(
        dict(sorted(normalized_files.items()))
    ):
        mismatches.append(f"section digest mismatch: {name}")


def _bound_value(value: Mapping[str, Any], label: str) -> dict[str, Any]:
    if not isinstance(value, Mapping) or not value:
        raise LockingError(f"{label} must be a non-empty object")
    normalized = deepcopy(dict(value))
    canonical_json_bytes(normalized)
    return {"digest": canonical_sha256(normalized), "value": normalized}


def _verify_bound_value(
    section: Any, label: str, mismatches: list[str]
) -> dict[str, Any] | None:
    if not isinstance(section, Mapping) or set(section) != {"digest", "value"}:
        mismatches.append(f"locked {label} is invalid")
        return None
    value = section.get("value")
    if not isinstance(value, Mapping) or not value:
        mismatches.append(f"locked {label} has no value")
        return None
    try:
        digest = canonical_sha256(value)
    except LockingError as exc:
        mismatches.append(f"invalid locked {label}: {exc}")
        return None
    if section.get("digest") != digest:
        mismatches.append(f"locked {label} digest mismatch")
    return deepcopy(dict(value))


def _select_repository_root(
    repository_root: str | os.PathLike[str] | None,
    legacy_root: str | os.PathLike[str] | None,
) -> Path:
    if repository_root is None and legacy_root is None:
        raise TypeError("repository_root is required")
    if repository_root is not None and legacy_root is not None:
        raise TypeError("repository_root and root cannot both be supplied")
    selected = repository_root if repository_root is not None else legacy_root
    return Path(selected).resolve()


def _repository_state(base: Path, *, require_clean: bool) -> dict[str, Any]:
    def git(*arguments: str) -> str:
        try:
            completed = subprocess.run(
                ["git", "-C", str(base), *arguments],
                check=True,
                capture_output=True,
                text=True,
                encoding="utf-8",
            )
        except (OSError, subprocess.CalledProcessError, UnicodeError) as exc:
            raise LockingError(f"cannot inspect repository state: {exc}") from exc
        return completed.stdout.strip()

    head = git("rev-parse", "--verify", "HEAD")
    tree = git("rev-parse", "HEAD^{tree}")
    status = git("status", "--porcelain", "--untracked-files=no")
    if require_clean and status:
        raise LockingError("repository has tracked changes")
    for label, digest in (("repository HEAD", head), ("repository tree", tree)):
        _validate_git_object_id(digest, label)
    return {"head_sha": head, "tree_sha": tree, "tracked_clean": not bool(status)}


def _validate_digest(value: Any, label: str) -> None:
    if not isinstance(value, str) or len(value) != 64 or any(
        character not in "0123456789abcdef" for character in value
    ):
        raise LockingError(f"{label} digest must be lowercase SHA-256")


def _validate_git_object_id(value: Any, label: str) -> None:
    if not isinstance(value, str) or len(value) not in {40, 64} or any(
        character not in "0123456789abcdef" for character in value
    ):
        raise LockingError(f"{label} must be a lowercase Git object identifier")


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
    pure = Path(relative)
    if not relative or pure.is_absolute() or ".." in pure.parts or "." in pure.parts:
        raise LockingError(f"invalid locked path: {relative}")
    unresolved = base / pure
    if unresolved.is_symlink() or any(
        parent != base and parent.is_symlink()
        for parent in unresolved.parents
        if parent == base or base in parent.parents
    ):
        raise LockingError(f"locked paths cannot be symbolic links: {relative}")
    path = unresolved.resolve()
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


__all__ = [
    "CALIBRATION_LOCK_SCHEMA_VERSION",
    "CALIBRATION_LOCK_SECTIONS",
    "CALIBRATION_PLAN_SCHEMA_VERSION",
    "GEMINI_MODEL_SETTINGS_FIELDS",
    "GEMINI_PARAMETER_FIELDS",
    "LOCK_SCHEMA_VERSION",
    "LOCK_SECTIONS",
    "LOCK_V2_SCHEMA_VERSION",
    "LOCK_V2_SECTIONS",
    "MODEL_PARAMETER_FIELDS",
    "RETRY_FIELDS",
    "LockVerificationError",
    "LockingError",
    "build_calibration_lock_manifest",
    "build_lock_manifest",
    "build_lock_manifest_v2",
    "canonical_json_bytes",
    "canonical_sha256",
    "file_sha256",
    "validate_model_settings",
    "verify_calibration_lock_manifest",
    "verify_lock_manifest",
    "write_lock_manifest",
]
