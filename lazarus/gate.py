from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence
from copy import deepcopy
from dataclasses import dataclass
from datetime import datetime, timezone
import json
import os
from pathlib import Path, PurePosixPath
import re
from typing import Any

from lazarus.execution import (
    MODEL_ARMS,
    ExecutionError,
    sha256_bytes,
    sha256_json,
    validate_execution_plan,
    write_immutable_bytes,
    write_immutable_json,
)
from lazarus.gemini import (
    Clock,
    GEMINI_ENDPOINT,
    GeminiInvocation,
    GeminiResponseError,
    GeminiTransportError,
    Transport,
    build_generate_content_request,
    invoke_generate_content,
)
from lazarus.locking import (
    CALIBRATION_LOCK_SCHEMA_VERSION,
    LOCK_V2_SCHEMA_VERSION,
    LockingError,
    canonical_json_bytes,
    canonical_sha256,
    validate_model_settings,
    verify_calibration_lock_manifest,
    verify_lock_manifest,
)


MODEL_CAPTURE_SCHEMA_VERSION = "lazarus.model-capture/v2"
MODEL_CAPTURE_ERROR_SCHEMA_VERSION = "lazarus.model-capture-error/v1"
CALIBRATION_PLAN_SCHEMA_VERSION = "lazarus.calibration-capture-plan/v1"
CALIBRATION_INDEX_SCHEMA_VERSION = "lazarus.calibration-capture-index/v1"

_DIGEST = re.compile(r"^[0-9a-f]{64}$")
_CALIBRATION_INPUT_FIELDS = frozenset({"case_id", "arm", "path"})
ProgressCallback = Callable[[int, int], None]


class GateError(ValueError):
    def __init__(self, code: str, *, error_path: Path | None = None) -> None:
        self.code = code
        self.error_path = error_path
        super().__init__(f"model capture aborted: {code}")


@dataclass(frozen=True, slots=True)
class _CaptureContext:
    lock_sha256: str
    model_settings: dict[str, Any]
    model_settings_sha256: str
    plan_sha256: str
    sealed_oracle_sha256: str | None


def capture_execution_plan(
    execution_root: str | os.PathLike[str],
    execution_plan: Mapping[str, Any],
    *,
    repository_root: str | os.PathLike[str],
    lock_manifest: Mapping[str, Any],
    model_settings: Mapping[str, Any],
    sealed_oracle_digest: str,
    api_key: str,
    transport: Transport | None = None,
    clock: Clock | None = None,
    progress: ProgressCallback | None = None,
) -> tuple[dict[str, Any], ...]:
    """Capture only the model evaluations, sequentially and in plan order."""

    root = _execution_root(execution_root)
    try:
        plan = validate_execution_plan(execution_plan)
        _validate_progress(progress)
        embedded = _embedded_final_lock_values(lock_manifest)
        verify_lock_manifest(
            lock_manifest,
            repository_root,
            execution_root=root,
            model_settings=model_settings,
            execution_plan=plan,
            calibration_index=embedded["calibration_index"],
            suite_manifest=embedded["suite_manifest"],
            suite_attestation=embedded["suite_attestation"],
            sealed_oracle_digest=sealed_oracle_digest,
        )
        context, locked_inputs = _execution_context(
            lock_manifest,
            model_settings,
            plan,
            sealed_oracle_digest,
        )
        prepared = {
            (entry["case_id"], entry["arm"]): deepcopy(entry)
            for entry in plan["prepared_inputs"]
        }
    except (ExecutionError, LockingError, GateError, TypeError, ValueError):
        error_path = root / "error.json"
        _write_error(
            error_path,
            stage="identity",
            code="execution_context_invalid",
            occurred_at=_clock_timestamp(clock),
        )
        raise GateError(
            "execution_context_invalid", error_path=error_path
        ) from None

    model_evaluations = [
        entry for entry in plan["evaluations"] if entry["invocation_id"] is not None
    ]
    captures: list[dict[str, Any]] = []
    response_ids: set[str] = set()
    for evaluation in model_evaluations:
        input_entry = prepared[(evaluation["case_id"], evaluation["arm"])]
        try:
            model_input = _read_exact_input(root, input_entry["path"])
        except GateError:
            error_path = _evaluation_error_path(root, evaluation)
            _write_error(
                error_path,
                stage="identity",
                code="prepared_input_unavailable",
                occurred_at=_clock_timestamp(clock),
                evaluation=evaluation,
                context=context,
                input_path=input_entry["path"],
            )
            raise GateError(
                "prepared_input_unavailable", error_path=error_path
            ) from None
        expected_digest = locked_inputs[input_entry["path"]]
        captures.append(
            _capture_one(
                root,
                evaluation,
                input_path=input_entry["path"],
                model_input=model_input,
                expected_input_sha256=expected_digest,
                context=context,
                api_key=api_key,
                transport=transport,
                clock=clock,
                seen_response_ids=response_ids,
            )
        )
        if progress is not None:
            progress(len(captures), len(model_evaluations))
    return tuple(captures)


def capture_model_evaluation(
    execution_root: str | os.PathLike[str],
    evaluation: Mapping[str, Any],
    *,
    repository_root: str | os.PathLike[str],
    input_path: str,
    lock_manifest: Mapping[str, Any],
    model_settings: Mapping[str, Any],
    execution_plan: Mapping[str, Any],
    sealed_oracle_digest: str,
    api_key: str,
    transport: Transport | None = None,
    clock: Clock | None = None,
) -> dict[str, Any]:
    """Capture one model evaluation after checking every locked identity."""

    root = _execution_root(execution_root)
    try:
        plan = validate_execution_plan(execution_plan)
        embedded = _embedded_final_lock_values(lock_manifest)
        verify_lock_manifest(
            lock_manifest,
            repository_root,
            execution_root=root,
            model_settings=model_settings,
            execution_plan=plan,
            calibration_index=embedded["calibration_index"],
            suite_manifest=embedded["suite_manifest"],
            suite_attestation=embedded["suite_attestation"],
            sealed_oracle_digest=sealed_oracle_digest,
        )
        context, locked_inputs = _execution_context(
            lock_manifest,
            model_settings,
            plan,
            sealed_oracle_digest,
        )
        selected = _select_model_evaluation(plan, evaluation)
        expected_input = next(
            entry
            for entry in plan["prepared_inputs"]
            if entry["case_id"] == selected["case_id"]
            and entry["arm"] == selected["arm"]
        )
        if input_path != expected_input["path"]:
            raise GateError("prepared_input_path_mismatch")
        model_input = _read_exact_input(root, input_path)
    except (ExecutionError, LockingError, GateError, StopIteration, TypeError, ValueError):
        error_path = _evaluation_error_path(root, evaluation)
        _write_error(
            error_path,
            stage="identity",
            code="evaluation_identity_invalid",
            occurred_at=_clock_timestamp(clock),
            evaluation=evaluation,
            input_path=input_path,
        )
        raise GateError(
            "evaluation_identity_invalid", error_path=error_path
        ) from None

    return _capture_one(
        root,
        selected,
        input_path=input_path,
        model_input=model_input,
        expected_input_sha256=locked_inputs[input_path],
        context=context,
        api_key=api_key,
        transport=transport,
        clock=clock,
    )


def build_calibration_plan() -> dict[str, Any]:
    inputs: list[dict[str, Any]] = []
    for sequence in range(1, 5):
        case_id = f"cal-{sequence:02d}"
        execution_id = f"calibration-{sequence:03d}"
        base = f"calibration/{execution_id}"
        inputs.append(
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
    return {"schema_version": CALIBRATION_PLAN_SCHEMA_VERSION, "inputs": inputs}


def capture_calibration_inputs(
    execution_root: str | os.PathLike[str],
    calibration_inputs: Sequence[Mapping[str, Any]],
    *,
    repository_root: str | os.PathLike[str],
    lock_manifest: Mapping[str, Any],
    model_settings: Mapping[str, Any],
    api_key: str,
    transport: Transport | None = None,
    clock: Clock | None = None,
    progress: ProgressCallback | None = None,
) -> dict[str, Any]:
    """Capture four explicit calibration inputs and write their aggregate index."""

    root = _execution_root(execution_root)
    try:
        plan = build_calibration_plan()
        _validate_explicit_calibration_inputs(calibration_inputs, plan)
        _validate_progress(progress)
        verify_calibration_lock_manifest(
            lock_manifest,
            repository_root,
            execution_root=root,
            model_settings=model_settings,
            calibration_plan=plan,
        )
        context, locked_inputs = _calibration_context(
            lock_manifest,
            model_settings,
            plan,
        )
    except (LockingError, GateError, TypeError, ValueError):
        error_path = root / "calibration" / "error.json"
        _write_error(
            error_path,
            stage="identity",
            code="calibration_context_invalid",
            occurred_at=_clock_timestamp(clock),
        )
        raise GateError(
            "calibration_context_invalid", error_path=error_path
        ) from None

    index_entries: list[dict[str, Any]] = []
    response_ids: set[str] = set()
    for entry in plan["inputs"]:
        try:
            model_input = _read_exact_input(root, entry["input_path"])
        except GateError:
            error_path = _evaluation_error_path(root, entry)
            _write_error(
                error_path,
                stage="identity",
                code="calibration_input_unavailable",
                occurred_at=_clock_timestamp(clock),
                evaluation=entry,
                context=context,
                input_path=entry["input_path"],
            )
            raise GateError(
                "calibration_input_unavailable", error_path=error_path
            ) from None
        capture = _capture_one(
            root,
            entry,
            input_path=entry["input_path"],
            model_input=model_input,
            expected_input_sha256=locked_inputs[entry["input_path"]],
            context=context,
            api_key=api_key,
            transport=transport,
            clock=clock,
            seen_response_ids=response_ids,
        )
        capture_path = _safe_output_path(root, entry["capture_path"])
        index_entries.append(
            {
                "sequence": entry["sequence"],
                "execution_id": entry["execution_id"],
                "invocation_id": entry["invocation_id"],
                "case_id": entry["case_id"],
                "arm": entry["arm"],
                "input_path": entry["input_path"],
                "input_sha256": capture["input_sha256"],
                "request_path": entry["request_path"],
                "request_sha256": capture["request_sha256"],
                "raw_response_path": entry["raw_response_path"],
                "raw_response_sha256": capture["raw_response_sha256"],
                "capture_path": entry["capture_path"],
                "capture_sha256": sha256_bytes(capture_path.read_bytes()),
                "response_id": capture["response_id"],
                "model_version": capture["model_version"],
            }
        )
        if progress is not None:
            progress(len(index_entries), len(plan["inputs"]))

    index = {
        "schema_version": CALIBRATION_INDEX_SCHEMA_VERSION,
        "lock_sha256": context.lock_sha256,
        "model_settings_sha256": context.model_settings_sha256,
        "calibration_plan_sha256": context.plan_sha256,
        "count": len(index_entries),
        "captures": index_entries,
    }
    write_immutable_json(root / "calibration" / "index.json", index)
    return index


def capture_calibration(
    execution_root: str | os.PathLike[str],
    calibration_inputs: Sequence[Mapping[str, Any]],
    **kwargs: Any,
) -> dict[str, Any]:
    """Compatibility name for the explicit calibration capture helper."""

    return capture_calibration_inputs(
        execution_root,
        calibration_inputs,
        **kwargs,
    )


def _capture_one(
    root: Path,
    evaluation: Mapping[str, Any],
    *,
    input_path: str,
    model_input: bytes,
    expected_input_sha256: str | None,
    context: _CaptureContext,
    api_key: str,
    transport: Transport | None,
    clock: Clock | None,
    seen_response_ids: set[str] | None = None,
) -> dict[str, Any]:
    input_digest = sha256_bytes(model_input)
    error_path = _evaluation_error_path(root, evaluation)
    if expected_input_sha256 is not None and input_digest != expected_input_sha256:
        _write_error(
            error_path,
            stage="identity",
            code="prepared_input_digest_mismatch",
            occurred_at=_clock_timestamp(clock),
            evaluation=evaluation,
            context=context,
            input_path=input_path,
            input_sha256=input_digest,
        )
        raise GateError(
            "prepared_input_digest_mismatch", error_path=error_path
        )
    try:
        _validate_input_identity(model_input, evaluation)
        request_bytes = build_generate_content_request(model_input)
        _validate_request_settings(request_bytes, context.model_settings)
    except (GateError, TypeError, ValueError):
        _write_error(
            error_path,
            stage="identity",
            code="model_input_identity_invalid",
            occurred_at=_clock_timestamp(clock),
            evaluation=evaluation,
            context=context,
            input_path=input_path,
            input_sha256=input_digest,
        )
        raise GateError(
            "model_input_identity_invalid", error_path=error_path
        ) from None

    request_path = _safe_output_path(root, evaluation["request_path"])
    raw_response_path = _safe_output_path(root, evaluation["raw_response_path"])
    capture_path = _safe_output_path(root, evaluation["capture_path"])
    write_immutable_bytes(request_path, request_bytes)
    request_digest = sha256_bytes(request_bytes)

    try:
        invocation = invoke_generate_content(
            model_input,
            api_key,
            transport=transport,
            timeout_seconds=context.model_settings["request"]["timeout_seconds"],
            clock=clock,
        )
    except GeminiTransportError as exc:
        raw_digest = _write_failure_response(raw_response_path, exc.capture)
        failure_code = (
            "provider_http_failure"
            if exc.capture.http_status is not None
            else "provider_transport_failure"
        )
        _write_error(
            error_path,
            stage="transport",
            code=failure_code,
            occurred_at=exc.capture.completed_at,
            evaluation=evaluation,
            context=context,
            input_path=input_path,
            input_sha256=input_digest,
            request_path=evaluation["request_path"],
            request_sha256=request_digest,
            raw_response_path=(
                evaluation["raw_response_path"]
                if exc.capture.response_bytes is not None
                else None
            ),
            raw_response_sha256=raw_digest,
            http_status=exc.capture.http_status,
        )
        raise GateError(failure_code, error_path=error_path) from None
    except GeminiResponseError as exc:
        invocation = exc.capture
        raw_digest = _write_failure_response(raw_response_path, invocation)
        _write_error(
            error_path,
            stage="envelope",
            code="provider_response_invalid",
            occurred_at=(
                invocation.completed_at
                if invocation is not None
                else _clock_timestamp(clock)
            ),
            evaluation=evaluation,
            context=context,
            input_path=input_path,
            input_sha256=input_digest,
            request_path=evaluation["request_path"],
            request_sha256=request_digest,
            raw_response_path=(
                evaluation["raw_response_path"]
                if invocation is not None and invocation.response_bytes is not None
                else None
            ),
            raw_response_sha256=raw_digest,
            http_status=invocation.http_status if invocation is not None else None,
        )
        raise GateError(
            "provider_response_invalid", error_path=error_path
        ) from None
    except ValueError:
        _write_error(
            error_path,
            stage="identity",
            code="provider_invocation_invalid",
            occurred_at=_clock_timestamp(clock),
            evaluation=evaluation,
            context=context,
            input_path=input_path,
            input_sha256=input_digest,
            request_path=evaluation["request_path"],
            request_sha256=request_digest,
        )
        raise GateError(
            "provider_invocation_invalid", error_path=error_path
        ) from None

    if invocation.response_bytes is None:
        _write_error(
            error_path,
            stage="envelope",
            code="provider_response_missing",
            occurred_at=invocation.completed_at,
            evaluation=evaluation,
            context=context,
            input_path=input_path,
            input_sha256=input_digest,
            request_path=evaluation["request_path"],
            request_sha256=request_digest,
            http_status=invocation.http_status,
        )
        raise GateError("provider_response_missing", error_path=error_path)

    write_immutable_bytes(raw_response_path, invocation.response_bytes)
    raw_response_digest = sha256_bytes(invocation.response_bytes)
    if invocation.request_bytes != request_bytes or invocation.url != GEMINI_ENDPOINT:
        _write_error(
            error_path,
            stage="identity",
            code="provider_request_identity_mismatch",
            occurred_at=invocation.completed_at,
            evaluation=evaluation,
            context=context,
            input_path=input_path,
            input_sha256=input_digest,
            request_path=evaluation["request_path"],
            request_sha256=request_digest,
            raw_response_path=evaluation["raw_response_path"],
            raw_response_sha256=raw_response_digest,
            http_status=invocation.http_status,
        )
        raise GateError(
            "provider_request_identity_mismatch", error_path=error_path
        )
    try:
        _validate_response_identity(invocation, context.model_settings)
    except GateError as exc:
        _write_error(
            error_path,
            stage="identity" if exc.code == "model_version_mismatch" else "envelope",
            code=exc.code,
            occurred_at=invocation.completed_at,
            evaluation=evaluation,
            context=context,
            input_path=input_path,
            input_sha256=input_digest,
            request_path=evaluation["request_path"],
            request_sha256=request_digest,
            raw_response_path=evaluation["raw_response_path"],
            raw_response_sha256=raw_response_digest,
            http_status=invocation.http_status,
            response_id=(
                invocation.response.response_id
                if invocation.response is not None
                else None
            ),
            model_version=(
                invocation.response.model_version
                if invocation.response is not None
                else None
            ),
        )
        raise GateError(exc.code, error_path=error_path) from None

    response = invocation.response
    candidate = response.candidates[0]
    if seen_response_ids is not None and response.response_id in seen_response_ids:
        _write_error(
            error_path,
            stage="identity",
            code="duplicate_response_id",
            occurred_at=invocation.completed_at,
            evaluation=evaluation,
            context=context,
            input_path=input_path,
            input_sha256=input_digest,
            request_path=evaluation["request_path"],
            request_sha256=request_digest,
            raw_response_path=evaluation["raw_response_path"],
            raw_response_sha256=raw_response_digest,
            http_status=invocation.http_status,
            response_id=response.response_id,
            model_version=response.model_version,
        )
        raise GateError("duplicate_response_id", error_path=error_path)
    capture = {
        "schema_version": MODEL_CAPTURE_SCHEMA_VERSION,
        "execution_id": evaluation["execution_id"],
        "sequence": evaluation["sequence"],
        "invocation_id": evaluation["invocation_id"],
        "case_id": evaluation["case_id"],
        "arm": evaluation["arm"],
        "run_id": evaluation["run_id"],
        "started_at": invocation.started_at,
        "completed_at": invocation.completed_at,
        "http_status": invocation.http_status,
        "provider": context.model_settings["provider"],
        "endpoint": context.model_settings["endpoint"],
        "model": context.model_settings["model"],
        "resolved_model_version": context.model_settings["resolved_model_version"],
        "model_version": response.model_version,
        "response_id": response.response_id,
        "lock_sha256": context.lock_sha256,
        "model_settings_sha256": context.model_settings_sha256,
        "execution_plan_sha256": context.plan_sha256,
        "sealed_oracle_sha256": context.sealed_oracle_sha256,
        "input_path": input_path,
        "input_sha256": input_digest,
        "request_path": evaluation["request_path"],
        "request_sha256": request_digest,
        "raw_response_path": evaluation["raw_response_path"],
        "raw_response_sha256": raw_response_digest,
        "capture_path": evaluation["capture_path"],
        "candidate_index": candidate.index,
        "candidate_role": candidate.role,
        "finish_reason": candidate.finish_reason,
        "text_parts": list(candidate.text_parts),
        "parts": [deepcopy(part) for part in candidate.parts],
        "tool_parts": [deepcopy(part) for part in candidate.tool_parts],
        "safety_ratings": [deepcopy(rating) for rating in candidate.safety_ratings],
        "usage_metadata": deepcopy(response.usage_metadata),
        "prompt_feedback": deepcopy(response.prompt_feedback),
        "model_status": deepcopy(response.model_status),
        "response_text": candidate.response_text,
        "response_text_sha256": sha256_bytes(
            candidate.response_text.encode("utf-8")
        ),
    }
    write_immutable_json(capture_path, capture)
    if seen_response_ids is not None:
        seen_response_ids.add(response.response_id)
    return capture


def _execution_context(
    lock_manifest: Mapping[str, Any],
    model_settings: Mapping[str, Any],
    plan: Mapping[str, Any],
    sealed_oracle_digest: str,
) -> tuple[_CaptureContext, dict[str, str]]:
    settings, lock_digest = _locked_settings(
        lock_manifest,
        model_settings,
        schema_version=LOCK_V2_SCHEMA_VERSION,
    )
    plan_digest = canonical_sha256(plan)
    bound_plan = lock_manifest.get("execution_plan")
    if (
        not isinstance(bound_plan, Mapping)
        or set(bound_plan) != {"digest", "value"}
        or bound_plan.get("digest") != plan_digest
        or bound_plan.get("value") != plan
    ):
        raise GateError("locked_execution_plan_mismatch")

    sections = lock_manifest.get("sections")
    prepared = sections.get("prepared_inputs") if isinstance(sections, Mapping) else None
    files = prepared.get("files") if isinstance(prepared, Mapping) else None
    expected_paths = {entry["path"] for entry in plan["prepared_inputs"]}
    if (
        not isinstance(files, Mapping)
        or set(files) != expected_paths
        or any(
            not isinstance(path, str)
            or not isinstance(digest, str)
            or _DIGEST.fullmatch(digest) is None
            for path, digest in files.items()
        )
        or prepared.get("digest") != canonical_sha256(dict(sorted(files.items())))
    ):
        raise GateError("locked_prepared_inputs_mismatch")
    sealed = lock_manifest.get("sealed_oracle")
    if (
        not isinstance(sealed_oracle_digest, str)
        or _DIGEST.fullmatch(sealed_oracle_digest) is None
        or not isinstance(sealed, Mapping)
        or sealed.get("algorithm") != "sha256"
        or sealed.get("digest") != sealed_oracle_digest
    ):
        raise GateError("sealed_oracle_digest_mismatch")
    return (
        _CaptureContext(
            lock_sha256=lock_digest,
            model_settings=settings,
            model_settings_sha256=canonical_sha256(settings),
            plan_sha256=plan_digest,
            sealed_oracle_sha256=sealed_oracle_digest,
        ),
        dict(files),
    )


def _locked_settings(
    lock_manifest: Mapping[str, Any],
    model_settings: Mapping[str, Any],
    *,
    schema_version: str,
) -> tuple[dict[str, Any], str]:
    if (
        not isinstance(lock_manifest, Mapping)
        or lock_manifest.get("schema_version") != schema_version
    ):
        raise GateError("unsupported_lock")
    settings = validate_model_settings(model_settings, require_gemini=True)
    settings_digest = canonical_sha256(settings)
    bound = lock_manifest.get("model_settings")
    if (
        not isinstance(bound, Mapping)
        or set(bound) != {"digest", "value"}
        or bound.get("digest") != settings_digest
        or bound.get("value") != settings
    ):
        raise GateError("locked_model_settings_mismatch")
    return settings, canonical_sha256(lock_manifest)


def _calibration_context(
    lock_manifest: Mapping[str, Any],
    model_settings: Mapping[str, Any],
    plan: Mapping[str, Any],
) -> tuple[_CaptureContext, dict[str, str]]:
    settings, lock_digest = _locked_settings(
        lock_manifest,
        model_settings,
        schema_version=CALIBRATION_LOCK_SCHEMA_VERSION,
    )
    plan_digest = canonical_sha256(plan)
    bound_plan = lock_manifest.get("calibration_plan")
    if (
        not isinstance(bound_plan, Mapping)
        or set(bound_plan) != {"digest", "value"}
        or bound_plan.get("digest") != plan_digest
        or bound_plan.get("value") != plan
    ):
        raise GateError("locked_calibration_plan_mismatch")
    sections = lock_manifest.get("sections")
    prepared = sections.get("prepared_inputs") if isinstance(sections, Mapping) else None
    files = prepared.get("files") if isinstance(prepared, Mapping) else None
    expected_paths = {entry["input_path"] for entry in plan["inputs"]}
    if (
        not isinstance(files, Mapping)
        or set(files) != expected_paths
        or any(
            not isinstance(path, str)
            or not isinstance(digest, str)
            or _DIGEST.fullmatch(digest) is None
            for path, digest in files.items()
        )
        or prepared.get("digest") != canonical_sha256(dict(sorted(files.items())))
    ):
        raise GateError("locked_calibration_inputs_mismatch")
    return (
        _CaptureContext(
            lock_sha256=lock_digest,
            model_settings=settings,
            model_settings_sha256=canonical_sha256(settings),
            plan_sha256=plan_digest,
            sealed_oracle_sha256=None,
        ),
        dict(files),
    )


def _embedded_final_lock_values(
    lock_manifest: Mapping[str, Any],
) -> dict[str, dict[str, Any]]:
    values: dict[str, dict[str, Any]] = {}
    for field in ("calibration_index", "suite_manifest", "suite_attestation"):
        bound = lock_manifest.get(field) if isinstance(lock_manifest, Mapping) else None
        value = bound.get("value") if isinstance(bound, Mapping) else None
        if (
            not isinstance(bound, Mapping)
            or set(bound) != {"digest", "value"}
            or not isinstance(value, Mapping)
            or bound.get("digest") != canonical_sha256(value)
        ):
            raise GateError(f"locked_{field}_invalid")
        values[field] = deepcopy(dict(value))
    return values


def _validate_progress(progress: ProgressCallback | None) -> None:
    if progress is not None and not callable(progress):
        raise GateError("progress_callback_invalid")


def _select_model_evaluation(
    plan: Mapping[str, Any], supplied: Mapping[str, Any]
) -> dict[str, Any]:
    if not isinstance(supplied, Mapping):
        raise GateError("evaluation_identity_invalid")
    execution_id = supplied.get("execution_id")
    matches = [
        entry for entry in plan["evaluations"] if entry["execution_id"] == execution_id
    ]
    if len(matches) != 1 or supplied != matches[0]:
        raise GateError("evaluation_identity_invalid")
    selected = deepcopy(matches[0])
    if selected["arm"] not in MODEL_ARMS or selected["invocation_id"] is None:
        raise GateError("evaluation_is_not_model_call")
    return selected


def _validate_input_identity(
    model_input: bytes, evaluation: Mapping[str, Any]
) -> None:
    try:
        document = json.loads(
            model_input.decode("utf-8", errors="strict"),
            object_pairs_hook=_unique_mapping,
            parse_constant=_reject_constant,
        )
    except (UnicodeError, ValueError, json.JSONDecodeError):
        raise GateError("model_input_invalid") from None
    if not isinstance(document, Mapping) or canonical_json_bytes(document) != model_input:
        raise GateError("model_input_not_canonical")
    case = document.get("case")
    if (
        document.get("schema_version") != "lazarus.model-input/v1"
        or document.get("arm") != evaluation.get("arm")
        or not isinstance(case, Mapping)
        or case.get("case_id") != evaluation.get("case_id")
    ):
        raise GateError("model_input_identity_mismatch")


def _validate_request_settings(
    request_bytes: bytes, model_settings: Mapping[str, Any]
) -> None:
    try:
        request = json.loads(request_bytes)
        generation = request["generationConfig"]
        schema = generation["responseJsonSchema"]
    except (KeyError, TypeError, ValueError, json.JSONDecodeError):
        raise GateError("provider_request_invalid") from None
    expected_top_level = {
        "systemInstruction",
        "contents",
        "generationConfig",
        "store",
        "serviceTier",
    }
    parameters = model_settings["parameters"]
    thinking = model_settings["thinking"]
    expected_generation = {
        "temperature": parameters["temperature"],
        "topP": parameters["top_p"],
        "candidateCount": parameters["candidate_count"],
        "maxOutputTokens": parameters["max_output_tokens"],
        "responseMimeType": parameters["response_mime_type"],
        "responseJsonSchema": schema,
        "thinkingConfig": {
            "thinkingLevel": thinking["level"],
            "includeThoughts": thinking["include_thoughts"],
        },
    }
    if (
        not isinstance(request, Mapping)
        or set(request) != expected_top_level
        or request.get("store") is not model_settings["request"]["store"]
        or request.get("serviceTier") != model_settings["request"]["service_tier"]
        or generation != expected_generation
    ):
        raise GateError("provider_request_settings_mismatch")
    expected = model_settings["parameters"]["response_schema_sha256"]
    if canonical_sha256(schema) != expected:
        raise GateError("response_schema_digest_mismatch")


def _validate_response_identity(
    invocation: GeminiInvocation, model_settings: Mapping[str, Any]
) -> None:
    if invocation.http_status != 200 or invocation.response is None:
        raise GateError("provider_response_invalid")
    response = invocation.response
    if response.model_version != model_settings["resolved_model_version"]:
        raise GateError("model_version_mismatch")
    if not isinstance(response.response_id, str) or not response.response_id:
        raise GateError("response_id_missing")
    if len(response.candidates) != 1:
        raise GateError("candidate_count_mismatch")
    candidate = response.candidates[0]
    if candidate.index != 0:
        raise GateError("candidate_index_mismatch")
    if candidate.role != "model":
        raise GateError("candidate_role_mismatch")
    if not isinstance(candidate.finish_reason, str) or not candidate.finish_reason:
        raise GateError("finish_reason_missing")
    if response.usage_metadata is None:
        raise GateError("usage_metadata_missing")


def _validate_explicit_calibration_inputs(
    calibration_inputs: Sequence[Mapping[str, Any]],
    plan: Mapping[str, Any],
) -> None:
    if (
        not isinstance(calibration_inputs, Sequence)
        or isinstance(calibration_inputs, (str, bytes, bytearray))
        or len(calibration_inputs) != 4
    ):
        raise GateError("calibration_requires_four_inputs")
    normalized: list[dict[str, Any]] = []
    for supplied in calibration_inputs:
        if not isinstance(supplied, Mapping) or set(supplied) != _CALIBRATION_INPUT_FIELDS:
            raise GateError("calibration_input_fields_invalid")
        normalized.append(deepcopy(dict(supplied)))
    expected = [
        {
            "case_id": entry["case_id"],
            "arm": entry["arm"],
            "path": entry["input_path"],
        }
        for entry in plan["inputs"]
    ]
    if canonical_json_bytes(normalized) != canonical_json_bytes(expected):
        raise GateError("calibration_input_identity_invalid")


def _read_exact_input(root: Path, relative: str) -> bytes:
    path = _safe_input_path(root, relative)
    try:
        return path.read_bytes()
    except OSError:
        raise GateError("prepared_input_unavailable") from None


def _safe_input_path(root: Path, relative: str) -> Path:
    _validate_relative_path(relative)
    path = root.joinpath(*PurePosixPath(relative).parts)
    if path.is_symlink() or any(
        parent != root and parent.is_symlink()
        for parent in path.parents
        if parent == root or root in parent.parents
    ):
        raise GateError("input_path_uses_symlink")
    try:
        resolved = path.resolve(strict=True)
        resolved.relative_to(root.resolve(strict=True))
    except (OSError, ValueError):
        raise GateError("input_path_invalid") from None
    if not resolved.is_file():
        raise GateError("input_path_is_not_file")
    return resolved


def _safe_output_path(root: Path, relative: Any) -> Path:
    if not isinstance(relative, str):
        raise GateError("output_path_invalid")
    _validate_relative_path(relative)
    path = root.joinpath(*PurePosixPath(relative).parts)
    try:
        path.resolve().relative_to(root.resolve())
    except ValueError:
        raise GateError("output_path_escapes_root") from None
    return path


def _validate_relative_path(relative: str) -> None:
    if not isinstance(relative, str):
        raise GateError("path_invalid")
    pure = PurePosixPath(relative)
    if (
        not relative
        or pure.is_absolute()
        or not pure.parts
        or "." in pure.parts
        or ".." in pure.parts
        or "\\" in relative
    ):
        raise GateError("path_invalid")


def _execution_root(value: str | os.PathLike[str]) -> Path:
    root = Path(value)
    if root.is_symlink():
        raise GateError("execution_root_uses_symlink")
    try:
        root.mkdir(parents=True, exist_ok=True)
    except OSError:
        raise GateError("execution_root_unavailable") from None
    if not root.is_dir():
        raise GateError("execution_root_is_not_directory")
    return root.resolve()


def _evaluation_error_path(root: Path, evaluation: Mapping[str, Any]) -> Path:
    capture_path = evaluation.get("capture_path") if isinstance(evaluation, Mapping) else None
    if isinstance(capture_path, str):
        try:
            return _safe_output_path(root, capture_path).with_name("error.json")
        except GateError:
            pass
    return root / "error.json"


def _write_failure_response(
    path: Path, invocation: GeminiInvocation | None
) -> str | None:
    if invocation is None or invocation.response_bytes is None:
        return None
    write_immutable_bytes(path, invocation.response_bytes)
    return sha256_bytes(invocation.response_bytes)


def _write_error(
    path: Path,
    *,
    stage: str,
    code: str,
    occurred_at: str,
    evaluation: Mapping[str, Any] | None = None,
    context: _CaptureContext | None = None,
    input_path: str | None = None,
    input_sha256: str | None = None,
    request_path: str | None = None,
    request_sha256: str | None = None,
    raw_response_path: str | None = None,
    raw_response_sha256: str | None = None,
    http_status: int | None = None,
    response_id: str | None = None,
    model_version: str | None = None,
) -> None:
    record = {
        "schema_version": MODEL_CAPTURE_ERROR_SCHEMA_VERSION,
        "stage": stage,
        "code": code,
        "occurred_at": occurred_at,
        "execution_id": evaluation.get("execution_id") if evaluation else None,
        "invocation_id": evaluation.get("invocation_id") if evaluation else None,
        "case_id": evaluation.get("case_id") if evaluation else None,
        "arm": evaluation.get("arm") if evaluation else None,
        "lock_sha256": context.lock_sha256 if context else None,
        "model_settings_sha256": (
            context.model_settings_sha256 if context else None
        ),
        "execution_plan_sha256": context.plan_sha256 if context else None,
        "sealed_oracle_sha256": (
            context.sealed_oracle_sha256 if context else None
        ),
        "input_path": input_path,
        "input_sha256": input_sha256,
        "request_path": request_path,
        "request_sha256": request_sha256,
        "raw_response_path": raw_response_path,
        "raw_response_sha256": raw_response_sha256,
        "http_status": http_status,
        "response_id": response_id,
        "model_version": model_version,
    }
    write_immutable_json(path, record)


def _clock_timestamp(clock: Clock | None) -> str:
    value = clock() if clock is not None else datetime.now(timezone.utc)
    if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() is None:
        raise GateError("clock_invalid")
    return value.astimezone(timezone.utc).isoformat(timespec="microseconds").replace(
        "+00:00", "Z"
    )


def _unique_mapping(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise ValueError("duplicate JSON object key")
        value[key] = item
    return value


def _reject_constant(_value: str) -> None:
    raise ValueError("non-finite JSON number")


__all__ = [
    "CALIBRATION_INDEX_SCHEMA_VERSION",
    "CALIBRATION_PLAN_SCHEMA_VERSION",
    "GateError",
    "MODEL_CAPTURE_ERROR_SCHEMA_VERSION",
    "MODEL_CAPTURE_SCHEMA_VERSION",
    "ProgressCallback",
    "build_calibration_plan",
    "capture_calibration",
    "capture_calibration_inputs",
    "capture_execution_plan",
    "capture_model_evaluation",
]
