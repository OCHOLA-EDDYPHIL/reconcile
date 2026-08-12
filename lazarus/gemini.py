from __future__ import annotations

from collections.abc import Callable, Mapping
from copy import deepcopy
from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import json
import math
from typing import Any, Protocol
import urllib.error
import urllib.request

from lazarus.locking import canonical_json_bytes


MODEL_INPUT_SCHEMA_VERSION = "lazarus.model-input/v1"
GEMINI_MODEL = "gemini-3.5-flash"
GEMINI_ENDPOINT = (
    "https://generativelanguage.googleapis.com/v1beta/"
    f"models/{GEMINI_MODEL}:generateContent"
)
DEFAULT_TIMEOUT_SECONDS = 60.0

_MODEL_INPUT_FIELDS = frozenset(
    {
        "schema_version",
        "arm",
        "system_prompt",
        "task_prompt",
        "semantic_output_schema",
        "semantic_output_schema_sha256",
        "ablation_policy",
        "disabled_relation_types",
        "case",
        "untrusted_artifacts",
    }
)

# These are the JSON Schema keywords accepted by Gemini responseJsonSchema.
_SUPPORTED_SCHEMA_KEYWORDS = frozenset(
    {
        "$id",
        "$defs",
        "$ref",
        "$anchor",
        "type",
        "format",
        "title",
        "description",
        "enum",
        "items",
        "prefixItems",
        "minItems",
        "maxItems",
        "minimum",
        "maximum",
        "anyOf",
        "oneOf",
        "properties",
        "additionalProperties",
        "required",
        "propertyOrdering",
    }
)

# These unsupported constraints occur in the authoritative Lazarus schema. The
# provider projection is intentionally weaker; the local protocol validator
# remains authoritative after generation. Other unknown keywords are rejected
# instead of being silently weakened.
_DROPPED_SCHEMA_KEYWORDS = frozenset(
    {
        "$schema",
        "allOf",
        "if",
        "then",
        "else",
        "not",
        "pattern",
        "minLength",
        "maxLength",
        "uniqueItems",
    }
)
_TOOL_PART_KEYS = frozenset(
    {
        "functionCall",
        "functionResponse",
        "executableCode",
        "codeExecutionResult",
    }
)


class GeminiError(ValueError):
    pass


class GeminiInputError(GeminiError):
    pass


class GeminiSchemaError(GeminiError):
    pass


class GeminiResponseError(GeminiError):
    def __init__(
        self,
        message: str,
        *,
        capture: GeminiInvocation | None = None,
    ) -> None:
        self.capture = capture
        super().__init__(message)


class GeminiTransportError(GeminiError):
    def __init__(self, message: str, *, capture: GeminiInvocation) -> None:
        self.capture = capture
        super().__init__(message)


class _HTTPResponse(Protocol):
    status: int

    def read(self) -> bytes: ...

    def close(self) -> None: ...


Transport = Callable[[urllib.request.Request, float], _HTTPResponse]
Clock = Callable[[], datetime]


class _NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    def redirect_request(
        self,
        request: urllib.request.Request,
        file_pointer: Any,
        code: int,
        message: str,
        headers: Any,
        new_url: str,
    ) -> None:
        return None


@dataclass(frozen=True, slots=True)
class GeminiCandidate:
    index: int | None
    finish_reason: str | None
    role: str | None
    text_parts: tuple[str, ...]
    parts: tuple[dict[str, Any], ...]
    tool_parts: tuple[dict[str, Any], ...]
    safety_ratings: tuple[dict[str, Any], ...]

    @property
    def response_text(self) -> str:
        return "".join(self.text_parts)


@dataclass(frozen=True, slots=True)
class GeminiResponse:
    response_id: str | None
    model_version: str | None
    usage_metadata: dict[str, Any] | None
    prompt_feedback: dict[str, Any] | None
    model_status: dict[str, Any] | None
    candidates: tuple[GeminiCandidate, ...]

    @property
    def response_text(self) -> str:
        if len(self.candidates) != 1:
            return ""
        return self.candidates[0].response_text

    @property
    def finish_reason(self) -> str | None:
        if len(self.candidates) != 1:
            return None
        return self.candidates[0].finish_reason

    @property
    def tool_parts(self) -> tuple[dict[str, Any], ...]:
        if len(self.candidates) != 1:
            return ()
        return self.candidates[0].tool_parts


@dataclass(frozen=True, slots=True)
class GeminiInvocation:
    url: str
    request_bytes: bytes
    response_bytes: bytes | None
    started_at: str
    completed_at: str
    http_status: int | None
    response: GeminiResponse | None

    @property
    def request_sha256(self) -> str:
        return hashlib.sha256(self.request_bytes).hexdigest()

    @property
    def response_sha256(self) -> str | None:
        if self.response_bytes is None:
            return None
        return hashlib.sha256(self.response_bytes).hexdigest()


def project_response_schema(schema: Mapping[str, Any]) -> dict[str, Any]:
    """Create the deterministic Gemini responseJsonSchema projection."""

    if not isinstance(schema, Mapping):
        raise GeminiSchemaError("response schema must be an object")
    projected = _project_schema(schema, path="$")
    return _inline_local_schema_refs(projected)


def build_generate_content_request(model_input: bytes) -> bytes:
    """Map locked canonical model-input bytes to the exact REST request body."""

    document = _parse_model_input(model_input)
    system_prompt = document.pop("system_prompt")
    schema_text = document["semantic_output_schema"]
    schema = _parse_json_text(
        schema_text,
        contract="semantic output schema",
        error_type=GeminiInputError,
    )
    if not isinstance(schema, Mapping):
        raise GeminiInputError("semantic output schema must be an object")
    projected_schema = project_response_schema(schema)

    request = {
        "systemInstruction": {"parts": [{"text": system_prompt}]},
        "contents": [
            {
                "role": "user",
                "parts": [
                    {"text": canonical_json_bytes(document).decode("utf-8")}
                ],
            }
        ],
        "generationConfig": {
            "temperature": 1.0,
            "topP": 1.0,
            "candidateCount": 1,
            "maxOutputTokens": 8192,
            "responseMimeType": "application/json",
            "responseJsonSchema": projected_schema,
            "thinkingConfig": {
                "thinkingLevel": "MEDIUM",
                "includeThoughts": False,
            },
        },
        "store": False,
        "serviceTier": "standard",
    }
    return canonical_json_bytes(request)


def extract_generate_content_response(response_bytes: bytes) -> GeminiResponse:
    """Extract provider metadata and candidate parts without parsing semantics."""

    document = _parse_json_bytes(
        response_bytes,
        contract="Gemini response",
        error_type=GeminiResponseError,
        require_canonical=False,
    )
    if not isinstance(document, Mapping):
        raise GeminiResponseError("Gemini response must be an object")

    candidates_value = document.get("candidates", [])
    if not isinstance(candidates_value, list):
        raise GeminiResponseError("Gemini response candidates must be an array")
    candidates: list[GeminiCandidate] = []
    for candidate_index, candidate_value in enumerate(candidates_value):
        path = f"candidates[{candidate_index}]"
        if not isinstance(candidate_value, Mapping):
            raise GeminiResponseError(f"{path} must be an object")
        index = candidate_value.get("index")
        if index is not None and (
            isinstance(index, bool) or not isinstance(index, int)
        ):
            raise GeminiResponseError(f"{path}.index must be an integer")
        finish_reason = candidate_value.get("finishReason")
        if finish_reason is not None and not isinstance(finish_reason, str):
            raise GeminiResponseError(f"{path}.finishReason must be text")

        content = candidate_value.get("content", {})
        if not isinstance(content, Mapping):
            raise GeminiResponseError(f"{path}.content must be an object")
        role = content.get("role")
        if role is not None and not isinstance(role, str):
            raise GeminiResponseError(f"{path}.content.role must be text")
        parts_value = content.get("parts", [])
        if not isinstance(parts_value, list):
            raise GeminiResponseError(f"{path}.content.parts must be an array")

        parts: list[dict[str, Any]] = []
        text_parts: list[str] = []
        tool_parts: list[dict[str, Any]] = []
        for part_index, part_value in enumerate(parts_value):
            part_path = f"{path}.content.parts[{part_index}]"
            if not isinstance(part_value, Mapping):
                raise GeminiResponseError(f"{part_path} must be an object")
            part = deepcopy(dict(part_value))
            text_value = part.get("text")
            if text_value is not None:
                if not isinstance(text_value, str):
                    raise GeminiResponseError(f"{part_path}.text must be text")
                text_parts.append(text_value)
            parts.append(part)
            if _TOOL_PART_KEYS.intersection(part):
                tool_parts.append(deepcopy(part))

        safety_value = candidate_value.get("safetyRatings", [])
        if not isinstance(safety_value, list) or any(
            not isinstance(rating, Mapping) for rating in safety_value
        ):
            raise GeminiResponseError(f"{path}.safetyRatings must be an object array")
        candidates.append(
            GeminiCandidate(
                index=index,
                finish_reason=finish_reason,
                role=role,
                text_parts=tuple(text_parts),
                parts=tuple(parts),
                tool_parts=tuple(tool_parts),
                safety_ratings=tuple(deepcopy(dict(value)) for value in safety_value),
            )
        )

    return GeminiResponse(
        response_id=_optional_text(document, "responseId"),
        model_version=_optional_text(document, "modelVersion"),
        usage_metadata=_optional_mapping(document, "usageMetadata"),
        prompt_feedback=_optional_mapping(document, "promptFeedback"),
        model_status=_optional_mapping(document, "modelStatus"),
        candidates=tuple(candidates),
    )


def invoke_generate_content(
    model_input: bytes,
    api_key: str,
    *,
    transport: Transport | None = None,
    timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS,
    clock: Clock | None = None,
) -> GeminiInvocation:
    """Perform exactly one Gemini request and retain a replayable body capture."""

    _validate_api_key(api_key)
    if (
        isinstance(timeout_seconds, bool)
        or not isinstance(timeout_seconds, (int, float))
        or not math.isfinite(timeout_seconds)
        or timeout_seconds <= 0
    ):
        raise GeminiInputError("timeout_seconds must be a positive finite number")
    request_bytes = build_generate_content_request(model_input)
    request = urllib.request.Request(
        GEMINI_ENDPOINT,
        data=request_bytes,
        headers={
            "Accept": "application/json",
            "Content-Type": "application/json",
            "X-Goog-Api-Key": api_key,
        },
        method="POST",
    )
    selected_transport = transport or _urllib_transport
    selected_clock = clock or _utc_now
    started_at = _timestamp(selected_clock())

    try:
        provider_response = selected_transport(request, float(timeout_seconds))
        try:
            status = _response_status(provider_response)
            response_bytes = provider_response.read()
            if not isinstance(response_bytes, bytes):
                raise TypeError("transport response body is not bytes")
        finally:
            close = getattr(provider_response, "close", None)
            if callable(close):
                close()
    except urllib.error.HTTPError as exc:
        try:
            response_bytes = exc.read()
        except Exception:
            response_bytes = b""
        completed_at = _timestamp(selected_clock())
        capture = GeminiInvocation(
            url=GEMINI_ENDPOINT,
            request_bytes=request_bytes,
            response_bytes=response_bytes,
            started_at=started_at,
            completed_at=completed_at,
            http_status=exc.code,
            response=None,
        )
        raise GeminiTransportError(
            f"Gemini returned HTTP {exc.code}", capture=capture
        ) from None
    except Exception:
        completed_at = _timestamp(selected_clock())
        capture = GeminiInvocation(
            url=GEMINI_ENDPOINT,
            request_bytes=request_bytes,
            response_bytes=None,
            started_at=started_at,
            completed_at=completed_at,
            http_status=None,
            response=None,
        )
        raise GeminiTransportError("Gemini transport failed", capture=capture) from None

    completed_at = _timestamp(selected_clock())
    capture = GeminiInvocation(
        url=GEMINI_ENDPOINT,
        request_bytes=request_bytes,
        response_bytes=response_bytes,
        started_at=started_at,
        completed_at=completed_at,
        http_status=status,
        response=None,
    )
    if status != 200:
        raise GeminiTransportError(
            f"Gemini returned HTTP {status}", capture=capture
        )
    try:
        extracted = extract_generate_content_response(response_bytes)
    except GeminiResponseError as exc:
        raise GeminiResponseError(str(exc), capture=capture) from None
    return GeminiInvocation(
        url=capture.url,
        request_bytes=capture.request_bytes,
        response_bytes=capture.response_bytes,
        started_at=capture.started_at,
        completed_at=capture.completed_at,
        http_status=capture.http_status,
        response=extracted,
    )


def _project_schema(source: Mapping[str, Any], *, path: str) -> dict[str, Any]:
    if not isinstance(source, Mapping):
        raise GeminiSchemaError(f"{path} must be an object")
    unknown = set(source) - _SUPPORTED_SCHEMA_KEYWORDS - _DROPPED_SCHEMA_KEYWORDS - {
        "const"
    }
    if unknown:
        name = sorted(unknown)[0]
        raise GeminiSchemaError(f"unsupported schema keyword at {path}: {name}")

    has_ref = "$ref" in source
    if has_ref:
        invalid_sibling = next(
            (key for key in source if key != "$ref" and not key.startswith("$")),
            None,
        )
        if invalid_sibling is not None:
            raise GeminiSchemaError(
                f"$ref at {path} has unsupported sibling: {invalid_sibling}"
            )
    projected: dict[str, Any] = {}
    source_properties = source.get("properties")
    for key, value in source.items():
        if key in _DROPPED_SCHEMA_KEYWORDS or key == "propertyOrdering":
            continue
        if key == "const":
            if "enum" in source:
                raise GeminiSchemaError(f"{path} cannot contain both const and enum")
            _validate_enum_value(value, f"{path}.const")
            projected["enum"] = [deepcopy(value)]
            if "type" not in source:
                projected["type"] = _value_schema_type(value)
            continue
        if key in {"$id", "$ref", "$anchor", "format", "title", "description"}:
            if not isinstance(value, str) or not value:
                raise GeminiSchemaError(f"{path}.{key} must be non-empty text")
            projected[key] = value
            continue
        if key == "type":
            if value not in {
                "null",
                "boolean",
                "object",
                "array",
                "number",
                "integer",
                "string",
            }:
                raise GeminiSchemaError(f"{path}.type is unsupported")
            projected[key] = value
            continue
        if key == "enum":
            if not isinstance(value, list) or not value:
                raise GeminiSchemaError(f"{path}.enum must be a non-empty array")
            for index, member in enumerate(value):
                _validate_enum_value(member, f"{path}.enum[{index}]")
            if len({json.dumps(member) for member in value}) != len(value):
                raise GeminiSchemaError(f"{path}.enum must contain unique values")
            projected[key] = deepcopy(value)
            if "type" not in source and "const" not in source:
                inferred = {_value_schema_type(member) for member in value}
                if inferred == {"integer", "number"}:
                    projected["type"] = "number"
                elif len(inferred) == 1:
                    projected["type"] = inferred.pop()
                else:
                    raise GeminiSchemaError(f"{path}.enum has mixed value types")
            continue
        if key in {"items", "additionalProperties"}:
            if key == "additionalProperties" and isinstance(value, bool):
                projected[key] = value
            elif isinstance(value, Mapping):
                projected[key] = _project_schema(
                    value,
                    path=f"{path}.{key}",
                )
            else:
                raise GeminiSchemaError(f"{path}.{key} must be a schema object")
            continue
        if key == "prefixItems":
            projected[key] = _project_schema_array(value, path=f"{path}.{key}")
            continue
        if key in {"anyOf", "oneOf"}:
            choices = _project_schema_array(value, path=f"{path}.{key}")
            if not choices:
                raise GeminiSchemaError(f"{path}.{key} cannot be empty")
            projected[key] = choices
            continue
        if key in {"minItems", "maxItems"}:
            if isinstance(value, bool) or not isinstance(value, int) or value < 0:
                raise GeminiSchemaError(f"{path}.{key} must be a nonnegative integer")
            projected[key] = value
            continue
        if key in {"minimum", "maximum"}:
            if (
                isinstance(value, bool)
                or not isinstance(value, (int, float))
                or not math.isfinite(value)
            ):
                raise GeminiSchemaError(f"{path}.{key} must be a finite number")
            projected[key] = value
            continue
        if key in {"properties", "$defs"}:
            if not isinstance(value, Mapping):
                raise GeminiSchemaError(f"{path}.{key} must be an object")
            members: dict[str, Any] = {}
            for name, member in value.items():
                if not isinstance(name, str) or not name:
                    raise GeminiSchemaError(f"{path}.{key} has an invalid name")
                if not isinstance(member, Mapping):
                    raise GeminiSchemaError(f"{path}.{key}.{name} must be an object")
                members[name] = _project_schema(
                    member,
                    path=f"{path}.{key}.{name}",
                )
            projected[key] = members
            continue
        if key == "required":
            if (
                not isinstance(value, list)
                or any(not isinstance(member, str) or not member for member in value)
                or len(set(value)) != len(value)
            ):
                raise GeminiSchemaError(f"{path}.required must contain unique names")
            projected[key] = list(value)
            continue
        raise GeminiSchemaError(f"unsupported schema keyword at {path}: {key}")

    if isinstance(source_properties, Mapping):
        property_names = list(source_properties)
        required = projected.get("required")
        if isinstance(required, list) and any(
            name not in source_properties for name in required
        ):
            raise GeminiSchemaError(f"{path}.required names an unknown property")
        supplied_order = source.get("propertyOrdering")
        if supplied_order is not None and supplied_order != property_names:
            raise GeminiSchemaError(f"{path}.propertyOrdering must match properties")
        projected["propertyOrdering"] = property_names
    elif "propertyOrdering" in source:
        raise GeminiSchemaError(f"{path}.propertyOrdering requires properties")

    declared_type = source.get("type")
    constrained_values = (
        [source["const"]]
        if "const" in source
        else source.get("enum", [])
    )
    if declared_type is not None and any(
        not _value_matches_schema_type(value, declared_type)
        for value in constrained_values
    ):
        raise GeminiSchemaError(f"{path} enum values do not match type")
    return projected


def _project_schema_array(value: Any, *, path: str) -> list[dict[str, Any]]:
    if not isinstance(value, list):
        raise GeminiSchemaError(f"{path} must be an array")
    projected: list[dict[str, Any]] = []
    for index, member in enumerate(value):
        if not isinstance(member, Mapping):
            raise GeminiSchemaError(f"{path}[{index}] must be an object")
        projected.append(
            _project_schema(member, path=f"{path}[{index}]")
        )
    return projected


def _inline_local_schema_refs(projected: Mapping[str, Any]) -> dict[str, Any]:
    definitions = projected.get("$defs", {})
    if not isinstance(definitions, Mapping):
        raise GeminiSchemaError("$.$defs must be an object")

    def resolve(value: Any, *, path: str, stack: tuple[str, ...]) -> Any:
        if isinstance(value, list):
            return [
                resolve(item, path=f"{path}[{index}]", stack=stack)
                for index, item in enumerate(value)
            ]
        if not isinstance(value, Mapping):
            return deepcopy(value)
        reference = value.get("$ref")
        if reference is not None:
            if set(value) != {"$ref"} or not isinstance(reference, str):
                raise GeminiSchemaError(f"{path} has an unsupported $ref shape")
            prefix = "#/$defs/"
            if not reference.startswith(prefix):
                raise GeminiSchemaError(f"{path} uses a non-local $ref")
            encoded_name = reference[len(prefix) :]
            if not encoded_name or "/" in encoded_name:
                raise GeminiSchemaError(f"{path} uses an unsupported $ref pointer")
            name = encoded_name.replace("~1", "/").replace("~0", "~")
            target = definitions.get(name)
            if not isinstance(target, Mapping):
                raise GeminiSchemaError(f"{path} references an undefined schema")
            if name in stack:
                raise GeminiSchemaError(f"{path} contains a recursive schema reference")
            return resolve(
                target,
                path=f"$.$defs.{name}",
                stack=(*stack, name),
            )
        return {
            key: resolve(item, path=f"{path}.{key}", stack=stack)
            for key, item in value.items()
            if key != "$defs"
        }

    resolved = resolve(projected, path="$", stack=())
    if not isinstance(resolved, dict):
        raise GeminiSchemaError("projected response schema must be an object")
    return resolved


def _parse_model_input(model_input: bytes) -> dict[str, Any]:
    document = _parse_json_bytes(
        model_input,
        contract="model input",
        error_type=GeminiInputError,
        require_canonical=True,
    )
    if not isinstance(document, dict):
        raise GeminiInputError("model input must be an object")
    if set(document) != _MODEL_INPUT_FIELDS:
        raise GeminiInputError("model input fields do not match the protocol")
    if document.get("schema_version") != MODEL_INPUT_SCHEMA_VERSION:
        raise GeminiInputError("unsupported model input schema")
    system_prompt = document.get("system_prompt")
    if not isinstance(system_prompt, str) or not system_prompt.strip():
        raise GeminiInputError("model input requires a non-empty system_prompt")
    schema_text = document.get("semantic_output_schema")
    schema_digest = document.get("semantic_output_schema_sha256")
    if not isinstance(schema_text, str) or not schema_text:
        raise GeminiInputError("model input requires semantic_output_schema text")
    if not isinstance(schema_digest, str) or schema_digest != hashlib.sha256(
        schema_text.encode("utf-8")
    ).hexdigest():
        raise GeminiInputError("semantic output schema digest mismatch")
    return deepcopy(document)


def _parse_json_bytes(
    payload: bytes,
    *,
    contract: str,
    error_type: type[GeminiError],
    require_canonical: bool,
) -> Any:
    if not isinstance(payload, bytes):
        raise error_type(f"{contract} must be bytes")
    try:
        text = payload.decode("utf-8", errors="strict")
    except UnicodeError:
        raise error_type(f"{contract} must be UTF-8") from None
    value = _parse_json_text(text, contract=contract, error_type=error_type)
    if require_canonical:
        try:
            canonical = canonical_json_bytes(value)
        except (TypeError, ValueError):
            raise error_type(f"{contract} is not canonical JSON") from None
        if canonical != payload:
            raise error_type(f"{contract} must use canonical JSON bytes")
    return value


def _parse_json_text(
    text: str,
    *,
    contract: str,
    error_type: type[GeminiError],
) -> Any:
    def unique_mapping(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        mapping: dict[str, Any] = {}
        for key, value in pairs:
            if key in mapping:
                raise ValueError(f"duplicate key: {key}")
            mapping[key] = value
        return mapping

    def reject_constant(value: str) -> None:
        raise ValueError(f"non-finite number: {value}")

    try:
        return json.loads(
            text,
            object_pairs_hook=unique_mapping,
            parse_constant=reject_constant,
        )
    except (TypeError, ValueError, json.JSONDecodeError):
        raise error_type(f"{contract} is not strict JSON") from None


def _validate_enum_value(value: Any, path: str) -> None:
    if isinstance(value, bool) or not isinstance(value, (str, int, float)):
        raise GeminiSchemaError(f"{path} must be a string or number")
    if isinstance(value, float) and not math.isfinite(value):
        raise GeminiSchemaError(f"{path} must be finite")


def _value_schema_type(value: str | int | float) -> str:
    if isinstance(value, str):
        return "string"
    if isinstance(value, int):
        return "integer"
    return "number"


def _value_matches_schema_type(value: Any, schema_type: str) -> bool:
    if schema_type == "string":
        return isinstance(value, str)
    if schema_type == "integer":
        return isinstance(value, int) and not isinstance(value, bool)
    if schema_type == "number":
        return isinstance(value, (int, float)) and not isinstance(value, bool)
    return False


def _optional_text(document: Mapping[str, Any], field: str) -> str | None:
    value = document.get(field)
    if value is not None and not isinstance(value, str):
        raise GeminiResponseError(f"Gemini response {field} must be text")
    return value


def _optional_mapping(
    document: Mapping[str, Any], field: str
) -> dict[str, Any] | None:
    value = document.get(field)
    if value is None:
        return None
    if not isinstance(value, Mapping):
        raise GeminiResponseError(f"Gemini response {field} must be an object")
    return deepcopy(dict(value))


def _validate_api_key(api_key: str) -> None:
    if (
        not isinstance(api_key, str)
        or not api_key
        or api_key != api_key.strip()
        or any(ord(character) < 33 or ord(character) == 127 for character in api_key)
    ):
        raise GeminiInputError("api_key must be non-empty header-safe text")


def _response_status(response: _HTTPResponse) -> int:
    status = getattr(response, "status", None)
    if status is None:
        getcode = getattr(response, "getcode", None)
        status = getcode() if callable(getcode) else None
    if isinstance(status, bool) or not isinstance(status, int):
        raise TypeError("transport response has no integer status")
    return status


def _urllib_transport(
    request: urllib.request.Request, timeout_seconds: float
) -> _HTTPResponse:
    opener = urllib.request.build_opener(_NoRedirectHandler())
    return opener.open(request, timeout=timeout_seconds)


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _timestamp(value: datetime) -> str:
    if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() is None:
        raise GeminiInputError("clock must return an aware datetime")
    return value.astimezone(timezone.utc).isoformat(timespec="microseconds").replace(
        "+00:00", "Z"
    )
