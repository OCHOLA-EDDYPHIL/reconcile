"""Canonical JSON encoding and explicit version-aware contract decoding."""

from __future__ import annotations

import hashlib
import json
import math
from datetime import UTC, datetime
from enum import Enum
from typing import Any

from pydantic import BaseModel, ValidationError
from pydantic_core import PydanticUndefined


class ContractError(ValueError):
    """A safe public contract failure with a stable error code."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


def _reject_constant(value: str) -> None:
    raise ValueError(f"non-finite JSON number is not allowed: {value}")


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON object key: {key}")
        result[key] = value
    return result


def _expected_version(model_type: type[BaseModel]) -> str:
    field = model_type.model_fields.get("schema_version")
    if field is None:
        raise TypeError("contract model has no schema_version field")
    annotation = field.annotation
    values = getattr(annotation, "__args__", ())
    if len(values) != 1 or not isinstance(values[0], str):
        if field.default is PydanticUndefined or not isinstance(field.default, str):
            raise TypeError("contract model does not declare one exact schema version")
        return field.default
    return values[0]


def decode_contract[ContractModel: BaseModel](
    payload: bytes | str,
    model_type: type[ContractModel],
) -> ContractModel:
    """Decode one versioned payload without accepting duplicate keys or versions."""

    try:
        text = payload.decode("utf-8") if isinstance(payload, bytes) else payload
    except UnicodeDecodeError as error:
        raise ContractError(
            "invalid_contract", "contract is not valid UTF-8"
        ) from error
    try:
        value = json.loads(
            text,
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=_reject_constant,
        )
    except (RecursionError, TypeError, ValueError, json.JSONDecodeError) as error:
        raise ContractError("invalid_contract", "contract is not valid JSON") from error
    if not isinstance(value, dict):
        raise ContractError("invalid_contract", "contract must be a JSON object")

    version = value.get("schema_version")
    if not isinstance(version, str):
        raise ContractError("invalid_contract", "schema_version is required")
    try:
        version.encode("utf-8")
    except UnicodeEncodeError as error:
        raise ContractError(
            "invalid_contract",
            "schema_version must contain Unicode scalar values",
        ) from error
    if version != _expected_version(model_type):
        raise ContractError(
            "unsupported_contract_version",
            "contract schema_version is unsupported",
        )

    try:
        normalized = json.dumps(
            value,
            allow_nan=False,
            ensure_ascii=False,
            separators=(",", ":"),
        )
        return model_type.model_validate_json(normalized)
    except ValidationError as error:
        if any(
            item["type"] == "literal_error"
            and item["loc"]
            and item["loc"][-1] == "schema_version"
            and isinstance(item["input"], str)
            for item in error.errors()
        ):
            raise ContractError(
                "unsupported_contract_version",
                "contract contains an unsupported nested schema_version",
            ) from error
        raise ContractError("invalid_contract", "contract validation failed") from error
    except (RecursionError, TypeError, ValueError) as error:
        raise ContractError("invalid_contract", "contract validation failed") from error


def _canonical_value(value: Any) -> Any:
    if isinstance(value, BaseModel):
        return _canonical_value(value.model_dump(mode="python"))
    if isinstance(value, datetime):
        if value.tzinfo is None or value.utcoffset() is None:
            raise ContractError("invalid_contract", "timestamp lacks a UTC offset")
        utc = value.astimezone(UTC)
        timespec = "microseconds" if utc.microsecond else "seconds"
        return utc.isoformat(timespec=timespec).replace("+00:00", "Z")
    if isinstance(value, Enum):
        return _canonical_value(value.value)
    if value is None or isinstance(value, (bool, str, int)):
        return value
    if isinstance(value, float):
        if not math.isfinite(value):
            raise ContractError("invalid_contract", "JSON numbers must be finite")
        return value
    if isinstance(value, (list, tuple)):
        return [_canonical_value(item) for item in value]
    if isinstance(value, dict):
        if not all(isinstance(key, str) for key in value):
            raise ContractError("invalid_contract", "JSON object keys must be strings")
        return {key: _canonical_value(item) for key, item in value.items()}
    raise ContractError("invalid_contract", "value cannot be represented as JSON")


def canonical_json_bytes(model: BaseModel) -> bytes:
    """Return compact, key-sorted UTF-8 for a validated contract model."""

    try:
        validated = type(model).model_validate(model)
        return json.dumps(
            _canonical_value(validated),
            allow_nan=False,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
    except (TypeError, ValueError) as error:
        if isinstance(error, ContractError):
            raise
        raise ContractError("invalid_contract", "canonical encoding failed") from error


def canonical_sha256(model: BaseModel) -> str:
    """Return the SHA-256 digest of a model's canonical wire representation."""

    return hashlib.sha256(canonical_json_bytes(model)).hexdigest()
