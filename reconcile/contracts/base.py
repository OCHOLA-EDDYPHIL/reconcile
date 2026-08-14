"""Strict shared primitives for versioned wire contracts."""

from __future__ import annotations

import json
import math
from datetime import UTC, datetime
from typing import Annotated

from pydantic import (
    AfterValidator,
    BaseModel,
    ConfigDict,
    Field,
    JsonValue,
    StringConstraints,
)

from reconcile.security import contains_sensitive_material, is_sensitive_key


def _validate_unicode_text(value: str) -> str:
    try:
        value.encode("utf-8")
    except UnicodeEncodeError as error:
        raise ValueError("text must contain Unicode scalar values") from error
    return value


Identifier = Annotated[
    str,
    StringConstraints(
        min_length=1,
        max_length=128,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]*$",
    ),
    AfterValidator(_validate_unicode_text),
]
NonEmptyText = Annotated[
    str,
    StringConstraints(min_length=1, max_length=4096),
    AfterValidator(_validate_unicode_text),
]
ShortText = Annotated[
    str,
    StringConstraints(min_length=1, max_length=512),
    AfterValidator(_validate_unicode_text),
]
Sha256Digest = Annotated[
    str,
    StringConstraints(pattern=r"^[0-9a-f]{64}$"),
]


def _normalize_datetime(value: datetime) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("timestamp must include a UTC offset")
    return value.astimezone(UTC)


AwareDatetime = Annotated[datetime, AfterValidator(_normalize_datetime)]


def _validate_json(value: JsonValue, *, depth: int = 0) -> JsonValue:
    if depth > 12:
        raise ValueError("JSON value exceeds maximum nesting depth")
    if value is None or isinstance(value, bool):
        return value
    if isinstance(value, str):
        try:
            value.encode("utf-8")
        except UnicodeEncodeError as error:
            raise ValueError(
                "JSON strings must contain Unicode scalar values"
            ) from error
        return value
    if isinstance(value, int):
        if not -(2**63) <= value < 2**63:
            raise ValueError("integer is outside signed 64-bit range")
        return value
    if isinstance(value, float):
        if not math.isfinite(value):
            raise ValueError("JSON numbers must be finite")
        return value
    if isinstance(value, list):
        for item in value:
            _validate_json(item, depth=depth + 1)
        return value
    if isinstance(value, dict):
        if len(value) > 128:
            raise ValueError("JSON object has too many keys")
        for key, item in value.items():
            if not key or len(key) > 128:
                raise ValueError("JSON object keys must be bounded and nonempty")
            try:
                key.encode("utf-8")
            except UnicodeEncodeError as error:
                raise ValueError(
                    "JSON object keys must contain Unicode scalar values"
                ) from error
            _validate_json(item, depth=depth + 1)
        return value
    raise ValueError("value is not representable as JSON")


def _validate_json_object(value: dict[str, JsonValue]) -> dict[str, JsonValue]:
    _validate_json(value)
    return value


type JsonObject = Annotated[
    dict[str, JsonValue],
    Field(max_length=128),
    AfterValidator(_validate_json_object),
]
type SmallJsonObject = Annotated[
    dict[str, JsonValue],
    Field(max_length=32),
    AfterValidator(_validate_json_object),
]
type NonEmptySmallJsonObject = Annotated[
    dict[str, JsonValue],
    Field(min_length=1, max_length=32),
    AfterValidator(_validate_json_object),
]
type ArgumentsObject = Annotated[
    dict[str, JsonValue],
    Field(max_length=64),
    AfterValidator(_validate_json_object),
]

def reject_sensitive_keys(value: JsonValue) -> None:
    """Reject credential-shaped fields from secret-free public objects."""

    if isinstance(value, dict):
        for key, item in value.items():
            if is_sensitive_key(key):
                raise ValueError("secret-bearing fields are not allowed")
            reject_sensitive_keys(item)
    elif isinstance(value, list):
        for item in value:
            reject_sensitive_keys(item)


def reject_sensitive_values(value: JsonValue) -> None:
    """Reject strong credential signatures from secret-free public objects."""

    if isinstance(value, str):
        if contains_sensitive_material(value):
            raise ValueError("secret-bearing values are not allowed")
    elif isinstance(value, dict):
        for item in value.values():
            reject_sensitive_values(item)
    elif isinstance(value, list):
        for item in value:
            reject_sensitive_values(item)


class StrictModel(BaseModel):
    """Immutable, strict, unknown-field-rejecting contract base."""

    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        revalidate_instances="always",
        strict=True,
        validate_default=True,
    )


def canonical_json_value_bytes(value: JsonValue) -> bytes:
    """Serialize an already validated JSON value with the wire key ordering."""

    _validate_json(value)
    return json.dumps(
        value,
        allow_nan=False,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
