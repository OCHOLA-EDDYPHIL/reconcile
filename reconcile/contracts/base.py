"""Strict shared primitives for versioned wire contracts."""

from __future__ import annotations

import json
import math
import re
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

_SENSITIVE_KEY_TOKENS = frozenset(
    {
        "authorization",
        "cookie",
        "credential",
        "credentials",
        "header",
        "headers",
        "password",
        "secret",
        "token",
    }
)
_SENSITIVE_KEY_NAMES = frozenset(
    {
        "access_key",
        "api_key",
        "private_key",
        "refresh_key",
        "session_key",
        "signing_key",
    }
)


def reject_sensitive_keys(value: JsonValue) -> None:
    """Reject credential-shaped fields from secret-free public objects."""

    if isinstance(value, dict):
        for key, item in value.items():
            normalized = re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", key).lower()
            normalized = re.sub(r"[^a-z0-9]+", "_", normalized).strip("_")
            tokens = {part for part in normalized.split("_") if part}
            wrapped_name = f"_{normalized}_"
            contains_sensitive_name = any(
                f"_{name}_" in wrapped_name for name in _SENSITIVE_KEY_NAMES
            )
            collapsed_name = normalized.replace("_", "")
            contains_collapsed_sensitive_name = any(
                name.replace("_", "") in collapsed_name for name in _SENSITIVE_KEY_NAMES
            )
            if (
                contains_sensitive_name
                or contains_collapsed_sensitive_name
                or tokens.intersection(_SENSITIVE_KEY_TOKENS)
            ):
                raise ValueError("secret-bearing fields are not allowed")
            reject_sensitive_keys(item)
    elif isinstance(value, list):
        for item in value:
            reject_sensitive_keys(item)


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
