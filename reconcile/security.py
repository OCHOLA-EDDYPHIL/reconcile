"""Bounded sanitization for untrusted data crossing public boundaries."""

from __future__ import annotations

import re
import unicodedata
from collections.abc import Mapping, Sequence
from typing import Any

REDACTED = "[REDACTED]"

_MAX_SANITIZE_DEPTH = 12
_MAX_SANITIZE_ITEMS = 128
_MAX_TEXT_LENGTH = 4096

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
_ASSIGNMENT_SECRET = re.compile(
    r"(?i)\b(api[ _-]?key|access[ _-]?key|authorization|credential|"
    r"password|private[ _-]?key|refresh[ _-]?token|secret|session[ _-]?key|"
    r"token)\b(\s*[:=]\s*)([^\s,;]+)"
)
_AUTHORIZATION_SECRET = re.compile(
    r"(?i)\b(bearer|basic)\s+[A-Za-z0-9._~+/=-]{8,}"
)
_JWT_SECRET = re.compile(
    r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b"
)
_GOOGLE_API_KEY = re.compile(r"\bAIza[0-9A-Za-z_-]{20,}\b")
_PEM_PRIVATE_KEY = re.compile(
    r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----.*?"
    r"-----END [A-Z0-9 ]*PRIVATE KEY-----",
    re.DOTALL,
)


def _normalized_key(value: str) -> str:
    words = re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", value).lower()
    return re.sub(r"[^a-z0-9]+", "_", words).strip("_")


def is_sensitive_key(value: object) -> bool:
    """Return whether a field name is credential-shaped."""

    if type(value) is not str or not value:
        return False
    normalized = _normalized_key(value)
    tokens = {part for part in normalized.split("_") if part}
    wrapped = f"_{normalized}_"
    collapsed = normalized.replace("_", "")
    return bool(
        tokens.intersection(_SENSITIVE_KEY_TOKENS)
        or any(f"_{name}_" in wrapped for name in _SENSITIVE_KEY_NAMES)
        or any(name.replace("_", "") in collapsed for name in _SENSITIVE_KEY_NAMES)
    )


def redact_untrusted_text(value: str) -> str:
    """Redact common credential forms from one already bounded text value."""

    if type(value) is not str:
        raise TypeError("untrusted text must be a string")
    try:
        value.encode("utf-8")
    except UnicodeEncodeError as error:
        raise ValueError("untrusted text must contain Unicode scalar values") from error
    if len(value) > _MAX_TEXT_LENGTH:
        raise ValueError("untrusted text exceeds the sanitization limit")

    sanitized = _PEM_PRIVATE_KEY.sub(REDACTED, value)
    sanitized = _AUTHORIZATION_SECRET.sub(REDACTED, sanitized)
    sanitized = _JWT_SECRET.sub(REDACTED, sanitized)
    sanitized = _GOOGLE_API_KEY.sub(REDACTED, sanitized)
    sanitized = _ASSIGNMENT_SECRET.sub(
        lambda match: f"{match.group(1)}{match.group(2)}{REDACTED}",
        sanitized,
    )
    return sanitized


def contains_sensitive_material(value: object) -> bool:
    """Return whether bounded text contains a strong credential signature."""

    if type(value) is not str:
        return False
    try:
        value.encode("utf-8")
    except UnicodeEncodeError:
        return True
    return any(
        pattern.search(value) is not None
        for pattern in (
            _PEM_PRIVATE_KEY,
            _AUTHORIZATION_SECRET,
            _JWT_SECRET,
            _GOOGLE_API_KEY,
            _ASSIGNMENT_SECRET,
        )
    )


def terminal_safe_text(value: str) -> str:
    """Escape characters that can alter terminal, log-line, or bidi rendering."""

    value = redact_untrusted_text(value)
    output: list[str] = []
    for character in value:
        category = unicodedata.category(character)
        if category.startswith("C") or category in {"Zl", "Zp"}:
            codepoint = ord(character)
            escape = "\\u" if codepoint <= 0xFFFF else "\\U"
            width = 4 if codepoint <= 0xFFFF else 8
            output.append(f"{escape}{codepoint:0{width}x}")
        else:
            output.append(character)
    return "".join(output)


def redact_boundary_value(
    value: Any,
    *,
    _depth: int = 0,
) -> Any:
    """Return a bounded recursive copy suitable for structured telemetry."""

    if _depth > _MAX_SANITIZE_DEPTH:
        return "[TRUNCATED]"
    if value is None or type(value) in {bool, int, float}:
        return value
    if isinstance(value, str):
        return terminal_safe_text(value)
    if isinstance(value, Mapping):
        output: dict[str, Any] = {}
        for index, (key, item) in enumerate(value.items()):
            if index >= _MAX_SANITIZE_ITEMS:
                output["truncated"] = True
                break
            safe_key = terminal_safe_text(str(key))
            output[safe_key] = (
                REDACTED
                if is_sensitive_key(key)
                else redact_boundary_value(item, _depth=_depth + 1)
            )
        return output
    if isinstance(value, Sequence) and not isinstance(value, (bytes, bytearray)):
        return [
            redact_boundary_value(item, _depth=_depth + 1)
            for item in value[:_MAX_SANITIZE_ITEMS]
        ]
    return terminal_safe_text(type(value).__name__)


__all__ = [
    "REDACTED",
    "contains_sensitive_material",
    "is_sensitive_key",
    "redact_boundary_value",
    "redact_untrusted_text",
    "terminal_safe_text",
]
