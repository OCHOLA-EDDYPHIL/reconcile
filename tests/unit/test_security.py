from __future__ import annotations

import pytest

from reconcile.security import (
    REDACTED,
    is_sensitive_key,
    redact_boundary_value,
    redact_untrusted_text,
    terminal_safe_text,
)


@pytest.mark.unit
@pytest.mark.parametrize(
    "name",
    [
        "authorization",
        "apiToken",
        "nested.private-key.value",
        "refreshToken",
        "session_credentials",
    ],
)
def test_sensitive_key_detection_covers_nested_and_compound_names(name: str) -> None:
    assert is_sensitive_key(name)


@pytest.mark.unit
def test_recursive_boundary_redaction_removes_keys_values_and_log_controls() -> None:
    marker = "must-not-cross-boundary"
    value = {
        "investigation_id": "investigation-7\nforged=true",
        "nested": {
            "api_token": marker,
            "provider_message": f"Bearer {marker}",
        },
    }

    sanitized = redact_boundary_value(value)
    encoded = repr(sanitized)

    assert marker not in encoded
    assert sanitized["nested"]["api_token"] == REDACTED
    assert "\\u000a" in sanitized["investigation_id"]


@pytest.mark.unit
def test_terminal_sanitizer_escapes_ansi_bidi_and_multiline_injection() -> None:
    value = "safe\x1b[31m\nforged\u202eresult"

    sanitized = terminal_safe_text(value)

    assert sanitized == "safe\\u001b[31m\\u000aforged\\u202eresult"
    assert "\x1b" not in sanitized
    assert "\n" not in sanitized
    assert "\u202e" not in sanitized


@pytest.mark.unit
def test_text_redaction_removes_assignment_authorization_jwt_and_pem_forms() -> None:
    jwt = "eyJabcdefgh.ijklmnop.qrstuvwx"
    value = (
        "password=must-not-cross Bearer must-not-cross-boundary "
        f"{jwt} -----BEGIN PRIVATE KEY-----\nmaterial\n"
        "-----END PRIVATE KEY-----"
    )

    sanitized = redact_untrusted_text(value)

    assert "must-not-cross" not in sanitized
    assert jwt not in sanitized
    assert "material" not in sanitized
    assert sanitized.count(REDACTED) == 4


@pytest.mark.unit
def test_boundary_sanitization_is_idempotent_after_control_escaping() -> None:
    value = "token=private-marker\n\x1b[31m forged\u202e"

    first = terminal_safe_text(value)
    second = terminal_safe_text(first)

    assert second == first


@pytest.mark.unit
def test_boundary_sanitizer_is_bounded_for_depth_and_collection_width() -> None:
    deep: object = "leaf"
    for _ in range(20):
        deep = {"safe": deep}
    wide = {f"item_{index}": index for index in range(200)}

    deep_sanitized = redact_boundary_value(deep)
    wide_sanitized = redact_boundary_value(wide)

    assert "[TRUNCATED]" in repr(deep_sanitized)
    assert len(wide_sanitized) == 129
    assert wide_sanitized["truncated"] is True


@pytest.mark.unit
def test_text_sanitizer_rejects_unbounded_or_non_string_input() -> None:
    with pytest.raises(ValueError, match="sanitization limit"):
        redact_untrusted_text("x" * 4097)
    with pytest.raises(TypeError, match="must be a string"):
        redact_untrusted_text(7)  # type: ignore[arg-type]
