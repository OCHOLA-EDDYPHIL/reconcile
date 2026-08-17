"""Deterministic checks for the hosted application identity boundary."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

import pytest

from reconcile.hosted.identity import (
    GoogleIdentityVerifier,
    IdentityVerificationError,
    validate_platform_authorization,
)

pytestmark = pytest.mark.unit

NOW = 2_000_000_000
AUDIENCE = "https://controller.example.test"
CALLER = "api@project.example.iam.gserviceaccount.com"
TOKEN = "header.payload.signature"


def _claims(**updates: Any) -> dict[str, Any]:
    claims: dict[str, Any] = {
        "aud": AUDIENCE,
        "email": CALLER,
        "email_verified": True,
        "exp": NOW + 300,
        "iat": NOW - 30,
        "iss": "https://accounts.google.com",
        "sub": "123456789012345678901",
    }
    claims.update(updates)
    return claims


@pytest.mark.parametrize(
    "issuer",
    ("accounts.google.com", "https://accounts.google.com"),
)
def test_verifier_accepts_only_exact_google_issuer_and_route_caller(
    issuer: str,
) -> None:
    calls: list[tuple[str, str]] = []

    def verify(token: str, audience: str) -> Mapping[str, Any]:
        calls.append((token, audience))
        return _claims(iss=issuer)

    caller = GoogleIdentityVerifier(verify, clock=lambda: NOW).verify(
        f"Bearer {TOKEN}",
        AUDIENCE,
        frozenset({CALLER}),
    )

    assert calls == [(TOKEN, AUDIENCE)]
    assert caller.email == CALLER
    assert caller.subject == "123456789012345678901"
    assert caller.issuer == issuer
    assert caller.audience == AUDIENCE
    assert caller.expires_at == NOW + 300


@pytest.mark.parametrize(
    ("claim_updates", "expected_audience", "allowed_emails"),
    (
        ({"iss": "https://accounts.google.com/"}, AUDIENCE, frozenset({CALLER})),
        ({"iss": "https://evil.example"}, AUDIENCE, frozenset({CALLER})),
        ({"aud": f"{AUDIENCE}/"}, AUDIENCE, frozenset({CALLER})),
        ({"aud": [AUDIENCE]}, AUDIENCE, frozenset({CALLER})),
        ({"email": CALLER.upper()}, AUDIENCE, frozenset({CALLER})),
        ({"email_verified": False}, AUDIENCE, frozenset({CALLER})),
        ({"email_verified": "true"}, AUDIENCE, frozenset({CALLER})),
        ({"exp": NOW}, AUDIENCE, frozenset({CALLER})),
        ({"exp": str(NOW + 300)}, AUDIENCE, frozenset({CALLER})),
        ({"iat": NOW + 61}, AUDIENCE, frozenset({CALLER})),
        ({"nbf": NOW + 61}, AUDIENCE, frozenset({CALLER})),
        ({"sub": ""}, AUDIENCE, frozenset({CALLER})),
        ({}, f"{AUDIENCE}/", frozenset({CALLER})),
        ({}, AUDIENCE, frozenset({"controller@project.example"})),
    ),
)
def test_verifier_rejects_nonexact_or_invalid_claims_and_policy(
    claim_updates: dict[str, Any],
    expected_audience: str,
    allowed_emails: frozenset[str],
) -> None:
    verifier = GoogleIdentityVerifier(
        lambda _token, _audience: _claims(**claim_updates),
        clock=lambda: NOW,
    )

    with pytest.raises(
        IdentityVerificationError,
        match=r"^application identity could not be verified$",
    ):
        verifier.verify(
            f"Bearer {TOKEN}",
            expected_audience,
            allowed_emails,
        )


@pytest.mark.parametrize("missing_claim", ("exp", "iat", "sub", "email", "aud", "iss"))
def test_verifier_rejects_missing_required_claim(missing_claim: str) -> None:
    claims = _claims()
    del claims[missing_claim]
    verifier = GoogleIdentityVerifier(
        lambda _token, _audience: claims,
        clock=lambda: NOW,
    )

    with pytest.raises(IdentityVerificationError):
        verifier.verify(f"Bearer {TOKEN}", AUDIENCE, frozenset({CALLER}))


@pytest.mark.parametrize(
    "authorization",
    (
        None,
        "",
        TOKEN,
        f"Basic {TOKEN}",
        f"bearer {TOKEN}",
        "Bearer header.payload.",
        "Bearer header.payload.signature extra",
        "Bearer header.payload.sign/ature",
        "Bearer héader.payload.signature",
        "Bearer " + ("x" * 8_193),
    ),
)
def test_application_authorization_requires_bounded_signed_bearer(
    authorization: str | None,
) -> None:
    verifier = GoogleIdentityVerifier(
        lambda _token, _audience: _claims(),
        clock=lambda: NOW,
    )

    with pytest.raises(IdentityVerificationError):
        verifier.verify(authorization, AUDIENCE, frozenset({CALLER}))


@pytest.mark.parametrize(
    "authorization",
    (
        f"Bearer {TOKEN}",
        "Bearer platform.payload.",
        "cloud-run-verified-header",
    ),
)
def test_platform_authorization_accepts_one_bounded_upstream_verified_header(
    authorization: str,
) -> None:
    assert validate_platform_authorization(authorization) is None


@pytest.mark.parametrize(
    "authorization",
    (
        None,
        "",
        "line\nbreak",
        "héader",
        "Bearer " + ("x" * 8_193),
    ),
)
def test_platform_authorization_fails_closed_on_invalid_shape(
    authorization: str | None,
) -> None:
    with pytest.raises(IdentityVerificationError):
        validate_platform_authorization(authorization)


def test_platform_and_application_authorization_are_independently_validated() -> None:
    seen: list[str] = []

    def verify(token: str, _audience: str) -> Mapping[str, Any]:
        seen.append(token)
        return _claims()

    validate_platform_authorization("cloud-run-verified-header")
    verifier = GoogleIdentityVerifier(verify, clock=lambda: NOW)

    with pytest.raises(IdentityVerificationError):
        verifier.verify(None, AUDIENCE, frozenset({CALLER}))
    assert seen == []

    verifier.verify(f"Bearer {TOKEN}", AUDIENCE, frozenset({CALLER}))
    assert seen == [TOKEN]


def test_verifier_failure_is_sanitized_and_has_no_chained_secret() -> None:
    def fail(_token: str, _audience: str) -> Mapping[str, Any]:
        raise OSError("private-key-fetch-token")

    verifier = GoogleIdentityVerifier(fail, clock=lambda: NOW)

    with pytest.raises(IdentityVerificationError) as captured:
        verifier.verify(f"Bearer {TOKEN}", AUDIENCE, frozenset({CALLER}))

    assert str(captured.value) == "application identity could not be verified"
    assert captured.value.__cause__ is None
    assert "private-key" not in repr(captured.value)


def test_default_verifier_bounds_key_fetch_without_environment_proxy(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from google.auth.transport.requests import Request
    from google.oauth2 import id_token

    requests: list[tuple[str, float, bool]] = []

    def request_call(
        self: Request,
        url: str,
        _method: str = "GET",
        _body: bytes | None = None,
        _headers: Mapping[str, str] | None = None,
        timeout: float = 120,
        **_kwargs: Any,
    ) -> object:
        requests.append((url, timeout, self.session.trust_env))
        return object()

    def verify_token(
        token: str,
        request: Any,
        audience: str,
    ) -> Mapping[str, Any]:
        assert token == TOKEN
        assert audience == AUDIENCE
        request("https://certs.example.test", timeout=120)
        return _claims()

    monkeypatch.setattr(Request, "__call__", request_call)
    monkeypatch.setattr(id_token, "verify_oauth2_token", verify_token)

    caller = GoogleIdentityVerifier(clock=lambda: NOW).verify(
        f"Bearer {TOKEN}",
        AUDIENCE,
        frozenset({CALLER}),
    )

    assert caller.email == CALLER
    assert requests == [("https://certs.example.test", 5.0, False)]
