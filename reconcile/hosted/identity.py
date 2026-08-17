"""Strict application identity checks for hosted internal routes."""

from __future__ import annotations

import math
import re
import time
from collections.abc import Callable, Collection, Mapping
from dataclasses import dataclass
from typing import Any, Protocol

_GOOGLE_ISSUERS = frozenset(
    {
        "accounts.google.com",
        "https://accounts.google.com",
    }
)
_MAX_AUTHORIZATION_HEADER_BYTES = 8_192
_MAX_ID_TOKEN_BYTES = 6_144
_MAX_AUDIENCE_BYTES = 2_048
_MAX_ALLOWED_EMAILS = 32
_MAX_EMAIL_BYTES = 320
_MAX_SUBJECT_BYTES = 255
_MAX_CLOCK_SKEW_SECONDS = 60
_GOOGLE_REQUEST_TIMEOUT_SECONDS = 5.0
_JWT_SEGMENT = re.compile(r"^[A-Za-z0-9_-]+$")
_EMAIL = re.compile(
    r"^[A-Za-z0-9][A-Za-z0-9._%+\-]{0,254}@[A-Za-z0-9][A-Za-z0-9.\-]{0,252}$"
)


class IdentityTokenVerifier(Protocol):
    def __call__(self, token: str, audience: str) -> Mapping[str, Any]: ...


class IdentityVerificationError(Exception):
    """A credential or its exact caller policy could not be verified."""

    def __init__(self) -> None:
        super().__init__("application identity could not be verified")


@dataclass(frozen=True, slots=True)
class VerifiedCaller:
    """Bounded caller identity retained after signature and claim verification."""

    email: str
    subject: str
    issuer: str
    audience: str
    expires_at: int


def _verification_error() -> IdentityVerificationError:
    return IdentityVerificationError()


def _bounded_ascii(value: object, *, maximum: int) -> str:
    if type(value) is not str or not value:
        raise _verification_error() from None
    try:
        encoded = value.encode("ascii")
    except UnicodeEncodeError:
        raise _verification_error() from None
    if len(encoded) > maximum or any(character.isspace() for character in value):
        raise _verification_error() from None
    if any(ord(character) < 33 or ord(character) == 127 for character in value):
        raise _verification_error() from None
    return value


def _validated_audience(value: object) -> str:
    return _bounded_ascii(value, maximum=_MAX_AUDIENCE_BYTES)


def _validated_allowed_emails(value: object) -> frozenset[str]:
    if isinstance(value, (str, bytes)) or not isinstance(value, Collection):
        raise _verification_error() from None
    if not value or len(value) > _MAX_ALLOWED_EMAILS:
        raise _verification_error() from None

    emails: set[str] = set()
    for candidate in value:
        email = _bounded_ascii(candidate, maximum=_MAX_EMAIL_BYTES)
        if _EMAIL.fullmatch(email) is None:
            raise _verification_error() from None
        emails.add(email)
    if not emails:
        raise _verification_error() from None
    return frozenset(emails)


def _extract_bearer_token(
    authorization_header: object,
    *,
    require_signature: bool,
) -> str:
    if type(authorization_header) is not str or not authorization_header:
        raise _verification_error() from None
    try:
        encoded_header = authorization_header.encode("ascii")
    except UnicodeEncodeError:
        raise _verification_error() from None
    if len(encoded_header) > _MAX_AUTHORIZATION_HEADER_BYTES or any(
        ord(character) < 32 or ord(character) == 127
        for character in authorization_header
    ):
        raise _verification_error() from None
    header = authorization_header
    if not header.startswith("Bearer "):
        raise _verification_error() from None
    token = header.removeprefix("Bearer ")
    if not token or len(token.encode("ascii")) > _MAX_ID_TOKEN_BYTES:
        raise _verification_error() from None

    segments = token.split(".")
    if (
        len(segments) != 3
        or not segments[0]
        or not segments[1]
        or _JWT_SEGMENT.fullmatch(segments[0]) is None
        or _JWT_SEGMENT.fullmatch(segments[1]) is None
        or (segments[2] and _JWT_SEGMENT.fullmatch(segments[2]) is None)
        or (require_signature and not segments[2])
    ):
        raise _verification_error() from None
    return token


def validate_platform_authorization(authorization_header: str | None) -> None:
    """Require one bounded header whose signature was verified by Cloud Run."""

    if type(authorization_header) is not str or not authorization_header:
        raise _verification_error() from None
    try:
        encoded = authorization_header.encode("ascii")
    except UnicodeEncodeError:
        raise _verification_error() from None
    if len(encoded) > _MAX_AUTHORIZATION_HEADER_BYTES or any(
        ord(character) < 32 or ord(character) == 127
        for character in authorization_header
    ):
        raise _verification_error() from None


def _default_google_verifier(token: str, audience: str) -> Mapping[str, Any]:
    try:
        from google.auth.transport.requests import Request
        from google.oauth2 import id_token

        request = Request()
        request.session.trust_env = False

        def bounded_request(
            url: str,
            method: str = "GET",
            body: bytes | None = None,
            headers: Mapping[str, str] | None = None,
            **kwargs: Any,
        ) -> Any:
            kwargs.pop("timeout", None)
            return request(
                url,
                method=method,
                body=body,
                headers=headers,
                timeout=_GOOGLE_REQUEST_TIMEOUT_SECONDS,
                **kwargs,
            )

        claims = id_token.verify_oauth2_token(
            token,
            bounded_request,
            audience=audience,
        )
    except Exception:
        raise _verification_error() from None
    if not isinstance(claims, Mapping):
        raise _verification_error() from None
    return claims


class GoogleIdentityVerifier:
    """Verify Google-signed identity plus an exact route caller policy."""

    def __init__(
        self,
        verifier: IdentityTokenVerifier | None = None,
        clock: Callable[[], float] | None = None,
    ) -> None:
        self._verifier = verifier or _default_google_verifier
        self._clock = clock or time.time

    def verify(
        self,
        authorization_header: str | None,
        expected_audience: str,
        allowed_emails: Collection[str],
    ) -> VerifiedCaller:
        """Return the exact allowed caller or fail closed with no credential detail."""

        try:
            audience = _validated_audience(expected_audience)
            allowed = _validated_allowed_emails(allowed_emails)
            token = _extract_bearer_token(
                authorization_header,
                require_signature=True,
            )
            claims = self._verifier(token, audience)
            if not isinstance(claims, Mapping):
                raise _verification_error()

            issuer = claims.get("iss")
            claim_audience = claims.get("aud")
            email = claims.get("email")
            subject = claims.get("sub")
            expires_at = claims.get("exp")
            issued_at = claims.get("iat")
            not_before = claims.get("nbf")
            now = self._clock()

            if (
                issuer not in _GOOGLE_ISSUERS
                or claim_audience != audience
                or type(email) is not str
                or email not in allowed
                or claims.get("email_verified") is not True
                or type(expires_at) is not int
                or type(issued_at) is not int
                or isinstance(now, bool)
                or not isinstance(now, (int, float))
                or not math.isfinite(now)
                or expires_at <= now
                or issued_at > now + _MAX_CLOCK_SKEW_SECONDS
                or (
                    not_before is not None
                    and (
                        type(not_before) is not int
                        or not_before > now + _MAX_CLOCK_SKEW_SECONDS
                    )
                )
            ):
                raise _verification_error()

            verified_email = _bounded_ascii(email, maximum=_MAX_EMAIL_BYTES)
            verified_subject = _bounded_ascii(subject, maximum=_MAX_SUBJECT_BYTES)
            if _EMAIL.fullmatch(verified_email) is None:
                raise _verification_error()

            return VerifiedCaller(
                email=verified_email,
                subject=verified_subject,
                issuer=issuer,
                audience=audience,
                expires_at=expires_at,
            )
        except IdentityVerificationError:
            raise
        except Exception:
            raise _verification_error() from None


__all__ = [
    "GoogleIdentityVerifier",
    "IdentityTokenVerifier",
    "IdentityVerificationError",
    "VerifiedCaller",
    "validate_platform_authorization",
]
