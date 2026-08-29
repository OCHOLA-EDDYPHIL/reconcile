"""Bounded local Google identity-token supply for authenticated remote clients."""

from __future__ import annotations

import base64
import json
import os
import re
import subprocess
import threading
import time
from collections.abc import Mapping
from pathlib import Path

from reconcile.deployment_profile import (
    DeploymentProfileError,
    load_sealed_deployment_profile_file,
    resolve_deployment_identity,
)

_GCLOUD = "/usr/bin/gcloud"
_OPERATOR_SERVICE_ACCOUNT = "rec-p5-apply@example-project-id.iam.gserviceaccount.com"
_DEPLOYMENT_PROFILE = "RECONCILE_DEPLOYMENT_PROFILE"
_REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
_MAX_TOKEN_BYTES = 16_384
_AUDIENCE = re.compile(r"^[\x21-\x7e]{1,2048}$")
_OPERATOR_SERVICE_ACCOUNT_PATTERN = re.compile(
    r"^rec-p5-apply@[a-z][a-z0-9-]{4,28}[a-z0-9][.]iam[.]gserviceaccount[.]com$"
)
_CONFIGURATION = re.compile(r"^[a-z][a-z0-9-]{0,62}$")
_COMPACT_JWT = re.compile(r"^[A-Za-z0-9_-]+[.][A-Za-z0-9_-]+[.][A-Za-z0-9_-]+$")


class GoogleIdentityTokenError(RuntimeError):
    """A sanitized failure to obtain the exact requested identity token."""


def _decode_payload(token: str) -> dict[str, object]:
    if _COMPACT_JWT.fullmatch(token) is None:
        raise GoogleIdentityTokenError from None
    segments = token.split(".")
    payload = segments[1]
    padding = "=" * (-len(payload) % 4)
    try:
        decoded = base64.urlsafe_b64decode((payload + padding).encode("ascii"))
        value = json.loads(decoded)
    except (UnicodeError, ValueError, TypeError):
        raise GoogleIdentityTokenError from None
    if not isinstance(value, dict):
        raise GoogleIdentityTokenError from None
    return value


def _minimal_environment(source: Mapping[str, str]) -> dict[str, str]:
    try:
        home = str(Path.home().resolve())
    except (OSError, RuntimeError):
        raise GoogleIdentityTokenError from None
    environment = {
        "CLOUDSDK_CORE_DISABLE_PROMPTS": "1",
        "HOME": home,
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "PATH": "/usr/bin:/bin",
    }
    configuration = source.get("CLOUDSDK_ACTIVE_CONFIG_NAME")
    if configuration is not None:
        if (
            type(configuration) is not str
            or _CONFIGURATION.fullmatch(configuration) is None
        ):
            raise GoogleIdentityTokenError from None
        environment["CLOUDSDK_ACTIVE_CONFIG_NAME"] = configuration
    return environment


class GcloudIdentityTokenSupplier:
    """Mint and briefly cache the approval-bound operator service-account token."""

    def __init__(
        self,
        environ: Mapping[str, str] | None = None,
        *,
        operator_service_account: str = _OPERATOR_SERVICE_ACCOUNT,
    ) -> None:
        if (
            type(operator_service_account) is not str
            or _OPERATOR_SERVICE_ACCOUNT_PATTERN.fullmatch(operator_service_account)
            is None
        ):
            raise GoogleIdentityTokenError from None
        self._environment = _minimal_environment(
            os.environ if environ is None else environ
        )
        self._operator_service_account = operator_service_account
        self._lock = threading.Lock()
        self._audience: str | None = None
        self._token: str | None = None
        self._expires_at = 0

    def __call__(self, audience: str) -> str:
        if type(audience) is not str or _AUDIENCE.fullmatch(audience) is None:
            raise GoogleIdentityTokenError from None
        with self._lock:
            now = int(time.time())
            if (
                self._audience == audience
                and self._token is not None
                and self._expires_at > now + 60
            ):
                return self._token
            try:
                result = subprocess.run(
                    (
                        _GCLOUD,
                        "auth",
                        "print-identity-token",
                        (
                            "--impersonate-service-account="
                            f"{self._operator_service_account}"
                        ),
                        "--include-email",
                        f"--audiences={audience}",
                        "--quiet",
                    ),
                    cwd=self._environment["HOME"],
                    env=dict(self._environment),
                    check=False,
                    capture_output=True,
                    stdin=subprocess.DEVNULL,
                    timeout=30,
                )
            except (OSError, subprocess.SubprocessError):
                raise GoogleIdentityTokenError from None
            if (
                not isinstance(result, subprocess.CompletedProcess)
                or type(result.returncode) is not int
                or type(result.stdout) is not bytes
                or type(result.stderr) is not bytes
                or result.returncode != 0
                or len(result.stdout) > _MAX_TOKEN_BYTES
                or len(result.stderr) > _MAX_TOKEN_BYTES
            ):
                raise GoogleIdentityTokenError from None
            try:
                token = result.stdout.decode("ascii").strip()
            except UnicodeError:
                raise GoogleIdentityTokenError from None
            payload = _decode_payload(token)
            expires_at = payload.get("exp")
            observed_at = int(time.time())
            if (
                payload.get("aud") != audience
                or type(expires_at) is not int
                or expires_at <= observed_at + 60
            ):
                raise GoogleIdentityTokenError from None
            self._audience = audience
            self._token = token
            self._expires_at = expires_at
            return token


def operator_client_identity(
    environ: Mapping[str, str] | None = None,
) -> tuple[GcloudIdentityTokenSupplier, str] | None:
    """Return an authenticated-client binding only when an audience is explicit."""

    source = os.environ if environ is None else environ
    audience = source.get("RECONCILE_API_AUDIENCE")
    if audience is None:
        return None
    if type(audience) is not str or _AUDIENCE.fullmatch(audience) is None:
        raise GoogleIdentityTokenError from None
    operator_service_account = _OPERATOR_SERVICE_ACCOUNT
    profile_path = source.get(_DEPLOYMENT_PROFILE)
    if profile_path is not None:
        if type(profile_path) is not str or not profile_path:
            raise GoogleIdentityTokenError from None
        try:
            profile = load_sealed_deployment_profile_file(
                Path(profile_path),
                repo_root=_REPOSITORY_ROOT,
            )
            deployment = resolve_deployment_identity(profile)
        except (DeploymentProfileError, OSError, TypeError, ValueError):
            raise GoogleIdentityTokenError from None
        if audience != deployment.audiences.api:
            raise GoogleIdentityTokenError from None
        operator_service_account = deployment.apply_service_account_email
    return (
        GcloudIdentityTokenSupplier(
            source,
            operator_service_account=operator_service_account,
        ),
        audience,
    )


__all__ = [
    "GcloudIdentityTokenSupplier",
    "GoogleIdentityTokenError",
    "operator_client_identity",
]
