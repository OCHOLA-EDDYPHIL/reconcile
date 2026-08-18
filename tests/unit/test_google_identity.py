from __future__ import annotations

import base64
import json
import subprocess
import threading
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any

import pytest

from reconcile.interfaces import google_identity

pytestmark = pytest.mark.unit

_AUDIENCE = "https://reconcile.invalid/phase5/operator"


def _segment(value: object) -> str:
    payload = json.dumps(value, separators=(",", ":"), sort_keys=True).encode()
    return base64.urlsafe_b64encode(payload).decode().rstrip("=")


def _token(payload: object) -> str:
    return f"{_segment({'alg': 'RS256'})}.{_segment(payload)}.signature"


def _result(
    stdout: bytes,
    *,
    returncode: int = 0,
    stderr: bytes = b"",
) -> subprocess.CompletedProcess[bytes]:
    return subprocess.CompletedProcess(
        [google_identity._GCLOUD],
        returncode,
        stdout,
        stderr,
    )


def _fixed_home(monkeypatch: pytest.MonkeyPatch, home: Path) -> None:
    monkeypatch.setattr(
        google_identity.Path,
        "home",
        staticmethod(lambda: home),
    )


def test_minimal_environment_is_closed_and_allows_only_a_valid_configuration(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    home = tmp_path / "operator-home"
    home.mkdir()
    _fixed_home(monkeypatch, home)
    source = {
        "AMBIENT_SECRET": "do-not-propagate",
        "CLOUDSDK_ACTIVE_CONFIG_NAME": "reconcile-phase5",
        "CLOUDSDK_CONFIG": "/private/cloud-sdk",
        "GOOGLE_APPLICATION_CREDENTIALS": "/private/key.json",
        "HOME": "/attacker-selected-home",
        "PATH": "/attacker-selected-path",
    }

    environment = google_identity._minimal_environment(source)

    assert environment == {
        "CLOUDSDK_ACTIVE_CONFIG_NAME": "reconcile-phase5",
        "CLOUDSDK_CORE_DISABLE_PROMPTS": "1",
        "HOME": str(home.resolve()),
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "PATH": "/usr/bin:/bin",
    }


@pytest.mark.parametrize(
    "configuration",
    ("", "UPPER", "a_b", "a/b", "a" * 64, 7),
)
def test_minimal_environment_rejects_invalid_configuration_names(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    configuration: object,
) -> None:
    _fixed_home(monkeypatch, tmp_path)

    with pytest.raises(google_identity.GoogleIdentityTokenError) as raised:
        google_identity._minimal_environment(
            {"CLOUDSDK_ACTIVE_CONFIG_NAME": configuration}  # type: ignore[dict-item]
        )

    assert raised.value.args == ()


def test_minimal_environment_sanitizes_home_resolution_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def unavailable_home() -> Path:
        raise RuntimeError("private home diagnostic")

    monkeypatch.setattr(
        google_identity.Path,
        "home",
        staticmethod(unavailable_home),
    )

    with pytest.raises(google_identity.GoogleIdentityTokenError) as raised:
        google_identity._minimal_environment({})

    assert raised.value.args == ()


def test_operator_identity_is_opt_in_and_does_not_validate_unused_gcloud_state() -> (
    None
):
    assert (
        google_identity.operator_client_identity(
            {"CLOUDSDK_ACTIVE_CONFIG_NAME": "INVALID_AND_UNUSED"}
        )
        is None
    )


def test_operator_identity_returns_the_exact_explicit_audience(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    _fixed_home(monkeypatch, tmp_path)

    identity = google_identity.operator_client_identity(
        {
            "CLOUDSDK_ACTIVE_CONFIG_NAME": "reconcile-phase5",
            "RECONCILE_API_AUDIENCE": _AUDIENCE,
        }
    )

    assert identity is not None
    supplier, audience = identity
    assert type(supplier) is google_identity.GcloudIdentityTokenSupplier
    assert audience == _AUDIENCE
    assert supplier._environment["CLOUDSDK_ACTIVE_CONFIG_NAME"] == "reconcile-phase5"


@pytest.mark.parametrize(
    "audience",
    ("", "contains space", "contains\nnewline", "x" * 2049, 7),
)
def test_operator_identity_rejects_invalid_explicit_audiences(
    audience: object,
) -> None:
    with pytest.raises(google_identity.GoogleIdentityTokenError) as raised:
        google_identity.operator_client_identity(
            {"RECONCILE_API_AUDIENCE": audience}  # type: ignore[dict-item]
        )

    assert raised.value.args == ()


def test_supplier_uses_exact_gcloud_argv_cwd_and_minimal_environment(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    home = tmp_path / "operator-home"
    home.mkdir()
    _fixed_home(monkeypatch, home)
    monkeypatch.setattr(google_identity.time, "time", lambda: 1_000)
    token = _token({"aud": _AUDIENCE, "exp": 2_000})
    calls: list[tuple[tuple[str, ...], dict[str, Any]]] = []

    def run(
        command: tuple[str, ...],
        **options: Any,
    ) -> subprocess.CompletedProcess[bytes]:
        calls.append((command, options))
        return _result(f"  {token}\n".encode())

    monkeypatch.setattr(google_identity.subprocess, "run", run)
    supplier = google_identity.GcloudIdentityTokenSupplier(
        {
            "AMBIENT_SECRET": "do-not-propagate",
            "CLOUDSDK_ACTIVE_CONFIG_NAME": "reconcile-phase5",
        }
    )

    assert supplier(_AUDIENCE) == token
    assert calls == [
        (
            (
                "/usr/bin/gcloud",
                "auth",
                "print-identity-token",
                (
                    "--impersonate-service-account="
                    f"{google_identity._OPERATOR_SERVICE_ACCOUNT}"
                ),
                "--include-email",
                f"--audiences={_AUDIENCE}",
                "--quiet",
            ),
            {
                "capture_output": True,
                "check": False,
                "cwd": str(home.resolve()),
                "env": {
                    "CLOUDSDK_ACTIVE_CONFIG_NAME": "reconcile-phase5",
                    "CLOUDSDK_CORE_DISABLE_PROMPTS": "1",
                    "HOME": str(home.resolve()),
                    "LANG": "C.UTF-8",
                    "LC_ALL": "C.UTF-8",
                    "PATH": "/usr/bin:/bin",
                },
                "stdin": subprocess.DEVNULL,
                "timeout": 30,
            },
        )
    ]


@pytest.mark.parametrize(
    "payload",
    (
        {"aud": "https://wrong.invalid", "exp": 2_000},
        {"aud": _AUDIENCE},
        {"aud": _AUDIENCE, "exp": "2000"},
        {"aud": _AUDIENCE, "exp": True},
        {"aud": _AUDIENCE, "exp": 1_060},
        {"aud": [_AUDIENCE], "exp": 2_000},
        ["not", "an", "object"],
    ),
)
def test_supplier_rejects_wrong_audience_or_invalid_expiry_claims(
    monkeypatch: pytest.MonkeyPatch,
    payload: object,
) -> None:
    monkeypatch.setattr(google_identity.time, "time", lambda: 1_000)
    monkeypatch.setattr(
        google_identity.subprocess,
        "run",
        lambda *_args, **_kwargs: _result(_token(payload).encode()),
    )
    supplier = google_identity.GcloudIdentityTokenSupplier({})

    with pytest.raises(google_identity.GoogleIdentityTokenError) as raised:
        supplier(_AUDIENCE)

    assert raised.value.args == ()


@pytest.mark.parametrize(
    "stdout",
    (
        b"",
        b"one.segment",
        b"one.two.three.four",
        b"header.!.signature",
        b"header.bm90LWpzb24.signature",
        f"{_token({'aud': _AUDIENCE, 'exp': 2_000})}\nwarning".encode(),
        f"{_segment({'alg': 'RS256'})}.{_segment({'aud': _AUDIENCE, 'exp': 2_000})}.!".encode(),
        b"\xff",
    ),
)
def test_supplier_rejects_malformed_or_non_ascii_tokens(
    monkeypatch: pytest.MonkeyPatch,
    stdout: bytes,
) -> None:
    monkeypatch.setattr(google_identity.time, "time", lambda: 1_000)
    monkeypatch.setattr(
        google_identity.subprocess,
        "run",
        lambda *_args, **_kwargs: _result(stdout),
    )
    supplier = google_identity.GcloudIdentityTokenSupplier({})

    with pytest.raises(google_identity.GoogleIdentityTokenError):
        supplier(_AUDIENCE)


@pytest.mark.parametrize(
    "result",
    (
        _result(b"private-token", returncode=1, stderr=b"private diagnostic"),
        _result(b"x" * (google_identity._MAX_TOKEN_BYTES + 1)),
        _result(
            b"private-token",
            stderr=b"x" * (google_identity._MAX_TOKEN_BYTES + 1),
        ),
        subprocess.CompletedProcess([], True, b"private-token", b""),
        subprocess.CompletedProcess([], 0, "private-token", b""),
        subprocess.CompletedProcess([], 0, b"private-token", "private diagnostic"),
        object(),
    ),
)
def test_supplier_sanitizes_failed_oversized_or_malformed_process_results(
    monkeypatch: pytest.MonkeyPatch,
    result: object,
) -> None:
    monkeypatch.setattr(google_identity.time, "time", lambda: 1_000)
    monkeypatch.setattr(
        google_identity.subprocess,
        "run",
        lambda *_args, **_kwargs: result,
    )
    supplier = google_identity.GcloudIdentityTokenSupplier({})

    with pytest.raises(google_identity.GoogleIdentityTokenError) as raised:
        supplier(_AUDIENCE)

    assert raised.value.args == ()
    assert "private" not in str(raised.value)


@pytest.mark.parametrize(
    "error",
    (
        OSError("private operating-system diagnostic"),
        subprocess.TimeoutExpired("private command", 30),
    ),
)
def test_supplier_sanitizes_process_exceptions(
    monkeypatch: pytest.MonkeyPatch,
    error: BaseException,
) -> None:
    def fail(*_args: object, **_kwargs: object) -> None:
        raise error

    monkeypatch.setattr(google_identity.subprocess, "run", fail)
    supplier = google_identity.GcloudIdentityTokenSupplier({})

    with pytest.raises(google_identity.GoogleIdentityTokenError) as raised:
        supplier(_AUDIENCE)

    assert raised.value.args == ()


def test_supplier_rechecks_expiry_after_a_slow_mint(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    observed_times = iter((1_000, 1_050))
    monkeypatch.setattr(google_identity.time, "time", lambda: next(observed_times))
    monkeypatch.setattr(
        google_identity.subprocess,
        "run",
        lambda *_args, **_kwargs: _result(
            _token({"aud": _AUDIENCE, "exp": 1_110}).encode()
        ),
    )
    supplier = google_identity.GcloudIdentityTokenSupplier({})

    with pytest.raises(google_identity.GoogleIdentityTokenError):
        supplier(_AUDIENCE)


def test_supplier_cache_is_audience_bound_and_refreshes_at_the_safety_window(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    clock = [1_000]
    monkeypatch.setattr(google_identity.time, "time", lambda: clock[0])
    calls: list[str] = []

    def run(
        command: tuple[str, ...], **_kwargs: object
    ) -> subprocess.CompletedProcess[bytes]:
        audience = command[5].removeprefix("--audiences=")
        calls.append(audience)
        expiry = 1_500 if len(calls) == 1 else 2_000 + len(calls)
        return _result(_token({"aud": audience, "exp": expiry}).encode())

    monkeypatch.setattr(google_identity.subprocess, "run", run)
    supplier = google_identity.GcloudIdentityTokenSupplier({})
    first = supplier(_AUDIENCE)

    assert supplier(_AUDIENCE) == first
    other = "https://reconcile.invalid/phase5/other"
    assert supplier(other) != first
    assert supplier(other) == supplier(other)
    assert supplier(_AUDIENCE) != first
    assert calls == [_AUDIENCE, other, _AUDIENCE]

    clock[0] = 1_942
    cached = supplier(_AUDIENCE)
    assert cached == supplier(_AUDIENCE)
    assert calls == [_AUDIENCE, other, _AUDIENCE]
    clock[0] = 1_943
    assert supplier(_AUDIENCE) != cached
    assert calls == [_AUDIENCE, other, _AUDIENCE, _AUDIENCE]


def test_supplier_serializes_concurrent_cache_misses_to_one_gcloud_call(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(google_identity.time, "time", lambda: 1_000)
    token = _token({"aud": _AUDIENCE, "exp": 2_000})
    call_count = 0
    count_lock = threading.Lock()
    entered = threading.Event()
    release = threading.Event()

    def run(*_args: object, **_kwargs: object) -> subprocess.CompletedProcess[bytes]:
        nonlocal call_count
        with count_lock:
            call_count += 1
        entered.set()
        assert release.wait(timeout=5)
        return _result(token.encode())

    monkeypatch.setattr(google_identity.subprocess, "run", run)
    supplier = google_identity.GcloudIdentityTokenSupplier({})

    with ThreadPoolExecutor(max_workers=8) as executor:
        first = executor.submit(supplier, _AUDIENCE)
        assert entered.wait(timeout=5)
        remaining = tuple(executor.submit(supplier, _AUDIENCE) for _ in range(15))
        release.set()
        observed = (first.result(), *(item.result() for item in remaining))

    assert observed == (token,) * 16
    assert call_count == 1


def test_invalid_call_audience_never_starts_gcloud(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        google_identity.subprocess,
        "run",
        lambda *_args, **_kwargs: pytest.fail("gcloud must not run"),
    )
    supplier = google_identity.GcloudIdentityTokenSupplier({})

    with pytest.raises(google_identity.GoogleIdentityTokenError):
        supplier("invalid audience")
