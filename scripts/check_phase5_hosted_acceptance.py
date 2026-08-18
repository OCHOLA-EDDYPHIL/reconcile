#!/usr/bin/env python3
"""Seal one bounded provider or hosted Phase 5 acceptance record."""

from __future__ import annotations

import argparse
import asyncio
import json
import sys
from pathlib import Path

from reconcile.contracts import canonical_json_bytes
from reconcile.phase5_hosted_acceptance import (
    AcceptanceMode,
    CloudRunAcceptanceBackend,
    HostedAcceptanceError,
    build_candidate_identity,
    run_hosted_acceptance,
    run_provider_acceptance,
)


def _arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("mode", choices=tuple(item.value for item in AcceptanceMode))
    parser.add_argument("--state-root", type=Path, required=True)
    parser.add_argument("--source-revision", required=True)
    parser.add_argument("--image-digest", required=True)
    parser.add_argument("--infrastructure-revision", required=True)
    parser.add_argument("--semantic-config-sha256", required=True)
    return parser.parse_args()


def _failure(code: str) -> bytes:
    return json.dumps(
        {
            "reason": code,
            "schema_version": "reconcile/phase5-hosted-acceptance-result/v1",
            "status": "failed",
        },
        allow_nan=False,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


def main() -> int:
    arguments = _arguments()
    try:
        candidate = build_candidate_identity(
            source_revision=arguments.source_revision,
            image_digest=arguments.image_digest,
            infrastructure_revision=arguments.infrastructure_revision,
            semantic_config_sha256=arguments.semantic_config_sha256,
        )
    except (TypeError, ValueError):
        sys.stderr.buffer.write(_failure("ACCEPTANCE_INPUT_INVALID") + b"\n")
        return 1
    try:
        backend = CloudRunAcceptanceBackend(candidate)
        if arguments.mode == AcceptanceMode.PROVIDER.value:
            binding = asyncio.run(
                run_provider_acceptance(
                    candidate,
                    state_root=arguments.state_root,
                    backend=backend,
                )
            )
        else:
            binding = asyncio.run(
                run_hosted_acceptance(
                    candidate,
                    state_root=arguments.state_root,
                    backend=backend,
                )
            )
    except HostedAcceptanceError as error:
        sys.stderr.buffer.write(_failure(error.code) + b"\n")
        return 1
    except Exception:
        sys.stderr.buffer.write(_failure("ACCEPTANCE_EXECUTION_FAILED") + b"\n")
        return 1
    sys.stdout.buffer.write(canonical_json_bytes(binding) + b"\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
