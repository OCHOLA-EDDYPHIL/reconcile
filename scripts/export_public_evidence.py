#!/usr/bin/env python3
"""Export sanitized public evidence from exact hosted acceptance artifacts."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from reconcile.public_evidence import PublicEvidenceError, export_public_evidence


def _absolute_path(value: str) -> Path:
    path = Path(value)
    if not path.is_absolute():
        raise argparse.ArgumentTypeError("path must be absolute")
    return path


def _arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Export a non-overwriting, sanitized four-file public evidence bundle."
        )
    )
    parser.add_argument(
        "--provider-acceptance",
        required=True,
        type=_absolute_path,
    )
    parser.add_argument(
        "--hosted-acceptance",
        required=True,
        type=_absolute_path,
    )
    parser.add_argument(
        "--runtime-teardown-evidence", required=True, type=_absolute_path
    )
    parser.add_argument(
        "--foundation-teardown-evidence", required=True, type=_absolute_path
    )
    parser.add_argument(
        "--state-protection-evidence", required=True, type=_absolute_path
    )
    parser.add_argument(
        "--bootstrap-teardown-evidence", required=True, type=_absolute_path
    )
    parser.add_argument("--post-teardown-inventory", required=True, type=_absolute_path)
    parser.add_argument("--output", required=True, type=_absolute_path)
    return parser.parse_args()


def main() -> int:
    arguments = _arguments()
    try:
        bundle = export_public_evidence(
            provider_acceptance=arguments.provider_acceptance,
            hosted_acceptance=arguments.hosted_acceptance,
            runtime_teardown_evidence=arguments.runtime_teardown_evidence,
            foundation_teardown_evidence=arguments.foundation_teardown_evidence,
            state_protection_evidence=arguments.state_protection_evidence,
            bootstrap_teardown_evidence=arguments.bootstrap_teardown_evidence,
            post_teardown_inventory=arguments.post_teardown_inventory,
            output=arguments.output,
        )
    except PublicEvidenceError as error:
        print(f"FAIL: {error.code}", file=sys.stderr)
        return 1
    print(
        json.dumps(
            {
                "candidate_sha256": bundle.index.candidate_sha256,
                "output": str(arguments.output),
                "schema_version": bundle.index.schema_version,
                "source_revision": bundle.index.source_revision,
                "status": bundle.index.status,
            },
            allow_nan=False,
            separators=(",", ":"),
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
