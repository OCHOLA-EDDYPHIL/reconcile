#!/usr/bin/env python3
"""Capture the fixed read-only Google Cloud post-teardown inventory."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from reconcile.public_evidence import (
    PublicEvidenceError,
    capture_post_teardown_inventory_from_manifest,
)


def _absolute_path(value: str) -> Path:
    path = Path(value)
    if not path.is_absolute():
        raise argparse.ArgumentTypeError("path must be absolute")
    return path


def main() -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Run the fixed read-only gcloud inventory and seal its private result."
        )
    )
    parser.add_argument("--manifest", required=True, type=_absolute_path)
    parser.add_argument("--output", required=True, type=_absolute_path)
    arguments = parser.parse_args()
    try:
        observation = capture_post_teardown_inventory_from_manifest(
            manifest_path=arguments.manifest,
            output=arguments.output,
        )
    except PublicEvidenceError as error:
        print(f"FAIL: {error.code}", file=sys.stderr)
        return 1
    matched_resource_counts = {
        query.kind: len(query.matched_resource_ids) for query in observation.queries
    }
    empty = not any(matched_resource_counts.values())
    print(
        json.dumps(
            {
                "captured_at": observation.model_dump(mode="json")["captured_at"],
                "matched_resource_counts": matched_resource_counts,
                "output": str(arguments.output),
                "query_count": len(observation.queries),
                "schema_version": observation.schema_version,
                "status": "PASS" if empty else "RESOURCES_REMAIN",
            },
            allow_nan=False,
            separators=(",", ":"),
            sort_keys=True,
        )
    )
    return 0 if empty else 2


if __name__ == "__main__":
    raise SystemExit(main())
