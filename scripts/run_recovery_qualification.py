"""Run and export the scripted proof-to-permit recovery qualification."""

from __future__ import annotations

import argparse
import asyncio
import json
from datetime import UTC, datetime
from pathlib import Path

from reconcile.recovery_qualification import (
    build_recovery_qualification_bundle,
    export_recovery_qualification_bundle,
    verify_recovery_qualification_bundle,
)


def _timestamp(value: str) -> datetime:
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise argparse.ArgumentTypeError("--created-at must include a UTC offset")
    return parsed.astimezone(UTC)


async def _run(arguments: argparse.Namespace) -> int:
    repository = arguments.repository.resolve()
    bundle = await build_recovery_qualification_bundle(
        source_repository=repository,
        created_at=arguments.created_at,
    )
    index = export_recovery_qualification_bundle(
        arguments.output,
        bundle,
        source_repository=repository,
    )
    verify_recovery_qualification_bundle(
        arguments.output,
        source_repository=repository,
    )
    print(
        json.dumps(
            {
                "adaptive_efficiency_claim_authorized": (
                    index.adaptive_efficiency_claim_authorized
                ),
                "bundle": str(arguments.output.resolve()),
                "case_count": bundle.results.case_count,
                "false_permit_count": bundle.results.false_permit_count,
                "lane_result_count": bundle.results.lane_result_count,
                "median_probe_reduction_basis_points": (
                    bundle.comparison.median_probe_reduction_basis_points
                ),
                "safety_claim_authorized": index.safety_claim_authorized,
                "source_revision": index.source_revision,
            },
            separators=(",", ":"),
            sort_keys=True,
        )
    )
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Run the frozen scripted recovery qualification matrix."
    )
    parser.add_argument(
        "--output",
        type=Path,
        required=True,
        help="new directory for the non-overwriting evidence bundle",
    )
    parser.add_argument(
        "--repository",
        type=Path,
        default=Path.cwd(),
        help="Git worktree whose exact source identity is recorded",
    )
    parser.add_argument(
        "--created-at",
        type=_timestamp,
        default=None,
        help="optional reproducible ISO-8601 timestamp",
    )
    return asyncio.run(_run(parser.parse_args()))


if __name__ == "__main__":
    raise SystemExit(main())
