"""Run and export the scripted proof-to-permit recovery qualification."""

from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
from datetime import UTC, datetime
from pathlib import Path

from reconcile.recovery_qualification import (
    build_recovery_qualification_bundle,
    export_recovery_qualification_bundle,
    recovery_qualification_source_state,
    verify_recovery_qualification_bundle,
)


def _timestamp(value: str) -> datetime:
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise argparse.ArgumentTypeError("--created-at must include a UTC offset")
    return parsed.astimezone(UTC)


async def _run(arguments: argparse.Namespace) -> int:
    repository = arguments.repository.resolve()
    source_revision, source_tree_sha256, clean = recovery_qualification_source_state(
        repository
    )
    lock_path = repository / "uv.lock"
    if not lock_path.is_file():
        raise RuntimeError("qualification requires the checked-in uv.lock")
    dependency_lock_sha256 = hashlib.sha256(lock_path.read_bytes()).hexdigest()
    bundle = await build_recovery_qualification_bundle(
        source_revision=source_revision,
        source_tree_sha256=source_tree_sha256,
        repository_clean=clean,
        dependency_lock_sha256=dependency_lock_sha256,
        created_at=arguments.created_at,
    )
    final_source_state = recovery_qualification_source_state(repository)
    final_lock_sha256 = hashlib.sha256(lock_path.read_bytes()).hexdigest()
    if final_source_state != (source_revision, source_tree_sha256, clean) or (
        final_lock_sha256 != dependency_lock_sha256
    ):
        raise RuntimeError("qualification source changed while the matrix was running")
    index = export_recovery_qualification_bundle(
        arguments.output,
        bundle,
        source_repository=repository,
    )
    verify_recovery_qualification_bundle(arguments.output)
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
