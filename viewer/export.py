"""Export a static projection from one validated versioned evidence bundle."""

from __future__ import annotations

import argparse
import hashlib
import os
import re
import stat
import subprocess
from pathlib import Path
from typing import Any

from scripts.validate_evidence import EvidenceError, load_and_validate

from .public_contract import (
    DISPLAY_LABEL,
    LIMITATIONS,
    SNAPSHOT_VERSION,
    PublicContractError,
    build_manifest,
    canonical_json_bytes,
    read_bounded_regular_at,
    render_html,
    seal_snapshot,
    sha256_hex,
)

_EVIDENCE_FILES = frozenset(
    {
        "proof-to-permit.json",
        "provider-proof.json",
        "live-corroboration.json",
        "cleanup-verification.json",
    }
)
_SOURCE_REVISION = re.compile(r"^[0-9a-f]{40}$")
_EVIDENCE_VERSION = re.compile(r"^v[0-9]+\.[0-9]+\.[0-9]+$")
_MAX_EVIDENCE_BYTES = 8 * 1_048_576
_BUILD_CONTEXT_FILES = ("Dockerfile", "public_contract.py", "server.py")
_REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
_VIEWER_ROOT = Path(__file__).resolve().parent
_GIT = "/usr/bin/git"


class ViewerExportError(RuntimeError):
    """A fixed refusal while projecting public evidence."""


def _read_bundle_bytes(root: Path) -> dict[str, bytes]:
    flags = os.O_RDONLY | os.O_CLOEXEC | os.O_DIRECTORY | os.O_NOFOLLOW
    try:
        descriptor = os.open(root, flags)
    except OSError as error:
        raise ViewerExportError("EVIDENCE_DIRECTORY_INVALID") from error
    try:
        metadata = os.fstat(descriptor)
        entries = os.listdir(descriptor)
        if not stat.S_ISDIR(metadata.st_mode) or set(entries) != _EVIDENCE_FILES:
            raise ViewerExportError("EVIDENCE_DIRECTORY_INVALID")
        return {
            name: read_bounded_regular_at(descriptor, name, _MAX_EVIDENCE_BYTES)
            for name in sorted(_EVIDENCE_FILES)
        }
    except ViewerExportError:
        raise
    except (OSError, PublicContractError) as error:
        raise ViewerExportError("EVIDENCE_FILE_INVALID") from error
    finally:
        os.close(descriptor)


def _validated_evidence(root: Path) -> tuple[dict[str, Any], dict[str, bytes]]:
    before = _read_bundle_bytes(root)
    try:
        payload = load_and_validate(root / "proof-to-permit.json")
    except (EvidenceError, OSError, ValueError) as error:
        raise ViewerExportError("EVIDENCE_CONTRACT_INVALID") from error
    after = _read_bundle_bytes(root)
    if before != after:
        raise ViewerExportError("EVIDENCE_CHANGED_DURING_EXPORT")
    return payload, after


def _build_snapshot(evidence_root: Path, viewer_source_revision: str) -> dict[str, Any]:
    """Build one closed projection without run-specific source constants."""

    if (
        not isinstance(evidence_root, Path)
        or _SOURCE_REVISION.fullmatch(viewer_source_revision) is None
        or _EVIDENCE_VERSION.fullmatch(evidence_root.name) is None
    ):
        raise ViewerExportError("EXPORT_ARGUMENT_INVALID")
    payload, raw = _validated_evidence(evidence_root)
    provider = payload["provider_proof"]
    live = payload["live_corroboration"]
    cleanup = payload["cleanup_verification"]
    current = payload["schema_version"] == "reconcile/public-evidence/v1"
    if current:
        adaptive = provider["adaptive_recovery"]
        replay = adaptive["replay"]
        effects = adaptive["effects"]
        ambiguity = live["ambiguity_proof"]
        recovery = {
            "initial_classification": "UNKNOWN",
            "settled_classification": "COMMITTED",
            "acknowledgement_lost": adaptive["acknowledgement_lost"],
            "initial_continue_allowed": False,
            "initial_retry_allowed": False,
            "initial_action_permits_issued": 0,
            "permit_count": adaptive["action_permits_consumed"],
            "all_permits_single_use": replay["rejected_before_provider_contact"],
            "replay_outcome": "rejected-before-provider-contact",
            "replay_contacted_provider": replay["provider_contact_delta"] != 0,
            "effects": {
                "revisions": effects["revisions"],
                "promotions": effects["promotions"],
                "release_records": effects["release_records"],
            },
        }
        advisory = live["advisory_planning"]
        advisory_planning = {
            "configured_model": advisory["configured_model"],
            "reported_model": advisory["reported_model"],
            "planner_outcome": advisory["planner_outcome"],
            "bound_to_hypothesis": True,
            "hypothesis_count": advisory["generation_attempts"],
            "authority": advisory["authority"],
        }
        ambiguity_projection: dict[str, Any] | None = {
            "classification": ambiguity["classification"],
            "lifecycle": ambiguity["lifecycle"],
            "decision": ambiguity["decision"],
            "history_ids": list(ambiguity["history_ids"]),
            "history_classifications": list(ambiguity["history_classifications"]),
            "history_evidence_counts": list(ambiguity["history_evidence_counts"]),
            "discriminating_observation_count": ambiguity[
                "discriminating_observation_count"
            ],
            "certificate_count": ambiguity["certificate_count"],
            "action_permit_count": ambiguity["action_permit_count"],
            "effects": dict(ambiguity["effects"]),
        }
        inventory = cleanup["inventory"]
        candidate = provider["candidate"]
    else:
        permits = provider["permits"]
        recovery = {
            "initial_classification": provider["initial_pass"]["classification"],
            "settled_classification": provider["settled_pass"]["classification"],
            "acknowledgement_lost": provider["initial_pass"]["acknowledgement_lost"],
            "initial_continue_allowed": provider["initial_pass"]["continue_allowed"],
            "initial_retry_allowed": provider["initial_pass"]["retry_allowed"],
            "initial_action_permits_issued": provider["initial_pass"][
                "action_permits_issued"
            ],
            "permit_count": len(permits),
            "all_permits_single_use": all(
                permit["max_uses"] == 1 for permit in permits
            ),
            "replay_outcome": provider["replay"]["outcome"],
            "replay_contacted_provider": provider["replay"]["provider_contact"],
            "effects": {
                "revisions": provider["effects"]["revisions"],
                "promotions": provider["effects"]["promotions"],
                "release_records": provider["effects"]["release_records"],
            },
        }
        advisory_planning = {
            "configured_model": live["gemini"]["configured_model"],
            "reported_model": live["gemini"]["reported_model"],
            "planner_outcome": live["gemini"]["planner_outcome"],
            "bound_to_hypothesis": provider["gemini"]["bound_to_hypothesis"],
            "hypothesis_count": provider["gemini"]["hypothesis_count"],
            "authority": "read-only-probe-planning-only",
        }
        ambiguity_projection = None
        inventory = cleanup["inventory"]
        candidate = provider["candidate"]
    base = {
        "schema_version": SNAPSHOT_VERSION,
        "display_label": DISPLAY_LABEL,
        "viewer_source_revision": viewer_source_revision,
        "evidence_source_revision": candidate["source_revision"],
        "evidence_version": evidence_root.name,
        "evidence": {
            "manifest_schema_version": payload["schema_version"],
            "manifest_sha256": sha256_hex(raw["proof-to-permit.json"]),
            "provider_proof_sha256": sha256_hex(raw["provider-proof.json"]),
            "live_corroboration_sha256": sha256_hex(raw["live-corroboration.json"]),
            "cleanup_verification_sha256": sha256_hex(raw["cleanup-verification.json"]),
            "image_digest": candidate["image_digest"],
            "candidate_sha256": candidate["candidate_sha256"],
            "status": provider["status"],
        },
        "claim_boundary": dict(payload["claim_boundary"]),
        "recovery": recovery,
        "ambiguity": ambiguity_projection,
        "advisory_planning": advisory_planning,
        "cleanup": {
            "status": cleanup["status"],
            "retained_resource_count": sum(inventory.values()),
        },
        "limitations": list(LIMITATIONS),
    }
    try:
        return seal_snapshot(base)
    except PublicContractError as error:
        raise ViewerExportError("PUBLIC_PROJECTION_INVALID") from error


def _git(*arguments: str) -> bytes:
    try:
        completed = subprocess.run(
            (_GIT, *arguments),
            cwd=_REPOSITORY_ROOT,
            check=False,
            capture_output=True,
            timeout=10,
        )
    except (OSError, subprocess.SubprocessError) as error:
        raise ViewerExportError("VIEWER_SOURCE_NOT_EXACT_MAIN") from error
    if completed.returncode != 0:
        raise ViewerExportError("VIEWER_SOURCE_NOT_EXACT_MAIN")
    return completed.stdout


def _verified_viewer_source(
    expected_revision: str | None = None,
) -> tuple[str, dict[str, bytes]]:
    """Return immutable runtime source only from a clean exact-main checkout."""

    head = _git("rev-parse", "HEAD").decode("ascii", errors="strict").strip()
    branch = _git("branch", "--show-current").decode("utf-8", errors="strict").strip()
    remote_main = (
        _git("rev-parse", "refs/remotes/origin/main")
        .decode("ascii", errors="strict")
        .strip()
    )
    status = _git("status", "--porcelain=v1", "--untracked-files=all")
    if (
        _SOURCE_REVISION.fullmatch(head) is None
        or branch != "main"
        or remote_main != head
        or status
        or (expected_revision is not None and expected_revision != head)
    ):
        raise ViewerExportError("VIEWER_SOURCE_NOT_EXACT_MAIN")

    sources: dict[str, bytes] = {}
    for name in _BUILD_CONTEXT_FILES:
        try:
            committed = _git("show", f"{head}:viewer/{name}")
            current = (_VIEWER_ROOT / name).read_bytes()
        except (OSError, UnicodeError) as error:
            raise ViewerExportError("VIEWER_SOURCE_NOT_EXACT_MAIN") from error
        if current != committed:
            raise ViewerExportError("VIEWER_SOURCE_NOT_EXACT_MAIN")
        sources[name] = committed
    return head, sources


def _write_new_at(directory_descriptor: int, name: str, payload: bytes) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW
    try:
        descriptor = os.open(name, flags, 0o400, dir_fd=directory_descriptor)
    except OSError as error:
        raise ViewerExportError("OUTPUT_WRITE_FAILED") from error
    try:
        offset = 0
        while offset < len(payload):
            written = os.write(descriptor, payload[offset:])
            if written < 1:
                raise ViewerExportError("OUTPUT_WRITE_FAILED")
            offset += written
        os.fchmod(descriptor, 0o400)
        os.fsync(descriptor)
    except ViewerExportError:
        raise
    except OSError as error:
        raise ViewerExportError("OUTPUT_WRITE_FAILED") from error
    finally:
        os.close(descriptor)


def write_bundle(snapshot: dict[str, Any], output: Path) -> dict[str, Any]:
    """Write exactly three immutable public files into a new directory."""

    try:
        snapshot_payload = canonical_json_bytes(snapshot)
        html_payload = render_html(snapshot)
        manifest = build_manifest(snapshot, snapshot_payload, html_payload)
        manifest_payload = canonical_json_bytes(manifest)
    except PublicContractError as error:
        raise ViewerExportError("PUBLIC_BUNDLE_INVALID") from error
    try:
        output.mkdir(mode=0o700, parents=True, exist_ok=False)
        descriptor = os.open(
            output,
            os.O_RDONLY | os.O_CLOEXEC | os.O_DIRECTORY | os.O_NOFOLLOW,
        )
    except OSError as error:
        raise ViewerExportError("OUTPUT_DIRECTORY_INVALID") from error
    try:
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISDIR(metadata.st_mode)
            or metadata.st_uid != os.getuid()
            or stat.S_IMODE(metadata.st_mode) != 0o700
        ):
            raise ViewerExportError("OUTPUT_DIRECTORY_INVALID")
        _write_new_at(descriptor, "index.html", html_payload)
        _write_new_at(descriptor, "snapshot.json", snapshot_payload)
        _write_new_at(descriptor, "bundle-manifest.json", manifest_payload)
        os.fsync(descriptor)
    except ViewerExportError:
        raise
    except OSError as error:
        raise ViewerExportError("OUTPUT_WRITE_FAILED") from error
    finally:
        os.close(descriptor)
    return manifest


def export_bundle(evidence_root: Path, output: Path) -> dict[str, Any]:
    """Validate evidence, derive its projection, and write an immutable bundle."""

    viewer_source_revision, _ = _verified_viewer_source()
    resolved_output = output.resolve()
    if (
        resolved_output == _REPOSITORY_ROOT
        or _REPOSITORY_ROOT in resolved_output.parents
    ):
        raise ViewerExportError("OUTPUT_MUST_BE_OUTSIDE_REPOSITORY")
    return write_bundle(
        _build_snapshot(evidence_root, viewer_source_revision), resolved_output
    )


def stage_build_context(bundle: Path, output: Path) -> None:
    """Stage a validated viewer bundle and fixed runtime sources outside the repo."""

    if not isinstance(bundle, Path) or not isinstance(output, Path):
        raise ViewerExportError("BUILD_CONTEXT_ARGUMENT_INVALID")
    resolved_bundle = bundle.resolve()
    resolved_output = output.resolve()
    if (
        resolved_output == _REPOSITORY_ROOT
        or _REPOSITORY_ROOT in resolved_output.parents
    ):
        raise ViewerExportError("BUILD_CONTEXT_ARGUMENT_INVALID")
    from .public_contract import decode_snapshot
    from .server import BundleError, load_bundle

    try:
        responses = load_bundle(resolved_bundle)
        snapshot = decode_snapshot(responses["/snapshot.json"][0])
        _, source_payloads = _verified_viewer_source(snapshot["viewer_source_revision"])
    except BundleError as error:
        raise ViewerExportError("VIEWER_BUNDLE_INVALID") from error
    except PublicContractError as error:
        raise ViewerExportError("VIEWER_BUNDLE_INVALID") from error
    bundle_payloads = {
        "bundle-manifest.json": responses["/bundle-manifest.json"][0],
        "index.html": responses["/index.html"][0],
        "snapshot.json": responses["/snapshot.json"][0],
    }
    try:
        resolved_output.mkdir(mode=0o700, parents=True, exist_ok=False)
        (resolved_output / "bundle").mkdir(mode=0o700)
        root_descriptor = os.open(
            resolved_output,
            os.O_RDONLY | os.O_CLOEXEC | os.O_DIRECTORY | os.O_NOFOLLOW,
        )
        bundle_descriptor = os.open(
            resolved_output / "bundle",
            os.O_RDONLY | os.O_CLOEXEC | os.O_DIRECTORY | os.O_NOFOLLOW,
        )
    except OSError as error:
        raise ViewerExportError("BUILD_CONTEXT_DIRECTORY_INVALID") from error
    try:
        for name in _BUILD_CONTEXT_FILES:
            _write_new_at(root_descriptor, name, source_payloads[name])
        for name, payload in bundle_payloads.items():
            _write_new_at(bundle_descriptor, name, payload)
        os.fsync(bundle_descriptor)
        os.fsync(root_descriptor)
    except (OSError, ViewerExportError) as error:
        if isinstance(error, ViewerExportError):
            raise
        raise ViewerExportError("BUILD_CONTEXT_WRITE_FAILED") from error
    finally:
        os.close(bundle_descriptor)
        os.close(root_descriptor)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Export a static viewer bundle from versioned public evidence."
    )
    parser.add_argument("--evidence", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--build-context-output", type=Path)
    arguments = parser.parse_args()
    try:
        manifest = export_bundle(
            arguments.evidence.resolve(),
            arguments.output.resolve(),
        )
        if arguments.build_context_output is not None:
            stage_build_context(
                arguments.output.resolve(),
                arguments.build_context_output.resolve(),
            )
    except ViewerExportError as error:
        print(f"FAIL: {error}")
        return 1
    print(hashlib.sha256(canonical_json_bytes(manifest)).hexdigest())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())


__all__ = [
    "ViewerExportError",
    "export_bundle",
    "stage_build_context",
    "write_bundle",
]
