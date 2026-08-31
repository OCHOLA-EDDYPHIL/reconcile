"""Dependency-free contract for an immutable public evidence viewer."""

from __future__ import annotations

import hashlib
import html
import json
import os
import re
import stat
from collections.abc import Callable
from typing import Any

SNAPSHOT_VERSION = "reconcile/viewer-snapshot/v4"
LEGACY_SNAPSHOT_VERSION = "reconcile/viewer-snapshot/v3"
BUNDLE_VERSION = "reconcile/viewer-bundle/v2"
DISPLAY_LABEL = "Recorded evidence - not a live operation"

MAX_MANIFEST_BYTES = 8_192
MAX_SNAPSHOT_BYTES = 65_536
MAX_HTML_BYTES = 65_536

_SHA256_PATTERN = re.compile(r"^[0-9a-f]{64}$")
_SOURCE_REVISION_PATTERN = re.compile(r"^[0-9a-f]{40}$")
_IMAGE_DIGEST_PATTERN = re.compile(r"^sha256:[0-9a-f]{64}$")
_EVIDENCE_VERSION_PATTERN = re.compile(r"^v[0-9]+\.[0-9]+\.[0-9]+$")
_SCHEMA_VERSION_PATTERN = re.compile(r"^reconcile/[a-z0-9-]+/v[0-9]+$")
_MODEL_PATTERN = re.compile(r"^gemini-3[.]5-[A-Za-z0-9._-]+$")
_CLASSIFICATIONS = frozenset(
    {"COMMITTED", "NOT_COMMITTED", "PARTIAL", "PENDING", "UNKNOWN"}
)
LIMITATIONS = (
    "The viewer serves a static projection and has no operational-core connection.",
    "Validate the versioned source bundle for the complete evidence contract.",
    "Model output was advisory; deterministic code controlled action authority.",
    "The displayed result applies only to the identified evidence source.",
)


class PublicContractError(ValueError):
    """A stable refusal at the public bundle boundary."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


def sha256_hex(payload: bytes) -> str:
    """Return the lowercase SHA-256 digest for exact bytes."""

    return hashlib.sha256(payload).hexdigest()


def canonical_json_bytes(value: object) -> bytes:
    """Encode one public object with canonical newline framing."""

    try:
        return (
            json.dumps(
                value,
                allow_nan=False,
                ensure_ascii=False,
                separators=(",", ":"),
                sort_keys=True,
            ).encode("utf-8")
            + b"\n"
        )
    except (RecursionError, TypeError, UnicodeError, ValueError) as error:
        raise PublicContractError("PUBLIC_JSON_INVALID") from error


def _reject_constant(_value: str) -> None:
    raise ValueError("non-finite number")


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate key")
        result[key] = value
    return result


def _decode_canonical_object(
    payload: bytes,
    *,
    maximum_bytes: int,
    validator: Callable[[object], None],
    code: str,
) -> dict[str, Any]:
    if type(payload) is not bytes or not 1 <= len(payload) <= maximum_bytes:
        raise PublicContractError(code)
    try:
        value = json.loads(
            payload.decode("utf-8"),
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=_reject_constant,
        )
        validator(value)
        if canonical_json_bytes(value) != payload:
            raise PublicContractError(code)
    except PublicContractError:
        raise
    except (RecursionError, TypeError, UnicodeError, ValueError) as error:
        raise PublicContractError(code) from error
    return value


def _keys(value: object, expected: tuple[str, ...], code: str) -> dict[str, Any]:
    if type(value) is not dict or set(value) != set(expected):
        raise PublicContractError(code)
    return value


def _text(
    value: object,
    *,
    code: str,
    exact: str | None = None,
    pattern: re.Pattern[str] | None = None,
    allowed: frozenset[str] | None = None,
    maximum_length: int = 512,
) -> str:
    if type(value) is not str or not 1 <= len(value) <= maximum_length:
        raise PublicContractError(code)
    try:
        value.encode("utf-8")
    except UnicodeError as error:
        raise PublicContractError(code) from error
    if any(ord(character) < 0x20 or ord(character) == 0x7F for character in value):
        raise PublicContractError(code)
    if exact is not None and value != exact:
        raise PublicContractError(code)
    if pattern is not None and pattern.fullmatch(value) is None:
        raise PublicContractError(code)
    if allowed is not None and value not in allowed:
        raise PublicContractError(code)
    return value


def _digest(value: object, code: str) -> str:
    return _text(value, code=code, pattern=_SHA256_PATTERN)


def _count(value: object, code: str, *, maximum: int = 1_000_000) -> int:
    if type(value) is not int or not 0 <= value <= maximum:
        raise PublicContractError(code)
    return value


def _boolean(value: object, code: str) -> bool:
    if type(value) is not bool:
        raise PublicContractError(code)
    return value


def _validate_evidence(value: object) -> None:
    code = "SNAPSHOT_EVIDENCE_INVALID"
    evidence = _keys(
        value,
        (
            "manifest_schema_version",
            "manifest_sha256",
            "provider_proof_sha256",
            "live_corroboration_sha256",
            "cleanup_verification_sha256",
            "image_digest",
            "candidate_sha256",
            "status",
        ),
        code,
    )
    _text(
        evidence["manifest_schema_version"],
        code=code,
        pattern=_SCHEMA_VERSION_PATTERN,
    )
    for name in (
        "manifest_sha256",
        "provider_proof_sha256",
        "live_corroboration_sha256",
        "cleanup_verification_sha256",
        "candidate_sha256",
    ):
        _digest(evidence[name], code)
    _text(evidence["image_digest"], code=code, pattern=_IMAGE_DIGEST_PATTERN)
    _text(evidence["status"], code=code, exact="PASS")


def _validate_claim_boundary(value: object) -> None:
    code = "SNAPSHOT_CLAIM_BOUNDARY_INVALID"
    boundary = _keys(
        value,
        (
            "authorized_safety_claim",
            "adaptive_efficiency_claim_authorized",
            "live_cloud_is_a_policy_comparison",
            "live_endpoint_exists",
        ),
        code,
    )
    _text(boundary["authorized_safety_claim"], code=code)
    _boolean(boundary["adaptive_efficiency_claim_authorized"], code)
    _boolean(boundary["live_cloud_is_a_policy_comparison"], code)
    _boolean(boundary["live_endpoint_exists"], code)


def _validate_legacy_recovery(value: object) -> None:
    code = "SNAPSHOT_RECOVERY_INVALID"
    recovery = _keys(
        value,
        (
            "initial_classification",
            "settled_classification",
            "acknowledgement_lost",
            "initial_continue_allowed",
            "initial_retry_allowed",
            "initial_action_permits_issued",
            "permit_count",
            "all_permits_single_use",
            "replay_outcome",
            "replay_contacted_provider",
            "effects",
        ),
        code,
    )
    initial = _text(
        recovery["initial_classification"], code=code, allowed=_CLASSIFICATIONS
    )
    _text(recovery["settled_classification"], code=code, allowed=_CLASSIFICATIONS)
    _boolean(recovery["acknowledgement_lost"], code)
    continue_allowed = _boolean(recovery["initial_continue_allowed"], code)
    retry_allowed = _boolean(recovery["initial_retry_allowed"], code)
    initial_permits = _count(recovery["initial_action_permits_issued"], code)
    permit_count = _count(recovery["permit_count"], code)
    single_use = _boolean(recovery["all_permits_single_use"], code)
    _text(recovery["replay_outcome"], code=code)
    _boolean(recovery["replay_contacted_provider"], code)
    effects = _keys(
        recovery["effects"],
        ("revisions", "promotions", "release_records"),
        code,
    )
    for count in effects.values():
        _count(count, code)
    if initial == "UNKNOWN" and (
        continue_allowed or retry_allowed or initial_permits != 0
    ):
        raise PublicContractError(code)
    if permit_count and not single_use:
        raise PublicContractError(code)


def _validate_recovery(value: object) -> None:
    code = "SNAPSHOT_RECOVERY_INVALID"
    recovery = _keys(
        value,
        (
            "policy",
            "fault",
            "acknowledgement_lost",
            "launch_outcome",
            "terminal_disposition",
            "chain_completed",
            "certificate_count",
            "continue_permits_issued",
            "action_permits_consumed",
            "provider_contacts",
            "replay",
            "effects",
        ),
        code,
    )
    _text(recovery["policy"], code=code, exact="adaptive")
    _text(recovery["fault"], code=code, exact="drop-after-accept")
    if not _boolean(recovery["acknowledgement_lost"], code):
        raise PublicContractError(code)
    _text(recovery["launch_outcome"], code=code, exact="OUTCOME_UNKNOWN")
    _text(recovery["terminal_disposition"], code=code, exact="COMPLETED")
    if not _boolean(recovery["chain_completed"], code):
        raise PublicContractError(code)
    for name in (
        "certificate_count",
        "continue_permits_issued",
        "action_permits_consumed",
        "provider_contacts",
    ):
        if _count(recovery[name], code, maximum=32) < 1:
            raise PublicContractError(code)

    replay = _keys(
        recovery["replay"],
        (
            "snapshot_stable",
            "rejected_before_provider_contact",
            "provider_contact_delta",
            "denial_count",
        ),
        code,
    )
    if (
        not _boolean(replay["snapshot_stable"], code)
        or not _boolean(replay["rejected_before_provider_contact"], code)
        or _count(replay["provider_contact_delta"], code) != 0
        or _count(replay["denial_count"], code) != 1
    ):
        raise PublicContractError(code)

    effects = _keys(
        recovery["effects"],
        ("revisions", "promotions", "release_records"),
        code,
    )
    if any(_count(count, code, maximum=16) != 1 for count in effects.values()):
        raise PublicContractError(code)


def _validate_legacy_advisory(value: object) -> None:
    code = "SNAPSHOT_ADVISORY_INVALID"
    advisory = _keys(
        value,
        (
            "configured_model",
            "reported_model",
            "planner_outcome",
            "bound_to_hypothesis",
            "hypothesis_count",
            "authority",
        ),
        code,
    )
    for name in ("configured_model", "reported_model", "planner_outcome"):
        _text(advisory[name], code=code)
    _boolean(advisory["bound_to_hypothesis"], code)
    _count(advisory["hypothesis_count"], code)
    _text(
        advisory["authority"],
        code=code,
        exact="read-only-probe-planning-only",
    )


def _validate_advisory(value: object) -> None:
    code = "SNAPSHOT_ADVISORY_INVALID"
    advisory = _keys(
        value,
        (
            "configured_model",
            "reported_model",
            "planner_outcome",
            "count_attempts",
            "generation_attempts",
            "authority",
        ),
        code,
    )
    _text(advisory["configured_model"], code=code, exact="gemini-3.5-flash")
    _text(
        advisory["reported_model"],
        code=code,
        pattern=_MODEL_PATTERN,
        maximum_length=128,
    )
    _text(advisory["planner_outcome"], code=code, exact="planner-succeeded")
    if (
        _count(advisory["count_attempts"], code, maximum=16) != 1
        or _count(advisory["generation_attempts"], code, maximum=16) != 1
    ):
        raise PublicContractError(code)
    _text(
        advisory["authority"],
        code=code,
        exact="read-only-probe-planning-only",
    )


def _validate_cleanup(value: object) -> None:
    code = "SNAPSHOT_CLEANUP_INVALID"
    cleanup = _keys(value, ("status", "retained_resource_count"), code)
    status = _text(cleanup["status"], code=code, allowed=frozenset({"PASS", "FAIL"}))
    retained = _count(cleanup["retained_resource_count"], code)
    if status == "PASS" and retained != 0:
        raise PublicContractError(code)


def _validate_ambiguity(value: object) -> None:
    if value is None:
        return
    code = "SNAPSHOT_AMBIGUITY_INVALID"
    ambiguity = _keys(
        value,
        (
            "classification",
            "lifecycle",
            "decision",
            "history_ids",
            "history_classifications",
            "history_evidence_counts",
            "discriminating_observation_count",
            "certificate_count",
            "action_permit_count",
            "effects",
        ),
        code,
    )
    _text(ambiguity["classification"], code=code, exact="UNKNOWN")
    _text(ambiguity["lifecycle"], code=code, exact="ESCALATED")
    _text(ambiguity["decision"], code=code, exact="ESCALATE")
    histories = ambiguity["history_ids"]
    if histories != ["effects-occurred", "effects-not-occurred"]:
        raise PublicContractError(code)
    classifications = ambiguity["history_classifications"]
    if type(classifications) is not list or classifications != ["COMMITTED", "PARTIAL"]:
        raise PublicContractError(code)
    evidence_counts = ambiguity["history_evidence_counts"]
    if (
        type(evidence_counts) is not list
        or len(evidence_counts) != 2
        or any(_count(count, code, maximum=64) < 1 for count in evidence_counts)
    ):
        raise PublicContractError(code)
    if _count(ambiguity["discriminating_observation_count"], code, maximum=16) < 1:
        raise PublicContractError(code)
    if (
        _count(ambiguity["certificate_count"], code) != 0
        or _count(ambiguity["action_permit_count"], code) != 0
    ):
        raise PublicContractError(code)
    effects = _keys(
        ambiguity["effects"],
        ("staged_revisions", "promotions", "release_records"),
        code,
    )
    if (
        _count(effects["staged_revisions"], code) != 1
        or _count(effects["promotions"], code) != 0
        or _count(effects["release_records"], code) != 0
    ):
        raise PublicContractError(code)


def validate_snapshot(value: object) -> None:
    """Validate the exact closed public snapshot and its self hash."""

    code = "SNAPSHOT_INVALID"
    snapshot = _keys(
        value,
        (
            "schema_version",
            "display_label",
            "viewer_source_revision",
            "evidence_source_revision",
            "evidence_version",
            "evidence",
            "claim_boundary",
            "recovery",
            "ambiguity",
            "advisory_planning",
            "cleanup",
            "limitations",
            "projection_sha256",
        ),
        code,
    )
    schema_version = _text(
        snapshot["schema_version"],
        code=code,
        allowed=frozenset({LEGACY_SNAPSHOT_VERSION, SNAPSHOT_VERSION}),
    )
    _text(snapshot["display_label"], code=code, exact=DISPLAY_LABEL)
    _text(
        snapshot["viewer_source_revision"],
        code=code,
        pattern=_SOURCE_REVISION_PATTERN,
    )
    _text(
        snapshot["evidence_source_revision"],
        code=code,
        pattern=_SOURCE_REVISION_PATTERN,
    )
    _text(
        snapshot["evidence_version"],
        code=code,
        pattern=_EVIDENCE_VERSION_PATTERN,
    )
    _validate_evidence(snapshot["evidence"])
    _validate_claim_boundary(snapshot["claim_boundary"])
    if schema_version == LEGACY_SNAPSHOT_VERSION:
        if snapshot["evidence"]["manifest_schema_version"] != "reconcile/demo-proof/v2":
            raise PublicContractError(code)
        _validate_legacy_recovery(snapshot["recovery"])
        _validate_legacy_advisory(snapshot["advisory_planning"])
    else:
        if (
            snapshot["evidence"]["manifest_schema_version"]
            != "reconcile/public-evidence/v1"
        ):
            raise PublicContractError(code)
        _validate_recovery(snapshot["recovery"])
        _validate_advisory(snapshot["advisory_planning"])
    _validate_ambiguity(snapshot["ambiguity"])
    _validate_cleanup(snapshot["cleanup"])
    limitations = snapshot["limitations"]
    if type(limitations) is not list or len(limitations) != len(LIMITATIONS):
        raise PublicContractError(code)
    for observed, expected in zip(limitations, LIMITATIONS, strict=True):
        _text(observed, code=code, exact=expected)
    observed_projection = _digest(snapshot["projection_sha256"], code)
    base = {key: item for key, item in snapshot.items() if key != "projection_sha256"}
    if observed_projection != sha256_hex(canonical_json_bytes(base)):
        raise PublicContractError("SNAPSHOT_PROJECTION_MISMATCH")


def seal_snapshot(base: dict[str, Any]) -> dict[str, Any]:
    """Add and verify the self projection hash for a new snapshot."""

    if type(base) is not dict or "projection_sha256" in base:
        raise PublicContractError("SNAPSHOT_INVALID")
    snapshot = dict(base)
    snapshot["projection_sha256"] = sha256_hex(canonical_json_bytes(base))
    validate_snapshot(snapshot)
    return snapshot


def decode_snapshot(payload: bytes) -> dict[str, Any]:
    """Decode one canonical, closed, self-bound public snapshot."""

    return _decode_canonical_object(
        payload,
        maximum_bytes=MAX_SNAPSHOT_BYTES,
        validator=validate_snapshot,
        code="SNAPSHOT_INVALID",
    )


def render_html(snapshot: dict[str, Any]) -> bytes:
    """Render the only accepted HTML representation of a valid snapshot."""

    validate_snapshot(snapshot)
    recovery = snapshot["recovery"]
    advisory = snapshot["advisory_planning"]
    effects = recovery["effects"]
    ambiguity = snapshot["ambiguity"]
    if snapshot["schema_version"] == LEGACY_SNAPSHOT_VERSION:
        recovery_html = f"""
<section class="grid">
<article class="card"><h2>Initial result</h2>
<p><strong>{html.escape(recovery["initial_classification"])}</strong></p>
<p>Continue allowed: {str(recovery["initial_continue_allowed"]).lower()}</p>
<p>Retry allowed: {str(recovery["initial_retry_allowed"]).lower()}</p></article>
<article class="card"><h2>Settled result</h2>
<p><strong>{html.escape(recovery["settled_classification"])}</strong></p>
<p>Permits: {recovery["permit_count"]}; single-use: {str(recovery["all_permits_single_use"]).lower()}</p>
<p>Replay: {html.escape(recovery["replay_outcome"])}</p></article>
<article class="card"><h2>Observed effects</h2>
<p>Revisions: {effects["revisions"]}</p>
<p>Promotions: {effects["promotions"]}</p>
<p>Release records: {effects["release_records"]}</p></article>
</section>"""
        advisory_html = f"""<section><h2>Advisory planning</h2>
<p>{html.escape(advisory["reported_model"])} reported
{html.escape(advisory["planner_outcome"])}. Its authority was limited to
read-only probe planning.</p></section>"""
    else:
        replay = recovery["replay"]
        recovery_html = f"""
<section class="grid">
<article class="card"><h2>Recorded recovery</h2>
<p>Launch outcome: <strong>{html.escape(recovery["launch_outcome"])}</strong></p>
<p>Terminal disposition: <strong>{html.escape(recovery["terminal_disposition"])}</strong></p>
<p>Policy: {html.escape(recovery["policy"])}; fault: {html.escape(recovery["fault"])}</p>
<p>Acknowledgement lost: {str(recovery["acknowledgement_lost"]).lower()}; chain completed: {str(recovery["chain_completed"]).lower()}</p></article>
<article class="card"><h2>Recorded counts</h2>
<p>Certificates: {recovery["certificate_count"]}</p>
<p>Continue permits issued: {recovery["continue_permits_issued"]}</p>
<p>Action permits consumed: {recovery["action_permits_consumed"]}</p>
<p>Provider contacts: {recovery["provider_contacts"]}</p></article>
<article class="card"><h2>Recorded replay</h2>
<p>Rejected before provider contact: {str(replay["rejected_before_provider_contact"]).lower()}</p>
<p>Provider contact delta: {replay["provider_contact_delta"]}; denial count: {replay["denial_count"]}</p>
<p>Snapshot stable: {str(replay["snapshot_stable"]).lower()}</p></article>
<article class="card"><h2>Observed effects</h2>
<p>Revisions: {effects["revisions"]}</p>
<p>Promotions: {effects["promotions"]}</p>
<p>Release records: {effects["release_records"]}</p></article>
</section>"""
        advisory_html = f"""<section><h2>Advisory planning</h2>
<p>Configured model: {html.escape(advisory["configured_model"])}</p>
<p>Reported model: {html.escape(advisory["reported_model"])}</p>
<p>Planner outcome: {html.escape(advisory["planner_outcome"])}</p>
<p>Count attempts: {advisory["count_attempts"]}; generation attempts: {advisory["generation_attempts"]}</p>
<p>Recorded authority: {html.escape(advisory["authority"])}</p></section>"""
    ambiguity_html = ""
    if ambiguity is not None:
        ambiguity_effects = ambiguity["effects"]
        histories = " / ".join(
            f"{html.escape(history_id)} ({html.escape(classification)})"
            for history_id, classification in zip(
                ambiguity["history_ids"],
                ambiguity["history_classifications"],
                strict=True,
            )
        )
        ambiguity_html = f"""
<section><h2>Ambiguous provider outcome</h2>
<div class="grid">
<article class="card"><h3>Decision</h3>
<p><strong>{html.escape(ambiguity["classification"])} / {html.escape(ambiguity["lifecycle"])}</strong></p>
<p>Certificates: {ambiguity["certificate_count"]}; action permits: {ambiguity["action_permit_count"]}</p></article>
<article class="card"><h3>Possible histories</h3>
<p>{histories}</p>
<p>Each history is bound to compatible evidence.</p>
<p>Discriminating observations: {ambiguity["discriminating_observation_count"]}</p></article>
<article class="card"><h3>Observed effects</h3>
<p>Staged revisions: {ambiguity_effects["staged_revisions"]}</p>
<p>Promotions: {ambiguity_effects["promotions"]}</p>
<p>Release records: {ambiguity_effects["release_records"]}</p></article>
</div></section>"""
    limitations = "".join(
        f"<li>{html.escape(item)}</li>" for item in snapshot["limitations"]
    )
    page = f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Reconcile evidence viewer</title>
<style>
:root {{ color-scheme: light; font-family: ui-sans-serif, system-ui, sans-serif; }}
body {{ margin: 0; background: #f4f7f5; color: #12221b; }}
main {{ width: min(68rem, calc(100% - 2rem)); margin: auto; padding: 3rem 0; }}
.banner {{ border-left: .4rem solid #256b4b; padding: 1rem; background: #e6f5ec; }}
.grid {{ display: grid; grid-template-columns: repeat(auto-fit,minmax(16rem,1fr)); gap: 1rem; margin: 2rem 0; }}
.card {{ background: white; border: 1px solid #cad8d0; border-radius: .6rem; padding: 1rem; }}
.identity {{ font-size: .85rem; overflow-wrap: anywhere; }}
code {{ overflow-wrap: anywhere; }}
a {{ color: #145f40; }}
</style>
</head>
<body><main>
<section class="banner"><strong>{html.escape(snapshot["display_label"])}</strong></section>
<h1>Reconcile evidence</h1>
<p>A bounded projection of a validated versioned evidence bundle.</p>
{recovery_html}
{ambiguity_html}
{advisory_html}
<section><h2>Limitations</h2><ul>{limitations}</ul></section>
<section class="identity"><h2>Verification</h2>
<p>Viewer and evidence identities were verified before this bundle was built.</p>
<p>Evidence version <code>{html.escape(snapshot["evidence_version"])}</code></p>
<p>Exact integrity metadata remains available in the machine-readable files.</p>
<p><a href="/snapshot.json">Machine-readable snapshot</a> ·
<a href="/bundle-manifest.json">Bundle manifest</a></p>
</section>
</main></body></html>
"""
    payload = page.encode("utf-8")
    if not 1 <= len(payload) <= MAX_HTML_BYTES:
        raise PublicContractError("HTML_INVALID")
    return payload


def build_manifest(
    snapshot: dict[str, Any], snapshot_payload: bytes, html_payload: bytes
) -> dict[str, Any]:
    """Build the exact manifest for canonical snapshot and HTML bytes."""

    validate_snapshot(snapshot)
    if canonical_json_bytes(snapshot) != snapshot_payload:
        raise PublicContractError("SNAPSHOT_INVALID")
    if render_html(snapshot) != html_payload:
        raise PublicContractError("HTML_INVALID")
    manifest = {
        "schema_version": BUNDLE_VERSION,
        "files": {
            "index.html": {
                "byte_count": len(html_payload),
                "sha256": sha256_hex(html_payload),
            },
            "snapshot.json": {
                "byte_count": len(snapshot_payload),
                "sha256": sha256_hex(snapshot_payload),
            },
        },
        "snapshot_projection_sha256": snapshot["projection_sha256"],
    }
    validate_manifest(manifest, snapshot, snapshot_payload, html_payload)
    return manifest


def validate_manifest(
    value: object,
    snapshot: dict[str, Any],
    snapshot_payload: bytes,
    html_payload: bytes,
) -> None:
    """Validate the exact bundle manifest and all byte bindings."""

    code = "BUNDLE_MANIFEST_INVALID"
    manifest = _keys(
        value,
        ("schema_version", "files", "snapshot_projection_sha256"),
        code,
    )
    _text(manifest["schema_version"], code=code, exact=BUNDLE_VERSION)
    files = _keys(manifest["files"], ("index.html", "snapshot.json"), code)
    expected_payloads = {
        "index.html": html_payload,
        "snapshot.json": snapshot_payload,
    }
    for name, payload in expected_payloads.items():
        binding = _keys(files[name], ("byte_count", "sha256"), code)
        if type(binding["byte_count"]) is not int or binding["byte_count"] != len(
            payload
        ):
            raise PublicContractError(code)
        if _digest(binding["sha256"], code) != sha256_hex(payload):
            raise PublicContractError(code)
    if (
        _digest(manifest["snapshot_projection_sha256"], code)
        != snapshot["projection_sha256"]
    ):
        raise PublicContractError(code)


def decode_manifest(
    payload: bytes,
    snapshot: dict[str, Any],
    snapshot_payload: bytes,
    html_payload: bytes,
) -> dict[str, Any]:
    """Decode one canonical manifest bound to the public files."""

    return _decode_canonical_object(
        payload,
        maximum_bytes=MAX_MANIFEST_BYTES,
        validator=lambda value: validate_manifest(
            value, snapshot, snapshot_payload, html_payload
        ),
        code="BUNDLE_MANIFEST_INVALID",
    )


def _read_open_descriptor(descriptor: int, maximum_bytes: int) -> bytes:
    try:
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_nlink != 1
            or not 1 <= before.st_size <= maximum_bytes
        ):
            raise PublicContractError("FILE_INVALID")
        remaining = before.st_size
        chunks: list[bytes] = []
        while remaining:
            chunk = os.read(descriptor, min(65_536, remaining))
            if not chunk:
                raise PublicContractError("FILE_INVALID")
            chunks.append(chunk)
            remaining -= len(chunk)
        if os.read(descriptor, 1):
            raise PublicContractError("FILE_INVALID")
        after = os.fstat(descriptor)
        if (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) != (
            after.st_dev,
            after.st_ino,
            after.st_size,
            after.st_mtime_ns,
        ):
            raise PublicContractError("FILE_INVALID")
        return b"".join(chunks)
    except PublicContractError:
        raise
    except OSError as error:
        raise PublicContractError("FILE_INVALID") from error


def read_bounded_regular_at(
    directory_descriptor: int, name: str, maximum_bytes: int
) -> bytes:
    """Read one exact child from an already-open directory descriptor."""

    if (
        type(directory_descriptor) is not int
        or type(name) is not str
        or not name
        or "/" in name
        or name in {".", ".."}
        or type(maximum_bytes) is not int
        or maximum_bytes < 1
    ):
        raise PublicContractError("FILE_INVALID")
    flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW
    try:
        descriptor = os.open(name, flags, dir_fd=directory_descriptor)
    except OSError as error:
        raise PublicContractError("FILE_INVALID") from error
    try:
        return _read_open_descriptor(descriptor, maximum_bytes)
    finally:
        os.close(descriptor)


__all__ = [
    "BUNDLE_VERSION",
    "DISPLAY_LABEL",
    "LEGACY_SNAPSHOT_VERSION",
    "LIMITATIONS",
    "MAX_HTML_BYTES",
    "MAX_MANIFEST_BYTES",
    "MAX_SNAPSHOT_BYTES",
    "SNAPSHOT_VERSION",
    "PublicContractError",
    "build_manifest",
    "canonical_json_bytes",
    "decode_manifest",
    "decode_snapshot",
    "read_bounded_regular_at",
    "render_html",
    "seal_snapshot",
    "sha256_hex",
    "validate_manifest",
    "validate_snapshot",
]
