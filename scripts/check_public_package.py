#!/usr/bin/env python3
"""Validate the durable public source, documentation, and evidence package."""

from __future__ import annotations

import argparse
import json
import re
import shutil
import struct
import subprocess
import sys
import tempfile
import urllib.error
import urllib.request
from pathlib import Path

if __package__:
    from .build_public_release import (
        ASSETS,
        CHECKSUM_NAME,
        RELEASE_VERSION,
        SOURCE_MANIFEST_NAME,
        SOURCE_REVISION,
        ReleaseBuildError,
        build_release,
    )
    from .validate_evidence import DEFAULT_EVIDENCE, EvidenceError, load_and_validate
else:
    from build_public_release import (
        ASSETS,
        CHECKSUM_NAME,
        RELEASE_VERSION,
        SOURCE_MANIFEST_NAME,
        SOURCE_REVISION,
        ReleaseBuildError,
        build_release,
    )
    from validate_evidence import DEFAULT_EVIDENCE, EvidenceError, load_and_validate

ROOT = Path(__file__).resolve().parents[1]
CURRENT_VERSION = "v0.2.0"
BASELINE_VERSION = "v0.1.0"
EVIDENCE_ROOT = ROOT / "evidence" / CURRENT_VERSION
BASELINE_EVIDENCE_ROOT = ROOT / "evidence" / BASELINE_VERSION
EVIDENCE_DIRECTORY = ROOT / "evidence"
WORKFLOW = ROOT / ".github" / "workflows" / "public-verification.yml"
PUBLIC_VIEWER = "https://reconcile-evidence-g6fwwrme5a-uc.a.run.app"
CURRENT_RELEASE = "https://github.com/OCHOLA-EDDYPHIL/reconcile/releases/tag/v0.2.0"
DURABLE_EXTERNAL_LINKS = frozenset(
    {
        "https://docs.astral.sh/uv/",
        CURRENT_RELEASE,
        PUBLIC_VIEWER,
    }
)
EVIDENCE_FILES = frozenset(
    {
        "proof-to-permit.json",
        "provider-proof.json",
        "live-corroboration.json",
        "cleanup-verification.json",
    }
)
REQUIRED = (
    ROOT / "README.md",
    ROOT / "docs" / "architecture.dot",
    ROOT / "docs" / "architecture.png",
    ROOT / "docs" / "deployment.dot",
    ROOT / "docs" / "deployment.png",
    ROOT / "docs" / "evidence-proof.dot",
    ROOT / "docs" / "evidence-proof.png",
    ROOT / "docs" / "claims-and-limitations.md",
    ROOT / "docs" / "hosted-runbook.md",
    WORKFLOW,
    EVIDENCE_ROOT / "proof-to-permit.json",
    EVIDENCE_ROOT / "provider-proof.json",
    EVIDENCE_ROOT / "live-corroboration.json",
    EVIDENCE_ROOT / "cleanup-verification.json",
    ROOT / "scripts" / "build_public_release.py",
    ROOT / "scripts" / "verify_publication.py",
    ROOT / "scripts" / "validate_evidence.py",
    ROOT / "viewer" / ".dockerignore",
    ROOT / "viewer" / "Dockerfile",
    ROOT / "viewer" / "export.py",
    ROOT / "viewer" / "public_contract.py",
    ROOT / "viewer" / "server.py",
)
REMOVED = (
    ROOT / "demo",
    ROOT / "scripts" / "check_release_candidate.py",
    ROOT / "scripts" / "replay_gate_g5r.py",
    ROOT / "viewer" / "bundle",
)
MARKDOWN = (
    ROOT / "README.md",
    ROOT / "docs" / "claims-and-limitations.md",
    ROOT / "docs" / "hosted-runbook.md",
)
DIAGRAMS = (
    (ROOT / "docs" / "architecture.dot", ROOT / "docs" / "architecture.png"),
    (ROOT / "docs" / "deployment.dot", ROOT / "docs" / "deployment.png"),
)
EVIDENCE_PROOF = (
    ROOT / "docs" / "evidence-proof.dot",
    ROOT / "docs" / "evidence-proof.png",
)
LINK = re.compile(r"!?(?:\[[^]]*\])\(([^)]+)\)")
PRIVATE_PATH = re.compile(r"(?:/home/|/Users/|file://|[A-Za-z]:\\\\Users\\\\)")
GITHUB_LINK = re.compile(r"https://github\.com/[^\s)>]+")
CANONICAL_REPOSITORY = "https://github.com/OCHOLA-EDDYPHIL/reconcile"
CANONICAL_RELEASE_LINK = re.compile(
    re.escape(f"{CANONICAL_REPOSITORY}/releases/")
    + r"(?:tag|download)/v[0-9]+\.[0-9]+\.[0-9]+(?:/[^\s)>]+)?"
)
SVG_REFERENCE = re.compile(r"\.svg(?:\b|$)", re.I)
FORBIDDEN_CLAIMS = (
    re.compile(
        r"\bgemini\s+(?:proved|proves|decided|decides|authorized|authorizes)\b",
        re.I,
    ),
    re.compile(r"\badaptive\s+(?:beat|beats|outperformed|outperforms)\b", re.I),
)
FORBIDDEN_DIAGRAM_CONTENT = (
    re.compile(r"\b(?:sha(?:256)?|hash|digest|run[_ -]?id|timestamp)\b", re.I),
    re.compile(r"\b[0-9a-f]{40}\b", re.I),
    re.compile(r"\b[0-9a-f]{64}\b", re.I),
    re.compile(r"\b\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z\b"),
    re.compile(
        r"(?:projects/|serviceAccount:|\.iam\.gserviceaccount\.com|\.run\.app)", re.I
    ),
    re.compile(r"\b\d+\s+(?:events|permits|records|revisions)\b", re.I),
)
EVIDENCE_VERSION = re.compile(r"^v([0-9]+)[.]([0-9]+)[.]([0-9]+)$")
PINNED_ACTION = re.compile(
    r"^\s*-\s+uses:\s+[^@\s]+@([0-9a-f]{40})(?:\s+#\s*[^\r\n]+)?$",
    re.MULTILINE,
)
ACTION_REFERENCE = re.compile(r"^\s*-\s+uses:\s+\S+", re.MULTILINE)
TRACKED_SECRET_NAMES = (
    re.compile(r"(?:^|/)[.]env(?:[.].+)?$", re.I),
    re.compile(r"[.](?:pem|key|p12|pfx|tfstate|tfvars)$", re.I),
    re.compile(r"(?:^|/)(?:credentials?|service[-_]?account)[^/]*[.]json$", re.I),
)
TRACKED_SECRET_CONTENT = (
    (
        "private-key material",
        re.compile(
            "-----BEGIN "
            + r"(?:RSA |EC |OPENSSH )?"
            + r"PRIVATE KEY-----\s+[0-9A-Za-z+/=\r\n]{80,}"
            + "-----END"
        ),
    ),
    ("Google API key", re.compile(r"\bAI" + r"za[0-9A-Za-z_-]{35}\b")),
    ("GitHub token", re.compile(r"\bgh" + r"[pousr]_[0-9A-Za-z]{20,}\b")),
    ("AWS access key", re.compile(r"\bAK" + r"IA[0-9A-Z]{16}\b")),
    ("Slack token", re.compile(r"\bxox" + r"[abprs]-[0-9A-Za-z-]{10,}\b")),
    ("OAuth access token", re.compile(r"\bya" + r"29[.][0-9A-Za-z_-]{20,}\b")),
)
MAX_SECRET_SCAN_BYTES = 2 * 1024 * 1024


class PackageError(ValueError):
    """The durable public package violates its checked contract."""


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise PackageError(message)


def _check_files() -> None:
    missing = [str(path.relative_to(ROOT)) for path in REQUIRED if not path.is_file()]
    _require(not missing, "missing required files: " + ", ".join(missing))
    retained = [str(path.relative_to(ROOT)) for path in REMOVED if path.exists()]
    _require(
        not retained, "obsolete public-package paths remain: " + ", ".join(retained)
    )


def _versioned_evidence_roots() -> tuple[Path, ...]:
    roots: list[tuple[tuple[int, int, int], Path]] = []
    for path in EVIDENCE_DIRECTORY.iterdir():
        match = EVIDENCE_VERSION.fullmatch(path.name)
        if path.is_dir() and not path.is_symlink() and match is not None:
            roots.append((tuple(int(value) for value in match.groups()), path))
    roots.sort()
    _require(bool(roots), "no versioned evidence directory exists")
    _require(
        BASELINE_EVIDENCE_ROOT in {path for _, path in roots},
        f"the {BASELINE_VERSION} evidence baseline is missing",
    )
    _require(
        roots[-1][1] == EVIDENCE_ROOT,
        f"current evidence must be the latest version ({CURRENT_VERSION})",
    )
    _require(
        DEFAULT_EVIDENCE.resolve() == EVIDENCE_ROOT / "proof-to-permit.json",
        "default validator evidence does not select the current version",
    )
    _require(
        RELEASE_VERSION == CURRENT_VERSION,
        "release package version does not select the current evidence",
    )
    for _, path in roots:
        entries = tuple(path.iterdir())
        names = {item.name for item in entries}
        _require(
            names == EVIDENCE_FILES
            and all(item.is_file() and not item.is_symlink() for item in entries),
            f"versioned evidence inventory drifted: {path.relative_to(ROOT)}",
        )
    return tuple(path for _, path in roots)


def _target_from_markdown(raw: str) -> str:
    target = raw.strip()
    if target.startswith("<") and ">" in target:
        target = target[1 : target.index(">")]
    elif " " in target:
        target = target.split(" ", 1)[0]
    return target


def _check_links_and_paths() -> tuple[int, frozenset[str]]:
    checked = 0
    external: set[str] = set()
    for document in MARKDOWN:
        content = document.read_text(encoding="utf-8")
        _require(
            PRIVATE_PATH.search(content) is None,
            f"private path in {document.relative_to(ROOT)}",
        )
        _require(
            SVG_REFERENCE.search(content) is None,
            f"SVG reference in {document.relative_to(ROOT)}",
        )
        for github_link in GITHUB_LINK.findall(content):
            valid = (
                github_link
                in {
                    CANONICAL_REPOSITORY,
                    f"{CANONICAL_REPOSITORY}.git",
                }
                or CANONICAL_RELEASE_LINK.fullmatch(github_link) is not None
            )
            _require(
                valid,
                "non-canonical repository link in "
                f"{document.relative_to(ROOT)}: {github_link}",
            )
        for pattern in FORBIDDEN_CLAIMS:
            _require(
                pattern.search(content) is None,
                f"forbidden claim in {document.relative_to(ROOT)}",
            )
        for match in LINK.finditer(content):
            target = _target_from_markdown(match.group(1))
            if target.startswith(("http://", "https://")):
                external.add(target)
                continue
            if not target or target.startswith(("#", "mailto:")):
                continue
            resolved = (document.parent / target.split("#", 1)[0]).resolve()
            _require(
                resolved == ROOT or ROOT in resolved.parents,
                f"link escapes repository: {target}",
            )
            _require(
                resolved.exists(),
                f"broken link in {document.relative_to(ROOT)}: {target}",
            )
            checked += 1
    _require(
        external == DURABLE_EXTERNAL_LINKS,
        "durable external link inventory drifted: "
        + ", ".join(sorted(external ^ DURABLE_EXTERNAL_LINKS)),
    )
    return checked, frozenset(external)


def _check_external_links(links: frozenset[str]) -> int:
    for link in sorted(links):
        request = urllib.request.Request(
            link,
            headers={"User-Agent": "Reconcile-public-package-check/1"},
            method="GET",
        )
        try:
            with urllib.request.urlopen(request, timeout=20) as response:
                _require(
                    200 <= response.status < 400,
                    f"durable external link returned HTTP {response.status}: {link}",
                )
                response.read(1)
        except urllib.error.HTTPError as error:
            raise PackageError(
                f"durable external link returned HTTP {error.code}: {link}"
            ) from error
        except urllib.error.URLError as error:
            raise PackageError(
                f"durable external link is unreachable: {link}"
            ) from error
    return len(links)


def _check_claim_boundaries(latest_evidence: Path) -> None:
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    claims = (ROOT / "docs" / "claims-and-limitations.md").read_text(encoding="utf-8")
    _require(
        "Gemini investigates. Deterministic evidence decides." in readme,
        "authority shorthand is missing",
    )
    _require(
        "Reconcile is an evidence-bound recovery layer for ambiguous agent "
        "side effects." in readme,
        "canonical product description is missing",
    )
    _require("No general exactly-once guarantee" in claims, "non-claim is missing")
    _require(
        f"evidence/{latest_evidence.name}/proof-to-permit.json" in readme,
        "versioned evidence entry point is missing",
    )
    _require(
        "python scripts/check_public_package.py" in readme,
        "public package check is not documented",
    )
    _require(
        "python scripts/build_public_release.py" in readme,
        "release package build is not documented",
    )
    _require(CURRENT_RELEASE in readme, "current release link is missing")
    _require(CURRENT_RELEASE in claims, "current release claim link is missing")
    _require(PUBLIC_VIEWER in readme, "public viewer link is missing")
    _require(PUBLIC_VIEWER in claims, "public viewer claim link is missing")
    public_text = "\n".join(path.read_text(encoding="utf-8") for path in MARKDOWN)
    _require(
        "Proof-to-Permit" not in public_text,
        "retired protocol label remains in public prose",
    )


def _tracked_files() -> tuple[Path, ...]:
    completed = subprocess.run(
        ("git", "ls-files", "--cached", "--others", "--exclude-standard", "-z"),
        cwd=ROOT,
        check=True,
        capture_output=True,
    )
    paths = []
    for raw in completed.stdout.split(b"\0"):
        if not raw:
            continue
        relative = raw.decode("utf-8", errors="strict")
        paths.append(ROOT / relative)
    return tuple(paths)


def _check_repository_hygiene() -> int:
    checked = 0
    for path in _tracked_files():
        relative = path.relative_to(ROOT).as_posix()
        for pattern in TRACKED_SECRET_NAMES:
            _require(
                pattern.search(relative) is None,
                f"secret-bearing filename is tracked: {relative}",
            )
        if not path.is_file() or path.is_symlink():
            continue
        size = path.stat().st_size
        if size > MAX_SECRET_SCAN_BYTES:
            continue
        raw = path.read_bytes()
        if b"\0" in raw:
            continue
        content = raw.decode("utf-8", errors="ignore")
        for label, pattern in TRACKED_SECRET_CONTENT:
            _require(
                pattern.search(content) is None,
                f"possible {label} in tracked file: {relative}",
            )
        checked += 1
    return checked


def _check_workflow() -> int:
    content = WORKFLOW.read_text(encoding="utf-8")
    _require("pull_request:" in content, "pull request trigger is missing")
    _require(
        "push:" in content and "branches: [main]" in content,
        "main trigger is missing",
    )
    _require("contents: read" in content, "workflow permissions are not read-only")
    _require("self-hosted" not in content, "fast gate must use GitHub-hosted runners")
    _require("pull_request_target" not in content, "unsafe workflow trigger is present")
    action_references = ACTION_REFERENCE.findall(content)
    pinned_actions = PINNED_ACTION.findall(content)
    _require(bool(action_references), "workflow has no actions")
    _require(
        len(action_references) == len(pinned_actions),
        "every workflow action must be pinned to a full commit",
    )
    runners = re.findall(r"^\s+runs-on:\s+ubuntu-24[.]04\s*$", content, re.MULTILINE)
    timeouts = [
        int(value)
        for value in re.findall(
            r"^\s+timeout-minutes:\s+(\d+)\s*$", content, re.MULTILINE
        )
    ]
    _require(bool(runners), "workflow has no GitHub-hosted jobs")
    _require(
        len(runners) == len(timeouts) and all(value <= 15 for value in timeouts),
        "every workflow job needs a timeout of 15 minutes or less",
    )
    required_commands = (
        "uv lock --check",
        "ruff format --check .",
        "ruff check .",
        "python -m scripts.validate_evidence",
        "python scripts/check_public_package.py",
        "python scripts/check_public_package.py --offline",
        "python scripts/build_public_release.py",
        "python scripts/verify_publication.py",
        "sha256sum --check --strict",
        "terraform fmt -check -recursive infra",
        "python scripts/check_phase5_terraform_plans.py",
        "tests/unit/test_phase5_terraform_plans.py",
        "tests/contract",
        "tests/unit",
        "tests/unit/test_publication_verification.py",
        "tests/integration/test_recovery_api.py",
        "--cov-fail-under=",
    )
    missing = [command for command in required_commands if command not in content]
    _require(not missing, "workflow checks are missing: " + ", ".join(missing))
    return len(runners)


def _check_release_package() -> int:
    with tempfile.TemporaryDirectory(prefix="reconcile-package-check-") as directory:
        output = Path(directory) / CURRENT_VERSION
        assets = build_release(output)
        _require(
            len(assets) == len(ASSETS) + 2,
            "release asset inventory is incomplete",
        )
        _require(
            assets[-2].name == SOURCE_MANIFEST_NAME
            and assets[-1].name == CHECKSUM_NAME,
            "release provenance or checksum manifest name changed",
        )
        for source, name in ASSETS:
            _require(
                (output / name).read_bytes() == source.read_bytes(),
                f"release asset bytes changed: {name}",
            )
        source_manifest = json.loads(
            (output / SOURCE_MANIFEST_NAME).read_text(encoding="utf-8")
        )
        project_version = source_manifest.get("project_version")
        expected_status = (
            "candidate" if project_version == CURRENT_VERSION else "staged-evidence"
        )
        _require(
            source_manifest.get("schema_version")
            == "reconcile/public-release-source/v2"
            and source_manifest.get("release_version") == CURRENT_VERSION
            and source_manifest.get("package_status") == expected_status
            and source_manifest.get("source_tag") is None
            and isinstance(project_version, str)
            and EVIDENCE_VERSION.fullmatch(project_version) is not None
            and SOURCE_REVISION.fullmatch(
                str(source_manifest.get("source_revision", ""))
            )
            is not None,
            "release candidate provenance is invalid",
        )
        return len(assets)


def _png_dimensions(path: Path) -> tuple[int, int]:
    payload = path.read_bytes()
    _require(
        len(payload) >= 24
        and payload.startswith(b"\x89PNG\r\n\x1a\n")
        and payload[12:16] == b"IHDR",
        f"invalid PNG: {path.relative_to(ROOT)}",
    )
    return struct.unpack(">II", payload[16:24])


def _check_diagrams() -> str:
    for source, _export in DIAGRAMS:
        content = source.read_text(encoding="utf-8")
        for pattern in FORBIDDEN_DIAGRAM_CONTENT:
            _require(
                pattern.search(content) is None,
                f"provenance detail in conceptual diagram: {source.relative_to(ROOT)}",
            )

    executable = shutil.which("dot")
    if executable is not None:
        with tempfile.TemporaryDirectory(
            prefix="reconcile-diagram-check-"
        ) as directory:
            temporary = Path(directory)
            for source, export in (*DIAGRAMS, EVIDENCE_PROOF):
                rendered = temporary / export.name
                subprocess.run(
                    [
                        executable,
                        "-Tpng:cairo",
                        "-Gdpi=134.25",
                        str(source),
                        "-o",
                        str(rendered),
                    ],
                    check=True,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.PIPE,
                )
                _require(
                    rendered.read_bytes() == export.read_bytes(),
                    f"stale diagram export: {export.relative_to(ROOT)}",
                )

    for _, export in (*DIAGRAMS, EVIDENCE_PROOF):
        width, height = _png_dimensions(export)
        _require(
            width >= 1280 and height >= 720 and 1.6 <= width / height <= 1.8,
            f"diagram is not a readable widescreen export: {export.relative_to(ROOT)}",
        )
    proof_source = EVIDENCE_PROOF[0].read_text(encoding="utf-8")
    _require(CURRENT_VERSION in proof_source, "evidence proof version is stale")
    for statement in (
        "UNKNOWN\\n0 action permits",
        "1 revision • 1 promotion\\n1 release record",
        "Denied before provider contact",
        "Zero retained operational resources",
    ):
        _require(statement in proof_source, "evidence proof claim surface drifted")
    return (
        "source/export parity checked"
        if executable is not None
        else "PNG structure checked"
    )


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Validate the durable public source, documentation, and evidence package."
    )
    parser.add_argument(
        "--offline",
        action="store_true",
        help="validate the external-link inventory without contacting those endpoints",
    )
    arguments = parser.parse_args()
    try:
        _check_files()
        evidence_roots = _versioned_evidence_roots()
        for evidence_root in evidence_roots:
            load_and_validate(evidence_root / "proof-to-permit.json")
        link_count, external_links = _check_links_and_paths()
        external_count = (
            0 if arguments.offline else _check_external_links(external_links)
        )
        _check_claim_boundaries(evidence_roots[-1])
        diagram_result = _check_diagrams()
        tracked_count = _check_repository_hygiene()
        workflow_jobs = _check_workflow()
        release_assets = _check_release_package()
    except (
        PackageError,
        EvidenceError,
        OSError,
        ReleaseBuildError,
        subprocess.SubprocessError,
        UnicodeError,
    ) as error:
        print(f"FAIL: {error}", file=sys.stderr)
        return 1

    print("Reconcile public package: PASS")
    print(f"  versioned evidence: {len(evidence_roots)} release(s) checked")
    print(f"  local documentation links: {link_count} checked")
    if arguments.offline:
        print(f"  durable external links: {len(external_links)} inventoried (offline)")
    else:
        print(f"  durable external links: {external_count} reached")
    print(f"  conceptual diagrams: {diagram_result}")
    print(f"  tracked text files: {tracked_count} checked for credential patterns")
    print(f"  fast workflow: {workflow_jobs} bounded job(s) checked")
    print(f"  release package: {release_assets} checksum-bound asset(s) checked")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
