#!/usr/bin/env python3
"""Validate the durable public source, documentation, and evidence package."""

from __future__ import annotations

import re
import shutil
import struct
import subprocess
import sys
import tempfile
from pathlib import Path

from validate_evidence import EvidenceError, load_and_validate

ROOT = Path(__file__).resolve().parents[1]
EVIDENCE_ROOT = ROOT / "evidence" / "v0.1.0"
EVIDENCE_DIRECTORY = ROOT / "evidence"
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
    ROOT / "docs" / "claims-and-limitations.md",
    ROOT / "docs" / "hosted-runbook.md",
    EVIDENCE_ROOT / "proof-to-permit.json",
    EVIDENCE_ROOT / "provider-proof.json",
    EVIDENCE_ROOT / "live-corroboration.json",
    EVIDENCE_ROOT / "cleanup-verification.json",
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
        EVIDENCE_ROOT in {path for _, path in roots},
        "the v0.1.0 evidence baseline is missing",
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


def _check_links_and_paths() -> int:
    checked = 0
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
            if not target or target.startswith(("#", "http://", "https://", "mailto:")):
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
    return checked


def _check_claim_boundaries(latest_evidence: Path) -> None:
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    claims = (ROOT / "docs" / "claims-and-limitations.md").read_text(encoding="utf-8")
    _require(
        "Gemini investigates. Deterministic evidence decides." in readme,
        "authority shorthand is missing",
    )
    _require(
        "RECONCILE is an evidence-bound recovery layer for ambiguous agent "
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
    public_text = "\n".join(path.read_text(encoding="utf-8") for path in MARKDOWN)
    _require(
        public_text.count("Proof-to-Permit") == 1,
        "protocol name must appear exactly once in public prose",
    )
    _require(
        public_text.count("proof-to-permit safety on the frozen recovery matrix.") == 1,
        "frozen compatibility claim must appear exactly once",
    )


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
            for source, export in DIAGRAMS:
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

    for _, export in DIAGRAMS:
        width, height = _png_dimensions(export)
        _require(
            width >= 1280 and height >= 720 and 1.6 <= width / height <= 1.8,
            f"diagram is not a readable widescreen export: {export.relative_to(ROOT)}",
        )
    return (
        "source/export parity checked"
        if executable is not None
        else "PNG structure checked"
    )


def main() -> int:
    try:
        _check_files()
        evidence_roots = _versioned_evidence_roots()
        for evidence_root in evidence_roots:
            load_and_validate(evidence_root / "proof-to-permit.json")
        link_count = _check_links_and_paths()
        _check_claim_boundaries(evidence_roots[-1])
        diagram_result = _check_diagrams()
    except (PackageError, EvidenceError, OSError, subprocess.SubprocessError) as error:
        print(f"FAIL: {error}", file=sys.stderr)
        return 1

    print("RECONCILE public package: PASS")
    print(f"  versioned evidence: {len(evidence_roots)} release(s) checked")
    print(f"  local documentation links: {link_count} checked")
    print(f"  conceptual diagrams: {diagram_result}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
