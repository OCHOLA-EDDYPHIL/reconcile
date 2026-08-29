#!/usr/bin/env python3
"""Focused, local acceptance for the documentation and demo package."""

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
REQUIRED = (
    ROOT / "README.md",
    ROOT / "docs" / "architecture.dot",
    ROOT / "docs" / "architecture.png",
    ROOT / "docs" / "deployment.dot",
    ROOT / "docs" / "deployment.png",
    ROOT / "docs" / "claims-and-limitations.md",
    ROOT / "docs" / "hosted-runbook.md",
    ROOT / "demo" / "README.md",
    ROOT / "demo" / "script.md",
    ROOT / "demo" / "proof.dot",
    ROOT / "demo" / "proof.png",
    ROOT / "demo" / "evidence" / "proof-to-permit.json",
    ROOT / "demo" / "evidence" / "provider-proof.json",
    ROOT / "demo" / "evidence" / "live-corroboration.json",
    ROOT / "demo" / "evidence" / "cleanup-verification.json",
    ROOT / "scripts" / "validate_evidence.py",
    ROOT / "scripts" / "replay_gate_g5r.py",
)
MARKDOWN = tuple(path for path in REQUIRED if path.suffix == ".md")
LINK = re.compile(r"!?(?:\[[^]]*\])\(([^)]+)\)")
PRIVATE_PATH = re.compile(r"(?:/home/|/Users/|file://|[A-Za-z]:\\\\Users\\\\)")
GITHUB_LINK = re.compile(r"https://github\.com/[^\s)>]+")
CANONICAL_REPOSITORY = "https://github.com/OCHOLA-EDDYPHIL/reconcile"
CANONICAL_RELEASE = f"{CANONICAL_REPOSITORY}/releases"
SVG_REFERENCE = re.compile(r"\.svg(?:\b|$)", re.I)
FORBIDDEN_CLAIMS = (
    re.compile(
        r"\bgemini\s+(?:proved|proves|decided|decides|authorized|authorizes)\b", re.I
    ),
    re.compile(r"\badaptive\s+(?:beat|beats|outperformed|outperforms)\b", re.I),
)


class PackageError(ValueError):
    """The documentation or demo package contract failed."""


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise PackageError(message)


def _check_files() -> None:
    missing = [str(path.relative_to(ROOT)) for path in REQUIRED if not path.is_file()]
    _require(not missing, "missing required files: " + ", ".join(missing))


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
        text = document.read_text(encoding="utf-8")
        _require(
            PRIVATE_PATH.search(text) is None,
            f"private path in {document.relative_to(ROOT)}",
        )
        _require(
            SVG_REFERENCE.search(text) is None,
            f"SVG reference in {document.relative_to(ROOT)}",
        )
        for github_link in GITHUB_LINK.findall(text):
            if "/releases/" in github_link:
                valid = github_link in {
                    f"{CANONICAL_RELEASE}/tag/v0.1.0",
                } or github_link.startswith(f"{CANONICAL_RELEASE}/download/v0.1.0/")
            else:
                valid = github_link in {
                    CANONICAL_REPOSITORY,
                    f"{CANONICAL_REPOSITORY}.git",
                }
            _require(
                valid,
                f"non-canonical repository or release link in "
                f"{document.relative_to(ROOT)}: {github_link}",
            )
        for pattern in FORBIDDEN_CLAIMS:
            _require(
                pattern.search(text) is None,
                f"forbidden claim in {document.relative_to(ROOT)}: {pattern.pattern}",
            )
        for match in LINK.finditer(text):
            target = _target_from_markdown(match.group(1))
            if not target or target.startswith(("#", "http://", "https://", "mailto:")):
                continue
            relative = target.split("#", 1)[0]
            resolved = (document.parent / relative).resolve()
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


def _check_claim_markers() -> None:
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
    _require(
        "It did not authorize adaptive-efficiency" in readme,
        "README efficiency boundary is missing",
    )
    _require("No general exactly-once guarantee" in claims, "non-claim is missing")
    _require(
        re.search(r"does not depend on a public\s+endpoint", readme) is not None,
        "durable endpoint limitation is missing",
    )
    _require(
        "git clone https://github.com/OCHOLA-EDDYPHIL/reconcile.git" in readme,
        "public clone command is missing",
    )
    _require(
        "python scripts/validate_evidence.py" in readme,
        "canonical evidence validator command is missing",
    )
    _require(
        "scripts/replay_gate_g5r.py" not in readme,
        "legacy validator is still documented",
    )
    _require(
        "[![Scripted policy fixture and recorded Google Cloud trace]"
        "(demo/proof.png)](demo/proof.png)" in readme,
        "README evidence PNG is missing",
    )
    _require(
        "[![Recovery authority and trust boundaries](docs/architecture.png)]"
        "(docs/architecture.png)" in readme,
        "README architecture PNG is missing",
    )
    _require(
        "[![Hosted deployment and identity boundaries](docs/deployment.png)]"
        "(docs/deployment.png)" in readme,
        "README deployment PNG is missing",
    )
    public_text = "\n".join(
        path.read_text(encoding="utf-8")
        for path in (
            ROOT / "README.md",
            ROOT / "demo" / "README.md",
            ROOT / "demo" / "script.md",
            ROOT / "docs" / "claims-and-limitations.md",
            ROOT / "docs" / "hosted-runbook.md",
            ROOT / "docs" / "architecture.dot",
            ROOT / "docs" / "deployment.dot",
            ROOT / "demo" / "proof.dot",
        )
    )
    _require(
        public_text.count("Proof-to-Permit") == 1,
        "protocol name must appear exactly once in public prose",
    )
    _require(
        public_text.count("proof-to-permit safety on the frozen recovery matrix.") == 1,
        "frozen compatibility claim must appear exactly once",
    )
    for stale_wording in ("Three policies", "0 permits", "create exactly once"):
        _require(
            stale_wording not in public_text,
            f"stale public wording remains: {stale_wording}",
        )


def _check_demo_duration() -> int:
    script = (ROOT / "demo" / "script.md").read_text(encoding="utf-8")
    match = re.search(r"<!--\s*duration-seconds:\s*(\d+)\s*-->", script)
    _require(match is not None, "demo duration marker is missing")
    duration = int(match.group(1))
    _require(1 <= duration <= 240, "demo exceeds four minutes")
    return duration


def _png_dimensions(path: Path) -> tuple[int, int]:
    payload = path.read_bytes()
    _require(
        len(payload) >= 24
        and payload.startswith(b"\x89PNG\r\n\x1a\n")
        and payload[12:16] == b"IHDR",
        f"invalid PNG: {path.relative_to(ROOT)}",
    )
    return struct.unpack(">II", payload[16:24])


def _check_image_dimensions() -> None:
    for path in (
        ROOT / "docs" / "architecture.png",
        ROOT / "docs" / "deployment.png",
        ROOT / "demo" / "proof.png",
    ):
        width, height = _png_dimensions(path)
        _require(
            width >= 1280 and height >= 720 and 1.6 <= width / height <= 1.8,
            f"diagram is not a readable 16:9 export: {path.relative_to(ROOT)}",
        )


def _check_graphviz() -> str:
    executable = shutil.which("dot")
    if executable is None:
        _check_image_dimensions()
        return "PNG structure checked (Graphviz unavailable)"

    with tempfile.TemporaryDirectory(prefix="reconcile-diagram-check-") as directory:
        temporary = Path(directory)
        for source, export in (
            (ROOT / "docs" / "architecture.dot", ROOT / "docs" / "architecture.png"),
            (ROOT / "docs" / "deployment.dot", ROOT / "docs" / "deployment.png"),
            (ROOT / "demo" / "proof.dot", ROOT / "demo" / "proof.png"),
        ):
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
    _check_image_dimensions()
    return "Graphviz source/export parity checked"


def main() -> int:
    try:
        _check_files()
        load_and_validate(ROOT / "demo" / "evidence" / "proof-to-permit.json")
        link_count = _check_links_and_paths()
        _check_claim_markers()
        duration = _check_demo_duration()
        diagram_result = _check_graphviz()
    except (
        PackageError,
        EvidenceError,
        OSError,
        subprocess.SubprocessError,
    ) as error:
        print(f"FAIL: {error}", file=sys.stderr)
        return 1

    print("RECONCILE documentation/demo package: PASS")
    print("  accepted evidence invariants: checked")
    print(f"  local documentation links: {link_count} checked")
    print("  repository links, paths, and frozen claims: checked")
    print(f"  demo duration: {duration}s (limit 240s)")
    print(f"  diagrams: {diagram_result}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
