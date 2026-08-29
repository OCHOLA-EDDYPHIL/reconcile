#!/usr/bin/env python3
"""Compatibility entry point for :mod:`validate_evidence`."""

from __future__ import annotations

import sys
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

from validate_evidence import (  # noqa: E402
    BASELINE_REVISION,
    CANDIDATE_SHA256,
    CLEANUP_CAPTURED_AT,
    CLEANUP_VERIFICATION_SHA256,
    DEFAULT_EVIDENCE,
    EVENT_COUNT,
    HYPOTHESIS_IDENTIFIER,
    IMAGE_DIGEST,
    LIVE_CAPTURED_AT,
    LIVE_CORROBORATION_SHA256,
    MODEL,
    PROVIDER_PROJECTION_SHA256,
    RELEASE_REVISION,
    REVISION,
    RFC3339_UTC,
    ROOT,
    RUN_ID,
    RUN_IDENTIFIER,
    SHA256,
    SOURCE_REVISION,
    EvidenceError,
    load_and_validate,
    main,
    summary,
)

__all__ = (
    "BASELINE_REVISION",
    "CANDIDATE_SHA256",
    "CLEANUP_CAPTURED_AT",
    "CLEANUP_VERIFICATION_SHA256",
    "DEFAULT_EVIDENCE",
    "EVENT_COUNT",
    "HYPOTHESIS_IDENTIFIER",
    "IMAGE_DIGEST",
    "LIVE_CAPTURED_AT",
    "LIVE_CORROBORATION_SHA256",
    "MODEL",
    "PROVIDER_PROJECTION_SHA256",
    "RELEASE_REVISION",
    "REVISION",
    "RFC3339_UTC",
    "ROOT",
    "RUN_ID",
    "RUN_IDENTIFIER",
    "SHA256",
    "SOURCE_REVISION",
    "EvidenceError",
    "load_and_validate",
    "main",
    "summary",
)


if __name__ == "__main__":
    raise SystemExit(main())
