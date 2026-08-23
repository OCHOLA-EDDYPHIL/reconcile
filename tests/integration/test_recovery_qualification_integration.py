"""SQLite, Firestore, contention, and evidence-custody qualification tests."""

from __future__ import annotations

import asyncio
import os
import stat
from datetime import UTC, datetime

import pytest

import reconcile.recovery_qualification as recovery_qualification_module
from reconcile.contracts import PermitAction
from reconcile.contracts.recovery_qualification import (
    RecoveryQualificationStorageBackend,
)
from reconcile.recovery_qualification import (
    RecoveryQualificationError,
    build_recovery_qualification_bundle,
    export_recovery_qualification_bundle,
    verify_recovery_qualification_bundle,
)

pytestmark = pytest.mark.integration

NOW = datetime(2026, 8, 23, tzinfo=UTC)


def test_both_permit_actions_survive_32_way_sqlite_and_firestore_contention(
    tmp_path,
    monkeypatch,
) -> None:
    bundle = asyncio.run(
        build_recovery_qualification_bundle(
            source_revision="d403db32b7507a8e04008d34484e8ba8a51bc657",
            source_tree_sha256="a" * 64,
            repository_clean=True,
            dependency_lock_sha256="b" * 64,
            created_at=NOW,
            contention_directory=tmp_path,
        )
    )

    assert {
        (item.backend, item.permit_action) for item in bundle.contention.trials
    } == {
        (RecoveryQualificationStorageBackend.SQLITE, PermitAction.CONTINUE),
        (RecoveryQualificationStorageBackend.SQLITE, PermitAction.RETRY),
        (RecoveryQualificationStorageBackend.FIRESTORE, PermitAction.CONTINUE),
        (RecoveryQualificationStorageBackend.FIRESTORE, PermitAction.RETRY),
    }
    assert all(item.contender_count == 32 for item in bundle.contention.trials)
    assert all(item.winner_count == 1 for item in bundle.contention.trials)
    assert all(item.denied_count == 31 for item in bundle.contention.trials)
    assert all(item.outbound_call_count <= 1 for item in bundle.contention.trials)
    assert bundle.contention.passed is True
    assert bundle.claim_authorization.safety_claim_authorized is True
    assert (
        bundle.claim_authorization.adaptive_efficiency_claim_authorized is False
    )

    destination = tmp_path / "proof-to-permit-qualification-v1"
    index = export_recovery_qualification_bundle(destination, bundle)

    assert verify_recovery_qualification_bundle(destination) == index
    assert {item.name for item in destination.iterdir()} == {
        "manifest.json",
        "environment.json",
        "results.json",
        "contention.json",
        "comparison.json",
        "claim-authorization.json",
        "index.json",
    }
    assert all(
        stat.S_IMODE(item.stat().st_mode) == 0o600
        for item in destination.iterdir()
    )
    with pytest.raises(FileExistsError):
        export_recovery_qualification_bundle(destination, bundle)

    with pytest.raises(RecoveryQualificationError, match="must not overlap"):
        export_recovery_qualification_bundle(
            tmp_path / "inside-source",
            bundle,
            source_repository=tmp_path,
        )

    original_write = recovery_qualification_module._write_exclusive
    write_count = 0

    def interrupted_write(path, payload):
        nonlocal write_count
        write_count += 1
        if write_count == 3:
            raise OSError("injected qualification export interruption")
        original_write(path, payload)

    monkeypatch.setattr(
        recovery_qualification_module,
        "_write_exclusive",
        interrupted_write,
    )
    interrupted = tmp_path / "interrupted-bundle"
    with pytest.raises(OSError, match="injected qualification"):
        export_recovery_qualification_bundle(interrupted, bundle)
    assert not interrupted.exists()
    assert not tuple(tmp_path.glob(".interrupted-bundle.tmp-*"))

    environment_path = destination / "environment.json"
    os.chmod(environment_path, 0o644)
    with pytest.raises(RecoveryQualificationError, match="mode is not 0600"):
        verify_recovery_qualification_bundle(destination)
