"""Candidate-wide provider authority persisted through bounded Firestore CAS."""

from __future__ import annotations

import asyncio
import hashlib
from enum import StrEnum
from typing import Literal, Never, Protocol
from uuid import uuid4

from pydantic import Field, model_validator

from reconcile.contracts.base import Identifier, Sha256Digest, StrictModel
from reconcile.contracts.codec import canonical_json_bytes, decode_contract
from reconcile.hosted.firestore_cas import (
    FirestoreCasCollection,
    FirestoreCasDocument,
    FirestoreCasSnapshot,
    build_firestore_cas_document,
    new_firestore_cas_mutation_id,
)
from reconcile.hosted.provider import (
    HostedCandidateIdentity,
    HostedCountFailure,
    HostedCountReservation,
    HostedCountTokensUsage,
    HostedGenerationFailure,
    HostedGenerationReservation,
    HostedGenerationUsage,
    HostedPlannerOutcome,
    HostedProviderDispatch,
    HostedProviderLedgerError,
)

HOSTED_PROVIDER_LEDGER_DOCUMENT_VERSION = "reconcile/hosted-provider-ledger-document/v1"


class HostedProviderLedgerState(StrEnum):
    """Closed, non-reopenable states for one candidate provider allowance."""

    COUNT_RESERVED = "count-reserved"
    COUNT_FAILED = "count-failed"
    GENERATION_RESERVED = "generation-reserved"
    GENERATION_USAGE_RECORDED = "generation-usage-recorded"
    GENERATION_FAILED = "generation-failed"
    FINALIZED = "finalized"


class HostedProviderLedgerObservation(StrictModel):
    """Sanitized proof that the candidate's sole generation was finalized."""

    schema_version: Literal["reconcile/hosted-provider-ledger-observation/v1"]
    candidate_id: Identifier
    candidate_sha256: Sha256Digest
    state: Literal["finalized"]
    revision: Literal[4]
    count_attempts: Literal[1] = 1
    generation_attempts: Literal[1] = 1
    dispatch: HostedProviderDispatch
    dispatch_sha256: Sha256Digest
    count_usage: HostedCountTokensUsage
    generation_usage: HostedGenerationUsage
    planner_outcome: Literal[HostedPlannerOutcome.SUCCEEDED]
    output_sha256: Sha256Digest
    reported_model: Identifier
    reported_model_raw_sha256: Sha256Digest
    record_sha256: Sha256Digest

    @model_validator(mode="after")
    def validate_candidate(self) -> HostedProviderLedgerObservation:
        if (
            self.candidate_id != f"candidate-{self.candidate_sha256}"
            or self.dispatch_sha256
            != hashlib.sha256(canonical_json_bytes(self.dispatch)).hexdigest()
        ):
            raise ValueError("provider ledger observation changed candidate identity")
        return self


class _ProviderLedgerDocument(StrictModel):
    """Exact canonical payload stored under the candidate's CAS document."""

    schema_version: Literal["reconcile/hosted-provider-ledger-document/v1"]
    state: HostedProviderLedgerState
    revision: int = Field(ge=1, le=2**63 - 1)
    candidate_id: Identifier
    candidate: HostedCandidateIdentity
    dispatch: HostedProviderDispatch
    count_reservation_id: Identifier
    count_reservation_revision: int = Field(ge=1, le=2**63 - 1)
    count_usage: HostedCountTokensUsage | None = None
    count_failure: HostedCountFailure | None = None
    generation_reservation_id: Identifier | None = None
    generation_reservation_revision: int | None = Field(
        default=None,
        ge=1,
        le=2**63 - 1,
    )
    generation_usage: HostedGenerationUsage | None = None
    generation_failure: HostedGenerationFailure | None = None
    planner_outcome: HostedPlannerOutcome | None = None
    output_sha256: Sha256Digest | None = None
    reported_model: Identifier | None = None
    reported_model_raw_sha256: Sha256Digest | None = None

    @model_validator(mode="after")
    def validate_state(self) -> _ProviderLedgerDocument:
        if self.candidate_id != self.candidate.candidate_id:
            raise ValueError("provider ledger candidate identity does not match")
        if self.count_reservation_revision != 1:
            raise ValueError("provider ledger count reservation revision changed")
        if (self.reported_model is None) != (self.reported_model_raw_sha256 is None):
            raise ValueError("provider ledger reported model is incomplete")

        generation_fields_present = (
            self.generation_reservation_id is not None
            and self.generation_reservation_revision is not None
        )
        generation_fields_absent = (
            self.generation_reservation_id is None
            and self.generation_reservation_revision is None
        )
        final_fields_absent = (
            self.planner_outcome is None
            and self.output_sha256 is None
            and self.reported_model is None
            and self.reported_model_raw_sha256 is None
        )

        if self.state is HostedProviderLedgerState.COUNT_RESERVED:
            valid = (
                self.revision == 1
                and self.count_usage is None
                and self.count_failure is None
                and generation_fields_absent
                and self.generation_usage is None
                and self.generation_failure is None
                and final_fields_absent
            )
        elif self.state is HostedProviderLedgerState.COUNT_FAILED:
            valid = (
                self.revision == 2
                and self.count_usage is None
                and self.count_failure is not None
                and generation_fields_absent
                and self.generation_usage is None
                and self.generation_failure is None
                and final_fields_absent
            )
        else:
            generation_revision = self.generation_reservation_revision
            common_generation = (
                self.count_usage is not None
                and self.count_failure is None
                and generation_fields_present
                and generation_revision == 2
            )
            if self.state is HostedProviderLedgerState.GENERATION_RESERVED:
                valid = (
                    common_generation
                    and self.revision == 2
                    and self.generation_usage is None
                    and self.generation_failure is None
                    and final_fields_absent
                )
            elif self.state is HostedProviderLedgerState.GENERATION_USAGE_RECORDED:
                valid = (
                    common_generation
                    and self.revision == 3
                    and self.generation_usage is not None
                    and self.generation_failure is None
                    and final_fields_absent
                )
            elif self.state is HostedProviderLedgerState.GENERATION_FAILED:
                expected_revision = 3 if self.generation_usage is None else 4
                valid = (
                    common_generation
                    and self.revision == expected_revision
                    and self.generation_failure is not None
                    and final_fields_absent
                )
            elif self.state is HostedProviderLedgerState.FINALIZED:
                valid = (
                    common_generation
                    and self.revision == 4
                    and self.generation_usage is not None
                    and self.generation_failure is None
                    and self.planner_outcome is not None
                    and (
                        self.planner_outcome is not HostedPlannerOutcome.SUCCEEDED
                        or self.output_sha256 is not None
                    )
                )
            else:  # pragma: no cover - enum exhaustiveness defense.
                valid = False
        if not valid:
            raise ValueError("provider ledger state fields are inconsistent")
        return self


class _FirestoreCasStorePort(Protocol):
    async def read(
        self,
        collection: FirestoreCasCollection,
        logical_id: str,
    ) -> FirestoreCasSnapshot | None: ...

    async def create(
        self,
        document: FirestoreCasDocument,
    ) -> FirestoreCasSnapshot: ...

    async def update(
        self,
        current: FirestoreCasSnapshot,
        replacement: FirestoreCasDocument,
    ) -> FirestoreCasSnapshot: ...


def _ledger_failure() -> Never:
    raise HostedProviderLedgerError from None


def _reservation_id(kind: Literal["count", "generation"]) -> str:
    return f"{kind}-{uuid4().hex}"


def _transition(
    current: _ProviderLedgerDocument,
    **changes: object,
) -> _ProviderLedgerDocument:
    values = {
        name: getattr(current, name) for name in _ProviderLedgerDocument.model_fields
    }
    values.update(changes)
    return _ProviderLedgerDocument(**values)  # type: ignore[arg-type]


def _cas_document(record: _ProviderLedgerDocument) -> FirestoreCasDocument:
    return build_firestore_cas_document(
        collection=FirestoreCasCollection.PROVIDER_CANDIDATE,
        logical_id=record.candidate_id,
        revision=record.revision,
        mutation_id=new_firestore_cas_mutation_id(),
        canonical_payload=canonical_json_bytes(record),
    )


def _decoded_record(snapshot: FirestoreCasSnapshot) -> _ProviderLedgerDocument:
    if (
        type(snapshot) is not FirestoreCasSnapshot
        or snapshot.collection is not FirestoreCasCollection.PROVIDER_CANDIDATE
        or snapshot.document.kind is not FirestoreCasCollection.PROVIDER_CANDIDATE
    ):
        _ledger_failure()
    try:
        record = decode_contract(
            snapshot.document.payload_bytes,
            _ProviderLedgerDocument,
        )
    except Exception:
        _ledger_failure()
    if (
        snapshot.document.logical_id != record.candidate_id
        or snapshot.document.revision != record.revision
    ):
        _ledger_failure()
    return record


class FirestoreHostedProviderLedger:
    """Non-retryable candidate-wide provider fences over one Firestore CAS store."""

    def __init__(self, cas_store: _FirestoreCasStorePort) -> None:
        if any(
            not callable(getattr(cas_store, name, None))
            for name in ("create", "read", "update")
        ):
            raise TypeError("hosted provider ledger requires a CAS store")
        self._cas_store = cas_store

    async def _load(
        self,
        candidate_id: str,
    ) -> tuple[FirestoreCasSnapshot, _ProviderLedgerDocument]:
        try:
            snapshot = await self._cas_store.read(
                FirestoreCasCollection.PROVIDER_CANDIDATE,
                candidate_id,
            )
        except asyncio.CancelledError:
            raise
        except Exception:
            _ledger_failure()
        if snapshot is None:
            _ledger_failure()
        record = _decoded_record(snapshot)
        if record.candidate_id != candidate_id:
            _ledger_failure()
        return snapshot, record

    async def is_absent(self, candidate: HostedCandidateIdentity) -> bool:
        """Prove that no candidate-wide provider allowance has been consumed."""

        if type(candidate) is not HostedCandidateIdentity:
            _ledger_failure()
        try:
            snapshot = await self._cas_store.read(
                FirestoreCasCollection.PROVIDER_CANDIDATE,
                candidate.candidate_id,
            )
        except asyncio.CancelledError:
            raise
        except Exception:
            _ledger_failure()
        return snapshot is None

    async def _create(
        self,
        record: _ProviderLedgerDocument,
    ) -> None:
        try:
            document = _cas_document(record)
            written = await self._cas_store.create(document)
            if written.document != document or _decoded_record(written) != record:
                _ledger_failure()
        except asyncio.CancelledError:
            raise
        except Exception:
            _ledger_failure()

    async def _update(
        self,
        snapshot: FirestoreCasSnapshot,
        record: _ProviderLedgerDocument,
    ) -> None:
        try:
            document = _cas_document(record)
            written = await self._cas_store.update(snapshot, document)
            if written.document != document or _decoded_record(written) != record:
                _ledger_failure()
        except asyncio.CancelledError:
            raise
        except Exception:
            _ledger_failure()

    @staticmethod
    def _count_record(
        record: _ProviderLedgerDocument,
        reservation: HostedCountReservation,
    ) -> None:
        if (
            type(reservation) is not HostedCountReservation
            or record.state is not HostedProviderLedgerState.COUNT_RESERVED
            or reservation.candidate_id != record.candidate_id
            or reservation.reservation_id != record.count_reservation_id
            or reservation.revision != record.count_reservation_revision
            or reservation.dispatch != record.dispatch
        ):
            _ledger_failure()

    @staticmethod
    def _generation_record(
        record: _ProviderLedgerDocument,
        reservation: HostedGenerationReservation,
        states: frozenset[HostedProviderLedgerState],
    ) -> None:
        if (
            type(reservation) is not HostedGenerationReservation
            or record.state not in states
            or reservation.candidate_id != record.candidate_id
            or reservation.reservation_id != record.generation_reservation_id
            or reservation.revision != record.generation_reservation_revision
            or reservation.dispatch != record.dispatch
        ):
            _ledger_failure()

    async def reserve_count_tokens(
        self,
        candidate: HostedCandidateIdentity,
        dispatch: HostedProviderDispatch,
    ) -> HostedCountReservation:
        """Atomically consume the absent candidate's sole CountTokens attempt."""

        if (
            type(candidate) is not HostedCandidateIdentity
            or type(dispatch) is not HostedProviderDispatch
        ):
            _ledger_failure()
        reservation_id = _reservation_id("count")
        try:
            record = _ProviderLedgerDocument(
                schema_version=HOSTED_PROVIDER_LEDGER_DOCUMENT_VERSION,
                state=HostedProviderLedgerState.COUNT_RESERVED,
                revision=1,
                candidate_id=candidate.candidate_id,
                candidate=candidate,
                dispatch=dispatch,
                count_reservation_id=reservation_id,
                count_reservation_revision=1,
            )
        except Exception:
            _ledger_failure()
        await self._create(record)
        return HostedCountReservation(
            candidate_id=record.candidate_id,
            reservation_id=record.count_reservation_id,
            revision=record.count_reservation_revision,
            dispatch=record.dispatch,
        )

    async def fail_count_tokens(
        self,
        reservation: HostedCountReservation,
        failure: HostedCountFailure,
    ) -> None:
        """Seal a reserved count attempt as a terminal sanitized failure."""

        if (
            type(reservation) is not HostedCountReservation
            or type(failure) is not HostedCountFailure
        ):
            _ledger_failure()
        snapshot, current = await self._load(reservation.candidate_id)
        self._count_record(current, reservation)
        try:
            replacement = _transition(
                current,
                state=HostedProviderLedgerState.COUNT_FAILED,
                revision=current.revision + 1,
                count_failure=failure,
            )
        except Exception:
            _ledger_failure()
        await self._update(snapshot, replacement)

    async def complete_count_and_reserve_generation(
        self,
        reservation: HostedCountReservation,
        usage: HostedCountTokensUsage,
    ) -> HostedGenerationReservation:
        """Atomically record count usage and consume the generation attempt."""

        if (
            type(reservation) is not HostedCountReservation
            or type(usage) is not HostedCountTokensUsage
        ):
            _ledger_failure()
        snapshot, current = await self._load(reservation.candidate_id)
        self._count_record(current, reservation)
        generation_reservation_id = _reservation_id("generation")
        next_revision = current.revision + 1
        try:
            replacement = _transition(
                current,
                state=HostedProviderLedgerState.GENERATION_RESERVED,
                revision=next_revision,
                count_usage=usage,
                generation_reservation_id=generation_reservation_id,
                generation_reservation_revision=next_revision,
            )
        except Exception:
            _ledger_failure()
        await self._update(snapshot, replacement)
        return HostedGenerationReservation(
            candidate_id=replacement.candidate_id,
            reservation_id=generation_reservation_id,
            revision=next_revision,
            dispatch=replacement.dispatch,
        )

    async def fail_generation(
        self,
        reservation: HostedGenerationReservation,
        failure: HostedGenerationFailure,
    ) -> None:
        """Seal a generation failure while preserving any recorded usage."""

        if (
            type(reservation) is not HostedGenerationReservation
            or type(failure) is not HostedGenerationFailure
        ):
            _ledger_failure()
        snapshot, current = await self._load(reservation.candidate_id)
        self._generation_record(
            current,
            reservation,
            frozenset(
                {
                    HostedProviderLedgerState.GENERATION_RESERVED,
                    HostedProviderLedgerState.GENERATION_USAGE_RECORDED,
                }
            ),
        )
        try:
            replacement = _transition(
                current,
                state=HostedProviderLedgerState.GENERATION_FAILED,
                revision=current.revision + 1,
                generation_failure=failure,
            )
        except Exception:
            _ledger_failure()
        await self._update(snapshot, replacement)

    async def record_generation_usage(
        self,
        reservation: HostedGenerationReservation,
        usage: HostedGenerationUsage,
    ) -> None:
        """Persist complete billed usage before any caller-side validation."""

        if (
            type(reservation) is not HostedGenerationReservation
            or type(usage) is not HostedGenerationUsage
        ):
            _ledger_failure()
        snapshot, current = await self._load(reservation.candidate_id)
        self._generation_record(
            current,
            reservation,
            frozenset({HostedProviderLedgerState.GENERATION_RESERVED}),
        )
        try:
            replacement = _transition(
                current,
                state=HostedProviderLedgerState.GENERATION_USAGE_RECORDED,
                revision=current.revision + 1,
                generation_usage=usage,
            )
        except Exception:
            _ledger_failure()
        await self._update(snapshot, replacement)

    async def finalize_generation(
        self,
        reservation: HostedGenerationReservation,
        outcome: HostedPlannerOutcome,
        *,
        output_sha256: Sha256Digest | None,
        reported_model: Identifier | None,
        reported_model_raw_sha256: Sha256Digest | None,
    ) -> None:
        """Finalize only a generation whose complete usage is already durable."""

        if (
            type(reservation) is not HostedGenerationReservation
            or type(outcome) is not HostedPlannerOutcome
        ):
            _ledger_failure()
        snapshot, current = await self._load(reservation.candidate_id)
        self._generation_record(
            current,
            reservation,
            frozenset({HostedProviderLedgerState.GENERATION_USAGE_RECORDED}),
        )
        try:
            replacement = _transition(
                current,
                state=HostedProviderLedgerState.FINALIZED,
                revision=current.revision + 1,
                planner_outcome=outcome,
                output_sha256=output_sha256,
                reported_model=reported_model,
                reported_model_raw_sha256=reported_model_raw_sha256,
            )
        except Exception:
            _ledger_failure()
        await self._update(snapshot, replacement)

    async def observe_finalized(
        self,
        candidate: HostedCandidateIdentity,
    ) -> HostedProviderLedgerObservation:
        """Read one successful terminal ledger without exposing reservation IDs."""

        if type(candidate) is not HostedCandidateIdentity:
            _ledger_failure()
        _snapshot, current = await self._load(candidate.candidate_id)
        if (
            current.candidate != candidate
            or current.state is not HostedProviderLedgerState.FINALIZED
            or current.revision != 4
            or current.count_usage is None
            or current.generation_usage is None
            or current.planner_outcome is not HostedPlannerOutcome.SUCCEEDED
            or current.output_sha256 is None
            or current.reported_model is None
            or current.reported_model_raw_sha256 is None
        ):
            _ledger_failure()
        try:
            return HostedProviderLedgerObservation(
                schema_version="reconcile/hosted-provider-ledger-observation/v1",
                candidate_id=current.candidate_id,
                candidate_sha256=candidate.sha256,
                state="finalized",
                revision=4,
                dispatch=current.dispatch,
                dispatch_sha256=hashlib.sha256(
                    canonical_json_bytes(current.dispatch)
                ).hexdigest(),
                count_usage=current.count_usage,
                generation_usage=current.generation_usage,
                planner_outcome=HostedPlannerOutcome.SUCCEEDED,
                output_sha256=current.output_sha256,
                reported_model=current.reported_model,
                reported_model_raw_sha256=current.reported_model_raw_sha256,
                record_sha256=hashlib.sha256(canonical_json_bytes(current)).hexdigest(),
            )
        except (TypeError, ValueError):
            _ledger_failure()


__all__ = [
    "HOSTED_PROVIDER_LEDGER_DOCUMENT_VERSION",
    "FirestoreHostedProviderLedger",
    "HostedProviderLedgerObservation",
    "HostedProviderLedgerState",
]
