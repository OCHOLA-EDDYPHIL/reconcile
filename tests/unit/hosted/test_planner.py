"""Hosted one-generation provider metering and failure boundaries."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass

import pytest
from google.genai import types

from reconcile.adaptive import (
    AdvisoryPlannerMetadata,
    AdvisoryPlannerTurn,
    AdvisoryPlannerUsage,
    PlannerFailureKind,
)
from reconcile.hosted.planner import (
    _HostedProviderAttempt,
    normalize_count_tokens_usage,
    normalize_generation_usage,
)
from reconcile.hosted.provider import (
    HOSTED_CANDIDATE_IDENTITY_VERSION,
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

pytestmark = pytest.mark.unit


def _candidate() -> HostedCandidateIdentity:
    return HostedCandidateIdentity(
        schema_version=HOSTED_CANDIDATE_IDENTITY_VERSION,
        source_revision="a" * 40,
        image_digest=f"sha256:{'b' * 64}",
        infrastructure_revision="c" * 64,
        semantic_config_sha256="d" * 64,
        project_id="reconcile-dev-260813-14fa6d",
        vertex_location="us",
        configured_model="gemini-3.5-flash",
        prompt_version="hosted-acquisition-v1",
        prompt_sha256="e" * 64,
        maximum_input_tokens=12_000,
        maximum_output_tokens=1_024,
        thinking_level="MINIMAL",
        maximum_count_tokens_attempts=1,
        maximum_generation_attempts=1,
    )


def _count_response(
    *,
    total: int = 20,
    cached: int = 0,
) -> types.CountTokensResponse:
    return types.CountTokensResponse(
        total_tokens=total,
        cached_content_token_count=cached,
    )


def _generation_response(
    *,
    candidates: int = 3,
    thoughts: int = 2,
    tool: int = 0,
    cached: int = 0,
    total: int | None = None,
    traffic: types.TrafficType = types.TrafficType.ON_DEMAND,
) -> types.GenerateContentResponse:
    selected_total = 10 + candidates + thoughts + tool if total is None else total
    return types.GenerateContentResponse(
        usage_metadata=types.GenerateContentResponseUsageMetadata(
            prompt_token_count=10,
            candidates_token_count=candidates,
            thoughts_token_count=thoughts,
            tool_use_prompt_token_count=tool,
            cached_content_token_count=cached,
            total_token_count=selected_total,
            traffic_type=traffic,
            prompt_tokens_details=[
                types.ModalityTokenCount(
                    modality=types.MediaModality.TEXT,
                    token_count=10,
                )
            ],
            candidates_tokens_details=[
                types.ModalityTokenCount(
                    modality=types.MediaModality.TEXT,
                    token_count=candidates,
                )
            ],
            tool_use_prompt_tokens_details=(
                None
                if tool == 0
                else [
                    types.ModalityTokenCount(
                        modality=types.MediaModality.TEXT,
                        token_count=tool,
                    )
                ]
            ),
            cache_tokens_details=(
                None
                if cached == 0
                else [
                    types.ModalityTokenCount(
                        modality=types.MediaModality.TEXT,
                        token_count=cached,
                    )
                ]
            ),
        )
    )


class _Context:
    model = "gemini-3.5-flash"
    request_byte_count = 1_024
    provider_request_sha256 = "1" * 64
    sealed_generation_request_sha256 = "2" * 64

    def __init__(
        self,
        *,
        count_response: types.CountTokensResponse | None = None,
        generation_response: types.GenerateContentResponse | None = None,
        count_failure: BaseException | None = None,
        generation_failure: BaseException | None = None,
    ) -> None:
        self._count_response = count_response or _count_response()
        self._generation_response = generation_response or _generation_response()
        self._count_failure = count_failure
        self._generation_failure = generation_failure
        self.count_calls = 0
        self.generation_calls = 0

    async def count_tokens(self) -> int:
        self.count_calls += 1
        if self._count_failure is not None:
            raise self._count_failure
        assert self._count_response.total_tokens is not None
        return self._count_response.total_tokens

    @property
    def count_tokens_response(self) -> types.CountTokensResponse:
        return self._count_response.model_copy(deep=True)

    async def generate_content(self) -> types.GenerateContentResponse:
        self.generation_calls += 1
        if self._generation_failure is not None:
            raise self._generation_failure
        return self._generation_response


@dataclass
class _LedgerFaults:
    complete: bool = False
    record: bool = False
    finalize: bool = False


class _Ledger:
    def __init__(self, faults: _LedgerFaults | None = None) -> None:
        self._lock = asyncio.Lock()
        self._count_candidate_ids: set[str] = set()
        self._generation_candidate_ids: set[str] = set()
        self.faults = faults or _LedgerFaults()
        self.count_attempts = 0
        self.generation_attempts = 0
        self.count_failures: list[HostedCountFailure] = []
        self.generation_failures: list[HostedGenerationFailure] = []
        self.count_usage: HostedCountTokensUsage | None = None
        self.generation_usage: HostedGenerationUsage | None = None
        self.final_outcome: HostedPlannerOutcome | None = None

    async def reserve_count_tokens(
        self,
        candidate: HostedCandidateIdentity,
        dispatch: HostedProviderDispatch,
    ) -> HostedCountReservation:
        async with self._lock:
            if candidate.candidate_id in self._count_candidate_ids:
                raise HostedProviderLedgerError
            self._count_candidate_ids.add(candidate.candidate_id)
            self.count_attempts += 1
            return HostedCountReservation(
                candidate_id=candidate.candidate_id,
                reservation_id="count-1",
                revision=1,
                dispatch=dispatch,
            )

    async def fail_count_tokens(
        self,
        reservation: HostedCountReservation,
        failure: HostedCountFailure,
    ) -> None:
        del reservation
        self.count_failures.append(failure)

    async def complete_count_and_reserve_generation(
        self,
        reservation: HostedCountReservation,
        usage: HostedCountTokensUsage,
    ) -> HostedGenerationReservation:
        if self.faults.complete:
            raise RuntimeError("private complete failure")
        async with self._lock:
            if reservation.candidate_id in self._generation_candidate_ids:
                raise HostedProviderLedgerError
            self._generation_candidate_ids.add(reservation.candidate_id)
            self.generation_attempts += 1
            self.count_usage = usage
            return HostedGenerationReservation(
                candidate_id=reservation.candidate_id,
                reservation_id="generation-1",
                revision=2,
                dispatch=reservation.dispatch,
            )

    async def fail_generation(
        self,
        reservation: HostedGenerationReservation,
        failure: HostedGenerationFailure,
    ) -> None:
        del reservation
        self.generation_failures.append(failure)

    async def record_generation_usage(
        self,
        reservation: HostedGenerationReservation,
        usage: HostedGenerationUsage,
    ) -> None:
        del reservation
        if self.faults.record:
            raise RuntimeError("private record failure")
        self.generation_usage = usage

    async def finalize_generation(
        self,
        reservation: HostedGenerationReservation,
        outcome: HostedPlannerOutcome,
        *,
        output_sha256: str | None,
        reported_model: str | None,
        reported_model_raw_sha256: str | None,
    ) -> None:
        del reservation, output_sha256, reported_model, reported_model_raw_sha256
        if self.faults.finalize:
            raise RuntimeError("private finalize failure")
        self.final_outcome = outcome


class _BlockingCountCompletionLedger(_Ledger):
    def __init__(self) -> None:
        super().__init__()
        self.started = asyncio.Event()
        self.release = asyncio.Event()

    async def complete_count_and_reserve_generation(
        self,
        reservation: HostedCountReservation,
        usage: HostedCountTokensUsage,
    ) -> HostedGenerationReservation:
        self.started.set()
        await self.release.wait()
        return await super().complete_count_and_reserve_generation(
            reservation,
            usage,
        )


class _BlockingGenerationUsageLedger(_Ledger):
    def __init__(self) -> None:
        super().__init__()
        self.started = asyncio.Event()
        self.release = asyncio.Event()

    async def record_generation_usage(
        self,
        reservation: HostedGenerationReservation,
        usage: HostedGenerationUsage,
    ) -> None:
        self.started.set()
        await self.release.wait()
        await super().record_generation_usage(reservation, usage)


def test_normalizes_complete_count_and_thought_inclusive_generation_usage() -> None:
    count = normalize_count_tokens_usage(_count_response(cached=5))
    generation = normalize_generation_usage(_generation_response(tool=1, cached=4))

    assert count == HostedCountTokensUsage(
        total_tokens=20,
        cached_content_tokens=5,
    )
    assert generation.prompt_tokens == 10
    assert generation.candidates_tokens == 3
    assert generation.thoughts_tokens == 2
    assert generation.tool_use_prompt_tokens == 1
    assert generation.cached_content_tokens == 4
    assert generation.total_tokens == 16
    assert generation.output_tokens_including_thoughts == 6
    assert generation.traffic_type == "ON_DEMAND"


@pytest.mark.parametrize(
    "response",
    (
        _count_response(total=12_001),
        _count_response(total=10, cached=11),
    ),
)
def test_rejects_invalid_or_over_limit_count_usage(
    response: types.CountTokensResponse,
) -> None:
    with pytest.raises(ValueError):
        normalize_count_tokens_usage(response)


def test_rejects_incomplete_generation_usage() -> None:
    with pytest.raises(ValueError):
        normalize_generation_usage(_generation_response(total=14))
    with pytest.raises(ValueError):
        normalize_generation_usage(types.GenerateContentResponse())


def test_concurrent_attempts_consume_only_one_candidate_wide_pair() -> None:
    async def scenario() -> None:
        candidate = _candidate()
        ledger = _Ledger()
        contexts = (_Context(), _Context())
        attempts = (
            _HostedProviderAttempt(candidate, ledger, "f" * 64),
            _HostedProviderAttempt(candidate, ledger, "f" * 64),
        )

        results = await asyncio.gather(
            attempts[0].dispatch(contexts[0]),  # type: ignore[arg-type]
            attempts[1].dispatch(contexts[1]),  # type: ignore[arg-type]
            return_exceptions=True,
        )

        assert (
            sum(type(result) is types.GenerateContentResponse for result in results)
            == 1
        )
        assert (
            sum(isinstance(result, HostedProviderLedgerError) for result in results)
            == 1
        )
        assert ledger.count_attempts == 1
        assert ledger.generation_attempts == 1
        assert sum(context.count_calls for context in contexts) == 1
        assert sum(context.generation_calls for context in contexts) == 1

    asyncio.run(scenario())


def test_count_completion_settles_before_cancellation_propagates() -> None:
    async def scenario() -> None:
        ledger = _BlockingCountCompletionLedger()
        context = _Context()
        attempt = _HostedProviderAttempt(_candidate(), ledger, "f" * 64)
        pending = asyncio.create_task(attempt.dispatch(context))  # type: ignore[arg-type]
        await ledger.started.wait()

        pending.cancel()
        await asyncio.sleep(0)

        assert pending.done() is False
        assert ledger.generation_attempts == 0
        assert context.count_calls == 1
        assert context.generation_calls == 0

        ledger.release.set()
        with pytest.raises(asyncio.CancelledError):
            await pending

        assert ledger.count_usage == HostedCountTokensUsage(
            total_tokens=20,
            cached_content_tokens=0,
        )
        assert ledger.generation_attempts == 1
        assert context.count_calls == 1
        assert context.generation_calls == 0

    asyncio.run(scenario())


def test_generation_usage_settles_before_cancellation_propagates() -> None:
    async def scenario() -> None:
        ledger = _BlockingGenerationUsageLedger()
        context = _Context()
        attempt = _HostedProviderAttempt(_candidate(), ledger, "f" * 64)
        pending = asyncio.create_task(attempt.dispatch(context))  # type: ignore[arg-type]
        await ledger.started.wait()

        pending.cancel()
        await asyncio.sleep(0)

        assert pending.done() is False
        assert ledger.generation_usage is None
        assert context.count_calls == 1
        assert context.generation_calls == 1

        ledger.release.set()
        with pytest.raises(asyncio.CancelledError):
            await pending

        assert ledger.generation_usage == normalize_generation_usage(
            _generation_response()
        )
        assert ledger.count_attempts == 1
        assert ledger.generation_attempts == 1
        assert context.count_calls == 1
        assert context.generation_calls == 1

    asyncio.run(scenario())


@pytest.mark.parametrize(
    ("context", "faults", "count_failure", "generation_failure"),
    (
        (
            _Context(count_failure=TimeoutError()),
            _LedgerFaults(),
            HostedCountFailure.TIMEOUT,
            None,
        ),
        (
            _Context(count_failure=RuntimeError("private")),
            _LedgerFaults(),
            HostedCountFailure.UNAVAILABLE,
            None,
        ),
        (
            _Context(count_response=_count_response(total=10, cached=11)),
            _LedgerFaults(),
            HostedCountFailure.INVALID,
            None,
        ),
        (
            _Context(count_response=_count_response(total=20, cached=1)),
            _LedgerFaults(),
            HostedCountFailure.INVALID,
            None,
        ),
        (_Context(), _LedgerFaults(complete=True), None, None),
        (
            _Context(generation_failure=TimeoutError()),
            _LedgerFaults(),
            None,
            HostedGenerationFailure.TIMEOUT,
        ),
        (
            _Context(generation_failure=RuntimeError("private")),
            _LedgerFaults(),
            None,
            HostedGenerationFailure.UNAVAILABLE,
        ),
        (
            _Context(generation_response=_generation_response(total=14)),
            _LedgerFaults(),
            None,
            HostedGenerationFailure.USAGE_INVALID,
        ),
        (
            _Context(generation_response=_generation_response(cached=1)),
            _LedgerFaults(),
            None,
            HostedGenerationFailure.USAGE_INVALID,
        ),
        (
            _Context(generation_response=_generation_response(tool=1)),
            _LedgerFaults(),
            None,
            HostedGenerationFailure.USAGE_INVALID,
        ),
        (
            _Context(
                generation_response=_generation_response(
                    candidates=1_023,
                    thoughts=2,
                )
            ),
            _LedgerFaults(),
            None,
            HostedGenerationFailure.USAGE_INVALID,
        ),
        (_Context(), _LedgerFaults(record=True), None, None),
    ),
)
def test_failure_edges_do_not_retry_or_release_candidate_attempts(
    context: _Context,
    faults: _LedgerFaults,
    count_failure: HostedCountFailure | None,
    generation_failure: HostedGenerationFailure | None,
) -> None:
    async def scenario() -> None:
        ledger = _Ledger(faults)
        attempt = _HostedProviderAttempt(_candidate(), ledger, "f" * 64)

        with pytest.raises(HostedProviderLedgerError):
            await attempt.dispatch(context)  # type: ignore[arg-type]

        assert ledger.count_attempts == 1
        assert ledger.generation_attempts <= 1
        assert context.count_calls <= 1
        assert context.generation_calls <= 1
        assert ledger.count_failures == (
            [] if count_failure is None else [count_failure]
        )
        assert ledger.generation_failures == (
            [] if generation_failure is None else [generation_failure]
        )

    asyncio.run(scenario())


def test_invalid_billed_usage_is_recorded_and_restart_cannot_redispatch() -> None:
    async def scenario() -> None:
        candidate = _candidate()
        ledger = _Ledger()
        first_context = _Context(generation_response=_generation_response(cached=1))
        first = _HostedProviderAttempt(candidate, ledger, "f" * 64)

        with pytest.raises(HostedProviderLedgerError):
            await first.dispatch(first_context)  # type: ignore[arg-type]

        assert ledger.generation_usage is not None
        assert ledger.generation_usage.cached_content_tokens == 1
        assert ledger.generation_failures == [HostedGenerationFailure.USAGE_INVALID]

        restarted_context = _Context()
        restarted = _HostedProviderAttempt(candidate, ledger, "f" * 64)
        with pytest.raises(HostedProviderLedgerError):
            await restarted.dispatch(restarted_context)  # type: ignore[arg-type]

        assert ledger.count_attempts == 1
        assert ledger.generation_attempts == 1
        assert restarted_context.count_calls == 0
        assert restarted_context.generation_calls == 0

    asyncio.run(scenario())


def test_persists_usage_before_sanitized_planner_finalization() -> None:
    async def scenario() -> None:
        ledger = _Ledger()
        attempt = _HostedProviderAttempt(_candidate(), ledger, "f" * 64)
        await attempt.dispatch(_Context())  # type: ignore[arg-type]
        metadata = AdvisoryPlannerMetadata(
            provider_name="google-vertex-ai",
            configured_model="gemini-3.5-flash",
            reported_model=None,
            adk_version="2.6.3",
            genai_version="2.18.0",
            prompt_version="hosted-acquisition-v1",
            prompt_sha256="e" * 64,
            input_schema_version="reconcile/adaptive-planner-input/v1",
            output_schema_version="reconcile/adaptive-planner-output/v1",
        )
        turn = AdvisoryPlannerTurn(
            output=None,
            failure=PlannerFailureKind.SCHEMA_INVALID,
            metadata=metadata,
            input_sha256="f" * 64,
            output_sha256=None,
            usage=AdvisoryPlannerUsage(
                prompt_tokens=10,
                output_tokens=5,
                total_tokens=15,
            ),
        )

        finalized = await attempt.finalize(turn)

        assert finalized is turn
        assert ledger.generation_usage is not None
        assert ledger.final_outcome is HostedPlannerOutcome.SCHEMA_INVALID

    asyncio.run(scenario())
