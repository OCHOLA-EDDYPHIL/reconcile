"""Candidate-wide metering for one sealed hosted Gemini planning turn."""

from __future__ import annotations

import asyncio
import hashlib
from collections.abc import Sequence
from enum import Enum
from typing import NoReturn

from google.genai import types

from reconcile.adaptive import (
    AdvisoryPlannerMetadata,
    AdvisoryPlannerTurn,
    AdvisoryPlannerUsage,
    PlannerFailureKind,
)
from reconcile.adk_planner import (
    AdkGeminiPlanner,
    GuardedDispatchContext,
    GuardedDispatchHook,
    GuardedInputTokenLimitExceeded,
)
from reconcile.contracts.codec import canonical_json_bytes
from reconcile.contracts.planning import AdaptivePlannerInput
from reconcile.hosted.provider import (
    HOSTED_PROVIDER_DISPATCH_VERSION,
    HostedCandidateIdentity,
    HostedCountFailure,
    HostedCountReservation,
    HostedCountTokensUsage,
    HostedGenerationFailure,
    HostedGenerationReservation,
    HostedGenerationUsage,
    HostedModalityUsage,
    HostedPlannerOutcome,
    HostedProviderDispatch,
    HostedProviderLedger,
    HostedProviderLedgerError,
)


def _provider_integer(value: object, label: str, *, positive: bool = False) -> int:
    if type(value) is not int or value < (1 if positive else 0):
        raise ValueError(f"{label} is invalid")
    return value


def _provider_identifier(value: object, label: str) -> str:
    if isinstance(value, Enum):
        value = value.value
    if type(value) is not str or value.endswith("_UNSPECIFIED"):
        raise ValueError(f"{label} is invalid")
    return value


def _modality_usage(
    values: Sequence[types.ModalityTokenCount] | None,
    label: str,
) -> tuple[HostedModalityUsage, ...]:
    if values is None:
        return ()
    if not isinstance(values, (list, tuple)) or len(values) > 16:
        raise ValueError(f"{label} modality usage is invalid")
    normalized: list[HostedModalityUsage] = []
    for item in values:
        if type(item) is not types.ModalityTokenCount:
            raise ValueError(f"{label} modality usage is invalid")
        normalized.append(
            HostedModalityUsage(
                modality=_provider_identifier(item.modality, label),
                token_count=_provider_integer(item.token_count, label),
            )
        )
    return tuple(normalized)


def normalize_count_tokens_usage(
    response: types.CountTokensResponse,
) -> HostedCountTokensUsage:
    """Normalize the complete bounded CountTokens response without raw text."""

    if type(response) is not types.CountTokensResponse:
        raise ValueError("count response type is invalid")
    cached = response.cached_content_token_count
    return HostedCountTokensUsage(
        total_tokens=_provider_integer(
            response.total_tokens,
            "count total",
            positive=True,
        ),
        cached_content_tokens=(
            0 if cached is None else _provider_integer(cached, "count cached total")
        ),
    )


def normalize_generation_usage(
    response: types.GenerateContentResponse,
) -> HostedGenerationUsage:
    """Normalize thought-inclusive billed usage before ADK parses the response."""

    if type(response) is not types.GenerateContentResponse:
        raise ValueError("generation response type is invalid")
    metadata = response.usage_metadata
    if type(metadata) is not types.GenerateContentResponseUsageMetadata:
        raise ValueError("generation usage is unavailable")

    def optional_integer(value: object, label: str) -> int:
        return 0 if value is None else _provider_integer(value, label)

    return HostedGenerationUsage(
        prompt_tokens=_provider_integer(metadata.prompt_token_count, "prompt total"),
        candidates_tokens=optional_integer(
            metadata.candidates_token_count,
            "candidate total",
        ),
        thoughts_tokens=optional_integer(
            metadata.thoughts_token_count,
            "thought total",
        ),
        tool_use_prompt_tokens=optional_integer(
            metadata.tool_use_prompt_token_count,
            "tool-use total",
        ),
        cached_content_tokens=optional_integer(
            metadata.cached_content_token_count,
            "cache total",
        ),
        total_tokens=_provider_integer(metadata.total_token_count, "generation total"),
        traffic_type=_provider_identifier(metadata.traffic_type, "traffic type"),
        prompt_details=_modality_usage(
            metadata.prompt_tokens_details,
            "prompt",
        ),
        candidates_details=_modality_usage(
            metadata.candidates_tokens_details,
            "candidate",
        ),
        tool_use_prompt_details=_modality_usage(
            metadata.tool_use_prompt_tokens_details,
            "tool-use",
        ),
        cache_details=_modality_usage(
            metadata.cache_tokens_details,
            "cache",
        ),
    )


def _ledger_failure() -> NoReturn:
    raise HostedProviderLedgerError from None


class _HostedProviderAttempt:
    """One non-releasable candidate attempt spanning count and generation."""

    def __init__(
        self,
        candidate: HostedCandidateIdentity,
        ledger: HostedProviderLedger,
        input_sha256: str,
    ) -> None:
        self._candidate = candidate
        self._ledger = ledger
        self._input_sha256 = input_sha256
        self._dispatch: HostedProviderDispatch | None = None
        self._count: HostedCountReservation | None = None
        self._generation: HostedGenerationReservation | None = None
        self._usage: HostedGenerationUsage | None = None
        self._generation_failed = False
        self._planner_failure: PlannerFailureKind | None = None

    @property
    def generation_reserved(self) -> bool:
        return self._generation is not None

    @property
    def usage(self) -> HostedGenerationUsage | None:
        return self._usage

    @property
    def planner_failure(self) -> PlannerFailureKind | None:
        return self._planner_failure

    def _validate_count_reservation(
        self,
        value: object,
        dispatch: HostedProviderDispatch,
    ) -> HostedCountReservation:
        if (
            type(value) is not HostedCountReservation
            or value.candidate_id != self._candidate.candidate_id
            or value.dispatch != dispatch
        ):
            raise HostedProviderLedgerError
        return value

    def _validate_generation_reservation(
        self,
        value: object,
        dispatch: HostedProviderDispatch,
    ) -> HostedGenerationReservation:
        if (
            type(value) is not HostedGenerationReservation
            or value.candidate_id != self._candidate.candidate_id
            or value.dispatch != dispatch
        ):
            raise HostedProviderLedgerError
        return value

    async def _fail_count(self, failure: HostedCountFailure) -> NoReturn:
        reservation = self._count
        assert reservation is not None
        self._planner_failure = (
            PlannerFailureKind.TIMEOUT
            if failure is HostedCountFailure.TIMEOUT
            else (
                PlannerFailureKind.SCHEMA_INVALID
                if failure
                in {HostedCountFailure.INVALID, HostedCountFailure.LIMIT_EXCEEDED}
                else PlannerFailureKind.UNAVAILABLE
            )
        )
        try:
            await self._ledger.fail_count_tokens(reservation, failure)
        except asyncio.CancelledError:
            raise
        except Exception:
            _ledger_failure()
        raise HostedProviderLedgerError from None

    async def _fail_generation(self, failure: HostedGenerationFailure) -> NoReturn:
        reservation = self._generation
        assert reservation is not None
        self._generation_failed = True
        self._planner_failure = (
            PlannerFailureKind.TIMEOUT
            if failure is HostedGenerationFailure.TIMEOUT
            else (
                PlannerFailureKind.SCHEMA_INVALID
                if failure is HostedGenerationFailure.USAGE_INVALID
                else PlannerFailureKind.UNAVAILABLE
            )
        )
        try:
            await self._ledger.fail_generation(reservation, failure)
        except asyncio.CancelledError:
            raise
        except Exception:
            _ledger_failure()
        raise HostedProviderLedgerError from None

    async def dispatch(
        self,
        context: GuardedDispatchContext,
    ) -> types.GenerateContentResponse:
        if self._dispatch is not None:
            raise HostedProviderLedgerError
        dispatch = HostedProviderDispatch(
            schema_version=HOSTED_PROVIDER_DISPATCH_VERSION,
            input_sha256=self._input_sha256,
            count_request_sha256=context.provider_request_sha256,
            generation_request_sha256=context.sealed_generation_request_sha256,
            request_byte_count=context.request_byte_count,
        )
        self._dispatch = dispatch
        try:
            reserved_count = await self._ledger.reserve_count_tokens(
                self._candidate,
                dispatch,
            )
            self._count = self._validate_count_reservation(
                reserved_count,
                dispatch,
            )
        except asyncio.CancelledError:
            raise
        except HostedProviderLedgerError:
            raise
        except Exception:
            _ledger_failure()

        try:
            await context.count_tokens()
        except asyncio.CancelledError:
            raise
        except GuardedInputTokenLimitExceeded:
            await self._fail_count(HostedCountFailure.LIMIT_EXCEEDED)
        except TimeoutError:
            await self._fail_count(HostedCountFailure.TIMEOUT)
        except Exception:
            await self._fail_count(HostedCountFailure.UNAVAILABLE)
        try:
            count_usage = normalize_count_tokens_usage(
                context.count_tokens_response,
            )
        except Exception:
            await self._fail_count(HostedCountFailure.INVALID)
        if count_usage.cached_content_tokens != 0:
            await self._fail_count(HostedCountFailure.INVALID)

        try:
            reserved_generation = (
                await self._ledger.complete_count_and_reserve_generation(
                    self._count,
                    count_usage,
                )
            )
            self._generation = self._validate_generation_reservation(
                reserved_generation,
                dispatch,
            )
        except asyncio.CancelledError:
            raise
        except HostedProviderLedgerError:
            raise
        except Exception:
            _ledger_failure()

        try:
            response = await context.generate_content()
        except asyncio.CancelledError:
            raise
        except TimeoutError:
            await self._fail_generation(HostedGenerationFailure.TIMEOUT)
        except Exception:
            await self._fail_generation(HostedGenerationFailure.UNAVAILABLE)
        try:
            usage = normalize_generation_usage(response)
        except Exception:
            await self._fail_generation(HostedGenerationFailure.USAGE_INVALID)
        try:
            await self._ledger.record_generation_usage(self._generation, usage)
        except asyncio.CancelledError:
            raise
        except Exception:
            _ledger_failure()
        self._usage = usage
        if (
            usage.prompt_tokens > self._candidate.maximum_input_tokens
            or usage.output_tokens_including_thoughts
            > self._candidate.maximum_output_tokens
            or usage.cached_content_tokens != 0
            or usage.tool_use_prompt_tokens != 0
            or usage.traffic_type != types.TrafficType.ON_DEMAND.value
        ):
            await self._fail_generation(HostedGenerationFailure.USAGE_INVALID)
        return response

    async def finalize(self, turn: AdvisoryPlannerTurn) -> AdvisoryPlannerTurn:
        reservation = self._generation
        usage = self._usage
        if reservation is None or usage is None or self._generation_failed:
            return turn

        expected_usage = AdvisoryPlannerUsage(
            prompt_tokens=usage.prompt_tokens,
            output_tokens=usage.output_tokens_including_thoughts,
            total_tokens=usage.total_tokens,
        )
        if turn.failure is None and turn.usage != expected_usage:
            turn = AdvisoryPlannerTurn(
                output=None,
                failure=PlannerFailureKind.SCHEMA_INVALID,
                metadata=turn.metadata,
                input_sha256=turn.input_sha256,
                output_sha256=turn.output_sha256,
                usage=expected_usage,
            )
        outcome = {
            None: HostedPlannerOutcome.SUCCEEDED,
            PlannerFailureKind.UNAVAILABLE: HostedPlannerOutcome.UNAVAILABLE,
            PlannerFailureKind.TIMEOUT: HostedPlannerOutcome.TIMEOUT,
            PlannerFailureKind.SCHEMA_INVALID: HostedPlannerOutcome.SCHEMA_INVALID,
        }[turn.failure]
        try:
            await self._ledger.finalize_generation(
                reservation,
                outcome,
                output_sha256=turn.output_sha256,
                reported_model=turn.metadata.reported_model,
                reported_model_raw_sha256=(turn.metadata.reported_model_raw_sha256),
            )
        except asyncio.CancelledError:
            raise
        except Exception:
            return _failure_turn(
                turn.metadata,
                turn.input_sha256,
                usage=expected_usage,
            )
        return turn


def _failure_turn(
    metadata: AdvisoryPlannerMetadata,
    input_sha256: str,
    *,
    failure: PlannerFailureKind = PlannerFailureKind.UNAVAILABLE,
    usage: AdvisoryPlannerUsage | None = None,
) -> AdvisoryPlannerTurn:
    return AdvisoryPlannerTurn(
        output=None,
        failure=failure,
        metadata=metadata,
        input_sha256=input_sha256,
        output_sha256=None,
        usage=usage,
    )


class HostedGeminiPlanner:
    """Run one sealed provider turn under candidate-wide durable authority."""

    def __init__(
        self,
        planner: AdkGeminiPlanner,
        candidate: HostedCandidateIdentity,
        ledger: HostedProviderLedger,
    ) -> None:
        if type(planner) is not AdkGeminiPlanner:
            raise TypeError("hosted planner requires an exact ADK planner")
        if type(candidate) is not HostedCandidateIdentity:
            raise TypeError("hosted planner candidate must be exact")
        planner.validate_guarded_candidate_identity(
            project=candidate.project_id,
            location=candidate.vertex_location,
            configured_model=candidate.configured_model,
            prompt_version=candidate.prompt_version,
            prompt_sha256=candidate.prompt_sha256,
            maximum_output_tokens=candidate.maximum_output_tokens,
            thinking_level=candidate.thinking_level,
        )
        self._planner = planner
        self._candidate = candidate
        self._ledger = ledger

    @property
    def metadata(self) -> AdvisoryPlannerMetadata:
        return self._planner.metadata

    async def plan(self, planner_input: AdaptivePlannerInput) -> AdvisoryPlannerTurn:
        if type(planner_input) is not AdaptivePlannerInput:
            raise TypeError("hosted planner input must be exact")
        input_sha256 = hashlib.sha256(canonical_json_bytes(planner_input)).hexdigest()
        attempt = _HostedProviderAttempt(
            self._candidate,
            self._ledger,
            input_sha256,
        )
        hook: GuardedDispatchHook = attempt.dispatch
        try:
            self._planner.bind_guarded_dispatch_hook(hook)
        except asyncio.CancelledError:
            raise
        except Exception:
            return _failure_turn(self.metadata, input_sha256)

        consumed: bool | None = None
        try:
            turn = await self._planner.plan(planner_input)
        except asyncio.CancelledError:
            raise
        except Exception:
            turn = _failure_turn(self.metadata, input_sha256)
        finally:
            try:
                consumed = self._planner.clear_guarded_dispatch_hook(hook)
            except asyncio.CancelledError:
                raise
            except Exception:
                consumed = None
        if consumed is not True:
            return _failure_turn(self.metadata, input_sha256)
        if attempt.planner_failure is not None:
            measured = attempt.usage
            turn = _failure_turn(
                turn.metadata,
                input_sha256,
                failure=attempt.planner_failure,
                usage=(
                    None
                    if measured is None
                    else AdvisoryPlannerUsage(
                        prompt_tokens=measured.prompt_tokens,
                        output_tokens=measured.output_tokens_including_thoughts,
                        total_tokens=measured.total_tokens,
                    )
                ),
            )
        return await attempt.finalize(turn)

    async def aclose(self) -> None:
        await self._planner.aclose()


__all__ = [
    "HostedGeminiPlanner",
    "normalize_count_tokens_usage",
    "normalize_generation_usage",
]
