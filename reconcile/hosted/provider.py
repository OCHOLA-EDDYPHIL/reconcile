"""Candidate-wide provider reservation and sanitized usage contracts."""

from __future__ import annotations

import hashlib
import re
from enum import StrEnum
from typing import Literal, Protocol

from pydantic import Field, model_validator

from reconcile.contracts.base import Identifier, Sha256Digest, StrictModel
from reconcile.contracts.codec import canonical_json_bytes

HOSTED_CANDIDATE_IDENTITY_VERSION = "reconcile/hosted-candidate-identity/v1"
HOSTED_PROVIDER_DISPATCH_VERSION = "reconcile/hosted-provider-dispatch/v1"

_SOURCE_REVISION = re.compile(r"[0-9a-f]{40}")
_IMAGE_DIGEST = re.compile(r"sha256:[0-9a-f]{64}")


class HostedCandidateIdentity(StrictModel):
    """Immutable source, image, infrastructure, and planner candidate identity."""

    schema_version: Literal["reconcile/hosted-candidate-identity/v1"]
    source_revision: str
    image_digest: str
    infrastructure_revision: Sha256Digest
    semantic_config_sha256: Sha256Digest
    project_id: Identifier
    vertex_location: Identifier
    configured_model: Identifier
    prompt_version: Identifier
    prompt_sha256: Sha256Digest
    maximum_input_tokens: Literal[12_000]
    maximum_output_tokens: Literal[1_024]
    thinking_level: Literal["MINIMAL"]
    maximum_count_tokens_attempts: Literal[1]
    maximum_generation_attempts: Literal[1]

    @model_validator(mode="after")
    def validate_candidate(self) -> HostedCandidateIdentity:
        if _SOURCE_REVISION.fullmatch(self.source_revision) is None:
            raise ValueError("candidate source revision is invalid")
        if _IMAGE_DIGEST.fullmatch(self.image_digest) is None:
            raise ValueError("candidate image digest is invalid")
        return self

    @property
    def sha256(self) -> str:
        return hashlib.sha256(canonical_json_bytes(self)).hexdigest()

    @property
    def candidate_id(self) -> str:
        return f"candidate-{self.sha256}"


class HostedProviderDispatch(StrictModel):
    """Exact sealed CountTokens and generation request identity."""

    schema_version: Literal["reconcile/hosted-provider-dispatch/v1"]
    input_sha256: Sha256Digest
    count_request_sha256: Sha256Digest
    generation_request_sha256: Sha256Digest
    request_byte_count: int = Field(ge=1, le=12_000)


class HostedModalityUsage(StrictModel):
    """One sanitized provider modality token count."""

    modality: Identifier
    token_count: int = Field(ge=0, le=2**63 - 1)


def _validate_details(
    details: tuple[HostedModalityUsage, ...],
    expected: int,
    label: str,
) -> None:
    if len(details) > 16:
        raise ValueError(f"{label} modality usage is too large")
    modalities = tuple(item.modality for item in details)
    if len(modalities) != len(set(modalities)):
        raise ValueError(f"{label} modality usage must be unique")
    if details and sum(item.token_count for item in details) != expected:
        raise ValueError(f"{label} modality usage does not match its total")


class HostedCountTokensUsage(StrictModel):
    """Complete bounded accounting returned by one CountTokens attempt."""

    total_tokens: int = Field(ge=1, le=12_000)
    cached_content_tokens: int = Field(ge=0, le=12_000)

    @model_validator(mode="after")
    def validate_count_usage(self) -> HostedCountTokensUsage:
        if self.cached_content_tokens > self.total_tokens:
            raise ValueError("cached token count exceeds the counted input")
        return self


class HostedGenerationUsage(StrictModel):
    """Thought-inclusive sanitized accounting for one billed generation."""

    prompt_tokens: int = Field(ge=0, le=2**63 - 1)
    candidates_tokens: int = Field(ge=0, le=2**63 - 1)
    thoughts_tokens: int = Field(ge=0, le=2**63 - 1)
    tool_use_prompt_tokens: int = Field(ge=0, le=2**63 - 1)
    cached_content_tokens: int = Field(ge=0, le=2**63 - 1)
    total_tokens: int = Field(ge=0, le=2**63 - 1)
    traffic_type: Identifier
    prompt_details: tuple[HostedModalityUsage, ...] = ()
    candidates_details: tuple[HostedModalityUsage, ...] = ()
    thoughts_details: tuple[HostedModalityUsage, ...] = ()
    tool_use_prompt_details: tuple[HostedModalityUsage, ...] = ()
    cache_details: tuple[HostedModalityUsage, ...] = ()

    @model_validator(mode="after")
    def validate_generation_usage(self) -> HostedGenerationUsage:
        expected_total = (
            self.prompt_tokens
            + self.candidates_tokens
            + self.thoughts_tokens
            + self.tool_use_prompt_tokens
        )
        if self.total_tokens != expected_total:
            raise ValueError("generation usage does not match its complete total")
        if self.cached_content_tokens > self.prompt_tokens:
            raise ValueError("cached generation tokens exceed prompt tokens")
        _validate_details(self.prompt_details, self.prompt_tokens, "prompt")
        _validate_details(
            self.candidates_details,
            self.candidates_tokens,
            "candidate",
        )
        _validate_details(self.thoughts_details, self.thoughts_tokens, "thought")
        _validate_details(
            self.tool_use_prompt_details,
            self.tool_use_prompt_tokens,
            "tool-use",
        )
        _validate_details(
            self.cache_details,
            self.cached_content_tokens,
            "cache",
        )
        return self

    @property
    def output_tokens_including_thoughts(self) -> int:
        return self.total_tokens - self.prompt_tokens


class HostedCountFailure(StrEnum):
    UNAVAILABLE = "count-unavailable"
    TIMEOUT = "count-timeout"
    INVALID = "count-invalid"
    LIMIT_EXCEEDED = "count-limit-exceeded"


class HostedGenerationFailure(StrEnum):
    UNAVAILABLE = "generation-unavailable"
    TIMEOUT = "generation-timeout"
    USAGE_INVALID = "generation-usage-invalid"


class HostedPlannerOutcome(StrEnum):
    SUCCEEDED = "planner-succeeded"
    UNAVAILABLE = "planner-unavailable"
    TIMEOUT = "planner-timeout"
    SCHEMA_INVALID = "planner-schema-invalid"


class HostedCountReservation(StrictModel):
    """Opaque persisted fence consuming the candidate's CountTokens attempt."""

    candidate_id: Identifier
    reservation_id: Identifier
    revision: int = Field(ge=1, le=2**63 - 1)
    dispatch: HostedProviderDispatch


class HostedGenerationReservation(StrictModel):
    """Opaque persisted fence consuming the candidate's billed generation."""

    candidate_id: Identifier
    reservation_id: Identifier
    revision: int = Field(ge=1, le=2**63 - 1)
    dispatch: HostedProviderDispatch


class HostedProviderLedgerError(RuntimeError):
    """Candidate provider authority was unavailable without implementation detail."""

    def __init__(self) -> None:
        super().__init__("hosted provider authority is unavailable")


class HostedProviderLedger(Protocol):
    """Atomic candidate-wide authority implemented durably by the hosted runtime."""

    async def reserve_count_tokens(
        self,
        candidate: HostedCandidateIdentity,
        dispatch: HostedProviderDispatch,
    ) -> HostedCountReservation: ...

    async def fail_count_tokens(
        self,
        reservation: HostedCountReservation,
        failure: HostedCountFailure,
    ) -> None: ...

    async def complete_count_and_reserve_generation(
        self,
        reservation: HostedCountReservation,
        usage: HostedCountTokensUsage,
    ) -> HostedGenerationReservation: ...

    async def fail_generation(
        self,
        reservation: HostedGenerationReservation,
        failure: HostedGenerationFailure,
    ) -> None: ...

    async def record_generation_usage(
        self,
        reservation: HostedGenerationReservation,
        usage: HostedGenerationUsage,
    ) -> None: ...

    async def finalize_generation(
        self,
        reservation: HostedGenerationReservation,
        outcome: HostedPlannerOutcome,
        *,
        output_sha256: Sha256Digest | None,
        reported_model: Identifier | None,
        reported_model_raw_sha256: Sha256Digest | None,
    ) -> None: ...


__all__ = [
    "HOSTED_CANDIDATE_IDENTITY_VERSION",
    "HOSTED_PROVIDER_DISPATCH_VERSION",
    "HostedCandidateIdentity",
    "HostedCountFailure",
    "HostedCountReservation",
    "HostedCountTokensUsage",
    "HostedGenerationFailure",
    "HostedGenerationReservation",
    "HostedGenerationUsage",
    "HostedModalityUsage",
    "HostedPlannerOutcome",
    "HostedProviderDispatch",
    "HostedProviderLedger",
    "HostedProviderLedgerError",
]
