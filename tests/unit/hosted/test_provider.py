"""Strict candidate-wide hosted provider accounting contracts."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from reconcile.hosted.provider import (
    HOSTED_CANDIDATE_IDENTITY_VERSION,
    HOSTED_PROVIDER_DISPATCH_VERSION,
    HostedCandidateIdentity,
    HostedCountTokensUsage,
    HostedGenerationUsage,
    HostedModalityUsage,
    HostedProviderDispatch,
)

pytestmark = pytest.mark.unit


def _candidate(**updates: object) -> HostedCandidateIdentity:
    values: dict[str, object] = {
        "schema_version": HOSTED_CANDIDATE_IDENTITY_VERSION,
        "source_revision": "a" * 40,
        "image_digest": f"sha256:{'b' * 64}",
        "infrastructure_revision": "c" * 64,
        "semantic_config_sha256": "d" * 64,
        "project_id": "example-project-id",
        "vertex_location": "us",
        "configured_model": "gemini-3.5-flash",
        "prompt_version": "hosted-acquisition-v1",
        "prompt_sha256": "e" * 64,
        "maximum_input_tokens": 12_000,
        "maximum_output_tokens": 1_024,
        "thinking_level": "MINIMAL",
        "maximum_count_tokens_attempts": 1,
        "maximum_generation_attempts": 1,
    }
    values.update(updates)
    return HostedCandidateIdentity(**values)  # type: ignore[arg-type]


def test_candidate_identity_is_canonical_and_drift_sensitive() -> None:
    first = _candidate()
    identical = _candidate()
    drifted = _candidate(semantic_config_sha256="f" * 64)

    assert first == identical
    assert first.sha256 == identical.sha256
    assert first.candidate_id == f"candidate-{first.sha256}"
    assert drifted.sha256 != first.sha256


@pytest.mark.parametrize(
    "updates",
    (
        {"source_revision": "a" * 39},
        {"image_digest": "b" * 64},
        {"maximum_input_tokens": 11_999},
        {"maximum_output_tokens": 1_025},
        {"thinking_level": "LOW"},
        {"maximum_generation_attempts": 2},
    ),
)
def test_candidate_rejects_identity_or_allowance_drift(
    updates: dict[str, object],
) -> None:
    with pytest.raises(ValidationError):
        _candidate(**updates)


def test_provider_dispatch_binds_both_exact_requests() -> None:
    dispatch = HostedProviderDispatch(
        schema_version=HOSTED_PROVIDER_DISPATCH_VERSION,
        input_sha256="a" * 64,
        count_request_sha256="b" * 64,
        generation_request_sha256="c" * 64,
        request_byte_count=12_000,
    )

    assert dispatch.count_request_sha256 != dispatch.generation_request_sha256
    with pytest.raises(ValidationError):
        HostedProviderDispatch(
            schema_version=HOSTED_PROVIDER_DISPATCH_VERSION,
            input_sha256="a" * 64,
            count_request_sha256="b" * 64,
            generation_request_sha256="c" * 64,
            request_byte_count=12_001,
        )


def test_count_usage_includes_cached_tokens_within_exact_limit() -> None:
    usage = HostedCountTokensUsage(
        total_tokens=12_000,
        cached_content_tokens=2_000,
    )

    assert usage.total_tokens == 12_000
    with pytest.raises(ValidationError):
        HostedCountTokensUsage(total_tokens=12_001, cached_content_tokens=0)
    with pytest.raises(ValidationError):
        HostedCountTokensUsage(total_tokens=10, cached_content_tokens=11)


def test_generation_usage_is_complete_and_thought_inclusive() -> None:
    usage = HostedGenerationUsage(
        prompt_tokens=100,
        candidates_tokens=20,
        thoughts_tokens=30,
        tool_use_prompt_tokens=0,
        cached_content_tokens=10,
        total_tokens=150,
        traffic_type="ON_DEMAND",
        prompt_details=(HostedModalityUsage(modality="TEXT", token_count=100),),
        candidates_details=(HostedModalityUsage(modality="TEXT", token_count=20),),
        thoughts_details=(HostedModalityUsage(modality="TEXT", token_count=30),),
        cache_details=(HostedModalityUsage(modality="TEXT", token_count=10),),
    )

    assert usage.output_tokens_including_thoughts == 50


@pytest.mark.parametrize(
    "updates",
    (
        {"total_tokens": 149},
        {"cached_content_tokens": 101},
        {"prompt_details": (HostedModalityUsage(modality="TEXT", token_count=99),)},
        {
            "candidates_details": (
                HostedModalityUsage(modality="TEXT", token_count=10),
                HostedModalityUsage(modality="TEXT", token_count=10),
            )
        },
    ),
)
def test_generation_usage_rejects_incomplete_or_inconsistent_accounting(
    updates: dict[str, object],
) -> None:
    values: dict[str, object] = {
        "prompt_tokens": 100,
        "candidates_tokens": 20,
        "thoughts_tokens": 30,
        "tool_use_prompt_tokens": 0,
        "cached_content_tokens": 10,
        "total_tokens": 150,
        "traffic_type": "ON_DEMAND",
    }
    values.update(updates)
    with pytest.raises(ValidationError):
        HostedGenerationUsage(**values)  # type: ignore[arg-type]
