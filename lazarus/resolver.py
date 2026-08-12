from __future__ import annotations

from collections import Counter
from collections.abc import Mapping
from pathlib import Path
import re
from typing import Any

from .protocol import (
    RELATION_EVIDENCE_CLASSES,
    ProtocolValidationError,
    ValidationIssue,
    artifact_digest,
    load_artifact_texts,
    validate_case_contract,
    validate_model_citation_shape,
    validate_model_proposal_shape,
    validate_proposal_shape,
    validate_semantic_envelope,
)


_SUPPORT_REQUIRED_RELATION_TYPES = frozenset(RELATION_EVIDENCE_CLASSES)
_ADVISORY_CONTEXT_RELATION_TYPES = frozenset({"incident_relevance_advisory"})


def resolve_semantic_output(
    case: Mapping[str, Any],
    semantic_output: Mapping[str, Any],
    artifact_texts: Mapping[str, str | bytes] | str | Path,
    *,
    disabled_relation_types: frozenset[str] = frozenset(),
    disabled_artifact_ids: frozenset[str] = frozenset(),
) -> dict[str, Any]:
    validated_case = validate_case_contract(case)
    validated_output = validate_semantic_envelope(
        semantic_output, case_id=validated_case["case_id"]
    )
    if isinstance(artifact_texts, (str, Path)):
        texts: Mapping[str, str | bytes] = load_artifact_texts(
            validated_case, artifact_texts
        )
    elif isinstance(artifact_texts, Mapping):
        texts = artifact_texts
    else:
        raise TypeError("artifact_texts must be a mapping or case directory")

    declared_ids = frozenset(
        artifact["artifact_id"] for artifact in validated_case["artifacts"]
    )
    advisory_ids = frozenset(
        artifact["artifact_id"]
        for artifact in validated_case["artifacts"]
        if artifact["authority"] == "advisory_context"
    )
    unknown_disabled_artifacts = disabled_artifact_ids - declared_ids
    if unknown_disabled_artifacts:
        raise ValueError(
            f"unknown disabled artifacts: {sorted(unknown_disabled_artifacts)}"
        )
    allowed_probes = frozenset(validated_case["policy"]["allowed_probe_ids"])
    unknown_disabled = disabled_relation_types - frozenset(RELATION_EVIDENCE_CLASSES)
    if unknown_disabled:
        raise ValueError(
            f"unknown disabled relation types: {sorted(unknown_disabled)}"
        )
    proposals = validated_output["proposals"]
    proposal_id_counts = Counter(
        proposal.get("proposal_id")
        for proposal in proposals
        if isinstance(proposal, Mapping) and isinstance(proposal.get("proposal_id"), str)
    )

    admitted: list[dict[str, Any]] = []
    rejected: list[dict[str, Any]] = []
    for index, proposal in enumerate(proposals):
        proposal_path = f"$.proposals[{index}]"
        issues = list(validate_model_proposal_shape(proposal, path=proposal_path))
        proposal_id = _proposal_id(proposal, index)
        resolved_citations: list[dict[str, Any]] = []

        if proposal_id_counts.get(proposal_id, 0) > 1:
            issues.append(
                ValidationIssue(
                    "duplicate_proposal_id",
                    f"{proposal_path}.proposal_id",
                    "proposal_id must be unique",
                )
            )

        if isinstance(proposal, Mapping):
            relation_type = proposal.get("relation_type")
            probe_id = proposal.get("probe_id")
            if relation_type in disabled_relation_types:
                issues.append(
                    ValidationIssue(
                        "capability_disabled",
                        f"{proposal_path}.relation_type",
                        "relation type is disabled for this ablation",
                    )
                )
            if relation_type == "probe_selection" and probe_id not in allowed_probes:
                issues.append(
                    ValidationIssue(
                        "probe_not_allowed",
                        f"{proposal_path}.probe_id",
                        "probe is not enabled by case policy",
                    )
                )
            if (
                relation_type == "probe_selection"
                and probe_id in allowed_probes
                and any(
                    admitted_proposal.get("relation_type") == "probe_selection"
                    for admitted_proposal in admitted
                )
            ):
                issues.append(
                    ValidationIssue(
                        "multiple_probe_selection",
                        f"{proposal_path}.relation_type",
                        "only one probe selection may be admitted",
                    )
                )
            citations = proposal.get("citations")
            if isinstance(citations, list):
                for citation_index, citation in enumerate(citations):
                    citation_path = (
                        f"{proposal_path}.citations[{citation_index}]"
                    )
                    if validate_model_citation_shape(citation, path=citation_path):
                        continue
                    if citation.get("artifact_id") in disabled_artifact_ids:
                        issues.append(
                            ValidationIssue(
                                "artifact_disabled",
                                f"{citation_path}.artifact_id",
                                "artifact is excluded by this ablation",
                            )
                        )
                    if (
                        citation.get("artifact_id") in advisory_ids
                        and relation_type not in _ADVISORY_CONTEXT_RELATION_TYPES
                    ):
                        issues.append(
                            ValidationIssue(
                                "advisory_context_decision_attempt",
                                f"{citation_path}.artifact_id",
                                "advisory context cannot support a decision-capable relation",
                            )
                        )
                    try:
                        resolved_citations.append(
                            _resolve_model_citation(
                                citation,
                                texts,
                                allowed_artifact_ids=declared_ids,
                                path=citation_path,
                            )
                        )
                    except ProtocolValidationError as exc:
                        issues.extend(exc.issues)
            normalized = dict(proposal)
            normalized["citations"] = resolved_citations
            if not issues:
                issues.extend(validate_proposal_shape(normalized, path=proposal_path))
            if (
                not issues
                and relation_type in _SUPPORT_REQUIRED_RELATION_TYPES
                and not relation_endpoints_are_distinct(normalized)
            ):
                issues.append(
                    ValidationIssue(
                        "relation_endpoints_identical",
                        proposal_path,
                        "intent contradiction endpoints must be distinct",
                    )
                )
            if (
                not issues
                and relation_type in _SUPPORT_REQUIRED_RELATION_TYPES
                and not proposal_has_citation_support(normalized)
            ):
                issues.append(
                    ValidationIssue(
                        "citation_support_missing",
                        proposal_path,
                        "candidate relation endpoints must appear in the cited quotes",
                    )
                )

        if issues:
            rejected.append(
                {
                    "proposal_id": proposal_id,
                    "reason_codes": _unique_codes(issues),
                }
            )
            continue

        normalized = dict(proposal)
        normalized["citations"] = resolved_citations
        normalized["evidence_class"] = RELATION_EVIDENCE_CLASSES[
            normalized["relation_type"]
        ]
        admitted.append(normalized)

    return {
        "admitted": admitted,
        "rejected": rejected,
        "abstained": validated_output["abstained"],
        "requested_evidence": list(validated_output["requested_evidence"]),
    }


def unavailable_semantic_resolution(
    requested_evidence: list[str] | tuple[str, ...],
) -> dict[str, Any]:
    if not requested_evidence or any(
        not isinstance(item, str) or not item.strip() for item in requested_evidence
    ):
        raise ValueError("unavailable semantic resolution requires specific evidence")
    if len(set(requested_evidence)) != len(requested_evidence):
        raise ValueError("requested evidence must be unique")
    return {
        "admitted": [],
        "rejected": [],
        "abstained": True,
        "requested_evidence": list(requested_evidence),
    }


def not_requested_semantic_resolution() -> dict[str, Any]:
    return {
        "admitted": [],
        "rejected": [],
        "abstained": False,
        "requested_evidence": [],
    }


def _resolve_model_citation(
    citation: Mapping[str, Any],
    artifact_texts: Mapping[str, str | bytes],
    *,
    allowed_artifact_ids: frozenset[str],
    path: str,
) -> dict[str, Any]:
    issues = list(validate_model_citation_shape(citation, path=path))
    if issues:
        raise ProtocolValidationError("model citation", issues)

    artifact_id = citation["artifact_id"]
    if artifact_id not in allowed_artifact_ids:
        issues.append(
            ValidationIssue(
                "undeclared_artifact",
                f"{path}.artifact_id",
                "citation artifact is not declared by the case",
            )
        )
    if artifact_id not in artifact_texts:
        issues.append(
            ValidationIssue(
                "missing_artifact",
                f"{path}.artifact_id",
                "citation artifact text is unavailable",
            )
        )
        raise ProtocolValidationError("model citation", issues)

    raw = artifact_texts[artifact_id]
    if isinstance(raw, bytes):
        try:
            text = raw.decode("utf-8", errors="strict")
        except UnicodeDecodeError:
            issues.append(
                ValidationIssue(
                    "artifact_encoding",
                    f"{path}.artifact_id",
                    "artifact must be valid UTF-8",
                )
            )
            raise ProtocolValidationError("model citation", issues) from None
        payload = raw
    elif isinstance(raw, str):
        text = raw
        try:
            payload = raw.encode("utf-8", errors="strict")
        except UnicodeEncodeError:
            issues.append(
                ValidationIssue(
                    "artifact_encoding",
                    f"{path}.artifact_id",
                    "artifact must contain valid Unicode",
                )
            )
            raise ProtocolValidationError("model citation", issues) from None
    else:
        issues.append(
            ValidationIssue(
                "artifact_type",
                f"{path}.artifact_id",
                "artifact text must be text or bytes",
            )
        )
        raise ProtocolValidationError("model citation", issues)

    quote = citation["quote"]
    start = text.find(quote)
    if start < 0:
        issues.append(
            ValidationIssue(
                "citation_quote_missing",
                f"{path}.quote",
                "quote does not occur in the referenced artifact",
            )
        )
    elif text.find(quote, start + 1) >= 0:
        issues.append(
            ValidationIssue(
                "citation_quote_ambiguous",
                f"{path}.quote",
                "quote occurs more than once in the referenced artifact",
            )
        )
    if issues:
        raise ProtocolValidationError("model citation", issues)

    return {
        "artifact_id": artifact_id,
        "digest": artifact_digest(payload),
        "start": start,
        "end": start + len(quote),
        "quote": quote,
    }


def proposal_has_citation_support(proposal: Mapping[str, Any]) -> bool:
    if proposal.get("relation_type") not in _SUPPORT_REQUIRED_RELATION_TYPES:
        return True
    citations = proposal.get("citations")
    if not isinstance(citations, list):
        return False
    citation_tokens = [
        _support_tokens(citation["quote"])
        for citation in citations
        if isinstance(citation, Mapping)
        and isinstance(citation.get("quote"), str)
    ]
    if not citation_tokens:
        return False
    for endpoint in (proposal.get("subject"), proposal.get("object")):
        if not any(
            citation_supports_endpoint(citation, endpoint)
            for citation in citations
        ):
            return False
    return True


def citation_supports_endpoint(citation: Any, endpoint: Any) -> bool:
    if (
        not isinstance(citation, Mapping)
        or not isinstance(citation.get("quote"), str)
        or not isinstance(endpoint, str)
    ):
        return False
    endpoint_tokens = _support_tokens(endpoint)
    if sum(len(token) for token in endpoint_tokens) < 2:
        return False
    return _contains_token_sequence(
        _support_tokens(citation["quote"]),
        endpoint_tokens,
    )


def relation_endpoints_are_distinct(proposal: Mapping[str, Any]) -> bool:
    if proposal.get("relation_type") != "intent_effect_contradiction":
        return True
    subject = proposal.get("subject")
    object_ = proposal.get("object")
    if not isinstance(subject, str) or not isinstance(object_, str):
        return False
    subject_tokens = _support_tokens(subject)
    object_tokens = _support_tokens(object_)
    return bool(subject_tokens and object_tokens and subject_tokens != object_tokens)


def _support_tokens(value: str) -> tuple[str, ...]:
    return tuple(re.findall(r"[a-z0-9]+", value.casefold()))


def _contains_token_sequence(
    evidence: tuple[str, ...], endpoint: tuple[str, ...]
) -> bool:
    if not endpoint or len(endpoint) > len(evidence):
        return False
    width = len(endpoint)
    return any(
        evidence[index : index + width] == endpoint
        for index in range(len(evidence) - width + 1)
    )


def _proposal_id(proposal: Any, index: int) -> str:
    if isinstance(proposal, Mapping):
        proposal_id = proposal.get("proposal_id")
        if isinstance(proposal_id, str) and proposal_id.strip():
            return proposal_id
    return f"proposal[{index}]"


def _unique_codes(issues: list[ValidationIssue]) -> list[str]:
    codes: list[str] = []
    seen: set[str] = set()
    for issue in issues:
        if issue.code not in seen:
            codes.append(issue.code)
            seen.add(issue.code)
    return codes
