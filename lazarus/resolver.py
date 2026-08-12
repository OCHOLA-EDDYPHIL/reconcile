from __future__ import annotations

from collections import Counter
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from .protocol import (
    RELATION_EVIDENCE_CLASSES,
    ProtocolValidationError,
    ValidationIssue,
    load_artifact_texts,
    validate_case_contract,
    validate_citation,
    validate_citation_shape,
    validate_proposal_shape,
    validate_semantic_envelope,
)


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
        issues = list(validate_proposal_shape(proposal, path=proposal_path))
        proposal_id = _proposal_id(proposal, index)

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
                    if validate_citation_shape(citation, path=citation_path):
                        continue
                    if citation.get("artifact_id") in disabled_artifact_ids:
                        issues.append(
                            ValidationIssue(
                                "artifact_disabled",
                                f"{citation_path}.artifact_id",
                                "artifact is excluded by this ablation",
                            )
                        )
                    try:
                        validate_citation(
                            citation,
                            texts,
                            allowed_artifact_ids=declared_ids,
                            path=citation_path,
                        )
                    except ProtocolValidationError as exc:
                        issues.extend(exc.issues)

        if issues:
            rejected.append(
                {
                    "proposal_id": proposal_id,
                    "reason_codes": _unique_codes(issues),
                }
            )
            continue

        normalized = dict(proposal)
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
